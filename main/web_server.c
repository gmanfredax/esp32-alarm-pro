// web_server.c — ESP-IDF 5.x
// - UI con SPIFFS: index.html, login.html, style.css, app.js, login.js
// - Gate lato server: cookie HttpOnly "gate=1" decide index vs login su GET "/"
// - API solo con Authorization: Bearer <token> (no cookie) => no CSRF
// - Sessioni in RAM (token→username) con TTL assoluto 7g e inattività 5m (sliding)
// - Login con password (+ TOTP opzionale se abilitato per l’utente)

#include "sdkconfig.h"

#include "esp_timer.h"
#include "esp_check.h"
#include "esp_random.h"
#include "esp_spiffs.h"
#include "esp_vfs.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_system.h"
#include "esp_http_server.h"
#include "esp_https_server.h"
#include "esp_netif.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "freertos/portmacro.h"

#include "nvs_flash.h"
#include "nvs.h"

#include "cJSON.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include "mbedtls/md.h"
#include "mbedtls/base64.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/error.h"
#include "mbedtls/version.h"

#include "web_server.h"

#include "alarm_core.h"
#include "auth.h"
#include "ethernet.h"
#include "device_identity.h"
#include "spiffs_utils.h"
#include "totp.h"
#include "audit_log.h"
#include "pn532_spi.h"
#include "log_system.h"
#include "gpio_inputs.h"
#include "outputs.h"
#include "utils.h"
#include "scenes.h"
#include "roster.h"
#include "pdo.h"
#include "mqtt_client.h"
#include "app_mqtt.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/param.h>
#include <sys/unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

#include "lwip/ip4_addr.h"
#include "lwip/ip_addr.h"

extern const unsigned char certs_server_cert_pem_start[] asm("_binary_server_cert_pem_start");
extern const unsigned char certs_server_cert_pem_end[]   asm("_binary_server_cert_pem_end");
extern const unsigned char certs_server_key_pem_start[]  asm("_binary_server_key_pem_start");
extern const unsigned char certs_server_key_pem_end[]    asm("_binary_server_key_pem_end");
extern const uint8_t certs_broker_ca_pem_start[] asm("_binary_broker_ca_pem_start");
extern const uint8_t certs_broker_ca_pem_end[]   asm("_binary_broker_ca_pem_end");

extern esp_err_t can_master_request_scan(bool *started);
extern esp_err_t can_master_send_test_toggle(bool enable);

static void web_server_restart_async(void);

static const char *TAG = "web";
static const char *TAG_ADMIN __attribute__((unused)) = "admin_html";

// ─────────────────────────────────────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────────────────────────────────────
#define OTP_DISABLED        1   // 1 = disattiva completamente la richiesta OTP su /api/login
#define WEB_MAX_BODY_LEN     2048
#define SESSION_TTL_S        (7*24*60*60)  // 7 giorni
#define SESSION_IDLE_S       (5*60)       // 30 minuti sliding

static const char* ISSUER_NAME = "Alarm Pro";
#define GATE_COOKIE "gate"

#define WEB_TLS_NS             "websec"
#define WEB_TLS_CERT_KEY       "cert"
#define WEB_TLS_PRIV_KEY       "key"
#define WEB_TLS_TS_KEY         "inst"
#define WEB_TLS_MAX_PEM_LEN    (4096)
#define WEB_TLS_MAX_BODY       (8*1024)

typedef enum {
    WEB_TLS_SRC_NONE = 0,
    WEB_TLS_SRC_BUILTIN,
    WEB_TLS_SRC_EMBEDDED,
    WEB_TLS_SRC_CUSTOM
} web_tls_source_t;

static const char builtin_cert_pem[] =
"";

static const char builtin_key_pem[] =
"";

typedef struct {
    uint8_t *dyn_cert;
    size_t dyn_cert_len;
    uint8_t *dyn_key;
    size_t dyn_key_len;
    const uint8_t *cert;
    size_t cert_len;
    const uint8_t *key;
    size_t key_len;
    web_tls_source_t source;
} web_tls_material_t;

typedef struct {
    web_tls_source_t active_source;
    bool using_builtin;
    bool custom_available;
    bool custom_valid;
    char active_subject[128];
    char active_issuer[128];
    char active_not_before[32];
    char active_not_after[32];
    char active_fingerprint[96];
    char custom_subject[128];
    char custom_issuer[128];
    char custom_not_before[32];
    char custom_not_after[32];
    char custom_fingerprint[96];
    uint64_t custom_installed_at;
    char custom_installed_iso[32];
    char last_error[128];
} web_tls_state_t;

static web_tls_material_t s_tls_material = {
    .cert = (const uint8_t*)builtin_cert_pem,
    .cert_len = sizeof(builtin_cert_pem),
    .key = (const uint8_t*)builtin_key_pem,
    .key_len = sizeof(builtin_key_pem),
    .source = WEB_TLS_SRC_BUILTIN,
};

static web_tls_state_t s_web_tls_state = {
    .active_source = WEB_TLS_SRC_BUILTIN,
    .using_builtin = true,
    .custom_available = false,
    .custom_valid = false,
    .custom_installed_at = 0,
};

static bool s_restart_pending = false;

#define DEFAULT_CF_UI_URL "https://dash.cloudflare.com/"
static bool s_provisioned = false;
static char s_cloudflare_ui_url[128] = DEFAULT_CF_UI_URL;

typedef struct {
    char central_name[64];
} provisioning_general_config_t;

typedef struct {
    bool dhcp;
    char hostname[64];
    char ip[16];
    char gw[16];
    char mask[16];
    char dns[16];
} provisioning_net_config_t;

typedef struct {
    char uri[96];
    char cid[64];
    char user[64];
    char pass[64];
    uint32_t keepalive;
} provisioning_mqtt_config_t;

typedef struct {
    char account_id[96];
    char tunnel_id[96];
    char auth_token[256];
    char ui_url[128];
} provisioning_cloudflare_config_t;

static esp_timer_handle_t s_net_apply_timer = NULL;
static provisioning_net_config_t s_net_apply_cfg = {0};
static bool s_net_apply_cfg_valid = false;
static portMUX_TYPE s_net_apply_lock = portMUX_INITIALIZER_UNLOCKED;

typedef struct ws_client {
    int fd;
    struct ws_client *next;
} ws_client_t;

static ws_client_t *s_ws_clients = NULL;
static SemaphoreHandle_t s_ws_lock = NULL;

// ─────────────────────────────────────────────────────────────────────────────
// Server handle & SPIFFS
// ─────────────────────────────────────────────────────────────────────────────
//static httpd_handle_t s_server = NULL;
static httpd_handle_t s_https_server = NULL;
static httpd_handle_t s_http_redirect_server = NULL;
static bool s_spiffs_mounted __attribute__((unused)) = false;

static void set_https_security_headers(httpd_req_t* req){
    if (!req) return;
    auth_set_security_headers(req);
}

static void build_https_location(httpd_req_t* req, const char* target, char* out, size_t outlen){
    if (!out || !outlen) return;
    const char* dest = target && target[0] ? target : "/";
    if (!strncasecmp(dest, "https://", 8)){ strlcpy(out, dest, outlen); return; }
    if (!strncasecmp(dest, "http://", 7)){
        snprintf(out, outlen, "https://%s", dest + 7);
        return;
    }
    char host[96] = {0};
    if (httpd_req_get_hdr_value_str(req, "Host", host, sizeof(host)) == ESP_OK && host[0]){
        if (dest[0] == '/') snprintf(out, outlen, "https://%s%s", host, dest);
        else snprintf(out, outlen, "https://%s/%s", host, dest);
        return;
    }
    if (dest[0] == '/') dest++;
    snprintf(out, outlen, "https://%s", dest);
}

static esp_err_t send_https_redirect(httpd_req_t* req, const char* target, const char* status){
    char location[192];
    build_https_location(req, target, location, sizeof(location));
    set_https_security_headers(req);
    httpd_resp_set_status(req, status ? status : "302 Found");
    httpd_resp_set_hdr(req, "Location", location);
    return httpd_resp_send(req, NULL, 0);
}

static bool check_bearer(httpd_req_t* req){
    return auth_check_bearer(req, NULL);
}

static bool is_admin_user(httpd_req_t* req){
    user_info_t u; return auth_check_bearer(req, &u) && u.role==ROLE_ADMIN;
}

static bool cors_origin_allowed(const char *origin, const char *host)
{
    if (!origin || !origin[0]) {
        return false;
    }
    if (strcasecmp(origin, "https://ui.nsalarm.pro") == 0) {
        return true;
    }
    if (host && host[0]) {
        char buf[192];
        snprintf(buf, sizeof(buf), "https://%s", host);
        if (strcasecmp(origin, buf) == 0) {
            return true;
        }
        snprintf(buf, sizeof(buf), "http://%s", host);
        if (strcasecmp(origin, buf) == 0) {
            return true;
        }
    }
    return false;
}

static bool cors_apply(httpd_req_t *req)
{
    char origin[160];
    if (httpd_req_get_hdr_value_str(req, "Origin", origin, sizeof(origin)) != ESP_OK) {
        return false;
    }
    char host[128] = {0};
    httpd_req_get_hdr_value_str(req, "Host", host, sizeof(host));
    if (!cors_origin_allowed(origin, host)) {
        return false;
    }
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", origin);
    httpd_resp_set_hdr(req, "Vary", "Origin");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "Content-Type, Authorization");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Credentials", "true");
    return true;
}

static esp_err_t cors_handle_options(httpd_req_t *req)
{
    cors_apply(req);
    httpd_resp_set_status(req, "204 No Content");
    return httpd_resp_send(req, NULL, 0);
}

static bool current_user_from_req(httpd_req_t* req, char* out, size_t cap){
    user_info_t u;
    if(!auth_check_bearer(req, &u)) return false;
    if(out && cap){ strncpy(out, u.username, cap-1); out[cap-1]=0; }
    return true;
}

static esp_err_t read_body_to_buf(httpd_req_t* req, char* buf, size_t cap, size_t* out_len){
    int total = req->content_len;
    if (total <= 0 || (size_t)total >= cap) return ESP_FAIL;
    int rd = 0;
    while (rd < total) {
        int r = httpd_req_recv(req, buf + rd, total - rd);
        if (r <= 0) return ESP_FAIL;
        rd += r;
    }
    buf[rd] = 0;
    if (out_len) *out_len = rd;
    return ESP_OK;
}

static esp_err_t json_reply(httpd_req_t* req, const char* json){
    set_https_security_headers(req);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, json);
}

static esp_err_t json_reply_cjson(httpd_req_t* req, cJSON* json){
    if (!json) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
    char* payload = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (!payload) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
    esp_err_t err = json_reply(req, payload);
    free(payload);
    return err;
}

static esp_err_t json_error_reply(httpd_req_t *req, const char *status, const char *error_code)
{
    if (status) {
        httpd_resp_set_status(req, status);
    }
    cJSON *resp = cJSON_CreateObject();
    if (!resp) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
    }
    cJSON_AddStringToObject(resp, "error", error_code ? error_code : "error");
    return json_reply_cjson(req, resp);
}

// ----- START CANBUS -----------------------------------
static SemaphoreHandle_t ws_lock_get(void)
{
    if (!s_ws_lock) {
        s_ws_lock = xSemaphoreCreateMutex();
    }
    return s_ws_lock;
}

static void ws_clients_reset(void)
{
    SemaphoreHandle_t lock = ws_lock_get();
    if (!lock) {
        return;
    }
    xSemaphoreTake(lock, portMAX_DELAY);
    ws_client_t *cur = s_ws_clients;
    while (cur) {
        ws_client_t *next = cur->next;
        free(cur);
        cur = next;
    }
    s_ws_clients = NULL;
    xSemaphoreGive(lock);
}

static void ws_client_add(int fd)
{
    SemaphoreHandle_t lock = ws_lock_get();
    if (!lock) {
        return;
    }
    xSemaphoreTake(lock, portMAX_DELAY);
    for (ws_client_t *it = s_ws_clients; it; it = it->next) {
        if (it->fd == fd) {
            xSemaphoreGive(lock);
            return;
        }
    }
    ws_client_t *item = calloc(1, sizeof(ws_client_t));
    if (!item) {
        xSemaphoreGive(lock);
        return;
    }
    item->fd = fd;
    item->next = s_ws_clients;
    s_ws_clients = item;
    xSemaphoreGive(lock);
}

static void ws_client_remove(int fd)
{
    SemaphoreHandle_t lock = ws_lock_get();
    if (!lock) {
        return;
    }
    xSemaphoreTake(lock, portMAX_DELAY);
    ws_client_t **it = &s_ws_clients;
    while (*it) {
        if ((*it)->fd == fd) {
            ws_client_t *old = *it;
            *it = old->next;
            free(old);
            break;
        }
        it = &(*it)->next;
    }
    xSemaphoreGive(lock);
}

static esp_err_t ws_broadcast_payload(const char *payload, size_t len)
{
    if (!payload || len == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_https_server) {
        return ESP_ERR_INVALID_STATE;
    }
    SemaphoreHandle_t lock = ws_lock_get();
    if (!lock) {
        return ESP_ERR_NO_MEM;
    }
    xSemaphoreTake(lock, portMAX_DELAY);
    ws_client_t **it = &s_ws_clients;
    while (*it) {
        ws_client_t *client = *it;
        httpd_ws_frame_t frame = {
            .type = HTTPD_WS_TYPE_TEXT,
            .payload = (uint8_t *)payload,
            .len = len,
        };
        esp_err_t err = httpd_ws_send_frame_async(s_https_server, client->fd, &frame);
        if (err != ESP_OK) {
            ws_client_t *old = client;
            *it = client->next;
            free(old);
            continue;
        }
        it = &client->next;
    }
    xSemaphoreGive(lock);
    return ESP_OK;
}

esp_err_t web_server_ws_broadcast_event(const char *event, cJSON *fields)
{
    if (!event) {
        if (fields) {
            cJSON_Delete(fields);
        }
        return ESP_ERR_INVALID_ARG;
    }
    cJSON *root = fields ? fields : cJSON_CreateObject();
    if (!root) {
        return ESP_ERR_NO_MEM;
    }
    if (!cJSON_AddStringToObject(root, "event", event)) {
        cJSON_Delete(root);
        return ESP_ERR_NO_MEM;
    }
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json) {
        return ESP_ERR_NO_MEM;
    }
    size_t len = strlen(json);
    char *payload = malloc(len + 2);
    if (!payload) {
        free(json);
        return ESP_ERR_NO_MEM;
    }
    memcpy(payload, json, len);
    payload[len] = '\n';
    payload[len + 1] = '\0';
    free(json);
    esp_err_t err = ws_broadcast_payload(payload, len + 1);
    free(payload);
    return err;
}

static esp_err_t ws_handler(httpd_req_t *req)
{
    if (!check_bearer(req)) {
        httpd_resp_send_err(req, 401, "token");
        return ESP_FAIL;
    }
    if (req->method == HTTP_GET) {
        int fd = httpd_req_to_sockfd(req);
        ws_client_add(fd);
        return ESP_OK;
    }
    httpd_ws_frame_t frame = {
        .type = HTTPD_WS_TYPE_TEXT,
    };
    esp_err_t err = httpd_ws_recv_frame(req, &frame, 0);
    if (err != ESP_OK) {
        return err;
    }
    if (frame.len) {
        frame.payload = calloc(1, frame.len + 1);
        if (!frame.payload) {
            return ESP_ERR_NO_MEM;
        }
        err = httpd_ws_recv_frame(req, &frame, frame.len);
        if (err != ESP_OK) {
            free(frame.payload);
            return err;
        }
    }
    int fd = httpd_req_to_sockfd(req);
    if (frame.type == HTTPD_WS_TYPE_CLOSE) {
        ws_client_remove(fd);
    } else if (frame.type == HTTPD_WS_TYPE_PING) {
        httpd_ws_frame_t pong = {
            .type = HTTPD_WS_TYPE_PONG,
            .payload = frame.payload,
            .len = frame.len,
        };
        httpd_ws_send_frame(req, &pong);
    }
    if (frame.payload) {
        free(frame.payload);
    }
    return ESP_OK;
}

static bool parse_can_node_id(const char *uri, uint8_t *out_node)
{
    const char *prefix = "/api/can/node/";
    size_t prefix_len = strlen(prefix);
    if (strncmp(uri, prefix, prefix_len) != 0) {
        return false;
    }
    const char *p = uri + prefix_len;
    if (!isdigit((unsigned char)*p)) {
        return false;
    }
    char *end = NULL;
    long node = strtol(p, &end, 10);
    if (end == p || node < 0 || node > 255) {
        return false;
    }
    if (strcmp(end, "/identify") != 0) {
        return false;
    }
    if (out_node) {
        *out_node = (uint8_t)node;
    }
    return true;
}

static bool parse_can_nodes_uri(const char *uri, uint8_t *out_node)
{
    const char *prefix = "/api/can/nodes/";
    size_t prefix_len = strlen(prefix);
    if (strncmp(uri, prefix, prefix_len) != 0) {
        return false;
    }
    const char *p = uri + prefix_len;
    if (!isdigit((unsigned char)*p)) {
        return false;
    }
    char *end = NULL;
    long node = strtol(p, &end, 10);
    if (end == p || node < 0 || node > 255) {
        return false;
    }
    if (*end != '\0' && *end != '?') {
        return false;
    }
    if (out_node) {
        *out_node = (uint8_t)node;
    }
    return true;
}

static esp_err_t api_can_nodes_get(httpd_req_t *req)
{
    if (s_provisioned && !check_bearer(req)) {
        httpd_resp_send_err(req, 401, "token");
        return ESP_FAIL;
    }
    cors_apply(req);
    cJSON *array = cJSON_CreateArray();
    if (!array) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json");
        return ESP_FAIL;
    }
    roster_to_json(array);
    return json_reply_cjson(req, array);
}

static esp_err_t api_can_nodes_options(httpd_req_t *req)
{
    return cors_handle_options(req);
}

static esp_err_t api_can_scan_post(httpd_req_t *req)
{
    if (s_provisioned && !check_bearer(req)) {
        httpd_resp_send_err(req, 401, "token");
        return ESP_FAIL;
    }
    cors_apply(req);
    bool started = false;
    esp_err_t err = can_master_request_scan(&started);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "scan");
        return ESP_FAIL;
    }
    cJSON *resp = cJSON_CreateObject();
    if (!resp) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json");
        return ESP_FAIL;
    }
    httpd_resp_set_status(req, "202 Accepted");
    cJSON_AddBoolToObject(resp, "started", started);
    return json_reply_cjson(req, resp);
}

static esp_err_t api_can_scan_options(httpd_req_t *req)
{
    return cors_handle_options(req);
}

static bool can_test_require_admin(httpd_req_t *req)
{
    if (!check_bearer(req) || !is_admin_user(req)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden");
        return false;
    }
    return true;
}

static esp_err_t can_test_broadcast_send(httpd_req_t *req, bool enable)
{
#if !defined(CAN_TEST_BROADCAST)
    return json_error_reply(req, "503 Service Unavailable", "can_not_supported");
#else
    esp_err_t err = can_master_send_test_toggle(enable);
    if (err == ESP_ERR_NOT_SUPPORTED) {
        return json_error_reply(req, "503 Service Unavailable", "can_not_supported");
    }
    if (err == ESP_ERR_TIMEOUT || err == ESP_ERR_INVALID_STATE) {
        return json_error_reply(req, "503 Service Unavailable", "can_not_ready");
    }
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "can");
        return ESP_FAIL;
    }
    cJSON *resp = cJSON_CreateObject();
    if (!resp) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json");
        return ESP_FAIL;
    }
    cJSON_AddStringToObject(resp, "state", enable ? "on" : "off");
    cJSON_AddBoolToObject(resp, "on", enable);
    return json_reply_cjson(req, resp);
#endif
}

static esp_err_t api_can_test_toggle_post(httpd_req_t *req)
{
    if (!can_test_require_admin(req)) {
        return ESP_FAIL;
    }
    cors_apply(req);

    char body[64];
    size_t body_len = 0;
    if (read_body_to_buf(req, body, sizeof(body), &body_len) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "body");
        return ESP_FAIL;
    }

    cJSON *json = cJSON_ParseWithLength(body, body_len);
    if (!json) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "json");
        return ESP_FAIL;
    }

    cJSON *jstate = cJSON_GetObjectItemCaseSensitive(json, "state");
    bool enable = false;
    bool has_state = false;
    if (cJSON_IsBool(jstate)) {
        enable = cJSON_IsTrue(jstate);
        has_state = true;
    } else if (cJSON_IsString(jstate) && jstate->valuestring) {
        const char *value = jstate->valuestring;
        if (strcasecmp(value, "on") == 0 ||
            strcasecmp(value, "1") == 0 ||
            strcasecmp(value, "true") == 0) {
            enable = true;
            has_state = true;
        } else if (strcasecmp(value, "off") == 0 ||
                   strcasecmp(value, "0") == 0 ||
                   strcasecmp(value, "false") == 0) {
            enable = false;
            has_state = true;
        }
    }

    cJSON_Delete(json);

    if (!has_state) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "state");
        return ESP_FAIL;
    }

    return can_test_broadcast_send(req, enable);
}

static esp_err_t api_can_test_toggle_options(httpd_req_t *req)
{
    return cors_handle_options(req);
}

static esp_err_t api_can_test_broadcast_on_post(httpd_req_t *req)
{
    if (!can_test_require_admin(req)) {
        return ESP_FAIL;
    }
    cors_apply(req);
    return can_test_broadcast_send(req, true);
}

static esp_err_t api_can_test_broadcast_off_post(httpd_req_t *req)
{
    if (!can_test_require_admin(req)) {
        return ESP_FAIL;
    }
    cors_apply(req);
    return can_test_broadcast_send(req, false);
}

static esp_err_t api_can_test_broadcast_options(httpd_req_t *req)
{
    return cors_handle_options(req);
}

static esp_err_t api_can_node_delete(httpd_req_t *req)
{
    if (!check_bearer(req) || !is_admin_user(req)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden");
        return ESP_FAIL;
    }
    uint8_t node_id = 0;
    if (!parse_can_nodes_uri(req->uri, &node_id) || node_id == 0) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "node");
        return ESP_FAIL;
    }
    cors_apply(req);
    bool hard = false;
    size_t qlen = httpd_req_get_url_query_len(req);
    if (qlen > 0) {
        char *query = malloc(qlen + 1);
        if (query) {
            if (httpd_req_get_url_query_str(req, query, qlen + 1) == ESP_OK) {
                char value[16];
                if (httpd_query_key_value(query, "hard", value, sizeof(value)) == ESP_OK) {
                    if (value[0] == '1' || strcasecmp(value, "true") == 0 || strcasecmp(value, "yes") == 0) {
                        hard = true;
                    }
                }
                if (!hard && httpd_query_key_value(query, "mode", value, sizeof(value)) == ESP_OK) {
                    if (strcasecmp(value, "forget") == 0 || strcasecmp(value, "delete") == 0) {
                        hard = true;
                    }
                }
            }
            free(query);
        }
    }
    esp_err_t err = hard ? roster_forget_node(node_id) : roster_mark_offline(node_id, 0);
    if (err == ESP_ERR_NOT_FOUND) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "node");
        return ESP_FAIL;
    }
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "roster");
        return ESP_FAIL;
    }
    cJSON *resp = cJSON_CreateObject();
    if (!resp) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json");
        return ESP_FAIL;
    }
    cJSON_AddNumberToObject(resp, "node_id", node_id);
    cJSON_AddStringToObject(resp, "result", hard ? "forgotten" : "offline");
    return json_reply_cjson(req, resp);
}

static esp_err_t api_can_node_delete_options(httpd_req_t *req)
{
    return cors_handle_options(req);
}

static esp_err_t api_can_node_identify_post(httpd_req_t *req)
{
    if (!check_bearer(req)) {
        httpd_resp_send_err(req, 401, "token");
        return ESP_FAIL;
    }
    uint8_t node_id = 0;
    if (!parse_can_node_id(req->uri, &node_id) || node_id == 0) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "node");
        return ESP_FAIL;
    }
    if (!roster_node_exists(node_id)) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "node");
        return ESP_FAIL;
    }
    cors_apply(req);
    char body[128];
    size_t body_len = 0;
    if (read_body_to_buf(req, body, sizeof(body), &body_len) != ESP_OK) {
        httpd_resp_send_err(req, 400, "body");
        return ESP_FAIL;
    }
    cJSON *json = cJSON_ParseWithLength(body, body_len);
    if (!json) {
        httpd_resp_send_err(req, 400, "json");
        return ESP_FAIL;
    }
    cJSON *jen = cJSON_GetObjectItemCaseSensitive(json, "enable");
    if (!cJSON_IsBool(jen)) {
        cJSON_Delete(json);
        httpd_resp_send_err(req, 400, "enable");
        return ESP_FAIL;
    }
    bool enable = cJSON_IsTrue(jen);
    cJSON_Delete(json);
    bool changed = false;
    esp_err_t err = pdo_send_led_identify_toggle(node_id, enable, &changed);
    if (err == ESP_ERR_NOT_FOUND) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "node");
        return ESP_FAIL;
    }
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "pdo");
        return ESP_FAIL;
    }
    bool final_state = false;
    roster_get_identify(node_id, &final_state);

    cJSON *resp = cJSON_CreateObject();
    if (!resp) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json");
        return ESP_FAIL;
    }
    cJSON_AddNumberToObject(resp, "node_id", node_id);
    cJSON_AddBoolToObject(resp, "identify_active", final_state);

    esp_err_t send_err = json_reply_cjson(req, resp);

    cJSON *evt = cJSON_CreateObject();
    if (evt) {
        cJSON_AddNumberToObject(evt, "node_id", node_id);
        cJSON_AddBoolToObject(evt, "identify_active", final_state);
        web_server_ws_broadcast_event("identify_state", evt);
    }

    (void)changed;
    return send_err;
}

static esp_err_t api_can_node_identify_options(httpd_req_t *req)
{
    return cors_handle_options(req);
}
// ----- END CANBUS -------------------------------------

static void web_tls_state_reset_custom(void){
    s_web_tls_state.custom_available = false;
    s_web_tls_state.custom_valid = false;
    s_web_tls_state.custom_subject[0] = '\0';
    s_web_tls_state.custom_issuer[0] = '\0';
    s_web_tls_state.custom_not_before[0] = '\0';
    s_web_tls_state.custom_not_after[0] = '\0';
    s_web_tls_state.custom_fingerprint[0] = '\0';
    s_web_tls_state.custom_installed_iso[0] = '\0';
    s_web_tls_state.custom_installed_at = 0;
}

static void web_tls_state_set_last_error(const char* msg){
    if (!msg) msg = "";
    strlcpy(s_web_tls_state.last_error, msg, sizeof(s_web_tls_state.last_error));
}

static void web_tls_clear_dynamic(void){
    if (s_tls_material.dyn_cert){
        uint8_t *ptr = s_tls_material.dyn_cert;
        free(ptr);
        if (s_tls_material.cert == ptr){
            s_tls_material.cert = NULL;
            s_tls_material.cert_len = 0;
        }
        s_tls_material.dyn_cert = NULL;
        s_tls_material.dyn_cert_len = 0;
    }
    if (s_tls_material.dyn_key){
        uint8_t *ptr = s_tls_material.dyn_key;
        free(ptr);
        if (s_tls_material.key == ptr){
            s_tls_material.key = NULL;
            s_tls_material.key_len = 0;
        }
        s_tls_material.dyn_key = NULL;
        s_tls_material.dyn_key_len = 0;
    }
}

static void format_x509_time(const mbedtls_x509_time* t, char out[32]){
    if (!out) return;
    if (!t || t->year == 0){ out[0] = '\0'; return; }
    snprintf(out, 32, "%04d-%02d-%02dT%02d:%02d:%02dZ",
             t->year, t->mon, t->day, t->hour, t->min, t->sec);
}

static void format_time_iso(uint64_t ts, char out[32]){
    if (!out) return;
    if (ts == 0){ out[0] = '\0'; return; }
    time_t t = (time_t)ts;
    struct tm tm_info;
    if (!gmtime_r(&t, &tm_info)){ out[0] = '\0'; return; }
    strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", &tm_info);
}

static void web_tls_fill_cert_info(const mbedtls_x509_crt* crt,
                                   char* subject, size_t subject_len,
                                   char* issuer, size_t issuer_len,
                                   char* not_before, size_t nb_len,
                                   char* not_after, size_t na_len,
                                   char* fingerprint, size_t fp_len){
    if (!crt) return;
    if (subject && subject_len){
        int rc = mbedtls_x509_dn_gets(subject, subject_len, &crt->subject);
        if (rc < 0) subject[0] = '\0';
    }
    if (issuer && issuer_len){
        int rc = mbedtls_x509_dn_gets(issuer, issuer_len, &crt->issuer);
        if (rc < 0) issuer[0] = '\0';
    }
    if (not_before && nb_len) format_x509_time(&crt->valid_from, not_before);
    if (not_after && na_len) format_x509_time(&crt->valid_to, not_after);
    if (fingerprint && fp_len){
        fingerprint[0] = '\0';
        const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        if (md){
            unsigned char hash[32];
            if (mbedtls_md(md, crt->raw.p, crt->raw.len, hash) == 0){
                size_t off = 0;
                for (size_t i = 0; i < sizeof(hash) && off + 3 < fp_len; ++i){
                    int n = snprintf(fingerprint + off, fp_len - off,
                                     (i + 1 < sizeof(hash)) ? "%02X:" : "%02X", hash[i]);
                    if (n < 0) break;
                    off += (size_t)n;
                    if (off >= fp_len) break;
                }
            }
        }
    }
}

static void web_tls_state_set_active_from_crt(const mbedtls_x509_crt* crt, web_tls_source_t src){
    if (!crt) return;
    s_web_tls_state.active_source = src;
    s_web_tls_state.using_builtin = (src != WEB_TLS_SRC_CUSTOM);
    web_tls_fill_cert_info(crt,
                           s_web_tls_state.active_subject, sizeof(s_web_tls_state.active_subject),
                           s_web_tls_state.active_issuer, sizeof(s_web_tls_state.active_issuer),
                           s_web_tls_state.active_not_before, sizeof(s_web_tls_state.active_not_before),
                           s_web_tls_state.active_not_after, sizeof(s_web_tls_state.active_not_after),
                           s_web_tls_state.active_fingerprint, sizeof(s_web_tls_state.active_fingerprint));
}

static void web_tls_state_set_custom_from_crt(const mbedtls_x509_crt* crt, uint64_t installed_at){
    if (!crt){
        web_tls_state_reset_custom();
        return;
    }
    s_web_tls_state.custom_available = true;
    s_web_tls_state.custom_valid = true;
    web_tls_fill_cert_info(crt,
                           s_web_tls_state.custom_subject, sizeof(s_web_tls_state.custom_subject),
                           s_web_tls_state.custom_issuer, sizeof(s_web_tls_state.custom_issuer),
                           s_web_tls_state.custom_not_before, sizeof(s_web_tls_state.custom_not_before),
                           s_web_tls_state.custom_not_after, sizeof(s_web_tls_state.custom_not_after),
                           s_web_tls_state.custom_fingerprint, sizeof(s_web_tls_state.custom_fingerprint));
    s_web_tls_state.custom_installed_at = installed_at;
    format_time_iso(installed_at, s_web_tls_state.custom_installed_iso);
}

// ----- Utilizzo certificati EXAMPLE --------------------------------
// static void web_tls_use_builtin(void){
//     web_tls_clear_dynamic();
//     s_tls_material.cert = (const uint8_t*)builtin_cert_pem;
//     s_tls_material.cert_len = sizeof(builtin_cert_pem);
//     s_tls_material.key = (const uint8_t*)builtin_key_pem;
//     s_tls_material.key_len = sizeof(builtin_key_pem);
//     s_tls_material.source = WEB_TLS_SRC_BUILTIN;

//     mbedtls_x509_crt crt; mbedtls_x509_crt_init(&crt);
//     if (mbedtls_x509_crt_parse(&crt, (const unsigned char*)builtin_cert_pem, sizeof(builtin_cert_pem)) == 0){
//         web_tls_state_set_active_from_crt(&crt, WEB_TLS_SRC_BUILTIN);
//         if (!s_web_tls_state.custom_available){
//             web_tls_state_reset_custom();
//         }
//     }
//     mbedtls_x509_crt_free(&crt);
// }

// ----- Utilizzo certificati REALI ----------------------------------
static void web_tls_use_builtin(void){
    web_tls_clear_dynamic();

    size_t cert_len = (size_t)(certs_server_cert_pem_end - certs_server_cert_pem_start);
    size_t key_len = (size_t)(certs_server_key_pem_end - certs_server_key_pem_start);

    uint8_t *cert = NULL;
    uint8_t *key = NULL;

    if (cert_len > 0){
        cert = malloc(cert_len + 1);
    }
    if (key_len > 0){
        key = malloc(key_len + 1);
    }

    if (!cert || !key){
        ESP_LOGE(TAG, "TLS: unable to allocate buffers for builtin material");
        free(cert);
        free(key);
        s_tls_material.cert = (const uint8_t*)builtin_cert_pem;
        s_tls_material.cert_len = sizeof(builtin_cert_pem);
        s_tls_material.key = (const uint8_t*)builtin_key_pem;
        s_tls_material.key_len = sizeof(builtin_key_pem);
    } else {
        memcpy(cert, certs_server_cert_pem_start, cert_len);
        cert[cert_len] = '\0';
        memcpy(key, certs_server_key_pem_start, key_len);
        key[key_len] = '\0';

        s_tls_material.dyn_cert = cert;
        s_tls_material.dyn_cert_len = cert_len + 1;
        s_tls_material.dyn_key = key;
        s_tls_material.dyn_key_len = key_len + 1;
        s_tls_material.cert = s_tls_material.dyn_cert;
        s_tls_material.cert_len = s_tls_material.dyn_cert_len;
        s_tls_material.key = s_tls_material.dyn_key;
        s_tls_material.key_len = s_tls_material.dyn_key_len;
    }
    s_tls_material.source = WEB_TLS_SRC_BUILTIN;

    mbedtls_x509_crt crt; 
    mbedtls_x509_crt_init(&crt);
    if (mbedtls_x509_crt_parse(&crt, (const unsigned char*)s_tls_material.cert, s_tls_material.cert_len) == 0){
        web_tls_state_set_active_from_crt(&crt, WEB_TLS_SRC_BUILTIN);
        if (!s_web_tls_state.custom_available) {
            web_tls_state_reset_custom();
        }
    }
    mbedtls_x509_crt_free(&crt);
}


static int web_tls_check_pk_pair(const mbedtls_pk_context* pub, const mbedtls_pk_context* prv){
    if (!pub || !prv) return MBEDTLS_ERR_PK_BAD_INPUT_DATA;

    mbedtls_entropy_context entropy; mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_context ctr_drbg; mbedtls_ctr_drbg_init(&ctr_drbg);
    const unsigned char pers[] = "web_tls_pair";

    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    pers, sizeof(pers) - 1);
    if (ret == 0){
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
        ret = mbedtls_pk_check_pair(pub, prv, mbedtls_ctr_drbg_random, &ctr_drbg);
#else
        ret = mbedtls_pk_check_pair(pub, prv);
#endif
    }

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

static esp_err_t web_tls_load_from_nvs(void){
    web_tls_state_set_last_error("");
    nvs_handle_t nvs = 0;
    esp_err_t err = nvs_open(WEB_TLS_NS, NVS_READONLY, &nvs);
    if (err != ESP_OK){
        web_tls_state_reset_custom();
        if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_ERR_NOT_FOUND;
        char msg[96];
        snprintf(msg, sizeof(msg), "nvs open: %s", esp_err_to_name(err));
        web_tls_state_set_last_error(msg);
        return err;
    }

    size_t cert_len = 0;
    err = nvs_get_blob(nvs, WEB_TLS_CERT_KEY, NULL, &cert_len);
    if (err != ESP_OK || cert_len == 0 || cert_len > WEB_TLS_MAX_PEM_LEN){
        nvs_close(nvs);
        web_tls_state_reset_custom();
        if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_ERR_NOT_FOUND;
        char msg[96];
        snprintf(msg, sizeof(msg), "cert blob: %s", esp_err_to_name(err));
        web_tls_state_set_last_error(msg);
        return (err == ESP_OK) ? ESP_ERR_INVALID_SIZE : err;
    }

    size_t key_len = 0;
    err = nvs_get_blob(nvs, WEB_TLS_PRIV_KEY, NULL, &key_len);
    if (err != ESP_OK || key_len == 0 || key_len > WEB_TLS_MAX_PEM_LEN){
        nvs_close(nvs);
        web_tls_state_reset_custom();
        if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_ERR_NOT_FOUND;
        char msg[96];
        snprintf(msg, sizeof(msg), "key blob: %s", esp_err_to_name(err));
        web_tls_state_set_last_error(msg);
        return (err == ESP_OK) ? ESP_ERR_INVALID_SIZE : err;
    }

    web_tls_state_reset_custom();
    s_web_tls_state.custom_available = true;
    s_web_tls_state.custom_valid = false;

    uint8_t *cert = calloc(1, cert_len + 1);
    uint8_t *key = calloc(1, key_len + 1);
    if (!cert || !key){
        nvs_close(nvs);
        free(cert); free(key);
        web_tls_state_set_last_error("no mem");
        return ESP_ERR_NO_MEM;
    }

    size_t tmp_len = cert_len;
    err = nvs_get_blob(nvs, WEB_TLS_CERT_KEY, cert, &tmp_len);
    if (err != ESP_OK || tmp_len != cert_len){
        nvs_close(nvs);
        free(cert); free(key);
        char msg[96];
        snprintf(msg, sizeof(msg), "cert read: %s", esp_err_to_name(err));
        web_tls_state_set_last_error(msg);
        return err != ESP_OK ? err : ESP_FAIL;
    }
    cert[cert_len] = '\0';

    tmp_len = key_len;
    err = nvs_get_blob(nvs, WEB_TLS_PRIV_KEY, key, &tmp_len);
    if (err != ESP_OK || tmp_len != key_len){
        nvs_close(nvs);
        free(cert); free(key);
        char msg[96];
        snprintf(msg, sizeof(msg), "key read: %s", esp_err_to_name(err));
        web_tls_state_set_last_error(msg);
        return err != ESP_OK ? err : ESP_FAIL;
    }
    key[key_len] = '\0';

    uint64_t installed_at = 0;
    nvs_get_u64(nvs, WEB_TLS_TS_KEY, &installed_at);
    nvs_close(nvs);

    if (!strstr((char*)cert, "BEGIN CERTIFICATE") || !strstr((char*)cert, "END CERTIFICATE")){
        free(cert); free(key);
        web_tls_state_reset_custom();
        s_web_tls_state.custom_available = true;
        web_tls_state_set_last_error("cert PEM invalid");
        return ESP_ERR_INVALID_RESPONSE;
    }
    if (!strstr((char*)key, "BEGIN") || !strstr((char*)key, "PRIVATE KEY")){
        free(cert); free(key);
        web_tls_state_reset_custom();
        s_web_tls_state.custom_available = true;
        web_tls_state_set_last_error("key PEM invalid");
        return ESP_ERR_INVALID_RESPONSE;
    }

    mbedtls_x509_crt crt; mbedtls_x509_crt_init(&crt);
    int ret = mbedtls_x509_crt_parse(&crt, cert, cert_len + 1);
    if (ret != 0){
        free(cert); free(key);
        web_tls_state_reset_custom();
        s_web_tls_state.custom_available = true;
        char msg[96]; mbedtls_strerror(ret, msg, sizeof(msg));
        web_tls_state_set_last_error(msg);
        mbedtls_x509_crt_free(&crt);
        return ESP_ERR_INVALID_RESPONSE;
    }

    mbedtls_pk_context pk; mbedtls_pk_init(&pk);
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    ret = mbedtls_pk_parse_key(&pk, key, key_len + 1, NULL, 0, NULL, NULL);
#else
    ret = mbedtls_pk_parse_key(&pk, key, key_len + 1, NULL, 0);
#endif
    if (ret != 0){
        free(cert); free(key);
        char msg[96]; mbedtls_strerror(ret, msg, sizeof(msg));
        web_tls_state_reset_custom();
        s_web_tls_state.custom_available = true;
        web_tls_state_set_last_error(msg);
        mbedtls_x509_crt_free(&crt);
        mbedtls_pk_free(&pk);
        return ESP_ERR_INVALID_RESPONSE;
    }

    ret = web_tls_check_pk_pair(&crt.pk, &pk);
    if (ret != 0){
        free(cert); free(key);
        char msg[96]; mbedtls_strerror(ret, msg, sizeof(msg));
        web_tls_state_set_last_error("cert/key mismatch");
        web_tls_state_reset_custom();
        s_web_tls_state.custom_available = true;
        mbedtls_x509_crt_free(&crt);
        mbedtls_pk_free(&pk);
        return ESP_ERR_INVALID_RESPONSE;
    }

    web_tls_clear_dynamic();
    s_tls_material.dyn_cert = cert;
    s_tls_material.dyn_cert_len = cert_len + 1;
    s_tls_material.dyn_key = key;
    s_tls_material.dyn_key_len = key_len + 1;
    s_tls_material.cert = s_tls_material.dyn_cert;
    s_tls_material.cert_len = s_tls_material.dyn_cert_len;
    s_tls_material.key = s_tls_material.dyn_key;
    s_tls_material.key_len = s_tls_material.dyn_key_len;
    s_tls_material.source = WEB_TLS_SRC_CUSTOM;

    web_tls_state_set_custom_from_crt(&crt, installed_at);
    web_tls_state_set_active_from_crt(&crt, WEB_TLS_SRC_CUSTOM);
    web_tls_state_set_last_error("");

    mbedtls_pk_free(&pk);
    mbedtls_x509_crt_free(&crt);
    return ESP_OK;
}

static esp_err_t web_tls_prepare_material(void){
    esp_err_t err = web_tls_load_from_nvs();
    if (err == ESP_OK){
        ESP_LOGI(TAG, "TLS: using persisted certificate");
        return ESP_OK;
    }
    if (err == ESP_ERR_NOT_FOUND){
        ESP_LOGI(TAG, "TLS: no persisted certificate, using builtin default");
        web_tls_use_builtin();
        return ESP_OK;
    }
    ESP_LOGW(TAG, "TLS: persisted material unavailable (%s), using builtin", esp_err_to_name(err));
    web_tls_use_builtin();
    return err;
}

static esp_err_t read_body_alloc(httpd_req_t* req, char** out, size_t* out_len, size_t max_len){
    if (!req || !out) return ESP_ERR_INVALID_ARG;
    size_t total = req->content_len;
    if (total == 0 || total > max_len) return ESP_ERR_INVALID_SIZE;
    char *buf = calloc(1, total + 1);
    if (!buf) return ESP_ERR_NO_MEM;
    size_t off = 0;
    while (off < total){
        int r = httpd_req_recv(req, buf + off, total - off);
        if (r <= 0){
            free(buf);
            return ESP_FAIL;
        }
        off += (size_t)r;
    }
    buf[off] = '\0';
    *out = buf;
    if (out_len) *out_len = off;
    return ESP_OK;
}

static esp_err_t decode_base64_alloc(const char* b64, uint8_t** out, size_t* out_len){
    if (!b64 || !out) return ESP_ERR_INVALID_ARG;
    size_t in_len = strlen(b64);
    size_t needed = 0;
    int rc = mbedtls_base64_decode(NULL, 0, &needed, (const unsigned char*)b64, in_len);
    if (rc != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL && rc != 0){
        return ESP_ERR_INVALID_ARG;
    }
    uint8_t *buf = calloc(1, needed + 1);
    if (!buf) return ESP_ERR_NO_MEM;
    size_t out_sz = 0;
    rc = mbedtls_base64_decode(buf, needed, &out_sz, (const unsigned char*)b64, in_len);
    if (rc != 0){
        free(buf);
        return ESP_ERR_INVALID_ARG;
    }
    buf[out_sz] = '\0';
    *out = buf;
    if (out_len) *out_len = out_sz;
    return ESP_OK;
}

static esp_err_t web_tls_validate_pair(const uint8_t* cert, size_t cert_len,
                                       const uint8_t* key, size_t key_len,
                                       mbedtls_x509_crt* crt_out,
                                       char* errbuf, size_t errbuf_len){
    if (!cert || !key || !crt_out) return ESP_ERR_INVALID_ARG;
    mbedtls_x509_crt_init(crt_out);
    int ret = mbedtls_x509_crt_parse(crt_out, cert, cert_len + 1);
    if (ret != 0){
        if (errbuf) mbedtls_strerror(ret, errbuf, errbuf_len);
        mbedtls_x509_crt_free(crt_out);
        return ESP_ERR_INVALID_RESPONSE;
    }
    mbedtls_pk_context pk; mbedtls_pk_init(&pk);
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    ret = mbedtls_pk_parse_key(&pk, key, key_len + 1, NULL, 0, NULL, NULL);
#else
    ret = mbedtls_pk_parse_key(&pk, key, key_len + 1, NULL, 0);
#endif
    if (ret != 0){
        if (errbuf) mbedtls_strerror(ret, errbuf, errbuf_len);
        mbedtls_pk_free(&pk);
        mbedtls_x509_crt_free(crt_out);
        return ESP_ERR_INVALID_RESPONSE;
    }
    ret = web_tls_check_pk_pair(&crt_out->pk, &pk);
    mbedtls_pk_free(&pk);
    if (ret != 0){
        if (errbuf) snprintf(errbuf, errbuf_len, "cert/key mismatch");
        mbedtls_x509_crt_free(crt_out);
        return ESP_ERR_INVALID_RESPONSE;
    }
    return ESP_OK;
}

// Se non stai usando davvero HTTPS qui, usa httpd_start come wrapper
static esp_err_t https_start(httpd_handle_t* s, httpd_config_t* cfg){
    if (!s || !cfg) return ESP_ERR_INVALID_ARG;
    esp_err_t tls_err = web_tls_prepare_material();
    httpd_ssl_config_t ssl_cfg = HTTPD_SSL_CONFIG_DEFAULT();
    ssl_cfg.httpd = *cfg;
    ssl_cfg.servercert = s_tls_material.cert;
    ssl_cfg.servercert_len = s_tls_material.cert_len;
    ssl_cfg.prvtkey_pem = s_tls_material.key;
    ssl_cfg.prvtkey_len = s_tls_material.key_len;
    ssl_cfg.port_secure = cfg->server_port;
    ssl_cfg.httpd.server_port = cfg->server_port;
    esp_err_t err = httpd_ssl_start(s, &ssl_cfg);
    if (err != ESP_OK){
        ESP_LOGE(TAG, "httpd_ssl_start failed: %s", esp_err_to_name(err));
        return err;
    }
    if (tls_err != ESP_OK && tls_err != ESP_ERR_NOT_FOUND){
        ESP_LOGW(TAG, "TLS material fallback in use (%s)", esp_err_to_name(tls_err));
    }
    return ESP_OK;
}

// Stub TOTP (compila; implementa poi quello reale oppure rimuovi gli endpoint se non ti servono)
static bool totp_verify_b32(const char* b32, const char* otp, int step, int window){
    if (!b32 || !otp) return false;
    if (step <= 0) return false;
    if (window < 0) window = 0;
    char clean[64]; size_t w = 0;
    for (const char* p=b32; *p && w+1<sizeof(clean); ++p){
        char c = *p;
        if (c==' ' || c=='-' || c=='\t') continue;
        if (c>='a' && c<='z') c = (char)(c - ('a'-'A'));
        clean[w++] = c;
    }
    clean[w] = 0;
    if (!clean[0]) return false;
    return totp_check(clean, otp, step, window);
}

static void nvs_get_str_def(nvs_handle_t h, const char* key, char* out, size_t cap, const char* def){
    size_t len = cap;
    esp_err_t e = nvs_get_str(h, key, out, &len);
    if (e != ESP_OK) { strncpy(out, def?def:"", cap-1); out[cap-1]=0; }
}
static uint32_t nvs_get_u32_def(nvs_handle_t h, const char* key, uint32_t def){
    uint32_t v=def; nvs_get_u32(h, key, &v); return v;
}

static void trim_inplace(char* s){
    if (!s) return;
    char* start = s;
    while (*start && isspace((unsigned char)*start)) start++;
    char* end = start + strlen(start);
    while (end > start && isspace((unsigned char)end[-1])) --end;
    *end = '\0';
    if (start != s) memmove(s, start, (size_t)(end - start + 1));
}

static void provisioning_set_ui_url(const char* url){
    if (!url || !url[0]){
        strlcpy(s_cloudflare_ui_url, DEFAULT_CF_UI_URL, sizeof(s_cloudflare_ui_url));
        return;
    }
    strlcpy(s_cloudflare_ui_url, url, sizeof(s_cloudflare_ui_url));
    trim_inplace(s_cloudflare_ui_url);
    if (!s_cloudflare_ui_url[0]){
        strlcpy(s_cloudflare_ui_url, DEFAULT_CF_UI_URL, sizeof(s_cloudflare_ui_url));
    }
}

static void provisioning_load_state(void){
    s_provisioned = false;
    provisioning_set_ui_url(DEFAULT_CF_UI_URL);
    nvs_handle_t nvs;
    if (nvs_open("sys", NVS_READONLY, &nvs) == ESP_OK){
        uint8_t flag = 0;
        if (nvs_get_u8(nvs, "provisioned", &flag) == ESP_OK){
            s_provisioned = flag != 0;
        }
        char url_buf[sizeof(s_cloudflare_ui_url)];
        nvs_get_str_def(nvs, "cf_ui", url_buf, sizeof(url_buf), DEFAULT_CF_UI_URL);
        provisioning_set_ui_url(url_buf);
        nvs_close(nvs);
    }
}

static esp_err_t provisioning_set_flag(bool value){
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("sys", NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;
    err = nvs_set_u8(nvs, "provisioned", value ? 1 : 0);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    if (err == ESP_OK) s_provisioned = value;
    return err;
}

static void provisioning_load_general(provisioning_general_config_t* cfg){
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    nvs_handle_t nvs;
    if (nvs_open("sys", NVS_READONLY, &nvs) == ESP_OK){
        nvs_get_str_def(nvs, "central_name", cfg->central_name, sizeof(cfg->central_name), "");
        nvs_close(nvs);
    }
}

static const char MQTT_PASSWORD_POLICY_ERROR[] = "Password MQTT non valida: usa 12-63 caratteri con lettere maiuscole, minuscole, numeri e simboli. Lascia il campo vuoto se il broker non richiede autenticazione.";

static bool mqtt_password_is_valid(const char* pass){
    if (!pass) return false;
    size_t len = strlen(pass);
    if (len == 0) return true;
    if (len < 12 || len > 63) return false;
    bool has_upper = false;
    bool has_lower = false;
    bool has_digit = false;
    bool has_special = false;
    for (size_t i = 0; i < len; ++i){
        unsigned char ch = (unsigned char)pass[i];
        if (ch < 0x20 || ch == 0x7f) return false;
        if (islower(ch)) has_lower = true;
        else if (isupper(ch)) has_upper = true;
        else if (isdigit(ch)) has_digit = true;
        else has_special = true;
    }
    return has_lower && has_upper && has_digit && has_special;
}

static esp_netif_t* provisioning_get_primary_netif(void)
{
    esp_netif_t* netif = eth_get_netif();
    if (netif) return netif;
    netif = esp_netif_get_handle_from_ifkey("ETH_DEF");
    if (netif) return netif;
    return esp_netif_get_handle_from_ifkey("ETH");
}

static bool provisioning_ip4_from_str(const char* str, esp_ip4_addr_t* out)
{
    if (!str || !out) return false;
    ip4_addr_t tmp = {0};
    if (!ip4addr_aton(str, &tmp)) return false;
    out->addr = tmp.addr;
    return true;
}

static void provisioning_apply_netif_config(const provisioning_net_config_t* cfg)
{
    if (!cfg) return;
    esp_netif_t* netif = provisioning_get_primary_netif();
    if (!netif) return;

    esp_err_t err = ESP_OK;
    const char* host = cfg->hostname[0] ? cfg->hostname : NULL;
    err = esp_netif_set_hostname(netif, host);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "esp_netif_set_hostname failed: %s", esp_err_to_name(err));
    }

    if (cfg->dhcp) {
        err = esp_netif_dhcpc_stop(netif);
        if (err != ESP_OK && err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED) {
            ESP_LOGW(TAG, "dhcpc_stop: %s", esp_err_to_name(err));
        }
        err = esp_netif_dhcpc_start(netif);
        if (err != ESP_OK && err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STARTED) {
            ESP_LOGW(TAG, "dhcpc_start: %s", esp_err_to_name(err));
        }
        return;
    }

    err = esp_netif_dhcpc_stop(netif);
    if (err != ESP_OK && err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED) {
        ESP_LOGW(TAG, "dhcpc_stop(static): %s", esp_err_to_name(err));
    }

    esp_netif_ip_info_t info = {0};
    bool have_ip = provisioning_ip4_from_str(cfg->ip, &info.ip);
    bool have_mask = provisioning_ip4_from_str(cfg->mask, &info.netmask);
    bool have_gw = provisioning_ip4_from_str(cfg->gw, &info.gw);
    if (have_ip && have_mask) {
        if (!have_gw) {
            info.gw.addr = 0;
        }
        err = esp_netif_set_ip_info(netif, &info);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "set_ip_info failed: %s", esp_err_to_name(err));
        }
    } else {
        ESP_LOGW(TAG, "static IP config incomplete (ip=%s, mask=%s)", cfg->ip, cfg->mask);
    }

    esp_netif_dns_info_t dns = {0};
    if (provisioning_ip4_from_str(cfg->dns, &dns.ip.u_addr.ip4)) {
        dns.ip.type = IPADDR_TYPE_V4;
        err = esp_netif_set_dns_info(netif, ESP_NETIF_DNS_MAIN, &dns);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "set_dns_info failed: %s", esp_err_to_name(err));
        }
    }
}

static void provisioning_schedule_netif_apply(const provisioning_net_config_t* cfg);

static void provisioning_netif_apply_timer_cb(void* arg)
{
    (void)arg;
    provisioning_net_config_t cfg = {0};
    bool have_cfg = false;

    portENTER_CRITICAL(&s_net_apply_lock);
    if (s_net_apply_cfg_valid) {
        cfg = s_net_apply_cfg;
        s_net_apply_cfg_valid = false;
        have_cfg = true;
    }
    portEXIT_CRITICAL(&s_net_apply_lock);

    if (have_cfg) {
        provisioning_apply_netif_config(&cfg);
    }
}

static esp_err_t provisioning_ensure_netif_timer(void)
{
    if (s_net_apply_timer) {
        return ESP_OK;
    }

    const esp_timer_create_args_t args = {
        .callback = provisioning_netif_apply_timer_cb,
        .arg = NULL,
        .dispatch_method = ESP_TIMER_TASK,
        .name = "net_apply",
        .skip_unhandled_events = true,
    };

    esp_err_t err = esp_timer_create(&args, &s_net_apply_timer);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_timer_create(net_apply) failed: %s", esp_err_to_name(err));
        return err;
    }
    return ESP_OK;
}

static void provisioning_schedule_netif_apply(const provisioning_net_config_t* cfg)
{
    if (!cfg) {
        return;
    }

    if (provisioning_ensure_netif_timer() != ESP_OK) {
        return;
    }

    portENTER_CRITICAL(&s_net_apply_lock);
    s_net_apply_cfg = *cfg;
    s_net_apply_cfg_valid = true;
    portEXIT_CRITICAL(&s_net_apply_lock);

    if (s_net_apply_timer) {
        esp_err_t err = esp_timer_stop(s_net_apply_timer);
        if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
            ESP_LOGW(TAG, "esp_timer_stop(net_apply) failed: %s", esp_err_to_name(err));
        }
        err = esp_timer_start_once(s_net_apply_timer, 200 * 1000);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "esp_timer_start_once(net_apply) failed: %s", esp_err_to_name(err));
        }
    }
}

static void provisioning_load_net(provisioning_net_config_t* cfg){
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->dhcp = true;
    nvs_handle_t nvs;
    if (nvs_open("sys", NVS_READONLY, &nvs) == ESP_OK){
        nvs_get_str_def(nvs, "hostname", cfg->hostname, sizeof(cfg->hostname), "");
        nvs_get_str_def(nvs, "ip",   cfg->ip,   sizeof(cfg->ip),   "");
        nvs_get_str_def(nvs, "gw",   cfg->gw,   sizeof(cfg->gw),   "");
        nvs_get_str_def(nvs, "mask", cfg->mask, sizeof(cfg->mask), "");
        nvs_get_str_def(nvs, "dns",  cfg->dns,  sizeof(cfg->dns),  "");
        cfg->dhcp = nvs_get_u32_def(nvs, "dhcp", 1) != 0;
        nvs_close(nvs);
    }
    esp_netif_t* netif = provisioning_get_primary_netif();
    if (!netif) return;

    const char *hostname = NULL;
    if (esp_netif_get_hostname(netif, &hostname) == ESP_OK && hostname && hostname[0]) {    
        strlcpy(cfg->hostname, hostname, sizeof(cfg->hostname));
    }

    if (!cfg->dhcp) return;

    esp_netif_ip_info_t info = {0};
    if (esp_netif_get_ip_info(netif, &info) == ESP_OK){
        ip4addr_ntoa_r((const ip4_addr_t*)&info.ip,   cfg->ip,   sizeof(cfg->ip));
        ip4addr_ntoa_r((const ip4_addr_t*)&info.gw,   cfg->gw,   sizeof(cfg->gw));
        ip4addr_ntoa_r((const ip4_addr_t*)&info.netmask, cfg->mask, sizeof(cfg->mask));
    }

    esp_netif_dns_info_t dns = {0};
    if (esp_netif_get_dns_info(netif, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK && dns.ip.type == IPADDR_TYPE_V4){
        ip4addr_ntoa_r((const ip4_addr_t*)&dns.ip.u_addr.ip4, cfg->dns, sizeof(cfg->dns));
    }
}

static void provisioning_load_mqtt(provisioning_mqtt_config_t* cfg){
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    strlcpy(cfg->uri, CONFIG_APP_CLOUD_MQTT_URI, sizeof(cfg->uri));
    cfg->keepalive = CONFIG_APP_CLOUD_KEEPALIVE;
    nvs_handle_t nvs;
    if (nvs_open("sys", NVS_READONLY, &nvs) == ESP_OK){
        nvs_get_str_def(nvs, "mq_uri",  cfg->uri,  sizeof(cfg->uri),  CONFIG_APP_CLOUD_MQTT_URI);
        nvs_get_str_def(nvs, "mq_pass", cfg->pass, sizeof(cfg->pass), "");
        cfg->keepalive = nvs_get_u32_def(nvs, "mq_keep", CONFIG_APP_CLOUD_KEEPALIVE);
        nvs_close(nvs);
    }
    char device_id[DEVICE_ID_MAX] = {0};
    make_device_id(device_id);
    strlcpy(cfg->cid, device_id, sizeof(cfg->cid));
    strlcpy(cfg->user, device_id, sizeof(cfg->user));
}

static void provisioning_load_cloudflare(provisioning_cloudflare_config_t* cfg){
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    strlcpy(cfg->ui_url, s_cloudflare_ui_url, sizeof(cfg->ui_url));
    nvs_handle_t nvs;
    if (nvs_open("sys", NVS_READONLY, &nvs) == ESP_OK){
        char url_buf[sizeof(cfg->ui_url)];
        nvs_get_str_def(nvs, "cf_ui", url_buf, sizeof(url_buf), s_cloudflare_ui_url);
        provisioning_set_ui_url(url_buf);
        strlcpy(cfg->ui_url, s_cloudflare_ui_url, sizeof(cfg->ui_url));
        nvs_close(nvs);
    }
}

static esp_err_t only_admin(httpd_req_t* req){
    if (!s_provisioned) return ESP_OK;
    user_info_t u;
    if (!auth_check_bearer(req,&u) || u.role != ROLE_ADMIN){
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden");
    }
    return ESP_OK;
}

// ---- /api/sys/net GET/POST ----
static esp_err_t sys_net_get(httpd_req_t* req){
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    provisioning_net_config_t cfg; provisioning_load_net(&cfg);
    cJSON* root = cJSON_CreateObject();
    if (!root) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
    cJSON_AddStringToObject(root, "hostname", cfg.hostname);
    cJSON_AddBoolToObject(root, "dhcp", cfg.dhcp);
    cJSON_AddStringToObject(root, "ip", cfg.ip);
    cJSON_AddStringToObject(root, "gw", cfg.gw);
    cJSON_AddStringToObject(root, "mask", cfg.mask);
    cJSON_AddStringToObject(root, "dns", cfg.dns);
    return json_reply_cjson(req, root);
}

static esp_err_t sys_net_post(httpd_req_t* req){
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    char body[256]; size_t bl=0;
    if (read_body_to_buf(req, body, sizeof(body), &bl)!=ESP_OK) return httpd_resp_send_err(req,400,"body"), ESP_FAIL;
    cJSON* j = cJSON_ParseWithLength(body, bl);
    if (!j) return httpd_resp_send_err(req,400,"json"), ESP_FAIL;
    provisioning_net_config_t cfg; provisioning_load_net(&cfg);
    const cJSON* jd = cJSON_GetObjectItemCaseSensitive(j,"dhcp");
    const cJSON* jip= cJSON_GetObjectItemCaseSensitive(j,"ip");
    const cJSON* jgw= cJSON_GetObjectItemCaseSensitive(j,"gw");
    const cJSON* jmk= cJSON_GetObjectItemCaseSensitive(j,"mask");
    const cJSON* jdn= cJSON_GetObjectItemCaseSensitive(j,"dns");
    const cJSON* jhn= cJSON_GetObjectItemCaseSensitive(j,"hostname");

    nvs_handle_t nvs; if (nvs_open("sys", NVS_READWRITE, &nvs)!=ESP_OK){ cJSON_Delete(j); return httpd_resp_send_err(req,500,"nvs"), ESP_FAIL; }
    if (cJSON_IsBool(jd))   nvs_set_u32(nvs,"dhcp", cJSON_IsTrue(jd)?1:0);
    if (cJSON_IsString(jip))nvs_set_str(nvs,"ip",   jip->valuestring);
    if (cJSON_IsString(jgw))nvs_set_str(nvs,"gw",   jgw->valuestring);
    if (cJSON_IsString(jmk))nvs_set_str(nvs,"mask", jmk->valuestring);
    if (cJSON_IsString(jdn))nvs_set_str(nvs,"dns",  jdn->valuestring);
    if (cJSON_IsString(jhn)){
        strlcpy(cfg.hostname, jhn->valuestring, sizeof(cfg.hostname));
        nvs_set_str(nvs,"hostname", jhn->valuestring);
    }
    if (cJSON_IsBool(jd)){
        cfg.dhcp = cJSON_IsTrue(jd);
        nvs_set_u32(nvs,"dhcp", cfg.dhcp?1:0);
    }
    if (cJSON_IsString(jip)){
        strlcpy(cfg.ip, jip->valuestring, sizeof(cfg.ip));
        nvs_set_str(nvs,"ip", jip->valuestring);
    }
    if (cJSON_IsString(jgw)){
        strlcpy(cfg.gw, jgw->valuestring, sizeof(cfg.gw));
        nvs_set_str(nvs,"gw", jgw->valuestring);
    }
    if (cJSON_IsString(jmk)){
        strlcpy(cfg.mask, jmk->valuestring, sizeof(cfg.mask));
        nvs_set_str(nvs,"mask", jmk->valuestring);
    }
    if (cJSON_IsString(jdn)){
        strlcpy(cfg.dns, jdn->valuestring, sizeof(cfg.dns));
        nvs_set_str(nvs,"dns", jdn->valuestring);
    }
    nvs_commit(nvs); nvs_close(nvs); cJSON_Delete(j);

    esp_err_t resp_err = json_reply(req, "{\"ok\":true}");
    if (resp_err != ESP_OK) {
        ESP_LOGW(TAG, "sys_net_post response failed: %s", esp_err_to_name(resp_err));
    }
    provisioning_schedule_netif_apply(&cfg);
    return resp_err;
}

// ---- /api/sys/mqtt GET/POST ----
static esp_err_t sys_mqtt_get(httpd_req_t* req){
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    provisioning_mqtt_config_t cfg; provisioning_load_mqtt(&cfg);
    cJSON* root = cJSON_CreateObject();
    if (!root) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
    cJSON_AddStringToObject(root, "uri", cfg.uri);
    cJSON_AddStringToObject(root, "cid", cfg.cid);
    cJSON_AddStringToObject(root, "user", cfg.user);
    bool has_pass = cfg.pass[0] != '\0';
    cJSON_AddStringToObject(root, "pass", has_pass ? "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022" : "");
    cJSON_AddBoolToObject(root, "has_pass", has_pass);
    cJSON_AddNumberToObject(root, "keepalive", cfg.keepalive);
    cJSON_AddStringToObject(root, "device_id", cfg.cid);
    cJSON_AddStringToObject(root, "default_uri", CONFIG_APP_CLOUD_MQTT_URI);
    cJSON_AddNumberToObject(root, "default_keepalive", CONFIG_APP_CLOUD_KEEPALIVE);
    return json_reply_cjson(req, root);
}

static esp_err_t sys_mqtt_reveal_post(httpd_req_t* req){
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;

    char admin[32] = {0};
    if (!current_user_from_req(req, admin, sizeof(admin))){
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"), ESP_FAIL;
    }

    char body[128]; size_t bl = 0;
    if (read_body_to_buf(req, body, sizeof(body), &bl)!=ESP_OK){
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "body"), ESP_FAIL;
    }

    cJSON* root = cJSON_ParseWithLength(body, bl);
    if (!root){
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "json"), ESP_FAIL;
    }

    const cJSON* jpass = cJSON_GetObjectItemCaseSensitive(root, "password");
    const char* admin_pass = (cJSON_IsString(jpass) && jpass->valuestring) ? jpass->valuestring : NULL;
    if (!admin_pass || admin_pass[0] == '\0'){
        cJSON_Delete(root);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "password"), ESP_FAIL;
    }

    bool ok = auth_verify_password(admin, admin_pass);
    cJSON_Delete(root);
    if (!ok){
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "bad pass"), ESP_FAIL;
    }

    provisioning_mqtt_config_t cfg; provisioning_load_mqtt(&cfg);
    cJSON* resp = cJSON_CreateObject();
    if (!resp){
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
    }
    cJSON_AddStringToObject(resp, "pass", cfg.pass);
    cJSON_AddBoolToObject(resp, "has_pass", cfg.pass[0] != '\0');
    return json_reply_cjson(req, resp);
}

static esp_err_t sys_mqtt_post(httpd_req_t* req){
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    char body[256]; size_t bl=0;
    if (read_body_to_buf(req, body, sizeof(body), &bl)!=ESP_OK) return httpd_resp_send_err(req,400,"body"), ESP_FAIL;
    cJSON* j = cJSON_ParseWithLength(body, bl);
    if (!j) return httpd_resp_send_err(req,400,"json"), ESP_FAIL;
    const cJSON* juri=cJSON_GetObjectItemCaseSensitive(j,"uri");
    const cJSON* jpw =cJSON_GetObjectItemCaseSensitive(j,"pass");
    const cJSON* jka =cJSON_GetObjectItemCaseSensitive(j,"keepalive");
    const char* pass = NULL;
    if (cJSON_IsString(jpw) && jpw->valuestring) pass = jpw->valuestring;
    if (pass && !mqtt_password_is_valid(pass)){
        cJSON_Delete(j);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, MQTT_PASSWORD_POLICY_ERROR), ESP_FAIL;
    }
    char device_id[DEVICE_ID_MAX] = {0};
    make_device_id(device_id);
    nvs_handle_t nvs; if (nvs_open("sys", NVS_READWRITE, &nvs)!=ESP_OK){ cJSON_Delete(j); return httpd_resp_send_err(req,500,"nvs"), ESP_FAIL; }
    if (cJSON_IsString(juri)) nvs_set_str(nvs,"mq_uri", juri->valuestring);
    nvs_set_str(nvs,"mq_cid", device_id);
    nvs_set_str(nvs,"mq_user", device_id);
    if (pass) nvs_set_str(nvs,"mq_pass",pass);
    if (cJSON_IsNumber(jka)) nvs_set_u32(nvs,"mq_keep",(uint32_t)jka->valuedouble);
    nvs_commit(nvs); nvs_close(nvs); cJSON_Delete(j);

    esp_err_t reload_err = mqtt_reload_config();
    if (reload_err != ESP_OK) {
        ESP_LOGE(TAG, "Riavvio MQTT fallito dopo aggiornamento configurazione: %s", esp_err_to_name(reload_err));
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "mqtt"), ESP_FAIL;
    }

    return json_reply(req, "{\"ok\":true}");
}

#define MQTT_TEST_TIMEOUT_MS   5000
#define MQTT_TEST_BIT_OK       BIT0
#define MQTT_TEST_BIT_FAIL     BIT1

typedef struct {
    EventGroupHandle_t events;
    esp_err_t last_err;
    int tls_stack_err;
    int transport_errno;
} mqtt_test_ctx_t;

static void mqtt_test_event_handler(void* handler_args, esp_event_base_t base, int32_t event_id, void* event_data)
{
    (void)base;
    mqtt_test_ctx_t* ctx = (mqtt_test_ctx_t*)handler_args;
    if (!ctx) return;
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;
    switch ((esp_mqtt_event_id_t)event_id) {
    case MQTT_EVENT_CONNECTED:
        if (ctx->events) xEventGroupSetBits(ctx->events, MQTT_TEST_BIT_OK);
        break;
    case MQTT_EVENT_ERROR:
        if (event && event->error_handle){
            ctx->last_err = event->error_handle->esp_tls_last_esp_err;
            ctx->tls_stack_err = event->error_handle->esp_tls_stack_err;
            ctx->transport_errno = event->error_handle->esp_transport_sock_errno;
        }
        if (ctx->events) xEventGroupSetBits(ctx->events, MQTT_TEST_BIT_FAIL);
        break;
    case MQTT_EVENT_DISCONNECTED:
        if (ctx->events) xEventGroupSetBits(ctx->events, MQTT_TEST_BIT_FAIL);
        break;
    default:
        break;
    }
}

static void mqtt_test_format_error(char* buf, size_t len, bool timeout, esp_err_t start_err, const mqtt_test_ctx_t* ctx)
{
    if (!buf || len == 0) return;
    if (timeout){
        strlcpy(buf, "Timeout di connessione.", len);
        return;
    }
    if (start_err != ESP_OK){
        const char* name = esp_err_to_name(start_err);
        if (name) strlcpy(buf, name, len);
        else snprintf(buf, len, "Errore 0x%x", (unsigned)start_err);
        return;
    }
    if (!ctx){
        strlcpy(buf, "Connessione non riuscita.", len);
        return;
    }
    if (ctx->last_err != ESP_OK && ctx->last_err != 0){
        const char* name = esp_err_to_name(ctx->last_err);
        if (name) strlcpy(buf, name, len);
        else snprintf(buf, len, "Errore 0x%x", (unsigned)ctx->last_err);
        return;
    }
    if (ctx->tls_stack_err){
        snprintf(buf, len, "TLS err 0x%x", (unsigned)ctx->tls_stack_err);
        return;
    }
    if (ctx->transport_errno){
        const char* err = strerror(ctx->transport_errno);
        if (err && *err) snprintf(buf, len, "Errore di rete (%d: %s)", ctx->transport_errno, err);
        else snprintf(buf, len, "Errore di rete (%d)", ctx->transport_errno);
        return;
    }
    strlcpy(buf, "Connessione rifiutata o credenziali errate.", len);
}

static esp_err_t sys_mqtt_test_post(httpd_req_t* req)
{
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    char body[256]; size_t bl = 0;
    if (read_body_to_buf(req, body, sizeof(body), &bl)!=ESP_OK) return httpd_resp_send_err(req,400,"body"), ESP_FAIL;
    cJSON* j = cJSON_ParseWithLength(body, bl);
    if (!j) return httpd_resp_send_err(req,400,"json"), ESP_FAIL;

    const cJSON* juri  = cJSON_GetObjectItemCaseSensitive(j, "uri");
    const cJSON* jcid  = cJSON_GetObjectItemCaseSensitive(j, "cid");
    const cJSON* juser = cJSON_GetObjectItemCaseSensitive(j, "user");
    const cJSON* jpass = cJSON_GetObjectItemCaseSensitive(j, "pass");
    const cJSON* jka   = cJSON_GetObjectItemCaseSensitive(j, "keepalive");

    char uri[128] = {0};
    char cid[80] = {0};
    char user[80] = {0};
    char pass[96] = {0};

    if (cJSON_IsString(juri) && juri->valuestring){
        strlcpy(uri, juri->valuestring, sizeof(uri));
    }
    trim_inplace(uri);
    if (!uri[0]){
        cJSON_Delete(j);
        return httpd_resp_send_err(req,400,"uri"), ESP_FAIL;
    }
    if (cJSON_IsString(jcid) && jcid->valuestring){
        strlcpy(cid, jcid->valuestring, sizeof(cid));
        trim_inplace(cid);
    }
    if (cJSON_IsString(juser) && juser->valuestring){
        strlcpy(user, juser->valuestring, sizeof(user));
        trim_inplace(user);
    }
    if (cJSON_IsString(jpass) && jpass->valuestring){
        strlcpy(pass, jpass->valuestring, sizeof(pass));
        trim_inplace(pass);
    }

    uint32_t keepalive = 60;
    if (cJSON_IsNumber(jka)){
        double v = jka->valuedouble;
        if (v < 10) v = 10;
        if (v > 600) v = 600;
        keepalive = (uint32_t)v;
    } else if (cJSON_IsString(jka) && jka->valuestring){
        long v = strtol(jka->valuestring, NULL, 10);
        if (v > 0){
            if (v < 10) v = 10;
            if (v > 600) v = 600;
            keepalive = (uint32_t)v;
        }
    }

    cJSON_Delete(j);

    EventGroupHandle_t events = xEventGroupCreate();
    if (!events){
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "events"), ESP_FAIL;
    }

    mqtt_test_ctx_t ctx = {
        .events = events,
        .last_err = ESP_OK,
        .tls_stack_err = 0,
        .transport_errno = 0,
    };

    size_t ca_len = (size_t)(certs_broker_ca_pem_end - certs_broker_ca_pem_start);

    esp_mqtt_client_config_t cfg = {
        .broker.address.uri = uri,
        .session.keepalive = keepalive,
    };
    cfg.network.disable_auto_reconnect = true;
    cfg.credentials.client_id = cid[0] ? cid : NULL;
    cfg.credentials.username = user[0] ? user : NULL;
    cfg.credentials.authentication.password = pass[0] ? pass : NULL;

    if (ca_len == 0) {
        vEventGroupDelete(events);
        cJSON* root = cJSON_CreateObject();
        if (!root) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
        cJSON_AddBoolToObject(root, "success", false);
        cJSON_AddStringToObject(root, "error", "Certificato CA MQTT mancante nel firmware");
        return json_reply_cjson(req, root);
    }

    cfg.broker.verification.certificate = (const char *)certs_broker_ca_pem_start;
    cfg.broker.verification.certificate_len = ca_len;

    esp_mqtt_client_handle_t client = esp_mqtt_client_init(&cfg);
    if (!client){
        vEventGroupDelete(events);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "mqtt"), ESP_FAIL;
    }

    esp_err_t reg_err = esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_test_event_handler, &ctx);
    if (reg_err != ESP_OK){
        esp_mqtt_client_destroy(client);
        vEventGroupDelete(events);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "mqtt"), ESP_FAIL;
    }

    esp_err_t start_err = esp_mqtt_client_start(client);
    EventBits_t bits = 0;
    bool timed_out = false;
    if (start_err == ESP_OK){
        bits = xEventGroupWaitBits(events, MQTT_TEST_BIT_OK | MQTT_TEST_BIT_FAIL, pdTRUE, pdFALSE,
                                   pdMS_TO_TICKS(MQTT_TEST_TIMEOUT_MS));
        if (bits == 0) timed_out = true;
    }

    ctx.events = NULL;
    if (start_err == ESP_OK){
        esp_mqtt_client_stop(client);
    }
    esp_mqtt_client_destroy(client);
    vEventGroupDelete(events);

    if (start_err != ESP_OK){
        char msg[128];
        mqtt_test_format_error(msg, sizeof(msg), false, start_err, &ctx);
        cJSON* root = cJSON_CreateObject();
        if (!root) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
        cJSON_AddBoolToObject(root, "success", false);
        cJSON_AddStringToObject(root, "error", msg);
        return json_reply_cjson(req, root);
    }

    if (bits & MQTT_TEST_BIT_OK){
        return json_reply(req, "{\"success\":true}");
    }

    char msg[128];
    mqtt_test_format_error(msg, sizeof(msg), timed_out, ESP_OK, &ctx);
    cJSON* root = cJSON_CreateObject();
    if (!root) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
    cJSON_AddBoolToObject(root, "success", false);
    cJSON_AddStringToObject(root, "error", msg);
    return json_reply_cjson(req, root);
}

static esp_err_t sys_cloudflare_get(httpd_req_t* req){
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    provisioning_cloudflare_config_t cfg; provisioning_load_cloudflare(&cfg);
    cJSON* root = cJSON_CreateObject();
    if (!root) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
    cJSON_AddStringToObject(root, "ui_url", cfg.ui_url);
    return json_reply_cjson(req, root);
}

static esp_err_t sys_cloudflare_post(httpd_req_t* req){
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    char body[768]; size_t bl=0;
    if (read_body_to_buf(req, body, sizeof(body), &bl)!=ESP_OK) return httpd_resp_send_err(req,400,"body"), ESP_FAIL;
    cJSON* j = cJSON_ParseWithLength(body, bl);
    if (!j) return httpd_resp_send_err(req,400,"json"), ESP_FAIL;
    const cJSON* jurl = cJSON_GetObjectItemCaseSensitive(j, "ui_url");

    nvs_handle_t nvs;
    if (nvs_open("sys", NVS_READWRITE, &nvs) != ESP_OK){
        cJSON_Delete(j);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "nvs"), ESP_FAIL;
    }

    char url_buf[sizeof(s_cloudflare_ui_url)];
    bool url_updated = false;
    if (cJSON_IsString(jurl) && jurl->valuestring){
        strlcpy(url_buf, jurl->valuestring, sizeof(url_buf));
        trim_inplace(url_buf);
        nvs_set_str(nvs, "cf_ui", url_buf);
        provisioning_set_ui_url(url_buf);
        url_updated = true;
    }
    esp_err_t err = nvs_commit(nvs);
    nvs_close(nvs);
    cJSON_Delete(j);
    if (err != ESP_OK) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "commit"), ESP_FAIL;
    if (!url_updated){
        provisioning_cloudflare_config_t cfg; provisioning_load_cloudflare(&cfg);
        (void)cfg;
    }
    return json_reply(req, "{\"ok\":true}");
}

static esp_err_t provision_status_get(httpd_req_t* req){
    provisioning_general_config_t general; provisioning_net_config_t net; provisioning_mqtt_config_t mqtt; provisioning_cloudflare_config_t cf;
    provisioning_load_general(&general);
    provisioning_load_net(&net);
    provisioning_load_mqtt(&mqtt);
    provisioning_load_cloudflare(&cf);

    cJSON* root = cJSON_CreateObject();
    if (!root) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
    cJSON_AddBoolToObject(root, "provisioned", s_provisioned);
    cJSON* jgeneral = cJSON_AddObjectToObject(root, "general");
    if (jgeneral){
        cJSON_AddStringToObject(jgeneral, "central_name", general.central_name);
    }
    cJSON_AddStringToObject(root, "device_id", mqtt.cid);

    cJSON* jnet = cJSON_AddObjectToObject(root, "network");
    if (jnet){
        cJSON_AddStringToObject(jnet, "hostname", net.hostname);
        cJSON_AddBoolToObject(jnet, "dhcp", net.dhcp);
        cJSON_AddStringToObject(jnet, "ip", net.ip);
        cJSON_AddStringToObject(jnet, "gw", net.gw);
        cJSON_AddStringToObject(jnet, "mask", net.mask);
        cJSON_AddStringToObject(jnet, "dns", net.dns);
    }

    cJSON* jmq = cJSON_AddObjectToObject(root, "mqtt");
    if (jmq){
        cJSON_AddStringToObject(jmq, "uri", mqtt.uri);
        cJSON_AddStringToObject(jmq, "cid", mqtt.cid);
        cJSON_AddStringToObject(jmq, "user", mqtt.user);
        cJSON_AddStringToObject(jmq, "pass", mqtt.pass);
        cJSON_AddNumberToObject(jmq, "keepalive", mqtt.keepalive);
        cJSON_AddStringToObject(jmq, "device_id", mqtt.cid);
        cJSON_AddStringToObject(jmq, "default_uri", CONFIG_APP_CLOUD_MQTT_URI);
        cJSON_AddNumberToObject(jmq, "default_keepalive", CONFIG_APP_CLOUD_KEEPALIVE);
    }

    cJSON* jcf = cJSON_AddObjectToObject(root, "cloudflare");
    if (jcf){
        cJSON_AddStringToObject(jcf, "ui_url", cf.ui_url);
    }

    return json_reply_cjson(req, root);
}

static esp_err_t provision_general_post(httpd_req_t* req){
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    char body[160]; size_t bl = 0;
    if (read_body_to_buf(req, body, sizeof(body), &bl)!=ESP_OK) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "body"), ESP_FAIL;
    cJSON* root = cJSON_ParseWithLength(body, bl);
    if (!root) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "json"), ESP_FAIL;
    const cJSON* jname = cJSON_GetObjectItemCaseSensitive(root, "central_name");
    char name_buf[sizeof(((provisioning_general_config_t*)0)->central_name)];
    memset(name_buf, 0, sizeof(name_buf));
    if (cJSON_IsString(jname) && jname->valuestring){
        strlcpy(name_buf, jname->valuestring, sizeof(name_buf));
        trim_inplace(name_buf);
    }
    if (!name_buf[0]){
        cJSON_Delete(root);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "name"), ESP_FAIL;
    }

    nvs_handle_t nvs;
    esp_err_t err = nvs_open("sys", NVS_READWRITE, &nvs);
    if (err != ESP_OK){
        cJSON_Delete(root);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "nvs"), ESP_FAIL;
    }

    err = nvs_set_str(nvs, "central_name", name_buf);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    cJSON_Delete(root);
    if (err != ESP_OK) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "commit"), ESP_FAIL;
    return json_reply(req, "{\"ok\":true}");
}

static esp_err_t provision_finish_post(httpd_req_t* req){
    esp_err_t err = provisioning_set_flag(true);
    if (err != ESP_OK) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "nvs"), ESP_FAIL;

    err = mqtt_reload_config();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Impossibile riavviare MQTT al termine del provisioning: %s", esp_err_to_name(err));
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "mqtt"), ESP_FAIL;
    }

    // cJSON* root = cJSON_CreateObject();
    // if (!root) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
    // cJSON_AddBoolToObject(root, "ok", true);
    // cJSON_AddStringToObject(root, "redirect", s_cloudflare_ui_url);
    // return json_reply_cjson(req, root);
    return send_https_redirect(req, "/login.html", "302 Found");
}

static bool req_has_hard_reset_header(httpd_req_t* req){
    char hdr[16] = {0};
    if (httpd_req_get_hdr_value_str(req, "X-Hard-Reset", hdr, sizeof(hdr)) == ESP_OK){
        trim_inplace(hdr);
        if (!hdr[0]) return false;
        if (!strcasecmp(hdr, "1") || !strcasecmp(hdr, "true") || !strcasecmp(hdr, "yes")) return true;
    }
    return false;
}

static esp_err_t provision_reset_post(httpd_req_t* req){
    bool allow = !s_provisioned;
    if (!allow && req_has_hard_reset_header(req)) allow = true;
    if (!allow && only_admin(req)!=ESP_OK) return ESP_FAIL;
    esp_err_t err = provisioning_set_flag(false);
    if (err != ESP_OK) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "nvs"), ESP_FAIL;
    return json_reply(req, "{\"ok\":true,\"provisioned\":false}");
}

static esp_err_t erase_namespace(const char* ns){
    if (!ns || !ns[0]) return ESP_ERR_INVALID_ARG;
    nvs_handle_t h = 0;
    esp_err_t err = nvs_open(ns, NVS_READWRITE, &h);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return ESP_OK;
    }
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_erase_all(h);
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return err;
}

esp_err_t provisioning_reset_all(void){
    static const char* TAG_RST = "prov_reset";
    const char* namespaces[] = {"sys", "app", "zones", "scenes", "usrdb", WEB_TLS_NS};
    esp_err_t first_err = ESP_OK;

    for (size_t i = 0; i < (sizeof(namespaces) / sizeof(namespaces[0])); ++i) {
        const char* ns = namespaces[i];
        esp_err_t err = erase_namespace(ns);
        if (err != ESP_OK) {
            ESP_LOGE(TAG_RST, "Impossibile cancellare namespace '%s': %s", ns, esp_err_to_name(err));
            if (first_err == ESP_OK) first_err = err;
        } else {
            ESP_LOGW(TAG_RST, "Namespace NVS '%s' cancellato", ns);
        }
    }

    esp_err_t err = provisioning_set_flag(false);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_RST, "provisioning_set_flag(false) fallita: %s", esp_err_to_name(err));
        if (first_err == ESP_OK) first_err = err;
    } else {
        ESP_LOGI(TAG_RST, "Flag di provisioning azzerato");
    }

    provisioning_load_state();

    esp_err_t final_err = (first_err != ESP_OK) ? first_err : err;
    if (final_err == ESP_OK) {
        log_add("Reset hardware completato");
        audit_append("hw_reset", "system", 0, "Factory reset da pulsanti HW");
    } else {
        log_add("Reset hardware fallito: %s", esp_err_to_name(final_err));
        audit_append("hw_reset", "system", -1, "Factory reset incompleto");
    }

    return final_err;
}

static esp_err_t sys_websec_get(httpd_req_t* req){
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    cJSON *root = cJSON_CreateObject();
    if (!root) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
    const char* src = (s_web_tls_state.active_source == WEB_TLS_SRC_CUSTOM) ? "custom" : "builtin";
    cJSON_AddStringToObject(root, "active_source", src);
    cJSON_AddBoolToObject(root, "using_builtin", s_web_tls_state.using_builtin);
    cJSON_AddStringToObject(root, "active_subject", s_web_tls_state.active_subject[0]?s_web_tls_state.active_subject:"");
    cJSON_AddStringToObject(root, "active_issuer", s_web_tls_state.active_issuer[0]?s_web_tls_state.active_issuer:"");
    cJSON_AddStringToObject(root, "active_not_before", s_web_tls_state.active_not_before[0]?s_web_tls_state.active_not_before:"");
    cJSON_AddStringToObject(root, "active_not_after", s_web_tls_state.active_not_after[0]?s_web_tls_state.active_not_after:"");
    cJSON_AddStringToObject(root, "active_fingerprint", s_web_tls_state.active_fingerprint[0]?s_web_tls_state.active_fingerprint:"");
    cJSON_AddBoolToObject(root, "custom_available", s_web_tls_state.custom_available);
    cJSON_AddBoolToObject(root, "custom_valid", s_web_tls_state.custom_valid);
    cJSON_AddStringToObject(root, "custom_subject", s_web_tls_state.custom_subject[0]?s_web_tls_state.custom_subject:"");
    cJSON_AddStringToObject(root, "custom_issuer", s_web_tls_state.custom_issuer[0]?s_web_tls_state.custom_issuer:"");
    cJSON_AddStringToObject(root, "custom_not_before", s_web_tls_state.custom_not_before[0]?s_web_tls_state.custom_not_before:"");
    cJSON_AddStringToObject(root, "custom_not_after", s_web_tls_state.custom_not_after[0]?s_web_tls_state.custom_not_after:"");
    cJSON_AddStringToObject(root, "custom_fingerprint", s_web_tls_state.custom_fingerprint[0]?s_web_tls_state.custom_fingerprint:"");
    cJSON_AddNumberToObject(root, "custom_installed_at", (double)s_web_tls_state.custom_installed_at);
    cJSON_AddStringToObject(root, "custom_installed_iso", s_web_tls_state.custom_installed_iso[0]?s_web_tls_state.custom_installed_iso:"");
    cJSON_AddBoolToObject(root, "restart_pending", s_restart_pending);
    cJSON_AddStringToObject(root, "last_error", s_web_tls_state.last_error[0]?s_web_tls_state.last_error:"");
    char* out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!out) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
    httpd_resp_set_type(req, "application/json");
    esp_err_t send = httpd_resp_sendstr(req, out);
    cJSON_free(out);
    return send;
}

static esp_err_t sys_websec_post(httpd_req_t* req){
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    char* body = NULL; size_t blen = 0;
    esp_err_t err = read_body_alloc(req, &body, &blen, WEB_TLS_MAX_BODY);
    if (err != ESP_OK){
        if (body) free(body);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "body");
        return ESP_FAIL;
    }
    cJSON* root = cJSON_ParseWithLength(body, blen);
    free(body);
    if (!root) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "json"), ESP_FAIL;

    const cJSON* cert_b64 = cJSON_GetObjectItemCaseSensitive(root, "cert_b64");
    const cJSON* key_b64  = cJSON_GetObjectItemCaseSensitive(root, "key_b64");
    const cJSON* cert_txt = cJSON_GetObjectItemCaseSensitive(root, "cert");
    const cJSON* key_txt  = cJSON_GetObjectItemCaseSensitive(root, "key");

    uint8_t *cert = NULL, *key = NULL;
    size_t cert_len = 0, key_len = 0;

    if (cJSON_IsString(cert_b64) && cert_b64->valuestring && cert_b64->valuestring[0]){
        err = decode_base64_alloc(cert_b64->valuestring, &cert, &cert_len);
    } else if (cJSON_IsString(cert_txt) && cert_txt->valuestring && cert_txt->valuestring[0]){
        cert_len = strlen(cert_txt->valuestring);
        if (cert_len > WEB_TLS_MAX_PEM_LEN){ err = ESP_ERR_INVALID_SIZE; }
        else {
            cert = calloc(1, cert_len + 1);
            if (cert) { memcpy(cert, cert_txt->valuestring, cert_len); cert[cert_len] = '\0'; err = ESP_OK; }
            else err = ESP_ERR_NO_MEM;
        }
    } else {
        err = ESP_ERR_INVALID_ARG;
    }
    if (err != ESP_OK || !cert){
        cJSON_Delete(root);
        if (cert) free(cert);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "cert");
        return ESP_FAIL;
    }

    if (cJSON_IsString(key_b64) && key_b64->valuestring && key_b64->valuestring[0]){
        err = decode_base64_alloc(key_b64->valuestring, &key, &key_len);
    } else if (cJSON_IsString(key_txt) && key_txt->valuestring && key_txt->valuestring[0]){
        key_len = strlen(key_txt->valuestring);
        if (key_len > WEB_TLS_MAX_PEM_LEN){ err = ESP_ERR_INVALID_SIZE; }
        else {
            key = calloc(1, key_len + 1);
            if (key) { memcpy(key, key_txt->valuestring, key_len); key[key_len] = '\0'; err = ESP_OK; }
            else err = ESP_ERR_NO_MEM;
        }
    } else {
        err = ESP_ERR_INVALID_ARG;
    }
    if (err != ESP_OK || !key){
        free(cert);
        cJSON_Delete(root);
        if (key) free(key);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "key");
        return ESP_FAIL;
    }

    if (cert_len == 0 || key_len == 0 || cert_len > WEB_TLS_MAX_PEM_LEN || key_len > WEB_TLS_MAX_PEM_LEN){
        free(cert); free(key); cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "size");
        return ESP_FAIL;
    }
    if (!strstr((char*)cert, "BEGIN CERTIFICATE") || !strstr((char*)cert, "END CERTIFICATE")){
        free(cert); free(key); cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "cert pem");
        return ESP_FAIL;
    }
    if (!strstr((char*)key, "BEGIN") || !strstr((char*)key, "PRIVATE KEY")){
        free(cert); free(key); cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "key pem");
        return ESP_FAIL;
    }

    char errbuf[96] = {0};
    mbedtls_x509_crt crt;
    esp_err_t val = web_tls_validate_pair(cert, cert_len, key, key_len, &crt, errbuf, sizeof(errbuf));
    if (val != ESP_OK){
        free(cert); free(key); cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, errbuf[0]?errbuf:"validate");
        return ESP_FAIL;
    }

    nvs_handle_t nvs;
    err = nvs_open(WEB_TLS_NS, NVS_READWRITE, &nvs);
    if (err != ESP_OK){
        mbedtls_x509_crt_free(&crt);
        free(cert); free(key); cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "nvs");
        return ESP_FAIL;
    }
    err = nvs_set_blob(nvs, WEB_TLS_CERT_KEY, cert, cert_len);
    if (err == ESP_OK) err = nvs_set_blob(nvs, WEB_TLS_PRIV_KEY, key, key_len);
    uint64_t now = (uint64_t)time(NULL);
    if (err == ESP_OK) err = nvs_set_u64(nvs, WEB_TLS_TS_KEY, now);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    if (err != ESP_OK){
        mbedtls_x509_crt_free(&crt);
        free(cert); free(key); cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "nvs");
        return ESP_FAIL;
    }

    free(cert); free(key); cJSON_Delete(root);

    if (now == (uint64_t)-1) now = 0;
    web_tls_state_set_custom_from_crt(&crt, now);
    web_tls_state_set_last_error("");
    mbedtls_x509_crt_free(&crt);

    char admin[32]={0};
    current_user_from_req(req, admin, sizeof(admin));
    ESP_LOGI(TAG, "Certificato HTTPS aggiornato da %s (CN=%s)", admin[0]?admin:"?", s_web_tls_state.custom_subject);
    audit_append("websec", admin, 1, "cert aggiornato");

    web_server_restart_async();

    cJSON *resp = cJSON_CreateObject();
    if (!resp) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
    cJSON_AddBoolToObject(resp, "ok", true);
    cJSON_AddBoolToObject(resp, "restart", true);
    cJSON_AddStringToObject(resp, "active_source", "custom");
    char* out = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);
    if (!out) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
    httpd_resp_set_type(req, "application/json");
    esp_err_t send = httpd_resp_sendstr(req, out);
    cJSON_free(out);
    return send;
}

// ─────────────────────────────────────────────────────────────────────────────
// USER SETTINGS & ADMIN
// ─────────────────────────────────────────────────────────────────────────────
static esp_err_t json_bool(httpd_req_t* req, bool v){
    return json_reply(req, v ? "{\"ok\":true}" : "{\"ok\":false}");
}

static esp_err_t user_get_totp(httpd_req_t* req){
    if(!check_bearer(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"), ESP_FAIL;
    char uname[16]={0}; if(!current_user_from_req(req, uname, sizeof(uname))) return httpd_resp_send_err(req, 401, "token"), ESP_FAIL;
    bool enabled = auth_totp_enabled(uname);
    char buf[64]; snprintf(buf, sizeof(buf), "{\"enabled\":%s}", enabled?"true":"false");
    return json_reply(req, buf);
}

static esp_err_t user_post_password(httpd_req_t* req){
    if(!check_bearer(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"), ESP_FAIL;
    char uname[32]={0}; 
    if(!current_user_from_req(req, uname, sizeof(uname))) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"), ESP_FAIL;

    char body[WEB_MAX_BODY_LEN]; size_t blen = 0;
    if(read_body_to_buf(req, body, sizeof(body), &blen)!=ESP_OK) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "body"), ESP_FAIL;

    cJSON* root = cJSON_ParseWithLength(body, blen);
    if(!root) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "json"), ESP_FAIL;

    const cJSON* jcur = cJSON_GetObjectItemCaseSensitive(root, "current");
    const cJSON* jnew = cJSON_GetObjectItemCaseSensitive(root, "newpass");
    char cur[96]={0}, np[96]={0};
    if(cJSON_IsString(jcur) && jcur->valuestring) strlcpy(cur, jcur->valuestring, sizeof(cur));
    if(cJSON_IsString(jnew) && jnew->valuestring) strlcpy(np, jnew->valuestring, sizeof(np));
    if(!cur[0] || !np[0]){ cJSON_Delete(root); return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "fields"), ESP_FAIL; }

    if(!auth_verify_password(uname, cur)){ cJSON_Delete(root); return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "bad pass"), ESP_FAIL; }
    esp_err_t e = auth_set_password(uname, np);
    cJSON_Delete(root);
    if(e != ESP_OK){
        ESP_LOGE(TAG, "auth_set_password('%s') failed: %s", uname, esp_err_to_name(e));
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "set pass"), ESP_FAIL;
    }
    return json_bool(req, true);
}

static esp_err_t user_post_totp_enable(httpd_req_t* req){
    if(!check_bearer(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"), ESP_FAIL;
    char uname[16]={0}; if(!current_user_from_req(req, uname, sizeof(uname))) return httpd_resp_send_err(req, 401, "token"), ESP_FAIL;

    char secret[64]={0};
    // 160 bit -> base32
    uint8_t raw[20]; for(size_t i=0;i<sizeof(raw);i++) raw[i]=(uint8_t)(esp_random() & 0xFF);
    static const char* A="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    size_t outi=0; uint32_t buffer=0; int bitsLeft=0;
    for(size_t i=0;i<sizeof(raw);++i){ buffer=(buffer<<8)|raw[i]; bitsLeft+=8; while(bitsLeft>=5){ if(outi+1<sizeof(secret)) secret[outi++]=A[(buffer>>(bitsLeft-5))&31]; bitsLeft-=5; } }
    if(bitsLeft>0 && outi+1<sizeof(secret)) secret[outi++]=A[(buffer<<(5-bitsLeft))&31];
    secret[outi]=0;

    // Azzeriamo eventuale TOTP precedente finché la procedura non viene confermata
    if(auth_totp_disable(uname) != ESP_OK) {
        ESP_LOGW(TAG, "auth_totp_disable('%s') failed during enrolment", uname);
    }

    if(!auth_totp_store_pending(req, secret)){
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "totp pending"), ESP_FAIL;
    }

    char uri[256];
    snprintf(uri, sizeof(uri), "otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=6&period=%d&algorithm=SHA1",
             ISSUER_NAME, uname, secret, ISSUER_NAME, TOTP_STEP_SECONDS);
    char resp[384]; snprintf(resp, sizeof(resp), "{\"secret_base32\":\"%s\",\"otpauth_uri\":\"%s\"}", secret, uri);
    return json_reply(req, resp);
}

static esp_err_t user_post_totp_confirm(httpd_req_t* req){
    if(!check_bearer(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"), ESP_FAIL;
    char uname[16]={0}; if(!current_user_from_req(req, uname, sizeof(uname))) return httpd_resp_send_err(req, 401, "token"), ESP_FAIL;

    char body[128]; size_t blen = 0;
    if(read_body_to_buf(req, body, sizeof(body), &blen)!=ESP_OK) return httpd_resp_send_err(req, 400, "body"), ESP_FAIL;

    cJSON* root = cJSON_ParseWithLength(body, blen);
    if(!root) return httpd_resp_send_err(req, 400, "json"), ESP_FAIL;

    const cJSON* jotp    = cJSON_GetObjectItemCaseSensitive(root, "otp");
    const cJSON* jsecret = cJSON_GetObjectItemCaseSensitive(root, "secret");
    char otp[16]={0};
    char secret[64]={0};
    if (cJSON_IsString(jotp) && jotp->valuestring) strncpy(otp, jotp->valuestring, sizeof(otp)-1);
    if(!auth_totp_get_pending(req, secret, sizeof(secret))){
        if (cJSON_IsString(jsecret) && jsecret->valuestring) strncpy(secret, jsecret->valuestring, sizeof(secret)-1);
    }
    cJSON_Delete(root);

    if(!otp[0]) return httpd_resp_send_err(req, 400, "fields"), ESP_FAIL;
    if(!secret[0]) return httpd_resp_send_err(req, 409, "no totp"), ESP_FAIL;

    time_t now_chk = time(NULL);
    if (now_chk < 1577836800) { // 2020-01-01
        return httpd_resp_send_err(req, 409, "time not set"), ESP_FAIL;
    }
    if(!totp_verify_b32(secret, otp, TOTP_STEP_SECONDS, TOTP_WINDOW_STEPS)){
        return httpd_resp_send_err(req, 409, "bad otp"), ESP_FAIL;
    }

    if(auth_totp_enable(uname, secret)!=ESP_OK) return httpd_resp_send_err(req,500,"enable"), ESP_FAIL;
    auth_totp_clear_pending(req);
    return json_bool(req, true);
}

static esp_err_t user_post_totp_disable(httpd_req_t* req){
    if(!check_bearer(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"), ESP_FAIL;
    char uname[16]={0}; if(!current_user_from_req(req, uname, sizeof(uname))) return httpd_resp_send_err(req, 401, "token"), ESP_FAIL;

    auth_totp_clear_pending(req);
    if(auth_totp_disable(uname)!=ESP_OK) return httpd_resp_send_err(req, 500, "disable"), ESP_FAIL;
    return json_bool(req, true);
}

static bool normalize_username_for_api(char *username)
{
    if (!username) {
        return false;
    }

    size_t len = strlen(username);
    while (len > 0 && (username[len - 1] == '\n' || username[len - 1] == '\r')) {
        username[--len] = '\0';
    }

    if (!username[0]) {
        return false;
    }

    if ((username[0] == 'u' || username[0] == 'U') && username[1] == '_') {
        const char *src = username + 2;
        size_t new_len = strlen(src);
        memmove(username, src, new_len + 1);
    }

    return username[0] != '\0';
}

static esp_err_t users_list_get(httpd_req_t* req){
    if(!check_bearer(req) || !is_admin_user(req)) return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden"), ESP_FAIL;
    char csv[256]={0};
    auth_list_users(csv, sizeof(csv));
    char* p = csv;
    char buf[256]; size_t off=0; off += snprintf(buf+off, sizeof(buf)-off, "[");
    bool first=true;
    while(*p){
        char u[32]={0}; int i=0; while(*p && *p!=',' && i<31) u[i++]=*p++; if(*p==',') p++;
        if(!u[0]) continue;
        if(!normalize_username_for_api(u)) continue;
        off += snprintf(buf+off, sizeof(buf)-off, "%s\"%s\"", first?"":",", u);
        first=false;
    }
    off += snprintf(buf+off, sizeof(buf)-off, "]");
    return json_reply(req, buf);
}

// Admin: reset della password di un utente qualunque
static esp_err_t users_password_post(httpd_req_t* req){
    // Solo admin
    if (!check_bearer(req) || !is_admin_user(req)) {
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden"), ESP_FAIL;
    }

    // Body
    char body[WEB_MAX_BODY_LEN]; size_t blen = 0;
    if (read_body_to_buf(req, body, sizeof(body), &blen) != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "body"), ESP_FAIL;
    }

    // Parse robusto via cJSON (evita sscanf fragile)
    cJSON *root = cJSON_ParseWithLength(body, blen);
    if (!root) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "json"), ESP_FAIL;
    }

    const cJSON *juser = cJSON_GetObjectItemCaseSensitive(root, "user");
    const cJSON *jnew  = cJSON_GetObjectItemCaseSensitive(root, "newpass");
    char usr[32] = {0};
    char np [96] = {0};
    if (cJSON_IsString(juser) && juser->valuestring) strlcpy(usr, juser->valuestring, sizeof(usr));
    if (cJSON_IsString(jnew)  && jnew->valuestring)  strlcpy(np,  jnew->valuestring,  sizeof(np));
    if (!usr[0] || !np[0]) {
        cJSON_Delete(root);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "fields"), ESP_FAIL;
    }

    // (facoltativo) sanity check
    if (strlen(usr) < 3) {
        cJSON_Delete(root);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "user"), ESP_FAIL;
    }
    if (strlen(np) < 6) { // lunghezza minima
        cJSON_Delete(root);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "weak"), ESP_FAIL;
    }

    // Applica
    esp_err_t rc = auth_set_password(usr, np);
    cJSON_Delete(root);
    if (rc != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "set pass"), ESP_FAIL;
    }
    return json_bool(req, true);
}

static esp_err_t users_name_post(httpd_req_t* req){
    if (!check_bearer(req) || !is_admin_user(req)) {
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden"), ESP_FAIL;
    }

    char body[WEB_MAX_BODY_LEN];
    size_t blen = 0;
    if (read_body_to_buf(req, body, sizeof(body), &blen) != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "body"), ESP_FAIL;
    }

    cJSON *root = cJSON_ParseWithLength(body, blen);
    if (!root) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "json"), ESP_FAIL;
    }

    const cJSON *juser  = cJSON_GetObjectItemCaseSensitive(root, "user");
    const cJSON *jfirst = cJSON_GetObjectItemCaseSensitive(root, "first_name");
    const cJSON *jlast  = cJSON_GetObjectItemCaseSensitive(root, "last_name");

    char usr[32] = {0};
    char first[32] = {0};
    char last[32] = {0};

    if (cJSON_IsString(juser) && juser->valuestring) {
        if (strlen(juser->valuestring) >= sizeof(usr)) {
            cJSON_Delete(root);
            return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "user"), ESP_FAIL;
        }
        strlcpy(usr, juser->valuestring, sizeof(usr));
    }

    if (cJSON_IsString(jfirst) && jfirst->valuestring) {
        if (strlen(jfirst->valuestring) >= sizeof(first)) {
            cJSON_Delete(root);
            return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "first"), ESP_FAIL;
        }
        strlcpy(first, jfirst->valuestring, sizeof(first));
    }

    if (cJSON_IsString(jlast) && jlast->valuestring) {
        if (strlen(jlast->valuestring) >= sizeof(last)) {
            cJSON_Delete(root);
            return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "last"), ESP_FAIL;
        }
        strlcpy(last, jlast->valuestring, sizeof(last));
    }

    if (!usr[0]) {
        cJSON_Delete(root);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "user"), ESP_FAIL;
    }

    esp_err_t err = auth_set_user_name(usr, first, last);
    cJSON_Delete(root);
    if (err != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "set name"), ESP_FAIL;
    }

    return json_bool(req, true);
}

static __attribute__((unused)) esp_err_t users_totp_reset_post(httpd_req_t* req){
    if(!check_bearer(req) || !is_admin_user(req)) return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden"), ESP_FAIL;
    char body[128]; size_t blen = 0;
    if(read_body_to_buf(req, body, sizeof(body), &blen)!=ESP_OK) return httpd_resp_send_err(req, 400, "body"), ESP_FAIL;
    char usr[32]={0}; sscanf(body, "%*[^\"\"u]\"user\"%*[^\"\"]\"%31[^\"]", usr);
    if(!usr[0]) return httpd_resp_send_err(req, 400, "user"), ESP_FAIL;
    if(auth_totp_disable(usr)!=ESP_OK) return httpd_resp_send_err(req, 500, "reset totp"), ESP_FAIL;
    return json_bool(req, true);
}

// ---------------------- ADMIN: Users management ----------------------
static esp_err_t users_create_post(httpd_req_t* req){
    if(!check_bearer(req) || !is_admin_user(req)) return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden"), ESP_FAIL;
    char body[256]; size_t blen = 0;
    if(read_body_to_buf(req, body, sizeof(body), &blen)!=ESP_OK) return httpd_resp_send_err(req, 400, "body"), ESP_FAIL;
    char usr[32]={0}, fn[32]={0}, ln[32]={0}, pw[96]={0}, pin[16]={0};
    sscanf(body, "%*[^\"\"u]\"user\"%*[^\"\"]\"%31[^\"]", usr);
    sscanf(body, "%*[^\"\"f]\"first_name\"%*[^\"\"]\"%31[^\"]", fn);
    sscanf(body, "%*[^\"\"l]\"last_name\"%*[^\"\"]\"%31[^\"]", ln);
    sscanf(body, "%*[^\"\"p]\"password\"%*[^\"\"]\"%95[^\"]", pw);
    sscanf(body, "%*[^\"\"p]\"pin\"%*[^\"\"]\"%15[^\"]", pin);
    if(!usr[0]) return httpd_resp_send_err(req, 400, "user"), ESP_FAIL;

    esp_err_t err = auth_create_user(usr, fn, ln, pw[0]?pw:NULL);
    if(err != ESP_OK) return httpd_resp_send_err(req, 500, "create"), ESP_FAIL;
    if(pin[0]){
        if(auth_set_pin(usr, pin)!=ESP_OK) ESP_LOGW(TAG, "auth_set_pin failed for %s", usr);
    }
    return json_bool(req, true);
}

static esp_err_t users_pin_admin_post(httpd_req_t* req){
    if(!check_bearer(req) || !is_admin_user(req))
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden"), ESP_FAIL;

    char body[WEB_MAX_BODY_LEN]; size_t blen = 0;
    if(read_body_to_buf(req, body, sizeof(body), &blen)!=ESP_OK)
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "body"), ESP_FAIL;

    cJSON* root = cJSON_ParseWithLength(body, blen);
    if(!root) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "json"), ESP_FAIL;

    const cJSON* juser = cJSON_GetObjectItemCaseSensitive(root, "user");
    const cJSON* jpin  = cJSON_GetObjectItemCaseSensitive(root, "pin");
    char usr[32]={0}, pin[16]={0};
    if (cJSON_IsString(juser) && juser->valuestring) strlcpy(usr, juser->valuestring, sizeof(usr));
    if (cJSON_IsString(jpin)  && jpin->valuestring)  strlcpy(pin,  jpin->valuestring,  sizeof(pin));
    cJSON_Delete(root);

    if(!usr[0] || !pin[0]) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "fields"), ESP_FAIL;

    // Validazione PIN: 4–8 cifre numeriche
    size_t n = strlen(pin);
    if(n < 4 || n > 8) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "pin"), ESP_FAIL;
    for (size_t i=0; i<n; ++i){
        if(pin[i] < '0' || pin[i] > '9') return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "pin"), ESP_FAIL;
    }

    if(auth_set_pin(usr, pin)!=ESP_OK)
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "set pin"), ESP_FAIL;
    return json_bool(req, true);
}

static esp_err_t users_rfid_learn_post(httpd_req_t* req){
    if(!check_bearer(req) || !is_admin_user(req)) return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden"), ESP_FAIL;
    pn532_init();
    
    if(!pn532_is_ready()){
        ESP_LOGW(TAG, "RFID learn: PN532 non pronto/assente");
        return httpd_resp_send_err(req, 503, "pn532 not ready"), ESP_FAIL;
    }
    char body[128]; size_t blen = 0; if(read_body_to_buf(req, body, sizeof(body), &blen)!=ESP_OK) return httpd_resp_send_err(req, 400, "body"), ESP_FAIL;
    char usr[32]={0}; int timeout=10;
    sscanf(body, "%*[^\"\"u]\"user\"%*[^\"\"]\"%31[^\"]", usr);
    sscanf(body, "%*[^\"\"t]\"timeout\"%*[^0-9]%d", &timeout);
    if(timeout<=0 || timeout>60) timeout=10;
    if(!usr[0]) return httpd_resp_send_err(req, 400, "user"), ESP_FAIL;

    uint64_t until = esp_timer_get_time() + (uint64_t)timeout * 1000000ULL;
    uint8_t uid[16]; int uidlen=-1;
    while(esp_timer_get_time() < until){
        uidlen = pn532_read_uid(uid, sizeof(uid));
        if(uidlen > 0) break;
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    if(uidlen <= 0) return httpd_resp_send_err(req, 408, "timeout"), ESP_FAIL;
    if(auth_set_rfid_uid(usr, uid, uidlen)!=ESP_OK) return httpd_resp_send_err(req, 500, "save rfid"), ESP_FAIL;

    char hex[40]={0}; int off=0; for(int i=0;i<uidlen;i++){ off += snprintf(hex+off, sizeof(hex)-off, "%02X", uid[i]); }
    char buf[96]; snprintf(buf, sizeof(buf), "{\"ok\":true,\"uid_hex\":\"%s\"}", hex);
    return json_reply(req, buf);
}

static esp_err_t users_rfid_clear_post(httpd_req_t* req){
    if(!check_bearer(req) || !is_admin_user(req)) return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden"), ESP_FAIL;
    char body[128]; size_t blen = 0; if(read_body_to_buf(req, body, sizeof(body), &blen)!=ESP_OK) return httpd_resp_send_err(req, 400, "body"), ESP_FAIL;
    char usr[32]={0}; sscanf(body, "%*[^\"\"u]\"user\"%*[^\"\"]\"%31[^\"]", usr);
    if(!usr[0]) return httpd_resp_send_err(req, 400, "user"), ESP_FAIL;
    if(auth_clear_rfid_uid(usr)!=ESP_OK) return httpd_resp_send_err(req, 500, "rfid clear"), ESP_FAIL;
    return json_bool(req, true);
}

static esp_err_t users_admin_list_get(httpd_req_t* req){
    if(!check_bearer(req) || !is_admin_user(req)){
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden");
        return ESP_FAIL;
    }
    char csv[256]={0};
    auth_list_users(csv, sizeof(csv));

    cJSON *array = cJSON_CreateArray();
    if (!array) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json alloc");
        return ESP_FAIL;
    }

    const char *p = csv;
    while(*p){
        char username[32]={0};

        int i=0;
        while(*p && *p!=',' && i<(int)sizeof(username)-1) username[i++]=*p++;
        if(*p==',') p++;
        if(!username[0]) continue;
        if(!normalize_username_for_api(username)) continue;

        const char *login_ptr = username;
        char login[32]={0};
        strlcpy(login, login_ptr, sizeof(login));

        char first_name[32]={0}, last_name[32]={0};
        auth_get_user_name(login, first_name, sizeof(first_name), last_name, sizeof(last_name));
        bool has_pin = auth_has_pin(login);

        uint8_t uid[16];
        int uidlen = auth_get_rfid_uid(login, uid, sizeof(uid));
        bool has_rfid = uidlen > 0;
        char uid_hex[40]={0};
        if (has_rfid) {
            size_t off = 0;
            for (int j = 0; j < uidlen && off + 3 <= sizeof(uid_hex); j++) {
                int written = snprintf(uid_hex + off, sizeof(uid_hex) - off, "%02X", uid[j]);
                if (written != 2) {
                    uid_hex[0] = '\0';
                    break;
                }
                off += (size_t)written;
            }
        }

        bool totp_enabled = auth_totp_enabled(login);

        cJSON *user = cJSON_CreateObject();
        if (!user ||
            !cJSON_AddStringToObject(user, "username", login) ||
            !cJSON_AddStringToObject(user, "first_name", first_name) ||
            !cJSON_AddStringToObject(user, "last_name", last_name) ||
            !cJSON_AddBoolToObject(user, "has_pin", has_pin) ||
            !cJSON_AddBoolToObject(user, "has_rfid", has_rfid) ||
            !cJSON_AddBoolToObject(user, "totp_enabled", totp_enabled)) {
            if (user) {
                cJSON_Delete(user);
            }
            cJSON_Delete(array);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json alloc");
            return ESP_FAIL;
        }

        if (has_rfid && uid_hex[0]) {
            if (!cJSON_AddStringToObject(user, "rfid_uid", uid_hex)) {
                cJSON_Delete(user);
                cJSON_Delete(array);
                httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json alloc");
                return ESP_FAIL;
            }
        }

        cJSON_AddItemToArray(array, user);
    }
    return json_reply_cjson(req, array);
}

// ─────────────────────────────────────────────────────────────────────────────
// STATUS / ZONES / SCENES
// ─────────────────────────────────────────────────────────────────────────────

typedef struct {
    bool     zone_delay;   // ritardo unico abilitato
    uint16_t zone_time;    // secondi
    bool     auto_exclude; // se aperta all'ARM e non ritardata -> bypassabile?
    char     name[24];
} zone_cfg_t;

static zone_cfg_t s_zone_cfg[INPUT_ZONES_COUNT];
static uint8_t    s_zone_board_map[INPUT_ZONES_COUNT];

static uint8_t zone_board_for_index(int zone_1_based){
    if (zone_1_based < 1 || zone_1_based > INPUT_ZONES_COUNT) {
        return 0;
    }
    return s_zone_board_map[zone_1_based - 1];
}

static void zones_apply_to_alarm(void){
     // Invia le opzioni zona ad alarm_core
    for(int i=1;i<=INPUT_ZONES_COUNT;i++){
        zone_cfg_t *c = &s_zone_cfg[i-1];
        zone_opts_t o = { .entry_delay = c->zone_delay, .entry_time_ms = (uint16_t)(c->zone_time * 1000u), .exit_delay = c->zone_delay, .exit_time_ms = (uint16_t)(c->zone_time * 1000u), .auto_exclude = c->auto_exclude };
        alarm_set_zone_opts(i, &o);
    }
}

static void zones_load_from_nvs(void){
    memset(s_zone_board_map, 0, sizeof(s_zone_board_map));

    nvs_handle_t h;
    if (nvs_open("zones", NVS_READONLY, &h) == ESP_OK){
        size_t cfg_sz = sizeof(s_zone_cfg);
        if (nvs_get_blob(h, "cfg", s_zone_cfg, &cfg_sz) != ESP_OK) {
            /* default vuoti */
        }

        size_t map_sz = sizeof(s_zone_board_map);
        esp_err_t map_res = nvs_get_blob(h, "map", s_zone_board_map, &map_sz);
        if (map_res != ESP_OK || map_sz != sizeof(s_zone_board_map)) {
            memset(s_zone_board_map, 0, sizeof(s_zone_board_map));
        }
        nvs_close(h);
    }
    zones_apply_to_alarm();
}
static void zones_save_to_nvs(void){
    nvs_handle_t h; if(nvs_open("zones", NVS_READWRITE, &h)!=ESP_OK) return;
    nvs_set_blob(h,"cfg",s_zone_cfg,sizeof(s_zone_cfg));
    nvs_set_blob(h,"map",s_zone_board_map,sizeof(s_zone_board_map));
    nvs_commit(h);
    nvs_close(h);
    zones_apply_to_alarm();
}

#define LOGS_DEFAULT_LIMIT     64
#define LOGS_MAX_FETCH         128
#define LOGS_EVENT_FILTER_MAX  8

typedef struct {
    int limit;
    bool has_result;
    int result;
    bool only_success;
    bool only_failure;
    bool has_user;
    char user[sizeof(((audit_entry_t *)0)->username)];
    size_t event_count;
    char events[LOGS_EVENT_FILTER_MAX][sizeof(((audit_entry_t *)0)->event)];
    bool has_since;
    int64_t since_us;
    bool has_until;
    int64_t until_us;
} logs_filter_t;

static void trim_whitespace(char *str)
{
    if (!str) {
        return;
    }
    char *start = str;
    while (*start && isspace((unsigned char)*start)) {
        ++start;
    }
    if (start != str) {
        size_t len = strlen(start);
        memmove(str, start, len + 1);
    }
    size_t len = strlen(str);
    while (len > 0 && isspace((unsigned char)str[len - 1])) {
        str[--len] = '\0';
    }
}

static void str_to_lower(char *str)
{
    if (!str) {
        return;
    }
    for (; *str; ++str) {
        *str = (char)tolower((unsigned char)*str);
    }
}

static bool parse_time_param(const char *value, int64_t *out_us)
{
    if (!value || !*value || !out_us) {
        return false;
    }
    char *end = NULL;
    double number = strtod(value, &end);
    if (end == value) {
        return false;
    }
    while (end && isspace((unsigned char)*end)) {
        ++end;
    }
    if (end && *end != '\0') {
        return false;
    }
    size_t len = strlen(value);
    double seconds = number;
    if (len > 16) {
        seconds = number / 1000000.0;
    } else if (len > 13) {
        seconds = number / 1000.0;
    }
    if (seconds < -62135596800.0) { // clamp before year 0001
        seconds = -62135596800.0;
    }
    *out_us = (int64_t)(seconds * 1000000.0);
    return true;
}

static void logs_filter_parse(httpd_req_t *req, logs_filter_t *filter)
{
    if (!filter) {
        return;
    }
    memset(filter, 0, sizeof(*filter));
    filter->limit = LOGS_DEFAULT_LIMIT;

    size_t qlen = httpd_req_get_url_query_len(req);
    if (qlen == 0) {
        return;
    }
    if (qlen > 1024) {
        qlen = 1024;
    }
    char *query = calloc(qlen + 1, 1);
    if (!query) {
        return;
    }
    if (httpd_req_get_url_query_str(req, query, qlen + 1) != ESP_OK) {
        free(query);
        return;
    }

    char value[160];

    if (httpd_query_key_value(query, "limit", value, sizeof(value)) == ESP_OK) {
        trim_whitespace(value);
        if (value[0]) {
            char *end = NULL;
            long parsed = strtol(value, &end, 10);
            while (end && isspace((unsigned char)*end)) {
                ++end;
            }
            if (end && *end == '\0') {
                if (parsed < 0) {
                    parsed = 0;
                }
                if (parsed > LOGS_MAX_FETCH) {
                    parsed = LOGS_MAX_FETCH;
                }
                filter->limit = (int)parsed;
            }
        }
    }

    if (httpd_query_key_value(query, "result", value, sizeof(value)) == ESP_OK) {
        trim_whitespace(value);
        str_to_lower(value);
        if (strcmp(value, "1") == 0 || strcmp(value, "ok") == 0 || strcmp(value, "success") == 0 || strcmp(value, "true") == 0 || strcmp(value, "pass") == 0) {
            filter->has_result = true;
            filter->result = 1;
        } else if (strcmp(value, "0") == 0 || strcmp(value, "fail") == 0 || strcmp(value, "error") == 0 || strcmp(value, "false") == 0 || strcmp(value, "warn") == 0) {
            filter->has_result = true;
            filter->result = 0;
        }
    }

    if (httpd_query_key_value(query, "level", value, sizeof(value)) == ESP_OK) {
        trim_whitespace(value);
        str_to_lower(value);
        if (strcmp(value, "warn") == 0 || strcmp(value, "warning") == 0 || strcmp(value, "error") == 0) {
            filter->only_failure = true;
        } else if (strcmp(value, "info") == 0 || strcmp(value, "success") == 0 || strcmp(value, "ok") == 0) {
            filter->only_success = true;
        }
    }

    if (httpd_query_key_value(query, "user", value, sizeof(value)) == ESP_OK) {
        trim_whitespace(value);
        if (value[0]) {
            strlcpy(filter->user, value, sizeof(filter->user));
            filter->has_user = true;
        }
    }

    if (httpd_query_key_value(query, "event", value, sizeof(value)) == ESP_OK) {
        char *save = NULL;
        for (char *token = strtok_r(value, ",", &save); token && filter->event_count < LOGS_EVENT_FILTER_MAX; token = strtok_r(NULL, ",", &save)) {
            trim_whitespace(token);
            if (!token[0]) {
                continue;
            }
            str_to_lower(token);
            strlcpy(filter->events[filter->event_count], token, sizeof(filter->events[0]));
            filter->event_count++;
        }
    }

    if (httpd_query_key_value(query, "since", value, sizeof(value)) == ESP_OK ||
        httpd_query_key_value(query, "from", value, sizeof(value)) == ESP_OK) {
        trim_whitespace(value);
        int64_t since_us = 0;
        if (parse_time_param(value, &since_us)) {
            filter->has_since = true;
            filter->since_us = since_us;
        }
    }

    if (httpd_query_key_value(query, "until", value, sizeof(value)) == ESP_OK ||
        httpd_query_key_value(query, "to", value, sizeof(value)) == ESP_OK) {
        trim_whitespace(value);
        int64_t until_us = 0;
        if (parse_time_param(value, &until_us)) {
            filter->has_until = true;
            filter->until_us = until_us;
        }
    }

    free(query);
}

static int64_t logs_compute_wall_ts(const audit_entry_t *entry, int64_t now_wall_us, int64_t now_uptime_us)
{
    if (!entry) {
        return 0;
    }
    if (entry->wall_ts_us > 0) {
        return entry->wall_ts_us;
    }
    if (now_wall_us <= 0 || now_uptime_us <= 0 || entry->ts_us <= 0) {
        return 0;
    }
    int64_t delta = now_uptime_us - entry->ts_us;
    if (delta < 0) {
        return 0;
    }
    int64_t candidate = now_wall_us - delta;
    return candidate > 0 ? candidate : 0;
}

static bool logs_entry_matches(const audit_entry_t *entry, const logs_filter_t *filter, int64_t wall_ts_us)
{
    if (!entry || !filter) {
        return false;
    }
    if (filter->has_result) {
        int desired = filter->result > 0 ? 1 : 0;
        int actual = entry->result > 0 ? 1 : 0;
        if (desired != actual) {
            return false;
        }
    }
    if (filter->only_success && entry->result <= 0) {
        return false;
    }
    if (filter->only_failure && entry->result > 0) {
        return false;
    }
    if (filter->has_user) {
        if (!entry->username[0] || strcasecmp(entry->username, filter->user) != 0) {
            return false;
        }
    }
    if (filter->event_count > 0) {
        bool matched = false;
        for (size_t i = 0; i < filter->event_count; ++i) {
            if (strcasecmp(entry->event, filter->events[i]) == 0) {
                matched = true;
                break;
            }
        }
        if (!matched) {
            return false;
        }
    }
    if (filter->has_since) {
        if (wall_ts_us <= 0 || wall_ts_us < filter->since_us) {
            return false;
        }
    }
    if (filter->has_until) {
        if (wall_ts_us <= 0 || wall_ts_us > filter->until_us) {
            return false;
        }
    }
    return true;
}

static bool logs_format_iso8601(int64_t ts_us, char *out, size_t cap)
{
    if (!out || cap == 0 || ts_us <= 0) {
        return false;
    }
    time_t seconds = (time_t)(ts_us / 1000000LL);
    struct tm tm_utc;
    if (!gmtime_r(&seconds, &tm_utc)) {
        return false;
    }
    int64_t micros = ts_us % 1000000LL;
    if (micros < 0) {
        micros += 1000000LL;
    }
    int written = snprintf(out, cap, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                           tm_utc.tm_year + 1900,
                           tm_utc.tm_mon + 1,
                           tm_utc.tm_mday,
                           tm_utc.tm_hour,
                           tm_utc.tm_min,
                           tm_utc.tm_sec,
                           (int)(micros / 1000LL));
    return written > 0 && (size_t)written < cap;
}

static const char* audit_event_label(const char* code){
    if (!code || !code[0]) {
        return "Evento";
    }
    if (strcmp(code, "login") == 0) return "Login";
    if (strcmp(code, "logout") == 0) return "Logout";
    if (strcmp(code, "hw_reset") == 0) return "Reset hardware";
    if (strcmp(code, "websec") == 0) return "Certificato web";
    if (strcmp(code, "tamper_reset") == 0) return "Reset tamper";
    return code;
}

static void audit_format_message(const audit_entry_t* ent, char* out, size_t cap){
    if (!out || cap == 0) {
        return;
    }
    const char* label = audit_event_label(ent ? ent->event : NULL);
    const bool has_user = ent && ent->username[0] != '\0';
    const bool has_note = ent && ent->note[0] != '\0';
    const bool otp_pending = ent && strcmp(ent->note, "otp required") == 0;
    const char* outcome = otp_pending ? "in attesa OTP" : (ent && ent->result > 0) ? "riuscito" : "fallito";

    if (!ent) {
        snprintf(out, cap, "%s", label);
        return;
    }

    if (otp_pending) {
        if (has_user) {
            snprintf(out, cap, "%s %s per %s", label, outcome, ent->username);
        } else {
            snprintf(out, cap, "%s %s", label, outcome);
        }
        return;
    }

    if (has_note) {
        snprintf(out, cap, "%s %s%s%s (%s)",
                 label,
                 outcome,
                 has_user ? " per " : "",
                 has_user ? ent->username : "",
                 ent->note);
    } else {
        snprintf(out, cap, "%s %s%s%s",
                 label,
                 outcome,
                 has_user ? " per " : "",
                 has_user ? ent->username : "");
    }
}

static esp_err_t logs_get(httpd_req_t* req){
    if (!check_bearer(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token");
        return ESP_FAIL;
    }

    logs_filter_t filter;
    logs_filter_parse(req, &filter);

    audit_entry_t *entries_buf = calloc(LOGS_MAX_FETCH, sizeof(audit_entry_t));
    if (!entries_buf) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        return ESP_ERR_NO_MEM;
    }

    int fetched = audit_dump_recent(entries_buf, LOGS_MAX_FETCH);
    if (fetched < 0) {
        fetched = 0;
    }

    struct timeval now_tv;
    int64_t now_wall_us = 0;
    if (gettimeofday(&now_tv, NULL) == 0) {
        now_wall_us = (int64_t)now_tv.tv_sec * 1000000LL + (int64_t)now_tv.tv_usec;
    }
    int64_t now_uptime_us = esp_timer_get_time();

    int match_indexes[LOGS_MAX_FETCH];
    int64_t match_wall_ts[LOGS_MAX_FETCH];
    int match_count = 0;

    for (int i = 0; i < fetched; ++i) {
        int64_t wall_ts = logs_compute_wall_ts(&entries_buf[i], now_wall_us, now_uptime_us);
        if (!logs_entry_matches(&entries_buf[i], &filter, wall_ts)) {
            continue;
        }
        match_indexes[match_count] = i;
        match_wall_ts[match_count] = wall_ts;
        ++match_count;
    }

    int64_t resolved_wall_ts[LOGS_MAX_FETCH];
    for (int i = 0; i < match_count; ++i) {
        resolved_wall_ts[i] = match_wall_ts[i];
    }

    const int64_t fallback_gap_us = 1000000; // 1 second gap when we have no better reference
    const int64_t max_reasonable_gap_us = (int64_t)7 * 24 * 3600 * 1000000LL; // one week

    bool have_prev = false;
    int64_t prev_wall = 0;
    int64_t prev_ts = 0;
    for (int i = 0; i < match_count; ++i) {
        int idx = match_indexes[i];
        int64_t entry_ts = entries_buf[idx].ts_us;
        if (resolved_wall_ts[i] > 0) {
            prev_wall = resolved_wall_ts[i];
            prev_ts = entry_ts;
            have_prev = true;
        } else if (have_prev) {
            int64_t delta_ts = entry_ts - prev_ts;
            int64_t candidate = prev_wall + ((delta_ts > 0 && delta_ts < max_reasonable_gap_us) ? delta_ts : fallback_gap_us);
            if (candidate <= prev_wall) {
                candidate = prev_wall + fallback_gap_us;
            }
            resolved_wall_ts[i] = candidate;
            prev_wall = candidate;
            prev_ts = entry_ts;
        }
    }

    bool have_next = false;
    int64_t next_wall = 0;
    int64_t next_ts = 0;
    for (int i = match_count - 1; i >= 0; --i) {
        int idx = match_indexes[i];
        int64_t entry_ts = entries_buf[idx].ts_us;
        if (resolved_wall_ts[i] > 0) {
            next_wall = resolved_wall_ts[i];
            next_ts = entry_ts;
            have_next = true;
        } else if (have_next) {
            int64_t delta_ts = next_ts - entry_ts;
            int64_t candidate = next_wall - ((delta_ts > 0 && delta_ts < max_reasonable_gap_us) ? delta_ts : fallback_gap_us);
            if (candidate <= 0 || candidate >= next_wall) {
                candidate = (next_wall > fallback_gap_us) ? (next_wall - fallback_gap_us) : (next_wall / 2);
                if (candidate <= 0) {
                    candidate = 1;
                }
            }
            resolved_wall_ts[i] = candidate;
            next_wall = candidate;
            next_ts = entry_ts;
        }
    }

    bool have_reference_ts = false;
    for (int i = 0; i < match_count; ++i) {
        if (resolved_wall_ts[i] > 0) {
            have_reference_ts = true;
            break;
        }
    }

    if (have_reference_ts) {
        int64_t seed = now_wall_us > 0 ? now_wall_us : now_uptime_us;
        if (seed <= 0) {
            seed = esp_timer_get_time();
        }
        for (int i = 0; i < match_count; ++i) {
            if (resolved_wall_ts[i] <= 0) {
                seed += fallback_gap_us;
                resolved_wall_ts[i] = seed;
            }
        }
    }

    int start = 0;
    if (filter.limit > 0 && match_count > filter.limit) {
        start = match_count - filter.limit;
    }
    int returned = match_count - start;
    if (returned < 0) {
        returned = 0;
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        free(entries_buf);
        return ESP_ERR_NO_MEM;
    }

    cJSON *entries = cJSON_CreateArray();
    if (!entries) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        free(entries_buf);
        return ESP_ERR_NO_MEM;
    }

    for (int j = match_count - 1; j >= start; --j) {
        int idx = match_indexes[j];
        audit_entry_t *ent = &entries_buf[idx];
        int64_t wall_ts = resolved_wall_ts[j];

        cJSON *entry = cJSON_CreateObject();
        if (!entry) {
            cJSON_Delete(entries);
            cJSON_Delete(root);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
            free(entries_buf);
            return ESP_ERR_NO_MEM;
        }

        char message[160];
        audit_format_message(ent, message, sizeof(message));

        if (wall_ts > 0) {
            double epoch_seconds = (double)wall_ts / 1000000.0;
            cJSON_AddNumberToObject(entry, "ts", epoch_seconds);
            cJSON_AddNumberToObject(entry, "ts_epoch", epoch_seconds);
            cJSON_AddNumberToObject(entry, "ts_ms", epoch_seconds * 1000.0);
            cJSON_AddNumberToObject(entry, "wall_ts_us", (double)wall_ts);
            char iso[32];
            if (logs_format_iso8601(wall_ts, iso, sizeof(iso))) {
                cJSON_AddStringToObject(entry, "ts_iso", iso);
            }
        }

        cJSON_AddNumberToObject(entry, "ts_us", (double)ent->ts_us);
        cJSON_AddNumberToObject(entry, "uptime_s", (double)ent->ts_us / 1000000.0);
        cJSON_AddNumberToObject(entry, "result", ent->result);
        cJSON_AddStringToObject(entry, "event", ent->event);
        cJSON_AddStringToObject(entry, "user", ent->username);
        cJSON_AddStringToObject(entry, "note", ent->note);
        cJSON_AddStringToObject(entry, "message", message);
        const bool otp_pending = ent && strcmp(ent->note, "otp required") == 0;
        cJSON_AddStringToObject(entry, "level", (ent->result > 0 || otp_pending) ? "INFO" : "WARN");
        cJSON_AddItemToArray(entries, entry);
    }

    cJSON_AddItemToObject(root, "entries", entries);
    cJSON_AddNumberToObject(root, "count", returned);
    cJSON_AddNumberToObject(root, "total", match_count);
    cJSON_AddNumberToObject(root, "limit", filter.limit);
    if (filter.has_since) {
        cJSON_AddNumberToObject(root, "since", (double)filter.since_us / 1000000.0);
    }
    if (filter.has_until) {
        cJSON_AddNumberToObject(root, "until", (double)filter.until_us / 1000000.0);
    }

    esp_err_t res = json_reply_cjson(req, root);
    free(entries_buf);
    return res;
}

static esp_err_t logs_clear_post(httpd_req_t* req){
    if (!check_bearer(req) || !is_admin_user(req)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden");
        return ESP_FAIL;
    }

    esp_err_t err = audit_clear_all();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "logs_clear_all failed: %s", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "clear");
        return err;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"ok\"}");
    return ESP_OK;
}

static esp_err_t status_get(httpd_req_t* req){
    if(!check_bearer(req)) { httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"); return ESP_FAIL; }

    provisioning_general_config_t general;
    provisioning_load_general(&general);

    const char* state = "UNKNOWN";

    alarm_state_t _st = alarm_get_state();

    switch (_st){
        case ALARM_DISARMED:     state = "DISARMED"; break;
        case ALARM_ARMED_HOME:   state = "ARMED_HOME"; break;
        case ALARM_ARMED_AWAY:   state = "ARMED_AWAY"; break;
        case ALARM_ARMED_NIGHT:  state = "ARMED_NIGHT"; break;
        case ALARM_ARMED_CUSTOM: state = "ARMED_CUSTOM"; break;
        case ALARM_ALARM:        state = "ALARM"; break;
        case ALARM_MAINTENANCE:  state = "MAINT"; break;
        default: break;
    }

    uint32_t exit_ms = 0, entry_ms = 0; int entry_zone = -1;
    bool exit_p  = alarm_exit_pending(&exit_ms);
    bool entry_p = alarm_entry_pending(&entry_zone, &entry_ms);

    bool is_armed = (_st==ALARM_ARMED_HOME || _st==ALARM_ARMED_AWAY || _st==ALARM_ARMED_NIGHT || _st==ALARM_ARMED_CUSTOM);
    if (entry_p && is_armed) state = "PRE_DISARM";
    else if (exit_p && is_armed) state = "PRE_ARM";

    uint16_t gpioab = 0;
    inputs_read_all(&gpioab);
    bool tamper = inputs_tamper(gpioab);
    bool tamper_alarm = (alarm_last_alarm_was_tamper() && _st == ALARM_ALARM);

    uint16_t outmask = 0;
    outputs_get_mask(&outmask);

    // char zones[256]; size_t off=0;
    // off += snprintf(zones+off, sizeof(zones)-off, "[");
    // for (int z=1; z<=INPUT_ZONES_COUNT; ++z){
    //     bool on = inputs_zone_bit(gpioab, z);
    //     off += snprintf(zones+off, sizeof(zones)-off, "%s%s", (z>1?",":""), on?"true":"false");
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        return ESP_ERR_NO_MEM;
    }
    // off += snprintf(zones+off, sizeof(zones)-off, "]");

    // char buf[512];
    // snprintf(buf, sizeof(buf),
    //     "{\"state\":\"%s\",\"zones_count\":%d,\"zones_active\":%s,\"tamper\":%s,\"outputs_mask\":%u,\"bypass_mask\":%u,\"exit_pending_ms\":%u,\"entry_pending_ms\":%u,\"entry_zone\":%d}",
    //     state, INPUT_ZONES_COUNT, zones, tamper?"true":"false", (unsigned)outmask, (unsigned)alarm_get_bypass_mask(), (unsigned)exit_ms, (unsigned)entry_ms, entry_zone);
    // // snprintf(buf, sizeof(buf),
    // //     "{\"state\":\"%s\",\"zones_count\":%d,\"zones_active\":%s,\"tamper\":%s,\"outputs_mask\":%u,\"bypass_mask\":%u}",
    // //     state, INPUT_ZONES_COUNT, zones, tamper?"true":"false", (unsigned)outmask, (unsigned)alarm_get_bypass_mask());
 
    // return json_reply(req, buf);
    cJSON_AddStringToObject(root, "state", state);
    cJSON_AddNumberToObject(root, "zones_count", INPUT_ZONES_COUNT);

    cJSON *zones = cJSON_CreateArray();
    if (zones) {
        for (int z=1; z<=INPUT_ZONES_COUNT; ++z){
            bool on = inputs_zone_bit(gpioab, z);
            cJSON_AddItemToArray(zones, cJSON_CreateBool(on));
        }
        cJSON_AddItemToObject(root, "zones_active", zones);
    } else {
        cJSON_AddNullToObject(root, "zones_active");
    }

    cJSON_AddBoolToObject(root, "tamper", tamper);
    cJSON_AddBoolToObject(root, "tamper_alarm", tamper_alarm);
    cJSON_AddNumberToObject(root, "outputs_mask", (unsigned)outmask);
    cJSON_AddNumberToObject(root, "bypass_mask", (unsigned)alarm_get_bypass_mask());
    cJSON_AddNumberToObject(root, "exit_pending_ms", (unsigned)exit_ms);
    cJSON_AddNumberToObject(root, "entry_pending_ms", (unsigned)entry_ms);
    cJSON_AddNumberToObject(root, "entry_zone", entry_zone);
    cJSON_AddStringToObject(root, "central_name", general.central_name);

    char *out = cJSON_PrintUnformatted(root);
    if (!out) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        return ESP_ERR_NO_MEM;
    }

    esp_err_t err = json_reply(req, out);
    cJSON_free(out);
    cJSON_Delete(root);
    return err;
}

static esp_err_t zones_get(httpd_req_t* req){
    if(!check_bearer(req)) { httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"); return ESP_FAIL; }
    uint16_t gpioab=0; inputs_read_all(&gpioab);
    cJSON *root = cJSON_CreateObject();
    cJSON *arr  = cJSON_CreateArray();
    cJSON_AddItemToObject(root, "zones", arr);
    for(int z=1; z<=INPUT_ZONES_COUNT; ++z){
        bool on = inputs_zone_bit(gpioab, z);
        cJSON *it = cJSON_CreateObject();
        cJSON_AddNumberToObject(it, "id", z);
        zone_cfg_t *cfg = &s_zone_cfg[z-1];
        const char* zname = cfg->name[0] ? cfg->name : "";        cJSON_AddStringToObject(it, "name", zname);
        cJSON_AddBoolToObject(it, "active", on);
        cJSON_AddBoolToObject(it, "auto_exclude", cfg->auto_exclude);
        cJSON_AddBoolToObject(it, "zone_delay", cfg->zone_delay);
        cJSON_AddNumberToObject(it, "zone_time", (double)cfg->zone_time);
        cJSON_AddNumberToObject(it, "board", (double)zone_board_for_index(z));
        cJSON_AddItemToArray(arr, it);
    }
    char *out = cJSON_PrintUnformatted(root);
    esp_err_t e = json_reply(req, out);
    cJSON_free(out);
    cJSON_Delete(root);
    return e;
}

static esp_err_t scenes_get(httpd_req_t* req){
    if(!check_bearer(req)) { httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"); return ESP_FAIL; }
    uint16_t h=0,n=0,c=0,a=0;
    scenes_get_mask(SCENE_HOME,  &h);
    scenes_get_mask(SCENE_NIGHT, &n);
    scenes_get_mask(SCENE_CUSTOM,&c);
    a = scenes_get_active_mask();

    char buf[256];
    snprintf(buf, sizeof(buf),
        "{\"zones\":%d,\"home\":%u,\"night\":%u,\"custom\":%u,\"active\":%u}",
        INPUT_ZONES_COUNT, (unsigned)h,(unsigned)n,(unsigned)c,(unsigned)a);
    return json_reply(req, buf);
}

static esp_err_t scenes_post(httpd_req_t* req){
    if(!check_bearer(req) || !is_admin_user(req)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden");
        return ESP_FAIL;
    }
    char body[256]; size_t blen = 0;
    if(read_body_to_buf(req, body, sizeof(body), &blen)!=ESP_OK){
        httpd_resp_send_err(req, 400, "body");
        return ESP_FAIL;
    }
    cJSON *json = cJSON_ParseWithLength(body, blen);
    if(!json){
        httpd_resp_send_err(req, 400, "json");
        return ESP_FAIL;
    }
    // scene
    const cJSON *jscene = cJSON_GetObjectItemCaseSensitive(json, "scene");
    if(!cJSON_IsString(jscene) || !jscene->valuestring){
        cJSON_Delete(json);
        httpd_resp_send_err(req, 400, "scene");
        return ESP_FAIL;
    }
    scene_t s = SCENE_CUSTOM;
    if      (strcmp(jscene->valuestring,"home")==0)   s = SCENE_HOME;
    else if (strcmp(jscene->valuestring,"night")==0)  s = SCENE_NIGHT;
    else if (strcmp(jscene->valuestring,"custom")==0) s = SCENE_CUSTOM;
    else { cJSON_Delete(json); httpd_resp_send_err(req, 400, "scene"); return ESP_FAIL; }

    // mask o ids[]
    uint32_t mask = 0u;
    const cJSON *jmask = cJSON_GetObjectItemCaseSensitive(json, "mask");
    if(cJSON_IsNumber(jmask)){
        mask = (jmask->valuedouble < 0) ? 0u : (uint32_t)jmask->valuedouble;
    } else {
        const cJSON *ids = cJSON_GetObjectItemCaseSensitive(json, "ids");
        if (cJSON_IsArray(ids)){
            cJSON *it=NULL;
            cJSON_ArrayForEach(it, ids){
                if(cJSON_IsNumber(it)){
                    int id = it->valueint;
                    if(id>=1 && id<=INPUT_ZONES_COUNT) mask |= (1u << (id-1));
                }
            }
        } else {
            cJSON_Delete(json);
            httpd_resp_send_err(req, 400, "mask");
            return ESP_FAIL;
        }
    }
    cJSON_Delete(json);

    if (scenes_set_mask(s, (uint16_t)mask)!=ESP_OK){
        httpd_resp_send_err(req, 500, "nvs");
        return ESP_FAIL;
    }
    return json_bool(req, true);
//    return json_reply(req, "{\"ok\":true}");
}

// GET /api/zones/config
static esp_err_t zones_config_get(httpd_req_t* req){
    if(!check_bearer(req)) return httpd_resp_send_err(req,401,"token"), ESP_FAIL;
    char buf[INPUT_ZONES_COUNT*128]; size_t off=0;
    off += snprintf(buf+off,sizeof(buf)-off,"{\"items\":[");
    for(int z=1; z<=INPUT_ZONES_COUNT; ++z){
        zone_cfg_t *c=&s_zone_cfg[z-1];
        off += snprintf(buf+off,sizeof(buf)-off,
          "%s{\"id\":%d,\"name\":\"%s\",\"zone_delay\":%s,\"zone_time\":%u,\"auto_exclude\":%s,\"board\":%u}",
          (z>1?",":""), z, (c->name[0]?c->name:""), c->zone_delay?"true":"false", c->zone_time, c->auto_exclude?"true":"false", (unsigned)zone_board_for_index(z));
    }
    off += snprintf(buf+off,sizeof(buf)-off,"]}");
    return json_reply(req, buf);
}

// POST /api/zones/config
static esp_err_t zones_config_post(httpd_req_t* req){
    if(!check_bearer(req) || !is_admin_user(req)) { httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden"); return ESP_FAIL; }
    char body[2048]; size_t blen = 0;
    if(read_body_to_buf(req, body, sizeof(body), &blen)!=ESP_OK){ httpd_resp_send_err(req, 400, "body"); return ESP_FAIL; }
    cJSON *json = cJSON_ParseWithLength(body, blen);
    if(!json){ httpd_resp_send_err(req, 400, "json"); return ESP_FAIL; }
    cJSON *items = cJSON_GetObjectItemCaseSensitive(json, "items");
    if(!cJSON_IsArray(items)){ cJSON_Delete(json); httpd_resp_send_err(req, 400, "items"); return ESP_FAIL; }
    cJSON *it = NULL;
    cJSON_ArrayForEach(it, items){
        cJSON *jid = cJSON_GetObjectItemCaseSensitive(it, "id");
        if(!cJSON_IsNumber(jid)) continue;
        int id = jid->valueint;
        if(id<1 || id>INPUT_ZONES_COUNT) continue;
        zone_cfg_t *c = &s_zone_cfg[id-1];
        cJSON *jn=NULL;
        jn = cJSON_GetObjectItemCaseSensitive(it, "name");
        if(cJSON_IsString(jn)){
            size_t maxlen = sizeof(c->name)-1;
            strncpy(c->name, jn->valuestring, maxlen);
            c->name[maxlen]=0;
        }
        // nuovo schema: zone_delay/zone_time (con fallback legacy)
        bool z_delay = c->zone_delay;
        uint16_t z_time = c->zone_time;

        jn = cJSON_GetObjectItemCaseSensitive(it, "zone_delay");
        if(cJSON_IsBool(jn)) z_delay = cJSON_IsTrue(jn);

        jn = cJSON_GetObjectItemCaseSensitive(it, "zone_time");
        if(cJSON_IsNumber(jn)) z_time = (uint16_t)jn->valuedouble;

        // fallback legacy
        jn = cJSON_GetObjectItemCaseSensitive(it, "entry_delay");
        if(cJSON_IsBool(jn)) z_delay = cJSON_IsTrue(jn);
        jn = cJSON_GetObjectItemCaseSensitive(it, "exit_delay");
        if(cJSON_IsBool(jn)) z_delay = (z_delay || cJSON_IsTrue(jn));

        jn = cJSON_GetObjectItemCaseSensitive(it, "entry_time");
        if(cJSON_IsNumber(jn) && (uint16_t)jn->valuedouble>0) z_time = (uint16_t)jn->valuedouble;
        jn = cJSON_GetObjectItemCaseSensitive(it, "exit_time");
        if(cJSON_IsNumber(jn) && (uint16_t)jn->valuedouble>0) z_time = (uint16_t)jn->valuedouble;

        jn = cJSON_GetObjectItemCaseSensitive(it, "auto_exclude");
        if(cJSON_IsBool(jn)) c->auto_exclude = cJSON_IsTrue(jn);

        uint8_t board = zone_board_for_index(id);
        jn = cJSON_GetObjectItemCaseSensitive(it, "board");
        if (cJSON_IsNumber(jn)) {
            int raw = (int)jn->valuedouble;
            if (raw < 0) raw = 0;
            if (raw > 255) raw = 255;
            board = (uint8_t)raw;
        }

        c->zone_delay = z_delay;
        c->zone_time  = z_time;
        s_zone_board_map[id-1] = board;
    }
    cJSON_Delete(json);
    zones_save_to_nvs();
    return json_bool(req, true);
}

// ─────────────────────────────────────────────────────────────────────────────
// GESTIONE SERVIZI SERVER HTTP
// ─────────────────────────────────────────────────────────────────────────────

static esp_err_t send_file(httpd_req_t* req, const char* fname){
    char path[128];
    snprintf(path,sizeof(path),"/spiffs/%s", fname);
    extern esp_err_t auth__send_file_from_spiffs__internal_for_example_only(httpd_req_t*, const char*); // not exported; we'll re-serve in auth.c privately
    // As a workaround in sample: duplicate a tiny static sender here:
    FILE* f = fopen(path,"rb");
    if (!f){ httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Not found"); return ESP_FAIL; }
    const char* ext = strrchr(path,'.');
    const char* ct = "text/plain";
    if (ext){
        if (!strcmp(ext,".html")) ct = "text/html";
        else if (!strcmp(ext,".css")) ct = "text/css";
        else if (!strcmp(ext,".js")) ct = "application/javascript";
        else if (!strcmp(ext,".svg")) ct = "image/svg+xml";
        else if (!strcmp(ext,".ico")) ct = "image/x-icon";
    }
    httpd_resp_set_type(req, ct);
    // auth_set_security_headers(req);
    set_https_security_headers(req);
    char buf[1024];
    size_t r;
    while((r=fread(buf,1,sizeof(buf),f))>0){
        if (httpd_resp_send_chunk(req, buf, r)!=ESP_OK){ fclose(f); httpd_resp_sendstr_chunk(req, NULL); return ESP_FAIL; }
    }
    fclose(f);
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

static esp_err_t redirect_http_handler(httpd_req_t* req){
    const char* uri = "/";
    if (req->uri[0] != '\0'){
        uri = req->uri;
    }
    char path[192];
    strlcpy(path, uri, sizeof(path));
    size_t qlen = httpd_req_get_url_query_len(req);
    if (qlen > 0){
        char* query = malloc(qlen + 1);
        if (query){
            if (httpd_req_get_url_query_str(req, query, qlen + 1) == ESP_OK){
                if (strlen(path) + 1 < sizeof(path)){
                    strlcat(path, "?", sizeof(path));
                    strlcat(path, query, sizeof(path));
                }
            }
            free(query);
        }
    }
    char location[192];
    build_https_location(req, path, location, sizeof(location));
    httpd_resp_set_status(req, "301 Moved Permanently");
    httpd_resp_set_hdr(req, "Location", location);
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req, NULL, 0);
}

static esp_err_t start_http_redirect_server(void){
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.server_port = 80;
    cfg.ctrl_port += 1;  // avoid clashing with the HTTPS server control socket
    cfg.uri_match_fn = httpd_uri_match_wildcard;
    cfg.lru_purge_enable = true;
    httpd_handle_t srv = NULL;
    esp_err_t err = httpd_start(&srv, &cfg);
    if (err != ESP_OK){
        ESP_LOGE(TAG, "Start HTTP redirect server failed: %s", esp_err_to_name(err));
        return err;
    }
    s_http_redirect_server = srv;
    static httpd_uri_t redirect_get    = {.uri="/*", .method=HTTP_GET,    .handler=redirect_http_handler, .user_ctx=NULL};
    static httpd_uri_t redirect_post   = {.uri="/*", .method=HTTP_POST,   .handler=redirect_http_handler, .user_ctx=NULL};
    static httpd_uri_t redirect_put    = {.uri="/*", .method=HTTP_PUT,    .handler=redirect_http_handler, .user_ctx=NULL};
    static httpd_uri_t redirect_delete = {.uri="/*", .method=HTTP_DELETE, .handler=redirect_http_handler, .user_ctx=NULL};
#ifdef HTTP_HEAD
    static httpd_uri_t redirect_head   = {.uri="/*", .method=HTTP_HEAD,   .handler=redirect_http_handler, .user_ctx=NULL};
#endif
#ifdef HTTP_OPTIONS
    static httpd_uri_t redirect_options = {.uri="/*", .method=HTTP_OPTIONS, .handler=redirect_http_handler, .user_ctx=NULL};
#endif
    httpd_register_uri_handler(srv, &redirect_get);
    httpd_register_uri_handler(srv, &redirect_post);
    httpd_register_uri_handler(srv, &redirect_put);
    httpd_register_uri_handler(srv, &redirect_delete);
#ifdef HTTP_HEAD
    httpd_register_uri_handler(srv, &redirect_head);
#endif
#ifdef HTTP_OPTIONS
    httpd_register_uri_handler(srv, &redirect_options);
#endif
    ESP_LOGI(TAG, "Server HTTP redirect attivo sulla porta %d", cfg.server_port);
    return ESP_OK;
}

static esp_err_t root_get(httpd_req_t* req){
    if (!s_provisioned){
        // auth_set_security_headers(req);
        // return send_file(req, "index.html");
        return send_file(req, "wizard.html");
    }
    // auth_set_security_headers(req);
    // httpd_resp_set_status(req, "302 Found");
    // httpd_resp_set_hdr(req, "Location", s_cloudflare_ui_url);
    // return httpd_resp_send(req, NULL, 0);
    user_info_t user;
    if (!auth_check_cookie(req, &user)){
        return send_file(req, "login.html");
    }
    return send_file(req, "index.html");
}

static esp_err_t login_html_get(httpd_req_t* req){
    // If already logged, go to index
    user_info_t u;
    if (auth_check_cookie(req,&u)){
        // httpd_resp_set_status(req,"302 Found");
        // httpd_resp_set_hdr(req,"Location","/");
        // auth_set_security_headers(req);
        // return httpd_resp_send(req,NULL,0);
        return send_https_redirect(req, "/", "302 Found");
    }
    return send_file(req,"login.html");
}

static esp_err_t index_html_get(httpd_req_t* req){
    if (!s_provisioned){
        // auth_set_security_headers(req);
        // return send_file(req, "index.html");
        return send_file(req, "wizard.html");
    }
    // auth_set_security_headers(req);
    // httpd_resp_set_status(req, "302 Found");
    // httpd_resp_set_hdr(req, "Location", s_cloudflare_ui_url);
    // return httpd_resp_send(req, NULL, 0);
    user_info_t u;
    if (!auth_check_cookie(req,&u)){
        return send_https_redirect(req, "/login.html", "302 Found");
    }
    return send_file(req, "index.html");
}
static esp_err_t wizard_html_get(httpd_req_t* req){
    return send_file(req, "wizard.html");
}
static esp_err_t admin_html_get(httpd_req_t* req){
    if (!auth_gate_html(req, ROLE_ADMIN)) return ESP_OK;
    return send_file(req,"admin.html");
}
static esp_err_t four03_html_get(httpd_req_t* req){
    return send_file(req,"403.html");
}

// Static assets (no gate)
static esp_err_t js_get(httpd_req_t* req){
    const char* uri = req->uri;
    if (strstr(uri,"config.js")) return send_file(req,"js/config.js");
    if (strstr(uri,"legacy-script.js")) return send_file(req,"js/legacy-script.js");
    if (strstr(uri,"script.js")) return send_file(req,"js/script.js");
    if (strstr(uri,"admin.js")) return send_file(req,"js/admin.js");
    if (strstr(uri,"qrcode.min.js")) return send_file(req,"js/qrcode.min.js");
    if (strstr(uri,"bootstrap.bundle.min.js")) return send_file(req,"js/bootstrap.bundle.min.js");
    if (strstr(uri,"bootstrap.bundle.min.js.map")) return send_file(req,"js/bootstrap.bundle.min.js.map");
    // if (strstr(uri,"login.js")) return send_file(req,"js/login.js");
    // if (strstr(uri,"app.js"))   return send_file(req,"js/app.js");
    if (strstr(uri,"/js/api.js")) return send_file(req,"js/api.js");
    if (strstr(uri,"/js/login.js")) return send_file(req,"js/login.js");
    if (strstr(uri,"/js/app.js"))   return send_file(req,"js/app.js");
    return httpd_resp_send_err(req,HTTPD_404_NOT_FOUND,"nope");
}
static esp_err_t css_get(httpd_req_t* req){
    const char* uri = req->uri;
    if (strstr(uri,"style.css")) return send_file(req,"css/style.css"); 
    if (strstr(uri,"bootstrap.min.css")) return send_file(req,"css/bootstrap.min.css");
    if (strstr(uri,"bootstrap.min.css.map")) return send_file(req,"css/bootstrap.min.css.map");
    return httpd_resp_send_err(req,HTTPD_404_NOT_FOUND,"nope");
}

// Example protected API
static esp_err_t api_me_get(httpd_req_t* req){ return auth_handle_me(req); }
static esp_err_t api_login_post(httpd_req_t* req){ return auth_handle_login(req); }
static esp_err_t api_logout_post(httpd_req_t* req){ return auth_handle_logout(req); }

// Example admin-only API using Bearer
static esp_err_t api_admin_only_get(httpd_req_t* req){
    user_info_t u;
    if (!auth_check_bearer(req,&u) || u.role != ROLE_ADMIN){
        return httpd_resp_send_err(req,HTTPD_403_FORBIDDEN,"admin only");
    }
    httpd_resp_set_type(req,"application/json");
    auth_set_security_headers(req);
    return httpd_resp_sendstr(req,"{\"secret\":\"42\"}");
}

static esp_err_t status_get(httpd_req_t* req);
static esp_err_t logs_get(httpd_req_t* req);
static esp_err_t logs_clear_post(httpd_req_t* req);
static esp_err_t zones_get (httpd_req_t* req);
static esp_err_t scenes_get(httpd_req_t* req);
static esp_err_t scenes_post(httpd_req_t* req);
static esp_err_t arm_post(httpd_req_t* req);
static esp_err_t disarm_post(httpd_req_t* req);
static esp_err_t tamper_reset_post(httpd_req_t* req);
static esp_err_t user_post_pin(httpd_req_t* req);

static esp_err_t users_create_post(httpd_req_t* req);
static esp_err_t users_name_post(httpd_req_t* req);
static esp_err_t users_pin_admin_post(httpd_req_t* req);
static esp_err_t users_rfid_learn_post(httpd_req_t* req);
static esp_err_t users_rfid_clear_post(httpd_req_t* req);
static esp_err_t users_admin_list_get(httpd_req_t* req);

// ─────────────────────────────────────────────────────────────────────────────
// START/STOP server + registrazione URI
// ─────────────────────────────────────────────────────────────────────────────
static const httpd_uri_t s_http_routes[] = {
    { .uri = "/",                 .method = HTTP_GET,     .handler = root_get },
    { .uri = "/login.html",       .method = HTTP_GET,     .handler = login_html_get },
    { .uri = "/index.html",       .method = HTTP_GET,     .handler = index_html_get },
    { .uri = "/wizard.html",      .method = HTTP_GET,     .handler = wizard_html_get },
    { .uri = "/admin.html",       .method = HTTP_GET,     .handler = admin_html_get },
    { .uri = "/403.html",         .method = HTTP_GET,     .handler = four03_html_get },
    { .uri = "/js/app.js",        .method = HTTP_GET,     .handler = js_get },
    { .uri = "/js/api.js",        .method = HTTP_GET,     .handler = js_get },
    { .uri = "/js/admin.js",      .method = HTTP_GET,     .handler = js_get },
    { .uri = "/js/script.js",     .method = HTTP_GET,     .handler = js_get },
    { .uri = "/js/login.js",      .method = HTTP_GET,     .handler = js_get },
    { .uri = "/js/qrcode.min.js", .method = HTTP_GET,     .handler = js_get },
    { .uri = "/js/bootstrap.bundle.min.js",     .method = HTTP_GET, .handler = js_get },
    { .uri = "/js/bootstrap.bundle.min.js.map", .method = HTTP_GET, .handler = js_get },
    { .uri = "/css/bootstrap.min.css",          .method = HTTP_GET, .handler = css_get },
    { .uri = "/css/bootstrap.min.css.map",      .method = HTTP_GET, .handler = css_get },
    { .uri = "/css/style.css",    .method = HTTP_GET,     .handler = css_get },
    { .uri = "/api/login",        .method = HTTP_POST,    .handler = api_login_post },
    { .uri = "/api/logout",       .method = HTTP_POST,    .handler = api_logout_post },
    { .uri = "/api/me",           .method = HTTP_GET,     .handler = api_me_get },
    { .uri = "/api/admin/secret", .method = HTTP_GET,     .handler = api_admin_only_get },
    { .uri = "/api/provision/status",  .method = HTTP_GET,  .handler = provision_status_get },
    { .uri = "/api/provision/finish",  .method = HTTP_POST, .handler = provision_finish_post },
    { .uri = "/api/provision/reset",   .method = HTTP_POST, .handler = provision_reset_post },
    { .uri = "/api/provision/general", .method = HTTP_POST, .handler = provision_general_post },
    { .uri = "/api/can/nodes",           .method = HTTP_GET,     .handler = api_can_nodes_get },
    { .uri = "/api/can/nodes",           .method = HTTP_OPTIONS, .handler = api_can_nodes_options },
    { .uri = "/api/can/nodes/*",         .method = HTTP_DELETE,  .handler = api_can_node_delete },
    { .uri = "/api/can/nodes/*",         .method = HTTP_OPTIONS, .handler = api_can_node_delete_options },
    { .uri = "/api/can/scan",            .method = HTTP_POST,    .handler = api_can_scan_post },
    { .uri = "/api/can/scan",            .method = HTTP_OPTIONS, .handler = api_can_scan_options },
    { .uri = "/api/can/test-toggle",           .method = HTTP_POST,    .handler = api_can_test_toggle_post },
    { .uri = "/api/can/test-toggle",           .method = HTTP_OPTIONS, .handler = api_can_test_toggle_options },
    { .uri = "/api/can/test/broadcast/on",     .method = HTTP_POST,    .handler = api_can_test_broadcast_on_post },
    { .uri = "/api/can/test/broadcast/on",     .method = HTTP_OPTIONS, .handler = api_can_test_broadcast_options },
    { .uri = "/api/can/test/broadcast/off",    .method = HTTP_POST,    .handler = api_can_test_broadcast_off_post },
    { .uri = "/api/can/test/broadcast/off",    .method = HTTP_OPTIONS, .handler = api_can_test_broadcast_options },
    { .uri = "/api/can/node/*/identify", .method = HTTP_POST,    .handler = api_can_node_identify_post },
    { .uri = "/api/can/node/*/identify", .method = HTTP_OPTIONS, .handler = api_can_node_identify_options },
    { .uri = "/api/status",             .method = HTTP_GET,  .handler = status_get },
    { .uri = "/api/zones",              .method = HTTP_GET,  .handler = zones_get },
    { .uri = "/api/zones/config",       .method = HTTP_GET,  .handler = zones_config_get },
    { .uri = "/api/zones/config",       .method = HTTP_POST, .handler = zones_config_post },
    { .uri = "/api/scenes",             .method = HTTP_GET,  .handler = scenes_get },
    { .uri = "/api/scenes",             .method = HTTP_POST, .handler = scenes_post },
    { .uri = "/api/logs",               .method = HTTP_GET,  .handler = logs_get },
    { .uri = "/api/logs/clear",         .method = HTTP_POST, .handler = logs_clear_post },
    { .uri = "/api/user/password",      .method = HTTP_POST, .handler = user_post_password },
    { .uri = "/api/user/totp",          .method = HTTP_GET,  .handler = user_get_totp },
    { .uri = "/api/user/totp/enable",   .method = HTTP_POST, .handler = user_post_totp_enable },
    { .uri = "/api/user/totp/confirm",  .method = HTTP_POST, .handler = user_post_totp_confirm },
    { .uri = "/api/user/totp/disable",  .method = HTTP_POST, .handler = user_post_totp_disable },
    { .uri = "/api/arm",                .method = HTTP_POST, .handler = arm_post },
    { .uri = "/api/disarm",             .method = HTTP_POST, .handler = disarm_post },
    { .uri = "/api/tamper/reset",       .method = HTTP_POST, .handler = tamper_reset_post },
    { .uri = "/api/user/pin",           .method = HTTP_POST, .handler = user_post_pin },
    { .uri = "/api/users",              .method = HTTP_GET,  .handler = users_list_get },
    { .uri = "/api/users/password",     .method = HTTP_POST, .handler = users_password_post },
    { .uri = "/api/users/name",         .method = HTTP_POST, .handler = users_name_post },
    { .uri = "/api/users/create",       .method = HTTP_POST, .handler = users_create_post },
    { .uri = "/api/users/pin",          .method = HTTP_POST, .handler = users_pin_admin_post },
    { .uri = "/api/users/rfid/learn",   .method = HTTP_POST, .handler = users_rfid_learn_post },
    { .uri = "/api/users/rfid/clear",   .method = HTTP_POST, .handler = users_rfid_clear_post },
    { .uri = "/api/admin/users",        .method = HTTP_GET,  .handler = users_admin_list_get },
    { .uri = "/api/sys/net",            .method = HTTP_GET,  .handler = sys_net_get },
    { .uri = "/api/sys/net",            .method = HTTP_POST, .handler = sys_net_post },
    { .uri = "/api/sys/mqtt",           .method = HTTP_GET,  .handler = sys_mqtt_get },
    { .uri = "/api/sys/mqtt",           .method = HTTP_POST, .handler = sys_mqtt_post },
    { .uri = "/api/sys/mqtt/reveal",    .method = HTTP_POST, .handler = sys_mqtt_reveal_post },
    { .uri = "/api/sys/mqtt/test",      .method = HTTP_POST, .handler = sys_mqtt_test_post },
    { .uri = "/api/sys/cloudflare",     .method = HTTP_GET,  .handler = sys_cloudflare_get },
    { .uri = "/api/sys/cloudflare",     .method = HTTP_POST, .handler = sys_cloudflare_post },
    { .uri = "/api/sys/websec",         .method = HTTP_GET,  .handler = sys_websec_get },
    { .uri = "/api/sys/websec",         .method = HTTP_POST, .handler = sys_websec_post },
    { .uri = "/ws",                     .method = HTTP_GET,  .handler = ws_handler, .is_websocket = true },
};

static void register_uri_set(httpd_handle_t srv, const httpd_uri_t *routes, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        const httpd_uri_t *uri = &routes[i];
        esp_err_t reg_err = httpd_register_uri_handler(srv, uri);
        if (reg_err != ESP_OK) {
            ESP_LOGW(TAG, "httpd_register_uri_handler failed for %s (%s)",
                     uri->uri, esp_err_to_name(reg_err));
        }
    }
}


static esp_err_t start_web(void){
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.stack_size = 12288;
    cfg.max_uri_handlers = 80;
    cfg.lru_purge_enable = true;
    cfg.server_port = 443;
    cfg.uri_match_fn = httpd_uri_match_wildcard;

    httpd_handle_t srv = NULL;
    esp_err_t err = https_start(&srv, &cfg);
    if (err != ESP_OK){
        return err;
    }
    // s_server = srv;
    s_https_server = srv;

    esp_err_t redir_err = start_http_redirect_server();
    if (redir_err != ESP_OK){
        ESP_LOGW(TAG, "HTTP redirect server non disponibile: %s", esp_err_to_name(redir_err));
    }
    ws_clients_reset();

    register_uri_set(srv, s_http_routes, sizeof(s_http_routes) / sizeof(s_http_routes[0]));


    ESP_LOGI(TAG, "Server HTTPS avviato su porta %d (%s)",
             cfg.server_port, s_web_tls_state.using_builtin ? "certificato builtin" : "certificato personalizzato");

    return ESP_OK;
}

esp_err_t web_server_start(void){
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(spiffs_init());
    ESP_ERROR_CHECK(audit_init(128));
    ESP_ERROR_CHECK(auth_init());

    provisioning_load_state();
    
    ESP_ERROR_CHECK(start_web());

    zones_load_from_nvs();

    ESP_LOGI(TAG, "Pronto. Apri https://<esp-ip>");
    return ESP_OK;
}

esp_err_t web_server_stop(void){
    // if (!s_server) return ESP_OK;
    // httpd_handle_t handle = s_server;
    // s_server = NULL;
    // ws_clients_reset();
    // esp_err_t err = httpd_ssl_stop(handle);
    // if (err != ESP_OK){
    //     ESP_LOGE(TAG, "httpd_ssl_stop failed: %s", esp_err_to_name(err));
    esp_err_t first_err = ESP_OK;
    if (s_https_server){
        httpd_handle_t handle = s_https_server;
        s_https_server = NULL;
        ws_clients_reset();
        esp_err_t err = httpd_ssl_stop(handle);
        if (err != ESP_OK){
            ESP_LOGE(TAG, "httpd_ssl_stop failed: %s", esp_err_to_name(err));
            if (first_err == ESP_OK) first_err = err;
        }
    }
    // return err;
    if (s_http_redirect_server){
        httpd_handle_t handle = s_http_redirect_server;
        s_http_redirect_server = NULL;
        ws_clients_reset();
        esp_err_t err = httpd_stop(handle);
        if (err != ESP_OK){
            ESP_LOGE(TAG, "httpd_stop (redirect) failed: %s", esp_err_to_name(err));
            if (first_err == ESP_OK) first_err = err;
        }
    }
    return first_err;
}

static void web_restart_task(void* arg){
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(200));
    ESP_LOGI(TAG, "Riavvio del server HTTPS in corso");
    esp_err_t err = web_server_stop();
    if (err != ESP_OK){
        ESP_LOGW(TAG, "Stop server fallito: %s", esp_err_to_name(err));
    }
    err = start_web();
    if (err != ESP_OK){
        ESP_LOGE(TAG, "Start server fallito: %s", esp_err_to_name(err));
    }
    s_restart_pending = false;
    vTaskDelete(NULL);
}

static void web_server_restart_async(void){
    if (s_restart_pending) return;
    s_restart_pending = true;
    BaseType_t ok = xTaskCreate(web_restart_task, "web_rst", 4096, NULL, tskIDLE_PRIORITY+2, NULL);
    if (ok != pdPASS){
        s_restart_pending = false;
        ESP_LOGE(TAG, "Impossibile creare il task di riavvio web");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GESTIONE ALLARME - ARM / DISARM
// ─────────────────────────────────────────────────────────────────────────────

static esp_err_t arm_post(httpd_req_t* req)
{
    if(!check_bearer(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"), ESP_FAIL;
    char user[32]={0};
    user_info_t info;
    if (!auth_check_bearer(req, &info)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"), ESP_FAIL;
    strncpy(user, info.username, sizeof(user)-1); user[sizeof(user)-1]=0;


    char body[WEB_MAX_BODY_LEN]; size_t blen = 0;
    if(read_body_to_buf(req, body, sizeof(body), &blen)!=ESP_OK) return httpd_resp_send_err(req, 400, "body"), ESP_FAIL;
    cJSON* root = cJSON_Parse(body);
    if(!root) return httpd_resp_send_err(req, 400, "json"), ESP_FAIL;

    char mode[16]={0}, pin[16]={0};
    const cJSON* jmode = cJSON_GetObjectItemCaseSensitive(root, "mode");
    const cJSON* jpin  = cJSON_GetObjectItemCaseSensitive(root, "pin");
    if (cJSON_IsString(jmode) && jmode->valuestring) strncpy(mode, jmode->valuestring, sizeof(mode)-1);
    if (cJSON_IsString(jpin)  && jpin->valuestring)  strncpy(pin,  jpin->valuestring,  sizeof(pin)-1);
    cJSON_Delete(root);

    if(!mode[0] || !pin[0]) return httpd_resp_send_err(req, 400, "mode/pin"), ESP_FAIL;
    if(!auth_verify_pin(user, pin)) return httpd_resp_send_err(req, 401, "bad pin"), ESP_FAIL;

    // if      (strcasecmp(mode, "away")==0)   alarm_arm_away();
    // else if (strcasecmp(mode, "home")==0)   alarm_arm_home();
    // else if (strcasecmp(mode, "night")==0)  alarm_arm_night();
    // else if (strcasecmp(mode, "custom")==0) alarm_arm_custom();
    // else return httpd_resp_send_err(req, 400, "bad mode"), ESP_FAIL;

    // 1) Determina stato target e maschera scena
    alarm_state_t target = ALARM_DISARMED;
    uint16_t scene_mask = 0;
    if      (strcasecmp(mode, "away")==0)   { target = ALARM_ARMED_AWAY;  scene_mask = scenes_mask_all(INPUT_ZONES_COUNT); }
    else if (strcasecmp(mode, "home")==0)   { target = ALARM_ARMED_HOME;  scenes_get_mask(SCENE_HOME,  &scene_mask); }
    else if (strcasecmp(mode, "night")==0)  { target = ALARM_ARMED_NIGHT; scenes_get_mask(SCENE_NIGHT, &scene_mask); }
    else if (strcasecmp(mode, "custom")==0) { target = ALARM_ARMED_CUSTOM;scenes_get_mask(SCENE_CUSTOM,&scene_mask); }
    else return httpd_resp_send_err(req, 400, "bad mode"), ESP_FAIL;

    // 2) Calcola effettiva maschera attiva (profilo ∧ scena)
    profile_t prof = alarm_get_profile(target);
    uint16_t eff_mask = prof.active_mask & scene_mask;

    // 3) Costruisci elenco zone aperte e bypass automatico (auto_exclude)
    uint16_t ab=0; (void)inputs_read_all(&ab);
    uint16_t open_mask = 0;
    for (int z=1; z<=INPUT_ZONES_COUNT; ++z){
        if (inputs_zone_bit(ab, z)) open_mask |= (1u << (z-1));
    }
    uint16_t blocking = 0, bypass = 0;
    for (int i=0; i<INPUT_ZONES_COUNT; ++i){
        uint16_t bit = (1u<<i);
        if ( (eff_mask & bit) && (open_mask & bit) ){
            /* RITARDO UNICO: se la zona ha un ritardo ingresso configurato (>0),
               consentiamo l’ARM e NON la mettiamo in bypass: partirà il countdown. */
            bool has_delay = (s_zone_cfg[i].zone_delay && s_zone_cfg[i].zone_time > 0);   // se nel tuo struct è _ms, adatta!
            if (has_delay){
                continue;  // né blocking, né bypass
            }
            if (s_zone_cfg[i].auto_exclude) bypass |= bit;
            else                            blocking |= bit;
        }
    }
    
    if (blocking){
        // Ritorna 409 + lista zone bloccanti con id+name
        char buf[512]; size_t off=0;
        off += snprintf(buf+off,sizeof(buf)-off,"{\"open_blocking\":[");
        bool first=true;
        for (int i=0;i<INPUT_ZONES_COUNT;i++){
            if (blocking & (1u<<i)){
                zone_cfg_t *c=&s_zone_cfg[i];
                off += snprintf(buf+off,sizeof(buf)-off, "%s{\"id\":%d", first?"":",", i+1);
                if (c->name[0]) off += snprintf(buf+off,sizeof(buf)-off, ",\"name\":\"%s\"", c->name);
                off += snprintf(buf+off,sizeof(buf)-off, "}");
                first=false;
            }
        }
        off += snprintf(buf+off,sizeof(buf)-off,"]}");
        httpd_resp_set_status(req, "409 Conflict");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, buf, HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    // 4) Applica scena attiva e bypass
    scenes_set_active_mask(scene_mask);
    alarm_set_bypass_mask(bypass);

    // 5) ARM vero e proprio
    if      (target == ALARM_ARMED_AWAY)   alarm_arm_away();
    else if (target == ALARM_ARMED_HOME)   alarm_arm_home();
    else if (target == ALARM_ARMED_NIGHT)  alarm_arm_night();
    else if (target == ALARM_ARMED_CUSTOM) alarm_arm_custom();

    // 6) Avvia exit delay (ritardo unico: se al momento dell'ARM ci sono zone ritardate aperte,
    //    usa il MIN dei loro zone_time come durata di uscita; altrimenti usa il profilo)
    prof = alarm_get_profile(target);
    uint32_t exit_ms = prof.exit_delay_ms;
    {
        uint32_t min_s = 0; bool found=false;
        for (int i=0;i<INPUT_ZONES_COUNT;i++){
            uint16_t bit = (1u<<i);
            if ( (eff_mask & bit) && (open_mask & bit) && s_zone_cfg[i].zone_delay && s_zone_cfg[i].zone_time>0 ){
                if (!found || (uint32_t)s_zone_cfg[i].zone_time < min_s){ min_s = (uint32_t)s_zone_cfg[i].zone_time; }
                found = true;
            }
        }
        if (found){ exit_ms = min_s * 1000u; }
    }
    alarm_begin_exit(exit_ms);

    return json_reply(req, "{\"ok\":true}");
}

static esp_err_t tamper_reset_post(httpd_req_t* req)
{
    if (!check_bearer(req)) {
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"), ESP_FAIL;
    }

    char user[32] = {0};
    if (!current_user_from_req(req, user, sizeof(user))) {
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"), ESP_FAIL;
    }

    char body[128]; size_t bl = 0;
    if (read_body_to_buf(req, body, sizeof(body), &bl) != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "body"), ESP_FAIL;
    }

    cJSON* root = cJSON_ParseWithLength(body, bl);
    if (!root) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "json"), ESP_FAIL;
    }

    const cJSON* jpass = cJSON_GetObjectItemCaseSensitive(root, "password");
    const char* pass = (cJSON_IsString(jpass) && jpass->valuestring) ? jpass->valuestring : NULL;
    if (!pass || pass[0] == '\0') {
        cJSON_Delete(root);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "password"), ESP_FAIL;
    }

    if (!auth_verify_password(user, pass)) {
        cJSON_Delete(root);
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "bad pass"), ESP_FAIL;
    }

    bool is_tamper_alarm = (alarm_get_state() == ALARM_ALARM) && alarm_last_alarm_was_tamper();
    if (!is_tamper_alarm) {
        cJSON_Delete(root);
        httpd_resp_set_status(req, "409 Conflict");
        return json_reply(req, "{\"error\":\"notamper\",\"message\":\"Allarme non generato dal tamper.\"}");
    }

    uint16_t gpioab = 0;
    inputs_read_all(&gpioab);
    if (inputs_tamper(gpioab)) {
        cJSON_Delete(root);
        httpd_resp_set_status(req, "409 Conflict");
        return json_reply(req, "{\"error\":\"tamper_open\",\"message\":\"Linea tamper ancora aperta.\"}");
    }

    cJSON_Delete(root);

    alarm_disarm();
    audit_append("tamper_reset", user, 1, "Reset tamper");
    return json_reply(req, "{\"ok\":true}");
}

static esp_err_t disarm_post(httpd_req_t* req)
{
    if(!check_bearer(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"), ESP_FAIL;
    char user[32]={0};
    user_info_t info;
    if (!auth_check_bearer(req, &info)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"), ESP_FAIL;
    strncpy(user, info.username, sizeof(user)-1); user[sizeof(user)-1]=0;


    char body[WEB_MAX_BODY_LEN]; size_t blen = 0;
    if(read_body_to_buf(req, body, sizeof(body), &blen)!=ESP_OK) return httpd_resp_send_err(req, 400, "body"), ESP_FAIL;
    cJSON* root = cJSON_Parse(body);
    if(!root) return httpd_resp_send_err(req, 400, "json"), ESP_FAIL;

    char pin[16]={0};
    const cJSON* jpin = cJSON_GetObjectItemCaseSensitive(root, "pin");
    if (cJSON_IsString(jpin) && jpin->valuestring) strncpy(pin, jpin->valuestring, sizeof(pin)-1);
    cJSON_Delete(root);

    if(!pin[0]) return httpd_resp_send_err(req, 400, "pin"), ESP_FAIL;
    if(!auth_verify_pin(user, pin)) return httpd_resp_send_err(req, 401, "bad pin"), ESP_FAIL;

    alarm_disarm();
    return json_reply(req, "{\"ok\":true}");
}

static esp_err_t user_post_pin(httpd_req_t* req)
{
    if(!check_bearer(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"), ESP_FAIL;
    char user[32]={0};
    user_info_t info;
    if (!auth_check_bearer(req, &info)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"), ESP_FAIL;
    strncpy(user, info.username, sizeof(user)-1); user[sizeof(user)-1]=0;


    char body[WEB_MAX_BODY_LEN]; size_t blen = 0;
    if(read_body_to_buf(req, body, sizeof(body), &blen)!=ESP_OK) return httpd_resp_send_err(req, 400, "body"), ESP_FAIL;
    cJSON* root = cJSON_Parse(body);
    if(!root) return httpd_resp_send_err(req, 400, "json"), ESP_FAIL;

    char pin[16]={0};
    const cJSON* jpin = cJSON_GetObjectItemCaseSensitive(root, "pin");
    if (cJSON_IsString(jpin) && jpin->valuestring) strncpy(pin, jpin->valuestring, sizeof(pin)-1);
    cJSON_Delete(root);

    if(!pin[0]) return httpd_resp_send_err(req, 400, "pin"), ESP_FAIL;
    esp_err_t err = auth_set_pin(user, pin);
    if (err != ESP_OK) return httpd_resp_send_err(req, 400, "pin-invalid"), ESP_FAIL;

    return json_reply(req, "{\"ok\":true}");
}