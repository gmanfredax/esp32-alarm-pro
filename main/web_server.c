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
#include "can_master.h"
#include "can_bus_protocol.h"
#include "system_info.h"
#include "system_time.h"
#include "notification_events.h"
#include "network_manager.h"

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
#include "lwip/inet.h"

extern const uint8_t certs_broker_ca_pem_start[] asm("_binary_broker_ca_pem_start");
extern const uint8_t certs_broker_ca_pem_end[]   asm("_binary_broker_ca_pem_end");

static void web_server_restart_async(void);
static esp_err_t read_body_alloc(httpd_req_t* req, char** out, size_t* out_len, size_t max_len);
static esp_err_t read_body_to_str(httpd_req_t* req, char** out, size_t* out_len);

static const char *TAG = "web";
static const char *TAG_ADMIN __attribute__((unused)) = "admin_html";

static bool parse_can_node_id(const char *uri, uint8_t *out_node);
static bool parse_can_node_outputs_uri(const char *uri, uint8_t *out_node);
static bool parse_can_node_assign_uri(const char *uri, uint8_t *out_node);
static bool parse_can_node_label_uri(const char *uri, uint8_t *out_node);
static bool web_uri_match(const char *reference_uri,
                          const char *uri_to_match,
                          size_t match_upto);

// ─────────────────────────────────────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────────────────────────────────────
#define OTP_DISABLED        1   // 1 = disattiva completamente la richiesta OTP su /api/login
#define WEB_MAX_BODY_LEN     2048
#define ANALOG_E0L_MAX_BODY_LEN (4*1024)
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
    bool enabled;
    char uri[128];
    bool tls_enabled;
    char cid[80];
    char user[80];
    char pass[96];
    uint32_t keepalive;
    char tenant_id[48];
    char site_id[48];
    char device_id[64];
    char base_topic[320];
    char configured_base_topic[320];
    bool discovery_enabled;
    char discovery_prefix[64];
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
static httpd_handle_t s_http_server = NULL;
static bool s_spiffs_mounted __attribute__((unused)) = false;

static void set_http_security_headers(httpd_req_t* req){
    if (!req) return;
    auth_set_security_headers(req);
}

static void build_http_location(httpd_req_t* req, const char* target, char* out, size_t outlen){
    if (!out || !outlen) return;
    const char* dest = target && target[0] ? target : "/";
    if (!strncasecmp(dest, "http://", 7) || !strncasecmp(dest, "https://", 8)){
        strlcpy(out, dest, outlen);
        return;
    }
    char host[96] = {0};
    if (httpd_req_get_hdr_value_str(req, "Host", host, sizeof(host)) == ESP_OK && host[0]){
        if (dest[0] == '/') snprintf(out, outlen, "http://%s%s", host, dest);
        else snprintf(out, outlen, "http://%s/%s", host, dest);
        return;
    }
    if (dest[0] == '/') dest++;
    snprintf(out, outlen, "http://%s", dest);
}

static esp_err_t send_http_redirect(httpd_req_t* req, const char* target, const char* status){
    const char *location = (target && target[0]) ? target : "/";
    set_http_security_headers(req);
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

static bool json_get_int64(const cJSON *json, const char *key, int64_t *out){
    if (!json || !key || !out) {
        return false;
    }
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(json, key);
    if (!item) {
        return false;
    }
    if (cJSON_IsString(item) && item->valuestring) {
        char *end = NULL;
        long long value = strtoll(item->valuestring, &end, 10);
        if (end && *end == '\0') {
            *out = (int64_t)value;
            return true;
        }
    }
    if (cJSON_IsNumber(item)) {
        *out = (int64_t)item->valuedouble;
        return true;
    }
    return false;
}

static esp_err_t json_reply(httpd_req_t* req, const char* json){
    set_http_security_headers(req);
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

static esp_err_t json_mqtt_error_reply(httpd_req_t* req, int status, const char* error, const char* message){
    cJSON* root = cJSON_CreateObject();
    if (!root) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
    cJSON_AddBoolToObject(root, "ok", false);
    cJSON_AddStringToObject(root, "error", error ? error : "error");
    cJSON_AddStringToObject(root, "message", message ? message : "Errore");
    char* payload = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!payload) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
    set_http_security_headers(req);
    httpd_resp_set_status(req, status == HTTPD_500_INTERNAL_SERVER_ERROR ? "500 Internal Server Error" : "400 Bad Request");
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, payload);
    free(payload);
    return err;
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
    if (!s_http_server) {
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
        esp_err_t err = httpd_ws_send_frame_async(s_http_server, client->fd, &frame);
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

static bool parse_can_node_outputs_uri(const char *uri, uint8_t *out_node)
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
    if (strcmp(end, "/outputs") != 0) {
        return false;
    }
    if (out_node) {
        *out_node = (uint8_t)node;
    }
    return true;
}

static bool parse_can_node_assign_uri(const char *uri, uint8_t *out_node)
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
    if (strcmp(end, "/assign") != 0) {
        return false;
    }
    if (out_node) {
        *out_node = (uint8_t)node;
    }
    return true;
}

static bool parse_can_node_label_uri(const char *uri, uint8_t *out_node)
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
    if (strncmp(end, "/label", 6) != 0) {
        return false;
    }
    end += 6;
    if (*end != '\0' && *end != '?') {
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

static bool web_uri_match(const char *reference_uri,
                          const char *uri_to_match,
                          size_t match_upto)
{
    if (!reference_uri || !uri_to_match) {
        return false;
    }

    if (httpd_uri_match_wildcard(reference_uri, uri_to_match, match_upto)) {
        return true;
    }

    int can_match_kind = 0;
    if (strcmp(reference_uri, "/api/can/node/*/assign") == 0) {
        can_match_kind = 1;
    } else if (strcmp(reference_uri, "/api/can/node/*/outputs") == 0) {
        can_match_kind = 2;
    } else if (strcmp(reference_uri, "/api/can/node/*/identify") == 0) {
        can_match_kind = 3;
    } else if (strcmp(reference_uri, "/api/can/node/*/label") == 0) {
        can_match_kind = 4;
    } else {
        return false;
    }

    size_t uri_len = strlen(uri_to_match);
    size_t effective_len = match_upto;
    if (effective_len == 0 || effective_len > uri_len) {
        effective_len = uri_len;
    }

    size_t path_len = strcspn(uri_to_match, "?");
    if (path_len > effective_len) {
        path_len = effective_len;
    }

    char *path = malloc(path_len + 1);
    if (!path) {
        return false;
    }
    memcpy(path, uri_to_match, path_len);
    path[path_len] = '\0';

    bool matched = false;
    switch (can_match_kind) {
        case 1:
            matched = parse_can_node_assign_uri(path, NULL);
            break;
        case 2:
            matched = parse_can_node_outputs_uri(path, NULL);
            break;
        case 3:
            matched = parse_can_node_id(path, NULL);
            break;
        case 4:
            matched = parse_can_node_label_uri(path, NULL);
            break;
        default:
            matched = false;
            break;
    }

    free(path);
    return matched;
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
    roster_node_t snapshot = {0};
    if (hard) {
        bool have_uid = roster_get_node_snapshot(node_id, &snapshot) && snapshot.info_valid;
        if (have_uid) {
            esp_err_t can_err = can_master_assign_address(0, snapshot.uid);
            if (can_err != ESP_OK) {
                httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "can");
                return ESP_FAIL;
            }
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

static esp_err_t api_can_node_outputs_post(httpd_req_t *req)
{
    if (!check_bearer(req)) {
        httpd_resp_send_err(req, 401, "token");
        return ESP_FAIL;
    }
    uint8_t node_id = 0;
    if (!parse_can_node_outputs_uri(req->uri, &node_id) || node_id == 0) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "node");
        return ESP_FAIL;
    }

    roster_io_state_t io_state = {0};
    if (!roster_get_io_state(node_id, &io_state) || !io_state.exists) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "node");
        return ESP_FAIL;
    }
    if (io_state.state != ROSTER_NODE_STATE_OPERATIONAL) {
        httpd_resp_send_err(req, 409, "node_offline");
        return ESP_FAIL;
    }

    cors_apply(req);

    char body[256];
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

    uint32_t desired = 0;
    bool have_desired = false;
    cJSON *jbitmap = cJSON_GetObjectItemCaseSensitive(json, "outputs_bitmap");
    if (cJSON_IsNumber(jbitmap)) {
        double val = jbitmap->valuedouble;
        if (val < 0.0 || val > (double)UINT32_MAX) {
            cJSON_Delete(json);
            httpd_resp_send_err(req, 400, "outputs_bitmap");
            return ESP_FAIL;
        }
        desired = (uint32_t)val;
        have_desired = true;
    }

    if (!have_desired) {
        cJSON *jmask = cJSON_GetObjectItemCaseSensitive(json, "mask");
        cJSON *jvalue = cJSON_GetObjectItemCaseSensitive(json, "value");
        if (cJSON_IsNumber(jmask) && cJSON_IsNumber(jvalue)) {
            if (!io_state.outputs_valid) {
                cJSON_Delete(json);
                httpd_resp_send_err(req, 409, "outputs_unknown");
                return ESP_FAIL;
            }
            double mask_val = jmask->valuedouble;
            double value_val = jvalue->valuedouble;
            if (mask_val < 0.0 || mask_val > (double)UINT32_MAX ||
                value_val < 0.0 || value_val > (double)UINT32_MAX) {
                cJSON_Delete(json);
                httpd_resp_send_err(req, 400, "mask_value");
                return ESP_FAIL;
            }
            uint32_t mask = (uint32_t)mask_val;
            uint32_t value = (uint32_t)value_val;
            desired = (io_state.outputs_bitmap & ~mask) | (value & mask);
            have_desired = true;
        }
    }

    if (!have_desired) {
        cJSON_Delete(json);
        httpd_resp_send_err(req, 400, "outputs_bitmap");
        return ESP_FAIL;
    }

    uint8_t flags = 0;
    cJSON *jflags = cJSON_GetObjectItemCaseSensitive(json, "flags");
    if (cJSON_IsNumber(jflags)) {
        double val = jflags->valuedouble;
        if (val < 0.0 || val > (double)UINT8_MAX) {
            cJSON_Delete(json);
            httpd_resp_send_err(req, 400, "flags");
            return ESP_FAIL;
        }
        flags = (uint8_t)val;
    }

    uint8_t pwm_level = 0;
    cJSON *jpwm = cJSON_GetObjectItemCaseSensitive(json, "pwm_level");
    if (cJSON_IsNumber(jpwm)) {
        double val = jpwm->valuedouble;
        if (val < 0.0 || val > (double)UINT8_MAX) {
            cJSON_Delete(json);
            httpd_resp_send_err(req, 400, "pwm_level");
            return ESP_FAIL;
        }
        pwm_level = (uint8_t)val;
    }

    cJSON_Delete(json);

    esp_err_t err = can_master_set_node_outputs(node_id, desired, flags, pwm_level);
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

    roster_io_state_t updated_state = {0};
    roster_get_io_state(node_id, &updated_state);

    cJSON *resp = cJSON_CreateObject();
    if (!resp) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json");
        return ESP_FAIL;
    }

    cJSON_AddNumberToObject(resp, "node_id", node_id);
    cJSON_AddBoolToObject(resp, "outputs_known", updated_state.outputs_valid);
    cJSON_AddNumberToObject(resp,
                            "outputs_bitmap",
                            (double)(updated_state.outputs_valid ?
                                     updated_state.outputs_bitmap : desired));
    cJSON_AddNumberToObject(resp,
                            "outputs_flags",
                            (double)(updated_state.outputs_valid ?
                                     updated_state.outputs_flags : flags));
    cJSON_AddNumberToObject(resp,
                            "pwm_level",
                            (double)(updated_state.outputs_valid ?
                                     updated_state.outputs_pwm : pwm_level));
    cJSON_AddBoolToObject(resp, "inputs_known", updated_state.inputs_valid);
    if (updated_state.inputs_valid) {
        cJSON_AddNumberToObject(resp, "inputs_bitmap", (double)updated_state.inputs_bitmap);
        cJSON_AddNumberToObject(resp, "change_counter", updated_state.change_counter);
        cJSON_AddNumberToObject(resp, "node_state_flags", updated_state.node_state_flags);
    }

    return json_reply_cjson(req, resp);
}

static esp_err_t api_can_node_outputs_options(httpd_req_t *req)
{
    return cors_handle_options(req);
}

static esp_err_t api_can_node_assign_post(httpd_req_t *req)
{
    if (!check_bearer(req) || !is_admin_user(req)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden");
        return ESP_FAIL;
    }

    uint8_t current_id = 0;
    if (!parse_can_node_assign_uri(req->uri, &current_id) || current_id == 0) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "node");
        return ESP_FAIL;
    }

    cors_apply(req);

    char body[128];
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

    int new_id = -1;
    cJSON *jnew = cJSON_GetObjectItemCaseSensitive(json, "new_id");
    if (cJSON_IsNumber(jnew)) {
        new_id = (int)jnew->valuedouble;
    } else if (cJSON_IsString(jnew) && jnew->valuestring) {
        char *end = NULL;
        long parsed = strtol(jnew->valuestring, &end, 10);
        if (end && *end == '\0') {
            new_id = (int)parsed;
        }
    }

    if (new_id < 1 || new_id > CAN_MAX_NODE_ID) {
        cJSON_Delete(json);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "new_id");
        return ESP_FAIL;
    }

    roster_node_t snapshot = {0};
    if (!roster_get_node_snapshot(current_id, &snapshot) || !snapshot.used) {
        cJSON_Delete(json);
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "node");
        return ESP_FAIL;
    }
    if (!snapshot.info_valid) {
        cJSON_Delete(json);
        httpd_resp_send_err(req, 409, "uid");
        return ESP_FAIL;
    }

    if (new_id != current_id) {
        roster_node_t target_snapshot = {0};
        if (roster_get_node_snapshot((uint8_t)new_id, &target_snapshot) && target_snapshot.used) {
            cJSON_Delete(json);
            httpd_resp_send_err(req, 409, "busy");
            return ESP_FAIL;
        }
    }

    esp_err_t assign_err = can_master_assign_address((uint8_t)new_id, snapshot.uid);
    cJSON_Delete(json);
    if (assign_err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "can");
        return ESP_FAIL;
    }

    if (new_id != current_id) {
        esp_err_t move_err = roster_reassign_node_id(current_id, (uint8_t)new_id);
        if (move_err != ESP_OK) {
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "roster");
            return ESP_FAIL;
        }
    }

    cJSON *resp = roster_node_to_json((uint8_t)new_id);
    if (!resp) {
        resp = cJSON_CreateObject();
        if (resp) {
            cJSON_AddNumberToObject(resp, "node_id", new_id);
        } else {
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json");
            return ESP_FAIL;
        }
    }
    return json_reply_cjson(req, resp);
}

static esp_err_t api_can_node_assign_options(httpd_req_t *req)
{
    return cors_handle_options(req);
}

static esp_err_t api_can_node_label_post(httpd_req_t *req)
{
    if (!check_bearer(req) || !is_admin_user(req)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden");
        return ESP_FAIL;
    }

    uint8_t node_id = 0;
    if (!parse_can_node_label_uri(req->uri, &node_id) || node_id == 0) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "node");
        return ESP_FAIL;
    }

    cors_apply(req);

    char body[128];
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

    bool has_label = false;
    const char *label_value = NULL;
    cJSON *jlabel = cJSON_GetObjectItemCaseSensitive(json, "label");
    if (cJSON_IsString(jlabel)) {
        has_label = true;
        label_value = jlabel->valuestring ? jlabel->valuestring : "";
    } else if (cJSON_IsNull(jlabel)) {
        has_label = true;
        label_value = NULL;
    }

    if (!has_label) {
        cJSON_Delete(json);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "label");
        return ESP_FAIL;
    }

    esp_err_t err = roster_set_node_label(node_id, label_value);
    cJSON_Delete(json);
    if (err == ESP_ERR_NOT_FOUND) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "node");
        return ESP_FAIL;
    }
    if (err == ESP_ERR_INVALID_ARG) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "label");
        return ESP_FAIL;
    }
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "roster");
        return ESP_FAIL;
    }

    cJSON *resp = roster_node_to_json(node_id);
    if (!resp) {
        resp = cJSON_CreateObject();
        if (resp) {
            cJSON_AddNumberToObject(resp, "node_id", node_id);
        } else {
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json");
            return ESP_FAIL;
        }
    }
    return json_reply_cjson(req, resp);
}

static esp_err_t api_can_node_label_options(httpd_req_t *req)
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

// ----- Utilizzo certificati REALI ----------------------------------
static void web_tls_use_builtin(void){
    web_tls_clear_dynamic();

    s_tls_material.cert = (const uint8_t*)builtin_cert_pem;
    s_tls_material.cert_len = sizeof(builtin_cert_pem);
    s_tls_material.key = (const uint8_t*)builtin_key_pem;
    s_tls_material.key_len = sizeof(builtin_key_pem);
    s_tls_material.source = WEB_TLS_SRC_BUILTIN;

    s_web_tls_state.active_source = WEB_TLS_SRC_BUILTIN;
    s_web_tls_state.using_builtin = true;
    s_web_tls_state.active_subject[0] = '\0';
    s_web_tls_state.active_issuer[0] = '\0';
    s_web_tls_state.active_not_before[0] = '\0';
    s_web_tls_state.active_not_after[0] = '\0';
    s_web_tls_state.active_fingerprint[0] = '\0';
    if (!s_web_tls_state.custom_available) {
        web_tls_state_reset_custom();
    }
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

static esp_err_t read_body_to_str(httpd_req_t* req, char** out, size_t* out_len)
{
    return read_body_alloc(req, out, out_len, ANALOG_E0L_MAX_BODY_LEN);
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

static bool mqtt_string_field_is_valid(const char* s, size_t max_len, bool allow_empty){
    if (!s) return allow_empty;
    size_t len = strlen(s);
    if (len == 0) return allow_empty;
    if (len >= max_len) return false;
    for (size_t i = 0; i < len; ++i){
        unsigned char ch = (unsigned char)s[i];
        if (ch < 0x21 || ch == 0x7f) return false;
        if (!(isalnum(ch) || ch == '_' || ch == '-' || ch == '.' || ch == '/' || ch == ':')) return false;
    }
    return true;
}

static bool mqtt_topic_field_is_valid(const char* s, size_t max_len, bool allow_empty){
    if (!s) return allow_empty;
    size_t len = strlen(s);
    if (len == 0) return allow_empty;
    if (len >= max_len || s[0] == '/' || s[len - 1] == '/') return false;
    for (size_t i = 0; i < len; ++i){
        unsigned char ch = (unsigned char)s[i];
        if (ch < 0x21 || ch == 0x7f || ch == '+' || ch == '#') return false;
    }
    return true;
}

static esp_err_t mqtt_normalize_and_validate_uri(const char* input, bool tls_enabled, char* out, size_t out_len, const char** error, const char** message){
    if (error) *error = "invalid_broker_uri";
    if (message) *message = "URI broker non valido";
    if (!input || !out || out_len == 0) return ESP_ERR_INVALID_ARG;
    char uri[128] = {0};
    strlcpy(uri, input, sizeof(uri));
    trim_inplace(uri);
    if (!uri[0]){
        if (message) *message = "URI broker obbligatorio";
        return ESP_ERR_INVALID_ARG;
    }
    bool has_mqtt = strncasecmp(uri, "mqtt://", 7) == 0;
    bool has_mqtts = strncasecmp(uri, "mqtts://", 8) == 0;
    if (has_mqtts && !tls_enabled){
        if (message) *message = "TLS disabilitato: usa mqtt:// oppure abilita TLS";
        return ESP_ERR_INVALID_ARG;
    }
    if (has_mqtt && tls_enabled){
        if (message) *message = "TLS abilitato: usa mqtts:// oppure disabilita TLS";
        return ESP_ERR_INVALID_ARG;
    }
    if (!has_mqtt && !has_mqtts){
        snprintf(out, out_len, "%s%s", tls_enabled ? "mqtts://" : "mqtt://", uri);
    } else {
        strlcpy(out, uri, out_len);
    }
    const char* host = out + (strncasecmp(out, "mqtts://", 8) == 0 ? 8 : 7);
    if (!host[0] || strchr(host, '/') || strchr(host, ' ') || strchr(host, '\t')){
        if (message) *message = "URI broker non valido: usa mqtt://host:1883 o mqtts://host:8883";
        return ESP_ERR_INVALID_ARG;
    }
    const char* colon = strrchr(host, ':');
    if (!colon || colon == host || !colon[1]){
        size_t used = strlen(out);
        snprintf(out + used, out_len > used ? out_len - used : 0, ":%u", tls_enabled ? 8883U : 1883U);
    } else {
        char* end = NULL;
        long port = strtol(colon + 1, &end, 10);
        if (!end || *end != '\0' || port <= 0 || port > 65535){
            if (message) *message = "Porta broker MQTT non valida";
            return ESP_ERR_INVALID_ARG;
        }
        if ((tls_enabled && port == 1883) || (!tls_enabled && port == 8883)){
            snprintf((char*)colon + 1, out_len - (size_t)((colon + 1) - out), "%u", tls_enabled ? 8883U : 1883U);
        }
    }
    return ESP_OK;
}

static void mqtt_config_add_json(cJSON* root, const provisioning_mqtt_config_t* cfg){
    if (!root || !cfg) return;
    cJSON_AddBoolToObject(root, "mqtt_enabled", cfg->enabled);
    cJSON_AddBoolToObject(root, "enabled", cfg->enabled);
    cJSON_AddBoolToObject(root, "ha_discovery_enabled", cfg->discovery_enabled);
    cJSON_AddBoolToObject(root, "discovery_enabled", cfg->discovery_enabled);
    cJSON_AddBoolToObject(root, "tls_enabled", cfg->tls_enabled);
    cJSON_AddStringToObject(root, "broker_uri", cfg->uri);
    cJSON_AddStringToObject(root, "uri", cfg->uri);
    cJSON_AddStringToObject(root, "client_id", cfg->cid);
    cJSON_AddStringToObject(root, "cid", cfg->cid);
    cJSON_AddStringToObject(root, "username", cfg->user);
    cJSON_AddStringToObject(root, "user", cfg->user);
    cJSON_AddBoolToObject(root, "has_pass", cfg->pass[0] != '\0');
    cJSON_AddNumberToObject(root, "keepalive", cfg->keepalive);
    cJSON_AddStringToObject(root, "tenant_id", cfg->tenant_id);
    cJSON_AddStringToObject(root, "site_id", cfg->site_id);
    cJSON_AddStringToObject(root, "device_id", cfg->device_id);
    cJSON_AddStringToObject(root, "base_topic", cfg->base_topic);
    cJSON_AddStringToObject(root, "configured_base_topic", cfg->configured_base_topic);
    cJSON_AddStringToObject(root, "discovery_prefix", cfg->discovery_prefix);
}

static esp_netif_t* provisioning_get_primary_netif(void)
{
    network_status_t st;
    if (network_get_status(&st) == ESP_OK && st.active_if == NETWORK_IF_WIFI) {
        esp_netif_t *wifi = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        if (wifi) return wifi;
    }
    esp_netif_t* netif = eth_get_netif();
    if (netif) return netif;
    netif = esp_netif_get_handle_from_ifkey("ETH_DEF");
    if (netif) return netif;
    netif = esp_netif_get_handle_from_ifkey("ETH");
    if (netif) return netif;
    return esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
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
    cfg->enabled = false;
    cfg->discovery_enabled = false;
    cfg->tls_enabled = false;
    strlcpy(cfg->uri, "", sizeof(cfg->uri));
    strlcpy(cfg->tenant_id, "default", sizeof(cfg->tenant_id));
    strlcpy(cfg->site_id, "default", sizeof(cfg->site_id));
    strlcpy(cfg->discovery_prefix, "homeassistant", sizeof(cfg->discovery_prefix));
    cfg->keepalive = CONFIG_APP_CLOUD_KEEPALIVE;
    char device_id[DEVICE_ID_MAX] = {0};
    make_device_id(device_id);
    strlcpy(cfg->device_id, device_id, sizeof(cfg->device_id));
    strlcpy(cfg->cid, device_id, sizeof(cfg->cid));
    strlcpy(cfg->user, device_id, sizeof(cfg->user));
    nvs_handle_t nvs;
    if (nvs_open("sys", NVS_READONLY, &nvs) == ESP_OK){
        uint8_t b = 0;
        if (nvs_get_u8(nvs, "mq_enabled", &b) == ESP_OK) cfg->enabled = b != 0;
        if (nvs_get_u8(nvs, "mq_tls", &b) == ESP_OK) cfg->tls_enabled = b != 0;
        if (nvs_get_u8(nvs, "mq_disc", &b) == ESP_OK) cfg->discovery_enabled = b != 0;
        nvs_get_str_def(nvs, "mq_uri",  cfg->uri,  sizeof(cfg->uri),  "");
        nvs_get_str_def(nvs, "mq_cid",  cfg->cid,  sizeof(cfg->cid), cfg->cid);
        nvs_get_str_def(nvs, "mq_user", cfg->user, sizeof(cfg->user), cfg->user);
        nvs_get_str_def(nvs, "mq_pass", cfg->pass, sizeof(cfg->pass), "");
        nvs_get_str_def(nvs, "mq_tenant", cfg->tenant_id, sizeof(cfg->tenant_id), cfg->tenant_id);
        nvs_get_str_def(nvs, "mq_site", cfg->site_id, sizeof(cfg->site_id), cfg->site_id);
        nvs_get_str_def(nvs, "mq_device", cfg->device_id, sizeof(cfg->device_id), cfg->device_id);
        nvs_get_str_def(nvs, "mq_base", cfg->configured_base_topic, sizeof(cfg->configured_base_topic), "");
        nvs_get_str_def(nvs, "mq_disc_pref", cfg->discovery_prefix, sizeof(cfg->discovery_prefix), cfg->discovery_prefix);
        cfg->keepalive = nvs_get_u32_def(nvs, "mq_keep", CONFIG_APP_CLOUD_KEEPALIVE);
        nvs_close(nvs);
    }
    if (mqtt_build_effective_base_topic(cfg->configured_base_topic, cfg->tenant_id, cfg->site_id, cfg->device_id, cfg->base_topic, sizeof(cfg->base_topic)) != ESP_OK) {
        snprintf(cfg->base_topic, sizeof(cfg->base_topic), "tenants/%s/sites/%s/devices/%s", cfg->tenant_id, cfg->site_id, cfg->device_id);
    }
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
    if (!(auth_check_bearer(req,&u) || auth_check_cookie(req,&u)) || u.role != ROLE_ADMIN || auth_session_is_setup_limited(req)){
        ESP_LOGW(TAG, "route denied uri=%s requires=admin", req->uri ? req->uri : "");
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden");
    }
    return ESP_OK;
}

static esp_err_t setup_or_admin(httpd_req_t* req){
    if (!s_provisioned) return ESP_OK;
    user_info_t u;
    if (!(auth_check_bearer(req,&u) || auth_check_cookie(req,&u))) {
        ESP_LOGW(TAG, "route denied uri=%s reason=no-auth-or-not-allowlisted", req->uri ? req->uri : "");
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden");
    }
    if (u.role == ROLE_ADMIN || auth_session_is_setup_limited(req)) {
        if (auth_session_is_setup_limited(req)) ESP_LOGI(TAG, "route allowed for setup_limited uri=%s", req->uri ? req->uri : "");
        return ESP_OK;
    }
    ESP_LOGW(TAG, "route denied uri=%s requires=setup-or-admin role=%d", req->uri ? req->uri : "", (int)u.role);
    return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden");
}

static esp_err_t api_admin_system_get(httpd_req_t* req){
    if (setup_or_admin(req)!=ESP_OK) return ESP_FAIL;
    cJSON *root = cJSON_CreateObject();
    if (!root) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
    system_info_append_json(root);
    cJSON *mqtt = cJSON_AddObjectToObject(root, "mqtt");
    cJSON_AddBoolToObject(mqtt, "connected", mqtt_is_connected());
    return json_reply_cjson(req, root);
}

static esp_err_t api_admin_mqtt_rediscover_post(httpd_req_t* req){
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    provisioning_mqtt_config_t cfg; provisioning_load_mqtt(&cfg);
    if (!cfg.enabled){
        return json_mqtt_error_reply(req, HTTPD_400_BAD_REQUEST, "mqtt_disabled", "MQTT non è abilitato"), ESP_FAIL;
    }
    if (!cfg.discovery_enabled){
        return json_mqtt_error_reply(req, HTTPD_400_BAD_REQUEST, "discovery_disabled", "Discovery Home Assistant non è abilitata"), ESP_FAIL;
    }
    if (!mqtt_is_connected()){
        return json_mqtt_error_reply(req, HTTPD_400_BAD_REQUEST, "mqtt_not_connected", "MQTT non connesso: impossibile ripubblicare discovery"), ESP_FAIL;
    }
    esp_err_t err = mqtt_publish_discovery();
    if (err != ESP_OK) return json_mqtt_error_reply(req, HTTPD_500_INTERNAL_SERVER_ERROR, "mqtt_publish_failed", "Ripubblicazione discovery fallita"), ESP_FAIL;
    return json_reply(req, "{\"ok\":true,\"message\":\"Discovery ripubblicata\"}");
}

static esp_err_t api_admin_notifications_get(httpd_req_t* req){
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    cJSON *root = cJSON_CreateObject();
    if (!root) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
    notification_events_append_config_json(root);
    return json_reply_cjson(req, root);
}

static esp_err_t api_admin_notifications_post(httpd_req_t* req){
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    char body[512]; size_t bl=0;
    if (read_body_to_buf(req, body, sizeof(body), &bl)!=ESP_OK) return httpd_resp_send_err(req,400,"body"), ESP_FAIL;
    cJSON* j = cJSON_ParseWithLength(body, bl);
    if (!j) return httpd_resp_send_err(req,400,"json"), ESP_FAIL;
    esp_err_t err = notification_events_update_config_from_json(j);
    cJSON_Delete(j);
    if (err != ESP_OK) return httpd_resp_send_err(req,500,"nvs"), ESP_FAIL;
    return json_reply(req, "{\"ok\":true}");
}

static esp_err_t api_admin_notifications_test_post(httpd_req_t* req){
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    notification_events_emit_simple("test_notification", NOTIFY_SEVERITY_INFO, "web", -1, "Test notifica", "Evento di test generato dalla UI admin", false);
    return json_reply(req, "{\"ok\":true}");
}


static esp_err_t network_json_error(httpd_req_t *req, int status, const char *error, const char *message)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
    cJSON_AddBoolToObject(root, "ok", false);
    cJSON_AddStringToObject(root, "error", error ? error : "network_error");
    cJSON_AddStringToObject(root, "message", message ? message : "Errore configurazione rete");
    httpd_resp_set_status(req, status == HTTPD_400_BAD_REQUEST ? "400 Bad Request" : "500 Internal Server Error");
    return json_reply_cjson(req, root);
}

static esp_err_t api_admin_network_get(httpd_req_t* req)
{
    if (setup_or_admin(req)!=ESP_OK) return ESP_FAIL;
    cJSON *root = cJSON_CreateObject();
    if (!root) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
    network_status_append_json(root);
    return json_reply_cjson(req, root);
}

static esp_err_t api_network_status_get(httpd_req_t* req)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
    network_status_append_json(root);
    return json_reply_cjson(req, root);
}

static esp_err_t api_admin_network_restart_post(httpd_req_t* req)
{
    if (setup_or_admin(req)!=ESP_OK) return ESP_FAIL;
    esp_err_t err = network_manager_restart();
    if (err != ESP_OK) return network_json_error(req, HTTPD_500_INTERNAL_SERVER_ERROR, "restart_failed", "Riavvio rete fallito");
    return json_reply(req, "{\"ok\":true,\"message\":\"Riavvio rete avviato\"}");
}

static esp_err_t api_admin_network_wifi_scan_get(httpd_req_t* req)
{
    if (setup_or_admin(req)!=ESP_OK) return ESP_FAIL;
    cJSON *root = cJSON_CreateObject();
    if (!root) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
    cJSON *arr = cJSON_AddArrayToObject(root, "networks");
    if (!arr) { cJSON_Delete(root); return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL; }
    esp_err_t err = network_wifi_scan_append_json(arr);
    if (err != ESP_OK) {
        cJSON_Delete(root);
        return network_json_error(req, HTTPD_500_INTERNAL_SERVER_ERROR, "wifi_scan_failed", "Scansione reti Wi-Fi fallita");
    }
    return json_reply_cjson(req, root);
}

static esp_err_t api_admin_network_setup_exit_post(httpd_req_t* req)
{
    if (setup_or_admin(req)!=ESP_OK) return ESP_FAIL;
    esp_err_t err = network_setup_exit();
    if (err != ESP_OK) {
        return network_json_error(req, HTTPD_400_BAD_REQUEST, "setup_exit_failed", "Impossibile uscire dal setup senza una rete operativa");
    }
    return json_reply(req, "{\"ok\":true,\"message\":\"Modalità setup disattivata\"}");
}

static esp_err_t api_admin_network_wifi_test_post(httpd_req_t* req)
{
    if (setup_or_admin(req)!=ESP_OK) return ESP_FAIL;
    char body[512]; size_t bl=0;
    if (read_body_to_buf(req, body, sizeof(body), &bl)!=ESP_OK) return httpd_resp_send_err(req,400,"body"), ESP_FAIL;
    cJSON* j = cJSON_ParseWithLength(body, bl);
    if (!j) return httpd_resp_send_err(req,400,"json"), ESP_FAIL;
    const cJSON *jssid = cJSON_GetObjectItemCaseSensitive(j, "ssid");
    const cJSON *jpass = cJSON_GetObjectItemCaseSensitive(j, "password");
    const char *ssid = (cJSON_IsString(jssid) && jssid->valuestring) ? jssid->valuestring : "";
    const char *pass = (cJSON_IsString(jpass) && jpass->valuestring) ? jpass->valuestring : "";
    if (!ssid[0]) { cJSON_Delete(j); return network_json_error(req, HTTPD_400_BAD_REQUEST, "missing_wifi_ssid", "SSID Wi-Fi obbligatorio per il test"); }
    if (strlen(ssid) > NETWORK_WIFI_SSID_MAX) { cJSON_Delete(j); return network_json_error(req, HTTPD_400_BAD_REQUEST, "wifi_ssid_too_long", "SSID Wi-Fi massimo 32 caratteri"); }
    network_config_t saved; network_config_load(&saved);
    bool use_saved = !pass[0];
    if (use_saved && (!saved.wifi_password_set || strcmp(saved.wifi_ssid, ssid))) {
        cJSON_Delete(j);
        return network_json_error(req, HTTPD_400_BAD_REQUEST, "missing_wifi_password", "Password Wi-Fi obbligatoria per testare nuove credenziali");
    }
    if (pass[0] && strlen(pass) > NETWORK_WIFI_PASSWORD_MAX) { cJSON_Delete(j); return network_json_error(req, HTTPD_400_BAD_REQUEST, "wifi_password_too_long", "Password Wi-Fi massimo 64 caratteri"); }
    esp_err_t err = network_wifi_test(ssid, pass, use_saved, 15000);
    cJSON_Delete(j);
    if (err != ESP_OK) return network_json_error(req, HTTPD_400_BAD_REQUEST, "wifi_test_failed", "Connessione Wi-Fi fallita o IP non ottenuto");
    return json_reply(req, "{\"ok\":true,\"message\":\"Test Wi-Fi riuscito\"}");
}

static esp_err_t api_admin_network_post(httpd_req_t* req)
{
    if (setup_or_admin(req)!=ESP_OK) return ESP_FAIL;
    char body[1024]; size_t bl=0;
    if (read_body_to_buf(req, body, sizeof(body), &bl)!=ESP_OK) return httpd_resp_send_err(req,400,"body"), ESP_FAIL;
    cJSON* j = cJSON_ParseWithLength(body, bl);
    if (!j) return httpd_resp_send_err(req,400,"json"), ESP_FAIL;

    network_config_t cfg; network_config_load(&cfg);
    const cJSON *jmode = cJSON_GetObjectItemCaseSensitive(j, "network_mode");
    const cJSON *jhost = cJSON_GetObjectItemCaseSensitive(j, "hostname");
    const cJSON *jwifi = cJSON_GetObjectItemCaseSensitive(j, "wifi");
    const cJSON *jsetup = cJSON_GetObjectItemCaseSensitive(j, "setup_ap");
    const cJSON *jssid = jwifi ? cJSON_GetObjectItemCaseSensitive(jwifi, "ssid") : cJSON_GetObjectItemCaseSensitive(j, "wifi_ssid");
    const cJSON *jpass = jwifi ? cJSON_GetObjectItemCaseSensitive(jwifi, "password") : cJSON_GetObjectItemCaseSensitive(j, "wifi_password");
    const cJSON *jclear = jwifi ? cJSON_GetObjectItemCaseSensitive(jwifi, "clear_password") : cJSON_GetObjectItemCaseSensitive(j, "wifi_clear_password");
    const cJSON *jap_enabled = jsetup ? cJSON_GetObjectItemCaseSensitive(jsetup, "enabled") : cJSON_GetObjectItemCaseSensitive(j, "fallback_ap_enabled");
    const cJSON *jap_pass = jsetup ? cJSON_GetObjectItemCaseSensitive(jsetup, "password") : cJSON_GetObjectItemCaseSensitive(j, "fallback_ap_password");

    if (cJSON_IsString(jmode)) {
        network_mode_t mode;
        if (!network_mode_from_str(jmode->valuestring, &mode)) { cJSON_Delete(j); return network_json_error(req, HTTPD_400_BAD_REQUEST, "invalid_network_mode", "Modalità rete non valida"); }
        cfg.mode = mode;
    }
    if (cJSON_IsString(jhost) && jhost->valuestring) {
        if (strlen(jhost->valuestring) > NETWORK_HOSTNAME_MAX) { cJSON_Delete(j); return network_json_error(req, HTTPD_400_BAD_REQUEST, "hostname_too_long", "Hostname massimo 63 caratteri"); }
        strlcpy(cfg.hostname, jhost->valuestring, sizeof(cfg.hostname));
    }
    if (cJSON_IsString(jssid) && jssid->valuestring) {
        if (strlen(jssid->valuestring) > NETWORK_WIFI_SSID_MAX) { cJSON_Delete(j); return network_json_error(req, HTTPD_400_BAD_REQUEST, "wifi_ssid_too_long", "SSID Wi-Fi massimo 32 caratteri"); }
        strlcpy(cfg.wifi_ssid, jssid->valuestring, sizeof(cfg.wifi_ssid));
    }
    if (cJSON_IsTrue(jclear)) {
        cfg.wifi_password[0] = '\0';
        cfg.wifi_password_set = false;
    } else if (cJSON_IsString(jpass) && jpass->valuestring && jpass->valuestring[0]) {
        if (strlen(jpass->valuestring) > NETWORK_WIFI_PASSWORD_MAX) { cJSON_Delete(j); return network_json_error(req, HTTPD_400_BAD_REQUEST, "wifi_password_too_long", "Password Wi-Fi massimo 64 caratteri"); }
        strlcpy(cfg.wifi_password, jpass->valuestring, sizeof(cfg.wifi_password));
        cfg.wifi_password_set = true;
    }
    if (cJSON_IsBool(jap_enabled)) cfg.fallback_ap_enabled = cJSON_IsTrue(jap_enabled);
    if (cJSON_IsString(jap_pass) && jap_pass->valuestring && jap_pass->valuestring[0]) {
        if (strlen(jap_pass->valuestring) > NETWORK_WIFI_PASSWORD_MAX || strlen(jap_pass->valuestring) < 8) { cJSON_Delete(j); return network_json_error(req, HTTPD_400_BAD_REQUEST, "setup_ap_password_invalid", "Password AP setup da 8 a 64 caratteri"); }
        strlcpy(cfg.fallback_ap_password, jap_pass->valuestring, sizeof(cfg.fallback_ap_password));
        cfg.fallback_ap_password_set = true;
    }
    if (network_mode_requires_wifi(cfg.mode)) {
        if (!cfg.wifi_ssid[0]) { cJSON_Delete(j); return network_json_error(req, HTTPD_400_BAD_REQUEST, "missing_wifi_ssid", "SSID Wi-Fi obbligatorio per la modalità selezionata"); }
        if (!cfg.wifi_password_set) { cJSON_Delete(j); return network_json_error(req, HTTPD_400_BAD_REQUEST, "missing_wifi_password", "Password Wi-Fi obbligatoria; reti aperte non abilitate"); }
    }
    if (cfg.mode == NETWORK_MODE_WIFI_ONLY && !network_wifi_test_recent_ok(cfg.wifi_ssid, cfg.wifi_password)) {
        cJSON_Delete(j);
        return network_json_error(req, HTTPD_400_BAD_REQUEST, "wifi_test_required", "Per passare a Solo Wi-Fi eseguire prima un Test Wi-Fi riuscito");
    }
    esp_err_t err = network_config_save(&cfg);
    cJSON_Delete(j);
    if (err != ESP_OK) return network_json_error(req, HTTPD_500_INTERNAL_SERVER_ERROR, "save_failed", "Salvataggio configurazione rete fallito");
    network_manager_restart();
    return json_reply(req, "{\"ok\":true,\"message\":\"Configurazione rete salvata\"}");
}

// ---- /api/sys/net GET/POST ----

static esp_err_t api_setup_time_post(httpd_req_t* req)
{
    if (setup_or_admin(req)!=ESP_OK) return ESP_FAIL;
    char body[256]; size_t bl=0;
    if (read_body_to_buf(req, body, sizeof(body), &bl)!=ESP_OK) return httpd_resp_send_err(req,400,"body"), ESP_FAIL;
    cJSON* j = cJSON_ParseWithLength(body, bl);
    if (!j) return httpd_resp_send_err(req,400,"json"), ESP_FAIL;
    const cJSON *jt = cJSON_GetObjectItemCaseSensitive(j, "unix_time");
    const cJSON *jtz = cJSON_GetObjectItemCaseSensitive(j, "timezone");
    int64_t unix_time = cJSON_IsNumber(jt) ? (int64_t)jt->valuedouble : 0;
    const char *tz = (cJSON_IsString(jtz) && jtz->valuestring) ? jtz->valuestring : "browser";
    esp_err_t err = system_time_set_browser_manual(unix_time, tz);
    cJSON_Delete(j);
    if (err != ESP_OK) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "time"), ESP_FAIL;
    audit_append("time", "", 1, "browser_manual");
    return json_reply(req, "{\"ok\":true,\"time_valid\":true,\"source\":\"browser_manual\",\"message\":\"Ora sincronizzata da browser. Effettua OTP per accesso admin completo.\"}");
}

static esp_err_t api_recovery_status_get(httpd_req_t* req)
{
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    char uname[32]={0}; if(!current_user_from_req(req, uname, sizeof(uname))) return httpd_resp_send_err(req, 401, "token"), ESP_FAIL;
    char resp[96];
    snprintf(resp, sizeof(resp), "{\"ok\":true,\"remaining\":%u}", (unsigned)auth_recovery_remaining(uname));
    return json_reply(req, resp);
}

static esp_err_t api_recovery_generate_post(httpd_req_t* req)
{
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    char uname[32]={0}; if(!current_user_from_req(req, uname, sizeof(uname))) return httpd_resp_send_err(req, 401, "token"), ESP_FAIL;
    char codes[AUTH_RECOVERY_CODE_COUNT][AUTH_RECOVERY_CODE_LEN];
    if (auth_recovery_generate(uname, codes) != ESP_OK) return httpd_resp_send_err(req, 500, "recovery"), ESP_FAIL;
    audit_append("recovery", uname, 1, "generated");
    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "ok", true);
    cJSON *arr = cJSON_AddArrayToObject(root, "codes");
    for (int i=0; i<AUTH_RECOVERY_CODE_COUNT; ++i) cJSON_AddItemToArray(arr, cJSON_CreateString(codes[i]));
    cJSON_AddNumberToObject(root, "remaining", AUTH_RECOVERY_CODE_COUNT);
    cJSON_AddStringToObject(root, "message", "Salva questi codici. Saranno mostrati una sola volta.");
    return json_reply_cjson(req, root);
}

static esp_err_t api_recovery_revoke_post(httpd_req_t* req)
{
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    char uname[32]={0}; if(!current_user_from_req(req, uname, sizeof(uname))) return httpd_resp_send_err(req, 401, "token"), ESP_FAIL;
    if (auth_recovery_revoke(uname) != ESP_OK) return httpd_resp_send_err(req, 500, "recovery"), ESP_FAIL;
    audit_append("recovery", uname, 1, "revoked");
    return json_reply(req, "{\"ok\":true,\"remaining\":0}");
}

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
    char body[1024]; size_t bl=0;
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
static const cJSON* mqtt_json_get_alias(const cJSON* root, const char* a, const char* b){
    const cJSON* v = cJSON_GetObjectItemCaseSensitive(root, a);
    if (!v && b) v = cJSON_GetObjectItemCaseSensitive(root, b);
    return v;
}

static esp_err_t sys_mqtt_get(httpd_req_t* req){
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    provisioning_mqtt_config_t cfg; provisioning_load_mqtt(&cfg);
    cJSON* root = cJSON_CreateObject();
    if (!root) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
    mqtt_config_add_json(root, &cfg);
    cJSON_AddStringToObject(root, "default_uri", "");
    cJSON_AddNumberToObject(root, "default_keepalive", CONFIG_APP_CLOUD_KEEPALIVE);
    cJSON_AddBoolToObject(root, "connected", mqtt_is_connected());
    cJSON_AddStringToObject(root, "connection_status", mqtt_is_connected() ? "connected" : "disconnected");
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
    char body[1536]; size_t bl=0;
    if (read_body_to_buf(req, body, sizeof(body), &bl)!=ESP_OK) return json_mqtt_error_reply(req, HTTPD_400_BAD_REQUEST, "invalid_body", "Body richiesta non valido"), ESP_FAIL;
    cJSON* j = cJSON_ParseWithLength(body, bl);
    if (!j) return json_mqtt_error_reply(req, HTTPD_400_BAD_REQUEST, "invalid_json", "JSON non valido"), ESP_FAIL;

    provisioning_mqtt_config_t cfg; provisioning_load_mqtt(&cfg);
    const cJSON* jen = mqtt_json_get_alias(j, "mqtt_enabled", "enabled");
    const cJSON* juri = mqtt_json_get_alias(j, "broker_uri", "uri");
    const cJSON* jtls = cJSON_GetObjectItemCaseSensitive(j,"tls_enabled");
    const cJSON* jcid = mqtt_json_get_alias(j, "client_id", "cid");
    const cJSON* juser = mqtt_json_get_alias(j, "username", "user");
    const cJSON* jpw = mqtt_json_get_alias(j, "password", "pass");
    const cJSON* jclear = cJSON_GetObjectItemCaseSensitive(j, "clear_password");
    const cJSON* jka = cJSON_GetObjectItemCaseSensitive(j,"keepalive");
    const cJSON* jtenant = cJSON_GetObjectItemCaseSensitive(j,"tenant_id");
    const cJSON* jsite = cJSON_GetObjectItemCaseSensitive(j,"site_id");
    const cJSON* jdev = cJSON_GetObjectItemCaseSensitive(j,"device_id");
    const cJSON* jbase = cJSON_GetObjectItemCaseSensitive(j,"base_topic");
    const cJSON* jdisc = mqtt_json_get_alias(j, "ha_discovery_enabled", "discovery_enabled");
    const cJSON* jdp = cJSON_GetObjectItemCaseSensitive(j,"discovery_prefix");

    if (jen && !cJSON_IsBool(jen)){ cJSON_Delete(j); return json_mqtt_error_reply(req, HTTPD_400_BAD_REQUEST, "invalid_mqtt_enabled", "mqtt_enabled deve essere booleano"), ESP_FAIL; }
    if (jdisc && !cJSON_IsBool(jdisc)){ cJSON_Delete(j); return json_mqtt_error_reply(req, HTTPD_400_BAD_REQUEST, "invalid_discovery_enabled", "ha_discovery_enabled deve essere booleano"), ESP_FAIL; }
    if (jtls && !cJSON_IsBool(jtls)){ cJSON_Delete(j); return json_mqtt_error_reply(req, HTTPD_400_BAD_REQUEST, "invalid_tls_enabled", "tls_enabled deve essere booleano"), ESP_FAIL; }
    if (jen) cfg.enabled = cJSON_IsTrue(jen);
    if (jdisc) cfg.discovery_enabled = cJSON_IsTrue(jdisc);
    if (jtls) cfg.tls_enabled = cJSON_IsTrue(jtls);
    else if (cJSON_IsString(juri) && juri->valuestring){
        if (strncasecmp(juri->valuestring, "mqtts://", 8) == 0) cfg.tls_enabled = true;
        else if (strncasecmp(juri->valuestring, "mqtt://", 7) == 0) cfg.tls_enabled = false;
    }

    if (cJSON_IsString(juri) && juri->valuestring){
        const char* err_code = NULL;
        const char* msg = NULL;
        if (mqtt_normalize_and_validate_uri(juri->valuestring, cfg.tls_enabled, cfg.uri, sizeof(cfg.uri), &err_code, &msg) != ESP_OK){
            cJSON_Delete(j);
            return json_mqtt_error_reply(req, HTTPD_400_BAD_REQUEST, err_code, msg), ESP_FAIL;
        }
    } else if (cfg.enabled && !cfg.uri[0]){
        cJSON_Delete(j);
        return json_mqtt_error_reply(req, HTTPD_400_BAD_REQUEST, "invalid_broker_uri", "URI broker obbligatorio quando MQTT è abilitato"), ESP_FAIL;
    }

    if (cJSON_IsString(jcid) && jcid->valuestring){ strlcpy(cfg.cid, jcid->valuestring, sizeof(cfg.cid)); trim_inplace(cfg.cid); }
    if (cJSON_IsString(juser) && juser->valuestring){ strlcpy(cfg.user, juser->valuestring, sizeof(cfg.user)); trim_inplace(cfg.user); }
    if (cJSON_IsString(jtenant) && jtenant->valuestring){ strlcpy(cfg.tenant_id, jtenant->valuestring, sizeof(cfg.tenant_id)); trim_inplace(cfg.tenant_id); }
    if (cJSON_IsString(jsite) && jsite->valuestring){ strlcpy(cfg.site_id, jsite->valuestring, sizeof(cfg.site_id)); trim_inplace(cfg.site_id); }
    if (cJSON_IsString(jdev) && jdev->valuestring){ strlcpy(cfg.device_id, jdev->valuestring, sizeof(cfg.device_id)); trim_inplace(cfg.device_id); }
    if (cJSON_IsString(jbase) && jbase->valuestring){ strlcpy(cfg.configured_base_topic, jbase->valuestring, sizeof(cfg.configured_base_topic)); trim_inplace(cfg.configured_base_topic); }
    if (cJSON_IsString(jdp) && jdp->valuestring){ strlcpy(cfg.discovery_prefix, jdp->valuestring, sizeof(cfg.discovery_prefix)); trim_inplace(cfg.discovery_prefix); }

    if (!cfg.cid[0]) strlcpy(cfg.cid, cfg.device_id, sizeof(cfg.cid));
    if (!cfg.device_id[0]) strlcpy(cfg.device_id, cfg.cid, sizeof(cfg.device_id));
    if (!cfg.tenant_id[0]) strlcpy(cfg.tenant_id, "default", sizeof(cfg.tenant_id));
    if (!cfg.site_id[0]) strlcpy(cfg.site_id, "default", sizeof(cfg.site_id));
    if (!cfg.discovery_prefix[0]) strlcpy(cfg.discovery_prefix, "homeassistant", sizeof(cfg.discovery_prefix));

    if (cJSON_IsNumber(jka)) cfg.keepalive = (uint32_t)jka->valuedouble;
    else if (cJSON_IsString(jka) && jka->valuestring) cfg.keepalive = (uint32_t)strtoul(jka->valuestring, NULL, 10);
    if (cfg.keepalive < 10 || cfg.keepalive > 600){
        cJSON_Delete(j);
        return json_mqtt_error_reply(req, HTTPD_400_BAD_REQUEST, "invalid_keepalive", "Keepalive MQTT deve essere tra 10 e 600 secondi"), ESP_FAIL;
    }
    if (!mqtt_string_field_is_valid(cfg.cid, sizeof(cfg.cid), false)){
        cJSON_Delete(j);
        return json_mqtt_error_reply(req, HTTPD_400_BAD_REQUEST, "invalid_client_id", "Client ID MQTT non valido"), ESP_FAIL;
    }
    if (!mqtt_string_field_is_valid(cfg.tenant_id, sizeof(cfg.tenant_id), false) ||
        !mqtt_string_field_is_valid(cfg.site_id, sizeof(cfg.site_id), false) ||
        !mqtt_string_field_is_valid(cfg.device_id, sizeof(cfg.device_id), false)){
        cJSON_Delete(j);
        return json_mqtt_error_reply(req, HTTPD_400_BAD_REQUEST, "invalid_topic_identity", "tenant_id, site_id e device_id non validi"), ESP_FAIL;
    }
    if (!mqtt_topic_field_is_valid(cfg.configured_base_topic, sizeof(cfg.configured_base_topic), true)){
        cJSON_Delete(j);
        return json_mqtt_error_reply(req, HTTPD_400_BAD_REQUEST, "invalid_base_topic", "Base topic MQTT non valido"), ESP_FAIL;
    }
    if (!mqtt_topic_field_is_valid(cfg.discovery_prefix, sizeof(cfg.discovery_prefix), false)){
        cJSON_Delete(j);
        return json_mqtt_error_reply(req, HTTPD_400_BAD_REQUEST, "invalid_discovery_prefix", "Discovery prefix non valido"), ESP_FAIL;
    }

    bool clear_password = cJSON_IsBool(jclear) && cJSON_IsTrue(jclear);
    bool update_password = false;
    char new_pass[sizeof(cfg.pass)] = {0};
    if (cJSON_IsString(jpw) && jpw->valuestring && jpw->valuestring[0] != '\0'){
        strlcpy(new_pass, jpw->valuestring, sizeof(new_pass));
        update_password = true;
        if (!mqtt_password_is_valid(new_pass)){
            cJSON_Delete(j);
            return json_mqtt_error_reply(req, HTTPD_400_BAD_REQUEST, "invalid_password", MQTT_PASSWORD_POLICY_ERROR), ESP_FAIL;
        }
    }

    if (mqtt_build_effective_base_topic(cfg.configured_base_topic, cfg.tenant_id, cfg.site_id, cfg.device_id, cfg.base_topic, sizeof(cfg.base_topic)) != ESP_OK) {
        cJSON_Delete(j);
        return json_mqtt_error_reply(req, HTTPD_400_BAD_REQUEST, "invalid_base_topic", "Base topic MQTT troppo lungo"), ESP_FAIL;
    }
    cJSON_Delete(j);

    nvs_handle_t nvs;
    esp_err_t err = nvs_open("sys", NVS_READWRITE, &nvs);
    if (err != ESP_OK) return json_mqtt_error_reply(req, HTTPD_500_INTERNAL_SERVER_ERROR, "nvs_open_failed", "Impossibile aprire NVS"), ESP_FAIL;
    if (err == ESP_OK) err = nvs_set_u8(nvs,"mq_enabled", cfg.enabled ? 1 : 0);
    if (err == ESP_OK) err = nvs_set_u8(nvs,"mq_tls", cfg.tls_enabled ? 1 : 0);
    if (err == ESP_OK) err = nvs_set_u8(nvs,"mq_disc", cfg.discovery_enabled ? 1 : 0);
    if (err == ESP_OK) err = nvs_set_str(nvs,"mq_uri", cfg.uri);
    if (err == ESP_OK) err = nvs_set_str(nvs,"mq_cid", cfg.cid);
    if (err == ESP_OK) err = nvs_set_str(nvs,"mq_user", cfg.user);
    if (err == ESP_OK) err = nvs_set_u32(nvs,"mq_keep", cfg.keepalive);
    if (err == ESP_OK) err = nvs_set_str(nvs,"mq_tenant", cfg.tenant_id);
    if (err == ESP_OK) err = nvs_set_str(nvs,"mq_site", cfg.site_id);
    if (err == ESP_OK) err = nvs_set_str(nvs,"mq_device", cfg.device_id);
    if (err == ESP_OK) err = nvs_set_str(nvs,"mq_base", cfg.configured_base_topic);
    if (err == ESP_OK) err = nvs_set_str(nvs,"mq_disc_pref", cfg.discovery_prefix);
    if (err == ESP_OK && clear_password) {
        esp_err_t erase_err = nvs_erase_key(nvs, "mq_pass");
        if (erase_err != ESP_OK && erase_err != ESP_ERR_NVS_NOT_FOUND) err = erase_err;
    }
    if (err == ESP_OK && update_password) err = nvs_set_str(nvs,"mq_pass", new_pass);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    if (err != ESP_OK) return json_mqtt_error_reply(req, HTTPD_500_INTERNAL_SERVER_ERROR, "nvs_save_failed", "Salvataggio configurazione MQTT fallito"), ESP_FAIL;

    provisioning_load_mqtt(&cfg);
    esp_err_t reload_err = mqtt_reload_config();
    if (reload_err != ESP_OK) {
        ESP_LOGE(TAG, "Riavvio MQTT fallito dopo aggiornamento configurazione: %s", esp_err_to_name(reload_err));
    }

    cJSON* resp = cJSON_CreateObject();
    if (!resp) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL;
    cJSON_AddBoolToObject(resp, "ok", true);
    cJSON_AddStringToObject(resp, "message", reload_err == ESP_OK ? "Configurazione MQTT salvata" : "Configurazione MQTT salvata; riavvio client MQTT fallito");
    cJSON* c = cJSON_AddObjectToObject(resp, "config");
    if (!c) { cJSON_Delete(resp); return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json"), ESP_FAIL; }
    mqtt_config_add_json(c, &cfg);
    cJSON_AddBoolToObject(c, "connected", mqtt_is_connected());
    return json_reply_cjson(req, resp);
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
    const cJSON* jtls  = cJSON_GetObjectItemCaseSensitive(j, "tls_enabled");

    char uri[128] = {0};
    char cid[80] = {0};
    char user[80] = {0};
    char pass[96] = {0};

    bool tls_enabled = cJSON_IsBool(jtls) ? cJSON_IsTrue(jtls) :
                       (cJSON_IsString(juri) && juri->valuestring && strncasecmp(juri->valuestring, "mqtts://", 8) == 0);
    if (cJSON_IsString(juri) && juri->valuestring){
        const char* err_code = NULL;
        const char* msg = NULL;
        if (mqtt_normalize_and_validate_uri(juri->valuestring, tls_enabled, uri, sizeof(uri), &err_code, &msg) != ESP_OK){
            cJSON_Delete(j);
            return json_mqtt_error_reply(req, HTTPD_400_BAD_REQUEST, err_code, msg), ESP_FAIL;
        }
    }
    trim_inplace(uri);
    if (!uri[0]){
        cJSON_Delete(j);
        return json_mqtt_error_reply(req, HTTPD_400_BAD_REQUEST, "invalid_broker_uri", "URI broker obbligatorio"), ESP_FAIL;
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

    bool test_tls_uri = (strncasecmp(uri, "mqtts://", 8) == 0) || (strncasecmp(uri, "wss://", 6) == 0);
    if (test_tls_uri) {
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
    }

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

    uint64_t now_ms = utils_wall_time_ms();
    esp_err_t reg_err = roster_master_set_registered_at(now_ms);
    if (reg_err != ESP_OK) {
        ESP_LOGW(TAG, "Impossibile salvare registered_at della centrale: %s", esp_err_to_name(reg_err));
    }

    err = mqtt_reload_config();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Impossibile riavviare MQTT al termine del provisioning: %s", esp_err_to_name(err));
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "mqtt"), ESP_FAIL;
    }

    return send_http_redirect(req, "/login.html", "302 Found");
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
    char codes[AUTH_RECOVERY_CODE_COUNT][AUTH_RECOVERY_CODE_LEN];
    if (auth_recovery_generate(uname, codes) != ESP_OK) return httpd_resp_send_err(req,500,"recovery"), ESP_FAIL;
    audit_append("recovery", uname, 1, "generated");
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "ok", true);
    cJSON_AddStringToObject(resp, "message", "2FA abilitata. Salva questi codici: saranno mostrati una sola volta.");
    cJSON *arr = cJSON_AddArrayToObject(resp, "recovery_codes");
    for (int i=0; i<AUTH_RECOVERY_CODE_COUNT; ++i) cJSON_AddItemToArray(arr, cJSON_CreateString(codes[i]));
    return json_reply_cjson(req, resp);
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

#define ZONE_CONFIG_CAPACITY ALARM_MAX_ZONES

typedef struct {
    bool known;
    bool active;
    uint8_t board;
    uint8_t board_input;
    bool board_online;
    bool analog;
    float analog_value;
    bool tamper;
    bool analog_device_present;
    bool analog_sample_valid;
    uint8_t analog_mode;
} zone_state_entry_t;

typedef struct {
    int total;
    int master_total;
    zone_state_entry_t entries[ZONE_CONFIG_CAPACITY];
} zones_snapshot_t;

static zone_cfg_t s_zone_cfg[ZONE_CONFIG_CAPACITY];
static uint8_t    s_zone_board_map[ZONE_CONFIG_CAPACITY];

#define ZONE_BOARD_ID_ADS1115_BASE 200

static void zone_board_label_copy(uint8_t board_id, char *out, size_t cap)
{
    if (!out || cap == 0) {
        return;
    }
    out[0] = '\0';

    if (board_id == 0) {
        snprintf(out, cap, "%s", "Centrale");
        return;
    }

#if ADS1115_COUNT > 0
    if (board_id >= ZONE_BOARD_ID_ADS1115_BASE &&
        board_id < ZONE_BOARD_ID_ADS1115_BASE + ADS1115_COUNT) {
        snprintf(out, cap, "ADS1115 #%u",
                 (unsigned)(board_id - ZONE_BOARD_ID_ADS1115_BASE + 1u));
        return;
    }
#endif

    roster_node_t snapshot;
    if (roster_get_node_snapshot(board_id, &snapshot)) {
        snprintf(out, cap, "%s", snapshot.label);
    }
}


static bool zone_entry_is_local_digital_normal(int idx, const zone_state_entry_t *entry)
{
    return idx >= 0 && idx < INPUT_ZONES_COUNT && entry && !entry->analog && entry->board == 0;
}

static void zone_add_filter_fields(cJSON *it, int idx, const zone_state_entry_t *entry)
{
    if (!it || !zone_entry_is_local_digital_normal(idx, entry)) {
        return;
    }
    zone_filter_profile_t profile = inputs_zone_filter_get((uint16_t)idx);
    cJSON_AddStringToObject(it, "filter_profile", inputs_zone_filter_profile_name(profile));
    cJSON_AddNumberToObject(it, "debounce_ms", (double)inputs_zone_filter_effective_ms((uint16_t)idx));
}

static const char* zone_entry_display_name(int zone_index, const zone_state_entry_t *entry, char *out, size_t cap)
{
    if (!out || cap == 0) {
        return "";
    }
    out[0] = '\0';
    if (zone_index >= 0 && zone_index < ZONE_CONFIG_CAPACITY) {
        zone_cfg_t *cfg = &s_zone_cfg[zone_index];
        if (cfg && cfg->name[0]) {
            snprintf(out, cap, "%s", cfg->name);
            return out;
        }
    }

#if ADS1115_COUNT > 0
    if (entry && entry->analog) {
        snprintf(out, cap, "ADS%u CH%u",
                 (unsigned)(entry->board - ZONE_BOARD_ID_ADS1115_BASE + 1u),
                 (unsigned)(entry->board_input + 1u));
        return out;
    }
#endif
    if (entry && entry->board != 0) {
        snprintf(out, cap, "Exp %u Z%u", (unsigned)entry->board, (unsigned)(entry->board_input + 1u));
        return out;
    }
    snprintf(out, cap, "Z%d", zone_index + 1);
    return out;
}

static uint8_t zone_board_for_index(int zone_1_based){
    if (zone_1_based < 1 || zone_1_based > ZONE_CONFIG_CAPACITY) {
        return 0;
    }
    return s_zone_board_map[zone_1_based - 1];
}

static void zones_apply_to_alarm(void){
     // Invia le opzioni zona ad alarm_core
    for(int i=1;i<=ALARM_MAX_ZONES;i++){
        zone_cfg_t *c = &s_zone_cfg[i-1];
        zone_opts_t o = { .entry_delay = c->zone_delay, .entry_time_ms = (uint16_t)(c->zone_time * 1000u), .exit_delay = c->zone_delay, .exit_time_ms = (uint16_t)(c->zone_time * 1000u), .auto_exclude = c->auto_exclude };
        alarm_set_zone_opts(i, &o);
    }
}

static void zones_snapshot_build(zones_snapshot_t *snap)
{
    if (!snap) {
        return;
    }
    memset(snap, 0, sizeof(*snap));

    snap->master_total = INPUT_ZONES_COUNT;
    if (snap->master_total > ZONE_CONFIG_CAPACITY) {
        snap->master_total = ZONE_CONFIG_CAPACITY;
    }

    uint16_t gpioab = 0;
    bool gpio_ok = (inputs_read_all(&gpioab) == ESP_OK);
    for (int i = 0; i < snap->master_total; ++i) {
        input_zone_filtered_state_t filtered = {0};
        bool filtered_ok = inputs_get_filtered_zone_state((uint16_t)i, &filtered);
        zone_state_entry_t *entry = &snap->entries[i];
        entry->board = 0;
        entry->board_input = (uint8_t)i;
        entry->board_online = gpio_ok;
        entry->known = filtered_ok ? filtered.known : gpio_ok;
        entry->active = filtered_ok ? filtered.alarm : (gpio_ok ? inputs_zone_bit(gpioab, i + 1) : false);
        entry->analog = false;
        entry->analog_value = 0.0f;
        entry->tamper = false;
        entry->analog_device_present = false;
        entry->analog_sample_valid = false;
        entry->analog_mode = 0;
        s_zone_board_map[i] = 0;
        snap->total++;
    }

#if ADS1115_COUNT > 0
    size_t ads_expected = inputs_ads1115_expected_devices();
    size_t ads_detected = inputs_ads1115_count();
    uint16_t analog_slots = (uint16_t)inputs_analog_zone_count();
    if (snap->total + analog_slots > ZONE_CONFIG_CAPACITY) {
        if (snap->total < ZONE_CONFIG_CAPACITY) {
            analog_slots = (uint16_t)(ZONE_CONFIG_CAPACITY - snap->total);
        } else {
            analog_slots = 0;
        }
    }

    uint16_t added = 0;
    for (size_t dev = 0; dev < ads_expected && added < analog_slots; ++dev) {
        bool device_online = (dev < ads_detected);
        for (int ch = 0; ch < ADS1115_CHANNEL_COUNT && added < analog_slots; ++ch, ++added) {
            if (snap->total >= ZONE_CONFIG_CAPACITY) {
                break;
            }
            zone_state_entry_t *entry = &snap->entries[snap->total];
            entry->board = (uint8_t)(ZONE_BOARD_ID_ADS1115_BASE + dev);
            entry->board_input = (uint8_t)ch;
            entry->board_online = device_online;
            entry->analog = true;
            entry->analog_value = 0.0f;
            entry->known = false;
            entry->active = false;
            entry->tamper = false;
            entry->analog_device_present = false;
            entry->analog_sample_valid = false;
            entry->analog_mode = 0;
#if ADS1115_COUNT > 0
            size_t analog_index = (size_t)(dev * ADS1115_CHANNEL_COUNT + ch);
            input_analog_zone_state_t state;
            input_zone_filtered_state_t filtered = {0};
            bool filtered_ok = inputs_get_filtered_zone_state((uint16_t)(INPUT_ZONES_COUNT + analog_index), &filtered);
            if (inputs_analog_evaluate(analog_index, pdMS_TO_TICKS(75), &state) == ESP_OK) {
                entry->analog_mode = (uint8_t)state.mode;
                entry->analog_device_present = state.device_present;
                entry->analog_sample_valid = state.sample_valid;
                entry->board_online = state.device_present;
                if (filtered_ok) {
                    entry->known = filtered.known;
                    entry->active = filtered.alarm;
                    entry->analog_value = filtered.voltage;
                    entry->tamper = filtered.tamper;
                }
            }
#endif
            s_zone_board_map[snap->total] = entry->board;
            snap->total++;
        }
    }
#endif

    const size_t nodes_cap = 32;
    roster_node_inputs_t *nodes = calloc(nodes_cap, sizeof(*nodes));
    size_t node_count = nodes ? roster_collect_nodes(nodes, nodes_cap) : 0;
    for (size_t idx = 0; idx < node_count; ++idx) {
        const roster_node_inputs_t *node = &nodes[idx];
        if (node->inputs_count == 0) {
            continue;
        }
        for (uint8_t bit = 0; bit < node->inputs_count; ++bit) {
            if (snap->total >= ZONE_CONFIG_CAPACITY) {
                break;
            }
            zone_state_entry_t *entry = &snap->entries[snap->total];
            entry->board = node->node_id;
            entry->board_input = bit;
            entry->board_online = (node->state == ROSTER_NODE_STATE_OPERATIONAL);
            entry->known = entry->board_online && node->inputs_valid;
            entry->active = entry->known ? ((node->inputs_bitmap & (1u << bit)) != 0u) : false;
            entry->analog = false;
            entry->analog_value = 0.0f;
            entry->tamper = false;
            entry->analog_device_present = false;
            entry->analog_sample_valid = false;
            entry->analog_mode = 0;
            s_zone_board_map[snap->total] = entry->board;
            snap->total++;
        }
        if (snap->total >= ZONE_CONFIG_CAPACITY) {
            break;
        }
    }
    free(nodes);

    for (int i = snap->total; i < ZONE_CONFIG_CAPACITY; ++i) {
        s_zone_board_map[i] = 0;
        snap->entries[i].known = false;
        snap->entries[i].active = false;
        snap->entries[i].board = 0;
        snap->entries[i].board_input = 0;
        snap->entries[i].board_online = false;
        snap->entries[i].tamper = false;
        snap->entries[i].analog_device_present = false;
        snap->entries[i].analog_sample_valid = false;
        snap->entries[i].analog_mode = 0;
    }
}

static int zones_snapshot_total(const zones_snapshot_t *snap)
{
    if (!snap) {
        return INPUT_ZONES_COUNT;
    }
    if (snap->total <= 0) {
        return snap->master_total;
    }
    return snap->total;
}

static int zones_effective_total(void)
{
    uint16_t total = roster_effective_zones(inputs_master_zone_capacity());
    if (total > ZONE_CONFIG_CAPACITY) {
        total = ZONE_CONFIG_CAPACITY;
    }
    return (int)total;
}

static void zones_load_from_nvs(void){
    memset(s_zone_cfg, 0, sizeof(s_zone_cfg));
    memset(s_zone_board_map, 0, sizeof(s_zone_board_map));

    nvs_handle_t h;
    if (nvs_open("zones", NVS_READONLY, &h) == ESP_OK){
        size_t cfg_sz = 0;
        if (nvs_get_blob(h, "cfg", NULL, &cfg_sz) == ESP_OK && cfg_sz > 0) {
            uint8_t *buf = malloc(cfg_sz);
            if (buf) {
                size_t read_len = cfg_sz;
                if (nvs_get_blob(h, "cfg", buf, &read_len) == ESP_OK) {
                    size_t copy = read_len;
                    if (copy > sizeof(s_zone_cfg)) {
                        copy = sizeof(s_zone_cfg);
                    }
                    memcpy(s_zone_cfg, buf, copy);
                }
                free(buf);
            }
        }

        size_t map_sz = 0;
        if (nvs_get_blob(h, "map", NULL, &map_sz) == ESP_OK && map_sz > 0) {
            uint8_t *buf = malloc(map_sz);
            if (buf) {
                size_t read_len = map_sz;
                if (nvs_get_blob(h, "map", buf, &read_len) == ESP_OK) {
                    size_t copy = read_len;
                    if (copy > sizeof(s_zone_board_map)) {
                        copy = sizeof(s_zone_board_map);
                    }
                    memcpy(s_zone_board_map, buf, copy);
                }
                free(buf);
            }
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
    if (strcmp(code, "tamper_alarm") == 0) return "Tamper violato";
    if (strcmp(code, "alarm_arm") == 0) return "Allarme armato";
    if (strcmp(code, "alarm_disarm") == 0) return "Allarme disinserito";
    if (strcmp(code, "alarm_trigger") == 0) return "Allarme zone";
    return code;
}

static bool extract_note_field(const char *note, const char *key, char *out, size_t cap)
{
    if (!out || cap == 0 || !note || !key || !key[0]) {
        return false;
    }
    out[0] = '\0';
    size_t key_len = strlen(key);
    const char *cursor = note;
    while (*cursor) {
        while (*cursor == ' ') {
            ++cursor;
        }
        if (*cursor == '\0') {
            break;
        }
        const char *segment_end = strchr(cursor, ' ');
        size_t segment_len = segment_end ? (size_t)(segment_end - cursor) : strlen(cursor);
        if (segment_len > key_len + 1 && strncmp(cursor, key, key_len) == 0 && cursor[key_len] == '=') {
            size_t value_len = segment_len - key_len - 1;
            if (value_len >= cap) {
                value_len = cap - 1;
            }
            memcpy(out, cursor + key_len + 1, value_len);
            out[value_len] = '\0';
            return true;
        }
        cursor += segment_len;
        if (*cursor == ' ') {
            ++cursor;
        }
    }
    return false;
}

static void scenario_label_from_code(const char *code, char *out, size_t cap)
{
    if (!out || cap == 0) {
        return;
    }
    out[0] = '\0';
    if (!code || !code[0]) {
        return;
    }
    char buffer[48];
    strlcpy(buffer, code, sizeof(buffer));
    char *start = buffer;
    if (strncasecmp(start, "ARMED_", 6) == 0) {
        start += 6;
    } else if (strncasecmp(start, "PRE_", 4) == 0) {
        start += 4;
    }
    for (char *p = start; *p; ++p) {
        if (*p == '_' || *p == '-') {
            *p = ' ';
        } else {
            *p = (char)tolower((unsigned char)*p);
        }
    }
    bool new_word = true;
    size_t out_idx = 0;
    for (const char *p = start; *p && out_idx + 1 < cap; ++p) {
        char c = *p;
        if (c == ' ') {
            if (out_idx == 0 || out[out_idx - 1] == ' ') {
                continue;
            }
            out[out_idx++] = ' ';
            new_word = true;
            continue;
        }
        if (new_word) {
            out[out_idx++] = (char)toupper((unsigned char)c);
            new_word = false;
        } else {
            out[out_idx++] = c;
        }
    }
    while (out_idx > 0 && out[out_idx - 1] == ' ') {
        --out_idx;
    }
    out[out_idx] = '\0';
    if (out[0] == '\0') {
        strlcpy(out, code, cap);
    }
}

static void format_user_display(const char *username, char *out, size_t cap)
{
    if (!out || cap == 0) {
        return;
    }
    out[0] = '\0';
    if (!username || !username[0]) {
        return;
    }
    bool has_upper = false;
    for (const char *p = username; *p; ++p) {
        if (isupper((unsigned char)*p)) {
            has_upper = true;
            break;
        }
    }
    if (!has_upper) {
        size_t idx = 0;
        for (const char *p = username; *p && idx + 1 < cap; ++p) {
            out[idx] = (idx == 0) ? (char)toupper((unsigned char)*p) : (char)tolower((unsigned char)*p);
            ++idx;
        }
        out[idx] = '\0';
        return;
    }
    strlcpy(out, username, cap);
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

    if (strcmp(ent->event, "alarm_arm") == 0 || strcmp(ent->event, "alarm_disarm") == 0) {
        char scenario_code[48];
        scenario_code[0] = '\0';
        if (strcmp(ent->event, "alarm_arm") == 0) {
            extract_note_field(ent->note, "mode", scenario_code, sizeof(scenario_code));
        } else {
            extract_note_field(ent->note, "prev", scenario_code, sizeof(scenario_code));
        }
        char scenario_label[48];
        scenario_label_from_code(scenario_code, scenario_label, sizeof(scenario_label));
        if (!scenario_label[0]) {
            strlcpy(scenario_label, "—", sizeof(scenario_label));
        }
        char user_buf[48];
        format_user_display(ent->username, user_buf, sizeof(user_buf));
        if (!user_buf[0]) {
            strlcpy(user_buf, "-", sizeof(user_buf));
        }
        const char *action = (strcmp(ent->event, "alarm_arm") == 0) ? "INSERITO" : "DISINSERITO";
        snprintf(out, cap, "Allarme %s - scenario: %s\nutente: %s", action, scenario_label, user_buf);
        return;
    }

    if (strcmp(ent->event, "tamper_alarm") == 0) {
        char prev_code[48];
        prev_code[0] = '\0';
        extract_note_field(ent->note, "prev", prev_code, sizeof(prev_code));
        char scenario_label[48];
        scenario_label_from_code(prev_code, scenario_label, sizeof(scenario_label));
        if (!scenario_label[0]) {
            strlcpy(scenario_label, "—", sizeof(scenario_label));
        }
        char user_buf[48];
        format_user_display(ent->username, user_buf, sizeof(user_buf));
        if (!user_buf[0]) {
            strlcpy(user_buf, "Sistema", sizeof(user_buf));
        }
        snprintf(out, cap, "Allarme TAMPER - scenario: %s\nutente: %s", scenario_label, user_buf);
        return;
    }

    if (strcmp(ent->event, "alarm_trigger") == 0) {
        if (has_note) {
            snprintf(out, cap, "%s (%s)", label, ent->note);
        } else {
            snprintf(out, cap, "%s", label);
        }
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

static bool logs_event_is_alarm_related(const audit_entry_t *ent)
{
    if (!ent || !ent->event[0]) {
        return false;
    }
    const char *ev = ent->event;
    if (strcasecmp(ev, "alarm_arm") == 0) return true;
    if (strcasecmp(ev, "alarm_disarm") == 0) return true;
    if (strcasecmp(ev, "alarm_trigger") == 0) return true;
    if (strcasecmp(ev, "tamper_alarm") == 0) return true;
    if (strcasecmp(ev, "tamper_reset") == 0) return true;
    return false;
}

static size_t json_escape_string(const char *src, char *dst, size_t dst_cap)
{
    if (!dst || dst_cap == 0) {
        return 0;
    }
    size_t out = 0;
    const char *input = src ? src : "";
    const char hex[] = "0123456789ABCDEF";
    while (*input) {
        unsigned char c = (unsigned char)(*input++);
        const char *esc = NULL;
        switch (c) {
            case '\"': esc = "\\\""; break;
            case '\\': esc = "\\\\"; break;
            case '\b': esc = "\\b"; break;
            case '\f': esc = "\\f"; break;
            case '\n': esc = "\\n"; break;
            case '\r': esc = "\\r"; break;
            case '\t': esc = "\\t"; break;
            default:
                if (c < 0x20) {
                    if (out + 6 >= dst_cap) {
                        dst_cap = out + 1;
                        break;
                    }
                    dst[out++] = '\\';
                    dst[out++] = 'u';
                    dst[out++] = '0';
                    dst[out++] = '0';
                    dst[out++] = hex[(c >> 4) & 0xF];
                    dst[out++] = hex[c & 0xF];
                    continue;
                }
                if (out + 1 >= dst_cap) {
                    dst_cap = out + 1;
                    break;
                }
                dst[out++] = (char)c;
                continue;
        }
        if (esc) {
            size_t len = strlen(esc);
            if (out + len >= dst_cap) {
                dst_cap = out + 1;
                break;
            }
            memcpy(dst + out, esc, len);
            out += len;
        }
    }
    if (out >= dst_cap) {
        dst[dst_cap - 1] = '\0';
        return dst_cap - 1;
    }
    dst[out] = '\0';
    return out;
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

    set_http_security_headers(req);
    httpd_resp_set_type(req, "application/json");

    esp_err_t send_err = httpd_resp_sendstr_chunk(req, "{\"entries\":[");
    if (send_err != ESP_OK) {
        free(entries_buf);
        return send_err;
    }

    bool first = true;

    for (int j = match_count - 1; j >= start; --j) {
        int idx = match_indexes[j];
        audit_entry_t *ent = &entries_buf[idx];
        int64_t wall_ts = resolved_wall_ts[j];

        char message[160];
        audit_format_message(ent, message, sizeof(message));

        char message_json[640];
        char event_json[128];
        char user_json[192];
        char note_json[256];
        json_escape_string(message, message_json, sizeof(message_json));
        json_escape_string(ent->event, event_json, sizeof(event_json));
        json_escape_string(ent->username, user_json, sizeof(user_json));
        json_escape_string(ent->note, note_json, sizeof(note_json));

        const bool otp_pending = strcmp(ent->note, "otp required") == 0;
        const char *level = (ent->result > 0 || otp_pending) ? "INFO" : "WARN";

        char iso[32] = {0};
        if (wall_ts > 0) {
            logs_format_iso8601(wall_ts, iso, sizeof(iso));
        }

        if (!first) {
            send_err = httpd_resp_sendstr_chunk(req, ",");
            if (send_err != ESP_OK) {
                free(entries_buf);
                return send_err;
            }
        }

        char entry_buf[768];
        int offset = 0;
        if (offset < (int)sizeof(entry_buf)) {
            entry_buf[offset++] = '{';
        }
        if (offset < (int)sizeof(entry_buf)) {
            entry_buf[offset] = '\0';
        } else {
            entry_buf[sizeof(entry_buf) - 1] = '\0';
        }

        if (wall_ts > 0) {
            double epoch_seconds = (double)wall_ts / 1000000.0;
            offset += snprintf(entry_buf + offset,
                               sizeof(entry_buf) - (size_t)offset,
                               "\"ts\":%.6f,\"ts_epoch\":%.6f,\"ts_ms\":%.3f,\"wall_ts_us\":%.0f",
                               epoch_seconds,
                               epoch_seconds,
                               epoch_seconds * 1000.0,
                               (double)wall_ts);
            if (iso[0] != '\0') {
                offset += snprintf(entry_buf + offset,
                                   sizeof(entry_buf) - (size_t)offset,
                                   ",\"ts_iso\":\"%s\"",
                                   iso);
            }
            offset += snprintf(entry_buf + offset,
                               sizeof(entry_buf) - (size_t)offset,
                               ",");
        }
        offset += snprintf(entry_buf + offset,
                           sizeof(entry_buf) - (size_t)offset,
                           "\"ts_us\":%.0f,\"uptime_s\":%.6f,\"result\":%d,"
                           "\"event\":\"%s\",\"user\":\"%s\",\"note\":\"%s\","
                           "\"message\":\"%s\",\"level\":\"%s\"",
                           (double)ent->ts_us,
                           (double)ent->ts_us / 1000000.0,
                           ent->result,
                           event_json,
                           user_json,
                           note_json,
                           message_json,
                           level);
        if (offset < 0 || offset >= (int)sizeof(entry_buf)) {
            entry_buf[sizeof(entry_buf) - 1] = '\0';
        }

        if (offset >= 0 && offset < (int)sizeof(entry_buf) && logs_event_is_alarm_related(ent)) {
            offset += snprintf(entry_buf + offset,
                               sizeof(entry_buf) - (size_t)offset,
                               ",\"category\":\"alarm\"");
            if (offset < 0 || offset >= (int)sizeof(entry_buf)) {
                entry_buf[sizeof(entry_buf) - 1] = '\0';
            }
        }

        if (offset >= 0 && offset < (int)sizeof(entry_buf)) {
            if ((size_t)offset < sizeof(entry_buf) - 1) {
                entry_buf[offset++] = '}';
                entry_buf[offset] = '\0';
            } else {
                entry_buf[sizeof(entry_buf) - 1] = '\0';
            }
        }

        send_err = httpd_resp_sendstr_chunk(req, entry_buf);
        if (send_err != ESP_OK) {
            free(entries_buf);
            return send_err;
        }
        first = false;
    }

    char meta[256];
    size_t used = 0;
    int written = snprintf(meta + used, sizeof(meta) - used,
                           "],\"count\":%d,\"total\":%d,\"limit\":%d",
                           returned,
                           match_count,
                           filter.limit);
    if (written < 0) {
        written = 0;
    }
    if ((size_t)written >= sizeof(meta) - used) {
        used = sizeof(meta) - 1;
    } else {
        used += (size_t)written;
    }
    if (filter.has_since && used < sizeof(meta) - 1) {
        double since = (double)filter.since_us / 1000000.0;
        written = snprintf(meta + used, sizeof(meta) - used, ",\"since\":%.6f", since);
        if (written < 0) written = 0;
        if ((size_t)written >= sizeof(meta) - used) {
            used = sizeof(meta) - 1;
        } else {
            used += (size_t)written;
        }
    }
    if (filter.has_until && used < sizeof(meta) - 1) {
        double until = (double)filter.until_us / 1000000.0;
        written = snprintf(meta + used, sizeof(meta) - used, ",\"until\":%.6f", until);
        if (written < 0) written = 0;
        if ((size_t)written >= sizeof(meta) - used) {
            used = sizeof(meta) - 1;
        } else {
            used += (size_t)written;
        }
    }
    if (used < sizeof(meta) - 1) {
        meta[used++] = '}';
        meta[used] = '\0';
    } else {
        meta[sizeof(meta) - 2] = '}';
        meta[sizeof(meta) - 1] = '\0';
    }
    send_err = httpd_resp_sendstr_chunk(req, meta);
    if (send_err != ESP_OK) {
        free(entries_buf);
        return send_err;
    }

    send_err = httpd_resp_sendstr_chunk(req, NULL);
    free(entries_buf);
    return send_err;
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

static esp_err_t logs_delete_post(httpd_req_t* req){
    if (!check_bearer(req) || !is_admin_user(req)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden");
        return ESP_FAIL;
    }

    if (req->content_len <= 0 || req->content_len > 256) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "body");
        return ESP_FAIL;
    }

    char body[256];
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

    int64_t ts_us = 0;
    bool has_ts = json_get_int64(json, "ts_us", &ts_us);
    if (!has_ts) {
        has_ts = json_get_int64(json, "tsUs", &ts_us);
    }

    if (!has_ts || ts_us <= 0) {
        cJSON_Delete(json);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "ts_us");
        return ESP_FAIL;
    }

    esp_err_t err = audit_delete(ts_us);
    cJSON_Delete(json);
    if (err == ESP_ERR_NOT_FOUND) {
        return json_error_reply(req, "404 Not Found", "not_found");
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "audit_delete failed: %s", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "delete");
        return err;
    }

    set_http_security_headers(req);
    httpd_resp_set_status(req, "204 No Content");
    return httpd_resp_send(req, NULL, 0);
}


static cJSON *json_create_zone_id_array_from_mask(const zone_mask_t *mask, uint16_t zone_limit)
{
    cJSON *arr = cJSON_CreateArray();
    if (!arr) {
        return NULL;
    }
    for (uint16_t idx = 0; idx < zone_limit; ++idx) {
        if (zone_mask_test(mask, idx)) {
            cJSON_AddItemToArray(arr, cJSON_CreateNumber((double)(idx + 1u)));
        }
    }
    return arr;
}

static uint16_t zone_mask_count_limited(const zone_mask_t *mask, uint16_t zone_limit)
{
    uint16_t count = 0;
    if (!mask) {
        return 0;
    }
    for (uint16_t idx = 0; idx < zone_limit; ++idx) {
        if (zone_mask_test(mask, idx)) {
            ++count;
        }
    }
    return count;
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
    input_debounce_state_t tamper_state = {0};
    bool tamper_global = inputs_get_filtered_tamper(&tamper_state) ? tamper_state.stable_value : false;
    zone_mask_t tamper_mask;
    zone_mask_clear(&tamper_mask);
    bool tamper_alarm = (alarm_last_alarm_was_tamper() && _st == ALARM_ALARM);

    uint16_t outmask = 0;
    outputs_get_mask(&outmask);

    zones_snapshot_t snapshot;
    zones_snapshot_build(&snapshot);
    const int zones_total = zones_snapshot_total(&snapshot);
    const uint16_t zone_limit = (zones_total < 0) ? 0 : (uint16_t)zones_total;
    zone_mask_t open_zone_mask;
    zone_mask_t zone_tamper_mask;
    zone_mask_t violated_zone_mask;
    zone_mask_t armed_zone_mask;
    zone_mask_clear(&open_zone_mask);
    zone_mask_clear(&zone_tamper_mask);
    zone_mask_clear(&violated_zone_mask);
    zone_mask_clear(&armed_zone_mask);
    alarm_get_violated_zone_mask(&violated_zone_mask);
    alarm_get_zone_tamper_mask(&zone_tamper_mask);
    alarm_get_armed_zone_mask(&armed_zone_mask);
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        return ESP_ERR_NO_MEM;
    }

    cJSON_AddStringToObject(root, "state", state);
    cJSON_AddNumberToObject(root, "zones_count", zones_total);
#if ADS1115_COUNT > 0
    cJSON_AddNumberToObject(root, "ads1115_expected", (double)inputs_ads1115_expected_devices());
    cJSON_AddNumberToObject(root, "ads1115_detected", (double)inputs_ads1115_count());
#else
    cJSON_AddNumberToObject(root, "ads1115_expected", 0);
    cJSON_AddNumberToObject(root, "ads1115_detected", 0);
#endif

    cJSON *zones = cJSON_CreateArray();
    cJSON *zones_known = cJSON_CreateArray();
    if (zones && zones_known) {
        for (int idx = 0; idx < zones_total; ++idx) {
            const zone_state_entry_t *entry = &snapshot.entries[idx];
            cJSON_AddItemToArray(zones, cJSON_CreateBool(entry->active));
            cJSON_AddItemToArray(zones_known, cJSON_CreateBool(entry->known));
            if (entry->known && entry->active) {
                zone_mask_set(&open_zone_mask, (uint16_t)idx);
            }
            if (entry->known && entry->tamper) {
                zone_mask_set(&tamper_mask, (uint16_t)idx);
                zone_mask_set(&zone_tamper_mask, (uint16_t)idx);
            }
        }
        cJSON_AddItemToObject(root, "zones_active", zones);
        cJSON_AddItemToObject(root, "zones_known", zones_known);
    } else {
        if (zones) cJSON_Delete(zones);
        if (zones_known) cJSON_Delete(zones_known);
        cJSON_AddNullToObject(root, "zones_active");
        cJSON_AddNullToObject(root, "zones_known");
    }

    zone_mask_limit(&open_zone_mask, zone_limit);
    zone_mask_limit(&zone_tamper_mask, zone_limit);
    zone_mask_limit(&violated_zone_mask, zone_limit);
    zone_mask_limit(&armed_zone_mask, zone_limit);
    bool tamper = tamper_global || zone_mask_any(&tamper_mask);
    cJSON_AddBoolToObject(root, "tamper", tamper);
    cJSON_AddBoolToObject(root, "system_tamper", tamper);
    cJSON_AddBoolToObject(root, "tamper_global", tamper_global);
    cJSON_AddBoolToObject(root, "global_tamper", tamper_global);
    cJSON_AddStringToObject(root, "alarm_state", state);
    cJSON_AddStringToObject(root, "alarm_cause", alarm_last_alarm_cause());
    cJSON_AddNumberToObject(root, "open_zone_count", (double)zone_mask_count_limited(&open_zone_mask, zone_limit));
    cJSON_AddNumberToObject(root, "open_zone_mask", (double)zone_mask_to_u32(&open_zone_mask));
    cJSON_AddNumberToObject(root, "violated_zone_mask", (double)zone_mask_to_u32(&violated_zone_mask));
    cJSON_AddNumberToObject(root, "armed_zone_mask", (double)zone_mask_to_u32(&armed_zone_mask));
    cJSON *open_zones = json_create_zone_id_array_from_mask(&open_zone_mask, zone_limit);
    cJSON *violated_zones = json_create_zone_id_array_from_mask(&violated_zone_mask, zone_limit);
    cJSON *zone_tampers = json_create_zone_id_array_from_mask(&zone_tamper_mask, zone_limit);
    cJSON *zone_faults = cJSON_CreateArray();
    if (open_zones) cJSON_AddItemToObject(root, "open_zones", open_zones); else cJSON_AddNullToObject(root, "open_zones");
    if (violated_zones) cJSON_AddItemToObject(root, "violated_zones", violated_zones); else cJSON_AddNullToObject(root, "violated_zones");
    if (zone_tampers) cJSON_AddItemToObject(root, "zone_tampers", zone_tampers); else cJSON_AddNullToObject(root, "zone_tampers");
    if (zone_faults) cJSON_AddItemToObject(root, "zone_faults", zone_faults); else cJSON_AddNullToObject(root, "zone_faults");
    if (tamper_global) {
        cJSON_AddStringToObject(root, "tamper_message", "Tamper generale aperto: serie antimanomissione interrotta");
    }
    cJSON_AddNumberToObject(root, "tamper_zone_mask", (double)zone_mask_to_u32(&zone_tamper_mask));
    cJSON_AddBoolToObject(root, "tamper_alarm", tamper_alarm);
    cJSON *tamper_sources = cJSON_CreateArray();
    if (tamper_sources) {
        if (tamper_global) {
            cJSON *src = cJSON_CreateObject();
            if (src) {
                cJSON_AddStringToObject(src, "type", "global");
                cJSON_AddStringToObject(src, "label", "Tamper centrale");
                cJSON_AddItemToArray(tamper_sources, src);
            }
        }
        for (int idx = 0; idx < zones_total; ++idx) {
            const zone_state_entry_t *entry = &snapshot.entries[idx];
            if (!entry->known || !entry->tamper) {
                continue;
            }
            cJSON *src = cJSON_CreateObject();
            if (!src) {
                continue;
            }
            cJSON_AddStringToObject(src, "type", "zone");
            cJSON_AddNumberToObject(src, "zone_id", (double)(idx + 1));
            char name_buf[48];
            const char *label = zone_entry_display_name(idx, entry, name_buf, sizeof(name_buf));
            cJSON_AddStringToObject(src, "name", label ? label : "");
            cJSON_AddItemToArray(tamper_sources, src);
        }
        cJSON_AddItemToObject(root, "tamper_sources", tamper_sources);
    } else {
        cJSON_AddNullToObject(root, "tamper_sources");
    }
    cJSON_AddNumberToObject(root, "outputs_mask", (unsigned)outmask);
    zone_mask_t bypass_mask;
    alarm_get_bypass_mask(&bypass_mask);
    zone_mask_limit(&bypass_mask, (uint16_t)zones_total);
    char bypass_hex[ZONE_MASK_WORDS * 8u + 1u];
    zone_mask_to_hex(&bypass_mask, (uint16_t)zones_total, bypass_hex, sizeof(bypass_hex));
    cJSON_AddNumberToObject(root, "bypass_mask", (double)zone_mask_to_u32(&bypass_mask));
    cJSON_AddStringToObject(root, "bypass_mask_hex", bypass_hex);
    cJSON_AddBoolToObject(root, "arming", exit_p);
    cJSON_AddStringToObject(root, "active_mode", alarm_active_mode());
    cJSON_AddStringToObject(root, "target_mode", exit_p ? alarm_active_mode() : "");
    cJSON_AddNumberToObject(root, "exit_delay_s", (double)((alarm_exit_duration_ms() + 999u) / 1000u));
    cJSON_AddNumberToObject(root, "exit_delay_remaining_s", (double)((exit_ms + 999u) / 1000u));
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

#if ADS1115_COUNT > 0
static const char* ads_gain_label(ads1115_gain_t gain)
{
    switch (gain) {
        case ADS1115_PGA_FSR_6144: return "±6.144 V";
        case ADS1115_PGA_FSR_4096: return "±4.096 V";
        case ADS1115_PGA_FSR_2048: return "±2.048 V";
        case ADS1115_PGA_FSR_1024: return "±1.024 V";
        case ADS1115_PGA_FSR_0512: return "±0.512 V";
        case ADS1115_PGA_FSR_0256: return "±0.256 V";
        default: return "±6.144 V";
    }
}

static const char* ads_mode_label(ads1115_mode_t mode)
{
    switch (mode) {
        case ADS1115_MODE_CONTINUOUS: return "Continuo";
        case ADS1115_MODE_SINGLE_SHOT: return "Singolo (single-shot)";
        default: return "Sconosciuto";
    }
}

static int ads_data_rate_value(ads1115_data_rate_t rate)
{
    switch (rate) {
        case ADS1115_DATA_RATE_8_SPS: return 8;
        case ADS1115_DATA_RATE_16_SPS: return 16;
        case ADS1115_DATA_RATE_32_SPS: return 32;
        case ADS1115_DATA_RATE_64_SPS: return 64;
        case ADS1115_DATA_RATE_128_SPS: return 128;
        case ADS1115_DATA_RATE_250_SPS: return 250;
        case ADS1115_DATA_RATE_475_SPS: return 475;
        case ADS1115_DATA_RATE_860_SPS: return 860;
        default: return 0;
    }
}

static const char* ads_data_rate_label(ads1115_data_rate_t rate)
{
    static char label[16];
    int value = ads_data_rate_value(rate);
    if (value <= 0) {
        snprintf(label, sizeof(label), "? SPS");
    } else {
        snprintf(label, sizeof(label), "%d SPS", value);
    }
    return label;
}

static const char* ads_comp_queue_label(ads1115_comp_queue_t queue)
{
    switch (queue) {
        case ADS1115_COMP_QUEUE_ASSERT_1: return "Comparator attivo dopo 1 conversione";
        case ADS1115_COMP_QUEUE_ASSERT_2: return "Comparator attivo dopo 2 conversioni";
        case ADS1115_COMP_QUEUE_ASSERT_4: return "Comparator attivo dopo 4 conversioni";
        case ADS1115_COMP_QUEUE_DISABLE: return "Comparator disabilitato";
        default: return "Comparator sconosciuto";
    }
}

static esp_err_t api_admin_ads1115_diag_get(httpd_req_t* req)
{
    if (!check_bearer(req) || !is_admin_user(req)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden");
        return ESP_FAIL;
    }

    cJSON* root = cJSON_CreateObject();
    if (!root) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        return ESP_ERR_NO_MEM;
    }

    size_t expected = inputs_ads1115_expected_devices();
    size_t detected = inputs_ads1115_count();
    uint64_t now_ms = esp_timer_get_time() / 1000ULL;

    cJSON_AddBoolToObject(root, "enabled", true);
    cJSON_AddBoolToObject(root, "all_online", (expected > 0) && (detected == expected));
    cJSON_AddNumberToObject(root, "expected", (double)expected);
    cJSON_AddNumberToObject(root, "detected", (double)detected);
    cJSON_AddNumberToObject(root, "channel_count", ADS1115_CHANNEL_COUNT);
    cJSON_AddNumberToObject(root, "timestamp_ms", (double)now_ms);

    cJSON* devices = cJSON_CreateArray();
    if (!devices) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        return ESP_ERR_NO_MEM;
    }
    cJSON_AddItemToObject(root, "devices", devices);

    for (size_t slot = 0; slot < expected; ++slot) {
        cJSON* device = cJSON_CreateObject();
        if (!device) {
            continue;
        }
        cJSON_AddItemToArray(devices, device);
        cJSON_AddNumberToObject(device, "slot", (double)slot);

        ads1115_device_config_t cfg;
        esp_err_t cfg_err = inputs_ads1115_get_expected_config(slot, &cfg);
        if (cfg_err != ESP_OK) {
            cJSON_AddStringToObject(device, "status", "Configurazione ADS1115 non disponibile");
            cJSON_AddBoolToObject(device, "online", false);
            continue;
        }

        cJSON_AddNumberToObject(device, "address", (double)cfg.address);
        char addr_hex[8];
        snprintf(addr_hex, sizeof(addr_hex), "0x%02X", cfg.address);
        cJSON_AddStringToObject(device, "address_hex", addr_hex);

        cJSON* config = cJSON_CreateObject();
        if (config) {
            cJSON_AddNumberToObject(config, "gain", (double)cfg.options.gain);
            cJSON_AddStringToObject(config, "gain_label", ads_gain_label(cfg.options.gain));
            cJSON_AddNumberToObject(config, "mode", (double)cfg.options.mode);
            cJSON_AddStringToObject(config, "mode_label", ads_mode_label(cfg.options.mode));
            cJSON_AddNumberToObject(config, "data_rate", (double)cfg.options.data_rate);
            cJSON_AddNumberToObject(config, "data_rate_sps", (double)ads_data_rate_value(cfg.options.data_rate));
            cJSON_AddStringToObject(config, "data_rate_label", ads_data_rate_label(cfg.options.data_rate));
            cJSON_AddNumberToObject(config, "comp_queue", (double)cfg.options.comp_queue);
            cJSON_AddStringToObject(config, "comp_queue_label", ads_comp_queue_label(cfg.options.comp_queue));
            cJSON_AddBoolToObject(config, "comparator_enabled", cfg.options.comp_queue != ADS1115_COMP_QUEUE_DISABLE);
            cJSON_AddItemToObject(device, "config", config);
        }

        int detected_index = inputs_ads1115_detected_index_for_address(cfg.address);
        bool online = (detected_index >= 0);
        cJSON_AddBoolToObject(device, "online", online);
        if (online) {
            cJSON_AddNumberToObject(device, "detected_index", (double)detected_index);
        }

        cJSON* channels = cJSON_CreateArray();
        if (channels) {
            esp_err_t read_err = ESP_ERR_INVALID_STATE;
            int16_t raw_values[ADS1115_CHANNEL_COUNT] = {0};
            if (online) {
                read_err = inputs_ads1115_read_all_raw((size_t)detected_index, pdMS_TO_TICKS(100), raw_values);
            }

            const char* status_text = NULL;
            char status_buf[96];

            if (!online) {
                status_text = "Modulo non rilevato sul bus I2C.";
            } else if (read_err != ESP_OK) {
                snprintf(status_buf, sizeof(status_buf), "Errore lettura canali: %s", esp_err_to_name(read_err));
                status_text = status_buf;
                cJSON_AddStringToObject(device, "error_code", esp_err_to_name(read_err));
                cJSON_AddNumberToObject(device, "error_value", (double)read_err);
            } else {
                status_text = "Campionamento completato.";
            }

            if (status_text) {
                cJSON_AddStringToObject(device, "status", status_text);
            }

            ads1115_device_info_t info;
            if (online && ads1115_get_info((size_t)detected_index, &info) == ESP_OK) {
                cJSON_AddNumberToObject(device, "last_config_word", (double)info.last_config_word);
            }

            for (int ch = 0; ch < ADS1115_CHANNEL_COUNT; ++ch) {
                cJSON* ch_obj = cJSON_CreateObject();
                if (!ch_obj) {
                    continue;
                }
                cJSON_AddNumberToObject(ch_obj, "index", (double)ch);
                if (online && read_err == ESP_OK) {
                    cJSON_AddNumberToObject(ch_obj, "raw", (double)raw_values[ch]);
                    double volts = (double)ads1115_raw_to_voltage(raw_values[ch], cfg.options.gain);
                    cJSON_AddNumberToObject(ch_obj, "voltage", volts);
                } else {
                    cJSON_AddNullToObject(ch_obj, "raw");
                    cJSON_AddNullToObject(ch_obj, "voltage");
                }
                cJSON_AddItemToArray(channels, ch_obj);
            }

            if (cJSON_GetArraySize(channels) == 0) {
                for (int ch = 0; ch < ADS1115_CHANNEL_COUNT; ++ch) {
                    cJSON* ch_obj = cJSON_CreateObject();
                    if (!ch_obj) {
                        continue;
                    }
                    cJSON_AddNumberToObject(ch_obj, "index", (double)ch);
                    cJSON_AddNullToObject(ch_obj, "raw");
                    cJSON_AddNullToObject(ch_obj, "voltage");
                    cJSON_AddItemToArray(channels, ch_obj);
                }
            }

            cJSON_AddItemToObject(device, "channels", channels);
        } else {
            cJSON_AddItemToObject(device, "channels", cJSON_CreateArray());
        }
    }

    return json_reply_cjson(req, root);
}

static bool parse_ads_address_json(const cJSON* root, const char* key, uint8_t* out)
{
    const cJSON* item = cJSON_GetObjectItemCaseSensitive(root, key);
    if (!item || !out) return false;
    long value = -1;
    if (cJSON_IsString(item) && item->valuestring) {
        char* end = NULL;
        value = strtol(item->valuestring, &end, 0);
    } else if (cJSON_IsNumber(item)) {
        value = (long)item->valuedouble;
    }
    if (value < 0 || value > 0x7F || !ads1115_is_valid_address((uint8_t)value)) return false;
    *out = (uint8_t)value;
    return true;
}

static void ads_module_info_to_json(cJSON* arr, const input_ads1115_module_info_t* info)
{
    if (!arr || !info) return;
    cJSON* item = cJSON_CreateObject();
    if (!item) return;
    cJSON_AddItemToArray(arr, item);
    cJSON_AddStringToObject(item, "id", info->id);
    cJSON_AddStringToObject(item, "label", info->label);
    cJSON_AddStringToObject(item, "role", info->role);
    cJSON_AddNumberToObject(item, "i2c_address", info->i2c_address);
    char addr_hex[8]; snprintf(addr_hex, sizeof(addr_hex), "0x%02X", info->i2c_address);
    cJSON_AddStringToObject(item, "address_hex", addr_hex);
    cJSON_AddBoolToObject(item, "configured", info->configured);
    cJSON_AddBoolToObject(item, "enabled", info->enabled);
    cJSON_AddBoolToObject(item, "detected", info->detected);
    cJSON_AddBoolToObject(item, "online", info->online);
    cJSON_AddNumberToObject(item, "last_seen", (double)info->last_seen_ms);
    cJSON_AddNumberToObject(item, "last_scan", (double)info->last_scan_ms);
    cJSON_AddStringToObject(item, "last_error", info->last_error);
    cJSON_AddNumberToObject(item, "consecutive_failures", (double)info->consecutive_failures);
    cJSON* zones = cJSON_AddArrayToObject(item, "zones");
    for (uint8_t i = 0; zones && i < info->zone_count; ++i) cJSON_AddItemToArray(zones, cJSON_CreateNumber(info->zones[i]));
    cJSON_AddNumberToObject(item, "zone_count", (double)info->zone_count);
}

static esp_err_t api_admin_ads1115_get(httpd_req_t* req)
{
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    cJSON* root = cJSON_CreateObject();
    if (!root) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom"), ESP_FAIL;
    input_ads1115_summary_t sum;
    inputs_ads1115_get_summary(&sum);
    cJSON_AddNumberToObject(root, "configured", (double)sum.configured_count);
    cJSON_AddNumberToObject(root, "enabled", (double)sum.enabled_count);
    cJSON_AddNumberToObject(root, "detected", (double)sum.detected_count);
    cJSON_AddNumberToObject(root, "offline", (double)sum.offline_count);
    cJSON_AddNumberToObject(root, "last_scan", (double)sum.last_scan_ms);
    cJSON_AddStringToObject(root, "bus_status", sum.bus_status);
    cJSON_AddStringToObject(root, "last_error", sum.last_error);
    cJSON* modules = cJSON_AddArrayToObject(root, "modules");
    for (size_t i = 0; modules && i < inputs_ads1115_expected_devices(); ++i) {
        input_ads1115_module_info_t info;
        if (inputs_ads1115_get_module_info(i, &info) == ESP_OK) ads_module_info_to_json(modules, &info);
    }
    cJSON* unconfigured = cJSON_AddArrayToObject(root, "detected_unconfigured");
    for (uint8_t addr = 0x48; unconfigured && addr <= 0x4B; ++addr) {
        bool configured = false;
        for (size_t i = 0; i < inputs_ads1115_expected_devices(); ++i) {
            input_ads1115_module_info_t info;
            if (inputs_ads1115_get_module_info(i, &info) == ESP_OK && info.i2c_address == addr) configured = true;
        }
        if (!configured && ads1115_probe_address(addr, pdMS_TO_TICKS(25)) == ESP_OK) {
            char buf[8]; snprintf(buf, sizeof(buf), "0x%02X", addr);
            cJSON_AddItemToArray(unconfigured, cJSON_CreateString(buf));
        }
    }
    return json_reply_cjson(req, root);
}

static esp_err_t api_admin_ads1115_scan_post(httpd_req_t* req)
{
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    esp_err_t err = inputs_ads1115_scan();
    if (err != ESP_OK) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, esp_err_to_name(err)), ESP_FAIL;
    return api_admin_ads1115_get(req);
}

static esp_err_t api_admin_ads1115_post(httpd_req_t* req)
{
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    char body[512]; size_t bl=0;
    if (read_body_to_buf(req, body, sizeof(body), &bl)!=ESP_OK) return httpd_resp_send_err(req,400,"body"), ESP_FAIL;
    cJSON* j = cJSON_ParseWithLength(body, bl);
    if (!j) return httpd_resp_send_err(req,400,"json"), ESP_FAIL;
    uint8_t address = 0;
    bool ok = parse_ads_address_json(j, "address", &address) || parse_ads_address_json(j, "i2c_address", &address);
    const cJSON* jl = cJSON_GetObjectItemCaseSensitive(j, "label");
    const cJSON* je = cJSON_GetObjectItemCaseSensitive(j, "enabled");
    bool enabled = !cJSON_IsBool(je) || cJSON_IsTrue(je);
    bool detected = false;
    esp_err_t err = ok ? inputs_ads1115_add_module(address, cJSON_IsString(jl) ? jl->valuestring : NULL, enabled, &detected) : ESP_ERR_INVALID_ARG;
    cJSON_Delete(j);
    if (err != ESP_OK) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, esp_err_to_name(err)), ESP_FAIL;
    cJSON* root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "ok", true);
    cJSON_AddBoolToObject(root, "detected", detected);
    cJSON_AddStringToObject(root, "warning", detected ? "" : "Modulo salvato come previsto ma offline");
    return json_reply_cjson(req, root);
}

static bool parse_ads_id_action(const char* uri, char* id, size_t id_len, const char** action)
{
    const char* base = "/api/admin/ads1115/";
    size_t base_len = strlen(base);
    if (!uri || strncmp(uri, base, base_len) != 0) return false;
    const char* p = uri + base_len;
    const char* slash = strchr(p, '/');
    const char* query = strchr(p, '?');
    const char* end = slash ? slash : (query ? query : p + strlen(p));
    size_t n = (size_t)(end - p);
    if (n == 0 || n >= id_len) return false;
    memcpy(id, p, n); id[n] = '\0';
    *action = slash ? slash + 1 : "";
    return true;
}

static esp_err_t api_admin_ads1115_action_post(httpd_req_t* req)
{
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    char id[16]; const char* action = NULL;
    if (!parse_ads_id_action(req->uri, id, sizeof(id), &action)) return httpd_resp_send_err(req,400,"uri"), ESP_FAIL;
    char body[512]; size_t bl=0;
    cJSON* j = NULL;
    if (req->content_len > 0 && read_body_to_buf(req, body, sizeof(body), &bl)==ESP_OK) j = cJSON_ParseWithLength(body, bl);
    esp_err_t err = ESP_ERR_INVALID_ARG;
    bool detected = false;
    if (strcmp(action, "disable") == 0) err = inputs_ads1115_set_enabled(id, false);
    else if (strcmp(action, "enable") == 0) err = inputs_ads1115_set_enabled(id, true);
    else if (strcmp(action, "reset-errors") == 0) err = inputs_ads1115_reset_errors(id);
    else if (strcmp(action, "replace") == 0 && j) {
        uint8_t addr = 0;
        const cJSON* jl = cJSON_GetObjectItemCaseSensitive(j, "label");
        if (parse_ads_address_json(j, "new_address", &addr)) err = inputs_ads1115_replace_module(id, addr, cJSON_IsString(jl) ? jl->valuestring : NULL, &detected);
    } else if (strcmp(action, "test-read") == 0) {
        int16_t raw[ADS1115_CHANNEL_COUNT] = {0};
        err = inputs_ads1115_test_read(id, raw);
        if (err == ESP_OK) {
            cJSON* root = cJSON_CreateObject();
            cJSON_AddBoolToObject(root, "ok", true);
            cJSON* arr = cJSON_AddArrayToObject(root, "raw");
            for (int i = 0; arr && i < ADS1115_CHANNEL_COUNT; ++i) cJSON_AddItemToArray(arr, cJSON_CreateNumber(raw[i]));
            if (j) cJSON_Delete(j);
            return json_reply_cjson(req, root);
        }
    }
    if (j) cJSON_Delete(j);
    if (err != ESP_OK) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, esp_err_to_name(err)), ESP_FAIL;
    cJSON* root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "ok", true);
    if (strcmp(action, "replace") == 0) cJSON_AddBoolToObject(root, "detected", detected);
    return json_reply_cjson(req, root);
}

static esp_err_t api_admin_ads1115_delete(httpd_req_t* req)
{
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    char id[16]; const char* action = NULL;
    if (!parse_ads_id_action(req->uri, id, sizeof(id), &action)) return httpd_resp_send_err(req,400,"uri"), ESP_FAIL;
    bool force = strstr(req->uri, "force=true") != NULL;
    char query[64];
    if (!force && httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        char value[8];
        force = httpd_query_key_value(query, "force", value, sizeof(value)) == ESP_OK && strcmp(value, "true") == 0;
    }
    esp_err_t err = inputs_ads1115_delete_module(id, force);
    if (err != ESP_OK) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, esp_err_to_name(err)), ESP_FAIL;
    return json_reply(req, "{\"ok\":true}");
}


static esp_err_t api_admin_analog_eol_get(httpd_req_t* req)
{
    if (!check_bearer(req) || !is_admin_user(req)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden");
        return ESP_FAIL;
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        return ESP_ERR_NO_MEM;
    }

    size_t analog_count = inputs_analog_zone_count();
    size_t expected = inputs_ads1115_expected_devices();
    size_t detected = inputs_ads1115_count();

    cJSON_AddBoolToObject(root, "enabled", analog_count > 0 && expected > 0);
    cJSON_AddNumberToObject(root, "expected_devices", (double)expected);
    cJSON_AddNumberToObject(root, "detected_devices", (double)detected);
    cJSON_AddNumberToObject(root, "zones_offset", (double)INPUT_ZONES_COUNT);
    cJSON_AddNumberToObject(root, "analog_count", (double)((expected > 0) ? analog_count : 0));
    if (expected == 0) {
        cJSON_AddStringToObject(root, "message", "Nessun modulo ADS1115 configurato");
        cJSON_AddStringToObject(root, "analog_message", "Nessuna zona analogica attiva");
    }

    input_analog_zone_config_t cfg = {0};
    bool have_cfg = false;
    if (analog_count > 0 && expected > 0) {
        esp_err_t cfg_err = inputs_analog_get_zone_config(0, &cfg);
        if (cfg_err == ESP_OK) {
            have_cfg = true;
        } else {
            ESP_LOGW(TAG, "analog-eol get: config globale non disponibile (%s)",
                     esp_err_to_name(cfg_err));
        }
    }

    cJSON *config_obj = cJSON_CreateObject();
    if (!config_obj) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        return ESP_ERR_NO_MEM;
    }
    cJSON_AddItemToObject(root, "config", config_obj);
    if (have_cfg) {
        cJSON_AddNumberToObject(config_obj, "mode", (double)cfg.mode);
        cJSON_AddNumberToObject(config_obj, "normal_min", cfg.normal_min);
        cJSON_AddNumberToObject(config_obj, "normal_max", cfg.normal_max);
        cJSON_AddNumberToObject(config_obj, "alarm_min", cfg.alarm_min);
        cJSON_AddNumberToObject(config_obj, "alarm_max", cfg.alarm_max);
        cJSON_AddNumberToObject(config_obj, "tamper_low", cfg.tamper_low);
        cJSON_AddNumberToObject(config_obj, "tamper_high", cfg.tamper_high);
    }

    cJSON *zones = cJSON_CreateArray();
    if (!zones) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        return ESP_ERR_NO_MEM;
    }
    cJSON_AddItemToObject(root, "zones", zones);

    if (expected == 0) {
        analog_count = 0;
    }

    for (size_t idx = 0; idx < analog_count; ++idx) {
        cJSON *item = cJSON_CreateObject();
        if (!item) {
            continue;
        }
        cJSON_AddItemToArray(zones, item);

        size_t dev = idx / ADS1115_CHANNEL_COUNT;
        int channel = (int)(idx % ADS1115_CHANNEL_COUNT);
        size_t zone_index = INPUT_ZONES_COUNT + idx;

        cJSON_AddNumberToObject(item, "index", (double)idx);
        cJSON_AddNumberToObject(item, "zone_id", (double)(zone_index + 1));
        cJSON_AddNumberToObject(item, "device_slot", (double)dev);
        cJSON_AddNumberToObject(item, "channel", (double)(channel + 1));

        if (have_cfg) {
            cJSON_AddNumberToObject(item, "mode", (double)cfg.mode);
        }

        ads1115_device_config_t expected_cfg;
        esp_err_t expected_err = inputs_ads1115_get_expected_config(dev, &expected_cfg);
        if (expected_err == ESP_OK) {
            cJSON_AddNumberToObject(item, "address", (double)expected_cfg.address);
            char addr_hex[8];
            snprintf(addr_hex, sizeof(addr_hex), "0x%02X", expected_cfg.address);
            cJSON_AddStringToObject(item, "address_hex", addr_hex);
            int detected_index = inputs_ads1115_detected_index_for_address(expected_cfg.address);
            cJSON_AddNumberToObject(item, "detected_index", (double)detected_index);
        } else {
            ESP_LOGW(TAG, "analog-eol get: config attesa ADS%u non disponibile (%s)",
                     (unsigned)(dev + 1u), esp_err_to_name(expected_err));
        }

        input_analog_zone_state_t state;
        esp_err_t eval_err = inputs_analog_evaluate(idx, pdMS_TO_TICKS(75), &state);
        bool sample_ok = (eval_err == ESP_OK) && state.sample_valid;
        cJSON_AddBoolToObject(item, "device_present", state.device_present);
        cJSON_AddBoolToObject(item, "sample_valid", sample_ok);
        cJSON_AddBoolToObject(item, "alarm_active", sample_ok && state.alarm);
        cJSON_AddBoolToObject(item, "tamper_active", sample_ok && state.tamper);
        if (sample_ok) {
            cJSON_AddNumberToObject(item, "voltage", state.voltage);
        } else {
            cJSON_AddNullToObject(item, "voltage");
            if (eval_err != ESP_OK && eval_err != ESP_ERR_INVALID_ARG) {
                cJSON_AddStringToObject(item, "last_error", esp_err_to_name(eval_err));
                ESP_LOGW(TAG, "analog-eol get: lettura zona %u fallita (%s)",
                         (unsigned)idx, esp_err_to_name(eval_err));
            }
        }

        zone_state_entry_t synthetic = {0};
        synthetic.analog = true;
        synthetic.board = (uint8_t)(ZONE_BOARD_ID_ADS1115_BASE + dev);
        synthetic.board_input = (uint8_t)channel;
        char label_buf[48];
        const char *label = zone_entry_display_name((int)zone_index, &synthetic, label_buf, sizeof(label_buf));
        cJSON_AddStringToObject(item, "name", label ? label : "");
    }

    cJSON *supply_obj = cJSON_CreateObject();
    if (supply_obj) {
        input_supply_state_t supply_state;
        esp_err_t supply_err = inputs_analog_supply_state(pdMS_TO_TICKS(75), &supply_state);
        bool available = (supply_err != ESP_ERR_NOT_SUPPORTED);
        cJSON_AddBoolToObject(supply_obj, "available", available);
        if (available) {
            cJSON_AddBoolToObject(supply_obj, "device_present", supply_state.device_present);
            cJSON_AddBoolToObject(supply_obj, "sample_valid", supply_state.sample_valid);
            if (supply_state.sample_valid) {
                cJSON_AddNumberToObject(supply_obj, "adc_voltage", supply_state.adc_voltage);
                cJSON_AddNumberToObject(supply_obj, "supply_voltage", supply_state.supply_voltage);
            } else {
                cJSON_AddNullToObject(supply_obj, "adc_voltage");
                cJSON_AddNullToObject(supply_obj, "supply_voltage");
                if (supply_err != ESP_OK && supply_err != ESP_ERR_INVALID_STATE) {
                    cJSON_AddStringToObject(supply_obj, "last_error", esp_err_to_name(supply_err));
                }
            }
        }
        cJSON_AddItemToObject(root, "supply", supply_obj);
    }

    return json_reply_cjson(req, root);
}

static esp_err_t api_admin_analog_eol_post(httpd_req_t* req)
{
    if (!check_bearer(req) || !is_admin_user(req)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden");
        return ESP_FAIL;
    }

    char *body = NULL;
    size_t blen = 0;
    esp_err_t read_err = read_body_to_str(req, &body, &blen);
    if (read_err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "body");
        return ESP_FAIL;
    }

    cJSON *json = cJSON_ParseWithLength(body, blen);
    free(body);
    if (!json) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "json");
        return ESP_FAIL;
    }

    cJSON *config = cJSON_GetObjectItemCaseSensitive(json, "config");
    if (!cJSON_IsObject(config)) {
        cJSON_Delete(json);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "config");
        return ESP_FAIL;
    }

    if (inputs_analog_zone_count() == 0) {
        cJSON_Delete(json);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "analog");
        return ESP_FAIL;
    }

    input_analog_zone_config_t cfg;
    esp_err_t cfg_err = inputs_analog_get_zone_config(0, &cfg);
    if (cfg_err != ESP_OK) {
        cJSON_Delete(json);
        ESP_LOGE(TAG, "analog-eol post: impossibile recuperare la configurazione attuale (%s)",
                 esp_err_to_name(cfg_err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "state");
        return ESP_FAIL;
    }

    cJSON *jmode = cJSON_GetObjectItemCaseSensitive(config, "mode");
    cJSON *jnormal_min = cJSON_GetObjectItemCaseSensitive(config, "normal_min");
    cJSON *jnormal_max = cJSON_GetObjectItemCaseSensitive(config, "normal_max");
    cJSON *jalarm_min = cJSON_GetObjectItemCaseSensitive(config, "alarm_min");
    cJSON *jalarm_max = cJSON_GetObjectItemCaseSensitive(config, "alarm_max");
    cJSON *jtamper_low = cJSON_GetObjectItemCaseSensitive(config, "tamper_low");
    cJSON *jtamper_high = cJSON_GetObjectItemCaseSensitive(config, "tamper_high");

    if (cJSON_IsNumber(jmode)) cfg.mode = (input_analog_eol_mode_t)jmode->valueint;
    if (cJSON_IsNumber(jnormal_min)) cfg.normal_min = (float)jnormal_min->valuedouble;
    if (cJSON_IsNumber(jnormal_max)) cfg.normal_max = (float)jnormal_max->valuedouble;
    if (cJSON_IsNumber(jalarm_min)) cfg.alarm_min = (float)jalarm_min->valuedouble;
    if (cJSON_IsNumber(jalarm_max)) cfg.alarm_max = (float)jalarm_max->valuedouble;
    if (cJSON_IsNumber(jtamper_low)) cfg.tamper_low = (float)jtamper_low->valuedouble;
    if (cJSON_IsNumber(jtamper_high)) cfg.tamper_high = (float)jtamper_high->valuedouble;

    cJSON_Delete(json);

    esp_err_t set_err = inputs_analog_set_zone_config(0, &cfg, true);
    if (set_err != ESP_OK) {
        ESP_LOGE(TAG, "analog-eol post: salvataggio configurazione fallito (%s)",
                 esp_err_to_name(set_err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "persist");
        return ESP_FAIL;
        }

    return json_bool(req, true);
}

#else
static esp_err_t api_admin_ads1115_diag_get(httpd_req_t* req)
{
    if (!check_bearer(req) || !is_admin_user(req)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden");
        return ESP_FAIL;
    }
    cJSON* root = cJSON_CreateObject();
    if (!root) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        return ESP_ERR_NO_MEM;
    }
    cJSON_AddBoolToObject(root, "enabled", false);
    cJSON_AddBoolToObject(root, "all_online", false);
    cJSON_AddNumberToObject(root, "expected", 0);
    cJSON_AddNumberToObject(root, "detected", 0);
    cJSON_AddNumberToObject(root, "channel_count", 0);
    cJSON_AddNumberToObject(root, "timestamp_ms", 0);
    cJSON_AddItemToObject(root, "devices", cJSON_CreateArray());
    return json_reply_cjson(req, root);
}

static esp_err_t api_admin_analog_eol_get(httpd_req_t* req)
{
    if (!check_bearer(req) || !is_admin_user(req)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden");
        return ESP_FAIL;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        return ESP_ERR_NO_MEM;
    }
    cJSON_AddBoolToObject(root, "enabled", false);
    cJSON_AddNumberToObject(root, "expected_devices", 0);
    cJSON_AddNumberToObject(root, "detected_devices", 0);
    cJSON_AddNumberToObject(root, "zones_offset", (double)INPUT_ZONES_COUNT);
    cJSON_AddNumberToObject(root, "analog_count", 0);
    cJSON_AddItemToObject(root, "zones", cJSON_CreateArray());
    return json_reply_cjson(req, root);
}

static esp_err_t api_admin_analog_eol_post(httpd_req_t* req)
{
    if (!check_bearer(req) || !is_admin_user(req)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden");
        return ESP_FAIL;
    }
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "analog disabled");
    return ESP_FAIL;
}
#endif


static esp_err_t api_admin_filters_get(httpd_req_t* req)
{
    if (!check_bearer(req) || !is_admin_user(req)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden");
        return ESP_FAIL;
    }
    input_digital_filter_config_t cfg = inputs_digital_filters_get_config();
    cJSON *root = cJSON_CreateObject();
    cJSON *filters = cJSON_CreateObject();
    if (!root || !filters) {
        if (root) cJSON_Delete(root);
        if (filters) cJSON_Delete(filters);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        return ESP_ERR_NO_MEM;
    }
    cJSON_AddItemToObject(root, "debounce_filters", filters);
    cJSON_AddNumberToObject(filters, "fast_ms", (double)cfg.fast_ms);
    cJSON_AddNumberToObject(filters, "standard_ms", (double)cfg.standard_ms);
    cJSON_AddNumberToObject(filters, "protected_ms", (double)cfg.protected_ms);
    return json_reply_cjson(req, root);
}

static bool json_positive_u32(cJSON *obj, const char *name, uint32_t *out)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, name);
    if (!cJSON_IsNumber(item) || item->valuedouble <= 0 || item->valuedouble > 1000 ||
        item->valuedouble != (double)((uint32_t)item->valuedouble)) {
        return false;
    }
    *out = (uint32_t)item->valuedouble;
    return true;
}

static esp_err_t api_admin_filters_post(httpd_req_t* req)
{
    if (!check_bearer(req) || !is_admin_user(req)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden");
        return ESP_FAIL;
    }
    char body[512];
    size_t blen = 0;
    if (read_body_to_buf(req, body, sizeof(body), &blen) != ESP_OK) {
        httpd_resp_send_err(req, 400, "body");
        return ESP_FAIL;
    }
    cJSON *json = cJSON_ParseWithLength(body, blen);
    if (!json) {
        httpd_resp_send_err(req, 400, "json");
        return ESP_FAIL;
    }
    cJSON *filters = cJSON_GetObjectItemCaseSensitive(json, "debounce_filters");
    if (!cJSON_IsObject(filters)) {
        filters = json;
    }

    input_digital_filter_config_t cfg = {0};
    if (!json_positive_u32(filters, "fast_ms", &cfg.fast_ms) ||
        !json_positive_u32(filters, "standard_ms", &cfg.standard_ms) ||
        !json_positive_u32(filters, "protected_ms", &cfg.protected_ms)) {
        cJSON_Delete(json);
        httpd_resp_send_err(req, 400, "numeric range 1..1000 required");
        return ESP_FAIL;
    }
    if (cfg.fast_ms < 10u || cfg.standard_ms < 20u || cfg.protected_ms < 50u) {
        cJSON_Delete(json);
        httpd_resp_send_err(req, 400, "minimums: fast 10, standard 20, protected 50");
        return ESP_FAIL;
    }
    if (!(cfg.fast_ms <= cfg.standard_ms && cfg.standard_ms <= cfg.protected_ms)) {
        cJSON_Delete(json);
        httpd_resp_send_err(req, 400, "fast <= standard <= protected required");
        return ESP_FAIL;
    }
    esp_err_t err = inputs_digital_filters_set_config(&cfg, true);
    cJSON_Delete(json);
    if (err != ESP_OK) {
        httpd_resp_send_err(req, 500, "nvs");
        return ESP_FAIL;
    }
    return json_bool(req, true);
}

static esp_err_t zones_get(httpd_req_t* req){
    if(!check_bearer(req)) { httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"); return ESP_FAIL; }
    zones_snapshot_t snapshot;
    zones_snapshot_build(&snapshot);
    const int total = zones_snapshot_total(&snapshot);

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        return ESP_ERR_NO_MEM;
    }

    cJSON *arr  = cJSON_CreateArray();
    if (!root) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        return ESP_ERR_NO_MEM;
    }

    cJSON_AddItemToObject(root, "zones", arr);
    cJSON_AddNumberToObject(root, "total", total);

    for(int idx = 0; idx < total; ++idx){
        const int zone_id = idx + 1;
        const zone_state_entry_t *entry = &snapshot.entries[idx];
        cJSON *it = cJSON_CreateObject();
        if (!it) {
            continue;
        }
        char name_buf[48];
        const char *zname = zone_entry_display_name(idx, entry, name_buf, sizeof(name_buf));
        cJSON_AddNumberToObject(it, "id", zone_id);
        cJSON_AddStringToObject(it, "name", zname ? zname : "");
        cJSON_AddBoolToObject(it, "known", entry->known);
        cJSON_AddBoolToObject(it, "active", entry->known ? entry->active : false);
        cJSON_AddBoolToObject(it, "board_online", entry->board_online);
        cJSON_AddNumberToObject(it, "board", (double)entry->board);
        cJSON_AddNumberToObject(it, "board_input", (double)(entry->board_input + 1u));
        cJSON_AddBoolToObject(it, "analog", entry->analog);
        zone_add_filter_fields(it, idx, entry);
        cJSON_AddBoolToObject(it, "tamper", entry->known ? entry->tamper : false);
        cJSON_AddBoolToObject(it, "fault", entry->known ? false : true);
        input_zone_filtered_state_t diag = {0};
        if (inputs_get_filtered_zone_state((uint16_t)idx, &diag)) {
            cJSON_AddBoolToObject(it, "debouncing", diag.debouncing);
            cJSON_AddBoolToObject(it, "unavailable", diag.unavailable);
            cJSON_AddNumberToObject(it, "bounce_count", (double)diag.bounce_count);
            cJSON_AddNumberToObject(it, "last_raw_change_ms", (double)diag.last_raw_change_ms);
            cJSON_AddNumberToObject(it, "last_stable_change_ms", (double)diag.last_stable_change_ms);
            if (entry->analog) {
                cJSON_AddNumberToObject(it, "discarded_samples", (double)diag.discarded_samples);
            }
        }
#if ADS1115_COUNT > 0
        if (entry->analog) {
            cJSON_AddBoolToObject(it, "analog_device_present", entry->analog_device_present);
            cJSON_AddBoolToObject(it, "analog_sample_valid", entry->analog_sample_valid);
            cJSON_AddNumberToObject(it, "analog_mode", (double)entry->analog_mode);
            cJSON_AddBoolToObject(it, "supports_tamper", entry->analog_mode >= INPUT_ANALOG_EOL_2);
            cJSON_AddBoolToObject(it, "tamper_capable", entry->analog_mode >= INPUT_ANALOG_EOL_2);
            if (entry->known) {
                cJSON_AddNumberToObject(it, "analog_value", entry->analog_value);
            }
        } else {
            cJSON_AddBoolToObject(it, "supports_tamper", false);
            cJSON_AddBoolToObject(it, "tamper_capable", false);
        }
#else
        if (entry->analog && entry->known) {
            cJSON_AddNumberToObject(it, "analog_value", entry->analog_value);
        }
        cJSON_AddBoolToObject(it, "supports_tamper", false);
        cJSON_AddBoolToObject(it, "tamper_capable", false);
#endif
        char board_label[sizeof(((roster_node_t *)0)->label)];
        zone_board_label_copy(entry->board, board_label, sizeof(board_label));
        cJSON_AddStringToObject(it, "board_label", board_label);
        zone_cfg_t *cfg = &s_zone_cfg[idx];
        if (cfg) {
            cJSON_AddBoolToObject(it, "auto_exclude", cfg->auto_exclude);
            cJSON_AddBoolToObject(it, "zone_delay", cfg->zone_delay);
            cJSON_AddNumberToObject(it, "zone_time", (double)cfg->zone_time);
        } else {
            cJSON_AddBoolToObject(it, "auto_exclude", false);
            cJSON_AddBoolToObject(it, "zone_delay", false);
            cJSON_AddNumberToObject(it, "zone_time", 0);
        }
        cJSON_AddItemToArray(arr, it);
    }
    char *out = cJSON_PrintUnformatted(root);
    esp_err_t e = json_reply(req, out);
    cJSON_free(out);
    cJSON_Delete(root);
    return e;
}

static void zones_valid_mask(zone_mask_t *out_mask, uint16_t zone_limit)
{
    if (!out_mask) {
        return;
    }
    // Nel modello attuale le zone armabili sono quelle comprese nel totale
    // effettivo calcolato da roster/input locali. I riferimenti oltre questo
    // limite sono considerati eliminati/orfani/non configurati.
    zone_mask_fill(out_mask, zone_limit);
}

static bool scenes_filter_mask_to_valid(zone_mask_t *mask, uint16_t zone_limit, const char *label)
{
    static bool warned_once = false;
    if (!mask) {
        return false;
    }
    zone_mask_t before;
    zone_mask_copy(&before, mask);
    zone_mask_t valid;
    zones_valid_mask(&valid, zone_limit);
    zone_mask_and(mask, mask, &valid);
    zone_mask_limit(mask, zone_limit);
    bool changed = !zone_mask_equal(&before, mask);
    if (changed && label && !warned_once) {
        ESP_LOGW(TAG, "Scenario %s: rimossi riferimenti a zone non valide/orfane (limite=%u)", label, (unsigned)zone_limit);
        warned_once = true;
    }
    return changed;
}

static esp_err_t scenes_get(httpd_req_t* req){
    if(!check_bearer(req)) { httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"); return ESP_FAIL; }
    zone_mask_t h, n, c, a;
    scenes_get_mask(SCENE_HOME,  &h);
    scenes_get_mask(SCENE_NIGHT, &n);
    scenes_get_mask(SCENE_CUSTOM,&c);
    scenes_get_active_mask(&a);

    int zones_total = zones_effective_total();
    if (zones_total > SCENES_MAX_ZONES) {
        zones_total = SCENES_MAX_ZONES;
    }

    int ids[SCENES_MAX_ZONES];

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        return ESP_ERR_NO_MEM;
    }

    scenes_filter_mask_to_valid(&h, (uint16_t)zones_total, "home");
    scenes_filter_mask_to_valid(&n, (uint16_t)zones_total, "night");
    scenes_filter_mask_to_valid(&c, (uint16_t)zones_total, "custom");
    scenes_filter_mask_to_valid(&a, (uint16_t)zones_total, "active");

    char home_hex[ZONE_MASK_WORDS * 8u + 1u];
    char night_hex[ZONE_MASK_WORDS * 8u + 1u];
    char custom_hex[ZONE_MASK_WORDS * 8u + 1u];
    char active_hex[ZONE_MASK_WORDS * 8u + 1u];
    zone_mask_to_hex(&h, (uint16_t)zones_total, home_hex, sizeof(home_hex));
    zone_mask_to_hex(&n, (uint16_t)zones_total, night_hex, sizeof(night_hex));
    zone_mask_to_hex(&c, (uint16_t)zones_total, custom_hex, sizeof(custom_hex));
    zone_mask_to_hex(&a, (uint16_t)zones_total, active_hex, sizeof(active_hex));

    cJSON_AddNumberToObject(root, "zones", zones_total);
    cJSON_AddNumberToObject(root, "home",   (double)zone_mask_to_u32(&h));
    cJSON_AddNumberToObject(root, "night",  (double)zone_mask_to_u32(&n));
    cJSON_AddNumberToObject(root, "custom", (double)zone_mask_to_u32(&c));
    cJSON_AddNumberToObject(root, "active", (double)zone_mask_to_u32(&a));
    cJSON_AddStringToObject(root, "home_hex", home_hex);
    cJSON_AddStringToObject(root, "night_hex", night_hex);
    cJSON_AddStringToObject(root, "custom_hex", custom_hex);
    cJSON_AddStringToObject(root, "active_hex", active_hex);

    cJSON *home_ids = cJSON_CreateArray();
    cJSON *night_ids = cJSON_CreateArray();
    cJSON *custom_ids = cJSON_CreateArray();
    if (!home_ids || !night_ids || !custom_ids) {
        if (home_ids) cJSON_Delete(home_ids);
        if (night_ids) cJSON_Delete(night_ids);
        if (custom_ids) cJSON_Delete(custom_ids);
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        return ESP_ERR_NO_MEM;
    }

    int cnt = scenes_mask_to_ids(&h, ids, zones_total, (uint16_t)zones_total);
    for (int i = 0; i < cnt; ++i) cJSON_AddItemToArray(home_ids, cJSON_CreateNumber(ids[i]));
    cnt = scenes_mask_to_ids(&n, ids, zones_total, (uint16_t)zones_total);
    for (int i = 0; i < cnt; ++i) cJSON_AddItemToArray(night_ids, cJSON_CreateNumber(ids[i]));
    cnt = scenes_mask_to_ids(&c, ids, zones_total, (uint16_t)zones_total);
    for (int i = 0; i < cnt; ++i) cJSON_AddItemToArray(custom_ids, cJSON_CreateNumber(ids[i]));

    cJSON_AddItemToObject(root, "home_ids", home_ids);
    cJSON_AddItemToObject(root, "night_ids", night_ids);
    cJSON_AddItemToObject(root, "custom_ids", custom_ids);

    char *out = cJSON_PrintUnformatted(root);
    esp_err_t res = json_reply(req, out);
    cJSON_free(out);
    cJSON_Delete(root);
    return res;
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

    int zones_total = zones_effective_total();
    if (zones_total > SCENES_MAX_ZONES) {
        zones_total = SCENES_MAX_ZONES;
    }

    // mask o ids[]
    zone_mask_t mask;
    zone_mask_clear(&mask);
    bool have_mask = false;

    const cJSON *jmask_hex = cJSON_GetObjectItemCaseSensitive(json, "mask_hex");
    if (cJSON_IsString(jmask_hex) && jmask_hex->valuestring) {
        have_mask = zone_mask_from_hex(&mask, jmask_hex->valuestring);
    }

    if (!have_mask) {
        const cJSON *jmask = cJSON_GetObjectItemCaseSensitive(json, "mask");
        if (cJSON_IsNumber(jmask)) {
            zone_mask_from_u32(&mask, (uint32_t)((jmask->valuedouble < 0) ? 0 : jmask->valuedouble));
            have_mask = true;
        }
    }

    if (!have_mask) {
        const cJSON *ids = cJSON_GetObjectItemCaseSensitive(json, "ids");
        if (cJSON_IsArray(ids)){
            int tmp_ids[SCENES_MAX_ZONES];
            int count = 0;
            cJSON *it=NULL;
            cJSON_ArrayForEach(it, ids){
                if(cJSON_IsNumber(it) && count < SCENES_MAX_ZONES){
                    tmp_ids[count++] = it->valueint;
                }
            }
            scenes_ids_to_mask(tmp_ids, count, &mask);
            have_mask = true;
        }
    }

    if (!have_mask) {
        cJSON_Delete(json);
        httpd_resp_send_err(req, 400, "mask");
        return ESP_FAIL;
    }
    cJSON_Delete(json);

    scenes_filter_mask_to_valid(&mask, (uint16_t)zones_total, jscene->valuestring);

    if (scenes_set_mask(s, &mask)!=ESP_OK){
        httpd_resp_send_err(req, 500, "nvs");
        return ESP_FAIL;
    }
    return json_bool(req, true);
}

// GET /api/zones/config
static esp_err_t zones_config_get(httpd_req_t* req){
    if(!check_bearer(req)) return httpd_resp_send_err(req,401,"token"), ESP_FAIL;

    zones_snapshot_t snapshot;
    zones_snapshot_build(&snapshot);
    const int total = zones_snapshot_total(&snapshot);

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        return ESP_ERR_NO_MEM;
    }

    cJSON *items = cJSON_CreateArray();
    if (!items) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        return ESP_ERR_NO_MEM;
    }
    cJSON_AddItemToObject(root, "items", items);
    input_digital_filter_config_t filter_cfg = inputs_digital_filters_get_config();
    cJSON *filters = cJSON_CreateObject();
    if (filters) {
        cJSON_AddNumberToObject(filters, "fast_ms", (double)filter_cfg.fast_ms);
        cJSON_AddNumberToObject(filters, "standard_ms", (double)filter_cfg.standard_ms);
        cJSON_AddNumberToObject(filters, "protected_ms", (double)filter_cfg.protected_ms);
        cJSON_AddItemToObject(root, "debounce_filters", filters);
    }

    for (int idx = 0; idx < total; ++idx) {
        const int zone_id = idx + 1;
        zone_cfg_t *cfg = &s_zone_cfg[idx];
        const zone_state_entry_t *entry = &snapshot.entries[idx];
        cJSON *it = cJSON_CreateObject();
        if (!it) {
            continue;
        }
        cJSON_AddNumberToObject(it, "id", zone_id);
        cJSON_AddStringToObject(it, "name", cfg->name);
        cJSON_AddBoolToObject(it, "zone_delay", cfg->zone_delay);
        cJSON_AddNumberToObject(it, "zone_time", (double)cfg->zone_time);
        cJSON_AddBoolToObject(it, "auto_exclude", cfg->auto_exclude);
        cJSON_AddNumberToObject(it, "board", (double)(entry->board ? entry->board : zone_board_for_index(zone_id)));
        cJSON_AddNumberToObject(it, "board_input", (double)(entry->board_input + 1u));
        cJSON_AddBoolToObject(it, "board_online", entry->board_online);
        cJSON_AddBoolToObject(it, "analog", entry->analog);
        zone_add_filter_fields(it, idx, entry);
        cJSON_AddBoolToObject(it, "supports_tamper", entry->analog && entry->analog_mode >= INPUT_ANALOG_EOL_2);
        cJSON_AddBoolToObject(it, "is_global_tamper_input", false);
#if ADS1115_COUNT > 0
        if (entry->analog && entry->known) {
            cJSON_AddNumberToObject(it, "analog_value", entry->analog_value);
        }
#endif
        char board_label[sizeof(((roster_node_t *)0)->label)];
        zone_board_label_copy(entry->board ? entry->board : zone_board_for_index(zone_id),
                              board_label,
                              sizeof(board_label));
        cJSON_AddStringToObject(it, "board_label", board_label);
        cJSON_AddItemToArray(items, it);
    }

    char *out = cJSON_PrintUnformatted(root);
    esp_err_t res = json_reply(req, out);
    cJSON_free(out);
    cJSON_Delete(root);
    return res;
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
    zones_snapshot_t snapshot;
    zones_snapshot_build(&snapshot);
    const int snapshot_total = zones_snapshot_total(&snapshot);

    cJSON *it = NULL;
    cJSON_ArrayForEach(it, items){
        cJSON *jid = cJSON_GetObjectItemCaseSensitive(it, "id");
        if(!cJSON_IsNumber(jid)) continue;
        int id = jid->valueint;
        if(id<1 || id>ZONE_CONFIG_CAPACITY) continue;
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
        if(cJSON_IsNumber(jn)) {
            double raw_time = jn->valuedouble;
            if(raw_time < 0 || raw_time > 600) { cJSON_Delete(json); httpd_resp_send_err(req, 400, "zone_time"); return ESP_FAIL; }
            z_time = (uint16_t)raw_time;
        }

        // fallback legacy
        jn = cJSON_GetObjectItemCaseSensitive(it, "entry_delay");
        if(cJSON_IsBool(jn)) z_delay = cJSON_IsTrue(jn);
        jn = cJSON_GetObjectItemCaseSensitive(it, "exit_delay");
        if(cJSON_IsBool(jn)) z_delay = (z_delay || cJSON_IsTrue(jn));

        jn = cJSON_GetObjectItemCaseSensitive(it, "entry_time");
        if(cJSON_IsNumber(jn) && jn->valuedouble>0) {
            if(jn->valuedouble > 600) { cJSON_Delete(json); httpd_resp_send_err(req, 400, "entry_time"); return ESP_FAIL; }
            z_time = (uint16_t)jn->valuedouble;
        }
        jn = cJSON_GetObjectItemCaseSensitive(it, "exit_time");
        if(cJSON_IsNumber(jn) && jn->valuedouble>0) {
            if(jn->valuedouble > 600) { cJSON_Delete(json); httpd_resp_send_err(req, 400, "exit_time"); return ESP_FAIL; }
            z_time = (uint16_t)jn->valuedouble;
        }

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

        jn = cJSON_GetObjectItemCaseSensitive(it, "filter_profile");
        if (jn) {
            const int idx = id - 1;
            bool digital_normal = idx >= 0 && idx < snapshot_total &&
                                  zone_entry_is_local_digital_normal(idx, &snapshot.entries[idx]);
            if (!digital_normal) {
                cJSON_Delete(json);
                httpd_resp_send_err(req, 400, "filter_profile not allowed for this zone");
                return ESP_FAIL;
            }
            if (!cJSON_IsString(jn)) {
                cJSON_Delete(json);
                httpd_resp_send_err(req, 400, "filter_profile");
                return ESP_FAIL;
            }
            zone_filter_profile_t profile = ZONE_FILTER_STANDARD;
            if (!inputs_zone_filter_profile_from_name(jn->valuestring, &profile)) {
                cJSON_Delete(json);
                httpd_resp_send_err(req, 400, "filter_profile");
                return ESP_FAIL;
            }
            if (inputs_zone_filter_set((uint16_t)idx, profile, false) != ESP_OK) {
                cJSON_Delete(json);
                httpd_resp_send_err(req, 400, "filter_profile");
                return ESP_FAIL;
            }
        }

        s_zone_board_map[id-1] = board;
    }
    cJSON_Delete(json);
    zones_save_to_nvs();
    inputs_digital_filters_save();
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
    set_http_security_headers(req);
    char buf[1024];
    size_t r;
    while((r=fread(buf,1,sizeof(buf),f))>0){
        if (httpd_resp_send_chunk(req, buf, r)!=ESP_OK){ fclose(f); httpd_resp_sendstr_chunk(req, NULL); return ESP_FAIL; }
    }
    fclose(f);
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

static esp_err_t root_get(httpd_req_t* req){
    if (!s_provisioned){
        return send_file(req, "wizard.html");
    }
    user_info_t user;
    if (!auth_check_cookie(req, &user)){
        return send_file(req, "login.html");
    }
    if (auth_session_is_setup_limited(req)){
        ESP_LOGI(TAG, "setup_limited root redirect target=/setup");
        return send_http_redirect(req, "/setup", "302 Found");
    }
    return send_file(req, "index.html");
}

static esp_err_t login_html_get(httpd_req_t* req){
    // If already logged, go to index
    user_info_t u;
    if (auth_check_cookie(req,&u)){
        return send_http_redirect(req, "/", "302 Found");
    }
    return send_file(req,"login.html");
}

static esp_err_t index_html_get(httpd_req_t* req){
    if (!s_provisioned){
        return send_file(req, "wizard.html");
    }
    user_info_t u;
    if (!auth_check_cookie(req,&u)){
        return send_http_redirect(req, "/login.html", "302 Found");
    }
    if (auth_session_is_setup_limited(req)){
        ESP_LOGI(TAG, "setup_limited root redirect target=/setup");
        return send_http_redirect(req, "/setup", "302 Found");
    }
    return send_file(req, "index.html");
}
static esp_err_t setup_html_get(httpd_req_t* req){
    user_info_t u;
    if (!auth_check_cookie(req, &u)) return send_http_redirect(req, "/login.html", "302 Found");
    bool setup_limited = auth_session_is_setup_limited(req);
    if (u.role == ROLE_ADMIN || setup_limited) {
        ESP_LOGI(TAG, "setup page allowed role=%d setup_limited=%s", (int)u.role, setup_limited ? "true" : "false");
        return send_file(req, "admin.html");
    }
    ESP_LOGW(TAG, "setup page denied role=%d", (int)u.role);
    return send_file(req,"403.html");
}
static esp_err_t wizard_html_get(httpd_req_t* req){
    return send_file(req, "wizard.html");
}
static esp_err_t admin_html_get(httpd_req_t* req){
    user_info_t u;
    if (!auth_check_cookie(req, &u)) return send_http_redirect(req, "/login.html", "302 Found");
    if (auth_session_is_setup_limited(req)) {
        ESP_LOGI(TAG, "setup_limited admin.html redirect target=/setup");
        return send_http_redirect(req, "/setup", "302 Found");
    }
    if (u.role != ROLE_ADMIN) {
        ESP_LOGW(TAG, "admin.html denied role=%d", (int)u.role);
        return send_file(req,"403.html");
    }
    return send_file(req,"admin.html");
}
static esp_err_t four03_html_get(httpd_req_t* req){
    if (auth_session_is_setup_limited(req)) {
        ESP_LOGI(TAG, "setup_limited 403 redirect target=/setup");
        return send_http_redirect(req, "/setup", "302 Found");
    }
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
    if (strstr(uri,"/js/api.js")) return send_file(req,"js/api.js");
    if (strstr(uri,"/js/login.js")) return send_file(req,"js/login.js");
    if (strstr(uri,"/js/app.js"))   return send_file(req,"js/app.js");
    return httpd_resp_send_err(req,HTTPD_404_NOT_FOUND,"nope");
}
static esp_err_t favicon_get(httpd_req_t* req){
    httpd_resp_set_status(req, "204 No Content");
    return httpd_resp_send(req, NULL, 0);
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
static esp_err_t logs_delete_post(httpd_req_t* req);
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
    { .uri = "/setup",            .method = HTTP_GET,     .handler = setup_html_get },
    { .uri = "/favicon.ico",      .method = HTTP_GET,     .handler = favicon_get },
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
    { .uri = "/api/admin/system", .method = HTTP_GET, .handler = api_admin_system_get },
    { .uri = "/api/admin/network", .method = HTTP_GET, .handler = api_admin_network_get },
    { .uri = "/api/admin/network", .method = HTTP_POST, .handler = api_admin_network_post },
    { .uri = "/api/admin/network/restart", .method = HTTP_POST, .handler = api_admin_network_restart_post },
    { .uri = "/api/admin/network/wifi/test", .method = HTTP_POST, .handler = api_admin_network_wifi_test_post },
    { .uri = "/api/admin/network/wifi/scan", .method = HTTP_GET, .handler = api_admin_network_wifi_scan_get },
    { .uri = "/api/admin/network/setup/exit", .method = HTTP_POST, .handler = api_admin_network_setup_exit_post },
    { .uri = "/api/setup/time", .method = HTTP_POST, .handler = api_setup_time_post },
    { .uri = "/api/network/status", .method = HTTP_GET, .handler = api_network_status_get },
    { .uri = "/api/network/config", .method = HTTP_POST, .handler = api_admin_network_post },
    { .uri = "/api/admin/mqtt", .method = HTTP_GET, .handler = sys_mqtt_get },
    { .uri = "/api/admin/mqtt", .method = HTTP_POST, .handler = sys_mqtt_post },
    { .uri = "/api/admin/mqtt/rediscover", .method = HTTP_POST, .handler = api_admin_mqtt_rediscover_post },
    { .uri = "/api/admin/notifications", .method = HTTP_GET, .handler = api_admin_notifications_get },
    { .uri = "/api/admin/notifications", .method = HTTP_POST, .handler = api_admin_notifications_post },
    { .uri = "/api/admin/notifications/test", .method = HTTP_POST, .handler = api_admin_notifications_test_post },
    { .uri = "/api/admin/filters", .method = HTTP_GET, .handler = api_admin_filters_get },
    { .uri = "/api/admin/filters", .method = HTTP_POST, .handler = api_admin_filters_post },
    { .uri = "/api/admin/ads1115", .method = HTTP_GET, .handler = api_admin_ads1115_get },
    { .uri = "/api/admin/ads1115", .method = HTTP_POST, .handler = api_admin_ads1115_post },
    { .uri = "/api/admin/ads1115/scan", .method = HTTP_POST, .handler = api_admin_ads1115_scan_post },
    { .uri = "/api/admin/ads1115/*", .method = HTTP_POST, .handler = api_admin_ads1115_action_post },
    { .uri = "/api/admin/ads1115/*", .method = HTTP_DELETE, .handler = api_admin_ads1115_delete },
    { .uri = "/api/admin/diagnostics/ads1115", .method = HTTP_GET, .handler = api_admin_ads1115_diag_get },
    { .uri = "/api/admin/security/recovery-codes/status", .method = HTTP_GET, .handler = api_recovery_status_get },
    { .uri = "/api/admin/security/recovery-codes/generate", .method = HTTP_POST, .handler = api_recovery_generate_post },
    { .uri = "/api/admin/security/recovery-codes/revoke", .method = HTTP_POST, .handler = api_recovery_revoke_post },
#if ADS1115_COUNT > 0
    { .uri = "/api/admin/inputs/analog-eol", .method = HTTP_GET,  .handler = api_admin_analog_eol_get },
    { .uri = "/api/admin/inputs/analog-eol", .method = HTTP_POST, .handler = api_admin_analog_eol_post },
#endif
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
    { .uri = "/api/can/node/*/outputs",   .method = HTTP_POST,    .handler = api_can_node_outputs_post },
    { .uri = "/api/can/node/*/outputs",   .method = HTTP_OPTIONS, .handler = api_can_node_outputs_options },
    { .uri = "/api/can/node/*/assign",    .method = HTTP_POST,    .handler = api_can_node_assign_post },
    { .uri = "/api/can/node/*/assign",    .method = HTTP_OPTIONS, .handler = api_can_node_assign_options },
    { .uri = "/api/can/node/*/label",     .method = HTTP_POST,    .handler = api_can_node_label_post },
    { .uri = "/api/can/node/*/label",     .method = HTTP_OPTIONS, .handler = api_can_node_label_options },
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
    { .uri = "/api/logs/delete",        .method = HTTP_POST, .handler = logs_delete_post },
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
    cfg.max_uri_handlers = 150;
    cfg.lru_purge_enable = true;
    cfg.server_port = 80;
    cfg.uri_match_fn = web_uri_match; //httpd_uri_match_wildcard;

    httpd_handle_t srv = NULL;
    esp_err_t tls_err = web_tls_prepare_material();
    if (tls_err != ESP_OK && tls_err != ESP_ERR_NOT_FOUND){
        ESP_LOGW(TAG, "TLS material unavailable (%s), avvio server HTTP senza TLS", esp_err_to_name(tls_err));
    }
    esp_err_t err = httpd_start(&srv, &cfg);
    if (err != ESP_OK){
        ESP_LOGE(TAG, "httpd_start failed: %s", esp_err_to_name(err));
        return err;
    }
    // s_server = srv;
    s_http_server = srv;
    ws_clients_reset();

    register_uri_set(srv, s_http_routes, sizeof(s_http_routes) / sizeof(s_http_routes[0]));

    ESP_LOGI(TAG, "Server HTTP avviato su porta %d", cfg.server_port);

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

    const char *ip_url = "<esp-ip>";
    char ip_str[IP4ADDR_STRLEN_MAX] = {0};
    esp_netif_t* netif = provisioning_get_primary_netif();
    if (netif){
        esp_netif_ip_info_t ip_info = {0};
        if (esp_netif_get_ip_info(netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0){
            ip4addr_ntoa_r((const ip4_addr_t*)&ip_info.ip, ip_str, sizeof(ip_str));
            if (ip_str[0] != '\0'){
                ip_url = ip_str;
            }
        }
    }
    ESP_LOGI(TAG, "Pronto. Apri http://%s", ip_url);
    return ESP_OK;
}

esp_err_t web_server_stop(void){
    esp_err_t first_err = ESP_OK;
    if (s_http_server){
        httpd_handle_t handle = s_http_server;
        s_http_server = NULL;
        ws_clients_reset();
        esp_err_t err = httpd_stop(handle);
        if (err != ESP_OK){
            ESP_LOGE(TAG, "httpd_stop failed: %s", esp_err_to_name(err));
            if (first_err == ESP_OK) first_err = err;
        }
    }
    return first_err;
}

static void web_restart_task(void* arg){
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(200));
    ESP_LOGI(TAG, "Riavvio del server HTTP in corso");
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
    const UBaseType_t stack_before = uxTaskGetStackHighWaterMark(NULL);
    const uint32_t heap_before = esp_get_free_heap_size();
    ESP_LOGI(TAG, "POST /api/arm heap=%" PRIu32 " stack_hwm=%u",
             heap_before, (unsigned)stack_before);

    if(!check_bearer(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"), ESP_FAIL;
    char user[32]={0};
    user_info_t info;
    if (!auth_check_bearer(req, &info)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"), ESP_FAIL;
    strncpy(user, info.username, sizeof(user)-1); user[sizeof(user)-1]=0;

    char body[256]; size_t blen = 0;
    if(read_body_to_buf(req, body, sizeof(body), &blen)!=ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "body"), ESP_FAIL;
    }
    cJSON* root = cJSON_ParseWithLength(body, blen);
    if(!root) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "json"), ESP_FAIL;

    char mode[16]={0}, pin[16]={0};
    const cJSON* jmode = cJSON_GetObjectItemCaseSensitive(root, "mode");
    const cJSON* jpin  = cJSON_GetObjectItemCaseSensitive(root, "pin");
    if (cJSON_IsString(jmode) && jmode->valuestring) strlcpy(mode, jmode->valuestring, sizeof(mode));
    if (cJSON_IsString(jpin)  && jpin->valuestring)  strlcpy(pin,  jpin->valuestring,  sizeof(pin));
    cJSON_Delete(root);

    if(!mode[0] || !pin[0]) {
        httpd_resp_set_status(req, "400 Bad Request");
        return json_reply(req, "{\"ok\":false,\"error\":\"missing_fields\",\"message\":\"mode e PIN richiesti\"}");
    }

    const bool pin_ok = auth_verify_pin(user, pin);
    ESP_LOGI(TAG, "POST /api/arm mode=%s pin_ok=%s heap=%" PRIu32 " stack_hwm=%u",
             mode, pin_ok ? "yes" : "no", esp_get_free_heap_size(),
             (unsigned)uxTaskGetStackHighWaterMark(NULL));
    if(!pin_ok) {
        httpd_resp_set_status(req, "403 Forbidden");
        return json_reply(req, "{\"ok\":false,\"error\":\"invalid_pin\",\"message\":\"PIN non valido\"}");
    }

    // 1) Determina stato target e maschera scena
    alarm_state_t target = ALARM_DISARMED;
    const char *mode_norm = NULL;
    int zones_total = zones_effective_total();
    if (zones_total < 0) {
        zones_total = 0;
    }
    if (zones_total > SCENES_MAX_ZONES) {
        zones_total = SCENES_MAX_ZONES;
    }

    zone_mask_t scene_mask;
    zone_mask_clear(&scene_mask);
    if      (strcasecmp(mode, "away")  == 0) { target = ALARM_ARMED_AWAY;   mode_norm = "away";   zones_valid_mask(&scene_mask, (uint16_t)zones_total); }
    else if (strcasecmp(mode, "home")  == 0) { target = ALARM_ARMED_HOME;   mode_norm = "home";   scenes_get_mask(SCENE_HOME,  &scene_mask); }
    else if (strcasecmp(mode, "night") == 0) { target = ALARM_ARMED_NIGHT;  mode_norm = "night";  scenes_get_mask(SCENE_NIGHT, &scene_mask); }
    else if (strcasecmp(mode, "custom")== 0) { target = ALARM_ARMED_CUSTOM; mode_norm = "custom"; scenes_get_mask(SCENE_CUSTOM,&scene_mask); }
    else {
        httpd_resp_set_status(req, "400 Bad Request");
        return json_reply(req, "{\"ok\":false,\"error\":\"invalid_mode\",\"message\":\"Modalità non valida\"}");
    }
    scenes_filter_mask_to_valid(&scene_mask, (uint16_t)zones_total, mode_norm);

    profile_t prof = alarm_get_profile(target);
    zone_mask_t eff_mask;
    zone_mask_copy(&eff_mask, &prof.active_mask);
    zone_mask_limit(&eff_mask, (uint16_t)zones_total);
    zone_mask_and(&eff_mask, &eff_mask, &scene_mask);
    const uint16_t included_zones = zone_mask_count_limited(&eff_mask, (uint16_t)zones_total);

    char eff_hex[ZONE_MASK_WORDS * 8u + 1u];
    zone_mask_to_hex(&eff_mask, (uint16_t)zones_total, eff_hex, sizeof(eff_hex));
    ESP_LOGI(TAG, "arm request mode=%s zones=%u mask=%s heap=%" PRIu32 " stack_hwm=%u",
             mode_norm, (unsigned)included_zones, eff_hex, esp_get_free_heap_size(),
             (unsigned)uxTaskGetStackHighWaterMark(NULL));

    if (included_zones == 0) {
        httpd_resp_set_status(req, "409 Conflict");
        return json_reply(req, "{\"ok\":false,\"error\":\"empty_mode\",\"message\":\"Nessuna zona valida associata alla modalità\"}");
    }

    zones_snapshot_t *snapshot = calloc(1, sizeof(*snapshot));
    if (!snapshot) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom"), ESP_FAIL;
    }
    zones_snapshot_build(snapshot);
    int snapshot_total = zones_snapshot_total(snapshot);
    if (snapshot_total > zones_total) {
        snapshot_total = zones_total;
    }

    zone_mask_t open_mask;
    zone_mask_clear(&open_mask);
    for (int idx = 0; idx < snapshot_total; ++idx){
        const zone_state_entry_t *entry = &snapshot->entries[idx];
        if (entry->known && entry->active) zone_mask_set(&open_mask, (uint16_t)idx);
    }
    free(snapshot);
    zone_mask_limit(&open_mask, (uint16_t)zones_total);

    zone_mask_t blocking;
    zone_mask_t bypass_mask;
    zone_mask_clear(&blocking);
    zone_mask_clear(&bypass_mask);
    for (int i=0; i<zones_total; ++i){
        if (zone_mask_test(&eff_mask, (uint16_t)i) && zone_mask_test(&open_mask, (uint16_t)i)){
            bool has_delay = (s_zone_cfg[i].zone_delay && s_zone_cfg[i].zone_time > 0);
            if (has_delay){
                continue;
            }
            if (s_zone_cfg[i].auto_exclude) zone_mask_set(&bypass_mask, (uint16_t)i);
            else                            zone_mask_set(&blocking, (uint16_t)i);
        }
    }

    if (zone_mask_any(&blocking)){
        char blocking_hex[ZONE_MASK_WORDS * 8u + 1u];
        zone_mask_to_hex(&blocking, (uint16_t)zones_total, blocking_hex, sizeof(blocking_hex));
        char buf[256];
        snprintf(buf, sizeof(buf), "{\"ok\":false,\"error\":\"open_zones\",\"message\":\"Zone aperte non bypassabili\",\"open_zone_mask\":\"%s\"}", blocking_hex);
        httpd_resp_set_status(req, "409 Conflict");
        return json_reply(req, buf);
    }

    scenes_set_active_mask(&scene_mask);
    alarm_set_bypass_mask(&bypass_mask);

    if      (target == ALARM_ARMED_AWAY)   alarm_arm_away();
    else if (target == ALARM_ARMED_HOME)   alarm_arm_home();
    else if (target == ALARM_ARMED_NIGHT)  alarm_arm_night();
    else if (target == ALARM_ARMED_CUSTOM) alarm_arm_custom();
    alarm_set_current_armed_zone_mask(&eff_mask);
    (void)mqtt_publish_state_async();

    prof = alarm_get_profile(target);
    uint32_t exit_ms = prof.exit_delay_ms;
    {
        uint32_t min_s = 0; bool found=false;
        for (int i=0;i<zones_total;i++){
            if (zone_mask_test(&eff_mask, (uint16_t)i) && zone_mask_test(&open_mask, (uint16_t)i) &&
                s_zone_cfg[i].zone_delay && s_zone_cfg[i].zone_time>0 ){
                if (!found || (uint32_t)s_zone_cfg[i].zone_time < min_s){ min_s = (uint32_t)s_zone_cfg[i].zone_time; }
                found = true;
            }
        }
        if (found){ exit_ms = min_s * 1000u; }
    }
    alarm_begin_exit(exit_ms);

    char scene_desc[48];
    zone_mask_format_brief(&scene_mask, (uint16_t)zones_total, 4, scene_desc, sizeof(scene_desc));
    char note[64];
    snprintf(note, sizeof(note), "mode=%s zones=%u", mode_norm, (unsigned)included_zones);
    audit_append("alarm_arm", user, 1, note);

    ESP_LOGI(TAG, "arm complete mode=%s zones=%u scene=%s heap=%" PRIu32 " stack_hwm=%u",
             mode_norm, (unsigned)included_zones, scene_desc, esp_get_free_heap_size(),
             (unsigned)uxTaskGetStackHighWaterMark(NULL));

    char resp[160];
    snprintf(resp, sizeof(resp),
             "{\"ok\":true,\"message\":\"Armamento attivato\",\"alarm_state\":\"armed\",\"active_mode\":\"%s\"}",
             mode_norm);
    return json_reply(req, resp);
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

    input_debounce_state_t tamper_state = {0};
    bool tamper_known = inputs_get_filtered_tamper(&tamper_state);
    if (tamper_known && tamper_state.stable_value) {
        cJSON_Delete(root);
        httpd_resp_set_status(req, "409 Conflict");
        return json_reply(req, "{\"error\":\"tamper_open\",\"message\":\"Linea tamper ancora aperta.\"}");
    }

    cJSON_Delete(root);

    alarm_state_t prev_state = alarm_get_state();
    zone_mask_t scene_mask;
    scenes_get_active_mask(&scene_mask);
    int zones_total = zones_effective_total();
    if (zones_total < 0) {
        zones_total = 0;
    }
    zone_mask_limit(&scene_mask, (uint16_t)zones_total);
    char scene_desc[48];
    zone_mask_format_brief(&scene_mask, (uint16_t)zones_total, 4, scene_desc, sizeof(scene_desc));
    const char *prev_label = alarm_state_name(prev_state);
    char disarm_note[64];
    size_t avail_note = sizeof(disarm_note);
    if (avail_note > 0) {
        const size_t prefix = 25; // strlen("prev=") + strlen(" scene=") + strlen(" cause=tamper")
        if (avail_note > 1) {
            avail_note -= 1;
        }
        if (avail_note > prefix) {
            avail_note -= prefix;
        } else {
            avail_note = 0;
        }
    }
    size_t prev_len = strnlen(prev_label, avail_note);
    size_t scene_len = 0;
    if (avail_note > prev_len) {
        size_t scene_avail = avail_note - prev_len;
        size_t scene_cap = sizeof(scene_desc) - 1;
        if (scene_avail < scene_cap) {
            scene_cap = scene_avail;
        }
        scene_len = strnlen(scene_desc, scene_cap);
    }
    snprintf(disarm_note, sizeof(disarm_note), "prev=%.*s scene=%.*s cause=tamper", (int)prev_len, prev_label, (int)scene_len, scene_desc);

    alarm_disarm();
    audit_append("tamper_reset", user, 1, "Reset tamper");
    audit_append("alarm_disarm", user, 1, disarm_note);
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

    alarm_state_t prev_state = alarm_get_state();
    zone_mask_t scene_mask;
    scenes_get_active_mask(&scene_mask);
    int zones_total = zones_effective_total();
    if (zones_total < 0) {
        zones_total = 0;
    }
    zone_mask_limit(&scene_mask, (uint16_t)zones_total);
    char scene_desc[48];
    zone_mask_format_brief(&scene_mask, (uint16_t)zones_total, 4, scene_desc, sizeof(scene_desc));
    const char *prev_label = alarm_state_name(prev_state);
    char note[64];
    size_t avail = sizeof(note);
    if (avail > 0) {
        const size_t prefix = 12; // strlen("prev=") + strlen(" scene=")
        if (avail > 1) {
            avail -= 1;
        }
        if (avail > prefix) {
            avail -= prefix;
        } else {
            avail = 0;
        }
    }
    size_t prev_len = strnlen(prev_label, avail);
    size_t scene_len = 0;
    if (avail > prev_len) {
        size_t scene_avail = avail - prev_len;
        size_t scene_cap = sizeof(scene_desc) - 1;
        if (scene_avail < scene_cap) {
            scene_cap = scene_avail;
        }
        scene_len = strnlen(scene_desc, scene_cap);
    }
    snprintf(note, sizeof(note), "prev=%.*s scene=%.*s", (int)prev_len, prev_label, (int)scene_len, scene_desc);

    alarm_disarm();
    audit_append("alarm_disarm", user, 1, note);
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