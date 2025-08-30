#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "esp_mac.h"

#include "esp_http_server.h"
#include "esp_spiffs.h"
#include "esp_log.h"

#include "web_server.h"
#include "auth.h"
#include "alarm_core.h"
#include "log_system.h"
#include "gpio_inputs.h"
#include "outputs.h"
#include "utils.h"
#include "pins.h"

static const char *TAG = "web";
static httpd_handle_t s_server = NULL;
static char s_token[33] = {0};

static esp_err_t send_file(httpd_req_t* req, const char* path, const char* type){
    FILE* f = fopen(path, "rb");
    if(!f){
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Not found");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, type);
    httpd_resp_set_hdr(req, "Cache-Control", "public, max-age=3600");

    char b[1024];
    size_t n;
    while((n = fread(b, 1, sizeof(b), f)) > 0){
        if (httpd_resp_send_chunk(req, b, n) != ESP_OK){
            fclose(f);
            return ESP_FAIL;
        }
    }
    fclose(f);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t root_get(httpd_req_t* req){ return send_file(req, "/spiffs/index.html", "text/html"); }
static esp_err_t style_get(httpd_req_t* req){ return send_file(req, "/spiffs/style.css", "text/css"); }
static esp_err_t script_get(httpd_req_t* req){ return send_file(req, "/spiffs/script.js", "application/javascript"); }

static bool check_token(httpd_req_t* req){
    size_t tlen = httpd_req_get_hdr_value_len(req, "X-Auth-Token") + 1;
    if (tlen <= 1 || tlen > 64) return false;
    char tok[64];
    if (httpd_req_get_hdr_value_str(req, "X-Auth-Token", tok, tlen) != ESP_OK) return false;
    return (strcmp(tok, s_token) == 0);
}

/* Util: leggi interamente il body (JSON) in modo sicuro */
static int read_body(httpd_req_t* req, char* buf, size_t buflen){
    size_t total = 0;
    while (total < req->content_len && total < buflen - 1){
        int r = httpd_req_recv(req, buf + total, buflen - 1 - total);
        if (r <= 0){
            return -1; // errore o timeout
        }
        total += (size_t)r;
    }
    buf[total] = 0;
    return (int)total;
}

static esp_err_t login_post(httpd_req_t* req){
    char buf[256] = {0};
    if (read_body(req, buf, sizeof(buf)) < 0){
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "read body failed");
        return ESP_FAIL;
    }

    char user[32] = {0}, pass[64] = {0}, otp[16] = {0};
    /* Parsing minimalista: accetta il JSON compatto {"user":"...","pass":"...","otp":"..."} */
    if (sscanf(buf, "{%*[^u]\"user\":\"%31[^\"]\"%*[^p]\"pass\":\"%63[^\"]\"%*[^o]\"otp\":\"%15[^\"]\"%*[^}]}", user, pass, otp) < 2){
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad json");
        return ESP_FAIL;
    }

    if(!auth_verify_password(user, pass)){
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "bad creds");
        return ESP_FAIL;
    }
    if(!auth_verify_totp_if_enabled(user, (*otp ? otp : NULL))){
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "bad otp");
        return ESP_FAIL;
    }

    utils_random_token(s_token, 32);
    s_token[32] = 0;

    char out[80];
    snprintf(out, sizeof(out), "{\"token\":\"%s\"}", s_token); // <-- virgolette corrette
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, out);
}

static esp_err_t status_get(httpd_req_t* req){
    if(!check_token(req)){
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "no token");
        return ESP_FAIL;
    }
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "Content-Type,X-Auth-Token");

    const char* st = "UNKNOWN";
    switch(alarm_get_state()){
        case ALARM_DISARMED:      st = "DISARMED"; break;
        case ALARM_ARMED_HOME:    st = "ARMED_HOME"; break;
        case ALARM_ARMED_AWAY:    st = "ARMED_AWAY"; break;
        case ALARM_ARMED_NIGHT:   st = "ARMED_NIGHT"; break;
        case ALARM_ARMED_CUSTOM:  st = "ARMED_CUSTOM"; break;
        case ALARM_ALARM:         st = "ALARM"; break;
        case ALARM_MAINTENANCE:   st = "MAINTENANCE"; break;
    }
    char b[96];
    snprintf(b, sizeof(b), "{\"state\":\"%s\",\"zones_count\":12}", st);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, b);
}

static esp_err_t zones_get(httpd_req_t* req){
    if(!check_token(req)){
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "no token");
        return ESP_FAIL;
    }
    uint16_t ab = 0;
    inputs_read_all(&ab);

    char buf[256];
    char *p = buf;                       // <-- corretto (prima variabile inesistente "out")
    *p++ = '[';
    for (int i = 1; i <= 12; i++) {
        p += sprintf(p, "{\"id\":%d,\"level\":%d}%s",
                     i,
                     inputs_zone_bit(ab, i) ? 1 : 0,
                     (i < 12) ? "," : "");
    }
    *p++ = ']';
    *p = 0;

    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buf, p - buf);
}

static esp_err_t arm_post(httpd_req_t* req){
    if(!check_token(req)){
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "no token");
        return ESP_FAIL;
    }
    char buf[64] = {0};
    if (read_body(req, buf, sizeof(buf)) < 0){
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "read body failed");
        return ESP_FAIL;
    }

    if      (strstr(buf, "\"home\""))   alarm_arm_home();
    else if (strstr(buf, "\"away\""))   alarm_arm_away();
    else if (strstr(buf, "\"night\""))  alarm_arm_night();
    else if (strstr(buf, "\"custom\"")) alarm_arm_custom();

    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

static esp_err_t disarm_post(httpd_req_t* req){
    if(!check_token(req)){
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "no token");
        return ESP_FAIL;
    }
    alarm_disarm();
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

static esp_err_t outputs_post(httpd_req_t* req){
    if(!check_token(req)){
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "no token");
        return ESP_FAIL;
    }
    char buf[96] = {0};
    if (read_body(req, buf, sizeof(buf)) < 0){
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "read body failed");
        return ESP_FAIL;
    }

    int relay = 0, ls = 0, lm = 0;
    /* accetta forme tipo {"relay":1,"ls":0,"lm":1} in ordine qualsiasi */
    if (sscanf(buf, "%*[^0-9a-zA-Z]\"relay\":%d%*[^0-9]\"ls\":%d%*[^0-9]\"lm\":%d", &relay, &ls, &lm) < 1){
        /* fallback più permissivo */
        sscanf(buf, "{\"relay\":%d%*[^0-9]%d%*[^0-9]%d}", &relay, &ls, &lm);
    }

    outputs_siren(relay != 0);
    outputs_led_state(ls != 0);
    outputs_led_maint(lm != 0);

    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

static esp_err_t logs_get(httpd_req_t* req){
    if(!check_token(req)){
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "no token");
        return ESP_FAIL;
    }
    log_item_t items[64];
    int n = log_dump(items, 64);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr_chunk(req, "[");
    for(int i = 0; i < n; i++){
        char b[160];
        int len = snprintf(b, sizeof(b),
                   "{\"ts\":%" PRIu32 ",\"msg\":\"%s\"}%s",
                   (uint32_t)items[i].ts, items[i].msg, (i < n - 1) ? "," : "");
        httpd_resp_send_chunk(req, b, len);
    }
    httpd_resp_send_chunk(req, "]", 1);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

esp_err_t web_server_start(void){
    // Monta SPIFFS con i file web
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = NULL,
        .max_files = 8,
        .format_if_mount_failed = true
    };
    ESP_ERROR_CHECK(esp_vfs_spiffs_register(&conf));

    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.server_port = 80;
    // <-- Aumenti i limiti qui
    cfg.max_uri_handlers   = 24;    // default 8
    cfg.max_open_sockets   = 12;    // default 7/8
    cfg.stack_size         = 8192;  // default ~4096/6144 (alza se hai molte route)
    cfg.lru_purge_enable   = true;  // opzionale: libera handler LRU quando serve
    // opzionale:
    // cfg.recv_wait_timeout = 10;
    // cfg.send_wait_timeout = 10;

    ESP_ERROR_CHECK(httpd_start(&s_server, &cfg));

    httpd_uri_t u_root    = {.uri="/",           .method=HTTP_GET,  .handler=root_get};
    httpd_uri_t u_css     = {.uri="/style.css",  .method=HTTP_GET,  .handler=style_get};
    httpd_uri_t u_js      = {.uri="/script.js",  .method=HTTP_GET,  .handler=script_get};

    httpd_uri_t api_login   = {.uri="/api/login",   .method=HTTP_POST, .handler=login_post};
    httpd_uri_t api_status  = {.uri="/api/status",  .method=HTTP_GET,  .handler=status_get};
    httpd_uri_t api_zones   = {.uri="/api/zones",   .method=HTTP_GET,  .handler=zones_get};
    httpd_uri_t api_arm     = {.uri="/api/arm",     .method=HTTP_POST, .handler=arm_post};
    httpd_uri_t api_disarm  = {.uri="/api/disarm",  .method=HTTP_POST, .handler=disarm_post};
    httpd_uri_t api_outputs = {.uri="/api/outputs", .method=HTTP_POST, .handler=outputs_post};
    httpd_uri_t api_logs    = {.uri="/api/logs",    .method=HTTP_GET,  .handler=logs_get};

    httpd_register_uri_handler(s_server, &u_root);
    httpd_register_uri_handler(s_server, &u_css);
    httpd_register_uri_handler(s_server, &u_js);

    httpd_register_uri_handler(s_server, &api_login);
    httpd_register_uri_handler(s_server, &api_status);
    httpd_register_uri_handler(s_server, &api_zones);
    httpd_register_uri_handler(s_server, &api_arm);
    httpd_register_uri_handler(s_server, &api_disarm);
    httpd_register_uri_handler(s_server, &api_outputs);
    httpd_register_uri_handler(s_server, &api_logs);

    ESP_LOGI(TAG, "Web server started on port %d", cfg.server_port);
    return ESP_OK;
}
