// web_server.c — ESP-IDF 5.x
// - UI con SPIFFS: index.html, login.html, style.css, app.js, login.js
// - Gate lato server: cookie HttpOnly "gate=1" decide index vs login su GET "/"
// - API solo con Authorization: Bearer <token> (no cookie) => no CSRF
// - Sessioni in RAM (token→username) con TTL assoluto 7g e inattività 30m (sliding)
// - Login con password (+ TOTP opzionale se abilitato per l’utente)

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

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

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
#include "spiffs_utils.h"
#include "totp.h"
#include "audit_log.h"
#include "pn532_spi.h"
#include "log_system.h"
#include "gpio_inputs.h"
#include "outputs.h"
#include "utils.h"
#include "scenes.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/param.h>
#include <sys/unistd.h>
#include <sys/stat.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>

extern const unsigned char certs_server_cert_pem_start[] asm("_binary_certs_server_cert_pem_start");
extern const unsigned char certs_server_cert_pem_end[]   asm("_binary_certs_server_cert_pem_end");
extern const unsigned char certs_server_key_pem_start[]  asm("_binary_certs_server_key_pem_start");
extern const unsigned char certs_server_key_pem_end[]    asm("_binary_certs_server_key_pem_end");

static void web_server_restart_async(void);

static const char *TAG = "web";
static const char *TAG_ADMIN __attribute__((unused)) = "admin_html";

// ─────────────────────────────────────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────────────────────────────────────
#define OTP_DISABLED        1   // 1 = disattiva completamente la richiesta OTP su /api/login
#define WEB_MAX_BODY_LEN     2048
#define SESSION_TTL_S        (7*24*60*60)  // 7 giorni
#define SESSION_IDLE_S       (30*60)       // 30 minuti sliding
#define TOTP_STEP_SECONDS    30
#define TOTP_WINDOW_STEPS    1

static const char* ISSUER_NAME = "CentraleESP32";
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

// ─────────────────────────────────────────────────────────────────────────────
// Server handle & SPIFFS
// ─────────────────────────────────────────────────────────────────────────────
static httpd_handle_t s_server = NULL;
static bool s_spiffs_mounted __attribute__((unused)) = false;

static esp_err_t json_reply(httpd_req_t* req, const char* json){
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, json);
}
static bool check_bearer(httpd_req_t* req){
    return auth_check_bearer(req, NULL);
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
        free(s_tls_material.dyn_cert);
        s_tls_material.dyn_cert = NULL;
        s_tls_material.dyn_cert_len = 0;
    }
    if (s_tls_material.dyn_key){
        free(s_tls_material.dyn_key);
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

static void web_tls_use_builtin(void){
    web_tls_clear_dynamic();
    s_tls_material.cert = (const uint8_t*)builtin_cert_pem;
    s_tls_material.cert_len = sizeof(builtin_cert_pem);
    s_tls_material.key = (const uint8_t*)builtin_key_pem;
    s_tls_material.key_len = sizeof(builtin_key_pem);
    s_tls_material.source = WEB_TLS_SRC_BUILTIN;

    mbedtls_x509_crt crt; mbedtls_x509_crt_init(&crt);
    if (mbedtls_x509_crt_parse(&crt, (const unsigned char*)builtin_cert_pem, sizeof(builtin_cert_pem)) == 0){
        web_tls_state_set_active_from_crt(&crt, WEB_TLS_SRC_BUILTIN);
        if (!s_web_tls_state.custom_available){
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

static bool is_admin_user(httpd_req_t* req){
    user_info_t u; return auth_check_bearer(req, &u) && u.role==ROLE_ADMIN;
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
    (void)step; (void)window;
    if (!b32 || !otp) return false;
    char clean[64]; size_t w = 0;
    for (const char* p=b32; *p && w+1<sizeof(clean); ++p){
        char c = *p;
        if (c==' ' || c=='-' || c=='\t') continue;
        if (c>='a' && c<='z') c = (char)(c - ('a'-'A'));
        clean[w++] = c;
    }
    clean[w] = 0;
    if (!clean[0]) return false;
    return totp_check(clean, otp);
}

static void nvs_get_str_def(nvs_handle_t h, const char* key, char* out, size_t cap, const char* def){
    size_t len = cap;
    esp_err_t e = nvs_get_str(h, key, out, &len);
    if (e != ESP_OK) { strncpy(out, def?def:"", cap-1); out[cap-1]=0; }
}
static uint32_t nvs_get_u32_def(nvs_handle_t h, const char* key, uint32_t def){
    uint32_t v=def; nvs_get_u32(h, key, &v); return v;
}
static esp_err_t only_admin(httpd_req_t* req){
    user_info_t u;
    if (!auth_check_bearer(req,&u) || u.role != ROLE_ADMIN){
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden");
    }
    return ESP_OK;
}

// ---- /api/sys/net GET/POST ----
static esp_err_t sys_net_get(httpd_req_t* req){
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    nvs_handle_t nvs; if (nvs_open("sys", NVS_READONLY, &nvs)!=ESP_OK) {
        return json_reply(req, "{\"hostname\":\"centrale-esp32\",\"dhcp\":true,\"ip\":\"\",\"gw\":\"\",\"mask\":\"\",\"dns\":\"\"}");
    }
    char host[64], ip[16], gw[16], mask[16], dns[16];
    nvs_get_str_def(nvs,"host", host,sizeof(host),"centrale-esp32");
    nvs_get_str_def(nvs,"ip",   ip,  sizeof(ip),  "");
    nvs_get_str_def(nvs,"gw",   gw,  sizeof(gw),  "");
    nvs_get_str_def(nvs,"mask", mask,sizeof(mask),"");
    nvs_get_str_def(nvs,"dns",  dns, sizeof(dns), "");
    bool dhcp = nvs_get_u32_def(nvs,"dhcp",1)!=0;
    nvs_close(nvs);
    char buf[256];
    snprintf(buf,sizeof(buf),
      "{\"hostname\":\"%s\",\"dhcp\":%s,\"ip\":\"%s\",\"gw\":\"%s\",\"mask\":\"%s\",\"dns\":\"%s\"}",
      host, dhcp?"true":"false", ip, gw, mask, dns);
    return json_reply(req, buf);
}

static esp_err_t sys_net_post(httpd_req_t* req){
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    char body[256]; size_t bl=0;
    if (read_body_to_buf(req, body, sizeof(body), &bl)!=ESP_OK) return httpd_resp_send_err(req,400,"body"), ESP_FAIL;
    cJSON* j = cJSON_ParseWithLength(body, bl);
    if (!j) return httpd_resp_send_err(req,400,"json"), ESP_FAIL;
    const cJSON* hn = cJSON_GetObjectItemCaseSensitive(j,"hostname");
    const cJSON* jd = cJSON_GetObjectItemCaseSensitive(j,"dhcp");
    const cJSON* jip= cJSON_GetObjectItemCaseSensitive(j,"ip");
    const cJSON* jgw= cJSON_GetObjectItemCaseSensitive(j,"gw");
    const cJSON* jmk= cJSON_GetObjectItemCaseSensitive(j,"mask");
    const cJSON* jdn= cJSON_GetObjectItemCaseSensitive(j,"dns");
    nvs_handle_t nvs; if (nvs_open("sys", NVS_READWRITE, &nvs)!=ESP_OK){ cJSON_Delete(j); return httpd_resp_send_err(req,500,"nvs"), ESP_FAIL; }
    if (cJSON_IsString(hn)) nvs_set_str(nvs,"host", hn->valuestring);
    if (cJSON_IsBool(jd))   nvs_set_u32(nvs,"dhcp", cJSON_IsTrue(jd)?1:0);
    if (cJSON_IsString(jip))nvs_set_str(nvs,"ip",   jip->valuestring);
    if (cJSON_IsString(jgw))nvs_set_str(nvs,"gw",   jgw->valuestring);
    if (cJSON_IsString(jmk))nvs_set_str(nvs,"mask", jmk->valuestring);
    if (cJSON_IsString(jdn))nvs_set_str(nvs,"dns",  jdn->valuestring);
    nvs_commit(nvs); nvs_close(nvs); cJSON_Delete(j);
    return json_reply(req, "{\"ok\":true}");
}

// ---- /api/sys/mqtt GET/POST ----
static esp_err_t sys_mqtt_get(httpd_req_t* req){
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    nvs_handle_t nvs; 
    if (nvs_open("sys", NVS_READONLY, &nvs)!=ESP_OK) {
        return json_reply(req, "{\"uri\":\"\",\"cid\":\"\",\"user\":\"\",\"pass\":\"\",\"keepalive\":60}");
    }
    char uri[96], cid[64], user[64], pass[64];
    nvs_get_str_def(nvs,"mq_uri", uri,sizeof(uri),"");
    nvs_get_str_def(nvs,"mq_cid", cid,sizeof(cid),"");
    nvs_get_str_def(nvs,"mq_user",user,sizeof(user),"");
    nvs_get_str_def(nvs,"mq_pass",pass,sizeof(pass),"");
    uint32_t ka = nvs_get_u32_def(nvs,"mq_keep",60);
    nvs_close(nvs);

    char buf[512]; // <-- più ampio
    int n = snprintf(buf,sizeof(buf),
      "{\"uri\":\"%s\",\"cid\":\"%s\",\"user\":\"%s\",\"pass\":\"%s\",\"keepalive\":%u}",
      uri,cid,user,pass,(unsigned)ka);
    if (n < 0 || n >= (int)sizeof(buf)) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "resp");
    }
    return json_reply(req, buf);
}

static esp_err_t sys_mqtt_post(httpd_req_t* req){
    if (only_admin(req)!=ESP_OK) return ESP_FAIL;
    char body[256]; size_t bl=0;
    if (read_body_to_buf(req, body, sizeof(body), &bl)!=ESP_OK) return httpd_resp_send_err(req,400,"body"), ESP_FAIL;
    cJSON* j = cJSON_ParseWithLength(body, bl);
    if (!j) return httpd_resp_send_err(req,400,"json"), ESP_FAIL;
    const cJSON* juri=cJSON_GetObjectItemCaseSensitive(j,"uri");
    const cJSON* jcid=cJSON_GetObjectItemCaseSensitive(j,"cid");
    const cJSON* jus =cJSON_GetObjectItemCaseSensitive(j,"user");
    const cJSON* jpw =cJSON_GetObjectItemCaseSensitive(j,"pass");
    const cJSON* jka =cJSON_GetObjectItemCaseSensitive(j,"keepalive");
    nvs_handle_t nvs; if (nvs_open("sys", NVS_READWRITE, &nvs)!=ESP_OK){ cJSON_Delete(j); return httpd_resp_send_err(req,500,"nvs"), ESP_FAIL; }
    if (cJSON_IsString(juri)) nvs_set_str(nvs,"mq_uri", juri->valuestring);
    if (cJSON_IsString(jcid)) nvs_set_str(nvs,"mq_cid", jcid->valuestring);
    if (cJSON_IsString(jus))  nvs_set_str(nvs,"mq_user",jus->valuestring);
    if (cJSON_IsString(jpw))  nvs_set_str(nvs,"mq_pass",jpw->valuestring);
    if (cJSON_IsNumber(jka))  nvs_set_u32(nvs,"mq_keep",(uint32_t)jka->valuedouble);
    nvs_commit(nvs); nvs_close(nvs); cJSON_Delete(j);
    return json_reply(req, "{\"ok\":true}");
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

static __attribute__((unused)) esp_err_t user_post_totp_enable(httpd_req_t* req){
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

    char uri[256];
    snprintf(uri, sizeof(uri), "otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=6&period=%d&algorithm=SHA1",
             ISSUER_NAME, uname, secret, ISSUER_NAME, TOTP_STEP_SECONDS);
    char resp[384]; snprintf(resp, sizeof(resp), "{\"secret_base32\":\"%s\",\"otpauth_uri\":\"%s\"}", secret, uri);
    return json_reply(req, resp);
}

static __attribute__((unused)) esp_err_t user_post_totp_confirm(httpd_req_t* req){
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
    if (cJSON_IsString(jsecret) && jsecret->valuestring) strncpy(secret, jsecret->valuestring, sizeof(secret)-1);
    cJSON_Delete(root);

    if(!otp[0] || !secret[0]) return httpd_resp_send_err(req, 400, "fields"), ESP_FAIL;

    time_t now_chk = time(NULL);
    if (now_chk < 1577836800) { // 2020-01-01
        return httpd_resp_send_err(req, 409, "time not set"), ESP_FAIL;
    }
    if(!totp_verify_b32(secret, otp, TOTP_STEP_SECONDS, TOTP_WINDOW_STEPS)){
        return httpd_resp_send_err(req, 401, "bad otp"), ESP_FAIL;
    }

    if(auth_totp_enable(uname, secret)!=ESP_OK) return httpd_resp_send_err(req,500,"enable"), ESP_FAIL;
    return json_bool(req, true);
}

static __attribute__((unused)) esp_err_t user_post_totp_disable(httpd_req_t* req){
    if(!check_bearer(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"), ESP_FAIL;
    char uname[16]={0}; if(!current_user_from_req(req, uname, sizeof(uname))) return httpd_resp_send_err(req, 401, "token"), ESP_FAIL;

    if(auth_totp_disable(uname)!=ESP_OK) return httpd_resp_send_err(req, 500, "disable"), ESP_FAIL;
    return json_bool(req, true);
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
    if(!check_bearer(req) || !is_admin_user(req)) return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "forbidden"), ESP_FAIL;
    // Build JSON array with details
    char csv[256]={0};
    auth_list_users(csv, sizeof(csv)); // returns comma-separated
    char* p = csv; char buf[1024]; size_t off=0; off += snprintf(buf+off, sizeof(buf)-off, "[");
    while(*p){
        // parse one username
        char u[32]={0};
        int i=0;
        while(*p && *p!=',' && i<31) u[i++]=*p++;
        if(*p==',') p++;
        if(!u[0]) continue;
        // names
        char fn[32]={0}, ln[32]={0};
        auth_get_user_name(u, fn, sizeof(fn), ln, sizeof(ln));
        // pin
        bool has_pin = auth_has_pin(u);
        // rfid
        uint8_t uid[16]; int uidlen = auth_get_rfid_uid(u, uid, sizeof(uid));
        char uidhex[40]={0}; if(uidlen>0){ int k=0; for(int j=0;j<uidlen;j++) k+= snprintf(uidhex+k,sizeof(uidhex)-k,"%02X",uid[j]); }
        // totp
        bool totp = auth_totp_enabled(u);

        off += snprintf(buf+off, sizeof(buf)-off,
            "%s{\"username\":\"%s\",\"first_name\":\"%s\",\"last_name\":\"%s\",\"has_pin\":%s,\"has_rfid\":%s%s}",
            (off>1?",":""), u, fn, ln, has_pin?"true":"false", (uidlen>0)?"true":"false", (uidlen>0)?",\"rfid_uid\":\"":"" );
        if(uidlen>0){ off += snprintf(buf+off, sizeof(buf)-off, "%s\"", uidhex); }
        off += snprintf(buf+off, sizeof(buf)-off, ",\"totp_enabled\":%s", totp?"true":"false");
        // Fix JSON: above added totp twice; construct anew to be safe:
    }
    // Due to complexity, rebuild cleanly using second pass
    off = 0; off += snprintf(buf+off, sizeof(buf)-off, "[");
    p = csv;
    bool first=true;
    while(*p){
        char u[32]={0}; int i=0; while(*p && *p!=',' && i<31) u[i++]=*p++; if(*p==',') p++;
        if(!u[0]) continue;
        char fn[32]={0}, ln[32]={0};
        auth_get_user_name(u, fn, sizeof(fn), ln, sizeof(ln));
        bool has_pin = auth_has_pin(u);
        uint8_t uid[16]; int uidlen = auth_get_rfid_uid(u, uid, sizeof(uid));
        char uidhex[40]={0}; if(uidlen>0){ int k=0; for(int j=0;j<uidlen;j++) k+= snprintf(uidhex+k,sizeof(uidhex)-k,"%02X",uid[j]); }
        bool totp = auth_totp_enabled(u);

        off += snprintf(buf+off, sizeof(buf)-off, "%s{\"username\":\"%s\",\"first_name\":\"%s\",\"last_name\":\"%s\",\"has_pin\":%s,\"has_rfid\":%s",
                        first?"":",", u, fn, ln, has_pin?"true":"false", (uidlen>0)?"true":"false");
        if(uidlen>0){ off += snprintf(buf+off, sizeof(buf)-off, ",\"rfid_uid\":\"%s\"", uidhex); }
        off += snprintf(buf+off, sizeof(buf)-off, ",\"totp_enabled\":%s}", totp?"true":"false");
        first=false;
    }
    off += snprintf(buf+off, sizeof(buf)-off, "]");
    return json_reply(req, buf);
}

// ─────────────────────────────────────────────────────────────────────────────
// STATUS / ZONES / SCENES
// ─────────────────────────────────────────────────────────────────────────────
static nvs_handle_t s_nvs = 0;
static esp_err_t open_nvs_if_needed(void){
    if (s_nvs) return ESP_OK;
    esp_err_t err = nvs_open("app", NVS_READWRITE, &s_nvs);
    if (err != ESP_OK) ESP_LOGE(TAG, "nvs_open: %s", esp_err_to_name(err));
    return err;
}

typedef struct {
    bool     zone_delay;   // ritardo unico abilitato
    uint16_t zone_time;    // secondi
    bool     auto_exclude; // se aperta all'ARM e non ritardata -> bypassabile?
    char     name[24];
} zone_cfg_t;

static zone_cfg_t s_zone_cfg[INPUT_ZONES_COUNT];

static void zones_apply_to_alarm(void){
     // Invia le opzioni zona ad alarm_core
    for(int i=1;i<=INPUT_ZONES_COUNT;i++){
        zone_cfg_t *c = &s_zone_cfg[i-1];
        zone_opts_t o = { .entry_delay = c->zone_delay, .entry_time_ms = (uint16_t)(c->zone_time * 1000u), .exit_delay = c->zone_delay, .exit_time_ms = (uint16_t)(c->zone_time * 1000u), .auto_exclude = c->auto_exclude };
        alarm_set_zone_opts(i, &o);
    }
}

static void zones_load_from_nvs(void){
    nvs_handle_t h; if(nvs_open("zones", NVS_READONLY, &h)!=ESP_OK) return;
    size_t sz = sizeof(s_zone_cfg);
    if(nvs_get_blob(h,"cfg",s_zone_cfg,&sz)!=ESP_OK) { /* default vuoti */ }
    nvs_close(h);
    zones_apply_to_alarm();
}
static void zones_save_to_nvs(void){
    nvs_handle_t h; if(nvs_open("zones", NVS_READWRITE, &h)!=ESP_OK) return;
    nvs_set_blob(h,"cfg",s_zone_cfg,sizeof(s_zone_cfg));
    nvs_commit(h);
    nvs_close(h);
    zones_apply_to_alarm();
}

static esp_err_t status_get(httpd_req_t* req){
    if(!check_bearer(req)) { httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"); return ESP_FAIL; }

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
    if (entry_p) state = "PRE_DISARM";
    else if (exit_p && (_st==ALARM_ARMED_HOME || _st==ALARM_ARMED_AWAY || _st==ALARM_ARMED_NIGHT || _st==ALARM_ARMED_CUSTOM)) state = "PRE_ARM";

    uint16_t gpioab = 0;
    inputs_read_all(&gpioab);
    bool tamper = inputs_tamper(gpioab);

    uint16_t outmask = 0;
    outputs_get_mask(&outmask);

    char zones[256]; size_t off=0;
    off += snprintf(zones+off, sizeof(zones)-off, "[");
    for (int z=1; z<=INPUT_ZONES_COUNT; ++z){
        bool on = inputs_zone_bit(gpioab, z);
        off += snprintf(zones+off, sizeof(zones)-off, "%s%s", (z>1?",":""), on?"true":"false");
    }
    off += snprintf(zones+off, sizeof(zones)-off, "]");

    char buf[512];
    snprintf(buf, sizeof(buf),
        "{\"state\":\"%s\",\"zones_count\":%d,\"zones_active\":%s,\"tamper\":%s,\"outputs_mask\":%u,\"bypass_mask\":%u,\"exit_pending_ms\":%u,\"entry_pending_ms\":%u,\"entry_zone\":%d}",
        state, INPUT_ZONES_COUNT, zones, tamper?"true":"false", (unsigned)outmask, (unsigned)alarm_get_bypass_mask(), (unsigned)exit_ms, (unsigned)entry_ms, entry_zone);
    // snprintf(buf, sizeof(buf),
    //     "{\"state\":\"%s\",\"zones_count\":%d,\"zones_active\":%s,\"tamper\":%s,\"outputs_mask\":%u,\"bypass_mask\":%u}",
    //     state, INPUT_ZONES_COUNT, zones, tamper?"true":"false", (unsigned)outmask, (unsigned)alarm_get_bypass_mask());
 
    return json_reply(req, buf);
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
        const char* zname = s_zone_cfg[z-1].name[0] ? s_zone_cfg[z-1].name : "";
        cJSON_AddStringToObject(it, "name", zname);
        cJSON_AddBoolToObject(it, "active", on);
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
          "%s{\"id\":%d,\"name\":\"%s\",\"zone_delay\":%s,\"zone_time\":%u,\"auto_exclude\":%s}",
          (z>1?",":""), z, (c->name[0]?c->name:""), c->zone_delay?"true":"false", c->zone_time, c->auto_exclude?"true":"false");
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

        c->zone_delay = z_delay;
        c->zone_time  = z_time;
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
    }
    httpd_resp_set_type(req, ct);
    auth_set_security_headers(req);
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
    // If logged -> /index.html else /login.html
    user_info_t u;
    if (auth_check_cookie(req,&u)){
        httpd_resp_set_status(req,"302 Found");
        httpd_resp_set_hdr(req,"Location","/index.html");
    } else {
        httpd_resp_set_status(req,"302 Found");
        httpd_resp_set_hdr(req,"Location","/login.html");
    }
    auth_set_security_headers(req);
    return httpd_resp_send(req, NULL, 0);
}

static esp_err_t login_html_get(httpd_req_t* req){
    // If already logged, go to index
    user_info_t u;
    if (auth_check_cookie(req,&u)){
        httpd_resp_set_status(req,"302 Found");
        httpd_resp_set_hdr(req,"Location","/");
        auth_set_security_headers(req);
        return httpd_resp_send(req,NULL,0);
    }
    return send_file(req,"login.html");
}

static esp_err_t index_html_get(httpd_req_t* req){
    if (!auth_gate_html(req, ROLE_USER)) return ESP_OK;
    return send_file(req,"index.html");
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
    if (strstr(uri,"login.js")) return send_file(req,"js/login.js");
    if (strstr(uri,"app.js"))   return send_file(req,"js/app.js");
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
static esp_err_t zones_get (httpd_req_t* req);
static esp_err_t scenes_get(httpd_req_t* req);
static esp_err_t scenes_post(httpd_req_t* req);
static esp_err_t arm_post(httpd_req_t* req);
static esp_err_t disarm_post(httpd_req_t* req);
static esp_err_t user_post_pin(httpd_req_t* req);

static esp_err_t users_create_post(httpd_req_t* req);
static esp_err_t users_pin_admin_post(httpd_req_t* req);
static esp_err_t users_rfid_learn_post(httpd_req_t* req);
static esp_err_t users_rfid_clear_post(httpd_req_t* req);
static esp_err_t users_admin_list_get(httpd_req_t* req);

// ─────────────────────────────────────────────────────────────────────────────
// START/STOP server + registrazione URI
// ─────────────────────────────────────────────────────────────────────────────
static esp_err_t start_web(void){
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.stack_size = 12288;
    cfg.max_uri_handlers = 50;
    cfg.lru_purge_enable = true;
    cfg.server_port = 443;
    cfg.uri_match_fn = httpd_uri_match_wildcard;

    httpd_handle_t srv = NULL;
    esp_err_t err = https_start(&srv, &cfg);
    if (err != ESP_OK){
        return err;
    }
    s_server = srv;

    // static files
    httpd_uri_t ui_root      = {.uri="/",                 .method=HTTP_GET,  .handler=root_get,           .user_ctx=NULL};
    httpd_uri_t ui_login_h   = {.uri="/login.html",       .method=HTTP_GET,  .handler=login_html_get,     .user_ctx=NULL};
    httpd_uri_t ui_index_h   = {.uri="/index.html",       .method=HTTP_GET,  .handler=index_html_get,     .user_ctx=NULL};
    httpd_uri_t ui_admin_h   = {.uri="/admin.html",       .method=HTTP_GET,  .handler=admin_html_get,     .user_ctx=NULL};
    httpd_uri_t ui_403_h     = {.uri="/403.html",         .method=HTTP_GET,  .handler=four03_html_get,    .user_ctx=NULL};

    httpd_uri_t ui_app_js    = {.uri="/js/app.js",        .method=HTTP_GET,  .handler=js_get,             .user_ctx=NULL};
    httpd_uri_t ui_admin_js  = {.uri="/js/admin.js",      .method=HTTP_GET,  .handler=js_get,             .user_ctx=NULL};
    httpd_uri_t ui_login_js  = {.uri="/js/login.js",      .method=HTTP_GET,  .handler=js_get,             .user_ctx=NULL};
    httpd_uri_t ui_qrcode_js = {.uri="/js/qrcode.min.js", .method=HTTP_GET,  .handler=js_get,             .user_ctx=NULL};
    httpd_uri_t ui_bs_js     = {.uri="/js/bootstrap.bundle.min.js",     .method=HTTP_GET,  .handler=js_get,             .user_ctx=NULL};
    httpd_uri_t ui_bs_js_map = {.uri="/js/bootstrap.bundle.min.js.map", .method=HTTP_GET,  .handler=js_get,             .user_ctx=NULL};
    httpd_uri_t ui_bs_css    = {.uri="/css/bootstrap.min.css",          .method=HTTP_GET,  .handler=css_get,            .user_ctx=NULL};
    httpd_uri_t ui_bs_css_map= {.uri="/css/bootstrap.min.css.map",      .method=HTTP_GET,  .handler=css_get,            .user_ctx=NULL};
    httpd_uri_t ui_css       = {.uri="/css/style.css",    .method=HTTP_GET,  .handler=css_get,            .user_ctx=NULL};

    httpd_uri_t u_api_login  = {.uri="/api/login",        .method=HTTP_POST, .handler=api_login_post,     .user_ctx=NULL};
    httpd_uri_t u_api_logout = {.uri="/api/logout",       .method=HTTP_POST, .handler=api_logout_post,    .user_ctx=NULL};
    httpd_uri_t u_api_me     = {.uri="/api/me",           .method=HTTP_GET,  .handler=api_me_get,         .user_ctx=NULL};
    httpd_uri_t u_api_admin  = {.uri="/api/admin/secret", .method=HTTP_GET,  .handler=api_admin_only_get, .user_ctx=NULL};

    httpd_register_uri_handler(srv,&ui_root);
    httpd_register_uri_handler(srv,&ui_login_h);
    httpd_register_uri_handler(srv,&ui_index_h);
    httpd_register_uri_handler(srv,&ui_admin_h);
    httpd_register_uri_handler(srv,&ui_403_h);

    httpd_register_uri_handler(srv,&ui_app_js);
    httpd_register_uri_handler(srv,&ui_admin_js);
    httpd_register_uri_handler(srv,&ui_qrcode_js);
    httpd_register_uri_handler(srv,&ui_bs_js);
    httpd_register_uri_handler(srv,&ui_bs_js_map);
    httpd_register_uri_handler(srv,&ui_login_js);
    httpd_register_uri_handler(srv,&ui_css);
    httpd_register_uri_handler(srv,&ui_bs_css);
    httpd_register_uri_handler(srv,&ui_bs_css_map);

    httpd_register_uri_handler(srv,&u_api_login);
    httpd_register_uri_handler(srv,&u_api_logout);
    httpd_register_uri_handler(srv,&u_api_me);
    httpd_register_uri_handler(srv,&u_api_admin);

    // API protette
    httpd_uri_t api_status     = {.uri="/api/status",             .method=HTTP_GET,  .handler=status_get,           .user_ctx=NULL };
    httpd_uri_t api_zones      = {.uri="/api/zones",              .method=HTTP_GET,  .handler=zones_get,            .user_ctx=NULL };
    httpd_uri_t api_zone_cfg_g = {.uri="/api/zones/config",       .method=HTTP_GET,  .handler=zones_config_get,     .user_ctx=NULL};
    httpd_uri_t api_zone_cfg_p = {.uri="/api/zones/config",       .method=HTTP_POST, .handler=zones_config_post,    .user_ctx=NULL};
    httpd_uri_t api_scenes_g   = {.uri="/api/scenes",             .method=HTTP_GET,  .handler=scenes_get,           .user_ctx=NULL };
    httpd_uri_t api_scenes_p   = {.uri="/api/scenes",             .method=HTTP_POST, .handler=scenes_post,          .user_ctx=NULL };
    httpd_uri_t api_user_pw    = {.uri="/api/user/password",      .method=HTTP_POST, .handler=user_post_password,   .user_ctx=NULL};
    httpd_uri_t api_user_totp  = {.uri="/api/user/totp",          .method=HTTP_GET,  .handler=user_get_totp,        .user_ctx=NULL};
    httpd_uri_t api_arm        = {.uri="/api/arm",                .method=HTTP_POST, .handler=arm_post,             .user_ctx=NULL};
    httpd_uri_t api_disarm     = {.uri="/api/disarm",             .method=HTTP_POST, .handler=disarm_post,          .user_ctx=NULL};
    httpd_uri_t api_user_pin   = {.uri="/api/user/pin",           .method=HTTP_POST, .handler=user_post_pin,        .user_ctx=NULL};

    httpd_uri_t api_users_ls   = {.uri="/api/users",              .method=HTTP_GET,  .handler=users_list_get,       .user_ctx=NULL};
    httpd_uri_t api_users_pw   = {.uri="/api/users/password",     .method=HTTP_POST, .handler=users_password_post,  .user_ctx=NULL};
    
    httpd_uri_t api_users_create = {.uri="/api/users/create",     .method=HTTP_POST, .handler=users_create_post,    .user_ctx=NULL};
    httpd_uri_t api_users_pin    = {.uri="/api/users/pin",        .method=HTTP_POST, .handler=users_pin_admin_post, .user_ctx=NULL};
    httpd_uri_t api_users_rfid_l = {.uri="/api/users/rfid/learn", .method=HTTP_POST, .handler=users_rfid_learn_post,.user_ctx=NULL};
    httpd_uri_t api_users_rfid_c = {.uri="/api/users/rfid/clear", .method=HTTP_POST, .handler=users_rfid_clear_post,.user_ctx=NULL};
    httpd_uri_t api_admin_users  = {.uri="/api/admin/users",      .method=HTTP_GET,  .handler=users_admin_list_get, .user_ctx=NULL};

    httpd_uri_t api_sys_net_g  = {.uri="/api/sys/net",  .method=HTTP_GET,  .handler=sys_net_get,  .user_ctx=NULL};
    httpd_uri_t api_sys_net_p  = {.uri="/api/sys/net",  .method=HTTP_POST, .handler=sys_net_post, .user_ctx=NULL};
    httpd_uri_t api_sys_mqtt_g = {.uri="/api/sys/mqtt", .method=HTTP_GET,  .handler=sys_mqtt_get, .user_ctx=NULL};
    httpd_uri_t api_sys_mqtt_p = {.uri="/api/sys/mqtt", .method=HTTP_POST, .handler=sys_mqtt_post,.user_ctx=NULL};
    httpd_uri_t api_sys_websec_g = {.uri="/api/sys/websec", .method=HTTP_GET,  .handler=sys_websec_get, .user_ctx=NULL};
    httpd_uri_t api_sys_websec_p = {.uri="/api/sys/websec", .method=HTTP_POST, .handler=sys_websec_post,.user_ctx=NULL};

    httpd_register_uri_handler(srv, &api_status);
    httpd_register_uri_handler(srv, &api_zones);
    httpd_register_uri_handler(srv, &api_zone_cfg_g);
    httpd_register_uri_handler(srv, &api_zone_cfg_p);
    httpd_register_uri_handler(srv, &api_scenes_g);
    httpd_register_uri_handler(srv, &api_scenes_p);
    httpd_register_uri_handler(srv, &api_user_pw);
    httpd_register_uri_handler(srv, &api_user_totp);
    httpd_register_uri_handler(srv, &api_arm);
    httpd_register_uri_handler(srv, &api_disarm);
    httpd_register_uri_handler(srv, &api_user_pin);

    httpd_register_uri_handler(srv, &api_users_ls);
    httpd_register_uri_handler(srv, &api_users_pw);
    
    httpd_register_uri_handler(srv, &api_users_create);
    httpd_register_uri_handler(srv, &api_users_pin);
    httpd_register_uri_handler(srv, &api_users_rfid_l);
    httpd_register_uri_handler(srv, &api_users_rfid_c);
    httpd_register_uri_handler(srv, &api_admin_users);

    httpd_register_uri_handler(srv, &api_sys_net_g);
    httpd_register_uri_handler(srv, &api_sys_net_p);
    httpd_register_uri_handler(srv, &api_sys_mqtt_g);
    httpd_register_uri_handler(srv, &api_sys_mqtt_p);
    httpd_register_uri_handler(srv, &api_sys_websec_g);
    httpd_register_uri_handler(srv, &api_sys_websec_p);

    ESP_LOGI(TAG, "Server HTTPS avviato su porta %d (%s)",
             cfg.server_port, s_web_tls_state.using_builtin ? "certificato builtin" : "certificato personalizzato");

    return ESP_OK;
}

esp_err_t web_server_start(void){
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(spiffs_init());
    ESP_ERROR_CHECK(audit_init(128));
    ESP_ERROR_CHECK(auth_init());
    
    ESP_ERROR_CHECK(start_web());

    zones_load_from_nvs();

    ESP_LOGI(TAG, "Pronto. Apri https://<esp-ip>");
    return ESP_OK;
}

esp_err_t web_server_stop(void){
    if (!s_server) return ESP_OK;
    httpd_handle_t handle = s_server;
    s_server = NULL;
    esp_err_t err = httpd_ssl_stop(handle);
    if (err != ESP_OK){
        ESP_LOGE(TAG, "httpd_ssl_stop failed: %s", esp_err_to_name(err));
    }
    return err;
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
    char tok[128]={0}, user[32]={0};
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

static esp_err_t disarm_post(httpd_req_t* req)
{
    if(!check_bearer(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"), ESP_FAIL;
    char tok[128]={0}, user[32]={0};
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
    char tok[128]={0}, user[32]={0};
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
