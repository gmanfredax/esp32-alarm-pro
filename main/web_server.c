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

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "nvs_flash.h"
#include "nvs.h"

#include "cJSON.h"

#include "mbedtls/md.h"

#include "web_server.h"

#include "alarm_core.h"
#include "auth.h"
#include "spiffs_utils.h"
#include "userdb.h"
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

// ─────────────────────────────────────────────────────────────────────────────
// Server handle & SPIFFS
// ─────────────────────────────────────────────────────────────────────────────
static httpd_handle_t s_server __attribute__((unused)) = NULL;
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


static bool is_admin_user(httpd_req_t* req){
    user_info_t u; return auth_check_bearer(req, &u) && u.role==ROLE_ADMIN;
}

// Se non stai usando davvero HTTPS qui, usa httpd_start come wrapper
static esp_err_t https_start(httpd_handle_t* s, httpd_config_t* cfg){
    return httpd_start(s, cfg);
}

// Stub TOTP (compila; implementa poi quello reale oppure rimuovi gli endpoint se non ti servono)
static bool totp_verify_b32(const char* b32, const char* otp, int step, int window){
    (void)b32; (void)otp; (void)step; (void)window;
    return false;
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

// ─────────────────────────────────────────────────────────────────────────────
// USER SETTINGS & ADMIN
// ─────────────────────────────────────────────────────────────────────────────
static esp_err_t json_bool(httpd_req_t* req, bool v){
    return json_reply(req, v ? "{\"ok\":true}" : "{\"ok\":false}");
}

static esp_err_t user_get_totp(httpd_req_t* req){
    if(!check_bearer(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"), ESP_FAIL;
    char uname[16]={0}; if(!current_user_from_req(req, uname, sizeof(uname))) return httpd_resp_send_err(req, 401, "token"), ESP_FAIL;
    user_record_t u; if(auth_get_user(uname, &u)!=ESP_OK) return httpd_resp_send_err(req, 500, "user"), ESP_FAIL;
    char buf[64]; snprintf(buf, sizeof(buf), "{\"enabled\":%s}", u.totp_enabled?"true":"false");
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

    if(auth_set_totp(uname, false, secret)!=ESP_OK) return httpd_resp_send_err(req, 500, "set totp"), ESP_FAIL;

    char uri[256];
    snprintf(uri, sizeof(uri), "otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=6&period=%d&algorithm=SHA1",
             ISSUER_NAME, uname, secret, ISSUER_NAME, TOTP_STEP_SECONDS);
    char resp[384]; snprintf(resp, sizeof(resp), "{\"secret_base32\":\"%s\",\"otpauth_uri\":\"%s\"}", secret, uri);
    return json_reply(req, resp);
}

static __attribute__((unused)) esp_err_t user_post_totp_confirm(httpd_req_t* req){
    if(!check_bearer(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"), ESP_FAIL;
    char uname[16]={0}; if(!current_user_from_req(req, uname, sizeof(uname))) return httpd_resp_send_err(req, 401, "token"), ESP_FAIL;

    char body[64]; size_t blen = 0;
    if(read_body_to_buf(req, body, sizeof(body), &blen)!=ESP_OK) return httpd_resp_send_err(req, 400, "body"), ESP_FAIL;
    char otp[16]={0}; sscanf(body, "%*[^\"\"o]\"otp\"%*[^\"\"]\"%15[^\"]", otp);
    if(!otp[0]) return httpd_resp_send_err(req, 400, "otp"), ESP_FAIL;

    user_record_t u; if(auth_get_user(uname,&u)!=ESP_OK) return httpd_resp_send_err(req,500,"user"), ESP_FAIL;
    if(strlen(u.totp_base32)<10) return httpd_resp_send_err(req, 400, "no secret"), ESP_FAIL;

    // if(!totp_verify_b32(u.totp_base32, otp, TOTP_STEP_SECONDS, TOTP_WINDOW_STEPS))
    //     return httpd_resp_send_err(req, 401, "bad otp"), ESP_FAIL;
    
    // prima verifica che l'orologio sia sincronizzato
    time_t now_chk = time(NULL);
    if (now_chk < 1577836800) { // 2020-01-01
        return httpd_resp_send_err(req, 409, "time not set"), ESP_FAIL;
    }
    if(!totp_verify_b32(u.totp_base32, otp, TOTP_STEP_SECONDS, TOTP_WINDOW_STEPS)){
        return httpd_resp_send_err(req, 401, "bad otp"), ESP_FAIL;
    }

    if(auth_set_totp(uname, true, u.totp_base32)!=ESP_OK) return httpd_resp_send_err(req,500,"enable"), ESP_FAIL;
    return json_bool(req, true);
}

static __attribute__((unused)) esp_err_t user_post_totp_disable(httpd_req_t* req){
    if(!check_bearer(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "token"), ESP_FAIL;
    char uname[16]={0}; if(!current_user_from_req(req, uname, sizeof(uname))) return httpd_resp_send_err(req, 401, "token"), ESP_FAIL;

    if(auth_set_totp(uname, false, NULL)!=ESP_OK) return httpd_resp_send_err(req, 500, "disable"), ESP_FAIL;
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
    if(auth_set_totp(usr, false, NULL)!=ESP_OK) return httpd_resp_send_err(req, 500, "reset totp"), ESP_FAIL;
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
        user_record_t rec; bool totp=false; if(auth_get_user(u, &rec)==ESP_OK) totp = rec.totp_enabled;

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
        user_record_t rec; bool totp=false; if(auth_get_user(u, &rec)==ESP_OK) totp = rec.totp_enabled;

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
void start_web(void){
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.stack_size = 12288;
    cfg.max_uri_handlers = 40;
    cfg.lru_purge_enable = true;
    cfg.server_port = 80;
    cfg.uri_match_fn = httpd_uri_match_wildcard;

    httpd_handle_t srv = NULL;
    ESP_ERROR_CHECK( https_start(&srv, &cfg) );

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
    httpd_uri_t ui_bs_js     = {.uri="/js/bootstrap.bundle.min.js", .method=HTTP_GET,  .handler=js_get,             .user_ctx=NULL};
    httpd_uri_t ui_bs_js_map = {.uri="/js/bootstrap.bundle.min.js.map", .method=HTTP_GET,  .handler=js_get,             .user_ctx=NULL};
    httpd_uri_t ui_bs_css    = {.uri="/css/bootstrap.min.css",    .method=HTTP_GET,  .handler=css_get,            .user_ctx=NULL};
    httpd_uri_t ui_bs_css_map= {.uri="/css/bootstrap.min.css.map",    .method=HTTP_GET,  .handler=css_get,            .user_ctx=NULL};
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
}

esp_err_t web_server_start(void){
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(spiffs_init());
    ESP_ERROR_CHECK(userdb_init());
    ESP_ERROR_CHECK(audit_init(128));
    ESP_ERROR_CHECK(auth_init());
    
    start_web();

    zones_load_from_nvs();

    ESP_LOGI(TAG, "Pronto. Apri http://<esp-ip>");
    return ESP_OK;
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
