// main/auth.c — versione MIGRATA 100% su userdb
#include "auth.h"
#include "userdb.h"
#include "audit_log.h"

#include "esp_log.h"
#include "esp_err.h"
#include "esp_system.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_http_server.h"

#include "mbedtls/base64.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

#ifndef HTTPD_429_TOO_MANY_REQUESTS
#define HTTPD_429_TOO_MANY_REQUESTS 429
#endif
#ifndef HTTPD_503_SERVICE_UNAVAILABLE
#define HTTPD_503_SERVICE_UNAVAILABLE 503
#endif

static const char* TAG = "auth";

// ====== CONFIG ======
#define SESSION_MAX            16
#define ABS_TTL_SEC            (7*24*3600)    // 7 giorni
#define IDLE_TTL_SEC           (5*60)        // 30 minuti
#define SID_LEN                48             // bytes raw -> base64 ~64
#define ATK_LEN                48
#define CSRF_LEN               16

typedef struct {
    bool used;
    char sid_b64[96];
    char atk_b64[96];
    char csrf_b64[32];
    char username[32];
    user_role_t role;
    time_t created;
    time_t last_seen;
    time_t expires_abs;
    char  pending_totp_secret[64];
    time_t pending_totp_time;
} session_t;

static session_t g_sessions[SESSION_MAX];

#define TOTP_PENDING_TTL_SEC    (10*60)

// ===== Rate limit (per username) =============================================
#define RL_MAX_TRACK 32
#define RL_MAX_FAILS 5
#define RL_LOCK_SEC  (5*60)
#define RL_WIN_SEC   (15*60)

typedef struct { char key[32]; int fails; int64_t win_us; int64_t lock_until_us; } rl_item_t;
static rl_item_t s_rl[RL_MAX_TRACK];

static int64_t now_us(void){ return esp_timer_get_time(); }
static rl_item_t* rl_find_or_make(const char* key){
    int free_i=-1;
    for(int i=0;i<RL_MAX_TRACK;i++){
        if(!s_rl[i].key[0]){ if(free_i<0) free_i=i; continue; }
        if(strncmp(s_rl[i].key,key,sizeof(s_rl[i].key))==0) return &s_rl[i];
    }
    if(free_i>=0){ memset(&s_rl[free_i],0,sizeof(s_rl[free_i])); strncpy(s_rl[free_i].key,key,sizeof(s_rl[free_i].key)-1); return &s_rl[free_i]; }
    return NULL;
}
static bool rl_check_locked(rl_item_t* it, int* retry_after){
    int64_t now = now_us();
    if(it && it->lock_until_us > now){
        if(retry_after) *retry_after = (int)((it->lock_until_us - now)/1000000);
        return true;
    }
    return false;
}
static void rl_on_fail(rl_item_t* it){
    int64_t now = now_us();
    if(it->win_us==0 || now - it->win_us > (int64_t)RL_WIN_SEC*1000000){ it->win_us = now; it->fails = 0; }
    if(++it->fails >= RL_MAX_FAILS){ it->lock_until_us = now + (int64_t)RL_LOCK_SEC*1000000; it->fails = 0; it->win_us = now; }
}
static void rl_on_success(rl_item_t* it){ it->fails=0; it->win_us=now_us(); it->lock_until_us=0; }

// ===== Helpers sessioni/cookie ===============================================
static void b64_of_random(size_t raw_len, char* out_b64, size_t out_cap){
    uint8_t raw[128];
    if (raw_len > sizeof(raw)) raw_len = sizeof(raw);
    for (size_t i=0;i<raw_len;i++){ raw[i] = (uint8_t) (esp_random() & 0xFF); }
    size_t olen = 0;
    (void) mbedtls_base64_encode((unsigned char*)out_b64, out_cap, &olen, raw, raw_len);
    if (olen < out_cap) out_b64[olen] = 0; else out_b64[out_cap-1] = 0;
}

static session_t* find_by_sid(const char* sid_b64){
    if (!sid_b64) return NULL;
    for (int i=0;i<SESSION_MAX;i++){
        if (g_sessions[i].used && strcmp(g_sessions[i].sid_b64, sid_b64)==0) return &g_sessions[i];
    }
    return NULL;
}
static session_t* find_by_atk(const char* atk_b64){
    if (!atk_b64) return NULL;
    for (int i=0;i<SESSION_MAX;i++){
        if (g_sessions[i].used && strcmp(g_sessions[i].atk_b64, atk_b64)==0) return &g_sessions[i];
    }
    return NULL;
}
static session_t* alloc_session(void){
    time_t now = time(NULL);
    for (int i=0;i<SESSION_MAX;i++){
        if (g_sessions[i].used){
            if (now >= g_sessions[i].expires_abs) g_sessions[i].used = false;
        }
    }
    for (int i=0;i<SESSION_MAX;i++){
        if (!g_sessions[i].used){
            memset(&g_sessions[i],0,sizeof(g_sessions[i]));
            g_sessions[i].used = true;
            return &g_sessions[i];
        }
    }
    return NULL;
}
static void touch_session(session_t* s){
    time_t now = time(NULL);
    s->last_seen = now;
    s->expires_abs = (now - s->created > ABS_TTL_SEC) ? s->expires_abs : (now + IDLE_TTL_SEC);
}

// Costruisce la stringa Set-Cookie nel frame chiamante (evita buffer dangling)
static int build_cookie_sid(char* out, size_t outcap, const char* sid_b64){
    if (!out || outcap==0 || !sid_b64 || !sid_b64[0]) return -1;
    // Aggiungi "Secure" se servi in HTTPS
    int n = snprintf(out, outcap, "SID=%s; HttpOnly; Path=/; SameSite=Lax; Secure", sid_b64);
    return (n > 0 && n < (int)outcap) ? n : -1;
}

static bool get_cookie_value(httpd_req_t* req, const char* key, char* out, size_t cap){
    size_t len = httpd_req_get_hdr_value_len(req, "Cookie");
    if (!len) return false;
    char* cookie = malloc(len+1);
    if (!cookie) return false;
    if (httpd_req_get_hdr_value_str(req,"Cookie",cookie,len+1)!=ESP_OK){ free(cookie); return false; }
    bool found=false;
    char* tok = strtok(cookie,";");
    while(tok){
        while(*tok==' ') tok++;
        char* eq = strchr(tok,'=');
        if (eq){
            *eq = 0;
            const char* k = tok;
            const char* v = eq+1;
            if (strcmp(k,key)==0){
                strncpy(out,v,cap-1);
                out[cap-1]=0;
                found=true; break;
            }
        }
        tok = strtok(NULL,";");
    }
    free(cookie);
    return found;
}

static session_t* session_from_request(httpd_req_t* req){
    if (!req) return NULL;
    size_t len = httpd_req_get_hdr_value_len(req, "Authorization");
    if (len){
        char* hdr = malloc(len+1);
        if (hdr){
            if (httpd_req_get_hdr_value_str(req, "Authorization", hdr, len+1) == ESP_OK){
                if (!strncmp(hdr, "Bearer ", 7)){
                    const char* token = hdr + 7;
                    session_t* s = find_by_atk(token);
                    if (s){
                        touch_session(s);
                        free(hdr);
                        return s;
                    }
                }
            }
            free(hdr);
        }
    }
    char sid[128] = {0};
    if (get_cookie_value(req, "SID", sid, sizeof(sid))){
        session_t* s = find_by_sid(sid);
        if (s){
            touch_session(s);
            return s;
        }
    }
    return NULL;
}

// ===== Sicurezza / headers ====================================================
static void security_headers(httpd_req_t* req){
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_set_hdr(req, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(req, "X-Frame-Options", "DENY");
    httpd_resp_set_hdr(req, "Referrer-Policy", "same-origin");
    httpd_resp_set_hdr(req, "Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    httpd_resp_set_hdr(req, "Content-Security-Policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; frame-ancestors 'none'");
}
void auth_set_security_headers(httpd_req_t* req){ security_headers(req); }

// ===== Gate HTML (redirect a login o 403) ====================================
static esp_err_t send_file_from_spiffs(httpd_req_t* req, const char* path){
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
    security_headers(req);
    char buf[1024];
    size_t r;
    while((r=fread(buf,1,sizeof(buf),f))>0){
        if (httpd_resp_send_chunk(req, buf, r)!=ESP_OK){ fclose(f); httpd_resp_sendstr_chunk(req, NULL); return ESP_FAIL; }
    }
    fclose(f);
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

bool auth_gate_html(httpd_req_t* req, user_role_t required){
    user_info_t u = {0};
    if (!auth_check_cookie(req,&u)){
        httpd_resp_set_status(req,"302 Found");
        httpd_resp_set_hdr(req,"Location","/login.html");
        security_headers(req);
        httpd_resp_send(req, NULL, 0);
        return false;
    }
    if ((int)u.role < (int)required){
        return (send_file_from_spiffs(req, "/spiffs/403.html")==ESP_OK);
    }
    return true;
}

// ===== Body JSON ==============================================================
static esp_err_t parse_json_from_body(httpd_req_t* req, char** out, size_t* out_len){
    int total = req->content_len;
    if (total <=0 || total > 4096) return ESP_FAIL;
    char* buf = malloc(total+1);
    if (!buf) return ESP_ERR_NO_MEM;
    int rd = 0;
    while(rd < total){
        int r = httpd_req_recv(req, buf+rd, total-rd);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (r <= 0){ free(buf); return ESP_FAIL; }
        rd += r;
    }
    buf[rd]=0;
    *out = buf; if (out_len) *out_len = rd;
    return ESP_OK;
}
static esp_err_t json_reply(httpd_req_t* req, const char* json){
    httpd_resp_set_type(req,"application/json");
    security_headers(req);
    return httpd_resp_sendstr(req, json);
}

// ===== Check Authorization / Cookie ==========================================
bool auth_check_bearer(httpd_req_t* req, user_info_t* out){
    size_t n = httpd_req_get_hdr_value_len(req, "Authorization");
    if (!n) return false;
    char* h = malloc(n+1);
    if (!h) return false;
    if (httpd_req_get_hdr_value_str(req,"Authorization",h,n+1)!=ESP_OK){ free(h); return false; }
    bool ok = false;
    if (!strncmp(h,"Bearer ",7)){
        const char* token = h+7;
        session_t* s = find_by_atk(token);
        if (s){
            touch_session(s);
            if (out){ strncpy(out->username, s->username, sizeof(out->username)-1); out->role = s->role; }
            ok = true;
        }
    }
    free(h);
    return ok;
}
bool auth_check_cookie(httpd_req_t* req, user_info_t* out){
    char sid[128]={0};
    if (!get_cookie_value(req,"SID",sid,sizeof(sid))) return false;
    session_t* s = find_by_sid(sid);
    if (!s) return false;
    touch_session(s);
    if (out){ strncpy(out->username, s->username, sizeof(out->username)-1); out->role=s->role; }
    return true;
}

// ===== LOGIN / LOGOUT / ME ===================================================
static bool valid_user_pass(const char* user, const char* pass, user_role_t* out_role){
    if (!user || !pass || !out_role) return false;
    udb_role_t r = UDB_ROLE_USER;
    if (!userdb_verify_password(user, pass, &r)) return false;
    *out_role = (r == UDB_ROLE_ADMIN) ? ROLE_ADMIN : ROLE_USER;
    return true;
}

esp_err_t auth_handle_login(httpd_req_t* req){
    char* body=NULL; size_t blen=0;
    if (parse_json_from_body(req,&body,&blen)!=ESP_OK){
        return httpd_resp_send_err(req,HTTPD_400_BAD_REQUEST,"bad body");
    }
    char user[32]={0}, pass[64]={0};
    char otp[16]={0};
    const char* u = strstr(body,"\"user\"");
    const char* p = strstr(body,"\"pass\"");
    if (u){ u = strchr(u,':'); if(u){ while(*u && (*u==' '||*u==':'||*u=='\"')) u++; char* e = strchr(u,'\"'); if(e){ size_t n=(size_t)(e-u); if(n>sizeof(user)-1)n=sizeof(user)-1; memcpy(user,u,n); user[n]=0; } } }
    if (p){ p = strchr(p,':'); if(p){ while(*p && (*p==' '||*p==':'||*p=='\"')) p++; char* e = strchr(p,'\"'); if(e){ size_t n=(size_t)(e-p); if(n>sizeof(pass)-1)n=sizeof(pass)-1; memcpy(pass,p,n); pass[n]=0; } } }
    const char* o = strstr(body,"\"otp\"");
    if (o){ o = strchr(o,':'); if(o){ while(*o && (*o==' '||*o==':'||*o=='\"')) o++; char* e = strchr(o,'\"'); if(e){ size_t n=(size_t)(e-o); if(n>sizeof(otp)-1)n=sizeof(otp)-1; memcpy(otp,o,n); otp[n]=0; } } }
    free(body);

    // Rate limit per-username
    rl_item_t* rl = rl_find_or_make(user[0]?user:"(empty)");
    int retry_after=0;
    if (rl && rl_check_locked(rl, &retry_after)){
        char hdr[64]; snprintf(hdr,sizeof(hdr),"%d", retry_after);
        httpd_resp_set_hdr(req,"Retry-After", hdr);
        audit_append("login", user, 0, "locked");
        return httpd_resp_send_err(req,HTTPD_429_TOO_MANY_REQUESTS,"locked");
    }

    user_role_t role;
    if (!valid_user_pass(user,pass,&role)){
        if (rl) rl_on_fail(rl);
        audit_append("login", user, 0, "invalid");
        return httpd_resp_send_err(req,HTTPD_401_UNAUTHORIZED,"invalid");
    }

    if (auth_totp_enabled(user)){
        if (!otp[0]){
            audit_append("login", user, 0, "otp required");
            httpd_resp_set_status(req, "401 Unauthorized");
            return json_reply(req, "{\"otp_required\":true}");
        }
        if (!auth_check_totp_for_user(user, otp)){
            if (rl) rl_on_fail(rl);
            audit_append("login", user, 0, "otp invalid");
            httpd_resp_set_status(req, "401 Unauthorized");
            return json_reply(req, "{\"otp_required\":true}");
        }
    }

    if (rl) rl_on_success(rl);

    session_t* s = alloc_session();
    if (!s){ audit_append("login", user, 0, "no slots"); return httpd_resp_send_err(req,HTTPD_503_SERVICE_UNAVAILABLE,"no slots"); }

    b64_of_random(SID_LEN,  s->sid_b64,  sizeof(s->sid_b64));
    b64_of_random(ATK_LEN,  s->atk_b64,  sizeof(s->atk_b64));
    b64_of_random(CSRF_LEN, s->csrf_b64, sizeof(s->csrf_b64));
    strncpy(s->username, user, sizeof(s->username)-1);
    s->role = role;

    time_t now = time(NULL);
    s->created   = now;
    s->last_seen = now;
    s->expires_abs = now + IDLE_TTL_SEC;

    // Set-Cookie
    char cookie[160];
    if (build_cookie_sid(cookie, sizeof(cookie), s->sid_b64) < 0){
        audit_append("login", user, 0, "cookie build fail");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "cookie");
    }
    httpd_resp_set_hdr(req, "Set-Cookie", cookie);

    char resp[256];
    snprintf(resp,sizeof(resp),
        "{\"ok\":true,\"user\":\"%s\",\"role\":%d,\"token\":\"%s\"}",
        s->username, (int)s->role, s->atk_b64);
    audit_append("login", user, 1, "ok");
    return json_reply(req, resp);
}

esp_err_t auth_handle_logout(httpd_req_t* req){
    const char* who = NULL; user_info_t u; if (auth_check_cookie(req,&u) || auth_check_bearer(req,&u)) who = u.username;
    char sid[128]={0};
    bool done=false;
    if (get_cookie_value(req,"SID",sid,sizeof(sid))){
        session_t* s = find_by_sid(sid);
        if (s){ s->used=false; done=true; }
    } else {
        user_info_t tmp;
        if (auth_check_bearer(req,&tmp)){
            size_t n = httpd_req_get_hdr_value_len(req, "Authorization");
            char* h = malloc(n+1);
            httpd_req_get_hdr_value_str(req,"Authorization",h,n+1);
            const char* token = h+7;
            session_t* s = find_by_atk(token);
            if (s){ s->used=false; done=true; }
            free(h);
        }
    }
    (void)done;
    httpd_resp_set_hdr(req,"Set-Cookie","SID=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure");
    audit_append("logout", who?who:"", 1, "ok");
    return json_reply(req,"{\"ok\":true}");
}

esp_err_t auth_handle_me(httpd_req_t* req){
    user_info_t u={0};
    if (auth_check_bearer(req,&u) || auth_check_cookie(req,&u)){
        char resp[200];
        bool is_admin = ((int)u.role >= (int)ROLE_ADMIN);
        snprintf(resp,sizeof(resp),"{\"ok\":true,\"user\":\"%s\",\"role\":%d,\"is_admin\":%s}", u.username,(int)u.role,is_admin?"true":"false");
        return json_reply(req, resp);
    }
    return httpd_resp_send_err(req,HTTPD_401_UNAUTHORIZED,"no auth");
}

// ===== API di utilità per web_server.c: DELEGA a userdb ======================
// Password
bool auth_verify_password(const char* username, const char* password){
    if (!username || !password) return false;
    return userdb_verify_password(username, password, NULL);
}
esp_err_t auth_set_password(const char* username, const char* new_password){
    if (!username || !new_password) return ESP_ERR_INVALID_ARG;
    return userdb_set_password(username, new_password);
}

// Lista / Create / Nomi
esp_err_t auth_list_users(char* csv_out, size_t out_size){
    if(!csv_out || out_size==0) return ESP_ERR_INVALID_ARG;
    (void)userdb_list_csv(csv_out, out_size);
    return ESP_OK;
}
esp_err_t auth_create_user(const char* username, const char* first_name, const char* last_name, const char* initial_password){
    if(!username || !username[0]) return ESP_ERR_INVALID_ARG;
    if (userdb_exists(username)) return ESP_ERR_INVALID_STATE;
    const char* pw = (initial_password && initial_password[0]) ? initial_password : "user";
    esp_err_t err = userdb_create_user(username, UDB_ROLE_USER, pw);
    if (err != ESP_OK) return err;
    (void)userdb_set_name(username, first_name?first_name:"", last_name?last_name:"");
    return ESP_OK;
}
esp_err_t auth_set_user_name(const char* username, const char* first_name, const char* last_name){
    return userdb_set_name(username, first_name?first_name:"", last_name?last_name:"");
}
esp_err_t auth_get_user_name(const char* username, char* first_name, size_t fn_size, char* last_name, size_t ln_size){
    return userdb_get_name(username, first_name, fn_size, last_name, ln_size);
}

// PIN
bool auth_has_pin(const char* username){
    return userdb_has_pin(username);
}
esp_err_t auth_set_pin(const char* username, const char* new_pin){
    return userdb_set_pin(username, new_pin);
}
bool auth_verify_pin(const char* username, const char* candidate_pin){
    return userdb_verify_pin(username, candidate_pin);
}

// RFID
esp_err_t auth_set_rfid_uid(const char* username, const uint8_t* uid, size_t uid_len){
    return userdb_set_rfid(username, uid, uid_len);
}
int auth_get_rfid_uid(const char* username, uint8_t* uid_out, size_t max_len){
    return userdb_get_rfid(username, uid_out, max_len);
}
esp_err_t auth_clear_rfid_uid(const char* username){
    return userdb_clear_rfid(username);
}

// TOTP
esp_err_t auth_totp_enable(const char* username, const char* base32_secret){
    return userdb_totp_enable(username, base32_secret);
}
esp_err_t auth_totp_disable(const char* username){
    return userdb_totp_disable(username);
}
bool auth_totp_enabled(const char* username){
    return userdb_totp_is_enabled(username);
}
bool auth_check_totp_for_user(const char* username, const char* otp){
    return userdb_totp_verify(username, otp);
}

bool auth_totp_store_pending(httpd_req_t* req, const char* secret_base32){
    session_t* s = session_from_request(req);
    if (!s) return false;
    if (secret_base32 && secret_base32[0]){
        strncpy(s->pending_totp_secret, secret_base32, sizeof(s->pending_totp_secret)-1);
        s->pending_totp_secret[sizeof(s->pending_totp_secret)-1] = 0;
        s->pending_totp_time = time(NULL);
    } else {
        s->pending_totp_secret[0] = 0;
        s->pending_totp_time = 0;
    }
    return true;
}

bool auth_totp_get_pending(httpd_req_t* req, char* out, size_t out_cap){
    if (!out || out_cap == 0) return false;
    session_t* s = session_from_request(req);
    if (!s || !s->pending_totp_secret[0]) return false;
    time_t now = time(NULL);
    if (!s->pending_totp_time || (now - s->pending_totp_time) > TOTP_PENDING_TTL_SEC){
        s->pending_totp_secret[0] = 0;
        s->pending_totp_time = 0;
        return false;
    }
    strlcpy(out, s->pending_totp_secret, out_cap);
    return true;
}

void auth_totp_clear_pending(httpd_req_t* req){
    session_t* s = session_from_request(req);
    if (!s) return;
    s->pending_totp_secret[0] = 0;
    s->pending_totp_time = 0;
}

// ===== Init ==================================================================
esp_err_t auth_init(void){
    memset(g_sessions,0,sizeof(g_sessions));
    userdb_init(); // inizializza DB utenti + eventuale bootstrap admin/user
    ESP_LOGI(TAG,"auth_init: session table ready (%d slots)", SESSION_MAX);
    return ESP_OK;
}
