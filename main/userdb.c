#include "userdb.h"
#include "esp_system.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_log.h"
#include "mbedtls/sha256.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "esp_random.h"         // <-- IDF 5.x: NON è più incluso da esp_system.h
#include "mbedtls/version.h"
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
  // mbedTLS 3.x: funzioni senza _ret
  #define mbedtls_sha256_starts_ret  mbedtls_sha256_starts
  #define mbedtls_sha256_update_ret  mbedtls_sha256_update
  #define mbedtls_sha256_finish_ret  mbedtls_sha256_finish
#endif

#include "totp.h"


static const char* TAG="userdb";
static nvs_handle_t s_nvs = 0;
#define UDB_NS "usrdb"
#define ITER_DEFAULT 10000

#define USER_REC_VER 2
#define PIN_SALT_LEN  8
#define PIN_HASH_LEN  32
#define RFID_MAX_LEN  16
#define TOTP_MAX_LEN  48

typedef struct __attribute__((packed)){
    uint8_t ver;               // versione record (2 = con metadati estesi)
    uint8_t role;              // 0 guest,1 user,2 admin
    uint32_t iter;             // numero iterazioni hash password
    uint8_t salt[16];          // salt password
    uint8_t hash[32];          // hash password iterata
    char    first_name[32];    // nome (UTF-8)
    char    last_name[32];     // cognome (UTF-8)
    uint8_t pin_salt[PIN_SALT_LEN];
    uint8_t pin_hash[PIN_HASH_LEN];
    uint8_t pin_set;           // 0=no PIN, 1=PIN presente
    uint8_t rfid_len;          // lunghezza UID RFID
    uint8_t rfid[RFID_MAX_LEN];// dati UID RFID
    uint8_t totp_enabled;      // 0=off, 1=abilitato
    char    totp_secret[TOTP_MAX_LEN]; // segreto Base32 (pulito)
} user_rec_t;

static void k_userkey(const char* username, char out[32]){
    char u[20]={0};
    size_t n = strlen(username);
    if (n>15) n=15;
    for(size_t i=0;i<n;i++){ char c=username[i]; u[i]=(char)tolower((unsigned char)c); }
    snprintf(out,32,"u_%s",u);
}

static void random_bytes(uint8_t* dst, size_t n){
    for (size_t i=0;i<n;i++) dst[i] = (uint8_t)(esp_random() & 0xFF);
}

static void sha256_once(const uint8_t* in, size_t inlen, uint8_t out32[32]){
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, in, inlen);
    mbedtls_sha256_finish(&ctx, out32);
    mbedtls_sha256_free(&ctx);
}

static void hash_password_iter(const char* password, const uint8_t salt[16], uint32_t iter, uint8_t out32[32]){
    uint8_t buf[64];
    size_t pwlen = strlen(password);
    if (pwlen > 48) pwlen = 48;
    memcpy(buf, salt, 16);
    memcpy(buf+16, password, pwlen);
    sha256_once(buf, 16+pwlen, out32);
    for (uint32_t i=1;i<iter;i++){
        sha256_once(out32, 32, out32);
    }
}

static void copy_string_field(char* dst, size_t cap, const char* src){
    if (!dst || cap == 0) return;
    if (!src){ dst[0] = 0; return; }
    size_t len = strlen(src);
    if (len >= cap) len = cap - 1;
    memcpy(dst, src, len);
    dst[len] = 0;
}

static bool pin_is_valid(const char* pin){
    if (!pin) return false;
    size_t len = strlen(pin);
    if (len < 4 || len > 8) return false;
    for (size_t i=0;i<len;i++){
        if (pin[i] < '0' || pin[i] > '9') return false;
    }
    return true;
}

static void hash_pin_value(const char* pin, const uint8_t salt[PIN_SALT_LEN], uint8_t out32[PIN_HASH_LEN]){
    uint8_t buf[PIN_SALT_LEN + 16];
    size_t len = strlen(pin);
    if (len > 16) len = 16;
    memcpy(buf, salt, PIN_SALT_LEN);
    memcpy(buf + PIN_SALT_LEN, pin, len);
    sha256_once(buf, PIN_SALT_LEN + len, out32);
    for (int i=0;i<999;i++){
        sha256_once(out32, PIN_HASH_LEN, out32);
    }
}

static size_t sanitize_base32(const char* in, char* out, size_t cap){
    if (!out || cap == 0) return 0;
    size_t w = 0;
    if (!in){ out[0] = 0; return 0; }
    for (const char* p=in; *p && w+1<cap; ++p){
        char c = *p;
        if (c==' ' || c=='-' || c=='\t') continue;
        if (c>='a' && c<='z') c = (char)(c - ('a'-'A'));
        if ((c>='A' && c<='Z') || (c>='2' && c<='7')){
            out[w++] = c;
        }
    }
    out[w] = 0;
    return w;
}

static esp_err_t load_user(const char* username, user_rec_t* out){
    char key[32]; k_userkey(username,key);
    memset(out, 0, sizeof(*out));
    size_t sz = sizeof(*out);
    esp_err_t err = nvs_get_blob(s_nvs, key, out, &sz);
    if (err == ESP_OK && out->ver == 0) {
        out->ver = 1; // record legacy senza campo ver esplicito
    }
    return err;
}

static esp_err_t store_user(const char* username, user_rec_t* rec){
    char key[32]; k_userkey(username,key);
    if (rec->ver < USER_REC_VER) rec->ver = USER_REC_VER;
    esp_err_t err = nvs_set_blob(s_nvs, key, rec, sizeof(*rec));
    if (err==ESP_OK) err = nvs_commit(s_nvs);
    return err;
}

bool userdb_exists(const char* username){
    user_rec_t r;
    return load_user(username,&r)==ESP_OK;
}

esp_err_t userdb_create_user(const char* username, udb_role_t role, const char* password){
    if (!username || !*username || !password) return ESP_ERR_INVALID_ARG;
    user_rec_t rec = {0};
    rec.ver = USER_REC_VER;
    rec.role = (uint8_t)role;
    rec.iter = ITER_DEFAULT;
    random_bytes(rec.salt, sizeof(rec.salt));
    hash_password_iter(password, rec.salt, rec.iter, rec.hash);
    return store_user(username, &rec);
}

esp_err_t userdb_set_password(const char* username, const char* new_password){
    if (!username || !new_password) return ESP_ERR_INVALID_ARG;
    user_rec_t rec;
    esp_err_t err = load_user(username,&rec);
    if (err != ESP_OK) return err;
    random_bytes(rec.salt, sizeof(rec.salt));
    rec.iter = ITER_DEFAULT;
    hash_password_iter(new_password, rec.salt, rec.iter, rec.hash);
    return store_user(username, &rec);
}

esp_err_t userdb_delete_user(const char* username){
    if (!username) return ESP_ERR_INVALID_ARG;
    if (strcasecmp(username,"admin")==0) return ESP_ERR_INVALID_STATE;
    char key[32]; k_userkey(username,key);
    esp_err_t err = nvs_erase_key(s_nvs, key);
    if (err==ESP_OK) err = nvs_commit(s_nvs);
    return err;
}

bool userdb_verify_password(const char* username, const char* password, udb_role_t* out_role){
    user_rec_t rec;
    if (load_user(username,&rec)!=ESP_OK) return false;
    uint8_t h[32];
    hash_password_iter(password, rec.salt, rec.iter, h);
    if (memcmp(h, rec.hash, 32)!=0) return false;
    if (out_role) *out_role = (udb_role_t)rec.role;
    return true;
}

esp_err_t userdb_set_name(const char* user, const char* first, const char* last){
    if (!user) return ESP_ERR_INVALID_ARG;
    user_rec_t rec;
    esp_err_t err = load_user(user, &rec);
    if (err != ESP_OK) return err;
    copy_string_field(rec.first_name, sizeof(rec.first_name), first ? first : "");
    copy_string_field(rec.last_name,  sizeof(rec.last_name),  last  ? last  : "");
    return store_user(user, &rec);
}

esp_err_t userdb_get_name(const char* user, char* first, size_t fcap, char* last, size_t lcap){
    if (!user) return ESP_ERR_INVALID_ARG;
    user_rec_t rec;
    esp_err_t err = load_user(user, &rec);
    if (err != ESP_OK) return err;
    if (first && fcap){ copy_string_field(first, fcap, rec.first_name); }
    if (last  && lcap){ copy_string_field(last,  lcap, rec.last_name); }
    return ESP_OK;
}

bool userdb_has_pin(const char* user){
    if (!user) return false;
    user_rec_t rec;
    if (load_user(user, &rec) != ESP_OK) return false;
    return rec.pin_set != 0;
}

esp_err_t userdb_set_pin(const char* user, const char* pin){
    if (!user) return ESP_ERR_INVALID_ARG;
    user_rec_t rec;
    esp_err_t err = load_user(user, &rec);
    if (err != ESP_OK) return err;

    if (!pin || !*pin){
        memset(rec.pin_salt, 0, sizeof(rec.pin_salt));
        memset(rec.pin_hash, 0, sizeof(rec.pin_hash));
        rec.pin_set = 0;
        return store_user(user, &rec);
    }

    if (!pin_is_valid(pin)) return ESP_ERR_INVALID_ARG;
    random_bytes(rec.pin_salt, sizeof(rec.pin_salt));
    hash_pin_value(pin, rec.pin_salt, rec.pin_hash);
    rec.pin_set = 1;
    return store_user(user, &rec);
}

bool userdb_verify_pin(const char* user, const char* pin){
    if (!user || !pin) return false;
    if (!pin_is_valid(pin)) return false;
    user_rec_t rec;
    if (load_user(user, &rec) != ESP_OK) return false;
    if (!rec.pin_set) return false;
    uint8_t h[PIN_HASH_LEN];
    hash_pin_value(pin, rec.pin_salt, h);
    return memcmp(h, rec.pin_hash, PIN_HASH_LEN) == 0;
}

esp_err_t userdb_set_rfid(const char* user, const uint8_t* uid, size_t uid_len){
    if (!user || !uid || uid_len == 0 || uid_len > RFID_MAX_LEN) return ESP_ERR_INVALID_ARG;
    user_rec_t rec;
    esp_err_t err = load_user(user, &rec);
    if (err != ESP_OK) return err;
    memset(rec.rfid, 0, sizeof(rec.rfid));
    memcpy(rec.rfid, uid, uid_len);
    rec.rfid_len = (uint8_t)uid_len;
    return store_user(user, &rec);
}

int userdb_get_rfid(const char* user, uint8_t* uid_out, size_t max_len){
    if (!user) return -1;
    user_rec_t rec;
    if (load_user(user, &rec) != ESP_OK) return -1;
    if (rec.rfid_len == 0) return 0;
    if (uid_out && max_len){
        size_t n = rec.rfid_len;
        if (n > max_len) n = max_len;
        memcpy(uid_out, rec.rfid, n);
    }
    return rec.rfid_len;
}

esp_err_t userdb_clear_rfid(const char* user){
    if (!user) return ESP_ERR_INVALID_ARG;
    user_rec_t rec;
    esp_err_t err = load_user(user, &rec);
    if (err != ESP_OK) return err;
    rec.rfid_len = 0;
    memset(rec.rfid, 0, sizeof(rec.rfid));
    return store_user(user, &rec);
}

esp_err_t userdb_totp_enable(const char* user, const char* base32_secret){
    if (!user || !base32_secret) return ESP_ERR_INVALID_ARG;
    user_rec_t rec;
    esp_err_t err = load_user(user, &rec);
    if (err != ESP_OK) return err;
    char clean[TOTP_MAX_LEN];
    size_t n = sanitize_base32(base32_secret, clean, sizeof(clean));
    if (n < 8) return ESP_ERR_INVALID_ARG;
    copy_string_field(rec.totp_secret, sizeof(rec.totp_secret), clean);
    rec.totp_enabled = 1;
    return store_user(user, &rec);
}

esp_err_t userdb_totp_disable(const char* user){
    if (!user) return ESP_ERR_INVALID_ARG;
    user_rec_t rec;
    esp_err_t err = load_user(user, &rec);
    if (err != ESP_OK) return err;
    rec.totp_enabled = 0;
    rec.totp_secret[0] = 0;
    return store_user(user, &rec);
}

bool userdb_totp_is_enabled(const char* user){
    if (!user) return false;
    user_rec_t rec;
    if (load_user(user, &rec) != ESP_OK) return false;
    return rec.totp_enabled != 0 && rec.totp_secret[0] != 0;
}

bool userdb_totp_verify(const char* user, const char* otp){
    if (!user || !otp) return false;
    user_rec_t rec;
    if (load_user(user, &rec) != ESP_OK) return false;
    if (!rec.totp_enabled || rec.totp_secret[0] == 0) return false;
    return totp_check(rec.totp_secret, otp);
}

static void bootstrap_if_missing(const char* username, udb_role_t role, const char* password){
    if (!userdb_exists(username)){
        if (userdb_create_user(username, role, password)==ESP_OK){
            ESP_LOGW(TAG,"Creato utente di bootstrap '%s' (cambiare password al primo accesso).", username);
        } else {
            ESP_LOGE(TAG,"Impossibile creare utente di bootstrap '%s'", username);
        }
    }
}

esp_err_t userdb_init(void){
    esp_err_t err = nvs_open(UDB_NS, NVS_READWRITE, &s_nvs);
    if (err != ESP_OK){
        ESP_LOGE(TAG,"nvs_open(%s) = %s", UDB_NS, esp_err_to_name(err));
        return err;
    }
    bootstrap_if_missing("admin", UDB_ROLE_ADMIN, "admin");
    bootstrap_if_missing("user",  UDB_ROLE_USER,  "user");
    return ESP_OK;
}

// Ritorna la lunghezza necessaria (CSV "user1,user2,..."), e scrive in buf se non NULL.
size_t userdb_list_csv(char* buf, size_t buflen)
{
    size_t needed = 0;
    size_t off = 0;

    nvs_iterator_t it = NULL;
    esp_err_t err = nvs_entry_find(NVS_DEFAULT_PART_NAME,
                                   UDB_NS /* namespace */,
                                   NVS_TYPE_BLOB /* tipo record utenti */,
                                   &it);
    if (err != ESP_OK) {
        if (err == ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGD(TAG, "Nessun utente presente in NVS (%s)", esp_err_to_name(err));
        } else {
            ESP_LOGE(TAG, "nvs_entry_find fallita: %s", esp_err_to_name(err));
        }
        if (buf && buflen) buf[0] = 0;
        return 0;
    }

    while (err == ESP_OK && it) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);                 // info.key = username
        size_t klen = strlen(info.key);

        // conteggio totale (virgola tra le voci)
        needed += klen + 1;

        if (buf && (off + klen + 1) < buflen) {
            memcpy(buf + off, info.key, klen);
            off += klen;
            buf[off++] = ',';                      // aggiungo separatore
        }

        err = nvs_entry_next(&it);                 // <-- NUOVA FIRMA (per puntatore)
    }
    nvs_release_iterator(it);

    // togli la virgola finale
    if (buf) {
        if (off > 0) buf[off - 1] = 0;
        else if (buflen) buf[0] = 0;
    }

    return needed ? (needed - 1) : 0;              // lunghezza senza l’ultima virgola
}

