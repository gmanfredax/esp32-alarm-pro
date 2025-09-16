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


static const char* TAG="userdb";
static nvs_handle_t s_nvs = 0;
#define UDB_NS "usrdb"
#define ITER_DEFAULT 50000

typedef struct __attribute__((packed)){
    uint8_t ver;      // =1
    uint8_t role;     // 0 guest,1 user,2 admin
    uint32_t iter;    // numero iterazioni hash
    uint8_t salt[16]; // random
    uint8_t hash[32]; // sha256 iterata
} user_rec_v1_t;

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

static esp_err_t load_user(const char* username, user_rec_v1_t* out){
    char key[32]; k_userkey(username,key);
    size_t sz = sizeof(*out);
    return nvs_get_blob(s_nvs, key, out, &sz);
}

static esp_err_t store_user(const char* username, const user_rec_v1_t* rec){
    char key[32]; k_userkey(username,key);
    esp_err_t err = nvs_set_blob(s_nvs, key, rec, sizeof(*rec));
    if (err==ESP_OK) err = nvs_commit(s_nvs);
    return err;
}

bool userdb_exists(const char* username){
    user_rec_v1_t r;
    return load_user(username,&r)==ESP_OK;
}

esp_err_t userdb_create_user(const char* username, udb_role_t role, const char* password){
    if (!username || !*username || !password) return ESP_ERR_INVALID_ARG;
    user_rec_v1_t rec = {0};
    rec.ver = 1;
    rec.role = (uint8_t)role;
    rec.iter = ITER_DEFAULT;
    random_bytes(rec.salt, sizeof(rec.salt));
    hash_password_iter(password, rec.salt, rec.iter, rec.hash);
    return store_user(username, &rec);
}

esp_err_t userdb_set_password(const char* username, const char* new_password){
    if (!username || !new_password) return ESP_ERR_INVALID_ARG;
    user_rec_v1_t rec;
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
    user_rec_v1_t rec;
    if (load_user(username,&rec)!=ESP_OK) return false;
    uint8_t h[32];
    hash_password_iter(password, rec.salt, rec.iter, h);
    if (memcmp(h, rec.hash, 32)!=0) return false;
    if (out_role) *out_role = (udb_role_t)rec.role;
    return true;
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
    esp_err_t err = nvs_entry_find(NULL /* partition */,
                                   UDB_NS /* namespace */,
                                   NVS_TYPE_BLOB /* tipo record utenti */,
                                   &it);
    if (err != ESP_OK) {
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

