#include "auth.h"
#include "storage.h"
#include "mbedtls/sha256.h"
#include <string.h>
#include <stdio.h>

#define NVS_USER_NS "users"
#define NVS_USER_KEY "admin"

static user_record_t g_user;

static void sha256(const char* s, uint8_t out[32]){
    mbedtls_sha256_context ctx; mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx,0);
    mbedtls_sha256_update(&ctx,(const unsigned char*)s, strlen(s));
    mbedtls_sha256_finish(&ctx,out);
    mbedtls_sha256_free(&ctx);
}

esp_err_t auth_init(void){
    size_t len = sizeof(g_user);
    esp_err_t err = storage_get_blob(NVS_USER_NS, NVS_USER_KEY, &g_user, &len);
    if (err != ESP_OK || len != sizeof(g_user)){
        memset(&g_user,0,sizeof(g_user));
        strcpy(g_user.user, "admin");
        sha256("admin", g_user.pass_sha256);
        g_user.totp_enabled = false;
        strcpy(g_user.totp_base32, "");
        storage_set_blob(NVS_USER_NS, NVS_USER_KEY, &g_user, sizeof(g_user));
    }
    return ESP_OK;
}

bool auth_verify_password(const char* user, const char* pass){
    if (!user || !pass) return false;
    if (strcmp(user,g_user.user)!=0) return false;
    uint8_t h[32]; sha256(pass,h);
    return memcmp(h,g_user.pass_sha256,32)==0;
}

// totp.c provides totp_check()
bool totp_check(const char* base32_secret, const char* otp6);
bool auth_verify_totp_if_enabled(const char* user, const char* otp6digits){
    if(strcmp(user,g_user.user)!=0) return false;
    if(!g_user.totp_enabled) return true;
    return totp_check(g_user.totp_base32, otp6digits);
}

esp_err_t auth_get_user(user_record_t* out){ if(!out) return ESP_ERR_INVALID_ARG; *out = g_user; return ESP_OK; }
esp_err_t auth_set_password(const char* user, const char* newpass){
    if(strcmp(user,g_user.user)!=0) return ESP_ERR_INVALID_ARG;
    sha256(newpass, g_user.pass_sha256);
    return storage_set_blob(NVS_USER_NS, NVS_USER_KEY, &g_user, sizeof(g_user));
}
esp_err_t auth_set_totp(const char* user, bool enabled, const char* base32){
    if(strcmp(user,g_user.user)!=0) return ESP_ERR_INVALID_ARG;
    g_user.totp_enabled = enabled;
    if(base32) strncpy(g_user.totp_base32, base32, sizeof(g_user.totp_base32)-1);
    return storage_set_blob(NVS_USER_NS, NVS_USER_KEY, &g_user, sizeof(g_user));
}
