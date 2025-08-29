#pragma once
#include <stdbool.h>
#include "esp_err.h"
typedef struct {
    char user[16];
    uint8_t pass_sha256[32];
    bool totp_enabled;
    char totp_base32[32]; // base32 secret (max 160-bit)
} user_record_t;

esp_err_t auth_init(void);
bool auth_verify_password(const char* user, const char* pass);
bool auth_verify_totp_if_enabled(const char* user, const char* otp6digits);
esp_err_t auth_get_user(user_record_t* out);
esp_err_t auth_set_password(const char* user, const char* newpass);
esp_err_t auth_set_totp(const char* user, bool enabled, const char* base32_or_null);
