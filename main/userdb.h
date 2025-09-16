#pragma once
#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { UDB_ROLE_GUEST  = 0, UDB_ROLE_USER  = 1, UDB_ROLE_ADMIN = 2, } udb_role_t;

esp_err_t   userdb_init(void);
bool        userdb_exists(const char* username);
size_t      userdb_list_csv(char* buf, size_t buflen);

bool        userdb_verify_password(const char* username, const char* password, udb_role_t* out_role);
esp_err_t   userdb_set_password(const char* username, const char* new_password);
esp_err_t   userdb_create_user(const char* username, udb_role_t role, const char* password);
esp_err_t   userdb_delete_user(const char* username);

esp_err_t   userdb_set_name(const char* user, const char* first, const char* last);
esp_err_t   userdb_get_name(const char* user, char* first, size_t fcap, char* last, size_t lcap);

bool        userdb_has_pin(const char* user);
esp_err_t   userdb_set_pin(const char* user, const char* pin);
bool        userdb_verify_pin(const char* user, const char* pin);

esp_err_t   userdb_set_rfid(const char* user, const uint8_t* uid, size_t uid_len);
int         userdb_get_rfid(const char* user, uint8_t* uid_out, size_t max_len);
esp_err_t   userdb_clear_rfid(const char* user);

esp_err_t   userdb_totp_enable(const char* user, const char* base32_secret);
esp_err_t   userdb_totp_disable(const char* user);
bool        userdb_totp_is_enabled(const char* user);
bool        userdb_totp_verify(const char* user, const char* otp);

#ifdef __cplusplus
}
#endif
