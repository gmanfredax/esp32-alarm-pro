#pragma once
// main/auth.h — Facciata di autenticazione/sessioni. Tutto il DB utenti è in userdb.*

#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"
#include "esp_http_server.h"

#ifdef __cplusplus
extern "C" {
#endif

// ===== Ruoli (coerenti con la UI: admin se role >= 2)
typedef enum {
    ROLE_GUEST = 0,
    ROLE_USER  = 1,
    ROLE_ADMIN = 2
} user_role_t;

// Info utente minimale (usata in /api/me, gate ecc.)
typedef struct {
    char        username[32];
    user_role_t role;
} user_info_t;

// ===== Init del sottosistema auth (sessioni + userdb_init all'interno)
esp_err_t auth_init(void);

// ===== Header di sicurezza comuni alle risposte HTTP
void auth_set_security_headers(httpd_req_t* req);

// ===== Gate per servire HTML protetto (redirect a /login.html o 403.html)
// Ritorna true se la pagina può essere servita (utente autenticato e con ruolo sufficiente).
bool auth_gate_html(httpd_req_t* req, user_role_t required);

// ===== Check autenticazione su richiesta HTTP
// - Bearer: Authorization: Bearer <token> (access token di sessione)
// - Cookie: Cookie: SID=<session-id>
bool auth_check_bearer(httpd_req_t* req, user_info_t* out /* può essere NULL */);
bool auth_check_cookie (httpd_req_t* req, user_info_t* out /* può essere NULL */);

// ===== Handlers HTTP principali
esp_err_t auth_handle_login (httpd_req_t* req);  // POST /api/login  {user,pass}
esp_err_t auth_handle_logout(httpd_req_t* req);  // POST /api/logout
esp_err_t auth_handle_me    (httpd_req_t* req);  // GET  /api/me

// ===== Wrapper verso userdb — password / utenti / anagrafiche
bool      auth_verify_password (const char* username, const char* password);
esp_err_t auth_set_password    (const char* username, const char* new_password);

esp_err_t auth_list_users      (char* csv_out, size_t out_size); // CSV "user1,user2,..."
esp_err_t auth_create_user     (const char* username,
                                const char* first_name,
                                const char* last_name,
                                const char* initial_password);

esp_err_t auth_set_user_name   (const char* username,
                                const char* first_name,
                                const char* last_name);
esp_err_t auth_get_user_name   (const char* username,
                                char* first_name, size_t fn_size,
                                char* last_name,  size_t ln_size);

// ===== PIN
bool      auth_has_pin         (const char* username);
esp_err_t auth_set_pin         (const char* username, const char* new_pin);
bool      auth_verify_pin      (const char* username, const char* candidate_pin);

// ===== RFID
esp_err_t auth_set_rfid_uid    (const char* username, const uint8_t* uid, size_t uid_len);
int       auth_get_rfid_uid    (const char* username, uint8_t* uid_out, size_t max_len);
esp_err_t auth_clear_rfid_uid  (const char* username);

// ===== TOTP
esp_err_t auth_totp_enable     (const char* username, const char* base32_secret);
esp_err_t auth_totp_disable    (const char* username);
bool      auth_totp_enabled    (const char* username);
bool      auth_check_totp_for_user(const char* username, const char* otp);
bool      auth_totp_store_pending(httpd_req_t* req, const char* secret_base32);
bool      auth_totp_get_pending  (httpd_req_t* req, char* out, size_t out_cap);
void      auth_totp_clear_pending(httpd_req_t* req);

#ifdef __cplusplus
}
#endif
