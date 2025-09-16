#pragma once
#include "esp_err.h"
#include "esp_http_server.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int64_t ts_us;           // esp_timer_get_time()
    char event[16];          // "login","logout","user_create","user_del","user_setpwd"
    char username[32];       // subject username (or attempted user for login)
    int result;              // 1 ok, 0 fail
    char note[64];           // short note/reason
} audit_entry_t;

esp_err_t audit_init(size_t capacity /* e.g., 128 */);
void audit_append(const char* event, const char* username, int result, const char* note);

// Stream gli ultimi 'limit' eventi come JSON array nella response (admin API)
esp_err_t audit_stream_json(httpd_req_t* req, size_t limit);

#ifdef __cplusplus
}
#endif
