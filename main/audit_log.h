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
    int64_t wall_ts_us;      // absolute wall-clock timestamp (gettimeofday), 0 if unknown
} audit_entry_t;

esp_err_t audit_init(size_t capacity /* e.g., 128 */);
void audit_append(const char* event, const char* username, int result, const char* note);
esp_err_t audit_clear_all(void);

// Stream gli ultimi 'limit' eventi come JSON array nella response (admin API)
esp_err_t audit_stream_json(httpd_req_t* req, size_t limit);

// Copia gli ultimi eventi (in ordine cronologico) dentro l'array out.
int audit_dump_recent(audit_entry_t* out, size_t max);

#ifdef __cplusplus
}
#endif
