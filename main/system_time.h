#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SYSTEM_TIME_SOURCE_UNKNOWN = 0,
    SYSTEM_TIME_SOURCE_SNTP,
    SYSTEM_TIME_SOURCE_BROWSER_MANUAL,
} system_time_source_t;

bool system_time_is_valid(void);
system_time_source_t system_time_source(void);
const char *system_time_source_name(void);
bool system_time_sntp_syncing(void);
const char *system_time_sync_status(void);
int64_t system_time_last_sync_unix(void);
void system_time_mark_sntp_synced(int64_t unix_time);
esp_err_t system_time_sntp_start_async(const char *reason);
esp_err_t system_time_set_browser_manual(int64_t unix_time, const char *timezone);
esp_err_t system_time_append_json(cJSON *root);

#ifdef __cplusplus
}
#endif
