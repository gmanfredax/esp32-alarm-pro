#include "system_time.h"

#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "esp_log.h"

#define SYSTEM_TIME_MIN_VALID_UNIX 1577836800LL /* 2020-01-01T00:00:00Z */
#define SYSTEM_TIME_MAX_VALID_UNIX 4102444800LL /* 2100-01-01T00:00:00Z */

static const char *TAG = "system_time";
static bool s_time_valid;
static system_time_source_t s_time_source = SYSTEM_TIME_SOURCE_UNKNOWN;
static int64_t s_last_sync_unix;
static char s_timezone[48] = "UTC";

static bool unix_time_plausible(int64_t unix_time)
{
    return unix_time >= SYSTEM_TIME_MIN_VALID_UNIX && unix_time < SYSTEM_TIME_MAX_VALID_UNIX;
}

bool system_time_is_valid(void)
{
    time_t now = time(NULL);
    return s_time_valid && unix_time_plausible((int64_t)now);
}

system_time_source_t system_time_source(void)
{
    return system_time_is_valid() ? s_time_source : SYSTEM_TIME_SOURCE_UNKNOWN;
}

const char *system_time_source_name(void)
{
    switch (system_time_source()) {
    case SYSTEM_TIME_SOURCE_SNTP: return "sntp";
    case SYSTEM_TIME_SOURCE_BROWSER_MANUAL: return "browser_manual";
    default: return "unknown";
    }
}

int64_t system_time_last_sync_unix(void)
{
    return system_time_is_valid() ? s_last_sync_unix : 0;
}

void system_time_mark_sntp_synced(int64_t unix_time)
{
    if (!unix_time_plausible(unix_time)) return;
    s_time_valid = true;
    s_time_source = SYSTEM_TIME_SOURCE_SNTP;
    s_last_sync_unix = unix_time;
    strlcpy(s_timezone, "UTC", sizeof(s_timezone));
}

esp_err_t system_time_set_browser_manual(int64_t unix_time, const char *timezone)
{
    if (!unix_time_plausible(unix_time)) return ESP_ERR_INVALID_ARG;
    struct timeval tv = { .tv_sec = (time_t)unix_time, .tv_usec = 0 };
    if (settimeofday(&tv, NULL) != 0) return ESP_FAIL;
    s_time_valid = true;
    s_time_source = SYSTEM_TIME_SOURCE_BROWSER_MANUAL;
    s_last_sync_unix = unix_time;
    if (timezone && timezone[0]) strlcpy(s_timezone, timezone, sizeof(s_timezone));
    else strlcpy(s_timezone, "browser", sizeof(s_timezone));
    ESP_LOGI(TAG, "Ora impostata manualmente da browser (source=%s)", system_time_source_name());
    return ESP_OK;
}

esp_err_t system_time_append_json(cJSON *root)
{
    if (!root) return ESP_ERR_INVALID_ARG;
    cJSON *time_obj = cJSON_AddObjectToObject(root, "time");
    if (!time_obj) return ESP_ERR_NO_MEM;
    time_t now = time(NULL);
    cJSON_AddBoolToObject(time_obj, "time_valid", system_time_is_valid());
    cJSON_AddStringToObject(time_obj, "source", system_time_source_name());
    cJSON_AddNumberToObject(time_obj, "unix_time", (double)now);
    cJSON_AddNumberToObject(time_obj, "last_sync_unix", (double)system_time_last_sync_unix());
    cJSON_AddStringToObject(time_obj, "timezone", s_timezone);
    return ESP_OK;
}
