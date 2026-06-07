#include "system_time.h"

#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "lwip/apps/sntp.h"

#define SYSTEM_TIME_MIN_VALID_UNIX 1577836800LL /* 2020-01-01T00:00:00Z */
#define SYSTEM_TIME_MAX_VALID_UNIX 4102444800LL /* 2100-01-01T00:00:00Z */

static const char *TAG = "system_time";
static bool s_time_valid;
static system_time_source_t s_time_source = SYSTEM_TIME_SOURCE_UNKNOWN;
static int64_t s_last_sync_unix;
static char s_timezone[48] = "UTC";
static TaskHandle_t s_sntp_task;
static bool s_sntp_initialized;

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

static void sntp_sync_task(void *arg)
{
    char reason[32] = {0};
    if (arg) {
        strlcpy(reason, (const char *)arg, sizeof(reason));
        free(arg);
    }
    ESP_LOGI(TAG, "sntp_start_after_ip reason=%s", reason[0] ? reason : "network_ip");
    if (!s_sntp_initialized && !sntp_enabled()) {
        sntp_setoperatingmode(SNTP_OPMODE_POLL);
        sntp_setservername(0, "time.google.com");
        sntp_init();
        s_sntp_initialized = true;
    }

    time_t now = 0;
    for (int tries = 0; tries < 30; ++tries) {
        time(&now);
        if (unix_time_plausible((int64_t)now)) break;
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    if (unix_time_plausible((int64_t)now)) {
        system_time_mark_sntp_synced((int64_t)now);
        ESP_LOGI(TAG, "sntp_sync_ok time_valid=true unix=%ld", (long)now);
    } else {
        ESP_LOGW(TAG, "sntp_sync_timeout time_valid=false");
    }
    s_sntp_task = NULL;
    vTaskDelete(NULL);
}

esp_err_t system_time_sntp_start_async(const char *reason)
{
    if (system_time_is_valid() && system_time_source() == SYSTEM_TIME_SOURCE_SNTP) return ESP_OK;
    if (s_sntp_task) return ESP_OK;
    char *task_reason = NULL;
    if (reason && reason[0]) {
        task_reason = strdup(reason);
        if (!task_reason) return ESP_ERR_NO_MEM;
    }
    BaseType_t ok = xTaskCreate(sntp_sync_task, "sntp_sync", 4096, task_reason, tskIDLE_PRIORITY + 2, &s_sntp_task);
    if (ok != pdPASS) {
        free(task_reason);
        s_sntp_task = NULL;
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
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
