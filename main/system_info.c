#include "system_info.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "esp_timer.h"
#include "esp_chip_info.h"
#include "esp_flash.h"
#include "esp_heap_caps.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "nvs.h"
#include "sdkconfig.h"
#include "lwip/ip4_addr.h"


#include "alarm_core.h"
#include "gpio_inputs.h"
#include "outputs.h"
#include "roster.h"
#include "network_manager.h"
#include "system_time.h"

#ifndef FW_VERSION
#define FW_VERSION "unknown"
#endif
#ifndef BUILD_DATE
#define BUILD_DATE __DATE__
#endif
#ifndef BUILD_TIME
#define BUILD_TIME __TIME__
#endif
#ifndef GIT_COMMIT
#define GIT_COMMIT "unknown"
#endif
#ifndef GIT_BRANCH
#define GIT_BRANCH "unknown"
#endif
#ifndef GIT_DIRTY
#define GIT_DIRTY "unknown"
#endif

static const char *TAG = "system_info";
static uint32_t s_boot_count;
static char s_installed_at[32] = "unknown";
static char s_build_dt[40];

static void iso_now_or_build(char *out, size_t len)
{
    time_t now = time(NULL);
    struct tm tm = {0};
    if (now > 1577836800 && gmtime_r(&now, &tm)) {
        strftime(out, len, "%Y-%m-%dT%H:%M:%SZ", &tm);
    } else {
        snprintf(out, len, "%s %s", BUILD_DATE, BUILD_TIME);
    }
}

esp_err_t system_info_init(void)
{
    snprintf(s_build_dt, sizeof(s_build_dt), "%s %s", BUILD_DATE, BUILD_TIME);
    char build_id[96];
    snprintf(build_id, sizeof(build_id), "%s|%s", FW_VERSION, GIT_COMMIT);

    nvs_handle_t nvs;
    esp_err_t err = nvs_open("sysinfo", NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;

    nvs_get_u32(nvs, "boot_count", &s_boot_count);
    s_boot_count++;
    nvs_set_u32(nvs, "boot_count", s_boot_count);

    char stored_id[96] = {0};
    size_t len = sizeof(stored_id);
    bool version_changed = nvs_get_str(nvs, "build_id", stored_id, &len) != ESP_OK || strcmp(stored_id, build_id) != 0;
    len = sizeof(s_installed_at);
    bool missing_installed = nvs_get_str(nvs, "installed_at", s_installed_at, &len) != ESP_OK || s_installed_at[0] == '\0';
    if (version_changed || missing_installed) {
        iso_now_or_build(s_installed_at, sizeof(s_installed_at));
        nvs_set_str(nvs, "build_id", build_id);
        nvs_set_str(nvs, "installed_at", s_installed_at);
    }
    nvs_commit(nvs);
    nvs_close(nvs);
    ESP_LOGI(TAG, "boot=%" PRIu32 " installed_at=%s", s_boot_count, s_installed_at);
    return ESP_OK;
}

uint32_t system_info_get_boot_count(void) { return s_boot_count; }
const char *system_info_get_installed_at(void) { return s_installed_at; }
const char *system_info_get_build_datetime(void) { return s_build_dt; }


static void format_uptime(uint64_t uptime_s, char *out, size_t len)
{
    if (!out || len == 0) {
        return;
    }
    uint64_t days = uptime_s / 86400ULL;
    uint64_t rem = uptime_s % 86400ULL;
    uint64_t hours = rem / 3600ULL;
    rem %= 3600ULL;
    uint64_t minutes = rem / 60ULL;
    uint64_t seconds = rem % 60ULL;
    snprintf(out, len, "%" PRIu64 "g %02" PRIu64 ":%02" PRIu64 ":%02" PRIu64,
             days, hours, minutes, seconds);
}

static const char *reset_reason_name(esp_reset_reason_t r)
{
    switch (r) {
    case ESP_RST_POWERON: return "poweron";
    case ESP_RST_EXT: return "external";
    case ESP_RST_SW: return "software";
    case ESP_RST_PANIC: return "panic";
    case ESP_RST_INT_WDT: return "interrupt_wdt";
    case ESP_RST_TASK_WDT: return "task_wdt";
    case ESP_RST_WDT: return "watchdog";
    case ESP_RST_DEEPSLEEP: return "deepsleep";
    case ESP_RST_BROWNOUT: return "brownout";
    case ESP_RST_SDIO: return "sdio";
    default: return "unknown";
    }
}

static void add_net(cJSON *root)
{
    cJSON *net = cJSON_AddObjectToObject(root, "network");
    if (!net) return;
    if (network_status_append_json(net) != ESP_OK) {
        cJSON_AddStringToObject(net, "status", "unknown");
        return;
    }
    cJSON *eth = cJSON_GetObjectItemCaseSensitive(net, "ethernet");
    cJSON *wifi = cJSON_GetObjectItemCaseSensitive(net, "wifi");
    const char *active = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(net, "active_interface"));
    const char *ip = "0.0.0.0";
    const char *mac = "";
    if (active && !strcmp(active, "ethernet") && eth) {
        ip = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(eth, "ip"));
        mac = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(eth, "mac"));
    } else if (active && !strcmp(active, "wifi") && wifi) {
        ip = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(wifi, "ip"));
        mac = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(wifi, "mac"));
    }
    cJSON_AddStringToObject(net, "ip", ip ? ip : "0.0.0.0");
    cJSON_AddStringToObject(net, "mac", mac ? mac : "");
    cJSON_AddStringToObject(net, "status", (active && strcmp(active, "none")) ? "connected" : "disconnected");
}

esp_err_t system_info_append_json(cJSON *root)
{
    if (!root) return ESP_ERR_INVALID_ARG;
    cJSON *fw = cJSON_AddObjectToObject(root, "firmware");
    cJSON_AddStringToObject(fw, "project", "NS Alarm Pro");
    cJSON_AddStringToObject(fw, "version", FW_VERSION);
    cJSON_AddStringToObject(fw, "git_commit", GIT_COMMIT);
    cJSON_AddStringToObject(fw, "git_branch", GIT_BRANCH);
    cJSON_AddStringToObject(fw, "git_dirty", GIT_DIRTY);
    cJSON_AddStringToObject(fw, "build_date", BUILD_DATE);
    cJSON_AddStringToObject(fw, "build_time", BUILD_TIME);
    cJSON_AddStringToObject(fw, "build_time_full", s_build_dt);
    cJSON_AddStringToObject(fw, "installed_at", s_installed_at);
    cJSON_AddStringToObject(fw, "esp_idf", esp_get_idf_version());
    cJSON_AddStringToObject(fw, "target", CONFIG_IDF_TARGET);
#ifdef CONFIG_COMPILER_OPTIMIZATION_DEBUG
    cJSON_AddStringToObject(fw, "build_mode", "debug");
#else
    cJSON_AddStringToObject(fw, "build_mode", "release");
#endif

    esp_chip_info_t chip; esp_chip_info(&chip);
    uint32_t flash_size = 0; esp_flash_get_size(NULL, &flash_size);
    cJSON *hw = cJSON_AddObjectToObject(root, "hardware");
    cJSON_AddStringToObject(hw, "chip_model", CONFIG_IDF_TARGET);
    cJSON_AddNumberToObject(hw, "chip_revision", chip.revision);
    cJSON_AddNumberToObject(hw, "cores", chip.cores);
    cJSON_AddNumberToObject(hw, "cpu_mhz", CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ);
    cJSON_AddNumberToObject(hw, "flash_size", flash_size);
    cJSON_AddNumberToObject(hw, "flash_size_mb", flash_size / (1024.0 * 1024.0));
    cJSON_AddNumberToObject(hw, "free_heap", esp_get_free_heap_size());
    cJSON_AddNumberToObject(hw, "min_free_heap", esp_get_minimum_free_heap_size());
    cJSON_AddBoolToObject(hw, "psram", heap_caps_get_total_size(MALLOC_CAP_SPIRAM) > 0);

    cJSON *rt = cJSON_AddObjectToObject(root, "runtime");
    uint64_t uptime_s = esp_timer_get_time() / 1000000ULL;
    char uptime_text[32];
    format_uptime(uptime_s, uptime_text, sizeof(uptime_text));
    cJSON_AddNumberToObject(rt, "uptime_s", uptime_s);
    cJSON_AddStringToObject(rt, "uptime", uptime_text);
    cJSON_AddStringToObject(rt, "reset_reason", reset_reason_name(esp_reset_reason()));
    cJSON_AddNumberToObject(rt, "boot_count", s_boot_count);
    cJSON_AddStringToObject(rt, "alarm_state", alarm_state_name(alarm_get_state()));
    add_net(root);
    system_time_append_json(root);

    const esp_partition_t *running = esp_ota_get_running_partition();
    cJSON *st = cJSON_AddObjectToObject(root, "storage");
    cJSON_AddStringToObject(st, "active_partition", running ? running->label : "unknown");
    cJSON_AddStringToObject(st, "partition_type", running ? "app" : "unknown");

    uint16_t outmask = 0; outputs_get_mask(&outmask);
    cJSON *p = cJSON_AddObjectToObject(root, "peripherals");
    cJSON_AddStringToObject(p, "i2c", "configured");
    cJSON_AddNumberToObject(p, "zones_configured", roster_effective_zones(inputs_master_zone_capacity()));
    input_debounce_state_t tamper_state = {0};
    cJSON_AddBoolToObject(p, "tamper", inputs_get_filtered_tamper(&tamper_state) ? tamper_state.stable_value : false);
    cJSON_AddNumberToObject(p, "outputs_mask", outmask);
#if ADS1115_COUNT > 0
    input_ads1115_summary_t ads = {0};
    if (inputs_ads1115_get_summary(&ads) == ESP_OK) {
        cJSON *ads_obj = cJSON_AddObjectToObject(p, "ads1115");
        cJSON_AddNumberToObject(ads_obj, "configured", (double)ads.configured_count);
        cJSON_AddNumberToObject(ads_obj, "enabled", (double)ads.enabled_count);
        cJSON_AddNumberToObject(ads_obj, "detected", (double)ads.detected_count);
        cJSON_AddNumberToObject(ads_obj, "offline", (double)ads.offline_count);
        cJSON_AddNumberToObject(ads_obj, "last_scan", (double)ads.last_scan_ms);
        cJSON_AddStringToObject(ads_obj, "bus_status", ads.bus_status);
        cJSON_AddStringToObject(ads_obj, "last_error", ads.last_error);
    } else {
        cJSON_AddStringToObject(p, "ads1115", "configured");
    }
#else
    cJSON_AddStringToObject(p, "ads1115", "not_configured");
#endif
    cJSON *diag = cJSON_AddObjectToObject(root, "diagnostics");
    cJSON_AddBoolToObject(diag, "active", false);
    cJSON_AddStringToObject(diag, "message", "Nessuna diagnostica attiva");
    return ESP_OK;
}
