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
    char macs[18] = "";
    uint8_t mac[6];
    if (esp_read_mac(mac, ESP_MAC_ETH) == ESP_OK) snprintf(macs, sizeof(macs), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    cJSON_AddStringToObject(net, "mac", macs);
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("ETH_DEF");
    if (!netif) netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    const char *hn = NULL;
    if (netif) esp_netif_get_hostname(netif, &hn);
    cJSON_AddStringToObject(net, "hostname", hn ? hn : "unknown");
    esp_netif_ip_info_t ip = {0};
    char ipbuf[16] = "0.0.0.0";
    if (netif && esp_netif_get_ip_info(netif, &ip) == ESP_OK) ip4addr_ntoa_r((const ip4_addr_t*)&ip.ip, ipbuf, sizeof(ipbuf));
    cJSON_AddStringToObject(net, "ip", ipbuf);
    cJSON_AddStringToObject(net, "status", ip.ip.addr ? "connected" : "disconnected");
}

esp_err_t system_info_append_json(cJSON *root)
{
    if (!root) return ESP_ERR_INVALID_ARG;
    cJSON *fw = cJSON_AddObjectToObject(root, "firmware");
    cJSON_AddStringToObject(fw, "project", "ESP32 Alarm Pro");
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
    cJSON_AddNumberToObject(hw, "free_heap", esp_get_free_heap_size());
    cJSON_AddNumberToObject(hw, "min_free_heap", esp_get_minimum_free_heap_size());
    cJSON_AddBoolToObject(hw, "psram", heap_caps_get_total_size(MALLOC_CAP_SPIRAM) > 0);

    cJSON *rt = cJSON_AddObjectToObject(root, "runtime");
    cJSON_AddNumberToObject(rt, "uptime_s", esp_timer_get_time() / 1000000ULL);
    cJSON_AddStringToObject(rt, "reset_reason", reset_reason_name(esp_reset_reason()));
    cJSON_AddNumberToObject(rt, "boot_count", s_boot_count);
    cJSON_AddStringToObject(rt, "alarm_state", alarm_state_name(alarm_get_state()));
    add_net(root);

    const esp_partition_t *running = esp_ota_get_running_partition();
    cJSON *st = cJSON_AddObjectToObject(root, "storage");
    cJSON_AddStringToObject(st, "active_partition", running ? running->label : "unknown");
    cJSON_AddStringToObject(st, "partition_type", running ? "app" : "unknown");

    uint16_t gpioab = 0; inputs_read_all(&gpioab);
    uint16_t outmask = 0; outputs_get_mask(&outmask);
    cJSON *p = cJSON_AddObjectToObject(root, "peripherals");
    cJSON_AddStringToObject(p, "i2c", "configured");
    cJSON_AddNumberToObject(p, "zones_configured", roster_effective_zones(inputs_master_zone_capacity()));
    cJSON_AddBoolToObject(p, "tamper", inputs_tamper(gpioab));
    cJSON_AddNumberToObject(p, "outputs_mask", outmask);
#if ADS1115_COUNT > 0
    cJSON_AddStringToObject(p, "ads1115", "configured");
#else
    cJSON_AddStringToObject(p, "ads1115", "not_configured");
#endif
    cJSON_AddObjectToObject(root, "diagnostics");
    return ESP_OK;
}
