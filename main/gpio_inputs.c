#include "gpio_inputs.h"
#include "mcp23017.h"
#include "zone_backend.h"
#include "esp_log.h"
#include <string.h>

static const char* TAG = "inputs";
static zone_backend_snapshot_t s_last_snapshot;

esp_err_t inputs_init(void)
{
    esp_err_t err = zone_backend_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "zone backend init failed: %s", esp_err_to_name(err));
        return err;
    }
    ESP_LOGI(TAG, "Zone backend ready (%s)", zone_backend_type_label(zone_backend_current()));
    memset(&s_last_snapshot, 0, sizeof(s_last_snapshot));
    return ESP_OK;
}

static void snapshot_to_gpio(const zone_backend_snapshot_t *snap, uint16_t *out_gpio)
{
    if (!snap || !out_gpio) {
        return;
    }
    if (snap->backend == ZONE_BACKEND_DIGITAL_MCP23017) {
        *out_gpio = snap->gpio_raw;
        return;
    }
    uint16_t value = 0;
    uint8_t limit = snap->zone_count;
    if (limit > 12) {
        limit = 12;
    }
    for (uint8_t i = 0; i < limit; ++i) {
        const zone_backend_zone_state_t *zone = &snap->zones[i];
        bool active = zone->present && zone->alarm;
        if (i < 8) {
            if (active) {
                value |= (uint16_t)(1u << i);
            }
        } else {
            uint8_t bit = (uint8_t)(i - 8u);
            if (active) {
                value |= (uint16_t)(1u << (8u + bit));
            }
        }
    }
    *out_gpio = value;
}

esp_err_t inputs_read_all(uint16_t* gpioab)
{
    if (!gpioab) {
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t err = zone_backend_poll(&s_last_snapshot, false);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "zone backend poll failed: %s", esp_err_to_name(err));
        return err;
    }
    snapshot_to_gpio(&s_last_snapshot, gpioab);
    return ESP_OK;
}

zone_backend_type_t inputs_backend_get(void)
{
    return zone_backend_current();
}

esp_err_t inputs_backend_set(zone_backend_type_t backend, bool persist)
{
    esp_err_t err = zone_backend_set(backend, persist);
    if (err == ESP_OK) {
        memset(&s_last_snapshot, 0, sizeof(s_last_snapshot));
    }
    return err;
}

esp_err_t inputs_poll_snapshot(zone_backend_snapshot_t *snapshot)
{
    esp_err_t err = zone_backend_poll(&s_last_snapshot, false);
    if (err != ESP_OK) {
        return err;
    }
    if (snapshot) {
        *snapshot = s_last_snapshot;
    }
    return ESP_OK;
}
