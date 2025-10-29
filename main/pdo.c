#include "sdkconfig.h"
#include "pdo.h"

#include <string.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "esp_log.h"
// #include "driver/twai.h"
#include "esp_err.h"

#include "can_proto.h"
#include "can_master.h"
#include "roster.h"

// #ifndef TWAI_FRAME_MAX_DLC
// #define TWAI_FRAME_MAX_DLC 8
// #endif

#define PDO_LED_CMD_BLINK_ONESHOT  0x01u
#define PDO_LED_CMD_IDENTIFY_TOGGLE 0x02u

#if !defined(CONFIG_APP_CAN_ENABLED)

esp_err_t pdo_send_led_oneshot(uint8_t node_id, uint8_t pattern_arg, uint16_t duration_ms)
{
    (void)node_id;
    (void)pattern_arg;
    (void)duration_ms;
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t pdo_send_led_identify_toggle(uint8_t node_id, bool enable, bool *out_changed)
{
    (void)node_id;
    (void)enable;
    if (out_changed) {
        *out_changed = false;
    }
    return ESP_ERR_NOT_SUPPORTED;
}

#else

static const char *TAG = "pdo";

static esp_err_t send_pdo(uint32_t cob_id, const void *payload, size_t len)
{
    // if (!payload || len > TWAI_FRAME_MAX_DLC) {
    if (!payload || len == 0 || len > UINT8_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    // twai_message_t msg = {
    //     .identifier = cob_id,
    //     .extd = 0,
    //     .rtr = 0,
    //     .ss = 0,
    //     .dlc_non_comp = 0,
    //     .data_length_code = len,
    // };
    // memset(msg.data, 0, sizeof(msg.data));
    // memcpy(msg.data, payload, len);
    // esp_err_t err = twai_transmit(&msg, pdMS_TO_TICKS(50));
    esp_err_t err = can_master_send_raw(cob_id, payload, (uint8_t)len);
    if (err != ESP_OK) {
        // ESP_LOGW(TAG, "twai_transmit 0x%03" PRIx32 " failed: %s", cob_id, esp_err_to_name(err));
        ESP_LOGW(TAG, "PDO 0x%03" PRIx32 " transmit failed: %s", cob_id, esp_err_to_name(err));
    }
    return err;
}

esp_err_t pdo_send_led_oneshot(uint8_t node_id, uint8_t pattern_arg, uint16_t duration_ms)
{
    if (node_id == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    pdo_led_cmd_t cmd = {
        .led_cmd = PDO_LED_CMD_BLINK_ONESHOT,
        .duration_ms = duration_ms,
        .pattern_arg = pattern_arg,
        .reserved = {0},
    };
    return send_pdo(COBID_PDO_RX2(node_id), &cmd, sizeof(cmd));
}

esp_err_t pdo_send_led_identify_toggle(uint8_t node_id, bool enable, bool *out_changed)
{
    if (node_id == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    bool current = false;
    if (!roster_get_identify(node_id, &current)) {
        return ESP_ERR_NOT_FOUND;
    }
    if (current == enable) {
        if (out_changed) {
            *out_changed = false;
        }
        return ESP_OK;
    }

    pdo_led_cmd_t cmd = {
        .led_cmd = PDO_LED_CMD_IDENTIFY_TOGGLE,
        .duration_ms = 0,
        .pattern_arg = 0,
        .reserved = {0},
    };
    esp_err_t err = send_pdo(COBID_PDO_RX2(node_id), &cmd, sizeof(cmd));
    if (err == ESP_OK) {
        bool changed = false;
        err = roster_set_identify(node_id, enable, &changed);
        if (out_changed) {
            *out_changed = changed;
        }
    }
    return err;
}

#endif