#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t pdo_send_led_oneshot(uint8_t node_id, uint8_t pattern_arg, uint16_t duration_ms);
esp_err_t pdo_send_led_identify_toggle(uint8_t node_id, bool enable, bool *out_changed);

#ifdef __cplusplus
}
#endif