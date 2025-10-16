#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize CAN master subsystem.
 *
 * Safe to call multiple times; initialization runs only once.
 */
esp_err_t can_master_init(void);

/**
 * @brief Request a CAN scan operation.
 *
 * @param[out] started Optional pointer updated to true when a new scan
 *                     started, false otherwise.
 * @return ESP_OK on success, ESP_ERR_NOT_SUPPORTED when CAN is disabled,
 *         or another esp_err_t value on failure.
 */
esp_err_t can_master_request_scan(bool *started);

/**
 * @brief Send the broadcast test toggle command.
 */
esp_err_t can_master_send_test_toggle(bool enable);

/**
 * @brief Command the outputs of a specific CAN expansion node.
 */
esp_err_t can_master_set_node_outputs(uint8_t node_id,
                                      uint32_t outputs_bitmap,
                                      uint8_t flags,
                                      uint8_t pwm_level);

/**
 * @brief Transmit a raw CAN frame with the provided payload.
 */
esp_err_t can_master_send_raw(uint32_t cob_id, const void *payload, uint8_t len);

#ifdef __cplusplus
}
#endif