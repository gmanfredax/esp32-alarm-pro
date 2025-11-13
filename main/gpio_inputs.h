#pragma once

#include "pins.h"
#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#if ADS1115_COUNT > 0
#include "ads1115.h"
#endif

// Numero di zone esposte al web: A0..A7 (8) + B0..B3 (4) = 12
// (Se vuoi usare anche B4 come Z13, cambia a 13)
#define INPUT_ZONES_COUNT 12


/**
 * @brief Inizializza il sottosistema ingressi (basato su MCP23017).
 */
esp_err_t inputs_init(void);

/**
 * @brief Legge tutti i 16 bit da MCP23017 (GPIOA+GPIOB).
 *
 * @param gpioab [out] valore combinato:
 *        bit 0..7   -> GPIOA0..7
 *        bit 8..15  -> GPIOB0..7
 * @return ESP_OK se tutto ok
 */
esp_err_t inputs_read_all(uint16_t* gpioab);

#if ADS1115_COUNT > 0
size_t inputs_ads1115_count(void);
esp_err_t inputs_ads1115_read_channel_raw(size_t index, int channel, TickType_t timeout, int16_t* raw);
esp_err_t inputs_ads1115_read_channel_voltage(size_t index, int channel, TickType_t timeout, float* voltage);
esp_err_t inputs_ads1115_read_all_raw(size_t index, TickType_t timeout_per_channel, int16_t out_raw[ADS1115_CHANNEL_COUNT]);
esp_err_t inputs_ads1115_read_all_voltage(size_t index, TickType_t timeout_per_channel, float out_voltage[ADS1115_CHANNEL_COUNT]);
#endif

/**
 * @brief Helper: ritorna true se la zona z (1..12) è attiva.
 */
static inline bool inputs_zone_bit(uint16_t gpioab, int z) {
    if (z < 1 || z > INPUT_ZONES_COUNT) return false;

    if (z <= 8) {
        // Z1..Z8 -> A0..A7 (pull-up: 0 = attivo)
        return ((gpioab & (1u << (z - 1))) != 0);
    } else {
        // Z9..Z12 -> B0..B3 (pull-up: 0 = attivo)
        int bbit = z - 9;      // 0..3
        return ((gpioab & (1u << (8 + bbit))) != 0);
    }
}


/**
 * @brief Helper: ritorna true se il tamper (bit su GPIOB) è attivo.
 *        MCPB_TAMPER_BIT deve essere definito in pins.h (0..7).
 */
static inline bool inputs_tamper(uint16_t gpioab) {
    // Pull-up: 0 = attivo
    return ((gpioab & (1u << (8 + MCPB_TAMPER_BIT))) != 0);
}