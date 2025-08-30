#pragma once

#include "pins.h"
#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

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

/**
 * @brief Helper: ritorna true se la zona z (1..12) è attiva.
 */
static inline bool inputs_zone_bit(uint16_t gpioab, int z) {
    if (z < 1 || z > 12) return false;
    if (z <= 8) return (gpioab & (1u << (z - 1))) != 0;      // zone 1..8 -> GPIOA
    return (gpioab & (1u << (8 + (z - 9)))) != 0;            // zone 9..12 -> GPIOB0..3
}

/**
 * @brief Helper: ritorna true se il tamper (bit su GPIOB) è attivo.
 *        MCPB_TAMPER_BIT deve essere definito in pins.h (0..7).
 */
static inline bool inputs_tamper(uint16_t gpioab) {
    return (gpioab & (1u << (8 + MCPB_TAMPER_BIT))) != 0;
}
