#pragma once

#include "pins.h"
#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

#ifndef INPUT_ZONES_COUNT
  #define INPUT_ZONES_COUNT ZONE_ANALOG_CHANNEL_COUNT
#endif

typedef struct {
    uint16_t zone_active_mask;            // bit0 -> Z1 ...
    uint16_t zone_tamper_mask;            // bit set → tamper zona attivo
    uint16_t adc_raw[INPUT_ZONES_COUNT];  // ultimo valore letto
    bool     global_tamper;               // tamper globale MCP23017
} inputs_snapshot_t;


/**
 * @brief Inizializza il sottosistema ingressi.
 *
 * Configura gli ADC per le zone locali e prepara il MCP23017 per la lettura del
 * tamper globale.
 */
esp_err_t inputs_init(void);

/**
 * @brief Legge tutte le zone analogiche e aggiorna gli snapshot interni.
 *
 * @param zone_mask [out] maschera delle zone in allarme (bit0→Z1 ...).
 * @return ESP_OK se tutto ok.
 */
esp_err_t inputs_read_all(uint16_t* zone_mask);

/**
 * @brief Restituisce l'ultimo snapshot completo.
 */
void inputs_get_last_snapshot(inputs_snapshot_t *snapshot);

/**
 * @brief Maschera tamper per-zona (bit0→Z1 ...).
 */
uint16_t inputs_zone_tamper_mask(void);

/**
 * @brief Stato tamper globale.
 */
bool inputs_global_tamper(void);

/**
 * @brief Helper: ritorna true se la zona z (1..INPUT_ZONES_COUNT) è attiva.
 */
static inline bool inputs_zone_bit(uint16_t gpioab, int z) {
    if (z < 1 || z > INPUT_ZONES_COUNT) return false;
    return ((gpioab & (1u << (z - 1))) != 0);
}


/**
 * @brief Helper: ritorna true se il tamper globale è attivo.
 */
static inline bool inputs_tamper(uint16_t gpioab) {
    (void)gpioab;
    return inputs_global_tamper();
}