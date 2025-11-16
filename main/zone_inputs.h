#pragma once

#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

#include "pins.h"

typedef enum {
    ZONE_EOL_MODE_1 = 0,
    ZONE_EOL_MODE_2 = 1,
    ZONE_EOL_MODE_3 = 2,
} zone_eol_mode_t;

typedef struct {
    uint32_t raw;     ///< valore ADC medio grezzo
    float    ratio;   ///< rapporto normalizzato 0..1
} zone_adc_sample_t;

typedef struct {
    uint8_t          zone_count;
    zone_eol_mode_t  eol_mode;
    uint16_t         alarm_mask;   ///< bit 0..zone_count-1 (1 = allarme)
    uint16_t         tamper_mask;  ///< bit 0..zone_count-1 (1 = tamper)
    bool             global_tamper;
    zone_adc_sample_t zones[ZONE_INPUT_COUNT];
    uint32_t         supply_raw;
    float            supply_voltage;  ///< Volt reali stimati
} zone_inputs_snapshot_t;

esp_err_t        zone_inputs_init(void);
esp_err_t        zone_inputs_sample(zone_inputs_snapshot_t *snapshot);
esp_err_t        zone_inputs_set_eol_mode(zone_eol_mode_t mode);
zone_eol_mode_t  zone_inputs_get_eol_mode(void);
const char      *zone_inputs_eol_mode_name(zone_eol_mode_t mode);

bool zone_inputs_zone_alarm(const zone_inputs_snapshot_t *snapshot, uint8_t zone_index);
bool zone_inputs_zone_tamper(const zone_inputs_snapshot_t *snapshot, uint8_t zone_index);
