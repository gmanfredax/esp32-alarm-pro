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
    float eol1_fault_max;
    float eol1_alarm_min;
    float eol2_tamper_low_max;
    float eol2_normal_max;
    float eol2_alarm_max;
    float eol3_tamper_low_max;
    float eol3_normal_max;
    float eol3_alarm_max;
} zone_eol_thresholds_t;

typedef enum {
    ZONE_INPUT_STATE_NORMAL = 0,
    ZONE_INPUT_STATE_ALARM,
    ZONE_INPUT_STATE_TAMPER,
    ZONE_INPUT_STATE_MASKING,
    ZONE_INPUT_STATE_FAULT,
} zone_input_state_t;

typedef struct {
    uint32_t           raw;     ///< valore ADC medio grezzo
    float              ratio;   ///< rapporto normalizzato 0..1
    zone_input_state_t state;   ///< classificazione corrente
} zone_adc_sample_t;

typedef struct {
    uint8_t          zone_count;
    zone_eol_mode_t  eol_mode;
    uint16_t         alarm_mask;   ///< bit 0..zone_count-1 (1 = allarme)
    uint16_t         tamper_mask;  ///< bit 0..zone_count-1 (1 = tamper)
    uint16_t         masking_mask; ///< bit 0..zone_count-1 (1 = masking)
    uint16_t         fault_mask;   ///< bit 0..zone_count-1 (1 = fault)
    bool             global_tamper;
    zone_adc_sample_t zones[ZONE_INPUT_COUNT];
    uint32_t         supply_raw;
    float            supply_voltage;  ///< Volt reali stimati
} zone_inputs_snapshot_t;

#define ZONE_INPUTS_ADC_REFERENCE_MV 1100.0f
#define ZONE_INPUTS_ADC_MAX_STEPS    4095u
#define ZONE_INPUTS_SAMPLES          8u

esp_err_t        zone_inputs_init(void);
esp_err_t        zone_inputs_sample(zone_inputs_snapshot_t *snapshot);
esp_err_t        zone_inputs_set_eol_mode(zone_eol_mode_t mode);
zone_eol_mode_t  zone_inputs_get_eol_mode(void);
const char      *zone_inputs_eol_mode_name(zone_eol_mode_t mode);
void             zone_inputs_get_thresholds(zone_eol_thresholds_t *out);
esp_err_t        zone_inputs_set_thresholds(const zone_eol_thresholds_t *cfg, bool persist);
esp_err_t        zone_inputs_load_thresholds_from_nvs(void);
zone_input_state_t zone_inputs_classify_ratio(zone_eol_mode_t mode, float ratio);
float            zone_inputs_reference_mv(void);
const char      *zone_inputs_state_label(zone_input_state_t state);

void zone_inputs_set_supply_voltage(float supply_v);

bool zone_inputs_zone_alarm(const zone_inputs_snapshot_t *snapshot, uint8_t zone_index);
bool zone_inputs_zone_tamper(const zone_inputs_snapshot_t *snapshot, uint8_t zone_index);
