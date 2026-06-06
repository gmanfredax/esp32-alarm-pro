#pragma once

#include "pins.h"
#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "zone_mask.h"

#if ADS1115_COUNT > 0
#include "ads1115.h"
#endif

// Numero di zone esposte dal MCP23017: A0..A7 (8) + B0..B3 (4) = 12
// (Se vuoi usare anche B4 come Z13, cambia a 13)
#define INPUT_ZONES_COUNT 12

#if ADS1115_COUNT > 0
#define INPUT_ANALOG_TOTAL_CHANNELS   (ADS1115_COUNT * ADS1115_CHANNEL_COUNT)
#if ADS1115_COUNT >= 3
#define INPUT_ANALOG_ZONES_COUNT      10
#define INPUT_ANALOG_SUPPLY_SLOT      2
#define INPUT_ANALOG_SUPPLY_CHANNEL   2
#define INPUT_ANALOG_SUPPLY_INDEX     ((INPUT_ANALOG_SUPPLY_SLOT * ADS1115_CHANNEL_COUNT) + INPUT_ANALOG_SUPPLY_CHANNEL)
#else
#define INPUT_ANALOG_ZONES_COUNT      INPUT_ANALOG_TOTAL_CHANNELS
#define INPUT_ANALOG_SUPPLY_SLOT      0
#define INPUT_ANALOG_SUPPLY_CHANNEL   0
#define INPUT_ANALOG_SUPPLY_INDEX     0
#endif
#else
#define INPUT_ANALOG_TOTAL_CHANNELS   0
#define INPUT_ANALOG_ZONES_COUNT      0
#define INPUT_ANALOG_SUPPLY_SLOT      0
#define INPUT_ANALOG_SUPPLY_CHANNEL   0
#define INPUT_ANALOG_SUPPLY_INDEX     0
#endif

#define INPUT_MASTER_ZONES_COUNT (INPUT_ZONES_COUNT + INPUT_ANALOG_ZONES_COUNT)

// Parametri anti-debounce/anti-glitch centralizzati per gli ingressi.
#ifndef INPUT_DIGITAL_DEBOUNCE_MS
#define INPUT_DIGITAL_DEBOUNCE_MS 60u
#endif
#ifndef INPUT_TAMPER_DEBOUNCE_MS
#define INPUT_TAMPER_DEBOUNCE_MS 120u
#endif
#ifndef INPUT_ANALOG_DEBOUNCE_MS
#define INPUT_ANALOG_DEBOUNCE_MS 250u
#endif
#ifndef INPUT_ANALOG_CONFIRM_SAMPLES
#define INPUT_ANALOG_CONFIRM_SAMPLES 4u
#endif
#ifndef INPUT_ANALOG_HYSTERESIS_MV
#define INPUT_ANALOG_HYSTERESIS_MV 75u
#endif

#define INPUT_DIGITAL_FILTER_FAST_DEFAULT_MS      40u
#define INPUT_DIGITAL_FILTER_STANDARD_DEFAULT_MS  80u
#define INPUT_DIGITAL_FILTER_PROTECTED_DEFAULT_MS 180u

typedef enum {
    ZONE_FILTER_FAST = 0,
    ZONE_FILTER_STANDARD = 1,
    ZONE_FILTER_PROTECTED = 2,
} zone_filter_profile_t;

typedef struct {
    uint32_t fast_ms;
    uint32_t standard_ms;
    uint32_t protected_ms;
} input_digital_filter_config_t;

#ifndef INPUT_BOOT_SETTLE_MS
#define INPUT_BOOT_SETTLE_MS 1000u
#endif
#ifndef INPUT_FAULT_CONFIRM_MS
#define INPUT_FAULT_CONFIRM_MS 500u
#endif

typedef struct {
    bool raw_value;
    bool filtered_value;
    bool stable_value;
    bool previous_stable_value;
    bool debouncing;
    bool unavailable;
    bool initialized;
    uint64_t last_raw_change_ms;
    uint64_t last_stable_change_ms;
    uint32_t required_stable_ms;
    uint32_t bounce_count;
} input_debounce_state_t;

typedef struct {
    bool known;
    bool alarm;
    bool tamper;
    bool unavailable;
    bool debouncing;
    float voltage;
    uint32_t bounce_count;
    uint32_t discarded_samples;
    uint64_t last_raw_change_ms;
    uint64_t last_stable_change_ms;
} input_zone_filtered_state_t;

void inputs_debounce_bool(input_debounce_state_t* state, bool raw_value, bool unavailable, uint32_t stable_ms, uint64_t now_ms);
esp_err_t inputs_baseline_init(uint16_t gpioab, uint16_t zones_total);
esp_err_t inputs_compose_debounced_mask(uint16_t gpioab, uint16_t zones_total, zone_mask_t* out_mask, bool* tamper_out);
bool inputs_get_filtered_zone_state(uint16_t zero_based_index, input_zone_filtered_state_t* out_state);
bool inputs_get_filtered_tamper(input_debounce_state_t* out_state);
uint32_t inputs_filter_change_counter(void);

void inputs_digital_filters_load_defaults(void);
esp_err_t inputs_digital_filters_load(void);
esp_err_t inputs_digital_filters_save(void);
input_digital_filter_config_t inputs_digital_filters_get_config(void);
esp_err_t inputs_digital_filters_set_config(const input_digital_filter_config_t* cfg, bool persist);
zone_filter_profile_t inputs_zone_filter_get(uint16_t zero_based_index);
esp_err_t inputs_zone_filter_set(uint16_t zero_based_index, zone_filter_profile_t profile, bool persist);
uint32_t inputs_zone_filter_effective_ms(uint16_t zero_based_index);
const char* inputs_zone_filter_profile_name(zone_filter_profile_t profile);
bool inputs_zone_filter_profile_from_name(const char* name, zone_filter_profile_t* out_profile);


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
typedef enum {
    INPUT_ANALOG_EOL_1 = 1,
    INPUT_ANALOG_EOL_2 = 2,
    INPUT_ANALOG_EOL_3 = 3,
} input_analog_eol_mode_t;

typedef struct {
    input_analog_eol_mode_t mode;
    float normal_min;
    float normal_max;
    float alarm_min;
    float alarm_max;
    float tamper_low;
    float tamper_high;
} input_analog_zone_config_t;

typedef struct {
    bool device_present;
    bool sample_valid;
    float voltage;
    bool alarm;
    bool tamper;
    input_analog_eol_mode_t mode;
} input_analog_zone_state_t;

typedef struct {
    bool global_tamper;
    zone_mask_t zone_mask;
} input_tamper_snapshot_t;

typedef struct {
    bool device_present;
    bool sample_valid;
    float adc_voltage;
    float supply_voltage;
} input_supply_state_t;

typedef struct {
    char id[16];
    char label[32];
    char role[24];
    uint8_t i2c_address;
    bool configured;
    bool enabled;
    bool detected;
    bool online;
    uint64_t last_seen_ms;
    uint64_t last_scan_ms;
    char last_error[32];
    uint32_t consecutive_failures;
    uint8_t zone_count;
    uint16_t zones[ADS1115_CHANNEL_COUNT];
} input_ads1115_module_info_t;

typedef struct {
    size_t configured_count;
    size_t enabled_count;
    size_t detected_count;
    size_t offline_count;
    uint64_t last_scan_ms;
    char bus_status[24];
    char last_error[32];
} input_ads1115_summary_t;
#endif

#if ADS1115_COUNT > 0
size_t inputs_ads1115_count(void);
size_t inputs_ads1115_expected_devices(void);
esp_err_t inputs_ads1115_read_channel_raw(size_t index, int channel, TickType_t timeout, int16_t* raw);
esp_err_t inputs_ads1115_read_channel_voltage(size_t index, int channel, TickType_t timeout, float* voltage);
esp_err_t inputs_ads1115_read_all_raw(size_t index, TickType_t timeout_per_channel, int16_t out_raw[ADS1115_CHANNEL_COUNT]);
esp_err_t inputs_ads1115_read_all_voltage(size_t index, TickType_t timeout_per_channel, float out_voltage[ADS1115_CHANNEL_COUNT]);
esp_err_t inputs_ads1115_get_expected_config(size_t index, ads1115_device_config_t* out_cfg);
int inputs_ads1115_detected_index_for_address(uint8_t address);
esp_err_t inputs_ads1115_scan(void);
esp_err_t inputs_ads1115_get_module_info(size_t index, input_ads1115_module_info_t* out_info);
size_t inputs_ads1115_configured_count(void);
esp_err_t inputs_ads1115_get_summary(input_ads1115_summary_t* out_summary);
esp_err_t inputs_ads1115_add_module(uint8_t address, const char* label, bool enabled, bool* detected);
esp_err_t inputs_ads1115_replace_module(const char* id, uint8_t new_address, const char* label, bool* detected);
esp_err_t inputs_ads1115_set_enabled(const char* id, bool enabled);
esp_err_t inputs_ads1115_delete_module(const char* id, bool force);
esp_err_t inputs_ads1115_reset_errors(const char* id);
esp_err_t inputs_ads1115_test_read(const char* id, int16_t out_raw[ADS1115_CHANNEL_COUNT]);
bool inputs_analog_zone_available(size_t index);

size_t inputs_analog_zone_count(void);
void inputs_analog_load_defaults(void);
esp_err_t inputs_analog_load_configs(void);
esp_err_t inputs_analog_save_configs(void);
esp_err_t inputs_analog_get_zone_config(size_t index, input_analog_zone_config_t* out_cfg);
esp_err_t inputs_analog_set_zone_config(size_t index, const input_analog_zone_config_t* cfg, bool persist);
esp_err_t inputs_analog_evaluate(size_t index, TickType_t timeout, input_analog_zone_state_t* out_state);
esp_err_t inputs_collect_tamper_snapshot(uint16_t gpioab, TickType_t timeout, input_tamper_snapshot_t* snapshot);
esp_err_t inputs_analog_supply_state(TickType_t timeout, input_supply_state_t* out_state);
#endif

uint16_t inputs_master_zone_capacity(void);

/**
 * @brief Helper: ritorna true se la zona z (1..12) è attiva.
 */
static inline bool inputs_zone_bit(uint16_t gpioab, int z) {
    if (z < 1 || z > INPUT_ZONES_COUNT) return false;

    if (z <= 8) {
        // Z1..Z8 -> A0..A7 (pull-up: 1 = circuito aperto / violazione)
        return ((gpioab & (1u << (z - 1))) != 0);
    } else {
        // Z9..Z12 -> B0..B3 (pull-up: 1 = circuito aperto / violazione)
        int bbit = z - 9;      // 0..3
        return ((gpioab & (1u << (8 + bbit))) != 0);
    }
}


/**
 * @brief Helper: ritorna true se il tamper (bit su GPIOB) è attivo.
 *        MCPB_TAMPER_BIT deve essere definito in pins.h (0..7).
 */
static inline bool inputs_tamper(uint16_t gpioab) {
    // Pull-up: 1 = circuito aperto / tamper attivo
    return ((gpioab & (1u << (8 + MCPB_TAMPER_BIT))) != 0);
}