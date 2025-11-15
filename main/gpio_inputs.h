#pragma once

#include "pins.h"
#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#if ADS1115_COUNT > 0
#include "ads1115.h"
#include "zone_mask.h"
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