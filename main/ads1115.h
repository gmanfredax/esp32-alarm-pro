#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "pins.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ADS1115_MAX_DEVICES ADS1115_ADMIN_MAX_MODULES
#define ADS1115_CHANNEL_COUNT 4

// ADS1115 register map
#define ADS1115_REG_CONVERSION 0x00
#define ADS1115_REG_CONFIG     0x01
#define ADS1115_REG_LO_THRESH  0x02
#define ADS1115_REG_HI_THRESH  0x03

typedef enum {
    ADS1115_MUX_AIN0_AIN1 = 0,
    ADS1115_MUX_AIN0_AIN3 = 1,
    ADS1115_MUX_AIN1_AIN3 = 2,
    ADS1115_MUX_AIN2_AIN3 = 3,
    ADS1115_MUX_AIN0_GND  = 4,
    ADS1115_MUX_AIN1_GND  = 5,
    ADS1115_MUX_AIN2_GND  = 6,
    ADS1115_MUX_AIN3_GND  = 7,
} ads1115_mux_t;

typedef enum {
    ADS1115_PGA_FSR_6144 = 0,
    ADS1115_PGA_FSR_4096 = 1,
    ADS1115_PGA_FSR_2048 = 2,
    ADS1115_PGA_FSR_1024 = 3,
    ADS1115_PGA_FSR_0512 = 4,
    ADS1115_PGA_FSR_0256 = 5,
} ads1115_gain_t;

typedef enum {
    ADS1115_MODE_CONTINUOUS = 0,
    ADS1115_MODE_SINGLE_SHOT = 1,
} ads1115_mode_t;

typedef enum {
    ADS1115_DATA_RATE_8_SPS   = 0,
    ADS1115_DATA_RATE_16_SPS  = 1,
    ADS1115_DATA_RATE_32_SPS  = 2,
    ADS1115_DATA_RATE_64_SPS  = 3,
    ADS1115_DATA_RATE_128_SPS = 4,
    ADS1115_DATA_RATE_250_SPS = 5,
    ADS1115_DATA_RATE_475_SPS = 6,
    ADS1115_DATA_RATE_860_SPS = 7,
} ads1115_data_rate_t;

typedef enum {
    ADS1115_COMP_MODE_TRADITIONAL = 0,
    ADS1115_COMP_MODE_WINDOW      = 1,
} ads1115_comp_mode_t;

typedef enum {
    ADS1115_COMP_POL_ACTIVE_LOW  = 0,
    ADS1115_COMP_POL_ACTIVE_HIGH = 1,
} ads1115_comp_polarity_t;

typedef enum {
    ADS1115_COMP_NON_LATCHING = 0,
    ADS1115_COMP_LATCHING     = 1,
} ads1115_comp_latch_t;

typedef enum {
    ADS1115_COMP_QUEUE_ASSERT_1 = 0,
    ADS1115_COMP_QUEUE_ASSERT_2 = 1,
    ADS1115_COMP_QUEUE_ASSERT_4 = 2,
    ADS1115_COMP_QUEUE_DISABLE  = 3,
} ads1115_comp_queue_t;

typedef struct {
    ads1115_gain_t gain;
    ads1115_mode_t mode;
    ads1115_data_rate_t data_rate;
    ads1115_comp_mode_t comp_mode;
    ads1115_comp_polarity_t comp_polarity;
    ads1115_comp_latch_t comp_latch;
    ads1115_comp_queue_t comp_queue;
} ads1115_operating_config_t;

typedef struct {
    uint8_t address;          // 7-bit unshifted I2C address
    ads1115_mux_t default_mux;
    ads1115_operating_config_t options;
} ads1115_device_config_t;

typedef struct {
    uint8_t address;
    ads1115_operating_config_t options;
    ads1115_mux_t current_mux;
    uint16_t last_config_word;
    bool detected;
    bool online;
    uint64_t last_seen_ms;
    esp_err_t last_error;
    uint32_t consecutive_failures;
} ads1115_device_info_t;

typedef struct {
    bool detected[ADS1115_ADMIN_MAX_MODULES];
    uint64_t scan_time_ms;
} ads1115_scan_result_t;

esp_err_t ads1115_install(const ads1115_device_config_t* configs, size_t count);
esp_err_t ads1115_uninstall(void);
size_t ads1115_device_count(void);

esp_err_t ads1115_get_config(size_t unit, ads1115_operating_config_t* out_cfg);
esp_err_t ads1115_get_info(size_t unit, ads1115_device_info_t* out_info);
esp_err_t ads1115_configure(size_t unit, const ads1115_operating_config_t* cfg);
esp_err_t ads1115_set_mux(size_t unit, ads1115_mux_t mux);
esp_err_t ads1115_read_latest(size_t unit, int16_t* raw_value);
esp_err_t ads1115_single_shot(size_t unit, ads1115_mux_t mux, TickType_t timeout_ticks, int16_t* raw_value);
esp_err_t ads1115_set_thresholds(size_t unit, int16_t low, int16_t high);
esp_err_t ads1115_get_thresholds(size_t unit, int16_t* low, int16_t* high);
float ads1115_raw_to_voltage(int16_t raw, ads1115_gain_t gain);
bool ads1115_is_valid_address(uint8_t address);
esp_err_t ads1115_probe_address(uint8_t address, TickType_t timeout_ticks);
esp_err_t ads1115_scan(ads1115_scan_result_t* out_result);
void ads1115_debug_dump(void);

#ifdef __cplusplus
}
#endif