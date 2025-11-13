#include "ads1115.h"

#include <string.h>

#include "esp_check.h"
#include "esp_log.h"
#include "driver/i2c_master.h"

#include "i2c_bus.h"
#include "pins.h"

#define ADS1115_CONFIG_OS_SINGLE   (1U << 15)
#define ADS1115_CONFIG_OS_READY    (1U << 15)
#define ADS1115_CONFIG_MUX_SHIFT   12
#define ADS1115_CONFIG_PGA_SHIFT    9
#define ADS1115_CONFIG_MODE_SHIFT   8
#define ADS1115_CONFIG_DR_SHIFT     5
#define ADS1115_CONFIG_COMP_MODE    4
#define ADS1115_CONFIG_COMP_POL     3
#define ADS1115_CONFIG_COMP_LAT     2
#define ADS1115_CONFIG_COMP_QUE     0

static const char* TAG = "ads1115";

typedef struct {
    bool in_use;
    i2c_master_dev_handle_t handle;
    ads1115_operating_config_t options;
    ads1115_mux_t current_mux;
    uint16_t base_config;
    uint16_t last_config_word;
    TickType_t conversion_wait_ticks;
    TickType_t poll_delay_ticks;
} ads1115_device_t;

static ads1115_device_t s_devices[ADS1115_MAX_DEVICES];
static size_t s_device_count = 0;

static inline TickType_t ensure_min_tick(TickType_t ticks)
{
    return (ticks == 0) ? 1 : ticks;
}

static uint16_t build_config_word(const ads1115_operating_config_t* opt)
{
    uint16_t value = 0;
    value |= ((uint16_t)opt->gain        & 0x07) << ADS1115_CONFIG_PGA_SHIFT;
    value |= ((uint16_t)opt->mode        & 0x01) << ADS1115_CONFIG_MODE_SHIFT;
    value |= ((uint16_t)opt->data_rate   & 0x07) << ADS1115_CONFIG_DR_SHIFT;
    value |= ((uint16_t)opt->comp_mode   & 0x01) << ADS1115_CONFIG_COMP_MODE;
    value |= ((uint16_t)opt->comp_polarity & 0x01) << ADS1115_CONFIG_COMP_POL;
    value |= ((uint16_t)opt->comp_latch  & 0x01) << ADS1115_CONFIG_COMP_LAT;
    value |= ((uint16_t)opt->comp_queue  & 0x03) << ADS1115_CONFIG_COMP_QUE;
    return value;
}

static uint32_t conversion_time_us(ads1115_data_rate_t dr)
{
    switch (dr) {
        case ADS1115_DATA_RATE_8_SPS:   return 125000;
        case ADS1115_DATA_RATE_16_SPS:  return 62500;
        case ADS1115_DATA_RATE_32_SPS:  return 31250;
        case ADS1115_DATA_RATE_64_SPS:  return 15625;
        case ADS1115_DATA_RATE_128_SPS: return 7813;
        case ADS1115_DATA_RATE_250_SPS: return 4000;
        case ADS1115_DATA_RATE_475_SPS: return 2105;
        case ADS1115_DATA_RATE_860_SPS: return 1163;
        default:                        return 125000;
    }
}

static TickType_t compute_wait_ticks(const ads1115_operating_config_t* opt)
{
    uint32_t us = conversion_time_us(opt->data_rate);
    uint32_t ms = (us + 999) / 1000 + 1; // aggiungi margine
    return ensure_min_tick(pdMS_TO_TICKS(ms));
}

static esp_err_t write_reg(i2c_master_dev_handle_t dev, uint8_t reg, uint16_t value)
{
    uint8_t payload[3] = { reg, (uint8_t)(value >> 8), (uint8_t)(value & 0xFF) };
    return i2c_master_transmit(dev, payload, sizeof(payload), 1000);
}

static esp_err_t read_reg(i2c_master_dev_handle_t dev, uint8_t reg, uint16_t* value)
{
    uint8_t rx[2] = { 0 };
    esp_err_t err = i2c_master_transmit_receive(dev, &reg, 1, rx, sizeof(rx), 1000);
    if (err == ESP_OK && value) {
        *value = ((uint16_t)rx[0] << 8) | rx[1];
    }
    return err;
}

static ads1115_device_t* get_device(size_t unit)
{
    if (unit >= s_device_count) {
        return NULL;
    }
    return &s_devices[unit];
}

static esp_err_t apply_config_to_device(ads1115_device_t* dev, ads1115_mux_t mux)
{
    uint16_t word = dev->base_config | ((uint16_t)mux << ADS1115_CONFIG_MUX_SHIFT);
    if (dev->options.mode == ADS1115_MODE_SINGLE_SHOT) {
        word |= ADS1115_CONFIG_OS_SINGLE;
    } else {
        word |= ADS1115_CONFIG_OS_READY;
    }
    esp_err_t err = write_reg(dev->handle, ADS1115_REG_CONFIG, word);
    if (err == ESP_OK) {
        dev->last_config_word = word;
        dev->current_mux = mux;
    }
    return err;
}

static esp_err_t wait_conversion_ready(ads1115_device_t* dev, TickType_t timeout_ticks)
{
    TickType_t wait_ticks = timeout_ticks ? timeout_ticks : dev->conversion_wait_ticks;
    TickType_t poll_delay = ensure_min_tick(dev->poll_delay_ticks);
    TickType_t start = xTaskGetTickCount();

    while (true) {
        uint16_t cfg = 0;
        ESP_RETURN_ON_ERROR(read_reg(dev->handle, ADS1115_REG_CONFIG, &cfg), TAG, "read cfg");
        if (cfg & ADS1115_CONFIG_OS_READY) {
            return ESP_OK;
        }
        TickType_t now = xTaskGetTickCount();
        if ((now - start) >= wait_ticks) {
            break;
        }
        vTaskDelay(poll_delay);
    }
    return ESP_ERR_TIMEOUT;
}

static void reset_state(void)
{
    for (size_t i = 0; i < ADS1115_MAX_DEVICES; ++i) {
        s_devices[i].in_use = false;
        s_devices[i].handle = NULL;
        memset(&s_devices[i].options, 0, sizeof(s_devices[i].options));
        s_devices[i].current_mux = ADS1115_MUX_AIN0_GND;
        s_devices[i].base_config = 0;
        s_devices[i].last_config_word = 0;
        s_devices[i].conversion_wait_ticks = 1;
        s_devices[i].poll_delay_ticks = ensure_min_tick(pdMS_TO_TICKS(1));
    }
    s_device_count = 0;
}

esp_err_t ads1115_uninstall(void)
{
    for (size_t i = 0; i < s_device_count; ++i) {
        if (s_devices[i].handle) {
            esp_err_t err = i2c_master_bus_rm_device(s_devices[i].handle);
            if (err != ESP_OK) {
                ESP_LOGW(TAG, "Failed to remove ADS1115 device %zu: %s", i, esp_err_to_name(err));
            }
            s_devices[i].handle = NULL;
        }
        s_devices[i].in_use = false;
    }
    s_device_count = 0;
    return ESP_OK;
}

esp_err_t ads1115_install(const ads1115_device_config_t* configs, size_t count)
{
    if (!configs && count) {
        return ESP_ERR_INVALID_ARG;
    }
    ESP_RETURN_ON_FALSE(count <= ADS1115_MAX_DEVICES, ESP_ERR_INVALID_SIZE, TAG, "too many devices");

    if (s_device_count) {
        ESP_LOGW(TAG, "ADS1115 already initialised, uninstalling previous instances");
        ESP_RETURN_ON_ERROR(ads1115_uninstall(), TAG, "uninstall");
    }
    reset_state();

    i2c_master_bus_handle_t bus = i2c_bus_get();
    ESP_RETURN_ON_FALSE(bus != NULL, ESP_ERR_INVALID_STATE, TAG, "I2C bus not ready");

    for (size_t i = 0; i < count; ++i) {
        const ads1115_device_config_t* cfg = &configs[i];
        ads1115_device_t* dev = &s_devices[i];

        i2c_device_config_t dev_cfg = {
            .dev_addr_length = I2C_ADDR_BIT_LEN_7,
            .device_address = cfg->address,
            .scl_speed_hz = I2C_SPEED_HZ,
        };
        ESP_RETURN_ON_ERROR(i2c_master_bus_add_device(bus, &dev_cfg, &dev->handle), TAG, "add device");

        dev->options = cfg->options;
        dev->base_config = build_config_word(&dev->options);
        dev->current_mux = cfg->default_mux;
        dev->conversion_wait_ticks = compute_wait_ticks(&dev->options);
        dev->poll_delay_ticks = ensure_min_tick(pdMS_TO_TICKS(1));
        dev->in_use = true;

        // set soglie comparator default
        ESP_RETURN_ON_ERROR(write_reg(dev->handle, ADS1115_REG_LO_THRESH, 0x8000), TAG, "lo_thresh");
        ESP_RETURN_ON_ERROR(write_reg(dev->handle, ADS1115_REG_HI_THRESH, 0x7FFF), TAG, "hi_thresh");

        ESP_RETURN_ON_ERROR(apply_config_to_device(dev, cfg->default_mux), TAG, "config");
        ESP_LOGI(TAG, "ADS1115[%zu] ready @0x%02X (mode=%s, gain=%d, rate=%d SPS)", i, cfg->address,
                 (cfg->options.mode == ADS1115_MODE_SINGLE_SHOT) ? "single" : "continuous",
                 cfg->options.gain, cfg->options.data_rate);
    }

    s_device_count = count;
    return ESP_OK;
}

size_t ads1115_device_count(void)
{
    return s_device_count;
}

esp_err_t ads1115_get_config(size_t unit, ads1115_operating_config_t* out_cfg)
{
    ads1115_device_t* dev = get_device(unit);
    ESP_RETURN_ON_FALSE(dev && dev->in_use, ESP_ERR_INVALID_ARG, TAG, "invalid unit");
    if (!out_cfg) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_cfg = dev->options;
    return ESP_OK;
}

static esp_err_t update_device_options(ads1115_device_t* dev, const ads1115_operating_config_t* cfg)
{
    dev->options = *cfg;
    dev->base_config = build_config_word(cfg);
    dev->conversion_wait_ticks = compute_wait_ticks(cfg);
    return ESP_OK;
}

esp_err_t ads1115_configure(size_t unit, const ads1115_operating_config_t* cfg)
{
    ads1115_device_t* dev = get_device(unit);
    ESP_RETURN_ON_FALSE(dev && dev->in_use, ESP_ERR_INVALID_ARG, TAG, "invalid unit");
    ESP_RETURN_ON_FALSE(cfg != NULL, ESP_ERR_INVALID_ARG, TAG, "null cfg");

    update_device_options(dev, cfg);
    return apply_config_to_device(dev, dev->current_mux);
}

esp_err_t ads1115_set_mux(size_t unit, ads1115_mux_t mux)
{
    ads1115_device_t* dev = get_device(unit);
    ESP_RETURN_ON_FALSE(dev && dev->in_use, ESP_ERR_INVALID_ARG, TAG, "invalid unit");
    ESP_RETURN_ON_FALSE(mux <= ADS1115_MUX_AIN3_GND, ESP_ERR_INVALID_ARG, TAG, "invalid mux");

    return apply_config_to_device(dev, mux);
}

esp_err_t ads1115_read_latest(size_t unit, int16_t* raw_value)
{
    ads1115_device_t* dev = get_device(unit);
    ESP_RETURN_ON_FALSE(dev && dev->in_use, ESP_ERR_INVALID_ARG, TAG, "invalid unit");
    ESP_RETURN_ON_FALSE(raw_value != NULL, ESP_ERR_INVALID_ARG, TAG, "null out");

    uint16_t reg_val = 0;
    ESP_RETURN_ON_ERROR(read_reg(dev->handle, ADS1115_REG_CONVERSION, &reg_val), TAG, "read conv");
    *raw_value = (int16_t)reg_val;
    return ESP_OK;
}

esp_err_t ads1115_single_shot(size_t unit, ads1115_mux_t mux, TickType_t timeout_ticks, int16_t* raw_value)
{
    ads1115_device_t* dev = get_device(unit);
    ESP_RETURN_ON_FALSE(dev && dev->in_use, ESP_ERR_INVALID_ARG, TAG, "invalid unit");
    ESP_RETURN_ON_FALSE(raw_value != NULL, ESP_ERR_INVALID_ARG, TAG, "null out");
    ESP_RETURN_ON_FALSE(dev->options.mode == ADS1115_MODE_SINGLE_SHOT, ESP_ERR_INVALID_STATE, TAG, "not in single-shot mode");

    ESP_RETURN_ON_ERROR(apply_config_to_device(dev, mux), TAG, "start single");
    ESP_RETURN_ON_ERROR(wait_conversion_ready(dev, timeout_ticks), TAG, "wait");
    return ads1115_read_latest(unit, raw_value);
}

esp_err_t ads1115_set_thresholds(size_t unit, int16_t low, int16_t high)
{
    ads1115_device_t* dev = get_device(unit);
    ESP_RETURN_ON_FALSE(dev && dev->in_use, ESP_ERR_INVALID_ARG, TAG, "invalid unit");

    ESP_RETURN_ON_ERROR(write_reg(dev->handle, ADS1115_REG_LO_THRESH, (uint16_t)low), TAG, "lo");
    ESP_RETURN_ON_ERROR(write_reg(dev->handle, ADS1115_REG_HI_THRESH, (uint16_t)high), TAG, "hi");
    return ESP_OK;
}

esp_err_t ads1115_get_thresholds(size_t unit, int16_t* low, int16_t* high)
{
    ads1115_device_t* dev = get_device(unit);
    ESP_RETURN_ON_FALSE(dev && dev->in_use, ESP_ERR_INVALID_ARG, TAG, "invalid unit");

    uint16_t tmp = 0;
    if (low) {
        ESP_RETURN_ON_ERROR(read_reg(dev->handle, ADS1115_REG_LO_THRESH, &tmp), TAG, "read lo");
        *low = (int16_t)tmp;
    }
    if (high) {
        ESP_RETURN_ON_ERROR(read_reg(dev->handle, ADS1115_REG_HI_THRESH, &tmp), TAG, "read hi");
        *high = (int16_t)tmp;
    }
    return ESP_OK;
}

float ads1115_raw_to_voltage(int16_t raw, ads1115_gain_t gain)
{
    float fs = 6.144f;
    switch (gain) {
        case ADS1115_PGA_FSR_6144: fs = 6.144f; break;
        case ADS1115_PGA_FSR_4096: fs = 4.096f; break;
        case ADS1115_PGA_FSR_2048: fs = 2.048f; break;
        case ADS1115_PGA_FSR_1024: fs = 1.024f; break;
        case ADS1115_PGA_FSR_0512: fs = 0.512f; break;
        case ADS1115_PGA_FSR_0256: fs = 0.256f; break;
        default: fs = 6.144f; break;
    }
    return ((float)raw / 32768.0f) * fs;
}

void ads1115_debug_dump(void)
{
    for (size_t i = 0; i < s_device_count; ++i) {
        ads1115_device_t* dev = &s_devices[i];
        if (!dev->in_use) continue;
        uint16_t cfg = 0, lo = 0, hi = 0;
        if (read_reg(dev->handle, ADS1115_REG_CONFIG, &cfg) != ESP_OK) cfg = 0;
        if (read_reg(dev->handle, ADS1115_REG_LO_THRESH, &lo) != ESP_OK) lo = 0;
        if (read_reg(dev->handle, ADS1115_REG_HI_THRESH, &hi) != ESP_OK) hi = 0;
        ESP_LOGI(TAG, "ADS1115[%zu] cfg=0x%04X mux=%u wait=%u ticks lo=0x%04X hi=0x%04X", i, cfg, dev->current_mux,
                 (unsigned)dev->conversion_wait_ticks, lo, hi);
    }
}

static __attribute__((constructor)) void ads1115_constructor(void)
{
    reset_state();
}