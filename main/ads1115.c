#include "ads1115.h"

#include <inttypes.h>
#include <string.h>

#include "esp_check.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "driver/i2c_master.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

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

#define ADS1115_I2C_TIMEOUT_MS        200
#define ADS1115_SCAN_TIMEOUT_MS       25
#define ADS1115_ERROR_BACKOFF_SHORT   pdMS_TO_TICKS(100)
#define ADS1115_ERROR_BACKOFF_MEDIUM  pdMS_TO_TICKS(500)
#define ADS1115_ERROR_BACKOFF_LONG    pdMS_TO_TICKS(2000)

typedef struct {
    bool in_use;
    i2c_master_dev_handle_t handle;
    uint8_t address;
    ads1115_operating_config_t options;
    ads1115_mux_t current_mux;
    uint16_t base_config;
    uint16_t last_config_word;
    TickType_t conversion_wait_ticks;
    TickType_t poll_delay_ticks;
    TickType_t resume_at_tick;
    uint32_t consecutive_failures;
    uint64_t last_seen_ms;
    esp_err_t last_error;
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
    return i2c_master_transmit(dev, payload, sizeof(payload), ADS1115_I2C_TIMEOUT_MS);
}

static esp_err_t read_reg(i2c_master_dev_handle_t dev, uint8_t reg, uint16_t* value)
{
    uint8_t rx[2] = { 0 };
    esp_err_t err = i2c_master_transmit_receive(dev, &reg, 1, rx, sizeof(rx), ADS1115_I2C_TIMEOUT_MS);
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

bool ads1115_is_valid_address(uint8_t address)
{
    return address >= 0x48 && address <= 0x4B;
}

static ads1115_device_t* find_device_by_address(uint8_t address)
{
    for (size_t i = 0; i < s_device_count; ++i) {
        if (s_devices[i].in_use && s_devices[i].address == address) {
            return &s_devices[i];
        }
    }
    return NULL;
}

static TickType_t select_backoff_ticks(uint32_t failures)
{
    if (failures > 6) {
        return ensure_min_tick(ADS1115_ERROR_BACKOFF_LONG);
    }
    if (failures > 3) {
        return ensure_min_tick(ADS1115_ERROR_BACKOFF_MEDIUM);
    }
    return ensure_min_tick(ADS1115_ERROR_BACKOFF_SHORT);
}

static bool error_requires_reset(esp_err_t err)
{
    return err == ESP_ERR_TIMEOUT || err == ESP_FAIL || err == ESP_ERR_INVALID_STATE;
}

static void record_failure(size_t unit, ads1115_device_t* dev, esp_err_t err)
{
    dev->consecutive_failures++;
    dev->last_error = err;
    TickType_t backoff = select_backoff_ticks(dev->consecutive_failures);
    dev->resume_at_tick = xTaskGetTickCount() + backoff;

    if (dev->consecutive_failures == 1 || (dev->consecutive_failures % 3u) == 0u) {
        ESP_LOGW(TAG,
                 "ADS1115[%zu] I2C failure (%s). Consecutive=%" PRIu32 " backoff=%lu ticks",
                 unit,
                 esp_err_to_name(err),
                 (uint32_t)dev->consecutive_failures,
                 (unsigned long)backoff);
    }

    if (error_requires_reset(err)) {
        esp_err_t reset_err = i2c_bus_reset();
        if (reset_err != ESP_OK) {
            ESP_LOGW(TAG, "ADS1115[%zu] bus reset reported: %s", unit, esp_err_to_name(reset_err));
        }
    }
}

static void record_success(ads1115_device_t* dev)
{
    dev->consecutive_failures = 0;
    dev->resume_at_tick = 0;
    dev->last_error = ESP_OK;
    dev->last_seen_ms = esp_timer_get_time() / 1000ULL;
}

static bool device_is_suspended(ads1115_device_t* dev)
{
    if (dev->resume_at_tick == 0) {
        return false;
    }
    TickType_t now = xTaskGetTickCount();
    if ((int32_t)(now - dev->resume_at_tick) < 0) {
        return true;
    }
    dev->resume_at_tick = 0;
    return false;
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
        s_devices[i].address = 0;
        memset(&s_devices[i].options, 0, sizeof(s_devices[i].options));
        s_devices[i].current_mux = ADS1115_MUX_AIN0_GND;
        s_devices[i].base_config = 0;
        s_devices[i].last_config_word = 0;
        s_devices[i].conversion_wait_ticks = 1;
        s_devices[i].poll_delay_ticks = ensure_min_tick(pdMS_TO_TICKS(1));
        s_devices[i].resume_at_tick = 0;
        s_devices[i].consecutive_failures = 0;
        s_devices[i].last_seen_ms = 0;
        s_devices[i].last_error = ESP_OK;
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
    }
    reset_state();
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

    size_t ready = 0;
    for (size_t i = 0; i < count; ++i) {
        const ads1115_device_config_t* cfg = &configs[i];
        ESP_LOGI(TAG, "i2c_optional: ADS1115 addr=0x%02X configured, probe", cfg->address);
        ads1115_device_t* dev = &s_devices[ready];

        i2c_device_config_t dev_cfg = {
            .dev_addr_length = I2C_ADDR_BIT_LEN_7,
            .device_address = cfg->address,
            .scl_speed_hz = I2C_SPEED_HZ,
        };

        esp_err_t err = i2c_master_bus_add_device(bus, &dev_cfg, &dev->handle);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "ADS1115 add_device @0x%02X failed: %s", cfg->address, esp_err_to_name(err));
            continue;
        }

        dev->options = cfg->options;
        dev->base_config = build_config_word(&dev->options);
        dev->current_mux = cfg->default_mux;
        dev->conversion_wait_ticks = compute_wait_ticks(&dev->options);
        dev->poll_delay_ticks = ensure_min_tick(pdMS_TO_TICKS(1));
        dev->in_use = true;
        dev->address = cfg->address;
        dev->last_error = ESP_OK;

        bool skip_thresholds = (dev->options.comp_queue == ADS1115_COMP_QUEUE_DISABLE);
        if (!skip_thresholds) {
            err = write_reg(dev->handle, ADS1115_REG_LO_THRESH, 0x8000);
            if (err != ESP_OK) {
                ESP_LOGW(TAG, "ADS1115 @0x%02X NACK writing LO threshold: %s", cfg->address, esp_err_to_name(err));
                goto skip_device;
            }
            err = write_reg(dev->handle, ADS1115_REG_HI_THRESH, 0x7FFF);
            if (err != ESP_OK) {
                ESP_LOGW(TAG, "ADS1115 @0x%02X NACK writing HI threshold: %s", cfg->address, esp_err_to_name(err));
                goto skip_device;
            }
        }

        err = apply_config_to_device(dev, cfg->default_mux);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "ADS1115 @0x%02X configuration failed: %s", cfg->address, esp_err_to_name(err));
            ESP_LOGW(TAG, "i2c_optional: ADS1115 addr=0x%02X configured but not detected after 3 attempts, marked offline", cfg->address);
            goto skip_device;
        }

        ESP_LOGI(TAG, "ADS1115[%zu] ready @0x%02X (mode=%s, gain=%d, rate=%d SPS)", ready, cfg->address,
                 (cfg->options.mode == ADS1115_MODE_SINGLE_SHOT) ? "single" : "continuous",
                 cfg->options.gain, cfg->options.data_rate);
        record_success(dev);
        ready++;
        continue;

    skip_device:
        if (dev->handle) {
            esp_err_t rm_err = i2c_master_bus_rm_device(dev->handle);
            if (rm_err != ESP_OK) {
                ESP_LOGW(TAG, "ADS1115 cleanup @0x%02X failed: %s", cfg->address, esp_err_to_name(rm_err));
            }
        }
        memset(dev, 0, sizeof(*dev));
        dev->poll_delay_ticks = ensure_min_tick(pdMS_TO_TICKS(1));
    }

    s_device_count = ready;
    if (ready == 0 && count > 0) {
        ESP_LOGW(TAG, "No ADS1115 devices responded (requested=%zu)", count);
        return ESP_ERR_NOT_FOUND;
    }
    if (ready > 0 && ready < count) {
        ESP_LOGW(TAG, "ADS1115 detected %zu/%zu requested device(s)", ready, count);
    }
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

esp_err_t ads1115_get_info(size_t unit, ads1115_device_info_t* out_info)
{
    ads1115_device_t* dev = get_device(unit);
    ESP_RETURN_ON_FALSE(dev && dev->in_use, ESP_ERR_INVALID_ARG, TAG, "invalid unit");
    ESP_RETURN_ON_FALSE(out_info != NULL, ESP_ERR_INVALID_ARG, TAG, "null info");

    out_info->address = dev->address;
    out_info->options = dev->options;
    out_info->current_mux = dev->current_mux;
    out_info->last_config_word = dev->last_config_word;
    out_info->detected = true;
    out_info->online = !device_is_suspended(dev);
    out_info->last_seen_ms = dev->last_seen_ms;
    out_info->last_error = dev->last_error;
    out_info->consecutive_failures = dev->consecutive_failures;
    return ESP_OK;
}

esp_err_t ads1115_probe_address(uint8_t address, TickType_t timeout_ticks)
{
    if (!ads1115_is_valid_address(address)) {
        return ESP_ERR_INVALID_ARG;
    }

    uint32_t timeout_ms = pdTICKS_TO_MS(timeout_ticks);
    if (timeout_ms == 0 || timeout_ms > ADS1115_SCAN_TIMEOUT_MS) {
        timeout_ms = ADS1115_SCAN_TIMEOUT_MS;
    }

    ads1115_device_t* existing = find_device_by_address(address);
    uint16_t cfg = 0;
    if (existing && existing->handle) {
        esp_err_t err = read_reg(existing->handle, ADS1115_REG_CONFIG, &cfg);
        if (err == ESP_OK) {
            record_success(existing);
        } else {
            record_failure((size_t)(existing - s_devices), existing, err);
        }
        return err;
    }

    i2c_master_bus_handle_t bus = i2c_bus_get();
    if (!bus) {
        return ESP_ERR_INVALID_STATE;
    }

    i2c_master_dev_handle_t tmp = NULL;
    i2c_device_config_t dev_cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = address,
        .scl_speed_hz = I2C_SPEED_HZ,
    };
    esp_err_t err = i2c_master_bus_add_device(bus, &dev_cfg, &tmp);
    if (err != ESP_OK) {
        return err;
    }
    uint8_t reg = ADS1115_REG_CONFIG;
    uint8_t rx[2] = {0};
    err = i2c_master_transmit_receive(tmp, &reg, 1, rx, sizeof(rx), timeout_ms);
    esp_err_t rm_err = i2c_master_bus_rm_device(tmp);
    if (rm_err != ESP_OK) {
        ESP_LOGW(TAG, "ADS1115 probe cleanup @0x%02X: %s", address, esp_err_to_name(rm_err));
    }
    return err;
}

esp_err_t ads1115_scan(ads1115_scan_result_t* out_result)
{
    if (!out_result) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(out_result, 0, sizeof(*out_result));
    out_result->scan_time_ms = esp_timer_get_time() / 1000ULL;
    for (uint8_t address = 0x48; address <= 0x4B; ++address) {
        esp_err_t err = ads1115_probe_address(address, pdMS_TO_TICKS(ADS1115_SCAN_TIMEOUT_MS));
        out_result->detected[address - 0x48] = (err == ESP_OK);
    }
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

    if (device_is_suspended(dev)) {
        return ESP_ERR_TIMEOUT;
    }

    uint16_t reg_val = 0;
    esp_err_t err = read_reg(dev->handle, ADS1115_REG_CONVERSION, &reg_val);
    if (err != ESP_OK) {
        record_failure(unit, dev, err);
        return err;
    }
    record_success(dev);
    *raw_value = (int16_t)reg_val;
    return ESP_OK;
}

esp_err_t ads1115_single_shot(size_t unit, ads1115_mux_t mux, TickType_t timeout_ticks, int16_t* raw_value)
{
    ads1115_device_t* dev = get_device(unit);
    ESP_RETURN_ON_FALSE(dev && dev->in_use, ESP_ERR_INVALID_ARG, TAG, "invalid unit");
    ESP_RETURN_ON_FALSE(raw_value != NULL, ESP_ERR_INVALID_ARG, TAG, "null out");
    ESP_RETURN_ON_FALSE(dev->options.mode == ADS1115_MODE_SINGLE_SHOT, ESP_ERR_INVALID_STATE, TAG, "not in single-shot mode");

    if (device_is_suspended(dev)) {
        return ESP_ERR_TIMEOUT;
    }

    esp_err_t err = apply_config_to_device(dev, mux);
    if (err != ESP_OK) {
        record_failure(unit, dev, err);
        return err;
    }

    err = wait_conversion_ready(dev, timeout_ticks);
    if (err != ESP_OK) {
        record_failure(unit, dev, err);
        return err;
    }

    uint16_t reg_val = 0;
    err = read_reg(dev->handle, ADS1115_REG_CONVERSION, &reg_val);
    if (err != ESP_OK) {
        record_failure(unit, dev, err);
        return err;
    }

    record_success(dev);
    *raw_value = (int16_t)reg_val;
    return ESP_OK;
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