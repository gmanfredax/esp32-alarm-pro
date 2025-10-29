#include "ads1115.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_check.h"
#include "esp_log.h"
#include "driver/i2c_master.h"
#include <stdbool.h>

#include "i2c_bus.h"
#include "pins.h"

typedef struct {
    bool attached;
    uint8_t address;
    i2c_master_dev_handle_t dev;
} ads1115_slot_t;

static const char *TAG = "ads1115";
static ads1115_slot_t s_slots[ADS1115_MAX_DEVICES];
static bool s_initialized = false;

static esp_err_t ensure_initialized(void)
{
    if (!s_initialized) {
        ESP_RETURN_ON_ERROR(i2c_bus_init(), TAG, "i2c_bus_init");
        s_initialized = true;
    }
    return ESP_OK;
}

esp_err_t ads1115_init(void)
{
    return ensure_initialized();
}

esp_err_t ads1115_attach(uint8_t index, uint8_t address)
{
    if (index >= ADS1115_MAX_DEVICES) {
        return ESP_ERR_INVALID_ARG;
    }
    ESP_RETURN_ON_ERROR(ensure_initialized(), TAG, "ensure_initialized");

    ads1115_slot_t *slot = &s_slots[index];
    if (slot->attached) {
        if (slot->address == address) {
            return ESP_OK;
        }
        if (slot->dev) {
            ESP_RETURN_ON_ERROR(i2c_master_bus_rm_device(slot->dev), TAG, "rm_device");
        }
        slot->attached = false;
        slot->dev = NULL;
    }

    i2c_device_config_t dev_cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = address,
        .scl_speed_hz = I2C_SPEED_HZ,
    };

    ESP_RETURN_ON_ERROR(i2c_master_bus_add_device(i2c_bus_get(), &dev_cfg, &slot->dev),
                        TAG,
                        "add_device");

    slot->attached = true;
    slot->address = address;
    ESP_LOGI(TAG, "ADS1115 attached on index %u (addr=0x%02X)", (unsigned)index, (unsigned)address);
    return ESP_OK;
}

static ads1115_slot_t *get_slot(uint8_t index)
{
    if (index >= ADS1115_MAX_DEVICES) {
        return NULL;
    }
    ads1115_slot_t *slot = &s_slots[index];
    if (!slot->attached) {
        return NULL;
    }
    return slot;
}

float ads1115_raw_to_mv(int16_t raw)
{
    // PGA ±4.096 V => LSB 125 µV => 0.125 mV
    return (float)raw * 0.125f;
}

esp_err_t ads1115_read_raw(uint8_t index, uint8_t channel, int16_t *out_raw)
{
    if (!out_raw) {
        return ESP_ERR_INVALID_ARG;
    }
    ads1115_slot_t *slot = get_slot(index);
    if (!slot) {
        return ESP_ERR_INVALID_STATE;
    }
    if (channel > 3) {
        return ESP_ERR_INVALID_ARG;
    }

    static const uint16_t mux_table[4] = {
        0x4000, // AIN0
        0x5000, // AIN1
        0x6000, // AIN2
        0x7000, // AIN3
    };

    uint16_t config = 0x8000; // OS=1 (start single conversion)
    config |= mux_table[channel];
    config |= 0x0200; // PGA ±4.096V
    config |= 0x0100; // MODE=1 (single-shot)
    config |= 0x00E0; // DR=111 (860SPS)
    config |= 0x0003; // Disable comparator

    uint8_t buf[3];
    buf[0] = 0x01; // Config register
    buf[1] = (uint8_t)(config >> 8);
    buf[2] = (uint8_t)(config & 0xFF);

    ESP_RETURN_ON_ERROR(i2c_master_transmit(slot->dev, buf, sizeof(buf), 1000),
                        TAG,
                        "write_config");

    vTaskDelay(pdMS_TO_TICKS(2));

    uint8_t reg = 0x00;
    uint8_t data[2] = {0};
    ESP_RETURN_ON_ERROR(i2c_master_transmit_receive(slot->dev, &reg, 1, data, sizeof(data), 1000),
                        TAG,
                        "read_conversion");

    int16_t raw = (int16_t)((data[0] << 8) | data[1]);
    *out_raw = raw;
    return ESP_OK;
}

esp_err_t ads1115_read_mv(uint8_t index, uint8_t channel, float *out_mv)
{
    if (!out_mv) {
        return ESP_ERR_INVALID_ARG;
    }
    int16_t raw = 0;
    ESP_RETURN_ON_ERROR(ads1115_read_raw(index, channel, &raw), TAG, "read_raw");
    *out_mv = ads1115_raw_to_mv(raw);
    return ESP_OK;
}