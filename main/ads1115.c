#include "ads1115.h"

#include "esp_log.h"
#include "esp_check.h"
#include "esp_rom_sys.h"
#include "driver/i2c_master.h"

#include "i2c_bus.h"

typedef struct {
    uint8_t addr;
    i2c_master_dev_handle_t dev;
} ads_device_t;

static const char *TAG = "ads1115";

static ads_device_t s_devices[] = {
    { 0x48, NULL },
    { 0x49, NULL },
    { 0x4A, NULL },
};

static ads_device_t *find_device(uint8_t addr)
{
    for (size_t i = 0; i < sizeof(s_devices) / sizeof(s_devices[0]); ++i) {
        if (s_devices[i].addr == addr) {
            return &s_devices[i];
        }
    }
    return NULL;
}

static esp_err_t ensure_device(ads_device_t *device)
{
    if (!device) {
        return ESP_ERR_INVALID_ARG;
    }
    if (device->dev) {
        return ESP_OK;
    }
    i2c_master_bus_handle_t bus = i2c_bus_get();
    ESP_RETURN_ON_FALSE(bus != NULL, ESP_ERR_INVALID_STATE, TAG, "I2C bus not ready");

    i2c_device_config_t cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address  = device->addr,
        .scl_speed_hz    = 100000,
    };

    ESP_RETURN_ON_ERROR(i2c_master_bus_add_device(bus, &cfg, &device->dev), TAG, "add_device");
    return ESP_OK;
}

esp_err_t ads1115_init(void)
{
    for (size_t i = 0; i < sizeof(s_devices) / sizeof(s_devices[0]); ++i) {
        esp_err_t err = ensure_device(&s_devices[i]);
        if (err != ESP_OK) {
            return err;
        }
    }
    ESP_LOGI(TAG, "ADS1115 devices initialised");
    return ESP_OK;
}

static esp_err_t write_config(i2c_master_dev_handle_t dev, uint16_t config)
{
    uint8_t buf[3];
    buf[0] = 0x01; // config register pointer
    buf[1] = (uint8_t)((config >> 8) & 0xFF);
    buf[2] = (uint8_t)(config & 0xFF);
    return i2c_master_transmit(dev, buf, sizeof(buf), 1000);
}

static esp_err_t read_conversion(i2c_master_dev_handle_t dev, int16_t *out_code)
{
    if (!out_code) {
        return ESP_ERR_INVALID_ARG;
    }
    uint8_t reg = 0x00;
    uint8_t data[2] = {0};
    esp_err_t err = i2c_master_transmit_receive(dev, &reg, 1, data, sizeof(data), 1000);
    if (err != ESP_OK) {
        return err;
    }
    *out_code = (int16_t)((data[0] << 8) | data[1]);
    return ESP_OK;
}

esp_err_t ads1115_read_single(uint8_t addr, uint8_t channel, int16_t *out_code)
{
    if (!out_code) {
        return ESP_ERR_INVALID_ARG;
    }
    if (channel > 3) {
        return ESP_ERR_INVALID_ARG;
    }
    ads_device_t *device = find_device(addr);
    ESP_RETURN_ON_FALSE(device != NULL, ESP_ERR_INVALID_ARG, TAG, "Unknown ADS1115 addr 0x%02X", addr);
    ESP_RETURN_ON_ERROR(ensure_device(device), TAG, "ensure_device");

    uint16_t mux = (uint16_t)(0x04u + channel); // single-ended AINx vs GND
    uint16_t config = 0;
    config |= 0x8000u;                   // OS = start single conversion
    config |= (mux & 0x07u) << 12;       // MUX bits
    config |= 0x0200u;                   // PGA ±4.096V
    config |= 0x0100u;                   // MODE = single-shot
    config |= 0x00E0u;                   // Data rate 860 SPS
    config |= 0x0003u;                   // Disable comparator (QUE=11)

    ESP_RETURN_ON_ERROR(write_config(device->dev, config), TAG, "write_config");
    esp_rom_delay_us(1400); // wait for conversion (~1.2ms at 860 SPS)
    ESP_RETURN_ON_ERROR(read_conversion(device->dev, out_code), TAG, "read_conv");
    return ESP_OK;
}