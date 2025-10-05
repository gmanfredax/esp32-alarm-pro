#include "i2c_bus.h"
#include "esp_check.h"
#include "esp_log.h"
#include "pins.h"  // I2C_SDA_GPIO, I2C_SCL_GPIO, I2C_SPEED_HZ

static const char* TAG = "i2c_bus";
static i2c_master_bus_handle_t s_bus = NULL;

esp_err_t i2c_bus_init(void)
{
    if (s_bus) return ESP_OK;
    i2c_master_bus_config_t bus_cfg = {
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .sda_io_num = I2C_SDA_GPIO,
        .scl_io_num = I2C_SCL_GPIO,
        .glitch_ignore_cnt = 7,
        .flags = { .enable_internal_pullup = true } // solo aiuto in debug; restano valide le 10k esterne
    };
    ESP_RETURN_ON_ERROR(i2c_new_master_bus(&bus_cfg, &s_bus), TAG, "i2c_new_master_bus failed");
    ESP_LOGI(TAG, "I2C bus ready: SDA=%d SCL=%d speed=%u", I2C_SDA_GPIO, I2C_SCL_GPIO, I2C_SPEED_HZ);
    return ESP_OK;
}

i2c_master_bus_handle_t i2c_bus_get(void)
{
    // Se qualcuno chiama prima di init, proviamo a inizializzare noi.
    if (!s_bus) {
        if (i2c_bus_init() != ESP_OK) return NULL;
    }
    return s_bus;
}