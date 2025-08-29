// mcp23017.c — IDF 5.x (nuova API I2C bus/device)
#include <string.h>
#include "esp_log.h"
#include "driver/i2c.h"
#include "pins.h"   // I2C_SDA_GPIO, I2C_SCL_GPIO, I2C_SPEED_HZ, MCP23017_ADDR

#define IODIRA 0x00
#define IODIRB 0x01
#define GPPUA  0x0C
#define GPPUB  0x0D
#define GPIOA  0x12
#define GPIOB  0x13

static const char* TAG = "mcp23017";

static i2c_master_bus_handle_t s_i2c_bus = NULL;
static i2c_master_dev_handle_t s_dev     = NULL;

static esp_err_t wr(uint8_t reg, uint8_t val) {
    uint8_t b[2] = { reg, val };
    return i2c_master_transmit(s_dev, b, sizeof(b), 1000);
}

static esp_err_t rd(uint8_t reg, uint8_t* val) {
    return i2c_master_transmit_receive(s_dev, &reg, 1, val, 1, 1000);
}

esp_err_t inputs_init(void)
{
    // 1) BUS
    i2c_master_bus_config_t bus_cfg = {
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .scl_io_num = I2C_SCL_GPIO,
        .sda_io_num = I2C_SDA_GPIO,
        .glitch_ignore_cnt = 7,
        .flags = { .enable_internal_pullup = true } // metti false se usi pullup esterni
    };
    ESP_ERROR_CHECK(i2c_new_master_bus(&bus_cfg, &s_i2c_bus));

    // 2) DEVICE MCP23017
    i2c_device_config_t dev_cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address  = MCP23017_ADDR,
        .scl_speed_hz    = I2C_SPEED_HZ,
    };
    ESP_ERROR_CHECK(i2c_master_bus_add_device(s_i2c_bus, &dev_cfg, &s_dev));

    // 3) Config MCP: tutti input + pull-up
    ESP_ERROR_CHECK(wr(IODIRA, 0xFF));
    ESP_ERROR_CHECK(wr(IODIRB, 0xFF));
    ESP_ERROR_CHECK(wr(GPPUA,  0xFF));
    ESP_ERROR_CHECK(wr(GPPUB,  0xFF));

    ESP_LOGI(TAG, "MCP23017 @0x%02X pronto (SDA=%d SCL=%d %d Hz)",
             MCP23017_ADDR, I2C_SDA_GPIO, I2C_SCL_GPIO, I2C_SPEED_HZ);
    return ESP_OK;
}

esp_err_t inputs_read_all(uint16_t* gpioab)
{
    uint8_t a = 0, b = 0;
    ESP_ERROR_CHECK(rd(GPIOA, &a));
    ESP_ERROR_CHECK(rd(GPIOB, &b));
    *gpioab = ((uint16_t)b << 8) | a;
    return ESP_OK;
}

void inputs_deinit(void)
{
    if (s_dev)  { i2c_master_bus_rm_device(s_dev); s_dev = NULL; }
    if (s_i2c_bus) { i2c_del_master_bus(s_i2c_bus); s_i2c_bus = NULL; }
}
