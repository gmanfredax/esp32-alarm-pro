// outputs.c — MCP23017 uscite, riuso bus I2C (ESP-IDF 5.x)
#include <string.h>
#include "esp_log.h"
#include "esp_check.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "driver/i2c_master.h"

#include "pins.h"       // MCP23017_ADDR, MCPB_*_BIT
#include "i2c_bus.h"    // i2c_bus_get()
#include "outputs.h"

/* Verifica che pins.h esponga le macro attese */
#ifndef MCP23017_ADDR
#error "MCP23017_ADDR non definito in pins.h"
#endif
#ifndef MCPB_RELAY_BIT
#error "MCPB_RELAY_BIT non definito in pins.h"
#endif
#ifndef MCPB_LED_STATO_BIT
#error "MCPB_LED_STATO_BIT non definito in pins.h"
#endif
#ifndef MCPB_LED_MANUT_BIT
#error "MCPB_LED_MANUT_BIT non definito in pins.h"
#endif

// Registri MCP23017
#define MCP_IODIRA   0x00
#define MCP_IODIRB   0x01
#define MCP_GPPUA    0x0C
#define MCP_GPPUB    0x0D
#define MCP_GPIOA    0x12
#define MCP_GPIOB    0x13

static const char *TAG = "outputs";

static i2c_master_dev_handle_t s_dev = NULL;
static SemaphoreHandle_t s_lock = NULL;
// Mirror stato: bit0..7 = A0..A7, bit8..15 = B0..B7
static uint16_t s_mask = 0;

// Helpers I2C
static esp_err_t wr_reg(uint8_t reg, uint8_t val)
{
    uint8_t buf[2] = { reg, val };
    return i2c_master_transmit(s_dev, buf, sizeof(buf), -1);
}

static esp_err_t wr_ab(uint8_t reg_a, uint8_t val_a, uint8_t reg_b, uint8_t val_b)
{
    ESP_RETURN_ON_ERROR(wr_reg(reg_a, val_a), TAG, "wr A 0x%02X", reg_a);
    ESP_RETURN_ON_ERROR(wr_reg(reg_b, val_b), TAG, "wr B 0x%02X", reg_b);
    return ESP_OK;
}

static esp_err_t push_mask_to_hw(uint16_t mask)
{
    uint8_t a = (uint8_t)(mask & 0xFF);
    uint8_t b = (uint8_t)((mask >> 8) & 0xFF);
    return wr_ab(MCP_GPIOA, a, MCP_GPIOB, b);
}

esp_err_t outputs_init(void)
{
    if (!s_lock) {
        s_lock = xSemaphoreCreateMutex();
        ESP_RETURN_ON_FALSE(s_lock != NULL, ESP_ERR_NO_MEM, TAG, "mutex");
    }

    i2c_master_bus_handle_t bus = i2c_bus_get();
    ESP_RETURN_ON_FALSE(bus != NULL, ESP_ERR_INVALID_STATE, TAG, "I2C bus not ready");

    if (s_dev == NULL) {
        i2c_device_config_t dev_cfg = {
            .dev_addr_length = I2C_ADDR_BIT_LEN_7,
            .device_address  = MCP23017_ADDR,
            .scl_speed_hz    = 100000,  // effettiva = quella del bus
        };
        ESP_RETURN_ON_ERROR(i2c_master_bus_add_device(bus, &dev_cfg, &s_dev),
                            TAG, "add dev 0x%02X", MCP23017_ADDR);
    }

    // Tutte uscite, niente pull-up, tutte OFF
    ESP_RETURN_ON_ERROR(wr_ab(MCP_IODIRA, 0x00, MCP_IODIRB, 0x00), TAG, "IODIR");
    ESP_RETURN_ON_ERROR(wr_ab(MCP_GPPUA,  0x00, MCP_GPPUB,  0x00), TAG, "GPPU");

    s_mask = 0;
    ESP_RETURN_ON_ERROR(push_mask_to_hw(s_mask), TAG, "clear");

    ESP_LOGI(TAG, "Outputs ready on MCP23017 @0x%02X (A0..A7,B0..B7).", MCP23017_ADDR);
    return ESP_OK;
}

esp_err_t outputs_set(uint8_t ch, bool on)
{
    if (ch == 0 || ch > 16) return ESP_ERR_INVALID_ARG;
    ESP_RETURN_ON_FALSE(s_dev != NULL, ESP_ERR_INVALID_STATE, TAG, "not initialized");

    xSemaphoreTake(s_lock, portMAX_DELAY);
    uint16_t new_mask = s_mask;
    uint16_t bit = (1u << (ch - 1));
    if (on) new_mask |= bit; else new_mask &= ~bit;

    esp_err_t err = ESP_OK;
    if (new_mask != s_mask) {
        err = push_mask_to_hw(new_mask);
        if (err == ESP_OK) s_mask = new_mask;
    }
    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t outputs_toggle(uint8_t ch)
{
    if (ch == 0 || ch > 16) return ESP_ERR_INVALID_ARG;
    ESP_RETURN_ON_FALSE(s_dev != NULL, ESP_ERR_INVALID_STATE, TAG, "not initialized");

    xSemaphoreTake(s_lock, portMAX_DELAY);
    uint16_t new_mask = s_mask ^ (1u << (ch - 1));
    esp_err_t err = push_mask_to_hw(new_mask);
    if (err == ESP_OK) s_mask = new_mask;
    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t outputs_set_mask(uint16_t mask)
{
    ESP_RETURN_ON_FALSE(s_dev != NULL, ESP_ERR_INVALID_STATE, TAG, "not initialized");

    xSemaphoreTake(s_lock, portMAX_DELAY);
    esp_err_t err = push_mask_to_hw(mask);
    if (err == ESP_OK) s_mask = mask;
    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t outputs_get_mask(uint16_t *out_mask)
{
    if (!out_mask) return ESP_ERR_INVALID_ARG;
    ESP_RETURN_ON_FALSE(s_dev != NULL, ESP_ERR_INVALID_STATE, TAG, "not initialized");

    xSemaphoreTake(s_lock, portMAX_DELAY);
    *out_mask = s_mask;
    xSemaphoreGive(s_lock);
    return ESP_OK;
}

esp_err_t outputs_all_off(void)
{
    return outputs_set_mask(0);
}

/* ───────── Uscite semantiche: bit su PORTB (B0..B7 → canali 9..16) ───────── */
static inline uint8_t ch_from_portb_bit(uint8_t portb_bit /*0..7*/)
{
    return (uint8_t)(9u + portb_bit);  // B0=ch9 ... B7=ch16
}

void outputs_siren(bool on)
{
    uint8_t ch = ch_from_portb_bit((uint8_t)MCPB_RELAY_BIT);
    esp_err_t err = outputs_set(ch, on);
    if (err != ESP_OK) ESP_LOGE(TAG, "siren(%d) ch=%u err=%s", (int)on, ch, esp_err_to_name(err));
}

void outputs_led_state(bool on)
{
    uint8_t ch = ch_from_portb_bit((uint8_t)MCPB_LED_STATO_BIT);
    esp_err_t err = outputs_set(ch, on);
    if (err != ESP_OK) ESP_LOGE(TAG, "led_state(%d) ch=%u err=%s", (int)on, ch, esp_err_to_name(err));
}

void outputs_led_maint(bool on)
{
    uint8_t ch = ch_from_portb_bit((uint8_t)MCPB_LED_MANUT_BIT);
    esp_err_t err = outputs_set(ch, on);
    if (err != ESP_OK) ESP_LOGE(TAG, "led_maint(%d) ch=%u err=%s", (int)on, ch, esp_err_to_name(err));
}
