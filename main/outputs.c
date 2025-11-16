#include "outputs.h"

#include <string.h>

#include "esp_log.h"
#include "esp_check.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "driver/i2c_master.h"

#include "pins.h"
#include "i2c_bus.h"

#define TAG "outputs"

#define MCP_IODIRA   0x00
#define MCP_IODIRB   0x01
#define MCP_GPPUA    0x0C
#define MCP_GPPUB    0x0D
#define MCP_GPIOA    0x12
#define MCP_GPIOB    0x13
#define MCP_OLATA    0x14
#define MCP_OLATB    0x15

#define BIT_(x) (1u << (x))

static const uint8_t PORTA_OUTPUT_MASK =
    BIT_(MCP_PORTA_LED_STATE_BIT) |
    BIT_(MCP_PORTA_LED_ALARM_BIT) |
    BIT_(MCP_PORTA_LED_MAINT_BIT) |
    BIT_(MCP_PORTA_LED_PROV_R_BIT) |
    BIT_(MCP_PORTA_LED_PROV_G_BIT) |
    BIT_(MCP_PORTA_LED_PROV_B_BIT);

static const uint8_t PORTB_OUTPUT_MASK =
    BIT_(MCP_PORTB_SIREN_INT_BIT) |
    BIT_(MCP_PORTB_SIREN_EXT_BIT) |
    BIT_(MCP_PORTB_FOG_BIT);

static const uint8_t PORTB_INPUT_MASK = BIT_(MCP_PORTB_GLOBAL_TAMPER_BIT);

static i2c_master_dev_handle_t s_dev = NULL;
static SemaphoreHandle_t      s_lock = NULL;
static uint8_t                s_cache_a = 0x00;
static uint8_t                s_cache_b = 0x00;

static esp_err_t rd_reg(uint8_t reg, uint8_t *val)
{
    if (!s_dev) {
        return ESP_ERR_INVALID_STATE;
    }
    return i2c_master_transmit_receive(s_dev, &reg, 1, val, 1, -1);
}

static esp_err_t wr_reg(uint8_t reg, uint8_t val)
{
    if (!s_dev) {
        return ESP_ERR_INVALID_STATE;
    }
    uint8_t buf[2] = { reg, val };
    return i2c_master_transmit(s_dev, buf, sizeof(buf), -1);
}

static esp_err_t update_bits(uint8_t reg, uint8_t mask, uint8_t value)
{
    uint8_t cur = 0;
    ESP_RETURN_ON_ERROR(rd_reg(reg, &cur), TAG, "rd 0x%02X", reg);
    cur = (cur & ~mask) | (value & mask);
    return wr_reg(reg, cur);
}

static esp_err_t write_porta(void)
{
    return update_bits(MCP_OLATA, PORTA_OUTPUT_MASK, s_cache_a & PORTA_OUTPUT_MASK);
}

static esp_err_t write_portb(void)
{
    return update_bits(MCP_OLATB, PORTB_OUTPUT_MASK, s_cache_b & PORTB_OUTPUT_MASK);
}

static esp_err_t ensure_device(void)
{
    if (s_dev) {
        return ESP_OK;
    }
    i2c_master_bus_handle_t bus = i2c_bus_get();
    ESP_RETURN_ON_FALSE(bus != NULL, ESP_ERR_INVALID_STATE, TAG, "I2C bus not ready");
    i2c_device_config_t dev_cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address  = MCP23017_ADDR,
        .scl_speed_hz    = I2C_SPEED_HZ,
    };
    return i2c_master_bus_add_device(bus, &dev_cfg, &s_dev);
}

esp_err_t outputs_init(void)
{
    if (!s_lock) {
        s_lock = xSemaphoreCreateMutex();
        ESP_RETURN_ON_FALSE(s_lock != NULL, ESP_ERR_NO_MEM, TAG, "mutex");
    }

    ESP_RETURN_ON_ERROR(ensure_device(), TAG, "attach");

    // Configura PORTA come uscite LED
    ESP_RETURN_ON_ERROR(update_bits(MCP_IODIRA, PORTA_OUTPUT_MASK, 0x00), TAG, "IODIRA outs");
    ESP_RETURN_ON_ERROR(update_bits(MCP_GPPUA,  PORTA_OUTPUT_MASK, 0x00), TAG, "GPPUA offs");
    
    // Configura PORTB: B0..B2 uscire, B5 ingresso con pull-up
    uint8_t out_mask = PORTB_OUTPUT_MASK;
    uint8_t in_mask  = PORTB_INPUT_MASK;
    ESP_RETURN_ON_ERROR(update_bits(MCP_IODIRB, out_mask, 0x00), TAG, "IODIRB outs");
    ESP_RETURN_ON_ERROR(update_bits(MCP_IODIRB, in_mask, in_mask), TAG, "IODIRB tamper in");
    ESP_RETURN_ON_ERROR(update_bits(MCP_GPPUB,  out_mask, 0x00), TAG, "GPPUB outs off");
    ESP_RETURN_ON_ERROR(update_bits(MCP_GPPUB,  in_mask, in_mask), TAG, "GPPUB tamper pull");

    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_cache_a &= ~PORTA_OUTPUT_MASK;  // Tutti LED OFF
    s_cache_b &= ~PORTB_OUTPUT_MASK;  // Tutti output OFF
    esp_err_t err_a = write_porta();
    esp_err_t err_b = write_portb();
    xSemaphoreGive(s_lock);
    ESP_RETURN_ON_ERROR(err_a, TAG, "write porta");
    ESP_RETURN_ON_ERROR(err_b, TAG, "write portb");

    uint8_t iodira=0, iodirb=0, gppua = 0, gppub=0;
    rd_reg(MCP_IODIRA, &iodira);
    rd_reg(MCP_IODIRB, &iodirb);
    rd_reg(MCP_GPPUA,  &gppua);
    rd_reg(MCP_GPPUB,  &gppub);
    ESP_LOGI(TAG, "Outputs ready @0x%02X IODIRA=0x%02X IODIRB=0x%02X GPPUA=0x%02X GPPUB=0x%02X",
             MCP23017_ADDR, iodira, iodirb, gppua, gppub);
    return ESP_OK;
}

static esp_err_t set_port_bit(uint8_t channel, bool on)
{
    if (channel == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    uint8_t idx = (uint8_t)(channel - 1u);
    if (idx < 8u) {
        uint8_t bit = BIT_(idx);
        if ((bit & PORTA_OUTPUT_MASK) == 0) {
            return ESP_ERR_INVALID_ARG;
        }
        if (on) {
            s_cache_a |= bit;
        } else {
            s_cache_a &= (uint8_t)~bit;
        }
        return write_porta();
    }
    uint8_t bit = BIT_(idx - 8u);
    if ((bit & PORTB_OUTPUT_MASK) == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    if (on) {
        s_cache_b |= bit;
    } else {
        s_cache_b &= (uint8_t)~bit;
    }
    return write_portb();
}

esp_err_t outputs_set(uint8_t channel_1_based, bool on)
{
    ESP_RETURN_ON_FALSE(s_dev != NULL, ESP_ERR_INVALID_STATE, TAG, "not initialized");
    xSemaphoreTake(s_lock, portMAX_DELAY);
    esp_err_t err = set_port_bit(channel_1_based, on);
    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t outputs_toggle(uint8_t channel_1_based)
{
    ESP_RETURN_ON_FALSE(s_dev != NULL, ESP_ERR_INVALID_STATE, TAG, "not initialized");
    xSemaphoreTake(s_lock, portMAX_DELAY);
    uint8_t idx = (uint8_t)(channel_1_based - 1u);
    if (channel_1_based == 0 || (idx >= 8 && (BIT_(idx - 8) & PORTB_OUTPUT_MASK) == 0) ||
        (idx < 8 && (BIT_(idx) & PORTA_OUTPUT_MASK) == 0)) {
        xSemaphoreGive(s_lock);
        return ESP_ERR_INVALID_ARG;
    }
    if (idx < 8u) {
        s_cache_a ^= BIT_(idx);
        esp_err_t err = write_porta();
        xSemaphoreGive(s_lock);
        return err;
    }
    s_cache_b ^= BIT_(idx - 8u);
    esp_err_t err = write_portb();
    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t outputs_set_mask(uint16_t mask)
{
    ESP_RETURN_ON_FALSE(s_dev != NULL, ESP_ERR_INVALID_STATE, TAG, "not initialized");
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_cache_a = (uint8_t)((mask & 0x00FFu) & PORTA_OUTPUT_MASK);
    s_cache_b = (uint8_t)(((mask >> 8u) & 0x00FFu) & PORTB_OUTPUT_MASK);
    esp_err_t err_a = write_porta();
    esp_err_t err_b = write_portb();
    xSemaphoreGive(s_lock);
    if (err_a != ESP_OK) {
        return err_a;
    }
    return err_b;
}

esp_err_t outputs_get_mask(uint16_t *out_mask)
{
    if (!out_mask) {
        return ESP_ERR_INVALID_ARG;
    }
    ESP_RETURN_ON_FALSE(s_dev != NULL, ESP_ERR_INVALID_STATE, TAG, "not initialized");
    xSemaphoreTake(s_lock, portMAX_DELAY);
    *out_mask = ((uint16_t)s_cache_b << 8) | (uint16_t)s_cache_a;
    xSemaphoreGive(s_lock);
    return ESP_OK;
}

esp_err_t outputs_all_off(void)
{
    ESP_RETURN_ON_FALSE(s_dev != NULL, ESP_ERR_INVALID_STATE, TAG, "not initialized");
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_cache_a &= ~PORTA_OUTPUT_MASK;
    s_cache_b &= ~PORTB_OUTPUT_MASK;
    esp_err_t err_a = write_porta();
    esp_err_t err_b = write_portb();
    xSemaphoreGive(s_lock);
    if (err_a != ESP_OK) {
        return err_a;
    }
    return err_b;
}

static inline uint8_t channel_from_porta_bit(uint8_t bit) { return (uint8_t)(bit + 1u); }
static inline uint8_t channel_from_portb_bit(uint8_t bit) { return (uint8_t)(bit + 9u); }

void output_siren_internal(bool on)
{
    esp_err_t err = outputs_set(channel_from_portb_bit(MCP_PORTB_SIREN_INT_BIT), on);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "siren_int(%d) err=%s", (int)on, esp_err_to_name(err));
    }
}

void output_siren_external(bool on)
{
    esp_err_t err = outputs_set(channel_from_portb_bit(MCP_PORTB_SIREN_EXT_BIT), on);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "siren_ext(%d) err=%s", (int)on, esp_err_to_name(err));
    }
}

void outputs_sirens(bool internal, bool external)
{
    output_siren_internal(internal);
    output_siren_external(external);
}

void outputs_fog(bool on)
{  
    esp_err_t err = outputs_set(channel_from_portb_bit(MCP_PORTB_FOG_BIT), on);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "fog(%d) err=%s", (int)on, esp_err_to_name(err));
    }
}

void outputs_led_state(bool on)
{
    esp_err_t err = outputs_set(channel_from_porta_bit(MCP_PORTA_LED_STATE_BIT), on);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "led_state(%d) err=%s", (int)on, esp_err_to_name(err));
    }
}

void outputs_led_alarm(bool on)
{
    esp_err_t err = outputs_set(channel_from_porta_bit(MCP_PORTA_LED_ALARM_BIT), on);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "led_alarm(%d) err=%s", (int)on, esp_err_to_name(err));
    }
}

void outputs_led_maint(bool on)
{
    esp_err_t err = outputs_set(channel_from_porta_bit(MCP_PORTA_LED_MAINT_BIT), on);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "led_maint(%d) err=%s", (int)on, esp_err_to_name(err));
    }
}

void outputs_led_provisioning_rgb(bool red, bool green, bool blue)
{
    esp_err_t er = outputs_set(channel_from_porta_bit((uint8_t)MCP_PORTA_LED_PROV_R_BIT), red);
    if (er != ESP_OK) {
        ESP_LOGE(TAG, "prov_red(%d) err=%s", (int)red, esp_err_to_name(er));
    }
    er = outputs_set(channel_from_porta_bit((uint8_t)MCP_PORTA_LED_PROV_G_BIT), green);
    if (er != ESP_OK) {
        ESP_LOGE(TAG, "prov_green(%d) err=%s", (int)green, esp_err_to_name(er));
    }
    er = outputs_set(channel_from_porta_bit((uint8_t)MCP_PORTA_LED_PROV_B_BIT), blue);
    if (er != ESP_OK) {
        ESP_LOGE(TAG, "prov_blue(%d) err=%s", (int)blue, esp_err_to_name(er));
    }
}

void outputs_siren(bool on)
{
    outputs_sirens(on, on);
}