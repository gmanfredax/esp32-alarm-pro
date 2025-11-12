// outputs.c — MCP23017 uscite, riuso bus I2C (ESP-IDF 5.x)
// Gestisce i LED (PORTA) e le uscite di potenza (PORTB) lasciando intatti i bit
// configurati come ingressi, ad esempio il tamper globale su B5.

#include <string.h>
#include "esp_log.h"
#include "esp_check.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "driver/i2c_master.h"

#include "pins.h"       // MCP23017_ADDR, MCPB_*_BIT
#include "i2c_bus.h"    // i2c_bus_get()
#include "outputs.h"

#ifndef MCP23017_ADDR
#error "MCP23017_ADDR non definito in pins.h"
#endif
#ifndef MCPA_LED_STATO_BIT
#error "MCPA_LED_STATO_BIT non definito in pins.h"
#endif
#ifndef MCPA_LED_ALLARME_BIT
#error "MCPA_LED_ALLARME_BIT non definito in pins.h"
#endif
#ifndef MCPA_LED_MANUT_BIT
#error "MCPA_LED_MANUT_BIT non definito in pins.h"
#endif
#ifndef MCPA_LED_PROV_R_BIT
#error "MCPA_LED_PROV_R_BIT non definito in pins.h"
#endif
#ifndef MCPA_LED_PROV_G_BIT
#error "MCPA_LED_PROV_G_BIT non definito in pins.h"
#endif
#ifndef MCPA_LED_PROV_B_BIT
#error "MCPA_LED_PROV_B_BIT non definito in pins.h"
#endif
#ifndef MCPB_SIREN_INT_BIT
#error "MCPB_SIREN_INT_BIT non definito in pins.h"
#endif
#ifndef MCPB_SIREN_EXT_BIT
#error "MCPB_SIREN_EXT_BIT non definito in pins.h"
#endif
#ifndef MCPB_NEBBIOGENO_BIT
#error "MCPB_NEBBIOGENO_BIT non definito in pins.h"
#endif

// Registri MCP23017 (BANK=0)
#define MCP_IODIRA   0x00
#define MCP_IODIRB   0x01
#define MCP_GPPUA    0x0C
#define MCP_GPPUB    0x0D
#define MCP_GPIOA    0x12
#define MCP_GPIOB    0x13
#define MCP_OLATA    0x14
#define MCP_OLATB    0x15

#define BIT_(x) (1u << (x))

// Uscite su PORTA e PORTB
#define OUTA_MASK  ( BIT_(MCPA_LED_STATO_BIT) | BIT_(MCPA_LED_ALLARME_BIT) | \
                    BIT_(MCPA_LED_MANUT_BIT) | BIT_(MCPA_LED_PROV_R_BIT) | \
                    BIT_(MCPA_LED_PROV_G_BIT) | BIT_(MCPA_LED_PROV_B_BIT) )
#define OUTB_MASK  ( BIT_(MCPB_SIREN_INT_BIT) | BIT_(MCPB_SIREN_EXT_BIT) | BIT_(MCPB_NEBBIOGENO_BIT) )

static const char *TAG = "outputs";

static i2c_master_dev_handle_t s_dev = NULL;
static SemaphoreHandle_t s_lock = NULL;

// Cache stato uscite su PORTB (solo i bit OUTB_MASK sono significativi)
static uint8_t s_olata_cache = 0x00;
static uint8_t s_olatb_cache = 0x00;

// ─────────────── Helpers I2C di basso livello ───────────────
static esp_err_t rd_reg(uint8_t reg, uint8_t *val){
    if (!s_dev) return ESP_ERR_INVALID_STATE;
    return i2c_master_transmit_receive(s_dev, &reg, 1, val, 1, -1);
}
static esp_err_t wr_reg(uint8_t reg, uint8_t val){
    if (!s_dev) return ESP_ERR_INVALID_STATE;
    uint8_t buf[2] = { reg, val };
    return i2c_master_transmit(s_dev, buf, sizeof(buf), -1);
}
// read-modify-write su 8 bit
static esp_err_t update_bits(uint8_t reg, uint8_t mask, uint8_t value){
    uint8_t cur=0;
    ESP_RETURN_ON_ERROR(rd_reg(reg, &cur), TAG, "rd 0x%02X", reg);
    cur = (cur & ~mask) | (value & mask);
    return wr_reg(reg, cur);
}

// Scrive le uscite su OLATB preservando i bit non di uscita
static esp_err_t outputs_writeback(void){
    ESP_RETURN_ON_ERROR(update_bits(MCP_OLATA, OUTA_MASK, s_olata_cache & OUTA_MASK), TAG, "OLATA");
    return update_bits(MCP_OLATB, OUTB_MASK, s_olatb_cache & OUTB_MASK);
}

// Converte bit di PORTA/B in canale 1..16
static inline uint8_t ch_from_porta_bit(uint8_t porta_bit){ return (uint8_t)(1u + porta_bit); }
static inline uint8_t ch_from_portb_bit(uint8_t portb_bit){ return (uint8_t)(9u + portb_bit); }

// ─────────────── API ───────────────
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
            .scl_speed_hz    = 100000,
        };
        ESP_RETURN_ON_ERROR(i2c_master_bus_add_device(bus, &dev_cfg, &s_dev),
                            TAG, "add dev 0x%02X", MCP23017_ADDR);
    }

    // *** CHIAVE: tocca SOLO i bit di uscita su PORTB ***
    ESP_RETURN_ON_ERROR(update_bits(MCP_IODIRA, OUTA_MASK, 0x00), TAG, "IODIRA[outs]=out");
    ESP_RETURN_ON_ERROR(update_bits(MCP_IODIRB, OUTB_MASK, 0x00), TAG, "IODIRB[outs]=out");
    ESP_RETURN_ON_ERROR(update_bits(MCP_GPPUA,  OUTA_MASK, 0x00), TAG, "GPPUA[outs]=off");
    ESP_RETURN_ON_ERROR(update_bits(MCP_GPPUB,  OUTB_MASK, 0x00), TAG, "GPPUB[outs]=off");

    s_olata_cache &= ~OUTA_MASK;
    s_olatb_cache &= ~OUTB_MASK;
    ESP_RETURN_ON_ERROR(outputs_writeback(), TAG, "OLATB init");

    // LOG di servizio: mostra cosa è rimasto su IODIRB/GPPUB dopo l'init
    uint8_t iodira=0, iodirb=0, gppua=0, gppub=0, olata=0, olatb=0;
    rd_reg(MCP_IODIRA, &iodira);
    rd_reg(MCP_IODIRB, &iodirb);
    rd_reg(MCP_GPPUA,  &gppua);
    rd_reg(MCP_GPPUB,  &gppub);
    rd_reg(MCP_GPPUA,  &gppua);
    rd_reg(MCP_OLATB,  &olatb);
    ESP_LOGI(TAG, "Outputs ready @0x%02X  IODIRA=0x%02X GPPUA=0x%02X OLATA=0x%02X | IODIRB=0x%02X GPPUB=0x%02X OLATB=0x%02X",
             MCP23017_ADDR, iodira, gppua, olata, iodirb, gppub, olatb);

    return ESP_OK;
}

esp_err_t outputs_set(uint8_t ch, bool on)
{
    ESP_RETURN_ON_FALSE(s_dev != NULL, ESP_ERR_INVALID_STATE, TAG, "not initialized");
    if (ch < 1 || ch > 16) return ESP_ERR_INVALID_ARG;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    esp_err_t err = ESP_OK;
    if (ch <= 8) {
        uint8_t bit = (uint8_t)(ch - 1);
        uint8_t mask = (uint8_t)BIT_(bit);
        if ((mask & OUTA_MASK) == 0) {
            err = ESP_ERR_INVALID_ARG;
        } else {
            if (on) s_olata_cache |= mask;
            else    s_olata_cache &= (uint8_t)~mask;
            err = outputs_writeback();
        }
    } else {
        uint8_t bit = (uint8_t)(ch - 9);
        uint8_t mask = (uint8_t)BIT_(bit);
        if ((mask & OUTB_MASK) == 0) {
            err = ESP_ERR_INVALID_ARG;
        } else {
            if (on) s_olatb_cache |= mask;
            else    s_olatb_cache &= (uint8_t)~mask;
            err = outputs_writeback();
        }
    }
    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t outputs_toggle(uint8_t ch)
{
    ESP_RETURN_ON_FALSE(s_dev != NULL, ESP_ERR_INVALID_STATE, TAG, "not initialized");
    if (ch < 1 || ch > 16) return ESP_ERR_INVALID_ARG;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    esp_err_t err = ESP_OK;
    if (ch <= 8) {
        uint8_t mask = (uint8_t)BIT_(ch - 1);
        if ((mask & OUTA_MASK) == 0) {
            err = ESP_ERR_INVALID_ARG;
        } else {
            s_olata_cache ^= mask;
            err = outputs_writeback();
        }
    } else {
        uint8_t mask = (uint8_t)BIT_(ch - 9);
        if ((mask & OUTB_MASK) == 0) {
            err = ESP_ERR_INVALID_ARG;
        } else {
            s_olatb_cache ^= mask;
            err = outputs_writeback();
        }
    }
    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t outputs_set_mask(uint16_t mask)
{
    ESP_RETURN_ON_FALSE(s_dev != NULL, ESP_ERR_INVALID_STATE, TAG, "not initialized");
    xSemaphoreTake(s_lock, portMAX_DELAY);
    uint8_t want_a = (uint8_t)(mask & 0xFF);
    uint8_t want_b = (uint8_t)((mask >> 8) & 0xFF);
    s_olata_cache = (uint8_t)((want_a & OUTA_MASK) | (s_olata_cache & ~OUTA_MASK));
    s_olatb_cache = (uint8_t)((want_b & OUTB_MASK) | (s_olatb_cache & ~OUTB_MASK));
    esp_err_t err = outputs_writeback();
    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t outputs_get_mask(uint16_t *out_mask)
{
    if (!out_mask) return ESP_ERR_INVALID_ARG;
    ESP_RETURN_ON_FALSE(s_dev != NULL, ESP_ERR_INVALID_STATE, TAG, "not initialized");
    xSemaphoreTake(s_lock, portMAX_DELAY);
    *out_mask = ((uint16_t)s_olatb_cache << 8) | s_olata_cache;
    xSemaphoreGive(s_lock);
    return ESP_OK;
}

esp_err_t outputs_all_off(void)
{
    ESP_RETURN_ON_FALSE(s_dev != NULL, ESP_ERR_INVALID_STATE, TAG, "not initialized");
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_olata_cache &= ~OUTA_MASK;
    s_olatb_cache &= ~OUTB_MASK;
    esp_err_t err = outputs_writeback();
    xSemaphoreGive(s_lock);
    return err;
}

/* ───────── Uscite semantiche: bit su PORTB (B0..B7 → canali 9..16) ───────── */
static void log_output_err(const char *name, esp_err_t err)
{
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "%s failed: %s", name, esp_err_to_name(err));
    }
}

void outputs_siren_internal(bool on)
{
    log_output_err("siren_int", outputs_set(ch_from_portb_bit((uint8_t)MCPB_SIREN_INT_BIT), on));
}

void outputs_siren_external(bool on)
{
    log_output_err("siren_ext", outputs_set(ch_from_portb_bit((uint8_t)MCPB_SIREN_EXT_BIT), on));
}

void outputs_nebbiogeno(bool on)
{
    log_output_err("nebbiogeno", outputs_set(ch_from_portb_bit((uint8_t)MCPB_NEBBIOGENO_BIT), on));
}

void outputs_siren(bool on)
{
    outputs_siren_internal(on);
    outputs_siren_external(on);
    outputs_led_alarm(on);
}

void outputs_led_state(bool on)
{
    log_output_err("led_state", outputs_set(ch_from_porta_bit((uint8_t)MCPA_LED_STATO_BIT), on));
}

void outputs_led_alarm(bool on)
{
    log_output_err("led_alarm", outputs_set(ch_from_porta_bit((uint8_t)MCPA_LED_ALLARME_BIT), on));
}

void outputs_led_maint(bool on)
{
    log_output_err("led_maint", outputs_set(ch_from_porta_bit((uint8_t)MCPA_LED_MANUT_BIT), on));
}

void outputs_led_provisioning(bool r, bool g, bool b)
{
    log_output_err("led_prov_r", outputs_set(ch_from_porta_bit((uint8_t)MCPA_LED_PROV_R_BIT), r));
    log_output_err("led_prov_g", outputs_set(ch_from_porta_bit((uint8_t)MCPA_LED_PROV_G_BIT), g));
    log_output_err("led_prov_b", outputs_set(ch_from_porta_bit((uint8_t)MCPA_LED_PROV_B_BIT), b));
}
