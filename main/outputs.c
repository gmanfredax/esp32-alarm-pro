// outputs.c — MCP23017 uscite, riuso bus I2C (ESP-IDF 5.x)
// FIX: configura SOLO i bit di PORTB usati come uscite (B5..B7) e non tocca gli ingressi.

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
#ifndef MCPB_RELAY_BIT
#error "MCPB_RELAY_BIT non definito in pins.h"
#endif
#ifndef MCPB_LED_STATO_BIT
#error "MCPB_LED_STATO_BIT non definito in pins.h"
#endif
#ifndef MCPB_LED_MANUT_BIT
#error "MCPB_LED_MANUT_BIT non definito in pins.h"
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

// Uscite su PORTB (ADATTA se diverso)
#define OUTB_MASK  ( BIT_(MCPB_RELAY_BIT) | BIT_(MCPB_LED_STATO_BIT) | BIT_(MCPB_LED_MANUT_BIT) )

static const char *TAG = "outputs";

static i2c_master_dev_handle_t s_dev = NULL;
static SemaphoreHandle_t s_lock = NULL;

// Cache stato uscite su PORTB (solo i bit OUTB_MASK sono significativi)
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
    return update_bits(MCP_OLATB, OUTB_MASK, s_olatb_cache & OUTB_MASK);
}

// Converte bit di PORTB (0..7) nel canale 9..16
static inline uint8_t ch_from_portb_bit(uint8_t portb_bit /*0..7*/){
    return (uint8_t)(9u + portb_bit);  // B0=ch9 ... B7=ch16
}

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
    // Imposta B5..B7 come OUTPUT (0), lascia B0..B4 invariati (ingressi).
    ESP_RETURN_ON_ERROR(update_bits(MCP_IODIRB, OUTB_MASK, 0x00), TAG, "IODIRB[outs]=out");
    // Disabilita pull-up sui bit di uscita (inutile e sconsigliato sugli output)
    ESP_RETURN_ON_ERROR(update_bits(MCP_GPPUB,  OUTB_MASK, 0x00), TAG, "GPPUB[outs]=off");

    // Porta le uscite in stato sicuro iniziale (attivo-alto → 0=spento)
    s_olatb_cache &= ~OUTB_MASK;
    ESP_RETURN_ON_ERROR(outputs_writeback(), TAG, "OLATB init");

    // LOG di servizio: mostra cosa è rimasto su IODIRB/GPPUB dopo l'init
    uint8_t iodirb=0, gppub=0, olatb=0;
    rd_reg(MCP_IODIRB, &iodirb);
    rd_reg(MCP_GPPUB,  &gppub);
    rd_reg(MCP_OLATB,  &olatb);
    ESP_LOGI(TAG, "Outputs ready @0x%02X  IODIRB=0x%02X GPPUB=0x%02X OLATB=0x%02X (OUTB_MASK=0x%02X)",
             MCP23017_ADDR, iodirb, gppub, olatb, OUTB_MASK);

    return ESP_OK;
}

esp_err_t outputs_set(uint8_t ch, bool on)
{
    // Accettiamo solo canali su PORTB corrispondenti ai nostri bit di uscita
    if (ch < 9 || ch > 16) return ESP_ERR_INVALID_ARG;
    uint8_t bbit = (uint8_t)(ch - 9);
    uint8_t bitmask = (uint8_t)BIT_(bbit);
    if ((bitmask & OUTB_MASK) == 0) return ESP_ERR_INVALID_ARG;

    ESP_RETURN_ON_FALSE(s_dev != NULL, ESP_ERR_INVALID_STATE, TAG, "not initialized");
    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (on) s_olatb_cache |=  bitmask;
    else    s_olatb_cache &= ~bitmask;
    esp_err_t err = outputs_writeback();
    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t outputs_toggle(uint8_t ch)
{
    if (ch < 9 || ch > 16) return ESP_ERR_INVALID_ARG;
    uint8_t bbit = (uint8_t)(ch - 9);
    uint8_t bitmask = (uint8_t)BIT_(bbit);
    if ((bitmask & OUTB_MASK) == 0) return ESP_ERR_INVALID_ARG;

    ESP_RETURN_ON_FALSE(s_dev != NULL, ESP_ERR_INVALID_STATE, TAG, "not initialized");
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_olatb_cache ^= bitmask;
    esp_err_t err = outputs_writeback();
    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t outputs_set_mask(uint16_t mask)
{
    // Interpretiamo la mask come 16 bit (A=0..7, B=8..15) ma applichiamo SOLO i nostri bit su B
    uint8_t want_b = (uint8_t)((mask >> 8) & 0xFF);
    uint8_t new_b  = (want_b & OUTB_MASK) | (s_olatb_cache & ~OUTB_MASK);

    ESP_RETURN_ON_FALSE(s_dev != NULL, ESP_ERR_INVALID_STATE, TAG, "not initialized");
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_olatb_cache = new_b;
    esp_err_t err = outputs_writeback();
    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t outputs_get_mask(uint16_t *out_mask)
{
    if (!out_mask) return ESP_ERR_INVALID_ARG;
    ESP_RETURN_ON_FALSE(s_dev != NULL, ESP_ERR_INVALID_STATE, TAG, "not initialized");
    xSemaphoreTake(s_lock, portMAX_DELAY);
    // Ricostruiamo una mask 16 bit con solo i bit B che gestiamo
    *out_mask = ((uint16_t)s_olatb_cache) << 8;
    xSemaphoreGive(s_lock);
    return ESP_OK;
}

esp_err_t outputs_all_off(void)
{
    ESP_RETURN_ON_FALSE(s_dev != NULL, ESP_ERR_INVALID_STATE, TAG, "not initialized");
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_olatb_cache &= ~OUTB_MASK;
    esp_err_t err = outputs_writeback();
    xSemaphoreGive(s_lock);
    return err;
}

/* ───────── Uscite semantiche: bit su PORTB (B0..B7 → canali 9..16) ───────── */
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
