// Driver MCP23017 per ESP-IDF 5.x
// - Usa bus I2C condiviso (i2c_bus_get())
// - Indirizzo 7-bit non shiftato definito in pins.h (MCP23017_ADDR)

#include <string.h>
#include "esp_log.h"
#include "esp_check.h"
#include "driver/i2c_master.h"

#include "pins.h"       // I2C_SDA_GPIO, I2C_SCL_GPIO, I2C_SPEED_HZ, MCP23017_ADDR
#include "i2c_bus.h"    // i2c_bus_get()
#include "mcp23017.h"

// Registri MCP23017 (bank=0)
#define MCP_IODIRA  0x00
#define MCP_IODIRB  0x01
#define MCP_IPOLA   0x02
#define MCP_IPOLB   0x03
#define MCP_GPINTENA 0x04
#define MCP_GPINTENB 0x05
#define MCP_DEFVALA 0x06
#define MCP_DEFVALB 0x07
#define MCP_INTCONA 0x08
#define MCP_INTCONB 0x09
#define MCP_IOCON   0x0A   // anche 0x0B (mirror)
#define MCP_GPPUA   0x0C
#define MCP_GPPUB   0x0D
#define MCP_INTFA   0x0E
#define MCP_INTFB   0x0F
#define MCP_INTCAPA 0x10
#define MCP_INTCAPB 0x11
#define MCP_GPIOA   0x12
#define MCP_GPIOB   0x13
#define MCP_OLATA   0x14
#define MCP_OLATB   0x15

static const char* TAG = "mcp23017";
static i2c_master_dev_handle_t s_dev = NULL;

// --- helper basse ---
static esp_err_t mcp_wr(uint8_t reg, uint8_t val)
{
    if (!s_dev) return ESP_ERR_INVALID_STATE;
    uint8_t buf[2] = { reg, val };
    esp_err_t err = i2c_master_transmit(s_dev, buf, sizeof(buf), 1000 /* ms */);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "WR reg 0x%02X <- 0x%02X FAILED: %s", reg, val, esp_err_to_name(err));
    }
    return err;
}

static esp_err_t mcp_rd1(uint8_t reg, uint8_t* val)
{
    if (!s_dev) return ESP_ERR_INVALID_STATE;
    if (!val)   return ESP_ERR_INVALID_ARG;
    esp_err_t err = i2c_master_transmit_receive(s_dev, &reg, 1, val, 1, 1000 /* ms */);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "RD reg 0x%02X FAILED: %s", reg, esp_err_to_name(err));
    }
    return err;
}

// --- setup device ---
static esp_err_t mcp_device_attach(void)
{
    if (s_dev) return ESP_OK;

    i2c_master_bus_handle_t bus = i2c_bus_get();
    ESP_RETURN_ON_FALSE(bus != NULL, ESP_ERR_INVALID_STATE, TAG, "I2C bus not ready");

    // Configurazione device sul bus condiviso
    i2c_device_config_t dev_cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address  = MCP23017_ADDR,   // 0x27 (7-bit) definito in pins.h
        .scl_speed_hz    = I2C_SPEED_HZ
    };

    ESP_RETURN_ON_ERROR(i2c_master_bus_add_device(bus, &dev_cfg, &s_dev),
                        TAG, "i2c_master_bus_add_device");
    return ESP_OK;
}

// --- API pubbliche ---
esp_err_t mcp23017_init(void)
{
    ESP_RETURN_ON_ERROR(mcp_device_attach(), TAG, "attach");

    // IOCON: BANK=0, SEQOP=0 (auto-increment abilitato), resto default
    ESP_RETURN_ON_ERROR(mcp_wr(MCP_IOCON,   0x00), TAG, "IOCON(A)");
    ESP_RETURN_ON_ERROR(mcp_wr(MCP_IOCON+1, 0x00), TAG, "IOCON(B mirror)");

    // IOCON: valori “safe” (se serve, personalizza)
    //  - SEQOP=1 (no auto-increment? di default 1=disable sequential op, ma bank=0 consente increment)
    //  - MIRROR/INTPOL non usati qui
    // Qui lasciamo def. power-on, oppure imposta esplicitamente:
    // ESP_RETURN_ON_ERROR(mcp_wr(MCP_IOCON, 0x20 /* SEQOP=1 */), TAG, "IOCON");

    // Direzioni = input su tutte le linee
    ESP_RETURN_ON_ERROR(mcp_wr(MCP_IODIRA, 0xFF), TAG, "IODIRA");
    ESP_RETURN_ON_ERROR(mcp_wr(MCP_IODIRB, 0x1F), TAG, "IODIRB");

    // Pull-up interni abilitati su tutte le linee
    ESP_RETURN_ON_ERROR(mcp_wr(MCP_GPPUA,  0xFF), TAG, "GPPUA");
    ESP_RETURN_ON_ERROR(mcp_wr(MCP_GPPUB,  0x1F), TAG, "GPPUB");

    uint8_t olatb = 0x00;

    ESP_RETURN_ON_ERROR(mcp_wr(MCP_OLATB, olatb), TAG, "OLATB");

    // Lettura di prova + dump
    uint8_t a=0, b=0;
    (void)mcp_rd1(MCP_GPIOA, &a);
    (void)mcp_rd1(MCP_GPIOB, &b);
    ESP_LOGI(TAG, "MCP23017 ready @0x%02X  A=0x%02X  B=0x%02X", MCP23017_ADDR, a, b);
    mcp23017_debug_dump();

    return ESP_OK;
}

esp_err_t mcp23017_read_gpioab(uint16_t* out_ab)
{
    if (!out_ab) return ESP_ERR_INVALID_ARG;
    ESP_RETURN_ON_ERROR(mcp_device_attach(), TAG, "attach");

    uint8_t a=0, b=0;
    ESP_RETURN_ON_ERROR(mcp_rd1(MCP_GPIOA, &a), TAG, "GPIOA");
    ESP_RETURN_ON_ERROR(mcp_rd1(MCP_GPIOB, &b), TAG, "GPIOB");

    *out_ab = ( ((uint16_t)b) << 8 ) | a;
    return ESP_OK;
}

void mcp23017_debug_dump(void){
    uint8_t iodira, iodirb, gppua, gppub, ipola, ipolb, ioc, a, b;
    mcp_rd1(MCP_IOCON,  &ioc);
    mcp_rd1(MCP_IODIRA, &iodira);  mcp_rd1(MCP_IODIRB, &iodirb);
    mcp_rd1(MCP_GPPUA,  &gppua);   mcp_rd1(MCP_GPPUB,  &gppub);
    mcp_rd1(MCP_IPOLA,  &ipola);   mcp_rd1(MCP_IPOLB,  &ipolb);
    mcp_rd1(MCP_GPIOA,  &a);       mcp_rd1(MCP_GPIOB,  &b);
    ESP_LOGI(TAG, "CFG @0x%02X | IOCON=%02X IODIR A=%02X B=%02X GPPU A=%02X B=%02X IPOL A=%02X B=%02X | GPIO A=%02X B=%02X",
             MCP23017_ADDR, ioc, iodira, iodirb, gppua, gppub, ipola, ipolb, a, b);
}
