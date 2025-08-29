#include "outputs.h"
#include "driver/i2c.h"
//#include "config.h"
#include "esp_log.h"
#include "pins.h"

#define IODIRB  0x01
#define OLATB   0x15
#define GPIOB   0x13

static uint8_t s_b_olat = 0x00;
static const char* TAG="outputs";

static esp_err_t i2c_wr(uint8_t reg, uint8_t val){
    uint8_t buf[2]={reg,val};
    return i2c_master_write_to_device(I2C_PORT, MCP23017_ADDR, buf, 2, 1000/portTICK_PERIOD_MS);
}
static esp_err_t i2c_rd(uint8_t reg, uint8_t* val){
    return i2c_master_write_read_device(I2C_PORT, MCP23017_ADDR, &reg, 1, val, 1, 1000/portTICK_PERIOD_MS);
}

esp_err_t outputs_init(void){
    // assume i2c driver already initialized in inputs_init()
    // Set B5,B6,B7 as outputs (0), keep others inputs (1)
    uint8_t iodirb=0xFF;
    iodirb &= ~( (1<<MCPB_RELAY_BIT) | (1<<MCPB_LED_STATO_BIT) | (1<<MCPB_LED_MANUT_BIT) );
    ESP_ERROR_CHECK(i2c_wr(IODIRB, iodirb));
    i2c_rd(OLATB,&s_b_olat);
    ESP_LOGI(TAG,"IODIRB=0x%02X", iodirb);
    return ESP_OK;
}
static void set_b_bit(int bit, bool on){
    if(on) s_b_olat |= (1<<bit);
    else   s_b_olat &= ~(1<<bit);
    i2c_wr(OLATB, s_b_olat);
}
void outputs_siren(bool on){ set_b_bit(MCPB_RELAY_BIT, on); }
void outputs_led_state(bool on){ set_b_bit(MCPB_LED_STATO_BIT, on); }
void outputs_led_maint(bool on){ set_b_bit(MCPB_LED_MANUT_BIT, on); }
