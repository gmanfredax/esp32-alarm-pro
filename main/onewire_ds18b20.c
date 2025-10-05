#include "onewire_ds18b20.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "pins.h"
esp_err_t ds18b20_init(void){
    gpio_config_t io={.pin_bit_mask=1ULL<<ONEWIRE_GPIO,.mode=GPIO_MODE_INPUT_OUTPUT_OD,.pull_up_en=GPIO_PULLUP_ENABLE,.pull_down_en=GPIO_PULLDOWN_DISABLE,.intr_type=GPIO_INTR_DISABLE};
    gpio_config(&io); return ESP_OK;
}
