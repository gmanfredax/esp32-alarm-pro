#pragma once
#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>
#include "pins.h"

esp_err_t inputs_init(void);
esp_err_t inputs_read_all(uint16_t* gpioab);
static inline bool inputs_zone_bit(uint16_t gpioab, int z){ 
    if(z<1||z>12) return false; 
    if(z<=8) return (gpioab & (1u<<(z-1)))!=0; 
    return (gpioab & (1u<<(8+(z-9))))!=0;
}
static inline bool inputs_tamper(uint16_t gpioab){ return (gpioab & (1u<<(8+MCPB_TAMPER_BIT)))!=0; }
