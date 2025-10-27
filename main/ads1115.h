#pragma once

#include <stdint.h>
#include "esp_err.h"

esp_err_t ads1115_init(void);
esp_err_t ads1115_read_single(uint8_t addr, uint8_t channel, int16_t *out_code);