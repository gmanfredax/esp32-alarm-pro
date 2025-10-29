#pragma once

#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ADS1115_DEFAULT_ADDRESS 0x48u
#define ADS1115_MAX_DEVICES     3u

typedef struct {
    uint8_t address;
} ads1115_device_t;

esp_err_t ads1115_init(void);
esp_err_t ads1115_attach(uint8_t index, uint8_t address);
esp_err_t ads1115_read_raw(uint8_t index, uint8_t channel, int16_t *out_raw);
esp_err_t ads1115_read_mv(uint8_t index, uint8_t channel, float *out_mv);
float ads1115_raw_to_mv(int16_t raw);

#ifdef __cplusplus
}
#endif