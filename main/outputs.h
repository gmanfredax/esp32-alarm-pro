#pragma once
#include <stdbool.h>
#include "esp_err.h"
esp_err_t outputs_init(void);
void outputs_siren(bool on);
void outputs_led_state(bool on);
void outputs_led_maint(bool on);
