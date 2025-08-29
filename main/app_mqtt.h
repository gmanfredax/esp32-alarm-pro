// main/app_mqtt.h
#pragma once
#include "esp_err.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t mqtt_start(void);
void mqtt_publish_state(const char* state);
void mqtt_publish_zones(uint16_t mask);

#ifdef __cplusplus
}
#endif
