// main/app_mqtt.h
#pragma once
#include "esp_err.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t mqtt_start(void);
esp_err_t mqtt_publish_state(void);
esp_err_t mqtt_publish_zones(uint16_t mask);
esp_err_t mqtt_publish_scenes(void);

#ifdef __cplusplus
}
#endif
