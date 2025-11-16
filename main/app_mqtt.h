// main/app_mqtt.h
#pragma once
#include "esp_err.h"
#include <stdint.h>

#include "zone_mask.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t mqtt_start(void);
esp_err_t mqtt_stop(void);
esp_err_t mqtt_reload_config(void);
esp_err_t mqtt_publish_state(void);
esp_err_t mqtt_publish_zones(const zone_mask_t *alarm_mask, const zone_mask_t *tamper_mask, bool tamper_global);
esp_err_t mqtt_publish_scenes(void);

#ifdef __cplusplus
}
#endif
