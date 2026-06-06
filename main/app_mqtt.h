// main/app_mqtt.h
#pragma once
#include "esp_err.h"
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "zone_mask.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t mqtt_start(void);
esp_err_t mqtt_stop(void);
esp_err_t mqtt_reload_config(void);
esp_err_t mqtt_publish_state(void);
esp_err_t mqtt_publish_state_async(void);
esp_err_t mqtt_publish_zones(const zone_mask_t *mask);
esp_err_t mqtt_publish_scenes(void);
esp_err_t mqtt_publish_event_json(const char *payload, const char *severity);
esp_err_t mqtt_publish_discovery(void);
esp_err_t mqtt_build_effective_base_topic(const char *configured_base, const char *tenant_id, const char *site_id, const char *device_id, char *out, size_t out_len);
bool mqtt_is_connected(void);

#ifdef __cplusplus
}
#endif
