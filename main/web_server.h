#pragma once
#include "esp_err.h"
#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t web_server_start(void);
esp_err_t web_server_stop(void);
esp_err_t provisioning_reset_all(void);

esp_err_t web_server_ws_broadcast_event(const char *event, cJSON *fields);

#ifdef __cplusplus
}
#endif
