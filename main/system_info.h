#pragma once
#include "esp_err.h"
#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t system_info_init(void);
esp_err_t system_info_append_json(cJSON *root);
uint32_t system_info_get_boot_count(void);
const char *system_info_get_installed_at(void);
const char *system_info_get_build_datetime(void);

#ifdef __cplusplus
}
#endif
