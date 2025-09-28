#pragma once

#include "esp_err.h"

esp_err_t mdns_service_start(void);
esp_err_t mdns_service_update_hostname(const char *hostname);