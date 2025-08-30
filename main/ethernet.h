#pragma once
#include "esp_err.h"

esp_err_t eth_start(void);
void      eth_stop(void);
void eth_dump_link_once(void);