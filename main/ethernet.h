#pragma once
#include "freertos/FreeRTOS.h"
#include "esp_err.h"
#include "esp_netif.h"

esp_err_t    eth_start(void);
void         eth_stop(void);
void         eth_dump_link_once(void);
esp_netif_t* eth_get_netif(void);
esp_err_t    eth_wait_for_ip(TickType_t timeout);