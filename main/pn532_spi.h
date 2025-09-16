#pragma once
#include "esp_err.h"
#include "pins.h"

esp_err_t pn532_init(void);

int pn532_read_uid(uint8_t* uid, int maxlen); // returns uid len or <0

bool pn532_is_ready(void);
