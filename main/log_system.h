#pragma once
#include "esp_err.h"
#include <stdint.h>

typedef struct { uint32_t ts; char msg[80]; } log_item_t;
esp_err_t log_system_init(void);
void log_add(const char* fmt, ...);
int log_dump(log_item_t* out, int max);
