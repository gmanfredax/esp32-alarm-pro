#pragma once
#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"

uint64_t utils_millis(void);
uint32_t utils_time(void); // seconds
void utils_random_token(char* out, size_t len);
