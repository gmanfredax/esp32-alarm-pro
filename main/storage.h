#pragma once
#include "esp_err.h"
esp_err_t storage_init(void);
esp_err_t storage_get_blob(const char* ns, const char* key, void* out, size_t* len_inout);
esp_err_t storage_set_blob(const char* ns, const char* key, const void* data, size_t len);
