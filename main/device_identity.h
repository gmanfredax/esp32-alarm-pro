#pragma once
#include <stdint.h>
#include "esp_err.h"

#define DEVICE_ID_MAX 32
#define DEVICE_SECRET_LEN 32

// Genera stringa "<prefix><MAC8hex>" in out (null-terminated)
void make_device_id(char out[DEVICE_ID_MAX]);

// Crea (se mancano) e recupera deviceId + deviceSecret da NVS
esp_err_t ensure_device_identity(char id_out[DEVICE_ID_MAX],
                                 uint8_t secret_out[DEVICE_SECRET_LEN]);

// Recupera il deviceSecret dalla NVS senza modificare altri valori
esp_err_t device_identity_get_secret(uint8_t secret_out[DEVICE_SECRET_LEN]);