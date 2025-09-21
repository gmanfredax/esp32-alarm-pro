#include "device_identity.h"
#include <stdio.h>
#include <string.h>
#include "esp_system.h"
#include "esp_random.h"
#include "esp_mac.h"
#include "nvs_flash.h"
#include "nvs.h"

// Prefisso e forma richiesta: "nsalarmpro-xxxxxx"
#define DEVICE_ID_PREFIX "nsalarmpro-"
_Static_assert(DEVICE_ID_MAX >= 18, "DEVICE_ID_MAX must be >= 18 for 'nsalarmpro-xxxxxx'");

static void get_factory_mac(uint8_t mac[6]) {
    // MAC di fabbrica (eFuse), stabile
    esp_efuse_mac_get_default(mac);
}

// Verifica "nsalarmpro-" + 6 hex minuscoli
static bool device_id_is_ok(const char* s){
    if (!s) return false;
    const size_t len = strlen(s);
    if (len != (sizeof(DEVICE_ID_PREFIX)-1 + 6)) return false;
    if (strncmp(s, DEVICE_ID_PREFIX, sizeof(DEVICE_ID_PREFIX)-1) != 0) return false;
    const char* p = s + (sizeof(DEVICE_ID_PREFIX)-1);
    for (int i = 0; i < 6; ++i) {
        char c = p[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

void make_device_id(char out[DEVICE_ID_MAX]) {
    uint8_t mac[6] = {0};
    get_factory_mac(mac);
    // Usa gli ultimi 3 byte della MAC (univoci) in minuscolo
    snprintf(out, DEVICE_ID_MAX, DEVICE_ID_PREFIX "%02x%02x%02x%02x", mac[2], mac[3], mac[4], mac[5]);
}

esp_err_t ensure_device_identity(char id_out[DEVICE_ID_MAX],
                                 uint8_t secret_out[DEVICE_SECRET_LEN]) {
    // Inizializza NVS se non già fatto
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    nvs_handle_t n;
    ESP_ERROR_CHECK(nvs_open("appcfg", NVS_READWRITE, &n));

    // deviceId
    size_t id_sz = DEVICE_ID_MAX;
    err = nvs_get_str(n, "device_id", id_out, &id_sz);
    if (err != ESP_OK || !device_id_is_ok(id_out)) {
        make_device_id(id_out);
        ESP_ERROR_CHECK(nvs_set_str(n, "device_id", id_out));
    }

    // deviceSecret (32B random)
    size_t sec_sz = DEVICE_SECRET_LEN;
    err = nvs_get_blob(n, "device_secret", secret_out, &sec_sz);
    if (err != ESP_OK || sec_sz != DEVICE_SECRET_LEN) {
        // Riempie con entropia hardware
        esp_fill_random(secret_out, DEVICE_SECRET_LEN);
        ESP_ERROR_CHECK(nvs_set_blob(n, "device_secret", secret_out, DEVICE_SECRET_LEN));
    }

    ESP_ERROR_CHECK(nvs_commit(n));
    nvs_close(n);
    return ESP_OK;
}
