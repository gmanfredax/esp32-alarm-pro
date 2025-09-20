#include "device_identity.h"
#include <stdio.h>
#include <string.h>
#include "esp_system.h"
#include "esp_chip_info.h"
#include "esp_mac.h"
#include "nvs_flash.h"
#include "nvs.h"

static void get_factory_mac(uint8_t mac[6]) {
    // MAC di fabbrica (eFuse), stabile
    esp_efuse_mac_get_default(mac);
}

static const char* chip_model_str(void){
    esp_chip_info_t ci; esp_chip_info(&ci);
    switch (ci.model) {
        case CHIP_ESP32:   return "esp32";
        case CHIP_ESP32S2: return "esp32s2";
        case CHIP_ESP32S3: return "esp32s3";
        case CHIP_ESP32C3: return "esp32c3";
        case CHIP_ESP32C6: return "esp32c6";
        case CHIP_ESP32H2: return "esp32h2";
        default:           return "esp32";
    }
}

void make_device_id(char out[DEVICE_ID_MAX]) {
    uint8_t mac[6] = {0};
    get_factory_mac(mac);
    snprintf(out, DEVICE_ID_MAX, "%s-%02X%02X%02X%02X%02X%02X",
             chip_model_str(), mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
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
    if (err != ESP_OK) {
        make_device_id(id_out);
        ESP_ERROR_CHECK(nvs_set_str(n, "device_id", id_out));
    }

    // deviceSecret (32B random)
    size_t sec_sz = DEVICE_SECRET_LEN;
    err = nvs_get_blob(n, "device_secret", secret_out, &sec_sz);
    if (err != ESP_OK || sec_sz != DEVICE_SECRET_LEN) {
        for (int i = 0; i < DEVICE_SECRET_LEN; ++i) secret_out[i] = (uint8_t) esp_random();
        ESP_ERROR_CHECK(nvs_set_blob(n, "device_secret", secret_out, DEVICE_SECRET_LEN));
    }

    ESP_ERROR_CHECK(nvs_commit(n));
    nvs_close(n);
    return ESP_OK;
}
