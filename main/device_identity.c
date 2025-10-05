#include "device_identity.h"
#include "sdkconfig.h"
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "esp_system.h"
#include "esp_random.h"
#include "esp_mac.h"
#include "nvs_flash.h"
#include "nvs.h"

// Prefisso e forma richiesta: "nsalarmpro-xxxxxx"
#define DEVICE_ID_PREFIX      CONFIG_APP_CLOUD_CLIENT_ID_PREFIX
#define DEVICE_ID_PREFIX_LEN (sizeof(CONFIG_APP_CLOUD_CLIENT_ID_PREFIX) - 1)

_Static_assert(DEVICE_ID_MAX >= DEVICE_ID_PREFIX_LEN + 8 + 1, "DEVICE_ID_MAX must allow <prefix> + 8 hex digits");

// Verifica "nsalarmpro-" + 6 hex minuscoli
void make_device_id(char out[DEVICE_ID_MAX]) {
    if (!out) {
        return;
    }

#ifdef CONFIG_APP_CLOUD_DEVICE_ID
    const char *forced = CONFIG_APP_CLOUD_DEVICE_ID;
    if (forced && forced[0] != '\0') {
        strlcpy(out, forced, DEVICE_ID_MAX);
        return;
    }
#endif
    uint8_t mac[6] = {0};
    if (esp_read_mac(mac, ESP_MAC_ETH) != ESP_OK) {
        esp_efuse_mac_get_default(mac);
    }

    snprintf(out, DEVICE_ID_MAX, DEVICE_ID_PREFIX "%02X%02X%02X%02X",
             mac[2], mac[3], mac[4], mac[5]);
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

    char expected_id[DEVICE_ID_MAX] = {0};
    make_device_id(expected_id);

    // deviceId
    char stored_id[DEVICE_ID_MAX] = {0};
    size_t id_sz = sizeof(stored_id);
    err = nvs_get_str(n, "device_id", stored_id, &id_sz);
    if (err == ESP_OK && stored_id[0] != '\0' && strcmp(stored_id, expected_id) == 0) {
        strlcpy(id_out, stored_id, DEVICE_ID_MAX);
    } else {
        strlcpy(id_out, expected_id, DEVICE_ID_MAX);
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

esp_err_t device_identity_get_secret(uint8_t secret_out[DEVICE_SECRET_LEN]) {
    if (!secret_out) {
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t n = 0;
    esp_err_t err = nvs_open("appcfg", NVS_READONLY, &n);
    if (err != ESP_OK) {
        return err;
    }

    size_t len = DEVICE_SECRET_LEN;
    err = nvs_get_blob(n, "device_secret", secret_out, &len);
    nvs_close(n);

    if (err != ESP_OK) {
        return err;
    }
    if (len != DEVICE_SECRET_LEN) {
        return ESP_ERR_INVALID_SIZE;
    }
    return ESP_OK;
}