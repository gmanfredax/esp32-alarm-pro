// main.c — ESP-IDF 5.x

#include <stdint.h>
#include <stdbool.h>

#include "esp_mac.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_err.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_netif.h"
#include "nvs_flash.h"

// Header del progetto
#include "ethernet.h"
#include "storage.h"
#include "auth.h"
#include "app_mqtt.h"
#include "alarm_core.h"
#include "gpio_inputs.h"
#include "outputs.h"
#include "pn532_spi.h"
#include "onewire_ds18b20.h"
#include "log_system.h"
#include "web_server.h"
#include "pins.h"

static const char *TAG = "app";

static void nvs_init_safe(void)
{
    // Se NVS viene già inizializzato in storage_init(), puoi rimuovere questa funzione.
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    } else {
        ESP_ERROR_CHECK(err);
    }
}

void app_main(void)
{
    // Stack di rete/eventi prima di tutto
    nvs_init_safe();                              // RIMUOVI se già fatto in storage_init()
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // Init componenti applicativi
    ESP_ERROR_CHECK(storage_init());
    if (eth_start() != ESP_OK) {
        ESP_LOGW(TAG, "Ethernet not available. Continuing without it...");
    }
    ESP_ERROR_CHECK(auth_init());
    ESP_ERROR_CHECK(mqtt_start());
    ESP_ERROR_CHECK(inputs_init());
    ESP_ERROR_CHECK(outputs_init());
    ESP_ERROR_CHECK(pn532_init());
    ESP_ERROR_CHECK(ds18b20_init());
    ESP_ERROR_CHECK(log_system_init());
    alarm_init();

    // Avvia web server (serve i file SPIFFS)
    ESP_ERROR_CHECK(web_server_start());

    ESP_LOGI(TAG, "System ready.");

    // Main loop: leggi ingressi e alimenta la logica d’allarme
    while (true) {
        uint16_t ab = 0;
        inputs_read_all(&ab);

        uint16_t zmask = 0;
        for (int i = 1; i <= 12; i++) {
            if (inputs_zone_bit(ab, i)) {
                zmask |= (1u << (i - 1));
            }
        }

        // esempio: tamper su bit (8+4) come da tuo codice
        bool tamper = (ab & (1u << (8 + 4))) != 0;

        alarm_tick(zmask, tamper);

        vTaskDelay(pdMS_TO_TICKS(100));
    }
}
