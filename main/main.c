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
#include "esp_intr_alloc.h"
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
#include "i2c_bus.h"
#include "scenes.h"

#include "lwip/apps/sntp.h"
#include "esp_idf_version.h"
#include <time.h>

#include "utils.h"

static void sntp_start_and_wait(void){
    // API compatibile con IDF “classico” (LWIP SNTP)
    sntp_setoperatingmode(SNTP_OPMODE_POLL);
    sntp_setservername(0, "pool.ntp.org");          // puoi usare anche "time.google.com"
    sntp_init();

    // Attendi che time() diventi plausibile (> 2020-01-01)
    time_t now = 0;
    int tries = 0;
    do {
        vTaskDelay(pdMS_TO_TICKS(1000));
        time(&now);
    } while (now < 1577836800 && ++tries < 30);     // ~30s timeout

    if (now < 1577836800) {
        ESP_LOGW("time", "SNTP non sincronizzato (timeout)");
    } else {
        ESP_LOGI("time", "SNTP ok: %ld", (long)now);
    }
}

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

static void nvs_erase_namespace_once(const char* ns){
    nvs_handle_t h;
    if (nvs_open(ns, NVS_READWRITE, &h) == ESP_OK){
        nvs_erase_all(h);
        nvs_commit(h);
        nvs_close(h);
        ESP_LOGW("nvs","namespace '%s' wiped", ns);
    }
}


void app_main(void)
{
    // Stack di rete/eventi prima di tutto
    nvs_init_safe();                              // RIMUOVI se già fatto in storage_init()
    //nvs_erase_namespace_once("users");
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // Init componenti applicativi
    ESP_ERROR_CHECK(storage_init());
    ESP_ERROR_CHECK(i2c_bus_init());
    ESP_LOGI(TAG, "Interrupts before ETH:");
    esp_intr_dump(stdout);  // diagnostica: verifica chi occupa cosa
    esp_err_t eth_ret = eth_start();
    if (eth_ret != ESP_OK) ESP_LOGW(TAG, "Ethernet not available. Continuing without it...");
    ESP_ERROR_CHECK(auth_init());
// [debug disattivato] loop dump link rimosso per build pulita

    ESP_ERROR_CHECK(inputs_init());
    ESP_ERROR_CHECK(scenes_init(INPUT_ZONES_COUNT));
    ESP_ERROR_CHECK(outputs_init());
    ESP_ERROR_CHECK(pn532_init());
    ESP_ERROR_CHECK(ds18b20_init());
    ESP_ERROR_CHECK(log_system_init());
    sntp_start_and_wait();
    ESP_ERROR_CHECK(mqtt_start());

    alarm_init();
    mqtt_publish_state();
    mqtt_publish_scenes();

    uint16_t initial_gpio = 0;
    if (inputs_read_all(&initial_gpio) == ESP_OK) {
        uint16_t init_mask = 0;
        for (int i = 1; i <= INPUT_ZONES_COUNT; ++i) {
            if (inputs_zone_bit(initial_gpio, i)) {
                init_mask |= (1u << (i - 1));
            }
        }
        mqtt_publish_zones(init_mask);
    }

    // Avvia web server (serve i file SPIFFS)
    //ESP_ERROR_CHECK(web_server_start());
    ESP_ERROR_CHECK(web_server_start());

    // Riduci il rumore di handshake cancellati dal client (-0x0050) e altre riconnessioni
    esp_log_level_set("esp-tls-mbedtls", ESP_LOG_WARN);
    esp_log_level_set("esp_https_server", ESP_LOG_WARN);
    esp_log_level_set("httpd",           ESP_LOG_WARN);
    // opzionale:
    // esp_log_level_set("esp-tls",      ESP_LOG_WARN);



    ESP_LOGI(TAG, "System ready.");

    // Main loop: leggi ingressi e alimenta la logica d’allarme
    uint16_t last_mask = 0xFFFFu;
    bool first_cycle = true;

    while (true) {
        uint16_t ab = 0;
        inputs_read_all(&ab);

        uint16_t zmask = 0;
        for (int i = 1; i <= INPUT_ZONES_COUNT; i++) {
            if (inputs_zone_bit(ab, i)) {
                zmask |= (1u << (i - 1));
            }
        }

        // esempio: tamper su bit (8+4) come da tuo codice
        bool tamper = inputs_tamper(ab);

        if (first_cycle || zmask != last_mask) {
            mqtt_publish_zones(zmask);
            last_mask = zmask;
            first_cycle = false;
        }

        alarm_tick(zmask, tamper);

        vTaskDelay(pdMS_TO_TICKS(100));
    }
}
