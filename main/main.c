// main.c — ESP-IDF 5.x

#include <stdint.h>
#include <stdbool.h>

#include "esp_mac.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "esp_err.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_netif.h"
#include "esp_intr_alloc.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "driver/gpio.h"

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
#include "device_identity.h"
#include "roster.h"
#include "pdo.h"
#include "web_server.h"
#include "cJSON.h"

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

// ---- START CANBUS -------------------------------------------

#define CAN_SCAN_WINDOW_US (2000000ULL)
#define MASTER_OUTPUTS_COUNT 3

static SemaphoreHandle_t s_scan_mutex = NULL;
static esp_timer_handle_t s_scan_timer = NULL;
static bool s_scan_in_progress = false;
static size_t s_scan_new_nodes = 0;

static SemaphoreHandle_t ensure_scan_mutex(void)
{
    if (!s_scan_mutex) {
        s_scan_mutex = xSemaphoreCreateMutex();
    }
    return s_scan_mutex;
}

static void can_scan_timer_cb(void *arg)
{
    (void)arg;
    size_t new_nodes = 0;
    SemaphoreHandle_t mtx = ensure_scan_mutex();
    if (mtx) {
        xSemaphoreTake(mtx, portMAX_DELAY);
        new_nodes = s_scan_new_nodes;
        s_scan_new_nodes = 0;
        s_scan_in_progress = false;
        xSemaphoreGive(mtx);
    }
    size_t total_nodes = 0;
    roster_stats(&total_nodes, NULL);
    uint64_t ts_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);
    cJSON *evt = cJSON_CreateObject();
    if (evt) {
        cJSON_AddNumberToObject(evt, "ts", (double)ts_ms);
        cJSON_AddNumberToObject(evt, "new_nodes", (double)new_nodes);
        cJSON_AddNumberToObject(evt, "total", (double)total_nodes);
        web_server_ws_broadcast_event("scan_completed", evt);
    }
}

esp_err_t can_master_request_scan(bool *started)
{
    SemaphoreHandle_t mtx = ensure_scan_mutex();
    if (!mtx) {
        if (started) *started = false;
        return ESP_ERR_NO_MEM;
    }
    bool trigger = false;
    xSemaphoreTake(mtx, portMAX_DELAY);
    if (!s_scan_in_progress) {
        s_scan_in_progress = true;
        s_scan_new_nodes = 0;
        trigger = true;
    }
    xSemaphoreGive(mtx);

    if (!trigger) {
        if (started) *started = false;
        return ESP_OK;
    }

    if (!s_scan_timer) {
        const esp_timer_create_args_t args = {
            .callback = can_scan_timer_cb,
            .name = "can_scan",
        };
        esp_err_t terr = esp_timer_create(&args, &s_scan_timer);
        if (terr != ESP_OK) {
            xSemaphoreTake(mtx, portMAX_DELAY);
            s_scan_in_progress = false;
            xSemaphoreGive(mtx);
            if (started) *started = false;
            return terr;
        }
    }

    esp_err_t terr = esp_timer_start_once(s_scan_timer, CAN_SCAN_WINDOW_US);
    if (terr != ESP_OK) {
        xSemaphoreTake(mtx, portMAX_DELAY);
        s_scan_in_progress = false;
        xSemaphoreGive(mtx);
        if (started) *started = false;
        return terr;
    }

    uint64_t ts_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);
    cJSON *evt = cJSON_CreateObject();
    if (evt) {
        cJSON_AddNumberToObject(evt, "ts", (double)ts_ms);
        web_server_ws_broadcast_event("scan_started", evt);
    }

    if (started) {
        *started = true;
    }
    return ESP_OK;
}

esp_err_t can_master_handle_node_info(uint8_t node_id, const roster_node_info_t *info)
{
    if (!info || node_id == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    bool is_new = false;
    esp_err_t err = roster_update_node(node_id, info, &is_new);
    if (err != ESP_OK) {
        return err;
    }
    cJSON *node_obj = roster_node_to_json(node_id);
    if (node_obj) {
        web_server_ws_broadcast_event(is_new ? "node_added" : "node_updated", node_obj);
    }
    return ESP_OK;
}

void can_master_handle_node_online(uint8_t node_id)
{
    if (node_id == 0) {
        return;
    }
    uint64_t now_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);
    bool is_new = false;
    if (roster_mark_online(node_id, now_ms, &is_new) != ESP_OK) {
        return;
    }
    pdo_send_led_oneshot(node_id, 1, 1000);
    if (is_new) {
        SemaphoreHandle_t mtx = ensure_scan_mutex();
        if (mtx) {
            xSemaphoreTake(mtx, portMAX_DELAY);
            s_scan_new_nodes++;
            xSemaphoreGive(mtx);
        }
        cJSON *node_obj = roster_node_to_json(node_id);
        if (node_obj) {
            web_server_ws_broadcast_event("node_added", node_obj);
        }
    } else {
        cJSON *evt = cJSON_CreateObject();
        if (evt) {
            cJSON_AddNumberToObject(evt, "node_id", node_id);
            cJSON_AddNumberToObject(evt, "last_seen_ms", (double)now_ms);
            web_server_ws_broadcast_event("node_online", evt);
        }
    }
}

void can_master_handle_node_offline(uint8_t node_id)
{
    if (node_id == 0) {
        return;
    }
    uint64_t now_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);
    if (roster_mark_offline(node_id, now_ms) != ESP_OK) {
        return;
    }
    pdo_send_led_oneshot(node_id, 2, 1500);
    cJSON *evt = cJSON_CreateObject();
    if (evt) {
        cJSON_AddNumberToObject(evt, "node_id", node_id);
        cJSON_AddNumberToObject(evt, "last_seen_ms", (double)now_ms);
        web_server_ws_broadcast_event("node_offline", evt);
    }
}
// ---- END CANBUS ---------------------------------------------

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

// static void reset_buttons_init(void)
// {
//     gpio_reset_pin(PIN_HW_RESET_BTN_A);
//     gpio_reset_pin(PIN_HW_RESET_BTN_B);

//     gpio_config_t cfg = {
//         .pin_bit_mask = (1ULL << PIN_HW_RESET_BTN_A) | (1ULL << PIN_HW_RESET_BTN_B),
//         .mode = GPIO_MODE_INPUT,
//         .pull_up_en = GPIO_PULLUP_ENABLE,
//         .pull_down_en = GPIO_PULLDOWN_DISABLE,
//         .intr_type = GPIO_INTR_DISABLE,
//     };
//     ESP_ERROR_CHECK(gpio_config(&cfg));
// }

// static bool reset_buttons_pressed(void)
// {
//     int a = gpio_get_level(PIN_HW_RESET_BTN_A);
//     int b = gpio_get_level(PIN_HW_RESET_BTN_B);
//     return (a == 0) && (b == 0);
// }

void app_main(void)
{
    char device_id[DEVICE_ID_MAX] = {0};
    uint8_t device_secret[DEVICE_SECRET_LEN] = {0};

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

    // Crea/legge da NVS ID e secret
    ensure_device_identity(device_id, device_secret);
        // Stampa su seriale (NON stampare il secret in produzione)
    ESP_LOGI(TAG, "Device ID: %s", device_id);
    ESP_LOGI(TAG, "Device Secret (hex first 8): %02X%02X%02X%02X %02X%02X%02X%02X ...",
             device_secret[0],device_secret[1],device_secret[2],device_secret[3],
             device_secret[4],device_secret[5],device_secret[6],device_secret[7]);
    
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

    ensure_scan_mutex();
    roster_init(INPUT_ZONES_COUNT, MASTER_OUTPUTS_COUNT, 0);
    
    // reset_buttons_init();
    // ESP_LOGI(TAG, "Pulsanti HW reset su GPIO %d e %d", PIN_HW_RESET_BTN_A, PIN_HW_RESET_BTN_B);
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
    const TickType_t loop_delay = pdMS_TO_TICKS(100);
    const TickType_t reset_hold_ticks = pdMS_TO_TICKS(10000);
    TickType_t reset_press_start = 0;
    bool reset_triggered = false;

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

        // TickType_t now = xTaskGetTickCount();
        // bool buttons_pressed = reset_buttons_pressed();
        // if (buttons_pressed) {
        //     if (reset_press_start == 0) {
        //         reset_press_start = now;
        //         ESP_LOGW(TAG, "Pulsanti reset premuti: tenere per 10s per ripristino");
        //     } else if (!reset_triggered && (now - reset_press_start) >= reset_hold_ticks) {
        //         reset_triggered = true;
        //         ESP_LOGW(TAG, "Avvio reset configurazione da pulsanti hardware");
        //         esp_err_t reset_err = provisioning_reset_all();
        //         if (reset_err == ESP_OK) {
        //             ESP_LOGI(TAG, "Reset completato, riavvio del dispositivo");
        //             vTaskDelay(pdMS_TO_TICKS(250));
        //             esp_restart();
        //         } else {
        //             ESP_LOGE(TAG, "Reset hardware fallito: %s", esp_err_to_name(reset_err));
        //         }
        //     }
        // } else {
        //     if (reset_press_start != 0 || reset_triggered) {
        //         reset_press_start = 0;
        //         reset_triggered = false;
        //     }
        // }

        // vTaskDelay(loop_delay);
    }
}
