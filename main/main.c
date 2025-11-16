// main.c — ESP-IDF 5.x

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include "sdkconfig.h"

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
// #include "driver/twai.h"

// Header del progetto
#include "ethernet.h"
#include "storage.h"
#include "auth.h"
#include "app_mqtt.h"
#include "alarm_core.h"
#include "zone_inputs.h"
#include "outputs.h"
#include "pn532_spi.h"
#include "onewire_ds18b20.h"
#include "log_system.h"
#include "web_server.h"
// #include "mdns_service.h"
#include "pins.h"
#include "i2c_bus.h"
#include "scenes.h"
#include "can_proto.h"
#include "can_master.h"

#include "lwip/apps/sntp.h"
#include "esp_idf_version.h"
#include <time.h>

#include "utils.h"
#include "device_identity.h"
#include "roster.h"
#include "pdo.h"
#include "web_server.h"
#include "cJSON.h"

//#ifndef TWAI_FRAME_MAX_DLC
//#define TWAI_FRAME_MAX_DLC 8
//#endif

static void sntp_start_and_wait(void){
    // API compatibile con IDF “classico” (LWIP SNTP)
    sntp_setoperatingmode(SNTP_OPMODE_POLL);
    sntp_setservername(0, "time.google.com");          // puoi usare anche "time.google.com"
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

#define SYSTEM_MAIN_TASK_STACK_BYTES      (16384)
#define SYSTEM_MAIN_TASK_PRIORITY         (tskIDLE_PRIORITY + 5)
#define WEB_SERVER_START_TASK_STACK_BYTES (16384)
#define WEB_SERVER_START_TASK_PRIORITY    (SYSTEM_MAIN_TASK_PRIORITY)

_Static_assert((SYSTEM_MAIN_TASK_STACK_BYTES % sizeof(StackType_t)) == 0,
               "SYSTEM_MAIN_TASK_STACK_BYTES must align to StackType_t size");


// ---- START CANBUS -------------------------------------------

//#define CAN_SCAN_WINDOW_US (2000000ULL)
#define MASTER_OUTPUTS_COUNT 3

typedef struct {
    SemaphoreHandle_t done;
    esp_err_t result;
} web_server_start_ctx_t;

static void web_server_start_task(void *arg)
{
    web_server_start_ctx_t *ctx = (web_server_start_ctx_t *)arg;
    if (ctx) {
        ctx->result = web_server_start();
        if (ctx->done) {
            xSemaphoreGive(ctx->done);
        }
    }
    vTaskDelete(NULL);
}

static esp_err_t web_server_start_with_stack(void)
{
    web_server_start_ctx_t ctx = {
        .done = xSemaphoreCreateBinary(),
        .result = ESP_FAIL,
    };
    if (!ctx.done) {
        ESP_LOGW(TAG, "Unable to allocate semaphore for web server start task");
        return web_server_start();
    }

    const BaseType_t created = xTaskCreatePinnedToCore(
        web_server_start_task,
        "web_start",
        WEB_SERVER_START_TASK_STACK_BYTES / sizeof(StackType_t),
        &ctx,
        WEB_SERVER_START_TASK_PRIORITY,
        NULL,
        tskNO_AFFINITY);

    if (created != pdPASS) {
        ESP_LOGW(TAG, "Unable to create web server start task (%ld), running inline", (long)created);
        vSemaphoreDelete(ctx.done);
        return web_server_start();
    }

    esp_err_t err = ESP_OK;
    if (xSemaphoreTake(ctx.done, portMAX_DELAY) != pdTRUE) {
        ESP_LOGE(TAG, "Web server start task failed to signal completion");
        err = ESP_ERR_INVALID_STATE;
    } else {
        err = ctx.result;
    }

    vSemaphoreDelete(ctx.done);
    return err;
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

static void compose_zone_masks(const zone_inputs_snapshot_t *snapshot,
                               uint16_t zones_total,
                               zone_mask_t *out_alarm,
                               zone_mask_t *out_tamper,
                               bool *out_global_tamper)
{
    if (!out_alarm || !out_tamper || !out_global_tamper) {
        return;
    }
    *out_global_tamper = (snapshot ? snapshot->global_tamper : false);

    zone_mask_clear(out_alarm);
    zone_mask_clear(out_tamper);

    if (!snapshot) {
        return;
    }
    
    if (zones_total > ALARM_MAX_ZONES) {
        zones_total = ALARM_MAX_ZONES;
    }

    uint16_t master_limit = snapshot->zone_count;
    if (master_limit > zones_total) {
        master_limit = zones_total;
    }

    for (uint16_t i = 0; i < master_limit; ++i) {
        if (zone_inputs_zone_alarm(snapshot, i)) {
            zone_mask_set(out_alarm, i);
        }
        if (zone_inputs_zone_tamper(snapshot, i)) {
            zone_mask_set(out_tamper, i);
        }
    }

    if (zones_total <= snapshot->zone_count) {
        zone_mask_limit(out_alarm, zones_total);
        zone_mask_limit(out_tamper, zones_total);
        return;
    }

    roster_node_inputs_t nodes[32];
    size_t node_count = roster_collect_nodes(nodes, sizeof(nodes) / sizeof(nodes[0]));
    uint16_t offset = snapshot->zone_count;
    if (offset > zones_total) {
        offset = zones_total;
    }

    for (size_t idx = 0; idx < node_count && offset < zones_total && offset < ALARM_MAX_ZONES; ++idx) {
        const roster_node_inputs_t *node = &nodes[idx];
        const uint8_t inputs = node->inputs_count;
        for (uint8_t bit = 0; bit < inputs && offset < zones_total && offset < ALARM_MAX_ZONES; ++bit, ++offset) {
            bool active = node->inputs_valid && ((node->inputs_bitmap & (1u << bit)) != 0u);
            if (active) {
                zone_mask_set(out_alarm, offset);
            }
        }
    }

    zone_mask_limit(out_alarm, zones_total);
    zone_mask_limit(out_tamper, zones_total);
}

static void system_main_task(void *arg)
{
    (void)arg;

    char device_id[DEVICE_ID_MAX] = {0};
    uint8_t device_secret[DEVICE_SECRET_LEN] = {0};

    // Stack di rete/eventi prima di tutto
    nvs_init_safe();                              // RIMUOVI se già fatto in storage_init()
    //nvs_erase_namespace_once("users");
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // Init componenti applicativi
    ESP_ERROR_CHECK(storage_init());
    {
        nvs_handle_t nvs_mode;
        if (nvs_open("sys", NVS_READONLY, &nvs_mode) == ESP_OK) {
            uint8_t mode_u8 = (uint8_t)zone_inputs_get_eol_mode();
            if (nvs_get_u8(nvs_mode, "zone_eol_mode", &mode_u8) == ESP_OK) {
                if (mode_u8 <= (uint8_t)ZONE_EOL_MODE_3) {
                    zone_inputs_set_eol_mode((zone_eol_mode_t)mode_u8);
                }
            }
            nvs_close(nvs_mode);
        }
    }
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
    if (eth_ret != ESP_OK) {
        ESP_LOGW(TAG, "Ethernet not available. Continuing without it...");
    }
    ESP_ERROR_CHECK(auth_init());
// [debug disattivato] loop dump link rimosso per build pulita

    ESP_ERROR_CHECK(zone_inputs_init());
    ESP_ERROR_CHECK(scenes_init(ALARM_MAX_ZONES));
    ESP_ERROR_CHECK(outputs_init());
    //ESP_ERROR_CHECK(pn532_init());
    //ESP_ERROR_CHECK(ds18b20_init());
    ESP_ERROR_CHECK(log_system_init());

    // ensure_scan_mutex();
    roster_init(ZONE_INPUT_COUNT, MASTER_OUTPUTS_COUNT, 0);
    roster_master_set_device_id(device_id);

#if defined(CONFIG_APP_CAN_ENABLED)
    // ESP_ERROR_CHECK(can_master_driver_start());
    ESP_ERROR_CHECK(can_master_init());
#else
    ESP_LOGW(TAG, "CAN master disabled via Kconfig");
#endif

    // reset_buttons_init();
    // ESP_LOGI(TAG, "Pulsanti HW reset su GPIO %d e %d", PIN_HW_RESET_BTN_A, PIN_HW_RESET_BTN_B);
    bool eth_ready_for_time = false;
    if (eth_ret == ESP_OK) {
        const TickType_t wait_timeout = pdMS_TO_TICKS(15000);
        esp_err_t wait_res = eth_wait_for_ip(wait_timeout);
        if (wait_res == ESP_OK) {
            eth_ready_for_time = true;
            ESP_LOGI(TAG, "Ethernet ready, starting SNTP");
            // esp_err_t mdns_err = mdns_service_start();
            // if (mdns_err != ESP_OK) {
            //     ESP_LOGW(TAG, "mDNS start failed: %s", esp_err_to_name(mdns_err));
            // }
        } else if (wait_res == ESP_ERR_TIMEOUT) {
            ESP_LOGW(TAG, "Timeout waiting for Ethernet IP (%lu ms)",
                     (unsigned long)(wait_timeout * portTICK_PERIOD_MS));
        } else {
            ESP_LOGW(TAG, "Failed waiting for Ethernet IP: %s", esp_err_to_name(wait_res));
        }
    }
    if (eth_ready_for_time) {
        sntp_start_and_wait();
    } else {
        ESP_LOGW(TAG, "Skipping SNTP start because Ethernet is not ready");
    }
    ESP_ERROR_CHECK(mqtt_start());

    alarm_init();
    mqtt_publish_state();
    mqtt_publish_scenes();

    zone_inputs_snapshot_t snapshot;
    uint16_t last_zones_total = roster_effective_zones(ZONE_INPUT_COUNT);
    zone_mask_t last_alarm_mask;
    zone_mask_t last_tamper_mask;
    zone_mask_clear(&last_alarm_mask);
    zone_mask_clear(&last_tamper_mask);
    bool last_global_tamper = false;
    bool first_cycle = true;
    if (zone_inputs_sample(&snapshot) == ESP_OK) {
        uint16_t zones_total = roster_effective_zones(ZONE_INPUT_COUNT);
        zone_mask_t init_alarm;
        zone_mask_t init_tamper;
        bool global_tamper = false;
        compose_zone_masks(&snapshot, zones_total, &init_alarm, &init_tamper, &global_tamper);
        mqtt_publish_zones(&init_alarm, &init_tamper, global_tamper);
        zone_mask_copy(&last_alarm_mask, &init_alarm);
        zone_mask_copy(&last_tamper_mask, &init_tamper);
        last_global_tamper = global_tamper;
        last_zones_total = zones_total;
        first_cycle = false;
    }

    // Avvia web server (serve i file SPIFFS)
    //ESP_ERROR_CHECK(web_server_start());
    ESP_ERROR_CHECK(web_server_start_with_stack());

    // Riduci il rumore di handshake cancellati dal client (-0x0050) e altre riconnessioni
    esp_log_level_set("esp-tls-mbedtls", ESP_LOG_WARN);
    esp_log_level_set("esp_http_server", ESP_LOG_WARN);
    esp_log_level_set("httpd",           ESP_LOG_WARN);
    // opzionale:
    // esp_log_level_set("esp-tls",      ESP_LOG_WARN);


    UBaseType_t watermark_words = uxTaskGetStackHighWaterMark(NULL);
    size_t watermark_bytes = watermark_words * sizeof(StackType_t);
    ESP_LOGI(TAG,
             "System ready. sys_main stack high watermark: %u bytes (stack size %u bytes, default main stack %u bytes)",
             (unsigned)watermark_bytes,
             (unsigned)SYSTEM_MAIN_TASK_STACK_BYTES,
             (unsigned)CONFIG_ESP_MAIN_TASK_STACK_SIZE);

    // Main loop: leggi ingressi e alimenta la logica d’allarme
    
    while (true) {
        zone_inputs_snapshot_t loop_snapshot;
        if (zone_inputs_sample(&loop_snapshot) != ESP_OK) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        uint16_t zones_total = roster_effective_zones(ZONE_INPUT_COUNT);
        zone_mask_t alarm_mask;
        zone_mask_t tamper_mask;
        bool global_tamper = false;
        compose_zone_masks(&loop_snapshot, zones_total, &alarm_mask, &tamper_mask, &global_tamper);

        if (first_cycle || zone_mask_equal(&alarm_mask, &last_alarm_mask) != 0 ||
            !zone_mask_equal(&tamper_mask, &last_tamper_mask) ||
            global_tamper != last_global_tamper || zones_total != last_zones_total) {
            mqtt_publish_zones(&alarm_mask, &tamper_mask, global_tamper);
            zone_mask_copy(&last_alarm_mask, &alarm_mask);
            zone_mask_copy(&last_tamper_mask, &tamper_mask);
            last_global_tamper = global_tamper;
            last_zones_total = zones_total;
            first_cycle = false;
        }

        bool any_tamper = global_tamper || zone_mask_any(&tamper_mask);
        alarm_tick(&alarm_mask, &tamper_mask, any_tamper, global_tamper);

        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

void app_main(void)
{
    const uint32_t stack_words = SYSTEM_MAIN_TASK_STACK_BYTES / sizeof(StackType_t);
    const BaseType_t created = xTaskCreatePinnedToCore(
        system_main_task,
        "sys_main",
        stack_words,
        NULL,
        SYSTEM_MAIN_TASK_PRIORITY,
        NULL,
        tskNO_AFFINITY);

    if (created != pdPASS) {
        ESP_LOGE(TAG, "Unable to create system main task (%ld)", (long)created);
        system_main_task(NULL);
    }
}