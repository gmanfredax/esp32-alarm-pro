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
#include "driver/twai.h"

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
// #include "mdns_service.h"
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

#if defined(CONFIG_APP_CAN_ENABLED)
static const char *TAG_CAN = "can";

static esp_err_t can_master_handle_node_info(uint8_t node_id, const roster_node_info_t *info);
static void can_master_handle_node_online(uint8_t node_id);
static void can_master_handle_node_offline(uint8_t node_id);
static esp_err_t can_master_driver_start(void);
static void can_master_driver_stop(void);
static void can_master_process_restart(void);
static void can_master_trigger_discovery(void);
#endif

#define SYSTEM_MAIN_TASK_STACK_BYTES      (16384)
#define SYSTEM_MAIN_TASK_PRIORITY         (tskIDLE_PRIORITY + 5)
#define WEB_SERVER_START_TASK_STACK_BYTES (16384)
#define WEB_SERVER_START_TASK_PRIORITY    (SYSTEM_MAIN_TASK_PRIORITY)

_Static_assert((SYSTEM_MAIN_TASK_STACK_BYTES % sizeof(StackType_t)) == 0,
               "SYSTEM_MAIN_TASK_STACK_BYTES must align to StackType_t size");


// ---- START CANBUS -------------------------------------------

#define CAN_SCAN_WINDOW_US (2000000ULL)
#define MASTER_OUTPUTS_COUNT 3

#if defined(CONFIG_APP_CAN_ENABLED)

#define CAN_RX_TASK_STACK_BYTES (CONFIG_APP_CAN_RX_TASK_STACK)
#define CAN_RX_TASK_PRIORITY    (tskIDLE_PRIORITY + 4)

#define CAN_MAX_NODE_ID         (127u)
#define CAN_NODE_TIMEOUT_MS     ((uint32_t)CONFIG_APP_CAN_NODE_TIMEOUT_MS)

_Static_assert((CAN_RX_TASK_STACK_BYTES % sizeof(StackType_t)) == 0,
               "CAN_RX_TASK_STACK_BYTES must align to StackType_t size");

typedef struct {
    bool used;
    bool online;
    uint8_t last_state;
    uint64_t last_seen_ms;
} can_node_state_t;

static bool s_can_driver_started = false;
static bool s_can_driver_starting = false;
static bool s_can_driver_restart_pending = false;
static bool s_can_driver_stop_pending = false;
static bool s_can_discovery_pending = false;
static TaskHandle_t s_can_rx_task = NULL;
static SemaphoreHandle_t s_can_state_lock = NULL;
static can_node_state_t s_can_nodes[CAN_MAX_NODE_ID + 1];
static char s_can_driver_stop_reason[64];

static inline uint64_t can_now_ms(void)
{
    return (uint64_t)(esp_timer_get_time() / 1000ULL);
}

static SemaphoreHandle_t can_state_lock_get(void)
{
    if (!s_can_state_lock) {
        s_can_state_lock = xSemaphoreCreateMutex();
    }
    return s_can_state_lock;
}

static void can_master_request_driver_restart(const char *reason)
{
    if (!s_can_driver_restart_pending) {
        s_can_driver_restart_pending = true;
    }

    if (reason && reason[0] != '\0') {
        snprintf(s_can_driver_stop_reason, sizeof(s_can_driver_stop_reason), "%s", reason);
    } else {
        s_can_driver_stop_reason[0] = '\0';
    }

    if (!s_can_driver_stop_pending) {
        s_can_driver_stop_pending = true;
        if (s_can_driver_started) {
            const char *log_reason = s_can_driver_stop_reason[0] ? s_can_driver_stop_reason : "fault";
            ESP_LOGW(TAG_CAN, "Scheduling CAN driver stop (%s)", log_reason);
        }
    }

    if (s_can_rx_task) {
        xTaskNotifyGive(s_can_rx_task);
    }
}

static void can_master_driver_stop(void)
{
    if (!s_can_driver_started) {
        if (!s_can_driver_starting) {
            s_can_driver_stop_pending = false;
            s_can_driver_stop_reason[0] = '\0';
        }
        return;
    }

    const char *reason = s_can_driver_stop_reason[0] ? s_can_driver_stop_reason : "fault";
    ESP_LOGW(TAG_CAN, "Stopping CAN driver (%s)", reason);

    esp_err_t err = twai_stop();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGW(TAG_CAN, "twai_stop failed: %s", esp_err_to_name(err));
    }

    err = twai_driver_uninstall();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGW(TAG_CAN, "twai_driver_uninstall failed: %s", esp_err_to_name(err));
    }

    s_can_driver_started = false;
    s_can_driver_stop_pending = false;
    s_can_driver_stop_reason[0] = '\0';
}

static inline twai_timing_config_t can_timing_config(void)
{
#if defined(CONFIG_APP_CAN_BITRATE_125K)
    return (twai_timing_config_t)TWAI_TIMING_CONFIG_125KBITS();
#elif defined(CONFIG_APP_CAN_BITRATE_500K)
    return (twai_timing_config_t)TWAI_TIMING_CONFIG_500KBITS();
#else
    return (twai_timing_config_t)TWAI_TIMING_CONFIG_250KBITS();
#endif
}

static void can_log_frame_debug(const twai_message_t *msg)
{
    if (!msg) {
        return;
    }
    char payload[3 * TWAI_FRAME_MAX_DLC + 1];
    size_t off = 0;
    for (int i = 0; i < msg->data_length_code && off + 3 < sizeof(payload); ++i) {
        off += snprintf(&payload[off], sizeof(payload) - off, "%02X ", msg->data[i]);
    }
    if (off == 0) {
        payload[0] = '\0';
    } else if (off > 0) {
        payload[off - 1] = '\0';
    }
    ESP_LOGD(TAG_CAN, "RX id=0x%03" PRIx32 " len=%d rtr=%d data=%s",
             msg->identifier & 0x7FFu,
             (int)msg->data_length_code,
             (int)msg->rtr,
             payload);
}

static void can_state_mark_seen(uint8_t node_id, uint8_t state)
{
    if (node_id == 0 || node_id > CAN_MAX_NODE_ID) {
        return;
    }
    SemaphoreHandle_t lock = can_state_lock_get();
    if (!lock) {
        return;
    }
    uint64_t now_ms = can_now_ms();
    bool became_online = false;
    xSemaphoreTake(lock, portMAX_DELAY);
    can_node_state_t *entry = &s_can_nodes[node_id];
    became_online = !entry->online;
    entry->used = true;
    entry->online = true;
    entry->last_state = state;
    entry->last_seen_ms = now_ms;
    xSemaphoreGive(lock);

    if (became_online) {
        ESP_LOGI(TAG_CAN, "node %u online (state=0x%02X)", (unsigned)node_id, state);
        can_master_handle_node_online(node_id);
    }
}

static void can_state_check_timeouts(void)
{
    SemaphoreHandle_t lock = can_state_lock_get();
    if (!lock) {
        return;
    }
    uint8_t offline_nodes[CAN_MAX_NODE_ID + 1];
    const size_t offline_capacity = sizeof(offline_nodes) / sizeof(offline_nodes[0]);
    size_t offline_count = 0;
    uint64_t now_ms = can_now_ms();
    xSemaphoreTake(lock, portMAX_DELAY);
    for (uint32_t node_id = 1; node_id <= CAN_MAX_NODE_ID; ++node_id) {
        can_node_state_t *entry = &s_can_nodes[node_id];
        if (!entry->used || !entry->online) {
            continue;
        }
        if ((now_ms - entry->last_seen_ms) > CAN_NODE_TIMEOUT_MS) {
            entry->online = false;
            if (offline_count < offline_capacity) {
                offline_nodes[offline_count++] = (uint8_t)node_id;
            }
        }
    }
    xSemaphoreGive(lock);

    for (size_t i = 0; i < offline_count; ++i) {
        uint8_t node_id = offline_nodes[i];
        ESP_LOGW(TAG_CAN, "node %u offline (timeout)", (unsigned)node_id);
        can_master_handle_node_offline(node_id);
    }
}

static void can_process_pdo_or_heartbeat(uint32_t cob_id, const twai_message_t *msg)
{
    uint8_t node_id = (uint8_t)(cob_id & 0x7Fu);
    uint8_t state = (msg && msg->data_length_code > 0) ? msg->data[0] : 0x05u;
    can_state_mark_seen(node_id, state);
}

static void can_process_node_info(uint8_t node_id, const twai_message_t *msg)
{
    if (!msg) {
        return;
    }
    roster_node_info_t info = {
        .label = NULL,
        .kind = NULL,
        .uid = NULL,
        .has_uid = false,
        .model = 0,
        .fw = 0,
        .caps = 0,
        .inputs_count = 0,
        .outputs_count = 0,
    };

    if (msg->data_length_code >= 8) {
        info.model = (uint16_t)((uint16_t)msg->data[1] << 8 | (uint16_t)msg->data[0]);
        info.fw = (uint16_t)((uint16_t)msg->data[3] << 8 | (uint16_t)msg->data[2]);
        info.inputs_count = msg->data[4];
        info.outputs_count = msg->data[5];
        info.caps = (uint16_t)((uint16_t)msg->data[7] << 8 | (uint16_t)msg->data[6]);
        can_master_handle_node_info(node_id, &info);
    }
}

static void can_process_frame(const twai_message_t *msg)
{
    if (!msg || msg->extd) {
        return;
    }
    can_log_frame_debug(msg);
    uint32_t cob_id = msg->identifier & 0x7FFu;

    if ((cob_id & 0x780u) == 0x700u) { // Heartbeat or boot-up
        can_process_pdo_or_heartbeat(cob_id, msg);
        return;
    }

    if (cob_id >= 0x180u && cob_id <= 0x1FFu) { // PDO1 (inputs)
        can_process_pdo_or_heartbeat(cob_id, msg);
        return;
    }

    if (cob_id >= 0x580u && cob_id <= 0x5FFu) { // SDO response
        uint8_t node_id = (uint8_t)(cob_id - 0x580u);
        if (node_id == 0) {
            return;
        }
        can_state_mark_seen(node_id, 0x05u);
        can_process_node_info(node_id, msg);
        return;
    }
}

static void can_rx_task(void *arg)
{
    (void)arg;
    ESP_LOGI(TAG_CAN, "RX task started");
    while (true) {
        if (s_can_driver_stop_pending) {
            if (s_can_driver_started) {
                can_master_driver_stop();
            } else if (!s_can_driver_starting) {
                s_can_driver_stop_pending = false;
                s_can_driver_stop_reason[0] = '\0';
            }
            can_state_check_timeouts();
            can_master_process_restart();
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }

        if (!s_can_driver_started) {
            can_master_process_restart();
            vTaskDelay(pdMS_TO_TICKS(50));
            can_state_check_timeouts();
            continue;
        }
        twai_message_t msg = {0};
        esp_err_t err = twai_receive(&msg, pdMS_TO_TICKS(200));
        if (err == ESP_OK) {
            can_process_frame(&msg);
        } else if (err != ESP_ERR_TIMEOUT) {
            if (!(err == ESP_ERR_INVALID_STATE && !s_can_driver_started)) {
                ESP_LOGW(TAG_CAN, "twai_receive failed: %s", esp_err_to_name(err));
            }
            if (err == ESP_ERR_INVALID_STATE) {
                can_master_request_driver_restart("rx invalid state");
                vTaskDelay(pdMS_TO_TICKS(50));
            }
        }
        can_state_check_timeouts();
        can_master_process_restart();
        if (s_can_discovery_pending) {
            can_master_trigger_discovery();
        }
    }
}

static esp_err_t can_master_send_frame(uint32_t cob_id, const uint8_t *data, uint8_t len)
{
    if (s_can_driver_stop_pending) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!s_can_driver_started) {
        if (!s_can_driver_starting && !s_can_driver_restart_pending) {
            esp_err_t serr = can_master_driver_start();
            if (serr != ESP_OK) {
                return serr;
            }
        } else {
            return ESP_ERR_INVALID_STATE;
        }
    }
    twai_message_t msg = {0};
    msg.identifier = cob_id & 0x7FFu;
    msg.extd = 0;
    msg.rtr = 0;
    msg.data_length_code = len;
    if (data && len > 0) {
        if (len > sizeof(msg.data)) {
            len = sizeof(msg.data);
            msg.data_length_code = sizeof(msg.data);
        }
        memcpy(msg.data, data, len);
    } else {
        memset(msg.data, 0, sizeof(msg.data));
    }
    esp_err_t err = twai_transmit(&msg, pdMS_TO_TICKS(50));
    if (err == ESP_ERR_INVALID_STATE) {
        can_master_request_driver_restart("tx invalid state");
    }
    return err;
}

static esp_err_t can_master_send_nmt(uint8_t command, uint8_t target)
{
    uint8_t payload[2] = { command, target };
    esp_err_t err = can_master_send_frame(0x000u, payload, sizeof(payload));
    if (err != ESP_OK) {
        ESP_LOGW(TAG_CAN, "NMT 0x%02X to %u failed: %s", (unsigned)command, (unsigned)target, esp_err_to_name(err));
    }
    return err;
}

static inline bool can_driver_ready_for_discovery(void)
{
    if (!(s_can_driver_started && !s_can_driver_starting &&
          !s_can_driver_stop_pending && !s_can_driver_restart_pending)) {
        return false;
    }

    twai_status_info_t status = {0};
    esp_err_t err = twai_get_status_info(&status);
    if (err != ESP_OK) {
        return false;
    }

    return status.state == TWAI_STATE_RUNNING;
}

static void can_master_send_discovery_commands(void)
{
    (void)can_master_send_nmt(0x82u, 0x00u); // Reset communication
    (void)can_master_send_nmt(0x01u, 0x00u); // Start all nodes
}

static void can_master_trigger_discovery(void)
{
    if (!can_driver_ready_for_discovery()) {
        s_can_discovery_pending = true;
        return;
    }

    s_can_discovery_pending = false;
    can_master_send_discovery_commands();
}

static void can_master_process_restart(void)
{
    if (!s_can_driver_restart_pending || s_can_driver_starting || s_can_driver_stop_pending) {
        return;
    }
    esp_err_t err = can_master_driver_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG_CAN, "CAN driver restart failed: %s", esp_err_to_name(err));
        s_can_driver_restart_pending = true;
        vTaskDelay(pdMS_TO_TICKS(250));
        return;
    }
    s_can_driver_restart_pending = false;
    can_master_trigger_discovery();
}

static esp_err_t can_master_driver_start(void)
{
    if (s_can_driver_started) {
        return ESP_OK;
    }
    if (s_can_driver_starting) {
        return ESP_ERR_INVALID_STATE;
    }
    s_can_driver_starting = true;

    twai_general_config_t g_config = TWAI_GENERAL_CONFIG_DEFAULT(CAN_TX_GPIO, CAN_RX_GPIO, TWAI_MODE_NORMAL);
    g_config.clkout_divider = 0;
    g_config.rx_queue_len = 32;
    g_config.tx_queue_len = 32;
    g_config.alerts_enabled = TWAI_ALERT_NONE;
#if CONFIG_TWAI_ISR_IN_IRAM
    g_config.intr_flags = ESP_INTR_FLAG_IRAM;
#endif

    twai_timing_config_t t_config = can_timing_config();
    twai_filter_config_t f_config = TWAI_FILTER_CONFIG_ACCEPT_ALL();

    esp_err_t err = twai_driver_install(&g_config, &t_config, &f_config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_CAN, "twai_driver_install failed: %s", esp_err_to_name(err));
        s_can_driver_starting = false;
        return err;
    }

    err = twai_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG_CAN, "twai_start failed: %s", esp_err_to_name(err));
        twai_driver_uninstall();
        s_can_driver_starting = false;
        return err;
    }

    uint32_t current_alerts = 0;
    err = twai_reconfigure_alerts(TWAI_ALERT_BUS_OFF | TWAI_ALERT_BUS_RECOVERED |
                                  TWAI_ALERT_ERR_PASS | TWAI_ALERT_RX_DATA |
                                  TWAI_ALERT_TX_FAILED | TWAI_ALERT_RX_QUEUE_FULL,
                                  &current_alerts);
    (void)current_alerts;
    if (err != ESP_OK) {
        ESP_LOGW(TAG_CAN, "twai_reconfigure_alerts failed: %s", esp_err_to_name(err));
    }

    memset(s_can_nodes, 0, sizeof(s_can_nodes));

    if (!s_can_rx_task) {
        const BaseType_t task_ok = xTaskCreatePinnedToCore(
            can_rx_task,
            "can_rx",
            CAN_RX_TASK_STACK_BYTES / sizeof(StackType_t),
            NULL,
            CAN_RX_TASK_PRIORITY,
            &s_can_rx_task,
            tskNO_AFFINITY);
        if (task_ok != pdPASS) {
            ESP_LOGE(TAG_CAN, "unable to create CAN RX task (%ld)", (long)task_ok);
            twai_stop();
            twai_driver_uninstall();
            s_can_driver_starting = false;
            return ESP_ERR_NO_MEM;
        }
    }

    s_can_driver_started = true;
    s_can_driver_starting = false;
    s_can_driver_restart_pending = false;

    ESP_LOGI(TAG_CAN, "driver started (bitrate %s)",
#if defined(CONFIG_APP_CAN_BITRATE_125K)
             "125k"
#elif defined(CONFIG_APP_CAN_BITRATE_500K)
             "500k"
#else
             "250k"
#endif
    );
    can_master_trigger_discovery();
    return ESP_OK;
}

#endif // CONFIG_APP_CAN_ENABLED

static SemaphoreHandle_t s_scan_mutex = NULL;
static esp_timer_handle_t s_scan_timer = NULL;
static bool s_scan_in_progress = false;
static size_t s_scan_new_nodes = 0;

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
#if !defined(CONFIG_APP_CAN_ENABLED)
    if (started) {
        *started = false;
    }
    return ESP_ERR_NOT_SUPPORTED;
#endif
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

#if defined(CONFIG_APP_CAN_ENABLED)
    can_master_trigger_discovery();
#endif

    if (started) {
        *started = true;
    }
    return ESP_OK;
}

static esp_err_t can_master_handle_node_info(uint8_t node_id, const roster_node_info_t *info)
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

static void can_master_handle_node_online(uint8_t node_id)
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

static void can_master_handle_node_offline(uint8_t node_id)
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

//void app_main(void)
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

    ESP_ERROR_CHECK(inputs_init());
    ESP_ERROR_CHECK(scenes_init(INPUT_ZONES_COUNT));
    ESP_ERROR_CHECK(outputs_init());
    ESP_ERROR_CHECK(pn532_init());
    ESP_ERROR_CHECK(ds18b20_init());
    ESP_ERROR_CHECK(log_system_init());

    ensure_scan_mutex();
    roster_init(INPUT_ZONES_COUNT, MASTER_OUTPUTS_COUNT, 0);

#if defined(CONFIG_APP_CAN_ENABLED)
    ESP_ERROR_CHECK(can_master_driver_start());
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
    ESP_ERROR_CHECK(web_server_start_with_stack());

    // Riduci il rumore di handshake cancellati dal client (-0x0050) e altre riconnessioni
    esp_log_level_set("esp-tls-mbedtls", ESP_LOG_WARN);
    esp_log_level_set("esp_https_server", ESP_LOG_WARN);
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