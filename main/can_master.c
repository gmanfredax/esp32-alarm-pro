#include "sdkconfig.h"
#include "can_master.h"

#include <string.h>
#include <inttypes.h>

#if CONFIG_APP_CAN_ENABLED

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "driver/twai.h"
#include "esp_err.h"

#include "can_bus_protocol.h"
#include "pins.h"
#include "roster.h"
#include "pdo.h"
#include "web_server.h"
#include "cJSON.h"

#ifndef TWAI_FRAME_MAX_DLC
#define TWAI_FRAME_MAX_DLC 8
#endif

#define CAN_RX_TASK_STACK_BYTES  (4096)
#define CAN_RX_TASK_PRIORITY     (tskIDLE_PRIORITY + 4)
#define CAN_NODE_TIMEOUT_MS      (2500ULL)
#define CAN_MAX_NODE_ID          (127u)
#define CAN_SCAN_WINDOW_US       (2000000ULL)

typedef struct {
    bool used;
    bool online;
    uint64_t last_seen_ms;
    uint32_t last_inputs;
    uint8_t last_state;
    uint8_t change_counter;
} can_master_node_t;

static const char *TAG = "can_master";

static TaskHandle_t s_rx_task = NULL;
static bool s_driver_started = false;
static SemaphoreHandle_t s_state_lock = NULL;
static can_master_node_t s_nodes[CAN_MAX_NODE_ID + 1];

static SemaphoreHandle_t s_scan_lock = NULL;
static bool s_scan_in_progress = false;
static size_t s_scan_new_nodes = 0;
static esp_timer_handle_t s_scan_timer = NULL;

static SemaphoreHandle_t state_lock_get(void);
static SemaphoreHandle_t scan_lock_get(void);
static void can_master_rx_task(void *arg);
static void can_master_handle_frame(const twai_message_t *msg);
static void can_master_handle_heartbeat(uint8_t node_id, const can_proto_heartbeat_t *payload);
static void can_master_handle_info(uint8_t node_id, const can_proto_info_t *payload);
static void can_master_check_timeouts(void);
static void can_master_notify_online(uint8_t node_id, bool is_new, uint64_t now_ms);
static void can_master_notify_offline(uint8_t node_id, uint64_t now_ms);
static void can_scan_note_new_node(void);
static esp_err_t can_master_driver_start_internal(void);
static void scan_timer_cb(void *arg);
static twai_timing_config_t can_timing_config(void);

static inline uint64_t now_ms(void)
{
    return (uint64_t)(esp_timer_get_time() / 1000ULL);
}

static SemaphoreHandle_t state_lock_get(void)
{
    if (!s_state_lock) {
        s_state_lock = xSemaphoreCreateMutex();
    }
    return s_state_lock;
}

static SemaphoreHandle_t scan_lock_get(void)
{
    if (!s_scan_lock) {
        s_scan_lock = xSemaphoreCreateMutex();
    }
    return s_scan_lock;
}

static twai_timing_config_t can_timing_config(void)
{
#if defined(CONFIG_APP_CAN_BITRATE_125K)
    return (twai_timing_config_t)TWAI_TIMING_CONFIG_125KBITS();
#elif defined(CONFIG_APP_CAN_BITRATE_500K)
    return (twai_timing_config_t)TWAI_TIMING_CONFIG_500KBITS();
#else
    return (twai_timing_config_t)TWAI_TIMING_CONFIG_250KBITS();
#endif
}

static esp_err_t can_master_driver_start_internal(void)
{
    if (s_driver_started) {
        return ESP_OK;
    }

    twai_general_config_t g_config =
        TWAI_GENERAL_CONFIG_DEFAULT(CAN_TX_GPIO, CAN_RX_GPIO, TWAI_MODE_NORMAL);
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
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "twai_driver_install failed: %s", esp_err_to_name(err));
        return err;
    } else if (err == ESP_ERR_INVALID_STATE) {
        ESP_LOGW(TAG, "twai driver already installed, attempting restart");
        (void)twai_stop();
        (void)twai_driver_uninstall();
        err = twai_driver_install(&g_config, &t_config, &f_config);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "twai_driver_install retry failed: %s", esp_err_to_name(err));
            return err;
        }
    }

    err = twai_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "twai_start failed: %s", esp_err_to_name(err));
        (void)twai_driver_uninstall();
        return err;
    }

    memset(s_nodes, 0, sizeof(s_nodes));
    s_driver_started = true;

    if (!s_rx_task) {
        BaseType_t task_ok = xTaskCreate(can_master_rx_task,
                                         "can_rx",
                                         CAN_RX_TASK_STACK_BYTES,
                                         NULL,
                                         CAN_RX_TASK_PRIORITY,
                                         &s_rx_task);
        if (task_ok != pdPASS) {
            ESP_LOGE(TAG, "unable to create CAN RX task (%ld)", (long)task_ok);
            s_rx_task = NULL;
            (void)twai_stop();
            (void)twai_driver_uninstall();
            s_driver_started = false;
            return ESP_ERR_NO_MEM;
        }
    }

    ESP_LOGI(TAG, "CAN master driver started");
    return ESP_OK;
}

esp_err_t can_master_init(void)
{
    static bool s_initialized = false;

    if (!s_initialized) {
        if (!state_lock_get() || !scan_lock_get()) {
            return ESP_ERR_NO_MEM;
        }
        esp_err_t err = can_master_driver_start_internal();
        if (err != ESP_OK) {
            return err;
        }
        s_initialized = true;
    } else if (!s_driver_started) {
        esp_err_t err = can_master_driver_start_internal();
        if (err != ESP_OK) {
            return err;
        }
    }

    return ESP_OK;
}

static void can_scan_note_new_node(void)
{
    SemaphoreHandle_t lock = scan_lock_get();
    if (!lock) {
        return;
    }
    xSemaphoreTake(lock, portMAX_DELAY);
    if (s_scan_in_progress) {
        ++s_scan_new_nodes;
    }
    xSemaphoreGive(lock);
}

static void scan_timer_cb(void *arg)
{
    (void)arg;
    size_t discovered = 0;
    SemaphoreHandle_t lock = scan_lock_get();
    if (lock) {
        xSemaphoreTake(lock, portMAX_DELAY);
        discovered = s_scan_new_nodes;
        s_scan_new_nodes = 0;
        s_scan_in_progress = false;
        xSemaphoreGive(lock);
    }

    uint64_t ts = now_ms();
    cJSON *evt = cJSON_CreateObject();
    if (evt) {
        cJSON_AddNumberToObject(evt, "ts", (double)ts);
        cJSON_AddNumberToObject(evt, "new_nodes", (double)discovered);
        web_server_ws_broadcast_event("scan_completed", evt);
    }
}

static void can_master_notify_online(uint8_t node_id, bool is_new, uint64_t now_ms)
{
    (void)pdo_send_led_oneshot(node_id, 1, 1000);

    if (is_new) {
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

static void can_master_notify_offline(uint8_t node_id, uint64_t now_ms)
{
    (void)pdo_send_led_oneshot(node_id, 2, 1500);

    cJSON *evt = cJSON_CreateObject();
    if (evt) {
        cJSON_AddNumberToObject(evt, "node_id", node_id);
        cJSON_AddNumberToObject(evt, "last_seen_ms", (double)now_ms);
        web_server_ws_broadcast_event("node_offline", evt);
    }
}

static void can_master_check_timeouts(void)
{
    uint64_t now = now_ms();
    uint8_t offline[CAN_MAX_NODE_ID + 1];
    size_t offline_count = 0;

    SemaphoreHandle_t lock = state_lock_get();
    if (!lock) {
        return;
    }

    xSemaphoreTake(lock, portMAX_DELAY);
    for (uint32_t node_id = 1; node_id <= CAN_MAX_NODE_ID; ++node_id) {
        can_master_node_t *node = &s_nodes[node_id];
        if (!node->used || !node->online) {
            continue;
        }
        if (now - node->last_seen_ms > CAN_NODE_TIMEOUT_MS) {
            node->online = false;
            offline[offline_count++] = (uint8_t)node_id;
        }
    }
    xSemaphoreGive(lock);

    for (size_t i = 0; i < offline_count; ++i) {
        uint8_t node_id = offline[i];
        if (roster_mark_offline(node_id, now) == ESP_OK) {
            can_master_notify_offline(node_id, now);
        }
    }
}

static void can_master_handle_heartbeat(uint8_t node_id, const can_proto_heartbeat_t *payload)
{
    if (!payload) {
        return;
    }
    uint64_t now = now_ms();
    bool was_online = false;

    SemaphoreHandle_t lock = state_lock_get();
    if (!lock) {
        return;
    }

    xSemaphoreTake(lock, portMAX_DELAY);
    can_master_node_t *node = &s_nodes[node_id];
    was_online = node->online;
    node->used = true;
    node->online = true;
    node->last_seen_ms = now;
    node->last_inputs = payload->inputs_bitmap;
    node->last_state = payload->node_state;
    node->change_counter = payload->change_counter;
    xSemaphoreGive(lock);

    bool is_new = false;
    if (roster_mark_online(node_id, now, &is_new) == ESP_OK) {
        if (is_new) {
            can_scan_note_new_node();
        }
        if (!was_online || is_new) {
            can_master_notify_online(node_id, is_new, now);
        }
    }
}

static void can_master_handle_info(uint8_t node_id, const can_proto_info_t *payload)
{
    if (!payload) {
        return;
    }

    if (payload->protocol != CAN_PROTO_PROTOCOL_VERSION) {
        ESP_LOGW(TAG,
                 "Node %u protocol mismatch (got %u expected %u)",
                 (unsigned)node_id,
                 (unsigned)payload->protocol,
                 (unsigned)CAN_PROTO_PROTOCOL_VERSION);
    }

    roster_node_info_t info = {
        .label = NULL,
        .kind = "exp",
        .uid = NULL,
        .has_uid = false,
        .model = payload->model,
        .fw = payload->firmware,
        .caps = 0,
        .inputs_count = payload->inputs_count,
        .outputs_count = payload->outputs_count,
    };

    bool is_new = false;
    if (roster_update_node(node_id, &info, &is_new) == ESP_OK) {
        if (is_new) {
            can_scan_note_new_node();
        }
        cJSON *node_obj = roster_node_to_json(node_id);
        if (node_obj) {
            web_server_ws_broadcast_event(is_new ? "node_added" : "node_updated", node_obj);
        }
    }

    uint64_t now = now_ms();
    bool was_online = false;
    SemaphoreHandle_t lock = state_lock_get();
    if (lock) {
        xSemaphoreTake(lock, portMAX_DELAY);
        can_master_node_t *node = &s_nodes[node_id];
        was_online = node->online;
        node->used = true;
        node->online = true;
        node->last_seen_ms = now;
        xSemaphoreGive(lock);
    }

    bool online_new = false;
    if (roster_mark_online(node_id, now, &online_new) == ESP_OK) {
        if (online_new && !is_new) {
            can_scan_note_new_node();
        }
        if (!was_online || online_new) {
            can_master_notify_online(node_id, online_new, now);
        }
    }
}

static void can_master_handle_scan_response(const twai_message_t *msg)
{
    if (!msg || msg->data_length_code == 0) {
        return;
    }
    const can_proto_scan_t *scan = (const can_proto_scan_t *)msg->data;
    if (scan->msg_type != CAN_PROTO_MSG_SCAN_RESPONSE) {
        return;
    }
    ESP_LOGI(TAG, "Received CAN scan response frame");
}

static void can_master_handle_frame(const twai_message_t *msg)
{
    if (!msg || msg->extd) {
        return;
    }

    uint32_t cob_id = msg->identifier & 0x7FFu;

    if (cob_id == CAN_PROTO_ID_BROADCAST_SCAN) {
        can_master_handle_scan_response(msg);
        return;
    }

    if (cob_id >= CAN_PROTO_ID_STATUS_BASE &&
        cob_id < (CAN_PROTO_ID_STATUS_BASE + CAN_MAX_NODE_ID + 1)) {
        uint8_t node_id = (uint8_t)(cob_id - CAN_PROTO_ID_STATUS_BASE);
        if (msg->data_length_code >= sizeof(can_proto_heartbeat_t)) {
            const can_proto_heartbeat_t *payload = (const can_proto_heartbeat_t *)msg->data;
            if (payload->msg_type == CAN_PROTO_MSG_HEARTBEAT ||
                payload->msg_type == CAN_PROTO_MSG_IO_REPORT) {
                can_master_handle_heartbeat(node_id, payload);
            }
        }
        return;
    }

    if (cob_id >= CAN_PROTO_ID_INFO_BASE &&
        cob_id < (CAN_PROTO_ID_INFO_BASE + CAN_MAX_NODE_ID + 1)) {
        uint8_t node_id = (uint8_t)(cob_id - CAN_PROTO_ID_INFO_BASE);
        if (msg->data_length_code >= sizeof(can_proto_info_t)) {
            const can_proto_info_t *payload = (const can_proto_info_t *)msg->data;
            if (payload->msg_type == CAN_PROTO_MSG_INFO) {
                can_master_handle_info(node_id, payload);
            }
        }
        return;
    }
}

static void can_master_rx_task(void *arg)
{
    (void)arg;
    ESP_LOGI(TAG, "CAN RX task started");

    for (;;) {
        twai_message_t msg = {0};
        esp_err_t err = twai_receive(&msg, pdMS_TO_TICKS(100));
        if (err == ESP_OK) {
            can_master_handle_frame(&msg);
        } else if (err != ESP_ERR_TIMEOUT) {
            ESP_LOGW(TAG, "twai_receive failed: %s", esp_err_to_name(err));
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        can_master_check_timeouts();
    }
}

esp_err_t can_master_send_raw(uint32_t cob_id, const void *payload, uint8_t len)
{
    if (len > TWAI_FRAME_MAX_DLC) {
        len = TWAI_FRAME_MAX_DLC;
    }

    esp_err_t err = can_master_init();
    if (err != ESP_OK) {
        return err;
    }

    twai_message_t msg = {
        .identifier = cob_id & 0x7FFu,
        .extd = 0,
        .rtr = 0,
        .ss = 0,
        .self = 0,
        .dlc_non_comp = 0,
        .data_length_code = len,
    };

    memset(msg.data, 0, sizeof(msg.data));
    if (payload && len > 0) {
        memcpy(msg.data, payload, len);
    }

    err = twai_transmit(&msg, pdMS_TO_TICKS(50));
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "twai_transmit 0x%03" PRIx32 " failed: %s",
                 cob_id & 0x7FFu,
                 esp_err_to_name(err));
    }
    return err;
}

esp_err_t can_master_send_test_toggle(bool enable)
{
    can_proto_test_toggle_t payload = {
        .msg_type = CAN_PROTO_MSG_TEST_TOGGLE,
        .enable = enable ? 1u : 0u,
        .reserved = {0},
    };
    return can_master_send_raw(CAN_PROTO_ID_BROADCAST_TEST, &payload, sizeof(payload));
}

esp_err_t can_master_request_scan(bool *started)
{
    esp_err_t err = can_master_init();
    if (err != ESP_OK) {
        if (started) {
            *started = false;
        }
        return err;
    }

    SemaphoreHandle_t lock = scan_lock_get();
    if (!lock) {
        if (started) {
            *started = false;
        }
        return ESP_ERR_NO_MEM;
    }

    xSemaphoreTake(lock, portMAX_DELAY);
    if (s_scan_in_progress) {
        xSemaphoreGive(lock);
        if (started) {
            *started = false;
        }
        return ESP_ERR_INVALID_STATE;
    }

    s_scan_in_progress = true;
    s_scan_new_nodes = 0;
    xSemaphoreGive(lock);

    if (!s_scan_timer) {
        const esp_timer_create_args_t args = {
            .callback = scan_timer_cb,
            .arg = NULL,
            .dispatch_method = ESP_TIMER_TASK,
            .name = "can_scan",
        };
        err = esp_timer_create(&args, &s_scan_timer);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "esp_timer_create failed: %s", esp_err_to_name(err));
            xSemaphoreTake(lock, portMAX_DELAY);
            s_scan_in_progress = false;
            xSemaphoreGive(lock);
            if (started) {
                *started = false;
            }
            return err;
        }
    }

    can_proto_scan_t payload = {
        .msg_type = CAN_PROTO_MSG_SCAN_REQUEST,
        .reserved = {0},
    };

    err = can_master_send_raw(CAN_PROTO_ID_BROADCAST_SCAN, &payload, sizeof(payload));
    if (err != ESP_OK) {
        xSemaphoreTake(lock, portMAX_DELAY);
        s_scan_in_progress = false;
        xSemaphoreGive(lock);
        if (started) {
            *started = false;
        }
        return err;
    }

    uint64_t ts = now_ms();
    cJSON *evt = cJSON_CreateObject();
    if (evt) {
        cJSON_AddNumberToObject(evt, "ts", (double)ts);
        web_server_ws_broadcast_event("scan_started", evt);
    }

    err = esp_timer_start_once(s_scan_timer, CAN_SCAN_WINDOW_US);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "esp_timer_start_once failed: %s", esp_err_to_name(err));
        xSemaphoreTake(lock, portMAX_DELAY);
        s_scan_in_progress = false;
        xSemaphoreGive(lock);
        if (started) {
            *started = false;
        }
        return err;
    }

    if (started) {
        *started = true;
    }
    return ESP_OK;
}

#else

esp_err_t can_master_init(void)
{
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t can_master_send_raw(uint32_t cob_id, const void *payload, uint8_t len)
{
    (void)cob_id;
    (void)payload;
    (void)len;
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t can_master_send_test_toggle(bool enable)
{
    (void)enable;
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t can_master_request_scan(bool *started)
{
    if (started) {
        *started = false;
    }
    return ESP_ERR_NOT_SUPPORTED;
}

#endif