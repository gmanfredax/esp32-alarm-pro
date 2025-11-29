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
    uint64_t last_online_ms;
    uint32_t last_inputs;
    uint8_t last_state;
    uint8_t change_counter;
    uint32_t outputs_bitmap;
    uint8_t outputs_flags;
    uint8_t outputs_pwm;
    bool outputs_valid;
    bool inputs_valid;
    uint32_t heartbeat_count;
    uint32_t info_count;
    uint32_t command_count;
    uint32_t command_errors;
    uint32_t offline_events;
} can_master_node_t;

static const char *TAG = "can_master";

static TaskHandle_t s_rx_task = NULL;
static bool s_driver_started = false;
static SemaphoreHandle_t s_state_lock = NULL;
static can_master_node_t s_nodes[CAN_MAX_NODE_ID + 1];

typedef struct {
    uint64_t last_activity_ms;
    uint32_t packets_sent;
    uint32_t packets_received;
    uint32_t packets_lost;
    uint32_t tx_errors;
    uint32_t rx_errors;
    uint32_t offline_events;
} can_master_bus_stats_t;

static can_master_bus_stats_t s_bus_stats = {0};

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
static void can_master_handle_scan_response(const can_proto_scan_t *scan);
static void can_master_check_timeouts(void);
static void can_master_notify_online(uint8_t node_id, bool is_new, uint64_t now_ms);
static void can_master_notify_offline(uint8_t node_id, uint64_t now_ms);
static void can_master_notify_io_state(uint8_t node_id,
                                       uint32_t inputs_bitmap,
                                       bool inputs_valid,
                                       uint8_t change_counter,
                                       uint8_t node_state_flags,
                                       uint32_t outputs_bitmap,
                                       bool outputs_valid,
                                       uint8_t outputs_flags,
                                       uint8_t outputs_pwm,
                                       uint64_t timestamp_ms);
static void can_scan_note_new_node(void);
static esp_err_t can_master_driver_start_internal(void);
static void scan_timer_cb(void *arg);
static twai_timing_config_t can_timing_config(void);
static void can_master_handle_addr_request(const can_proto_addr_request_t *req);
static void can_master_handle_parsed(const can_proto_parsed_frame_t *parsed);
static bool can_master_convert_to_frame(const twai_message_t *msg, can_proto_frame_t *frame);
static bool can_master_convert_to_twai(const can_proto_frame_t *frame, twai_message_t *msg);
static esp_err_t can_master_get_bus_telemetry_locked(can_master_bus_telemetry_t *out);
static esp_err_t can_master_get_node_telemetry_locked(uint8_t node_id, can_master_node_telemetry_t *out);
static void can_master_handle_ext_heartbeat(uint8_t node_id, const can_proto_ext_heartbeat_t *payload);
static void can_master_handle_zone_event(uint8_t node_id, const can_proto_zone_event_t *payload);

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
    memset(&s_bus_stats, 0, sizeof(s_bus_stats));
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

static void can_master_notify_io_state(uint8_t node_id,
                                       uint32_t inputs_bitmap,
                                       bool inputs_valid,
                                       uint8_t change_counter,
                                       uint8_t node_state_flags,
                                       uint32_t outputs_bitmap,
                                       bool outputs_valid,
                                       uint8_t outputs_flags,
                                       uint8_t outputs_pwm,
                                       uint64_t timestamp_ms)
{
    cJSON *evt = cJSON_CreateObject();
    if (!evt) {
        return;
    }
    cJSON_AddNumberToObject(evt, "node_id", node_id);
    cJSON_AddNumberToObject(evt, "ts_ms", (double)timestamp_ms);
    cJSON_AddBoolToObject(evt, "inputs_known", inputs_valid);
    if (inputs_valid) {
        cJSON_AddNumberToObject(evt, "inputs_bitmap", (double)inputs_bitmap);
        cJSON_AddNumberToObject(evt, "change_counter", change_counter);
        cJSON_AddNumberToObject(evt, "node_state_flags", node_state_flags);
    }
    cJSON_AddBoolToObject(evt, "outputs_known", outputs_valid);
    if (outputs_valid) {
        cJSON_AddNumberToObject(evt, "outputs_bitmap", (double)outputs_bitmap);
        cJSON_AddNumberToObject(evt, "outputs_flags", outputs_flags);
        cJSON_AddNumberToObject(evt, "outputs_pwm", outputs_pwm);
    }
    web_server_ws_broadcast_event("node_io_state", evt);
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
            ++node->offline_events;
            offline[offline_count++] = (uint8_t)node_id;
        }
    }
    xSemaphoreGive(lock);

    for (size_t i = 0; i < offline_count; ++i) {
        uint8_t node_id = offline[i];
        if (roster_mark_offline(node_id, now) == ESP_OK) {
            can_master_notify_offline(node_id, now);
            lock = state_lock_get();
            if (lock) {
                xSemaphoreTake(lock, portMAX_DELAY);
                ++s_bus_stats.offline_events;
                xSemaphoreGive(lock);
            }
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
    bool notify_io = false;
    uint32_t outputs_bitmap = 0;
    uint8_t outputs_flags = 0;
    uint8_t outputs_pwm = 0;
    bool outputs_valid = false;

    SemaphoreHandle_t lock = state_lock_get();
    if (!lock) {
        return;
    }

    xSemaphoreTake(lock, portMAX_DELAY);
    can_master_node_t *node = &s_nodes[node_id];
    was_online = node->online;
    notify_io = (!node->inputs_valid) ||
                (node->last_inputs != payload->inputs_bitmap) ||
                (node->change_counter != payload->change_counter) ||
                (node->last_state != payload->node_state);
    node->used = true;
    node->online = true;
    node->last_seen_ms = now;
    node->last_online_ms = now;
    node->last_inputs = payload->inputs_bitmap;
    node->last_state = payload->node_state;
    node->change_counter = payload->change_counter;
    node->inputs_valid = true;
    outputs_bitmap = node->outputs_bitmap;
    outputs_flags = node->outputs_flags;
    outputs_pwm = node->outputs_pwm;
    outputs_valid = node->outputs_valid;
    ++node->heartbeat_count;
    xSemaphoreGive(lock);

    esp_err_t roster_err = roster_note_inputs(node_id,
                                              payload->inputs_bitmap,
                                              payload->change_counter,
                                              payload->node_state);
    if (roster_err != ESP_OK) {
        ESP_LOGW(TAG, "Unable to store inputs for node %u (err=%s)",
                 (unsigned)node_id,
                 esp_err_to_name(roster_err));
    }

    bool is_new = false;
    if (roster_mark_online(node_id, now, &is_new) == ESP_OK) {
        if (is_new) {
            can_scan_note_new_node();
        }
        if (!was_online || is_new) {
            can_master_notify_online(node_id, is_new, now);
        }
    }

    if (notify_io) {
        can_master_notify_io_state(node_id,
                                   payload->inputs_bitmap,
                                   true,
                                   payload->change_counter,
                                   payload->node_state,
                                   outputs_bitmap,
                                   outputs_valid,
                                   outputs_flags,
                                   outputs_pwm,
                                   now);
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
        node->last_online_ms = now;
        ++node->info_count;
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

static void can_master_handle_scan_response(const can_proto_scan_t *scan)
{
    if (!scan || scan->msg_type != CAN_PROTO_MSG_SCAN_RESPONSE) {
        return;
    }
    ESP_LOGI(TAG, "Received CAN scan response frame");
}

static void can_master_handle_addr_request(const can_proto_addr_request_t *req)
{
    if (!req || req->protocol != CAN_PROTO_PROTOCOL_VERSION) {
        if (req) {
            ESP_LOGW(TAG, "Ignoring address request with protocol %u", (unsigned)req->protocol);
        }
        return;
    }

    uint8_t node_id = 0;
    bool is_new = false;
    esp_err_t err = roster_assign_node_id_from_uid(req->uid,
                                                   CAN_PROTO_UID_LENGTH,
                                                   &node_id,
                                                   &is_new);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to allocate node id for request (err=%s)", esp_err_to_name(err));
        return;
    }

    can_proto_addr_assign_t payload = {
        .node_id = node_id,
    };
    memcpy(payload.uid, req->uid, sizeof(payload.uid));

    can_proto_frame_t frame = {0};
    if (!can_proto_build_addr_assign(node_id, &payload, &frame)) {
        ESP_LOGW(TAG, "Failed to build address assign frame");
        return;
    }

    err = can_master_send_raw(frame.cob_id, frame.data, frame.dlc);
    if (err != ESP_OK) {
        ESP_LOGW(TAG,
                 "Failed to reply to address request for UID %02X:%02X:%02X:%02X:%02X:%02X:%02X",
                 req->uid[0],
                 req->uid[1],
                 req->uid[2],
                 req->uid[3],
                 req->uid[4],
                 req->uid[5],
                 req->uid[6]);
        return;
    }

    SemaphoreHandle_t lock = state_lock_get();
    if (lock && node_id > 0 && node_id <= CAN_MAX_NODE_ID) {
        xSemaphoreTake(lock, portMAX_DELAY);
        can_master_node_t *node = &s_nodes[node_id];
        node->used = true;
        node->online = false;
        node->last_seen_ms = now_ms();
        node->inputs_valid = false;
        node->outputs_valid = false;
        node->outputs_bitmap = 0;
        node->outputs_flags = 0;
        node->outputs_pwm = 0;
        node->last_inputs = 0;
        node->last_state = 0;
        node->change_counter = 0;
        xSemaphoreGive(lock);
    }

    if (is_new) {
        cJSON *evt = cJSON_CreateObject();
        if (evt) {
            cJSON_AddNumberToObject(evt, "node_id", node_id);
            cJSON_AddBoolToObject(evt, "allocated", true);
            web_server_ws_broadcast_event("node_id_assigned", evt);
        }
    }
}

static void can_master_handle_ext_heartbeat(uint8_t node_id, const can_proto_ext_heartbeat_t *payload)
{
    if (!payload || node_id == 0 || node_id > CAN_MAX_NODE_ID) {
        return;
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
        node->last_online_ms = now;
        xSemaphoreGive(lock);
    }

    bool roster_new = false;
    if (roster_mark_online(node_id, now, &roster_new) == ESP_OK) {
        if (!was_online || roster_new) {
            can_master_notify_online(node_id, roster_new, now);
        }
    }

    cJSON *evt = cJSON_CreateObject();
    if (!evt) {
        return;
    }
    cJSON_AddNumberToObject(evt, "node_id", node_id);
    cJSON_AddNumberToObject(evt, "alarm_bitmap", payload->alarm_bitmap);
    cJSON_AddNumberToObject(evt, "short_bitmap", payload->short_bitmap);
    cJSON_AddNumberToObject(evt, "open_bitmap", payload->open_bitmap);
    cJSON_AddNumberToObject(evt, "tamper_bitmap", payload->tamper_bitmap);
    cJSON_AddNumberToObject(evt, "vdda_100mv", payload->vdda_100mv);
    cJSON_AddNumberToObject(evt, "vbias_10mv", payload->vbias_10mv);
    cJSON_AddNumberToObject(evt, "temperature_c_plus40", payload->temperature_c_plus40);
    cJSON_AddNumberToObject(evt, "fw_nibbles", payload->fw_nibbles);
    web_server_ws_broadcast_event("node_ext_heartbeat", evt);
}

static void can_master_handle_zone_event(uint8_t node_id, const can_proto_zone_event_t *payload)
{
    if (!payload || node_id == 0 || node_id > CAN_MAX_NODE_ID) {
        return;
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
        node->last_online_ms = now;
        xSemaphoreGive(lock);
    }

    bool roster_new = false;
    if (roster_mark_online(node_id, now, &roster_new) == ESP_OK) {
        if (!was_online || roster_new) {
            can_master_notify_online(node_id, roster_new, now);
        }
    }

    cJSON *evt = cJSON_CreateObject();
    if (!evt) {
        return;
    }
    cJSON_AddNumberToObject(evt, "node_id", node_id);
    cJSON_AddNumberToObject(evt, "zone_id", payload->zone_id);
    cJSON_AddNumberToObject(evt, "seq", payload->seq);
    cJSON_AddNumberToObject(evt, "state_bits", payload->state_bits);
    cJSON_AddBoolToObject(evt, "present", (payload->state_bits & CAN_PROTO_ZONE_EVENT_STATE_PRESENT) != 0);
    cJSON_AddBoolToObject(evt, "contact_no", (payload->state_bits & CAN_PROTO_ZONE_EVENT_STATE_CONTACT_NO) != 0);
    cJSON_AddBoolToObject(evt, "alarm", (payload->state_bits & CAN_PROTO_ZONE_EVENT_STATE_ALARM) != 0);
    cJSON_AddBoolToObject(evt, "short", (payload->state_bits & CAN_PROTO_ZONE_EVENT_STATE_SHORT) != 0);
    cJSON_AddBoolToObject(evt, "open", (payload->state_bits & CAN_PROTO_ZONE_EVENT_STATE_OPEN) != 0);
    cJSON_AddBoolToObject(evt, "tamper", (payload->state_bits & CAN_PROTO_ZONE_EVENT_STATE_TAMPER) != 0);
    cJSON_AddNumberToObject(evt, "raw_adc", payload->raw_adc);
    cJSON_AddNumberToObject(evt, "rloop_ohm_div100", payload->rloop_ohm_div100);
    cJSON_AddNumberToObject(evt, "vbias_10mv", payload->vbias_10mv);
    web_server_ws_broadcast_event("node_zone_event", evt);
}

static void can_master_handle_parsed(const can_proto_parsed_frame_t *parsed)
{
    if (!parsed) {
        return;
    }

    switch (parsed->kind) {
    case CAN_PROTO_FRAME_HEARTBEAT:
    case CAN_PROTO_FRAME_IO_REPORT:
        can_master_handle_heartbeat(parsed->node_id, &parsed->payload.heartbeat);
        break;
    case CAN_PROTO_FRAME_INFO:
        can_master_handle_info(parsed->node_id, &parsed->payload.info);
        break;
    case CAN_PROTO_FRAME_EXT_HEARTBEAT:
        can_master_handle_ext_heartbeat(parsed->node_id, &parsed->payload.ext_heartbeat);
        break;
    case CAN_PROTO_FRAME_EXT_ZONE_EVENT:
        can_master_handle_zone_event(parsed->node_id, &parsed->payload.zone_event);
        break;
    case CAN_PROTO_FRAME_SCAN_RESPONSE:
        can_master_handle_scan_response(&parsed->payload.scan);
        break;
    case CAN_PROTO_FRAME_ADDR_REQUEST:
        can_master_handle_addr_request(&parsed->payload.addr_request);
        break;
    case CAN_PROTO_FRAME_TEST_TOGGLE:
    case CAN_PROTO_FRAME_OUTPUT_COMMAND:
    case CAN_PROTO_FRAME_IDENTIFY_CMD:
    case CAN_PROTO_FRAME_SCAN_REQUEST:
    case CAN_PROTO_FRAME_ADDR_ASSIGN:
    case CAN_PROTO_FRAME_UNKNOWN:
    default:
        break;
    }
}

static void can_master_handle_frame(const twai_message_t *msg)
{
    if (!msg) {
        return;
    }

    can_proto_frame_t frame = {0};
    if (!can_master_convert_to_frame(msg, &frame)) {
        SemaphoreHandle_t lock = state_lock_get();
        if (lock) {
            xSemaphoreTake(lock, portMAX_DELAY);
            ++s_bus_stats.rx_errors;
            ++s_bus_stats.packets_lost;
            xSemaphoreGive(lock);
        }
        return;
    }

    uint64_t now = now_ms();
    SemaphoreHandle_t lock = state_lock_get();
    if (lock) {
        xSemaphoreTake(lock, portMAX_DELAY);
        s_bus_stats.last_activity_ms = now;
        xSemaphoreGive(lock);
    }

    can_proto_parsed_frame_t parsed = {0};
    if (can_proto_parse(&frame, &parsed)) {
        lock = state_lock_get();
        if (lock) {
            xSemaphoreTake(lock, portMAX_DELAY);
            ++s_bus_stats.packets_received;
            xSemaphoreGive(lock);
        }
        can_master_handle_parsed(&parsed);
    } else {
        lock = state_lock_get();
        if (lock) {
            xSemaphoreTake(lock, portMAX_DELAY);
            ++s_bus_stats.rx_errors;
            ++s_bus_stats.packets_lost;
            xSemaphoreGive(lock);
        }
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

static bool can_master_convert_to_frame(const twai_message_t *msg, can_proto_frame_t *frame)
{
    if (!msg || msg->extd || msg->rtr || msg->data_length_code > TWAI_FRAME_MAX_DLC || !frame) {
        return false;
    }
    frame->cob_id = msg->identifier & 0x7FFu;
    frame->dlc = msg->data_length_code;
    memset(frame->data, 0, sizeof(frame->data));
    if (frame->dlc) {
        memcpy(frame->data, msg->data, frame->dlc);
    }
    return true;
}

static bool can_master_convert_to_twai(const can_proto_frame_t *frame, twai_message_t *msg)
{
    if (!frame || !msg || frame->dlc > TWAI_FRAME_MAX_DLC) {
        return false;
    }

    *msg = (twai_message_t){
        .identifier = frame->cob_id & 0x7FFu,
        .extd = 0,
        .rtr = 0,
        .ss = 0,
        .self = 0,
        .dlc_non_comp = 0,
        .data_length_code = frame->dlc,
    };
    memset(msg->data, 0, sizeof(msg->data));
    if (frame->dlc) {
        memcpy(msg->data, frame->data, frame->dlc);
    }
    return true;
}

esp_err_t can_master_send_raw(uint32_t cob_id, const void *payload, uint8_t len)
{
    if (len > TWAI_FRAME_MAX_DLC) {
        len = TWAI_FRAME_MAX_DLC;
    }

    can_proto_frame_t frame = {
        .cob_id = cob_id & 0x7FFu,
        .dlc = len,
    };
    memset(frame.data, 0, sizeof(frame.data));
    if (payload && len > 0) {
        memcpy(frame.data, payload, len);
    }

    twai_message_t msg = {0};
    if (!can_master_convert_to_twai(&frame, &msg)) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = can_master_init();
    if (err != ESP_OK) {
        return err;
    }

    err = twai_transmit(&msg, pdMS_TO_TICKS(50));
    if (err == ESP_ERR_INVALID_STATE) {
        ESP_LOGW(TAG,
                 "twai_transmit 0x%03" PRIx32 " failed (invalid state), attempting recovery",
                 cob_id & 0x7FFu);
        esp_err_t restart_err = twai_start();
        if (restart_err != ESP_OK) {
            (void)twai_stop();
            (void)twai_driver_uninstall();
            s_driver_started = false;
            if (can_master_driver_start_internal() == ESP_OK) {
                err = twai_transmit(&msg, pdMS_TO_TICKS(50));
            } else {
                err = restart_err;
            }
        } else {
            err = twai_transmit(&msg, pdMS_TO_TICKS(50));
            if (err == ESP_ERR_INVALID_STATE) {
                (void)twai_stop();
                (void)twai_driver_uninstall();
                s_driver_started = false;
                if (can_master_driver_start_internal() == ESP_OK) {
                    err = twai_transmit(&msg, pdMS_TO_TICKS(50));
                }
            }
        }
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "twai_transmit 0x%03" PRIx32 " failed: %s",
                 cob_id & 0x7FFu,
                 esp_err_to_name(err));
        SemaphoreHandle_t lock = state_lock_get();
        if (lock) {
            xSemaphoreTake(lock, portMAX_DELAY);
            ++s_bus_stats.tx_errors;
            ++s_bus_stats.packets_lost;
            xSemaphoreGive(lock);
        }
    }

    if (err == ESP_OK) {
        SemaphoreHandle_t lock = state_lock_get();
        if (lock) {
            xSemaphoreTake(lock, portMAX_DELAY);
            ++s_bus_stats.packets_sent;
            s_bus_stats.last_activity_ms = now_ms();
            xSemaphoreGive(lock);
        }
    }
    return err;
}

esp_err_t can_master_send_test_toggle(bool enable)
{
    can_proto_frame_t frame = {0};
    if (!can_proto_build_test_toggle(enable, &frame)) {
        return ESP_ERR_INVALID_ARG;
    }
    return can_master_send_raw(frame.cob_id, frame.data, frame.dlc);
}

esp_err_t can_master_assign_address(uint8_t node_id, const uint8_t uid[CAN_PROTO_UID_LENGTH])
{
    if (!uid) {
        return ESP_ERR_INVALID_ARG;
    }

    can_proto_addr_assign_t payload = {
        .node_id = node_id,
    };
    memcpy(payload.uid, uid, sizeof(payload.uid));
    can_proto_frame_t frame = {0};
    if (!can_proto_build_addr_assign(node_id, &payload, &frame)) {
        return ESP_ERR_INVALID_ARG;
    }
    return can_master_send_raw(frame.cob_id, frame.data, frame.dlc);
}

esp_err_t can_master_set_node_outputs(uint8_t node_id,
                                      uint32_t outputs_bitmap,
                                      uint8_t flags,
                                      uint8_t pwm_level)
{
    if (node_id == 0 || node_id > CAN_MAX_NODE_ID) {
        return ESP_ERR_INVALID_ARG;
    }

    can_proto_output_cmd_t payload = {
        .msg_type = CAN_PROTO_MSG_OUTPUT_COMMAND,
        .flags = flags,
        .outputs_bitmap = outputs_bitmap,
        .pwm_level = pwm_level,
        .reserved = 0,
    };

    can_proto_frame_t frame = {0};
    if (!can_proto_build_output_cmd(node_id, &payload, &frame)) {
        return ESP_ERR_INVALID_ARG;
    }

    SemaphoreHandle_t lock = state_lock_get();
    if (lock) {
        xSemaphoreTake(lock, portMAX_DELAY);
        can_master_node_t *node = &s_nodes[node_id];
        node->used = true;
        ++node->command_count;
        xSemaphoreGive(lock);
    }

    esp_err_t err = can_master_send_raw(frame.cob_id, frame.data, frame.dlc);
    if (err != ESP_OK) {
        if (lock) {
            xSemaphoreTake(lock, portMAX_DELAY);
            can_master_node_t *node = &s_nodes[node_id];
            ++node->command_errors;
            xSemaphoreGive(lock);
        }
        return err;
    }

    uint32_t inputs_bitmap = 0;
    uint8_t change_counter = 0;
    uint8_t node_state_flags = 0;
    bool inputs_valid = false;
    uint64_t timestamp = now_ms();

    lock = state_lock_get();
    if (lock) {
        xSemaphoreTake(lock, portMAX_DELAY);
        can_master_node_t *node = &s_nodes[node_id];
        node->used = true;
        node->outputs_bitmap = outputs_bitmap;
        node->outputs_flags = flags;
        node->outputs_pwm = pwm_level;
        node->outputs_valid = true;
        inputs_bitmap = node->last_inputs;
        change_counter = node->change_counter;
        node_state_flags = node->last_state;
        inputs_valid = node->inputs_valid;
        xSemaphoreGive(lock);
    }

    esp_err_t roster_err = roster_note_outputs(node_id,
                                               outputs_bitmap,
                                               flags,
                                               pwm_level,
                                               true);
    if (roster_err != ESP_OK && roster_err != ESP_ERR_NOT_FOUND) {
        ESP_LOGW(TAG, "Unable to store outputs for node %u (err=%s)",
                 (unsigned)node_id,
                 esp_err_to_name(roster_err));
    }

    can_master_notify_io_state(node_id,
                               inputs_bitmap,
                               inputs_valid,
                               change_counter,
                               node_state_flags,
                               outputs_bitmap,
                               true,
                               flags,
                               pwm_level,
                               timestamp);

    return ESP_OK;
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

    can_proto_frame_t frame = {0};
    if (!can_proto_build_scan_request(&frame)) {
        xSemaphoreTake(lock, portMAX_DELAY);
        s_scan_in_progress = false;
        xSemaphoreGive(lock);
        if (started) {
            *started = false;
        }
        return ESP_ERR_INVALID_ARG;
    }

    err = can_master_send_raw(frame.cob_id, frame.data, frame.dlc);
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

static esp_err_t can_master_get_bus_telemetry_locked(can_master_bus_telemetry_t *out)
{
    if (!out) {
        return ESP_ERR_INVALID_ARG;
    }

    uint32_t known = 0;
    uint32_t online = 0;
    for (uint32_t i = 1; i <= CAN_MAX_NODE_ID; ++i) {
        const can_master_node_t *node = &s_nodes[i];
        if (node->used) {
            ++known;
            if (node->online) {
                ++online;
            }
        }
    }

    *out = (can_master_bus_telemetry_t){
        .timestamp_ms = now_ms(),
        .last_activity_ms = s_bus_stats.last_activity_ms,
        .packets_sent = s_bus_stats.packets_sent,
        .packets_received = s_bus_stats.packets_received,
        .packets_lost = s_bus_stats.packets_lost,
        .tx_errors = s_bus_stats.tx_errors,
        .rx_errors = s_bus_stats.rx_errors,
        .offline_events = s_bus_stats.offline_events,
        .nodes_known = known,
        .nodes_online = online,
        .driver_started = s_driver_started,
    };
    return ESP_OK;
}

static esp_err_t can_master_get_node_telemetry_locked(uint8_t node_id,
                                                      can_master_node_telemetry_t *out)
{
    if (!out || node_id == 0 || node_id > CAN_MAX_NODE_ID) {
        return ESP_ERR_INVALID_ARG;
    }

    const can_master_node_t *node = &s_nodes[node_id];
    *out = (can_master_node_telemetry_t){
        .node_id = node_id,
        .exists = node->used,
        .online = node->online,
        .last_seen_ms = node->last_seen_ms,
        .last_online_ms = node->last_online_ms,
        .heartbeat_count = node->heartbeat_count,
        .info_count = node->info_count,
        .command_count = node->command_count,
        .command_errors = node->command_errors,
        .offline_events = node->offline_events,
    };
    return ESP_OK;
}

esp_err_t can_master_get_bus_telemetry(can_master_bus_telemetry_t *out)
{
    SemaphoreHandle_t lock = state_lock_get();
    if (!lock) {
        return ESP_ERR_NO_MEM;
    }

    esp_err_t res;
    xSemaphoreTake(lock, portMAX_DELAY);
    res = can_master_get_bus_telemetry_locked(out);
    xSemaphoreGive(lock);
    return res;
}

esp_err_t can_master_get_node_telemetry(uint8_t node_id, can_master_node_telemetry_t *out)
{
    SemaphoreHandle_t lock = state_lock_get();
    if (!lock) {
        return ESP_ERR_NO_MEM;
    }

    esp_err_t res;
    xSemaphoreTake(lock, portMAX_DELAY);
    res = can_master_get_node_telemetry_locked(node_id, out);
    xSemaphoreGive(lock);
    return res;
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

esp_err_t can_master_set_node_outputs(uint8_t node_id,
                                      uint32_t outputs_bitmap,
                                      uint8_t flags,
                                      uint8_t pwm_level)
{
    (void)node_id;
    (void)outputs_bitmap;
    (void)flags;
    (void)pwm_level;
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t can_master_get_bus_telemetry(can_master_bus_telemetry_t *out)
{
    (void)out;
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t can_master_get_node_telemetry(uint8_t node_id, can_master_node_telemetry_t *out)
{
    (void)node_id;
    (void)out;
    return ESP_ERR_NOT_SUPPORTED;
}

#endif