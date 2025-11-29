#include "expansion_node.h"

#include "pins.h"
#include "can_bus_protocol.h"

#include <string.h>
#include <math.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "driver/gpio.h"
#include "driver/twai.h"

#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"

#include "nvs_flash.h"
#include "nvs.h"

#include "esp_adc/adc_oneshot.h"
#include "esp_adc/adc_cali.h"
#include "esp_adc/adc_cali_scheme.h"
#include "esp_check.h"

#include "esp_mac.h"

#define TAG "exp_node"

// -----------------------------------------------------------------------------
// Config generale nodo
// -----------------------------------------------------------------------------

#define EXP_NODE_ZONE_COUNT    ZONE_INPUT_COUNT
#define EXP_NODE_OUTPUT_COUNT  EXP_OUTPUT_COUNT

// Riutilizziamo un modello esistente (10 ingressi, 2 uscite) anche se qui ne usiamo 4
#define EXP_NODE_MODEL_ID      CAN_PROTO_MODEL_IO10R2_V1
#define EXP_NODE_FW_VERSION    0x0001u   // v0.0.1

#define EXP_NODE_NVS_NAMESPACE "exp_can"
#define EXP_NODE_NVS_KEY_ID    "node_id"

// Timing
#define EXP_ADDR_REQ_PERIOD_MS   5000ULL  // ogni 5s se non abbiamo node_id
#define EXP_HEARTBEAT_PERIOD_MS  1000ULL  // ext heartbeat ogni 1s
#define EXP_SAMPLE_PERIOD_MS      100ULL  // campionamento zone ogni 100ms

#define EXP_TASK_STACK_RX     (4096)
#define EXP_TASK_STACK_LOGIC  (4096)
#define EXP_TASK_PRIO_RX      (tskIDLE_PRIORITY + 4)
#define EXP_TASK_PRIO_LOGIC   (tskIDLE_PRIORITY + 3)

// ADC
#define EXP_ADC_MAX_UNITS      2
#define ADC_MAX_RAW            4095.0f
#define ADC_SAMPLES_PER_CH     8

// -----------------------------------------------------------------------------
// Tipi per EOL e stato zona (versione "compatta" del codice della centrale)
// -----------------------------------------------------------------------------

typedef enum {
    ZONE_INPUT_STATE_NORMAL = 0,
    ZONE_INPUT_STATE_ALARM,
    ZONE_INPUT_STATE_TAMPER,
    ZONE_INPUT_STATE_MASKING,
    ZONE_INPUT_STATE_FAULT,
} zone_input_state_t;

typedef struct {
    float eol1_fault_max;
    float eol1_alarm_min;
    float eol2_tamper_low_max;
    float eol2_normal_max;
    float eol2_alarm_max;
    float eol3_tamper_low_max;
    float eol3_normal_max;
    float eol3_alarm_max;
} zone_eol_thresholds_t;

// Mappiamo direttamente sui valori del protocollo CAN
typedef enum {
    ZONE_EOL_MODE_1 = CAN_ZONE_MEASURE_MODE_EOL,
    ZONE_EOL_MODE_2 = CAN_ZONE_MEASURE_MODE_2EOL,
    ZONE_EOL_MODE_3 = CAN_ZONE_MEASURE_MODE_3EOL,
} zone_eol_mode_t;

typedef struct {
    uint32_t          raw_mv;
    float             ratio;
    zone_input_state_t state;
} zone_sample_t;

typedef struct {
    bool            enabled;
    zone_eol_mode_t eol_mode;
    bool            contact_is_no;  // true = contatto NO, false = NC
    uint16_t        r_normal_ohm;
    uint16_t        r_alarm_ohm;
} zone_config_t;

typedef struct {
    gpio_num_t   gpio;
    adc_unit_t   unit;
    adc_channel_t channel;
    bool         configured;
} zone_adc_entry_t;

// -----------------------------------------------------------------------------
// Stato globale nodo
// -----------------------------------------------------------------------------

static uint8_t              s_node_id = 0;
static bool                 s_node_id_valid = false;
static uint8_t              s_uid[CAN_PROTO_UID_LENGTH] = {0};

static SemaphoreHandle_t    s_state_mutex = NULL;

// CAN
static bool                 s_can_started = false;

// ADC
static adc_oneshot_unit_handle_t s_adc_units[EXP_ADC_MAX_UNITS] = {0};
static bool                      s_adc_unit_ready[EXP_ADC_MAX_UNITS] = {0};
static adc_cali_handle_t         s_adc_cali[EXP_ADC_MAX_UNITS] = {0};
static bool                      s_adc_cali_ready[EXP_ADC_MAX_UNITS] = {0};

static zone_adc_entry_t          s_zone_entries[EXP_NODE_ZONE_COUNT];

// Config e stato zone
static zone_config_t             s_zone_cfg[EXP_NODE_ZONE_COUNT];
static zone_sample_t             s_zone_samples[EXP_NODE_ZONE_COUNT];
static uint8_t                   s_zone_seq[EXP_NODE_ZONE_COUNT] = {0};
static uint8_t                   s_zone_last_state_bits[EXP_NODE_ZONE_COUNT] = {0};

// Soglie EOL iniziali (copiate dalla centrale)
static zone_eol_thresholds_t     s_eol_thresholds = {
    .eol1_fault_max      = 0.08f,
    .eol1_alarm_min      = 0.80f,
    .eol2_tamper_low_max = 0.10f,
    .eol2_normal_max     = 0.50f,
    .eol2_alarm_max      = 0.80f,
    .eol3_tamper_low_max = 0.07f,
    .eol3_normal_max     = 0.38f,
    .eol3_alarm_max      = 0.72f,
};

// LED / stato logico
static bool     s_identify_enabled = false;
static zone_eol_mode_t s_global_eol_mode = ZONE_EOL_MODE_2;

// Timing (ms)
static uint64_t s_last_addr_req_ms  = 0;
static uint64_t s_last_hb_ms        = 0;
static uint64_t s_last_sample_ms    = 0;
static uint8_t  s_change_counter    = 0;
static uint32_t s_outputs_bitmap    = 0;

// -----------------------------------------------------------------------------
// Helper tempo
// -----------------------------------------------------------------------------

static inline uint64_t now_ms(void)
{
    return (uint64_t)(esp_timer_get_time() / 1000ULL);
}

// -----------------------------------------------------------------------------
// Helper NVS: salvataggio node_id
// -----------------------------------------------------------------------------

static esp_err_t nvs_load_node_id(uint8_t *out_id)
{
    if (!out_id) return ESP_ERR_INVALID_ARG;

    nvs_handle_t h;
    esp_err_t err = nvs_open(EXP_NODE_NVS_NAMESPACE, NVS_READONLY, &h);
    if (err != ESP_OK) return err;

    uint8_t value = 0;
    err = nvs_get_u8(h, EXP_NODE_NVS_KEY_ID, &value);
    nvs_close(h);
    if (err != ESP_OK) return err;

    if (value == 0 || value > CAN_PROTO_MAX_NODE_ID) {
        return ESP_ERR_INVALID_STATE;
    }
    *out_id = value;
    return ESP_OK;
}

static esp_err_t nvs_save_node_id(uint8_t node_id)
{
    if (node_id == 0 || node_id > CAN_PROTO_MAX_NODE_ID) {
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t h;
    esp_err_t err = nvs_open(EXP_NODE_NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;

    err = nvs_set_u8(h, EXP_NODE_NVS_KEY_ID, node_id);
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return err;
}

// -----------------------------------------------------------------------------
// UID: derivato dal MAC ESP32 (LSB-first) + "type"
// -----------------------------------------------------------------------------

static void fill_uid_from_mac(uint8_t uid[CAN_PROTO_UID_LENGTH])
{
    uint8_t mac[6] = {0};
    esp_read_mac(mac, ESP_MAC_WIFI_STA); // usa MAC Wi-Fi

    // LSB-first, come richiesto dal protocollo
    for (int i = 0; i < 6 && i < CAN_PROTO_UID_LENGTH; ++i) {
        uid[i] = mac[i];
    }
    if (CAN_PROTO_UID_LENGTH > 6) {
        uid[6] = 0xE1; // "tipo" scheda (ESP32 expansion board)
    }
}

// -----------------------------------------------------------------------------
// ADC / zone analogiche
// -----------------------------------------------------------------------------

static const gpio_num_t s_zone_gpio_map[EXP_NODE_ZONE_COUNT] = {
    ZONE_INPUT_GPIO_1,
    ZONE_INPUT_GPIO_2,
    ZONE_INPUT_GPIO_3,
    ZONE_INPUT_GPIO_4,
    ZONE_INPUT_GPIO_5,
    ZONE_INPUT_GPIO_6,
    ZONE_INPUT_GPIO_7,
    ZONE_INPUT_GPIO_8,
    ZONE_INPUT_GPIO_9,
    ZONE_INPUT_GPIO_10,
};

static esp_err_t ensure_adc_unit(adc_unit_t unit)
{
    if (unit >= EXP_ADC_MAX_UNITS) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_adc_unit_ready[unit]) {
        return ESP_OK;
    }

    adc_oneshot_unit_init_cfg_t cfg = {
        .unit_id = unit,
        .ulp_mode = ADC_ULP_MODE_DISABLE,
    };
    ESP_RETURN_ON_ERROR(adc_oneshot_new_unit(&cfg, &s_adc_units[unit]), TAG, "adc_oneshot_new_unit");
    s_adc_unit_ready[unit] = true;

    adc_cali_line_fitting_config_t cali_cfg = {
        .unit_id  = unit,
        .atten    = ADC_ATTEN_DB_0,
        .bitwidth = ADC_BITWIDTH_DEFAULT,
    };

    if (adc_cali_create_scheme_line_fitting(&cali_cfg, &s_adc_cali[unit]) == ESP_OK) {
        s_adc_cali_ready[unit] = true;
        ESP_LOGI(TAG, "Calibrazione ADC unit %d ok", unit);
    } else {
        s_adc_cali_ready[unit] = false;
        ESP_LOGW(TAG, "Calibrazione ADC unit %d fallita, uso fallback");
    }


    return ESP_OK;
}

static esp_err_t configure_adc_channel(zone_adc_entry_t *entry)
{
    if (!entry || entry->configured) {
        return ESP_OK;
    }
    ESP_RETURN_ON_ERROR(ensure_adc_unit(entry->unit), TAG, "ensure_adc_unit");

    adc_oneshot_chan_cfg_t chan_cfg = {
        .bitwidth = ADC_BITWIDTH_DEFAULT,
        .atten    = ADC_ATTEN_DB_0,
    };
    ESP_RETURN_ON_ERROR(
        adc_oneshot_config_channel(s_adc_units[entry->unit], entry->channel, &chan_cfg),
        TAG, "adc_oneshot_config_channel"
    );
    entry->configured = true;
    return ESP_OK;
}

static esp_err_t sample_raw_mv(const zone_adc_entry_t *entry, int *out_mv)
{
    if (!entry || !out_mv || !entry->configured) {
        return ESP_ERR_INVALID_STATE;
    }

    int sum_mv = 0;
    for (int i = 0; i < ADC_SAMPLES_PER_CH; ++i) {
        int raw = 0;
        esp_err_t err = adc_oneshot_read(s_adc_units[entry->unit], entry->channel, &raw);
        if (err != ESP_OK) {
            return err;
        }

        int mv = 0;
        if (s_adc_cali_ready[entry->unit] && s_adc_cali[entry->unit]) {
            if (adc_cali_raw_to_voltage(s_adc_cali[entry->unit], raw, &mv) != ESP_OK) {
                mv = (int)((raw / ADC_MAX_RAW) * 1100.0f);
            }
        } else {
            mv = (int)((raw / ADC_MAX_RAW) * 1100.0f);
        }
        sum_mv += mv;
    }

    *out_mv = sum_mv / ADC_SAMPLES_PER_CH;
    return ESP_OK;
}

static inline float clamp_ratio(float v)
{
    if (v < 0.0f) v = 0.0f;
    if (v > 1.0f) v = 1.0f;
    return v;
}

static bool ratio_invalid(float r)
{
    return isnan(r) || isinf(r) || r < 0.0f || r > 1.0f;
}

static zone_input_state_t classify_ratio(zone_eol_mode_t mode, float ratio)
{
    if (ratio_invalid(ratio)) {
        return ZONE_INPUT_STATE_FAULT;
    }
    const zone_eol_thresholds_t *thr = &s_eol_thresholds;

    switch (mode) {
    case ZONE_EOL_MODE_1:
        if (ratio < thr->eol1_fault_max) {
            return ZONE_INPUT_STATE_FAULT;
        }
        if (ratio > thr->eol1_alarm_min) {
            return ZONE_INPUT_STATE_ALARM;
        }
        return ZONE_INPUT_STATE_NORMAL;

    case ZONE_EOL_MODE_2:
        if (ratio < thr->eol2_tamper_low_max) {
            return ZONE_INPUT_STATE_TAMPER;
        }
        if (ratio <= thr->eol2_normal_max) {
            return ZONE_INPUT_STATE_NORMAL;
        }
        if (ratio <= thr->eol2_alarm_max) {
            return ZONE_INPUT_STATE_ALARM;
        }
        if (ratio <= 1.0f) {
            return ZONE_INPUT_STATE_TAMPER;
        }
        return ZONE_INPUT_STATE_FAULT;

    case ZONE_EOL_MODE_3:
    default:
        if (ratio < thr->eol3_tamper_low_max) {
            return ZONE_INPUT_STATE_TAMPER;
        }
        if (ratio <= thr->eol3_normal_max) {
            return ZONE_INPUT_STATE_NORMAL;
        }
        if (ratio <= thr->eol3_alarm_max) {
            return ZONE_INPUT_STATE_ALARM;
        }
        if (ratio <= 1.0f) {
            return ZONE_INPUT_STATE_MASKING;
        }
        return ZONE_INPUT_STATE_FAULT;
    }
}

static void zones_default_config(void)
{
    for (int i = 0; i < EXP_NODE_ZONE_COUNT; ++i) {
        s_zone_cfg[i].enabled       = true;
        s_zone_cfg[i].eol_mode      = ZONE_EOL_MODE_2; // default
        s_zone_cfg[i].contact_is_no = false;
        s_zone_cfg[i].r_normal_ohm  = 5600;  // placeholder
        s_zone_cfg[i].r_alarm_ohm   = 5600;  // placeholder
        s_zone_samples[i].raw_mv    = 0;
        s_zone_samples[i].ratio     = 0.0f;
        s_zone_samples[i].state     = ZONE_INPUT_STATE_FAULT;
        s_zone_seq[i]               = 0;
        s_zone_last_state_bits[i]   = 0;
    }
    s_global_eol_mode = ZONE_EOL_MODE_2;
}

static esp_err_t zones_adc_init(void)
{
    memset(s_zone_entries, 0, sizeof(s_zone_entries));

    for (int i = 0; i < EXP_NODE_ZONE_COUNT; ++i) {
        gpio_num_t g = s_zone_gpio_map[i];
        if (g == GPIO_NUM_NC) {
            s_zone_entries[i].configured = false;
            continue;
        }
        adc_unit_t unit = 0;
        adc_channel_t ch = 0;
        esp_err_t err = adc_oneshot_io_to_channel(g, &unit, &ch);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "GPIO %d non supporta ADC: %s", (int)g, esp_err_to_name(err));
            return err;
        }
        s_zone_entries[i].gpio = g;
        s_zone_entries[i].unit = unit;
        s_zone_entries[i].channel = ch;
        s_zone_entries[i].configured = false;

        ESP_RETURN_ON_ERROR(configure_adc_channel(&s_zone_entries[i]),
                            TAG, "config_channel zone %d", i);
    }

    return ESP_OK;
}

static esp_err_t zones_sample_all(void)
{
    for (int i = 0; i < EXP_NODE_ZONE_COUNT; ++i) {
        zone_adc_entry_t *entry = &s_zone_entries[i];
        zone_config_t    *cfg   = &s_zone_cfg[i];
        zone_sample_t    *smp   = &s_zone_samples[i];

        if (!cfg->enabled || !entry->configured) {
            smp->raw_mv = 0;
            smp->ratio  = 0.0f;
            smp->state  = ZONE_INPUT_STATE_FAULT;
            continue;
        }

        int mv = 0;
        esp_err_t err = sample_raw_mv(entry, &mv);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "Errore lettura zona %d: %s", i, esp_err_to_name(err));
            smp->raw_mv = 0;
            smp->ratio  = 0.0f;
            smp->state  = ZONE_INPUT_STATE_FAULT;
            continue;
        }

        smp->raw_mv = (mv < 0) ? 0 : (uint32_t)mv;
        float ratio = 0.0f;
        if (mv <= 0) {
            ratio = 0.0f;
        } else if (mv >= 1100) {
            ratio = 1.0f;
        } else {
            ratio = (float)mv / 1100.0f;
        }
        smp->ratio = ratio;
        smp->state = classify_ratio(cfg->eol_mode, ratio);
    }
    return ESP_OK;
}

// -----------------------------------------------------------------------------
// GPIO: uscite + LED di stato
// -----------------------------------------------------------------------------

static void hw_init_outputs_and_leds(void)
{
    // Uscite
    uint64_t out_mask = 0;
    out_mask |= (1ULL << EXP_OUTPUT_GPIO_1);
    out_mask |= (1ULL << EXP_OUTPUT_GPIO_2);
    out_mask |= (1ULL << EXP_OUTPUT_GPIO_3);
    out_mask |= (1ULL << EXP_OUTPUT_GPIO_4);

    gpio_config_t out_cfg = {
        .pin_bit_mask = out_mask,
        .mode         = GPIO_MODE_OUTPUT,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&out_cfg);

    // LED
    uint64_t led_mask = 0;
    led_mask |= (1ULL << EXP_LED_RUN_GPIO);
    led_mask |= (1ULL << EXP_LED_LINK_GPIO);
    led_mask |= (1ULL << EXP_LED_EOL_GPIO);
    led_mask |= (1ULL << EXP_LED_UPDATE_GPIO);

    gpio_config_t led_cfg = {
        .pin_bit_mask = led_mask,
        .mode         = GPIO_MODE_OUTPUT,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&led_cfg);

    gpio_set_level(EXP_LED_RUN_GPIO, 0);
    gpio_set_level(EXP_LED_LINK_GPIO, 0);
    gpio_set_level(EXP_LED_EOL_GPIO, 0);
    gpio_set_level(EXP_LED_UPDATE_GPIO, 0);
}

static void hw_set_outputs(uint32_t bitmap)
{
    // Solo primi 4 bit usati
    gpio_set_level(EXP_OUTPUT_GPIO_1, (bitmap & (1u << 0)) ? 1 : 0);
    gpio_set_level(EXP_OUTPUT_GPIO_2, (bitmap & (1u << 1)) ? 1 : 0);
    gpio_set_level(EXP_OUTPUT_GPIO_3, (bitmap & (1u << 2)) ? 1 : 0);
    gpio_set_level(EXP_OUTPUT_GPIO_4, (bitmap & (1u << 3)) ? 1 : 0);
}

static void hw_update_leds(uint64_t now)
{
    // LED RUN: lampeggio 1 Hz
    bool run_on = ((now / 500) % 2) ? true : false;
    gpio_set_level(EXP_LED_RUN_GPIO, run_on ? 1 : 0);

    // LED LINK: acceso se abbiamo node_id valido e CAN partito
    bool link_on = (s_node_id_valid && s_can_started);
    gpio_set_level(EXP_LED_LINK_GPIO, link_on ? 1 : 0);

    // LED EOL: breve logica: acceso se EOL=3, spento se 1, lampeggio lento se 2
    switch (s_global_eol_mode) {
    case ZONE_EOL_MODE_1:
        gpio_set_level(EXP_LED_EOL_GPIO, 0);
        break;
    case ZONE_EOL_MODE_2:
        gpio_set_level(EXP_LED_EOL_GPIO, ((now / 1000) % 2) ? 1 : 0);
        break;
    case ZONE_EOL_MODE_3:
    default:
        gpio_set_level(EXP_LED_EOL_GPIO, 1);
        break;
    }

    // LED UPDATE: per ora sempre spento (verrà usato in futuro per OTA)
    gpio_set_level(EXP_LED_UPDATE_GPIO, 0);

    // Identify: se attivo, facciamo lampeggiare tutti gli output come pattern
    if (s_identify_enabled) {
        bool on = ((now / 250) % 2) ? true : false;
        uint32_t bm = on ? 0x0Fu : 0x00u;
        hw_set_outputs(bm);
    }
}

// -----------------------------------------------------------------------------
// CAN helper
// -----------------------------------------------------------------------------

static esp_err_t can_start(void)
{
    if (s_can_started) {
        return ESP_OK;
    }

    twai_general_config_t g_config =
        TWAI_GENERAL_CONFIG_DEFAULT(CAN_TX_GPIO, CAN_RX_GPIO, TWAI_MODE_NORMAL);
    g_config.clkout_divider = 0;
    g_config.rx_queue_len   = 32;
    g_config.tx_queue_len   = 32;

    // bitrate 125k di default (puoi cambiare in TWAI_TIMING_CONFIG_250KBITS)
    twai_timing_config_t t_config = TWAI_TIMING_CONFIG_250KBITS();
    twai_filter_config_t f_config = TWAI_FILTER_CONFIG_ACCEPT_ALL();

    ESP_RETURN_ON_ERROR(twai_driver_install(&g_config, &t_config, &f_config),
                        TAG, "twai_driver_install");
    ESP_RETURN_ON_ERROR(twai_start(), TAG, "twai_start");

    s_can_started = true;
    ESP_LOGI(TAG, "CAN (TWAI) avviato");
    return ESP_OK;
}

static bool twai_to_proto(const twai_message_t *msg, can_proto_frame_t *frame)
{
    if (!msg || !frame) return false;
    memset(frame, 0, sizeof(*frame));
    frame->cob_id = msg->identifier;
    frame->dlc    = msg->data_length_code;
    if (frame->dlc > 0 && frame->dlc <= 8) {
        memcpy(frame->data, msg->data, frame->dlc);
    }
    return true;
}

static bool proto_to_twai(const can_proto_frame_t *frame, twai_message_t *msg)
{
    if (!frame || !msg) return false;
    memset(msg, 0, sizeof(*msg));
    msg->identifier       = frame->cob_id;
    msg->extd             = 0;
    msg->rtr              = 0;
    msg->data_length_code = frame->dlc;
    if (frame->dlc > 0 && frame->dlc <= 8) {
        memcpy(msg->data, frame->data, frame->dlc);
    }
    return true;
}

static esp_err_t can_send_frame(const can_proto_frame_t *frame)
{
    if (!frame) return ESP_ERR_INVALID_ARG;
    if (!s_can_started) return ESP_ERR_INVALID_STATE;

    twai_message_t msg;
    if (!proto_to_twai(frame, &msg)) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = twai_transmit(&msg, pdMS_TO_TICKS(50));
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "twai_transmit fallita: %s", esp_err_to_name(err));
    }
    return err;
}

// -----------------------------------------------------------------------------
// CAN: invio Info / Address request / Ext heartbeat / Zone event
// -----------------------------------------------------------------------------

static void send_addr_request(void)
{
    can_proto_addr_request_t req = {
        .protocol = CAN_PROTO_PROTOCOL_VERSION,
    };
    memcpy(req.uid, s_uid, sizeof(req.uid));

    can_proto_frame_t frame = {0};
    if (!can_proto_build_addr_request(&req, &frame)) {
        ESP_LOGW(TAG, "can_proto_build_addr_request fallita");
        return;
    }
    (void)can_send_frame(&frame);
    ESP_LOGI(TAG, "Inviata address request");
}

static void send_info(void)
{
    if (!s_node_id_valid || s_node_id == 0) {
        return;
    }

    can_proto_info_t info = {
        .msg_type      = CAN_PROTO_MSG_INFO,
        .protocol      = CAN_PROTO_PROTOCOL_VERSION,
        .model         = EXP_NODE_MODEL_ID,
        .firmware      = EXP_NODE_FW_VERSION,
        .inputs_count  = EXP_NODE_ZONE_COUNT,
        .outputs_count = EXP_NODE_OUTPUT_COUNT,
    };

    can_proto_frame_t frame = {0};
    if (!can_proto_build_info(s_node_id, &info, &frame)) {
        ESP_LOGW(TAG, "can_proto_build_info fallita");
        return;
    }
    (void)can_send_frame(&frame);
}

static void send_scan_response(void)
{
    if (!s_node_id_valid || s_node_id == 0) {
        return;
    }

    can_proto_frame_t frame = {0};
    if (!can_proto_build_scan_response(s_node_id, &frame)) {
        ESP_LOGW(TAG, "can_proto_build_scan_response fallita");
        return;
    }
    (void)can_send_frame(&frame);
}

static void send_heartbeat(void)
{
    if (!s_node_id_valid || s_node_id == 0) {
        return;
    }

    can_proto_heartbeat_t hb = {
        .msg_type      = CAN_PROTO_MSG_HEARTBEAT,
        .node_state    = 0,
        .change_counter = s_change_counter,
        .reserved      = 0,
        .inputs_bitmap = 0,
    };

    can_proto_frame_t frame = {0};
    if (!can_proto_build_heartbeat(s_node_id, &hb, &frame)) {
        ESP_LOGW(TAG, "can_proto_build_heartbeat fallita");
        return;
    }
    (void)can_send_frame(&frame);
}

static uint8_t compute_zone_state_bits(int zone_idx, const zone_sample_t *smp)
{
    if (!smp || zone_idx < 0 || zone_idx >= EXP_NODE_ZONE_COUNT) {
        return 0;
    }

    const zone_config_t *cfg = &s_zone_cfg[zone_idx];
    const zone_eol_thresholds_t *thr = &s_eol_thresholds;

    uint8_t bits = 0;
    if (cfg->enabled) {
        bits |= CAN_PROTO_ZONE_EVENT_STATE_PRESENT;
    }
    if (cfg->contact_is_no) {
        bits |= CAN_PROTO_ZONE_EVENT_STATE_CONTACT_NO;
    }

    switch (smp->state) {
    case ZONE_INPUT_STATE_ALARM:
        bits |= CAN_PROTO_ZONE_EVENT_STATE_ALARM;
        break;
    case ZONE_INPUT_STATE_TAMPER:
    case ZONE_INPUT_STATE_MASKING:
        bits |= CAN_PROTO_ZONE_EVENT_STATE_TAMPER;
        break;
    case ZONE_INPUT_STATE_FAULT:
    case ZONE_INPUT_STATE_NORMAL:
    default:
        break;
    }

    // Heuristica short/open basata sul rapporto EOL
    float r = smp->ratio;
    switch (cfg->eol_mode) {
    case ZONE_EOL_MODE_1:
        if (r < thr->eol1_fault_max) {
            bits |= CAN_PROTO_ZONE_EVENT_STATE_OPEN;
        }
        break;
    case ZONE_EOL_MODE_2:
        if (r < thr->eol2_tamper_low_max) {
            bits |= CAN_PROTO_ZONE_EVENT_STATE_SHORT;
        } else if (r > thr->eol2_alarm_max) {
            bits |= CAN_PROTO_ZONE_EVENT_STATE_OPEN;
        }
        break;
    case ZONE_EOL_MODE_3:
    default:
        if (r < thr->eol3_tamper_low_max) {
            bits |= CAN_PROTO_ZONE_EVENT_STATE_SHORT;
        } else if (r > thr->eol3_alarm_max) {
            bits |= CAN_PROTO_ZONE_EVENT_STATE_OPEN;
        }
        break;
    }

    return bits;
}

static uint16_t estimate_rloop_ohm_div100(int zone_idx, float ratio)
{
    if (ratio <= 0.0f) {
        return 0;
    }

    const zone_config_t *cfg = &s_zone_cfg[zone_idx];
    float base = (float)cfg->r_normal_ohm;
    float add  = (float)cfg->r_alarm_ohm;
    float est  = base + add * ratio;
    if (est < 0.0f) {
        est = 0.0f;
    }
    if (est > 65535.0f * 100.0f) {
        est = 65535.0f * 100.0f;
    }
    return (uint16_t)(est / 100.0f);
}

static void send_zone_event(int zone_idx)
{
    if (!s_node_id_valid || s_node_id == 0) {
        return;
    }
    if (zone_idx < 0 || zone_idx >= EXP_NODE_ZONE_COUNT) {
        return;
    }

    const zone_sample_t *smp = &s_zone_samples[zone_idx];
    uint8_t state_bits       = compute_zone_state_bits(zone_idx, smp);

    uint16_t raw_adc = (uint16_t)(clamp_ratio(smp->ratio) * ADC_MAX_RAW);
    uint16_t rloop   = estimate_rloop_ohm_div100(zone_idx, smp->ratio);

    can_proto_zone_event_t evt = {
        .zone_id         = (uint8_t)zone_idx,
        .state_bits      = state_bits,
        .raw_adc         = raw_adc,
        .rloop_ohm_div100 = rloop,
        .vbias_10mv      = 330 / 10,
        .seq             = s_zone_seq[zone_idx],
    };

    can_proto_frame_t frame = {
        .cob_id = CAN_PROTO_ID_EXT_ZONE_EVENT(s_node_id),
        .dlc    = sizeof(evt),
    };
    memcpy(frame.data, &evt, sizeof(evt));
    (void)can_send_frame(&frame);
}

static void send_ext_heartbeat(void)
{
    if (!s_node_id_valid || s_node_id == 0) {
        return;
    }

    uint8_t alarm_bm  = 0;
    uint8_t short_bm  = 0;
    uint8_t open_bm   = 0;
    uint8_t tamper_bm = 0;

    for (int i = 0; i < EXP_NODE_ZONE_COUNT && i < 8; ++i) {
        const zone_sample_t *smp = &s_zone_samples[i];
        uint8_t bits = compute_zone_state_bits(i, smp);
        if (bits & CAN_PROTO_ZONE_EVENT_STATE_ALARM) {
            alarm_bm |= (1u << i);
        }
        if (bits & CAN_PROTO_ZONE_EVENT_STATE_SHORT) {
            short_bm |= (1u << i);
        }
        if (bits & CAN_PROTO_ZONE_EVENT_STATE_OPEN) {
            open_bm |= (1u << i);
        }
        if (bits & CAN_PROTO_ZONE_EVENT_STATE_TAMPER) {
            tamper_bm |= (1u << i);
        }
    }

    can_proto_ext_heartbeat_t hb = {
        .alarm_bitmap       = alarm_bm,
        .short_bitmap       = short_bm,
        .open_bitmap        = open_bm,
        .tamper_bitmap      = tamper_bm,
        .vdda_100mv         = 33,
        .vbias_10mv         = 33,
        .temperature_c_plus40 = 40,
        .fw_nibbles         = (uint8_t)(EXP_NODE_FW_VERSION & 0xFFu),
    };

    can_proto_frame_t frame = {
        .cob_id = CAN_PROTO_ID_EXT_HEARTBEAT(s_node_id),
        .dlc    = sizeof(hb),
    };
    memcpy(frame.data, &hb, sizeof(hb));
    (void)can_send_frame(&frame);
}

// -----------------------------------------------------------------------------
// Gestione comandi CAN
// -----------------------------------------------------------------------------

static void handle_output_cmd(const can_proto_output_cmd_t *cmd)
{
    if (!cmd) {
        return;
    }
    s_outputs_bitmap = cmd->outputs_bitmap;
    hw_set_outputs(s_outputs_bitmap);
}

static void handle_identify_cmd(const can_proto_identify_cmd_t *cmd)
{
    if (!cmd) {
        return;
    }
    s_identify_enabled = (cmd->enable != 0);
}

static void handle_zone_config(const can_proto_zone_config_t *cfg)
{
    if (!cfg || cfg->zone_index >= EXP_NODE_ZONE_COUNT) {
        return;
    }

    if (!CAN_ZONE_MEASURE_MODE_IS_VALID(cfg->measure_mode)) {
        return;
    }

    zone_config_t *dst = &s_zone_cfg[cfg->zone_index];
    dst->enabled      = true;
    dst->eol_mode     = (zone_eol_mode_t)cfg->measure_mode;
    dst->contact_is_no = (cfg->contact_flags & CAN_ZONE_CONTACT_FLAG_IS_NO) != 0;
    dst->r_normal_ohm = cfg->r_normal_ohm;
    dst->r_alarm_ohm  = cfg->r_alarm_ohm;

    s_global_eol_mode = dst->eol_mode;
}

static void handle_addr_assign(const can_proto_addr_assign_t *assign)
{
    if (!assign) {
        return;
    }

    if (memcmp(assign->uid, s_uid, sizeof(s_uid)) != 0) {
        ESP_LOGD(TAG, "Addr assign non per noi");
        return;
    }

    if (assign->node_id == 0 || assign->node_id > CAN_PROTO_MAX_NODE_ID) {
        ESP_LOGW(TAG, "Addr assign invalido: %u", (unsigned)assign->node_id);
        return;
    }

    s_node_id       = assign->node_id;
    s_node_id_valid = true;
    (void)nvs_save_node_id(s_node_id);
    ESP_LOGI(TAG, "Node ID assegnato: %u", (unsigned)s_node_id);
    send_info();
}

static void handle_parsed_frame(const can_proto_parsed_frame_t *parsed)
{
    if (!parsed) {
        return;
    }

    switch (parsed->kind) {
    case CAN_PROTO_FRAME_OUTPUT_COMMAND:
        handle_output_cmd(&parsed->payload.output_cmd);
        break;
    case CAN_PROTO_FRAME_IDENTIFY_CMD:
        handle_identify_cmd(&parsed->payload.identify);
        break;
    case CAN_PROTO_FRAME_ZONE_CONFIG:
        handle_zone_config(&parsed->payload.zone_config);
        break;
    case CAN_PROTO_FRAME_SCAN_REQUEST:
        send_scan_response();
        break;
    case CAN_PROTO_FRAME_ADDR_ASSIGN:
        handle_addr_assign(&parsed->payload.addr_assign);
        break;
    case CAN_PROTO_FRAME_TEST_TOGGLE:
        // per ora nessuna azione specifica
        break;
    default:
        break;
    }
}

// -----------------------------------------------------------------------------
// Task FreeRTOS
// -----------------------------------------------------------------------------

static void can_rx_task(void *arg)
{
    (void)arg;
    twai_message_t msg;
    can_proto_frame_t frame;
    can_proto_parsed_frame_t parsed;

    while (1) {
        esp_err_t err = twai_receive(&msg, portMAX_DELAY);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "twai_receive: %s", esp_err_to_name(err));
            continue;
        }

        if (!twai_to_proto(&msg, &frame)) {
            continue;
        }
        if (!can_proto_parse(&frame, &parsed)) {
            continue;
        }
        handle_parsed_frame(&parsed);
    }
}

static void logic_task(void *arg)
{
    (void)arg;

    while (1) {
        const uint64_t now = now_ms();

        // Se non abbiamo node_id valido, continuiamo a fare address request
        if (!s_node_id_valid && (now - s_last_addr_req_ms) >= EXP_ADDR_REQ_PERIOD_MS) {
            send_addr_request();
            s_last_addr_req_ms = now;
        }

        // Campiona le zone
        if ((now - s_last_sample_ms) >= EXP_SAMPLE_PERIOD_MS) {
            zones_sample_all();
            for (int i = 0; i < EXP_NODE_ZONE_COUNT; ++i) {
                uint8_t bits = compute_zone_state_bits(i, &s_zone_samples[i]);
                if (bits != s_zone_last_state_bits[i]) {
                    ESP_LOGI(TAG,
                             "Zona %d variazione: mv=%" PRIu32 " ratio=%.3f bits=0x%02x->0x%02x",
                             i,
                             s_zone_samples[i].raw_mv,
                             s_zone_samples[i].ratio,
                             s_zone_last_state_bits[i],
                             bits);
                    s_zone_last_state_bits[i] = bits;
                    s_zone_seq[i]++;
                    s_change_counter++;
                    send_zone_event(i);
                }
            }
            s_last_sample_ms = now;
        }

        // Heartbeat esteso + standard
        if (s_node_id_valid && (now - s_last_hb_ms) >= EXP_HEARTBEAT_PERIOD_MS) {
            send_ext_heartbeat();
            send_heartbeat();
            s_last_hb_ms = now;
        }

        // Aggiorna LED e uscite identify
        hw_update_leds(now);

        vTaskDelay(pdMS_TO_TICKS(25));
    }
}

// -----------------------------------------------------------------------------
// API pubblica
// -----------------------------------------------------------------------------

static void apply_default_zone_config(void)
{
    for (int i = 0; i < EXP_NODE_ZONE_COUNT; ++i) {
        s_zone_cfg[i].enabled       = true;
        s_zone_cfg[i].eol_mode      = s_global_eol_mode;
        s_zone_cfg[i].contact_is_no = false;
        s_zone_cfg[i].r_normal_ohm  = 5600;
        s_zone_cfg[i].r_alarm_ohm   = 2200;

        s_zone_samples[i].raw_mv = 0;
        s_zone_samples[i].ratio  = 0.0f;
        s_zone_samples[i].state  = ZONE_INPUT_STATE_FAULT;
        s_zone_seq[i]            = 0;
        s_zone_last_state_bits[i] = 0;
    }
}

esp_err_t expansion_node_init(void)
{
    memset(s_zone_entries, 0, sizeof(s_zone_entries));
    memset(s_zone_cfg, 0, sizeof(s_zone_cfg));
    memset(s_zone_samples, 0, sizeof(s_zone_samples));

    fill_uid_from_mac(s_uid);

    s_state_mutex = xSemaphoreCreateMutex();
    if (!s_state_mutex) {
        ESP_LOGE(TAG, "Impossibile creare mutex stato");
        return ESP_ERR_NO_MEM;
    }

    apply_default_zone_config();
    hw_init_outputs_and_leds();
    hw_set_outputs(0);

    ESP_RETURN_ON_ERROR(zones_adc_init(), TAG, "zones_adc_init");

    uint8_t stored_id = 0;
    if (nvs_load_node_id(&stored_id) == ESP_OK) {
        s_node_id       = stored_id;
        s_node_id_valid = true;
        ESP_LOGI(TAG, "Node ID caricato da NVS: %u", (unsigned)stored_id);
    }

    ESP_RETURN_ON_ERROR(can_start(), TAG, "can_start");

    if (s_node_id_valid) {
        send_info();
    }

    return ESP_OK;
}

esp_err_t expansion_node_start_tasks(void)
{
    BaseType_t ok;

    if (!s_can_started) {
        ESP_RETURN_ON_ERROR(can_start(), TAG, "can_start");
    }

    ok = xTaskCreate(can_rx_task, "exp_can_rx", EXP_TASK_STACK_RX, NULL, EXP_TASK_PRIO_RX, NULL);
    if (ok != pdPASS) {
        ESP_LOGE(TAG, "Impossibile creare can_rx_task (%ld)", (long)ok);
        return ESP_ERR_NO_MEM;
    }

    ok = xTaskCreate(logic_task, "exp_logic", EXP_TASK_STACK_LOGIC, NULL, EXP_TASK_PRIO_LOGIC, NULL);
    if (ok != pdPASS) {
        ESP_LOGE(TAG, "Impossibile creare logic_task (%ld)", (long)ok);
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}
