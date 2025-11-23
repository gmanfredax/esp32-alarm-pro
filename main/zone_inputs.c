#include "zone_inputs.h"

#include "esp_log.h"
#include "esp_check.h"
#include "esp_timer.h"
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "esp_adc/adc_oneshot.h"

#include "mcp23017.h"

#include "esp_adc/adc_cali.h"
#include "esp_adc/adc_cali_scheme.h"

#define TAG "zones"

#define MAX_ADC_UNITS 2
#define ADC_SAMPLES_PER_CHANNEL 8
#define ADC_MAX_RAW 4095.0f

#define ZONE_INPUTS_TASK_STACK        4096
#define ZONE_INPUTS_TASK_PRIORITY     5
#define ZONE_INPUTS_TASK_PERIOD_MS    100

typedef struct {
    gpio_num_t     gpio;
    adc_unit_t     unit;
    adc_channel_t  channel;
    bool           configured;
} zone_adc_entry_t;

static adc_cali_handle_t s_cali_handles[MAX_ADC_UNITS] = {0};
static bool              s_cali_ready[MAX_ADC_UNITS] = {0};

static zone_adc_entry_t s_zone_entries[ZONE_INPUT_COUNT];
//static zone_adc_entry_t s_supply_entry;

static adc_oneshot_unit_handle_t s_unit_handles[MAX_ADC_UNITS];
static bool                     s_unit_ready[MAX_ADC_UNITS];

static zone_eol_mode_t          s_eol_mode = ZONE_EOL_MODE_2;

// ── NUOVO: snapshot globale e sincronizzazione ──────────────────────────────
static zone_inputs_snapshot_t    s_last_snapshot;
static bool                      s_snapshot_valid = false;
static SemaphoreHandle_t         s_snapshot_mutex = NULL;
static TaskHandle_t              s_zone_task_handle = NULL;

static const gpio_num_t s_zone_gpio_map[ZONE_INPUT_COUNT] = {
    ZONE_INPUT_GPIO_1, ZONE_INPUT_GPIO_2, ZONE_INPUT_GPIO_3, ZONE_INPUT_GPIO_4,
    ZONE_INPUT_GPIO_5, ZONE_INPUT_GPIO_6, ZONE_INPUT_GPIO_7, ZONE_INPUT_GPIO_8,
    ZONE_INPUT_GPIO_9, ZONE_INPUT_GPIO_10
};

static inline uint32_t zone_mask_bit(uint8_t index)
{
    return (1u << index);
}

static esp_err_t zone_inputs_do_sample(zone_inputs_snapshot_t *snapshot);
static void zone_inputs_task(void *arg);

static esp_err_t ensure_unit_handle(adc_unit_t unit)
{
    if (unit >= MAX_ADC_UNITS) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_unit_ready[unit]) {
        return ESP_OK;
    }

    adc_oneshot_unit_init_cfg_t cfg = {
        .unit_id = unit,
        .ulp_mode = ADC_ULP_MODE_DISABLE,
    };
    ESP_RETURN_ON_ERROR(adc_oneshot_new_unit(&cfg, &s_unit_handles[unit]), TAG, "adc_oneshot_new_unit");
    s_unit_ready[unit] = true;

    adc_cali_curve_fitting_config_t cali_cfg = {
        .unit_id  = unit,
        .atten    = ADC_ATTEN_DB_0,
        .bitwidth = ADC_BITWIDTH_DEFAULT,
    };
    if (adc_cali_create_scheme_curve_fitting(&cali_cfg, &s_cali_handles[unit]) == ESP_OK) {
        s_cali_ready[unit] = true;
    }

    return ESP_OK;
}

static esp_err_t configure_channel(zone_adc_entry_t *entry)
{
    if (!entry || entry->configured) {
        return ESP_OK;
    }
    ESP_RETURN_ON_ERROR(ensure_unit_handle(entry->unit), TAG, "ensure_unit_handle");

    adc_oneshot_chan_cfg_t chan_cfg = {
        .bitwidth = ADC_BITWIDTH_DEFAULT,
        .atten = ADC_ATTEN_DB_0,
    };
    ESP_RETURN_ON_ERROR(adc_oneshot_config_channel(s_unit_handles[entry->unit], entry->channel, &chan_cfg),
                        TAG, "adc_oneshot_config_channel");
    entry->configured = true;
    return ESP_OK;
}

static esp_err_t sample_raw(const zone_adc_entry_t *entry, int *out_raw)
{
    if (!entry || !out_raw || !entry->configured) {
        return ESP_ERR_INVALID_STATE;
    }
    int sum_mv = 0;
    for (int i = 0; i < ADC_SAMPLES_PER_CHANNEL; ++i) {
        int raw = 0;
        esp_err_t err = adc_oneshot_read(s_unit_handles[entry->unit], entry->channel, &raw);
        if (err != ESP_OK) {
            return err;
        }

        int mv = 0;
        if (s_cali_ready[entry->unit] && s_cali_handles[entry->unit]) {
            if (adc_cali_raw_to_voltage(s_cali_handles[entry->unit], raw, &mv) != ESP_OK) {
                // fallback se la conversione fallisce
                mv = (int)((raw / ADC_MAX_RAW) * 1100.0f);
            }
        } else {
            // fallback lineare 0–1.1 V se la calibrazione non è disponibile
            mv = (int)((raw / ADC_MAX_RAW) * 1100.0f);
        }
        sum_mv += mv;
    }
    // media in mV
    *out_raw = sum_mv / ADC_SAMPLES_PER_CHANNEL;
    return ESP_OK;
}

static float compute_ratio(uint32_t mv)
{
    if (mv <= 0) return 0.0f;
    if (mv >= 1100) return 1.0f;
    return (float)mv / 1100.0f;
}

typedef enum {
    ZONE_CLASS_NORMAL = 0,
    ZONE_CLASS_ALARM,
    ZONE_CLASS_TAMPER,
    ZONE_CLASS_FAULT,
} zone_class_t;

static zone_class_t classify_ratio(zone_eol_mode_t mode, float ratio)
{
    switch (mode) {
    case ZONE_EOL_MODE_1:
        if (ratio < 0.08f) {
            return ZONE_CLASS_FAULT;
        }
        if (ratio > 0.80f) {
            return ZONE_CLASS_ALARM;
        }
        return ZONE_CLASS_NORMAL;
    case ZONE_EOL_MODE_2:
        if (ratio < 0.10f) {
            return ZONE_CLASS_TAMPER;
        }
        if (ratio < 0.50f) {
            return ZONE_CLASS_NORMAL;
        }
        if (ratio < 0.80f) {
            return ZONE_CLASS_ALARM;
        }
        return ZONE_CLASS_TAMPER;
    case ZONE_EOL_MODE_3:
    default:
        if (ratio < 0.07f) {
            return ZONE_CLASS_TAMPER;
        }
        if (ratio < 0.38f) {
            return ZONE_CLASS_NORMAL;
        }
        if (ratio < 0.72f) {
            return ZONE_CLASS_ALARM;
        }
        return ZONE_CLASS_TAMPER;
    }
}

static bool read_global_tamper(void)
{
    uint16_t gpioab = 0;
    if (mcp23017_read_gpioab(&gpioab) != ESP_OK) {
        ESP_LOGE(TAG, "Errore lettura MCP23017: forzo tamper globale attivo");
        return true; // fail-safe
    }
    uint16_t mask = (uint16_t)(1u << (8 + MCP_PORTB_GLOBAL_TAMPER_BIT));
    // PB5 con pull-up: LOW=OK, HIGH=TAMPER
    bool tamper = (gpioab & mask) != 0;
    return tamper;
}

esp_err_t zone_inputs_init(void)
{
    memset(s_zone_entries, 0, sizeof(s_zone_entries));
    memset(s_unit_handles, 0, sizeof(s_unit_handles));
    memset(s_unit_ready, 0, sizeof(s_unit_ready));
    //memset(&s_supply_entry, 0, sizeof(s_supply_entry));

    for (size_t i = 0; i < ZONE_INPUT_COUNT; ++i) {
        s_zone_entries[i].gpio = s_zone_gpio_map[i];
        s_zone_entries[i].configured = false;
        if (s_zone_entries[i].gpio == GPIO_NUM_NC) {
            continue;
        }
        adc_unit_t unit = 0;
        adc_channel_t ch = 0;
        esp_err_t err = adc_oneshot_io_to_channel(s_zone_entries[i].gpio, &unit, &ch);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "GPIO %d non supporta ADC: %s", s_zone_entries[i].gpio, esp_err_to_name(err));
            return err;
        }
        s_zone_entries[i].unit = unit;
        s_zone_entries[i].channel = ch;
        ESP_RETURN_ON_ERROR(configure_channel(&s_zone_entries[i]), TAG, "config_channel zone");
    }

    // s_supply_entry.gpio = ZONE_SUPPLY_MONITOR_GPIO;
    // s_supply_entry.configured = false;
    // if (s_supply_entry.gpio != GPIO_NUM_NC) {
    //     adc_unit_t unit = 0;
    //     adc_channel_t ch = 0;
    //     esp_err_t err = adc_oneshot_io_to_channel(s_supply_entry.gpio, &unit, &ch);
    //     if (err != ESP_OK) {
    //         ESP_LOGE(TAG, "GPIO %d non supporta ADC (supply): %s", s_supply_entry.gpio, esp_err_to_name(err));
    //         return err;
    //     }
    //     s_supply_entry.unit = unit;
    //     s_supply_entry.channel = ch;
    //     ESP_RETURN_ON_ERROR(configure_channel(&s_supply_entry), TAG, "config_channel supply");
    // }

    // ── NUOVO: mutex + task che legge periodicamente le zone ────────────────
    if (!s_snapshot_mutex) {
        s_snapshot_mutex = xSemaphoreCreateMutex();
        if (!s_snapshot_mutex) {
            ESP_LOGE(TAG, "Impossibile creare mutex snapshot zone");
            return ESP_ERR_NO_MEM;
        }
    }

    if (!s_zone_task_handle) {
        BaseType_t rc = xTaskCreate(
            zone_inputs_task,
            "zone_inputs",
            ZONE_INPUTS_TASK_STACK,
            NULL,
            ZONE_INPUTS_TASK_PRIORITY,
            &s_zone_task_handle
        );
        if (rc != pdPASS) {
            ESP_LOGE(TAG, "Impossibile creare task zone_inputs");
            return ESP_FAIL;
        }
    }

    ESP_LOGI(TAG, "Zone analogiche inizializzate (mode=%d)", (int)s_eol_mode);
    return ESP_OK;
}

static void zone_inputs_task(void *arg)
{
    zone_inputs_snapshot_t snapshot;

    while (true) {
        esp_err_t err = zone_inputs_do_sample(&snapshot);
        if (err == ESP_OK) {
            if (s_snapshot_mutex) {
                xSemaphoreTake(s_snapshot_mutex, portMAX_DELAY);
            }
            s_last_snapshot = snapshot;
            s_snapshot_valid = true;
            if (s_snapshot_mutex) {
                xSemaphoreGive(s_snapshot_mutex);
            }
        } else {
            ESP_LOGW(TAG, "zone_inputs_task: sampling failed: %s", esp_err_to_name(err));
        }

        vTaskDelay(pdMS_TO_TICKS(ZONE_INPUTS_TASK_PERIOD_MS));
    }
}

static esp_err_t zone_inputs_do_sample(zone_inputs_snapshot_t *snapshot)
{
    if (!snapshot) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->zone_count = ZONE_INPUT_COUNT;
    snapshot->eol_mode = s_eol_mode;

    for (uint8_t i = 0; i < ZONE_INPUT_COUNT; ++i) {
        zone_adc_entry_t *entry = &s_zone_entries[i];
        if (entry->gpio == GPIO_NUM_NC || !entry->configured) {
            continue;
        }
        int raw = 0;
        esp_err_t err = sample_raw(entry, &raw);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "ADC read failed zone %u: %s", (unsigned)i + 1, esp_err_to_name(err));
            continue;
        }
        float ratio = compute_ratio((uint32_t)raw);
        zone_class_t cls = classify_ratio(s_eol_mode, ratio);

        snapshot->zones[i].raw = (uint32_t)raw;
        snapshot->zones[i].ratio = ratio;

        switch (cls) {
        case ZONE_CLASS_ALARM:
            snapshot->alarm_mask |= zone_mask_bit(i);
            break;
        case ZONE_CLASS_TAMPER:
            snapshot->tamper_mask |= zone_mask_bit(i);
            break;
        case ZONE_CLASS_FAULT:
            // In 1EOL il fault NON deve generare tamper globale.
            // In 2EOL/3EOL lo assimiliamo a tamper di zona (anomalia sulla linea).
            if (s_eol_mode != ZONE_EOL_MODE_1) {
                snapshot->tamper_mask |= zone_mask_bit(i);
            }
            break;
        case ZONE_CLASS_NORMAL:
        default:
            break;
        }
    }

    // if (s_supply_entry.configured) {
    //     int raw = 0;
    //     if (sample_raw(&s_supply_entry, &raw) == ESP_OK) {
    //         snapshot->supply_raw = (uint32_t)raw;
    //         float ratio = compute_ratio(s_supply_entry.unit, snapshot->supply_raw);
    //         float vout = ratio * 3.3f;
    //         float scale = (ZONE_SUPPLY_DIVIDER_R1_OHMS + ZONE_SUPPLY_DIVIDER_R2_OHMS) / ZONE_SUPPLY_DIVIDER_R2_OHMS;
    //         snapshot->supply_voltage = vout * scale;
    //     }
    // }

    // Il tamper globale H24 è SOLO la catena tamper cablata su PB5 del MCP23017
    snapshot->global_tamper = read_global_tamper();
    if (s_eol_mode == ZONE_EOL_MODE_1) {
        snapshot->tamper_mask = 0; // 1EOL non gestisce tamper per-zona
    }

    return ESP_OK;
}

esp_err_t zone_inputs_sample(zone_inputs_snapshot_t *snapshot)
{
    if (!snapshot) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!s_snapshot_valid) {
        // Nessun campione ancora disponibile (task non ha finito la prima lettura)
        return ESP_ERR_INVALID_STATE;
    }

    if (s_snapshot_mutex) {
        if (xSemaphoreTake(s_snapshot_mutex, pdMS_TO_TICKS(50)) != pdTRUE) {
            return ESP_ERR_TIMEOUT;
        }
    }

    memcpy(snapshot, &s_last_snapshot, sizeof(*snapshot));

    if (s_snapshot_mutex) {
        xSemaphoreGive(s_snapshot_mutex);
    }

    return ESP_OK;
}

esp_err_t zone_inputs_set_eol_mode(zone_eol_mode_t mode)
{
    if (mode < ZONE_EOL_MODE_1 || mode > ZONE_EOL_MODE_3) {
        return ESP_ERR_INVALID_ARG;
    }
    s_eol_mode = mode;
    ESP_LOGI(TAG, "EOL mode impostato a %d", (int)mode);
    return ESP_OK;
}

zone_eol_mode_t zone_inputs_get_eol_mode(void)
{
    return s_eol_mode;
}

const char *zone_inputs_eol_mode_name(zone_eol_mode_t mode)
{
    switch (mode) {
    case ZONE_EOL_MODE_1: return "1EOL";
    case ZONE_EOL_MODE_2: return "2EOL";
    case ZONE_EOL_MODE_3: return "3EOL";
    default:              return "unknown";
    }
}

bool zone_inputs_zone_alarm(const zone_inputs_snapshot_t *snapshot, uint8_t zone_index)
{
    if (!snapshot || zone_index >= snapshot->zone_count) {
        return false;
    }
    return (snapshot->alarm_mask & zone_mask_bit(zone_index)) != 0;
}

bool zone_inputs_zone_tamper(const zone_inputs_snapshot_t *snapshot, uint8_t zone_index)
{
    if (!snapshot || zone_index >= snapshot->zone_count) {
        return false;
    }
    return (snapshot->tamper_mask & zone_mask_bit(zone_index)) != 0;
}