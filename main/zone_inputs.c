#include "zone_inputs.h"

#include "esp_log.h"
#include "esp_check.h"
#include "esp_timer.h"
#include <string.h>

#include "esp_adc/adc_oneshot.h"

#include "mcp23017.h"

#define TAG "zones"

#define MAX_ADC_UNITS 2
#define ADC_SAMPLES_PER_CHANNEL 8
#define ADC_MAX_RAW 4095.0f

typedef struct {
    gpio_num_t     gpio;
    adc_unit_t     unit;
    adc_channel_t  channel;
    bool           configured;
} zone_adc_entry_t;

static zone_adc_entry_t s_zone_entries[ZONE_INPUT_COUNT];
//static zone_adc_entry_t s_supply_entry;

static adc_oneshot_unit_handle_t s_unit_handles[MAX_ADC_UNITS];
static bool                     s_unit_ready[MAX_ADC_UNITS];

static zone_eol_mode_t          s_eol_mode = ZONE_EOL_MODE_2;

static const gpio_num_t s_zone_gpio_map[ZONE_INPUT_COUNT] = {
    ZONE_INPUT_GPIO_1, ZONE_INPUT_GPIO_2, ZONE_INPUT_GPIO_3, ZONE_INPUT_GPIO_4,
    ZONE_INPUT_GPIO_5, ZONE_INPUT_GPIO_6, ZONE_INPUT_GPIO_7, ZONE_INPUT_GPIO_8,
    ZONE_INPUT_GPIO_9, ZONE_INPUT_GPIO_10
};

static inline uint32_t zone_mask_bit(uint8_t index)
{
    return (1u << index);
}

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
        .atten = ADC_ATTEN_DB_12,
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
    int sum = 0;
    for (int i = 0; i < ADC_SAMPLES_PER_CHANNEL; ++i) {
        int value = 0;
        esp_err_t err = adc_oneshot_read(s_unit_handles[entry->unit], entry->channel, &value);
        if (err != ESP_OK) {
            return err;
        }
        sum += value;
    }
    *out_raw = sum / ADC_SAMPLES_PER_CHANNEL;
    return ESP_OK;
}

static float compute_ratio(uint32_t raw)
{
    if (raw == 0) {
        return 0.0f;
    }
    if (raw >= ADC_MAX_RAW) {
        return 1.0f;
    }
    return (float)raw / ADC_MAX_RAW;
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
        return false;
    }
    uint16_t mask = (uint16_t)(1u << (8 + MCP_PORTB_GLOBAL_TAMPER_BIT));
    return (gpioab & mask) == 0; // attivo basso con pull-up
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

    ESP_LOGI(TAG, "Zone analogiche inizializzate (mode=%d)", (int)s_eol_mode);
    return ESP_OK;
}

esp_err_t zone_inputs_sample(zone_inputs_snapshot_t *snapshot)
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
            if (s_eol_mode == ZONE_EOL_MODE_1) {
                snapshot->global_tamper = true;
            } else {
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
    //         float ratio = compute_ratio(snapshot->supply_raw);
    //         float vout = ratio * 3.3f;
    //         float scale = (ZONE_SUPPLY_DIVIDER_R1_OHMS + ZONE_SUPPLY_DIVIDER_R2_OHMS) / ZONE_SUPPLY_DIVIDER_R2_OHMS;
    //         snapshot->supply_voltage = vout * scale;
    //     }
    // }

    snapshot->global_tamper = snapshot->global_tamper || read_global_tamper();
    if (s_eol_mode == ZONE_EOL_MODE_1) {
        snapshot->tamper_mask = 0; // 1EOL non gestisce tamper per-zona
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