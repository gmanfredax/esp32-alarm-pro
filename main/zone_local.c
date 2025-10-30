#include "zone_local.h"

#include <math.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "sdkconfig.h"

#include "ads1115.h"

typedef struct {
    uint8_t adc_index;
    uint8_t channel;
} zone_channel_map_t;

static const char *TAG = "zone_local";

#if CONFIG_APP_ZONE_DEBUG_LOG_INTERVAL_MS > 0
#define ZONE_LOCAL_LOG_INTERVAL_US ((int64_t)CONFIG_APP_ZONE_DEBUG_LOG_INTERVAL_MS * 1000LL)
static int64_t s_last_log_us = 0;

static void log_snapshot_if_due(const zone_local_zone_t *zones,
                                uint8_t count,
                                float supply_mv,
                                bool supply_valid)
{
    if (!zones || count == 0) {
        return;
    }

    const int64_t now = esp_timer_get_time();
    if (s_last_log_us != 0 && (now - s_last_log_us) < ZONE_LOCAL_LOG_INTERVAL_US) {
        return;
    }

    s_last_log_us = now;

    ESP_LOGI(TAG,
             "ADS1115 supply %.1f mV (%s)",
             (double)supply_mv,
             supply_valid ? "valid" : "invalid");

    for (uint8_t i = 0; i < count; ++i) {
        const zone_local_zone_t *entry = &zones[i];
        const zone_eol_result_t *res = &entry->result;
        ESP_LOGI(TAG,
                 "  Z%02u %-13s mv=%ld ratio=%.3f valid=%d mode=%d flags[A=%d T=%d F=%d] adc=%u/%u",
                 (unsigned)(i + 1u),
                 zone_line_state_name(res->state),
                 (long)res->millivolts,
                 (double)res->ratio,
                 entry->valid ? 1 : 0,
                 (int)res->mode,
                 entry->alarm ? 1 : 0,
                 entry->tamper ? 1 : 0,
                 entry->fault ? 1 : 0,
                 (unsigned)entry->adc_index,
                 (unsigned)entry->adc_channel);
    }
}
#else
static inline void log_snapshot_if_due(const zone_local_zone_t *zones,
                                       uint8_t count,
                                       float supply_mv,
                                       bool supply_valid)
{
    (void)zones;
    (void)count;
    (void)supply_mv;
    (void)supply_valid;
}
#endif

#ifdef CONFIG_APP_ZONE_ADS1115_ADDR0
#define ZONE_LOCAL_ADS1115_ADDR0 ((uint8_t)(CONFIG_APP_ZONE_ADS1115_ADDR0))
#else
#define ZONE_LOCAL_ADS1115_ADDR0 ((uint8_t)0x48)
#endif
#ifdef CONFIG_APP_ZONE_ADS1115_ADDR1
#define ZONE_LOCAL_ADS1115_ADDR1 ((uint8_t)(CONFIG_APP_ZONE_ADS1115_ADDR1))
#else
#define ZONE_LOCAL_ADS1115_ADDR1 ((uint8_t)0x49)
#endif
#ifdef CONFIG_APP_ZONE_ADS1115_ADDR2
#define ZONE_LOCAL_ADS1115_ADDR2 ((uint8_t)(CONFIG_APP_ZONE_ADS1115_ADDR2))
#else
#define ZONE_LOCAL_ADS1115_ADDR2 ((uint8_t)0x4A)
#endif

static const uint8_t s_ads_addresses[] = {
    ZONE_LOCAL_ADS1115_ADDR0,
    ZONE_LOCAL_ADS1115_ADDR1,
    ZONE_LOCAL_ADS1115_ADDR2,
};
static const size_t s_ads_count = sizeof(s_ads_addresses) / sizeof(s_ads_addresses[0]);
_Static_assert(ADS1115_MAX_DEVICES >= (sizeof(s_ads_addresses) / sizeof(s_ads_addresses[0])),
               "ADS1115_MAX_DEVICES must cover configured ADS1115 addresses");

#if defined(CONFIG_APP_ZONE_SUPPLY_SENSE)
#define ZONE_LOCAL_SUPPLY_SENSE_ENABLED 1
#else
#define ZONE_LOCAL_SUPPLY_SENSE_ENABLED 0
#endif

#if ZONE_LOCAL_SUPPLY_SENSE_ENABLED
#ifdef CONFIG_APP_ZONE_SUPPLY_ADC_INDEX
#define ZONE_LOCAL_SUPPLY_ADC_INDEX ((uint8_t)(CONFIG_APP_ZONE_SUPPLY_ADC_INDEX))
#else
#define ZONE_LOCAL_SUPPLY_ADC_INDEX ((uint8_t)2)
#endif
#ifdef CONFIG_APP_ZONE_SUPPLY_ADC_CHANNEL
#define ZONE_LOCAL_SUPPLY_ADC_CHANNEL ((uint8_t)(CONFIG_APP_ZONE_SUPPLY_ADC_CHANNEL))
#else
#define ZONE_LOCAL_SUPPLY_ADC_CHANNEL ((uint8_t)2)
#endif
_Static_assert(CONFIG_APP_ZONE_SUPPLY_SCALE_DEN != 0, "Supply scale denominator must be non-zero");
#define ZONE_LOCAL_SUPPLY_SCALE ((float)CONFIG_APP_ZONE_SUPPLY_SCALE_NUM / (float)CONFIG_APP_ZONE_SUPPLY_SCALE_DEN)
#define ZONE_LOCAL_SUPPLY_MIN_VALID_MV ((float)CONFIG_APP_ZONE_SUPPLY_MIN_MV)
#define ZONE_LOCAL_SUPPLY_MAX_VALID_MV ((float)CONFIG_APP_ZONE_SUPPLY_MAX_MV)
static const zone_channel_map_t s_channel_map[] = {
    { .adc_index = 0, .channel = 0 },
    { .adc_index = 0, .channel = 1 },
    { .adc_index = 0, .channel = 2 },
    { .adc_index = 0, .channel = 3 },
    { .adc_index = 1, .channel = 0 },
    { .adc_index = 1, .channel = 1 },
    { .adc_index = 1, .channel = 2 },
    { .adc_index = 1, .channel = 3 },
    { .adc_index = 2, .channel = 0 },
    { .adc_index = 2, .channel = 1 },
};
static const zone_channel_map_t s_supply_channel = {
    .adc_index = ZONE_LOCAL_SUPPLY_ADC_INDEX,
    .channel = ZONE_LOCAL_SUPPLY_ADC_CHANNEL,
};

static float supply_classification_fallback_raw_mv(void)
{
    float midpoint = 0.5f * (ZONE_LOCAL_SUPPLY_MIN_VALID_MV + ZONE_LOCAL_SUPPLY_MAX_VALID_MV);
    if (midpoint <= 0.0f) {
        midpoint = (float)ZONE_LOCAL_SUPPLY_MIN_VALID_MV;
    }
    float raw = midpoint / ZONE_LOCAL_SUPPLY_SCALE;
    if (raw <= 0.0f) {
        raw = ZONE_LOCAL_SUPPLY_DEFAULT_MV / ZONE_LOCAL_SUPPLY_SCALE;
    }
    return raw;
}
#else
static const zone_channel_map_t s_channel_map[] = {
    { .adc_index = 0, .channel = 0 },
    { .adc_index = 0, .channel = 1 },
    { .adc_index = 0, .channel = 2 },
    { .adc_index = 0, .channel = 3 },
    { .adc_index = 1, .channel = 0 },
    { .adc_index = 1, .channel = 1 },
    { .adc_index = 1, .channel = 2 },
    { .adc_index = 1, .channel = 3 },
    { .adc_index = 2, .channel = 0 },
    { .adc_index = 2, .channel = 1 },
    { .adc_index = 2, .channel = 2 },
    { .adc_index = 2, .channel = 3 },
};
#endif

_Static_assert(ZONE_LOCAL_MAX_ZONES >= (sizeof(s_channel_map) / sizeof(s_channel_map[0])),
               "ZONE_LOCAL_MAX_ZONES too small for channel map");

static float supply_reference_for_classification(float supply_mv, bool supply_valid)
{
#if ZONE_LOCAL_SUPPLY_SENSE_ENABLED
    if (supply_valid && supply_mv > 0.0f) {
        return supply_mv / ZONE_LOCAL_SUPPLY_SCALE;
    }
    return supply_classification_fallback_raw_mv();
#else
    (void)supply_valid;
    if (supply_mv > 0.0f) {
        return supply_mv;
    }
    return ZONE_LOCAL_SUPPLY_DEFAULT_MV;
#endif
}

static const size_t s_channel_map_count = sizeof(s_channel_map) / sizeof(s_channel_map[0]);

static zone_eol_mode_t s_modes[ZONE_LOCAL_MAX_ZONES] = {
    ZONE_EOL_DOUBLE, ZONE_EOL_DOUBLE, ZONE_EOL_DOUBLE, ZONE_EOL_DOUBLE,
    ZONE_EOL_DOUBLE, ZONE_EOL_DOUBLE, ZONE_EOL_DOUBLE, ZONE_EOL_DOUBLE,
    ZONE_EOL_DOUBLE, ZONE_EOL_DOUBLE, ZONE_EOL_DOUBLE, ZONE_EOL_DOUBLE,
};

static zone_local_zone_t s_state[ZONE_LOCAL_MAX_ZONES];
static uint8_t s_zone_count = 0;
static uint16_t s_alarm_mask = 0;
static uint16_t s_tamper_mask = 0;
static uint16_t s_fault_mask = 0;
static float s_supply_mv = ZONE_LOCAL_SUPPLY_DEFAULT_MV;
static bool s_supply_valid = false;
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;

static void state_reset(void)
{
    s_zone_count = (uint8_t)s_channel_map_count;
    memset(s_state, 0, sizeof(s_state));
    s_alarm_mask = 0;
    s_tamper_mask = 0;
    s_fault_mask = 0;
    for (uint8_t i = 0; i < s_zone_count; ++i) {
        if (s_modes[i] < ZONE_EOL_DISABLED || s_modes[i] > ZONE_EOL_TRIPLE) {
            s_modes[i] = ZONE_EOL_DOUBLE;
        }
        s_state[i].mode = s_modes[i];
        s_state[i].adc_index = s_channel_map[i].adc_index;
        s_state[i].adc_channel = s_channel_map[i].channel;
    }
    for (uint8_t i = s_zone_count; i < ZONE_LOCAL_MAX_ZONES; ++i) {
        s_modes[i] = ZONE_EOL_DISABLED;
        s_state[i].mode = s_modes[i];
        s_state[i].adc_index = 0;
        s_state[i].adc_channel = 0;
    }
    s_supply_mv = ZONE_LOCAL_SUPPLY_DEFAULT_MV;
    s_supply_valid = !ZONE_LOCAL_SUPPLY_SENSE_ENABLED;
}

static esp_err_t attach_ads_devices(void)
{
    for (uint8_t idx = 0; idx < (uint8_t)s_ads_count; ++idx) {
        uint8_t address = s_ads_addresses[idx];
        if (address < 0x08 || address > 0x77) {
            ESP_LOGE(TAG, "ADS1115 index %u address 0x%02X out of range", (unsigned)idx, (unsigned)address);
            return ESP_ERR_INVALID_ARG;
        }
        for (uint8_t prev = 0; prev < idx; ++prev) {
            if (s_ads_addresses[prev] == address) {
                ESP_LOGE(TAG,
                         "ADS1115 address collision: index %u and %u both use 0x%02X",
                         (unsigned)prev,
                         (unsigned)idx,
                         (unsigned)address);
                return ESP_ERR_INVALID_STATE;
            }
        }
        esp_err_t err = ads1115_attach(idx, address);
        if (err != ESP_OK) {
            ESP_LOGE(TAG,
                     "ads1115_attach failed for index %u (addr 0x%02X): %s",
                     (unsigned)idx,
                     (unsigned)address,
                     esp_err_to_name(err));
            return err;
        }
    }
    return ESP_OK;
}

#if ZONE_LOCAL_SUPPLY_SENSE_ENABLED
static bool read_supply_mv(float *out_mv)
{
    if (!out_mv) {
        return false;
    }
    float raw_mv = 0.0f;
    esp_err_t err = ads1115_read_mv(s_supply_channel.adc_index, s_supply_channel.channel, &raw_mv);
    if (err != ESP_OK) {
        ESP_LOGW(TAG,
                 "Supply sense read failed (adc=%u ch=%u): %s",
                 (unsigned)s_supply_channel.adc_index,
                 (unsigned)s_supply_channel.channel,
                 esp_err_to_name(err));
        return false;
    }
    float scaled = raw_mv * ZONE_LOCAL_SUPPLY_SCALE;
    if (scaled < ZONE_LOCAL_SUPPLY_MIN_VALID_MV) {
        scaled = ZONE_LOCAL_SUPPLY_MIN_VALID_MV;
    } else if (scaled > ZONE_LOCAL_SUPPLY_MAX_VALID_MV) {
        scaled = ZONE_LOCAL_SUPPLY_MAX_VALID_MV;
    }
    *out_mv = scaled;
    return true;
}
#endif

esp_err_t zone_local_init(void)
{
    portENTER_CRITICAL(&s_lock);
    state_reset();
    portEXIT_CRITICAL(&s_lock);

    esp_err_t err = ads1115_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "ads1115_init failed: %s", esp_err_to_name(err));
        return err;
    }
    err = attach_ads_devices();
    if (err != ESP_OK) {
        return err;
    }

#if ZONE_LOCAL_SUPPLY_SENSE_ENABLED
    if (s_supply_channel.adc_index >= ADS1115_MAX_DEVICES || s_supply_channel.channel > 3) {
        ESP_LOGE(TAG,
                 "Invalid supply sense mapping (adc=%u ch=%u)",
                 (unsigned)s_supply_channel.adc_index,
                 (unsigned)s_supply_channel.channel);
        return ESP_ERR_INVALID_ARG;
    }
    for (size_t i = 0; i < s_channel_map_count; ++i) {
        if (s_channel_map[i].adc_index == s_supply_channel.adc_index &&
            s_channel_map[i].channel == s_supply_channel.channel) {
            ESP_LOGE(TAG,
                     "Supply sense channel conflicts with zone %u (adc=%u ch=%u)",
                     (unsigned)(i + 1),
                     (unsigned)s_supply_channel.adc_index,
                     (unsigned)s_supply_channel.channel);
            return ESP_ERR_INVALID_STATE;
        }
    }
    ESP_LOGI(TAG,
             "Supply sensing enabled on ADS1115[%u] channel %u (scale %.3f, clamp %.0f-%.0f mV)",
             (unsigned)s_supply_channel.adc_index,
             (unsigned)s_supply_channel.channel,
             (double)ZONE_LOCAL_SUPPLY_SCALE,
             (double)ZONE_LOCAL_SUPPLY_MIN_VALID_MV,
             (double)ZONE_LOCAL_SUPPLY_MAX_VALID_MV);
#else
    ESP_LOGI(TAG,
             "Supply sensing disabled; using fixed reference %.1f mV",
             (double)ZONE_LOCAL_SUPPLY_DEFAULT_MV);
#endif

    ESP_LOGI(TAG, "Local zones ready (%u)", (unsigned)s_zone_count);
    return ESP_OK;
}

static void update_state_locked(const zone_local_zone_t *zones,
                                uint16_t alarm_mask,
                                uint16_t tamper_mask,
                                uint16_t fault_mask,
                                float supply_mv,
                                bool supply_valid)
{
    memcpy(s_state, zones, sizeof(s_state));
    s_alarm_mask = alarm_mask;
    s_tamper_mask = tamper_mask;
    s_fault_mask = fault_mask;
    s_supply_mv = supply_mv;
    s_supply_valid = supply_valid;
}

void zone_local_update(void)
{
    zone_local_zone_t tmp[ZONE_LOCAL_MAX_ZONES];
    memset(tmp, 0, sizeof(tmp));

    uint16_t alarm_mask = 0;
    uint16_t tamper_mask = 0;
    uint16_t fault_mask = 0;

    float supply_mv = ZONE_LOCAL_SUPPLY_DEFAULT_MV;
    bool supply_valid = false;

#if ZONE_LOCAL_SUPPLY_SENSE_ENABLED
    supply_valid = read_supply_mv(&supply_mv);
    if (!supply_valid) {
        supply_mv = ZONE_LOCAL_SUPPLY_DEFAULT_MV;
    }
#else
    supply_valid = true;
#endif

    float supply_for_classification = supply_reference_for_classification(supply_mv, supply_valid);
    if (supply_for_classification <= 0.0f) {
        supply_for_classification = ZONE_LOCAL_SUPPLY_DEFAULT_MV;
    }

    for (uint8_t i = 0; i < s_zone_count; ++i) {
        zone_local_zone_t entry = {
            .mode = s_modes[i],
            .adc_index = s_channel_map[i].adc_index,
            .adc_channel = s_channel_map[i].channel,
            .valid = false,
            .alarm = false,
            .tamper = false,
            .fault = false,
        };

        float mv = 0.0f;
        esp_err_t err = ads1115_read_mv(entry.adc_index, entry.adc_channel, &mv);
        if (err == ESP_OK) {
            int32_t mv_i = (int32_t)lroundf(mv);
            entry.result = zone_eol_build_result(entry.mode, mv_i, supply_for_classification);
            entry.valid = entry.result.valid;
#if ZONE_LOCAL_SUPPLY_SENSE_ENABLED
            if (!supply_valid) {
                entry.valid = false;
                entry.result.valid = false;
                entry.result.state = ZONE_LINE_FAULT;
                entry.result.ratio = 0.0f;
            }
#endif
            if (!entry.result.valid && entry.result.state == ZONE_LINE_UNKNOWN) {
                entry.result.state = ZONE_LINE_FAULT;
                entry.result.ratio = 0.0f;
            }
        } else {
            entry.result.mode = entry.mode;
            entry.result.millivolts = 0;
            entry.result.valid = false;
            entry.result.state = ZONE_LINE_FAULT;
            ESP_LOGW(TAG,
                     "ADC read failed for zone %u (adc=%u ch=%u): %s",
                     (unsigned)(i + 1),
                     (unsigned)entry.adc_index,
                     (unsigned)entry.adc_channel,
                     esp_err_to_name(err));
        }

        switch (entry.result.state) {
        case ZONE_LINE_ALARM:
            entry.alarm = true;
            break;
        case ZONE_LINE_TAMPER_OPEN:
        case ZONE_LINE_TAMPER_SHORT:
            entry.tamper = true;
            break;
        case ZONE_LINE_FAULT:
            entry.fault = true;
            entry.tamper = true;
            break;
        default:
            break;
        }

        if (entry.alarm) {
            alarm_mask |= (1u << i);
        }
        if (entry.tamper) {
            tamper_mask |= (1u << i);
        }
        if (entry.fault) {
            fault_mask |= (1u << i);
            tamper_mask |= (1u << i);
        }

        tmp[i] = entry;
    }

    portENTER_CRITICAL(&s_lock);
    update_state_locked(tmp, alarm_mask, tamper_mask, fault_mask, supply_mv, supply_valid);
    portEXIT_CRITICAL(&s_lock);

    log_snapshot_if_due(tmp, s_zone_count, supply_mv, supply_valid);
}

void zone_local_get_snapshot(zone_local_snapshot_t *out_snapshot)
{
    if (!out_snapshot) {
        return;
    }
    portENTER_CRITICAL(&s_lock);
    out_snapshot->count = s_zone_count;
    out_snapshot->alarm_mask = s_alarm_mask;
    out_snapshot->tamper_mask = s_tamper_mask;
    out_snapshot->fault_mask = s_fault_mask;
    out_snapshot->supply_mv = s_supply_mv;
    out_snapshot->supply_valid = s_supply_valid;
    memcpy(out_snapshot->zones, s_state, sizeof(s_state));
    portEXIT_CRITICAL(&s_lock);
}

uint16_t zone_local_alarm_mask(void)
{
    portENTER_CRITICAL(&s_lock);
    uint16_t mask = s_alarm_mask | s_tamper_mask;
    portEXIT_CRITICAL(&s_lock);
    return mask;
}

uint16_t zone_local_tamper_mask(void)
{
    portENTER_CRITICAL(&s_lock);
    uint16_t mask = s_tamper_mask;
    portEXIT_CRITICAL(&s_lock);
    return mask;
}

uint16_t zone_local_fault_mask(void)
{
    portENTER_CRITICAL(&s_lock);
    uint16_t mask = s_fault_mask;
    portEXIT_CRITICAL(&s_lock);
    return mask;
}

uint8_t zone_local_zone_count(void)
{
    return s_zone_count;
}

float zone_local_supply_mv(void)
{
    portENTER_CRITICAL(&s_lock);
    float mv = s_supply_mv;
    portEXIT_CRITICAL(&s_lock);
    return mv;
}

bool zone_local_supply_valid(void)
{
    portENTER_CRITICAL(&s_lock);
    bool valid = s_supply_valid;
    portEXIT_CRITICAL(&s_lock);
    return valid;
}

void zone_local_set_mode(uint8_t zone_index, zone_eol_mode_t mode)
{
    if (zone_index >= s_zone_count) {
        return;
    }
    portENTER_CRITICAL(&s_lock);
    s_modes[zone_index] = mode;
    s_state[zone_index].mode = mode;
    portEXIT_CRITICAL(&s_lock);
}

zone_eol_mode_t zone_local_get_mode(uint8_t zone_index)
{
    if (zone_index >= s_zone_count) {
        return ZONE_EOL_DISABLED;
    }
    return s_modes[zone_index];
}

void zone_local_apply_modes(const zone_eol_mode_t *modes, size_t count)
{
    if (!modes) {
        return;
    }
    portENTER_CRITICAL(&s_lock);
    size_t limit = s_zone_count;
    if (count > limit) {
        count = limit;
    }
    for (size_t i = 0; i < count; ++i) {
        s_modes[i] = modes[i];
        s_state[i].mode = modes[i];
    }
    portEXIT_CRITICAL(&s_lock);
}