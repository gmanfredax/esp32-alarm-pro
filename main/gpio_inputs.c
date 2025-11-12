#include "gpio_inputs.h"

#include <string.h>

#include "esp_log.h"
#include "esp_check.h"
#include "esp_idf_version.h"

#ifdef __has_include
  #if __has_include("esp_adc/adc_oneshot.h")
    #define HAS_ADC_ONESHOT 1
  #endif
#endif

#ifndef HAS_ADC_ONESHOT
  #define HAS_ADC_ONESHOT 0
#endif

#if HAS_ADC_ONESHOT
  #include "esp_adc/adc_oneshot.h"
#else
  #include "driver/adc.h"
#endif

#include "mcp23017.h"

static const char *TAG = "inputs";

#define ZONE_ADC_CHANNEL(gpio_num, tshort, alarm, topen, tenable) \
    { .gpio = (gpio_num), .tamper_short_raw = (tshort), .alarm_raw = (alarm), \
      .tamper_open_raw = (topen), .tamper_enabled = (tenable) }
static const zone_adc_channel_cfg_t s_zone_cfg[INPUT_ZONES_COUNT] = {ZONE_ADC_CHANNEL_LIST};
#undef ZONE_ADC_CHANNEL

_Static_assert(sizeof(s_zone_cfg) / sizeof(s_zone_cfg[0]) == INPUT_ZONES_COUNT, "ZONE_ADC_CHANNEL_LIST deve avere INPUT_ZONES_COUNT elementi");
_Static_assert(INPUT_ZONES_COUNT == ZONE_ANALOG_CHANNEL_COUNT, "INPUT_ZONES_COUNT deve corrispondere a ZONE_ANALOG_CHANNEL_COUNT");

typedef struct {
    adc_unit_t unit;
#if HAS_ADC_ONESHOT
    adc_channel_t channel;
#else
    int          channel;   // usa adc1_channel_t / adc2_channel_t in base all'unità
#endif
    bool         configured;
} zone_adc_runtime_t;

static zone_adc_runtime_t            s_zone_runtime[INPUT_ZONES_COUNT];
#if HAS_ADC_ONESHOT
static adc_oneshot_unit_handle_t     s_adc_unit1 = NULL;
static adc_oneshot_unit_handle_t     s_adc_unit2 = NULL;
#else
static bool                          s_adc1_width_set = false;
#endif
static inputs_snapshot_t             s_last_snapshot = {0};

static bool gpio_to_adc_channel(gpio_num_t gpio, adc_unit_t *unit,
#if HAS_ADC_ONESHOT
                                adc_channel_t *channel)
#else
                                int *channel)
#endif
{
    switch (gpio) {
#if HAS_ADC_ONESHOT
    case GPIO_NUM_1:  *unit = ADC_UNIT_1; *channel = ADC_CHANNEL_0; return true;
    case GPIO_NUM_2:  *unit = ADC_UNIT_1; *channel = ADC_CHANNEL_1; return true;
    case GPIO_NUM_3:  *unit = ADC_UNIT_1; *channel = ADC_CHANNEL_2; return true;
    case GPIO_NUM_4:  *unit = ADC_UNIT_1; *channel = ADC_CHANNEL_3; return true;
    case GPIO_NUM_5:  *unit = ADC_UNIT_1; *channel = ADC_CHANNEL_4; return true;
    case GPIO_NUM_6:  *unit = ADC_UNIT_1; *channel = ADC_CHANNEL_5; return true;
    case GPIO_NUM_7:  *unit = ADC_UNIT_1; *channel = ADC_CHANNEL_6; return true;
    case GPIO_NUM_8:  *unit = ADC_UNIT_1; *channel = ADC_CHANNEL_7; return true;
    case GPIO_NUM_9:  *unit = ADC_UNIT_1; *channel = ADC_CHANNEL_8; return true;
    case GPIO_NUM_10: *unit = ADC_UNIT_1; *channel = ADC_CHANNEL_9; return true;
    case GPIO_NUM_11: *unit = ADC_UNIT_2; *channel = ADC_CHANNEL_0; return true;
    case GPIO_NUM_12: *unit = ADC_UNIT_2; *channel = ADC_CHANNEL_1; return true;
    case GPIO_NUM_13: *unit = ADC_UNIT_2; *channel = ADC_CHANNEL_2; return true;
    case GPIO_NUM_14: *unit = ADC_UNIT_2; *channel = ADC_CHANNEL_3; return true;
    case GPIO_NUM_15: *unit = ADC_UNIT_2; *channel = ADC_CHANNEL_4; return true;
    case GPIO_NUM_16: *unit = ADC_UNIT_2; *channel = ADC_CHANNEL_5; return true;
    case GPIO_NUM_17: *unit = ADC_UNIT_2; *channel = ADC_CHANNEL_6; return true;
    case GPIO_NUM_18: *unit = ADC_UNIT_2; *channel = ADC_CHANNEL_7; return true;
    case GPIO_NUM_19: *unit = ADC_UNIT_2; *channel = ADC_CHANNEL_8; return true;
    case GPIO_NUM_20: *unit = ADC_UNIT_2; *channel = ADC_CHANNEL_9; return true;
#else
    case GPIO_NUM_1:  *unit = ADC_UNIT_1; *channel = ADC1_CHANNEL_0; return true;
    case GPIO_NUM_2:  *unit = ADC_UNIT_1; *channel = ADC1_CHANNEL_1; return true;
    case GPIO_NUM_3:  *unit = ADC_UNIT_1; *channel = ADC1_CHANNEL_2; return true;
    case GPIO_NUM_4:  *unit = ADC_UNIT_1; *channel = ADC1_CHANNEL_3; return true;
    case GPIO_NUM_5:  *unit = ADC_UNIT_1; *channel = ADC1_CHANNEL_4; return true;
    case GPIO_NUM_6:  *unit = ADC_UNIT_1; *channel = ADC1_CHANNEL_5; return true;
    case GPIO_NUM_7:  *unit = ADC_UNIT_1; *channel = ADC1_CHANNEL_6; return true;
    case GPIO_NUM_8:  *unit = ADC_UNIT_1; *channel = ADC1_CHANNEL_7; return true;
    case GPIO_NUM_9:  *unit = ADC_UNIT_1; *channel = ADC1_CHANNEL_8; return true;
    case GPIO_NUM_10: *unit = ADC_UNIT_1; *channel = ADC1_CHANNEL_9; return true;
    case GPIO_NUM_11: *unit = ADC_UNIT_2; *channel = ADC2_CHANNEL_0; return true;
    case GPIO_NUM_12: *unit = ADC_UNIT_2; *channel = ADC2_CHANNEL_1; return true;
    case GPIO_NUM_13: *unit = ADC_UNIT_2; *channel = ADC2_CHANNEL_2; return true;
    case GPIO_NUM_14: *unit = ADC_UNIT_2; *channel = ADC2_CHANNEL_3; return true;
    case GPIO_NUM_15: *unit = ADC_UNIT_2; *channel = ADC2_CHANNEL_4; return true;
    case GPIO_NUM_16: *unit = ADC_UNIT_2; *channel = ADC2_CHANNEL_5; return true;
    case GPIO_NUM_17: *unit = ADC_UNIT_2; *channel = ADC2_CHANNEL_6; return true;
    case GPIO_NUM_18: *unit = ADC_UNIT_2; *channel = ADC2_CHANNEL_7; return true;
    case GPIO_NUM_19: *unit = ADC_UNIT_2; *channel = ADC2_CHANNEL_8; return true;
    case GPIO_NUM_20: *unit = ADC_UNIT_2; *channel = ADC2_CHANNEL_9; return true;
#endif
    default:
        return false;
    }
}

#if HAS_ADC_ONESHOT
static adc_oneshot_unit_handle_t adc_handle_for_unit(adc_unit_t unit)
{
    return (unit == ADC_UNIT_1) ? s_adc_unit1 : s_adc_unit2;
}
#endif

esp_err_t inputs_init(void)
{
    ESP_RETURN_ON_ERROR(mcp23017_init(), TAG, "MCP23017");

#if HAS_ADC_ONESHOT
    bool need_unit1 = false;
    bool need_unit2 = false;
#endif
    for (size_t i = 0; i < INPUT_ZONES_COUNT; ++i) {
        adc_unit_t unit = ADC_UNIT_1;
        
#if HAS_ADC_ONESHOT
        adc_channel_t channel = ADC_CHANNEL_0;
#else
        int channel = 0;
#endif
        if (!gpio_to_adc_channel(s_zone_cfg[i].gpio, &unit, &channel)) {
            ESP_LOGE(TAG, "GPIO %d non valido per ADC", s_zone_cfg[i].gpio);
            return ESP_ERR_INVALID_ARG;
        }
        s_zone_runtime[i].unit = unit;
        s_zone_runtime[i].channel = channel;
        s_zone_runtime[i].configured = false;
#if HAS_ADC_ONESHOT
        if (unit == ADC_UNIT_1) need_unit1 = true; else need_unit2 = true;
#else
        if (unit == ADC_UNIT_1 && !s_adc1_width_set) {
            ESP_RETURN_ON_ERROR(adc1_config_width(ADC_WIDTH_BIT_12), TAG, "adc1 width");
            s_adc1_width_set = true;
        }
#endif
    }

#if HAS_ADC_ONESHOT
    if (need_unit1 && !s_adc_unit1) {
        adc_oneshot_unit_init_cfg_t cfg = {
            .unit_id = ADC_UNIT_1,
            .ulp_mode = ADC_ULP_MODE_DISABLE,
        };
        ESP_RETURN_ON_ERROR(adc_oneshot_new_unit(&cfg, &s_adc_unit1), TAG, "adc_unit1");
    }
    if (need_unit2 && !s_adc_unit2) {
        adc_oneshot_unit_init_cfg_t cfg = {
            .unit_id = ADC_UNIT_2,
            .ulp_mode = ADC_ULP_MODE_DISABLE,
        };
        ESP_RETURN_ON_ERROR(adc_oneshot_new_unit(&cfg, &s_adc_unit2), TAG, "adc_unit2");
    }

    adc_oneshot_chan_cfg_t chan_cfg = {
        .bitwidth = ADC_BITWIDTH_DEFAULT,
        .atten = ADC_ATTEN_DB_12,
    };

    for (size_t i = 0; i < INPUT_ZONES_COUNT; ++i) {
        zone_adc_runtime_t *rt = &s_zone_runtime[i];
        adc_oneshot_unit_handle_t handle = adc_handle_for_unit(rt->unit);
        if (!handle) {
            ESP_LOGE(TAG, "ADC unit handle mancante per zona %d", (int)i);
            return ESP_ERR_INVALID_STATE;
        }
        if (!rt->configured) {
            ESP_RETURN_ON_ERROR(adc_oneshot_config_channel(handle, rt->channel, &chan_cfg), TAG, "adc_chan");
            rt->configured = true;
        }
    }
#else
    for (size_t i = 0; i < INPUT_ZONES_COUNT; ++i) {
        zone_adc_runtime_t *rt = &s_zone_runtime[i];
        if (rt->configured) {
            continue;
        }
        if (rt->unit == ADC_UNIT_1) {
            ESP_RETURN_ON_ERROR(adc1_config_channel_atten((adc1_channel_t)rt->channel, ADC_ATTEN_DB_12), TAG, "adc1 atten");
        } else {
            ESP_RETURN_ON_ERROR(adc2_config_channel_atten((adc2_channel_t)rt->channel, ADC_ATTEN_DB_12), TAG, "adc2 atten");
        }
        rt->configured = true;
    }
#endif

    memset(&s_last_snapshot, 0, sizeof(s_last_snapshot));
    ESP_LOGI(TAG, "Inputs ready: %d zone analogiche", INPUT_ZONES_COUNT);
    return ESP_OK;
}

static esp_err_t read_all_zones(uint16_t *active_mask, uint16_t *tamper_mask)
{
    uint16_t act = 0;
    uint16_t tamp = 0;
    for (size_t i = 0; i < INPUT_ZONES_COUNT; ++i) {
        const zone_adc_channel_cfg_t *cfg = &s_zone_cfg[i];
        zone_adc_runtime_t *rt = &s_zone_runtime[i];
#if HAS_ADC_ONESHOT
        adc_oneshot_unit_handle_t handle = adc_handle_for_unit(rt->unit);
        if (!handle) {
            return ESP_ERR_INVALID_STATE;
        }
        int raw = 0;
        esp_err_t err = adc_oneshot_read(handle, rt->channel, &raw);
#else
        int raw = 0;
        esp_err_t err = ESP_OK;
        if (rt->unit == ADC_UNIT_1) {
            raw = adc1_get_raw((adc1_channel_t)rt->channel);
        } else {
            int value = 0;
            err = adc2_get_raw((adc2_channel_t)rt->channel, ADC_WIDTH_BIT_12, &value);
            if (err == ESP_OK) {
                raw = value;
            }
        }
#endif
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "ADC read zona %d fallito: %s", (int)i + 1, esp_err_to_name(err));
            return err;
        }
        if (raw < 0) raw = 0;
        if (raw > 4095) raw = 4095;
        s_last_snapshot.adc_raw[i] = (uint16_t)raw;

        bool zone_tamper = false;
        if (cfg->tamper_enabled) {
            if ((cfg->tamper_short_raw > 0 && raw <= cfg->tamper_short_raw) ||
                (cfg->tamper_open_raw > 0 && raw >= cfg->tamper_open_raw)) {
                zone_tamper = true;
            }
        }
        if (zone_tamper) {
            tamp |= (1u << i);
        }
        if (raw <= cfg->alarm_raw) {
            act |= (1u << i);
        }
    }
    if (active_mask) *active_mask = act;
    if (tamper_mask) *tamper_mask = tamp;
    return ESP_OK;
}

esp_err_t inputs_read_all(uint16_t* zone_mask)
{
    if (!zone_mask) return ESP_ERR_INVALID_ARG;

    uint16_t active_mask = 0;
    uint16_t tamper_mask = 0;
    ESP_RETURN_ON_ERROR(read_all_zones(&active_mask, &tamper_mask), TAG, "read zones");

    uint16_t gpioab = 0;
    esp_err_t mcp_err = mcp23017_read_gpioab(&gpioab);
    if (mcp_err != ESP_OK) {
        ESP_LOGE(TAG, "MCP23017 read failed: %s", esp_err_to_name(mcp_err));
        return mcp_err;
    }
    bool global_tamper = ((gpioab & (1u << (8 + MCPB_TAMPER_GLOBAL_BIT))) == 0);

    s_last_snapshot.zone_active_mask = active_mask;
    s_last_snapshot.zone_tamper_mask = tamper_mask;
    s_last_snapshot.global_tamper = global_tamper;

    *zone_mask = active_mask;
    return ESP_OK;
}

void inputs_get_last_snapshot(inputs_snapshot_t *snapshot)
{
    if (!snapshot) {
        return;
    }
    *snapshot = s_last_snapshot;
}

uint16_t inputs_zone_tamper_mask(void)
{
    return s_last_snapshot.zone_tamper_mask;
}

bool inputs_global_tamper(void)
{
    return s_last_snapshot.global_tamper;
}