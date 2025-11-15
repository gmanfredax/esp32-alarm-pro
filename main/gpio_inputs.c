#include "gpio_inputs.h"
#include "mcp23017.h"
#include "ads1115.h"
#include "esp_log.h"
#include "esp_check.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static size_t s_ads_devices = 0;
#if ADS1115_COUNT > 0
static input_analog_zone_config_t s_analog_cfg;
static StaticSemaphore_t s_ads_mutex_buffer;
static SemaphoreHandle_t s_ads_mutex = NULL;

_Static_assert(INPUT_ANALOG_ZONES_COUNT <= INPUT_ANALOG_TOTAL_CHANNELS,
               "Analog zone count exceeds available ADS1115 channels");
#if INPUT_ANALOG_SUPPLY_INDEX > 0
_Static_assert(INPUT_ANALOG_SUPPLY_INDEX < INPUT_ANALOG_TOTAL_CHANNELS,
               "Supply channel index outside ADS1115 channel range");
#endif
#endif

static const char* TAG = "inputs";

#if ADS1115_COUNT > 0
static const ads1115_device_config_t s_ads_configs[] = {
#if ADS1115_COUNT > 0
    {
        .address = ADS1115_ADDR_0,
        .default_mux = ADS1115_MUX_AIN0_GND,
        .options = {
            .gain = ADS1115_PGA_FSR_4096,
            .mode = ADS1115_MODE_SINGLE_SHOT,
            .data_rate = ADS1115_DATA_RATE_128_SPS,
            .comp_mode = ADS1115_COMP_MODE_TRADITIONAL,
            .comp_polarity = ADS1115_COMP_POL_ACTIVE_LOW,
            .comp_latch = ADS1115_COMP_NON_LATCHING,
            .comp_queue = ADS1115_COMP_QUEUE_DISABLE,
        },
    },
#endif
#if ADS1115_COUNT > 1
    {
        .address = ADS1115_ADDR_1,
        .default_mux = ADS1115_MUX_AIN0_GND,
        .options = {
            .gain = ADS1115_PGA_FSR_4096,
            .mode = ADS1115_MODE_SINGLE_SHOT,
            .data_rate = ADS1115_DATA_RATE_128_SPS,
            .comp_mode = ADS1115_COMP_MODE_TRADITIONAL,
            .comp_polarity = ADS1115_COMP_POL_ACTIVE_LOW,
            .comp_latch = ADS1115_COMP_NON_LATCHING,
            .comp_queue = ADS1115_COMP_QUEUE_DISABLE,
        },
    },
#endif
#if ADS1115_COUNT > 2
    {
        .address = ADS1115_ADDR_2,
        .default_mux = ADS1115_MUX_AIN0_GND,
        .options = {
            .gain = ADS1115_PGA_FSR_4096,
            .mode = ADS1115_MODE_SINGLE_SHOT,
            .data_rate = ADS1115_DATA_RATE_128_SPS,
            .comp_mode = ADS1115_COMP_MODE_TRADITIONAL,
            .comp_polarity = ADS1115_COMP_POL_ACTIVE_LOW,
            .comp_latch = ADS1115_COMP_NON_LATCHING,
            .comp_queue = ADS1115_COMP_QUEUE_DISABLE,
        },
    },
#endif
};

static inline size_t ads_config_count(void)
{
    return sizeof(s_ads_configs) / sizeof(s_ads_configs[0]);
}

static bool ads_lock_take(TickType_t ticks)
{
    if (!s_ads_mutex) {
        return true;
    }

    TickType_t wait = ticks;
    if (wait == 0) {
        wait = pdMS_TO_TICKS(100);
        if (wait == 0) {
            wait = 1;
        }
    }

    if (xSemaphoreTake(s_ads_mutex, wait) == pdTRUE) {
        return true;
    }

    ESP_LOGW(TAG, "Timeout acquisendo il mutex ADS1115 (%lu ticks)", (unsigned long)wait);
    return false;
}

static void ads_lock_give(void)
{
    if (s_ads_mutex) {
        xSemaphoreGive(s_ads_mutex);
    }
}

static TickType_t ads_lock_timeout_for_single(TickType_t timeout)
{
    if (timeout == portMAX_DELAY) {
        return portMAX_DELAY;
    }

    TickType_t base = timeout;
    if (base == 0) {
        base = pdMS_TO_TICKS(100);
        if (base == 0) {
            base = 1;
        }
    }

    TickType_t extra = pdMS_TO_TICKS(100);
    if (extra == 0) {
        extra = 1;
    }

    if (base > portMAX_DELAY - extra) {
        return portMAX_DELAY;
    }

    return base + extra;
}

static esp_err_t single_channel_mux(int channel, ads1115_mux_t* mux);

static esp_err_t ads_single_shot_locked(size_t index, int channel, TickType_t timeout, int16_t* raw)
{
    ads1115_mux_t mux = ADS1115_MUX_AIN0_GND;
    ESP_RETURN_ON_ERROR(single_channel_mux(channel, &mux), TAG, "channel");
    return ads1115_single_shot(index, mux, timeout, raw);
}

static esp_err_t ensure_ads_index(size_t index)
{
    if (index >= s_ads_devices) {
        ESP_LOGE(TAG, "Indice ADS1115 %zu fuori range (dispositivi=%zu)", index, s_ads_devices);
        return ESP_ERR_INVALID_ARG;
    }
    return ESP_OK;
}

static esp_err_t single_channel_mux(int channel, ads1115_mux_t* mux)
{
    if (!mux) {
        return ESP_ERR_INVALID_ARG;
    }
    switch (channel) {
        case 0: *mux = ADS1115_MUX_AIN0_GND; break;
        case 1: *mux = ADS1115_MUX_AIN1_GND; break;
        case 2: *mux = ADS1115_MUX_AIN2_GND; break;
        case 3: *mux = ADS1115_MUX_AIN3_GND; break;
        default:
            ESP_LOGE(TAG, "Canale ADS1115 non valido: %d", channel);
            return ESP_ERR_INVALID_ARG;
    }
    return ESP_OK;
}
#endif

#if ADS1115_COUNT > 0
static float analog_supply_from_adc(float adc_voltage)
{
    const float divider_ratio = (float)((ANALOG_SUPPLY_DIVIDER_R1_OHMS + ANALOG_SUPPLY_DIVIDER_R2_OHMS) /
                                        ANALOG_SUPPLY_DIVIDER_R2_OHMS);
    return adc_voltage * divider_ratio;
}

static esp_err_t read_ads_slot_channel_voltage(size_t slot,
                                               int channel,
                                               TickType_t timeout,
                                               float* voltage,
                                               bool* device_present)
{
    if (!voltage) {
        return ESP_ERR_INVALID_ARG;
    }

    size_t expected_devices = inputs_ads1115_expected_devices();
    if (slot >= expected_devices) {
        if (device_present) {
            *device_present = false;
        }
        return ESP_ERR_INVALID_ARG;
    }

    ads1115_device_config_t expected;
    ESP_RETURN_ON_ERROR(inputs_ads1115_get_expected_config(slot, &expected), TAG, "expected cfg");

    int detected = inputs_ads1115_detected_index_for_address(expected.address);
    if (device_present) {
        *device_present = (detected >= 0);
    }
    if (detected < 0) {
        return ESP_OK;
    }

    return inputs_ads1115_read_channel_voltage((size_t)detected, channel, timeout, voltage);
}
#endif

esp_err_t inputs_init(void)
{
    esp_err_t e = mcp23017_init();
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "MCP23017 init failed: %s", esp_err_to_name(e));
        return e;
    }
    ESP_LOGI(TAG, "Inputs ready (MCP23017).");

#if ADS1115_COUNT > 0
    esp_err_t ads_err = ads1115_install(s_ads_configs, ads_config_count());
    if (ads_err == ESP_ERR_NOT_FOUND) {
        ESP_LOGW(TAG, "Nessun ADS1115 rilevato sul bus I2C");
    } else {
        ESP_RETURN_ON_ERROR(ads_err, TAG, "ads1115");
    }
    s_ads_devices = ads1115_device_count();
    if (s_ads_devices > 0) {
        ESP_LOGI(TAG, "ADS1115 ready: %zu device(s)", s_ads_devices);
        if (!s_ads_mutex) {
            s_ads_mutex = xSemaphoreCreateMutexStatic(&s_ads_mutex_buffer);
        }
    }

    esp_err_t cfg_err = inputs_analog_load_configs();
    if (cfg_err != ESP_OK) {
        ESP_LOGW(TAG, "Analog EOL config load failed: %s", esp_err_to_name(cfg_err));
    }
#else
    s_ads_devices = 0;
#endif

    return ESP_OK;
}

esp_err_t inputs_read_all(uint16_t* gpioab)
{
    if (!gpioab) return ESP_ERR_INVALID_ARG;
    return mcp23017_read_gpioab(gpioab);
}

#if ADS1115_COUNT > 0
size_t inputs_ads1115_count(void)
{
    return s_ads_devices;
}

size_t inputs_ads1115_expected_devices(void)
{
    return ads_config_count();
}

esp_err_t inputs_ads1115_read_channel_raw(size_t index, int channel, TickType_t timeout, int16_t* raw)
{
    ESP_RETURN_ON_ERROR(ensure_ads_index(index), TAG, "index");
    ESP_RETURN_ON_FALSE(raw != NULL, ESP_ERR_INVALID_ARG, TAG, "raw null");
    TickType_t wait = ads_lock_timeout_for_single(timeout);
    if (!ads_lock_take(wait)) {
        return ESP_ERR_TIMEOUT;
    }
    esp_err_t res = ads_single_shot_locked(index, channel, timeout, raw);
    ads_lock_give();
    return res;
}

esp_err_t inputs_ads1115_read_channel_voltage(size_t index, int channel, TickType_t timeout, float* voltage)
{
    ESP_RETURN_ON_FALSE(voltage != NULL, ESP_ERR_INVALID_ARG, TAG, "voltage null");
    int16_t raw = 0;
    ESP_RETURN_ON_ERROR(inputs_ads1115_read_channel_raw(index, channel, timeout, &raw), TAG, "raw");
    ads1115_operating_config_t cfg;
    ESP_RETURN_ON_ERROR(ads1115_get_config(index, &cfg), TAG, "cfg");
    *voltage = ads1115_raw_to_voltage(raw, cfg.gain);
    return ESP_OK;
}

esp_err_t inputs_ads1115_read_all_raw(size_t index, TickType_t timeout_per_channel, int16_t out_raw[ADS1115_CHANNEL_COUNT])
{
    ESP_RETURN_ON_FALSE(out_raw != NULL, ESP_ERR_INVALID_ARG, TAG, "out_raw null");
    ESP_RETURN_ON_ERROR(ensure_ads_index(index), TAG, "index");

    esp_err_t res = ESP_OK;
    for (int ch = 0; ch < ADS1115_CHANNEL_COUNT; ++ch) {
        res = inputs_ads1115_read_channel_raw(index, ch, timeout_per_channel, &out_raw[ch]);
        if (res != ESP_OK) {
            break;
        }
    }
    return res;
}

esp_err_t inputs_ads1115_read_all_voltage(size_t index, TickType_t timeout_per_channel, float out_voltage[ADS1115_CHANNEL_COUNT])
{
    ESP_RETURN_ON_FALSE(out_voltage != NULL, ESP_ERR_INVALID_ARG, TAG, "out_voltage null");
    ads1115_operating_config_t cfg;
    ESP_RETURN_ON_ERROR(ads1115_get_config(index, &cfg), TAG, "cfg");

    esp_err_t res = ESP_OK;
    for (int ch = 0; ch < ADS1115_CHANNEL_COUNT; ++ch) {
        int16_t raw = 0;
        res = inputs_ads1115_read_channel_raw(index, ch, timeout_per_channel, &raw);
        if (res != ESP_OK) {
            break;
        }
        out_voltage[ch] = ads1115_raw_to_voltage(raw, cfg.gain);
    }
    return res;
}

esp_err_t inputs_ads1115_get_expected_config(size_t index, ads1115_device_config_t* out_cfg)
{
    ESP_RETURN_ON_FALSE(out_cfg != NULL, ESP_ERR_INVALID_ARG, TAG, "expected cfg null");
    size_t count = ads_config_count();
    ESP_RETURN_ON_FALSE(index < count, ESP_ERR_INVALID_ARG, TAG, "expected index");
    *out_cfg = s_ads_configs[index];
    return ESP_OK;
}

int inputs_ads1115_detected_index_for_address(uint8_t address)
{
    for (size_t idx = 0; idx < s_ads_devices; ++idx) {
        ads1115_device_info_t info;
        if (ads1115_get_info(idx, &info) == ESP_OK && info.address == address) {
            return (int)idx;
        }
    }
    return -1;
}

static float clampf_range(float value, float min_v, float max_v)
{
    if (value < min_v) {
        return min_v;
    }
    if (value > max_v) {
        return max_v;
    }
    return value;
}

static void analog_cfg_default(input_analog_zone_config_t* cfg)
{
    if (!cfg) {
        return;
    }
    cfg->mode = INPUT_ANALOG_EOL_2;
    cfg->normal_min = 0.6f;
    cfg->normal_max = 1.8f;
    cfg->alarm_min = 2.2f;
    cfg->alarm_max = 3.2f;
    cfg->tamper_low = 0.2f;
    cfg->tamper_high = 3.6f;
}

static void analog_cfg_normalize(input_analog_zone_config_t* cfg)
{
    if (!cfg) {
        return;
    }
    if (cfg->mode < INPUT_ANALOG_EOL_1 || cfg->mode > INPUT_ANALOG_EOL_3) {
        cfg->mode = INPUT_ANALOG_EOL_2;
    }
    const float vmin = 0.0f;
    const float vmax = 4.096f;
    cfg->normal_min = clampf_range(cfg->normal_min, vmin, vmax);
    cfg->normal_max = clampf_range(cfg->normal_max, vmin, vmax);
    cfg->alarm_min = clampf_range(cfg->alarm_min, vmin, vmax);
    cfg->alarm_max = clampf_range(cfg->alarm_max, vmin, vmax);
    cfg->tamper_low = clampf_range(cfg->tamper_low, vmin, vmax);
    cfg->tamper_high = clampf_range(cfg->tamper_high, vmin, vmax);

    if (cfg->normal_min > cfg->normal_max) {
        float tmp = cfg->normal_min;
        cfg->normal_min = cfg->normal_max;
        cfg->normal_max = tmp;
    }
    if (cfg->alarm_min > cfg->alarm_max) {
        float tmp = cfg->alarm_min;
        cfg->alarm_min = cfg->alarm_max;
        cfg->alarm_max = tmp;
    }
    if (cfg->mode == INPUT_ANALOG_EOL_1) {
        if (cfg->alarm_min < cfg->normal_max) {
            cfg->alarm_min = fminf(fmaxf(cfg->normal_max + 0.05f, cfg->alarm_min), vmax);
        }
    } else {
        if (cfg->tamper_low > cfg->normal_min) {
            cfg->tamper_low = clampf_range(cfg->normal_min - 0.05f, vmin, cfg->normal_min);
        }
        if (cfg->tamper_high < cfg->alarm_max) {
            cfg->tamper_high = clampf_range(cfg->alarm_max + 0.05f, cfg->alarm_max, vmax);
        }
        if (cfg->alarm_min < cfg->normal_max) {
            cfg->alarm_min = fminf(fmaxf(cfg->normal_max + 0.05f, cfg->alarm_min), vmax);
        }
    }
}

static bool analog_cfg_is_valid(const input_analog_zone_config_t* cfg)
{
    if (!cfg) {
        return false;
    }
    const float min_span = 0.05f;
    bool normal_ok = (cfg->normal_max - cfg->normal_min) >= min_span;
    bool alarm_ok = (cfg->alarm_max - cfg->alarm_min) >= min_span;
    if (!normal_ok || !alarm_ok) {
        return false;
    }
    if (cfg->mode == INPUT_ANALOG_EOL_1) {
        return true;
    }
    return (cfg->tamper_high - cfg->tamper_low) >= min_span;
}

size_t inputs_analog_zone_count(void)
{
    return INPUT_ANALOG_ZONES_COUNT;
}

void inputs_analog_load_defaults(void)
{
    analog_cfg_default(&s_analog_cfg);
}

esp_err_t inputs_analog_load_configs(void)
{
    inputs_analog_load_defaults();

    if (INPUT_ANALOG_ZONES_COUNT == 0) {
        return ESP_OK;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open("analog", NVS_READONLY, &handle);
    if (err != ESP_OK) {
        return (err == ESP_ERR_NVS_NOT_FOUND) ? ESP_OK : err;
    }

    size_t required = 0;
    err = nvs_get_blob(handle, "cfg", NULL, &required);
    if (err == ESP_OK && required >= sizeof(input_analog_zone_config_t)) {
        void* blob = malloc(required);
        if (!blob) {
            nvs_close(handle);
            return ESP_ERR_NO_MEM;
        }
        esp_err_t read_err = nvs_get_blob(handle, "cfg", blob, &required);
        if (read_err == ESP_OK) {
            memcpy(&s_analog_cfg, blob, sizeof(input_analog_zone_config_t));
            analog_cfg_normalize(&s_analog_cfg);
            if (!analog_cfg_is_valid(&s_analog_cfg)) {
                ESP_LOGW(TAG, "Config EOL analogica non valida in NVS, ripristino default");
                analog_cfg_default(&s_analog_cfg);
            }
        }
        free(blob);
        err = read_err;
    }
    nvs_close(handle);
    return (err == ESP_ERR_NVS_NOT_FOUND) ? ESP_OK : err;
}

esp_err_t inputs_analog_save_configs(void)
{
    if (INPUT_ANALOG_ZONES_COUNT == 0) {
        return ESP_OK;
    }
    nvs_handle_t handle;
    ESP_RETURN_ON_ERROR(nvs_open("analog", NVS_READWRITE, &handle), TAG, "analog nvs");
    esp_err_t err = nvs_set_blob(handle, "cfg", &s_analog_cfg, sizeof(s_analog_cfg));
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    nvs_close(handle);
    return err;
}

esp_err_t inputs_analog_get_zone_config(size_t index, input_analog_zone_config_t* out_cfg)
{
    ESP_RETURN_ON_FALSE(out_cfg != NULL, ESP_ERR_INVALID_ARG, TAG, "analog cfg null");
    ESP_RETURN_ON_FALSE(index < INPUT_ANALOG_ZONES_COUNT, ESP_ERR_INVALID_ARG, TAG, "analog cfg index");
    *out_cfg = s_analog_cfg;
    return ESP_OK;
}

esp_err_t inputs_analog_set_zone_config(size_t index, const input_analog_zone_config_t* cfg, bool persist)
{
    ESP_RETURN_ON_FALSE(cfg != NULL, ESP_ERR_INVALID_ARG, TAG, "analog cfg in");
    ESP_RETURN_ON_FALSE(index < INPUT_ANALOG_ZONES_COUNT, ESP_ERR_INVALID_ARG, TAG, "analog cfg index");

    input_analog_zone_config_t temp = *cfg;
    analog_cfg_normalize(&temp);
    ESP_RETURN_ON_FALSE(analog_cfg_is_valid(&temp), ESP_ERR_INVALID_ARG, TAG, "analog cfg invalid");
    s_analog_cfg = temp;

    if (persist) {
        return inputs_analog_save_configs();
    }
    return ESP_OK;
}

static void analog_cfg_eval_multi_resistor(const input_analog_zone_config_t* cfg,
                                           float voltage,
                                           bool* alarm_val,
                                           bool* tamper_val)
{
    if (!cfg || !alarm_val || !tamper_val) {
        return;
    }

    if (voltage <= cfg->tamper_low || voltage >= cfg->tamper_high) {
        *tamper_val = true;
        return;
    }

    if (voltage >= cfg->alarm_min && voltage <= cfg->alarm_max) {
        *alarm_val = true;
        return;
    }

    if (!(voltage >= cfg->normal_min && voltage <= cfg->normal_max)) {
        *tamper_val = true;
    }
}

static void analog_cfg_evaluate(const input_analog_zone_config_t* cfg, float voltage, bool* alarm, bool* tamper)
{
    bool alarm_val = false;
    bool tamper_val = false;

    if (!cfg) {
        if (alarm) *alarm = false;
        if (tamper) *tamper = false;
        return;
    }

    switch (cfg->mode) {
        case INPUT_ANALOG_EOL_1:
            if (!(voltage >= cfg->normal_min && voltage <= cfg->normal_max)) {
                alarm_val = true;
            }
            break;
        case INPUT_ANALOG_EOL_2:
            analog_cfg_eval_multi_resistor(cfg, voltage, &alarm_val, &tamper_val);
            break;
        case INPUT_ANALOG_EOL_3:
        default:
            analog_cfg_eval_multi_resistor(cfg, voltage, &alarm_val, &tamper_val);
            break;
    }

    if (alarm) {
        *alarm = alarm_val;
    }
    if (tamper) {
        *tamper = tamper_val;
    }
}

esp_err_t inputs_analog_evaluate(size_t index, TickType_t timeout, input_analog_zone_state_t* out_state)
{
    ESP_RETURN_ON_FALSE(out_state != NULL, ESP_ERR_INVALID_ARG, TAG, "analog state null");
    ESP_RETURN_ON_FALSE(index < INPUT_ANALOG_ZONES_COUNT, ESP_ERR_INVALID_ARG, TAG, "analog index");

    memset(out_state, 0, sizeof(*out_state));
    const input_analog_zone_config_t* cfg = &s_analog_cfg;
    out_state->mode = cfg->mode;

    size_t expected_devices = inputs_ads1115_expected_devices();
    size_t dev_index = index / ADS1115_CHANNEL_COUNT;
    int channel = (int)(index % ADS1115_CHANNEL_COUNT);
    if (dev_index >= expected_devices) {
        return ESP_ERR_INVALID_ARG;
    }

    bool device_present = false;
    float voltage = 0.0f;
    esp_err_t err = read_ads_slot_channel_voltage(dev_index, channel, timeout, &voltage, &device_present);
    out_state->device_present = device_present;
    if (!device_present) {
        return ESP_OK;
    }
    if (err != ESP_OK) {
        return err;
    }

    out_state->sample_valid = true;
    out_state->voltage = voltage;
    analog_cfg_evaluate(cfg, voltage, &out_state->alarm, &out_state->tamper);
    if (cfg->mode == INPUT_ANALOG_EOL_1) {
        out_state->tamper = false;
    }
    return ESP_OK;
}

esp_err_t inputs_collect_tamper_snapshot(uint16_t gpioab, TickType_t timeout, input_tamper_snapshot_t* snapshot)
{
    ESP_RETURN_ON_FALSE(snapshot != NULL, ESP_ERR_INVALID_ARG, TAG, "tamper snapshot null");
    zone_mask_clear(&snapshot->zone_mask);
    snapshot->global_tamper = inputs_tamper(gpioab);

    for (size_t idx = 0; idx < INPUT_ANALOG_ZONES_COUNT; ++idx) {
        input_analog_zone_state_t state;
        esp_err_t err = inputs_analog_evaluate(idx, timeout, &state);
        if (err != ESP_OK) {
            continue;
        }
        if (!state.device_present || !state.sample_valid) {
            continue;
        }
        if (state.tamper) {
            zone_mask_set(&snapshot->zone_mask, (uint16_t)(INPUT_ZONES_COUNT + idx));
        }
    }

    return ESP_OK;
}

esp_err_t inputs_analog_supply_state(TickType_t timeout, input_supply_state_t* out_state)
{
#if ADS1115_COUNT < 3
    (void)timeout;
    ESP_RETURN_ON_FALSE(out_state != NULL, ESP_ERR_INVALID_ARG, TAG, "supply state null");
    memset(out_state, 0, sizeof(*out_state));
    return ESP_ERR_NOT_SUPPORTED;
#else
    ESP_RETURN_ON_FALSE(out_state != NULL, ESP_ERR_INVALID_ARG, TAG, "supply state null");

    memset(out_state, 0, sizeof(*out_state));

    size_t expected_devices = inputs_ads1115_expected_devices();
    if (INPUT_ANALOG_SUPPLY_SLOT >= expected_devices) {
        return ESP_ERR_INVALID_STATE;
    }

    bool device_present = false;
    float adc_voltage = 0.0f;
    esp_err_t err = read_ads_slot_channel_voltage(INPUT_ANALOG_SUPPLY_SLOT,
                                                  INPUT_ANALOG_SUPPLY_CHANNEL,
                                                  timeout,
                                                  &adc_voltage,
                                                  &device_present);
    out_state->device_present = device_present;
    if (!device_present) {
        return ESP_OK;
    }
    if (err != ESP_OK) {
        return err;
    }

    out_state->sample_valid = true;
    out_state->adc_voltage = adc_voltage;
    out_state->supply_voltage = analog_supply_from_adc(adc_voltage);
    return ESP_OK;
#endif
}
#endif

uint16_t inputs_master_zone_capacity(void)
{
#if ADS1115_COUNT > 0
    return (uint16_t)(INPUT_ZONES_COUNT + (ADS1115_COUNT * ADS1115_CHANNEL_COUNT));
#else
    return INPUT_ZONES_COUNT;
#endif
}