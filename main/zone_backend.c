#include "zone_backend.h"

#include "esp_log.h"
#include "esp_check.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "i2c_bus.h"
#include "mcp23017.h"
#include "pins.h"
#include "storage.h"
#include "nvs.h"

#include <limits.h>
#include <math.h>
#include <string.h>

// ADS1115 register map
#define ADS1115_REG_CONVERSION 0x00
#define ADS1115_REG_CONFIG     0x01

#define ADS1115_OS_START       (1u << 15)

typedef struct {
    i2c_master_dev_handle_t handle;
    uint8_t                 address;
} ads1115_dev_t;

typedef struct {
    zone_backend_zone_state_t state;
    uint64_t                  stable_since_us;
    uint64_t                  pending_since_us;
    bool                      pending_active;
} zone_runtime_t;

typedef struct {
    zone_backend_type_t backend;
    uint8_t             zone_count;
    bool                tamper;
    uint16_t            gpio_raw;
    float               vbias_V;
    uint64_t            timestamp_us;
    zone_backend_zone_state_t zones[ZONE_BACKEND_MAX_ZONES];
} backend_snapshot_t;

static const char *TAG = "zone_backend";

static const char *NVS_NAMESPACE   = "zb";
static const char *NVS_KEY_BACKEND = "backend";
static const char *NVS_KEY_CFG     = "cfg";

static zone_backend_type_t s_backend = ZONE_BACKEND_DIGITAL_MCP23017;
static zone_backend_cfg_t  s_cfg[ZONE_BACKEND_MAX_ZONES];
static zone_runtime_t      s_runtime[ZONE_BACKEND_MAX_ZONES];
static ads1115_dev_t       s_ads[3];
static bool                s_ads_ready = false;
static float               s_vbias_cache = 0.0f;
static uint64_t            s_vbias_timestamp_us = 0;

static backend_snapshot_t  s_last_snapshot;

static const struct {
    uint8_t dev;
    uint8_t channel;
} s_zone_map[10] = {
    {0, 0}, {0, 1}, {0, 2}, {0, 3},
    {1, 0}, {1, 1}, {1, 2}, {1, 3},
    {2, 0}, {2, 1}
};

static const uint8_t s_vbias_dev = 2;
static const uint8_t s_vbias_channel = 2;

static inline float ohm_to_scaled(float value)
{
    if (value <= 0.0f) {
        return 0.0f;
    }
    if (value > 655350.0f) {
        return 655350.0f;
    }
    return value;
}

static inline uint16_t clamp_ohm_100(float ohm)
{
    float scaled = ohm_to_scaled(ohm);
    if (scaled >= 655.35f) {
        if (scaled >= 6553.5f) {
            float tmp = scaled * 100.0f;
            if (tmp >= (float)UINT16_MAX) {
                return UINT16_MAX;
            }
            return (uint16_t)(tmp + 0.5f);
        }
    }
    float tmp = scaled * 100.0f;
    if (tmp >= (float)UINT16_MAX) {
        return UINT16_MAX;
    }
    if (tmp <= 0.0f) {
        return 0;
    }
    return (uint16_t)(tmp + 0.5f);
}

static void cfg_apply_defaults(zone_backend_cfg_t *cfg)
{
    if (!cfg) {
        return;
    }
    cfg->mode          = ZONE_MODE_DIGITAL;
    cfg->contact       = ZONE_CONTACT_NC;
    cfg->r_normal_ohm  = 4700;
    cfg->r_alarm_ohm   = 2200;
    cfg->r_tamper_ohm  = 8200;
    cfg->r_eol_ohm     = 4700;
    cfg->debounce_ms   = 150;
    cfg->hyst_pct      = 12;
    cfg->short_ohm     = 1000;
    cfg->open_ohm      = 20000;
}

void zone_backend_get_defaults(zone_backend_cfg_t *cfg)
{
    cfg_apply_defaults(cfg);
}

static void runtime_reset(zone_runtime_t *rt)
{
    if (!rt) {
        return;
    }
    memset(rt, 0, sizeof(*rt));
    rt->state.present = true;
}

static esp_err_t cfg_load_from_nvs(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &h);
    if (err != ESP_OK) {
        return err;
    }
    size_t required = sizeof(s_cfg);
    err = nvs_get_blob(h, NVS_KEY_CFG, NULL, &required);
    if (err == ESP_OK && required == sizeof(s_cfg)) {
        err = nvs_get_blob(h, NVS_KEY_CFG, s_cfg, &required);
    }
    nvs_close(h);
    if (err == ESP_OK) {
        for (size_t i = 0; i < ZONE_BACKEND_MAX_ZONES; ++i) {
            if (s_cfg[i].debounce_ms == 0) {
                cfg_apply_defaults(&s_cfg[i]);
            }
        }
    }
    return err;
}

static esp_err_t cfg_save_to_nvs(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_set_blob(h, NVS_KEY_CFG, s_cfg, sizeof(s_cfg));
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return err;
}

static esp_err_t backend_load_from_nvs(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &h);
    if (err != ESP_OK) {
        return err;
    }
    uint8_t value = 0;
    size_t len = sizeof(value);
    err = nvs_get_u8(h, NVS_KEY_BACKEND, &value);
    nvs_close(h);
    if (err == ESP_OK) {
        if (value <= ZONE_BACKEND_ANALOG_3X_ADS1115) {
            s_backend = (zone_backend_type_t)value;
        }
    }
    return err;
}

static void backend_save_to_nvs(zone_backend_type_t backend)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        return;
    }
    nvs_set_u8(h, NVS_KEY_BACKEND, (uint8_t)backend);
    nvs_commit(h);
    nvs_close(h);
}

static esp_err_t ads_device_attach(ads1115_dev_t *dev, uint8_t address)
{
    if (!dev) {
        return ESP_ERR_INVALID_ARG;
    }
    if (dev->handle) {
        return ESP_OK;
    }
    i2c_master_bus_handle_t bus = i2c_bus_get();
    ESP_RETURN_ON_FALSE(bus != NULL, ESP_ERR_INVALID_STATE, TAG, "I2C bus missing");
    i2c_device_config_t cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address  = address,
        .scl_speed_hz    = I2C_SPEED_HZ
    };
    ESP_RETURN_ON_ERROR(i2c_master_bus_add_device(bus, &cfg, &dev->handle), TAG, "ads attach");
    dev->address = address;
    return ESP_OK;
}

static esp_err_t ads_write_config(ads1115_dev_t *dev, uint16_t value)
{
    uint8_t buf[3];
    buf[0] = ADS1115_REG_CONFIG;
    buf[1] = (value >> 8) & 0xFFu;
    buf[2] = value & 0xFFu;
    return i2c_master_transmit(dev->handle, buf, sizeof(buf), 1000);
}

static esp_err_t ads_read_config(ads1115_dev_t *dev, uint16_t *value)
{
    uint8_t reg = ADS1115_REG_CONFIG;
    uint8_t buf[2] = {0};
    esp_err_t err = i2c_master_transmit_receive(dev->handle, &reg, 1, buf, sizeof(buf), 1000);
    if (err != ESP_OK) {
        return err;
    }
    *value = ((uint16_t)buf[0] << 8) | buf[1];
    return ESP_OK;
}

static esp_err_t ads_read_conversion(ads1115_dev_t *dev, int16_t *value)
{
    uint8_t reg = ADS1115_REG_CONVERSION;
    uint8_t buf[2] = {0};
    esp_err_t err = i2c_master_transmit_receive(dev->handle, &reg, 1, buf, sizeof(buf), 1000);
    if (err != ESP_OK) {
        return err;
    }
    *value = (int16_t)(((uint16_t)buf[0] << 8) | buf[1]);
    return ESP_OK;
}

static uint16_t ads_mux_value(uint8_t channel)
{
    static const uint16_t mux_table[4] = {
        0x4000u, // 100 AIN0
        0x5000u, // 101 AIN1
        0x6000u, // 110 AIN2
        0x7000u, // 111 AIN3
    };
    if (channel < 4) {
        return mux_table[channel];
    }
    return mux_table[0];
}

static esp_err_t ads_perform_single_shot(ads1115_dev_t *dev, uint8_t channel, int16_t *result)
{
    if (!dev || !dev->handle || !result) {
        return ESP_ERR_INVALID_ARG;
    }
    uint16_t config = ADS1115_OS_START |
                      ads_mux_value(channel) |
                      (1u << 11) |   // PGA ±4.096V -> 001
                      (1u << 8)  |   // MODE single-shot
                      (4u << 5)  |   // DR = 250 SPS
                      0x0003u;       // Comparator disabled

    esp_err_t err = ads_write_config(dev, config);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "ADS1115 0x%02X cfg write failed: %s", dev->address, esp_err_to_name(err));
        return err;
    }

    for (int tries = 0; tries < 20; ++tries) {
        uint16_t cfg_value = 0;
        err = ads_read_config(dev, &cfg_value);
        if (err != ESP_OK) {
            return err;
        }
        if (cfg_value & ADS1115_OS_START) {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(2));
    }

    return ads_read_conversion(dev, result);
}

static esp_err_t ads_read_average(ads1115_dev_t *dev, uint8_t channel, int16_t *out)
{
    if (!dev || !out) {
        return ESP_ERR_INVALID_ARG;
    }
    int32_t sum = 0;
    int warmup = 1;
    const int samples = 4;
    for (int i = 0; i < samples; ++i) {
        int16_t val = 0;
        esp_err_t err = ads_perform_single_shot(dev, channel, &val);
        if (err != ESP_OK) {
            return err;
        }
        if (i >= warmup) {
            sum += val;
        }
        vTaskDelay(pdMS_TO_TICKS(2));
    }
    *out = (int16_t)(sum / (samples - warmup));
    return ESP_OK;
}

static float adc_code_to_voltage(int16_t code)
{
    const float lsb = 4.096f / 32768.0f;
    return (float)code * lsb;
}

static float compute_vbias(bool *valid)
{
    uint64_t now = (uint64_t)esp_timer_get_time();
    if (s_vbias_cache > 0.0f && (now - s_vbias_timestamp_us) < 75000) {
        if (valid) *valid = true;
        return s_vbias_cache;
    }
    if (!s_ads_ready) {
        if (valid) *valid = false;
        return 0.0f;
    }
    ads1115_dev_t *dev = &s_ads[s_vbias_dev];
    int16_t raw = 0;
    esp_err_t err = ads_read_average(dev, s_vbias_channel, &raw);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Vbias read failed: %s", esp_err_to_name(err));
        if (valid) *valid = false;
        return 0.0f;
    }
    float vbias = adc_code_to_voltage(raw) * 11.0f;
    if (vbias < 0.0f) {
        vbias = 0.0f;
    }
    s_vbias_cache = vbias;
    s_vbias_timestamp_us = now;
    if (valid) *valid = true;
    return vbias;
}

static float compute_rloop(float vz, float vbias)
{
    if (vbias <= 0.05f) {
        return 0.0f;
    }
    float lambda = vz / vbias;
    if (lambda <= 0.0f || lambda >= 0.999f) {
        return INFINITY;
    }
    return 6800.0f * lambda / (1.0f - lambda);
}

static void apply_contact(zone_backend_zone_state_t *state, zone_contact_t contact)
{
    if (!state) {
        return;
    }
    if (contact == ZONE_CONTACT_NO && state->present) {
        state->alarm = !state->alarm;
    }
}

static void classify_digital(zone_backend_zone_state_t *state, bool level, const zone_backend_cfg_t *cfg)
{
    if (!state || !cfg) {
        return;
    }
    state->present = true;
    state->fault_open = false;
    state->fault_short = false;
    state->tamper = false;
    state->alarm = level;
    state->mode = ZONE_MODE_DIGITAL;
    apply_contact(state, cfg->contact);
}

static void classify_analog(zone_backend_zone_state_t *state,
                            const zone_backend_cfg_t *cfg,
                            float vz,
                            float vbias,
                            float rloop)
{
    if (!state || !cfg) {
        return;
    }
    state->mode = cfg->mode;
    state->vbias_V = vbias;
    state->vz_V    = vz;
    state->rloop_ohm_100 = clamp_ohm_100(rloop);
    state->fault_short = false;
    state->fault_open  = false;
    state->tamper      = false;
    state->alarm       = false;
    state->present     = true;

    if (vbias <= 0.1f) {
        state->present = false;
        state->fault_open = true;
        return;
    }

    if (vz < 0.05f) {
        state->fault_short = true;
        state->present = false;
        return;
    }
    if (vz > (0.95f * vbias)) {
        state->fault_open = true;
        state->present = false;
        return;
    }

    if (cfg->short_ohm > 0 && rloop < (float)cfg->short_ohm) {
        state->fault_short = true;
        state->present = false;
        return;
    }
    if (cfg->open_ohm > 0 && rloop > (float)cfg->open_ohm) {
        state->fault_open = true;
        state->present = false;
        return;
    }

    float hyst = (float)cfg->hyst_pct / 100.0f;
    float tol_norm = 0.20f;
    float tol_alarm = 0.20f;
    float tol_tamper = 0.15f;

    switch (cfg->mode) {
        case ZONE_MODE_EOL1: {
            float rn = (float)cfg->r_eol_ohm;
            if (rn <= 0.0f) {
                rn = 4700.0f;
            }
            float delta = fabsf(rloop - rn) / rn;
            if (delta <= (tol_norm + hyst)) {
                state->alarm = false;
            } else {
                state->alarm = true;
            }
            state->present = true;
            break;
        }
        case ZONE_MODE_EOL2: {
            float rn = (float)cfg->r_normal_ohm;
            float ra = (float)(cfg->r_normal_ohm + cfg->r_alarm_ohm);
            if (rn <= 0.0f) {
                rn = 4700.0f;
            }
            if (ra <= 0.0f) {
                ra = rn + 2200.0f;
            }
            float d_alarm = fabsf(rloop - ra) / ra;
            float d_norm  = fabsf(rloop - rn) / rn;
            if (d_alarm <= (tol_alarm + hyst)) {
                state->alarm = true;
            } else if (d_norm <= (tol_norm + hyst)) {
                state->alarm = false;
            } else {
                state->alarm = true;
            }
            break;
        }
        case ZONE_MODE_EOL3: {
            float rn = (float)cfg->r_normal_ohm;
            float ra = (float)(cfg->r_normal_ohm + cfg->r_alarm_ohm);
            float rt = (float)(cfg->r_normal_ohm + cfg->r_tamper_ohm);
            if (rn <= 0.0f) {
                rn = 4700.0f;
            }
            if (ra <= 0.0f) {
                ra = rn + 2200.0f;
            }
            if (rt <= 0.0f) {
                rt = rn + 8200.0f;
            }
            float d_t = fabsf(rloop - rt) / rt;
            float d_a = fabsf(rloop - ra) / ra;
            float d_n = fabsf(rloop - rn) / rn;
            if (d_t <= (tol_tamper + hyst)) {
                state->tamper = true;
                state->alarm  = false;
            } else if (d_a <= (tol_alarm + hyst)) {
                state->alarm = true;
            } else if (d_n <= (tol_norm + hyst)) {
                state->alarm = false;
            } else {
                state->alarm = true;
            }
            break;
        }
        case ZONE_MODE_DIGITAL:
        default: {
            bool high = (vz > (vbias * 0.5f));
            state->alarm = high;
            break;
        }
    }

    apply_contact(state, cfg->contact);
}

static void runtime_update(zone_runtime_t *rt,
                           const zone_backend_zone_state_t *instant,
                           uint32_t debounce_ms)
{
    if (!rt || !instant) {
        return;
    }

    uint64_t now_us = (uint64_t)esp_timer_get_time();
    bool changed = false;

    zone_backend_zone_state_t *target = &rt->state;

    if (instant->present != target->present ||
        instant->alarm   != target->alarm   ||
        instant->tamper  != target->tamper  ||
        instant->fault_open  != target->fault_open ||
        instant->fault_short != target->fault_short) {
        if (!rt->pending_active) {
            rt->pending_active = true;
            rt->pending_since_us = now_us;
        }
        uint64_t debounce = (uint64_t)debounce_ms * 1000ULL;
        if ((now_us - rt->pending_since_us) >= debounce) {
            changed = true;
        }
    } else {
        rt->pending_active = false;
    }

    if (changed) {
        *target = *instant;
        rt->stable_since_us = now_us;
        rt->pending_active = false;
    } else {
        target->adc_raw     = instant->adc_raw;
        target->vz_V        = instant->vz_V;
        target->vbias_V     = instant->vbias_V;
        target->rloop_ohm_100 = instant->rloop_ohm_100;
        target->mode        = instant->mode;
    }
}

static esp_err_t backend_read_digital(backend_snapshot_t *snap)
{
    ESP_RETURN_ON_FALSE(snap != NULL, ESP_ERR_INVALID_ARG, TAG, "snap null");
    uint16_t gpioab = 0;
    esp_err_t err = mcp23017_read_gpioab(&gpioab);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "MCP23017 read failed (%s), reinitializing", esp_err_to_name(err));
        ESP_RETURN_ON_ERROR(mcp23017_init(), TAG, "mcp reinit");
        ESP_RETURN_ON_ERROR(mcp23017_read_gpioab(&gpioab), TAG, "mcp reread");
    }

    snap->backend = ZONE_BACKEND_DIGITAL_MCP23017;
    snap->zone_count = ZONE_BACKEND_MAX_ZONES;
    snap->gpio_raw = gpioab;
    snap->tamper = ((gpioab & MCPB_MASK(MCPB_TAMPER_BIT)) != 0);
    snap->timestamp_us = (uint64_t)esp_timer_get_time();

    for (uint8_t i = 0; i < ZONE_BACKEND_MAX_ZONES; ++i) {
        zone_backend_zone_state_t instant = {0};
        bool active = false;
        if (i < 8) {
            active = ((gpioab & (1u << i)) != 0);
        } else {
            uint8_t bit = (uint8_t)(i - 8);
            active = ((gpioab & (1u << (8 + bit))) != 0);
        }
        zone_backend_cfg_t *cfg = &s_cfg[i];
        classify_digital(&instant, active, cfg);
        instant.adc_raw = active ? 32767 : 0;
        runtime_update(&s_runtime[i], &instant, cfg->debounce_ms);
        snap->zones[i] = s_runtime[i].state;
    }
    return ESP_OK;
}

static esp_err_t ensure_ads_ready(void)
{
    if (s_ads_ready) {
        return ESP_OK;
    }
    ESP_RETURN_ON_ERROR(i2c_bus_init(), TAG, "i2c init");
    static const uint8_t addresses[3] = { 0x48, 0x49, 0x4A };
    for (size_t i = 0; i < 3; ++i) {
        ESP_RETURN_ON_ERROR(ads_device_attach(&s_ads[i], addresses[i]), TAG, "ads attach");
    }
    s_ads_ready = true;
    ESP_LOGI(TAG, "ADS1115 devices ready");
    return ESP_OK;
}

static esp_err_t backend_read_analog(backend_snapshot_t *snap)
{
    ESP_RETURN_ON_FALSE(snap != NULL, ESP_ERR_INVALID_ARG, TAG, "snap null");
    ESP_RETURN_ON_ERROR(ensure_ads_ready(), TAG, "ads ready");

    bool vbias_valid = false;
    float vbias = compute_vbias(&vbias_valid);
    snap->backend = ZONE_BACKEND_ANALOG_3X_ADS1115;
    snap->zone_count = 10;
    snap->gpio_raw = 0;
    snap->vbias_V = vbias;
    snap->tamper = false;
    snap->timestamp_us = (uint64_t)esp_timer_get_time();

    for (uint8_t i = 0; i < snap->zone_count; ++i) {
        const zone_backend_cfg_t *cfg = &s_cfg[i];
        zone_backend_zone_state_t instant = {0};
        instant.mode = cfg->mode;
        instant.present = false;
        instant.vbias_V = vbias;

        const uint8_t dev_idx = s_zone_map[i].dev;
        const uint8_t channel = s_zone_map[i].channel;
        ads1115_dev_t *dev = &s_ads[dev_idx];

        int16_t raw = 0;
        esp_err_t err = ads_read_average(dev, channel, &raw);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "ADS1115 read failed zone %u: %s", (unsigned)(i + 1), esp_err_to_name(err));
            runtime_update(&s_runtime[i], &instant, cfg->debounce_ms);
            snap->zones[i] = s_runtime[i].state;
            continue;
        }
        instant.adc_raw = raw;
        float vz = adc_code_to_voltage(raw);
        instant.vz_V = vz;
        float rloop = compute_rloop(vz, vbias_valid ? vbias : 0.0f);
        classify_analog(&instant, cfg, vz, vbias, rloop);
        runtime_update(&s_runtime[i], &instant, cfg->debounce_ms);
        snap->zones[i] = s_runtime[i].state;
    }

    for (uint8_t idx = snap->zone_count; idx < ZONE_BACKEND_MAX_ZONES; ++idx) {
        zone_backend_zone_state_t instant = {0};
        runtime_update(&s_runtime[idx], &instant, s_cfg[idx].debounce_ms);
        snap->zones[idx] = s_runtime[idx].state;
    }

    return ESP_OK;
}

esp_err_t zone_backend_init(void)
{
    for (size_t i = 0; i < ZONE_BACKEND_MAX_ZONES; ++i) {
        cfg_apply_defaults(&s_cfg[i]);
        runtime_reset(&s_runtime[i]);
        memset(&s_last_snapshot.zones[i], 0, sizeof(s_last_snapshot.zones[i]));
    }
    backend_load_from_nvs();
    cfg_load_from_nvs();

    if (s_backend == ZONE_BACKEND_DIGITAL_MCP23017) {
        ESP_RETURN_ON_ERROR(mcp23017_init(), TAG, "mcp init");
    } else {
        ensure_ads_ready();
    }
    memset(&s_last_snapshot, 0, sizeof(s_last_snapshot));
    s_last_snapshot.backend = s_backend;
    s_last_snapshot.zone_count = (s_backend == ZONE_BACKEND_ANALOG_3X_ADS1115) ? 10 : ZONE_BACKEND_MAX_ZONES;
    return ESP_OK;
}

zone_backend_type_t zone_backend_current(void)
{
    return s_backend;
}

const char *zone_backend_type_label(zone_backend_type_t backend)
{
    switch (backend) {
    case ZONE_BACKEND_DIGITAL_MCP23017: return "digital";
    case ZONE_BACKEND_ANALOG_3X_ADS1115: return "ads";
    default: return "unknown";
    }
}

esp_err_t zone_backend_set(zone_backend_type_t backend, bool persist)
{
    if (backend > ZONE_BACKEND_ANALOG_3X_ADS1115) {
        return ESP_ERR_INVALID_ARG;
    }
    if (backend == s_backend) {
        return ESP_OK;
    }
    s_backend = backend;
    if (persist) {
        backend_save_to_nvs(backend);
    }
    if (backend == ZONE_BACKEND_DIGITAL_MCP23017) {
        mcp23017_init();
    } else {
        ensure_ads_ready();
        s_vbias_cache = 0.0f;
        s_vbias_timestamp_us = 0;
    }
    memset(&s_last_snapshot, 0, sizeof(s_last_snapshot));
    s_last_snapshot.backend = backend;
    s_last_snapshot.zone_count = (backend == ZONE_BACKEND_ANALOG_3X_ADS1115) ? 10 : ZONE_BACKEND_MAX_ZONES;
    for (size_t i = 0; i < ZONE_BACKEND_MAX_ZONES; ++i) {
        runtime_reset(&s_runtime[i]);
    }
    return ESP_OK;
}

esp_err_t zone_backend_poll(zone_backend_snapshot_t *snapshot, bool force_refresh)
{
    backend_snapshot_t tmp = s_last_snapshot;
    esp_err_t err = ESP_OK;
    if (s_backend == ZONE_BACKEND_DIGITAL_MCP23017) {
        err = backend_read_digital(&tmp);
    } else {
        err = backend_read_analog(&tmp);
    }
    if (err != ESP_OK) {
        return err;
    }
    s_last_snapshot = tmp;
    if (snapshot) {
        memcpy(snapshot, &s_last_snapshot, sizeof(*snapshot));
    }
    (void)force_refresh;
    return ESP_OK;
}

uint8_t zone_backend_master_zones(void)
{
    return (s_backend == ZONE_BACKEND_ANALOG_3X_ADS1115) ? 10 : ZONE_BACKEND_MAX_ZONES;
}

bool zone_backend_tamper_active(void)
{
    if (s_backend == ZONE_BACKEND_DIGITAL_MCP23017) {
        uint16_t gpioab = 0;
        if (mcp23017_read_gpioab(&gpioab) == ESP_OK) {
            return ((gpioab & MCPB_MASK(MCPB_TAMPER_BIT)) != 0);
        }
    }
    return false;
}

esp_err_t zone_backend_get_cfg(uint8_t zone_index_1_based, zone_backend_cfg_t *cfg)
{
    if (!cfg || zone_index_1_based == 0 || zone_index_1_based > ZONE_BACKEND_MAX_ZONES) {
        return ESP_ERR_INVALID_ARG;
    }
    *cfg = s_cfg[zone_index_1_based - 1u];
    return ESP_OK;
}

esp_err_t zone_backend_set_cfg(uint8_t zone_index_1_based, const zone_backend_cfg_t *cfg, bool persist)
{
    if (!cfg || zone_index_1_based == 0 || zone_index_1_based > ZONE_BACKEND_MAX_ZONES) {
        return ESP_ERR_INVALID_ARG;
    }
    zone_backend_cfg_t tmp = *cfg;
    if (tmp.debounce_ms == 0) {
        tmp.debounce_ms = 150;
    }
    if (tmp.hyst_pct == 0) {
        tmp.hyst_pct = 12;
    }
    s_cfg[zone_index_1_based - 1u] = tmp;
    if (persist) {
        cfg_save_to_nvs();
    }
    return ESP_OK;
}