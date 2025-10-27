#include "gpio_inputs.h"

#include <string.h>
#include <math.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "nvs.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "i2c_bus.h"

#if CONFIG_APP_INPUT_BACKEND_MCP23017
#include "mcp23017.h"
#endif

#if CONFIG_APP_INPUT_BACKEND_ADS1115
#include "ads1115.h"
#include "esp_rom_sys.h"
#endif

static const char *TAG = "inputs";

static SemaphoreHandle_t        s_lock;
static zone_measure_cfg_t       s_measure_cfg[INPUTS_MAX_ZONES];
static zone_measure_globals_t   s_measure_globals;

#if CONFIG_APP_INPUT_BACKEND_ADS1115

#define ANALOG_ZONE_COUNT 10

typedef struct {
    zone_status_t state;
    zone_status_t pending;
    uint64_t      pending_since_us;
    float         vz;
    float         vbias;
    float         rloop;
    int16_t       code;
    bool          present;
    uint64_t      timestamp_us;
} analog_zone_runtime_t;

static analog_zone_runtime_t s_zone_runtime[INPUTS_MAX_ZONES];
static float                 s_vbias_cache = 12.0f;
static uint64_t              s_vbias_updated_us = 0;
static bool                  s_last_tamper = false;

typedef struct {
    uint8_t addr;
    uint8_t channel;
} ads_map_entry_t;

static const ads_map_entry_t s_ads_map[ANALOG_ZONE_COUNT] = {
    { 0x48, 0 }, { 0x48, 1 }, { 0x48, 2 }, { 0x48, 3 },
    { 0x49, 0 }, { 0x49, 1 }, { 0x49, 2 }, { 0x49, 3 },
    { 0x4A, 0 }, { 0x4A, 1 },
};

static const ads_map_entry_t s_vbias_map = { 0x4A, 2 };

#endif

static void measure_cfg_defaults(void)
{
    for (int i = 0; i < INPUTS_MAX_ZONES; ++i) {
        s_measure_cfg[i].mode = (i < INPUTS_MAX_ZONES) ? ZONE_MEASURE_DIGITAL : ZONE_MEASURE_DIGITAL;
        s_measure_cfg[i].contact = ZONE_CONTACT_NC;
    }
#if CONFIG_APP_INPUT_BACKEND_ADS1115
    for (int i = 0; i < ANALOG_ZONE_COUNT; ++i) {
        s_measure_cfg[i].mode = ZONE_MEASURE_EOL2;
    }
#endif
}

static void measure_globals_defaults(void)
{
    s_measure_globals.r_normal        = 4700.0f;
    s_measure_globals.r_alarm         = 2200.0f;
    s_measure_globals.r_tamper        = 8200.0f;
    s_measure_globals.r_eol           = 4700.0f;
    s_measure_globals.short_threshold = 1000.0f;
    s_measure_globals.open_threshold  = 20000.0f;
    s_measure_globals.debounce_ms     = 150;
    s_measure_globals.hysteresis_pct  = 12.0f;
}

static void measure_cfg_load(void)
{
    measure_cfg_defaults();
    measure_globals_defaults();

    nvs_handle_t h;
    if (nvs_open("inputs", NVS_READONLY, &h) != ESP_OK) {
        return;
    }

    size_t cfg_len = sizeof(s_measure_cfg);
    esp_err_t err = nvs_get_blob(h, "cfg", s_measure_cfg, &cfg_len);
    if (err != ESP_OK) {
        cfg_len = 0;
    }
    size_t glob_len = sizeof(s_measure_globals);
    err = nvs_get_blob(h, "globals", &s_measure_globals, &glob_len);
    if (err != ESP_OK) {
        measure_globals_defaults();
    }
    nvs_close(h);
}

static void measure_cfg_save(void)
{
    nvs_handle_t h;
    if (nvs_open("inputs", NVS_READWRITE, &h) != ESP_OK) {
        ESP_LOGW(TAG, "Unable to open NVS namespace for inputs");
        return;
    }
    nvs_set_blob(h, "cfg", s_measure_cfg, sizeof(s_measure_cfg));
    nvs_set_blob(h, "globals", &s_measure_globals, sizeof(s_measure_globals));
    nvs_commit(h);
    nvs_close(h);
}

uint8_t inputs_master_zone_count(void)
{
#if CONFIG_APP_INPUT_BACKEND_ADS1115
    return ANALOG_ZONE_COUNT;
#else
    return 12;
#endif
}

void inputs_get_measure_cfg(int zone_index_1_based, zone_measure_cfg_t *out_cfg)
{
    if (!out_cfg) {
        return;
    }
    if (zone_index_1_based < 1 || zone_index_1_based > INPUTS_MAX_ZONES) {
        memset(out_cfg, 0, sizeof(*out_cfg));
        out_cfg->mode = ZONE_MEASURE_DIGITAL;
        out_cfg->contact = ZONE_CONTACT_NC;
        return;
    }
    int idx = zone_index_1_based - 1;
    if (s_lock) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
    }
    *out_cfg = s_measure_cfg[idx];
    if (s_lock) {
        xSemaphoreGive(s_lock);
    }
}

esp_err_t inputs_set_measure_cfg(int zone_index_1_based, const zone_measure_cfg_t *cfg)
{
    if (!cfg) {
        return ESP_ERR_INVALID_ARG;
    }
    if (zone_index_1_based < 1 || zone_index_1_based > INPUTS_MAX_ZONES) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_lock) {
        return ESP_ERR_INVALID_STATE;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_measure_cfg[zone_index_1_based - 1] = *cfg;
    measure_cfg_save();
    xSemaphoreGive(s_lock);
    return ESP_OK;
}

void inputs_get_measure_globals(zone_measure_globals_t *out_globals)
{
    if (!out_globals) {
        return;
    }
    if (s_lock) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
    }
    *out_globals = s_measure_globals;
    if (s_lock) {
        xSemaphoreGive(s_lock);
    }
}

esp_err_t inputs_set_measure_globals(const zone_measure_globals_t *globals)
{
    if (!globals) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_lock) {
        return ESP_ERR_INVALID_STATE;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_measure_globals = *globals;
    measure_cfg_save();
    xSemaphoreGive(s_lock);
    return ESP_OK;
}

zone_status_t inputs_zone_status(int zone_index_1_based)
{
    if (zone_index_1_based < 1 || zone_index_1_based > INPUTS_MAX_ZONES) {
        return ZONE_STATUS_UNKNOWN;
    }
#if CONFIG_APP_INPUT_BACKEND_ADS1115
    return s_zone_runtime[zone_index_1_based - 1].state;
#else
    return ZONE_STATUS_UNKNOWN;
#endif
}

#if CONFIG_APP_INPUT_BACKEND_ADS1115

static zone_status_t classify_resistance(float rloop,
                                         const zone_measure_cfg_t *cfg,
                                         const zone_measure_globals_t *globals,
                                         const analog_zone_runtime_t *runtime)
{
    if (!cfg || !globals || !runtime) {
        return ZONE_STATUS_UNKNOWN;
    }

    const zone_measure_globals_t *g = globals;
    const float hyst = g->hysteresis_pct / 100.0f;
    zone_status_t result = ZONE_STATUS_NORMAL;

    float rn = g->r_normal;
    float ra = g->r_normal + g->r_alarm;
    float rt = g->r_normal + g->r_tamper;
    float re = g->r_eol;

    float tol_normal = 0.20f;
    float tol_alarm  = 0.20f;
    float tol_tamper = 0.15f;

    switch (runtime->state) {
    case ZONE_STATUS_NORMAL: tol_normal *= (1.0f + hyst); break;
    case ZONE_STATUS_ALARM:  tol_alarm  *= (1.0f + hyst); break;
    case ZONE_STATUS_TAMPER: tol_tamper *= (1.0f + hyst); break;
    default: break;
    }

    float low_short = g->short_threshold;
    float high_open = g->open_threshold;

    if (rloop < low_short) {
        return ZONE_STATUS_FAULT_SHORT;
    }
    if (rloop > high_open) {
        return ZONE_STATUS_FAULT_OPEN;
    }

    float diff_normal = (rn > 0.0f) ? fabsf(rloop - rn) / rn : 1.0f;
    float diff_alarm  = (ra > 0.0f) ? fabsf(rloop - ra) / ra : 1.0f;
    float diff_tamper = (rt > 0.0f) ? fabsf(rloop - rt) / rt : 1.0f;
    float diff_eol    = (re > 0.0f) ? fabsf(rloop - re) / re : 1.0f;

    switch (cfg->mode) {
    case ZONE_MEASURE_EOL1:
        if (diff_eol <= tol_normal) {
            result = ZONE_STATUS_NORMAL;
        } else {
            result = ZONE_STATUS_ALARM;
        }
        break;
    case ZONE_MEASURE_EOL2:
        if (diff_normal <= tol_normal && diff_normal <= diff_alarm) {
            result = ZONE_STATUS_NORMAL;
        } else if (diff_alarm <= tol_alarm) {
            result = ZONE_STATUS_ALARM;
        } else {
            result = (diff_normal < diff_alarm) ? ZONE_STATUS_NORMAL : ZONE_STATUS_ALARM;
        }
        break;
    case ZONE_MEASURE_EOL3:
        if (diff_normal <= tol_normal && diff_normal <= diff_alarm && diff_normal <= diff_tamper) {
            result = ZONE_STATUS_NORMAL;
        } else if (diff_alarm <= tol_alarm && diff_alarm <= diff_tamper) {
            result = ZONE_STATUS_ALARM;
        } else if (diff_tamper <= tol_tamper) {
            result = ZONE_STATUS_TAMPER;
        } else {
            result = ZONE_STATUS_ALARM;
        }
        break;
    default:
        result = ZONE_STATUS_ALARM;
        break;
    }

    if (cfg->contact == ZONE_CONTACT_NO) {
        if (result == ZONE_STATUS_NORMAL) {
            result = ZONE_STATUS_ALARM;
        } else if (result == ZONE_STATUS_ALARM) {
            result = ZONE_STATUS_NORMAL;
        }
    }

    return result;
}

static void runtime_apply_state(analog_zone_runtime_t *rt, zone_status_t candidate, uint64_t now_us)
{
    if (!rt) {
        return;
    }
    if (rt->state == candidate) {
        rt->pending = candidate;
        rt->pending_since_us = now_us;
        return;
    }
    uint64_t debounce = ((uint64_t)s_measure_globals.debounce_ms) * 1000ULL;
    if (rt->pending != candidate) {
        rt->pending = candidate;
        rt->pending_since_us = now_us;
        return;
    }
    if ((now_us - rt->pending_since_us) >= debounce) {
        rt->state = candidate;
    }
}

static esp_err_t update_vbias(uint64_t now_us)
{
    if ((now_us - s_vbias_updated_us) < 75000ULL && s_vbias_updated_us != 0) {
        return ESP_OK;
    }
    int16_t code = 0;
    ESP_RETURN_ON_ERROR(ads1115_read_single(s_vbias_map.addr, s_vbias_map.channel, &code), TAG, "bias");
    const float lsb = 4.096f / 32768.0f;
    s_vbias_cache = (float)code * lsb * 11.0f;
    s_vbias_updated_us = now_us;
    return ESP_OK;
}

static esp_err_t analog_sample(uint16_t *mask)
{
    if (!mask) {
        return ESP_ERR_INVALID_ARG;
    }
    uint64_t now_us = esp_timer_get_time();
    ESP_RETURN_ON_ERROR(update_vbias(now_us), TAG, "vbias");

    const float lsb = 4.096f / 32768.0f;
    uint16_t bits = 0;
    bool tamper = false;

    zone_measure_globals_t globals;
    zone_measure_cfg_t cfg_local[ANALOG_ZONE_COUNT];
    if (s_lock) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
        globals = s_measure_globals;
        memcpy(cfg_local, s_measure_cfg, sizeof(zone_measure_cfg_t) * ANALOG_ZONE_COUNT);
        xSemaphoreGive(s_lock);
    } else {
        measure_globals_defaults();
        globals = s_measure_globals;
        memcpy(cfg_local, s_measure_cfg, sizeof(zone_measure_cfg_t) * ANALOG_ZONE_COUNT);
    }

    for (int i = 0; i < ANALOG_ZONE_COUNT; ++i) {
        const ads_map_entry_t *map = &s_ads_map[i];
        analog_zone_runtime_t *rt = &s_zone_runtime[i];
        int16_t code = 0;
        esp_err_t err = ads1115_read_single(map->addr, map->channel, &code);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "ADS1115 read failed for zone %d: %s", i + 1, esp_err_to_name(err));
            continue;
        }
        float vz_adc = (float)code * lsb;
        float vz = vz_adc * 5.545f;

        float vbias = s_vbias_cache;
        zone_status_t candidate = ZONE_STATUS_UNKNOWN;
        bool present = true;
        float rloop = 0.0f;

        if (vz < 0.05f) {
            candidate = ZONE_STATUS_FAULT_SHORT;
            present = false;
        } else if (vbias > 0.01f && vz > 0.95f * vbias) {
            candidate = ZONE_STATUS_FAULT_OPEN;
            present = false;
        } else if (vbias <= 0.01f) {
            candidate = ZONE_STATUS_FAULT_OPEN;
            present = false;
        } else {
            float lambda = vz / vbias;
            if (lambda <= 0.0f || lambda >= 0.999f) {
                candidate = ZONE_STATUS_FAULT_OPEN;
                present = false;
            } else {
                rloop = 6800.0f * lambda / (1.0f - lambda);
                const zone_measure_cfg_t *cfg = &cfg_local[i];
                candidate = classify_resistance(rloop, cfg, &globals, rt);
            }
        }

        runtime_apply_state(rt, candidate, now_us);
        rt->vz = vz;
        rt->vbias = s_vbias_cache;
        rt->code = code;
        rt->present = present;
        if (present) {
            rt->rloop = rloop;
        } else {
            rt->rloop = 0.0f;
        }
        rt->timestamp_us = now_us;

        if (rt->state == ZONE_STATUS_ALARM || rt->state == ZONE_STATUS_FAULT_OPEN || rt->state == ZONE_STATUS_FAULT_SHORT) {
            bits |= (1u << i);
        }
        if (rt->state == ZONE_STATUS_TAMPER || rt->state == ZONE_STATUS_FAULT_OPEN || rt->state == ZONE_STATUS_FAULT_SHORT) {
            tamper = true;
        }
    }

    s_last_tamper = tamper;
    if (tamper) {
        bits |= MCPB_MASK(MCPB_TAMPER_BIT);
    } else {
        bits &= (uint16_t)~MCPB_MASK(MCPB_TAMPER_BIT);
    }

    *mask = bits;
    return ESP_OK;
}

#endif // CONFIG_APP_INPUT_BACKEND_ADS1115

esp_err_t inputs_get_diagnostics(inputs_diag_snapshot_t *out_snapshot)
{
    if (!out_snapshot) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(out_snapshot, 0, sizeof(*out_snapshot));
    out_snapshot->total_zones = inputs_master_zone_count();
#if CONFIG_APP_INPUT_BACKEND_ADS1115
    for (int i = 0; i < ANALOG_ZONE_COUNT; ++i) {
        const analog_zone_runtime_t *rt = &s_zone_runtime[i];
        zone_diag_entry_t *dst = &out_snapshot->entries[i];
        dst->status = rt->state;
        dst->vz = rt->vz;
        dst->vbias = rt->vbias;
        dst->rloop = rt->rloop;
        dst->code = rt->code;
        dst->present = rt->present;
        dst->timestamp_us = rt->timestamp_us;
    }
#endif
    return ESP_OK;
}

esp_err_t inputs_init(void)
{
    if (!s_lock) {
        s_lock = xSemaphoreCreateMutex();
    }
    if (!s_lock) {
        return ESP_ERR_NO_MEM;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    measure_cfg_load();
#if CONFIG_APP_INPUT_BACKEND_ADS1115
    memset(s_zone_runtime, 0, sizeof(s_zone_runtime));
    for (int i = 0; i < ANALOG_ZONE_COUNT; ++i) {
        s_zone_runtime[i].state = ZONE_STATUS_UNKNOWN;
        s_zone_runtime[i].pending = ZONE_STATUS_UNKNOWN;
    }
    esp_err_t err = ads1115_init();
    xSemaphoreGive(s_lock);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "ADS1115 init failed: %s", esp_err_to_name(err));
        return err;
    }
    ESP_LOGI(TAG, "Inputs ready (ADS1115 analog frontend).");
    return ESP_OK;
#else
    xSemaphoreGive(s_lock);
    esp_err_t e = mcp23017_init();
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "MCP23017 init failed: %s", esp_err_to_name(e));
        return e;
    }
    ESP_LOGI(TAG, "Inputs ready (MCP23017).");
    return ESP_OK;
#endif
}

esp_err_t inputs_read_all(uint16_t *gpioab)
{
    if (!gpioab) {
        return ESP_ERR_INVALID_ARG;
    }
#if CONFIG_APP_INPUT_BACKEND_ADS1115
    return analog_sample(gpioab);
#else
    return mcp23017_read_gpioab(gpioab);
#endif
}