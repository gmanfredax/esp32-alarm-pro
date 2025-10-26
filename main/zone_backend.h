#pragma once

#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ZONE_BACKEND_MAX_ZONES
#define ZONE_BACKEND_MAX_ZONES 12u
#endif

typedef enum {
    ZONE_BACKEND_DIGITAL_MCP23017 = 0,
    ZONE_BACKEND_ANALOG_3X_ADS1115 = 1,
} zone_backend_type_t;

typedef enum {
    ZONE_MODE_DIGITAL = 0,
    ZONE_MODE_EOL1,
    ZONE_MODE_EOL2,
    ZONE_MODE_EOL3,
} zone_mode_t;

typedef enum {
    ZONE_CONTACT_NC = 0,
    ZONE_CONTACT_NO = 1,
} zone_contact_t;

typedef struct {
    zone_mode_t    mode;
    zone_contact_t contact;
    uint16_t       r_normal_ohm;   // R_N
    uint16_t       r_alarm_ohm;    // R_A
    uint16_t       r_tamper_ohm;   // R_T
    uint16_t       r_eol_ohm;      // R_E (EOL1 reference)
    uint16_t       debounce_ms;
    uint16_t       hyst_pct;
    uint16_t       short_ohm;
    uint16_t       open_ohm;
} zone_backend_cfg_t;

typedef struct {
    bool     present;
    bool     alarm;
    bool     fault_short;
    bool     fault_open;
    bool     tamper;
    uint16_t rloop_ohm_100;
    int16_t  adc_raw;
    float    vz_V;
    float    vbias_V;
    zone_mode_t mode;
} zone_backend_zone_state_t;

typedef struct {
    zone_backend_type_t backend;
    uint8_t             zone_count;
    bool                tamper_input;
    uint16_t            gpio_raw;
    float               vbias_V;
    uint64_t            timestamp_us;
    zone_backend_zone_state_t zones[ZONE_BACKEND_MAX_ZONES];
} zone_backend_snapshot_t;

esp_err_t            zone_backend_init(void);
zone_backend_type_t  zone_backend_current(void);
const char*          zone_backend_type_label(zone_backend_type_t backend);
esp_err_t            zone_backend_set(zone_backend_type_t backend, bool persist);
esp_err_t            zone_backend_poll(zone_backend_snapshot_t *snapshot, bool force_refresh);
uint8_t              zone_backend_master_zones(void);
bool                 zone_backend_tamper_active(void);

esp_err_t            zone_backend_get_cfg(uint8_t zone_index_1_based, zone_backend_cfg_t *cfg);
esp_err_t            zone_backend_set_cfg(uint8_t zone_index_1_based, const zone_backend_cfg_t *cfg, bool persist);
void                 zone_backend_get_defaults(zone_backend_cfg_t *cfg);

#ifdef __cplusplus
}
#endif