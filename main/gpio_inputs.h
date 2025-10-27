#pragma once

#include "pins.h"
#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

#define INPUTS_MAX_ZONES 12

typedef enum {
    ZONE_MEASURE_DIGITAL = 0,
    ZONE_MEASURE_EOL1,
    ZONE_MEASURE_EOL2,
    ZONE_MEASURE_EOL3,
} zone_measure_mode_t;

typedef enum {
    ZONE_CONTACT_NC = 0,
    ZONE_CONTACT_NO = 1,
} zone_contact_t;

typedef enum {
    ZONE_STATUS_UNKNOWN = 0,
    ZONE_STATUS_NORMAL,
    ZONE_STATUS_ALARM,
    ZONE_STATUS_TAMPER,
    ZONE_STATUS_FAULT_SHORT,
    ZONE_STATUS_FAULT_OPEN,
} zone_status_t;

typedef struct {
    zone_measure_mode_t mode;
    zone_contact_t      contact;
} zone_measure_cfg_t;

typedef struct {
    float    r_normal;
    float    r_alarm;
    float    r_tamper;
    float    r_eol;
    float    short_threshold;
    float    open_threshold;
    uint16_t debounce_ms;
    float    hysteresis_pct;
} zone_measure_globals_t;

typedef struct {
    zone_status_t status;
    float         vz;
    float         vbias;
    float         rloop;
    int16_t       code;
    bool          present;
    uint64_t      timestamp_us;
} zone_diag_entry_t;

typedef struct {
    int               total_zones;
    zone_diag_entry_t entries[INPUTS_MAX_ZONES];
} inputs_diag_snapshot_t;

esp_err_t inputs_init(void);
esp_err_t inputs_read_all(uint16_t *gpioab);

uint8_t        inputs_master_zone_count(void);
zone_status_t  inputs_zone_status(int zone_index_1_based);
void           inputs_get_measure_cfg(int zone_index_1_based, zone_measure_cfg_t *out_cfg);
esp_err_t      inputs_set_measure_cfg(int zone_index_1_based, const zone_measure_cfg_t *cfg);
void           inputs_get_measure_globals(zone_measure_globals_t *out_globals);
esp_err_t      inputs_set_measure_globals(const zone_measure_globals_t *globals);
esp_err_t      inputs_get_diagnostics(inputs_diag_snapshot_t *out_snapshot);

static inline bool inputs_zone_bit(uint16_t gpioab, int z)
{
    if (z < 1 || z > INPUTS_MAX_ZONES) {
        return false;
    }
    return ((gpioab & (1u << (z - 1))) != 0);
}

static inline bool inputs_tamper(uint16_t gpioab)
{
    return ((gpioab & (1u << (8 + MCPB_TAMPER_BIT))) != 0);
}