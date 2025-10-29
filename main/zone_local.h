#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "esp_err.h"

#include "zone_eol.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ZONE_LOCAL_MAX_ZONES 12u
#define ZONE_LOCAL_SUPPLY_DEFAULT_MV 3300.0f
#define ZONE_LOCAL_SUPPLY_MV        ZONE_LOCAL_SUPPLY_DEFAULT_MV

typedef struct {
    zone_eol_result_t result;
    zone_eol_mode_t   mode;
    bool alarm;
    bool tamper;
    bool fault;
    bool valid;
    uint8_t adc_index;
    uint8_t adc_channel;
} zone_local_zone_t;

typedef struct {
    uint8_t count;
    uint16_t alarm_mask;
    uint16_t tamper_mask;
    uint16_t fault_mask;
    zone_local_zone_t zones[ZONE_LOCAL_MAX_ZONES];
    float supply_mv;
    bool  supply_valid;
} zone_local_snapshot_t;

esp_err_t zone_local_init(void);
void zone_local_update(void);
void zone_local_get_snapshot(zone_local_snapshot_t *out_snapshot);
uint16_t zone_local_alarm_mask(void);
uint16_t zone_local_tamper_mask(void);
uint16_t zone_local_fault_mask(void);
uint8_t zone_local_zone_count(void);
float zone_local_supply_mv(void);
bool zone_local_supply_valid(void);

void zone_local_set_mode(uint8_t zone_index, zone_eol_mode_t mode);
zone_eol_mode_t zone_local_get_mode(uint8_t zone_index);
void zone_local_apply_modes(const zone_eol_mode_t *modes, size_t count);

#ifdef __cplusplus
}
#endif