#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ROSTER_NODE_STATE_OFFLINE = 0,
    ROSTER_NODE_STATE_PREOP,
    ROSTER_NODE_STATE_OPERATIONAL,
} roster_node_state_t;

#define ROSTER_MAX_ZONES 8u

typedef struct {
    bool valid;
    uint8_t zone_index;
    uint8_t state_bits;
    uint16_t adc_raw;
    uint16_t rloop_ohm_div100;
    uint16_t vbias_100mv;
    uint8_t seq;
    uint64_t last_update_ms;
} roster_zone_telemetry_t;

typedef struct {
    bool valid;
    uint8_t alarm_bitmap;
    uint8_t short_bitmap;
    uint8_t open_bitmap;
    uint8_t tamper_bitmap;
    uint16_t vdda_10mv;
    uint16_t vbias_100mv;
    int16_t temp_c;
    uint8_t fw_version;
    uint64_t last_update_ms;
} roster_ext_status_t;

typedef struct {
    bool used;
    uint8_t node_id;
    char kind[16];
    char label[32];
    uint8_t uid[8];
    uint16_t model;
    uint16_t fw;
    uint16_t caps;
    uint8_t inputs_count;
    uint8_t outputs_count;
    uint32_t inputs_bitmap;
    uint32_t inputs_tamper_bitmap;
    uint32_t inputs_fault_bitmap;
    uint32_t outputs_bitmap;
    uint8_t change_counter;
    uint8_t node_state_flags;
    uint8_t outputs_flags;
    uint8_t outputs_pwm;
    roster_node_state_t state;
    uint64_t last_seen_ms;
    uint64_t associated_at_ms;
    bool identify_active;
    bool info_valid;
    bool inputs_valid;
    bool outputs_valid;
    roster_ext_status_t ext_status;
    roster_zone_telemetry_t zones[ROSTER_MAX_ZONES];
} roster_node_t;

typedef struct {
    const char *label;      /**< Optional label */
    const char *kind;       /**< Optional kind string */
    const uint8_t *uid;     /**< Optional pointer to UID (8 bytes) */
    bool has_uid;           /**< True if uid pointer is valid */
    uint16_t model;
    uint16_t fw;
    uint16_t caps;
    uint8_t inputs_count;
    uint8_t outputs_count;
} roster_node_info_t;

typedef struct {
    bool exists;            /**< True when the node slot is allocated */
    roster_node_state_t state;
    bool inputs_valid;
    uint32_t inputs_bitmap;
    uint32_t inputs_tamper_bitmap;
    uint32_t inputs_fault_bitmap;
    uint8_t change_counter;
    uint8_t node_state_flags;
    bool outputs_valid;
    uint32_t outputs_bitmap;
    uint8_t outputs_flags;
    uint8_t outputs_pwm;
} roster_io_state_t;

typedef struct {
    uint8_t node_id;
    uint8_t inputs_count;
    uint8_t outputs_count;
    bool inputs_valid;
    uint32_t inputs_bitmap;
    uint32_t inputs_tamper_bitmap;
    uint32_t inputs_fault_bitmap;
    uint16_t caps;
    roster_node_state_t state;
} roster_node_inputs_t;

void roster_init(uint8_t master_inputs, uint8_t master_outputs, uint16_t master_caps);
esp_err_t roster_reset(void);

esp_err_t roster_update_node(uint8_t node_id, const roster_node_info_t *info, bool *out_is_new);
esp_err_t roster_mark_online(uint8_t node_id, uint64_t now_ms, bool *out_is_new);
esp_err_t roster_mark_offline(uint8_t node_id, uint64_t now_ms);
esp_err_t roster_forget_node(uint8_t node_id);
esp_err_t roster_set_identify(uint8_t node_id, bool active, bool *out_changed);
bool roster_get_identify(uint8_t node_id, bool *out_active);
bool roster_node_exists(uint8_t node_id);
const roster_node_t *roster_get_node(uint8_t node_id);
bool roster_get_node_snapshot(uint8_t node_id, roster_node_t *out_snapshot);
esp_err_t roster_assign_node_id_from_uid(const uint8_t *uid, size_t uid_len, uint8_t *out_node_id, bool *out_is_new);
esp_err_t roster_note_inputs(uint8_t node_id,
                             uint32_t alarm_bitmap,
                             uint32_t tamper_bitmap,
                             uint32_t fault_bitmap,
                             uint8_t change_counter,
                             uint8_t node_state_flags,
                             bool has_extended);
esp_err_t roster_note_outputs(uint8_t node_id,
                              uint32_t outputs_bitmap,
                              uint8_t flags,
                              uint8_t pwm_level,
                              bool known);
esp_err_t roster_note_ext_status(uint8_t node_id,
                                 uint8_t alarm_bitmap,
                                 uint8_t short_bitmap,
                                 uint8_t open_bitmap,
                                 uint8_t tamper_bitmap,
                                 uint16_t vdda_10mv,
                                 uint16_t vbias_100mv,
                                 int16_t temp_c,
                                 uint8_t fw_version,
                                 uint64_t timestamp_ms);
esp_err_t roster_note_zone_event(uint8_t node_id,
                                 uint8_t zone_index,
                                 uint8_t state_bits,
                                 uint16_t adc_raw,
                                 uint16_t rloop_ohm_div100,
                                 uint16_t vbias_100mv,
                                 uint8_t seq,
                                 uint64_t timestamp_ms);
bool roster_get_io_state(uint8_t node_id, roster_io_state_t *out_state);
esp_err_t roster_reassign_node_id(uint8_t current_id, uint8_t new_id);
bool roster_get_ext_status(uint8_t node_id, roster_ext_status_t *out_status);
bool roster_get_zone_telemetry(uint8_t node_id,
                               uint8_t zone_index,
                               roster_zone_telemetry_t *out_zone);
esp_err_t roster_set_node_label(uint8_t node_id, const char *label);

size_t roster_collect_nodes(roster_node_inputs_t *out_nodes, size_t max_nodes);
uint16_t roster_total_inputs(void);
uint16_t roster_effective_zones(uint8_t master_inputs);

void roster_stats(size_t *out_total, size_t *out_online);
void roster_to_json(cJSON *out_array);
cJSON *roster_node_to_json(uint8_t node_id);

void roster_master_set_device_id(const char *device_id);
esp_err_t roster_master_set_registered_at(uint64_t registered_at_ms);
uint64_t roster_master_get_registered_at(void);

#ifdef __cplusplus
}
#endif