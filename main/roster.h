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
    roster_node_state_t state;
    uint64_t last_seen_ms;
    bool identify_active;
    bool info_valid;
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

void roster_init(uint8_t master_inputs, uint8_t master_outputs, uint16_t master_caps);
esp_err_t roster_reset(void);

esp_err_t roster_update_node(uint8_t node_id, const roster_node_info_t *info, bool *out_is_new);
esp_err_t roster_mark_online(uint8_t node_id, uint64_t now_ms, bool *out_is_new);
esp_err_t roster_mark_offline(uint8_t node_id, uint64_t now_ms);
esp_err_t roster_set_identify(uint8_t node_id, bool active, bool *out_changed);
bool roster_get_identify(uint8_t node_id, bool *out_active);
bool roster_node_exists(uint8_t node_id);
const roster_node_t *roster_get_node(uint8_t node_id);

void roster_stats(size_t *out_total, size_t *out_online);
void roster_to_json(cJSON *out_array);
cJSON *roster_node_to_json(uint8_t node_id);

#ifdef __cplusplus
}
#endif