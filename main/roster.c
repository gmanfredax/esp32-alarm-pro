#include "roster.h"
#include "alarm_core.h"

#include <string.h>
#include <stdio.h>
#include <limits.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_timer.h"

#define ROSTER_MAX_NODES 128u

typedef struct {
    char label[32];
    char kind[16];
    uint16_t caps;
    uint8_t inputs_count;
    uint8_t outputs_count;
    uint64_t last_seen_ms;
} roster_master_info_t;

static roster_master_info_t s_master = {
    .label = "Centrale",
    .kind = "master",
    .caps = 0,
    .inputs_count = 0,
    .outputs_count = 0,
    .last_seen_ms = 0,
};

static roster_node_t s_nodes[ROSTER_MAX_NODES];
static SemaphoreHandle_t s_roster_lock = NULL;

static SemaphoreHandle_t ensure_lock(void)
{
    if (!s_roster_lock) {
        s_roster_lock = xSemaphoreCreateMutex();
    }
    return s_roster_lock;
}

static const char *state_to_string(roster_node_state_t state)
{
    switch (state) {
        case ROSTER_NODE_STATE_OFFLINE:      return "OFFLINE";
        case ROSTER_NODE_STATE_PREOP:        return "PREOP";
        case ROSTER_NODE_STATE_OPERATIONAL:  return "ONLINE";
        default:                             return "UNKNOWN";
    }
}

static roster_node_t *node_slot(uint8_t node_id)
{
    if (node_id >= ROSTER_MAX_NODES) {
        return NULL;
    }
    return &s_nodes[node_id];
}

static void node_init_defaults(roster_node_t *node, uint8_t node_id)
{
    if (!node) return;
    memset(node, 0, sizeof(*node));
    node->used = true;
    node->node_id = node_id;
    node->state = ROSTER_NODE_STATE_OFFLINE;
    node->identify_active = false;
    node->inputs_valid = false;
    node->outputs_valid = false;
    node->inputs_bitmap = 0;
    node->outputs_bitmap = 0;
    node->change_counter = 0;
    node->node_state_flags = 0;
    node->outputs_flags = 0;
    node->outputs_pwm = 0;
    snprintf(node->kind, sizeof(node->kind), "%s", "exp");
    snprintf(node->label, sizeof(node->label), "Exp %u", (unsigned)node_id);
}

void roster_init(uint8_t master_inputs, uint8_t master_outputs, uint16_t master_caps)
{
    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);
    memset(s_nodes, 0, sizeof(s_nodes));
    strncpy(s_master.label, "Centrale", sizeof(s_master.label) - 1);
    strncpy(s_master.kind, "master", sizeof(s_master.kind) - 1);
    s_master.caps = master_caps;
    s_master.inputs_count = master_inputs;
    s_master.outputs_count = master_outputs;
    s_master.last_seen_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);
    xSemaphoreGive(s_roster_lock);
}

esp_err_t roster_reset(void)
{
    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);
    memset(s_nodes, 0, sizeof(s_nodes));
    xSemaphoreGive(s_roster_lock);
    return ESP_OK;
}

esp_err_t roster_update_node(uint8_t node_id, const roster_node_info_t *info, bool *out_is_new)
{
    if (node_id == 0 || !info) {
        return ESP_ERR_INVALID_ARG;
    }
    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);
    roster_node_t *node = node_slot(node_id);
    if (!node) {
        xSemaphoreGive(s_roster_lock);
        return ESP_ERR_INVALID_ARG;
    }
    bool was_used = node->used;
    if (!was_used) {
        node_init_defaults(node, node_id);
    }

    if (info->label) {
        strncpy(node->label, info->label, sizeof(node->label) - 1);
        node->label[sizeof(node->label) - 1] = '\0';
    }
    if (info->kind) {
        strncpy(node->kind, info->kind, sizeof(node->kind) - 1);
        node->kind[sizeof(node->kind) - 1] = '\0';
    }
    if (info->has_uid && info->uid) {
        memcpy(node->uid, info->uid, sizeof(node->uid));
        node->info_valid = true;
    }
    node->model = info->model;
    node->fw = info->fw;
    node->caps = info->caps;
    node->inputs_count = info->inputs_count;
    node->outputs_count = info->outputs_count;
    if (!was_used && node->last_seen_ms == 0) {
        node->last_seen_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);
    }
    bool is_new = !was_used;
    node->used = true;
    xSemaphoreGive(s_roster_lock);
    if (out_is_new) {
        *out_is_new = is_new;
    }
    return ESP_OK;
}

esp_err_t roster_mark_online(uint8_t node_id, uint64_t now_ms, bool *out_is_new)
{
    if (node_id == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);
    roster_node_t *node = node_slot(node_id);
    if (!node) {
        xSemaphoreGive(s_roster_lock);
        return ESP_ERR_INVALID_ARG;
    }
    bool was_used = node->used;
    if (!was_used) {
        node_init_defaults(node, node_id);
    }
    bool was_online = (node->state == ROSTER_NODE_STATE_OPERATIONAL);
    node->state = ROSTER_NODE_STATE_OPERATIONAL;
    if (now_ms == 0) {
        now_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);
    }
    node->last_seen_ms = now_ms;
    node->used = true;
    bool is_new = !was_used;
    xSemaphoreGive(s_roster_lock);
    if (out_is_new) {
        *out_is_new = is_new;
    }
    (void)was_online;
    return ESP_OK;
}

esp_err_t roster_mark_offline(uint8_t node_id, uint64_t now_ms)
{
    if (node_id == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);
    roster_node_t *node = node_slot(node_id);
    if (!node || !node->used) {
        xSemaphoreGive(s_roster_lock);
        return ESP_ERR_NOT_FOUND;
    }
    if (now_ms == 0) {
        now_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);
    }
    node->state = ROSTER_NODE_STATE_OFFLINE;
    node->last_seen_ms = now_ms;
    xSemaphoreGive(s_roster_lock);
    return ESP_OK;
}

esp_err_t roster_forget_node(uint8_t node_id)
{
    if (node_id == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);
    roster_node_t *node = node_slot(node_id);
    if (!node || !node->used) {
        xSemaphoreGive(s_roster_lock);
        return ESP_ERR_NOT_FOUND;
    }
    memset(node, 0, sizeof(*node));
    xSemaphoreGive(s_roster_lock);
    return ESP_OK;
}

esp_err_t roster_set_identify(uint8_t node_id, bool active, bool *out_changed)
{
    if (node_id == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);
    roster_node_t *node = node_slot(node_id);
    if (!node || !node->used) {
        xSemaphoreGive(s_roster_lock);
        return ESP_ERR_NOT_FOUND;
    }
    bool changed = (node->identify_active != active);
    node->identify_active = active;
    xSemaphoreGive(s_roster_lock);
    if (out_changed) {
        *out_changed = changed;
    }
    return ESP_OK;
}

bool roster_get_identify(uint8_t node_id, bool *out_active)
{
    if (node_id == 0) {
        return false;
    }
    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);
    roster_node_t *node = node_slot(node_id);
    bool ok = (node && node->used);
    bool active = false;
    if (ok) {
        active = node->identify_active;
    }
    xSemaphoreGive(s_roster_lock);
    if (ok && out_active) {
        *out_active = active;
    }
    return ok;
}

bool roster_node_exists(uint8_t node_id)
{
    if (node_id == 0) {
        return false;
    }
    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);
    roster_node_t *node = node_slot(node_id);
    bool exists = (node && node->used);
    xSemaphoreGive(s_roster_lock);
    return exists;
}

const roster_node_t *roster_get_node(uint8_t node_id)
{
    if (node_id >= ROSTER_MAX_NODES) {
        return NULL;
    }
    return &s_nodes[node_id];
}

esp_err_t roster_assign_node_id_from_uid(const uint8_t *uid, size_t uid_len, uint8_t *out_node_id, bool *out_is_new)
{
    if (!uid || uid_len == 0 || uid_len > sizeof(((roster_node_t *)0)->uid) || !out_node_id) {
        return ESP_ERR_INVALID_ARG;
    }

    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);

    for (uint32_t i = 1; i < ROSTER_MAX_NODES; ++i) {
        roster_node_t *node = &s_nodes[i];
        if (!node->used) {
            continue;
        }
        if (memcmp(node->uid, uid, uid_len) == 0) {
            *out_node_id = (uint8_t)i;
            if (out_is_new) {
                *out_is_new = false;
            }
            xSemaphoreGive(s_roster_lock);
            return ESP_OK;
        }
    }

    for (uint32_t i = 1; i < ROSTER_MAX_NODES; ++i) {
        roster_node_t *node = &s_nodes[i];
        if (node->used) {
            continue;
        }
        node_init_defaults(node, (uint8_t)i);
        memset(node->uid, 0, sizeof(node->uid));
        memcpy(node->uid, uid, uid_len);
        node->info_valid = true;
        node->state = ROSTER_NODE_STATE_PREOP;
        node->used = true;
        *out_node_id = (uint8_t)i;
        if (out_is_new) {
            *out_is_new = true;
        }
        xSemaphoreGive(s_roster_lock);
        return ESP_OK;
    }

    xSemaphoreGive(s_roster_lock);
    return ESP_ERR_NO_MEM;
}

void roster_stats(size_t *out_total, size_t *out_online)
{
    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);
    size_t total = 0;
    size_t online = 0;
    for (uint32_t i = 1; i < ROSTER_MAX_NODES; ++i) {
        roster_node_t *node = &s_nodes[i];
        if (!node->used) continue;
        ++total;
        if (node->state == ROSTER_NODE_STATE_OPERATIONAL) {
            ++online;
        }
    }
    xSemaphoreGive(s_roster_lock);
    if (out_total) *out_total = total;
    if (out_online) *out_online = online;
}

static void add_common_fields(cJSON *obj, const roster_node_t *node)
{
    cJSON_AddNumberToObject(obj, "node_id", node->node_id);
    cJSON_AddStringToObject(obj, "kind", node->kind[0] ? node->kind : "exp");
    cJSON_AddStringToObject(obj, "label", node->label);
    if (node->info_valid) {
        char uid_str[17];
        for (size_t i = 0; i < sizeof(node->uid); ++i) {
            snprintf(uid_str + (i * 2), sizeof(uid_str) - (i * 2), "%02X", node->uid[i]);
        }
        uid_str[16] = '\0';
        cJSON_AddStringToObject(obj, "uid", uid_str);
    }
    cJSON_AddNumberToObject(obj, "model", node->model);
    cJSON_AddNumberToObject(obj, "fw", node->fw);
    cJSON_AddNumberToObject(obj, "caps", node->caps);
    cJSON_AddNumberToObject(obj, "inputs_count", node->inputs_count);
    cJSON_AddNumberToObject(obj, "outputs_count", node->outputs_count);
    cJSON_AddBoolToObject(obj, "inputs_known", node->inputs_valid);
    if (node->inputs_valid) {
        cJSON_AddNumberToObject(obj, "inputs_bitmap", (double)node->inputs_bitmap);
    }
    cJSON_AddNumberToObject(obj, "change_counter", node->change_counter);
    cJSON_AddNumberToObject(obj, "node_state_flags", node->node_state_flags);
    cJSON_AddBoolToObject(obj, "outputs_known", node->outputs_valid);
    if (node->outputs_valid) {
        cJSON_AddNumberToObject(obj, "outputs_bitmap", (double)node->outputs_bitmap);
    }
    cJSON_AddNumberToObject(obj, "outputs_flags", node->outputs_flags);
    cJSON_AddNumberToObject(obj, "outputs_pwm", node->outputs_pwm);
    cJSON_AddStringToObject(obj, "state", state_to_string(node->state));
    cJSON_AddNumberToObject(obj, "last_seen_ms", (double)node->last_seen_ms);
    cJSON_AddBoolToObject(obj, "identify_active", node->identify_active);
}

void roster_to_json(cJSON *out_array)
{
    if (!out_array) return;
    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);

    cJSON *master = cJSON_CreateObject();
    if (master) {
        cJSON_AddNumberToObject(master, "node_id", 0);
        cJSON_AddStringToObject(master, "kind", s_master.kind);
        cJSON_AddStringToObject(master, "label", s_master.label);
        cJSON_AddNumberToObject(master, "inputs_count", s_master.inputs_count);
        cJSON_AddNumberToObject(master, "outputs_count", s_master.outputs_count);
        cJSON_AddNumberToObject(master, "caps", s_master.caps);
        cJSON_AddStringToObject(master, "state", "ONLINE");
        cJSON_AddNumberToObject(master, "last_seen_ms", (double)s_master.last_seen_ms);
        cJSON_AddBoolToObject(master, "identify_active", false);
        cJSON_AddItemToArray(out_array, master);
    }

    for (uint32_t i = 1; i < ROSTER_MAX_NODES; ++i) {
        roster_node_t *node = &s_nodes[i];
        if (!node->used) continue;
        cJSON *obj = cJSON_CreateObject();
        if (!obj) continue;
        add_common_fields(obj, node);
        cJSON_AddItemToArray(out_array, obj);
    }

    xSemaphoreGive(s_roster_lock);
}

cJSON *roster_node_to_json(uint8_t node_id)
{
    if (node_id == 0) {
        ensure_lock();
        xSemaphoreTake(s_roster_lock, portMAX_DELAY);
        cJSON *obj = cJSON_CreateObject();
        if (obj) {
            cJSON_AddNumberToObject(obj, "node_id", 0);
            cJSON_AddStringToObject(obj, "kind", s_master.kind);
            cJSON_AddStringToObject(obj, "label", s_master.label);
            cJSON_AddNumberToObject(obj, "inputs_count", s_master.inputs_count);
            cJSON_AddNumberToObject(obj, "outputs_count", s_master.outputs_count);
            cJSON_AddNumberToObject(obj, "caps", s_master.caps);
            cJSON_AddStringToObject(obj, "state", "ONLINE");
            cJSON_AddNumberToObject(obj, "last_seen_ms", (double)s_master.last_seen_ms);
            cJSON_AddBoolToObject(obj, "identify_active", false);
        }
        xSemaphoreGive(s_roster_lock);
        return obj;
    }

    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);
    roster_node_t *node = node_slot(node_id);
    if (!node || !node->used) {
        xSemaphoreGive(s_roster_lock);
        return NULL;
    }
    roster_node_t snapshot = *node;
    xSemaphoreGive(s_roster_lock);

    cJSON *obj = cJSON_CreateObject();
    if (!obj) {
        return NULL;
    }
    add_common_fields(obj, &snapshot);
    return obj;
}

esp_err_t roster_note_inputs(uint8_t node_id,
                             uint32_t inputs_bitmap,
                             uint8_t change_counter,
                             uint8_t node_state_flags)
{
    if (node_id == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);
    roster_node_t *node = node_slot(node_id);
    if (!node) {
        xSemaphoreGive(s_roster_lock);
        return ESP_ERR_INVALID_ARG;
    }
    if (!node->used) {
        node_init_defaults(node, node_id);
    }
    node->inputs_valid = true;
    node->inputs_bitmap = inputs_bitmap;
    node->change_counter = change_counter;
    node->node_state_flags = node_state_flags;
    xSemaphoreGive(s_roster_lock);
    return ESP_OK;
}

esp_err_t roster_note_outputs(uint8_t node_id,
                              uint32_t outputs_bitmap,
                              uint8_t flags,
                              uint8_t pwm_level,
                              bool known)
{
    if (node_id == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);
    roster_node_t *node = node_slot(node_id);
    if (!node || !node->used) {
        xSemaphoreGive(s_roster_lock);
        return ESP_ERR_NOT_FOUND;
    }
    node->outputs_bitmap = outputs_bitmap;
    node->outputs_flags = flags;
    node->outputs_pwm = pwm_level;
    node->outputs_valid = known;
    xSemaphoreGive(s_roster_lock);
    return ESP_OK;
}

bool roster_get_io_state(uint8_t node_id, roster_io_state_t *out_state)
{
    if (!out_state) {
        return false;
    }
    if (node_id == 0) {
        memset(out_state, 0, sizeof(*out_state));
        out_state->exists = false;
        out_state->state = ROSTER_NODE_STATE_OFFLINE;
        return false;
    }

    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);
    roster_node_t *node = node_slot(node_id);
    bool ok = (node && node->used);
    if (ok) {
        out_state->exists = true;
        out_state->state = node->state;
        out_state->inputs_valid = node->inputs_valid;
        out_state->inputs_bitmap = node->inputs_bitmap;
        out_state->change_counter = node->change_counter;
        out_state->node_state_flags = node->node_state_flags;
        out_state->outputs_valid = node->outputs_valid;
        out_state->outputs_bitmap = node->outputs_bitmap;
        out_state->outputs_flags = node->outputs_flags;
        out_state->outputs_pwm = node->outputs_pwm;
    }
    xSemaphoreGive(s_roster_lock);
    if (!ok) {
        memset(out_state, 0, sizeof(*out_state));
        out_state->exists = false;
        out_state->state = ROSTER_NODE_STATE_OFFLINE;
    }
    return ok;
}

size_t roster_collect_nodes(roster_node_inputs_t *out_nodes, size_t max_nodes)
{
    if (!out_nodes || max_nodes == 0) {
        return 0;
    }

    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);

    size_t count = 0;
    for (uint32_t i = 1; i < ROSTER_MAX_NODES && count < max_nodes; ++i) {
        const roster_node_t *node = &s_nodes[i];
        if (!node->used) {
            continue;
        }
        roster_node_inputs_t *dst = &out_nodes[count++];
        dst->node_id = node->node_id;
        dst->inputs_count = node->inputs_count;
        dst->outputs_count = node->outputs_count;
        dst->inputs_valid = node->inputs_valid;
        dst->inputs_bitmap = node->inputs_bitmap;
        dst->state = node->state;
    }

    xSemaphoreGive(s_roster_lock);
    return count;
}

uint16_t roster_total_inputs(void)
{
    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);
    uint32_t total = 0;
    for (uint32_t i = 1; i < ROSTER_MAX_NODES; ++i) {
        const roster_node_t *node = &s_nodes[i];
        if (!node->used) {
            continue;
        }
        total += node->inputs_count;
    }
    xSemaphoreGive(s_roster_lock);
    if (total > UINT16_MAX) {
        total = UINT16_MAX;
    }
    return (uint16_t)total;
}

uint16_t roster_effective_zones(uint8_t master_inputs)
{
    uint32_t total = (uint32_t)master_inputs;
    total += (uint32_t)roster_total_inputs();
    if (total > ALARM_MAX_ZONES) {
        total = ALARM_MAX_ZONES;
    }
    return (uint16_t)total;
}