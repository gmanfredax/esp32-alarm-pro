#include "roster.h"
#include "alarm_core.h"
#include "device_identity.h"
#include "utils.h"

#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <ctype.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "nvs.h"

#define ROSTER_MAX_NODES 128u
#define ROSTER_NVS_NAMESPACE "roster"
#define ROSTER_NVS_KEY_UID_MAP "uid_map"
#define ROSTER_UID_MAP_VERSION 2u
#define ROSTER_NVS_KEY_LABEL_MAP "label_map"
#define ROSTER_LABEL_MAP_VERSION 1u
#define ROSTER_NVS_KEY_MASTER_REG "master_reg_ms"
#define ROSTER_WALL_TIME_MIN_MS 946684800000ULL

#define ROSTER_UID_LEN (sizeof(((roster_node_t *)0)->uid))
#define ROSTER_UID_RECORD_SIZE (1u + ROSTER_UID_LEN + sizeof(uint64_t))

static const char *TAG = "roster";

enum {
    CAN_EXT_ZONE_STATE_ALARM      = 0x01u,
    CAN_EXT_ZONE_STATE_SHORT      = 0x02u,
    CAN_EXT_ZONE_STATE_OPEN       = 0x04u,
    CAN_EXT_ZONE_STATE_TAMPER     = 0x08u,
    CAN_EXT_ZONE_STATE_PRESENT    = 0x10u,
    CAN_EXT_ZONE_STATE_CONTACT_NO = 0x20u,
};

typedef struct {
    bool used;
    uint8_t node_id;
    uint8_t uid[ROSTER_UID_LEN];
    uint64_t associated_at_ms;
} roster_uid_entry_t;

typedef struct {
    char label[32];
    char kind[16];
    uint16_t caps;
    uint8_t inputs_count;
    uint8_t outputs_count;
    uint64_t last_seen_ms;
    uint64_t registered_at_ms;
    char device_id[DEVICE_ID_MAX];
} roster_master_info_t;

static roster_master_info_t s_master = {
    .label = "Centrale",
    .kind = "master",
    .caps = 0,
    .inputs_count = 0,
    .outputs_count = 0,
    .last_seen_ms = 0,
    .registered_at_ms = 0,
    .device_id = "",
};

static roster_node_t s_nodes[ROSTER_MAX_NODES];
static roster_uid_entry_t s_uid_map[ROSTER_MAX_NODES];

typedef struct {
    bool used;
    char label[sizeof(((roster_node_t *)0)->label)];
} roster_label_entry_t;

static roster_label_entry_t s_label_map[ROSTER_MAX_NODES];
static SemaphoreHandle_t s_roster_lock = NULL;

static bool uid_map_set_internal(uint8_t node_id, const uint8_t *uid, uint64_t associated_at_ms);

typedef struct __attribute__((packed)) {
    uint8_t node_id;
    uint8_t uid[ROSTER_UID_LEN];
    uint64_t associated_at_ms;
} roster_uid_record_t;

static esp_err_t uid_map_save_locked(void)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(ROSTER_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "nvs_open(%s) failed: %s", ROSTER_NVS_NAMESPACE, esp_err_to_name(err));
        return err;
    }

    uint8_t blob[2 + ROSTER_MAX_NODES * ROSTER_UID_RECORD_SIZE];
    memset(blob, 0, sizeof(blob));
    blob[0] = ROSTER_UID_MAP_VERSION;
    size_t offset = 2;
    uint8_t count = 0;

    for (size_t i = 0; i < ROSTER_MAX_NODES; ++i) {
        const roster_uid_entry_t *entry = &s_uid_map[i];
        if (!entry->used) {
            continue;
        }
        if (count >= ROSTER_MAX_NODES) {
            break;
        }
        blob[offset++] = entry->node_id;
        memcpy(blob + offset, entry->uid, ROSTER_UID_LEN);
        offset += ROSTER_UID_LEN;
        uint64_t ts = entry->associated_at_ms;
        memcpy(blob + offset, &ts, sizeof(ts));
        offset += sizeof(ts);
        ++count;
    }

    blob[1] = count;
    size_t blob_size = offset;
    if (blob_size < 2) {
        blob_size = 2;
    }

    err = nvs_set_blob(handle, ROSTER_NVS_KEY_UID_MAP, blob, blob_size);
    if (err == ESP_ERR_NVS_NOT_ENOUGH_SPACE) {
        esp_err_t erase_err = nvs_erase_key(handle, ROSTER_NVS_KEY_UID_MAP);
        if (erase_err != ESP_OK && erase_err != ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGW(TAG, "Failed to erase UID map blob before retry: %s", esp_err_to_name(erase_err));
        } else {
            err = nvs_set_blob(handle, ROSTER_NVS_KEY_UID_MAP, blob, blob_size);
        }
    }
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to persist CAN UID map: %s", esp_err_to_name(err));
    }

    nvs_close(handle);
    return err;
}

static bool roster_timestamp_is_valid(uint64_t ts_ms)
{
    return ts_ms >= ROSTER_WALL_TIME_MIN_MS;
}

static uint64_t roster_sanitize_wall_time(uint64_t ts_ms)
{
    return roster_timestamp_is_valid(ts_ms) ? ts_ms : 0;
}

static uint64_t roster_current_wall_time_ms(void)
{
    uint64_t now_ms = utils_wall_time_ms();
    return roster_sanitize_wall_time(now_ms);
}

static void uid_map_load_locked(void)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(ROSTER_NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        if (err != ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGW(TAG, "nvs_open(%s) for read failed: %s", ROSTER_NVS_NAMESPACE, esp_err_to_name(err));
        }
        return;
    }

    uint8_t blob[2 + ROSTER_MAX_NODES * ROSTER_UID_RECORD_SIZE];
    size_t required = sizeof(blob);
    err = nvs_get_blob(handle, ROSTER_NVS_KEY_UID_MAP, blob, &required);
    bool rewrite = false;
    memset(s_uid_map, 0, sizeof(s_uid_map));

    if (err == ESP_ERR_NVS_NOT_FOUND) {
        // nothing stored
    } else if (err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to load CAN UID map: %s", esp_err_to_name(err));
    } else if (required >= 2) {
        uint8_t version = blob[0];
        uint8_t count = blob[1];
        const uint8_t *cursor = blob + 2;
        size_t remaining = required >= 2 ? required - 2 : 0;
        if (count > ROSTER_MAX_NODES) {
            ESP_LOGW(TAG, "Invalid CAN UID map count %u", (unsigned)count);
            count = 0;
        }

        if (version == ROSTER_UID_MAP_VERSION) {
            size_t needed = ((size_t)count) * ROSTER_UID_RECORD_SIZE;
            if (remaining < needed) {
                ESP_LOGW(TAG, "CAN UID map blob too small (%zu < %zu)", remaining, needed);
            } else {
                for (size_t i = 0; i < count; ++i) {
                    if (remaining < ROSTER_UID_RECORD_SIZE) {
                        break;
                    }
                    uint8_t node_id = *cursor++;
                    remaining -= 1;
                    if (node_id == 0 || node_id >= ROSTER_MAX_NODES) {
                        cursor += ROSTER_UID_LEN + sizeof(uint64_t);
                        remaining -= (ROSTER_UID_LEN + sizeof(uint64_t));
                        continue;
                    }
                    roster_uid_entry_t *entry = NULL;
                    for (size_t j = 0; j < ROSTER_MAX_NODES; ++j) {
                        if (!s_uid_map[j].used) {
                            entry = &s_uid_map[j];
                            break;
                        }
                    }
                    if (!entry) {
                        cursor += ROSTER_UID_LEN + sizeof(uint64_t);
                        remaining -= (ROSTER_UID_LEN + sizeof(uint64_t));
                        continue;
                    }
                    entry->used = true;
                    entry->node_id = node_id;
                    memcpy(entry->uid, cursor, ROSTER_UID_LEN);
                    cursor += ROSTER_UID_LEN;
                    remaining -= ROSTER_UID_LEN;
                    memcpy(&entry->associated_at_ms, cursor, sizeof(uint64_t));
                    cursor += sizeof(uint64_t);
                    remaining -= sizeof(uint64_t);
                    uint64_t sanitized = roster_sanitize_wall_time(entry->associated_at_ms);
                    if (sanitized != entry->associated_at_ms) {
                        entry->associated_at_ms = sanitized;
                        rewrite = true;
                    }
                }
            }
        } else if (version == 1u) {
            size_t legacy_record = 1u + ROSTER_UID_LEN;
            size_t needed = ((size_t)count) * legacy_record;
            if (remaining < needed) {
                ESP_LOGW(TAG, "Legacy CAN UID map blob too small (%zu < %zu)", remaining, needed);
            } else {
                for (size_t i = 0; i < count; ++i) {
                    if (remaining < legacy_record) {
                        break;
                    }
                    uint8_t node_id = *cursor++;
                    remaining -= 1;
                    if (node_id == 0 || node_id >= ROSTER_MAX_NODES) {
                        cursor += ROSTER_UID_LEN;
                        remaining -= ROSTER_UID_LEN;
                        continue;
                    }
                    roster_uid_entry_t *entry = NULL;
                    for (size_t j = 0; j < ROSTER_MAX_NODES; ++j) {
                        if (!s_uid_map[j].used) {
                            entry = &s_uid_map[j];
                            break;
                        }
                    }
                    if (!entry) {
                        cursor += ROSTER_UID_LEN;
                        remaining -= ROSTER_UID_LEN;
                        continue;
                    }
                    entry->used = true;
                    entry->node_id = node_id;
                    memcpy(entry->uid, cursor, ROSTER_UID_LEN);
                    cursor += ROSTER_UID_LEN;
                    remaining -= ROSTER_UID_LEN;
                    entry->associated_at_ms = 0;
                }
                rewrite = true;
            }
        } else {
            ESP_LOGW(TAG, "Unknown CAN UID map version %u", (unsigned)version);
        }
    }

    nvs_close(handle);

    for (size_t i = 0; i < ROSTER_MAX_NODES; ++i) {
        roster_uid_entry_t *entry = &s_uid_map[i];
        if (!entry->used) {
            continue;
        }
        if (entry->node_id == 0 || entry->node_id >= ROSTER_MAX_NODES) {
            memset(entry, 0, sizeof(*entry));
        }
    }

    if (rewrite) {
        uid_map_save_locked();
    }
}

static uint64_t master_load_registered_at(void)
{
    nvs_handle_t handle;
    uint64_t value = 0;
    if (nvs_open(ROSTER_NVS_NAMESPACE, NVS_READONLY, &handle) == ESP_OK) {
        uint64_t stored = 0;
        if (nvs_get_u64(handle, ROSTER_NVS_KEY_MASTER_REG, &stored) == ESP_OK) {
            uint64_t sanitized = roster_sanitize_wall_time(stored);
            value = sanitized;
            if (sanitized != stored) {
                nvs_close(handle);
                if (nvs_open(ROSTER_NVS_NAMESPACE, NVS_READWRITE, &handle) == ESP_OK) {
                    esp_err_t err = nvs_set_u64(handle, ROSTER_NVS_KEY_MASTER_REG, sanitized);
                    if (err == ESP_OK) {
                        err = nvs_commit(handle);
                    }
                    if (err != ESP_OK) {
                        ESP_LOGW(TAG, "Failed to rewrite master registered_at: %s", esp_err_to_name(err));
                    }
                    nvs_close(handle);
                } else {
                    ESP_LOGW(TAG, "Failed to reopen NVS to rewrite master registered_at");
                }
                return value;
            }
        }
        nvs_close(handle);
    }
    return value;
}

typedef struct {
    uint8_t node_id;
    char label[sizeof(((roster_node_t *)0)->label)];
} roster_label_record_t;

static size_t label_trim_copy(char *dst, size_t dst_len, const char *src)
{
    if (!dst || dst_len == 0) {
        return 0;
    }
    dst[0] = '\0';
    if (!src) {
        return 0;
    }

    const char *start = src;
    while (*start && isspace((unsigned char)*start)) {
        ++start;
    }

    const char *cursor = start;
    const char *last_non_space = NULL;
    size_t processed = 0;
    while (*cursor && processed < 255) {
        if (!isspace((unsigned char)*cursor)) {
            last_non_space = cursor;
        }
        ++cursor;
        ++processed;
    }

    size_t length = 0;
    if (last_non_space) {
        length = (size_t)(last_non_space - start + 1);
    }
    if (length == 0) {
        dst[0] = '\0';
        return 0;
    }
    if (length >= dst_len) {
        length = dst_len - 1;
    }
    memcpy(dst, start, length);
    dst[length] = '\0';
    return length;
}

static bool label_map_set_internal(uint8_t node_id, const char *label)
{
    if (node_id == 0 || node_id >= ROSTER_MAX_NODES) {
        return false;
    }
    roster_label_entry_t *entry = &s_label_map[node_id];
    char normalized[sizeof(entry->label)];
    size_t len = label_trim_copy(normalized, sizeof(normalized), label);
    if (len == 0) {
        if (!entry->used) {
            return false;
        }
        entry->used = false;
        memset(entry->label, 0, sizeof(entry->label));
        return true;
    }

    if (entry->used && strncmp(entry->label, normalized, sizeof(entry->label)) == 0) {
        return false;
    }

    entry->used = true;
    memset(entry->label, 0, sizeof(entry->label));
    snprintf(entry->label, sizeof(entry->label), "%s", normalized);
    return true;
}

static bool label_map_clear_internal(uint8_t node_id)
{
    if (node_id == 0 || node_id >= ROSTER_MAX_NODES) {
        return false;
    }
    roster_label_entry_t *entry = &s_label_map[node_id];
    if (!entry->used) {
        return false;
    }
    entry->used = false;
    memset(entry->label, 0, sizeof(entry->label));
    return true;
}

static bool label_map_move_internal(uint8_t from_id, uint8_t to_id)
{
    if (from_id == 0 || to_id == 0 ||
        from_id >= ROSTER_MAX_NODES || to_id >= ROSTER_MAX_NODES) {
        return false;
    }
    if (from_id == to_id) {
        return false;
    }

    roster_label_entry_t from_entry = s_label_map[from_id];
    if (!from_entry.used) {
        return label_map_clear_internal(to_id);
    }

    bool changed = true;
    roster_label_entry_t *dst = &s_label_map[to_id];
    *dst = from_entry;
    roster_label_entry_t *src = &s_label_map[from_id];
    src->used = false;
    memset(src->label, 0, sizeof(src->label));
    return changed;
}

static esp_err_t label_map_save_locked(void)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(ROSTER_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "nvs_open(%s) failed: %s", ROSTER_NVS_NAMESPACE, esp_err_to_name(err));
        return err;
    }

    roster_label_record_t records[ROSTER_MAX_NODES];
    uint8_t count = 0;
    for (size_t i = 1; i < ROSTER_MAX_NODES; ++i) {
        const roster_label_entry_t *entry = &s_label_map[i];
        if (!entry->used) {
            continue;
        }
        if (count >= ROSTER_MAX_NODES) {
            break;
        }
        records[count].node_id = (uint8_t)i;
        snprintf(records[count].label, sizeof(records[count].label), "%s", entry->label);
        ++count;
    }

    uint8_t blob[2 + sizeof(records)];
    blob[0] = ROSTER_LABEL_MAP_VERSION;
    blob[1] = count;
    size_t blob_size = 2 + ((size_t)count) * sizeof(roster_label_record_t);
    if (count > 0) {
        memcpy(blob + 2, records, ((size_t)count) * sizeof(roster_label_record_t));
    }

    err = nvs_set_blob(handle, ROSTER_NVS_KEY_LABEL_MAP, blob, blob_size);
    if (err == ESP_ERR_NVS_NOT_ENOUGH_SPACE) {
        esp_err_t erase_err = nvs_erase_key(handle, ROSTER_NVS_KEY_LABEL_MAP);
        if (erase_err != ESP_OK && erase_err != ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGW(TAG, "Failed to erase label map blob before retry: %s", esp_err_to_name(erase_err));
        } else {
            err = nvs_set_blob(handle, ROSTER_NVS_KEY_LABEL_MAP, blob, blob_size);
        }
    }
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to persist CAN label map: %s", esp_err_to_name(err));
    }

    nvs_close(handle);
    return err;
}

static void label_map_load_locked(void)
{
    memset(s_label_map, 0, sizeof(s_label_map));

    nvs_handle_t handle;
    esp_err_t err = nvs_open(ROSTER_NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        if (err != ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGW(TAG, "nvs_open(%s) for read failed: %s", ROSTER_NVS_NAMESPACE, esp_err_to_name(err));
        }
        return;
    }

    uint8_t blob[2 + ROSTER_MAX_NODES * sizeof(roster_label_record_t)];
    size_t required = sizeof(blob);
    err = nvs_get_blob(handle, ROSTER_NVS_KEY_LABEL_MAP, blob, &required);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(handle);
        return;
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to load CAN label map: %s", esp_err_to_name(err));
        nvs_close(handle);
        return;
    }
    if (required < 2) {
        nvs_close(handle);
        return;
    }

    uint8_t version = blob[0];
    if (version != ROSTER_LABEL_MAP_VERSION) {
        ESP_LOGW(TAG, "Unknown CAN label map version %u", (unsigned)version);
        nvs_close(handle);
        return;
    }

    uint8_t count = blob[1];
    size_t expected = 2 + ((size_t)count) * sizeof(roster_label_record_t);
    if (count > ROSTER_MAX_NODES || required < expected) {
        ESP_LOGW(TAG, "Invalid CAN label map blob (count=%u size=%zu)", (unsigned)count, required);
        nvs_close(handle);
        return;
    }

    const roster_label_record_t *records = (const roster_label_record_t *)(blob + 2);
    for (size_t i = 0; i < count; ++i) {
        uint8_t node_id = records[i].node_id;
        if (node_id == 0 || node_id >= ROSTER_MAX_NODES) {
            continue;
        }
        label_map_set_internal(node_id, records[i].label);
    }

    nvs_close(handle);
}

static bool label_map_set(uint8_t node_id, const char *label)
{
    if (!label_map_set_internal(node_id, label)) {
        return false;
    }
    label_map_save_locked();
    return true;
}

static bool label_map_clear(uint8_t node_id)
{
    if (!label_map_clear_internal(node_id)) {
        return false;
    }
    label_map_save_locked();
    return true;
}

static void label_map_apply(roster_node_t *node)
{
    if (!node) {
        return;
    }
    uint8_t node_id = node->node_id;
    if (node_id == 0 || node_id >= ROSTER_MAX_NODES) {
        return;
    }
    const roster_label_entry_t *entry = &s_label_map[node_id];
    if (!entry->used) {
        return;
    }
    snprintf(node->label, sizeof(node->label), "%s", entry->label);
}

static void node_set_default_label(roster_node_t *node)
{
    if (!node) {
        return;
    }
    snprintf(node->label, sizeof(node->label), "Exp %u", (unsigned)node->node_id);
}

static SemaphoreHandle_t ensure_lock(void)
{
    if (!s_roster_lock) {
        s_roster_lock = xSemaphoreCreateMutex();
    }
    return s_roster_lock;
}

static void uid_normalize(uint8_t *dst, size_t dst_len, const uint8_t *src, size_t src_len)
{
    if (!dst || dst_len == 0) {
        return;
    }
    memset(dst, 0, dst_len);
    if (!src || src_len == 0) {
        return;
    }
    if (src_len > dst_len) {
        src_len = dst_len;
    }
    memcpy(dst, src, src_len);
}

static bool uid_equals(const uint8_t *a, const uint8_t *b)
{
    if (!a || !b) {
        return false;
    }
    return memcmp(a, b, sizeof(((roster_node_t *)0)->uid)) == 0;
}

static bool uid_map_lookup(const uint8_t *uid, uint8_t *out_node_id)
{
    if (!uid) {
        return false;
    }
    for (size_t i = 0; i < ROSTER_MAX_NODES; ++i) {
        const roster_uid_entry_t *entry = &s_uid_map[i];
        if (!entry->used) {
            continue;
        }
        if (uid_equals(entry->uid, uid)) {
            if (out_node_id) {
                *out_node_id = entry->node_id;
            }
            return true;
        }
    }
    return false;
}

static roster_uid_entry_t *uid_map_find_entry(uint8_t node_id)
{
    if (node_id == 0) {
        return NULL;
    }
    for (size_t i = 0; i < ROSTER_MAX_NODES; ++i) {
        roster_uid_entry_t *entry = &s_uid_map[i];
        if (!entry->used) {
            continue;
        }
        if (entry->node_id == node_id) {
            return entry;
        }
    }
    return NULL;
}

static bool uid_map_set_internal(uint8_t node_id, const uint8_t *uid, uint64_t associated_at_ms)
{
    if (node_id == 0 || !uid) {
        return false;
    }
    uint64_t sanitized_ts = roster_sanitize_wall_time(associated_at_ms);
    bool changed = false;
    roster_uid_entry_t *entry = uid_map_find_entry(node_id);
    if (entry) {
        if (memcmp(entry->uid, uid, sizeof(entry->uid)) != 0) {
            memcpy(entry->uid, uid, sizeof(entry->uid));
            changed = true;
        }
        if ((sanitized_ts != 0 || !roster_timestamp_is_valid(entry->associated_at_ms)) &&
            entry->associated_at_ms != sanitized_ts) {
            entry->associated_at_ms = sanitized_ts;
            changed = true;
        }
        return changed;
    }

    for (size_t i = 0; i < ROSTER_MAX_NODES; ++i) {
        roster_uid_entry_t *slot = &s_uid_map[i];
        if (slot->used) {
            continue;
        }
        slot->used = true;
        slot->node_id = node_id;
        memcpy(slot->uid, uid, sizeof(slot->uid));
        slot->associated_at_ms = sanitized_ts;
        changed = true;
        break;
    }
    return changed;
}

static void uid_map_set(uint8_t node_id, const uint8_t *uid, uint64_t associated_at_ms)
{
    if (uid_map_set_internal(node_id, uid, associated_at_ms)) {
        uid_map_save_locked();
    }
}

static bool uid_map_clear_internal(uint8_t node_id)
{
    if (node_id == 0) {
        return false;
    }
    for (size_t i = 0; i < ROSTER_MAX_NODES; ++i) {
        roster_uid_entry_t *entry = &s_uid_map[i];
        if (!entry->used) {
            continue;
        }
        if (entry->node_id == node_id) {
            memset(entry, 0, sizeof(*entry));
            return true;
        }
    }
    return false;
}

static void uid_map_clear(uint8_t node_id)
{
    if (uid_map_clear_internal(node_id)) {
        uid_map_save_locked();
    }
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

static void node_apply_uid(roster_node_t *node)
{
    if (!node) {
        return;
    }
    roster_uid_entry_t *entry = uid_map_find_entry(node->node_id);
    if (!entry) {
        return;
    }
    memcpy(node->uid, entry->uid, sizeof(node->uid));
    node->info_valid = true;
    node->associated_at_ms = roster_sanitize_wall_time(entry->associated_at_ms);
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
    node->inputs_tamper_bitmap = 0;
    node->inputs_fault_bitmap = 0;
    node->outputs_bitmap = 0;
    node->change_counter = 0;
    node->node_state_flags = 0;
    node->outputs_flags = 0;
    node->outputs_pwm = 0;
    node->associated_at_ms = 0;
    node_set_default_label(node);
    label_map_apply(node);
    node_apply_uid(node);
}

static void add_ext_status_json(cJSON *obj, const roster_node_t *node)
{
    if (!obj || !node) {
        return;
    }
    const roster_ext_status_t *status = &node->ext_status;
    if (!status->valid) {
        return;
    }

    cJSON *ext = cJSON_CreateObject();
    if (!ext) {
        return;
    }

    uint32_t alarm_bitmap = status->alarm_bitmap;
    uint32_t short_bitmap = status->short_bitmap;
    uint32_t open_bitmap = status->open_bitmap;
    uint32_t tamper_bitmap = status->tamper_bitmap;
    uint32_t fault_bitmap = (short_bitmap | open_bitmap);

    cJSON_AddNumberToObject(ext, "alarm_bitmap", (double)alarm_bitmap);
    cJSON_AddNumberToObject(ext, "short_bitmap", (double)short_bitmap);
    cJSON_AddNumberToObject(ext, "open_bitmap", (double)open_bitmap);
    cJSON_AddNumberToObject(ext, "tamper_bitmap", (double)tamper_bitmap);
    cJSON_AddNumberToObject(ext, "fault_bitmap", (double)fault_bitmap);
    cJSON_AddNumberToObject(ext, "vdda_mv", (double)status->vdda_10mv * 10.0);
    cJSON_AddNumberToObject(ext, "vbias_mv", (double)status->vbias_100mv * 100.0);
    cJSON_AddNumberToObject(ext, "vbias_volts", (double)status->vbias_100mv / 10.0);
    cJSON_AddNumberToObject(ext, "temp_c", (double)status->temp_c);
    cJSON_AddNumberToObject(ext, "fw_version", status->fw_version);
    cJSON_AddNumberToObject(ext, "last_update_ms", (double)status->last_update_ms);

    cJSON_AddItemToObject(obj, "ext_status", ext);
}

static void add_zone_telemetry_json(cJSON *obj, const roster_node_t *node)
{
    if (!obj || !node) {
        return;
    }
    cJSON *zones = cJSON_CreateArray();
    if (!zones) {
        return;
    }

    bool any = false;
    for (size_t i = 0; i < ROSTER_MAX_ZONES; ++i) {
        const roster_zone_telemetry_t *zone = &node->zones[i];
        if (!zone->valid) {
            continue;
        }
        cJSON *entry = cJSON_CreateObject();
        if (!entry) {
            continue;
        }
        cJSON_AddNumberToObject(entry, "zone", zone->zone_index);
        cJSON_AddNumberToObject(entry, "state_bits", zone->state_bits);
        cJSON_AddBoolToObject(entry, "present", (zone->state_bits & CAN_EXT_ZONE_STATE_PRESENT) != 0);
        cJSON_AddBoolToObject(entry, "alarm", (zone->state_bits & CAN_EXT_ZONE_STATE_ALARM) != 0);
        cJSON_AddBoolToObject(entry, "fault_short", (zone->state_bits & CAN_EXT_ZONE_STATE_SHORT) != 0);
        cJSON_AddBoolToObject(entry, "fault_open", (zone->state_bits & CAN_EXT_ZONE_STATE_OPEN) != 0);
        cJSON_AddBoolToObject(entry, "tamper", (zone->state_bits & CAN_EXT_ZONE_STATE_TAMPER) != 0);
        cJSON_AddBoolToObject(entry, "contact_no", (zone->state_bits & CAN_EXT_ZONE_STATE_CONTACT_NO) != 0);
        cJSON_AddNumberToObject(entry, "adc_raw", zone->adc_raw);
        cJSON_AddNumberToObject(entry, "rloop_ohm_div100", zone->rloop_ohm_div100);
        cJSON_AddNumberToObject(entry, "rloop_ohm", (double)zone->rloop_ohm_div100 * 100.0);
        cJSON_AddNumberToObject(entry, "vbias_100mv", zone->vbias_100mv);
        cJSON_AddNumberToObject(entry, "vbias_volts", (double)zone->vbias_100mv / 10.0);
        cJSON_AddNumberToObject(entry, "seq", zone->seq);
        cJSON_AddNumberToObject(entry, "last_update_ms", (double)zone->last_update_ms);
        cJSON_AddItemToArray(zones, entry);
        any = true;
    }

    if (any) {
        cJSON_AddItemToObject(obj, "zones", zones);
    } else {
        cJSON_Delete(zones);
    }
}

void roster_init(uint8_t master_inputs, uint8_t master_outputs, uint16_t master_caps)
{
    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);
    memset(s_nodes, 0, sizeof(s_nodes));
    memset(s_uid_map, 0, sizeof(s_uid_map));
    uid_map_load_locked();
    memset(s_label_map, 0, sizeof(s_label_map));
    label_map_load_locked();
    strncpy(s_master.label, "Centrale", sizeof(s_master.label) - 1);
    strncpy(s_master.kind, "master", sizeof(s_master.kind) - 1);
    s_master.caps = master_caps;
    s_master.inputs_count = master_inputs;
    s_master.outputs_count = master_outputs;
    s_master.last_seen_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);
    s_master.registered_at_ms = master_load_registered_at();
    s_master.device_id[0] = '\0';
    xSemaphoreGive(s_roster_lock);
}

esp_err_t roster_reset(void)
{
    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);
    memset(s_nodes, 0, sizeof(s_nodes));
    memset(s_uid_map, 0, sizeof(s_uid_map));
    uid_map_save_locked();
    memset(s_label_map, 0, sizeof(s_label_map));
    label_map_save_locked();
    s_master.registered_at_ms = 0;
    s_master.device_id[0] = '\0';
    xSemaphoreGive(s_roster_lock);

    nvs_handle_t handle;
    if (nvs_open(ROSTER_NVS_NAMESPACE, NVS_READWRITE, &handle) == ESP_OK) {
        esp_err_t err = nvs_erase_key(handle, ROSTER_NVS_KEY_MASTER_REG);
        if (err == ESP_ERR_NVS_NOT_FOUND) {
            err = ESP_OK;
        }
        if (err == ESP_OK) {
            err = nvs_commit(handle);
        }
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "Failed to clear master registered_at: %s", esp_err_to_name(err));
        }
        nvs_close(handle);
    }
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
        bool uid_differs = !node->info_valid || memcmp(node->uid, info->uid, sizeof(node->uid)) != 0;
        memcpy(node->uid, info->uid, sizeof(node->uid));
        node->info_valid = true;
        if (uid_differs || !roster_timestamp_is_valid(node->associated_at_ms)) {
            uint64_t assoc_ms = roster_current_wall_time_ms();
            if (assoc_ms != 0 || !roster_timestamp_is_valid(node->associated_at_ms)) {
                node->associated_at_ms = assoc_ms;
            }
        }
        uid_map_set(node_id, node->uid, node->associated_at_ms);
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
    label_map_apply(node);
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
    uid_map_clear(node_id);
    label_map_clear(node_id);
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

bool roster_get_node_snapshot(uint8_t node_id, roster_node_t *out_snapshot)
{
    if (!out_snapshot || node_id >= ROSTER_MAX_NODES) {
        return false;
    }

    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);
    roster_node_t *node = node_slot(node_id);
    bool ok = (node && node->used);
    if (ok) {
        *out_snapshot = *node;
    }
    xSemaphoreGive(s_roster_lock);
    return ok;
}

esp_err_t roster_reassign_node_id(uint8_t current_id, uint8_t new_id)
{
    if (current_id == 0 || new_id == 0 ||
        current_id >= ROSTER_MAX_NODES || new_id >= ROSTER_MAX_NODES) {
        return ESP_ERR_INVALID_ARG;
    }
    if (current_id == new_id) {
        roster_node_t snapshot;
        return roster_get_node_snapshot(current_id, &snapshot) ? ESP_OK : ESP_ERR_NOT_FOUND;
    }

    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);

    roster_node_t *src = node_slot(current_id);
    roster_node_t *dst = node_slot(new_id);
    if (!src || !src->used) {
        xSemaphoreGive(s_roster_lock);
        return ESP_ERR_NOT_FOUND;
    }
    if (!dst) {
        xSemaphoreGive(s_roster_lock);
        return ESP_ERR_INVALID_ARG;
    }
    if (dst->used) {
        xSemaphoreGive(s_roster_lock);
        return ESP_ERR_INVALID_STATE;
    }

    roster_node_t snapshot = *src;
    memset(src, 0, sizeof(*src));
    src->node_id = current_id;
    src->used = false;

    *dst = snapshot;
    dst->node_id = new_id;
    dst->used = true;
    dst->state = ROSTER_NODE_STATE_PREOP;
    dst->inputs_valid = false;
    dst->outputs_valid = false;
    dst->inputs_bitmap = 0;
    dst->outputs_bitmap = 0;
    dst->outputs_flags = 0;
    dst->outputs_pwm = 0;
    dst->change_counter = 0;
    dst->node_state_flags = 0;
    dst->identify_active = false;
    dst->last_seen_ms = 0;

    bool map_changed = false;
    if (uid_map_clear_internal(current_id)) {
        map_changed = true;
    }
    if (uid_map_clear_internal(new_id)) {
        map_changed = true;
    }
    if (snapshot.info_valid && uid_map_set_internal(new_id, snapshot.uid, snapshot.associated_at_ms)) {
        map_changed = true;
    }
    if (map_changed) {
        uid_map_save_locked();
    }

    if (label_map_move_internal(current_id, new_id)) {
        label_map_save_locked();
        label_map_apply(dst);
    }

    xSemaphoreGive(s_roster_lock);
    return ESP_OK;
}

esp_err_t roster_set_node_label(uint8_t node_id, const char *label)
{
    if (node_id == 0 || node_id >= ROSTER_MAX_NODES) {
        return ESP_ERR_INVALID_ARG;
    }

    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);

    roster_node_t *node = node_slot(node_id);
    if (!node || !node->used) {
        xSemaphoreGive(s_roster_lock);
        return ESP_ERR_NOT_FOUND;
    }

    char normalized[sizeof(node->label)];
    size_t len = label_trim_copy(normalized, sizeof(normalized), label);
    if (len == 0) {
        node_set_default_label(node);
        label_map_clear(node_id);
        xSemaphoreGive(s_roster_lock);
        return ESP_OK;
    }

    snprintf(node->label, sizeof(node->label), "%s", normalized);
    label_map_set(node_id, normalized);

    xSemaphoreGive(s_roster_lock);
    return ESP_OK;
}

esp_err_t roster_assign_node_id_from_uid(const uint8_t *uid, size_t uid_len, uint8_t *out_node_id, bool *out_is_new)
{
    if (!uid || uid_len == 0 || uid_len > sizeof(((roster_node_t *)0)->uid) || !out_node_id) {
        return ESP_ERR_INVALID_ARG;
    }

    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);

    uint8_t normalized_uid[sizeof(((roster_node_t *)0)->uid)];
    uid_normalize(normalized_uid, sizeof(normalized_uid), uid, uid_len);

    uint64_t now_ms = roster_current_wall_time_ms();

    for (uint32_t i = 1; i < ROSTER_MAX_NODES; ++i) {
        roster_node_t *node = &s_nodes[i];
        if (!node->used) {
            continue;
        }
        if (uid_equals(node->uid, normalized_uid)) {
            *out_node_id = (uint8_t)i;
            if (out_is_new) {
                *out_is_new = false;
            }
            if (!roster_timestamp_is_valid(node->associated_at_ms)) {
                node->associated_at_ms = now_ms;
            }
            uid_map_set(*out_node_id, normalized_uid, node->associated_at_ms);
            xSemaphoreGive(s_roster_lock);
            return ESP_OK;
        }
    }

    uint8_t mapped_id = 0;
    if (uid_map_lookup(normalized_uid, &mapped_id) && mapped_id > 0 && mapped_id < ROSTER_MAX_NODES) {
        roster_node_t *node = &s_nodes[mapped_id];
        if (!node->used) {
            node_init_defaults(node, mapped_id);
        }
        memcpy(node->uid, normalized_uid, sizeof(node->uid));
        node->info_valid = true;
        node->used = true;
        node->state = ROSTER_NODE_STATE_PREOP;
        if (!roster_timestamp_is_valid(node->associated_at_ms)) {
            node->associated_at_ms = now_ms;
        }
        *out_node_id = mapped_id;
        if (out_is_new) {
            *out_is_new = false;
        }
        uid_map_set(mapped_id, normalized_uid, node->associated_at_ms);
        xSemaphoreGive(s_roster_lock);
        return ESP_OK;
    }

    for (uint32_t i = 1; i < ROSTER_MAX_NODES; ++i) {
        roster_node_t *node = &s_nodes[i];
        if (node->used) {
            continue;
        }
        node_init_defaults(node, (uint8_t)i);
        memcpy(node->uid, normalized_uid, sizeof(node->uid));
        node->info_valid = true;
        node->state = ROSTER_NODE_STATE_PREOP;
        node->used = true;
        node->associated_at_ms = now_ms;
        *out_node_id = (uint8_t)i;
        if (out_is_new) {
            *out_is_new = true;
        }
        uid_map_set(*out_node_id, normalized_uid, node->associated_at_ms);
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
        cJSON_AddNumberToObject(obj, "inputs_alarm_bitmap", (double)node->inputs_bitmap);
        cJSON_AddNumberToObject(obj, "inputs_tamper_bitmap", (double)node->inputs_tamper_bitmap);
        cJSON_AddNumberToObject(obj, "inputs_fault_bitmap", (double)node->inputs_fault_bitmap);
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
    cJSON_AddNumberToObject(obj, "associated_at_ms", (double)node->associated_at_ms);
    cJSON_AddBoolToObject(obj, "identify_active", node->identify_active);
    add_ext_status_json(obj, node);
    add_zone_telemetry_json(obj, node);
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
        cJSON_AddNumberToObject(master, "registered_at_ms", (double)s_master.registered_at_ms);
        if (s_master.device_id[0]) {
            cJSON_AddStringToObject(master, "uid", s_master.device_id);
        }
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
            cJSON_AddNumberToObject(obj, "registered_at_ms", (double)s_master.registered_at_ms);
            if (s_master.device_id[0]) {
                cJSON_AddStringToObject(obj, "uid", s_master.device_id);
            }
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

void roster_master_set_device_id(const char *device_id)
{
    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);
    if (device_id && device_id[0]) {
        snprintf(s_master.device_id, sizeof(s_master.device_id), "%s", device_id);
    } else {
        s_master.device_id[0] = '\0';
    }
    xSemaphoreGive(s_roster_lock);
}

esp_err_t roster_master_set_registered_at(uint64_t registered_at_ms)
{
    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);
    uint64_t sanitized = roster_sanitize_wall_time(registered_at_ms);
    s_master.registered_at_ms = sanitized;
    xSemaphoreGive(s_roster_lock);

    nvs_handle_t handle;
    esp_err_t err = nvs_open(ROSTER_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to open NVS for master registered_at: %s", esp_err_to_name(err));
        return err;
    }
    err = nvs_set_u64(handle, ROSTER_NVS_KEY_MASTER_REG, sanitized);
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to persist master registered_at: %s", esp_err_to_name(err));
    }
    nvs_close(handle);
    return err;
}

uint64_t roster_master_get_registered_at(void)
{
    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);
    uint64_t value = s_master.registered_at_ms;
    xSemaphoreGive(s_roster_lock);
    return value;
}

esp_err_t roster_note_inputs(uint8_t node_id,
                             uint32_t alarm_bitmap,
                             uint32_t tamper_bitmap,
                             uint32_t fault_bitmap,
                             uint8_t change_counter,
                             uint8_t node_state_flags,
                             bool has_extended)
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
    node->inputs_bitmap = alarm_bitmap;
    node->inputs_tamper_bitmap = has_extended ? tamper_bitmap : 0u;
    node->inputs_fault_bitmap = has_extended ? fault_bitmap : 0u;
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

esp_err_t roster_note_ext_status(uint8_t node_id,
                                 uint8_t alarm_bitmap,
                                 uint8_t short_bitmap,
                                 uint8_t open_bitmap,
                                 uint8_t tamper_bitmap,
                                 uint16_t vdda_10mv,
                                 uint16_t vbias_100mv,
                                 int16_t temp_c,
                                 uint8_t fw_version,
                                 uint64_t timestamp_ms)
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

    roster_ext_status_t *status = &node->ext_status;
    status->valid = true;
    status->alarm_bitmap = alarm_bitmap;
    status->short_bitmap = short_bitmap;
    status->open_bitmap = open_bitmap;
    status->tamper_bitmap = tamper_bitmap;
    status->vdda_10mv = vdda_10mv;
    status->vbias_100mv = vbias_100mv;
    status->temp_c = temp_c;
    status->fw_version = fw_version;
    status->last_update_ms = timestamp_ms;

    const uint32_t zone_mask = (ROSTER_MAX_ZONES >= 32u) ? UINT32_MAX : ((1u << ROSTER_MAX_ZONES) - 1u);
    uint32_t alarm32 = ((uint32_t)alarm_bitmap) & zone_mask;
    uint32_t tamper32 = ((uint32_t)tamper_bitmap) & zone_mask;
    uint32_t fault32 = (((uint32_t)short_bitmap | (uint32_t)open_bitmap) & zone_mask);

    bool changed = (node->inputs_bitmap != alarm32) ||
                   (node->inputs_tamper_bitmap != tamper32) ||
                   (node->inputs_fault_bitmap != fault32);
    if (changed) {
        node->change_counter++;
    }

    node->inputs_bitmap = alarm32;
    node->inputs_tamper_bitmap = tamper32;
    node->inputs_fault_bitmap = fault32;
    node->inputs_valid = true;

    uint32_t combined = alarm32 | tamper32 | fault32;
    for (uint8_t bit = 0; bit < ROSTER_MAX_ZONES; ++bit) {
        if (combined & (1u << bit)) {
            uint8_t candidate = (uint8_t)(bit + 1u);
            if (candidate > node->inputs_count) {
                node->inputs_count = candidate;
            }
        }
    }
    if (node->inputs_count > ROSTER_MAX_ZONES) {
        node->inputs_count = ROSTER_MAX_ZONES;
    }

    xSemaphoreGive(s_roster_lock);
    return ESP_OK;
}

esp_err_t roster_note_zone_event(uint8_t node_id,
                                 uint8_t zone_index,
                                 uint8_t state_bits,
                                 uint16_t adc_raw,
                                 uint16_t rloop_ohm_div100,
                                 uint16_t vbias_100mv,
                                 uint8_t seq,
                                 uint64_t timestamp_ms)
{
    if (node_id == 0 || zone_index >= ROSTER_MAX_ZONES) {
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

    roster_zone_telemetry_t *zone = &node->zones[zone_index];
    zone->valid = true;
    zone->zone_index = zone_index;
    zone->state_bits = state_bits;
    zone->adc_raw = adc_raw;
    zone->rloop_ohm_div100 = rloop_ohm_div100;
    zone->vbias_100mv = vbias_100mv;
    zone->seq = seq;
    zone->last_update_ms = timestamp_ms;

    uint32_t mask = (zone_index < 32u) ? (1u << zone_index) : 0u;
    bool alarm = (state_bits & CAN_EXT_ZONE_STATE_ALARM) != 0;
    bool tamper = (state_bits & CAN_EXT_ZONE_STATE_TAMPER) != 0;
    bool fault = ((state_bits & CAN_EXT_ZONE_STATE_SHORT) != 0) ||
                 ((state_bits & CAN_EXT_ZONE_STATE_OPEN) != 0);

    bool changed = false;
    if (mask != 0u) {
        if (((node->inputs_bitmap & mask) != 0u) != alarm) {
            if (alarm) {
                node->inputs_bitmap |= mask;
            } else {
                node->inputs_bitmap &= ~mask;
            }
            changed = true;
        }
        if (((node->inputs_tamper_bitmap & mask) != 0u) != tamper) {
            if (tamper) {
                node->inputs_tamper_bitmap |= mask;
            } else {
                node->inputs_tamper_bitmap &= ~mask;
            }
            changed = true;
        }
        if (((node->inputs_fault_bitmap & mask) != 0u) != fault) {
            if (fault) {
                node->inputs_fault_bitmap |= mask;
            } else {
                node->inputs_fault_bitmap &= ~mask;
            }
            changed = true;
        }
    }

    if (changed) {
        node->change_counter++;
    }

    node->inputs_valid = true;
    uint8_t required = (uint8_t)(zone_index + 1u);
    if (required > node->inputs_count) {
        node->inputs_count = required;
    }
    if (node->inputs_count > ROSTER_MAX_ZONES) {
        node->inputs_count = ROSTER_MAX_ZONES;
    }

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
        out_state->inputs_tamper_bitmap = node->inputs_tamper_bitmap;
        out_state->inputs_fault_bitmap = node->inputs_fault_bitmap;
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

bool roster_get_ext_status(uint8_t node_id, roster_ext_status_t *out_status)
{
    if (!out_status) {
        return false;
    }
    if (node_id == 0) {
        memset(out_status, 0, sizeof(*out_status));
        return false;
    }

    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);
    roster_node_t *node = node_slot(node_id);
    bool ok = (node && node->used && node->ext_status.valid);
    if (ok) {
        *out_status = node->ext_status;
    }
    xSemaphoreGive(s_roster_lock);
    if (!ok) {
        memset(out_status, 0, sizeof(*out_status));
    }
    return ok;
}

bool roster_get_zone_telemetry(uint8_t node_id,
                               uint8_t zone_index,
                               roster_zone_telemetry_t *out_zone)
{
    if (!out_zone) {
        return false;
    }
    if (node_id == 0 || zone_index >= ROSTER_MAX_ZONES) {
        memset(out_zone, 0, sizeof(*out_zone));
        return false;
    }

    ensure_lock();
    xSemaphoreTake(s_roster_lock, portMAX_DELAY);
    roster_node_t *node = node_slot(node_id);
    bool ok = (node && node->used && node->zones[zone_index].valid);
    if (ok) {
        *out_zone = node->zones[zone_index];
    }
    xSemaphoreGive(s_roster_lock);
    if (!ok) {
        memset(out_zone, 0, sizeof(*out_zone));
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
        dst->inputs_tamper_bitmap = node->inputs_tamper_bitmap;
        dst->inputs_fault_bitmap = node->inputs_fault_bitmap;
        dst->caps = node->caps;
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