// main/scenes.c
#include "scenes.h"
#include "esp_log.h"
#include "storage.h"

#include <string.h>

static const char *TAG = "scenes";
#define NVS_SCENE_NS   "scenes"
#define KEY_HOME       "home"
#define KEY_NIGHT      "night"
#define KEY_CUSTOM     "custom"

static uint16_t   s_zones = 12;    // default, verrà sovrascritto in init
static zone_mask_t s_home;
static zone_mask_t s_night;
static zone_mask_t s_custom;
static zone_mask_t s_active;

static esp_err_t nvs_get_mask(const char *key, zone_mask_t *out)
{
    if (!out) {
        return ESP_ERR_INVALID_ARG;
    }
    zone_mask_clear(out);
    size_t len = 0;
    esp_err_t err = storage_get_blob(NVS_SCENE_NS, key, NULL, &len);
    if (err != ESP_OK) {
        return err;
    }
    if (len == sizeof(zone_mask_t)) {
        size_t read_len = len;
        return storage_get_blob(NVS_SCENE_NS, key, out, &read_len);
    }
    if (len == sizeof(uint16_t)) {
        uint16_t legacy = 0;
        size_t legacy_len = sizeof(legacy);
        err = storage_get_blob(NVS_SCENE_NS, key, &legacy, &legacy_len);
        if (err == ESP_OK) {
            zone_mask_from_u32(out, (uint32_t)legacy);
        }
        return err;
    }
    if (len == sizeof(uint32_t)) {
        uint32_t legacy = 0;
        size_t legacy_len = sizeof(legacy);
        err = storage_get_blob(NVS_SCENE_NS, key, &legacy, &legacy_len);
        if (err == ESP_OK) {
            zone_mask_from_u32(out, legacy);
        }
        return err;
    }
    uint8_t tmp[sizeof(zone_mask_t)] = {0};
    size_t read_len = len;
    if (read_len > sizeof(tmp)) {
        read_len = sizeof(tmp);
    }
    err = storage_get_blob(NVS_SCENE_NS, key, tmp, &read_len);
    if (err != ESP_OK) {
        return err;
    }
    memcpy(out, tmp, read_len);
    for (size_t i = (read_len + 3) / 4; i < ZONE_MASK_WORDS; ++i) {
        out->words[i] = 0u;
    }
    return ESP_OK;
}

static esp_err_t nvs_set_mask(const char *key, const zone_mask_t *mask)
{
    if (!mask) {
        return ESP_ERR_INVALID_ARG;
    }
    return storage_set_blob(NVS_SCENE_NS, key, mask, sizeof(*mask));
}

void scenes_mask_all(uint16_t zones_count, zone_mask_t *out_mask)
{
    if (!out_mask) {
        return;
    }
    zone_mask_fill(out_mask, zones_count);
}

static void ensure_default(zone_mask_t *mask)
{
    if (!mask) {
        return;
    }
    zone_mask_limit(mask, s_zones);
}

esp_err_t scenes_init(int zones_count)
{
    if (zones_count <= 0) {
        zones_count = SCENES_MAX_ZONES;
    }
    if (zones_count > SCENES_MAX_ZONES) {
        zones_count = SCENES_MAX_ZONES;
    }
    s_zones = (uint16_t)zones_count;

    zone_mask_t def;
    scenes_mask_all(s_zones, &def);

    if (nvs_get_mask(KEY_HOME, &s_home)   != ESP_OK) { s_home   = def; nvs_set_mask(KEY_HOME,   &s_home); }
    if (nvs_get_mask(KEY_NIGHT, &s_night) != ESP_OK) { s_night  = def; nvs_set_mask(KEY_NIGHT,  &s_night); }
    if (nvs_get_mask(KEY_CUSTOM,&s_custom)!= ESP_OK) { s_custom = def; nvs_set_mask(KEY_CUSTOM, &s_custom); }

    ensure_default(&s_home);
    ensure_default(&s_night);
    ensure_default(&s_custom);

    s_active = def;

    char home_hex[ZONE_MASK_WORDS * 8u + 1u];
    char night_hex[ZONE_MASK_WORDS * 8u + 1u];
    char custom_hex[ZONE_MASK_WORDS * 8u + 1u];
    zone_mask_to_hex(&s_home,   s_zones, home_hex,   sizeof(home_hex));
    zone_mask_to_hex(&s_night,  s_zones, night_hex,  sizeof(night_hex));
    zone_mask_to_hex(&s_custom, s_zones, custom_hex, sizeof(custom_hex));

    ESP_LOGI(TAG, "init: zones=%u home=%s night=%s custom=%s",
             (unsigned)s_zones, home_hex, night_hex, custom_hex);
    return ESP_OK;
}

esp_err_t scenes_set_mask(scene_t s, const zone_mask_t *mask)
{
    if (!mask) {
        return ESP_ERR_INVALID_ARG;
    }
    zone_mask_t limited;
    zone_mask_copy(&limited, mask);
    zone_mask_limit(&limited, s_zones);

    switch (s) {
    case SCENE_HOME:  zone_mask_copy(&s_home, &limited);   return nvs_set_mask(KEY_HOME,  &s_home);
    case SCENE_NIGHT: zone_mask_copy(&s_night, &limited);  return nvs_set_mask(KEY_NIGHT, &s_night);
    case SCENE_CUSTOM:zone_mask_copy(&s_custom, &limited); return nvs_set_mask(KEY_CUSTOM,&s_custom);
    default: return ESP_ERR_INVALID_ARG;
    }
}

esp_err_t scenes_get_mask(scene_t s, zone_mask_t *out_mask)
{
    if (!out_mask) return ESP_ERR_INVALID_ARG;
    switch (s) {
    case SCENE_HOME:  zone_mask_copy(out_mask, &s_home);  return ESP_OK;
    case SCENE_NIGHT: zone_mask_copy(out_mask, &s_night); return ESP_OK;
    case SCENE_CUSTOM:zone_mask_copy(out_mask, &s_custom);return ESP_OK;
    default: return ESP_ERR_INVALID_ARG;
    }
}

void scenes_ids_to_mask(const int *ids, int n, zone_mask_t *out_mask)
{
    if (!out_mask) {
        return;
    }
    zone_mask_clear(out_mask);
    if (!ids || n <= 0) {
        return;
    }
    for (int i = 0; i < n; ++i) {
        int id = ids[i];
        if (id >= 1 && id <= (int)s_zones && id <= (int)SCENES_MAX_ZONES) {
            zone_mask_set(out_mask, (uint16_t)(id - 1));
        }
    }
    zone_mask_limit(out_mask, s_zones);
}

int scenes_mask_to_ids(const zone_mask_t *mask, int *out_ids, int max, uint16_t zone_limit)
{
    if (!mask) {
        return 0;
    }
    int count = 0;
    uint16_t limit = s_zones;
    if (zone_limit > 0 && zone_limit < limit) {
        limit = zone_limit;
    }
    if (limit > SCENES_MAX_ZONES) {
        limit = SCENES_MAX_ZONES;
    }
    for (uint16_t id = 1; id <= limit; ++id) {
        if (zone_mask_test(mask, (uint16_t)(id - 1))) {
            if (out_ids && count < max) {
                out_ids[count] = (int)id;
            }
            ++count;
        }
    }
    return count;
}

void scenes_set_active_mask(const zone_mask_t *mask)
{
    if (!mask) {
        zone_mask_clear(&s_active);
        return;
    }
    zone_mask_copy(&s_active, mask);
    zone_mask_limit(&s_active, s_zones);
}

void scenes_get_active_mask(zone_mask_t *out_mask)
{
    if (!out_mask) {
        return;
    }
    zone_mask_copy(out_mask, &s_active);
}
