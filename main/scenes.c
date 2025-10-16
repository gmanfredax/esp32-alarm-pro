// main/scenes.c
#include "scenes.h"
#include "esp_log.h"
#include "storage.h"
#include <inttypes.h>

static const char *TAG = "scenes";
#define NVS_SCENE_NS   "scenes"
#define KEY_HOME       "home"
#define KEY_NIGHT      "night"
#define KEY_CUSTOM     "custom"

static int       s_zones = 12;    // default, verrà sovrascritto in init
static uint32_t  s_home  = 0;
static uint32_t  s_night = 0;
static uint32_t  s_custom= 0;
static uint32_t  s_active= 0;

static esp_err_t nvs_get_mask(const char *key, uint32_t *out)
{
    if (!out) {
        return ESP_ERR_INVALID_ARG;
    }
    size_t len = 0;
    esp_err_t err = storage_get_blob(NVS_SCENE_NS, key, NULL, &len);
    if (err != ESP_OK) {
        return err;
    }
    if (len == sizeof(uint32_t)) {
        return storage_get_blob(NVS_SCENE_NS, key, out, &len);
    }
    if (len == sizeof(uint16_t)) {
        uint16_t legacy = 0;
        size_t legacy_len = sizeof(legacy);
        err = storage_get_blob(NVS_SCENE_NS, key, &legacy, &legacy_len);
        if (err == ESP_OK) {
            *out = (uint32_t)legacy;
        }
        return err;
    }
    uint32_t tmp = 0;
    size_t read_len = len;
    err = storage_get_blob(NVS_SCENE_NS, key, &tmp, &read_len);
    if (err == ESP_OK) {
        *out = tmp;
    }
    return err;
}

static esp_err_t nvs_set_mask(const char *key, uint16_t val)
{
    return storage_set_blob(NVS_SCENE_NS, key, &val, sizeof(val));
}

uint32_t scenes_mask_all(int zones_count)
{
    if (zones_count >= SCENES_MAX_ZONES) {
        return (SCENES_MAX_ZONES >= 32) ? 0xFFFFFFFFu : ((1u << SCENES_MAX_ZONES) - 1u);
    }
    if (zones_count <= 0)  return 0;
    if (zones_count >= 32) {
        return 0xFFFFFFFFu;
    }
    return (uint32_t)((1u << zones_count) - 1u);
}

esp_err_t scenes_init(int zones_count)
{
    if (zones_count <= 0) {
        zones_count = SCENES_MAX_ZONES;
    }
    if (zones_count > SCENES_MAX_ZONES) {
        zones_count = SCENES_MAX_ZONES;
    }
    s_zones = zones_count;

    uint32_t def = scenes_mask_all(s_zones);

    if (nvs_get_mask(KEY_HOME, &s_home)   != ESP_OK) { s_home   = def; nvs_set_mask(KEY_HOME,   s_home); }
    if (nvs_get_mask(KEY_NIGHT, &s_night) != ESP_OK) { s_night  = def; nvs_set_mask(KEY_NIGHT,  s_night); }
    if (nvs_get_mask(KEY_CUSTOM,&s_custom)!= ESP_OK) { s_custom = def; nvs_set_mask(KEY_CUSTOM, s_custom); }

    // Active = def all zones (utile per AWAY)
    s_active = def;

    ESP_LOGI(TAG, "init: zones=%d home=0x%08" PRIX32 " night=0x%08" PRIX32 " custom=0x%08" PRIX32,
             s_zones, s_home, s_night, s_custom);
    return ESP_OK;
}

esp_err_t scenes_set_mask(scene_t s, uint32_t mask)
{
    // Maschera alle sole zone esistenti
    uint32_t lim = scenes_mask_all(s_zones);
    mask &= lim;

    switch (s) {
    case SCENE_HOME:  s_home = mask;  return nvs_set_mask(KEY_HOME,  s_home);
    case SCENE_NIGHT: s_night= mask;  return nvs_set_mask(KEY_NIGHT, s_night);
    case SCENE_CUSTOM:s_custom= mask; return nvs_set_mask(KEY_CUSTOM,s_custom);
    default: return ESP_ERR_INVALID_ARG;
    }
}

esp_err_t scenes_get_mask(scene_t s, uint32_t *out_mask)
{
    if (!out_mask) return ESP_ERR_INVALID_ARG;
    switch (s) {
    case SCENE_HOME:  *out_mask = s_home;  return ESP_OK;
    case SCENE_NIGHT: *out_mask = s_night; return ESP_OK;
    case SCENE_CUSTOM:*out_mask = s_custom;return ESP_OK;
    default: return ESP_ERR_INVALID_ARG;
    }
}

uint32_t scenes_ids_to_mask(const int *ids, int n)
{
    uint32_t m = 0;
    for (int i=0;i<n;i++){
        int id = ids[i];
        if (id >= 1 && id <= s_zones && id <= SCENES_MAX_ZONES) {
            m |= (1u << (id-1));
        }
    }
    return m;
}

int scenes_mask_to_ids(uint32_t mask, int *out_ids, int max)
{
    int c=0;
    int limit = s_zones;
    if (max > 0 && max < limit) {
        limit = max;
    }
    if (limit > SCENES_MAX_ZONES) {
        limit = SCENES_MAX_ZONES;
    }
    for (int id=1; id<=limit; id++){
        if (mask & (1u << (id-1))){
            if (out_ids && c<max) out_ids[c] = id;
            c++;
        }
    }
    return c;
}

void scenes_set_active_mask(uint32_t mask)
{
    s_active = (mask & scenes_mask_all(s_zones));
}
uint32_t scenes_get_active_mask(void)
{
    return s_active;
}
