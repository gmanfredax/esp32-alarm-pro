// main/scenes.c
#include "scenes.h"
#include "esp_log.h"
#include "storage.h"

static const char *TAG = "scenes";
#define NVS_SCENE_NS   "scenes"
#define KEY_HOME       "home"
#define KEY_NIGHT      "night"
#define KEY_CUSTOM     "custom"

static int       s_zones = 12;    // default, verrà sovrascritto in init
static uint16_t  s_home  = 0;
static uint16_t  s_night = 0;
static uint16_t  s_custom= 0;
static uint16_t  s_active= 0;

static esp_err_t nvs_get_u16(const char *key, uint16_t *out)
{
    size_t len = sizeof(uint16_t);
    return storage_get_blob(NVS_SCENE_NS, key, out, &len);
}
static esp_err_t nvs_set_u16(const char *key, uint16_t val)
{
    return storage_set_blob(NVS_SCENE_NS, key, &val, sizeof(val));
}

uint16_t scenes_mask_all(int zones_count)
{
    if (zones_count >= 16) return 0xFFFFu;
    if (zones_count <= 0)  return 0;
    return (uint16_t)((1u << zones_count) - 1u);
}

esp_err_t scenes_init(int zones_count)
{
    if (zones_count <= 0 || zones_count > 16) zones_count = 12;
    s_zones = zones_count;

    uint16_t def = scenes_mask_all(s_zones);

    if (nvs_get_u16(KEY_HOME, &s_home)  != ESP_OK) { s_home  = def; nvs_set_u16(KEY_HOME,  s_home); }
    if (nvs_get_u16(KEY_NIGHT, &s_night)!= ESP_OK) { s_night = def; nvs_set_u16(KEY_NIGHT, s_night); }
    if (nvs_get_u16(KEY_CUSTOM,&s_custom)!=ESP_OK) { s_custom= def; nvs_set_u16(KEY_CUSTOM,s_custom); }

    // Active = def all zones (utile per AWAY)
    s_active = def;

    ESP_LOGI(TAG, "init: zones=%d home=0x%04X night=0x%04X custom=0x%04X",
             s_zones, s_home, s_night, s_custom);
    return ESP_OK;
}

esp_err_t scenes_set_mask(scene_t s, uint16_t mask)
{
    // Maschera alle sole zone esistenti
    uint16_t lim = scenes_mask_all(s_zones);
    mask &= lim;

    switch (s) {
    case SCENE_HOME:  s_home = mask;  return nvs_set_u16(KEY_HOME,  s_home);
    case SCENE_NIGHT: s_night= mask;  return nvs_set_u16(KEY_NIGHT, s_night);
    case SCENE_CUSTOM:s_custom= mask; return nvs_set_u16(KEY_CUSTOM,s_custom);
    default: return ESP_ERR_INVALID_ARG;
    }
}

esp_err_t scenes_get_mask(scene_t s, uint16_t *out_mask)
{
    if (!out_mask) return ESP_ERR_INVALID_ARG;
    switch (s) {
    case SCENE_HOME:  *out_mask = s_home;  return ESP_OK;
    case SCENE_NIGHT: *out_mask = s_night; return ESP_OK;
    case SCENE_CUSTOM:*out_mask = s_custom;return ESP_OK;
    default: return ESP_ERR_INVALID_ARG;
    }
}

uint16_t scenes_ids_to_mask(const int *ids, int n)
{
    uint16_t m = 0;
    for (int i=0;i<n;i++){
        int id = ids[i];
        if (id >= 1 && id <= s_zones) m |= (1u << (id-1));
    }
    return m;
}

int scenes_mask_to_ids(uint16_t mask, int *out_ids, int max)
{
    int c=0;
    for (int id=1; id<=s_zones; id++){
        if (mask & (1u << (id-1))){
            if (out_ids && c<max) out_ids[c] = id;
            c++;
        }
    }
    return c;
}

void scenes_set_active_mask(uint16_t mask)
{
    s_active = (mask & scenes_mask_all(s_zones));
}
uint16_t scenes_get_active_mask(void)
{
    return s_active;
}
