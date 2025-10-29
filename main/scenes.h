// main/scenes.h
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "zone_mask.h"

#ifdef __cplusplus
extern "C" {
#endif

// Supportiamo fino a ZONE_MASK_CAPACITY zone (12 della centrale + espansioni CAN).
#define SCENES_MAX_ZONES ZONE_MASK_CAPACITY
typedef enum {
    SCENE_HOME = 0,
    SCENE_NIGHT,
    SCENE_CUSTOM,
} scene_t;

// Inizializza (carica da NVS o crea default = maschere “tutte ON” per HOME/NIGHT/CUSTOM)
esp_err_t scenes_init(int zones_count);

// Set/get maschera per singola scena (bit i=1 corrisponde a zona id=i)
esp_err_t scenes_set_mask(scene_t s, const zone_mask_t *mask);
esp_err_t scenes_get_mask(scene_t s, zone_mask_t *out_mask);

// Utility: converte array di id in mask e viceversa
void     scenes_ids_to_mask(const int *ids, int n, zone_mask_t *out_mask);
int      scenes_mask_to_ids(const zone_mask_t *mask, int *out_ids, int max, uint16_t zone_limit);

// Maschera con tutte le zone abilitate in base a zones_count
void     scenes_mask_all(uint16_t zones_count, zone_mask_t *out_mask);

// (opzionale) memorizza/recupera la maschera attiva correntemente (usata da ALARM)
void     scenes_set_active_mask(const zone_mask_t *mask);
void     scenes_get_active_mask(zone_mask_t *out_mask);

#ifdef __cplusplus
}
#endif