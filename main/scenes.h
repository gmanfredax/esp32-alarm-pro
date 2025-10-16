// main/scenes.h
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

// Supportiamo fino a 32 zone (12 della centrale + espansioni CAN).
#define SCENES_MAX_ZONES 32
typedef enum {
    SCENE_HOME = 0,
    SCENE_NIGHT,
    SCENE_CUSTOM,
} scene_t;

// Inizializza (carica da NVS o crea default = maschere “tutte ON” per HOME/NIGHT/CUSTOM)
esp_err_t scenes_init(int zones_count);

// Set/get maschera per singola scena (bit i=1 corrisponde a zona id=i)
esp_err_t scenes_set_mask(scene_t s, uint32_t mask);
esp_err_t scenes_get_mask(scene_t s, uint32_t *out_mask);

// Utility: converte array di id in mask e viceversa
uint32_t scenes_ids_to_mask(const int *ids, int n);
int      scenes_mask_to_ids(uint32_t mask, int *out_ids, int max);

// Maschera con tutte le zone abilitate in base a zones_count
uint32_t scenes_mask_all(int zones_count);

// (opzionale) memorizza/recupera la maschera attiva correntemente (usata da ALARM)
void     scenes_set_active_mask(uint32_t mask);
uint32_t scenes_get_active_mask(void);

#ifdef __cplusplus
}
#endif
