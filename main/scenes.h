// main/scenes.h
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

// Supportiamo fino a 16 zone (A0..A7 + B0..B7). Usa INPUT_ZONES_COUNT del tuo gpio_inputs.h.
typedef enum {
    SCENE_HOME = 0,
    SCENE_NIGHT,
    SCENE_CUSTOM,
} scene_t;

// Inizializza (carica da NVS o crea default = maschere “tutte ON” per HOME/NIGHT/CUSTOM)
esp_err_t scenes_init(int zones_count);

// Set/get maschera per singola scena (bit i=1 corrisponde a zona id=i)
esp_err_t scenes_set_mask(scene_t s, uint16_t mask);
esp_err_t scenes_get_mask(scene_t s, uint16_t *out_mask);

// Utility: converte array di id in mask e viceversa
uint16_t scenes_ids_to_mask(const int *ids, int n);
int      scenes_mask_to_ids(uint16_t mask, int *out_ids, int max);

// Maschera con tutte le zone abilitate in base a zones_count
uint16_t scenes_mask_all(int zones_count);

// (opzionale) memorizza/recupera la maschera attiva correntemente (usata da ALARM)
void     scenes_set_active_mask(uint16_t mask);
uint16_t scenes_get_active_mask(void);

#ifdef __cplusplus
}
#endif
