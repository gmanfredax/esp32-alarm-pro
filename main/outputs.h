#pragma once

#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>

/**
 * Inizializza l’expander uscite (MCP23017) configurando come uscite soltanto i
 * bit dedicati a LED (PORTA) e attuatori (PORTB). I bit lasciati come ingressi
 * (es. tamper globale su B5) non vengono toccati.
 */
esp_err_t outputs_init(void);

/** Imposta una singola uscita (1..16). true=ON, false=OFF
 *  Canali: 1..8 = PORTA bit0..7, 9..16 = PORTB bit0..7.
 */
esp_err_t outputs_set(uint8_t channel_1_based, bool on);

/** Inverte una singola uscita (1..16). */
esp_err_t outputs_toggle(uint8_t channel_1_based);

/** Scrive tutte le uscite con una bitmask combinata: bit0..7=A0..A7, bit8..15=B0..B7. */
esp_err_t outputs_set_mask(uint16_t mask);

/** Legge la bitmask corrente delle uscite. */
esp_err_t outputs_get_mask(uint16_t *out_mask);

/** Spegne tutte le uscite. */
esp_err_t outputs_all_off(void);

/* ───────── Uscite semantiche dedicate (usano i bit di PORTB definiti in pins.h) ───────── */
void outputs_siren(bool on);
void outputs_siren_internal(bool on);
void outputs_siren_external(bool on);
void outputs_nebbiogeno(bool on);

void outputs_led_state(bool on);
void outputs_led_alarm(bool on);
void outputs_led_maint(bool on);
void outputs_led_provisioning(bool r, bool g, bool b);
