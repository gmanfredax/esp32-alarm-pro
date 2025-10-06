// main/alarm_core.h
#pragma once
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ─────────────────────────────────────────────────────────────────────────────
// Stati logici dell’impianto
// ─────────────────────────────────────────────────────────────────────────────
typedef enum {
    ALARM_DISARMED = 0,
    ALARM_ARMED_HOME,
    ALARM_ARMED_AWAY,
    ALARM_ARMED_NIGHT,
    ALARM_ARMED_CUSTOM,
    ALARM_ALARM,
    ALARM_MAINTENANCE
} alarm_state_t;

// ─────────────────────────────────────────────────────────────────────────────
// Profilo per modalità (maschera zone + eventuali ritardi globali di fallback)
//  - active_mask: bitfield zone attive (bit0 → Z1, bit1 → Z2, ...)
//  - *_delay_ms:  ritardi globali (se vuoi usarli come default di profilo)
// ─────────────────────────────────────────────────────────────────────────────
typedef struct {
    uint16_t active_mask;     // bit0..bit15 → Z1..Z16
    uint32_t entry_delay_ms;  // opzionale fallback (non necessario se usi per-zona)
    uint32_t exit_delay_ms;   // opzionale fallback (non necessario se usi per-zona)
} profile_t;

// ─────────────────────────────────────────────────────────────────────────────
// Opzioni per-zona (usate dal core nei calcoli di entry/exit)
//  - entry_delay=true  → zona a ritardo ingresso; entry_time_ms = durata
//  - exit_delay=true   → zona ignorata durante exit-window; exit_time_ms = durata
//  - auto_exclude=true → se aperta al momento dell’ARM può essere bypassata
// ─────────────────────────────────────────────────────────────────────────────
typedef struct {
    bool     entry_delay;
    uint16_t entry_time_ms;
    bool     exit_delay;
    uint16_t exit_time_ms;
    bool     auto_exclude;
} zone_opts_t;

// ─────────────────────────────────────────────────────────────────────────────
// API principali
// ─────────────────────────────────────────────────────────────────────────────
void           alarm_init(void);
alarm_state_t  alarm_get_state(void);

// Stato temporaneo (ritardi in corso)
bool           alarm_exit_pending(uint32_t* remain_ms);     // true se finestra uscita attiva
bool           alarm_entry_pending(int* zone_1_based, uint32_t* remain_ms); // true se ritardo ingresso attivo

void           alarm_set_profile(alarm_state_t st, profile_t p);
profile_t      alarm_get_profile(alarm_state_t st);

// Config per-zona / bypass / finestra di uscita (chiamate tipicamente da web_server.c)
void           alarm_set_zone_opts(int zone_index_1_based, const zone_opts_t* opts);
void           alarm_set_bypass_mask(uint16_t mask);     // bitfield zone bypassate in questa sessione
uint16_t       alarm_get_bypass_mask(void);
void           alarm_begin_exit(uint32_t duration_ms);   // imposta exit-window (ms) a partire da “ora”

// Tick di valutazione (chiamalo ciclicamente; zmask: bit0→Z1,...; tamper: true se attivo)
void           alarm_tick(uint16_t zmask, bool tamper);

// Comandi
void           alarm_arm_home(void);
void           alarm_arm_away(void);
void           alarm_arm_night(void);
void           alarm_arm_custom(void);
void           alarm_disarm(void);

// Uscite (verso il layer outputs.c)
void           alarm_set_siren(bool on);
void           alarm_set_led_state(bool on);
void           alarm_set_led_maint(bool on);

// Info diagnostica
bool           alarm_last_alarm_was_tamper(void);

#ifdef __cplusplus
}
#endif
