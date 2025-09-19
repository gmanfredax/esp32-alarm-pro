#include "alarm_core.h"
#include "esp_log.h"
#include "outputs.h"
#include <string.h>
#include "esp_timer.h"
#include "scenes.h"
#include "gpio_inputs.h"   // per INPUT_ZONES_COUNT e inputs_zone_bit()
#include "app_mqtt.h"

// ─────────────────────────────────────────────────────────────────────────────
// Stato interno
// ─────────────────────────────────────────────────────────────────────────────
static const char* TAG = "alarm_core";

static alarm_state_t s_state = ALARM_DISARMED;
static profile_t     profiles[7];

// Bypass dinamico valido per la singola sessione ARM (auto-exclude)
static uint16_t      s_bypass_mask = 0;

// Opzioni per-zona (ritardi, auto_esclude)
static zone_opts_t   s_zone_opts[16];  // fino a 16 zone supportate

// Finestra di uscita (exit delay)
static uint64_t      s_exit_deadline_us = 0;
// "Ritardo unico": se armo con una o più zone a ritardo già aperte,
// usiamo il loro tempo come exit e, alla scadenza, se restano aperte -> ALLARME.
static uint16_t      s_exit_guard_mask  = 0;   // zone aperte al momento dell'ARM con ritardo ingresso>0
static bool          s_exit_unified     = false;

// Gestione ritardo di ingresso (entry delay)
static bool          s_entry_pending     = false;
static uint16_t      s_entry_zmask       = 0;
static uint64_t      s_entry_deadline_us = 0;
static int           s_entry_zone        = -1;   // indice 0-based di una zona coinvolta

// ─────────────────────────────────────────────────────────────────────────────
// Inizializzazione e profili
// ─────────────────────────────────────────────────────────────────────────────
void alarm_init(void)
{
    s_state = ALARM_DISARMED;
    s_bypass_mask = 0;
    s_exit_deadline_us = 0;
    s_entry_pending = false;
    s_entry_deadline_us = 0;
    s_entry_zone = -1;
    memset(s_zone_opts, 0, sizeof(s_zone_opts));

    const uint16_t ALL = scenes_mask_all(INPUT_ZONES_COUNT);

    // Profili di default (12 zone): AWAY = tutte, HOME/NIGHT = perimetrali, CUSTOM = nessuna
    // profiles[ALARM_ARMED_AWAY]  = (profile_t){ .active_mask = 0x0FFF, .entry_delay_ms = 30000, .exit_delay_ms = 30000 };
    // profiles[ALARM_ARMED_HOME]  = (profile_t){ .active_mask = 0x00FF, .entry_delay_ms =  1500, .exit_delay_ms =  1500 };
    // profiles[ALARM_ARMED_NIGHT] = (profile_t){ .active_mask = 0x00FF, .entry_delay_ms =  1500, .exit_delay_ms =  1500 };
    // profiles[ALARM_ARMED_CUSTOM]= (profile_t){ .active_mask = 0x0000, .entry_delay_ms =     0, .exit_delay_ms =     0 };

    profiles[ALARM_ARMED_AWAY]  = (profile_t){ .active_mask = ALL,    .entry_delay_ms = 30000, .exit_delay_ms = 30000 };
    profiles[ALARM_ARMED_HOME]  = (profile_t){ .active_mask = ALL,    .entry_delay_ms =  1500, .exit_delay_ms =  1500 };
    profiles[ALARM_ARMED_NIGHT] = (profile_t){ .active_mask = ALL,    .entry_delay_ms =  1500, .exit_delay_ms =  1500 };
    profiles[ALARM_ARMED_CUSTOM]= (profile_t){ .active_mask = ALL,    .entry_delay_ms =     0, .exit_delay_ms =     0 };

    profiles[ALARM_DISARMED]    = (profile_t){ .active_mask = 0x0000, .entry_delay_ms =     0, .exit_delay_ms =     0 };
    profiles[ALARM_ALARM]       = (profile_t){ .active_mask = 0x0000, .entry_delay_ms =     0, .exit_delay_ms =     0 };
    profiles[ALARM_MAINTENANCE] = (profile_t){ .active_mask = 0x0000, .entry_delay_ms =     0, .exit_delay_ms =     0 };

    outputs_led_state(false);
    outputs_led_maint(false);
    outputs_siren(false);
    ESP_LOGI(TAG, "Alarm core initialized");
}

alarm_state_t alarm_get_state(void){ return s_state; }
void alarm_set_profile(alarm_state_t st, profile_t p){ profiles[st]=p; }
profile_t alarm_get_profile(alarm_state_t st){ return profiles[st]; }

// Stato temporaneo (ritardi)
bool alarm_exit_pending(uint32_t* remain_ms){
    if (s_exit_deadline_us == 0) { if (remain_ms) *remain_ms = 0; return false; }
    uint64_t now = esp_timer_get_time();
    if (now >= s_exit_deadline_us){ if (remain_ms) *remain_ms = 0; return false; }
    uint32_t ms = (uint32_t)((s_exit_deadline_us - now)/1000ULL);
    if (remain_ms) *remain_ms = ms;
    return true;
}
bool alarm_entry_pending(int* zone_1_based, uint32_t* remain_ms){
    if (!s_entry_pending){ if (remain_ms) *remain_ms = 0; if(zone_1_based) *zone_1_based=-1; return false; }
    uint64_t now = esp_timer_get_time();
    if (now >= s_entry_deadline_us){ if (remain_ms) *remain_ms = 0; if(zone_1_based) *zone_1_based=-1; return false; }
    uint32_t ms = (uint32_t)((s_entry_deadline_us - now)/1000ULL);
    if (remain_ms) *remain_ms = ms;
    if (zone_1_based) *zone_1_based = (s_entry_zone>=0)? (s_entry_zone+1): -1;
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// API per configurazione per-zona / bypass / exit
// ─────────────────────────────────────────────────────────────────────────────
void alarm_set_zone_opts(int zone_index_1_based, const zone_opts_t* opts)
{
    int i = zone_index_1_based - 1;
    if (i < 0 || i >= 16 || !opts) return;
    s_zone_opts[i] = *opts;
}

void alarm_set_bypass_mask(uint16_t mask) { s_bypass_mask = mask; }

uint16_t alarm_get_bypass_mask(void) { return s_bypass_mask; }

void alarm_begin_exit(uint32_t duration_ms)
{
    if (duration_ms == 0) {
        s_exit_deadline_us = 0;
        return;
    }
    const uint64_t now = esp_timer_get_time();
    s_exit_deadline_us = now + ((uint64_t)duration_ms) * 1000ULL;
    ESP_LOGI(TAG, "Exit delay avviato: %u ms", (unsigned)duration_ms);
}

void alarm_set_exit_guard(uint16_t mask, bool use_unified)
{
    s_exit_guard_mask = mask;
    s_exit_unified    = use_unified && (mask != 0);
}
// ─────────────────────────────────────────────────────────────────────────────
// Comandi ARM/DISARM
// ─────────────────────────────────────────────────────────────────────────────
void alarm_arm_home(void)
{
    s_state = ALARM_ARMED_HOME;
    outputs_led_state(true);
    ESP_LOGI(TAG, "ARMED_HOME");
    mqtt_publish_state();
}

void alarm_arm_away(void)
{
    s_state = ALARM_ARMED_AWAY;
    outputs_led_state(true);
    ESP_LOGI(TAG, "ARMED_AWAY");
    mqtt_publish_state();
}

void alarm_arm_night(void)
{
    s_state = ALARM_ARMED_NIGHT;
    outputs_led_state(true);
    ESP_LOGI(TAG, "ARMED_NIGHT");
    mqtt_publish_state();
}

void alarm_arm_custom(void)
{
    s_state = ALARM_ARMED_CUSTOM;
    outputs_led_state(true);
    ESP_LOGI(TAG, "ARMED_CUSTOM");
    mqtt_publish_state();
}

void alarm_disarm(void)
{
    s_state = ALARM_DISARMED;
    outputs_led_state(false);
    outputs_led_maint(false);
    outputs_siren(false);

    // Reset stato dinamico della sessione
    s_bypass_mask = 0;
    s_exit_deadline_us = 0;
    s_entry_pending = false;
    s_entry_deadline_us = 0;
    s_entry_zone = -1;

    ESP_LOGI(TAG, "DISARMED");
    mqtt_publish_state();
}

// ─────────────────────────────────────────────────────────────────────────────
// Uscite
// ─────────────────────────────────────────────────────────────────────────────
void alarm_set_siren(bool on)      { outputs_siren(on); }
void alarm_set_led_state(bool on)  { outputs_led_state(on); }
void alarm_set_led_maint(bool on)  { outputs_led_maint(on); }

// ─────────────────────────────────────────────────────────────────────────────
// Ciclo logico
//  - zmask: bitfield Z1..Z16 -> bit0..bit15
//  - tamper: TRUE se tamper attivo
// ─────────────────────────────────────────────────────────────────────────────
void alarm_tick(uint16_t zmask, bool tamper)
{
    // Tamper ha priorità (eccetto manutenzione)
    if (tamper) {
        if (s_state != ALARM_MAINTENANCE) {
            if (s_state != ALARM_ALARM) {
                s_state = ALARM_ALARM;
                outputs_siren(true);
                ESP_LOGW(TAG, "TAMPER -> ALARM");
                mqtt_publish_state();
            }
        }
        return;
    }

    // Stati ARMATI: gestisci trigger zone / ritardi
    if (s_state == ALARM_ARMED_HOME || s_state == ALARM_ARMED_AWAY || s_state == ALARM_ARMED_NIGHT || s_state == ALARM_ARMED_CUSTOM)
    {
        const profile_t p = profiles[s_state];
        uint16_t eff_mask = p.active_mask & scenes_get_active_mask(); // scenari
        eff_mask &= ~s_bypass_mask;                                   // bypass sessione

        const uint64_t now = esp_timer_get_time();
        const bool in_exit = (s_exit_deadline_us != 0 && now < s_exit_deadline_us);

        // Ritardo unico: se la finestra di uscita è stata avviata perché c'erano zone a ritardo già aperte,
        // allora allo scadere dell'exit, se una di quelle zone è ANCORA aperta, scatta l'allarme.
        if (s_exit_unified && s_exit_deadline_us != 0 && now >= s_exit_deadline_us) {
            if ((zmask & s_exit_guard_mask) != 0) {
                if (s_state != ALARM_ALARM) {
                    s_state = ALARM_ALARM;
                    outputs_siren(true);
                    ESP_LOGW(TAG, "EXIT timeout (ritardo unico) con zona ancora aperta -> ALARM");
                    mqtt_publish_state();
                }
                // reset stato entry eventuale
                s_entry_pending = false;
                s_entry_zmask = 0;
                s_entry_deadline_us = 0;
                s_entry_zone = -1;
                return;
            } else {
                // tutte richiusE prima della scadenza: fine exit "silenziosa"
                s_exit_unified = false;
                s_exit_guard_mask = 0;
                // prosegui (stato rimane armato)
            }
        }

        // Se è in corso un entry delay, verifica la scadenza
        if (s_entry_pending) {
            if (now >= s_entry_deadline_us) {
                if (s_state != ALARM_ALARM) {
                    s_state = ALARM_ALARM;
                    outputs_siren(true);
                    ESP_LOGW(TAG, "ENTRY timeout -> ALARM (Z%d)", s_entry_zone >= 0 ? (s_entry_zone + 1) : -1);
                    mqtt_publish_state();
                }
                s_entry_pending = false;
            }
            // Non “return”: continuiamo comunque a valutare nuovi trigger
        }

        // Trigger effettivi sulle zone attive (profilo + scenari − bypass)
        uint16_t trig = zmask & eff_mask;
        if (!trig) return;

        // Durante exit window: ignora i trigger di sole zone marcate exit_delay
        if (in_exit) {
            uint16_t masked = 0;
            for (int z = 0; z < 16; ++z) {
                if (trig & (1u << z)) {
                    if (s_zone_opts[z].exit_delay || (s_exit_unified && (s_exit_guard_mask & (1u << z)))) masked |= (1u << z);
                }
            }
            // Se tutte le zone triggerate sono "exit_delay", ignorale finché dura l'exit
            if ((trig & ~masked) == 0) return;
            // Altrimenti, “trig” mantiene almeno una zona fuori exit_delay → prosegui
        }

        // Se esiste una zona senza entry_delay -> ALARM immediato
        bool any_instant = false;
        for (int z = 0; z < 16; ++z) {
            if (trig & (1u << z)) {
                if (!s_zone_opts[z].entry_delay) {
                    any_instant = true;
                    break;
                }
            }
        }
        if (any_instant) {
            if (s_state != ALARM_ALARM) {
                s_state = ALARM_ALARM;
                outputs_siren(true);
                ESP_LOGW(TAG, "ZONE instant -> ALARM");
                mqtt_publish_state();
            }
            return;
        }

        // Tutte le zone triggerate richiedono entry_delay
        // Regola richiesta: usare il tempo MINIMO tra quelle violate (non estendere).
        uint32_t min_ms = 0xFFFFFFFFu;
        int      min_z  = -1;
        for (int z = 0; z < 16; ++z) {
            if (trig & (1u << z)) {
                const uint32_t ms = s_zone_opts[z].entry_time_ms;
                if (ms < min_ms) { min_ms = ms; min_z = z; }
            }
        }
        if (min_ms == 0xFFFFFFFFu) min_ms = 0;

        if (!s_entry_pending) {
            s_entry_pending = true;
            s_entry_zone = min_z;
            s_entry_deadline_us = now + ((uint64_t)min_ms) * 1000ULL;
            ESP_LOGI(TAG, "ENTRY delay avviato %u ms (Z%d)", (unsigned)min_ms, min_z >= 0 ? (min_z + 1) : -1);
        } else {
            // Se già in corso, eventualmente ACCORCIA la deadline se il nuovo minimo è più vicino
            const uint64_t candidate = now + ((uint64_t)min_ms) * 1000ULL;
            if (candidate < s_entry_deadline_us) {
                s_entry_deadline_us = candidate;
                s_entry_zone = min_z;
                ESP_LOGI(TAG, "ENTRY deadline accorciata a %u ms (Z%d)", (unsigned)min_ms, min_z >= 0 ? (min_z + 1) : -1);
            }
        }
    }
}