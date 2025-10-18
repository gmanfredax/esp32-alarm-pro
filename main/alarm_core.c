#include "alarm_core.h"
#include "esp_log.h"
#include "outputs.h"
#include "audit_log.h"
#include <string.h>
#include <stdio.h>
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

// True se l'ultimo passaggio allo stato ALARM è stato causato dal tamper
static bool          s_alarm_from_tamper = false;

// Bypass dinamico valido per la singola sessione ARM (auto-exclude)
static zone_mask_t   s_bypass_mask;

// Opzioni per-zona (ritardi, auto_esclude)
static zone_opts_t   s_zone_opts[ALARM_MAX_ZONES];

// Finestra di uscita (exit delay)
static uint64_t      s_exit_deadline_us  = 0;
// "Ritardo unico": se armo con una o più zone a ritardo già aperte,
// usiamo il loro tempo come exit e, alla scadenza, se restano aperte -> ALLARME.
static zone_mask_t   s_exit_guard_mask;   // zone aperte al momento dell'ARM con ritardo ingresso>0
static bool          s_exit_unified      = false;

// Gestione ritardo di ingresso (entry delay)
static bool          s_entry_pending     = false;
static zone_mask_t   s_entry_zmask;

const char* alarm_state_name(alarm_state_t st)
{
    switch (st) {
    case ALARM_DISARMED:    return "DISARMED";
    case ALARM_ARMED_HOME:  return "ARMED_HOME";
    case ALARM_ARMED_AWAY:  return "ARMED_AWAY";
    case ALARM_ARMED_NIGHT: return "ARMED_NIGHT";
    case ALARM_ARMED_CUSTOM:return "ARMED_CUSTOM";
    case ALARM_ALARM:       return "ALARM";
    case ALARM_MAINTENANCE: return "MAINTENANCE";
    default:                return "UNKNOWN";
    }
}

static void audit_alarm_trigger_event(const char *cause, const zone_mask_t *zones, int zone_index)
{
    char note[64];
    char zones_buf[48];
    zone_mask_t tmp;
    bool has_mask = false;
    zone_mask_clear(&tmp);
    if (zones) {
        zone_mask_copy(&tmp, zones);
        zone_mask_limit(&tmp, ALARM_MAX_ZONES);
        has_mask = zone_mask_any(&tmp);
    }
    if (!has_mask && zone_index >= 0 && zone_index < (int)ALARM_MAX_ZONES) {
        zone_mask_clear(&tmp);
        zone_mask_set(&tmp, (uint16_t)zone_index);
        has_mask = true;
    }
    if (has_mask) {
        zone_mask_format_brief(&tmp, ALARM_MAX_ZONES, 4, zones_buf, sizeof(zones_buf));
    } else {
        snprintf(zones_buf, sizeof(zones_buf), "-");
    }
    const char *reason = (cause && cause[0]) ? cause : "unknown";
    size_t avail = sizeof(note);
    if (avail > 0) {
        const size_t prefix = 13; // strlen("cause=") + strlen(" zones=")
        if (avail > 1) {
            avail -= 1; // leave space for null terminator
        }
        if (avail > prefix) {
            avail -= prefix;
        } else {
            avail = 0;
        }
    }
    size_t reason_len = strnlen(reason, avail);
    size_t zones_len = 0;
    if (avail > reason_len) {
        size_t zones_avail = avail - reason_len;
        size_t zones_cap = sizeof(zones_buf) - 1;
        if (zones_avail < zones_cap) {
            zones_cap = zones_avail;
        }
        zones_len = strnlen(zones_buf, zones_cap);
    }
    snprintf(note, sizeof(note), "cause=%.*s zones=%.*s", (int)reason_len, reason, (int)zones_len, zones_buf);
    audit_append("alarm_trigger", "system", 1, note);
}

static uint64_t      s_entry_deadline_us = 0;
static int           s_entry_zone        = -1;   // indice 0-based di una zona coinvolta

// ─────────────────────────────────────────────────────────────────────────────
// Inizializzazione e profili
// ─────────────────────────────────────────────────────────────────────────────
void alarm_init(void)
{
    s_state = ALARM_DISARMED;
    zone_mask_clear(&s_bypass_mask);
    s_exit_deadline_us = 0;
    s_entry_pending = false;
    s_entry_deadline_us = 0;
    s_entry_zone = -1;
    s_alarm_from_tamper = false;
    zone_mask_clear(&s_exit_guard_mask);
    zone_mask_clear(&s_entry_zmask);
    memset(s_zone_opts, 0, sizeof(s_zone_opts));

    zone_mask_t ALL;
    scenes_mask_all(ALARM_MAX_ZONES, &ALL);
    zone_mask_t NONE;
    zone_mask_clear(&NONE);

    profiles[ALARM_ARMED_AWAY]  = (profile_t){ .active_mask = ALL,  .entry_delay_ms = 30000, .exit_delay_ms = 30000 };
    profiles[ALARM_ARMED_HOME]  = (profile_t){ .active_mask = ALL,  .entry_delay_ms =  1500, .exit_delay_ms =  1500 };
    profiles[ALARM_ARMED_NIGHT] = (profile_t){ .active_mask = ALL,  .entry_delay_ms =  1500, .exit_delay_ms =  1500 };
    profiles[ALARM_ARMED_CUSTOM]= (profile_t){ .active_mask = ALL,  .entry_delay_ms =     0, .exit_delay_ms =     0 };

    profiles[ALARM_DISARMED]    = (profile_t){ .active_mask = NONE, .entry_delay_ms =     0, .exit_delay_ms =     0 };
    profiles[ALARM_ALARM]       = (profile_t){ .active_mask = NONE, .entry_delay_ms =     0, .exit_delay_ms =     0 };
    profiles[ALARM_MAINTENANCE] = (profile_t){ .active_mask = NONE, .entry_delay_ms =     0, .exit_delay_ms =     0 };

    outputs_led_state(false);
    outputs_led_maint(false);
    outputs_siren(false);
    ESP_LOGI(TAG, "Alarm core initialized");
}

bool alarm_last_alarm_was_tamper(void)
{
    return s_alarm_from_tamper;
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
    if (i < 0 || i >= ALARM_MAX_ZONES || !opts) return;
    s_zone_opts[i] = *opts;
}

void alarm_set_bypass_mask(const zone_mask_t *mask)
{
    if (!mask) {
        zone_mask_clear(&s_bypass_mask);
        return;
    }
    zone_mask_copy(&s_bypass_mask, mask);
    zone_mask_limit(&s_bypass_mask, ALARM_MAX_ZONES);
}

void alarm_get_bypass_mask(zone_mask_t *out_mask)
{
    if (!out_mask) {
        return;
    }
    zone_mask_copy(out_mask, &s_bypass_mask);
}

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

void alarm_set_exit_guard(const zone_mask_t *mask, bool use_unified)
{
    if (mask) {
        zone_mask_copy(&s_exit_guard_mask, mask);
        zone_mask_limit(&s_exit_guard_mask, ALARM_MAX_ZONES);
    } else {
        zone_mask_clear(&s_exit_guard_mask);
    }
    s_exit_unified = use_unified && zone_mask_any(&s_exit_guard_mask);
}
// ─────────────────────────────────────────────────────────────────────────────
// Comandi ARM/DISARM
// ─────────────────────────────────────────────────────────────────────────────
void alarm_arm_home(void)
{
    s_state = ALARM_ARMED_HOME;
    s_alarm_from_tamper = false;
    outputs_led_state(true);
    ESP_LOGI(TAG, "ARMED_HOME");
    mqtt_publish_state();
}

void alarm_arm_away(void)
{
    s_state = ALARM_ARMED_AWAY;
    s_alarm_from_tamper = false;
    outputs_led_state(true);
    ESP_LOGI(TAG, "ARMED_AWAY");
    mqtt_publish_state();
}

void alarm_arm_night(void)
{
    s_state = ALARM_ARMED_NIGHT;
    s_alarm_from_tamper = false;
    outputs_led_state(true);
    ESP_LOGI(TAG, "ARMED_NIGHT");
    mqtt_publish_state();
}

void alarm_arm_custom(void)
{
    s_state = ALARM_ARMED_CUSTOM;
    s_alarm_from_tamper = false;
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
    zone_mask_clear(&s_bypass_mask);
    s_exit_deadline_us = 0;
    s_entry_pending = false;
    s_entry_deadline_us = 0;
    s_entry_zone = -1;
    s_alarm_from_tamper = false;
    zone_mask_clear(&s_exit_guard_mask);
    zone_mask_clear(&s_entry_zmask);

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
//  - zmask: bitfield Z1..Z32 -> bit0..bit31
//  - tamper: TRUE se tamper attivo
// ─────────────────────────────────────────────────────────────────────────────
void alarm_tick(const zone_mask_t *zmask, bool tamper)
{
    if (!zmask) {
        return;
    }
    // Tamper ha priorità (eccetto manutenzione)
    if (tamper) {
        if (s_state != ALARM_MAINTENANCE) {
            if (s_state != ALARM_ALARM) {
                s_state = ALARM_ALARM;
                s_alarm_from_tamper = true;
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
        zone_mask_t eff_mask = p.active_mask;
        zone_mask_t scene_mask;
        scenes_get_active_mask(&scene_mask);
        zone_mask_and(&eff_mask, &eff_mask, &scene_mask); // scenari
        zone_mask_andnot(&eff_mask, &eff_mask, &s_bypass_mask); // bypass sessione

        const uint64_t now = esp_timer_get_time();
        const bool in_exit = (s_exit_deadline_us != 0 && now < s_exit_deadline_us);

        // Ritardo unico: se la finestra di uscita è stata avviata perché c'erano zone a ritardo già aperte,
        // allora allo scadere dell'exit, se una di quelle zone è ANCORA aperta, scatta l'allarme.
        if (s_exit_unified && s_exit_deadline_us != 0 && now >= s_exit_deadline_us) {
            if (zone_mask_intersects(zmask, &s_exit_guard_mask)) {
                if (s_state != ALARM_ALARM) {
                    s_state = ALARM_ALARM;
                    s_alarm_from_tamper = false;
                    outputs_siren(true);
                    ESP_LOGW(TAG, "EXIT timeout (ritardo unico) con zona ancora aperta -> ALARM");
                    mqtt_publish_state();
                    zone_mask_t triggered;
                    zone_mask_and(&triggered, zmask, &s_exit_guard_mask);
                    audit_alarm_trigger_event("exit", &triggered, -1);
                }
                // reset stato entry eventuale
                s_entry_pending = false;
                zone_mask_clear(&s_entry_zmask);
                s_entry_deadline_us = 0;
                s_entry_zone = -1;
                return;
            } else {
                // tutte richiusE prima della scadenza: fine exit "silenziosa"
                s_exit_unified = false;
                zone_mask_clear(&s_exit_guard_mask);
                // prosegui (stato rimane armato)
            }
        }

        // Se è in corso un entry delay, verifica la scadenza
        if (s_entry_pending) {
            if (now >= s_entry_deadline_us) {
                if (s_state != ALARM_ALARM) {
                    s_state = ALARM_ALARM;
                    s_alarm_from_tamper = false;
                    outputs_siren(true);
                    ESP_LOGW(TAG, "ENTRY timeout -> ALARM (Z%d)", s_entry_zone >= 0 ? (s_entry_zone + 1) : -1);
                    mqtt_publish_state();
                    audit_alarm_trigger_event("entry_timeout", &s_entry_zmask, s_entry_zone);
                }
                s_entry_pending     = false;
                s_entry_deadline_us = 0;
                s_entry_zone        = -1;
                zone_mask_clear(&s_entry_zmask);
                return;
            }
            // Non “return”: continuiamo comunque a valutare nuovi trigger
        }

        // Trigger effettivi sulle zone attive (profilo + scenari − bypass)
        zone_mask_t trig;
        zone_mask_and(&trig, zmask, &eff_mask);
        if (!zone_mask_any(&trig)) return;

        // Durante exit window: ignora i trigger di sole zone marcate exit_delay
        if (in_exit) {
            bool has_non_exit = false;
            for (int z = 0; z < ALARM_MAX_ZONES; ++z) {
                if (zone_mask_test(&trig, (uint16_t)z)) {
                    bool guarded = s_exit_unified && zone_mask_test(&s_exit_guard_mask, (uint16_t)z);
                    if (!s_zone_opts[z].exit_delay && !guarded) {
                        has_non_exit = true;
                        break;
                    }
                }
            }
            // Se tutte le zone triggerate sono "exit_delay", ignorale finché dura l'exit
            if (!has_non_exit) return;
            // Altrimenti, “trig” mantiene almeno una zona fuori exit_delay → prosegui
        }

        // Se esiste una zona senza entry_delay -> ALARM immediato
        bool any_instant = false;
        for (int z = 0; z < ALARM_MAX_ZONES; ++z) {
            if (zone_mask_test(&trig, (uint16_t)z)) {
                if (!s_zone_opts[z].entry_delay) {
                    any_instant = true;
                    break;
                }
            }
        }
        if (any_instant) {
            if (s_state != ALARM_ALARM) {
                s_state = ALARM_ALARM;
                s_alarm_from_tamper = false;
                outputs_siren(true);
                ESP_LOGW(TAG, "ZONE instant -> ALARM");
                mqtt_publish_state();
                audit_alarm_trigger_event("instant", &trig, -1);
            }
            return;
        }

        // Tutte le zone triggerate richiedono entry_delay
        // Regola richiesta: usare il tempo MINIMO tra quelle violate (non estendere).
        uint32_t min_ms = 0xFFFFFFFFu;
        int      min_z  = -1;
        for (int z = 0; z < ALARM_MAX_ZONES; ++z) {
            if (zone_mask_test(&trig, (uint16_t)z)) {
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
            zone_mask_copy(&s_entry_zmask, &trig);
        } else {
            // Se già in corso, eventualmente ACCORCIA la deadline se il nuovo minimo è più vicino
            const uint64_t candidate = now + ((uint64_t)min_ms) * 1000ULL;
            if (candidate < s_entry_deadline_us) {
                s_entry_deadline_us = candidate;
                s_entry_zone = min_z;
                ESP_LOGI(TAG, "ENTRY deadline accorciata a %u ms (Z%d)", (unsigned)min_ms, min_z >= 0 ? (min_z + 1) : -1);
            }
            zone_mask_or(&s_entry_zmask, &s_entry_zmask, &trig);
        }
    }
}