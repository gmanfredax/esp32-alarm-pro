#include "alarm_core.h"
#include "esp_log.h"
#include "outputs.h"
#include <string.h>

static const char* TAG="alarm_core";
static alarm_state_t s_state=ALARM_DISARMED;
static profile_t profiles[7];

void alarm_init(void){
    s_state = ALARM_DISARMED;
    // default profiles: enable all zones in AWAY, perimeter in HOME/NIGHT, custom none
    profiles[ALARM_ARMED_AWAY]  = (profile_t){ .active_mask = 0x0FFF, .entry_delay_ms=30000, .exit_delay_ms=30000 };
    // HOME: perimetrali (esempio: Z1..Z8) -> 0x00FF
    profiles[ALARM_ARMED_HOME]  = (profile_t){ .active_mask = 0x00FF, .entry_delay_ms=20000, .exit_delay_ms=20000 };
    // NIGHT: perimetro + qualche zona tecnica (Z1..Z8 + Z12) -> 0x08FF
    profiles[ALARM_ARMED_NIGHT] = (profile_t){ .active_mask = 0x08FF, .entry_delay_ms=15000, .exit_delay_ms=5000 };
    profiles[ALARM_ARMED_CUSTOM]= (profile_t){ .active_mask = 0x0000, .entry_delay_ms=0, .exit_delay_ms=0 };
    ESP_LOGI(TAG, "init");
    outputs_init();
    outputs_led_state(false);
    outputs_led_maint(false);
    outputs_siren(false);
}

alarm_state_t alarm_get_state(void){ return s_state; }
void alarm_set_profile(alarm_state_t st, profile_t p){ profiles[st]=p; }
profile_t alarm_get_profile(alarm_state_t st){ return profiles[st]; }

void alarm_arm_home(void){ s_state=ALARM_ARMED_HOME; ESP_LOGI(TAG,"ARMED_HOME"); outputs_led_state(true); }
void alarm_arm_away(void){ s_state=ALARM_ARMED_AWAY; ESP_LOGI(TAG,"ARMED_AWAY"); outputs_led_state(true); }
void alarm_arm_night(void){ s_state=ALARM_ARMED_NIGHT; ESP_LOGI(TAG,"ARMED_NIGHT"); outputs_led_state(true); }
void alarm_arm_custom(void){ s_state=ALARM_ARMED_CUSTOM; ESP_LOGI(TAG,"ARMED_CUSTOM"); outputs_led_state(true); }
void alarm_disarm(void){ s_state=ALARM_DISARMED; ESP_LOGI(TAG,"DISARMED"); outputs_led_state(false); outputs_siren(false); }

void alarm_set_siren(bool on){ outputs_siren(on); }
void alarm_set_led_state(bool on){ outputs_led_state(on); }
void alarm_set_led_maint(bool on){ outputs_led_maint(on); }

void alarm_tick(uint16_t zmask, bool tamper){
    if(tamper){
        if(s_state != ALARM_MAINTENANCE){
            s_state = ALARM_ALARM;
            outputs_siren(true);
            ESP_LOGW(TAG,"TAMPER -> ALARM");
        }
        return;
    }
    if(s_state==ALARM_ARMED_HOME || s_state==ALARM_ARMED_AWAY || s_state==ALARM_ARMED_NIGHT || s_state==ALARM_ARMED_CUSTOM){
        profile_t p = profiles[s_state];
        if(zmask & p.active_mask){
            s_state = ALARM_ALARM;
            outputs_siren(true);
            ESP_LOGW(TAG,"ZONE TRIGGER -> ALARM");
        }
    }
}
