#pragma once
#include <stdbool.h>
#include <stdint.h>

typedef enum {
    ALARM_DISARMED = 0,
    ALARM_ARMED_HOME,
    ALARM_ARMED_AWAY,
    ALARM_ARMED_NIGHT,
    ALARM_ARMED_CUSTOM,
    ALARM_ALARM,
    ALARM_MAINTENANCE
} alarm_state_t;

typedef struct {
    uint16_t active_mask;   // bit0..11 for Z1..Z12
    uint16_t entry_delay_ms;
    uint16_t exit_delay_ms;
} profile_t;

void alarm_init(void);
alarm_state_t alarm_get_state(void);
void alarm_set_profile(alarm_state_t st, profile_t p);
profile_t alarm_get_profile(alarm_state_t st);
void alarm_tick(uint16_t zmask, bool tamper);

void alarm_arm_home(void);
void alarm_arm_away(void);
void alarm_arm_night(void);
void alarm_arm_custom(void);
void alarm_disarm(void);

// Outputs
void alarm_set_siren(bool on);
void alarm_set_led_state(bool on);
void alarm_set_led_maint(bool on);
