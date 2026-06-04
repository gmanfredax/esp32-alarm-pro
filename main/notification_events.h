#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NOTIFY_SEVERITY_INFO = 0,
    NOTIFY_SEVERITY_WARNING,
    NOTIFY_SEVERITY_ALARM,
    NOTIFY_SEVERITY_CRITICAL,
    NOTIFY_SEVERITY_TECHNICAL,
} notification_severity_t;

typedef struct {
    char type[32];
    notification_severity_t severity;
    char source[32];
    int zone_id;
    char title[64];
    char message[160];
    bool requires_ack;
    char dedup_key[64];
} notification_event_t;

typedef struct {
    bool mqtt_publish_enabled;
    notification_severity_t min_severity;
    bool repeat_critical_unacked;
    uint32_t repeat_interval_s;
} notification_config_t;

esp_err_t notification_events_init(void);
esp_err_t notification_events_load_config(notification_config_t *cfg);
esp_err_t notification_events_save_config(const notification_config_t *cfg);
esp_err_t notification_events_append_config_json(cJSON *root);
esp_err_t notification_events_update_config_from_json(const cJSON *root);
esp_err_t notification_events_emit(const notification_event_t *event);
esp_err_t notification_events_emit_simple(const char *type, notification_severity_t severity,
                                          const char *source, int zone_id,
                                          const char *title, const char *message,
                                          bool requires_ack);
esp_err_t notification_events_mark_ack(const char *event_id, const char *actor);
const char *notification_severity_name(notification_severity_t severity);

#ifdef __cplusplus
}
#endif
