#include "notification_events.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "esp_log.h"
#include "esp_random.h"
#include "nvs.h"

#include "app_mqtt.h"

static const char *TAG = "notify";
static uint32_t s_seq;

const char *notification_severity_name(notification_severity_t severity)
{
    switch (severity) {
    case NOTIFY_SEVERITY_INFO: return "info";
    case NOTIFY_SEVERITY_WARNING: return "warning";
    case NOTIFY_SEVERITY_ALARM: return "alarm";
    case NOTIFY_SEVERITY_CRITICAL: return "critical";
    case NOTIFY_SEVERITY_TECHNICAL: return "technical";
    default: return "info";
    }
}

static notification_severity_t severity_from_name(const char *s)
{
    if (!s) return NOTIFY_SEVERITY_INFO;
    if (!strcmp(s, "warning")) return NOTIFY_SEVERITY_WARNING;
    if (!strcmp(s, "alarm")) return NOTIFY_SEVERITY_ALARM;
    if (!strcmp(s, "critical")) return NOTIFY_SEVERITY_CRITICAL;
    if (!strcmp(s, "technical")) return NOTIFY_SEVERITY_TECHNICAL;
    return NOTIFY_SEVERITY_INFO;
}

esp_err_t notification_events_init(void) { return ESP_OK; }

esp_err_t notification_events_load_config(notification_config_t *cfg)
{
    if (!cfg) return ESP_ERR_INVALID_ARG;
    cfg->mqtt_publish_enabled = true;
    cfg->min_severity = NOTIFY_SEVERITY_INFO;
    cfg->repeat_critical_unacked = true;
    cfg->repeat_interval_s = 300;
    nvs_handle_t nvs;
    if (nvs_open("notify", NVS_READONLY, &nvs) == ESP_OK) {
        uint8_t b = 0;
        if (nvs_get_u8(nvs, "mqtt_pub", &b) == ESP_OK) cfg->mqtt_publish_enabled = b != 0;
        if (nvs_get_u8(nvs, "min_sev", &b) == ESP_OK) cfg->min_severity = (notification_severity_t)b;
        if (nvs_get_u8(nvs, "rep_crit", &b) == ESP_OK) cfg->repeat_critical_unacked = b != 0;
        uint32_t u = 0;
        if (nvs_get_u32(nvs, "rep_int", &u) == ESP_OK) cfg->repeat_interval_s = u;
        nvs_close(nvs);
    }
    return ESP_OK;
}

esp_err_t notification_events_save_config(const notification_config_t *cfg)
{
    if (!cfg) return ESP_ERR_INVALID_ARG;
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("notify", NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;
    nvs_set_u8(nvs, "mqtt_pub", cfg->mqtt_publish_enabled ? 1 : 0);
    nvs_set_u8(nvs, "min_sev", (uint8_t)cfg->min_severity);
    nvs_set_u8(nvs, "rep_crit", cfg->repeat_critical_unacked ? 1 : 0);
    nvs_set_u32(nvs, "rep_int", cfg->repeat_interval_s);
    err = nvs_commit(nvs);
    nvs_close(nvs);
    return err;
}

esp_err_t notification_events_append_config_json(cJSON *root)
{
    notification_config_t cfg; notification_events_load_config(&cfg);
    cJSON_AddBoolToObject(root, "mqtt_publish_enabled", cfg.mqtt_publish_enabled);
    cJSON_AddStringToObject(root, "min_severity", notification_severity_name(cfg.min_severity));
    cJSON_AddBoolToObject(root, "repeat_critical_unacked", cfg.repeat_critical_unacked);
    cJSON_AddNumberToObject(root, "repeat_interval_s", cfg.repeat_interval_s);
    cJSON_AddBoolToObject(root, "webhook_supported", false);
    cJSON_AddBoolToObject(root, "gsm_supported", false);
    return ESP_OK;
}

esp_err_t notification_events_update_config_from_json(const cJSON *root)
{
    notification_config_t cfg; notification_events_load_config(&cfg);
    const cJSON *j = cJSON_GetObjectItemCaseSensitive(root, "mqtt_publish_enabled");
    if (cJSON_IsBool(j)) cfg.mqtt_publish_enabled = cJSON_IsTrue(j);
    j = cJSON_GetObjectItemCaseSensitive(root, "min_severity");
    if (cJSON_IsString(j)) cfg.min_severity = severity_from_name(j->valuestring);
    j = cJSON_GetObjectItemCaseSensitive(root, "repeat_critical_unacked");
    if (cJSON_IsBool(j)) cfg.repeat_critical_unacked = cJSON_IsTrue(j);
    j = cJSON_GetObjectItemCaseSensitive(root, "repeat_interval_s");
    if (cJSON_IsNumber(j)) cfg.repeat_interval_s = (uint32_t)j->valuedouble;
    return notification_events_save_config(&cfg);
}

esp_err_t notification_events_emit(const notification_event_t *event)
{
    if (!event) return ESP_ERR_INVALID_ARG;
    notification_config_t cfg; notification_events_load_config(&cfg);
    if (event->severity < cfg.min_severity) return ESP_OK;
    cJSON *root = cJSON_CreateObject();
    if (!root) return ESP_ERR_NO_MEM;
    char id[40]; snprintf(id, sizeof(id), "%lu-%08lx", (unsigned long)time(NULL), (unsigned long)(++s_seq ^ esp_random()));
    cJSON_AddStringToObject(root, "event_id", id);
    cJSON_AddNumberToObject(root, "timestamp", (double)time(NULL));
    cJSON_AddStringToObject(root, "type", event->type);
    cJSON_AddStringToObject(root, "severity", notification_severity_name(event->severity));
    cJSON_AddStringToObject(root, "source", event->source[0] ? event->source : "firmware");
    if (event->zone_id > 0) cJSON_AddNumberToObject(root, "zone_id", event->zone_id);
    cJSON_AddStringToObject(root, "title", event->title);
    cJSON_AddStringToObject(root, "message", event->message);
    cJSON_AddBoolToObject(root, "requires_ack", event->requires_ack);
    if (event->dedup_key[0]) cJSON_AddStringToObject(root, "dedup_key", event->dedup_key);
    char *payload = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!payload) return ESP_ERR_NO_MEM;
    ESP_LOGI(TAG, "event %s %s", event->type, notification_severity_name(event->severity));
    esp_err_t err = cfg.mqtt_publish_enabled ? mqtt_publish_event_json(payload, notification_severity_name(event->severity)) : ESP_OK;
    cJSON_free(payload);
    return err;
}

esp_err_t notification_events_emit_simple(const char *type, notification_severity_t severity,
                                          const char *source, int zone_id,
                                          const char *title, const char *message,
                                          bool requires_ack)
{
    notification_event_t e = {0};
    snprintf(e.type, sizeof(e.type), "%s", type ? type : "event");
    e.severity = severity;
    snprintf(e.source, sizeof(e.source), "%s", source ? source : "firmware");
    e.zone_id = zone_id;
    snprintf(e.title, sizeof(e.title), "%s", title ? title : e.type);
    snprintf(e.message, sizeof(e.message), "%s", message ? message : "");
    e.requires_ack = requires_ack;
    return notification_events_emit(&e);
}

esp_err_t notification_events_mark_ack(const char *event_id, const char *actor)
{
    ESP_LOGI(TAG, "ack event=%s actor=%s", event_id ? event_id : "", actor ? actor : "mqtt");
    return ESP_OK;
}
