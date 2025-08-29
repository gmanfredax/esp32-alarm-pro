// main/mqtt_client.c
#include "esp_mac.h"
#include <mqtt_client.h>       // header UFFICIALE IDF
#include "app_mqtt.h"          // il TUO header (rinominato)
#include "esp_log.h"
#include <stdio.h>
#include "pins.h"

static const char* TAG = "mqtt";
static esp_mqtt_client_handle_t s_client = NULL;

esp_err_t mqtt_start(void){
    const esp_mqtt_client_config_t cfg = {
        .broker.address.uri = "mqtt://192.168.1.10", // cambia secondo rete
    };
    s_client = esp_mqtt_client_init(&cfg);
    if (!s_client) return ESP_FAIL;
    esp_err_t err = esp_mqtt_client_start(s_client);
    if (err != ESP_OK) return err;
    ESP_LOGI(TAG, "MQTT started");
    return ESP_OK;
}

void mqtt_publish_state(const char* state){
    if(!s_client) return;
    esp_mqtt_client_publish(s_client, "alarm/state", state, 0, 1, 0);
}

void mqtt_publish_zones(uint16_t mask){
    if(!s_client) return;
    char b[16];
    snprintf(b, sizeof(b), "0x%03X", mask & 0x0FFF);
    esp_mqtt_client_publish(s_client, "alarm/zones", b, 0, 1, 0);
}
