// main/mqtt_client.c
// MQTT client per ESP-IDF 5.x con gating su ETH/IP e autostart sugli eventi di rete.

#include <string.h>
#include <inttypes.h>
#include "esp_check.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_mac.h"
#include "mqtt_client.h"

// ─────────────────────────────────────────────────────────────────────────────
// Opzioni da Kconfig (impostale in sdkconfig / menuconfig → Component config → MQTT)
#ifndef CONFIG_MQTT_URI
#define CONFIG_MQTT_URI           "mqtt://192.168.1.10:1883"
#endif
#ifndef CONFIG_MQTT_USERNAME
#define CONFIG_MQTT_USERNAME      ""
#endif
#ifndef CONFIG_MQTT_PASSWORD
#define CONFIG_MQTT_PASSWORD      ""
#endif
#ifndef CONFIG_MQTT_CLIENT_ID_PREFIX
#define CONFIG_MQTT_CLIENT_ID_PREFIX "CentraleESP32-"
#endif
#ifndef CONFIG_MQTT_KEEPALIVE
#define CONFIG_MQTT_KEEPALIVE     60
#endif
#ifndef CONFIG_MQTT_DISABLE_AUTO_RECONNECT
#define CONFIG_MQTT_DISABLE_AUTO_RECONNECT 0
#endif
// Se usi TLS, puoi abilitare le seguenti opzioni in Kconfig e caricare i certificati:
// CONFIG_MQTT_TRANSPORT_SSL, CONFIG_MQTT_CERT_PEM, ecc.
// ─────────────────────────────────────────────────────────────────────────────

// Header opzionale (se hai già app_mqtt.h, usa il tuo)
// /* app_mqtt.h
// #pragma once
// #include <stdbool.h>
// void mqtt_start(void);
// void mqtt_stop(void);
// bool mqtt_is_connected(void);
// int  mqtt_publish(const char* topic, const char* data, int qos, int retain);
// */

// ─────────────────────────────────────────────────────────────────────────────

static const char* TAG = "mqtt";

static esp_mqtt_client_handle_t s_client = NULL;
static bool s_started = false;
static bool s_connected = false;

// Hook deboli da poter sovrascrivere in altri file (weak symbols)
__attribute__((weak)) void mqtt_on_connected(esp_mqtt_client_handle_t client) {
    // Esempio: subscribe a topic
    // esp_mqtt_client_subscribe(client, "allarme/cmd/#", 1);
}
__attribute__((weak)) void mqtt_on_disconnected(void) {}
__attribute__((weak)) void mqtt_on_message(const esp_mqtt_event_handle_t e) {
    // Esempio:
    // ESP_LOGI(TAG, "MSG topic=%.*s data=%.*s", e->topic_len, e->topic, e->data_len, e->data);
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility: ottieni handle netif ETH e verifica IP pronto

static esp_netif_t* get_eth_netif(void) {
    // La chiave di default per l'interfaccia Ethernet creata da esp_netif è "ETH_DEF".
    return esp_netif_get_handle_from_ifkey("ETH_DEF");
}

static bool eth_has_ip(void) {
    esp_netif_t* eth = get_eth_netif();
    if (!eth) return false;
    esp_netif_ip_info_t info;
    if (esp_netif_get_ip_info(eth, &info) != ESP_OK) return false;
    return info.ip.addr != 0;
}

static void log_ip_info(const char* prefix) {
    esp_netif_t* eth = get_eth_netif();
    if (!eth) {
        ESP_LOGW(TAG, "%s: nessuna netif ETH", prefix);
        return;
    }
    esp_netif_ip_info_t info;
    if (esp_netif_get_ip_info(eth, &info) == ESP_OK) {
        char ip[16], nm[16], gw[16];
        esp_ip4addr_ntoa(&info.ip, ip, sizeof ip);
        esp_ip4addr_ntoa(&info.netmask, nm, sizeof nm);
        esp_ip4addr_ntoa(&info.gw, gw, sizeof gw);
        ESP_LOGI(TAG, "%s: ip=%s mask=%s gw=%s", prefix, ip, nm, gw);
    } else {
        ESP_LOGW(TAG, "%s: nessun IP", prefix);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Event handler MQTT

static void mqtt_event_handler(void* handler_args, esp_event_base_t base, int32_t event_id, void* event_data)
{
    esp_mqtt_event_handle_t e = (esp_mqtt_event_handle_t)event_data;
    switch ((esp_mqtt_event_id_t)event_id) {
    case MQTT_EVENT_CONNECTED:
        s_connected = true;
        ESP_LOGI(TAG, "MQTT CONNECTED");
        mqtt_on_connected(e->client);
        break;
    case MQTT_EVENT_DISCONNECTED:
        s_connected = false;
        ESP_LOGW(TAG, "MQTT DISCONNECTED");
        mqtt_on_disconnected();
        break;
    case MQTT_EVENT_SUBSCRIBED:
        ESP_LOGI(TAG, "SUBSCRIBED msg_id=%d", e->msg_id);
        break;
    case MQTT_EVENT_UNSUBSCRIBED:
        ESP_LOGI(TAG, "UNSUBSCRIBED msg_id=%d", e->msg_id);
        break;
    case MQTT_EVENT_PUBLISHED:
        ESP_LOGD(TAG, "PUBLISHED msg_id=%d", e->msg_id);
        break;
    case MQTT_EVENT_DATA:
        mqtt_on_message(e);
        break;
    case MQTT_EVENT_ERROR:
        ESP_LOGE(TAG, "MQTT EVENT ERROR");
        break;
    default:
        ESP_LOGD(TAG, "MQTT event id=%" PRId32, event_id);
        break;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Creazione e avvio client

static void mqtt_create_if_needed(void)
{
    if (s_client) return;

    // Client ID = prefix + MAC
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_ETH);
    char client_id[64];
    snprintf(client_id, sizeof client_id, "%s%02X%02X%02X%02X%02X%02X",
             CONFIG_MQTT_CLIENT_ID_PREFIX, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    esp_mqtt_client_config_t cfg = {
        .broker.address.uri = CONFIG_MQTT_URI,
        .credentials = {
            .username = CONFIG_MQTT_USERNAME,
            .authentication = {
                .password = CONFIG_MQTT_PASSWORD,
            },
            .client_id = client_id,
        },
        .network = {
            .disable_auto_reconnect = CONFIG_MQTT_DISABLE_AUTO_RECONNECT,
        },
        .session = {
            .keepalive = CONFIG_MQTT_KEEPALIVE,
        },
        // Se usi TLS, popola qui .broker.verification e .broker.certificate
        // .broker.verification.certificate = (const char*) mqtt_root_ca_pem,
    };

    s_client = esp_mqtt_client_init(&cfg);
    ESP_ERROR_CHECK(esp_mqtt_client_register_event(s_client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL));
    ESP_LOGI(TAG, "MQTT client creato (uri=%s, client_id=%s)", CONFIG_MQTT_URI, client_id);
}

void mqtt_start(void)
{
    // Evita di partire se la rete non è pronta
    if (!eth_has_ip()) {
        ESP_LOGW(TAG, "Rete non pronta (no IP). Rimando start MQTT.");
        return;
    }
    log_ip_info("Prima di MQTT");

    mqtt_create_if_needed();

    if (!s_started) {
        ESP_ERROR_CHECK(esp_mqtt_client_start(s_client));
        s_started = true;
        ESP_LOGI(TAG, "MQTT started");
    } else {
        ESP_LOGD(TAG, "MQTT già avviato");
    }
}

void mqtt_stop(void)
{
    if (s_client && s_started) {
        ESP_ERROR_CHECK(esp_mqtt_client_stop(s_client));
        s_started = false;
        s_connected = false;
        ESP_LOGI(TAG, "MQTT stopped");
    }
}

bool mqtt_is_connected(void)
{
    return s_connected;
}

int mqtt_publish(const char* topic, const char* data, int qos, int retain)
{
    if (!s_client) {
        ESP_LOGW(TAG, "Publish ignorato: client non inizializzato");
        return -1;
    }
    int mid = esp_mqtt_client_publish(s_client, topic, data, 0, qos, retain);
    if (mid < 0) {
        ESP_LOGE(TAG, "Publish fallito su topic %s", topic);
    }
    return mid;
}

// ─────────────────────────────────────────────────────────────────────────────
// Event handlers di rete → autostart/stop

static void on_eth_event(void* arg, esp_event_base_t base, int32_t id, void* data)
{
    switch (id) {
    case ETHERNET_EVENT_CONNECTED:
        ESP_LOGI(TAG, "ETH link UP");
        break;
    case ETHERNET_EVENT_DISCONNECTED:
        ESP_LOGW(TAG, "ETH link DOWN → stop MQTT");
        mqtt_stop();
        break;
    case ETHERNET_EVENT_START:
        ESP_LOGI(TAG, "ETH START");
        break;
    case ETHERNET_EVENT_STOP:
        ESP_LOGI(TAG, "ETH STOP");
        mqtt_stop();
        break;
    default:
        ESP_LOGD(TAG, "ETH event id=%" PRId32, id);
        break;
    }
}

static void on_ip_event(void* arg, esp_event_base_t base, int32_t id, void* data)
{
    if (id == IP_EVENT_ETH_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*)data;
        char ip[16], nm[16], gw[16];
        esp_ip4addr_ntoa(&event->ip_info.ip, ip, sizeof ip);
        esp_ip4addr_ntoa(&event->ip_info.netmask, nm, sizeof nm);
        esp_ip4addr_ntoa(&event->ip_info.gw, gw, sizeof gw);
        ESP_LOGI(TAG, "ETH GOT IP | ip=%s mask=%s gw=%s → start MQTT", ip, nm, gw);
        mqtt_start(); // parte solo se non già partito
    }
}

// Call una volta all’avvio (ad es. da app_main, dopo eth_start())
static bool s_net_handlers_registered = false;
void mqtt_register_net_handlers_once(void)
{
    if (s_net_handlers_registered) return;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(ETH_EVENT, ESP_EVENT_ANY_ID, &on_eth_event, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &on_ip_event, NULL, NULL));
    s_net_handlers_registered = true;
    ESP_LOGI(TAG, "Registrati handlers ETH/IP per autostart MQTT");
}
