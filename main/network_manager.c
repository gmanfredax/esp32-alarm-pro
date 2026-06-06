#include "network_manager.h"

#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <sys/param.h>
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"

#include "esp_check.h"
#include "esp_event.h"
#include "esp_eth.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "lwip/ip4_addr.h"
#include "lwip/inet.h"

#include "ethernet.h"
#include "app_mqtt.h"

static const char *TAG = "network";

#define NETWORK_NVS_NS "sys"
#define NETWORK_DEFAULT_HOSTNAME "nsalarmpro"
#define NETWORK_WAIT_ACTIVE_BIT BIT0
#define NETWORK_WIFI_TEST_MAX_AGE_MS (10ULL * 60ULL * 1000ULL)
#define NETWORK_FALLBACK_TIMEOUT_MS 8000
#define NETWORK_ETH_IP_TIMEOUT_MS 20000
#define NETWORK_WIFI_MAX_ATTEMPTS 4
#define NETWORK_WIFI_CONNECT_TIMEOUT_MS 8000
#define NETWORK_WIFI_RETRY_BASE_MS 5000
#define NETWORK_SETUP_AP_IP "192.168.4.1"
#define NETWORK_SETUP_AP_NETMASK "255.255.255.0"
#define NETWORK_SETUP_AP_CHANNEL 6
#define NETWORK_WIFI_RETRY_MAX_MS 60000

typedef struct {
    network_config_t cfg;
    bool started;
    bool wifi_driver_ready;
    bool wifi_sta_started;
    bool wifi_runtime_desired;
    bool eth_started;
    bool eth_link_up;
    bool eth_has_ip;
    bool wifi_connected;
    bool setup_ap_active;
    bool wifi_has_ip;
    uint32_t wifi_failures;
    int wifi_rssi;
    network_active_if_t active_if;
    char eth_ip[16];
    char setup_ap_ssid[NETWORK_WIFI_SSID_MAX + 1];
    char setup_ap_ip[16];
    char wifi_ip[16];
    char last_error[96];
    uint64_t last_change_ms;
    uint64_t last_wifi_test_ok_ms;
    char last_wifi_test_ssid[NETWORK_WIFI_SSID_MAX + 1];
    char last_wifi_test_password[NETWORK_WIFI_PASSWORD_MAX + 1];
    EventGroupHandle_t events;
    SemaphoreHandle_t lock;
} network_state_t;

static network_state_t s_net = {0};
static esp_netif_t *s_ap_netif = NULL;
static esp_netif_t *s_wifi_netif = NULL;
static TaskHandle_t s_manager_task = NULL;

static void network_eth_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data);
static void network_ip_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data);
static void network_wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data);

static uint64_t now_ms(void)
{
    return (uint64_t)(esp_timer_get_time() / 1000ULL);
}

static void set_error_locked(const char *err)
{
    strlcpy(s_net.last_error, err ? err : "", sizeof(s_net.last_error));
}

static void set_active_locked(network_active_if_t iface)
{
    if (s_net.active_if == iface) return;
    s_net.active_if = iface;
    s_net.last_change_ms = now_ms();
    if (s_net.events) {
        if (iface == NETWORK_IF_ETHERNET || iface == NETWORK_IF_WIFI) xEventGroupSetBits(s_net.events, NETWORK_WAIT_ACTIVE_BIT);
        else xEventGroupClearBits(s_net.events, NETWORK_WAIT_ACTIVE_BIT);
    }
    ESP_LOGI(TAG, "Interfaccia attiva: %s", network_active_if_to_str(iface));
}

static bool wifi_configured(const network_config_t *cfg)
{
    return cfg && cfg->wifi_ssid[0] && cfg->wifi_password_set;
}

static bool setup_ap_allowed(const network_config_t *cfg)
{
    return !cfg || cfg->fallback_ap_enabled;
}

static bool has_real_link_locked(void)
{
    return s_net.active_if == NETWORK_IF_ETHERNET || s_net.active_if == NETWORK_IF_WIFI ||
           s_net.eth_has_ip || s_net.wifi_has_ip;
}

static void build_default_ap_password(char *out, size_t len)
{
    uint8_t mac[6] = {0};
    if (!out || !len) return;
    if (esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP) == ESP_OK || esp_read_mac(mac, ESP_MAC_WIFI_STA) == ESP_OK) {
        snprintf(out, len, "NS%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else {
        strlcpy(out, "NSAlarmPro-Setup!", len);
    }
}

static void build_setup_ap_ssid(char *out, size_t len)
{
    uint8_t mac[6] = {0};
    if (!out || !len) return;
    if (esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP) == ESP_OK || esp_read_mac(mac, ESP_MAC_WIFI_STA) == ESP_OK) {
        snprintf(out, len, "NSAlarmPro-Setup-%02X%02X", mac[4], mac[5]);
    } else {
        strlcpy(out, "NSAlarmPro-Setup", len);
    }
}

bool network_mode_requires_wifi(network_mode_t mode)
{
    return mode == NETWORK_MODE_WIFI_ONLY || mode == NETWORK_MODE_ETHERNET_PREFERRED || mode == NETWORK_MODE_WIFI_PREFERRED;
}

const char *network_mode_to_str(network_mode_t mode)
{
    switch (mode) {
    case NETWORK_MODE_ETHERNET_ONLY: return "ethernet_only";
    case NETWORK_MODE_WIFI_ONLY: return "wifi_only";
    case NETWORK_MODE_ETHERNET_PREFERRED: return "ethernet_preferred";
    case NETWORK_MODE_WIFI_PREFERRED: return "wifi_preferred";
    default: return "ethernet_only";
    }
}

bool network_mode_from_str(const char *str, network_mode_t *out)
{
    if (!str || !out) return false;
    if (!strcmp(str, "ethernet_only")) { *out = NETWORK_MODE_ETHERNET_ONLY; return true; }
    if (!strcmp(str, "wifi_only")) { *out = NETWORK_MODE_WIFI_ONLY; return true; }
    if (!strcmp(str, "ethernet_preferred")) { *out = NETWORK_MODE_ETHERNET_PREFERRED; return true; }
    if (!strcmp(str, "wifi_preferred")) { *out = NETWORK_MODE_WIFI_PREFERRED; return true; }
    return false;
}

const char *network_active_if_to_str(network_active_if_t iface)
{
    switch (iface) {
    case NETWORK_IF_ETHERNET: return "ethernet";
    case NETWORK_IF_WIFI: return "wifi";
    case NETWORK_IF_SETUP_AP: return "setup_ap";
    default: return "none";
    }
}

static void mac_to_str(esp_mac_type_t type, char *out, size_t len)
{
    uint8_t mac[6] = {0};
    if (esp_read_mac(mac, type) == ESP_OK) {
        snprintf(out, len, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else if (len) {
        out[0] = '\0';
    }
}

static void ip_to_str(const esp_netif_ip_info_t *info, char *out, size_t len)
{
    if (!out || !len) return;
    strlcpy(out, "0.0.0.0", len);
    if (info && info->ip.addr) {
        ip4addr_ntoa_r((const ip4_addr_t *)&info->ip, out, len);
    }
}

esp_err_t network_config_load(network_config_t *cfg)
{
    if (!cfg) return ESP_ERR_INVALID_ARG;
    memset(cfg, 0, sizeof(*cfg));
    cfg->mode = NETWORK_MODE_ETHERNET_ONLY;
    cfg->wifi_dhcp = true;
    cfg->eth_dhcp = true;
    cfg->fallback_ap_enabled = true;
    strlcpy(cfg->hostname, NETWORK_DEFAULT_HOSTNAME, sizeof(cfg->hostname));
    build_default_ap_password(cfg->fallback_ap_password, sizeof(cfg->fallback_ap_password));
    cfg->fallback_ap_password_set = true;

    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NETWORK_NVS_NS, NVS_READONLY, &nvs);
    if (err != ESP_OK) return err == ESP_ERR_NVS_NOT_FOUND ? ESP_OK : err;

    uint32_t mode = cfg->mode;
    if (nvs_get_u32(nvs, "network_mode", &mode) == ESP_OK && mode <= NETWORK_MODE_WIFI_PREFERRED) cfg->mode = (network_mode_t)mode;
    size_t len = sizeof(cfg->hostname);
    nvs_get_str(nvs, "hostname", cfg->hostname, &len);
    len = sizeof(cfg->wifi_ssid);
    nvs_get_str(nvs, "wifi_ssid", cfg->wifi_ssid, &len);
    len = sizeof(cfg->wifi_password);
    if (nvs_get_str(nvs, "wifi_pass", cfg->wifi_password, &len) == ESP_OK && cfg->wifi_password[0]) {
        cfg->wifi_password_set = true;
    }
    uint32_t pass_set = cfg->wifi_password_set ? 1 : 0;
    if (nvs_get_u32(nvs, "wifi_pass_set", &pass_set) == ESP_OK) cfg->wifi_password_set = pass_set != 0;
    uint32_t ap_enabled = cfg->fallback_ap_enabled ? 1 : 0;
    if (nvs_get_u32(nvs, "fallback_ap", &ap_enabled) == ESP_OK) cfg->fallback_ap_enabled = ap_enabled != 0;
    len = sizeof(cfg->fallback_ap_password);
    if (nvs_get_str(nvs, "ap_pass", cfg->fallback_ap_password, &len) == ESP_OK && cfg->fallback_ap_password[0]) {
        cfg->fallback_ap_password_set = true;
    }
    uint32_t ap_pass_set = cfg->fallback_ap_password_set ? 1 : 0;
    if (nvs_get_u32(nvs, "ap_pass_set", &ap_pass_set) == ESP_OK) cfg->fallback_ap_password_set = ap_pass_set != 0;
    if (!cfg->fallback_ap_password_set || strlen(cfg->fallback_ap_password) < 8) {
        build_default_ap_password(cfg->fallback_ap_password, sizeof(cfg->fallback_ap_password));
        cfg->fallback_ap_password_set = true;
    }
    cfg->wifi_dhcp = true;
    cfg->eth_dhcp = true;
    nvs_close(nvs);
    return ESP_OK;
}

esp_err_t network_config_save(const network_config_t *cfg)
{
    if (!cfg) return ESP_ERR_INVALID_ARG;
    nvs_handle_t nvs;
    ESP_RETURN_ON_ERROR(nvs_open(NETWORK_NVS_NS, NVS_READWRITE, &nvs), TAG, "nvs_open");
    esp_err_t err = nvs_set_u32(nvs, "network_mode", (uint32_t)cfg->mode);
    if (err == ESP_OK) err = nvs_set_str(nvs, "hostname", cfg->hostname);
    if (err == ESP_OK) err = nvs_set_str(nvs, "wifi_ssid", cfg->wifi_ssid);
    if (err == ESP_OK && cfg->wifi_password_set) err = nvs_set_str(nvs, "wifi_pass", cfg->wifi_password);
    if (err == ESP_OK && !cfg->wifi_password_set) err = nvs_erase_key(nvs, "wifi_pass");
    if (err == ESP_ERR_NVS_NOT_FOUND) err = ESP_OK;
    if (err == ESP_OK) err = nvs_set_u32(nvs, "wifi_pass_set", cfg->wifi_password_set ? 1 : 0);
    if (err == ESP_OK) err = nvs_set_u32(nvs, "fallback_ap", cfg->fallback_ap_enabled ? 1 : 0);
    if (err == ESP_OK && cfg->fallback_ap_password_set && cfg->fallback_ap_password[0]) err = nvs_set_str(nvs, "ap_pass", cfg->fallback_ap_password);
    if (err == ESP_OK && (!cfg->fallback_ap_password_set || !cfg->fallback_ap_password[0])) err = nvs_erase_key(nvs, "ap_pass");
    if (err == ESP_ERR_NVS_NOT_FOUND) err = ESP_OK;
    if (err == ESP_OK) err = nvs_set_u32(nvs, "ap_pass_set", cfg->fallback_ap_password_set ? 1 : 0);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    return err;
}

static esp_err_t ensure_wifi_driver(void)
{
    if (s_net.wifi_driver_ready) return ESP_OK;
    ESP_RETURN_ON_ERROR(esp_netif_init(), TAG, "netif_init");
    esp_err_t e = esp_event_loop_create_default();
    if (e != ESP_OK && e != ESP_ERR_INVALID_STATE) return e;
    if (!s_wifi_netif) {
        s_wifi_netif = esp_netif_create_default_wifi_sta();
        if (!s_wifi_netif) return ESP_ERR_NO_MEM;
    }
    if (!s_ap_netif) {
        s_ap_netif = esp_netif_create_default_wifi_ap();
        if (!s_ap_netif) return ESP_ERR_NO_MEM;
    }
    wifi_init_config_t init_cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_RETURN_ON_ERROR(esp_wifi_init(&init_cfg), TAG, "wifi_init");
    ESP_RETURN_ON_ERROR(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, network_wifi_event_handler, NULL), TAG, "wifi_handler");
    ESP_RETURN_ON_ERROR(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, network_ip_event_handler, NULL), TAG, "ip_handler");
    ESP_RETURN_ON_ERROR(esp_wifi_set_storage(WIFI_STORAGE_RAM), TAG, "wifi_storage");
    s_net.wifi_driver_ready = true;
    return ESP_OK;
}


static esp_err_t configure_ap_ip(void)
{
    if (!s_ap_netif) return ESP_ERR_INVALID_STATE;
    esp_netif_ip_info_t ip_info = {0};
    ip_info.ip.addr = ipaddr_addr(NETWORK_SETUP_AP_IP);
    ip_info.gw.addr = ipaddr_addr(NETWORK_SETUP_AP_IP);
    ip_info.netmask.addr = ipaddr_addr(NETWORK_SETUP_AP_NETMASK);
    esp_netif_dhcps_stop(s_ap_netif);
    ESP_RETURN_ON_ERROR(esp_netif_set_ip_info(s_ap_netif, &ip_info), TAG, "ap_ip");
    return esp_netif_dhcps_start(s_ap_netif);
}

static esp_err_t wifi_apply_mode_locked(void)
{
    wifi_mode_t mode = WIFI_MODE_NULL;
    if (s_net.wifi_sta_started || s_net.wifi_runtime_desired) mode = WIFI_MODE_STA;
    if (s_net.setup_ap_active) mode = (mode == WIFI_MODE_STA) ? WIFI_MODE_APSTA : WIFI_MODE_AP;
    return esp_wifi_set_mode(mode);
}

static esp_err_t setup_ap_start_locked(const char *reason)
{
    if (!setup_ap_allowed(&s_net.cfg)) return ESP_ERR_INVALID_STATE;
    ESP_RETURN_ON_ERROR(ensure_wifi_driver(), TAG, "ensure_wifi_ap");
    build_setup_ap_ssid(s_net.setup_ap_ssid, sizeof(s_net.setup_ap_ssid));
    strlcpy(s_net.setup_ap_ip, NETWORK_SETUP_AP_IP, sizeof(s_net.setup_ap_ip));
    ESP_RETURN_ON_ERROR(configure_ap_ip(), TAG, "ap_ip_config");

    char ap_pass[NETWORK_WIFI_PASSWORD_MAX + 1] = {0};
    if (s_net.cfg.fallback_ap_password_set && strlen(s_net.cfg.fallback_ap_password) >= 8) {
        strlcpy(ap_pass, s_net.cfg.fallback_ap_password, sizeof(ap_pass));
    } else {
        build_default_ap_password(ap_pass, sizeof(ap_pass));
    }

    wifi_config_t ap_cfg = {0};
    strlcpy((char *)ap_cfg.ap.ssid, s_net.setup_ap_ssid, sizeof(ap_cfg.ap.ssid));
    ap_cfg.ap.ssid_len = strlen(s_net.setup_ap_ssid);
    ap_cfg.ap.channel = NETWORK_SETUP_AP_CHANNEL;
    ap_cfg.ap.max_connection = 4;
    ap_cfg.ap.authmode = WIFI_AUTH_WPA2_PSK;
    strlcpy((char *)ap_cfg.ap.password, ap_pass, sizeof(ap_cfg.ap.password));
    if (strlen(ap_pass) < 8) ap_cfg.ap.authmode = WIFI_AUTH_OPEN;

    bool already = s_net.setup_ap_active;
    s_net.setup_ap_active = true;
    ESP_RETURN_ON_ERROR(wifi_apply_mode_locked(), TAG, "ap_mode");
    ESP_RETURN_ON_ERROR(esp_wifi_set_config(WIFI_IF_AP, &ap_cfg), TAG, "ap_config");
    esp_err_t err = esp_wifi_start();
    if (err != ESP_OK && err != ESP_ERR_WIFI_CONN) return err;
    if (!has_real_link_locked()) set_active_locked(NETWORK_IF_SETUP_AP);
    if (!already) {
        ESP_LOGW(TAG, "Fallback AP attivo: SSID=%s IP=%s motivo=%s", s_net.setup_ap_ssid, s_net.setup_ap_ip, reason ? reason : "fallback");
        ESP_LOGW(TAG, "MQTT sospeso: AP setup senza connettività broker");
    }
    return ESP_OK;
}

static void setup_ap_stop_locked(void)
{
    if (!s_net.setup_ap_active || !s_net.wifi_driver_ready) return;
    s_net.setup_ap_active = false;
    s_net.setup_ap_ssid[0] = '\0';
    s_net.setup_ap_ip[0] = '\0';
    if (s_net.active_if == NETWORK_IF_SETUP_AP) set_active_locked(NETWORK_IF_NONE);
    wifi_apply_mode_locked();
    if (!s_net.wifi_sta_started) esp_wifi_stop();
    ESP_LOGI(TAG, "AP fallback disattivato");
}

static esp_err_t wifi_apply_hostname(void)
{
    if (!s_wifi_netif) return ESP_ERR_INVALID_STATE;
    if (s_net.cfg.hostname[0]) return esp_netif_set_hostname(s_wifi_netif, s_net.cfg.hostname);
    return ESP_OK;
}

static esp_err_t wifi_start_sta_locked(void)
{
    if (!wifi_configured(&s_net.cfg)) {
        set_error_locked("wifi_not_configured");
        return ESP_ERR_INVALID_STATE;
    }
    ESP_RETURN_ON_ERROR(ensure_wifi_driver(), TAG, "ensure_wifi");
    wifi_apply_hostname();
    wifi_config_t wifi_cfg = {0};
    strlcpy((char *)wifi_cfg.sta.ssid, s_net.cfg.wifi_ssid, sizeof(wifi_cfg.sta.ssid));
    memcpy(wifi_cfg.sta.password, s_net.cfg.wifi_password, MIN(strlen(s_net.cfg.wifi_password), sizeof(wifi_cfg.sta.password)));
    wifi_cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    wifi_cfg.sta.sae_pwe_h2e = WPA3_SAE_PWE_BOTH;
    s_net.wifi_runtime_desired = true;
    ESP_RETURN_ON_ERROR(wifi_apply_mode_locked(), TAG, "wifi_mode_sta");
    ESP_RETURN_ON_ERROR(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg), TAG, "wifi_config");
    esp_err_t err = esp_wifi_start();
    if (err == ESP_ERR_WIFI_NOT_INIT) return err;
    if (err != ESP_OK && err != ESP_ERR_WIFI_CONN) return err;
    s_net.wifi_sta_started = true;
    err = esp_wifi_connect();
    if (err != ESP_OK && err != ESP_ERR_WIFI_CONN) return err;
    ESP_LOGI(TAG, "Wi-Fi STA avviato per SSID '%s'", s_net.cfg.wifi_ssid);
    return ESP_OK;
}

static void wifi_stop_sta_locked(void)
{
    if (!s_net.wifi_driver_ready) return;
    esp_wifi_disconnect();
    s_net.wifi_sta_started = false;
    s_net.wifi_runtime_desired = false;
    wifi_apply_mode_locked();
    if (!s_net.setup_ap_active) esp_wifi_stop();
    s_net.wifi_connected = false;
    s_net.wifi_has_ip = false;
    s_net.wifi_ip[0] = '\0';
    if (s_net.active_if == NETWORK_IF_WIFI) set_active_locked(NETWORK_IF_NONE);
}

static esp_err_t start_eth_locked(void)
{
    if (s_net.eth_started) return ESP_OK;
    esp_err_t err = eth_start();
    if (err == ESP_OK) {
        s_net.eth_started = true;
        esp_netif_t *netif = eth_get_netif();
        if (netif && s_net.cfg.hostname[0]) esp_netif_set_hostname(netif, s_net.cfg.hostname);
    } else {
        set_error_locked("ethernet_start_failed");
    }
    return err;
}

static void stop_eth_locked(void)
{
    if (!s_net.eth_started) return;
    eth_stop();
    s_net.eth_started = false;
    s_net.eth_link_up = false;
    s_net.eth_has_ip = false;
    s_net.eth_ip[0] = '\0';
    if (s_net.active_if == NETWORK_IF_ETHERNET) set_active_locked(NETWORK_IF_NONE);
}

static void network_eth_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg; (void)base; (void)data;
    if (!s_net.lock) return;
    bool stop_mqtt = false;
    xSemaphoreTake(s_net.lock, portMAX_DELAY);
    if (id == ETHERNET_EVENT_CONNECTED) {
        s_net.eth_link_up = true;
        ESP_LOGI(TAG, "Ethernet link up");
        set_error_locked("");
    } else if (id == ETHERNET_EVENT_DISCONNECTED || id == ETHERNET_EVENT_STOP) {
        bool was_active = s_net.active_if == NETWORK_IF_ETHERNET || s_net.eth_has_ip;
        s_net.eth_link_up = false;
        s_net.eth_has_ip = false;
        s_net.eth_ip[0] = '\0';
        ESP_LOGW(TAG, "Ethernet link down");
        if (s_net.cfg.mode == NETWORK_MODE_ETHERNET_PREFERRED && wifi_configured(&s_net.cfg)) {
            s_net.wifi_runtime_desired = true;
        }
        if (s_net.active_if == NETWORK_IF_ETHERNET) set_active_locked(NETWORK_IF_NONE);
        stop_mqtt = was_active && !has_real_link_locked();
    }
    xSemaphoreGive(s_net.lock);
    if (stop_mqtt) {
        ESP_LOGW(TAG, "MQTT sospeso: connettività IP persa");
        mqtt_stop();
    }
}

static void network_ip_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg; (void)base;
    if (!s_net.lock || !data) return;
    bool start_mqtt = false;
    xSemaphoreTake(s_net.lock, portMAX_DELAY);
    if (id == IP_EVENT_ETH_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)data;
        s_net.eth_has_ip = true;
        ip_to_str(&event->ip_info, s_net.eth_ip, sizeof(s_net.eth_ip));
        ESP_LOGI(TAG, "Ethernet IP ottenuto: %s", s_net.eth_ip);
        set_error_locked("");
        if (s_net.setup_ap_active) setup_ap_stop_locked();
        if (s_net.cfg.mode == NETWORK_MODE_ETHERNET_ONLY || s_net.cfg.mode == NETWORK_MODE_ETHERNET_PREFERRED) {
            set_active_locked(NETWORK_IF_ETHERNET);
            if (s_net.cfg.mode == NETWORK_MODE_ETHERNET_PREFERRED && s_net.wifi_sta_started) wifi_stop_sta_locked();
        }
        start_mqtt = has_real_link_locked();
    } else if (id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)data;
        s_net.wifi_has_ip = true;
        ip_to_str(&event->ip_info, s_net.wifi_ip, sizeof(s_net.wifi_ip));
        wifi_ap_record_t ap = {0};
        if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) s_net.wifi_rssi = ap.rssi;
        ESP_LOGI(TAG, "Wi-Fi connesso, IP ottenuto: %s", s_net.wifi_ip);
        set_error_locked("");
        if (s_net.setup_ap_active) setup_ap_stop_locked();
        s_net.wifi_failures = 0;
        if (s_net.cfg.mode == NETWORK_MODE_WIFI_ONLY ||
            s_net.cfg.mode == NETWORK_MODE_WIFI_PREFERRED ||
            (s_net.cfg.mode == NETWORK_MODE_ETHERNET_PREFERRED && !s_net.eth_has_ip)) {
            set_active_locked(NETWORK_IF_WIFI);
        }
        start_mqtt = has_real_link_locked();
    }
    xSemaphoreGive(s_net.lock);
    if (start_mqtt) {
        esp_err_t err = mqtt_reload_config();
        if (err != ESP_OK) ESP_LOGW(TAG, "MQTT non avviato dopo IP: %s", esp_err_to_name(err));
    }
}

static void network_wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg; (void)base; (void)data;
    if (!s_net.lock) return;
    bool stop_mqtt = false;
    xSemaphoreTake(s_net.lock, portMAX_DELAY);
    if (id == WIFI_EVENT_STA_START) {
        s_net.wifi_sta_started = true;
    } else if (id == WIFI_EVENT_STA_CONNECTED) {
        s_net.wifi_connected = true;
        set_error_locked("");
    } else if (id == WIFI_EVENT_STA_DISCONNECTED) {
        bool was_active = s_net.active_if == NETWORK_IF_WIFI || s_net.wifi_has_ip;
        s_net.wifi_failures++;
        ESP_LOGW(TAG, "Wi-Fi disconnesso (tentativo fallito %lu/%u)", (unsigned long)s_net.wifi_failures, NETWORK_WIFI_MAX_ATTEMPTS);
        s_net.wifi_connected = false;
        s_net.wifi_has_ip = false;
        s_net.wifi_ip[0] = '\0';
        set_error_locked("wifi_disconnected");
        if (s_net.active_if == NETWORK_IF_WIFI) set_active_locked(NETWORK_IF_NONE);
        stop_mqtt = was_active && !has_real_link_locked();
    } else if (id == WIFI_EVENT_STA_STOP) {
        bool was_active = s_net.active_if == NETWORK_IF_WIFI || s_net.wifi_has_ip;
        s_net.wifi_sta_started = false;
        s_net.wifi_connected = false;
        s_net.wifi_has_ip = false;
        stop_mqtt = was_active && !has_real_link_locked();
    }
    xSemaphoreGive(s_net.lock);
    if (stop_mqtt) {
        ESP_LOGW(TAG, "MQTT sospeso: connettività IP persa");
        mqtt_stop();
    }
}

static void manager_loop(void *arg)
{
    (void)arg;
    TickType_t last_wifi_attempt = 0;
    TickType_t wifi_attempt_started = 0;
    uint32_t wifi_backoff_ms = NETWORK_WIFI_RETRY_BASE_MS;
    TickType_t eth_started_at = xTaskGetTickCount();

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        bool need_mqtt_reload = false;
        xSemaphoreTake(s_net.lock, portMAX_DELAY);
        network_mode_t mode = s_net.cfg.mode;
        bool eth_usable = (mode == NETWORK_MODE_ETHERNET_ONLY || mode == NETWORK_MODE_ETHERNET_PREFERRED || mode == NETWORK_MODE_WIFI_PREFERRED) &&
                          s_net.eth_started && s_net.eth_has_ip;
        bool wifi_usable = (mode == NETWORK_MODE_WIFI_ONLY || mode == NETWORK_MODE_ETHERNET_PREFERRED || mode == NETWORK_MODE_WIFI_PREFERRED) &&
                           s_net.wifi_has_ip;

        if (mode == NETWORK_MODE_ETHERNET_PREFERRED && eth_usable) {
            set_active_locked(NETWORK_IF_ETHERNET);
            if (s_net.wifi_sta_started) wifi_stop_sta_locked();
        } else if ((mode == NETWORK_MODE_WIFI_ONLY || mode == NETWORK_MODE_WIFI_PREFERRED) && wifi_usable) {
            set_active_locked(NETWORK_IF_WIFI);
        } else if (mode == NETWORK_MODE_ETHERNET_ONLY && eth_usable) {
            set_active_locked(NETWORK_IF_ETHERNET);
        }

        bool eth_timed_out = (mode == NETWORK_MODE_ETHERNET_PREFERRED || mode == NETWORK_MODE_WIFI_PREFERRED || mode == NETWORK_MODE_ETHERNET_ONLY) &&
                             s_net.eth_started && !s_net.eth_has_ip &&
                             (xTaskGetTickCount() - eth_started_at) >= pdMS_TO_TICKS(NETWORK_ETH_IP_TIMEOUT_MS);
        bool need_wifi = false;
        if (mode == NETWORK_MODE_WIFI_ONLY || mode == NETWORK_MODE_WIFI_PREFERRED) {
            need_wifi = wifi_configured(&s_net.cfg);
        } else if (mode == NETWORK_MODE_ETHERNET_PREFERRED) {
            need_wifi = !s_net.eth_has_ip && eth_timed_out && wifi_configured(&s_net.cfg);
        }

        if (need_wifi && !s_net.wifi_has_ip) {
            TickType_t now = xTaskGetTickCount();
            bool timed_out = s_net.wifi_sta_started && wifi_attempt_started &&
                             (now - wifi_attempt_started) >= pdMS_TO_TICKS(NETWORK_WIFI_CONNECT_TIMEOUT_MS);
            if (timed_out) {
                s_net.wifi_failures++;
                set_error_locked("wifi_connect_timeout");
                wifi_stop_sta_locked();
                wifi_backoff_ms = MIN(wifi_backoff_ms * 2, NETWORK_WIFI_RETRY_MAX_MS);
            }
            if (s_net.wifi_failures < NETWORK_WIFI_MAX_ATTEMPTS &&
                (!s_net.wifi_sta_started || (now - last_wifi_attempt) >= pdMS_TO_TICKS(wifi_backoff_ms))) {
                last_wifi_attempt = now;
                wifi_attempt_started = now;
                esp_err_t err = wifi_start_sta_locked();
                if (err != ESP_OK) {
                    s_net.wifi_failures++;
                    set_error_locked("wifi_start_failed");
                    wifi_backoff_ms = MIN(wifi_backoff_ms * 2, NETWORK_WIFI_RETRY_MAX_MS);
                }
            }
        }
        if (s_net.wifi_has_ip) {
            s_net.wifi_failures = 0;
            wifi_backoff_ms = NETWORK_WIFI_RETRY_BASE_MS;
        }

        bool needs_setup_ap = false;
        const char *reason = NULL;
        if (!has_real_link_locked()) {
            if (mode == NETWORK_MODE_WIFI_ONLY && !wifi_configured(&s_net.cfg)) { needs_setup_ap = true; reason = "wifi_not_configured"; }
            else if ((mode == NETWORK_MODE_WIFI_ONLY || mode == NETWORK_MODE_ETHERNET_PREFERRED || mode == NETWORK_MODE_WIFI_PREFERRED) &&
                     wifi_configured(&s_net.cfg) && s_net.wifi_failures >= NETWORK_WIFI_MAX_ATTEMPTS) { needs_setup_ap = true; reason = "wifi_failed"; }
            else if ((mode == NETWORK_MODE_ETHERNET_PREFERRED || mode == NETWORK_MODE_WIFI_PREFERRED) && eth_timed_out && !wifi_configured(&s_net.cfg)) { needs_setup_ap = true; reason = "ethernet_no_ip_wifi_missing"; }
            else if (mode == NETWORK_MODE_ETHERNET_ONLY && eth_timed_out) { needs_setup_ap = true; reason = "ethernet_no_ip"; }
        }

        if (needs_setup_ap) {
            setup_ap_start_locked(reason);
        } else if (has_real_link_locked() && s_net.setup_ap_active) {
            setup_ap_stop_locked();
        }
        static network_active_if_t last_mqtt_iface = NETWORK_IF_NONE;
        if (has_real_link_locked() && s_net.active_if != last_mqtt_iface) {
            last_mqtt_iface = s_net.active_if;
            need_mqtt_reload = true;
        }
        xSemaphoreGive(s_net.lock);
        if (need_mqtt_reload) mqtt_reload_config();
    }
}

esp_err_t network_manager_start(void)
{
    if (!s_net.lock) s_net.lock = xSemaphoreCreateMutex();
    if (!s_net.events) s_net.events = xEventGroupCreate();
    if (!s_net.lock || !s_net.events) return ESP_ERR_NO_MEM;

    network_config_t cfg;
    ESP_RETURN_ON_ERROR(network_config_load(&cfg), TAG, "config_load");

    xSemaphoreTake(s_net.lock, portMAX_DELAY);
    s_net.cfg = cfg;
    s_net.started = true;
    s_net.active_if = NETWORK_IF_NONE;
    s_net.last_change_ms = now_ms();
    xSemaphoreGive(s_net.lock);

    esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, network_eth_event_handler, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, network_ip_event_handler, NULL);

    xSemaphoreTake(s_net.lock, portMAX_DELAY);
    if (cfg.mode == NETWORK_MODE_ETHERNET_ONLY || cfg.mode == NETWORK_MODE_ETHERNET_PREFERRED || cfg.mode == NETWORK_MODE_WIFI_PREFERRED) {
        if (cfg.mode != NETWORK_MODE_WIFI_ONLY) start_eth_locked();
    }
    if (cfg.mode == NETWORK_MODE_WIFI_ONLY || cfg.mode == NETWORK_MODE_WIFI_PREFERRED) {
        wifi_start_sta_locked();
    }
    xSemaphoreGive(s_net.lock);

    if (!s_manager_task) xTaskCreate(manager_loop, "net_mgr", 4096, NULL, tskIDLE_PRIORITY + 3, &s_manager_task);
    ESP_LOGI(TAG, "Modalità rete: %s", network_mode_to_str(cfg.mode));
    return ESP_OK;
}

esp_err_t network_manager_restart(void)
{
    network_config_t cfg;
    ESP_RETURN_ON_ERROR(network_config_load(&cfg), TAG, "config_load");
    xSemaphoreTake(s_net.lock, portMAX_DELAY);
    setup_ap_stop_locked();
    wifi_stop_sta_locked();
    stop_eth_locked();
    s_net.cfg = cfg;
    s_net.eth_has_ip = false;
    s_net.wifi_has_ip = false;
    s_net.wifi_failures = 0;
    set_active_locked(NETWORK_IF_NONE);
    set_error_locked("");
    if (cfg.mode == NETWORK_MODE_ETHERNET_ONLY || cfg.mode == NETWORK_MODE_ETHERNET_PREFERRED || cfg.mode == NETWORK_MODE_WIFI_PREFERRED) {
        if (cfg.mode != NETWORK_MODE_WIFI_ONLY) start_eth_locked();
    }
    if (cfg.mode == NETWORK_MODE_WIFI_ONLY || cfg.mode == NETWORK_MODE_WIFI_PREFERRED) wifi_start_sta_locked();
    xSemaphoreGive(s_net.lock);
    mqtt_reload_config();
    return ESP_OK;
}

esp_err_t network_wait_for_active_ip(TickType_t timeout)
{
    if (!s_net.events) return ESP_ERR_INVALID_STATE;
    EventBits_t bits = xEventGroupWaitBits(s_net.events, NETWORK_WAIT_ACTIVE_BIT, pdFALSE, pdTRUE, timeout);
    return (bits & NETWORK_WAIT_ACTIVE_BIT) ? ESP_OK : ESP_ERR_TIMEOUT;
}

esp_err_t network_get_status(network_status_t *out)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    if (s_net.lock) xSemaphoreTake(s_net.lock, portMAX_DELAY);
    out->mode = s_net.cfg.mode;
    out->active_if = s_net.active_if;
    strlcpy(out->hostname, s_net.cfg.hostname, sizeof(out->hostname));
    out->ethernet_started = s_net.eth_started;
    out->ethernet_link_up = s_net.eth_link_up || eth_link_is_up();
    out->ethernet_has_ip = s_net.eth_has_ip;
    strlcpy(out->ethernet_ip, s_net.eth_ip[0] ? s_net.eth_ip : "0.0.0.0", sizeof(out->ethernet_ip));
    out->wifi_started = s_net.wifi_sta_started;
    out->wifi_connected = s_net.wifi_connected;
    out->wifi_has_ip = s_net.wifi_has_ip;
    strlcpy(out->wifi_ssid, s_net.cfg.wifi_ssid, sizeof(out->wifi_ssid));
    out->wifi_password_set = s_net.cfg.wifi_password_set;
    out->wifi_rssi = s_net.wifi_rssi;
    strlcpy(out->wifi_ip, s_net.wifi_ip[0] ? s_net.wifi_ip : "0.0.0.0", sizeof(out->wifi_ip));
    out->setup_ap_active = s_net.setup_ap_active;
    strlcpy(out->setup_ap_ssid, s_net.setup_ap_ssid, sizeof(out->setup_ap_ssid));
    strlcpy(out->setup_ap_ip, s_net.setup_ap_ip[0] ? s_net.setup_ap_ip : NETWORK_SETUP_AP_IP, sizeof(out->setup_ap_ip));
    out->fallback_ap_enabled = s_net.cfg.fallback_ap_enabled;
    out->fallback_ap_password_set = s_net.cfg.fallback_ap_password_set;
    strlcpy(out->last_error, s_net.last_error, sizeof(out->last_error));
    out->last_interface_change_ms = s_net.last_change_ms;
    if (s_net.lock) xSemaphoreGive(s_net.lock);
    mac_to_str(ESP_MAC_ETH, out->ethernet_mac, sizeof(out->ethernet_mac));
    mac_to_str(ESP_MAC_WIFI_STA, out->wifi_mac, sizeof(out->wifi_mac));
    return ESP_OK;
}

esp_err_t network_status_append_json(cJSON *root)
{
    if (!root) return ESP_ERR_INVALID_ARG;
    network_status_t st;
    ESP_RETURN_ON_ERROR(network_get_status(&st), TAG, "status");
    cJSON_AddStringToObject(root, "network_mode", network_mode_to_str(st.mode));
    cJSON_AddStringToObject(root, "active_interface", network_active_if_to_str(st.active_if));
    cJSON_AddStringToObject(root, "hostname", st.hostname);
    cJSON_AddStringToObject(root, "last_error", st.last_error);
    cJSON_AddNumberToObject(root, "last_interface_change_ms", (double)st.last_interface_change_ms);

    cJSON *eth = cJSON_AddObjectToObject(root, "ethernet");
    cJSON_AddBoolToObject(eth, "started", st.ethernet_started);
    cJSON_AddBoolToObject(eth, "link_up", st.ethernet_link_up);
    cJSON_AddBoolToObject(eth, "has_ip", st.ethernet_has_ip);
    cJSON_AddStringToObject(eth, "ip", st.ethernet_ip);
    cJSON_AddStringToObject(eth, "mac", st.ethernet_mac);

    cJSON *wifi = cJSON_AddObjectToObject(root, "wifi");
    cJSON_AddStringToObject(wifi, "ssid", st.wifi_ssid);
    cJSON_AddBoolToObject(wifi, "password_set", st.wifi_password_set);
    cJSON_AddBoolToObject(wifi, "started", st.wifi_started);
    cJSON_AddBoolToObject(wifi, "connected", st.wifi_connected);
    cJSON_AddBoolToObject(wifi, "has_ip", st.wifi_has_ip);
    cJSON_AddNumberToObject(wifi, "rssi", st.wifi_rssi);
    cJSON_AddStringToObject(wifi, "ip", st.wifi_ip);
    cJSON_AddStringToObject(wifi, "mac", st.wifi_mac);

    cJSON *ap = cJSON_AddObjectToObject(root, "setup_ap");
    cJSON_AddBoolToObject(ap, "enabled", st.fallback_ap_enabled);
    cJSON_AddBoolToObject(ap, "active", st.setup_ap_active);
    cJSON_AddStringToObject(ap, "ssid", st.setup_ap_ssid);
    cJSON_AddStringToObject(ap, "ip", st.setup_ap_ip);
    cJSON_AddBoolToObject(ap, "password_set", st.fallback_ap_password_set);

    cJSON *mqtt = cJSON_AddObjectToObject(root, "mqtt");
    bool real_connectivity = st.ethernet_has_ip || st.wifi_has_ip ||
                             st.active_if == NETWORK_IF_ETHERNET || st.active_if == NETWORK_IF_WIFI;
    cJSON_AddBoolToObject(mqtt, "connected", mqtt_is_connected());
    if (mqtt_is_connected()) {
        cJSON_AddStringToObject(mqtt, "status", "connected");
        cJSON_AddStringToObject(mqtt, "reason", "broker_connected");
    } else if (!real_connectivity && st.setup_ap_active) {
        cJSON_AddStringToObject(mqtt, "status", "suspended");
        cJSON_AddStringToObject(mqtt, "reason", "ap_setup_no_broker_connectivity");
    } else if (!real_connectivity) {
        cJSON_AddStringToObject(mqtt, "status", "suspended");
        cJSON_AddStringToObject(mqtt, "reason", "network_not_ready");
    } else {
        cJSON_AddStringToObject(mqtt, "status", "disconnected");
        cJSON_AddStringToObject(mqtt, "reason", "broker_disconnected_or_retrying");
    }
    return ESP_OK;
}


bool network_has_real_connectivity(void)
{
    bool ok = false;
    if (s_net.lock) xSemaphoreTake(s_net.lock, portMAX_DELAY);
    ok = has_real_link_locked();
    if (s_net.lock) xSemaphoreGive(s_net.lock);
    return ok;
}

esp_err_t network_setup_exit(void)
{
    if (!s_net.lock) return ESP_ERR_INVALID_STATE;
    xSemaphoreTake(s_net.lock, portMAX_DELAY);
    if (!has_real_link_locked()) {
        xSemaphoreGive(s_net.lock);
        return ESP_ERR_INVALID_STATE;
    }
    setup_ap_stop_locked();
    xSemaphoreGive(s_net.lock);
    return ESP_OK;
}

esp_err_t network_wifi_scan_append_json(cJSON *array)
{
    if (!array) return ESP_ERR_INVALID_ARG;
    if (!s_net.lock) return ESP_ERR_INVALID_STATE;
    xSemaphoreTake(s_net.lock, portMAX_DELAY);
    esp_err_t err = ensure_wifi_driver();
    if (err == ESP_OK) {
        s_net.wifi_runtime_desired = true;
        err = wifi_apply_mode_locked();
    }
    if (err == ESP_OK) {
        err = esp_wifi_start();
        if (err == ESP_ERR_WIFI_CONN) err = ESP_OK;
    }
    xSemaphoreGive(s_net.lock);
    if (err != ESP_OK) return err;

    wifi_scan_config_t scan_cfg = {0};
    err = esp_wifi_scan_start(&scan_cfg, true);
    if (err != ESP_OK) return err;
    uint16_t count = 0;
    ESP_RETURN_ON_ERROR(esp_wifi_scan_get_ap_num(&count), TAG, "scan_num");
    if (count > 20) count = 20;
    wifi_ap_record_t aps[20] = {0};
    ESP_RETURN_ON_ERROR(esp_wifi_scan_get_ap_records(&count, aps), TAG, "scan_records");
    for (uint16_t i = 0; i < count; ++i) {
        cJSON *item = cJSON_CreateObject();
        if (!item) continue;
        cJSON_AddStringToObject(item, "ssid", (const char *)aps[i].ssid);
        cJSON_AddNumberToObject(item, "rssi", aps[i].rssi);
        cJSON_AddStringToObject(item, "security", aps[i].authmode == WIFI_AUTH_OPEN ? "open" : "secured");
        cJSON_AddItemToArray(array, item);
    }
    return ESP_OK;
}

esp_err_t network_wifi_test(const char *ssid, const char *password, bool use_saved_password, uint32_t timeout_ms)
{
    if (!ssid || !ssid[0]) return ESP_ERR_INVALID_ARG;
    if (strlen(ssid) > NETWORK_WIFI_SSID_MAX) return ESP_ERR_INVALID_SIZE;
    network_config_t old_cfg;
    network_config_load(&old_cfg);
    const char *pass = password;
    if (use_saved_password || !pass || !pass[0]) pass = old_cfg.wifi_password;
    if (!pass || !pass[0] || strlen(pass) > NETWORK_WIFI_PASSWORD_MAX) return ESP_ERR_INVALID_ARG;

    xSemaphoreTake(s_net.lock, portMAX_DELAY);
    network_config_t runtime_bak = s_net.cfg;
    bool wifi_was_started = s_net.wifi_sta_started;
    s_net.cfg = old_cfg;
    strlcpy(s_net.cfg.wifi_ssid, ssid, sizeof(s_net.cfg.wifi_ssid));
    strlcpy(s_net.cfg.wifi_password, pass, sizeof(s_net.cfg.wifi_password));
    s_net.cfg.wifi_password_set = true;
    s_net.wifi_has_ip = false;
    esp_err_t err = wifi_start_sta_locked();
    xSemaphoreGive(s_net.lock);
    if (err != ESP_OK) goto out_restore;

    uint64_t deadline = now_ms() + timeout_ms;
    while (now_ms() < deadline) {
        network_status_t st;
        network_get_status(&st);
        if (st.wifi_has_ip) {
            xSemaphoreTake(s_net.lock, portMAX_DELAY);
            s_net.last_wifi_test_ok_ms = now_ms();
            strlcpy(s_net.last_wifi_test_ssid, ssid, sizeof(s_net.last_wifi_test_ssid));
            strlcpy(s_net.last_wifi_test_password, pass, sizeof(s_net.last_wifi_test_password));
            xSemaphoreGive(s_net.lock);
            err = ESP_OK;
            goto out_restore;
        }
        vTaskDelay(pdMS_TO_TICKS(250));
    }
    err = ESP_ERR_TIMEOUT;

out_restore:
    xSemaphoreTake(s_net.lock, portMAX_DELAY);
    s_net.cfg = runtime_bak;
    if (!wifi_was_started && runtime_bak.mode != NETWORK_MODE_WIFI_ONLY && runtime_bak.mode != NETWORK_MODE_WIFI_PREFERRED) {
        wifi_stop_sta_locked();
    } else if (wifi_was_started) {
        wifi_start_sta_locked();
    }
    if (err != ESP_OK) set_error_locked("wifi_test_failed");
    xSemaphoreGive(s_net.lock);
    return err;
}

bool network_wifi_test_recent_ok(const char *ssid, const char *password)
{
    if (!ssid || !ssid[0] || !password || !password[0] || !s_net.lock) return false;
    bool ok = false;
    xSemaphoreTake(s_net.lock, portMAX_DELAY);
    ok = s_net.last_wifi_test_ok_ms && !strcmp(ssid, s_net.last_wifi_test_ssid) &&
         !strcmp(password, s_net.last_wifi_test_password) &&
         (now_ms() - s_net.last_wifi_test_ok_ms) <= NETWORK_WIFI_TEST_MAX_AGE_MS;
    xSemaphoreGive(s_net.lock);
    return ok;
}