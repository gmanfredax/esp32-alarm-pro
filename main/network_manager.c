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
#include "system_time.h"

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
    bool setup_ap_ip_configured;
    bool setup_ap_dhcp_started;
    uint32_t setup_ap_start_count;
    uint32_t setup_ap_client_count;
    uint64_t setup_ap_last_start_ms;
    uint64_t setup_ap_grace_until_ms;
    char setup_ap_last_reason[48];
    char setup_ap_last_client_event[96];
    bool wifi_test_active;
    bool network_transition_in_progress;
    uint32_t last_grace_log_remaining_s;
    wifi_mode_t wifi_current_mode;
    bool wifi_started;
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

static bool setup_ap_grace_active_locked(void)
{
    return s_net.setup_ap_grace_until_ms && now_ms() < s_net.setup_ap_grace_until_ms;
}

static uint32_t setup_ap_grace_remaining_locked(void)
{
    if (!setup_ap_grace_active_locked()) return 0;
    uint64_t remaining_ms = s_net.setup_ap_grace_until_ms - now_ms();
    return (uint32_t)((remaining_ms + 999ULL) / 1000ULL);
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
    ESP_LOGI(TAG, "active_interface=%s", network_active_if_to_str(iface));
}

static bool wifi_configured(const network_config_t *cfg)
{
    return cfg && cfg->wifi_ssid[0] && cfg->wifi_password_set;
}

static bool setup_ap_allowed(const network_config_t *cfg)
{
    return !cfg || cfg->fallback_ap_enabled;
}

static bool ethernet_allowed_locked(void)
{
    return s_net.cfg.mode == NETWORK_MODE_ETHERNET_ONLY ||
           s_net.cfg.mode == NETWORK_MODE_ETHERNET_PREFERRED ||
           s_net.cfg.mode == NETWORK_MODE_WIFI_PREFERRED;
}

static bool wifi_allowed_locked(void)
{
    return s_net.cfg.mode == NETWORK_MODE_WIFI_ONLY ||
           s_net.cfg.mode == NETWORK_MODE_ETHERNET_PREFERRED ||
           s_net.cfg.mode == NETWORK_MODE_WIFI_PREFERRED;
}

static network_active_if_t compute_active_if_locked(void)
{
    bool eth_usable = ethernet_allowed_locked() && s_net.eth_has_ip;
    bool wifi_usable = wifi_allowed_locked() && s_net.wifi_has_ip;
    switch (s_net.cfg.mode) {
    case NETWORK_MODE_ETHERNET_ONLY:
        if (eth_usable) return NETWORK_IF_ETHERNET;
        break;
    case NETWORK_MODE_WIFI_ONLY:
        if (wifi_usable) return NETWORK_IF_WIFI;
        break;
    case NETWORK_MODE_ETHERNET_PREFERRED:
        if (eth_usable) return NETWORK_IF_ETHERNET;
        if (wifi_usable) return NETWORK_IF_WIFI;
        break;
    case NETWORK_MODE_WIFI_PREFERRED:
        if (wifi_usable) return NETWORK_IF_WIFI;
        if (eth_usable) return NETWORK_IF_ETHERNET;
        break;
    default:
        break;
    }
    return s_net.setup_ap_active ? NETWORK_IF_SETUP_AP : NETWORK_IF_NONE;
}

static void refresh_active_locked(void)
{
    set_active_locked(compute_active_if_locked());
}

static bool has_real_link_locked(void)
{
    network_active_if_t iface = compute_active_if_locked();
    return iface == NETWORK_IF_ETHERNET || iface == NETWORK_IF_WIFI;
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


static void ip4_addr_to_str(uint32_t addr, char *out, size_t len)
{
    if (!out || len == 0) return;
    esp_ip4_addr_t ip = { .addr = addr };
    esp_ip4addr_ntoa(&ip, out, len);
}

static void netif_info_to_strings(esp_netif_t *netif, char *ip, size_t ip_len,
                                  char *mask, size_t mask_len,
                                  char *gw, size_t gw_len,
                                  char *dns1, size_t dns1_len,
                                  char *dns2, size_t dns2_len,
                                  bool *dhcp)
{
    if (ip && ip_len) strlcpy(ip, "0.0.0.0", ip_len);
    if (mask && mask_len) strlcpy(mask, "0.0.0.0", mask_len);
    if (gw && gw_len) strlcpy(gw, "0.0.0.0", gw_len);
    if (dns1 && dns1_len) strlcpy(dns1, "0.0.0.0", dns1_len);
    if (dns2 && dns2_len) strlcpy(dns2, "0.0.0.0", dns2_len);
    if (dhcp) *dhcp = true;
    if (!netif) return;
    esp_netif_ip_info_t info = {0};
    if (esp_netif_get_ip_info(netif, &info) == ESP_OK) {
        ip4_addr_to_str(info.ip.addr, ip, ip_len);
        ip4_addr_to_str(info.netmask.addr, mask, mask_len);
        ip4_addr_to_str(info.gw.addr, gw, gw_len);
    }
    esp_netif_dns_info_t dns = {0};
    if (esp_netif_get_dns_info(netif, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK) ip4_addr_to_str(dns.ip.u_addr.ip4.addr, dns1, dns1_len);
    if (esp_netif_get_dns_info(netif, ESP_NETIF_DNS_BACKUP, &dns) == ESP_OK) ip4_addr_to_str(dns.ip.u_addr.ip4.addr, dns2, dns2_len);
    esp_netif_dhcp_status_t dhcp_status = ESP_NETIF_DHCP_STOPPED;
    if (dhcp && esp_netif_dhcpc_get_status(netif, &dhcp_status) == ESP_OK) *dhcp = (dhcp_status == ESP_NETIF_DHCP_STARTED);
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


static esp_err_t configure_ap_ip_locked(void)
{
    if (!s_ap_netif) return ESP_ERR_INVALID_STATE;
    if (s_net.setup_ap_ip_configured && s_net.setup_ap_dhcp_started) return ESP_OK;

    esp_netif_ip_info_t ip_info = {0};
    ip_info.ip.addr = ipaddr_addr(NETWORK_SETUP_AP_IP);
    ip_info.gw.addr = ipaddr_addr(NETWORK_SETUP_AP_IP);
    ip_info.netmask.addr = ipaddr_addr(NETWORK_SETUP_AP_NETMASK);

    if (!s_net.setup_ap_ip_configured) {
        esp_err_t err = esp_netif_dhcps_stop(s_ap_netif);
        if (err != ESP_OK && err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED) return err;
        s_net.setup_ap_dhcp_started = false;
        ESP_RETURN_ON_ERROR(esp_netif_set_ip_info(s_ap_netif, &ip_info), TAG, "ap_ip");
        s_net.setup_ap_ip_configured = true;
    }

    if (!s_net.setup_ap_dhcp_started) {
        esp_err_t err = esp_netif_dhcps_start(s_ap_netif);
        if (err != ESP_OK && err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STARTED) return err;
        s_net.setup_ap_dhcp_started = true;
    }
    return ESP_OK;
}

static esp_err_t wifi_apply_mode_locked(void)
{
    wifi_mode_t mode = WIFI_MODE_NULL;
    if (s_net.wifi_sta_started || s_net.wifi_runtime_desired) mode = WIFI_MODE_STA;
    if (s_net.setup_ap_active) mode = (mode == WIFI_MODE_STA) ? WIFI_MODE_APSTA : WIFI_MODE_AP;
    if (s_net.wifi_current_mode == mode) return ESP_OK;
    esp_err_t err = esp_wifi_set_mode(mode);
    if (err == ESP_OK) s_net.wifi_current_mode = mode;
    return err;
}

static esp_err_t wifi_start_once_locked(void)
{
    if (s_net.wifi_started) return ESP_OK;
    esp_err_t err = esp_wifi_start();
    if (err == ESP_ERR_WIFI_CONN) err = ESP_OK;
    if (err == ESP_OK) s_net.wifi_started = true;
    return err;
}

static void wifi_stop_driver_locked(void)
{
    if (!s_net.wifi_started) return;
    esp_wifi_stop();
    s_net.wifi_started = false;
    s_net.wifi_current_mode = WIFI_MODE_NULL;
}

static esp_err_t setup_ap_start_locked(const char *reason)
{
    if (!setup_ap_allowed(&s_net.cfg)) return ESP_ERR_INVALID_STATE;
    if (s_net.setup_ap_active) {
        if (!has_real_link_locked()) set_active_locked(NETWORK_IF_SETUP_AP);
        ESP_LOGD(TAG, "Fallback AP already active");
        return ESP_OK;
    }

    ESP_RETURN_ON_ERROR(ensure_wifi_driver(), TAG, "ensure_wifi_ap");
    build_setup_ap_ssid(s_net.setup_ap_ssid, sizeof(s_net.setup_ap_ssid));
    strlcpy(s_net.setup_ap_ip, NETWORK_SETUP_AP_IP, sizeof(s_net.setup_ap_ip));
    ESP_RETURN_ON_ERROR(configure_ap_ip_locked(), TAG, "ap_ip_config");

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
    ap_cfg.ap.ssid_hidden = 0;
    ap_cfg.ap.pmf_cfg.required = false;
    strlcpy((char *)ap_cfg.ap.password, ap_pass, sizeof(ap_cfg.ap.password));
    if (strlen(ap_pass) < 8) ap_cfg.ap.authmode = WIFI_AUTH_OPEN;

    s_net.setup_ap_active = true;
    esp_err_t err = wifi_apply_mode_locked();
    if (err == ESP_OK) err = esp_wifi_set_config(WIFI_IF_AP, &ap_cfg);
    if (err == ESP_OK) err = wifi_start_once_locked();
    if (err != ESP_OK) {
        s_net.setup_ap_active = false;
        s_net.setup_ap_ssid[0] = '\0';
        s_net.setup_ap_ip[0] = '\0';
        return err;
    }
    if (!has_real_link_locked()) set_active_locked(NETWORK_IF_SETUP_AP);
    s_net.setup_ap_start_count++;
    s_net.setup_ap_last_start_ms = now_ms();
    strlcpy(s_net.setup_ap_last_reason, reason ? reason : "fallback", sizeof(s_net.setup_ap_last_reason));
    ESP_LOGW(TAG, "Fallback AP started: SSID=%s IP=%s reason=%s start_count=%lu",
             s_net.setup_ap_ssid, s_net.setup_ap_ip, s_net.setup_ap_last_reason,
             (unsigned long)s_net.setup_ap_start_count);
    ESP_LOGW(TAG, "MQTT sospeso: AP setup senza connettività broker");
    return ESP_OK;
}

static esp_err_t setup_ap_stop_force_locked(const char *reason, bool ignore_grace)
{
    if (setup_ap_grace_active_locked() && !ignore_grace) return ESP_ERR_INVALID_STATE;
    if (!s_net.setup_ap_active || !s_net.wifi_driver_ready) return ESP_OK;
    s_net.setup_ap_active = false;
    s_net.setup_ap_ssid[0] = '\0';
    s_net.setup_ap_ip[0] = '\0';
    if (s_net.active_if == NETWORK_IF_SETUP_AP) set_active_locked(NETWORK_IF_NONE);
    esp_err_t err = wifi_apply_mode_locked();
    if (err == ESP_OK && !s_net.wifi_sta_started && !s_net.wifi_runtime_desired) wifi_stop_driver_locked();
    refresh_active_locked();
    ESP_LOGI(TAG, "fallback_ap_stopped active_interface=%s", network_active_if_to_str(s_net.active_if));
    ESP_LOGI(TAG, "AP fallback disattivato reason=%s", reason ? reason : "manual");
    return err;
}

static void setup_ap_stop_locked(void)
{
    (void)setup_ap_stop_force_locked("auto", false);
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
    esp_err_t err = wifi_start_once_locked();
    if (err == ESP_ERR_WIFI_NOT_INIT) return err;
    if (err != ESP_OK) return err;
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
    if (!s_net.setup_ap_active) wifi_stop_driver_locked();
    s_net.wifi_connected = false;
    s_net.wifi_has_ip = false;
    s_net.wifi_ip[0] = '\0';
    if (s_net.active_if == NETWORK_IF_WIFI) refresh_active_locked();
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
    if (s_net.active_if == NETWORK_IF_ETHERNET) refresh_active_locked();
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
        if (s_net.active_if == NETWORK_IF_ETHERNET) refresh_active_locked();
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
    bool start_sntp = false;
    xSemaphoreTake(s_net.lock, portMAX_DELAY);
    if (id == IP_EVENT_ETH_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)data;
        s_net.eth_has_ip = true;
        ip_to_str(&event->ip_info, s_net.eth_ip, sizeof(s_net.eth_ip));
        char gw[16];
        ip_to_str(&(esp_netif_ip_info_t){ .ip = event->ip_info.gw }, gw, sizeof(gw));
        ESP_LOGI(TAG, "Ethernet IP ottenuto: %s", s_net.eth_ip);
        set_error_locked("");
        ESP_LOGI(TAG, "eth_got_ip ip=%s gw=%s", s_net.eth_ip, gw);
        if (s_net.setup_ap_active && !setup_ap_grace_active_locked()) setup_ap_stop_locked();
        if (s_net.cfg.mode == NETWORK_MODE_ETHERNET_PREFERRED && s_net.wifi_sta_started) wifi_stop_sta_locked();
        refresh_active_locked();
        start_sntp = has_real_link_locked();
        start_mqtt = has_real_link_locked() && !s_net.network_transition_in_progress;
    } else if (id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)data;
        s_net.wifi_has_ip = true;
        ip_to_str(&event->ip_info, s_net.wifi_ip, sizeof(s_net.wifi_ip));
        wifi_ap_record_t ap = {0};
        if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) s_net.wifi_rssi = ap.rssi;
        char gw[16];
        ip_to_str(&(esp_netif_ip_info_t){ .ip = event->ip_info.gw }, gw, sizeof(gw));
        ESP_LOGI(TAG, "Wi-Fi connesso, IP ottenuto: %s", s_net.wifi_ip);
        set_error_locked("");
        ESP_LOGI(TAG, "wifi_got_ip ip=%s gw=%s", s_net.wifi_ip, gw);
        if (s_net.setup_ap_active && !s_net.wifi_test_active && !setup_ap_grace_active_locked()) setup_ap_stop_locked();
        s_net.wifi_failures = 0;
        refresh_active_locked();
        start_sntp = has_real_link_locked();
        start_mqtt = has_real_link_locked() && !s_net.network_transition_in_progress;
    }
    xSemaphoreGive(s_net.lock);
    if (start_sntp) {
        esp_err_t time_err = system_time_sntp_start_async(id == IP_EVENT_ETH_GOT_IP ? "eth_got_ip" : "wifi_got_ip");
        if (time_err != ESP_OK) ESP_LOGW(TAG, "SNTP non avviato dopo IP: %s", esp_err_to_name(time_err));
    }
    if (start_mqtt) {
        esp_err_t err = mqtt_reload_config();
        if (err != ESP_OK) ESP_LOGW(TAG, "MQTT non avviato dopo IP: %s", esp_err_to_name(err));
    }
}

static void network_wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg; (void)base;
    if (!s_net.lock) return;
    bool stop_mqtt = false;
    xSemaphoreTake(s_net.lock, portMAX_DELAY);
    if (id == WIFI_EVENT_STA_START) {
        s_net.wifi_started = true;
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
        if (s_net.active_if == NETWORK_IF_WIFI) refresh_active_locked();
        stop_mqtt = was_active && !has_real_link_locked();
    } else if (id == WIFI_EVENT_STA_STOP) {
        bool was_active = s_net.active_if == NETWORK_IF_WIFI || s_net.wifi_has_ip;
        s_net.wifi_started = false;
        s_net.wifi_current_mode = WIFI_MODE_NULL;
        s_net.wifi_sta_started = false;
        s_net.wifi_connected = false;
        s_net.wifi_has_ip = false;
        stop_mqtt = was_active && !has_real_link_locked();
    } else if (id == WIFI_EVENT_AP_START) {
        s_net.wifi_started = true;
    } else if (id == WIFI_EVENT_AP_STOP) {
        s_net.setup_ap_active = false;
        s_net.setup_ap_client_count = 0;
        s_net.wifi_started = s_net.wifi_sta_started;
    } else if (id == WIFI_EVENT_AP_STACONNECTED && data) {
        wifi_event_ap_staconnected_t *event = (wifi_event_ap_staconnected_t *)data;
        if (s_net.setup_ap_client_count < UINT32_MAX) s_net.setup_ap_client_count++;
        snprintf(s_net.setup_ap_last_client_event, sizeof(s_net.setup_ap_last_client_event),
                 "join " MACSTR " aid=%u", MAC2STR(event->mac), event->aid);
        ESP_LOGI(TAG, "Fallback AP station join: " MACSTR " aid=%u clients=%lu",
                 MAC2STR(event->mac), event->aid, (unsigned long)s_net.setup_ap_client_count);
    } else if (id == WIFI_EVENT_AP_STADISCONNECTED && data) {
        wifi_event_ap_stadisconnected_t *event = (wifi_event_ap_stadisconnected_t *)data;
        if (s_net.setup_ap_client_count > 0) s_net.setup_ap_client_count--;
        snprintf(s_net.setup_ap_last_client_event, sizeof(s_net.setup_ap_last_client_event),
                 "leave " MACSTR " aid=%u reason=%u", MAC2STR(event->mac), event->aid, event->reason);
        ESP_LOGI(TAG, "Fallback AP station leave: " MACSTR " aid=%u reason=%u clients=%lu",
                 MAC2STR(event->mac), event->aid, event->reason, (unsigned long)s_net.setup_ap_client_count);
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

        if (mode == NETWORK_MODE_ETHERNET_PREFERRED && eth_usable && s_net.wifi_sta_started) {
            wifi_stop_sta_locked();
        }
        refresh_active_locked();

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

        if (s_net.setup_ap_grace_until_ms && !setup_ap_grace_active_locked()) {
            bool primary_ready = has_real_link_locked();
            ESP_LOGI(TAG, "fallback_ap_grace_expired primary_ready=%s", primary_ready ? "true" : "false");
            s_net.setup_ap_grace_until_ms = 0;
            if (primary_ready && s_net.setup_ap_active) {
                ESP_LOGI(TAG, "fallback_ap_stop_requested reason=grace_expired");
                (void)setup_ap_stop_force_locked("grace_expired", true);
            } else if (!primary_ready) {
                set_error_locked("primary_not_ready_after_grace");
                ESP_LOGW(TAG, "fallback_ap_grace_expired primary_ready=false keeping_setup_ap=true");
            }
        } else if (needs_setup_ap && !s_net.setup_ap_active) {
            setup_ap_start_locked(reason);
        } else if (has_real_link_locked() && s_net.setup_ap_active && !setup_ap_grace_active_locked()) {
            setup_ap_stop_locked();
        }
        uint32_t grace_remaining = setup_ap_grace_remaining_locked();
        if (grace_remaining && (s_net.last_grace_log_remaining_s == 0 || grace_remaining <= 5 || (grace_remaining % 15u) == 0u) && grace_remaining != s_net.last_grace_log_remaining_s) {
            s_net.last_grace_log_remaining_s = grace_remaining;
            ESP_LOGI(TAG, "fallback_ap_grace_remaining=%lu", (unsigned long)grace_remaining);
        }
        static network_active_if_t last_mqtt_iface = NETWORK_IF_NONE;
        if (has_real_link_locked() && !s_net.network_transition_in_progress && s_net.active_if != last_mqtt_iface) {
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


esp_err_t network_setup_ap_start_grace(uint32_t seconds)
{
    if (seconds < 60) seconds = 60;
    if (seconds > 180) seconds = 180;
    if (!s_net.lock) return ESP_ERR_INVALID_STATE;
    network_config_t cfg;
    xSemaphoreTake(s_net.lock, portMAX_DELAY);
    if (network_config_load(&cfg) == ESP_OK) s_net.cfg = cfg;
    s_net.setup_ap_grace_until_ms = now_ms() + ((uint64_t)seconds * 1000ULL);
    s_net.last_grace_log_remaining_s = seconds;
    ESP_LOGI(TAG, "fallback_ap_grace_started seconds=%lu", (unsigned long)seconds);
    esp_err_t err = setup_ap_allowed(&s_net.cfg) ? setup_ap_start_locked("grace") : ESP_ERR_INVALID_STATE;
    xSemaphoreGive(s_net.lock);
    return err;
}

esp_err_t network_manager_restart(void)
{
    network_config_t cfg;
    ESP_RETURN_ON_ERROR(network_config_load(&cfg), TAG, "config_load");
    xSemaphoreTake(s_net.lock, portMAX_DELAY);
    s_net.network_transition_in_progress = true;
    if (!setup_ap_grace_active_locked()) setup_ap_stop_locked();
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
    s_net.network_transition_in_progress = false;
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
    out->active_if = compute_active_if_locked();
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
    out->setup_ap_client_count = s_net.setup_ap_client_count;
    out->setup_ap_start_count = s_net.setup_ap_start_count;
    out->setup_ap_last_start_ms = s_net.setup_ap_last_start_ms;
    strlcpy(out->setup_ap_last_reason, s_net.setup_ap_last_reason, sizeof(out->setup_ap_last_reason));
    strlcpy(out->setup_ap_last_client_event, s_net.setup_ap_last_client_event, sizeof(out->setup_ap_last_client_event));
    out->fallback_ap_enabled = s_net.cfg.fallback_ap_enabled;
    out->fallback_ap_password_set = s_net.cfg.fallback_ap_password_set;
    strlcpy(out->last_error, s_net.last_error, sizeof(out->last_error));
    out->last_interface_change_ms = s_net.last_change_ms;
    out->setup_ap_grace_active = setup_ap_grace_active_locked();
    out->setup_ap_grace_remaining_s = setup_ap_grace_remaining_locked();
    out->network_transition_in_progress = s_net.network_transition_in_progress;
    strlcpy(out->setup_ap_netmask, NETWORK_SETUP_AP_NETMASK, sizeof(out->setup_ap_netmask));
    if (s_net.lock) xSemaphoreGive(s_net.lock);
    mac_to_str(ESP_MAC_ETH, out->ethernet_mac, sizeof(out->ethernet_mac));
    mac_to_str(ESP_MAC_WIFI_STA, out->wifi_mac, sizeof(out->wifi_mac));
    netif_info_to_strings(eth_get_netif(), out->ethernet_ip, sizeof(out->ethernet_ip),
                          out->ethernet_netmask, sizeof(out->ethernet_netmask),
                          out->ethernet_gateway, sizeof(out->ethernet_gateway),
                          out->ethernet_dns1, sizeof(out->ethernet_dns1),
                          out->ethernet_dns2, sizeof(out->ethernet_dns2),
                          &out->ethernet_dhcp);
    netif_info_to_strings(s_wifi_netif, out->wifi_ip, sizeof(out->wifi_ip),
                          out->wifi_netmask, sizeof(out->wifi_netmask),
                          out->wifi_gateway, sizeof(out->wifi_gateway),
                          out->wifi_dns1, sizeof(out->wifi_dns1),
                          out->wifi_dns2, sizeof(out->wifi_dns2),
                          &out->wifi_dhcp);
    out->wifi_dhcp = out->wifi_dhcp || s_net.cfg.wifi_dhcp;
    out->ethernet_dhcp = out->ethernet_dhcp || s_net.cfg.eth_dhcp;
    if (!out->ethernet_has_ip) {
        strlcpy(out->ethernet_ip, "0.0.0.0", sizeof(out->ethernet_ip));
        strlcpy(out->ethernet_netmask, "0.0.0.0", sizeof(out->ethernet_netmask));
        strlcpy(out->ethernet_gateway, "0.0.0.0", sizeof(out->ethernet_gateway));
        strlcpy(out->ethernet_dns1, "0.0.0.0", sizeof(out->ethernet_dns1));
        strlcpy(out->ethernet_dns2, "0.0.0.0", sizeof(out->ethernet_dns2));
    }
    if (!out->wifi_has_ip) {
        strlcpy(out->wifi_ip, "0.0.0.0", sizeof(out->wifi_ip));
        strlcpy(out->wifi_netmask, "0.0.0.0", sizeof(out->wifi_netmask));
        strlcpy(out->wifi_gateway, "0.0.0.0", sizeof(out->wifi_gateway));
        strlcpy(out->wifi_dns1, "0.0.0.0", sizeof(out->wifi_dns1));
        strlcpy(out->wifi_dns2, "0.0.0.0", sizeof(out->wifi_dns2));
    }
    wifi_ap_record_t ap = {0};
    if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
        out->wifi_rssi = ap.rssi;
        out->wifi_channel = ap.primary;
        snprintf(out->wifi_bssid, sizeof(out->wifi_bssid), MACSTR, MAC2STR(ap.bssid));
    } else {
        out->wifi_channel = 0;
        out->wifi_bssid[0] = '\0';
    }
    return ESP_OK;
}

esp_err_t network_status_append_json(cJSON *root)
{
    if (!root) return ESP_ERR_INVALID_ARG;
    network_status_t st;
    ESP_RETURN_ON_ERROR(network_get_status(&st), TAG, "status");
    const bool real_connectivity = st.active_if == NETWORK_IF_ETHERNET || st.active_if == NETWORK_IF_WIFI;
    cJSON_AddStringToObject(root, "configured_mode", network_mode_to_str(st.mode));
    cJSON_AddStringToObject(root, "network_mode", network_mode_to_str(st.mode));
    cJSON_AddStringToObject(root, "active_interface", network_active_if_to_str(st.active_if));
    cJSON_AddStringToObject(root, "hostname", st.hostname);
    cJSON_AddStringToObject(root, "connectivity", real_connectivity ? "connected" : (st.setup_ap_active ? "setup_ap" : "disconnected"));
    cJSON_AddStringToObject(root, "last_error", st.last_error);
    cJSON_AddStringToObject(root, "last_event", network_active_if_to_str(st.active_if));
    cJSON_AddNumberToObject(root, "last_interface_change_ms", (double)st.last_interface_change_ms);
    cJSON_AddBoolToObject(root, "network_transition_in_progress", st.network_transition_in_progress);
    cJSON_AddBoolToObject(root, "primary_network_ready", st.active_if == NETWORK_IF_ETHERNET || st.active_if == NETWORK_IF_WIFI);

    cJSON *eth = cJSON_AddObjectToObject(root, "ethernet");
    cJSON_AddBoolToObject(eth, "enabled", st.mode != NETWORK_MODE_WIFI_ONLY);
    cJSON_AddBoolToObject(eth, "configured", st.mode != NETWORK_MODE_WIFI_ONLY);
    cJSON_AddBoolToObject(eth, "initialized", st.ethernet_started);
    cJSON_AddBoolToObject(eth, "active", st.active_if == NETWORK_IF_ETHERNET);
    cJSON_AddBoolToObject(eth, "started", st.ethernet_started);
    cJSON_AddBoolToObject(eth, "link_up", st.ethernet_link_up);
    cJSON_AddBoolToObject(eth, "has_ip", st.ethernet_has_ip);
    cJSON_AddStringToObject(eth, "mac", st.ethernet_mac);
    cJSON_AddStringToObject(eth, "ip", st.ethernet_ip);
    cJSON_AddStringToObject(eth, "netmask", st.ethernet_netmask);
    cJSON_AddStringToObject(eth, "gateway", st.ethernet_gateway);
    cJSON_AddStringToObject(eth, "dns1", st.ethernet_dns1);
    cJSON_AddStringToObject(eth, "dns2", st.ethernet_dns2);
    cJSON_AddBoolToObject(eth, "dhcp", st.ethernet_dhcp);

    cJSON *wifi = cJSON_AddObjectToObject(root, "wifi");
    cJSON_AddBoolToObject(wifi, "enabled", network_mode_requires_wifi(st.mode));
    cJSON_AddBoolToObject(wifi, "configured", network_mode_requires_wifi(st.mode));
    cJSON_AddBoolToObject(wifi, "active", st.active_if == NETWORK_IF_WIFI);
    cJSON_AddStringToObject(wifi, "ssid", st.wifi_ssid);
    cJSON_AddBoolToObject(wifi, "password_set", st.wifi_password_set);
    cJSON_AddBoolToObject(wifi, "started", st.wifi_started);
    cJSON_AddBoolToObject(wifi, "connected", st.wifi_connected);
    cJSON_AddBoolToObject(wifi, "has_ip", st.wifi_has_ip);
    cJSON_AddStringToObject(wifi, "bssid", st.wifi_bssid);
    cJSON_AddNumberToObject(wifi, "channel", st.wifi_channel);
    cJSON_AddNumberToObject(wifi, "rssi", st.wifi_rssi);
    cJSON_AddStringToObject(wifi, "mac", st.wifi_mac);
    cJSON_AddStringToObject(wifi, "ip", st.wifi_ip);
    cJSON_AddStringToObject(wifi, "netmask", st.wifi_netmask);
    cJSON_AddStringToObject(wifi, "gateway", st.wifi_gateway);
    cJSON_AddStringToObject(wifi, "dns1", st.wifi_dns1);
    cJSON_AddStringToObject(wifi, "dns2", st.wifi_dns2);
    cJSON_AddBoolToObject(wifi, "dhcp", st.wifi_dhcp);

    cJSON *ap = cJSON_AddObjectToObject(root, "fallback_ap");
    cJSON_AddBoolToObject(ap, "enabled", st.fallback_ap_enabled);
    cJSON_AddBoolToObject(ap, "active", st.setup_ap_active);
    cJSON_AddBoolToObject(ap, "runtime", st.setup_ap_active);
    cJSON_AddStringToObject(ap, "ssid", st.setup_ap_ssid);
    cJSON_AddStringToObject(ap, "ip", st.setup_ap_ip);
    cJSON_AddStringToObject(ap, "netmask", st.setup_ap_netmask);
    cJSON_AddNumberToObject(ap, "clients", st.setup_ap_client_count);
    cJSON_AddNumberToObject(ap, "start_count", st.setup_ap_start_count);
    cJSON_AddNumberToObject(ap, "last_start_ms", (double)st.setup_ap_last_start_ms);
    cJSON_AddStringToObject(ap, "last_reason", st.setup_ap_last_reason);
    cJSON_AddStringToObject(ap, "last_client_event", st.setup_ap_last_client_event);
    cJSON_AddBoolToObject(ap, "password_set", st.fallback_ap_password_set);
    cJSON_AddBoolToObject(ap, "grace_active", st.setup_ap_grace_active);
    cJSON_AddBoolToObject(root, "fallback_ap_active", st.setup_ap_active);
    cJSON_AddBoolToObject(root, "fallback_ap_grace_active", st.setup_ap_grace_active);
    cJSON_AddNumberToObject(root, "fallback_ap_grace_remaining_s", (double)st.setup_ap_grace_remaining_s);
    cJSON_AddNumberToObject(ap, "grace_remaining_s", st.setup_ap_grace_remaining_s);
    cJSON *ap_alias = cJSON_Duplicate(ap, true);
    if (ap_alias) cJSON_AddItemToObject(root, "setup_ap", ap_alias);

    cJSON *mqtt = cJSON_AddObjectToObject(root, "mqtt");
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
    s_net.setup_ap_grace_until_ms = 0;
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
        err = wifi_start_once_locked();
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
    ESP_LOGI(TAG, "wifi_test_start ssid=%s", ssid);
    if (strlen(ssid) > NETWORK_WIFI_SSID_MAX) return ESP_ERR_INVALID_SIZE;
    network_config_t old_cfg;
    network_config_load(&old_cfg);
    const char *pass = password;
    if (use_saved_password || !pass || !pass[0]) pass = old_cfg.wifi_password;
    if (!pass || !pass[0] || strlen(pass) > NETWORK_WIFI_PASSWORD_MAX) return ESP_ERR_INVALID_ARG;

    network_status_t current = {0};
    if (network_get_status(&current) == ESP_OK && current.wifi_connected && current.wifi_has_ip && !strcmp(current.wifi_ssid, ssid)) {
        xSemaphoreTake(s_net.lock, portMAX_DELAY);
        s_net.last_wifi_test_ok_ms = now_ms();
        strlcpy(s_net.last_wifi_test_ssid, ssid, sizeof(s_net.last_wifi_test_ssid));
        strlcpy(s_net.last_wifi_test_password, pass, sizeof(s_net.last_wifi_test_password));
        xSemaphoreGive(s_net.lock);
        ESP_LOGI(TAG, "wifi_test_already_connected ssid=%s ip=%s", ssid, current.wifi_ip);
        return ESP_OK;
    }

    xSemaphoreTake(s_net.lock, portMAX_DELAY);
    network_config_t runtime_bak = s_net.cfg;
    bool wifi_was_started = s_net.wifi_sta_started;
    s_net.wifi_test_active = true;
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
            ESP_LOGI(TAG, "wifi_test_success ip=%s gw=%s rssi=%d", st.wifi_ip, st.wifi_gateway, st.wifi_rssi);
            err = ESP_OK;
            goto out_restore;
        }
        vTaskDelay(pdMS_TO_TICKS(250));
    }
    err = ESP_ERR_TIMEOUT;

out_restore:
    xSemaphoreTake(s_net.lock, portMAX_DELAY);
    s_net.cfg = runtime_bak;
    s_net.wifi_test_active = false;
    if (err != ESP_OK) {
        if (!wifi_was_started && runtime_bak.mode != NETWORK_MODE_WIFI_ONLY && runtime_bak.mode != NETWORK_MODE_WIFI_PREFERRED) {
            wifi_stop_sta_locked();
        } else if (wifi_was_started) {
            wifi_start_sta_locked();
        }
    }
    if (err != ESP_OK) {
        set_error_locked("wifi_test_failed");
        ESP_LOGW(TAG, "wifi_test_failed reason=%s", esp_err_to_name(err));
    }
    xSemaphoreGive(s_net.lock);
    return err;
}


esp_err_t network_wifi_test_append_json(cJSON *root, const char *ssid, const char *password, bool use_saved_password, uint32_t timeout_ms)
{
    if (!root) return ESP_ERR_INVALID_ARG;
    esp_err_t err = network_wifi_test(ssid, password, use_saved_password, timeout_ms);
    if (err != ESP_OK) return err;
    network_status_t st = {0};
    ESP_RETURN_ON_ERROR(network_get_status(&st), TAG, "wifi_test_status");
    cJSON_AddBoolToObject(root, "ok", true);
    cJSON_AddStringToObject(root, "message", !strcmp(st.wifi_ssid, ssid) && st.wifi_connected ? "Wi-Fi già connesso" : "Connessione Wi-Fi riuscita");
    cJSON_AddBoolToObject(root, "temporary", true);
    cJSON_AddBoolToObject(root, "saved", false);
    cJSON_AddStringToObject(root, "ssid", ssid);
    cJSON_AddStringToObject(root, "ip", st.wifi_ip);
    cJSON_AddStringToObject(root, "netmask", st.wifi_netmask);
    cJSON_AddStringToObject(root, "gateway", st.wifi_gateway);
    cJSON_AddStringToObject(root, "dns1", st.wifi_dns1);
    cJSON_AddStringToObject(root, "dns2", st.wifi_dns2);
    cJSON_AddNumberToObject(root, "rssi", st.wifi_rssi);
    cJSON_AddNumberToObject(root, "channel", st.wifi_channel);
    cJSON_AddStringToObject(root, "bssid", st.wifi_bssid);
    return ESP_OK;
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

bool network_wifi_sta_ready_for(const char *ssid)
{
    if (!ssid || !ssid[0] || !s_net.lock) return false;
    bool ok = false;
    xSemaphoreTake(s_net.lock, portMAX_DELAY);
    ok = s_net.wifi_connected && s_net.wifi_has_ip && s_net.wifi_ip[0] && strcmp(s_net.wifi_ip, "0.0.0.0") != 0;
    xSemaphoreGive(s_net.lock);
    if (!ok) return false;
    wifi_ap_record_t ap = {0};
    if (esp_wifi_sta_get_ap_info(&ap) != ESP_OK) return false;
    if (strcmp((const char *)ap.ssid, ssid) != 0) return false;
    if (s_wifi_netif) {
        esp_netif_ip_info_t info = {0};
        if (esp_netif_get_ip_info(s_wifi_netif, &info) != ESP_OK || info.ip.addr == 0 || info.gw.addr == 0) return false;
    }
    return true;
}

esp_err_t network_apply_runtime_non_destructive(const network_config_t *cfg)
{
    if (!cfg || !s_net.lock) return ESP_ERR_INVALID_ARG;
    if (!network_mode_requires_wifi(cfg->mode) || !network_wifi_sta_ready_for(cfg->wifi_ssid)) return ESP_ERR_INVALID_STATE;
    xSemaphoreTake(s_net.lock, portMAX_DELAY);
    s_net.cfg = *cfg;
    s_net.wifi_runtime_desired = true;
    s_net.wifi_sta_started = true;
    s_net.network_transition_in_progress = false;
    set_error_locked("");
    refresh_active_locked();
    esp_err_t err = wifi_apply_mode_locked();
    xSemaphoreGive(s_net.lock);
    ESP_LOGI(TAG, "network_apply_non_destructive mode=%s ssid=%s active_interface=%s", network_mode_to_str(cfg->mode), cfg->wifi_ssid, network_active_if_to_str(s_net.active_if));
    return err;
}

esp_err_t network_setup_ap_stop_grace(void)
{
    if (!s_net.lock) return ESP_ERR_INVALID_STATE;
    xSemaphoreTake(s_net.lock, portMAX_DELAY);
    bool primary_ready = has_real_link_locked();
    ESP_LOGI(TAG, "fallback_ap_stop_requested reason=manual primary_ready=%s", primary_ready ? "true" : "false");
    esp_err_t err = ESP_OK;
    if (!primary_ready) {
        set_error_locked("primary_not_ready");
        err = ESP_ERR_INVALID_STATE;
    } else {
        s_net.setup_ap_grace_until_ms = 0;
        err = setup_ap_stop_force_locked("manual", true);
    }
    xSemaphoreGive(s_net.lock);
    return err;
}

bool network_transition_in_progress(void)
{
    if (!s_net.lock) return false;
    xSemaphoreTake(s_net.lock, portMAX_DELAY);
    bool in_progress = s_net.network_transition_in_progress;
    xSemaphoreGive(s_net.lock);
    return in_progress;
}

bool network_primary_ready(void)
{
    if (!s_net.lock) return false;
    xSemaphoreTake(s_net.lock, portMAX_DELAY);
    bool ready = has_real_link_locked() && !s_net.network_transition_in_progress;
    xSemaphoreGive(s_net.lock);
    return ready;
}


esp_err_t network_mark_transition_pending(bool pending)
{
    if (!s_net.lock) return ESP_ERR_INVALID_STATE;
    xSemaphoreTake(s_net.lock, portMAX_DELAY);
    s_net.network_transition_in_progress = pending;
    xSemaphoreGive(s_net.lock);
    ESP_LOGI(TAG, "network_transition_in_progress=%s", pending ? "true" : "false");
    return ESP_OK;
}