#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NETWORK_MODE_ETHERNET_ONLY = 0,
    NETWORK_MODE_WIFI_ONLY,
    NETWORK_MODE_ETHERNET_PREFERRED,
    NETWORK_MODE_WIFI_PREFERRED
} network_mode_t;

typedef enum {
    NETWORK_IF_NONE = 0,
    NETWORK_IF_ETHERNET,
    NETWORK_IF_WIFI,
    NETWORK_IF_SETUP_AP
} network_active_if_t;

#define NETWORK_WIFI_SSID_MAX 32
#define NETWORK_WIFI_PASSWORD_MAX 64
#define NETWORK_HOSTNAME_MAX 63

typedef struct {
    network_mode_t mode;
    char hostname[NETWORK_HOSTNAME_MAX + 1];
    char wifi_ssid[NETWORK_WIFI_SSID_MAX + 1];
    char wifi_password[NETWORK_WIFI_PASSWORD_MAX + 1];
    bool wifi_password_set;
    bool wifi_dhcp;
    bool eth_dhcp;
    bool fallback_ap_enabled;
    char fallback_ap_password[NETWORK_WIFI_PASSWORD_MAX + 1];
    bool fallback_ap_password_set;
} network_config_t;

typedef struct {
    network_mode_t mode;
    network_active_if_t active_if;
    char hostname[NETWORK_HOSTNAME_MAX + 1];
    bool ethernet_started;
    bool ethernet_link_up;
    bool ethernet_has_ip;
    char ethernet_ip[16];
    char ethernet_mac[18];
    bool wifi_started;
    bool wifi_connected;
    bool wifi_has_ip;
    char wifi_ssid[NETWORK_WIFI_SSID_MAX + 1];
    bool wifi_password_set;
    int wifi_rssi;
    char wifi_ip[16];
    char wifi_mac[18];
    bool setup_ap_active;
    char setup_ap_ssid[NETWORK_WIFI_SSID_MAX + 1];
    char setup_ap_ip[16];
    bool fallback_ap_enabled;
    bool fallback_ap_password_set;
    char last_error[96];
    uint64_t last_interface_change_ms;
} network_status_t;

const char *network_mode_to_str(network_mode_t mode);
bool network_mode_from_str(const char *str, network_mode_t *out);
const char *network_active_if_to_str(network_active_if_t iface);
bool network_mode_requires_wifi(network_mode_t mode);

esp_err_t network_config_load(network_config_t *cfg);
esp_err_t network_config_save(const network_config_t *cfg);
esp_err_t network_manager_start(void);
esp_err_t network_manager_restart(void);
esp_err_t network_wait_for_active_ip(TickType_t timeout);
esp_err_t network_get_status(network_status_t *out);
esp_err_t network_status_append_json(cJSON *root);
esp_err_t network_wifi_test(const char *ssid, const char *password, bool use_saved_password, uint32_t timeout_ms);
bool network_wifi_test_recent_ok(const char *ssid, const char *password);
esp_err_t network_wifi_scan_append_json(cJSON *array);
esp_err_t network_setup_exit(void);
bool network_has_real_connectivity(void);

#ifdef __cplusplus
}
#endif