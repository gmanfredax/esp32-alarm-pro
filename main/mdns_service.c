#include "mdns_service.h"

#include <stdbool.h>
#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "mdns.h"

#include "ethernet.h"

#define MDNS_HOSTNAME_MAX_LEN 63

static const char *TAG = "mdns_svc";

static bool s_mdns_initialized = false;
static bool s_https_registered = false;
static bool s_http_registered = false;
static char s_current_hostname[MDNS_HOSTNAME_MAX_LEN + 1] = "";

static const char *fallback_hostname(void)
{
    if (s_current_hostname[0]) {
        return s_current_hostname;
    }
    const char *default_name = "esp32-alarm";
    strlcpy(s_current_hostname, default_name, sizeof(s_current_hostname));
    return s_current_hostname;
}

static const char *netif_hostname(void)
{
    esp_netif_t *netif = eth_get_netif();
    if (!netif) {
        return NULL;
    }
    const char *hostname = NULL;
    const char *hostname_ptr = NULL;
    esp_err_t err = esp_netif_get_hostname(netif, &hostname_ptr);
    if (err == ESP_OK && hostname_ptr && hostname_ptr[0]) {
        hostname = hostname_ptr;
        return hostname;
    }
    return NULL;
}

static esp_err_t ensure_mdns_initialized(void)
{
    if (s_mdns_initialized) {
        return ESP_OK;
    }
    esp_err_t err = mdns_init();
    if (err == ESP_ERR_INVALID_STATE) {
        ESP_LOGW(TAG, "mDNS already initialised");
        s_mdns_initialized = true;
        return ESP_OK;
    }
    if (err == ESP_ERR_NO_MEM) {
        ESP_LOGE(TAG, "mDNS init failed: %s", esp_err_to_name(err));
        return err;
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "mDNS init error: %s", esp_err_to_name(err));
        return err;
    }
    s_mdns_initialized = true;
    return ESP_OK;
}

static void update_service_instance_names(void)
{
    const char *name = fallback_hostname();
    if (s_https_registered) {
        esp_err_t err = mdns_service_instance_name_set("_https", "_tcp", name);
        if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
            ESP_LOGW(TAG, "https instance update failed: %s", esp_err_to_name(err));
        }
    }
    if (s_http_registered) {
        esp_err_t err = mdns_service_instance_name_set("_http", "_tcp", name);
        if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
            ESP_LOGW(TAG, "http instance update failed: %s", esp_err_to_name(err));
        }
    }
}

static esp_err_t apply_hostname(const char *hostname)
{
    if (!hostname || !hostname[0]) {
        hostname = fallback_hostname();
    }

    esp_err_t err = mdns_hostname_set(hostname);
    if (err == ESP_ERR_NO_MEM) {
        ESP_LOGE(TAG, "mdns_hostname_set: %s", esp_err_to_name(err));
        return err;
    }
    if (err == ESP_ERR_INVALID_STATE) {
        ESP_LOGW(TAG, "mdns_hostname_set: %s", esp_err_to_name(err));
    } else if (err != ESP_OK) {
        ESP_LOGW(TAG, "mdns_hostname_set: %s", esp_err_to_name(err));
        return err;
    }

    err = mdns_instance_name_set(hostname);
    if (err == ESP_ERR_NO_MEM) {
        ESP_LOGE(TAG, "mdns_instance_name_set: %s", esp_err_to_name(err));
        return err;
    }
    if (err == ESP_ERR_INVALID_STATE) {
        ESP_LOGW(TAG, "mdns_instance_name_set: %s", esp_err_to_name(err));
    } else if (err != ESP_OK) {
        ESP_LOGW(TAG, "mdns_instance_name_set: %s", esp_err_to_name(err));
        return err;
    }

    strlcpy(s_current_hostname, hostname, sizeof(s_current_hostname));
    update_service_instance_names();

    return ESP_OK;
}

static void register_http_service_if_needed(void)
{
    if (s_http_registered) {
        return;
    }
    mdns_txt_item_t txt[] = {
        {"path", "/"},
    };
    esp_err_t err = mdns_service_add(NULL, "_http", "_tcp", 80, txt, sizeof(txt) / sizeof(txt[0]));
    if (err == ESP_OK || err == ESP_ERR_INVALID_STATE) {
        s_http_registered = true;
        update_service_instance_names();
        return;
    }
    if (err == ESP_ERR_NO_MEM) {
        ESP_LOGE(TAG, "mDNS http service: %s", esp_err_to_name(err));
        return;
    }
    ESP_LOGW(TAG, "mDNS http service: %s", esp_err_to_name(err));
}

static esp_err_t register_https_service(void)
{
    if (s_https_registered) {
        return ESP_OK;
    }
    mdns_txt_item_t txt[] = {
        {"path", "/"},
    };
    esp_err_t err = mdns_service_add(NULL, "_https", "_tcp", 443, txt, sizeof(txt) / sizeof(txt[0]));
    if (err == ESP_OK || err == ESP_ERR_INVALID_STATE) {
        s_https_registered = true;
        update_service_instance_names();
        return ESP_OK;
    }
    if (err == ESP_ERR_NO_MEM) {
        ESP_LOGE(TAG, "mDNS https service: %s", esp_err_to_name(err));
        return err;
    }
    ESP_LOGW(TAG, "mDNS https service: %s", esp_err_to_name(err));
    return err;
}

esp_err_t mdns_service_start(void)
{
    esp_err_t err = ensure_mdns_initialized();
    if (err != ESP_OK) {
        return err;
    }

    const char *hostname = netif_hostname();
    err = apply_hostname(hostname);
    if (err != ESP_OK) {
        return err;
    }

    err = register_https_service();
    if (err == ESP_ERR_NO_MEM) {
        return err;
    }

    register_http_service_if_needed();

    return ESP_OK;
}

esp_err_t mdns_service_update_hostname(const char *hostname)
{
    esp_err_t err = ensure_mdns_initialized();
    if (err != ESP_OK) {
        return err;
    }

    err = apply_hostname(hostname);
    if (err == ESP_ERR_NO_MEM) {
        return err;
    }

    if (!s_https_registered) {
        err = register_https_service();
        if (err == ESP_ERR_NO_MEM) {
            return err;
        }
    }

    register_http_service_if_needed();

    return ESP_OK;
}