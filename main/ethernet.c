// main/ethernet.c — ESP-IDF 5.3.x (LAN8720, RMII clk esterno su GPIO0)
#include "ethernet.h"
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "driver/gpio.h"

#include "esp_log.h"
#include "esp_check.h"
#include "esp_event.h"
#include "esp_system.h"

#include "esp_netif.h"

#include "esp_eth.h"
#include "esp_eth_mac.h"
#include "esp_eth_com.h"
#include "esp_eth_driver.h"
#include "esp_eth_mac_esp.h"
#include "esp_eth_phy.h"
#include "esp_eth_netif_glue.h"   // per esp_eth_new_netif_glue()

static const char *TAG = "eth";

// Pin PHY / RMII (adatta se diverso sul tuo HW)
#define ETH_MDC_GPIO         GPIO_NUM_23
#define ETH_MDIO_GPIO        GPIO_NUM_18
#define ETH_POWER_GPIO       GPIO_NUM_17
#define ETH_PHY_ADDR         1
// RMII clock esterno a 50MHz su GPIO0
#define ETH_RMII_CLK_IN_GPIO GPIO_NUM_0

static esp_eth_handle_t s_eth = NULL;
static esp_netif_t *s_eth_netif = NULL;
static esp_eth_netif_glue_handle_t s_glue = NULL;
static volatile bool s_eth_link_up = false; // aggiornato dagli eventi

// ─────────────────────────────────────────────────────────────────────────────
// Per sicurezza: lascia i pad RMII “puliti”: niente pull e direzione disabilitata
static void rmii_pins_release(void)
{
    const gpio_num_t rmii_pins[] = {
        GPIO_NUM_0,  // REF_CLK (50MHz in)
        GPIO_NUM_18, // MDIO
        GPIO_NUM_19, // TXD0
        GPIO_NUM_21, // TX_EN
        GPIO_NUM_22, // TXD1
        GPIO_NUM_23, // MDC
        GPIO_NUM_25, // RXD0
        GPIO_NUM_26, // RXD1
        GPIO_NUM_27, // CRS_DV
    };
    for (size_t i = 0; i < sizeof(rmii_pins)/sizeof(rmii_pins[0]); ++i) {
        gpio_pullup_dis(rmii_pins[i]);
        gpio_pulldown_dis(rmii_pins[i]);
        gpio_set_direction(rmii_pins[i], GPIO_MODE_DISABLE);
    }
    ESP_LOGI(TAG, "RMII pads released (no pulls, direction disabled).");
}

// ─────────────────────────────────────────────────────────────────────────────
// Event handlers
static void on_eth_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    switch (id) {
    case ETHERNET_EVENT_START:
        ESP_LOGI(TAG, "Ethernet STARTED");
        break;
    case ETHERNET_EVENT_CONNECTED:
        s_eth_link_up = true;
        ESP_LOGI(TAG, "Ethernet LINK UP");
        break;
    case ETHERNET_EVENT_DISCONNECTED:
        s_eth_link_up = false;
        ESP_LOGW(TAG, "Ethernet LINK DOWN");
        break;
    case ETHERNET_EVENT_STOP:
        ESP_LOGI(TAG, "Ethernet STOPPED");
        break;
    default:
        break;
    }
}

static void on_ip_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (id == IP_EVENT_ETH_GOT_IP && data) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)data;
        const esp_netif_ip_info_t *ip = &event->ip_info;
        ESP_LOGI(TAG, "Got IP: " IPSTR ", Mask: " IPSTR ", GW: " IPSTR,
                 IP2STR(&ip->ip), IP2STR(&ip->netmask), IP2STR(&ip->gw));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
esp_err_t eth_start(void)
{
    rmii_pins_release(); // IMPORTANTISSIMO: i pin RMII non devono avere pulls

    // Alimentazione PHY (power pin)
    gpio_config_t pwr = {
        .pin_bit_mask = 1ULL << ETH_POWER_GPIO,
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = 0,
        .pull_down_en = 0,
        .intr_type = GPIO_INTR_DISABLE
    };
    ESP_RETURN_ON_ERROR(gpio_config(&pwr), TAG, "gpio_config(power)");
    // power cycle breve
    gpio_set_level(ETH_POWER_GPIO, 0);
    vTaskDelay(pdMS_TO_TICKS(10));
    gpio_set_level(ETH_POWER_GPIO, 1);
    vTaskDelay(pdMS_TO_TICKS(10));

    // Init stack di rete e loop eventi (idempotente)
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_netif_init());
    esp_err_t __e = esp_event_loop_create_default();
    if (__e != ESP_OK && __e != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "esp_event_loop_create_default failed: %s", esp_err_to_name(__e));
        return __e;
    }   
    // Registra eventi (idempotente)
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, &on_eth_event, NULL));
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &on_ip_event, NULL));

    // --- MAC config (IDF 5.3 API) ---
    eth_mac_config_t mac_cfg = ETH_MAC_DEFAULT_CONFIG();
    eth_esp32_emac_config_t esp32_cfg = ETH_ESP32_EMAC_DEFAULT_CONFIG();

    // Priorità IRQ EMAC
    esp32_cfg.intr_priority = 2;

    // SMI (MDIO/MDC) — forma nuova
    esp32_cfg.smi_gpio.mdc_num  = ETH_MDC_GPIO;
    esp32_cfg.smi_gpio.mdio_num = ETH_MDIO_GPIO;

    // RMII clock: external 50MHz IN su GPIO0
    esp32_cfg.clock_config.rmii.clock_mode = EMAC_CLK_EXT_IN;
    esp32_cfg.clock_config.rmii.clock_gpio = ETH_RMII_CLK_IN_GPIO;

    esp_eth_mac_t *mac = esp_eth_mac_new_esp32(&esp32_cfg, &mac_cfg);
    if (!mac) {
        ESP_LOGE(TAG, "esp_eth_mac_new_esp32 failed");
        return ESP_FAIL;
    }

    // --- PHY config ---
    eth_phy_config_t phy_cfg = ETH_PHY_DEFAULT_CONFIG();
    phy_cfg.phy_addr       = ETH_PHY_ADDR;
    phy_cfg.reset_gpio_num = GPIO_NUM_NC; // nessun GPIO di reset dedicato

    // LAN8720/87xx
    esp_eth_phy_t *phy = esp_eth_phy_new_lan87xx(&phy_cfg);
    if (!phy) {
        ESP_LOGE(TAG, "esp_eth_phy_new_lan87xx failed");
        mac->del(mac);
        return ESP_FAIL;
    }

    // --- Driver ETH ---
    esp_eth_config_t eth_cfg = ETH_DEFAULT_CONFIG(mac, phy);
    ESP_RETURN_ON_ERROR(esp_eth_driver_install(&eth_cfg, &s_eth), TAG, "driver_install");

    // Crea la netif “a mano” per compatibilità ampia (invece del helper)
    esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_ETH();
    s_eth_netif = esp_netif_new(&netif_cfg);
    if (!s_eth_netif) {
        ESP_LOGE(TAG, "esp_netif_new failed");
        esp_eth_driver_uninstall(s_eth);
        s_eth = NULL;
        return ESP_FAIL;
    }

    // Collega driver ETH a netif (glue)
    s_glue = esp_eth_new_netif_glue(s_eth);
    if (!s_glue || esp_netif_attach(s_eth_netif, s_glue) != ESP_OK) {
        ESP_LOGE(TAG, "netif glue attach failed");
        if (s_glue) { esp_eth_del_netif_glue(s_glue); s_glue = NULL; }
        esp_netif_destroy(s_eth_netif); s_eth_netif = NULL;
        esp_eth_driver_uninstall(s_eth); s_eth = NULL;
        return ESP_FAIL;
    }

    // Avvio driver
    ESP_RETURN_ON_ERROR(esp_eth_start(s_eth), TAG, "esp_eth_start");

    ESP_LOGI(TAG, "Ethernet start: LAN8720 @ addr %d, MDC=%d MDIO=%d, CLK_IN=GPIO%d",
             ETH_PHY_ADDR, ETH_MDC_GPIO, ETH_MDIO_GPIO, ETH_RMII_CLK_IN_GPIO);
    return ESP_OK;
}

// ─────────────────────────────────────────────────────────────────────────────
void eth_stop(void)
{
    if (s_eth) {
        esp_eth_stop(s_eth);
        if (s_glue) {
            esp_eth_del_netif_glue(s_glue);
            s_glue = NULL;
        }
        if (s_eth_netif) {
            esp_netif_destroy(s_eth_netif);
            s_eth_netif = NULL;
        }
        esp_eth_driver_uninstall(s_eth);
        s_eth = NULL;
    }
    gpio_set_level(ETH_POWER_GPIO, 0);
    s_eth_link_up = false;
    ESP_LOGI(TAG, "Ethernet stopped");
}

// ─────────────────────────────────────────────────────────────────────────────
// Stato link dagli eventi + (opzionale) velocità
void eth_dump_link_once(void)
{
    if (!s_eth) {
        ESP_LOGW(TAG, "ETH handle not ready");
        return;
    }

    ESP_LOGI(TAG, "Link: %s", s_eth_link_up ? "UP" : "DOWN");

    // Lettura velocità solo se il comando è disponibile nella toolchain
#ifdef ETH_CMD_G_SPEED
    eth_speed_t sp = ETH_SPEED_10M;
    if (esp_eth_ioctl(s_eth, ETH_CMD_G_SPEED, &sp) == ESP_OK) {
        ESP_LOGI(TAG, "Speed: %s", (sp == ETH_SPEED_100M) ? "100M" : "10M");
    } else {
        ESP_LOGW(TAG, "Speed: unknown");
    }
#else
    ESP_LOGI(TAG, "Speed: (not available in this IDF build)");
#endif
}
