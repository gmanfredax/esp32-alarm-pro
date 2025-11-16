// main/ethernet.c — ESP32-P4NRW32 + IP101GRI RMII configuration
#include "ethernet.h"

#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "driver/gpio.h"

#include "esp_check.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"

#include "esp_eth.h"
#include "esp_eth_com.h"
#include "esp_eth_driver.h"
#include "esp_eth_mac.h"
#include "esp_eth_mac_esp.h"
#include "esp_eth_netif_glue.h"
#include "esp_eth_phy.h"

#include "pins.h"

static const char *TAG = "eth";

static esp_eth_handle_t s_eth = NULL;
static esp_netif_t *s_eth_netif = NULL;
static esp_eth_netif_glue_handle_t s_glue = NULL;
static EventGroupHandle_t s_eth_event_group = NULL;
static volatile bool s_eth_link_up = false;

#define ETH_EVENT_BIT_GOT_IP BIT0

static void rmii_pins_release(void)
{
    const gpio_num_t rmii_pins[] = {
        (gpio_num_t)ETH_RMII_REF_CLK_GPIO,
        (gpio_num_t)ETH_RMII_TX_EN_GPIO,
        (gpio_num_t)ETH_RMII_TXD0_GPIO,
        (gpio_num_t)ETH_RMII_TXD1_GPIO,
        (gpio_num_t)ETH_RMII_CRS_DV_GPIO,
        (gpio_num_t)ETH_RMII_RXD0_GPIO,
        (gpio_num_t)ETH_RMII_RXD1_GPIO,
        (gpio_num_t)ETH_MDC_GPIO,
        (gpio_num_t)ETH_MDIO_GPIO
    };

    for (size_t i = 0; i < sizeof(rmii_pins) / sizeof(rmii_pins[0]); ++i) {
        if (rmii_pins[i] < 0) {
            continue;
        }
        gpio_pullup_dis(rmii_pins[i]);
        gpio_pulldown_dis(rmii_pins[i]);
        gpio_set_direction(rmii_pins[i], GPIO_MODE_DISABLE);
    }
    ESP_LOGI(TAG, "RMII/I2C pads released (pulls disabled)");
}

static void phy_reset_pulse(void)
{
    if (ETH_PHY_RST_GPIO < 0) {
        return;
    }
    gpio_config_t rst = {
        .pin_bit_mask = 1ULL << ETH_PHY_RST_GPIO,
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    ESP_ERROR_CHECK(gpio_config(&rst));
    gpio_set_level(ETH_PHY_RST_GPIO, 0);
    vTaskDelay(pdMS_TO_TICKS(10));
    gpio_set_level(ETH_PHY_RST_GPIO, 1);
    vTaskDelay(pdMS_TO_TICKS(10));
}

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
        if (s_eth_event_group) {
            xEventGroupClearBits(s_eth_event_group, ETH_EVENT_BIT_GOT_IP);
        }
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
        const ip_event_got_ip_t *event = (const ip_event_got_ip_t *)data;
        const esp_netif_ip_info_t *ip = &event->ip_info;
        ESP_LOGI(TAG, "Got IP: " IPSTR ", Mask: " IPSTR ", GW: " IPSTR,
                 IP2STR(&ip->ip), IP2STR(&ip->netmask), IP2STR(&ip->gw));
        if (s_eth_event_group) {
            xEventGroupSetBits(s_eth_event_group, ETH_EVENT_BIT_GOT_IP);
        }
    }
}

esp_err_t eth_start(void)
{
    rmii_pins_release();
    phy_reset_pulse();

    if (!s_eth_event_group) {
        s_eth_event_group = xEventGroupCreate();
        if (!s_eth_event_group) {
            ESP_LOGE(TAG, "Failed to create Ethernet event group");
            return ESP_ERR_NO_MEM;
        }
    }
    xEventGroupClearBits(s_eth_event_group, ETH_EVENT_BIT_GOT_IP);

    ESP_RETURN_ON_ERROR(esp_netif_init(), TAG, "netif init");

    esp_err_t err = esp_event_loop_create_default();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "esp_event_loop_create_default failed: %s", esp_err_to_name(err));
        return err;
    }
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, &on_eth_event, NULL));
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &on_ip_event, NULL));

    eth_mac_config_t mac_cfg = ETH_MAC_DEFAULT_CONFIG();
    eth_esp32_emac_config_t esp32_cfg = ETH_ESP32_EMAC_DEFAULT_CONFIG();

    esp32_cfg.interface = EMAC_DATA_INTERFACE_RMII;
    esp32_cfg.smi_gpio.mdc_num  = ETH_MDC_GPIO;
    esp32_cfg.smi_gpio.mdio_num = ETH_MDIO_GPIO;
    esp32_cfg.clock_config.rmii.clock_mode = EMAC_CLK_EXT_IN;
    esp32_cfg.clock_config.rmii.clock_gpio = ETH_RMII_REF_CLK_GPIO;
    esp32_cfg.emac_dataif_gpio.rmii.tx_en_num  = ETH_RMII_TX_EN_GPIO;
    esp32_cfg.emac_dataif_gpio.rmii.txd0_num    = ETH_RMII_TXD0_GPIO;
    esp32_cfg.emac_dataif_gpio.rmii.txd1_num    = ETH_RMII_TXD1_GPIO;
    esp32_cfg.emac_dataif_gpio.rmii.crs_dv_num  = ETH_RMII_CRS_DV_GPIO;
    esp32_cfg.emac_dataif_gpio.rmii.rxd0_num    = ETH_RMII_RXD0_GPIO;
    esp32_cfg.emac_dataif_gpio.rmii.rxd1_num    = ETH_RMII_RXD1_GPIO;
    esp32_cfg.intr_priority = 2;

    esp_eth_mac_t *mac = esp_eth_mac_new_esp32(&esp32_cfg, &mac_cfg);
    if (!mac) {
        ESP_LOGE(TAG, "esp_eth_mac_new_esp32 failed");
        return ESP_FAIL;
    }

    eth_phy_config_t phy_cfg = ETH_PHY_DEFAULT_CONFIG();
    phy_cfg.phy_addr = ETH_PHY_ADDR;
    phy_cfg.reset_gpio_num = ETH_PHY_RST_GPIO;

    esp_eth_phy_t *phy = esp_eth_phy_new_ip101(&phy_cfg);
    if (!phy) {
        ESP_LOGE(TAG, "esp_eth_phy_new_ip101 failed");
        mac->del(mac);
        return ESP_FAIL;
    }

    esp_eth_config_t eth_cfg = ETH_DEFAULT_CONFIG(mac, phy);
    ESP_RETURN_ON_ERROR(esp_eth_driver_install(&eth_cfg, &s_eth), TAG, "driver install");

    esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_ETH();
    s_eth_netif = esp_netif_new(&netif_cfg);
    if (!s_eth_netif) {
        ESP_LOGE(TAG, "esp_netif_new failed");
        esp_eth_driver_uninstall(s_eth);
        s_eth = NULL;
        return ESP_FAIL;
    }

    s_glue = esp_eth_new_netif_glue(s_eth);
    if (!s_glue || esp_netif_attach(s_eth_netif, s_glue) != ESP_OK) {
        ESP_LOGE(TAG, "netif glue attach failed");
        if (s_glue) {
            esp_eth_del_netif_glue(s_glue);
        }
        esp_netif_destroy(s_eth_netif);
        s_eth_netif = NULL;
        esp_eth_driver_uninstall(s_eth);
        s_eth = NULL;
        return ESP_FAIL;
    }

    ESP_RETURN_ON_ERROR(esp_eth_start(s_eth), TAG, "esp_eth_start");
    ESP_LOGI(TAG, "Ethernet start: IP101GRI addr %d, MDC=%d MDIO=%d, REF_CLK=GPIO%d",
             ETH_PHY_ADDR, ETH_MDC_GPIO, ETH_MDIO_GPIO, ETH_RMII_REF_CLK_GPIO);
    return ESP_OK;
}

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
    if (ETH_PHY_RST_GPIO >= 0) {
        gpio_set_level(ETH_PHY_RST_GPIO, 0);
    }
    s_eth_link_up = false;
    if (s_eth_event_group) {
        xEventGroupClearBits(s_eth_event_group, ETH_EVENT_BIT_GOT_IP);
    }
    ESP_LOGI(TAG, "Ethernet stopped");
}

void eth_dump_link_once(void)
{
    if (!s_eth) {
        ESP_LOGW(TAG, "ETH handle not ready");
        return;
    }
    ESP_LOGI(TAG, "Link: %s", s_eth_link_up ? "UP" : "DOWN");
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

esp_netif_t *eth_get_netif(void)
{
    return s_eth_netif;
}

esp_err_t eth_wait_for_ip(TickType_t timeout)
{
    if (!s_eth_event_group) {
        return ESP_ERR_INVALID_STATE;
    }
    EventBits_t bits = xEventGroupWaitBits(s_eth_event_group, ETH_EVENT_BIT_GOT_IP, pdFALSE, pdTRUE, timeout);
    if (bits & ETH_EVENT_BIT_GOT_IP) {
        return ESP_OK;
    }
    return ESP_ERR_TIMEOUT;
}