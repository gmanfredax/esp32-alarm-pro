#include "ethernet.h"
#include <stdio.h>
#include <stddef.h>
#include "esp_log.h"
#include "esp_check.h"
#include "esp_event.h"

#include "esp_eth.h"
#include "esp_eth_mac.h"
#include "esp_eth_com.h"
#include "esp_eth_driver.h"
#include "esp_eth_mac_esp.h"
#include "esp_eth_phy.h"

#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "eth";

#define ETH_MDC_GPIO         GPIO_NUM_23
#define ETH_MDIO_GPIO        GPIO_NUM_18
#define ETH_POWER_GPIO       GPIO_NUM_17
#define ETH_PHY_ADDR         1
// RMII clock esterno a 50MHz su GPIO0 (come in ESPHome: clk_mode: GPIO0_IN)
#define ETH_RMII_CLK_IN_GPIO GPIO_NUM_0

static esp_eth_handle_t s_eth = NULL;

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

esp_err_t eth_start(void)
{
    rmii_pins_release(); // IMPORTANTISSIMO: lascia i pin RMII “puliti”
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

    // --- MAC config (IDF 5.3 API) ---
    eth_mac_config_t mac_cfg = ETH_MAC_DEFAULT_CONFIG();

    eth_esp32_emac_config_t esp32_cfg = ETH_ESP32_EMAC_DEFAULT_CONFIG();

    // ❗ Imposta una priorità “bassa/media” disponibile (prova 2, e se serve 1 o 3)
    esp32_cfg.intr_priority = 2;

    // NUOVO campo: usa smi_gpio invece dei campi deprecati
    esp32_cfg.smi_gpio.mdc_num  = ETH_MDC_GPIO;
    esp32_cfg.smi_gpio.mdio_num = ETH_MDIO_GPIO;
    
    // RMII clock: EXTERNAL IN su GPIO0
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

    // LAN8720 → costruttore generico LAN87xx
    esp_eth_phy_t *phy = esp_eth_phy_new_lan87xx(&phy_cfg);
    if (!phy) {
        ESP_LOGE(TAG, "esp_eth_phy_new_lan87xx failed");
        mac->del(mac);
        return ESP_FAIL;
    }

    // --- Driver ETH ---
    esp_eth_config_t eth_cfg = ETH_DEFAULT_CONFIG(mac, phy);
    ESP_RETURN_ON_ERROR(esp_eth_driver_install(&eth_cfg, &s_eth), TAG, "driver_install");

    // Avvio
    ESP_RETURN_ON_ERROR(esp_eth_start(s_eth), TAG, "esp_eth_start");

    ESP_LOGI(TAG, "Ethernet start: LAN8720 @ addr %d, MDC=%d MDIO=%d, CLK_IN=GPIO%d",
             ETH_PHY_ADDR, ETH_MDC_GPIO, ETH_MDIO_GPIO, ETH_RMII_CLK_IN_GPIO);
    return ESP_OK;
}

void eth_stop(void)
{
    if (s_eth) {
        esp_eth_stop(s_eth);
        esp_eth_driver_uninstall(s_eth);
        s_eth = NULL;
    }
    gpio_set_level(ETH_POWER_GPIO, 0);
}

void eth_dump_link_once(void) {
    bool link = false;
    if (s_eth && esp_eth_ioctl(s_eth, ETH_CMD_G_LINK, &link) == ESP_OK) {
        ESP_LOGI("eth", "Link status: %s", link ? "UP" : "DOWN");
    } else {
        ESP_LOGW("eth", "Link status: unknown (handle non pronto)");
    }
}
