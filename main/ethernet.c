#include <string.h>
#include <stdio.h>
#include "pins.h"
#include "esp_check.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_netif_defaults.h"
#include "esp_eth.h"
#include "esp_eth_mac.h"
#include "esp_eth_phy.h"
#include "esp_eth_mac_esp.h"
#include "esp_eth_netif_glue.h"   // <-- necessario per esp_eth_set_default_handlers
#include "driver/gpio.h"
#include "esp_log.h"

// ---- Adatta questi define ai TUOI collegamenti ----
#define ETH_MDC_GPIO         GPIO_NUM_23
#define ETH_MDIO_GPIO        GPIO_NUM_18
#define ETH_REF_CLK_GPIO     GPIO_NUM_0      // 50MHz dal PHY (RMII REF_CLK in)
#define ETH_PHY_RST_GPIO     -1      // SE diverso o non cablato, cambia/usa -1
#define ETH_PHY_ADDR         1               // 0 o 1 sono i più frequenti
// ---------------------------------------------------

static const char* TAG = "eth";
static esp_eth_handle_t s_eth = NULL;
static esp_netif_t*     s_netif = NULL;

esp_err_t eth_start(void)
{
    // 0) Porta il PHY fuori reset PRIMA di installare il driver (serve il 50 MHz attivo)
#if (ETH_PHY_RST_GPIO >= 0)
    gpio_config_t io = {
        .pin_bit_mask = 1ULL << ETH_PHY_RST_GPIO,
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = 0, .pull_down_en = 0, .intr_type = GPIO_INTR_DISABLE
    };
    ESP_ERROR_CHECK(gpio_config(&io));
    gpio_set_level(ETH_PHY_RST_GPIO, 1);
    vTaskDelay(pdMS_TO_TICKS(100)); // attesa stabilizzazione REF_CLK
#endif

    // 1) netif una sola volta
    if (!s_netif) {
        esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_ETH();
        s_netif = esp_netif_new(&netif_cfg);
        ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ETHERNET_EVENT_START,        &esp_netif_action_start,        s_netif));
        ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ETHERNET_EVENT_STOP,         &esp_netif_action_stop,         s_netif));
        ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ETHERNET_EVENT_CONNECTED,    &esp_netif_action_connected,    s_netif));
        ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ETHERNET_EVENT_DISCONNECTED, &esp_netif_action_disconnected, s_netif));
        ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT,  IP_EVENT_ETH_GOT_IP,         &esp_netif_action_got_ip,       s_netif));
        ESP_RETURN_ON_FALSE(s_netif, ESP_FAIL, TAG, "esp_netif_new failed");
    }

    // 2) MAC + PHY
    eth_mac_config_t mac_cfg = ETH_MAC_DEFAULT_CONFIG();
    eth_phy_config_t phy_cfg = ETH_PHY_DEFAULT_CONFIG();

    phy_cfg.phy_addr       = ETH_PHY_ADDR;
    phy_cfg.reset_gpio_num = -1; // reset già gestito sopra (se hai RC hardware, lascia -1)

    eth_esp32_emac_config_t esp32_cfg = ETH_ESP32_EMAC_DEFAULT_CONFIG();
    esp32_cfg.smi_gpio.mdc_num  = ETH_MDC_GPIO;
    esp32_cfg.smi_gpio.mdio_num = ETH_MDIO_GPIO;

    // Clock RMII: 50 MHz esterno dal PHY su GPIO0
    esp32_cfg.clock_config.rmii.clock_mode = EMAC_CLK_EXT_IN;
    esp32_cfg.clock_config.rmii.clock_gpio = ETH_REF_CLK_GPIO;

    esp_eth_mac_t* mac = esp_eth_mac_new_esp32(&esp32_cfg, &mac_cfg);
    ESP_RETURN_ON_FALSE(mac, ESP_FAIL, TAG, "esp_eth_mac_new_esp32 failed");

    // Costruttore generico per LAN87xx (copre anche LAN8720)
    esp_eth_phy_t* phy = esp_eth_phy_new_lan87xx(&phy_cfg);
    ESP_RETURN_ON_FALSE(phy, ESP_FAIL, TAG, "esp_eth_phy_new_lan87xx failed");

    esp_eth_config_t eth_cfg = ETH_DEFAULT_CONFIG(mac, phy);
    if (esp_eth_driver_install(&eth_cfg, &s_eth) != ESP_OK) {
        ESP_LOGE(TAG, "Ethernet driver install failed");
        return ESP_FAIL;
    }

    // 3) glue + attach
    void* glue = esp_eth_new_netif_glue(s_eth);
    ESP_ERROR_CHECK(esp_netif_attach(s_netif, glue));
    ESP_ERROR_CHECK(esp_netif_set_hostname(s_netif, "esp32-alarm-pro"));

    // 4) start
    ESP_ERROR_CHECK(esp_eth_start(s_eth));
    ESP_LOGI(TAG, "Ethernet started");
    return ESP_OK;
}