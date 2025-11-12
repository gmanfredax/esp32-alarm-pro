// main/ethernet.c — Driver Ethernet per ESP32-S3 + W5500 (SPI)
#include "ethernet.h"

#include <stddef.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "driver/gpio.h"
#include "driver/spi_master.h"

#include "esp_check.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"

#include "esp_eth.h"
#include "esp_eth_com.h"
#include "esp_eth_driver.h"
#include "esp_eth_mac.h"
#include "esp_eth_netif_glue.h"
#include "esp_eth_phy.h"
#include "esp_idf_version.h"
#if __has_include("esp_eth_mac_w5500.h")
  #include "esp_eth_mac_w5500.h"
#else
  esp_eth_mac_t *esp_eth_mac_new_w5500(const eth_w5500_config_t *w5500_config,
                                       const eth_mac_config_t *mac_config);
#endif
#if __has_include("esp_eth_phy_w5500.h")
  #include "esp_eth_phy_w5500.h"
#else
  esp_eth_phy_t *esp_eth_phy_new_w5500(const eth_phy_config_t *phy_config);
#endif

#include "pins.h"

static const char *TAG = "eth";
static bool s_gpio_isr_service_installed = false;

static spi_device_handle_t             s_w5500_spi    = NULL;
static spi_device_interface_config_t   s_w5500_devcfg = {0};
static int                             s_w5500_active_clock_hz = ETH_W5500_SPI_CLOCK_HZ;
static esp_eth_handle_t                s_eth          = NULL;
static esp_netif_t                    *s_eth_netif    = NULL;
static esp_eth_netif_glue_handle_t     s_glue         = NULL;
static EventGroupHandle_t              s_event_group  = NULL;
static volatile bool                   s_link_up      = false;

#define ETH_EVENT_BIT_GOT_IP  BIT0

static void w5500_hw_reset_sequence(uint32_t assert_ms, uint32_t post_ms)
{
    if (ETH_W5500_RST_GPIO < 0) {
        if (post_ms) {
            vTaskDelay(pdMS_TO_TICKS(post_ms));
        }
        return;
    }

    gpio_set_level(ETH_W5500_RST_GPIO, 0);
    if (assert_ms) {
        vTaskDelay(pdMS_TO_TICKS(assert_ms));
    }
    gpio_set_level(ETH_W5500_RST_GPIO, 1);
    if (post_ms) {
        vTaskDelay(pdMS_TO_TICKS(post_ms));
    }
}

static esp_err_t ensure_gpio_isr_service(void)
{
    if (s_gpio_isr_service_installed) {
        return ESP_OK;
    }

    esp_err_t err = gpio_install_isr_service(0);
    if (err == ESP_ERR_INVALID_STATE) {
        // ISR service already installed elsewhere.
        s_gpio_isr_service_installed = true;
        return ESP_OK;
    }
    ESP_RETURN_ON_ERROR(err, TAG, "gpio isr service");

    s_gpio_isr_service_installed = true;
    return ESP_OK;
}

static esp_err_t w5500_bus_init(void)
{
    if (s_w5500_spi) {
        return ESP_OK;
    }

    spi_bus_config_t buscfg = {
        .mosi_io_num = ETH_W5500_PIN_MOSI,
        .miso_io_num = ETH_W5500_PIN_MISO,
        .sclk_io_num = ETH_W5500_PIN_SCLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 0,
        .flags = 0,
        .intr_flags = 0,
    };

    ESP_RETURN_ON_ERROR(ensure_gpio_isr_service(), TAG, "install isr service");

    esp_err_t err = spi_bus_initialize(ETH_W5500_SPI_HOST, &buscfg, SPI_DMA_CH_AUTO);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "spi_bus_initialize failed: %s", esp_err_to_name(err));
        return err;
    }

    s_w5500_devcfg = (spi_device_interface_config_t) {
        .command_bits = 16,
        .address_bits = 8,
        .dummy_bits = 0,
        .mode = 0,
        .clock_speed_hz = ETH_W5500_SPI_CLOCK_HZ,
        .spics_io_num = ETH_W5500_PIN_CS,
        // Il driver ufficiale del W5500 effettua transazioni full-duplex:
        // impostare HALFDUPLEX causa "spi transmit failed" durante il reset.
        .flags = 0,
        .queue_size = ETH_W5500_SPI_QUEUE_LEN,
        .input_delay_ns = 50,
        .cs_ena_posttrans = 2,
        .cs_ena_pretrans = 2,
    };
    s_w5500_active_clock_hz = ETH_W5500_SPI_CLOCK_HZ;
    s_w5500_spi = NULL;

    gpio_config_t int_gpio = {
        .pin_bit_mask = 1ULL << ETH_W5500_INT_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    ESP_ERROR_CHECK_WITHOUT_ABORT(gpio_config(&int_gpio));

    if (ETH_W5500_RST_GPIO >= 0) {
        gpio_config_t rst_gpio = {
            .pin_bit_mask = 1ULL << ETH_W5500_RST_GPIO,
            .mode = GPIO_MODE_OUTPUT,
            .pull_up_en = GPIO_PULLUP_DISABLE,
            .pull_down_en = GPIO_PULLDOWN_DISABLE,
            .intr_type = GPIO_INTR_DISABLE,
        };
        ESP_ERROR_CHECK_WITHOUT_ABORT(gpio_config(&rst_gpio));
        w5500_hw_reset_sequence(ETH_W5500_RST_ASSERT_MS, ETH_W5500_RST_POST_MS);
    }

    return ESP_OK;
}

static void w5500_bus_deinit(void)
{
    if (s_w5500_spi) {
        spi_bus_remove_device(s_w5500_spi);
        s_w5500_spi = NULL;
    }
    esp_err_t err = spi_bus_free(ETH_W5500_SPI_HOST);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGW(TAG, "spi_bus_free: %s", esp_err_to_name(err));
    }
}

static void on_eth_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    switch (id) {
    case ETHERNET_EVENT_START:
        ESP_LOGI(TAG, "Ethernet STARTED");
        break;
    case ETHERNET_EVENT_CONNECTED:
        s_link_up = true;
        ESP_LOGI(TAG, "Ethernet LINK UP");
        break;
    case ETHERNET_EVENT_DISCONNECTED:
        s_link_up = false;
        if (s_event_group) {
            xEventGroupClearBits(s_event_group, ETH_EVENT_BIT_GOT_IP);
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
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)data;
        const esp_netif_ip_info_t *ip = &event->ip_info;
        ESP_LOGI(TAG, "Got IP: " IPSTR ", Mask: " IPSTR ", GW: " IPSTR,
                 IP2STR(&ip->ip), IP2STR(&ip->netmask), IP2STR(&ip->gw));
        if (s_event_group) {
            xEventGroupSetBits(s_event_group, ETH_EVENT_BIT_GOT_IP);
        }
    }
}

esp_err_t eth_start(void)
{
    ESP_RETURN_ON_ERROR(w5500_bus_init(), TAG, "bus init");

    if (!s_event_group) {
        s_event_group = xEventGroupCreate();
        ESP_RETURN_ON_FALSE(s_event_group != NULL, ESP_ERR_NO_MEM, TAG, "event group");
    }
    xEventGroupClearBits(s_event_group, ETH_EVENT_BIT_GOT_IP);

    ESP_RETURN_ON_ERROR(esp_netif_init(), TAG, "netif init");
    esp_err_t err = esp_event_loop_create_default();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "esp_event_loop_create_default: %s", esp_err_to_name(err));
        return err;
    }
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, &on_eth_event, NULL));
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &on_ip_event, NULL));

    const int desired_clock_hz = ETH_W5500_SPI_CLOCK_HZ;
    const int fallback_clock_hz = ETH_W5500_SPI_SAFE_CLOCK_HZ;
    const int min_clock_hz = ETH_W5500_SPI_MIN_CLOCK_HZ > 0 ? ETH_W5500_SPI_MIN_CLOCK_HZ : 0;
    int clock_candidates[6] = {0};
    size_t candidate_count = 0;

    if (desired_clock_hz > 0) {
        clock_candidates[candidate_count++] = desired_clock_hz;
    }
    int pending_clock = -1;
    bool fallback_added = false;
    while (candidate_count > 0 &&
           candidate_count < (sizeof(clock_candidates) / sizeof(clock_candidates[0]))) {
        int next_clock = -1;
        if (pending_clock > 0) {
            next_clock = pending_clock;
            pending_clock = -1;
        } else {
            int last_clock = clock_candidates[candidate_count - 1];
            if (last_clock <= 0) {
                break;
            }
            int halved_clock = last_clock / 2;
            if (min_clock_hz > 0 && min_clock_hz < last_clock && halved_clock < min_clock_hz) {
                halved_clock = min_clock_hz;
            }
            if (halved_clock <= 0 || halved_clock == last_clock) {
                break;
            }
            if (!fallback_added && fallback_clock_hz > 0 && fallback_clock_hz < last_clock &&
                fallback_clock_hz > halved_clock) {
                next_clock = fallback_clock_hz;
                pending_clock = halved_clock;
            } else {
                next_clock = halved_clock;
            }
        }

        bool duplicate = false;
        for (size_t i = 0; i < candidate_count; ++i) {
            if (clock_candidates[i] == next_clock) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) {
            continue;
        }
        clock_candidates[candidate_count++] = next_clock;
        if (next_clock == fallback_clock_hz) {
            fallback_added = true;
        }
        if (next_clock == min_clock_hz) {
            break;
        }
    }

    if (candidate_count == 0) {
        ESP_LOGE(TAG, "Nessuna frequenza SPI valida configurata per il W5500");
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t driver_err = ESP_FAIL;
    esp_eth_mac_t *mac = NULL;
    esp_eth_phy_t *phy = NULL;
    size_t attempt = 0;

    for (; attempt < candidate_count; ++attempt) {
        const int clock_hz = clock_candidates[attempt];
        s_w5500_devcfg.clock_speed_hz = clock_hz;
        s_w5500_active_clock_hz = clock_hz;

        if (attempt > 0) {
            ESP_LOGW(TAG, "Nuovo tentativo di inizializzazione W5500 a %d Hz", clock_hz);
            w5500_hw_reset_sequence(ETH_W5500_RST_ASSERT_MS, ETH_W5500_RST_POST_MS);
            if (ETH_W5500_RETRY_DELAY_MS > 0) {
                vTaskDelay(pdMS_TO_TICKS(ETH_W5500_RETRY_DELAY_MS));
            }
        }

#if (ESP_IDF_VERSION_MAJOR < 5) || (ESP_IDF_VERSION_MAJOR == 5 && ESP_IDF_VERSION_MINOR == 0)
        if (s_w5500_spi) {
            spi_bus_remove_device(s_w5500_spi);
            s_w5500_spi = NULL;
        }
        esp_err_t add_err = spi_bus_add_device(ETH_W5500_SPI_HOST, &s_w5500_devcfg, &s_w5500_spi);
        if (add_err != ESP_OK) {
            ESP_LOGE(TAG, "spi_bus_add_device failed: %s", esp_err_to_name(add_err));
            return add_err;
        }
#endif

        eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
        mac_config.sw_reset_timeout_ms = ETH_W5500_SW_RESET_TIMEOUT_MS;
        eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
        phy_config.phy_addr = 0;
        phy_config.reset_gpio_num = ETH_W5500_RST_GPIO;

#if defined(ETH_W5500_DEFAULT_CONFIG) && defined(ESP_IDF_VERSION) && defined(ESP_IDF_VERSION_VAL) && \
    (ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 1, 0))
        eth_w5500_config_t w5500_config = ETH_W5500_DEFAULT_CONFIG(ETH_W5500_SPI_HOST, &s_w5500_devcfg);
#elif defined(ETH_W5500_DEFAULT_CONFIG)
        eth_w5500_config_t w5500_config = ETH_W5500_DEFAULT_CONFIG(s_w5500_spi);
#else
        eth_w5500_config_t w5500_config = (eth_w5500_config_t){0};
        w5500_config.spi_handle = s_w5500_spi;
#endif
#if (ESP_IDF_VERSION_MAJOR < 5) || (ESP_IDF_VERSION_MAJOR == 5 && ESP_IDF_VERSION_MINOR == 0)
        w5500_config.spi_handle = s_w5500_spi;
#endif
        w5500_config.int_gpio_num = ETH_W5500_INT_GPIO;

        mac = esp_eth_mac_new_w5500(&w5500_config, &mac_config);
        if (!mac) {
            ESP_LOGE(TAG, "mac new failed");
#if (ESP_IDF_VERSION_MAJOR < 5) || (ESP_IDF_VERSION_MAJOR == 5 && ESP_IDF_VERSION_MINOR == 0)
            if (s_w5500_spi) {
                spi_bus_remove_device(s_w5500_spi);
                s_w5500_spi = NULL;
            }
#endif
            driver_err = ESP_ERR_NO_MEM;
            break;
        }

        phy = esp_eth_phy_new_w5500(&phy_config);
        if (!phy) {
            mac->del(mac);
            mac = NULL;
            ESP_LOGE(TAG, "phy new failed");
            driver_err = ESP_ERR_NO_MEM;
#if (ESP_IDF_VERSION_MAJOR < 5) || (ESP_IDF_VERSION_MAJOR == 5 && ESP_IDF_VERSION_MINOR == 0)
            s_w5500_spi = NULL;
#endif
            break;
        }

        esp_eth_config_t eth_config = ETH_DEFAULT_CONFIG(mac, phy);
        driver_err = esp_eth_driver_install(&eth_config, &s_eth);
        if (driver_err == ESP_OK) {
#if (ESP_IDF_VERSION_MAJOR < 5) || (ESP_IDF_VERSION_MAJOR == 5 && ESP_IDF_VERSION_MINOR == 0)
            s_w5500_spi = NULL;
#endif
            break;
        }

        phy->del(phy);
        phy = NULL;
        mac->del(mac);
        mac = NULL;
#if (ESP_IDF_VERSION_MAJOR < 5) || (ESP_IDF_VERSION_MAJOR == 5 && ESP_IDF_VERSION_MINOR == 0)
        s_w5500_spi = NULL;
#endif

        if (driver_err == ESP_ERR_INVALID_VERSION && attempt + 1 < candidate_count) {
            const int next_clock = clock_candidates[attempt + 1];
            ESP_LOGW(TAG, "W5500 version check failed a %d Hz, riprovo a %d Hz", clock_hz, next_clock);
            continue;
        }

        ESP_LOGE(TAG, "driver install failed: %s", esp_err_to_name(driver_err));
        return driver_err;
    }

    if (driver_err != ESP_OK) {
        w5500_bus_deinit();
        return driver_err;
    }

    if (attempt > 0) {
        ESP_LOGW(TAG, "W5500 SPI clock ridotto a %d Hz dopo %zu tentativi", s_w5500_active_clock_hz, attempt + 1);
    }

    esp_netif_config_t netif_config = ESP_NETIF_DEFAULT_ETH();
    s_eth_netif = esp_netif_new(&netif_config);
    if (!s_eth_netif) {
        ESP_LOGE(TAG, "esp_netif_new failed");
        esp_eth_driver_uninstall(s_eth);
        s_eth = NULL;
        phy->del(phy);
        mac->del(mac);
#if (ESP_IDF_VERSION_MAJOR < 5) || (ESP_IDF_VERSION_MAJOR == 5 && ESP_IDF_VERSION_MINOR == 0)
        s_w5500_spi = NULL;
#endif
        return ESP_ERR_NO_MEM;
    }

    s_glue = esp_eth_new_netif_glue(s_eth);
    if (!s_glue || esp_netif_attach(s_eth_netif, s_glue) != ESP_OK) {
        ESP_LOGE(TAG, "netif attach failed");
        if (s_glue) {
            esp_eth_del_netif_glue(s_glue);
            s_glue = NULL;
        }
        esp_netif_destroy(s_eth_netif);
        s_eth_netif = NULL;
        esp_eth_driver_uninstall(s_eth);
        s_eth = NULL;
#if (ESP_IDF_VERSION_MAJOR < 5) || (ESP_IDF_VERSION_MAJOR == 5 && ESP_IDF_VERSION_MINOR == 0)
        s_w5500_spi = NULL;
#endif
        return ESP_FAIL;
    }

    ESP_RETURN_ON_ERROR(esp_eth_start(s_eth), TAG, "eth start");

    ESP_LOGI(TAG, "Ethernet start: W5500 SPI@%dHz CS=%d INT=%d RST=%d",
             s_w5500_active_clock_hz, ETH_W5500_PIN_CS, ETH_W5500_INT_GPIO, ETH_W5500_RST_GPIO);
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
#if (ESP_IDF_VERSION_MAJOR < 5) || (ESP_IDF_VERSION_MAJOR == 5 && ESP_IDF_VERSION_MINOR == 0)
        s_w5500_spi = NULL;
#endif
    }
    s_link_up = false;
    if (s_event_group) {
        xEventGroupClearBits(s_event_group, ETH_EVENT_BIT_GOT_IP);
    }
    w5500_bus_deinit();
    ESP_LOGI(TAG, "Ethernet stopped");
}

void eth_dump_link_once(void)
{
    if (!s_eth) {
        ESP_LOGW(TAG, "ETH handle not ready");
        return;
    }

    ESP_LOGI(TAG, "Link: %s", s_link_up ? "UP" : "DOWN");

    eth_duplex_t duplex = ETH_DUPLEX_HALF;
    if (esp_eth_ioctl(s_eth, ETH_CMD_G_DUPLEX_MODE, &duplex) == ESP_OK) {
        ESP_LOGI(TAG, "Duplex: %s", duplex == ETH_DUPLEX_FULL ? "FULL" : "HALF");
    }
    eth_speed_t speed = ETH_SPEED_10M;
    if (esp_eth_ioctl(s_eth, ETH_CMD_G_SPEED, &speed) == ESP_OK) {
        ESP_LOGI(TAG, "Speed: %s", speed == ETH_SPEED_100M ? "100M" : "10M");
    }
}

esp_netif_t* eth_get_netif(void)
{
    return s_eth_netif;
}

esp_err_t eth_wait_for_ip(TickType_t timeout)
{
    if (!s_event_group) {
        return ESP_ERR_INVALID_STATE;
    }
    EventBits_t bits = xEventGroupWaitBits(s_event_group,
                                           ETH_EVENT_BIT_GOT_IP,
                                           pdFALSE,
                                           pdTRUE,
                                           timeout);
    if (bits & ETH_EVENT_BIT_GOT_IP) {
        return ESP_OK;
    }
    return ESP_ERR_TIMEOUT;
}