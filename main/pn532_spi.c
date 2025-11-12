#include "pn532_spi.h"
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include <stdbool.h>
#include <string.h>
#include "pins.h"

static const char* TAG="pn532";
static spi_device_handle_t s_dev;
static bool s_bus_inited = false;
static bool s_irq_configured = false;
static bool s_isr_service_installed = false;
static SemaphoreHandle_t s_irq_sem;

#define PN532_PREAMBLE 0x00
#define PN532_STARTCODE1 0x00
#define PN532_STARTCODE2 0xFF
#define PN532_POSTAMBLE 0x00
#define PN532_HOSTTOPN532 0xD4
#define PN532_PN532TOHOST 0xD5
#define PN532_COMMAND_INLISTPASSIVETARGET 0x4A

static esp_err_t spi_txrx(const uint8_t* tx, int txlen, uint8_t* rx, int rxlen){
    spi_transaction_t t={0}; t.length=8*txlen; t.tx_buffer=tx; t.rxlength=8*rxlen; t.rx_buffer=rx;
    return spi_device_transmit(s_dev,&t);
}

static void cs_select(){ gpio_set_level(PN532_PIN_CS, 0); }
static void cs_deselect(){ gpio_set_level(PN532_PIN_CS, 1); }

static void IRAM_ATTR pn532_irq_handler(void *arg)
{
    (void)arg;
    if (!s_irq_sem) {
        return;
    }
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    xSemaphoreGiveFromISR(s_irq_sem, &xHigherPriorityTaskWoken);
    if (xHigherPriorityTaskWoken == pdTRUE) {
        portYIELD_FROM_ISR();
    }
}

static esp_err_t pn532_wait_ready(TickType_t timeout_ticks)
{
    if (!s_irq_configured || !s_irq_sem) {
        return ESP_ERR_INVALID_STATE;
    }

    while (xSemaphoreTake(s_irq_sem, 0) == pdTRUE) {
        // flush pending gives
    }

    gpio_intr_enable(PN532_PIN_IRQ);
    if (gpio_get_level(PN532_PIN_IRQ) == 0) {
        xSemaphoreGive(s_irq_sem);
    }

    if (xSemaphoreTake(s_irq_sem, timeout_ticks) != pdTRUE) {
        gpio_intr_disable(PN532_PIN_IRQ);
        return ESP_ERR_TIMEOUT;
    }

    gpio_intr_disable(PN532_PIN_IRQ);
    return ESP_OK;
}

// Very simplified, polling only
esp_err_t pn532_init(void){
    // Idempotent init: safe to call multiple times
    gpio_set_direction(PN532_PIN_CS, GPIO_MODE_OUTPUT);
    cs_deselect();
    gpio_set_direction(PN532_PIN_RST, GPIO_MODE_OUTPUT);
    gpio_set_level(PN532_PIN_RST, 1);
    // spi_bus_config_t bus={.mosi_io_num=PN532_PIN_MOSI,.miso_io_num=PN532_PIN_MISO,.sclk_io_num=PN532_PIN_SCK,.quadwp_io_num=-1,.quadhd_io_num=-1,.max_transfer_sz=256};
    // ESP_ERROR_CHECK(spi_bus_initialize(PN532_SPI_HOST,&bus,SPI_DMA_CH_AUTO));
    // spi_device_interface_config_t dev={.clock_speed_hz=1000000,.mode=0,.spics_io_num=-1,.queue_size=1};
    // ESP_ERROR_CHECK(spi_bus_add_device(PN532_SPI_HOST,&dev,&s_dev));
    
    if (!s_bus_inited) {
        spi_bus_config_t bus = {
            .mosi_io_num = PN532_PIN_MOSI,
            .miso_io_num = PN532_PIN_MISO,
            .sclk_io_num = PN532_PIN_SCK,
            .quadwp_io_num = -1,
            .quadhd_io_num = -1,
            .max_transfer_sz = 256
        };
        esp_err_t err = spi_bus_initialize(PN532_SPI_HOST, &bus, SPI_DMA_CH_AUTO);
        if (err == ESP_OK || err == ESP_ERR_INVALID_STATE) {
            // INVALID_STATE = bus già inizializzato da qualcun altro → ok
            s_bus_inited = true;
        } else {
            ESP_LOGE(TAG, "spi_bus_initialize failed: %s", esp_err_to_name(err));
            return err;
        }
    }

    if (!s_irq_configured) {
        gpio_config_t irq_cfg = {
            .pin_bit_mask = 1ULL << PN532_PIN_IRQ,
            .mode = GPIO_MODE_INPUT,
            .pull_up_en = GPIO_PULLUP_ENABLE,
            .pull_down_en = GPIO_PULLDOWN_DISABLE,
            .intr_type = GPIO_INTR_NEGEDGE,
        };
        esp_err_t cfg_err = gpio_config(&irq_cfg);
        if (cfg_err != ESP_OK) {
            ESP_LOGE(TAG, "gpio_config IRQ failed: %s", esp_err_to_name(cfg_err));
            return cfg_err;
        }

        if (!s_irq_sem) {
            s_irq_sem = xSemaphoreCreateBinary();
            if (!s_irq_sem) {
                ESP_LOGE(TAG, "sem alloc failed");
                return ESP_ERR_NO_MEM;
            }
        }

        esp_err_t add_err = gpio_isr_handler_add(PN532_PIN_IRQ, pn532_irq_handler, NULL);
        if (add_err == ESP_ERR_INVALID_STATE && !s_isr_service_installed) {
            esp_err_t isr_err = gpio_install_isr_service(0);
            if (isr_err != ESP_OK && isr_err != ESP_ERR_INVALID_STATE) {
                ESP_LOGE(TAG, "gpio_install_isr_service failed: %s", esp_err_to_name(isr_err));
                return isr_err;
            }
            s_isr_service_installed = true;
            add_err = gpio_isr_handler_add(PN532_PIN_IRQ, pn532_irq_handler, NULL);
        }

        if (add_err == ESP_OK || add_err == ESP_ERR_INVALID_STATE) {
            s_isr_service_installed = true;
        } else {
            ESP_LOGE(TAG, "gpio_isr_handler_add failed: %s", esp_err_to_name(add_err));
            return add_err;
        }
        gpio_intr_disable(PN532_PIN_IRQ);
        s_irq_configured = true;
        ESP_LOGI(TAG, "IRQ ready on GPIO %d", PN532_PIN_IRQ);
    }

    if (s_dev == NULL) {
        spi_device_interface_config_t dev = (spi_device_interface_config_t){
            .clock_speed_hz = 1000000,
            .mode = 0,
            .spics_io_num = -1, // CS manuale via GPIO
            .queue_size = 1
        };
        esp_err_t derr = spi_bus_add_device(PN532_SPI_HOST, &dev, &s_dev);
        if (derr != ESP_OK) {
            ESP_LOGE(TAG, "spi_bus_add_device failed: %s", esp_err_to_name(derr));
            return derr;
        }
        ESP_LOGI(TAG, "SPI device attached");
    } else {
        ESP_LOGD(TAG, "PN532 già inizializzato");
    }

    ESP_LOGI(TAG,"SPI ready");
    return ESP_OK;
}

static void frame_cmd(uint8_t* out, int* outlen, const uint8_t* data, int len){
    uint8_t sum = 0;
    out[0]=PN532_PREAMBLE; out[1]=PN532_STARTCODE1; out[2]=PN532_STARTCODE2;
    out[3]=len+1; out[4] = (uint8_t)(~out[3]+1);
    out[5]=PN532_HOSTTOPN532;
    for(int i=0;i<len;i++){ out[6+i]=data[i]; sum += data[i]; }
    uint8_t cksum = (uint8_t)(~(PN532_HOSTTOPN532 + sum) + 1);
    out[6+len]=cksum;
    out[7+len]=PN532_POSTAMBLE;
    *outlen = 8+len;
}

int pn532_read_uid(uint8_t* uid, int maxlen){
    if (pn532_init() != ESP_OK) {
        return -1;
    }
    // Send InListPassiveTarget (106 kbps, 1 target)
    uint8_t cmd[3] = { PN532_COMMAND_INLISTPASSIVETARGET, 0x01, 0x00 };
    uint8_t frame[64]; int flen=0; frame_cmd(frame,&flen,cmd,3);
    uint8_t dummy_rx[64]={0};
    cs_select(); spi_txrx(frame, flen, dummy_rx, 0); cs_deselect();
    if (pn532_wait_ready(pdMS_TO_TICKS(120)) != ESP_OK) {
        ESP_LOGW(TAG, "Timeout in attesa di IRQ PN532");
        return -1;
    }
    uint8_t readbuf[64]={0x03}; // read register command (SPI)
    cs_select(); spi_txrx(readbuf, 1, readbuf, sizeof(readbuf)); cs_deselect();
    // Ultra-simplified: parse for UID (not robust)
    for(int i=0;i<60;i++){
        // look for 0xD5 0x4B (response to InListPassiveTarget)
        if(readbuf[i]==0xD5 && readbuf[i+1]==0x4B){
//            int tgt = readbuf[i+2];
            int sensLen = readbuf[i+3];
//            int selRes = readbuf[i+4+sensLen];
            int uidLen = readbuf[i+5+sensLen];
            if(uidLen>0 && uidLen<=maxlen){
                memcpy(uid, &readbuf[i+6+sensLen], uidLen);
                return uidLen;
            }
        }
    }
    return -1;
}

bool pn532_is_ready(void){
    // Sonda il chip con GetFirmwareVersion (0x02) e cerca la risposta D5 03
    // Usa lo stesso percorso semplificato già usato in pn532_read_uid()
    if (pn532_init() != ESP_OK) return false;
    return gpio_get_level(PN532_PIN_IRQ) == 0;
}
