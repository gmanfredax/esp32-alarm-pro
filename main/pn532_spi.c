#include "pn532_spi.h"
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include <stdbool.h>
#include <string.h>
#include "pins.h"

static const char* TAG="pn532";
static spi_device_handle_t s_dev;
static bool s_bus_inited = false;

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

// Very simplified, polling only
esp_err_t pn532_init(void){
    // Idempotent init: safe to call multiple times
    gpio_set_direction(PN532_PIN_CS, GPIO_MODE_OUTPUT);
    cs_deselect();
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
    // Send InListPassiveTarget (106 kbps, 1 target)
    uint8_t cmd[3] = { PN532_COMMAND_INLISTPASSIVETARGET, 0x01, 0x00 };
    uint8_t frame[64]; int flen=0; frame_cmd(frame,&flen,cmd,3);
    uint8_t dummy_rx[64]={0};
    cs_select(); spi_txrx(frame, flen, dummy_rx, 0); cs_deselect();
    // Busy wait then read data
    vTaskDelay(pdMS_TO_TICKS(50));
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
    uint8_t cmd[] = { 0x02 }; // PN532_COMMAND_GETFIRMWAREVERSION
    uint8_t frame[64]; int flen=0; frame_cmd(frame,&flen,cmd,1);
    uint8_t dummy_rx[64]={0};
    cs_select(); spi_txrx(frame, flen, dummy_rx, 0); cs_deselect();
    // attesa breve e lettura
    vTaskDelay(pdMS_TO_TICKS(20));
    uint8_t readbuf[64]={0x03}; // SPI data read
    cs_select(); spi_txrx(readbuf, 1, readbuf, sizeof(readbuf)); cs_deselect();
    for(int i=0;i<62;i++){
        if(readbuf[i]==0xD5 && readbuf[i+1]==0x03){
            return true;
        }
    }
    return false;
}
