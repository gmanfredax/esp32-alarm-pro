#pragma once

// Questo file fornisce le override di default per i pin hardware. Tutti i valori
// possono essere ridefiniti in pins_user.h se necessario.

// I2C bus condiviso (MCP23017, sensori vari)
#define I2C_PORT                 I2C_NUM_0
#define I2C_SDA_GPIO             GPIO_NUM_21
#define I2C_SCL_GPIO             GPIO_NUM_47
#define MCP23017_ADDR            0x27

// MCP23017 PORTA → LED, PORTB → uscite potenza
#define MCPA_LED_STATO_BIT       0
#define MCPA_LED_ALLARME_BIT     1
#define MCPA_LED_MANUT_BIT       2
#define MCPA_LED_PROV_R_BIT      3
#define MCPA_LED_PROV_G_BIT      4
#define MCPA_LED_PROV_B_BIT      5

#define MCPB_SIREN_INT_BIT       0
#define MCPB_SIREN_EXT_BIT       1
#define MCPB_NEBBIOGENO_BIT      2
#define MCPB_TAMPER_GLOBAL_BIT   5

// PN532 NFC reader su SPI dedicata (GPIO non analogici)
#define PN532_SPI_HOST           SPI3_HOST
#define PN532_PIN_CS             GPIO_NUM_48
#define PN532_PIN_SCK            GPIO_NUM_40
#define PN532_PIN_MOSI           GPIO_NUM_41
#define PN532_PIN_MISO           GPIO_NUM_42
#define PN532_PIN_RST            GPIO_NUM_43
#define PN532_PIN_IRQ            GPIO_NUM_44

// 1-Wire (DS18B20)
#define ONEWIRE_GPIO             GPIO_NUM_37

// Ethernet cablata (W5500 su SPI2)
#define ETH_W5500_SPI_HOST       SPI2_HOST
#define ETH_W5500_PIN_SCLK       GPIO_NUM_12
#define ETH_W5500_PIN_MOSI       GPIO_NUM_11
#define ETH_W5500_PIN_MISO       GPIO_NUM_13
#define ETH_W5500_PIN_CS         GPIO_NUM_10
#define ETH_W5500_INT_GPIO       GPIO_NUM_17
#define ETH_W5500_RST_GPIO       GPIO_NUM_18
#define ETH_W5500_SPI_CLOCK_HZ   (26 * 1000 * 1000)
#define ETH_W5500_SPI_QUEUE_LEN  10

// Zone analogiche (10 canali di default)
#define ZONE_ANALOG_CHANNEL_COUNT 10
#define ZONE_ADC_CHANNEL_LIST \
    ZONE_ADC_CHANNEL(GPIO_NUM_1,  150, 1700, 3600, true), \
    ZONE_ADC_CHANNEL(GPIO_NUM_2,  150, 1700, 3600, true), \
    ZONE_ADC_CHANNEL(GPIO_NUM_4,  150, 1700, 3600, true), \
    ZONE_ADC_CHANNEL(GPIO_NUM_5,  150, 1700, 3600, true), \
    ZONE_ADC_CHANNEL(GPIO_NUM_6,  150, 1700, 3600, true), \
    ZONE_ADC_CHANNEL(GPIO_NUM_7,  150, 1700, 3600, true), \
    ZONE_ADC_CHANNEL(GPIO_NUM_8,  150, 1700, 3600, true), \
    ZONE_ADC_CHANNEL(GPIO_NUM_9,  150, 1700, 3600, true), \
    ZONE_ADC_CHANNEL(GPIO_NUM_14, 150, 1700, 3600, true), \
    ZONE_ADC_CHANNEL(GPIO_NUM_15, 150, 1700, 3600, true)

#define SUPPLY_12V_MONITOR_GPIO  GPIO_NUM_16