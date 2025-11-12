// main/pins.h — mappa hardware per ESP32-S3 + Ethernet W5500
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "driver/i2c_master.h"

#if __has_include("config.h")
  #include "config.h"
#endif

// ─────────────────────────────────────────────────────────────────────────────
// Override utente (opzionale): crea "pins_user.h" e ridefinisci le macro che ti
// servono. Verrà incluso automaticamente.

#if __has_include("pins_user.h")
  #include "pins_user.h"
#endif

// ─────────────────────────────────────────────────────────────────────────────
// Ethernet W5500 (SPI dedicata)
// ─────────────────────────────────────────────────────────────────────────────
#ifndef ETH_W5500_SPI_HOST
  #define ETH_W5500_SPI_HOST      SPI2_HOST
#endif
#ifndef ETH_W5500_PIN_SCLK
  #define ETH_W5500_PIN_SCLK      GPIO_NUM_12
#endif
#ifndef ETH_W5500_PIN_MOSI
  #define ETH_W5500_PIN_MOSI      GPIO_NUM_11
#endif
#ifndef ETH_W5500_PIN_MISO
  #define ETH_W5500_PIN_MISO      GPIO_NUM_13
#endif
#ifndef ETH_W5500_PIN_CS
  #define ETH_W5500_PIN_CS        GPIO_NUM_10
#endif
#ifndef ETH_W5500_INT_GPIO
  #define ETH_W5500_INT_GPIO      GPIO_NUM_17
#endif
#ifndef ETH_W5500_RST_GPIO
  #define ETH_W5500_RST_GPIO      GPIO_NUM_18
#endif
#ifndef ETH_W5500_SPI_CLOCK_HZ
  #define ETH_W5500_SPI_CLOCK_HZ  (26 * 1000 * 1000)   // 26 MHz stabile anche con cavi lunghi
#endif
#ifndef ETH_W5500_SPI_QUEUE_LEN
  #define ETH_W5500_SPI_QUEUE_LEN 10
#endif

// ─────────────────────────────────────────────────────────────────────────────
// I2C (MCP23017, sensori vari)
// ─────────────────────────────────────────────────────────────────────────────
#ifndef I2C_PORT
  #define I2C_PORT                 I2C_NUM_0
#endif
#ifndef I2C_SDA_GPIO
  #define I2C_SDA_GPIO             GPIO_NUM_21
#endif
#ifndef I2C_SCL_GPIO
  #define I2C_SCL_GPIO             GPIO_NUM_47
#endif
#ifndef I2C_SPEED_HZ
  #define I2C_SPEED_HZ             400000
#endif

// ─────────────────────────────────────────────────────────────────────────────
// PN532 (SPI) — usa l'altro host disponibile per non disturbare il W5500
// ─────────────────────────────────────────────────────────────────────────────
#ifndef PN532_SPI_HOST
  #define PN532_SPI_HOST           SPI3_HOST
#endif
#ifndef PN532_PIN_SCK
  #define PN532_PIN_SCK            GPIO_NUM_40
#endif
#ifndef PN532_PIN_MOSI
  #define PN532_PIN_MOSI           GPIO_NUM_41
#endif
#ifndef PN532_PIN_MISO
  #define PN532_PIN_MISO           GPIO_NUM_42
#endif
#ifndef PN532_PIN_CS
  #define PN532_PIN_CS             GPIO_NUM_48
#endif
#ifndef PN532_PIN_RST
  #define PN532_PIN_RST            GPIO_NUM_43
#endif
#ifndef PN532_PIN_IRQ
  #define PN532_PIN_IRQ            GPIO_NUM_44
#endif

// ─────────────────────────────────────────────────────────────────────────────
// 1-Wire (DS18B20)
// ─────────────────────────────────────────────────────────────────────────────
#ifndef ONEWIRE_GPIO
  #define ONEWIRE_GPIO             GPIO_NUM_37
#endif

// ─────────────────────────────────────────────────────────────────────────────
// CAN / TWAI (opzionale)
// ─────────────────────────────────────────────────────────────────────────────
#if defined(CONFIG_APP_CAN_ENABLED)
  #ifndef CAN_TX_GPIO
    #define CAN_TX_GPIO            ((gpio_num_t)CONFIG_APP_CAN_TX_GPIO)
  #endif
  #ifndef CAN_RX_GPIO
    #define CAN_RX_GPIO            ((gpio_num_t)CONFIG_APP_CAN_RX_GPIO)
  #endif
#endif

// ─────────────────────────────────────────────────────────────────────────────
// MCP23017 — mappa bit
//   PORTA → LED di segnalazione
//   PORTB → Uscite di potenza + tamper globale
// ─────────────────────────────────────────────────────────────────────────────
#ifndef MCP23017_ADDR
  #define MCP23017_ADDR            0x20
#endif
#ifndef MCPA_LED_STATO_BIT
  #define MCPA_LED_STATO_BIT       0
#endif
#ifndef MCPA_LED_ALLARME_BIT
  #define MCPA_LED_ALLARME_BIT     1
#endif
#ifndef MCPA_LED_ALLARME_BIT
  #define MCPA_LED_ALLARME_BIT     1
#endif
#ifndef MCPA_LED_PROV_R_BIT
  #define MCPA_LED_PROV_R_BIT      3
#endif
#ifndef MCPA_LED_PROV_G_BIT
  #define MCPA_LED_PROV_G_BIT      4
#endif
#ifndef MCPA_LED_PROV_B_BIT
  #define MCPA_LED_PROV_B_BIT      5
#endif
#ifndef MCPB_SIREN_INT_BIT
  #define MCPB_SIREN_INT_BIT       0
#endif
#ifndef MCPB_SIREN_EXT_BIT
  #define MCPB_SIREN_EXT_BIT       1
#endif
#ifndef MCPB_NEBBIOGENO_BIT
  #define MCPB_NEBBIOGENO_BIT      2
#endif
#ifndef MCPB_TAMPER_GLOBAL_BIT
  #define MCPB_TAMPER_GLOBAL_BIT   5
#endif

_Static_assert(MCPA_LED_STATO_BIT      >= 0 && MCPA_LED_STATO_BIT      <= 7, "MCPA_LED_STATO_BIT fuori range");
_Static_assert(MCPA_LED_ALLARME_BIT    >= 0 && MCPA_LED_ALLARME_BIT    <= 7, "MCPA_LED_ALLARME_BIT fuori range");
_Static_assert(MCPA_LED_MANUT_BIT      >= 0 && MCPA_LED_MANUT_BIT      <= 7, "MCPA_LED_MANUT_BIT fuori range");
_Static_assert(MCPA_LED_PROV_R_BIT     >= 0 && MCPA_LED_PROV_R_BIT     <= 7, "MCPA_LED_PROV_R_BIT fuori range");
_Static_assert(MCPA_LED_PROV_G_BIT     >= 0 && MCPA_LED_PROV_G_BIT     <= 7, "MCPA_LED_PROV_G_BIT fuori range");
_Static_assert(MCPA_LED_PROV_B_BIT     >= 0 && MCPA_LED_PROV_B_BIT     <= 7, "MCPA_LED_PROV_B_BIT fuori range");
_Static_assert(MCPB_SIREN_INT_BIT      >= 0 && MCPB_SIREN_INT_BIT      <= 7, "MCPB_SIREN_INT_BIT fuori range");
_Static_assert(MCPB_SIREN_EXT_BIT      >= 0 && MCPB_SIREN_EXT_BIT      <= 7, "MCPB_SIREN_EXT_BIT fuori range");
_Static_assert(MCPB_NEBBIOGENO_BIT     >= 0 && MCPB_NEBBIOGENO_BIT     <= 7, "MCPB_NEBBIOGENO_BIT fuori range");
_Static_assert(MCPB_TAMPER_GLOBAL_BIT  >= 0 && MCPB_TAMPER_GLOBAL_BIT  <= 7, "MCPB_TAMPER_GLOBAL_BIT fuori range");

#define MCPA_MASK(bit) (1u << (bit))
#define MCPB_MASK(bit) (1u << (8 + (bit)))

// ─────────────────────────────────────────────────────────────────────────────
// Zone locali: ingressi analogici su MCU (ADC)
// Ogni zona ha: GPIO, soglia allarme, soglie tamper (bassa/alta).
// Raw ADC (0..4095). Tamper disabilitato se enable=false.
// ─────────────────────────────────────────────────────────────────────────────
typedef struct {
    gpio_num_t gpio;
    uint16_t   tamper_short_raw;   // ≤ valore → tamper (corto)
    uint16_t   alarm_raw;          // ≤ valore → zona in allarme
    uint16_t   tamper_open_raw;    // ≥ valore → tamper (aperto)
    bool       tamper_enabled;
} zone_adc_channel_cfg_t;

#ifndef ZONE_ANALOG_CHANNEL_COUNT
  #define ZONE_ANALOG_CHANNEL_COUNT 10
#endif

#ifndef ZONE_ADC_CHANNEL_LIST
  #define ZONE_ADC_CHANNEL_LIST \
    ZONE_ADC_CHANNEL(GPIO_NUM_1,  150, 1700, 3600, true) \
    ZONE_ADC_CHANNEL(GPIO_NUM_2,  150, 1700, 3600, true) \
    ZONE_ADC_CHANNEL(GPIO_NUM_4,  150, 1700, 3600, true) \
    ZONE_ADC_CHANNEL(GPIO_NUM_5,  150, 1700, 3600, true) \
    ZONE_ADC_CHANNEL(GPIO_NUM_6,  150, 1700, 3600, true) \
    ZONE_ADC_CHANNEL(GPIO_NUM_7,  150, 1700, 3600, true) \
    ZONE_ADC_CHANNEL(GPIO_NUM_8,  150, 1700, 3600, true) \
    ZONE_ADC_CHANNEL(GPIO_NUM_9,  150, 1700, 3600, true) \
    ZONE_ADC_CHANNEL(GPIO_NUM_14, 150, 1700, 3600, true) \
    ZONE_ADC_CHANNEL(GPIO_NUM_15, 150, 1700, 3600, true)
#endif

#ifndef SUPPLY_12V_MONITOR_GPIO
  #define SUPPLY_12V_MONITOR_GPIO  GPIO_NUM_16
#endif

_Static_assert(ZONE_ANALOG_CHANNEL_COUNT > 0, "Serve almeno una zona analogica");

// ─────────────────────────────────────────────────────────────────────────────
// Utility runtime per debug
// ─────────────────────────────────────────────────────────────────────────────
static inline void pins_print_map(void) {
    printf("\n--- PIN MAP ---\n");
    printf("Ethernet W5500: host=%d SCK=%d MOSI=%d MISO=%d CS=%d INT=%d RST=%d\n",
           (int)ETH_W5500_SPI_HOST,
           ETH_W5500_PIN_SCLK,
           ETH_W5500_PIN_MOSI,
           ETH_W5500_PIN_MISO,
           ETH_W5500_PIN_CS,
           ETH_W5500_INT_GPIO,
           ETH_W5500_RST_GPIO);
    printf("I2C: port=%d SDA=%d SCL=%d @ %d Hz\n",
           I2C_PORT, I2C_SDA_GPIO, I2C_SCL_GPIO, I2C_SPEED_HZ);
    printf("PN532 SPI: host=%d SCK=%d MOSI=%d MISO=%d CS=%d RST=%d IRQ=%d\n",
           (int)PN532_SPI_HOST,
           PN532_PIN_SCK,
           PN532_PIN_MOSI,
           PN532_PIN_MISO,
           PN532_PIN_CS,
           PN532_PIN_RST,
           PN532_PIN_IRQ);
    printf("1-Wire GPIO=%d\n", ONEWIRE_GPIO);
#if defined(CONFIG_APP_CAN_ENABLED)
    printf("CAN TX=%d RX=%d\n", CAN_TX_GPIO, CAN_RX_GPIO);
#else
    printf("CAN disabilitato\n");
#endif
    printf("MCP23017 @0x%02X — PORTA: stato=%d allarme=%d manut=%d provRGB=(%d,%d,%d) | PORTB: sirena_int=%d sirena_ext=%d nebbiogeno=%d tamper_global=%d\n",
           MCP23017_ADDR,
           MCPA_LED_STATO_BIT,
           MCPA_LED_ALLARME_BIT,
           MCPA_LED_MANUT_BIT,
           MCPA_LED_PROV_R_BIT,
           MCPA_LED_PROV_G_BIT,
           MCPA_LED_PROV_B_BIT,
           MCPB_SIREN_INT_BIT,
           MCPB_SIREN_EXT_BIT,
           MCPB_NEBBIOGENO_BIT,
           MCPB_TAMPER_GLOBAL_BIT);
    printf("Zone analogiche (%d canali) | misura 12V su GPIO=%d\n",
           ZONE_ANALOG_CHANNEL_COUNT,
           SUPPLY_12V_MONITOR_GPIO);
    printf("---------------\n\n");
}
