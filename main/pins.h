// main/pins.h - Mappatura pin hardware per ESP32-P4NRW32 + IPI01GRI
#pragma once

#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "driver/i2c_master.h"
#include "sdkconfig.h"

// ─────────────────────────────────────────────────────────────────────────────
// OVERRIDE UTENTE (opzionale)
// Crea un file "pins_user.h" con le tue definizioni personalizzate
#if __has_include("pins_user.h")
#  include "pins_user.h"
#endif
// ─────────────────────────────────────────────────────────────────────────────

// ========================= ETHERNET (RMII, ESP32-P4) ============================
// Mappatura fissata dal layout ESP32-P4NRW32 + IP101GRI
#define ETH_RMII_REF_CLK_GPIO   GPIO_NUM_50   // 50 MHz IN da IP101GRI (doppia frequenza)
#define ETH_RMII_TX_EN_GPIO     GPIO_NUM_49
#define ETH_RMII_TXD0_GPIO      GPIO_NUM_34
#define ETH_RMII_TXD1_GPIO      GPIO_NUM_35
#define ETH_RMII_RXD0_GPIO      GPIO_NUM_29
#define ETH_RMII_RXD1_GPIO      GPIO_NUM_30
#define ETH_RMII_CRS_DV_GPIO    GPIO_NUM_28

#ifndef ETH_PHY_ADDR
#  define ETH_PHY_ADDR          1 
#endif
#ifndef ETH_PHY_RST_GPIO
#  define ETH_PHY_RST_GPIO      GPIO_NUM_51
#endif
#ifndef ETH_MDC_GPIO
#  define ETH_MDC_GPIO          GPIO_NUM_31
#endif
#ifndef ETH_MDIO_GPIO
#  define ETH_MDIO_GPIO         GPIO_NUM_52
#endif
#ifndef ETH_USE_EXT_REF_CLK
#  define ETH_USE_EXT_REF_CLK   1           // clock da PHY
#endif

// =============================== PN532 (SPI) =================================
#ifndef PN532_SPI_HOST
#  define PN532_SPI_HOST        SPI2_HOST
#endif
#ifndef PN532_PIN_SCK
#  define PN532_PIN_SCK         GPIO_NUM_14
#endif
#ifndef PN532_PIN_MOSI
#  define PN532_PIN_MOSI        GPIO_NUM_13
#endif
#ifndef PN532_PIN_MISO
#  define PN532_PIN_MISO        GPIO_NUM_12
#endif
#ifndef PN532_PIN_CS
#  define PN532_PIN_CS          GPIO_NUM_11
#endif

// =============================== CAN / TWAI ==================================
#if defined(CONFIG_APP_CAN_ENABLED)
  #ifndef CAN_TX_GPIO
    #define CAN_TX_GPIO ((gpio_num_t)CONFIG_APP_CAN_TX_GPIO)
  #endif
  #ifndef CAN_RX_GPIO
    #define CAN_RX_GPIO ((gpio_num_t)CONFIG_APP_CAN_RX_GPIO)
  #endif
#endif

// ================================ I2C ========================================
// Nota: NON usare 21/22 perché sono coinvolti nel bus RMII.
#ifndef I2C_PORT
  #define I2C_PORT              I2C_NUM_0
#endif
#ifndef I2C_SDA_GPIO
  #define I2C_SDA_GPIO          GPIO_NUM_7
#endif
#ifndef I2C_SCL_GPIO
  #define I2C_SCL_GPIO          GPIO_NUM_8
#endif
#ifndef I2C_SPEED_HZ
  #define I2C_SPEED_HZ          400000
#endif

// ============================== 1-Wire (DS18B20) =============================
#ifndef ONEWIRE_GPIO
  #define ONEWIRE_GPIO          GPIO_NUM_24
#endif

// ============================ ZONE ANALOGICHE ================================
#ifndef ZONE_INPUT_COUNT
  #define ZONE_INPUT_COUNT      10
#endif

#ifndef ZONE_INPUT_GPIO_1
  #define ZONE_INPUT_GPIO_1     GPIO_NUM_16
#endif
#ifndef ZONE_INPUT_GPIO_2
  #define ZONE_INPUT_GPIO_2     GPIO_NUM_17
#endif
#ifndef ZONE_INPUT_GPIO_3
  #define ZONE_INPUT_GPIO_3     GPIO_NUM_18
#endif
#ifndef ZONE_INPUT_GPIO_4
  #define ZONE_INPUT_GPIO_4     GPIO_NUM_19
#endif
#ifndef ZONE_INPUT_GPIO_5
  #define ZONE_INPUT_GPIO_5     GPIO_NUM_20
#endif
#ifndef ZONE_INPUT_GPIO_6
  #define ZONE_INPUT_GPIO_6     GPIO_NUM_21
#endif
#ifndef ZONE_INPUT_GPIO_7
  #define ZONE_INPUT_GPIO_7     GPIO_NUM_22
#endif
#ifndef ZONE_INPUT_GPIO_8
  #define ZONE_INPUT_GPIO_8     GPIO_NUM_23
#endif
#ifndef ZONE_INPUT_GPIO_9
  #define ZONE_INPUT_GPIO_9     GPIO_NUM_53
#endif
#ifndef ZONE_INPUT_GPIO_10
  #define ZONE_INPUT_GPIO_10    GPIO_NUM_54
#endif

#ifndef ZONE_SUPPLY_MONITOR_GPIO
  #define ZONE_SUPPLY_MONITOR_GPIO GPIO_NUM_NC
#endif

#ifndef ZONE_SUPPLY_DIVIDER_R1_OHMS   // Resistenza lato ingresso (verso Vin)
  #define ZONE_SUPPLY_DIVIDER_R1_OHMS 47000.0f
#endif
#ifndef ZONE_SUPPLY_DIVIDER_R2_OHMS   // Resistenza lato GND
  #define ZONE_SUPPLY_DIVIDER_R2_OHMS 10000.0f
#endif
  
// ================================ MCP23017 ===================================
// Indirizzo 7-bit NON shiftato (modifica se A2..A0 != 111)
#ifndef MCP23017_ADDR
  #define MCP23017_ADDR         0x27
#endif

// PORTA -> LED di stato
#define MCP_PORTA_LED_STATE_BIT     0
#define MCP_PORTA_LED_ALARM_BIT     1
#define MCP_PORTA_LED_MAINT_BIT     2
#define MCP_PORTA_LED_PROV_R_BIT    3
#define MCP_PORTA_LED_PROV_G_BIT    4
#define MCP_PORTA_LED_PROV_B_BIT    5

// PORTB -> attuatori + tamper globale
#define MCP_PORTB_SIREN_INT_BIT     0
#define MCP_PORTB_SIREN_EXT_BIT     1
#define MCP_PORTB_FOG_BIT           2
#define MCP_PORTB_GLOBAL_TAMPER_BIT 5

// ============================ CONTROLLI DI COERENZA ===========================
#define _ASSERT_NOT_RMII(pin) \
  _Static_assert((pin)!=ETH_RMII_REF_CLK_GPIO && (pin)!=ETH_RMII_TX_EN_GPIO && \
                 (pin)!=ETH_RMII_TXD0_GPIO   && (pin)!=ETH_RMII_TXD1_GPIO   && \
                 (pin)!=ETH_RMII_RXD0_GPIO   && (pin)!=ETH_RMII_RXD1_GPIO   && \
                 (pin)!=ETH_RMII_CRS_DV_GPIO, "GPIO in conflitto con RMII")

// PN532 non deve usare linee RMII
_ASSERT_NOT_RMII(PN532_PIN_SCK);
_ASSERT_NOT_RMII(PN532_PIN_MOSI);
_ASSERT_NOT_RMII(PN532_PIN_MISO);
_ASSERT_NOT_RMII(PN532_PIN_CS);

// I2C non deve usare linee RMII
_ASSERT_NOT_RMII(I2C_SDA_GPIO);
_ASSERT_NOT_RMII(I2C_SCL_GPIO);

// 1-Wire
_ASSERT_NOT_RMII(ONEWIRE_GPIO);

// MDC/MDIO: consigliato NON metterli su pin RMII
_ASSERT_NOT_RMII(ETH_MDC_GPIO);
_ASSERT_NOT_RMII(ETH_MDIO_GPIO);

#if defined(CONFIG_APP_CAN_ENABLED)
_ASSERT_NOT_RMII(CAN_TX_GPIO);
_ASSERT_NOT_RMII(CAN_RX_GPIO);
#endif

// ─────────────────────────────────────────────────────────────────────────────
// Utility a runtime: stampa mappa pin (chiamala all’avvio, es. in app_main)
static inline void pins_print_map(void) {
    printf("\n--- PIN MAP ---\n");
    printf("ETH RMII: REF_CLK=%d TX_EN=%d TXD0=%d TXD1=%d RXD0=%d RXD1=%d CRS_DV=%d\n",
           ETH_RMII_REF_CLK_GPIO, ETH_RMII_TX_EN_GPIO, ETH_RMII_TXD0_GPIO,
           ETH_RMII_TXD1_GPIO, ETH_RMII_RXD0_GPIO, ETH_RMII_RXD1_GPIO,
           ETH_RMII_CRS_DV_GPIO);
    printf("ETH SMI: MDC=%d MDIO=%d PHY_ADDR=%d RESET=%d ext_clk=%d\n",
           ETH_MDC_GPIO, ETH_MDIO_GPIO, ETH_PHY_ADDR, ETH_PHY_RST_GPIO,
           ETH_USE_EXT_REF_CLK);
    printf("I2C: SDA=%d SCL=%d @%dHz\n", I2C_SDA_GPIO, I2C_SCL_GPIO, I2C_SPEED_HZ);
    printf("PN532 SPI host=%d SCK=%d MOSI=%d MISO=%d CS=%d\n",
           PN532_SPI_HOST, PN532_PIN_SCK, PN532_PIN_MOSI, PN532_PIN_MISO,
           PN532_PIN_CS);
    printf("Zone analogiche (%u): %d %d %d %d %d %d %d %d %d %d\n",
           ZONE_INPUT_COUNT,
           ZONE_INPUT_GPIO_1, ZONE_INPUT_GPIO_2, ZONE_INPUT_GPIO_3,
           ZONE_INPUT_GPIO_4, ZONE_INPUT_GPIO_5, ZONE_INPUT_GPIO_6,
           ZONE_INPUT_GPIO_7, ZONE_INPUT_GPIO_8, ZONE_INPUT_GPIO_9,
           ZONE_INPUT_GPIO_10);
    printf("Monitor 12V GPIO=%d (R1=%.0fΩ R2=%.0fΩ)\n",
           ZONE_SUPPLY_MONITOR_GPIO,
           (double)ZONE_SUPPLY_DIVIDER_R1_OHMS,
           (double)ZONE_SUPPLY_DIVIDER_R2_OHMS);
    printf("MCP23017 addr=0x%02X\n", MCP23017_ADDR);
    printf("PORTA LED bits: state=%d alarm=%d maint=%d provRGB=%d/%d/%d\n",
           MCP_PORTA_LED_STATE_BIT, MCP_PORTA_LED_ALARM_BIT,
           MCP_PORTA_LED_MAINT_BIT, MCP_PORTA_LED_PROV_R_BIT,
           MCP_PORTA_LED_PROV_G_BIT, MCP_PORTA_LED_PROV_B_BIT);
    printf("PORTB attuatori: siren_int=%d siren_ext=%d fog=%d tamper=%d\n",
           MCP_PORTB_SIREN_INT_BIT, MCP_PORTB_SIREN_EXT_BIT,
           MCP_PORTB_FOG_BIT, MCP_PORTB_GLOBAL_TAMPER_BIT);
    printf("1-Wire GPIO=%d\n", ONEWIRE_GPIO);

// #if defined(CONFIG_APP_CAN_ENABLED)
//     int can_bitrate = 0;
// #if defined(CONFIG_APP_CAN_BITRATE_125K)
//     can_bitrate = 125000;
// #elif defined(CONFIG_APP_CAN_BITRATE_500K)
//     can_bitrate = 500000;
// #else
//     can_bitrate = 250000;
// #endif
//     printf("CAN  TWAI  TX=%d RX=%d bitrate=%d\n", CAN_TX_GPIO, CAN_RX_GPIO, can_bitrate);
// #else
//     printf("CAN  TWAI  disabled\n");
// #endif

    printf("---------------\n\n");
}
