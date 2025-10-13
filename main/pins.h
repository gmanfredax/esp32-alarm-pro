// main/pins.h
#pragma once
#include "driver/gpio.h"
#include "driver/spi_master.h"   // per SPIx_HOST
#include "sdkconfig.h"
#include "driver/i2c_master.h"

// ─────────────────────────────────────────────────────────────────────────────
// OVERRIDE UTENTE (opzionale):
// Crea un file "pins_user.h" nella cartella del progetto e definisci lì
// le macro dei pin che vuoi cambiare. Verrà incluso qui sotto.
#if __has_include("pins_user.h")
  #include "pins_user.h"
#endif
// ─────────────────────────────────────────────────────────────────────────────


// ========================= ETHERNET (RMII, ESP32) ============================
// Pin RMII fissi lato ESP32 (NON cambiarli nel codice: sono cablati in HW).
// ATTENZIONE: non impostare pull/direzioni su questi pin dall'app.
#define ETH_RMII_REF_CLK_GPIO   GPIO_NUM_0   // 50 MHz IN (da PHY) o OUT (APLL)
#define ETH_RMII_TX_EN_GPIO     GPIO_NUM_21
#define ETH_RMII_TXD0_GPIO      GPIO_NUM_19
#define ETH_RMII_TXD1_GPIO      GPIO_NUM_22
#define ETH_RMII_RXD0_GPIO      GPIO_NUM_25
#define ETH_RMII_RXD1_GPIO      GPIO_NUM_26
#define ETH_RMII_CRS_DV_GPIO    GPIO_NUM_27

// Pin SMI (MDC/MDIO) — configurabili
#ifndef ETH_MDC_GPIO
  #define ETH_MDC_GPIO          GPIO_NUM_23
#endif
#ifndef ETH_MDIO_GPIO
  #define ETH_MDIO_GPIO         GPIO_NUM_18
#endif
#ifndef ETH_PHY_ADDR
  #define ETH_PHY_ADDR          1           // 0 o 1 tipici
#endif
#ifndef ETH_PHY_RST_GPIO
  #define ETH_PHY_RST_GPIO      -1          // -1 se non cablato a GPIO
#endif
#ifndef ETH_USE_EXT_REF_CLK
  #define ETH_USE_EXT_REF_CLK   1           // 1 = 50 MHz dal PHY su GPIO0; 0 = APLL interno
#endif


// =============================== PN532 (SPI) =================================
// Rimappati per evitare conflitti con RMII
#ifndef PN532_SPI_HOST
  #define PN532_SPI_HOST        2   // VSPI
#endif
#ifndef PN532_PIN_SCK
  #define PN532_PIN_SCK         GPIO_NUM_14
#endif
#ifndef PN532_PIN_MOSI
  #define PN532_PIN_MOSI        GPIO_NUM_13
#endif
#ifndef PN532_PIN_MISO
  #define PN532_PIN_MISO        GPIO_NUM_12   // input-only: perfetto per MISO
#endif
#ifndef PN532_PIN_CS
  #define PN532_PIN_CS          GPIO_NUM_16
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
  #define I2C_PORT              0
#endif
#ifndef I2C_SDA_GPIO
  #define I2C_SDA_GPIO          33
#endif
#ifndef I2C_SCL_GPIO
  #define I2C_SCL_GPIO          32
#endif
#ifndef I2C_SPEED_HZ
  #define I2C_SPEED_HZ          100000   // con pull-up esterne da 10k è l’ideale
#endif


// ============================== 1-Wire (DS18B20) =============================
#ifndef ONEWIRE_GPIO
  #define ONEWIRE_GPIO          GPIO_NUM_15
#endif


// ================================ MCP23017 ===================================
// Indirizzo 7-bit NON shiftato (modifica se A2..A0 != 111)
#ifndef MCP23017_ADDR
  #define MCP23017_ADDR         0x27
#endif

// Mappatura **BIT** (0..7) su PORTB del MCP23017 (NON sono GPIO dell’ESP32)
#ifndef MCPB_RELAY_BIT
  #define MCPB_RELAY_BIT        5
#endif
#ifndef MCPB_LED_STATO_BIT
  #define MCPB_LED_STATO_BIT    6
#endif
#ifndef MCPB_LED_MANUT_BIT
  #define MCPB_LED_MANUT_BIT    7
#endif
#ifndef MCPB_TAMPER_BIT
  #define MCPB_TAMPER_BIT       4
#endif

// Controlli compile-time: bit validi 0..7
_Static_assert(MCPB_RELAY_BIT      >= 0 && MCPB_RELAY_BIT      <= 7, "MCPB_RELAY_BIT fuori range (0..7)");
_Static_assert(MCPB_LED_STATO_BIT  >= 0 && MCPB_LED_STATO_BIT  <= 7, "MCPB_LED_STATO_BIT fuori range (0..7)");
_Static_assert(MCPB_LED_MANUT_BIT  >= 0 && MCPB_LED_MANUT_BIT  <= 7, "MCPB_LED_MANUT_BIT fuori range (0..7)");
_Static_assert(MCPB_TAMPER_BIT     >= 0 && MCPB_TAMPER_BIT     <= 7, "MCPB_TAMPER_BIT fuori range (0..7)");

// Utility: maschera per bit di PORTB (PORTB mappato su bit 8..15 del valore combinato)
#define MCPB_MASK(b)            (1u << (8 + (b)))


// ============================== USCITE / INGRESSI ============================
// Esempi (lasciati commentati finché non servono):
// #ifndef PIN_SIREN_RELAY
//   #define PIN_SIREN_RELAY       GPIO_NUM_12
// #endif
// #ifndef PIN_LED_STATE
//   #define PIN_LED_STATE         GPIO_NUM_2
// #endif
// #ifndef PIN_LED_MAINT
//   #define PIN_LED_MAINT         GPIO_NUM_15
// #endif

// #ifndef PIN_HW_RESET_BTN_A
//   #define PIN_HW_RESET_BTN_A     GPIO_NUM_4
// #endif
// #ifndef PIN_HW_RESET_BTN_B
//   #define PIN_HW_RESET_BTN_B     GPIO_NUM_5
// #endif

// _ASSERT_NOT_RMII(PIN_HW_RESET_BTN_A);
// _ASSERT_NOT_RMII(PIN_HW_RESET_BTN_B);
// _Static_assert(PIN_HW_RESET_BTN_A != PIN_HW_RESET_BTN_B, "I pulsanti di reset devono usare GPIO distinti");
// … aggiungi qui eventuali altre definizioni relative a GPIO ESP32 …


// ─────────────────────────────────────────────────────────────────────────────
// CONTROLLI COMPILAZIONE: evita conflitti con RMII
// Usa _Static_assert per fallire a compile-time se assegni pin vietati agli I/O ESP32.

// Helper macro (valuta a compile-time)
#define _ASSERT_NOT_RMII(pin) \
  _Static_assert((pin)!=ETH_RMII_REF_CLK_GPIO && (pin)!=ETH_RMII_TX_EN_GPIO && \
                 (pin)!=ETH_RMII_TXD0_GPIO   && (pin)!=ETH_RMII_TXD1_GPIO   && \
                 (pin)!=ETH_RMII_RXD0_GPIO   && (pin)!=ETH_RMII_RXD1_GPIO   && \
                 (pin)!=ETH_RMII_CRS_DV_GPIO, \
                 "PIN CONFLITTO con Ethernet RMII")

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
    printf("ETH  RMII  REF_CLK=%d TX_EN=%d TXD0=%d TXD1=%d RXD0=%d RXD1=%d CRS_DV=%d\n",
           ETH_RMII_REF_CLK_GPIO, ETH_RMII_TX_EN_GPIO, ETH_RMII_TXD0_GPIO, ETH_RMII_TXD1_GPIO,
           ETH_RMII_RXD0_GPIO, ETH_RMII_RXD1_GPIO, ETH_RMII_CRS_DV_GPIO);
    printf("ETH  SMI   MDC=%d MDIO=%d PHY_ADDR=%d RST=%d ext_refclk=%d\n",
           ETH_MDC_GPIO, ETH_MDIO_GPIO, ETH_PHY_ADDR, ETH_PHY_RST_GPIO, ETH_USE_EXT_REF_CLK);

    printf("PN532 SPI host=%d  SCK=%d MOSI=%d MISO=%d CS=%d\n",
           (int)PN532_SPI_HOST, PN532_PIN_SCK, PN532_PIN_MOSI, PN532_PIN_MISO, PN532_PIN_CS);

    printf("I2C  port=%d  SDA=%d SCL=%d @ %d Hz\n",
           I2C_PORT, I2C_SDA_GPIO, I2C_SCL_GPIO, I2C_SPEED_HZ);

    printf("1-Wire GPIO=%d\n", ONEWIRE_GPIO);

#if defined(CONFIG_APP_CAN_ENABLED)
    int can_bitrate = 0;
#if defined(CONFIG_APP_CAN_BITRATE_125K)
    can_bitrate = 125000;
#elif defined(CONFIG_APP_CAN_BITRATE_500K)
    can_bitrate = 500000;
#else
    can_bitrate = 250000;
#endif
    printf("CAN  TWAI  TX=%d RX=%d bitrate=%d\n", CAN_TX_GPIO, CAN_RX_GPIO, can_bitrate);
#else
    printf("CAN  TWAI  disabled\n");
#endif

    printf("MCP23017 addr=0x%02X  PORTB bits: RELAY=%d LED_STATO=%d LED_MANUT=%d TAMPER=%d\n",
           MCP23017_ADDR, MCPB_RELAY_BIT, MCPB_LED_STATO_BIT, MCPB_LED_MANUT_BIT, MCPB_TAMPER_BIT);
    printf("---------------\n\n");
}
