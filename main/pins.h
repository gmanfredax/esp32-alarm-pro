// main/pins.h
#pragma once
#include "driver/gpio.h"
#include "driver/spi_master.h"  // per SPIx_HOST
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
// Pin RMII fissi lato ESP32 (NON cambiarli nel codice: sono cablati in HW):
#define ETH_RMII_REF_CLK_GPIO   GPIO_NUM_0   // 50MHz IN (da PHY) o OUT (APLL)
#define ETH_RMII_TX_EN_GPIO     GPIO_NUM_21
#define ETH_RMII_TXD0_GPIO      GPIO_NUM_19
#define ETH_RMII_TXD1_GPIO      GPIO_NUM_22
#define ETH_RMII_RXD0_GPIO      GPIO_NUM_25
#define ETH_RMII_RXD1_GPIO      GPIO_NUM_26
#define ETH_RMII_CRS_DV_GPIO    GPIO_NUM_27
// Pin SMI (liberi): puoi spostarli se vuoi
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
  #define ETH_USE_EXT_REF_CLK   1           // 1 = 50MHz dal PHY su GPIO0; 0 = da ESP32 (APLL)
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

// ================================ I2C (ADS, ecc.) ============================
#ifndef I2C_PORT
  #define I2C_PORT              0
#endif
#ifndef I2C_SDA_GPIO
  #define I2C_SDA_GPIO          33   // NON usare 21/22 perché RMII li occupa
#endif
#ifndef I2C_SCL_GPIO
  #define I2C_SCL_GPIO          32
#endif
#ifndef I2C_SPEED_HZ
  #define I2C_SPEED_HZ          400000
#endif

// ============================== 1-Wire (DS18B20) =============================
#ifndef ONEWIRE_GPIO
  #define ONEWIRE_GPIO          GPIO_NUM_15
#endif

// ===== MCP23017 =====
// Indirizzo con A2..A0 = 0 -> 0x20 (modifica se usi altri strap)
#ifndef MCP23017_ADDR
#define MCP23017_ADDR       0x20
#endif

// Mappatura bit su PORTB (aggiorna se il tuo schema è diverso)
#ifndef MCPB_RELAY_BIT
#define MCPB_RELAY_BIT      0
#endif

#ifndef MCPB_LED_STATO_BIT
#define MCPB_LED_STATO_BIT  1
#endif

#ifndef MCPB_LED_MANUT_BIT
#define MCPB_LED_MANUT_BIT  2
#endif

#ifndef MCPB_TAMPER_BIT
#define MCPB_TAMPER_BIT     3
#endif

// ===== 1-Wire (DS18B20) =====
#ifndef ONEWIRE_GPIO
#define ONEWIRE_GPIO        15
#endif

// ============================== USCITE / INGRESSI ============================
// #ifndef PIN_SIREN_RELAY
//   #define PIN_SIREN_RELAY       GPIO_NUM_12
// #endif
// #ifndef PIN_LED_STATE
//   #define PIN_LED_STATE         GPIO_NUM_2
// #endif
// #ifndef PIN_LED_MAINT
//   #define PIN_LED_MAINT         GPIO_NUM_15
// #endif
// // Esempio ingressi zona (adatta alla tua scheda):
// #ifndef PIN_ZONE1
//   #define PIN_ZONE1             GPIO_NUM_35  // input-only
// #endif
// #ifndef PIN_ZONE2
//   #define PIN_ZONE2             GPIO_NUM_36  // input-only
// #endif
// … aggiungi tutte le zone necessarie …

// ─────────────────────────────────────────────────────────────────────────────
// CONTROLLI COMPILAZIONE: evita conflitti con RMII
// Usa _Static_assert per fallire a compile-time se assegni pin vietati

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

// I2C non deve usare 21/22 (RMII)
_ASSERT_NOT_RMII(I2C_SDA_GPIO);
_ASSERT_NOT_RMII(I2C_SCL_GPIO);

// 1-Wire e output: esempi di check
_ASSERT_NOT_RMII(ONEWIRE_GPIO);
//_ASSERT_NOT_RMII(PIN_SIREN_RELAY);
//_ASSERT_NOT_RMII(PIN_LED_STATE);
//_ASSERT_NOT_RMII(PIN_LED_MAINT);

// MDC/MDIO possono stare ovunque, ma ti sconsiglio di metterli su RMII
_ASSERT_NOT_RMII(ETH_MDC_GPIO);
_ASSERT_NOT_RMII(ETH_MDIO_GPIO);

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
    //printf("OUT  Siren=%d LED_state=%d LED_maint=%d\n",
    //       PIN_SIREN_RELAY, PIN_LED_STATE, PIN_LED_MAINT);
    //printf("Z1=%d Z2=%d ... (completa per le altre zone)\n", PIN_ZONE1, PIN_ZONE2);
    printf("---------------\n\n");
}
