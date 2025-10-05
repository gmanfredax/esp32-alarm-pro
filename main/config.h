#pragma once
// I2C (MCP23017)
#define I2C_PORT        I2C_NUM_0
#define I2C_SDA_GPIO    33
#define I2C_SCL_GPIO    32
#define MCP23017_ADDR   0x20

// MCP23017 bits
// Port A: Z1..Z8  -> bits 0..7
// Port B: Z9..Z12 -> bits 0..3
#define MCPB_TAMPER_BIT     4   // input
#define MCPB_RELAY_BIT      5   // output
#define MCPB_LED_STATO_BIT  6   // output
#define MCPB_LED_MANUT_BIT  7   // output

// PN532 SPI
#define PN532_SPI_HOST  SPI2_HOST
#define PN532_PIN_CS    16
#define PN532_PIN_SCK   14
#define PN532_PIN_MOSI  13
#define PN532_PIN_MISO  12

// DS18B20
#define ONEWIRE_GPIO     15

// Ethernet RMII (LAN8720)
// refclk to GPIO0 is handled by hardware oscillator; pins set by esp-idf defaults + overridden in ethernet.c
