#pragma once
#include "esp_err.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Inizializza il device MCP23017 sul bus I2C condiviso.
 *        - imposta IODIRA/IODIRB = input
 *        - abilita pull-up interni GPPUA/GPPUB
 *
 * @return ESP_OK su successo, altrimenti errore IDF.
 */
esp_err_t mcp23017_init(void);

/**
 * @brief Legge GPIOA/GPIOB e ritorna i 16 bit combinati:
 *        bit 0..7  -> GPIOA0..7
 *        bit 8..15 -> GPIOB0..7
 *
 * @param out_ab puntatore dove scrivere il valore letto
 * @return ESP_OK su successo, altrimenti errore IDF.
 */
esp_err_t mcp23017_read_gpioab(uint16_t* out_ab);

void mcp23017_debug_dump(void);


#ifdef __cplusplus
}
#endif
