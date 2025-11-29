#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Inizializza la scheda di espansione (ADC, GPIO, CAN, NVS, ecc.)
 */
esp_err_t expansion_node_init(void);

/**
 * @brief Avvia i task FreeRTOS (CAN RX, logica di zona/heartbeat).
 */
esp_err_t expansion_node_start_tasks(void);

#ifdef __cplusplus
}
#endif
