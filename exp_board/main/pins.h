#pragma once

#include "driver/gpio.h"
#include "sdkconfig.h"

// =============================== CAN / TWAI ==================================
#if defined(CONFIG_APP_CAN_ENABLED)
  #ifndef CAN_TX_GPIO
    #define CAN_TX_GPIO ((gpio_num_t)CONFIG_APP_CAN_TX_GPIO)
  #endif
  #ifndef CAN_RX_GPIO
    #define CAN_RX_GPIO ((gpio_num_t)CONFIG_APP_CAN_RX_GPIO)
  #endif
#endif

// =============================== ZONE ANALOGICHE ==========================

// Numero massimo di zone per questa espansione
#ifndef ZONE_INPUT_COUNT
#  define ZONE_INPUT_COUNT 10
#endif

// Pin ADC per le 10 zone (adatta in base alla tua scheda)

// ADC1: GPIO32,33,34,35,36,39
// ADC2: GPIO25,26,27,4
#ifndef ZONE_INPUT_GPIO_1
#  define ZONE_INPUT_GPIO_1  GPIO_NUM_32
#endif
#ifndef ZONE_INPUT_GPIO_2
#  define ZONE_INPUT_GPIO_2  GPIO_NUM_33
#endif
#ifndef ZONE_INPUT_GPIO_3
#  define ZONE_INPUT_GPIO_3  GPIO_NUM_34
#endif
#ifndef ZONE_INPUT_GPIO_4
#  define ZONE_INPUT_GPIO_4  GPIO_NUM_35
#endif
#ifndef ZONE_INPUT_GPIO_5
#  define ZONE_INPUT_GPIO_5  GPIO_NUM_36
#endif
#ifndef ZONE_INPUT_GPIO_6
#  define ZONE_INPUT_GPIO_6  GPIO_NUM_39
#endif
#ifndef ZONE_INPUT_GPIO_7
#  define ZONE_INPUT_GPIO_7  GPIO_NUM_25
#endif
#ifndef ZONE_INPUT_GPIO_8
#  define ZONE_INPUT_GPIO_8  GPIO_NUM_26
#endif
#ifndef ZONE_INPUT_GPIO_9
#  define ZONE_INPUT_GPIO_9  GPIO_NUM_27
#endif
#ifndef ZONE_INPUT_GPIO_10
#  define ZONE_INPUT_GPIO_10 GPIO_NUM_4
#endif

// =============================== USCITE DIGITALI ==========================

#ifndef EXP_OUTPUT_COUNT
#  define EXP_OUTPUT_COUNT 4
#endif

#ifndef EXP_OUTPUT_GPIO_1
#  define EXP_OUTPUT_GPIO_1 GPIO_NUM_14
#endif
#ifndef EXP_OUTPUT_GPIO_2
#  define EXP_OUTPUT_GPIO_2 GPIO_NUM_12
#endif
#ifndef EXP_OUTPUT_GPIO_3
#  define EXP_OUTPUT_GPIO_3 GPIO_NUM_13
#endif
#ifndef EXP_OUTPUT_GPIO_4
#  define EXP_OUTPUT_GPIO_4 GPIO_NUM_15
#endif

// =============================== LED DI STATO =============================

// Adatta in base a dove colleghi i LED sulla scheda di espansione

// LED RUN: lampeggia se il firmware gira
#ifndef EXP_LED_RUN_GPIO
#  define EXP_LED_RUN_GPIO   GPIO_NUM_2    // spesso LED onboard su molti dev kit
#endif

// LED LINK: acceso se node_id assegnato e CAN ok
#ifndef EXP_LED_LINK_GPIO
#  define EXP_LED_LINK_GPIO  GPIO_NUM_5
#endif

// LED EOL: mostra modalità EOL (semplice indicazione)
#ifndef EXP_LED_EOL_GPIO
#  define EXP_LED_EOL_GPIO   GPIO_NUM_21
#endif

// LED UPDATE: riservato per OTA future (per ora sempre spento)
#ifndef EXP_LED_UPDATE_GPIO
#  define EXP_LED_UPDATE_GPIO GPIO_NUM_22
#endif
