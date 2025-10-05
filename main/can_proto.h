#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct __attribute__((packed)) {
    uint32_t inputs_bitmap;
    uint8_t  change_counter;
    uint8_t  reserved[3];
} pdo_inputs_t;

typedef struct __attribute__((packed)) {
    uint32_t outputs_bitmap;
    uint8_t  pwm_level;
    uint8_t  reserved[3];
} pdo_outputs_cmd_t;

typedef struct __attribute__((packed)) {
    uint8_t  led_cmd;
    uint16_t duration_ms;
    uint8_t  pattern_arg;
    uint8_t  reserved[4];
} pdo_led_cmd_t;

#define COBID_PDO_TX1(node_id)   (0x180u + (node_id))
#define COBID_PDO_RX1(node_id)   (0x200u + (node_id))
#define COBID_PDO_RX2(node_id)   (0x300u + (node_id))
#define COBID_SDO_TX(node_id)    (0x580u + (node_id))
#define COBID_SDO_RX(node_id)    (0x600u + (node_id))
#define COBID_HEARTBEAT(node_id) (0x700u + (node_id))
#define COBID_LSS_MASTER         (0x7E5u)
#define COBID_LSS_SLAVE          (0x7E4u)

#ifdef __cplusplus
}
#endif