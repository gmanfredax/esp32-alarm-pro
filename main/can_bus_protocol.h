#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file can_bus_protocol.h
 * @brief Shared definitions for the Alarm Pro CAN communication protocol.
 */

#define CAN_PROTO_PROTOCOL_VERSION 0x01u

#define CAN_PROTO_MODEL_IO8R8_V1   0x0101u

#define CAN_PROTO_ID_STATUS_BASE   0x180u
#define CAN_PROTO_ID_INFO_BASE     0x280u
#define CAN_PROTO_ID_COMMAND_BASE  0x380u
#define CAN_PROTO_ID_DIAG_BASE     0x480u

#define CAN_PROTO_ID_STATUS(node_id)  (CAN_PROTO_ID_STATUS_BASE + (node_id))
#define CAN_PROTO_ID_INFO(node_id)    (CAN_PROTO_ID_INFO_BASE + (node_id))
#define CAN_PROTO_ID_COMMAND(node_id) (CAN_PROTO_ID_COMMAND_BASE + (node_id))
#define CAN_PROTO_ID_DIAG(node_id)    (CAN_PROTO_ID_DIAG_BASE + (node_id))

#define CAN_PROTO_ID_BROADCAST_SCAN   0x070u
#define CAN_PROTO_ID_BROADCAST_TEST   0x071u

typedef enum {
    CAN_PROTO_MSG_HEARTBEAT      = 0x01u,
    CAN_PROTO_MSG_IO_REPORT      = 0x02u,
    CAN_PROTO_MSG_INFO           = 0x10u,
    CAN_PROTO_MSG_OUTPUT_COMMAND = 0x20u,
    CAN_PROTO_MSG_IDENTIFY       = 0x21u,
    CAN_PROTO_MSG_TEST_TOGGLE    = 0x30u,
    CAN_PROTO_MSG_SCAN_REQUEST   = 0x31u,
    CAN_PROTO_MSG_SCAN_RESPONSE  = 0x32u,
    CAN_PROTO_MSG_ACK            = 0x7Fu,
} can_proto_msg_type_t;

typedef struct __attribute__((packed)) {
    uint8_t  msg_type;      /**< CAN_PROTO_MSG_HEARTBEAT */
    uint8_t  node_state;    /**< Application specific state flags */
    uint8_t  change_counter;/**< Increments every input change */
    uint8_t  reserved;      /**< Reserved for future use */
    uint32_t inputs_bitmap; /**< Snapshot of digital inputs */
} can_proto_heartbeat_t;

typedef struct __attribute__((packed)) {
    uint8_t msg_type;      /**< CAN_PROTO_MSG_INFO */
    uint8_t protocol;      /**< CAN protocol version */
    uint16_t model;        /**< Device model identifier */
    uint16_t firmware;     /**< Firmware version */
    uint8_t inputs_count;  /**< Number of inputs supported */
    uint8_t outputs_count; /**< Number of outputs supported */
} can_proto_info_t;

typedef struct __attribute__((packed)) {
    uint8_t  msg_type;      /**< CAN_PROTO_MSG_OUTPUT_COMMAND */
    uint8_t  flags;         /**< Command flags */
    uint32_t outputs_bitmap;/**< Desired outputs state */
    uint8_t  pwm_level;     /**< Optional PWM level */
    uint8_t  reserved;      /**< Reserved for alignment */
} can_proto_output_cmd_t;

typedef struct __attribute__((packed)) {
    uint8_t msg_type;   /**< CAN_PROTO_MSG_IDENTIFY */
    uint8_t enable;     /**< 1 to enable identify pattern, 0 to stop */
    uint8_t reserved[6];
} can_proto_identify_cmd_t;

typedef struct __attribute__((packed)) {
    uint8_t msg_type;   /**< CAN_PROTO_MSG_SCAN_REQUEST or response */
    uint8_t reserved[7];
} can_proto_scan_t;

typedef struct __attribute__((packed)) {
    uint8_t msg_type;  /**< CAN_PROTO_MSG_TEST_TOGGLE */
    uint8_t enable;    /**< 1 => enable, 0 => disable */
    uint8_t reserved[6];
} can_proto_test_toggle_t;

#ifdef __cplusplus
}
#endif