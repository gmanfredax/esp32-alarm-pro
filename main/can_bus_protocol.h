#pragma once

#include <stdint.h>

#include "zone_eol.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CAN_PROTO_PROTOCOL_VERSION 0x02u

#define CAN_PROTO_MODEL_IO8R8_V1   0x0101u

#define CAN_PROTO_ID_STATUS_BASE   0x180u
#define CAN_PROTO_ID_INFO_BASE     0x280u
#define CAN_PROTO_ID_COMMAND_BASE  0x380u
#define CAN_PROTO_ID_DIAG_BASE     0x480u

#define CAN_PROTO_ID_STATUS(node_id)  (CAN_PROTO_ID_STATUS_BASE + (node_id))
#define CAN_PROTO_ID_INFO(node_id)    (CAN_PROTO_ID_INFO_BASE + (node_id))
#define CAN_PROTO_ID_COMMAND(node_id) (CAN_PROTO_ID_COMMAND_BASE + (node_id))
#define CAN_PROTO_ID_DIAG(node_id)    (CAN_PROTO_ID_DIAG_BASE + (node_id))

#define CAN_PROTO_ID_BROADCAST_SCAN        0x070u
#define CAN_PROTO_ID_BROADCAST_TEST        0x071u
#define CAN_PROTO_ID_BROADCAST_ADDR_REQ    0x072u
#define CAN_PROTO_ID_BROADCAST_ADDR_ASSIGN 0x073u

#define CAN_PROTO_UID_LENGTH 7u

typedef enum {
    CAN_PROTO_MSG_STATUS      = 0x01u,
    CAN_PROTO_MSG_INFO        = 0x02u,
    CAN_PROTO_MSG_OUTPUT      = 0x10u,
    CAN_PROTO_MSG_IDENTIFY    = 0x11u,
    CAN_PROTO_MSG_SET_MODE    = 0x12u,
    CAN_PROTO_MSG_TEST_TOGGLE = 0x30u,
    CAN_PROTO_MSG_SCAN_REQ    = 0x31u,
    CAN_PROTO_MSG_SCAN_RES    = 0x32u,
    CAN_PROTO_MSG_ACK         = 0x7Fu,
} can_proto_msg_type_t;

typedef enum {
    CAN_STATUS_FLAG_TAMPER   = (1u << 0),
    CAN_STATUS_FLAG_SUPPLY   = (1u << 1),
    CAN_STATUS_FLAG_INTERNAL = (1u << 2),
} can_proto_status_flag_t;

typedef struct __attribute__((packed)) {
    uint8_t  msg_type;      /**< CAN_PROTO_MSG_STATUS */
    uint8_t  zone_count;    /**< Number of zones provided (max 8) */
    uint8_t  eol_mode;      /**< zone_eol_mode_t */
    uint8_t  flags;         /**< can_proto_status_flag_t */
    uint16_t alarm_bitmap;  /**< Zones currently in alarm */
    uint8_t  tamper_bitmap; /**< Zones with tamper/trouble */
    uint8_t  change_counter;/**< Monotonic counter incremented on state change */
} can_proto_status_t;

typedef struct __attribute__((packed)) {
    uint8_t msg_type;      /**< CAN_PROTO_MSG_INFO */
    uint8_t protocol;      /**< CAN protocol version */
    uint16_t model;        /**< Device model identifier */
    uint16_t firmware;     /**< Firmware version */
    uint8_t inputs_count;  /**< Number of inputs supported */
    uint8_t outputs_count; /**< Number of outputs supported */
} can_proto_info_t;

typedef struct __attribute__((packed)) {
    uint8_t  msg_type;      /**< CAN_PROTO_MSG_OUTPUT */
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
    uint8_t msg_type;   /**< CAN_PROTO_MSG_SET_MODE */
    uint8_t eol_mode;   /**< zone_eol_mode_t value */
    uint8_t reserved[6];
} can_proto_set_mode_t;

typedef struct __attribute__((packed)) {
    uint8_t msg_type;   /**< CAN_PROTO_MSG_SCAN_REQ or response */
    uint8_t reserved[7];
} can_proto_scan_t;

typedef struct __attribute__((packed)) {
    uint8_t msg_type;  /**< CAN_PROTO_MSG_TEST_TOGGLE */
    uint8_t enable;    /**< 1 => enable, 0 => disable */
    uint8_t reserved[6];
} can_proto_test_toggle_t;

typedef struct __attribute__((packed)) {
    uint8_t protocol;                /**< CAN protocol version requested */
    uint8_t uid[CAN_PROTO_UID_LENGTH]; /**< Board hardware identifier (LSB first) */
} can_proto_addr_request_t;

typedef struct __attribute__((packed)) {
    uint8_t node_id;                 /**< Assigned CAN node id */
    uint8_t uid[CAN_PROTO_UID_LENGTH]; /**< Board hardware identifier (LSB first) */
} can_proto_addr_assign_t;

#ifdef __cplusplus
}
#endif