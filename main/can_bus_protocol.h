#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file can_bus_protocol.h
 * @brief Shared definitions and helpers for the Alarm Pro CAN communication protocol.
 *
 * This header is intentionally platform-agnostic so that both the ESP32 (master)
 * and STM32F103 (expansion boards) can include it without pulling any RTOS or
 * vendor-specific headers. The companion implementation in can_bus_protocol.c
 * provides encode/decode helpers that remove ambiguity around frame layout.
 */

#define CAN_PROTO_PROTOCOL_VERSION 0x01u

#define CAN_PROTO_MODEL_IO8R8_V1   0x0101u
#define CAN_PROTO_MODEL_IO10R2_V1  0x0102u
#define CAN_PROTO_MAX_NODE_ID      0x7Fu

// ------------------------
// COB-ID layout
// ------------------------

#define CAN_PROTO_ID_STATUS_BASE   0x180u
#define CAN_PROTO_ID_INFO_BASE     0x280u
#define CAN_PROTO_ID_COMMAND_BASE  0x380u
#define CAN_PROTO_ID_DIAG_BASE     0x480u

#define CAN_PROTO_ID_EXT_HEARTBEAT_BASE 0x100u
#define CAN_PROTO_ID_EXT_ZONE_BASE      0x120u

#define CAN_PROTO_ID_STATUS(node_id)  (CAN_PROTO_ID_STATUS_BASE + (node_id))
#define CAN_PROTO_ID_INFO(node_id)    (CAN_PROTO_ID_INFO_BASE + (node_id))
#define CAN_PROTO_ID_COMMAND(node_id) (CAN_PROTO_ID_COMMAND_BASE + (node_id))
#define CAN_PROTO_ID_DIAG(node_id)    (CAN_PROTO_ID_DIAG_BASE + (node_id))
#define CAN_PROTO_ID_EXT_HEARTBEAT(node_id) (CAN_PROTO_ID_EXT_HEARTBEAT_BASE + (node_id))
#define CAN_PROTO_ID_EXT_ZONE_EVENT(node_id) (CAN_PROTO_ID_EXT_ZONE_BASE + (node_id))

#define CAN_PROTO_ID_BROADCAST_SCAN        0x070u
#define CAN_PROTO_ID_BROADCAST_TEST        0x071u
#define CAN_PROTO_ID_BROADCAST_ADDR_REQ    0x072u
#define CAN_PROTO_ID_BROADCAST_ADDR_ASSIGN 0x073u

#define CAN_PROTO_UID_LENGTH 7u

typedef enum {
    CAN_PROTO_MSG_HEARTBEAT      = 0x01u,
    CAN_PROTO_MSG_IO_REPORT      = 0x02u,
    CAN_PROTO_MSG_INFO           = 0x10u,
    CAN_PROTO_MSG_OUTPUT_COMMAND = 0x20u,
    CAN_PROTO_MSG_IDENTIFY       = 0x21u,
    CAN_PROTO_MSG_ZONE_CONFIG    = 0x22u,
    CAN_PROTO_MSG_TEST_TOGGLE    = 0x30u,
    CAN_PROTO_MSG_SCAN_REQUEST   = 0x31u,
    CAN_PROTO_MSG_SCAN_RESPONSE  = 0x32u,
    CAN_PROTO_MSG_ACK            = 0x7Fu,
} can_proto_msg_type_t;

#define CAN_PROTO_NODE_STATE_WARNING_VBIAS 0x01u

typedef enum {
    CAN_ZONE_MEASURE_MODE_EOL   = 0,
    CAN_ZONE_MEASURE_MODE_2EOL  = 1,
    CAN_ZONE_MEASURE_MODE_3EOL  = 2,
} can_zone_measure_mode_t;

#define CAN_ZONE_CONTACT_FLAG_IS_NO   (1u << 0)

#define CAN_ZONE_MEASURE_MODE_IS_VALID(mode) \
    ((mode) == CAN_ZONE_MEASURE_MODE_EOL || (mode) == CAN_ZONE_MEASURE_MODE_2EOL || \
     (mode) == CAN_ZONE_MEASURE_MODE_3EOL)

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
    uint8_t  msg_type;      /**< CAN_PROTO_MSG_ZONE_CONFIG */
    uint8_t  zone_index;    /**< Target zone (0-based) */
    uint8_t  measure_mode;  /**< can_zone_measure_mode_t */
    uint8_t  contact_flags; /**< CAN_ZONE_CONTACT_FLAG_* */
    uint16_t r_normal_ohm;  /**< Reference normal resistor value */
    uint16_t r_alarm_ohm;   /**< Alarm resistor contribution */
} can_proto_zone_config_t;

typedef struct __attribute__((packed)) {
    uint8_t msg_type;   /**< CAN_PROTO_MSG_SCAN_REQUEST or response */
    uint8_t reserved[7];
} can_proto_scan_t;

typedef struct __attribute__((packed)) {
    uint8_t msg_type;  /**< CAN_PROTO_MSG_TEST_TOGGLE */
    uint8_t enable;    /**< 1 => enable, 0 => disable */
    uint8_t reserved[6];
} can_proto_test_toggle_t;

typedef struct __attribute__((packed)) {
    uint8_t protocol;                  /**< CAN protocol version requested */
    uint8_t uid[CAN_PROTO_UID_LENGTH]; /**< Board hardware identifier (LSB first) */
} can_proto_addr_request_t;

typedef struct __attribute__((packed)) {
    uint8_t node_id;                   /**< Assigned CAN node id */
    uint8_t uid[CAN_PROTO_UID_LENGTH]; /**< Board hardware identifier (LSB first) */
} can_proto_addr_assign_t;

typedef struct __attribute__((packed)) {
    uint8_t alarm_bitmap;
    uint8_t short_bitmap;
    uint8_t open_bitmap;
    uint8_t tamper_bitmap;
    uint8_t vdda_100mv;
    uint8_t vbias_10mv;
    uint8_t temperature_c_plus40;
    uint8_t fw_nibbles;
} can_proto_ext_heartbeat_t;

typedef struct __attribute__((packed)) {
    uint8_t zone_id;
    uint8_t state_bits; /**< CAN_PROTO_ZONE_EVENT_STATE_* flags */
    uint16_t raw_adc;
    uint16_t rloop_ohm_div100;
    uint8_t vbias_10mv;
    uint8_t seq;
} can_proto_zone_event_t;

#define CAN_PROTO_ZONE_EVENT_STATE_ALARM      (1u << 0)
#define CAN_PROTO_ZONE_EVENT_STATE_SHORT      (1u << 1)
#define CAN_PROTO_ZONE_EVENT_STATE_OPEN       (1u << 2)
#define CAN_PROTO_ZONE_EVENT_STATE_TAMPER     (1u << 3)
#define CAN_PROTO_ZONE_EVENT_STATE_PRESENT    (1u << 4)
#define CAN_PROTO_ZONE_EVENT_STATE_CONTACT_NO (1u << 5)

/**
 * Lightweight representation of a CAN frame, independent from ESP-IDF or
 * STM32 HAL types. This allows sharing the encoder/decoder between platforms.
 */
typedef struct {
    uint32_t cob_id;
    uint8_t  dlc;
    uint8_t  data[8];
} can_proto_frame_t;

/**
 * Canonical list of frame kinds understood by the Alarm Pro CAN stack. The
 * enum differentiates messages that share the same COB-ID range but use a
 * different payload layout (e.g. heartbeat vs IO report).
 */
typedef enum {
    CAN_PROTO_FRAME_HEARTBEAT,
    CAN_PROTO_FRAME_IO_REPORT,
    CAN_PROTO_FRAME_INFO,
    CAN_PROTO_FRAME_OUTPUT_COMMAND,
    CAN_PROTO_FRAME_IDENTIFY_CMD,
    CAN_PROTO_FRAME_ZONE_CONFIG,
    CAN_PROTO_FRAME_EXT_HEARTBEAT,
    CAN_PROTO_FRAME_EXT_ZONE_EVENT,
    CAN_PROTO_FRAME_TEST_TOGGLE,
    CAN_PROTO_FRAME_SCAN_REQUEST,
    CAN_PROTO_FRAME_SCAN_RESPONSE,
    CAN_PROTO_FRAME_ADDR_REQUEST,
    CAN_PROTO_FRAME_ADDR_ASSIGN,
    CAN_PROTO_FRAME_UNKNOWN,
} can_proto_frame_kind_t;

typedef struct {
    can_proto_frame_kind_t kind;
    uint8_t node_id; /**< 0 for broadcast frames */
    union {
        can_proto_heartbeat_t   heartbeat;
        can_proto_info_t        info;
        can_proto_output_cmd_t  output_cmd;
        can_proto_identify_cmd_t identify;
        can_proto_zone_config_t zone_config;
        can_proto_ext_heartbeat_t ext_heartbeat;
        can_proto_zone_event_t  zone_event;
        can_proto_scan_t        scan;
        can_proto_test_toggle_t test_toggle;
        can_proto_addr_request_t addr_request;
        can_proto_addr_assign_t  addr_assign;
    } payload;
} can_proto_parsed_frame_t;

/**
 * Encode helpers: populate `out` with a fully formed COB-ID, DLC and payload.
 */
bool can_proto_build_heartbeat(uint8_t node_id, const can_proto_heartbeat_t *heartbeat,
                               can_proto_frame_t *out);
bool can_proto_build_info(uint8_t node_id, const can_proto_info_t *info, can_proto_frame_t *out);
bool can_proto_build_output_cmd(uint8_t node_id, const can_proto_output_cmd_t *cmd,
                                can_proto_frame_t *out);
bool can_proto_build_test_toggle(bool enable, can_proto_frame_t *out);
bool can_proto_build_scan_request(can_proto_frame_t *out);
bool can_proto_build_scan_response(uint8_t node_id, can_proto_frame_t *out);
bool can_proto_build_addr_request(const can_proto_addr_request_t *req, can_proto_frame_t *out);
bool can_proto_build_addr_assign(uint8_t node_id, const can_proto_addr_assign_t *assign,
                                 can_proto_frame_t *out);

/**
 * Parse a raw frame into a structured representation. Returns false if the
 * payload length or COB-ID does not match the protocol expectations.
 */
bool can_proto_parse(const can_proto_frame_t *frame, can_proto_parsed_frame_t *out);

#ifdef __cplusplus
}
#endif