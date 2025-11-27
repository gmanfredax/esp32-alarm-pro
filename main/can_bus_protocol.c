/*
 * can_bus_protocol.c
 *
 *  Created on: Nov 26, 2025
 *      Author: gabriele
 */

#include "can_bus_protocol.h"

#include <stdbool.h>
#include <string.h>

static bool can_proto_validate_dlc(uint8_t dlc, size_t expected)
{
    return dlc == expected && expected <= 8u;
}

static void can_proto_frame_fill(can_proto_frame_t *frame, uint32_t cob_id, const void *payload,
                                 size_t payload_len)
{
    frame->cob_id = cob_id;
    frame->dlc = (uint8_t)payload_len;
    if (payload_len) {
        memcpy(frame->data, payload, payload_len);
    }
}

bool can_proto_build_heartbeat(uint8_t node_id, const can_proto_heartbeat_t *heartbeat,
                               can_proto_frame_t *out)
{
    if (!heartbeat || !out) {
        return false;
    }
    return can_proto_validate_dlc(sizeof(*heartbeat), sizeof(*heartbeat)) &&
           (can_proto_frame_fill(out, CAN_PROTO_ID_STATUS(node_id), heartbeat, sizeof(*heartbeat)),
            true);
}

bool can_proto_build_info(uint8_t node_id, const can_proto_info_t *info, can_proto_frame_t *out)
{
    if (!info || !out) {
        return false;
    }
    return can_proto_validate_dlc(sizeof(*info), sizeof(*info)) &&
           (can_proto_frame_fill(out, CAN_PROTO_ID_INFO(node_id), info, sizeof(*info)), true);
}

bool can_proto_build_output_cmd(uint8_t node_id, const can_proto_output_cmd_t *cmd,
                                can_proto_frame_t *out)
{
    if (!cmd || !out) {
        return false;
    }
    return can_proto_validate_dlc(sizeof(*cmd), sizeof(*cmd)) &&
           (can_proto_frame_fill(out, CAN_PROTO_ID_COMMAND(node_id), cmd, sizeof(*cmd)), true);
}

bool can_proto_build_test_toggle(bool enable, can_proto_frame_t *out)
{
    if (!out) {
        return false;
    }
    can_proto_test_toggle_t payload = {
        .msg_type = CAN_PROTO_MSG_TEST_TOGGLE,
        .enable = enable ? 1u : 0u,
        .reserved = {0},
    };
    return can_proto_validate_dlc(sizeof(payload), sizeof(payload)) &&
           (can_proto_frame_fill(out, CAN_PROTO_ID_BROADCAST_TEST, &payload, sizeof(payload)),
            true);
}

bool can_proto_build_scan_request(can_proto_frame_t *out)
{
    if (!out) {
        return false;
    }
    can_proto_scan_t payload = {
        .msg_type = CAN_PROTO_MSG_SCAN_REQUEST,
        .reserved = {0},
    };
    return can_proto_validate_dlc(sizeof(payload), sizeof(payload)) &&
           (can_proto_frame_fill(out, CAN_PROTO_ID_BROADCAST_SCAN, &payload, sizeof(payload)),
            true);
}

bool can_proto_build_scan_response(uint8_t node_id, can_proto_frame_t *out)
{
    if (!out) {
        return false;
    }
    can_proto_scan_t payload = {
        .msg_type = CAN_PROTO_MSG_SCAN_RESPONSE,
        .reserved = {0},
    };
    return can_proto_validate_dlc(sizeof(payload), sizeof(payload)) &&
           (can_proto_frame_fill(out, CAN_PROTO_ID_INFO(node_id), &payload, sizeof(payload)), true);
}

bool can_proto_build_addr_request(const can_proto_addr_request_t *req, can_proto_frame_t *out)
{
    if (!req || !out) {
        return false;
    }
    return can_proto_validate_dlc(sizeof(*req), sizeof(*req)) &&
           (can_proto_frame_fill(out, CAN_PROTO_ID_BROADCAST_ADDR_REQ, req, sizeof(*req)), true);
}

bool can_proto_build_addr_assign(uint8_t node_id, const can_proto_addr_assign_t *assign,
                                 can_proto_frame_t *out)
{
    if (!assign || !out) {
        return false;
    }
    return can_proto_validate_dlc(sizeof(*assign), sizeof(*assign)) &&
           (can_proto_frame_fill(out, CAN_PROTO_ID_BROADCAST_ADDR_ASSIGN, assign, sizeof(*assign)),
            true);
}

static bool can_proto_parse_from_cob(uint32_t cob_id, const uint8_t *data, uint8_t dlc,
                                     can_proto_parsed_frame_t *out)
{
    if (!out) {
        return false;
    }

    memset(out, 0, sizeof(*out));
    out->kind = CAN_PROTO_FRAME_UNKNOWN;

    if (cob_id >= CAN_PROTO_ID_STATUS_BASE && cob_id <= CAN_PROTO_ID_STATUS(CAN_PROTO_MAX_NODE_ID)) {
        out->node_id = (uint8_t)(cob_id - CAN_PROTO_ID_STATUS_BASE);
        if (dlc == sizeof(can_proto_heartbeat_t) && data[0] == CAN_PROTO_MSG_HEARTBEAT) {
            memcpy(&out->payload.heartbeat, data, sizeof(can_proto_heartbeat_t));
            out->kind = CAN_PROTO_FRAME_HEARTBEAT;
            return true;
        }
        if (dlc == sizeof(can_proto_heartbeat_t) && data[0] == CAN_PROTO_MSG_IO_REPORT) {
            memcpy(&out->payload.heartbeat, data, sizeof(can_proto_heartbeat_t));
            out->kind = CAN_PROTO_FRAME_IO_REPORT;
            return true;
        }
    } else if (cob_id >= CAN_PROTO_ID_INFO_BASE && cob_id <= CAN_PROTO_ID_INFO(CAN_PROTO_MAX_NODE_ID)) {
        out->node_id = (uint8_t)(cob_id - CAN_PROTO_ID_INFO_BASE);
        if (dlc == sizeof(can_proto_info_t) && data[0] == CAN_PROTO_MSG_INFO) {
            memcpy(&out->payload.info, data, sizeof(can_proto_info_t));
            out->kind = CAN_PROTO_FRAME_INFO;
            return true;
        }
        if (dlc == sizeof(can_proto_scan_t) && data[0] == CAN_PROTO_MSG_SCAN_RESPONSE) {
            memcpy(&out->payload.scan, data, sizeof(can_proto_scan_t));
            out->kind = CAN_PROTO_FRAME_SCAN_RESPONSE;
            return true;
        }
    } else if (cob_id >= CAN_PROTO_ID_COMMAND_BASE &&
               cob_id <= CAN_PROTO_ID_COMMAND(CAN_PROTO_MAX_NODE_ID)) {
        out->node_id = (uint8_t)(cob_id - CAN_PROTO_ID_COMMAND_BASE);
        if (dlc == sizeof(can_proto_output_cmd_t) && data[0] == CAN_PROTO_MSG_OUTPUT_COMMAND) {
            memcpy(&out->payload.output_cmd, data, sizeof(can_proto_output_cmd_t));
            out->kind = CAN_PROTO_FRAME_OUTPUT_COMMAND;
            return true;
        }
        if (dlc == sizeof(can_proto_zone_config_t) && data[0] == CAN_PROTO_MSG_ZONE_CONFIG) {
            memcpy(&out->payload.zone_config, data, sizeof(can_proto_zone_config_t));
            out->kind = CAN_PROTO_FRAME_ZONE_CONFIG;
            return true;
        }
        if (dlc == sizeof(can_proto_identify_cmd_t) && data[0] == CAN_PROTO_MSG_IDENTIFY) {
            memcpy(&out->payload.identify, data, sizeof(can_proto_identify_cmd_t));
            out->kind = CAN_PROTO_FRAME_IDENTIFY_CMD;
            return true;
        }
    } else if (cob_id == CAN_PROTO_ID_BROADCAST_SCAN) {
        if (dlc == sizeof(can_proto_scan_t) &&
            (data[0] == CAN_PROTO_MSG_SCAN_REQUEST || data[0] == CAN_PROTO_MSG_SCAN_RESPONSE)) {
            memcpy(&out->payload.scan, data, sizeof(can_proto_scan_t));
            out->kind = (data[0] == CAN_PROTO_MSG_SCAN_REQUEST) ? CAN_PROTO_FRAME_SCAN_REQUEST
                                                                 : CAN_PROTO_FRAME_SCAN_RESPONSE;
            return true;
        }
    } else if (cob_id == CAN_PROTO_ID_BROADCAST_TEST) {
        if (dlc == sizeof(can_proto_test_toggle_t) && data[0] == CAN_PROTO_MSG_TEST_TOGGLE) {
            memcpy(&out->payload.test_toggle, data, sizeof(can_proto_test_toggle_t));
            out->kind = CAN_PROTO_FRAME_TEST_TOGGLE;
            return true;
        }
    } else if (cob_id == CAN_PROTO_ID_BROADCAST_ADDR_REQ) {
        if (dlc == sizeof(can_proto_addr_request_t)) {
            memcpy(&out->payload.addr_request, data, sizeof(can_proto_addr_request_t));
            out->kind = CAN_PROTO_FRAME_ADDR_REQUEST;
            return true;
        }
    } else if (cob_id == CAN_PROTO_ID_BROADCAST_ADDR_ASSIGN) {
        if (dlc == sizeof(can_proto_addr_assign_t)) {
            memcpy(&out->payload.addr_assign, data, sizeof(can_proto_addr_assign_t));
            out->kind = CAN_PROTO_FRAME_ADDR_ASSIGN;
            return true;
        }
    } else if (cob_id >= CAN_PROTO_ID_DIAG_BASE &&
               cob_id <= CAN_PROTO_ID_DIAG(CAN_PROTO_MAX_NODE_ID)) {
        out->node_id = (uint8_t)(cob_id - CAN_PROTO_ID_DIAG_BASE);
        if (dlc == sizeof(can_proto_zone_event_t)) {
            memcpy(&out->payload.zone_event, data, sizeof(can_proto_zone_event_t));
            out->kind = CAN_PROTO_FRAME_ZONE_EVENT;
            return true;
        }
    }

    return false;
}

bool can_proto_parse(const can_proto_frame_t *frame, can_proto_parsed_frame_t *out)
{
    if (!frame || !out || frame->dlc > 8u) {
        return false;
    }
    return can_proto_parse_from_cob(frame->cob_id, frame->data, frame->dlc, out);
}
