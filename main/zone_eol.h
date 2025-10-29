#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ZONE_EOL_DISABLED = 0,
    ZONE_EOL_SINGLE   = 1,
    ZONE_EOL_DOUBLE   = 2,
    ZONE_EOL_TRIPLE   = 3,
} zone_eol_mode_t;

typedef enum {
    ZONE_LINE_UNKNOWN = 0,
    ZONE_LINE_SECURE,
    ZONE_LINE_ALARM,
    ZONE_LINE_TAMPER_OPEN,
    ZONE_LINE_TAMPER_SHORT,
    ZONE_LINE_FAULT,
} zone_line_state_t;

typedef struct {
    zone_line_state_t state;
    zone_eol_mode_t   mode;
    float             ratio;     /**< Normalized ADC reading (0..1) */
    int32_t           millivolts;/**< Raw reading in millivolts */
    bool              valid;
} zone_eol_result_t;

/**
 * @brief Classify a normalized ADC reading according to the configured mode.
 *
 * The ratio value must be in the range [0, 1]. Values outside the range are
 * automatically clamped before classification.
 */
zone_line_state_t zone_eol_classify(zone_eol_mode_t mode, float ratio);

/**
 * @brief Helper to build a result structure from a raw measurement.
 */
static inline zone_eol_result_t zone_eol_build_result(zone_eol_mode_t mode,
                                                      int32_t millivolts,
                                                      float supply_mv)
{
    zone_eol_result_t res = {
        .mode = mode,
        .millivolts = millivolts,
        .valid = (supply_mv > 0.0f),
        .ratio = 0.0f,
        .state = ZONE_LINE_UNKNOWN,
    };
    if (res.valid) {
        float ratio = (float)millivolts / supply_mv;
        if (ratio < 0.0f) ratio = 0.0f;
        if (ratio > 1.0f) ratio = 1.0f;
        res.ratio = ratio;
        res.state = zone_eol_classify(mode, ratio);
    }
    return res;
}

static inline const char *zone_line_state_name(zone_line_state_t st)
{
    switch (st) {
    case ZONE_LINE_SECURE:       return "secure";
    case ZONE_LINE_ALARM:        return "alarm";
    case ZONE_LINE_TAMPER_OPEN:  return "tamper_open";
    case ZONE_LINE_TAMPER_SHORT: return "tamper_short";
    case ZONE_LINE_FAULT:        return "fault";
    case ZONE_LINE_UNKNOWN:
    default:
        return "unknown";
    }
}

#ifdef __cplusplus
}
#endif