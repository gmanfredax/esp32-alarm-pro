#include "zone_eol.h"

#include <math.h>

static float clamp_ratio(float ratio)
{
    if (ratio < 0.0f) {
        return 0.0f;
    }
    if (ratio > 1.0f) {
        return 1.0f;
    }
    return ratio;
}

zone_line_state_t zone_eol_classify(zone_eol_mode_t mode, float ratio)
{
    ratio = clamp_ratio(ratio);

    switch (mode) {
    case ZONE_EOL_DISABLED:
        return (ratio > 0.8f) ? ZONE_LINE_ALARM : ZONE_LINE_SECURE;

    case ZONE_EOL_SINGLE:
        if (ratio >= 0.9f) {
            return ZONE_LINE_TAMPER_OPEN;
        }
        if (ratio <= 0.1f) {
            return ZONE_LINE_TAMPER_SHORT;
        }
        if (ratio >= 0.55f) {
            return ZONE_LINE_ALARM;
        }
        return ZONE_LINE_SECURE;

    case ZONE_EOL_DOUBLE:
        if (ratio >= 0.92f) {
            return ZONE_LINE_TAMPER_OPEN;
        }
        if (ratio <= 0.08f) {
            return ZONE_LINE_TAMPER_SHORT;
        }
        if (ratio >= 0.58f && ratio <= 0.78f) {
            return ZONE_LINE_ALARM;
        }
        if (ratio >= 0.32f && ratio <= 0.50f) {
            return ZONE_LINE_SECURE;
        }
        return ZONE_LINE_FAULT;

    case ZONE_EOL_TRIPLE:
        if (ratio >= 0.95f) {
            return ZONE_LINE_TAMPER_OPEN;
        }
        if (ratio <= 0.05f) {
            return ZONE_LINE_TAMPER_SHORT;
        }
        if (ratio >= 0.62f && ratio <= 0.82f) {
            return ZONE_LINE_ALARM;
        }
        if (ratio >= 0.38f && ratio <= 0.58f) {
            return ZONE_LINE_SECURE;
        }
        if (ratio >= 0.18f && ratio <= 0.30f) {
            return ZONE_LINE_FAULT;
        }
        return ZONE_LINE_FAULT;
    }

    return ZONE_LINE_UNKNOWN;
}