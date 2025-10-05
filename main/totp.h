#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef TOTP_STEP_SECONDS
#define TOTP_STEP_SECONDS    30
#endif

#ifndef TOTP_WINDOW_STEPS
#define TOTP_WINDOW_STEPS    1
#endif

bool totp_check(const char* base32_secret, const char* otp6, int step_seconds, int window);

#ifdef __cplusplus
}
#endif