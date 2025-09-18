#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool totp_check(const char* base32_secret, const char* otp6);

#ifdef __cplusplus
}
#endif