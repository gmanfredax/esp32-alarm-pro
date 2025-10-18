#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ZONE_MASK_CAPACITY
#define ZONE_MASK_CAPACITY 512u
#endif

#define ZONE_MASK_WORDS ((ZONE_MASK_CAPACITY + 31u) / 32u)

typedef struct {
    uint32_t words[ZONE_MASK_WORDS];
} zone_mask_t;

static inline void zone_mask_clear(zone_mask_t *mask)
{
    if (mask) {
        memset(mask->words, 0, sizeof(mask->words));
    }
}

static inline void zone_mask_copy(zone_mask_t *dst, const zone_mask_t *src)
{
    if (!dst || !src) {
        return;
    }
    memcpy(dst->words, src->words, sizeof(dst->words));
}

static inline bool zone_mask_equal(const zone_mask_t *a, const zone_mask_t *b)
{
    if (a == b) {
        return true;
    }
    if (!a || !b) {
        return false;
    }
    for (size_t i = 0; i < ZONE_MASK_WORDS; ++i) {
        if (a->words[i] != b->words[i]) {
            return false;
        }
    }
    return true;
}

static inline size_t zone_mask_required_words(uint16_t zone_count)
{
    size_t words = (zone_count + 31u) / 32u;
    if (words > ZONE_MASK_WORDS) {
        words = ZONE_MASK_WORDS;
    }
    return words;
}

static inline void zone_mask_limit(zone_mask_t *mask, uint16_t zone_count)
{
    if (!mask) {
        return;
    }
    size_t words = zone_mask_required_words(zone_count);
    for (size_t i = words; i < ZONE_MASK_WORDS; ++i) {
        mask->words[i] = 0u;
    }
    if (words == 0) {
        return;
    }
    uint32_t keep = (zone_count % 32u);
    if (keep == 0u) {
        return;
    }
    uint32_t mask_keep = (keep >= 32u) ? 0xFFFFFFFFu : ((1u << keep) - 1u);
    mask->words[words - 1u] &= mask_keep;
}

static inline void zone_mask_fill(zone_mask_t *mask, uint16_t zone_count)
{
    if (!mask) {
        return;
    }
    zone_mask_clear(mask);
    size_t words = zone_mask_required_words(zone_count);
    size_t full_words = zone_count / 32u;
    for (size_t i = 0; i < full_words && i < ZONE_MASK_WORDS; ++i) {
        mask->words[i] = 0xFFFFFFFFu;
    }
    if (full_words < words) {
        uint32_t remain = zone_count % 32u;
        if (remain == 0u) {
            mask->words[full_words] = 0xFFFFFFFFu;
        } else {
            mask->words[full_words] = (1u << remain) - 1u;
        }
    }
    for (size_t i = words; i < ZONE_MASK_WORDS; ++i) {
        mask->words[i] = 0u;
    }
}

static inline void zone_mask_set(zone_mask_t *mask, uint16_t index)
{
    if (!mask || index >= ZONE_MASK_CAPACITY) {
        return;
    }
    mask->words[index / 32u] |= (1u << (index % 32u));
}

static inline void zone_mask_clear_bit(zone_mask_t *mask, uint16_t index)
{
    if (!mask || index >= ZONE_MASK_CAPACITY) {
        return;
    }
    mask->words[index / 32u] &= ~(1u << (index % 32u));
}

static inline bool zone_mask_test(const zone_mask_t *mask, uint16_t index)
{
    if (!mask || index >= ZONE_MASK_CAPACITY) {
        return false;
    }
    return (mask->words[index / 32u] & (1u << (index % 32u))) != 0u;
}

static inline bool zone_mask_any(const zone_mask_t *mask)
{
    if (!mask) {
        return false;
    }
    for (size_t i = 0; i < ZONE_MASK_WORDS; ++i) {
        if (mask->words[i] != 0u) {
            return true;
        }
    }
    return false;
}

static inline bool zone_mask_intersects(const zone_mask_t *a, const zone_mask_t *b)
{
    if (!a || !b) {
        return false;
    }
    for (size_t i = 0; i < ZONE_MASK_WORDS; ++i) {
        if ((a->words[i] & b->words[i]) != 0u) {
            return true;
        }
    }
    return false;
}

static inline void zone_mask_or(zone_mask_t *dst, const zone_mask_t *a, const zone_mask_t *b)
{
    if (!dst || !a || !b) {
        return;
    }
    for (size_t i = 0; i < ZONE_MASK_WORDS; ++i) {
        dst->words[i] = a->words[i] | b->words[i];
    }
}

static inline void zone_mask_and(zone_mask_t *dst, const zone_mask_t *a, const zone_mask_t *b)
{
    if (!dst || !a || !b) {
        return;
    }
    for (size_t i = 0; i < ZONE_MASK_WORDS; ++i) {
        dst->words[i] = a->words[i] & b->words[i];
    }
}

static inline void zone_mask_andnot(zone_mask_t *dst, const zone_mask_t *a, const zone_mask_t *b)
{
    if (!dst || !a || !b) {
        return;
    }
    for (size_t i = 0; i < ZONE_MASK_WORDS; ++i) {
        dst->words[i] = a->words[i] & ~b->words[i];
    }
}

static inline uint32_t zone_mask_to_u32(const zone_mask_t *mask)
{
    if (!mask) {
        return 0u;
    }
    return mask->words[0];
}

static inline void zone_mask_from_u32(zone_mask_t *mask, uint32_t value)
{
    if (!mask) {
        return;
    }
    mask->words[0] = value;
    for (size_t i = 1; i < ZONE_MASK_WORDS; ++i) {
        mask->words[i] = 0u;
    }
}

static inline size_t zone_mask_hex_length(uint16_t zone_count)
{
    size_t words = zone_mask_required_words(zone_count);
    if (words == 0) {
        return 1; // "0"
    }
    return words * 8u;
}

static inline void zone_mask_to_hex(const zone_mask_t *mask, uint16_t zone_count, char *buf, size_t buf_len)
{
    if (!buf || buf_len == 0) {
        return;
    }
    buf[0] = '\0';
    if (!mask) {
        return;
    }
    size_t words = zone_mask_required_words(zone_count);
    if (words == 0) {
        if (buf_len > 1) {
            buf[0] = '0';
            buf[1] = '\0';
        }
        return;
    }
    size_t pos = 0;
    for (size_t idx = 0; idx < words; ++idx) {
        size_t word_index = words - 1u - idx;
        if (pos + 8u >= buf_len) {
            break;
        }
        snprintf(&buf[pos], buf_len - pos, "%08" PRIX32, mask->words[word_index]);
        pos += 8u;
    }
    if (pos == 0) {
        if (buf_len > 1) {
            buf[0] = '0';
            buf[1] = '\0';
        }
        return;
    }
    // Trim leading zeros keeping at least one digit
    size_t start = 0;
    while (start + 1u < pos && buf[start] == '0') {
        ++start;
    }
    if (start > 0) {
        memmove(buf, buf + start, pos - start);
        pos -= start;
    }
    if (pos < buf_len) {
        buf[pos] = '\0';
    } else {
        buf[buf_len - 1u] = '\0';
    }
}

static inline bool zone_mask_from_hex(zone_mask_t *mask, const char *hex)
{
    if (!mask) {
        return false;
    }
    zone_mask_clear(mask);
    if (!hex) {
        return false;
    }
    // Skip leading whitespace
    while (*hex == ' ' || *hex == '\t' || *hex == '\n' || *hex == '\r') {
        ++hex;
    }
    if (*hex == '\0') {
        return true;
    }
    size_t len = strlen(hex);
    size_t max_chars = ZONE_MASK_WORDS * 8u;
    if (len > max_chars) {
        hex += len - max_chars;
        len = max_chars;
    }
    size_t idx = 0;
    while (idx < len) {
        size_t remaining = len - idx;
        size_t chunk = remaining >= 8u ? 8u : remaining;
        uint32_t value = 0u;
        for (size_t i = 0; i < chunk; ++i) {
            char c = hex[len - idx - chunk + i];
            value <<= 4;
            if (c >= '0' && c <= '9') value |= (uint32_t)(c - '0');
            else if (c >= 'a' && c <= 'f') value |= (uint32_t)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') value |= (uint32_t)(c - 'A' + 10);
            else return false;
        }
        size_t word_index = idx / 8u;
        if (word_index < ZONE_MASK_WORDS) {
            mask->words[word_index] = value;
        }
        idx += chunk;
    }
    return true;
}

#ifdef __cplusplus
}
#endif