// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint16_t type;
    uint16_t reserved[3];
    union {
        uint16_t *wide;
        uint64_t slots[2];
    } value;
} Variant;

_Static_assert(sizeof(Variant) == 24 && offsetof(Variant, value) == 8,
               "Win64 PROPVARIANT layout");

enum { VT_EMPTY = 0, VT_LPWSTR = 31, INITIAL_UNITS = 5, GROWN_UNITS = 8 };
