// SPDX-License-Identifier: GPL-3.0-or-later

#include "ownership.h"

__declspec(dllimport) void *CoTaskMemAlloc(size_t);

__declspec(dllexport) int ProduceText(uint16_t first, uint16_t **out) {
    uint16_t *text = CoTaskMemAlloc(INITIAL_UNITS * sizeof *text);
    *out = text;
    if (!text)
        return 0;
    text[0] = first;
    text[1] = 0x03a9;
    text[2] = '!';
    text[3] = 0;
    text[4] = 0xb17e;
    return 1;
}

__declspec(dllexport) int ProduceVariant(Variant *out) {
    uint16_t *text;
    if (!ProduceText('V', &text))
        return 0;
    out->type = VT_LPWSTR;
    out->value.wide = text;
    return 1;
}
