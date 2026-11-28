// SPDX-License-Identifier: GPL-3.0-or-later

#include "ownership.h"

__declspec(dllimport) void *CoTaskMemRealloc(void *, size_t);
__declspec(dllimport) int32_t PropVariantClear(Variant *);

__declspec(dllexport) int GrowText(uint16_t **inout, size_t units) {
    // SIZE_MAX is a deliberate allocation failure, independent of available
    // host memory. The valid path supplies a small count of UTF-16 units.
    const size_t bytes = units == SIZE_MAX ? SIZE_MAX : units * sizeof **inout;
    uint16_t *grown = CoTaskMemRealloc(*inout, bytes);
    if (!grown)
        return 0;
    *inout = grown;
    return 1;
}

__declspec(dllexport) int32_t ClearVariant(Variant *inout) {
    return PropVariantClear(inout);
}
