// SPDX-License-Identifier: GPL-3.0-or-later

#include "ownership.h"

__declspec(dllimport) int ProduceText(uint16_t, uint16_t **);
__declspec(dllimport) int ProduceVariant(Variant *);
__declspec(dllimport) int GrowText(uint16_t **, size_t);
__declspec(dllimport) int32_t ClearVariant(Variant *);
__declspec(dllimport) void CoTaskMemFree(void *);
__declspec(dllimport) uint32_t GetLastError(void);
__declspec(dllimport) void ExitProcess(unsigned);

typedef struct {
    uint64_t base;
    uint64_t allocation_base;
    uint32_t allocation_protect;
    uint16_t partition_id;
    uint64_t size;
    uint32_t state;
    uint32_t protect;
    uint32_t type;
} Region;

_Static_assert(sizeof(Region) == 48 && offsetof(Region, size) == 24 &&
               offsetof(Region, state) == 32, "Win64 MEMORY_BASIC_INFORMATION layout");

__declspec(dllimport) size_t VirtualQuery(const void *, Region *, size_t);

static int matches(const uint16_t *text, uint16_t first) {
    return text[0] == first && text[1] == 0x03a9 && text[2] == '!' &&
           text[3] == 0 && text[4] == 0xb17e;
}

static int mapped(uintptr_t address, size_t bytes) {
    Region region;
    return VirtualQuery((const void *)address, &region, sizeof region) == sizeof region &&
           region.base == address && region.size == bytes && region.state == 0x1000;
}

static int released(uintptr_t address) {
    // Xenora's bounded VirtualQuery reports an uncommitted address as
    // ERROR_INVALID_ADDRESS. This is an observation of the guest mapping.
    Region region;
    return VirtualQuery((const void *)address, &region, sizeof region) == 0 &&
           GetLastError() == 487;
}

static unsigned check(void) {
    uint16_t *text, *neighbor;
    if (!ProduceText('A', &text) || !ProduceText('B', &neighbor))
        return 10;
    const uintptr_t original = (uintptr_t)text;
    const uintptr_t neighbor_address = (uintptr_t)neighbor;
    const size_t initial_bytes = INITIAL_UNITS * sizeof *text;
    if (original == neighbor_address || !mapped(original, initial_bytes) ||
        !mapped(neighbor_address, initial_bytes) || !matches(text, 'A') ||
        !matches(neighbor, 'B'))
        return 11;
    if (GrowText(&text, SIZE_MAX) || (uintptr_t)text != original ||
        !mapped(original, initial_bytes) || !matches(text, 'A') || !matches(neighbor, 'B'))
        return 12;
    if (!GrowText(&text, GROWN_UNITS) || !matches(text, 'A') || !matches(neighbor, 'B'))
        return 13;

    const uintptr_t grown = (uintptr_t)text;
    if (!mapped(grown, GROWN_UNITS * sizeof *text))
        return 14;
    if (grown != original && !released(original))
        return 15;
    text[5] = 'X';
    text[6] = 'Y';
    text[7] = 0;
    if (((volatile uint16_t *)text)[5] != 'X' ||
        ((volatile uint16_t *)text)[6] != 'Y' ||
        ((volatile uint16_t *)text)[7] != 0)
        return 16;
    CoTaskMemFree(text);
    if (!released(grown) || !mapped(neighbor_address, initial_bytes) || !matches(neighbor, 'B'))
        return 17;

    Variant variant = {0};
    if (!ProduceVariant(&variant) || variant.type != VT_LPWSTR || !matches(variant.value.wide, 'V'))
        return 18;
    const uintptr_t payload = (uintptr_t)variant.value.wide;
    if (payload == neighbor_address || !mapped(payload, initial_bytes))
        return 19;
    if (ClearVariant(&variant) != 0 || variant.type != VT_EMPTY || !released(payload))
        return 20;
    if (ClearVariant(&variant) != 0 || variant.type != VT_EMPTY ||
        !mapped(neighbor_address, initial_bytes) || !matches(neighbor, 'B'))
        return 21;

    CoTaskMemFree(neighbor);
    return released(neighbor_address) ? 0 : 22;
}

void entry(void) {
    static unsigned entered;
    ExitProcess(entered++ == 0 ? check() : 23);
}
