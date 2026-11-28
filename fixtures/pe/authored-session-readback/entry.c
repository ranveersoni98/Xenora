// SPDX-License-Identifier: GPL-3.0-or-later

#include "../authored-session/xenora-session-v1.h"

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
#define IMPORT __declspec(dllimport)
#define CHECK(condition) do { if (!(condition)) ExitProcess(__LINE__); } while (0)

IMPORT __declspec(noreturn) void ExitProcess(u32);
IMPORT int XenoraCreateDevice(u64 *);
IMPORT int XenoraCreateCommandQueue(u64, u32, u64 *);
IMPORT int XenoraCreateCommandAllocator(u64, u32, u64 *);
IMPORT int XenoraCreateBuffer(u64, u64, u64, u64 *);
IMPORT int XenoraCreateRenderTarget(u64, u32, u32, u64 *);
IMPORT int XenoraCreateCommandList(u64, u64, u32, u64 *);
IMPORT int XenoraSetVertexBuffer(u64, u32, u64, u64, u64);
IMPORT int XenoraSetRenderTarget(u64, u64, u32);
IMPORT int XenoraSetViewport(u64, u32, u32);
IMPORT int XenoraDraw(u64, u32, u32, u32);
IMPORT int XenoraCloseCommandList(u64);
IMPORT int XenoraExecuteCommandLists(u64, u64);
IMPORT int XenoraReadbackResource(u64, u64, u64);
IMPORT int XenoraDestroyResource(u64);
IMPORT int XenoraDestroyCommandList(u64);
IMPORT int XenoraDestroyCommandAllocator(u64);
IMPORT int XenoraDestroyCommandQueue(u64);
IMPORT int XenoraDestroyDevice(u64);

enum { WIDTH = 4, HEIGHT = 3, RGBA_BYTES = WIDTH * HEIGHT * 4, GUARD = 0xa5 };
static const u32 invalid_argument = 0x80070057u;
static const u32 clear = 0xff332211u;
static const u8 read_only_guard[4] = {GUARD, GUARD, GUARD, GUARD};
static const float left_column[3][4] = {
    {-1.0f, -8.0f, 0.5f, 1.0f}, {-0.375f, 0.0f, 0.5f, 1.0f}, {-1.0f, 8.0f, 0.5f, 1.0f},
};
static const u8 row[WIDTH * 4] = {
    0xff, 0, 0, 0xff, 0x11, 0x22, 0x33, 0xff,
    0x11, 0x22, 0x33, 0xff, 0x11, 0x22, 0x33, 0xff,
};

static void verify_readback(u64 target) {
    u8 bytes[RGBA_BYTES + 4 + 2];
    const u64 output = (u64)&bytes[1];
    for (u32 i = 0; i < sizeof bytes; ++i) bytes[i] = GUARD;

    const u32 oversized = (u32)XenoraReadbackResource(target, output, RGBA_BYTES + 4);
    if (oversized == 0 && bytes[1] == row[0] && bytes[RGBA_BYTES + 1] == GUARD)
        ExitProcess(84);  // Baseline short-success discriminator.
    CHECK(oversized == invalid_argument);
    for (u32 i = 0; i < sizeof bytes; ++i) CHECK(bytes[i] == GUARD);

    CHECK((u32)XenoraReadbackResource(target, output, 0) == invalid_argument);
    for (u32 i = 0; i < sizeof bytes; ++i) CHECK(bytes[i] == GUARD);

    CHECK((u32)XenoraReadbackResource(target, (u64)read_only_guard, sizeof read_only_guard) == invalid_argument);
    const volatile u8 *untouched = read_only_guard;
    for (u32 i = 0; i < sizeof read_only_guard; ++i) CHECK(untouched[i] == GUARD);

    CHECK(XenoraReadbackResource(target, output, 7) == 0);
    CHECK(bytes[0] == GUARD);
    for (u32 i = 0; i < 7; ++i) CHECK(bytes[i + 1] == row[i]);
    for (u32 i = 8; i < sizeof bytes; ++i) CHECK(bytes[i] == GUARD);

    CHECK(XenoraReadbackResource(target, output, RGBA_BYTES) == 0);
    CHECK(bytes[0] == GUARD);
    for (u32 i = 0; i < RGBA_BYTES; ++i) CHECK(bytes[i + 1] == row[i % sizeof row]);
    for (u32 i = RGBA_BYTES + 1; i < sizeof bytes; ++i) CHECK(bytes[i] == GUARD);
}

void entry(void) {
    u64 device, queue, allocator, vertex_buffer, target, list;
    CHECK(XenoraCreateDevice(&device) == 0);
    CHECK(XenoraCreateCommandQueue(device, 0, &queue) == 0);
    CHECK(XenoraCreateCommandAllocator(device, 0, &allocator) == 0);
    CHECK(XenoraCreateBuffer(device, (u64)left_column, sizeof left_column, &vertex_buffer) == 0);
    CHECK(XenoraCreateRenderTarget(device, WIDTH, HEIGHT, &target) == 0);

    u32 input;
    CHECK(XenoraSessionNextInput(&input) == 1 && input == 10);
    CHECK(XenoraCreateCommandList(device, allocator, 0, &list) == 0);
    CHECK(XenoraSetVertexBuffer(list, 0, vertex_buffer, 0, sizeof left_column[0]) == 0);
    CHECK(XenoraSetRenderTarget(list, target, clear) == 0);
    CHECK(XenoraSetViewport(list, WIDTH, HEIGHT) == 0);
    CHECK(XenoraDraw(list, 3, 1, 0) == 0);
    CHECK(XenoraCloseCommandList(list) == 0);
    CHECK(XenoraExecuteCommandLists(queue, list) == 0);
    verify_readback(target);
    CHECK(XenoraDestroyCommandList(list) == 0);
    CHECK(XenoraSessionPresent() == 1);

    CHECK(XenoraSessionNextInput(&input) == 0);
    CHECK(XenoraDestroyResource(target) == 0 && XenoraDestroyResource(vertex_buffer) == 0);
    CHECK(XenoraDestroyCommandAllocator(allocator) == 0);
    CHECK(XenoraDestroyCommandQueue(queue) == 0 && XenoraDestroyDevice(device) == 0);
    CHECK(XenoraSessionFinish() == 1);
    ExitProcess(0);
}
