// SPDX-License-Identifier: GPL-3.0-or-later

#include "../authored-session/xenora-session-v1.h"

typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

#define IMPORT __declspec(dllimport)
#define CHECK(condition) do { if (!(condition)) ExitProcess(__LINE__); } while (0)

IMPORT __declspec(noreturn) void ExitProcess(u32);
IMPORT u64 CreateEventW(void *, int, int, const u16 *);
IMPORT int SetEvent(u64);
IMPORT u32 WaitForSingleObject(u64, u32);
IMPORT u64 CreateThread(void *, u64, u32 (*)(void *), void *, u32, u32 *);
IMPORT int GetExitCodeThread(u64, u32 *);
IMPORT u32 TlsAlloc(void);
IMPORT int TlsSetValue(u32, u64);
IMPORT u64 TlsGetValue(u32);
IMPORT int TlsFree(u32);
IMPORT u64 CreateFileW(const u16 *, u32, u32, void *, u32, u32, u64);
IMPORT int WriteFile(u64, const void *, u32, u32 *, void *);
IMPORT int ReadFile(u64, void *, u32, u32 *, void *);
IMPORT int SetFilePointerEx(u64, long long, u64 *, u32);
IMPORT int CloseHandle(u64);

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
IMPORT int XenoraDestroyResource(u64);
IMPORT int XenoraDestroyCommandList(u64);
IMPORT int XenoraDestroyCommandAllocator(u64);
IMPORT int XenoraDestroyCommandQueue(u64);
IMPORT int XenoraDestroyDevice(u64);

enum { WIDTH = 4, HEIGHT = 3, MAX_FRAMES = 64, WORKER_EXIT_BASE = 0x100 };
static const u32 wait_forever = 0xffffffffu;
static const u16 journal_path[] = L"C:\\authored-worker.bin";

struct record {
    u32 sequence;
    u32 input;
};
static struct record expected[MAX_FRAMES], journal[MAX_FRAMES];
static u64 request_event, reply_event, file;
static u32 slot;
static volatile u32 request_sequence, request_input, reply_blue, stopping;

// Each fullscreen-height triangle covers one outer column of the target.
static const float vertices[2][3][4] = {
    {{-1.0f, -8.0f, 0.5f, 1.0f}, {-0.375f, 0.0f, 0.5f, 1.0f}, {-1.0f, 8.0f, 0.5f, 1.0f}},
    {{0.5f, -8.0f, 0.5f, 1.0f}, {1.125f, 0.0f, 0.5f, 1.0f}, {0.5f, 8.0f, 0.5f, 1.0f}},
};

struct graphics {
    u64 device, queue, allocator, buffer, target;
};

static void set_up(struct graphics *g) {
    CHECK(XenoraCreateDevice(&g->device) == 0);
    CHECK(XenoraCreateCommandQueue(g->device, 0, &g->queue) == 0);
    CHECK(XenoraCreateCommandAllocator(g->device, 0, &g->allocator) == 0);
    CHECK(XenoraCreateBuffer(g->device, (u64)vertices, sizeof vertices, &g->buffer) == 0);
    CHECK(XenoraCreateRenderTarget(g->device, WIDTH, HEIGHT, &g->target) == 0);
}

static void render(const struct graphics *g, u32 input, u32 sequence, u32 blue) {
    u64 list;
    const u32 side = input & 1;
    const u32 clear = 0xff000000u | (blue << 16) | (sequence << 8) | (input & 255);
    CHECK(XenoraCreateCommandList(g->device, g->allocator, 0, &list) == 0);
    CHECK(XenoraSetVertexBuffer(list, 0, g->buffer, side * sizeof vertices[0], sizeof vertices[0][0]) == 0);
    CHECK(XenoraSetRenderTarget(list, g->target, clear) == 0);
    CHECK(XenoraSetViewport(list, WIDTH, HEIGHT) == 0);
    CHECK(XenoraDraw(list, 3, 1, 0) == 0);
    CHECK(XenoraCloseCommandList(list) == 0 && XenoraExecuteCommandLists(g->queue, list) == 0);
    CHECK(XenoraDestroyCommandList(list) == 0);
}

static void tear_down(const struct graphics *g) {
    CHECK(XenoraDestroyResource(g->target) == 0 && XenoraDestroyResource(g->buffer) == 0);
    CHECK(XenoraDestroyCommandAllocator(g->allocator) == 0);
    CHECK(XenoraDestroyCommandQueue(g->queue) == 0 && XenoraDestroyDevice(g->device) == 0);
}

static u32 write_journal(void *unused) {
    (void)unused;
    CHECK(TlsGetValue(slot) == 0 && TlsSetValue(slot, 1));
    CHECK(SetEvent(reply_event));
    for (;;) {
        CHECK(WaitForSingleObject(request_event, wait_forever) == 0);
        const u32 next = (u32)TlsGetValue(slot);
        CHECK(next != 0 && next <= MAX_FRAMES + 1);
        if (stopping) return WORKER_EXIT_BASE + next - 1;
        CHECK(next == request_sequence && TlsSetValue(slot, next + 1));
        struct record record = {next, request_input};
        u32 count;
        CHECK(WriteFile(file, &record, sizeof record, &count, 0) && count == sizeof record);
        // Tie the displayed result to the full input written by this worker.
        const u32 upper_bytes = (record.input >> 8) ^ (record.input >> 16) ^ (record.input >> 24);
        reply_blue = ((0x40 + next) ^ upper_bytes) & 255;
        CHECK(SetEvent(reply_event));
    }
}

void entry(void) {
    file = CreateFileW(journal_path, 0xc0000000u, 0, 0, 2, 0, 0);
    CHECK(file != 0 && file != ~0ull);
    slot = TlsAlloc();
    CHECK(slot != 0xffffffffu && TlsSetValue(slot, 0x99));
    request_event = CreateEventW(0, 0, 0, 0);
    reply_event = CreateEventW(0, 0, 0, 0);
    CHECK(request_event && reply_event);
    const u64 thread = CreateThread(0, 0, write_journal, 0, 0, 0);
    CHECK(thread && WaitForSingleObject(reply_event, wait_forever) == 0);

    struct graphics g;
    set_up(&g);
    u32 frames = 0;
    for (;;) {
        u32 input;
        int available = XenoraSessionNextInput(&input);
        if (!available) break;
        CHECK(available == 1 && frames < MAX_FRAMES);
        expected[frames] = (struct record){frames + 1, input};
        request_sequence = ++frames;
        request_input = input;
        CHECK(SetEvent(request_event) && WaitForSingleObject(reply_event, wait_forever) == 0);
        CHECK(TlsGetValue(slot) == 0x99);
        render(&g, input, frames, reply_blue);
        CHECK(XenoraSessionPresent() == 1);
    }

    stopping = 1;
    CHECK(SetEvent(request_event) && WaitForSingleObject(thread, wait_forever) == 0);
    u32 exit_code;
    CHECK(GetExitCodeThread(thread, &exit_code) && exit_code == WORKER_EXIT_BASE + frames);
    CHECK(CloseHandle(thread) && CloseHandle(request_event) && CloseHandle(reply_event));
    CHECK(TlsFree(slot) && SetFilePointerEx(file, 0, 0, 0));
    u32 count;
    CHECK(ReadFile(file, journal, sizeof journal, &count, 0) && count == frames * sizeof journal[0]);
    for (u32 i = 0; i < frames; ++i) {
        CHECK(journal[i].sequence == expected[i].sequence && journal[i].input == expected[i].input);
    }
    unsigned char extra;
    CHECK(ReadFile(file, &extra, sizeof extra, &count, 0) && count == 0);
    CHECK(CloseHandle(file));
    tear_down(&g);
    CHECK(XenoraSessionFinish() == 1);
    ExitProcess(0);
}
