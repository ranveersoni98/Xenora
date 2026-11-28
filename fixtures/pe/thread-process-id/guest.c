// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdint.h>

typedef void *Handle;
typedef uint32_t Dword;
typedef Dword (*ThreadStart)(void *);

__declspec(dllimport) Dword GetProcessIdOfThread(Handle);
__declspec(dllimport) Dword GetCurrentProcessId(void);
__declspec(dllimport) Handle GetCurrentThread(void);
__declspec(dllimport) Dword GetCurrentThreadId(void);
__declspec(dllimport) Handle OpenThread(Dword, int, Dword);
__declspec(dllimport) Handle CreateThread(void *, uint64_t, ThreadStart, void *, Dword, Dword *);
__declspec(dllimport) Handle CreateEventW(void *, int, int, const uint16_t *);
__declspec(dllimport) int SetEvent(Handle);
__declspec(dllimport) Dword WaitForSingleObject(Handle, Dword);
__declspec(dllimport) int GetExitCodeThread(Handle, Dword *);
__declspec(dllimport) int CloseHandle(Handle);
__declspec(dllimport) Dword GetLastError(void);
__declspec(dllimport) void SetLastError(Dword);
__declspec(dllimport) void ExitProcess(Dword);

enum {
    QUERY_INFORMATION = 0x0040,
    QUERY_LIMITED_INFORMATION = 0x0800,
    SYNCHRONIZE = 0x00100000,
    ACCESS_DENIED = 5,
    INVALID_HANDLE = 6,
    WAIT_SIGNALED = 0,
    WAIT_TIMEOUT = 258
};

typedef struct {
    Handle ready;
    Handle release;
    Dword process;
} Worker;

static Dword worker_main(void *context) {
    const Worker *worker = context;
    if (GetProcessIdOfThread(GetCurrentThread()) != worker->process)
        return 31;
    if (!SetEvent(worker->ready))
        return 32;
    return WaitForSingleObject(worker->release, UINT32_MAX) == WAIT_SIGNALED ? 0 : 33;
}

static int denied(Handle handle, Dword expected) {
    SetLastError(0);
    return GetProcessIdOfThread(handle) == 0 && GetLastError() == expected;
}

static Dword check(void) {
    const Dword process = GetCurrentProcessId();
    const Handle self = GetCurrentThread();
    // Xenora preserves the thread's last error on a successful query.
    SetLastError(0x5a5a);
    if (!process || GetProcessIdOfThread(self) != process || GetLastError() != 0x5a5a)
        return 10;

    const Dword main_id = GetCurrentThreadId();
    const Handle main_limited = OpenThread(QUERY_LIMITED_INFORMATION, 0, main_id);
    const Handle main_full = OpenThread(QUERY_INFORMATION, 0, main_id);
    if (!main_limited || !main_full || GetProcessIdOfThread(main_limited) != process ||
        GetProcessIdOfThread(main_full) != process)
        return 11;
    if (!CloseHandle(main_limited) || !CloseHandle(main_full))
        return 12;

    Worker worker = {CreateEventW(0, 0, 0, 0), CreateEventW(0, 0, 0, 0), process};
    if (!worker.ready || !worker.release)
        return 13;

    Dword worker_id = 0;
    const Handle live = CreateThread(0, 0, worker_main, &worker, 0, &worker_id);
    if (!live || !worker_id || worker_id == main_id || worker_id == process)
        return 14;
    if (WaitForSingleObject(worker.ready, 50) != WAIT_SIGNALED ||
        WaitForSingleObject(live, 0) != WAIT_TIMEOUT)
        return 15;
    if (GetProcessIdOfThread(live) != process)
        return 16;

    const Handle wait_only = OpenThread(SYNCHRONIZE, 0, worker_id);
    if (!wait_only || !denied(wait_only, ACCESS_DENIED))
        return 17;
    if (!denied(worker.ready, INVALID_HANDLE) || !denied(0, INVALID_HANDLE))
        return 18;

    if (!SetEvent(worker.release) || WaitForSingleObject(wait_only, 50) != WAIT_SIGNALED ||
        WaitForSingleObject(live, 0) != WAIT_SIGNALED)
        return 19;
    Dword worker_exit = UINT32_MAX;
    if (!GetExitCodeThread(live, &worker_exit) || worker_exit != 0 ||
        GetProcessIdOfThread(live) != process)
        return 20;
    if (!CloseHandle(wait_only) || !CloseHandle(worker.ready) ||
        !CloseHandle(worker.release) || !CloseHandle(live))
        return 21;
    return denied(live, INVALID_HANDLE) ? 0 : 22;
}

void entry(void) { ExitProcess(check()); }
