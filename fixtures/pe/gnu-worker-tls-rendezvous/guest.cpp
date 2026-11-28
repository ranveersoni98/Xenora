// SPDX-License-Identifier: GPL-3.0-or-later

#include <cstdio>
#include <windows.h>

struct Thread {
    DWORD id;
    unsigned seed;
    unsigned writes;
    unsigned initializations;
    unsigned *address;
};

static Thread threads[] = {{0, 17, 101, 0, nullptr},
                           {0, 29, 202, 0, nullptr},
                           {0, 43, 303, 0, nullptr}};
static CRITICAL_SECTION section;
static CONDITION_VARIABLE ready;
static CONDITION_VARIABLE release_workers;
static unsigned waiting;
static bool released;

// The caller holds section. Runtime thread identity prevents constant
// initialization, so the compiler emits a guard in thread-local storage.
__attribute__((noinline)) static unsigned initialize_value() {
    const DWORD id = GetCurrentThreadId();
    for (auto &thread : threads) {
        if (thread.id == id) {
            ++thread.initializations;
            return thread.seed;
        }
    }
    return 0;
}

thread_local unsigned value = initialize_value();

__attribute__((noinline)) static unsigned *current_value() { return &value; }

static bool check_initialization(Thread &thread) {
    thread.id = GetCurrentThreadId();
    thread.address = current_value();
    if (*thread.address != thread.seed || thread.initializations != 1)
        return false;
    *thread.address = thread.writes;
    return current_value() == thread.address && value == thread.writes &&
           thread.initializations == 1;
}

// A timed wait requires ownership on entry and reacquires the section
// before returning. LeaveCriticalSection below also requires ownership.
static bool timeout_while_holding_section() {
    return !SleepConditionVariableCS(&ready, &section, 5) &&
           GetLastError() == ERROR_TIMEOUT;
}

static DWORD WINAPI worker(LPVOID context) {
    auto &thread = *static_cast<Thread *>(context);
    EnterCriticalSection(&section);
    const bool initialized = check_initialization(thread);
    ++waiting;
    WakeConditionVariable(&ready);
    while (!released) {
        if (!SleepConditionVariableCS(&release_workers, &section, INFINITE)) {
            LeaveCriticalSection(&section);
            return 11;
        }
    }
    const bool timed_out = timeout_while_holding_section();
    const bool still_private = current_value() == thread.address &&
                               value == thread.writes && thread.initializations == 1;
    LeaveCriticalSection(&section);
    if (!initialized)
        return 12;
    if (!timed_out)
        return 13;
    return still_private ? 0 : 14;
}

int main() {
    if (waiting != 0 || released)
        return 20;
    InitializeCriticalSection(&section);
    InitializeConditionVariable(&ready);
    InitializeConditionVariable(&release_workers);
    EnterCriticalSection(&section);
    if (!check_initialization(threads[0]))
        return 21;

    HANDLE workers[] = {
        CreateThread(nullptr, 0, worker, &threads[1], 0, nullptr),
        CreateThread(nullptr, 0, worker, &threads[2], 0, nullptr),
    };
    if (!workers[0] || !workers[1])
        return 22;
    while (waiting != 2) {
        if (!SleepConditionVariableCS(&ready, &section, INFINITE))
            return 23;
    }

    // Each worker must release the critical section in the gate wait
    // before main can own it again and see both reports.
    for (unsigned index = 0; index < 3; ++index) {
        if (!threads[index].id || !threads[index].address ||
            threads[index].initializations != 1)
            return 24;
        for (unsigned prior = 0; prior < index; ++prior) {
            if (threads[prior].id == threads[index].id ||
                threads[prior].address == threads[index].address)
                return 25;
        }
    }
    if (current_value() != threads[0].address || value != threads[0].writes)
        return 26;
    released = true;
    WakeAllConditionVariable(&release_workers);
    LeaveCriticalSection(&section);

    for (HANDLE handle : workers) {
        if (WaitForSingleObject(handle, INFINITE) != WAIT_OBJECT_0)
            return 27;
        DWORD status = 0;
        if (!GetExitCodeThread(handle, &status) || !CloseHandle(handle))
            return 28;
        if (status != 0)
            return static_cast<int>(status);
    }
    EnterCriticalSection(&section);
    const bool main_unchanged = current_value() == threads[0].address &&
                                value == threads[0].writes &&
                                threads[0].initializations == 1;
    LeaveCriticalSection(&section);
    DeleteCriticalSection(&section);
    if (!main_unchanged)
        return 29;

    std::puts("tls: 17->101 29->202 43->303");
    std::puts("rendezvous: 2 workers, 2 timeouts");
    return 0;
}
