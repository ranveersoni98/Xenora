// SPDX-License-Identifier: GPL-3.0-or-later

// Original GUI-subsystem guest with a small freestanding startup shim.
typedef unsigned int u32;
typedef unsigned short u16;
typedef void *handle;

struct startup_info {
    u32 size;
    const u16 *reserved, *desktop, *title;
    u32 x, y, width, height, columns, rows, fill_attribute, flags;
    u16 show_window, reserved_count;
    void *reserved_bytes;
    handle standard_input, standard_output, standard_error;
};
_Static_assert(sizeof(struct startup_info) == 104, "Win64 STARTUPINFOW");

#define IMPORT __declspec(dllimport)
IMPORT const char *GetCommandLineA(void);
IMPORT const u16 *GetCommandLineW(void);
IMPORT handle GetModuleHandleW(const u16 *);
IMPORT void GetStartupInfoW(struct startup_info *);
IMPORT const char *_get_narrow_winmain_command_line(void);
IMPORT u16 *_get_wide_winmain_command_line(void);
IMPORT __declspec(noreturn) void ExitProcess(u32);

enum { STARTF_USESHOWWINDOW = 1, SW_SHOWDEFAULT = 10 };
static const char root_a[] = "\"Wide Root 🧪.exe\"";
static const u16 root_w[] = L"\"Wide Root 🧪.exe\"";
static const char arguments_a[] = "\"A 🚀\" \"\" \"say\\\"hello\" \"path end \\\\\" \"a\tb\" --trace";
static const u16 arguments_w[] = L"\"A 🚀\" \"\" \"say\\\"hello\" \"path end \\\\\" \"a\tb\" --trace";

static int same_narrow(const char *left, const char *right) {
    while (*left == *right) {
        if (!*left) return 1;
        ++left;
        ++right;
    }
    return 0;
}

static int same_wide(const u16 *left, const u16 *right) {
    while (*left == *right) {
        if (!*left) return 1;
        ++left;
        ++right;
    }
    return 0;
}

__declspec(noinline)
int wWinMain(handle instance, handle previous, u16 *tail, int show) {
    const char *full_a = GetCommandLineA();
    const u16 *full_w = GetCommandLineW();
    const char *tail_a = _get_narrow_winmain_command_line();
    if (!instance || previous || show != SW_SHOWDEFAULT) return 11;
    if (!full_a || !full_w || !tail_a || !tail) return 12;
    if (GetCommandLineA() != full_a || GetCommandLineW() != full_w ||
        _get_narrow_winmain_command_line() != tail_a ||
        _get_wide_winmain_command_line() != tail) return 13;

    const u32 root_units = sizeof root_w / sizeof root_w[0] - 1;
    for (u32 i = 0; i < sizeof root_a - 1; ++i) {
        if (full_a[i] != root_a[i]) return 14;
    }
    for (u32 i = 0; i < root_units; ++i) {
        if (full_w[i] != root_w[i]) return 15;
    }

    const char *after_a = full_a + sizeof root_a - 1;
    const u16 *after_w = full_w + root_units;
    if (!*after_a) {
        return !*after_w && tail_a == after_a && tail == after_w ? 41 : 16;
    }
    if (*after_a != ' ' || *after_w != ' ' ||
        tail_a != after_a + 1 || tail != after_w + 1) return 17;
    if (same_narrow(tail_a, "\"\"") && same_wide(tail, L"\"\"")) return 42;
    if (!same_narrow(tail_a, arguments_a) || !same_wide(tail, arguments_w)) return 18;
    return 43;
}

void entry(void) {
    // The narrow and wide strings have independent allocations. Use the
    // narrow tail to choose both wide access orders across fresh processes.
    const char *tail_a = _get_narrow_winmain_command_line();
    if (!tail_a) ExitProcess(19);
    if (!*tail_a && !GetCommandLineW()) ExitProcess(20);

    struct startup_info info;
    GetStartupInfoW(&info);
    if (info.size != sizeof info) ExitProcess(21);
    int show = info.flags & STARTF_USESHOWWINDOW ? info.show_window : SW_SHOWDEFAULT;
    u16 *tail = _get_wide_winmain_command_line();
    ExitProcess(wWinMain(GetModuleHandleW(0), 0, tail, show));
}
