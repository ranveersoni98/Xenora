// SPDX-License-Identifier: GPL-3.0-or-later

#include <stddef.h>
#include <stdint.h>

typedef struct {
    int16_t x, y;
} Coord;

typedef struct {
    int16_t left, top, right, bottom;
} Rect;

typedef struct {
    union {
        uint16_t wide;
        char narrow;
    } character;
    uint16_t attributes;
} Cell;

_Static_assert(sizeof(Cell) == 4 && offsetof(Cell, attributes) == 2, "CHAR_INFO layout");

typedef void *Handle;
__declspec(dllimport) Handle CreateConsoleScreenBuffer(uint32_t, uint32_t, void *, uint32_t, void *);
__declspec(dllimport) int WriteConsoleOutputA(Handle, const Cell *, Coord, Coord, Rect *);
__declspec(dllimport) int WriteConsoleOutputW(Handle, const Cell *, Coord, Coord, Rect *);
__declspec(dllimport) int ReadConsoleOutputW(Handle, Cell *, Coord, Coord, Rect *);
__declspec(dllimport) int CloseHandle(Handle);
__declspec(dllimport) void ExitProcess(unsigned);

static unsigned check(Handle screen) {
    const Coord size = {2, 1};
    const Coord origin = {0, 0};
    const Coord second = {1, 0};
    Cell ansi[2] = {{{.narrow = 'Q'}, 0x001e}, {{.narrow = 'Z'}, 0x002b}};
    // Set the unused bytes directly after initializing the ANSI members.
    ((unsigned char *)&ansi[0].character)[1] = 0xab;
    ((unsigned char *)&ansi[1].character)[1] = 0xcd;

    Rect target = {0, 0, 1, 0};
    if (!WriteConsoleOutputA(screen, ansi, size, origin, &target))
        return 11;
    if (target.left != 0 || target.right != 1 || target.top != 0 || target.bottom != 0)
        return 12;

    Cell readback[2] = {{{.wide = 0}, 0}, {{.wide = 0}, 0}};
    if (!ReadConsoleOutputW(screen, readback, size, origin, &target))
        return 13;
    if (readback[0].character.wide != 'Q' || readback[1].character.wide != 'Z')
        return 14;
    if (readback[0].attributes != 0x001e || readback[1].attributes != 0x002b)
        return 15;

    const Cell wide = {{.wide = 0x03a9}, 0x004d};
    const Coord single = {1, 1};
    if (!WriteConsoleOutputW(screen, &wide, single, origin, &target))
        return 16;
    if (target.left != 0 || target.right != 0 || target.top != 0 || target.bottom != 0)
        return 17;

    // Only the second destination cell lies inside the caller's buffer.
    target.right = 1;
    if (!ReadConsoleOutputW(screen, readback, size, second, &target))
        return 18;
    if (target.left != 0 || target.right != 0 || target.top != 0 || target.bottom != 0)
        return 19;
    if (readback[0].character.wide != 'Q' || readback[0].attributes != 0x001e ||
        readback[1].character.wide != 0x03a9 || readback[1].attributes != 0x004d)
        return 20;

    return 0;
}

void entry(void) {
    Handle screen = CreateConsoleScreenBuffer(0xc0000000u, 3, 0, 1, 0);
    if (screen == (Handle)(uintptr_t)-1)
        ExitProcess(10);
    const unsigned result = check(screen);
    const int closed = CloseHandle(screen);
    ExitProcess(result ? result : closed ? 0 : 21);
}
