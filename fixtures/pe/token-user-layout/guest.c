// SPDX-License-Identifier: GPL-3.0-or-later

#include <stddef.h>
#include <stdint.h>

typedef void *Handle;
typedef struct {
    void *sid;
    uint32_t attributes;
} SidAndAttributes;
typedef struct {
    SidAndAttributes user;
} TokenUser;

_Static_assert(sizeof(TokenUser) == 16 && offsetof(SidAndAttributes, attributes) == 8,
               "AMD64 TOKEN_USER layout");

__declspec(dllimport) Handle GetCurrentProcess(void);
__declspec(dllimport) unsigned GetLastError(void);
__declspec(dllimport) int OpenProcessToken(Handle, unsigned, Handle *);
__declspec(dllimport) int GetTokenInformation(Handle, unsigned, void *, unsigned, unsigned *);
__declspec(dllimport) void ExitProcess(unsigned);

enum {
    TOKEN_QUERY = 8,
    TOKEN_USER = 1,
    INSUFFICIENT_BUFFER = 122,
    REQUIRED = 28,
    CANARY = 0x5a
};

static unsigned check(void) {
    Handle token = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) || !token)
        return 10;
    unsigned required = 0;
    if (GetTokenInformation(token, TOKEN_USER, 0, 0, &required) ||
        GetLastError() != INSUFFICIENT_BUFFER)
        return 11;

    union {
        TokenUser header;
        unsigned char bytes[REQUIRED + 1];
    } output;
    for (unsigned i = 0; i < sizeof(output.bytes); ++i)
        output.bytes[i] = CANARY;

    unsigned returned = 0;
    if (!GetTokenInformation(token, TOKEN_USER, &output, REQUIRED, &returned))
        return 12;
    if (output.header.user.attributes != 0 || output.header.user.sid != output.bytes + 16)
        return 13;
    if (required != REQUIRED || returned != REQUIRED || output.bytes[REQUIRED] != CANARY)
        return 14;
    for (unsigned i = 12; i < 16; ++i)
        if (output.bytes[i] != 0)
            return 15;
    static const unsigned char sid[] = {1, 1, 0, 0, 0, 0, 0, 5, 0xe8, 3, 0, 0};
    for (unsigned i = 0; i < sizeof(sid); ++i)
        if (output.bytes[16 + i] != sid[i])
            return 16;

    for (unsigned i = 0; i < sizeof(output.bytes); ++i)
        output.bytes[i] = CANARY;
    returned = 0;
    if (GetTokenInformation(token, TOKEN_USER, &output, REQUIRED - 1, &returned) ||
        GetLastError() != INSUFFICIENT_BUFFER || returned != REQUIRED)
        return 17;
    for (unsigned i = 0; i < sizeof(output.bytes); ++i)
        if (output.bytes[i] != CANARY)
            return 18;
    return 0;
}

void entry(void) { ExitProcess(check()); }
