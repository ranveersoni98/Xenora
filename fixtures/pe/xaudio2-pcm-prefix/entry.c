// SPDX-License-Identifier: GPL-3.0-or-later

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef int hresult;

struct engine;
struct voice;
struct voice_details { u32 creation_flags, active_flags, channels, sample_rate; };

struct engine_vtable {
    void (*query_interface)(void);
    void (*add_ref)(void);
    u32 (*release)(struct engine *);
    void (*callback_registration[2])(void);
    hresult (*create_source)(struct engine *, struct voice **, const void *,
                             u32, float, void *, void *, void *);
    void (*create_submix)(void);
    hresult (*create_mastering)(struct engine *, struct voice **, u32, u32, u32,
                                const u16 *, void *, u32);
};
struct voice_vtable {
    void (*get_details)(struct voice *, struct voice_details *);
    void (*other_common_methods[17])(void);
    void (*destroy)(struct voice *);
};
struct engine { const struct engine_vtable *v; };
struct voice { const struct voice_vtable *v; };

#define IMPORT __declspec(dllimport)
IMPORT hresult XAudio2Create(struct engine **, u32, u32);
IMPORT void *VirtualAlloc(void *, u64, u32, u32);
IMPORT int VirtualFree(void *, u64, u32);
IMPORT __declspec(noreturn) void ExitProcess(u32);

#define CHECK(condition) do { if (!(condition)) ExitProcess(__LINE__); } while (0)
enum { PAGE_SIZE = 4096 };
static const hresult pointer_error = (hresult)0x80004003u;

#pragma pack(push, 2)
struct pcm_wave_format { u16 tag, channels; u32 rate, average; u16 alignment, bits; };
struct wave_format_ex { struct pcm_wave_format prefix; u16 extra; };
#pragma pack(pop)
_Static_assert(sizeof(struct pcm_wave_format) == 16, "packed PCMWAVEFORMAT");
_Static_assert(sizeof(struct wave_format_ex) == 18, "packed WAVEFORMATEX");

static void check_format(struct engine *engine, u8 *page, const struct wave_format_ex *format,
                         u32 accessible, hresult expected, u32 line) {
    u8 *address = page + PAGE_SIZE - accessible;
    const u8 *input = (const u8 *)format;
    for (u32 i = 0; i < accessible; ++i) address[i] = input[i];

    struct {
        u64 left;
        struct voice *output;
        u64 right;
    } result = {0x123456789abcdef0ull, (struct voice *)1, 0xfedcba9876543210ull};
    const hresult actual = engine->v->create_source(
        engine, &result.output, address, 0, 2.0f, 0, 0, 0);
    if (actual != expected) ExitProcess(line);
    CHECK(result.left == 0x123456789abcdef0ull && result.right == 0xfedcba9876543210ull);
    for (u32 i = 0; i < accessible; ++i) CHECK(address[i] == input[i]);
    if (expected != 0) {
        CHECK(result.output == 0);
        return;
    }
    CHECK(result.output && result.output != (struct voice *)1);
    struct voice_details details = {~0u, ~0u, ~0u, ~0u};
    result.output->v->get_details(result.output, &details);
    CHECK(details.creation_flags == 0 && details.active_flags == 0);
    CHECK(details.channels == 2 && details.sample_rate == 48000);
    result.output->v->destroy(result.output);
}

#define CHECK_FORMAT(engine, page, format, accessible, expected) \
    check_format(engine, page, format, accessible, expected, __LINE__)

void entry(void) {
    struct engine *engine = 0;
    struct voice *mastering = 0;
    CHECK(XAudio2Create(&engine, 0, 1) == 0 && engine);
    CHECK(engine->v->create_mastering(engine, &mastering, 2, 48000, 0, 0, 0, 6) == 0);
    u8 *page = VirtualAlloc(0, PAGE_SIZE, 0x3000, 4);  // MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE
    CHECK(page);

    static const struct wave_format_ex pcm = {{1, 2, 48000, 192000, 4, 16}, 0xa5a5};
    static const struct wave_format_ex float32 = {{3, 2, 48000, 384000, 8, 32}, 0};
    CHECK_FORMAT(engine, page, &pcm, 16, 0);
    CHECK_FORMAT(engine, page, &pcm, 15, pointer_error);
    CHECK_FORMAT(engine, page, &pcm, 18, 0);
    CHECK_FORMAT(engine, page, &float32, 16, pointer_error);
    CHECK_FORMAT(engine, page, &float32, 18, 0);

    CHECK(VirtualFree(page, 0, 0x8000));  // MEM_RELEASE
    mastering->v->destroy(mastering);
    CHECK(engine->v->release(engine) == 0);
    ExitProcess(0);
}
