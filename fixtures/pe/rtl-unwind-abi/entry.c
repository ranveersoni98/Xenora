// SPDX-License-Identifier: GPL-3.0-or-later

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
struct runtime_function { u32 begin, end, unwind; };
struct context { u8 bytes[0x4d0]; };

extern int capture_frame(struct context *);
extern int invoke_capture(struct context *);
extern const u8 capture_resume[], invoke_resume[], __ImageBase[];
__declspec(dllimport) const struct runtime_function *RtlLookupFunctionEntry(u64, u64 *, void *);
__declspec(dllimport) void *RtlVirtualUnwind(u32, u64, u64, const struct runtime_function *,
                                            struct context *, void **, u64 *, void *);
__declspec(dllimport) __declspec(noreturn) void ExitProcess(u32);

// The initial value needs a DIR64 relocation when the runner chooses a new base.
static int (*volatile relocated_anchor)(struct context *) = capture_frame;

static __declspec(align(16)) struct {
    volatile u64 left[2];
    struct context value;
    volatile u64 right[2];
} captured;

static const u64 left_guard = 0x1020304050607080ull;
static const u64 right_guard = 0x8171615141312111ull;
enum { RBX = 0x90, RSP = 0x98, RIP = 0xf8, XMM6 = 0x200 };

static int context_guards_intact(void) {
    return captured.left[0] == left_guard && captured.left[1] == left_guard &&
        captured.right[0] == right_guard && captured.right[1] == right_guard;
}

static u64 read_qword(const u8 *bytes) {
    u64 value = 0;
    for (u32 i = 0; i < 8; ++i) value |= (u64)bytes[i] << (8 * i);
    return value;
}

int inspect_capture(struct context *context, u64 frame_rsp, u64 caller_rbx, u64 caller_pc) {
    const u64 pc = (u64)capture_resume;
    if (!context_guards_intact() ||
        read_qword(context->bytes + RIP) != pc ||
        read_qword(context->bytes + RSP) != frame_rsp ||
        read_qword(context->bytes + RBX) != 0x1122334455667788ull ||
        read_qword(context->bytes + XMM6) != 0x0123456789abcdefull ||
        read_qword(context->bytes + XMM6 + 8) != 0xfedcba9876543210ull) return 61;

    struct guarded_output { volatile u64 left; u64 value; volatile u64 right; };
    struct guarded_output base = {left_guard, 0, right_guard};
    const struct runtime_function *function = RtlLookupFunctionEntry(pc, &base.value, 0);
    if (!function || base.value != (u64)__ImageBase ||
        base.value + function->begin != (u64)capture_frame ||
        base.value + function->end <= pc || !function->unwind ||
        base.left != left_guard || base.right != right_guard) return 62;

    u64 first_base = 0, miss_base = 0;
    const u64 end = base.value + function->end;
    if (RtlLookupFunctionEntry((u64)capture_frame, &first_base, 0) != function ||
        first_base != base.value ||
        RtlLookupFunctionEntry(end - 1, &first_base, 0) != function ||
        RtlLookupFunctionEntry(end, &miss_base, 0) == function ||
        RtlLookupFunctionEntry(0, &miss_base, 0)) return 63;

    const u64 caller_xmm6_low = read_qword((const u8 *)frame_rsp + 32);
    const u64 caller_xmm6_high = read_qword((const u8 *)frame_rsp + 40);
    if (caller_rbx != 0x8877665544332211ull || caller_pc != (u64)invoke_resume ||
        caller_xmm6_low != 0x1029384756abcdefull ||
        caller_xmm6_high != 0xf1e2d3c4b5a69788ull) return 66;

    struct guarded_output establisher = {left_guard, 0, right_guard};
    struct { volatile u64 left; void *value; volatile u64 right; } handler_data = {
        left_guard, &captured, right_guard
    };
    // UNW_FLAG_NHANDLER: both output addresses are live, but no handler is returned.
    if (RtlVirtualUnwind(0, base.value, pc, function, context, &handler_data.value,
                         &establisher.value, 0)) return 64;
    if (!context_guards_intact() || establisher.left != left_guard ||
        establisher.right != right_guard || handler_data.left != left_guard ||
        handler_data.value != &captured || handler_data.right != right_guard ||
        establisher.value != frame_rsp ||
        read_qword(context->bytes + RSP) != frame_rsp + 96 ||
        read_qword(context->bytes + RIP) != caller_pc ||
        read_qword(context->bytes + RBX) != caller_rbx ||
        read_qword(context->bytes + XMM6) != caller_xmm6_low ||
        read_qword(context->bytes + XMM6 + 8) != caller_xmm6_high) return 65;
    return 0;
}

void entry(void) {
    captured.left[0] = captured.left[1] = left_guard;
    captured.right[0] = captured.right[1] = right_guard;
    if (relocated_anchor != capture_frame) ExitProcess(60);
    ExitProcess((u32)invoke_capture(&captured.value));
}
