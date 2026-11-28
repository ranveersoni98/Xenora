# SPDX-License-Identifier: GPL-3.0-or-later

.text
.globl invoke_capture
.globl invoke_resume
.globl capture_frame
.globl capture_resume

.seh_proc invoke_capture
invoke_capture:
    pushq %rbx
    .seh_pushreg %rbx
    subq $48, %rsp
    .seh_stackalloc 48
    movaps %xmm6, 32(%rsp)
    .seh_savexmm %xmm6, 32
    .seh_endprologue

    movabsq $0x8877665544332211, %rbx
    movaps caller_vector(%rip), %xmm6
    callq capture_frame
invoke_resume:
    movaps 32(%rsp), %xmm6
    addq $48, %rsp
    popq %rbx
    retq
.seh_endproc

.seh_proc capture_frame
capture_frame:
    pushq %rbx
    .seh_pushreg %rbx
    subq $80, %rsp
    .seh_stackalloc 80
    movaps %xmm6, 32(%rsp)
    .seh_savexmm %xmm6, 32
    .seh_endprologue

    movq %rcx, 48(%rsp)
    movabsq $0x1122334455667788, %rbx
    movaps capture_vector(%rip), %xmm6
    callq *__imp_RtlCaptureContext(%rip)
capture_resume:
    # Inspect while the saved registers and return address remain on the stack.
    movq 48(%rsp), %rcx
    movq %rsp, %rdx
    movq 80(%rsp), %r8
    movq 88(%rsp), %r9
    callq inspect_capture
    movaps 32(%rsp), %xmm6
    addq $80, %rsp
    popq %rbx
    retq
.seh_endproc

.section .rdata,"dr"
.p2align 4
caller_vector:
    .quad 0x1029384756abcdef, 0xf1e2d3c4b5a69788
capture_vector:
    .quad 0x0123456789abcdef, 0xfedcba9876543210
