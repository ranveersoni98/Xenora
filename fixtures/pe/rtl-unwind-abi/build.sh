#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
clang=${CLANG:-/opt/homebrew/opt/llvm/bin/clang}
linker=${LLD_LINK:-/opt/homebrew/opt/lld/bin/lld-link}
if [ -z "${CLANG:-}" ] && [ ! -x "$clang" ]; then
    clang=$(xcrun --find clang)
fi
if [ -z "${LLD_LINK:-}" ] && [ ! -x "$linker" ]; then
    linker="$(rustc --print sysroot)/lib/rustlib/aarch64-apple-darwin/bin/rust-lld"
fi
for tool in "$clang" "$linker"; do
    [ -x "$tool" ] && lipo -verify_arch arm64 "$tool" || {
        echo "Expected a native ARM64 tool: $tool" >&2
        exit 1
    }
done
link() {
    case "${linker##*/}" in
        rust-lld) arch -arm64 "$linker" -flavor link "$@" ;;
        *) arch -arm64 "$linker" "$@" ;;
    esac
}

scratch=$(mktemp -d "${TMPDIR:-/tmp}/xenora-rtl-unwind-abi.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
cd "$scratch"
printf '%s\n' 'LIBRARY kernel32.dll' EXPORTS ExitProcess RtlCaptureContext \
    RtlLookupFunctionEntry RtlVirtualUnwind > kernel32.def
link /lib /def:kernel32.def /machine:x64 /out:kernel32.lib
arch -arm64 "$clang" --target=x86_64-pc-windows-msvc -std=c17 -O1 -Wall -Wextra -Werror \
    -ffreestanding -fno-builtin -fno-stack-protector -fno-vectorize -fno-slp-vectorize \
    -c "$here/entry.c" -o entry.obj
arch -arm64 "$clang" --target=x86_64-pc-windows-msvc -c "$here/capture.s" -o capture.obj
link /entry:entry /subsystem:console /nodefaultlib /timestamp:0 /machine:x64 \
    /out:rtl-unwind-abi.exe entry.obj capture.obj kernel32.lib
if [ "${1:-}" = --check ]; then
    cmp rtl-unwind-abi.exe "$here/rtl-unwind-abi.exe"
else
    install -m 0644 rtl-unwind-abi.exe "$here/rtl-unwind-abi.exe"
fi
