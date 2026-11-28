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

scratch=$(mktemp -d "${TMPDIR:-/tmp}/xenora-xaudio2-pcm-prefix.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
cd "$scratch"
printf '%s\n' 'LIBRARY kernel32.dll' EXPORTS ExitProcess VirtualAlloc VirtualFree > kernel32.def
link /lib /def:kernel32.def /machine:x64 /out:kernel32.lib
link /lib /def:"$here/../xaudio2_9.def" /machine:x64 /out:xaudio2_9.lib
arch -arm64 "$clang" --target=x86_64-pc-windows-msvc -std=c17 -O1 -Wall -Wextra -Werror \
    -ffreestanding -fno-builtin -fno-stack-protector -fno-vectorize -fno-slp-vectorize \
    -c "$here/entry.c" -o entry.obj
arch -arm64 "$clang" --target=x86_64-pc-windows-msvc -std=c17 -O1 -Wall -Wextra -Werror \
    -ffreestanding -fno-builtin -c "$here/../xaudio2-fltused.c" -o support.obj
link /entry:entry /subsystem:console /nodefaultlib /timestamp:0 /machine:x64 \
    /out:xaudio2-pcm-prefix.exe entry.obj support.obj kernel32.lib xaudio2_9.lib
if [ "${1:-}" = --check ]; then
    cmp xaudio2-pcm-prefix.exe "$here/xaudio2-pcm-prefix.exe"
else
    install -m 0644 xaudio2-pcm-prefix.exe "$here/xaudio2-pcm-prefix.exe"
fi
