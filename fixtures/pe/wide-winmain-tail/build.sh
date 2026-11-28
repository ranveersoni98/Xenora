#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Build or check the original AMD64 GUI fixture on native Apple Silicon.
set -eu
case "$#:${1:-}" in
    0:|1:--check) ;;
    *) printf 'usage: %s [--check]\n' "$0" >&2; exit 2 ;;
esac

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
        echo "Native ARM64 tool required: $tool" >&2
        exit 1
    }
done
link() {
    case "${linker##*/}" in
        rust-lld) arch -arm64 "$linker" -flavor link "$@" ;;
        *) arch -arm64 "$linker" "$@" ;;
    esac
}
scratch=$(mktemp -d "${TMPDIR:-/tmp}/xenora-wide-winmain-tail.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
cd "$scratch"
cat > kernel32.def <<'DEF'
LIBRARY kernel32.dll
EXPORTS
    ExitProcess
    GetCommandLineA
    GetCommandLineW
    GetModuleHandleW
    GetStartupInfoW
DEF
cat > runtime.def <<'DEF'
LIBRARY api-ms-win-crt-runtime-l1-1-0.dll
EXPORTS
    _get_narrow_winmain_command_line
    _get_wide_winmain_command_line
DEF
link /lib /def:kernel32.def /machine:x64 /out:kernel32.lib
link /lib /def:runtime.def /machine:x64 /out:runtime.lib
arch -arm64 "$clang" --target=x86_64-pc-windows-msvc -std=c17 -O1 -Wall -Wextra -Werror -ffreestanding -fno-builtin -fno-stack-protector -fno-vectorize -fno-slp-vectorize -c "$here/entry.c" -o guest.obj
link /entry:entry /subsystem:windows /nodefaultlib /timestamp:0 /machine:x64 /out:wide-winmain-tail.exe guest.obj kernel32.lib runtime.lib
if [ "${1:-}" = --check ]; then
    cmp wide-winmain-tail.exe "$here/wide-winmain-tail.exe"
else
    install -m 0644 wide-winmain-tail.exe "$here/wide-winmain-tail.exe"
fi
