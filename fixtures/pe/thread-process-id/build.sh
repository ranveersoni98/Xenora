#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
out=${1:?usage: build.sh OUTPUT_DIRECTORY}
mkdir -p "$out"
out=$(CDPATH= cd -- "$out" && pwd)
clang=${CLANG:-/opt/homebrew/opt/llvm/bin/clang}
if [ -z "${CLANG:-}" ] && [ ! -x "$clang" ]; then
    clang=$(command -v clang)
fi
linker=${LLD_LINK:-/opt/homebrew/opt/lld/bin/lld-link}
if [ -z "${LLD_LINK:-}" ] && [ ! -x "$linker" ]; then
    linker="$(rustc --print sysroot)/lib/rustlib/aarch64-apple-darwin/bin/rust-lld"
fi
for tool in "$clang" "$linker"; do
    file -L "$tool"
    lipo -archs "$tool"
    lipo -verify_arch arm64 "$tool"
    otool -L "$tool"
done
link() {
    case "${linker##*/}" in
        rust-lld) arch -arm64 "$linker" -flavor link "$@" ;;
        *) arch -arm64 "$linker" "$@" ;;
    esac
}

scratch=$(mktemp -d "${TMPDIR:-/tmp}/xenora-thread-process-id.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
cd "$scratch"
cat > kernel32.def <<'DEF'
LIBRARY kernel32.dll
EXPORTS
    GetProcessIdOfThread
    GetCurrentProcessId
    GetCurrentThread
    GetCurrentThreadId
    OpenThread
    CreateThread
    CreateEventW
    SetEvent
    WaitForSingleObject
    GetExitCodeThread
    CloseHandle
    GetLastError
    SetLastError
    ExitProcess
DEF
link /lib /def:kernel32.def /machine:x64 /out:kernel32.lib
for optimization in O1 O2; do
    arch -arm64 "$clang" --target=x86_64-pc-windows-msvc "-$optimization" \
        -Wall -Wextra -Werror -ffreestanding -fno-builtin -fno-stack-protector \
        -fno-vectorize -fno-slp-vectorize -c "$here/guest.c" -o guest.obj
    link /entry:entry /subsystem:console /nodefaultlib /timestamp:0 /machine:x64 \
        "/out:$out/thread-process-id-$optimization.exe" guest.obj kernel32.lib
done
