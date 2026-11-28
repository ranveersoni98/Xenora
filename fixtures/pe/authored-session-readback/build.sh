#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
out=${1:?usage: build.sh output-directory}
mkdir -p "$out"
out=$(CDPATH= cd -- "$out" && pwd)
clang=${CLANG:-$(xcrun --find clang)}
linker=${LLD_LINK:-"$(rustc --print sysroot)/lib/rustlib/aarch64-apple-darwin/bin/rust-lld"}
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

scratch=$(mktemp -d "${TMPDIR:-/tmp}/xenora-authored-session-readback.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
cd "$scratch"
printf '%s\n' 'LIBRARY kernel32.dll' EXPORTS ExitProcess > kernel32.def
cat > session.def <<'DEF'
LIBRARY xenora-session-v1.dll
EXPORTS
    XenoraSessionNextInput
    XenoraSessionPresent
    XenoraSessionFinish
DEF
cat > graphics.def <<'DEF'
LIBRARY xenora_graphics.dll
EXPORTS
    XenoraCloseCommandList
    XenoraCreateBuffer
    XenoraCreateCommandAllocator
    XenoraCreateCommandList
    XenoraCreateCommandQueue
    XenoraCreateDevice
    XenoraCreateRenderTarget
    XenoraDestroyCommandAllocator
    XenoraDestroyCommandList
    XenoraDestroyCommandQueue
    XenoraDestroyDevice
    XenoraDestroyResource
    XenoraDraw
    XenoraExecuteCommandLists
    XenoraReadbackResource
    XenoraSetRenderTarget
    XenoraSetVertexBuffer
    XenoraSetViewport
DEF
for module in kernel32 session graphics; do
    link /lib "/def:$module.def" /machine:x64 "/out:$module.lib"
done
arch -arm64 "$clang" --target=x86_64-pc-windows-msvc -std=c17 -O1 -Wall -Wextra -Werror \
    -ffreestanding -fno-builtin -fno-stack-protector -fno-vectorize -fno-slp-vectorize \
    -c "$here/entry.c" -o entry.obj
link /entry:entry /subsystem:console /nodefaultlib /timestamp:0 /machine:x64 \
    "/out:$out/authored-session-readback.exe" entry.obj kernel32.lib session.lib graphics.lib
