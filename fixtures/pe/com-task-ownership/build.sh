#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Usage: fixtures/pe/com-task-ownership/build.sh artifacts/com-task-ownership
# The original application and independently compiled provider DLLs use local
# import definitions. CLANG and LLD_LINK may select other native ARM64 tools.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
outdir=${1:?usage: build.sh OUTPUT_DIRECTORY}
mkdir -p "$outdir"
outdir=$(cd -- "$outdir" && pwd)
clang=${CLANG:-$(xcrun --find clang)}
linker=${LLD_LINK:-/opt/homebrew/opt/lld/bin/lld-link}
if [ -z "${LLD_LINK:-}" ] && [ ! -x "$linker" ]; then
    linker="$(rustc --print sysroot)/lib/rustlib/aarch64-apple-darwin/bin/rust-lld"
fi
test "$(uname -m)" = arm64
for tool in "$clang" "$linker"; do
    file -L "$tool"
    lipo -archs "$tool"
    lipo "$tool" -verify_arch arm64
    otool -L "$tool"
done

link() {
    case "${linker##*/}" in
        rust-lld) "$linker" -flavor link "$@" ;;
        *) "$linker" "$@" ;;
    esac
}

compile() {
    "$clang" --target=x86_64-pc-windows-msvc "-$optimization" -Wall -Wextra -Werror \
        -ffreestanding -fno-builtin -fno-stack-protector -fno-vectorize -fno-slp-vectorize "$@"
}

scratch=$(mktemp -d "${TMPDIR:-/tmp}/xenora-com-task-ownership.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
cd "$scratch"
cat > ole32.def <<'DEF'
LIBRARY ole32.dll
EXPORTS
    CoTaskMemAlloc
DEF
cat > combase.def <<'DEF'
LIBRARY combase.dll
EXPORTS
    CoTaskMemRealloc
    PropVariantClear
DEF
cat > com-api.def <<'DEF'
LIBRARY api-ms-win-core-com-l1-1-0.dll
EXPORTS
    CoTaskMemFree
DEF
cat > kernel32.def <<'DEF'
LIBRARY kernel32.dll
EXPORTS
    ExitProcess
    GetLastError
    VirtualQuery
DEF
for module in ole32 combase com-api kernel32; do
    link /lib "/def:$module.def" /machine:x64 "/out:$module.lib"
done
for optimization in O1 O2; do
    mkdir -p "$outdir/$optimization"
    compile -c "$here/producer.c" -o producer.obj
    compile -c "$here/consumer.c" -o consumer.obj
    compile -c "$here/entry.c" -o entry.obj
    link /dll /noentry /nodefaultlib /timestamp:0 /machine:x64 \
        "/out:$outdir/$optimization/task_producer.dll" /implib:producer.lib producer.obj ole32.lib
    link /dll /noentry /nodefaultlib /timestamp:0 /machine:x64 \
        "/out:$outdir/$optimization/task_consumer.dll" /implib:consumer.lib consumer.obj combase.lib
    link /entry:entry /subsystem:console /nodefaultlib /timestamp:0 /machine:x64 \
        "/out:$outdir/$optimization/com-task-ownership.exe" entry.obj producer.lib consumer.lib \
        com-api.lib kernel32.lib
done
