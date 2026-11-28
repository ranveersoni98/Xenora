#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
out=${1:?usage: build.sh OUTPUT_DIRECTORY}
mkdir -p "$out"

gxx=${MINGW_GXX:-/opt/homebrew/opt/mingw-w64/bin/x86_64-w64-mingw32-g++}
if [ ! -x "$gxx" ] && [ -z "${MINGW_GXX:-}" ]; then
    gxx=$(command -v x86_64-w64-mingw32-g++)
fi
verify_native() {
    file -L "$1"
    lipo -archs "$1"
    lipo -verify_arch arm64 "$1"
    otool -L "$1"
}
verify_native "$gxx"
test "$(arch -arm64 "$gxx" -dumpmachine)" = x86_64-w64-mingw32
for helper in cc1plus as ld collect2 nm; do
    tool=$(arch -arm64 "$gxx" -print-prog-name="$helper")
    if [ ! -x "$tool" ]; then
        tool=$(command -v "$tool")
    fi
    verify_native "$tool"
    if [ "$helper" = nm ]; then
        nm=$tool
    fi
done

for optimization in O1 O2; do
    object="$out/worker-tls-$optimization.o"
    arch -arm64 "$gxx" "-$optimization" -std=c++17 -Wall -Wextra -Werror \
        -fno-exceptions -fno-rtti -c "$here/guest.cpp" -o "$object"
    arch -arm64 "$nm" "$object" > "$out/worker-tls-$optimization.symbols"
    arch -arm64 "$gxx" "-$optimization" -shared-libgcc \
        "$object" -o "$out/worker-tls-$optimization.exe"
done
