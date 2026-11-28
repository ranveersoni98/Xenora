#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
out=${1:?usage: build.sh OUTPUT_DIRECTORY [-O1|-O2]}
opt=${2:--O1}
case "$opt" in
    -O1|-O2) ;;
    *) echo "expected -O1 or -O2" >&2; exit 2 ;;
esac

gxx=${MINGW_GXX:-/opt/homebrew/opt/mingw-w64/bin/x86_64-w64-mingw32-g++}
if [ ! -x "$gxx" ] && [ -z "${MINGW_GXX:-}" ]; then
    gxx=$(command -v x86_64-w64-mingw32-g++)
fi
native_tool() {
    file -L "$1"
    lipo -archs "$1"
    lipo "$1" -verify_arch arm64
    otool -L "$1"
}
native_tool "$gxx"
test "$(arch -arm64 "$gxx" -dumpmachine)" = x86_64-w64-mingw32
for helper in cc1plus as ld collect2; do
    path=$(arch -arm64 "$gxx" -print-prog-name="$helper")
    if [ ! -x "$path" ]; then
        path=$(command -v "$path")
    fi
    native_tool "$path"
done

unwinder=libgcc_s_seh-1.dll
runtime=$(arch -arm64 "$gxx" "-print-file-name=$unwinder")
test "$runtime" != "$unwinder"
test -f "$runtime"
runtime_dir=$(CDPATH= cd -- "$(dirname -- "$runtime")" && pwd -P)

mkdir -p "$out"
out=$(CDPATH= cd -- "$out" && pwd)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/xenora-gnu-vector-reserve.XXXXXX")
trap 'rm -rf "$scratch"' EXIT

cd "$scratch"
arch -arm64 "$gxx" "$opt" -std=c++17 -Wall -Wextra -Werror -static-libstdc++ -shared-libgcc \
    "$here/guest.cpp" -o "$out/gnu-vector-reserve.exe"
printf '%s\n' "$runtime_dir/$(basename -- "$runtime")" > "$out/unwinder-path.txt"
