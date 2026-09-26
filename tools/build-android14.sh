#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
NDK_ROOT=${NDK_ROOT:-${ANDROID_NDK_ROOT:-}}
: "${NDK_ROOT:?Set ANDROID_NDK_ROOT or NDK_ROOT to Android NDK r27d}"
API=${API:-34}
QEMU_OUT="$ROOT/build/qemu-glibc"
ANDROID_OUT="$ROOT/build/android${API}"

mkdir -p "$QEMU_OUT" "$ANDROID_OUT"

# The QEMU gates use the existing GNU/Linux static artifacts. Preserve them
# separately before the in-tree Makefile target names are reused by the NDK.
for name in ghostlock ghostlock-tcl-v643-lab tcl-v643-mcast-helper; do
  if [ -f "$ROOT/$name" ] && file "$ROOT/$name" | grep -q 'GNU/Linux'; then
    cp -f "$ROOT/$name" "$QEMU_OUT/$name"
  fi
done

restore_qemu() {
  for name in ghostlock ghostlock-tcl-v643-lab tcl-v643-mcast-helper; do
    if [ -f "$QEMU_OUT/$name" ]; then
      cp -f "$QEMU_OUT/$name" "$ROOT/$name"
    fi
  done
}
trap restore_qemu EXIT INT TERM

make -C "$ROOT" clean
make -C "$ROOT" -j"$(nproc)" API="$API" NDK_ROOT="$NDK_ROOT" \
  ghostlock ghostlock-tcl-v643-lab tcl-v643-mcast-helper \
  tcl-v643-uring-perf-probe

cp -f "$ROOT/ghostlock" "$ROOT/ghostlock-tcl-v643-lab" \
  "$ROOT/tcl-v643-mcast-helper" "$ROOT/tcl-v643-uring-perf-probe" \
  "$ANDROID_OUT/"

file "$ANDROID_OUT/ghostlock" "$ANDROID_OUT/ghostlock-tcl-v643-lab" \
  "$ANDROID_OUT/tcl-v643-mcast-helper" \
  "$ANDROID_OUT/tcl-v643-uring-perf-probe"
sha256sum "$ANDROID_OUT/ghostlock" \
  "$ANDROID_OUT/ghostlock-tcl-v643-lab" \
  "$ANDROID_OUT/tcl-v643-mcast-helper" \
  "$ANDROID_OUT/tcl-v643-uring-perf-probe" > "$ANDROID_OUT/SHA256SUMS"
cat "$ANDROID_OUT/SHA256SUMS"
