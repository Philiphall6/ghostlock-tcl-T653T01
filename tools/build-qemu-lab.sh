#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT="$ROOT/build/qemu-glibc"
CFLAGS='-O2 -Wall -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function'
INCLUDES="-I$ROOT/src/core -I$ROOT/src/devices"
SRCS="$ROOT/src/core/main.c $ROOT/src/core/util.c $ROOT/src/core/fops.c"

mkdir -p "$OUT"
aarch64-linux-gnu-gcc $CFLAGS $INCLUDES \
  -DTARGET_CONFIG_H='"target.h"' -include "$ROOT/stubs/dl_stub.h" \
  -DTCL_V643_LAB_ARMING=1 -static -pthread $SRCS \
  -o "$OUT/ghostlock-tcl-v643-lab"
arm-linux-gnueabihf-gcc $CFLAGS $INCLUDES \
  -DTARGET_CONFIG_H='"target.h"' -include "$ROOT/stubs/dl_stub.h" \
  -static -pthread "$ROOT/src/helpers/tcl_v643_mcast_helper.c" \
  -o "$OUT/tcl-v643-mcast-helper"
aarch64-linux-gnu-gcc $CFLAGS -static \
  "$ROOT/tests/tcl_v643_uring_perf_probe.c" \
  -o "$OUT/tcl-v643-uring-perf-probe"

cp -f "$OUT/ghostlock-tcl-v643-lab" "$ROOT/ghostlock-tcl-v643-lab"
cp -f "$OUT/tcl-v643-mcast-helper" "$ROOT/tcl-v643-mcast-helper"
if command -v file >/dev/null 2>&1; then
  file "$OUT"/*
fi
sha256sum "$OUT"/* > "$OUT/SHA256SUMS"
cat "$OUT/SHA256SUMS"
