#!/bin/sh
set -eu

# QEMU-only integration gate for the T653T01 V65x profile plumbing.  The
# source kernel is TCL's published 5.15.180 tree, whose relevant allocator
# and carrier semantics have been checked offline against exact V65x code.
# This is deliberately called a surrogate: it cannot validate live V65x PCP
# state, vendor concurrency or post-root Android network/SELinux cleanup.
LAB=${LAB:-/lab}
PORT="$LAB/09_TOOLS/ghostlock-sabrina"
KERNEL_OUT=${KERNEL_OUT:-$LAB/11_KERNEL_ANALYSIS_GENERATED/V643_20260918/qemu-reclaim-kernel}
OUT=${GL_V65X_MODEL_OUT:-$LAB/11_KERNEL_ANALYSIS_GENERATED/V655_V665_V667_20260927/qemu-v65x-surrogate}
ROOTFS="$OUT/initramfs"
SYSTEM_MAP="$KERNEL_OUT/build/System.map"
LOG="$OUT/qemu-v65x-surrogate-console.log"

root_tg=$(awk '$3 == "root_task_group" { print "0x" $1; exit }' "$SYSTEM_MAP")
test -n "$root_tg"
mkdir -p "$ROOTFS"

aarch64-linux-gnu-gcc -O2 -Wall -Wextra -static \
  -DGL_QEMU_ROOT_TASK_GROUP=\"$root_tg\" \
  "$PORT/tests/tcl_v65x_qemu_model_init.c" -o "$ROOTFS/init"
cp "$PORT/build/qemu-glibc/ghostlock-tcl-v65x-qemu-model" \
  "$ROOTFS/ghostlock-tcl-v65x-qemu-model"
cp "$PORT/build/qemu-glibc/tcl-v643-mcast-helper" \
  "$ROOTFS/tcl-v65x-newselect-helper"

(cd "$ROOTFS" && find . -print0 | cpio --null -o --format=newc) | \
  gzip -9 > "$OUT/initramfs-v65x-surrogate.cpio.gz"

timeout --signal=INT 240 qemu-system-aarch64 \
  -machine virt -cpu max -smp 4 -m 1024 -nodefaults -display none \
  -serial stdio -monitor none -no-reboot \
  -kernel "$KERNEL_OUT/build/arch/arm64/boot/Image" \
  -initrd "$OUT/initramfs-v65x-surrogate.cpio.gz" \
  -append 'console=ttyAMA0 rdinit=/init panic=1 loglevel=5' \
  </dev/null 2>&1 | tee "$LOG"

grep -q 'QEMU V65X MODEL ARMING' "$LOG"
grep -q 'offsets matched: 5.15.192-android14-11' "$LOG"
grep -q 'TCL capture witness: method=qemu-observer' "$LOG"
grep -q 'TCL split: erase=1 handler=1 cleanup=1 status=0 failures=0' "$LOG"
grep -q 'GLV65XMODEL PASS' "$LOG"
if grep -Eq 'GLV65XMODEL FAIL|Kernel panic|Unable to handle kernel' "$LOG"; then
  echo 'V65x surrogate gate emitted a failure marker' >&2
  exit 1
fi

(cd "$OUT" && sha256sum initramfs/init \
  initramfs/ghostlock-tcl-v65x-qemu-model \
  initramfs/tcl-v65x-newselect-helper \
  initramfs-v65x-surrogate.cpio.gz qemu-v65x-surrogate-console.log \
  > SHA256SUMS)
