#!/bin/sh
set -eu

# QEMU-only negative gate: boot the exact TCL kernel harness that exposes the
# layout ioctl but deliberately has no PFN observer.  The production reclaim
# must stop at the capture witness and the VM must remain panic-free.
LAB=${LAB:-/lab}
TOOLS="$LAB/09_TOOLS/qemu-v643-cleanup"
PORT="$LAB/09_TOOLS/ghostlock-sabrina"
KERNEL_OUT="$LAB/11_KERNEL_ANALYSIS_GENERATED/V643_20260918/qemu-exact-root-aosp"
OUT=${GL_WITNESS_NEG_OUT:-$LAB/11_KERNEL_ANALYSIS_GENERATED/V643_20260918/qemu-stability-witness-negative}
ROOTFS="$OUT/initramfs"
SYSTEM_MAP="$KERNEL_OUT/build/System.map"
LOG="$OUT/qemu-witness-negative-console.log"

root_tg=$(awk '$3 == "root_task_group" { print "0x" $1; exit }' "$SYSTEM_MAP")
init_ns=$(awk '$3 == "init_user_ns" { print "0x" $1; exit }' "$SYSTEM_MAP")
test -n "$root_tg"
test -n "$init_ns"

mkdir -p "$ROOTFS"
rm -f "$ROOTFS/init" "$ROOTFS/ghostlock-tcl-v643-lab" \
  "$ROOTFS/tcl-v643-mcast-helper"

aarch64-linux-gnu-gcc -O2 -Wall -Wextra -static \
  -DGL_QEMU_ROOT_TASK_GROUP=\"$root_tg\" \
  -DGL_QEMU_INIT_USER_NS=\"$init_ns\" \
  "$TOOLS/gl_production_root_gate_init.c" -o "$ROOTFS/init"
cp "$PORT/build/qemu-glibc/ghostlock-tcl-v643-lab" \
  "$ROOTFS/ghostlock-tcl-v643-lab"
cp "$PORT/build/qemu-glibc/tcl-v643-mcast-helper" \
  "$ROOTFS/tcl-v643-mcast-helper"

(cd "$ROOTFS" && find . -print0 | cpio --null -o --format=newc) | \
  gzip -9 > "$OUT/initramfs-witness-negative.cpio.gz"

timeout --signal=INT 240 qemu-system-aarch64 \
  -machine virt -cpu max -smp 4 -m 1024 -nodefaults -display none \
  -serial stdio -monitor none -no-reboot \
  -kernel "$KERNEL_OUT/build/arch/arm64/boot/Image" \
  -initrd "$OUT/initramfs-witness-negative.cpio.gz" \
  -append 'console=ttyAMA0 rdinit=/init panic=1 loglevel=5' \
  2>&1 | tee "$LOG"

grep -q 'TCL capture witness: method=pagemap visible=0/16 hits=0 block=-1' "$LOG"
grep -q 'TCL reclaim: capture is not proven; refusing the dangerous route' "$LOG"
grep -q 'GL2CYCLE GATE FAIL' "$LOG"
if grep -Eq 'TCL split diag|TCL split: erase=|Kernel panic|Unable to handle kernel' "$LOG"; then
  echo 'negative witness gate reached the trigger or emitted a kernel failure' >&2
  exit 1
fi
echo 'GL WITNESS NEGATIVE PASS: unavailable PFNs stopped before the split trigger'

(cd "$OUT" && sha256sum initramfs/init \
  initramfs/ghostlock-tcl-v643-lab initramfs/tcl-v643-mcast-helper \
  initramfs-witness-negative.cpio.gz qemu-witness-negative-console.log \
  > SHA256SUMS)
