#!/bin/bash
set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD="$ROOT/build/android34"
: "${ADB_TARGET:?Set ADB_TARGET to the authorized TV serial}"
ADB_VENDOR_KEYS=${ADB_VENDOR_KEYS:-${HOME}/.android/adbkey}
export ADB_VENDOR_KEYS

diag_name=ghostlock-v643-perf-witness-diag
helper_name=tcl-v643-mcast-helper-perf-diag

adb -s "$ADB_TARGET" get-state
adb -s "$ADB_TARGET" push "$BUILD/ghostlock-tcl-v643-lab" \
  "/data/local/tmp/$diag_name"
adb -s "$ADB_TARGET" push "$BUILD/tcl-v643-mcast-helper" \
  "/data/local/tmp/$helper_name"
adb -s "$ADB_TARGET" shell chmod 755 \
  "/data/local/tmp/$diag_name" "/data/local/tmp/$helper_name"

before_boot=$(adb -s "$ADB_TARGET" shell cat /proc/sys/kernel/random/boot_id | tr -d '\r')
printf 'TV_DIAG before_boot=%s\n' "$before_boot"
sha256sum "$BUILD/ghostlock-tcl-v643-lab" "$BUILD/tcl-v643-mcast-helper"

set +e
diag_output=$(adb -s "$ADB_TARGET" shell \
  "cd /data/local/tmp && timeout 600 env \
TCL_PERF_WITNESS_DIAG_ONLY=1 \
TCL_PERF_WITNESS_ATTEMPTS=5 \
TCL_PERF_RING_LOOPS=20000 \
TCL_MCAST_HELPER=/data/local/tmp/$helper_name \
GHOST_SELINUX=0 GHOST_EXEC=0 GHOST_REBOOT=0 \
FOPS_MAX_ATTEMPTS=1 CRED_ATTEMPTS=1 KSNITCH_VERBOSE=0 \
./$diag_name --cred" 2>&1)
diag_rc=$?
set -e
printf '%s\n' "$diag_output"
printf 'TV_DIAG command_rc=%d\n' "$diag_rc"

after_boot=$(adb -s "$ADB_TARGET" shell cat /proc/sys/kernel/random/boot_id | tr -d '\r')
printf 'TV_DIAG after_boot=%s\n' "$after_boot"
adb -s "$ADB_TARGET" shell \
  "getprop ro.boot.verifiedbootstate; getprop ro.boot.vbmeta.device_state; \
getprop ro.boot.veritymode; getenforce; ps -A | grep -E 'ghostlock|mcast-helper' || true"

test "$before_boot" = "$after_boot"
test "$diag_rc" -eq 255
printf '%s\n' "$diag_output" | grep -Eq \
  'TCL capture witness: method=perf-regs .*block=[0-9]+ pfn_reference=-1 verdict=1'
printf '%s\n' "$diag_output" | grep -q \
  'TCL reclaim: capture is not proven; refusing the dangerous route'
if printf '%s\n' "$diag_output" | grep -q 'TCL split diag:'; then
  printf 'TV_DIAG FAIL: dangerous split route executed\n' >&2
  exit 1
fi
printf 'TV_DIAG PASS: unique perf witness observed; trigger remained blocked\n'
