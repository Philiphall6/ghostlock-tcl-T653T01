#!/bin/bash
set -euo pipefail

BUNDLE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
: "${ADB_TARGET:?Set ADB_TARGET to an owner-authorized T653T01 TV}"
ADB=${ADB:-$(command -v adb)}
ADB_VENDOR_KEYS=${ADB_VENDOR_KEYS:-$HOME/.android/adbkey}
export ADB_VENDOR_KEYS

ACK_TEXT=I_ACCEPT_V65X_KERNEL_PANIC_RISK
FAILURE_REBOOT=${TCL_V65X_FAILURE_REBOOT:-1}
GHOST="$BUNDLE/ghostlock-tcl-v65x-experimental"
HELPER="$BUNDLE/tcl-newselect-arm32-helper"
HANDOFF="$BUNDLE/tcl-resukisu-handoff-v65x"
PREFLIGHT="$BUNDLE/tcl-resukisu-preflight-v65x"
KSUD="$BUNDLE/resukisu-ksud-armv7"
MODULE="$BUNDLE/resukisu-tcl-v65x-5.15.192-android14-11.ko"
MANAGER_PACKAGE=com.philiphall6.resukisu.tcl

printf '%s\n' \
  'DANGER — EXPERIMENTAL T653T01 V65x PRE-RELEASE' \
  'V655/V665/V667 and kernel 5.15.192 have not been tested on real hardware.' \
  'The TV may kernel-panic, reboot, lose ADB/network, or require a power cycle.' \
  'This is one volatile attempt only. It does not flash or unlock the TV.'

if [ "${TCL_V65X_UNTESTED_ACK:-}" != "$ACK_TEXT" ]; then
  if [ ! -t 0 ]; then
    printf 'REFUSED: set TCL_V65X_UNTESTED_ACK=%s explicitly.\n' \
      "$ACK_TEXT" >&2
    exit 2
  fi
  printf 'Type exactly %s to continue: ' "$ACK_TEXT"
  IFS= read -r answer
  if [ "$answer" != "$ACK_TEXT" ]; then
    printf 'REFUSED: risk acknowledgement did not match.\n' >&2
    exit 2
  fi
  TCL_V65X_UNTESTED_ACK=$answer
fi
export TCL_V65X_UNTESTED_ACK

for required in "$GHOST" "$HELPER" "$HANDOFF" "$PREFLIGHT" \
                "$KSUD" "$MODULE" "$BUNDLE/SHA256SUMS"; do
  test -f "$required" || { printf 'Missing asset: %s\n' "$required" >&2; exit 2; }
done
(cd "$BUNDLE" && sha256sum -c SHA256SUMS)

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
LOG_DIR=${GHOSTLOCK_LOG_DIR:-$PWD/ghostlock-t653t01-v65x-$STAMP}
mkdir -p "$LOG_DIR"
exec > >(tee -a "$LOG_DIR/session.log") 2>&1

attempt_started=0
root_success=0
initial_boot_id=
safety_reboot() {
  rc=$?
  trap - EXIT INT TERM
  if [ "$attempt_started" -eq 1 ] && [ "$root_success" -eq 0 ] &&
     [ "$FAILURE_REBOOT" = 1 ]; then
    printf 'FAIL-SAFE: experimental attempt did not validate; requesting one reboot.\n' >&2
    if timeout 8 "$ADB" connect "$ADB_TARGET" >/dev/null 2>&1 &&
       timeout 5 "$ADB" -s "$ADB_TARGET" get-state 2>/dev/null | grep -Fqx device; then
      now=$($ADB -s "$ADB_TARGET" shell cat /proc/sys/kernel/random/boot_id \
        2>/dev/null | tr -d '\r\n' || true)
      if [ -n "$initial_boot_id" ] && [ "$now" = "$initial_boot_id" ]; then
        "$ADB" -s "$ADB_TARGET" reboot || true
      else
        printf 'The TV already rebooted; no second reboot requested.\n' >&2
      fi
    else
      printf 'ADB unavailable: the local handoff emergency path is the only remaining reboot path.\n' >&2
    fi
  fi
  exit "$rc"
}
trap safety_reboot EXIT INT TERM

timeout 10 "$ADB" connect "$ADB_TARGET" >/dev/null 2>&1 || true
"$ADB" -s "$ADB_TARGET" get-state | grep -Fx device

report=$($ADB -s "$ADB_TARGET" shell '
  caps=$(for cap in network_peer_controls open_perms extended_socket_class \
      always_check_network cgroup_seclabel nnp_nosuid_transition \
      genfs_seclabel_symlinks ioctl_skip_cloexec; do
    cat "/sys/fs/selinux/policy_capabilities/$cap" 2>/dev/null || printf "?"
  done | tr -d "\r\n")
  printf "SOFTWARE=%s\n" "$(getprop ro.software.version_id)"
  printf "KERNEL=%s\n" "$(uname -r)"
  printf "ANDROID=%s\n" "$(getprop ro.build.version.release)"
  printf "BOOT=%s\n" "$(getprop sys.boot_completed)"
  printf "AVB=%s/%s\n" "$(getprop ro.boot.verifiedbootstate)" \
    "$(getprop ro.boot.vbmeta.device_state)"
  printf "VERITY=%s\n" "$(getprop ro.boot.veritymode)"
  printf "SELINUX=%s\n" "$(getenforce)"
  printf "POLICYCAPS=%s\n" "$caps"
  printf "MODULES=%s\n" "$(grep -Ec "^(kernelsu|resukisu|kowsu) " \
    /proc/modules 2>/dev/null || true)"
  printf "UPTIME=%s\n" "$(cut -d. -f1 /proc/uptime)"
  printf "BOOT_ID=%s\n" "$(cat /proc/sys/kernel/random/boot_id)"
  printf "POLICY_SHA=%s\n" "$(sha256sum \
    /vendor/etc/selinux/precompiled_sepolicy | cut -d" " -f1)"
  printf "POLICY_SIZE=%s\n" "$(wc -c < \
    /vendor/etc/selinux/precompiled_sepolicy | tr -d " ")"
' | tr -d '\r')
printf '%s\n' "$report" | tee "$LOG_DIR/preflight.txt"

value() { printf '%s\n' "$report" | sed -n "s/^$1=//p"; }
firmware=$(value SOFTWARE)
kernel=$(value KERNEL)
policy_sha=$(value POLICY_SHA)
policy_size=$(value POLICY_SIZE)
initial_boot_id=$(value BOOT_ID)

case "$firmware" in
  V8-T653T01-LF1V655)
    expected_policy=05910147a35a431e7fd12eb6e9d872a82002c6794cb929d4139c88df3d61b83d
    expected_size=1044927
    ;;
  V8-T653T01-LF1V665|V8-T653T01-LF1V667)
    expected_policy=8386bc2d38e3909c81eb9fc079d3acb7fa2f1271c77b02698091e35a7f61ed3c
    expected_size=1045234
    ;;
  *) printf 'REFUSED: unsupported firmware %s\n' "$firmware" >&2; exit 3 ;;
esac

test "$kernel" = 5.15.192-android14-11
test "$(value ANDROID)" = 14
test "$(value BOOT)" = 1
test "$(value AVB)" = green/locked
test "$(value VERITY)" = enforcing
test "$(value SELINUX)" = Enforcing
test "$(value POLICYCAPS)" = 11100100
test "$(value MODULES)" = 0
test "$policy_sha" = "$expected_policy"
test "$policy_size" = "$expected_size"
printf '%s\n' "$initial_boot_id" | grep -Eq \
  '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

uptime_s=$(value UPTIME)
case "$uptime_s" in ''|*[!0-9]*) exit 3 ;; esac
if [ "$uptime_s" -gt 900 ]; then
  printf 'REFUSED: boot is not fresh (%ss); reboot before the attempt.\n' \
    "$uptime_s" >&2
  exit 3
fi

manager_path=$($ADB -s "$ADB_TARGET" shell "pm path '$MANAGER_PACKAGE'" \
  | tr -d '\r')
case "$manager_path" in package:/data/app/*) ;; *)
  printf 'REFUSED: required TCL ReSukiSU manager is absent.\n' >&2; exit 3 ;;
esac

REMOTE=/data/local/tmp/tcl-v65x-resukisu-lab
REMOTE_GHOST=$REMOTE/ghostlock-tcl-v65x-experimental
REMOTE_HELPER=$REMOTE/tcl-newselect-arm32-helper
REMOTE_HANDOFF=$REMOTE/tcl-resukisu-handoff-v65x
REMOTE_PREFLIGHT=$REMOTE/tcl-resukisu-preflight-v65x
REMOTE_KSUD=$REMOTE/resukisu-ksud-armv7
REMOTE_MODULE=$REMOTE/resukisu-tcl-v65x.ko
STATUS=/data/local/tmp/.tcl_resukisu_v65x_handoff_$initial_boot_id.status

$ADB -s "$ADB_TARGET" shell "mkdir -p '$REMOTE' && chmod 700 '$REMOTE'"
for pair in \
  "$GHOST:$REMOTE_GHOST" "$HELPER:$REMOTE_HELPER" \
  "$HANDOFF:$REMOTE_HANDOFF" "$PREFLIGHT:$REMOTE_PREFLIGHT" \
  "$KSUD:$REMOTE_KSUD" "$MODULE:$REMOTE_MODULE"; do
  local_path=${pair%%:*}
  remote_path=${pair#*:}
  $ADB -s "$ADB_TARGET" push "$local_path" "$remote_path"
  local_sha=$(sha256sum "$local_path" | awk '{print $1}')
  remote_sha=$($ADB -s "$ADB_TARGET" shell sha256sum "$remote_path" \
    | awk '{print $1}' | tr -d '\r')
  test "$local_sha" = "$remote_sha"
done
$ADB -s "$ADB_TARGET" shell \
  "chmod 700 '$REMOTE_GHOST' '$REMOTE_HELPER' '$REMOTE_HANDOFF' '$REMOTE_PREFLIGHT' '$REMOTE_KSUD'; chmod 600 '$REMOTE_MODULE'"

$ADB -s "$ADB_TARGET" shell "$REMOTE_HELPER --selftest" \
  | tee "$LOG_DIR/helper-selftest.log"
$ADB -s "$ADB_TARGET" shell "$REMOTE_GHOST --profile-info 5.15.192-android14-11" \
  | tee "$LOG_DIR/profile-info.log"
$ADB -s "$ADB_TARGET" shell "$REMOTE_GHOST --capture-witness-preflight" \
  | tee "$LOG_DIR/capture-preflight.log"

gate=/data/local/tmp/.tcl_v65x_experimental_attempt_$initial_boot_id
gate_result=$($ADB -s "$ADB_TARGET" shell \
  "if mkdir '$gate' 2>/dev/null; then echo ROOT_GATE_OK; else echo ROOT_GATE_EXISTS; fi" \
  | tr -d '\r')
test "$gate_result" = ROOT_GATE_OK || {
  printf 'REFUSED: the one-attempt gate is already consumed for this boot.\n' >&2
  exit 4
}

attempt_started=1
printf 'Starting one UNTESTED volatile V65x attempt now.\n'
set +e
$ADB -s "$ADB_TARGET" shell \
  "cd '$REMOTE' && timeout 240 env \
TCL_V65X_UNTESTED_ACK='$ACK_TEXT' \
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
printf 'GhostLock rc=%d; reconnecting for validation.\n' "$exploit_rc"

connected=0
for _ in $(seq 1 60); do
  timeout 5 "$ADB" connect "$ADB_TARGET" >/dev/null 2>&1 || true
  if timeout 4 "$ADB" -s "$ADB_TARGET" get-state 2>/dev/null | grep -Fqx device; then
    connected=1
    break
  fi
  sleep 2
done
test "$connected" = 1

after_boot=$($ADB -s "$ADB_TARGET" shell cat /proc/sys/kernel/random/boot_id \
  | tr -d '\r\n')
test "$after_boot" = "$initial_boot_id" || {
  printf 'FAILED: the kernel rebooted/panicked during the attempt.\n' >&2
  exit 7
}

validation=$($ADB -s "$ADB_TARGET" shell "
  cat '$STATUS' 2>/dev/null || echo state=UNAVAILABLE
  caps=\$(for cap in network_peer_controls open_perms extended_socket_class \
      always_check_network cgroup_seclabel nnp_nosuid_transition \
      genfs_seclabel_symlinks ioctl_skip_cloexec; do
    cat \"/sys/fs/selinux/policy_capabilities/\$cap\" 2>/dev/null || printf '?'
  done | tr -d '\\r\\n')
  echo POLICYCAPS=\$caps
  echo SELINUX=\$(getenforce)
  echo AVB=\$(getprop ro.boot.verifiedbootstate)/\$(getprop ro.boot.vbmeta.device_state)
  echo MODULE=\$(grep '^kernelsu ' /proc/modules 2>/dev/null || echo absent)
  '$REMOTE_KSUD' debug version 2>&1; echo KSUD_PROBE_RC=\$?
  echo ADB_POST=ok" | tr -d '\r')
printf '%s\n' "$validation" | tee "$LOG_DIR/final-validation.txt"

for marker in state=READY module=kernelsu mode=volatile late_load=ok \
  POLICYCAPS=11100100 SELINUX=Enforcing AVB=green/locked ADB_POST=ok; do
  printf '%s\n' "$validation" | grep -Fq "$marker"
done

root_success=1
sha256sum "$LOG_DIR"/*.log "$LOG_DIR"/*.txt > "$LOG_DIR/SHA256SUMS"
printf '%s\n' \
  'EXPERIMENTAL PASS: V65x temporary root and ReSukiSU are active.' \
  'This single success does not promote the firmware to stable support.'
