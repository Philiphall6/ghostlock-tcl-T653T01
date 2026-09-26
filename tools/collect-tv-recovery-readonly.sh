#!/bin/bash
set -euo pipefail

TARGET=${1:-${ADB_TARGET:-}}
ADB=${ADB:-$(command -v adb)}
ADB_VENDOR_KEYS=${ADB_VENDOR_KEYS:-${HOME}/.android/adbkey}
LAB_ROOT=${LAB_ROOT:-/lab}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT=${RECOVERY_LOG_DIR:-$LAB_ROOT/10_LOGS/tv-recovery-readonly-$STAMP}
export ADB_VENDOR_KEYS

if [ -z "$TARGET" ]; then
  printf 'Usage: %s <authorized-adb-serial>\n' "$0" >&2
  exit 2
fi

mkdir -p "$OUT"
exec > >(tee -a "$OUT/session.log") 2>&1

printf 'READONLY_RECOVERY start=%s target=%s\n' "$STAMP" "$TARGET"
printf 'This script does not run GhostLock, change properties, or reboot the TV.\n'

timeout 5 "$ADB" connect "$TARGET" || true
state=$(timeout 5 "$ADB" -s "$TARGET" get-state 2>/dev/null || true)
if [ "$state" != device ]; then
  printf '[BLOCKED] adb_state=%s\n' "${state:-missing}" >&2
  exit 2
fi

run() {
  local name=$1
  shift
  printf '\n===== %s =====\n' "$name"
  timeout 30 "$ADB" -s "$TARGET" shell "$@" 2>&1 \
    | tr -d '\r' | tee "$OUT/$name.txt"
}

run identity 'printf "boot_id="; cat /proc/sys/kernel/random/boot_id; printf "uptime="; cat /proc/uptime; uname -a; id'
run boot-state '
  for p in ro.software.version_id ro.build.display.id ro.build.version.incremental \
      ro.build.version.release ro.build.type ro.build.tags ro.debuggable ro.secure \
      ro.adb.secure ro.boot.flash.locked ro.boot.vbmeta.device_state \
      ro.boot.verifiedbootstate ro.boot.veritymode ro.boot.bootreason \
      ro.boot.boot_recovery ro.bootmode sys.boot_completed; do
    printf "%s=%s\n" "$p" "$(getprop "$p")"
  done
'
run selinux-state '
  printf "getenforce="; getenforce 2>&1
  printf "enforce_file="; cat /sys/fs/selinux/enforce 2>&1
  printf "policy_sha256="; sha256sum /sys/fs/selinux/policy 2>&1
  caps=""
  for cap in network_peer_controls open_perms extended_socket_class \
      always_check_network cgroup_seclabel nnp_nosuid_transition \
      genfs_seclabel_symlinks ioctl_skip_cloexec; do
    value=$(cat "/sys/fs/selinux/policy_capabilities/$cap" 2>&1)
    printf "%s=%s\n" "$cap" "$value"
    caps="${caps}${value}"
  done
  printf "policycaps=%s\n" "$caps"
'
run modules 'cat /proc/modules 2>&1; printf "tainted="; cat /proc/sys/kernel/tainted 2>&1'
run network '
  ip -details link show 2>&1
  ip address show 2>&1
  ip route show table all 2>&1
  printf "dns1=%s\n" "$(getprop net.dns1)"
  printf "dns2=%s\n" "$(getprop net.dns2)"
'
run connectivity 'dumpsys connectivity 2>&1'
run ethernet 'dumpsys ethernet 2>&1'
run wifi 'dumpsys wifi 2>&1'
run pstore '
  ls -la /sys/fs/pstore 2>&1
  for file in /sys/fs/pstore/*; do
    [ -f "$file" ] || continue
    printf "\n----- %s -----\n" "$file"
    cat "$file" 2>&1
  done
'
run kernel-tail 'dmesg 2>&1 | tail -n 500'

printf '\n[OK] Read-only collection complete: %s\n' "$OUT"
