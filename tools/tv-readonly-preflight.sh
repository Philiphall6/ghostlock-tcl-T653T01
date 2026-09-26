#!/bin/sh
set -eu

SERIAL=${1:-${ADB_TARGET:-}}
ADB=${ADB:-adb}
fail=0

if [ -z "$SERIAL" ]; then
  printf 'Usage: %s <authorized-adb-serial>\n' "$0" >&2
  exit 2
fi

prop() {
  "$ADB" -s "$SERIAL" shell getprop "$1" 2>/dev/null | tr -d '\r'
}

check_eq() {
  label=$1
  got=$2
  want=$3
  if [ "$got" = "$want" ]; then
    printf '[OK] %s=%s\n' "$label" "$got"
  else
    printf '[BLOCKED] %s=%s (expected %s)\n' "$label" "$got" "$want"
    fail=1
  fi
}

state=$("$ADB" devices | awk -v s="$SERIAL" '$1 == s { print $2 }')
check_eq adb_state "${state:-missing}" device

model=$(prop ro.product.model)
device=$(prop ro.product.device)
android=$(prop ro.build.version.release)
kernel=$("$ADB" -s "$SERIAL" shell uname -r 2>/dev/null | tr -d '\r')
display=$(prop ro.build.display.id)
incremental=$(prop ro.build.version.incremental)
software=$(prop ro.software.version_id)
if [ -z "$software" ]; then
  software=$(prop persist.odm.tcl.glp_copy_version)
fi
abilist=$(prop ro.product.cpu.abilist)
abilist32=$(prop ro.product.cpu.abilist32)

printf 'model=%s\ndevice=%s\ndisplay=%s\nincremental=%s\nsoftware=%s\n' \
  "$model" "$device" "$display" "$incremental" "$software"
check_eq device "$device" G08
check_eq android "$android" 14
check_eq kernel "$kernel" 5.15.180-android14-11

case "$software" in
  *V8-T653T01-LF1V643*) printf '[OK] firmware=T653T01 V643\n' ;;
  *) printf '[BLOCKED] unexpected firmware: %s\n' "$software"; fail=1 ;;
esac
case "$abilist" in
  *arm64-v8a*) printf '[OK] Android ABI64 reported=%s\n' "$abilist" ;;
  *) printf '[INFO] reported 32-bit Android userspace=%s; test the static ARM64 ELF separately\n' "$abilist" ;;
esac
case "$abilist32" in
  *armeabi-v7a*) printf '[OK] ABI32=%s\n' "$abilist32" ;;
  *) printf '[BLOCKED] ABI32 missing: %s\n' "$abilist32"; fail=1 ;;
esac

for key in ro.build.type ro.build.tags ro.debuggable ro.secure ro.adb.secure \
  ro.boot.flash.locked ro.boot.vbmeta.device_state ro.boot.verifiedbootstate \
  ro.boot.veritymode ro.build.version.security_patch; do
  printf '%s=%s\n' "$key" "$(prop "$key")"
done

"$ADB" -s "$SERIAL" shell '
  echo "selinux=$(cat /sys/fs/selinux/enforce 2>/dev/null || echo inaccessible)"
  echo "perf_event_paranoid=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo inaccessible)"
  echo "kptr_restrict=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo inaccessible)"
  echo "io_uring_disabled=$(cat /proc/sys/kernel/io_uring_disabled 2>/dev/null || echo absent)"
  echo "nofile=$(ulimit -n 2>/dev/null || echo unknown)"
  ls -l /dev/ashmem /dev/binderfs 2>/dev/null || true
  cat /proc/meminfo | head -12
  cat /proc/zoneinfo 2>/dev/null | grep -E "^(Node|  start_pfn|  managed|  high|  batch)" | head -80
' | tr -d '\r'

if [ "$fail" -ne 0 ]; then
  echo '[BLOCKED] Read-only preflight does not match the target profile.'
  exit 1
fi
echo '[OK] Read-only ADB preflight matches; no file was written to the TV.'
