#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT HUP INT TERM

cc -O2 -Wall -Wextra -Werror -DTCL_BROKER_TESTING \
  "$ROOT/broker/tcl_root_broker.c" -o "$TEST_DIR/broker"
cc -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/tcl_root_broker_client.c" -o "$TEST_DIR/client"

run_client_when_ready() {
  socket_name=$1
  output_file=$2
  shift 2
  attempt=0
  while [ "$attempt" -lt 100 ]; do
    if "$TEST_DIR/client" "$socket_name" "$@" \
        > "$output_file" 2>/dev/null; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 0.02
  done
  printf 'client could not connect to broker %s\n' "$socket_name" >&2
  return 1
}

mkdir "$TEST_DIR/policycaps"
printf '\214\377\174\371\010\000\000\000SE Linux\036\000\000\000\001\000\000\300' \
  > "$TEST_DIR/boot-policy"
truncate -s 1030054 "$TEST_DIR/boot-policy"
for cap in network_peer_controls open_perms extended_socket_class \
           nnp_nosuid_transition; do
  printf '1\n' > "$TEST_DIR/policycaps/$cap"
done
for cap in always_check_network cgroup_seclabel genfs_seclabel_symlinks \
           ioctl_skip_cloexec; do
  printf '0\n' > "$TEST_DIR/policycaps/$cap"
done
printf '0\n' > "$TEST_DIR/enforce"
: > "$TEST_DIR/load"
cp "$ROOT/tests/fake_handoff.sh" "$TEST_DIR/handoff"
chmod 755 "$TEST_DIR/handoff"
: > "$TEST_DIR/module.ko"

run_test_client() {
  socket_name=$1
  output_file=$2
  status_file=$3
  run_client_when_ready "$socket_name" "$output_file" \
    "$TEST_DIR/handoff" /bin/true /bin/true \
    "$TEST_DIR/module.ko" "$status_file"
}

name="tcl_policy_network_test_$$"
TCL_BROKER_ENFORCE_FILE="$TEST_DIR/enforce" \
TCL_BROKER_POLICY_FILE="$TEST_DIR/boot-policy" \
TCL_BROKER_LOAD_FILE="$TEST_DIR/load" \
TCL_BROKER_POLICYCAP_DIR="$TEST_DIR/policycaps" \
TCL_BROKER_WATCHDOG_FILE="$TEST_DIR/watchdog" \
  "$TEST_DIR/broker" --uid "$(id -u)" --abstract "$name" \
    --arm-timeout-ms 10000 --reboot-after-ms 5000 \
    > "$TEST_DIR/broker.log" 2>&1 &
broker_pid=$!
run_test_client "$name" "$TEST_DIR/client.log" "$TEST_DIR/status"
wait "$broker_pid"

grep -q 'policycaps=11100100 netlink=restored' "$TEST_DIR/client.log"
grep -q 'stage=parked-no-reboot.*selinux=1' "$TEST_DIR/watchdog"
if grep -q 'stage=rebooting' "$TEST_DIR/watchdog"; then
  printf 'unexpected reboot marker on successful restoration\n' >&2
  exit 1
fi
[ "$(cat "$TEST_DIR/enforce")" = 1 ]
cmp "$TEST_DIR/boot-policy" "$TEST_DIR/load"
[ "$(stat -c %a "$TEST_DIR/watchdog")" = 644 ]

# A supervised ADB heartbeat is optional. When armed, a normal proof writes
# the disarm marker only after ADB has verified the restored state. The
# broker must then park without rebooting.
printf 'heartbeat-1\n' > "$TEST_DIR/heartbeat"
rm -f "$TEST_DIR/disarm"
printf '0\n' > "$TEST_DIR/enforce"
: > "$TEST_DIR/load"
name="tcl_adb_heartbeat_disarm_$$"
TCL_BROKER_ENFORCE_FILE="$TEST_DIR/enforce" \
TCL_BROKER_POLICY_FILE="$TEST_DIR/boot-policy" \
TCL_BROKER_LOAD_FILE="$TEST_DIR/load" \
TCL_BROKER_POLICYCAP_DIR="$TEST_DIR/policycaps" \
TCL_BROKER_WATCHDOG_FILE="$TEST_DIR/watchdog-heartbeat" \
TCL_BROKER_ADB_HEARTBEAT_FILE="$TEST_DIR/heartbeat" \
TCL_BROKER_ADB_DISARM_FILE="$TEST_DIR/disarm" \
TCL_BROKER_ADB_HEARTBEAT_TIMEOUT_MS=3000 \
  "$TEST_DIR/broker" --uid "$(id -u)" --abstract "$name" \
    --arm-timeout-ms 10000 --reboot-after-ms 5000 \
    > "$TEST_DIR/broker-heartbeat.log" 2>&1 &
broker_pid=$!
run_test_client "$name" "$TEST_DIR/client-heartbeat.log" \
  "$TEST_DIR/status-heartbeat"
for _ in $(seq 1 50); do
  grep -q 'stage=adb-heartbeat-armed' "$TEST_DIR/watchdog-heartbeat" \
    2>/dev/null && break
  sleep 0.05
done
grep -q 'stage=adb-heartbeat-armed.*delay_ms=3000.*selinux=1' \
  "$TEST_DIR/watchdog-heartbeat"
printf 'disarmed\n' > "$TEST_DIR/disarm"
wait "$broker_pid"
grep -q 'stage=adb-heartbeat-disarmed.*selinux=1' \
  "$TEST_DIR/watchdog-heartbeat"
if grep -q 'stage=adb-heartbeat-rebooting' "$TEST_DIR/watchdog-heartbeat"; then
  printf 'unexpected heartbeat reboot after explicit disarm\n' >&2
  exit 1
fi

# If the ADB heartbeat freezes before disarm, the local broker must select
# the recovery reboot path without requiring another ADB command.
printf 'heartbeat-stale\n' > "$TEST_DIR/heartbeat-expiry"
rm -f "$TEST_DIR/disarm-expiry"
printf '0\n' > "$TEST_DIR/enforce"
: > "$TEST_DIR/load"
name="tcl_adb_heartbeat_expiry_$$"
set +e
TCL_BROKER_ENFORCE_FILE="$TEST_DIR/enforce" \
TCL_BROKER_POLICY_FILE="$TEST_DIR/boot-policy" \
TCL_BROKER_LOAD_FILE="$TEST_DIR/load" \
TCL_BROKER_POLICYCAP_DIR="$TEST_DIR/policycaps" \
TCL_BROKER_WATCHDOG_FILE="$TEST_DIR/watchdog-heartbeat-expiry" \
TCL_BROKER_ADB_HEARTBEAT_FILE="$TEST_DIR/heartbeat-expiry" \
TCL_BROKER_ADB_DISARM_FILE="$TEST_DIR/disarm-expiry" \
TCL_BROKER_ADB_HEARTBEAT_TIMEOUT_MS=500 \
  "$TEST_DIR/broker" --uid "$(id -u)" --abstract "$name" \
    --arm-timeout-ms 10000 --reboot-after-ms 5000 \
    > "$TEST_DIR/broker-heartbeat-expiry.log" 2>&1 &
broker_pid=$!
run_test_client "$name" "$TEST_DIR/client-heartbeat-expiry.log" \
  "$TEST_DIR/status-heartbeat-expiry"
wait "$broker_pid"
heartbeat_expiry_rc=$?
set -e
[ "$heartbeat_expiry_rc" -eq 10 ]
grep -q 'stage=adb-heartbeat-expired.*delay_ms=500.*selinux=1' \
  "$TEST_DIR/watchdog-heartbeat-expiry"
grep -q 'stage=adb-heartbeat-rebooting.*selinux=1' \
  "$TEST_DIR/watchdog-heartbeat-expiry"

# The 5.15 /sys/fs/selinux/policy serializer omits both Android netlink
# compatibility bits.  It must be rejected rather than reloaded: doing so is
# the network-loss bug this guard exists to prevent.
cp "$TEST_DIR/boot-policy" "$TEST_DIR/live-serialized-policy"
printf '\001\000\000\000' | dd of="$TEST_DIR/live-serialized-policy" \
  bs=1 seek=20 conv=notrunc status=none
printf '0\n' > "$TEST_DIR/enforce"
: > "$TEST_DIR/load"
name="tcl_serialized_policy_negative_$$"
set +e
TCL_BROKER_ENFORCE_FILE="$TEST_DIR/enforce" \
TCL_BROKER_POLICY_FILE="$TEST_DIR/live-serialized-policy" \
TCL_BROKER_LOAD_FILE="$TEST_DIR/load" \
TCL_BROKER_POLICYCAP_DIR="$TEST_DIR/policycaps" \
TCL_BROKER_WATCHDOG_FILE="$TEST_DIR/watchdog-serialized-negative" \
  "$TEST_DIR/broker" --uid "$(id -u)" --abstract "$name" \
    --arm-timeout-ms 1000 --reboot-after-ms 5000 \
    > "$TEST_DIR/broker-serialized-negative.log" 2>&1
serialized_negative_rc=$?
set -e
[ "$serialized_negative_rc" -eq 9 ]
[ "$(cat "$TEST_DIR/enforce")" = 0 ]
[ ! -s "$TEST_DIR/load" ]
grep -q 'stage=armed.*delay_ms=1000.*selinux=0.*errno=71' \
  "$TEST_DIR/watchdog-serialized-negative"

# A mismatched network policycap must fail closed: do not enable enforcing,
# and arm the shortened reboot watchdog.
printf '1\n' > "$TEST_DIR/policycaps/always_check_network"
printf '0\n' > "$TEST_DIR/enforce"
: > "$TEST_DIR/load"
name="tcl_policy_network_negative_$$"
set +e
TCL_BROKER_ENFORCE_FILE="$TEST_DIR/enforce" \
TCL_BROKER_POLICY_FILE="$TEST_DIR/boot-policy" \
TCL_BROKER_LOAD_FILE="$TEST_DIR/load" \
TCL_BROKER_POLICYCAP_DIR="$TEST_DIR/policycaps" \
TCL_BROKER_WATCHDOG_FILE="$TEST_DIR/watchdog-negative" \
  "$TEST_DIR/broker" --uid "$(id -u)" --abstract "$name" \
    --arm-timeout-ms 1000 --reboot-after-ms 5000 \
    > "$TEST_DIR/broker-negative.log" 2>&1
negative_rc=$?
set -e
[ "$negative_rc" -eq 9 ]
[ "$(cat "$TEST_DIR/enforce")" = 0 ]
grep -q 'stage=armed.*delay_ms=1000.*selinux=0' \
  "$TEST_DIR/watchdog-negative"

printf 'PASS: broker restores network policy, parks without reboot, and fails closed\n'
