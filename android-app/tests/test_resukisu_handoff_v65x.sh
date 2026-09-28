#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT HUP INT TERM

cc -O2 -Wall -Wextra -Werror -DTCL_HANDOFF_TESTING \
  -DEXPECTED_RELEASE='"5.15.192-android14-11"' \
  -DEXPECTED_SELINUX_POLICY_SIZE=1044927U \
  -DEXPECTED_SELINUX_POLICY_SIZE_ALT=1045234U \
  -DTCL_LAB_PREFIX='"/data/local/tmp/tcl-v65x-resukisu-lab/"' \
  "$ROOT/broker/tcl_resukisu_handoff.c" -o "$TEST_DIR/handoff"
cp "$ROOT/tests/fake_ksud.sh" "$TEST_DIR/ksud"
chmod 755 "$TEST_DIR/ksud"

run_case() {
  policy_size=$1
  printf '0' > "$TEST_DIR/enforce"
  : > "$TEST_DIR/modules"
  : > "$TEST_DIR/module.ko"
  : > "$TEST_DIR/load"
  mkdir -p "$TEST_DIR/policycaps"
  printf '\214\377\174\371\010\000\000\000SE Linux\036\000\000\000\001\000\000\300' \
    > "$TEST_DIR/policy"
  truncate -s "$policy_size" "$TEST_DIR/policy"
  for cap in network_peer_controls open_perms extended_socket_class \
             nnp_nosuid_transition; do
    printf '1\n' > "$TEST_DIR/policycaps/$cap"
  done
  for cap in always_check_network cgroup_seclabel genfs_seclabel_symlinks \
             ioctl_skip_cloexec; do
    printf '0\n' > "$TEST_DIR/policycaps/$cap"
  done

  TCL_HANDOFF_ENFORCE_FILE="$TEST_DIR/enforce" \
  TCL_HANDOFF_MODULES_FILE="$TEST_DIR/modules" \
  TCL_HANDOFF_POLICY_FILE="$TEST_DIR/policy" \
  TCL_HANDOFF_LOAD_FILE="$TEST_DIR/load" \
  TCL_HANDOFF_POLICYCAP_DIR="$TEST_DIR/policycaps" \
    "$TEST_DIR/handoff" --direct-child \
    --preflight /bin/true --ksud "$TEST_DIR/ksud" \
    --module "$TEST_DIR/module.ko" --status "$TEST_DIR/status-$policy_size" \
    --completion-fd 9 9>/dev/null

  grep -q '^state=READY$' "$TEST_DIR/status-$policy_size"
  [ "$(cat "$TEST_DIR/enforce")" = 1 ]
  cmp "$TEST_DIR/policy" "$TEST_DIR/load"
}

run_case 1044927
run_case 1045234
printf 'PASS: V655 and V665/V667 policy sizes accepted by V65x handoff\n'
