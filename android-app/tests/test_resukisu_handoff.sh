#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT HUP INT TERM

cc -O2 -Wall -Wextra -Werror -DTCL_HANDOFF_TESTING \
  "$ROOT/broker/tcl_resukisu_handoff.c" -o "$TEST_DIR/handoff"
cp "$ROOT/tests/fake_ksud.sh" "$TEST_DIR/ksud"
chmod 755 "$TEST_DIR/ksud"
printf '0' > "$TEST_DIR/enforce"
: > "$TEST_DIR/modules"
: > "$TEST_DIR/module.ko"
mkdir "$TEST_DIR/policycaps"
# Minimal V643-compatible binary policy header: policy magic, "SE Linux",
# version 30 and config 0xc0000001 (both Android netlink compatibility bits).
printf '\214\377\174\371\010\000\000\000SE Linux\036\000\000\000\001\000\000\300' \
  > "$TEST_DIR/policy"
# Production accepts only the exact V643 combined-policy size.  Preserve the
# validated header above and pad the fixture to the same byte count so the
# test exercises the production guard rather than bypassing it.
truncate -s 1030054 "$TEST_DIR/policy"
: > "$TEST_DIR/load"
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
  --module "$TEST_DIR/module.ko" --status "$TEST_DIR/status" \
  --completion-fd 9 9>/dev/null

grep -q '^state=READY$' "$TEST_DIR/status"
grep -q '^mode=volatile$' "$TEST_DIR/status"
[ "$(cat "$TEST_DIR/enforce")" = 1 ]
cmp "$TEST_DIR/policy" "$TEST_DIR/load"

# The TCL release must never accept the generic upstream manager package in
# place of the pinned Philiphall6 fork.
set +e
TCL_RESUKISU_MANAGER_PACKAGE=com.resukisu.resukisu \
TCL_HANDOFF_ENFORCE_FILE="$TEST_DIR/enforce" \
TCL_HANDOFF_MODULES_FILE="$TEST_DIR/modules" \
TCL_HANDOFF_POLICY_FILE="$TEST_DIR/policy" \
TCL_HANDOFF_LOAD_FILE="$TEST_DIR/load" \
TCL_HANDOFF_POLICYCAP_DIR="$TEST_DIR/policycaps" \
  "$TEST_DIR/handoff" --direct-child \
  --preflight /bin/true --ksud "$TEST_DIR/ksud" \
  --module "$TEST_DIR/module.ko" --status "$TEST_DIR/status-generic" \
  --completion-fd 9 9>/dev/null
generic_rc=$?
set -e
[ "$generic_rc" -eq 3 ]
[ ! -e "$TEST_DIR/status-generic" ]
printf 'PASS: ReSukiSU policy/network restore precedes enforcing\n'
