#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ACTIVITY="$ROOT/src/lab/tcl/rootverifier/MainActivity.java"
SERVICE="$ROOT/src/lab/tcl/rootverifier/AutoRootService.java"
STATE="$ROOT/src/lab/tcl/rootverifier/AutoRootState.java"
RECEIVER="$ROOT/src/lab/tcl/rootverifier/BootReceiver.java"
MANIFEST="$ROOT/AndroidManifest.xml"

require() {
  pattern=$1
  file=$2
  grep -F "$pattern" "$file" >/dev/null || {
    printf 'FAIL: missing %s in %s\n' "$pattern" "$file" >&2
    exit 1
  }
}

# Opt-in state is false by default and tied to the one exact validated profile.
require 'getBoolean(ENABLED, false)' "$STATE"
require 'V8-T653T01-LF1V643|5.15.180-android14-11|android14' "$STATE"
require 'disarmAfterIncompletePreviousBoot' "$STATE"
require '|| !AutoRootState.isEnabled(context)) return;' "$RECEIVER"

# The TV control remains grey until this app itself has working su + driver.
require 'autoRoot.setEnabled(false)' "$ACTIVITY"
require 'else if (appRootValidated)' "$ACTIVITY"
require 'su.contains("uid=0") && driver.contains("Kernel Version:")' "$ACTIVITY"
require 'exact_v643_profile=' "$ACTIVITY"

# Boot worker stays V643-exact, one-shot, volatile and non-rebooting.
require '5.15.180-android14-11|14|1|green|locked|enforcing|Enforcing' "$SERVICE"
require 'consumeRootAttemptForCurrentBoot' "$SERVICE"
require 'markAttemptStarted' "$SERVICE"
require 'GHOST_REBOOT=0' "$SERVICE"
if grep -E '(^|[^A-Za-z])reboot([^A-Za-z]|$)' "$SERVICE" \
    | grep -v -E 'comment|reboot loop|GHOST_REBOOT|following boot|next boot' \
    >/dev/null; then
  printf 'FAIL: automatic worker contains an unexpected reboot route\n' >&2
  exit 1
fi

require 'android.intent.action.BOOT_COMPLETED' "$MANIFEST"
require 'android:foregroundServiceType="specialUse"' "$MANIFEST"
require 'android:exported="false"' "$MANIFEST"
require '!ACTION_BOOT_AUTO_ROOT.equals(intent.getAction())' "$SERVICE"

gate_line=$(grep -n 'consumeRootAttemptForCurrentBoot' "$SERVICE" \
  | head -n 1 | cut -d: -f1)
attempt_line=$(grep -n 'runGhostLockViaLocalAdb' "$SERVICE" \
  | head -n 1 | cut -d: -f1)
if [ "$gate_line" -ge "$attempt_line" ]; then
  printf 'FAIL: one-attempt gate must precede GhostLock execution\n' >&2
  exit 1
fi

printf '%s\n' \
  'PASS: auto-root is opt-in, root-gated, V643-exact, one-shot and anti-loop'
