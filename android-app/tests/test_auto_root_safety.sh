#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ACTIVITY="$ROOT/src/lab/tcl/rootverifier/MainActivity.java"
SERVICE="$ROOT/src/lab/tcl/rootverifier/AutoRootService.java"
STATE="$ROOT/src/lab/tcl/rootverifier/AutoRootState.java"
PROFILE="$ROOT/src/lab/tcl/rootverifier/TclRootProfile.java"
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

# Opt-in state is false by default and tied to one recognized exact profile.
require 'getBoolean(ENABLED, false)' "$STATE"
require 'TclRootProfile.fromAuthorizationKey' "$STATE"
require 'enableForValidatedProfile' "$STATE"
require 'disarmAfterIncompletePreviousBoot' "$STATE"
require '|| !AutoRootState.isEnabled(context)) return;' "$RECEIVER"

# Each enabled firmware is exact. Experimental families retain their runtime
# acknowledgements and never fall through to a generic V6xx profile.
for firmware in V8-T653T01-LF1V637 V8-T653T01-LF1V643 \
    V8-T653T01-LF1V655 V8-T653T01-LF1V665 V8-T653T01-LF1V667; do
  require "$firmware" "$PROFILE"
done
require 'TCL_V637_UNTESTED_ACK=I_ACCEPT_V637_KERNEL_PANIC_RISK' "$PROFILE"
require 'TCL_V65X_UNTESTED_ACK=I_ACCEPT_V65X_KERNEL_PANIC_RISK' "$PROFILE"
require 'static TclRootProfile exact(String state' "$PROFILE"

# The TV control remains grey until this app itself has working su + driver.
require 'autoRoot.setEnabled(false)' "$ACTIVITY"
require 'else if (appRootValidated)' "$ACTIVITY"
require 'su.contains("uid=0") && driver.contains("Kernel Version:")' "$ACTIVITY"
require 'exact_supported_profile=' "$ACTIVITY"
require 'showExperimentalRootWarning' "$ACTIVITY"

# Boot worker stays authorization-exact, one-shot, volatile and non-rebooting.
require 'AutoRootState.authorizedProfile' "$SERVICE"
require '!profile.id.equals(detected.id)' "$SERVICE"
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
  'PASS: auto-root is opt-in, root-gated, exact-profile, one-shot and anti-loop'
