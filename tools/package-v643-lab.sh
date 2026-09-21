#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
STAMP=${STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}
OUT="$ROOT/build/TCL_V643_ROOT_LAB_$STAMP"
ANDROID="$ROOT/build/android34"

mkdir -p "$OUT"
cp -f "$ANDROID/ghostlock" "$OUT/ghostlock-analysis-only"
cp -f "$ANDROID/ghostlock-tcl-v643-lab" "$OUT/ghostlock-tcl-v643-lab"
cp -f "$ANDROID/tcl-v643-mcast-helper" "$OUT/tcl-v643-mcast-helper"
cp -f "$ROOT/tools/tv-readonly-preflight.sh" "$OUT/"
cp -f "$ROOT/docs/TCL_V643_STABILITY_GATE_20260921.md" "$OUT/"

commit=$(git -C "$ROOT" rev-parse HEAD)
dirty=$(git -C "$ROOT" status --porcelain | wc -l)
{
  echo "TCL C855 / T653T01 V643 Android 14 laboratory package"
  echo "commit=$commit"
  echo "dirty_entries_at_package_time=$dirty"
  echo "api=34"
  echo "ndk=r27d"
  echo "normal_binary=analysis-only (primitive refused)"
  echo "lab_binary=explicitly armed; volatile test only; kernel panic/reboot possible"
  echo "capture_witness=all mapping PFNs visible and exactly one target required"
  echo "safe_preflight=--capture-witness-preflight performs no reclaim/futex/MCAST/write"
  echo "forbidden=fastboot, OEM unlock, flash, persistent installation"
} > "$OUT/MANIFEST.txt"

file "$OUT/ghostlock-analysis-only" "$OUT/ghostlock-tcl-v643-lab" \
  "$OUT/tcl-v643-mcast-helper" > "$OUT/FILE.txt"
(cd "$OUT" && sha256sum ghostlock-analysis-only \
  ghostlock-tcl-v643-lab tcl-v643-mcast-helper \
  tv-readonly-preflight.sh TCL_V643_STABILITY_GATE_20260921.md \
  MANIFEST.txt FILE.txt > SHA256SUMS)
(cd "$OUT" && sha1sum ghostlock-analysis-only \
  ghostlock-tcl-v643-lab tcl-v643-mcast-helper > SHA1SUMS)
(cd "$OUT" && md5sum ghostlock-analysis-only \
  ghostlock-tcl-v643-lab tcl-v643-mcast-helper > MD5SUMS)

tar -C "$ROOT/build" -cJf "$OUT.tar.xz" "$(basename "$OUT")"
sha256sum "$OUT.tar.xz" > "$OUT.tar.xz.sha256"
printf '%s\n' "$OUT"
