#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ANDROID="$ROOT/build/android34"
APP_BUILD="$ROOT/android-app/build"
RESUKISU_ROOT=${RESUKISU_ROOT:-$ROOT/../ReSukiSU}
RESUKISU_DIST=${RESUKISU_DIST:-$RESUKISU_ROOT/dist-tcl/v1.0/module}
OUT=${RELEASE_OUT:-$ROOT/build/release-v1.0}
ADB_NAME=GhostLock-TCL-C855-v1.0-ADB
ADB_ARCHIVE="$OUT/$ADB_NAME.tar.xz"
APK_SOURCE=${APK_SOURCE:-$APP_BUILD/TCL-Root-Verifier.apk}
APK_RELEASE="$OUT/GhostLock-TCL-C855-v1.0.apk"
PINNED_RESUKISU_COMMIT=68e8d3333d1fdbaf9ce8e2aec5e31abca7e3cbd9

mkdir -p "$OUT"
STAGE=$(mktemp -d "$OUT/.stage.XXXXXX")
cleanup() {
  case "$STAGE" in "$OUT"/.stage.*) rm -rf -- "$STAGE" ;; esac
}
trap cleanup EXIT HUP INT TERM
ADB_STAGE="$STAGE/$ADB_NAME"
mkdir -p "$ADB_STAGE"

if git -C "$RESUKISU_ROOT" rev-parse HEAD >/dev/null 2>&1; then
  test "$(git -C "$RESUKISU_ROOT" rev-parse HEAD)" = \
    "$PINNED_RESUKISU_COMMIT"
  test "$(git -C "$RESUKISU_ROOT" remote get-url origin)" = \
    https://github.com/Philiphall6/ReSukiSU.git
fi

copy_required() {
  test -f "$1"
  cp -f "$1" "$2"
}

copy_required "$ANDROID/ghostlock-tcl-v643-lab" \
  "$ADB_STAGE/ghostlock-tcl-v643"
copy_required "$ANDROID/tcl-v643-mcast-helper" \
  "$ADB_STAGE/tcl-v643-mcast-helper"
copy_required "$APP_BUILD/apk-payload/lib/armeabi-v7a/libtclresukisuhandoff.so" \
  "$ADB_STAGE/tcl-resukisu-handoff"
copy_required "$APP_BUILD/apk-payload/lib/armeabi-v7a/libtclresukisupreflight.so" \
  "$ADB_STAGE/tcl-resukisu-preflight"
copy_required "$RESUKISU_DIST/ksud-armv7" \
  "$ADB_STAGE/resukisu-ksud-armv7"
copy_required \
  "$RESUKISU_DIST/resukisu-tcl-v643-5.15.180-android14-11-stripped.ko" \
  "$ADB_STAGE/resukisu-tcl-v643-5.15.180-android14-11.ko"
copy_required "$ROOT/tools/run-tcl-c855-v643-adb.sh" \
  "$ADB_STAGE/run-tcl-c855-v643-adb.sh"
copy_required "$ROOT/tools/tv-readonly-preflight.sh" \
  "$ADB_STAGE/readonly-preflight.sh"
copy_required "$ROOT/docs/ADB_EDITION.md" "$ADB_STAGE/README.md"
copy_required "$ROOT/NOTICE.md" "$ADB_STAGE/NOTICE.md"
copy_required "$ROOT/THIRD_PARTY_NOTICES.md" \
  "$ADB_STAGE/THIRD_PARTY_NOTICES.md"
copy_required "$ROOT/LICENSE" "$ADB_STAGE/LICENSE"
cp -R "$ROOT/LICENSES" "$ADB_STAGE/LICENSES"

chmod 755 "$ADB_STAGE/ghostlock-tcl-v643" \
  "$ADB_STAGE/tcl-v643-mcast-helper" \
  "$ADB_STAGE/tcl-resukisu-handoff" \
  "$ADB_STAGE/tcl-resukisu-preflight" \
  "$ADB_STAGE/resukisu-ksud-armv7" \
  "$ADB_STAGE/run-tcl-c855-v643-adb.sh" \
  "$ADB_STAGE/readonly-preflight.sh"
chmod 644 "$ADB_STAGE/resukisu-tcl-v643-5.15.180-android14-11.ko"

commit=$(git -C "$ROOT" rev-parse HEAD)
cat > "$ADB_STAGE/MANIFEST.txt" <<EOF
GhostLock TCL C855 v1.0 — ADB edition
source_commit=$commit
target_firmware=V8-T653T01-LF1V643
target_kernel=5.15.180-android14-11
resukisu_repository=https://github.com/Philiphall6/ReSukiSU
resukisu_release=tcl-c855-v1.0
resukisu_commit=$PINNED_RESUKISU_COMMIT
resukisu_package=com.philiphall6.resukisu.tcl
mode=volatile
persistence=none
EOF

(cd "$ADB_STAGE" && sha256sum \
  ghostlock-tcl-v643 tcl-v643-mcast-helper \
  tcl-resukisu-handoff tcl-resukisu-preflight \
  resukisu-ksud-armv7 \
  resukisu-tcl-v643-5.15.180-android14-11.ko \
  run-tcl-c855-v643-adb.sh readonly-preflight.sh \
  README.md NOTICE.md THIRD_PARTY_NOTICES.md LICENSE MANIFEST.txt \
  LICENSES/BSD-3-Clause-adblib.txt LICENSES/GPL-2.0.txt \
  LICENSES/GPL-3.0.txt LICENSES/MIT-KernelSnitch.txt > SHA256SUMS)

tar -C "$STAGE" -cJf "$ADB_ARCHIVE" "$ADB_NAME"
copy_required "$APK_SOURCE" "$APK_RELEASE"
(cd "$OUT" && sha256sum \
  "$(basename "$ADB_ARCHIVE")" "$(basename "$APK_RELEASE")" \
  > SHA256SUMS-v1.0.txt)

printf '%s\n' "$ADB_ARCHIVE" "$APK_RELEASE" "$OUT/SHA256SUMS-v1.0.txt"
