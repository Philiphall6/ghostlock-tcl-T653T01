#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
NDK=${ANDROID_NDK_ROOT:-$HOME/.cache/oa2/android-ndk-r27d}
CC32="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi34-clang"
RESUKISU_ROOT=${RESUKISU_ROOT:-$ROOT/../ReSukiSU}
V65X_DIST=${V65X_DIST:-$RESUKISU_ROOT/dist-tcl/v65x-analysis/module}
V643_DIST=${V643_DIST:-$RESUKISU_ROOT/dist-tcl/v1.0/module}
VERSION=v1.1.0-pre1
NAME=GhostLock-TCL-T653T01-V65x-$VERSION-ADB
OUT=${RELEASE_OUT:-$ROOT/build/release-v65x-pre1}
ARCHIVE="$OUT/$NAME.tar.xz"
OUT_SUMS="$OUT/SHA256SUMS-$VERSION.txt"

MODULE_SOURCE_COMMIT=68e8d3333d1fdbaf9ce8e2aec5e31abca7e3cbd9
MODULE_SHA=48c64c0d8b85e62dd5db1125b32ea12cff91590d58138ad4a742ae19583b5db9
KSUD_SHA=528c80259613a1e27a90d8f202fda33ecceba9c1fd42e1d807fdbbc859af5e68
MODULE_SOURCE="$V65X_DIST/resukisu-tcl-v65x-5.15.192-android14-11-stripped.ko"
SYMBOLS_SOURCE="$V65X_DIST/module-undefined-symbols.txt"
KSUD_SOURCE="$V643_DIST/ksud-armv7"

for required in "$CC32" "$MODULE_SOURCE" "$SYMBOLS_SOURCE" \
                "$KSUD_SOURCE" "$V65X_DIST/BUILD-IDENTITY.txt" \
                "$V65X_DIST/STATIC_VALIDATION_V65X.md"; do
  test -f "$required" || {
    printf 'Missing required input: %s\n' "$required" >&2
    exit 2
  }
done

test "$(sha256sum "$MODULE_SOURCE" | awk '{print $1}')" = "$MODULE_SHA"
test "$(sha256sum "$KSUD_SOURCE" | awk '{print $1}')" = "$KSUD_SHA"
grep -Fqx "source_commit=$MODULE_SOURCE_COMMIT" \
  "$V65X_DIST/BUILD-IDENTITY.txt"
grep -Fqx 'target_kernel_release=5.15.192-android14-11' \
  "$V65X_DIST/BUILD-IDENTITY.txt"
grep -Fqx 'manager_package=com.philiphall6.resukisu.tcl' \
  "$V65X_DIST/BUILD-IDENTITY.txt"

make -C "$ROOT" API=34 NDK_ROOT="$NDK" \
  ghostlock-tcl-v65x-experimental tcl-v643-mcast-helper

mkdir -p "$OUT"
STAGE=$(mktemp -d "$OUT/.stage.XXXXXX")
cleanup() {
  case "$STAGE" in "$OUT"/.stage.*) rm -rf -- "$STAGE" ;; esac
}
trap cleanup EXIT HUP INT TERM
BUNDLE="$STAGE/$NAME"
NATIVE="$STAGE/native"
mkdir -p "$BUNDLE" "$NATIVE"

{
  printf '%s\n' '#ifndef RESUKISU_REQUIRED_SYMBOLS_H' \
    '#define RESUKISU_REQUIRED_SYMBOLS_H' \
    'static const char *const resukisu_required_symbols[] = {'
  awk '{printf "  \"%s\",\n", $1}' "$SYMBOLS_SOURCE"
  printf '%s\n' '};' \
    '#define RESUKISU_REQUIRED_SYMBOL_COUNT (sizeof(resukisu_required_symbols) / sizeof(resukisu_required_symbols[0]))' \
    '#endif'
} > "$NATIVE/resukisu_required_symbols.h"

"$CC32" -O2 -Wall -Wextra -Werror -static -I"$NATIVE" \
  -DEXPECTED_RELEASE='"5.15.192-android14-11"' \
  "$ROOT/android-app/broker/resukisu_kernel_preflight.c" \
  -o "$NATIVE/tcl-resukisu-preflight-v65x"
"$CC32" -O2 -Wall -Wextra -Werror -static \
  -DEXPECTED_RELEASE='"5.15.192-android14-11"' \
  -DEXPECTED_SELINUX_POLICY_SIZE=1044927U \
  -DEXPECTED_SELINUX_POLICY_SIZE_ALT=1045234U \
  -DTCL_LAB_PREFIX='"/data/local/tmp/tcl-v65x-resukisu-lab/"' \
  "$ROOT/android-app/broker/tcl_resukisu_handoff.c" \
  -o "$NATIVE/tcl-resukisu-handoff-v65x"

install -m 0755 "$ROOT/ghostlock-tcl-v65x-experimental" \
  "$BUNDLE/ghostlock-tcl-v65x-experimental"
install -m 0755 "$ROOT/tcl-v643-mcast-helper" \
  "$BUNDLE/tcl-newselect-arm32-helper"
install -m 0755 "$NATIVE/tcl-resukisu-preflight-v65x" \
  "$BUNDLE/tcl-resukisu-preflight-v65x"
install -m 0755 "$NATIVE/tcl-resukisu-handoff-v65x" \
  "$BUNDLE/tcl-resukisu-handoff-v65x"
install -m 0755 "$KSUD_SOURCE" "$BUNDLE/resukisu-ksud-armv7"
install -m 0644 "$MODULE_SOURCE" \
  "$BUNDLE/resukisu-tcl-v65x-5.15.192-android14-11.ko"
install -m 0755 "$ROOT/tools/run-tcl-t653t01-v65x-experimental-adb.sh" \
  "$BUNDLE/run-tcl-t653t01-v65x-experimental-adb.sh"
install -m 0644 "$ROOT/docs/RELEASE_V65X_PRE1.md" "$BUNDLE/README.md"
install -m 0644 "$V65X_DIST/BUILD-IDENTITY.txt" \
  "$BUNDLE/RESUKISU-BUILD-IDENTITY.txt"
install -m 0644 "$V65X_DIST/STATIC_VALIDATION_V65X.md" \
  "$BUNDLE/RESUKISU-STATIC-VALIDATION.md"
install -m 0644 "$V65X_DIST/ANALYSIS_ONLY.txt" \
  "$BUNDLE/RESUKISU-UPSTREAM-CANDIDATE-WARNING.txt"
install -m 0644 "$ROOT/NOTICE.md" "$BUNDLE/NOTICE.md"
install -m 0644 "$ROOT/THIRD_PARTY_NOTICES.md" \
  "$BUNDLE/THIRD_PARTY_NOTICES.md"
install -m 0644 "$ROOT/LICENSE" "$BUNDLE/LICENSE"
cp -R "$ROOT/LICENSES" "$BUNDLE/LICENSES"

commit=$(git -C "$ROOT" rev-parse HEAD)
cat > "$BUNDLE/MANIFEST.txt" <<EOF
GhostLock TCL T653T01 V65x $VERSION — experimental ADB pre-release
source_commit=$commit
target_firmwares=V8-T653T01-LF1V655,V8-T653T01-LF1V665,V8-T653T01-LF1V667
target_kernel=5.15.192-android14-11
target_android=14
hardware_validated=false
manual_only=true
auto_root=false
one_attempt_per_boot=true
kernel_panic_risk=true
runtime_ack=I_ACCEPT_V65X_KERNEL_PANIC_RISK
ordinary_profile_status=analysis_only
experimental_promotion=explicit-binary-plus-runtime-ack
resukisu_repository=https://github.com/Philiphall6/ReSukiSU
resukisu_source_commit=$MODULE_SOURCE_COMMIT
resukisu_package=com.philiphall6.resukisu.tcl
resukisu_module_sha256=$MODULE_SHA
mode=volatile
persistence=none
forbidden=flash,fastboot,OEM-unlock,boot-or-vbmeta-patch,partition-write
EOF

(cd "$BUNDLE" && file \
  ghostlock-tcl-v65x-experimental \
  tcl-newselect-arm32-helper \
  tcl-resukisu-preflight-v65x \
  tcl-resukisu-handoff-v65x \
  resukisu-ksud-armv7 \
  resukisu-tcl-v65x-5.15.192-android14-11.ko > FILE.txt)

(cd "$BUNDLE" && sha256sum \
  ghostlock-tcl-v65x-experimental \
  tcl-newselect-arm32-helper \
  tcl-resukisu-preflight-v65x \
  tcl-resukisu-handoff-v65x \
  resukisu-ksud-armv7 \
  resukisu-tcl-v65x-5.15.192-android14-11.ko \
  run-tcl-t653t01-v65x-experimental-adb.sh \
  README.md RESUKISU-BUILD-IDENTITY.txt \
  RESUKISU-STATIC-VALIDATION.md \
  RESUKISU-UPSTREAM-CANDIDATE-WARNING.txt \
  NOTICE.md THIRD_PARTY_NOTICES.md LICENSE MANIFEST.txt FILE.txt \
  LICENSES/BSD-3-Clause-adblib.txt LICENSES/GPL-2.0.txt \
  LICENSES/GPL-3.0.txt LICENSES/MIT-KernelSnitch.txt > SHA256SUMS)

tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
  -C "$STAGE" -cJf "$ARCHIVE" "$NAME"
(cd "$OUT" && sha256sum "$(basename "$ARCHIVE")" > "$(basename "$OUT_SUMS")")

printf '%s\n' "$ARCHIVE" "$OUT_SUMS"
