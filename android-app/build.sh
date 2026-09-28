#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$ROOT/.." && pwd)
DEFAULT_SDK=/usr/lib/android-sdk
if [ ! -d "$DEFAULT_SDK/platforms/android-35" ]; then
  DEFAULT_SDK="$HOME/tools/android-sdk"
fi
SDK=${ANDROID_SDK_ROOT:-$DEFAULT_SDK}
PLATFORM=${ANDROID_PLATFORM:-$SDK/platforms/android-35/android.jar}
BUILD_TOOLS=${ANDROID_BUILD_TOOLS:-$SDK/build-tools/35.0.0}
if [ -z "${JAVA_HOME:-}" ]; then
  if command -v javac >/dev/null 2>&1; then
    JAVAC_BIN=$(readlink -f "$(command -v javac)")
    JAVA_HOME=$(CDPATH= cd -- "$(dirname -- "$JAVAC_BIN")/.." && pwd)
  fi
fi
if [ -z "${JAVA_HOME:-}" ]; then
  for candidate in /usr/lib/jvm/java-17-openjdk-amd64 \
      "$HOME/tools/jdk17-download/jdk-17.0.20.1+1"; do
    if [ -x "$candidate/bin/javac" ]; then
      JAVA_HOME=$candidate
      break
    fi
  done
fi
: "${JAVA_HOME:?Set JAVA_HOME to a JDK 17 installation}"
PATH="$JAVA_HOME/bin:$BUILD_TOOLS:$PATH"
export JAVA_HOME PATH
OUT="$ROOT/build"
CLASSES="$OUT/classes"
GENERATED="$OUT/generated"
COMPILED_RES="$OUT/resources.zip"
UNSIGNED="$OUT/tcl-root-verifier-unsigned.apk"
ALIGNED="$OUT/tcl-root-verifier-aligned.apk"
SIGNED="$OUT/TCL-Root-Verifier.apk"
NDK=${ANDROID_NDK_ROOT:-$HOME/.cache/oa2/android-ndk-r27d}
NDK_CC64="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang"
NDK_CC32="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi34-clang"
GHOST_ROOT=${GHOST_ROOT:-$PROJECT_ROOT}
GHOST_BIN="$GHOST_ROOT/build/android34/ghostlock-tcl-v643-lab"
MCAST_BIN="$GHOST_ROOT/build/android34/tcl-v643-mcast-helper"
PAYLOAD="$OUT/apk-payload/lib/armeabi-v7a"
ADBLIB_ROOT=${ADBLIB_ROOT:-$PROJECT_ROOT/../adblib}
RESUKISU_ROOT=${RESUKISU_ROOT:-$PROJECT_ROOT/../ReSukiSU}
RESUKISU_DIST=${RESUKISU_DIST:-$RESUKISU_ROOT/dist-tcl/v1.0/module}
RESUKISU_FORK_COMMIT=68e8d3333d1fdbaf9ce8e2aec5e31abca7e3cbd9
RESUKISU_KSUD32="$RESUKISU_DIST/ksud-armv7"
RESUKISU_KSUD64="$RESUKISU_DIST/ksud-arm64"
RESUKISU_MODULE="$RESUKISU_DIST/resukisu-tcl-v643-5.15.180-android14-11-stripped.ko"
RESUKISU_SYMBOLS="$RESUKISU_DIST/module-undefined-symbols.txt"

rm -rf "$OUT"
mkdir -p "$CLASSES" "$GENERATED"

for required in "$PLATFORM" "$BUILD_TOOLS/d8" "$NDK_CC64" "$NDK_CC32" \
                "$GHOST_BIN" "$MCAST_BIN" \
                "$RESUKISU_KSUD32" "$RESUKISU_KSUD64" \
                "$RESUKISU_MODULE" "$RESUKISU_SYMBOLS" \
                "$ROOT/broker/resukisu_kernel_preflight.c" \
                "$ROOT/broker/tcl_resukisu_handoff.c" \
                "$ROOT/broker/tcl_resukisu_broker_client.c" \
                "$ADBLIB_ROOT/src/main/java/com/tananaev/adblib/AdbConnection.java"; do
  if [ ! -f "$required" ]; then
    printf 'Missing dependency: %s\n' "$required" >&2
    exit 2
  fi
done

if git -C "$RESUKISU_ROOT" rev-parse HEAD >/dev/null 2>&1; then
  RESUKISU_COMMIT=$(git -C "$RESUKISU_ROOT" rev-parse HEAD)
  RESUKISU_ORIGIN=$(git -C "$RESUKISU_ROOT" remote get-url origin 2>/dev/null || true)
  if [ "$RESUKISU_COMMIT" != "$RESUKISU_FORK_COMMIT" ] ||
     [ "$RESUKISU_ORIGIN" != "https://github.com/Philiphall6/ReSukiSU.git" ]; then
    printf '%s\n' \
      'Refusing a non-pinned ReSukiSU tree.' \
      "Required origin: https://github.com/Philiphall6/ReSukiSU.git" \
      "Required commit: $RESUKISU_FORK_COMMIT" \
      "Found origin:    $RESUKISU_ORIGIN" \
      "Found commit:    $RESUKISU_COMMIT" >&2
    exit 2
  fi
fi

aapt2 compile --dir "$ROOT/res" -o "$COMPILED_RES"
aapt2 link -o "$UNSIGNED" -I "$PLATFORM" --auto-add-overlay \
  -R "$COMPILED_RES" \
  --java "$GENERATED" \
  --manifest "$ROOT/AndroidManifest.xml" \
  --min-sdk-version 23 --target-sdk-version 35 \
  --version-code 110 --version-name 1.1.0-pre3

javac -encoding UTF-8 -source 8 -target 8 \
  -classpath "$PLATFORM" -d "$CLASSES" \
  "$ADBLIB_ROOT"/src/main/java/com/tananaev/adblib/*.java \
  "$GENERATED/lab/tcl/rootverifier/R.java" \
  "$ROOT"/src/lab/tcl/rootverifier/*.java

jar cf "$OUT/classes.jar" -C "$CLASSES" .
"$BUILD_TOOLS/d8" --lib "$PLATFORM" --min-api 23 \
  --output "$OUT" "$OUT/classes.jar"

jar uf "$UNSIGNED" -C "$OUT" classes.dex

"$NDK_CC32" -O2 -Wall -Wextra -Werror -static \
  "$ROOT/broker/tcl_root_broker.c" -o "$OUT/tcl-root-broker"
"$NDK_CC32" -O2 -Wall -Wextra -Werror -static \
  "$ROOT/broker/tcl_resukisu_broker_client.c" \
  -o "$OUT/tcl-resukisu-broker-client"
mkdir -p "$PAYLOAD"
cp "$GHOST_BIN" "$PAYLOAD/libtclghostlock.so"
cp "$MCAST_BIN" "$PAYLOAD/libtclmcast.so"
cp "$OUT/tcl-root-broker" "$PAYLOAD/libtclrootbroker.so"
cp "$OUT/tcl-resukisu-broker-client" \
  "$PAYLOAD/libtclresukisuclient.so"
cp "$RESUKISU_KSUD32" "$PAYLOAD/libresukisuksud.so"
cp "$RESUKISU_KSUD64" "$PAYLOAD/libresukisuksud64.so"
cp "$RESUKISU_MODULE" "$PAYLOAD/libtclresukisumodule.so"
"$NDK_CC32" -O2 -Wall -Wextra -Werror -static \
  "$ROOT/broker/app_syscall_preflight.c" -o "$PAYLOAD/libtclpreflight.so"
"$NDK_CC64" -O2 -Wall -Wextra -Werror -static \
  "$ROOT/broker/app_syscall_preflight.c" -o "$PAYLOAD/libtclpreflight64.so"
{
  printf '%s\n' '#ifndef RESUKISU_REQUIRED_SYMBOLS_H' \
    '#define RESUKISU_REQUIRED_SYMBOLS_H' \
    'static const char *const resukisu_required_symbols[] = {'
  awk '{printf "  \"%s\",\n", $1}' "$RESUKISU_SYMBOLS"
  printf '%s\n' '};' \
    '#define RESUKISU_REQUIRED_SYMBOL_COUNT (sizeof(resukisu_required_symbols) / sizeof(resukisu_required_symbols[0]))' \
    '#endif'
} > "$OUT/resukisu_required_symbols.h"
"$NDK_CC32" -O2 -Wall -Wextra -Werror -static -I"$OUT" \
  "$ROOT/broker/resukisu_kernel_preflight.c" \
  -o "$PAYLOAD/libtclresukisupreflight.so"
# The shared V6xx source uses neutral helper names.  Keep the released V643
# symbol names for a byte-identical, hardware-validated handoff payload.
"$NDK_CC32" -O2 -Wall -Wextra -Werror -static \
  -Dverify_tcl_policy_header=verify_v643_policy_header \
  -Dverify_tcl_policycaps=verify_v643_policycaps \
  "$ROOT/broker/tcl_resukisu_handoff.c" \
  -o "$PAYLOAD/libtclresukisuhandoff.so"
EXPECTED_V643_HANDOFF_SHA256=e519266c0a9774b63e48c8df7c813284073c320314121952bae18ecbfd5fd299
ACTUAL_V643_HANDOFF_SHA256=$(sha256sum \
  "$PAYLOAD/libtclresukisuhandoff.so" | awk '{print $1}')
if [ "$ACTUAL_V643_HANDOFF_SHA256" != "$EXPECTED_V643_HANDOFF_SHA256" ]; then
  printf 'Refusing unpinned V643 handoff: expected %s, found %s\n' \
    "$EXPECTED_V643_HANDOFF_SHA256" "$ACTUAL_V643_HANDOFF_SHA256" >&2
  exit 2
fi
chmod 755 "$PAYLOAD"/*.so
jar uf "$UNSIGNED" -C "$OUT/apk-payload" lib
zipalign -f 4 "$UNSIGNED" "$ALIGNED"

if [ -n "${APK_KEYSTORE:-}" ]; then
  KEYSTORE=$APK_KEYSTORE
  KEY_ALIAS=${APK_KEY_ALIAS:-ghostlock-tcl}
  : "${APK_KEYSTORE_PASSWORD:?Set APK_KEYSTORE_PASSWORD for the supplied keystore}"
  APK_KEY_PASSWORD=${APK_KEY_PASSWORD:-$APK_KEYSTORE_PASSWORD}
else
  KEYSTORE="$ROOT/local-signing.jks"
  KEY_ALIAS=ghostlock-tcl-local
  APK_KEYSTORE_PASSWORD=local-development-only
  APK_KEY_PASSWORD=$APK_KEYSTORE_PASSWORD
  if [ ! -f "$KEYSTORE" ]; then
    keytool -genkeypair -noprompt -keystore "$KEYSTORE" \
      -storepass "$APK_KEYSTORE_PASSWORD" -keypass "$APK_KEY_PASSWORD" \
      -alias "$KEY_ALIAS" -keyalg RSA -keysize 3072 -validity 3650 \
      -dname "CN=GhostLock TCL Local Build, O=Security Research"
  fi
fi
export APK_KEYSTORE_PASSWORD APK_KEY_PASSWORD

"$BUILD_TOOLS/apksigner" sign --ks "$KEYSTORE" \
  --ks-key-alias "$KEY_ALIAS" --ks-pass env:APK_KEYSTORE_PASSWORD \
  --key-pass env:APK_KEY_PASSWORD --out "$SIGNED" "$ALIGNED"
"$BUILD_TOOLS/apksigner" verify --verbose --print-certs "$SIGNED"

sha256sum "$SIGNED" "$OUT/tcl-root-broker" \
  "$OUT/tcl-resukisu-broker-client" \
  "$GHOST_BIN" "$MCAST_BIN" "$RESUKISU_KSUD32" "$RESUKISU_KSUD64" \
  "$RESUKISU_MODULE" "$PAYLOAD/libtclresukisupreflight.so" \
  "$PAYLOAD/libtclresukisuhandoff.so"
