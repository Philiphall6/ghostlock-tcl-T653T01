# GhostLock TCL T653T01 Android TV app

This directory contains the source for the TCL T653T01 APK edition. The app performs
the same exact-target checks as the ADB edition, starts GhostLock through an
owner-authorized local ADB connection, and hands the temporary UID-0 process
directly to the TCL ReSukiSU loader. Root is volatile and disappears after a
reboot.

## Exact profiles and optional automatic session

The sixth TV button is always visible. It is grey and cannot be selected while
the option is off and this app has no validated root grant. It becomes
selectable only after all of the following are observed in the current
session:

- this app's real `su -c id` result is UID 0;
- the volatile ReSukiSU driver answers;
- firmware, kernel and vendor SELinux policy match one exact profile;
- AVB is green/locked, verity and SELinux are enforcing;
- the V643 SELinux policy and loaded module match;
- the app's dedicated local-ADB key still works.

V643 is hardware validated. V637 and V655/V665/V667 are explicitly marked
experimental and display a kernel-panic/power-cycle warning before both manual
and automatic opt-in. They use separate binaries, modules, hashes and exact
firmware/kernel/policy checks.

After confirmation, Android's `BOOT_COMPLETED` broadcast starts a visible
foreground service. The worker repeats the authorized exact-profile checks and
permits one attempt per boot. If an attempt is interrupted before it reports
success, a persistent latch disables automation at the following boot. The
worker does not automatically reboot the TV.

An already enabled option remains selectable even without root, so it can
always be turned off. The root itself is still volatile and disappears on
reboot; only the user's opt-in preference persists.

## Required ReSukiSU fork

This app intentionally supports only
[Philiphall6/ReSukiSU](https://github.com/Philiphall6/ReSukiSU), release
[`tcl-c855-v1.0`](https://github.com/Philiphall6/ReSukiSU/releases/tag/tcl-c855-v1.0),
module baseline commit `68e8d3333d1fdbaf9ce8e2aec5e31abca7e3cbd9`, and manager package
`com.philiphall6.resukisu.tcl`.

The upstream generic ReSukiSU manager is not a substitute. The build script
rejects a Git checkout outside the TCL fork/module ancestry, and
the app pins the SHA-256 hashes of its ARMv7 `ksud`, ARM64 helper, and exact
TCL V643 kernel module.

## Source layout

- `src/`: Android TV activity and safety gates;
- `broker/`: direct UID-0 handoff, policy/network restoration, and exact-module
  preflight;
- `tests/`: host-only handoff and restoration tests;
- `build.sh`: reproducible command-line build without Gradle.

The ADB client is built from
[`tananaev/adblib`](https://github.com/tananaev/adblib) as an external source
dependency; it is not vendored here.

## Build

Place the repositories next to each other:

```text
workspace/
├── ghostlock-tcl-c855/    # historical repository slug
├── ReSukiSU/             # Philiphall6 fork at the pinned commit
└── adblib/
```

Then build the GhostLock TCL binaries first and the APK:

```sh
cd ghostlock-tcl-c855
tools/build-android14.sh
ANDROID_SDK_ROOT=/path/to/android-sdk \
ANDROID_NDK_ROOT=/path/to/android-ndk-r27d \
JAVA_HOME=/path/to/jdk-17 \
./android-app/build.sh
```

Without signing variables, the script creates an ignored local-development
keystore. For a release build, provide `APK_KEYSTORE`, `APK_KEY_ALIAS`,
`APK_KEYSTORE_PASSWORD`, and optionally `APK_KEY_PASSWORD`. Never commit a
keystore or its password.

The resulting APK is `android-app/build/TCL-Root-Verifier.apk`.

## Safety scope

Every profile is restricted to an exact TCL T653T01 firmware, Android 14,
kernel, pinned SELinux policy, AVB green/locked, and a fresh boot with no root
module already loaded. It permits one attempt per boot.
It does not flash, unlock the bootloader, patch `boot.img` or VBMeta, or write
to a partition.

Run the static automation guard test with:

```sh
./android-app/tests/test_auto_root_safety.sh
```
