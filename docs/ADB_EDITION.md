# ADB edition — TCL C855 V643

The ADB edition runs the same hardware-validated direct handoff as the APK,
from a Linux host already authorized by the TV owner. It is restricted to the
exact T653T01 V643 Android 14 profile and uses the exact module from
[Philiphall6/ReSukiSU](https://github.com/Philiphall6/ReSukiSU), release
[`tcl-c855-v1.0`](https://github.com/Philiphall6/ReSukiSU/releases/tag/tcl-c855-v1.0).

## Requirements

- TCL C855/T653T01 on `V8-T653T01-LF1V643`;
- kernel `5.15.180-android14-11`;
- AVB `green`, VBMeta `locked`, SELinux enforcing;
- a fresh boot, with no KernelSU-family module already loaded;
- the TCL ReSukiSU manager package `com.philiphall6.resukisu.tcl` installed;
- an owner-authorized ADB key on the Linux host.

The script refuses a mismatched firmware, kernel, policy hash, policy
capabilities, manager package, embedded artifact hash, or a second attempt in
the same boot.

## Run

Extract the release archive, enter its directory, and explicitly select the
authorized TV:

```sh
export ADB_TARGET=192.0.2.10:5555
./run-tcl-c855-v643-adb.sh
```

Replace the documentation address above with the TV address. ADB uses the
host's already configured, owner-authorized identity. No address or ADB
private key is bundled in the release.

The script records local logs, verifies every pushed file, and performs one
volatile attempt. It never flashes, unlocks, patches boot/VBMeta, writes a
partition, or automatically reboots the TV. A full manual reboot removes the
temporary root module.

## APK edition

The APK wraps the same checks and direct handoff in an Android TV interface.
Its main controls follow the TV language (French and English are included),
while low-level diagnostic markers remain English for reproducibility.
