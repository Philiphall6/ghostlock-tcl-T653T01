# GhostLock TCL C855 v1.0

This is the first hardware-validated TCL C855/T653T01 V643 release.

## Included editions

- `GhostLock-TCL-C855-v1.0-ADB.tar.xz`: Linux/ADB runner, GhostLock TCL
  binary, exact helper, direct handoff, preflight, and the pinned TCL ReSukiSU
  module/loader.
- `GhostLock-TCL-C855-v1.0.apk`: Android TV interface with automatic French
  or English controls based on the TV locale.
- `SHA256SUMS-v1.0.txt`: release-asset hashes.

## Required companion

Install the unchanged manager from
[Philiphall6/ReSukiSU `tcl-c855-v1.0`](https://github.com/Philiphall6/ReSukiSU/releases/tag/tcl-c855-v1.0).
The required package is `com.philiphall6.resukisu.tcl`. Generic upstream
ReSukiSU builds are not interchangeable with this exact TCL module.

## Validated target and outcome

- firmware: `V8-T653T01-LF1V643`;
- Android: 14;
- kernel: `5.15.180-android14-11`;
- platform: T653T01;
- root handoff: temporary UID 0 to the pinned ReSukiSU TCL module;
- post-state: SELinux enforcing, policy capabilities restored, Ethernet/DNS/
  ADB retained, AVB green, VBMeta locked;
- persistence: none; a reboot removes root.

The release does not flash, unlock the bootloader, patch boot/VBMeta, modify
firmware, or write a partition. It permits one attempt per boot and fails
closed if the exact target profile or hashes do not match.

## Validation

- all 18 TCL host-model tests pass;
- ReSukiSU handoff and policy/network restoration test passes;
- Android APK v1/v2/v3 signature verification passes;
- exact ARMv7 loader and TCL module hashes are pinned;
- the full direct-handoff chain was validated on the owned TCL C855 hardware.

See `README.md`, `NOTICE.md`, `docs/ADB_EDITION.md`, and
`android-app/README.md` for details and acknowledgements.
