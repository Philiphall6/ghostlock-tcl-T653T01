# GhostLock TCL T653T01 v1.1.0-pre3

> [!CAUTION]
> The manual V643 chain is hardware-validated, but this new boot-triggered
> orchestration has not yet completed a full real-TV reboot test. Keep this as
> a pre-release until that test succeeds.

This build adds an opt-in automatic **temporary** root session for the exact
T653T01 V643 profile. The TV button is visible but grey until this application
has a real UID 0 `su` grant and confirms the exact firmware, kernel, AVB,
SELinux policy, loaded ReSukiSU driver and local-ADB route.

The boot worker is restricted to `V8-T653T01-LF1V643`, Android 14 and
`5.15.180-android14-11`. V637 and V655/V665/V667 remain blocked in the APK.
It permits one attempt per boot and uses a pending-boot latch: an interrupted
attempt disables automation at the following boot before another exploit can
run. It does not automatically reboot the TV.

No boot image, VBMeta, firmware, bootloader state or partition is modified.
Root still disappears on reboot; only the user's opt-in setting persists.

Asset:

- `GhostLock-TCL-T653T01-V643-v1.1.0-pre3.apk`
- SHA-256: `25d73e06ef463dda7f6e3adf9442cbe2edac4a6238527f9cc371b4f65481db8e`
- Package/version: `lab.tcl.rootverifier` / `110` (`1.1.0-pre3`)
- Signing certificate SHA-256:
  `1f2aa7ce9224d49bc993c0d83fe8db42570c92ee71942b9605896c3286a7d876`

The signing certificate matches the public v1.0 APK, so Android can install it
as an update without removing the existing app or its authorized local-ADB
key.
