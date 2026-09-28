# GhostLock TCL T653T01 v1.1.0-pre4

> [!CAUTION]
> V637, V655, V665 and V667 have not been root-tested on matching real
> hardware. They can panic or reboot the TV, interrupt networking/ADB, or
> require a physical power cycle. V643 is the only hardware-validated profile.

This pre-release adds exact-profile APK support for:

- V637 and V643 on Android 14 / `5.15.180-android14-11`;
- V655, V665 and V667 on Android 14 / `5.15.192-android14-11`.

The APK contains separate build-pinned GhostLock binaries, ReSukiSU
preflights, handoff helpers and kernel modules for the two kernel families.
Selection requires an exact firmware, kernel, AVB, verity, SELinux policy and
policy-capability match. There is no generic V6xx fallback.

Experimental manual root requires an on-screen risk confirmation. Automatic
root is initially grey and can only be enabled after that exact profile has
completed a successful manual root session and granted the app UID 0 through
ReSukiSU. It remains one-shot per boot; an incomplete attempt disables the
automation on the next boot.

Install the companion `ReSukiSU-TCL-T653T01-v1.1.0-pre4.apk`. It recognizes
the same five exact firmware/kernel pairs as volatile-only targets, including
the dedicated 5.15.192 module. Persistent installation and boot-image flashing
remain disabled for these TCL profiles.

No boot image, VBMeta, firmware, bootloader state or partition is modified.
Root remains volatile and disappears after reboot.
