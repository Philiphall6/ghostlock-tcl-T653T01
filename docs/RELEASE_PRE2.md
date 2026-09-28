# GhostLock TCL T653T01 v1.1.0-pre2

> [!CAUTION]
> V637, V655, V665 and V667 support in this release is **not validated on
> matching real hardware**. A test may panic or reboot the TV, interrupt
> network/ADB, or require a physical power cycle.

This pre-release contains separate, manual ADB bundles:

- V637: Android 14, kernel `5.15.180-android14-11`;
- V655/V665/V667: Android 14, kernel `5.15.192-android14-11`.

Each binary accepts only its exact firmware family and kernel. Each runner
also requires AVB `green/locked`, enforcing verity and SELinux, the pinned
SELinux policy identity, a fresh boot, no loaded root module, an installed
`com.philiphall6.resukisu.tcl` manager, an unused one-attempt gate and an
explicit typed risk acknowledgement.

The V637 profile has substantially stronger offline evidence than V65x: its
BTF, embedded configuration, critical offsets, compat-select route, SELinux
policy and ReSukiSU symbol CRCs match V643. Its exact physical text address is
also proved from all packaged DTBO maps, vendor boot headers and mboot. This
still does not constitute a V637 hardware test.

No APK or boot-time auto-root is provided for these untested profiles. The
ordinary build remains fail-closed and both manifests remain
`analysis_only`. The bundles do not flash, unlock, patch boot/VBMeta, or write
partitions. Root, if an experiment succeeds, is volatile and ends at reboot.

The required manager is the
[Philiphall6/ReSukiSU](https://github.com/Philiphall6/ReSukiSU) fork.
