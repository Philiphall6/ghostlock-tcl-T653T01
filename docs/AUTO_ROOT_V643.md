# V643 opt-in automatic temporary root

This feature does not make root persistent. It stores only an opt-in setting
and, after a later completed Android boot, runs the same volatile V643
GhostLock-to-ReSukiSU chain in a foreground service.

## TV control states

| State | Label/behaviour |
|---|---|
| No validated root grant | Grey, `ROOT REQUIRED`, not selectable |
| App has UID 0 through `su` and exact V643 checks pass | Selectable, `OFF` |
| User has enabled automation | Selectable, `ON`; pressing it disables it |

Keeping the `ON` state selectable is deliberate: the user can always disarm
the next boot even if the current volatile root session has ended.

## Boot gates

The worker requires the exact `V8-T653T01-LF1V643` firmware, Android 14,
`5.15.180-android14-11`, green/locked AVB, enforcing verity/SELinux, the pinned
V643 SELinux policy, exact embedded payload hashes, the TCL ReSukiSU manager,
working app-local ADB and an unused one-attempt-per-boot gate.

V637 and V655/V665/V667 remain blocked. A version prefix such as `V6xx` is
never sufficient.

## Anti-loop behaviour

Immediately before the kernel attempt, the service durably records the current
boot identifier. Success clears that pending marker. If the device instead
reboots or the attempt does not report success, the different boot identifier
on the following startup disables automation before another attempt can run.
There is no automatic recovery reboot.

No firmware, partition, boot image, VBMeta image or bootloader state is
modified.
