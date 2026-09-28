# GhostLock TCL T653T01 V65x v1.1.0-pre1

> [!CAUTION]
> **UNTESTED ON REAL V655, V665 OR V667 HARDWARE.** This pre-release can
> trigger a kernel panic, an immediate reboot, loss of network/ADB, or a state
> requiring a physical power cycle. It is not the stable V643 release.

This is an **ADB-only, manual, experimental pre-release** for the exact
following TCL T653T01 builds:

- `V8-T653T01-LF1V655`;
- `V8-T653T01-LF1V665`;
- `V8-T653T01-LF1V667`;
- Android 14 and kernel `5.15.192-android14-11` only.

There is no V65x APK and no boot-time auto-root in this pre-release. The
ordinary `ghostlock` build remains fail-closed; only the explicitly named
`ghostlock-tcl-v65x-experimental` binary can promote the V65x profile, and it
requires the exact live firmware/kernel checks plus the acknowledgement:

```text
I_ACCEPT_V65X_KERNEL_PANIC_RISK
```

## What is included

- the explicit V65x experimental GhostLock binary;
- the ARM32 `_newselect` helper;
- V65x-specific ReSukiSU preflight and handoff binaries;
- the exact-vermagic ReSukiSU module candidate;
- the pinned ARMv7 `ksud` loader;
- a guarded Linux/ADB runner and checksums.

The TCL-specific ReSukiSU manager package
`com.philiphall6.resukisu.tcl` must already be installed. Use the manager from
the [Philiphall6/ReSukiSU](https://github.com/Philiphall6/ReSukiSU) fork.

## Guardrails

The runner refuses to start unless it observes all of the following:

- an exact listed firmware and the exact `5.15.192-android14-11` kernel;
- Android 14, completed boot, AVB green/locked and enforcing verity;
- SELinux enforcing with the expected policy capabilities;
- the exact firmware-specific SELinux policy hash and size;
- no already loaded root module;
- a fresh boot and an unused one-attempt-per-boot gate;
- an installed TCL ReSukiSU manager and an explicit typed risk acknowledgement.

If an attempt starts but cannot be validated while ADB remains reachable on
the same boot, the runner requests one reboot. If the TV has already rebooted,
it does not request a second one. It never flashes firmware, unlocks the
bootloader, patches boot/VBMeta or writes a partition.

## Why this remains a pre-release

Offline analysis confirms the vulnerable condition, exact BTF/KMI data,
critical offsets, physical kernel load address, allocator geometry, matching
ReSukiSU symbol CRCs and a passing source-built QEMU surrogate. It does **not**
prove the live stock V65x PCP/reclaim choreography, vendor concurrency, module
late-load or SELinux/network restoration. A successful V643 test cannot be
treated as V65x hardware validation.

Use only on hardware you own and can recover, with one attempt per full boot.
