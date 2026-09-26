# TCL V643 Sabrina mode-7 live proof — 2026-09-21

## Result

The Sabrina-style volatile chain succeeded once on the TCL C855 / T653T01
V643 Android 14 television. No firmware, partition, bootloader or vbmeta image
was changed.

The TCL adaptation uses two independently witnessed reclaims:

1. a clean eight-byte zero at `selinux_state` (`ffffffc00a940460`);
2. a credential write to the current task, followed by the normal TCL
   credential synchronization path.

The run reached all of the following markers:

```text
TCL capture witness: method=perf-regs ... block=6 pfn_reference=-1 verdict=1
TCL split: erase=1 handler=1 cleanup=1 status=0 failures=0
sid: selinux OFF - no SID resolution needed
=== ROOT: uid=0 hits=1/1 ===
file_create=OK
kallsyms: OPEN OK, scanning...
```

`GHOST_EXEC=0` prevented a root shell from being started. `GHOST_REBOOT=1`
rebooted the television immediately after the bounded proof so all volatile
credential and SELinux changes were discarded.

## Security state

Before:

```text
boot_id=b4116978-5495-470b-9aa4-984fadb5a9bc
verifiedboot=green
vbmeta=locked
verity=enforcing
selinux=1
```

After the automatic reboot:

```text
boot_id=1ca2a49f-137a-4269-8736-3631992bf8ce
verifiedboot=green
vbmeta=locked
verity=enforcing
selinux=1
```

## Artifacts

- Launcher: `tools/run-tv-sabrina-mode7-proof.sh`
- Full log: `10_LOGS/tcl-v643-sabrina-mode7-proof-20260921.log`
- AArch64 binary SHA-256:
  `1b4ffd58d5ba6805d9dc53efc772dc6e94062973b1a009735b12d4cdbfb9fd79`
- AArch32 helper SHA-256:
  `6321dfa9fb8d18cf085d98c957e4f13b11cc760854350ba87b944162ea781f36`

## Scope

This proves a temporary runtime root and temporary global SELinux disable on
the tested V643 boot. It does not establish persistence, compatibility with a
different firmware build, or the absence of application-level integrity
detection during a longer rooted session.

## No-reboot confirmation

A second bounded run used `REBOOT_AFTER=0`. It again reached `uid=0`, created
a root-owned test file and opened `kallsyms`. The root process then exited
because `GHOST_EXEC=0`, while the global in-memory SELinux state intentionally
remained disabled:

```text
boot_id before=1ca2a49f-137a-4269-8736-3631992bf8ce
boot_id after =1ca2a49f-137a-4269-8736-3631992bf8ce
verifiedboot=green
vbmeta=locked
verity=enforcing
selinux=0
```

Full log: `10_LOGS/tcl-v643-sabrina-mode7-no-reboot-20260921.log`.
SELinux will return to enforcing at the next television reboot.
