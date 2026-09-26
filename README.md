# GhostLock TCL C855 / Sabrina

> **TCL C855 V643 release v1.0:** the ARM32 `_newselect` carrier is now
> validated on a real T653T01 television running Android 14 and
> `5.15.180-android14-11`. One supervised, single-attempt boot completed the
> GhostLock UID-0 handoff, loaded the separate ReSukiSU module, restored
> SELinux to enforcing, and kept Ethernet, DNS and ADB operational. Verified
> Boot remained green and VBMeta locked. The resulting root is volatile and
> disappears at reboot; no flash, fastboot or OEM unlock is involved.
>
> Before the hardware validation, the ARM32 `_newselect` carrier passed the
> instrumented-kernel, exact uninstrumented-kernel and genuine `mm_struct`
> reclaim campaigns on 10/10 independent QEMU boots each. The integrated
> two-cycle root-to-app gate also completes with clean teardown. This replaces
> the rejected MCAST route, which faulted once in ten exact-kernel runs. The
> complete root-to-app gate also passes when the PFN-free semantic `perf`
> witness is forced; it selects the same unique block as the independent QEMU
> PFN observer. The normal binary remains `analysis_only=1`; the armed build
> is laboratory-only and guarded by an exact V643 profile.

## Required TCL companion

The APK edition requires **the project's TCL-specific ReSukiSU fork**:

- repository: [Philiphall6/ReSukiSU](https://github.com/Philiphall6/ReSukiSU)
- required release: [ReSukiSU TCL C855 v1.0](https://github.com/Philiphall6/ReSukiSU/releases/tag/tcl-c855-v1.0)
- required manager package: `com.philiphall6.resukisu.tcl`

The generic upstream ReSukiSU manager is credited as the parent project, but
it is not a drop-in replacement for the exact TCL V643 module and handoff used
by this release. Do not load a generic module on the television.

## v1.0 editions

- **ADB edition:** command-line GhostLock binary, TCL helper, read-only
  preflight, checksums, and exact-target documentation. It requires an ADB
  connection already authorized by the device owner.
- **APK edition:** English Android TV interface with an embedded local-ADB
  client. Local ADB only starts GhostLock under the Android `shell` domain;
  the UID-0 process performs the ReSukiSU handoff directly. The APK requires
  the TCL ReSukiSU fork and does not contain a persistent boot modification.

Both editions are temporary. A reboot removes the root module.

Build and usage details are in
[`docs/ADB_EDITION.md`](docs/ADB_EDITION.md) and
[`android-app/README.md`](android-app/README.md). The APK automatically uses
French controls on a French TV and English controls otherwise; low-level
diagnostic markers remain English for reproducible support logs.

The read-only command below checks the remaining device capability. It maps
one private page and reads its own pagemap entry; it performs no reclaim,
futex PI, MCAST or kernel write:

```sh
./ghostlock-tcl-v643-lab --capture-witness-preflight
```

`PFN_VISIBLE=0` means pagemap cannot be used. The semantic `perf` witness can
still prove a unique mapping without exposing the PFN, but its success is not
by itself authorization to run the root path on hardware.

The exact-source QEMU validation completed the live
futex/`_newselect`/PI/`rb_erase`/credential chain and clean teardown on 10/10
independent boots. The same carrier also passed 10/10 boots under the
instrumented kernel. A second integrated campaign used a genuine order-2
`mm_struct` slab, discarded it to CPU0 PCP index 8, captured its exact PFN
with `io_uring`, used that captured page for the AArch64/AArch32 chain, and
reached normalized UID/EUID/GID 0 on 10/10 independent boots. The QEMU
observer reveals the target slab/PFN/KVA, current task, scheduler group and
credential template, and the setup starts privileged before dropping its
UID. The final stability gate additionally requires all 16 mapping PFNs to be
visible, exactly one target hit, and the later `rb_erase` marker to appear in
that same witnessed block. Its positive two-cycle run passed; a negative VM
without the PFN ioctl returned `visible=0/16` and stopped before `TCL split`
without a panic. A later complete gate forced the PFN-free semantic `perf`
witness: it selected block 6 with unanimous exact-site hits, agreed with the
independent PFN observer, completed the `_newselect` root-to-app session and
powered down cleanly. The read-only preflight on the V643 TV returned
`PFN_VISIBLE=0`, while an earlier diagnostic-only `perf` pass selected exactly
one block. Android 14 therefore blocks pagemap, not the semantic witness. A cleanup
regression discovered during that validation was also fixed: expected capture
refusals now unwind normally, signal and reap the original-shell relay, and
return without leaving an init-owned process or holding the ADB transport.

The host-only target `tcl-v643-syscall-stack-model-test` models the exact V643
entry frames and the dormant random-kstack alternative. The stock V643 live
configuration leaves that static key disabled, preserving the futex/pselect
`+0x30` coordinate. This arithmetic result does not validate the vulnerable
futex transition or make the TCL profile runnable.

The host-only `tcl-v643-pi-blocked-on-model-test` records a separate static
finding from the exact V643 disassembly: the post-enqueue rollback clears
`current+0x910` while the proxy waiter was armed at `waiter->task+0x910`.
The upstream Android fix confirms this task mismatch. The test issues no
syscall and does not prove that the current TCL choreography reaches the
required post-enqueue `-EDEADLK`, signal timing, PI walk or reclaim.

The trigger also refuses `CMP_REQUEUE_PI` until the contending owner has
published `FUTEX_WAITERS` on the chain lock. This closes the former fixed-delay
race and makes the intended proxy -> target owner -> proxy cycle explicit.
The rejected `pselect6` scaffold ends its copied bitmap eight bytes before the
stale waiter; `sendmmsg` also corrupts the required task/lock fields. The TCL
profile instead uses ARM32 `_newselect`: its 320-fd bitmap block places the
controlled words exactly at waiter offsets `task=+0x30`, `lock=+0x38` and
`wake/prio=+0x40/+0x44`. GDB verified this geometry in the exact kernel, and
the helper refuses to arm until `/proc/.../syscall` shows syscall 142 with the
expected fdset pointers for three stable samples. The owner now times out via
an absolute two-second `FUTEX_LOCK_PI` deadline, matching the QEMU choreography
and avoiding the failed signal-abort variant.

Exact V643 anchors are modeled for the 0x400-byte
`panic.buf` fake-lock scratch, the `boot_id` ctl_table data field and the
2 MiB KASLR image alignment.  `tcl-v643-direct-primitive-model-test` also
records the unavoidable `rb_erase` collateral store at `parent_color+8`;
`tcl-v643-kaslr-model-test` proves only the coordinate mask, not a live leak.
The `_newselect` route is connected to the laboratory runnable path, but the
production profile remains `primitive_arming=REFUSED` until the live PFN
witness exists.

Root exploit for **Chromecast with Google TV** (sabrina) via [CVE-2026-43499](https://nvd.nist.gov/vuln/detail/CVE-2026-43499) -- a use-after-free in the Linux kernel's futex PI (priority inheritance) subsystem.

Achieves root on a **locked bootloader** device running Android 14 with kernel 5.15.170 (PGO+BOLT+LTO, clang 17).

## The vulnerability

GhostLock exploits a bug in `remove_waiter()` called from the `-EDEADLK` rollback path in `rt_mutex_start_proxy_lock()`. The function clears `current->pi_blocked_on` (the requeuer's, already NULL) instead of the waiter task's. The waiter's `pi_blocked_on` is never cleared, leaving a dangling pointer to a freed `rt_mutex_waiter` on the kernel stack.

A subsequent `sched_setattr` triggers `rt_mutex_adjust_pi` -> `rt_mutex_adjust_prio_chain`, which follows the dangling pointer and walks a PI chain over attacker-controlled data on a reclaimed heap page -- giving an arbitrary write primitive via `rb_erase`.

## Exploit chain

| Stage | Technique |
|-------|-----------|
| KASLR leak | `perf_event_open` with `PERF_SAMPLE_IP` (TID-gated) — min kernel IP is in `.entry.text` (+0x10000), `_text` is 2MB-aligned and the KASLR slide is a 2MB multiple, so `min_ip & ~0x1fffff` recovers the runtime `_text` exactly |
| Task struct leak | `perf_event_open` with `PERF_SAMPLE_REGS_INTR` (TID-gated, mode of linear-map addresses) |
| Symbol-table validation | perf-samples `&init_user_ns` out of `security_capable()`'s register arguments during a `setpriority(-20)` storm and matches it against `kaslr_base + off_init_user_ns` — proves the running kernel's `.data/.bss` layout matches the offsets table before any blind write |
| mm_struct leak | KernelSnitch -- futex hash collision timing side-channel |
| Heap spray | SLUB discard choreography (memfd-close, CPU-partial overflow) + `io_uring_setup(256)` order-2 page reclaim |
| Stack overlay | Sabrina uses `AF_UNIX SOCK_SEQPACKET`; the TCL V643 branch uses ARM32 `_newselect` syscall 142 with a 320-fd bitmap block at the verified waiter `+0x30` coordinate |
| Walk trigger | `sched_setattr` with monotonic nice ladder (7 -> 14 -> 19) fires the PI chain walk, one per overlay round |
| Write primitive | `rb_erase` Case 1: `{pc=(TARGET-8)|1, right=VALUE, left=0}` writes `VALUE` to `*TARGET` (plus `pc` to `*VALUE` when VALUE≠0); `{right=0}` is a clean 8-byte **zero**-write at TARGET with no side store |
| SELinux off (walk 0) | 8-byte zero at `selinux_state` clears `enforcing`, `checkreqprot`, `initialized` and `policycap[0..4]` — `avc_denied()` never denies (enforcing=0) and `security_compute_av()` short-circuits to allow-all (!initialized), so the post-swap kernel-SID (`u:r:kernel`) stops mattering |
| Cred swap (walks 1+2) | `task->cred = fake_cred` and `task->real_cred = fake_cred` (uid=0, caps FULL, self-contained fake `user_namespace` on the spray page; both writes required — `commit_creds()` at exec BUG_ONs unless cred == real_cred) |
| Root battery | raw-syscall-only probes (uid/SELinux/`/proc/1`/`/dev/kmsg`/wifi/packages/`/data/data`/kallsyms) into `/data/local/tmp/.ghostlock_out` |
| Root shell | `execve("/system/bin/sh")` — `commit_creds` in the exec path copies fake_cred into a clean slab credential; gated on all planned erases having landed |

### Key innovations

- **Walk-before-cleanup**: the overlay runs in the waiter context before futex cleanup; Sabrina uses the SIGUSR1/SEQPACKET route, while TCL V643 keeps `_newselect` resident until the owner timeout drives the PI walk
- **Three writes from one reclaim (mode 7)**: SELinux-off + cred + real_cred all fire against the *same* reclaimed page via same-page overlay retry rounds, consuming exactly the three rungs of the nice ladder — the heap-reclaim dice are rolled once for the whole chain
- **SELinux off via zero-write**: the rb_erase primitive with `rb_right = 0` performs a single clean 8-byte zero store at an arbitrary kernel address (no side store, no wild dereferences); zeroing the first qword of `selinux_state` gives double permissive (`enforcing=0` + `!initialized` → allow-all), which unblocks all post-root file I/O despite the kernel SID
- **Device-side symbol validation**: the offsets table comes from a reference vmlinux, but the device kernel is built with a different toolchain — before the blind SELinux write, the exploit perf-leaks `&init_user_ns` from the live `security_capable()` path and aborts to the cred-only flow unless it matches `kaslr_base + off_init_user_ns`
- **Fake user_namespace**: a self-contained namespace on the spray page with identity uid/gid maps and `ucounts = NULL` -- `cap_capable` matches on the first iteration and `inc_rlimit_ucounts` terminates after one loop, eliminating the need to leak `&init_user_ns`
- **TID-gated perf sampling**: `PERF_SAMPLE_TID` filters ensure only the calling thread's register snapshots are counted, preventing hot system services from dominating the mode-vote

## Target

- **Device**: Chromecast with Google TV (sabrina), Amlogic S905X3 (4x A55), 2 GB RAM
- **Kernel**: `5.15.170-android14-11-gf4a1f03072af` (aarch64, PGO+BOLT+LTO, clang 17.0.2)
- **Android**: 14, build UTTC.250917.004, security patch 2025-10-01
- **Config**: `CONFIG_FUTEX_PI=y`, `CONFIG_IO_URING=y`, `perf_event_paranoid=-1`, SELinux enforcing, `panic_on_oops=1`, no user namespaces

## Building

```bash
export ANDROID_NDK_HOME=/path/to/android-ndk
make -j$(nproc)
```

Requires the Android NDK (tested with r27). Produces a statically linked aarch64 binary.

## Usage

```bash
adb push ghostlock /data/local/tmp/
adb shell "cd /data/local/tmp && ./ghostlock --cred"
```

The exploit takes ~25 seconds (KASLR/task/layout leaks + heap spray + KernelSnitch bruteforce + three 3-second overlay rounds). On success it writes the root battery to `/data/local/tmp/.ghostlock_out`, the marker to `/data/local/tmp/.ghostlock_root`, and execs `/system/bin/sh` with uid=0 under a permissive kernel.

Environment knobs:

- `GHOST_SELINUX=0` — skip the SELinux write, run the proven cred-only route (mode 6)
- `GHOST_SELINUX_FORCE=1` — arm the SELinux write even if the device symbol-layout validation fails
- `GHOST_EXEC=0` — write the battery and exit(99) instead of execing a shell
- `CRED_ATTEMPTS=n` — full-spray retries when a run misses the reclaim (default 3)

## Acknowledgements and sources

Our sincere thanks go to every author, researcher, and maintainer whose work
made this port possible:

- **[k-o-n-t-o-r/ghostlock-sabrina](https://github.com/k-o-n-t-o-r/ghostlock-sabrina)** — direct upstream and the Sabrina port used as this repository's base;
- **[NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia)** — original IonStack research and GhostLock exploit chain;
- **[R0rt1z2/GhostLock](https://github.com/R0rt1z2/GhostLock)** — GhostLock implementation and profile references;
- **[AnonymousUser369/GhostLockAdapt](https://github.com/AnonymousUser369/GhostLockAdapt)** — related multi-target adaptation work;
- **[JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus)** — Android/OnePlus port and KernelSU integration references;
- **[pubglite55/oppo-ghostlock](https://github.com/pubglite55/oppo-ghostlock)** — OPPO porting research and kernel-family findings;
- **[YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app)** — Android application model and direct handoff from the process that gains UID 0;
- **[isec-tugraz/KernelSnitch](https://github.com/isec-tugraz/KernelSnitch)** — timing side channel used to locate `mm_struct`;
- **[ReSukiSU/ReSukiSU](https://github.com/ReSukiSU/ReSukiSU)** — separate KernelSU manager used after the handoff;
- **[Philiphall6/ReSukiSU](https://github.com/Philiphall6/ReSukiSU)** — required TCL fork, intentionally kept outside this GhostLock repository;
- **[tananaev/adblib](https://github.com/tananaev/adblib)** — local ADB transport used by the Android TV interface;
- **[Android Common Kernel](https://android.googlesource.com/kernel/common/)** and Linux — reference sources for futex PI, rtmutex, and rbtree.

Roles, links, and attribution details are recorded in
[`NOTICE.md`](NOTICE.md). Thank you to every one of these projects for sharing
code, analysis, and both successful and unsuccessful research results.

The TCL branch was developed and validated in the device owner's lab with assistance
from AI models, while preserving the upstream Git history and attribution.

Vulnerability reference:
**[CVE-2026-43499](https://nvd.nist.gov/vuln/detail/CVE-2026-43499)**.

## Disclaimer

This exploit is published for **security research and educational purposes**. It targets a device owned by the researcher. Do not use this on devices you do not own or without authorization.

## License

The GhostLock/CyberMeowfia-derived project is distributed under Apache-2.0;
third-party and separately distributed components retain their own licenses.
See [`LICENSE`](LICENSE), [`NOTICE.md`](NOTICE.md),
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md), and [`LICENSES/`](LICENSES/).
