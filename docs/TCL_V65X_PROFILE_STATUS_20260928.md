# TCL T653T01 V655/V665/V667 profile status

This document describes offline analysis only. No V65x firmware was flashed
and no primitive was run on a television.

## Current result

V655, V665 and V667 use the same kernel release:

```text
5.15.192-android14-11
```

The three exact images have:

- identical embedded BTF;
- identical critical kallsyms addresses;
- matching layouts for all 16 root-chain structures compared with V643;
- identical compat-select and futex frame sizes;
- the vulnerable `remove_waiter()` condition still present;
- 163/163 ReSukiSU imported-symbol CRCs compatible with the existing source.
- an offline-proven physical kernel `_text` load address of `0x26000000`.
- exact static SLUB thresholds (`min_partial=5`, `cpu_partial=6`), an order-2
  `mm_struct` slab, and the same order-2 io_uring allocator geometry as V643;
- exact pageblock order 10 and half-block retag threshold 512, confirmed from
  machine code rather than inferred from the vendor configuration label.
- a shared V65x runtime route using the ARM32 `_newselect` carrier; and
- a successful QEMU surrogate cycle covering witnessed reclaim, the
  `_newselect` carrier, one `rb_erase` write and cleanup without a panic.

An analysis-only ReSukiSU candidate was also rebuilt with the exact target
vermagic `5.15.192-android14-11`. Its 163 imported symbol CRCs match all three
firmwares, its 20 relevant DWARF/BTF layouts match the real V655 BTF, and all
214 ELF imports resolve uniquely in each of the three exact System.map files.
Of these imports, 52 are private and therefore still require the normal
ReSukiSU relocation loader rather than a direct `insmod`.

The raw kernel image hashes differ, so the portable manifest records all three
hashes individually and does not identify a kernel by release string alone.

## Fail-closed profile

The native profile for `5.15.192-android14-11` is committed as
`analysis_only=1`. It uses the shared TCL ARM32 carrier but retains a distinct,
unproven V65x reclaim state. Consequently, the ordinary Android build and the
V643 QEMU lab build both refuse to execute it.

A separate `ghostlock-tcl-v65x-qemu-model` binary can promote that state only
inside the disposable source-built kernel. It first requires the
QEMU-exclusive `/dev/glqemu-root` observer, so copying it to Android cannot
arm the primitive. This binary is neither an APK payload nor a hardware
release.

The portable manifest is:

```text
profiles/tcl/t653t01/5.15.192-android14-11/profile.json
```

The manifest validator enforces that a profile cannot set
`execution_allowed=true` unless it is `hardware_validated` and has no remaining
blockers.

## Remaining blockers

1. Validate the live PCP/reclaim choreography on the exact stock V65x kernel
   or on an owned T653T01 device already running V65x. The source-built
   semantic surrogate now passes, but exact CPU/zone/PCP state and concurrent
   vendor drains remain runtime conditions.
2. Obtain or independently validate the still-unpublished exact TCL 5.15.192
   vendor source. The current module candidate uses TCL's published 5.15.180
   baseline plus exact target KMI/BTF checks.
3. Validate network, SELinux restoration and cleanup before any device test.

The physical-load item is closed offline. In V655, V665 and V667, all 13
packaged memory-map overlays set the `MI_KERNEL_POOL1` base to `0x26000000`.
Each exact `vendor_boot.img` has `kernel_addr=0`, each ARM64 Image has
`text_offset=0`, and each matching `mboot.img` implements the same
`MI_KERNEL_POOL1 + vendor_boot.kernel_addr` calculation. The complete evidence
is recorded in
`11_KERNEL_ANALYSIS_GENERATED/V655_V665_V667_20260927/T653T01-V65x-physical-text-proof.md`.

`struct page::slab_cache` is no longer a blocker. The 5.15 BTF represents it
through anonymous nested types: `page+0x08`, then `slab_cache+0x10`, yielding
the exact offset `0x18`.

The nf_log logger-pair offset is also resolved. Exact `nf_log_register()`
disassembly uses `loggers=+0x026d18f0`, a `0x10` protocol-row stride and the
same indexing sequence as V643. The required address is therefore
`+0x026d1900`; the corresponding data range was checked in the reconstructed
V65x ELF.

Until every blocker is closed, V655/V665/V667 remain unsupported and no APK or
ADB release should offer a root button for them.

## Static reclaim audit

All three V65x embedded configurations are byte-identical and have SHA-256
`2b1df3e8c81a2603e0fd771c32da2588149b4e5701cb82f2271109429bb93fbd`.
Their embedded BTF is also identical. `mm_cache_init()` requests 984 bytes,
which SLUB rounds to a 1024-byte stride; `__kmem_cache_create()` stores
`min_partial=5` and `cpu_partial=6`.

`put_cpu_partial()`, `__unfreeze_partials()` and `discard_slab()` are
instruction-identical across V655, V665 and V667. Other relevant allocator
functions have identical control flow; their few differing instruction words
only materialize firmware-specific diagnostic strings. The exact evidence is
recorded in `V655-V665-V667-reclaim-functions.csv` and
`T653T01-V65x-reclaim-static-audit.md` in the generated analysis directory.

The configuration contains `CONFIG_PAGE_BLOCK_ORDER=11`, but this is not the
compiled migration pageblock order. HugeTLB is disabled and
`CONFIG_FORCE_MAX_ZONEORDER=11`; exact `move_freepages_block()` code masks a
1024-page block (`~0x3ff`) and exact fallback code uses a 512-page threshold
(`0x1ff`). The effective pageblock order is therefore 10.

This closes the missing static geometry, not the live choreography. T653T01
firmware serves several models, so a C855 V643 zone snapshot cannot be treated
as proof for every model or for V65x. The profile remains `analysis_only` and
the distinct V65x reclaim enum still refuses execution.

## QEMU surrogate integration gate

The dedicated gate uses TCL's published 5.15.180 source-built laboratory
kernel after verifying the root-relevant allocator and carrier semantics
against the exact V655/V665/V667 binaries. On 2026-09-28 it produced:

```text
TCL capture witness: method=qemu-observer visible=16/16 hits=1 ... verdict=1
TCL split: erase=1 handler=1 cleanup=1 status=0 failures=0
GLV65XMODEL PASS: shared reclaim + ARM32 _newselect + rb_erase schema completed
```

The console log SHA-256 is
`b07a4021ab165845241e6b5cc0b9c559c4efcd628d1f64a0833ba4b609c072c2`.
It is stored under
`11_KERNEL_ANALYSIS_GENERATED/V655_V665_V667_20260927/qemu-v65x-surrogate-20260928-retry2/`.

This proves that the V65x profile plumbing follows the same chain as V643. It
does not make the surrogate an exact 5.15.192 vendor kernel and therefore
does not change the profile status to `qemu_validated` or authorize a TV run.

After the shared-route changes, the complete V643 production gate was run
again as a regression check. It reported a 16/16 reclaim witness,
`erase=1 handler=1 cleanup=1`, a verified write and the final result
`GLPROD PASS`, without a kernel panic. Its console log is stored under
`11_KERNEL_ANALYSIS_GENERATED/V643_20260918/qemu-production-gate-v65x-final-20260928/`
and has SHA-256
`eb6878992bb1de3a6a26fb55ac6e449c36b66b65c4a0777d02f2146847b93947`.

## Static ReSukiSU candidate

The reproducible build entry point is kept in the separate ReSukiSU tree:

```text
scripts/build-tcl-v65x-lkm-analysis.sh
```

The stripped candidate has SHA-256:

```text
48c64c0d8b85e62dd5db1125b32ea12cff91590d58138ad4a742ae19583b5db9
```

Its output contains `ANALYSIS_ONLY.txt` and `load_authorized=false`. No loader,
APK integration or device deployment is provided for this candidate.

## Host validation

```sh
make profile-guard-test profile-manifest-test \
  tcl-v65x-reclaim-static-model-test tcl-v65x-runtime-offsets-test
make NDK_ROOT=/path/to/android-ndk ghostlock
qemu-aarch64 ./ghostlock --profile-info 5.15.192-android14-11
./tools/build-qemu-lab.sh
./tools/run-qemu-v65x-surrogate.sh
```

Expected final line:

```text
primitive_arming=REFUSED
```
