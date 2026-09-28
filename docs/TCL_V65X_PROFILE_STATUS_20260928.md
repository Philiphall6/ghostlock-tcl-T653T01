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
`analysis_only=1`. It also uses distinct V65x stack/reclaim enum values and an
unproven reclaim route. Consequently, the ordinary build and the V643 QEMU lab
arming build both refuse to execute it.

The portable manifest is:

```text
profiles/tcl/t653t01/5.15.192-android14-11/profile.json
```

The manifest validator enforces that a profile cannot set
`execution_allowed=true` unless it is `hardware_validated` and has no remaining
blockers.

## Remaining blockers

1. Confirm the physical kernel load address after a real V65x boot.
2. Re-run the exact SLUB/reclaim route in instrumented QEMU.
3. Obtain or independently validate the still-unpublished exact TCL 5.15.192
   vendor source. The current module candidate uses TCL's published 5.15.180
   baseline plus exact target KMI/BTF checks.
4. Validate network, SELinux restoration and cleanup before any device test.

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
make profile-guard-test profile-manifest-test
make NDK_ROOT=/path/to/android-ndk ghostlock
qemu-aarch64 ./ghostlock --profile-info 5.15.192-android14-11
```

Expected final line:

```text
primitive_arming=REFUSED
```
