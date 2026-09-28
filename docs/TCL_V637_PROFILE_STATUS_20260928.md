# TCL T653T01 V637 profile status

Date: 2026-09-28. This assessment is entirely offline. No command was sent to
a television.

## Verdict

`V8-T653T01-LF1V637` has a high static compatibility level with the
hardware-validated V643 chain, but V637 itself has not been tested on a TV.
It therefore remains `analysis_only`; the dedicated pre-release executable
requires exact runtime checks and an explicit risk acknowledgement.

## Exact package

- Source: <https://disk.yandex.ru/d/SE7SY4RPhqD7YA>
- File: `V8-T653T01-LF1V637.zip`
- Type: signed Android BLOCK OTA, not a full USB image
- Size: 2,359,668,793 bytes
- SHA-256: `38ea4a9f8df49afed7ee6f64a69f86d8e7118e484d19aba2fa90dbf730180c1e`
- Kernel: `5.15.180-android14-11`
- Kernel SHA-256: `656873a169372cafa170867519198b9649ac408badc3bdd640b82e6f4ee80548`

## V637 versus V643

- embedded kernel configuration: bit-identical;
- embedded BTF: bit-identical;
- 28/28 critical symbol addresses: identical;
- `_newselect` compat path and `free_unref_page`: instruction-identical;
- `remove_waiter`: same address, size and control flow; only two diagnostic
  string-address immediates differ;
- ReSukiSU module ABI: 163/163 imported symbol CRCs match, with exact
  vermagic;
- SELinux combined policy: bit-identical, size 1,030,054 and SHA-256
  `1930f6750090c816a3ea8cc32f752e2eec9b9e6d10d2851fe001fd690b069819`;
- vendor boot DTB and bootconfig: bit-identical.

The raw kernel files are not identical, so V637 is intentionally represented
by a separate manifest and exact kernel hash.

## Physical text address

The exact V637 package proves `_text` physical load `0x26000000`:

- all 12 DTBO memory-map overlays containing `MI_KERNEL_POOL1` use base
  `0x26000000`;
- `vendor_boot.kernel_addr` is zero;
- the ARM64 Image `text_offset` is zero and its magic is `ARMd`;
- the exact V637 mboot routines at `0x27499510` and `0x274995f8` read
  `/mmap_info/MI_KERNEL_POOL1` and calculate pool base plus the header load
  offset.

## Remaining blocker

No V637 hardware run has demonstrated the complete reclaim, cleanup,
ReSukiSU late-load and network/SELinux restoration sequence. A first test, if
the owner elects to perform one, must remain a single volatile attempt on a
fresh boot. It may panic or reboot the kernel and must not be described as
stable support unless all post-run checks pass.
