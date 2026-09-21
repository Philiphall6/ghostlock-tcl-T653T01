# TCL V643 reclaim stability gate

Date: 2026-09-21  
Scope: offline/QEMU stabilization after two unwitnessed live kernel panics.

## Cause addressed

The previous route copied the payload into all 16 `io_uring` mappings and
only learned which one backed the leaked `mm_struct` slab after triggering
the PI walk. If no mapping owned that physical page, the MCAST handler could
walk stale or unrelated memory. The object address slot was not a reliable
predictor: QEMU subsequently completed a witnessed slot-0 cycle.

## New fail-closed contract

Before creating the futex/MCAST chain the implementation now requires:

1. all tracked mapping PFNs are readable;
2. exactly one mapping PFN equals the target slab PFN;
3. the witnessed block index is valid;
4. the split route rechecks the confirmed verdict before creating the chain;
5. after the walk, the `rb_erase` marker must be in the same witnessed block.

PFNs masked by the kernel, partial visibility, zero matches and multiple
matches all abort before the vulnerable route.

## Final positive gate

Log:
`11_KERNEL_ANALYSIS_GENERATED/V643_20260918/qemu-stability-witness-final-positive/qemu-production-two-cycle-root-console.log`

- cycle 1: `visible=16/16 hits=1 block=7`, later `found=7`;
- cycle 2: `visible=16/16 hits=1 block=7`, later `found=7`;
- result: `GL2CYCLE PASS`, UID/EUID/GID normalized to 0;
- no panic or kernel fault marker.

Log SHA-256:
`871ae3aa654be0111cd97354281c7aceb022654e76ceee568cb2b0194408330c`

## Final negative gate

Log:
`11_KERNEL_ANALYSIS_GENERATED/V643_20260918/qemu-stability-witness-final-negative/qemu-witness-negative-console.log`

- the VM deliberately has no PFN observer;
- unprivileged pagemap returned `visible=0/16`;
- the reclaim printed `capture is not proven; refusing the dangerous route`;
- no `TCL split`, panic, or kernel-fault marker occurred.

Log SHA-256:
`80b40bc3a47cc1071c06df1c5915bf88890894c1075aab2186fb73972badd084`

## Tests

- all 16 host model targets passed;
- capture-witness unit cases cover PFN masked, partial, missing, unique and
  ambiguous states;
- cleanup model passed 100,000 transitions;
- final Android 14 API 34 binaries compile for AArch64 plus AArch32 helper.

Android lab binary SHA-256:
`af5a9f395a5dfbf42b569d4ec1d1e61365c243f3e4f3a15f6c58ed8f3f434efe`

Normal analysis-only binary SHA-256:
`6a6748cd4c6ff034456dedadaffabf0fc450b3d450b7b157f2d12422936991f5`

## Live TV validation

The safe preflight on the stock V643 TV returned:

`CAPTURE_WITNESS_PREFLIGHT PFN_VISIBLE=0 PFN=0 SAFE_READ_ONLY=1`

A single guarded attempt (`FOPS_MAX_ATTEMPTS=1`, `CRED_ATTEMPTS=1`) then
reported `visible=0/16 hits=0 block=-1` and refused the route. The complete
log contains no `heap spray done`, `TCL split`, `rb_erase` or root marker.

That first validation exposed a userspace-only cleanup defect: two expected
refusal messages still used `pr_error()`, whose macro calls `exit()` before
the reclaim and relay cleanup blocks. The kernel route was never entered, but
the diagnostic relay became an init-owned shell process and kept the ADB pipe
open. Both refusal paths now use non-fatal returns. A final bounded run emitted
the following ordered markers and returned in eight seconds:

```text
TCL capture witness: method=pagemap visible=0/16 hits=0 block=-1 ... verdict=0
TCL reclaim: capture is not proven; refusing the dangerous route
heap spray failed or was refused by the capture gate
TCL relay: fail-path child reaped status=0
cred swap failed after 1 attempts
```

No GhostLock process remained afterward. The nonzero program status is the
intentional fail-closed result.

The Android shell therefore receives zeroed PFNs from `/proc/self/pagemap`.
The stabilized build correctly refuses a live root attempt. This is an
intentional safety result, not a failed exploit retry.

Post-check state remained AVB green, VBMeta locked, verity enforcing and
SELinux enforcing, with continuously increasing uptime and no reboot.
