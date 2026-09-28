# Notice, sources, and acknowledgements

GhostLock TCL T653T01 v1.0 is derived from several open security-research
projects. We sincerely thank their authors and maintainers. The links below
identify sources that were used or consulted during the port. Inclusion does
not imply that those authors endorse this adaptation.

## Direct foundations

- [k-o-n-t-o-r/ghostlock-sabrina](https://github.com/k-o-n-t-o-r/ghostlock-sabrina)
  — direct upstream, Sabrina architecture, and preserved Git history.
- [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia)
  — original IonStack/GhostLock research and exploit-chain foundation.

## Implementations and ports consulted

- [R0rt1z2/GhostLock](https://github.com/R0rt1z2/GhostLock)
  — GhostLock implementation and target-profile mechanisms.
- [AnonymousUser369/GhostLockAdapt](https://github.com/AnonymousUser369/GhostLockAdapt)
  — related multi-device adaptation work.
- [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus)
  — Android/OnePlus port, network restoration, and KernelSU integration.
- [pubglite55/oppo-ghostlock](https://github.com/pubglite55/oppo-ghostlock)
  — OPPO porting research and documentation of kernel-family differences.
- [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app)
  — Android application model and direct handoff executed by the child that
  gains UID 0.

## Research components and root management

- [isec-tugraz/KernelSnitch](https://github.com/isec-tugraz/KernelSnitch)
  — futex timing side channel used to locate kernel objects. Copyright notices
  in derived files are preserved.
- [ReSukiSU/ReSukiSU](https://github.com/ReSukiSU/ReSukiSU)
  — parent KernelSU manager project and userspace foundation.
- [Philiphall6/ReSukiSU](https://github.com/Philiphall6/ReSukiSU)
  — required TCL T653T01 companion fork. The APK edition specifically requires
  its `tcl-c855-v1.0` release and package `com.philiphall6.resukisu.tcl`.
  Upstream generic modules are not interchangeable with the exact V643 module.
- [tananaev/adblib](https://github.com/tananaev/adblib)
  — owner-authorized local ADB transport used by the Android TV application.

## Reference sources

- [Android Common Kernel](https://android.googlesource.com/kernel/common/)
  — Android futex PI and rtmutex implementations and fixes.
- [Linux kernel](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/)
  — reference rbtree, futex, and kernel primitives.
- [CVE-2026-43499](https://nvd.nist.gov/vuln/detail/CVE-2026-43499)
  — public identifier for the vulnerability under study.

## TCL port attribution

The TCL T653T01/V643 profile, ARM32 `_newselect` carrier, safety gates, QEMU
models, and hardware validation were developed in the device owner's lab with
assistance from AI models. The direct upstream Git history is preserved so
earlier contributions remain traceable.

Thank you to everyone who publishes research, answers issues, and documents
failures as carefully as successes.

License details and the applicable verbatim license texts are listed in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) and [`LICENSES/`](LICENSES/).
