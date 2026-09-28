# GhostLock for TCL C855

Experimental temporary-root port for the **TCL C855 / T653T01** running:

- firmware `V8-T653T01-LF1V643`;
- Android 14;
- kernel `5.15.180-android14-11`.

Version 1.0 was validated on an owned television with a locked bootloader,
green Verified Boot and SELinux restored to enforcing after setup. It does not
flash the TV, modify `boot.img` or require OEM unlocking. Root is volatile and
is removed by a reboot.

> [!WARNING]
> This is build-specific security-research software, not a universal TCL root
> tool. A kernel exploit can crash or reboot the device. Use it only on hardware
> you own, on the exact supported build, and make only one attempt per boot.

## Download

The [v1.0 release](https://github.com/Philiphall6/ghostlock-tcl-c855/releases/tag/v1.0)
contains:

- `GhostLock-TCL-C855-v1.0.apk` — Android TV interface;
- `GhostLock-TCL-C855-v1.0-ADB.tar.xz` — command-line ADB edition;
- `SHA256SUMS-v1.0.txt` — download checksums.

## Required ReSukiSU companion

The APK edition requires the TCL-specific
[Philiphall6/ReSukiSU](https://github.com/Philiphall6/ReSukiSU) fork and its
[TCL C855 v1.0 release](https://github.com/Philiphall6/ReSukiSU/releases/tag/tcl-c855-v1.0).
The expected manager package is `com.philiphall6.resukisu.tcl`.

Do not substitute a generic ReSukiSU module: the included handoff is specific
to the TCL V643 kernel.

## Editions

### Android TV APK

The APK provides an English/French TV interface, device checks, local ADB
authorization and the temporary GhostLock-to-ReSukiSU handoff. Install the TCL
ReSukiSU manager first, then install and open the GhostLock APK.

See [android-app/README.md](android-app/README.md) for the controls and setup.

### ADB command line

The ADB edition is intended for an already authorized computer and includes
the binary, helper scripts, checksums and exact-target checks.

See [docs/ADB_EDITION.md](docs/ADB_EDITION.md) for usage.

## Scope

- Supported target: TCL C855 / T653T01 V643 only.
- No firmware flashing, Fastboot operation or bootloader unlock.
- No persistent root or boot-time installation.
- Rebooting ends the root session.
- Other firmware versions require separate validation.

## V655 / V665 / V667 development status

An extraction-only profile for the common `5.15.192-android14-11` kernel is
tracked in
[`profiles/tcl/t653t01/5.15.192-android14-11/profile.json`](profiles/tcl/t653t01/5.15.192-android14-11/profile.json).
It recognizes the exact V655, V665 and V667 kernel hashes but deliberately
refuses primitive arming. These versions are **not supported by the v1.0
release**. See
[`docs/TCL_V65X_PROFILE_STATUS_20260928.md`](docs/TCL_V65X_PROFILE_STATUS_20260928.md).

## Credits

This port builds on work from
[k-o-n-t-o-r/ghostlock-sabrina](https://github.com/k-o-n-t-o-r/ghostlock-sabrina),
[NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia),
[R0rt1z2/GhostLock](https://github.com/R0rt1z2/GhostLock),
[AnonymousUser369/GhostLockAdapt](https://github.com/AnonymousUser369/GhostLockAdapt),
[JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus),
[pubglite55/oppo-ghostlock](https://github.com/pubglite55/oppo-ghostlock),
[YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app),
[isec-tugraz/KernelSnitch](https://github.com/isec-tugraz/KernelSnitch),
[ReSukiSU/ReSukiSU](https://github.com/ReSukiSU/ReSukiSU),
[tananaev/adblib](https://github.com/tananaev/adblib),
the [Android Common Kernel](https://android.googlesource.com/kernel/common/)
and Linux.

Full attribution is available in [NOTICE.md](NOTICE.md) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Disclaimer

For authorized security research and education only. Do not use this project
on devices you do not own or do not have permission to test.

## License

The GhostLock/CyberMeowfia-derived project is distributed under Apache-2.0.
Third-party components retain their original licenses. See [LICENSE](LICENSE)
and [LICENSES/](LICENSES/).
