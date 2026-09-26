# Third-party licensing

This repository preserves upstream history and attribution. Components retain
their upstream licenses; no entry below implies endorsement of this port.

| Component | Role | License |
|---|---|---|
| [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) | Original GhostLock/IonStack foundation | Apache-2.0 (`LICENSE`) |
| [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app) | Android direct-handoff design reference | Apache-2.0 (`LICENSE`) |
| [Philiphall6/ReSukiSU](https://github.com/Philiphall6/ReSukiSU) / [ReSukiSU/ReSukiSU](https://github.com/ReSukiSU/ReSukiSU) | Required userspace loader/manager | GPL-3.0 (`LICENSES/GPL-3.0.txt`) |
| ReSukiSU kernel module | Exact TCL V643 kernel module | GPL-2.0 (`LICENSES/GPL-2.0.txt`) |
| [tananaev/adblib](https://github.com/tananaev/adblib) | Local ADB client compiled into the APK | BSD-3-Clause (`LICENSES/BSD-3-Clause-adblib.txt`) |
| [isec-tugraz/KernelSnitch](https://github.com/isec-tugraz/KernelSnitch) | Timing side-channel component | MIT (`LICENSES/MIT-KernelSnitch.txt`) |
| [pubglite55/oppo-ghostlock](https://github.com/pubglite55/oppo-ghostlock) | Porting references | MIT, as declared upstream |

The repositories linked in `NOTICE.md` that do not publish license metadata
remain subject to their authors' rights. Their inclusion as acknowledgements
does not grant additional rights.

The ADB release archive redistributes exact binaries from the required
ReSukiSU fork. Corresponding source is the pinned public commit
`68e8d3333d1fdbaf9ce8e2aec5e31abca7e3cbd9` in
`https://github.com/Philiphall6/ReSukiSU`.
