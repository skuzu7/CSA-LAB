# MIRRORTRACE — APT-like Adversary Emulation (Offline)

**Threat-informed red/purple-team engineering portfolio · MITRE ATT&CK mapping · reproducible detection evidence**

This fictional, independent lab models an APT-style *sequence of behaviors* using **synthetic events only**. It demonstrates scenario design, ATT&CK mapping, event replay, correlation, negative controls, a JSON evidence report, and explicit limitations.

> **Not an APT tool or a real engagement.** No malware, exploitation, lateral movement, persistence, C2 or exfiltration occurs. No packets are sent, no endpoint settings are changed, and no third-party systems are accessed. It neither impersonates nor credibly attributes behavior to a real threat group.

## Hypothetical seven-stage chain

| Phase | MITRE ATT&CK | Synthetic observable |
| --- | --- | --- |
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Web access anomaly |
| Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | System inventory |
| Persistence | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Autorun configuration event |
| Lateral Movement | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | Remote-share session |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Fixture file access |
| Command and Control | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Periodic web traffic |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Outbound byte count |

**These are log labels, not actions performed.** Every fixture event is marked `synthetic: true`. The actor, host and campaign names are fictional.

## Reproduce on Python 3.11+ (standard library only)

```bash
python -m unittest discover -s apt_emulation/tests -t . -v
python -m apt_emulation.runner --output apt-emulation-report.json
```

The CLI exits non-zero when a labelled case fails; CI exports the report as a build artifact.

## Measured results on this hand-authored dataset

| Result | Count |
| --- | ---: |
| Full synthetic chain detected | 1 / 1 |
| Negative controls not alerted | 5 / 5 |
| False positives / false negatives | 0 / 0 |
| ATT&CK technique mappings in full chain | 7 / 7 |

Negative controls cover benign inventory, simulated admin and backup activity, missing C2, mixed actors and mixed campaign IDs. The detector joins events by actor and campaign, requires technique **and** event-type matches in sequence, and enforces a 30-minute window.

**Critical limitations:** One positive and five negatives do not establish production efficacy, threat attribution, realistic APT procedure reproduction, independent review, authorized client work, or vendor-program access. No SIEM, EDR, live host, real commands, independent validation or production traffic were used. The labels and expected outcomes were authored for this lab.

## Scope & sources

The module respects [the lab's authorization policy](../AUTHORIZATION.md). A separate first-party local web intrusion exercise appears in [the existing adversary-emulation plan](../docs/adversary-emulation-plan.md). This module does not broaden authorization for any external activity.

Methodology: [MITRE Adversary Emulation Plans](https://attack.mitre.org/resources/adversary-emulation-plans/) and [ATT&CK Enterprise](https://attack.mitre.org/). MITRE does not endorse or certify this project.
