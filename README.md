# Detection-Engineering

A CI/CD-driven detection engineering pipeline: Sigma rules → Splunk SPL → deployed saved searches → Atomic Red Team validation → verified coverage.

<!-- STATS_START -->
![Total Rules](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.total_rules&label=Total%20Rules&color=informational)

![Sigma Rules](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.total_sigma_rules&label=Sigma%20Rules&color=00ACD7) ![Native SPL](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.total_native_spl_rules&label=Native%20SPL&color=FF6600)

![Pass](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.verified_pass&label=Pass&color=brightgreen) ![Fail](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.verified_fail&label=Fail&color=red) ![Pass Rate](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.pass_rate_pct&label=Pass%20Rate%20%25&color=yellow) ![Not Verified](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.not_verified&label=Not%20Verified&color=lightgrey)

```mermaid
pie title Verification Status
    "Pass ✅" : 3
    "Not Verified ⬜" : 1
```

```mermaid
pie title Rules by Severity
    "🟡 Medium" : 1
    "🟢 Low" : 3
```

```mermaid
xychart-beta
    title "Rules by MITRE ATT&CK Tactic"
    x-axis ["Execution", "Persistence"]
    y-axis "Rule Count" 0 --> 4
    bar [3, 1]
```

| ID | Title | Source | Severity | Status | Verdict |
|:---|:------|:------:|:--------:|:------:|:-------:|
| `DETECT-2026-0001` | Scheduled Task Creation via schtasks.exe | Sigma | 🟡 Medium | test | ✅ PASS |
| `DETECT-2026-0002` | Test Sigma Rule | Sigma | 🟢 Low | test | ✅ PASS |
| `DETECT-2026-0003` | Test3 | Native SPL | 🟢 Low | test | ⬜ N/A |
| `DETECT-2026-0004` | Test Sigma Rule | Sigma | 🟢 Low | test | ✅ PASS |

*Generated at 2026-04-17T14:23:17 UTC*
<!-- STATS_END -->
