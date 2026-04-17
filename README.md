# Detection-Engineering

A CI/CD-driven detection engineering pipeline: Sigma rules → Splunk SPL → deployed saved searches → Atomic Red Team validation → verified coverage.

<!-- STATS_START -->
![Sigma Rules](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.total_sigma_rules&label=Sigma%20Rules&color=blue) ![Pass](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.verified_pass&label=Pass&color=brightgreen) ![Fail](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.verified_fail&label=Fail&color=red) ![Pass Rate](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.pass_rate_pct&label=Pass%20Rate%20%25&color=brightgreen) ![Not Verified](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.not_verified&label=Not%20Verified&color=lightgrey)

```mermaid
pie title Verification Status
    "Pass ✅" : 2
```

```mermaid
pie title Rules by Severity
    "🟡 Medium" : 1
    "🟢 Low" : 1
```

```mermaid
xychart-beta
    title "Rules by MITRE ATT&CK Tactic"
    x-axis ["Execution", "Persistence"]
    y-axis "Rule Count" 0 --> 3
    bar [2, 1]
```

| ID | Title | Severity | Status | Verdict |
|:---|:------|:--------:|:------:|:-------:|
| `DETECT-2026-0004` | Test Sigma Rule | 🟢 Low | test | ✅ PASS |
| `DETECT-2026-0005` | Scheduled Task Creation via schtasks.exe | 🟡 Medium | test | ✅ PASS |

*Generated at 2026-04-17T11:20:02 UTC*
<!-- STATS_END -->
