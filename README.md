# Detection-Engineering

A CI/CD-driven detection engineering pipeline that treats Sigma/SPL detections as code: every rule is schema-validated, converted, deployed to a live Splunk instance, fired at with real Atomic Red Team techniques, and verified to actually generate a hit — automatically, on every push to `main`. Nothing in the published pass/fail numbers below is self-reported by the rule author; it's produced by the pipeline running the attack and checking Splunk for the result.

🔍 **[Interactive Rule Browser](https://martonbence.github.io/Detection-Engineering/)**

🛡️ **[Interactive MITRE Navigator](https://martonbence.github.io/Detection-Engineering/#navigator)**

<!-- STATS_START -->
[![Total Rules](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.total_rules&label=Total%20Rules&color=informational)](https://github.com/martonbence/Detection-Engineering/tree/main/rules)

[![Sigma Rules](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.total_sigma_rules&label=Sigma%20Rules&color=00ACD7)](https://github.com/martonbence/Detection-Engineering/tree/main/rules/sigma) [![Native SPL](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.total_native_spl_rules&label=Native%20SPL&color=FF6600)](https://github.com/martonbence/Detection-Engineering/tree/main/rules/splunk)

![Pass](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.verified_pass&label=Pass&color=brightgreen) ![Fail](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.verified_fail&label=Fail&color=red) ![Pass Rate](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.pass_rate_pct&label=Pass%20Rate%20%25&color=brightgreen) ![Not Verified](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.not_verified&label=Not%20Verified&color=lightgrey)

**MITRE ATT&CK Coverage**
![MITRE ATT&CK Coverage](https://quickchart.io/chart?c=%7B%22type%22%3A%22doughnut%22%2C%22data%22%3A%7B%22datasets%22%3A%5B%7B%22data%22%3A%5B11%2C211%5D%2C%22backgroundColor%22%3A%5B%22%23FFAA00%22%2C%22rgba%28128%2C128%2C128%2C0.15%29%22%5D%2C%22borderColor%22%3A%22black%22%2C%22borderWidth%22%3A0.5%7D%5D%7D%2C%22options%22%3A%7B%22rotation%22%3A3.141592653589793%2C%22circumference%22%3A3.141592653589793%2C%22cutoutPercentage%22%3A80%2C%22plugins%22%3A%7B%22legend%22%3A%7B%22display%22%3Afalse%7D%2C%22tooltip%22%3A%7B%22enabled%22%3Afalse%7D%2C%22datalabels%22%3A%7B%22display%22%3Afalse%7D%2C%22doughnutlabel%22%3A%7B%22labels%22%3A%5B%7B%22text%22%3A%22MITRE%20ATT%26CK%20Coverage%22%2C%22color%22%3A%22%23FFAA00%22%2C%22font%22%3A%7B%22size%22%3A18%2C%22weight%22%3A%22bold%22%7D%7D%2C%7B%22text%22%3A%225.0%25%22%2C%22color%22%3A%22%23FFAA00%22%2C%22font%22%3A%7B%22size%22%3A34%2C%22weight%22%3A%22bold%22%7D%7D%2C%7B%22text%22%3A%2211%20/%20222%22%2C%22color%22%3A%22%23FFAA00%22%2C%22font%22%3A%7B%22size%22%3A13%7D%7D%5D%7D%7D%7D%7D&width=500&height=300&f=svg)

**Rules by Severity**
![Rules by Severity](https://quickchart.io/chart?c=%7B%22type%22%3A%22outlabeledPie%22%2C%22backgroundColor%22%3A%22transparent%22%2C%22data%22%3A%7B%22labels%22%3A%5B%22Critical%22%2C%22High%22%2C%22Medium%22%2C%22Low%22%5D%2C%22datasets%22%3A%5B%7B%22backgroundColor%22%3A%5B%22%237B0000%22%2C%22%23DC2626%22%2C%22%23FFAA00%22%2C%22%232EA44F%22%5D%2C%22borderColor%22%3A%22black%22%2C%22borderWidth%22%3A0.5%2C%22hoverOffset%22%3A8%2C%22data%22%3A%5B14%2C9%2C3%2C1%5D%7D%5D%7D%2C%22options%22%3A%7B%22cutoutPercentage%22%3A45%2C%22layout%22%3A%7B%22padding%22%3A%7B%22top%22%3A5%2C%22right%22%3A30%2C%22bottom%22%3A0%2C%22left%22%3A30%7D%7D%2C%22plugins%22%3A%7B%22legend%22%3Afalse%2C%22outlabels%22%3A%7B%22text%22%3A%22%25l%3A%20%25v%20%28%25p%29%22%2C%22color%22%3A%22white%22%2C%22backgroundColor%22%3A%22rgba%2885%2C%2085%2C%2085%2C1%29%22%2C%22lineColor%22%3A%22rgba%2885%2C%2085%2C%2085%2C1%29%22%2C%22borderRadius%22%3A13%2C%22padding%22%3A6%2C%22stretch%22%3A20%2C%22font%22%3A%7B%22weight%22%3A%22bold%22%2C%22resizable%22%3Atrue%2C%22minSize%22%3A12%2C%22maxSize%22%3A22%7D%2C%22formatter%22%3A%22%28value%29%20%3D%3E%20value%20%3E%200%20%3F%20value%20%3A%20null%22%7D%7D%7D%7D&width=500&height=300&f=svg)

**Rules per MITRE ATT&CK Tactic**
![Rules per MITRE ATT&CK Tactic](https://quickchart.io/chart?c=%7B%22type%22%3A%22horizontalBar%22%2C%22data%22%3A%7B%22labels%22%3A%5B%22Execution%22%2C%22Credential%20Access%22%2C%22Stealth%22%2C%22Persistence%22%2C%22Defense%20Impairment%22%2C%22Command%20%26%20Control%22%2C%22Initial%20Access%22%5D%2C%22datasets%22%3A%5B%7B%22label%22%3A%22Rules%22%2C%22data%22%3A%5B14%2C13%2C8%2C2%2C2%2C1%2C1%5D%2C%22backgroundColor%22%3A%22%23FFAA00%22%2C%22borderColor%22%3A%22black%22%2C%22borderWidth%22%3A0.5%7D%5D%7D%2C%22options%22%3A%7B%22scales%22%3A%7B%22xAxes%22%3A%5B%7B%22display%22%3Afalse%2C%22gridLines%22%3A%7B%22display%22%3Afalse%2C%22drawOnChartArea%22%3Afalse%2C%22drawBorder%22%3Afalse%7D%2C%22ticks%22%3A%7B%22display%22%3Afalse%2C%22beginAtZero%22%3Atrue%7D%7D%5D%2C%22yAxes%22%3A%5B%7B%22display%22%3Atrue%2C%22position%22%3A%22left%22%2C%22gridLines%22%3A%7B%22display%22%3Afalse%2C%22drawOnChartArea%22%3Afalse%2C%22drawBorder%22%3Afalse%7D%2C%22ticks%22%3A%7B%22fontColor%22%3A%22%23FFAA00%22%7D%7D%5D%7D%2C%22legend%22%3A%7B%22display%22%3Afalse%7D%2C%22plugins%22%3A%7B%22datalabels%22%3A%7B%22anchor%22%3A%22end%22%2C%22align%22%3A%22start%22%2C%22color%22%3A%22black%22%2C%22font%22%3A%7B%22size%22%3A12%2C%22weight%22%3A%22bold%22%7D%7D%7D%7D%7D&width=500&height=322&f=svg)

🗺️ Interactive MITRE Navigator → [GitHub Pages](https://martonbence.github.io/Detection-Engineering/#navigator)

📋 Full rule index → [GitHub Pages](https://martonbence.github.io/Detection-Engineering/)

*Generated at 2026-07-23T15:11:38 UTC*
<!-- STATS_END -->

## Why this exists

Most "detection as code" repos stop at linting YAML. This one closes the loop: a rule isn't considered done because it parses — it's done because the pipeline deployed it to a real Splunk instance, ran the corresponding Atomic Red Team technique against a real Windows host, and confirmed the saved search actually fired on that specific execution. The Pass/Fail badges above are a live measurement, regenerated on every merge, not a claim.

## Pipeline

Every detection is authored as [Sigma](https://github.com/SigmaHQ/sigma) YAML — there is a single authoring format and a single pipeline, not two.

**1. Author.** Detections are written as Sigma YAML in [`rules/sigma/`](rules/sigma/). Most rules have a real `detection:` block that Sigma can compile. Some detections are too sophisticated or robust to express in the Sigma spec — those still live in `rules/sigma/*.yml` (a real `detection:` block is a required placeholder, never actually used), but set `custom.splunk.raw_query` to the raw SPL text, which the converter emits verbatim instead of compiling. Either way, `rules/sigma/*.yml` is the single source of truth for every field: severity, MITRE mapping, false positives, and testing config.

**2. Validate.** [`scripts/validate/validate_sigma.py`](scripts/validate/validate_sigma.py) checks every rule (converted or `raw_query`) against a Draft-07 JSON Schema ([`docs/schemas/sigma_schema.json`](docs/schemas/sigma_schema.json)). Nothing downstream runs on a rule that fails schema validation.

**3. Convert.** [`scripts/convert/sigma_to_spl.py`](scripts/convert/sigma_to_spl.py) compiles each validated Sigma rule into a `.spl` file in `rules/splunk/` (via `pysigma` with the Splunk backend, or verbatim for `raw_query` rules), plus a `.meta.json` sidecar carrying the same metadata for the deploy/verify/atomic-runner steps. The `.spl` file contains only the query — no embedded metadata — and is committed back to `main` by CI; the `.meta.json` sidecar is CI-runtime-only and never committed.

**4. Deploy.** [`scripts/deploy/deploy_spl_to_splunk.py`](scripts/deploy/deploy_spl_to_splunk.py) pushes each SPL file to a real Splunk instance as a saved search / scheduled alert, via Splunk's REST API, using credentials injected as GitHub Actions secrets. The saved search name is derived from the rule's `detect_id` + title (from the `.meta.json` sidecar), not from the filename — so renaming or restructuring files never orphans a deployed saved search.

**5. Attack.** [`scripts/atomic/run_atomic.ps1`](scripts/atomic/run_atomic.ps1) executes the [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) test(s) referenced in each rule's testing metadata against a live Windows host — a preflight dry run followed by the real execution. This is what actually generates the telemetry the deployed saved search is supposed to catch.

**6. Verify.** [`scripts/verify/check_saved_search_hits.py`](scripts/verify/check_saved_search_hits.py) queries Splunk for events matching each saved search in the minutes following the attack; [`scripts/verify/pass_fail_eval.py`](scripts/verify/pass_fail_eval.py) turns those matches into a per-rule Pass/Fail verdict written to [`outputs/results/`](outputs/results/) as `DETECT-*` result files.

**7. Report.** [`scripts/docs/generate_stats.py`](scripts/docs/generate_stats.py), [`generate_mitre_matrix.py`](scripts/docs/generate_mitre_matrix.py), and [`generate_atomic_coverage.py`](scripts/docs/generate_atomic_coverage.py) aggregate every rule and result into [`outputs/reports/stats.json`](outputs/reports/), `mitre_technique_map.json`, and `navigator_layer.json`. These feed both the stats block above and the rule browser.

**8. Publish.** [`docs/index.html`](docs/index.html) is a self-contained rule browser and interactive MITRE ATT&CK Navigator, published to GitHub Pages by the `deploy_pages` job (in [`ci_sigma_to_splunk_workflow.yml`](.github/workflows/ci_sigma_to_splunk_workflow.yml) and as a standalone [`deploy_pages.yml`](.github/workflows/deploy_pages.yml) that fires on any push to `docs/**`).

### CI orchestration

One workflow drives the whole pipeline: **[`ci_sigma_to_splunk_workflow.yml`](.github/workflows/ci_sigma_to_splunk_workflow.yml)**, triggered by changes under `rules/sigma/`. Validates → converts to SPL (+ meta sidecar) → deploys → runs Atomic Red Team (and, where applicable, domain-controller-specific or script-emulation tests) → verifies → regenerates stats → publishes.

Deploy, attack, and verify steps only run on pushes to `main` (not PRs), and only for rules whose testing metadata declares them ready. The workflow commits its own generated artifacts back to `main` (`chore(...): update ... [skip ci]`) — converted SPL (metadata-free), verification results, and refreshed stats/README — so the repository state always reflects the last pipeline run. The `.meta.json` sidecars are CI-runtime artifacts only; they're never committed.

The jobs run on a deliberate mix of runners, each mapped to what it needs physical/network access to:

| Runner label(s) | Role |
|---|---|
| `ubuntu-latest` | Validate/convert/bundle steps and the GitHub Pages publish job — no access to lab infrastructure needed. |
| `self-hosted, linux, de-lab` | The Splunk-side box: deploys saved searches and queries Splunk for verification results. |
| `self-hosted, X64, Windows, victim, atomic, windows-victim` | The Windows victim host where Atomic Red Team tests and script emulations actually execute. |
| `self-hosted, X64, Windows, dc, windows-dc` | A domain-controller host, used only for techniques that specifically require DC context. |

## Repository layout

| Path | Contents |
|---|---|
| [`rules/sigma/`](rules/sigma/) | Source-of-truth Sigma detection rules (`DETECT-*.sigma.yml`) |
| [`rules/splunk/`](rules/splunk/) | Deployable SPL — pure query text (`*.spl`), no embedded metadata, for every rule regardless of authoring style |
| [`scripts/validate/`](scripts/validate/), [`convert/`](scripts/convert/), [`deploy/`](scripts/deploy/), [`atomic/`](scripts/atomic/), [`verify/`](scripts/verify/), [`docs/`](scripts/docs/), [`lib/`](scripts/lib/) | The pipeline itself, one directory per stage, plus a small shared library |
| [`docs/schemas/`](docs/schemas/) | JSON Schema that gates every rule (`sigma_schema.json`) |
| [`docs/index.html`](docs/index.html) | The rule browser / MITRE Navigator published to GitHub Pages |
| [`docs/architecture/`](docs/architecture/) | Deeper technical references (pipeline overview, data flow, threat model) — see note below |
| [`outputs/reports/`](outputs/reports/) | Generated aggregate JSON (`stats.json`, `mitre_technique_map.json`, `navigator_layer.json`) |
| [`outputs/results/`](outputs/results/) | Per-rule `DETECT-*` pass/fail verification results |
| [`.github/workflows/`](.github/workflows/) | The CI/CD workflow described above |

`docs/architecture/pipeline_overview.md`, `data_flow.md`, and `threat_model.md` are placeholders being actively written up — treat the pipeline description above as the current source of truth until those land.

## Adding a new detection rule, end to end

1. Write a Sigma rule under `rules/sigma/` following the naming convention `DETECT-YYYY-NNNN_Short-Title.sigma.yml`, conforming to `docs/schemas/sigma_schema.json` (including the `custom.splunk` block for index/cron/testing metadata). If the detection is too sophisticated to express as a Sigma `detection:` block, set `custom.splunk.raw_query` to the raw SPL instead — the converter emits it verbatim.
2. Open a PR. `ci_sigma_to_splunk_workflow.yml` validates the rule and converts it to SPL on both `push` and `pull_request` — you can see the compiled SPL and any schema errors before merge.
3. On merge to `main`, the same workflow deploys the saved search to Splunk, executes the mapped Atomic Red Team test, and verifies a hit was recorded.
4. `generate_stats.py` regenerates the stats block in this README and the rule browser; results land in `outputs/results/` and `outputs/reports/`.
5. Check the [rule browser](https://martonbence.github.io/Detection-Engineering/) or [MITRE Navigator](https://martonbence.github.io/Detection-Engineering/#navigator) to confirm the new rule shows up with a Pass verdict and correct technique mapping.

## Built on the GitHub platform, not just in it

Part of what this repo demonstrates is disciplined use of GitHub's native collaboration surface for planning and tracking detection engineering work — not just committing YAML:

- **Issues** track planned pipeline enhancements as scoped, evidence-backed proposals rather than TODO comments. For example, [issue #20](https://github.com/martonbence/Detection-Engineering/issues/20) specifies auto-generating audit-ready per-rule documentation once a rule passes CI. The metadata-source question it raised has since been resolved: every rule's metadata now lives solely in `rules/sigma/*.yml` (including hand-crafted SPL rules, via `custom.splunk.raw_query`), so the future automation has one unambiguous source to read from.
- **[Detection Engineering Platform](https://github.com/users/martonbence/projects/3)** (Project #3) is a private GitHub Project board tracking pipeline and rule-content work through a `Todo` → in-progress → done workflow, with fields for status, labels, linked PRs, and parent/sub-issue relationships — the same mechanism used to plan and sequence the work in this repo, not an ad-hoc backlog.
- **Wiki**: intentionally not oversold — GitHub only provisions the wiki repository once the feature is enabled and a first page exists via the web UI, and that hasn't happened yet for this repo. It's planned as a more narrative, newcomer-facing companion to `docs/architecture/`, but as of now it does not exist as a clonable repo.

## Further reading

- [`docs/architecture/`](docs/architecture/) — Mermaid-diagrammed technical deep dives on the pipeline, data flow, and threat model (in progress; see note above)
- [GitHub Wiki](../../wiki) — planned newcomer-facing walkthrough (not yet initialized, see above)
