# Detection-Engineering

A CI/CD-driven detection engineering pipeline that treats Sigma/SPL detections as code: every rule is schema-validated, converted, deployed to a live Splunk instance, fired at with real Atomic Red Team techniques, and verified to actually generate a hit — automatically, on every push to `dev`. A rule only reaches `main` (and the prod Splunk instance) after it has already passed that live verification on `dev`, via an auto-opened promotion pull request. Nothing in the published pass/fail numbers below is self-reported by the rule author; it's produced by the pipeline running the attack and checking Splunk for the result.

🔍 **[Interactive Rule Browser](https://martonbence.github.io/Detection-Engineering/)**

🛡️ **[Interactive MITRE Navigator](https://martonbence.github.io/Detection-Engineering/#navigator)**

<!-- STATS_START -->
[![Total Rules](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.total_rules&label=Total%20Rules&color=informational)](https://github.com/martonbence/Detection-Engineering/tree/main/rules)

[![Sigma Rules](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.total_sigma_rules&label=Sigma%20Rules&color=00ACD7)](https://github.com/martonbence/Detection-Engineering/tree/main/rules/sigma) [![Native SPL](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.total_native_spl_rules&label=Native%20SPL&color=FF6600)](https://github.com/martonbence/Detection-Engineering/tree/main/rules/splunk)

![Pass](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.verified_pass&label=Pass&color=brightgreen) ![Fail](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.verified_fail&label=Fail&color=red) ![Pass Rate](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.pass_rate_pct&label=Pass%20Rate%20%25&color=brightgreen) ![Not Verified](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.not_verified&label=Not%20Verified&color=lightgrey)

🗺️ Interactive MITRE Navigator → [GitHub Pages](https://martonbence.github.io/Detection-Engineering/#navigator)

📋 Full rule index → [GitHub Pages](https://martonbence.github.io/Detection-Engineering/)

*Generated at 2026-07-25T08:09:45 UTC*
<!-- STATS_END -->

## Why this exists

Most "detection as code" repos stop at linting YAML. This one closes the loop: a rule isn't considered done because it parses — it's done because the pipeline deployed it to a real Splunk instance, ran the corresponding Atomic Red Team technique against a real Windows host, and confirmed the saved search actually fired on that specific execution. The Pass/Fail badges above are a live measurement, regenerated on every merge, not a claim.

## Pipeline

Every detection is authored as [Sigma](https://github.com/SigmaHQ/sigma) YAML — there is a single authoring format and a single pipeline, not two.

**1. Author.** Detections are written as Sigma YAML in [`rules/sigma/`](rules/sigma/). Most rules have a real `detection:` block that Sigma can compile. Some detections are too sophisticated or robust to express in the Sigma spec — those still live in `rules/sigma/*.yml` (a real `detection:` block is a required placeholder, never actually used), but set `custom.splunk.raw_query` to the raw SPL text, which the converter emits verbatim instead of compiling. Either way, `rules/sigma/*.yml` is the single source of truth for every field: severity, MITRE mapping, false positives, and testing config.

**2. Validate.** [`scripts/validate/validate_sigma.py`](scripts/validate/validate_sigma.py) checks every rule (converted or `raw_query`) against a Draft-07 JSON Schema ([`docs/schemas/sigma_schema.json`](docs/schemas/sigma_schema.json)). Nothing downstream runs on a rule that fails schema validation.

**3. Convert.** [`scripts/convert/sigma_to_spl.py`](scripts/convert/sigma_to_spl.py) compiles each validated Sigma rule into a `.spl` file in `rules/splunk/` (via `pysigma` with the Splunk backend, or verbatim for `raw_query` rules), plus a `.meta.json` sidecar carrying the same metadata for the deploy/verify/atomic-runner steps. The `.spl` file contains only the query — no embedded metadata — and is committed back to `main` by CI; the `.meta.json` sidecar is CI-runtime-only and never committed.

**4. Deploy.** [`scripts/deploy/deploy_spl_to_splunk.py`](scripts/deploy/deploy_spl_to_splunk.py) pushes each SPL file to a real Splunk instance as a saved search / scheduled alert, via Splunk's REST API, using credentials injected as GitHub Actions secrets. The saved search name is computed by the shared [`scripts/lib/rule_naming.py`](scripts/lib/rule_naming.py) helper from the rule's `detect_id` + title (from the `.meta.json` sidecar), not from the filename — so renaming or restructuring files never orphans a deployed saved search, and this step and the verify step below always agree on the name since both import the same function.

**5. Attack.** [`scripts/atomic/run_atomic.ps1`](scripts/atomic/run_atomic.ps1) executes the [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) test(s) referenced in each rule's testing metadata against a live Windows host — a preflight dry run followed by the real execution. This is what actually generates the telemetry the deployed saved search is supposed to catch.

**6. Verify.** [`scripts/verify/check_saved_search_hits.py`](scripts/verify/check_saved_search_hits.py) queries Splunk for events matching each saved search in the minutes following the attack; [`scripts/verify/pass_fail_eval.py`](scripts/verify/pass_fail_eval.py) turns those matches into a per-rule Pass/Fail verdict written to [`outputs/results/`](outputs/results/) as `DETECT-*` result files.

**7. Report.** [`scripts/docs/generate_stats.py`](scripts/docs/generate_stats.py) aggregates every rule and result into [`outputs/reports/stats.json`](outputs/reports/), `mitre_technique_map.json`, and `navigator_layer.json`. These feed both the stats block above and the rule browser.

**8. Publish.** [`docs/index.html`](docs/index.html) is a self-contained rule browser and interactive MITRE ATT&CK Navigator, published to GitHub Pages from the `dev` branch by the `deploy_pages` job inside [`ci_dev_workflow.yml`](.github/workflows/ci_dev_workflow.yml) (runs after verification, on every dev pipeline push) and, redundantly, by the standalone [`deploy_pages.yml`](.github/workflows/deploy_pages.yml) workflow that fires independently on any push to `dev` touching `docs/**`. Both publish the same `docs/` tree from `dev` to the same GitHub Pages site — this is a real duplication in the workflow config, not a documentation simplification.

### CI orchestration — two workflows, dev then main

Detection changes are authored against `dev`, not `main` directly. Two separate workflows split "prove it works" from "ship it":

**[`ci_dev_workflow.yml`](.github/workflows/ci_dev_workflow.yml) — the full pipeline, runs on `dev`.** Triggered on `push` to any branch other than `main` and on `pull_request`, whenever `rules/sigma/**`, the schema, or the pipeline scripts change. Jobs, in dependency order:

| Job | Runs on | What it does |
|---|---|---|
| `prepare_validate_convert` | `ubuntu-latest` | Diffs changed Sigma files, validates them, converts them to `.spl` + `.meta.json`, and — on `push` to `dev` only — commits the regenerated `.spl` files back to `dev` and bundles the SPL/meta/scripts into an uploaded artifact (`spl-pipeline-bundle`, 1-day retention) for the self-hosted jobs below to consume without a full checkout. |
| `deploy_to_splunk` | `self-hosted, linux, de-lab` | Pushes the bundled SPL to the **dev** Splunk instance via `deploy_spl_to_splunk.py` (`environment: dev` secrets). Only on `push` to `dev` with SPL to deploy. |
| `atomic_verify` / `atomic_verify_dc` | `self-hosted, X64, Windows, victim, atomic, windows-victim` / `self-hosted, X64, Windows, dc, windows-dc` | Run `run_atomic.ps1` (preflight, then real execution) for rules whose testing metadata targets the victim host or the domain controller, respectively. Both are `continue-on-error: true` and upload their own progress markers (`atomic-progress-victim-*` / `atomic-progress-dc-*`, 1-day retention) so a hung/timed-out run still leaves ground truth for the verify step. |
| `emulation_verify` | `self-hosted, X64, Windows, victim, windows-victim` | Runs script-emulation-style tests via the same `run_atomic.ps1`, for rules whose testing metadata declares `type: emulation`. |
| `splunk_verify` | `self-hosted, linux, de-lab` | Waits for Splunk indexing, queries matched events (`check_saved_search_hits.py`), scores Pass/Fail (`pass_fail_eval.py`), uploads matched events as a diagnostic artifact (`matched-events-sigma-*`, 90-day retention), regenerates stats (`generate_stats.py`), commits results/stats/README back to `dev`, and — **only if the overall verdict is PASS** — opens the promotion PR described below. |
| `deploy_pages` | `ubuntu-latest` | Publishes `docs/` from `dev` to GitHub Pages (see the duplication note above). |

**[`ci_prod_workflow.yml`](.github/workflows/ci_prod_workflow.yml) — deploy-only, runs on `main`.** Triggered on `push` to `main` when `rules/sigma/**` changes (i.e. on merge of a promotion PR, or any other direct change to `main`). It does **not** re-validate, re-test, or re-verify anything: it regenerates the `.meta.json` sidecars from the already-committed, already-reviewed Sigma source (deterministic — the `.spl` output is byte-identical to what dev already produced and committed) and deploys every rule in `rules/splunk/*.spl` straight to the **prod** Splunk instance (`environment: prod` secrets) via the same `deploy_spl_to_splunk.py`. There is no Atomic Red Team run, no verification, and no stats/README commit on `main` — production deploy trusts the dev-branch verification that already happened.

#### Promotion PR: dev → main

When `splunk_verify`'s Pass/Fail evaluation (`pass_fail_eval.py`) exits `0` (overall PASS) on a `dev` push, the `Open promotion PR to main on PASS` step auto-opens a pull request (unless one is already open) with `gh pr create --base main --head dev --title "Promote verified detections from dev to main" --label automated-promotion`. This PR does **not** auto-merge — a human reviews and merges it manually, which is what triggers `ci_prod_workflow.yml` to deploy to prod. The same step immediately adds the new PR to [Project #3](https://github.com/users/martonbence/projects/3) (`gh project item-add`) and sets its Status field to `In review` (option `4fdb6324`), so auto-opened promotion PRs land on the board pre-triaged instead of mixed in with manually-created Todo/Ready items.

#### Project board automation on merge

[`project_status_automerged.yml`](.github/workflows/project_status_automerged.yml) is a separate, minimal workflow triggered on `pull_request: closed` (any PR, any branch). Its single job (`set_automerged_status`, on `ubuntu-latest`) only runs `if` the PR was actually merged **and** carries the `automated-promotion` label — i.e. specifically the promotion PRs opened by the step above. When that condition holds, it runs `gh project item-add 3 --owner martonbence --url <PR URL>` (idempotent — the item already exists from the `In review` step above) then `gh project item-edit` to move that item's Status field (`PVTSSF_lAHOA_8eh84BeHTLzhYj6O0`) from `In review` to the `Auto-merged` option (`be04d00f`). Together, the two steps give a promotion PR's board item a full lifecycle: `In review` from the moment it's opened, `Auto-merged` once it's actually merged.

The jobs run on a deliberate mix of runners, each mapped to what it needs physical/network access to. `dev` and `prod` share the same runner labels for the Splunk-side and Windows jobs — what differs between them is the GitHub Actions `environment` (`dev` vs `prod`), which selects a different set of `SPLUNK_*` secrets:

| Runner label(s) | Role |
|---|---|
| `ubuntu-latest` | Validate/convert/bundle steps and both GitHub Pages publish jobs — no access to lab infrastructure needed. |
| `self-hosted, linux, de-lab` | The Splunk-side box: deploys saved searches (dev and prod, via different `environment` secrets) and queries Splunk for dev verification results. |
| `self-hosted, X64, Windows, victim, atomic, windows-victim` | The Windows victim host where Atomic Red Team tests and script emulations actually execute (dev pipeline only). |
| `self-hosted, X64, Windows, dc, windows-dc` | A domain-controller host, used only for techniques that specifically require DC context (dev pipeline only). |

Note: `ci_prod_workflow.yml`'s single job (`deploy_to_prod`) also runs on `self-hosted, linux, de-lab`, not `ubuntu-latest` — it needs the same network path to Splunk as the dev deploy step.

## Repository layout

| Path | Contents |
|---|---|
| [`rules/sigma/`](rules/sigma/) | Source-of-truth Sigma detection rules (`DETECT-*.yml`) |
| [`rules/splunk/`](rules/splunk/) | Deployable SPL — pure query text (`*.spl`), no embedded metadata, for every rule regardless of authoring style |
| [`scripts/validate/`](scripts/validate/), [`convert/`](scripts/convert/), [`deploy/`](scripts/deploy/), [`atomic/`](scripts/atomic/), [`verify/`](scripts/verify/), [`docs/`](scripts/docs/), [`lib/`](scripts/lib/) | The pipeline itself, one directory per stage, plus a small shared library |
| [`docs/schemas/`](docs/schemas/) | JSON Schema that gates every rule (`sigma_schema.json`) |
| [`docs/index.html`](docs/index.html) | The rule browser / MITRE Navigator published to GitHub Pages |
| [`docs/architecture/`](docs/architecture/) | Deeper technical references with Mermaid diagrams: pipeline overview, data flow, threat model |
| [`outputs/reports/`](outputs/reports/) | Generated aggregate JSON (`stats.json`, `mitre_technique_map.json`, `navigator_layer.json`) |
| [`outputs/results/`](outputs/results/) | Per-rule `DETECT-*` pass/fail verification results |
| [`.github/workflows/`](.github/workflows/) | The CI/CD workflows described above (`ci_dev_workflow.yml`, `ci_prod_workflow.yml`, `project_status_automerged.yml`, `deploy_pages.yml`) |

## Adding a new detection rule, end to end

1. Write a Sigma rule under `rules/sigma/` following the naming convention `DETECT-YYYY-NNNN_Short-Title.yml`, conforming to `docs/schemas/sigma_schema.json` (including the `custom.splunk` block for index/cron/testing metadata). If the detection is too sophisticated to express as a Sigma `detection:` block, set `custom.splunk.raw_query` to the raw SPL instead — the converter emits it verbatim.
2. Open a PR against `dev` (or push a feature branch). `ci_dev_workflow.yml` validates the rule and converts it to SPL on both `push` and `pull_request` — you can see the compiled SPL and any schema errors before merge.
3. On merge/push to `dev`, the same workflow deploys the saved search to the **dev** Splunk instance, executes the mapped Atomic Red Team test (or DC / emulation variant), and verifies a hit was recorded via `check_saved_search_hits.py` + `pass_fail_eval.py`.
4. `generate_stats.py` regenerates the stats block in this README and the rule browser; results land in `outputs/results/` and `outputs/reports/`, committed back to `dev`.
5. If the overall dev-pipeline verdict is PASS, CI automatically opens a **promotion pull request** (`dev` → `main`, titled "Promote verified detections from dev to main", labeled `automated-promotion`) and adds it to [Project #3](https://github.com/users/martonbence/projects/3) with Status `In review`. This does not auto-merge — review it and merge manually to actually ship to prod.
6. Merging the promotion PR triggers `ci_prod_workflow.yml`, which deploys the same, already-verified SPL to the **prod** Splunk instance (no re-testing). Merging also fires `project_status_automerged.yml`, which moves the board item's Status from `In review` to `Auto-merged`.
7. Check the [rule browser](https://martonbence.github.io/Detection-Engineering/) or [MITRE Navigator](https://martonbence.github.io/Detection-Engineering/#navigator) (published from `dev`) to confirm the new rule shows up with a Pass verdict and correct technique mapping.

## Built on the GitHub platform, not just in it

Part of what this repo demonstrates is disciplined use of GitHub's native collaboration surface for planning and tracking detection engineering work — not just committing YAML:

- **Issues** track planned pipeline enhancements as scoped, evidence-backed proposals rather than TODO comments. For example, [issue #20](https://github.com/martonbence/Detection-Engineering/issues/20) specifies auto-generating audit-ready per-rule documentation once a rule passes CI. The metadata-source question it raised has since been resolved: every rule's metadata now lives solely in `rules/sigma/*.yml` (including hand-crafted SPL rules, via `custom.splunk.raw_query`), so the future automation has one unambiguous source to read from.
- **[Detection Engineering Platform](https://github.com/users/martonbence/projects/3)** (Project #3) is a private GitHub Project board tracking pipeline and rule-content work through a `Todo` → in-progress → done workflow, with fields for status, labels, linked PRs, and parent/sub-issue relationships — the same mechanism used to plan and sequence the work in this repo, not an ad-hoc backlog. Promotion PRs are automated end-to-end on this board: `ci_dev_workflow.yml` adds the PR to Project #3 with Status `In review` the moment it's auto-opened, then [`project_status_automerged.yml`](.github/workflows/project_status_automerged.yml) moves it to `Auto-merged` once it's actually merged — so these automated items never sit in `Todo`/`Ready` alongside manually-triaged work.
- **Wiki**: intentionally not oversold — GitHub only provisions the wiki repository once the feature is enabled and a first page exists via the web UI, and that hasn't happened yet for this repo. It's planned as a more narrative, newcomer-facing companion to `docs/architecture/`, but as of now it does not exist as a clonable repo.

## Further reading

- [`docs/architecture/`](docs/architecture/) — Mermaid-diagrammed technical deep dives: [`pipeline_overview.md`](docs/architecture/pipeline_overview.md), [`data_flow.md`](docs/architecture/data_flow.md), [`threat_model.md`](docs/architecture/threat_model.md)
- [GitHub Wiki](../../wiki) — planned newcomer-facing walkthrough (not yet initialized, see above)
