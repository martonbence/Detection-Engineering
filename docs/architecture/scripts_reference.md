# Scripts Reference

Every executable file in this repo, what it is for, and who runs it. This is the "what does
this file do" lookup; [`pipeline_overview.md`](pipeline_overview.md) is the "how do they fit
together" narrative, and [`data_flow.md`](data_flow.md) traces the artefacts they pass around.

Nothing here is run by hand in the happy path — the two pipeline workflows invoke everything.
The manual entry points are called out explicitly where they exist.

> **Keeping this honest.** This file is maintained by hand, so it can drift from the code. The
> descriptions below state what a script is *for*; for exact flags and behaviour the module
> docstring at the top of each file is the source of truth, and it is where the reasoning behind
> the non-obvious decisions lives.

---

## At a glance

| File | Job | Run by |
|---|---|---|
| **Workflows** | | |
| [`.github/workflows/ci_dev_workflow.yml`](../../.github/workflows/ci_dev_workflow.yml) | The whole dev loop: validate → convert → deploy → attack → verify → report | push/PR to any branch but `main` |
| [`.github/workflows/ci_prod_workflow.yml`](../../.github/workflows/ci_prod_workflow.yml) | Deploys already-verified rules to the prod Splunk | push to `main` |
| [`.github/workflows/ci_code_checks.yml`](../../.github/workflows/ci_code_checks.yml) | CI for the pipeline's *own* code: ruff, pytest, PowerShell analysis, Console republish | push/PR touching `scripts/`, `tests/`, workflows, config |
| **Pipeline stages** | | |
| [`scripts/validate/validate_sigma.ps1`](../../scripts/validate/validate_sigma.ps1) | Thin wrapper that feeds the rule list to the Python validator in one process | dev workflow |
| [`scripts/validate/validate_sigma.py`](../../scripts/validate/validate_sigma.py) | Validates each Sigma rule against the JSON Schema | the wrapper above |
| [`scripts/validate/check_test_routing.py`](../../scripts/validate/check_test_routing.py) | Warns when a rule's test runner has no job that services it | dev workflow, pytest |
| [`scripts/convert/sigma_to_spl.py`](../../scripts/convert/sigma_to_spl.py) | Sigma YAML → `.spl` query + `.meta.json` sidecar | dev + prod workflows |
| [`scripts/deploy/deploy_spl_to_splunk.py`](../../scripts/deploy/deploy_spl_to_splunk.py) | Creates/updates the Splunk saved searches | dev + prod workflows |
| [`scripts/atomic/run_atomic.ps1`](../../scripts/atomic/run_atomic.ps1) | Executes the attack that is supposed to trigger each rule | dev workflow, 3 jobs |
| [`scripts/verify/check_saved_search_hits.py`](../../scripts/verify/check_saved_search_hits.py) | Asks Splunk how many events each deployed search matched | dev workflow |
| [`scripts/verify/pass_fail_eval.py`](../../scripts/verify/pass_fail_eval.py) | Turns those counts into a per-rule PASS / FAIL / NOT_VERIFIED verdict | dev workflow |
| [`scripts/docs/generate_stats.py`](../../scripts/docs/generate_stats.py) | Aggregates everything into `stats.json`, the README block and the rule browser | dev workflow + code checks |
| **Shared and state** | | |
| [`scripts/lib/rule_naming.py`](../../scripts/lib/rule_naming.py) | The one function deciding a rule's Splunk object name | deploy, verify, reconcile |
| [`scripts/state/reconcile.py`](../../scripts/state/reconcile.py) | Compares the repo against live Splunk, and cleans up what no longer belongs | dev workflow (+ manual for removals) |
| [`scripts/state/prune_orphans.py`](../../scripts/state/prune_orphans.py) | Deletes repo-side artefacts of rules that no longer exist | dev workflow |
| **Tests** | | |
| [`tests/`](../../tests/) | pytest suite over the Python scripts, with Splunk faked | `ci_code_checks.yml` |

---

## Workflows

### `ci_dev_workflow.yml` — the pipeline

The main event. Eight jobs; the interesting property is that the middle ones run on **self-hosted
runners** because they need the lab: a Linux runner that can reach Splunk, and Windows machines
that get genuinely attacked.

| Job | Runner | Does |
|---|---|---|
| `prepare_validate_convert` | `ubuntu-latest` | Works out which rules changed, prunes orphans, validates, converts, commits the `.spl`, builds the *pipeline bundle* artefact the later jobs consume |
| `deploy_to_splunk` | self-hosted Linux | Deploys the bundle's SPL to the dev Splunk |
| `atomic_verify` | self-hosted Windows (victim) | Runs the Atomic Red Team tests |
| `atomic_verify_dc` | self-hosted Windows (DC) | Same, for rules that must be attacked on a domain controller |
| `emulation_verify` | self-hosted Windows (victim) | Runs `emulation`-type rules' own commands; shares the victim host with `atomic_verify`, so these run in sequence |
| `splunk_verify` | self-hosted Linux | Queries Splunk, evaluates verdicts, reconciles state, regenerates stats, commits results |
| `open_promotion_pr` | `ubuntu-latest` | On an overall PASS, opens the `dev` → `main` promotion PR |
| `deploy_pages` | `ubuntu-latest` | Publishes the rule browser to GitHub Pages after a pipeline run |

Two things worth knowing before editing it:

- **The `changes` step decides how much work happens.** It builds a list of changed Sigma rule
  files; if that list is empty, `has_rules=false` and nearly every job below is skipped. Adding a
  path to the `paths:` trigger without also teaching the `changes` step about it produces a run
  that starts, skips everything, and reports green.
- **Deletions are invisible to it.** The diff uses `--diff-filter=AMRC`, which excludes removals,
  so a commit that only deletes a rule produces no work at all. That is why the prune step has its
  own trigger conditions and its own commit.

### `ci_prod_workflow.yml` — production deploy

One job, on `main`. It re-converts from Sigma (which is how the `.meta.json` sidecars, gitignored
and never committed, come to exist on the prod runner), then runs a **drift gate** — `git diff
--exit-code -- rules/splunk` — before deploying. If the re-conversion produced a different `.spl`
than the one reviewed and merged, the deploy stops. Both workflows install from the same pinned
[`.github/requirements.txt`](../../.github/requirements.txt), which is what makes that
reproducibility claim mean anything.

`main` never attacks anything or verifies anything; it trusts what `dev` proved.

### `ci_code_checks.yml` — CI for the pipeline itself

Exists because the dev workflow only does real work when a *rule* changes, so the code running the
pipeline was never itself exercised. Four jobs:

| Job | Does |
|---|---|
| `static_analysis` | `ruff check .` and `pytest` on `ubuntu-latest` — no Splunk, no lab, no live attacks |
| `powershell_analysis` | Parses every `.ps1` with PowerShell's own parser, then runs PSScriptAnalyzer. Separate job so a ruff failure cannot mask a PowerShell one |
| `regenerate_console` | Re-runs `generate_stats.py` and commits if the output changed by more than its embedded timestamps |
| `publish_console` | Publishes the regenerated site, because Pages serves an uploaded artefact rather than the branch — a commit alone would update the repo but not the live page |

Pages therefore has two publishers: this workflow's `publish_console` and the dev pipeline's
`deploy_pages`. They share the repo-wide `pages` concurrency group so the two deployments queue
instead of racing.

---

## Pipeline stages

### `scripts/validate/validate_sigma.ps1`

Wrapper around the Python validator. Its whole reason to exist is that it hands the **entire** rule
list to one Python process instead of spawning one per file, and it filters out paths that no
longer exist (a rule deleted in the same push). Also prints the run summary: validated / ok /
invalid / skipped / deleted.

*Note:* its `-SchemaPath` default (`docs/schemas/schema.json`) does not match the real schema
filename; the workflow always passes the path explicitly, so the default is never exercised.

### `scripts/validate/validate_sigma.py`

Validates each rule against [`docs/schemas/sigma_schema.json`](../../docs/schemas/sigma_schema.json)
(Draft-07). Parses with `yaml.safe_load`, normalises YAML dates to ISO strings so the schema's
`string` type matches, and prints per-rule OK/INVALID plus the failing paths.

Exit codes are meaningful: `0` all valid, `1` at least one rule invalid, `2` the validator itself
could not run (missing dependency, unreadable schema). Nothing downstream runs on a rule that fails
here.

### `scripts/validate/check_test_routing.py`

Answers one question the schema cannot: **is there a job that will actually run this rule's test?**

`run_atomic.ps1` selects work by an exact match on the `(custom.testing.type, custom.testing.runner)`
pair the job hands it via `ATOMIC_TESTER_TYPE` / `ATOMIC_RUNNER`. The schema's `runner` enum is wider
than the set of jobs — `linux-victim` is in it deliberately, ahead of that VM existing — so a rule can
be schema-valid, deploy fine, and then be dropped by every test job with a single `Write-Host` line
in a job that exits `0`. Nothing else reports it.

The serviced combinations are **derived from the workflow**, not hardcoded: the script parses
`ci_dev_workflow.yml`, collects every step that sets both env vars, and treats those pairs as the
matrix. Adding the linux job later needs no edit here, and deleting a job cannot leave a stale
allow-list behind claiming its rules are still covered. If no job sets both vars it exits `2` rather
than reporting every rule in the repo as unrouted — that state is a checker fault, not a rule fault.

A missing `runner` is flagged the same way as an unserviced one: the converter only writes the meta
field when it is non-empty, so "unset" is not "the default", it is a value every job's filter rejects.

Runs in two places with two different severities. In the dev workflow it is a `::warning` plus a step
summary table — a detection is worth deploying even when its test cannot run yet. In the pytest suite
(`tests/test_check_test_routing.py`, run by `ci_code_checks.yml`) it is a hard failure, because a
*committed* rule that stops routing means a job was renamed or removed.

Exit codes: `0` clean or advisory, `1` findings under `--strict`, `2` the checker could not run.

### `scripts/convert/sigma_to_spl.py`

**In:** Sigma YAML. **Out:** `rules/splunk/<same stem>.spl` plus a `<same stem>.meta.json` sidecar.

Picks the pySigma pipeline from the rule's log source (`sysmon` → `splunk_sysmon_acceleration`,
`security` → `splunk_windows`, anything else → no pipeline), overridable with
`custom.splunk.splunk_pipeline`. A rule that sets `custom.splunk.raw_query` bypasses conversion
entirely and is emitted verbatim — the escape hatch for detections too sophisticated to express as
a Sigma `detection:` block.

The **sidecar is the important output**: it carries `detect_id`, title, description, deploy mode,
cron, severity, status and the testing block forward to the deploy and the runners, and it is
gitignored — it exists only during a run, which is why prod re-converts before deploying.

### `scripts/deploy/deploy_spl_to_splunk.py`

Creates or updates one Splunk saved search per `.spl`, addressed in the
`servicesNS/{owner}/{app}` namespace. Sets the schedule and alert configuration from the sidecar
(`deploy_mode: alert` becomes a scheduled alert; `report` becomes an unscheduled object), applies
the object ACL, and stamps every description with `Managed by CI/CD (Detection-Engineering repo)`.

That stamp is load-bearing: it is how `reconcile.py` later tells the pipeline's own objects apart
from searches an analyst built by hand.

**Skips `status: deprecated` rules.** Skipping only stops the object being created or updated —
retiring one that already exists is `reconcile.py --apply-removals`, deliberately a separate,
manual act.

### `scripts/atomic/run_atomic.ps1`

The largest single script, and the only one that runs on the Windows lab machines. Reads each
rule's testing block from its sidecar and, depending on `custom.testing.type`, either invokes
**Atomic Red Team** tests or executes the rule's own emulation commands. Used by all three test
jobs; `-Runner` decides which rules a given host claims.

What it does beyond "run the test":

- **Progress markers.** Writes a started/completed marker per rule, synchronously. This is what
  lets `pass_fail_eval.py` distinguish "the attack ran and the rule did not fire" (FAIL) from "we
  never got to this rule" (NOT_VERIFIED) — for instance when the step's 10-minute timeout killed it
  halfway through.
- **Prereqs and cleanup.** Runs Atomic Red Team's `-GetPrereqs` before and `-Cleanup` after each
  test (three separate invocations, since those are mutually exclusive switches). A failure in
  either does not count against the verdict — the verdict is about detection, not housekeeping.
- **Defender handling with a failsafe.** When real-time monitoring is disabled for a test, a
  scheduled task is registered **first** that will re-enable it (once after 20 minutes, and again
  at startup) even if this process is hard-killed and its `finally` block never runs. If that task
  cannot be registered, the script refuses to disable Defender at all.
- **Degrades instead of dying.** A malformed rule produces a warning and is skipped, not an
  exception that takes the rest of the batch with it. If *every* rule in the batch is malformed, it
  exits non-zero — "nothing to run" and "everything is broken" both mean zero tests, but only one
  deserves a green check.

`-PreflightOnly` and `-DryRun` are the manual entry points for checking a batch without attacking
anything.

### `scripts/verify/check_saved_search_hits.py`

Dispatches each **already-deployed** saved search over a time window via the Splunk REST API and
records what matched into `<output-dir>/<detect_id>/hits.json`. It does not re-run the raw SPL — it
measures the object that is actually deployed, which is the only thing worth measuring.

Two details that exist because of past false verdicts: it only reads results once the search
reaches `DONE` (reading early returned partial counts that looked like real ones), and every error
carries an `error_kind` — `unmeasured` (we could not measure) versus `rule_error` (something is
genuinely wrong with the rule or its deployment). Its own exit code is always `0`; per-rule
problems live inside the JSON.

### `scripts/verify/pass_fail_eval.py`

Turns hit counts into verdicts, written to `outputs/results/<detect_id>/result.json` plus a
Markdown table in the job summary.

- **PASS** — `--min-pass ≤ events ≤ --max-pass` (currently 1..10; the ceiling catches a rule that
  fires on everything).
- **FAIL** — outside that window, or an `error_kind: rule_error`.
- **NOT_VERIFIED** — the attack never reached this rule (no completed progress marker), or the
  measurement itself failed (`error_kind: unmeasured`). Not a soft FAIL: nothing was learned, and
  reporting a confirmed negative would be inventing data.

Exit code `0` only if every rule passed; `1` otherwise. That exit code is the pipeline's verdict —
it is what gates the promotion PR.

### `scripts/docs/generate_stats.py`

The reporting layer, and by a wide margin the longest file in the repo (~6000 lines, most of it
inline HTML for the rule browser — [register item 3.4](../../audit/remediation-plan.md) is about
splitting that up).

**Reads** every Sigma rule, the `.spl` count and every `result.json`. **Writes**
`outputs/reports/stats.json` (which the README badges read), `mitre_technique_map.json`,
`navigator_layer.json` (a portable ATT&CK Navigator layer), the stats block inside `README.md`, and
the whole of `docs/index.html`.

It is also where a verdict's *standing* is derived: it recomputes each rule's current version from
git history, compares it to the version recorded in the result file, and checks the result's age
against the 180-day review interval — so the published pass rate only counts measurements still
valid for the rule as it stands today. Because the expiry depends on when the page is opened, the
browser recomputes it client-side too; `stats.json` is the build-time snapshot.

---

## Shared and state

### `scripts/lib/rule_naming.py`

Twenty lines, and every Splunk object name in the system comes from it: `<detect_id>_<slug(title)>`.
Deploy, verification and reconciliation all import the same function, which is what makes them
agree about which object belongs to which rule.

The name deliberately includes the title even though that makes it mutable — an analyst reading
Splunk's search bar or an alert list sees the name, not the description. The cost is that editing a
title orphans the old object, which is what `reconcile.py` cleans up.

### `scripts/state/reconcile.py`

Compares desired state (the repo's rules) against actual state (what is live in Splunk), sorting
every name into one of five buckets: `in_sync`, `missing`, `orphan_renamed`, `orphan_removed`,
`unmanaged`.

| Mode | Does |
|---|---|
| default | Read-only report + JSON output |
| `--apply` | **Deletes** rename orphans. Safe unattended, and runs on every dev pipeline run |
| `--apply-removals` | **Disables and marks** (never deletes) objects whose rule left the repo. Manual only; requires `--apply` |

The two orphan kinds are separated because they mean different things: a rename orphan's rule is
alive under a new name, so the leftover is safe to delete — but only once the replacement is
verified live in Splunk, otherwise a failed deploy plus an eager cleanup would leave a rule with no
saved search at all. A removal orphan's rule is gone entirely, which is not always intentional, so
it is disabled rather than deleted and a human has to ask for it.

Objects without the CI marker are reported and never touched.

### `scripts/state/prune_orphans.py`

The repo-side counterpart. Deletes `rules/splunk/*.spl` files and `outputs/results/<detect_id>/`
directories that no longer belong to any rule — the leftovers of a deleted rule, which otherwise
keep being deployed to prod (which reads `git ls-files`) and keep counting towards the dashboard's
coverage.

Compares current state rather than a diff, so it is idempotent and self-healing. Refuses to run
against an empty rules directory, on the grounds that a bad path or a partial checkout should not
read as "delete the whole library". Deprecated rules keep their artefacts: the rule still exists,
and its measurement history is still its own.

`--apply` to actually delete; without it, it just names what would go.

---

## Tests

Run by `ci_code_checks.yml` on every code change. Splunk is faked throughout — the whole suite runs
in milliseconds, on any machine, with no lab and no credentials. It is the only fast feedback loop
in this repo: the real one is a full pipeline run with live attacks.

| File | Covers |
|---|---|
| [`tests/conftest.py`](../../tests/conftest.py) | Puts `scripts/*` on `sys.path`. The scripts are standalone CLI entry points invoked by path, not an installable package, and this is what makes them importable without restructuring that |
| [`tests/test_check_saved_search_hits.py`](../../tests/test_check_saved_search_hits.py) | The Splunk polling loop: timeouts, `FINALIZING` handling, `error_kind` classification |
| [`tests/test_pass_fail_eval.py`](../../tests/test_pass_fail_eval.py) | Verdict logic, including which errors soften to NOT_VERIFIED and which stay FAIL |
| [`tests/test_reconcile.py`](../../tests/test_reconcile.py) | Bucket classification, and the write path: that a rename orphan is not deleted when its replacement is not live, that removals are disabled rather than deleted, that the CI marker survives, that unmanaged objects are never written to |
| [`tests/test_prune_orphans.py`](../../tests/test_prune_orphans.py) | Which artefacts count as orphaned, the fail-safes, idempotency |
| [`tests/test_deploy_deprecated.py`](../../tests/test_deploy_deprecated.py) | That a deprecated rule generates *zero* HTTP calls, and that everything else still deploys |
| [`tests/test_sigma_to_spl.py`](../../tests/test_sigma_to_spl.py) | Index-prefix injection, including that a query opening with a generating command is left alone rather than turned into invalid SPL |
| [`tests/test_check_test_routing.py`](../../tests/test_check_test_routing.py) | That the serviced matrix is derived from the workflow rather than hardcoded, and — against the real repo — that every committed rule still has a job that can run its test |

---

## Supporting configuration

Not scripts, but they decide how the scripts behave.

| File | Role |
|---|---|
| [`docs/schemas/sigma_schema.json`](../../docs/schemas/sigma_schema.json) | The contract every rule must satisfy. Conditionally requires the right testing block for the declared test type (only for `enabled: true` rules, so a parked rule need not maintain a test list) |
| [`.github/requirements.txt`](../../.github/requirements.txt) | Pinned pipeline toolchain, installed by both dev and prod. `pySigma` is pinned separately from `sigma-cli` because it is what actually serialises the query |
| [`.github/requirements-dev.txt`](../../.github/requirements-dev.txt) | Pinned `pytest` and `ruff`, for the code-checks workflow only |
| [`pyproject.toml`](../../pyproject.toml) | ruff and pytest config. ruff is deliberately narrow (`F` + `E9`) for now — see the comment in the file |
| [`.github/PSScriptAnalyzerSettings.psd1`](../../.github/PSScriptAnalyzerSettings.psd1) | PowerShell lint rules, with three exclusions and the reasoning for each in the file |

`.vscode/settings.json` and `.claude/settings.json` are local editor and agent configuration; they
have no effect on CI.

## What is *not* a script

- [`docs/index.html`](../../docs/index.html) — generated output, never edited by hand. Its source
  is the HTML embedded in `generate_stats.py`.
- [`rules/splunk/*.spl`](../../rules/splunk/) — generated from Sigma, committed so that prod
  deploys exactly what was reviewed.
- [`outputs/`](../../outputs/) — verification results and reports, written by the pipeline.
- [`audit/`](../../audit/) — the standing remediation plan and its published register.
