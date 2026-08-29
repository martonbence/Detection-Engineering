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
| [`.github/workflows/ci_prod_workflow.yml`](../../.github/workflows/ci_prod_workflow.yml) | Deploys already-verified rules to the prod Splunk app (same server as dev, different app), then folds that run's own deploy report into the dashboard and republishes it — 4 jobs: `announce_lab_offline`, `deploy_to_prod`, `update_dashboard`, `deploy_pages` | push to `main` |
| [`.github/workflows/ci_code_checks.yml`](../../.github/workflows/ci_code_checks.yml) | CI for the pipeline's *own* code: ruff, pytest, PowerShell analysis, actionlint, `pip-audit`, Console republish | push/PR touching `scripts/`, `tests/`, `pyproject.toml`, the requirements files, `.github/workflows/**`, `.github/PSScriptAnalyzerSettings.psd1`, `.github/actionlint.yaml` |
| **Pipeline stages** | | |
| [`scripts/validate/validate_sigma.ps1`](../../scripts/validate/validate_sigma.ps1) | Thin wrapper that feeds the rule list to the Python validator in one process | dev workflow |
| [`scripts/validate/validate_sigma.py`](../../scripts/validate/validate_sigma.py) | Validates each Sigma rule against the JSON Schema | the wrapper above |
| [`scripts/validate/check_test_routing.py`](../../scripts/validate/check_test_routing.py) | Warns when a rule's test runner has no job that services it, and tells the workflow which test jobs a batch needs | dev workflow (twice), pytest |
| [`scripts/validate/check_mitre_tags.py`](../../scripts/validate/check_mitre_tags.py) | Checks every rule's ATT&CK tags against the committed technique map — offline, advisory in CI | dev workflow, pytest |
| [`scripts/convert/sigma_to_spl.py`](../../scripts/convert/sigma_to_spl.py) | Sigma YAML → `.spl` query + `.meta.json` sidecar | dev + prod workflows |
| [`scripts/convert/backend_config.py`](../../scripts/convert/backend_config.py) | Loads `config/backends.yml` — which backend the converter targets and which pipeline each rule gets | `sigma_to_spl.py`, pytest |
| [`scripts/deploy/deploy_spl_to_splunk.py`](../../scripts/deploy/deploy_spl_to_splunk.py) | Creates/updates the Splunk saved searches | dev + prod workflows |
| [`scripts/atomic/run_atomic.ps1`](../../scripts/atomic/run_atomic.ps1) | Executes the attack that is supposed to trigger each rule | dev workflow, 3 jobs |
| [`scripts/verify/check_saved_search_hits.py`](../../scripts/verify/check_saved_search_hits.py) | Asks Splunk how many events each deployed search matched | dev workflow |
| [`scripts/verify/wait_for_indexing.py`](../../scripts/verify/wait_for_indexing.py) | Polls Splunk until the test window's events are indexed, instead of sleeping a fixed minute | dev workflow |
| [`scripts/verify/pass_fail_eval.py`](../../scripts/verify/pass_fail_eval.py) | Turns those counts into a per-rule PASS / FAIL / NOT_VERIFIED verdict | dev workflow |
| [`scripts/docs/generate_stats.py`](../../scripts/docs/generate_stats.py) | Aggregates everything into `stats.json`, the README block and the rule browser | dev workflow + code checks |
| [`scripts/docs/assets/`](../../scripts/docs/assets/) | `page.template.html` + `page.css` + `page.js` — the rule browser's source, inlined into `docs/index.html` | `generate_stats.py` |
| **Shared and state** | | |
| [`scripts/lib/rule_naming.py`](../../scripts/lib/rule_naming.py) | The one function deciding a rule's Splunk object name | deploy, verify, reconcile |
| [`scripts/state/reconcile.py`](../../scripts/state/reconcile.py) | Compares the repo against live Splunk, and cleans up what no longer belongs | dev workflow (+ manual for removals) |
| [`scripts/state/prune_orphans.py`](../../scripts/state/prune_orphans.py) | Deletes repo-side artefacts of rules that no longer exist | dev workflow |
| [`scripts/state/select_unverified.py`](../../scripts/state/select_unverified.py) | Picks the rules whose verification is missing or stale, for a manual run | dev workflow (`workflow_dispatch`) |
| [`scripts/state/resolve_rule_selection.py`](../../scripts/state/resolve_rule_selection.py) | Turns a hand-typed list of detect_ids into rule paths, or fails loudly | dev workflow (`workflow_dispatch`) |
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
| `prepare_validate_convert` | `ubuntu-latest` | Works out which rules changed, prunes orphans, validates, checks test routing and ATT&CK tags, converts, commits the `.spl`, builds the *pipeline bundle* artefact the later jobs consume |
| `deploy_to_splunk` | self-hosted Linux | Deploys the bundle's SPL to the dev Splunk app |
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
- **The `paths:` trigger and the full-rebuild list are deliberately different shapes.** The trigger
  uses globs (`scripts/validate/**`, `scripts/convert/**`, `config/**`, …) because a hand-listed
  module goes stale the moment a second one appears — register item 3.7 added exactly that, and a
  `config/backends.yml` edit changes every rule's SPL while starting no run at all under the old
  single-file entry. The `rebuild_all_files` list inside the `Determine changed Sigma files` step
  stays an explicit list of seven paths (schema, `validate_sigma.py`, `validate_sigma.ps1`,
  `sigma_to_spl.py`, `rule_naming.py`, `backend_config.py`, `config/backends.yml`) because a false
  positive there re-deploys and re-attacks all 27 rules on the lab VMs.

### `ci_prod_workflow.yml` — production deploy

Four jobs, on `main`: `announce_lab_offline` (a conditional lab-offline notice), `deploy_to_prod`
(the actual deploy), and two appended after it — `update_dashboard` and `deploy_pages` — that fold
that run's own deploy report into the dashboard and republish it. Before the last two existed,
nothing updated `outputs/reports/deployment_inventory.json`'s `prod` section after a prod deploy
succeeded — the only writer of that section was `ci_prod_audit.yml`, a `workflow_dispatch`-only,
live-reconcile workflow that has to be triggered by hand — so the dashboard kept showing prod on its
previous rule version right after a deploy that had already succeeded, until someone remembered to
run that audit *and* a later `dev` push happened to regenerate `docs/index.html` as a side effect.

**`deploy_to_prod` no longer re-converts Sigma and diffs the result** (register item 3.2, stage C).
It downloads the `.meta.json` sidecars from the exact dev-workflow run recorded in
`rules/splunk/.bundle-provenance.json` — a pointer file `dev` commits alongside the `.spl` it
describes, naming the `spl-pipeline-bundle` artifact and the run that built it — then runs
`gh attestation verify` against every committed `.spl` file, pinned to
`--signer-workflow .../ci_dev_workflow.yml`: a Sigstore build-provenance check that the file about to
be deployed was actually produced by the dev workflow with a matching digest, not hand-edited or
converted outside it. A failure here stops the deploy exactly as hard as the old
`git diff --exit-code -- rules/splunk` drift gate did — this step replaced that gate, because it
proves provenance more strongly (a tampered, mismatched-signer, or mismatched-repo file is rejected)
and lets prod skip installing the whole Sigma conversion toolchain: `deploy_to_prod` now installs
only [`.github/requirements-deploy.txt`](../../.github/requirements-deploy.txt) (`requests` alone,
pinned separately), not the full `.github/requirements.txt` dev needs for conversion reproducibility.
The verification calls run with bounded parallelism (`max_parallel=8`) since each is a real network
round-trip plus a Sigstore signature check (~5s/file observed).

The deploy itself runs with `--report`, which writes the per-rule outcome — created / updated /
skipped (deprecated) / failed, with the rule version — to `outputs/deploy/prod_deploy_report.json`,
uploaded as an artifact (`prod-deploy-report-${{ github.run_id }}`, 90 days) and rendered into the
step summary. The upload runs under `always() && steps.deploy.outcome != 'skipped'`, because a
*failed* deploy is when the record matters most: it names which rules reached production before the
run stopped, which the exit code alone cannot say. The report carries repo-side facts only — no
Splunk URL, app name or account — since the artifact is downloadable from a public repository.

**`update_dashboard`** (`needs: [deploy_to_prod]`, `if: always() && needs.deploy_to_prod.result !=
'skipped'`, `ubuntu-latest`, `environment: dev`) downloads that same-run deploy report and folds it
into `outputs/reports/deployment_inventory.json`'s `prod` section via
`scripts/state/deployment_inventory.py --env prod --deploy-report ...` — deliberately no
`--reconcile`: it trusts the deploy that triggered it rather than duplicating `ci_prod_audit.yml`'s
live-Splunk reconcile, which stays `workflow_dispatch`-only for its own `LAB_ONLINE`-drift reasons
(see that workflow's own header comment). It then regenerates `docs/index.html`/`stats.json`
(`generate_stats.py`) and `docs/team-ops.html` (`.claude/generate_dashboard.py` — both are
regenerated fresh on disk every run and never committed, so skipping either would republish a stale
copy) and commits the report data to `dev` — checked out with `GH_PAT_DEV_PUSH`, retried up to 3
times against `origin/dev` on push conflict, the same shape `ci_prod_audit.yml`'s own
`record_inventory` job and `ci_dev_workflow.yml`'s `update_dashboard` job both use. The `always()`
plus the explicit `!= 'skipped'` check (rather than a bare `needs:`, which implies `success()`) is
deliberate for two reasons: it must still run when `deploy_to_prod` itself was skipped by
`LAB_ONLINE=false`, and it must still run on a *partial* deploy failure —
`deploy_spl_to_splunk.py` only returns non-zero at the very end if *any one* file failed, so a run
that deployed 26 of 27 rules still makes `deploy_to_prod` report `failure`, and that run's successes
are exactly what the dashboard most needs to pick up.

**`deploy_pages`** (`needs: [update_dashboard]`, `if: always() && needs.update_dashboard.result ==
'success'`) publishes the regenerated `docs/` to GitHub Pages from the same-run
`console-${{ github.run_id }}` artifact `update_dashboard` uploads. It shares the repo-wide `pages`
concurrency group with `ci_dev_workflow.yml`'s own `deploy_pages` and `ci_code_checks.yml`'s
`publish_console`, so all three queue rather than race to publish different snapshots — Pages now has
three publishers, not one; see [`pipeline_overview.md`](pipeline_overview.md).

`main` never attacks anything or verifies anything; it trusts what `dev` proved.

It also honours the `LAB_ONLINE` repository variable, because `deploy_to_prod` runs on the same
`de-lab` machine dev uses and would otherwise queue against an offline runner rather than fail.
`announce_lab_offline`, on `ubuntu-latest`, runs under the exactly complementary condition and is the
only job that reports anything on a lab-offline run: `deploy_to_prod` is skipped, which cascades —
`update_dashboard` skips too (its `!= 'skipped'` guard fails), and so does `deploy_pages` behind it.
See the `LAB_ONLINE` section in [`pipeline_overview.md`](pipeline_overview.md).

**`ci_prod_workflow.yml` still makes no commits to `main`** — only `update_dashboard`'s commit, which
lands on `dev`, not `main`. The `.spl` files `deploy_to_prod` deploys are exactly what `dev` already
committed and what the promotion PR carried; `main` itself is never pushed to by this workflow.

### `ci_code_checks.yml` — CI for the pipeline itself

Exists because the dev workflow only does real work when a *rule* changes, so the code running the
pipeline was never itself exercised. Six jobs, each a separate job rather than a step so one
linter's failure cannot mask another's:

| Job | Does |
|---|---|
| `static_analysis` | `ruff check .` and `pytest` on `ubuntu-latest` — no Splunk, no lab, no live attacks |
| `powershell_analysis` | Parses every `.ps1` with PowerShell's own parser, then runs PSScriptAnalyzer |
| `workflow_analysis` | Runs a pinned, checksum-verified `actionlint` over `.github/workflows/**` (self-hosted runner labels come from `.github/actionlint.yaml`), after asserting `shellcheck` is on PATH — actionlint delegates every `run:` block to it, so its silent absence would mean checking strictly less while still passing |
| `dependency_audit` | `pip-audit` over both pinned requirements files. Advisory by design: findings become a `::warning` and a step-summary report, while pip-audit failing to *run* still fails the job |
| `regenerate_console` | Re-runs `generate_stats.py` and commits if the output changed by more than its embedded timestamps |
| `publish_console` | Publishes the regenerated site, because Pages serves an uploaded artefact rather than the branch — a commit alone would update the repo but not the live page |

`regenerate_console` gates on `[static_analysis, powershell_analysis, workflow_analysis]` — not on
`dependency_audit`, which is advisory and must not hold up a republish.

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

**`--job-flags` reuses the same matrix to answer a second question** (register item 2.10): which of
the three test jobs does this batch actually need? The workflow used to work that out in bash, by
spawning *two* `python3 -c` one-liners per rule — 54 processes for 27 rules — to read two fields from
one file, each ending in `2>/dev/null || true`, so a rule whose YAML failed to parse silently became
an empty tester and dropped out of routing with nothing said.

Since the matrix already maps `(tester, runner)` to the job that services it, "does this job have
work?" is a lookup rather than a second parse. `JOB_OUTPUT_FLAGS` maps job name to the workflow
output the jobs gate on — the only part that cannot be derived, because it is the workflow's own
naming. Flag mode is deliberately quiet: the dedicated routing step earlier in the same job already
reported any findings, over a superset of these rules.

One behaviour change worth knowing: a rule requesting an unserviced runner used to set
`has_atomic_tests` and start the victim job, which then skipped it. Now no job is started for work
that does not exist.

### `scripts/validate/check_mitre_tags.py`

Answers the other question the schema cannot: **do this rule's ATT&CK tags mean anything?**

The schema *looks* like it validates them — there is a tactic enum and a
`^attack\.[Tt]\d{4}(\.\d{3})?$` technique pattern — but both sit in an `anyOf` whose last branch is
plain `{"type": "string"}`, so they are suggestions, not gates: `attack.t1059.999`,
`attack.t1O59.001` and `attack.defense_evasion` all validate today. Downstream is looser still —
`generate_stats.py`'s `extract_techniques()` turns anything matching `attack\.t\d+` into a badge and
a Navigator cell. A mistyped technique therefore does not vanish; it renders as *covered*.

What it flags as errors: unknown technique, revoked/withdrawn sub-technique, malformed tag, unknown
tactic, tactic mismatch. As warnings: a technique whose tactic the rule never declares, and a parent
technique listed redundantly alongside its own sub-technique.

Three properties worth knowing:

- **Zero network I/O.** It reads the technique map `generate_stats.py` already caches at
  `outputs/reports/mitre_technique_map.json` (committed, 7-day TTL) — a validator that fetches would
  go green for the wrong reason the day the fetch quietly fails. A missing or unusable cache is exit
  `2` (the checker's own failure), not "every rule is broken". A cache older than 30 days is noted
  and nothing more.
- **Revoked vs. mistyped is answered honestly, and only where it can be.** The cache drops revoked
  objects, so a withdrawn technique is absent exactly like a typo. Sub-technique numbering under a
  parent is dense, so an absent sub *inside* the parent's allocated range was allocated once and
  withdrawn; one *above* it never existed. Main technique IDs are sparse, so for those the script
  makes no such claim.
- **The tactic vocabulary is derived from the cache, not from upstream ATT&CK.** This repo's map
  uses `Stealth` and `Defense Impairment` where upstream has Defense Evasion; a hardcoded upstream
  list would have reported a third of the library as wrong on the first run. `attack.stealth` is
  valid here for that reason, not as a carve-out.

Run over **every** rule, not just the changed ones, because what invalidates a tag is usually
upstream (a technique revoked, the cache refreshed) rather than this push. In CI it is deliberately
advisory — invoked without `--strict` from the `Check MITRE ATT&CK tags against the technique map`
step, so findings arrive as annotations and a step-summary table while the exit code stays `0`. A
wrong tag misfiles a working detection on the matrix; it does not break it, and the rule is worth
deploying while the tag is argued about.

Exit codes: `0` clean or advisory, `1` error-severity findings under `--strict`, `2` the checker
could not run. `--json` writes the full findings, `--quiet` drops the per-rule OK lines, `--cache`
points at a different map.

### `scripts/convert/sigma_to_spl.py`

**In:** Sigma YAML. **Out:** `rules/splunk/<same stem>.spl` plus a `<same stem>.meta.json` sidecar.

The backend and the pipeline routing are **not** in this file any more — they are loaded from
`config/backends.yml` through `backend_config.py` (see below). The precedence is unchanged: a rule
naming its own pipeline under the backend's override key (`custom.splunk_pipeline` for Splunk) wins,
otherwise `logsource.service` is looked up in the backend's routing (`sysmon` →
`splunk_sysmon_acceleration`, `security` → `splunk_windows`), and anything unmapped gets the
backend's declared default — for Splunk deliberately empty, i.e. `--without-pipeline`. A rule that
sets `custom.splunk.raw_query` bypasses conversion entirely and is emitted verbatim — the escape
hatch for detections too sophisticated to express as a Sigma `detection:` block.

`--backend` selects a backend by name; `--backends-config` points at a different config file. Both
workflows invoke the converter with neither, so both use `config/backends.yml`'s `default_backend`.
The config is loaded **before the conversion loop**, and a problem with it exits `2` before the
first file is written: a half-converted `rules/splunk/` is exactly what a promotion-PR reviewer
would see diffed against `main`, and exactly what `deploy_to_prod`'s build-provenance attestation
would end up vouching for if it slipped through.

The **sidecar is the important output**: it carries `detect_id`, title, description, deploy mode,
cron, severity, status and the testing block forward to the deploy and the runners, and it is
gitignored — it exists only during a run. Prod no longer re-converts to obtain its own copy
(register item 3.2, stage C): `deploy_to_prod` downloads the sidecar the dev run already produced
from the attested `spl-pipeline-bundle` artifact instead — see `ci_prod_workflow.yml`'s own entry
below.

### `scripts/convert/backend_config.py`

The loader for [`config/backends.yml`](../../config/backends.yml) (register item 3.7). It returns a
frozen `BackendConfig` — the `sigma convert -t <target>` target, the per-rule pipeline override key,
the `logsource.service` → pipeline map and the default for everything unmapped — and raises
`BackendConfigError` for anything it cannot resolve.

**Nothing falls back to a built-in default**, and that is the design rather than an omission. A
converter that shrugs off a missing or misspelled config and converts with some remembered setting
emits SPL that looks fine, gets committed, reviewed and merged by a human who has no way to see the
misconfiguration in a diff of query text, then reaches prod exactly as-is — `deploy_to_prod`'s
build-provenance attestation only proves *dev built this file*, not that dev's config was right, so
it would happily vouch for a wrongly-routed rule and deploy it before anyone can say which pipeline
actually produced it. Unknown keys are rejected for the same reason: `by_services:` instead of
`by_service:` is valid YAML and would
route every rule to the default pipeline, silently.

The config path resolves against `__file__`, not the working directory, so "which config did it
read" does not depend on where the shell happened to be. Adding a second backend is a new block in
the YAML — the tests introduce an `elastic`/`esql` backend purely from config, with no code change.

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

**Create-vs-update is decided by status code, never by error text.** The deploy POSTs to the
*object* endpoint first: `200` means the saved search was there and is now updated, `404` means it
does not exist yet and gets created on the collection endpoint. Anything else — including a `500`
whose body happens to say "already exists" — is a real error, reported with the status and what was
expected, rather than guessed past.

That is the point of the design. It previously created first and then matched Splunk's error *prose*
(`already exists` / `conflict` / `in use`) to detect the conflict: wording that is not part of any
contract, varies by version, and that unrelated failures can contain. A rephrased conflict was
reported as a create failure; an unrelated error carrying one of those words was sent down the
update path to fail again, more confusingly. As a side effect the common case — a rule that has been
deployed before — is now one call instead of two.

A create still gets a follow-up POST to the object endpoint, because Splunk does not reliably persist
`is_scheduled`/`cron_schedule` on the same request that creates the object. The update path needs no
such follow-up: it already *is* that request.

**It states which TLS mode it is running in** (register item 2.14). `env_bool("SPLUNK_VERIFY_TLS",
default=True)` had always chosen the safe answer for an unset value; what was missing was the
sentence, so a run that skipped certificate verification looked exactly like one that did not. It
now prints `TLS certificate verification: on.` when verification is on and a `::warning` annotation
when it is off. The same four lines appear verbatim in `check_saved_search_hits.py`,
`wait_for_indexing.py` and `reconcile.py` — the four Splunk clients, each with its own copy of
`env_bool` (register item 3.6). Turning verification off for a self-signed lab certificate is still
possible; it just has to be said out loud by setting the secret to `false`, because the workflows'
`|| 'false'` fallback — which turned a *missing* secret into a positive instruction to skip
verification — is gone from all five call sites.

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

The reporting layer. It used to be ~6000 lines, 4709 of them a single `_PAGE_TEMPLATE` string
literal holding the rule browser's HTML, CSS and ~2800 lines of JavaScript — which meant no tool
looked at the front end at all: `ruff` lints the Python around the literal and sees the literal
itself as one opaque token, so a JS typo was found by the user rather than by CI. Phase 1 of
[register item 3.4](../../audit/remediation-plan.md) moved the page out to
`scripts/docs/assets/page.template.html`, `page.css` and `page.js`, leaving the generator at 1425
lines. Phase 2 (folding 16 of the 20 `@@MARKER@@` placeholders into one JSON block) is deliberately
still open, because it necessarily changes the generated HTML and so cannot be proven by
byte-identity the way phase 1 was.

**Reads** every Sigma rule, the `.spl` count, every `result.json`, and the three page assets.
**Writes**
`outputs/reports/stats.json` (which the README badges read), `mitre_technique_map.json`,
`navigator_layer.json` (a portable ATT&CK Navigator layer), the stats block inside `README.md`, and
the whole of `docs/index.html`.

It is also where a verdict's *standing* is derived: it recomputes each rule's current version from
git history, compares it to the version recorded in the result file, and checks the result's age
against the 180-day review interval — so the published pass rate only counts measurements still
valid for the rule as it stands today. Because the expiry depends on when the page is opened, the
browser recomputes it client-side too; `stats.json` is the build-time snapshot.

`mitre_technique_map.json` is not only an output: `check_mitre_tags.py` reads it back as its offline
source of truth about which techniques exist, which is the one place the reporting layer feeds the
validation layer.

### `scripts/docs/assets/page.template.html`, `page.css`, `page.js`

The rule browser's markup, styling and behaviour, split out of `generate_stats.py` by register item
3.4 phase 1. They are **not** servable on their own: they still carry the `@@MARKER@@` placeholders
`render_html_summary()` substitutes, and `load_page_template()` inlines the stylesheet and the
script into the markup (`@@INLINE_CSS@@` / `@@INLINE_JS@@`, each alone on its line, newline
included) so the published page stays one self-contained file.

They are read verbatim — no escaping, no interpolation — exactly as the old `r"""…"""` literal held
them, so a backslash in a JS regex is still a backslash. Line endings are normalised on read, so a
CRLF checkout renders the same bytes as an LF one. The path resolves against `__file__` rather than
the working directory, because the workflows invoke the script by path. A missing asset is
`SystemExit` naming the file: assembling half a page and writing it would be worse than not writing
one.

The extraction was done from the original module's runtime `_PAGE_TEMPLATE` value rather than by
cutting text out of the source, and the resulting `docs/index.html` is byte-identical (with the
clock frozen — the generator stamps `datetime.now()` and the HEAD sha into the page, so a naive
diff shows the same three lines for an unmodified generator too).

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

### `scripts/state/select_unverified.py`

Answers "which rules still need a lab run?" for a manual `workflow_dispatch`, which has no
before/after to diff.

The baseline it uses already exists in the repo: each committed
`outputs/results/<detect_id>/result.json` records the `rule_version` it was measured against, and a
rule's version is its commit count (`git log --follow` on the Sigma source, the same scheme
`sigma_to_spl.py` and `generate_stats.py` use). A rule therefore needs a run when it has no result
at all, or when its result belongs to an older version of itself — the same "drift" the rule browser
already displays, made into something you can *start* a run from.

Deprecated rules are skipped, because they are not deployed and measuring them would measure nothing.
A FAIL still counts as verified at that version: this selects work, it does not re-litigate verdicts.

**Biases towards selecting.** If the current version cannot be established — no git history, a
shallow clone, an unreadable rule — the rule is included. A needless re-run costs lab time; a wrong
skip leaves a rule everyone believes was verified and was not.

stdout carries the selected rule paths and nothing else, so the workflow reads it straight into an
array; everything explanatory goes to stderr. `--json` writes the full per-rule reasoning.

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
| [`tests/test_pass_fail_gate.py`](../../tests/test_pass_fail_gate.py) | The progress-marker gate that runs before scoring: that it now covers emulation as well as atomic, and the cases where it must *not* fire |
| [`tests/test_reconcile.py`](../../tests/test_reconcile.py) | Bucket classification, and the write path: that a rename orphan is not deleted when its replacement is not live, that removals are disabled rather than deleted, that the CI marker survives, that unmanaged objects are never written to |
| [`tests/test_prune_orphans.py`](../../tests/test_prune_orphans.py) | Which artefacts count as orphaned, the fail-safes, idempotency |
| [`tests/test_deploy_deprecated.py`](../../tests/test_deploy_deprecated.py) | That a deprecated rule generates *zero* HTTP calls, and that everything else still deploys |
| [`tests/test_deploy_report.py`](../../tests/test_deploy_report.py) | What the deploy writes down: every outcome including skips and failures, and that no connection detail reaches the artifact |
| [`tests/test_deploy_upsert.py`](../../tests/test_deploy_upsert.py) | That create-vs-update comes from the status code: none of the old magic phrases steer anything, and an unexpected response fails instead of falling through to create |
| [`tests/test_wait_for_indexing.py`](../../tests/test_wait_for_indexing.py) | When the wait stops: on the first indexed event, at the timeout, and that a failed probe means "keep waiting" rather than "go ahead" |
| [`tests/test_sigma_to_spl.py`](../../tests/test_sigma_to_spl.py) | Index-prefix injection, including that a query opening with a generating command is left alone rather than turned into invalid SPL |
| [`tests/test_backend_config.py`](../../tests/test_backend_config.py) | That the backend really is data: a second backend (`elastic`/`esql`) is introduced from config alone, and that nothing falls back — a missing file, an unknown backend name, a misspelled key all raise rather than convert with a remembered default |
| [`tests/test_check_mitre_tags.py`](../../tests/test_check_mitre_tags.py) | The tag findings and their severities, and — asserted against the script's own source — that it performs no network call, so the day someone adds a fallback fetch is the day this fails rather than the day the check starts going green for the wrong reason |
| [`tests/test_tls_verification.py`](../../tests/test_tls_verification.py) | Both halves of register item 2.14: a workflow guard requiring the `||`-free form at all five call sites (and failing if it does not find exactly five), and that all four `env_bool` consumers fail closed on empty, missing and unrecognisable values |
| [`tests/test_check_test_routing.py`](../../tests/test_check_test_routing.py) | That the serviced matrix is derived from the workflow rather than hardcoded, and — against the real repo — that every committed rule still has a job that can run its test |
| [`tests/test_select_unverified.py`](../../tests/test_select_unverified.py) | Which rules a manual run picks up, including that an unknown version selects rather than skips, and — in a real temp git repo — that editing a rule makes it selectable again |
| [`tests/test_resolve_rule_selection.py`](../../tests/test_resolve_rule_selection.py) | Mostly the failure path: that an unknown id stops the run, lists the valid ones, and never lets a partial selection through |

---

## Supporting configuration

Not scripts, but they decide how the scripts behave.

| File | Role |
|---|---|
| [`docs/schemas/sigma_schema.json`](../../docs/schemas/sigma_schema.json) | The contract every rule must satisfy. Conditionally requires the right testing block for the declared test type (only for `enabled: true` rules, so a parked rule need not maintain a test list). Note its `tags` pattern is *not* a gate — it sits beside a free-text `anyOf` branch, which is why `check_mitre_tags.py` exists |
| [`config/backends.yml`](../../config/backends.yml) | Which pySigma backend the converter targets and which pipeline each `logsource.service` gets — the values that used to be constants in `sigma_to_spl.py`, moved character for character. Editing it changes every rule's SPL, which is why it is in the dev workflow's `paths:` trigger, in the full-rebuild list, and — since the test that guards it lives in `tests/test_backend_config.py` — in `ci_code_checks.yml`'s `paths:` as well |
| [`.github/actionlint.yaml`](../../.github/actionlint.yaml) | Declares the self-hosted runner labels to `actionlint`; without it every `runs-on:` in the dev and prod workflows reports as an unknown label |
| [`.github/requirements.txt`](../../.github/requirements.txt) | Pinned pipeline toolchain, installed by both dev and prod. `pySigma` is pinned separately from `sigma-cli` because it is what actually serialises the query |
| [`.github/dependabot.yml`](../../.github/dependabot.yml) | Weekly bumps for the pinned Python toolchain and the SHA-pinned actions. Targets `dev`, not the default branch — a bump landing on `main` would deploy to production without ever being validated, attacked or measured |
| [`.github/requirements-dev.txt`](../../.github/requirements-dev.txt) | Pinned `pytest` and `ruff`, for the code-checks workflow only |
| [`pyproject.toml`](../../pyproject.toml) | ruff and pytest config. ruff's selection is curated rather than "everything" — `F, E9, E7, B, I, UP, C4, SIM, RET, PIE, RUF`, with `E501`, `ARG` and `PTH` deliberately left out and each omission justified against measured findings in the file's own comment |
| [`.github/PSScriptAnalyzerSettings.psd1`](../../.github/PSScriptAnalyzerSettings.psd1) | PowerShell lint rules, with three exclusions and the reasoning for each in the file |

`.vscode/settings.json` and `.claude/settings.json` are local editor and agent configuration; they
have no effect on CI.

## What is *not* a script

- [`docs/index.html`](../../docs/index.html) — generated output, never edited by hand. Its source is
  `scripts/docs/assets/page.template.html` + `page.css` + `page.js`, assembled and filled in by
  `generate_stats.py`. (It used to be a string literal *inside* that script; it no longer is.)
- [`rules/splunk/*.spl`](../../rules/splunk/) — generated from Sigma, committed so that prod
  deploys exactly what was reviewed.
- [`outputs/`](../../outputs/) — verification results and reports, written by the pipeline.
- [`audit/`](../../audit/) — the standing remediation plan and its published register.
