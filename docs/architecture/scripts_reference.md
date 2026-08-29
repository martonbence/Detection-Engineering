# Scripts Reference

Every executable file in this repo, what it is for, and who runs it. This is the "what does
this file do" lookup; [`pipeline_overview.md`](pipeline_overview.md) is the "how do they fit
together" narrative, [`data_flow.md`](data_flow.md) traces the artefacts they pass around,
[`threat_model.md`](threat_model.md) covers scope and credential handling, and
[`agent_workflow.md`](agent_workflow.md) documents the AI-agent team that maintains all of it.

Nothing here is run by hand in the happy path — the CI workflows invoke everything. The manual
entry points (`scripts/new_rule.py` to scaffold a rule, the one-off migration scripts, the
`workflow_dispatch`-only selection paths, and `ci_prod_audit.yml`) are called out explicitly where
they exist.

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
| [`.github/workflows/ci_prod_audit.yml`](../../.github/workflows/ci_prod_audit.yml) | Live reconcile of the prod Splunk app against `main` + records what prod was last deployed from into `deployment_inventory.json` — 2 jobs: `audit_prod`, `record_inventory` | `workflow_dispatch` only, never automatic |
| [`.github/workflows/ci_code_checks.yml`](../../.github/workflows/ci_code_checks.yml) | CI for the pipeline's *own* code: ruff, pytest, PowerShell analysis, actionlint, `pip-audit`, Console republish | push/PR touching `scripts/`, `tests/`, `config/`, `pyproject.toml`, the requirements files, `.github/workflows/**`, `.github/PSScriptAnalyzerSettings.psd1`, `.github/actionlint.yaml` |
| **Authoring** | | |
| [`scripts/new_rule.py`](../../scripts/new_rule.py) | Scaffolds a schema-valid new Sigma rule file with the next free `detect_id` filled in | manual, run by hand from any directory |
| **Pipeline stages** | | |
| [`scripts/validate/validate_sigma.ps1`](../../scripts/validate/validate_sigma.ps1) | Thin wrapper that feeds the rule list to the Python validator in one process | dev workflow |
| [`scripts/validate/validate_sigma.py`](../../scripts/validate/validate_sigma.py) | Validates each Sigma rule against the JSON Schema | the wrapper above |
| [`scripts/validate/check_test_routing.py`](../../scripts/validate/check_test_routing.py) | Warns when a rule's test runner has no job that services it, and tells the workflow which test jobs a batch needs | dev workflow (twice), pytest |
| [`scripts/validate/check_mitre_tags.py`](../../scripts/validate/check_mitre_tags.py) | Checks every rule's ATT&CK tags against the committed technique map — offline, advisory in CI | dev workflow, pytest |
| [`scripts/validate/check_detect_id_uniqueness.py`](../../scripts/validate/check_detect_id_uniqueness.py) | **Hard gate:** fails if two rule files share a `detect_id` (they would collide on one Splunk saved search) | dev workflow, pytest |
| [`scripts/validate/check_version_bump.py`](../../scripts/validate/check_version_bump.py) | **Hard gate:** that a rule's `version:` moved when its `detection:`/`logsource:`/`raw_query` did — the CI backstop for `.githooks/pre-commit` | dev workflow, pytest |
| [`.githooks/pre-commit`](../../.githooks/pre-commit) | Auto-bumps a rule's `version:` at commit time on a real logic change (not installed until `git config core.hooksPath .githooks` is run once per clone) | local `git commit`, opt-in |
| [`scripts/migrate_backfill_rule_version.py`](../../scripts/migrate_backfill_rule_version.py) | One-time backfill that recomputed every rule's `version:` from its real logic-change history; already run | manual, one-off |
| [`scripts/convert/sigma_to_spl.py`](../../scripts/convert/sigma_to_spl.py) | Sigma YAML → `.spl` query + `.meta.json` sidecar | dev + prod workflows |
| [`scripts/convert/backend_config.py`](../../scripts/convert/backend_config.py) | Loads `config/backends.yml` — which backend the converter targets and which pipeline each rule gets | `sigma_to_spl.py`, pytest |
| [`scripts/deploy/check_spl_syntax.py`](../../scripts/deploy/check_spl_syntax.py) | **Hard gate:** parses every SPL query against Splunk's own parser before the deploy writes it into a saved search | dev workflow, pytest |
| [`scripts/deploy/deploy_spl_to_splunk.py`](../../scripts/deploy/deploy_spl_to_splunk.py) | Creates/updates the Splunk saved searches | dev + prod workflows |
| [`scripts/atomic/run_atomic.ps1`](../../scripts/atomic/run_atomic.ps1) | Executes the attack that is supposed to trigger each rule | dev workflow, 3 jobs |
| [`scripts/verify/check_saved_search_hits.py`](../../scripts/verify/check_saved_search_hits.py) | Asks Splunk how many events each deployed search matched | dev workflow |
| [`scripts/verify/wait_for_indexing.py`](../../scripts/verify/wait_for_indexing.py) | Polls Splunk until the test window's events are indexed, instead of sleeping a fixed minute | dev workflow |
| [`scripts/verify/pass_fail_eval.py`](../../scripts/verify/pass_fail_eval.py) | Turns those counts into a per-rule PASS / FAIL / NOT_VERIFIED verdict | dev workflow |
| [`scripts/verify/anonymize_matched_events.py`](../../scripts/verify/anonymize_matched_events.py) | Pseudonymises lab hostnames/domain/accounts in the matched-events artifact before it is uploaded | dev workflow |
| [`scripts/verify/diff_matched_events.py`](../../scripts/verify/diff_matched_events.py) | Field-level outlier analysis of a rule's matched events — investigative, run by hand | manual, not in CI |
| [`scripts/docs/generate_stats.py`](../../scripts/docs/generate_stats.py) | Aggregates everything into `stats.json`, the README block and the rule browser | dev workflow + code checks |
| [`scripts/docs/assets/`](../../scripts/docs/assets/) | `page.template.html` + `page.css` + `page.js` — the rule browser's source, inlined into `docs/index.html` | `generate_stats.py` |
| **Shared and state** | | |
| [`scripts/lib/rule_naming.py`](../../scripts/lib/rule_naming.py) | The one function deciding a rule's Splunk object name | deploy, verify, reconcile |
| [`scripts/lib/rules.py`](../../scripts/lib/rules.py) | The one Sigma-rule discoverer/loader — recursive, both `.yml`/`.yaml`; each caller keeps its own failure policy | every script that reads the rule library |
| [`scripts/lib/env.py`](../../scripts/lib/env.py) | Shared env-var reading (`env_bool`, `env_required`) + the TLS-mode announcement, for the Splunk scripts | deploy, verify, reconcile, `check_spl_syntax.py` |
| [`scripts/lib/splunk_client.py`](../../scripts/lib/splunk_client.py) | Builds the `requests.Session` (TLS flag, basic auth, JSON header) every Splunk call uses | the 5 Splunk-facing scripts |
| [`scripts/lib/splunk_ns.py`](../../scripts/lib/splunk_ns.py) | Which `servicesNS/{owner}/{app}` namespace saved-search writes go through (`nobody` in the path, real account in the ACL) | deploy, reconcile |
| [`scripts/lib/meta_sidecar.py`](../../scripts/lib/meta_sidecar.py) | Finds and parses a rule's `<name>.meta.json` sidecar; each caller keeps its own except clause | deploy, verify |
| [`scripts/lib/verdict_history.py`](../../scripts/lib/verdict_history.py) | Read/write the append-only `history.jsonl` next to each `result.json` | `pass_fail_eval.py`, `generate_stats.py` |
| [`scripts/lib/summary.py`](../../scripts/lib/summary.py) | Shared vocabulary (outcome marks) for `$GITHUB_STEP_SUMMARY` output | the validators, deploy, verify |
| [`scripts/state/determine_changed_rules.py`](../../scripts/state/determine_changed_rules.py) | The scope-decision gate: which rules this run validates/converts/deploys/attacks/verifies | dev workflow (`prepare_validate_convert`), pytest |
| [`scripts/state/build_pipeline_bundle.py`](../../scripts/state/build_pipeline_bundle.py) | Assembles the `spl-pipeline-bundle` artefact the later jobs consume | dev workflow (`prepare_validate_convert`), pytest |
| [`scripts/state/merge_verification_results.py`](../../scripts/state/merge_verification_results.py) | Resets to `origin/dev`, merges this run's verification delta, regenerates stats and commits (the one write-back) | dev workflow (`update_dashboard`), pytest |
| [`scripts/state/reconcile_step.py`](../../scripts/state/reconcile_step.py) | Assembles `reconcile.py`'s CLI args and runs it, mirroring the old inline shell | dev workflow (`splunk_verify`), pytest |
| [`scripts/state/open_promotion_pr.py`](../../scripts/state/open_promotion_pr.py) | Opens (or short-circuits) the `dev` → `main` promotion PR and adds it to Project #3 | dev workflow (`open_promotion_pr`), pytest |
| [`scripts/state/deployment_inventory.py`](../../scripts/state/deployment_inventory.py) | Folds a deploy/reconcile report into the committed `deployment_inventory.json` digest the dashboard reads | via `merge_verification_results.py` (dev); prod + prod-audit workflows |
| [`scripts/state/reconcile.py`](../../scripts/state/reconcile.py) | Compares the repo against live Splunk, and cleans up what no longer belongs | dev workflow (+ manual for removals) |
| [`scripts/state/prune_orphans.py`](../../scripts/state/prune_orphans.py) | Deletes repo-side artefacts of rules that no longer exist | dev workflow |
| [`scripts/state/select_unverified.py`](../../scripts/state/select_unverified.py) | Picks the rules whose verification is missing or stale, for a manual run | dev workflow (`workflow_dispatch`) |
| [`scripts/state/resolve_rule_selection.py`](../../scripts/state/resolve_rule_selection.py) | Turns a hand-typed list of detect_ids into rule paths, or fails loudly | dev workflow (`workflow_dispatch`) |
| **Tests** | | |
| [`tests/`](../../tests/) | pytest suite over the Python scripts, with Splunk faked | `ci_code_checks.yml` |

---

## Workflows

### `ci_dev_workflow.yml` — the pipeline

The main event. Eleven jobs; the interesting property is that the middle ones run on **self-hosted
runners** because they need the lab: a Linux runner that can reach Splunk, and Windows machines
that get genuinely attacked. [`pipeline_overview.md`](pipeline_overview.md#named-workflow-jobs-and-steps)
has the per-step breakdown; this is the one-line-per-job summary.

| Job | Runner | Does |
|---|---|---|
| `prepare_validate_convert` | `ubuntu-latest` | Works out which rules changed, prunes orphans, validates, checks test routing / ATT&CK tags / `detect_id` uniqueness / version-bump discipline, converts, attests and commits the `.spl`, builds the *pipeline bundle* artefact the later jobs consume |
| `deploy_to_splunk` | self-hosted Linux | Parses each SPL against Splunk (`check_spl_syntax.py`), then deploys the bundle's SPL to the dev Splunk app |
| `atomic_verify` | self-hosted Windows (victim) | Runs the Atomic Red Team tests |
| `atomic_verify_dc` | self-hosted Windows (DC) | Same, for rules that must be attacked on a domain controller |
| `emulation_verify` | self-hosted Windows (victim) | Runs `emulation`-type rules' own commands; shares the victim host with `atomic_verify`, so these run in sequence |
| `splunk_verify` | self-hosted Linux | Queries Splunk, evaluates verdicts, reconciles state, and *stages* this run's results as an artifact (it no longer commits or regenerates stats itself) |
| `update_dashboard` | `ubuntu-latest` | Downloads that artifact, merges it, regenerates `stats.json` / `docs/index.html` / `team-ops.html`, and makes the one write-back commit to `dev`. `always()` — runs even when the lab was off, so a new rule still reaches the dashboard as "Not Verified" |
| `persist_results_fallback` | `ubuntu-latest` | Zero steps on a normal run. Only if `update_dashboard` failed/was cancelled: commits the raw `outputs/results/` from the artifact so the evidence is not lost |
| `open_promotion_pr` | `ubuntu-latest` | On an overall PASS (`splunk_verify` result `success`), opens the `dev` → `main` promotion PR |
| `notify_pipeline_status` | `ubuntu-latest` | Posts the run verdict + library counts to Slack |
| `deploy_pages` | `ubuntu-latest` | Publishes the rule browser to GitHub Pages from `update_dashboard`'s console artifact |

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

Pages therefore has **three** publishers: this workflow's `publish_console`, the dev pipeline's
`deploy_pages`, and `ci_prod_workflow.yml`'s own `deploy_pages`. All three declare the repo-wide
`pages` concurrency group with `cancel-in-progress: false`, so the deployments queue instead of
racing to publish different snapshots.

### `ci_prod_audit.yml` — live prod reconcile (manual)

`workflow_dispatch` only — never runs on a push. It is the one workflow that reconciles the **prod**
Splunk app against `main` live, and it stays manual for the `LAB_ONLINE`-drift reason its own header
comment gives (`deploy_to_prod` runs on the same `de-lab` runner; a scheduled audit would queue
against an offline runner). Two jobs:

| Job | Runner | Does |
|---|---|---|
| `audit_prod` | `self-hosted, linux, de-lab` | Checks out `main`, runs `reconcile.py` against the prod app, records what prod was last deployed from, warns on drift, uploads the reconcile report |
| `record_inventory` | `ubuntu-latest` | Checks out `dev`, downloads that report plus the last prod deploy report, and folds both into `outputs/reports/deployment_inventory.json`'s `prod` section via `deployment_inventory.py`, committing to `dev` |

Until `ci_prod_workflow.yml` grew its own `update_dashboard` job, this was the *only* writer of the
inventory's `prod` section — see that workflow's entry above.

---

## Authoring

### `scripts/new_rule.py`

Register item 4.5 (scaffolder half). The starting point for every new detection: run by hand from
any directory, it writes a new `rules/sigma/<detect_id>_<slug>.yml` with the next free `detect_id`
already filled in (the id space has gaps — `0001`, `0002`, `0004`, `0017` are missing from deleted
or renamed rules — so "next free" is computed from the current checkout, not `max + 1`).

The generated file is schema-valid unedited, so `validate_sigma.py` passes on it immediately — but
it is *not* meant to stay unedited: the placeholder `attack.TODO` / `attack.t0000` tags are
deliberately ones `check_mitre_tags.py` flags as unknown, as the visible nudge to replace them.

It only narrows `detect_id` collisions, it cannot prevent them: two branches off the same base
commit can both compute the same "next free" id. `check_detect_id_uniqueness.py` (below) is the
actual backstop, running on the merged tree.

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

### `scripts/validate/check_detect_id_uniqueness.py`

Register item 4.5 (collision-protection half; `new_rule.py` above is the scaffolder half). Answers
the one question `validate_sigma.py` structurally cannot: **is this `detect_id` used by any other
rule file?** The schema validates each file in isolation and has no way to see a sibling.

A collision is not cosmetic. `rule_naming.saved_search_name()` builds the Splunk object name from
`detect_id` + `slug(title)`, so two rules sharing a `detect_id` collide on the same saved search:
the deploy would have the second silently overwrite the first's Splunk object, and `reconcile.py` /
`generate_stats.py` would key verdicts and coverage onto whichever rule loaded last.

**A hard gate**, no `--strict` — unlike `check_mitre_tags.py` beside it, a duplicate `detect_id` is
unambiguous and always wrong, so it fails outright, the same contract as `validate_sigma.py`. Runs
over every rule (not just the changed ones) in `prepare_validate_convert`'s `Check detect_id
uniqueness` step, and again as a hard failure in pytest. Exit codes: `0` all unique, `1` a
`detect_id` is used twice, `2` checker setup failure.

### `scripts/validate/check_version_bump.py`

Answers a third question the schema cannot: **does this rule's hand-maintained `version:` field
actually reflect what changed?** Register item 3.5, closed — this is now the sole mechanism
deciding whether a rule's Sigma `version:` field means anything, and every downstream reader of
`rule_version` (`sigma_to_spl.py`'s sidecar, `generate_stats.py`'s superseded-verdict check, the
Splunk saved-search description) ultimately trusts what this file — and `.githooks/pre-commit`,
which reuses it — decided.

For every changed rule file in the push, it loads the rule as staged and the same path at the diff's
base ref, and calls `logic_diff()` to see whether `detection:`, `logsource:`, or
`custom.splunk.raw_query` differ between the two. Only those three fields count as a behaviour
change; `description`, `references`, `falsepositives`, `status`, `level`, tags and everything under
`custom.testing`/`custom.splunk` other than `raw_query` do not — rewording a description should
never force a version bump, which was the exact complaint that opened this register item. If any of
the three changed and `version:` did not move between the two revisions, the rule is a finding; a new
file or a base ref that can't be read is skipped rather than failed, since there is no prior version
to compare against.

Severity: a **hard gate**, unlike the two advisory checks above it — whether a version moved between
two git blobs is not a judgment call the way an ATT&CK tag or a test-routing gap is, so there is no
`--strict` toggle and no reason to let a finding through as a warning.

**As of `.githooks/pre-commit` (below), this check should rarely have anything to report.** The hook
runs the identical `logic_diff()`/`version_of()` logic at commit time and bumps `version:`
automatically before the commit is even made, so a finding here now more likely means the hook
never ran — `--no-verify`, a fresh clone before the one-time `git config core.hooksPath .githooks`
step, or a rule edited through the GitHub web UI, none of which invoke a local hook — than an author
who forgot to type a version by hand.

Exit codes: `0` every logic-changing edit bumped its version (or nothing needed one, or no rule files
were given), `1` a rule changed logic without bumping `version:`, `2` setup failure (missing
`pyyaml`).

### `.githooks/pre-commit`

The other half of register item 3.5. Not installed by default — `git config core.hooksPath
.githooks` is a one-time, per-clone step, deliberately not run automatically by any script here (a
hook that installs itself is a hook that can start running code nobody asked for). Once set, git
runs this on every commit that stages a `rules/sigma/**/*.yml`/`*.yaml` file.

For each such file it imports `check_version_bump.py`'s own `logic_diff()`/`version_of()` — not a
reimplementation, so the hook and the CI backstop can never quietly define "logic changed"
differently — and compares the staged copy against HEAD's. If `detection:`/`logsource:`/
`custom.splunk.raw_query` changed and the author did not already bump `version:` by hand, it parses
the current `MAJOR.MINOR` value (schema-enforced pattern), increments MINOR by one (treating a
missing/unparseable value as `1.0` first), rewrites the staged file in place, and `git add`s it back
so the bump rides along in the commit being made rather than a follow-up one. A version the author
already changed by hand — e.g. jumping straight to `2.0` for a rewrite — is left alone.

It never fails or blocks the commit — this is a rewrite, not a gate; gating stays
`check_version_bump.py`'s job in CI — and every exception it can hit (missing PyYAML, a git plumbing
failure, an unparseable rule) is caught and logged to stderr as "skip this file," never a non-zero
exit. It also refuses to touch a file whose worktree content doesn't match what's actually staged,
trading a rare missed auto-bump for never silently discarding an edit the author hadn't staged yet.

No test file currently exercises this hook or `scripts/migrate_backfill_rule_version.py` below — a
known, non-blocking gap noted in review at the time 3.5 closed; `check_version_bump.py`, whose logic
both reuse, is covered by `tests/test_check_version_bump.py`.

### `scripts/migrate_backfill_rule_version.py`

A one-time migration, already run with `--apply`. Recomputes every existing rule's `version:` field
from a real replay of that rule's logic-change history — walking its actual commit history and
re-running `logic_diff()` between consecutive revisions, bumping only on a genuine
`detection:`/`logsource:`/`custom.splunk.raw_query` change — rather than the raw commit count the
now-deleted `scripts/lib/rule_version.py::compute_rule_version()` used to produce. Default mode
reports what it would write; `--apply` writes it. Run once against the existing 28 rules, it changed
27 of their version numbers. Not invoked by any workflow — it exists for this one migration and for
re-running by hand if a similar backfill is ever needed again.

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

`meta["rule_version"]` is popped straight from the Sigma YAML's own `version:` field (register item
3.5, closed) — no computation, `build_meta_dict()` just reads it. See
`scripts/validate/check_version_bump.py`'s entry above for what keeps that field meaningful, and
[`data_flow.md`](data_flow.md#rule_version-the-one-field-that-travels-the-whole-chain) for everywhere
this value travels afterward (the deploy step's Splunk saved-search description, the verify sidecar,
the committed result, and `generate_stats.py`'s superseded-verdict check).

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

### `scripts/deploy/check_spl_syntax.py`

Register item 4.2. Splunk's `saved/searches` endpoint does not parse the search string at save time,
so a syntax error becomes a live saved search that has never been checked — the error only surfaces
later, when the search runs. `custom.splunk.raw_query` rules are the sharpest case: they bypass the
Sigma→SPL converter entirely, so nothing else in the pipeline has ever looked at their query text.

This step runs `deploy_to_splunk`'s `Validate SPL syntax against Splunk before deploying`, immediately
before `deploy_spl_to_splunk.py` and scoped to the **same** files (this run's, not the whole repo).
It POSTs each query to Splunk's `services/search/v2/parser` with `parse_only=true` — which parses and
returns a semantic map without dispatching a job or expanding subsearches/lookups/macros, so it
checks **syntax only**, deliberately (those expansions depend on objects that may not exist in every
environment). Unlike the local network-free validators, it costs one real Splunk API call per rule,
which is why it is scoped like the deploy it gates.

**A hard gate.** Exit codes: `0` every query parsed, `1` a query failed to parse (the deploy does
not run), `2` checker setup failure (env, auth, or Splunk unreachable — not a property of any one
rule).

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

### `scripts/verify/wait_for_indexing.py`

Runs as `splunk_verify`'s `Wait for Splunk indexing` step, immediately before
`check_saved_search_hits.py`. Polls Splunk until an event at or after the verification window's start
appears in the indexes under test (up to 180s), then warns and continues rather than failing. It
replaces a fixed `sleep`: a fixed wait is either too short (working rules fail because their
telemetry has not landed) or wastefully long. Setup failure — bad env, auth, Splunk unreachable — is
exit `2`, distinct from "indexing is just slow".

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
it is what gates the promotion PR. `pass_fail_eval.py` also appends one line per rule to that rule's
`history.jsonl` via `scripts/lib/verdict_history.py` — the append-only record `result.json` (which
every run overwrites) deliberately does not keep.

### `scripts/verify/anonymize_matched_events.py`

Register item 3.10. The matched-events artifact is publicly downloadable (this is a public repo).
Shorter retention was already chosen over stripping fields — the raw event *is* the debugging value
— but the lab's naming (hostnames, domain, service accounts) still leaked, and that has
reconnaissance value to the extent the lab mirrors production. This step, `splunk_verify`'s
`Anonymize matched events before upload`, runs between the verify step and the upload step and
rewrites those identifiers to stable per-entity pseudonyms: the artifact keeps every property a
debugger needs (which events came from the same box / account / domain) and loses what the box is
actually called. The identifiers are **discovered from the events**, never read from a config file —
a config file would itself commit the lab's naming to the public repo.

### `scripts/verify/diff_matched_events.py`

Register item 3.11. **Not wired into any CI job** — an investigative tool for after a verdict looks
wrong (an unexpected FAIL/count, a rule oscillating between runs in `history.jsonl`). It reads a
`hits.json` written by `check_saved_search_hits.py` and answers "which field(s) does this matched
event set split along?" — i.e. when `event_count` came back as 11 instead of 10, which event was the
extra one and what distinguishes it. The `--max-pass` window itself is deliberately not tightened
(item 2.7); this is the tool for investigating a specific over-count instead.

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

### Shared libraries — `scripts/lib/`

Small modules that exist so several scripts stop each carrying their own copy. The recurring design
rule across all of them: the *mechanism* moves into `lib/`, the *failure policy* stays at each call
site — several of these consolidations (register items 3.1, 3.6, 3.9) found "duplication" that was
actually three or four callers deliberately handling the same error differently, and merging that
would have silently changed exit codes.

| Module | What it holds | Why it is shared, and what deliberately stayed with the caller |
|---|---|---|
| `rules.py` | `discover()` (recursive, `.yml`+`.yaml`) and `load_rule()` — Sigma rule discovery and loading | Item 3.1, rescoped. Six scripts each decided for themselves which files count as a rule, in **four** different ways (flat vs. recursive, `.yml` only vs. both). Harmless only because `rules/sigma/` is currently flat and all-`.yml` — on the day subdirectories land (item 3.8), `prune_orphans.py` and `reconcile.py` would have deleted every subdirectory rule's artefacts/objects. `discover()` is the widest of the four behaviours; each caller keeps its own `except` (drop silently / raise / warn-and-select). |
| `env.py` | `env_bool`, `env_required`, `MissingEnvVar`, and the "TLS verification: on/off" announcement | Item 3.6. Four Splunk scripts carried identical copies; item 2.14's TLS notice was pasted four more times. `env_required` stays wired per-caller via `env_reader()` because its exit code differs by script on purpose (1 / 2 / a `ReconcileError`). |
| `splunk_client.py` | `build_session()` — the `requests.Session` with TLS flag, basic auth, `Accept: application/json` | Item 3.6. Five scripts built it the same four lines; the fifth copy (`check_spl_syntax.py`) landed *after* the item was written, proving the point. Deliberately no retry/backoff — none of the five does that today. |
| `splunk_ns.py` | `NAMESPACE_OWNER = "nobody"` and the URL/ACL helpers — the namespace saved-search writes go through | Item 3.9. Writing through the service account's namespace created a shadow private copy of every rule. `nobody` in the path + the authenticating user in the ACL payload is the combination that avoids both the shadow copy and the 403. `nobody` belongs on `saved/searches` paths only, never `search/jobs`. |
| `meta_sidecar.py` | `meta_sidecar_path()` and `read_meta_sidecar()` | Item 3.6. Three callers located and parsed the `<name>.meta.json` sidecar identically; only that part moved. Each keeps its own except clause (`die` / empty dict / skip-this-file), which are load-bearing, not accidental. The PowerShell reader in `run_atomic.ps1` is not consolidated here — cross-language sharing is not what this addresses. |
| `verdict_history.py` | `append_entry()` / `read_history()` for the per-rule `history.jsonl` | Item 4.6. `result.json` is overwritten every run; this is the append-only companion. `pass_fail_eval.py` writes it, `generate_stats.py` reads it for the dashboard sparkline. Deliberately unbounded — a cap would delete the answer to "when did it start failing". |
| `summary.py` | The outcome marks (`MARK_PASS` 🟢, `MARK_FAIL` 🔴, `MARK_UNKNOWN`/`MARK_WARN` 🟡, `MARK_INFO` ⚪) | Five places write to `$GITHUB_STEP_SUMMARY` and the Actions page stacks them; one vocabulary keeps them consistent. The two bash writers in `ci_dev_workflow.yml` and `run_atomic.ps1` can't import it and carry literals with a pointer back here. |

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
`outputs/results/<detect_id>/result.json` records the `rule_version` it was measured against. A rule
therefore needs a run when it has no result at all, or when its result belongs to an older version of
itself — the same "drift" the rule browser already displays, made into something you can *start* a
run from.

`classify()` reads the rule's current version straight from the loaded rule dict —
`data.get("version")`, the same field and the same read pattern `generate_stats.py` uses — and
compares it against `result.json`'s `rule_version`. Both sides are now the single, unified version
number: the rule's hand-set Sigma YAML `version:` field, auto-bumped by `.githooks/pre-commit` on a
real `detection:`/`logsource:`/`custom.splunk.raw_query` change (register item 3.5, closed same day
as commit `cd40d34`). The script previously computed its own "current version" via a local
`git_version()` (a raw git-commit-count scheme, `1.<commit-count-1>`), which briefly diverged from
the newer YAML-field scheme after 3.5 landed and made `classify()`'s `verified != current` check
compare two unrelated numbering schemes — that bug is fixed as of commit `4bc4ea5`: `git_version()`
was deleted outright (no other caller depended on it) and `classify()` now reads `version:` directly,
matching `result.json`'s `rule_version` for real.

Deprecated rules are skipped, because they are not deployed and measuring them would measure nothing.
A FAIL still counts as verified at that version: this selects work, it does not re-litigate verdicts.

**Biases towards selecting.** If the current version cannot be established — no `version:` field, an
unreadable rule — the rule is included. A needless re-run costs lab time; a wrong skip leaves a rule
everyone believes was verified and was not.

stdout carries the selected rule paths and nothing else, so the workflow reads it straight into an
array; everything explanatory goes to stderr. `--json` writes the full per-rule reasoning.

### `scripts/state/resolve_rule_selection.py`

Backs the `workflow_dispatch` `rules` input — a comma/space-separated list of `detect_id`s, bare
filenames or paths, case-insensitively — and turns it into rule file paths. It parses no YAML: rule
files are named `<detect_id>_<slug>.yml`, so resolution is a glob. Mostly a failure path: one
unknown token fails the whole run and prints every valid id, because a partial selection would look
like the request was honoured. This is the safety a dropdown would have given, done as validation
instead (`workflow_dispatch` inputs are static YAML with no multi-select type).

### `scripts/state/determine_changed_rules.py`

Register item 4.1, slice 1. The dev pipeline's scope-decision gate — `prepare_validate_convert`'s
`Determine changed Sigma files` step, formerly 206 lines of inline bash. Given the event, the SHAs
and the dispatch inputs it decides which rules this run validates/converts/deploys/attacks/verifies,
and writes `base_sha`, `has_base_diff`, `changed_rule_files`, `has_rules`, `mode`, `rule_files` for a
dozen downstream steps to branch on. The five modes are unchanged (push diff, the seven-file
full-rebuild widening, `workflow_dispatch` `all` / `unverified` / explicit `rules`). A wrong answer
here either starts a full lab run that should not have happened or silently skips rules while the run
goes green — which is why it moved somewhere `tests/test_determine_changed_rules.py` can reach it.
Exit `1` if a manual selection names a rule that does not exist.

### `scripts/state/build_pipeline_bundle.py`

Register item 4.1, slice 5 (last of five). `prepare_validate_convert`'s `Build pipeline bundle`
step, formerly ~116 lines of inline bash. Assembles the `spl-pipeline-bundle` artefact every later
job downloads: the changed `.spl` + `.meta.json` files, `run_atomic.ps1`, `deploy_spl_to_splunk.py`,
`check_spl_syntax.py`, and the **whole** of `scripts/lib/` copied wholesale (an itemised copy list
caused a real bug once — run #67 — so `copy_lib_wholesale()` exists on purpose), with `__pycache__`
pruned. Covered by `tests/test_build_pipeline_bundle.py`.

### `scripts/state/merge_verification_results.py`

Register item 4.1, slice 2. `update_dashboard`'s `Merge verification results, generate stats and
commit` step, formerly ~137 lines of inline bash inside a 3-attempt retry loop. Per attempt: reset
the working tree to `origin/dev`'s tip, overlay this run's verification-results artifact into
`outputs/results/` (last verdict wins) and append each `.delta` sidecar's one new `history.jsonl`
line if it isn't already the last line (the idempotency guard that makes a retry — or
`persist_results_fallback` replaying the same delta later — safe), rebuild the dev deployment
inventory via `deployment_inventory.py`, re-run `generate_stats.py`, then commit and push. Its
`STAGE_PATHS` deliberately no longer includes `docs/index.html` or `README.md` (item 4.4,
2026-08-24): those are regenerated on disk but travel to Pages as an artifact, not a commit. "No
artifact" is a normal state (lab offline), not an error. Covered by
`tests/test_merge_verification_results.py`.

### `scripts/state/reconcile_step.py`

Register item 4.1, slice 4. `splunk_verify`'s `Reconcile Splunk state against the repo` step,
formerly ~118 lines of inline bash. Assembles `reconcile.py`'s CLI args — crucially, `--apply-removals`
only when **both** `github.event_name == 'workflow_dispatch'` and `inputs.retire_orphans == 'true'`
(`inputs.*` reads as empty string on a push, the truthiness trap this double condition closes) — then
runs `reconcile.py --apply` and re-exits its real code via `PIPESTATUS` so a cleanup that failed to
land is visible. Covered by `tests/test_reconcile_step.py`.

### `scripts/state/open_promotion_pr.py`

Register item 4.1, slice 3. `open_promotion_pr`'s only step, formerly ~137 lines of `gh`-CLI-heavy
bash. Short-circuits if a `dev`→`main` PR is already open; otherwise `gh pr create --base main
--head dev --label automated-promotion`, then best-effort fetches `stats.json` off `dev` for the
stale-count and rule-table blocks in the PR body, then best-effort adds the PR to Project #3 and sets
its Status to `In review`. The verdict gate that decides *whether* this runs lives in the job's
`if:`, not here. Covered by `tests/test_open_promotion_pr.py`.

### `scripts/state/deployment_inventory.py`

Register item 4.7. Folds a deploy report and/or a reconcile report into
`outputs/reports/deployment_inventory.json` — a committed **digest** (not a dump) of what is deployed
where and at what version, which the dashboard reads. Every environment section carries its own
`checked_at`, because the deployment chain is one-way and a stale `prod` timestamp is itself the
answer to "when did anyone last look". It records what was deployed and what was found, **never**
where — no Splunk URL, app name or account — because it is committed to a public repo. Called via
`merge_verification_results.py` for the `dev` section, and directly by `ci_prod_workflow.yml`'s
`update_dashboard` and `ci_prod_audit.yml`'s `record_inventory` for the `prod` section. The counts
it carries out of a reconcile report are a fixed list, so a new field has to be added on purpose.

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
| [`tests/test_validate_sigma.py`](../../tests/test_validate_sigma.py) | Schema validation: valid/invalid rules, YAML-date normalisation, and the three exit codes |
| [`tests/test_check_version_bump.py`](../../tests/test_check_version_bump.py) | `logic_diff()`/`version_of()`: which fields count as a logic change, and that a new file with no prior version is skipped not failed |
| [`tests/test_check_detect_id_uniqueness.py`](../../tests/test_check_detect_id_uniqueness.py) | `find_duplicates()` and the hard-fail on the merged tree when two rules share a `detect_id` |
| [`tests/test_check_spl_syntax.py`](../../tests/test_check_spl_syntax.py) | The parser call: a good query passes, a bad one exits 1, and setup failure is exit 2 not a per-rule fault |
| [`tests/test_check_saved_search_hits_dispatch_gate.py`](../../tests/test_check_saved_search_hits_dispatch_gate.py) | That the dispatch never re-adds a leading `search` to the SPL (the `/saved/searches` double-`search` 0-hit bug) |
| [`tests/test_meta_only.py`](../../tests/test_meta_only.py), [`tests/test_meta_sidecar.py`](../../tests/test_meta_sidecar.py) | Sidecar generation from the Sigma YAML, and `lib/meta_sidecar.py`'s locate/parse with each caller's own error handling |
| [`tests/test_lib_env.py`](../../tests/test_lib_env.py), [`tests/test_splunk_client.py`](../../tests/test_splunk_client.py), [`tests/test_splunk_namespace.py`](../../tests/test_splunk_namespace.py), [`tests/test_lib_rules.py`](../../tests/test_lib_rules.py), [`tests/test_verdict_history.py`](../../tests/test_verdict_history.py) | The `scripts/lib/` modules — fail-closed env reading, session construction, the `nobody` namespace split, recursive dual-extension discovery, append-only history with corrupt-line tolerance |
| [`tests/test_determine_changed_rules.py`](../../tests/test_determine_changed_rules.py) | `decide()` branch by branch: the five modes, the rebuild-all widening, and that an unknown manual id exits 1 |
| [`tests/test_build_pipeline_bundle.py`](../../tests/test_build_pipeline_bundle.py) | The bundle skeleton, the named-script copies, and that `scripts/lib/` is copied wholesale |
| [`tests/test_merge_verification_results.py`](../../tests/test_merge_verification_results.py) | The reset/merge/commit retry loop: delta-append idempotency, "no artifact" as a normal state, and `STAGE_PATHS` no longer carrying `docs/`/`README.md` |
| [`tests/test_reconcile_step.py`](../../tests/test_reconcile_step.py) | The `--apply-removals` double condition (event **and** input), and that a failed reconcile is re-exited not hidden |
| [`tests/test_open_promotion_pr.py`](../../tests/test_open_promotion_pr.py) | The existing-PR short-circuit, the best-effort stats/rule-table fetches, and the Project #3 add/status edits |
| [`tests/test_deployment_inventory.py`](../../tests/test_deployment_inventory.py) | The digest shape, per-environment `checked_at`, and that no Splunk URL/app/account is ever written |
| [`tests/test_anonymize_matched_events.py`](../../tests/test_anonymize_matched_events.py), [`tests/test_diff_matched_events.py`](../../tests/test_diff_matched_events.py) | Discovered-not-configured pseudonymisation with stable mappings, and that `diff_matched_events` finds the same field splits before and after anonymisation |
| [`tests/test_new_rule.py`](../../tests/test_new_rule.py) | Next-free-`detect_id` selection over a gapped id space, and that the generated file is schema-valid unedited |
| [`tests/test_generate_stats_math.py`](../../tests/test_generate_stats_math.py), [`tests/test_deployment_panel.py`](../../tests/test_deployment_panel.py) | The verdict-standing arithmetic (superseded/expired, the moving denominator) and the dashboard's deployment-panel rendering |

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
