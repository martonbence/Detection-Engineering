---
name: pipeline-ci-gotchas
description: Use when modifying, reviewing, or auditing this repo's GitHub Actions workflows (ci_dev_workflow.yml, ci_prod_workflow.yml, ci_prod_audit.yml, ci_code_checks.yml) or the scripts they call. Catalogs real, already-happened CI failure modes — silent green-but-skipped runs, environment-scoped-var gotchas, bundle packaging gaps, bash -e traps — so a plausible-looking change doesn't silently reintroduce a bug this pipeline already paid to learn about.
---

Every entry below is backed by a real incident, a defensive-code comment, or
both — not speculative "this could go wrong" material. Each gives: the trap,
the evidence it's real, where to find it in the workflow, and the failure
signature to recognize if it comes back. Anchors are line ranges as of
2026-08-21 in `.github/workflows/*.yml` — they drift; if a cited range looks
wrong, search the step name instead of trusting the number.

This complements `docs/architecture/scripts_reference.md` (what each script
does) rather than replacing it — this file is about what goes wrong at the
*workflow* layer specifically, usually in ways schema/unit tests can't catch.

## A — Silent-skip and false-green traps

The pipeline's worst failure mode isn't a red X — it's a green run that did
less than it looks like it did.

**`has_rules=false` skip cascade.** Job `prepare_validate_convert`, step
`changes` ("Determine changed Sigma files"), `ci_dev_workflow.yml:215-431`.
It derives the changed-rule-file list; if empty, `has_rules=false` and every
downstream job (deploy, all three attack jobs, verify, dashboard, promotion
PR) is gated on it transitively. *Failure signature:* run starts, does
nothing, reports green. Usually caused by adding a path to a workflow
`paths:` trigger without teaching this step about it.

**`--diff-filter=AMRC` excludes deletions**, `ci_dev_workflow.yml:285`. A
commit that only deletes a rule produces `has_rules=false` via this filter —
which is why "Prune repo artefacts of deleted rules" (`477-489`) runs
unconditionally on push/dispatch to `dev`, not gated on `has_rules`.

**`rebuild_all_files` explicit list**, `ci_dev_workflow.yml:342-350`. Files
like `rule_naming.py`, `sigma_to_spl.py`, `backend_config.py`,
`config/backends.yml` can change every rule's SPL or Splunk saved-search
name without touching a rule file — a real incident (comment at `314-341`)
happened when `rule_naming.py` changed and only the diffed rules got
renamed in Splunk, leaving the rest running under stale names. *If you add
a new file under `scripts/convert/` or `scripts/lib/` that affects
conversion/naming output, add it to this list* — otherwise: green run,
majority of deployed rules silently keep running under old logic.

**`open_promotion_pr` and `needs.*.outputs` under `always()`.**
`ci_dev_workflow.yml:2399-2430`. Reading `needs.splunk_verify.outputs.*` in
a downstream `if:` is unreliable when the upstream job's own `if:` starts
with `always()` — empirically observed (run `30154222981`: 5/5 PASS,
`splunk_verify` succeeded, `open_promotion_pr` still skipped with zero
steps). Fixed by checking `needs.splunk_verify.result == 'success'` (job
*result*, not `.outputs`). Any new downstream job written the "normal" way
against an `always()`-gated upstream will silently stay skipped even on a
genuine upstream success.

**`update_dashboard`/`deploy_pages` vs `LAB_ONLINE` skip.**
`ci_dev_workflow.yml:2292-2320`, `2575-2597`. The old condition
`needs.splunk_verify.result == 'success' || 'failure'` is false when the
result is `skipped` — Actions has no third value that catches it. Fixed by
decoupling dashboard/Pages from `splunk_verify` entirely. Re-coupling them
("simplify by removing a job") means `LAB_ONLINE=false` runs silently stop
updating the public Console for new rules, everything else green.

**A rule can target a runner with no job servicing it.**
`ci_dev_workflow.yml:529-535` (`check_test_routing.py`, register 2.17).
Schema validation doesn't check the `runner` value against real jobs;
`run_atomic.ps1` matches exactly, so an unrouted rule deploys, its test
step prints one line and skips, and the run still exits 0. Advisory only —
the hard gate (pytest) only catches an *already-committed* rule that stops
routing, not a new one authored wrong.

**MITRE tag validation is deliberately loose, and dashboard extraction is
looser still.** `ci_dev_workflow.yml:577-582` (register 4.3). The schema's
tag pattern has a free-text `anyOf` fallback (`attack.t123` validates);
`generate_stats.py`'s `extract_techniques()` regex (`attack\.t\d+`) is
looser still and renders a mistyped tag as a covered Navigator badge.
Non-blocking by design — judging tag correctness needs domain knowledge a
checker can't verify offline — but easy to miss in review since nothing
red flags it.

**`workflow_dispatch` has no before/after diff to select on.** Register
2.21, comment at `ci_dev_workflow.yml:93-133`. A manual run has no
`github.event.before`; naively falling through to "diff against nothing"
used to mean re-attacking all 27 rules on lab VMs to catch up two. Fixed
via explicit `scope`/`rules` inputs and a `has_base_diff` guard
(`270-283`). Removing that guard silently regains "attack everything on
every manual run" behavior.

## B — Runner and environment-scoped-variable traps

**Self-hosted runner queue ignores `timeout-minutes`.** Comment at
`ci_dev_workflow.yml:83-91`. A job queued for an offline runner never
starts, so its timeout (which only counts from job *start*) never fires;
with `cancel-in-progress: false` the queued run blocks every later push to
`dev` for about a day until GitHub drops it. Mitigated by `vars.LAB_ONLINE`
gating every lab-dependent job, plus an explicit "lab is switched off"
warning step (`1092-1114`) so the skip is never silent — same pattern in
`ci_prod_workflow.yml`'s `announce_lab_offline` and `ci_prod_audit.yml`'s
gate. **Polarity is deliberate everywhere this appears:** checks are always
`!= 'false'`, never `== 'true'` — an unset var or a typo'd var name then
fails toward *running*, not toward silently never deploying/auditing.
Flipping this polarity means a typo silently disables deploys/audits
forever with no signal.

**`environment:`-scoped vars in a job-level `if:` read as empty.** Canonical
comment at `ci_dev_workflow.yml:1223-1279`, repeated at `1786-1789`,
`1819-1824` — "the trap register item 2.20 hit with LAB_ONLINE" is a
recurring bug class here. A job's `environment:` block resolves *after*
its own `if:` is evaluated, so `vars.SPLUNK_APP`/`SPLUNK_VERIFY_TLS` (both
environment-scoped) read as empty string in a job-level `if:`. Only read
these inside a step's `env:` block. (`LAB_ONLINE` is workflow-level, not
environment-scoped, so job-level `if:` is fine for it specifically — don't
generalize the fix to "never use job-level if with vars".)

**`de-lab`'s pre-installed `gh` predates `gh attestation verify`.**
`ci_prod_workflow.yml:130-147`. Confirmed empirically against run
`31307470773` (2026-08-09): the shared self-hosted runner's system `gh`
(2.45.0) has no `attestation` subcommand. Prod installs a pinned,
checksum-verified `gh` 2.97.0 into `${RUNNER_TEMP}` for just that job
rather than upgrading the shared binary dev also uses. Removing this step
as "redundant" breaks the provenance-verify step right after it with an
unknown-subcommand error that looks like a script bug.

## C — Bundle and artifact packaging

**Incomplete sidecar coverage broke every rule's prod deploy.** Comment at
`ci_dev_workflow.yml:673-689`, named incident run `31314423690`: a run that
only touched one rule uploaded a bundle with only that rule's `.meta.json`
sidecar; prod downloads exactly one bundle and has no other sidecar source,
so every *other* rule's deploy died on a missing sidecar before writing
anything. Fixed by "Regenerate meta sidecars for unchanged rules"
(`690-731`). "Optimizing" the bundle back to changed-rules-only reproduces
this for every rule, not just the touched ones.

**Bundle packaging omission surfaces later, on a different runner.**
Comment at `ci_dev_workflow.yml:749-762`, named incident run `#67`: a
refactor moved env helpers into `scripts/lib/env.py`, the bundle's
hand-maintained `cp` list wasn't updated, the bundle shipped without it,
and `deploy_to_splunk` died 0.1s in with `ModuleNotFoundError` on the lab
runner — long after `prepare_validate_convert` had already gone green.
Fixed by wholesale `cp -r scripts/lib/.` instead of naming files, plus a
"Smoke-test the pipeline bundle" step (`997-1067`, register 3.6) that
imports every bundled `.py` file at build time. Reverting to named `cp`
calls reproduces a failure that looks like a lab/environment problem but
is a packaging omission two jobs upstream.

## D — Commit-back and state-consistency traps

**Three separate pushes to `dev` per run, deliberately not merged further.**
`prepare_validate_convert`'s output commit (`925-963`), `splunk_verify`'s
result commit (`2142-2279`), and `update_dashboard`'s dashboard commit
(`2361-2397`) are independent fetch/reset/reapply/push cycles. Comment at
`2116-2141` explains why the last two stay separate: `splunk_verify` runs
on the self-hosted lab runner and must commit `outputs/results/` *before*
`update_dashboard` (often a different runner) can read those results back
off `origin/dev` — it doesn't read them off local disk. Merging these two
steps to "simplify" creates a job-ordering/race problem. (Matches project
memory: verify/dashboard commit coupling — don't re-derive, this is why.)

**`reconcile.py`'s report reflects pre-`--apply` state.** Comment at
`ci_dev_workflow.yml:2038-2046`, verified against two real runs (`#42`
retire-on now correctly reports 0 where a naive read said 3; `#41`
retire-off still correctly reports 3). The script prints its report before
applying fixes, so a naive `jq` read of `.orphan_removed[] | select(...)`
would re-flag just-fixed drift as still broken. The actual `unresolved`/
`renamed` expressions (`2047-2059`) subtract `.applied.actions[]` first —
any new report/annotation reading the raw counts directly reproduces this.

## E — Bash step and error-handling traps

**GitHub `shell: bash` steps always run `-e`, regardless of the script's
own `set` line.** Comment at `ci_dev_workflow.yml:1996-2003`: Actions runs
bash steps as `bash --noprofile --norc -e -o pipefail` unconditionally, so
`some_command; rc=$?` never reaches the `rc=$?` line — the step dies the
instant the command exits non-zero, skipping every diagnostic/summary code
after it. The correct pattern, used at `1996-2013` and in
`ci_code_checks.yml:453-479`, wraps the command in `if ... ; then rc=0;
else rc="${PIPESTATUS[0]}"; fi`.

**`continue-on-error: true` still renders a step/job as failed.** Comment
at `ci_code_checks.yml:397-413`: the first version of `dependency_audit`
used `continue-on-error`, and pip-audit's exit code 1 (findings, tool ran
fine) still showed "Error: Process completed with exit code 1" and a red
job — advisory findings looked identical to a broken build. Fixed
(`414-504`) by explicitly translating that specific exit code into a
`::warning::` annotation + `exit 0`, while any *other* non-zero exit (the
tool itself crashed) still fails the job for real. Reverting to
`continue-on-error` loses the distinction between "found something" and
"the checker didn't run."

## F — Secrets and TLS

**A flag whose job is to be visible cannot be stored as a secret.** Comment
at `ci_dev_workflow.yml:1246-1279`: `SPLUNK_VERIFY_TLS` used to be a GitHub
*secret*, and secret redaction blanks its value everywhere in logs —
including unrelated boolean action inputs (`overwrite: ***`) — which gagged
the very warning meant to announce "TLS verification is off." Also removed:
a `|| 'false'` fallback that silently converted a *missing* secret into
"skip TLS verification," overriding the safe `default=True` in the Python
consumer (`env_bool`). Both `SPLUNK_APP` and `SPLUNK_VERIFY_TLS` are
`vars.`, not `secrets.`, for exactly this reason — moving either back
reproduces both failure modes.

## G — Prod deploy and attestation

**`gh attestation verify --signer-workflow` rejects `--signer-repo`
alongside it.** `ci_prod_workflow.yml:220-244`. Confirmed empirically —
`gh` rejects the combination outright, since `--signer-workflow` already
pins the repo. Adding `--signer-repo` "to be extra explicit" breaks the
step outright, it's not a harmless no-op. Three rejection cases (mismatched
signer-workflow, mismatched signer-repo, tampered file) were tested, not
assumed, when this gate was built.

**Provenance verification is prod's *sole* integrity gate**, and prod's
trigger only fires on rule-file changes. `ci_prod_workflow.yml:1-22`,
`196-219` (register 3.2 stage C). Prod no longer re-converts Sigma or
diffs against the committed SPL — `gh attestation verify` against dev's
signed bundle is the only check. Separately, since the workflow's `push`
`paths:` filter only matches rule files, a fix merged to `.../deploy_spl_to_splunk.py`,
`sigma_to_spl.py`, `rule_naming.py`, or a dependency pin sits **dormant on
prod** until some unrelated rule change happens to trigger a redeploy — "That
delay is invisible: nothing reports that prod is running an older deploy
path" (comment at `11-21`). The lever to force it is `workflow_dispatch`
(deploys from `git ls-files`, full library, not a diff) — but nothing
prompts anyone to pull it.

**Prod installs a narrower, separate dependency pin.**
`ci_prod_workflow.yml:106-111` installs `.github/requirements-deploy.txt`
(`requests` only) — *not* `.github/requirements.txt`, which dev and the
conversion toolchain use — because stage C above removed prod's need for
`pyyaml`/`sigma-cli`/`pySigma`/etc entirely. Both requirement files'
header comments cross-reference this split explicitly. Assuming prod
shares dev's full pin file is a real, already-observed source of doc drift
— it was wrong in Jamal's own agent file until 2026-08-21.

## H — Console/Pages publishing

**Console publish only fires on an actual regen *commit*.**
`ci_code_checks.yml:646-658`, comment at `55-61`. `publish_console` only
runs when `regenerate_console` set `published=true`, or on manual
`workflow_dispatch`. Landing a correct, already-regenerated `docs/index.html`
by hand (not through the auto-regen step) means `regenerate_console` finds
nothing to commit, `published` stays false, and Pages keeps serving the
previous deploy — fully green CI, correct file on `dev`, stale live page.
This exact gap shipped once, 2026-08-10. The `workflow_dispatch` trigger on
`ci_code_checks.yml` exists specifically to force a republish without
pulling in the full dev/Splunk/Atomic run.

**Change-detection must normalize timestamps/SHAs, never filter lines.**
`ci_code_checks.yml:559-592`. `generate_stats.py` stamps the current time
and HEAD's SHA into everything, so naive byte-diffing commits on every
push forever. Line-level timestamp filtering was deliberately rejected
(comment at `559-576`) because `COVERAGE_HISTORY`/`RULE_GROWTH_HISTORY` are
each one enormous line mixing real data *and* a timestamp — a line filter
would silently discard genuine coverage changes. The actual fix substitutes
ISO-8601 timestamps and 40-hex SHAs with placeholders before diffing
(`has_substantive_change`, `571-592`). Too-narrow normalization →
commit-storm; too-broad (reverting to line-filtering) → real content
changes silently swallowed while the job reports "nothing to publish" as
if that were correct. (`.claude/commands/rebuild-dashboard.md` runs this
same normalize-then-diff locally.)

**`fetch-depth: 0` is load-bearing wherever `generate_stats.py` runs.**
Comment repeated at `ci_dev_workflow.yml:2330-2334` and
`ci_code_checks.yml:529-533` (confirming this bit more than one job
independently). `compute_rule_version()` runs `git log --follow` per rule
to derive its version from commit count; a shallow checkout makes every
rule silently report version `1.0` — no error, just wrong dashboard data.
Any new job that regenerates the dashboard needs the full checkout.
