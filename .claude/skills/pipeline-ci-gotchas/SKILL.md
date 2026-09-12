---
name: pipeline-ci-gotchas
description: Use when modifying, reviewing, or auditing this repo's GitHub Actions workflows (ci_dev_workflow.yml, ci_prod_workflow.yml, ci_prod_audit.yml, ci_code_checks.yml) or the scripts they call. Catalogs real, already-happened CI failure modes — silent green-but-skipped runs, environment-scoped-var gotchas, bundle packaging gaps, bash -e traps — so a plausible-looking change doesn't silently reintroduce a bug this pipeline already paid to learn about.
---

Every entry below is backed by a real incident, a defensive-code comment, or
both — not speculative "this could go wrong" material. Each gives: the trap,
the evidence it's real, where to find it in the workflow, and the failure
signature to recognize if it comes back. Anchors are line ranges as of
2026-08-21 in `.github/workflows/*.yml` (section A's three entries updated
2026-08-23 after register item 4.1 moved the scope-decision step's logic
into `scripts/state/determine_changed_rules.py`; section H's first entry
rewritten 2026-08-24 after item 4.4 changed console publishing from a
git-diff-gated commit to an unconditional artifact handoff — the rest of
the file wasn't re-verified at either pass, and item 4.1's four other
2026-08-24 slices moved plenty of other line numbers this file still
cites) — they drift; if a cited range looks wrong, search the step name
instead of trusting the number.

This complements `docs/architecture/scripts_reference.md` (what each script
does) rather than replacing it — this file is about what goes wrong at the
*workflow* layer specifically, usually in ways schema/unit tests can't catch.

## A — Silent-skip and false-green traps

The pipeline's worst failure mode isn't a red X — it's a green run that did
less than it looks like it did.

**`has_rules=false` skip cascade.** Job `prepare_validate_convert`, step
`changes` ("Determine changed Sigma files"), `ci_dev_workflow.yml:215-247`ish
(now a two-line call into `scripts/state/determine_changed_rules.py` —
register item 4.1 moved the 206-line decision tree there 2026-08-23; the
logic itself, `decide()`, is unchanged and now has direct pytest coverage in
`tests/test_determine_changed_rules.py`). It derives the changed-rule-file
list; if empty, `has_rules=false` and every downstream job (deploy, all
three attack jobs, verify, dashboard, promotion PR) is gated on it
transitively. *Failure signature:* run starts, does nothing, reports green.
Usually caused by adding a path to a workflow `paths:` trigger without
teaching this step about it.

**`--diff-filter=AMRC` excludes deletions**, now `git_diff_names()` in
`scripts/state/determine_changed_rules.py` (was inline at
`ci_dev_workflow.yml:285`). A commit that only deletes a rule produces
`has_rules=false` via this filter — which is why "Prune repo artefacts of
deleted rules" (`ci_dev_workflow.yml:307-319`) runs unconditionally on
push/dispatch to `dev`, not gated on `has_rules`.

**`REBUILD_ALL_FILES` explicit list**, now a module-level constant in
`scripts/state/determine_changed_rules.py` (was inline at
`ci_dev_workflow.yml:342-350`, before the 4.1 extraction). Files like
`rule_naming.py`, `sigma_to_spl.py`, `backend_config.py`,
`config/backends.yml` can change every rule's SPL or Splunk saved-search
name without touching a rule file — a real incident happened when
`rule_naming.py` changed and only the diffed rules got renamed in Splunk,
leaving the rest running under stale names. *If you add a new file under
`scripts/convert/` or `scripts/lib/` that affects conversion/naming output,
add it to this list* — otherwise: green run, majority of deployed rules
silently keep running under old logic. The list is now parametrized-tested
(`tests/test_determine_changed_rules.py` asserts every entry actually
triggers `all` mode), so a future addition that doesn't wire the trigger
correctly fails a test instead of failing silently in production.

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

**Two pushes to `dev` per run — down from three as of register item 4.4
(2026-08-22), not further mergeable without a real transport channel.**
`prepare_validate_convert`'s output commit (`925-963`) stays independent —
`deploy_to_splunk` needs the SPL bundle committed before it can read it
back, same reasoning as below, just one hop earlier in the graph.
`splunk_verify` no longer commits at all: it *uploads* a delta artifact
(`verify-results-${{ github.run_id }}`, step "Stage verification results
for transport") instead of pushing, because it runs on the self-hosted lab
runner while `update_dashboard` (often a different runner) does its own
`git reset --hard origin/dev` and only ever reads the working tree — a
push was the only channel before this fix, now the artifact is. If you're
tempted to "simplify" by having `splunk_verify` commit again, you're
reverting 4.4, not fixing anything — the artifact-download step in
`update_dashboard` (`2359-2385` region) merges it in and makes the single
remaining write-back commit. A `persist_results_fallback` job
(`needs.splunk_verify.result != 'skipped' && needs.update_dashboard.result
!= 'success'`) exists specifically to re-commit the artifact if
`update_dashboard` itself fails after downloading it — don't mistake that
job's *existence* for a sign the artifact transport is unsafe; it's the
one edge case (a mid-flight failure) that transport can't self-heal, and
it's designed to run approximately never. (Matches project memory: verify/
dashboard commit coupling, and the 4.4 register Napló entry — don't
re-derive either, this entry is the summary of both.)

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

**Console publish used to only fire on an actual regen *commit* — fixed
2026-08-24, but know the shape of the bug it replaced.** Historically
(through 2026-08-23), `publish_console` only ran when `regenerate_console`
set `published=true`, or on manual `workflow_dispatch`. Landing a correct,
already-regenerated `docs/index.html` by hand (not through the auto-regen
step) meant `regenerate_console` found nothing to commit, `published`
stayed false, and Pages kept serving the previous deploy — fully green CI,
correct file on `dev`, stale live page. This exact gap shipped once,
2026-08-10.

As of `audit/feature-and-process-audit.md` item 4.4 (2026-08-24, commit
`da85f9c`), `docs/index.html` and README's generated STATS block are no
longer committed to `dev` at all — `regenerate_console` (and
`ci_dev_workflow.yml`'s `update_dashboard`) now upload `docs/` as a
same-run `actions/upload-artifact`, and `publish_console`/`deploy_pages`
`download-artifact` it directly instead of checking out `dev`. Publishing
no longer reacts to a git diff at all: `publish_console`'s gate is now
`needs.regenerate_console.result == 'success'`, full stop, so the
"hand-fix commits nothing, Pages never learns" failure mode above is now
structurally impossible, not just rarer. The `workflow_dispatch` trigger
is kept for a different reason now: forcing a republish without the full
dev/Splunk/Atomic run.

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
`ci_code_checks.yml:529-538` (confirming this bit more than one job
independently). As of 2026-08-29 the reason is `generate_stats.py`'s
`update_trend_history()`/`_backfill_stats_history()` (lines ~866-903),
which runs `git log -n 500` against `outputs/reports/stats.json` for the
trend-history backfill, plus `.claude/generate_dashboard.py`'s activity
feed (`ACTIVITY_LIMIT = 40`) — a shallow checkout starves both silently, no
error, just truncated/wrong history. Any new job that regenerates the
dashboard needs the full checkout.

**Original reason, now retired (kept for the incident it caused, below):**
until 2026-08-29 this comment was load-bearing because `compute_rule_version()`
(`scripts/lib/rule_version.py`, deleted when the version scheme changed to
a hand-set, `.githooks/pre-commit`-auto-bumped `version:` field — register
item 3.5) ran `git log --follow` per rule to derive its version from raw
commit count; a shallow checkout made every rule silently report version
`1.0`. That specific mechanism is gone, but the failure mode it caused is
exactly why this gotcha is documented at all — still worth reading if a
future job adds its own `generate_stats.py` call with a shallow checkout,
since a *different* silent-1.0-shaped bug is just as reachable today.

**Third occurrence, found missing and fixed 2026-08-22:**
`ci_code_checks.yml`'s `static_analysis` job also calls `generate_stats.py`
(its "Generate rule browser for smoke test" step, feeding the Playwright
smoke test) but its `Checkout` step had no `fetch-depth: 0` — missed when
the fix landed on `regenerate_console`'s checkout elsewhere in the same
file. This wasn't just "wrong dashboard data" here, it broke a real CI
gate deterministically: the shallow-checkout "1.0" fed
`isVerdictSuperseded()` in `page.js`, which flags a verdict superseded
when this run's computed `ruleVersion` disagrees with the
`verdictRuleVersion` recorded at actual verification time.
DETECT-2026-0007 was (at the time) the repo's only rule with a real PASS
verdict, so under the bug it alone got wrongly marked superseded,
`verifyCount` went all-zero across every rule, and the smoke test's
chart-verify ring check failed with "dataset sums to 0" on every run that
reached it — not flaky, reproducible every time. Any *new* job added to
this workflow (or `ci_prod_audit.yml`) that calls `generate_stats.py`
needs this checked explicitly; grep for `generate_stats.py` across the
workflows and confirm each caller's own `Checkout` step carries
`fetch-depth: 0` rather than assuming the first two fixes covered every
site.

## J — Dependabot-triggered runs

**A Dependabot rebase force-push can fire `ci_dev_workflow.yml` despite the
diff not matching its `paths:` filter — and then fails for an unrelated
reason.** Real incident, 2026-09-07, PR #70 (a `.github/requirements-dev.txt`
ruff bump, dependabot/pip branch). Commenting `@dependabot rebase` made
Dependabot force-push its branch onto the new `dev` tip. That triggered
`ci_dev_workflow.yml`'s `push` trigger (`branches-ignore: [main]`, otherwise
unrestricted) even though the only actual file changed was
`.github/requirements-dev.txt`, which matches none of the trigger's
`paths:` entries (`rules/sigma/**`, `scripts/validate/**`, etc.) — because
GitHub's `paths:` filter can't reliably compute a diff across a
force-pushed ref with no consistent "before" commit in the branch's own
history, and falls back to running the workflow rather than skipping it.
Run confirmed: `34138572509`, job `101795144178`.

The triggered run then failed immediately (~4s) at its own `Checkout` step
— `Input required and not supplied: token` — because that step passes
`token: ${{ secrets.GH_PAT_DEV_PUSH }}` (see section F), and **workflow
runs whose actor is `dependabot[bot]` never get access to repository
secrets**, by GitHub's own design (a supply-chain protection: a compromised
dependency's changelog/metadata can't be crafted to exfiltrate secrets
through an auto-triggered CI run). This isn't a bug to fix in this
specific step — no secret will ever be available here no matter how the
token line is written — it's a structural mismatch between "this workflow
assumes it can always check out with a PAT" and "Dependabot pushes can
trigger it."

*Failure signature:* a `Prepare, Validate, Convert` (or any other
secret-consuming job) red X, dying in seconds at `Checkout`, specifically
on a `dependabot/**` branch, right after a rebase/recreate comment or an
initial Dependabot PR push.

**Why this hasn't broken anything load-bearing (yet):** `dev`'s branch
protection has no `required_status_checks` configured (confirmed via `gh
api repos/.../branches/dev/protection` — the field is simply absent), so
this red X doesn't block the PR's `mergeStateStatus`; the actual gate for
a Dependabot bump PR is `ci_code_checks.yml`'s `Static analysis and tests`
job, which runs independently and did pass. **If `required_status_checks`
is ever added to `dev` and someone reflexively lists `Prepare, Validate,
Convert` among them** (it looks like a natural "must pass" candidate), any
future Dependabot PR that gets rebased even once becomes permanently
unmergeable through no fault of its own diff — worth remembering before
tightening branch protection, not just when triggering a rebase.

## K — Sigma-to-SPL boolean grouping

**A nested `(A or B) and (C or D)`-shaped Sigma `condition:` converts to SPL
*without* explicit parentheses around the inner OR groups — and that's
correct, not a bug, only because of a Splunk `search`-command precedence
rule easy to not know.** Real incident, 2026-09-07, reviewing
DETECT-2026-0033 (`condition: (selection_img and (selection_named_tool or
selection_raw_socket_idiom)) or (selection_netcat_img and
selection_netcat_flag) or selection_msfvenom`). Running the repo's own
`scripts/convert/sigma_to_spl.py` on it emits (backend Image/OriginalFileName
list collapsed for brevity):

```
index=sysmon (OriginalFileName IN (...) OR Image IN (...)
  CommandLine IN (<named_tool list>) OR (CommandLine="* Net.Sockets.TCPClient*" ...))
  OR (Image IN (<nc list>) CommandLine IN (<flags>))
  OR (CommandLine="*msfvenom*" CommandLine="*-p*")
```

On sight this looks broken — the `selection_img` OR-pair (`OriginalFileName
IN (...) OR Image IN (...)`) isn't wrapped before it's implicitly ANDed
(bare juxtaposition) against the next clause. It isn't broken: Splunk's
`search` command evaluates **OR before AND** — the opposite of `eval`/
`where`, confirmed against Splunk's own docs, whose own worked example
(`host="www1" AND status=200 OR action="addtocart"` →
`host="www1" AND (status=200 OR action="addtocart")`) is exactly this
shape. Applying that precedence to the full emitted string resolves to
precisely the Sigma source's intended grouping.

**Why this is a trap, not just a fun fact:** every rule in this repo that
predates DETECT-2026-0033 uses a flat `1 of selection_*` or `all of
selection_*` condition, so this precedence quirk has never mattered before
and won't be familiar. A future author writing a nested boolean condition
who eyeballs the resulting SPL and "fixes" the apparent missing parens (by
restructuring the Sigma `condition:`, or by hand-editing generated SPL) is
liable to guess the wrong grouping and silently broaden or narrow the
rule. And the correctness here is contingent, not structural: it depends
on this SPL running as a saved-search `search` command specifically
(`custom.splunk.mode: alert`, deployed via
`scripts/deploy/deploy_spl_to_splunk.py`'s `saved/searches` path,
dispatched via `/saved/searches/{name}/dispatch`) — the identical string
pasted into an `eval`/`where` context would evaluate under the opposite
precedence and mean something else.

*If you write a Sigma `condition:` with nested OR-inside-AND groupings*,
verify the emitted SPL's real grouping against Splunk's documented
`search`-command precedence before trusting or "correcting" it — don't
assume missing parentheses means broken logic, and don't assume pySigma
adds parens defensively; it doesn't.

**Re-running failed jobs within a run that already reached `deploy_pages`
breaks the Pages deploy, every time.** Real incident, twice in one session,
2026-09-12 (`ci_dev_workflow.yml` runs `34690498895` and `34696370915`).
`actions/upload-pages-artifact` always uploads under the fixed name
`github-pages`; GitHub does not let a re-run of a job replace or supersede
an artifact a prior attempt of the *same run* already uploaded under that
name. So if `deploy_pages` (or anything upstream of it, e.g. `update_dashboard`
via `needs:`) runs more than once inside one workflow run — which "Re-run
failed jobs" does deliberately, since it re-runs a failed job *and every job
that depends on it* — the second attempt's `actions/deploy-pages` step dies
with:
```
Error: Multiple artifacts named "github-pages" were unexpectedly found for this workflow run. Artifact count is 2.
```
Both incidents had a real, unrelated upstream failure (`Splunk Verification`
FAILing because the atomic's events hadn't finished indexing yet) get
"Re-run failed jobs"'d, which correctly re-ran `Splunk Verification` (this
time it PASSed — a genuine fix) but *also* re-ran the already-`success`
`update_dashboard`/`deploy_pages` chain as a `needs:` dependent, producing
the second `github-pages` artifact and failing Pages on both attempts.
**Not a bug in this repo's workflow logic** — the real fix (Splunk
catching up, verification re-passing) worked exactly as intended; Pages
failing is a structural GitHub Actions/`actions/deploy-pages` limitation
around artifact re-upload within one run, not something `ci_dev_workflow.yml`
can guard against from the workflow-author side. *Recovery:* don't keep
re-running failed jobs chasing the Pages step specifically — either accept
the site staying on its previous deploy until the *next* fresh run (a new
push or a new `workflow_dispatch`, which starts a clean run with no
accumulated artifact), or trigger a full fresh run immediately if the
Console needs to be current right away. *Failure signature:* `deploy_pages`
red X with exactly the "Multiple artifacts named github-pages... Artifact
count is 2" error, specifically on a run's second-or-later attempt, never
on a run's first attempt.

## I — Register-item citations

**A bare "register item N.N" in a comment is ambiguous, and it has already
misled twice.** This repo runs *two* independent audit registers —
`audit/feature-and-process-audit.md` (active) and `audit/remediation-plan.md`
(closed) — and both number their items `N.N` from scratch, so the same
number means two unrelated things depending on which file you mean. Real
incidents, not a hypothetical: (1) 2026-08-21, `.github/requirements.txt`
cited "register item 4.10" for the diskcache CVE accepted-risk note — that's
`remediation-plan.md`'s 4.10 (closed 2026-08-04); the active register's
section 4 doesn't reach 4.10 at all. (2) 2026-08-22, while implementing
register item 4.4 (this file's own D-section entry above), a first draft
introduced **ten** bare citations across new comments in
`ci_dev_workflow.yml` — three of the four distinct numbers used (`4.6`,
`4.7`, `2.20`) collided with real, unrelated items in the *other* file, and
would have silently resolved to a plausible-looking wrong item for any
reader who defaulted to "the register we're currently working in." Only
one of the ten (`2.20`, which doesn't exist past 2.14 in the active
register) would have failed loudly; the rest were quiet mis-attributions.
**Always name the file** — `audit/feature-and-process-audit.md item 4.4`,
not `register item 4.4` — and when the same number genuinely exists in
both files with different meanings, say so explicitly in a parenthetical
(see `ci_dev_workflow.yml`'s `persist_results_fallback` job comment, added
2026-08-22, for the pattern). This applies anywhere in `scripts/` or the
workflows that cites either register, not just new comments — pre-existing
bare citations found but deliberately left alone during the 2026-08-22 pass
(e.g. `.github/requirements.txt:34`'s "register item 4.10") are still real
drift, just out of scope for whoever last touched them.

## L — Promotion merge strategy and prod-scope

Both entries are 2026-09-09 incidents on the DETECT-2026-0001 promotion
(PR #73). They chain: the first stopped prod deploying, the manual recovery
for the first exposed the second. Anchors verified 2026-09-09.

**Squash-merging the `dev`→`main` promotion PR suppresses the *entire* prod
deploy workflow — no run, not a skipped run.** The `open_promotion_pr` job
opens one PR per passing dev run, titled *"Promote verified detections from
dev to main"*. If it is **squash-merged** instead of merge-committed, GitHub
builds the squash commit body by concatenating every `dev`-branch commit
message — and this repo's CI writes back to `dev` with `[skip ci]` in nearly
every automated commit (`chore(convert): ... [skip ci]`, `chore(pipeline):
verification results and dashboard [skip ci]`, `chore(inventory): ...
[skip ci]`). The squash HEAD commit that lands on `main` therefore carries
`[skip ci]` many times (PR #73's `bfa99f7`: 10 occurrences, all in the body
— the squash *title* is clean). GitHub Actions honors a skip string
(`[skip ci]` / `[ci skip]` / `[no ci]` / `[skip actions]` / `[actions skip]`)
matched **anywhere in a push's HEAD commit message, title or body**, and
**creates no workflow run at all** — `ci_prod_workflow.yml` (`CI - Prod
Deploy`) never starts. `announce_lab_offline` and every other in-workflow
guard are unreachable because the workflow never initializes. Skip strings
affect only `push`/`pull_request`, so `workflow_dispatch` is unaffected —
which is the recovery. *Evidence:* every promotion #58–#71 was a merge
commit (`Merge pull request #NN from martonbence/dev`, 2 parents, no skip
string) and prod deployed each time; #73 was the first squash (1 parent,
`git rev-list --parents -n1 bfa99f7`), and `gh run list --branch main
--workflow ci_prod_workflow.yml --json headSha,event` has no `push` entry
for `bfa99f7`. `scripts/state/open_promotion_pr.py` generates a clean PR
title (`:437`) and body (templates `:119-127`, `:173-188`, `:222-265`) —
no skip string — so a **merge commit** (message = PR title + body only)
fully closes this; the permanent fix is disabling squash + rebase merge at
the repo level (done 2026-09-09: `allow_squash_merge=false`,
`allow_rebase_merge=false`). Rebase-merge has the same defect (the new
`main` HEAD becomes a `dev` `[skip ci]` writeback commit). Branch
protection *cannot* pin merge method — no such rule in classic protection
or the rulesets API; the repo `allow_*_merge` toggles are the only lever.
Tie-in: `ci_dev_workflow.yml:659-669` already documents that squash/rebase
on this PR break the build-provenance ancestry walk — same root cause,
different subsystem; merge-commit-only is the mode that comment already
wants. *Failure signature:* promotion PR shows Merged, `main` HEAD advanced,
but no new `CI - Prod Deploy` run whose `headSha` is the new `main` HEAD;
`git log -1 --format=%B <main HEAD>` shows a skip string and
`git rev-list --parents -n1 <main HEAD>` shows one parent. *Recovery:* run
`ci_prod_workflow.yml` via `workflow_dispatch` — deploys the full `main`
library from `git ls-files`, no diff needed. Worked here (run
`34389283647`, 7 min after the bad merge).

**Prod deploy has no `status`/verdict filter — a `workflow_dispatch`
recovery deploys every non-`deprecated` `.spl` on `main`, enabled,
including experimental rules that never reached dev Splunk.** `ci_prod_
workflow.yml`'s deploy step (`~:277-326`) hands `git ls-files "rules/splunk/
*.spl"` — the whole library — to `scripts/deploy/deploy_spl_to_splunk.py`,
which applies exactly one eligibility filter: `status == "deprecated"` skip
(`:473-476`, via `lib.rules.is_deprecated`). `status: experimental`,
`testing.enabled: false`, and verification verdict are all ignored, and the
runtime payload hard-codes `disabled: "0"` (`:105`, `:117`) with the alert
schedule from `custom.splunk.mode`. So a dispatched prod run **creates
experimental rules in prod as live, enabled, every-5-min, severity-high
alerting saved searches.** The dev deploy is narrower only by accident, not
policy — it deploys `determine_changed_rules.py`'s *changed-rule* list, so a
rule committed to `dev` while `LAB_ONLINE=false` (dev deploy skipped) can
sit undeployed in dev indefinitely while a `git ls-files` prod dispatch
sweeps it in. `prod ⊆ dev` is **not an enforced invariant anywhere**.
*Evidence:* run `34389283647` deployed DETECT-2026-0033 and -0034
(both `status: experimental`, never Bjorn-reviewed, not in dev Splunk) to
prod — deploy report `totals: {created: 3, updated: 28}`. 0033's SPL
`| lookup known_smb_servers.csv ...` references a lookup that exists nowhere
in the repo → hard search error every run. No gate catches this: the dev
deploy job that runs `check_spl_syntax.py` was skipped for the run that
added it, but even a non-skipped run would not have caught it —
`check_spl_syntax.py:15-19` passes `parse_only=true`, which deliberately
skips lookup/macro/eventtype expansion. Nothing in this pipeline validates
that a referenced Splunk object (lookup, macro, eventtype) actually exists.
`reconcile.py` does not self-heal this: `load_desired()` (`:96-142`) drops
only `is_deprecated` rules, so an `experimental` rule is "desired" and a
prod audit treats it as legitimately present. *Remediation when it happens:*
there is no repo-native delete for this kind of orphan — `reconcile.py
--apply-removals` only disables + `[RETIRED]`-relabels, and only for rules
absent from desired state. Delete the stray saved searches directly
(`servicesNS/nobody/<SPLUNK_APP>/saved/searches/<name>`), then dispatch
`ci_prod_audit.yml` to re-sync `deployment_inventory.json`. *Durable fix
(in progress 2026-09-09):* a `--exclude-status experimental` flag on both
`deploy_spl_to_splunk.py` and `reconcile.py load_desired()`, passed only by
`ci_prod_workflow.yml` / `ci_prod_audit.yml` (never by dev — dev
legitimately tests experimental rules in the lab). *Failure signature:* a
prod deploy report with unexpected `created` entries; a rule live in prod
Splunk that dev Splunk doesn't have; `ci_prod_audit.yml` reporting "N
rule(s) on main not in prod app" for rules you know are experimental.
