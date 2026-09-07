# Contributing

This is the end-to-end flow for adding or changing a detection, collected in one
place. It is **not** a gate or a checklist you have to sign off — the pipeline
enforces what needs enforcing. It's a map, so you don't have to reassemble the
flow from five documents and three skills every time.

Deeper mechanics live in [`docs/architecture/`](docs/architecture/); this page
links out rather than repeating them.

> This repo is maintained mostly by a team of scoped AI agents under a human
> lead. How that team is coordinated is documented in
> [`docs/architecture/agent_workflow.md`](docs/architecture/agent_workflow.md),
> and [`CLAUDE.md`](CLAUDE.md); per-agent bios are on the *Ügynökök* tab of
> the team-ops dashboard ([`docs/team-ops.html`](docs/team-ops.html)). The
> flow below is the same whether a human or an agent is doing the authoring.

---

## Running the checks locally

Use **Python 3.11** to match CI (`ci_code_checks.yml` pins `python-version: "3.11"`).
Run everything from the repo root.

**Full lint + test suite** (what `ci_code_checks.yml` runs):

```
pip install -r .github/requirements.txt -r .github/requirements-dev.txt
ruff check .
pytest
```

Ruff and pytest both read their config from the root `pyproject.toml`
(`[tool.ruff]` / `[tool.pytest.ini_options]`).

**Just running a pipeline script** — `validate_sigma.py`, `generate_stats.py`,
the Sigma→SPL converter — needs only the toolchain file:

```
pip install -r .github/requirements.txt
```

(The header comment in that file says nothing there is needed to work locally —
that's true for *editing rules*, not for running the scripts or the test suite.)

**Windows note.** `scripts/convert/sigma_to_spl.py` resolves the
`Europe/Budapest` timezone, which needs IANA tzdata that Windows doesn't ship at
the OS level. `tzdata` is pinned in `.github/requirements-dev.txt`, so a Windows
checkout with the dev requirements installed no longer hits
`ZoneInfo: No time zone found with key Europe/Budapest`. A suite that's red with
that error means the dev requirements are missing.

**Git hook.** The pre-commit version-bump hook is inert until you point git at it
once per clone:

```
git config core.hooksPath .githooks
```

After that, `.githooks/pre-commit` bumps a rule's `version:` field automatically
when its `detection:` / `logsource:` / `custom.splunk.raw_query` changes;
`check_version_bump.py` is the CI backstop for commits that skipped it.

---

## Adding a new detection, end to end

### 1. Scaffold

```
python3 scripts/new_rule.py "Suspicious LSASS Access"
```

Writes `rules/sigma/<detect_id>_<slug>.yml` with the next free `detect_id`
(the id space has gaps — "next free" is computed from your checkout, not
`max + 1`) and a schema-valid skeleton. Run from anywhere; check `--help` for
current flags. The generated file passes `validate_sigma.py` immediately, but the
placeholder `attack.t0000` / `attack.TODO` tags are deliberately ones
`check_mitre_tags.py` flags — that's the nudge to replace them.

Follow the [`sigma-rule-authoring`](.claude/skills/sigma-rule-authoring/SKILL.md)
skill for the repo's authoring conventions.

### 2. Detection logic — or the raw-query fallback

Fill in the real `detection:` block that Sigma can compile. If the idea genuinely
can't be expressed in Sigma's block syntax, keep the (required, unused)
placeholder `detection:` block and set **`custom.splunk.raw_query`** to the literal
SPL text instead — it's emitted verbatim, bypassing conversion. There is one
authoring format (`rules/sigma/*.yml`) and one pipeline either way; native SPL
detections are not a separate track.

### 3. MITRE ATT&CK tags

Replace the placeholder tags with real `attack.tXXXX(.YYY)` technique tags and
`attack.<tactic>` tactic tags. Ground them in this repo's own cached technique map
and tactic vocabulary via the
[`mitre-attack-mapping`](.claude/skills/mitre-attack-mapping/SKILL.md) skill —
the vocabulary diverges from upstream ATT&CK (`attack.stealth` and
`attack.defense_impairment` are valid here). `check_mitre_tags.py` checks these
offline and advisory in CI.

### 4. Fill in the rest

`falsepositives`, `level`/`severity`, `status`, and the `custom.testing` block
(the Atomic Red Team test or emulation commands that should trigger the rule, plus
its `type` and `runner`). `check_test_routing.py` will warn if no CI job services
the `(type, runner)` pair you chose.

### 5. Version bump (automatic)

Once per clone, enable the hook:

```
git config core.hooksPath .githooks
```

After that, `.githooks/pre-commit` bumps the rule's `version:` field automatically
whenever `detection:`, `logsource:`, or `custom.splunk.raw_query` actually change.
`check_version_bump.py` is the CI backstop for commits that skipped the hook
(`--no-verify`, a fresh clone, or a web-UI edit). A reworded description does not
bump the version.

### 6. Local validation (optional but fast)

```
python3 scripts/validate/validate_sigma.py rules/sigma/<your-file>.yml
```

The hard CI gates you'll hit otherwise: schema validation, `detect_id` uniqueness,
version-bump discipline, and SPL syntax parsed against Splunk's own parser. See
[`scripts_reference.md`](docs/architecture/scripts_reference.md) for each.

### 7. Open a pull request against `dev`

CI (`ci_dev_workflow.yml`) validates → converts to `.spl` → deploys to the dev
Splunk app → runs the attack → queries Splunk for a real hit → writes a
PASS / FAIL / NOT_VERIFIED verdict. The full stage-by-stage narrative is
[`docs/architecture/pipeline_overview.md`](docs/architecture/pipeline_overview.md);
the artefacts moving between stages are in
[`data_flow.md`](docs/architecture/data_flow.md).

If the lab is offline (`LAB_ONLINE=false`), the push still validates, converts and
commits its SPL; deploy/attack/verify are skipped and picked up later by a manual
`workflow_dispatch` run.

### 8. Review

Rule *quality* — logic soundness, false-positive realism, ATT&CK tag accuracy,
overlap with existing rules, test coverage — is judged by a reviewer (Bjorn, via
the lead), separate from the author. CI's schema and pass/fail checks don't cover
that judgment layer. See
[`agent_workflow.md`](docs/architecture/agent_workflow.md#the-review-gate).

### 9. Promotion to production

On an overall PASS, the pipeline opens a `dev` → `main` promotion PR
(labelled `automated-promotion`, added to the project board as `In review`).
**A human reviews and merges it** — nothing ships automatically.

### 10. Production deploy

Merging the promotion PR triggers `ci_prod_workflow.yml`, which verifies the build
provenance of every `.spl` and deploys the already-verified queries to the prod
Splunk app. `main` never re-tests — it trusts what `dev` proved.

---

## Changing or retiring an existing rule

- **Editing logic**: same flow; the version bump (step 5) makes the old verdict
  count as *Superseded* until the pipeline re-measures the rule.
- **Renaming (title change)**: produces a new Splunk saved-search name;
  `reconcile.py --apply` deletes the orphaned old object automatically on the next
  dev run.
- **Deleting a rule**: `prune_orphans.py` removes its `.spl` and results;
  `reconcile.py --apply-removals` (manual) disables the live Splunk object.
- **Parking a rule**: set `status: deprecated` — the deploy skips it and reconcile
  drops it from desired state.

See the "Retirement" section of
[`pipeline_overview.md`](docs/architecture/pipeline_overview.md#retirement-the-reverse-path).

---

## A note on the `author:` field

The `author:` field records real accountability for the rule (audit/legal
provenance). Set it to a real identity — never a team persona or working-identity
name.

---

## Reference

- [`docs/architecture/pipeline_overview.md`](docs/architecture/pipeline_overview.md) — end-to-end pipeline narrative
- [`docs/architecture/data_flow.md`](docs/architecture/data_flow.md) — the files and artefacts between stages
- [`docs/architecture/scripts_reference.md`](docs/architecture/scripts_reference.md) — what every script does
- [`docs/architecture/threat_model.md`](docs/architecture/threat_model.md) — scope and credential handling
- [`docs/architecture/agent_workflow.md`](docs/architecture/agent_workflow.md) — how the maintainer team is coordinated
- [`.claude/skills/sigma-rule-authoring/`](.claude/skills/sigma-rule-authoring/SKILL.md) and [`.claude/skills/mitre-attack-mapping/`](.claude/skills/mitre-attack-mapping/SKILL.md) — the authoring playbooks
