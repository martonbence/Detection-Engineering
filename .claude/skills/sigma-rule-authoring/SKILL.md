---
name: sigma-rule-authoring
description: Use when drafting a new Sigma detection rule for this repo — scaffolding via scripts/new_rule.py and filling it in per the repo-specific conventions that validate_sigma.py, check_mitre_tags.py and check_version_bump.py enforce (detect_id allocation, author field, custom.splunk.raw_query fallback, schema-valid placeholders, version bump discipline).
---

Repo-specific conventions for authoring a new rule under `rules/sigma/`,
distilled from `scripts/new_rule.py` and an existing rule so a new one is
schema-valid and review-ready on the first pass.

## Always scaffold, never copy-paste

Start from:

```
python3 scripts/new_rule.py "Rule Title Here"
```

(check `--help` for current flags before assuming the signature). It
computes the next free `detect_id` from this checkout and writes a
schema-valid skeleton — every placeholder already satisfies
`docs/schemas/sigma_schema.json`'s length/pattern constraints, so
`validate_sigma.py` passes on the untouched skeleton. Hand-picking a
`detect_id` from a copy-pasted rule risks a collision with a parallel
branch; `check_detect_id_uniqueness.py` in CI is the real backstop, but
catching it locally saves a review round-trip.

## The one field you don't touch: `author:`

`DEFAULT_AUTHOR` in `new_rule.py` is hardcoded, not read from git config,
specifically because rule authorship is a real accountability fact for this
project — not a per-session detail. Leave `author:` exactly as the script
or the user set it. **Never write a team persona name (e.g. "Yuki") into
this field** — see `CLAUDE.md` rule 6.

## Fill every TODO — enum fields need a real value, not the literal string

`level`, `custom.splunk.mode`, `custom.splunk.severity`, and
`custom.testing.runner` are schema enums with no free-text branch: a literal
`"TODO"` fails `validate_sigma.py`. Pick a real, reviewable value and mark it
`# TODO: review` in a comment instead — that's the pattern the skeleton
itself uses. `title`, `description`, `tags`, `logsource`, `detection`, and
`falsepositives` are free-text and can carry a literal TODO placeholder
until filled.

## Detection logic: `detection:` block vs. `custom.splunk.raw_query`

Use Sigma's `detection:` selection/condition block by default — it's what
`sigma_to_spl.py` converts. Fall back to `custom.splunk.raw_query` (raw SPL,
emitted verbatim by the converter) only when the logic is genuinely too
sophisticated for Sigma's block syntax to express. Even then, keep the
`detection:` block populated with its required placeholder — the schema
demands it, but it is never actually evaluated for a `raw_query` rule.

## `version:` — auto-bumped when the detection changes, not when the words do

Every rule carries an explicit `version:` field (`"MAJOR.MINOR"`, e.g.
`"1.0"` on a freshly scaffolded rule — see `new_rule.py`'s skeleton). As of
2026-08-29 (register item 3.5, closed for real) this is the **only** version
number for a rule — the old, separate git-commit-count-derived `rule_version`
(`scripts/lib/rule_version.py`) is gone, and `.meta.json`'s `rule_version`
now reads straight from this same field. You normally never type it by
hand: `.githooks/pre-commit` bumps it automatically the moment a commit
actually changes the detection (see the field list below), and respects a
version you already changed yourself (e.g. jumping straight to `2.0` for a
rewrite) rather than overwriting it.

`scripts/validate/check_version_bump.py` (register item 3.5) remains the
CI-side backstop — it fails the run (hard gate, no `--strict` — same
contract as `check_detect_id_uniqueness.py`) if a push changes any of the
following without `version:` also having changed from what the same file
carried at the base commit. It exists for the cases the hook can't reach:
`--no-verify`, a fresh clone before the one-time `git config
core.hooksPath .githooks` setup, or a rule edited through the GitHub web UI.
In the normal local-commit case you shouldn't need to think about this at
all:

- `detection:` — the matching logic itself.
- `logsource:` — which events the logic even runs against; repointing this
  can silently detect nothing, which is as much a behaviour change as the
  condition.
- `custom.splunk.raw_query` — for a raw-SPL rule this *is* the detection
  logic (see the section above); `detection:` on that rule is an unused
  placeholder the checker deliberately ignores.

Editing `description`, `references`, `falsepositives`, `tags`, `status`,
`level`, `fields`, or anything under `custom.testing` / `custom.splunk`
other than `raw_query` does **not** trigger a bump — that was the original
complaint this register item opened with (a wording fix and a rewritten
condition: block used to look identical to the version number).

## Tagging and handoff

Tag `attack.<tactic>` / `attack.tXXXX(.YYY)` using the
[[mitre-attack-mapping]] skill — don't tag from memory of upstream ATT&CK,
this repo's tactic vocabulary and cache diverge from it. Before calling a
rule done, run `scripts/validate/validate_sigma.py` and
`scripts/validate/check_mitre_tags.py` locally if feasible (the version
bump on an existing rule is handled automatically by `.githooks/pre-commit`
at commit time — see above — so there's normally nothing to run for that
yourself), then hand the rule to the Detection Quality Engineer for review.
A newly authored rule is never self-approved or merged straight through.
