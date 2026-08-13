---
name: sigma-rule-authoring
description: Use when drafting a new Sigma detection rule for this repo — scaffolding via scripts/new_rule.py and filling it in per the repo-specific conventions that validate_sigma.py and check_mitre_tags.py enforce (detect_id allocation, author field, custom.splunk.raw_query fallback, schema-valid placeholders).
---

Repo-specific conventions for authoring a new rule under `rules/sigma/`,
distilled from `scripts/new_rule.py` and an existing rule so a new one is
schema-valid and review-ready on the first pass.

## Always scaffold, never copy-paste

Start from:

```
python scripts/new_rule.py --title "..."
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

## Tagging and handoff

Tag `attack.<tactic>` / `attack.tXXXX(.YYY)` using the
[[mitre-attack-mapping]] skill — don't tag from memory of upstream ATT&CK,
this repo's tactic vocabulary and cache diverge from it. Before calling a
rule done, run `scripts/validate/validate_sigma.py` and
`scripts/validate/check_mitre_tags.py` locally if feasible, then hand the
rule to the Detection Quality Engineer for review. A newly authored rule is
never self-approved or merged straight through.
