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

## Testing: prefer a real Atomic Red Team test over writing a custom command

`custom.testing.type` is `atomic` or `emulation`. Default to `atomic` and
cite a real test from `redcanaryco/atomic-red-team` — reach for `emulation`
(a hand-written `custom[]` command) only when no atomic exists for the
technique, or a real check (below) rules every existing one out. A
hand-written command is more code to trust and re-verify than a test the
community has already run; don't default to it out of habit when a real
atomic is sitting right there.

"A real atomic exists for this technique" is not the bar, though —
**"this specific atomic produces the telemetry this specific rule's
detection logic keys on"** is. Use [[technique-research-sources]]'s
guidance to open the actual atomic YAML/Markdown and read what the test's
command really does before citing its number, then check that against what
the rule matches, not just against the technique ID both share. A test can
be entirely real and on-topic for the technique and still be the wrong
fit for a *particular* rule:

- **DETECT-2026-0033** (T1557.001, victim-side detection: a DNS failure
  immediately followed by an SMB connection) is `type: emulation` on
  purpose, not from having skipped this check. T1557.001's real atomic
  (test 1, "LLMNR Poisoning with Inveigh") is a genuine, correctly-scoped
  atomic for the technique — it just detects the wrong side of it for this
  rule. It stands up the *poisoner* on the runner it executes on; it does
  not make that same host (or any other) issue the *victim* query the
  rule's correlation needs, and this repo's pipeline runs every rule's
  test against exactly one runner (`atomic_verify`/`atomic_verify_dc` in
  `ci_dev_workflow.yml` — no job orchestrates two hosts attacking each
  other for a single rule's test). That atomic is the right citation for a
  *different*, tool-execution-based rule instead — and indeed is exactly
  what **DETECT-2026-0034** (Network Sniffing and AiTM Tooling Execution,
  a Sysmon EID 1 rule) cites it for: run alone on one runner, "start
  Inveigh" is precisely the process-creation event that rule's
  `selection_inveigh` matches, no second host required.
- The general shape: an atomic that reproduces the **attacker's own
  action** fits a rule that detects that action. A rule that detects the
  **victim's or a bystander's resulting behavior** (a downstream log
  failure, a second host's reaction, an environmental side effect) usually
  has no matching atomic, because Atomic Red Team tests are single-host
  attacker actions by design — that gap is a legitimate, real reason to
  write a custom emulation command instead, not a shortcut taken to avoid
  the research.

When you do fall back to `emulation`, the custom command should still be
the minimal, safe reproduction of *only* the telemetry the rule's
detection logic actually consumes (see the LSASS rules' emulation tests
for the established pattern) — not a scaled-down attempt at the real
attack chain.

**A real atomic covering only "the attacker's half" of a multi-host chain
is not necessarily wasted — it just doesn't belong in `custom.testing`.**
DETECT-2026-0033's case again: the lab this repo targets happens to have
both a DC and a victim host on the same segment, so the *actual* attack
chain (Atomic Red Team's real Inveigh test on one host, a genuine
NetBIOS-name lookup forced on the other) can be run for real, by hand —
just not encoded as `custom.testing.atomics`, because CI only ever
executes one rule's test against one runner, so citing it there would
have CI run the atomic alone and get a guaranteed, uninformative FAIL. The
right move in that situation: keep `custom.testing.type: emulation` (what
CI actually runs), and add a plain YAML comment above `testing:` spelling
out the manual two-host procedure — which host does what, what to check
in Sysmon on the victim side, and the cleanup step (stop the poisoner
promptly — it answers every broadcast on the segment while running, not
just the test's). This gets the real atomic used where it's genuinely
applicable (a one-time manual confirmation) without corrupting the
automated test field with something that cannot pass automatically.

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

## Linking a finished rule to the ATT&CK notes vault

Separate from the pipeline, this repo carries a personal Obsidian study
vault at `personal/MITRE-Notes/`. Whenever a rule is created, finished, reviewed, or
has its `attack.*` tags or detection logic changed, use the
[[mitre-notes-vault]] skill to check whether the vault needs a
cross-reference update — do this on your own, not only when asked.
