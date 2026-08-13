---
name: mitre-attack-mapping
description: Use when assigning, verifying, or reviewing an attack.tXXXX(.YYY) technique tag or an attack.<tactic> tag on a Sigma rule in this repo. Confirms the tag is valid in this repo's own ATT&CK vocabulary before judging whether it semantically matches the detection logic.
---

Grounds MITRE ATT&CK tagging decisions in what this repo actually checks,
instead of recalling ATT&CK from training data — the repo has its own
cached technique map and its own tactic vocabulary, and both diverge from
upstream ATT&CK in ways that matter.

## Step 1 — check this repo's vocabulary before assuming a typo

`scripts/validate/check_mitre_tags.py` is the CI gate for tag validity. It
reads a cached technique map at `outputs/reports/mitre_technique_map.json`
(the same cache `generate_stats.py` builds for the coverage matrix/Navigator
layer, 7-day TTL) — it does **not** hit the network. Read that cache (or run
the checker) before flagging a tag as wrong:

```
python scripts/validate/check_mitre_tags.py --strict
```

Two things this repo does differently from upstream ATT&CK:

- **Tactic vocabulary is derived from the cache, not upstream's list.**
  `Stealth` and `Defense Impairment` are valid tactics *here* (`attack.stealth`,
  `attack.defense_impairment`) where upstream ATT&CK has `Defense Evasion`.
  Do not flag `attack.stealth` as invalid — it is real in this project's
  taxonomy.
- **Revoked/deprecated techniques are simply absent from the cache**, which
  looks identical to a typo unless you know the numbering rule: main
  technique IDs are sparse (revoked look like a normal gap), but
  sub-technique IDs under a parent are dense with no reuse after
  retirement — an absent sub-technique *inside* its parent's allocated
  range was retired; one *above* the range was never allocated. Use this
  before assuming a sub-technique tag is simply wrong.

## Step 2 — judge semantic fit against the real technique page

Tag *existence* in the cache doesn't mean it's the *right* tag for the
rule's actual logic. For that judgment, WebFetch
`https://attack.mitre.org/techniques/<ID>/` and compare its description
against the rule's `detection:` block (or `custom.splunk.raw_query` text)
and its `title`/`description` — not just against the prose claim.

## Step 3 — prefer the most specific sub-technique the logic actually supports

A parent technique tag (`attack.t1059`) is valid but under-specific if the
detection logic clearly targets one sub-technique's mechanism (e.g.
PowerShell specifically → `attack.t1059.001`). Don't downgrade to the parent
just to be safe — check whether the `detection:` selection is narrow enough
to justify the sub-technique, and tag it if so.

## Output

State, per tag: valid-in-cache (yes/no, with the revoked/never-allocated
distinction from Step 1 if absent), and semantic-fit verdict from Step 2/3
with the one-line reason. Don't just say "looks fine."
