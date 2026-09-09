---
name: technique-research-sources
description: Use before finalizing a new Sigma rule's detection logic (or judging one during review) — check these sources for the technique's real-world command syntax, tool signatures, and any existing rule someone else already wrote for it, instead of inventing patterns from memory. Complements sigma-rule-authoring (repo conventions/schema) and mitre-attack-mapping (tag validity/fit) — this skill is about the detection *content* itself: does the selection actually match what attackers really run.
---

Seven sources, each answering a different question a new rule's `detection:`
block should be checked against before it's considered finished. None of
these are optional "nice to check" — skipping the existing-rule check
(1-2) risks reinventing a worse version of a pattern the community already
hardened; skipping the real-syntax check (3-6) risks a rule built on a
guessed command line that doesn't match what the tool actually outputs.

## 1 — Has someone already written this rule? Check first, not last.

**detection.fyi** (`https://detection.fyi/`) — a search engine over SigmaHQ
and other public Sigma rule sets. Search the technique or tool name before
drafting `detection:` from scratch. An existing public rule is free,
reviewed prior art: its field names, its false-positive list, its exact
`contains`/`re` boundary choices are usually the product of someone else's
already-paid-for mistakes.

**SigmaHQ repo** (`https://github.com/SigmaHQ/sigma`) — the raw source
detection.fyi indexes. Go here (not just detection.fyi's summary) when you
need the actual YAML: exact field names for a log source you're unfamiliar
with, how they structure a multi-selection `condition:`, what they put in
`falsepositives:` for a similar rule. This repo's own `rules/sigma/*.yml`
schema and conventions were shaped by this ecosystem — matching its idioms
where they fit makes a new rule easier for Bjorn to review, not just easier
to write.

## 2 — What does this technique actually look like when someone runs it?

**HackTricks** (`https://hacktricks.wiki/en/index.html`) — broad
pentesting/red-team technique wiki with concrete command examples for a
huge range of exploitation and post-exploitation techniques. Use it to get
the *actual* syntax real tools use (flag names, argument order, common
variants) rather than guessing from a technique's English description.

**ired.team** (`https://www.ired.team/`) — red-team notes covering
internals, credential access, execution, and persistence techniques in
technical depth, often closer to "here's the API call sequence" than
HackTricks' more command-line-first style. Reach for this when the
technique is really about an API/internals-level behavior (e.g. a specific
Win32 call sequence) rather than a single command line.

## 3 — What does the atomic test for this technique actually execute?

**Atomic Red Team atomics** (`https://github.com/redcanaryco/atomic-red-team/tree/master/atomics`,
raw YAML at `.../atomics/<TID>/<TID>.yaml`) — the source this repo's own
`custom.testing.atomics` test_numbers reference. Before writing
`detection:`, fetch the relevant technique's YAML and read the actual
`executor`/`command` text of the tests you're likely to cite — don't assume
a test's *name* implies it runs the command variant your rule expects (this
repo hit exactly that gap 2026-09-07 authoring DETECT-2026-0033: an atomic
literally named "Netcat C2" turned out not to use the `-e` flag the rule's
`selection_netcat` matches on, and would not have fired it). Reading the
YAML first prevents citing a mismatched test number or wrongly assuming
atomic coverage exists for a branch it doesn't.

## 4 — Is this actually a living-off-the-land binary being abused?

**LOLBAS** (`https://lolbas-project.github.io/`) — the living-off-the-land
binaries/scripts project for Windows: which built-in Windows binaries can
be abused for execution, download, bypass, etc., and the exact command
forms that trigger each abuse. Check this whenever a rule's premise is
"a normal Windows binary being used in an abnormal way" (rundll32, mshta,
certutil, regsvr32, and dozens more) — this repo's logsource is
Windows/sysmon almost exclusively, so this is a high-hit-rate source here.
(No Linux/Unix equivalent — GTFOBins — is in this list yet; add it if this
repo ever gains Linux-scoped rules.)

## 5 — Does Splunk's own team already have prior art for this, in SPL?

**Splunk Security Content** (`https://github.com/splunk/security_content`)
— Splunk's own maintained detection-rule and "Analytic Story" collection,
native SPL rather than Sigma. Since this repo's whole pipeline compiles
down to SPL and deploys to Splunk, a matching Analytic Story here is more
directly comparable than a generic Sigma rule: read its search logic and
its notes on false positives/tuning before assuming this repo's Sigma ->
SPL conversion is the only reasonable way to express the query.

## How these fit together on a real rule

1. Search **detection.fyi** / skim **SigmaHQ** and **Splunk Security
   Content** for existing coverage of the technique — don't start from a
   blank `detection:` block if solid prior art exists.
2. Pull the technique's real command syntax from **HackTricks** /
   **ired.team** (or **LOLBAS** specifically for living-off-the-land
   binary abuse) — this is what the actual `contains`/`re` values should be
   built from, not a paraphrase of the technique's name.
3. Before setting `custom.testing.atomics`, open the real **Atomic Red
   Team** YAML for the cited technique and read the test's actual
   `command:` — confirm it produces the string your `detection:` matches,
   don't infer from the test's title.

This complements, not replaces, the [[sigma-rule-authoring]] skill (repo
schema/scaffold conventions) and [[mitre-attack-mapping]] skill (whether a
tag is valid and semantically fits) — those two are about the rule's
*shape*; this one is about whether its *content* reflects how the
technique is actually carried out and whether someone already solved it.
