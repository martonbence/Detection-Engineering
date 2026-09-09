---
name: mitre-notes-vault
description: Use whenever a Sigma rule in rules/sigma/ is created, finished, reviewed, or has its detection logic or attack.* tags changed — check whether personal/MITRE-Notes/ (the user's personal Obsidian ATT&CK study vault, committed to this repo) needs a cross-reference update, and make it without being asked first. Also use when drafting or editing any note inside personal/MITRE-Notes/ (Tactics/, Techniques/, Subtechniques/), to follow its established structure, templates, and house style instead of re-deriving it.
---

`personal/MITRE-Notes/` is the user's own Hungarian-language study vault on ATT&CK
tactics/techniques/sub-techniques, edited mainly in Obsidian, committed to
this repo so it follows the user across devices. No CI workflow's `paths:`
filter matches `personal/MITRE-Notes/**` and no pre-commit hook touches it, so
nothing here is a pipeline gate — this is upkeep, not validation.

Three separate jobs fall under this skill: **(A) keeping the vault in sync
every time a rule changes** — the part that should happen on its own, not
on request — **(B) writing vault content in the repo's own house style**,
for when you are asked to draft or edit a note directly, and **(C) grounding
that content in real sources** rather than memory alone.

## A — Sync the vault whenever a rule changes

Treat this the same way you'd treat running `validate_sigma.py` before
calling a rule done: a routine last step, not a favor to remember to ask
for. Trigger on any of: a new rule file lands in `rules/sigma/`, an
existing rule's `detection:` / `custom.splunk.raw_query` changes, its
`attack.*` tags change, or a rule finishes Bjorn's review.

1. Read the rule's `attack.tXXXX(.YYY)` and `attack.<tactic>` tags.
2. For each `attack.tXXXX.YYY` tag, look for
   `personal/MITRE-Notes/Subtechniques/TXXXX.YYY - *.md`. If it exists:
   - Add the `detect_id` to its `rules:` frontmatter list (if not already
     there).
   - Add or update a row in its "Kapcsolódó szabályok" table. The
     `detect_id` cell is always a GitHub link to the actual file:
     `[DETECT-2026-XXXX](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/<exact filename>.yml)`
     — link to `main` (where deployed rules actually live), not `dev`.
   - If a "Nem fedett" (not covered) line in that note now names something
     the new/changed rule covers, trim it.
3. For a tag with no sub-technique (`attack.tXXXX` only), do the same
   against `personal/MITRE-Notes/Techniques/TXXXX - *.md` instead.
4. If the technique note *also* keeps its own aggregate "Kapcsolódó
   szabályok" table across all sub-techniques (check the note itself — not
   every technique note necessarily has one), update that row too.
5. Only touch a tactic-level note's "Lefedettség ebben a repóban" prose
   when the change is real (e.g. the first rule for a previously-uncovered
   technique) — don't rewrite it for a rule that just adds another entry
   to an already-covered technique.
6. **Never scaffold a brand-new tactic/technique/sub-technique note as a
   side effect.** If the tagged technique or sub-technique has no note yet,
   skip it silently (or mention it in one line when reporting back) — the
   note's actual content is the user's own study writing, per
   [[sigma-rule-authoring]]'s framing of rule authorship. You only ever add
   the cross-reference to a note that already exists.
7. A rule *edit* that only touches tags (e.g. a correction from
   `attack.t1003` to the more specific `attack.t1003.001`) still triggers
   this — move the cross-reference to the newly-correct note, don't leave
   a stale reference behind on the old one: remove the row and the
   `detect_id` from `rules:` on the note(s) it no longer belongs to, per
   point 8, before adding it to the newly-correct one.
8. **The sync also runs backwards, on removal.** If a rule that was
   cross-referenced in the vault is deleted from `rules/sigma/`, or a
   retag (point 7) moves its tag away from a sub-technique/technique it
   used to be tagged with, remove the stale entry from every note that
   still references it: drop the `detect_id` from that note's `rules:`
   frontmatter list and delete its row from the "Kapcsolódó szabályok"
   table. Re-add the method to "Nem fedett" only if the note's prose
   already described what that specific rule covered and nothing else in
   the table covers it anymore — don't invent new "Nem fedett" text that
   wasn't already implied by the note.

## B — House style when writing vault content

- **Structure:** `Tactics/`, `Techniques/`, `Subtechniques/`, `Alapfogalmak/`
  (recurring concepts), `Templates/` (the three note templates — always
  start a new note from one of these, never freehand the frontmatter).
- **Hierarchy links are real `[[wikilinks]]`**: tactic ↔ technique ↔
  sub-technique, and technique ↔ related concept. This is what makes the
  graph view cluster by tactic.
- **Tactics are never wikilinked to each other — this is a hard rule, not
  a style nicety.** The "Hely a támadási láncban" (Előtte/Utána) block on a
  tactic note, and the "Mihez vezet" block on a technique note (which names
  the *next* tactic), both use a single-bracket `[TAxxxx - name]`
  reference. A `[[wikilink]]` there would connect two tactic clusters
  through that one node in graph view, which the user explicitly does not
  want (2026-09-08).
- **Keep established English DE jargon in English — don't force a
  Hungarian translation that reads worse than the loanword.** "Kerberos
  ticket", not "Kerberos jegy"; "cleartext jelszó", not "nyílt szövegű
  jelszó"; tactic names stay English (Lateral Movement, Initial Access,
  privilege escalation). Well-worn Hungarian security terms are fine to
  keep Hungarian — "hitelesítő adat" (credentials), "tanúsítvány"
  (certificate), "sérülékenység" (vulnerability). The test: would a
  Hungarian SOC analyst actually say it this way out loud, or does the
  translation only exist on the page?
- **Technique notes carry a "## Mihez vezet" section**, placed after the
  definition and before "Altechnikák": one short paragraph on what the
  attacker does with a successful run of this technique — which tactic
  comes next, and one sentence on that tactic's goal. Single-bracket
  tactic reference, per the rule above.
- **Two distinct "Kapcsolódó ..." sections, never merged:**
  "Kapcsolódó szabályok" (this repo's actual Sigma rules, as a table with
  GitHub-linked `detect_id`) and "Kapcsolódó jegyzetek" (note-to-note links,
  no rule content). On a **sub-technique** note (2026-09-09) the latter holds
  substance only: `Alapfogalmak/` concept links that carry real prerequisite
  knowledge for exploiting the technique, plus the MITRE URL. **No
  parent-technique link** — it's already in `parent_technique:` frontmatter —
  and **no sibling-sub-technique links** — they belong in the technique
  note's "Altechnikák"/"Összehasonlítás", which is the single place
  cross-sub comparison lives; don't duplicate it per sibling. **Technique
  notes** get the same trim (2026-09-09): drop the "Taktika" link (it's in
  `tactic:` frontmatter) and the "Altechnikák" list (it's the body
  "## Altechnikák" section) — keep "Rokon technikák" (real cross-technique
  relationships), "Fogalmak", and the MITRE URL. Tactic notes have no
  "Kapcsolódó jegyzetek" section, so nothing changes there.
- **"Mitigáció" stays, but framed for detection engineering, not hardening
  compliance** (2026-09-08 — this is a DE repo, not a hardening one). A
  control only belongs in this section if it answers a question the
  *rule* needs answered: does it remove the technique's precondition
  entirely (tells you which environments the rule is even relevant in —
  e.g. LLMNR disabled means Responder has nothing to answer), does it
  block the technique's *effect* without stopping the attempt (this is
  literally false-positive/scope information for the rule — e.g. SMB
  Signing means the relay fails silently on hardened targets even though
  the poisoning happened), or is it *not* applicable here (that's the
  reason the rule is the only defense, worth saying explicitly). Leave out
  generic security-awareness advice or a bare compliance-framework
  citation (NIST/CIS control number) that doesn't tie back to what the
  rule does or doesn't catch. At the technique level, keep this even
  shorter — only which sub-technique a control effectively closes off
  entirely (not worth a rule) versus which remains the real detection
  target; full per-method mitigation detail belongs on the sub-technique
  note, not duplicated at the technique level.
- **"Hogyan csinálják a gyakorlatban" for a multi-actor technique names the
  actors first.** When a technique involves more than one host/role (an
  attacker box, a victim, a separate target the attacker pivots to —
  T1557.001's relay path is the worked example: A the poisoning proxy, B
  the victim, C the relay's actual target), open the section with one
  short paragraph naming them by letter or role before any commands, so
  the rest of the section can say "on B" instead of re-describing who B is
  every time. Skip this for a single-host technique (T1003.001's LSASS
  dump has no second actor). Each named execution method then gets its own
  `### Subheading` (not a bold lead-in) — matches this note's own
  `### Szükséges telemetria` / `### Detekciós logika` pattern one level up,
  and shows up in Obsidian's outline pane. Close with a plain (non-heading)
  "Mi váltja ki a gyakorlatban" paragraph — the mundane, non-malicious
  situation that actually produces the technique's precondition (a failed
  name lookup, a mistyped path) — because that's what makes the technique
  real rather than theoretical.
- Worked reference for depth and shape: `personal/MITRE-Notes/Subtechniques/T1003.001
  - LSASS Memory.md` (single-actor) and `personal/MITRE-Notes/Subtechniques/T1557.001
  - LLMNR-NBT-NS Poisoning and SMB Relay.md` (multi-actor, role-labeled) —
  and `personal/MITRE-Notes/Techniques/T1003 - OS Credential Dumping.md` at the
  technique level.

## C — Ground note content in real sources, not memory alone

A study note is worse than no note if it teaches a plausible-sounding but
wrong command or a made-up GPO path. Use the same discipline
[[technique-research-sources]] already establishes for Sigma rule content —
its seven sources (detection.fyi, the SigmaHQ repo, HackTricks, ired.team,
Atomic Red Team's atomics YAML, LOLBAS, Splunk Security Content) apply
here just as directly: they're exactly where "Hogyan csinálják a
gyakorlatban" and "Detekciós logika" content should come from — the real
tool syntax, the real field names, the real command a technique actually
looks like when someone runs it. Check them the same way you would before
finalizing a rule's `detection:` block.

Two more, specific to vault notes because they answer questions a Sigma
rule doesn't ask:

- **attack.mitre.org's own Detection and Mitigations tabs** on the
  technique's page (not just the one-line definition already quoted in
  every note's `> [!quote]` block) — read these before writing a note's
  own "Mitigáció" and "Detekciós stratégia" sections. MITRE's own
  data-component/mitigation list is the baseline; the note should build on
  it with repo-specific reasoning, not silently diverge from it.
- **Microsoft Learn / official Microsoft documentation** for any concrete
  Windows administrative claim a note makes — an exact GPO path, a
  registry key, an `auditpol` subcategory name, a DHCP option number.
  These are the kind of specific, checkable facts that are easy to get
  subtly wrong from memory (a slightly-off GPO path reads exactly as
  confidently as a correct one) and cheap to verify against the vendor's
  own current docs.

## See also

[[sigma-rule-authoring]] (this repo's rule-authoring conventions) and
[[mitre-attack-mapping]] (tag validity) — this skill is the third leg:
once a rule exists and is tagged, this is what keeps the study vault
pointing at it. [[technique-research-sources]] is the source list this
skill's part C points back to.
