---
description: Scaffold a new Sigma rule and carry it through Yuki (author) to Bjorn (review)
argument-hint: <rule title>
---

Take `$ARGUMENTS` as the new rule's title (ask for one if it's empty — don't
guess a title for a detection nobody asked for).

1. Scaffold it: `python scripts/new_rule.py "$ARGUMENTS"` — this allocates
   the next free `detect_id` and writes a schema-valid skeleton under
   `rules/sigma/`.
2. Dispatch `yuki-detection-engineer` (Yuki) with the scaffolded file path
   and whatever intent/context prompted this rule (a coverage gap from
   Yara, a CTI finding from Masha, or a direct ask) so she's not filling in
   detection logic blind. She follows the `sigma-rule-authoring` and
   `mitre-attack-mapping` skills for this repo's conventions.
3. Once Yuki reports the rule finished, dispatch `bjorn-detection-content-reviewer`
   (Bjorn) to review it — logic soundness, FP risk, MITRE tag accuracy,
   duplication, test coverage. A rule is never done on Yuki's say-so alone.
4. Report back the finished `detect_id`, Bjorn's findings, and whether the
   rule is ready to commit or needs another pass.
