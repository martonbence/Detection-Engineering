---
description: Check where the pipeline actually stands against the audit registers, verified against real repo state
---

Dispatch `kwame-audit-compliance` (Kwame) to verify current status against
real repo state — never answer this from memory or a stale summary.

Kwame should check **both** standing registers:
- `audit/remediation-plan.md` (closed 54/54 as of 2026-08-15 — confirm it's
  still closed, not drifted)
- `audit/feature-and-process-audit.md` (the active one — report verified
  open/closed count, any drift between the register and real code or
  `register.html`, and the confirmed next item to pick up)

Report back: verified counts for each register, any drift found and where,
and the real next item — before routing that next item to whichever
specialist owns it.
