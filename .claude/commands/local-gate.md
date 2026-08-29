---
description: Run the full local pre-push gate (lint, tests, schema, MITRE tags, detect_id uniqueness, version bump, test routing)
---

Run this repo's local checks in the same order `ci_code_checks.yml` and the
validation stage of `ci_dev_workflow.yml` do, so a failure surfaces before a
push does. Stop and report at the first failure rather than pushing through
— each of these is a real CI gate, not a style nit.

1. `ruff check .`
2. `pytest`
3. Schema-validate every Sigma rule:
   ```bash
   python scripts/validate/validate_sigma.py --schema docs/schemas/sigma_schema.json rules/sigma/*.yml
   ```
4. `python scripts/validate/check_test_routing.py` (defaults to every rule; warns, doesn't hard-fail without `--strict`)
5. `python scripts/validate/check_detect_id_uniqueness.py`
6. `python scripts/validate/check_mitre_tags.py` (defaults to every rule under `rules/sigma/`)
7. Version-bump check — only meaningful for rules actually changed since the
   base branch, so compute that set first:
   ```bash
   git fetch origin dev
   mapfile -t changed < <(git diff --name-only --diff-filter=AMRC origin/dev...HEAD -- rules/sigma/)
   if [ "${#changed[@]}" -gt 0 ]; then
     python scripts/validate/check_version_bump.py --base-ref origin/dev "${changed[@]}"
   else
     echo "No changed Sigma rules vs origin/dev — nothing to check."
   fi
   ```

Report back: pass/fail per step, and for any failure the exact command output — not a paraphrase — so the fix is obvious without re-running it.
