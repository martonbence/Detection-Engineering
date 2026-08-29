---
description: Regenerate stats.json / README block / rule browser locally and show whether the change is substantive
---

Regenerate the dashboard locally and determine whether the output actually
changed, mirroring the check `ci_code_checks.yml`'s `regenerate_console`
job runs in CI (which compares with timestamps and commit SHAs normalized
out, since two runs over identical sources are never byte-identical).

1. Run `python scripts/docs/generate_stats.py` from the repo root.
2. Check what it touched: `git status --porcelain -- outputs/reports/ README.md docs/index.html`
   (deliberately excludes `outputs/results/` — those are verdicts owned by
   the verification pipeline, not this generator's output).
3. If nothing is listed, report "byte-identical, nothing to publish" and stop.
4. Otherwise, for each changed file, diff it against `HEAD` with timestamps
   and commit SHAs normalized away before deciding whether the change is
   substantive:
   ```bash
   normalize() {
     sed -E \
       -e 's/\r$//' \
       -e 's/[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})?/<TIMESTAMP>/g' \
       -e 's/[0-9a-f]{40}/<SHA>/g'
   }
   diff <(git show "HEAD:$f" | normalize) <(normalize < "$f")
   ```
5. Report per file: "generation-timestamp noise only" or "substantive
   change" with a short summary of what changed (e.g. a rule count, a new
   MITRE badge, a coverage-history point).

This is a local sanity check before committing — it does not commit or
push anything itself. If Sienna is mid-edit on the rule browser, this is
also the fastest way for her to confirm a change actually rendered
differently rather than just re-stamping the same output.
