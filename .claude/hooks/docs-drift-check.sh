#!/usr/bin/env bash
# Post-commit documentation reminder. Deterministic: no LLM, no agent, no
# network. Reads the PostToolUse hook payload on stdin and, when a commit has
# just touched code the architecture docs describe, prints one JSON object
# asking for the docs to be checked.
#
# Why this is a plain script rather than an `agent` hook: the pipeline in this
# repo is agent-independent by design, and an agent hook fired a model call on
# *every* Bash tool call -- its `if` filter did not actually filter -- then
# surfaced its own decision to do nothing as a blocking error. The work here is
# three git commands and a path match; it does not need judgement, and anything
# that runs this often must not depend on a model being available.
#
# Contract: always exits 0. This is a reminder, never a gate. Silence is the
# expected outcome; output happens only when all three conditions below hold.

set -u

# 1. Was this even a commit? Cheapest possible check, and the one that ends
#    almost every invocation -- the hook fires on every Bash call, so the
#    common path must cost nothing. Substring only; step 2 does the real work.
payload=$(cat)
case "$payload" in
  *"git commit"*) ;;
  *) exit 0 ;;
esac

cd "$(git rev-parse --show-toplevel 2>/dev/null)" 2>/dev/null || exit 0

# 2. Did a commit actually land? The string above can appear in a command that
#    failed, was quoted, or only mentioned committing. A HEAD that is not fresh
#    means no new commit came from this call -- which is also what stopped the
#    previous version from re-reporting the same old commit forever.
#    Overridable only so the test script can exercise the path below.
max_age=${DOCS_DRIFT_MAX_AGE_SECONDS:-300}
head_ts=$(git log -1 --format=%ct 2>/dev/null || echo 0)
now=$(date +%s)
age=$((now - head_ts))
[ "$head_ts" -gt 0 ] && [ "$age" -ge 0 ] && [ "$age" -lt "$max_age" ] || exit 0

# 3. Did it touch anything the docs describe? These are the paths
#    docs/architecture/*.md and README.md make claims about.
#
#    `git show --name-only` rather than `git diff-tree -r HEAD`: the latter
#    returns nothing for a commit with no parent, so on a repository's very
#    first commit the check would silently pass regardless of content. Caught
#    by the test script, which builds a throwaway repo whose only commit is a
#    root commit.
files=$(git show --pretty=format: --name-only HEAD 2>/dev/null \
  | grep -E '^(\.github/workflows/|scripts/)' || true)
[ -n "$files" ] || exit 0

# Emit through python rather than string-building JSON in shell: a path with a
# quote or a backslash in it would otherwise produce malformed JSON, and a
# malformed hook response is worse than no response.
#
# python3 first, python as fallback: unlike the CI workflows (which run on
# GitHub-hosted runners where actions/setup-python guarantees a bare
# `python`), this hook runs on whatever machine the user's Claude Code
# session is on -- and a `python`-less, python3-only local install silently
# broke this exact step (caught by test-docs-drift-check.sh once actually
# run: `python: command not found`, swallowed by the unconditional `exit 0`
# below, so the hook looked like a correctly-silent no-drift result instead
# of a broken one).
PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python
printf '%s\n' "$files" | "$PY" -c '
import json, sys

files = [line for line in sys.stdin.read().splitlines() if line]
shown = ", ".join(files[:6])
if len(files) > 6:
    shown += f" (+{len(files) - 6} more)"

print(json.dumps({
    "systemMessage": f"Docs check: this commit touched {shown}",
    "hookSpecificOutput": {
        "hookEventName": "PostToolUse",
        "additionalContext": (
            "The commit that just landed touched files the architecture docs describe: "
            + shown
            + ". Check whether README.md and docs/architecture/*.md are still accurate for "
            "what changed -- docs/architecture/scripts_reference.md is the per-file map and "
            "is the most likely to need a new or corrected entry. If the same commit already "
            "updated the docs, or the change does not affect anything they claim, do nothing "
            "and do not mention this. Only report if you actually change something."
        ),
    },
}))
'

exit 0
