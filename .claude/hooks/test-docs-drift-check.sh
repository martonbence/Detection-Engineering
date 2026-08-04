#!/usr/bin/env bash
# Tests for docs-drift-check.sh. Run it directly:
#
#   bash .claude/hooks/test-docs-drift-check.sh
#
# Builds a throwaway git repository in a temp directory so the positive cases
# can be exercised against real commits, and asserts on the hook's stdout.
# The hook must be silent in every case except the last two.

set -u

HOOK=$(cd "$(dirname "$0")" && pwd)/docs-drift-check.sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0

check() {
  local name=$1 expected=$2 actual=$3
  if [ "$expected" = "$actual" ]; then
    printf '  PASS  %s\n' "$name"
    pass=$((pass + 1))
  else
    printf '  FAIL  %s\n        expected: %s\n        actual:   %s\n' "$name" "$expected" "$actual"
    fail=$((fail + 1))
  fi
}

# "silent" or the list of files named in the systemMessage.
run_hook() {
  local command_json=$1
  local out
  out=$(printf '{"tool_name":"Bash","tool_input":{"command":"%s"}}' "$command_json" | bash "$HOOK" 2>/dev/null)
  if [ -z "$out" ]; then
    echo "silent"
  else
    printf '%s' "$out" | python -c 'import json,sys; print(json.load(sys.stdin)["systemMessage"])'
  fi
}

cd "$TMP"
git init -q .
git config user.email test@example.com
git config user.name test

echo "docs-drift-check.sh"

# --- cases that must stay silent, evaluated before any commit exists ---------

check "no git commit in the command" \
  "silent" "$(run_hook 'cd x && git log --oneline && cat README.md')"

check "no commit has ever landed" \
  "silent" "$(run_hook 'git commit -m x')"

# --- root commit touching watched paths -------------------------------------
# Also the regression case for `git diff-tree -r HEAD`, which returns nothing
# for a parentless commit and made this pass silently regardless of content.

mkdir -p scripts/deploy .github/workflows docs
echo a > scripts/deploy/deploy_spl_to_splunk.py
echo b > .github/workflows/ci_dev_workflow.yml
echo c > docs/notes.md
git add -A
git commit -qm "root commit touching scripts and workflows"

check "root commit touching watched paths reports them" \
  "Docs check: this commit touched .github/workflows/ci_dev_workflow.yml, scripts/deploy/deploy_spl_to_splunk.py" \
  "$(run_hook 'git commit -m x')"

check "a command that only mentions committing is ignored" \
  "silent" "$(run_hook 'echo how to git log things')"

# --- a commit touching nothing the docs describe ----------------------------

echo d >> docs/notes.md
git commit -qam "docs-only commit"

check "docs-only commit stays silent" \
  "silent" "$(run_hook 'git commit -m x')"

# --- the freshness gate ------------------------------------------------------
# Same repository, same commit, but now treated as old: this is what stops the
# hook re-reporting one commit on every later Bash call.

echo e > scripts/new_thing.py
git add -A
git commit -qm "fresh commit touching scripts"

check "fresh commit touching scripts reports it" \
  "Docs check: this commit touched scripts/new_thing.py" \
  "$(run_hook 'git commit -m x')"

check "the same commit is silent once it is no longer fresh" \
  "silent" "$(DOCS_DRIFT_MAX_AGE_SECONDS=0 run_hook 'git commit -m x')"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
