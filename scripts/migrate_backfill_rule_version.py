#!/usr/bin/env python3
"""
scripts/migrate_backfill_rule_version.py

One-time migration closing out register item 3.5's remaining gap: every rule
under rules/sigma/ already carries a `version:` field, but it is whatever a
human happened to type there over time -- not necessarily what a true
field-diff replay of that rule's history would produce. This script computes
that true value and (with --apply) writes it in.

For every current rule, it walks the file's git history oldest -> newest
(following renames -- this repo dropped the `.sigma.yml` naming partway
through, see commit 99a5b4a) and replays check_version_bump.py's own
logic-diff check (`logic_diff()`, imported from there, not reimplemented)
between each consecutive pair of historical versions of the file. It counts
only the transitions where detection:/logsource:/custom.splunk.raw_query
actually changed -- not every commit that touched the file -- and sets
version: "1.{that count}", 0-indexed the same way the retired scheme was
(1.0 on the commit that added the file and was never logic-edited since), so
every already-published "1.N" value in this repo keeps meaning the same
shape of thing even where the number itself moves.

This is deliberately NOT what scripts/lib/rule_version.py's now-removed
compute_rule_version() did. That counted every commit touching the file --
a typo fix and a rewritten condition: both added exactly one to the same
number. This script counts only the commits that would have tripped
check_version_bump.py's gate: if the .githooks/pre-commit hook and this
check had existed since the rule's first commit, the value this script
computes is the version number the rule would already be carrying.

--follow + --reverse note: this deliberately does NOT ask git for the
history pre-reversed. `git log --follow --reverse` has a long-standing bug
(reproduced against this repo's own history on git 2.43: it silently
truncates --follow's output to a single commit) where combining the two
flags loses history instead of merely reordering it. This asks for the
normal --follow order (newest -> oldest) and reverses the parsed list in
Python instead.

Prints a before (hand-typed) -> after (computed) table for every rule so a
human -- and Bjorn, reviewing this change -- can sanity-check a sample
before trusting ~30 silent rewrites, rather than being asked to trust this
script's arithmetic blind.

This is a migration, run once by hand. It is not wired into CI or into
.githooks/pre-commit -- ongoing correctness from here on is that hook's job,
with check_version_bump.py as its CI-side backstop. Re-running this script
after that point would be actively wrong: it would recompute from full
history again and silently undo any deliberate manual version jump (e.g.
someone jumping straight to 2.0 for a rewrite) that the hook was built to
respect, not override.

Usage:
    python scripts/migrate_backfill_rule_version.py            # report only, no writes
    python scripts/migrate_backfill_rule_version.py --apply    # write the computed values
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT / "scripts" / "validate"))

VERSION_LINE_RE = re.compile(r"^version:\s*.*$", re.MULTILINE)


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def commit_history(repo_root: Path, rel_path: str) -> list[tuple[str, str]]:
    """(commit_hash, path_at_that_commit) pairs, oldest -> newest, following
    renames. See the module docstring for why --reverse is not used here."""
    result = subprocess.run(
        ["git", "log", "--follow", "--name-only", "--format=COMMIT %H", "--", rel_path],
        cwd=str(repo_root), capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        return []

    # Blank lines separate each commit's `--name-only` block from the next
    # `COMMIT <hash>` line, so they are pure separators here, not consumed as
    # part of either the hash or the filename collection.
    pairs: list[tuple[str, str]] = []
    current_hash: str | None = None
    current_names: list[str] = []

    def flush() -> None:
        if current_hash is not None and current_names:
            # A --follow-filtered log's --name-only block for one commit has
            # held exactly one line in every case observed against this
            # repo's history; taking the last is a defensive tie-breaker,
            # not evidence multiple lines are expected.
            pairs.append((current_hash, current_names[-1]))

    for line in result.stdout.splitlines():
        if line.startswith("COMMIT "):
            flush()
            current_hash = line[len("COMMIT "):].strip()
            current_names = []
        elif line.strip():
            current_names.append(line.strip())
    flush()

    pairs.reverse()
    return pairs


def content_at(repo_root: Path, commit_hash: str, rel_path: str) -> str | None:
    result = subprocess.run(
        ["git", "show", f"{commit_hash}:{rel_path}"],
        cwd=str(repo_root), capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        return None
    return result.stdout


def replay_logic_changes(repo_root: Path, rel_path: str, logic_diff, yaml_module) -> int | None:
    """Count of historical transitions where logic_diff() found a change, or
    None if the history could not be walked at all (e.g. an uncommitted
    file -- discover() reads the filesystem, git log reads commits, and
    those two are not guaranteed to agree at every instant)."""
    pairs = commit_history(repo_root, rel_path)
    if not pairs:
        return None

    prev_data = None
    count = 0
    for commit_hash, path_at_commit in pairs:
        text = content_at(repo_root, commit_hash, path_at_commit)
        if text is None:
            continue
        try:
            data = yaml_module.safe_load(text)
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        if prev_data is not None and logic_diff(prev_data, data):
            count += 1
        prev_data = data
    return count


def rewrite_version_line(content: str, new_version: str) -> str | None:
    if not VERSION_LINE_RE.search(content):
        return None
    return VERSION_LINE_RE.sub(f'version: "{new_version}"', content, count=1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--apply", action="store_true",
        help="Write the computed version: values to disk. Default is report-only (dry run).",
    )
    args = parser.parse_args(argv)

    try:
        import yaml
        from check_version_bump import logic_diff
        from lib.rules import discover, load_rule
    except Exception as ex:
        eprint(f"[FATAL] Missing dependency or import failure: {ex}")
        return 2

    rule_paths = discover(REPO_ROOT / "rules" / "sigma")
    if not rule_paths:
        print("No rules found under rules/sigma -- nothing to do.")
        return 0

    rows: list[tuple[str, str, str]] = []
    for path in sorted(rule_paths):
        rel_path = path.relative_to(REPO_ROOT).as_posix()
        try:
            rule = load_rule(path)
        except Exception as ex:
            eprint(f"[SKIP] {rel_path}: could not load current rule: {ex}")
            continue

        old_version = str(rule.get("version") or "")
        count = replay_logic_changes(REPO_ROOT, rel_path, logic_diff, yaml)
        if count is None:
            eprint(f"[SKIP] {rel_path}: could not walk git history (uncommitted file?).")
            continue

        new_version = f"1.{count}"
        rows.append((rel_path, old_version, new_version))

    name_width = max((len(r) for r, _, _ in rows), default=4)
    print(f"{'Rule':<{name_width}}  {'Old':>8}  {'New':>8}")
    print("-" * (name_width + 22))
    changed = 0
    for rel_path, old_version, new_version in rows:
        is_changed = old_version != new_version
        changed += is_changed
        marker = "  <-- CHANGED" if is_changed else ""
        print(f"{rel_path:<{name_width}}  {old_version:>8}  {new_version:>8}{marker}")
    print("-" * (name_width + 22))
    print(f"{len(rows)} rules checked, {changed} would change.")

    if not args.apply:
        print("\nDry run only -- re-run with --apply to write these values.")
        return 0

    written = 0
    for rel_path, old_version, new_version in rows:
        if old_version == new_version:
            continue
        full_path = REPO_ROOT / rel_path
        content = full_path.read_text(encoding="utf-8")
        rewritten = rewrite_version_line(content, new_version)
        if rewritten is None:
            eprint(f"[SKIP-WRITE] {rel_path}: no version: line found, not rewriting.")
            continue
        full_path.write_text(rewritten, encoding="utf-8")
        written += 1
        print(f"[WROTE] {rel_path}: {old_version} -> {new_version}")

    print(f"\n{written} file(s) rewritten.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
