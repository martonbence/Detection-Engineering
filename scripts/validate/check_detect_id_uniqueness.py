# scripts/validate/check_detect_id_uniqueness.py
#
# Register item 4.5 (collision-protection half; see scripts/new_rule.py for
# the scaffolder half). Nothing else in the pipeline checks that detect_id
# stays unique across rules/sigma/ -- validate_sigma.py validates each file
# in isolation against the schema, which has no way to see a sibling file.
#
# A collision is not cosmetic: rule_naming.saved_search_name() builds the
# Splunk object name from detect_id + slug(title), so two rules sharing a
# detect_id collide on the same saved search -- deploy_spl_to_splunk.py
# would have the second rule silently overwrite the first's Splunk object,
# and reconcile.py / generate_stats.py would key verdicts and coverage
# stats onto whichever rule happened to load last.
#
# scripts/new_rule.py picks the next free id by scanning the current
# checkout, which narrows how often this happens but cannot close it: two
# branches started from the same base commit can independently compute the
# same "next free" id. This is the actual backstop -- it runs on the merged
# tree, where the collision would otherwise be invisible until someone
# noticed a saved search behaving strangely in Splunk.
#
# Unlike check_mitre_tags.py (item 4.3, advisory by design because a wrong
# ATT&CK tag misfiles a working detection rather than breaking anything), a
# duplicate detect_id is unambiguous and always wrong, so this has no
# --strict flag: it fails outright, the same contract as validate_sigma.py.
#
# Exit codes:
# 0 = every detect_id is unique
# 1 = a detect_id is used by more than one rule file
# 2 = checker setup failure

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.rules import RuleLoadError, detect_id, discover, load_rule

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RULES_DIR = REPO_ROOT / "rules" / "sigma"


def find_duplicates(rules_dir: Path) -> dict[str, list[Path]]:
    """detect_id -> the (2+) rule files that share it. Empty if none do."""
    by_id: dict[str, list[Path]] = defaultdict(list)
    for path in discover(rules_dir):
        try:
            rule = load_rule(path)
        except RuleLoadError:
            # validate_sigma.py owns malformed/unreadable rules -- do not
            # double-report a file that already fails for a different reason.
            continue
        did = detect_id(rule)
        if did:
            by_id[did].append(path)
    return {did: paths for did, paths in by_id.items() if len(paths) > 1}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Fail if two rules under rules/sigma/ share a detect_id."
    )
    p.add_argument("--rules-dir", default=str(DEFAULT_RULES_DIR))
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    rules_dir = Path(args.rules_dir)

    dupes = find_duplicates(rules_dir)

    print("=== detect_id Uniqueness Check ===")
    print(f"Rules dir: {rules_dir}")

    if not dupes:
        print("[OK] No duplicate detect_id found.")
        return 0

    for did, paths in sorted(dupes.items()):
        files = ", ".join(str(p) for p in paths)
        print(f"[DUPLICATE] {did} used by {len(paths)} rule files: {files}")
        print(f"::error title=Duplicate detect_id::{did} is used by: {files}")

    print("")
    print(f"Duplicates: {len(dupes)}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
