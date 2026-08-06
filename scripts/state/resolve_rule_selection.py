# scripts/state/resolve_rule_selection.py
#
# Resolves a hand-typed rule selection from a manual workflow run into actual
# rule file paths.
#
# Why this is free text rather than a dropdown: GitHub Actions' workflow_dispatch
# inputs are static YAML, and `type: choice` is single-select -- there is no
# multi-select input type at all. A dropdown could only ever offer one rule, and
# keeping its `options:` list in step with rules/sigma/ would mean CI rewriting
# its own workflow file on every rule change, which is a large failure mode to
# accept for a convenience feature.
#
# So the safety a dropdown would have given comes from validation instead: an
# unknown token fails the run immediately and prints every valid detect_id,
# which is the same information a dropdown would have shown -- just after
# pressing the button rather than before.
#
# Deliberately does not parse any YAML. Rule files are named
# <detect_id>_<slug>.yml, so resolution is a glob. Item 2.10 was about this repo
# parsing the same metadata in four places; this adds no fifth reader.
#
# Exit codes:
# 0 = every token resolved; paths written to stdout
# 1 = at least one token matched no rule (nothing is written to stdout)
# 2 = setup failure (rules directory missing)

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

DEFAULT_RULES_DIR = "rules/sigma"

# Tokens may be separated by commas, whitespace, or newlines -- whichever the
# person typing found natural in a single-line web form.
SPLIT = re.compile(r"[,\s]+")


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Resolve a manual rule selection into rule file paths.")
    p.add_argument("--rules-dir", default=DEFAULT_RULES_DIR)
    p.add_argument("selection", help="Rule tokens: detect_id, filename or path; comma or space separated")
    return p.parse_args(argv)


def tokenize(selection: str) -> list[str]:
    return [t for t in SPLIT.split((selection or "").strip()) if t]


def available(rules_dir: Path) -> dict[str, Path]:
    """Every rule, keyed by detect_id -- the part of the filename before the first `_`."""
    found: dict[str, Path] = {}
    for path in sorted(list(rules_dir.rglob("*.yml")) + list(rules_dir.rglob("*.yaml"))):
        detect_id = path.stem.split("_", 1)[0]
        found.setdefault(detect_id, path)
    return found


def resolve_one(token: str, rules_dir: Path, by_id: dict[str, Path]) -> Path | None:
    """A token may be a detect_id, a bare filename, or a path. All three are
    things somebody might reasonably paste in, so all three are accepted."""
    token = token.strip().strip("'\"")
    if not token:
        return None

    # An exact path, relative to the repo or already including the rules dir.
    candidate = Path(token)
    if candidate.is_file():
        return candidate

    # A bare filename, with or without the extension.
    for suffix in (".yml", ".yaml", ""):
        candidate = rules_dir / f"{token}{suffix}"
        if candidate.is_file():
            return candidate

    # A detect_id, case-insensitively: the ids are upper case but nobody should
    # lose a run to that.
    hit = by_id.get(token)
    if hit is not None:
        return hit
    for detect_id, path in by_id.items():
        if detect_id.lower() == token.lower():
            return path

    return None


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    rules_dir = Path(args.rules_dir)
    if not rules_dir.is_dir():
        eprint(f"[FATAL] Rules directory not found: {rules_dir}")
        return 2

    by_id = available(rules_dir)
    tokens = tokenize(args.selection)

    if not tokens:
        eprint("No rules named in the selection.")
        return 1

    resolved: list[Path] = []
    unknown: list[str] = []
    for token in tokens:
        path = resolve_one(token, rules_dir, by_id)
        if path is None:
            unknown.append(token)
        elif path not in resolved:
            # Naming the same rule twice is a typo, not a request to run it
            # twice, and a duplicate would be converted and attacked twice.
            resolved.append(path)

    if unknown:
        eprint(f"::error title=Unknown rule(s)::Not found in {rules_dir}: {', '.join(unknown)}")
        eprint("")
        eprint("Valid detect_ids:")
        for detect_id in sorted(by_id):
            eprint(f"  {detect_id}")
        # Nothing on stdout: a partial selection would run a subset of what was
        # asked for, which is worse than not running at all.
        return 1

    eprint(f"Selected {len(resolved)} rule(s) by hand:")
    for path in resolved:
        eprint(f"  {path}")

    for path in resolved:
        print(str(path).replace("\\", "/"))

    return 0


if __name__ == "__main__":
    sys.exit(main())
