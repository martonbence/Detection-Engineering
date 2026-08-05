# scripts/state/select_unverified.py
#
# Register item 2.21. Answers "which rules still need a lab run?" for a manual
# workflow_dispatch, where there is no before..after diff to work from.
#
# A push knows what changed. A manual run does not -- so it used to widen to
# every rule, which meant re-attacking all 27 on the lab VMs to catch up two.
# The baseline that does exist is in the committed results: every result.json
# records the rule_version it was measured against, and a rule's version is its
# commit count. A rule therefore needs a run when it has no result at all, or
# when its result belongs to an older version of itself.
#
# That is the same "drift" the rule browser already displays; this just makes it
# something you can *start* a run from.
#
# Fails towards selecting. Whenever the current version cannot be established --
# no git history, a shallow clone, an unreadable rule -- the rule is selected
# rather than skipped: the cost of a needless re-run is lab time, the cost of a
# wrong skip is a rule everyone believes was verified and was not.
#
# Exit codes:
# 0 = selection written to stdout (possibly empty)
# 2 = setup failure (missing dependency, rules directory absent)

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

DEFAULT_RULES_DIR = "rules/sigma"
DEFAULT_RESULTS_DIR = "outputs/results"


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="List the Sigma rules whose verification is missing or belongs to an older version."
    )
    p.add_argument("--rules-dir", default=DEFAULT_RULES_DIR)
    p.add_argument("--results-dir", default=DEFAULT_RESULTS_DIR)
    p.add_argument("--json", dest="json_out", help="Also write the full reasoning to this JSON file")
    return p.parse_args(argv)


def git_version(rule_path: Path) -> str:
    """The rule's version: 1.0 on its first commit, 1.1 on the second, ...

    Same scheme as sigma_to_spl.py and generate_stats.py -- commit count on the
    Sigma source, via --follow so a rename does not reset it. Returns "" when it
    cannot be determined, which the caller treats as "must run".
    """
    try:
        out = subprocess.run(
            ["git", "log", "--follow", "--format=%H", "--", str(rule_path)],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return ""

    if out.returncode != 0:
        return ""

    count = len([line for line in out.stdout.splitlines() if line.strip()])
    if count <= 0:
        return ""
    return f"1.{max(0, count - 1)}"


def verified_version(results_dir: Path, detect_id: str) -> str | None:
    """The rule version the committed result was measured against, if any."""
    result_file = results_dir / detect_id / "result.json"
    if not result_file.is_file():
        return None
    try:
        data = json.loads(result_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    version = data.get("rule_version")
    return str(version) if version else None


def classify(rule_path: Path, data: object, results_dir: Path) -> dict:
    """Decide whether this rule needs a run, and record why."""
    entry = {
        "rule": str(rule_path).replace("\\", "/"),
        "detect_id": "",
        "current_version": "",
        "verified_version": None,
        "select": True,
        "reason": "",
    }

    if not isinstance(data, dict):
        entry["reason"] = "unreadable"
        return entry

    detect_id = str(data.get("detect_id") or "").strip()
    entry["detect_id"] = detect_id

    if str(data.get("status") or "").strip().lower() == "deprecated":
        # Deprecated rules are not deployed at all (item 1.7), so measuring them
        # would be measuring something that is not there.
        entry["select"] = False
        entry["reason"] = "deprecated"
        return entry

    if not detect_id:
        entry["reason"] = "no detect_id, cannot match a result"
        return entry

    current = git_version(rule_path)
    entry["current_version"] = current
    verified = verified_version(results_dir, detect_id)
    entry["verified_version"] = verified

    if not current:
        entry["reason"] = "version unknown (no git history?), selecting to be safe"
        return entry

    if verified is None:
        entry["reason"] = "never verified"
        return entry

    if verified != current:
        entry["reason"] = f"verified at {verified}, now {current}"
        return entry

    entry["select"] = False
    entry["reason"] = f"verified at {current}"
    return entry


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        import yaml  # type: ignore
    except Exception as ex:
        eprint(f"[FATAL] Missing dependency: pyyaml. ({ex})")
        return 2

    rules_dir = Path(args.rules_dir)
    if not rules_dir.is_dir():
        eprint(f"[FATAL] Rules directory not found: {rules_dir}")
        return 2

    results_dir = Path(args.results_dir)

    rule_paths = sorted(list(rules_dir.rglob("*.yml")) + list(rules_dir.rglob("*.yaml")))

    entries: list[dict] = []
    for rule_path in rule_paths:
        try:
            data = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as ex:
            eprint(f"WARNING: {rule_path} could not be read ({ex}) -- selecting it.")
            data = None
        entries.append(classify(rule_path, data, results_dir))

    selected = [e for e in entries if e["select"]]

    eprint(f"Examined {len(entries)} rule(s); {len(selected)} need a run.")
    for e in entries:
        mark = "RUN " if e["select"] else "skip"
        eprint(f"  {mark} {e['detect_id'] or e['rule']}: {e['reason']}")

    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({"examined": len(entries), "entries": entries}, indent=2) + "\n", encoding="utf-8")
        eprint(f"Wrote {out}")

    # stdout carries the selection and nothing else, so the workflow can read it
    # straight into an array.
    for e in selected:
        print(e["rule"])

    return 0


if __name__ == "__main__":
    sys.exit(main())
