# scripts/validate/check_version_bump.py
#
# Register item 3.5 (schema/discipline half; the duplication half -- one
# shared scripts/lib/rule_version.py instead of two drifted copies -- closed
# 2026-08-11). That module is deliberately untouched by this file: its
# git-commit-count-derived `rule_version` is a *measurement* consumed by
# sigma_to_spl.py's sidecar and generate_stats.py's Superseded check, and
# stays exactly what it was. The `version:` field this script enforces is a
# different thing living beside it -- a number a person sets, meant to answer
# "did the detection actually change", which a commit count structurally
# cannot: a typo fix and a rewritten condition: block both add one commit.
#
# What this checks: for every rule file this push changed, does the new
# `version:` differ from the version the same file carried at the base ref? -
# but only when it has to. The check does not require every edit to bump the
# version -- only edits that could change what the rule catches. Two things
# count as that:
#
#   - detection:   the actual matching logic.
#   - logsource:   which events the logic even runs against; changing this
#                  can silently point a rule at nothing, which is exactly as
#                  much of a behaviour change as editing the condition.
#
# One more field counts, and it is not in the two above: `custom.splunk.raw_query`.
# A rule with `custom.splunk.raw_query` set (see sigma_schema.json's own
# description of the field) has its real detection logic *there*, verbatim
# SPL, with `detection:` reduced to a required-but-unused placeholder --
# sigma_to_spl.py emits the raw text instead of converting anything. Watching
# only detection:/logsource: would let the one rule that bypasses the
# converter entirely (DETECT-2026-0003_Test3, as of this check's introduction)
# rewrite its actual query and never trip the gate.
#
# Deliberately NOT logic for this check's purposes: description, references,
# falsepositives, tags (MITRE classification -- check_mitre_tags.py's job,
# not this one), status, level, fields, and everything under custom.testing /
# custom.splunk other than raw_query (scheduling and test wiring, not
# detection content). Rewording a description or fixing a false-positive note
# should not force a version bump -- that was the exact complaint this
# register item opened with.
#
# Scope is the changed rule files for *this push*, not every rule in the repo
# (unlike check_detect_id_uniqueness.py / check_mitre_tags.py, which check a
# global invariant that any rule can violate regardless of what changed).
# Whether a version needed to move is a question about a diff, so it is only
# askable for files that have a diff -- reusing the same before/after the
# `Determine changed Sigma files` step in ci_dev_workflow.yml already
# computes (its `base_sha` output), rather than re-deriving a second notion
# of "changed" here.
#
# Severity: a hard gate, no --strict, same contract as
# check_detect_id_uniqueness.py and unlike check_test_routing.py /
# check_mitre_tags.py. Those two are advisory because judging them requires
# domain knowledge the checker cannot fully verify offline (is this really
# the right ATT&CK technique? will a runner exist later?) -- a wrong verdict
# there is possible. Whether the version field's text changed between two
# git blobs is not a judgment call, and the fix is always one line, so there
# is no reason to let it through as a warning the way a debatable tag is let
# through.
#
# Exit codes:
# 0 = every logic-changing edit bumped its version (or nothing changed logic,
#     or no rule files were given -- an empty selection is not a failure)
# 1 = a rule changed detection:/logsource:/raw_query without bumping version
# 2 = checker setup failure (missing pyyaml)

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

REPO_ROOT = Path(__file__).resolve().parents[2]

LOGIC_FIELDS = ("detection", "logsource")


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def raw_query(data: dict) -> str | None:
    splunk = (data.get("custom") or {}).get("splunk")
    if not isinstance(splunk, dict):
        return None
    value = splunk.get("raw_query")
    return value if isinstance(value, str) else None


def version_of(data: dict) -> str:
    return str(data.get("version") or "").strip()


def logic_diff(old: dict, new: dict) -> list[str]:
    """Which logic-relevant pieces differ between two parsed rules. Empty means none do."""
    changed = [field for field in LOGIC_FIELDS if old.get(field) != new.get(field)]
    if raw_query(old) != raw_query(new):
        changed.append("custom.splunk.raw_query")
    return changed


def load_old_rule(path: str, base_ref: str, repo_root: Path, yaml_module) -> dict | None:
    """The rule as it existed at `base_ref`, or None when there is nothing to compare.

    None covers every case where a prior version cannot be established: a
    brand-new file, a bad/empty base ref, or a base-ref blob that is not
    parseable YAML. All of those mean "skip this rule" rather than "assume a
    violation" -- guessing here would fail a rule for a git plumbing gap that
    has nothing to do with the author's discipline.
    """
    if not base_ref:
        return None
    try:
        result = subprocess.run(
            ["git", "show", f"{base_ref}:{path}"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=30,
        )
    except Exception:
        return None
    if result.returncode != 0:
        return None
    try:
        data = yaml_module.safe_load(result.stdout)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    return data


def write_step_summary(findings: list[dict]) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path or not findings:
        return

    from lib.summary import escape_cell  # deferred, same reason as the yaml/lib.rules imports below

    lines = [
        "### Missing version bump",
        "",
        "These rules changed detection-relevant content in this push but kept the same `version:`.",
        "",
        "| Rule | Version | Changed |",
        "| --- | --- | --- |",
    ]
    for f in findings:
        lines.append(
            f"| `{escape_cell(f['detect_id'])}` | `{escape_cell(f['version'])}` "
            f"| {escape_cell(', '.join(f['changed']))} |"
        )
    lines.append("")

    try:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError as ex:
        eprint(f"WARNING: could not write the step summary: {ex}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Fail if a changed Sigma rule's detection:/logsource:/raw_query differs "
            "from its base-ref version without version: also changing."
        )
    )
    p.add_argument(
        "--base-ref",
        default="",
        help="Commit-ish to diff against (the base_sha the 'Determine changed Sigma files' "
        "step already computed). Empty means nothing can be compared -- every rule is skipped.",
    )
    p.add_argument("rules", nargs="*", help="Changed rule file paths, repo-relative.")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    # Deferred for the same reason as check_mitre_tags.py: these two imports
    # pull in pyyaml, and a top-level import would turn a missing dependency
    # into a traceback (exit 1, "this script found rule problems") instead of
    # the clean setup-failure exit 2 this function returns below.
    try:
        import yaml  # type: ignore

        from lib.rules import RuleLoadError, detect_id, load_rule
    except Exception as ex:
        eprint(f"[FATAL] Missing dependency: pyyaml. ({ex})")
        return 2

    print("=== Version Bump Discipline Check ===")
    print(f"Base ref: {args.base_ref or '<none>'}")

    if not args.rules:
        print("No changed rule files given -> nothing to check.")
        return 0

    findings: list[dict] = []
    checked = 0
    skipped = 0

    for rule_path in args.rules:
        path = Path(rule_path)

        try:
            new_data = load_rule(path)
        except RuleLoadError as ex:
            # validate_sigma.py owns unreadable/malformed rules and already
            # fails the run for them; this check has nothing useful to add.
            eprint(f"SKIP: {ex}")
            skipped += 1
            continue

        old_data = load_old_rule(rule_path, args.base_ref, REPO_ROOT, yaml)
        if old_data is None:
            print(f"[NEW] {rule_path} (no prior version to compare)")
            skipped += 1
            continue

        checked += 1
        changed = logic_diff(old_data, new_data)
        old_version = version_of(old_data)
        new_version = version_of(new_data)
        did = detect_id(new_data) or path.stem

        if not changed:
            print(f"[OK] {rule_path} (no logic-relevant change)")
            continue

        if new_version != old_version:
            print(
                f"[OK] {rule_path} (version bumped: {old_version!r} -> {new_version!r}, "
                f"changed: {', '.join(changed)})"
            )
            continue

        findings.append({
            "rule": str(path).replace("\\", "/"),
            "detect_id": did,
            "version": new_version,
            "changed": changed,
        })
        print(
            f"[MISSING-BUMP] {rule_path}: {', '.join(changed)} changed but version stayed at "
            f"{new_version!r}"
        )
        print(
            f"::error file={rule_path},title=Missing version bump::{did} changed "
            f"{', '.join(changed)} without bumping version: (still {new_version!r})"
        )

    print("")
    print(f"Checked:  {checked}")
    print(f"Skipped:  {skipped} (new file or no comparable prior version)")
    print(f"Findings: {len(findings)}")

    write_step_summary(findings)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
