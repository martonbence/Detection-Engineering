# scripts/validate/check_test_routing.py
#
# Register item 2.17: a rule can ask to be tested on a runner that no CI job
# actually services, and today that failure is completely silent.
#
# run_atomic.ps1 filters the bundle by an exact (tester type, runner) match
# against the ATOMIC_TESTER_TYPE / ATOMIC_RUNNER the job hands it. A rule whose
# combination no job sets is skipped with a plain Write-Host line buried in the
# log of a job that then exits 0 -- no annotation, no failed step, and (for
# emulation rules, see item 2.8) not even a NOT_VERIFIED verdict. The rule looks
# tested and is not.
#
# The schema deliberately allows `linux-victim` before that VM exists, so this
# is a warning, not a gate: a detection rule is worth deploying even when its
# test cannot run yet. What it must not be is quiet.
#
# The serviced combinations are *derived from the workflow* rather than listed
# here, so adding the linux job later needs no edit to this file -- and deleting
# a job cannot leave a stale allow-list behind claiming the rules are covered.
#
# Exit codes:
# 0 = no findings, or findings reported advisory (default)
# 1 = findings, with --strict
# 2 = checker setup failure (deps / workflow unreadable / matrix underivable)

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.summary import MARK_WARN, escape_cell

DEFAULT_WORKFLOW = ".github/workflows/ci_dev_workflow.yml"

# The two env vars run_atomic.ps1 filters on. A step that sets both is, by
# definition, a job that services that combination.
TESTER_ENV = "ATOMIC_TESTER_TYPE"
RUNNER_ENV = "ATOMIC_RUNNER"


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Warn about Sigma rules whose test runner no CI job services."
    )
    p.add_argument(
        "--workflow",
        default=DEFAULT_WORKFLOW,
        help=f"Workflow to derive the serviced combinations from (default: {DEFAULT_WORKFLOW})",
    )
    p.add_argument("--json", dest="json_out", help="Write the findings to this JSON file")
    p.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 when a rule is unrouted, instead of only warning",
    )
    p.add_argument(
        "--job-flags",
        action="store_true",
        help="Also emit has_*_tests flags to $GITHUB_OUTPUT: which test jobs this batch needs",
    )
    p.add_argument("rules", nargs="*", help="Rule files to check (default: every rule in rules/sigma)")
    return p.parse_args(argv)


def derive_matrix(workflow: dict) -> tuple[dict[tuple[str, str], str], list[str]]:
    """Map every (tester type, runner) a job sets to the name of that job.

    Returns the matrix plus a list of combinations that could not be resolved
    statically, so a workflow that computes these from an expression is
    reported rather than silently narrowing the matrix.
    """
    serviced: dict[tuple[str, str], str] = {}
    unresolved: list[str] = []

    for job_name, job in (workflow.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        job_env = job.get("env") or {}
        for step in job.get("steps") or []:
            if not isinstance(step, dict):
                continue
            env = {**job_env, **(step.get("env") or {})}
            if TESTER_ENV not in env or RUNNER_ENV not in env:
                continue

            tester = str(env[TESTER_ENV]).strip()
            runner = str(env[RUNNER_ENV]).strip()

            if "${{" in tester or "${{" in runner:
                unresolved.append(f"{job_name}: {TESTER_ENV}={tester!r}, {RUNNER_ENV}={runner!r}")
                continue

            serviced[(tester.lower(), runner.lower())] = job_name

    return serviced, unresolved


def describe(matrix: dict[tuple[str, str], str]) -> str:
    return ", ".join(f"{t}/{r}" for t, r in sorted(matrix)) or "(none)"


def testing_block(data: object) -> dict:
    """The rule's `custom.testing` mapping, or an empty one.

    Shared so the routing check and the job flags read the rule exactly the
    same way -- two readers disagreeing about what "tested" means is how a rule
    ends up starting a job that then skips it.
    """
    if not isinstance(data, dict):
        return {}
    custom = data.get("custom") or {}
    testing = (custom.get("testing") if isinstance(custom, dict) else None) or {}
    return testing if isinstance(testing, dict) else {}


def check_rule(path: Path, data: object, matrix: dict[tuple[str, str], str]) -> dict | None:
    """Return a finding for this rule, or None when it routes to a real job."""
    if not isinstance(data, dict):
        return None

    testing = testing_block(data)
    if not testing.get("enabled"):
        return None

    detect_id = str(data.get("detect_id") or path.stem)
    tester = str(testing.get("type") or "").strip()
    runner = str(testing.get("runner") or "").strip()

    if not runner:
        # run_atomic.ps1 compares the runner exactly, and the converter only
        # writes the meta field when it is non-empty -- so "unset" does not mean
        # "the default", it means every job's filter rejects it.
        return {
            "rule": str(path).replace("\\", "/"),
            "detect_id": detect_id,
            "type": tester,
            "runner": "",
            "reason": "no_runner",
            "message": (
                f"{detect_id} enables testing but declares no custom.testing.runner. "
                f"The runner is matched exactly, so the rule is skipped by every test job "
                f"and never actually tested. Serviced combinations: {describe(matrix)}."
            ),
        }

    if (tester.lower(), runner.lower()) not in matrix:
        return {
            "rule": str(path).replace("\\", "/"),
            "detect_id": detect_id,
            "type": tester,
            "runner": runner,
            "reason": "unserviced",
            "message": (
                f"{detect_id} requests type='{tester}' on runner='{runner}', which no job "
                f"services. The rule deploys, but its test is silently skipped and the rule "
                f"is left untested. Serviced combinations: {describe(matrix)}."
            ),
        }

    return None


# Register item 2.10. The workflow used to answer "which test jobs does this
# batch need?" in bash, by spawning *two* `python3 -c` one-liners per rule -- 54
# processes for 27 rules -- each ending in `2>/dev/null || true`, so a rule whose
# YAML failed to parse silently became an empty tester and dropped out of routing
# with nothing said.
#
# The question is already answered here: the matrix maps (tester, runner) to the
# job that services it, so "does this job have work?" is a lookup, not a second
# parse. This is the mapping from that job name to the workflow output the jobs
# gate on -- the only part that cannot be derived, because it is the workflow's
# own naming.
#
# A job missing from this table simply gets no flag; item 2.17's warning is what
# reports a rule that routes nowhere. Note this is stricter than the old bash in
# a way that matters: a rule requesting an unserviced runner used to set
# has_atomic_tests and start the victim job, which then skipped it. Now no job is
# started for work that does not exist.
JOB_OUTPUT_FLAGS = {
    "atomic_verify": "has_atomic_tests",
    "atomic_verify_dc": "has_atomic_dc_tests",
    "emulation_verify": "has_emulation_tests",
}


def job_flags(entries: list[dict], matrix: dict[tuple[str, str], str]) -> dict[str, bool]:
    """Which of the workflow's test jobs have at least one rule to run."""
    flags = dict.fromkeys(JOB_OUTPUT_FLAGS.values(), False)
    for entry in entries:
        job = matrix.get((entry["type"].lower(), entry["runner"].lower()))
        flag = JOB_OUTPUT_FLAGS.get(job)
        if flag:
            flags[flag] = True
    return flags


def write_job_flags(flags: dict[str, bool]) -> None:
    lines = [f"{name}={'true' if value else 'false'}" for name, value in sorted(flags.items())]
    for line in lines:
        print(line)

    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    try:
        with open(output_path, "a", encoding="utf-8") as fh:
            for line in lines:
                fh.write(line + "\n")
    except OSError as ex:
        eprint(f"WARNING: could not write the job flags: {ex}")


def write_step_summary(findings: list[dict]) -> None:
    """Put the findings where a human sees them without opening the job log."""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path or not findings:
        return

    lines = [
        "### Rules with no test runner",
        "",
        "These rules deploy normally, but nothing will execute their tests:",
        "",
        "| Rule | Test type | Runner requested |",
        "| --- | --- | --- |",
    ]
    for f in findings:
        lines.append(
            f"| {MARK_WARN} `{escape_cell(f['detect_id'])}` "
            f"| `{escape_cell(f['type'] or '-')}` "
            f"| `{escape_cell(f['runner'] or '(unset)')}` |"
        )
    lines.append("")

    try:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError as ex:
        eprint(f"WARNING: could not write the step summary: {ex}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        import yaml  # type: ignore
    except Exception as ex:
        eprint(f"[FATAL] Missing dependency: pyyaml. ({ex})")
        return 2

    workflow_path = Path(args.workflow)
    try:
        workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    except OSError as ex:
        eprint(f"[FATAL] Could not read the workflow: {workflow_path} ({ex})")
        return 2
    except yaml.YAMLError as ex:
        eprint(f"[FATAL] Workflow is not valid YAML: {workflow_path} ({ex})")
        return 2

    if not isinstance(workflow, dict):
        eprint(f"[FATAL] Workflow did not parse into a mapping: {workflow_path}")
        return 2

    matrix, unresolved = derive_matrix(workflow)

    for note in unresolved:
        # Not fatal, but the matrix is now narrower than reality, so every
        # finding below has to be read knowing that.
        eprint(f"WARNING: could not resolve a test-runner combination statically -- {note}")

    if not matrix:
        # Without this guard a workflow refactor that moves those env vars would
        # turn every rule in the repo into a finding, which reads as a rule
        # problem when it is a checker problem.
        eprint(
            f"[FATAL] No job in {workflow_path} sets both {TESTER_ENV} and {RUNNER_ENV}. "
            f"Either the test jobs were removed or this checker needs updating -- "
            f"refusing to report every rule as unrouted."
        )
        return 2

    rule_paths = (
        [Path(r) for r in args.rules]
        if args.rules
        else sorted(Path("rules/sigma").rglob("*.yml"))
    )

    findings: list[dict] = []
    tested: list[dict] = []
    checked = 0

    for path in rule_paths:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as ex:
            # Schema validation owns malformed rules; this checker just says so
            # and moves on rather than failing the step twice for one cause.
            eprint(f"SKIP: {path} could not be read ({ex})")
            continue

        checked += 1
        finding = check_rule(path, data, matrix)
        if finding:
            findings.append(finding)

        testing = testing_block(data)
        if testing.get("enabled"):
            tested.append(
                {
                    "type": str(testing.get("type") or "").strip(),
                    "runner": str(testing.get("runner") or "").strip(),
                }
            )

    # --job-flags is the workflow asking "which test jobs does this batch need?",
    # not a human asking "is anything unrouted?". The dedicated routing step
    # earlier in the same job already answered the second question over a
    # superset of these rules, so repeating the annotations and the summary
    # table here would only duplicate them.
    reporting = not args.job_flags

    if reporting:
        print(f"Serviced test combinations: {describe(matrix)}")
        print(f"Checked {checked} rule(s); {len(findings)} with no runner to execute them.")

        for f in findings:
            print(f"::warning file={f['rule']},title=No runner for this test::{f['message']}")

        write_step_summary(findings)

    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(
                {
                    "serviced": [{"type": t, "runner": r, "job": j} for (t, r), j in sorted(matrix.items())],
                    "unresolved": unresolved,
                    "checked": checked,
                    "findings": findings,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"Wrote {out}")

    if args.job_flags:
        write_job_flags(job_flags(tested, matrix))

    if findings and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
