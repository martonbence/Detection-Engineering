# scripts/state/reconcile_step.py
#
# The dev pipeline's splunk_verify job, "Reconcile Splunk state against the
# repo" step in ci_dev_workflow.yml.
#
# Extracted verbatim (in behaviour, not in syntax) from ~118 lines of inline
# bash -- audit/feature-and-process-audit.md item 4.1, slice 4 (slice 1 was
# determine_changed_rules.py, slice 2 was merge_verification_results.py,
# slice 3 was open_promotion_pr.py). That register item is about the
# workflows' inline shell being the repo's largest untestable surface. Every
# branch below is now covered by tests/test_reconcile_step.py.
#
# What this step does, unchanged from the shell:
#   1. Assemble reconcile.py's extra CLI args: `--apply-removals` only when
#      BOTH `github.event_name == 'workflow_dispatch'` AND
#      `inputs.retire_orphans == 'true'` -- `inputs.*` reads as an empty
#      string on a push, so checking the input alone is the truthiness trap
#      this double condition exists to close.
#   2. Run `scripts/state/reconcile.py --rules-dir rules/sigma --json
#      outputs/state/reconcile.json --apply [extra_args]`, mirroring the
#      shell's `| tee reconcile_report.txt` (stdout streamed live AND
#      captured; stderr left connected to the terminal, uncaptured, same as
#      the pipe only ever redirected stdout) and its
#      `rc="${PIPESTATUS[0]}"` (the *reconcile.py* exit code, not a
#      wrapper's).
#   3. Write the step summary: a `### Splunk state reconciliation` header
#      plus the captured report text in a code fence -- unconditionally,
#      regardless of rc.
#   4. If outputs/state/reconcile.json exists (and parses), compute four
#      corrected counts and, for every nonzero one, a distinct remedy
#      sentence; if any fired, one combined `::warning::`.
#   5. If rc != 0, a second, separate `::warning::` about the reconciliation
#      itself failing.
#   6. Exit with rc.
#
# Why this step needed the `if cmd; then rc=0; else rc="${PIPESTATUS[0]}";
# fi` dance in the original shell, and why this Python replacement does not:
# GitHub's `shell: bash` always runs as `bash --noprofile --norc -e
# -o pipefail`, regardless of the script's own `set` line (which was
# `set -uo pipefail`, no `-e`, precisely so the *rest* of the step's
# diagnostics could still run after a nonzero reconcile.py exit -- and a
# command inside an `if` condition is exempt from `-e`). That constraint is
# about *bash's* control flow, not this step's logic: a Python function
# returning a nonzero exit code does not abort the interpreter the way a
# bash command does, so run_step() below runs its write-summary/build-
# warnings/emit-failure-warning tail unconditionally regardless of rc, with
# no special-casing needed. The *only* place `bash -e` still matters is the
# one-line `python scripts/state/reconcile_step.py` invocation in the
# workflow itself, which is deliberately the step's last command, so dying
# there on a nonzero exit is exactly the intended `exit "$rc"`.
#
# The split, following slices 1-3's shape:
#   build_extra_args()        -- pure. The event/input truthiness guard.
#   corrected_unresolved_count() / corrected_renamed_count() /
#   missing_count() / dupes_count() --
#                                 pure. Set-subtraction arithmetic over the
#                                 already-parsed reconcile.json structure --
#                                 see the comment above
#                                 corrected_unresolved_count() for why the
#                                 subtraction exists at all.
#   build_drift_warning_parts() / build_drift_warning() /
#   build_reconcile_failure_warning() / build_step_summary() --
#                                 pure string assembly.
#   ReconcileOps / run_step()  -- the orchestration, with the reconcile.py
#                                 subprocess call and the reconcile.json read
#                                 injected as callables, same
#                                 Resolvers/GhOps injection pattern slices
#                                 1-3 used.
#   run_reconcile_subprocess() / read_reconcile_json() / main() --
#                                 the real I/O: the tee-equivalent subprocess
#                                 capture, the JSON file read, and wiring
#                                 GITHUB_EVENT_NAME / RETIRE_ORPHANS /
#                                 GITHUB_STEP_SUMMARY from the environment.
#
# Exit codes: reconcile.py's own exit code, always (0 = clean/drift-free run,
# 1 = --fail-on-drift would have fired (never passed here, so unreachable in
# practice), 2 = the comparison itself could not be trusted -- see
# reconcile.py's own ReconcileError paths). continue-on-error: true on the
# workflow step means a nonzero exit here never fails the job; it only makes
# the failure visible via the two ::warning:: annotations and the summary.

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

RULES_DIR = "rules/sigma"
RECONCILE_JSON_PATH = "outputs/state/reconcile.json"


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


# --- extra_args (pure) ---------------------------------------------------------


def build_extra_args(event_name: str, retire_orphans: str) -> list[str]:
    """`--apply-removals` only on an explicit manual request.

    Guarded on the event as well as the input because `inputs.*` is empty on
    a push, and an empty string is not "false" in every comparison anyone
    might later write here -- being explicit costs one condition and removes
    the class of mistake that silently disables detections.
    """
    if event_name == "workflow_dispatch" and retire_orphans == "true":
        return ["--apply-removals"]
    return []


def reconcile_command(extra_args: Sequence[str]) -> list[str]:
    return [
        sys.executable,
        "scripts/state/reconcile.py",
        "--rules-dir",
        RULES_DIR,
        "--json",
        RECONCILE_JSON_PATH,
        "--apply",
        *extra_args,
    ]


# --- corrected counts (pure) ----------------------------------------------------


def _applied_names(report: dict, action: str) -> set[str]:
    """Names this run's `--apply` successfully acted on for the given action.

    `report["applied"]["actions"]` items look like
    `{"action": "delete"|"retire", "name": ..., "ok": bool, "detail": ...}`
    (see reconcile.py's apply_changes()); absent entirely when `--apply` was
    not passed, though this step always passes it.
    """
    applied = report.get("applied") or {}
    actions = applied.get("actions") or []
    return {item["name"] for item in actions if item.get("action") == action and item.get("ok")}


def corrected_unresolved_count(report: dict) -> int:
    """Orphan-by-removal objects still live after this run, corrected for
    what THIS run's --apply-removals just fixed.

    reconcile.py builds and prints its report *before* applying anything --
    its own docstring says "Read-only unless asked otherwise" and the report
    fields (`retired`, `counts`) describe scan-time state. Reading them alone
    would make the run that JUST retired 3 orphans announce the very orphans
    it had just resolved, and tell the operator to re-run with the switch
    they had in fact just used. Verified against the real artifacts of two
    runs: #42 (retire_orphans on) now reports 0 where a naive read said 3,
    and #41 (switch off) still reports 3.
    """
    unretired = [item["name"] for item in report.get("orphan_removed") or [] if not item.get("retired")]
    retired_this_run = _applied_names(report, "retire")
    return len([name for name in unretired if name not in retired_this_run])


def corrected_renamed_count(report: dict) -> int:
    """Orphan-by-rename objects still left behind, corrected for what this
    run's --apply just deleted (renames are deleted unattended, unlike
    removals, which need --apply-removals -- see reconcile.py's module
    docstring).
    """
    renamed_names = [item["name"] for item in report.get("orphan_renamed") or []]
    deleted_this_run = _applied_names(report, "delete")
    return len([name for name in renamed_names if name not in deleted_this_run])


def missing_count(report: dict) -> int:
    """No correction needed -- a missing object is a missing object either
    way, --apply never creates one.
    """
    return int((report.get("counts") or {}).get("missing", 0) or 0)


def dupes_count(report: dict) -> int:
    """Reported only, never actioned by --apply -- see reconcile.py's
    reconcile()/has_drift() for why duplicate names stay out of the apply
    path entirely.
    """
    return int((report.get("counts") or {}).get("duplicate_names", 0) or 0)


# --- warning/summary text (pure) -------------------------------------------------


def build_drift_warning_parts(unresolved: int, renamed: int, missing: int, dupes: int) -> list[str]:
    """One clause per condition that occurred, each with its own remedy
    sentence. Deliberately NOT a shared template: the previous version named
    all three counts and gave the remedy for exactly one of them, telling the
    operator that a *missing* object "keeps running and alerting" and to
    re-run with retire_orphans -- for an object that does not exist, is not
    running, and needs deploying rather than retiring.
    """
    parts: list[str] = []
    if unresolved > 0:
        parts.append(
            f"{unresolved} object(s) whose rule left the repo, still live -- "
            "re-run with 'retire_orphans' to disable and mark them (reversible)"
        )
    if renamed > 0:
        parts.append(
            f"{renamed} left behind by a rename -- --apply deletes these unattended, "
            "so one surviving means the deletion did not land"
        )
    if missing > 0:
        parts.append(f"{missing} rule(s) the repo defines but Splunk does not have -- these need a deploy, not a retirement")
    if dupes > 0:
        parts.append(
            f"{dupes} name(s) answered by more than one object -- every other line above "
            "describes only one of each, and --apply acts on only one too"
        )
    return parts


def build_drift_warning(parts: Sequence[str]) -> str | None:
    """The combined `::warning::`, or None when nothing drifted.

    `"; ".join(parts)` is the moral equivalent of the shell's
    `printf '%s; ' "${parts[@]}"` followed by stripping the trailing `; `.
    """
    if not parts:
        return None
    return f"::warning title=Splunk state drift::{'; '.join(parts)}"


def build_reconcile_failure_warning(rc: int) -> str:
    return f"::warning::Reconciliation exited {rc} -- a cleanup action may not have landed. See the step summary."


def build_step_summary(report_text: str) -> str:
    """`### Splunk state reconciliation` header plus the captured report in a
    code fence -- the shell's
    `echo header; echo; echo '```'; cat reconcile_report.txt; echo '```'`.
    Assumes report_text already ends in a newline (reconcile.py's own
    output does, one `print()` per line), same as the shell's `cat` did.
    """
    return f"### Splunk state reconciliation\n\n```\n{report_text}```\n"


# --- orchestration (I/O, but every side effect injected) -------------------------


@dataclass(frozen=True)
class ReconcileOps:
    """The side effects this step needs. main() supplies the real,
    subprocess/filesystem-backed versions; tests supply fakes -- same
    Resolvers/GhOps injection pattern slices 1-3 used.
    """

    run_reconcile: Callable[[Sequence[str]], tuple[int, str]]
    read_report: Callable[[], dict | None]


def run_step(
    ops: ReconcileOps,
    *,
    event_name: str,
    retire_orphans: str,
    log: Callable[[str], None],
    write_summary: Callable[[str], None],
) -> int:
    """One run of the step, start to finish. Every branch runs
    unconditionally in the order the shell ran them in -- write the summary,
    then the drift warning, then the failure warning -- regardless of rc;
    see the module docstring for why Python does not need the shell's
    `if`-exemption trick to get there.
    """
    extra_args = build_extra_args(event_name, retire_orphans)
    if extra_args:
        log("Retiring removal orphans as requested by the dispatch input.")

    rc, report_text = ops.run_reconcile(extra_args)

    write_summary(build_step_summary(report_text))

    report = ops.read_report()
    if report is not None:
        unresolved = corrected_unresolved_count(report)
        renamed = corrected_renamed_count(report)
        missing = missing_count(report)
        dupes = dupes_count(report)
        parts = build_drift_warning_parts(unresolved, renamed, missing, dupes)
        warning = build_drift_warning(parts)
        if warning is not None:
            log(warning)

    if rc != 0:
        log(build_reconcile_failure_warning(rc))

    return rc


# --- the I/O half ------------------------------------------------------------------


def run_reconcile_subprocess(cmd: Sequence[str]) -> tuple[int, str]:
    """Mirrors `<cmd> | tee reconcile_report.txt` plus
    `rc="${PIPESTATUS[0]}"`: reconcile.py's stdout is streamed line-by-line
    to our own stdout (so it still appears live in the job log) and
    simultaneously collected into the returned text (the tee'd copy). stderr
    is left connected to our own stderr (`stderr=None` inherits it), exactly
    like the original pipe -- which only ever redirected stdout -- so
    reconcile.py's `print(..., file=sys.stderr)` diagnostics (a rule missing
    detect_id, an HTTP error) land directly in the job log, same as before,
    and are never part of the captured report text or the step summary.
    """
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None, text=True, bufsize=1)
    assert proc.stdout is not None
    lines: list[str] = []
    for line in proc.stdout:
        print(line, end="", flush=True)
        lines.append(line)
    proc.wait()
    return proc.returncode, "".join(lines)


def read_reconcile_json(path: str = RECONCILE_JSON_PATH) -> dict | None:
    """None when the file does not exist OR fails to parse -- reconcile.py
    always writes well-formed JSON when it writes at all (json.dumps of its
    own report dict), so a parse failure here is not a realistic path; folding
    it into the same "skip the drift block" behaviour as file-absent is
    strictly safer than letting an exception escape and kill the whole step
    the way an un-exempted `jq` failure would have under the shell's `-e`.
    """
    p = Path(path)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def default_reconcile_ops() -> ReconcileOps:
    def run_reconcile(extra_args: Sequence[str]) -> tuple[int, str]:
        return run_reconcile_subprocess(reconcile_command(extra_args))

    return ReconcileOps(run_reconcile=run_reconcile, read_report=read_reconcile_json)


def main(argv: list[str] | None = None) -> int:
    _ = argv  # no arguments: every input arrives as an environment variable
    env = os.environ
    event_name = env.get("GITHUB_EVENT_NAME", "")
    retire_orphans = env.get("RETIRE_ORPHANS", "")

    def log(msg: str) -> None:
        print(msg, flush=True)

    def write_summary(text: str) -> None:
        path = env.get("GITHUB_STEP_SUMMARY", "")
        if not path:
            eprint("[note] GITHUB_STEP_SUMMARY is not set -- skipping this write (not running under GitHub Actions?).")
            return
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(text)

    return run_step(
        default_reconcile_ops(),
        event_name=event_name,
        retire_orphans=retire_orphans,
        log=log,
        write_summary=write_summary,
    )


if __name__ == "__main__":
    sys.exit(main())
