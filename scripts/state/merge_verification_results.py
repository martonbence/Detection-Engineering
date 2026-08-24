# scripts/state/merge_verification_results.py
#
# The dev pipeline's write-back step: `update_dashboard`'s "Merge verification
# results, generate stats and commit" step in ci_dev_workflow.yml.
#
# Extracted verbatim (in behaviour, not in syntax) from ~137 lines of inline
# bash inside a `for i in 1 2 3; do ... done` retry loop --
# audit/feature-and-process-audit.md item 4.1, slice 2 (slice 1 was
# determine_changed_rules.py). That register item is about the workflows'
# inline shell being the repo's largest untestable surface. Every branch below
# is now covered by tests/test_merge_verification_results.py.
#
# What this step does, unchanged from the shell:
#   1. Per attempt (up to 3): reset the working tree to origin/dev's tip.
#   2. If this run's verification-results artifact was downloaded, overlay its
#      plain files into outputs/results/ (last verdict wins) and append each
#      .delta sidecar's one new history line to the matching results file,
#      but only if that line is not already the file's last line -- the
#      idempotency guard that makes a retry (or persist_results_fallback
#      replaying the same delta later) safe. No artifact is a normal state
#      (lab offline, or splunk_verify never reached staging), not an error.
#   3. Rebuild the dev deployment inventory via deployment_inventory.py, with
#      --deploy-report/--reconcile included only when those files exist; if
#      neither exists, the script is not invoked at all (not fatal either
#      way -- a failure here is a ::warning::, not a crash).
#   4. Regenerate stats/docs/rule-browser content via generate_stats.py.
#   5. Stage exactly outputs/results/, outputs/reports/, README.md,
#      docs/index.html -- never `git add -A`: outputs/verify/ holds the
#      downloaded artifact (including .delta sidecars) and must never be
#      committed.
#   6. Nothing staged -> exit 0 (no-op). Otherwise commit and push; on push
#      failure, sleep and retry the whole loop, up to 3 attempts total.
#
# The split, following determine_changed_rules.py's shape but adapted to this
# step's own character (a retry/idempotency state machine, not a single pure
# decision):
#   needs_delta_append()   -- pure. One delta line, one on-disk last line, one
#                              bool: does this line still need appending.
#   merge_overlay_files()/
#   merge_delta_files()     -- real file I/O (they copy/append bytes), but
#                              deterministic and cheap to run against a tmp_path
#                              in a test -- no subprocess, no real git repo.
#   build_inventory_args()  -- pure given two Path objects; the four
#                              presence/absence combinations are the whole
#                              contract with deployment_inventory.py's CLI.
#   run_attempt()           -- one iteration of the loop body, with every git
#                              call and every subprocess call injected (a
#                              GitOps bundle plus two callables), so a test
#                              drives it with fakes instead of a real repo --
#                              same Resolvers-injection pattern slice 1 used.
#   merge_and_commit_loop() -- pure. The retry/backoff state machine itself:
#                              how many times run_attempt() is called, when it
#                              sleeps, and what the final exit code is, given
#                              only the sequence of AttemptOutcomes it saw.
#   main()                  -- wires the real git/subprocess calls into
#                              run_attempt() and drives merge_and_commit_loop().
#
# Exit codes: 0 = a commit landed, or there was nothing to commit (both are
# success). 1 = three attempts all failed to push.

from __future__ import annotations

import functools
import os
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

# Where the "Download verification results" step (continue-on-error, may not
# exist at all) unpacks the artifact. Deliberately a download side path, not
# outputs/results/ itself -- the artifact carries .delta sidecars, and this
# step's own `git add` only stages outputs/results/, so unpacking in place
# would risk committing them.
DOWNLOAD_DIR = "outputs/verify/results_download/results"
RESULTS_DIR = "outputs/results"

# Both land in .gitignore'd directories -- see the workflow's "Download dev
# deploy report" / "Download reconciliation report" steps -- which is what
# lets them survive the `git reset --hard` below untouched.
DEPLOY_REPORT_PATH = "outputs/deploy/dev_deploy_report.json"
RECONCILE_PATH = "outputs/state/reconcile.json"

COMMIT_MESSAGE = "chore(pipeline): verification results and dashboard [skip ci]"
MAX_ATTEMPTS = 3


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


# --- delta merge idempotency (pure) ------------------------------------------


def needs_delta_append(new_line: str, last_line: str) -> bool:
    """Does this .delta sidecar's line still need to land in the results file?

    A blank new_line (an empty delta -- nothing new was appended this run)
    is never written, mirroring the shell's `[ -z "$new_line" ] && continue`.
    Otherwise idempotent on purpose: the line is only appended if it is not
    already the file's last line, which is what makes a retry safe against
    a delta being replayed after a concurrent run already carried it in (or
    after persist_results_fallback replays it later).
    """
    if not new_line:
        return False
    return new_line != last_line


def _tail_line(path: Path) -> str:
    """The moral equivalent of `tail -n 1 path`; "" if the file is empty or absent.

    history.jsonl-style files hold one JSON object per line, so line-based
    reading is sufficient here -- this is not meant to reproduce bash `tail`
    byte-for-byte on arbitrary binary input.
    """
    if not path.is_file():
        return ""
    text = path.read_text(encoding="utf-8")
    if not text:
        return ""
    lines = text.splitlines()
    return lines[-1] if lines else ""


# --- the overlay/delta merge (real file I/O, no subprocess/git) --------------


def merge_overlay_files(dl: Path, results_dir: Path) -> list[str]:
    """Plain overlay for every non-.delta file: this run's verdict replaces the
    previous one. Returns the relative paths touched, for logging/assertions.
    """
    touched: list[str] = []
    for src in sorted(p for p in dl.rglob("*") if p.is_file() and p.suffix != ".delta"):
        rel = src.relative_to(dl)
        dest = results_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(src.read_bytes())
        touched.append(str(rel))
    return touched


def merge_delta_files(dl: Path, results_dir: Path) -> list[str]:
    """Append-only merge for every .delta sidecar, via needs_delta_append().

    Each .delta holds exactly the one line this run's pass_fail_eval.py
    appended for that rule; it is appended to whatever is on disk after the
    reset, which may already carry lines a concurrent run pushed for rules
    this run never touched -- overwriting from a snapshot would silently
    erase those, which is why this never rewrites the destination file.
    """
    touched: list[str] = []
    for src in sorted(p for p in dl.rglob("*.delta") if p.is_file()):
        rel = src.relative_to(dl)
        dest_rel = str(rel)[: -len(".delta")]
        dest = results_dir / dest_rel

        new_line = _tail_line(src)
        last_line = _tail_line(dest)
        if not needs_delta_append(new_line, last_line):
            continue

        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open("a", encoding="utf-8") as fh:
            fh.write(new_line + "\n")
        touched.append(dest_rel)
    return touched


# --- deployment_inventory.py arg assembly (pure) ------------------------------


def build_inventory_args(deploy_report: Path, reconcile: Path) -> list[str]:
    """The --deploy-report/--reconcile flags to pass, for whichever of the two
    files exist. Empty when neither does -- the caller's contract (matching
    the shell's `${#inv_args[@]} -gt 0` check) is that an empty list means
    "do not invoke deployment_inventory.py at all", not "invoke it with no
    report". Naming a missing file makes the script warn, and if both were
    unreadable it would refuse to write at all -- skipping is not fatal
    either way, an inventory that missed one run is a far smaller loss than a
    dashboard that never regenerated because a bookkeeping step failed.
    """
    args: list[str] = []
    if deploy_report.is_file():
        args += ["--deploy-report", str(deploy_report)]
    if reconcile.is_file():
        args += ["--reconcile", str(reconcile)]
    return args


# --- one retry attempt (I/O, but every git/subprocess call injected) --------


class AttemptOutcome(Enum):
    NO_CHANGES = "no_changes"
    PUSHED = "pushed"
    PUSH_FAILED = "push_failed"


@dataclass(frozen=True)
class GitOps:
    """The git side effects one attempt needs. main() supplies the real,
    subprocess-backed versions; tests supply fakes -- same Resolvers-injection
    pattern determine_changed_rules.py uses for its three rule-listing calls.
    """

    fetch_reset: Callable[[], None]
    diff_cached_quiet: Callable[[], bool]
    commit: Callable[[str], None]
    push: Callable[[], bool]


def run_attempt(
    i: int,
    *,
    dl: Path,
    results_dir: Path,
    deploy_report: Path,
    reconcile: Path,
    git: GitOps,
    run_inventory: Callable[[list[str]], None],
    run_generate_stats: Callable[[], None],
    stage_paths: Callable[[], None],
    log: Callable[[str], None],
) -> AttemptOutcome:
    """One pass of the shell's `for i in 1 2 3` loop body.

    Everything here is re-derived from inputs that live OUTSIDE the git tree
    (the downloaded artifacts, in .gitignore'd or untracked directories),
    which is why `git.fetch_reset()` can be this blunt on every attempt and
    still be correct on attempt 2 and 3.
    """
    git.fetch_reset()

    if dl.is_dir():
        log("Merging this run's verification results...")
        merge_overlay_files(dl, results_dir)
        merge_delta_files(dl, results_dir)
    else:
        log(
            "No verification results artifact for this run (lab offline, or "
            "verification did not reach the staging step). Regenerating from "
            "the previously committed state."
        )

    inv_args = build_inventory_args(deploy_report, reconcile)
    if inv_args:
        run_inventory(inv_args)
    else:
        log("No deploy or reconcile report for this run; leaving the deployment inventory as committed.")

    log("Regenerating aggregate stats, MITRE coverage map, and rule browser content...")
    run_generate_stats()

    stage_paths()

    if git.diff_cached_quiet():
        log("No changes to commit.")
        return AttemptOutcome.NO_CHANGES

    git.commit(COMMIT_MESSAGE)

    if git.push():
        log("Push succeeded.")
        return AttemptOutcome.PUSHED

    return AttemptOutcome.PUSH_FAILED


# --- the retry/backoff state machine (pure) -----------------------------------


def merge_and_commit_loop(
    attempt: Callable[[int], AttemptOutcome],
    sleep_fn: Callable[[int], None],
    *,
    max_attempts: int = MAX_ATTEMPTS,
    log: Callable[[str], None] | None = None,
) -> int:
    """How many times `attempt` gets called, when it sleeps, and the final
    exit code -- driven only by the sequence of AttemptOutcomes it returns.

    Preserved quirk: the shell's loop slept after attempt 3's failure too
    (`sleep $((i * 2))` runs unconditionally at the bottom of every iteration,
    including the last), even though nothing reads that sleep's result before
    the loop ends and the script exits 1. Harmless -- it costs the job a few
    seconds of idle time -- but reproduced verbatim rather than "optimized
    away" here, per the same reasoning slice 1 used for git fetch --depth=0:
    changing what a relocated step does, even to something strictly better,
    is a behaviour change and not what this extraction is for.
    """

    def emit(msg: str) -> None:
        if log is not None:
            log(msg)

    for i in range(1, max_attempts + 1):
        outcome = attempt(i)
        if outcome in (AttemptOutcome.NO_CHANGES, AttemptOutcome.PUSHED):
            return 0
        emit(f"Push failed (attempt {i}), retrying...")
        sleep_fn(i * 2)

    emit("Push failed after 3 attempts.")
    return 1


# --- the I/O half --------------------------------------------------------------


def _run(cmd: Sequence[str]) -> None:
    subprocess.run(cmd, check=True)


def git_fetch_reset() -> None:
    _run(["git", "fetch", "origin", "dev"])
    _run(["git", "reset", "--hard", "origin/dev"])


def git_diff_cached_quiet() -> bool:
    # `git diff --cached --quiet` exits 0 when there is no difference from
    # HEAD, 1 when there is -- the same polarity the shell's `if ... ; then`
    # relied on.
    result = subprocess.run(["git", "diff", "--cached", "--quiet"], check=False)
    return result.returncode == 0


def git_commit(message: str) -> None:
    _run(["git", "commit", "-m", message])


def git_push() -> bool:
    result = subprocess.run(["git", "push", "origin", "HEAD:dev"], check=False)
    return result.returncode == 0


def default_git_ops() -> GitOps:
    return GitOps(
        fetch_reset=git_fetch_reset,
        diff_cached_quiet=git_diff_cached_quiet,
        commit=git_commit,
        push=git_push,
    )


def stage_paths() -> None:
    # Deliberately scoped, never `git add -A`: outputs/verify/ holds the
    # downloaded artifact (including the .delta sidecars) and must never be
    # committed.
    _run(["git", "add", "outputs/results/", "outputs/reports/", "README.md", "docs/index.html"])


def run_inventory(inv_args: list[str]) -> None:
    cmd = [
        sys.executable,
        "scripts/state/deployment_inventory.py",
        "--env",
        "dev",
        *inv_args,
        "--commit",
        os.environ.get("GITHUB_SHA", ""),
        "--run-id",
        os.environ.get("GITHUB_RUN_ID", ""),
        "--run-url",
        "{server}/{repo}/actions/runs/{run_id}".format(
            server=os.environ.get("GITHUB_SERVER_URL", ""),
            repo=os.environ.get("GITHUB_REPOSITORY", ""),
            run_id=os.environ.get("GITHUB_RUN_ID", ""),
        ),
    ]
    result = subprocess.run(cmd, check=False)
    if result.returncode != 0:
        # Not fatal -- see build_inventory_args' docstring. Matches the
        # shell's `|| echo "::warning ..."`.
        print(
            "::warning title=Inventory not updated::deployment_inventory.py failed; "
            "the dashboard will show the previous deployment state.",
            flush=True,
        )


def run_generate_stats() -> None:
    _run([sys.executable, "scripts/docs/generate_stats.py"])


def main(argv: list[str] | None = None) -> int:
    _ = argv  # no arguments: every input arrives as an environment variable

    _run(["git", "config", "user.name", "github-actions[bot]"])
    _run(["git", "config", "user.email", "github-actions[bot]@users.noreply.github.com"])

    dl = Path(DOWNLOAD_DIR)
    results_dir = Path(RESULTS_DIR)
    deploy_report = Path(DEPLOY_REPORT_PATH)
    reconcile = Path(RECONCILE_PATH)

    def log(msg: str) -> None:
        print(msg, flush=True)

    attempt = functools.partial(
        run_attempt,
        dl=dl,
        results_dir=results_dir,
        deploy_report=deploy_report,
        reconcile=reconcile,
        git=default_git_ops(),
        run_inventory=run_inventory,
        run_generate_stats=run_generate_stats,
        stage_paths=stage_paths,
        log=log,
    )

    return merge_and_commit_loop(attempt, time.sleep, log=log)


if __name__ == "__main__":
    sys.exit(main())
