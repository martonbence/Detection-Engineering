# scripts/state/open_promotion_pr.py
#
# The dev pipeline's last job: `open_promotion_pr`'s "Open promotion PR to
# main and mark it In review" step in ci_dev_workflow.yml.
#
# Extracted verbatim (in behaviour, not in syntax) from ~137 lines of inline
# `gh`-CLI-heavy bash -- audit/feature-and-process-audit.md item 4.1, slice 3
# (slice 1 was determine_changed_rules.py, slice 2 was
# merge_verification_results.py). That register item is about the workflows'
# inline shell being the repo's largest untestable surface. Every branch
# below is now covered by tests/test_open_promotion_pr.py.
#
# What this step does, unchanged from the shell:
#   1. `gh pr list` for an already-open dev->main PR. If one exists, write a
#      step-summary block and exit 0 without creating anything. This call is
#      NOT best-effort: a failure here aborts the step, same as the shell's
#      bare `existing_url=$(gh pr list ...)` under `set -euo pipefail`.
#   2. audit/remediation-plan.md item 4.11 (closed; that file's own 4.11 --
#      the active register's section 4 only runs 4.1-4.8, so this is not the
#      same numbered item as this extraction's own audit/feature-and-process-
#      audit.md item 4.1 above), best-effort: fetch outputs/reports/stats.json
#      off `dev` via the contents API and compute
#      stale_count = verified_expired + verified_superseded. Any failure
#      (API error, malformed JSON, missing keys) falls back to stale_count=0,
#      never aborts the step.
#   3. If stale_count > 0, build a GFM [!WARNING] blockquote (stale_note) and
#      a plain ::warning:: annotation line.
#   4. audit/remediation-plan.md item 4.9 (same caveat as 4.11 above), best-
#      effort: diff main...dev via `gh api compare`,
#      extract DETECT-####-#### ids from the changed filenames, look each up
#      in the stats_json already fetched above to build a markdown
#      rule_table. Any failure/empty result degrades to an empty table,
#      never aborts. A changed id missing from stats_json is silently
#      dropped, not flagged -- a documented, accepted gap (see
#      build_rule_table's docstring), not a bug.
#   5. Build the PR body (fixed sentence + optional stale_note + optional
#      rule_table), `gh pr create` it (also not best-effort -- a failure here
#      aborts the step), log success, write a step-summary block.
#   6. Best-effort: add the new PR to GitHub Project #3 and set its Status
#      field to "In review". Either call failing only emits a ::warning::,
#      never fails the step -- GH_PAT_DEV_PUSH likely lacks Projects
#      permission on fine-grained PATs for user-owned projects, a documented,
#      accepted limitation, not something to "fix" here.
#
# The split, following slice 1/2's shape but adapted to this step's own
# character -- linear, several independent best-effort try/fallback
# branches, nothing that retries:
#   parse_stats_json() / compute_stale_count() --
#                             pure. Turn the raw contents-API response into a
#                             stale rule count, folding every failure mode
#                             (absent, malformed, missing keys) into 0.
#   build_stale_note() / stale_warning_annotation() --
#                             pure. The GFM blockquote and the plain
#                             annotation line, from just the count.
#   extract_changed_rule_ids() / build_rule_table() --
#                             pure. DETECT-####-#### extraction from compare
#                             filenames, then the markdown table -- no gh
#                             calls, no jq.
#   build_pr_body() / build_step_summary() / build_project_*_warning() --
#                             pure string assembly for the remaining
#                             GitHub-facing text.
#   GhOps / run_step()     -- the orchestration, with every `gh` call
#                             injected as a callable (a GhOps bundle), same
#                             Resolvers-injection pattern slice 1 and slice 2
#                             used -- so a test drives it with fakes instead
#                             of a real GitHub repo/token.
#   main()                  -- wires the real `gh`-subprocess calls into
#                             run_step() and writes GITHUB_STEP_SUMMARY.
#
# Exit codes: 0 on every path this step can legitimately take, including
# "PR already open" and every best-effort branch failing. A non-zero exit
# only happens if `gh pr list` or `gh pr create` themselves fail (mirroring
# the shell's `set -euo pipefail` aborting on those two specifically, since
# neither is wrapped in `2>/dev/null` or `|| true` in the original).
#
# One deliberate hardening, not a behaviour change for any realistic input:
# build_rule_table() below runs title/level through lib.summary.escape_cell()
# before dropping them into a markdown table cell. The old bash never did --
# a title containing `|` would have broken the table, the same class of bug
# summary.py's own docstring documents happening for real in a different
# script (run #69, the deploy's Outcome column). Bash could not import
# lib.summary at all ("bash cannot import it", per the comments this step
# left behind); now that this is Python, there is no reason to leave that
# gap open. No `|`-free title renders any differently than before.

from __future__ import annotations

import functools
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.summary import ALERT_WARN, MARK_FAIL, MARK_INFO, MARK_PASS, MARK_UNKNOWN, MARK_WARN, alert, escape_cell

# GitHub Project #3 ("Detection Engineering Platform"), its Status field, and
# the "In review" option -- fixed ids the shell hard-coded, reproduced as-is.
PROJECT_NUMBER = "3"
PROJECT_OWNER = "martonbence"
PROJECT_ID = "PVT_kwHOA_8eh84BeHTL"
STATUS_FIELD_ID = "PVTSSF_lAHOA_8eh84BeHTLzhYj6O0"
IN_REVIEW_OPTION_ID = "4fdb6324"

_PROJECT_PERM_NOTE = (
    "GH_PAT_DEV_PUSH likely lacks Projects permission -- known gap for fine-grained PATs on user-owned projects"
)

# The rules/sigma detect id shape, same expression the shell's
# `grep -oE 'DETECT-[0-9]{4}-[0-9]{4}'` used.
RULE_ID_RE = re.compile(r"DETECT-\d{4}-\d{4}")

RULE_TABLE_HEADER = "### Rules in this promotion\n\n| Detect ID | Title | Level | Verdict |\n|---|---|---|---|"

PR_BODY_INTRO_TEMPLATE = (
    "Automatically opened because the dev pipeline run {run_id} reported PASS. "
    "This promotes the already-verified, already-compiled SPL to the prod Splunk App. "
    "Review and merge manually to deploy to production -- this PR does not auto-merge. "
    "If you edit any `.spl` content in this review, re-run the dev workflow before merging "
    "(push to `dev` again, or a manual `workflow_dispatch`): prod verifies the build-provenance "
    "signature recorded for the exact bytes that run produced, so a hand-edited file with no "
    "matching signature will stop the deploy."
)


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


# --- stats.json / stale_count (pure) -----------------------------------------


def parse_stats_json(raw: str) -> dict | None:
    """Turn the contents-API response into a dict, or None on any problem.

    None covers every way the best-effort fetch/parse can come up empty: the
    API call failed (raw == ""), the response was not valid JSON, or it
    parsed to something other than a JSON object. Every caller below treats
    None the same way the shell's `2>/dev/null || echo 0` / `-n "$stats_json"`
    checks did -- fall back, never abort.
    """
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def compute_stale_count(stats: dict | None) -> int:
    """verified_expired + verified_superseded, defaulting every failure to 0.

    audit/remediation-plan.md item 4.11: pass_fail_eval.py only scores the
    rules a run touched, so a verdict that quietly expired or was superseded
    on an untouched rule never fails anything on its own -- this surfaces
    the count instead of blocking on it.
    """
    if stats is None:
        return 0
    try:
        expired = stats.get("verified_expired", 0) or 0
        superseded = stats.get("verified_superseded", 0) or 0
        return int(expired) + int(superseded)
    except (TypeError, ValueError):
        return 0


def build_stale_note(stale_count: int) -> str:
    """The GFM [!WARNING] blockquote, or "" when there is nothing stale.

    Marks/alert-kind sourced from lib.summary directly now -- the old bash
    kept these in sync by hand with a comment pointing back here, because
    bash could not import the module at all.
    """
    if stale_count <= 0:
        return ""
    body = (
        f"{MARK_WARN} {stale_count} rule(s) already deployed to prod have an expired or superseded "
        "verification verdict -- no evidence they still work, through no fault of this run. See the "
        "Evidence card on the Console for which ones. This does not block promotion; schedule a manual "
        "re-run for them when convenient."
    )
    return "\n".join(alert(ALERT_WARN, body))


def stale_warning_annotation(stale_count: int) -> str | None:
    """The plain ::warning:: log line, or None when there is nothing stale."""
    if stale_count <= 0:
        return None
    return f"::warning::{stale_count} rule(s) in prod have an expired or superseded verdict -- see the Console's Evidence card"


# --- rule_table (pure) --------------------------------------------------------


def extract_changed_rule_ids(filenames: Sequence[str]) -> list[str]:
    """DETECT-####-#### ids found anywhere in the changed filenames, deduped
    and sorted -- the moral equivalent of
    `grep -oE 'DETECT-[0-9]{4}-[0-9]{4}' | sort -u`.
    """
    ids: set[str] = set()
    for name in filenames:
        ids.update(RULE_ID_RE.findall(name))
    return sorted(ids)


def _verdict_cell(verdict: str | None) -> str:
    if verdict == "PASS":
        return f"{MARK_PASS} PASS"
    if verdict == "FAIL":
        return f"{MARK_FAIL} FAIL"
    if verdict == "NOT_VERIFIED":
        return f"{MARK_UNKNOWN} NOT VERIFIED"
    return f"{MARK_INFO} {verdict or 'never tested'}"


def build_rule_table(changed_ids: Sequence[str], stats: dict | None) -> str:
    """The markdown table of rules touched by this dev->main diff, or "" if
    there is nothing to show.

    audit/remediation-plan.md item 4.9. A changed id with no matching entry in stats.json's
    `rules` list (e.g. a rule deleted in this diff -- it is no longer in
    stats.json's rules list) is silently dropped rather than flagged as a
    removal -- a documented, accepted gap for how this repo uses promotion
    PRs today (adding/changing rules), not a claim deletions never happen.
    """
    if not changed_ids or stats is None:
        return ""

    rules_by_id: dict[str, dict] = {}
    for rule in stats.get("rules") or []:
        did = rule.get("detect_id")
        if did and did not in rules_by_id:
            rules_by_id[did] = rule

    rows: list[str] = []
    for did in changed_ids:
        rule = rules_by_id.get(did)
        if rule is None:
            continue
        title = escape_cell(rule.get("title") or "")
        level = escape_cell(rule.get("level") or "")
        verdict = _verdict_cell(rule.get("verdict"))
        rows.append(f"| `{did}` | {title} | {level} | {verdict} |")

    if not rows:
        return ""
    return RULE_TABLE_HEADER + "\n" + "\n".join(rows)


# --- PR body / step summary / project-board messages (pure) ------------------


def build_pr_body(run_id: str, stale_note: str, rule_table: str) -> str:
    body = PR_BODY_INTRO_TEMPLATE.format(run_id=run_id)
    if stale_note:
        body += "\n\n" + stale_note
    if rule_table:
        body += "\n\n" + rule_table
    return body


def build_step_summary(*, pr_url: str, already_open: bool, stale_note: str, rule_table: str) -> str:
    mark = MARK_INFO if already_open else MARK_PASS
    verb = "Already open" if already_open else "Opened"
    lines = ["### Promotion PR", "", f"{mark} {verb}: {pr_url}"]
    if stale_note:
        lines += ["", stale_note]
    if rule_table:
        lines += ["", rule_table]
    return "\n".join(lines) + "\n"


def build_project_add_failed_warning(pr_url: str, detail: str) -> str:
    return f"::warning::Opened {pr_url} but failed to add it to Project #3 ({_PROJECT_PERM_NOTE}): {detail}"


def build_project_edit_failed_warning(pr_url: str) -> str:
    return f"::warning::Opened {pr_url} but failed to set its Project #3 status to In review ({_PROJECT_PERM_NOTE})"


# --- orchestration (I/O, but every gh call injected) --------------------------


@dataclass(frozen=True)
class GhOps:
    """The `gh` side effects this step needs. main() supplies the real,
    subprocess-backed versions; tests supply fakes -- same Resolvers/GitOps
    injection pattern slice 1 and slice 2 used.
    """

    find_existing_pr_url: Callable[[], str]
    fetch_stats_json: Callable[[], str]
    fetch_compare_filenames: Callable[[], list[str]]
    create_pr: Callable[[str], str]
    add_to_project: Callable[[str], tuple[bool, str]]
    set_project_status: Callable[[str], tuple[bool, str]]


def run_step(
    gh: GhOps,
    *,
    run_id: str,
    log: Callable[[str], None],
    write_summary: Callable[[str], None],
) -> int:
    """One run of the step, start to finish. Always returns 0 -- the two
    calls that can abort the real step (find_existing_pr_url, create_pr) are
    expected to raise on failure rather than return an error value, same as
    the shell dying under `set -euo pipefail`; main() is what turns that into
    a process exit code.
    """
    existing_url = gh.find_existing_pr_url()

    stats = parse_stats_json(gh.fetch_stats_json())
    stale_count = compute_stale_count(stats)
    stale_note = build_stale_note(stale_count)
    annotation = stale_warning_annotation(stale_count)
    if annotation is not None:
        log(annotation)

    rule_table = ""
    if stats is not None:
        changed_ids = extract_changed_rule_ids(gh.fetch_compare_filenames())
        rule_table = build_rule_table(changed_ids, stats)

    if existing_url:
        log(f"A dev -> main promotion PR is already open: {existing_url}")
        write_summary(
            build_step_summary(pr_url=existing_url, already_open=True, stale_note=stale_note, rule_table=rule_table)
        )
        return 0

    body = build_pr_body(run_id, stale_note, rule_table)
    pr_url = gh.create_pr(body)
    log(f"Opened promotion PR: {pr_url}")
    write_summary(build_step_summary(pr_url=pr_url, already_open=False, stale_note=stale_note, rule_table=rule_table))

    added, id_or_error = gh.add_to_project(pr_url)
    if not added:
        log(build_project_add_failed_warning(pr_url, id_or_error))
    else:
        edited, _detail = gh.set_project_status(id_or_error)
        if edited:
            log(f"Set Project #3 Status=In review for {pr_url}")
        else:
            log(build_project_edit_failed_warning(pr_url))

    return 0


# --- the I/O half --------------------------------------------------------------


def gh_find_existing_pr_url(repo: str) -> str:
    # Not best-effort: check=True, so a failure raises and propagates up to
    # main(), mirroring the shell dying under `set -euo pipefail` right here.
    result = subprocess.run(
        [
            "gh",
            "pr",
            "list",
            "--repo",
            repo,
            "--head",
            "dev",
            "--base",
            "main",
            "--state",
            "open",
            "--json",
            "url",
            "--jq",
            ".[0].url // empty",
        ],
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def gh_fetch_stats_json(repo: str) -> str:
    # Best-effort: check=False, stderr discarded, "" on any failure -- the
    # shell's `2>/dev/null` + `if stats_json=$(...)` pattern.
    result = subprocess.run(
        [
            "gh",
            "api",
            f"repos/{repo}/contents/outputs/reports/stats.json?ref=dev",
            "-H",
            "Accept: application/vnd.github.raw",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return ""
    return result.stdout


def gh_fetch_compare_filenames(repo: str) -> list[str]:
    # Best-effort: the shell's `... --jq '.files[].filename' 2>/dev/null | ... || true`.
    result = subprocess.run(
        ["gh", "api", f"repos/{repo}/compare/main...dev", "--jq", ".files[].filename"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return []
    return [line for line in result.stdout.splitlines() if line.strip()]


def gh_create_pr(repo: str, body: str) -> str:
    # Not best-effort: check=True, same reasoning as gh_find_existing_pr_url.
    result = subprocess.run(
        [
            "gh",
            "pr",
            "create",
            "--repo",
            repo,
            "--base",
            "main",
            "--head",
            "dev",
            "--title",
            "Promote verified detections from dev to main",
            "--label",
            "automated-promotion",
            "--body",
            body,
        ],
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def gh_add_to_project(pr_url: str) -> tuple[bool, str]:
    # Combined stdout+stderr captured either way, matching the shell's
    # `item_id=$(gh project item-add ... 2>&1)`: on success it is the item
    # id, on failure it is gh's error text, used verbatim in the warning.
    result = subprocess.run(
        ["gh", "project", "item-add", PROJECT_NUMBER, "--owner", PROJECT_OWNER, "--url", pr_url, "--format", "json", "--jq", ".id"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    return (result.returncode == 0, result.stdout.strip())


def gh_set_project_status(item_id: str) -> tuple[bool, str]:
    result = subprocess.run(
        [
            "gh",
            "project",
            "item-edit",
            "--id",
            item_id,
            "--project-id",
            PROJECT_ID,
            "--field-id",
            STATUS_FIELD_ID,
            "--single-select-option-id",
            IN_REVIEW_OPTION_ID,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    return (result.returncode == 0, result.stdout.strip())


def default_gh_ops(repo: str) -> GhOps:
    return GhOps(
        find_existing_pr_url=functools.partial(gh_find_existing_pr_url, repo),
        fetch_stats_json=functools.partial(gh_fetch_stats_json, repo),
        fetch_compare_filenames=functools.partial(gh_fetch_compare_filenames, repo),
        create_pr=functools.partial(gh_create_pr, repo),
        add_to_project=gh_add_to_project,
        set_project_status=gh_set_project_status,
    )


def main(argv: list[str] | None = None) -> int:
    _ = argv  # no arguments: every input arrives as an environment variable
    env = os.environ
    repo = env.get("GITHUB_REPOSITORY", "")
    run_id = env.get("GITHUB_RUN_ID", "")

    def log(msg: str) -> None:
        print(msg, flush=True)

    def write_summary(text: str) -> None:
        path = env.get("GITHUB_STEP_SUMMARY", "")
        if not path:
            eprint("[note] GITHUB_STEP_SUMMARY is not set -- skipping this write (not running under GitHub Actions?).")
            return
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(text)

    try:
        return run_step(default_gh_ops(repo), run_id=run_id, log=log, write_summary=write_summary)
    except subprocess.CalledProcessError as exc:
        # The two non-best-effort gh calls (pr list, pr create) failed. gh's
        # own stderr was never captured, so it already reached the step log;
        # exiting with the same code is what `set -euo pipefail` would do.
        return exc.returncode or 1


if __name__ == "__main__":
    sys.exit(main())
