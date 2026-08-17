"""
pass_fail_eval.py — Evaluate Pass/Fail for each rule based on Splunk matched events.

Usage:
    python pass_fail_eval.py [--matched-events-dir outputs/verify/matched_events]
                             [--results-dir outputs/results]
                             [--min-pass 1] [--max-pass 10]

Pass criteria : MIN_PASS <= event_count <= MAX_PASS
Fail criteria : event_count < MIN_PASS  (no alerts fired)
              | event_count > MAX_PASS  (too many / noisy)
              | error with error_kind "rule_error" -- the saved search is not
                deployed, or the search job itself errored inside Splunk

Not verified  : three independent routes, all meaning "we did not measure
                this", never "this rule is broken":
                (a) disabled side -- run #125, 2026-08-17: the rule's sidecar
                    carries `testing_enabled: False` (custom.testing.enabled:
                    false in the Sigma rule). Nobody attacked it this run, so
                    check_saved_search_hits.py never dispatched a query for
                    it, and whatever hits.json says about event_count is not
                    a measurement of anything -- checked FIRST, before (b),
                    because a disabled rule has no attack to have completed;
                (b) attack side -- rule's tester is "atomic" and its Atomic Red
                    Team test did not reach a "completed" progress marker (see
                    --progress-dir), e.g. run_atomic.ps1 was killed by its
                    10-minute timeout before getting to this rule;
                (c) measurement side -- the Splunk query carried an error with
                    error_kind "unmeasured": the search never finished, the
                    network dropped, or Splunk answered unparseably.
                All three are distinct from FAIL: nothing was learned either
                way, so reporting a confirmed negative would be inventing
                data. Note (c) reaches emulation-tested rules too, unlike (b).

                (a) is also distinct from (b) and (c) in how it is *gated*:
                a disabled rule is an intentional, ongoing state (today: 27 of
                28 rules, while a shared-script change forces mode=all), not a
                transient failure to measure. Counting it against the run's
                exit code would turn "one rule under test passed cleanly"
                into a red X for reasons nobody watching this run caused or
                can fix by re-running it. So (a) is tallied separately (the
                "disabled" count) and excluded from the exit-code gate that
                (b) and (c) are still subject to.

Outputs:
  <results-dir>/<detect_id>/result.json    — per-rule verdict, overwritten every run
  <results-dir>/<detect_id>/history.jsonl  — the same verdict, appended every run (register item 4.6)
  $GITHUB_STEP_SUMMARY                     — Markdown table (GitHub Actions), aggregated across this run's rules

Exit code:
  0  All rules PASS, or NOT_VERIFIED only because testing is disabled for them
  1  One or more rules FAIL, or NOT_VERIFIED for a reason other than being disabled
"""

import argparse
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.summary import (
    ALERT_FAIL,
    ALERT_PASS,
    ALERT_WARN,
    MARK_FAIL,
    MARK_PASS,
    MARK_UNKNOWN,
    alert,
    escape_cell,
)
from lib.verdict_history import append_entry

PASS = "PASS"
FAIL = "FAIL"
NOT_VERIFIED = "NOT_VERIFIED"

# Internal verdict identifiers above stay underscore-free/underscored to match
# the PASS/FAIL naming convention. Everything shown to a human (step summary
# table, printed lines, reasons) uses the display labels below instead.
DISPLAY_LABEL = {
    PASS: "PASS",
    FAIL: "FAIL",
    NOT_VERIFIED: "NOT VERIFIED",
}

MARK_BY_VERDICT = {
    PASS: MARK_PASS,
    FAIL: MARK_FAIL,
    NOT_VERIFIED: MARK_UNKNOWN,
}


def verdict_label(verdict: str) -> str:
    """Human-facing display text for a verdict (e.g. 'NOT_VERIFIED' -> 'NOT VERIFIED')."""
    return DISPLAY_LABEL.get(verdict, verdict)


def verdict_mark(verdict: str) -> str:
    return MARK_BY_VERDICT.get(verdict, MARK_FAIL)


def _sanitize_marker_name(detect_id: str) -> str:
    """Mirror run_atomic.ps1's `-replace '[^A-Za-z0-9_.-]', '_'` so marker
    filenames written on the Windows runner and read back here always match."""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", detect_id or "")


def atomic_test_completed(progress_dir: Path | None, detect_id: str) -> bool:
    """True only if run_atomic.ps1 flushed a {"status": "completed"} marker
    for this detect_id. Missing progress_dir, missing marker file, or a
    marker stuck at "started" all mean the Atomic Red Team test did not
    finish -- most commonly because the step hit its 10-minute timeout
    partway through testing multiple rules."""
    if progress_dir is None:
        return True  # no progress tracking requested -> don't override anything
    marker = progress_dir / f"{_sanitize_marker_name(detect_id)}.json"
    if not marker.is_file():
        return False
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return False
    return data.get("status") == "completed"


# Mirrors check_saved_search_hits.py's ERR_UNMEASURED. Only this exact kind
# softens a query error into NOT_VERIFIED; anything else -- including an
# unrecognised or absent kind, which is what result files written before this
# field existed look like -- keeps the original FAIL behaviour. Unknown input
# should not be able to talk its way out of a failure.
ERR_UNMEASURED = "unmeasured"


def evaluate(
    event_count: int,
    error: str | None,
    min_pass: int,
    max_pass: int,
    error_kind: str | None = None,
) -> tuple[str, str]:
    """Return (verdict, reason)."""
    if error:
        # A query that could not complete says nothing about the detection.
        # Reporting it as FAIL would manufacture a confirmed negative from
        # missing data -- the same mistake NOT_VERIFIED exists to prevent on
        # the attack side, arriving here from the measurement side instead.
        if error_kind == ERR_UNMEASURED:
            return NOT_VERIFIED, f"Could not measure: {error}"
        return FAIL, f"Splunk query error: {error}"
    if event_count < min_pass:
        return FAIL, f"Too few events: {event_count} (min expected: {min_pass})"
    if event_count > max_pass:
        return FAIL, f"Too many events: {event_count} (max expected: {max_pass})"
    return PASS, f"Event count {event_count} within expected range [{min_pass}–{max_pass}]"


def write_github_summary(path: str, report: dict) -> None:
    overall = report["overall"]
    passed = report["passed"]
    failed = report["failed"]
    not_verified = report.get("not_verified", 0)
    disabled = report.get("disabled", 0)
    total = report["total_rules"]
    run_ts = report["run_timestamp"]
    min_pass = report["min_pass"]
    max_pass = report["max_pass"]

    if overall == PASS:
        alert_kind = ALERT_PASS
    elif overall == NOT_VERIFIED:
        alert_kind = ALERT_WARN
    else:
        alert_kind = ALERT_FAIL

    # The counts line names only the states that actually occurred. A run where
    # everything passed used to still read "0 failed · 0 not verified", which
    # spends the most-read line in the summary describing things that did not
    # happen.
    tallies = [f"{passed} passed"]
    if failed:
        tallies.append(f"{failed} failed")
    if not_verified:
        tallies.append(f"{not_verified} not verified")
    if disabled:
        tallies.append(f"{disabled} disabled")

    lines = ["## Detection verification", ""]
    lines += alert(
        alert_kind,
        # The two trailing spaces are a markdown hard break. Without them the
        # verdict line and the context line join into one paragraph, which is
        # exactly what this layout exists to avoid.
        f"**{verdict_mark(overall)} {verdict_label(overall)}** — "
        f"{' · '.join(tallies)} of {total} rule(s)  \n"
        f"Pass band: {min_pass}–{max_pass} events · run `{run_ts}`",
    )
    lines += [
        "",
        "| Rule | Title | Events | Verdict | Reason |",
        "|:---|:---|---:|:---|:---|",
    ]

    for r in report["rules"]:
        lines.append(
            f"| `{escape_cell(r['detect_id'])}` "
            f"| {escape_cell(r['title'])} "
            f"| {r['event_count']} "
            f"| {verdict_mark(r['verdict'])} {verdict_label(r['verdict'])} "
            f"| {escape_cell(r['reason'])} |"
        )

    # The NOT VERIFIED legend is a footnote about a state, so it belongs in the
    # summary only when that state occurred. Printed unconditionally it told
    # every clean run at length about a failure mode it had not hit.
    if not_verified:
        lines += [
            "",
            f"{MARK_UNKNOWN} **NOT VERIFIED** — the attack did not complete (Atomic Red Team "
            "test cut short) or the measurement did not complete (Splunk search did not "
            "finish). Unknown, not broken; gated the same as FAIL.",
        ]

    # Distinct from the NOT VERIFIED footnote above on purpose (run #125,
    # 2026-08-17): a disabled rule was never attacked, so "the attack did not
    # complete" would be false for it, not just imprecise. These rows still
    # show verdict NOT VERIFIED in the table -- nothing was measured -- but
    # are not gated: a disabled rule staying disabled cannot be turned green
    # by re-running the pipeline, so counting it against the run would be
    # reporting a failure nobody can act on.
    if disabled:
        lines += [
            "",
            f"{MARK_UNKNOWN} **NOT VERIFIED (disabled)** — testing is disabled for these rules "
            "(`custom.testing.enabled: false`); no attack ran and no search was dispatched for "
            "them this run. Not gated -- excluded from the pass/fail count above.",
        ]

    lines += ["", "<sub>Per-rule detail in `outputs/results/`.</sub>", ""]

    # Appended, not written. This used to truncate the file, which is safe only
    # as long as nothing else writes a summary in the same step -- a constraint
    # nothing enforced and no other writer in the repo relies on.
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError as ex:
        print(f"WARNING: could not write the step summary: {ex}", file=sys.stderr)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate Pass/Fail for Splunk verification results"
    )
    parser.add_argument(
        "--matched-events-dir", default="outputs/verify/matched_events",
        help="Directory produced by check_saved_search_hits.py",
    )
    parser.add_argument(
        "--results-dir", default="outputs/results",
        help="Directory to write per-rule verdict JSON files",
    )
    parser.add_argument(
        "--min-pass", type=int, default=1,
        help="Minimum event count for PASS (default: 1)",
    )
    parser.add_argument(
        "--max-pass", type=int, default=10,
        help="Maximum event count for PASS (default: 10)",
    )
    parser.add_argument(
        "--run-id", default="",
        help="GitHub Actions run ID (${{ github.run_id }})",
    )
    parser.add_argument(
        "--progress-dir", default="",
        help="Directory of <detect_id>.json progress markers written by "
             "run_atomic.ps1 (merged from atomic_verify, atomic_verify_dc and "
             "emulation_verify). When provided, a rule whose testing is enabled "
             "but that never reached a 'completed' marker is verdict "
             "NOT_VERIFIED instead of whatever hits.json would otherwise say. "
             "Omit to disable this check entirely (backward compatible).",
    )
    args = parser.parse_args(argv)

    matched_dir = Path(args.matched_events_dir)
    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    progress_dir: Path | None = Path(args.progress_dir) if args.progress_dir else None

    run_ts = datetime.now(UTC).isoformat()

    summaries: list[dict] = []
    seen_detect_ids: set[str] = set()
    if matched_dir.is_dir():
        for subdir in sorted(matched_dir.iterdir()):
            hf = subdir / "hits.json"
            if hf.is_file():
                data = json.loads(hf.read_text(encoding="utf-8"))
                summary = {k: v for k, v in data.items() if k != "events"}
                summaries.append(summary)
                did = summary.get("detect_id")
                if did:
                    seen_detect_ids.add(did)

    # A rule can have a progress marker (its Atomic Red Team test was
    # scheduled to run) but no hits.json at all -- e.g. check_saved_search_hits.py
    # never got a chance to dispatch a query for it. Synthesize a minimal
    # placeholder summary so the NOT_VERIFIED gate below still applies to it
    # instead of silently dropping it from the report.
    if progress_dir is not None and progress_dir.is_dir():
        for marker_file in sorted(progress_dir.glob("*.json")):
            try:
                marker_data = json.loads(marker_file.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                continue
            marker_detect_id = str(marker_data.get("detect_id") or marker_file.stem)
            if marker_detect_id in seen_detect_ids:
                continue
            summaries.append({
                "detect_id": marker_detect_id,
                "title": "",
                "event_count": 0,
                "error": None,
                # The marker names its own tester as of register item 2.8;
                # markers written before that field existed are atomic by
                # construction, since emulation rules had none.
                "tester": str(marker_data.get("tester") or "atomic"),
                # A marker only exists because something set out to attack this
                # rule, so testing was enabled. Stating it explicitly matters:
                # the gate below requires it, and this summary is synthesized
                # rather than read from a hits.json that would have carried it.
                "testing_enabled": True,
            })
            seen_detect_ids.add(marker_detect_id)

    if not summaries:
        print("No verification summaries found in matched_events_dir. Nothing to evaluate.")
        return 0

    print(f"\nEvaluating {len(summaries)} rule(s)  (pass window: {args.min_pass}–{args.max_pass} events)\n")

    report_rows: list[dict] = []
    all_pass = True

    for summary in summaries:
        detect_id = summary.get("detect_id", "unknown")
        title = summary.get("title", "")
        event_count = int(summary.get("event_count", 0))
        error = summary.get("error") or None
        error_kind = summary.get("error_kind") or None
        tester = str(summary.get("tester") or "").strip().lower()

        # `is False` on purpose, not plain falsiness: a rule with no testing
        # config at all is a different, pre-existing case (missing/None) and
        # must not be pulled into this branch -- only a sidecar that
        # explicitly recorded custom.testing.enabled: false counts as
        # "deliberately not attacked this run". Checked before the two
        # NOT_VERIFIED routes below because a disabled rule has no attack to
        # have completed and no measurement worth trusting either -- run #125,
        # 2026-08-17: 27 disabled rules were scored PASS/FAIL from stale or
        # coincidental background Splunk data because nothing skipped them.
        disabled = summary.get("testing_enabled") is False

        if disabled:
            verdict = NOT_VERIFIED
            reason = "Testing is disabled for this rule (custom.testing.enabled: false)"
        # Two independent ways an *enabled* rule can end up unverified,
        # checked in this order because they answer different questions.
        # First: did the attack run? (progress markers, atomic only). Then:
        # did the measurement run? (error_kind from the Splunk query). A rule
        # whose test completed fine but whose search timed out reaches the
        # second check with a completed marker, which is exactly the case
        # that used to fall through to FAIL. Register item 2.8. This used to
        # read `tester == "atomic"`, which left the 8 emulation-tested rules
        # outside the gate entirely: an emulation command that never ran
        # produced no events, and no events scored FAIL -- a confirmed
        # negative manufactured from an attack that never happened, which is
        # the exact thing NOT_VERIFIED exists to prevent.
        elif (
            summary.get("testing_enabled")
            and tester in ("atomic", "emulation")
            and not atomic_test_completed(progress_dir, detect_id)
        ):
            verdict = NOT_VERIFIED
            reason = f"{tester.capitalize()} test did not complete before step timeout"
        else:
            verdict, reason = evaluate(
                event_count, error, args.min_pass, args.max_pass, error_kind
            )

        # A disabled rule is excluded from the gate entirely: it is an
        # intentional, ongoing state, not a transient failure to measure, so
        # it must not turn a run where every *enabled* rule passed into a
        # reported failure. Both the other NOT_VERIFIED routes above (and
        # FAIL) still gate the run, unchanged.
        if verdict != PASS and not disabled:
            all_pass = False

        result = {
            "detect_id": detect_id,
            "title": title,
            "verdict": verdict,
            "reason": reason,
            "disabled": disabled,
            "event_count": event_count,
            "min_pass": args.min_pass,
            "max_pass": args.max_pass,
            "earliest": summary.get("earliest", ""),
            "latest": summary.get("latest", ""),
            "run_timestamp": run_ts,
            "rule_version": summary.get("rule_version", ""),
            "git_sha": summary.get("git_sha", ""),
            "run_id": args.run_id,
        }

        rule_results_dir = results_dir / detect_id
        rule_results_dir.mkdir(parents=True, exist_ok=True)
        (rule_results_dir / "result.json").write_text(
            json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        # Register item 4.6. result.json above is this run's answer; this is
        # every run's answer, so "is this rule flaky" has something to look at.
        append_entry(
            results_dir,
            detect_id,
            {
                "run_timestamp": run_ts,
                "verdict": verdict,
                "disabled": disabled,
                "event_count": event_count,
                "rule_version": summary.get("rule_version", ""),
                "git_sha": summary.get("git_sha", ""),
                "run_id": args.run_id,
            },
        )

        report_rows.append(result)
        print(f"  {verdict_mark(verdict)}  {detect_id}  →  {verdict_label(verdict)}  ({event_count} events)  {reason}")

    overall = PASS if all_pass else FAIL
    aggregate_report = {
        "overall": overall,
        "run_timestamp": run_ts,
        "min_pass": args.min_pass,
        "max_pass": args.max_pass,
        "total_rules": len(report_rows),
        "passed": sum(1 for r in report_rows if r["verdict"] == PASS),
        "failed": sum(1 for r in report_rows if r["verdict"] == FAIL),
        # "disabled" is carved out of "not_verified" rather than counted
        # inside it: both are NOT_VERIFIED verdicts, but they mean different
        # things and only one of them is gated (see all_pass above), so
        # lumping them together in the tallies would misreport *why* a run
        # with 27 disabled rules and 0 genuine not-verified rules still says
        # "0 not verified" -- true, but only distinguishable from "27" if the
        # two are split here.
        "not_verified": sum(1 for r in report_rows if r["verdict"] == NOT_VERIFIED and not r["disabled"]),
        "disabled": sum(1 for r in report_rows if r["disabled"]),
        "rules": report_rows,
    }

    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_path:
        write_github_summary(summary_path, aggregate_report)

    print(
        f"\n{'─' * 60}"
        f"\n{verdict_mark(overall)}  Overall: {verdict_label(overall)}  "
        f"({aggregate_report['passed']}/{aggregate_report['total_rules']} rules passed, "
        f"{aggregate_report['not_verified']} not verified, "
        f"{aggregate_report['disabled']} disabled)"
        f"\n{'─' * 60}"
    )

    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
