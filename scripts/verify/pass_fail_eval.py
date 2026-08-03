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

Not verified  : two independent routes, both meaning "we did not measure this",
                never "this rule is broken":
                (a) attack side -- rule's tester is "atomic" and its Atomic Red
                    Team test did not reach a "completed" progress marker (see
                    --progress-dir), e.g. run_atomic.ps1 was killed by its
                    10-minute timeout before getting to this rule;
                (b) measurement side -- the Splunk query carried an error with
                    error_kind "unmeasured": the search never finished, the
                    network dropped, or Splunk answered unparseably.
                Both are distinct from FAIL: nothing was learned either way, so
                reporting a confirmed negative would be inventing data. Note
                (b) reaches emulation-tested rules too, unlike (a).

Outputs:
  <results-dir>/<detect_id>/result.json   — per-rule verdict
  $GITHUB_STEP_SUMMARY                    — Markdown table (GitHub Actions), aggregated across this run's rules

Exit code:
  0  All rules PASS
  1  One or more rules FAIL or NOT_VERIFIED
"""

import re
import sys
import json
import os
import argparse
from datetime import datetime, timezone
from pathlib import Path

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

PASS_EMOJI = "✅"
FAIL_EMOJI = "❌"
NOT_VERIFIED_EMOJI = "⚠️"

EMOJI_BY_VERDICT = {
    PASS: PASS_EMOJI,
    FAIL: FAIL_EMOJI,
    NOT_VERIFIED: NOT_VERIFIED_EMOJI,
}


def verdict_label(verdict: str) -> str:
    """Human-facing display text for a verdict (e.g. 'NOT_VERIFIED' -> 'NOT VERIFIED')."""
    return DISPLAY_LABEL.get(verdict, verdict)


def verdict_emoji(verdict: str) -> str:
    return EMOJI_BY_VERDICT.get(verdict, FAIL_EMOJI)


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
    emoji = PASS_EMOJI if overall == PASS else FAIL_EMOJI
    passed = report["passed"]
    failed = report["failed"]
    not_verified = report.get("not_verified", 0)
    total = report["total_rules"]
    run_ts = report["run_timestamp"]

    lines = [
        f"# {emoji} Detection Verification — {verdict_label(overall)}",
        "",
        f"**{passed} / {total}** rules passed &nbsp;·&nbsp; "
        f"**{failed}** failed &nbsp;·&nbsp; "
        f"**{not_verified}** not verified &nbsp;·&nbsp; "
        f"threshold: **{report['min_pass']}–{report['max_pass']} events**",
        "",
        f"> Run timestamp: `{run_ts}`",
        "",
        "| Rule | Title | Events | Verdict | Reason |",
        "|:-----|:------|-------:|:-------:|:-------|",
    ]

    for r in report["rules"]:
        v_emoji = verdict_emoji(r["verdict"])
        lines.append(
            f"| `{r['detect_id']}` | {r['title']} | {r['event_count']} "
            f"| {v_emoji} {verdict_label(r['verdict'])} | {r['reason']} |"
        )

    lines += [
        "",
        "---",
        f"Pass criteria: **{report['min_pass']} ≤ events ≤ {report['max_pass']}**  ",
        f"{NOT_VERIFIED_EMOJI} NOT VERIFIED: the attack did not complete (Atomic Red Team "
        "test cut short) or the measurement did not complete (Splunk search did not finish) "
        "-- unknown, not broken; treated the same as FAIL for gating purposes.  ",
        "Results saved to `outputs/results/`",
    ]

    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


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
             "run_atomic.ps1 (merged from atomic_verify + atomic_verify_dc). "
             "When provided, rules whose tester is 'atomic' but that never "
             "reached a 'completed' marker are verdict NOT_VERIFIED instead "
             "of whatever hits.json would otherwise say. Omit to disable "
             "this check entirely (backward compatible).",
    )
    args = parser.parse_args(argv)

    matched_dir = Path(args.matched_events_dir)
    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    progress_dir: Path | None = Path(args.progress_dir) if args.progress_dir else None

    run_ts = datetime.now(timezone.utc).isoformat()

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
                "tester": "atomic",
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

        # Two independent ways a rule can end up unverified, checked in this
        # order because they answer different questions. First: did the attack
        # run? (progress markers, atomic only). Then: did the measurement run?
        # (error_kind from the Splunk query). A rule whose test completed fine
        # but whose search timed out reaches the second check with a completed
        # marker, which is exactly the case that used to fall through to FAIL.
        if tester == "atomic" and not atomic_test_completed(progress_dir, detect_id):
            verdict = NOT_VERIFIED
            reason = "Atomic Red Team test did not complete before step timeout"
        else:
            verdict, reason = evaluate(
                event_count, error, args.min_pass, args.max_pass, error_kind
            )

        if verdict != PASS:
            all_pass = False

        result = {
            "detect_id": detect_id,
            "title": title,
            "verdict": verdict,
            "reason": reason,
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

        report_rows.append(result)
        v_emoji = verdict_emoji(verdict)
        print(f"  {v_emoji}  {detect_id}  →  {verdict_label(verdict)}  ({event_count} events)  {reason}")

    overall = PASS if all_pass else FAIL
    aggregate_report = {
        "overall": overall,
        "run_timestamp": run_ts,
        "min_pass": args.min_pass,
        "max_pass": args.max_pass,
        "total_rules": len(report_rows),
        "passed": sum(1 for r in report_rows if r["verdict"] == PASS),
        "failed": sum(1 for r in report_rows if r["verdict"] == FAIL),
        "not_verified": sum(1 for r in report_rows if r["verdict"] == NOT_VERIFIED),
        "rules": report_rows,
    }

    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_path:
        write_github_summary(summary_path, aggregate_report)

    overall_emoji = PASS_EMOJI if overall == PASS else FAIL_EMOJI
    print(
        f"\n{'─' * 60}"
        f"\n{overall_emoji}  Overall: {verdict_label(overall)}  "
        f"({aggregate_report['passed']}/{aggregate_report['total_rules']} rules passed, "
        f"{aggregate_report['not_verified']} not verified)"
        f"\n{'─' * 60}"
    )

    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
