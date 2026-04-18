"""
pass_fail_eval.py — Evaluate Pass/Fail for each rule based on Splunk matched events.

Usage:
    python pass_fail_eval.py [--matched-events-dir outputs/verify/matched_events]
                             [--results-dir outputs/results]
                             [--min-pass 1] [--max-pass 20]

Pass criteria : MIN_PASS <= event_count <= MAX_PASS
Fail criteria : event_count < MIN_PASS  (no alerts fired)
              | event_count > MAX_PASS  (too many / noisy)
              | error field is non-null (Splunk query failed)

Outputs:
  <results-dir>/<detect_id>/result.json   — per-rule verdict
  <results-dir>/report.json               — aggregate report
  $GITHUB_STEP_SUMMARY                    — Markdown table (GitHub Actions)

Exit code:
  0  All rules PASS
  1  One or more rules FAIL
"""

import sys
import json
import os
import argparse
from datetime import datetime, timezone
from pathlib import Path

PASS = "PASS"
FAIL = "FAIL"
PASS_EMOJI = "✅"
FAIL_EMOJI = "❌"


def evaluate(
    event_count: int, error: str | None, min_pass: int, max_pass: int
) -> tuple[str, str]:
    """Return (verdict, reason)."""
    if error:
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
    total = report["total_rules"]
    run_ts = report["run_timestamp"]

    lines = [
        f"# {emoji} Detection Verification — {overall}",
        "",
        f"**{passed} / {total}** rules passed &nbsp;·&nbsp; "
        f"**{failed}** failed &nbsp;·&nbsp; "
        f"threshold: **{report['min_pass']}–{report['max_pass']} events**",
        "",
        f"> Run timestamp: `{run_ts}`",
        "",
        "| Rule | Title | Events | Verdict | Reason |",
        "|:-----|:------|-------:|:-------:|:-------|",
    ]

    for r in report["rules"]:
        v_emoji = PASS_EMOJI if r["verdict"] == PASS else FAIL_EMOJI
        lines.append(
            f"| `{r['detect_id']}` | {r['title']} | {r['event_count']} "
            f"| {v_emoji} {r['verdict']} | {r['reason']} |"
        )

    lines += [
        "",
        "---",
        f"Pass criteria: **{report['min_pass']} ≤ events ≤ {report['max_pass']}**  ",
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
    args = parser.parse_args(argv)

    matched_dir = Path(args.matched_events_dir)
    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    run_ts = datetime.now(timezone.utc).isoformat()

    summaries: list[dict] = []
    for subdir in sorted(matched_dir.iterdir()):
        hf = subdir / "hits.json"
        if hf.is_file():
            data = json.loads(hf.read_text(encoding="utf-8"))
            summaries.append({k: v for k, v in data.items() if k != "events"})

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

        verdict, reason = evaluate(event_count, error, args.min_pass, args.max_pass)
        if verdict == FAIL:
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
        v_emoji = PASS_EMOJI if verdict == PASS else FAIL_EMOJI
        print(f"  {v_emoji}  {detect_id}  →  {verdict}  ({event_count} events)  {reason}")

    overall = PASS if all_pass else FAIL
    aggregate_report = {
        "overall": overall,
        "run_timestamp": run_ts,
        "min_pass": args.min_pass,
        "max_pass": args.max_pass,
        "total_rules": len(report_rows),
        "passed": sum(1 for r in report_rows if r["verdict"] == PASS),
        "failed": sum(1 for r in report_rows if r["verdict"] == FAIL),
        "rules": report_rows,
    }

    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_path:
        write_github_summary(summary_path, aggregate_report)

    overall_emoji = PASS_EMOJI if overall == PASS else FAIL_EMOJI
    print(
        f"\n{'─' * 60}"
        f"\n{overall_emoji}  Overall: {overall}  "
        f"({aggregate_report['passed']}/{aggregate_report['total_rules']} rules passed)"
        f"\n{'─' * 60}"
    )

    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
