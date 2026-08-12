"""Append-only per-rule verdict history (register item 4.6).

`result.json` answers "what is the current verdict"; `history.jsonl` answers
"what has it been" -- this file pins both the shared reader/writer in
lib/verdict_history.py and the one place that calls it, pass_fail_eval.main(),
alongside the existing test_pass_fail_gate.py harness pattern.
"""

import json

from lib.verdict_history import append_entry, history_path, read_history
from pass_fail_eval import main
from test_pass_fail_gate import write_hits

# --- the shared module itself --------------------------------------------------


def test_history_path_sits_under_the_rule_directory(tmp_path):
    assert history_path(tmp_path, "DETECT-2026-0001_Alpha") == (
        tmp_path / "DETECT-2026-0001_Alpha" / "history.jsonl"
    )


def test_reading_a_missing_history_returns_empty(tmp_path):
    assert read_history(tmp_path, "DETECT-2026-0001_Alpha") == []


def test_append_then_read_round_trips(tmp_path):
    append_entry(tmp_path, "DETECT-2026-0001_Alpha", {"verdict": "PASS", "run_id": "1"})
    append_entry(tmp_path, "DETECT-2026-0001_Alpha", {"verdict": "FAIL", "run_id": "2"})
    entries = read_history(tmp_path, "DETECT-2026-0001_Alpha")
    assert [e["run_id"] for e in entries] == ["1", "2"]
    assert entries[0]["verdict"] == "PASS"
    assert entries[1]["verdict"] == "FAIL"


def test_append_creates_the_rule_directory(tmp_path):
    """No prior result.json/mkdir needed -- append_entry is self-sufficient."""
    append_entry(tmp_path, "DETECT-2026-0099_New", {"verdict": "PASS"})
    assert (tmp_path / "DETECT-2026-0099_New" / "history.jsonl").exists()


def test_a_corrupt_line_is_skipped_not_fatal(tmp_path):
    """A killed step or a torn write should not blind the dashboard to every
    run before and after the bad line."""
    path = history_path(tmp_path, "DETECT-2026-0001_Alpha")
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps({"verdict": "PASS", "run_id": "1"}) + "\n"
        "{not json\n"
        + json.dumps({"verdict": "FAIL", "run_id": "3"}) + "\n",
        encoding="utf-8",
    )
    entries = read_history(tmp_path, "DETECT-2026-0001_Alpha")
    assert [e["run_id"] for e in entries] == ["1", "3"]


def test_blank_lines_are_ignored(tmp_path):
    path = history_path(tmp_path, "DETECT-2026-0001_Alpha")
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"verdict": "PASS", "run_id": "1"}) + "\n\n\n", encoding="utf-8")
    assert len(read_history(tmp_path, "DETECT-2026-0001_Alpha")) == 1


# --- wired into pass_fail_eval.main() ------------------------------------------


def test_a_verify_run_appends_one_history_line(tmp_path):
    matched = tmp_path / "matched"
    write_hits(matched, "DETECT-A", "emulation", event_count=3)

    results = tmp_path / "results"
    exit_code = main(
        ["--matched-events-dir", str(matched), "--results-dir", str(results), "--run-id", "1"]
    )

    assert exit_code == 0
    history = read_history(results, "DETECT-A")
    assert len(history) == 1
    assert history[0]["verdict"] == "PASS"
    assert history[0]["run_id"] == "1"


def test_result_json_is_overwritten_but_history_accumulates(tmp_path):
    """The whole point of the item: result.json only ever shows the latest
    verdict, history.jsonl keeps every one of them."""
    matched = tmp_path / "matched"
    results = tmp_path / "results"

    write_hits(matched, "DETECT-A", "emulation", event_count=3)  # PASS
    main(["--matched-events-dir", str(matched), "--results-dir", str(results), "--run-id", "1"])

    write_hits(matched, "DETECT-A", "emulation", event_count=0)  # FAIL
    main(["--matched-events-dir", str(matched), "--results-dir", str(results), "--run-id", "2"])

    latest = json.loads((results / "DETECT-A" / "result.json").read_text(encoding="utf-8"))
    assert latest["verdict"] == "FAIL"

    history = read_history(results, "DETECT-A")
    assert [h["verdict"] for h in history] == ["PASS", "FAIL"]
    assert [h["run_id"] for h in history] == ["1", "2"]


def test_history_entry_carries_the_provenance_fields(tmp_path):
    """These are what the future dashboard sparkline/tooltip needs -- pinned
    so a later refactor of pass_fail_eval.py cannot quietly drop one."""
    matched = tmp_path / "matched"
    d = matched / "DETECT-A"
    d.mkdir(parents=True)
    (d / "hits.json").write_text(
        json.dumps(
            {
                "detect_id": "DETECT-A",
                "title": "T",
                "tester": "emulation",
                "testing_enabled": True,
                "event_count": 3,
                "error": None,
                "error_kind": None,
                "events": [],
                "rule_version": "1.4",
                "git_sha": "abc123",
            }
        ),
        encoding="utf-8",
    )

    results = tmp_path / "results"
    main(["--matched-events-dir", str(matched), "--results-dir", str(results), "--run-id", "7"])

    entry = read_history(results, "DETECT-A")[0]
    assert entry["rule_version"] == "1.4"
    assert entry["git_sha"] == "abc123"
    assert entry["run_id"] == "7"
    assert entry["event_count"] == 3
    assert "run_timestamp" in entry
