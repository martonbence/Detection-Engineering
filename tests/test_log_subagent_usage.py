"""The SubagentStop hook that feeds .claude/agent_usage_log.jsonl.

The log's key set and order are a contract with .claude/generate_dashboard.py
(wrong keys once broke CI), so the row shape is pinned here.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("log_subagent_usage", Path(__file__).resolve().parents[1] / ".claude" / "hooks" / "log_subagent_usage.py")
hook = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hook)

KEYS = ["date", "name", "slug", "task", "tokens", "tool_uses", "duration_ms", "model"]
NAMES = {"bjorn-detection-content-reviewer": "Bjorn"}


def transcript(tmp_path: Path) -> Path:
    usage1 = {"input_tokens": 2, "cache_creation_input_tokens": 100, "cache_read_input_tokens": 0, "output_tokens": 10}
    usage2 = {"input_tokens": 2, "cache_creation_input_tokens": 5, "cache_read_input_tokens": 100, "output_tokens": 20}
    rows = [
        {"type": "user", "timestamp": "2026-10-25T14:00:00.000Z", "message": {"role": "user", "content": "Review the diff.\nSecond line."}},
        {"type": "assistant", "timestamp": "2026-10-25T14:00:10.000Z", "message": {"model": "claude-sonnet-5-5", "usage": usage1, "content": [{"type": "tool_use", "name": "Read"}, {"type": "text", "text": "x"}]}},
        {"type": "attachment", "timestamp": "2026-10-25T14:00:11.000Z"},
        {"type": "assistant", "timestamp": "2026-10-25T14:01:00.500Z", "message": {"model": "claude-sonnet-5-5", "usage": usage2, "content": [{"type": "tool_use", "name": "Bash"}]}},
    ]
    path = tmp_path / "agent.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\nnot json\n", encoding="utf-8")
    return path


def test_row_shape_and_values(tmp_path):
    row = hook.build_row("bjorn-detection-content-reviewer", transcript(tmp_path), NAMES)
    assert list(row) == KEYS
    assert (row["name"], row["tokens"], row["tool_uses"], row["duration_ms"], row["model"]) == ("Bjorn", 127, 2, 60500, "sonnet")
    assert row["task"] == "Review the diff."


def test_non_roster_agents_are_ignored(tmp_path):
    assert hook.build_row("general-purpose", transcript(tmp_path), NAMES) is None


def test_duplicate_dispatch_is_not_logged_twice(tmp_path):
    log = tmp_path / "log.jsonl"
    log.write_text('{"date": "x", "name": "Kai"}', encoding="utf-8")  # no trailing newline
    row = hook.build_row("bjorn-detection-content-reviewer", transcript(tmp_path), NAMES)
    assert hook.append_row(row, log) is True
    assert hook.append_row(row, log) is False
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2 and json.loads(lines[1]) == row


def test_empty_transcript_yields_no_row(tmp_path):
    empty = tmp_path / "e.jsonl"
    empty.write_text("", encoding="utf-8")
    assert hook.build_row("bjorn-detection-content-reviewer", empty, NAMES) is None


def test_roster_reads_real_agent_files():
    names = hook.roster()
    assert names["yuki-detection-engineer"] == "Yuki"
    assert "gaz-reference" not in names
