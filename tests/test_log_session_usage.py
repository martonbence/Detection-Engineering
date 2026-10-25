"""The SessionEnd hook that logs Gaz's own session into .claude/agent_usage_log.jsonl."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("log_session_usage", Path(__file__).resolve().parents[1] / ".claude" / "hooks" / "log_session_usage.py")
hook = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hook)

KEYS = ["date", "name", "slug", "task", "tokens", "tool_uses", "duration_ms", "model"]


def rec(ts, mid, usage, tools=(), side=False, kind="assistant"):
    content = [{"type": "tool_use", "id": t} for t in tools]
    return {"type": kind, "timestamp": ts, "isSidechain": side, "uuid": mid + ts, "message": {"id": mid, "model": "claude-sonnet-5-5", "usage": usage, "content": content}}


def transcript(tmp_path: Path) -> Path:
    u = {"input_tokens": 1, "cache_creation_input_tokens": 9, "cache_read_input_tokens": 90, "output_tokens": 10}  # 110
    rows = [
        rec("2026-10-25T10:00:00.000Z", "m1", u, tools=["t1"]),
        rec("2026-10-25T10:00:00.000Z", "m1", u, tools=["t1"]),  # same response, second record
        rec("2026-10-25T10:01:00.000Z", "m2", u, tools=["t2", "t3"]),
        rec("2026-10-25T10:02:00.000Z", "side", u, tools=["x"], side=True),  # dispatched specialist: excluded
        rec("2026-10-25T20:00:00.000Z", "m3", u),  # 10 h idle gap before this: not counted as active time
    ]
    path = tmp_path / "session.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return path


def test_row_counts_each_response_once_and_skips_sidechains(tmp_path):
    row = hook.build_row(transcript(tmp_path), "7d3cf2f1-aaaa")
    assert list(row) == KEYS
    assert (row["name"], row["slug"], row["task"]) == ("Gaz", "gaz", "Lead session 7d3cf2f1")
    assert row["tokens"] == 330  # m1, m2, m3
    assert row["tool_uses"] == 3  # t1, t2, t3
    assert row["duration_ms"] == 60_000  # idle gaps excluded
    assert row["model"] == "sonnet"


def test_upsert_rewrites_the_same_session_and_keeps_other_lines(tmp_path):
    log = tmp_path / "log.jsonl"
    log.write_text('{"name": "Kai", "task": "x"}\n', encoding="utf-8")
    row = hook.build_row(transcript(tmp_path), "7d3cf2f1-aaaa")
    assert hook.upsert_row(row, log) == "added"
    row2 = {**row, "tokens": 999}
    assert hook.upsert_row(row2, log) == "updated"
    lines = [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 2 and lines[0]["name"] == "Kai" and lines[1]["tokens"] == 999


def test_empty_transcript_yields_no_row(tmp_path):
    empty = tmp_path / "e.jsonl"
    empty.write_text("", encoding="utf-8")
    assert hook.build_row(empty, "abc") is None
