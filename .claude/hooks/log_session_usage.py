#!/usr/bin/env python3
"""SessionEnd hook: upsert Gaz's own session usage into .claude/agent_usage_log.jsonl.

Companion to log_subagent_usage.py. Specialists are logged per dispatch; the
lead (Gaz) is the top-level session itself, so it is logged once per *session*
and the row is rewritten in place if the same session is logged again (resume,
or a manual run), keyed on the "Lead session <id8>" task text.

Same row shape as every other line (dashboard contract):
    date, name, slug, task, tokens, tool_uses, duration_ms, model

Values (the convention set when Gaz usage was first logged, 2026-08-29):
  tokens      throughput: input + cache creation + cache read + output summed
              over every top-level (non-sidechain) assistant message. Sidechain
              work is the dispatched specialists, already logged under their own
              names. This dwarfs any dispatch figure by design.
  tool_uses   tool_use blocks in those messages.
  duration_ms active time: the sum of gaps between consecutive records that are
              shorter than IDLE_GAP_S, so a session left open overnight does not
              count the night.
  model       family of the latest assistant message.

Usable two ways: as a SessionEnd hook (payload on stdin carries
`transcript_path` and `session_id`) or manually:
    python3 .claude/hooks/log_session_usage.py <transcript.jsonl>

Contract: always exits 0, prints nothing.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import sys
from datetime import datetime
from itertools import pairwise
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LOG_PATH = REPO_ROOT / ".claude" / "agent_usage_log.jsonl"
IDLE_GAP_S = 600
USAGE_KEYS = ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens", "output_tokens")


def model_label(raw: str) -> str:
    low = (raw or "").lower()
    for family in ("opus", "sonnet", "haiku", "fable"):
        if family in low:
            return family
    return raw or "not recorded"


def summarize(transcript: Path) -> dict | None:
    stamps: list[datetime] = []
    per_message: dict[str, int] = {}
    tool_ids: set[str] = set()
    model = ""
    for line in transcript.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if not isinstance(rec, dict) or rec.get("isSidechain"):
            continue
        ts = rec.get("timestamp")
        if isinstance(ts, str):
            with contextlib.suppress(ValueError):
                stamps.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
        msg = rec.get("message")
        if rec.get("type") != "assistant" or not isinstance(msg, dict) or not isinstance(msg.get("usage"), dict):
            continue
        # One API response is written as several records sharing a message id,
        # each repeating the same usage: count each response once.
        key = str(msg.get("id") or rec.get("uuid"))
        per_message[key] = sum(int(msg["usage"].get(k) or 0) for k in USAGE_KEYS)
        model = msg.get("model") or model
        for block in msg.get("content") or []:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                tool_ids.add(str(block.get("id") or f"{key}:{len(tool_ids)}"))
    if not per_message or not stamps:
        return None
    stamps.sort()
    active = sum(g for a, b in pairwise(stamps) if (g := (b - a).total_seconds()) < IDLE_GAP_S)
    return {
        "end": stamps[-1].astimezone(),
        "tokens": sum(per_message.values()),
        "tool_uses": len(tool_ids),
        "duration_ms": int(active * 1000),
        "model": model_label(model),
    }


def build_row(transcript: Path, session_id: str) -> dict | None:
    s = summarize(transcript)
    if s is None:
        return None
    return {
        "date": s["end"].strftime("%Y-%m-%d"),
        "name": "Gaz",
        "slug": "gaz",
        "task": f"Lead session {session_id[:8]}",
        "tokens": s["tokens"],
        "tool_uses": s["tool_uses"],
        "duration_ms": s["duration_ms"],
        "model": s["model"],
    }


def upsert_row(row: dict, log: Path = LOG_PATH) -> str:
    """Replace the line for this session, or append. Returns 'updated' or 'added'."""
    log.touch(exist_ok=True)
    with log.open("r+", encoding="utf-8") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        lines = fh.read().splitlines()
        new = json.dumps(row, ensure_ascii=False)
        outcome = "added"
        for i, line in enumerate(lines):
            try:
                old = json.loads(line)
            except ValueError:
                continue
            if isinstance(old, dict) and old.get("name") == "Gaz" and old.get("task") == row["task"]:
                lines[i] = new
                outcome = "updated"
                break
        else:
            lines.append(new)
        fh.seek(0)
        fh.truncate()
        fh.write("\n".join(lines) + "\n")
    return outcome


def main(argv: list[str]) -> int:
    try:
        if len(argv) > 1:
            transcript, session_id = Path(argv[1]), Path(argv[1]).stem
        else:
            payload = json.load(sys.stdin)
            transcript = Path(payload.get("transcript_path") or "")
            session_id = str(payload.get("session_id") or transcript.stem)
        if transcript.is_file():
            row = build_row(transcript, session_id)
            if row:
                upsert_row(row)
    except Exception:  # a logging hook must never fail a session
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
