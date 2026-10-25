#!/usr/bin/env python3
"""SubagentStop hook: append one row to .claude/agent_usage_log.jsonl.

Replaces the hand-written "log the dispatch after the <usage> block arrives"
step, which lapsed twice and once broke CI with wrong key names (the dashboard's
load_usage() and the ci_code_checks path filter both depend on the exact row
shape). The hook builds the row from the subagent's own transcript, so the keys
can never drift:

    date, name, slug, task, tokens, tool_uses, duration_ms, model

How each value is derived (checked against the <usage> blocks the harness
reports for the same dispatches):
  tokens      total of the LAST assistant turn's usage (input + cache creation +
              cache read + output) -- the context the agent ended with.
  tool_uses   number of tool_use blocks across the agent's assistant turns.
  duration_ms last transcript timestamp minus the first.
  model       family label ("opus" / "sonnet" / "haiku" / "fable" / raw id).

Only roster agents are logged (a file in .claude/agents/ named "<Name> - <Role>.md"
whose frontmatter `name:` equals the hook's agent_type); general-purpose,
Explore, forks and Gaz's reference file are ignored. A row identical in
name/slug/tokens/tool_uses/duration to an existing one is not written twice.

Contract: always exits 0 and prints nothing. A logging hiccup must never block
or confuse a dispatch.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import re
import sys
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
AGENTS_DIR = REPO_ROOT / ".claude" / "agents"
LOG_PATH = REPO_ROOT / ".claude" / "agent_usage_log.jsonl"
NEVER_LOGGED = {"gaz-reference"}
TASK_MAX = 110


def roster() -> dict[str, str]:
    """slug -> display name, from .claude/agents/<Name> - <Role>.md frontmatter."""
    out: dict[str, str] = {}
    for path in sorted(AGENTS_DIR.glob("*.md")):
        m = re.search(r"^name:\s*(\S+)\s*$", path.read_text(encoding="utf-8"), re.M)
        if m and m.group(1) not in NEVER_LOGGED:
            out[m.group(1)] = path.name.split(" - ", 1)[0]
    return out


def model_label(raw: str) -> str:
    low = (raw or "").lower()
    for family in ("opus", "sonnet", "haiku", "fable"):
        if family in low:
            return family
    return raw or "not recorded"


def _text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(c.get("text", "") for c in content if isinstance(c, dict) and c.get("type") == "text")
    return ""


def summarize(transcript: Path) -> dict | None:
    """Reduce a subagent transcript to the numbers the log needs."""
    stamps: list[datetime] = []
    tool_uses = 0
    last_usage: dict | None = None
    model = ""
    task = ""
    for line in transcript.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue
        ts = rec.get("timestamp")
        if isinstance(ts, str):
            with contextlib.suppress(ValueError):
                stamps.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
        msg = rec.get("message")
        if not isinstance(msg, dict):
            continue
        if rec.get("type") == "user" and not task:
            first = next((ln.strip() for ln in _text(msg.get("content")).splitlines() if ln.strip()), "")
            task = first
        if rec.get("type") == "assistant":
            if isinstance(msg.get("usage"), dict):
                last_usage = msg["usage"]
            model = msg.get("model") or model
            tool_uses += sum(1 for c in msg.get("content") or [] if isinstance(c, dict) and c.get("type") == "tool_use")
    if not last_usage or not stamps:
        return None
    tokens = sum(int(last_usage.get(k) or 0) for k in ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens", "output_tokens"))
    return {
        "end": max(stamps).astimezone(),
        "tokens": tokens,
        "tool_uses": tool_uses,
        "duration_ms": int((max(stamps) - min(stamps)).total_seconds() * 1000),
        "model": model_label(model),
        "task": task if len(task) <= TASK_MAX else task[: TASK_MAX - 1].rstrip() + "…",
    }


def build_row(agent_type: str, transcript: Path, names: dict[str, str]) -> dict | None:
    if agent_type not in names:
        return None
    s = summarize(transcript)
    if s is None:
        return None
    # Key order is part of the contract with generate_dashboard.load_usage().
    return {
        "date": s["end"].strftime("%Y-%m-%d"),
        "name": names[agent_type],
        "slug": agent_type,
        "task": s["task"] or "(no task text)",
        "tokens": s["tokens"],
        "tool_uses": s["tool_uses"],
        "duration_ms": s["duration_ms"],
        "model": s["model"],
    }


def append_row(row: dict, log: Path = LOG_PATH) -> bool:
    """Append unless an identical dispatch is already logged. True if written."""
    log.touch(exist_ok=True)
    with log.open("r+", encoding="utf-8") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        ident = (row["name"], row["slug"], row["tokens"], row["tool_uses"], row["duration_ms"])
        for line in fh:
            try:
                old = json.loads(line)
            except ValueError:
                continue
            if isinstance(old, dict) and (old.get("name"), old.get("slug"), old.get("tokens"), old.get("tool_uses"), old.get("duration_ms")) == ident:
                return False
        fh.seek(0, 2)
        if fh.tell():
            fh.seek(fh.tell() - 1)
            if fh.read(1) != "\n":
                fh.write("\n")
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    return True


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        transcript = Path(payload.get("agent_transcript_path") or "")
        if not transcript.is_file():
            return 0
        row = build_row(str(payload.get("agent_type") or ""), transcript, roster())
        if row:
            append_row(row)
    except Exception:  # a logging hook must never fail a dispatch
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
