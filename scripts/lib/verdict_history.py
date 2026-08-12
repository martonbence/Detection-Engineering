"""Append-only per-rule verdict history (register item 4.6).

`pass_fail_eval.py` writes one `result.json` per rule, and every run
overwrites it -- only the latest verdict survives, so "is this rule flaky"
or "when did it start failing" have no answer without digging through git
log on a file that was never meant to carry history (the same anti-pattern
item 3.5 already names for `rule_version`). This module adds the other half:
an append-only `history.jsonl` next to it, one line per verify run, that
`result.json` deliberately does not replace.

Read and write both live here because both sides need the same shape and the
same path -- `pass_fail_eval.py` appends after every run, `generate_stats.py`
reads it back to build the dashboard's per-rule sparkline. Neither side owns
a policy the other needs to disagree with (unlike `lib/meta_sidecar.py`'s
three readers), so there is nothing to split.

Deliberately unbounded. A cap would answer "was it flaky recently" while
quietly deleting the answer to "when did it start" the moment the cause is
older than the cap -- which is the exact question this file exists to
answer. Display-side code (the dashboard sparkline) is what decides how much
of this to show; the log itself keeps everything.
"""

import json
from pathlib import Path


def history_path(results_dir: Path, detect_id: str) -> Path:
    return results_dir / detect_id / "history.jsonl"


def append_entry(results_dir: Path, detect_id: str, entry: dict) -> None:
    path = history_path(results_dir, detect_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def read_history(results_dir: Path, detect_id: str) -> list[dict]:
    """Oldest first. A corrupt line is skipped, not fatal to the rest --
    one bad append (a killed step, a full disk) should not blind the
    dashboard to every run before and after it."""
    path = history_path(results_dir, detect_id)
    if not path.exists():
        return []
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries
