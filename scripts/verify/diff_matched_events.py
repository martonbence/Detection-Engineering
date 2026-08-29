"""
diff_matched_events.py — Field-level outlier analysis of a rule's matched events.

Register item 3.11. The old remediation-plan item 2.7 looked at the global
`--max-pass 10` window and rightly rejected changing it: a hard cap cannot
tell you whether a rule is too broad or the technique it detects genuinely
produces that many events. That conclusion stands. But it leaves a real,
narrower gap: when `event_count` comes back as 11 instead of 10, nothing
today says *which* matched event was the extra one, or what distinguishes it
from the other ten. `check_saved_search_hits.py` already writes the raw
event set behind every verdict into `hits.json` (`events: [...]`) -- this
script is the missing second half: read that array and answer "which
field(s) does this event set split along?".

Not wired into any CI job. It answers a question a human asks *after* seeing
a verdict that looks wrong (an unexpected FAIL/count, a rule oscillating
between runs in history.jsonl) -- an investigative tool, not a gate. It
reads a `hits.json` written by `check_saved_search_hits.py` (either the
version still sitting under `outputs/verify/matched_events/<detect_id>/` from
a run that has not been cleaned up yet, or one pulled out of the
`matched-events-sigma-<run_id>` artifact -- see ci_dev_workflow.yml register
item 3.10 -- before its 14-day retention expires). A bare JSON array of event
dicts is also accepted, so a hand-extracted or synthetic event set works
without constructing a full hits.json wrapper.

Method: for every field present on at least one event, collapse each event's
value for that field to a hashable form (missing keys become the sentinel
"(missing)", multivalue/list fields become a tuple) and count how often each
distinct value occurs. A field is reported only when it *splits* the event
set: at least two distinct values, and the most common one is held by a
strict majority of the events (> half). That is deliberately narrower than
"has more than one value" -- a field where every event disagrees (e.g. a raw
timestamp) has no majority to split against and would just be noise in the
report; a field that is constant across every event carries no information
either. Ranking is by minority size ascending, so the field where the
smallest number of events disagree with the rest -- the "1 of 11" case the
register item names directly -- surfaces first.

This is a descriptive tool, not a verdict. A field splitting 10-1 is a
strong candidate for "the extra event is noise on this field", but the human
still decides -- the script does not filter, relabel, or discard events.

Usage:
    python diff_matched_events.py <hits.json-or-events.json>
                                  [--top N]
                                  [--include-field FIELD ...]
                                  [--exclude-field FIELD ...]
                                  [--all-fields]
                                  [--json]

Exit code:
    0  Ran successfully (including the case where no splitting field exists
       -- a homogeneous or fully-divergent event set is a valid finding).
    2  Input file missing, unreadable, or not a hits.json / event-list shape.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

# Splunk metadata/bookkeeping fields that are expected to vary (or be
# meaningless) per event and would otherwise dominate every report with
# non-diagnostic "splits" -- a raw event body or an index-time byte offset
# differs on every hit by construction, and that is never the signal item
# 3.11 is after. Underscore-prefixed fields (_raw, _time, _cd, _bkt, _si,
# _kv, _serial, _subsecond, _indextime, ...) are excluded as a group via
# `exclude_underscore` rather than named one by one, because Splunk adds new
# ones across versions and an allow-by-default posture would silently start
# reporting on whichever one is new. --include-field / --all-fields opt back
# in when one of these turns out to matter for a specific investigation.
DEFAULT_EXCLUDE_FIELDS = frozenset({
    "linecount",
    "punct",
    "splunk_server",
    "splunk_server_group",
    "timestartpos",
    "timeendpos",
})

MISSING = "(missing)"


def _hashable(value: Any) -> Any:
    """Collapse a raw Splunk field value to something Counter can key on.

    Splunk's REST results endpoint renders every scalar as a string and every
    multivalue field as a JSON array -- never a bare int/float/bool/dict -- but
    this stays defensive against a hand-built or synthetic fixture that hands
    in native JSON types instead.
    """
    if isinstance(value, list):
        return tuple(_hashable(v) for v in value)
    if isinstance(value, dict):
        return tuple(sorted((k, _hashable(v)) for k, v in value.items()))
    return value


def load_events(path: Path) -> tuple[list[dict], dict]:
    """Return (events, context) from a hits.json or a bare JSON event list.

    context carries whatever identifying fields were available (detect_id,
    title, event_count as recorded) purely for the report header -- empty
    when the input was a bare list.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"could not read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not valid JSON: {exc}") from exc

    if isinstance(data, list):
        return data, {}

    if isinstance(data, dict) and isinstance(data.get("events"), list):
        context = {
            k: data.get(k)
            for k in ("detect_id", "title", "search_name", "event_count", "rule_version")
            if k in data
        }
        return data["events"], context

    raise ValueError(
        f"{path} is neither a hits.json (dict with an 'events' list) nor a bare JSON array of events"
    )


def find_splitting_fields(
    events: list[dict],
    exclude_fields: frozenset[str] = DEFAULT_EXCLUDE_FIELDS,
    exclude_underscore: bool = True,
    include_fields: frozenset[str] = frozenset(),
) -> list[dict]:
    """Return the fields the event set splits along, ranked most-decisive first.

    A field qualifies when it has >= 2 distinct values across `events` and the
    most common value is held by a strict majority (> total / 2) of events --
    see module docstring for why. Each qualifying field is reported with its
    majority value/count and every minority value with the (0-based) indices
    of the events that carry it, so a human can jump straight to
    `events[i]` for the raw record.

    Fields present on only some events are handled the same way as any other:
    the missing ones count as the value "(missing)", so a field only 10 of 11
    events have at all is exactly the kind of split this exists to surface.

    `include_fields` overrides both `exclude_fields` and `exclude_underscore`
    for the named fields specifically -- it is how a caller opts a single
    default-excluded field (e.g. `_time`) back in without disabling the
    exclusion wholesale.
    """
    total = len(events)
    if total < 2:
        return []

    all_fields: set[str] = set()
    for event in events:
        if isinstance(event, dict):
            all_fields.update(event.keys())

    results: list[dict] = []
    for field in sorted(all_fields):
        if field not in include_fields:
            if exclude_underscore and field.startswith("_"):
                continue
            if field in exclude_fields:
                continue

        counter: Counter = Counter()
        indices_by_value: dict[Any, list[int]] = {}
        for i, event in enumerate(events):
            raw = event.get(field, MISSING) if isinstance(event, dict) else MISSING
            key = _hashable(raw)
            counter[key] += 1
            indices_by_value.setdefault(key, []).append(i)

        if len(counter) < 2:
            continue  # constant across every event -- no split

        ranked = counter.most_common()
        majority_value, majority_count = ranked[0]
        if majority_count <= total / 2:
            continue  # no value held by a strict majority -- not a clean split

        minority = [
            {
                "value": value,
                "count": count,
                "event_indices": indices_by_value[value],
            }
            for value, count in ranked[1:]
        ]
        minority.sort(key=lambda m: m["count"])

        results.append({
            "field": field,
            "total_events": total,
            "distinct_values": len(counter),
            "majority_value": majority_value,
            "majority_count": majority_count,
            "minority_total": total - majority_count,
            "minority": minority,
        })

    # Smallest minority first: the field where the fewest events disagree with
    # the rest is the strongest "this is the odd one out" candidate -- exactly
    # the FAIL(11)-vs-PASS(10) case the register item names.
    results.sort(key=lambda r: (r["minority_total"], r["field"]))
    return results


def format_report(context: dict, events: list[dict], splits: list[dict], top: int | None) -> str:
    lines: list[str] = []
    header_bits = [f"{len(events)} event(s)"]
    if context.get("detect_id"):
        header_bits.insert(0, str(context["detect_id"]))
    if context.get("title"):
        header_bits.append(str(context["title"]))
    lines.append(" — ".join(header_bits))
    lines.append("")

    if len(events) < 2:
        lines.append("Fewer than 2 events; nothing to split.")
        return "\n".join(lines)

    if not splits:
        lines.append(
            "No field has a strict-majority value with a minority split "
            "(event set is homogeneous on every checked field, or every "
            "field disagrees on every event). Try --all-fields or "
            "--include-field to widen the search."
        )
        return "\n".join(lines)

    shown = splits if top is None else splits[:top]
    for split in shown:
        lines.append(
            f"* {split['field']}: {split['majority_count']}/{split['total_events']} = "
            f"{split['majority_value']!r}"
        )
        for m in split["minority"]:
            idx_str = ", ".join(str(i) for i in m["event_indices"])
            lines.append(f"    {m['count']} event(s) = {m['value']!r}  (events[{idx_str}])")
    if top is not None and len(splits) > top:
        lines.append(f"... {len(splits) - top} more splitting field(s), use --top to see them")
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Show which field(s) a rule's matched-event set splits along "
                     "(hits.json from check_saved_search_hits.py, or a bare JSON event list)"
    )
    parser.add_argument("input", help="Path to a hits.json or a JSON array of event dicts")
    parser.add_argument("--top", type=int, default=None, help="Show only the N most decisive splitting fields")
    parser.add_argument(
        "--include-field", action="append", default=[], metavar="FIELD",
        help="Force-include a field the defaults would otherwise exclude "
             "(e.g. an underscore-prefixed one, or _time). Repeatable.",
    )
    parser.add_argument(
        "--exclude-field", action="append", default=[], metavar="FIELD",
        help="Additionally exclude a field on top of the defaults. Repeatable.",
    )
    parser.add_argument(
        "--all-fields", action="store_true",
        help="Disable all default exclusions (underscore-prefixed and metadata fields) -- "
             "still honours --exclude-field.",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON instead of text")
    return parser


def main(argv: list[str]) -> int:
    args = build_arg_parser().parse_args(argv)

    try:
        events, context = load_events(Path(args.input))
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    exclude_fields = set() if args.all_fields else set(DEFAULT_EXCLUDE_FIELDS)
    exclude_fields |= set(args.exclude_field)
    exclude_underscore = not args.all_fields

    splits = find_splitting_fields(
        events,
        exclude_fields=frozenset(exclude_fields),
        exclude_underscore=exclude_underscore,
        include_fields=frozenset(args.include_field),
    )

    if args.json:
        print(json.dumps({"context": context, "total_events": len(events), "splits": splits}, indent=2, default=str))
    else:
        print(format_report(context, events, splits, args.top))

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
