"""
check_saved_search_hits.py — Dispatch deployed Splunk saved searches and capture matched events.

The SPL queries are already deployed as saved searches in Splunk (by deploy_spl_to_splunk.py).
This script dispatches each saved search over a given time window via the REST API and records
how many events matched — without re-parsing or re-running the raw SPL queries.

Usage:
    python check_saved_search_hits.py [--earliest -5m] [--latest now]
                                      [--output-dir outputs/verify/matched_events]
                                      [--max-events 100]
                                      <spl_file1> [spl_file2 ...]

Output per rule:
    <output-dir>/<detect_id>/hits.json      — { meta, event_count, events[], error, ... }

Aggregate:
    <output-dir>/aggregate_summary.json     — list of per-rule summaries (no raw events)

Exit code is always 0 — per-rule errors are captured inside the JSON files.
"""

import os
import sys
import json
import re
import time
import argparse
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import requests


def die(msg: str, code: int = 1) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)


def env_required(name: str) -> str:
    v = (os.getenv(name) or "").strip()
    if not v:
        die(f"Missing required env var: {name}")
    return v


def env_bool(name: str, default: bool = True) -> bool:
    v = (os.getenv(name) or "").strip().lower()
    if v in ("true", "1", "yes", "y", "on"):
        return True
    if v in ("false", "0", "no", "n", "off"):
        return False
    return default


def savedsearch_name_from_file(path: Path) -> str:
    """rules/splunk/foo.sigma.spl  →  foo.sigma  (matches deploy logic exactly)"""
    name = path.name
    if name.endswith(".spl"):
        name = name[:-4]
    return name


def extract_meta(path: Path) -> dict:
    """Read META_START…META_END block for labelling purposes only."""
    content = path.read_text(encoding="utf-8")
    m = re.search(r"META_START\s*(\{.*?\})\s*META_END", content, re.DOTALL)
    if not m:
        return {}
    try:
        return json.loads(m.group(1))
    except ValueError:
        return {}


def dispatch_saved_search(
    session: requests.Session,
    base_url: str,
    app: str,
    owner: str,
    search_name: str,
    earliest: str,
    latest: str,
    max_events: int = 100,
    poll_interval: float = 3.0,
    max_wait: float = 120.0,
) -> tuple[list[dict], str | None]:
    """
    Dispatch an already-deployed saved search over [earliest, latest] and return
    (events, error_msg).  Uses /saved/searches/{name}/dispatch — no SPL re-parsing needed.
    """
    dispatch_url = (
        f"{base_url}/servicesNS/{quote(owner, safe='')}/{quote(app, safe='')}"
        f"/saved/searches/{quote(search_name, safe='')}/dispatch?output_mode=json"
    )
    payload = {
        "dispatch.earliest_time": earliest,
        "dispatch.latest_time": latest,
        "dispatch.count": str(max_events),
    }

    try:
        r = session.post(dispatch_url, data=payload, timeout=30)
    except requests.RequestException as exc:
        return [], f"Network error dispatching saved search: {exc}"

    if r.status_code == 404:
        return [], f"Saved search not found in Splunk: '{search_name}'"
    if r.status_code not in (200, 201):
        return [], f"Dispatch failed HTTP {r.status_code}: {r.text[:300]}"

    try:
        sid = r.json().get("sid")
    except ValueError:
        return [], f"Non-JSON dispatch response: {r.text[:300]}"

    if not sid:
        return [], f"No SID in dispatch response: {r.text[:300]}"

    # Poll until done
    status_url = (
        f"{base_url}/servicesNS/{quote(owner, safe='')}/{quote(app, safe='')}"
        f"/search/jobs/{quote(str(sid), safe='')}?output_mode=json"
    )

    dispatch_state = ""
    elapsed = 0.0

    while elapsed < max_wait:
        time.sleep(poll_interval)
        elapsed += poll_interval

        try:
            r_status = session.get(status_url, timeout=30)
        except requests.RequestException:
            continue

        if r_status.status_code != 200:
            continue

        try:
            entry = (r_status.json().get("entry") or [{}])[0]
            dispatch_state = entry.get("content", {}).get("dispatchState", "")
        except (ValueError, IndexError):
            continue

        if dispatch_state in ("DONE", "FAILED", "FINALIZING"):
            break

    if dispatch_state == "FAILED":
        return [], f"Search job failed (SID={sid})"

    # Fetch results
    results_url = (
        f"{base_url}/servicesNS/{quote(owner, safe='')}/{quote(app, safe='')}"
        f"/search/jobs/{quote(str(sid), safe='')}/results"
        f"?output_mode=json&count={max_events}"
    )

    try:
        r_results = session.get(results_url, timeout=30)
    except requests.RequestException as exc:
        return [], f"Network error fetching results: {exc}"

    if r_results.status_code != 200:
        return [], f"Failed to fetch results HTTP {r_results.status_code}: {r_results.text[:300]}"

    try:
        events = r_results.json().get("results", [])
    except ValueError:
        return [], f"Non-JSON results response: {r_results.text[:300]}"

    return events, None


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Dispatch deployed Splunk saved searches and record matched events"
    )
    parser.add_argument("spl_files", nargs="+", help="SPL files (used to derive saved search names)")
    parser.add_argument("--earliest", default="-5m", help="Earliest time window (default: -5m)")
    parser.add_argument("--latest", default="now", help="Latest time window (default: now)")
    parser.add_argument(
        "--output-dir", default="outputs/verify/matched_events",
        help="Directory to write hits.json files per rule",
    )
    parser.add_argument("--max-events", type=int, default=100, help="Max events per rule (default: 100)")
    args = parser.parse_args(argv)

    base_url = env_required("SPLUNK_BASE_URL").rstrip("/")
    username = env_required("SPLUNK_USERNAME")
    password = env_required("SPLUNK_PASSWORD")
    app = env_required("SPLUNK_APP")
    owner = env_required("SPLUNK_OWNER")
    verify_tls = env_bool("SPLUNK_VERIFY_TLS", default=True)

    output_dir = Path(args.output_dir)

    session = requests.Session()
    session.verify = verify_tls
    session.auth = (username, password)
    session.headers.update({"Accept": "application/json"})

    run_ts = datetime.now(timezone.utc).isoformat()
    aggregate: list[dict] = []

    for spl_path_str in args.spl_files:
        path = Path(spl_path_str.strip())
        if not path.exists():
            print(f"ERROR: file not found: {path}", file=sys.stderr)
            aggregate.append({
                "detect_id": path.stem,
                "title": "",
                "search_name": "",
                "rule_version": "",
                "git_sha": "",
                "earliest": args.earliest,
                "latest": args.latest,
                "run_timestamp": run_ts,
                "event_count": 0,
                "error": "SPL file not found",
            })
            continue

        search_name = savedsearch_name_from_file(path)
        meta = extract_meta(path)
        detect_id = (meta.get("detect_id") or "").strip() or path.stem

        print(f"\n[{detect_id}] Dispatching '{search_name}' ({args.earliest} → {args.latest})")

        events, error = dispatch_saved_search(
            session=session,
            base_url=base_url,
            app=app,
            owner=owner,
            search_name=search_name,
            earliest=args.earliest,
            latest=args.latest,
            max_events=args.max_events,
        )

        if error:
            print(f"  ERROR: {error}", file=sys.stderr)
        else:
            print(f"  Matched events: {len(events)}")

        rule_out_dir = output_dir / detect_id
        rule_out_dir.mkdir(parents=True, exist_ok=True)

        hits = {
            "detect_id": detect_id,
            "title": meta.get("title", ""),
            "search_name": search_name,
            "rule_version": meta.get("rule_version", ""),
            "git_sha": meta.get("git_sha", ""),
            "earliest": args.earliest,
            "latest": args.latest,
            "run_timestamp": run_ts,
            "event_count": len(events),
            "error": error,
            "events": events,
        }

        (rule_out_dir / "hits.json").write_text(
            json.dumps(hits, indent=2, ensure_ascii=False), encoding="utf-8"
        )

        # Aggregate has no raw events (kept small for pass_fail_eval)
        aggregate.append({k: v for k, v in hits.items() if k != "events"})

    (output_dir / "aggregate_summary.json").write_text(
        json.dumps(aggregate, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    print(f"\nDone. Results written to: {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
