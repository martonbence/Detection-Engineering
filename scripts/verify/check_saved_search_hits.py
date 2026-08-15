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

Exit code is always 0 — per-rule errors are captured inside the JSON files.
"""

import argparse
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.env import announce_tls_mode, env_bool, env_reader
from lib.meta_sidecar import read_meta_sidecar
from lib.rule_naming import saved_search_name
from lib.splunk_client import build_session
from lib.splunk_ns import namespace_url, saved_search_url


def die(msg: str, code: int = 1) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)


# Register item 3.6: the reading is shared, the exit policy stays here.
env_required = env_reader(die)






def extract_meta(path: Path) -> dict:
    """Read the sidecar <name>.meta.json generated alongside <name>.spl by sigma_to_spl.py.

    A missing or unparseable sidecar means this rule cannot be measured, not
    that setup failed -- unlike the deploy side, so this stays a soft `{}`
    rather than dying. See lib/meta_sidecar.py.
    """
    try:
        return read_meta_sidecar(path)
    except (OSError, ValueError):
        return {}


# Why an error needs a *kind* and not just a message: downstream, a failed
# measurement and a failed rule deserve opposite verdicts. If we could not
# measure -- the search never finished, the network dropped, Splunk answered
# with something unparseable -- then nothing is known about the detection, and
# calling that a FAIL invents a confirmed negative out of missing data. But if
# the saved search is not in Splunk at all, or the search job itself errored,
# that IS a real defect and hiding it behind a soft "unknown" would be the
# opposite mistake. pass_fail_eval.py maps these two to NOT_VERIFIED and FAIL
# respectively; the string stays human-facing, this field is the contract.
ERR_UNMEASURED = "unmeasured"   # we could not measure -> NOT_VERIFIED
ERR_RULE = "rule_error"         # the rule/deployment is wrong -> FAIL


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
) -> tuple[list[dict], str | None, str | None]:
    """
    Dispatch an already-deployed saved search over [earliest, latest] and return
    (events, error_msg, error_kind).  Uses /saved/searches/{name}/dispatch — no
    SPL re-parsing needed.  error_kind is one of ERR_UNMEASURED / ERR_RULE, and
    is None exactly when error_msg is None.

    Two namespaces are in play, and conflating them is a real bug rather than a
    style point (register item 3.9). The saved search is a configuration object
    and is addressed through `nobody`, the same namespace the deploy writes to,
    so the dispatch resolves the app-level object rather than any private layer
    over it. The job it returns is not a configuration object -- it belongs to
    whoever dispatched it -- so `owner`, the authenticating account, is what
    addresses the job endpoints below.
    """
    dispatch_url = (
        f"{saved_search_url(base_url, app, search_name)}/dispatch?output_mode=json"
    )
    payload = {
        "dispatch.earliest_time": earliest,
        "dispatch.latest_time": latest,
        "dispatch.count": str(max_events),
    }

    try:
        r = session.post(dispatch_url, data=payload, timeout=30)
    except requests.RequestException as exc:
        return [], f"Network error dispatching saved search: {exc}", ERR_UNMEASURED

    # A missing saved search is a deployment defect, not a measurement gap:
    # the rule is not in Splunk, so it cannot fire for anyone, and that should
    # read red rather than amber.
    if r.status_code == 404:
        return [], f"Saved search not found in Splunk: '{search_name}'", ERR_RULE
    if r.status_code >= 500:
        return [], f"Splunk error dispatching HTTP {r.status_code}: {r.text[:300]}", ERR_UNMEASURED
    if r.status_code not in (200, 201):
        return [], f"Dispatch failed HTTP {r.status_code}: {r.text[:300]}", ERR_RULE

    try:
        sid = r.json().get("sid")
    except ValueError:
        return [], f"Non-JSON dispatch response: {r.text[:300]}", ERR_UNMEASURED

    if not sid:
        return [], f"No SID in dispatch response: {r.text[:300]}", ERR_UNMEASURED

    # Poll until done
    status_url = (
        f"{namespace_url(base_url, owner, app)}"
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

        # FINALIZING deliberately does NOT end the loop. The job is still
        # assembling its result set in that state, so reading it here returns a
        # partial count -- which, being lower than the real one, can drop a
        # working rule under the pass threshold and report a failure that never
        # happened. DONE is the only state in which the numbers are final.
        if dispatch_state in ("DONE", "FAILED"):
            break

    if dispatch_state == "FAILED":
        # The search itself errored inside Splunk (malformed SPL, bad field
        # reference, missing index). That is a defect in the rule, so it stays
        # a FAIL.
        return [], f"Search job failed (SID={sid})", ERR_RULE

    if dispatch_state != "DONE":
        # The whole point of this branch: previously the code fell through here
        # and fetched results anyway, returning zero events with NO error --
        # indistinguishable from "the detection did not fire". A search that
        # never finished tells us nothing about the rule, so it is reported as
        # an explicit failure to measure and becomes NOT_VERIFIED downstream.
        state = dispatch_state or "no state reported"
        return (
            [],
            f"Search did not finish within {max_wait:.0f}s (SID={sid}, last state: {state})",
            ERR_UNMEASURED,
        )

    # Fetch results
    results_url = (
        f"{namespace_url(base_url, owner, app)}"
        f"/search/jobs/{quote(str(sid), safe='')}/results"
        f"?output_mode=json&count={max_events}"
    )

    try:
        r_results = session.get(results_url, timeout=30)
    except requests.RequestException as exc:
        return [], f"Network error fetching results: {exc}", ERR_UNMEASURED

    if r_results.status_code != 200:
        return (
            [],
            f"Failed to fetch results HTTP {r_results.status_code}: {r_results.text[:300]}",
            ERR_UNMEASURED,
        )

    try:
        events = r_results.json().get("results", [])
    except ValueError:
        return [], f"Non-JSON results response: {r_results.text[:300]}", ERR_UNMEASURED

    return events, None, None


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
    # The account that owns the dispatched *jobs*. Saved-search paths do not use
    # it -- those go through the `nobody` namespace via lib/splunk_ns.py.
    owner = username
    verify_tls = env_bool("SPLUNK_VERIFY_TLS", default=True)
    announce_tls_mode(verify_tls)

    output_dir = Path(args.output_dir)

    session = build_session(username, password, verify_tls)

    run_ts = datetime.now(UTC).isoformat()

    for spl_path_str in args.spl_files:
        path = Path(spl_path_str.strip())
        if not path.exists():
            print(f"ERROR: file not found: {path}", file=sys.stderr)
            rule_out_dir = output_dir / path.stem
            rule_out_dir.mkdir(parents=True, exist_ok=True)
            hits = {
                "detect_id": path.stem,
                "title": "",
                "search_name": "",
                "rule_version": "",
                "git_sha": "",
                "tester": "",
                "runner": "",
                "testing_enabled": False,
                "earliest": args.earliest,
                "latest": args.latest,
                "run_timestamp": run_ts,
                "event_count": 0,
                "error": "SPL file not found",
                # A missing SPL file is a repo/bundle defect, not a Splunk
                # outage -- there is nothing to measure because the rule is
                # not there, so it reads as a failure rather than an unknown.
                "error_kind": ERR_RULE,
                "events": [],
            }
            (rule_out_dir / "hits.json").write_text(
                json.dumps(hits, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            continue

        meta = extract_meta(path)
        search_name = saved_search_name(meta)
        detect_id = (meta.get("detect_id") or "").strip() or path.stem

        print(f"\n[{detect_id}] Dispatching '{search_name}' ({args.earliest} → {args.latest})")

        events, error, error_kind = dispatch_saved_search(
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
            # Carried over from the meta sidecar so downstream evaluation
            # (pass_fail_eval.py) can tell which rules were *supposed* to have
            # an Atomic Red Team run associated with them, and correlate that
            # against run_atomic.ps1's progress markers.
            "tester": meta.get("tester", ""),
            "runner": meta.get("runner", ""),
            "testing_enabled": bool(meta.get("testing enabled", False)),
            "earliest": args.earliest,
            "latest": args.latest,
            "run_timestamp": run_ts,
            "event_count": len(events),
            "error": error,
            # Machine-readable companion to "error": tells pass_fail_eval.py
            # whether this is a rule defect (FAIL) or a failure to measure
            # (NOT_VERIFIED). None whenever "error" is None.
            "error_kind": error_kind,
            "events": events,
        }

        (rule_out_dir / "hits.json").write_text(
            json.dumps(hits, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    print(f"\nDone. Results written to: {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
