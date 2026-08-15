# scripts/deploy/check_spl_syntax.py
#
# Register item 4.2. deploy_spl_to_splunk.py POSTs a rule's query straight
# into a saved search: Splunk's saved/searches create/update endpoint does
# not parse the search string at save time, so a syntax error in it becomes
# a live saved search that has never actually been checked -- the error only
# surfaces later, when the search runs (its cron fires, or the attack+verify
# pipeline dispatches it), and only for a rule whose testing is enabled and
# that gets exercised in that run. custom.splunk.raw_query rules are the
# sharpest case: they bypass the Sigma-to-SPL converter entirely, so nothing
# in the pipeline has ever looked at their query text before this.
#
# services/search/v2/parser parses a query and returns a semantic map
# without dispatching a search job -- no data is scanned, nothing is
# created. `parse_only=true` additionally skips subsearch/lookup/eventtype/
# macro expansion, so this checks SYNTAX only, deliberately: those
# expansions depend on objects that may not exist in every environment this
# runs against, and failing on that would be a false positive for a
# question this check does not ask.
#
# (The older, unversioned services/search/parser endpoint -- what this
# register item's own text originally named -- is deprecated as of Splunk
# Enterprise 9.0.1; v2 is what Splunk's current REST API reference points
# at, confirmed via Context7 before writing this rather than assumed.)
#
# Same scope as deploy_spl_to_splunk.py, which this runs immediately before
# in ci_dev_workflow.yml: the files being deployed THIS run, not every rule
# in the repo. Unlike the local, network-free validators (check_mitre_tags.py,
# check_detect_id_uniqueness.py) that check everything every time for free,
# this one costs a real Splunk API call per rule, and the deploy step it
# gates already scopes its own work the same way.
#
# Exit codes:
# 0 = every query parsed
# 1 = a query failed to parse
# 2 = checker setup failure (env, auth, or Splunk unreachable -- not a
#     property of any one rule's query)

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.env import announce_tls_mode, env_bool, env_reader
from lib.splunk_client import build_session
from lib.summary import MARK_FAIL, MARK_PASS, escape_cell


def die(msg: str, code: int = 2) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)


# Register item 3.6: the reading is shared via lib.env, the exit policy
# (setup failure here is always 2, never 1 -- 1 means "a query was rejected")
# stays with this script.
env_required = env_reader(lambda msg: die(msg, 2))


def read_spl_query(path: Path) -> str:
    query = path.read_text(encoding="utf-8").strip()
    if not query:
        die(f"No SPL query found in file: {path}")
    return query


# 2026-08-15 live-bug follow-up to item 4.2 (closed 2026-08-11 on mocks only --
# LAB_ONLINE had been false for weeks, so this was the first time this script
# ever ran against a real Splunk). Workflow run 31896204938 ("Deploy to
# Splunk") failed every single rule with the identical
# "Unknown search command 'index'." before a single one deployed.
#
# The .spl files this repo commits are bare, e.g.
#   index=sysmon Image="*\\tasklist.exe" | table ...
# with no leading `search`. That is valid input to Splunk's search bar and to
# the `saved/searches` create/update endpoint that deploy_spl_to_splunk.py
# actually uses (both auto-prepend `search` for a query that does not already
# open with `|` or an explicit generating command) -- but `search/v2/parser`
# does not do that auto-prepending. It parses the literal string as a
# complete pipeline and expects the first token to be a command name, so a
# bare `index=...` query makes it treat `index` itself as an unrecognized
# command. deploy_spl_to_splunk.py was never broken; this checker was sending
# it something Splunk would never actually be asked to run as-is.
#
# `sigma_to_spl.py::_inject_index_prefix()` is the reason every committed
# .spl looks like this: it deliberately writes the SIGMA-defined index as a
# BARE `index=<idx> ...` prefix (or leaves a `search ...` opener alone,
# rewriting only the index inside it), never adding `search` itself -- that
# was never its job, since the two consumers that read these files after
# conversion (`saved/searches`, and a human pasting into the search bar) both
# already add it implicitly. `search/v2/parser` is a third consumer with a
# different contract, so the prepending has to happen here instead.
_LEADING_PIPE_RE = re.compile(r"^\|")
_LEADING_SEARCH_RE = re.compile(r"(?i)^search\s")


def ensure_search_prefix(query: str) -> str:
    """Make `query` what `search/v2/parser` actually needs to see.

    Conservative, not the fully general "every Splunk generating command"
    rule: this repo's converter only ever emits two openers (confirmed by
    inspecting all 28 current .spl files under rules/splunk/) --

      - `search ...`      (DETECT-2026-0007, the one `|re:`-backed rule,
                            whose query needs an initial `search` term before
                            its own `| rex | ... | search ...` chain)
      - `index=... ...`   (every other rule; the bare form
                            `_inject_index_prefix()` writes by default)

    A leading `|` is also left alone rather than getting `search` prepended:
    Splunk's true generating commands (`| tstats`, `| inputlookup`, ...) are
    complete pipelines on their own and `search | tstats ...` is not valid
    SPL. `_inject_index_prefix()` already guarantees that any leading `|`
    left in a committed .spl belongs to one of those -- a non-generating
    `| rex ...`-style opener gets `search index=<idx>` written in front of it
    at conversion time, so it no longer starts with `|` by the time it
    reaches this checker. If a future query shape breaks that invariant,
    Splunk's parser response is exactly what surfaced this bug in the first
    place: a loud, specific "Unknown search command" error, not a silent
    false negative.
    """
    q = (query or "").strip()
    if not q:
        return q
    if _LEADING_PIPE_RE.match(q) or _LEADING_SEARCH_RE.match(q):
        return q
    return f"search {q}"


def parse_error_detail(response: requests.Response) -> str:
    """A human-readable reason the parser rejected the query."""
    try:
        payload = response.json()
    except ValueError:
        return (response.text or "").strip()[:500] or f"HTTP {response.status_code}, no body"

    messages = payload.get("messages")
    if isinstance(messages, list) and messages:
        texts = [str(m.get("text", m)) if isinstance(m, dict) else str(m) for m in messages]
        return "; ".join(texts)
    return (response.text or "").strip()[:500] or f"HTTP {response.status_code}"


def check_query(session: requests.Session, base_url: str, query: str) -> tuple[bool, str]:
    """(parsed_ok, detail). Auth/permission failures die() rather than being
    attributed to the query -- the same credentials are about to be used for
    the actual deploy, so a 401/403 here means every remaining rule would
    fail identically, not that this one rule's SPL is bad."""
    url = f"{base_url}/services/search/v2/parser"
    r = session.post(
        url,
        data={
            "q": ensure_search_prefix(query),
            "output_mode": "json",
            "parse_only": "true",
            "reload_macros": "false",
        },
        timeout=30,
    )
    if r.status_code == 200:
        return True, ""
    if r.status_code in (401, 403):
        die(f"Splunk auth/permission error (HTTP {r.status_code}) checking SPL syntax: {r.text[:500]}")
    return False, parse_error_detail(r)


def write_step_summary(results: list[dict]) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    failed = [r for r in results if not r["ok"]]
    lines = [
        "## SPL syntax check (`services/search/v2/parser`)",
        "",
        f"{len(results) - len(failed)}/{len(results)} parsed cleanly.",
    ]
    if failed:
        lines += ["", "| File | Detail |", "|---|---|"]
        for r in failed:
            lines.append(f"| `{escape_cell(r['file'])}` | {escape_cell(r['detail'])} |")
    lines.append("")
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError as ex:
        print(f"WARNING: could not write the step summary: {ex}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Parse each .spl file's query against Splunk's search/v2/parser before it is deployed."
    )
    p.add_argument("files", nargs="*", help="The .spl files to check")
    args = p.parse_args(argv)

    if not args.files:
        print("No input files.")
        return 0

    base_url = env_required("SPLUNK_BASE_URL").rstrip("/")
    username = env_required("SPLUNK_USERNAME")
    password = env_required("SPLUNK_PASSWORD")
    verify_tls = env_bool("SPLUNK_VERIFY_TLS", default=True)
    announce_tls_mode(verify_tls)

    session = build_session(username, password, verify_tls)

    results: list[dict] = []
    failed = 0

    for f in (Path(a) for a in args.files):
        if not f.exists():
            print(f"ERROR: file not found: {f}", file=sys.stderr)
            results.append({"file": str(f), "ok": False, "detail": "file not found"})
            failed += 1
            continue

        query = read_spl_query(f)

        try:
            ok, detail = check_query(session, base_url, query)
        except requests.RequestException as ex:
            die(f"Could not reach Splunk to check {f}: {ex}")

        results.append({"file": str(f), "ok": ok, "detail": detail})
        if ok:
            print(f"{MARK_PASS} {f}")
        else:
            print(f"{MARK_FAIL} {f}: {detail}")
            print(f"::error file={f},title=SPL syntax error::{detail}")
            failed += 1

    print("")
    print(f"Checked: {len(results)}  Parsed: {len(results) - failed}  Failed: {failed}")
    write_step_summary(results)

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
