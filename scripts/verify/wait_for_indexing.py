# scripts/verify/wait_for_indexing.py
#
# Register item 2.3. The verify job used to `sleep 60` before querying Splunk,
# via SPLUNK_VERIFY_WAIT_SECONDS -- a variable nothing ever set, so the value
# was always exactly 60 and the name only suggested it was tunable.
#
# A fixed sleep is wrong in both directions. It costs a full minute on every run
# even when the indexer was ready in eight seconds, and it silently gives up
# after sixty when the indexer needs ninety -- producing zero hits and a verdict
# that says the detection failed when what actually happened is that nobody
# waited long enough.
#
# So ask instead of guessing. The question is not "did the attack land?" -- that
# is what the verification itself measures, and asking it here would make a rule
# that legitimately matches nothing wait for the full timeout. The question is
# "has the indexer caught up to the test window?", which any event in the
# relevant indexes answers.
#
# Advisory by design: on timeout it warns and returns 0. Blocking here would
# convert a slow indexer into a pipeline failure, when the honest outcome is to
# go on and let the verification report what it finds.
#
# DETECT-2026-0002 exposed a hole in "any event in the relevant indexes"
# (2026-09-12): every rule before it targeted a Sysmon-dedicated index with
# little background noise, so "any event landed" was a fine proxy for "our
# event landed." That rule is the first against `wineventlog`, a shared,
# high-volume native-log index -- the probe was satisfied by unrelated
# Windows Security noise within one or two checks, long before the atomic
# test's own 4625/4771/4776 events had actually finished indexing, and
# check_saved_search_hits.py then queried too early and reported a FAIL for
# events that showed up moments later (confirmed live: re-running the
# identical search minutes after a FAIL run returned the expected 10-event
# match). So each rule now gets its own probe, narrowed to its actual
# selection filter (see `leading_filter_clause`) rather than a blanket
# `index=X` -- "caught up" means "this rule's own matching events exist,"
# not "the index received any traffic at all." A rule whose .spl opens with
# a true generating command (`| tstats`, `| inputlookup`, ...) has no
# extractable filter clause -- sigma_to_spl.py's `_inject_index_prefix()`
# treats those the same way -- so those still fall back to the old
# index-level probe.

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

import requests

DEFAULT_TIMEOUT = 180
DEFAULT_INTERVAL = 10


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.env import announce_tls_mode, env_bool, env_reader
from lib.meta_sidecar import read_meta_sidecar
from lib.splunk_client import build_session
from lib.splunk_ns import namespace_url


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


# Register item 3.6: the reading is shared, the exit policy stays here. Exit 2
# rather than the deploy's 1 is deliberate and predates this change -- a wait
# step that never got to start is a setup failure, not a verification result.
def _fail(msg: str) -> None:
    eprint(f"ERROR: {msg}")
    raise SystemExit(2)


env_required = env_reader(_fail)






def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Wait until Splunk has indexed events from the test window.")
    p.add_argument("--since", required=True, help="Epoch seconds: the start of the test phase")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"Seconds (default {DEFAULT_TIMEOUT})")
    p.add_argument("--interval", type=int, default=DEFAULT_INTERVAL, help=f"Seconds (default {DEFAULT_INTERVAL})")
    p.add_argument(
        "spl_files",
        nargs="*",
        help=".spl files to probe -- each rule's own leading filter clause is used where one can be "
        "extracted, falling back to its meta sidecar's index otherwise",
    )
    return p.parse_args(argv)


def indexes_from_meta(spl_files: list[str]) -> list[str]:
    """The indexes the rules under test actually write to, from their sidecars.

    Watching only these keeps the probe honest: a quiet index nobody in this
    batch uses should not be able to satisfy the wait.
    """
    found: list[str] = []
    for spl in spl_files:
        try:
            meta = read_meta_sidecar(Path(spl))
        except (OSError, json.JSONDecodeError):
            continue
        index = str((meta or {}).get("index") or "").strip()
        if index and index not in found:
            found.append(index)
    return found


def build_probe_search(indexes: list[str], since: str) -> str:
    """One event *anywhere in the index* is proof the indexer has reached
    `since`. Kept as the fallback for rules a filter clause can't be
    extracted from (see `leading_filter_clause`), and for the no-files case.
    """
    scope = " OR ".join(f"index={i}" for i in indexes) if indexes else "index=*"
    return f"search ({scope}) earliest={since} latest=now | head 1 | stats count as c"


# Mirrors sigma_to_spl.py's `_GENERATING_COMMANDS` (scripts/convert/sigma_to_spl.py).
# Duplicated rather than imported: importing that module pulls in the full
# conversion toolchain (pySigma, backend_config.yml) just for one constant.
# Keep in sync if that list changes.
_GENERATING_COMMANDS = {
    "tstats",
    "mstats",
    "datamodel",
    "pivot",
    "metadata",
    "inputlookup",
    "inputcsv",
    "dbxquery",
    "rest",
    "from",
    "mcatalog",
    "savedsearch",
    "loadjob",
    "makeresults",
    "multisearch",
    "union",
    "gentimes",
}


def _opens_with_generating_command(text: str) -> bool:
    match = re.match(r"\s*\|\s*([A-Za-z][A-Za-z0-9_]*)", text)
    return bool(match) and match.group(1).lower() in _GENERATING_COMMANDS


def _before_first_top_level_pipe(text: str) -> str:
    """Everything up to the first `|` that isn't inside a quoted string.

    A naive `text.split("|", 1)` would cut a query short at a `|` that's part
    of a quoted literal (e.g. a regex alternation inside a `rex` pattern).
    """
    in_dquote = False
    in_squote = False
    for i, ch in enumerate(text):
        if ch == '"' and not in_squote:
            in_dquote = not in_dquote
        elif ch == "'" and not in_dquote:
            in_squote = not in_squote
        elif ch == "|" and not in_dquote and not in_squote:
            return text[:i]
    return text


def leading_filter_clause(spl_text: str) -> str | None:
    """The rule's own selection/filter clause, or None if there isn't one to
    extract.

    For both `custom.splunk.raw_query` rules and normal pySigma output, the
    search text before the first transforming/aggregating pipe (`| eval`,
    `| stats`, `| bin`, `| streamstats`, etc.) IS the real filter -- it's not
    something that needs re-deriving from the Sigma source, and
    sigma_to_spl.py's `enforce_index_prefix()` already puts the index at the
    front of exactly this leading portion.

    Returns None for a .spl that opens with a true generating command
    (`| tstats`, `| inputlookup`, ...): those produce their own result set
    from scratch rather than filtering raw events, so there is no leading
    filter clause to extract. Callers should fall back to an index-level
    probe for these.
    """
    text = (spl_text or "").strip()
    if not text or _opens_with_generating_command(text):
        return None

    clause = _before_first_top_level_pipe(text).strip()
    return clause or None


def build_probes(spl_files: list[str], since: str) -> list[tuple[str, str]]:
    """One (label, search) probe per rule under test.

    Narrowed to each rule's own filter clause where one can be extracted, so
    "caught up" means that rule's own matching events exist -- not that its
    index received any traffic at all (see the module docstring). Falls back
    to the old index-level probe for rules a filter clause can't be pulled
    from (a true generating-command opener, or a .spl that couldn't be
    read). With no files at all -- the legacy call shape -- falls back to a
    single all-indexes probe exactly as before.
    """
    if not spl_files:
        return [("(no rule files given)", build_probe_search([], since))]

    probes: list[tuple[str, str]] = []
    for spl in spl_files:
        path = Path(spl)
        label = path.stem

        try:
            meta = read_meta_sidecar(path) or {}
        except (OSError, json.JSONDecodeError):
            meta = {}
        index = str(meta.get("index") or "").strip()

        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            text = ""

        clause = leading_filter_clause(text)
        if clause:
            search = f"search ({clause}) earliest={since} latest=now | head 1 | stats count as c"
        else:
            search = build_probe_search([index] if index else [], since)

        probes.append((label, search))
    return probes


def parse_count(payload: object) -> int:
    """Read `c` out of a oneshot search's JSON, treating anything odd as zero."""
    if not isinstance(payload, dict):
        return 0
    results = payload.get("results")
    if not isinstance(results, list) or not results:
        return 0
    first = results[0]
    if not isinstance(first, dict):
        return 0
    try:
        return int(str(first.get("c", "0")).strip() or 0)
    except ValueError:
        return 0


def probe(session: requests.Session, url: str, search: str) -> int:
    """Returns the event count, or 0 when the probe itself could not run.

    A failed probe is deliberately indistinguishable from "not yet indexed":
    both mean "keep waiting", and neither is worth failing the pipeline over.
    """
    try:
        response = session.post(
            url,
            data={"search": search, "exec_mode": "oneshot", "output_mode": "json"},
            timeout=30,
        )
    except requests.RequestException as ex:
        eprint(f"  probe failed ({ex}) -- treating as not ready")
        return 0

    if response.status_code != 200:
        eprint(f"  probe returned HTTP {response.status_code} -- treating as not ready")
        return 0

    try:
        return parse_count(response.json())
    except ValueError:
        eprint("  probe returned a non-JSON body -- treating as not ready")
        return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    base_url = env_required("SPLUNK_BASE_URL").rstrip("/")
    username = env_required("SPLUNK_USERNAME")
    password = env_required("SPLUNK_PASSWORD")
    app = env_required("SPLUNK_APP")
    verify_tls = env_bool("SPLUNK_VERIFY_TLS", default=True)
    announce_tls_mode(verify_tls)

    indexes = indexes_from_meta(args.spl_files)
    probes = build_probes(args.spl_files, str(args.since))

    print(f"Waiting for Splunk to index events at or after epoch {args.since}.")
    print(f"Indexes under test: {', '.join(indexes) if indexes else '(none resolved -- probing all)'}")
    print(f"Probing {len(probes)} rule(s) individually: {', '.join(label for label, _ in probes)}")
    print(f"Giving it up to {args.timeout}s, checking every {args.interval}s.")

    session = build_session(username, password, verify_tls)

    # search/jobs identifies a running job, owned by whoever dispatched it --
    # not a configuration object, so this stays on the account namespace and
    # never routes through lib/splunk_ns.py's `nobody` (see that module's
    # docstring, register item 3.9).
    url = f"{namespace_url(base_url, username, app)}/search/jobs"

    started = time.monotonic()
    attempts = 0
    satisfied: set[str] = set()

    while True:
        attempts += 1
        elapsed = time.monotonic() - started

        for label, search in probes:
            if label in satisfied:
                continue
            if probe(session, url, search) > 0:
                satisfied.add(label)
                print(f"  {label}: caught up after {elapsed:.0f}s.")

        if len(satisfied) == len(probes):
            print(f"Indexer has caught up on all {len(probes)} rule(s) after {elapsed:.0f}s ({attempts} check(s)).")
            return 0

        if elapsed + args.interval >= args.timeout:
            # Not a failure: the verification below will report what it finds,
            # and a rule with no events becomes NOT_VERIFIED rather than a FAIL.
            pending = [label for label, _ in probes if label not in satisfied]
            print(
                f"::warning title=Splunk indexing not confirmed::No events at or after the test window "
                f"start appeared within {args.timeout}s for: {', '.join(pending)}. Continuing anyway -- if "
                f"these rules come back with zero hits, a slow indexer is the first thing to rule out."
            )
            return 0

        print(f"  not yet ({elapsed:.0f}s elapsed), waiting {args.interval}s...")
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
