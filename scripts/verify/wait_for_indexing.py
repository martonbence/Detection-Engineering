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

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import requests

DEFAULT_TIMEOUT = 180
DEFAULT_INTERVAL = 10


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.env import announce_tls_mode, env_bool, env_reader


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
    p.add_argument("spl_files", nargs="*", help=".spl files whose meta sidecars name the indexes to watch")
    return p.parse_args(argv)


def indexes_from_meta(spl_files: list[str]) -> list[str]:
    """The indexes the rules under test actually write to, from their sidecars.

    Watching only these keeps the probe honest: a quiet index nobody in this
    batch uses should not be able to satisfy the wait.
    """
    found: list[str] = []
    for spl in spl_files:
        meta_path = Path(spl).parent / (Path(spl).stem + ".meta.json")
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        index = str((meta or {}).get("index") or "").strip()
        if index and index not in found:
            found.append(index)
    return found


def build_probe_search(indexes: list[str], since: str) -> str:
    """One event is proof enough that the indexer has reached `since`."""
    scope = " OR ".join(f"index={i}" for i in indexes) if indexes else "index=*"
    return f"search ({scope}) earliest={since} latest=now | head 1 | stats count as c"


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
    search = build_probe_search(indexes, str(args.since))

    print(f"Waiting for Splunk to index events at or after epoch {args.since}.")
    print(f"Indexes under test: {', '.join(indexes) if indexes else '(none resolved -- probing all)'}")
    print(f"Giving it up to {args.timeout}s, checking every {args.interval}s.")

    session = requests.Session()
    session.verify = verify_tls
    session.auth = (username, password)
    session.headers.update({"Accept": "application/json"})

    from urllib.parse import quote

    url = f"{base_url}/servicesNS/{quote(username, safe='')}/{quote(app, safe='')}/search/jobs"

    started = time.monotonic()
    attempts = 0

    while True:
        attempts += 1
        elapsed = time.monotonic() - started

        if probe(session, url, search) > 0:
            print(f"Indexer has caught up after {elapsed:.0f}s ({attempts} check(s)).")
            return 0

        if elapsed + args.interval >= args.timeout:
            # Not a failure: the verification below will report what it finds,
            # and a rule with no events becomes NOT_VERIFIED rather than a FAIL.
            print(
                f"::warning title=Splunk indexing not confirmed::No events at or after the test window "
                f"start appeared within {args.timeout}s. Continuing anyway -- if rules come back with zero "
                f"hits, a slow indexer is the first thing to rule out."
            )
            return 0

        print(f"  not yet ({elapsed:.0f}s elapsed), waiting {args.interval}s...")
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
