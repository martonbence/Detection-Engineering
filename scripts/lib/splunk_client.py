"""Splunk REST session construction shared by the Splunk-facing scripts.

Register item 3.6. Five scripts now build a `requests.Session` the exact same
way -- TLS verify flag, basic auth, an `Accept: application/json` header --
and the fifth copy (`check_spl_syntax.py`, item 4.2) landed *after* this item
was first written, which is the item's own point made concrete: each new
Splunk-facing script re-derives the same four lines because nothing central
existed yet to reuse instead.

What this deliberately does not add: retry/backoff, or anything else none of
the five scripts does today. Session construction is a pure function of three
inputs (credentials, TLS mode) with no state to share across calls, so a
function is enough -- a class would imply state this does not have. If a real
need for retry shows up later (a flaky Splunk endpoint, measured, not assumed)
that is a new register item, not a silent addition to this one.
"""

import requests


def build_session(username: str, password: str, verify_tls: bool) -> requests.Session:
    session = requests.Session()
    session.verify = verify_tls
    session.auth = (username, password)
    session.headers.update({"Accept": "application/json"})
    return session
