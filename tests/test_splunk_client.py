"""Session construction shared by the Splunk-facing scripts (register item 3.6).

Five scripts built a `requests.Session` with the exact same four lines --
verify flag, basic auth, an `Accept: application/json` header. The fifth
copy, in `check_spl_syntax.py`, landed after this item was first written
(item 4.2) -- proof the duplication was still actively growing, not just an
old debt. The identity test below checks five modules for that reason.
"""

import check_saved_search_hits
import check_spl_syntax
import deploy_spl_to_splunk as deploy
import reconcile
import wait_for_indexing
from lib.splunk_client import build_session


def test_every_consumer_now_shares_one_build_session():
    """A local copy reappearing is the regression this test is here to catch."""
    shared = build_session
    for module in (deploy, check_spl_syntax, check_saved_search_hits, wait_for_indexing, reconcile):
        assert module.build_session is shared, (
            f"{module.__name__} builds its own session again -- item 3.6 removed five copies of this"
        )


def test_session_carries_the_given_credentials_and_tls_mode():
    session = build_session("svc", "pw", False)
    assert session.auth == ("svc", "pw")
    assert session.verify is False


def test_session_verify_true_is_passed_through():
    session = build_session("svc", "pw", True)
    assert session.verify is True


def test_session_sends_a_json_accept_header():
    session = build_session("svc", "pw", True)
    assert session.headers["Accept"] == "application/json"
