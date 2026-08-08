"""Which namespace each Splunk call goes through (register item 3.9).

The pipeline used to address every saved search as the service account, through
`servicesNS/<account>/<app>`. Splunk accepts that and then stores each update as
a private stanza layered over the app-level object, so every rule appeared twice
in the UI: the live scheduled alert, plus a private unscheduled copy that did
nothing and came back however often it was deleted by hand.

Measured on 2026-08-08 against the dev app -- one throwaway object per arm,
listed through the wildcard owner after every step:

    servicesNS/<account>/<app>   create -> 1 copy; update -> 2 copies
    servicesNS/nobody/<app>      create -> 1 copy, already sharing=app;
                                 update -> 1 copy; update again -> 1 copy

so the fix is a URL, and a URL is exactly the kind of thing a later refactor
tidies away without knowing what it cost to find. Hence this file. Each test
below pins one half of a distinction that is invisible in the code:

  * `nobody` in the *path*, because the path decides which configuration layer
    a write lands in;
  * the authenticating account in the ACL *payload*, because naming `nobody`
    there is read as an ownership change and refused with 403 -- the very
    refusal that made an earlier attempt abandon this approach;
  * the account for `search/jobs`, because a job is not a configuration object
    and does not live in the app-level namespace at all;
  * the wildcard owner for listings, because no single-owner view can see both
    layers, and the reconcile's duplicate reporting depends on seeing both.
"""

import check_saved_search_hits
import deploy_spl_to_splunk as deploy
import pytest
import wait_for_indexing
from test_deploy_report import FakeResponse, FakeSession, write_rule


@pytest.fixture
def splunk(monkeypatch):
    """The deploy's usual harness: a faked session plus the env it reads."""

    def _make(responses=None):
        session = FakeSession(responses)
        monkeypatch.setattr(deploy.requests, "Session", lambda: session)
        return session

    for key, value in {
        "SPLUNK_BASE_URL": "https://splunk.example:8089",
        "SPLUNK_USERNAME": "svc",
        "SPLUNK_PASSWORD": "pw",
        "SPLUNK_APP": "detection_app",
        "SPLUNK_VERIFY_TLS": "false",
    }.items():
        monkeypatch.setenv(key, value)
    return _make


# --- the deploy --------------------------------------------------------------


def test_updates_are_addressed_through_the_nobody_namespace(tmp_path, splunk):
    """An update on the account's own path is what deposits the shadow."""
    session = splunk()

    assert deploy.main([str(write_rule(tmp_path))]) == 0

    update = next(p for p in session.posts if p["kind"] == "update")
    assert "/servicesNS/nobody/detection_app/saved/searches/" in update["url"]
    assert "/servicesNS/svc/" not in update["url"]


def test_creates_are_addressed_through_the_nobody_namespace(tmp_path, splunk):
    """Creating app-level is what leaves later updates nothing to shadow."""
    session = splunk({"update": FakeResponse(404), "create": FakeResponse(201)})

    assert deploy.main([str(write_rule(tmp_path))]) == 0

    create = next(p for p in session.posts if p["kind"] == "create")
    assert "/servicesNS/nobody/detection_app/saved/searches" in create["url"]
    assert "/servicesNS/svc/" not in create["url"]


def test_the_acl_call_names_the_authenticating_account_not_nobody(tmp_path, splunk):
    """`owner: nobody` here is an ownership change, and Splunk answers 403.

    Measured all three ways on 2026-08-08: no owner field -> 403, owner=nobody
    -> 403, owner=<account> -> 200 with the permissions actually applied. The
    path and the payload disagree on purpose, and this is the assertion that
    says so.
    """
    session = splunk()

    assert deploy.main([str(write_rule(tmp_path))]) == 0

    acl = next(p for p in session.posts if p["kind"] == "acl")
    assert "/servicesNS/nobody/detection_app/saved/searches/" in acl["url"]
    assert acl["data"]["owner"] == "svc"
    assert acl["data"]["owner"] != "nobody"


def test_permissions_are_still_enforced_under_the_new_namespace(tmp_path, splunk):
    """Objects born app-level inherit default.meta's perms, not the configured ones.

    Dropping the ACL call would have been the simpler fix and would have
    silently widened write access to whatever the app hands out (measured:
    admin, ci_deploy_savedsearches, power -- against a configured `admin`).
    """
    session = splunk()

    assert deploy.main([str(write_rule(tmp_path))]) == 0

    acl = next(p for p in session.posts if p["kind"] == "acl")
    assert acl["data"]["sharing"] == "app"
    assert acl["data"]["perms.write"] == "admin"


# --- the verify step ---------------------------------------------------------


class _Reply:
    def __init__(self, payload, status_code=200):
        self.status_code = status_code
        self.text = ""
        self._payload = payload

    def json(self):
        return self._payload


class _RecordingSession:
    """Records URLs and answers a dispatch-then-poll-then-results sequence."""

    def __init__(self):
        self.urls = []

    def post(self, url, **_kwargs):
        self.urls.append(url)
        return _Reply({"sid": "SID-1"}, status_code=201)

    def get(self, url, **_kwargs):
        self.urls.append(url)
        if "/results" in url:
            return _Reply({"results": []})
        return _Reply({"entry": [{"content": {"dispatchState": "DONE"}}]})


def test_dispatch_uses_the_object_namespace_and_jobs_use_the_account():
    """One call, two namespaces -- and conflating them is a bug, not untidiness.

    The saved search is configuration and lives app-level; the job the dispatch
    returns belongs to whoever dispatched it. Routing the job endpoints through
    `nobody` would address a namespace the job is not in.
    """
    session = _RecordingSession()

    check_saved_search_hits.dispatch_saved_search(
        session=session,
        base_url="https://splunk.example:8089",
        app="detection_app",
        owner="svc",
        search_name="DETECT-2026-0001_Alpha",
        earliest="1700000000",
        latest="now",
        poll_interval=0.001,
        max_wait=0.02,
    )

    dispatch_url = next(u for u in session.urls if "/dispatch" in u)
    assert "/servicesNS/nobody/detection_app/saved/searches/" in dispatch_url

    job_urls = [u for u in session.urls if "/search/jobs/" in u]
    assert job_urls, "expected the job to be polled and read"
    assert all("/servicesNS/svc/detection_app/search/jobs/" in u for u in job_urls)


def test_the_indexing_wait_keeps_the_account_namespace(monkeypatch):
    """wait_for_indexing only ever touches search/jobs, so it does not move.

    Recorded as a test rather than left implicit: it is the obvious file to
    "fix too" when the other three change, and doing so would be wrong.
    """
    captured = {}

    class _Session:
        def __init__(self):
            self.headers: dict = {}
            self.verify = True
            self.auth = None

        def post(self, url, data=None, timeout=None):
            captured["url"] = url
            # A non-zero count ends the wait on the first probe.
            return _Reply({"results": [{"c": "1"}]})

    for key, value in {
        "SPLUNK_BASE_URL": "https://splunk.example:8089",
        "SPLUNK_USERNAME": "svc",
        "SPLUNK_PASSWORD": "pw",
        "SPLUNK_APP": "detection_app",
        "SPLUNK_VERIFY_TLS": "false",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(wait_for_indexing.requests, "Session", lambda: _Session())

    wait_for_indexing.main(["--since", "1700000000", "--timeout", "1", "--interval", "1"])

    assert "/servicesNS/svc/detection_app/search/jobs" in captured["url"]
