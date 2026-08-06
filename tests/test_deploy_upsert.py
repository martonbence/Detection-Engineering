"""Deciding create-vs-update by status code, not by error prose (item 2.6).

The deploy used to POST to the collection endpoint and then read Splunk's error
*text* to work out whether the object already existed -- matching "already
exists", "conflict" and "in use". None of those are promised by Splunk, all vary
by version, and any unrelated failure could contain one.

It now addresses the object endpoint, where 200 means "was there, now updated"
and 404 means "not there yet". These tests are mostly about what must *not*
happen: no inference from prose, and no guessing past an unexpected response.
"""

import json

import deploy_spl_to_splunk as deploy
import pytest
from test_deploy_report import FakeResponse, FakeSession, write_rule


@pytest.fixture
def splunk(monkeypatch):
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


# --- the happy paths ---------------------------------------------------------


def test_an_existing_rule_never_touches_the_collection_endpoint(tmp_path, splunk):
    """The common case is one call, where it used to be a create plus a retry."""
    session = splunk()

    assert deploy.main([str(write_rule(tmp_path))]) == 0

    assert "create" not in session.kinds()
    assert session.kinds() == ["update", "acl"]


def test_a_missing_rule_is_created(tmp_path, splunk):
    session = splunk({"update": FakeResponse(404), "create": FakeResponse(201)})

    assert deploy.main([str(write_rule(tmp_path))]) == 0

    # update (404) -> create -> reapply scheduling fields -> acl
    assert session.kinds() == ["update", "create", "update", "acl"]


def test_the_scheduling_reapply_goes_to_the_object_endpoint(tmp_path, splunk):
    """Splunk does not reliably persist is_scheduled/cron on the create POST."""
    session = splunk({"update": FakeResponse(404), "create": FakeResponse(201)})

    deploy.main([str(write_rule(tmp_path))])

    reapply = session.posts[2]
    assert reapply["kind"] == "update"
    assert reapply["data"]["is_scheduled"] == "1"


def test_the_update_payload_carries_no_name(tmp_path, splunk):
    """The object endpoint addresses by URL; a name in the body is a create-ism."""
    session = splunk()

    deploy.main([str(write_rule(tmp_path))])

    assert "name" not in session.posts[0]["data"]
    assert session.posts[0]["data"]["search"]


def test_the_create_payload_still_carries_the_name(tmp_path, splunk):
    session = splunk({"update": FakeResponse(404), "create": FakeResponse(201)})

    deploy.main([str(write_rule(tmp_path))])

    create = next(p for p in session.posts if p["kind"] == "create")
    assert create["data"]["name"] == "DETECT-2026-0001_Alpha"


# --- what must not be inferred from prose ------------------------------------


def test_an_error_saying_already_exists_no_longer_steers_anything(tmp_path, splunk):
    """Exactly the string the old code keyed on, on a status that is not 404."""
    session = splunk({"update": FakeResponse(500, "savedsearch already exists")})

    assert deploy.main([str(write_rule(tmp_path))]) == 2

    assert "create" not in session.kinds()


@pytest.mark.parametrize("text", ["already exists", "conflict detected", "name in use"])
def test_none_of_the_old_magic_phrases_change_the_outcome(tmp_path, splunk, text):
    session = splunk({"update": FakeResponse(503, text)})

    assert deploy.main([str(write_rule(tmp_path))]) == 2
    assert "create" not in session.kinds()


def test_a_404_whose_body_says_nothing_useful_still_creates(tmp_path, splunk):
    """The status is the contract; the body is not consulted at all."""
    session = splunk({"update": FakeResponse(404, ""), "create": FakeResponse(201)})

    assert deploy.main([str(write_rule(tmp_path))]) == 0
    assert "create" in session.kinds()


# --- not guessing past an unexpected response --------------------------------


def test_an_unexpected_update_status_fails_instead_of_trying_create(tmp_path, splunk):
    """Falling through to create is what the old error-text matching did."""
    session = splunk({"update": FakeResponse(500, "boom")})

    assert deploy.main([str(write_rule(tmp_path))]) == 2

    assert session.kinds() == ["update"]


def test_the_unexpected_status_is_reported_with_what_was_expected(tmp_path, splunk, capsys):
    splunk({"update": FakeResponse(418, "teapot")})

    deploy.main([str(write_rule(tmp_path))])

    err = capsys.readouterr().err
    assert "418" in err
    assert "expected 200" in err and "404" in err


def test_an_auth_error_on_update_fails_fast(tmp_path, splunk):
    """No create attempt: the credentials are wrong, not the object missing."""
    session = splunk({"update": FakeResponse(403, "forbidden")})

    assert deploy.main([str(write_rule(tmp_path))]) == 2

    assert session.kinds() == ["update"]


def test_an_auth_error_on_create_is_reported_as_such(tmp_path, splunk):
    splunk({"update": FakeResponse(404), "create": FakeResponse(401, "nope")})
    report = tmp_path / "deploy.json"

    assert deploy.main(["--report", str(report), str(write_rule(tmp_path))]) == 2

    entry = json.loads(report.read_text(encoding="utf-8"))["rules"][0]
    assert "auth/permission" in entry["detail"]


def test_a_409_on_create_is_a_failure_not_a_silent_retry(tmp_path, splunk):
    """Something created it between our 404 and our create -- say so."""
    session = splunk({"update": FakeResponse(404), "create": FakeResponse(409, "already exists")})

    assert deploy.main([str(write_rule(tmp_path))]) == 2
    assert session.kinds() == ["update", "create"]


# --- the batch keeps going ---------------------------------------------------


def test_one_rule_failing_does_not_stop_the_others(tmp_path, splunk):
    """A per-rule fault must not cost the rest of the batch its deploy."""
    splunk()
    good = write_rule(tmp_path, "DETECT-2026-0002")
    report = tmp_path / "deploy.json"

    assert deploy.main(["--report", str(report), str(tmp_path / "gone.spl"), str(good)]) == 2

    outcomes = {e["detect_id"]: e["outcome"] for e in json.loads(report.read_text(encoding="utf-8"))["rules"]}
    assert outcomes["DETECT-2026-0002"] == "updated"
