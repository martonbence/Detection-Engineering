"""Desired-vs-actual classification in reconcile.py.

Covers register items 1.7 and 1.8: an object the pipeline created and the repo
no longer asks for has to be told apart from one that was merely renamed, and
neither may be confused with a search somebody built by hand in the same app.

No Splunk is involved -- the session is faked, so these run anywhere in
milliseconds.
"""

import json

import pytest

from reconcile import (
    CI_MARKER,
    ReconcileError,
    fetch_actual,
    has_drift,
    load_desired,
    reconcile,
)


def managed(description_extra=""):
    return {"description": f"{CI_MARKER}\n{description_extra}", "managed": True}


def unmanaged():
    return {"description": "Hand-built by an analyst", "managed": False}


# --- classification ---------------------------------------------------------


def test_everything_matches_reports_no_drift():
    desired = {"DETECT-2026-0001_Alpha": {"detect_id": "DETECT-2026-0001", "title": "Alpha", "path": "a.yml"}}
    actual = {"DETECT-2026-0001_Alpha": managed()}

    report = reconcile(desired, actual)

    assert report["counts"]["in_sync"] == 1
    assert not has_drift(report)


def test_rule_never_deployed_is_missing():
    desired = {"DETECT-2026-0001_Alpha": {"detect_id": "DETECT-2026-0001", "title": "Alpha", "path": "a.yml"}}

    report = reconcile(desired, actual={})

    assert report["counts"]["missing"] == 1
    assert report["missing"][0]["name"] == "DETECT-2026-0001_Alpha"
    assert has_drift(report)


def test_renamed_title_is_reported_as_rename_not_removal():
    """Audit 1.8: the detect_id still exists, only the title-derived slug moved."""
    desired = {"DETECT-2026-0001_New-Title": {"detect_id": "DETECT-2026-0001", "title": "New Title", "path": "a.yml"}}
    actual = {
        "DETECT-2026-0001_New-Title": managed(),
        "DETECT-2026-0001_Old-Title": managed(),
    }

    report = reconcile(desired, actual)

    assert report["counts"]["orphan_renamed"] == 1
    assert report["counts"]["orphan_removed"] == 0
    assert report["orphan_renamed"][0]["name"] == "DETECT-2026-0001_Old-Title"
    assert report["orphan_renamed"][0]["detect_id"] == "DETECT-2026-0001"


def test_deleted_rule_is_reported_as_removal():
    """Audit 1.7: the detect_id is gone from the repo entirely."""
    desired = {"DETECT-2026-0001_Alpha": {"detect_id": "DETECT-2026-0001", "title": "Alpha", "path": "a.yml"}}
    actual = {
        "DETECT-2026-0001_Alpha": managed(),
        "DETECT-2026-0099_Deleted": managed(),
    }

    report = reconcile(desired, actual)

    assert report["counts"]["orphan_removed"] == 1
    assert report["counts"]["orphan_renamed"] == 0
    assert report["orphan_removed"][0]["detect_id"] == "DETECT-2026-0099"


def test_hand_built_search_is_never_treated_as_an_orphan():
    """A search without the CI marker is not ours to have an opinion about."""
    desired = {}
    actual = {"Analyst ad-hoc search": unmanaged()}

    report = reconcile(desired, actual)

    assert report["counts"]["unmanaged"] == 1
    assert report["counts"]["orphan_removed"] == 0
    assert report["counts"]["orphan_renamed"] == 0
    # Unmanaged objects are noise, not drift -- they must not make CI shout.
    assert not has_drift(report)


def test_rename_and_removal_are_distinguished_in_the_same_run():
    desired = {"DETECT-2026-0001_New": {"detect_id": "DETECT-2026-0001", "title": "New", "path": "a.yml"}}
    actual = {
        "DETECT-2026-0001_New": managed(),
        "DETECT-2026-0001_Old": managed(),
        "DETECT-2026-0042_Gone": managed(),
        "Analyst search": unmanaged(),
    }

    report = reconcile(desired, actual)

    assert report["counts"] == {
        "desired": 1,
        "actual": 4,
        "in_sync": 1,
        "missing": 0,
        "orphan_renamed": 1,
        "orphan_removed": 1,
        "unmanaged": 1,
    }


# --- desired state from the repo -------------------------------------------


def write_rule(directory, filename, detect_id, title):
    (directory / filename).write_text(
        f"title: {title}\ndetect_id: {detect_id}\nstatus: test\n", encoding="utf-8"
    )


def test_desired_state_reproduces_the_deploy_naming(tmp_path):
    write_rule(tmp_path, "r1.yml", "DETECT-2026-0001", "LSASS Dump via ProcDump")

    desired = load_desired(tmp_path)

    # Same shape the deploy produces: "<detect_id>_<slugified title>".
    assert "DETECT-2026-0001_LSASS-Dump-via-ProcDump" in desired


def test_rule_without_detect_id_is_skipped_not_guessed(tmp_path, capsys):
    (tmp_path / "broken.yml").write_text("title: No Id Here\n", encoding="utf-8")

    desired = load_desired(tmp_path)

    assert desired == {}
    assert "no detect_id" in capsys.readouterr().err


def test_unparseable_rule_raises_rather_than_silently_shrinking_desired(tmp_path):
    (tmp_path / "bad.yml").write_text("title: [unclosed\n", encoding="utf-8")

    # Silently dropping it would under-count desired state and turn every other
    # rule's live object into a phantom orphan.
    with pytest.raises(ReconcileError):
        load_desired(tmp_path)


# --- fetching actual state --------------------------------------------------


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("not JSON")
        return self._payload


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.requested_url = None

    def get(self, url, timeout=None):
        self.requested_url = url
        return self.response


def test_fetch_actual_marks_ci_owned_objects():
    payload = {
        "entry": [
            {"name": "DETECT-2026-0001_Alpha", "content": {"description": f"{CI_MARKER}\nSomething"}},
            {"name": "Analyst search", "content": {"description": "mine"}},
        ]
    }
    session = FakeSession(FakeResponse(200, payload))

    actual = fetch_actual(session, "https://splunk:8089", "svc", "app")

    assert actual["DETECT-2026-0001_Alpha"]["managed"] is True
    assert actual["Analyst search"]["managed"] is False


def test_fetch_actual_disables_paging():
    """Without count=0 Splunk returns 30 rows and every later rule looks missing."""
    session = FakeSession(FakeResponse(200, {"entry": []}))

    fetch_actual(session, "https://splunk:8089", "svc", "app")

    assert "count=0" in session.requested_url
    assert "/servicesNS/svc/app/saved/searches" in session.requested_url


@pytest.mark.parametrize("status", [401, 403])
def test_permission_errors_are_fatal_not_an_empty_actual_state(status):
    """An empty list from a rejected request would report the whole library missing."""
    session = FakeSession(FakeResponse(status, None, "denied"))

    with pytest.raises(ReconcileError):
        fetch_actual(session, "https://splunk:8089", "svc", "app")


def test_non_json_response_is_fatal():
    session = FakeSession(FakeResponse(200, None, "<html>proxy error</html>"))

    with pytest.raises(ReconcileError):
        fetch_actual(session, "https://splunk:8089", "svc", "app")


# --- report shape -----------------------------------------------------------


def test_report_is_json_serialisable():
    """The JSON output is what audit item 4.7 will read."""
    desired = {"DETECT-2026-0001_Alpha": {"detect_id": "DETECT-2026-0001", "title": "Alpha", "path": "a.yml"}}
    report = reconcile(desired, {"DETECT-2026-0099_Gone": managed()})

    assert json.loads(json.dumps(report))["counts"]["orphan_removed"] == 1
