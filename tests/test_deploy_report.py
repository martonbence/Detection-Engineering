"""The record a deploy leaves behind (register item 2.4).

A prod run used to leave nothing: per-rule lines in a job log that ages out, and
afterwards nothing saying which rules reached production, which were created
versus updated, or at what version.

Splunk is faked throughout; what is asserted is what gets written down.
"""

import json

import deploy_spl_to_splunk as deploy
import pytest


class FakeResponse:
    def __init__(self, status_code=200, text="{}", payload=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload

    def json(self):
        if self._payload is not None:
            return self._payload
        return {"entry": [{"name": "x"}]}


# What Splunk returns for a freshly created, still user-private object. Used as
# the default GET /acl response so set_acl() sees a mismatch and goes on to POST
# -- i.e. the behaviour every test here was written against, before the deploy
# learned to read the ACL first.
ACL_PRIVATE = {"entry": [{"acl": {"sharing": "user", "perms": {"read": [], "write": []}}}]}


def acl_response(sharing="app", read=("*",), write=("admin",)):
    """A GET /acl body describing an object already in the given state."""
    return FakeResponse(
        payload={"entry": [{"acl": {"sharing": sharing, "perms": {"read": list(read), "write": list(write)}}}]}
    )


def endpoint_kind(url):
    """Which of the three endpoints a URL addresses.

    Order matters: the ACL URL also contains `saved/searches/`, and the object
    URL differs from the collection URL only by `/` versus `?` after it.
    """
    if "/acl" in url:
        return "acl"
    if "saved/searches?" in url:
        return "create"
    return "update"


class FakeSession:
    """Responds per endpoint, so create/update/ACL can be steered separately."""

    def __init__(self, responses=None, acl_get=None):
        self.headers = {}
        self.verify = True
        self.auth = None
        self.posts = []
        self.gets = []
        # Default: the object exists, so an update succeeds -- the common case
        # for a rule that has been deployed before.
        self.responses = {"update": FakeResponse(), "create": FakeResponse(), "acl": FakeResponse()}
        self.responses.update(responses or {})
        # set_acl() reads the current ACL before writing. Defaulting to a
        # user-private object means it always finds a mismatch and still POSTs,
        # which is what the tests written before that read expect.
        self.acl_get = acl_get if acl_get is not None else FakeResponse(payload=ACL_PRIVATE)

    def get(self, url, timeout=None):
        self.gets.append(url)
        return self.acl_get

    def post(self, url, data=None, timeout=None):
        kind = endpoint_kind(url)
        self.posts.append({"url": url, "data": data, "kind": kind})
        return self.responses[kind]

    def kinds(self):
        return [p["kind"] for p in self.posts]


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


def write_rule(tmp_path, detect_id="DETECT-2026-0001", status="stable", rule_version="1.3"):
    stem = f"{detect_id}_Alpha"
    spl = tmp_path / f"{stem}.spl"
    spl.write_text("index=main EventCode=4688\n", encoding="utf-8")
    (tmp_path / f"{stem}.meta.json").write_text(
        json.dumps(
            {
                "detect_id": detect_id,
                "title": "Alpha",
                "description": "Detects alpha",
                "deploy_mode": "alert",
                "status": status,
                "rule_version": rule_version,
            }
        ),
        encoding="utf-8",
    )
    return spl


def read_report(path):
    return json.loads(path.read_text(encoding="utf-8"))


# --- what gets recorded ------------------------------------------------------


def test_a_created_rule_is_recorded_with_its_version(tmp_path, splunk):
    splunk({"update": FakeResponse(404), "create": FakeResponse(201)})
    spl = write_rule(tmp_path)
    report = tmp_path / "out" / "deploy.json"

    assert deploy.main(["--report", str(report), str(spl)]) == 0

    data = read_report(report)
    assert data["totals"] == {"created": 1}
    entry = data["rules"][0]
    assert entry["detect_id"] == "DETECT-2026-0001"
    assert entry["rule_version"] == "1.3"
    assert entry["outcome"] == "created"


def test_an_existing_rule_is_recorded_as_updated(tmp_path, splunk):
    """200 from the object endpoint means it was there and is now updated."""
    splunk()
    spl = write_rule(tmp_path)
    report = tmp_path / "deploy.json"

    deploy.main(["--report", str(report), str(spl)])

    assert read_report(report)["rules"][0]["outcome"] == "updated"


def test_a_deprecated_rule_is_recorded_as_skipped_not_omitted(tmp_path, splunk):
    """Silence would read as "it was deployed" -- the skip has to be on the record."""
    splunk()
    spl = write_rule(tmp_path, status="deprecated")
    report = tmp_path / "deploy.json"

    assert deploy.main(["--report", str(report), str(spl)]) == 0

    entry = read_report(report)["rules"][0]
    assert entry["outcome"] == "skipped_deprecated"


def test_a_missing_file_is_recorded_as_failed(tmp_path, splunk):
    splunk()
    report = tmp_path / "deploy.json"

    assert deploy.main(["--report", str(report), str(tmp_path / "nope.spl")]) == 2

    entry = read_report(report)["rules"][0]
    assert entry["outcome"] == "failed"
    assert entry["detail"] == "file not found"


def test_a_failed_create_records_the_status_code(tmp_path, splunk):
    splunk({"update": FakeResponse(404), "create": FakeResponse(500, "boom")})
    spl = write_rule(tmp_path)
    report = tmp_path / "deploy.json"

    assert deploy.main(["--report", str(report), str(spl)]) == 2

    entry = read_report(report)["rules"][0]
    assert entry["outcome"] == "failed"
    assert "500" in entry["detail"]


def test_every_rule_appears_exactly_once(tmp_path, splunk):
    splunk()
    files = [str(write_rule(tmp_path, f"DETECT-2026-000{i}")) for i in (1, 2, 3)]
    report = tmp_path / "deploy.json"

    deploy.main(["--report", str(report), *files])

    data = read_report(report)
    assert len(data["rules"]) == 3
    assert len({e["detect_id"] for e in data["rules"]}) == 3


def test_a_run_with_no_files_still_writes_a_report(tmp_path, splunk):
    """An absent artifact must not be ambiguous with a deploy that did nothing."""
    splunk()
    report = tmp_path / "deploy.json"

    assert deploy.main(["--report", str(report)]) == 0

    assert read_report(report)["rules"] == []


# --- what must never be recorded ---------------------------------------------


def test_the_report_carries_no_connection_details(tmp_path, splunk):
    """It is uploaded as an artifact from a public repo."""
    splunk()
    spl = write_rule(tmp_path)
    report = tmp_path / "deploy.json"

    deploy.main(["--report", str(report), str(spl)])

    raw = report.read_text(encoding="utf-8")
    for secret in ("splunk.example", "8089", "detection_app", "svc", "pw"):
        assert secret not in raw


# --- the step summary --------------------------------------------------------


def test_the_step_summary_lists_the_rules(tmp_path, splunk, monkeypatch):
    splunk()
    spl = write_rule(tmp_path)
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))

    deploy.main([str(spl)])

    text = summary.read_text(encoding="utf-8")
    assert "DETECT-2026-0001" in text
    assert "updated" in text


def test_no_step_summary_is_written_when_github_provides_none(tmp_path, splunk):
    """The autouse fixture in conftest.py unsets it -- this must not then crash."""
    splunk()
    spl = write_rule(tmp_path)

    assert deploy.main([str(spl)]) == 0


def test_the_report_is_optional(tmp_path, splunk):
    """The dev workflow calls this without --report and must be unaffected."""
    splunk()
    spl = write_rule(tmp_path)

    assert deploy.main([str(spl)]) == 0
