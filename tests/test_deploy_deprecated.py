"""A deprecated rule must not be deployed (register item 1.7).

The schema has always allowed `status: deprecated`, but no script read it, so a
rule parked as deprecated went to Splunk and ran exactly like a stable one --
retirement had no expression anywhere in the pipeline.

Splunk is faked: the assertion is about which requests are made at all.
"""

import json

import pytest

import deploy_spl_to_splunk as deploy


class FakeResponse:
    status_code = 200
    text = "{}"

    def json(self):
        return {"entry": [{"name": "x"}]}


class FakeSession:
    def __init__(self):
        self.headers = {}
        self.verify = True
        self.auth = None
        self.posts = []

    def post(self, url, data=None, timeout=None):
        self.posts.append({"url": url, "data": data})
        return FakeResponse()

    def get(self, url, timeout=None):
        return FakeResponse()


@pytest.fixture
def splunk(monkeypatch):
    session = FakeSession()
    monkeypatch.setattr(deploy.requests, "Session", lambda: session)
    for key, value in {
        "SPLUNK_BASE_URL": "https://splunk.example:8089",
        "SPLUNK_USERNAME": "svc",
        "SPLUNK_PASSWORD": "pw",
        "SPLUNK_APP": "detection_app",
        "SPLUNK_VERIFY_TLS": "false",
    }.items():
        monkeypatch.setenv(key, value)
    return session


def write_rule_artefacts(tmp_path, status):
    spl = tmp_path / "DETECT-2026-0001_Alpha.spl"
    spl.write_text("index=main EventCode=4688\n", encoding="utf-8")
    (tmp_path / "DETECT-2026-0001_Alpha.meta.json").write_text(
        json.dumps({
            "detect_id": "DETECT-2026-0001",
            "title": "Alpha",
            "description": "Detects alpha",
            "deploy_mode": "alert",
            "status": status,
        }),
        encoding="utf-8",
    )
    return spl


def test_deprecated_rule_is_never_sent_to_splunk(tmp_path, splunk, capsys):
    spl = write_rule_artefacts(tmp_path, status="deprecated")

    assert deploy.main([str(spl)]) == 0
    assert splunk.posts == []
    assert "deprecated" in capsys.readouterr().out


def test_a_normal_rule_still_deploys(tmp_path, splunk):
    """The guard must be narrow -- everything else goes out as before."""
    spl = write_rule_artefacts(tmp_path, status="stable")

    assert deploy.main([str(spl)]) == 0
    assert any("saved/searches" in p["url"] for p in splunk.posts)


def test_skipping_is_not_reported_as_a_failure(tmp_path, splunk):
    """A deprecated rule in the batch must not fail the deploy step."""
    deprecated = write_rule_artefacts(tmp_path, status="deprecated")

    assert deploy.main([str(deprecated)]) == 0
