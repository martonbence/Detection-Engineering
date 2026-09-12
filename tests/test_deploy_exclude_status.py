"""`--exclude-status` keeps a rule out of a deploy target by its Sigma `status`.

Durable fix for the 2026-09-09 incident: `ci_prod_workflow.yml`'s
`workflow_dispatch` recovery deploys every `.spl` on `main` with no eligibility
filter, and `deploy_spl_to_splunk.py` only ever skipped `deprecated` -- so two
`status: experimental` WIP rules that had never reached dev Splunk went live in
prod. Prod now passes `--exclude-status experimental`; dev passes nothing, so
the lab still gets experimental rules to exercise.

Splunk is faked: the assertion is about which requests are made at all.
"""

import json

import deploy_spl_to_splunk as deploy
import pytest
from lib.rules import status as lib_status


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


def write_rule_artefacts(tmp_path, status, detect_id="DETECT-2026-0001", title="Alpha"):
    stem = f"{detect_id}_{title}"
    spl = tmp_path / f"{stem}.spl"
    spl.write_text("index=main EventCode=4688\n", encoding="utf-8")
    (tmp_path / f"{stem}.meta.json").write_text(
        json.dumps({
            "detect_id": detect_id,
            "title": title,
            "description": "Detects alpha",
            "deploy_mode": "alert",
            "status": status,
        }),
        encoding="utf-8",
    )
    return spl


def _deployed(session):
    return any("saved/searches" in p["url"] for p in session.posts)


# --- the new skip -----------------------------------------------------------


def test_experimental_rule_is_skipped_with_the_flag(tmp_path, splunk, capsys):
    spl = write_rule_artefacts(tmp_path, status="experimental")

    assert deploy.main(["--exclude-status", "experimental", str(spl)]) == 0
    assert splunk.posts == []
    assert "excluded by --exclude-status" in capsys.readouterr().out


def test_experimental_rule_still_deploys_without_the_flag(tmp_path, splunk):
    """Dev passes no --exclude-status, so experimental rules reach the lab."""
    spl = write_rule_artefacts(tmp_path, status="experimental")

    assert deploy.main([str(spl)]) == 0
    assert _deployed(splunk)


@pytest.mark.parametrize("status", ["stable", "test"])
def test_a_non_excluded_status_still_deploys_with_the_flag(tmp_path, splunk, status):
    """The exclusion must be narrow -- only the named status is affected.

    `test` is called out explicitly: the repo has DETECT-2026-0003 and
    DETECT-2026-0032 live in prod as `status: test`, and they must keep
    deploying when prod passes `--exclude-status experimental` (Finding 6)."""
    spl = write_rule_artefacts(tmp_path, status=status)

    assert deploy.main(["--exclude-status", "experimental", str(spl)]) == 0
    assert _deployed(splunk)


# --- deprecated is unconditional, flag or no flag --------------------------


def test_deprecated_rule_is_skipped_without_the_flag(tmp_path, splunk):
    spl = write_rule_artefacts(tmp_path, status="deprecated")

    assert deploy.main([str(spl)]) == 0
    assert splunk.posts == []


def test_deprecated_rule_is_skipped_with_an_unrelated_flag(tmp_path, splunk, capsys):
    spl = write_rule_artefacts(tmp_path, status="deprecated")

    assert deploy.main(["--exclude-status", "experimental", str(spl)]) == 0
    assert splunk.posts == []
    # It took the deprecated path, not the excluded-status path.
    assert "is deprecated" in capsys.readouterr().out


# --- flag parsing ---------------------------------------------------------


def test_flag_accepts_a_comma_separated_list(tmp_path, splunk):
    exp = write_rule_artefacts(tmp_path, status="experimental", detect_id="DETECT-2026-0001", title="Exp")
    tst = write_rule_artefacts(tmp_path, status="test", detect_id="DETECT-2026-0002", title="Tst")
    stable = write_rule_artefacts(tmp_path, status="stable", detect_id="DETECT-2026-0003", title="Std")

    rc = deploy.main(["--exclude-status", "experimental,test", str(exp), str(tst), str(stable)])

    assert rc == 0
    # Only the stable rule was sent.
    sent = [p["url"] for p in splunk.posts if "saved/searches" in p["url"]]
    assert any("DETECT-2026-0003_Std" in u for u in sent)
    assert not any("DETECT-2026-0001_Exp" in u for u in sent)
    assert not any("DETECT-2026-0002_Tst" in u for u in sent)


def test_flag_is_repeatable(tmp_path, splunk):
    exp = write_rule_artefacts(tmp_path, status="experimental", detect_id="DETECT-2026-0001", title="Exp")
    tst = write_rule_artefacts(tmp_path, status="test", detect_id="DETECT-2026-0002", title="Tst")

    rc = deploy.main([
        "--exclude-status", "experimental",
        "--exclude-status", "test",
        str(exp), str(tst),
    ])

    assert rc == 0
    assert splunk.posts == []


def test_case_and_whitespace_are_normalised(tmp_path, splunk):
    spl = write_rule_artefacts(tmp_path, status="Experimental")

    assert deploy.main(["--exclude-status", "  EXPERIMENTAL  ", str(spl)]) == 0
    assert splunk.posts == []


# --- outcome bookkeeping -------------------------------------------------


def test_excluded_rule_is_recorded_but_not_a_failure(tmp_path, splunk):
    spl = write_rule_artefacts(tmp_path, status="experimental")
    report = tmp_path / "report.json"

    rc = deploy.main(["--exclude-status", "experimental", "--report", str(report), str(spl)])

    assert rc == 0  # a skip is not a failure
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["totals"] == {"skipped_excluded": 1}
    assert data["rules"][0]["outcome"] == "skipped_excluded"
    assert "excluded" in data["rules"][0]["detail"]


# --- the deliberate mirror must not drift (Finding 3) --------------------


@pytest.mark.parametrize(
    "value",
    ["experimental", "  Experimental  ", "STABLE", "test", "deprecated", "", None],
)
def test_rule_status_helper_mirrors_lib_rules_status(value):
    """deploy._rule_status is a hand-copy of lib.rules.status (deploy cannot
    import lib.rules -- pyyaml is not in the prod deploy's pin). This asserts
    the copy stays byte-identical in behaviour."""
    assert deploy._rule_status({"status": value}) == lib_status({"status": value})
