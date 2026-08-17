"""The testing-enabled gate in check_saved_search_hits.main() (run #125, 2026-08-17).

Before this, main() dispatched a Splunk saved-search query for *every* rule in
the bundle, regardless of `custom.testing.enabled`. A run with 27 disabled
rules and 1 enabled one under test still fired 28 queries, and the 27 got
scored from whatever residual/background data happened to match their filter
-- 22 froze at 0 events (FAIL), 4 coincidentally matched something (PASS),
none of it meaning anything.

These tests pin down the fix: a disabled rule's saved search is never
dispatched, and its hits.json says so explicitly rather than leaving a caller
to infer it from an empty event list.
"""

import json

import check_saved_search_hits as csh
import pytest


class RecordingSession:
    """Whatever check_saved_search_hits.main() does with a Splunk session,
    other than dispatch a search, is not this test's concern -- only whether
    `.post` (the dispatch call) happened at all."""

    def __init__(self):
        self.posts = []

    def post(self, url, data=None, timeout=None):
        self.posts.append({"url": url, "data": data})
        raise AssertionError("dispatch_saved_search should not be reached for a disabled rule")

    def get(self, url, timeout=None):
        raise AssertionError("no GET should happen without a prior dispatch")


@pytest.fixture
def splunk_env(monkeypatch):
    for key, value in {
        "SPLUNK_BASE_URL": "https://splunk.example:8089",
        "SPLUNK_USERNAME": "svc",
        "SPLUNK_PASSWORD": "pw",
        "SPLUNK_APP": "detection_app",
        "SPLUNK_VERIFY_TLS": "false",
    }.items():
        monkeypatch.setenv(key, value)


def write_rule(tmp_path, detect_id="DETECT-2026-0001", testing_enabled=False, title="Alpha"):
    stem = f"{detect_id}_{title}"
    spl = tmp_path / f"{stem}.spl"
    spl.write_text("index=main EventCode=4688\n", encoding="utf-8")
    (tmp_path / f"{stem}.meta.json").write_text(
        json.dumps(
            {
                "detect_id": detect_id,
                "title": title,
                "tester": "atomic",
                "runner": "victim",
                # The real sidecar key, space and all -- not "testing_enabled".
                "testing enabled": testing_enabled,
            }
        ),
        encoding="utf-8",
    )
    return spl


def read_hits(output_dir, detect_id):
    return json.loads((output_dir / detect_id / "hits.json").read_text(encoding="utf-8"))


# --- a disabled rule is never dispatched --------------------------------------


def test_a_disabled_rule_never_calls_post(tmp_path, splunk_env, monkeypatch):
    session = RecordingSession()
    monkeypatch.setattr(csh, "build_session", lambda *a, **k: session)

    spl = write_rule(tmp_path, testing_enabled=False)
    output_dir = tmp_path / "out"

    exit_code = csh.main(["--output-dir", str(output_dir), str(spl)])

    assert exit_code == 0
    assert session.posts == []


def test_a_disabled_rules_hits_json_says_it_was_not_queried(tmp_path, splunk_env, monkeypatch):
    session = RecordingSession()
    monkeypatch.setattr(csh, "build_session", lambda *a, **k: session)

    spl = write_rule(tmp_path, testing_enabled=False)
    output_dir = tmp_path / "out"

    csh.main(["--output-dir", str(output_dir), str(spl)])

    hits = read_hits(output_dir, "DETECT-2026-0001")
    assert hits["testing_enabled"] is False
    assert hits["event_count"] == 0
    assert hits["events"] == []
    # Distinguishable from "queried, Splunk said nothing" (which also has
    # event_count 0) -- this is the whole point of the fix.
    assert hits["error_kind"] == csh.ERR_TESTING_DISABLED
    assert hits["error"]


# --- an enabled rule is unaffected ---------------------------------------------


def test_an_enabled_rule_still_dispatches(tmp_path, splunk_env, monkeypatch):
    calls = []

    def fake_dispatch(**kwargs):
        calls.append(kwargs)
        return [{"a": 1}], None, None

    monkeypatch.setattr(csh, "build_session", lambda *a, **k: object())
    monkeypatch.setattr(csh, "dispatch_saved_search", fake_dispatch)

    spl = write_rule(tmp_path, testing_enabled=True)
    output_dir = tmp_path / "out"

    csh.main(["--output-dir", str(output_dir), str(spl)])

    assert len(calls) == 1
    hits = read_hits(output_dir, "DETECT-2026-0001")
    assert hits["testing_enabled"] is True
    assert hits["event_count"] == 1
    assert hits["error"] is None
    assert hits["error_kind"] is None


def test_a_mixed_batch_only_dispatches_the_enabled_rule(tmp_path, splunk_env, monkeypatch):
    calls = []

    def fake_dispatch(**kwargs):
        calls.append(kwargs.get("search_name"))
        return [], None, None

    monkeypatch.setattr(csh, "build_session", lambda *a, **k: object())
    monkeypatch.setattr(csh, "dispatch_saved_search", fake_dispatch)

    disabled_spl = write_rule(tmp_path, detect_id="DETECT-2026-0001", testing_enabled=False)
    enabled_spl = write_rule(tmp_path, detect_id="DETECT-2026-0002", testing_enabled=True, title="Beta")
    output_dir = tmp_path / "out"

    csh.main(["--output-dir", str(output_dir), str(disabled_spl), str(enabled_spl)])

    assert len(calls) == 1
    assert read_hits(output_dir, "DETECT-2026-0001")["error_kind"] == csh.ERR_TESTING_DISABLED
    assert read_hits(output_dir, "DETECT-2026-0002")["error_kind"] is None
