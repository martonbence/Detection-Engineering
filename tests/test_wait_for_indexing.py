"""Waiting for the indexer instead of guessing at it (register item 2.3).

The old step was `sleep 60`, through a SPLUNK_VERIFY_WAIT_SECONDS nothing ever
set. A fixed sleep is wrong in both directions: it burns a minute when the
indexer was ready in eight seconds, and gives up at sixty when it needed ninety,
turning "nobody waited long enough" into a verdict that says the detection
failed.

Splunk and the clock are both faked; what is asserted is when it stops waiting.
"""

import json

import pytest
import wait_for_indexing as wait
from wait_for_indexing import build_probe_search, indexes_from_meta, main, parse_count


class FakeResponse:
    def __init__(self, count=0, status_code=200, body=None):
        self.status_code = status_code
        self._body = body if body is not None else {"results": [{"c": str(count)}]}

    def json(self):
        if self._body is _INVALID:
            raise ValueError("not json")
        return self._body


_INVALID = object()


class FakeSession:
    """Returns the queued counts in order, repeating the last one forever."""

    def __init__(self, responses):
        self.headers = {}
        self.verify = True
        self.auth = None
        self.calls = []
        self._responses = list(responses)

    def post(self, url, data=None, timeout=None):
        self.calls.append(data)
        if len(self._responses) > 1:
            return self._responses.pop(0)
        return self._responses[0]


@pytest.fixture
def splunk(monkeypatch):
    """Fakes Splunk plus sleep, so the tests assert behaviour rather than wait."""
    slept = []
    monkeypatch.setattr(wait.time, "sleep", lambda s: slept.append(s))

    clock = {"now": 0.0}

    def fake_monotonic():
        return clock["now"]

    monkeypatch.setattr(wait.time, "monotonic", fake_monotonic)
    # Every faked sleep advances the faked clock, so timeouts are reachable.
    monkeypatch.setattr(wait.time, "sleep", lambda s: (slept.append(s), clock.__setitem__("now", clock["now"] + s)))

    for key, value in {
        "SPLUNK_BASE_URL": "https://splunk.example:8089",
        "SPLUNK_USERNAME": "svc",
        "SPLUNK_PASSWORD": "pw",
        "SPLUNK_APP": "detection_app",
        "SPLUNK_VERIFY_TLS": "false",
    }.items():
        monkeypatch.setenv(key, value)

    def _make(responses):
        session = FakeSession(responses)
        monkeypatch.setattr(wait.requests, "Session", lambda: session)
        return session, slept

    return _make


# --- the probe ---------------------------------------------------------------


def test_the_probe_is_scoped_to_the_indexes_under_test():
    """A quiet index nobody in this batch uses must not satisfy the wait."""
    search = build_probe_search(["sysmon", "wineventlog"], "1785779762")

    assert "index=sysmon OR index=wineventlog" in search
    assert "earliest=1785779762" in search


def test_with_no_resolvable_index_the_probe_falls_back_to_all():
    assert "index=*" in build_probe_search([], "123")


def test_indexes_come_from_the_meta_sidecars(tmp_path):
    for name, index in (("a", "sysmon"), ("b", "wineventlog"), ("c", "sysmon")):
        (tmp_path / f"{name}.spl").write_text("index=x", encoding="utf-8")
        (tmp_path / f"{name}.meta.json").write_text(json.dumps({"index": index}), encoding="utf-8")

    found = indexes_from_meta([str(tmp_path / f"{n}.spl") for n in ("a", "b", "c")])

    assert found == ["sysmon", "wineventlog"]  # deduplicated, order preserved


def test_a_missing_sidecar_is_skipped_not_fatal(tmp_path):
    (tmp_path / "a.spl").write_text("index=x", encoding="utf-8")

    assert indexes_from_meta([str(tmp_path / "a.spl")]) == []


def test_parse_count_treats_anything_unexpected_as_zero():
    assert parse_count({"results": [{"c": "7"}]}) == 7
    assert parse_count({"results": []}) == 0
    assert parse_count({"results": [{"c": "not a number"}]}) == 0
    assert parse_count({}) == 0
    assert parse_count("nonsense") == 0


# --- the waiting -------------------------------------------------------------


def test_it_returns_as_soon_as_events_appear(splunk):
    """The whole point: no fixed minute when the indexer is already there."""
    session, slept = splunk([FakeResponse(count=1)])

    assert main(["--since", "100"]) == 0
    assert slept == []
    assert len(session.calls) == 1


def test_it_keeps_checking_until_events_appear(splunk):
    session, slept = splunk([FakeResponse(0), FakeResponse(0), FakeResponse(3)])

    assert main(["--since", "100", "--interval", "5", "--timeout", "60"]) == 0
    assert slept == [5, 5]
    assert len(session.calls) == 3


def test_it_gives_up_after_the_timeout_and_says_so(splunk, capsys):
    splunk([FakeResponse(0)])

    assert main(["--since", "100", "--interval", "10", "--timeout", "30"]) == 0

    out = capsys.readouterr().out
    assert "::warning" in out
    assert "indexing not confirmed" in out


def test_giving_up_is_not_a_failure(splunk):
    """Blocking here would turn a slow indexer into a pipeline failure."""
    splunk([FakeResponse(0)])

    assert main(["--since", "100", "--interval", "10", "--timeout", "20"]) == 0


def test_it_never_sleeps_past_the_timeout(splunk):
    """A last sleep that overshoots would make the cap a lie."""
    _, slept = splunk([FakeResponse(0)])

    main(["--since", "100", "--interval", "10", "--timeout", "35"])

    assert sum(slept) <= 35


# --- the probe failing is not the same as an answer --------------------------


def test_an_http_error_is_treated_as_not_ready_rather_than_ready(splunk):
    """Failing open here would skip the wait entirely on any Splunk hiccup."""
    _, slept = splunk([FakeResponse(status_code=503)])

    assert main(["--since", "100", "--interval", "10", "--timeout", "30"]) == 0
    assert slept  # it waited rather than sailing straight through


def test_a_non_json_body_is_treated_as_not_ready(splunk):
    _, slept = splunk([FakeResponse(body=_INVALID)])

    main(["--since", "100", "--interval", "10", "--timeout", "30"])

    assert slept


def test_a_connection_error_is_treated_as_not_ready(splunk, monkeypatch):
    class Exploding(FakeSession):
        def post(self, url, data=None, timeout=None):
            self.calls.append(data)
            raise wait.requests.RequestException("no route to host")

    session = Exploding([FakeResponse(0)])
    monkeypatch.setattr(wait.requests, "Session", lambda: session)

    assert main(["--since", "100", "--interval", "10", "--timeout", "30"]) == 0
    assert session.calls
