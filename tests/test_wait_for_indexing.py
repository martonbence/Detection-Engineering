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
from wait_for_indexing import (
    build_probe_search,
    build_probes,
    indexes_from_meta,
    leading_filter_clause,
    main,
    parse_count,
)


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


# --- per-rule filter extraction (DETECT-2026-0002 fix) -----------------------
#
# DETECT-2026-0002 is the first rule against `wineventlog`, a shared,
# high-volume native index -- "any event in the index" is satisfied almost
# instantly by unrelated noise there, long before the rule's own atomic-test
# events (4625/4771/4776) have actually been indexed. The probe must be
# specific to what each rule is actually looking for.


def test_leading_filter_clause_stops_at_first_top_level_pipe():
    spl = (
        'index=wineventlog source="wineventlog:security" (EventCode=4625 '
        'Sub_Status="0xC000006A") OR (EventCode=4771 Failure_Code="0x18") '
        "| eval target_account=case(EventCode=4625, mvindex(Account_Name, -1)) "
        "| stats count by target_account"
    )

    clause = leading_filter_clause(spl)

    assert clause == (
        'index=wineventlog source="wineventlog:security" (EventCode=4625 '
        'Sub_Status="0xC000006A") OR (EventCode=4771 Failure_Code="0x18")'
    )
    assert "eval" not in clause
    assert "stats" not in clause


def test_leading_filter_clause_ignores_a_pipe_inside_a_quoted_literal():
    spl = 'index=sysmon CommandLine="*a|b*" | table _time'

    clause = leading_filter_clause(spl)

    assert clause == 'index=sysmon CommandLine="*a|b*"'


def test_leading_filter_clause_is_none_for_a_true_generating_command():
    """`| tstats ...` produces its own result set -- there is no filter clause
    to extract, and sigma_to_spl.py's own index-injection treats it the same
    way (register: `_inject_index_prefix`'s generating-command branch)."""
    assert leading_filter_clause("| tstats count from datamodel=Endpoint.Processes") is None
    assert leading_filter_clause("| inputlookup my_lookup.csv") is None


def test_leading_filter_clause_handles_empty_input():
    assert leading_filter_clause("") is None
    assert leading_filter_clause("   ") is None


def test_build_probes_narrows_to_each_rules_own_filter(tmp_path):
    spl = tmp_path / "DETECT-2026-0002.spl"
    spl.write_text(
        'index=wineventlog (EventCode=4625 Sub_Status="0xC000006A") '
        "| eval target_account=lower(Account_Name) | stats count by target_account",
        encoding="utf-8",
    )
    (tmp_path / "DETECT-2026-0002.meta.json").write_text(
        json.dumps({"index": "wineventlog"}), encoding="utf-8"
    )

    probes = build_probes([str(spl)], "100")

    assert len(probes) == 1
    label, search = probes[0]
    assert label == "DETECT-2026-0002"
    assert 'EventCode=4625 Sub_Status="0xC000006A"' in search
    assert "eval" not in search
    assert "target_account" not in search  # the rule's own transforming logic, not its filter
    assert "earliest=100" in search


def test_build_probes_falls_back_to_index_level_for_generating_commands(tmp_path):
    spl = tmp_path / "DETECT-tstats.spl"
    spl.write_text("| tstats count from datamodel=Endpoint.Processes", encoding="utf-8")
    (tmp_path / "DETECT-tstats.meta.json").write_text(json.dumps({"index": "sysmon"}), encoding="utf-8")

    probes = build_probes([str(spl)], "100")

    assert len(probes) == 1
    label, search = probes[0]
    assert label == "DETECT-tstats"
    assert "index=sysmon" in search
    assert "tstats" not in search


def test_build_probes_with_no_files_falls_back_to_the_legacy_all_index_probe():
    probes = build_probes([], "100")

    assert len(probes) == 1
    assert "index=*" in probes[0][1]


class KeyedFakeSession:
    """A fake Splunk that answers differently per probe search text.

    Models the real bug: a noisy shared index (`wineventlog`) satisfies a
    blanket `index=X` probe almost immediately, while the specific rule's own
    matching events take longer to actually appear.
    """

    def __init__(self, response_queues: dict[str, list[int]]):
        self.headers = {}
        self.verify = True
        self.auth = None
        self.calls = []
        self._queues = {k: list(v) for k, v in response_queues.items()}

    def post(self, url, data=None, timeout=None):
        search = data["search"]
        self.calls.append(search)
        for key, queue in self._queues.items():
            if key in search:
                count = queue.pop(0) if len(queue) > 1 else queue[0]
                return FakeResponse(count=count)
        return FakeResponse(count=0)


def test_it_waits_for_every_rules_own_probe_not_just_any_index_hit(splunk, tmp_path, monkeypatch):
    """The regression this whole fix is for: with a blanket `index=wineventlog`
    probe, noise alone would have declared victory on the first check. The
    per-rule probe must keep waiting until DETECT-2026-0002's own narrow
    filter clause -- not just any event in the shared index -- returns a hit.
    """
    noisy_filter = "EventCode=4624"  # some other rule's own filter -- matches fast
    target_filter = 'EventCode=4625 Sub_Status="0xC000006A"'  # this rule's own filter -- slow

    noisy_spl = tmp_path / "DETECT-noisy.spl"
    noisy_spl.write_text(f"index=wineventlog {noisy_filter} | table _time", encoding="utf-8")
    (tmp_path / "DETECT-noisy.meta.json").write_text(json.dumps({"index": "wineventlog"}), encoding="utf-8")

    target_spl = tmp_path / "DETECT-2026-0002.spl"
    target_spl.write_text(f"index=wineventlog {target_filter} | table _time", encoding="utf-8")
    (tmp_path / "DETECT-2026-0002.meta.json").write_text(json.dumps({"index": "wineventlog"}), encoding="utf-8")

    # `splunk` fixture fakes env vars, time.sleep and time.monotonic, and also
    # wires up its own FakeSession -- swap that for the keyed one afterwards.
    _, slept = splunk([])

    session = KeyedFakeSession({noisy_filter: [1], target_filter: [0, 0, 5]})
    monkeypatch.setattr(wait.requests, "Session", lambda: session)

    result = main(
        [
            "--since",
            "100",
            "--interval",
            "10",
            "--timeout",
            "60",
            str(noisy_spl),
            str(target_spl),
        ]
    )

    assert result == 0
    # It kept polling past the point the noisy rule's own probe was already
    # satisfied -- the old blanket `index=wineventlog` probe would have
    # returned success on the very first check instead.
    assert len(slept) >= 2
    assert any(target_filter in call for call in session.calls)
    assert any(noisy_filter in call for call in session.calls)


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
