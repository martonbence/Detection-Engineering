"""Splunk dispatch/poll behaviour in check_saved_search_hits.dispatch_saved_search().

Covers register item 1.5: the search job's terminal state decides whether the
returned event count means anything, and each failure route has to declare
whether it is a measurement gap or a real defect.

No Splunk is involved -- the session is faked, so these run anywhere in
milliseconds.
"""

import pytest

from check_saved_search_hits import ERR_RULE, ERR_UNMEASURED, dispatch_saved_search


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
    """Replays a scripted sequence of dispatchStates, one per poll.

    The last state repeats once the script runs out, which is how a search
    that never settles ("RUNNING" forever) is simulated.
    """

    def __init__(self, states, results=None, dispatch=None):
        self.states = list(states)
        self.results = results if results is not None else {"results": []}
        self.dispatch = dispatch if dispatch is not None else FakeResponse(201, {"sid": "S1"})
        self.polls = 0

    def post(self, *_args, **_kwargs):
        return self.dispatch

    def get(self, url, **_kwargs):
        if "/results" in url:
            return FakeResponse(200, self.results)
        self.polls += 1
        state = self.states[min(self.polls - 1, len(self.states) - 1)]
        return FakeResponse(200, {"entry": [{"content": {"dispatchState": state}}]})


def dispatch(session):
    return dispatch_saved_search(
        session=session,
        base_url="http://splunk.invalid",
        app="app",
        owner="owner",
        search_name="search",
        earliest="1700000000",
        latest="now",
        poll_interval=0.001,
        max_wait=0.02,
    )


def test_done_returns_events_and_no_error():
    events, error, kind = dispatch(FakeSession(["DONE"], {"results": [{"a": 1}, {"b": 2}]}))
    assert len(events) == 2
    assert error is None
    assert kind is None


def test_search_that_never_finishes_is_unmeasured_not_zero_events():
    """The 1.5 defect. Previously this fell through, fetched results anyway and
    returned zero events with error=None -- indistinguishable from a detection
    that simply did not fire, and so scored as a FAIL."""
    events, error, kind = dispatch(FakeSession(["RUNNING"], {"results": [{"a": 1}]}))
    assert events == []
    assert kind == ERR_UNMEASURED
    assert "did not finish" in error


def test_finalizing_does_not_end_the_poll_loop():
    """FINALIZING still has an incomplete result set. Reading it there returns
    an undercount, which can push a working rule below the pass threshold."""
    events, error, kind = dispatch(FakeSession(["FINALIZING"], {"results": [{"a": 1}]}))
    assert events == []
    assert kind == ERR_UNMEASURED


def test_finalizing_then_done_reads_the_complete_result_set():
    """The counterpart to the test above, and the one that shows the change is
    a correction rather than just extra strictness: waiting for DONE yields all
    three events instead of the one visible mid-finalisation."""
    session = FakeSession(
        ["FINALIZING", "FINALIZING", "DONE"],
        {"results": [{"a": 1}, {"b": 2}, {"c": 3}]},
    )
    events, error, kind = dispatch(session)
    assert len(events) == 3
    assert error is None
    assert kind is None


@pytest.mark.parametrize(
    "session_factory, expected_kind, expected_fragment",
    [
        # Splunk ran the search and it errored -- that is the rule's problem.
        (lambda: FakeSession(["FAILED"]), ERR_RULE, "Search job failed"),
        # The rule is not deployed at all: real defect, must stay red.
        (
            lambda: FakeSession(["DONE"], dispatch=FakeResponse(404, {}, "not found")),
            ERR_RULE,
            "not found in Splunk",
        ),
        # Splunk itself is unwell -- says nothing about the detection.
        (
            lambda: FakeSession(["DONE"], dispatch=FakeResponse(503, {}, "unavailable")),
            ERR_UNMEASURED,
            "503",
        ),
        (
            lambda: FakeSession(["DONE"], dispatch=FakeResponse(201, {})),
            ERR_UNMEASURED,
            "No SID",
        ),
        (
            lambda: FakeSession(["DONE"], dispatch=FakeResponse(201, None, "<html>")),
            ERR_UNMEASURED,
            "Non-JSON",
        ),
    ],
)
def test_error_routes_declare_their_kind(session_factory, expected_kind, expected_fragment):
    events, error, kind = dispatch(session_factory())
    assert events == []
    assert kind == expected_kind
    assert expected_fragment in error


def test_error_kind_is_set_exactly_when_there_is_an_error():
    """The contract pass_fail_eval.py relies on: kind and message travel
    together, so a caller can never see one without the other."""
    for session in (
        FakeSession(["DONE"], {"results": []}),
        FakeSession(["RUNNING"]),
        FakeSession(["FAILED"]),
    ):
        _events, error, kind = dispatch(session)
        assert (error is None) == (kind is None)
