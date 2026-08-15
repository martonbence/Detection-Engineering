"""Verdict logic in pass_fail_eval.evaluate().

The distinction these tests pin down is the one that register item 1.5 was
about: a query that could not run is NOT a detection that did not fire. The
two used to collapse into FAIL, which manufactured confirmed negatives out of
missing data.
"""

import pytest
from pass_fail_eval import FAIL, NOT_VERIFIED, PASS, evaluate

MIN_PASS = 1
MAX_PASS = 10


@pytest.mark.parametrize(
    "event_count, error, error_kind, expected",
    [
        # --- no error: the count alone decides -------------------------------
        (3, None, None, PASS),
        (MIN_PASS, None, None, PASS),
        (MAX_PASS, None, None, PASS),
        (0, None, None, FAIL),               # detection did not fire
        (MAX_PASS + 1, None, None, FAIL),    # too noisy to call a pass
        # --- "we could not measure" -> NOT_VERIFIED --------------------------
        (0, "Search did not finish within 120s", "unmeasured", NOT_VERIFIED),
        (0, "Network error fetching results: boom", "unmeasured", NOT_VERIFIED),
        (0, "Non-JSON results response: <html>", "unmeasured", NOT_VERIFIED),
        # --- "the rule/deployment is wrong" -> stays FAIL --------------------
        (0, "Saved search not found in Splunk: 'x'", "rule_error", FAIL),
        (0, "Search job failed (SID=1)", "rule_error", FAIL),
        # --- anything unrecognised must NOT soften ---------------------------
        # Result files written before error_kind existed have no kind at all;
        # they have to keep behaving exactly as they did. And an unknown kind
        # is not a licence to downgrade a failure -- unfamiliar input should
        # never be able to talk its way out of one.
        (0, "some older error", None, FAIL),
        (0, "some error", "nonsense", FAIL),
        (0, "some error", "", FAIL),
    ],
)
def test_verdict(event_count, error, error_kind, expected):
    verdict, reason = evaluate(event_count, error, MIN_PASS, MAX_PASS, error_kind)
    assert verdict == expected
    assert reason  # every verdict must come with a human-readable why


def test_unmeasured_reason_is_not_phrased_as_a_query_failure():
    """The reason text ends up in the run summary and the rule browser, so the
    wording carries the meaning: 'could not measure' rather than 'query error'."""
    verdict, reason = evaluate(0, "Search did not finish", MIN_PASS, MAX_PASS, "unmeasured")
    assert verdict == NOT_VERIFIED
    assert "Could not measure" in reason


def test_error_takes_precedence_over_a_healthy_looking_count():
    """A partial result set can look like a pass. If the query errored, the
    count is not evidence of anything and must not be read as one."""
    verdict, _ = evaluate(5, "Search did not finish", MIN_PASS, MAX_PASS, "unmeasured")
    assert verdict == NOT_VERIFIED
