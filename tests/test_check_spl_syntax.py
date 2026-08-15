"""The `search` prefix `check_query()` sends to `search/v2/parser` (item 4.2
live-bug follow-up, 2026-08-15).

Item 4.2 closed 2026-08-11 verified only against mocked Splunk responses --
`LAB_ONLINE` had been false for weeks, so this script had never actually hit a
real Splunk until workflow run 31896204938. That run failed every rule with
the identical `Unknown search command 'index'.`: this repo's committed .spl
files are bare (`index=sysmon ...`), which is exactly what the search bar and
the `saved/searches` endpoint both expect -- they auto-prepend `search` for a
query that does not already open with `|` or an explicit generating command
-- but `search/v2/parser` does not do that auto-prepending, so it tried to
parse `index` itself as a command name.

These tests are against `ensure_search_prefix()` directly (the real forms
found by inspecting all 28 current .spl files under rules/splunk/, plus the
generating-command case `_inject_index_prefix()` guarantees never needs one)
and against `check_query()` end to end, so a regression that reintroduces the
bare query in the actual POST body -- not just in the helper -- is caught.
"""

import check_spl_syntax as c


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text="{}"):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is not None:
            return self._payload
        return {}


class RecordingSession:
    """Captures the POST body `check_query()` actually sends, and returns a
    canned response -- standing in for a real Splunk `search/v2/parser`."""

    def __init__(self, response=None):
        self.response = response or FakeResponse(200)
        self.last_data = None

    def post(self, url, data=None, timeout=None):
        self.last_data = data
        self.url = url
        return self.response


# --- ensure_search_prefix(): the real shapes this repo's .spl files take ----


def test_a_bare_index_query_gets_search_prepended():
    """The form 27 of the 28 current rules take -- and exactly what tripped
    workflow run 31896204938."""
    q = 'index=sysmon Image="*\\\\tasklist.exe" CommandLine="*qwinsta*"'
    assert c.ensure_search_prefix(q) == f"search {q}"


def test_a_query_already_starting_with_search_is_left_alone():
    """DETECT-2026-0007's shape: `search index=... | rex ... | search ...`."""
    q = 'search index=sysmon | rex field=CommandLine "foo"'
    assert c.ensure_search_prefix(q) == q


def test_search_keyword_match_is_case_insensitive():
    q = 'SEARCH index=sysmon CommandLine="*x*"'
    assert c.ensure_search_prefix(q) == q


def test_a_leading_pipe_is_left_alone():
    """A true generating command (`| tstats`, `| inputlookup`, ...) is a
    complete pipeline on its own; `search | tstats ...` is not valid SPL.
    `_inject_index_prefix()` in sigma_to_spl.py guarantees any leading `|`
    left in a committed .spl belongs to this case, not a bare `| rex ...`
    opener (which gets `search index=<idx>` written in front of it at
    conversion time instead)."""
    q = "| tstats count from datamodel=Endpoint.Processes"
    assert c.ensure_search_prefix(q) == q


def test_a_field_that_merely_starts_with_search_is_not_mistaken_for_the_keyword():
    """`search\\s` requires the keyword to stand alone -- a field named
    e.g. `searchterm=...` must still get prefixed."""
    q = 'searchterm="abc"'
    assert c.ensure_search_prefix(q) == f"search {q}"


def test_leading_and_trailing_whitespace_is_stripped():
    assert c.ensure_search_prefix("  index=sysmon x=1  ") == "search index=sysmon x=1"


def test_empty_query_is_returned_unchanged():
    assert c.ensure_search_prefix("") == ""
    assert c.ensure_search_prefix("   ") == ""


# --- check_query(): the prefix actually reaches the POST body ---------------


def test_check_query_sends_a_prefixed_bare_index_query():
    session = RecordingSession()

    ok, detail = c.check_query(session, "https://splunk.example:8089", "index=sysmon x=1")

    assert ok is True
    assert detail == ""
    assert session.last_data["q"] == "search index=sysmon x=1"


def test_check_query_does_not_double_prefix_a_search_query():
    session = RecordingSession()

    c.check_query(session, "https://splunk.example:8089", "search index=sysmon x=1")

    assert session.last_data["q"] == "search index=sysmon x=1"


def test_check_query_leaves_a_generating_command_query_unprefixed():
    session = RecordingSession()

    c.check_query(session, "https://splunk.example:8089", "| tstats count from datamodel=Endpoint")

    assert session.last_data["q"] == "| tstats count from datamodel=Endpoint"


def test_check_query_reports_a_real_parser_rejection():
    """The exact failure mode this bug produced: a bare query rejected with
    'Unknown search command'. Reproduced here to prove that a query which
    genuinely fails to parse is still reported as a failure after the fix --
    the prefix must not paper over real syntax errors."""
    session = RecordingSession(
        response=FakeResponse(
            400,
            payload={"messages": [{"type": "FATAL", "text": "Unknown search command 'bogus'."}]},
        )
    )

    ok, detail = c.check_query(session, "https://splunk.example:8089", "index=sysmon | bogus x=1")

    assert ok is False
    assert "Unknown search command" in detail


def test_check_query_still_posts_to_the_v2_parser_endpoint():
    session = RecordingSession()

    c.check_query(session, "https://splunk.example:8089", "index=sysmon x=1")

    assert session.url == "https://splunk.example:8089/services/search/v2/parser"
    assert session.last_data["parse_only"] == "true"
