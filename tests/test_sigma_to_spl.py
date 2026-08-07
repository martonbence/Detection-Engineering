"""Index-prefix handling in the converter (register item 2.9).

The generated SPL must always start with the index the Sigma rule declares --
except when the query opens with a generating command, where prefixing produces
`index=x | tstats ...`, which is not valid SPL at all. That case used to fall
through to the unconditional prefix.
"""

from sigma_to_spl import _inject_index_prefix

# --- the three cases that already worked ------------------------------------


def test_search_command_keeps_its_verb():
    assert _inject_index_prefix("search EventCode=4688", "sysmon") == "search index=sysmon EventCode=4688"


def test_existing_leading_index_is_replaced_with_the_sigma_one():
    """The rule's own `custom.splunk.index` wins over whatever the backend emitted."""
    assert _inject_index_prefix("index=main EventCode=4688", "sysmon") == "index=sysmon EventCode=4688"


def test_bare_query_gets_the_prefix():
    assert _inject_index_prefix("EventCode=4688", "sysmon") == "index=sysmon EventCode=4688"


# --- generating commands ----------------------------------------------------


def test_generating_command_is_left_alone_rather_than_made_invalid(capsys):
    """`index=sysmon | tstats ...` is not valid SPL -- this must not be produced."""
    query = "| tstats count where index=wineventlog by host"

    result = _inject_index_prefix(query, "sysmon")

    assert result == query
    assert not result.startswith("index=")


def test_generating_command_naming_its_own_index_is_not_warned_about(capsys):
    _inject_index_prefix("| tstats count where index=wineventlog by host", "sysmon")

    assert capsys.readouterr().err == ""


def test_generating_command_without_any_index_warns(capsys):
    """Nothing scopes this query -- it searches everything, and that should be said."""
    _inject_index_prefix("| tstats count by host", "sysmon")

    err = capsys.readouterr().err
    assert "could not be applied" in err
    assert "sysmon" in err


def test_inputlookup_is_not_treated_as_an_error():
    """A lookup legitimately touches no index; failing conversion here would be wrong."""
    query = "| inputlookup known_hosts.csv"

    assert _inject_index_prefix(query, "sysmon") == query


def test_leading_whitespace_before_the_pipe_is_still_a_generating_command():
    query = "   | tstats count where index=wineventlog by host"

    assert _inject_index_prefix(query, "sysmon") == query.strip()


# --- degenerate input -------------------------------------------------------


def test_empty_query_is_returned_untouched():
    assert _inject_index_prefix("", "sysmon") == ""


def test_missing_index_leaves_the_query_alone():
    assert _inject_index_prefix("EventCode=4688", "") == "EventCode=4688"
