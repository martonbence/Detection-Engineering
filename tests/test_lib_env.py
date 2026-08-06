"""The shared environment helpers, and the failure policies they did not merge.

Register item 3.6. Four scripts each carried their own `env_bool` -- identical
down to the token tables -- and item 2.14 then copied a TLS announcement into
all four as well. Those are now one implementation each.

`env_required` is the part that only looked duplicated: it fails differently in
every consumer, and those differences are load-bearing. The deploy and the hit
check exit 1, the indexing wait exits 2 because a step that never started is a
setup failure rather than a verification result, and the reconcile raises
`ReconcileError` so `main()` can still tell "the comparison could not be
trusted" apart from a drift finding. Most of this file exists to prove those
four behaviours survived being wired through one function.
"""

import check_saved_search_hits
import deploy_spl_to_splunk as deploy
import pytest
import reconcile
import wait_for_indexing
from lib.env import MissingEnvVar, announce_tls_mode, env_bool, env_reader, env_required

VAR = "SPLUNK_VERIFY_TLS"


# --- the part that really was duplicated --------------------------------------


def test_every_consumer_now_shares_one_env_bool():
    """A local copy reappearing is the regression this file is here to catch."""
    shared = env_bool
    for module in (deploy, reconcile, wait_for_indexing, check_saved_search_hits):
        assert module.env_bool is shared, (
            f"{module.__name__} has its own env_bool again -- item 3.6 removed four of them"
        )


@pytest.mark.parametrize("raw", ["true", "TRUE", " True ", "1", "yes", "y", "on"])
def test_recognised_true_spellings(monkeypatch, raw):
    monkeypatch.setenv(VAR, raw)
    assert env_bool(VAR, default=False) is True


@pytest.mark.parametrize("raw", ["false", "FALSE", " False ", "0", "no", "n", "off"])
def test_recognised_false_spellings(monkeypatch, raw):
    monkeypatch.setenv(VAR, raw)
    assert env_bool(VAR, default=True) is False


@pytest.mark.parametrize("raw", ["", "   ", "maybe", "0.0", "none", "null"])
def test_anything_else_falls_through_to_the_default(monkeypatch, raw):
    """Unrecognised is not guessed at -- this is what makes 2.14 fail closed."""
    monkeypatch.setenv(VAR, raw)
    assert env_bool(VAR, default=True) is True
    assert env_bool(VAR, default=False) is False


# --- env_required's own contract ----------------------------------------------


@pytest.mark.parametrize("raw", ["", "   ", "\n"])
def test_blank_counts_as_missing(monkeypatch, raw):
    monkeypatch.setenv("SPLUNK_APP", raw)
    with pytest.raises(MissingEnvVar):
        env_required("SPLUNK_APP")


def test_unset_counts_as_missing(monkeypatch):
    monkeypatch.delenv("SPLUNK_APP", raising=False)
    with pytest.raises(MissingEnvVar):
        env_required("SPLUNK_APP")


def test_a_present_value_is_stripped(monkeypatch):
    """Whitespace would otherwise travel into a REST path segment."""
    monkeypatch.setenv("SPLUNK_APP", "  detection_engineering  ")
    assert env_required("SPLUNK_APP") == "detection_engineering"


def test_the_message_names_the_variable(monkeypatch):
    monkeypatch.delenv("SPLUNK_APP", raising=False)
    with pytest.raises(MissingEnvVar, match="SPLUNK_APP"):
        env_required("SPLUNK_APP")


# --- the policies that stayed with the callers --------------------------------


@pytest.mark.parametrize(
    "module,expected_code",
    [
        pytest.param(deploy, 1, id="deploy"),
        pytest.param(check_saved_search_hits, 1, id="check_saved_search_hits"),
        pytest.param(wait_for_indexing, 2, id="wait_for_indexing"),
    ],
)
def test_each_script_keeps_its_own_exit_code(monkeypatch, module, expected_code):
    monkeypatch.delenv("SPLUNK_APP", raising=False)
    with pytest.raises(SystemExit) as excinfo:
        module.env_required("SPLUNK_APP")
    assert excinfo.value.code == expected_code


def test_reconcile_raises_rather_than_exiting(monkeypatch):
    """A SystemExit here would skip main()'s handler and lose the exit-2 meaning."""
    monkeypatch.delenv("SPLUNK_APP", raising=False)
    with pytest.raises(reconcile.ReconcileError, match="SPLUNK_APP"):
        reconcile.env_required("SPLUNK_APP")


def test_a_policy_that_returns_instead_of_exiting_still_fails(monkeypatch):
    """No caller does this, but silently returning None would be far worse."""
    monkeypatch.delenv("SPLUNK_APP", raising=False)
    read = env_reader(lambda _msg: None)
    with pytest.raises(MissingEnvVar):
        read("SPLUNK_APP")


def test_a_bound_reader_passes_present_values_through(monkeypatch):
    monkeypatch.setenv("SPLUNK_APP", "detection_engineering")
    calls: list[str] = []
    read = env_reader(calls.append)
    assert read("SPLUNK_APP") == "detection_engineering"
    assert calls == []


# --- the announcement ---------------------------------------------------------


def test_verification_on_is_stated_plainly(capsys):
    announce_tls_mode(True)
    out = capsys.readouterr().out
    assert "TLS certificate verification: on." in out
    assert "::warning" not in out


def test_verification_off_is_an_annotation(capsys):
    """Item 2.14's point: the downgrade has to be visible, not merely logged."""
    announce_tls_mode(False)
    out = capsys.readouterr().out
    assert "::warning title=TLS verification disabled::" in out
    assert "NOT verified" in out
