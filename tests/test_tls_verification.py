"""TLS verification must never switch itself off (register item 2.14).

The defect was a division of labour that nobody could see. Every script had
already chosen the safe answer -- `env_bool("SPLUNK_VERIFY_TLS", default=True)`
-- and the workflow then overrode it one layer up with `|| 'false'`, so a
*missing* secret was translated into a positive instruction to skip certificate
checks. Nothing logged which mode a run was in, so the downgrade left no trace
in the job output.

Two things are guarded here, because fixing only one leaves the hole open:
the workflow must not reintroduce a fallback, and the scripts must keep failing
closed on any value they do not recognise.
"""

from pathlib import Path

import check_saved_search_hits
import deploy_spl_to_splunk as deploy
import pytest
import reconcile
import wait_for_indexing
import yaml
from test_deploy_report import FakeResponse, FakeSession, write_rule

# Derived here rather than imported from tests/conftest.py. `tests` is not a
# package -- there is no __init__.py, and pytest puts the *tests* directory on
# sys.path, not the repo root -- so `from tests.conftest import ...` only
# resolves under `python -m pytest`, which additionally prepends the working
# directory. ci_code_checks.yml runs bare `pytest`, where that import raises at
# collection time and takes the whole suite down with it, not just this file.
REPO_ROOT = Path(__file__).resolve().parent.parent

WORKFLOWS = (
    REPO_ROOT / ".github/workflows/ci_dev_workflow.yml",
    REPO_ROOT / ".github/workflows/ci_prod_workflow.yml",
)

# The one form the env value is allowed to take. Anything else -- most of all
# anything containing `||` -- lets the workflow decide a question the scripts
# have already answered.
#
# `vars.`, not `secrets.`, since 2026-08-07. Stored as a secret the value was
# `false`, and GitHub redacts a secret's value everywhere it appears in a log --
# so the word "false" vanished from every line of every job that had this in
# scope, including the 2.14 warning whose entire purpose is to print it. What
# this test guards is unchanged either way: exactly one expression, no `||`
# fallback deciding for an operator who said nothing.
EXPECTED = "${{ vars.SPLUNK_VERIFY_TLS }}"

# These four were separate implementations when this file was written, which is
# why it checks all of them rather than one. Register item 3.6 has since made
# them the same object from scripts/lib/env.py -- the parametrisation is kept
# because it is what would notice a local copy being reintroduced, and
# test_lib_env.py asserts the identity directly.
ENV_BOOLS = pytest.mark.parametrize(
    "env_bool",
    [
        pytest.param(deploy.env_bool, id="deploy"),
        pytest.param(reconcile.env_bool, id="reconcile"),
        pytest.param(wait_for_indexing.env_bool, id="wait_for_indexing"),
        pytest.param(check_saved_search_hits.env_bool, id="check_saved_search_hits"),
    ],
)


def tls_env_values():
    """Every SPLUNK_VERIFY_TLS assignment in a step `env:` block, with its location."""
    found = []
    for path in WORKFLOWS:
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job_name, job in (workflow.get("jobs") or {}).items():
            for step in job.get("steps") or []:
                env = step.get("env") or {}
                if "SPLUNK_VERIFY_TLS" in env:
                    where = f"{path.name}::{job_name}::{step.get('name', '<unnamed>')}"
                    found.append((where, env["SPLUNK_VERIFY_TLS"]))
    return found


# --- the workflow side -------------------------------------------------------


def test_the_guard_actually_finds_the_assignments():
    """A checker that silently matches nothing would pass forever.

    If the workflows stop setting SPLUNK_VERIFY_TLS in a step `env:` block --
    renamed job, restructured step, moved to job-level env -- that is a change
    this file must be taught about, not one it should sleep through.
    """
    assert len(tls_env_values()) == 5


@pytest.mark.parametrize("where,value", tls_env_values(), ids=lambda v: v if isinstance(v, str) else "")
def test_no_workflow_turns_verification_off_by_default(where, value):
    assert value == EXPECTED, (
        f"{where} sets SPLUNK_VERIFY_TLS to {value!r}. A fallback here decides, "
        f"for an operator who never said anything, that certificates go unchecked."
    )


def test_no_workflow_reintroduces_a_fallback_expression():
    """Stated separately from the equality check so the failure names the cause."""
    for where, value in tls_env_values():
        assert "||" not in value, f"{where} restores a default for a missing secret: {value!r}"


# --- the script side ---------------------------------------------------------


@ENV_BOOLS
@pytest.mark.parametrize("raw", ["", "   ", "\n"])
def test_an_empty_value_verifies(env_bool, monkeypatch, raw):
    """What an unset secret now renders to. This is the case the item is about."""
    monkeypatch.setenv("SPLUNK_VERIFY_TLS", raw)
    assert env_bool("SPLUNK_VERIFY_TLS", default=True) is True


@ENV_BOOLS
def test_an_absent_variable_verifies(env_bool, monkeypatch):
    monkeypatch.delenv("SPLUNK_VERIFY_TLS", raising=False)
    assert env_bool("SPLUNK_VERIFY_TLS", default=True) is True


@ENV_BOOLS
@pytest.mark.parametrize("raw", ["maybe", "off-ish", "0.0", "none", "null"])
def test_an_unrecognised_value_verifies(env_bool, monkeypatch, raw):
    """Fail closed on nonsense too -- a typo is not a decision to skip checks."""
    monkeypatch.setenv("SPLUNK_VERIFY_TLS", raw)
    assert env_bool("SPLUNK_VERIFY_TLS", default=True) is True


@ENV_BOOLS
@pytest.mark.parametrize("raw", ["false", "FALSE", " False ", "0", "no", "n", "off"])
def test_switching_it_off_still_works_when_said_explicitly(env_bool, monkeypatch, raw):
    """The lab's self-signed certificate is a real reason. It just has to be stated."""
    monkeypatch.setenv("SPLUNK_VERIFY_TLS", raw)
    assert env_bool("SPLUNK_VERIFY_TLS", default=True) is False


# --- the wiring, end to end --------------------------------------------------


@pytest.fixture
def splunk(monkeypatch):
    def _make(responses=None):
        session = FakeSession(responses)
        monkeypatch.setattr(deploy.requests, "Session", lambda: session)
        return session

    for key, value in {
        "SPLUNK_BASE_URL": "https://splunk.example:8089",
        "SPLUNK_USERNAME": "svc",
        "SPLUNK_PASSWORD": "pw",
        "SPLUNK_APP": "detection_app",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("SPLUNK_VERIFY_TLS", raising=False)
    return _make


def test_an_unset_secret_reaches_the_session_as_verification_on(tmp_path, splunk, capsys):
    """env_bool's default is worth nothing if it never lands on the session."""
    session = splunk()

    assert deploy.main([str(write_rule(tmp_path))]) == 0

    assert session.verify is True
    assert "TLS certificate verification: on." in capsys.readouterr().out


def test_turning_verification_off_is_announced(tmp_path, splunk, monkeypatch, capsys):
    """The silence was half the defect: an operator could not tell from the log."""
    monkeypatch.setenv("SPLUNK_VERIFY_TLS", "false")
    session = splunk()

    assert deploy.main([str(write_rule(tmp_path))]) == 0

    assert session.verify is False
    out = capsys.readouterr().out
    assert "::warning title=TLS verification disabled::" in out
    assert "NOT verified" in out


def test_a_missing_rule_still_deploys_with_verification_on(tmp_path, splunk):
    """Fail-closed must not change what the deploy does, only how it connects."""
    session = splunk({"update": FakeResponse(404), "create": FakeResponse(201)})

    assert deploy.main([str(write_rule(tmp_path))]) == 0

    assert session.verify is True
