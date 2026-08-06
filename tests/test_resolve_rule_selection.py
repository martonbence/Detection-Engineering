"""Resolving a hand-typed rule selection from a manual run.

GitHub Actions has no multi-select input, so re-running specific rules is a free
text field. That trades a dropdown's safety for typos, which is why almost all
of these tests are about the failure path: an unknown id must stop the run and
say what the valid ones are, and must never let a partial selection through --
a subset that runs looks like the request was honoured.
"""

import pytest
from resolve_rule_selection import available, main, resolve_one, tokenize


@pytest.fixture
def rules_dir(tmp_path):
    d = tmp_path / "rules" / "sigma"
    d.mkdir(parents=True)
    for name in (
        "DETECT-2026-0001_Alpha.yml",
        "DETECT-2026-0002_Beta-With-Dashes.yml",
        "DETECT-2026-0003_Gamma.yaml",
    ):
        (d / name).write_text("title: x\n", encoding="utf-8")
    return d


def run(rules_dir, selection):
    return main(["--rules-dir", str(rules_dir), selection])


# --- tokenizing ---------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("A B", ["A", "B"]),
        ("A,B", ["A", "B"]),
        ("A, B", ["A", "B"]),
        ("  A ,, B  ", ["A", "B"]),
        ("A\nB", ["A", "B"]),
        ("", []),
        ("   ", []),
    ],
)
def test_tokenize_accepts_whatever_separator_someone_typed(raw, expected):
    assert tokenize(raw) == expected


# --- resolving a single token -------------------------------------------------


def test_a_detect_id_resolves(rules_dir):
    by_id = available(rules_dir)

    assert resolve_one("DETECT-2026-0001", rules_dir, by_id).name == "DETECT-2026-0001_Alpha.yml"


def test_case_does_not_lose_a_run(rules_dir):
    by_id = available(rules_dir)

    assert resolve_one("detect-2026-0001", rules_dir, by_id) is not None


def test_a_bare_filename_resolves(rules_dir):
    by_id = available(rules_dir)

    assert resolve_one("DETECT-2026-0001_Alpha.yml", rules_dir, by_id) is not None
    assert resolve_one("DETECT-2026-0001_Alpha", rules_dir, by_id) is not None


def test_a_yaml_extension_resolves_too(rules_dir):
    by_id = available(rules_dir)

    assert resolve_one("DETECT-2026-0003", rules_dir, by_id).suffix == ".yaml"


def test_quotes_someone_pasted_are_stripped(rules_dir):
    by_id = available(rules_dir)

    assert resolve_one('"DETECT-2026-0001"', rules_dir, by_id) is not None


def test_an_unknown_token_resolves_to_nothing(rules_dir):
    assert resolve_one("DETECT-2026-9999", rules_dir, available(rules_dir)) is None


def test_a_detect_id_prefix_is_not_a_match(rules_dir):
    """`DETECT-2026-000` must not quietly select `DETECT-2026-0001`."""
    assert resolve_one("DETECT-2026-000", rules_dir, available(rules_dir)) is None


# --- the CLI ------------------------------------------------------------------


def test_several_rules_resolve_to_several_paths(rules_dir, capsys):
    assert run(rules_dir, "DETECT-2026-0001, DETECT-2026-0002") == 0

    paths = [line for line in capsys.readouterr().out.splitlines() if line.strip()]
    assert len(paths) == 2
    assert all(p.endswith((".yml", ".yaml")) for p in paths)


def test_naming_one_rule_twice_runs_it_once(rules_dir, capsys):
    """A duplicate would be converted and attacked twice for one request."""
    assert run(rules_dir, "DETECT-2026-0001 DETECT-2026-0001") == 0

    assert len([line for line in capsys.readouterr().out.splitlines() if line.strip()]) == 1


def test_an_unknown_id_fails_the_run(rules_dir):
    assert run(rules_dir, "DETECT-2026-9999") == 1


def test_an_unknown_id_lists_every_valid_one(rules_dir, capsys):
    """This is the information a dropdown would have shown up front."""
    run(rules_dir, "DETECT-2026-9999")

    err = capsys.readouterr().err
    assert "DETECT-2026-0001" in err
    assert "DETECT-2026-0002" in err
    assert "DETECT-2026-0003" in err


def test_one_bad_token_discards_the_whole_selection(rules_dir, capsys):
    """A partial run would look like the request was honoured. It was not."""
    assert run(rules_dir, "DETECT-2026-0001 DETECT-2026-9999") == 1

    assert capsys.readouterr().out.strip() == ""


def test_an_empty_selection_is_a_failure_not_an_empty_run(rules_dir):
    """Reaching this script at all means rules were asked for."""
    assert run(rules_dir, "   ") == 1


def test_a_missing_rules_directory_is_a_setup_failure(tmp_path):
    assert main(["--rules-dir", str(tmp_path / "nope"), "DETECT-2026-0001"]) == 2


def test_diagnostics_stay_off_stdout(rules_dir, capsys):
    """The workflow reads stdout straight into an array."""
    run(rules_dir, "DETECT-2026-0001")

    captured = capsys.readouterr()
    assert captured.out.strip().endswith("DETECT-2026-0001_Alpha.yml")
    assert "Selected" in captured.err


# --- against the real repo ----------------------------------------------------


def test_a_real_detect_id_resolves_in_this_repo(capsys):
    assert main(["DETECT-2026-0012"]) == 0
    assert "DETECT-2026-0012" in capsys.readouterr().out
