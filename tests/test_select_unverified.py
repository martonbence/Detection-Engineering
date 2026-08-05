"""Choosing which rules a manual run should process (register item 2.21).

A push has a before..after diff; a manual run does not. The baseline used
instead is the committed result.json, which records the rule_version it was
measured against -- so "needs a run" means no result, or a result belonging to
an older version of the rule.

The bias throughout is to select: a needless re-run costs lab time, a wrong skip
leaves a rule everyone believes was verified and was not.
"""

import json
import subprocess

import pytest
import yaml

import select_unverified
from select_unverified import classify, main, verified_version


def rule(detect_id="DETECT-2026-0001", status="test"):
    return {"detect_id": detect_id, "status": status, "title": "T"}


def write_result(results_dir, detect_id, rule_version="1.0", verdict="PASS"):
    d = results_dir / detect_id
    d.mkdir(parents=True, exist_ok=True)
    payload = {"detect_id": detect_id, "verdict": verdict}
    if rule_version is not None:
        payload["rule_version"] = rule_version
    (d / "result.json").write_text(json.dumps(payload), encoding="utf-8")
    return d


@pytest.fixture
def at_version(monkeypatch):
    """Pins what the git-derived current version is, so tests need no repo."""

    def _set(version):
        monkeypatch.setattr(select_unverified, "git_version", lambda _p: version)

    return _set


# --- the decision ------------------------------------------------------------


def test_a_rule_verified_at_its_current_version_is_skipped(tmp_path, at_version):
    at_version("1.4")
    write_result(tmp_path, "DETECT-2026-0001", rule_version="1.4")

    entry = classify(tmp_path / "r.yml", rule(), tmp_path)

    assert entry["select"] is False


def test_a_rule_verified_at_an_older_version_is_selected(tmp_path, at_version):
    """The case this exists for: edited while the lab was off."""
    at_version("1.5")
    write_result(tmp_path, "DETECT-2026-0001", rule_version="1.4")

    entry = classify(tmp_path / "r.yml", rule(), tmp_path)

    assert entry["select"] is True
    assert entry["reason"] == "verified at 1.4, now 1.5"


def test_a_rule_that_was_never_verified_is_selected(tmp_path, at_version):
    """A brand new rule added while the lab was off has no result at all."""
    at_version("1.0")

    entry = classify(tmp_path / "r.yml", rule(), tmp_path)

    assert entry["select"] is True
    assert entry["reason"] == "never verified"


def test_a_result_with_no_rule_version_is_selected(tmp_path, at_version):
    """It cannot prove which version it measured, so it does not count."""
    at_version("1.2")
    write_result(tmp_path, "DETECT-2026-0001", rule_version=None)

    assert classify(tmp_path / "r.yml", rule(), tmp_path)["select"] is True


def test_an_unknown_current_version_selects_rather_than_skips(tmp_path, at_version):
    """No git history (a shallow clone) must not read as "already verified"."""
    at_version("")
    write_result(tmp_path, "DETECT-2026-0001", rule_version="1.4")

    entry = classify(tmp_path / "r.yml", rule(), tmp_path)

    assert entry["select"] is True
    assert "version unknown" in entry["reason"]


def test_a_deprecated_rule_is_skipped(tmp_path, at_version):
    """Deprecated rules are not deployed, so measuring them measures nothing."""
    at_version("1.9")

    entry = classify(tmp_path / "r.yml", rule(status="deprecated"), tmp_path)

    assert entry["select"] is False
    assert entry["reason"] == "deprecated"


def test_a_rule_without_a_detect_id_is_selected(tmp_path, at_version):
    at_version("1.0")

    entry = classify(tmp_path / "r.yml", {"title": "no id"}, tmp_path)

    assert entry["select"] is True


def test_an_unreadable_rule_is_selected(tmp_path):
    entry = classify(tmp_path / "r.yml", None, tmp_path)

    assert entry["select"] is True
    assert entry["reason"] == "unreadable"


def test_a_failed_verification_still_counts_as_verified_at_that_version(tmp_path, at_version):
    """This selects work, it does not re-litigate verdicts -- a FAIL was measured."""
    at_version("1.4")
    write_result(tmp_path, "DETECT-2026-0001", rule_version="1.4", verdict="FAIL")

    assert classify(tmp_path / "r.yml", rule(), tmp_path)["select"] is False


# --- reading the result ------------------------------------------------------


def test_a_missing_result_reads_as_none(tmp_path):
    assert verified_version(tmp_path, "DETECT-2026-0001") is None


def test_corrupt_result_json_reads_as_none_rather_than_crashing(tmp_path):
    d = tmp_path / "DETECT-2026-0001"
    d.mkdir()
    (d / "result.json").write_text("{not json", encoding="utf-8")

    assert verified_version(tmp_path, "DETECT-2026-0001") is None


def test_a_numeric_rule_version_is_read_as_a_string(tmp_path):
    d = tmp_path / "DETECT-2026-0001"
    d.mkdir()
    (d / "result.json").write_text(json.dumps({"rule_version": 1.4}), encoding="utf-8")

    assert verified_version(tmp_path, "DETECT-2026-0001") == "1.4"


# --- the CLI -----------------------------------------------------------------


def _repo(tmp_path, rules):
    """A real git repo, because the version is a commit count."""
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=tmp_path, check=True)

    rules_dir = tmp_path / "rules" / "sigma"
    rules_dir.mkdir(parents=True)
    for name, data in rules.items():
        (rules_dir / name).write_text(yaml.safe_dump(data), encoding="utf-8")

    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "add rules"], cwd=tmp_path, check=True)
    return rules_dir


def test_cli_prints_only_the_selection_on_stdout(tmp_path, monkeypatch, capsys):
    """The workflow reads stdout straight into an array -- nothing else may land there."""
    rules_dir = _repo(tmp_path, {"a.yml": rule("DETECT-A"), "b.yml": rule("DETECT-B")})
    results = tmp_path / "outputs" / "results"
    write_result(results, "DETECT-A", rule_version="1.0")  # current: one commit
    monkeypatch.chdir(tmp_path)

    assert main(["--rules-dir", str(rules_dir), "--results-dir", str(results)]) == 0

    captured = capsys.readouterr()
    stdout_lines = [line for line in captured.out.splitlines() if line.strip()]
    assert len(stdout_lines) == 1
    assert stdout_lines[0].endswith("b.yml")
    assert "Examined 2 rule(s); 1 need a run." in captured.err


def test_cli_selects_nothing_when_everything_is_current(tmp_path, monkeypatch, capsys):
    rules_dir = _repo(tmp_path, {"a.yml": rule("DETECT-A")})
    results = tmp_path / "outputs" / "results"
    write_result(results, "DETECT-A", rule_version="1.0")
    monkeypatch.chdir(tmp_path)

    assert main(["--rules-dir", str(rules_dir), "--results-dir", str(results)]) == 0
    assert capsys.readouterr().out.strip() == ""


def test_cli_selects_a_rule_again_after_it_is_edited(tmp_path, monkeypatch, capsys):
    """One more commit on the rule means a new version, which the result predates."""
    rules_dir = _repo(tmp_path, {"a.yml": rule("DETECT-A")})
    results = tmp_path / "outputs" / "results"
    write_result(results, "DETECT-A", rule_version="1.0")
    monkeypatch.chdir(tmp_path)

    assert main(["--rules-dir", str(rules_dir), "--results-dir", str(results)]) == 0
    assert capsys.readouterr().out.strip() == ""

    (rules_dir / "a.yml").write_text(yaml.safe_dump(rule("DETECT-A") | {"level": "high"}), encoding="utf-8")
    subprocess.run(["git", "commit", "-qam", "edit"], cwd=tmp_path, check=True)

    assert main(["--rules-dir", str(rules_dir), "--results-dir", str(results)]) == 0
    assert capsys.readouterr().out.strip().endswith("a.yml")


def test_cli_reports_a_missing_rules_directory_as_a_setup_failure(tmp_path):
    assert main(["--rules-dir", str(tmp_path / "nope")]) == 2


def test_json_output_records_why_each_rule_was_or_was_not_selected(tmp_path, monkeypatch):
    rules_dir = _repo(tmp_path, {"a.yml": rule("DETECT-A"), "b.yml": rule("DETECT-B")})
    results = tmp_path / "outputs" / "results"
    write_result(results, "DETECT-A", rule_version="1.0")
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "sel.json"

    main(["--rules-dir", str(rules_dir), "--results-dir", str(results), "--json", str(out)])

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["examined"] == 2
    by_id = {e["detect_id"]: e for e in data["entries"]}
    assert by_id["DETECT-A"]["select"] is False
    assert by_id["DETECT-B"]["select"] is True


# Deliberately no test asserting the real repo is fully verified. It would be
# vacuous where it runs: ci_code_checks.yml checks out at the default depth 1,
# so `git log --follow` sees one commit, every rule reads as version 1.0, and
# the answer says more about the clone than about the rules. It would also
# report a false failure on any push that edits a rule and a script together --
# at that instant the rule genuinely is unverified, and the dev pipeline is
# about to fix that.
