"""Version-bump discipline check (register item 3.5, schema/discipline half).

The duplication half (scripts/lib/rule_version.py) is tested separately and is
untouched here. What this module guards is the newer, independent question:
did a rule's version: move when its detection-relevant content did?

`load_old_rule` shells out to `git show <ref>:<path>` -- these tests avoid a
real git fixture the way test_select_unverified.py avoids one for
select_unverified.git_version, by monkeypatching the seam (`load_old_rule`
itself) rather than building a throwaway repo. `main()`'s exit-code contract
and per-field behaviour are exercised end to end against real files on disk
(the "new" side always comes from load_rule(path), which reads the
filesystem); only the "old" side is faked.
"""

from __future__ import annotations

import json

import pytest
import yaml
from check_version_bump import logic_diff, main, raw_query, version_of

BASE_RULE = {
    "detect_id": "DETECT-2026-0001",
    "version": "1.2",
    "logsource": {
        "product_category": "os", "product": "windows", "service": "sysmon", "event_type": "process_creation",
    },
    "detection": {"selection": {"Image|endswith": "\\foo.exe"}, "condition": "selection"},
    "description": "Original description.",
    "custom": {"splunk": {"index": "sysmon"}},
}


def rule_file(tmp_path, data, name="r.yml"):
    path = tmp_path / name
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


# --- pure helpers -------------------------------------------------------------


def test_raw_query_reads_the_nested_field():
    data = {"custom": {"splunk": {"raw_query": "index=foo"}}}
    assert raw_query(data) == "index=foo"


def test_raw_query_is_none_when_absent_or_malformed():
    assert raw_query({}) is None
    assert raw_query({"custom": {}}) is None
    assert raw_query({"custom": {"splunk": "not a dict"}}) is None


def test_version_of_strips_and_defaults_to_empty():
    assert version_of({"version": " 1.4 "}) == "1.4"
    assert version_of({}) == ""


def test_logic_diff_empty_when_nothing_relevant_changed():
    old = dict(BASE_RULE)
    new = {**BASE_RULE, "description": "Reworded, still the same detection."}
    assert logic_diff(old, new) == []


def test_logic_diff_catches_detection_change():
    old = dict(BASE_RULE)
    new = {**BASE_RULE, "detection": {"selection": {"Image|endswith": "\\bar.exe"}, "condition": "selection"}}
    assert logic_diff(old, new) == ["detection"]


def test_logic_diff_catches_logsource_change():
    old = dict(BASE_RULE)
    new = {**BASE_RULE, "logsource": {**BASE_RULE["logsource"], "service": "security"}}
    assert logic_diff(old, new) == ["logsource"]


def test_logic_diff_catches_raw_query_change_even_though_its_not_a_top_level_field():
    """The one field this check adds beyond detection:/logsource: -- raw_query
    rules bypass the Sigma->SPL converter entirely, so their real logic lives
    here, not in the (placeholder) detection: block."""
    old = {**BASE_RULE, "custom": {"splunk": {"raw_query": "index=foo | table _time"}}}
    new = {**BASE_RULE, "custom": {"splunk": {"raw_query": "index=foo | table _time,User"}}}
    assert logic_diff(old, new) == ["custom.splunk.raw_query"]


def test_logic_diff_ignores_falsepositives_references_and_description():
    old = {**BASE_RULE, "falsepositives": ["a"], "references": ["https://a"], "description": "old"}
    new = {**BASE_RULE, "falsepositives": ["a", "b"], "references": ["https://a", "https://b"], "description": "new"}
    assert logic_diff(old, new) == []


def test_logic_diff_can_report_more_than_one_field():
    old = dict(BASE_RULE)
    new = {
        **BASE_RULE,
        "detection": {"selection": {"Image|endswith": "\\bar.exe"}, "condition": "selection"},
        "logsource": {**BASE_RULE["logsource"], "service": "security"},
    }
    assert set(logic_diff(old, new)) == {"detection", "logsource"}


# --- main(), the seam faked -----------------------------------------------


@pytest.fixture
def fake_old(monkeypatch):
    """Stand in for git show <base-ref>:<path> -- the tests never touch git."""
    table: dict[str, dict | None] = {}

    def _load(path, base_ref, repo_root, yaml_module):  # noqa: ARG001 - matches real signature
        return table.get(str(path))

    import check_version_bump

    monkeypatch.setattr(check_version_bump, "load_old_rule", _load)
    return table


def test_new_rule_with_no_prior_version_is_skipped_not_failed(tmp_path, fake_old, capsys):
    path = rule_file(tmp_path, BASE_RULE)
    # table has no entry for this path -> load_old_rule returns None

    rc = main(["--base-ref", "deadbeef", str(path)])

    assert rc == 0
    out = capsys.readouterr().out
    assert "[NEW]" in out
    assert "Skipped:  1" in out


def test_no_logic_change_passes_regardless_of_version(tmp_path, fake_old):
    new = {**BASE_RULE, "description": "Reworded."}
    path = rule_file(tmp_path, new)
    fake_old[str(path)] = dict(BASE_RULE)  # same version, same detection/logsource

    assert main(["--base-ref", "abc123", str(path)]) == 0


def test_logic_change_without_bump_fails(tmp_path, fake_old, capsys):
    new = {**BASE_RULE, "detection": {"selection": {"Image|endswith": "\\bar.exe"}, "condition": "selection"}}
    path = rule_file(tmp_path, new)
    fake_old[str(path)] = dict(BASE_RULE)  # version unchanged: "1.2"

    rc = main(["--base-ref", "abc123", str(path)])

    assert rc == 1
    out = capsys.readouterr().out
    assert "[MISSING-BUMP]" in out
    assert "::error" in out


def test_logic_change_with_bump_passes(tmp_path, fake_old):
    new = {
        **BASE_RULE,
        "version": "1.3",
        "detection": {"selection": {"Image|endswith": "\\bar.exe"}, "condition": "selection"},
    }
    path = rule_file(tmp_path, new)
    fake_old[str(path)] = dict(BASE_RULE)

    assert main(["--base-ref", "abc123", str(path)]) == 0


def test_raw_query_change_without_bump_fails(tmp_path, fake_old, capsys):
    old = {**BASE_RULE, "custom": {"splunk": {"raw_query": "index=foo"}}}
    new = {**BASE_RULE, "custom": {"splunk": {"raw_query": "index=foo | table User"}}}
    path = rule_file(tmp_path, new)
    fake_old[str(path)] = old

    rc = main(["--base-ref", "abc123", str(path)])

    assert rc == 1
    assert "custom.splunk.raw_query" in capsys.readouterr().out


def test_mixed_batch_reports_only_the_offending_rule(tmp_path, fake_old, capsys):
    clean_path = rule_file(tmp_path, {**BASE_RULE, "description": "reworded"}, name="clean.yml")
    fake_old[str(clean_path)] = dict(BASE_RULE)

    bad_new = {**BASE_RULE, "logsource": {**BASE_RULE["logsource"], "service": "security"}}
    bad_path = rule_file(tmp_path, bad_new, name="bad.yml")
    fake_old[str(bad_path)] = dict(BASE_RULE)

    rc = main(["--base-ref", "abc123", str(clean_path), str(bad_path)])

    assert rc == 1
    out = capsys.readouterr().out
    assert "clean.yml" in out and "[OK]" in out
    assert "bad.yml" in out and "[MISSING-BUMP]" in out


def test_no_rules_given_is_a_clean_no_op(capsys):
    assert main(["--base-ref", "abc123"]) == 0


def test_step_summary_written_only_on_findings(tmp_path, fake_old, monkeypatch):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))

    bad_new = {**BASE_RULE, "detection": {"selection": {"Image|endswith": "\\bar.exe"}, "condition": "selection"}}
    path = rule_file(tmp_path, bad_new, name="bad.yml")
    fake_old[str(path)] = dict(BASE_RULE)

    main(["--base-ref", "abc123", str(path)])

    text = summary.read_text(encoding="utf-8")
    assert "Missing version bump" in text
    assert "DETECT-2026-0001" in text


def test_step_summary_not_written_when_clean(tmp_path, fake_old, monkeypatch):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))

    path = rule_file(tmp_path, dict(BASE_RULE), name="clean.yml")
    fake_old[str(path)] = dict(BASE_RULE)

    main(["--base-ref", "abc123", str(path)])

    assert not summary.exists()
