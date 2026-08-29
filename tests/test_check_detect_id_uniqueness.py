"""detect_id collision gate (register item 4.5, backstop half; see
tests/test_new_rule.py for the scaffolder half).

Nothing in `tests/` called this module before. It is the actual defense
against two rules sharing a `detect_id` on the merged tree -- new_rule.py's
"next free id" computation only narrows that, it cannot close it (see the
module's own header comment) -- so a collision here silently overwrites one
rule's Splunk saved search with another's.

All fixtures are synthetic YAML written into `tmp_path`; `rules/sigma/` is
never read.
"""

from __future__ import annotations

import yaml
from check_detect_id_uniqueness import find_duplicates, main


def write_rule(tmp_path, detect_id, name):
    path = tmp_path / name
    path.write_text(
        yaml.safe_dump({"detect_id": detect_id, "title": name}), encoding="utf-8"
    )
    return path


# --- find_duplicates() ---------------------------------------------------


def test_two_rules_sharing_a_detect_id_are_reported_as_duplicates(tmp_path):
    a = write_rule(tmp_path, "DETECT-2026-0001", "a.yml")
    b = write_rule(tmp_path, "DETECT-2026-0001", "b.yml")

    dupes = find_duplicates(tmp_path)

    assert list(dupes.keys()) == ["DETECT-2026-0001"]
    assert sorted(dupes["DETECT-2026-0001"]) == sorted([a, b])


def test_two_rules_with_distinct_detect_ids_are_not_duplicates(tmp_path):
    write_rule(tmp_path, "DETECT-2026-0001", "a.yml")
    write_rule(tmp_path, "DETECT-2026-0002", "b.yml")

    assert find_duplicates(tmp_path) == {}


def test_a_malformed_rule_is_skipped_rather_than_double_reported(tmp_path, capsys):
    """validate_sigma.py owns malformed YAML; this checker should not crash
    or fabricate a finding for a file it cannot read."""
    bad = tmp_path / "bad.yml"
    bad.write_text("detect_id: [unclosed\n", encoding="utf-8")
    write_rule(tmp_path, "DETECT-2026-0001", "good.yml")

    dupes = find_duplicates(tmp_path)

    assert dupes == {}


def test_a_rule_with_no_detect_id_is_ignored_not_grouped_as_blank(tmp_path):
    path = tmp_path / "no_id.yml"
    path.write_text(yaml.safe_dump({"title": "no detect_id here"}), encoding="utf-8")
    write_rule(tmp_path, "DETECT-2026-0001", "a.yml")

    assert find_duplicates(tmp_path) == {}


# --- main() / CLI exit codes ----------------------------------------------


def test_cli_exits_zero_when_every_detect_id_is_unique(tmp_path, capsys):
    write_rule(tmp_path, "DETECT-2026-0001", "a.yml")
    write_rule(tmp_path, "DETECT-2026-0002", "b.yml")

    rc = main(["--rules-dir", str(tmp_path)])

    assert rc == 0
    assert "[OK] No duplicate detect_id" in capsys.readouterr().out


def test_cli_exits_nonzero_and_annotates_on_a_collision(tmp_path, capsys):
    write_rule(tmp_path, "DETECT-2026-0001", "a.yml")
    write_rule(tmp_path, "DETECT-2026-0001", "b.yml")

    rc = main(["--rules-dir", str(tmp_path)])

    assert rc == 1
    out = capsys.readouterr().out
    assert "[DUPLICATE] DETECT-2026-0001" in out
    assert "::error title=Duplicate detect_id::DETECT-2026-0001" in out


def test_cli_on_an_empty_directory_is_clean(tmp_path, capsys):
    rc = main(["--rules-dir", str(tmp_path)])

    assert rc == 0
