"""Schema-gate for every Sigma rule (`scripts/validate/validate_sigma.py`),
the hard CI gate every rule -- hand-written or new_rule.py-scaffolded -- has
to clear before anything downstream (convert, deploy) touches it.

Nothing in `tests/` called this module before. `main()` reads argv itself
via `parse_args()` rather than taking a list, so these tests drive it the way
the CI step does: by setting `sys.argv` and calling `main()` with no
arguments.

Exit codes under test (from the module's own header):
    0 = all valid
    1 = one or more rules invalid
    2 = validator setup failure (missing schema, unreadable, etc.)
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml
from validate_sigma import main

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA = REPO_ROOT / "docs" / "schemas" / "sigma_schema.json"


def minimal_valid_rule() -> dict:
    """A synthetic rule, not one of the repo's real ones -- every required
    field present, every constraint satisfied, `custom.testing.enabled`
    false so the atomics/custom conditional requirement stays out of scope."""
    return {
        "title": "Synthetic Valid Test Rule",
        "detect_id": "DETECT-2026-0001",
        "status": "experimental",
        "description": "A synthetic rule used only to exercise schema validation.",
        "references": ["https://example.com/reference"],
        "author": "Test Author",
        "date": "2026-01-01",
        "modified": "2026-01-01",
        "version": "1.0",
        "tags": ["attack.execution", "attack.t1059.001"],
        "logsource": {
            "product_category": "os",
            "product": "windows",
            "service": "sysmon",
            "event_type": "process_creation",
        },
        "detection": {"selection": {"Image|endswith": "\\cmd.exe"}, "condition": "selection"},
        "fields": ["_time"],
        "falsepositives": ["Legitimate admin tooling"],
        "level": "medium",
        "custom": {
            "splunk": {
                "index": "main",
                "mode": "alert",
                "cron": "*/5 * * * *",
                "earliest": "-5m",
                "latest": "now",
                "severity": "medium",
            },
            "testing": {"enabled": False, "type": "atomic"},
        },
    }


def write_rule(tmp_path, data, name="rule.yml"):
    path = tmp_path / name
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def run(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["validate_sigma.py", *argv])
    return main()


# --- setup failures (exit 2) --------------------------------------------------


def test_missing_schema_is_a_setup_failure(tmp_path, monkeypatch, capsys):
    r = write_rule(tmp_path, minimal_valid_rule())

    rc = run(monkeypatch, ["--schema", str(tmp_path / "nope.json"), str(r)])

    assert rc == 2
    assert "Schema not found" in capsys.readouterr().err


# --- happy path (exit 0) ------------------------------------------------------


def test_a_minimal_valid_synthetic_rule_passes(tmp_path, monkeypatch, capsys):
    assert SCHEMA.exists()
    r = write_rule(tmp_path, minimal_valid_rule())

    rc = run(monkeypatch, ["--schema", str(SCHEMA), str(r)])

    assert rc == 0
    out = capsys.readouterr().out
    assert f"[OK] {r}" in out
    assert "OK:        1" in out
    assert "INVALID:   0" in out


# --- invalid rules (exit 1) ---------------------------------------------------


def test_a_rule_missing_a_required_field_fails_and_names_it(tmp_path, monkeypatch, capsys):
    data = minimal_valid_rule()
    del data["author"]
    r = write_rule(tmp_path, data)

    rc = run(monkeypatch, ["--schema", str(SCHEMA), str(r)])

    assert rc == 1
    out = capsys.readouterr().out
    assert f"[INVALID] {r}" in out
    assert "author" in out


def test_a_description_below_minlength_fails_and_names_the_field(tmp_path, monkeypatch, capsys):
    data = minimal_valid_rule()
    data["description"] = "short"  # schema requires minLength 10
    r = write_rule(tmp_path, data)

    rc = run(monkeypatch, ["--schema", str(SCHEMA), str(r)])

    assert rc == 1
    out = capsys.readouterr().out
    assert f"[INVALID] {r}" in out
    assert "/description" in out


def test_a_rule_with_no_attack_technique_tag_fails(tmp_path, monkeypatch, capsys):
    """The schema requires at least one attack.T#### / attack.t####.### tag --
    tactic-only tagging is not enough."""
    data = minimal_valid_rule()
    data["tags"] = ["attack.execution"]
    r = write_rule(tmp_path, data)

    rc = run(monkeypatch, ["--schema", str(SCHEMA), str(r)])

    assert rc == 1


def test_empty_yaml_file_is_reported_invalid_not_crashed_on(tmp_path, monkeypatch, capsys):
    r = tmp_path / "empty.yml"
    r.write_text("", encoding="utf-8")

    rc = run(monkeypatch, ["--schema", str(SCHEMA), str(r)])

    assert rc == 1
    assert "empty YAML" in capsys.readouterr().out


def test_mixed_batch_is_invalid_overall_and_reports_both(tmp_path, monkeypatch, capsys):
    good = write_rule(tmp_path, minimal_valid_rule(), name="good.yml")
    bad_data = minimal_valid_rule()
    del bad_data["status"]
    bad = write_rule(tmp_path, bad_data, name="bad.yml")

    rc = run(monkeypatch, ["--schema", str(SCHEMA), str(good), str(bad)])

    assert rc == 1
    out = capsys.readouterr().out
    assert f"[OK] {good}" in out
    assert f"[INVALID] {bad}" in out
    assert "Validated: 2" in out
    assert "OK:        1" in out
    assert "INVALID:   1" in out


# --- the committed schema, as a sanity check on the fixture itself -----------


def test_the_repo_schema_is_present_and_is_valid_json():
    import json

    assert SCHEMA.exists(), f"expected schema at {SCHEMA}"
    json.loads(SCHEMA.read_text(encoding="utf-8"))
