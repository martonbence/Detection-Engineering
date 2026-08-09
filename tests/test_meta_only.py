"""--meta-only mode in the converter (register item 3.2).

The dev pipeline's bundle needs a .meta.json for every currently-committed
rule on every run, not just the ones actually changed -- but re-running full
conversion (the sigma-cli subprocess in run_sigma_convert()) on the unchanged
majority does not scale as the rule count grows past the current 27. This
mode regenerates only the sidecar, which build_meta_dict() can do from the
already-parsed rule dict alone, without touching the rule's .spl at all.
"""

import sys
from pathlib import Path

import sigma_to_spl

REPO_ROOT = Path(__file__).resolve().parent.parent

RULE_BODY = """
title: Test Rule
detect_id: DETECT-TEST-0001
status: test
description: A rule for --meta-only tests.
author: Test
date: 2026-01-01
logsource:
  product_category: os
  product: windows
  service: sysmon
  event_type: process_creation
detection:
  selection:
    Image|endswith: "\\\\cmd.exe"
  condition: selection
custom:
  splunk:
    index: sysmon
    mode: report
"""


def write_rule(tmp_path: Path) -> Path:
    rule_path = tmp_path / "DETECT-TEST-0001.yml"
    rule_path.write_text(RULE_BODY, encoding="utf-8")
    return rule_path


def run_main(argv: list[str], monkeypatch) -> int:
    monkeypatch.chdir(REPO_ROOT)
    monkeypatch.setattr(sys, "argv", ["sigma_to_spl.py", *argv])
    return sigma_to_spl.main()


def test_meta_only_leaves_existing_spl_byte_identical(tmp_path, monkeypatch):
    rule_path = write_rule(tmp_path)
    out_path = tmp_path / "DETECT-TEST-0001.spl"
    original_bytes = b"index=sysmon Image=\"*\\\\cmd.exe\" | table _time\n"
    out_path.write_bytes(original_bytes)

    exit_code = run_main(["--outdir", str(tmp_path), "--meta-only", str(rule_path)], monkeypatch)

    assert exit_code == 0
    assert out_path.read_bytes() == original_bytes


def test_meta_only_writes_a_fresh_sidecar(tmp_path, monkeypatch):
    rule_path = write_rule(tmp_path)
    out_path = tmp_path / "DETECT-TEST-0001.spl"
    out_path.write_text("index=sysmon Image=\"*\\\\cmd.exe\"\n", encoding="utf-8")

    exit_code = run_main(["--outdir", str(tmp_path), "--meta-only", str(rule_path)], monkeypatch)

    assert exit_code == 0
    meta_path = tmp_path / "DETECT-TEST-0001.meta.json"
    assert meta_path.exists()

    import json

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta["detect_id"] == "DETECT-TEST-0001"
    assert meta["index"] == "sysmon"
    assert meta["deploy_mode"] == "report"


def test_meta_only_fails_without_an_existing_spl(tmp_path, monkeypatch, capsys):
    rule_path = write_rule(tmp_path)

    exit_code = run_main(["--outdir", str(tmp_path), "--meta-only", str(rule_path)], monkeypatch)

    assert exit_code == 2
    assert not (tmp_path / "DETECT-TEST-0001.meta.json").exists()
    assert "requires an existing .spl" in capsys.readouterr().err


def test_meta_only_does_not_invoke_the_sigma_cli_subprocess(tmp_path, monkeypatch):
    """The whole point: this must be cheap enough to run on every rule, every time."""
    rule_path = write_rule(tmp_path)
    out_path = tmp_path / "DETECT-TEST-0001.spl"
    out_path.write_text("index=sysmon Image=\"*\\\\cmd.exe\"\n", encoding="utf-8")

    def fail_if_called(*args, **kwargs):
        raise AssertionError("run_sigma_convert() must not run in --meta-only mode")

    monkeypatch.setattr(sigma_to_spl, "run_sigma_convert", fail_if_called)

    exit_code = run_main(["--outdir", str(tmp_path), "--meta-only", str(rule_path)], monkeypatch)

    assert exit_code == 0
