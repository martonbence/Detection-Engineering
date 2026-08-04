"""Detection of rules whose test runner no CI job services (register item 2.17).

The failure this guards against is a quiet one: run_atomic.ps1 matches the
(tester type, runner) pair exactly, so a rule asking for a combination no job
sets is dropped with a log line and the job still exits 0.
"""

import json

import pytest
import yaml

from check_test_routing import check_rule, derive_matrix, main

# The three combinations the dev workflow actually services today.
MATRIX = {
    ("atomic", "windows-victim"): "atomic_verify",
    ("atomic", "windows-dc"): "atomic_verify_dc",
    ("emulation", "windows-victim"): "emulation_verify",
}


def rule(detect_id="DETECT-2026-0001", enabled=True, tester="atomic", runner="windows-victim"):
    testing = {"enabled": enabled, "type": tester}
    if runner is not None:
        testing["runner"] = runner
    return {"detect_id": detect_id, "custom": {"testing": testing}}


def write_rule(tmp_path, name="rule.yml", **kwargs):
    path = tmp_path / name
    path.write_text(yaml.safe_dump(rule(**kwargs)), encoding="utf-8")
    return path


# --- deriving the matrix from the workflow -----------------------------------


def test_matrix_comes_from_the_jobs_env_not_a_hardcoded_list():
    workflow = {
        "jobs": {
            "atomic_verify": {
                "steps": [{"env": {"ATOMIC_RUNNER": "windows-victim", "ATOMIC_TESTER_TYPE": "atomic"}}]
            },
            "emulation_verify": {
                "steps": [{"env": {"ATOMIC_RUNNER": "windows-victim", "ATOMIC_TESTER_TYPE": "emulation"}}]
            },
        }
    }

    matrix, unresolved = derive_matrix(workflow)

    assert matrix == {
        ("atomic", "windows-victim"): "atomic_verify",
        ("emulation", "windows-victim"): "emulation_verify",
    }
    assert unresolved == []


def test_job_level_env_counts_too():
    workflow = {
        "jobs": {
            "j": {
                "env": {"ATOMIC_RUNNER": "linux-victim"},
                "steps": [{"env": {"ATOMIC_TESTER_TYPE": "atomic"}}],
            }
        }
    }

    matrix, _ = derive_matrix(workflow)

    assert ("atomic", "linux-victim") in matrix


def test_a_step_setting_only_one_of_the_two_services_nothing():
    workflow = {"jobs": {"j": {"steps": [{"env": {"ATOMIC_RUNNER": "windows-victim"}}]}}}

    matrix, _ = derive_matrix(workflow)

    assert matrix == {}


def test_an_expression_valued_runner_is_reported_rather_than_silently_dropped():
    """A narrower matrix means false findings -- the reader has to be told."""
    workflow = {
        "jobs": {
            "j": {
                "steps": [
                    {"env": {"ATOMIC_RUNNER": "${{ matrix.runner }}", "ATOMIC_TESTER_TYPE": "atomic"}}
                ]
            }
        }
    }

    matrix, unresolved = derive_matrix(workflow)

    assert matrix == {}
    assert len(unresolved) == 1
    assert "matrix.runner" in unresolved[0]


# --- classifying a rule ------------------------------------------------------


def test_a_serviced_combination_is_not_a_finding(tmp_path):
    assert check_rule(tmp_path / "r.yml", rule(), MATRIX) is None


def test_emulation_on_the_domain_controller_is_flagged(tmp_path):
    """The combination named in the register: no job sets emulation + windows-dc."""
    finding = check_rule(tmp_path / "r.yml", rule(tester="emulation", runner="windows-dc"), MATRIX)

    assert finding is not None
    assert finding["reason"] == "unserviced"
    assert "windows-dc" in finding["message"]


def test_the_planned_linux_runner_is_flagged_while_no_job_exists(tmp_path):
    """`linux-victim` is deliberately in the schema before the VM exists."""
    finding = check_rule(tmp_path / "r.yml", rule(runner="linux-victim"), MATRIX)

    assert finding is not None
    assert finding["reason"] == "unserviced"


def test_adding_the_job_clears_the_finding_with_no_edit_to_the_checker(tmp_path):
    extended = {**MATRIX, ("atomic", "linux-victim"): "atomic_verify_linux"}

    assert check_rule(tmp_path / "r.yml", rule(runner="linux-victim"), extended) is None


def test_a_missing_runner_is_flagged_because_the_match_is_exact(tmp_path):
    """An unset runner is not "the default" -- every job's filter rejects it."""
    finding = check_rule(tmp_path / "r.yml", rule(runner=None), MATRIX)

    assert finding is not None
    assert finding["reason"] == "no_runner"


def test_disabled_testing_is_not_a_finding(tmp_path):
    assert check_rule(tmp_path / "r.yml", rule(enabled=False, runner="linux-victim"), MATRIX) is None


def test_the_runner_comparison_ignores_case(tmp_path):
    assert check_rule(tmp_path / "r.yml", rule(runner="Windows-Victim"), MATRIX) is None


def test_a_rule_without_a_custom_block_is_not_a_finding(tmp_path):
    assert check_rule(tmp_path / "r.yml", {"detect_id": "DETECT-2026-0002"}, MATRIX) is None


def test_a_null_custom_block_does_not_crash(tmp_path):
    assert check_rule(tmp_path / "r.yml", {"custom": None}, MATRIX) is None


# --- the CLI -----------------------------------------------------------------


def _workflow_file(tmp_path):
    path = tmp_path / "wf.yml"
    path.write_text(
        yaml.safe_dump(
            {
                "jobs": {
                    "atomic_verify": {
                        "steps": [
                            {"env": {"ATOMIC_RUNNER": "windows-victim", "ATOMIC_TESTER_TYPE": "atomic"}}
                        ]
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    return path


def test_cli_warns_but_exits_zero_by_default(tmp_path, capsys):
    """A rule is worth deploying even when its test cannot run yet."""
    wf = _workflow_file(tmp_path)
    r = write_rule(tmp_path, runner="linux-victim")

    assert main(["--workflow", str(wf), str(r)]) == 0
    assert "::warning" in capsys.readouterr().out


def test_cli_exits_one_under_strict(tmp_path):
    wf = _workflow_file(tmp_path)
    r = write_rule(tmp_path, runner="linux-victim")

    assert main(["--workflow", str(wf), "--strict", str(r)]) == 1


def test_cli_is_quiet_when_everything_routes(tmp_path, capsys):
    wf = _workflow_file(tmp_path)
    r = write_rule(tmp_path)

    assert main(["--workflow", str(wf), str(r)]) == 0
    assert "::warning" not in capsys.readouterr().out


def test_a_workflow_with_no_test_jobs_is_a_checker_failure_not_27_findings(tmp_path, capsys):
    """Refusing to report is the honest answer when the matrix cannot be built."""
    wf = tmp_path / "wf.yml"
    wf.write_text(yaml.safe_dump({"jobs": {"build": {"steps": [{"run": "echo hi"}]}}}), encoding="utf-8")
    r = write_rule(tmp_path)

    assert main(["--workflow", str(wf), str(r)]) == 2
    assert "refusing" in capsys.readouterr().err.lower()


def test_missing_workflow_is_a_setup_failure(tmp_path):
    assert main(["--workflow", str(tmp_path / "nope.yml")]) == 2


def test_json_output_records_the_matrix_and_the_findings(tmp_path):
    wf = _workflow_file(tmp_path)
    r = write_rule(tmp_path, runner="linux-victim")
    out = tmp_path / "out" / "routing.json"

    main(["--workflow", str(wf), "--json", str(out), str(r)])

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["checked"] == 1
    assert data["findings"][0]["runner"] == "linux-victim"
    assert {"type": "atomic", "runner": "windows-victim", "job": "atomic_verify"} in data["serviced"]


def test_the_suite_cannot_write_to_a_real_job_summary(tmp_path, capsys):
    """Regression: these tests once appended invented findings to the real one.

    The autouse fixture in conftest.py unsets it; without that, running the
    suite inside CI reports fixture rules as broken in the job summary.
    """
    import os

    wf = _workflow_file(tmp_path)
    r = write_rule(tmp_path, runner="linux-victim")

    main(["--workflow", str(wf), str(r)])

    assert "GITHUB_STEP_SUMMARY" not in os.environ
    assert "::warning" in capsys.readouterr().out  # the finding still happened


def test_step_summary_is_appended_when_github_provides_one(tmp_path, monkeypatch):
    wf = _workflow_file(tmp_path)
    r = write_rule(tmp_path, runner="linux-victim")
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))

    main(["--workflow", str(wf), str(r)])

    assert "linux-victim" in summary.read_text(encoding="utf-8")


def test_an_unreadable_rule_is_skipped_not_fatal(tmp_path, capsys):
    wf = _workflow_file(tmp_path)
    bad = tmp_path / "bad.yml"
    bad.write_text("title: [unclosed\n", encoding="utf-8")

    assert main(["--workflow", str(wf), str(bad)]) == 0
    assert "SKIP" in capsys.readouterr().err


# --- the real workflow -------------------------------------------------------


def test_every_committed_rule_routes_to_a_real_job():
    """Guards the current repo: no rule should already be silently untested."""
    assert main([]) == 0


def test_the_real_workflow_still_services_the_three_known_combinations():
    """A subset assertion on purpose: adding the linux job must not fail this."""
    with open(".github/workflows/ci_dev_workflow.yml", encoding="utf-8") as fh:
        workflow = yaml.safe_load(fh)

    matrix, unresolved = derive_matrix(workflow)

    assert unresolved == []
    assert set(MATRIX) <= set(matrix)


@pytest.mark.parametrize("runner", ["linux-victim", "windows-dc"])
def test_the_schema_allows_combinations_the_workflow_does_not_service(runner):
    """The gap is real, not hypothetical -- the schema permits all of these."""
    with open("docs/schemas/sigma_schema.json", encoding="utf-8") as fh:
        schema = json.load(fh)

    allowed = schema["properties"]["custom"]["properties"]["testing"]["properties"]["runner"]["enum"]

    assert runner in allowed
    assert ("emulation", runner) not in MATRIX
