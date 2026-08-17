"""The progress-marker gate in pass_fail_eval.main() (register item 2.8).

`evaluate()` scores a rule from its event count; this gate runs *before* it and
answers a different question: was the attack even attempted? Without it, an
attack that never ran produces zero events, and zero events read as FAIL -- a
confirmed negative manufactured from something that never happened.

The gate existed but only for `tester == "atomic"`, leaving 8 of 27 rules
outside it. These tests pin down both testers, and the cases where the gate must
*not* fire.

Nothing here had test coverage before: the existing suite only exercises the
pure `evaluate()` function.
"""

import json

import pytest
from pass_fail_eval import FAIL, NOT_VERIFIED, PASS, main


def write_hits(matched_dir, detect_id, tester, enabled=True, event_count=0, error=None):
    d = matched_dir / detect_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "hits.json").write_text(
        json.dumps(
            {
                "detect_id": detect_id,
                "title": "T",
                "tester": tester,
                "testing_enabled": enabled,
                "event_count": event_count,
                "error": error,
                "error_kind": None,
                "events": [],
            }
        ),
        encoding="utf-8",
    )


def write_marker(progress_dir, detect_id, status, tester=None):
    progress_dir.mkdir(parents=True, exist_ok=True)
    payload = {"detect_id": detect_id, "status": status}
    if tester is not None:
        payload["tester"] = tester
    (progress_dir / f"{detect_id}.json").write_text(json.dumps(payload), encoding="utf-8")


def run(tmp_path, matched_dir, progress_dir=None):
    results = tmp_path / "results"
    argv = ["--matched-events-dir", str(matched_dir), "--results-dir", str(results), "--run-id", "1"]
    if progress_dir is not None:
        argv += ["--progress-dir", str(progress_dir)]
    exit_code = main(argv)
    return exit_code, results


def verdict_of(results, detect_id):
    return json.loads((results / detect_id / "result.json").read_text(encoding="utf-8"))["verdict"]


# --- the gate fires for both testers -----------------------------------------


@pytest.mark.parametrize("tester", ["atomic", "emulation"])
def test_no_marker_means_the_attack_never_ran(tmp_path, tester):
    """Zero events plus no marker is not evidence the detection failed."""
    matched, progress = tmp_path / "m", tmp_path / "p"
    write_hits(matched, "DETECT-A", tester, event_count=0)
    progress.mkdir()

    _, results = run(tmp_path, matched, progress)

    assert verdict_of(results, "DETECT-A") == NOT_VERIFIED


@pytest.mark.parametrize("tester", ["atomic", "emulation"])
def test_a_started_marker_is_not_a_completed_one(tmp_path, tester):
    """Killed by the step timeout partway through -- still not measured."""
    matched, progress = tmp_path / "m", tmp_path / "p"
    write_hits(matched, "DETECT-A", tester, event_count=0)
    write_marker(progress, "DETECT-A", "started", tester)

    _, results = run(tmp_path, matched, progress)

    assert verdict_of(results, "DETECT-A") == NOT_VERIFIED


@pytest.mark.parametrize("tester", ["atomic", "emulation"])
def test_a_completed_marker_hands_over_to_the_normal_verdict(tmp_path, tester):
    """The attack ran and Splunk saw nothing -- that is a real FAIL."""
    matched, progress = tmp_path / "m", tmp_path / "p"
    write_hits(matched, "DETECT-A", tester, event_count=0)
    write_marker(progress, "DETECT-A", "completed", tester)

    _, results = run(tmp_path, matched, progress)

    assert verdict_of(results, "DETECT-A") == FAIL


@pytest.mark.parametrize("tester", ["atomic", "emulation"])
def test_a_completed_marker_with_events_passes(tmp_path, tester):
    matched, progress = tmp_path / "m", tmp_path / "p"
    write_hits(matched, "DETECT-A", tester, event_count=3)
    write_marker(progress, "DETECT-A", "completed", tester)

    _, results = run(tmp_path, matched, progress)

    assert verdict_of(results, "DETECT-A") == PASS


def test_the_reason_names_the_tester_that_did_not_run(tmp_path):
    matched, progress = tmp_path / "m", tmp_path / "p"
    write_hits(matched, "DETECT-A", "emulation")
    progress.mkdir()

    _, results = run(tmp_path, matched, progress)

    reason = json.loads((results / "DETECT-A" / "result.json").read_text(encoding="utf-8"))["reason"]
    assert "Emulation" in reason


# --- where the gate must not fire --------------------------------------------


def test_a_rule_with_testing_disabled_is_not_evaluated_from_stray_data(tmp_path):
    """Run #125, 2026-08-17: a disabled rule's hits.json can carry a nonzero
    event_count from unrelated/background Splunk data (check_saved_search_hits.py
    never dispatched anything for it, but the field defaults to 0/None either
    way). That count must never reach evaluate() -- it is not a measurement of
    this rule, so scoring it PASS or FAIL invents a result nobody obtained."""
    matched, progress = tmp_path / "m", tmp_path / "p"
    write_hits(matched, "DETECT-A", "atomic", enabled=False, event_count=2)
    progress.mkdir()

    _, results = run(tmp_path, matched, progress)

    assert verdict_of(results, "DETECT-A") == NOT_VERIFIED


def test_a_disabled_rules_reason_names_the_flag(tmp_path):
    matched, progress = tmp_path / "m", tmp_path / "p"
    write_hits(matched, "DETECT-A", "atomic", enabled=False, event_count=0)
    progress.mkdir()

    _, results = run(tmp_path, matched, progress)

    result = json.loads((results / "DETECT-A" / "result.json").read_text(encoding="utf-8"))
    assert "disabled" in result["reason"].lower()
    assert result["disabled"] is True


def test_a_disabled_rule_does_not_flip_the_exit_code(tmp_path):
    """The bug's visible symptom: a run where the one rule under test passed
    cleanly still exited non-zero because 27 other, deliberately-disabled
    rules got scored anyway. A clean run must exit 0 regardless of how many
    other rules are sitting disabled."""
    matched, progress = tmp_path / "m", tmp_path / "p"
    write_hits(matched, "DETECT-A", "atomic", enabled=False, event_count=0)
    write_hits(matched, "DETECT-B", "atomic", enabled=True, event_count=3)
    write_marker(progress, "DETECT-B", "completed", "atomic")

    exit_code, results = run(tmp_path, matched, progress)

    assert verdict_of(results, "DETECT-A") == NOT_VERIFIED
    assert verdict_of(results, "DETECT-B") == PASS
    assert exit_code == 0


def test_a_disabled_rule_does_not_mask_a_genuine_failure(tmp_path):
    """The exclusion is scoped to the disabled rule itself -- an unrelated
    enabled rule that genuinely fails still gates the run."""
    matched, progress = tmp_path / "m", tmp_path / "p"
    write_hits(matched, "DETECT-A", "atomic", enabled=False, event_count=0)
    write_hits(matched, "DETECT-B", "atomic", enabled=True, event_count=0)
    write_marker(progress, "DETECT-B", "completed", "atomic")

    exit_code, results = run(tmp_path, matched, progress)

    assert verdict_of(results, "DETECT-A") == NOT_VERIFIED
    assert verdict_of(results, "DETECT-B") == FAIL
    assert exit_code == 1


def test_an_enabled_rule_with_no_testing_config_key_is_unaffected(tmp_path):
    """The disabled gate keys on `is False`, not falsiness -- a rule missing
    the field entirely (None) is the pre-existing, different case and must
    keep going through the normal atomic/emulation gate and evaluate()."""
    matched, progress = tmp_path / "m", tmp_path / "p"
    d = matched / "DETECT-A"
    d.mkdir(parents=True)
    (d / "hits.json").write_text(
        json.dumps(
            {
                "detect_id": "DETECT-A",
                "title": "T",
                "tester": "atomic",
                # testing_enabled deliberately absent
                "event_count": 3,
                "error": None,
                "error_kind": None,
                "events": [],
            }
        ),
        encoding="utf-8",
    )
    write_marker(progress, "DETECT-A", "completed", "atomic")

    _, results = run(tmp_path, matched, progress)

    assert verdict_of(results, "DETECT-A") == PASS


def test_a_rule_with_no_tester_is_evaluated_normally(tmp_path):
    matched, progress = tmp_path / "m", tmp_path / "p"
    write_hits(matched, "DETECT-A", "", event_count=0)
    progress.mkdir()

    _, results = run(tmp_path, matched, progress)

    assert verdict_of(results, "DETECT-A") == FAIL


def test_without_a_progress_dir_the_gate_is_off(tmp_path):
    """Backward compatible: omitting --progress-dir disables the check."""
    matched = tmp_path / "m"
    write_hits(matched, "DETECT-A", "emulation", event_count=4)

    _, results = run(tmp_path, matched, progress_dir=None)

    assert verdict_of(results, "DETECT-A") == PASS


# --- a marker with no hits.json ----------------------------------------------


def test_a_marker_without_hits_still_gets_a_verdict(tmp_path):
    """check_saved_search_hits.py never got to query this rule at all."""
    matched, progress = tmp_path / "m", tmp_path / "p"
    matched.mkdir()
    write_marker(progress, "DETECT-A", "started", "emulation")

    _, results = run(tmp_path, matched, progress)

    assert verdict_of(results, "DETECT-A") == NOT_VERIFIED


def test_a_synthesized_summary_uses_the_markers_own_tester(tmp_path):
    matched, progress = tmp_path / "m", tmp_path / "p"
    matched.mkdir()
    write_marker(progress, "DETECT-A", "started", "emulation")

    _, results = run(tmp_path, matched, progress)

    reason = json.loads((results / "DETECT-A" / "result.json").read_text(encoding="utf-8"))["reason"]
    assert "Emulation" in reason


def test_a_marker_predating_the_tester_field_is_treated_as_atomic(tmp_path):
    """Emulation rules had no markers at all before item 2.8, so this is safe."""
    matched, progress = tmp_path / "m", tmp_path / "p"
    matched.mkdir()
    write_marker(progress, "DETECT-A", "started")  # no tester key

    _, results = run(tmp_path, matched, progress)

    assert verdict_of(results, "DETECT-A") == NOT_VERIFIED


# --- the batch ----------------------------------------------------------------


def test_one_unverified_rule_does_not_change_the_others(tmp_path):
    matched, progress = tmp_path / "m", tmp_path / "p"
    write_hits(matched, "DETECT-A", "emulation", event_count=0)  # no marker
    write_hits(matched, "DETECT-B", "atomic", event_count=2)
    write_marker(progress, "DETECT-B", "completed", "atomic")

    exit_code, results = run(tmp_path, matched, progress)

    assert verdict_of(results, "DETECT-A") == NOT_VERIFIED
    assert verdict_of(results, "DETECT-B") == PASS
    assert exit_code == 1  # not all PASS, so no promotion
