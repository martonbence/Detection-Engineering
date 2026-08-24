"""splunk_verify's "Reconcile Splunk state against the repo" step
(audit/feature-and-process-audit.md item 4.1, slice 4 -- slice 1 was
determine_changed_rules.py, slice 2 was merge_verification_results.py, slice
3 was open_promotion_pr.py).

This step is the pipeline's only mechanism that notices Splunk-side drift
(deletions, renames) the repo's own diff never sees. These tests exist
because it spent its life as ~118 lines of inline bash whose correctness
depended on subtle, hard-won reasoning (the report-reflects-pre-apply-state
correction; the `bash -e`/`if`-exemption dance) that actionlint/shellcheck
could never verify -- same motivation as slices 1-3.

No real reconcile.py subprocess happens in the pure/orchestration tests
below; ReconcileOps is a plain callable bundle, same Resolvers/GhOps
injection pattern slices 1-3 used. run_reconcile_subprocess() itself is
exercised against real (tiny, throwaway) subprocesses further down, since
its whole job is the tee/PIPESTATUS-equivalent live-capture-plus-exit-code
behaviour, which a fake cannot demonstrate.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field

import pytest
from reconcile_step import (
    ReconcileOps,
    build_drift_warning,
    build_drift_warning_parts,
    build_extra_args,
    build_reconcile_failure_warning,
    build_step_summary,
    corrected_renamed_count,
    corrected_unresolved_count,
    dupes_count,
    missing_count,
    read_reconcile_json,
    reconcile_command,
    run_reconcile_subprocess,
    run_step,
)

# --- build_extra_args (pure) -----------------------------------------------------


def test_extra_args_workflow_dispatch_and_retire_true():
    assert build_extra_args("workflow_dispatch", "true") == ["--apply-removals"]


def test_extra_args_workflow_dispatch_but_retire_false():
    assert build_extra_args("workflow_dispatch", "false") == []


def test_extra_args_workflow_dispatch_but_retire_absent():
    # inputs.retire_orphans reads as "" on any event that is not the
    # dispatch that actually set it -- and even on a dispatch, an unset
    # boolean input can arrive empty.
    assert build_extra_args("workflow_dispatch", "") == []


def test_extra_args_push_event_with_retire_true_string():
    # The truthiness trap this double condition exists to close: on a push,
    # `inputs.retire_orphans` is empty, never "true" -- but if some future
    # caller passed "true" anyway (e.g. a copy-pasted env block), the event
    # check alone must still block it.
    assert build_extra_args("push", "true") == []


def test_extra_args_push_event_retire_empty():
    assert build_extra_args("push", "") == []


def test_extra_args_pull_request_event_retire_true():
    # Any non-dispatch event, not just push, must be blocked.
    assert build_extra_args("pull_request", "true") == []


def test_reconcile_command_includes_extra_args():
    cmd = reconcile_command(["--apply-removals"])
    assert cmd[-4:] == ["--apply", "--apply-removals"] or "--apply-removals" in cmd
    assert "--apply" in cmd
    assert "--rules-dir" in cmd
    assert "rules/sigma" in cmd
    assert "--json" in cmd
    assert "outputs/state/reconcile.json" in cmd


def test_reconcile_command_no_extra_args():
    cmd = reconcile_command([])
    assert "--apply-removals" not in cmd
    assert cmd[-1] == "--apply"


# --- corrected counts (pure) ------------------------------------------------------


def _report(**overrides) -> dict:
    base = {
        "orphan_removed": [],
        "orphan_renamed": [],
        "counts": {"missing": 0, "duplicate_names": 0},
    }
    base.update(overrides)
    return base


def test_corrected_unresolved_zero_drift():
    report = _report(orphan_removed=[])
    assert corrected_unresolved_count(report) == 0


def test_corrected_unresolved_some_drift_none_applied():
    report = _report(
        orphan_removed=[
            {"name": "a", "retired": False},
            {"name": "b", "retired": False},
            {"name": "c", "retired": True},
        ],
    )
    # c is already-retired (pre-existing resolved state), a and b are live.
    assert corrected_unresolved_count(report) == 2


def test_corrected_unresolved_some_applied_this_run():
    report = _report(
        orphan_removed=[
            {"name": "a", "retired": False},
            {"name": "b", "retired": False},
            {"name": "c", "retired": False},
        ],
        applied={"actions": [{"action": "retire", "name": "a", "ok": True, "detail": "disabled and marked"}]},
    )
    # a was just retired by this run's --apply-removals -- subtracted out.
    assert corrected_unresolved_count(report) == 2


def test_corrected_unresolved_all_applied_this_run_leaves_zero():
    report = _report(
        orphan_removed=[
            {"name": "a", "retired": False},
            {"name": "b", "retired": False},
        ],
        applied={
            "actions": [
                {"action": "retire", "name": "a", "ok": True, "detail": "disabled and marked"},
                {"action": "retire", "name": "b", "ok": True, "detail": "disabled and marked"},
            ]
        },
    )
    assert corrected_unresolved_count(report) == 0


def test_corrected_unresolved_failed_apply_action_not_subtracted():
    # ok=False means the retire attempt failed -- it must still count as
    # unresolved, not be silently subtracted out.
    report = _report(
        orphan_removed=[{"name": "a", "retired": False}],
        applied={"actions": [{"action": "retire", "name": "a", "ok": False, "detail": "HTTP 500"}]},
    )
    assert corrected_unresolved_count(report) == 1


def test_corrected_unresolved_ignores_delete_actions():
    # A "delete" action (rename cleanup) must never subtract from the
    # removal bucket -- only "retire" actions do.
    report = _report(
        orphan_removed=[{"name": "a", "retired": False}],
        applied={"actions": [{"action": "delete", "name": "a", "ok": True, "detail": "deleted"}]},
    )
    assert corrected_unresolved_count(report) == 1


def test_corrected_unresolved_no_applied_key_at_all():
    # --apply was not passed (never happens from this step, but the field
    # is genuinely absent from reconcile.py's report unless --apply ran).
    report = _report(orphan_removed=[{"name": "a", "retired": False}])
    assert "applied" not in report
    assert corrected_unresolved_count(report) == 1


def test_corrected_renamed_zero_drift():
    assert corrected_renamed_count(_report(orphan_renamed=[])) == 0


def test_corrected_renamed_some_drift_none_applied():
    report = _report(orphan_renamed=[{"name": "x_old_title"}, {"name": "y_old_title"}])
    assert corrected_renamed_count(report) == 2


def test_corrected_renamed_some_applied_this_run():
    report = _report(
        orphan_renamed=[{"name": "x_old_title"}, {"name": "y_old_title"}],
        applied={"actions": [{"action": "delete", "name": "x_old_title", "ok": True, "detail": "deleted"}]},
    )
    assert corrected_renamed_count(report) == 1


def test_corrected_renamed_all_applied_this_run_leaves_zero():
    report = _report(
        orphan_renamed=[{"name": "x_old_title"}],
        applied={"actions": [{"action": "delete", "name": "x_old_title", "ok": True, "detail": "deleted"}]},
    )
    assert corrected_renamed_count(report) == 0


def test_corrected_renamed_failed_delete_not_subtracted():
    report = _report(
        orphan_renamed=[{"name": "x_old_title"}],
        applied={"actions": [{"action": "delete", "name": "x_old_title", "ok": False, "detail": "HTTP 500"}]},
    )
    assert corrected_renamed_count(report) == 1


def test_corrected_renamed_ignores_retire_actions():
    report = _report(
        orphan_renamed=[{"name": "x_old_title"}],
        applied={"actions": [{"action": "retire", "name": "x_old_title", "ok": True, "detail": "disabled and marked"}]},
    )
    assert corrected_renamed_count(report) == 1


def test_missing_count_pass_through():
    assert missing_count(_report(counts={"missing": 5, "duplicate_names": 0})) == 5


def test_missing_count_absent_key_defaults_zero():
    assert missing_count({"counts": {}}) == 0


def test_dupes_count_pass_through():
    assert dupes_count(_report(counts={"missing": 0, "duplicate_names": 3})) == 3


def test_dupes_count_absent_key_defaults_zero():
    assert dupes_count({"counts": {"missing": 0}}) == 0


# --- build_drift_warning_parts / build_drift_warning (pure) -----------------------


def test_drift_parts_all_zero_is_empty():
    assert build_drift_warning_parts(0, 0, 0, 0) == []


def test_drift_parts_unresolved_only_has_retire_remedy():
    parts = build_drift_warning_parts(2, 0, 0, 0)
    assert len(parts) == 1
    assert "retire_orphans" in parts[0]
    assert "still live" in parts[0]


def test_drift_parts_renamed_only_has_deletion_did_not_land_remedy():
    parts = build_drift_warning_parts(0, 3, 0, 0)
    assert len(parts) == 1
    assert "deletion did not land" in parts[0]


def test_drift_parts_missing_only_has_deploy_not_retirement_remedy():
    parts = build_drift_warning_parts(0, 0, 4, 0)
    assert len(parts) == 1
    assert "need a deploy, not a retirement" in parts[0]


def test_drift_parts_dupes_only_has_duplicate_remedy():
    parts = build_drift_warning_parts(0, 0, 0, 1)
    assert len(parts) == 1
    assert "more than one object" in parts[0]


def test_drift_parts_each_remedy_is_distinct_not_a_template():
    # The bug this step's comment says it replaced: one generic sentence for
    # every condition. Confirm all four remedies are actually different text.
    all_four = build_drift_warning_parts(1, 1, 1, 1)
    assert len(all_four) == 4
    assert len(set(all_four)) == 4


def test_drift_parts_multiple_nonzero_preserves_order():
    parts = build_drift_warning_parts(1, 2, 3, 4)
    assert len(parts) == 4
    assert "retire_orphans" in parts[0]
    assert "deletion did not land" in parts[1]
    assert "need a deploy" in parts[2]
    assert "more than one object" in parts[3]


def test_build_drift_warning_none_when_no_parts():
    assert build_drift_warning([]) is None


def test_build_drift_warning_single_part_no_trailing_separator():
    warning = build_drift_warning(["one thing"])
    assert warning == "::warning title=Splunk state drift::one thing"


def test_build_drift_warning_joins_multiple_with_semicolon_no_trailing():
    warning = build_drift_warning(["a", "b", "c"])
    assert warning == "::warning title=Splunk state drift::a; b; c"
    assert not warning.endswith("; ")
    assert not warning.endswith(";")


# --- build_reconcile_failure_warning / build_step_summary (pure) ------------------


def test_reconcile_failure_warning_includes_exit_code():
    warning = build_reconcile_failure_warning(2)
    assert warning == "::warning::Reconciliation exited 2 -- a cleanup action may not have landed. See the step summary."


def test_step_summary_wraps_report_in_code_fence():
    summary = build_step_summary("Repo wants : 27 saved search(es)\nRESULT: Splunk matches the repo.\n")
    assert summary.startswith("### Splunk state reconciliation\n\n```\n")
    assert "Repo wants : 27 saved search(es)" in summary
    assert summary.endswith("```\n")


def test_step_summary_empty_report_still_fenced():
    summary = build_step_summary("")
    assert summary == "### Splunk state reconciliation\n\n```\n```\n"


# --- run_step (orchestration, injected ops) ----------------------------------------


@dataclass
class FakeOps:
    exit_code: int = 0
    report_text: str = "some report text\n"
    report_json: dict | None = None
    run_calls: list[list[str]] = field(default_factory=list)
    read_calls: int = 0

    def as_ops(self) -> ReconcileOps:
        def run_reconcile(extra_args):
            self.run_calls.append(list(extra_args))
            return (self.exit_code, self.report_text)

        def read_report():
            self.read_calls += 1
            return self.report_json

        return ReconcileOps(run_reconcile=run_reconcile, read_report=read_report)


def _collector():
    events: list[str] = []
    return events, events.append


def test_run_step_success_no_drift_returns_zero_and_no_warnings():
    fake = FakeOps(exit_code=0, report_json={"orphan_removed": [], "orphan_renamed": [], "counts": {"missing": 0, "duplicate_names": 0}})
    logs, log = _collector()
    summaries, write_summary = _collector()

    rc = run_step(fake.as_ops(), event_name="push", retire_orphans="", log=log, write_summary=write_summary)

    assert rc == 0
    assert not any("::warning" in msg for msg in logs)
    assert len(summaries) == 1
    assert "Splunk state reconciliation" in summaries[0]


def test_run_step_logs_retiring_message_only_when_extra_args_present():
    fake = FakeOps(exit_code=0, report_json=None)
    logs, log = _collector()

    run_step(fake.as_ops(), event_name="workflow_dispatch", retire_orphans="true", log=log, write_summary=lambda _s: None)

    assert fake.run_calls == [["--apply-removals"]]
    assert any("Retiring removal orphans as requested" in msg for msg in logs)


def test_run_step_no_retiring_message_on_push():
    fake = FakeOps(exit_code=0, report_json=None)
    logs, log = _collector()

    run_step(fake.as_ops(), event_name="push", retire_orphans="true", log=log, write_summary=lambda _s: None)

    assert fake.run_calls == [[]]
    assert not any("Retiring removal orphans" in msg for msg in logs)


def test_run_step_reconcile_json_absent_skips_drift_block_but_still_summarizes():
    fake = FakeOps(exit_code=0, report_text="report body\n", report_json=None)
    logs, log = _collector()
    summaries, write_summary = _collector()

    rc = run_step(fake.as_ops(), event_name="push", retire_orphans="", log=log, write_summary=write_summary)

    assert rc == 0
    assert not any("Splunk state drift" in msg for msg in logs)
    assert len(summaries) == 1
    assert "report body" in summaries[0]


def test_run_step_drift_warning_emitted_when_report_has_drift():
    fake = FakeOps(
        exit_code=0,
        report_json={
            "orphan_removed": [{"name": "a", "retired": False}],
            "orphan_renamed": [],
            "counts": {"missing": 0, "duplicate_names": 0},
        },
    )
    logs, log = _collector()

    run_step(fake.as_ops(), event_name="push", retire_orphans="", log=log, write_summary=lambda _s: None)

    warnings = [msg for msg in logs if msg.startswith("::warning title=Splunk state drift::")]
    assert len(warnings) == 1
    assert "1 object(s)" in warnings[0]


def test_run_step_reconcile_failure_emits_second_warning_and_propagates_exit_code():
    fake = FakeOps(exit_code=2, report_json=None)
    logs, log = _collector()

    rc = run_step(fake.as_ops(), event_name="push", retire_orphans="", log=log, write_summary=lambda _s: None)

    assert rc == 2
    assert any(msg == "::warning::Reconciliation exited 2 -- a cleanup action may not have landed. See the step summary." for msg in logs)


def test_run_step_reconcile_success_no_failure_warning():
    fake = FakeOps(exit_code=0, report_json=None)
    logs, log = _collector()

    run_step(fake.as_ops(), event_name="push", retire_orphans="", log=log, write_summary=lambda _s: None)

    assert not any("Reconciliation exited" in msg for msg in logs)


def test_run_step_summary_written_even_when_reconcile_fails():
    # continue-on-error masks the job result, but the diagnostics must still
    # land -- this is the entire reason the shell needed the `if`-exemption
    # trick in the first place.
    fake = FakeOps(exit_code=1, report_text="partial report\n", report_json=None)
    summaries, write_summary = _collector()

    run_step(fake.as_ops(), event_name="push", retire_orphans="", log=lambda _m: None, write_summary=write_summary)

    assert len(summaries) == 1
    assert "partial report" in summaries[0]


def test_run_step_drift_and_failure_warnings_can_both_fire():
    fake = FakeOps(
        exit_code=2,
        report_json={
            "orphan_removed": [{"name": "a", "retired": False}],
            "orphan_renamed": [],
            "counts": {"missing": 0, "duplicate_names": 0},
        },
    )
    logs, log = _collector()

    rc = run_step(fake.as_ops(), event_name="push", retire_orphans="", log=log, write_summary=lambda _s: None)

    assert rc == 2
    assert any(msg.startswith("::warning title=Splunk state drift::") for msg in logs)
    assert any(msg.startswith("::warning::Reconciliation exited 2") for msg in logs)


def test_run_step_malformed_report_json_treated_as_absent():
    # read_report() itself is responsible for folding a parse failure into
    # None (see read_reconcile_json below) -- run_step just has to handle
    # None correctly, which the absent-file test above already covers. This
    # confirms run_step does not special-case "present but empty dict" in a
    # way that would crash on a report missing expected keys.
    fake = FakeOps(exit_code=0, report_json={})
    logs, log = _collector()

    rc = run_step(fake.as_ops(), event_name="push", retire_orphans="", log=log, write_summary=lambda _s: None)

    assert rc == 0
    assert not any("::warning" in msg for msg in logs)


# --- read_reconcile_json (I/O, real filesystem via tmp_path) -----------------------


def test_read_reconcile_json_missing_file_returns_none(tmp_path):
    assert read_reconcile_json(str(tmp_path / "does_not_exist.json")) is None


def test_read_reconcile_json_valid_file_parses(tmp_path):
    path = tmp_path / "reconcile.json"
    path.write_text('{"counts": {"missing": 1, "duplicate_names": 0}}', encoding="utf-8")
    result = read_reconcile_json(str(path))
    assert result == {"counts": {"missing": 1, "duplicate_names": 0}}


def test_read_reconcile_json_malformed_file_returns_none(tmp_path):
    path = tmp_path / "reconcile.json"
    path.write_text("{not valid json", encoding="utf-8")
    assert read_reconcile_json(str(path)) is None


# --- run_reconcile_subprocess (I/O, real subprocesses) ------------------------------


def test_run_reconcile_subprocess_captures_exit_code_zero_on_success():
    cmd = [sys.executable, "-c", "print('line one'); print('line two')"]
    rc, text = run_reconcile_subprocess(cmd)
    assert rc == 0
    assert text == "line one\nline two\n"


def test_run_reconcile_subprocess_captures_nonzero_exit_code():
    # The equivalent of `${PIPESTATUS[0]}` -- must be the child's real exit
    # code, not swallowed to 0 by anything in between.
    cmd = [sys.executable, "-c", "print('some output'); raise SystemExit(2)"]
    rc, text = run_reconcile_subprocess(cmd)
    assert rc == 2
    assert "some output" in text


def test_run_reconcile_subprocess_captures_output_even_on_failure():
    # This is the entire reason PIPESTATUS/tee is needed in the shell: the
    # step's diagnostics (step summary, warnings) must still see the report
    # text that was produced before the failing exit.
    cmd = [sys.executable, "-c", "print('partial report line'); import sys; sys.exit(1)"]
    rc, text = run_reconcile_subprocess(cmd)
    assert rc == 1
    assert "partial report line" in text


def test_run_reconcile_subprocess_stderr_not_captured_in_report_text():
    # Mirrors `| tee` only ever redirecting stdout: reconcile.py's
    # `print(..., file=sys.stderr)` diagnostics must not end up in the
    # captured report text (and therefore not in the step summary).
    cmd = [
        sys.executable,
        "-c",
        "import sys; print('stdout line'); print('stderr line', file=sys.stderr)",
    ]
    rc, text = run_reconcile_subprocess(cmd)
    assert rc == 0
    assert "stdout line" in text
    assert "stderr line" not in text


def test_run_reconcile_subprocess_empty_output_on_immediate_failure():
    cmd = [sys.executable, "-c", "import sys; sys.exit(3)"]
    rc, text = run_reconcile_subprocess(cmd)
    assert rc == 3
    assert text == ""


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
