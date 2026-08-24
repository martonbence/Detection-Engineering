"""update_dashboard's write-back step (audit/feature-and-process-audit.md item 4.1,
slice 2 -- slice 1 was determine_changed_rules.py).

This step is the pipeline's only path that lands verification evidence and
dashboard/docs regeneration on `dev`, retrying commit+push up to three times
against a hard `git reset` each attempt. These tests exist because it spent
its life as ~137 lines of inline bash inside a `for i in 1 2 3` loop, where
actionlint/shellcheck could only check its syntax, never its behaviour --
same motivation as slice 1's tests, on a step with a different shape (a
retry/idempotency state machine, not a single decision).

No real git repo and no subprocess calls happen anywhere below: git/subprocess
calls are either pure-data functions (needs_delta_append, build_inventory_args)
or injected via GitOps / plain callables (run_attempt, merge_and_commit_loop).
The file-merge functions do touch real files, but only inside pytest's
tmp_path, never a git worktree.
"""

import pytest
from merge_verification_results import (
    COMMIT_MESSAGE,
    AttemptOutcome,
    GitOps,
    build_inventory_args,
    merge_and_commit_loop,
    merge_delta_files,
    merge_overlay_files,
    needs_delta_append,
    run_attempt,
)

# --- needs_delta_append (pure) ------------------------------------------------


def test_a_new_line_not_yet_present_needs_appending():
    assert needs_delta_append('{"detect_id": "DETECT-2026-0001", "verdict": "PASS"}', "") is True


def test_a_line_already_the_last_line_is_not_appended_again():
    """The idempotency guard: a retry that re-reads the same delta after a
    concurrent run already carried the line in must not duplicate it."""
    line = '{"detect_id": "DETECT-2026-0001", "verdict": "PASS"}'
    assert needs_delta_append(line, line) is False


def test_a_blank_delta_line_is_never_appended():
    """Mirrors the shell's `[ -z "$new_line" ] && continue` -- an empty delta
    (nothing new this run) is skipped outright, regardless of last_line."""
    assert needs_delta_append("", "") is False
    assert needs_delta_append("", "some prior line") is False


def test_a_different_last_line_still_gets_appended():
    """Not a duplicate check against the whole file -- only against the last
    line, matching the shell's `tail -n 1` comparison."""
    assert needs_delta_append("new line", "a different, older line") is True


# --- merge_overlay_files / merge_delta_files (real files, tmp_path) ----------


def test_overlay_copies_plain_files_last_verdict_wins(tmp_path):
    dl = tmp_path / "download"
    results = tmp_path / "results"
    (dl / "sub").mkdir(parents=True)
    (dl / "result.json").write_text('{"verdict": "PASS"}')
    (dl / "sub" / "nested.json").write_text('{"verdict": "FAIL"}')
    results.mkdir()
    (results / "result.json").write_text('{"verdict": "PREVIOUS"}')

    touched = merge_overlay_files(dl, results)

    assert sorted(touched) == ["result.json", "sub/nested.json"]
    assert (results / "result.json").read_text() == '{"verdict": "PASS"}'
    assert (results / "sub" / "nested.json").read_text() == '{"verdict": "FAIL"}'


def test_overlay_never_touches_delta_sidecars(tmp_path):
    dl = tmp_path / "download"
    results = tmp_path / "results"
    dl.mkdir()
    results.mkdir()
    (dl / "history.jsonl.delta").write_text('{"line": 1}\n')

    touched = merge_overlay_files(dl, results)

    assert touched == []
    assert not (results / "history.jsonl.delta").exists()
    assert not (results / "history.jsonl").exists()


def test_delta_merge_appends_a_line_not_yet_on_disk(tmp_path):
    dl = tmp_path / "download"
    results = tmp_path / "results"
    dl.mkdir()
    results.mkdir()
    (dl / "history.jsonl.delta").write_text('{"run": 2}\n')
    (results / "history.jsonl").write_text('{"run": 1}\n')

    touched = merge_delta_files(dl, results)

    assert touched == ["history.jsonl"]
    assert (results / "history.jsonl").read_text() == '{"run": 1}\n{"run": 2}\n'


def test_delta_merge_is_idempotent_on_a_replayed_delta(tmp_path):
    """A retry resets, re-reads the same .delta, and finds the line already
    last -- exactly one copy must end up in the file across repeated calls."""
    dl = tmp_path / "download"
    results = tmp_path / "results"
    dl.mkdir()
    results.mkdir()
    (dl / "history.jsonl.delta").write_text('{"run": 2}\n')
    (results / "history.jsonl").write_text('{"run": 1}\n{"run": 2}\n')

    touched = merge_delta_files(dl, results)

    assert touched == []
    assert (results / "history.jsonl").read_text() == '{"run": 1}\n{"run": 2}\n'


def test_delta_merge_creates_a_new_results_file_when_none_existed(tmp_path):
    """A brand-new rule's first verification: no prior history.jsonl to overlay."""
    dl = tmp_path / "download"
    results = tmp_path / "results"
    dl.mkdir()
    results.mkdir()
    (dl / "DETECT-2026-0099").mkdir()
    (dl / "DETECT-2026-0099" / "history.jsonl.delta").write_text('{"run": 1}\n')

    touched = merge_delta_files(dl, results)

    assert touched == ["DETECT-2026-0099/history.jsonl"]
    assert (results / "DETECT-2026-0099" / "history.jsonl").read_text() == '{"run": 1}\n'


def test_delta_merge_skips_an_empty_delta_file(tmp_path):
    dl = tmp_path / "download"
    results = tmp_path / "results"
    dl.mkdir()
    results.mkdir()
    (dl / "history.jsonl.delta").write_text("")

    touched = merge_delta_files(dl, results)

    assert touched == []
    assert not (results / "history.jsonl").exists()


# --- build_inventory_args: all four presence/absence combinations ------------


def test_inventory_args_both_present(tmp_path):
    deploy = tmp_path / "dev_deploy_report.json"
    reconcile = tmp_path / "reconcile.json"
    deploy.write_text("{}")
    reconcile.write_text("{}")

    assert build_inventory_args(deploy, reconcile) == [
        "--deploy-report",
        str(deploy),
        "--reconcile",
        str(reconcile),
    ]


def test_inventory_args_deploy_report_only(tmp_path):
    deploy = tmp_path / "dev_deploy_report.json"
    reconcile = tmp_path / "reconcile.json"  # never created
    deploy.write_text("{}")

    assert build_inventory_args(deploy, reconcile) == ["--deploy-report", str(deploy)]


def test_inventory_args_reconcile_only(tmp_path):
    deploy = tmp_path / "dev_deploy_report.json"  # never created
    reconcile = tmp_path / "reconcile.json"
    reconcile.write_text("{}")

    assert build_inventory_args(deploy, reconcile) == ["--reconcile", str(reconcile)]


def test_inventory_args_neither_present_is_a_skip(tmp_path):
    """Empty list is the caller's signal to not invoke deployment_inventory.py
    at all -- not "invoke it with no report", which the script would warn on."""
    deploy = tmp_path / "dev_deploy_report.json"
    reconcile = tmp_path / "reconcile.json"

    assert build_inventory_args(deploy, reconcile) == []


# --- run_attempt: the loop body with git/subprocess fully injected -----------


class FakeGit:
    """A GitOps stand-in that records calls and can be scripted to fail."""

    def __init__(self, *, has_diff: bool = True, push_succeeds: bool = True):
        self.has_diff = has_diff
        self.push_succeeds = push_succeeds
        self.fetch_reset_calls = 0
        self.committed_messages: list[str] = []
        self.push_calls = 0

    def as_ops(self) -> GitOps:
        return GitOps(
            fetch_reset=self._fetch_reset,
            diff_cached_quiet=lambda: not self.has_diff,
            commit=self._commit,
            push=self._push,
        )

    def _fetch_reset(self) -> None:
        self.fetch_reset_calls += 1

    def _commit(self, message: str) -> None:
        self.committed_messages.append(message)

    def _push(self) -> bool:
        self.push_calls += 1
        return self.push_succeeds


def _attempt_kwargs(tmp_path, **overrides):
    dl = tmp_path / "download"
    results_dir = tmp_path / "results"
    results_dir.mkdir(exist_ok=True)
    kwargs = {
        "i": 1,
        "dl": dl,
        "results_dir": results_dir,
        "deploy_report": tmp_path / "deploy_report.json",
        "reconcile": tmp_path / "reconcile.json",
        "git": FakeGit().as_ops(),
        "run_inventory": lambda args: None,
        "run_generate_stats": lambda: None,
        "stage_paths": lambda: None,
        "log": lambda msg: None,
    }
    kwargs.update(overrides)
    return kwargs


def test_run_attempt_with_no_download_dir_is_a_normal_state_not_an_error(tmp_path):
    """Lab offline, or splunk_verify never reached staging -- proceed to
    regenerate from previously-committed state, no download dir required."""
    messages: list[str] = []
    fake_git = FakeGit(has_diff=True, push_succeeds=True)
    kwargs = _attempt_kwargs(tmp_path, git=fake_git.as_ops(), log=messages.append)

    outcome = run_attempt(**kwargs)

    assert outcome is AttemptOutcome.PUSHED
    assert any("No verification results artifact" in m for m in messages)
    assert fake_git.committed_messages == [COMMIT_MESSAGE]


def test_run_attempt_merges_an_existing_download_dir(tmp_path):
    dl = tmp_path / "download"
    dl.mkdir()
    (dl / "result.json").write_text('{"verdict": "PASS"}')
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    messages: list[str] = []
    kwargs = _attempt_kwargs(tmp_path, dl=dl, results_dir=results_dir, log=messages.append)

    outcome = run_attempt(**kwargs)

    assert outcome is AttemptOutcome.PUSHED
    assert (results_dir / "result.json").read_text() == '{"verdict": "PASS"}'
    assert any("Merging this run's verification results" in m for m in messages)


def test_run_attempt_with_no_staged_changes_exits_without_committing(tmp_path):
    fake_git = FakeGit(has_diff=False)
    kwargs = _attempt_kwargs(tmp_path, git=fake_git.as_ops())

    outcome = run_attempt(**kwargs)

    assert outcome is AttemptOutcome.NO_CHANGES
    assert fake_git.committed_messages == []
    assert fake_git.push_calls == 0


def test_run_attempt_reports_push_failure_without_retrying_itself(tmp_path):
    """Retrying is merge_and_commit_loop's job, not run_attempt's -- one call
    here is exactly one reset+merge+commit+push cycle."""
    fake_git = FakeGit(has_diff=True, push_succeeds=False)
    kwargs = _attempt_kwargs(tmp_path, git=fake_git.as_ops())

    outcome = run_attempt(**kwargs)

    assert outcome is AttemptOutcome.PUSH_FAILED
    assert fake_git.committed_messages == [COMMIT_MESSAGE]
    assert fake_git.push_calls == 1


def test_run_attempt_skips_inventory_when_neither_input_exists(tmp_path):
    calls: list[list[str]] = []
    messages: list[str] = []
    kwargs = _attempt_kwargs(
        tmp_path,
        run_inventory=lambda args: calls.append(args),
        log=messages.append,
    )

    run_attempt(**kwargs)

    assert calls == []
    assert any("leaving the deployment inventory as committed" in m for m in messages)


def test_run_attempt_runs_inventory_when_a_report_exists(tmp_path):
    deploy_report = tmp_path / "deploy_report.json"
    deploy_report.write_text("{}")
    calls: list[list[str]] = []
    kwargs = _attempt_kwargs(
        tmp_path,
        deploy_report=deploy_report,
        run_inventory=lambda args: calls.append(args),
    )

    run_attempt(**kwargs)

    assert calls == [["--deploy-report", str(deploy_report)]]


# --- merge_and_commit_loop: the retry/backoff state machine (pure) -----------


def test_loop_returns_zero_immediately_when_the_first_attempt_pushes():
    calls: list[int] = []

    def attempt(i: int) -> AttemptOutcome:
        calls.append(i)
        return AttemptOutcome.PUSHED

    sleeps: list[int] = []
    rc = merge_and_commit_loop(attempt, sleeps.append)

    assert rc == 0
    assert calls == [1]
    assert sleeps == []


def test_loop_returns_zero_immediately_when_there_is_nothing_to_commit():
    def attempt(i: int) -> AttemptOutcome:
        return AttemptOutcome.NO_CHANGES

    sleeps: list[int] = []
    rc = merge_and_commit_loop(attempt, sleeps.append)

    assert rc == 0
    assert sleeps == []


def test_loop_retries_on_push_failure_and_succeeds_on_a_later_attempt():
    outcomes = [AttemptOutcome.PUSH_FAILED, AttemptOutcome.PUSH_FAILED, AttemptOutcome.PUSHED]
    calls: list[int] = []

    def attempt(i: int) -> AttemptOutcome:
        calls.append(i)
        return outcomes[i - 1]

    sleeps: list[int] = []
    rc = merge_and_commit_loop(attempt, sleeps.append)

    assert rc == 0
    assert calls == [1, 2, 3]
    # i * 2 for each failed attempt before the eventual success: 2, 4.
    assert sleeps == [2, 4]


def test_loop_gives_up_after_three_failed_attempts():
    calls: list[int] = []

    def attempt(i: int) -> AttemptOutcome:
        calls.append(i)
        return AttemptOutcome.PUSH_FAILED

    sleeps: list[int] = []
    messages: list[str] = []
    rc = merge_and_commit_loop(attempt, sleeps.append, log=messages.append)

    assert rc == 1
    assert calls == [1, 2, 3]
    assert "Push failed after 3 attempts." in messages


def test_loop_sleeps_after_the_third_failed_attempt_too():
    """Preserved quirk: the shell's `sleep $((i * 2))` sits at the bottom of
    every loop iteration unconditionally, including the last one that is about
    to give up anyway -- reproduced verbatim rather than trimmed as dead work,
    same reasoning slice 1 used to keep `git fetch --depth=0`."""

    def attempt(i: int) -> AttemptOutcome:
        return AttemptOutcome.PUSH_FAILED

    sleeps: list[int] = []
    merge_and_commit_loop(attempt, sleeps.append)

    assert sleeps == [2, 4, 6]


@pytest.mark.parametrize("max_attempts", [1, 2, 5])
def test_loop_respects_a_custom_attempt_count(max_attempts):
    calls: list[int] = []

    def attempt(i: int) -> AttemptOutcome:
        calls.append(i)
        return AttemptOutcome.PUSH_FAILED

    rc = merge_and_commit_loop(attempt, lambda _s: None, max_attempts=max_attempts)

    assert rc == 1
    assert calls == list(range(1, max_attempts + 1))


def test_loop_works_without_a_log_callable():
    """log is optional -- main() always supplies one, but the function itself
    must not require it."""

    def attempt(i: int) -> AttemptOutcome:
        return AttemptOutcome.PUSHED

    assert merge_and_commit_loop(attempt, lambda _s: None) == 0
