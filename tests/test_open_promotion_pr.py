"""open_promotion_pr's "Open promotion PR to main and mark it In review" step
(audit/feature-and-process-audit.md item 4.1, slice 3 -- slice 1 was
determine_changed_rules.py, slice 2 was merge_verification_results.py).

This step is the pipeline's only path that opens the dev->main promotion PR
and marks it In review on the project board. These tests exist because it
spent its life as ~137 lines of `gh`-CLI-heavy inline bash, where
actionlint/shellcheck could only check its syntax, never its behaviour --
same motivation as slices 1/2, on a step with a different shape (linear, with
several independent best-effort try/fallback branches, nothing that
retries).

No real `gh` process and no real GitHub repo/token happen anywhere below:
every gh call is injected via a GhOps bundle of plain callables, same
Resolvers/GitOps injection pattern slices 1 and 2 used.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from open_promotion_pr import (
    GhOps,
    build_pr_body,
    build_project_add_failed_warning,
    build_project_edit_failed_warning,
    build_rule_table,
    build_stale_note,
    build_step_summary,
    compute_stale_count,
    extract_changed_rule_ids,
    parse_stats_json,
    run_step,
    stale_warning_annotation,
)

STATS_WITH_RULES = {
    "verified_expired": 0,
    "verified_superseded": 0,
    "rules": [
        {"detect_id": "DETECT-2026-0001", "title": "Suspicious PowerShell", "level": "high", "verdict": "PASS"},
        {"detect_id": "DETECT-2026-0002", "title": "Odd|Pipe Title", "level": "medium", "verdict": "FAIL"},
        {"detect_id": "DETECT-2026-0003", "title": "Not Verified Yet", "level": "low", "verdict": "NOT_VERIFIED"},
        {"detect_id": "DETECT-2026-0004", "title": "Custom verdict", "level": "low", "verdict": "SOME_OTHER"},
        {"detect_id": "DETECT-2026-0005", "title": "No verdict recorded", "level": "low", "verdict": None},
    ],
}


# --- parse_stats_json / compute_stale_count (pure) ----------------------------


def test_parse_stats_json_empty_string_is_none():
    assert parse_stats_json("") is None


def test_parse_stats_json_malformed_is_none():
    assert parse_stats_json("{not valid json") is None


def test_parse_stats_json_non_object_is_none():
    assert parse_stats_json("[1, 2, 3]") is None


def test_parse_stats_json_valid_object_parses():
    assert parse_stats_json('{"verified_expired": 2}') == {"verified_expired": 2}


def test_compute_stale_count_stats_absent_is_zero():
    assert compute_stale_count(None) == 0


def test_compute_stale_count_zero_when_both_fields_zero():
    assert compute_stale_count({"verified_expired": 0, "verified_superseded": 0}) == 0


def test_compute_stale_count_sums_both_fields():
    assert compute_stale_count({"verified_expired": 2, "verified_superseded": 3}) == 5


def test_compute_stale_count_missing_fields_default_to_zero():
    assert compute_stale_count({}) == 0


def test_compute_stale_count_non_numeric_value_falls_back_to_zero():
    assert compute_stale_count({"verified_expired": "not a number", "verified_superseded": 1}) == 0


def test_compute_stale_count_null_fields_default_to_zero():
    assert compute_stale_count({"verified_expired": None, "verified_superseded": None}) == 0


# --- build_stale_note / stale_warning_annotation (pure) -----------------------


def test_stale_note_empty_when_zero():
    assert build_stale_note(0) == ""


def test_stale_note_empty_when_negative():
    assert build_stale_note(-1) == ""


def test_stale_note_present_when_positive():
    note = build_stale_note(3)
    assert note.startswith("> [!WARNING]")
    assert "3 rule(s)" in note
    assert "does not block promotion" in note


def test_stale_annotation_none_when_zero():
    assert stale_warning_annotation(0) is None


def test_stale_annotation_present_when_positive():
    ann = stale_warning_annotation(2)
    assert ann == "::warning::2 rule(s) in prod have an expired or superseded verdict -- see the Console's Evidence card"


# --- extract_changed_rule_ids (pure) ------------------------------------------


def test_extract_changed_rule_ids_empty_list():
    assert extract_changed_rule_ids([]) == []


def test_extract_changed_rule_ids_no_matches():
    assert extract_changed_rule_ids(["README.md", "scripts/lib/env.py"]) == []


def test_extract_changed_rule_ids_single_match():
    assert extract_changed_rule_ids(["rules/sigma/DETECT-2026-0001.yml"]) == ["DETECT-2026-0001"]


def test_extract_changed_rule_ids_dedupes_and_sorts():
    filenames = [
        "outputs/spl/DETECT-2026-0002.spl",
        "rules/sigma/DETECT-2026-0001.yml",
        "outputs/spl/DETECT-2026-0002.spl.meta.json",
    ]
    assert extract_changed_rule_ids(filenames) == ["DETECT-2026-0001", "DETECT-2026-0002"]


# --- build_rule_table (pure) --------------------------------------------------


def test_rule_table_empty_when_no_changed_ids():
    assert build_rule_table([], STATS_WITH_RULES) == ""


def test_rule_table_empty_when_stats_unavailable():
    assert build_rule_table(["DETECT-2026-0001"], None) == ""


def test_rule_table_single_row():
    table = build_rule_table(["DETECT-2026-0001"], STATS_WITH_RULES)
    assert table.startswith("### Rules in this promotion")
    assert "| Detect ID | Title | Level | Verdict |" in table
    assert "| `DETECT-2026-0001` | Suspicious PowerShell | high | \U0001f7e2 PASS |" in table


def test_rule_table_multiple_rows_in_changed_id_order():
    table = build_rule_table(["DETECT-2026-0003", "DETECT-2026-0001"], STATS_WITH_RULES)
    lines = table.splitlines()
    detect_lines = [ln for ln in lines if ln.startswith("| `DETECT-")]
    assert len(detect_lines) == 2
    assert detect_lines[0].startswith("| `DETECT-2026-0003`")
    assert detect_lines[1].startswith("| `DETECT-2026-0001`")


def test_rule_table_missing_id_silently_dropped_not_flagged():
    """A changed id with no matching entry in stats.json is dropped, not
    surfaced as an error or a placeholder row -- documented, accepted gap.
    """
    table = build_rule_table(["DETECT-2026-9999"], STATS_WITH_RULES)
    assert table == ""


def test_rule_table_mix_of_known_and_unknown_ids_only_shows_known():
    table = build_rule_table(["DETECT-2026-0001", "DETECT-2026-9999"], STATS_WITH_RULES)
    assert "DETECT-2026-0001" in table
    assert "DETECT-2026-9999" not in table


def test_rule_table_escapes_pipe_in_title():
    table = build_rule_table(["DETECT-2026-0002"], STATS_WITH_RULES)
    assert "Odd\\|Pipe Title" in table


def test_rule_table_verdict_mark_mapping():
    table = build_rule_table(
        ["DETECT-2026-0001", "DETECT-2026-0002", "DETECT-2026-0003", "DETECT-2026-0004", "DETECT-2026-0005"],
        STATS_WITH_RULES,
    )
    assert "\U0001f7e2 PASS" in table
    assert "\U0001f534 FAIL" in table
    assert "\U0001f7e1 NOT VERIFIED" in table
    assert "⚪ SOME_OTHER" in table
    assert "⚪ never tested" in table


# --- build_pr_body (pure) -----------------------------------------------------


def test_pr_body_no_stale_note_no_rule_table():
    body = build_pr_body("12345", "", "")
    assert "run 12345 reported PASS" in body
    assert "[!WARNING]" not in body
    assert "Rules in this promotion" not in body


def test_pr_body_stale_note_only():
    body = build_pr_body("12345", "> [!WARNING]\n> stale stuff", "")
    assert body.endswith("> [!WARNING]\n> stale stuff")
    assert "Rules in this promotion" not in body


def test_pr_body_rule_table_only():
    body = build_pr_body("12345", "", "### Rules in this promotion\n\n...")
    assert body.endswith("### Rules in this promotion\n\n...")
    assert "[!WARNING]" not in body


def test_pr_body_both_stale_note_and_rule_table():
    body = build_pr_body("12345", "> [!WARNING]\n> stale stuff", "### Rules in this promotion\n\n...")
    # stale_note appears before rule_table, each separated by a blank line.
    stale_idx = body.index("[!WARNING]")
    table_idx = body.index("Rules in this promotion")
    assert stale_idx < table_idx
    assert "\n\n> [!WARNING]" in body
    assert "\n\n### Rules in this promotion" in body


# --- build_step_summary (pure) ------------------------------------------------


def test_step_summary_already_open_bare():
    summary = build_step_summary(pr_url="https://x/pr/1", already_open=True, stale_note="", rule_table="")
    assert "### Promotion PR" in summary
    assert "⚪ Already open: https://x/pr/1" in summary
    assert "[!WARNING]" not in summary


def test_step_summary_opened_bare():
    summary = build_step_summary(pr_url="https://x/pr/1", already_open=False, stale_note="", rule_table="")
    assert "\U0001f7e2 Opened: https://x/pr/1" in summary


def test_step_summary_includes_stale_note_and_rule_table_when_present():
    summary = build_step_summary(
        pr_url="https://x/pr/1",
        already_open=False,
        stale_note="> [!WARNING]\n> stale stuff",
        rule_table="### Rules in this promotion\n\n...",
    )
    assert "stale stuff" in summary
    assert "Rules in this promotion" in summary


# --- project-board warning text (pure) ----------------------------------------


def test_project_add_failed_warning_includes_detail():
    msg = build_project_add_failed_warning("https://x/pr/1", "HTTP 403: no access")
    assert msg.startswith("::warning::Opened https://x/pr/1 but failed to add it to Project #3")
    assert "HTTP 403: no access" in msg


def test_project_edit_failed_warning_has_no_detail_placeholder():
    msg = build_project_edit_failed_warning("https://x/pr/1")
    assert msg.startswith("::warning::Opened https://x/pr/1 but failed to set its Project #3 status to In review")


# --- run_step orchestration (fakes, no real gh/subprocess) --------------------


@dataclass
class FakeGh:
    existing_pr_url: str = ""
    stats_json: str = ""
    compare_filenames: list[str] = field(default_factory=list)
    created_pr_url: str = "https://github.com/example/repo/pull/42"
    add_result: tuple[bool, str] = (True, "PVTI_new_item")
    edit_result: tuple[bool, str] = (True, "")
    create_pr_calls: list[str] = field(default_factory=list)
    add_to_project_calls: list[str] = field(default_factory=list)
    set_project_status_calls: list[str] = field(default_factory=list)

    def as_ops(self) -> GhOps:
        def create_pr(body: str) -> str:
            self.create_pr_calls.append(body)
            return self.created_pr_url

        def add_to_project(pr_url: str) -> tuple[bool, str]:
            self.add_to_project_calls.append(pr_url)
            return self.add_result

        def set_project_status(item_id: str) -> tuple[bool, str]:
            self.set_project_status_calls.append(item_id)
            return self.edit_result

        return GhOps(
            find_existing_pr_url=lambda: self.existing_pr_url,
            fetch_stats_json=lambda: self.stats_json,
            fetch_compare_filenames=lambda: self.compare_filenames,
            create_pr=create_pr,
            add_to_project=add_to_project,
            set_project_status=set_project_status,
        )


def _collector():
    events: list[str] = []
    return events, events.append


def test_run_step_existing_pr_short_circuits_and_does_not_create():
    fake = FakeGh(existing_pr_url="https://github.com/example/repo/pull/7")
    logs, log = _collector()
    summaries, write_summary = _collector()

    rc = run_step(fake.as_ops(), run_id="999", log=log, write_summary=write_summary)

    assert rc == 0
    assert fake.create_pr_calls == []
    assert fake.add_to_project_calls == []
    assert any("already open" in msg for msg in logs)
    assert len(summaries) == 1
    assert "Already open: https://github.com/example/repo/pull/7" in summaries[0]


def test_run_step_existing_pr_short_circuit_still_carries_stale_note_and_table():
    import json as _json

    fake = FakeGh(
        existing_pr_url="https://github.com/example/repo/pull/7",
        stats_json=_json.dumps(STATS_WITH_RULES),
        compare_filenames=["rules/sigma/DETECT-2026-0001.yml"],
    )
    summaries, write_summary = _collector()

    run_step(fake.as_ops(), run_id="999", log=lambda _m: None, write_summary=write_summary)

    assert "Rules in this promotion" in summaries[0]


def test_run_step_opens_new_pr_when_none_exists():
    fake = FakeGh(existing_pr_url="")
    logs, log = _collector()
    summaries, write_summary = _collector()

    rc = run_step(fake.as_ops(), run_id="123", log=log, write_summary=write_summary)

    assert rc == 0
    assert len(fake.create_pr_calls) == 1
    assert "run 123 reported PASS" in fake.create_pr_calls[0]
    assert any("Opened promotion PR" in msg for msg in logs)
    assert "Opened: https://github.com/example/repo/pull/42" in summaries[0]


def test_run_step_project_add_failure_warns_and_does_not_call_edit():
    fake = FakeGh(existing_pr_url="", add_result=(False, "HTTP 403: no Projects scope"))
    logs, log = _collector()

    rc = run_step(fake.as_ops(), run_id="123", log=log, write_summary=lambda _s: None)

    assert rc == 0
    assert fake.set_project_status_calls == []
    assert any(
        "failed to add it to Project #3" in msg and "HTTP 403: no Projects scope" in msg for msg in logs
    )


def test_run_step_project_edit_failure_warns_after_successful_add():
    fake = FakeGh(existing_pr_url="", add_result=(True, "PVTI_abc"), edit_result=(False, "server error"))
    logs, log = _collector()

    rc = run_step(fake.as_ops(), run_id="123", log=log, write_summary=lambda _s: None)

    assert rc == 0
    assert fake.set_project_status_calls == ["PVTI_abc"]
    assert any("failed to set its Project #3 status to In review" in msg for msg in logs)
    assert not any("Set Project #3 Status=In review" in msg for msg in logs)


def test_run_step_project_add_and_edit_both_succeed_logs_success():
    fake = FakeGh(existing_pr_url="", add_result=(True, "PVTI_abc"), edit_result=(True, ""))
    logs, log = _collector()

    run_step(fake.as_ops(), run_id="123", log=log, write_summary=lambda _s: None)

    assert any("Set Project #3 Status=In review" in msg for msg in logs)


def test_run_step_stale_annotation_logged_before_pr_created():
    import json as _json

    fake = FakeGh(existing_pr_url="", stats_json=_json.dumps({"verified_expired": 1, "verified_superseded": 0}))
    logs, log = _collector()

    run_step(fake.as_ops(), run_id="123", log=log, write_summary=lambda _s: None)

    assert any(msg.startswith("::warning::1 rule(s)") for msg in logs)


def test_run_step_no_stale_annotation_when_stats_unavailable():
    fake = FakeGh(existing_pr_url="", stats_json="")
    logs, log = _collector()

    run_step(fake.as_ops(), run_id="123", log=log, write_summary=lambda _s: None)

    assert not any(msg.startswith("::warning::") and "rule(s)" in msg and "Console's Evidence card" in msg for msg in logs)


def test_run_step_rule_table_omitted_when_stats_unavailable_even_with_changed_ids():
    fake = FakeGh(existing_pr_url="", stats_json="", compare_filenames=["rules/sigma/DETECT-2026-0001.yml"])
    summaries, write_summary = _collector()

    run_step(fake.as_ops(), run_id="123", log=lambda _m: None, write_summary=write_summary)

    assert "Rules in this promotion" not in summaries[0]


def test_run_step_does_not_fetch_compare_when_stats_unavailable():
    """build_rule_table is gated on stats being parseable at all -- fetching
    the compare diff when there is nothing to look ids up against would be
    pure waste.
    """
    calls: list[str] = []
    fake = FakeGh(existing_pr_url="", stats_json="")
    ops = fake.as_ops()
    original_fetch = ops.fetch_compare_filenames
    ops = GhOps(
        find_existing_pr_url=ops.find_existing_pr_url,
        fetch_stats_json=ops.fetch_stats_json,
        fetch_compare_filenames=lambda: (calls.append("called"), original_fetch())[1],
        create_pr=ops.create_pr,
        add_to_project=ops.add_to_project,
        set_project_status=ops.set_project_status,
    )

    run_step(ops, run_id="123", log=lambda _m: None, write_summary=lambda _s: None)

    assert calls == []


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
