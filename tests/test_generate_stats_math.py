"""generate_stats()'s own arithmetic (register item 1.6, feature-and-process-audit.md).

Before this module, nothing in tests/ exercised generate_stats()'s pass-rate /
staleness / verified_current math directly -- test_deployment_panel.py imports
generate_stats but only drives render_deployment_html(), a separate, smaller
helper. generate_stats() reads the filesystem itself (load_sigma_rules(),
load_verdicts()) and reaches out to git (update_trend_history()) and the
network (fetch_mitre_techniques()), so these tests monkeypatch all four to
synthetic, deterministic stand-ins rather than touching the real repo, git
history, or MITRE's STIX feed.

Two things are pinned here on purpose:

  * The REVIEW_INTERVAL_DAYS boundary is ">=" (a verdict exactly 180 days old
    is already expired), per generate_stats.py's own comment. A future
    refactor that quietly swaps that for ">" should fail
    test_review_interval_boundary_is_inclusive, not slide through green.

  * verified_testing_disabled_current -- not verified_testing_disabled -- is
    what verified_current's denominator subtracts. A disabled NOT_VERIFIED
    verdict that has *also* gone stale must be counted once, not twice: once
    it ages past the review interval it is removed from the denominator as
    stale, and counting it again via the full verified_testing_disabled would
    double-subtract it and could drive verified_current negative.
    test_disabled_verdict_going_stale_is_not_double_subtracted pins the exact
    scenario from the 1.5 audit finding.
"""

from datetime import UTC, datetime, timedelta

import generate_stats as gs

FROZEN_NOW = datetime(2026, 8, 20, 12, 0, 0, tzinfo=UTC)


class _FrozenDatetime(datetime):
    """Stands in for gs.datetime so verdict ages are exact, not "however long
    this test takes to run" -- important right at the REVIEW_INTERVAL_DAYS
    boundary, where a slow test process could otherwise flip a day."""

    @classmethod
    def now(cls, tz=None):
        return FROZEN_NOW if tz is not None else FROZEN_NOW.replace(tzinfo=None)


def _patch_common(monkeypatch, rules, verdicts, rule_versions=None):
    """Wires generate_stats() to synthetic data only: no disk, no git, no network.

    rule_versions: optional {file_path: version} map, consulted by the
    compute_rule_version() stand-in so a test can force a rule's "current"
    version to differ from a verdict's recorded verdict_rule_version
    (simulating a superseded verdict) without needing a real git history.
    """
    rule_versions = rule_versions or {}

    monkeypatch.setattr(gs, "load_sigma_rules", lambda: rules)
    monkeypatch.setattr(gs, "load_verdicts", lambda: verdicts)
    monkeypatch.setattr(
        gs, "compute_rule_version",
        lambda file_path, repo_root=None, default="": rule_versions.get(file_path, "1.0"),
    )
    # Network call -- fixed return so a test never depends on MITRE's live feed.
    monkeypatch.setattr(gs, "fetch_mitre_techniques", lambda *a, **kw: (200, [], False))
    # git-history-backed trend cache -- writes to real outputs/reports/*.json
    # otherwise; no test here asserts on trend history, so it is a no-op.
    monkeypatch.setattr(gs, "update_trend_history", lambda stats: ([], []))
    monkeypatch.setattr(gs, "datetime", _FrozenDatetime)


def make_rule(detect_id, *, level="medium", status="stable", testing_enabled=True):
    return {
        "detect_id": detect_id,
        "title": f"Title for {detect_id}",
        "description": "",
        "level": level,
        "status": status,
        "tags": [],
        "logsource": {},
        "author": "test",
        "date": "2026/01/01",
        "modified": "2026/01/01",
        "references": [],
        "falsepositives": [],
        "detection": {"selection": {"a": "b"}, "condition": "selection"},
        "custom": {"testing": {"enabled": testing_enabled}},
        "_file_path": f"rules/sigma/{detect_id.lower()}.yml",
    }


def make_verdict(verdict, *, age_days=0, disabled=False, rule_version="1.0", run_id="run-1"):
    ts = FROZEN_NOW - timedelta(days=age_days)
    return {
        "verdict": verdict,
        "run_id": run_id,
        "run_timestamp": ts.isoformat(),
        "rule_version": rule_version,
        "disabled": disabled,
    }


# --- full aggregate: one of every state -------------------------------------


def test_full_aggregate_across_every_verdict_state(monkeypatch):
    """Ten rules, one per meaningfully distinct state, checked against
    hand-computed expected totals for every published counter."""
    rules = [
        make_rule("A"),  # PASS, current
        make_rule("B"),  # PASS, expired -> stale
        make_rule("C"),  # PASS, superseded -> stale
        make_rule("D"),  # FAIL, current
        make_rule("E"),  # FAIL, expired -> stale
        make_rule("F"),  # NOT_VERIFIED, not disabled, current
        make_rule("G"),  # NOT_VERIFIED, disabled, current
        make_rule("H"),  # NOT_VERIFIED, disabled, expired -> stale
        make_rule("I"),  # never tested
        make_rule("J"),  # never tested
    ]
    verdicts = {
        "A": make_verdict("PASS", age_days=10, rule_version="1.0"),
        "B": make_verdict("PASS", age_days=200, rule_version="1.0"),
        "C": make_verdict("PASS", age_days=10, rule_version="1.0"),
        "D": make_verdict("FAIL", age_days=5, rule_version="1.0"),
        "E": make_verdict("FAIL", age_days=200, rule_version="1.0"),
        "F": make_verdict("NOT_VERIFIED", age_days=5, disabled=False, rule_version="1.0"),
        "G": make_verdict("NOT_VERIFIED", age_days=5, disabled=True, rule_version="1.0"),
        "H": make_verdict("NOT_VERIFIED", age_days=200, disabled=True, rule_version="1.0"),
        # I, J: no verdict at all -> never_tested
    }
    # C's *current* rule version disagrees with its verdict's recorded
    # version -- a superseded verdict, not merely an old one.
    rule_versions = {"rules/sigma/c.yml": "2.0"}

    _patch_common(monkeypatch, rules, verdicts, rule_versions)
    stats = gs.generate_stats()

    assert stats["total_rules"] == 10
    assert stats["verified_pass"] == 3          # A, B, C
    assert stats["verified_fail"] == 2           # D, E
    assert stats["verified_not_verified"] == 3   # F, G, H
    assert stats["never_tested"] == 2            # I, J
    assert stats["not_verified"] == 5            # 3 + 2, backward-compat union

    assert stats["verified_stale"] == 4          # B, C, E, H
    assert stats["verified_superseded"] == 1     # C
    assert stats["verified_expired"] == 3        # B, E, H

    assert stats["verified_pass_current"] == 1   # A only
    assert stats["verified_fail_current"] == 1   # D only

    assert stats["verified_testing_disabled"] == 2          # G, H
    assert stats["verified_testing_disabled_current"] == 1  # G only (H is stale)

    assert stats["verified_current"] == 3  # 10 - 4(stale) - 2(never_tested) - 1(disabled_current)

    assert stats["pass_rate_pct"] == 33            # round(1/3 * 100)
    assert stats["verification_current_pct"] == 30  # round(3/10 * 100)
    assert stats["confirmed_working_pct"] == 10     # round(1/10 * 100)


# --- the 1.5 regression: disabled verdict aging into stale -------------------


def test_disabled_verdict_going_stale_is_not_double_subtracted(monkeypatch):
    """A disabled NOT_VERIFIED verdict, 200 days old: stale AND
    testing-disabled, but only removed from the denominator once.

    Pins the exact failure mode named in the 1.5 finding: a future edit that
    subtracts the *full* verified_testing_disabled (rather than the
    "-_current" subset already excluded via verified_stale) from
    verified_current would double-count this single rule and drive the
    denominator negative.
    """
    rules = [make_rule("DISABLED1")]
    verdicts = {
        "DISABLED1": make_verdict("NOT_VERIFIED", age_days=200, disabled=True, rule_version="1.0"),
    }
    _patch_common(monkeypatch, rules, verdicts)
    stats = gs.generate_stats()

    assert stats["verified_stale"] == 1
    assert stats["verified_expired"] == 1
    assert stats["verified_testing_disabled"] == 1
    assert stats["verified_testing_disabled_current"] == 0

    # 1 total - 1 stale - 0 never_tested - 0 disabled_current = 0, never negative.
    assert stats["verified_current"] == 0
    assert stats["verified_current"] >= 0
    assert stats["pass_rate_pct"] == 0
    assert stats["verification_current_pct"] == 0


# --- REVIEW_INTERVAL_DAYS boundary (>=), exactly at the line -----------------


def _single_pass_rule_stats(monkeypatch, age_days):
    rules = [make_rule("BOUNDARY")]
    verdicts = {
        "BOUNDARY": make_verdict("PASS", age_days=age_days, rule_version="1.0"),
    }
    _patch_common(monkeypatch, rules, verdicts)
    return gs.generate_stats()


def test_review_interval_boundary_just_under_is_still_current(monkeypatch):
    assert gs.REVIEW_INTERVAL_DAYS == 180
    stats = _single_pass_rule_stats(monkeypatch, 179)

    assert stats["verified_stale"] == 0
    assert stats["verified_expired"] == 0
    assert stats["verified_pass_current"] == 1
    assert stats["verified_current"] == 1


def test_review_interval_boundary_is_inclusive(monkeypatch):
    """The comment above the check in generate_stats.py says ">=" is the
    intended boundary: a verdict exactly REVIEW_INTERVAL_DAYS old is already
    expired, not "one day away from" expired. If a refactor ever changes the
    comparison to plain ">", this is the test that should catch it."""
    stats = _single_pass_rule_stats(monkeypatch, 180)

    assert stats["verified_stale"] == 1
    assert stats["verified_expired"] == 1
    assert stats["verified_pass_current"] == 0
    assert stats["verified_current"] == 0


def test_review_interval_boundary_just_over_is_expired(monkeypatch):
    stats = _single_pass_rule_stats(monkeypatch, 181)

    assert stats["verified_stale"] == 1
    assert stats["verified_expired"] == 1
    assert stats["verified_pass_current"] == 0
    assert stats["verified_current"] == 0


# --- never_tested / N/A does not participate in staleness at all -------------


def test_never_tested_rule_is_not_counted_as_stale(monkeypatch):
    """A rule with no verdict at all is "N/A", explicitly excluded from the
    staleness check (verdict not in ("N/A", "")) -- it should show up only
    in never_tested, never in verified_stale/_expired/_superseded."""
    rules = [make_rule("NEVERTESTED")]
    _patch_common(monkeypatch, rules, verdicts={})
    stats = gs.generate_stats()

    assert stats["never_tested"] == 1
    assert stats["verified_stale"] == 0
    assert stats["verified_expired"] == 0
    assert stats["verified_superseded"] == 0
    assert stats["verified_current"] == 0  # 1 total - 0 stale - 1 never_tested - 0
