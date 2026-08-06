"""ATT&CK tag validation against the cached technique map (register item 4.3).

Two things these tests are really guarding.

The first is that the checker stays offline. The map it validates against is
already in the repo -- generate_stats.py caches it to draw the coverage matrix --
and a validator that reaches out to the internet turns "is this tag real?" into
"is GitHub raw up right now?". test_the_checker_never_reaches_the_network holds
that line at the source level, because the day someone adds a fallback fetch is
the day the check silently starts passing for the wrong reason.

The second is the difference between "revoked" and "invented". The cache is
built from live techniques only, so a withdrawn technique is absent exactly like
a typo is. The sub-technique numbering is what separates them, and it only works
because ATT&CK never reuses a sub-technique number.
"""

import json

import pytest
import yaml
from check_mitre_tags import (
    DEFAULT_CACHE,
    ERROR,
    WARNING,
    TechniqueMap,
    check_rule,
    load_technique_map,
    main,
    split_tags,
    tactic_key,
)

# A miniature map with the shape generate_stats.py writes: main techniques
# carrying their sub-techniques, tactics as display names.
#
# T1003 stops at .003 on purpose -- .002 is the hole a revoked sub-technique
# leaves behind, and .009 sits above anything ever allocated. Those two cases
# are the entire reason this checker can say more than "not found".
FAKE_TECHNIQUES = [
    {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactics": ["Credential Access"],
        "subs": [
            {"id": "T1003.001", "name": "LSASS Memory", "tactics": ["Credential Access"]},
            {"id": "T1003.003", "name": "NTDS", "tactics": ["Credential Access"]},
        ],
    },
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactics": ["Execution"],
        "subs": [{"id": "T1059.001", "name": "PowerShell", "tactics": ["Execution"]}],
    },
    {
        "id": "T1564",
        "name": "Hide Artifacts",
        "tactics": ["Stealth"],
        "subs": [{"id": "T1564.003", "name": "Hidden Window", "tactics": ["Stealth"]}],
    },
    {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactics": ["Command & Control"],
        "subs": [],
    },
]


@pytest.fixture
def tmap():
    return TechniqueMap(FAKE_TECHNIQUES, fetched_at="2026-08-01T00:00:00+00:00")


def rule(tags, detect_id="DETECT-2026-0001"):
    return {"detect_id": detect_id, "tags": tags}


def reasons(findings):
    return [f["reason"] for f in findings]


def write_cache(tmp_path, techniques=None, fetched_at="2026-08-01T00:00:00+00:00"):
    path = tmp_path / "map.json"
    payload = {"fetched_at": fetched_at, "techniques": FAKE_TECHNIQUES if techniques is None else techniques}
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def write_rule(tmp_path, tags, name="rule.yml", detect_id="DETECT-2026-0001"):
    path = tmp_path / name
    path.write_text(yaml.safe_dump(rule(tags, detect_id)), encoding="utf-8")
    return path


# --- reading the tags --------------------------------------------------------


def test_tags_split_into_techniques_tactics_and_junk():
    techniques, tactics, malformed = split_tags(
        ["attack.execution", "attack.t1059.001", "attack.T1105", "attack.t123", "car.2013-05-004"]
    )

    assert techniques == [("attack.t1059.001", "T1059.001"), ("attack.t1105", "T1105")]
    assert tactics == [("attack.execution", "execution")]
    assert malformed == ["attack.t123"]


def test_non_attack_tags_are_none_of_our_business():
    assert split_tags(["cve.2021-44228", "detection.threat_hunting", "tlp.amber"]) == ([], [], [])


def test_group_software_and_mitigation_references_are_skipped_not_mistaken_for_tactics():
    """`attack.g0016` is a legitimate Sigma tag and there is nothing in the cache
    to validate it against. Silence is the honest answer; a finding would be a
    false positive on the checker's first contact with one."""
    techniques, tactics, malformed = split_tags(
        ["attack.g0016", "attack.s0002", "attack.m1040", "attack.ta0006", "attack.t1059.001"]
    )

    assert tactics == []
    assert malformed == []
    assert techniques == [("attack.t1059.001", "T1059.001")]


def test_tactic_key_reconciles_the_tag_form_with_the_display_form():
    """The two spellings of the same tactic have to compare equal without a
    third hardcoded copy of generate_stats.py's TACTIC_MAP living here."""
    assert tactic_key("command_and_control") == tactic_key("Command & Control")
    assert tactic_key("defense_impairment") == tactic_key("Defense Impairment")
    assert tactic_key("stealth") == tactic_key("Stealth")
    assert tactic_key("execution") != tactic_key("exfiltration")


# --- what the map can and cannot resolve -------------------------------------


def test_a_correctly_tagged_rule_produces_nothing(tmap, tmp_path):
    findings = check_rule(tmp_path / "r.yml", rule(["attack.execution", "attack.t1059.001"]), tmap)

    assert findings == []


def test_an_invented_technique_id_is_an_error(tmap, tmp_path):
    findings = check_rule(tmp_path / "r.yml", rule(["attack.execution", "attack.t9999"]), tmap)

    assert reasons(findings) == ["unknown_technique"]
    assert findings[0]["severity"] == ERROR


def test_a_gap_in_the_parents_numbering_is_reported_as_revoked(tmap, tmp_path):
    """T1003.002 sits between .001 and .003, so the number was allocated once.

    ATT&CK does not hand a sub-technique number out twice; the only way for it to
    be missing from a map built from live techniques is that it was withdrawn.
    """
    findings = check_rule(tmp_path / "r.yml", rule(["attack.credential_access", "attack.t1003.002"]), tmap)

    assert reasons(findings) == ["revoked_technique"]
    assert "revoked or deprecated" in findings[0]["message"]


def test_a_suffix_above_the_allocated_range_is_a_typo_not_a_revocation(tmap, tmp_path):
    findings = check_rule(tmp_path / "r.yml", rule(["attack.credential_access", "attack.t1003.009"]), tmap)

    assert reasons(findings) == ["unknown_subtechnique"]
    assert "typo" in findings[0]["message"]


def test_a_subtechnique_of_an_unknown_parent_is_just_unknown(tmap, tmp_path):
    """Main technique IDs are sparse, so absence proves nothing about allocation
    -- claiming 'revoked' here would be a guess dressed up as a finding."""
    findings = check_rule(tmp_path / "r.yml", rule(["attack.execution", "attack.t8888.001"]), tmap)

    assert reasons(findings) == ["unknown_technique"]


def test_a_malformed_technique_tag_is_caught_even_though_the_schema_accepts_it(tmap, tmp_path):
    """And only once: the malformed tag also leaves the technique side
    unreadable, so the tactic checks stay quiet rather than blaming
    `attack.execution` for a defect one line below it."""
    findings = check_rule(tmp_path / "r.yml", rule(["attack.execution", "attack.t1059.1"]), tmap)

    assert reasons(findings) == ["malformed_technique_tag"]


# --- tactic / technique agreement --------------------------------------------


def test_a_tactic_the_map_knows_but_no_technique_supports_is_a_mismatch(tmap, tmp_path):
    findings = check_rule(
        tmp_path / "r.yml", rule(["attack.credential_access", "attack.t1003.001", "attack.execution"]), tmap
    )

    assert reasons(findings) == ["tactic_mismatch"]
    assert findings[0]["severity"] == ERROR
    assert findings[0]["tag"] == "attack.execution"
    assert "T1003.001 (LSASS Memory)" in findings[0]["message"]


def test_an_upstream_tactic_name_this_repo_does_not_use_is_reported(tmap, tmp_path):
    """This repo's taxonomy has Stealth where upstream has Defense Evasion.
    `attack.defense_evasion` would sail through the schema and then drop the rule
    out of the coverage matrix, because no column is named that."""
    findings = check_rule(
        tmp_path / "r.yml", rule(["attack.defense_evasion", "attack.t1564.003"]), tmap
    )

    assert reasons(findings) == ["unknown_tactic"]


def test_one_disagreement_is_reported_once_not_from_both_sides(tmap, tmp_path):
    """A tactic error and the undeclared-tactic warning are the same fact.

    `credential_access` + T1059.001 is one mistake: the declared tactic is
    unsupported *and* Execution goes undeclared. Reporting both would double the
    finding count for a single edit, and the warning is the weaker statement.
    """
    findings = check_rule(
        tmp_path / "r.yml", rule(["attack.credential_access", "attack.t1059.001"]), tmap
    )

    assert reasons(findings) == ["tactic_mismatch"]


def test_a_mismatch_is_not_reported_when_a_technique_could_not_be_resolved(tmap, tmp_path):
    """The covered-tactic set is derived from the techniques that resolved.

    With one unresolved technique that set is incomplete, so a mismatch would be
    an artefact of the unknown-technique finding rather than a fact about the
    tactic tag. One rule, one cause, one finding.
    """
    findings = check_rule(
        tmp_path / "r.yml", rule(["attack.credential_access", "attack.t9999"]), tmap
    )

    assert reasons(findings) == ["unknown_technique"]


def test_a_technique_whose_tactic_is_not_declared_is_a_warning(tmap, tmp_path):
    findings = check_rule(tmp_path / "r.yml", rule(["attack.execution", "attack.t1059.001", "attack.t1564.003"]), tmap)

    assert reasons(findings) == ["undeclared_tactic"]
    assert findings[0]["severity"] == WARNING


def test_tagging_a_parent_next_to_its_own_subtechnique_is_a_warning(tmap, tmp_path):
    findings = check_rule(
        tmp_path / "r.yml", rule(["attack.credential_access", "attack.t1003", "attack.t1003.001"]), tmap
    )

    assert reasons(findings) == ["redundant_parent"]
    assert findings[0]["severity"] == WARNING


def test_two_unrelated_techniques_under_two_tactics_is_normal(tmap, tmp_path):
    findings = check_rule(
        tmp_path / "r.yml",
        rule(["attack.execution", "attack.t1059.001", "attack.stealth", "attack.t1564.003"]),
        tmap,
    )

    assert findings == []


# --- attack.stealth ----------------------------------------------------------


def test_attack_stealth_is_valid_here(tmap, tmp_path):
    """Not a special case in the normal path: this repo's ATT&CK taxonomy uses
    Stealth, the cached map has techniques under it, and the vocabulary is read
    from that map rather than from upstream's tactic list."""
    findings = check_rule(tmp_path / "r.yml", rule(["attack.stealth", "attack.t1564.003"]), tmap)

    assert findings == []


def test_attack_stealth_survives_a_map_that_does_not_mention_stealth(tmp_path):
    """The belt-and-braces half of the carve-out.

    A truncated or half-written cache must not be able to turn a correct tag into
    a finding and start a conversation about deleting it. Note this is about the
    tag's *validity*; the pairing check is a separate question.
    """
    stealthless = TechniqueMap(
        [{"id": "T1059", "name": "CSI", "tactics": ["Execution"], "subs": []}],
        fetched_at="2026-08-01T00:00:00+00:00",
    )

    findings = check_rule(tmp_path / "r.yml", rule(["attack.stealth", "attack.t1059"]), stealthless)

    assert "unknown_tactic" not in reasons(findings)


# --- the cache is an input, and its absence is the checker's failure ----------


def test_a_missing_cache_is_a_setup_failure_not_27_broken_rules(tmp_path, capsys):
    r = write_rule(tmp_path, ["attack.execution", "attack.t1059.001"])

    assert main(["--cache", str(tmp_path / "nope.json"), str(r)]) == 2
    assert "will not fetch" in capsys.readouterr().err


def test_an_empty_cache_refuses_to_report_rather_than_condemn_everything(tmp_path, capsys):
    cache = write_cache(tmp_path, techniques=[])
    r = write_rule(tmp_path, ["attack.execution", "attack.t1059.001"])

    assert main(["--cache", str(cache), str(r)]) == 2
    assert "refusing" in capsys.readouterr().err.lower()


def test_a_corrupt_cache_is_a_setup_failure(tmp_path):
    cache = tmp_path / "map.json"
    cache.write_text("{not json", encoding="utf-8")

    assert main(["--cache", str(cache)]) == 2


def test_a_cache_without_a_techniques_list_is_a_setup_failure(tmp_path):
    cache = tmp_path / "map.json"
    cache.write_text(json.dumps({"fetched_at": "2026-08-01T00:00:00+00:00"}), encoding="utf-8")

    assert main(["--cache", str(cache)]) == 2


def test_a_stale_cache_warns_but_never_fetches(tmp_path, capsys):
    cache = write_cache(tmp_path, fetched_at="2020-01-01T00:00:00+00:00")
    r = write_rule(tmp_path, ["attack.execution", "attack.t1059.001"])

    assert main(["--cache", str(cache), str(r)]) == 0
    assert "Stale ATT&CK technique map" in capsys.readouterr().out


def test_malformed_cache_entries_are_ignored_rather_than_crashing():
    tm = TechniqueMap(["not a dict", {"no": "id"}, {"id": "T1059", "name": "CSI", "tactics": ["Execution"]}])

    assert len(tm) == 1
    assert tm.get("t1059")["name"] == "CSI"


# --- CLI ---------------------------------------------------------------------


def test_cli_reports_advisory_and_exits_zero_by_default(tmp_path, capsys):
    """Same stance as the routing checker: a mistagged rule is still a rule
    worth deploying, and a checker that blocks by default before anyone has
    seen its output gets switched off rather than fixed."""
    cache = write_cache(tmp_path)
    r = write_rule(tmp_path, ["attack.execution", "attack.t9999"])

    assert main(["--cache", str(cache), str(r)]) == 0
    out = capsys.readouterr().out
    assert "::warning" in out
    assert "::error" not in out


def test_cli_exits_one_under_strict_and_raises_the_annotation(tmp_path, capsys):
    cache = write_cache(tmp_path)
    r = write_rule(tmp_path, ["attack.execution", "attack.t9999"])

    assert main(["--cache", str(cache), "--strict", str(r)]) == 1
    assert "::error" in capsys.readouterr().out


def test_warnings_alone_do_not_fail_even_under_strict(tmp_path):
    cache = write_cache(tmp_path)
    r = write_rule(tmp_path, ["attack.credential_access", "attack.t1003", "attack.t1003.001"])

    assert main(["--cache", str(cache), "--strict", str(r)]) == 0


def test_a_clean_run_says_nothing_alarming(tmp_path, capsys):
    cache = write_cache(tmp_path)
    r = write_rule(tmp_path, ["attack.execution", "attack.t1059.001"])

    assert main(["--cache", str(cache), str(r)]) == 0
    out = capsys.readouterr().out
    assert "::warning" not in out
    assert "Errors:   0" in out


def test_an_unreadable_rule_is_skipped_not_fatal(tmp_path, capsys):
    """validate_sigma.py owns malformed YAML and already fails the run for it."""
    cache = write_cache(tmp_path)
    bad = tmp_path / "bad.yml"
    bad.write_text("title: [unclosed\n", encoding="utf-8")

    assert main(["--cache", str(cache), str(bad)]) == 0
    assert "SKIP" in capsys.readouterr().err


def test_a_rule_without_tags_is_left_to_the_schema(tmp_path):
    cache = write_cache(tmp_path)
    path = tmp_path / "r.yml"
    path.write_text(yaml.safe_dump({"detect_id": "DETECT-2026-0001", "title": "x"}), encoding="utf-8")

    assert main(["--cache", str(cache), str(path)]) == 0


def test_json_output_records_the_cache_and_the_findings(tmp_path):
    cache = write_cache(tmp_path)
    r = write_rule(tmp_path, ["attack.credential_access", "attack.t1003.002"])
    out = tmp_path / "out" / "mitre.json"

    main(["--cache", str(cache), "--json", str(out), str(r)])

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["checked"] == 1
    assert data["errors"] == 1
    assert data["cache_fetched_at"] == "2026-08-01T00:00:00+00:00"
    assert data["findings"][0]["reason"] == "revoked_technique"


def test_step_summary_is_appended_when_github_provides_one(tmp_path, monkeypatch):
    cache = write_cache(tmp_path)
    r = write_rule(tmp_path, ["attack.execution", "attack.t9999"])
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))

    main(["--cache", str(cache), str(r)])

    text = summary.read_text(encoding="utf-8")
    assert "MITRE ATT&CK tag findings" in text
    assert "T9999" in text


def test_a_clean_run_writes_no_step_summary(tmp_path, monkeypatch):
    cache = write_cache(tmp_path)
    r = write_rule(tmp_path, ["attack.execution", "attack.t1059.001"])
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))

    main(["--cache", str(cache), str(r)])

    assert not summary.exists()


# --- the committed repo ------------------------------------------------------


def test_the_checker_never_reaches_the_network():
    """The whole point of item 4.3 is that the data is already here.

    A fallback fetch would make validation depend on GitHub raw being up, and --
    worse -- would let the check pass for the wrong reason on the day it is down.
    """
    import check_mitre_tags

    source = pytest.importorskip("pathlib").Path(check_mitre_tags.__file__).read_text(encoding="utf-8")

    for forbidden in ("urllib", "requests", "http.client", "socket"):
        assert forbidden not in source, f"{forbidden} has no business in an offline validator"


def test_the_committed_cache_is_usable():
    """If this fails, every finding below is meaningless."""
    tm = load_technique_map(DEFAULT_CACHE)

    assert tm.main_count() > 100
    assert tm.get("T1003") is not None
    assert "stealth" in tm.tactics


def test_every_committed_rule_has_valid_attack_tags():
    """Guards the current repo: all 27 rules are clean against the cached map today.

    A regression here is a rule that ships tagged with a technique that does not
    exist, or a tactic no technique on it supports -- either way it disappears
    from the coverage view it was written to appear in.
    """
    tm = load_technique_map(DEFAULT_CACHE)
    rules_dir = DEFAULT_CACHE.parents[2] / "rules" / "sigma"

    problems = []
    for path in sorted(rules_dir.glob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        problems += [f for f in check_rule(path, data, tm) if f["severity"] == ERROR]

    assert not problems, "\n".join(f"{p['detect_id']}: {p['message']}" for p in problems)


def test_no_committed_rule_carries_a_tag_warning_either():
    """A tripwire, not a law. Relaxing it is a decision someone makes on purpose
    -- today the repo is clean of undeclared tactics and redundant parents too,
    and that is worth knowing when it stops being true."""
    tm = load_technique_map(DEFAULT_CACHE)
    rules_dir = DEFAULT_CACHE.parents[2] / "rules" / "sigma"

    problems = []
    for path in sorted(rules_dir.glob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        problems += [f for f in check_rule(path, data, tm) if f["severity"] == WARNING]

    assert not problems, "\n".join(f"{p['detect_id']}: {p['message']}" for p in problems)
