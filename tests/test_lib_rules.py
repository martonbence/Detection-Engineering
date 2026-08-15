"""Tests for scripts/lib/rules.py -- register item 3.1.

The interesting tests here are not the unit tests on `discover()` and
`load_rule()`; they are the two at the bottom. One asserts that every consumer
resolves the *same* function, so a hand-rolled glob sneaked back in later is
caught mechanically rather than by review. The other builds the layout that
would have triggered the original defect -- a subdirectory and a `.yaml` file --
and asserts the whole library is still visible.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from lib.rules import (
    DEFAULT_RULES_DIR,
    RuleLoadError,
    detect_id,
    discover,
    is_deprecated,
    load_rule,
    status,
    title,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

MINIMAL_RULE = {
    "title": "Example",
    "detect_id": "DETECT-2026-9999",
    "status": "test",
    "logsource": {"product": "windows"},
    "detection": {"sel": {"EventID": 1}, "condition": "sel"},
}


def write_rule(path: Path, **overrides) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({**MINIMAL_RULE, **overrides}), encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# discover()
# --------------------------------------------------------------------------


def test_discover_finds_both_extensions(tmp_path):
    a = write_rule(tmp_path / "a.yml")
    b = write_rule(tmp_path / "b.yaml")
    assert discover(tmp_path) == sorted([a, b])


def test_discover_is_recursive(tmp_path):
    """The defect this module exists for.

    Three of the six discoverers used a flat `glob`, so a rule moved into a
    subdirectory became invisible to them -- and invisible, to prune_orphans and
    reconcile, means "orphaned", which means deleted and disabled.
    """
    top = write_rule(tmp_path / "top.yml")
    nested = write_rule(tmp_path / "credential_access" / "nested.yml")
    deeper = write_rule(tmp_path / "credential_access" / "dumping" / "deep.yaml")

    assert discover(tmp_path) == sorted([top, nested, deeper])


def test_discover_is_sorted_and_deduplicated(tmp_path):
    for name in ("c.yml", "a.yml", "b.yaml"):
        write_rule(tmp_path / name)

    found = discover(tmp_path)

    assert found == sorted(found), "consumers render ordered output; order must be stable"
    assert len(found) == len(set(found))


def test_discover_ignores_non_rule_files(tmp_path):
    write_rule(tmp_path / "rule.yml")
    (tmp_path / "notes.md").write_text("not a rule", encoding="utf-8")
    (tmp_path / "data.json").write_text("{}", encoding="utf-8")

    assert [p.name for p in discover(tmp_path)] == ["rule.yml"]


def test_discover_missing_directory_is_empty_not_an_error(tmp_path):
    assert discover(tmp_path / "does-not-exist") == []


def test_discover_defaults_to_the_repo_rule_directory():
    assert Path("rules/sigma") == DEFAULT_RULES_DIR


# --------------------------------------------------------------------------
# load_rule()
# --------------------------------------------------------------------------


def test_load_rule_returns_the_mapping(tmp_path):
    path = write_rule(tmp_path / "r.yml", title="Specific")
    assert load_rule(path)["title"] == "Specific"


def test_load_rule_raises_on_missing_file(tmp_path):
    with pytest.raises(RuleLoadError, match="Could not read"):
        load_rule(tmp_path / "nope.yml")


def test_load_rule_raises_on_unparseable_yaml(tmp_path):
    path = tmp_path / "bad.yml"
    path.write_text("title: [unclosed\n", encoding="utf-8")
    with pytest.raises(RuleLoadError, match="Could not parse"):
        load_rule(path)


def test_load_rule_raises_on_empty_file(tmp_path):
    """The deliberate contract change.

    `safe_load("")` is None, and the previous `or {}` turned that into an empty
    dict that flowed on as though it were a rule with no fields. prune_orphans
    and reconcile would then act on it -- which is exactly what their own
    comments say must never be guessed at.
    """
    path = tmp_path / "empty.yml"
    path.write_text("", encoding="utf-8")
    with pytest.raises(RuleLoadError, match="empty"):
        load_rule(path)


def test_load_rule_raises_on_a_document_that_is_not_a_mapping(tmp_path):
    path = tmp_path / "list.yml"
    path.write_text("- one\n- two\n", encoding="utf-8")
    with pytest.raises(RuleLoadError, match="list"):
        load_rule(path)


# --------------------------------------------------------------------------
# Field helpers
# --------------------------------------------------------------------------


def test_detect_id_and_title_strip():
    rule = {"detect_id": "  DETECT-2026-0001  ", "title": "  Spaced  "}
    assert detect_id(rule) == "DETECT-2026-0001"
    assert title(rule) == "Spaced"


@pytest.mark.parametrize("rule", [{}, {"detect_id": None}, {"detect_id": ""}, {"detect_id": "   "}])
def test_detect_id_is_empty_never_the_string_none(rule):
    """`detect_id:` with nothing after it parses to None.

    `str(None)` is "None", which would be compared against Splunk object names
    and quietly match nothing -- the failure would look like an orphan.
    """
    assert detect_id(rule) == ""


def test_status_is_lowercased():
    assert status({"status": "  Deprecated "}) == "deprecated"


@pytest.mark.parametrize(
    ("value", "expected"),
    [("deprecated", True), ("DEPRECATED", True), ("stable", False), (None, False)],
)
def test_is_deprecated(value, expected):
    assert is_deprecated({"status": value}) is expected


# --------------------------------------------------------------------------
# The guards
# --------------------------------------------------------------------------

# Every module that discovers rules for itself. sigma_to_spl.py and
# validate_sigma.py are absent on purpose: the workflow hands them an explicit
# file list, so they never glob.
CONSUMERS = (
    "scripts/docs/generate_stats.py",
    "scripts/state/prune_orphans.py",
    "scripts/state/reconcile.py",
    "scripts/state/select_unverified.py",
    "scripts/validate/check_mitre_tags.py",
    "scripts/validate/check_test_routing.py",
)

# Matches a rule-file glob written by hand. Deliberately narrow: it looks for
# globbing on a yml/yaml pattern, not for the word "glob", so unrelated globbing
# (the .spl and result.json scans) stays allowed.
HANDROLLED_GLOB = re.compile(r"r?glob\(\s*f?[\"'][^\"']*\.ya?ml[\"']")


@pytest.mark.parametrize("relpath", CONSUMERS)
def test_no_consumer_rolls_its_own_rule_glob(relpath):
    """The mechanical guard against the defect coming back.

    Six modules had four different answers to "which files are rules". They
    agreed only because the layout happened to be flat and single-extension.
    This fails the moment someone reintroduces a local glob.
    """
    source = (REPO_ROOT / relpath).read_text(encoding="utf-8")
    found = HANDROLLED_GLOB.findall(source)
    assert not found, f"{relpath} globs for rule files itself instead of using lib.rules.discover: {found}"


def test_every_consumer_resolves_the_same_discover():
    """Mirrors the env_bool identity test from item 3.6.

    Importing the name is not enough -- what matters is that all of them end up
    calling one function, so a change to discovery reaches every consumer.
    """
    import generate_stats
    import prune_orphans
    import reconcile

    assert generate_stats.discover is discover
    assert prune_orphans.discover is discover
    assert reconcile.discover is discover

    # The other three import inside main() to keep their pyyaml guard reachable
    # (a top-level import of lib.rules would raise before the friendly message).
    # Resolving the module attribute is the equivalent assertion for them.
    import check_mitre_tags
    import check_test_routing
    import select_unverified

    for module in (check_mitre_tags, check_test_routing, select_unverified):
        source = Path(module.__file__).read_text(encoding="utf-8")
        assert "from lib.rules import" in source, f"{module.__name__} does not use lib.rules"


def test_the_whole_repo_library_loads(tmp_path):
    """Every committed rule parses through the shared loader.

    Cheap, and it is the assertion that would fail first if load_rule()'s
    contract ever drifted away from what the real library contains.
    """
    paths = discover(REPO_ROOT / "rules" / "sigma")
    assert len(paths) >= 20, "expected the committed rule library, got almost nothing"

    for path in paths:
        rule = load_rule(path)
        assert detect_id(rule), f"{path} has no detect_id"
