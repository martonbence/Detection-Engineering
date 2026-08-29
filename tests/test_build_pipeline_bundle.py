"""prepare_validate_convert's "Build pipeline bundle" step
(audit/feature-and-process-audit.md item 4.1, slice 5 of 5 -- slice 1 was
determine_changed_rules.py, slice 2 was merge_verification_results.py,
slice 3 was open_promotion_pr.py, slice 4 was reconcile_step.py).

This step assembles the exact bundle prod's build-provenance attestation
verifies against, so a packaging omission here (a missed lib/ module, a
scoping mistake between "attested this run" and "sidecar coverage only")
reproduces incidents this repo has already paid for once
(audit/remediation-plan.md items 3.6 and 3.2 -- see the module docstring).
These tests exist because that history depended on subtle reasoning
actionlint/shellcheck could never verify, same motivation as slices 1-4.

Selection/validation (select_changed_rule_files / select_unchanged_rule_files)
is exercised with an injected `exists` fake -- no real generated SPL/meta
files needed. The filesystem half (skeleton, wholesale lib/ copy,
__pycache__ pruning, per-rule copies) is exercised against real tmp_path
trees, same choice slice 2 made for its overlay/delta file merges.
"""

from __future__ import annotations

import pytest
from build_pipeline_bundle import (
    BundleError,
    RuleBundlePaths,
    append_to,
    bundle_paths_for_rule,
    copy_fixed_scripts,
    copy_lib_wholesale,
    copy_rule_pair,
    derive_rule_basename,
    parse_rule_list,
    prepare_bundle_skeleton,
    prune_pycache,
    render_kv,
    render_multiline,
    run_step,
    select_changed_rule_files,
    select_unchanged_rule_files,
)

# --- derive_rule_basename (pure) ---------------------------------------------


def test_yml_suffix_is_stripped():
    assert derive_rule_basename("rules/sigma/windows/proc_creation_foo.yml") == "proc_creation_foo"


def test_yaml_suffix_is_stripped():
    assert derive_rule_basename("rules/sigma/windows/proc_creation_foo.yaml") == "proc_creation_foo"


def test_sigma_suffix_is_stripped():
    assert derive_rule_basename("rules/sigma/proc_creation_foo.sigma") == "proc_creation_foo"


def test_basename_drops_the_directory_component():
    assert derive_rule_basename("rules/sigma/a/b/c/detect_1234.yml") == "detect_1234"


def test_a_name_with_no_matching_suffix_is_left_alone():
    assert derive_rule_basename("rules/sigma/oddball") == "oddball"


# --- bundle_paths_for_rule (pure) --------------------------------------------


def test_bundle_paths_mirror_rules_splunk():
    paths = bundle_paths_for_rule("detect_1234")
    assert paths == RuleBundlePaths(
        spl_path="rules/splunk/detect_1234.spl",
        meta_path="rules/splunk/detect_1234.meta.json",
    )


# --- parse_rule_list (pure) --------------------------------------------------


def test_parse_rule_list_splits_on_newlines_no_trailing_blank():
    assert parse_rule_list("rules/sigma/a.yml\nrules/sigma/b.yml\n") == [
        "rules/sigma/a.yml",
        "rules/sigma/b.yml",
    ]


def test_parse_rule_list_on_a_lone_blank_line_is_one_empty_string():
    """Mirrors `mapfile` over the old heredoc-interpolated "zero rules" case:
    one empty-string element, not zero -- see the module docstring."""
    assert parse_rule_list("\n") == [""]


def test_parse_rule_list_on_a_fully_empty_value_is_zero_elements():
    assert parse_rule_list("") == []


# --- select_changed_rule_files (pure, injected exists) -----------------------


def _always_exists(_path: str) -> bool:
    return True


def _none_exist(_path: str) -> bool:
    return False


def test_selecting_changed_rules_returns_bundle_paths_in_order():
    result = select_changed_rule_files(
        ["rules/sigma/a.yml", "rules/sigma/b.yaml"],
        exists=_always_exists,
    )
    assert result == [
        RuleBundlePaths(spl_path="rules/splunk/a.spl", meta_path="rules/splunk/a.meta.json"),
        RuleBundlePaths(spl_path="rules/splunk/b.spl", meta_path="rules/splunk/b.meta.json"),
    ]


def test_blank_entries_are_skipped_in_changed_rules():
    result = select_changed_rule_files(["", "rules/sigma/a.yml", ""], exists=_always_exists)
    assert [p.spl_path for p in result] == ["rules/splunk/a.spl"]


def test_a_lone_blank_line_selects_nothing():
    """The "zero rules" env-var case from parse_rule_list(): one blank
    element, filtered down to an empty selection, exactly like the shell's
    `[[ -z "$rule" ]] && continue` over a one-element blank mapfile array."""
    assert select_changed_rule_files(parse_rule_list("\n"), exists=_always_exists) == []


def test_changed_rule_missing_spl_is_a_hard_failure():
    def exists(path: str) -> bool:
        return not path.endswith(".spl")

    with pytest.raises(BundleError) as excinfo:
        select_changed_rule_files(["rules/sigma/a.yml"], exists=exists)
    assert str(excinfo.value) == "Expected generated SPL file is missing: rules/splunk/a.spl"


def test_changed_rule_missing_meta_is_a_hard_failure():
    def exists(path: str) -> bool:
        return not path.endswith(".meta.json")

    with pytest.raises(BundleError) as excinfo:
        select_changed_rule_files(["rules/sigma/a.yml"], exists=exists)
    assert str(excinfo.value) == "Expected generated meta sidecar is missing: rules/splunk/a.meta.json"


def test_a_changed_rule_missing_everything_reports_spl_first():
    # spl_path is checked before meta_path, same order as the shell.
    with pytest.raises(BundleError) as excinfo:
        select_changed_rule_files(["rules/sigma/a.yml"], exists=_none_exist)
    assert "SPL file" in str(excinfo.value)


# --- select_unchanged_rule_files (pure, injected exists) ---------------------


def test_selecting_unchanged_rules_returns_meta_only_paths():
    result = select_unchanged_rule_files(["rules/sigma/c.yml"], exists=_always_exists)
    assert result == [RuleBundlePaths(spl_path="rules/splunk/c.spl", meta_path="rules/splunk/c.meta.json")]


def test_unchanged_rule_missing_meta_is_a_hard_failure():
    with pytest.raises(BundleError) as excinfo:
        select_unchanged_rule_files(["rules/sigma/c.yml"], exists=_none_exist)
    assert str(excinfo.value) == "Expected refreshed meta sidecar is missing: rules/splunk/c.meta.json"


def test_blank_entries_are_skipped_in_unchanged_rules():
    result = select_unchanged_rule_files(["", ""], exists=_always_exists)
    assert result == []


# --- $GITHUB_OUTPUT formatting (pure) -----------------------------------------


def test_has_spl_true_kv():
    assert render_kv("has_spl", "true") == "has_spl=true\n"


def test_populated_spl_files_block_matches_the_heredoc_format():
    assert render_multiline("spl_files", ["rules/splunk/a.spl", "rules/splunk/b.spl"]) == (
        "spl_files<<EOF\nrules/splunk/a.spl\nrules/splunk/b.spl\nEOF\n"
    )


def test_empty_spl_files_block_has_no_body_line_at_all():
    """The one asymmetry kept from the shell: the "no SPL files" path wrote
    the two markers with plain echos and no printf between them."""
    assert render_multiline("spl_files", (), blank_when_empty=False) == "spl_files<<EOF\nEOF\n"


def test_append_to_writes_to_the_named_env_file(tmp_path, monkeypatch):
    out = tmp_path / "github_output"
    out.write_text("", encoding="utf-8")
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    append_to("GITHUB_OUTPUT", "has_spl=true\n")
    assert out.read_text(encoding="utf-8") == "has_spl=true\n"


def test_append_to_without_the_env_var_set_does_not_raise(monkeypatch):
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    append_to("GITHUB_OUTPUT", "has_spl=true\n")  # no exception


# --- the filesystem I/O half (real tmp_path trees) ----------------------------


def _make_repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / "scripts" / "atomic").mkdir(parents=True)
    (repo / "scripts" / "deploy").mkdir(parents=True)
    (repo / "scripts" / "lib").mkdir(parents=True)
    (repo / "scripts" / "atomic" / "run_atomic.ps1").write_text("# atomic\n", encoding="utf-8")
    (repo / "scripts" / "deploy" / "deploy_spl_to_splunk.py").write_text("# deploy\n", encoding="utf-8")
    (repo / "scripts" / "deploy" / "check_spl_syntax.py").write_text("# syntax\n", encoding="utf-8")
    (repo / "scripts" / "lib" / "env.py").write_text("# env\n", encoding="utf-8")
    (repo / "scripts" / "lib" / "rule_naming.py").write_text("# naming\n", encoding="utf-8")
    pycache = repo / "scripts" / "lib" / "__pycache__"
    pycache.mkdir()
    (pycache / "env.cpython-311.pyc").write_bytes(b"\x00\x01")
    (repo / "rules" / "splunk").mkdir(parents=True)
    return repo


def test_prepare_bundle_skeleton_wipes_and_recreates(tmp_path):
    bundle = tmp_path / "pipeline_bundle"
    (bundle / "stale").mkdir(parents=True)
    (bundle / "stale" / "leftover.txt").write_text("x", encoding="utf-8")

    prepare_bundle_skeleton(bundle)

    assert not (bundle / "stale").exists()
    assert (bundle / "scripts" / "atomic").is_dir()
    assert (bundle / "scripts" / "deploy").is_dir()
    assert (bundle / "scripts" / "lib").is_dir()


def test_copy_fixed_scripts_copies_all_three_named_files(tmp_path):
    repo = _make_repo(tmp_path)
    bundle = tmp_path / "pipeline_bundle"
    prepare_bundle_skeleton(bundle)

    copy_fixed_scripts(repo, bundle)

    assert (bundle / "scripts" / "atomic" / "run_atomic.ps1").read_text(encoding="utf-8") == "# atomic\n"
    assert (bundle / "scripts" / "deploy" / "deploy_spl_to_splunk.py").read_text(encoding="utf-8") == "# deploy\n"
    assert (bundle / "scripts" / "deploy" / "check_spl_syntax.py").read_text(encoding="utf-8") == "# syntax\n"


def test_copy_lib_wholesale_copies_everything_without_double_nesting(tmp_path):
    repo = _make_repo(tmp_path)
    bundle = tmp_path / "pipeline_bundle"
    prepare_bundle_skeleton(bundle)

    copy_lib_wholesale(repo, bundle)

    # Contents land directly under scripts/lib/, not scripts/lib/lib/.
    assert (bundle / "scripts" / "lib" / "env.py").is_file()
    assert (bundle / "scripts" / "lib" / "rule_naming.py").is_file()
    assert not (bundle / "scripts" / "lib" / "lib").exists()


def test_copy_lib_wholesale_carries_pycache_before_pruning(tmp_path):
    repo = _make_repo(tmp_path)
    bundle = tmp_path / "pipeline_bundle"
    prepare_bundle_skeleton(bundle)

    copy_lib_wholesale(repo, bundle)

    assert (bundle / "scripts" / "lib" / "__pycache__").is_dir()


def test_prune_pycache_removes_it(tmp_path):
    repo = _make_repo(tmp_path)
    bundle = tmp_path / "pipeline_bundle"
    prepare_bundle_skeleton(bundle)
    copy_lib_wholesale(repo, bundle)

    prune_pycache(bundle / "scripts" / "lib")

    assert not (bundle / "scripts" / "lib" / "__pycache__").exists()
    # Everything else survives the prune.
    assert (bundle / "scripts" / "lib" / "env.py").is_file()


def test_prune_pycache_on_a_tree_with_none_is_a_no_op(tmp_path):
    lib_dir = tmp_path / "lib"
    lib_dir.mkdir()
    (lib_dir / "env.py").write_text("# env\n", encoding="utf-8")

    prune_pycache(lib_dir)  # no exception

    assert (lib_dir / "env.py").is_file()


def test_copy_rule_pair_with_spl_copies_both_files(tmp_path):
    repo = _make_repo(tmp_path)
    bundle = tmp_path / "pipeline_bundle"
    prepare_bundle_skeleton(bundle)
    (repo / "rules" / "splunk" / "a.spl").write_text("search ...", encoding="utf-8")
    (repo / "rules" / "splunk" / "a.meta.json").write_text("{}", encoding="utf-8")

    copy_rule_pair(repo, bundle, bundle_paths_for_rule("a"), include_spl=True)

    assert (bundle / "rules" / "splunk" / "a.spl").read_text(encoding="utf-8") == "search ..."
    assert (bundle / "rules" / "splunk" / "a.meta.json").read_text(encoding="utf-8") == "{}"


def test_copy_rule_pair_without_spl_copies_only_meta(tmp_path):
    repo = _make_repo(tmp_path)
    bundle = tmp_path / "pipeline_bundle"
    prepare_bundle_skeleton(bundle)
    (repo / "rules" / "splunk" / "c.meta.json").write_text("{}", encoding="utf-8")

    copy_rule_pair(repo, bundle, bundle_paths_for_rule("c"), include_spl=False)

    assert (bundle / "rules" / "splunk" / "c.meta.json").is_file()
    assert not (bundle / "rules" / "splunk" / "c.spl").exists()


# --- run_step (orchestration, real tmp_path repo + bundle) --------------------


def _seed_rule(repo, name, *, spl=True, meta=True):
    if spl:
        (repo / "rules" / "splunk" / f"{name}.spl").write_text(f"search {name}", encoding="utf-8")
    if meta:
        (repo / "rules" / "splunk" / f"{name}.meta.json").write_text("{}", encoding="utf-8")


def test_run_step_empty_changed_rules_reports_has_spl_false(tmp_path):
    repo = _make_repo(tmp_path)
    bundle = tmp_path / "pipeline_bundle"
    logs: list[str] = []
    outputs: list[str] = []

    rc = run_step(
        repo_root=repo,
        bundle_dir=bundle,
        rule_files=[],
        unchanged_rule_files=[],
        log=logs.append,
        append_output=outputs.append,
    )

    assert rc == 0
    assert "No generated SPL files found." in logs
    assert outputs == ["has_spl=false\n", "spl_files<<EOF\nEOF\n"]
    # The skeleton + fixed scripts + lib were still assembled.
    assert (bundle / "scripts" / "lib" / "env.py").is_file()


def test_run_step_populated_case_writes_has_spl_true_and_the_file_list(tmp_path):
    repo = _make_repo(tmp_path)
    _seed_rule(repo, "a")
    _seed_rule(repo, "b")
    bundle = tmp_path / "pipeline_bundle"
    logs: list[str] = []
    outputs: list[str] = []

    rc = run_step(
        repo_root=repo,
        bundle_dir=bundle,
        rule_files=["rules/sigma/a.yml", "rules/sigma/b.yml"],
        unchanged_rule_files=[],
        log=logs.append,
        append_output=outputs.append,
    )

    assert rc == 0
    assert outputs == [
        "has_spl=true\n",
        "spl_files<<EOF\nrules/splunk/a.spl\nrules/splunk/b.spl\nEOF\n",
    ]
    assert (bundle / "rules" / "splunk" / "a.spl").is_file()
    assert (bundle / "rules" / "splunk" / "b.spl").is_file()
    assert any("Generated SPL files selected" in line for line in logs)


def test_run_step_unchanged_rule_is_copied_but_never_in_spl_files(tmp_path):
    repo = _make_repo(tmp_path)
    _seed_rule(repo, "a")
    _seed_rule(repo, "c", spl=False)  # unchanged: sidecar refreshed, no .spl expected here
    bundle = tmp_path / "pipeline_bundle"
    outputs: list[str] = []

    rc = run_step(
        repo_root=repo,
        bundle_dir=bundle,
        rule_files=["rules/sigma/a.yml"],
        unchanged_rule_files=["rules/sigma/c.yml"],
        log=lambda _m: None,
        append_output=outputs.append,
    )

    assert rc == 0
    assert (bundle / "rules" / "splunk" / "c.meta.json").is_file()
    assert not (bundle / "rules" / "splunk" / "c.spl").exists()
    # spl_files only ever names the changed rule.
    assert outputs == ["has_spl=true\n", "spl_files<<EOF\nrules/splunk/a.spl\nEOF\n"]


def test_run_step_changed_rule_missing_spl_fails_hard(tmp_path):
    repo = _make_repo(tmp_path)
    # a.spl deliberately not seeded.
    (repo / "rules" / "splunk" / "a.meta.json").write_text("{}", encoding="utf-8")
    bundle = tmp_path / "pipeline_bundle"
    logs: list[str] = []

    rc = run_step(
        repo_root=repo,
        bundle_dir=bundle,
        rule_files=["rules/sigma/a.yml"],
        unchanged_rule_files=[],
        log=logs.append,
        append_output=lambda _t: None,
    )

    assert rc == 1
    assert "Expected generated SPL file is missing: rules/splunk/a.spl" in logs


def test_run_step_changed_rule_missing_meta_fails_hard(tmp_path):
    repo = _make_repo(tmp_path)
    (repo / "rules" / "splunk" / "a.spl").write_text("search a", encoding="utf-8")
    # a.meta.json deliberately not seeded.
    bundle = tmp_path / "pipeline_bundle"
    logs: list[str] = []

    rc = run_step(
        repo_root=repo,
        bundle_dir=bundle,
        rule_files=["rules/sigma/a.yml"],
        unchanged_rule_files=[],
        log=logs.append,
        append_output=lambda _t: None,
    )

    assert rc == 1
    assert "Expected generated meta sidecar is missing: rules/splunk/a.meta.json" in logs


def test_run_step_unchanged_rule_missing_meta_fails_hard(tmp_path):
    repo = _make_repo(tmp_path)
    _seed_rule(repo, "a")
    # c.meta.json deliberately not seeded.
    bundle = tmp_path / "pipeline_bundle"
    logs: list[str] = []

    rc = run_step(
        repo_root=repo,
        bundle_dir=bundle,
        rule_files=["rules/sigma/a.yml"],
        unchanged_rule_files=["rules/sigma/c.yml"],
        log=logs.append,
        append_output=lambda _t: None,
    )

    assert rc == 1
    assert "Expected refreshed meta sidecar is missing: rules/splunk/c.meta.json" in logs


def test_run_step_a_lone_blank_line_in_both_inputs_is_the_empty_case(tmp_path):
    """Both env vars arriving as parse_rule_list("\\n") -- the "zero rules"
    shape -- still resolves to has_spl=false, not a crash."""
    repo = _make_repo(tmp_path)
    bundle = tmp_path / "pipeline_bundle"
    outputs: list[str] = []

    rc = run_step(
        repo_root=repo,
        bundle_dir=bundle,
        rule_files=parse_rule_list("\n"),
        unchanged_rule_files=parse_rule_list("\n"),
        log=lambda _m: None,
        append_output=outputs.append,
    )

    assert rc == 0
    assert outputs == ["has_spl=false\n", "spl_files<<EOF\nEOF\n"]
