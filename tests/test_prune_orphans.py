"""Repo-side half of register item 1.7: artefacts of rules that no longer exist.

A deleted rule leaves its converted .spl behind (which prod keeps deploying,
since prod reads `git ls-files`) and its results directory behind (which keeps
counting towards the dashboard's coverage). Nothing in the pipeline collects
either, because the conversion step only ever sees *changed* rule files.
"""

import pytest

from prune_orphans import PruneError, find_orphans, main, prune


def make_repo(tmp_path, rules, spl=(), results=(), status="stable"):
    rules_dir = tmp_path / "rules" / "sigma"
    spl_dir = tmp_path / "rules" / "splunk"
    results_dir = tmp_path / "outputs" / "results"
    for d in (rules_dir, spl_dir, results_dir):
        d.mkdir(parents=True)

    for stem, detect_id in rules:
        (rules_dir / f"{stem}.yml").write_text(
            f"title: T\ndetect_id: {detect_id}\nstatus: {status}\n", encoding="utf-8"
        )
    for stem in spl:
        (spl_dir / f"{stem}.spl").write_text("index=x\n", encoding="utf-8")
    for detect_id in results:
        (results_dir / detect_id).mkdir()

    return rules_dir, spl_dir, results_dir


def test_artefacts_of_a_live_rule_are_left_alone(tmp_path):
    dirs = make_repo(
        tmp_path,
        rules=[("DETECT-2026-0001_Alpha", "DETECT-2026-0001")],
        spl=["DETECT-2026-0001_Alpha"],
        results=["DETECT-2026-0001"],
    )

    orphans = find_orphans(*dirs)

    assert orphans["orphan_spl"] == []
    assert orphans["orphan_results"] == []


def test_deleted_rule_leaves_both_artefacts_orphaned(tmp_path):
    dirs = make_repo(
        tmp_path,
        rules=[("DETECT-2026-0001_Alpha", "DETECT-2026-0001")],
        spl=["DETECT-2026-0001_Alpha", "DETECT-2026-0099_Gone"],
        results=["DETECT-2026-0001", "DETECT-2026-0099"],
    )

    orphans = find_orphans(*dirs)

    assert [p.name for p in orphans["orphan_spl"]] == ["DETECT-2026-0099_Gone.spl"]
    assert [p.name for p in orphans["orphan_results"]] == ["DETECT-2026-0099"]


def test_renamed_rule_file_orphans_the_spl_but_not_the_results(tmp_path):
    """The .spl mirrors the filename; the results directory is keyed by detect_id."""
    dirs = make_repo(
        tmp_path,
        rules=[("DETECT-2026-0001_New-Name", "DETECT-2026-0001")],
        spl=["DETECT-2026-0001_New-Name", "DETECT-2026-0001_Old-Name"],
        results=["DETECT-2026-0001"],
    )

    orphans = find_orphans(*dirs)

    assert [p.name for p in orphans["orphan_spl"]] == ["DETECT-2026-0001_Old-Name.spl"]
    assert orphans["orphan_results"] == []


def test_deprecated_rules_keep_their_artefacts(tmp_path):
    """Deprecation stops the deploy; it does not erase the rule's history."""
    dirs = make_repo(
        tmp_path,
        rules=[("DETECT-2026-0001_Alpha", "DETECT-2026-0001")],
        spl=["DETECT-2026-0001_Alpha"],
        results=["DETECT-2026-0001"],
        status="deprecated",
    )

    orphans = find_orphans(*dirs)

    assert orphans["orphan_spl"] == []
    assert orphans["orphan_results"] == []


def test_apply_deletes_and_check_does_not(tmp_path):
    rules_dir, spl_dir, results_dir = make_repo(
        tmp_path,
        rules=[("DETECT-2026-0001_Alpha", "DETECT-2026-0001")],
        spl=["DETECT-2026-0099_Gone"],
        results=["DETECT-2026-0099"],
    )
    stray = spl_dir / "DETECT-2026-0099_Gone.spl"
    sidecar = spl_dir / "DETECT-2026-0099_Gone.meta.json"
    sidecar.write_text("{}", encoding="utf-8")

    prune(find_orphans(rules_dir, spl_dir, results_dir), apply=False)
    assert stray.exists()

    removed = prune(find_orphans(rules_dir, spl_dir, results_dir), apply=True)

    assert removed == 2
    assert not stray.exists()
    # Gitignored, so invisible to git -- but still read by anything that scans
    # the directory instead of the index.
    assert not sidecar.exists()
    assert not (results_dir / "DETECT-2026-0099").exists()


def test_pruning_is_idempotent(tmp_path):
    rules_dir, spl_dir, results_dir = make_repo(
        tmp_path,
        rules=[("DETECT-2026-0001_Alpha", "DETECT-2026-0001")],
        spl=["DETECT-2026-0099_Gone"],
    )

    prune(find_orphans(rules_dir, spl_dir, results_dir), apply=True)
    second = prune(find_orphans(rules_dir, spl_dir, results_dir), apply=True)

    assert second == 0


def test_empty_rules_directory_refuses_rather_than_deleting_everything(tmp_path):
    """A wrong path or partial checkout must not read as 'delete the library'."""
    rules_dir, spl_dir, results_dir = make_repo(
        tmp_path, rules=[], spl=["DETECT-2026-0001_Alpha"], results=["DETECT-2026-0001"]
    )

    with pytest.raises(PruneError):
        find_orphans(rules_dir, spl_dir, results_dir)

    assert (spl_dir / "DETECT-2026-0001_Alpha.spl").exists()


def test_unparseable_rule_stops_the_prune(tmp_path):
    rules_dir, spl_dir, results_dir = make_repo(
        tmp_path,
        rules=[("DETECT-2026-0001_Alpha", "DETECT-2026-0001")],
        spl=["DETECT-2026-0001_Alpha"],
    )
    (rules_dir / "broken.yml").write_text("title: [unclosed\n", encoding="utf-8")

    with pytest.raises(PruneError):
        find_orphans(rules_dir, spl_dir, results_dir)


def test_missing_rules_directory_is_an_error_not_a_clean_run(tmp_path):
    assert main(["--rules-dir", str(tmp_path / "nope")]) == 2
