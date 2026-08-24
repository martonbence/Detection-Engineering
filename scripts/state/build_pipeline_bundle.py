# scripts/state/build_pipeline_bundle.py
#
# The dev pipeline's prepare_validate_convert job, "Build pipeline bundle"
# step (id: bundle) in ci_dev_workflow.yml.
#
# Extracted verbatim (in behaviour, not in syntax) from ~116 lines of inline
# bash -- audit/feature-and-process-audit.md item 4.1, slice 5 of 5 (slice 1
# was determine_changed_rules.py, slice 2 was merge_verification_results.py,
# slice 3 was open_promotion_pr.py, slice 4 was reconcile_step.py). That
# register item is about the workflows' inline shell being the repo's
# largest untestable surface; this is the last inline block it names. Every
# branch below is now covered by tests/test_build_pipeline_bundle.py.
#
# What this step does, unchanged from the shell:
#   1. `rm -rf pipeline_bundle`, then recreate the fixed directory skeleton
#      (scripts/{atomic,deploy,lib}).
#   2. Copy three named scripts individually (run_atomic.ps1,
#      deploy_spl_to_splunk.py, check_spl_syntax.py), then copy the whole of
#      scripts/lib/ wholesale -- see copy_lib_wholesale() below for why
#      wholesale, not itemised (audit/remediation-plan.md item 3.6, and the
#      bug it caused).
#   3. Prune every __pycache__ directory out of the copied scripts/lib/ tree
#      -- bytecode was never part of the bundle's contract.
#   4. For every changed rule (RULE_FILES): derive its base name, require
#      both rules/splunk/<name>.spl AND rules/splunk/<name>.meta.json to
#      exist (hard failure otherwise -- see BundleError), copy both into the
#      bundle, and collect the .spl path into the eventual spl_files output.
#   5. For every unchanged rule whose sidecar the previous step refreshed
#      (UNCHANGED_RULE_FILES): same base-name derivation, require only the
#      .meta.json to exist (hard failure otherwise), copy it into the
#      bundle. These do NOT feed spl_files -- see select_unchanged_rule_files()
#      for why (audit/remediation-plan.md item 3.2).
#   6. Write $GITHUB_OUTPUT: has_spl=false + an empty spl_files block if no
#      rule produced an SPL file; otherwise has_spl=true + the populated
#      spl_files block.
#
# Hardening applied deliberately, same spirit as slice 3's escape_cell() and
# slice 4's structural PIPESTATUS simplification -- not a silent behaviour
# change:
#
# The old shell read steps.changes.outputs.rule_files and
# steps.unchanged.outputs.unchanged_rules via GitHub Actions expression
# interpolation directly inside a `mapfile -t rules <<'EOF' ... EOF` heredoc
# in the run: block's own text -- i.e. GitHub substitutes that text into the
# script BEFORE bash parses it, the same class of "untrusted text lands in a
# script body" pattern this repo's own gotchas already warn about elsewhere,
# even though here the values are constrained to rules/sigma/*.yml|yaml
# paths from a controlled upstream step, not attacker input. Since this step
# is rewritten in Python anyway, both lists now arrive as environment
# variables (RULE_FILES, UNCHANGED_RULE_FILES) set in the step's env: block,
# exactly like slice 4 did for RETIRE_ORPHANS -- the Python side reads
# os.environ and splits on newlines, never touching GitHub Actions
# expression syntax inside a script body at all. This is not a behaviour
# change for any realistic input: parse_rule_list()'s splitlines() drops a
# merely-trailing newline the same way the heredoc's closing delimiter did,
# and turns a lone blank line into a single empty-string element the same
# way `mapfile` did over the old heredoc-interpolated "zero rules" case
# (steps.unchanged.outputs.unchanged_rules is exactly that case whenever
# every rule in the run changed -- see determine_changed_rules.py's
# render_multiline(blank_when_empty=True), whose body is a bare "\n" for an
# empty list, and the "unchanged" step's own `printf '%s\n' "${arr[@]}"`
# over an empty array, which also emits one blank line, not zero). Either
# way the blank entry is filtered by select_changed_rule_files() /
# select_unchanged_rule_files() exactly like the shell's
# `[[ -z "$rule" ]] && continue`, so the set of rules actually processed is
# identical.
#
# The split, following slices 1-4's shape:
#   derive_rule_basename() / bundle_paths_for_rule() / parse_rule_list() --
#                                 pure. Path/string logic, no I/O.
#   select_changed_rule_files() / select_unchanged_rule_files() --
#                                 pure selection + validation, with the
#                                 filesystem existence check injected as a
#                                 callable (`exists`) so tests don't need
#                                 real generated SPL/meta files on disk.
#                                 Raises BundleError on a missing file,
#                                 mirroring the shell's `echo ...; exit 1`.
#   render_kv() / render_multiline() / append_to() --
#                                 pure $GITHUB_OUTPUT formatting, duplicated
#                                 from determine_changed_rules.py (slice 1)
#                                 rather than imported -- scripts/state/*.py
#                                 has no cross-import convention between
#                                 slices, each stays self-contained.
#   prepare_bundle_skeleton() / copy_fixed_scripts() / copy_lib_wholesale() /
#   prune_pycache() / copy_rule_pair() --
#                                 the real filesystem I/O half, exercised in
#                                 tests against real tmp_path trees rather
#                                 than mocked, same choice slice 2 made for
#                                 its overlay/delta file merges.
#   run_step() / main()        -- orchestration: real filesystem I/O first,
#                                 then the pure selection functions (which
#                                 can raise), then the real per-rule copies,
#                                 then the output block.
#
# One deliberate, documented simplification versus the original shell's
# exact sequencing: the shell interleaved "check this rule's files exist"
# with "copy this rule's files" inside a single loop, so if rule 3 of 5
# failed validation, rules 1-2 had already been copied into pipeline_bundle/
# by the time the step died. This version validates every changed (then
# every unchanged) rule fully before copying any of them. Both versions
# `exit 1` / return 1 with the identical message on the identical first
# missing file, and both fail the whole job -- nothing downstream ever reads
# a bundle from a job that failed to build one, so which partial files
# happened to land on disk before the failure is not externally observable.
# Not doing partial, doomed copies before failing is arguably safer, not
# riskier, but it is called out here because it is a real difference from
# the original's literal execution order, not just its outcome.
#
# Exit codes: 0 on success (with either has_spl=true or has_spl=false), 1 on
# any missing generated file (BundleError). There is no equivalent of
# reconcile.py's exit 2 here -- this step has no "the check itself could not
# be trusted" failure mode, only "the file that should exist does not".

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

RULES_SPLUNK_DIR = "rules/splunk"

BUNDLE_SKELETON_DIRS = (
    "scripts/atomic",
    "scripts/deploy",
    "scripts/lib",
)

FIXED_SCRIPTS = (
    "scripts/atomic/run_atomic.ps1",
    "scripts/deploy/deploy_spl_to_splunk.py",
    "scripts/deploy/check_spl_syntax.py",
)


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


class BundleError(Exception):
    """An expected generated file (SPL or meta sidecar) is missing.

    Caught by run_step()/main() and turned into a printed message + return
    1, mirroring the shell's `echo "..."; exit 1` at the point of the same
    check.
    """


# --- basename / path derivation (pure) ----------------------------------------


def derive_rule_basename(rule_path: str) -> str:
    """`name="$(basename "$rule")"` followed by three sequential
    `${name%.SUFFIX}` strips (.yml, then .yaml, then .sigma). Applied
    unconditionally in order, exactly like the shell -- not "first match
    wins" -- though for any real rule path (which ends in at most one of the
    three) the two are equivalent.
    """
    name = rule_path.rsplit("/", 1)[-1]
    for suffix in (".yml", ".yaml", ".sigma"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    return name


@dataclass(frozen=True)
class RuleBundlePaths:
    spl_path: str
    meta_path: str


def bundle_paths_for_rule(name: str) -> RuleBundlePaths:
    return RuleBundlePaths(
        spl_path=f"{RULES_SPLUNK_DIR}/{name}.spl",
        meta_path=f"{RULES_SPLUNK_DIR}/{name}.meta.json",
    )


def parse_rule_list(env_value: str) -> list[str]:
    """Splits an env var's raw text the way `mapfile -t arr <<'EOF' ... EOF`
    split the old heredoc body: a merely-trailing newline does not produce a
    trailing empty element, but a value that is just one blank line (the
    "zero rules" case -- see the module docstring) produces exactly one
    empty-string element, not zero. Blank-entry filtering is the caller's
    job (select_changed_rule_files() / select_unchanged_rule_files()),
    mirroring the shell's `[[ -z "$rule" ]] && continue`.
    """
    return env_value.splitlines()


# --- selection + validation (pure logic, injected existence check) -----------


def select_changed_rule_files(
    rule_files: Sequence[str],
    *,
    exists: Callable[[str], bool],
) -> list[RuleBundlePaths]:
    """One entry per non-blank changed rule, in order. Requires both the
    .spl and the .meta.json to already exist (checked in that order, same as
    the shell) -- raises BundleError with the same message the shell echoed
    on the first missing file, changed rule or not being "best effort" here.
    """
    result: list[RuleBundlePaths] = []
    for rule in rule_files:
        if not rule:
            continue
        paths = bundle_paths_for_rule(derive_rule_basename(rule))
        if not exists(paths.spl_path):
            raise BundleError(f"Expected generated SPL file is missing: {paths.spl_path}")
        if not exists(paths.meta_path):
            raise BundleError(f"Expected generated meta sidecar is missing: {paths.meta_path}")
        result.append(paths)
    return result


def select_unchanged_rule_files(
    rule_files: Sequence[str],
    *,
    exists: Callable[[str], bool],
) -> list[RuleBundlePaths]:
    """Sidecars only, for every rule the "Regenerate meta sidecars for
    unchanged rules" step refreshed -- audit/remediation-plan.md item 3.2
    (not this repo's active register's own 3.2, which is the unrelated,
    rejected prod-audit-schedule item). These rules deliberately do not
    appear in the eventual spl_files output: that stays scoped to what this
    run actually changed and tested, not to full sidecar coverage.
    """
    result: list[RuleBundlePaths] = []
    for rule in rule_files:
        if not rule:
            continue
        paths = bundle_paths_for_rule(derive_rule_basename(rule))
        if not exists(paths.meta_path):
            raise BundleError(f"Expected refreshed meta sidecar is missing: {paths.meta_path}")
        result.append(paths)
    return result


# --- $GITHUB_OUTPUT formatting (pure) -----------------------------------------
#
# Duplicated from determine_changed_rules.py (slice 1) rather than imported
# -- see the module docstring. Formats reproduced byte for byte from the
# shell this replaced, including its one asymmetry: the "no SPL files"
# path's spl_files block carries no body line at all (two plain `echo`s in
# the original), while a populated list always ends its body in a newline
# (`printf '%s\n'`).


def render_kv(name: str, value: str) -> str:
    return f"{name}={value}\n"


def render_multiline(name: str, values: Sequence[str], *, blank_when_empty: bool = True) -> str:
    if values:
        body = "\n".join(values) + "\n"
    elif blank_when_empty:
        body = "\n"
    else:
        body = ""
    return f"{name}<<EOF\n{body}EOF\n"


def append_to(env_var: str, text: str) -> None:
    """Append to one of the runner's writeback files, if it exists.

    Outside Actions (a local debug run) there is nothing to append to; say
    so on stderr and carry on rather than crashing, since every other side
    effect of this script is still worth seeing.
    """
    path = os.environ.get(env_var, "")
    if not path:
        eprint(f"[note] {env_var} is not set -- skipping this write (not running under GitHub Actions?).")
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(text)


# --- the I/O half --------------------------------------------------------------


def prepare_bundle_skeleton(bundle_dir: Path) -> None:
    """`rm -rf pipeline_bundle`, then `mkdir -p` the fixed skeleton."""
    if bundle_dir.exists():
        shutil.rmtree(bundle_dir)
    for sub in BUNDLE_SKELETON_DIRS:
        (bundle_dir / sub).mkdir(parents=True, exist_ok=True)


def copy_fixed_scripts(repo_root: Path, bundle_dir: Path) -> None:
    """The three named `cp` calls -- run_atomic.ps1, deploy_spl_to_splunk.py,
    check_spl_syntax.py. Named deliberately: these are the entry points the
    bundle exists to ship, not shared library code, so there is no
    "the next one will be missed" risk the way there was for scripts/lib/.
    """
    for rel_path in FIXED_SCRIPTS:
        shutil.copy2(repo_root / rel_path, bundle_dir / rel_path)


def copy_lib_wholesale(repo_root: Path, bundle_dir: Path) -> None:
    """`cp -r scripts/lib/. pipeline_bundle/scripts/lib/` --
    audit/remediation-plan.md item 3.6, and the bug it caused. A prior
    version of this step named lib files by hand; a refactor moved the env
    helpers into scripts/lib/env.py, deploy_spl_to_splunk.py was rewritten
    to import them, and the hand-maintained copy list could not know that --
    the bundle shipped without env.py and the deploy died 0.1s in on the lab
    runner with `ModuleNotFoundError: No module named 'lib.env'` (run #67),
    long after this job had already gone green. Wholesale rather than one
    more line: naming files by hand is the failure mode itself, and the next
    module under lib/ would reproduce it exactly. lib/ holds only small,
    non-secret, importable helpers shared by the bundled scripts, so copying
    all of it costs nothing and cannot leak anything the deploy script does
    not already carry.

    The source is `scripts/lib/.`, not `scripts/lib` -- the trailing `/.`
    tells `cp -r` to copy the directory's *contents* into the destination,
    not the directory itself, which is what avoids nesting a
    pipeline_bundle/scripts/lib/lib/ directory. shutil.copytree's default
    semantics are the reverse of a bare `cp -r`: it always creates `dst`
    itself and refuses to run if `dst` already exists, unless
    `dirs_exist_ok=True`. Since prepare_bundle_skeleton() already
    `mkdir -p`'d pipeline_bundle/scripts/lib/ as an empty directory,
    `copytree(src, dst, dirs_exist_ok=True)` copies src's contents directly
    into that existing dst -- the same "contents in, no extra level" result
    as `cp -r scripts/lib/. dst/`, not the nested one a naive
    `copytree(src, dst / "lib")` or an omitted `dirs_exist_ok` would produce.
    """
    src = repo_root / "scripts" / "lib"
    dst = bundle_dir / "scripts" / "lib"
    shutil.copytree(src, dst, dirs_exist_ok=True)


def prune_pycache(lib_dir: Path) -> None:
    """`find pipeline_bundle/scripts/lib -type d -name '__pycache__' -prune
    -exec rm -rf {} +` -- scoped to the copied scripts/lib/ tree only, same
    as the shell. Bytecode is not part of the bundle's contract, and it is
    not something to ship in a downloadable artifact just because it
    happened to be on disk; only reachable because the copy above is
    wholesale.
    """
    for path in list(lib_dir.rglob("__pycache__")):
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)


def copy_rule_pair(repo_root: Path, bundle_dir: Path, paths: RuleBundlePaths, *, include_spl: bool) -> None:
    """Copies one rule's already-validated files into the bundle at their
    mirrored path. `include_spl=False` for an unchanged rule's sidecar-only
    copy (see select_unchanged_rule_files()).
    """
    if include_spl:
        dst_spl = bundle_dir / paths.spl_path
        dst_spl.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(repo_root / paths.spl_path, dst_spl)
    dst_meta = bundle_dir / paths.meta_path
    dst_meta.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(repo_root / paths.meta_path, dst_meta)


# --- orchestration -------------------------------------------------------------


def run_step(
    *,
    repo_root: Path,
    bundle_dir: Path,
    rule_files: Sequence[str],
    unchanged_rule_files: Sequence[str],
    log: Callable[[str], None],
    append_output: Callable[[str], None],
) -> int:
    """One run of the step, start to finish. Returns 0 on success (either
    has_spl outcome) or 1 on a missing generated file, mirroring the shell's
    `exit 1` at the same points -- see BundleError and the module docstring
    for the one deliberate sequencing simplification versus the original.
    """
    log("Assembling pipeline bundle (SPL + meta sidecars + deploy/atomic scripts)...")

    prepare_bundle_skeleton(bundle_dir)
    copy_fixed_scripts(repo_root, bundle_dir)
    copy_lib_wholesale(repo_root, bundle_dir)
    prune_pycache(bundle_dir / "scripts" / "lib")

    try:
        changed = select_changed_rule_files(rule_files, exists=lambda p: (repo_root / p).is_file())
        unchanged = select_unchanged_rule_files(unchanged_rule_files, exists=lambda p: (repo_root / p).is_file())
    except BundleError as exc:
        log(str(exc))
        return 1

    for paths in changed:
        copy_rule_pair(repo_root, bundle_dir, paths, include_spl=True)
    for paths in unchanged:
        copy_rule_pair(repo_root, bundle_dir, paths, include_spl=False)

    spl_files = [paths.spl_path for paths in changed]

    if not spl_files:
        log("No generated SPL files found.")
        append_output(render_kv("has_spl", "false"))
        append_output(render_multiline("spl_files", (), blank_when_empty=False))
        return 0

    log("Generated SPL files selected for deploy + atomic verify:")
    for f in spl_files:
        log(f" - {f}")
    append_output(render_kv("has_spl", "true"))
    append_output(render_multiline("spl_files", spl_files))
    return 0


def main(argv: list[str] | None = None) -> int:
    _ = argv  # no arguments: every input arrives as an environment variable
    env = os.environ

    rule_files = parse_rule_list(env.get("RULE_FILES", ""))
    unchanged_rule_files = parse_rule_list(env.get("UNCHANGED_RULE_FILES", ""))

    def log(msg: str) -> None:
        print(msg, flush=True)

    def append_output(text: str) -> None:
        append_to("GITHUB_OUTPUT", text)

    return run_step(
        repo_root=Path("."),
        bundle_dir=Path("pipeline_bundle"),
        rule_files=rule_files,
        unchanged_rule_files=unchanged_rule_files,
        log=log,
        append_output=append_output,
    )


if __name__ == "__main__":
    sys.exit(main())
