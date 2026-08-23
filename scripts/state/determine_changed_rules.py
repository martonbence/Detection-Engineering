# scripts/state/determine_changed_rules.py
#
# The dev pipeline's scope-decision gate: which Sigma rules does *this* run
# validate, convert, deploy, attack and verify?
#
# Extracted verbatim (in behaviour, not in syntax) from ci_dev_workflow.yml's
# "Determine changed Sigma files" step, which was 206 lines of inline bash --
# audit/feature-and-process-audit.md item 4.1. That register item is about the
# workflows' inline shell being the repo's largest untestable surface: pytest
# cannot reach it, actionlint/shellcheck check its *syntax* and nothing checked
# its *behaviour*. Every branch below is now covered by
# tests/test_determine_changed_rules.py.
#
# This is a relocation, not a redesign: the same five modes, the same output
# names and formats, the same exit codes. The output format in particular is a
# contract -- roughly a dozen later steps and every downstream job branch on
# has_rules/mode/rule_files/base_sha/has_base_diff/changed_rule_files, and a
# wrong answer here either starts a full lab run (live Atomic Red Team attacks
# against the lab VMs) that should not have happened, or silently skips rules
# while the run still goes green.
#
# The split:
#   decide()  -- pure. Takes the event name, the SHAs, the dispatch inputs and
#                the already-computed diff; returns every output this step
#                writes. The three rule-listing side effects it cannot avoid
#                (resolve a manual selection, list unverified rules, list every
#                rule) are injected as `Resolvers`, so a test hands it plain
#                lists instead of a git repo and a Splunk-shaped world.
#   main()    -- the I/O half: git fetch/diff/ls-files, reading the
#                environment, and appending to $GITHUB_OUTPUT /
#                $GITHUB_STEP_SUMMARY in exactly the byte format the downstream
#                steps parse.
#
# Outputs written, in the order the old shell wrote them:
#   base_sha, has_base_diff, changed_rule_files, then either
#   (mode=none, has_rules=false, empty rule_files) or
#   (has_rules=true, mode, rule_files).
#
# Exit codes:
# 0 = a decision was written (including the legitimate "nothing to run" case)
# 1 = a manual selection named a rule that does not exist (nothing is selected)

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from importlib.util import find_spec

# The rules/sigma/*.yml|yaml subset of a diff. Same expression the shell used.
RULE_FILE_RE = re.compile(r"^rules/sigma/.*\.(yml|yaml)$")

# audit/remediation-plan.md item 2.19. Touching one of these invalidates every
# .spl already converted, so the run widens from "the rules in this push" to the
# whole rule set: re-convert, re-deploy, re-attack, re-measure.
#
# That is the single most expensive thing this pipeline does -- it puts live
# attacks on the lab VMs -- so the trigger is an explicit list of files that can
# change what a rule *converts to* or what it is *called* in Splunk. It used to
# be the glob `scripts/validate/*`, which meant any new file in that directory
# forced a full lab run: adding check_test_routing.py (item 2.17), which cannot
# affect a single rule's SPL, did exactly that.
#
# rule_naming.py is on the list and was not before, though it was already in the
# workflow's `paths:`. It decides the saved search name, so changing it renames
# every deployed object -- the strongest reason there is to rebuild everything,
# and it was the one case that started a run and then only processed the diff.
#
# audit/remediation-plan.md item 3.7 added the last two. Both decide what the
# converter emits without being the converter: backend_config.py resolves which
# backend and pipeline every rule is built with, and backends.yml is the data it
# resolves from -- editing either changes all 27 outputs while sigma_to_spl.py
# itself stays untouched.
#
# Still an explicit list rather than the `scripts/convert/**` glob used by the
# workflow's path filter: item 2.19 was exactly a glob here matching a file that
# changes no output, and the cost of being wrong at this point is a full lab run
# against every rule. A new file under scripts/convert/ has to be judged and
# added by hand.
REBUILD_ALL_FILES: tuple[str, ...] = (
    "docs/schemas/sigma_schema.json",
    "scripts/validate/validate_sigma.py",
    "scripts/validate/validate_sigma.ps1",
    "scripts/convert/sigma_to_spl.py",
    "scripts/lib/rule_naming.py",
    "scripts/convert/backend_config.py",
    "config/backends.yml",
)

# `all` mode's rule list. Four pathspecs because the top-level and the nested
# case need naming separately, and both extensions are allowed by the schema.
ALL_RULES_PATHSPECS: tuple[str, ...] = (
    "rules/sigma/*.yml",
    "rules/sigma/**/*.yml",
    "rules/sigma/*.yaml",
    "rules/sigma/**/*.yaml",
)

# Written to $GITHUB_STEP_SUMMARY when `unverified` mode selects nothing. Not
# "nothing to do because nothing changed" -- this one is a positive result, and
# worth saying so rather than looking like an empty run somebody has to
# interpret.
NOTHING_TO_VERIFY_SUMMARY = (
    "### Nothing to verify\n"
    "\n"
    "Every rule already has a verification result matching its current version. "
    "Choose the `all` scope to force a full rebuild anyway.\n"
)


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


# --- the decision (pure) -----------------------------------------------------


@dataclass(frozen=True)
class Resolvers:
    """The three "list some rules" side effects, injected so decide() stays pure.

    main() supplies the real, subprocess-backed versions; tests supply lists.
    """

    selected: Callable[[str], list[str]]
    unverified: Callable[[], list[str]]
    every_rule: Callable[[], list[str]]


@dataclass(frozen=True)
class Decision:
    """Everything the step writes, plus why."""

    # The resolved mode: changed | all | selected | unverified. Note this is
    # *not* always what lands in the `mode` output -- see output_mode below.
    mode: str
    # ok = rules selected; empty = nothing to run (still a success);
    # error = a manual selection named a rule that does not exist.
    outcome: str
    exit_code: int
    has_rules: bool
    rule_files: tuple[str, ...]
    base_sha: str
    head_sha: str
    has_base_diff: bool
    changed_rule_files: tuple[str, ...]
    messages: tuple[str, ...] = field(default_factory=tuple)
    summary: str = ""

    @property
    def output_mode(self) -> str:
        """The value written to the `mode` output.

        `none` on the empty path: downstream steps gate on has_rules, but the
        dashboard/summary steps read mode, and "the mode we would have used if
        there had been anything to do" would be actively misleading there.
        """
        return "none" if self.outcome == "empty" else self.mode


def pick_base_head(
    event_name: str,
    pr_base_sha: str = "",
    pr_head_sha: str = "",
    push_before_sha: str = "",
    push_head_sha: str = "",
) -> tuple[str, str]:
    """The two commits this run diffs between.

    A pull_request event's `github.sha` is the merge commit, not the branch tip,
    so the PR's own base/head are used there instead.
    """
    if event_name == "pull_request":
        return pr_base_sha, pr_head_sha
    return push_before_sha, push_head_sha


def base_diff_exists(base_sha: str) -> bool:
    """has_base_diff: is there a real prior commit to diff against at all?

    A narrower question than mode -- "does a real prior commit exist", not "what
    does this run do with that diff". False in exactly the two cases where
    BASE_SHA cannot be trusted: workflow_dispatch (github.event.before is unset
    for that event) and the very first push to a ref (before is the all-zero
    sha). True for every ordinary push or PR, including ones that go on to set
    mode=all because a REBUILD_ALL_FILES trigger was in the diff.

    check_version_bump.py (audit/remediation-plan.md item 3.5) reads this rather
    than mode: a schema/converter change widening the run to every rule does not
    erase the base commit, so a rule file touched in that same push should still
    be checked -- see the workflow's "Check version bump discipline" step.
    """
    return not (base_sha == "" or re.fullmatch(r"0+", base_sha) is not None)


def rule_files_in(files: Sequence[str]) -> tuple[str, ...]:
    """The rules/sigma/*.yml|yaml subset of a diff, order preserved.

    Exposed as its own output (changed_rule_files), unconditionally -- same
    reasoning as base_sha/has_base_diff. This is a fixed fact about the diff
    itself ("which rule files did this push touch") and does not change with
    mode, unlike rule_files, which mode redefines on purpose (a real subset in
    `changed` mode, every rule in `all`, a named list in `selected`...).
    check_version_bump.py (audit/remediation-plan.md item 3.5) needs the fixed
    fact, not whatever rule_files ends up meaning for this particular run, so it
    gets its own output rather than reusing rule_files.
    """
    return tuple(f for f in files if RULE_FILE_RE.match(f))


def rebuild_all_trigger(files: Sequence[str]) -> str | None:
    """The first REBUILD_ALL_FILES entry present in the diff, if any.

    Exact path match, never a prefix or glob -- see REBUILD_ALL_FILES above for
    why this list is maintained by hand.
    """
    for f in files:
        for trigger in REBUILD_ALL_FILES:
            if f == trigger:
                return f
    return None


def decide(
    *,
    event_name: str,
    resolvers: Resolvers,
    pr_base_sha: str = "",
    pr_head_sha: str = "",
    push_before_sha: str = "",
    push_head_sha: str = "",
    dispatch_scope: str = "",
    dispatch_rules: str = "",
    changed_files: Sequence[str] = (),
    log: Callable[[str], None] | None = None,
) -> Decision:
    """Pick this run's mode and rule set. No git, no environment, no file writes.

    `log`, when given, receives each message as it is produced so the step log
    keeps the ordering the old shell had; the same messages are also returned on
    the Decision so a test can assert on them without capturing stdout.
    """
    messages: list[str] = []

    def emit(msg: str) -> None:
        messages.append(msg)
        if log is not None:
            log(msg)

    base_sha, head_sha = pick_base_head(
        event_name,
        pr_base_sha=pr_base_sha,
        pr_head_sha=pr_head_sha,
        push_before_sha=push_before_sha,
        push_head_sha=push_head_sha,
    )
    has_base_diff = base_diff_exists(base_sha)

    mode = "changed" if has_base_diff else "all"

    # audit/remediation-plan.md item 2.21. A manual run says what it wants
    # explicitly, rather than falling into `all` as a side effect of
    # workflow_dispatch having no `github.event.before`.
    if event_name == "workflow_dispatch":
        # A named selection is a more specific instruction than either bulk
        # mode, so it wins over scope rather than intersecting with it.
        #
        # Spaces only, matching the shell's `${DISPATCH_RULES// /}`: a value of
        # nothing but spaces is an empty selection, not a request to fail.
        if dispatch_rules.replace(" ", ""):
            mode = "selected"
            emit("Manual run, explicit rule selection.")
        else:
            mode = dispatch_scope or "unverified"
            emit(f"Manual run, scope: {mode}")

    files = list(changed_files)
    if files:
        emit("Changed files:")
        for f in files:
            emit(f" - {f}")

    changed_rule_files = rule_files_in(files)

    if mode != "all":
        trigger = rebuild_all_trigger(files)
        if trigger is not None:
            mode = "all"
            emit(f"Full rebuild triggered by {trigger} (it can change every rule's output).")

    fixed = {
        "base_sha": base_sha,
        "head_sha": head_sha,
        "has_base_diff": has_base_diff,
        "changed_rule_files": changed_rule_files,
    }

    if mode == "selected":
        # Strict: an unknown id makes resolve_rule_selection.py exit non-zero
        # and print every valid one, and write nothing to stdout. Running the
        # subset that happened to resolve would be worse than not running -- it
        # would look like the request was honoured.
        rule_files = tuple(resolvers.selected(dispatch_rules))
        if not rule_files:
            emit("::error::No rules resolved from the selection. See the list of valid detect_ids above.")
            return Decision(
                mode=mode,
                outcome="error",
                exit_code=1,
                has_rules=False,
                rule_files=(),
                messages=tuple(messages),
                **fixed,
            )
    elif mode == "unverified":
        # Selecting nothing is a legitimate answer: it means every rule is
        # already verified at its current version.
        rule_files = tuple(resolvers.unverified())
    elif mode == "all":
        rule_files = tuple(resolvers.every_rule())
    else:
        # Same filter as changed_rule_files above -- mode == "changed" means
        # "process exactly what this push touched", which is that value by
        # definition, so reuse it instead of re-deriving it a second time.
        rule_files = changed_rule_files

    if not rule_files:
        summary = ""
        if mode == "unverified":
            emit("Every rule is already verified at its current version. Nothing to run.")
            summary = NOTHING_TO_VERIFY_SUMMARY
        else:
            emit("No Sigma rule files to process.")
        return Decision(
            mode=mode,
            outcome="empty",
            exit_code=0,
            has_rules=False,
            rule_files=(),
            messages=tuple(messages),
            summary=summary,
            **fixed,
        )

    emit(f"Mode: {mode}")
    return Decision(
        mode=mode,
        outcome="ok",
        exit_code=0,
        has_rules=True,
        rule_files=rule_files,
        messages=tuple(messages),
        **fixed,
    )


# --- $GITHUB_OUTPUT formatting (pure) ----------------------------------------
#
# The formats below are what the downstream steps parse, so they are reproduced
# byte for byte from the shell this replaced -- including the one asymmetry:
# an empty changed_rule_files carries a single blank line (the shell's
# `printf '%s\n' "${arr[@]}"` prints one newline for an empty array), while the
# empty rule_files on the "nothing to run" path carries no body line at all
# (that one was written with two plain `echo`s). Both parse as empty; the
# difference is preserved rather than tidied because tidying it would be a
# behaviour change smuggled into a relocation.


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


# --- the I/O half ------------------------------------------------------------


def append_to(env_var: str, text: str) -> None:
    """Append to one of the runner's writeback files, if it exists.

    Outside Actions (a local debug run) there is nothing to append to; say so on
    stderr and carry on rather than crashing, since every other side effect of
    this script is still worth seeing.
    """
    path = os.environ.get(env_var, "")
    if not path:
        eprint(f"[note] {env_var} is not set -- skipping this write (not running under GitHub Actions?).")
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(text)


def _lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip()]


def git_fetch_origin() -> None:
    # Preserved verbatim from the shell, including `--depth=0`, which git
    # rejects outright ("fatal: depth 0 is not a positive number") -- the old
    # step swallowed that with `|| true`, so this fetch has never actually run.
    # Harmless today because the job's checkout is already fetch-depth: 0.
    # Reported as a finding rather than fixed here: this extraction is a
    # relocation, and changing what the step fetches is a behaviour change.
    subprocess.run(
        ["git", "fetch", "--no-tags", "--prune", "--depth=0", "origin"],
        check=False,
    )


def git_diff_names(base_sha: str, head_sha: str) -> list[str]:
    # --diff-filter=AMRC: Added, Modified, Renamed, Copied -- deliberately not
    # Deleted. A deleted rule has no file left to validate or convert; the
    # workflow's "Prune repo artefacts of deleted rules" step handles that case
    # instead, and runs unconditionally rather than gated on has_rules.
    #
    # Errors are swallowed (an unusable BASE_SHA, a force-push that removed it):
    # the result is an empty diff, which the modes below already handle.
    out = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=AMRC", base_sha, head_sha],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return _lines(out.stdout)


def _ensure_conversion_deps() -> None:
    # This step runs before the job's "Install Python deps" -- that one is gated
    # on has_rules, which is what is being computed here. Same conditional
    # install the prune step uses, from the same pinned file.
    if find_spec("yaml") is not None:
        return
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", ".github/requirements.txt"],
        check=True,
    )


def _stdout_of(cmd: list[str]) -> list[str]:
    """Run cmd, return its non-empty stdout lines; stderr goes to the step log.

    The exit code is deliberately ignored, exactly as the shell's
    `while read ... < <(python ...)` ignored it: for both state scripts the
    contract is "stdout is the selection and nothing else", so an empty stdout
    is the failure signal, and the callers above act on that.
    """
    out = subprocess.run(cmd, stdout=subprocess.PIPE, text=True, check=False)
    return _lines(out.stdout)


def default_resolvers() -> Resolvers:
    def selected(dispatch_rules: str) -> list[str]:
        # Diagnostics (including the full list of valid detect_ids on a bad
        # selection) go to stderr, so they land in the step log unchanged.
        return _stdout_of([sys.executable, "scripts/state/resolve_rule_selection.py", dispatch_rules])

    def unverified() -> list[str]:
        _ensure_conversion_deps()
        # Feeds audit/feature-and-process-audit.md item 3.1 (the verification
        # expiry mechanism): stdout is the selection, diagnostics are on stderr.
        return _stdout_of([sys.executable, "scripts/state/select_unverified.py"])

    def every_rule() -> list[str]:
        return _stdout_of(["git", "ls-files", *ALL_RULES_PATHSPECS])

    return Resolvers(selected=selected, unverified=unverified, every_rule=every_rule)


def main(argv: list[str] | None = None) -> int:
    _ = argv  # no arguments: every input arrives as an environment variable
    env = os.environ

    event_name = env.get("GITHUB_EVENT_NAME", "")
    base_sha, head_sha = pick_base_head(
        event_name,
        pr_base_sha=env.get("PR_BASE_SHA", ""),
        pr_head_sha=env.get("PR_HEAD_SHA", ""),
        push_before_sha=env.get("PUSH_BEFORE_SHA", ""),
        push_head_sha=env.get("PUSH_HEAD_SHA", ""),
    )

    print(f"Diffing against previous commit: {base_sha or '<none>'} -> {head_sha or '<none>'}", flush=True)

    # Exposed unconditionally, before mode/rule_files are decided below, so it
    # is available on every path this step can take (including the early
    # "nothing to do" exit). check_version_bump.py
    # (audit/remediation-plan.md item 3.5) is the consumer: it needs the same
    # before/after this step already diffs against rather than re-deriving a
    # second notion of "base".
    append_to("GITHUB_OUTPUT", render_kv("base_sha", base_sha))

    git_fetch_origin()

    append_to("GITHUB_OUTPUT", render_kv("has_base_diff", "true" if base_diff_exists(base_sha) else "false"))

    changed_files = git_diff_names(base_sha, head_sha)

    decision = decide(
        event_name=event_name,
        resolvers=default_resolvers(),
        pr_base_sha=env.get("PR_BASE_SHA", ""),
        pr_head_sha=env.get("PR_HEAD_SHA", ""),
        push_before_sha=env.get("PUSH_BEFORE_SHA", ""),
        push_head_sha=env.get("PUSH_HEAD_SHA", ""),
        dispatch_scope=env.get("DISPATCH_SCOPE", ""),
        dispatch_rules=env.get("DISPATCH_RULES", ""),
        changed_files=changed_files,
        log=lambda msg: print(msg, flush=True),
    )

    append_to("GITHUB_OUTPUT", render_multiline("changed_rule_files", decision.changed_rule_files))

    if decision.outcome == "error":
        return decision.exit_code

    if decision.summary:
        append_to("GITHUB_STEP_SUMMARY", decision.summary)

    if decision.outcome == "empty":
        append_to(
            "GITHUB_OUTPUT",
            render_kv("mode", decision.output_mode)
            + render_kv("has_rules", "false")
            + render_multiline("rule_files", (), blank_when_empty=False),
        )
        return decision.exit_code

    append_to(
        "GITHUB_OUTPUT",
        render_kv("has_rules", "true")
        + render_kv("mode", decision.output_mode)
        + render_multiline("rule_files", decision.rule_files),
    )
    return decision.exit_code


if __name__ == "__main__":
    sys.exit(main())
