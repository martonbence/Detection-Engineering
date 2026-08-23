"""The dev pipeline's scope-decision gate (audit/feature-and-process-audit.md item 4.1).

`decide()` answers "which rules does this run process, and how wide is it" for
every trigger the dev workflow has. Getting it wrong is expensive in both
directions: too wide starts live Atomic Red Team attacks against the lab VMs
for rules nobody touched, too narrow silently skips rules while the run still
reports green -- which is this pipeline's documented worst failure mode.

These tests exist because the same logic spent its life as inline bash in
ci_dev_workflow.yml, where actionlint/shellcheck could only check its syntax.
They cover the decision, not the git plumbing around it: the three "list some
rules" side effects are injected.
"""

import pytest
from determine_changed_rules import (
    NOTHING_TO_VERIFY_SUMMARY,
    REBUILD_ALL_FILES,
    Resolvers,
    base_diff_exists,
    decide,
    pick_base_head,
    rebuild_all_trigger,
    render_kv,
    render_multiline,
    rule_files_in,
)

RULE_A = "rules/sigma/DETECT-2026-0001_a.yml"
RULE_B = "rules/sigma/DETECT-2026-0002_b.yml"
EVERY_RULE = [RULE_A, RULE_B, "rules/sigma/DETECT-2026-0003_c.yml"]

BASE = "1111111111111111111111111111111111111111"
HEAD = "2222222222222222222222222222222222222222"
ZEROS = "0000000000000000000000000000000000000000"


def resolvers(selected=None, unverified=None, every_rule=None):
    """Stand-ins for resolve_rule_selection.py, select_unverified.py, git ls-files."""
    return Resolvers(
        selected=lambda _rules: list(selected or []),
        unverified=lambda: list(unverified if unverified is not None else []),
        every_rule=lambda: list(every_rule if every_rule is not None else EVERY_RULE),
    )


def push(changed_files=(), before=BASE, **kw):
    return decide(
        event_name="push",
        resolvers=kw.pop("res", resolvers()),
        push_before_sha=before,
        push_head_sha=HEAD,
        changed_files=list(changed_files),
        **kw,
    )


def dispatch(scope="", rules="", **kw):
    # workflow_dispatch has no github.event.before at all, so the SHA is empty.
    return decide(
        event_name="workflow_dispatch",
        resolvers=kw.pop("res", resolvers()),
        push_before_sha="",
        push_head_sha=HEAD,
        dispatch_scope=scope,
        dispatch_rules=rules,
        changed_files=list(kw.pop("changed_files", [])),
        **kw,
    )


# --- the five modes ----------------------------------------------------------


def test_an_ordinary_push_processes_exactly_what_it_touched():
    """`changed`, the default: no widening, no narrowing."""
    d = push([RULE_A, "README.md"])

    assert d.mode == "changed"
    assert d.output_mode == "changed"
    assert d.has_rules is True
    assert d.rule_files == (RULE_A,)


def test_a_converter_change_widens_the_run_to_every_rule():
    """`all`: the .spl of rules nobody touched is now stale too."""
    d = push([RULE_A, "scripts/convert/sigma_to_spl.py"])

    assert d.mode == "all"
    assert d.rule_files == tuple(EVERY_RULE)


def test_a_manual_run_naming_rules_processes_exactly_those():
    """`selected`: a named list beats any diff, and there is no diff here anyway."""
    d = dispatch(rules="DETECT-2026-0002", res=resolvers(selected=[RULE_B]))

    assert d.mode == "selected"
    assert d.rule_files == (RULE_B,)


def test_a_manual_run_with_no_named_rules_defaults_to_unverified():
    """`unverified`: the 180-day expiry mechanism's entry point (item 3.1)."""
    d = dispatch(res=resolvers(unverified=[RULE_A]))

    assert d.mode == "unverified"
    assert d.rule_files == (RULE_A,)
    assert "Manual run, scope: unverified" in d.messages


def test_a_push_touching_no_rule_files_resolves_to_nothing_to_do():
    """The fifth path: has_rules=false, mode=none, and a green run that does nothing.

    Downstream this skips every job transitively -- correct here, and the exact
    shape of the pipeline's worst failure mode when it happens for a bad reason.
    """
    d = push(["README.md", "docs/architecture/scripts_reference.md"])

    assert d.outcome == "empty"
    assert d.has_rules is False
    assert d.mode == "changed"
    assert d.output_mode == "none"
    assert d.rule_files == ()


# --- the rebuild-all triggers ------------------------------------------------


@pytest.mark.parametrize("trigger", REBUILD_ALL_FILES)
def test_every_rebuild_all_file_widens_the_run(trigger):
    """Each entry can change every rule's SPL or its Splunk saved search name.

    Parametrized over the constant rather than a copy of it: a file added to
    REBUILD_ALL_FILES is covered automatically, and one removed cannot leave a
    stale test passing.
    """
    d = push([trigger], res=resolvers(every_rule=EVERY_RULE))

    assert d.mode == "all"
    assert d.rule_files == tuple(EVERY_RULE)
    assert f"Full rebuild triggered by {trigger}" in " ".join(d.messages)


def test_a_rebuild_trigger_widens_the_run_but_not_the_changed_rule_file_list():
    """The two outputs mean different things, and item 3.5 depends on that.

    check_version_bump.py reads changed_rule_files (what this push touched), not
    rule_files (every rule, in `all` mode) -- otherwise a schema change would
    make it demand a version bump on rules the push never touched.
    """
    d = push(["docs/schemas/sigma_schema.json", RULE_A])

    assert d.mode == "all"
    assert d.rule_files == tuple(EVERY_RULE)
    assert d.changed_rule_files == (RULE_A,)


def test_a_near_miss_path_does_not_trigger_a_full_rebuild():
    """Exact match only. A glob here is what caused item 2.19 in the first place:
    check_test_routing.py landed under scripts/validate/ and forced a full lab run."""
    d = push([RULE_A, "scripts/validate/check_test_routing.py"])

    assert d.mode == "changed"
    assert rebuild_all_trigger(["scripts/validate/check_test_routing.py"]) is None


# --- has_base_diff -----------------------------------------------------------


def test_the_first_push_to_a_ref_has_no_base_and_rebuilds_everything():
    """`before` is the all-zero sha: nothing to diff against, so process everything."""
    d = push([], before=ZEROS)

    assert d.has_base_diff is False
    assert d.mode == "all"
    assert d.rule_files == tuple(EVERY_RULE)


def test_a_manual_run_has_no_base_but_still_takes_its_mode_from_the_dispatch():
    """Both has_base_diff=false triggers start from mode=all; a dispatch then
    overrides that with what the operator actually asked for (item 2.21).

    The overriding is the point: falling into `all` as a side effect of
    workflow_dispatch having no `github.event.before` used to re-attack all 27
    rules on the lab to catch up two. has_base_diff itself stays false either
    way, which is what keeps the version-bump gate from running without a base.
    """
    d = dispatch(scope="unverified", res=resolvers(unverified=[RULE_A]))

    assert d.has_base_diff is False
    assert d.mode == "unverified"


def test_an_ordinary_push_keeps_has_base_diff_true_even_when_it_widens_to_all():
    """mode and has_base_diff are separate facts (item 3.5's own gap).

    A push that trips a rebuild trigger still has a perfectly good base commit,
    so the version-bump check must still run on it -- gating that check on
    mode == 'changed' is what made item 3.5's introducing commit skip its own
    new gate.
    """
    d = push(["config/backends.yml", RULE_A])

    assert d.mode == "all"
    assert d.has_base_diff is True


@pytest.mark.parametrize("sha", ["", ZEROS, "0", "0000000"])
def test_shas_with_no_prior_commit(sha):
    assert base_diff_exists(sha) is False


@pytest.mark.parametrize("sha", [BASE, HEAD, "0000000000000000000000000000000000000001"])
def test_shas_that_are_a_real_prior_commit(sha):
    assert base_diff_exists(sha) is True


# --- the selected-mode hard fail ---------------------------------------------


def test_an_unknown_rule_id_fails_the_run_instead_of_running_a_subset():
    """resolve_rule_selection.py writes nothing on an unknown token, so an empty
    selection here means "the request could not be honoured", not "nothing to do".

    Running the part that happened to resolve would look like the request *was*
    honoured, which is worse than not running at all.
    """
    d = dispatch(rules="DETECT-2026-9999", res=resolvers(selected=[]))

    assert d.outcome == "error"
    assert d.exit_code == 1
    assert d.has_rules is False
    assert d.rule_files == ()
    assert any(m.startswith("::error::No rules resolved") for m in d.messages)


def test_a_named_selection_beats_the_scope_dropdown():
    d = dispatch(scope="all", rules="DETECT-2026-0002", res=resolvers(selected=[RULE_B], every_rule=EVERY_RULE))

    assert d.mode == "selected"
    assert d.rule_files == (RULE_B,)
    assert "Manual run, explicit rule selection." in d.messages


def test_a_selection_of_nothing_but_spaces_is_not_a_selection():
    """Matches the shell's `${DISPATCH_RULES// /}`: whitespace typed into the
    free-text input falls back to the scope rather than hard-failing the run."""
    d = dispatch(scope="all", rules="   ", res=resolvers(every_rule=EVERY_RULE))

    assert d.mode == "all"


# --- the two empty-selection messages ----------------------------------------


def test_unverified_selecting_nothing_is_reported_as_a_positive_result():
    """Not "nothing changed" -- "every rule is already verified at its version"."""
    d = dispatch(scope="unverified", res=resolvers(unverified=[]))

    assert d.outcome == "empty"
    assert d.output_mode == "none"
    assert "Every rule is already verified at its current version. Nothing to run." in d.messages
    assert d.summary == NOTHING_TO_VERIFY_SUMMARY
    assert "Nothing to verify" in d.summary


def test_any_other_mode_selecting_nothing_is_reported_neutrally():
    """A push that touched no rule file gets no job summary at all -- there is
    nothing to celebrate and nothing to fix."""
    d = push(["README.md"])

    assert d.outcome == "empty"
    assert "No Sigma rule files to process." in d.messages
    assert d.summary == ""


def test_a_manual_all_scope_that_resolves_no_rules_is_still_neutral():
    """The distinction is on the mode, not on "was it manual"."""
    d = dispatch(scope="all", res=resolvers(every_rule=[]))

    assert d.outcome == "empty"
    assert d.summary == ""
    assert "No Sigma rule files to process." in d.messages


# --- the fixed facts ---------------------------------------------------------


def test_a_pull_request_diffs_the_prs_own_base_and_head():
    """github.sha on a pull_request is the merge commit, not the branch tip."""
    assert pick_base_head(
        "pull_request",
        pr_base_sha="pr-base",
        pr_head_sha="pr-head",
        push_before_sha="push-before",
        push_head_sha="push-head",
    ) == ("pr-base", "pr-head")


def test_a_push_diffs_before_against_the_pushed_sha():
    assert pick_base_head(
        "push",
        pr_base_sha="pr-base",
        pr_head_sha="pr-head",
        push_before_sha="push-before",
        push_head_sha="push-head",
    ) == ("push-before", "push-head")


def test_the_base_sha_output_is_the_diff_base_on_every_path():
    """check_version_bump.py reads this even on runs that resolve to nothing."""
    d = push(["README.md"])

    assert d.base_sha == BASE
    assert d.head_sha == HEAD


@pytest.mark.parametrize(
    "path,is_rule",
    [
        ("rules/sigma/DETECT-2026-0001_a.yml", True),
        ("rules/sigma/DETECT-2026-0001_a.yaml", True),
        ("rules/sigma/windows/DETECT-2026-0001_a.yml", True),
        ("rules/sigma/DETECT-2026-0001_a.yml.bak", False),
        ("rules/sigma/README.md", False),
        ("outputs/spl/DETECT-2026-0001_a.spl", False),
        ("docs/rules/sigma/x.yml", False),
    ],
)
def test_which_paths_count_as_changed_rule_files(path, is_rule):
    assert rule_files_in([path]) == ((path,) if is_rule else ())


def test_changed_rule_files_keeps_the_diffs_order():
    assert rule_files_in(["x.md", RULE_B, "y.md", RULE_A]) == (RULE_B, RULE_A)


# --- the $GITHUB_OUTPUT formats ----------------------------------------------
#
# These are a contract with a dozen downstream steps, so they are asserted
# literally rather than round-tripped through a parser.


def test_a_scalar_output_is_one_line():
    assert render_kv("base_sha", BASE) == f"base_sha={BASE}\n"


def test_an_empty_scalar_output_still_writes_the_key():
    """base_sha= is what a workflow_dispatch writes, and downstream reads it as
    empty rather than as "the key was missing"."""
    assert render_kv("base_sha", "") == "base_sha=\n"


def test_a_list_output_uses_a_heredoc_one_path_per_line():
    assert render_multiline("rule_files", [RULE_A, RULE_B]) == f"rule_files<<EOF\n{RULE_A}\n{RULE_B}\nEOF\n"


def test_an_empty_list_output_carries_a_blank_line():
    """Reproduces `printf '%s\\n' "${arr[@]}"` on an empty array. Consumers all
    filter blank lines, so this parses as empty."""
    assert render_multiline("changed_rule_files", []) == "changed_rule_files<<EOF\n\nEOF\n"


def test_the_nothing_to_do_rule_files_output_has_no_body_line_at_all():
    """The one asymmetry kept from the shell: that path wrote the two markers
    with plain echos and no printf between them."""
    assert render_multiline("rule_files", [], blank_when_empty=False) == "rule_files<<EOF\nEOF\n"
