"""Sigma rule discovery and loading, shared by everything that reads the library.

Register item 3.1, rescoped. The item as written described metadata being
parsed four times and proposed a `manifest.json` the workflow would read with
`jq`. That description had gone stale: the workflow parses no metadata at all
today -- it checks that the sidecars exist and copies them into the bundle --
so there was no `jq` to remove and no 60-80 workflow lines to save. The real
duplication turned out to be larger and one layer up: *eight* scripts open the
Sigma YAML themselves, and six of those also decide for themselves which files
count as rules.

Those six did not agree. Before this module:

    generate_stats.py       glob("*.yml")                     flat,      .yml
    prune_orphans.py        glob("*.yml")                     flat,      .yml
    reconcile.py            glob("*.yml")                     flat,      .yml
    check_mitre_tags.py     rglob("*.yml")                    recursive, .yml
    check_test_routing.py   rglob("*.yml")                    recursive, .yml
    select_unverified.py    rglob("*.yml") + rglob("*.yaml")  recursive, both

Four behaviours. They agree today only because `rules/sigma/` happens to be
flat and every file happens to end in `.yml` -- an accident of the current
layout, not a property anything enforces.

**Why that mattered more than the tidiness.** Register item 3.8 proposes
subdirectories under `rules/sigma/`. On the day that lands, the first three
stop seeing the rules inside them -- and the consequence is not just an
undercounted dashboard. `prune_orphans.py` would class every subdirectory
rule's artefacts as orphaned and delete them, and `reconcile.py` would class
their Splunk objects as orphans, with `--apply` running unattended in every dev
run. A layout change would have destroyed data. The same trap, smaller, applies
to a rule saved as `.yaml`: the workflow's `paths:` filter matches it and the
converter converts it, but five of the six discoverers never see it.

`discover()` is therefore recursive and accepts both extensions -- the widest
of the four behaviours, so no script loses sight of a rule it can see today.

**What stays with the caller.** The six disagree on failure policy too, and
unlike the globs those differences are deliberate:

    generate_stats.py       drop the rule silently   (a dashboard is not a gate)
    prune_orphans.py        raise                    (guessing here deletes artefacts)
    reconcile.py            raise                    (ditto, against live Splunk)
    select_unverified.py    warn, then select it     (unreadable -> re-measure it)
    check_mitre_tags.py     warn and skip            (validate_sigma.py owns malformed)
    check_test_routing.py   warn and skip            (ditto)

This is the lesson item 3.6 left behind: `env_required` looked duplicated four
times and was not, and merging it would have silently changed three exit codes.
So `load_rule()` raises one exception and every caller keeps its own `except`
at the call site -- visibly, rather than hidden behind a callback.

**One deliberate contract change.** `load_rule()` treats a document that is not
a mapping as an error, which folds in the empty file (`safe_load` returns
`None`). Previously `or {}` turned that into an empty dict that then flowed on
as if it were a rule with no fields. No such file exists in the repo, so no
output moves; where the behaviour does differ it is now the safer of the two --
`prune_orphans` and `reconcile` refuse to act on a file they could not read
rather than treating it as a rule with no `detect_id`, which is precisely the
case their own comments say must not be guessed at.
"""

from __future__ import annotations

from pathlib import Path

import yaml

# The directory every discoverer defaulted to, named once.
DEFAULT_RULES_DIR = Path("rules/sigma")

# Both spellings, because the workflow's `paths:` filter and the JSON schema
# both accept both. A discoverer that recognised only one would disagree with
# the gate that let the file in.
RULE_SUFFIXES = (".yml", ".yaml")


class RuleLoadError(Exception):
    """A Sigma file could not be read, parsed, or is not a mapping."""


def discover(rules_dir: Path | str = DEFAULT_RULES_DIR) -> list[Path]:
    """Every Sigma rule file under `rules_dir`, sorted, deduplicated.

    Recursive and extension-agnostic on purpose -- see the module docstring.
    Returns an empty list for a missing directory rather than raising: three of
    the six callers ran against a possibly-absent directory and treated that as
    "no rules", and only `prune_orphans` wants it to be fatal, which it checks
    for itself before calling here.
    """
    root = Path(rules_dir)
    if not root.is_dir():
        return []

    found: set[Path] = set()
    for suffix in RULE_SUFFIXES:
        found.update(root.rglob(f"*{suffix}"))

    # Sorted so every consumer walks the library in the same order. Several of
    # them write ordered output -- the dashboard's rule table, the reconcile
    # report -- and an unstable order would show up as spurious diffs.
    return sorted(found)


def load_rule(path: Path | str) -> dict:
    """Read and parse one Sigma file, or raise `RuleLoadError`.

    The single exception type is what lets each caller keep its own policy in
    one `except` clause without having to know whether the failure was IO or
    YAML -- a distinction none of the six acted on differently.
    """
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuleLoadError(f"Could not read {p}: {exc}") from exc

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"Could not parse {p}: {exc}") from exc

    if not isinstance(data, dict):
        kind = "empty" if data is None else type(data).__name__
        raise RuleLoadError(f"Not a Sigma rule mapping ({kind}): {p}")

    return data


def detect_id(rule: dict) -> str:
    """The rule's `detect_id`, or '' when absent or blank.

    Written out identically at five call sites before this. The `or ""` guard
    matters: `detect_id:` with nothing after it parses to `None`, and `str(None)`
    is the string "None" -- which would then be compared against Splunk object
    names and match nothing, silently.
    """
    return str(rule.get("detect_id") or "").strip()


def title(rule: dict) -> str:
    return str(rule.get("title") or "").strip()


def status(rule: dict) -> str:
    """Lower-cased `status`, or '' when absent."""
    return str(rule.get("status") or "").strip().lower()


def is_deprecated(rule: dict) -> bool:
    """True for a rule that is still in the repo but no longer wanted in Splunk.

    The deploy skips these and the reconcile drops them from desired state, so
    that a still-live object shows up as a removal orphan -- which is the
    accurate description of it.
    """
    return status(rule) == "deprecated"
