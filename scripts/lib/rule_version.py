"""Git-commit-count-derived rule versioning, shared by the converter and the
stats generator.

Register item 3.5, dedup half only -- the item also questions the *scheme*
itself (a version nobody sets, derived from how many commits happened to
touch the file, bumped the same by a typo fix and a rewrite, allocated in
bulk to every rule a mass-rename script touches). That is a separate,
larger decision (an explicit `version:` field in the Sigma YAML plus a CI
gate on it) and is not made here; this module only removes the duplicate
implementation the two callers had drifted into.

Before this module, `sigma_to_spl.py` and `generate_stats.py` each computed
`1.{commit_count - 1}` from `git log --follow` independently, and had
already diverged on more than formatting:

    sigma_to_spl.py     no cwd override (relies on process cwd), no timeout,
                         returns "1.0" when git fails or the count is 0
    generate_stats.py   cwd=REPO_ROOT, 60s timeout,
                         returns ""    when git fails or the count is 0

The empty-vs-"1.0" difference is not an accident worth erasing: the
converter is about to stamp a version onto a sidecar it is writing
regardless, so a placeholder is the least-wrong answer; the dashboard is
reporting what it *knows* about an existing rule, where asserting "1.0" it
never actually measured could manufacture a false match (or a false
mismatch) against a verdict's recorded rule_version. Register item 3.6
already drew this exact lesson from `env_required` -- something that looks
duplicated because the *reading* is identical can still carry a policy
difference at each call site. Here that policy is the `default` parameter,
not collapsed to one hardcoded choice.

The cwd/timeout divergence, by contrast, was not a considered difference
anywhere in either commit history -- both call sites always run inside the
repo, so `repo_root` defaults to the caller's choice, and the timeout is
applied unconditionally: a hung git process should not be able to hang a
CI step in either caller.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


def commit_count(rule_path: Path | str, repo_root: Path | str | None = None) -> int:
    """How many commits have touched `rule_path`, following renames.

    `git log --follow` so restructuring or renaming a rule file never resets
    its version count. Returns 0 on any git failure (missing binary, path
    outside a repo, timeout, ...) -- callers turn that into their own
    default via `compute_rule_version`.
    """
    try:
        result = subprocess.run(
            ["git", "log", "--follow", "--format=%H", "--", str(rule_path)],
            cwd=str(repo_root) if repo_root else None,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception:
        return 0
    if result.returncode != 0:
        return 0
    return len([line for line in result.stdout.splitlines() if line.strip()])


def compute_rule_version(
    rule_path: Path | str,
    repo_root: Path | str | None = None,
    default: str = "1.0",
) -> str:
    """Rule versioning scheme: 1.0 on the first commit, 1.1 on the second, etc.

    `default` is what a caller gets for an empty path or when git could not
    measure the file -- the two existing callers disagree on what that
    should be (see the module docstring), so it is a parameter here rather
    than a choice this module makes for them.
    """
    if not rule_path:
        return default
    count = commit_count(rule_path, repo_root)
    if count <= 0:
        return default
    return f"1.{max(0, count - 1)}"
