"""
Remove the repo-side remains of rules that no longer exist.

reconcile.py handles the Splunk side of retirement; this handles the other
half of register item 1.7, which is entirely inside the repo. Deleting a Sigma
rule leaves two things behind, and nothing ever collects them:

  rules/splunk/<same stem>.spl   the converted query. Prod deploys from
                                 `git ls-files`, so a leftover .spl keeps going
                                 out to production long after its rule is gone.
  outputs/results/<detect_id>/   the verification results, which keep feeding
                                 the dashboard's coverage and pass-rate numbers
                                 for a rule that no longer exists.

The conversion step cannot do this itself: it only ever sees *changed* rule
files (`--diff-filter=AMRC` excludes deletions), so a commit that only deletes
a rule produces no work for it at all -- which is exactly why the leftovers
accumulate unnoticed.

Deliberately keyed off the rule files themselves rather than a diff: a diff
tells you what one commit did, while the question here is what is currently
unaccounted for. That also makes it self-healing for anything an earlier run
missed, and idempotent.

Rules with `status: deprecated` are NOT pruned. The rule is still in the repo,
so its converted query and its measurement history are still its own; what
deprecation changes is that the deploy skips it and reconcile.py wants its
Splunk object retired.
"""

import argparse
import shutil
import sys
from pathlib import Path

import yaml


class PruneError(RuntimeError):
    """Raised when the repo state makes pruning unsafe to attempt."""


def load_rule_identity(rules_dir: Path) -> tuple[set[str], set[str]]:
    """
    Return (file stems, detect_ids) of every rule currently in the repo.

    Two keys because the two artefact kinds are named differently: the .spl
    mirrors the rule's *filename*, while the results directory is named after
    its *detect_id*. Renaming the file orphans the first; deleting the rule
    orphans both.
    """
    if not rules_dir.is_dir():
        raise PruneError(f"Rules directory not found: {rules_dir}")

    stems: set[str] = set()
    detect_ids: set[str] = set()

    for path in sorted(rules_dir.glob("*.yml")):
        stems.add(path.stem)
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            # Guessing here would mean deleting the artefacts of a rule that
            # exists and is merely malformed.
            raise PruneError(f"Could not parse {path}: {exc}") from exc

        detect_id = str(rule.get("detect_id") or "").strip()
        if detect_id:
            detect_ids.add(detect_id)

    if not stems:
        # An empty rules directory would classify every artefact in the repo as
        # an orphan. Far more likely a bad path or a partial checkout than an
        # actual instruction to delete the entire library.
        raise PruneError(
            f"No rules found in {rules_dir}. Refusing to treat every artefact as an orphan."
        )

    return stems, detect_ids


def find_orphans(rules_dir: Path, spl_dir: Path, results_dir: Path) -> dict:
    stems, detect_ids = load_rule_identity(rules_dir)

    orphan_spl = [
        path for path in sorted(spl_dir.glob("*.spl")) if path.stem not in stems
    ] if spl_dir.is_dir() else []

    orphan_results = [
        path
        for path in sorted(results_dir.iterdir())
        if path.is_dir() and path.name not in detect_ids
    ] if results_dir.is_dir() else []

    return {
        "rules": len(stems),
        "orphan_spl": orphan_spl,
        "orphan_results": orphan_results,
    }


def prune(orphans: dict, apply: bool) -> int:
    """Delete (or, without --apply, just name) every orphan found."""
    removed = 0

    for path in orphans["orphan_spl"]:
        # The .meta.json sidecar is generated next to the .spl and gitignored,
        # so it is invisible to git but very much present in a CI workspace --
        # leaving it would keep feeding a deleted rule's metadata to any step
        # that reads the directory rather than the git index.
        sidecar = path.with_suffix(".meta.json")
        if apply:
            path.unlink()
            if sidecar.exists():
                sidecar.unlink()
        print(f"  {'removed' if apply else 'would remove'}: {path}")
        removed += 1

    for path in orphans["orphan_results"]:
        if apply:
            shutil.rmtree(path)
        print(f"  {'removed' if apply else 'would remove'}: {path}/")
        removed += 1

    return removed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Delete converted SPL and verification results belonging to rules that no longer exist.",
    )
    parser.add_argument("--rules-dir", default="rules/sigma")
    parser.add_argument("--spl-dir", default="rules/splunk")
    parser.add_argument("--results-dir", default="outputs/results")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually delete. Without it, only reports what would go.",
    )
    args = parser.parse_args(argv)

    try:
        orphans = find_orphans(
            Path(args.rules_dir), Path(args.spl_dir), Path(args.results_dir)
        )
    except PruneError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    total = len(orphans["orphan_spl"]) + len(orphans["orphan_results"])

    print(f"\n=== Repo artefact prune ({orphans['rules']} rules in the repo) ===")
    if not total:
        print("Nothing orphaned: every .spl and results directory belongs to a rule.")
        return 0

    print(f"Orphaned artefacts of deleted or renamed rules ({total}):")
    prune(orphans, apply=args.apply)

    if not args.apply:
        print("\nNothing was deleted. Re-run with --apply to remove them.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
