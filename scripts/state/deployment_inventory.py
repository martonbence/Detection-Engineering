#!/usr/bin/env python3
"""
Register item 4.7 -- what is deployed where, and when anyone last looked.

The pipeline has always known this and always thrown it away. The deploy writes
a per-rule report (item 2.4) and the reconcile writes a per-object comparison
(item 3.3), but both land in `.gitignore`d directories and travel as build
artifacts that expire. The dashboard is generated from repo files, so it could
never see either, and the repo has therefore never held an answer to "is this
rule actually running in prod, at which version?".

Two incidents made the cost concrete rather than theoretical:

  2026-08-07  A rule was deleted from prod by hand. Nothing said so -- not the
              repo (nothing in it changed), not the reconcile (it only looks at
              the dev app), not the dashboard. Only the person who deleted it
              knew.
  2026-08-08  A deploy-script fix was merged to main and did not reach prod:
              the prod workflow's `paths:` filter only fires on rule changes.
              Nothing said that either; it took a person noticing.

Both are the same shape. The deployment chain is one-way, so what happens at
the far end -- or fails to -- is invisible from where the work is done. This
file is the record that closes the loop, and the deliberate design decisions
around it are worth stating, because each one was a real fork:

**It is a digest, not a dump.** `.gitignore` rejects the raw reports with a
reason that still holds: "describes the Splunk instance at one moment, not the
repo -- committing it would add a commit per run that says nothing about the
code". A distilled inventory is a different object. Where a rule is deployed
and at what version is a fact about the *system*, and on a run that changes
nothing it serializes to identical bytes.

**It never records where prod is.** The 2.4 report deliberately omits the
Splunk URL, the app name and the account, because it is downloadable from a
public repository. This file is committed to that repository, so the same rule
binds harder. Everything here is derivable from the repo itself: it says what
we deployed and what we found, never where.

**Prod writes nothing.** The prod workflow runs with `contents: read` on
purpose. Its reports arrive here the way everything else does -- through a dev
run that ingests the artifact -- which is why every environment carries its own
`checked_at`. A stale prod section is not a bug to hide; it is the answer to
"when did anyone last look", and printing the timestamp is what makes it
honest.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = 1

# The counts worth carrying out of a reconcile report. Deliberately a fixed
# list rather than "whatever the report has": this file is rendered on a public
# dashboard, and a future reconcile field should have to be added here on
# purpose rather than arrive by accident.
DRIFT_COUNTS = (
    "missing",
    "orphan_renamed",
    "orphan_removed",
    "unmanaged",
    "duplicate_names",
)


def read_json(path: Path | None, label: str) -> dict | None:
    """Parse a JSON file, or return None with a warning.

    Missing or unreadable inputs are never fatal. A run that deployed nothing
    still has an inventory to update, and losing the whole file because one
    optional input was absent would trade a small gap for a total one.
    """
    if path is None:
        return None
    if not path.exists():
        print(f"WARNING: {label} not found at {path} -- that section will not be updated", file=sys.stderr)
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"WARNING: could not read {label} at {path}: {exc}", file=sys.stderr)
        return None


def load_inventory(path: Path) -> dict:
    """The existing inventory, or an empty one.

    Read rather than overwritten because each run only knows about its own
    environment: a dev run must not erase what the last prod ingest recorded.
    """
    existing = read_json(path, "existing inventory")
    if not isinstance(existing, dict) or "environments" not in existing:
        return {"schema": SCHEMA_VERSION, "environments": {}}
    existing.setdefault("schema", SCHEMA_VERSION)
    envs = existing.get("environments")
    if not isinstance(envs, dict):
        existing["environments"] = {}
    return existing


def deploy_section(
    report: dict, commit: str, run_id: str, run_url: str, previous: dict | None = None
) -> dict:
    """The per-rule half: what this deploy sent, and at which version.

    The rule map is *merged* into what was already known, not replaced, and the
    reason is the dev pipeline's deploy: it only ever ships the rules that
    changed in that push. A replacing map would therefore show one or two rules
    on dev and nothing else -- reading as "25 rules are not deployed" when they
    are all deployed and simply were not touched today.

    Merging makes each entry mean "this is the version dev was last given, and
    when", which is the honest per-rule statement and also the useful one: a
    rule sitting at 1.1 while the repo is at 1.4 has not been redeployed since,
    and that is exactly the gap this panel exists to show. Each entry therefore
    carries its own timestamp rather than inheriting the run's.

    Prod needs none of this -- its deploy ships the whole library from
    `git ls-files` every time -- but the same code serves both, and the merge is
    a no-op when every rule is present.
    """
    deployed_at = str(report.get("deployed_at") or "")
    rules: dict[str, dict] = dict((previous or {}).get("rules") or {})

    for entry in report.get("rules") or []:
        detect_id = str(entry.get("detect_id") or "").strip()
        if not detect_id:
            # A record with no detect_id is a file that failed before its meta
            # could be read. It belongs in the totals, not in a per-rule map
            # keyed by an id that does not exist.
            continue
        outcome = str(entry.get("outcome") or "")
        if outcome == "failed":
            # A failed deploy did not change what is running, so recording it as
            # the rule's state would replace a true version with a false one.
            # The totals still carry the failure.
            continue
        rules[detect_id] = {
            "rule_version": str(entry.get("rule_version") or ""),
            "outcome": outcome,
            "at": deployed_at,
        }

    return {
        "at": str(report.get("deployed_at") or ""),
        "commit": commit,
        "run_id": run_id,
        "run_url": run_url,
        "totals": report.get("totals") or {},
        "rules": rules,
    }


def state_section(reconcile: dict, checked_at: str) -> dict:
    """The ground-truth half: what was actually in Splunk when we looked.

    Separate from the deploy section on purpose. "We sent 27 rules" and "27
    rules are there" are different claims, and the 2026-08-07 deletion is
    exactly the case where the first stays true while the second stops being.
    """
    counts = reconcile.get("counts") or {}
    section = {
        "checked_at": checked_at,
        "in_sync": counts.get("in_sync"),
    }
    for key in DRIFT_COUNTS:
        section[key] = counts.get(key, 0)

    # `has_drift` mirrors reconcile.has_drift() rather than inventing a second
    # definition, and the two differences from "any non-zero count" are both
    # deliberate there:
    #
    #   unmanaged  -- saved searches nobody deployed from this repo. An
    #                 analyst's own search living in the app is not drift, and
    #                 colouring the dashboard red for it would teach people to
    #                 ignore the colour.
    #   orphan_removed -- only the ones NOT yet retired. An orphan that has been
    #                 disabled and marked is the resolved state, not an open
    #                 problem; counting it would make a completed cleanup look
    #                 like a permanent fault.
    #
    # `duplicate_names` is drift here and has no counterpart in reconcile's
    # function, which predates the duplicate reporting (item 2.19). Two objects
    # under one name means one of them is a shadow or a leftover, and that is
    # precisely the condition item 3.9 spent two days on.
    unretired = sum(
        1 for item in (reconcile.get("orphan_removed") or []) if not item.get("retired")
    )
    section["orphan_removed_unretired"] = unretired

    # The one place a count is not enough. "3 rules missing" tells the dashboard
    # to colour something red but not *which* row -- and a per-rule table that
    # cannot point at the offending rule is back to making the reader go and
    # look somewhere else, which is the habit this item exists to break. Names
    # rather than counts, so the panel can mark exactly the rules Splunk did not
    # have. Bounded by the rule library, and normally empty.
    section["missing_ids"] = sorted(
        str(item.get("detect_id") or "").strip()
        for item in (reconcile.get("missing") or [])
        if str(item.get("detect_id") or "").strip()
    )
    section["has_drift"] = bool(
        counts.get("missing")
        or counts.get("orphan_renamed")
        or counts.get("duplicate_names")
        or unretired
    )
    return section


def update(
    inventory: dict,
    env: str,
    deploy: dict | None,
    reconcile: dict | None,
    commit: str,
    run_id: str,
    run_url: str,
    deployed_at: str,
    now: str,
) -> dict:
    envs = inventory.setdefault("environments", {})
    section = envs.setdefault(env, {})

    if deploy is not None:
        section["last_deploy"] = deploy_section(
            deploy, commit, run_id, run_url, previous=section.get("last_deploy")
        )
    elif commit or run_id or deployed_at:
        # The prod path, and the reason this branch exists at all.
        #
        # Prod deploys are recorded by a workflow that cannot commit, so the
        # audit learns "which commit is production running" from the Actions
        # API instead of from a report file. Without this the fields arrived
        # and were silently dropped, leaving the inventory saying "no deploy
        # recorded" for an environment that has been deployed all along --
        # exactly the blind spot item 4.7 exists to remove.
        #
        # Merged into whatever is already there rather than replacing it: a
        # report-derived entry carries a per-rule map that this path has no way
        # to know, and overwriting it with metadata alone would lose real
        # information in the name of updating a timestamp.
        last = dict(section.get("last_deploy") or {})
        if deployed_at:
            last["at"] = deployed_at
        if commit:
            last["commit"] = commit
        if run_id:
            last["run_id"] = run_id
        if run_url:
            last["run_url"] = run_url
        section["last_deploy"] = last

    if reconcile is not None:
        section["splunk_state"] = state_section(reconcile, now)

    return inventory


def write_if_changed(path: Path, inventory: dict) -> bool:
    """Write only on a real change, and report whether anything moved.

    The whole objection to committing this kind of file is a commit per run
    that says nothing. Serializing deterministically and comparing first means
    a run that deployed the same rules at the same versions leaves no diff --
    the file earns its place in git by changing only when the system does.
    """
    rendered = json.dumps(inventory, indent=2, ensure_ascii=False, sort_keys=True) + "\n"

    if path.exists():
        try:
            if path.read_text(encoding="utf-8") == rendered:
                print(f"{path}: unchanged.")
                return False
        except OSError:
            pass  # fall through and rewrite

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8")
    print(f"{path}: updated.")
    return True


def summarize(inventory: dict) -> None:
    """A short human-readable state, for the step summary and the run log."""
    for env, section in sorted((inventory.get("environments") or {}).items()):
        deploy = section.get("last_deploy") or {}
        state = section.get("splunk_state") or {}
        rules = deploy.get("rules") or {}

        line = f"{env}: "
        if deploy:
            line += f"{len(rules)} rule(s) deployed at {deploy.get('at') or 'unknown time'}"
            commit = str(deploy.get("commit") or "")
            if commit:
                line += f" from {commit[:7]}"
        else:
            line += "no deploy recorded"

        if state:
            drift = "drift" if state.get("has_drift") else "in sync"
            line += f" · Splunk checked {state.get('checked_at') or 'never'}: {drift}"
        else:
            line += " · Splunk never checked"

        print(line)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fold a deploy report and/or a reconcile report into the deployment inventory.",
    )
    parser.add_argument("--env", required=True, help="Environment name, e.g. dev or prod")
    parser.add_argument(
        "--inventory",
        default="outputs/reports/deployment_inventory.json",
        help="The inventory file to update in place (default: %(default)s)",
    )
    parser.add_argument("--deploy-report", help="A deploy_spl_to_splunk.py --report file")
    parser.add_argument("--reconcile", help="A reconcile.py --json file")
    parser.add_argument("--commit", default="", help="The commit the deploy ran from")
    parser.add_argument("--run-id", default="", help="The CI run id that deployed")
    parser.add_argument("--run-url", default="", help="Link to that CI run")
    parser.add_argument(
        "--deployed-at",
        default="",
        help="When that deploy ran, ISO 8601. Used when there is no report to read it from.",
    )
    args = parser.parse_args(argv)

    if not args.deploy_report and not args.reconcile:
        parser.error("nothing to fold in: pass --deploy-report, --reconcile, or both")

    inventory_path = Path(args.inventory)
    deploy = read_json(Path(args.deploy_report) if args.deploy_report else None, "deploy report")
    reconcile = read_json(Path(args.reconcile) if args.reconcile else None, "reconcile report")

    if deploy is None and reconcile is None:
        # Both inputs were named and neither could be read. Writing now would
        # record an environment we learned nothing about, and an inventory that
        # invents state is worse than one that is out of date.
        print("ERROR: none of the named inputs could be read -- inventory left untouched", file=sys.stderr)
        return 1

    inventory = load_inventory(inventory_path)
    update(
        inventory,
        env=args.env,
        deploy=deploy,
        reconcile=reconcile,
        commit=args.commit,
        run_id=args.run_id,
        run_url=args.run_url,
        deployed_at=args.deployed_at,
        now=datetime.now(UTC).isoformat(),
    )

    write_if_changed(inventory_path, inventory)
    summarize(inventory)
    return 0


if __name__ == "__main__":
    sys.exit(main())
