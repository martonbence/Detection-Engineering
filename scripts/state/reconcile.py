"""
Compare what the repo says should exist in Splunk against what actually does.

The pipeline is one-directional: it creates and updates saved searches, and
nothing ever looks back. Delete a rule, rename its title, or let a conversion
fail, and Splunk keeps whatever it was last told -- there is no step anywhere
that notices. Three audit items are the same blind spot seen from different
angles:

  1.7  no deletion path at all (`--diff-filter=AMRC` never sees a removal)
  1.8  renaming a rule's title changes the derived object name, so the old
       saved search is left behind under the previous name
  4.7  nothing on the dashboard says which rules are actually live

This script answers the question those share: what is the difference between
desired and actual state?

Read-only unless asked otherwise. Plain `--check` (the default) issues GETs and
nothing else; the write path is behind explicit flags, and the two kinds of
orphan are treated differently on purpose:

  --apply            deletes orphans left behind by a RENAME. Safe enough to
                     run on every deploy: the detect_id is still in the repo, so
                     the rule demonstrably lives on under its new name and this
                     object is the abandoned shell of the old one.
  --apply-removals   additionally RETIRES orphans whose rule is gone from the
                     repo entirely -- disabled, not deleted, and marked in the
                     description. Deliberately a second, separate opt-in: a rule
                     disappearing from the repo is not always intentional, and
                     silently stopping a detection is exactly the failure this
                     whole area is about. Disabling is reversible; deleting the
                     object would also throw away its Splunk-side scheduling and
                     alert configuration.

1.8 was closed on 2026-08-04 by deciding NOT to change the naming scheme: the
object name stays human-readable (`detect_id + slug(title)`), because that is
what an analyst sees in Splunk's search bar and alert lists. The consequence is
that renames keep producing orphans forever, so cleaning the rename bucket is a
standing mechanism rather than a one-off migration -- which is why --apply is
built to run unattended and --apply-removals is not.
"""

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from urllib.parse import quote

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.env import announce_tls_mode, env_bool, env_reader
from lib.rule_naming import saved_search_name

# Aliased: load_desired() keeps local `detect_id` and `title` variables that
# the rest of the function reads several times, and importing the helpers under
# their own names would shadow them.
from lib.rules import RuleLoadError, discover, is_deprecated, load_rule
from lib.rules import detect_id as rule_detect_id
from lib.rules import title as rule_title

# The deploy script stamps this into every description it writes
# (deploy_spl_to_splunk.py: build_savedsearch_description). It is therefore
# already a de-facto "managed by CI" marker on every object the pipeline owns,
# which is why this does not need a new `ci_managed` sidecar field: the mark is
# on the Splunk object, where the question is actually being asked. A field in
# the repo could only describe rules the repo still has -- and an orphan is
# precisely a rule the repo no longer has.
CI_MARKER = "Managed by CI/CD (Detection-Engineering repo)"

# Written to the front of a retired object's description, and matched on the
# prefix alone so the date can vary without breaking idempotency. Its job is to
# make the state legible in the Splunk UI -- a disabled search with no
# explanation invites someone to helpfully switch it back on.
RETIRED_MARKER = "[RETIRED"


class ReconcileError(RuntimeError):
    """Raised for conditions that make the comparison impossible to trust."""


# Register item 3.6: the reading is shared, the failure policy stays here. It
# has to be an exception rather than an exit, unlike the other three consumers:
# main() catches ReconcileError to separate "the comparison could not be
# trusted" from a drift finding, and a SystemExit raised down here would bypass
# that distinction entirely.
def _fail(msg: str) -> None:
    raise ReconcileError(msg)


env_required = env_reader(_fail)


def load_desired(rules_dir: Path) -> dict[str, dict]:
    """
    Desired state: the saved-search name every Sigma rule in the repo would
    deploy under, keyed by that name.

    Derived from the Sigma YAML rather than the .meta.json sidecars on purpose:
    the sidecars are generated during a run and gitignored (`.gitignore:1`), so
    outside a CI job they simply do not exist. `detect_id` and `title` are both
    top-level Sigma fields, and saved_search_name() is the same function the
    deploy uses, so this reproduces the deploy's naming exactly without needing
    to run a conversion first.
    """
    desired: dict[str, dict] = {}

    for path in discover(rules_dir):
        try:
            rule = load_rule(path)
        except RuleLoadError as exc:
            # Unchanged policy: refuse to compare rather than compare against a
            # library we could not fully read. main() distinguishes this from a
            # drift finding, and that distinction is the whole point -- an
            # unreadable rule must not look like an orphaned Splunk object.
            raise ReconcileError(str(exc)) from exc

        detect_id = rule_detect_id(rule)
        title = rule_title(rule)

        # A deprecated rule is still in the repo but is no longer wanted in
        # Splunk -- the deploy skips it (deploy_spl_to_splunk.py), so leaving it
        # in the desired state here would report it as permanently "missing" and
        # ask for a deployment that will never happen. Dropping it instead makes
        # any object that still exists show up as a removal orphan, which is the
        # accurate description: it is live, and it should not be.
        if is_deprecated(rule):
            continue

        if not detect_id:
            # Not this script's job to enforce -- the schema already requires
            # it. Skipping loudly beats inventing a name and reporting a
            # phantom mismatch.
            print(f"WARNING: {path} has no detect_id; skipped.", file=sys.stderr)
            continue

        name = saved_search_name({"detect_id": detect_id, "title": title})
        desired[name] = {"detect_id": detect_id, "title": title, "path": str(path)}

    return desired


def fetch_actual(
    session: requests.Session,
    base_url: str,
    owner: str,
    app: str,
) -> dict[str, dict]:
    """
    Actual state: saved searches that exist in the target app, keyed by name.

    Scoped to the same servicesNS/{owner}/{app} namespace the deploy writes to,
    so this compares like with like. count=0 disables Splunk's default 30-row
    page limit -- without it a library larger than 30 rules would silently
    report every rule past the first page as missing.
    """
    url = (
        f"{base_url}/servicesNS/{quote(owner, safe='')}/{quote(app, safe='')}"
        f"/saved/searches?output_mode=json&count=0"
    )

    response = session.get(url, timeout=30)

    if response.status_code in (401, 403):
        raise ReconcileError(
            f"Authentication or permission error listing saved searches "
            f"(HTTP {response.status_code})."
        )
    if response.status_code != 200:
        raise ReconcileError(
            f"Unexpected response listing saved searches "
            f"(HTTP {response.status_code}): {response.text[:300]}"
        )

    try:
        payload = response.json()
    except ValueError as exc:
        raise ReconcileError(f"Splunk returned a non-JSON response: {exc}") from exc

    actual: dict[str, dict] = {}
    for entry in payload.get("entry") or []:
        name = str(entry.get("name") or "").strip()
        if not name:
            continue
        content = entry.get("content") or {}
        description = str(content.get("description") or "")
        actual[name] = {
            "description": description,
            "managed": CI_MARKER in description,
            "disabled": str(content.get("disabled", "")),
            "is_scheduled": str(content.get("is_scheduled", "")),
        }

    return actual


def is_disabled(value: str) -> bool:
    """
    Splunk reports `disabled` as a JSON bool on some endpoints and as "0"/"1" on
    others, and fetch_actual() str()s whatever arrives -- so this has to accept
    both spellings rather than comparing against one of them.
    """
    return str(value).strip().lower() in ("1", "true")


def is_retired(info: dict) -> bool:
    """An object already taken out of service by a previous --apply-removals."""
    return is_disabled(info.get("disabled", "")) and str(
        info.get("description", "")
    ).lstrip().startswith(RETIRED_MARKER)


def reconcile(desired: dict[str, dict], actual: dict[str, dict]) -> dict:
    """
    Sort every name into exactly one bucket.

    The two orphan buckets are deliberately separate. Both are objects the
    pipeline created and the repo no longer asks for, but they mean different
    things and call for different actions: an orphan whose detect_id is still
    in the repo is a *rename* (audit 1.8) -- the rule is alive and well under a
    new name, and this is its abandoned shell, safe to delete. An orphan whose
    detect_id is gone entirely is a *removal* (audit 1.7), which deserves a look
    before anything is deleted, because a rule vanishing from the repo is not
    always intentional.
    """
    desired_by_id = {info["detect_id"]: name for name, info in desired.items()}
    desired_ids = set(desired_by_id)

    in_sync, missing, renamed, removed, unmanaged = [], [], [], [], []

    for name, info in sorted(desired.items()):
        if name in actual:
            in_sync.append({"name": name, **info})
        else:
            missing.append({"name": name, **info})

    for name, info in sorted(actual.items()):
        if name in desired:
            continue

        if not info["managed"]:
            # Someone's hand-built search living in the same app. Reported so
            # the numbers add up, never actioned: the pipeline did not create
            # it and has no business having an opinion about it.
            unmanaged.append({"name": name})
            continue

        # Names are "<detect_id>_<title-slug>", so the prefix up to the first
        # underscore identifies the rule independently of its title.
        detect_id = name.split("_", 1)[0]

        if detect_id in desired_ids:
            # Whether the successor is actually live decides if this is safe to
            # delete. "The rule lives on under its new name" is the entire
            # justification for the automatic deletion, so it is checked rather
            # than assumed: if the deploy that was meant to create the new
            # object failed, deleting the old one would leave the rule with no
            # saved search at all -- silently, and precisely for a rule someone
            # just edited.
            replacement = desired_by_id[detect_id]
            renamed.append({
                "name": name,
                "detect_id": detect_id,
                "replacement": replacement,
                "replacement_live": replacement in actual,
            })
        else:
            # description travels with the item because retiring rewrites it
            # (prefix, never replace -- dropping the CI marker would make the
            # object unrecognisable to the next run and it would show up as
            # somebody's hand-built search).
            removed.append({
                "name": name,
                "detect_id": detect_id,
                "description": info.get("description", ""),
                "retired": is_retired(info),
            })

    return {
        "in_sync": in_sync,
        "missing": missing,
        "orphan_renamed": renamed,
        "orphan_removed": removed,
        "unmanaged": unmanaged,
        "counts": {
            "desired": len(desired),
            "actual": len(actual),
            "in_sync": len(in_sync),
            "missing": len(missing),
            "orphan_renamed": len(renamed),
            "orphan_removed": len(removed),
            "unmanaged": len(unmanaged),
        },
    }


def has_drift(report: dict) -> bool:
    """
    Already-retired removals are not drift. They are the resolved state of a
    removal: disabled, marked, and deliberately kept for reversibility. Counting
    them would leave the report permanently red after the first --apply-removals
    and train everyone to ignore it.
    """
    counts = report["counts"]
    if counts["missing"] or counts["orphan_renamed"]:
        return True
    return any(not item["retired"] for item in report["orphan_removed"])


def object_url(base_url: str, owner: str, app: str, name: str) -> str:
    return (
        f"{base_url}/servicesNS/{quote(owner, safe='')}/{quote(app, safe='')}"
        f"/saved/searches/{quote(name, safe='')}?output_mode=json"
    )


def delete_saved_search(
    session: requests.Session, base_url: str, owner: str, app: str, name: str
) -> tuple[bool, str]:
    """Remove a rename orphan. Its replacement is already deployed and running."""
    response = session.delete(object_url(base_url, owner, app, name), timeout=30)

    if response.status_code in (200, 201):
        return True, "deleted"
    if response.status_code == 404:
        # Someone got there first, by hand or in a concurrent run. The end state
        # is the one we wanted, so this is not a failure.
        return True, "already absent"
    return False, f"HTTP {response.status_code}: {response.text[:200]}"


def retire_saved_search(
    session: requests.Session,
    base_url: str,
    owner: str,
    app: str,
    name: str,
    description: str,
) -> tuple[bool, str]:
    """
    Take a removal orphan out of service without destroying it: disable the
    schedule and say why in the description.

    Both fields go in one POST rather than using the /disable action endpoint
    plus a second write -- a half-applied retirement (disabled but unexplained,
    or explained but still firing) is worse than either end state.
    """
    marked = f"{RETIRED_MARKER} {date.today().isoformat()}] {description}".rstrip()

    response = session.post(
        object_url(base_url, owner, app, name),
        data={"disabled": 1, "description": marked},
        timeout=30,
    )

    if response.status_code in (200, 201):
        return True, "disabled and marked"
    return False, f"HTTP {response.status_code}: {response.text[:200]}"


def apply_changes(
    session: requests.Session,
    base_url: str,
    owner: str,
    app: str,
    report: dict,
    include_removals: bool,
) -> dict:
    """
    Act on the orphan buckets. Never touches `unmanaged` (not ours) or `missing`
    (a deploy's job, not a cleanup's).
    """
    actions: list[dict] = []
    failures = 0

    print("\n=== Applying ===")

    for item in report["orphan_renamed"]:
        if not item["replacement_live"]:
            print(
                f"  SKIP delete {item['name']} -- its replacement "
                f"{item['replacement']} is not in Splunk yet; deleting now would "
                "leave the rule with no saved search at all."
            )
            continue

        ok, detail = delete_saved_search(session, base_url, owner, app, item["name"])
        actions.append({"action": "delete", "name": item["name"], "ok": ok, "detail": detail})
        failures += 0 if ok else 1
        print(f"  {'OK  ' if ok else 'FAIL'} delete {item['name']} -- {detail}")

    if not report["orphan_renamed"]:
        print("  No rename orphans to delete.")

    if include_removals:
        for item in report["orphan_removed"]:
            if item["retired"]:
                print(f"  SKIP retire {item['name']} -- already retired")
                continue
            ok, detail = retire_saved_search(
                session, base_url, owner, app, item["name"], item["description"]
            )
            actions.append({"action": "retire", "name": item["name"], "ok": ok, "detail": detail})
            failures += 0 if ok else 1
            print(f"  {'OK  ' if ok else 'FAIL'} retire {item['name']} -- {detail}")
    elif any(not item["retired"] for item in report["orphan_removed"]):
        print(
            "  Removal orphans left untouched (pass --apply-removals to disable them).\n"
            "  A rule vanishing from the repo is not always intentional, so this one is manual."
        )

    return {"actions": actions, "failures": failures}


def print_report(report: dict, app: str) -> None:
    counts = report["counts"]

    print(f"\n=== Splunk state reconciliation (app: {app}) ===")
    print(f"Repo wants : {counts['desired']} saved search(es)")
    print(f"Splunk has : {counts['actual']} saved search(es) in this app")
    print(f"In sync    : {counts['in_sync']}")

    if report["missing"]:
        print(f"\nMISSING -- the repo defines these, Splunk does not have them ({counts['missing']}):")
        for item in report["missing"]:
            print(f"  - {item['name']}")
            print(f"      from {item['path']}")
        print("  Cause is usually that the rule has not completed a full dev run yet.")

    if report["orphan_renamed"]:
        print(f"\nORPHANED BY RENAME -- audit item 1.8 ({counts['orphan_renamed']}):")
        for item in report["orphan_renamed"]:
            print(f"  - {item['name']}")
            print(f"      {item['detect_id']} still exists in the repo under a different title,")
            print("      so this object is the abandoned shell of its previous name.")
            if not item["replacement_live"]:
                print(f"      NOTE: its replacement {item['replacement']} is not in Splunk yet,")
                print("      so --apply will leave this one in place for now.")

    if report["orphan_removed"]:
        print(f"\nORPHANED BY REMOVAL -- audit item 1.7 ({counts['orphan_removed']}):")
        for item in report["orphan_removed"]:
            if item["retired"]:
                print(f"  - {item['name']}  [already retired -- disabled, kept for reversibility]")
                continue
            print(f"  - {item['name']}")
            print(f"      {item['detect_id']} is not in the repo at all. It is still live in Splunk")
            print("      and will keep running and alerting until someone removes it.")

    if report["unmanaged"]:
        print(f"\nNOT MANAGED BY CI -- reported only, never actioned ({counts['unmanaged']}):")
        for item in report["unmanaged"]:
            print(f"  - {item['name']}")

    print()
    if has_drift(report):
        print("RESULT: desired and actual state differ (see above).")
    else:
        print("RESULT: Splunk matches the repo.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare the repo's rules against the saved searches live in Splunk (read-only).",
    )
    parser.add_argument(
        "--rules-dir",
        default="rules/sigma",
        help="Directory of Sigma rules defining the desired state (default: rules/sigma)",
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        help="Also write the full report as JSON to this path (feeds audit item 4.7)",
    )
    parser.add_argument(
        "--fail-on-drift",
        action="store_true",
        help=(
            "Exit 1 when desired and actual differ. Off by default so that adding this "
            "to CI reports a pre-existing condition without blocking the pipeline on it."
        ),
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help=(
            "Delete saved searches orphaned by a rename. Safe to run unattended: the "
            "rule is alive under its new name, this is the shell of the old one."
        ),
    )
    parser.add_argument(
        "--apply-removals",
        action="store_true",
        help=(
            "Also retire orphans whose rule left the repo entirely -- disabled and marked, "
            "not deleted. Requires --apply. Separate on purpose: a rule disappearing from "
            "the repo is not always intentional."
        ),
    )
    args = parser.parse_args(argv)

    if args.apply_removals and not args.apply:
        parser.error("--apply-removals requires --apply")

    try:
        base_url = env_required("SPLUNK_BASE_URL").rstrip("/")
        username = env_required("SPLUNK_USERNAME")
        password = env_required("SPLUNK_PASSWORD")
        app = env_required("SPLUNK_APP")
        # Mirrors the deploy's namespace choice, which is itself dictated by
        # Splunk assigning ownership to whoever authenticates. Addressing a
        # different owner here would list a different namespace than the one
        # the deploy writes to, and every rule would look missing.
        owner = username

        verify_tls = env_bool("SPLUNK_VERIFY_TLS", default=True)
        announce_tls_mode(verify_tls)

        session = requests.Session()
        session.verify = verify_tls
        session.auth = (username, password)
        session.headers.update({"Accept": "application/json"})

        desired = load_desired(Path(args.rules_dir))
        actual = fetch_actual(session, base_url, owner, app)
    except ReconcileError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except requests.RequestException as exc:
        print(f"ERROR: could not reach Splunk: {exc}", file=sys.stderr)
        return 2

    report = reconcile(desired, actual)
    print_report(report, app)

    applied = None
    if args.apply:
        try:
            applied = apply_changes(
                session, base_url, owner, app, report, args.apply_removals
            )
        except requests.RequestException as exc:
            print(f"ERROR: could not reach Splunk while applying: {exc}", file=sys.stderr)
            return 2
        report["applied"] = applied

    if args.json_path:
        out_path = Path(args.json_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"Report written to {out_path}")

    # A write that did not land is an error in its own right, and outranks the
    # drift gate: the report describes the state *before* the apply, so staying
    # quiet here would hide a failed cleanup behind a green --check.
    if applied and applied["failures"]:
        print(f"ERROR: {applied['failures']} action(s) failed.", file=sys.stderr)
        return 2

    if has_drift(report) and args.fail_on_drift:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
