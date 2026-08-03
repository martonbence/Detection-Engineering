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

READ-ONLY BY DESIGN. It issues GETs and nothing else -- there is deliberately
no --apply. Making the deletions automatic is a separate decision with a
separate blast radius, and it should be taken with this report already in hand,
not at the same time as building the thing that produces it.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import quote

import requests
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.rule_naming import saved_search_name  # noqa: E402

# The deploy script stamps this into every description it writes
# (deploy_spl_to_splunk.py: build_savedsearch_description). It is therefore
# already a de-facto "managed by CI" marker on every object the pipeline owns,
# which is why this does not need a new `ci_managed` sidecar field: the mark is
# on the Splunk object, where the question is actually being asked. A field in
# the repo could only describe rules the repo still has -- and an orphan is
# precisely a rule the repo no longer has.
CI_MARKER = "Managed by CI/CD (Detection-Engineering repo)"


class ReconcileError(RuntimeError):
    """Raised for conditions that make the comparison impossible to trust."""


def env_required(name: str) -> str:
    value = (os.getenv(name) or "").strip()
    if not value:
        raise ReconcileError(f"Missing required env var: {name}")
    return value


def env_bool(name: str, default: bool = True) -> bool:
    value = (os.getenv(name) or "").strip().lower()
    if value in ("true", "1", "yes", "y", "on"):
        return True
    if value in ("false", "0", "no", "n", "off"):
        return False
    return default


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

    for path in sorted(rules_dir.glob("*.yml")):
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ReconcileError(f"Could not parse {path}: {exc}") from exc

        detect_id = str(rule.get("detect_id") or "").strip()
        title = str(rule.get("title") or "").strip()

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
    desired_ids = {info["detect_id"] for info in desired.values()}

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
            renamed.append({"name": name, "detect_id": detect_id})
        else:
            removed.append({"name": name, "detect_id": detect_id})

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
    counts = report["counts"]
    return any(
        counts[key] for key in ("missing", "orphan_renamed", "orphan_removed")
    )


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

    if report["orphan_removed"]:
        print(f"\nORPHANED BY REMOVAL -- audit item 1.7 ({counts['orphan_removed']}):")
        for item in report["orphan_removed"]:
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
    args = parser.parse_args(argv)

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

        session = requests.Session()
        session.verify = env_bool("SPLUNK_VERIFY_TLS", default=True)
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

    if args.json_path:
        out_path = Path(args.json_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"Report written to {out_path}")

    if has_drift(report) and args.fail_on_drift:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
