import argparse
import datetime
import json
import os
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.env import announce_tls_mode, env_bool, env_reader
from lib.meta_sidecar import meta_sidecar_path, read_meta_sidecar
from lib.rule_naming import saved_search_name
from lib.splunk_client import build_session
from lib.splunk_ns import saved_search_url, saved_searches_url
from lib.summary import MARK_FAIL, MARK_INFO, MARK_PASS, escape_cell


def die(msg: str, code: int = 1) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)


# Register item 3.6: the reading is shared, the exit policy stays here. Exit 1
# is this script's convention for any setup failure, and env_reader keeps every
# call site below unchanged while the parsing itself lives in one place.
env_required = env_reader(die)


def read_spl_query(path: Path) -> str:
    """
    Return the SPL query. The file contains only the query -- no embedded metadata.
    """
    query = path.read_text(encoding="utf-8").strip()

    if not query:
        die(f"No SPL query found in file: {path}")

    return query


def extract_meta(path: Path) -> dict:
    """
    Read the sidecar <name>.meta.json generated alongside <name>.spl by sigma_to_spl.py.

    A missing or malformed sidecar is a setup failure here, not a measurement
    gap -- see lib/meta_sidecar.py for why this differs from the verify side.
    """
    try:
        return read_meta_sidecar(path)
    except FileNotFoundError as e:
        die(f"Meta sidecar not found: {e.filename}")
    except json.JSONDecodeError as e:
        die(f"Invalid meta JSON in {meta_sidecar_path(path)}: {e}")


def _norm_mode(v: str) -> str:
    v = (v or "").strip().lower()
    return v if v in ("report", "alert") else ""


def _default_if_empty(v: str, default: str) -> str:
    v = (v or "").strip()
    return v if v else default


def _severity_to_splunk_value(v: str) -> str:
    """
    Map rule severity to Splunk savedsearch alert.severity.

    Splunk REST expects numeric values:
      1=info, 2=low, 3=medium, 4=high, 5=critical, 6=fatal
    """
    mapping = {
        "low": "2",
        "medium": "3",
        "high": "4",
        "critical": "5",
    }
    return mapping.get((v or "").strip().lower(), "")


def build_splunk_runtime_payload_from_header(path: Path) -> dict:
    """
    Create savedsearch runtime fields (report vs alert) from META JSON.

    Supported META keys:
      - deploy_mode: report|alert
      - cron: */5 * * * *          (optional, defaults to */5 * * * *)
      - earliest: -5m             (optional, defaults to -5m)
      - latest: now               (optional, defaults to now)
    """
    meta = extract_meta(path)

    deploy_mode = (meta.get("deploy_mode") or "").strip().lower()
    if deploy_mode not in ("report", "alert"):
        die(f"Invalid deploy_mode in META for {path}: {deploy_mode!r} (allowed: 'report'|'alert')")

    # Default behavior: report -> not scheduled
    if deploy_mode != "alert":
        return {
            "is_scheduled": "0",
            # Keep it enabled as an object (just not scheduled)
            "disabled": "0",
        }

    cron = _default_if_empty(str(meta.get("cron") or ""), "*/5 * * * *")
    earliest = _default_if_empty(str(meta.get("earliest") or ""), "-5m")
    latest = _default_if_empty(str(meta.get("latest") or ""), "now")
    severity = _severity_to_splunk_value(str(meta.get("severity") or ""))

    payload = {
        "is_scheduled": "1",
        "cron_schedule": cron,
        "dispatch.earliest_time": earliest,
        "dispatch.latest_time": latest,
        "disabled": "0",

        # Trigger an alert when results exist (events > 0)
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": "0",

        # Optional but useful for visibility in Splunk UI/alerting
        "alert.track": "1",
    }

    if severity:
        payload["alert.severity"] = severity

    return payload



def build_savedsearch_description(
    ci_constant: str, sigma_description: str, rule_version: str = "", max_len: int = 800
) -> str:
    """
    Combine constant CI description + rule version + Sigma rule description into
    a single Splunk savedsearch description.

    `rule_version` is meta["rule_version"]. Register item 3.5, closed for
    real: this used to be the git-commit-count-derived value from
    lib/rule_version.py's compute_rule_version() (1.0, 1.1, ...) -- the same
    number generate_stats.py's staleness/superseded-verdict check used --
    which bumped on any edit to the rule file, including a non-semantic one
    (a typo fix), not only when detection logic changed.

    An earlier version of this function sourced this parameter from the
    hand-maintained Sigma `version:` field (meta["version"], gated by
    check_version_bump.py) instead, specifically to avoid surfacing that
    edit-count number in Splunk, and was deliberately swapped back to
    meta["rule_version"] at the source's request -- see git history/PR
    discussion around this line for that reasoning. That tension is now
    moot: sigma_to_spl.py's build_meta_dict() populates meta["rule_version"]
    *from* the YAML `version:` field directly (compute_rule_version() and
    lib/rule_version.py are gone), auto-bumped by .githooks/pre-commit on a
    real detection-logic change and gated as a backstop by
    check_version_bump.py. There is only the one number now; this
    parameter's name is what it is for call-site continuity, not because it
    still means something different from meta["version"].

    An empty/missing value (a rule somehow missing the now-required
    `version:` field) omits the line entirely -- never a blank line.
    """
    base = (ci_constant or "").strip()
    sigma = (sigma_description or "").strip()
    rule_version = (rule_version or "").strip()

    # Flatten multi-line sigma descriptions for Splunk UI
    sigma = " ".join(sigma.split())

    lines = [base]
    if rule_version:
        lines.append(f"Rule version: {rule_version}")
    if sigma:
        if len(sigma) > max_len:
            sigma = sigma[:max_len] + "..."
        lines.append(sigma)

    return "\n".join(lines)

def splunk_post(session: requests.Session, url: str, data: dict) -> requests.Response:
    # Splunkd REST expects form-encoded by default; requests does this with data=
    return session.post(url, data=data, timeout=30)


# Register item 2.6 removed is_already_exists() from here. It decided whether a
# saved search already existed by searching Splunk's error *text* for "already
# exists" / "conflict" / "in use" -- wording that varies by Splunk version and
# is not part of any contract, and which three unrelated failures could also
# contain. The deploy now asks the object endpoint instead and reads the status
# code, which is the contract.


def _perm_set(value: str) -> set[str]:
    """Splunk returns perms as a list; the config carries them comma-separated."""
    if isinstance(value, list):
        return {str(v).strip() for v in value if str(v).strip()}
    return {part.strip() for part in str(value or "").split(",") if part.strip()}


def read_acl(session: requests.Session, acl_url: str) -> dict | None:
    """The object's current ACL, or None when it cannot be read.

    None means "could not determine", never "no permissions" -- the caller
    falls through to the POST rather than assuming anything, so an unreadable
    ACL behaves exactly as it did before this comparison existed.
    """
    try:
        r = session.get(acl_url, timeout=30)
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None
    try:
        entries = r.json().get("entry") or []
    except ValueError:
        return None
    return (entries[0].get("acl") or {}) if entries else None


def acl_matches(current: dict, sharing: str, perms_read: str, perms_write: str) -> bool:
    perms = current.get("perms") or {}
    return (
        str(current.get("sharing") or "").strip() == sharing.strip()
        and _perm_set(perms.get("read")) == _perm_set(perms_read)
        and _perm_set(perms.get("write")) == _perm_set(perms_write)
    )


def set_acl(
    session: requests.Session,
    base_url: str,
    acl_owner: str,
    app: str,
    search_name: str,
    sharing: str,
    perms_read: str,
    perms_write: str,
) -> tuple[bool, str]:
    """
    Bring the object's ACL to the configured sharing and permissions.

    Reads before writing, which is what stops this being the noisiest line in
    every run. Splunk promotes an object to app scope once; POSTing the same
    promotion to an object that is *already* app-scoped is rejected with
    HTTP 409 "Cannot overwrite existing app object". Since the deploy updates
    far more often than it creates, the old unconditional POST meant a 409 per
    rule per run -- 27 of them on a full run, all of them meaning "the ACL is
    already correct".

    That noise was the smaller problem. Because the 409 came back whether the
    ACL was right or wrong, the deploy could never tell the two apart, and so
    could never correct real ACL drift: change SPLUNK_PERMS_READ and existing
    objects keep the old permissions forever, reporting it with the same warning
    everyone has learned to scroll past. Comparing first separates them -- a
    matching ACL is silent, and a mismatch that will not apply is now a warning
    that means something.

    `acl_owner` is the authenticating account, and is only ever the *payload*
    owner -- the URL goes through the `nobody` namespace like every other write
    here. See lib/splunk_ns.py: `nobody` in the payload is read as an ownership
    change and refused with 403, while the account's own name is accepted and
    still applies sharing and permissions.
    """
    acl_url = (
        f"{saved_search_url(base_url, app, search_name)}/acl?output_mode=json"
    )

    current = read_acl(session, acl_url)
    if current is not None and acl_matches(current, sharing, perms_read, perms_write):
        return True, "ACL already correct"

    payload = {
        "owner": acl_owner,          # Required, and must be the authenticating account:
                                     # omitting it and naming `nobody` both come back 403
                                     # ("You do not have permission to change the owner of
                                     # this object"); this value changes nothing and is
                                     # what makes the call succeed.
        "sharing": sharing,          # "app" or "global"
        "perms.read": perms_read,    # "*" or "admin,power"
        "perms.write": perms_write,  # "admin" or "ci_deploy_savedsearches"
    }

    r = splunk_post(session, acl_url, payload)

    if r.status_code == 200:
        return True, "ACL updated"

    # Reaching a 409 now means something the old code could not say: the ACL
    # does not match what we asked for, and Splunk will not let us change it.
    # Naming that explicitly, because "Cannot overwrite existing app object"
    # reads like a benign duplicate and is no longer one.
    if r.status_code == 409 and current is not None:
        return False, (
            f"ACL differs from the configured sharing/permissions and Splunk refused the "
            f"change (HTTP 409). Current: sharing={current.get('sharing')!r}, "
            f"perms={current.get('perms')!r}; wanted: sharing={sharing!r}, "
            f"read={perms_read!r}, write={perms_write!r}"
        )

    return False, f"ACL update failed HTTP {r.status_code}: {r.text[:300]}"


# Register item 2.4. A prod run used to leave nothing behind: the deploy printed
# per-rule lines into a job log that ages out, and afterwards nothing said which
# rules had gone to production, which were created versus updated, or at what
# version. The log is where you look when you already suspect something; this is
# what tells you what happened without having to.
#
# What deliberately never goes in here: the Splunk URL, the app name, and the
# account. Those are secrets or secret-adjacent, and this report is uploaded as
# an artifact on a public repository. Everything recorded below is derivable
# from the repo itself -- it says what *we* did, not where we did it.
def write_report(path: Path, records: list[dict]) -> None:
    totals: dict[str, int] = {}
    for r in records:
        totals[r["outcome"]] = totals.get(r["outcome"], 0) + 1

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "deployed_at": datetime.datetime.now(datetime.UTC).isoformat(),
                "totals": totals,
                "rules": records,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


OUTCOME_LABELS = {
    "created": "created",
    "updated": "updated",
    "skipped_deprecated": "skipped (deprecated)",
    "failed": "FAILED",
}

# A deliberate skip is neither success nor failure, so it gets the neutral mark
# rather than a tick that would imply the rule went to Splunk.
OUTCOME_MARKS = {
    "created": MARK_PASS,
    "updated": MARK_PASS,
    "skipped_deprecated": MARK_INFO,
    "failed": MARK_FAIL,
}


def write_step_summary(records: list[dict]) -> None:
    """Put the same facts where a human sees them without downloading anything."""
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_path or not records:
        return

    totals: dict[str, int] = {}
    for r in records:
        totals[r["outcome"]] = totals.get(r["outcome"], 0) + 1

    counts = ", ".join(f"{OUTCOME_LABELS.get(k, k)}: {v}" for k, v in sorted(totals.items()))

    lines = [
        "### Splunk deploy",
        "",
        f"{len(records)} rule(s) — {counts}",
        "",
        "| Rule | Saved search | Version | Outcome | Detail |",
        "|:---|:---|---:|:---|:---|",
    ]
    for r in records:
        outcome = r["outcome"]
        # The detail moved out of the Outcome cell and into its own column.
        # It carries Splunk error text, which is JSON, which is long -- inlined
        # it pushed the one word a reader is looking for off to the left of a
        # paragraph. escape_cell() is what keeps a pipe inside that JSON from
        # ending the cell and shifting every column after it.
        lines.append(
            f"| `{escape_cell(r['detect_id'] or '-')}` "
            f"| `{escape_cell(r['search_name'] or '-')}` "
            f"| `{escape_cell(r['rule_version'] or '-')}` "
            f"| {OUTCOME_MARKS.get(outcome, MARK_INFO)} {OUTCOME_LABELS.get(outcome, outcome)} "
            f"| {escape_cell(r['detail']) if r.get('detail') else ''} |"
        )
    lines.append("")

    try:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError as ex:
        print(f"WARNING: could not write the step summary: {ex}", file=sys.stderr)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Deploy .spl files to Splunk as saved searches.")
    parser.add_argument("--report", help="Write a JSON record of what was deployed to this path")
    parser.add_argument("files", nargs="*", help="The .spl files to deploy")
    args = parser.parse_args(argv)

    # Every rule's outcome, in the order they were attempted.
    records: list[dict] = []

    def record(outcome: str, path: Path, meta: dict | None = None, name: str = "", detail: str = "") -> None:
        records.append(
            {
                "detect_id": str((meta or {}).get("detect_id") or ""),
                "search_name": name,
                "file": str(path).replace("\\", "/"),
                "rule_version": str((meta or {}).get("rule_version") or ""),
                "outcome": outcome,
                "detail": detail,
            }
        )

    base_url = env_required("SPLUNK_BASE_URL").rstrip("/")
    username = env_required("SPLUNK_USERNAME")
    password = env_required("SPLUNK_PASSWORD")
    app = env_required("SPLUNK_APP")
    # Register item 3.9. Writes go through the `nobody` namespace so objects are
    # app-level from creation; addressing them as the service account instead
    # made every update deposit a private stanza over the live object. The full
    # measurement, and why the earlier attempt at this misread its own 403, is
    # in lib/splunk_ns.py.
    #
    # `username` still appears below, but only as the ACL payload's owner field.
    # The two are genuinely different values here, which is the part that took
    # so long to see.
    verify_tls = env_bool("SPLUNK_VERIFY_TLS", default=True)
    announce_tls_mode(verify_tls)

    sharing = (os.getenv("SPLUNK_SHARING") or "app").strip().lower()
    perms_read = (os.getenv("SPLUNK_PERMS_READ") or "*").strip()
    perms_write = (os.getenv("SPLUNK_PERMS_WRITE") or "admin").strip()

    files = [Path(a) for a in args.files]
    if not files:
        print("No input files.")
        # Still write the report, so a run that deployed nothing is
        # distinguishable from a run whose report failed to appear.
        if args.report:
            write_report(Path(args.report), records)
        return 0

    s = build_session(username, password, verify_tls)

    create_url = f"{saved_searches_url(base_url, app)}?output_mode=json"

    failed = 0

    for f in files:
        if not f.exists():
            print(f"ERROR: file not found: {f}", file=sys.stderr)
            record("failed", f, detail="file not found")
            failed += 1
            continue

        meta = extract_meta(f)
        search_name = saved_search_name(meta)

        # Register item 1.7: the schema has always allowed `status: deprecated`,
        # but nothing read it -- a rule parked as deprecated deployed and ran
        # exactly like a stable one, which made the field decorative and left
        # retirement with no expression anywhere in the pipeline.
        #
        # Skipping only stops it being (re)created or updated. An object already
        # in Splunk stays until it is retired deliberately: reconcile.py sees a
        # deprecated rule as no longer desired, reports it as a removal orphan,
        # and `--apply-removals` disables it. Deleting from here would be the
        # wrong place for it -- this script deploys one file at a time and has
        # no view of the whole desired state.
        if str(meta.get("status") or "").strip().lower() == "deprecated":
            print(f"SKIP: {search_name} is deprecated -- not deployed (retire it with reconcile.py --apply-removals)")
            record("skipped_deprecated", f, meta, search_name)
            continue

        try:
            search_query = read_spl_query(f)
        except Exception as e:
            print(f"ERROR: failed reading SPL file {f}: {e}", file=sys.stderr)
            record("failed", f, meta, search_name, f"unreadable SPL: {e}")
            failed += 1
            continue

        if not search_query:
            print(f"ERROR: empty SPL query after preprocessing: {f}", file=sys.stderr)
            record("failed", f, meta, search_name, "empty SPL query")
            failed += 1
            continue

        print(f"Deploying savedsearch '{search_name}' from {f}")
        final_desc = build_savedsearch_description(
            "Managed by CI/CD (Detection-Engineering repo)",
            str(meta.get("description") or ""),
            rule_version=str(meta.get("rule_version") or ""),
            max_len=800,
        )

        runtime_payload = build_splunk_runtime_payload_from_header(f)

        # Register item 2.6. This used to POST to the collection endpoint first
        # and then work out from the *error text* whether the object already
        # existed -- matching "already exists" / "conflict" / "in use", none of
        # which Splunk promises, all of which vary by version, and any of which
        # an unrelated failure could contain. A rephrased conflict was reported
        # as a create failure; an unrelated error carrying one of those words
        # sent the deploy down the update path to fail again, more confusingly.
        #
        # The object endpoint answers the same question by contract: 200 means
        # it was there and is now updated, 404 means it is not there yet.
        # Nothing is inferred from prose, and the common case -- a rule that has
        # been deployed before -- now takes one call instead of two.
        object_url = f"{saved_search_url(base_url, app, search_name)}?output_mode=json"

        # `name` belongs in the URL here, not the body: this endpoint addresses
        # an existing object rather than creating one.
        payload_update = {
            "search": search_query,
            "description": final_desc,
            **runtime_payload,
        }

        r = splunk_post(s, object_url, payload_update)

        if r.status_code == 200:
            print(f"Updated: {search_name}")
            ok, msg = set_acl(s, base_url, username, app, search_name, sharing, perms_read, perms_write)
            if not ok:
                print(f"WARNING: {search_name}: {msg}", file=sys.stderr)
            record("updated", f, meta, search_name, "" if ok else f"ACL warning: {msg}")
            continue

        if r.status_code in (401, 403):
            print(f"ERROR: auth/permission error updating {search_name} (HTTP {r.status_code})", file=sys.stderr)
            print(f"Response (first 800 chars): {r.text[:800]}", file=sys.stderr)
            record("failed", f, meta, search_name, f"auth/permission error (HTTP {r.status_code})")
            failed += 1
            continue

        if r.status_code != 404:
            # Deliberately not falling through to create. Anything that is
            # neither "updated" nor "not found" is a real error, and guessing
            # past it is what the old error-text matching did.
            print(
                f"ERROR: unexpected response updating {search_name} (HTTP {r.status_code}); "
                f"expected 200 (updated) or 404 (does not exist yet).",
                file=sys.stderr,
            )
            print(f"Response (first 800 chars): {r.text[:800]}", file=sys.stderr)
            record("failed", f, meta, search_name, f"unexpected update response (HTTP {r.status_code})")
            failed += 1
            continue

        # 404: the saved search does not exist yet, so create it.
        payload_create = {
            "name": search_name,
            "search": search_query,
            "description": final_desc,
            **runtime_payload,
        }

        r_create = splunk_post(s, create_url, payload_create)

        if r_create.status_code in (200, 201):
            print(f"Created: {search_name}")

            # Splunk's savedsearch creation endpoint doesn't reliably apply
            # scheduling fields (is_scheduled/cron_schedule) on the same POST
            # that creates the object -- a brand-new search can come back with
            # Next scheduled time = None even though the create call succeeded.
            # A follow-up edit POST with the same runtime payload forces Splunk
            # to actually persist them. The update path above needs no such
            # follow-up: it is already that same edit POST.
            r_reapply = splunk_post(s, object_url, runtime_payload)
            if r_reapply.status_code != 200:
                print(
                    f"WARNING: {search_name}: failed to reapply scheduling fields after create "
                    f"(HTTP {r_reapply.status_code}): {r_reapply.text[:300]}",
                    file=sys.stderr,
                )

            ok, msg = set_acl(s, base_url, username, app, search_name, sharing, perms_read, perms_write)
            if not ok:
                print(f"WARNING: {search_name}: {msg}", file=sys.stderr)
            record("created", f, meta, search_name, "" if ok else f"ACL warning: {msg}")
            continue

        if r_create.status_code in (401, 403):
            print(f"ERROR: auth/permission error creating {search_name} (HTTP {r_create.status_code})", file=sys.stderr)
            print(f"Response (first 800 chars): {r_create.text[:800]}", file=sys.stderr)
            record("failed", f, meta, search_name, f"auth/permission error (HTTP {r_create.status_code})")
            failed += 1
            continue

        print(f"ERROR: failed creating {search_name}. Create={r_create.status_code}", file=sys.stderr)
        print(f"Create response (first 800 chars): {r_create.text[:800]}", file=sys.stderr)
        record("failed", f, meta, search_name, f"create failed (HTTP {r_create.status_code})")
        failed += 1

    if args.report:
        write_report(Path(args.report), records)
    write_step_summary(records)

    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
