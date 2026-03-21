import os
import sys
import json
import re
from pathlib import Path
from urllib.parse import quote

import requests


def die(msg: str, code: int = 1) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)


def env_required(name: str) -> str:
    v = (os.getenv(name) or "").strip()
    if not v:
        die(f"Missing required env var: {name}")
    return v


def env_bool(name: str, default: bool = True) -> bool:
    v = (os.getenv(name) or "").strip().lower()
    if v in ("true", "1", "yes", "y", "on"):
        return True
    if v in ("false", "0", "no", "n", "off"):
        return False
    return default


def savedsearch_name_from_file(p: Path) -> str:
    # Keep ".sigma" in the name to distinguish converted vs native
    # rules/splunk/foo.sigma.spl -> foo.sigma
    name = p.name
    if name.endswith(".spl"):
        name = name[:-4]
    return name


def read_spl_query(path: Path) -> str:
    """
    Return only the actual SPL query part (everything after the '---' separator).
    The META_START/META_END header is CI metadata and must not be deployed as part of the savedsearch 'search'.
    """
    content = path.read_text(encoding="utf-8")

    if "---" not in content:
        die(f"No query separator ('---') found in file: {path}")

    _, query_part = content.split('---', 1)
    query = query_part.strip()

    if not query:
        die(f"No SPL query found after '---' in file: {path}")

    return query


def extract_meta(path: Path) -> dict:
    """
    Extract and parse META_START ... META_END JSON block from a CI-managed SPL artifact.
    """
    content = path.read_text(encoding="utf-8")
    m = re.search(r"META_START\s*(\{.*?\})\s*META_END", content, re.DOTALL)
    if not m:
        die(f"META block not found in file: {path}")

    meta_str = m.group(1)
    try:
        meta = json.loads(meta_str)
    except json.JSONDecodeError as e:
        die(f"Invalid META JSON in {path}: {e}")

    return meta


def extract_ci_header_value(path: Path, key: str) -> str:
    """
    Extract a CI header value from leading '#' lines.
    Example key: "SIGMA_DESCRIPTION"
    Looks for a line like: "# SIGMA_DESCRIPTION: <value>"
    Stops parsing when non-comment line is encountered.
    """
    prefix = f"# {key}:"
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.lstrip().startswith("#"):
                break
            if line.startswith(prefix):
                return line[len(prefix):].strip()
    except Exception:
        return ""
    return ""

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



def build_savedsearch_description(ci_constant: str, sigma_description: str, max_len: int = 800) -> str:
    """
    Combine constant CI description + Sigma rule description into a single Splunk savedsearch description.
    """
    base = (ci_constant or "").strip()
    sigma = (sigma_description or "").strip()

    # Flatten multi-line sigma descriptions for Splunk UI
    sigma = " ".join(sigma.split())

    if sigma:
        if len(sigma) > max_len:
            sigma = sigma[:max_len] + "..."
        return f"{base}\n{sigma}"

    return base

def splunk_post(session: requests.Session, url: str, data: dict) -> requests.Response:
    # Splunkd REST expects form-encoded by default; requests does this with data=
    return session.post(url, data=data, timeout=30)


def is_already_exists(resp_text: str) -> bool:
    # Splunk error messages vary by version; this catches the common ones.
    t = (resp_text or "").lower()
    return ("already exists" in t) or ("conflict" in t) or ("in use" in t)


def set_acl(
    session: requests.Session,
    base_url: str,
    owner: str,
    app: str,
    search_name: str,
    sharing: str,
    perms_read: str,
    perms_write: str,
) -> tuple[bool, str]:
    """
    Set object-level ACL for a saved search to ensure consistent sharing and permissions.
    """
    acl_url = (
        f"{base_url}/servicesNS/{quote(owner, safe='')}/{quote(app, safe='')}"
        f"/saved/searches/{quote(search_name, safe='')}/acl?output_mode=json"
    )

    payload = {
        "sharing": sharing,          # "app" or "global"
        "perms.read": perms_read,    # "*" or "admin,power"
        "perms.write": perms_write,  # "admin" or "ci_deploy_savedsearches"
    }

    r = splunk_post(session, acl_url, payload)

    if r.status_code == 200:
        return True, "ACL updated"

    return False, f"ACL update failed HTTP {r.status_code}: {r.text[:300]}"


def main(argv: list[str]) -> int:
    base_url = env_required("SPLUNK_BASE_URL").rstrip("/")
    username = env_required("SPLUNK_USERNAME")
    password = env_required("SPLUNK_PASSWORD")
    app = env_required("SPLUNK_APP")
    owner = env_required("SPLUNK_OWNER")
    verify_tls = env_bool("SPLUNK_VERIFY_TLS", default=True)

    sharing = (os.getenv("SPLUNK_SHARING") or "app").strip().lower()
    perms_read = (os.getenv("SPLUNK_PERMS_READ") or "*").strip()
    perms_write = (os.getenv("SPLUNK_PERMS_WRITE") or "admin").strip()

    files = [Path(a) for a in argv]
    if not files:
        print("No input files.")
        return 0

    s = requests.Session()
    s.verify = verify_tls
    s.auth = (username, password)
    s.headers.update({"Accept": "application/json"})

    create_url = (
        f"{base_url}/servicesNS/{quote(owner, safe='')}/{quote(app, safe='')}"
        f"/saved/searches?output_mode=json"
    )

    failed = 0

    for f in files:
        if not f.exists():
            print(f"ERROR: file not found: {f}", file=sys.stderr)
            failed += 1
            continue

        search_name = savedsearch_name_from_file(f)

        try:
            search_query = read_spl_query(f)
        except Exception as e:
            print(f"ERROR: failed reading SPL file {f}: {e}", file=sys.stderr)
            failed += 1
            continue

        if not search_query:
            print(f"ERROR: empty SPL query after preprocessing: {f}", file=sys.stderr)
            failed += 1
            continue

        print(f"Deploying savedsearch '{search_name}' from {f}")
        meta = extract_meta(f)
        final_desc = build_savedsearch_description(
            "Managed by CI/CD (Detection-Engineering repo)",
            str(meta.get("description") or ""),
            max_len=800,
        )

        runtime_payload = build_splunk_runtime_payload_from_header(f)

        payload_create = {
            "name": search_name,
            "search": search_query,
            "description": final_desc,
            **runtime_payload,

        }

        r = splunk_post(s, create_url, payload_create)

        if r.status_code in (200, 201):
            print(f"Created: {search_name}")
            ok, msg = set_acl(s, base_url, owner, app, search_name, sharing, perms_read, perms_write)
            if not ok:
                print(f"WARNING: {search_name}: {msg}", file=sys.stderr)
            continue

        # If auth/permission error -> fail fast (do not mask with update attempt)
        if r.status_code in (401, 403):
            print(f"ERROR: auth/permission error creating {search_name} (HTTP {r.status_code})", file=sys.stderr)
            print(f"Response (first 800 chars): {r.text[:800]}", file=sys.stderr)
            failed += 1
            continue

        update_url = (
            f"{base_url}/servicesNS/{quote(owner, safe='')}/{quote(app, safe='')}"
            f"/saved/searches/{quote(search_name, safe='')}?output_mode=json"
        )

        if r.status_code in (409,) or is_already_exists(r.text):

            runtime_payload = build_splunk_runtime_payload_from_header(f)

            payload_update = {
                "search": search_query,
                "description": final_desc,
                **runtime_payload,
            }
            r2 = splunk_post(s, update_url, payload_update)

            if r2.status_code == 200:
                print(f"Updated: {search_name}")
                ok, msg = set_acl(s, base_url, owner, app, search_name, sharing, perms_read, perms_write)
                if not ok:
                    print(f"WARNING: {search_name}: {msg}", file=sys.stderr)
                continue

            print(f"ERROR: failed updating {search_name}. Update={r2.status_code}", file=sys.stderr)
            print(f"Update response (first 800 chars): {r2.text[:800]}", file=sys.stderr)
            failed += 1
            continue

        # Other create failures -> report and fail
        print(f"ERROR: failed creating {search_name}. Create={r.status_code}", file=sys.stderr)
        print(f"Create response (first 800 chars): {r.text[:800]}", file=sys.stderr)
        failed += 1

    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
