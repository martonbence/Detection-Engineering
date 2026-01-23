import os
import sys
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
    Splunk savedsearch 'search' field should be valid SPL.
    If you keep CI comments in files, strip leading '#' comment lines to avoid parse errors.
    """
    lines = path.read_text(encoding="utf-8").splitlines()

    # Drop UTF-8 BOM if present in first line
    if lines and lines[0].startswith("\ufeff"):
        lines[0] = lines[0].lstrip("\ufeff")

    # Strip leading blank lines
    while lines and not lines[0].strip():
        lines.pop(0)

    # Strip leading comment lines (common in generated artifacts)
    while lines and lines[0].lstrip().startswith("#"):
        lines.pop(0)
        while lines and not lines[0].strip():
            lines.pop(0)

    return "\n".join(lines).strip()


def splunk_post(session: requests.Session, url: str, data: dict) -> requests.Response:
    # Splunkd REST expects form-encoded by default; requests does this with data=
    return session.post(url, data=data, timeout=30)


def is_already_exists(resp_text: str) -> bool:
    # Splunk error messages vary by version; this catches the common ones.
    t = (resp_text or "").lower()
    return ("already exists" in t) or ("conflict" in t) or ("in use" in t)


def main(argv: list[str]) -> int:
    base_url = env_required("SPLUNK_BASE_URL").rstrip("/")
    username = env_required("SPLUNK_USERNAME")
    password = env_required("SPLUNK_PASSWORD")
    app = env_required("SPLUNK_APP")
    owner = env_required("SPLUNK_OWNER")
    verify_tls = env_bool("SPLUNK_VERIFY_TLS", default=True)

    files = [Path(a) for a in argv]
    if not files:
        print("No input files.")
        return 0

    s = requests.Session()
    s.verify = verify_tls
    s.auth = (username, password)
    s.headers.update({"Accept": "application/json"})

    # Ask Splunk for JSON output to make errors/logging consistent
    create_url = f"{base_url}/servicesNS/{quote(owner)}/{quote(app)}/saved/searches?output_mode=json"

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

        payload_create = {
            "name": search_name,
            "search": search_query,
            "disabled": "0",
            # optional: make CI-owned objects obvious in Splunk UI
            "description": "Managed by CI/CD (Detection-Engineering repo)",
        }

        r = splunk_post(s, create_url, payload_create)

        if r.status_code in (200, 201):
            print(f"Created: {search_name}")
            continue

        # If auth/permission error -> fail fast (do not mask with update attempt)
        if r.status_code in (401, 403):
            print(f"ERROR: auth/permission error creating {search_name} (HTTP {r.status_code})", file=sys.stderr)
            print(f"Response (first 800 chars): {r.text[:800]}", file=sys.stderr)
            failed += 1
            continue

        # Only fall back to update if it's a 'already exists' scenario.
        update_url = f"{base_url}/servicesNS/{quote(owner)}/{quote(app)}/saved/searches/{quote(search_name)}?output_mode=json"

        if r.status_code in (409,) or is_already_exists(r.text):
            payload_update = {
                "search": search_query,
                "disabled": "0",
                "description": "Managed by CI/CD (Detection-Engineering repo)",
            }
            r2 = splunk_post(s, update_url, payload_update)

            if r2.status_code == 200:
                print(f"Updated: {search_name}")
                continue

            print(
                f"ERROR: failed updating {search_name}. Update={r2.status_code}",
                file=sys.stderr,
            )
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
