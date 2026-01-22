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


def splunk_post(session: requests.Session, url: str, data: dict) -> requests.Response:
    return session.post(url, data=data, timeout=30)


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

    # Splunk often returns XML by default; ask for JSON for friendlier errors.
    s.headers.update({"Accept": "application/json"})

    create_url = f"{base_url}/servicesNS/{quote(owner)}/{quote(app)}/saved/searches"

    failed = 0

    for f in files:
        if not f.exists():
            print(f"ERROR: file not found: {f}", file=sys.stderr)
            failed += 1
            continue

        search_name = savedsearch_name_from_file(f)
        search_query = f.read_text(encoding="utf-8").strip()

        if not search_query:
            print(f"ERROR: empty SPL file: {f}", file=sys.stderr)
            failed += 1
            continue

        print(f"Deploying savedsearch '{search_name}' from {f}")

        # 1) Try create
        r = splunk_post(
            s,
            create_url,
            {
                "name": search_name,
                "search": search_query,
                "disabled": "0",
            },
        )

        if r.status_code in (200, 201):
            print(f"Created: {search_name}")
            continue

        # 2) If exists -> update
        update_url = f"{create_url}/{quote(search_name)}"
        r2 = splunk_post(
            s,
            update_url,
            {
                "search": search_query,
                "disabled": "0",
            },
        )

        if r2.status_code == 200:
            print(f"Updated: {search_name}")
            continue

        print(
            f"ERROR: failed deploying {search_name}. "
            f"Create={r.status_code} Update={r2.status_code}",
            file=sys.stderr,
        )
        print(f"Create response (first 800 chars): {r.text[:800]}", file=sys.stderr)
        print(f"Update response (first 800 chars): {r2.text[:800]}", file=sys.stderr)
        failed += 1

    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
