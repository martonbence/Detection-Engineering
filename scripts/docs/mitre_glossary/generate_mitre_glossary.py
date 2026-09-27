"""
generate_mitre_glossary.py -- the MITRE-Notes vault's companion "MITRE Navigator".

A quick-reference glossary, not a coverage-status matrix: for every ATT&CK
tactic / technique / sub-technique that at least one rule in rules/sigma/
is tagged against (covered), or whose sub-techniques are (partial), it shows
a short, fixed-shape blurb on what that item *is* mechanically.

Scope is computed with the rule browser's own code, not re-derived:
  - generate_stats.load_sigma_rules() / _collect_rule_details() -> rule tags
  - generate_stats.build_technique_coverage()                   -> covered IDs
  - outputs/reports/mitre_technique_map.json                    -> names/tactics
so this page and the rule-browser Navigator (docs/index.html) can never
disagree on what counts as "covered". Classification mirrors
generate_stats._build_matrix_html():
  - sub-technique / technique with its own rule(s)   -> "covered"
  - technique with rules only on its sub-techniques  -> "partial" (the matrix's
    `has-cov` state)
  - tactic with >=1 in-scope technique in its column  -> in scope, shown with
    the same "n/m covered" ratio as the rule-browser column header

Reads:
  - rules/sigma/**/*.yml, outputs/results/*/result.json (via generate_stats)
  - outputs/reports/mitre_technique_map.json (cache written by generate_stats.py;
    never fetched here -- run generate_stats.py first if it is missing/stale)
  - scripts/docs/mitre_glossary/blurbs.yaml   -- hand-written blurbs, keyed by ID
  - scripts/docs/mitre_glossary/assets/glossary.{template.html,css,js}
  - personal/MITRE-Notes/{Tactics,Techniques,Subtechniques}/*.md -- only to link
    each item to its existing vault note, if there is one

Writes:
  - personal/MITRE-Notes/mitre-navigator.html

Blurbs are NOT generated: an in-scope ID with no entry in blurbs.yaml renders
with a visible "missing blurb" placeholder and is listed on stderr. With
--strict that exits non-zero instead of writing, so a regenerate after a new
rule can't silently ship a half-empty glossary.

Usage:
  python3 scripts/docs/mitre_glossary/generate_mitre_glossary.py [--strict] [--check]
    --check   report scope + missing/orphan blurbs, write nothing
"""

from __future__ import annotations

import argparse
import html as _html
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

import yaml

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))  # scripts/docs -> generate_stats
import generate_stats as gs

REPO_ROOT = gs.REPO_ROOT
VAULT_DIR = REPO_ROOT / "personal" / "MITRE-Notes"
OUTPUT_PATH = VAULT_DIR / "mitre-navigator.html"
BLURBS_PATH = _HERE / "blurbs.yaml"
ASSETS_DIR = _HERE / "assets"
REPO_SLUG = "martonbence/Detection-Engineering"

_INLINE_ASSETS = (("@@INLINE_CSS@@", "glossary.css"), ("@@INLINE_JS@@", "glossary.js"))
_ID_RE = re.compile(r"^(TA\d{4}|T\d{4}(?:\.\d{3})?)\b")


def _read_asset(name: str) -> str:
    path = ASSETS_DIR / name
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise SystemExit(f"generate_mitre_glossary.py: asset not found: {path}") from None


def load_technique_map() -> list[dict]:
    try:
        data = json.loads(gs.MITRE_MAP_CACHE_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(
            f"generate_mitre_glossary.py: {gs.MITRE_MAP_CACHE_PATH} missing -- "
            "run scripts/docs/generate_stats.py once to populate the ATT&CK cache."
        ) from None
    return data.get("techniques") or []


def load_blurbs() -> dict[str, str]:
    if not BLURBS_PATH.exists():
        return {}
    raw = yaml.safe_load(BLURBS_PATH.read_text(encoding="utf-8")) or {}
    return {str(k).strip(): " ".join(str(v).split()) for k, v in raw.items() if v}


def index_vault_notes() -> dict[str, str]:
    """{ATT&CK ID: vault-relative note path} for every existing note."""
    notes: dict[str, str] = {}
    for sub in ("Tactics", "Techniques", "Subtechniques"):
        for path in sorted((VAULT_DIR / sub).glob("*.md")):
            m = _ID_RE.match(path.name)
            if m:
                notes[m.group(1)] = path.relative_to(VAULT_DIR).as_posix()
    return notes


def compute_scope(technique_map: list[dict]) -> list[dict]:
    """Tactic columns (TACTIC_ORDER) holding only in-scope techniques/subs."""
    rules = gs.load_sigma_rules()
    rules_detail, _ = gs._collect_rule_details(rules, gs.load_verdicts())
    cov = gs.build_technique_coverage(rules_detail, REPO_SLUG)

    columns = []
    for tactic in gs.TACTIC_ORDER:
        techs = sorted(
            (t for t in technique_map if tactic in (t.get("tactics") or [])),
            key=lambda t: t["id"],
        )
        items = []
        for t in techs:
            subs = [s for s in t.get("subs") or [] if s["id"] in cov]
            direct = t["id"] in cov
            if not (direct or subs):
                continue
            items.append({
                "id": t["id"],
                "name": t["name"],
                "state": "covered" if direct else "partial",
                "tactics": t.get("tactics") or [],
                "platforms": t.get("platforms") or [],
                "rules": [r["id"] for r in cov.get(t["id"], {}).get("rules", [])],
                "subTotal": len(t.get("subs") or []),
                "subs": [{
                    "id": s["id"],
                    "name": s["name"],
                    "state": "covered",
                    "platforms": s.get("platforms") or [],
                    "rules": [r["id"] for r in cov[s["id"]]["rules"]],
                } for s in subs],
            })
        if items:
            columns.append({
                "id": gs.TACTIC_ID_MAP.get(tactic, ""),
                "name": tactic,
                "covered": len(items),
                "total": len(techs),
                "techniques": items,
            })
    return columns


def _all_ids(columns: list[dict]) -> list[str]:
    ids: list[str] = []
    for col in columns:
        ids.append(col["id"])
        for t in col["techniques"]:
            ids.append(t["id"])
            ids.extend(s["id"] for s in t["subs"])
    return list(dict.fromkeys(ids))


def _render_blurb(text: str) -> str:
    """Escape, then `code` -> <code>. Blurbs are plain text otherwise."""
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", _html.escape(text))


def build_payload(columns: list[dict], blurbs: dict[str, str], notes: dict[str, str]) -> dict:
    items: dict[str, dict] = {}

    def attach(entry: dict, kind: str) -> None:
        tid = entry["id"]
        blurb = blurbs.get(tid)
        items[tid] = {
            "id": tid,
            "name": entry["name"],
            "kind": kind,
            "state": entry.get("state", "covered"),
            "blurb": _render_blurb(blurb) if blurb else "",
            "note": notes.get(tid, ""),
            "rules": entry.get("rules", []),
            "platforms": entry.get("platforms", []),
            "url": (
                f"https://attack.mitre.org/tactics/{tid}/" if kind == "tactic"
                else gs.technique_url(tid)
            ),
        }

    for col in columns:
        attach(col, "tactic")
        items[col["id"]]["coverage"] = f"{col['covered']}/{col['total']}"
        for t in col["techniques"]:
            if t["id"] not in items:
                attach(t, "technique")
                items[t["id"]]["tacticNames"] = t["tactics"]
                items[t["id"]]["subTotal"] = t["subTotal"]
            for s in t["subs"]:
                if s["id"] not in items:
                    attach(s, "subtechnique")
                    items[s["id"]]["parent"] = t["id"]
    layout = [{
        "id": c["id"],
        "techniques": [{"id": t["id"], "subs": [s["id"] for s in t["subs"]]} for t in c["techniques"]],
    } for c in columns]
    return {"items": items, "layout": layout}


def render_html(payload: dict) -> str:
    html = _read_asset("glossary.template.html")
    for marker, asset in _INLINE_ASSETS:
        if marker not in html:
            raise SystemExit(f"generate_mitre_glossary.py: marker {marker!r} missing from template")
        html = html.replace(marker, _read_asset(asset))
    items = payload["items"]
    counts = {k: sum(1 for i in items.values() if i["kind"] == k) for k in ("tactic", "technique", "subtechnique")}
    data_json = json.dumps(payload, ensure_ascii=False).replace("</", "<\\/")
    html = (
        html.replace("@@DATA_JSON@@", data_json)
        .replace("@@TS@@", datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"))
        .replace("@@N_TACTICS@@", str(counts["tactic"]))
        .replace("@@N_TECHNIQUES@@", str(counts["technique"]))
        .replace("@@N_SUBS@@", str(counts["subtechnique"]))
        .replace("@@FAVICON_DATA@@", gs._read_image_b64("favicon-32.png"))
        .replace("@@LOGO_DATA@@", gs._read_image_b64("logo-header.png"))
    )
    leftover = sorted(set(re.findall(r"@@[A-Z_]+ ?@@", html)))
    if leftover:
        raise SystemExit(f"generate_mitre_glossary.py: unreplaced marker(s): {', '.join(leftover)}")
    return html


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--strict", action="store_true", help="fail if any in-scope item has no blurb")
    ap.add_argument("--check", action="store_true", help="report only, write nothing")
    args = ap.parse_args()

    columns = compute_scope(load_technique_map())
    blurbs = load_blurbs()
    ids = _all_ids(columns)
    missing = [i for i in ids if i not in blurbs]
    orphans = sorted(set(blurbs) - set(ids))

    print(f"in scope: {len(ids)} items ({len(columns)} tactics)")
    if missing:
        print(f"MISSING blurb ({len(missing)}): {', '.join(missing)}", file=sys.stderr)
    if orphans:
        print(f"orphan blurb, no longer in scope (kept, not rendered): {', '.join(orphans)}", file=sys.stderr)
    if args.check:
        return 1 if (missing and args.strict) else 0
    if missing and args.strict:
        print("--strict: not writing", file=sys.stderr)
        return 1

    OUTPUT_PATH.write_text(render_html(build_payload(columns, blurbs, index_vault_notes())), encoding="utf-8")
    print(f"wrote {OUTPUT_PATH.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
