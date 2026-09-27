"""
generate_mitre_glossary.py -- the MITRE-Notes vault's companion "MITRE Navigator".

A structural clone of the rule browser's MITRE Navigator tab (docs/index.html),
re-themed so the two pages can't be mistaken for each other, whose detail
panel shows a short hand-written blurb on what each ATT&CK item *is*.

Built from the rule browser's own components, not a parallel implementation:
  - matrix markup      -> generate_stats._build_matrix_html()   (the full
                          ATT&CK matrix, identical DOM/classes/cell states)
  - platform menu      -> generate_stats._build_platform_menu_html()
  - coverage           -> generate_stats.build_technique_coverage()
  - stylesheet         -> scripts/docs/assets/page.css, inlined whole, with
                          the brand accent (#ffaa00) swapped for ACCENT_HEX
  - behaviour          -> the Navigator block + ambient-background IIFE of
                          scripts/docs/assets/page.js, sliced out by marker
                          lines (hard failure if a marker moves), plus a few
                          helper functions extracted by name
  - glossary.{template.html,css,js,shims.js} only add what the rule browser lacks:
                          page shell, the blurb detail panel, and shims for
                          the rule-browser globals the sliced JS references.

Required-blurb scope (for --check/--strict) is the covered/partial subset,
classified exactly like _build_matrix_html():
  - sub-technique / technique with its own rule(s)   -> "covered"
  - technique with rules only on its sub-techniques  -> "partial" (`has-cov`)
  - tactic with >=1 in-scope technique in its column  -> in scope
Every other matrix item is still rendered and clickable; its panel says
plainly that there is no blurb / vault note / rule coverage yet.

Reads:
  - rules/sigma/**/*.yml, outputs/results/*/result.json (via generate_stats)
  - outputs/reports/mitre_technique_map.json (cache written by generate_stats.py;
    never fetched here -- run generate_stats.py first if it is missing/stale)
  - scripts/docs/mitre_glossary/blurbs.yaml   -- hand-written blurbs, keyed by ID
  - scripts/docs/mitre_glossary/assets/glossary.{template.html,css,js,shims.js}
  - scripts/docs/assets/page.{css,js}          -- the rule browser's own assets
  - personal/MITRE-Notes/{Tactics,Techniques,Subtechniques}/*.md -- only to link
    each item to its existing vault note, if there is one

Writes:
  - personal/MITRE-Notes/mitre-navigator.html

Blurbs are NOT generated: an in-scope ID with no entry in blurbs.yaml is
listed on stderr. With --strict that exits non-zero instead of writing, so a
regenerate after a new rule can't silently ship a half-empty glossary.

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

PAGE_ASSETS_DIR = gs.REPO_ROOT / "scripts" / "docs" / "assets"

# Theme: the rule browser's brand accent is solid amber #ffaa00 (hsl 40,100%,50%).
# This page keeps every structural/background token and swaps only that
# accent for the same saturation/lightness at hue 190 (cyan), so the two read
# as "same tool, different instance". Measured contrast never drops below the
# amber it replaces: #111 on #00d4ff 10.67:1 (amber 9.89:1) for the solid
# tactic headers / highlighted cells; #00d4ff on the #1c2128 cell 9.14:1
# (amber 8.48:1) for the sub-technique n/m badge.
ACCENT_HEX = "#00d4ff"
ACCENT_RGB = "0, 212, 255"
_BRAND_HEX = ("#ffaa00", "#FFAA00")
_BRAND_RGBA = "rgba(255, 170, 0,"

# page.js slices. Each marker must match exactly one full line; a moved or
# renamed marker is a SystemExit, never a silent partial page.
_JS_NAV_START = "var navTip = document.getElementById('att-tip');"
_JS_NAV_END = "renderStripTotal();"          # exclusive: rule-browser init follows
_JS_BG_START = "(function bgParticles() {"   # to end of file
_JS_HELPERS = (
    "escHtml", "vLabel", "downloadFile", "todayStamp", "toCSV", "isDrawerOpen",
    "isInfoOpen", "setInfo", "openInfo", "closeInfo", "toggleInfo",
)
_ID_RE = re.compile(r"^(TA\d{4}|T\d{4}(?:\.\d{3})?)\b")


def _read_asset(name: str) -> str:
    path = ASSETS_DIR / name
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise SystemExit(f"generate_mitre_glossary.py: asset not found: {path}") from None


def _line_index(lines: list[str], marker: str, what: str) -> int:
    hits = [i for i, ln in enumerate(lines) if ln.strip() == marker]
    if len(hits) != 1:
        raise SystemExit(
            f"generate_mitre_glossary.py: page.js marker for {what} matched {len(hits)} "
            f"lines (need exactly 1): {marker!r}"
        )
    return hits[0]


def _extract_function(lines: list[str], name: str) -> str:
    """A top-level `function name(...) {...}` from page.js: one-liner, or up
    to the first column-0 closing brace."""
    start = next((i for i, ln in enumerate(lines) if ln.startswith(f"function {name}(")), None)
    if start is None:
        raise SystemExit(f"generate_mitre_glossary.py: page.js has no top-level function {name}()")
    if lines[start].rstrip().endswith("}"):
        return lines[start]
    end = next((i for i in range(start + 1, len(lines)) if lines[i].rstrip() == "}"), None)
    if end is None:
        raise SystemExit(f"generate_mitre_glossary.py: could not find the end of {name}() in page.js")
    return "\n".join(lines[start:end + 1])


def build_shared_js() -> tuple[str, str]:
    """(helpers + Navigator block, ambient-background IIFE) sliced from page.js."""
    lines = (PAGE_ASSETS_DIR / "page.js").read_text(encoding="utf-8").split("\n")
    a = _line_index(lines, _JS_NAV_START, "Navigator block start")
    b = _line_index(lines, _JS_NAV_END, "Navigator block end")
    c = _line_index(lines, _JS_BG_START, "background IIFE")
    if not a < b < c:
        raise SystemExit("generate_mitre_glossary.py: page.js slice markers out of order")
    helpers = "\n\n".join(_extract_function(lines, n) for n in _JS_HELPERS)
    nav = "\n".join(lines[a:b])
    return helpers + "\n\n" + nav, "\n".join(lines[c:])


def build_themed_css() -> str:
    """page.css verbatim, brand accent swapped. Refuses to run if the swap
    target disappears (i.e. the rule browser changed its brand colour)."""
    css = (PAGE_ASSETS_DIR / "page.css").read_text(encoding="utf-8")
    if not any(h in css for h in _BRAND_HEX) or _BRAND_RGBA not in css:
        raise SystemExit(
            "generate_mitre_glossary.py: page.css no longer contains the #ffaa00 brand accent "
            "-- update _BRAND_HEX/_BRAND_RGBA before regenerating, or the theme swap no-ops."
        )
    for h in _BRAND_HEX:
        css = css.replace(h, ACCENT_HEX)
    return css.replace(_BRAND_RGBA, f"rgba({ACCENT_RGB},")


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


def compute_coverage() -> dict:
    rules = gs.load_sigma_rules()
    rules_detail, _ = gs._collect_rule_details(rules, gs.load_verdicts())
    return gs.build_technique_coverage(rules_detail, REPO_SLUG)


def compute_scope(technique_map: list[dict], cov: dict) -> list[dict]:
    """Tactic columns (TACTIC_ORDER) holding only the covered/partial items --
    the set every blurb is *required* for (--check/--strict)."""
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


def build_payload(technique_map: list[dict], blurbs: dict[str, str], notes: dict[str, str]) -> dict:
    """Only what the matrix DOM doesn't already carry: blurbs, vault-note
    links, tactic names/IDs. Names, platforms, rules and coverage state are
    read from the cells _build_matrix_html() rendered."""
    known = {gs.TACTIC_ID_MAP.get(t, "") for t in gs.TACTIC_ORDER}
    for t in technique_map:
        known.add(t["id"])
        known.update(s["id"] for s in t.get("subs") or [])
    return {
        "blurbs": {k: _render_blurb(v) for k, v in blurbs.items() if k in known},
        "notes": {k: v for k, v in notes.items() if k in known},
        "tactics": {t: gs.TACTIC_ID_MAP.get(t, "") for t in gs.TACTIC_ORDER},
    }


def render_html(technique_map: list[dict], cov: dict, payload: dict) -> str:
    html = _read_asset("glossary.template.html")
    shared_js, bg_js = build_shared_js()
    n_subs = sum(len(t.get("subs") or []) for t in technique_map)
    data_json = json.dumps(payload, ensure_ascii=False).replace("</", "<\\/")
    # Order matters: the big inlined assets go in last so a literal "@@X@@"
    # inside page.css/page.js could never be mistaken for one of ours.
    subs = [
        ("@@TS@@", datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")),
        ("@@N_TACTICS@@", str(len(gs.TACTIC_ORDER))),
        ("@@N_TECHNIQUES@@", str(len(technique_map))),
        ("@@N_SUBS@@", str(n_subs)),
        ("@@N_BLURBS@@", str(len(payload["blurbs"]))),
        ("@@FAVICON_DATA@@", gs._read_image_b64("favicon-32.png")),
        ("@@LOGO_DATA@@", gs._read_image_b64("logo-header.png")),
        ("@@PLATFORM_MENU_HTML@@", gs._build_platform_menu_html(technique_map)),
        ("@@DATA_JSON@@", data_json),
        ("@@MATRIX_HTML@@", gs._build_matrix_html(technique_map, cov)),
        ("@@INLINE_CSS@@", build_themed_css() + "\n" + _read_asset("glossary.css")),
        ("@@SHARED_JS@@", shared_js),
        ("@@INLINE_JS@@", _read_asset("glossary.shims.js")),
        ("@@GLOSSARY_JS@@", _read_asset("glossary.js")),
        ("@@BG_JS@@", bg_js),
    ]
    for marker, _ in subs:
        if marker not in html:
            raise SystemExit(f"generate_mitre_glossary.py: marker {marker!r} missing from template")
    # Check for leftovers on the template alone, before substitution: a
    # misspelled marker (e.g. the 2026-08-10 "@@INLINE_JS @@" stray-space
    # failure) is caught here, and nothing in the inlined page.css/page.js
    # slices can trip it.
    probe = html
    for marker, _ in subs:
        probe = probe.replace(marker, "")
    leftover = sorted(set(re.findall(r"@@[A-Z_]+ ?@@", probe)))
    if leftover:
        raise SystemExit(f"generate_mitre_glossary.py: unreplaced marker(s): {', '.join(leftover)}")
    for marker, value in subs:
        html = html.replace(marker, value)
    return html


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--strict", action="store_true", help="fail if any in-scope item has no blurb")
    ap.add_argument("--check", action="store_true", help="report only, write nothing")
    args = ap.parse_args()

    technique_map = load_technique_map()
    cov = compute_coverage()
    columns = compute_scope(technique_map, cov)
    blurbs = load_blurbs()
    ids = _all_ids(columns)
    missing = [i for i in ids if i not in blurbs]
    orphans = sorted(set(blurbs) - set(ids))

    print(f"in scope: {len(ids)} items ({len(columns)} tactics)")
    if missing:
        print(f"MISSING blurb ({len(missing)}): {', '.join(missing)}", file=sys.stderr)
    if orphans:
        print(
            f"blurb outside the covered/partial scope (kept; still shown in its panel): {', '.join(orphans)}",
            file=sys.stderr,
        )
    if args.check:
        return 1 if (missing and args.strict) else 0
    if missing and args.strict:
        print("--strict: not writing", file=sys.stderr)
        return 1

    payload = build_payload(technique_map, blurbs, index_vault_notes())
    OUTPUT_PATH.write_text(render_html(technique_map, cov, payload), encoding="utf-8")
    print(f"wrote {OUTPUT_PATH.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
