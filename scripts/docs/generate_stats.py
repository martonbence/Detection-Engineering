"""
generate_stats.py — Collect detection rule stats and update README.md + RULE_SUMMARY.md + docs/index.html.

Reads:
  - rules/sigma/*.yml          — sigma rules (level, status, tags, detect_id)
  - rules/splunk/*.spl         — counts native (non-sigma) SPL rules
  - outputs/results/*/result.json — pass/fail verdicts

Writes:
  - outputs/reports/stats.json — consumed by shields.io dynamic badges
  - README.md                  — replaces content between <!-- STATS_START --> and <!-- STATS_END -->
  - rules/RULE_SUMMARY.md      — full rule index with MITRE links
  - docs/index.html            — GitHub Pages filterable/sortable rule table
"""

import html as _html
import json
import math
import re
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]

TACTIC_MAP = {
    "reconnaissance": "Reconnaissance",
    "resource_development": "Resource Development",
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion": "Defense Evasion",
    "credential_access": "Credential Access",
    "discovery": "Discovery",
    "lateral_movement": "Lateral Movement",
    "collection": "Collection",
    "command_and_control": "Command & Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

TACTIC_ID_MAP = {
    "Reconnaissance": "TA0043",
    "Resource Development": "TA0042",
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "Privilege Escalation": "TA0004",
    "Defense Evasion": "TA0005",
    "Credential Access": "TA0006",
    "Discovery": "TA0007",
    "Lateral Movement": "TA0008",
    "Collection": "TA0009",
    "Command & Control": "TA0011",
    "Exfiltration": "TA0010",
    "Impact": "TA0040",
}

STIX_TACTIC_MAP = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command & Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access",
    "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command & Control",
    "Exfiltration", "Impact",
]

MITRE_MAP_CACHE_PATH = REPO_ROOT / "outputs" / "reports" / "mitre_technique_map.json"

LEVEL_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "informational": "⚪",
}

LEVEL_BADGE = {
    "critical": "![](https://img.shields.io/badge/Critical-7B0000?style=flat-square)",
    "high":     "![](https://img.shields.io/badge/High-DC2626?style=flat-square)",
    "medium":   "![](https://img.shields.io/badge/Medium-FFAA00?style=flat-square)",
    "low":      "![](https://img.shields.io/badge/Low-2EA44F?style=flat-square)",
    "informational": "![](https://img.shields.io/badge/Info-6E7681?style=flat-square)",
}

VERDICT_BADGE = {
    "PASS": "![](https://img.shields.io/badge/PASS-2EA44F?style=flat-square)",
    "FAIL": "![](https://img.shields.io/badge/FAIL-CF222E?style=flat-square)",
    "N/A":  "![](https://img.shields.io/badge/N%2FA-6E7681?style=flat-square)",
}

VERDICT_EMOJI = {
    "PASS": "✅ PASS",
    "FAIL": "❌ FAIL",
    "N/A": "⬜ N/A",
}


def load_sigma_rules() -> list[dict]:
    rules = []
    sigma_dir = REPO_ROOT / "rules" / "sigma"
    if not sigma_dir.exists():
        return rules
    for p in sorted(sigma_dir.glob("*.yml")):
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                data["_file_path"] = f"rules/sigma/{p.name}"
                rules.append(data)
        except Exception:
            pass
    return rules


def count_spl_rules() -> tuple[int, int]:
    """Returns (total_spl, native_spl). Total includes sigma-converted .spl files."""
    splunk_dir = REPO_ROOT / "rules" / "splunk"
    if not splunk_dir.exists():
        return 0, 0
    all_spl = list(splunk_dir.glob("*.spl"))
    native = sum(1 for p in all_spl if ".sigma." not in p.name)
    return len(all_spl), native


def load_native_spl_rules() -> list[dict]:
    """Read META block from native (non-sigma-converted) .spl files."""
    rules = []
    splunk_dir = REPO_ROOT / "rules" / "splunk"
    if not splunk_dir.exists():
        return rules
    for p in sorted(splunk_dir.glob("*.spl")):
        if ".sigma." in p.name:
            continue
        try:
            content = p.read_text(encoding="utf-8")
            m = re.search(r"META_START\s*(\{.*?\})\s*META_END", content, re.DOTALL)
            if m:
                meta = json.loads(m.group(1))
                if isinstance(meta, dict):
                    meta["_file_path"] = f"rules/splunk/{p.name}"
                    rules.append(meta)
        except Exception:
            pass
    return rules


def load_verdicts() -> dict[str, dict]:
    """Returns {detect_id: {verdict, run_id}} from outputs/results/*/result.json."""
    verdicts: dict[str, dict] = {}
    results_dir = REPO_ROOT / "outputs" / "results"
    if not results_dir.exists():
        return verdicts
    for result_file in results_dir.glob("*/result.json"):
        try:
            data = json.loads(result_file.read_text(encoding="utf-8"))
            detect_id = data.get("detect_id", "")
            verdict = data.get("verdict", "")
            if detect_id and verdict:
                verdicts[detect_id] = {
                    "verdict": verdict,
                    "run_id": data.get("run_id", ""),
                }
        except Exception:
            pass
    return verdicts


def extract_tactics(tags: list) -> list[str]:
    tactics = []
    for tag in tags or []:
        tag = str(tag).lower()
        if tag.startswith("attack.") and not re.match(r"attack\.t\d+", tag):
            key = tag[len("attack."):]
            tactics.append(TACTIC_MAP.get(key, key.replace("_", " ").title()))
    return tactics


def extract_techniques(tags: list) -> list[str]:
    """Returns technique IDs like ['T1053.005', 'T1059'] from sigma tags."""
    techniques = []
    for tag in tags or []:
        m = re.match(r"attack\.(t\d+(?:\.\d+)?)", str(tag).lower())
        if m:
            techniques.append(m.group(1).upper())
    return techniques


def technique_url(tech: str) -> str:
    """T1053.005 → https://attack.mitre.org/techniques/T1053/005/"""
    parts = tech.split(".")
    return "https://attack.mitre.org/techniques/" + "/".join(parts) + "/"


MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/enterprise-attack/enterprise-attack.json"
)
MITRE_CACHE_DAYS = 7


def pass_rate_color(pct: int) -> str:
    if pct >= 80:
        return "brightgreen"
    if pct >= 50:
        return "yellow"
    return "red"


def fetch_mitre_techniques(
    cached_count: int | None = None, cached_at: str | None = None
) -> tuple[int, list, bool]:
    """Returns (total_main_count, technique_map, was_freshly_fetched).

    technique_map: [{id, name, tactics, subs:[{id, name, tactics}]}]
    Caches the full map in MITRE_MAP_CACHE_PATH (7-day TTL).
    Falls back to cached values on any error.
    """
    cached_map: list = []
    disk_at: str | None = None
    if MITRE_MAP_CACHE_PATH.exists():
        try:
            disk = json.loads(MITRE_MAP_CACHE_PATH.read_text(encoding="utf-8"))
            cached_map = disk.get("techniques", [])
            disk_at = disk.get("fetched_at")
        except Exception:
            pass

    # Only skip fetch if both the count AND the technique map are cached and fresh
    ref_at = disk_at  # only trust disk cache timestamp, not the count-only stats.json timestamp
    if cached_count and cached_map and ref_at:
        try:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(ref_at)
            if age < timedelta(days=MITRE_CACHE_DAYS):
                return cached_count, cached_map, False
        except Exception:
            pass

    try:
        with urllib.request.urlopen(MITRE_STIX_URL, timeout=30) as resp:
            data = json.loads(resp.read())

        main_techs: dict = {}
        sub_techs: dict = {}

        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            if "enterprise-attack" not in obj.get("x_mitre_domains", []):
                continue
            tech_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    eid = ref.get("external_id", "")
                    if re.match(r"^T\d{4}(\.\d{3})?$", eid):
                        tech_id = eid
                    break
            if not tech_id:
                continue
            tactics = []
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    tname = STIX_TACTIC_MAP.get(phase.get("phase_name", ""), "")
                    if tname:
                        tactics.append(tname)
            entry = {"id": tech_id, "name": obj.get("name", ""), "tactics": tactics}
            if "." in tech_id:
                sub_techs[tech_id] = entry
            else:
                main_techs[tech_id] = entry

        for tid, entry in main_techs.items():
            entry["subs"] = sorted(
                [s for sid, s in sub_techs.items() if sid.startswith(tid + ".")],
                key=lambda x: x["id"],
            )

        technique_map = sorted(main_techs.values(), key=lambda x: x["id"])
        count = len(main_techs)
        now_iso = datetime.now(timezone.utc).isoformat()

        try:
            MITRE_MAP_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            MITRE_MAP_CACHE_PATH.write_text(
                json.dumps({"fetched_at": now_iso, "techniques": technique_map}, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception:
            pass

        return (count if count > 0 else cached_count or 201), technique_map, True
    except Exception:
        return cached_count or 201, cached_map, False


def mitre_coverage_color(pct: float) -> str:
    if pct <= 25:
        return "#7B0000"
    if pct <= 50:
        return "#DC2626"
    if pct <= 75:
        return "#FFAA00"
    return "#2EA44F"


def tactic_chart_url(by_tactic: dict) -> str:
    """Horizontal bar chart: rules per MITRE ATT&CK tactic, sorted by count desc."""
    if not by_tactic:
        return ""
    tactics = sorted(by_tactic.items(), key=lambda x: -x[1])
    labels = [t for t, _ in tactics]
    values = [c for _, c in tactics]
    height = max(160, len(tactics) * 36 + 70)
    cfg = {
        "type": "horizontalBar",
        "data": {
            "labels": labels,
            "datasets": [{
                "label": "Rules",
                "data": values,
                "backgroundColor": "#FFAA00",
                "borderColor": "black",
                "borderWidth": 0.5,
            }],
        },
        "options": {
            "scales": {
                "xAxes": [{
                    "display": False,
                    "gridLines": {
                        "display": False,
                        "drawOnChartArea": False,
                        "drawBorder": False,
                    },
                    "ticks": {
                        "display": False,
                        "beginAtZero": True,
                    },
                }],
                "yAxes": [{
                    "display": True,
                    "position": "left",
                    "gridLines": {
                        "display": False,
                        "drawOnChartArea": False,
                        "drawBorder": False,
                    },
                    "ticks": {"fontColor": "#FFAA00"},
                }],
            },
            "legend": {"display": False},
            "plugins": {
                "datalabels": {
                    "anchor": "end",
                    "align": "start",
                    "color": "black",
                    "font": {"size": 12, "weight": "bold"},
                },
            },
        },
    }
    chart_json = json.dumps(cfg, separators=(",", ":"))
    return (
        "https://quickchart.io/chart?c=" + urllib.parse.quote(chart_json)
        + f"&width=500&height={height}&f=svg"
    )


def mitre_coverage_chart_url(covered: int, total: int, pct: float) -> str:
    """Build a QuickChart URL for a half-doughnut MITRE coverage gauge.

    QuickChart's server-side SVG renderer does not expose the Canvas 2D API
    (beginPath, save, measureText, etc.) to custom afterDraw hooks, so
    per-label pill backgrounds are not achievable. The doughnutlabel plugin
    renders text with white color directly on the chart background.
    """
    cfg = {
        "type": "doughnut",
        "data": {
            "datasets": [{
                "data": [covered, total - covered],
                "backgroundColor": ["#FFAA00", "rgba(128,128,128,0.15)"],
                "borderColor": "black",
                "borderWidth": 0.5,
            }],
        },
        "options": {
            "rotation": math.pi,
            "circumference": math.pi,
            "cutoutPercentage": 80,
            "plugins": {
                "legend": {"display": False},
                "tooltip": {"enabled": False},
                "datalabels": {"display": False},
                "doughnutlabel": {
                    "labels": [
                        {"text": "MITRE ATT&CK Coverage", "color": "#FFAA00", "font": {"size": 18, "weight": "bold"}},
                        {"text": f"{pct:.1f}%", "color": "#FFAA00", "font": {"size": 34, "weight": "bold"}},
                        {"text": f"{covered} / {total}", "color": "#FFAA00", "font": {"size": 13}},
                    ],
                },
            },
        },
    }
    chart_json = json.dumps(cfg, separators=(",", ":"))
    return "https://quickchart.io/chart?c=" + urllib.parse.quote(chart_json) + "&width=500&height=300&f=svg"


def build_technique_coverage(rules_detail: list, repo: str) -> dict:
    """Build {tech_id: {best_verdict, rules:[{id,title,verdict,url}]}} from rules."""
    cov: dict = {}
    for rule in rules_detail:
        for tech in rule.get("techniques") or []:
            if tech not in cov:
                cov[tech] = {"best_verdict": "N/A", "rules": []}
            file_path = rule.get("file_path", "")
            url = f"https://github.com/{repo}/blob/main/{file_path}" if file_path else ""
            cov[tech]["rules"].append({
                "id": rule["detect_id"],
                "title": rule["title"],
                "verdict": rule["verdict"],
                "url": url,
            })
            v = rule["verdict"]
            cur = cov[tech]["best_verdict"]
            if v == "PASS":
                cov[tech]["best_verdict"] = "PASS"
            elif v == "FAIL" and cur not in ("PASS",):
                cov[tech]["best_verdict"] = "FAIL"
    return cov


def render_navigator_layer(technique_coverage: dict, stats: dict) -> str:
    techniques_out = []
    for tech_id, cov in technique_coverage.items():
        verdict = cov["best_verdict"]
        color = {"PASS": "#2EA44F", "FAIL": "#CF222E"}.get(verdict, "#6E7681")
        score = {"PASS": 100, "FAIL": 50}.get(verdict, 25)
        comment = "\n".join(
            f"{r['id']}: {r['title']} ({r['verdict']})" for r in cov["rules"]
        )
        techniques_out.append({
            "techniqueID": tech_id,
            "color": color,
            "comment": comment,
            "enabled": True,
            "score": score,
            "showSubtechniques": True,
        })
    layer = {
        "name": "Detection Engineering Coverage",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Auto-generated detection coverage. {stats['generated_at'][:19]} UTC.",
        "filters": {"platforms": [
            "Windows", "Linux", "macOS", "Network", "PRE", "Containers",
            "Office 365", "SaaS", "Google Workspace", "IaaS", "Azure AD",
        ]},
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
            "expandedSubtechniques": "annotated",
        },
        "hideDisabled": False,
        "techniques": techniques_out,
        "gradient": {"colors": ["#ffffff00", "#2EA44F"], "minValue": 0, "maxValue": 100},
        "legendItems": [
            {"label": "PASS", "color": "#2EA44F"},
            {"label": "FAIL", "color": "#CF222E"},
            {"label": "Not Verified", "color": "#6E7681"},
        ],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#205b8f",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }
    return json.dumps(layer, indent=2, ensure_ascii=False)


def write_navigator_layer(content: str) -> None:
    out_path = REPO_ROOT / "outputs" / "reports" / "navigator_layer.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(content, encoding="utf-8")


def _build_matrix_html(technique_map: list, technique_coverage: dict) -> str:
    tactic_techs: dict[str, list] = {t: [] for t in TACTIC_ORDER}
    for tech in technique_map:
        for tactic in tech.get("tactics", []):
            if tactic in tactic_techs:
                tactic_techs[tactic].append(tech)
    for tactic in TACTIC_ORDER:
        tactic_techs[tactic].sort(key=lambda x: x["id"])

    def vcls(tid: str) -> str:
        c = technique_coverage.get(tid)
        if not c:
            return "uncov"
        return {"PASS": "pass", "FAIL": "fail"}.get(c["best_verdict"], "nv")

    def rattr(tid: str) -> str:
        c = technique_coverage.get(tid)
        if not c:
            return ""
        return ' data-rules="' + _html.escape(json.dumps(c["rules"])) + '"'

    cols = []
    for tactic in TACTIC_ORDER:
        techs = tactic_techs.get(tactic, [])
        tac_id = TACTIC_ID_MAP.get(tactic, "")
        tac_url = f"https://attack.mitre.org/tactics/{tac_id}/" if tac_id else "#"
        cells = []
        for tech in techs:
            tid = tech["id"]
            tname = _html.escape(tech["name"])
            cells.append(
                f'<div class="tc {vcls(tid)}" data-id="{tid}"{rattr(tid)}>'
                f'<a class="ti" href="https://attack.mitre.org/techniques/{tid}/" target="_blank">{tid}</a>'
                f'<span class="tn">{tname}</span></div>'
            )
            for sub in tech.get("subs", []):
                sid = sub["id"]
                suffix = sid.split(".")[1]
                surl = f"https://attack.mitre.org/techniques/{tid}/{suffix}/"
                cells.append(
                    f'<div class="tc sub {vcls(sid)}" data-id="{sid}"{rattr(sid)}>'
                    f'<a class="ti" href="{surl}" target="_blank">.{suffix}</a>'
                    f'<span class="tn">{_html.escape(sub["name"])}</span></div>'
                )
        cols.append(
            f'<div class="tc-col">'
            f'<div class="tc-hdr"><a href="{tac_url}" target="_blank">{_html.escape(tactic)}</a></div>'
            + "".join(cells)
            + '</div>'
        )
    return '<div class="att-matrix">' + "".join(cols) + '</div>'


def generate_stats() -> dict:
    sigma_rules = load_sigma_rules()
    native_spl_rules = load_native_spl_rules()
    total_spl_count, native_spl_count = count_spl_rules()
    verdicts = load_verdicts()

    by_level: dict[str, int] = {}
    by_status: dict[str, int] = {}
    by_tactic: dict[str, int] = {}

    verified_pass = 0
    verified_fail = 0
    not_verified = 0
    rules_detail: list[dict] = []

    for rule in sigma_rules:
        detect_id = str(rule.get("detect_id") or "")
        title = str(rule.get("title") or "")
        level = str(rule.get("level") or "").lower()
        status = str(rule.get("status") or "").lower()
        tags = rule.get("tags") or []
        tactics = extract_tactics(tags)
        techniques = extract_techniques(tags)

        by_level[level] = by_level.get(level, 0) + 1
        by_status[status] = by_status.get(status, 0) + 1

        for tactic in tactics:
            by_tactic[tactic] = by_tactic.get(tactic, 0) + 1

        v_data = verdicts.get(detect_id, {})
        verdict = v_data.get("verdict", "N/A")
        run_id = v_data.get("run_id", "")
        if verdict == "PASS":
            verified_pass += 1
        elif verdict == "FAIL":
            verified_fail += 1
        else:
            not_verified += 1

        rules_detail.append({
            "detect_id": detect_id,
            "title": title,
            "level": level,
            "status": status,
            "source": "sigma",
            "verdict": verdict,
            "run_id": run_id,
            "tactics": tactics,
            "techniques": techniques,
            "file_path": rule.get("_file_path", ""),
        })

    for rule in native_spl_rules:
        detect_id = str(rule.get("detect_id") or "")
        title = str(rule.get("title") or "")
        level = str(rule.get("level") or "").lower()
        status = str(rule.get("status") or "").lower()
        tags = rule.get("tags") or []
        tactics = extract_tactics(tags)
        techniques = extract_techniques(tags)

        by_level[level] = by_level.get(level, 0) + 1
        by_status[status] = by_status.get(status, 0) + 1

        for tactic in tactics:
            by_tactic[tactic] = by_tactic.get(tactic, 0) + 1

        v_data = verdicts.get(detect_id, {})
        verdict = v_data.get("verdict", "N/A")
        run_id = v_data.get("run_id", "")
        if verdict == "PASS":
            verified_pass += 1
        elif verdict == "FAIL":
            verified_fail += 1
        else:
            not_verified += 1

        rules_detail.append({
            "detect_id": detect_id,
            "title": title,
            "level": level,
            "status": status,
            "source": "native_spl",
            "verdict": verdict,
            "run_id": run_id,
            "tactics": tactics,
            "techniques": techniques,
            "file_path": rule.get("_file_path", ""),
        })

    total_sigma = len(sigma_rules)
    total_rules = total_sigma + native_spl_count
    total_verifiable = total_sigma + native_spl_count
    pass_rate = round(verified_pass / total_verifiable * 100) if total_verifiable > 0 else 0

    # Unique parent techniques covered (T1053.005 → T1053)
    covered_techniques = {
        t.split(".")[0].upper()
        for r in rules_detail
        for t in (r.get("techniques") or [])
    }
    covered_count = len(covered_techniques)

    stats_path = REPO_ROOT / "outputs" / "reports" / "stats.json"
    cached_total: int | None = None
    cached_at: str | None = None
    if stats_path.exists():
        try:
            old = json.loads(stats_path.read_text(encoding="utf-8"))
            cached_total = old.get("mitre_total_techniques")
            cached_at = old.get("mitre_total_fetched_at")
        except Exception:
            pass

    mitre_total, technique_map, was_fetched = fetch_mitre_techniques(cached_total, cached_at)
    mitre_pct = round(covered_count / mitre_total * 100, 1) if mitre_total > 0 else 0.0
    now_iso = datetime.now(timezone.utc).isoformat()

    return {
        "generated_at": now_iso,
        "total_rules": total_rules,
        "total_sigma_rules": total_sigma,
        "total_splunk_rules": total_spl_count,
        "total_native_spl_rules": native_spl_count,
        "verified_pass": verified_pass,
        "verified_fail": verified_fail,
        "not_verified": not_verified,
        "pass_rate_pct": pass_rate,
        "pass_rate_color": pass_rate_color(pass_rate),
        "mitre_covered_techniques": covered_count,
        "mitre_total_techniques": mitre_total,
        "mitre_total_fetched_at": now_iso if was_fetched else (cached_at or now_iso),
        "mitre_coverage_pct": mitre_pct,
        "by_level": dict(sorted(by_level.items())),
        "by_status": dict(sorted(by_status.items())),
        "by_tactic": dict(sorted(by_tactic.items(), key=lambda x: -x[1])),
        "rules": sorted(rules_detail, key=lambda r: r["detect_id"]),
        # Not written to stats.json — used only by render functions
        "_technique_map": technique_map,
        "_rules_detail": rules_detail,
    }


def render_readme_section(stats: dict, repo: str) -> str:
    lines: list[str] = []

    # --- Shields.io dynamic badges ---
    raw_base = (
        f"https://raw.githubusercontent.com/{repo}/main/outputs/reports/stats.json"
    )
    encoded_url = raw_base.replace(":", "%3A").replace("/", "%2F")
    b = f"https://img.shields.io/badge/dynamic/json?style=flat-square&url={encoded_url}"

    row1 = f"[![Total Rules]({b}&query=%24.total_rules&label=Total%20Rules&color=informational)](https://github.com/martonbence/Detection-Engineering/tree/main/rules)"
    row2 = " ".join([
        f"[![Sigma Rules]({b}&query=%24.total_sigma_rules&label=Sigma%20Rules&color=00ACD7)](https://github.com/martonbence/Detection-Engineering/tree/main/rules/sigma)",
        f"[![Native SPL]({b}&query=%24.total_native_spl_rules&label=Native%20SPL&color=FF6600)](https://github.com/martonbence/Detection-Engineering/tree/main/rules/splunk)",
    ])
    row3 = " ".join([
        f"![Pass]({b}&query=%24.verified_pass&label=Pass&color=brightgreen)",
        f"![Fail]({b}&query=%24.verified_fail&label=Fail&color=red)",
        f"![Pass Rate]({b}&query=%24.pass_rate_pct&label=Pass%20Rate%20%25&color={stats['pass_rate_color']})",
        f"![Not Verified]({b}&query=%24.not_verified&label=Not%20Verified&color=lightgrey)",
    ])
    for row in [row1, "", row2, "", row3]:
        lines.append(row)
    lines.append("")

    # --- MITRE ATT&CK Coverage doughnut gauge ---
    covered = stats.get("mitre_covered_techniques", 0)
    total_mitre = stats.get("mitre_total_techniques", 201)
    mitre_pct = stats.get("mitre_coverage_pct", 0.0)
    coverage_url = mitre_coverage_chart_url(covered, total_mitre, mitre_pct)
    lines += ["**MITRE ATT&CK Coverage**", f"![MITRE ATT&CK Coverage]({coverage_url})", ""]

    # --- Severity outlabeledPie chart via quickchart.io ---
    level_order = ["critical", "high", "medium", "low", "informational"]
    level_colors_map = {
        "critical":      "#7B0000",
        "high":          "#DC2626",
        "medium":        "#FFAA00",
        "low":           "#2EA44F",
        "informational": "#6E7681",
    }
    level_display = {
        "critical": "Critical", "high": "High", "medium": "Medium",
        "low": "Low", "informational": "Info",
    }
    active = [
        (lvl, stats["by_level"].get(lvl, 0))
        for lvl in level_order
        if stats["by_level"].get(lvl, 0) > 0
    ]
    chart_cfg = {
        "type": "outlabeledPie",
        "backgroundColor": "transparent",
        "data": {
            "labels": [level_display[lvl] for lvl, _ in active],
            "datasets": [{
                "backgroundColor": [level_colors_map[lvl] for lvl, _ in active],
                "borderColor": "black",
                "borderWidth": 0.5,
                "hoverOffset": 8,
                "data": [cnt for _, cnt in active],
            }],
        },
        "options": {
            "cutoutPercentage": 45,
            "layout": {"padding": {"top": 5, "right": 30, "bottom": 0, "left": 30}},
            "plugins": {
                "legend": False,
                "outlabels": {
                    "text": "%l: %v (%p)",
                    "color": "white",
                    "backgroundColor": "rgba(85, 85, 85,1)",
                    "lineColor": "rgba(85, 85, 85,1)",
                    "borderRadius": 13,
                    "padding": 6,
                    "stretch": 20,
                    "font": {
                        "weight": "bold",
                        "resizable": True,
                        "minSize": 12,
                        "maxSize": 22,
                    },
                    "formatter": "(value) => value > 0 ? value : null",
                },
            },
        },
    }
    chart_json = json.dumps(chart_cfg, separators=(",", ":"))
    chart_url = "https://quickchart.io/chart?c=" + urllib.parse.quote(chart_json) + "&width=500&height=300&f=svg"
    lines += ["**Rules by Severity**", f"![Rules by Severity]({chart_url})", ""]

    # --- MITRE ATT&CK tactic bar chart ---
    if stats["by_tactic"]:
        tactic_url = tactic_chart_url(stats["by_tactic"])
        lines += ["**Rules per MITRE ATT&CK Tactic**", f"![Rules per MITRE ATT&CK Tactic]({tactic_url})", ""]

    gh_pages = f"https://{repo.split('/')[0]}.github.io/{repo.split('/')[1]}/"
    lines += [
        f"🗺️ Interactive MITRE Navigator → [GitHub Pages]({gh_pages})",
        "",
        f"📋 Full rule index → [rules/RULE_SUMMARY.md](https://github.com/{repo}/blob/main/rules/RULE_SUMMARY.md)",
        "",
        f"*Generated at {stats['generated_at'][:19]} UTC*",
    ]

    return "\n".join(lines)


def render_rule_summary(stats: dict, repo: str) -> str:
    lines: list[str] = [
        "# Rule Summary",
        "",
        f"*Generated at {stats['generated_at'][:19]} UTC — {stats['total_rules']} rules total*",
        "",
        "| ID | Title | Source | Tactic | Technique | Severity | Status | Verdict |",
        "|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|",
    ]

    for r in stats["rules"]:
        detect_id = r["detect_id"]
        display_id = detect_id.replace("-", "\u2011")  # non-breaking hyphen
        file_path = r.get("file_path", "")
        if file_path:
            id_cell = f"[`{display_id}`](https://github.com/{repo}/blob/main/{file_path})"
        else:
            id_cell = f"`{display_id}`"

        lvl = r["level"]
        lvl_cell = LEVEL_BADGE.get(lvl, f"`{lvl}`") if lvl else "—"
        run_id = r.get("run_id", "")
        badge_img = VERDICT_BADGE.get(r["verdict"], r["verdict"])
        if run_id:
            verdict_cell = f"[{badge_img}](https://github.com/{repo}/actions/runs/{run_id})"
        else:
            verdict_cell = badge_img
        source_cell = "Sigma" if r.get("source") == "sigma" else "Native&nbsp;SPL"

        tactics = r.get("tactics") or []
        tactic_links = []
        for t in tactics:
            ta_id = TACTIC_ID_MAP.get(t, "")
            if ta_id:
                tactic_links.append(f"[{t}](https://attack.mitre.org/tactics/{ta_id}/)")
            else:
                tactic_links.append(t)
        tactic_cell = "<br>".join(tactic_links) if tactic_links else "—"

        techniques = r.get("techniques") or []
        tech_links = [f"[{t}]({technique_url(t)})" for t in techniques]
        tech_cell = "<br>".join(tech_links) if tech_links else "—"

        title_cell = f"<nobr>{r['title']}</nobr>"
        lines.append(
            f"| {id_cell} | {title_cell} | {source_cell} | {tactic_cell} | {tech_cell} | {lvl_cell} | {r['status']} | {verdict_cell} |"
        )

    return "\n".join(lines) + "\n"


def update_readme(section_content: str) -> None:
    readme = REPO_ROOT / "README.md"
    text = readme.read_text(encoding="utf-8")

    start_marker = "<!-- STATS_START -->"
    end_marker = "<!-- STATS_END -->"
    new_block = f"{start_marker}\n{section_content}\n{end_marker}"

    if start_marker in text and end_marker in text:
        text = re.sub(
            rf"{re.escape(start_marker)}.*?{re.escape(end_marker)}",
            new_block,
            text,
            flags=re.DOTALL,
        )
    else:
        text = text.rstrip() + "\n\n" + new_block + "\n"

    readme.write_text(text, encoding="utf-8")


def update_rule_summary(content: str) -> None:
    out_path = REPO_ROOT / "rules" / "RULE_SUMMARY.md"
    out_path.write_text(content, encoding="utf-8")


def render_html_summary(stats: dict, repo: str) -> str:
    SEV_ORDER = ["critical", "high", "medium", "low", "informational"]
    SEV_COLORS = {
        "critical":      ("#7B0000", "#fff"),
        "high":          ("#DC2626", "#fff"),
        "medium":        ("#FFAA00", "#111"),
        "low":           ("#2EA44F", "#fff"),
        "informational": ("#6E7681", "#fff"),
    }
    VERDICT_COLORS = {"PASS": "#2EA44F", "FAIL": "#CF222E", "N/A": "#6E7681"}
    ALL_TACTICS = [
        "Reconnaissance", "Resource Development", "Initial Access",
        "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery",
        "Lateral Movement", "Collection", "Command & Control",
        "Exfiltration", "Impact",
    ]
    all_techniques = sorted({t for r in stats["rules"] for t in (r.get("techniques") or [])})

    def sev_badge(level: str) -> str:
        bg, fg = SEV_COLORS.get(level, ("#444", "#fff"))
        label = level.capitalize() if level else "—"
        return f'<span class="badge" style="background:{bg};color:{fg}">{label}</span>'

    def verdict_html(verdict: str, run_id: str) -> str:
        bg = VERDICT_COLORS.get(verdict, "#444")
        b = f'<span class="badge" style="background:{bg};color:#fff">{_html.escape(verdict)}</span>'
        if run_id:
            url = f"https://github.com/{repo}/actions/runs/{run_id}"
            return f'<a href="{url}" target="_blank" title="View Actions run">{b}</a>'
        return b

    def sel_html(options: list) -> str:
        opts = '<option value="">All</option>' + "".join(
            f'<option>{_html.escape(str(o))}</option>' for o in options
        )
        return f'<select class="col-sel">{opts}</select>'

    status_vals = sorted({r.get("status", "") for r in stats["rules"]} - {""})
    filter_row = (
        '<tr class="frow">'
        '<th><input class="col-txt" type="text" placeholder="Filter…"></th>'
        '<th><input class="col-txt" type="text" placeholder="Filter…"></th>'
        f'<th>{sel_html(["Sigma", "Native SPL"])}</th>'
        f'<th>{sel_html(ALL_TACTICS)}</th>'
        f'<th>{sel_html(all_techniques)}</th>'
        f'<th>{sel_html([s.capitalize() for s in SEV_ORDER])}</th>'
        f'<th>{sel_html(status_vals)}</th>'
        f'<th>{sel_html(["PASS", "FAIL", "N/A"])}</th>'
        '</tr>'
    )

    rows = []
    for r in stats["rules"]:
        detect_id = r["detect_id"]
        file_path = r.get("file_path", "")
        title = _html.escape(r["title"])
        source = "Sigma" if r.get("source") == "sigma" else "Native SPL"
        lvl = r.get("level", "")
        verdict = r["verdict"]
        run_id = r.get("run_id", "")
        status = _html.escape(r.get("status", ""))

        if file_path:
            id_cell = f'<a href="https://github.com/{repo}/blob/main/{file_path}" target="_blank"><code>{_html.escape(detect_id)}</code></a>'
        else:
            id_cell = f'<code>{_html.escape(detect_id)}</code>'

        tactics = r.get("tactics") or []
        tac_parts = []
        for t in tactics:
            ta_id = TACTIC_ID_MAP.get(t, "")
            url = f"https://attack.mitre.org/tactics/{ta_id}/" if ta_id else "#"
            tac_parts.append(f'<a href="{url}" target="_blank">{_html.escape(t)}</a>')
        tac_cell = "<br>".join(tac_parts) or "—"
        tac_search = _html.escape(", ".join(tactics) or "")

        techniques = r.get("techniques") or []
        tech_parts = [f'<a href="{technique_url(t)}" target="_blank">{_html.escape(t)}</a>' for t in techniques]
        tech_cell = "<br>".join(tech_parts) or "—"
        tech_search = _html.escape(", ".join(techniques) or "")

        sev_idx = SEV_ORDER.index(lvl) if lvl in SEV_ORDER else 99

        rows.append(
            f'<tr>'
            f'<td>{id_cell}</td>'
            f'<td>{title}</td>'
            f'<td>{source}</td>'
            f'<td data-search="{tac_search}">{tac_cell}</td>'
            f'<td data-search="{tech_search}">{tech_cell}</td>'
            f'<td data-search="{_html.escape(lvl.capitalize())}" data-order="{sev_idx}">{sev_badge(lvl)}</td>'
            f'<td>{status}</td>'
            f'<td data-search="{_html.escape(verdict)}">{verdict_html(verdict, run_id)}</td>'
            f'</tr>'
        )

    rows_html = "\n".join(rows)
    ts = stats["generated_at"][:19]
    total = stats["total_rules"]
    passed = stats["verified_pass"]
    failed = stats["verified_fail"]
    not_ver = stats["not_verified"]
    pass_rate = stats["pass_rate_pct"]

    technique_map = stats.get("_technique_map", [])
    rules_detail_inner = stats.get("_rules_detail", stats.get("rules", []))
    technique_coverage = build_technique_coverage(rules_detail_inner, repo)
    matrix_html = _build_matrix_html(technique_map, technique_coverage)
    layer_url = f"https://github.com/{repo}/blob/main/outputs/reports/navigator_layer.json"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Detection Engineering — Rule Summary</title>
  <link rel="stylesheet" href="https://cdn.datatables.net/1.13.8/css/jquery.dataTables.min.css">
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    :root {{ --bg:#0d1117; --surface:#161b22; --border:#30363d; --text:#e6edf3; --muted:#8b949e; --link:#58a6ff; }}
    body {{ background:var(--bg); color:var(--text); font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif; font-size:14px; line-height:1.5; padding:32px 24px; }}
    h1 {{ font-size:20px; font-weight:700; margin-bottom:24px; }}
    h1 a {{ color:var(--link); text-decoration:none; }}
    h1 a:hover {{ text-decoration:underline; }}
    .stats-row {{ display:flex; gap:12px; margin-bottom:24px; flex-wrap:wrap; }}
    .stat-card {{ background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:14px 22px; min-width:110px; text-align:center; }}
    .stat-value {{ font-size:26px; font-weight:700; }}
    .stat-label {{ font-size:11px; color:var(--muted); margin-top:3px; text-transform:uppercase; letter-spacing:.5px; }}
    .table-wrap {{ background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:20px; overflow-x:auto; }}
    table.dataTable {{ color:var(--text) !important; border-collapse:collapse !important; width:100% !important; }}
    table.dataTable thead th {{
      background:var(--bg) !important; color:var(--text) !important;
      border-bottom:1px solid var(--border) !important;
      text-align:center !important; padding:10px 14px 8px !important; white-space:nowrap; vertical-align:bottom;
    }}
    table.dataTable thead tr.frow th {{
      background:#0a0e14 !important; padding:5px 6px 7px !important;
      border-bottom:2px solid var(--border) !important;
    }}
    table.dataTable tbody td {{
      border-bottom:1px solid var(--border) !important; padding:10px 12px !important;
      vertical-align:middle; text-align:center; background:transparent !important;
    }}
    table.dataTable tbody tr:last-child td {{ border-bottom:none !important; }}
    table.dataTable tbody tr:hover td {{ background:rgba(255,255,255,.04) !important; }}
    a {{ color:var(--link); text-decoration:none; }} a:hover {{ text-decoration:underline; }}
    code {{ background:rgba(110,118,129,.15); border-radius:4px; padding:2px 6px; font-size:12px; white-space:nowrap; }}
    .badge {{ display:inline-block; padding:2px 10px; border-radius:12px; font-size:12px; font-weight:600; white-space:nowrap; }}
    .col-sel, .col-txt {{
      width:100%; background:#0a0e14 !important; color:var(--text) !important;
      border:1px solid var(--border); border-radius:4px; padding:3px 5px; font-size:11px;
    }}
    .col-sel option {{ background:#0a0e14; color:var(--text); }}
    .dataTables_wrapper .dataTables_length select,
    .dataTables_wrapper .dataTables_filter input {{
      background:#0a0e14 !important; color:var(--text) !important;
      border:1px solid var(--border) !important; border-radius:4px; padding:4px 8px; margin-left:6px;
    }}
    .dataTables_wrapper .dataTables_length select option {{ background:#0a0e14; color:var(--text); }}
    .dataTables_wrapper .dataTables_filter label,
    .dataTables_wrapper .dataTables_length label,
    .dataTables_wrapper .dataTables_info {{ color:var(--muted); }}
    .dataTables_wrapper .dataTables_paginate .paginate_button {{
      color:var(--text) !important; border-radius:4px !important; border:none !important; padding:4px 10px !important;
    }}
    .dataTables_wrapper .dataTables_paginate .paginate_button:hover {{
      background:var(--border) !important; color:var(--text) !important; border:none !important;
    }}
    .dataTables_wrapper .dataTables_paginate .paginate_button.current,
    .dataTables_wrapper .dataTables_paginate .paginate_button.current:hover {{
      background:var(--link) !important; color:#fff !important; border:none !important;
    }}
    .dataTables_wrapper .dataTables_paginate .paginate_button.disabled,
    .dataTables_wrapper .dataTables_paginate .paginate_button.disabled:hover {{ color:var(--muted) !important; }}
    footer {{ margin-top:20px; color:var(--muted); font-size:12px; text-align:center; }}
    /* Tabs */
    .tab-bar {{ display:flex; gap:4px; margin-bottom:0; border-bottom:1px solid var(--border); }}
    .tab-btn {{ background:none; border:1px solid transparent; border-bottom:none; color:var(--muted); padding:8px 20px; border-radius:6px 6px 0 0; cursor:pointer; font-size:13px; font-weight:600; transition:color .15s,background .15s; margin-bottom:-1px; }}
    .tab-btn:hover {{ color:var(--text); background:var(--surface); }}
    .tab-btn.active {{ background:var(--surface); border-color:var(--border); color:var(--text); }}
    .tab-pane {{ display:none; padding-top:16px; }}
    .tab-pane.active {{ display:block; }}
    /* MITRE Navigator */
    .nav-wrap {{ background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:16px; }}
    .nav-legend {{ display:flex; gap:16px; margin-bottom:12px; font-size:12px; align-items:center; flex-wrap:wrap; }}
    .nav-legend-item {{ display:flex; align-items:center; gap:5px; }}
    .nav-legend-dot {{ width:12px; height:12px; border-radius:2px; flex-shrink:0; }}
    .nav-import {{ margin-left:auto; font-size:12px; }}
    .att-matrix {{ display:flex; gap:2px; overflow-x:auto; padding-bottom:8px; }}
    .tc-col {{ flex:0 0 112px; display:flex; flex-direction:column; gap:1px; }}
    .tc-hdr {{ background:#205b8f; color:#fff; font-size:9px; font-weight:700; padding:5px 4px; text-align:center; border-radius:3px 3px 0 0; min-height:38px; display:flex; align-items:center; justify-content:center; }}
    .tc-hdr a {{ color:#fff; text-decoration:none; }}
    .tc-hdr a:hover {{ text-decoration:underline; }}
    .tc {{ font-size:8px; padding:3px 4px; border-radius:2px; cursor:default; display:flex; flex-direction:column; min-height:30px; gap:1px; }}
    .tc.uncov {{ background:#1c2128; color:#484f58; }}
    .tc.pass  {{ background:#1a4731; color:#aff3c5; }}
    .tc.fail  {{ background:#67060c; color:#ffc1c1; }}
    .tc.nv    {{ background:#3d444d; color:#cdd5df; }}
    .tc.sub   {{ min-height:22px; padding-left:8px; }}
    .tc[data-rules] {{ cursor:pointer; }}
    .tc[data-rules]:hover {{ filter:brightness(1.3); }}
    .ti {{ font-weight:700; font-size:8px; color:inherit; text-decoration:none; }}
    .ti:hover {{ text-decoration:underline; }}
    .tn {{ overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
    #att-tip {{
      display:none; position:fixed; z-index:9999; pointer-events:none;
      background:#161b22; border:1px solid #30363d; border-radius:8px;
      padding:10px 14px; max-width:340px; font-size:12px; color:#e6edf3;
      box-shadow:0 8px 24px rgba(0,0,0,.5);
    }}
    .tip-head {{ font-weight:700; font-size:13px; margin-bottom:6px; }}
    .tip-rule {{ display:flex; align-items:center; gap:6px; margin:3px 0; text-decoration:none; color:#58a6ff; font-size:11px; }}
    .tip-rule:hover {{ text-decoration:underline; }}
    .tip-vbadge {{ display:inline-block; padding:1px 7px; border-radius:8px; font-size:10px; font-weight:600; flex-shrink:0; }}
    .tip-vbadge.PASS {{ background:#2EA44F; color:#fff; }}
    .tip-vbadge.FAIL {{ background:#CF222E; color:#fff; }}
    .tip-vbadge.NA   {{ background:#6E7681; color:#fff; }}
  </style>
</head>
<body>
  <h1><a href="https://github.com/{repo}" target="_blank">Detection Engineering</a> — Rule Summary</h1>
  <div class="stats-row">
    <div class="stat-card"><div class="stat-value">{total}</div><div class="stat-label">Total Rules</div></div>
    <div class="stat-card"><div class="stat-value" style="color:#2EA44F">{passed}</div><div class="stat-label">Pass</div></div>
    <div class="stat-card"><div class="stat-value" style="color:#CF222E">{failed}</div><div class="stat-label">Fail</div></div>
    <div class="stat-card"><div class="stat-value">{not_ver}</div><div class="stat-label">Not Verified</div></div>
    <div class="stat-card"><div class="stat-value" style="color:#2EA44F">{pass_rate}%</div><div class="stat-label">Pass Rate</div></div>
  </div>
  <div class="tab-bar">
    <button class="tab-btn active" data-tab="rules">Rules Table</button>
    <button class="tab-btn" data-tab="navigator">MITRE Navigator</button>
  </div>
  <div id="tab-rules" class="tab-pane active">
    <div class="table-wrap">
      <table id="rules-table" class="display" style="width:100%">
        <thead>
          <tr>
            <th>ID</th><th>Title</th><th>Source</th>
            <th>Tactic</th><th>Technique</th>
            <th>Severity</th><th>Status</th><th>Verdict</th>
          </tr>
          {filter_row}
        </thead>
        <tbody>
{rows_html}
        </tbody>
      </table>
    </div>
  </div>
  <div id="tab-navigator" class="tab-pane">
    <div class="nav-wrap">
      <div class="nav-legend">
        <div class="nav-legend-item"><div class="nav-legend-dot" style="background:#1a4731;border:1px solid #2EA44F"></div> PASS</div>
        <div class="nav-legend-item"><div class="nav-legend-dot" style="background:#3d444d"></div> Not Verified</div>
        <div class="nav-legend-item"><div class="nav-legend-dot" style="background:#67060c;border:1px solid #CF222E"></div> FAIL</div>
        <div class="nav-legend-item"><div class="nav-legend-dot" style="background:#1c2128;border:1px solid #30363d"></div> Not covered</div>
        <div class="nav-import"><a href="{layer_url}" target="_blank">&#8659; Download Navigator layer (.json)</a></div>
      </div>
      {matrix_html}
    </div>
  </div>
  <div id="att-tip"></div>
  <footer>
    Generated at {ts} UTC &nbsp;·&nbsp;
    <a href="https://github.com/{repo}/blob/main/rules/RULE_SUMMARY.md" target="_blank">Markdown version</a>
  </footer>
  <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
  <script src="https://cdn.datatables.net/1.13.8/js/jquery.dataTables.min.js"></script>
  <script>
  document.querySelectorAll('.tab-btn').forEach(function(btn) {{
    btn.addEventListener('click', function() {{
      document.querySelectorAll('.tab-btn').forEach(function(b) {{ b.classList.remove('active'); }});
      document.querySelectorAll('.tab-pane').forEach(function(p) {{ p.classList.remove('active'); }});
      btn.classList.add('active');
      document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
    }});
  }});
  var tip = document.getElementById('att-tip');
  document.querySelectorAll('.tc[data-rules]').forEach(function(el) {{
    el.addEventListener('mouseenter', function() {{
      var rules = JSON.parse(el.dataset.rules);
      var html = '<div class="tip-head">' + el.dataset.id + '</div>';
      rules.forEach(function(r) {{
        var vc = r.verdict === 'N/A' ? 'NA' : r.verdict;
        var badge = '<span class="tip-vbadge ' + vc + '">' + r.verdict + '</span>';
        if (r.url) {{
          html += '<a class="tip-rule" href="' + r.url + '" target="_blank">' + badge + ' ' + r.id + ': ' + r.title + '</a>';
        }} else {{
          html += '<div class="tip-rule">' + badge + ' ' + r.id + ': ' + r.title + '</div>';
        }}
      }});
      tip.innerHTML = html;
      tip.style.display = 'block';
    }});
    el.addEventListener('mousemove', function(e) {{
      var x = e.clientX + 14, y = e.clientY + 14;
      if (x + 350 > window.innerWidth) x = e.clientX - 354;
      tip.style.left = x + 'px';
      tip.style.top  = y + 'px';
    }});
    el.addEventListener('mouseleave', function() {{ tip.style.display = 'none'; }});
  }});
  $(function() {{
    var table = $('#rules-table').DataTable({{
      orderCellsTop: true,
      pageLength: 25,
      lengthMenu: [[10, 25, 50, 100, 250, -1], [10, 25, 50, 100, 250, 'All']],
      order: [[0, 'asc']],
      language: {{
        search: 'Search:', lengthMenu: 'Show _MENU_ rules',
        zeroRecords: 'No rules match the current filter.',
        info: 'Showing _START_–_END_ of _TOTAL_ rules',
        infoFiltered: '(filtered from _MAX_ total)'
      }}
    }});
    var exactCols = [2, 5, 6, 7];
    $('#rules-table thead tr.frow').find('input.col-txt, select.col-sel').each(function(i) {{
      var isExact = exactCols.indexOf(i) !== -1;
      $(this)
        .on('click', function(e) {{ e.stopPropagation(); }})
        .on('input change', function() {{
          var v = $(this).val();
          var esc = $.fn.dataTable.util.escapeRegex(v);
          table.column(i).search(v ? (isExact ? '^' + esc + '$' : esc) : '', true, false).draw();
        }});
    }});
  }});
  </script>
</body>
</html>
"""


def update_html_summary(content: str) -> None:
    out_path = REPO_ROOT / "docs" / "index.html"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(content, encoding="utf-8")


def main() -> int:
    repo = "martonbence/Detection-Engineering"

    stats = generate_stats()

    out_dir = REPO_ROOT / "outputs" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    stats_for_json = {k: v for k, v in stats.items() if not k.startswith("_")}
    (out_dir / "stats.json").write_text(
        json.dumps(stats_for_json, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(
        f"Stats: {stats['total_sigma_rules']} sigma + {stats['total_native_spl_rules']} native SPL rules — "
        f"{stats['verified_pass']} pass / {stats['verified_fail']} fail / "
        f"{stats['not_verified']} not verified — pass rate: {stats['pass_rate_pct']}%"
    )

    section = render_readme_section(stats, repo)
    update_readme(section)
    print("README.md updated.")

    summary = render_rule_summary(stats, repo)
    update_rule_summary(summary)
    print("rules/RULE_SUMMARY.md updated.")

    nav_layer = render_navigator_layer(build_technique_coverage(stats.get("_rules_detail", stats.get("rules", [])), repo), stats)
    write_navigator_layer(nav_layer)
    print("outputs/reports/navigator_layer.json updated.")

    html_page = render_html_summary(stats, repo)
    update_html_summary(html_page)
    print("docs/index.html updated.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
