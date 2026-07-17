"""
generate_stats.py — Collect detection rule stats and update README.md + docs/index.html.

Reads:
  - rules/sigma/*.yml          — sigma rules (level, status, tags, detect_id)
  - rules/splunk/*.spl         — counts native (non-sigma) SPL rules
  - outputs/results/*/result.json — pass/fail verdicts

Writes:
  - outputs/reports/stats.json — consumed by shields.io dynamic badges
  - README.md                  — replaces content between <!-- STATS_START --> and <!-- STATS_END -->
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
    "stealth": "Stealth",
    "defense_impairment": "Defense Impairment",
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
    "Stealth": "TA0005",
    "Defense Impairment": "TA0112",
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
    "stealth": "Stealth",
    "defense-impairment": "Defense Impairment",
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
    "Stealth", "Defense Impairment", "Credential Access", "Discovery",
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
                    meta["_body"] = content[m.end():].strip()
                    rules.append(meta)
        except Exception:
            pass
    return rules


def extract_sigma_body(rule: dict) -> str:
    """Re-serializes the logsource/detection/fields portion of a sigma rule
    (the actual search logic) for the drawer's syntax-highlighted code view —
    keeps it separate from the metadata already shown elsewhere in the drawer."""
    body = {k: rule[k] for k in ("logsource", "detection", "fields") if k in rule}
    if not body:
        return ""
    try:
        return yaml.safe_dump(
            body, sort_keys=False, allow_unicode=True,
            default_flow_style=False, width=100,
        ).strip()
    except Exception:
        return ""


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


def extract_logsource(rule: dict) -> dict:
    ls = rule.get("logsource")
    if not isinstance(ls, dict):
        return {"product_category": "", "product": "", "service": "", "event_type": ""}
    return {
        "product_category": str(ls.get("product_category") or ""),
        "product": str(ls.get("product") or ""),
        "service": str(ls.get("service") or ""),
        "event_type": str(ls.get("event_type") or ""),
    }


def extract_testing(rule: dict) -> dict:
    """Normalizes the two testing-metadata shapes used by sigma rules
    (custom.testing) and native SPL META blocks (flat 'testing enabled'/'tester' keys)."""
    custom_testing = (rule.get("custom") or {}).get("testing")
    if isinstance(custom_testing, dict):
        return {
            "enabled": bool(custom_testing.get("enabled")),
            "runner": str(custom_testing.get("runner") or ""),
            "type": str(custom_testing.get("type") or ""),
            "atomics": custom_testing.get("atomics") or [],
        }
    if "testing enabled" in rule or "atomic tests" in rule:
        return {
            "enabled": bool(rule.get("testing enabled")),
            "runner": str(rule.get("runner") or ""),
            "type": str(rule.get("tester") or ""),
            "atomics": rule.get("atomic tests") or [],
        }
    return {"enabled": False, "runner": "", "type": "", "atomics": []}


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
        "versions": {"attack": "19", "navigator": "4.9.1", "layer": "4.5"},
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
        return " data-rules=\"" + _html.escape(json.dumps(c["rules"])) + "\""

    def detail_btn_html(tid: str, tname: str) -> str:
        c = technique_coverage.get(tid)
        if not c:
            return ""
        rj = _html.escape(json.dumps(c["rules"]))
        return (
            "<button class=\"tc-detail\""
            " data-id=\"" + tid + "\""
            " data-name=\"" + tname + "\""
            " data-rules=\"" + rj + "\""
            " title=\"Show details\">&#9776;</button>"
        )

    cols = []
    for tactic in TACTIC_ORDER:
        techs = tactic_techs.get(tactic, [])
        tac_id = TACTIC_ID_MAP.get(tactic, "")
        tac_url = "https://attack.mitre.org/tactics/" + tac_id + "/" if tac_id else "#"
        cells = []
        for tech in techs:
            tid = tech["id"]
            tname = _html.escape(tech["name"])
            subs = tech.get("subs", [])
            sub_total = len(subs)
            sub_covered = sum(1 for s in subs if s["id"] in technique_coverage)

            badge = ""
            expand = ""
            if sub_total > 0:
                bc = "sub-badge-cov" if sub_covered > 0 else "sub-badge"
                badge = "<span class=\"" + bc + "\">" + str(sub_covered) + "/" + str(sub_total) + "</span>"
                expand = (
                    "<button class=\"tc-expand\""
                    " data-target=\"subs-" + tid + "\""
                    " title=\"Toggle sub-techniques\">&#9654;</button>"
                )

            tech_url = "https://attack.mitre.org/techniques/" + tid + "/"
            badge_div = ("<div class=\"tc-foot\">" + badge + "</div>") if badge else ""
            cls = vcls(tid)
            has_cov = " has-cov" if (cls == "uncov" and sub_covered > 0) else ""
            cells.append(
                "<div class=\"tc " + cls + has_cov + "\" data-id=\"" + tid + "\"" + rattr(tid) + ">"
                "<div class=\"tc-row1\">"
                "<a class=\"ti\" href=\"" + tech_url + "\" target=\"_blank\">" + tid + "</a>"
                + expand +
                "</div>"
                "<span class=\"tn\">" + tname + "</span>"
                + badge_div
                + detail_btn_html(tid, tname)
                + "</div>"
            )
            for sub in subs:
                sid = sub["id"]
                suffix = sid.split(".")[1]
                sname = _html.escape(sub["name"])
                surl = "https://attack.mitre.org/techniques/" + tid + "/" + suffix + "/"
                cells.append(
                    "<div class=\"tc sub " + vcls(sid) + " subs-" + tid + "\""
                    " style=\"display:none\" data-id=\"" + sid + "\"" + rattr(sid) + ">"
                    "<div class=\"tc-row1\">"
                    "<a class=\"ti\" href=\"" + surl + "\" target=\"_blank\">." + suffix + "</a>"
                    "</div>"
                    "<span class=\"tn\">" + sname + "</span>"
                    + detail_btn_html(sid, sname)
                    + "</div>"
                )
        cols.append(
            "<div class=\"tc-col\">"
            "<div class=\"tc-hdr\"><a href=\"" + tac_url + "\" target=\"_blank\">"
            + _html.escape(tactic) + "</a>"
            + "<span class=\"tc-count\">" + str(len(techs)) + " techniques</span>"
            + "</div>"
            + "".join(cells)
            + "</div>"
        )
    return "<div class=\"att-matrix\">" + "".join(cols) + "</div>"



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

    for rule, source in (
        [(r, "sigma") for r in sigma_rules]
        + [(r, "native_spl") for r in native_spl_rules]
    ):
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

        if source == "sigma":
            rule_body = extract_sigma_body(rule)
            rule_body_lang = "yaml"
        else:
            rule_body = str(rule.get("_body") or "")
            rule_body_lang = "spl"

        rules_detail.append({
            "detect_id": detect_id,
            "title": title,
            "description": str(rule.get("description") or ""),
            "level": level,
            "status": status,
            "source": source,
            "verdict": verdict,
            "run_id": run_id,
            "tactics": tactics,
            "techniques": techniques,
            "file_path": rule.get("_file_path", ""),
            "logsource": extract_logsource(rule),
            "author": str(rule.get("author") or ""),
            "date": str(rule.get("date") or ""),
            "modified": str(rule.get("modified") or ""),
            "references": [str(r) for r in (rule.get("references") or [])],
            "falsepositives": [str(f) for f in (rule.get("falsepositives") or [])],
            "testing": extract_testing(rule),
            "rule_body": rule_body,
            "rule_body_lang": rule_body_lang if rule_body else "",
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
        f"🗺️ Interactive MITRE Navigator → [GitHub Pages]({gh_pages}#navigator)",
        "",
        f"📋 Full rule index → [GitHub Pages]({gh_pages})",
        "",
        f"*Generated at {stats['generated_at'][:19]} UTC*",
    ]

    return "\n".join(lines)




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




_PAGE_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Detection Engineering — Rule Browser</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg: #0d1117;
      --bg2: #161b22;
      --bg3: #1c2128;
      --bg4: #21262d;
      --border: #30363d;
      --border2: #444c56;
      --text: #e6edf3;
      --text2: #8b949e;
      --text3: #6e7681;
      --accent: #58a6ff;
      --accent2: #1f6feb;
      --accent-bg: rgba(88,166,255,0.1);
      --green: #2ea44f;
      --green-bg: rgba(46,164,79,0.12);
      --amber: #d29922;
      --amber-bg: rgba(210,153,34,0.12);
      --red: #cf222e;
      --red-bg: rgba(207,34,46,0.12);
      --purple: #8f95d6;
      --purple-bg: rgba(143,149,214,0.12);
      --radius: 6px;
      --radius-lg: 10px;
      --font: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
      --font-ui: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    }

    html, body { height: 100%; }

    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-ui);
      font-size: 14px;
      height: 100vh;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }

    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }

    /* ── Stats strip / collapsible stats bar ── */
    .stats-wrap {
      flex-shrink: 0;
      z-index: 100;
      background: var(--bg);
      border-bottom: 1px solid var(--border2);
    }

    .stats-strip {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 14px;
      height: 48px;
      padding: 0 18px;
      background: var(--bg2);
      border-bottom: 1px solid var(--border);
    }

    .strip-brand { display: flex; align-items: center; gap: 9px; min-width: 0; }

    .strip-title {
      font-size: 14px;
      font-weight: 700;
      color: var(--text);
      letter-spacing: -0.2px;
      white-space: nowrap;
    }

    .strip-sep { width: 1px; height: 14px; background: var(--border2); flex-shrink: 0; }

    .strip-total {
      font-family: var(--font);
      font-size: 12px;
      color: var(--text3);
      white-space: nowrap;
    }

    .strip-total strong { color: var(--text); font-weight: 700; }

    .tab-bar { display: flex; gap: 4px; flex-shrink: 0; }

    .tab-btn {
      background: none;
      border: 1px solid transparent;
      color: var(--text2);
      padding: 6px 14px;
      border-radius: var(--radius);
      cursor: pointer;
      font-size: 12px;
      font-weight: 600;
      font-family: var(--font-ui);
      transition: all 0.12s;
    }

    .tab-btn:hover { color: var(--text); background: var(--bg3); }

    .tab-btn.active {
      background: var(--accent-bg);
      border-color: rgba(88,166,255,0.35);
      color: var(--accent);
    }

    .tab-pane { display: none; flex: 1; min-height: 0; overflow-y: auto; }
    .tab-pane.active { display: block; }
    #tab-rules.active { display: flex; flex-direction: column; }

    .stats-toggle {
      display: flex;
      align-items: center;
      gap: 6px;
      height: 26px;
      padding: 0 10px;
      background: transparent;
      border: 1px solid var(--border2);
      border-radius: var(--radius);
      color: var(--text2);
      font-size: 11px;
      font-family: var(--font-ui);
      cursor: pointer;
      transition: all 0.12s;
      flex-shrink: 0;
    }

    .stats-toggle:hover { border-color: var(--accent); color: var(--text); }
    .stats-toggle svg { width: 12px; height: 12px; transition: transform 0.18s; stroke: currentColor; fill: none; }
    .stats-wrap.open .stats-toggle svg { transform: rotate(180deg); }

    .stats-bar {
      display: flex;
      align-items: stretch;
      gap: 0;
      padding: 0 18px;
      background: var(--bg2);
      border-bottom: 0 solid var(--border);
      flex-wrap: wrap;
      max-height: 0;
      opacity: 0;
      overflow: hidden;
      transition: max-height 0.18s ease, padding 0.18s ease, opacity 0.15s ease, border-bottom-width 0.18s ease;
    }

    .stats-wrap.open .stats-bar {
      max-height: 220px;
      opacity: 1;
      padding: 10px 18px;
      border-bottom-width: 1px;
    }

    .stat-block {
      display: flex;
      flex-direction: column;
      gap: 5px;
      padding: 0 18px;
      border-right: 1px solid var(--border);
      justify-content: center;
      min-width: 0;
    }

    .stat-block:first-child { padding-left: 0; }
    .stat-block:last-child { border-right: none; }

    .stat-block-title {
      font-size: 9px;
      font-weight: 700;
      letter-spacing: 0.7px;
      text-transform: uppercase;
      color: var(--text3);
      white-space: nowrap;
    }

    .stat-big { display: flex; align-items: baseline; gap: 5px; }

    .stat-big .num {
      font-size: 20px;
      font-weight: 700;
      font-family: var(--font);
      line-height: 1;
    }

    .stat-big .unit { font-size: 11px; color: var(--text3); }

    .stat-bar {
      display: flex;
      height: 6px;
      width: 100%;
      min-width: 150px;
      border-radius: 3px;
      overflow: hidden;
      background: var(--bg4);
    }

    .stat-bar-seg { height: 100%; transition: opacity 0.1s; }
    .stat-bar-seg:hover { opacity: 0.75; }

    .stat-legend { display: flex; gap: 10px; flex-wrap: wrap; }

    .stat-legend-item {
      display: flex;
      align-items: center;
      gap: 4px;
      font-size: 10px;
      color: var(--text2);
      white-space: nowrap;
    }

    .stat-legend-item .ldot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
    .stat-legend-item .lpct { font-family: var(--font); font-weight: 600; color: var(--text); }

    .stat-pct { font-size: 22px; font-weight: 700; font-family: var(--font); line-height: 1; }
    .stat-sub { font-size: 10px; color: var(--text3); white-space: nowrap; }

    /* ── Layout ── */
    .main { display: flex; flex: 1; min-height: 0; }

    .filters-panel {
      width: 250px;
      min-width: 250px;
      background: var(--bg2);
      border-right: 1px solid var(--border);
      overflow-y: auto;
      padding: 12px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .fc-source   { --fc:#58a6ff; --fc-bg:rgba(88,166,255,0.12);  --fc-br:rgba(88,166,255,0.38); }
    .fc-category { --fc:#7ec87e; --fc-bg:rgba(126,200,126,0.12); --fc-br:rgba(126,200,126,0.38); }
    .fc-product  { --fc:#fb923c; --fc-bg:rgba(251,146,60,0.12);  --fc-br:rgba(251,146,60,0.38); }
    .fc-service  { --fc:#f85149; --fc-bg:rgba(248,81,73,0.12);   --fc-br:rgba(248,81,73,0.38); }
    .fc-severity { --fc:#f0783c; --fc-bg:rgba(240,120,60,0.12);  --fc-br:rgba(240,120,60,0.38); }
    .fc-status   { --fc:#3fb950; --fc-bg:rgba(63,185,80,0.12);   --fc-br:rgba(63,185,80,0.38); }
    .fc-verdict  { --fc:#bc8cff; --fc-bg:rgba(188,140,255,0.12); --fc-br:rgba(188,140,255,0.38); }
    .fc-mitre    { --fc:#8f95d6; --fc-bg:rgba(143,149,214,0.12); --fc-br:rgba(143,149,214,0.38); }

    .fc-sev-critical      { --fc:#e05575; --fc-bg:rgba(128,20,50,0.28);  --fc-br:rgba(164,19,60,0.55); }
    .fc-sev-high          { --fc:#f85149; --fc-bg:rgba(248,81,73,0.13); --fc-br:rgba(248,81,73,0.38); }
    .fc-sev-medium        { --fc:#d29922; --fc-bg:rgba(210,153,34,0.13);--fc-br:rgba(210,153,34,0.38); }
    .fc-sev-low           { --fc:#3fb950; --fc-bg:rgba(63,185,80,0.13); --fc-br:rgba(63,185,80,0.38); }
    .fc-sev-informational { --fc:#8b949e; --fc-bg:rgba(139,148,158,0.12);--fc-br:rgba(139,148,158,0.35); }

    .fc-status-stable       { --fc:#3fb950; --fc-bg:rgba(63,185,80,0.13); --fc-br:rgba(63,185,80,0.38); }
    .fc-status-test         { --fc:#d29922; --fc-bg:rgba(210,153,34,0.13);--fc-br:rgba(210,153,34,0.38); }
    .fc-status-experimental { --fc:#58a6ff; --fc-bg:rgba(88,166,255,0.13);--fc-br:rgba(88,166,255,0.38); }
    .fc-status-deprecated   { --fc:#8b949e; --fc-bg:rgba(139,148,158,0.12);--fc-br:rgba(139,148,158,0.35); }

    .fc-verdict-pass { --fc:#3fb950; --fc-bg:rgba(63,185,80,0.13);  --fc-br:rgba(63,185,80,0.38); }
    .fc-verdict-fail { --fc:#f85149; --fc-bg:rgba(248,81,73,0.13); --fc-br:rgba(248,81,73,0.38); }
    .fc-verdict-na   { --fc:#8b949e; --fc-bg:rgba(139,148,158,0.12);--fc-br:rgba(139,148,158,0.35); }

    .filter-supergroup {
      border: 1px solid var(--border);
      border-left: 3px solid var(--group-accent, var(--border2));
      border-radius: var(--radius);
      background: var(--bg3);
      overflow: hidden;
      flex-shrink: 0;
    }

    .filter-supergroup-head {
      display: flex;
      align-items: center;
      gap: 7px;
      padding: 9px 10px;
      cursor: pointer;
      user-select: none;
    }

    .filter-supergroup-head:hover { background: var(--bg4); }

    .filter-supergroup-title {
      flex: 1;
      font-size: 10px;
      font-weight: 600;
      letter-spacing: 0.8px;
      text-transform: uppercase;
      color: var(--text3);
    }

    .filter-supergroup.open > .filter-supergroup-head .filter-supergroup-title { color: var(--group-accent, var(--text2)); }
    .filter-supergroup-head .filter-active-count { background: var(--group-accent, var(--accent2)); }
    .filter-supergroup.open > .filter-supergroup-head .filter-caret { transform: rotate(90deg); }

    .filter-supergroup-body {
      display: none;
      flex-direction: column;
      gap: 6px;
      padding: 0 8px 8px;
    }

    .filter-supergroup.open > .filter-supergroup-body { display: flex; }

    .filter-section {
      border: 1px solid var(--border);
      border-left: 3px solid var(--fc, var(--border2));
      border-radius: var(--radius);
      background: var(--bg3);
      overflow: hidden;
      flex-shrink: 0;
    }

    .filter-section.open { border-color: var(--border2); border-left-color: var(--fc, var(--border2)); }

    .filter-section-head {
      display: flex;
      align-items: center;
      gap: 7px;
      padding: 8px 10px;
      cursor: pointer;
      user-select: none;
      transition: background 0.1s;
    }

    .filter-section-head:hover { background: var(--bg4); }

    .filter-caret {
      width: 9px;
      height: 9px;
      flex-shrink: 0;
      stroke: var(--text3);
      fill: none;
      stroke-width: 2.5;
      transition: transform 0.15s;
    }

    .filter-section.open .filter-caret { transform: rotate(90deg); stroke: var(--fc, var(--accent)); }

    .filter-group-label {
      font-size: 10px;
      font-weight: 600;
      letter-spacing: 0.8px;
      text-transform: uppercase;
      color: var(--text3);
      flex: 1;
    }

    .filter-section.open .filter-group-label { color: var(--fc, var(--text2)); }

    .filter-uniq { font-family: var(--font); font-weight: 400; font-size: 9px; color: var(--text3); letter-spacing: 0; }

    .filter-active-count {
      background: var(--fc, var(--accent2));
      color: #0d1117;
      border-radius: 10px;
      padding: 0 6px;
      font-size: 9px;
      font-weight: 700;
      font-family: var(--font);
      min-width: 16px;
      text-align: center;
    }

    .filter-chips {
      display: flex;
      flex-wrap: wrap;
      gap: 5px;
      padding: 10px;
      border-top: 1px solid var(--border);
      max-height: 240px;
      overflow-y: auto;
    }

    .filter-section:not(.open) .filter-chips { display: none; }

    .chip.zero { opacity: 0.35; }

    .chip {
      padding: 3px 9px;
      border-radius: 20px;
      font-size: 11px;
      font-family: var(--font);
      cursor: pointer;
      border: 1px solid var(--border);
      background: var(--bg3);
      color: var(--text2);
      transition: all 0.1s;
      user-select: none;
      display: flex;
      align-items: center;
      gap: 5px;
    }

    .chip:hover { border-color: var(--border2); color: var(--text); }

    .chip-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--fc, var(--text3)); flex-shrink: 0; }

    .chip.active { background: var(--fc-bg, var(--accent-bg)); border-color: var(--fc-br, var(--accent2)); color: var(--fc, var(--accent)); }
    .chip.active .chip-dot { background: var(--fc, var(--accent)); box-shadow: 0 0 5px var(--fc, var(--accent)); }

    .chip .chip-count { background: var(--bg4); border-radius: 10px; padding: 0 5px; font-size: 10px; color: var(--text3); min-width: 18px; text-align: center; }
    .chip.active .chip-count { background: var(--fc, var(--accent2)); color: #0d1117; font-weight: 700; }

    .clear-filters-btn {
      background: none;
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 6px 12px;
      color: var(--text2);
      font-size: 12px;
      cursor: pointer;
      width: 100%;
      flex-shrink: 0;
      transition: all 0.1s;
      font-family: var(--font-ui);
    }

    .clear-filters-btn:hover { border-color: var(--red); color: var(--red); }

    /* ── Content / search / table ── */
    .content { flex: 1; min-width: 0; min-height: 0; overflow-y: auto; padding: 0 20px 24px; display: flex; flex-direction: column; gap: 0; }

    .active-filter-row {
      display: flex;
      flex-wrap: wrap;
      gap: 5px;
      padding: 8px 20px;
      background: var(--bg);
      border-bottom: 1px solid var(--border);
    }

    .active-filter-row.hidden { display: none; }

    .active-filter-tag {
      display: flex;
      align-items: center;
      gap: 5px;
      padding: 2px 8px;
      background: var(--fc-bg, var(--accent-bg));
      border: 1px solid var(--fc-br, var(--accent2));
      border-radius: 20px;
      font-size: 11px;
      color: var(--fc, var(--accent));
      font-family: var(--font);
    }

    .active-filter-tag button { background: none; border: none; color: var(--fc, var(--accent)); cursor: pointer; padding: 0; font-size: 13px; line-height: 1; opacity: 0.7; }
    .active-filter-tag button:hover { opacity: 1; }

    .search-row { display: flex; align-items: center; gap: 10px; margin-top: 16px; margin-bottom: 14px; }

    .search-input-wrap { position: relative; flex: 1; }

    .search-input-wrap svg {
      position: absolute;
      left: 10px;
      top: 50%;
      transform: translateY(-50%);
      width: 14px;
      height: 14px;
      stroke: var(--text3);
      fill: none;
    }

    .search-input {
      width: 100%;
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 7px 32px 7px 32px;
      font-size: 13px;
      color: var(--text);
      outline: none;
      font-family: var(--font-ui);
      transition: border-color 0.1s;
    }

    .search-input:focus { border-color: var(--accent); }
    .search-input::placeholder { color: var(--text3); }

    .search-clear {
      position: absolute;
      right: 7px;
      top: 50%;
      transform: translateY(-50%);
      display: none;
      align-items: center;
      justify-content: center;
      width: 20px;
      height: 20px;
      padding: 0;
      background: none;
      border: none;
      border-radius: var(--radius);
      color: var(--text3);
      cursor: pointer;
      transition: all 0.12s;
    }

    .search-clear.show { display: flex; }
    .search-clear:hover { color: var(--text); background: var(--bg3); }
    .search-clear svg { position: static; width: 13px; height: 13px; stroke: currentColor; fill: none; }

    .result-count { font-size: 12px; color: var(--text3); white-space: nowrap; font-family: var(--font); }

    .kbd-hint { display: flex; align-items: center; gap: 4px; font-size: 10px; color: var(--text3); white-space: nowrap; }

    .kbd {
      display: inline-block;
      padding: 1px 5px;
      background: var(--bg3);
      border: 1px solid var(--border2);
      border-bottom-width: 2px;
      border-radius: 3px;
      font-family: var(--font);
      font-size: 9px;
      color: var(--text2);
      line-height: 1.4;
    }

    .export-wrap { position: relative; flex-shrink: 0; }

    .export-btn, .code-copy {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 6px 12px;
      background: transparent;
      border: 1px solid var(--border2);
      border-radius: var(--radius);
      color: var(--text2);
      font-size: 12px;
      font-family: var(--font-ui);
      cursor: pointer;
      transition: all 0.1s;
      white-space: nowrap;
    }

    .export-btn:hover, .code-copy:hover { border-color: var(--accent); color: var(--text); }
    .export-btn svg, .code-copy svg { width: 13px; height: 13px; stroke: currentColor; fill: none; }
    .export-btn.ok, .code-copy.ok { border-color: var(--green); color: var(--green); }

    .export-menu {
      display: none;
      position: absolute;
      right: 0;
      top: calc(100% + 5px);
      min-width: 210px;
      background: var(--bg2);
      border: 1px solid var(--border2);
      border-radius: var(--radius-lg);
      box-shadow: 0 8px 28px rgba(0,0,0,0.5);
      z-index: 50;
      overflow: hidden;
    }

    .export-menu.open { display: block; }

    .export-menu-head {
      padding: 8px 12px;
      font-size: 10px;
      letter-spacing: 0.5px;
      text-transform: uppercase;
      color: var(--text3);
      background: var(--bg3);
      border-bottom: 1px solid var(--border);
    }

    .export-menu-item {
      display: flex;
      align-items: baseline;
      gap: 8px;
      padding: 8px 12px;
      cursor: pointer;
      transition: background 0.1s;
      border-bottom: 1px solid var(--border);
    }

    .export-menu-item:last-child { border-bottom: none; }
    .export-menu-item:hover { background: var(--bg3); }
    .export-menu-item .ext { font-family: var(--font); font-size: 11px; font-weight: 700; color: var(--accent); min-width: 34px; }
    .export-menu-item .desc { font-size: 11px; color: var(--text3); }

    .table-wrap {
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      overflow: visible;
    }

    table {
      width: 100%;
      border-collapse: separate;
      border-spacing: 0;
      table-layout: fixed;
    }

    thead th {
      position: sticky;
      top: 0;
      z-index: 3;
      background: #0d1117;
      box-shadow: inset 0 -3px 0 rgba(230,237,243,0.28), 0 5px 12px rgba(0,0,0,0.55);
      color: #ffffff;
      font-weight: 700;
    }

    thead th:first-child { border-top-left-radius: var(--radius-lg); }
    thead th:last-child { border-top-right-radius: var(--radius-lg); }

    th {
      text-align: left;
      padding: 9px 12px;
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.5px;
      text-transform: uppercase;
      color: var(--text3);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      cursor: pointer;
      user-select: none;
      transition: color 0.1s;
      position: relative;
    }

    th:hover { color: var(--text); }
    th.sorted { color: var(--accent); }
    th.sorted::after { content: ' \2193'; font-size: 10px; }
    th.sorted.desc::after { content: ' \2191'; }

    th:nth-child(1) { width: 130px; }
    th:nth-child(2) { width: 280px; }
    th:nth-child(3) { width: 110px; }
    th:nth-child(4) { width: 100px; }
    th:nth-child(5) { width: 90px; }
    th:nth-child(6) { width: 150px; }
    th:nth-child(7) { width: 150px; }
    th:nth-child(8) { width: 90px; }
    th:nth-child(9) { width: 90px; }
    th:nth-child(10) { width: auto; }

    tbody tr { cursor: pointer; transition: background 0.08s; }
    tbody tr:nth-child(even) { background: rgba(255,255,255,0.022); }
    tbody td { border-bottom: 1px solid var(--border); }
    tbody tr:last-child td { border-bottom: none; }

    tbody tr:hover, tbody tr.selected { background: rgba(88,166,255,0.08); }
    tbody tr.selected { box-shadow: inset 0 0 0 1px rgba(88,166,255,0.3); }

    td {
      padding: 9px 12px;
      font-size: 12px;
      color: var(--text2);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      vertical-align: middle;
    }

    td.rule-id {
      position: relative;
      font-family: var(--font);
      font-size: 11px;
      color: var(--text);
      font-weight: 600;
      letter-spacing: 0.2px;
      padding-left: 18px;
    }

    td.rule-id::before {
      content: '';
      position: absolute;
      left: 0;
      top: 0;
      bottom: 0;
      width: 4px;
      border-radius: 0 var(--radius) var(--radius) 0;
      background: var(--rid, var(--border2));
      box-shadow: 7px 0 16px -2px var(--rid-glow, transparent);
      transition: width 0.14s, box-shadow 0.14s;
    }

    tbody tr:hover td.rule-id::before, tbody tr.selected td.rule-id::before {
      width: 8px;
      box-shadow: 12px 0 24px -2px var(--rid-glow, transparent);
    }

    td.title-cell { font-size: 12px; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

    .cell-pills { display: flex; flex-wrap: wrap; gap: 4px; overflow: visible; white-space: normal; }

    .badge {
      display: inline-block;
      padding: 2px 7px;
      border-radius: 20px;
      font-size: 10px;
      font-weight: 600;
      font-family: var(--font);
      letter-spacing: 0.3px;
      white-space: nowrap;
    }

    .badge-source   { background: rgba(88,166,255,0.1);  color: #58a6ff; border: 1px solid rgba(88,166,255,0.25); }
    .badge-category { background: rgba(126,200,126,0.1); color: #7ec87e; border: 1px solid rgba(126,200,126,0.22); }
    .badge-product  { background: rgba(251,146,60,0.1);  color: #fb923c; border: 1px solid rgba(251,146,60,0.25); }
    .badge-service  { background: rgba(248,81,73,0.1);   color: #f85149; border: 1px solid rgba(248,81,73,0.25); }

    .badge-mitre {
      background: rgba(143,149,214,0.14);
      color: #b3b8e8;
      border: 1px solid rgba(143,149,214,0.35);
    }
    a.badge-mitre:hover { text-decoration: none; filter: brightness(1.25); }

    .sev-critical      { background: rgba(128,20,50,0.28);  color: #e05575; border: 1px solid rgba(164,19,60,0.55); }
    .sev-high          { background: rgba(248,81,73,0.13); color: #f85149; border: 1px solid rgba(248,81,73,0.3); }
    .sev-medium        { background: var(--amber-bg);      color: var(--amber); border: 1px solid rgba(210,153,34,0.25); }
    .sev-low           { background: var(--green-bg);      color: var(--green); border: 1px solid rgba(63,185,80,0.25); }
    .sev-informational { background: rgba(139,148,158,0.12); color: #8b949e; border: 1px solid var(--border); }

    .status-stable       { background: var(--green-bg); color: var(--green); border: 1px solid rgba(63,185,80,0.25); }
    .status-test         { background: var(--amber-bg); color: var(--amber); border: 1px solid rgba(210,153,34,0.25); }
    .status-experimental { background: var(--accent-bg); color: var(--accent); border: 1px solid rgba(88,166,255,0.25); }
    .status-deprecated   { background: rgba(139,148,158,0.1); color: var(--text3); border: 1px solid var(--border); }

    .verdict-pass { background: var(--green-bg); color: var(--green); border: 1px solid rgba(63,185,80,0.25); }
    .verdict-fail { background: rgba(248,81,73,0.13); color: #f85149; border: 1px solid rgba(248,81,73,0.3); }
    .verdict-na   { background: rgba(139,148,158,0.12); color: #8b949e; border: 1px solid var(--border); }

    .no-results { padding: 40px; text-align: center; color: var(--text3); font-size: 13px; }

    /* ── Resizable columns ── */
    .col-resizer { position: absolute; right: 0; top: 0; bottom: 0; width: 8px; cursor: col-resize; user-select: none; z-index: 10; display: flex; align-items: center; justify-content: center; }
    .col-resizer::after { content: ''; display: block; width: 1px; height: 60%; background: var(--border2); border-radius: 1px; transition: background 0.1s; }
    .col-resizer:hover::after, .col-resizer.dragging::after { background: var(--accent); }

    /* ── Drawer ── */
    .drawer-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 200; display: none; }
    .drawer-overlay.open { display: block; }

    .drawer {
      position: fixed;
      right: 0;
      top: 0;
      bottom: 0;
      width: 560px;
      max-width: 92vw;
      background: var(--bg2);
      border-left: 1px solid var(--border);
      z-index: 201;
      overflow-y: auto;
      transform: translateX(100%);
      transition: transform 0.2s ease;
    }

    .drawer.open { transform: translateX(0); }

    .drawer-header {
      padding: 18px 20px 14px;
      border-bottom: 1px solid var(--border);
      position: sticky;
      top: 0;
      background: var(--bg2);
      z-index: 1;
    }

    .drawer-header-top { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; margin-bottom: 10px; }
    .drawer-rule-id { font-family: var(--font); font-size: 12px; color: var(--accent); margin-bottom: 4px; }
    .drawer-rule-id a { color: inherit; }
    .drawer-title { font-size: 14px; font-weight: 600; color: var(--text); line-height: 1.4; }

    .drawer-close {
      background: none;
      border: 1px solid var(--border);
      border-radius: var(--radius);
      width: 28px;
      height: 28px;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      color: var(--text2);
      flex-shrink: 0;
      transition: all 0.1s;
    }

    .drawer-close:hover { border-color: var(--border2); color: var(--text); }
    .drawer-close svg { width: 14px; height: 14px; stroke: currentColor; fill: none; }

    .drawer-badges { display: flex; flex-wrap: wrap; gap: 5px; }
    .drawer-body { padding: 18px 20px; display: flex; flex-direction: column; gap: 18px; }

    .drawer-section-label { font-size: 10px; font-weight: 600; letter-spacing: 0.8px; text-transform: uppercase; color: var(--text3); margin-bottom: 8px; }
    .drawer-desc { font-size: 13px; color: var(--text2); line-height: 1.6; }

    .meta-grid { display: grid; grid-template-columns: 130px 1fr; gap: 7px 12px; }
    .meta-key { font-size: 12px; color: var(--text3); }
    .meta-val { font-size: 12px; color: var(--text); font-family: var(--font); word-break: break-word; }

    .mitre-pills { display: flex; flex-wrap: wrap; gap: 5px; }

    .mitre-pill {
      padding: 3px 8px;
      background: rgba(143,149,214,0.16);
      border: 1px solid rgba(143,149,214,0.42);
      border-radius: var(--radius);
      font-size: 11px;
      font-family: var(--font);
      font-weight: 600;
      color: #b3b8e8;
    }

    a.mitre-pill:hover { filter: brightness(1.25); text-decoration: none; }

    .drawer-list { display: flex; flex-direction: column; gap: 6px; }

    .drawer-list-item {
      font-size: 12px;
      color: var(--text2);
      background: var(--bg3);
      border: 1px solid var(--border);
      border-left: 2px solid var(--purple);
      border-radius: var(--radius);
      padding: 6px 10px;
      line-height: 1.5;
      word-break: break-word;
    }

    .drawer-list-item.fp { border-left-color: var(--amber); }
    .drawer-list-item.atomic { border-left-color: #7f9cb5; display: flex; justify-content: space-between; gap: 8px; align-items: center; }
    .drawer-list-item a { color: var(--accent); }

    .drawer-cta {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 12px;
      background: transparent;
      border: 1px solid var(--accent2);
      border-radius: var(--radius);
      color: var(--accent);
      font-size: 12px;
      font-family: var(--font-ui);
      text-decoration: none;
      transition: all 0.1s;
    }

    .drawer-cta:hover { background: var(--accent-bg); text-decoration: none; }
    .drawer-cta svg { width: 12px; height: 12px; stroke: currentColor; fill: none; }

    .code-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }

    .rule-body-pre {
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 12px 14px;
      font-family: var(--font);
      font-size: 11px;
      line-height: 1.65;
      color: #a5b4d4;
      overflow-x: auto;
      white-space: pre;
      tab-size: 2;
    }

    /* ── Rule body syntax highlight (Sigma YAML / SPL) ── */
    .t-kw  { color: #ff7b72; font-weight: 600; }  /* keywords: search, stats, detection… */
    .t-op  { color: #8b949e; }                    /* operators/punctuation: =, |, - , : */
    .t-fld { color: #79c0ff; }                     /* field/key names */
    .t-val { color: #ffffff; }                     /* literal values, strings, numbers */
    .t-fn  { color: #d2a8ff; }                     /* functions: count, sum… */
    .t-com { color: #6e7681; font-style: italic; } /* comments */
    .t-id  { color: #c9d1d9; }                     /* plain identifiers */

    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--text3); }

    /* MITRE Navigator */
    .nav-wrap { background:var(--bg2); border:1px solid var(--border); border-radius:6px; padding:16px; margin:16px 20px; }
    .nav-legend { display:flex; gap:16px; margin-bottom:12px; font-size:12px; align-items:center; flex-wrap:wrap; }
    .nav-legend-item { display:flex; align-items:center; gap:5px; }
    .nav-legend-dot { width:12px; height:12px; border-radius:2px; flex-shrink:0; }
    .nav-import { margin-left:auto; font-size:12px; }
    .att-matrix { display:flex; gap:2px; overflow-x:auto; padding-bottom:4px; scrollbar-width:none; }
    .att-matrix::-webkit-scrollbar { display:none; }
    .tc-col { flex:0 0 175px; display:flex; flex-direction:column; gap:1px; }
    .tc-hdr { background:#FFAA00; color:#111; font-size:12px; font-weight:700; padding:6px 5px; text-align:center; border-radius:3px 3px 0 0; min-height:44px; display:flex; flex-direction:column; align-items:center; justify-content:center; gap:2px; }
    .tc-count { font-size:10px; font-weight:400; opacity:.75; }
    .tc-hdr a { color:#111; text-decoration:none; }
    .tc-hdr a:hover { text-decoration:underline; }
    .tc { font-size:12px; padding:5px 6px; border-radius:2px; cursor:default; display:flex; flex-direction:column; min-height:40px; gap:1px; position:relative; }
    .tc.uncov { background:#1c2128; color:#484f58; }
    .tc.uncov.has-cov { background:rgba(255,170,0,.13); color:#545f6e; }
    .tc.pass  { background:#1a4731; color:#aff3c5; }
    .tc.fail  { background:#67060c; color:#ffc1c1; }
    .tc.nv    { background:#2d333b; color:#adbac7; border-left:2px solid rgba(255,170,0,.35); }
    .tc.sub   { min-height:28px; padding-left:12px; }
    .tc[data-rules] { cursor:pointer; }
    .tc[data-rules]:hover { filter:brightness(1.3); }
    .tc.highlighted { box-shadow:inset 0 0 0 2px #FFAA00; filter:brightness(1.15); }
    .tc.expanded { box-shadow:inset 0 0 0 1.5px rgba(255,170,0,.55); }
    .tc.expanded.highlighted { box-shadow:inset 0 0 0 2px #FFAA00; }
    .ti { font-weight:700; font-size:12px; color:inherit; text-decoration:none; }
    .ti:hover { text-decoration:underline; }
    .tn { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; flex:1; }
    .tc.sub .tn { white-space:normal; overflow:visible; text-overflow:clip; }
    .tc-row1 { display:flex; justify-content:space-between; align-items:center; gap:2px; }
    .tc-foot { display:flex; justify-content:space-between; align-items:center; margin-top:2px; min-height:10px; }
    .tc-expand { background:none; border:none; color:inherit; cursor:pointer; font-size:14px; padding:2px 3px; opacity:.65; line-height:1; flex-shrink:0; }
    .tc-expand:hover { opacity:1; }
    .tc-detail { position:absolute; right:4px; top:50%; transform:translateY(-50%); background:none; border:none; color:inherit; cursor:pointer; font-size:14px; padding:2px 4px; opacity:0; line-height:1; z-index:1; }
    .tc[data-rules]:hover .tc-detail { opacity:.85; }
    .tc-detail:hover { opacity:1 !important; color:#FFAA00; }
    .sub-badge { font-size:9px; opacity:.55; }
    .sub-badge-cov { font-size:9px; color:#FFAA00; font-weight:700; }
    .sub-group { border:1.5px solid rgba(255,170,0,.5); border-radius:3px; display:flex; flex-direction:column; gap:1px; padding:1px; margin-top:1px; }
    .tc.tc-hidden { display:none !important; }
    .nav-legend-item[data-filter] { cursor:pointer; border-radius:4px; padding:2px 6px; transition:background .15s; }
    .nav-legend-item[data-filter]:hover { background:rgba(255,170,0,.08); }
    .nav-legend-item.filter-active { background:rgba(255,170,0,.18); outline:1px solid rgba(255,170,0,.55); }
    .nav-legend-item[data-filter] .nav-legend-dot { position:relative; }
    .nav-legend-item.filter-active .nav-legend-dot::after { content:'✓'; position:absolute; inset:0; display:flex; align-items:center; justify-content:center; color:#fff; font-size:9px; font-weight:900; }
    #expand-all-btn { background:none; border:1px solid var(--border); color:var(--text2); border-radius:5px; padding:3px 10px; font-size:12px; cursor:pointer; white-space:nowrap; }
    #expand-all-btn:hover { color:var(--text); border-color:#FFAA00; }
    /* Detail panel */
    #detail-panel { position:fixed; right:0; top:0; bottom:0; width:300px; background:#161b22; border-left:1px solid #30363d; z-index:10000; display:none; flex-direction:column; box-shadow:-4px 0 24px rgba(0,0,0,.6); }
    #detail-panel.open { display:flex; }
    #detail-header { display:flex; justify-content:space-between; align-items:flex-start; padding:14px 16px 10px; border-bottom:1px solid #30363d; flex-shrink:0; }
    #detail-title { font-weight:700; font-size:13px; color:#e6edf3; }
    #detail-tid { color:#8b949e; font-size:10px; margin-top:2px; }
    #detail-close { background:none; border:none; color:#8b949e; font-size:20px; cursor:pointer; padding:0; line-height:1; }
    #detail-close:hover { color:#e6edf3; }
    #detail-body { padding:12px 16px; overflow-y:auto; flex:1; }
    .detail-rule { display:flex; align-items:center; gap:6px; margin:6px 0; text-decoration:none; color:#58a6ff; font-size:12px; line-height:1.4; }
    .detail-rule:hover { text-decoration:underline; }
    .detail-noverd { display:flex; align-items:center; gap:6px; margin:6px 0; font-size:12px; color:#8b949e; }
    .detail-vbadge { display:inline-block; padding:1px 7px; border-radius:8px; font-size:10px; font-weight:600; flex-shrink:0; }
    .detail-vbadge.PASS { background:#2EA44F; color:#fff; }
    .detail-vbadge.FAIL { background:#CF222E; color:#fff; }
    .detail-vbadge.NA { background:#6E7681; color:#fff; }
    #att-tip {
      display:none; position:fixed; z-index:9999; pointer-events:none;
      background:#161b22; border:1px solid #30363d; border-radius:8px;
      padding:10px 14px; max-width:340px; font-size:12px; color:#e6edf3;
      box-shadow:0 8px 24px rgba(0,0,0,.5);
    }
    .tip-head { font-weight:700; font-size:13px; margin-bottom:6px; }
    .tip-rule { display:flex; align-items:center; gap:6px; margin:3px 0; text-decoration:none; color:#58a6ff; font-size:11px; }
    .tip-rule:hover { text-decoration:underline; }
    .tip-vbadge { display:inline-block; padding:1px 7px; border-radius:8px; font-size:10px; font-weight:600; flex-shrink:0; }
    .tip-vbadge.PASS { background:#2EA44F; color:#fff; }
    .tip-vbadge.FAIL { background:#CF222E; color:#fff; }
    .tip-vbadge.NA   { background:#6E7681; color:#fff; }

  </style>
</head>
<body>
  <div class="stats-wrap" id="stats-wrap">
    <div class="stats-strip">
      <div class="strip-brand">
        <a class="strip-title" href="https://github.com/@@REPO@@" target="_blank">Detection Engineering</a>
        <span class="strip-sep"></span>
        <span class="strip-total" id="strip-total"></span>
        <span class="strip-sep"></span>
        <span class="strip-total" title="Last generated">Generated @@TS@@ UTC</span>
      </div>
      <div class="tab-bar">
        <button class="tab-btn active" data-tab="rules">Rules</button>
        <button class="tab-btn" data-tab="navigator">MITRE Navigator</button>
      </div>
      <button class="stats-toggle" id="stats-toggle" onclick="toggleStats()" title="Show/hide stats">
        <span>Stats</span>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"/></svg>
      </button>
    </div>
    <div class="stats-bar" id="stats-bar"></div>
  </div>

  <div id="tab-rules" class="tab-pane active">
    <div class="active-filter-row hidden" id="active-filter-row"></div>
    <div class="main">
      <div class="filters-panel" id="filters-panel"></div>
      <div class="content">
        <div class="search-row">
          <div class="search-input-wrap">
            <svg viewBox="0 0 24 24" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input class="search-input" id="search-input" type="text" placeholder="Search title, description, ID, product…" oninput="onSearchInput()">
            <button class="search-clear" id="search-clear" onclick="clearSearch()" title="Clear search" aria-label="Clear search">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
          </div>
          <span class="result-count" id="result-count"></span>
          <span class="kbd-hint">
            <span class="kbd">&uarr;&darr;</span> move
            <span class="kbd">&crarr;</span> open
          </span>
          <div class="export-wrap">
            <button class="export-btn" id="link-btn" onclick="copyDeepLink()" title="Copy a link to the current filtered view">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/>
                <path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/>
              </svg>
              <span class="btn-label">Link</span>
            </button>
          </div>
          <div class="export-wrap">
            <button class="export-btn" id="export-btn" onclick="toggleExportMenu(event)">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
                <polyline points="7 10 12 15 17 10"/>
                <line x1="12" y1="15" x2="12" y2="3"/>
              </svg>
              Export
            </button>
            <div class="export-menu" id="export-menu">
              <div class="export-menu-head">Current view (<span id="export-count">0</span> rules)</div>
              <div class="export-menu-item" onclick="exportView('csv')"><span class="ext">CSV</span><span class="desc">Spreadsheet</span></div>
              <div class="export-menu-item" onclick="exportView('json')"><span class="ext">JSON</span><span class="desc">Full metadata</span></div>
              <div class="export-menu-item" onclick="exportView('md')"><span class="ext">MD</span><span class="desc">Markdown table</span></div>
            </div>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th data-col="id" onclick="sortBy('id')">Rule ID</th>
                <th data-col="title" onclick="sortBy('title')">Title</th>
                <th data-col="category" onclick="sortBy('category')">Category</th>
                <th data-col="product" onclick="sortBy('product')">Product</th>
                <th data-col="service" onclick="sortBy('service')">Service</th>
                <th data-col="tactics" onclick="sortBy('tactics')">Tactic</th>
                <th data-col="techniques" onclick="sortBy('techniques')">Technique</th>
                <th data-col="severity" onclick="sortBy('severity')">Severity</th>
                <th data-col="status" onclick="sortBy('status')">Status</th>
                <th data-col="verdict" onclick="sortBy('verdict')">Verdict</th>
              </tr>
            </thead>
            <tbody id="table-body"></tbody>
          </table>
          <div id="no-results" class="no-results" style="display:none;">No rules match the current filters.</div>
        </div>
      </div>
    </div>
  </div>

  <div id="tab-navigator" class="tab-pane">
    <div class="nav-wrap">
      <div class="nav-legend">
        <div class="nav-legend-item" data-filter="pass"><div class="nav-legend-dot" style="background:#1a4731;border:1px solid #2EA44F"></div> PASS</div>
        <div class="nav-legend-item" data-filter="nv"><div class="nav-legend-dot" style="background:#9f9f9f"></div> Not Verified</div>
        <div class="nav-legend-item" data-filter="fail"><div class="nav-legend-dot" style="background:#67060c;border:1px solid #CF222E"></div> FAIL</div>
        <div class="nav-legend-item" data-filter="uncov"><div class="nav-legend-dot" style="background:#1c2128;border:1px solid #30363d"></div> Not covered</div>
        <button id="expand-all-btn">&#9660; Expand All</button>
        <div class="nav-import"><a href="@@LAYER_URL@@" target="_blank">&#8659; Download Navigator layer (.json)</a></div>
      </div>
      @@MATRIX_HTML@@
    </div>
  </div>

  <div class="drawer-overlay" id="drawer-overlay" onclick="closeDrawer()"></div>
  <div class="drawer" id="drawer">
    <div class="drawer-header">
      <div class="drawer-header-top">
        <div>
          <div class="drawer-rule-id" id="d-rule-id"></div>
          <div class="drawer-title" id="d-title"></div>
        </div>
        <button class="drawer-close" onclick="closeDrawer()">
          <svg viewBox="0 0 24 24" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </div>
      <div class="drawer-badges" id="d-badges"></div>
    </div>
    <div class="drawer-body" id="d-body"></div>
  </div>

  <div id="detail-panel">
    <div id="detail-header">
      <div><div id="detail-title"></div><div id="detail-tid"></div></div>
      <button id="detail-close">&#215;</button>
    </div>
    <div id="detail-body"></div>
  </div>
  <div id="att-tip"></div>

  <script>
  const RULES = @@RULES_JSON@@;
  const TACTIC_IDS = @@TACTIC_IDS_JSON@@;
  const TOTAL_RULES = @@TOTAL@@;
  const PASS_COUNT = @@PASSED@@;
  const FAIL_COUNT = @@FAILED@@;
  const NOTVER_COUNT = @@NOT_VER@@;
  const PASS_RATE = @@PASS_RATE@@;
  const MITRE_COVERED = @@MITRE_COVERED@@;
  const MITRE_TOTAL = @@MITRE_TOTAL@@;
  const MITRE_PCT = @@MITRE_PCT@@;

  const SEV_HEX = { critical: '#a4133c', high: '#f85149', medium: '#d29922', low: '#3fb950', informational: '#8b949e' };
  const STATUS_HEX = { stable: '#3fb950', test: '#d29922', experimental: '#58a6ff', deprecated: '#8b949e' };

  const FILTER_FIELDS = [
    { key: 'source',     label: 'Source' },
    { key: 'category',   label: 'Product Category' },
    { key: 'product',    label: 'Product' },
    { key: 'service',    label: 'Service' },
    { key: 'severity',   label: 'Severity' },
    { key: 'status',     label: 'Status' },
    { key: 'verdict',    label: 'Verdict' },
    { key: 'tactics',    label: 'Tactic',    group: 'MITRE ATT&CK' },
    { key: 'techniques', label: 'Technique', group: 'MITRE ATT&CK' },
  ];

  const GROUP_ACCENT = { 'MITRE ATT&CK': '#8f95d6' };

  const FIELD_FC = {
    source: 'fc-source',
    category: 'fc-category',
    product: 'fc-product',
    service: 'fc-service',
    severity: 'fc-severity',
    status: 'fc-status',
    verdict: 'fc-verdict',
    tactics: 'fc-mitre',
    techniques: 'fc-mitre',
  };

  let activeFilters = {};
  let sortCol = 'id';
  let sortAsc = true;
  let currentView = [];
  let selectedPos = -1;
  let currentTab = 'rules';
  let currentRuleBody = '';
  const openSections = new Set();
  const openGroups = new Set();

  function escHtml(s) {
    return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function jsStr(v) {
    return JSON.stringify(v).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function cap(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1) : s; }

  function normKey(s) { return (s || '').toLowerCase().replace(/[^a-z0-9]+/g, ''); }

  function emptyCell() { return '<span style="color:var(--text3)">—</span>'; }

  function tacticUrl(name) {
    const id = TACTIC_IDS[name];
    return id ? `https://attack.mitre.org/tactics/${id}/` : 'https://attack.mitre.org/';
  }

  function techniqueUrl(tech) {
    return 'https://attack.mitre.org/techniques/' + tech.split('.').join('/') + '/';
  }

  // ── Filters ──────────────────────────────────────────────────────────────

  function getFieldVal(rule, key) {
    if (key === 'tactics' || key === 'techniques') {
      return (rule[key] && rule[key].length) ? rule[key] : ['—'];
    }
    const v = rule[key];
    return (v === undefined || v === null || v === '') ? '—' : v;
  }

  function allVals(key) {
    const vals = new Set();
    RULES.forEach(r => {
      const v = getFieldVal(r, key);
      if (Array.isArray(v)) v.forEach(x => x && vals.add(x));
      else if (v) vals.add(v);
    });
    return [...vals].filter(v => v !== '—').sort();
  }

  function matchesFiltersExcept(rule, exceptKey) {
    return Object.entries(activeFilters).every(([key, vals]) => {
      if (key === exceptKey || !vals.length) return true;
      const v = getFieldVal(rule, key);
      if (Array.isArray(v)) return vals.some(fv => v.includes(fv));
      return vals.includes(v);
    });
  }

  function matchesFilters(rule) {
    return Object.entries(activeFilters).every(([key, vals]) => {
      if (!vals.length) return true;
      const v = getFieldVal(rule, key);
      if (Array.isArray(v)) return vals.some(fv => v.includes(fv));
      return vals.includes(v);
    });
  }

  function countFor(key, val) {
    const q = document.getElementById('search-input')?.value || '';
    return RULES.filter(r => {
      if (!matchesFiltersExcept(r, key)) return false;
      if (!matchesSearch(r, q)) return false;
      const v = getFieldVal(r, key);
      return Array.isArray(v) ? v.includes(val) : v === val;
    }).length;
  }

  function chipFc(key, val) {
    if (key === 'severity') return 'fc-sev-' + normKey(val);
    if (key === 'status') return 'fc-status-' + normKey(val);
    if (key === 'verdict') return 'fc-verdict-' + normKey(val);
    return FIELD_FC[key] || '';
  }

  // Word-start match: the term must begin at a word boundary in the haystack,
  // not just appear anywhere inside it — so "sec" matches "Security" but not
  // "WMIExec", cutting down noisy substring hits while typing.
  function wordStartMatch(haystack, term) {
    if (!term) return true;
    let from = 0;
    while (true) {
      const idx = haystack.indexOf(term, from);
      if (idx < 0) return false;
      const before = idx === 0 ? '' : haystack[idx - 1];
      if (!before || !/[\p{L}\p{N}]/u.test(before)) return true;
      from = idx + 1;
    }
  }

  function matchesSearch(rule, q) {
    if (!q || !q.trim()) return true;
    const haystack = [
      rule.id, rule.title, rule.description, rule.source,
      rule.category, rule.product, rule.service, rule.eventType,
      ...(rule.tactics || []), ...(rule.techniques || []),
      rule.severity, rule.status, rule.verdict, rule.author,
    ].join(' ').toLowerCase();
    return q.trim().toLowerCase().split(/\s+/).every(w => wordStartMatch(haystack, w));
  }

  function toggleSection(key) {
    if (openSections.has(key)) openSections.delete(key);
    else openSections.add(key);
    renderFilters();
  }

  function toggleGroup(name) {
    if (openGroups.has(name)) openGroups.delete(name);
    else openGroups.add(name);
    renderFilters();
  }

  function toggleFilter(key, val) {
    if (!activeFilters[key]) activeFilters[key] = [];
    const idx = activeFilters[key].indexOf(val);
    if (idx >= 0) activeFilters[key].splice(idx, 1);
    else activeFilters[key].push(val);
    if (!activeFilters[key].length) delete activeFilters[key];
    renderFilters();
    renderActiveFilterRow();
    renderTable();
    updateHash();
  }

  function clearFilters() {
    activeFilters = {};
    renderFilters();
    renderActiveFilterRow();
    renderTable();
    updateHash();
  }

  let hashDebounce = null;
  function onSearchInput() {
    const input = document.getElementById('search-input');
    document.getElementById('search-clear')?.classList.toggle('show', !!input.value);
    renderFilters();
    renderTable();
    clearTimeout(hashDebounce);
    hashDebounce = setTimeout(updateHash, 350);
  }

  function clearSearch() {
    const input = document.getElementById('search-input');
    input.value = '';
    document.getElementById('search-clear')?.classList.remove('show');
    renderFilters();
    renderTable();
    updateHash();
    input.focus();
  }

  function renderFilters() {
    const panel = document.getElementById('filters-panel');
    const groupHasVals = {};
    const groupActive = {};
    FILTER_FIELDS.forEach(({ key, group }) => {
      if (!group) return;
      if (allVals(key).length) groupHasVals[group] = true;
      groupActive[group] = (groupActive[group] || 0) + (activeFilters[key]?.length || 0);
    });

    let html = '';
    let openGroup = null;
    let groupVisible = true;

    FILTER_FIELDS.forEach(({ key, label, group }) => {
      const vals = allVals(key);
      const effectiveGroup = (group && groupHasVals[group]) ? group : null;

      if (effectiveGroup !== openGroup) {
        if (openGroup !== null) html += '</div></div>';
        if (effectiveGroup) {
          const accent = GROUP_ACCENT[effectiveGroup] || 'var(--border2)';
          const expanded = openGroups.has(effectiveGroup);
          const act = groupActive[effectiveGroup] || 0;
          html += `<div class="filter-supergroup ${expanded ? 'open' : ''}" style="--group-accent:${accent}">
            <div class="filter-supergroup-head" onclick="toggleGroup('${effectiveGroup}')">
              <svg class="filter-caret" viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg>
              <span class="filter-supergroup-title">${escHtml(effectiveGroup)}</span>
              ${act ? `<span class="filter-active-count">${act}</span>` : ''}
            </div>
            <div class="filter-supergroup-body">`;
          groupVisible = expanded;
        }
        openGroup = effectiveGroup;
      }

      if (!vals.length) return;
      if (effectiveGroup && !groupVisible) return;

      const activeCount = (activeFilters[key] || []).length;
      const isOpen = openSections.has(key);
      const sectionFc = FIELD_FC[key] || '';

      const chips = vals.map(v => {
        const active = (activeFilters[key] || []).includes(v);
        const n = countFor(key, v);
        const zero = (n === 0 && !active) ? ' zero' : '';
        const fc = chipFc(key, v);
        return `<div class="chip ${fc}${active ? ' active' : ''}${zero}" onclick="toggleFilter('${key}', ${jsStr(v)})">
          <span class="chip-dot"></span>${escHtml(v)}<span class="chip-count">${n}</span>
        </div>`;
      }).join('');

      html += `<div class="filter-section ${sectionFc}${isOpen ? ' open' : ''}">
        <div class="filter-section-head" onclick="toggleSection('${key}')">
          <svg class="filter-caret" viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg>
          <span class="filter-group-label">${escHtml(label)} <span class="filter-uniq">(${vals.length})</span></span>
          ${activeCount ? `<span class="filter-active-count">${activeCount}</span>` : ''}
        </div>
        <div class="filter-chips">${chips}</div>
      </div>`;
    });

    if (openGroup !== null) html += '</div></div>';
    panel.innerHTML = html + '<button class="clear-filters-btn" onclick="clearFilters()">Clear filters</button>';
  }

  function renderActiveFilterRow() {
    const row = document.getElementById('active-filter-row');
    const tags = Object.entries(activeFilters).flatMap(([key, vals]) =>
      vals.map(v => `<span class="active-filter-tag ${chipFc(key, v)}">
        ${escHtml(FILTER_FIELDS.find(f => f.key === key)?.label || key)}: <strong>${escHtml(v)}</strong>
        <button onclick="toggleFilter('${key}', ${jsStr(v)})">&times;</button>
      </span>`)
    );
    row.innerHTML = tags.join('');
    row.classList.toggle('hidden', !tags.length);
  }

  // ── Stats bar ────────────────────────────────────────────────────────────

  function pct(n, total) { return total ? Math.round(n / total * 100) : 0; }

  function distBlock(title, segments, total) {
    const present = segments.filter(s => s.n > 0);
    if (!present.length) return '';
    const bar = present.map(s =>
      `<div class="stat-bar-seg" style="width:${(s.n / total) * 100}%;background:${s.color}" title="${escHtml(s.label)}: ${s.n} (${pct(s.n, total)}%)"></div>`
    ).join('');
    const legend = present.map(s =>
      `<span class="stat-legend-item"><span class="ldot" style="background:${s.color}"></span>${escHtml(s.label)} <span class="lpct">${pct(s.n, total)}%</span></span>`
    ).join('');
    return `<div class="stat-block" style="flex:1;min-width:200px">
      <div class="stat-block-title">${escHtml(title)}</div>
      <div class="stat-bar">${bar}</div>
      <div class="stat-legend">${legend}</div>
    </div>`;
  }

  function pctBlock(title, value, sub) {
    return `<div class="stat-block">
      <div class="stat-block-title">${escHtml(title)}</div>
      <div class="stat-pct">${escHtml(value)}</div>
      <div class="stat-sub">${escHtml(sub)}</div>
    </div>`;
  }

  function renderStats() {
    const total = RULES.length;
    const stripTotal = document.getElementById('strip-total');
    if (stripTotal) stripTotal.innerHTML = `<strong>${total}</strong> rule${total === 1 ? '' : 's'}`;
    if (!total) { document.getElementById('stats-bar').innerHTML = ''; return; }

    const sourceCount = {};
    RULES.forEach(r => { sourceCount[r.source] = (sourceCount[r.source] || 0) + 1; });
    const sourceSegs = [
      { label: 'Sigma', n: sourceCount['Sigma'] || 0, color: '#58a6ff' },
      { label: 'Native SPL', n: sourceCount['Native SPL'] || 0, color: '#fb923c' },
    ];

    const sevOrder = ['critical', 'high', 'medium', 'low', 'informational'];
    const sevCount = {};
    RULES.forEach(r => { const k = (r.severity || '').toLowerCase(); if (k) sevCount[k] = (sevCount[k] || 0) + 1; });
    const sevSegs = sevOrder.filter(k => sevCount[k]).map(k => ({ label: cap(k), n: sevCount[k], color: SEV_HEX[k] || '#4d5866' }));

    const statusCount = {};
    RULES.forEach(r => { const k = (r.status || '').toLowerCase(); if (k) statusCount[k] = (statusCount[k] || 0) + 1; });
    const statusSegs = Object.entries(statusCount)
      .sort((a, b) => b[1] - a[1])
      .map(([k, n]) => ({ label: cap(k), n, color: STATUS_HEX[k] || '#4d5866' }));

    const verdictSegs = [
      { label: 'Pass', n: PASS_COUNT, color: '#3fb950' },
      { label: 'Fail', n: FAIL_COUNT, color: '#f85149' },
      { label: 'Not Verified', n: NOTVER_COUNT, color: '#8b949e' },
    ];

    document.getElementById('stats-bar').innerHTML =
      distBlock('Rule Type', sourceSegs, total) +
      distBlock('Severity', sevSegs, total) +
      distBlock('Status', statusSegs, total) +
      distBlock('Verification', verdictSegs, total) +
      pctBlock('Pass Rate', PASS_RATE + '%', `${PASS_COUNT} / ${PASS_COUNT + FAIL_COUNT + NOTVER_COUNT} verified`) +
      pctBlock('MITRE Coverage', MITRE_PCT + '%', `${MITRE_COVERED} / ${MITRE_TOTAL} techniques`);
  }

  function toggleStats() {
    document.getElementById('stats-wrap')?.classList.toggle('open');
  }

  // ── Badges ───────────────────────────────────────────────────────────────

  function sevBadge(r) {
    if (!r.severity) return emptyCell();
    return `<span class="badge sev-${normKey(r.severity)}">${escHtml(cap(r.severity))}</span>`;
  }

  function statusBadge(r) {
    if (!r.status) return emptyCell();
    return `<span class="badge status-${normKey(r.status)}">${escHtml(cap(r.status))}</span>`;
  }

  function verdictBadge(r) {
    const v = r.verdict || 'N/A';
    const badge = `<span class="badge verdict-${normKey(v)}">${escHtml(v)}</span>`;
    if (r.runUrl) return `<a href="${escHtml(r.runUrl)}" target="_blank" title="View Actions run" onclick="event.stopPropagation()">${badge}</a>`;
    return badge;
  }

  function mitrePills(list, kind) {
    if (!list || !list.length) return '';
    return list.map(v => {
      const url = kind === 'tactic' ? tacticUrl(v) : techniqueUrl(v);
      return `<a class="badge badge-mitre" href="${escHtml(url)}" target="_blank" onclick="event.stopPropagation()">${escHtml(v)}</a>`;
    }).join('');
  }

  // ── Table ────────────────────────────────────────────────────────────────

  function sortBy(col) {
    if (sortCol === col) sortAsc = !sortAsc;
    else { sortCol = col; sortAsc = true; }
    renderTable();
    updateHash();
  }

  function renderTable() {
    const q = document.getElementById('search-input').value;
    let filtered = RULES.filter(r => matchesFilters(r) && matchesSearch(r, q));

    filtered.sort((a, b) => {
      let va, vb;
      if (sortCol === 'tactics' || sortCol === 'techniques') {
        va = (a[sortCol] && a[sortCol][0]) || '';
        vb = (b[sortCol] && b[sortCol][0]) || '';
      } else {
        va = String(a[sortCol] ?? '');
        vb = String(b[sortCol] ?? '');
      }
      const cmp = va.localeCompare(vb, undefined, { numeric: true, sensitivity: 'base' });
      return sortAsc ? cmp : -cmp;
    });

    currentView = filtered;
    const ec = document.getElementById('export-count');
    if (ec) ec.textContent = filtered.length;

    document.querySelectorAll('th[data-col]').forEach(th => {
      const isSorted = th.dataset.col === sortCol;
      th.classList.toggle('sorted', isSorted);
      th.classList.toggle('desc', isSorted && !sortAsc);
    });

    const tbody = document.getElementById('table-body');
    const noRes = document.getElementById('no-results');

    if (!filtered.length) {
      tbody.innerHTML = '';
      noRes.style.display = '';
      document.getElementById('result-count').textContent = '0 results';
      return;
    }

    noRes.style.display = 'none';
    document.getElementById('result-count').textContent = `${filtered.length} / ${RULES.length}`;

    tbody.innerHTML = filtered.map(r => {
      const globalIdx = RULES.indexOf(r);
      const ridColor = SEV_HEX[normKey(r.severity)] || '#444c56';
      const idContent = r.fileUrl
        ? `<a href="${escHtml(r.fileUrl)}" target="_blank" onclick="event.stopPropagation()">${escHtml(r.id)}</a>`
        : escHtml(r.id);
      return `<tr data-idx="${globalIdx}">
        <td class="rule-id" style="--rid:${ridColor};--rid-glow:${ridColor}b3">${idContent}</td>
        <td class="title-cell" title="${escHtml(r.title)}">${escHtml(r.title)}</td>
        <td>${r.category ? `<span class="badge badge-category">${escHtml(r.category)}</span>` : emptyCell()}</td>
        <td>${r.product ? `<span class="badge badge-product">${escHtml(r.product)}</span>` : emptyCell()}</td>
        <td>${r.service ? `<span class="badge badge-service">${escHtml(r.service)}</span>` : emptyCell()}</td>
        <td><div class="cell-pills">${mitrePills(r.tactics, 'tactic') || emptyCell()}</div></td>
        <td><div class="cell-pills">${mitrePills(r.techniques, 'technique') || emptyCell()}</div></td>
        <td>${sevBadge(r)}</td>
        <td>${statusBadge(r)}</td>
        <td>${verdictBadge(r)}</td>
      </tr>`;
    }).join('');

    tbody.querySelectorAll('tr[data-idx]').forEach(tr => {
      tr.addEventListener('click', () => {
        const idx = parseInt(tr.dataset.idx, 10);
        selectedPos = currentView.indexOf(RULES[idx]);
        paintSelection();
        openDrawer(idx);
      });
    });

    if (selectedPos >= currentView.length) selectedPos = currentView.length - 1;
    paintSelection();
  }

  // ── Rule body syntax highlight (Sigma YAML / SPL) ───────────────────────

  const YAML_LIST_RX = /^(-\s+)(.*)$/;
  const YAML_KV_RX = /^([A-Za-z0-9_.|-]+)(:)(\s*)(.*)$/;

  function highlightYAMLValue(val) {
    if (!val) return '';
    if (/^['"]/.test(val)) return `<span class="t-val">${escHtml(val)}</span>`;
    if (/^-?\d+(\.\d+)?$/.test(val)) return `<span class="t-val">${escHtml(val)}</span>`;
    if (val === '|' || val === '>') return `<span class="t-op">${escHtml(val)}</span>`;
    return `<span class="t-id">${escHtml(val)}</span>`;
  }

  function highlightYAML(code) {
    return code.split('\n').map(line => {
      const indentM = line.match(/^\s*/);
      const indent = indentM[0];
      let rest = line.slice(indent.length);
      if (!rest) return line;
      if (rest.startsWith('#')) return indent + `<span class="t-com">${escHtml(rest)}</span>`;

      let prefix = '';
      const listM = rest.match(YAML_LIST_RX);
      if (listM) { prefix = `<span class="t-op">-</span> `; rest = listM[2]; }
      else if (rest === '-') { return indent + `<span class="t-op">-</span>`; }

      const kv = rest.match(YAML_KV_RX);
      if (kv) {
        const [, key, , sp, val] = kv;
        return indent + prefix + `<span class="t-fld">${escHtml(key)}</span><span class="t-op">:</span>${sp}${highlightYAMLValue(val)}`;
      }
      if (/^['"]/.test(rest)) return indent + prefix + `<span class="t-val">${escHtml(rest)}</span>`;
      return indent + prefix + `<span class="t-id">${escHtml(rest)}</span>`;
    }).join('\n');
  }

  const SPL_KEYWORDS = new Set([
    'search', 'stats', 'eval', 'where', 'table', 'sort', 'dedup', 'rename',
    'rex', 'lookup', 'join', 'transaction', 'timechart', 'bin', 'top', 'rare',
    'head', 'tail', 'fields', 'streamstats', 'eventstats', 'multikv',
    'fillnull', 'convert', 'makemv', 'mvexpand', 'append', 'appendcols',
    'union', 'format', 'foreach', 'map', 'collect', 'outputlookup',
    'inputlookup', 'regex', 'by', 'as', 'index', 'sourcetype',
  ]);
  const SPL_OPERATOR_WORDS = new Set(['and', 'or', 'not', 'in', 'like']);
  const SPL_FUNCS = new Set([
    'count', 'sum', 'avg', 'max', 'min', 'values', 'distinct_count',
    'earliest', 'latest', 'first', 'last', 'stdev', 'median', 'mode',
    'if', 'case', 'coalesce', 'strftime', 'strptime', 'tostring',
    'tonumber', 'substr', 'len', 'upper', 'lower', 'replace', 'split',
    'mvcount', 'mvindex', 'mvjoin',
  ]);

  function tokenizeSPL(code) {
    const rx = /(```[\s\S]*?```)|('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")|(\|)|(\b\d+(?:\.\d+)?\b)|([A-Za-z_][\w.]*)|(!=|>=|<=|=|<|>)|(\s+)|([\s\S])/g;
    const toks = [];
    let m;
    while ((m = rx.exec(code)) !== null) {
      const [, comment, str, pipe, num, ident, op, ws, other] = m;
      if (comment) toks.push({ k: 'comment', t: comment });
      else if (str) toks.push({ k: 'string', t: str });
      else if (pipe) toks.push({ k: 'pipe', t: pipe });
      else if (num) toks.push({ k: 'num', t: num });
      else if (ident) toks.push({ k: 'ident', t: ident });
      else if (op) toks.push({ k: 'op', t: op });
      else if (ws) toks.push({ k: 'ws', t: ws });
      else toks.push({ k: 'punct', t: other });
    }
    return toks;
  }

  function highlightSPL(code) {
    const toks = tokenizeSPL(code);
    const nextN = (i, n) => {
      let c = 0;
      for (let j = i + 1; j < toks.length; j++) {
        if (toks[j].k === 'ws') continue;
        if (++c === n) return toks[j];
      }
      return null;
    };

    let out = '';
    toks.forEach((tok, i) => {
      const { k, t } = tok;
      if (k === 'ws')      { out += t; return; }
      if (k === 'comment') { out += `<span class="t-com">${escHtml(t)}</span>`; return; }
      if (k === 'string')  { out += `<span class="t-val">${escHtml(t)}</span>`; return; }
      if (k === 'num')     { out += `<span class="t-val">${escHtml(t)}</span>`; return; }
      if (k === 'pipe')    { out += `<span class="t-kw">${escHtml(t)}</span>`; return; }
      if (k === 'op')      { out += `<span class="t-op">${escHtml(t)}</span>`; return; }
      if (k === 'punct')   { out += escHtml(t); return; }

      const lower = t.toLowerCase();
      const n1 = nextN(i, 1);
      let cls;
      if (SPL_OPERATOR_WORDS.has(lower)) cls = 't-op';
      else if (SPL_KEYWORDS.has(lower)) cls = 't-kw';
      else if (SPL_FUNCS.has(lower) && n1 && n1.t === '(') cls = 't-fn';
      else if (n1 && n1.t === '=') cls = 't-fld';
      else cls = 't-id';
      out += `<span class="${cls}">${escHtml(t)}</span>`;
    });
    return out;
  }

  function highlightRuleBody(code, lang) {
    return lang === 'spl' ? highlightSPL(code) : highlightYAML(code);
  }

  async function copyRuleBody(btn) {
    if (!currentRuleBody) return;
    try {
      await navigator.clipboard.writeText(currentRuleBody);
    } catch (e) {
      const ta = document.createElement('textarea');
      ta.value = currentRuleBody;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); } catch (e2) { /* clipboard unavailable */ }
      document.body.removeChild(ta);
    }
    const label = btn.querySelector('.cc-label');
    if (!label) return;
    const prev = label.textContent;
    label.textContent = 'Copied';
    btn.classList.add('ok');
    setTimeout(() => { label.textContent = prev; btn.classList.remove('ok'); }, 1400);
  }

  // ── Drawer ───────────────────────────────────────────────────────────────

  function openDrawer(idx) {
    const r = RULES[idx];

    document.getElementById('d-rule-id').innerHTML = r.fileUrl
      ? `<a href="${escHtml(r.fileUrl)}" target="_blank">${escHtml(r.id)}</a>`
      : escHtml(r.id);
    document.getElementById('d-title').textContent = r.title;

    const badges = [
      `<span class="badge badge-source">${escHtml(r.source)}</span>`,
      r.category ? `<span class="badge badge-category">${escHtml(r.category)}</span>` : '',
      r.product ? `<span class="badge badge-product">${escHtml(r.product)}</span>` : '',
      r.service ? `<span class="badge badge-service">${escHtml(r.service)}</span>` : '',
      r.severity ? sevBadge(r) : '',
      r.status ? statusBadge(r) : '',
      verdictBadge(r),
    ].filter(Boolean);
    document.getElementById('d-badges').innerHTML = badges.join('');

    let body = '';

    if (r.description) {
      body += `<div><div class="drawer-section-label">Description</div><div class="drawer-desc">${escHtml(r.description)}</div></div>`;
    }

    body += `<div>
      <div class="drawer-section-label">Metadata</div>
      <div class="meta-grid">
        <span class="meta-key">Rule ID</span><span class="meta-val">${escHtml(r.id)}</span>
        ${r.author ? `<span class="meta-key">Author</span><span class="meta-val">${escHtml(r.author)}</span>` : ''}
        ${r.date ? `<span class="meta-key">Created</span><span class="meta-val">${escHtml(r.date)}</span>` : ''}
        ${r.modified ? `<span class="meta-key">Modified</span><span class="meta-val">${escHtml(r.modified)}</span>` : ''}
        ${r.eventType ? `<span class="meta-key">Event Type</span><span class="meta-val">${escHtml(r.eventType)}</span>` : ''}
      </div>
    </div>`;

    if ((r.tactics && r.tactics.length) || (r.techniques && r.techniques.length)) {
      body += `<div>
        <div class="drawer-section-label">MITRE ATT&amp;CK</div>
        <div class="mitre-pills">
          ${(r.tactics || []).map(t => `<a class="mitre-pill" href="${escHtml(tacticUrl(t))}" target="_blank">${escHtml(t)}</a>`).join('')}
          ${(r.techniques || []).map(t => `<a class="mitre-pill" href="${escHtml(techniqueUrl(t))}" target="_blank">${escHtml(t)}</a>`).join('')}
        </div>
      </div>`;
    }

    if (r.falsepositives && r.falsepositives.length) {
      body += `<div>
        <div class="drawer-section-label">False Positives</div>
        <div class="drawer-list">${r.falsepositives.map(f => `<div class="drawer-list-item fp">${escHtml(f)}</div>`).join('')}</div>
      </div>`;
    }

    if (r.references && r.references.length) {
      body += `<div>
        <div class="drawer-section-label">References</div>
        <div class="drawer-list">${r.references.map(ref => `<div class="drawer-list-item"><a href="${escHtml(ref)}" target="_blank">${escHtml(ref)}</a></div>`).join('')}</div>
      </div>`;
    }

    if (r.testing && r.testing.enabled) {
      const t = r.testing;
      const atomicsHtml = (t.atomics || []).map(a => {
        const nums = (a.testNumbers || []).join(', #');
        const label = escHtml(a.technique) + (nums ? ' — test #' + escHtml(nums) : '');
        return a.url
          ? `<div class="drawer-list-item atomic"><a href="${escHtml(a.url)}" target="_blank">${label}</a></div>`
          : `<div class="drawer-list-item atomic">${label}</div>`;
      }).join('');
      body += `<div>
        <div class="drawer-section-label">Atomic Red Team Testing</div>
        <div class="meta-grid">
          ${t.runner ? `<span class="meta-key">Runner</span><span class="meta-val">${escHtml(t.runner)}</span>` : ''}
          ${t.type ? `<span class="meta-key">Type</span><span class="meta-val">${escHtml(t.type)}</span>` : ''}
        </div>
        <div class="drawer-list" style="margin-top:8px">${atomicsHtml}</div>
      </div>`;
    }

    currentRuleBody = '';
    if (r.ruleBody) {
      currentRuleBody = r.ruleBody;
      const langLabel = r.ruleBodyLang === 'spl' ? 'SPL' : 'Sigma YAML';
      body += `<div>
        <div class="code-head">
          <span class="drawer-section-label" style="margin:0">Rule Definition (${langLabel})</span>
          <button class="code-copy" onclick="copyRuleBody(this)">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
            <span class="cc-label">Copy</span>
          </button>
        </div>
        <pre class="rule-body-pre">${highlightRuleBody(r.ruleBody, r.ruleBodyLang)}</pre>
      </div>`;
    }

    if (r.fileUrl) {
      body += `<a class="drawer-cta" href="${escHtml(r.fileUrl)}" target="_blank">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg>
        View rule source on GitHub
      </a>`;
    }

    document.getElementById('d-body').innerHTML = body;
    document.getElementById('drawer-overlay').classList.add('open');
    document.getElementById('drawer').classList.add('open');
  }

  function closeDrawer() {
    document.getElementById('drawer-overlay').classList.remove('open');
    document.getElementById('drawer').classList.remove('open');
  }

  // ── Keyboard navigation ──────────────────────────────────────────────────

  function isDrawerOpen() { return document.getElementById('drawer')?.classList.contains('open'); }

  function paintSelection() {
    const tbody = document.getElementById('table-body');
    if (!tbody) return;
    tbody.querySelectorAll('tr').forEach(tr => tr.classList.remove('selected'));
    if (selectedPos < 0 || selectedPos >= currentView.length) return;
    const rule = currentView[selectedPos];
    const idx = RULES.indexOf(rule);
    const tr = tbody.querySelector(`tr[data-idx="${idx}"]`);
    if (!tr) return;
    tr.classList.add('selected');
    tr.scrollIntoView({ block: 'nearest' });
  }

  function moveSelection(delta) {
    if (!currentView.length) return;
    if (selectedPos < 0) selectedPos = delta > 0 ? 0 : currentView.length - 1;
    else selectedPos = Math.min(currentView.length - 1, Math.max(0, selectedPos + delta));
    paintSelection();
    if (isDrawerOpen()) {
      const idx = RULES.indexOf(currentView[selectedPos]);
      if (idx >= 0) openDrawer(idx);
    }
  }

  function openSelected() {
    if (selectedPos < 0 || selectedPos >= currentView.length) return;
    const idx = RULES.indexOf(currentView[selectedPos]);
    if (idx >= 0) openDrawer(idx);
  }

  document.addEventListener('keydown', e => {
    if (currentTab !== 'rules') return;
    const el = document.activeElement;
    const inInput = el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA');
    const searchEl = document.getElementById('search-input');

    if (e.key === 'Escape') {
      if (isDrawerOpen()) { closeDrawer(); return; }
      if (inInput) { el.blur(); return; }
      if (selectedPos >= 0) { selectedPos = -1; paintSelection(); }
      return;
    }

    if (inInput) return;

    if (e.key === '/') {
      e.preventDefault();
      searchEl?.focus();
      searchEl?.select();
      return;
    }

    if (!RULES.length) return;

    switch (e.key) {
      case 'ArrowDown': e.preventDefault(); moveSelection(1); break;
      case 'ArrowUp': e.preventDefault(); moveSelection(-1); break;
      case 'Enter':
        e.preventDefault();
        if (selectedPos < 0 && currentView.length) { selectedPos = 0; paintSelection(); }
        openSelected();
        break;
      case 'Home': e.preventDefault(); if (currentView.length) { selectedPos = 0; paintSelection(); } break;
      case 'End': e.preventDefault(); if (currentView.length) { selectedPos = currentView.length - 1; paintSelection(); } break;
    }
  });

  // ── Tabs ─────────────────────────────────────────────────────────────────

  function setActiveTab(name, opts) {
    opts = opts || {};
    currentTab = (name === 'navigator') ? 'navigator' : 'rules';
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === currentTab));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.toggle('active', p.id === 'tab-' + currentTab));
    if (!opts.skipHash) updateHash();
  }

  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => setActiveTab(btn.dataset.tab));
  });

  // ── Deep link (hash state: tab + filters + search + sort) ───────────────

  function encodeState() {
    const parts = ['tab=' + currentTab];
    Object.entries(activeFilters).forEach(([key, vals]) => {
      if (!vals.length) return;
      parts.push(`${key}=${vals.map(encodeURIComponent).join(',')}`);
    });
    const q = document.getElementById('search-input')?.value?.trim();
    if (q) parts.push('q=' + encodeURIComponent(q));
    if (sortCol !== 'id' || !sortAsc) parts.push(`sort=${sortCol}:${sortAsc ? 'asc' : 'desc'}`);
    return parts.join('&');
  }

  function decodeState(hash) {
    const raw = (hash || '').replace(/^#/, '');
    const state = { tab: 'rules', filters: {}, q: '', sortCol: 'id', sortAsc: true };
    if (!raw) return state;
    const validKeys = new Set(FILTER_FIELDS.map(f => f.key));
    raw.split('&').forEach(pair => {
      const eq = pair.indexOf('=');
      if (eq < 0) return;
      const key = pair.slice(0, eq);
      const val = pair.slice(eq + 1);
      if (key === 'tab') {
        state.tab = val === 'navigator' ? 'navigator' : 'rules';
      } else if (key === 'q') {
        state.q = decodeURIComponent(val);
      } else if (key === 'sort') {
        const [col, dir] = val.split(':');
        if (col) { state.sortCol = col; state.sortAsc = dir !== 'desc'; }
      } else if (validKeys.has(key)) {
        state.filters[key] = val.split(',').map(decodeURIComponent).filter(Boolean);
      }
    });
    return state;
  }

  function applyState(state) {
    activeFilters = {};
    Object.entries(state.filters).forEach(([key, vals]) => { if (vals.length) activeFilters[key] = vals; });
    Object.keys(activeFilters).forEach(key => {
      openSections.add(key);
      const f = FILTER_FIELDS.find(f => f.key === key);
      if (f && f.group) openGroups.add(f.group);
    });
    const si = document.getElementById('search-input');
    if (si) si.value = state.q || '';
    document.getElementById('search-clear')?.classList.toggle('show', !!(state.q));
    sortCol = state.sortCol;
    sortAsc = state.sortAsc;
    setActiveTab(state.tab, { skipHash: true });
    renderFilters();
    renderActiveFilterRow();
    renderTable();
  }

  function updateHash() {
    const enc = encodeState();
    const url = `${location.pathname}${location.search}#${enc}`;
    try { history.replaceState(null, '', url); } catch (e) { /* sandboxed preview, no real origin */ }
  }

  function buildDeepLink() {
    const enc = encodeState();
    const isWeb = (location.protocol === 'http:' || location.protocol === 'https:') && location.origin && location.origin !== 'null';
    if (isWeb) return { url: `${location.origin}${location.pathname}${location.search}#${enc}`, full: true };
    return { url: enc ? '#' + enc : '', full: false };
  }

  function flashBtn(btn, text) {
    if (!btn) return;
    const label = btn.querySelector('.btn-label');
    if (!label) return;
    const prev = label.textContent;
    label.textContent = text;
    btn.classList.add('ok');
    setTimeout(() => { label.textContent = prev; btn.classList.remove('ok'); }, 1400);
  }

  async function copyDeepLink() {
    const btn = document.getElementById('link-btn');
    const { url, full } = buildDeepLink();
    if (!url) { flashBtn(btn, 'No filters'); return; }
    const okLabel = full ? 'Copied' : 'Hash copied';
    try {
      await navigator.clipboard.writeText(url);
      flashBtn(btn, okLabel);
    } catch (e) {
      const ta = document.createElement('textarea');
      ta.value = url;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); flashBtn(btn, okLabel); }
      catch (e2) { prompt('Copy this link:', url); }
      document.body.removeChild(ta);
    }
  }

  window.addEventListener('hashchange', () => {
    applyState(decodeState(location.hash));
  });

  // ── Export ───────────────────────────────────────────────────────────────

  function toggleExportMenu(e) {
    e.stopPropagation();
    document.getElementById('export-menu').classList.toggle('open');
  }

  document.addEventListener('click', () => { document.getElementById('export-menu')?.classList.remove('open'); });

  function flat(v, sep) {
    sep = sep || ' | ';
    if (!v) return '';
    return Array.isArray(v) ? v.join(sep) : String(v);
  }

  function activeFilterSummary() {
    const q = document.getElementById('search-input')?.value?.trim();
    const parts = Object.entries(activeFilters).map(([key, vals]) => {
      const label = FILTER_FIELDS.find(f => f.key === key)?.label || key;
      return `${label}: ${vals.join(', ')}`;
    });
    if (q) parts.push(`Search: "${q}"`);
    return parts.length ? parts.join(' | ') : 'no active filters';
  }

  function exportRecord(r) {
    return {
      'Rule ID': r.id,
      'Title': r.title,
      'Source': r.source,
      'Category': r.category,
      'Product': r.product,
      'Service': r.service,
      'Event Type': r.eventType,
      'Tactics': flat(r.tactics),
      'Techniques': flat(r.techniques),
      'Severity': r.severity,
      'Status': r.status,
      'Verdict': r.verdict,
      'Author': r.author,
      'Created': r.date,
      'Modified': r.modified,
      'File': r.fileUrl,
    };
  }

  function downloadFile(content, filename, mime) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function todayStamp() {
    const d = new Date();
    const p = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
  }

  function toCSV(records) {
    if (!records.length) return '';
    const cols = Object.keys(records[0]);
    const esc = v => {
      const s = String(v ?? '');
      return /[,"\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const head = cols.map(esc).join(',');
    const rows = records.map(rec => cols.map(c => esc(rec[c])).join(','));
    return '﻿' + [head, ...rows].join('\r\n');
  }

  function toMarkdown(records) {
    const cols = ['Rule ID', 'Title', 'Category', 'Product', 'Service', 'Severity', 'Status', 'Verdict'];
    const esc = v => String(v ?? '').replace(/\|/g, '\\|');
    const header = `| ${cols.join(' | ')} |`;
    const sep = `| ${cols.map(() => '---').join(' | ')} |`;
    const rows = records.map(rec => `| ${cols.map(c => esc(rec[c])).join(' | ')} |`);
    return [
      '# Detection Rules', '',
      `**Exported:** ${todayStamp()}  `,
      `**Rules:** ${records.length}  `,
      `**Filters:** ${activeFilterSummary()}`,
      '', header, sep, ...rows, '',
    ].join('\n');
  }

  function exportView(format) {
    document.getElementById('export-menu').classList.remove('open');
    if (!currentView.length) { alert('The current view is empty — nothing to export.'); return; }
    const records = currentView.map(exportRecord);
    const stamp = todayStamp();
    if (format === 'csv') {
      downloadFile(toCSV(records), `detection_rules_${stamp}.csv`, 'text/csv;charset=utf-8');
    } else if (format === 'json') {
      const payload = {
        exportedAt: new Date().toISOString(),
        filters: activeFilterSummary(),
        count: currentView.length,
        rules: currentView,
      };
      downloadFile(JSON.stringify(payload, null, 2), `detection_rules_${stamp}.json`, 'application/json;charset=utf-8');
    } else if (format === 'md') {
      downloadFile(toMarkdown(records), `detection_rules_${stamp}.md`, 'text/markdown;charset=utf-8');
    }
  }

  // ── Resizable columns ────────────────────────────────────────────────────

  function initResizableColumns() {
    const table = document.querySelector('#tab-rules table');
    if (!table) return;
    const ths = table.querySelectorAll('thead th');
    ths.forEach((th, i) => {
      const old = th.querySelector('.col-resizer');
      if (old) old.remove();
      if (i === ths.length - 1) return;

      const resizer = document.createElement('div');
      resizer.className = 'col-resizer';
      th.appendChild(resizer);

      let startX, startW, dragged = false;

      resizer.addEventListener('mousedown', e => {
        e.stopPropagation();
        startX = e.clientX;
        startW = th.offsetWidth;
        dragged = false;
        resizer.classList.add('dragging');
        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';

        const onMove = ev => {
          const delta = ev.clientX - startX;
          if (Math.abs(delta) > 2) dragged = true;
          const newW = Math.max(50, startW + delta);
          th.style.width = newW + 'px';
          th.style.minWidth = newW + 'px';
        };

        const onUp = () => {
          resizer.classList.remove('dragging');
          document.body.style.cursor = '';
          document.body.style.userSelect = '';
          document.removeEventListener('mousemove', onMove);
          document.removeEventListener('mouseup', onUp);
        };

        document.addEventListener('mousemove', onMove);
        document.addEventListener('mouseup', onUp);
      });

      resizer.addEventListener('click', e => {
        if (dragged) { e.stopPropagation(); dragged = false; }
      });
    });
  }

  var navTip = document.getElementById('att-tip');
  document.querySelectorAll('.tc[data-rules]').forEach(function(el) {
    el.addEventListener('mouseenter', function() {
      var rules = JSON.parse(el.dataset.rules);
      var html = '<div class="tip-head">' + el.dataset.id + '</div>';
      rules.forEach(function(r) {
        var vc = r.verdict === 'N/A' ? 'NA' : r.verdict;
        var badge = '<span class="tip-vbadge ' + vc + '">' + r.verdict + '</span>';
        if (r.url) {
          html += '<a class="tip-rule" href="' + r.url + '" target="_blank">' + badge + ' ' + r.id + ': ' + r.title + '</a>';
        } else {
          html += '<div class="tip-rule">' + badge + ' ' + r.id + ': ' + r.title + '</div>';
        }
      });
      navTip.innerHTML = html;
      navTip.style.display = 'block';
    });
    el.addEventListener('mousemove', function(e) {
      var x = e.clientX + 14, y = e.clientY + 14;
      if (x + 350 > window.innerWidth) x = e.clientX - 354;
      navTip.style.left = x + 'px';
      navTip.style.top  = y + 'px';
    });
    el.addEventListener('mouseleave', function() { navTip.style.display = 'none'; });
  });
  // Shared expand/collapse helper
  function navDoExpand(btn, open) {
    var target = btn.dataset.target;
    var col = btn.closest('.tc-col');
    var subs = Array.from(col.querySelectorAll('.' + target));
    btn.classList.toggle('open', open);
    btn.innerHTML = open ? '&#9660;' : '&#9654;';
    var parentTc = btn.closest('.tc');
    if (open) {
      parentTc.classList.add('expanded');
      var grp = document.createElement('div');
      grp.className = 'sub-group';
      btn._subGrp = grp;
      parentTc.after(grp);
      subs.forEach(function(s) { s.style.display = 'flex'; grp.appendChild(s); });
    } else {
      parentTc.classList.remove('expanded');
      var grp = btn._subGrp;
      if (grp) {
        subs.forEach(function(s) { s.style.display = 'none'; grp.before(s); });
        grp.remove();
        btn._subGrp = null;
      }
    }
  }
  // Expand/collapse sub-techniques — scoped to column, grp stored on button
  document.querySelectorAll('.tc-expand').forEach(function(btn) {
    btn.addEventListener('click', function(e) {
      e.stopPropagation();
      navDoExpand(btn, !btn.classList.contains('open'));
    });
  });
  // Sticky mirror scrollbar
  (function() {
    var matrix = document.querySelector('.att-matrix');
    if (!matrix) return;
    var mirror = document.createElement('div');
    mirror.style.cssText = 'overflow-x:auto;position:sticky;bottom:0;height:14px;background:#0d1117;z-index:100;';
    var inner = document.createElement('div');
    inner.style.height = '1px';
    mirror.appendChild(inner);
    matrix.parentNode.insertBefore(mirror, matrix.nextSibling);
    function syncWidth() { inner.style.width = matrix.scrollWidth + 'px'; }
    syncWidth();
    var syncing = false;
    matrix.addEventListener('scroll', function() {
      if (syncing) return; syncing = true; mirror.scrollLeft = matrix.scrollLeft; syncing = false;
    });
    mirror.addEventListener('scroll', function() {
      if (syncing) return; syncing = true; matrix.scrollLeft = mirror.scrollLeft; syncing = false;
    });
    if (window.ResizeObserver) { new ResizeObserver(syncWidth).observe(matrix); }
  })();
  // Legend multi-filter with parent+sub logic
  var navActiveFilters = new Set();
  function tcVerdict(tc) {
    if (tc.classList.contains('pass')) return 'pass';
    if (tc.classList.contains('fail')) return 'fail';
    if (tc.classList.contains('nv'))   return 'nv';
    return 'uncov';
  }
  function applyNavFilters() {
    document.querySelectorAll('.tc-col').forEach(function(col) {
      col.querySelectorAll('.tc:not(.sub)').forEach(function(parentTc) {
        var tid = parentTc.dataset.id;
        if (!tid) return;
        var subs = Array.from(col.querySelectorAll('.tc.sub[data-id^="' + tid + '."]'));
        if (navActiveFilters.size === 0) {
          parentTc.classList.remove('tc-hidden');
          subs.forEach(function(s) { s.classList.remove('tc-hidden'); });
          return;
        }
        var parentMatch = navActiveFilters.has(tcVerdict(parentTc));
        var subMatch = subs.some(function(s) { return navActiveFilters.has(tcVerdict(s)); });
        parentTc.classList.toggle('tc-hidden', !parentMatch && !subMatch);
        subs.forEach(function(s) {
          s.classList.toggle('tc-hidden', !navActiveFilters.has(tcVerdict(s)));
        });
      });
    });
  }
  document.querySelectorAll('.nav-legend-item[data-filter]').forEach(function(item) {
    item.addEventListener('click', function() {
      var f = item.dataset.filter;
      if (navActiveFilters.has(f)) {
        navActiveFilters.delete(f);
        item.classList.remove('filter-active');
      } else {
        navActiveFilters.add(f);
        item.classList.add('filter-active');
      }
      applyNavFilters();
    });
  });
  // Expand All / Collapse All button
  (function() {
    var btn = document.getElementById('expand-all-btn');
    if (!btn) return;
    var expanded = false;
    btn.addEventListener('click', function() {
      expanded = !expanded;
      btn.innerHTML = expanded ? '&#9650; Collapse All' : '&#9660; Expand All';
      document.querySelectorAll('.tc-expand').forEach(function(exBtn) {
        var parentTc = exBtn.closest('.tc');
        if (navActiveFilters.size > 0 && parentTc.classList.contains('tc-hidden')) return;
        var isOpen = exBtn.classList.contains('open');
        if (expanded && !isOpen) navDoExpand(exBtn, true);
        else if (!expanded && isOpen) navDoExpand(exBtn, false);
      });
    });
  })();
  // Cross-highlight: click on cell body highlights all cells with same data-id
  var navHighlightedId = null;
  document.querySelectorAll('.tc').forEach(function(tc) {
    tc.addEventListener('click', function(e) {
      if (e.target.closest('.ti') || e.target.closest('.tc-expand') || e.target.closest('.tc-detail')) return;
      var tid = tc.dataset.id;
      if (!tid) return;
      if (navHighlightedId === tid) {
        navHighlightedId = null;
        document.querySelectorAll('.tc.highlighted').forEach(function(el) { el.classList.remove('highlighted'); });
      } else {
        navHighlightedId = tid;
        document.querySelectorAll('.tc.highlighted').forEach(function(el) { el.classList.remove('highlighted'); });
        document.querySelectorAll('.tc[data-id="' + tid + '"]').forEach(function(el) { el.classList.add('highlighted'); });
      }
    });
  });
  // Detail navPanel — toggle on same button, switch on different
  var navPanel = document.getElementById('detail-panel');
  var navPanelTitle = document.getElementById('detail-title');
  var navPanelTid = document.getElementById('detail-tid');
  var navPanelBody = document.getElementById('detail-body');
  var navOpenDetailId = null;
  document.getElementById('detail-close').addEventListener('click', function() {
    navPanel.classList.remove('open');
    navOpenDetailId = null;
  });
  document.querySelectorAll('.tc-detail').forEach(function(btn) {
    btn.addEventListener('click', function(e) {
      e.stopPropagation();
      var bid = btn.dataset.id;
      if (navPanel.classList.contains('open') && navOpenDetailId === bid) {
        navPanel.classList.remove('open');
        navOpenDetailId = null;
        return;
      }
      navOpenDetailId = bid;
      var rules = JSON.parse(btn.dataset.rules);
      navPanelTitle.textContent = btn.dataset.name;
      navPanelTid.textContent = bid;
      var html = '';
      rules.forEach(function(r) {
        var vc = r.verdict === 'N/A' ? 'NA' : r.verdict;
        var badge = '<span class="detail-vbadge ' + vc + '">' + r.verdict + '</span>';
        var label = r.id + ': ' + r.title;
        if (r.url) {
          html += '<a class="detail-rule" href="' + r.url + '" target="_blank">' + badge + label + '</a>';
        } else {
          html += '<div class="detail-noverd">' + badge + label + '</div>';
        }
      });
      navPanelBody.innerHTML = html;
      navPanel.classList.add('open');
    });
  });


  renderStats();
  applyState(decodeState(location.hash));
  initResizableColumns();

  </script>
</body>
</html>
"""


def _github_blob_url(repo: str, file_path: str) -> str:
    return f"https://github.com/{repo}/blob/main/{file_path}" if file_path else ""


def _atomic_test_url(tech: str) -> str:
    t = tech.upper()
    return f"https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/{t}/{t}.md"


def render_html_summary(stats: dict, repo: str) -> str:
    ts = stats["generated_at"][:19]
    total = stats["total_rules"]
    passed = stats["verified_pass"]
    failed = stats["verified_fail"]
    not_ver = stats["not_verified"]
    pass_rate = stats["pass_rate_pct"]
    mitre_covered = stats.get("mitre_covered_techniques", 0)
    mitre_total = stats.get("mitre_total_techniques", 0)
    mitre_pct = stats.get("mitre_coverage_pct", 0.0)

    rules_js = []
    for r in stats["rules"]:
        ls = r.get("logsource") or {}
        testing = r.get("testing") or {}
        atomics = []
        for a in (testing.get("atomics") or []):
            tech = str(a.get("technique") or "")
            nums = a.get("test_numbers") or []
            atomics.append({
                "technique": tech,
                "testNumbers": nums,
                "url": _atomic_test_url(tech) if tech else "",
            })
        rules_js.append({
            "id": r.get("detect_id", ""),
            "title": r.get("title", ""),
            "description": r.get("description", ""),
            "source": "Sigma" if r.get("source") == "sigma" else "Native SPL",
            "category": ls.get("product_category", ""),
            "product": ls.get("product", ""),
            "service": ls.get("service", ""),
            "eventType": ls.get("event_type", ""),
            "tactics": r.get("tactics") or [],
            "techniques": r.get("techniques") or [],
            "severity": r.get("level", ""),
            "status": r.get("status", ""),
            "verdict": r.get("verdict", "N/A"),
            "fileUrl": _github_blob_url(repo, r.get("file_path", "")),
            "runUrl": (
                f"https://github.com/{repo}/actions/runs/{r['run_id']}"
                if r.get("run_id") else ""
            ),
            "author": r.get("author", ""),
            "date": r.get("date", ""),
            "modified": r.get("modified", ""),
            "references": r.get("references") or [],
            "falsepositives": r.get("falsepositives") or [],
            "ruleBody": r.get("rule_body", ""),
            "ruleBodyLang": r.get("rule_body_lang", ""),
            "testing": {
                "enabled": bool(testing.get("enabled")),
                "runner": testing.get("runner", ""),
                "type": testing.get("type", ""),
                "atomics": atomics,
            },
        })

    rules_json = json.dumps(rules_js, ensure_ascii=False)
    tactic_ids_json = json.dumps(TACTIC_ID_MAP, ensure_ascii=False)

    technique_map = stats.get("_technique_map", [])
    rules_detail_inner = stats.get("_rules_detail", stats.get("rules", []))
    technique_coverage = build_technique_coverage(rules_detail_inner, repo)
    matrix_html = _build_matrix_html(technique_map, technique_coverage)
    layer_url = f"https://github.com/{repo}/blob/main/outputs/reports/navigator_layer.json"

    html = _PAGE_TEMPLATE
    html = html.replace("@@REPO@@", repo)
    html = html.replace("@@TS@@", ts)
    html = html.replace("@@TOTAL@@", str(total))
    html = html.replace("@@PASSED@@", str(passed))
    html = html.replace("@@FAILED@@", str(failed))
    html = html.replace("@@NOT_VER@@", str(not_ver))
    html = html.replace("@@PASS_RATE@@", str(pass_rate))
    html = html.replace("@@MITRE_COVERED@@", str(mitre_covered))
    html = html.replace("@@MITRE_TOTAL@@", str(mitre_total))
    html = html.replace("@@MITRE_PCT@@", str(mitre_pct))
    html = html.replace("@@RULES_JSON@@", rules_json)
    html = html.replace("@@TACTIC_IDS_JSON@@", tactic_ids_json)
    html = html.replace("@@MATRIX_HTML@@", matrix_html)
    html = html.replace("@@LAYER_URL@@", layer_url)
    return html
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

    nav_layer = render_navigator_layer(build_technique_coverage(stats.get("_rules_detail", stats.get("rules", [])), repo), stats)
    write_navigator_layer(nav_layer)
    print("outputs/reports/navigator_layer.json updated.")

    html_page = render_html_summary(stats, repo)
    update_html_summary(html_page)
    print("docs/index.html updated.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
