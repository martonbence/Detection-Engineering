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
import re
import sys
import urllib.parse
from datetime import datetime, timezone
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


def pass_rate_color(pct: int) -> str:
    if pct >= 80:
        return "brightgreen"
    if pct >= 50:
        return "yellow"
    return "red"


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

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_rules": total_rules,
        "total_sigma_rules": total_sigma,
        "total_splunk_rules": total_spl_count,
        "total_native_spl_rules": native_spl_count,
        "verified_pass": verified_pass,
        "verified_fail": verified_fail,
        "not_verified": not_verified,
        "pass_rate_pct": pass_rate,
        "pass_rate_color": pass_rate_color(pass_rate),
        "by_level": dict(sorted(by_level.items())),
        "by_status": dict(sorted(by_status.items())),
        "by_tactic": dict(sorted(by_tactic.items(), key=lambda x: -x[1])),
        "rules": sorted(rules_detail, key=lambda r: r["detect_id"]),
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
    chart_url = "https://quickchart.io/chart?c=" + urllib.parse.quote(chart_json) + "&width=500&height=200&f=svg"
    lines += ["**Rules by Severity**", "", f"![Rules by Severity]({chart_url})", ""]

    # --- MITRE ATT&CK tactic bar chart ---
    if stats["by_tactic"]:
        tactics = list(stats["by_tactic"].items())[:10]
        x_labels = "[" + ", ".join(f'"{t}"' for t, _ in tactics) + "]"
        y_values = "[" + ", ".join(str(c) for _, c in tactics) + "]"
        lines += [
            "```mermaid",
            "xychart-beta",
            '    title "Rules by MITRE ATT&CK Tactic"',
            f"    x-axis {x_labels}",
            '    y-axis "Rule Count" 0 --> ' + str(max(c for _, c in tactics) + 1),
            f"    bar {y_values}",
            "```",
            "",
        ]

    lines += [
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
  <footer>
    Generated at {ts} UTC &nbsp;·&nbsp;
    <a href="https://github.com/{repo}/blob/main/rules/RULE_SUMMARY.md" target="_blank">Markdown version</a>
  </footer>
  <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
  <script src="https://cdn.datatables.net/1.13.8/js/jquery.dataTables.min.js"></script>
  <script>
  $(function() {{
    var table = $('#rules-table').DataTable({{
      orderCellsTop: true,
      pageLength: 25,
      lengthMenu: [[10, 25, 50, 100, 250, -1], [10, 25, 50, 100, 250, 'All']],
      order: [[0, 'asc']],
      language: {{
        search: 'Search:', lengthMenu: 'Show _MENU_ rules',
        zeroRecords: 'No rules match the current filter.',
        info: 'Showing _START_\u2013_END_ of _TOTAL_ rules',
        infoFiltered: '(filtered from _MAX_ total)'
      }}
    }});

    // exactCols: exact-match select (Source=2, Severity=5, Status=6, Verdict=7)
    // containsCols: contains-match (ID=0, Title=1, Tactic=3, Technique=4)
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
    (out_dir / "stats.json").write_text(
        json.dumps(stats, indent=2, ensure_ascii=False), encoding="utf-8"
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

    html_page = render_html_summary(stats, repo)
    update_html_summary(html_page)
    print("docs/index.html updated.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
