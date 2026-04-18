"""
generate_stats.py — Collect detection rule stats and update README.md + RULE_SUMMARY.md.

Reads:
  - rules/sigma/*.yml          — sigma rules (level, status, tags, detect_id)
  - rules/splunk/*.spl         — counts native (non-sigma) SPL rules
  - outputs/results/*/result.json — pass/fail verdicts

Writes:
  - outputs/reports/stats.json — consumed by shields.io dynamic badges
  - README.md                  — replaces content between <!-- STATS_START --> and <!-- STATS_END -->
  - rules/RULE_SUMMARY.md      — full rule index with MITRE links
"""

import json
import re
import sys
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
    "critical": "![](https://img.shields.io/badge/Critical-CC0000?style=flat-square)",
    "high":     "![](https://img.shields.io/badge/High-FF6600?style=flat-square)",
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


def load_verdicts() -> dict[str, str]:
    """Returns {detect_id: verdict} from outputs/results/*/result.json."""
    verdicts: dict[str, str] = {}
    results_dir = REPO_ROOT / "outputs" / "results"
    if not results_dir.exists():
        return verdicts
    for result_file in results_dir.glob("*/result.json"):
        try:
            data = json.loads(result_file.read_text(encoding="utf-8"))
            detect_id = data.get("detect_id", "")
            verdict = data.get("verdict", "")
            if detect_id and verdict:
                verdicts[detect_id] = verdict
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

        verdict = verdicts.get(detect_id, "N/A")
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

        verdict = verdicts.get(detect_id, "N/A")
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

    # --- Verification status pie ---
    if stats["total_sigma_rules"] > 0:
        lines += ["```mermaid", "pie title Verification Status"]
        if stats["verified_pass"]:
            lines.append(f'    "Pass ✅" : {stats["verified_pass"]}')
        if stats["verified_fail"]:
            lines.append(f'    "Fail ❌" : {stats["verified_fail"]}')
        if stats["not_verified"]:
            lines.append(f'    "Not Verified ⬜" : {stats["not_verified"]}')
        lines += ["```", ""]

    # --- Severity distribution pie ---
    level_order = ["critical", "high", "medium", "low", "informational"]
    levels_present = {k: v for k, v in stats["by_level"].items() if v > 0}
    if levels_present:
        lines += ["```mermaid", "pie title Rules by Severity"]
        for lvl in level_order:
            cnt = levels_present.get(lvl, 0)
            if cnt:
                lines.append(f'    "{LEVEL_EMOJI.get(lvl, "")} {lvl.capitalize()}" : {cnt}')
        lines += ["```", ""]

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
        "|:---|:------|:------:|:------:|:---------:|:--------:|:------:|:-------:|",
    ]

    for r in stats["rules"]:
        detect_id = r["detect_id"]
        file_path = r.get("file_path", "")
        if file_path:
            id_cell = f"[`{detect_id}`](https://github.com/{repo}/blob/main/{file_path})"
        else:
            id_cell = f"`{detect_id}`"

        lvl = r["level"]
        lvl_cell = LEVEL_BADGE.get(lvl, f"`{lvl}`") if lvl else "—"
        verdict_cell = VERDICT_BADGE.get(r["verdict"], r["verdict"])
        source_cell = "Sigma" if r.get("source") == "sigma" else "Native SPL"

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

        lines.append(
            f"| {id_cell} | {r['title']} | {source_cell} | {tactic_cell} | {tech_cell} | {lvl_cell} | {r['status']} | {verdict_cell} |"
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

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
