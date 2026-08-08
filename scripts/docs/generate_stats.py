"""
generate_stats.py — Collect detection rule stats and update README.md + docs/index.html.

Reads:
  - rules/sigma/*.yml          — every rule (level, status, tags, detect_id);
    rules with custom.splunk.raw_query set are hand-crafted SPL classified as
    "native_spl" for the rule browser's source badge, everyone else is "sigma"
  - rules/splunk/*.spl         — generated query output, counted for total_splunk_rules only
  - outputs/results/*/result.json — pass/fail verdicts
  - scripts/docs/assets/page.{template.html,css,js} — the rule browser page,
    assembled by load_page_template(); the placeholders in it are filled in by
    render_html_summary()

Writes:
  - outputs/reports/stats.json — consumed by shields.io dynamic badges
  - README.md                  — replaces content between <!-- STATS_START --> and <!-- STATS_END -->
  - docs/index.html            — GitHub Pages filterable/sortable rule table
"""

import html as _html
import json
import re
import subprocess
import sys
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.rules import RuleLoadError, discover, load_rule

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
    # Deployed + attempted this run, but the Atomic Red Team test itself did not
    # complete (e.g. cut off by run_atomic.ps1's step timeout) -- distinct from
    # both FAIL (test ran, no matching Splunk events) and N/A (never tested at
    # all). Uses GitHub Primer's "attention" amber (#9A6700, the same emphasis
    # shade Primer reserves for warning/caution) so it reads as "caution/unknown"
    # rather than pass (green) or fail (red) -- see docs/index.html's
    # .verdict-notverified / .tc.notver / Navigator legend for the matching
    # rule-browser treatment.
    "NOT_VERIFIED": "![](https://img.shields.io/badge/NOT%20VERIFIED-9A6700?style=flat-square)",
}


def load_sigma_rules() -> list[dict]:
    rules = []
    for path in discover(REPO_ROOT / "rules" / "sigma"):
        try:
            data = load_rule(path)
        except RuleLoadError:
            # Unchanged policy: drop it and carry on. A dashboard is not a gate
            # -- validate_sigma.py already fails the run for a malformed rule,
            # and refusing to render the page as well helps nobody.
            continue
        # Derived from the path rather than assembled from the filename, so a
        # rule in a subdirectory gets a link that resolves (register 3.8).
        data["_file_path"] = path.relative_to(REPO_ROOT).as_posix()
        rules.append(data)
    return rules


def count_spl_rules() -> int:
    """Returns the total number of generated .spl files under rules/splunk."""
    splunk_dir = REPO_ROOT / "rules" / "splunk"
    if not splunk_dir.exists():
        return 0
    return len(list(splunk_dir.glob("*.spl")))


def get_raw_query(rule: dict) -> str:
    """Rules with no real Sigma detection logic set custom.splunk.raw_query
    instead -- sigma_to_spl.py emits that text verbatim. Used to classify a
    rule as 'native_spl' (hand-crafted SPL) vs 'sigma' (converted) for the
    rule browser's source badge, even though both live in rules/sigma/*.yml."""
    custom = rule.get("custom") or {}
    splunk_custom = custom.get("splunk") if isinstance(custom, dict) else None
    if not isinstance(splunk_custom, dict):
        return ""
    return str(splunk_custom.get("raw_query") or "").strip()


def extract_sigma_body(rule: dict) -> str:
    """Re-serializes the detection portion of a sigma rule (the actual search
    logic) for the drawer's syntax-highlighted code view — keeps it separate
    from the metadata already shown elsewhere in the drawer."""
    detection = rule.get("detection")
    if not detection:
        return ""
    try:
        return yaml.safe_dump(
            {"detection": detection}, sort_keys=False, allow_unicode=True,
            default_flow_style=False, width=100,
        ).strip()
    except Exception:
        return ""


def load_verdicts() -> dict[str, dict]:
    """Returns {detect_id: {verdict, run_id, run_timestamp, rule_version}}
    from outputs/results/*/result.json.

    The timestamp and the tested rule_version are carried through so the browser
    can say WHEN a verdict was measured and WHICH version of the rule it was
    measured against. A PASS is only evidence about the rule text that was
    actually fired at -- if the rule changed afterwards, the verdict is a
    statement about a rule that no longer exists.
    """
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
                    "run_timestamp": str(data.get("run_timestamp") or ""),
                    "rule_version": str(data.get("rule_version") or ""),
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
            age = datetime.now(UTC) - datetime.fromisoformat(ref_at)
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
        now_iso = datetime.now(UTC).isoformat()

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


# Precedence used to pick a technique's "best_verdict" when it's covered by
# several rules with different verdicts. PASS obviously wins (a working,
# verified detection exists). Below that, NOT_VERIFIED ranks above FAIL: FAIL
# means we found out and the answer was bad -- the test ran to completion and
# no Splunk alert fired, or the rule is not deployed / its search errored --
# whereas NOT_VERIFIED means either the attack or the measurement stopped
# before we found out either way, so it's still "unknown", not "confirmed
# broken".
# Surfacing the unknown state ahead of a confirmed failure avoids implying a
# technique is worse off than it's actually known to be. N/A (never tested)
# is last since no attempt was even made.
VERDICT_RANK = {"PASS": 3, "NOT_VERIFIED": 2, "FAIL": 1, "N/A": 0}

# How a verdict was produced, as the rule's `testing.type` calls it. Spelled out
# for the page because "atomic" is an in-house shorthand while "Atomic Red Team"
# names a tool the reader can go and check -- and the distinction matters: an
# emulation-backed PASS and an ART-backed PASS are not equal evidence, even
# though the badge is the same green.
VERIFY_METHOD_LABELS = {"atomic": "Atomic Red Team", "emulation": "Emulation"}

# How long a verdict stays current before the rule is due for re-validation.
# Injected into the page as @@REVIEW_DAYS@@ and evaluated in the browser, so a
# rule crosses the line on its own without the pipeline having to re-run.
REVIEW_INTERVAL_DAYS = 180


def _verdict_age_days(iso: str) -> int | None:
    """Whole days between a verdict's timestamp and now, or None if unusable.

    Calendar days in UTC, matching the page's verdictAgeDays() so the build-time
    figure and the browser's live one can only differ by the time between the
    two, never by how the arithmetic is done.
    """
    if not iso:
        return None
    try:
        parsed = datetime.fromisoformat(str(iso))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    then = parsed.astimezone(UTC).date()
    return (datetime.now(UTC).date() - then).days


def build_technique_coverage(rules_detail: list, repo: str) -> dict:
    """Build {tech_id: {best_verdict, has_fail, rules:[...]}} from rules.

    ``best_verdict`` is the *highest*-ranked verdict of the covering rules, so a
    technique covered by both a PASS and a FAIL rule reads as PASS — the cell
    colour answers "is this technique detected", not "is every rule healthy".
    ``has_fail`` carries the second question separately: it is True when ANY
    covering rule FAILed, so the matrix can flag a confirmed failure that the
    roll-up would otherwise hide.
    """
    cov: dict = {}
    for rule in rules_detail:
        for tech in rule.get("techniques") or []:
            if tech not in cov:
                cov[tech] = {"best_verdict": "N/A", "has_fail": False, "rules": []}
            file_path = rule.get("file_path", "")
            url = f"https://github.com/{repo}/blob/main/{file_path}" if file_path else ""
            cov[tech]["rules"].append({
                "id": rule["detect_id"],
                "title": rule["title"],
                "verdict": rule["verdict"],
                "url": url,
            })
            v = rule["verdict"]
            if v == "FAIL":
                cov[tech]["has_fail"] = True
            cur = cov[tech]["best_verdict"]
            if VERDICT_RANK.get(v, 0) > VERDICT_RANK.get(cur, 0):
                cov[tech]["best_verdict"] = v
    return cov


def render_navigator_layer(technique_coverage: dict, stats: dict) -> str:
    techniques_out = []
    for tech_id, cov in technique_coverage.items():
        verdict = cov["best_verdict"]
        color = {
            "PASS": "#2EA44F", "NOT_VERIFIED": "#d29922", "FAIL": "#CF222E",
        }.get(verdict, "#6E7681")
        score = {"PASS": 100, "NOT_VERIFIED": 75, "FAIL": 50}.get(verdict, 25)
        lines = [f"{r['id']}: {r['title']} ({r['verdict']})" for r in cov["rules"]]
        # The colour/score stay keyed to best_verdict, so this file agrees with
        # the in-page matrix — but that roll-up hides a failing rule behind a
        # passing one. The official Navigator has no per-technique flag, so the
        # warning goes where it will actually be read: first line of the comment
        # (shown on hover) plus a metadata row in the technique sidebar.
        failing = [r["id"] for r in cov["rules"] if r["verdict"] == "FAIL"]
        if failing:
            lines.insert(0, (
                f"⚠ {len(failing)} of {len(cov['rules'])} covering rule(s) "
                f"FAILED verification"
            ))
        entry = {
            "techniqueID": tech_id,
            "color": color,
            "comment": "\n".join(lines),
            "enabled": True,
            "score": score,
            "showSubtechniques": True,
        }
        if failing:
            entry["metadata"] = [
                {"name": "Failing rules", "value": ", ".join(failing)},
            ]
        techniques_out.append(entry)
    layer = {
        "name": "Detection Engineering Coverage",
        "versions": {"attack": "19", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            f"Auto-generated detection coverage. {stats['generated_at'][:19]} UTC. "
            "Colour is the best verdict among the rules covering a technique; "
            "a ⚠ in the comment marks techniques where a covering rule failed "
            "verification despite that."
        ),
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
            {"label": "NOT VERIFIED", "color": "#d29922"},
            {"label": "FAIL", "color": "#CF222E"},
            {"label": "N/A", "color": "#6E7681"},
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
        return {"PASS": "pass", "NOT_VERIFIED": "notver", "FAIL": "fail"}.get(
            c["best_verdict"], "nv"
        )

    def fcls(tid: str) -> str:
        c = technique_coverage.get(tid)
        return " fail-flag" if c and c.get("has_fail") else ""

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
            # A failing rule usually maps to a SUB-technique, and sub-techniques
            # are collapsed by default — so the flag has to climb to the parent
            # or the failure stays invisible on the matrix. Same reasoning as
            # has-cov above, which surfaces sub-level coverage on the parent.
            sub_fail = any(
                technique_coverage.get(s["id"], {}).get("has_fail") for s in subs
            )
            fail_cls = " fail-flag" if (fcls(tid) or sub_fail) else ""
            # Parents that only inherited the flag have no rules of their own,
            # so the hover tooltip (bound to [data-rules]) never fires for them;
            # a native title keeps the marker from being unexplained.
            inherit_tip = (
                " title=\"A sub-technique rule failed verification\""
                if sub_fail and tid not in technique_coverage else ""
            )
            cells.append(
                "<div class=\"tc " + cls + has_cov + fail_cls + "\" data-id=\"" + tid + "\""
                + inherit_tip + rattr(tid) + ">"
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
                    "<div class=\"tc sub " + vcls(sid) + fcls(sid) + " subs-" + tid + "\""
                    " style=\"display:none\" data-id=\"" + sid + "\"" + rattr(sid) + ">"
                    "<div class=\"tc-row1\">"
                    "<a class=\"ti\" href=\"" + surl + "\" target=\"_blank\">." + suffix + "</a>"
                    "</div>"
                    "<span class=\"tn\">" + sname + "</span>"
                    + detail_btn_html(sid, sname)
                    + "</div>"
                )
        # A technique counts as "covered" for the tactic ratio if it — or any
        # of its sub-techniques — has at least one mapped rule.
        covered = sum(
            1 for t in techs
            if t["id"] in technique_coverage
            or any(s["id"] in technique_coverage for s in t.get("subs", []))
        )
        total = len(techs)
        pct = round(covered / total * 100) if total else 0
        cols.append(
            "<div class=\"tc-col\" data-tactic=\"" + _html.escape(tactic) + "\">"
            "<div class=\"tc-hdr\">"
            "<button class=\"tc-col-toggle\" title=\"Collapse column\">&#9662;</button>"
            "<a href=\"" + tac_url + "\" target=\"_blank\">" + _html.escape(tactic) + "</a>"
            "<span class=\"tc-count\">" + str(covered) + "/" + str(total) + " covered</span>"
            "<span class=\"tc-cov-bar\"><span class=\"tc-cov-fill\" style=\"width:"
            + str(pct) + "%\"></span></span>"
            "</div>"
            + "".join(cells)
            + "</div>"
        )
    return "<div class=\"att-matrix\">" + "".join(cols) + "</div>"


# ── Historical trend mining (Dashboards "Trends Over Time" section) ────────
#
# Two JSON cache files under outputs/reports/ back the trend charts:
#   - coverage_history.json      → MITRE coverage % over time
#   - rule_growth_history.json   → total/Sigma/Native SPL rule counts over time
#
# Each is updated INCREMENTALLY: one data point is appended (or the existing
# same-day point replaced, so re-runs on the same day don't spam the file)
# every time this script runs — cheap, and avoids re-mining full git history
# on every CI invocation. The first time a cache file doesn't exist yet, a
# bounded backfill mines existing git history (one commit per calendar day,
# capped at HISTORY_BACKFILL_MAX_DAYS days) so the chart isn't a single dot
# the first time this feature ships; after that, backfill never runs again
# for that file.

HISTORY_MAX_POINTS = 365
HISTORY_BACKFILL_MAX_DAYS = 90

COVERAGE_HISTORY_PATH = REPO_ROOT / "outputs" / "reports" / "coverage_history.json"
RULE_GROWTH_HISTORY_PATH = REPO_ROOT / "outputs" / "reports" / "rule_growth_history.json"


def compute_rule_version(file_path: str) -> str:
    """
    Same versioning scheme as scripts/convert/sigma_to_spl.py's
    _compute_rule_version(): 1.0 on the first commit, 1.1 on the second, etc.,
    derived from how many commits have touched the rule's Sigma YAML source.
    Uses `git log --follow` (not `git rev-list --count`) so renaming or
    restructuring a rule file never resets its version count.

    rule_version only ever lived in the CI-generated .meta.json sidecar
    (gitignored, never committed) once rules/splunk/*.spl became pure query
    text -- surfacing it here in the rule browser is the only place a repo
    visitor can still see it without digging into a CI run's artifacts.
    """
    if not file_path:
        return ""
    raw = _git(["log", "--follow", "--format=%H", "--", file_path])
    count = len([line for line in raw.splitlines() if line.strip()])
    if count <= 0:
        return ""
    return f"1.{max(0, count - 1)}"


def _git(args: list[str], input_text: str | None = None) -> str:
    """Runs git in REPO_ROOT, returns stdout ('' on any failure).

    Best-effort by design: history mining is a nice-to-have dashboard feature,
    never worth failing the whole stats build over (e.g. shallow clones,
    missing git binary, non-repo checkouts in some CI contexts)."""
    try:
        result = subprocess.run(
            ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True,
            input=input_text, timeout=60,
        )
        return result.stdout if result.returncode == 0 else ""
    except Exception:
        return ""


def _commits_touching(path: str, max_commits: int = 500) -> list[tuple[str, str]]:
    """Returns [(sha, author_iso_date)] newest-first for commits touching `path`."""
    out = _git(["log", "--format=%H,%aI", "-n", str(max_commits), "--", path])
    commits: list[tuple[str, str]] = []
    for line in out.splitlines():
        sha, _, iso = line.partition(",")
        sha, iso = sha.strip(), iso.strip()
        if sha and iso:
            commits.append((sha, iso))
    return commits


def _one_commit_per_day(
    commits: list[tuple[str, str]], max_days: int
) -> list[tuple[str, str, str]]:
    """De-dupes newest-first commits to the single most-recent commit per
    calendar day, bounded to `max_days` days, returned oldest-first (the
    order charts want to plot in)."""
    seen: set[str] = set()
    picked: list[tuple[str, str, str]] = []
    for sha, iso in commits:
        day = iso[:10]
        if day in seen:
            continue
        seen.add(day)
        picked.append((sha, iso, day))
        if len(picked) >= max_days:
            break
    picked.reverse()
    return picked


def _load_history(path: Path, key: str) -> list[dict]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        points = data.get(key, [])
        return points if isinstance(points, list) else []
    except Exception:
        return []


def _save_history(path: Path, key: str, points: list[dict]) -> None:
    if len(points) > HISTORY_MAX_POINTS:
        points = points[-HISTORY_MAX_POINTS:]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({key: points}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def _append_or_replace_today(points: list[dict], new_point: dict) -> list[dict]:
    """Appends a new point, unless the last stored point is already today's
    (a re-run on the same day updates in place instead of duplicating)."""
    if points and points[-1].get("date") == new_point["date"]:
        points[-1] = new_point
    else:
        points.append(new_point)
    return points


def _backfill_stats_history() -> tuple[list[dict], list[dict]]:
    """One-time backfill (only runs while both cache files are still absent)
    for coverage + rule-growth history, mined from historical
    outputs/reports/stats.json commits — a single small JSON file, so one
    `git show` per sampled day is cheap even across ~100+ commits."""
    coverage_points: list[dict] = []
    growth_points: list[dict] = []
    commits = _commits_touching("outputs/reports/stats.json", max_commits=500)
    sampled = _one_commit_per_day(commits, HISTORY_BACKFILL_MAX_DAYS)
    for sha, iso, day in sampled:
        raw = _git(["show", f"{sha}:outputs/reports/stats.json"])
        if not raw:
            continue
        try:
            data = json.loads(raw)
        except Exception:
            continue
        coverage_points.append({
            "date": day,
            "timestamp": iso,
            "git_sha": sha,
            "mitre_covered_techniques": data.get("mitre_covered_techniques", 0),
            "mitre_total_techniques": data.get("mitre_total_techniques", 0),
            "mitre_coverage_pct": data.get("mitre_coverage_pct", 0),
        })
        # total_native_spl_rules counts rules/sigma/*.yml entries with
        # custom.splunk.raw_query set (hand-crafted SPL, no real Sigma
        # detection logic) -- a subset of total_sigma_rules, not disjoint.
        # Older stats.json commits predating this field will fall back to 0.
        growth_points.append({
            "date": day,
            "timestamp": iso,
            "git_sha": sha,
            "total_rules": data.get("total_rules", 0),
            "total_sigma_rules": data.get("total_sigma_rules", 0),
            "total_native_spl_rules": data.get("total_native_spl_rules", 0),
        })
    return coverage_points, growth_points


def update_trend_history(stats: dict) -> tuple[list[dict], list[dict]]:
    """Appends today's data point to each of the 2 history caches (backfilling
    from git history first if a cache file doesn't exist yet), writes the
    caches back to disk, and returns (coverage_points, growth_points) for
    rendering into the Dashboards charts."""
    now_iso = datetime.now(UTC).isoformat()
    today = now_iso[:10]
    current_sha = _git(["rev-parse", "HEAD"]).strip()

    coverage_points = _load_history(COVERAGE_HISTORY_PATH, "points")
    growth_points = _load_history(RULE_GROWTH_HISTORY_PATH, "points")
    if not coverage_points and not growth_points:
        coverage_points, growth_points = _backfill_stats_history()

    coverage_points = _append_or_replace_today(coverage_points, {
        "date": today,
        "timestamp": now_iso,
        "git_sha": current_sha,
        "mitre_covered_techniques": stats.get("mitre_covered_techniques", 0),
        "mitre_total_techniques": stats.get("mitre_total_techniques", 0),
        "mitre_coverage_pct": stats.get("mitre_coverage_pct", 0),
    })
    growth_points = _append_or_replace_today(growth_points, {
        "date": today,
        "timestamp": now_iso,
        "git_sha": current_sha,
        "total_rules": stats.get("total_rules", 0),
        "total_sigma_rules": stats.get("total_sigma_rules", 0),
        "total_native_spl_rules": stats.get("total_native_spl_rules", 0),
    })
    _save_history(COVERAGE_HISTORY_PATH, "points", coverage_points)
    _save_history(RULE_GROWTH_HISTORY_PATH, "points", growth_points)

    return coverage_points, growth_points


def generate_stats() -> dict:
    sigma_rules = load_sigma_rules()
    total_spl_count = count_spl_rules()
    native_spl_count = sum(1 for r in sigma_rules if get_raw_query(r))
    verdicts = load_verdicts()

    by_level: dict[str, int] = {}
    by_status: dict[str, int] = {}
    by_tactic: dict[str, int] = {}

    verified_pass = 0
    verified_fail = 0
    # "NOT_VERIFIED" (deployed + attempted, Atomic test didn't complete in
    # time) is tracked separately from true N/A (never tested at all -- no
    # result.json) so the rule browser can render them as distinct states
    # instead of silently folding NOT_VERIFIED into the old N/A bucket.
    verified_not_verified = 0
    never_tested = 0
    # Verdicts measured against a rule version that no longer exists, and the
    # subset of PASSes that still describe the rule as it stands today. These
    # two drive the pass rate; the four counters above keep their original
    # meaning so the README badges that already query them don't shift under
    # anyone's feet.
    verified_stale = 0
    verified_pass_current = 0
    # Its FAIL counterpart, so the two badges are drawn from the same
    # population. A stale FAIL is no more current evidence than a stale PASS,
    # and a Pass badge on fresh counts beside a Fail badge on all-time counts
    # would quietly imply a worse ratio than the data supports.
    verified_fail_current = 0
    # The two ways verified_stale is reached, reported separately because they
    # call for different reading: superseded is certain (the tested logic is
    # provably not the deployed logic), expired is probabilistic (same logic,
    # older than the review interval).
    verified_superseded = 0
    verified_expired = 0
    rules_detail: list[dict] = []

    for rule in sigma_rules:
        source = "native_spl" if get_raw_query(rule) else "sigma"
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
        verdict_at = v_data.get("run_timestamp", "")
        verdict_rule_version = v_data.get("rule_version", "")
        rule_version = compute_rule_version(rule.get("_file_path", ""))

        # A verdict is only as current as the rule it was measured on. Staleness
        # is derived HERE, at render time, and deliberately not in
        # pass_fail_eval.py: at the moment of measurement every verdict is fresh
        # by definition -- a verdict goes stale later, when someone edits the
        # rule out from under it. Same comparison the browser makes in
        # isVerdictSuperseded() / isVerdictLapsed(), kept in sync so the chart
        # and the table agree.
        # Known limitation: compute_rule_version() derives the version from git
        # history, so a typo fix bumps it exactly like a logic change does. That
        # is why staleness costs a rule its segment in the chart but is NOT
        # counted as a failure -- see the pass-rate denominator below.
        verdict_is_superseded = bool(
            verdict not in ("N/A", "")
            and rule_version
            and verdict_rule_version
            and str(rule_version) != str(verdict_rule_version)
        )
        # The second way a verdict stops being evidence: it simply got old. Same
        # standing as superseded, same remedy, so the same bucket -- what differs
        # is only the diagnosis, and the page labels those separately.
        #
        # Measured against generation time, which is the only clock this script
        # has. The page recomputes it against the reader's clock (see
        # isVerdictLapsed there), so a page left open for months keeps telling
        # the truth while this build-time figure stays a snapshot -- which is
        # exactly what a badge in a README is.
        #
        # This is also what stops the pass rate from freezing: with only the
        # version check, a pipeline that stopped running and a library nobody
        # edited would report the same green number forever.
        # An undateable verdict counts as expired, not as current -- same call
        # the page's isVerdictExpired() makes, and the two have to agree or the
        # chart and the badge would tell different stories. Treating "we cannot
        # tell when this was measured" as current would be an unfalsifiable
        # green, which is the shape of claim this whole mechanism removes.
        _age = _verdict_age_days(verdict_at)
        verdict_is_expired = bool(
            verdict not in ("N/A", "")
            and not verdict_is_superseded
            and (_age is None or _age >= REVIEW_INTERVAL_DAYS)
        )
        verdict_is_stale = verdict_is_superseded or verdict_is_expired

        if verdict == "PASS":
            verified_pass += 1
        elif verdict == "FAIL":
            verified_fail += 1
        elif verdict == "NOT_VERIFIED":
            verified_not_verified += 1
        else:
            never_tested += 1

        if verdict_is_stale:
            verified_stale += 1
            if verdict_is_superseded:
                verified_superseded += 1
            else:
                verified_expired += 1
        elif verdict == "PASS":
            verified_pass_current += 1
        elif verdict == "FAIL":
            verified_fail_current += 1

        if source == "native_spl":
            rule_body = get_raw_query(rule)
            rule_body_lang = "spl"
        else:
            rule_body = extract_sigma_body(rule)
            rule_body_lang = "yaml"

        rules_detail.append({
            "detect_id": detect_id,
            "title": title,
            "description": str(rule.get("description") or ""),
            "level": level,
            "status": status,
            "source": source,
            "verdict": verdict,
            "run_id": run_id,
            "verdict_at": verdict_at,
            "verdict_rule_version": verdict_rule_version,
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
            "rule_version": rule_version,
        })

    # native_spl_count is a subset of sigma_rules (raw_query rules), not a
    # disjoint set -- total/verifiable counts must not add it a second time.
    total_sigma = len(sigma_rules)
    total_rules = total_sigma
    total_verifiable = total_sigma
    # For the "Sigma Rules" badge specifically: rules with real, compiled
    # Sigma detection: logic, excluding the raw_query subset -- so that
    # badge and the "Native SPL" badge next to it are disjoint and sum to
    # total_rules, instead of visually double-counting the same rules.
    total_compiled_sigma_rules = total_sigma - native_spl_count

    # Rules whose verdict still describes the rule as it is today. This is the
    # pass rate's denominator, and the choice matters: counting stale verdicts
    # as failures would be the mirror image of the bug being fixed here (they
    # aren't broken, they're unmeasured), and it would make the headline number
    # get *worse* every time someone tidies a rule -- a metric that punishes
    # maintenance is a metric people learn to ignore. So the pass rate answers
    # "of what we actually measured against the current rule, how much works",
    # and verification_current_pct carries the other half of the truth: how
    # much of the library that measurement covers. The two are published, and
    # rendered, as a pair -- neither is honest read alone.
    verified_current = total_verifiable - verified_stale - never_tested
    pass_rate = round(verified_pass_current / verified_current * 100) if verified_current > 0 else 0
    verification_current_pct = (
        round(verified_current / total_verifiable * 100) if total_verifiable > 0 else 0
    )
    # The product of the two above: rules confirmed working against their
    # present-day logic, as a share of the whole library. Deliberately not the
    # headline -- it's derived, and a single number that fuses "does it work"
    # with "did we check recently" is exactly the conflation this fixes.
    confirmed_working_pct = (
        round(verified_pass_current / total_verifiable * 100) if total_verifiable > 0 else 0
    )

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
    now_iso = datetime.now(UTC).isoformat()

    result = {
        "generated_at": now_iso,
        "total_rules": total_rules,
        "total_sigma_rules": total_sigma,
        "total_compiled_sigma_rules": total_compiled_sigma_rules,
        "total_splunk_rules": total_spl_count,
        "total_native_spl_rules": native_spl_count,
        "verified_pass": verified_pass,
        "verified_fail": verified_fail,
        "verified_not_verified": verified_not_verified,
        "never_tested": never_tested,
        # Kept as the union of never_tested + verified_not_verified for
        # backward compatibility -- the README's shields.io badge already
        # queries stats.json's "not_verified" key by URL, so its scope
        # (anything not confirmed PASS/FAIL) stays the same; the rule
        # browser uses the two split counts above for its own chart segment.
        "not_verified": verified_not_verified + never_tested,
        # Verdicts measured on a rule version that has since changed, and the
        # PASS/current-coverage figures derived from excluding them. Added
        # alongside the counters above rather than replacing them: the shields
        # badges query stats.json by key over a raw URL, so a removed key is a
        # broken badge on every README revision that ever pointed at it.
        "verified_stale": verified_stale,
        "verified_superseded": verified_superseded,
        "verified_expired": verified_expired,
        "verified_pass_current": verified_pass_current,
        "verified_fail_current": verified_fail_current,
        "verified_current": verified_current,
        # NOTE: pass_rate_pct changed meaning in the 1.2 remediation. It was
        # verified_pass / total_rules (every PASS ever recorded, however old);
        # it is now verified_pass_current / verified_current -- of the rules we
        # measured against their present-day logic, how many work. Read it
        # together with verification_current_pct, never on its own.
        "pass_rate_pct": pass_rate,
        "pass_rate_color": pass_rate_color(pass_rate),
        "verification_current_pct": verification_current_pct,
        "verification_current_color": pass_rate_color(verification_current_pct),
        "confirmed_working_pct": confirmed_working_pct,
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

    # Dashboards "Trends Over Time" section — see update_trend_history()
    # docstring for the git-history-backed caching approach. Kept private
    # (not written to stats.json): these are raw per-day arrays meant only
    # for the Chart.js dashboard, not the shields.io badge consumers of
    # stats.json.
    coverage_history, growth_history = update_trend_history(result)
    result["_coverage_history"] = coverage_history
    result["_rule_growth_history"] = growth_history

    return result


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
        f"[![Sigma Rules]({b}&query=%24.total_compiled_sigma_rules&label=Sigma%20Rules&color=00ACD7)](https://github.com/martonbence/Detection-Engineering/tree/main/rules/sigma)",
        f"[![Native SPL]({b}&query=%24.total_native_spl_rules&label=Native%20SPL&color=FF6600)](https://github.com/martonbence/Detection-Engineering/tree/main/rules/splunk)",
    ])
    # Pass Rate and Verified Current ship as a pair, in that order and adjacent.
    # Pass Rate is now measured only against rules whose verdict still matches
    # their current version, so on its own it says nothing about how much of the
    # library that covers -- and a lone badge is exactly what gets quoted. The
    # second badge makes the coverage impossible to drop.
    row3 = " ".join([
        f"![Pass]({b}&query=%24.verified_pass_current&label=Pass&color=brightgreen)",
        f"![Fail]({b}&query=%24.verified_fail_current&label=Fail&color=red)",
        f"![Pass Rate]({b}&query=%24.pass_rate_pct&label=Pass%20Rate%20%25&color={stats['pass_rate_color']})",
        f"![Verified Current]({b}&query=%24.verification_current_pct&label=Verified%20Current%20%25&color={stats['verification_current_color']})",
        # verified_stale is the union of superseded and expired, and the page
        # deliberately never coined an umbrella word for that pair -- it names
        # both plainly instead. A badge has room for one word, so it takes the
        # one thing the two cases share that a reader can act on: they need
        # measuring again. Naming the remedy also beats naming the state here,
        # where there is no space to explain which state it was.
        f"![Needs Re-run]({b}&query=%24.verified_stale&label=Needs%20Re-run&color=BC8CFF)",
        f"![Not Verified]({b}&query=%24.not_verified&label=Not%20Verified&color=lightgrey)",
    ])
    for row in [row1, "", row2, "", row3]:
        lines.append(row)
    lines.append("")

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


# The page is three asset files next to this script rather than one
# multi-thousand-line string literal: assets/page.template.html carries the
# markup, assets/page.css and assets/page.js the styling and the behaviour it
# inlines. The split costs one assembly step and buys CSS and JS that an editor,
# a linter and a diff can all read as what they are.
#
# The assets are not servable on their own. They still carry the @@MARKER@@
# placeholders render_html_summary() substitutes, and the stylesheet and script
# are inlined rather than linked, so the published page stays a single
# self-contained file.
#
# They are read verbatim: no escaping, no interpolation, exactly what the
# r"""...""" literal used to hold, so a backslash in a JS regex is still a
# backslash. Paths resolve against __file__ because the workflow invokes this
# script by path and the working directory is not guaranteed.
_ASSETS_DIR = Path(__file__).resolve().parent / "assets"

# The two markers that inline the stylesheet and the script into the markup.
# Each sits alone on its own line, and the line break is part of the match: the
# asset files end with a newline of their own, so replacing the marker without
# its newline would insert a blank line and shift the output.
_INLINE_ASSETS = (("@@INLINE_CSS@@\n", "page.css"), ("@@INLINE_JS@@\n", "page.js"))

_page_template_cache: str | None = None


def _read_asset(name: str) -> str:
    """Read one page asset, or fail loudly naming the file that is missing.

    Line endings are normalised on read (the default universal-newline mode), so
    a checkout that materialises the assets with CRLF still renders byte-for-byte
    the same page as one that keeps LF.
    """
    path = _ASSETS_DIR / name
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise SystemExit(
            f"generate_stats.py: page asset not found: {path}\n"
            f"docs/index.html is assembled from page.template.html, page.css and "
            f"page.js in {_ASSETS_DIR}; without all three the page would render "
            f"half-built, so nothing is written."
        ) from None


DEPLOYMENT_INVENTORY_PATH = Path("outputs/reports/deployment_inventory.json")


def load_deployment_inventory(path: Path = DEPLOYMENT_INVENTORY_PATH) -> dict:
    """The deployment inventory, or an empty dict (register item 4.7).

    Absent is a normal state, not an error: the file appears the first time a
    run deploys anything, and until then the page simply has no deployment
    panel. Every other input to this generator describes the repo, which is
    always here; this one describes two Splunk instances that the generator
    cannot reach and must not pretend to know about.
    """
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"WARNING: could not read {path}: {exc}", file=sys.stderr)
        return {}
    return data if isinstance(data, dict) else {}


def _relative_age(iso: str) -> str:
    """"3 days ago", or "" when the timestamp is missing or unparseable.

    Deliberately coarse. The point of the age is whether anyone has looked
    recently, and a precise duration invites reading it as a measurement when
    it is really a staleness signal.
    """
    if not iso:
        return ""
    try:
        when = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)

    days = (datetime.now(UTC).date() - when.astimezone(UTC).date()).days
    if days <= 0:
        return "today"
    if days == 1:
        return "yesterday"
    return f"{days} days ago"


def _deployment_env_html(env: str, section: dict, repo: str) -> str:
    """One environment's column: what we sent, and what is actually there."""
    deploy = section.get("last_deploy") or {}
    state = section.get("splunk_state") or {}

    rules = deploy.get("rules") or {}
    commit = str(deploy.get("commit") or "")
    run_url = str(deploy.get("run_url") or "")
    deployed_at = str(deploy.get("at") or "")

    rows = []

    if deploy:
        age = _relative_age(deployed_at)
        when = _html.escape(deployed_at[:16].replace("T", " ")) if deployed_at else "unknown"
        when_cell = f"{when}<span class=\"dep-age\">{_html.escape(age)}</span>" if age else when
        rows.append(("Last deployed", when_cell))
        # Only when we actually counted them. Prod's entry is assembled from the
        # Actions API rather than from a deploy report, so there is no per-rule
        # map to size -- and rendering "0" for "not recorded here" would be the
        # page stating something false in the one panel that exists to stop it.
        if rules:
            rows.append(("Rules deployed", str(len(rules))))
        if commit:
            short = _html.escape(commit[:7])
            link = f"https://github.com/{repo}/commit/{_html.escape(commit)}"
            rows.append(("From commit", f'<a href="{link}" target="_blank" rel="noopener"><code>{short}</code></a>'))
        if run_url:
            rows.append(("CI run", f'<a href="{_html.escape(run_url)}" target="_blank" rel="noopener">workflow run</a>'))
    else:
        rows.append(("Last deployed", '<span class="dep-unknown">no deploy recorded</span>'))

    if state:
        checked = _relative_age(str(state.get("checked_at") or "")) or "unknown"
        drift = bool(state.get("has_drift"))
        # The two halves are stated separately on purpose. "We sent 27" staying
        # true while "27 are there" stops being true is exactly the 2026-08-07
        # case this panel exists for, and merging them would hide it again.
        verdict = (
            '<span class="dep-drift">drift — see the audit run</span>'
            if drift
            else '<span class="dep-ok">matches the repo</span>'
        )
        rows.append(("Splunk checked", _html.escape(checked)))
        rows.append(("Comparison", verdict))
        if drift:
            detail = ", ".join(
                f"{state.get(key) or 0} {key.replace('_', ' ')}"
                for key in ("missing", "orphan_renamed", "duplicate_names")
                if state.get(key)
            )
            unretired = state.get("orphan_removed_unretired") or 0
            if unretired:
                detail = ", ".join(filter(None, [detail, f"{unretired} awaiting retirement"]))
            if detail:
                rows.append(("What differs", _html.escape(detail)))
    else:
        rows.append(("Splunk checked", '<span class="dep-unknown">never</span>'))

    body = "".join(
        f'<tr><th scope="row">{_html.escape(label)}</th><td>{value}</td></tr>' for label, value in rows
    )
    return (
        f'<div class="dep-env"><div class="dep-env-name">{_html.escape(env)}</div>'
        f'<table class="dep-table"><tbody>{body}</tbody></table></div>'
    )


def render_deployment_html(inventory: dict, repo: str) -> str:
    """The whole panel, or an empty string when there is nothing to say."""
    environments = inventory.get("environments") if isinstance(inventory, dict) else None
    if not isinstance(environments, dict) or not environments:
        return ""

    # dev before prod when both exist, because that is the direction the
    # pipeline runs; anything else in alphabetical order rather than dict order,
    # so the panel does not reshuffle itself between builds.
    order = sorted(environments, key=lambda name: (name != "dev", name != "prod", name))
    columns = "".join(_deployment_env_html(env, environments[env] or {}, repo) for env in order)

    return f"""<div class="dash-section">
      <div class="dash-section-title">Deployment</div>
      <div class="info-note">Where each rule set actually lives. Everything else on this page
      describes the repository; this describes the two Splunk apps it deploys to, recorded by the
      pipeline itself. <strong>Last deployed</strong> is what we sent. <strong>Splunk checked</strong>
      is when anything last looked at what is really there &mdash; the two can disagree, and that
      disagreement is the point.</div>
      <div class="dep-grid">{columns}</div>
    </div>"""


def load_page_template() -> str:
    """The full page template, assembled from its assets and cached per run."""
    global _page_template_cache
    if _page_template_cache is None:
        template = _read_asset("page.template.html")
        for marker, asset in _INLINE_ASSETS:
            template = template.replace(marker, _read_asset(asset))
        _page_template_cache = template
    return _page_template_cache


def _github_blob_url(repo: str, file_path: str) -> str:
    return f"https://github.com/{repo}/blob/main/{file_path}" if file_path else ""


def render_html_summary(stats: dict, repo: str) -> str:
    ts = stats["generated_at"][:19]
    total = stats["total_rules"]
    passed = stats["verified_pass"]
    failed = stats["verified_fail"]
    not_ver = stats.get("verified_not_verified", 0)
    never_tested = stats.get("never_tested", stats.get("not_verified", 0))
    pass_rate = stats["pass_rate_pct"]
    verified_current = stats.get("verified_current", total)
    mitre_covered = stats.get("mitre_covered_techniques", 0)
    mitre_total = stats.get("mitre_total_techniques", 0)
    mitre_pct = stats.get("mitre_coverage_pct", 0.0)

    rules_js = []
    for r in stats["rules"]:
        ls = r.get("logsource") or {}
        testing = r.get("testing") or {}
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
            "ruleVersion": r.get("rule_version", ""),
            "verdictAt": r.get("verdict_at", ""),
            "verdictRuleVersion": r.get("verdict_rule_version", ""),
            "verifyMethod": VERIFY_METHOD_LABELS.get(
                testing.get("type", ""), testing.get("type", "")
            ),
            "verifyRunner": testing.get("runner", ""),
            "references": r.get("references") or [],
            "ruleBody": r.get("rule_body", ""),
            "ruleBodyLang": r.get("rule_body_lang", ""),
        })

    rules_json = json.dumps(rules_js, ensure_ascii=False)
    tactic_ids_json = json.dumps(TACTIC_ID_MAP, ensure_ascii=False)

    coverage_history_json = json.dumps(stats.get("_coverage_history", []), ensure_ascii=False)
    rule_growth_history_json = json.dumps(stats.get("_rule_growth_history", []), ensure_ascii=False)

    technique_map = stats.get("_technique_map", [])
    rules_detail_inner = stats.get("_rules_detail", stats.get("rules", []))
    technique_coverage = build_technique_coverage(rules_detail_inner, repo)
    matrix_html = _build_matrix_html(technique_map, technique_coverage)
    # Raw URL, not the blob page: this is what you paste into the official
    # Navigator's "Open Existing Layer → Load from URL" (raw.githubusercontent
    # serves it with CORS), and it still saves fine straight from the browser.
    layer_url = (
        f"https://raw.githubusercontent.com/{repo}/main/outputs/reports/navigator_layer.json"
    )

    html = load_page_template()
    html = html.replace("@@DEPLOYMENT_HTML@@", render_deployment_html(load_deployment_inventory(), repo))
    html = html.replace("@@TS@@", ts)
    html = html.replace("@@TOTAL@@", str(total))
    html = html.replace("@@PASSED@@", str(passed))
    html = html.replace("@@FAILED@@", str(failed))
    html = html.replace("@@NOT_VER@@", str(not_ver))
    html = html.replace("@@NEVER_TESTED@@", str(never_tested))
    # Render as a whole number so the Pass Rate overlay matches the Status
    # chart's Stable % (also integer) — no stray decimal on one but not the other.
    html = html.replace("@@PASS_RATE@@", str(round(pass_rate)))
    html = html.replace("@@VERIFIED_CURRENT@@", str(verified_current))
    html = html.replace("@@MITRE_COVERED@@", str(mitre_covered))
    html = html.replace("@@MITRE_TOTAL@@", str(mitre_total))
    html = html.replace("@@MITRE_PCT@@", str(mitre_pct))
    html = html.replace("@@RULES_JSON@@", rules_json)
    html = html.replace("@@TACTIC_IDS_JSON@@", tactic_ids_json)
    html = html.replace("@@COVERAGE_HISTORY_JSON@@", coverage_history_json)
    html = html.replace("@@RULE_GROWTH_HISTORY_JSON@@", rule_growth_history_json)
    html = html.replace("@@MATRIX_HTML@@", matrix_html)
    html = html.replace("@@LAYER_URL@@", layer_url)
    html = html.replace("@@REVIEW_DAYS@@", str(REVIEW_INTERVAL_DAYS))
    owner, name = repo.split("/", 1)
    html = html.replace("@@PAGE_URL@@", f"https://{owner}.github.io/{name}/")
    # Plain text, no markup: this lands inside a double-quoted meta attribute,
    # so a stray quote would end the attribute early. Nothing here is
    # user-supplied, but the escape keeps that true if the wording ever is.
    meta_desc = (
        f"Searchable index of {total} Sigma and native SPL detection rules with "
        f"MITRE ATT&amp;CK mapping, Atomic Red Team verification verdicts "
        f"({pass_rate:.0f}% pass rate across the {verified_current} of {total} rules "
        f"verified against their current version) and {mitre_covered} techniques covered."
    ).replace('"', "&quot;")
    return html.replace("@@META_DESC@@", meta_desc)
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
        f"{stats['not_verified']} not verified / {stats['verified_stale']} outdated — "
        f"pass rate: {stats['pass_rate_pct']}% of the {stats['verified_current']} "
        f"rule(s) verified against their current version "
        f"({stats['verification_current_pct']}% of the library)"
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
