#!/usr/bin/env python3
# .claude/generate_dashboard.py
#
# Generates the internal team-ops dashboard: a single self-contained HTML
# page (top tab strip, Overview / Agents / Team / Skills / MCP / Activity /
# Tokens) describing the custom subagent team and the repo it works on.
#
# Not part of the detection-rule pipeline -- it is an internal ops page for
# the team itself, which is why the generator lives under .claude/.
# Ownership (2026-08-25): the generator code, HTML structure, CSS and layout
# are Sienna's (Frontend Engineer); the roster *data* (ROSTER/TREE/BIOS
# below -- who is on the team, who reports to whom, the per-member bios) is
# Gaz's call, anchored to CLAUDE.md. Same split as the rule browser (the
# "Console"), where Sienna owns the page and Kwame/Gaz own what rules exist.
#
# Outputs (one run writes BOTH, from the same render, differing only in
# relative asset paths -- see OUT_PATH / PAGES_OUT_PATH below):
#   - .claude/team-ops.html  local copy, assets via ../docs/pictures/...
#   - docs/team-ops.html     the copy GitHub Pages serves (docs/ is the whole
#                            Pages artifact), assets via pictures/...
# A straight file copy would not work: the <img> paths only resolve relative
# to each file's own location. CI (ci_dev_workflow.yml update_dashboard,
# ci_prod_workflow.yml) re-runs this script before every Pages publish.
#
# Every number on the page is derived at generation time from files in this
# repo -- nothing is hardcoded, and a missing source renders as "not
# available" rather than a made-up value:
#   - .claude/agent_usage_log.jsonl    per-dispatch tokens/tool uses/duration/
#                                      model. A row only exists when Gaz read a
#                                      real <usage> block back from a dispatch;
#                                      silence means "not logged", not zero work.
#   - git log                          the Activity feed (read fresh each run)
#   - audit/*.md                       register checkbox progress
#   - CLAUDE.md                        roster "Owns" column (Team tab)
#   - .claude/agents/*.md              allowed tools, skill references
#   - .claude/skills/*/SKILL.md        skill names/descriptions
#   - .claude/commands/*.md            slash-command descriptions
#   - .mcp.json                        MCP server names + transport/command.
#                                      env values, headers and URLs are never
#                                      rendered (only an http server's host).
#
# Visual language: matches the Console (scripts/docs/assets/page.css) -- navy
# + two radial washes, glass cards, amber pill tabs, amber section pills,
# solid-amber table headers with oklch zebra rows. See the web-visual-system
# skill. The org chart's node/connector layout is deliberately untouched by
# the 2026-10 English/Console-alignment rework; only the panel behind it moved
# to the glass-card style.
#
# Run: python3 .claude/generate_dashboard.py

from __future__ import annotations

import html
import json
import re
import subprocess
from collections import Counter, defaultdict
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
LOG_PATH = HERE / "agent_usage_log.jsonl"
OUT_PATH = HERE / "team-ops.html"
PAGES_OUT_PATH = REPO_ROOT / "docs" / "team-ops.html"
CLAUDE_MD = REPO_ROOT / "CLAUDE.md"
AGENTS_DIR = HERE / "agents"
SKILLS_DIR = HERE / "skills"
COMMANDS_DIR = HERE / "commands"
MCP_JSON = REPO_ROOT / ".mcp.json"

# Relative to .claude/team-ops.html, so <img> tags resolve straight off disk.
LOCAL_AVATAR_DIR_REL = "../docs/pictures/avatars"
LOCAL_LOGO_REL = "../docs/pictures/branding/logo.png"
# Relative to docs/team-ops.html once published on Pages.
PAGES_AVATAR_DIR_REL = "pictures/avatars"
PAGES_LOGO_REL = "pictures/branding/logo.png"

ACTIVITY_LIMIT = 400  # commits read from git log; the feed is filtered client-side
ACTIVITY_CHART_DAYS = 60
RECENT_DISPATCHES = 25

# Chart-only grouping (2026-08-25, user's explicit ask) -- NOT the CLAUDE.md
# Strategic/Analytical/Operational Area column. Purple = leadership, green =
# strategic, blue = engineering/technology, amber = compliance/docs, teal =
# Bjorn as the engineering group's coordinator.
AREA_COLORS = {
    "leadership": {"fill": "#2c1b4d", "stroke": "#b388ff", "text": "#f1e6ff"},
    "strategic": {"fill": "#12351f", "stroke": "#4caf7d", "text": "#dcf7ee"},
    "engineering": {"fill": "#0d2440", "stroke": "#58a6ff", "text": "#dceeff"},
    "compliance": {"fill": "#3d2c07", "stroke": "#e0a94c", "text": "#fdecc9"},
    "coordinator": {"fill": "#0d3b36", "stroke": "#2dd4bf", "text": "#d3fff5"},
}

# Kept in sync by hand with CLAUDE.md's roster table. name, role, chart-color
# group (AREA_COLORS), agent slug (None for Gaz -- the top-level session,
# never dispatched via the Agent tool).
ROSTER = [
    ("Gaz", "Engineering Lead", "leadership", None),
    ("Yara", "Technology Strategist", "strategic", "yara-ideation"),
    ("Kwame", "Compliance Analyst", "strategic", "kwame-audit-compliance"),
    ("Masha", "Threat Intelligence Analyst", "compliance", "masha-threat-intel"),
    ("Yuki", "Detection Engineer", "engineering", "yuki-detection-engineer"),
    ("Bjorn", "Detection Quality Engineer", "coordinator", "bjorn-detection-content-reviewer"),
    ("Chloe", "Technical Writer", "compliance", "chloe-docs-maintainer"),
    ("Jamal", "DevOps Engineer", "engineering", "jamal-devops-engineer"),
    ("Sienna", "Frontend Engineer", "engineering", "sienna-frontend-engineer"),
    ("Kai", "Platform Engineer", "engineering", "kai-github-ops"),
    ("Priya", "Application Security Engineer", "compliance", "priya-security-scanner"),
]

# Per-member bios (Gaz's data). Moved here 2026-09-01 from the retired
# TEAM.md; tagline + personality bio added 2026-10. Rendered on the Agents
# tab: tagline and bio up top, `scope` (the longer role description) beneath
# as "Role scope". `area` is CLAUDE.md's Strategic / Analytical / Operational
# column -- NOT the chart-colour group in ROSTER.
BIOS: dict[str, dict[str, str]] = {
    "Gaz": {
        "area": "Strategic",
        "tagline": "Keeps the whole team in view so you only have to talk to one person.",
        "bio": "Gaz is the single point of contact: the one who turns a request into a plan, hands each piece to the right specialist, and reports back in plain words. Steady and unhurried, with a habit of saying who is doing what before anyone asks.",
        "scope": "The one point of contact, and the top-level session itself — always already running. Turns a request into a task, splits it into subtasks along the scope boundaries, delegates each to the right specialist, stays in contact while they work, and reports back. Only does a specialist's job when no one below owns it yet. Has no dispatchable subagent — CLAUDE.md is the source of truth for what Gaz does.",
        "works": "Yara and Kwame on direction-setting (the strategic trio); routes work to and takes reports from all ten specialists.",
    },
    "Bjorn": {
        "area": "Operational",
        "tagline": "Reads every rule like the one that will page someone at 3 a.m.",
        "bio": "Bjorn is the team's careful reviewer: logic, false-positive risk, tag accuracy, overlap and test evidence. Exacting but kind, he says what is good before what is not, and names what he did not re-verify.",
        "scope": "Reviews rule quality, never authors: whether a Sigma rule's detection block implements what its title and description claim, whether the listed false positives are realistic, whether its MITRE ATT&CK tag genuinely matches the technique, and whether it overlaps unnoticed with another rule. Also heads the engineering group's quality gate — real functional/structural work from Yuki, Jamal, Sienna and Kai passes him before it counts as done — and owns repo-wide file-hygiene audits.",
        "works": "Yuki — the tightest single pair on the team, one author, one reviewer, every rule.",
    },
    "Yuki": {
        "area": "Operational",
        "tagline": "Turns attacker behaviour into rules, one careful selection at a time.",
        "bio": "Yuki writes the repo's Sigma detections end to end, from scaffold to ATT&CK tags. Hands-on and a little perfectionist about matching what attackers really run, and glad to have Bjorn read every draft.",
        "scope": "Writes new detections. Starts every rule from scripts/new_rule.py's scaffold, fills in the real detection logic (or the custom.splunk.raw_query escape hatch for logic too complex for Sigma's block syntax), and tags it via the mitre-attack-mapping skill. Follows the sigma-rule-authoring skill for this repo's conventions — including the hard rule that a rule's author field records real accountability and is never a persona name. Hands every finished rule to Bjorn; never self-approves.",
        "works": "Bjorn on every rule; Masha and Yara as intake for what to build next; Chloe, who documents the results.",
    },
    "Jamal": {
        "area": "Operational",
        "tagline": "Has already watched the pipeline fail every way it can, and just fixes it.",
        "bio": "Jamal owns the CI/CD workflows and every script they call. Unflappable and practical, he debugs from the real run logs rather than from the YAML alone.",
        "scope": "Owns the CI/CD pipeline as code: the four GitHub Actions workflows and every script along the Sigma → validate → convert → deploy → Atomic Red Team → verify → reconcile → docs-generation chain, plus the pipeline's own test and lint gates. Not repo settings, secrets or runner registration — that is Kai.",
        "works": "Sienna, whose generated rule browser his CI publishes; Kai on the pipeline / platform boundary; Kwame and Priya, who verify and audit his surface.",
    },
    "Chloe": {
        "area": "Operational",
        "tagline": "If the repo does it, she makes sure the docs say it.",
        "bio": "Chloe keeps the README and architecture docs true to what the scripts and workflows actually do. Tidy and thorough, she trusts the code over old prose.",
        "scope": "Keeps README.md and the docs/architecture/*.md deep-reference pages consistent with the actual state of the pipeline. Triggered after any structural change to scripts/, rules/, the CI workflows, the MCP setup, or the team roster itself. Does not touch the team's own operating files (CLAUDE.md, agent and skill definitions) — those are Gaz's.",
        "works": "Jamal and Yuki, documenting what changes on their surfaces; Kai on PR mechanics for doc changes.",
    },
    "Sienna": {
        "area": "Operational",
        "tagline": "Makes the data legible, then makes it pleasant.",
        "bio": "Sienna builds the Console (the rule browser) and the internal team-ops dashboard, covering both the code and the design. She notices the pixel that is off and the contrast that is too low.",
        "scope": "Owns the rule browser: docs/index.html (generated, never hand-edited), scripts/docs/generate_stats.py and its assets (template, CSS, JS), plus the MITRE Navigator view. Also owns this dashboard — .claude/generate_dashboard.py and team-ops.html. Covers implementation and design decisions alike, since these are small generated static pages with no separate design handoff.",
        "works": "Jamal, whose CI publishes her output; Kai on PR / merge mechanics; Kwame, who verifies her register items for drift.",
    },
    "Kai": {
        "area": "Operational",
        "tagline": "Keeps the GitHub side steady so everyone else can ship.",
        "bio": "Kai handles branches, PRs, merges, secrets, runners and releases. Easygoing and careful at once, he explains what a change does and does not protect before touching shared state.",
        "scope": "Handles the GitHub platform side — branches, PRs, merge conflicts (walked through with the user, never resolved unilaterally), releases and tags, repo settings, secrets, and self-hosted runner registration. Not the content that moves through those mechanisms — that belongs to whoever owns it.",
        "works": "Jamal, Sienna and Chloe on PR / merge mechanics for their content; Priya on secrets and repo-settings exposure findings.",
    },
    "Yara": {
        "area": "Strategic",
        "tagline": "Always asking what the program should become next, and why.",
        "bio": "Yara looks across the whole repo (pipeline, Console, process, coverage) and proposes where it could go. She argues for a short list of strong ideas over a long list of shallow ones.",
        "scope": "Not a detection-only role: strategic ideation across the whole repo — pipeline and tooling direction, rule-browser and dashboard features, process improvements, future standalone tools for the wider lifecycle, and detection-coverage gaps against the MITRE Navigator data, all as one portfolio. Operates at the same strategic level as Gaz and Kwame. Never writes production code; a greenlit idea is routed by Gaz to whoever owns that surface.",
        "works": "Gaz and Kwame (strategic peers, across every surface); Masha, cross-checking detection-coverage findings against external threat data.",
    },
    "Masha": {
        "area": "Analytical",
        "tagline": "Looks outside the walls to see what is actually coming.",
        "bio": "Masha tracks real adversary campaigns, exploited CVEs and CTI reporting, and turns them into a ranked brief of what to detect next. Always sources her claims and says so when the evidence is thin.",
        "scope": "Looks outward instead of inward. Where Yara mines this repo's own coverage gaps, Masha researches what attackers are actually doing right now — CTI vendor reports, actively-exploited CVEs, MITRE ATT&CK group and software pages — and turns it into a prioritized, sourced brief on what is worth detecting next. Cross-checks every finding against what is already covered. Research and reporting only.",
        "works": "Yara, cross-checking gap analysis; Gaz, delivering prioritized briefs; Yuki, direct handoff when a finding is ready to build.",
    },
    "Priya": {
        "area": "Operational",
        "tagline": "Finds the risky thing before it finds you.",
        "bio": "Priya audits the repo's own code, workflows and dependencies for real security problems. Direct and pragmatic, she ranks findings by genuine exploitability in this repo.",
        "scope": "Audits the repo's own code and configuration — Python scripts, GitHub Actions workflows, config and schemas — for vulnerabilities, secrets and risky CI configuration, using semgrep plus supplementary open-source scanners. This is about securing the pipeline's engineering, not the detection rules' subject matter.",
        "works": "Jamal, flagging findings on pipeline code and CI config; Kai, on secrets and repo-settings exposure.",
    },
    "Kwame": {
        "area": "Strategic",
        "tagline": "Trust, but check the commit.",
        "bio": "Kwame audits the remediation registers against what the repo actually does, not what the status column claims. Patient and fair, he reports progress as it really is, good news included.",
        "scope": "Keeps the pipeline remediation register honest. audit/remediation-plan.md is maintained by hand, so it drifts — an item can be marked done when the code has since moved on, and the rendered register.html can fall out of sync with the source markdown. Kwame verifies claims against the actual repo state, catches that drift, and reports accurate progress plus the real next item. Verifies and reports, never implements.",
        "works": "Gaz and Yara (strategic peers) on what the program should prioritize next; Jamal and Sienna, whose surfaces carry the most register items to verify.",
    },
}

# CLAUDE.md Area chips (Agents/Team tabs). Opaque fill + bright text + border
# of the same hue, the Console's badge recipe. fill, stroke.
AREA_CHIP = {
    "Strategic": ("#2c1b4d", "#b388ff"),
    "Analytical": ("#3d2c07", "#e0a94c"),
    "Operational": ("#0d2440", "#58a6ff"),
}

# Direct-report tree (2026-08-25): parent -> children. Single source of truth
# for the org chart's connector lines (drawOrgLines() in the page script).
TREE: dict[str, list[str]] = {
    "Gaz": ["Yara", "Kwame"],
    "Yara": ["Bjorn"],
    "Kwame": ["Masha", "Priya", "Chloe"],
    "Bjorn": ["Yuki", "Jamal", "Sienna", "Kai"],
}

# The tree's root. Named once here because the connector routing treats it as
# a special case (top-down bus instead of 9 o'clock trunks) and both the Python
# and JS sides have to agree on who that is.
ROOT = "Gaz"


def _build_relationships() -> list[tuple[str, str]]:
    edges: list[tuple[str, str]] = []

    def walk(parent: str) -> None:
        for child in TREE.get(parent, []):
            edges.append((parent, child))
            walk(child)

    walk(ROOT)
    return edges


RELATIONSHIPS = _build_relationships()

# Chart layout (round 9, 2026-08-25, user-approved -- do not change without
# asking): the flexbox staircase tree. Two branch columns, one per top-level
# branch off Gaz, both stair-stepping left-to-right; .branches'
# justify-content: space-between anchors each column to its panel edge. Node
# positions are laid out live by flexbox, so drawOrgLines() measures them with
# getBoundingClientRect() at render time.
BRANCH_LAYOUT: list[tuple[str, list[list[str]]]] = [
    ("Yara", [["Bjorn"], ["Jamal"], ["Kai"], ["Sienna"], ["Yuki"]]),
    ("Kwame", [["Masha"], ["Priya"], ["Chloe"]]),
]

INDENT_STEP_REM = 3.25  # staircase indent per depth-step, in rem


def _build_depth_map() -> dict[str, int]:
    """BFS distance from the root over TREE; a branch node's staircase indent
    is depth[name] - depth[branch_head]."""
    depth: dict[str, int] = {ROOT: 0}

    def walk(parent: str) -> None:
        for child in TREE.get(parent, []):
            depth[child] = depth[parent] + 1
            walk(child)

    walk(ROOT)
    return depth


DEPTH = _build_depth_map()
ROSTER_NAMES = [r[0] for r in ROSTER]
ROSTER_BY_NAME: dict[str, tuple[str, str]] = {name: (role, area) for name, role, area, _ in ROSTER}
SLUG_TO_NAME = {slug: name for name, _r, _a, slug in ROSTER if slug}

# key, label
NAV_ITEMS = [
    ("overview", "Overview"),
    ("agents", "Agents"),
    ("team", "Team"),
    ("skills", "Skills"),
    ("mcp", "MCP"),
    ("activity", "Activity"),
    ("tokens", "Tokens"),
]

NA = '<span class="na">not available</span>'


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


# --- data loading ---------------------------------------------------------------


def load_usage_rows() -> tuple[list[dict], int]:
    """Every well-formed row of the usage log, plus a count of skipped lines.
    `model` is optional (absent in early rows); numeric fields default to 0."""
    rows: list[dict] = []
    skipped = 0
    if not LOG_PATH.is_file():
        return rows, skipped
    for raw in LOG_PATH.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
            row = {
                "date": str(rec["date"]),
                "name": str(rec.get("name") or SLUG_TO_NAME.get(rec.get("slug"), rec.get("slug")) or "unknown"),
                "slug": rec.get("slug"),
                "task": str(rec.get("task") or ""),
                "tokens": int(rec.get("tokens") or 0),
                "tool_uses": int(rec.get("tool_uses") or 0),
                "duration_ms": int(rec.get("duration_ms") or 0),
                "model": (str(rec["model"]).strip() if rec.get("model") else ""),
            }
            date.fromisoformat(row["date"])
        except (ValueError, KeyError, TypeError):
            skipped += 1
            continue
        rows.append(row)
    return rows, skipped


def model_family(label: str) -> str:
    low = label.lower()
    for fam in ("opus", "sonnet", "haiku"):
        if fam in low:
            return fam.capitalize()
    return label or "not recorded"


STOPWORDS = set(
    """a an the and or of to for in on at by with from into via vs per as is are be it its this that these those
    not no non new fix fixes add adds added review reviews check checks follow followup up out off re after before
    pass round block part item items step steps task final quick full real minor small only also plus vs into than
    what when which who why how then them they their there here over under about all any each both one two three
    rule rules work report""".split()  # noqa: SIM905 -- readable word block beats a 600-char list literal
)


NAME_WORDS = {r[0].lower() for r in ROSTER}


def top_keywords(tasks: list[str], n: int = 4) -> list[str]:
    counts: Counter[str] = Counter()
    for t in tasks:
        for w in re.findall(r"[A-Za-z][A-Za-z\-]{3,}", t.lower()):
            w = w.strip("-")
            if w and w not in STOPWORDS and w not in NAME_WORDS:
                counts[w] += 1
    return [w for w, c in counts.most_common(n) if c >= 2] or [w for w, _ in counts.most_common(min(n, 2))]


def member_usage(rows: list[dict]) -> dict[str, dict]:
    stats: dict[str, dict] = defaultdict(lambda: {"dispatches": 0, "tokens": 0, "tool_uses": 0, "duration_ms": 0, "last": None, "tasks": []})
    for r in rows:
        s = stats[r["name"]]
        s["dispatches"] += 1
        s["tokens"] += r["tokens"]
        s["tool_uses"] += r["tool_uses"]
        s["duration_ms"] += r["duration_ms"]
        s["tasks"].append(r["task"])
        if s["last"] is None or r["date"] > s["last"]:
            s["last"] = r["date"]
    return stats


def load_activity() -> list[dict] | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "log", f"-n{ACTIVITY_LIMIT}", "--pretty=format:%h%x1f%an%x1f%ad%x1f%s", "--date=format:%Y-%m-%d %H:%M"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            encoding="utf-8",
            check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    items = []
    for line in out.splitlines():
        parts = line.split("\x1f")
        if len(parts) != 4:
            continue
        h, author, when, msg = parts
        if "[bot]" in author or "dependabot" in author.lower() or "[skip ci]" in msg:
            kind = "automation"
        elif msg.startswith("Merge "):
            kind = "merge"
        else:
            kind = "human"
        m = re.match(r"^([a-z]+)(\([^)]*\))?!?:\s", msg)
        ctype = m.group(1) if m else ("merge" if msg.startswith("Merge ") else "other")
        items.append({"hash": h, "author": author, "when": when, "day": when[:10], "msg": msg, "kind": kind, "type": ctype})
    return items


def parse_frontmatter(path: Path) -> tuple[dict[str, str], str]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end == -1:
        return {}, text
    meta: dict[str, str] = {}
    for line in text[3:end].splitlines():
        if ":" in line and not line.startswith((" ", "\t")):
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip().strip('"').strip("'")
    return meta, text[end + 4 :]


def load_agents() -> dict[str, dict]:
    """member name -> {tools: [...], text: full file text}. Keyed by roster
    name via the frontmatter slug (Gaz's reference file maps by filename)."""
    agents: dict[str, dict] = {}
    if not AGENTS_DIR.is_dir():
        return agents
    for path in sorted(AGENTS_DIR.glob("*.md")):
        meta, _body = parse_frontmatter(path)
        slug = meta.get("name", "")
        name = SLUG_TO_NAME.get(slug) or path.name.split(" - ")[0]
        tools = [t.strip() for t in meta.get("tools", "").split(",") if t.strip()]
        agents[name] = {"slug": slug, "tools": tools, "text": path.read_text(encoding="utf-8"), "file": path.name}
    return agents


def load_skills(agents: dict[str, dict]) -> list[dict]:
    skills = []
    if not SKILLS_DIR.is_dir():
        return skills
    for path in sorted(SKILLS_DIR.glob("*/SKILL.md")):
        meta, _ = parse_frontmatter(path)
        name = meta.get("name") or path.parent.name
        users = [m for m in ROSTER_NAMES if m in agents and name in agents[m]["text"]]
        skills.append({"name": name, "description": meta.get("description", ""), "users": users, "path": str(path.relative_to(REPO_ROOT))})
    return skills


def load_commands() -> list[dict]:
    cmds = []
    if not COMMANDS_DIR.is_dir():
        return cmds
    for path in sorted(COMMANDS_DIR.glob("*.md")):
        meta, _ = parse_frontmatter(path)
        cmds.append({"name": path.stem, "description": meta.get("description", ""), "args": meta.get("argument-hint", "")})
    return cmds


def load_mcp_servers() -> list[dict] | None:
    """Name + transport + launch target only. env blocks, headers and full
    URLs are deliberately never read into the output."""
    if not MCP_JSON.is_file():
        return None
    try:
        servers = json.loads(MCP_JSON.read_text(encoding="utf-8")).get("mcpServers", {})
    except (OSError, ValueError):
        return None
    out = []
    for name, cfg in servers.items():
        transport = cfg.get("type") or ("stdio" if cfg.get("command") else "unknown")
        if cfg.get("url"):
            launch = f"remote · {urlparse(cfg['url']).hostname or 'host hidden'}"
        else:
            cmd = Path(str(cfg.get("command", ""))).name
            # Only the leading package/subcommand: skip leading flags, then stop. A later
            # positional could be a flag's value (e.g. `--token abc`), which must never print.
            args = [str(a) for a in cfg.get("args", [])]
            while args and args[0].startswith("-"):
                args.pop(0)
            pkg = args[0] if args and "=" not in args[0] else ""
            launch = f"{cmd} {pkg}".strip()
        out.append({"name": name, "transport": transport, "launch": launch})
    return out


def load_ownership() -> dict[str, dict[str, str]]:
    """CLAUDE.md roster rows -> {name: {area, owns}} where owns is the first
    sentence of the "Owns" column (rendered with inline markdown)."""
    out: dict[str, dict[str, str]] = {}
    if not CLAUDE_MD.is_file():
        return out
    for line in CLAUDE_MD.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^\|\s*\*\*(\w+)\*\*\s*\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)\|\s*$", line)
        if not m:
            continue
        owns = m.group(5).strip()
        first = re.split(r"(?<!e\.g)(?<!i\.e)\.\s+(?=[A-Z*`(])", owns, maxsplit=1)[0].rstrip(".") + "."
        out[m.group(1)] = {"area": m.group(3).strip(), "owns": first}
    return out


def md_inline(text: str) -> str:
    s = esc(text)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    return re.sub(r"\*([^*]+)\*", r"<em>\1</em>", s)


def lead_usage(session_rows: list[dict]) -> dict | None:
    """Gaz's own whole-session figures, kept apart from member_usage(): a Gaz
    row's tokens are throughput summed over every turn of a session (tens of
    millions), a specialist row's are one dispatch's final context size --
    different quantities, never averaged or ranked together. None = no rows."""
    if not session_rows:
        return None
    models = Counter(r["model"] or "not recorded" for r in session_rows)
    return {
        "sessions": len(session_rows),
        "tokens": sum(r["tokens"] for r in session_rows),
        "tool_uses": sum(r["tool_uses"] for r in session_rows),
        "duration_ms": sum(r["duration_ms"] for r in session_rows),
        "last": max(r["date"] for r in session_rows),
        "models": [m for m, _ in models.most_common()],
    }


# --- formatting -----------------------------------------------------------------


def fmt_tokens(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.2f}M"
    if n >= 1000:
        return f"{n / 1000:.1f}K"
    return str(n)


def fmt_duration(ms: int) -> str:
    minutes = ms / 60000
    if minutes >= 60:
        return f"{minutes / 60:.1f}h"
    if minutes >= 1:
        return f"{minutes:.0f}m"
    return f"{ms / 1000:.0f}s"


def area_chip(area: str) -> str:
    fill, stroke = AREA_CHIP[area]
    return f'<span class="chip" style="--chip-fill:{fill};--chip-stroke:{stroke}">{esc(area)}</span>'


def stat_tile(label: str, value: str, context: str = "") -> str:
    ctx = f'<div class="tile-context">{context}</div>' if context else ""
    return f'<div class="tile"><div class="tile-label">{esc(label)}</div><div class="tile-value">{value}</div>{ctx}</div>'


def section(title: str, body: str, sub: str = "") -> str:
    sub_html = f'<p class="section-sub">{sub}</p>' if sub else ""
    return f'<section class="dash-section"><div class="dash-section-title">{esc(title)}</div>{sub_html}{body}</section>'


def card(title: str, body: str, sub: str = "", cls: str = "") -> str:
    sub_html = f'<div class="card-sub">{sub}</div>' if sub else ""
    return f'<div class="card {cls}"><div class="card-title">{esc(title)}</div>{sub_html}{body}</div>'


def hbars(items: list[tuple[str, float, str]], label_cls: str = "") -> str:
    """Horizontal single-series bar list: (label, value, value_text). One hue;
    the row's label and value text carry identity, never the bar colour."""
    if not items:
        return f'<div class="empty">{NA}</div>'
    peak = max(v for _l, v, _t in items) or 1
    rows = []
    for label, value, text in items:
        pct = max(value / peak * 100, 0.8 if value else 0)
        rows.append(
            f'<div class="hbar" data-tip="{esc(label)}: {esc(text)}">'
            f'<span class="hbar-label {label_cls}">{esc(label)}</span>'
            f'<span class="hbar-track"><span class="hbar-fill" style="width:{pct:.1f}%"></span></span>'
            f'<span class="hbar-value">{esc(text)}</span></div>'
        )
    return f'<div class="hbars">{"".join(rows)}</div>'


def vbars(points: list[tuple[str, float, str]], aria: str) -> str:
    """Vertical single-series column chart over a time axis: (day, value,
    tooltip). Built from flex divs rather than a scaled SVG so axis text stays
    at real pixel size at every viewport width."""
    if not points:
        return f'<div class="empty">{NA}</div>'
    peak = max(v for _d, v, _t in points) or 1
    cols = []
    for day, value, tip in points:
        h = value / peak * 100
        cols.append(
            f'<div class="vbar" data-tip="{esc(day)} · {esc(tip)}" aria-hidden="true">'
            f'<span class="vbar-fill" style="height:{max(h, 1.5 if value else 0):.1f}%"></span></div>'
        )
    mid = points[len(points) // 2][0]
    return (
        f'<div class="vchart" role="img" aria-label="{esc(aria)}">'
        f'<div class="vchart-peak">max {esc(points[[v for _d, v, _t in points].index(peak)][2])}</div>'
        f'<div class="vbars">{"".join(cols)}</div>'
        f'<div class="vchart-axis"><span>{esc(points[0][0])}</span><span>{esc(mid)}</span><span>{esc(points[-1][0])}</span></div></div>'
    )


def table(headers: list[tuple[str, str]], rows: list[str], sortable: bool = True, cls: str = "") -> str:
    """headers: (label, kind) where kind is 'text' or 'num' (sort hint)."""
    ths = []
    for label, kind in headers:
        if sortable:
            ths.append(f'<th scope="col" data-kind="{kind}" tabindex="0" aria-sort="none">{esc(label)}</th>')
        else:
            ths.append(f'<th scope="col">{esc(label)}</th>')
    srt = " sortable" if sortable else ""
    return f'<div class="table-wrap"><table class="data-table{srt} {cls}"><thead><tr>{"".join(ths)}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'


def td(text: str, sort: object | None = None, cls: str = "") -> str:
    s = f' data-sort="{esc(sort)}"' if sort is not None else ""
    c = f' class="{cls}"' if cls else ""
    return f"<td{s}{c}>{text}</td>"


# --- org chart (layout untouched by the 2026-10 rework) -------------------------


def node_html(name: str, role: str, area: str, avatar_dir_rel: str) -> str:
    """One org-chart card: circle avatar left, coloured info-box overlapping it
    on the right. Connector lines anchor to #avatar-{name}, never the whole
    .node, so the info-box size never enters the line math."""
    colors = AREA_COLORS[area]
    avatar_file = f"{avatar_dir_rel}/{name}_transparent.png"
    return (
        f'<div class="node" style="--fill:{colors["fill"]};--stroke:{colors["stroke"]};--text:{colors["text"]}">'
        f'<div class="avatar-ring" id="avatar-{name}"><img src="{avatar_file}" alt="{name}" class="avatar" loading="lazy"></div>'
        f'<div class="info-box"><div class="rname">{name}</div><div class="rrole">{role}</div></div>'
        f"</div>"
    )


def build_branch_html(head: str, rows: list[list[str]], avatar_dir_rel: str) -> str:
    """One .branch column: the head at indent 0, then BRANCH_LAYOUT's report
    rows stair-stepped right by INDENT_STEP_REM per depth-step."""
    all_rows = [[head], *rows]
    rows_html = []
    for row in all_rows:
        indent = DEPTH[row[0]] - DEPTH[head]
        cells = "".join(node_html(name, *ROSTER_BY_NAME[name], avatar_dir_rel) for name in row)
        rows_html.append(f'      <div class="row" style="margin-left:{indent * INDENT_STEP_REM:.2f}rem">{cells}</div>')
    return "\n".join(rows_html)


def build_org_chart_html(avatar_dir_rel: str) -> str:
    """Root alone, centred, on top; below it a space-between row of the two
    branch columns. #lines is an empty SVG overlay drawOrgLines() fills once
    flexbox has placed the nodes."""
    root_html = node_html(ROOT, *ROSTER_BY_NAME[ROOT], avatar_dir_rel)
    branches = []
    for (head, rows), side in zip(BRANCH_LAYOUT, ("left", "right"), strict=True):
        branches.append(f'    <div class="branch branch-{side}">\n{build_branch_html(head, rows, avatar_dir_rel)}\n    </div>')
    branches_html = "\n".join(branches)
    return f"""<div class="org-chart" id="org-chart">
      <svg id="lines" aria-hidden="true"></svg>
      <div class="root-row">
        {root_html}
      </div>
      <div class="branches">
{branches_html}
      </div>
    </div>"""


LEGEND = [
    ("#2c1b4d", "#b388ff", "Leadership"),
    ("#12351f", "#4caf7d", "Strategic"),
    ("#0d2440", "#58a6ff", "Engineering / technology"),
    ("#0d3b36", "#2dd4bf", "Group coordinator"),
    ("#3d2c07", "#e0a94c", "Compliance / documentation"),
]


def build_legend_html() -> str:
    items = "".join(
        f'<div class="legend-item"><span class="legend-swatch" style="--fill-color:{f};--stroke-color:{s}"></span>{esc(label)}</div>' for f, s, label in LEGEND
    )
    return f'<div class="legend">{items}<div class="legend-item"><span class="legend-line"></span>Reports to</div></div>'


# --- tabs -----------------------------------------------------------------------


def page_head(title: str, text: str) -> str:
    return f'<div class="page-head"><h1>{esc(title)}</h1><p>{text}</p></div>'


def build_overview_tab(ctx: dict, avatar_dir_rel: str) -> str:
    rows = ctx["rows"]
    lead = ctx["lead"]

    # Team composition + dispatch totals.
    area_counts = Counter(BIOS[n]["area"] for n in ROSTER_NAMES)
    comp = ", ".join(f"{area_counts[a]} {a.lower()}" for a in ("Strategic", "Analytical", "Operational") if area_counts[a])
    total_tokens = sum(r["tokens"] for r in rows)
    fam = Counter()
    for r in rows:
        fam[model_family(r["model"])] += 1
    mix = " · ".join(f"{k} {round(v / len(rows) * 100)}%" for k, v in fam.most_common()) if rows else ""
    first, last = (min(r["date"] for r in rows), max(r["date"] for r in rows)) if rows else ("", "")
    team_tiles = "".join(
        [
            stat_tile("Members", str(len(ROSTER)), f"{comp} · {sum(1 for r in ROSTER if r[3])} dispatchable"),
            stat_tile("Dispatches logged", str(len(rows)) if rows else NA, f"subagent dispatches, {first} → {last}" if rows else ""),
            stat_tile("Tokens logged", fmt_tokens(total_tokens) if rows else NA, f"{fmt_tokens(total_tokens // len(rows))} avg per dispatch" if rows else ""),
            stat_tile("Model mix", esc(fam.most_common(1)[0][0]) if rows else NA, esc(mix)),
            stat_tile(
                "Lead session tokens",
                fmt_tokens(lead["tokens"]) if lead else NA,
                f"Gaz, {lead['sessions']} session{'s' if lead['sessions'] != 1 else ''} logged · separate from dispatch figures" if lead else "",
            ),
        ]
    )

    chart = f"""<div class="card org-card">
      <div class="card-head"><div class="card-title">Reporting structure</div><span class="card-hint">who reports to whom</span></div>
      <div class="canvas-scroll">
{build_org_chart_html(avatar_dir_rel)}
      </div>
      {build_legend_html()}
    </div>"""

    return f"""<section class="tab-panel active" id="tab-overview" role="tabpanel" aria-labelledby="tabbtn-overview" tabindex="-1">
      {page_head("Overview", "The team, as of this page's generation time.")}
      {section("Team", f'<div class="tiles">{team_tiles}</div>' + chart)}
    </section>"""


def build_agents_tab(ctx: dict, avatar_dir_rel: str) -> str:
    usage = ctx["usage"]
    agents = ctx["agents"]
    cards = []
    for name, role, _group, slug in ROSTER:
        b = BIOS[name]
        slug_html = f'<code class="slug">{esc(slug)}</code>' if slug else '<span class="slug slug-none">top-level session, not dispatchable</span>'
        u = usage.get(name)
        facts = []
        if u:
            facts.append(f"{u['dispatches']} dispatch{'es' if u['dispatches'] != 1 else ''}")
            facts.append(f"{fmt_tokens(u['tokens'])} tokens")
            facts.append(f"last {esc(u['last'])}")
        elif name == ROOT:
            lead = ctx["lead"]
            if lead:
                facts.append(f"{lead['sessions']} logged session{'s' if lead['sessions'] != 1 else ''}")
                facts.append(f"{fmt_tokens(lead['tokens'])} session tokens")
                facts.append(f"{lead['tool_uses']:,} tool uses")
                facts.append(f"last {esc(lead['last'])}")
            else:
                facts.append(f"session figures {NA}")
        else:
            facts.append("no dispatches logged")
        if slug and name in agents:
            facts.append(f"{len(agents[name]['tools'])} tools")
        facts_html = "".join(f"<span>{f}</span>" for f in facts)
        cards.append(
            f"""<article class="agent-card">
        <div class="agent-head">
          <div class="agent-avatar"><img src="{avatar_dir_rel}/{name}_transparent.png" alt="" loading="lazy"></div>
          <div class="agent-id"><div class="agent-name">{esc(name)}</div><div class="agent-role">{esc(role)}</div></div>
          {area_chip(b["area"])}
        </div>
        <p class="agent-tagline">{esc(b["tagline"])}</p>
        <p class="agent-bio">{esc(b["bio"])}</p>
        <details class="agent-scope"><summary>Role scope</summary><p>{esc(b["scope"])}</p></details>
        <div class="agent-foot">
          <div class="agent-works"><span class="agent-works-label">Works closely with:</span> {esc(b["works"])}</div>
          <div class="agent-meta">{slug_html}<div class="agent-facts">{facts_html}</div></div>
        </div>
      </article>"""
        )
    return f"""<section class="tab-panel" id="tab-agents" role="tabpanel" aria-labelledby="tabbtn-agents" tabindex="-1">
      {page_head("Agents", "The eleven team members: who they are, how they work, and what they own. The machine-readable delegation contract (scope boundaries, review gates) lives in <code>CLAUDE.md</code>, which every session loads.")}
      <div class="agent-grid">{"".join(cards)}</div>
    </section>"""


def build_team_tab(ctx: dict) -> str:
    usage = ctx["usage"]
    agents = ctx["agents"]
    skills = ctx["skills"]
    owners = ctx["ownership"]
    names = list(ROSTER_NAMES) + sorted(n for n in usage if n not in ROSTER_BY_NAME)
    peak = max((u["dispatches"] for u in usage.values()), default=0) or 1
    lead = ctx["lead"]

    rows = []
    for name in names:
        u = usage.get(name)
        if name == ROOT and lead:
            # Gaz: session figures, own row, no bar (a session count is not on
            # the dispatch-count scale the bars share).
            n = lead["sessions"]
            member = f'<div class="member"><strong>{esc(name)}</strong><span>{esc(ROSTER_BY_NAME[name][0])}</span></div>'
            kws = "".join(f'<span class="tag">{esc(k)}</span>' for k in top_keywords([r["task"] for r in ctx["session_rows"]]))
            rows.append(
                "<tr>"
                + td(member, name)
                + td(area_chip(BIOS[name]["area"]), BIOS[name]["area"])
                + td(f'{n} <span class="dim">session{"s" if n != 1 else ""}</span>', n, "num")
                + td(f'{fmt_tokens(lead["tokens"])} <span class="dim">sessions</span>', lead["tokens"], "num")
                + td(f'{fmt_tokens(lead["tokens"] // n)} <span class="dim">/ session</span>', lead["tokens"] // n, "num")
                + td(f'{fmt_duration(lead["duration_ms"] // n)} <span class="dim">/ session</span>', lead["duration_ms"] // n, "num")
                + td(esc(lead["last"]), lead["last"])
                + td(kws or '<span class="dim">—</span>')
                + td('<span class="na">session</span>', -1, "num")
                + td('<span class="dim">session — all available</span>', 0)
                + "</tr>"
            )
            continue
        on_roster = name in ROSTER_BY_NAME
        area = BIOS[name]["area"] if on_roster else ""
        role = ROSTER_BY_NAME[name][0] if on_roster else "not on the roster"
        member = f'<div class="member"><strong>{esc(name)}</strong><span>{esc(role)}</span></div>'
        if name == ROOT:
            tools_txt, tools_sort = '<span class="na">session</span>', -1
        elif name in agents:
            t = agents[name]["tools"]
            n_mcp = sum(1 for x in t if x.startswith("mcp__"))
            tools_txt = f"{len(t) - n_mcp}" + (f' <span class="dim">+{n_mcp} MCP</span>' if n_mcp else "")
            tools_sort = len(t)
        else:
            tools_txt, tools_sort = NA, -1
        used = [s["name"] for s in skills if name in s["users"]]
        if name == ROOT:
            skills_txt = '<span class="dim">session — all available</span>'
        else:
            skills_txt = "".join(f'<span class="tag">{esc(s)}</span>' for s in used) or '<span class="dim">none referenced</span>'
        if u:
            share = u["dispatches"] / peak * 100
            disp = f'<div class="cell-bar"><span>{u["dispatches"]}</span><span class="mini"><span style="width:{share:.0f}%"></span></span></div>'
            kws = "".join(f'<span class="tag">{esc(k)}</span>' for k in top_keywords(u["tasks"]))
            rows.append(
                "<tr>"
                + td(member, name)
                + td(area_chip(area) if area else '<span class="dim">—</span>', area)
                + td(disp, u["dispatches"], "num")
                + td(fmt_tokens(u["tokens"]), u["tokens"], "num")
                + td(fmt_tokens(u["tokens"] // u["dispatches"]), u["tokens"] // u["dispatches"], "num")
                + td(fmt_duration(u["duration_ms"] // u["dispatches"]), u["duration_ms"] // u["dispatches"], "num")
                + td(esc(u["last"]), u["last"])
                + td(kws or '<span class="dim">—</span>')
                + td(tools_txt, tools_sort, "num")
                + td(skills_txt, len(used))
                + "</tr>"
            )
        else:
            rows.append(
                "<tr>"
                + td(member, name)
                + td(area_chip(area) if area else "", area)
                + td('<span class="dim">0</span>', 0, "num")
                + td('<span class="dim">—</span>', 0, "num")
                + td('<span class="dim">—</span>', 0, "num")
                + td('<span class="dim">—</span>', 0, "num")
                + td(f'<span class="dim">{"top-level session, not dispatched" if name == ROOT else "no dispatch logged"}</span>', "")
                + td('<span class="dim">—</span>')
                + td(tools_txt, tools_sort, "num")
                + td(skills_txt, len(used))
                + "</tr>"
            )
    workload = table(
        [("Member", "text"), ("Area", "text"), ("Dispatches", "num"), ("Tokens", "num"), ("Avg tokens", "num"), ("Avg duration", "num"), ("Last active", "text"), ("Top task keywords", "text"), ("Tools", "num"), ("Skills referenced", "num")],
        rows,
        cls="workload",
    )

    if owners:
        own_rows = []
        for name in ROSTER_NAMES:
            o = owners.get(name)
            if not o:
                own_rows.append("<tr>" + td(f"<strong>{esc(name)}</strong>", name) + td("") + td(f"{NA} (no row in CLAUDE.md)") + "</tr>")
                continue
            own_rows.append("<tr>" + td(f"<strong>{esc(name)}</strong>", name) + td(area_chip(o["area"]), o["area"]) + td(md_inline(o["owns"]), cls="wrap") + "</tr>")
        ownership = table([("Owner", "text"), ("Area", "text"), ("Owns", "text")], own_rows, cls="ownership")
    else:
        ownership = f'<div class="empty">Ownership {NA} (<code>CLAUDE.md</code> roster table not found).</div>'

    return f"""<section class="tab-panel" id="tab-team" role="tabpanel" aria-labelledby="tabbtn-team" tabindex="-1">
      {page_head("Team", "Per-member workload from the dispatch log, each agent's tool and skill footprint, and who owns which surface.")}
      {section("Workload", workload, "Dispatch figures from <code>.claude/agent_usage_log.jsonl</code> (only dispatches Gaz logged — silence is not zero work). Gaz's row is his own whole-session throughput (Dispatches = logged sessions), a different quantity from a specialist's per-dispatch figures, so it has no bar and is not part of their scaling. Keywords are the most frequent words in each member's logged task titles. Tools = entries in the agent file's <code>tools:</code> list. Click a column header to sort.")}
      {section("Ownership", ownership, "First sentence of each member's <em>Owns</em> column in <code>CLAUDE.md</code>; the full text is the contract.")}
    </section>"""


def build_skills_tab(ctx: dict) -> str:
    skills = ctx["skills"]
    cmds = ctx["commands"]
    if skills:
        cards = []
        for s in skills:
            users = "".join(f'<span class="tag">{esc(u)}</span>' for u in s["users"]) or '<span class="dim">not referenced by any agent file</span>'
            cards.append(
                f'<article class="card skill-card"><div class="card-title mono">{esc(s["name"])}</div>'
                f'<p class="skill-desc">{esc(s["description"]) or NA}</p>'
                f'<div class="skill-users"><span class="label">Referenced by</span>{users}</div>'
                f'<code class="path">{esc(s["path"])}</code></article>'
            )
        skills_html = f'<div class="grid-auto">{"".join(cards)}</div>'
    else:
        skills_html = f'<div class="empty">Skills {NA} (<code>.claude/skills/</code> not found).</div>'
    if cmds:
        rows = [
            "<tr>" + td(f'<code class="slug">/{esc(c["name"])}</code>', c["name"]) + td(esc(c["args"]) or '<span class="dim">—</span>') + td(esc(c["description"]) or NA, cls="wrap") + "</tr>"
            for c in cmds
        ]
        cmds_html = table([("Command", "text"), ("Arguments", "text"), ("What it does", "text")], rows, sortable=False, cls="commands")
    else:
        cmds_html = f'<div class="empty">Slash commands {NA}.</div>'
    n_ref = sum(1 for s in skills if s["users"])
    return f"""<section class="tab-panel" id="tab-skills" role="tabpanel" aria-labelledby="tabbtn-skills" tabindex="-1">
      {page_head("Skills", f"{len(skills)} shared playbooks in <code>.claude/skills/</code>, {n_ref} of them referenced from at least one agent file. Skills are Gaz's to build; specialists flag candidates.")}
      {section("Skills", skills_html, "Description from each <code>SKILL.md</code> frontmatter. “Referenced by” = agent files that mention the skill by name.")}
      {section("Slash commands", cmds_html, "Project commands in <code>.claude/commands/</code>.")}
    </section>"""


def build_mcp_tab(ctx: dict) -> str:
    servers = ctx["mcp"]
    agents = ctx["agents"]
    per_server: dict[str, dict[str, int]] = defaultdict(dict)
    for name in ROSTER_NAMES:
        if name not in agents or name == ROOT:
            continue
        for t in agents[name]["tools"]:
            m = re.match(r"^mcp__([^_]+(?:-[^_]+)*)__", t)
            if m:
                per_server[m.group(1)][name] = per_server[m.group(1)].get(name, 0) + 1
    if servers is None:
        srv_html = f'<div class="empty">MCP servers {NA} (<code>.mcp.json</code> not found or unreadable).</div>'
        known = set()
    else:
        known = {s["name"] for s in servers}
        rows = []
        for s in servers:
            users = per_server.get(s["name"], {})
            chips = "".join(f'<span class="tag">{esc(n)} <span class="dim">{c}</span></span>' for n, c in sorted(users.items(), key=lambda kv: -kv[1])) or '<span class="dim">no agent has tools pinned (session-level use only)</span>'
            rows.append(
                "<tr>" + td(f'<code class="slug">{esc(s["name"])}</code>', s["name"]) + td(esc(s["transport"]), s["transport"]) + td(f'<code>{esc(s["launch"])}</code>', s["launch"]) + td(chips, sum(users.values())) + "</tr>"
            )
        srv_html = table([("Server", "text"), ("Transport", "text"), ("Launch", "text"), ("Agents with pinned tools (count)", "num")], rows, cls="mcp")
    unknown = sorted(set(per_server) - known)
    unknown_html = f'<p class="note">Agent files also pin tools for servers not in <code>.mcp.json</code>: {", ".join(f"<code>{esc(u)}</code>" for u in unknown)} (configured outside the repo).</p>' if unknown and servers is not None else ""
    none_agents = [n for n in ROSTER_NAMES if n != ROOT and n in agents and not any(t.startswith("mcp__") for t in agents[n]["tools"])]
    none_html = f'<p class="note">No MCP tools in their agent file: {", ".join(esc(n) for n in none_agents)}.</p>' if none_agents else ""
    detail_rows = []
    for name in ROSTER_NAMES:
        if name == ROOT or name not in agents:
            continue
        by_srv: dict[str, list[str]] = defaultdict(list)
        for t in agents[name]["tools"]:
            parts = t.split("__", 2)
            if len(parts) == 3 and parts[0] == "mcp":
                by_srv[parts[1]].append(parts[2])
        for srv, tl in by_srv.items():
            chips = "".join(f'<span class="tag">{esc(x)}</span>' for x in sorted(tl))
            detail_rows.append("<tr>" + td(f"<strong>{esc(name)}</strong>", name) + td(f'<code class="slug">{esc(srv)}</code>', srv) + td(str(len(tl)), len(tl), "num") + td(chips, cls="wrap") + "</tr>")
    detail_html = (
        section(
            "Pinned tools by agent",
            table([("Agent", "text"), ("Server", "text"), ("Tools", "num"), ("Tool names", "text")], detail_rows, cls="mcp-tools"),
            "Exact <code>mcp__server__tool</code> entries from each agent file, prefix stripped. A subagent can only call the MCP tools listed here.",
        )
        if detail_rows
        else ""
    )
    return f"""<section class="tab-panel" id="tab-mcp" role="tabpanel" aria-labelledby="tabbtn-mcp" tabindex="-1">
      {page_head("MCP", "Model Context Protocol servers configured for this project, and which agents are allowed to call them.")}
      {section("Servers", srv_html + unknown_html + none_html, "From <code>.mcp.json</code>: name, transport and launch target only — environment values, headers and full URLs are never shown. Counts are the <code>mcp__server__*</code> entries in each agent file's <code>tools:</code> list.")}
      {detail_html}
    </section>"""


TYPE_ORDER = ["feat", "fix", "docs", "chore", "refactor", "ci", "test", "style", "perf", "build", "revert", "merge", "other"]


def build_activity_tab(ctx: dict) -> str:
    items = ctx["activity"]
    if items is None:
        body = f'<div class="empty">Git history {NA} (<code>git log</code> failed).</div>'
        return f"""<section class="tab-panel" id="tab-activity" role="tabpanel" aria-labelledby="tabbtn-activity" tabindex="-1">
      {page_head("Activity", "Commit history for this repository.")}{section("Commits", body)}</section>"""
    kinds = Counter(i["kind"] for i in items)
    human = [i for i in items if i["kind"] == "human"]

    # Commits per day, human only, last N days ending at the newest commit.
    newest = date.fromisoformat(items[0]["day"]) if items else date.today()
    per_day = Counter(i["day"] for i in human)
    pts = []
    for k in range(ACTIVITY_CHART_DAYS - 1, -1, -1):
        d = (newest - timedelta(days=k)).isoformat()
        pts.append((d[5:], per_day.get(d, 0), f"{per_day.get(d, 0)} human commit(s)"))
    types = Counter(i["type"] for i in human)
    ranked = sorted((t for t in types if t != "other"), key=lambda t: (-types[t], TYPE_ORDER.index(t) if t in TYPE_ORDER else 99))
    type_bars = hbars([(t, types[t], str(types[t])) for t in ranked + (["other"] if types.get("other") else [])])

    span = f"{items[-1]['day']} → {items[0]['day']}" if items else ""
    tiles = "".join(
        [
            stat_tile("Commits read", str(len(items)), esc(span)),
            stat_tile("Human", str(kinds["human"]), "authored, non-merge"),
            stat_tile("Merges", str(kinds["merge"]), "PR and branch merges"),
            stat_tile("Automation", str(kinds["automation"]), "CI bot, Dependabot, [skip ci]"),
        ]
    )
    charts = (
        '<div class="grid-2">'
        + card("Human commits per day", vbars(pts, f"Human commits per day, last {ACTIVITY_CHART_DAYS} days"), f"Last {ACTIVITY_CHART_DAYS} days up to the newest commit.")
        + card("Human commits by type", type_bars, "Conventional-commit prefix; “other” has none.")
        + "</div>"
    )

    days: dict[str, list[dict]] = defaultdict(list)
    for i in items:
        days[i["day"]].append(i)
    groups = []
    for day, its in days.items():
        lis = []
        for i in its:
            lis.append(
                f'<li class="commit" data-kind="{i["kind"]}">'
                f'<span class="type type-{esc(i["type"])}">{esc(i["type"])}</span>'
                f'<span class="commit-msg">{esc(i["msg"])}</span>'
                f'<span class="commit-meta"><code>{esc(i["hash"])}</code> · {esc(i["when"][11:])} · {esc(i["author"])}</span></li>'
            )
        groups.append(f'<div class="day" data-day="{day}"><div class="day-head">{esc(day)} <span class="day-count"></span></div><ul>{"".join(lis)}</ul></div>')
    filters = (
        '<div class="filter-row" role="group" aria-label="Filter commits">'
        f'<button class="pill active" data-filter="human" aria-pressed="true">Human <span>{kinds["human"]}</span></button>'
        f'<button class="pill" data-filter="merge" aria-pressed="false">Merges <span>{kinds["merge"]}</span></button>'
        f'<button class="pill" data-filter="automation" aria-pressed="false">Automation <span>{kinds["automation"]}</span></button>'
        f'<button class="pill" data-filter="all" aria-pressed="false">All <span>{len(items)}</span></button></div>'
    )
    feed = f'{filters}<div class="feed" id="feed">{"".join(groups)}</div><div class="empty feed-empty" hidden>No commits of this kind in the window.</div>'
    return f"""<section class="tab-panel" id="tab-activity" role="tabpanel" aria-labelledby="tabbtn-activity" tabindex="-1">
      {page_head("Activity", f"The last {len(items)} commits from <code>git log</code>, read fresh at generation time. CI bot commits and <code>[skip ci]</code> writes are separated from human work.")}
      {section("Summary", f'<div class="tiles">{tiles}</div>' + charts)}
      {section("Commits by day", feed)}
    </section>"""


def build_lead_section(ctx: dict) -> str:
    lead = ctx["lead"]
    sub = (
        "Gaz's own top-level session, shown apart because its tokens are throughput summed across every turn "
        "(tens of millions), while a dispatch's figure is its final context size. The two are not comparable, "
        "so none of the dispatch figures above include these."
    )
    if not lead:
        return section("Lead session (Gaz)", f'<div class="empty">Lead session figures {NA} (no rows logged under {esc(ROOT)}).</div>', sub)
    n = lead["sessions"]
    tiles = "".join(
        [
            stat_tile("Session tokens", fmt_tokens(lead["tokens"]), f"{n} session{'s' if n != 1 else ''} logged"),
            stat_tile("Tool uses", f"{lead['tool_uses']:,}", "across logged sessions"),
            stat_tile("Session time", fmt_duration(lead["duration_ms"]), "total, logged sessions"),
            stat_tile("Latest session", esc(lead["last"]), "model: " + ", ".join(esc(m) for m in lead["models"])),
        ]
    )
    na = '<span class="dim">not recorded</span>'
    srows = [
        "<tr>"
        + td(esc(r["date"]), r["date"], "num")
        + td(esc(r["task"]), r["task"], "wrap")
        + td(esc(r["model"]) or na, r["model"])
        + td(fmt_tokens(r["tokens"]) if r["tokens"] else na, r["tokens"], "num")
        + td(str(r["tool_uses"]) if r["tool_uses"] else na, r["tool_uses"], "num")
        + td(fmt_duration(r["duration_ms"]) if r["duration_ms"] else na, r["duration_ms"], "num")
        + "</tr>"
        for r in reversed(ctx["session_rows"])
    ]
    tbl = table([("Date", "text"), ("Task", "text"), ("Model", "text"), ("Tokens", "num"), ("Tool uses", "num"), ("Time", "num")], srows, cls="dispatches")
    return section("Lead session (Gaz)", f'<div class="tiles">{tiles}</div>{tbl}', sub)


def build_tokens_tab(ctx: dict) -> str:
    rows = ctx["rows"]
    usage = ctx["usage"]
    skipped = ctx["skipped"]
    if not rows:
        body = f'<div class="empty">Dispatch log {NA} (<code>.claude/agent_usage_log.jsonl</code> missing or empty).</div>'
        return f"""<section class="tab-panel" id="tab-tokens" role="tabpanel" aria-labelledby="tabbtn-tokens" tabindex="-1">
      {page_head("Tokens", "Logged subagent dispatches.")}{section("Totals", body)}</section>"""
    total = sum(r["tokens"] for r in rows)
    tools = sum(r["tool_uses"] for r in rows)
    dur = sum(r["duration_ms"] for r in rows)
    first, last = min(r["date"] for r in rows), max(r["date"] for r in rows)
    tiles = "".join(
        [
            stat_tile("Tokens", fmt_tokens(total), f"{len(rows)} dispatches, {esc(first)} → {esc(last)}"),
            stat_tile("Avg per dispatch", fmt_tokens(total // len(rows)), f"median {fmt_tokens(sorted(r['tokens'] for r in rows)[len(rows) // 2])}"),
            stat_tile("Tool uses", f"{tools:,}", f"{tools / len(rows):.0f} per dispatch"),
            stat_tile("Agent time", fmt_duration(dur), f"{fmt_duration(dur // len(rows))} per dispatch"),
        ]
    )

    # Tokens per day, every day in the logged span (zero days included).
    per_day = Counter()
    disp_day = Counter()
    for r in rows:
        per_day[r["date"]] += r["tokens"]
        disp_day[r["date"]] += 1
    d0, d1 = date.fromisoformat(first), date.fromisoformat(last)
    pts = []
    d = d0
    while d <= d1:
        k = d.isoformat()
        pts.append((k[5:], per_day.get(k, 0), f"{fmt_tokens(per_day.get(k, 0))} tokens, {disp_day.get(k, 0)} dispatch(es)"))
        d += timedelta(days=1)

    # Per model family; raw labels listed underneath for honesty.
    fam_tok: Counter[str] = Counter()
    fam_n: Counter[str] = Counter()
    raw = Counter()
    for r in rows:
        f = model_family(r["model"])
        fam_tok[f] += r["tokens"]
        fam_n[f] += 1
        raw[r["model"] or "(missing)"] += 1
    model_bars = hbars([(f, fam_tok[f], f"{fmt_tokens(fam_tok[f])} · {fam_n[f]} disp · {round(fam_tok[f] / (total or 1) * 100)}%") for f, _ in fam_tok.most_common()])
    raw_txt = ", ".join(f"<code>{esc(k)}</code> ×{v}" for k, v in raw.most_common())
    charts = (
        '<div class="grid-2">'
        + card("Tokens per day", vbars(pts, "Tokens per day across the logged span"), "Every calendar day in the logged span; empty days are real zeros in the log, not missing data.")
        + card("Tokens by model", model_bars, f"Grouped by model family. Raw labels in the log: {raw_txt}.")
        + "</div>"
    )

    mem_rows = []
    for name, u in sorted(usage.items(), key=lambda kv: -kv[1]["tokens"]):
        on = name in ROSTER_BY_NAME
        label = esc(name) + ("" if on else ' <span class="dim">(not on roster)</span>')
        mem_rows.append(
            "<tr>"
            + td(label, name)
            + td(esc(ROSTER_BY_NAME[name][0]) if on else '<span class="dim">—</span>')
            + td(str(u["dispatches"]), u["dispatches"], "num")
            + td(fmt_tokens(u["tokens"]), u["tokens"], "num")
            + td(f"{round(u['tokens'] / (total or 1) * 100)}%", u["tokens"], "num")
            + td(str(u["tool_uses"]), u["tool_uses"], "num")
            + td(fmt_duration(u["duration_ms"]), u["duration_ms"], "num")
            + td(esc(u["last"]), u["last"])
            + "</tr>"
        )
    for name, role, _a, _slug in ROSTER:
        if name not in usage:
            mem_rows.append("<tr>" + td(esc(name), name) + td(esc(role)) + td(f'<span class="dim">{"top-level session, see Lead session (Gaz) below" if name == ROOT else "no logged dispatches"}</span>', 0, "num") + td("", 0, "num") + td("", 0, "num") + td("", 0, "num") + td("", 0, "num") + td("", "") + "</tr>")
    member_table = table(
        [("Member", "text"), ("Role", "text"), ("Dispatches", "num"), ("Tokens", "num"), ("Share", "num"), ("Tool uses", "num"), ("Time", "num"), ("Last", "text")],
        mem_rows,
        cls="members",
    )

    def disp_row(r: dict) -> str:
        return (
            "<tr>"
            + td(esc(r["date"]), r["date"], "num")
            + td(esc(r["name"]), r["name"])
            + td(esc(r["task"]), r["task"], "wrap")
            + td(esc(r["model"]) or '<span class="dim">not recorded</span>', r["model"])
            + td(fmt_tokens(r["tokens"]), r["tokens"], "num")
            + td(str(r["tool_uses"]), r["tool_uses"], "num")
            + td(fmt_duration(r["duration_ms"]), r["duration_ms"], "num")
            + "</tr>"
        )

    ordered = list(reversed(rows))  # log is append-only, so newest last
    hdr = [("Date", "text"), ("Member", "text"), ("Task", "text"), ("Model", "text"), ("Tokens", "num"), ("Tool uses", "num"), ("Time", "num")]
    recent = table(hdr, [disp_row(r) for r in ordered[:RECENT_DISPATCHES]], cls="dispatches")
    rest = ""
    if len(ordered) > RECENT_DISPATCHES:
        rest = f'<details class="more"><summary>Show all {len(ordered)} dispatches</summary>{table(hdr, [disp_row(r) for r in ordered], cls="dispatches")}</details>'
    skipped_html = f'<p class="note">{skipped} malformed log line(s) skipped.</p>' if skipped else ""
    lead_html = build_lead_section(ctx)
    return f"""<section class="tab-panel" id="tab-tokens" role="tabpanel" aria-labelledby="tabbtn-tokens" tabindex="-1">
      {page_head("Tokens", "Every subagent dispatch Gaz logged in <code>.claude/agent_usage_log.jsonl</code>. A dispatch that was never logged is absent here, not zero.")}
      {section("Totals", f'<div class="tiles">{tiles}</div>' + charts + skipped_html)}
      {section("By member", member_table, "Click a column header to sort.")}
      {lead_html}
      {section(f"Latest {min(RECENT_DISPATCHES, len(ordered))} dispatches", recent + rest)}
    </section>"""


def build_nav_html() -> str:
    items = []
    for i, (key, label) in enumerate(NAV_ITEMS):
        sel = "true" if i == 0 else "false"
        cls = "tab-btn active" if i == 0 else "tab-btn"
        tabindex = "0" if i == 0 else "-1"
        items.append(f'<button class="{cls}" role="tab" id="tabbtn-{key}" aria-controls="tab-{key}" aria-selected="{sel}" tabindex="{tabindex}" data-tab="{key}">{esc(label)}</button>')
    return "\n      ".join(items)


# --- page assembly --------------------------------------------------------------

CSS = r"""
  :root {
    --bg: #0d1117;
    /* --card-bg is only still read by the org chart's avatar ring (the 5px
       "gap" ring) -- kept at its original value so the nodes render exactly
       as before the 2026-10 rework. */
    --card-bg: #161b22;
    --border: #30363d;
    --border2: #444c56;
    --text: #e6edf3;
    --text2: #a2a9b1;
    --text3: #9a9fa7;
    --amber: #ffaa00;
    --blue: #58a6ff;
    --data: #8f95d6;
    --radius: 6px;
    --radius-lg: 10px;
    --font: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
    --font-ui: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    --glass: rgba(22, 27, 34, 0.45);
    --hair: rgba(255, 255, 255, 0.10);
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  /* Console "PREVIEW v5" page background (page.css body). */
  body {
    min-height: 100vh;
    background-color: #0f172a;
    background-image:
      radial-gradient(1500px 1200px at 8% -10%, rgba(64, 116, 244, 0.26), transparent 72%),
      radial-gradient(1300px 1100px at 100% 16%, rgba(132, 98, 230, 0.30), transparent 70%);
    background-attachment: fixed;
    color: var(--text);
    font-family: var(--font-ui);
    font-size: 14px;
  }
  a { color: var(--blue); }
  code { font-family: var(--font); font-size: 12px; }
  :focus-visible { outline: 2px solid var(--amber); outline-offset: 2px; }
  .skip { position: absolute; left: -9999px; }
  .skip:focus { left: 12px; top: 12px; z-index: 300; background: var(--amber); color: #111; padding: 6px 10px; border-radius: var(--radius); }

  /* --- top strip: brand + pill tabs (Console .stats-strip / .tab-btn) --- */
  .strip {
    position: sticky; top: 0; z-index: 100;
    display: flex; align-items: center; justify-content: space-between; gap: 14px;
    min-height: 60px; padding: 8px 16px;
    background: rgba(20, 25, 34, 0.55);
    backdrop-filter: blur(16px) saturate(1.3); -webkit-backdrop-filter: blur(16px) saturate(1.3);
    border-bottom: 1px solid var(--hair);
    box-shadow: inset 0 1px 0 rgba(255,255,255,.08), 0 12px 30px -10px rgba(0,0,0,.6);
  }
  .brand { display: flex; align-items: center; gap: 11px; min-width: 0; }
  .brand img { width: 40px; height: 40px; flex-shrink: 0; display: block; }
  .brand-title { font-size: 14px; font-weight: 700; letter-spacing: -0.2px; white-space: nowrap; }
  .brand-sep { width: 1px; height: 14px; background: var(--border2); flex-shrink: 0; }
  .brand-sub { font-family: var(--font); font-size: 12px; color: var(--text2); white-space: nowrap; }
  .tab-bar { display: flex; gap: 6px; align-items: center; overflow-x: auto; scrollbar-width: none; }
  .tab-bar::-webkit-scrollbar { display: none; }
  .tab-btn {
    background: none; border: 1px solid transparent; color: #fff;
    padding: 5px 12px; border-radius: 20px; cursor: pointer;
    font-size: 13px; font-weight: 600; font-family: var(--font-ui); white-space: nowrap;
    transition: all .12s;
  }
  .tab-btn:hover { border-color: rgba(255,170,0,.5); }
  .tab-btn.active { background: var(--amber); border-color: var(--amber); color: #111; }

  main { padding: 16px 20px 32px; max-width: 1680px; margin: 0 auto; }
  .page-head { margin: 4px 0 16px; }
  .page-head h1 { font-size: 15px; font-weight: 700; margin: 0 0 4px; }
  .page-head p { margin: 0; font-size: 13px; color: var(--text2); max-width: 820px; line-height: 1.5; }
  .tab-panel { display: none; }
  .tab-panel.active { display: block; }
  .tab-panel:focus { outline: none; }

  /* --- section tray + amber pill title (Console .dash-section) --- */
  .dash-section {
    border: 2px solid rgba(167, 153, 232, 0.4); border-radius: var(--radius-lg);
    padding: 18px; backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px);
  }
  .dash-section + .dash-section { margin-top: 16px; }
  .dash-section-title {
    display: inline-block; font-size: 12px; font-weight: 700; letter-spacing: .6px; text-transform: uppercase;
    color: #111; background: var(--amber); border: 1px solid var(--amber); border-radius: 5px; padding: 3px 10px;
    margin-bottom: 14px;
  }
  .section-sub { margin: -6px 0 14px; font-size: 12px; color: var(--text2); line-height: 1.5; max-width: 900px; }

  /* --- glass card (Console .chart-card) --- */
  .card {
    background: var(--glass); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
    border: 1px solid var(--hair); border-radius: var(--radius-lg);
    box-shadow: inset 0 1px 0 rgba(255,255,255,.06), 0 12px 30px -14px rgba(0,0,0,.55);
    padding: 20px; display: flex; flex-direction: column; gap: 12px; min-width: 0;
  }
  .card-head { display: flex; justify-content: space-between; align-items: baseline; gap: 10px; }
  .card-title { font-size: 13px; font-weight: 700; letter-spacing: -.1px; }
  .card-title.mono { font-family: var(--font); }
  .card-hint { font-size: 11px; color: var(--text2); }
  .card-sub { font-size: 11px; color: var(--text2); line-height: 1.45; margin-top: -6px; }
  .grid-2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; margin-top: 16px; }
  .grid-auto { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 16px; }

  /* --- stat tiles --- */
  .tiles { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; }
  .tile {
    background: var(--glass); border: 1px solid var(--hair); border-radius: var(--radius-lg);
    box-shadow: inset 0 1px 0 rgba(255,255,255,.06), 0 12px 30px -14px rgba(0,0,0,.55);
    padding: 14px 16px; min-width: 0;
  }
  .tile-label { font-size: 11px; font-weight: 700; letter-spacing: .5px; text-transform: uppercase; color: var(--text2); margin-bottom: 6px; overflow-wrap: anywhere; }
  .tile-value { font-size: 22px; font-weight: 700; font-variant-numeric: tabular-nums; }
  .tile-context { font-size: 11px; color: var(--text2); margin-top: 4px; line-height: 1.4; }
  .org-card { margin-top: 16px; }

  /* --- chips / tags / slugs (Console badge recipe: opaque fill, mono) --- */
  .chip {
    display: inline-block; padding: 2px 7px; border-radius: 20px; font-family: var(--font);
    font-size: 10px; font-weight: 600; letter-spacing: .3px; text-transform: uppercase;
    background: var(--chip-fill); border: 1px solid var(--chip-stroke); color: #fff; white-space: nowrap;
  }
  .tag {
    display: inline-block; padding: 2px 7px; margin: 2px 4px 2px 0; border-radius: 20px;
    font-family: var(--font); font-size: 10px; font-weight: 600; letter-spacing: .3px;
    background: #1d2333; border: 1px solid rgba(143,149,214,.4); color: #d4d7f5; white-space: nowrap;
  }
  .slug { font-family: var(--font); font-size: 11px; color: var(--amber); background: #2a2516; border: 1px solid rgba(255,170,0,.3); padding: 2px 7px; border-radius: 20px; white-space: nowrap; }
  .slug-none { color: var(--text2); background: #1c2128; border-color: var(--border); font-style: italic; font-family: var(--font-ui); }
  .dim, .na { color: var(--text2); }
  .na { font-style: italic; }
  .note { font-size: 12px; color: var(--text2); margin: 12px 0 0; }
  .empty { color: var(--text2); font-size: 13px; padding: 8px 0; }
  .path { color: var(--text3); font-size: 11px; }

  /* --- bar charts (single series, --data = the Console's coverage purple) --- */
  .hbars { display: flex; flex-direction: column; gap: 6px; }
  .hbar { display: grid; grid-template-columns: minmax(90px, 32%) 1fr auto; gap: 10px; align-items: center; font-size: 12px; }
  .hbar-label { color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .hbar-track { height: 10px; }
  .hbar-fill { display: block; height: 100%; background: var(--data); border-radius: 0 4px 4px 0; }
  .hbar-value { color: var(--text2); font-family: var(--font); font-size: 11px; white-space: nowrap; }
  .hbar:hover .hbar-fill, .vbar:hover .vbar-fill { background: #b3b8ec; }
  .vchart { display: flex; flex-direction: column; gap: 6px; }
  .vchart-peak { font-size: 11px; color: var(--text2); font-family: var(--font); }
  .vbars { display: flex; align-items: flex-end; gap: 2px; height: 150px; border-bottom: 1px solid var(--border2); }
  .vbar { flex: 1 1 0; height: 100%; display: flex; align-items: flex-end; min-width: 0; }
  .vbar-fill { display: block; width: 100%; background: var(--data); border-radius: 4px 4px 0 0; }
  .vchart-axis { display: flex; justify-content: space-between; font-family: var(--font); font-size: 11px; color: var(--text2); }
  #tip {
    position: fixed; z-index: 400; pointer-events: none; display: none; max-width: 280px;
    background: #111827; border: 1px solid var(--hair); border-radius: var(--radius);
    padding: 6px 9px; font-size: 12px; color: var(--text); box-shadow: 0 8px 20px -6px rgba(0,0,0,.6);
  }

  /* --- tables (Console: solid amber sticky header, oklch zebra) --- */
  .table-wrap { overflow-x: auto; border-radius: var(--radius-lg); border: 1px solid var(--hair); background: rgba(22,27,34,.82); }
  .data-table { width: 100%; border-collapse: separate; border-spacing: 0; font-size: 13px; }
  .data-table thead th {
    background: var(--amber); color: #111; text-align: left; padding: 10px 12px;
    font-size: 11px; font-weight: 800; letter-spacing: .5px; text-transform: uppercase; white-space: nowrap;
  }
  .data-table.sortable th { cursor: pointer; user-select: none; }
  .data-table.sortable th:hover { color: #000; }
  .data-table th[aria-sort="ascending"]::after { content: '\25B2'; font-size: 9px; margin-left: 5px; }
  .data-table th[aria-sort="descending"]::after { content: '\25BC'; font-size: 9px; margin-left: 5px; }
  .data-table td { padding: 9px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
  .data-table tbody tr:nth-child(even) { background: oklch(80% 0.03 300 / 0.16); }
  .data-table tbody tr:nth-child(odd) { background: oklch(80% 0.03 300 / 0.05); }
  .data-table tbody tr:hover { background: rgba(245, 242, 235, .14); }
  .data-table tbody tr:last-child td { border-bottom: none; }
  .data-table td.num { font-variant-numeric: tabular-nums; white-space: nowrap; }
  .data-table td.wrap { min-width: 260px; line-height: 1.45; }
  .data-table code { color: #d4d7f5; }
  .member { display: flex; flex-direction: column; white-space: nowrap; }
  .member span { font-size: 11px; color: var(--text2); }
  .cell-bar { display: flex; align-items: center; gap: 8px; }
  .cell-bar .mini { width: 56px; height: 6px; background: rgba(255,255,255,.08); border-radius: 3px; overflow: hidden; }
  .cell-bar .mini span { display: block; height: 100%; background: var(--data); }
  .workload td:nth-child(8) { min-width: 200px; }
  .workload td:nth-child(10) { min-width: 180px; }
  details.more { margin-top: 12px; }
  details.more summary, details.agent-scope summary { cursor: pointer; color: var(--blue); font-size: 12px; font-weight: 600; }
  details.more[open] summary { margin-bottom: 10px; }

  /* --- agents tab --- */
  .agent-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 16px; align-items: stretch; }
  .agent-card {
    background: var(--glass); border: 1px solid var(--hair); border-radius: var(--radius-lg);
    box-shadow: inset 0 1px 0 rgba(255,255,255,.06), 0 12px 30px -14px rgba(0,0,0,.55);
    backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
    padding: 18px; display: flex; flex-direction: column; gap: 10px;
  }
  .agent-head { display: flex; align-items: center; gap: 12px; }
  .agent-avatar { width: 52px; height: 52px; border-radius: 50%; overflow: hidden; flex-shrink: 0; background: #1c2128; border: 2px solid rgba(255,170,0,.55); }
  .agent-avatar img { width: 100%; height: 100%; object-fit: cover; object-position: top center; display: block; }
  .agent-id { flex: 1; min-width: 0; }
  .agent-name { font-weight: 700; font-size: 15px; }
  .agent-role { font-size: 12px; color: var(--text2); }
  .agent-tagline { margin: 2px 0 0; font-size: 15px; font-weight: 600; line-height: 1.4; color: #ffd27a; border-left: 3px solid var(--amber); padding-left: 10px; }
  .agent-bio { margin: 0; font-size: 13px; line-height: 1.55; }
  .agent-scope p { margin: 8px 0 0; font-size: 12px; line-height: 1.55; color: var(--text2); }
  .agent-foot { margin-top: auto; padding-top: 10px; border-top: 1px solid var(--hair); display: flex; flex-direction: column; gap: 8px; }
  .agent-works { font-size: 12px; line-height: 1.5; color: var(--text2); }
  .agent-works-label { color: var(--text); font-weight: 600; }
  .agent-meta { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; justify-content: space-between; }
  .agent-facts { display: flex; flex-wrap: wrap; gap: 4px 10px; font-family: var(--font); font-size: 11px; color: var(--text2); }

  /* --- skills tab --- */
  .skill-card { gap: 10px; }
  .skill-desc { margin: 0; font-size: 13px; line-height: 1.5; }
  .skill-users { display: flex; flex-wrap: wrap; align-items: center; gap: 2px; }
  .skill-users .dim { font-size: 12px; }
  .skill-users .label { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .5px; color: var(--text2); margin-right: 8px; }

  /* --- activity tab --- */
  .filter-row { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 14px; }
  .pill {
    background: rgba(255,255,255,.08); border: 1px solid var(--hair); color: var(--text);
    padding: 5px 12px; border-radius: 20px; cursor: pointer; font: 600 12px var(--font-ui);
  }
  .pill span { font-family: var(--font); color: var(--text2); margin-left: 4px; }
  .pill:hover { border-color: var(--amber); box-shadow: 0 0 0 2px rgba(255,170,0,.14); }
  .pill.active { background: var(--amber); border-color: var(--amber); color: #111; }
  .pill.active span { color: #111; }
  .feed { display: flex; flex-direction: column; gap: 14px; }
  .day[hidden] { display: none; }
  .day-head { font-family: var(--font); font-size: 12px; font-weight: 700; color: var(--text); padding-bottom: 6px; border-bottom: 1px solid var(--hair); }
  .day-count { color: var(--text2); font-weight: 400; margin-left: 6px; }
  .day ul { list-style: none; margin: 0; padding: 0; }
  .commit { display: grid; grid-template-columns: 74px 1fr; gap: 2px 10px; padding: 7px 0; border-bottom: 1px solid rgba(255,255,255,.05); }
  .commit[hidden] { display: none; }
  .commit .type { grid-row: span 2; align-self: start; text-align: center; padding: 2px 6px; border-radius: 20px; font-family: var(--font); font-size: 10px; font-weight: 600; letter-spacing: .3px; background: #1c2128; border: 1px solid var(--border2); color: var(--text2); }
  .type-feat { background: #10291a !important; border-color: rgba(63,185,80,.45) !important; color: #7ee2a0 !important; }
  .type-fix { background: #33191a !important; border-color: rgba(248,81,73,.45) !important; color: #ff9b94 !important; }
  .type-docs { background: #11233a !important; border-color: rgba(88,166,255,.45) !important; color: #9ccbff !important; }
  .type-chore, .type-ci, .type-build { background: #2a2516 !important; border-color: rgba(255,170,0,.35) !important; color: #ffd27a !important; }
  .type-refactor, .type-perf, .type-style, .type-test { background: #1d2333 !important; border-color: rgba(143,149,214,.45) !important; color: #c9cdf3 !important; }
  .commit-msg { font-size: 13px; line-height: 1.4; overflow-wrap: anywhere; }
  .commit-meta { font-size: 11px; color: var(--text2); }

  /* --- org chart: node/connector layout UNCHANGED (see BRANCH_LAYOUT). Only
     the panel around it (.org-card, a Console glass card) changed. --- */
  .canvas-scroll { overflow-x: auto; padding-bottom: .25rem; }
  /* Horizontal padding is load-bearing for drawOrgLines(): every trunk runs
     left of the avatars it serves at (leftmost avatar edge - 16px gutter),
     and Yara sits flush with the content edge, so without it her trunk would
     land at negative X and be clipped by .canvas-scroll. */
  .org-chart { position: relative; padding: .5rem 28px .25rem; }
  .root-row { display: flex; justify-content: center; margin-bottom: 2.25rem; }
  .branches { display: flex; justify-content: space-between; gap: 3rem; }
  .branch { display: flex; flex-direction: column; flex: 0 0 auto; }
  .branch-left { align-items: flex-start; }
  .branch-right { align-items: flex-start; }
  .row { margin-bottom: 2.25rem; }
  .row:last-child { margin-bottom: 0; }
  svg#lines { position: absolute; inset: 0; pointer-events: none; overflow: visible; z-index: 0; }
  .edge { fill: none; stroke: var(--border); stroke-width: 1.5; }
  .node { position: relative; z-index: 1; display: flex; flex-direction: row; align-items: center; width: max-content; }
  .avatar-ring {
    width: 140px; height: 140px; border-radius: 50%; flex-shrink: 0;
    background: var(--fill); border: 3px solid var(--stroke);
    display: flex; align-items: center; justify-content: center; overflow: hidden;
    box-shadow: 0 0 0 5px var(--card-bg), 0 4px 14px rgba(0,0,0,.35);
    position: relative; z-index: 2;
  }
  .avatar { width: 100%; height: 100%; object-fit: cover; object-position: top center; }
  /* Fixed px width AND height, no shrink: identical footprints keep sibling
     avatars on one trunk X, and px (not rem) keeps the plate invariant to
     the reader's root font size. Headroom: longest role "Application
     Security Engineer" ~159px in a 252px text column. */
  .info-box {
    background: var(--fill); border: 2px solid var(--stroke); border-radius: 10px;
    z-index: 1;
    flex: 0 0 300px; width: 300px; height: 64px;
    margin-left: -16px;
    padding: 0 16px 0 28px;
    display: flex; flex-direction: column; justify-content: center;
  }
  .rname { font-weight: 700; font-size: 16px; line-height: 20px; color: var(--text); white-space: nowrap; }
  .rrole { font-size: 12px; margin-top: 3px; line-height: 16px; color: var(--stroke); white-space: nowrap; }
  .legend { display: flex; justify-content: center; gap: 8px 22px; flex-wrap: wrap; font-size: 12px; color: var(--text2); padding-top: 12px; border-top: 1px solid var(--hair); }
  .legend-item { display: flex; align-items: center; gap: 6px; }
  .legend-swatch { width: 12px; height: 12px; border-radius: 50%; border: 2px solid var(--stroke-color); background: var(--fill-color); }
  .legend-line { width: 18px; height: 0; border-top: 1.4px solid var(--text2); }

  footer { text-align: center; color: var(--text2); font-size: 12px; margin: 28px 0 0; line-height: 1.6; }

  @media (max-width: 1100px) {
    .tiles { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .grid-2 { grid-template-columns: 1fr; }
  }
  @media (max-width: 760px) {
    .strip { position: static; flex-direction: column; align-items: stretch; gap: 8px; padding: 8px 10px; }
    .brand img { width: 32px; height: 32px; }
    .tab-bar { flex-wrap: wrap; overflow: visible; }
    main { padding: 12px 10px 24px; }
    .dash-section { padding: 12px; }
    .card { padding: 14px; }
    .agent-grid, .grid-auto { grid-template-columns: 1fr; }
  }
  @media (max-width: 480px) {
    .tiles { grid-template-columns: 1fr 1fr; gap: 10px; }
    .tile-value { font-size: 18px; }
    .brand-sep, .brand-sub { display: none; }
    .hbar { grid-template-columns: minmax(70px, 34%) 1fr auto; gap: 6px; }
  }
"""

JS = r"""
  // --- org chart connector lines (logic unchanged) --------------------------
  // Node positions are live flexbox layout, so lines are re-measured via
  // getBoundingClientRect() on load/resize/tab-switch. Every non-root node's
  // edges leave its own 9 o'clock point to a shared left-hand trunk and enter
  // each child's 9 o'clock point; the root uses a top-down bus instead.
  var TRUNK_GUTTER = 16; // must stay > the avatar ring's 5px box-shadow ring

  function drawOrgLines() {
    var container = document.getElementById('org-chart');
    var svg = document.getElementById('lines');
    if (!container || !svg) return;
    var containerRect = container.getBoundingClientRect();
    if (containerRect.width === 0 && containerRect.height === 0) return; // tab hidden

    function box(name) {
      var el = document.getElementById('avatar-' + name);
      if (!el) return null;
      var r = el.getBoundingClientRect();
      return {
        left: r.left - containerRect.left,
        top: r.top - containerRect.top,
        bottom: r.bottom - containerRect.top,
        cx: r.left + r.width / 2 - containerRect.left,
        cy: r.top + r.height / 2 - containerRect.top
      };
    }
    function n(v) { return v.toFixed(1); }

    var byParent = {};
    var order = [];
    EDGES.forEach(function (edge) {
      if (!byParent[edge[0]]) { byParent[edge[0]] = []; order.push(edge[0]); }
      byParent[edge[0]].push(edge[1]);
    });

    var paths = [];
    order.forEach(function (parent) {
      var p = box(parent);
      if (!p) return;
      var kids = byParent[parent].map(box).filter(Boolean);
      if (!kids.length) return;

      if (parent === ROOT) {
        var topMost = Math.min.apply(null, kids.map(function (k) { return k.top; }));
        var busY = (p.bottom + topMost) / 2;
        kids.forEach(function (k) {
          paths.push('<path class="edge" d="M ' + n(p.cx) + ' ' + n(p.bottom) +
            ' V ' + n(busY) + ' H ' + n(k.cx) + ' V ' + n(k.top) + '"></path>');
        });
        return;
      }

      var leftMost = Math.min.apply(null, kids.map(function (k) { return k.left; }));
      var trunkX = Math.min(p.left, leftMost) - TRUNK_GUTTER;
      kids.forEach(function (k) {
        paths.push('<path class="edge" d="M ' + n(p.left) + ' ' + n(p.cy) +
          ' H ' + n(trunkX) + ' V ' + n(k.cy) + ' H ' + n(k.left) + '"></path>');
      });
    });
    svg.innerHTML = paths.join('');
  }

  // --- tabs (WAI-ARIA tabs pattern: arrows/Home/End move, hash deep-links) --
  var tabs = Array.prototype.slice.call(document.querySelectorAll('.tab-btn'));
  function activate(key, focus) {
    var found = false;
    tabs.forEach(function (b) {
      var on = b.dataset.tab === key;
      if (on) found = true;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
      b.tabIndex = on ? 0 : -1;
      if (on && focus) b.focus();
    });
    if (!found) return;
    document.querySelectorAll('.tab-panel').forEach(function (p) {
      p.classList.toggle('active', p.id === 'tab-' + key);
    });
    if (history.replaceState) history.replaceState(null, '', '#' + key);
    if (key === 'overview') drawOrgLines();
  }
  tabs.forEach(function (btn, i) {
    btn.addEventListener('click', function () { activate(btn.dataset.tab, false); });
    btn.addEventListener('keydown', function (e) {
      var j = null;
      if (e.key === 'ArrowRight') j = (i + 1) % tabs.length;
      else if (e.key === 'ArrowLeft') j = (i - 1 + tabs.length) % tabs.length;
      else if (e.key === 'Home') j = 0;
      else if (e.key === 'End') j = tabs.length - 1;
      if (j !== null) { e.preventDefault(); activate(tabs[j].dataset.tab, true); }
    });
  });

  // --- sortable tables -------------------------------------------------------
  document.querySelectorAll('table.sortable').forEach(function (tbl) {
    var ths = tbl.querySelectorAll('thead th');
    ths.forEach(function (th, col) {
      function sort() {
        var asc = th.getAttribute('aria-sort') !== 'ascending';
        ths.forEach(function (o) { o.setAttribute('aria-sort', 'none'); });
        th.setAttribute('aria-sort', asc ? 'ascending' : 'descending');
        var num = th.dataset.kind === 'num';
        var body = tbl.tBodies[0];
        var rows = Array.prototype.slice.call(body.rows);
        rows.sort(function (a, b) {
          var ca = a.cells[col], cb = b.cells[col];
          var va = ca.dataset.sort !== undefined ? ca.dataset.sort : ca.textContent;
          var vb = cb.dataset.sort !== undefined ? cb.dataset.sort : cb.textContent;
          var r = num ? (parseFloat(va) || 0) - (parseFloat(vb) || 0) : String(va).localeCompare(String(vb));
          return asc ? r : -r;
        });
        rows.forEach(function (r) { body.appendChild(r); });
      }
      th.addEventListener('click', sort);
      th.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); sort(); } });
    });
  });

  // --- activity filter -------------------------------------------------------
  function filterFeed(kind) {
    var any = false;
    document.querySelectorAll('#feed .day').forEach(function (day) {
      var shown = 0;
      day.querySelectorAll('.commit').forEach(function (c) {
        var on = kind === 'all' || c.dataset.kind === kind;
        c.hidden = !on;
        if (on) shown++;
      });
      day.hidden = shown === 0;
      day.querySelector('.day-count').textContent = shown + (shown === 1 ? ' commit' : ' commits');
      if (shown) any = true;
    });
    var empty = document.querySelector('.feed-empty');
    if (empty) empty.hidden = any;
  }
  document.querySelectorAll('.filter-row .pill').forEach(function (p) {
    p.addEventListener('click', function () {
      document.querySelectorAll('.filter-row .pill').forEach(function (o) {
        o.classList.toggle('active', o === p);
        o.setAttribute('aria-pressed', o === p ? 'true' : 'false');
      });
      filterFeed(p.dataset.filter);
    });
  });
  if (document.getElementById('feed')) filterFeed('human');

  // --- chart tooltip ([data-tip]) --------------------------------------------
  var tip = document.getElementById('tip');
  document.addEventListener('mousemove', function (e) {
    var t = e.target.closest ? e.target.closest('[data-tip]') : null;
    if (!t) { tip.style.display = 'none'; return; }
    tip.textContent = t.getAttribute('data-tip');
    tip.style.display = 'block';
    var x = Math.min(e.clientX + 12, window.innerWidth - tip.offsetWidth - 8);
    tip.style.left = x + 'px';
    tip.style.top = (e.clientY + 14) + 'px';
  });

  var initial = (location.hash || '').replace('#', '');
  if (initial && document.getElementById('tab-' + initial)) activate(initial, false);
  window.addEventListener('hashchange', function () {
    var key = (location.hash || '').replace('#', '');
    if (key && document.getElementById('tab-' + key)) activate(key, false);
  });
  window.addEventListener('load', drawOrgLines);
  window.addEventListener('resize', drawOrgLines);
"""


def build_html(avatar_dir_rel: str, logo_rel: str, ctx: dict) -> str:
    """Render the full page for one output location (.claude/ or docs/), each
    with its own relative asset paths."""
    generated = ctx["generated"]
    panels = "\n".join(
        [
            build_overview_tab(ctx, avatar_dir_rel),
            build_agents_tab(ctx, avatar_dir_rel),
            build_team_tab(ctx),
            build_skills_tab(ctx),
            build_mcp_tab(ctx),
            build_activity_tab(ctx),
            build_tokens_tab(ctx),
        ]
    )
    data_js = f"var EDGES = {json.dumps(RELATIONSHIPS)};\n  var ROOT = {json.dumps(ROOT)};"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Detection-Engineering &mdash; Team Ops</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="{logo_rel}">
<style>{CSS}</style>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="strip">
  <div class="brand">
    <img src="{logo_rel}" alt="" width="40" height="40">
    <span class="brand-title">Detection-Engineering</span>
    <span class="brand-sep"></span>
    <span class="brand-sub">Team Ops · generated {generated}</span>
  </div>
  <nav class="tab-bar" role="tablist" aria-label="Dashboard sections">
      {build_nav_html()}
  </nav>
</header>
<main id="main">
{panels}
  <footer>
    Generated {generated} by <code>.claude/generate_dashboard.py</code> from <code>.claude/agent_usage_log.jsonl</code>,
    <code>git log</code>, <code>audit/</code>, <code>CLAUDE.md</code>, <code>.claude/agents|skills|commands</code> and <code>.mcp.json</code>.
    Re-run the script to refresh.
  </footer>
</main>
<div id="tip" role="tooltip"></div>
<script>
  {data_js}
{JS}
</script>
</body>
</html>
"""


def build_context() -> dict:
    all_rows, skipped = load_usage_rows()
    # Rows logged under the root (Gaz) are whole-session totals Gaz recorded
    # for work done directly in the top-level session -- one of them is ~87M
    # tokens -- not subagent dispatches. Folding them into dispatch totals and
    # averages would swamp every figure, so they are kept apart and disclosed.
    rows = [r for r in all_rows if r["name"] != ROOT]
    session_rows = [r for r in all_rows if r["name"] == ROOT]
    agents = load_agents()
    return {
        "rows": rows,
        "session_rows": session_rows,
        "lead": lead_usage(session_rows),
        "skipped": skipped,
        "usage": member_usage(rows),
        "activity": load_activity(),
        "agents": agents,
        "skills": load_skills(agents),
        "commands": load_commands(),
        "mcp": load_mcp_servers(),
        "ownership": load_ownership(),
        "generated": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
    }


def _check_avatars_present() -> int:
    """Every roster member's _transparent avatar must exist under
    docs/pictures/avatars/ -- both outputs read that one directory."""
    avatar_dir = REPO_ROOT / "docs" / "pictures" / "avatars"
    missing = 0
    for name, *_rest in ROSTER:
        path = avatar_dir / f"{name}_transparent.png"
        if not path.is_file():
            print(f"warning: missing avatar source {path}, team-ops.html will show a broken image for {name}")
            missing += 1
    return missing


def main() -> int:
    missing = _check_avatars_present()
    ctx = build_context()

    OUT_PATH.write_text(build_html(LOCAL_AVATAR_DIR_REL, LOCAL_LOGO_REL, ctx), encoding="utf-8")
    print(f"Wrote {OUT_PATH}")

    PAGES_OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    PAGES_OUT_PATH.write_text(build_html(PAGES_AVATAR_DIR_REL, PAGES_LOGO_REL, ctx), encoding="utf-8")
    print(f"Wrote {PAGES_OUT_PATH}")

    # Hard failure (2026-08-28): CI publishes this to Pages, so a missing
    # avatar must fail the run rather than ship a broken <img>.
    if missing:
        print(f"error: {missing} avatar(s) missing out of {len(ROSTER)} roster members -- team-ops.html would ship broken <img> tags, failing")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
