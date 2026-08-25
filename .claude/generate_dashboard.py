#!/usr/bin/env python3
# .claude/generate_dashboard.py
#
# Generates .claude/dashboard.html: an app-shell style overview of the
# custom subagent team -- sidebar nav, stat cards, team org chart, and a
# real activity feed sourced from `git log` at generation time.
#
# Not part of the detection-rule pipeline scripts/ generates -- this is an
# internal ops dashboard for the team itself. Lives under .claude/ for that
# reason. Ownership (2026-08-25): this is a data-driven HTML/CSS/JS generator,
# same shape of problem as scripts/docs/generate_stats.py -- so the generator
# code, HTML structure, CSS and layout are Sienna's (Frontend Engineer), not
# Gaz's, per CLAUDE.md's roster table. The file's actual content/roster data
# (WHO is on the team, the reporting tree, name/role text) stays Gaz's call
# via CLAUDE.md/TEAM.md -- same split as the rule browser, where Sienna owns
# the page and Kwame/Gaz own what rules exist.
#
# "Attekintes" (Overview), "Aktivitas" (Activity) and "Token Monitor" have
# real content; Agents, Group, Skills and MCP are still scaffolded nav
# entries that render a plain "not built yet" placeholder until a real need
# for that page shows up -- not a promise every one of them ships.
#
# 2026-08-25 redesign (user's explicit ask): the team chart moved from flat
# per-area rows to an actual reporting tree (TREE below), colors now encode
# leadership/strategic/engineering/compliance level rather than the
# CLAUDE.md Strategic/Analytical/Operational Area column -- the two are
# deliberately different groupings, this one is chart-only. Per-node token
# badges were dropped from the chart (tokens live on the Token Monitor tab
# instead), and the activity feed moved off the Overview tab onto its own.
#
# Two real, honest data sources, no fabricated numbers:
#   - .claude/agent_usage_log.jsonl -- per-dispatch tokens/tool-uses, a line
#     only exists when Gaz actually read a real <usage> block back from a
#     dispatch. Silence for a specialist means "not logged", not zero work.
#   - `git log` on this repo, read fresh at generation time -- the activity
#     feed is never a hardcoded snapshot.
#
# Run: python3 .claude/generate_dashboard.py

from __future__ import annotations

import json
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
LOG_PATH = HERE / "agent_usage_log.jsonl"
OUT_PATH = HERE / "dashboard.html"

# Relative to this generated file's own location (.claude/dashboard.html),
# so <img> tags resolve when the file is opened straight off disk.
AVATAR_DIR_REL = "agents/avatars"
LOGO_REL = "../docs/branding/logo.png"

ACTIVITY_LIMIT = 40

# Chart-only grouping (2026-08-25, user's explicit ask) -- NOT the CLAUDE.md
# Strategic/Analytical/Operational Area column. Purple = leadership, green =
# strategic, blue = engineering/technology, yellow = compliance/docs.
AREA_COLORS = {
    "leadership": {"fill": "#2c1b4d", "stroke": "#b388ff", "text": "#f1e6ff"},
    "strategic": {"fill": "#12351f", "stroke": "#4caf7d", "text": "#dcf7ee"},
    "engineering": {"fill": "#0d2440", "stroke": "#58a6ff", "text": "#dceeff"},
    "compliance": {"fill": "#3d2c07", "stroke": "#e0a94c", "text": "#fdecc9"},
    # Bjorn is the engineering branch's coordinator, not a peer of the four
    # specialists he sits above -- kept visually distinct (turquoise/teal)
    # from the "engineering" blue group (2026-08-25, user's explicit ask).
    "coordinator": {"fill": "#0d3b36", "stroke": "#2dd4bf", "text": "#d3fff5"},
}

# Kept in sync by hand with TEAM.md's table. name, role, chart-color group
# (see AREA_COLORS above), agent slug (None for Gaz -- reference file only,
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

# Direct-report tree (2026-08-25 redesign, user's explicit ask): parent ->
# children. Bjorn sits under Yara as team coordinator/lead engineer for the
# four engineering specialists; Masha, Priya and Chloe report directly under
# Kwame. This is the single source of truth for RELATIONSHIPS (the SVG
# connecting lines, drawn DOM-position-based via drawLines() in JS) --
# who-works-closely-with-whom (cross-branch collaboration) is deliberately
# left out for now, to be added once that's decided.
TREE: dict[str, list[str]] = {
    "Gaz": ["Yara", "Kwame"],
    "Yara": ["Bjorn"],
    "Kwame": ["Masha", "Priya", "Chloe"],
    "Bjorn": ["Yuki", "Jamal", "Sienna", "Kai"],
}

def _build_relationships() -> list[tuple[str, str]]:
    edges: list[tuple[str, str]] = []

    def walk(parent: str) -> None:
        for child in TREE.get(parent, []):
            edges.append((parent, child))
            walk(child)

    walk("Gaz")
    return edges


RELATIONSHIPS = _build_relationships()

# Chart *layout* (round 8, 2026-08-25 revert): back to the flexbox
# staircase tree from rounds 3-5, which the user explicitly approved, after
# a radial/polar composition was tried for two rounds (6-7) and rejected
# outright ("keeps getting worse") in favor of a reference org-chart
# graphic (circular photo + name/title box, right-angle connector lines).
# TREE above stays the single source of truth for who reports to whom;
# BRANCH_LAYOUT below is purely the *visual* grouping -- two independently
# shaped columns, one per top-level branch off Gaz, each stair-stepping
# inward from its own panel edge. Unlike round 6-7's fixed polar math,
# node positions are NOT computed here in Python -- flexbox lays them out
# live in the browser, so the connector lines are drawn by JS at render
# time via getBoundingClientRect() (see drawOrgLines() in the page script),
# same as the original round 3-5 tree.
BRANCH_LAYOUT: list[tuple[str, list[list[str]]]] = [
    ("Yara", [["Bjorn"], ["Jamal"], ["Kai"], ["Sienna"], ["Yuki"]]),
    ("Kwame", [["Masha"], ["Priya"], ["Chloe"]]),
]

INDENT_STEP_REM = 3.25  # staircase indent per depth-step, in rem -- see _build_depth_map()


def _build_depth_map() -> dict[str, int]:
    """BFS distance from Gaz over TREE. Used to compute each branch node's
    staircase indent: indent level = depth[name] - depth[branch_head]."""
    depth: dict[str, int] = {"Gaz": 0}

    def walk(parent: str) -> None:
        for child in TREE.get(parent, []):
            depth[child] = depth[parent] + 1
            walk(child)

    walk("Gaz")
    return depth


DEPTH = _build_depth_map()

NAV_ITEMS = [
    ("overview", "Áttekintés", "grid", True),
    ("agents", "Ügynökök", "bot", False),
    ("activity", "Aktivitás", "pulse", False),
    ("group", "Csapat", "people", False),
    ("skills", "Skillek", "star", False),
    ("mcp", "MCP", "plug", False),
    ("tokens", "Token Monitor", "bars", False),
]

ICONS = {
    "grid": '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
    "bot": '<rect x="4" y="8" width="16" height="12" rx="2.5"/><circle cx="9" cy="14" r="1.3" fill="currentColor" stroke="none"/><circle cx="15" cy="14" r="1.3" fill="currentColor" stroke="none"/><path d="M12 8V4"/><circle cx="12" cy="3" r="1.2"/>',
    "pulse": '<path d="M3 12h4l2-7 4 14 2-7h6"/>',
    "people": '<circle cx="9" cy="8" r="3"/><path d="M3 20c0-3.3 2.7-6 6-6s6 2.7 6 6"/><circle cx="17" cy="8" r="2.4"/><path d="M15.5 14.2c2.6.4 4.5 2.7 4.5 5.8"/>',
    "star": '<path d="M12 3l2.6 5.6 6.1.6-4.6 4.1 1.3 6-5.4-3.1-5.4 3.1 1.3-6-4.6-4.1 6.1-.6z"/>',
    "plug": '<path d="M9 2v6M15 2v6M6 8h12l-1 5a5 5 0 0 1-10 0z"/><path d="M12 17v5"/>',
    "bars": '<path d="M4 20V10M12 20V4M20 20v-7"/>',
    "empty": '<circle cx="12" cy="12" r="9"/><path d="M9 9l6 6M15 9l-6 6"/>',
}


def svg_icon(key: str, cls: str = "") -> str:
    return f'<svg class="{cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">{ICONS[key]}</svg>'


# --- data loading --------------------------------------------------------------


def load_usage() -> dict[str, dict]:
    stats: dict[str, dict] = defaultdict(lambda: {"dispatches": 0, "tokens": 0, "tool_uses": 0, "duration_ms": 0, "last_date": None, "dispatches_today": 0})
    if not LOG_PATH.exists():
        return stats
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    for raw in LOG_PATH.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        rec = json.loads(raw)
        s = stats[rec["name"]]
        s["dispatches"] += 1
        s["tokens"] += rec["tokens"]
        s["tool_uses"] += rec["tool_uses"]
        s["duration_ms"] += rec["duration_ms"]
        if rec["date"] == today:
            s["dispatches_today"] += 1
        if s["last_date"] is None or rec["date"] > s["last_date"]:
            s["last_date"] = rec["date"]
    return stats


def load_activity() -> list[dict]:
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "log", f"-n{ACTIVITY_LIMIT}", "--pretty=format:%h|%ad|%s", "--date=format:%Y-%m-%d %H:%M"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            encoding="utf-8",
            check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    items = []
    for line in out.splitlines():
        parts = line.split("|", 2)
        if len(parts) != 3:
            continue
        h, when, msg = parts
        items.append({"hash": h, "when": when, "msg": msg})
    return items


def load_register_progress() -> tuple[int, int] | None:
    path = REPO_ROOT / "audit" / "feature-and-process-audit.md"
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8")
    closed = sum(1 for line in text.splitlines() if line.startswith("- [x]"))
    open_ = sum(1 for line in text.splitlines() if line.startswith("- [ ]"))
    total = closed + open_
    if total == 0:
        return None
    return closed, total


# --- formatting ------------------------------------------------------------------


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
    return f"{minutes:.0f}m"


# --- team panel --------------------------------------------------------------


ROSTER_BY_NAME: dict[str, tuple[str, str]] = {name: (role, area) for name, role, area, _ in ROSTER}


def node_html(name: str, role: str, area: str) -> str:
    """One org-chart card: circle avatar on the left, a colored
    rounded-rectangle info-box overlapping it slightly on the right,
    holding bold name + role -- unchanged from the round 1-5/7 side
    info-box style. No left/right/top side switch anymore: that existed
    only to dodge radial-geometry collisions, and a flexbox tree never
    puts a parent on both sides of a node, so every card is simply
    avatar-left, box-right, matching the reference org-chart graphic.
    Connector lines anchor to #avatar-{name} specifically (not the whole
    .node), so they stay correct regardless of the info-box's variable
    width."""
    colors = AREA_COLORS[area]
    avatar_file = f"{AVATAR_DIR_REL}/{name}_transparent.png"
    return (
        f'<div class="node" style="--fill:{colors["fill"]};--stroke:{colors["stroke"]};--text:{colors["text"]}">'
        f'<div class="avatar-ring" id="avatar-{name}"><img src="{avatar_file}" alt="{name}" class="avatar" loading="lazy"></div>'
        f'<div class="info-box"><div class="rname">{name}</div><div class="rrole">{role}</div></div>'
        f"</div>"
    )


def build_branch_html(head: str, rows: list[list[str]], side: str) -> str:
    """One .branch column: the branch head itself as the first row (at
    indent 0), then a stack of .row divs for BRANCH_LAYOUT's explicit
    report rows, each stair-stepped inward (toward the panel's middle) by
    INDENT_STEP_REM per depth-step below the head, via inline margin-left
    (left branch, indenting rightward) or margin-right (right branch,
    indenting leftward). A row's indent is keyed off its first node's
    depth -- today every row holds exactly one node, so that's just that
    node's own depth. BRANCH_LAYOUT only lists the head's *reports* (e.g.
    Yara's rows are [Bjorn], [Jamal], ... -- Yara herself isn't in that
    list), so the head row is prepended here rather than expecting callers
    to repeat it."""
    prop = "margin-left" if side == "left" else "margin-right"
    all_rows = [[head], *rows]
    rows_html = []
    for row in all_rows:
        indent = DEPTH[row[0]] - DEPTH[head]
        cells = "".join(node_html(name, *ROSTER_BY_NAME[name]) for name in row)
        rows_html.append(f'      <div class="row" style="{prop}:{indent * INDENT_STEP_REM:.2f}rem">{cells}</div>')
    return "\n".join(rows_html)


def build_org_chart_html() -> str:
    """Gaz alone, centered, at top; below him a `.branches` flex row
    (`justify-content: space-between`) holding the two independently
    shaped branch columns, each anchored toward its own panel edge with an
    open gutter between them (reserved for a future "who collaborates
    closely with whom" feature -- not drawn yet). `#lines` is an empty SVG
    overlay; JS fills it in at render time once flexbox has actually
    placed the nodes (see drawOrgLines() in the page script) -- unlike
    round 6-7's static generation-time SVG, real positions aren't known
    until the browser lays the flex boxes out."""
    root_html = node_html("Gaz", *ROSTER_BY_NAME["Gaz"])
    branches = []
    for (head, rows), side in zip(BRANCH_LAYOUT, ("left", "right")):
        branches.append(f'    <div class="branch branch-{side}">\n{build_branch_html(head, rows, side)}\n    </div>')
    branches_html = "\n".join(branches)
    return f"""<div class="org-chart" id="org-chart">
      <svg id="lines"></svg>
      <div class="root-row">
        {root_html}
      </div>
      <div class="branches">
{branches_html}
      </div>
    </div>"""


# --- activity panel ------------------------------------------------------------


def build_activity_html(items: list[dict]) -> str:
    if not items:
        return '<div class="activity-empty">Nincs git előzmény ehhez a repo-hoz.</div>'
    rows = []
    for it in items:
        rows.append(
            f'      <div class="activity-item">'
            f'<span class="activity-dot"></span>'
            f'<div class="activity-body">'
            f'<span class="activity-msg">{it["msg"]}</span>'
            f'<span class="activity-meta"><span class="activity-hash">{it["hash"]}</span> · {it["when"]}</span>'
            f"</div></div>"
        )
    return "\n".join(rows)


def build_activity_tab_html(items: list[dict]) -> str:
    return f"""    <section class="tab-panel" id="tab-activity">
      <div class="page-head">
        <h1>Aktivitás</h1>
        <p>Commit-előzmény ehhez a repo-hoz, frissen a <code>git log</code>-ból generálva.</p>
      </div>
      <div class="panel">
        <div class="panel-header">
          <h2>Aktivitás</h2>
          <span class="hint">git log, friss</span>
        </div>
        <div class="activity-list">
{build_activity_html(items)}
        </div>
      </div>
    </section>"""


# --- token monitor panel --------------------------------------------------------


def build_tokens_table_html(usage: dict[str, dict]) -> str:
    rows = []
    for name, role, _area, slug in ROSTER:
        if slug is None:
            continue
        stat = usage.get(name)
        if stat and stat["dispatches"] > 0:
            rows.append(
                f"      <tr>"
                f"<td>{name}</td><td>{role}</td>"
                f'<td>{stat["dispatches"]}</td>'
                f'<td>{fmt_tokens(stat["tokens"])}</td>'
                f'<td>{stat["tool_uses"]}</td>'
                f'<td>{fmt_duration(stat["duration_ms"])}</td>'
                f'<td>{stat["last_date"]}</td>'
                f"</tr>"
            )
        else:
            rows.append(
                f'      <tr class="row-empty">'
                f"<td>{name}</td><td>{role}</td>"
                f'<td colspan="5">nincs naplózott munka</td>'
                f"</tr>"
            )
    return "\n".join(rows)


def build_tokens_tab_html(usage: dict[str, dict]) -> str:
    return f"""    <section class="tab-panel" id="tab-tokens">
      <div class="page-head">
        <h1>Token Monitor</h1>
        <p>Naplózott dispatch-ek tagonként, a <code>.claude/agent_usage_log.jsonl</code> naplóból. A vizualizáció designja később készül el.</p>
      </div>
      <div class="panel">
        <table class="token-table">
          <thead>
            <tr><th>Tag</th><th>Szerep</th><th>Dispatch</th><th>Token</th><th>Tool use</th><th>Idő</th><th>Utolsó</th></tr>
          </thead>
          <tbody>
{build_tokens_table_html(usage)}
          </tbody>
        </table>
      </div>
    </section>"""


# --- nav / placeholders --------------------------------------------------------

PLACEHOLDER_COPY = {
    "agents": "Részletes ügynök-lista és állapotfigyelés -- ha lesz rá valós igény.",
    "group": "Mélyebb csapat-nézet -- egyelőre az áttekintő oldal Csapat panelje adja ezt.",
    "skills": "A .claude/skills/ tartalmának áttekintése.",
    "mcp": "A konfigurált MCP szerverek állapota.",
}


def build_nav_html() -> str:
    items = []
    for key, label, icon, active in NAV_ITEMS:
        cls = "nav-item active" if active else "nav-item"
        items.append(f'      <button class="{cls}" data-tab="{key}">{svg_icon(icon)}<span>{label}</span></button>')
    return "\n".join(items)


def build_placeholder_tabs() -> str:
    panels = []
    for key, label, _icon, active in NAV_ITEMS:
        if active or key in ("activity", "tokens"):
            continue
        copy = PLACEHOLDER_COPY.get(key, "Hamarosan.")
        panels.append(f"""    <section class="tab-panel" id="tab-{key}">
      <div class="placeholder">
        {svg_icon("empty")}
        <h2>{label}</h2>
        <p>{copy}</p>
        <p class="placeholder-note">Még nincs megvalósítva.</p>
      </div>
    </section>""")
    return "\n".join(panels)


TEMPLATE = """<!doctype html>
<html lang="hu">
<head>
<meta charset="utf-8">
<title>Detection-Engineering &mdash; Áttekintés</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {{
    --bg: #0d1117;
    --sidebar-bg: #161b22;
    --card-bg: #161b22;
    --border: #30363d;
    --text: #e6edf3;
    --text-dim: #8b949e;
    --accent: #f0a341;
    --accent-soft: rgba(240, 163, 65, .12);
    --blue: #58a6ff;
    --green: #3fb950;
    --hover-bg: #21262d;
  }}
  * {{ box-sizing: border-box; }}
  html, body {{ margin: 0; padding: 0; }}
  body {{
    display: flex;
    min-height: 100vh;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }}

  /* --- sidebar --- */
  .sidebar {{
    width: 234px;
    flex-shrink: 0;
    background: var(--sidebar-bg);
    border-right: 1px solid var(--border);
    padding: 1.1rem .75rem 1.5rem;
    position: sticky;
    top: 0;
    height: 100vh;
    overflow-y: auto;
  }}
  .brand {{
    display: flex;
    align-items: center;
    gap: .6rem;
    padding: .35rem .5rem 1.4rem;
  }}
  .brand img {{ width: 30px; height: 30px; border-radius: 6px; }}
  .brand-text {{ font-weight: 700; font-size: .88rem; line-height: 1.25; }}
  .brand-sub {{ font-size: .68rem; color: var(--text-dim); display: flex; align-items: center; gap: .35rem; margin-top: .1rem; }}
  .status-dot {{ width: 6px; height: 6px; border-radius: 50%; background: var(--green); box-shadow: 0 0 0 3px rgba(63,185,80,.15); flex-shrink: 0; }}
  nav {{ display: flex; flex-direction: column; gap: .1rem; }}
  .nav-item {{
    display: flex;
    align-items: center;
    gap: .65rem;
    width: 100%;
    padding: .5rem .6rem;
    border-radius: 7px;
    background: none;
    border: none;
    color: var(--text-dim);
    font-size: .82rem;
    cursor: pointer;
    text-align: left;
    font-family: inherit;
  }}
  .nav-item svg {{ width: 16px; height: 16px; flex-shrink: 0; }}
  .nav-item:hover {{ background: var(--hover-bg); color: var(--text); }}
  .nav-item.active {{ background: var(--accent-soft); color: var(--accent); font-weight: 600; }}

  /* --- main --- */
  .main {{ flex: 1; min-width: 0; padding: 1.9rem 2.1rem 3.5rem; }}
  .page-head {{ margin-bottom: 1.5rem; }}
  .page-head h1 {{ font-size: 1.25rem; margin: 0 0 .3rem; letter-spacing: -.01em; }}
  .page-head p {{ margin: 0; font-size: .82rem; color: var(--text-dim); max-width: 640px; line-height: 1.5; }}

  .tab-panel {{ display: none; }}
  .tab-panel.active {{ display: block; }}

  /* --- stat cards --- */
  .stat-cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 1.75rem; }}
  .stat-card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 1.05rem 1.25rem; }}
  .stat-card .label {{ font-size: .72rem; color: var(--text-dim); margin-bottom: .5rem; }}
  .stat-card .value {{ font-size: 1.65rem; font-weight: 700; }}
  .stat-card .context {{ font-size: .7rem; color: var(--text-dim); margin-top: .35rem; }}

  /* --- panel --- */
  .panel {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem 1.35rem; }}
  .panel-header {{ display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 1.1rem; }}
  .panel-header h2 {{ font-size: .92rem; margin: 0; }}
  .panel-header .hint {{ font-size: .68rem; color: var(--text-dim); }}

  /* --- team chart: flexbox staircase tree (round 8 revert of the round
     6-7 radial/polar experiment -- see the comment above BRANCH_LAYOUT in
     the Python source for the full history). --- */
  .canvas-scroll {{ overflow-x: auto; padding-bottom: .25rem; }}
  /* Horizontal padding here isn't just breathing room -- it's load-bearing
     for drawOrgLines(): a branch head at indent 0 (Yara, Kwame) sits flush
     against the container's edge, so its child edges' trunk (avatar edge
     -+ ~16px gutter) needs at least that much clearance or it routes to a
     negative/overflowing X and gets clipped by .canvas-scroll's
     overflow-x. 28px comfortably clears the 16px gutter on both sides. */
  .org-chart {{ position: relative; padding: .5rem 28px .25rem; }}
  .root-row {{ display: flex; justify-content: center; margin-bottom: 2.25rem; }}
  .branches {{ display: flex; justify-content: space-between; gap: 3rem; }}
  .branch {{ display: flex; flex-direction: column; flex: 0 0 auto; }}
  .branch-left {{ align-items: flex-start; }}
  .branch-right {{ align-items: flex-end; }}
  .row {{ margin-bottom: 2.25rem; }}
  .row:last-child {{ margin-bottom: 0; }}
  svg#lines {{ position: absolute; inset: 0; pointer-events: none; overflow: visible; z-index: 0; }}
  .edge {{ fill: none; stroke: var(--border); stroke-width: 1.5; }}
  .node {{
    position: relative; z-index: 1;
    display: flex; flex-direction: row; align-items: center;
    width: max-content;
  }}
  .avatar-ring {{
    width: 140px; height: 140px; border-radius: 50%; flex-shrink: 0;
    background: var(--fill); border: 3px solid var(--stroke);
    display: flex; align-items: center; justify-content: center; overflow: hidden;
    box-shadow: 0 0 0 5px var(--card-bg), 0 4px 14px rgba(0,0,0,.35);
    position: relative; z-index: 2;
  }}
  .avatar {{ width: 100%; height: 100%; object-fit: cover; object-position: top center; }}
  /* Overlap amount (16px) must match TRUNK_GUTTER in the page script's
     drawOrgLines() -- keep the two in sync by hand. The near side (the
     side tucking under the avatar) gets extra padding so the 16px overlap
     only ever eats into background/border, never the actual name/role
     text -- the avatar renders above the box (z-index 2 vs 1). */
  /* Fixed width (not shrink-to-fit) is load-bearing, not cosmetic: the
     right branch (.branch-right, align-items: flex-end) right-aligns each
     whole .node (avatar+box) as one unit, so if the box's width tracked
     its own text length, siblings with different role-text lengths (e.g.
     "Threat Intelligence Analyst" vs "Application Security Engineer")
     would each shift their avatar to a different X -- breaking the
     "siblings share a trunk-X" property drawOrgLines() relies on. A fixed
     width makes every node's total footprint identical, so the avatar
     lands at the same X regardless of which branch/text it's paired with.
     280px comfortably fits the longest current role text
     ("Application Security Engineer") on one line; re-check this by eye
     if a much longer role string is ever added. */
  .info-box {{
    background: var(--fill); border: 2px solid var(--stroke); border-radius: 10px;
    padding: .45rem .85rem; z-index: 1;
    margin-left: -16px; padding-left: 28px; width: 280px;
  }}
  .rname {{ font-weight: 700; font-size: 1rem; line-height: 1.25; color: var(--text); white-space: nowrap; }}
  .rrole {{ font-size: .76rem; opacity: .92; margin-top: .2rem; line-height: 1.3; color: var(--stroke); white-space: nowrap; }}
  .legend {{ display: flex; justify-content: center; gap: 1.4rem; flex-wrap: wrap; font-size: .68rem; color: var(--text-dim); margin-top: .4rem; }}
  .legend-item {{ display: flex; align-items: center; gap: .35rem; }}
  .legend-swatch {{ width: 10px; height: 10px; border-radius: 50%; border: 2px solid var(--stroke-color); background: var(--fill-color); }}
  .legend-line {{ width: 18px; height: 0; border-top: 1.4px solid var(--text-dim); }}

  /* --- token table --- */
  .token-table {{ width: 100%; border-collapse: collapse; font-size: .78rem; }}
  .token-table th {{ text-align: left; font-size: .68rem; color: var(--text-dim); font-weight: 600; padding: .5rem .6rem; border-bottom: 1px solid var(--border); }}
  .token-table td {{ padding: .55rem .6rem; border-bottom: 1px solid var(--border); }}
  .token-table tr:last-child td {{ border-bottom: none; }}
  .token-table tr.row-empty td {{ color: var(--text-dim); font-style: italic; }}

  /* --- activity feed --- */
  .activity-list {{ display: flex; flex-direction: column; max-height: 560px; overflow-y: auto; }}
  .activity-item {{ display: flex; gap: .55rem; padding: .6rem 0; border-bottom: 1px solid var(--border); }}
  .activity-item:last-child {{ border-bottom: none; }}
  .activity-dot {{ width: 6px; height: 6px; border-radius: 50%; background: var(--blue); margin-top: .35rem; flex-shrink: 0; }}
  .activity-body {{ display: flex; flex-direction: column; gap: .2rem; min-width: 0; }}
  .activity-msg {{ font-size: .78rem; color: var(--text); line-height: 1.35; word-break: break-word; }}
  .activity-meta {{ font-size: .66rem; color: var(--text-dim); }}
  .activity-hash {{ font-family: ui-monospace, SFMono-Regular, monospace; }}
  .activity-empty {{ color: var(--text-dim); font-size: .8rem; padding: 1rem 0; }}

  /* --- placeholder tabs --- */
  .placeholder {{ display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 5rem 1rem; color: var(--text-dim); text-align: center; gap: .5rem; }}
  .placeholder svg {{ width: 42px; height: 42px; opacity: .35; margin-bottom: .5rem; }}
  .placeholder h2 {{ margin: 0; font-size: 1.05rem; color: var(--text); }}
  .placeholder p {{ margin: 0; font-size: .82rem; max-width: 360px; }}
  .placeholder-note {{ font-size: .68rem; opacity: .7; margin-top: .3rem !important; }}

  footer {{ text-align: center; color: var(--text-dim); font-size: .7rem; margin-top: 2.5rem; }}
  footer code {{ background: var(--sidebar-bg); border: 1px solid var(--border); border-radius: 4px; padding: .1rem .35rem; }}
</style>
</head>
<body>

<aside class="sidebar">
  <div class="brand">
    <img src="{logo_rel}" alt="logo">
    <div>
      <div class="brand-text">Detection-Engineering</div>
      <div class="brand-sub"><span class="status-dot"></span>csapat online</div>
    </div>
  </div>
  <nav>
{nav_html}
  </nav>
</aside>

<main class="main">
  <section class="tab-panel active" id="tab-overview">
    <div class="page-head">
      <h1>Áttekintés</h1>
      <p>A 11 tagú csapat mai állapota — valós adatokkal ott, ahol van; őszinte "nincs naplózva" mindenhol máshol.</p>
    </div>

    <div class="stat-cards">
      <div class="stat-card">
        <div class="label">Aktív ügynökök ma</div>
        <div class="value">{active_today}</div>
        <div class="context">{specialist_count} specialista összesen</div>
      </div>
      <div class="stat-card">
        <div class="label">Ma futott dispatch</div>
        <div class="value">{dispatches_today}</div>
        <div class="context">{dispatches_total} naplózott dispatch összesen</div>
      </div>
      <div class="stat-card">
        <div class="label">Token napló</div>
        <div class="value">{total_tokens}</div>
        <div class="context">{active_count}/{specialist_count} tagnál van adat</div>
      </div>
      <div class="stat-card">
        <div class="label">Audit register</div>
        <div class="value">{register_progress}</div>
        <div class="context">lezárt tétel</div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <h2>Csapat</h2>
        <span class="hint">jelentési hierarchia</span>
      </div>
      <div class="canvas-scroll">
{org_chart}
      </div>
      <div class="legend">
        <div class="legend-item"><span class="legend-swatch" style="--fill-color:#2c1b4d;--stroke-color:#b388ff"></span>Stratégiai/vezetői szint</div>
        <div class="legend-item"><span class="legend-swatch" style="--fill-color:#12351f;--stroke-color:#4caf7d"></span>Stratégiai szint</div>
        <div class="legend-item"><span class="legend-swatch" style="--fill-color:#0d2440;--stroke-color:#58a6ff"></span>Mérnöki/technológiai szint</div>
        <div class="legend-item"><span class="legend-swatch" style="--fill-color:#0d3b36;--stroke-color:#2dd4bf"></span>Csoportkoordinátor</div>
        <div class="legend-item"><span class="legend-swatch" style="--fill-color:#3d2c07;--stroke-color:#e0a94c"></span>Compliance/dokumentációs szint</div>
        <div class="legend-item"><span class="legend-line"></span>jelentési vonal</div>
      </div>
    </div>
  </section>

{activity_tab}

{tokens_tab}

{placeholder_tabs}

  <footer>
    Generálva {generated_at} &middot; <code>.claude/generate_dashboard.py</code>-vel,
    a <code>.claude/agent_usage_log.jsonl</code> naplóból és a repo <code>git log</code>-jából.
    A napló frissítése után futtasd újra a scriptet.
  </footer>
</main>

<script>
  // Round 8 revert: back to the flexbox staircase tree (rounds 3-5), after
  // a radial/polar layout was tried for two rounds (6-7) and rejected
  // outright. Node positions are real flexbox layout, not fixed math
  // computed at generation time, so -- like the original round 3-5 tree --
  // the connector lines have to be drawn here in JS, re-measuring the DOM
  // via getBoundingClientRect() on load/resize/tab-switch rather than
  // being embedded as a static SVG.
  var EDGES = {edges_json};
  var TRUNK_GUTTER = 16; // must match .info-box's -16px overlap margin in the CSS

  function drawOrgLines() {{
    var container = document.getElementById('org-chart');
    var svg = document.getElementById('lines');
    if (!container || !svg) return;
    var containerRect = container.getBoundingClientRect();
    if (containerRect.width === 0 && containerRect.height === 0) return; // tab hidden, nothing to measure
    var paths = [];
    EDGES.forEach(function (edge) {{
      var parentEl = document.getElementById('avatar-' + edge[0]);
      var childEl = document.getElementById('avatar-' + edge[1]);
      if (!parentEl || !childEl) return;
      var pr = parentEl.getBoundingClientRect();
      var cr = childEl.getBoundingClientRect();
      var px = (pr.left + pr.width / 2) - containerRect.left;
      var py = pr.bottom - containerRect.top;
      var childCenterX = (cr.left + cr.width / 2) - containerRect.left;
      var cy = (cr.top + cr.height / 2) - containerRect.top;
      // Trunk sits on whichever side of the child's avatar faces the
      // parent -- computed per edge from actual measured positions, not
      // hardcoded per branch, so the same logic works uniformly for both
      // the root->branch-head edges and every within-branch edge. Siblings
      // sharing a parent and a side naturally land on the same trunk X
      // (same indent = same avatar edge), producing one continuous trunk
      // with stubs peeling off, with no extra grouping logic needed here.
      var side = px >= childCenterX ? 'right' : 'left';
      var childLeft = cr.left - containerRect.left;
      var childRight = cr.right - containerRect.left;
      var nearX = side === 'left' ? childLeft : childRight;
      var trunkX = side === 'left' ? childLeft - TRUNK_GUTTER : childRight + TRUNK_GUTTER;
      var dropY = py + 14;
      var d = 'M ' + px.toFixed(1) + ' ' + py.toFixed(1) +
        ' V ' + dropY.toFixed(1) +
        ' H ' + trunkX.toFixed(1) +
        ' V ' + cy.toFixed(1) +
        ' H ' + nearX.toFixed(1);
      paths.push('<path d="' + d + '" class="edge"></path>');
    }});
    svg.innerHTML = paths.join('');
  }}

  document.querySelectorAll('.nav-item').forEach(function (btn) {{
    btn.addEventListener('click', function () {{
      document.querySelectorAll('.nav-item').forEach(function (b) {{ b.classList.remove('active'); }});
      btn.classList.add('active');
      var tab = btn.dataset.tab;
      document.querySelectorAll('.tab-panel').forEach(function (p) {{ p.classList.remove('active'); }});
      var target = document.getElementById('tab-' + tab);
      if (target) target.classList.add('active');
      if (tab === 'overview') drawOrgLines();
    }});
  }});

  window.addEventListener('load', drawOrgLines);
  window.addEventListener('resize', drawOrgLines);
</script>
</body>
</html>
"""


def build_html() -> str:
    usage = load_usage()
    activity = load_activity()
    register = load_register_progress()

    total_dispatches = sum(s["dispatches"] for s in usage.values())
    dispatches_today = sum(s["dispatches_today"] for s in usage.values())
    total_tokens = sum(s["tokens"] for s in usage.values())
    active_count = sum(1 for s in usage.values() if s["dispatches"] > 0)
    active_today = sum(1 for s in usage.values() if s["dispatches_today"] > 0)
    specialist_count = sum(1 for _n, _r, _a, slug in ROSTER if slug is not None)
    register_progress = f"{register[0]}/{register[1]}" if register else "n/a"

    return TEMPLATE.format(
        logo_rel=LOGO_REL,
        nav_html=build_nav_html(),
        org_chart=build_org_chart_html(),
        edges_json=json.dumps(RELATIONSHIPS),
        activity_tab=build_activity_tab_html(activity),
        tokens_tab=build_tokens_tab_html(usage),
        placeholder_tabs=build_placeholder_tabs(),
        active_today=active_today,
        specialist_count=specialist_count,
        dispatches_today=dispatches_today,
        dispatches_total=total_dispatches,
        total_tokens=fmt_tokens(total_tokens),
        active_count=active_count,
        register_progress=register_progress,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )


def main() -> int:
    OUT_PATH.write_text(build_html(), encoding="utf-8")
    print(f"Wrote {OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
