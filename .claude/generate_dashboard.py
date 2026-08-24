#!/usr/bin/env python3
# .claude/generate_dashboard.py
#
# Generates .claude/dashboard.html: an app-shell style overview of the
# custom subagent team -- sidebar nav, stat cards, team org chart, and a
# real activity feed sourced from `git log` at generation time.
#
# Not part of the detection-rule pipeline scripts/ generates -- this is an
# internal ops dashboard for the team itself. Lives under .claude/ for that
# reason, and is Gaz's own editing surface (CLAUDE.md point 8/9), same as
# CLAUDE.md/TEAM.md/the agent files -- not a specialist's job.
#
# Only the "Attekintes" (Overview) tab has real content right now, per the
# user's explicit ask (2026-08-24): the sidebar already lists Agents,
# Activity, Group, Skills, MCP and Token Monitor as scaffolded nav entries,
# but each renders a plain "not built yet" placeholder until a real need
# for that page shows up -- not a promise every one of them ships.
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

ACTIVITY_LIMIT = 18

AREA_COLORS = {
    "strategic": {"fill": "#2c2350", "stroke": "#a992eb", "text": "#eee6ff"},
    "analytical": {"fill": "#3d2c07", "stroke": "#e0a94c", "text": "#fdecc9"},
    "operational": {"fill": "#0d2e26", "stroke": "#59c9ab", "text": "#dcf7ee"},
}

# Kept in sync by hand with TEAM.md's table. name, role, area, agent slug
# (None for Gaz -- reference file only, never dispatched via the Agent tool).
ROSTER = [
    ("Gaz", "Engineering Lead", "strategic", None),
    ("Yara", "Technology Strategist", "strategic", "yara-ideation"),
    ("Kwame", "Compliance Analyst", "strategic", "kwame-audit-compliance"),
    ("Masha", "Threat Intelligence Analyst", "analytical", "masha-threat-intel"),
    ("Yuki", "Detection Engineer", "operational", "yuki-detection-engineer"),
    ("Bjorn", "Detection Quality Engineer", "operational", "bjorn-detection-content-reviewer"),
    ("Chloe", "Technical Writer", "operational", "chloe-docs-maintainer"),
    ("Jamal", "DevOps Engineer", "operational", "jamal-devops-engineer"),
    ("Sienna", "Frontend Engineer", "operational", "sienna-frontend-engineer"),
    ("Kai", "Platform Engineer", "operational", "kai-github-ops"),
    ("Priya", "Application Security Engineer", "operational", "priya-security-scanner"),
]

ROWS = [
    ["Gaz"],
    ["Yara", "Kwame"],
    ["Masha"],
    ["Yuki", "Bjorn", "Chloe", "Jamal", "Sienna", "Kai", "Priya"],
]

# (from, to, label, dashed) -- kept in sync by hand with TEAM.md's mermaid
# collaboration map. The "everyone reports to Gaz" link is omitted here for
# the same reason TEAM.md omits it: true for all ten, would just clutter it.
RELATIONSHIPS = [
    ("Gaz", "Yara", "co-sets roadmap", False),
    ("Gaz", "Kwame", "co-owns program health", False),
    ("Yara", "Kwame", "strategic peers", False),
    ("Yara", "Masha", "cross-checks gaps", False),
    ("Masha", "Gaz", "delivers CTI briefs", False),
    ("Masha", "Yuki", "hands off ready findings", False),
    ("Yara", "Yuki", "ideas, routed by Gaz", True),
    ("Yuki", "Bjorn", "every rule: author to review", False),
    ("Kwame", "Jamal", "verifies pipeline items", False),
    ("Kwame", "Sienna", "verifies browser items", False),
    ("Jamal", "Sienna", "CI publishes generated browser", False),
    ("Jamal", "Kai", "pipeline / platform boundary", False),
    ("Sienna", "Kai", "PR and merge mechanics", False),
    ("Chloe", "Kai", "PR and merge mechanics", False),
    ("Chloe", "Jamal", "documents pipeline changes", False),
    ("Chloe", "Yuki", "documents rule changes", False),
    ("Priya", "Jamal", "flags pipeline findings", False),
    ("Priya", "Kai", "flags secrets and config findings", False),
]

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
            text=True,
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


def node_html(name: str, role: str, area: str, usage: dict[str, dict]) -> str:
    colors = AREA_COLORS[area]
    stat = usage.get(name)
    if stat and stat["dispatches"] > 0:
        plural = "es" if stat["dispatches"] != 1 else ""
        stat_html = (
            f'<div class="stat">'
            f'<span class="stat-num">{stat["dispatches"]}</span> dispatch{plural} · '
            f'<span class="stat-num">{fmt_tokens(stat["tokens"])}</span> tok'
            f"</div>"
        )
    else:
        stat_html = '<div class="stat stat-empty">nincs naplózott munka</div>'
    avatar_file = f"{AVATAR_DIR_REL}/{name}_transparent.png"
    return f"""        <div class="node" id="node-{name}" style="--fill:{colors["fill"]};--stroke:{colors["stroke"]};--text:{colors["text"]}">
          <div class="avatar-ring"><img src="{avatar_file}" alt="{name}" class="avatar" loading="lazy"></div>
          <div class="name">{name}</div>
          <div class="role">{role}</div>
          {stat_html}
        </div>"""


def build_team_rows(usage: dict[str, dict]) -> str:
    roster_by_name = {n: (role, area) for n, role, area, _ in ROSTER}
    rows_html = []
    for row in ROWS:
        nodes = "\n".join(node_html(name, *roster_by_name[name], usage) for name in row)
        rows_html.append(f'      <div class="row">\n{nodes}\n      </div>')
    return "\n".join(rows_html)


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


# --- nav / placeholders --------------------------------------------------------

PLACEHOLDER_COPY = {
    "agents": "Részletes ügynök-lista és állapotfigyelés -- ha lesz rá valós igény.",
    "activity": "Teljes, szűrhető aktivitás-napló -- egyelőre az áttekintő oldal feed-je adja ezt.",
    "group": "Mélyebb csapat-nézet -- egyelőre az áttekintő oldal Csapat panelje adja ezt.",
    "skills": "A .claude/skills/ tartalmának áttekintése.",
    "mcp": "A konfigurált MCP szerverek állapota.",
    "tokens": "Részletes, időbeli token-fogyasztás tag/feladat szerint.",
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
        if active:
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

  /* --- content grid --- */
  .content-grid {{ display: grid; grid-template-columns: 1.55fr 1fr; gap: 1.15rem; align-items: start; }}
  @media (max-width: 1000px) {{ .content-grid {{ grid-template-columns: 1fr; }} }}
  .panel {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem 1.35rem; }}
  .panel-header {{ display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 1.1rem; }}
  .panel-header h2 {{ font-size: .92rem; margin: 0; }}
  .panel-header .hint {{ font-size: .68rem; color: var(--text-dim); }}

  /* --- team tree --- */
  .canvas {{ position: relative; }}
  svg#lines {{ position: absolute; top: 0; left: 0; pointer-events: none; overflow: visible; }}
  .edge {{ fill: none; stroke: var(--border); stroke-width: 1.4; }}
  .edge.dashed {{ stroke-dasharray: 4 4; stroke: var(--text-dim); }}
  .row {{ display: flex; justify-content: center; gap: 1.3rem; margin-bottom: 1.9rem; flex-wrap: wrap; position: relative; z-index: 1; }}
  .node {{ display: flex; flex-direction: column; align-items: center; width: 96px; text-align: center; }}
  .avatar-ring {{
    width: 60px; height: 60px; border-radius: 50%;
    background: var(--fill); border: 2px solid var(--stroke);
    display: flex; align-items: center; justify-content: center; overflow: hidden;
    box-shadow: 0 0 0 4px var(--card-bg), 0 4px 12px rgba(0,0,0,.35);
  }}
  .avatar {{ width: 100%; height: 100%; object-fit: cover; object-position: top center; }}
  .name {{ margin-top: .45rem; font-weight: 700; font-size: .8rem; }}
  .role {{ font-size: .63rem; color: var(--text-dim); margin-top: .05rem; line-height: 1.2; }}
  .stat {{ margin-top: .35rem; font-size: .6rem; color: var(--text-dim); background: var(--bg); border: 1px solid var(--border); border-radius: 999px; padding: .12rem .5rem; }}
  .stat-num {{ color: var(--text); font-weight: 700; }}
  .stat-empty {{ opacity: .55; font-style: italic; }}
  .legend {{ display: flex; justify-content: center; gap: 1.4rem; flex-wrap: wrap; font-size: .68rem; color: var(--text-dim); margin-top: .4rem; }}
  .legend-item {{ display: flex; align-items: center; gap: .35rem; }}
  .legend-swatch {{ width: 10px; height: 10px; border-radius: 50%; border: 2px solid var(--stroke-color); background: var(--fill-color); }}
  .legend-line {{ width: 18px; height: 0; border-top: 1.4px solid var(--text-dim); }}
  .legend-line.dashed {{ border-top-style: dashed; }}

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

    <div class="content-grid">
      <div class="panel">
        <div class="panel-header">
          <h2>Csapat</h2>
          <span class="hint">hierarchia és munkakapcsolatok</span>
        </div>
        <div class="canvas" id="canvas">
          <svg id="lines"></svg>
{team_rows}
        </div>
        <div class="legend">
          <div class="legend-item"><span class="legend-swatch" style="--fill-color:#2c2350;--stroke-color:#a992eb"></span>Stratégiai</div>
          <div class="legend-item"><span class="legend-swatch" style="--fill-color:#3d2c07;--stroke-color:#e0a94c"></span>Analitikai</div>
          <div class="legend-item"><span class="legend-swatch" style="--fill-color:#0d2e26;--stroke-color:#59c9ab"></span>Operátív</div>
          <div class="legend-item"><span class="legend-line"></span>közvetlen kapcsolat</div>
          <div class="legend-item"><span class="legend-line dashed"></span>Gaz-on át érkező</div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <h2>Aktivitás</h2>
          <span class="hint">git log, friss</span>
        </div>
        <div class="activity-list">
{activity_html}
        </div>
      </div>
    </div>
  </section>

{placeholder_tabs}

  <footer>
    Generálva {generated_at} &middot; <code>.claude/generate_dashboard.py</code>-vel,
    a <code>.claude/agent_usage_log.jsonl</code> naplóból és a repo <code>git log</code>-jából.
    A napló frissítése után futtasd újra a scriptet.
  </footer>
</main>

<script>
  const RELATIONSHIPS = {relationships_json};

  function drawLines() {{
    const canvas = document.getElementById('canvas');
    const svg = document.getElementById('lines');
    if (!canvas || !svg || canvas.offsetParent === null) return;
    const rect = canvas.getBoundingClientRect();
    svg.setAttribute('width', rect.width);
    svg.setAttribute('height', rect.height);
    svg.innerHTML = '';
    RELATIONSHIPS.forEach(function (rel) {{
      const a = document.getElementById('node-' + rel.from);
      const b = document.getElementById('node-' + rel.to);
      if (!a || !b) return;
      const ar = a.getBoundingClientRect();
      const br = b.getBoundingClientRect();
      const x1 = ar.left + ar.width / 2 - rect.left;
      const y1 = ar.top + ar.height / 2 - rect.top;
      const x2 = br.left + br.width / 2 - rect.left;
      const y2 = br.top + br.height / 2 - rect.top;
      const dx = x2 - x1, dy = y2 - y1;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
      const curve = Math.min(dist * 0.16, 46);
      const nx = -dy / dist, ny = dx / dist;
      const cx = mx + nx * curve, cy = my + ny * curve;
      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.setAttribute('d', 'M ' + x1 + ' ' + y1 + ' Q ' + cx + ' ' + cy + ' ' + x2 + ' ' + y2);
      path.setAttribute('class', 'edge' + (rel.dashed ? ' dashed' : ''));
      const title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
      title.textContent = rel.from + ' \\u2194 ' + rel.to + ': ' + rel.label;
      path.appendChild(title);
      svg.appendChild(path);
    }});
  }}

  document.querySelectorAll('.nav-item').forEach(function (btn) {{
    btn.addEventListener('click', function () {{
      document.querySelectorAll('.nav-item').forEach(function (b) {{ b.classList.remove('active'); }});
      btn.classList.add('active');
      const tab = btn.dataset.tab;
      document.querySelectorAll('.tab-panel').forEach(function (p) {{ p.classList.remove('active'); }});
      const target = document.getElementById('tab-' + tab);
      if (target) target.classList.add('active');
      requestAnimationFrame(drawLines);
    }});
  }});

  window.addEventListener('load', drawLines);
  window.addEventListener('resize', drawLines);
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
        team_rows=build_team_rows(usage),
        activity_html=build_activity_html(activity),
        placeholder_tabs=build_placeholder_tabs(),
        relationships_json=json.dumps([{"from": f, "to": t, "label": lbl, "dashed": d} for f, t, lbl, d in RELATIONSHIPS]),
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
