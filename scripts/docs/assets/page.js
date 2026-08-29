const RULES = @@RULES_JSON@@;
// Lookup so the Navigator can open the same in-page drawer the Rule Library
// uses (openDrawer takes a RULES index), instead of linking out to GitHub.
const RULE_IDX_BY_ID = {};
RULES.forEach(function (r, i) { RULE_IDX_BY_ID[r.id] = i; });
const TACTIC_IDS = @@TACTIC_IDS_JSON@@;
const GENERATED_TS = "@@TS@@";
const TOTAL_RULES = @@TOTAL@@;
const PASS_COUNT = @@PASSED@@;   // every PASS on record, stale ones included
const FAIL_COUNT = @@FAILED@@;
// Real "NOT_VERIFIED" rules (deployed + attempted, Atomic test timed out)
// vs. true N/A (never tested -- no result.json at all). Kept as two
// separate chart segments so NOT_VERIFIED isn't silently folded into "no
// coverage" nor misrepresented as a pass or a confirmed fail.
const NOTVER_COUNT = @@NOT_VER@@;
const NA_COUNT = @@NEVER_TESTED@@;
// PASS_RATE is measured over the rules whose verdict is still current
// evidence, not over the whole library (see generate_stats.py) -- the
// Evidence card beside the Verification ring is what names that population.
// The four counters above stay whole-library totals; both charts classify
// from RULES themselves, so neither can disagree with the table.
const PASS_RATE = @@PASS_RATE@@;
const MITRE_COVERED = @@MITRE_COVERED@@;
const MITRE_TOTAL = @@MITRE_TOTAL@@;
const MITRE_PCT = @@MITRE_PCT@@;
const COVERAGE_HISTORY = @@COVERAGE_HISTORY_JSON@@;
const RULE_GROWTH_HISTORY = @@RULE_GROWTH_HISTORY_JSON@@;

const SEV_HEX = { critical: '#a4133c', high: '#f85149', medium: '#fb923c', low: '#3fb950', informational: '#8b949e' };
const STATUS_HEX = { stable: '#3fb950', test: '#d29922', experimental: '#388bfd', deprecated: '#8b949e' };
const SOURCE_HEX = { sigma: '#00acd7', nativespl: '#ff6600' };

// ── Dashboards tab charts ────────────────────────────────────────────────
// Colors mirror the quickchart.io configs used for README.md (see
// generate_stats.py: level_colors_map / tactic_chart_url) so the charts
// look the same here as they do in the README.
const LEVEL_ORDER = ['critical', 'high', 'medium', 'low', 'informational'];
const LEVEL_COLORS = { critical: '#7B0000', high: '#DC2626', medium: '#FFAA00', low: '#2EA44F', informational: '#6E7681' };
const LEVEL_DISPLAY = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', informational: 'Info' };

let dashboardChartsBuilt = false;

// Chart.js 4.5.1 has a confirmed bug (verified empirically, not from docs):
// if a chart's canvas container has a FRACTIONAL CSS pixel width/height at
// construction time (e.g. 136.5px — routine with CSS Grid's auto-fit
// column division), the doughnut controller's entrance animation
// (animateRotate/animateScale) is silently skipped entirely — the ring
// renders at its final state on the very first frame, with zero visible
// sweep or grow-in. Integer widths (136px, 137px) animate correctly; the
// exact same config differs ONLY in whether the measured size happens to
// be a whole number. Snapping each canvas-wrap's box to the nearest whole
// pixel via inline style, right before constructing its chart, avoids the
// bug. A resize listener re-snaps (and re-triggers Chart.js's own resize)
// so this doesn't freeze these tiles at their initial size if the window
// is resized later.
// Ids whose canvas-wrap is a flex-grow item (flex: 1 1 auto) inside a ROW
// flex container (.severity-card-body / .verify-card-body) — main axis is
// horizontal, so plain `style.width` is ignored because flex-grow
// recomputes the main-axis size regardless of any width set on the item.
// Disabling grow/shrink and fixing the flex-basis to the rounded width is
// what actually makes the rendered width an integer.
const ROW_FLEX_CANVAS_IDS = ['chart-severity', 'chart-status', 'chart-verify', 'chart-evidence', 'chart-source'];

// Ids whose canvas-wrap (.chart-card-canvas-wrap, no row-flex modifier
// class) sits directly in a COLUMN flex container (.chart-card) — main
// axis there is vertical, so the wrap's width instead comes from
// align-items:stretch on the cross axis, which CSS Grid's auto-fit column
// division can just as easily leave fractional. Plain `style.width` isn't
// fought by flex-grow on this axis, so it's enough to pin it directly.
const COLUMN_FLEX_CANVAS_IDS = ['chart-coverage-trend', 'chart-rule-growth'];

function wrapOf(id) {
  const canvas = document.getElementById(id);
  return canvas ? canvas.parentElement : null;
}

// Two passes on purpose. Every previous pin is released first, then every
// width is measured, then every pin is written — so each measurement sees the
// natural flex layout instead of the pin this function left behind last time.
// Measuring while still pinned made the very first value permanent: the
// resize handler re-measured its own `flex: 0 0 Npx` and wrote it straight
// back, so these tiles never actually re-fitted. It also made the first
// measurement the wrong one, because it happens before the legends are
// populated: with an empty legend beside it the ring measures the full card
// width, gets pinned there, and the legend items appended a moment later have
// nowhere to go but past the card's edge. That is exactly what Evidence's
// longer labels ("Superseded", "Never tested") made visible.
function snapCanvasWrapsToIntegerSize() {
  const ids = [...ROW_FLEX_CANVAS_IDS, ...COLUMN_FLEX_CANVAS_IDS];
  ids.forEach(id => {
    const wrap = wrapOf(id);
    if (!wrap) return;
    wrap.style.flex = '';
    wrap.style.width = '';
    wrap.style.height = '';
  });
  const measured = ids.map(id => {
    const wrap = wrapOf(id);
    return wrap ? wrap.getBoundingClientRect() : null;
  });
  ids.forEach((id, i) => {
    const wrap = wrapOf(id);
    const rect = measured[i];
    if (!wrap || !rect) return;
    if (rect.width > 0) {
      // Row-flex wraps need the basis fixed as well as grow/shrink disabled;
      // plain width is ignored on a flex container's main axis.
      if (ROW_FLEX_CANVAS_IDS.includes(id)) wrap.style.flex = '0 0 ' + Math.round(rect.width) + 'px';
      else wrap.style.width = Math.round(rect.width) + 'px';
    }
    if (rect.height > 0) wrap.style.height = Math.round(rect.height) + 'px';
  });
}

let resizeSnapTimer = null;
window.addEventListener('resize', () => {
  if (!dashboardChartsBuilt) return;
  clearTimeout(resizeSnapTimer);
  resizeSnapTimer = setTimeout(() => {
    snapCanvasWrapsToIntegerSize();
    [...ROW_FLEX_CANVAS_IDS, ...COLUMN_FLEX_CANVAS_IDS].forEach(id => {
      const c = Chart.getChart(id);
      if (c) c.resize();
    });
  }, 150);
});

function buildDashboardCharts() {
  if (dashboardChartsBuilt || typeof Chart === 'undefined') return;
  dashboardChartsBuilt = true;
  if (window.ChartDataLabels) Chart.register(window.ChartDataLabels);
  snapCanvasWrapsToIntegerSize();

  const animation = { duration: 700, easing: 'easeOutQuart' };
  // Chart.js's doughnut/pie controller has two animation-specific toggles
  // that are NOT part of the generic duration/easing config: `animateRotate`
  // (default true — arcs sweep in) and `animateScale` (default FALSE — the
  // ring does not grow from the center, it appears at full radius
  // immediately and only the sweep plays). At the enlarged 95% radius used
  // by Severity/Status/Verification, the sweep-only default reads as much
  // less noticeable than the bar/gauge charts' size-change animations.
  // Explicitly turning on animateScale gives these 3 doughnuts a visible
  // "grow from center + sweep" reveal, matching the perceptible weight of
  // the other charts. Not applied to the Coverage gauge below, which
  // already animates visibly and isn't part of the reported issue.
  const doughnutAnimation = { ...animation, animateScale: true };

  // MITRE ATT&CK Coverage — half-doughnut gauge
  new Chart(document.getElementById('chart-coverage'), {
    type: 'doughnut',
    data: {
      datasets: [{
        data: [MITRE_COVERED, Math.max(MITRE_TOTAL - MITRE_COVERED, 0)],
        backgroundColor: ['#FFAA00', 'rgba(128,128,128,0.15)'],
        borderColor: '#0d1117',
        borderWidth: 1,
      }],
    },
    options: {
      maintainAspectRatio: false,
      rotation: -90,
      circumference: 180,
      cutout: '68%',
      animation,
      plugins: { legend: { display: false }, tooltip: { enabled: false }, datalabels: { display: false } },
    },
  });

  // Shared hover tooltip for Severity + Tactic charts — same box, same layout:
  // title / "N pcs" (same size as title) / "(pct%)" smaller below.
  // opts.hideCount drops the "N pcs" line for charts that already print the
  // count as a datalabel on the mark itself — repeating it in the tooltip is
  // noise. The percentage then takes over the primary row's styling so the
  // tooltip doesn't end on a small grey aside.
  function externalChartTip(ctx, total, opts) {
    const tip = document.getElementById('chart-tip');
    const t = ctx.tooltip;
    if (!t || t.opacity === 0) { tip.style.display = 'none'; return; }
    const dp = t.dataPoints && t.dataPoints[0];
    if (dp) {
      const value = dp.raw;
      const pct = total > 0 ? Math.round((value / total) * 100) : 0;
      const body = (opts && opts.hideCount)
        ? '<div class="sev-tip-count">' + pct + '% of all rules</div>'
        : '<div class="sev-tip-count">' + value + ' pcs</div>' +
        '<div class="sev-tip-pct">(' + pct + '%)</div>';
      tip.innerHTML = '<div class="sev-tip-title">' + dp.label + '</div>' + body;
    }
    const rect = ctx.chart.canvas.getBoundingClientRect();
    tip.style.display = 'block';
    tip.style.left = (rect.left + t.caretX) + 'px';
    tip.style.top = (rect.top + t.caretY) + 'px';
  }

  // Rules by Severity — doughnut, custom HTML legend (fades the dot on toggle, no strikethrough)
  const sevCounts = {};
  RULES.forEach(r => { sevCounts[r.severity] = (sevCounts[r.severity] || 0) + 1; });
  const sevActive = LEVEL_ORDER.filter(lvl => sevCounts[lvl] > 0);
  const sevTotal = sevActive.reduce((s, lvl) => s + sevCounts[lvl], 0);
  const sevChart = new Chart(document.getElementById('chart-severity'), {
    type: 'doughnut',
    data: {
      labels: sevActive.map(lvl => LEVEL_DISPLAY[lvl]),
      datasets: [{
        data: sevActive.map(lvl => sevCounts[lvl]),
        backgroundColor: sevActive.map(lvl => LEVEL_COLORS[lvl]),
        borderColor: '#0d1117',
        borderWidth: 1,
        hoverOffset: 8,
      }],
    },
    options: {
      maintainAspectRatio: false,
      cutout: '55%',
      radius: '85%',
      animation: doughnutAnimation,
      plugins: {
        legend: { display: false },
        tooltip: { enabled: false, external: (ctx) => externalChartTip(ctx, sevTotal) },
        datalabels: { display: false },
      },
    },
  });

  const sevLegendEl = document.getElementById('sev-legend');
  sevActive.forEach((lvl, i) => {
    const item = document.createElement('div');
    item.className = 'sev-legend-item';
    item.innerHTML = '<span class="sev-legend-dot" style="background:' + LEVEL_COLORS[lvl] + '"></span>' + LEVEL_DISPLAY[lvl];
    item.addEventListener('click', () => {
      sevChart.toggleDataVisibility(i);
      sevChart.update();
      item.classList.toggle('off', !sevChart.getDataVisibility(i));
    });
    sevLegendEl.appendChild(item);
  });

  // Verification Age — horizontal bar.
  //
  // One flat accent orange for every band, matching the tactic bar chart
  // below. The bands are ordered (0–45 … 180+), and that order is carried by
  // the axis alone rather than by a colour ramp. "Never tested" keeps a
  // neutral grey: it is an absence of data, not a very large age, and only
  // appears when it is non-empty.
  //
  // Every edge is derived from REVIEW_INTERVAL_DAYS. Hard-coding 45/90/180
  // would leave the chart quietly lying the day that constant changes.
  const ageQuarter = Math.round(REVIEW_INTERVAL_DAYS / 4);
  const ageHalf = Math.round(REVIEW_INTERVAL_DAYS / 2);
  const ageBands = [
    { label: '0–' + ageQuarter + ' days', max: ageQuarter },
    { label: ageQuarter + '–' + ageHalf + ' days', max: ageHalf },
    { label: ageHalf + '–' + REVIEW_INTERVAL_DAYS + ' days', max: REVIEW_INTERVAL_DAYS },
    { label: REVIEW_INTERVAL_DAYS + '+ days', max: Infinity },
  ];
  const ageCounts = ageBands.map(() => 0);
  let neverTested = 0;
  RULES.forEach(r => {
    const days = verdictAgeDays(r.verdictAt);
    if (days === null) { neverTested++; return; }
    ageCounts[ageBands.findIndex(b => days < b.max)]++;
  });
  const ageRows = ageBands.map((b, i) => ({ label: b.label, count: ageCounts[i], color: '#FFAA00', hover: '#ffc94d' }));
  if (neverTested > 0) {
    ageRows.push({ label: 'Never tested', count: neverTested, color: '#6e7681', hover: '#8b949e' });
  }
  const ageMax = Math.max.apply(null, ageRows.map(r => r.count));

  new Chart(document.getElementById('chart-age'), {
    type: 'bar',
    data: {
      labels: ageRows.map(r => r.label),
      datasets: [{
        data: ageRows.map(r => r.count),
        backgroundColor: ageRows.map(r => r.color),
        hoverBackgroundColor: ageRows.map(r => r.hover),
        borderColor: 'black',
        borderWidth: 0.5,
        borderRadius: 4,
      }],
    },
    options: {
      indexAxis: 'y',
      maintainAspectRatio: false,
      animation,
      layout: { padding: { right: 24 } },
      // Thinner than the tactic chart's bars: only 4–5 rows share this box,
      // so the default fill would read as slabs rather than marks.
      barPercentage: 0.62,
      categoryPercentage: 0.8,
      scales: {
        x: { display: false, grid: { display: false }, suggestedMax: Math.max(ageMax * 1.2, 1) },
        y: { grid: { display: false }, ticks: { color: '#e6edf3', font: { size: 12 } } },
      },
      plugins: {
        legend: { display: false },
        tooltip: { enabled: false, external: (ctx) => externalChartTip(ctx, TOTAL_RULES, { hideCount: true }) },
        datalabels: { clip: false, anchor: 'end', align: 'end', color: '#e6edf3', font: { weight: 'bold', size: 11 } },
      },
    },
  });

  // Rules per MITRE ATT&CK Tactic — horizontal bar
  const tacticCounts = {};
  RULES.forEach(r => (r.tactics || []).forEach(t => { tacticCounts[t] = (tacticCounts[t] || 0) + 1; }));
  const tacticEntries = Object.entries(tacticCounts).sort((a, b) => b[1] - a[1]);
  const tacticMax = tacticEntries.length ? tacticEntries[0][1] : 0;

  // Row hover highlight for the tactic bars — a plain color tint on the
  // hovered bar via Chart.js's built-in `hoverBackgroundColor`, no
  // geometry/size change at all, so there is zero possibility of the
  // highlight bleeding above/below the bar's own existing height (the
  // earlier "grow" plugin drew an oversized highlight rect that could
  // bleed into neighboring rows — replaced entirely, not just tuned down).
  new Chart(document.getElementById('chart-tactics'), {
    type: 'bar',
    data: {
      labels: tacticEntries.map(([t]) => t),
      datasets: [{
        data: tacticEntries.map(([, c]) => c),
        backgroundColor: '#FFAA00',
        hoverBackgroundColor: '#ffc94d',
        borderColor: 'black',
        borderWidth: 0.5,
      }],
    },
    options: {
      indexAxis: 'y',
      maintainAspectRatio: false,
      animation,
      layout: { padding: { right: 24 } },
      barPercentage: 0.9,
      categoryPercentage: 0.85,
      scales: {
        x: { display: false, grid: { display: false }, suggestedMax: tacticMax * 1.2 },
        y: { grid: { display: false }, ticks: { color: '#e6edf3', font: { size: 13 } } },
      },
      plugins: {
        legend: { display: false },
        tooltip: { enabled: false, external: (ctx) => externalChartTip(ctx, TOTAL_RULES) },
        datalabels: { clip: false, anchor: 'end', align: 'end', color: '#e6edf3', font: { weight: 'bold', size: 11 } },
      },
    },
  });

  // Rule Type — a single column, stacked internally into a Sigma segment and
  // a Native SPL segment. Sized to fill 85% of its plot box on both axes —
  // the same 85% fill proportion as the doughnuts' `radius: '85%'` — so the
  // column reads at the same visual "weight" within its tile as the
  // doughnuts do within theirs. Card markup (.severity-card-body /
  // .severity-canvas-wrap / .sev-legend) is reused verbatim from Severity,
  // so the margins around the plot — and now the overall canvas height too
  // (196px) — are byte-for-byte the same as Severity's.
  //
  // This is a TRUE 100%-stacked column: the plotted values are always a
  // percentage of whichever datasets are currently visible, recomputed on
  // every legend toggle, so hiding one segment makes the other expand to
  // fill the whole column rather than staying pinned to its original
  // share of the full (both-visible) total. The underlying raw counts
  // (sourceEntries) never change — only the plotted percentages do — so
  // the tooltip can still look up and display the real counts.
  const sourceCount = {};
  RULES.forEach(r => { sourceCount[normKey(r.source)] = (sourceCount[normKey(r.source)] || 0) + 1; });
  const sourceEntries = [
    { label: 'Sigma', n: sourceCount['sigma'] || 0, color: SOURCE_HEX.sigma },
    { label: 'Native SPL', n: sourceCount['nativespl'] || 0, color: SOURCE_HEX.nativespl },
  ].filter(s => s.n > 0);
  const sourceVisible = sourceEntries.map(() => true);

  function sourceChartTip(ctx) {
    const tip = document.getElementById('chart-tip');
    const t = ctx.tooltip;
    if (!t || t.opacity === 0) { tip.style.display = 'none'; return; }
    const dp = t.dataPoints && t.dataPoints[0];
    if (dp) {
      const entry = sourceEntries[dp.datasetIndex];
      const value = entry ? entry.n : 0;
      const pctVal = Math.round(dp.raw); // the percentage actually plotted (of the visible total)
      tip.innerHTML =
        '<div class="sev-tip-title">' + dp.dataset.label + '</div>' +
        '<div class="sev-tip-count">' + value + ' pcs</div>' +
        '<div class="sev-tip-pct">(' + pctVal + '%)</div>';
    }
    const rect = ctx.chart.canvas.getBoundingClientRect();
    tip.style.display = 'block';
    tip.style.left = (rect.left + t.caretX) + 'px';
    tip.style.top = (rect.top + t.caretY) + 'px';
  }

  const sourceChart = new Chart(document.getElementById('chart-source'), {
    type: 'bar',
    data: {
      labels: [''],
      datasets: sourceEntries.map(s => ({
        label: s.label,
        data: [0], // recomputed to real percentages immediately below
        backgroundColor: s.color,
        borderColor: '#0d1117',
        borderWidth: 1,
      })),
    },
    options: {
      maintainAspectRatio: false,
      animation,
      categoryPercentage: 0.85, // same 85% fill fraction as the doughnuts' radius
      barPercentage: 1,
      scales: {
        x: { stacked: true, display: false, grid: { display: false } },
        y: { stacked: true, display: false, grid: { display: false }, min: 0, max: 100 / 0.85 },
      },
      plugins: {
        legend: { display: false },
        tooltip: { enabled: false, external: (ctx) => sourceChartTip(ctx) },
        datalabels: { display: false },
      },
    },
  });

  // Recompute every dataset's plotted value as a percentage of the sum of
  // currently-visible datasets' real counts, so the visible segment(s)
  // always add up to exactly 100% of the column — a true 100%-stacked
  // chart, not a fixed scale based on the (both-visible) grand total.
  function recomputeSourceStack() {
    const visibleTotal = sourceEntries.reduce((s, e, i) => s + (sourceVisible[i] ? e.n : 0), 0);
    sourceChart.data.datasets.forEach((ds, i) => {
      ds.hidden = !sourceVisible[i];
      ds.data = [visibleTotal > 0 && sourceVisible[i] ? (sourceEntries[i].n / visibleTotal) * 100 : 0];
    });
    sourceChart.update();
  }
  recomputeSourceStack();

  const sourceLegendEl = document.getElementById('source-legend');
  sourceEntries.forEach((s, i) => {
    const item = document.createElement('div');
    item.className = 'sev-legend-item';
    item.innerHTML = '<span class="sev-legend-dot" style="background:' + s.color + '"></span>' + escHtml(s.label);
    item.addEventListener('click', () => {
      sourceVisible[i] = !sourceVisible[i];
      recomputeSourceStack();
      item.classList.toggle('off', !sourceVisible[i]);
    });
    sourceLegendEl.appendChild(item);
  });

  // Status — doughnut + custom HTML legend, built identically to Rules by
  // Severity (same interaction, same legend format: dot + name, no numbers).
  const statusOrder = ['stable', 'test', 'experimental', 'deprecated'];
  const STATUS_DISPLAY = { stable: 'Stable', test: 'Test', experimental: 'Experimental', deprecated: 'Deprecated' };
  const statusCount = {};
  RULES.forEach(r => { const k = (r.status || '').toLowerCase(); if (k) statusCount[k] = (statusCount[k] || 0) + 1; });
  const statusActive = statusOrder.filter(k => statusCount[k] > 0);
  const statusTotal = statusActive.reduce((s, k) => s + statusCount[k], 0);
  // Center overlay — % of rules that are Stable, mirroring Verification's
  // center Pass Rate overlay. Unlike PASS_RATE (a Python @@PASS_RATE@@
  // template substitution), this isn't known until RULES is parsed
  // client-side, so it's computed here and pushed into the DOM instead of
  // being baked into the HTML template.
  const stablePct = statusTotal > 0 ? Math.round((statusCount['stable'] || 0) / statusTotal * 100) : 0;
  document.getElementById('status-overlay-pct').textContent = stablePct + '%';
  document.getElementById('chart-status').setAttribute('aria-label', 'Doughnut chart showing rule counts broken down by status — ' + stablePct + '% stable');
  const statusChart = new Chart(document.getElementById('chart-status'), {
    type: 'doughnut',
    data: {
      labels: statusActive.map(k => STATUS_DISPLAY[k]),
      datasets: [{
        data: statusActive.map(k => statusCount[k]),
        backgroundColor: statusActive.map(k => STATUS_HEX[k] || '#4d5866'),
        borderColor: '#0d1117',
        borderWidth: 1,
        hoverOffset: 8,
      }],
    },
    options: {
      maintainAspectRatio: false,
      cutout: '55%',
      radius: '85%',
      animation: doughnutAnimation,
      plugins: {
        legend: { display: false },
        tooltip: { enabled: false, external: (ctx) => externalChartTip(ctx, statusTotal) },
        datalabels: { display: false },
      },
    },
  });

  const statusLegendEl = document.getElementById('status-legend');
  statusActive.forEach((k, i) => {
    const item = document.createElement('div');
    item.className = 'sev-legend-item';
    item.innerHTML = '<span class="sev-legend-dot" style="background:' + (STATUS_HEX[k] || '#4d5866') + '"></span>' + STATUS_DISPLAY[k];
    item.addEventListener('click', () => {
      statusChart.toggleDataVisibility(i);
      statusChart.update();
      item.classList.toggle('off', !statusChart.getDataVisibility(i));
    });
    statusLegendEl.appendChild(item);
  });

  // Evidence and Verification are two cards because they are two questions,
  // and a doughnut can only answer one — a slice gets exactly one name.
  // Evidence asks how much of the library has a verdict worth reading (all
  // rules); Verification asks what those readable verdicts say (only the
  // current ones). The denominators differ on purpose, which is why
  // Verification's overlay spells its own out underneath the percentage.
  //
  // Both are counted from RULES with the same predicates the table and the
  // Evidence facet use, rather than from separate @@ placeholders, so neither
  // ring can drift out of agreement with the rows underneath it. (Those
  // predicates are hoisted function declarations in this same scope, defined
  // further down.)
  const evidenceCount = { current: 0, superseded: 0, expired: 0, never: 0, scoped: 0 };
  const verifyCount = { pass: 0, notver: 0, fail: 0 };
  RULES.forEach(r => {
    const v = r.verdict || 'N/A';
    if (v === 'N/A' || !v) { evidenceCount.never++; return; }
    if (isVerdictSuperseded(r)) { evidenceCount.superseded++; return; }
    if (isVerdictExpired(r)) { evidenceCount.expired++; return; }
    // Checked after the two lapse tests, not before, so this stays in step
    // with generate_stats.py: there, an out-of-scope verdict that has also
    // aged out is counted as expired (verified_stale), and only the rest is
    // subtracted as out-of-scope. Same rule is excluded from the pass rate
    // either way -- the order decides only which slice names it, and the two
    // sides have to name it identically or the ring and the badge tell
    // different stories.
    if (isOutOfScope(r)) { evidenceCount.scoped++; return; }
    evidenceCount.current++;
    // Only current verdicts reach the verdict tally. A lapsed PASS is not a
    // pass that happens to be old, it is an absence of present-tense
    // evidence — and it is already accounted for one card to the left.
    if (v === 'PASS') verifyCount.pass++;
    else if (v === 'FAIL') verifyCount.fail++;
    else if (v === 'NOT_VERIFIED') verifyCount.notver++;
  });

  // Evidence — doughnut with center Current % overlay + side legend.
  //
  // Superseded and Expired get a segment each rather than sharing one under
  // some umbrella word: same standing, different diagnoses, and naming both
  // plainly beats coining a term a reader has to look up. Superseded keeps the
  // drift purple worn by the row marker and the Evidence facet so the three
  // tell one story in one hue; Expired takes the teal the retired Review facet
  // used to carry. Empty segments are filtered out, so Expired is simply not
  // drawn until a verdict actually crosses the review interval.
  //
  // Out of scope takes orange rather than another grey: it sits next to the
  // grey "Never tested" slice and means something different from it — skipped
  // on purpose, not missed — and every muted blue-grey tried against that grey
  // came back under the validator's normal-vision separation floor, i.e.
  // indistinguishable to readers with full colour vision, let alone without.
  // Orange clears it (ΔE 17.5 normal, 15.3 tritan) and is not one of the
  // page's reserved verdict hues, so it cannot be misread as a fourth verdict.
  const evidenceSegs = [
    { label: 'Current', n: evidenceCount.current, color: '#3fb950' },
    { label: 'Superseded', n: evidenceCount.superseded, color: '#bc8cff' },
    { label: 'Expired', n: evidenceCount.expired, color: '#2dd4bf' },
    { label: 'Out of scope', n: evidenceCount.scoped, color: '#db6d28' },
    { label: 'Never tested', n: evidenceCount.never, color: '#8b949e' },
  ].filter(s => s.n > 0);
  const evidenceTotal = evidenceSegs.reduce((s, x) => s + x.n, 0);
  const evidencePct = evidenceTotal > 0 ? Math.round(evidenceCount.current / evidenceTotal * 100) : 0;
  const evidencePctEl = document.getElementById('evidence-overlay-pct');
  if (evidencePctEl) evidencePctEl.textContent = evidencePct + '%';
  // The one number on this page that explains a low Current % without the
  // reader having to open a filter: rules nobody set out to measure. Shown
  // only while there are any, so the card carries no permanent footnote about
  // a state the library is normally not in -- and hidden via the hidden
  // attribute so it leaves no empty line behind when it goes.
  const scopeNoteEl = document.getElementById('evidence-scope-note');
  if (scopeNoteEl) {
    if (evidenceCount.scoped > 0) {
      scopeNoteEl.textContent =
        evidenceCount.scoped + ' of ' + RULES.length + ' rules are out of testing scope' +
        ' — testing is switched off on the rule itself, so the pipeline skips them' +
        ' rather than failing to measure them. Not counted in the Pass Rate.';
      scopeNoteEl.hidden = false;
    } else {
      scopeNoteEl.hidden = true;
    }
  }

  // Last live verification — a plain historical fact ("when did the pipeline
  // last actually measure anything, and how much of the library did that run
  // cover"), not a standing that erodes with elapsed time like the pass rate
  // or the Evidence segments above. It is recomputed here from RULES, rather
  // than left as the build-time @@LAST_LIVE_TEXT@@ seed, purely so it can
  // never silently drift from the Python-side figure in stats.json -- both
  // sides use the identical predicate (see _last_live_verification()'s
  // docstring in generate_stats.py): a rule counts only if its verdict is
  // not N/A, testing was not deliberately disabled for that run, and it
  // carries both a runId and a verdictAt. Rows failing that (e.g. legacy
  // result.json files written before run_id existed) are left out of the
  // grouping entirely, matching the Python side row for row.
  let lastLiveAt = '';
  let lastLiveRunId = '';
  RULES.forEach(r => {
    const v = r.verdict || 'N/A';
    if (v === 'N/A' || !v || r.testingDisabled) return;
    if (!r.runId || !r.verdictAt) return;
    if (r.verdictAt > lastLiveAt) { lastLiveAt = r.verdictAt; lastLiveRunId = r.runId; }
  });
  let lastLiveCount = 0;
  if (lastLiveAt) {
    RULES.forEach(r => {
      const v = r.verdict || 'N/A';
      if (v === 'N/A' || !v || r.testingDisabled) return;
      if (r.runId === lastLiveRunId) lastLiveCount++;
    });
  }
  const lastLiveNoteEl = document.getElementById('evidence-lastlive-note');
  if (lastLiveNoteEl) {
    if (lastLiveCount > 0) {
      const displayAt = lastLiveAt.slice(0, 19).replace('T', ' ') + ' UTC';
      lastLiveNoteEl.textContent =
        'Last live verification: ' + displayAt + ' — ' + lastLiveCount + ' of ' +
        RULES.length + ' rules measured in that run.';
      lastLiveNoteEl.hidden = false;
    } else {
      lastLiveNoteEl.hidden = true;
    }
  }
  const evidenceCanvas = document.getElementById('chart-evidence');
  if (evidenceCanvas) {
    evidenceCanvas.setAttribute('aria-label',
      'Doughnut chart of how much of the library has a verdict worth reading: ' +
      evidenceSegs.map(s => s.n + ' ' + s.label.toLowerCase()).join(', ') +
      ' — ' + evidencePct + '% current out of ' + RULES.length + ' rules');
  }
  const evidenceChart = new Chart(document.getElementById('chart-evidence'), {
    type: 'doughnut',
    data: {
      labels: evidenceSegs.map(s => s.label),
      datasets: [{
        data: evidenceSegs.map(s => s.n),
        backgroundColor: evidenceSegs.map(s => s.color),
        borderColor: '#0d1117',
        borderWidth: 1,
        hoverOffset: 8,
      }],
    },
    options: {
      maintainAspectRatio: false,
      cutout: '55%',
      radius: '85%',
      animation: doughnutAnimation,
      plugins: {
        legend: { display: false },
        tooltip: { enabled: false, external: (ctx) => externalChartTip(ctx, evidenceTotal) },
        datalabels: { display: false },
      },
    },
  });

  const evidenceLegendEl = document.getElementById('evidence-legend');
  evidenceSegs.forEach((s, i) => {
    const item = document.createElement('div');
    item.className = 'verify-legend-item';
    item.innerHTML = '<span class="vdot" style="background:' + s.color + '"></span><span class="vlabel">' + escHtml(s.label) + '</span>';
    item.addEventListener('click', () => {
      evidenceChart.toggleDataVisibility(i);
      evidenceChart.update();
      item.classList.toggle('off', !evidenceChart.getDataVisibility(i));
    });
    evidenceLegendEl.appendChild(item);
  });

  // Verification — one dimension again: of the verdicts that still count,
  // what did they say.
  const verifySegs = [
    { label: 'Pass', n: verifyCount.pass, color: '#3fb950' },
    { label: 'Not Verified', n: verifyCount.notver, color: '#d29922' },
    { label: 'Fail', n: verifyCount.fail, color: '#f85149' },
  ].filter(s => s.n > 0);

  // The overlay is recomputed here rather than left as the @@PASS_RATE@@ the
  // template was built with. Expiry moves with the reader's clock, so a page
  // opened six months after it was generated would otherwise show a headline
  // that its own ring below contradicts. stats.json and the README badges keep
  // the build-time figure -- a badge is a snapshot by definition -- but what
  // is on screen agrees with what is on screen.
  const liveCurrent = verifyCount.pass + verifyCount.fail + verifyCount.notver;
  const livePassRate = liveCurrent > 0 ? Math.round(verifyCount.pass / liveCurrent * 100) : 0;
  // Scoped through this chart's own canvas, not a bare
  // '.verify-canvas-wrap .verify-overlay-pct': Evidence reuses the same
  // wrapper class and now sits first in the DOM, so a document-wide
  // querySelector would quietly write the pass rate into Evidence's ring.
  const verifyWrap = document.getElementById('chart-verify').parentElement;
  const overlayPct = verifyWrap.querySelector('.verify-overlay-pct');
  if (overlayPct) overlayPct.textContent = livePassRate + '%';
  document.getElementById('chart-verify').setAttribute('aria-label',
    'Doughnut chart showing rule verification breakdown — pass rate ' + livePassRate +
    '% across the ' + liveCurrent + ' of ' + RULES.length +
    ' rules whose verdict is still current evidence');
  const verifyTotal = verifySegs.reduce((s, x) => s + x.n, 0);
  const verifyChart = new Chart(document.getElementById('chart-verify'), {
    type: 'doughnut',
    data: {
      labels: verifySegs.map(s => s.label),
      datasets: [{
        data: verifySegs.map(s => s.n),
        backgroundColor: verifySegs.map(s => s.color),
        borderColor: '#0d1117',
        borderWidth: 1,
        hoverOffset: 8,
      }],
    },
    options: {
      maintainAspectRatio: false,
      cutout: '55%',
      radius: '85%',
      animation: doughnutAnimation,
      plugins: {
        legend: { display: false },
        tooltip: { enabled: false, external: (ctx) => externalChartTip(ctx, verifyTotal) },
        datalabels: { display: false },
      },
    },
  });

  const verifyLegendEl = document.getElementById('verify-legend');
  verifySegs.forEach((s, i) => {
    const item = document.createElement('div');
    item.className = 'verify-legend-item';
    item.innerHTML = '<span class="vdot" style="background:' + s.color + '"></span><span class="vlabel">' + escHtml(s.label) + '</span>';
    item.addEventListener('click', () => {
      verifyChart.toggleDataVisibility(i);
      verifyChart.update();
      item.classList.toggle('off', !verifyChart.getDataVisibility(i));
    });
    verifyLegendEl.appendChild(item);
  });

  // ── Trends Over Time ──────────────────────────────────────────────────
  // Shared date formatter + empty-state helper for the 2 history-backed
  // charts below. History is only as deep as the incrementally-updated
  // outputs/reports/*_history.json caches (see generate_stats.py's
  // update_trend_history()) — a brand-new checkout may have just 1-2
  // points, which these charts render fine (a single dot / short line)
  // rather than erroring.
  function formatTrendDate(iso) {
    const d = new Date(iso + 'T00:00:00Z');
    if (isNaN(d.getTime())) return iso;
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' });
  }

  function clearTrendEmptyState(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    canvas.style.display = '';
    const wrap = canvas.parentElement;
    const note = wrap && wrap.querySelector('.trend-empty');
    if (note) note.remove();
  }

  function trendEmptyState(canvasId, message) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    clearTrendEmptyState(canvasId);
    canvas.style.display = 'none';
    const note = document.createElement('div');
    note.className = 'trend-empty';
    note.textContent = message;
    canvas.parentElement.appendChild(note);
  }

  function trendPointTip(ctx, points, formatBody) {
    const tip = document.getElementById('chart-tip');
    const t = ctx.tooltip;
    if (!t || t.opacity === 0) { tip.style.display = 'none'; return; }
    const dp = t.dataPoints && t.dataPoints[0];
    if (dp) tip.innerHTML = formatBody(points[dp.dataIndex]);
    const rect = ctx.chart.canvas.getBoundingClientRect();
    tip.style.display = 'block';
    tip.style.left = (rect.left + t.caretX) + 'px';
    tip.style.top = (rect.top + t.caretY) + 'px';
  }

  // ── Time-range bucketing (Yearly / Quarterly / Monthly / All) ──────────
  // Both history caches store one raw point per day (see
  // update_trend_history() in generate_stats.py). Over a multi-year
  // project that grows into thousands of points, which is exactly what
  // "All" is for — everyone else drills down to a coarser grain so the
  // chart stays a handful of ticks instead of an unreadable comb. Each
  // point is a snapshot/cumulative total (not a per-period delta), so
  // "bucketing" always means "keep the chronologically LAST point in the
  // period", never sum/average — that's what the underlying values mean
  // (e.g. total rule count as of that day).
  const MONTH_LABELS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const QUARTER_LABELS = ['Q1', 'Q2', 'Q3', 'Q4'];

  function trendPointYear(iso) { return parseInt(iso.slice(0, 4), 10); }
  function trendPointMonth(iso) { return parseInt(iso.slice(5, 7), 10); }
  function trendPointQuarter(iso) { return Math.ceil(trendPointMonth(iso) / 3); }

  function trendAvailableYears() {
    const years = new Set();
    COVERAGE_HISTORY.forEach(p => years.add(trendPointYear(p.date)));
    RULE_GROWTH_HISTORY.forEach(p => years.add(trendPointYear(p.date)));
    return [...years].sort((a, b) => a - b);
  }

  function bucketTrendPoints(points, granularity, year) {
    if (!points.length) return [];
    if (granularity === 'yearly') {
      const byYear = new Map();
      points.forEach(p => byYear.set(trendPointYear(p.date), p)); // points are date-ascending, so last write wins
      return [...byYear.entries()].sort((a, b) => a[0] - b[0]).map(([y, p]) => ({ ...p, _bucketLabel: String(y) }));
    }
    if (granularity === 'quarterly' || granularity === 'monthly') {
      const inYear = points.filter(p => trendPointYear(p.date) === year);
      const byBucket = new Map();
      inYear.forEach(p => {
        const key = granularity === 'quarterly' ? trendPointQuarter(p.date) : trendPointMonth(p.date);
        byBucket.set(key, p);
      });
      const labels = granularity === 'quarterly' ? QUARTER_LABELS : MONTH_LABELS;
      return [...byBucket.entries()].sort((a, b) => a[0] - b[0]).map(([i, p]) => ({ ...p, _bucketLabel: labels[i - 1] }));
    }
    // 'all' — every raw point, at full daily resolution.
    return points.map(p => ({ ...p, _bucketLabel: formatTrendDate(p.date) }));
  }

  // MITRE ATT&CK Coverage Over Time — single-series line/area. Uses the
  // same accent gold as the Coverage gauge and Tactics bar above, so color
  // keeps meaning "MITRE" consistently across the whole dashboard. Single
  // series → no legend needed (the card title already names it).
  function renderCoverageTrendChart(points) {
    const prior = Chart.getChart('chart-coverage-trend');
    if (prior) prior.destroy();
    if (!points.length) {
      trendEmptyState('chart-coverage-trend', 'History builds up as CI runs continue — check back soon.');
      return;
    }
    clearTrendEmptyState('chart-coverage-trend');
    new Chart(document.getElementById('chart-coverage-trend'), {
      type: 'line',
      data: {
        labels: points.map(p => p._bucketLabel),
        datasets: [{
          label: 'Coverage %',
          data: points.map(p => p.mitre_coverage_pct),
          borderColor: '#FFAA00',
          backgroundColor: 'rgba(255,170,0,0.1)',
          fill: true,
          borderWidth: 2,
          tension: 0.25,
          pointRadius: points.length > 1 ? 0 : 4,
          pointHoverRadius: 5,
          pointHitRadius: 12,
          pointBackgroundColor: '#FFAA00',
          pointBorderColor: '#0d1117',
          pointBorderWidth: 2,
        }],
      },
      options: {
        maintainAspectRatio: false,
        animation,
        // The entrance/rebuild animation above (700ms, easeOutQuart) should
        // NOT also govern the per-hover active-point transition — Chart.js
        // otherwise reuses `animation`'s duration for the hover-triggered
        // "move the highlighted point" transition too, which is why the
        // previous position's dot used to visibly linger/fade for ~700ms
        // after the cursor had already moved on. Zeroing just the `active`
        // transition makes the highlighted point snap immediately to the
        // new nearest position, independent of the entrance animation.
        transitions: { active: { animation: { duration: 0 } } },
        interaction: { mode: 'index', intersect: false },
        scales: {
          x: { grid: { display: false }, ticks: { color: '#8b949e', font: { size: 11 }, maxRotation: 0, autoSkip: true } },
          y: {
            grid: { color: 'rgba(139,148,158,0.15)' },
            ticks: { color: '#8b949e', font: { size: 11 }, callback: (v) => v + '%' },
            suggestedMin: 0, suggestedMax: 100,
          },
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            enabled: false,
            external: (ctx) => trendPointTip(ctx, points, (p) =>
              '<div class="trend-tip-primary">' + p.mitre_coverage_pct + '% coverage</div>' +
              '<div class="trend-tip-secondary">' + p.mitre_covered_techniques + ' / ' + p.mitre_total_techniques + ' techniques</div>'),
          },
          datalabels: { display: false },
        },
      },
    });
  }

  // Rule Count Growth — Sigma vs Native SPL as two INDEPENDENT lines (not
  // stacked): both are rule counts (same unit), just very different
  // magnitude, so one shared y-axis stays honest — stacking previously
  // made the near-flat Native SPL series visually track Sigma's growth
  // (it was drawn as Sigma-count + Native-count), which misrepresented it
  // as growing when it has stayed at 1 for most of this project's history.
  // Reuses the same 2 identity colors as the Rule Type tile above.
  function renderGrowthChart(points) {
    const priorLegend = document.getElementById('growth-legend');
    if (priorLegend) priorLegend.innerHTML = '';
    const prior = Chart.getChart('chart-rule-growth');
    if (prior) prior.destroy();
    if (!points.length) {
      trendEmptyState('chart-rule-growth', 'History builds up as CI runs continue — check back soon.');
      return;
    }
    clearTrendEmptyState('chart-rule-growth');
    const growthChart = new Chart(document.getElementById('chart-rule-growth'), {
      type: 'line',
      data: {
        labels: points.map(p => p._bucketLabel),
        datasets: [
          {
            label: 'Sigma',
            data: points.map(p => p.total_sigma_rules),
            borderColor: SOURCE_HEX.sigma,
            backgroundColor: 'rgba(0,172,215,0.1)',
            fill: 'origin',
            borderWidth: 2,
            tension: 0.2,
            pointRadius: points.length > 1 ? 0 : 4,
            pointHoverRadius: 5,
            pointHitRadius: 12,
            pointBackgroundColor: SOURCE_HEX.sigma,
            pointBorderColor: '#0d1117',
            pointBorderWidth: 2,
          },
          {
            label: 'Native SPL',
            data: points.map(p => p.total_native_spl_rules),
            borderColor: SOURCE_HEX.nativespl,
            backgroundColor: 'rgba(255,102,0,0.1)',
            fill: 'origin',
            borderWidth: 2,
            tension: 0.2,
            pointRadius: points.length > 1 ? 0 : 4,
            pointHoverRadius: 5,
            pointHitRadius: 12,
            pointBackgroundColor: SOURCE_HEX.nativespl,
            pointBorderColor: '#0d1117',
            pointBorderWidth: 2,
          },
        ],
      },
      options: {
        maintainAspectRatio: false,
        animation,
        // See renderCoverageTrendChart() above for why this is zeroed
        // separately from the entrance `animation` — without it the
        // previously-hovered point lingers/fades for the full entrance
        // duration after the cursor has already moved to a new date.
        transitions: { active: { animation: { duration: 0 } } },
        interaction: { mode: 'index', intersect: false },
        scales: {
          x: { grid: { display: false }, ticks: { color: '#8b949e', font: { size: 11 }, maxRotation: 0, autoSkip: true } },
          y: {
            beginAtZero: true,
            grid: { color: 'rgba(139,148,158,0.15)' },
            ticks: { color: '#8b949e', font: { size: 11 }, precision: 0 },
          },
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            enabled: false,
            external: (ctx) => trendPointTip(ctx, points, (p) =>
              '<div class="trend-tip-primary">' + p.total_rules + ' rules total</div>' +
              '<div class="trend-tip-secondary">' + p.total_sigma_rules + ' Sigma / ' + p.total_native_spl_rules + ' Native SPL</div>'),
          },
          datalabels: { display: false },
        },
      },
    });

    const growthLegendEl = document.getElementById('growth-legend');
    [['Sigma', SOURCE_HEX.sigma], ['Native SPL', SOURCE_HEX.nativespl]].forEach(([label, color], i) => {
      const item = document.createElement('div');
      item.className = 'sev-legend-item';
      item.innerHTML = '<span class="sev-legend-dot" style="background:' + color + '"></span>' + escHtml(label);
      item.addEventListener('click', () => {
        growthChart.setDatasetVisibility(i, !growthChart.isDatasetVisible(i));
        growthChart.update();
        item.classList.toggle('off', !growthChart.isDatasetVisible(i));
      });
      growthLegendEl.appendChild(item);
    });
  }

  // ── Trend range bar wiring ──────────────────────────────────────────────
  // One shared { granularity, year } selection scopes BOTH trend charts, so
  // they always agree on what window they're showing (see interaction.md:
  // filters live in one row above the content they scope, never per-chart).
  const trendState = { granularity: 'all', year: null };

  function applyTrendRange() {
    renderCoverageTrendChart(bucketTrendPoints(COVERAGE_HISTORY, trendState.granularity, trendState.year));
    renderGrowthChart(bucketTrendPoints(RULE_GROWTH_HISTORY, trendState.granularity, trendState.year));
  }

  const granGroupEl = document.getElementById('trend-gran-group');
  const yearSelectEl = document.getElementById('trend-year-select');
  const availableYears = trendAvailableYears();
  availableYears.forEach(y => {
    const opt = document.createElement('option');
    opt.value = String(y);
    opt.textContent = String(y);
    yearSelectEl.appendChild(opt);
  });
  trendState.year = availableYears.length ? availableYears[availableYears.length - 1] : new Date().getUTCFullYear();
  yearSelectEl.value = String(trendState.year);

  if (granGroupEl) {
    granGroupEl.querySelectorAll('.trend-gran-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        if (btn.classList.contains('active')) return;
        granGroupEl.querySelectorAll('.trend-gran-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        trendState.granularity = btn.dataset.granularity;
        yearSelectEl.style.display = (trendState.granularity === 'quarterly' || trendState.granularity === 'monthly') ? '' : 'none';
        applyTrendRange();
      });
    });
  }
  yearSelectEl.addEventListener('change', () => {
    trendState.year = parseInt(yearSelectEl.value, 10);
    applyTrendRange();
  });

  applyTrendRange();

  // Re-snap now that every legend has been populated. The first snap at the
  // top of this function measured cards whose legends were still empty, so
  // the rings were pinned to a width that left the labels nowhere to sit.
  // Doing it once here, rather than after each individual chart, keeps it to
  // a single layout pass for the whole section.
  snapCanvasWrapsToIntegerSize();
  [...ROW_FLEX_CANVAS_IDS, ...COLUMN_FLEX_CANVAS_IDS].forEach(id => {
    const c = Chart.getChart(id);
    if (c) c.resize();
  });
}

const FILTER_FIELDS = [
  { key: 'source', label: 'Rule Type' },
  { key: 'category', label: 'Product Category' },
  { key: 'product', label: 'Product' },
  { key: 'service', label: 'Service' },
  { key: 'severity', label: 'Severity' },
  { key: 'status', label: 'Status' },
  // The three testing facets run in the order the questions get asked: how
  // was it tested, what did it say, is it still current. renderFilters()
  // builds a supergroup out of any RUN OF ADJACENT fields sharing a group
  // name, so each group's members must stay next to each other — inserting
  // anything between them silently splits the group into two headers with
  // the same title.
  //
  // Shipped from the pipeline's `testing` block: not what the verdict said,
  // but how it was arrived at. Deliberately filter-only, no column — the
  // answer is the same for most of the library, so a column would spend real
  // width repeating "Atomic Red Team / windows-victim" down the page, while
  // as a facet it does the one job worth doing: isolating the rules verified
  // some other way.
  { key: 'verifyMethod', label: 'Method', group: 'Verification' },
  { key: 'verifyRunner', label: 'Runner', group: 'Verification' },
  // Grouped the way MITRE's Tactic/Technique are: the verdict and whether
  // that verdict is still evidence about the rule as it stands are two halves
  // of one question, and neither is much use read alone.
  //
  // Evidence replaces what used to be two separate facets, Sync (Current /
  // Outdated, by rule version) and Review (Up to date / Overdue, by age).
  // They were one concept wearing two names, and the names ran backwards
  // against the intuition: "Outdated" meant "the rule changed", while the
  // verdicts that were literally old were filed under "Overdue". A verdict is
  // a certificate — it stops being evidence either because it expired or
  // because the thing it certifies changed underneath it — so both live on
  // one axis now, and the values say which of the two happened. Derived in the
  // browser; see verdictEvidence.
  { key: 'verdict', label: 'Result', group: 'Verdict' },
  { key: 'evidence', label: 'Evidence', group: 'Verdict' },
  { key: 'tactics', label: 'Tactic', group: 'MITRE ATT&CK' },
  { key: 'techniques', label: 'Technique', group: 'MITRE ATT&CK' },
];

const GROUP_ACCENT = { 'MITRE ATT&CK': '#8f95d6', 'Verdict': '#bc8cff', 'Verification': '#39c5cf' };

const FIELD_FC = {
  source: 'fc-source',
  category: 'fc-category',
  product: 'fc-product',
  service: 'fc-service',
  severity: 'fc-severity',
  status: 'fc-status',
  verdict: 'fc-verdict',
  evidence: 'fc-verdict',
  verifyMethod: 'fc-verify',
  verifyRunner: 'fc-verify',
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

function normKey(s) { return (s || '').toLowerCase().replace(/[^a-z0-9]+/g, ''); }

// Verdict values are stored/exported as e.g. "NOT_VERIFIED" (matching
// pass_fail_eval.py) but displayed as "NOT VERIFIED" -- same no-underscore
// convention as PASS/FAIL/N-A. CSS class names use normKey() instead, so
// this only affects human-visible text, never selectors.
function vLabel(v) { return String(v ?? '').replace(/_/g, ' '); }

// A rule is due for re-validation this many days after its last verified run.
// Everything derived from it is computed in the browser against the visitor's
// clock, so the page keeps ageing correctly between pipeline runs.
const REVIEW_INTERVAL_DAYS = @@REVIEW_DAYS@@;

// Calendar days, not elapsed 24h blocks. verdictAt is a full timestamp, but
// every place that shows an age also shows the UTC date beside it, so the two
// have to agree: a run at 08:58Z read three calendar days later is "3 days
// ago", not the "2" that floor((now - then) / 86400000) would give until the
// clock passes 08:58Z. Both sides are normalised to UTC midnight — matching
// the .slice(0, 10) date the UI prints — so the subtraction is whole days and
// DST never enters into it.
function verdictAgeDays(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  if (isNaN(d.getTime())) return null;
  const then = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
  const now = new Date();
  const today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  return Math.round((today - then) / 86400000);
}

function isReviewDue(r) {
  const days = verdictAgeDays(r && r.verdictAt);
  return days !== null && days >= REVIEW_INTERVAL_DAYS;
}

// A verdict is only as current as the rule it was measured on. The pipeline
// records verdictRuleVersion — the rule version that actually ran — beside
// the rule's present ruleVersion; when the two diverge the badge is still
// green, but it is green for text that no longer exists.
function isVerdictSuperseded(r) {
  if (!r || !r.verdict || r.verdict === 'N/A') return false;
  if (!r.ruleVersion || !r.verdictRuleVersion) return false;
  return String(r.ruleVersion) !== String(r.verdictRuleVersion);
}

// A verdict we cannot place inside the review window counts as expired, not
// as current. A missing or unparseable verdictAt is the only way that
// happens; the pipeline always writes one, so this is a guard rather than a
// case, but the direction matters. Treating "we don't know when this was
// measured" as current would be an unfalsifiable green — precisely the shape
// of claim this whole mechanism exists to remove.
function isVerdictExpired(r) {
  if (!r || !r.verdict || r.verdict === 'N/A') return false;
  // Deliberately not isReviewDue(), which answers false for an undateable
  // verdict because "is it past the interval" genuinely has no answer there.
  // This asks the other question -- can we show it is still inside the
  // window -- and an unreadable timestamp answers that no, exactly as a
  // missing one does. Python's verdict_is_expired makes the same call on the
  // same two cases (_age is None), and the two must not drift apart.
  const days = verdictAgeDays(r.verdictAt);
  return days === null || days >= REVIEW_INTERVAL_DAYS;
}

// A verdict that was never attempted, on purpose. NOT_VERIFIED is one word
// covering two opposite situations -- the pipeline tried and could not tell,
// or the pipeline was told not to try (custom.testing.enabled: false on the
// rule) -- and only the second one is a scoping decision rather than a hole in
// the measurement. pass_fail_eval.py records which happened at the moment of
// the run, and generate_stats.py carries it through as testingDisabled; it is
// deliberately a property of the verdict, so re-enabling testing on a rule
// does not retroactively rewrite what the last run did.
//
// The verdict check is not redundant with the flag: it keeps the predicate
// answering "this verdict was skipped" rather than "this rule has testing
// off", which is what makes it safe to fold into the Evidence chain below.
function isOutOfScope(r) {
  return !!(r && r.testingDisabled && r.verdict === 'NOT_VERIFIED');
}

// The two ways a verdict stops being evidence about the rule as it stands
// today, in one predicate. Superseded is the certain one -- the logic that
// was tested is demonstrably not the logic that is deployed. Expired is the
// probabilistic one -- same logic, but @@REVIEW_DAYS@@ days of telemetry
// changes, Splunk config and attacker tooling sit between the measurement and
// now. Different diagnoses, but the same standing (not evidence) and the same
// remedy (re-run the workflow), which is why they share a bucket everywhere a
// number is computed, and stay separate only where a label is shown.
function isVerdictLapsed(r) {
  return isVerdictSuperseded(r) || isVerdictExpired(r);
}

// Evidence is a facet the pipeline cannot fully produce: whether a verdict has
// expired depends on when the page is READ, not when it was generated.
// Deriving it here — once per load, against the reader's clock — keeps the
// filter honest, and makes it an ordinary string field so the whole
// filter/count/export machinery works on it unchanged.
//
// Superseded wins over Expired when a rule is both, because it is the
// stronger claim: an expired verdict might still describe the rule, a
// superseded one provably does not.
RULES.forEach(r => {
  // '' — not a placeholder label — for rules the question cannot be asked
  // about (a verdict with no version on either side). allVals() drops
  // empties, so those rules simply never offer a chip, rather than pooling
  // under an "unknown" bucket that would filter to a meaningless set.
  // "Never tested" means no verdict at all. A verdict that exists but cannot
  // be dated is Expired, not Never tested -- the measurement did happen, we
  // just cannot show it still counts.
  // "Out of scope" sits last among the not-Current buckets for the same
  // reason it does in the chart above and in generate_stats.py: a skipped
  // verdict that has also gone stale is filed under the staleness, because
  // that is the state a re-run would have to clear first.
  r.evidence = (!r.verdict || r.verdict === 'N/A')
    ? 'Never tested'
    : isVerdictSuperseded(r) ? 'Superseded'
      : isVerdictExpired(r) ? 'Expired'
        : isOutOfScope(r) ? 'Out of scope'
          : 'Current';
});

// How long ago a verdict was measured, in plain words. Days all the way up —
// "200 days ago" carries the point better than "6 months ago" does. Returns
// '' for a missing or unparseable timestamp so callers can skip the line.
function verdictAge(iso) {
  const days = verdictAgeDays(iso);
  if (days === null) return '';
  if (days <= 0) return 'today';
  if (days === 1) return 'yesterday';
  return days + ' days ago';
}

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
  if (key === 'source') return 'fc-source-' + normKey(val);
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
    rule.id, rule.title,
    rule.category, rule.product, rule.service,
    ...(rule.tactics || []), ...(rule.techniques || []),
    rule.severity, rule.status, rule.verdict,
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

// Mobile-only: the filter rail is display:none below 900px until this opens
// it. Deliberately not tied to a resize handler — the class is inert on wide
// screens, so a phone→desktop rotation needs no cleanup.
function toggleFiltersPanel() {
  const panel = document.getElementById('filters-panel');
  const btn = document.getElementById('filters-toggle');
  if (!panel) return;
  const open = panel.classList.toggle('mobile-open');
  if (btn) {
    btn.classList.toggle('active', open);
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
  }
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

// Which sections/supergroups currently have any values to show — shared by
// renderFilters (to know what "all expanded" means) and the Expand All toggle.
function filterAvailability() {
  const groupHasVals = {};
  const keysWithVals = [];
  FILTER_FIELDS.forEach(({ key, group }) => {
    if (!allVals(key).length) return;
    keysWithVals.push(key);
    if (group) groupHasVals[group] = true;
  });
  return { keysWithVals, groupsWithVals: Object.keys(groupHasVals) };
}

function toggleExpandAllFilters() {
  const { keysWithVals, groupsWithVals } = filterAvailability();
  const allOpen = keysWithVals.every(k => openSections.has(k)) && groupsWithVals.every(g => openGroups.has(g));
  if (allOpen) {
    keysWithVals.forEach(k => openSections.delete(k));
    groupsWithVals.forEach(g => openGroups.delete(g));
  } else {
    keysWithVals.forEach(k => openSections.add(k));
    groupsWithVals.forEach(g => openGroups.add(g));
  }
  renderFilters();
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
          <span class="chip-dot"></span>${escHtml(key === 'verdict' ? vLabel(v) : v)}<span class="chip-count">${n}</span>
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

  const { keysWithVals, groupsWithVals } = filterAvailability();
  const allOpen = (keysWithVals.length + groupsWithVals.length) > 0
    && keysWithVals.every(k => openSections.has(k))
    && groupsWithVals.every(g => openGroups.has(g));
  const expandBtn = (keysWithVals.length || groupsWithVals.length)
    ? `<button class="expand-all-filters-btn" onclick="toggleExpandAllFilters()">${allOpen ? '▲ Collapse All' : '▼ Expand All'}</button>`
    : '';

  panel.innerHTML = expandBtn + html
    + '<button class="clear-filters-btn" onclick="clearFilters()">Clear filters</button>'
    + `<div class="filters-generated" title="Last generated">Generated ${GENERATED_TS} UTC</div>`;
}

function renderActiveFilterRow() {
  const row = document.getElementById('active-filter-row');
  const tags = Object.entries(activeFilters).flatMap(([key, vals]) =>
    vals.map(v => `<span class="active-filter-tag ${chipFc(key, v)}">
        ${escHtml(FILTER_FIELDS.find(f => f.key === key)?.label || key)}: <strong>${escHtml(key === 'verdict' ? vLabel(v) : v)}</strong>
        <button onclick="toggleFilter('${key}', ${jsStr(v)})">&times;</button>
      </span>`)
  );
  row.innerHTML = tags.join('');
  row.classList.toggle('hidden', !tags.length);
}

// ── Top strip total ─────────────────────────────────────────────────────

function renderStripTotal() {
  const total = RULES.length;
  const stripTotal = document.getElementById('strip-total');
  if (stripTotal) stripTotal.innerHTML = `<strong>${total}</strong> rule${total === 1 ? '' : 's'}`;
}

// ── Badges ───────────────────────────────────────────────────────────────

function sevBadge(r) {
  if (!r.severity) return emptyCell();
  return `<span class="badge sev-${normKey(r.severity)}">${escHtml(r.severity)}</span>`;
}

function statusBadge(r) {
  if (!r.status) return emptyCell();
  return `<span class="badge status-${normKey(r.status)}">${escHtml(r.status)}</span>`;
}

function verdictBadge(r) {
  const v = r.verdict || 'N/A';
  // A stale verdict is drawn hollow: same word, same hue, but outlined
  // instead of filled, so an outdated PASS never reads as a solid green chip
  // at a glance down the column. The badge keeps its verdict colour rather
  // than turning purple -- what the run found is still what it found; only
  // its standing has changed, and the drift marker beside it names that.
  // Hollowing costs no column width, which a second text pill would.
  // Hollow for either kind of lapse, since either one means the same thing
  // about the badge: it is a record, not a current claim. Which kind it was is
  // what the two markers beside it distinguish.
  const superseded = isVerdictSuperseded(r);
  const expired = !superseded && isVerdictExpired(r);
  const badge = `<span class="badge verdict-${normKey(v)}${(superseded || expired) ? ' verdict-lapsed' : ''}">${escHtml(vLabel(v))}</span>`;
  // A review interval nobody can see is a review interval nobody keeps, and
  // opening 27 drawers to find the lapsed ones is not a workflow — so the
  // markers ride next to the verdict in the table itself.
  const due = expired
    ? `<span class="review-due" title="Expired — last tested ${verdictAge(r.verdictAt)}, past the ${REVIEW_INTERVAL_DAYS}-day review interval. Not counted in the pass rate.">&#9679;</span>`
    : '';
  const drift = superseded
    ? `<span class="verdict-drift" title="Superseded — ${escHtml(vLabel(v))} measured on rule v${escHtml(r.verdictRuleVersion)}, but the rule is now v${escHtml(r.ruleVersion)}. Not counted in the pass rate."><svg viewBox="0 0 24 24"><path d="M12 5 L20.5 19 H3.5 Z"/></svg></span>`
    : '';
  // Without this, a column of identical NOT VERIFIED badges gives no way to
  // tell the rules nobody tried to test from the ones the pipeline could not
  // measure -- the same conflation that made the published pass rate read 27
  // deliberate skips as failures. Shown only where neither lapse marker is
  // (they answer first, and two markers on one badge would be a puzzle).
  const scoped = (!superseded && !expired && isOutOfScope(r))
    ? `<span class="verdict-scoped" title="Out of testing scope — testing is switched off on this rule (custom.testing.enabled: false), so the pipeline skipped it rather than failing to measure it. Not counted in the pass rate."><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8"/><line x1="6.3" y1="17.7" x2="17.7" y2="6.3"/></svg></span>`
    : '';
  if (r.runUrl) return `<a href="${escHtml(r.runUrl)}" target="_blank" title="View Actions run" onclick="event.stopPropagation()">${badge}</a>${due}${drift}${scoped}`;
  return badge + due + drift + scoped;
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

// Three columns hold an ordered vocabulary that alphabetising destroys: it
// files "low" above "medium" and scatters the verdicts. Rank them by meaning
// instead, ascending = whatever most wants attention, so one click on the
// header is the triage order. Anything outside a list sorts after it, and
// every other column still falls through to the string compare.
//
// severity and status reuse the orders the dashboard charts already sort by
// (LEVEL_ORDER, statusOrder) so the table and the doughnuts agree. verdict is
// generate_stats.py's VERDICT_RANK read backwards — least evidence first:
// never attempted, then confirmed broken, then unknown, then working. One
// ranking of the same vocabulary for the whole repo, not a competing one.
const SORT_RANK = {
  severity: LEVEL_ORDER,
  status: ['stable', 'test', 'experimental', 'deprecated', 'unsupported'],
  verdict: ['na', 'fail', 'notverified', 'pass'],
};

function rankOf(col, val) {
  const order = SORT_RANK[col];
  const i = order.indexOf(normKey(val));
  return i < 0 ? order.length : i;
}

function renderTable() {
  const q = document.getElementById('search-input').value;
  let filtered = RULES.filter(r => matchesFilters(r) && matchesSearch(r, q));

  filtered.sort((a, b) => {
    let cmp;
    if (SORT_RANK[sortCol]) {
      cmp = rankOf(sortCol, a[sortCol]) - rankOf(sortCol, b[sortCol]);
      // Within a rank the rows would otherwise keep whatever order the
      // previous sort left them in, which makes the table look unstable
      // while you flip between columns. Fall back to the rule ID.
      if (cmp === 0) cmp = String(a.id).localeCompare(String(b.id), undefined, { numeric: true });
    } else {
      let va, vb;
      if (sortCol === 'tactics' || sortCol === 'techniques') {
        va = (a[sortCol] && a[sortCol][0]) || '';
        vb = (b[sortCol] && b[sortCol][0]) || '';
      } else {
        va = String(a[sortCol] ?? '');
        vb = String(b[sortCol] ?? '');
      }
      cmp = va.localeCompare(vb, undefined, { numeric: true, sensitivity: 'base' });
    }
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

  tbody.style.opacity = '0.4';
  const fadeIn = () => requestAnimationFrame(() => requestAnimationFrame(() => { tbody.style.opacity = '1'; }));

  if (!filtered.length) {
    tbody.innerHTML = '';
    noRes.style.display = '';
    document.getElementById('result-count').textContent = '0 results';
    fadeIn();
    return;
  }

  noRes.style.display = 'none';
  document.getElementById('result-count').textContent = `${filtered.length} / ${RULES.length}`;

  tbody.innerHTML = filtered.map(r => {
    const globalIdx = RULES.indexOf(r);
    const ridColor = SOURCE_HEX[normKey(r.source)] || '#444c56';
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
  fadeIn();
}

// ── Rule body syntax highlight (Sigma YAML / SPL) ───────────────────────

const YAML_LIST_RX = /^(-\s+)(.*)$/;
const YAML_KV_RX = /^([A-Za-z0-9_.|-]+)(:)(\s*)(.*)$/;

function highlightYAMLValue(val) {
  if (!val) return '';
  if (val === '|' || val === '>') return `<span class="t-op">${escHtml(val)}</span>`;
  return `<span class="t-val">${escHtml(val)}</span>`;
}

// Sigma detection keys: top-level "detection" wrapper stays neutral, keys one
// level under it are selection/filter block names (red), a "field|modifier"
// key splits into field (green) + separator (amber) + modifier (blue).
function highlightYAMLKey(key, indent) {
  if (key === 'detection') return `<span class="t-id">${escHtml(key)}</span>`;
  if (key.includes('|')) {
    const i = key.indexOf('|');
    const field = key.slice(0, i);
    const mod = key.slice(i + 1);
    return `<span class="t-fld">${escHtml(field)}</span><span class="t-pipe">|</span><span class="t-mod">${escHtml(mod)}</span>`;
  }
  if (indent.length <= 2) return `<span class="t-sel">${escHtml(key)}</span>`;
  return `<span class="t-fld">${escHtml(key)}</span>`;
}

function highlightYAML(code) {
  // "condition" is conventionally the last key in a sigma detection block,
  // and its boolean expression can wrap onto following lines with no key
  // of its own — so once we see it, treat the remainder as its expression.
  let inCondition = false;
  return code.split('\n').map(line => {
    const indentM = line.match(/^\s*/);
    const indent = indentM[0];
    let rest = line.slice(indent.length);
    if (!rest) return line;

    if (inCondition) return indent + `<span class="t-cond">${escHtml(rest)}</span>`;

    if (rest.startsWith('#')) return indent + `<span class="t-com">${escHtml(rest)}</span>`;

    let prefix = '';
    const listM = rest.match(YAML_LIST_RX);
    if (listM) { prefix = `<span class="t-op">-</span> `; rest = listM[2]; }
    else if (rest === '-') { return indent + `<span class="t-op">-</span>`; }

    const kv = rest.match(YAML_KV_RX);
    if (kv) {
      const [, key, , sp, val] = kv;
      if (key === 'condition') {
        inCondition = true;
        return indent + prefix + `<span class="t-cond">${escHtml(key)}</span><span class="t-op">:</span>${sp}<span class="t-cond">${escHtml(val)}</span>`;
      }
      return indent + prefix + highlightYAMLKey(key, indent) + `<span class="t-op">:</span>${sp}${highlightYAMLValue(val)}`;
    }
    return indent + prefix + `<span class="t-val">${escHtml(rest)}</span>`;
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

  // Everything from the first top-level pipe onward (the reporting/
  // transforming stage, e.g. "| table ...") renders as one red block —
  // comments stay distinct, whitespace is untouched.
  let afterPipe = false;
  const isOperatorTok = (tok) => tok && (tok.k === 'op' || SPL_OPERATOR_WORDS.has(tok.t.toLowerCase()));
  let prevSig = null; // last non-whitespace token, for detecting values right after an operator

  let out = '';
  toks.forEach((tok, i) => {
    const { k, t } = tok;
    if (k === 'ws') { out += t; return; }
    if (k === 'comment') { prevSig = tok; out += `<span class="t-com">${escHtml(t)}</span>`; return; }
    if (k === 'pipe') { afterPipe = true; prevSig = tok; out += `<span class="t-kw">${escHtml(t)}</span>`; return; }
    if (afterPipe) { out += `<span class="t-kw">${escHtml(t)}</span>`; return; }

    if (k === 'string') { prevSig = tok; out += `<span class="t-val">${escHtml(t)}</span>`; return; }
    if (k === 'num') { prevSig = tok; out += `<span class="t-val">${escHtml(t)}</span>`; return; }
    if (k === 'op') { prevSig = tok; out += `<span class="t-mod">${escHtml(t)}</span>`; return; }
    if (k === 'punct') { prevSig = tok; out += escHtml(t); return; }

    const lower = t.toLowerCase();
    const n1 = nextN(i, 1);
    // A bare identifier immediately followed by a comparison/membership
    // operator (=, !=, IN, LIKE…) is a field reference — green, like a
    // Sigma field name — regardless of whether it's also an SPL keyword
    // (e.g. "index=", "sourcetype=" use the keyword name as a field).
    const isFieldRef = isOperatorTok(n1);
    // A bare (unquoted) identifier right after such an operator is its
    // value — same white as a quoted string value.
    const isValueRef = isOperatorTok(prevSig);
    let cls;
    if (isFieldRef) cls = 't-fld';
    else if (isValueRef) cls = 't-val';
    else if (SPL_OPERATOR_WORDS.has(lower)) cls = 't-mod';
    else if (SPL_KEYWORDS.has(lower)) cls = 't-kw';
    else if (SPL_FUNCS.has(lower) && n1 && n1.t === '(') cls = 't-fn';
    else cls = 't-id';
    prevSig = tok;
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
    `<span class="badge badge-source-${normKey(r.source)}">${escHtml(r.source)}</span>`,
    r.category ? `<span class="badge badge-category">${escHtml(r.category)}</span>` : '',
    r.product ? `<span class="badge badge-product">${escHtml(r.product)}</span>` : '',
    r.service ? `<span class="badge badge-service">${escHtml(r.service)}</span>` : '',
    r.severity ? sevBadge(r) : '',
    r.status ? statusBadge(r) : '',
    `<span class="badge verdict-${normKey(r.verdict)}">${escHtml(vLabel(r.verdict))}</span>`,
  ].filter(Boolean);
  document.getElementById('d-badges').innerHTML = badges.join('');

  let body = '';

  if (r.description) {
    const paras = r.description.split(/\n+/).filter(Boolean).map(p => `<p>${escHtml(p.trim())}</p>`).join('');
    body += `<div><div class="drawer-section-label">Description</div><div class="drawer-desc">${paras}</div></div>`;
  }

  body += `<div>
      <div class="drawer-section-label">Metadata</div>
      <div class="meta-grid">
        <span class="meta-key">Rule ID</span><span class="meta-val">${escHtml(r.id)}</span>
        ${r.author ? `<span class="meta-key">Author</span><span class="meta-val">${escHtml(r.author)}</span>` : ''}
        ${r.date ? `<span class="meta-key">Created</span><span class="meta-val">${escHtml(r.date)}</span>` : ''}
        ${r.modified ? `<span class="meta-key">Modified</span><span class="meta-val">${escHtml(r.modified)}</span>` : ''}
        ${r.ruleVersion ? `<span class="meta-key">Rule Version</span><span class="meta-val">${escHtml(r.ruleVersion)}</span>` : ''}
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

  if (r.references && r.references.length) {
    body += `<div>
        <div class="drawer-section-label">References</div>
        <div class="drawer-list">${r.references.map(ref => `<div class="drawer-list-item"><a href="${escHtml(ref)}" target="_blank">${escHtml(ref)}</a></div>`).join('')}</div>
      </div>`;
  }

  // Also render for a verdict with no run_id (a handful of older results have
  // a timestamp but no run to link to) — the age is worth showing on its own.
  if (r.runUrl || r.verdictAt) {
    const isFail = r.verdict === 'FAIL';
    const isNotVer = r.verdict === 'NOT_VERIFIED';
    const verifyCls = isFail ? 'verify-fail' : isNotVer ? 'verify-notver' : 'verify-pass';
    const icon = isFail
      ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>'
      : isNotVer
        ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="9"/><line x1="12" y1="8" x2="12" y2="13"/><line x1="12" y1="16" x2="12" y2="16.01"/></svg>'
        : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>';
    const cta = r.runUrl
      ? `<a class="drawer-cta ${verifyCls}" href="${escHtml(r.runUrl)}" target="_blank">
             ${icon} View Last Action Run — ${escHtml(vLabel(r.verdict))}
           </a>`
      : '';
    const meta = [];
    const age = verdictAge(r.verdictAt);
    if (age) {
      const due = isReviewDue(r);
      meta.push(`<span class="${due ? 'warn' : ''}">Tested ${escHtml(age)} · ${escHtml(r.verdictAt.slice(0, 10))}${due ? ` — past the ${REVIEW_INTERVAL_DAYS}-day review interval` : ''}</span>`);
    }
    // One sentence for the whole provenance of the verdict: by what means, on
    // which runner, against which version of the rule. Only the drift clause
    // is coloured — method and runner are not warnings, and painting the
    // whole line purple would say they were.
    if (r.verdictRuleVersion || r.verifyMethod) {
      const via = r.verifyMethod ? `Measured via ${escHtml(r.verifyMethod)}` : 'Measured';
      const on = r.verifyRunner ? ` on ${escHtml(r.verifyRunner)}` : '';
      // "against rule v1.3", not "on rule v1.3": the runner already claimed
      // the "on", and two of them in one clause read as a typo.
      const ver = r.verdictRuleVersion ? `, against rule v${escHtml(r.verdictRuleVersion)}` : '';
      const drifted = isVerdictSuperseded(r)
        ? `<span class="drift"> — but the rule is now v${escHtml(r.ruleVersion)}</span>`
        : '';
      meta.push(`<span>${via}${on}${ver}${drifted}</span>`);
    }
    // Said in words, not just carried by the marker in the table: the drawer
    // is where someone lands to find out why a rule reads NOT VERIFIED, and
    // "we chose not to test this" is a different answer from "the test did not
    // finish" -- the badge above is identical in both cases.
    if (isOutOfScope(r)) {
      meta.push('<span class="scoped">Out of testing scope — <code>custom.testing.enabled: false</code>,' +
        ' so the pipeline skipped this rule instead of measuring it. Not counted in the Pass Rate.</span>');
    }
    body += `<div>
        <div class="drawer-section-label">Verification</div>
        ${cta}
        ${meta.length ? `<div class="verify-meta">${meta.join('')}</div>` : ''}
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

  document.getElementById('d-body').innerHTML = body;
  document.getElementById('drawer-overlay').classList.add('open');
  document.getElementById('drawer').classList.add('open');
}

function closeDrawer() {
  document.getElementById('drawer-overlay').classList.remove('open');
  document.getElementById('drawer').classList.remove('open');
  // If this drawer was opened from a Navigator technique panel, reopen that
  // panel (with the same rule still highlighted) so the user lands back in
  // the rule list they were browsing rather than on a bare matrix.
  if (typeof navReopenAfterDrawer !== 'undefined' && navReopenAfterDrawer) {
    var ctx = navReopenAfterDrawer;
    navReopenAfterDrawer = null;
    openNavDetail(ctx.bid, ctx.name, ctx.rules, ctx.sel);
  }
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
  currentTab = (name === 'navigator' || name === 'dashboards') ? name : 'rules';
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === currentTab));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.toggle('active', p.id === 'tab-' + currentTab));
  if (currentTab === 'dashboards') {
    // Force a synchronous reflow before constructing the charts. The
    // `.active` class above switches this pane from display:none to
    // display:block in the same tick buildDashboardCharts() runs in, but
    // without an explicit layout read in between, Chart.js's own size
    // detection could still observe a stale (zero/previous) size on the
    // very first frame and only correct itself on a later async resize —
    // by which point its initial "created" animation has already played
    // out against the wrong dimensions. Reading offsetHeight forces the
    // browser to resolve layout immediately, so Chart.js always measures
    // the real, final size before its first paint.
    const dashPane = document.getElementById('tab-dashboards');
    if (dashPane) void dashPane.offsetHeight;
    // Defer the actual chart construction to after the browser's next
    // real paint. When the Dashboards tab is the one restored on initial
    // load (e.g. reloading a URL with #tab=dashboards, via the
    // applyState()/decodeState() call below), this whole function runs
    // synchronously during the page's initial <script> execution — i.e.
    // before the browser has painted anything at all yet. Chart.js's
    // animation progress is wall-clock-based, not frame-count-based, so
    // if a chart's "created" animation starts well before the first real
    // paint, a large chunk (or all) of its duration can silently elapse
    // while nothing is being rendered, and the very first frame the user
    // sees is already at (or very near) the final state — the reveal
    // never appears to animate. A double requestAnimationFrame guarantees
    // at least one real paint has already happened before the charts (and
    // their animation clocks) are created, on first load or later clicks
    // alike.
    requestAnimationFrame(() => requestAnimationFrame(() => buildDashboardCharts()));
    requestAnimationFrame(() => requestAnimationFrame(() => syncDepTraceAnimations()));
  }
  if (!opts.skipHash) updateHash();
}

// The deployment table's live/behind dots are separate CSS animations on
// separate elements -- equal duration is not equal phase. Each one starts
// counting from whenever the browser first computed its style, which for a
// pane that was just switched from display:none can differ element to
// element by more than a frame, so two dots with the same 1.6s period can
// still land visibly out of step forever. Pinning every dot's Web
// Animations API startTime to 0 forces them onto the same clock, so the
// whole legend (and the per-rule table's dots) beat together. Re-run every
// time the tab is shown, since display:none restarts each animation's
// clock from zero the next time it becomes visible.
function syncDepTraceAnimations() {
  document.querySelectorAll('.dep-trace').forEach(el => {
    el.getAnimations().forEach(anim => { anim.startTime = 0; });
  });
}

document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => setActiveTab(btn.dataset.tab));
});

// ── Legend & help dialog ───────────────────────────────────────────────
// Lives outside the tab panes, so one dialog serves all three tabs.

function isInfoOpen() {
  return document.getElementById('info-modal')?.classList.contains('open');
}

function setInfo(open) {
  document.getElementById('info-modal')?.classList.toggle('open', open);
  document.getElementById('info-backdrop')?.classList.toggle('open', open);
  const btn = document.getElementById('info-btn');
  if (btn) {
    btn.classList.toggle('active', open);
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
  }
  // Move focus into the dialog and hand it back on close, so Escape and the
  // close button are reachable without a mouse.
  if (open) document.querySelector('.info-close')?.focus();
  else btn?.focus();
}

function openInfo() { setInfo(true); }
function closeInfo() { setInfo(false); }
function toggleInfo() { setInfo(!isInfoOpen()); }

// Registered ahead of the Rule Library key handler below, so while the dialog
// is open Escape closes it and nothing else — the row drawer underneath stays
// put instead of being closed by the same keystroke.
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && isInfoOpen()) {
    e.stopImmediatePropagation();
    closeInfo();
  }
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
  // Deep-link the open Navigator technique panel so the view is shareable.
  if (currentTab === 'navigator' && typeof navOpenDetailId !== 'undefined' && navOpenDetailId) {
    parts.push('tech=' + encodeURIComponent(navOpenDetailId));
  }
  // The Navigator's own narrowing (verdict filters, Covered/Gaps scope,
  // technique search) rides along too, so "here is the gap list" is a link and
  // not an instruction. Emitted regardless of the active tab, like the table
  // filters above, so switching tabs doesn't silently drop the state.
  if (typeof navActiveFilters !== 'undefined' && navActiveFilters && navActiveFilters.size) {
    parts.push('navv=' + Array.from(navActiveFilters).join(','));
  }
  if (typeof navScope !== 'undefined' && navScope) parts.push('navs=' + navScope);
  if (typeof navSearchText !== 'undefined' && navSearchText) {
    parts.push('navq=' + encodeURIComponent(navSearchText));
  }
  return parts.join('&');
}

function decodeState(hash) {
  const raw = (hash || '').replace(/^#/, '');
  const state = {
    tab: 'rules', filters: {}, q: '', sortCol: 'id', sortAsc: true, tech: '',
    navFilters: [], navScope: '', navQ: '',
  };
  if (!raw) return state;
  const validKeys = new Set(FILTER_FIELDS.map(f => f.key));
  raw.split('&').forEach(pair => {
    const eq = pair.indexOf('=');
    if (eq < 0) return;
    const key = pair.slice(0, eq);
    const val = pair.slice(eq + 1);
    if (key === 'tab') {
      state.tab = (val === 'navigator' || val === 'dashboards') ? val : 'rules';
    } else if (key === 'q') {
      state.q = decodeURIComponent(val);
    } else if (key === 'tech') {
      state.tech = decodeURIComponent(val);
    } else if (key === 'sort') {
      const [col, dir] = val.split(':');
      if (col) { state.sortCol = col; state.sortAsc = dir !== 'desc'; }
    } else if (key === 'navv') {
      // Only the four verdicts the dropdown can toggle: an old link carrying
      // the retired 'uncov' filter would otherwise leave the matrix in a state
      // no visible control can undo (coverage now lives on Covered/Gaps).
      const okVerdicts = new Set(['pass', 'notver', 'fail', 'nv']);
      state.navFilters = val.split(',').filter(v => okVerdicts.has(v));
    } else if (key === 'navs') {
      state.navScope = (val === 'covered' || val === 'gaps') ? val : '';
    } else if (key === 'navq') {
      state.navQ = decodeURIComponent(val);
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
  // Narrow the matrix first, then open any deep-linked technique panel on top
  // of the restored view.
  if (typeof applyNavState === 'function') applyNavState(state);
  // Restore a deep-linked Navigator technique panel (if any).
  if (typeof openNavByTid === 'function') {
    if (state.tab === 'navigator' && state.tech) {
      if (typeof navOpenDetailId === 'undefined' || navOpenDetailId !== state.tech) openNavByTid(state.tech);
    } else if (typeof navOpenDetailId !== 'undefined' && navOpenDetailId && typeof closeNavDetail === 'function') {
      closeNavDetail();
    }
  }
}

function updateHash() {
  const enc = encodeState();
  const url = `${location.pathname}${location.search}#${enc}`;
  try { history.replaceState(null, '', url); } catch (e) { /* sandboxed preview, no real origin */ }
}

window.addEventListener('hashchange', () => {
  applyState(decodeState(location.hash));
});

// ── Export ───────────────────────────────────────────────────────────────

function toggleExportMenu(e) {
  e.stopPropagation();
  document.getElementById('export-menu').classList.toggle('open');
}

document.addEventListener('click', () => {
  document.getElementById('export-menu')?.classList.remove('open');
  document.getElementById('nav-export-menu')?.classList.remove('open');
  document.getElementById('nav-verdict-menu')?.classList.remove('open');
});

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
    'Last Tested': r.verdictAt ? r.verdictAt.slice(0, 10) : '',
    'Rule Version': r.ruleVersion,
    'Tested Version': r.verdictRuleVersion,
    // Replaces the former 'Review Status' + 'Verdict Sync' pair: one column
    // with Current / Superseded / Expired / Out of scope / Never tested,
    // matching the facet.
    'Evidence': r.evidence || '',
    'Verification Method': r.verifyMethod,
    'Verification Runner': r.verifyRunner,
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
document.querySelectorAll('.tc[data-rules]').forEach(function (el) {
  el.addEventListener('mouseenter', function () {
    var rules = JSON.parse(el.dataset.rules);
    var html = '<div class="tip-head">' + el.dataset.id + '</div>';
    rules.forEach(function (r) {
      var vc = r.verdict === 'N/A' ? 'NA' : r.verdict;
      var badge = '<span class="tip-vbadge ' + vc + '">' + vLabel(r.verdict) + '</span>';
      if (r.url) {
        html += '<a class="tip-rule" href="' + r.url + '" target="_blank">' + badge + ' ' + r.id + ': ' + r.title + '</a>';
      } else {
        html += '<div class="tip-rule">' + badge + ' ' + r.id + ': ' + r.title + '</div>';
      }
    });
    navTip.innerHTML = html;
    navTip.style.display = 'block';
  });
  el.addEventListener('mousemove', function (e) {
    var x = e.clientX + 14, y = e.clientY + 14;
    if (x + 350 > window.innerWidth) x = e.clientX - 354;
    navTip.style.left = x + 'px';
    navTip.style.top = y + 'px';
  });
  el.addEventListener('mouseleave', function () { navTip.style.display = 'none'; });
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
    subs.forEach(function (s) { s.style.display = 'flex'; grp.appendChild(s); });
  } else {
    parentTc.classList.remove('expanded');
    var grp = btn._subGrp;
    if (grp) {
      subs.forEach(function (s) { s.style.display = 'none'; grp.before(s); });
      grp.remove();
      btn._subGrp = null;
    }
  }
}
// Expand/collapse sub-techniques — scoped to column, grp stored on button
document.querySelectorAll('.tc-expand').forEach(function (btn) {
  btn.addEventListener('click', function (e) {
    e.stopPropagation();
    navDoExpand(btn, !btn.classList.contains('open'));
  });
});
// Sticky mirror scrollbar
(function () {
  var matrix = document.querySelector('.att-matrix');
  if (!matrix) return;
  var mirror = document.createElement('div');
  mirror.className = 'nav-scroll-mirror';
  mirror.style.cssText = 'overflow-x:auto;position:sticky;bottom:0;height:14px;background:#0d1117;z-index:100;';
  var inner = document.createElement('div');
  inner.style.height = '1px';
  mirror.appendChild(inner);
  matrix.parentNode.insertBefore(mirror, matrix.nextSibling);
  function syncWidth() { inner.style.width = matrix.scrollWidth + 'px'; }
  syncWidth();
  var syncing = false;
  matrix.addEventListener('scroll', function () {
    if (syncing) return; syncing = true; mirror.scrollLeft = matrix.scrollLeft; syncing = false;
  });
  mirror.addEventListener('scroll', function () {
    if (syncing) return; syncing = true; matrix.scrollLeft = mirror.scrollLeft; syncing = false;
  });
  if (window.ResizeObserver) { new ResizeObserver(syncWidth).observe(matrix); }
})();
// Combined Navigator visibility: legend verdict filters + Covered/Gaps scope
// + technique search all narrow the same matrix.
var navActiveFilters = new Set();
var navScope = null;          // 'covered' | 'gaps' | null
var navSearchText = '';
var navAutoExpanded = new Set();
function tcVerdict(tc) {
  if (tc.classList.contains('pass')) return 'pass';
  if (tc.classList.contains('notver')) return 'notver';
  if (tc.classList.contains('fail')) return 'fail';
  if (tc.classList.contains('nv')) return 'nv';
  return 'uncov';
}
function tcIsCovered(tc) { return tcVerdict(tc) !== 'uncov'; }
// A cell counts as FAIL for filtering whenever ANY covering rule failed — not
// only when FAIL won the best-verdict roll-up. Without this the FAIL filter is
// dead for every technique that also has a passing rule.
function tcHasFail(tc) {
  return tc.classList.contains('fail') || tc.classList.contains('fail-flag');
}
function tcText(tc) {
  var tn = tc.querySelector('.tn');
  return ((tc.dataset.id || '') + ' ' + (tn ? tn.textContent : '')).toLowerCase();
}
function tcMatches(tc) {
  var okLegend = navActiveFilters.size === 0
    || navActiveFilters.has(tcVerdict(tc))
    || (navActiveFilters.has('fail') && tcHasFail(tc));
  var okScope = !navScope || (navScope === 'covered' ? tcIsCovered(tc) : !tcIsCovered(tc));
  var okSearch = !navSearchText || tcText(tc).indexOf(navSearchText) >= 0;
  return okLegend && okScope && okSearch;
}
function applyNavVisibility() {
  // Filtering for FAIL is a "show me what's broken" request, and what's broken
  // is usually a sub-technique — collapsed by default, so the answer would be
  // one click away on every parent. Expand those automatically, exactly like a
  // search that only matches sub-techniques does.
  var failFocus = navActiveFilters.has('fail');
  // Drop auto-expands once neither driver is active any more.
  if (!navSearchText && !failFocus && navAutoExpanded.size) {
    navAutoExpanded.forEach(function (b) { if (b.classList.contains('open')) navDoExpand(b, false); });
    navAutoExpanded.clear();
  }
  var active = navActiveFilters.size > 0 || !!navScope || !!navSearchText;
  var shown = 0;
  document.querySelectorAll('.tc-col').forEach(function (col) {
    var colVisible = 0;
    col.querySelectorAll('.tc:not(.sub)').forEach(function (parentTc) {
      var tid = parentTc.dataset.id;
      if (!tid) return;
      var subs = Array.from(col.querySelectorAll('.tc.sub[data-id^="' + tid + '."]'));
      var pMatch = tcMatches(parentTc);
      var subMatches = subs.filter(tcMatches);
      var show = pMatch || subMatches.length > 0;
      parentTc.classList.toggle('tc-hidden', !show);
      subs.forEach(function (s) { s.classList.toggle('tc-hidden', !tcMatches(s)); });
      var exBtn = parentTc.querySelector('.tc-expand');
      if (!show) {
        // Collapse hidden parents so no orphan sub-group frame is left behind.
        if (exBtn && exBtn.classList.contains('open')) { navDoExpand(exBtn, false); navAutoExpanded.delete(exBtn); }
      } else {
        colVisible++;
        shown++;
        // Reveal sub-techniques the user is implicitly asking about: a search
        // that only matched below the parent, or a failing sub under a FAIL
        // filter. The fail case is scoped to subs that actually carry the flag
        // so a combined PASS+FAIL filter doesn't expand the whole matrix.
        var revealSubs = (navSearchText && !pMatch)
          || (failFocus && subMatches.some(tcHasFail));
        if (exBtn && revealSubs && subMatches.length > 0 && !exBtn.classList.contains('open')) {
          navDoExpand(exBtn, true);
          navAutoExpanded.add(exBtn);
        }
      }
    });
    // Hide whole columns that have no visible techniques under an active filter.
    col.classList.toggle('tc-col-hidden', active && colVisible === 0);
  });
  // With every column hidden the matrix collapses to a few pixels of nothing,
  // and the only feedback left is the small count in the toolbar. Swap in the
  // same empty state the rule table uses, plus a way back out.
  var wrap = document.querySelector('.nav-wrap');
  var empty = document.getElementById('nav-no-results');
  var isEmpty = active && shown === 0;
  if (wrap) wrap.classList.toggle('nav-empty', isEmpty);
  if (empty) empty.style.display = isEmpty ? 'block' : 'none';
  return shown;
}

// Reset every Navigator-side narrowing at once (verdict filters, scope,
// search) — reachable from the empty state, where nothing else is left to click.
function clearNavFilters() {
  navActiveFilters.clear();
  navScope = null;
  navSearchText = '';
  var inp = document.getElementById('nav-search');
  if (inp) inp.value = '';
  var clr = document.getElementById('nav-search-clear');
  if (clr) clr.classList.remove('show');
  document.querySelectorAll('.nav-verdict-item[data-filter]').forEach(function (item) {
    item.classList.remove('checked');
  });
  var cb = document.getElementById('nav-qf-covered');
  var gb = document.getElementById('nav-qf-gaps');
  if (cb) cb.classList.remove('active');
  if (gb) gb.classList.remove('active');
  refreshVerdictBtn();
  applyNavVisibility();
  var cnt = document.getElementById('nav-search-count');
  if (cnt) cnt.textContent = '';
  if (typeof updateHash === 'function') updateHash();
}
function computeNavLegendCounts() {
  var counts = { pass: 0, notver: 0, fail: 0, nv: 0, uncov: 0 };
  // Verdict counts partition the matrix (used for the coverage totals below);
  // failAny cross-cuts it — a PASS cell hiding a failed rule lands in both.
  var failAny = 0;
  document.querySelectorAll('.att-matrix .tc[data-id]').forEach(function (tc) {
    counts[tcVerdict(tc)]++;
    if (tcHasFail(tc)) failAny++;
  });
  Object.keys(counts).forEach(function (k) {
    var n = (k === 'fail') ? failAny : counts[k];
    var el = document.querySelector('.nav-legend-count[data-count="' + k + '"]');
    if (el) el.textContent = n;
    // Hide verdict rows that have no cells at all (e.g. N/A when every mapped
    // rule has been validated) so the dropdown only lists states in play.
    var item = el ? el.closest('.nav-verdict-item') : null;
    if (item) item.style.display = n === 0 ? 'none' : '';
  });
  // Coverage is a separate axis from verdict: the Covered/Gaps control owns it,
  // so its totals are rendered on the buttons rather than in the Verdict menu.
  var total = counts.pass + counts.notver + counts.fail + counts.nv + counts.uncov;
  var covEl = document.querySelector('.nav-qf-count[data-count="covered"]');
  var gapEl = document.querySelector('.nav-qf-count[data-count="uncov"]');
  if (covEl) covEl.textContent = total - counts.uncov;
  if (gapEl) gapEl.textContent = counts.uncov;
}
function refreshVerdictBtn() {
  var n = navActiveFilters.size;
  var lbl = document.getElementById('nav-verdict-active');
  var btn = document.getElementById('nav-verdict-btn');
  if (lbl) lbl.textContent = n ? '(' + n + ')' : '';
  if (btn) btn.classList.toggle('has-active', n > 0);
}
document.querySelectorAll('.nav-verdict-item[data-filter]').forEach(function (item) {
  item.addEventListener('click', function (e) {
    e.stopPropagation();
    var f = item.dataset.filter;
    if (navActiveFilters.has(f)) {
      navActiveFilters.delete(f);
      item.classList.remove('checked');
    } else {
      navActiveFilters.add(f);
      item.classList.add('checked');
    }
    refreshVerdictBtn();
    applyNavVisibility();
    if (typeof updateHash === 'function') updateHash();
  });
});
// Restore Navigator narrowing from a deep link (counterpart of encodeState).
function applyNavState(state) {
  navActiveFilters = new Set(state.navFilters || []);
  navScope = state.navScope || null;
  navSearchText = (state.navQ || '').trim().toLowerCase();
  document.querySelectorAll('.nav-verdict-item[data-filter]').forEach(function (item) {
    item.classList.toggle('checked', navActiveFilters.has(item.dataset.filter));
  });
  var cb = document.getElementById('nav-qf-covered');
  var gb = document.getElementById('nav-qf-gaps');
  if (cb) cb.classList.toggle('active', navScope === 'covered');
  if (gb) gb.classList.toggle('active', navScope === 'gaps');
  var inp = document.getElementById('nav-search');
  if (inp) inp.value = state.navQ || '';
  var clr = document.getElementById('nav-search-clear');
  if (clr) clr.classList.toggle('show', !!navSearchText);
  refreshVerdictBtn();
  var n = applyNavVisibility();
  var cnt = document.getElementById('nav-search-count');
  if (cnt) cnt.textContent = navSearchText ? (n + ' matching') : '';
}
function toggleVerdictMenu(e) {
  e.stopPropagation();
  document.getElementById('nav-export-menu').classList.remove('open');
  document.getElementById('nav-verdict-menu').classList.toggle('open');
}
// Covered / Gaps quick-scope toggles
function toggleNavScope(scope) {
  navScope = (navScope === scope) ? null : scope;
  var cb = document.getElementById('nav-qf-covered');
  var gb = document.getElementById('nav-qf-gaps');
  if (cb) cb.classList.toggle('active', navScope === 'covered');
  if (gb) gb.classList.toggle('active', navScope === 'gaps');
  applyNavVisibility();
  if (typeof updateHash === 'function') updateHash();
}
// Technique search
function onNavSearch() {
  var inp = document.getElementById('nav-search');
  navSearchText = (inp.value || '').trim().toLowerCase();
  document.getElementById('nav-search-clear').classList.toggle('show', !!navSearchText);
  var n = applyNavVisibility();
  var cnt = document.getElementById('nav-search-count');
  if (cnt) cnt.textContent = navSearchText ? (n + ' matching') : '';
  if (navSearchText) {
    var first = document.querySelector('.att-matrix .tc:not(.sub):not(.tc-hidden)[data-id]');
    if (first) first.scrollIntoView({ inline: 'center', block: 'nearest' });
  }
  if (typeof updateHash === 'function') updateHash();
}
function clearNavSearch() {
  var inp = document.getElementById('nav-search');
  inp.value = '';
  onNavSearch();
  inp.focus();
}
// Export the techniques currently shown (respects filters/search, not collapse)
function navViewRows() {
  var rows = [];
  var vmap = { pass: 'PASS', notver: 'NOT_VERIFIED', fail: 'FAIL', nv: 'N/A', uncov: 'Not covered' };
  document.querySelectorAll('.att-matrix .tc[data-id]:not(.tc-hidden)').forEach(function (tc) {
    var col = tc.closest('.tc-col');
    if (col && (col.classList.contains('collapsed') || col.classList.contains('tc-col-hidden'))) return;
    var tn = tc.querySelector('.tn');
    var ruleIds = '';
    if (tc.dataset.rules) {
      try { ruleIds = JSON.parse(tc.dataset.rules).map(function (r) { return r.id; }).join(' | '); } catch (e) { }
    }
    rows.push({
      Technique: tc.dataset.id,
      Name: tn ? tn.textContent : '',
      Tactic: col ? (col.dataset.tactic || '') : '',
      Coverage: vmap[tcVerdict(tc)],
      // Same roll-up caveat as the matrix cell: Coverage can read PASS while a
      // covering rule failed, so the failure is exported as its own column.
      HasFailingRule: tcHasFail(tc) ? 'yes' : 'no',
      Rules: ruleIds,
    });
  });
  return rows;
}
function navToMarkdown(rows) {
  var cols = ['Technique', 'Name', 'Tactic', 'Coverage', 'HasFailingRule', 'Rules'];
  var esc = function (v) { return String(v == null ? '' : v).replace(/\|/g, '\\|'); };
  var head = '| ' + cols.join(' | ') + ' |';
  var sep = '| ' + cols.map(function () { return '---'; }).join(' | ') + ' |';
  var body = rows.map(function (r) { return '| ' + cols.map(function (c) { return esc(r[c]); }).join(' | ') + ' |'; });
  return ['# MITRE ATT&CK Navigator — Current View', '', '**Exported:** ' + todayStamp() + '  ', '**Techniques:** ' + rows.length, '', head, sep].concat(body).join('\n');
}
function toggleNavExportMenu(e) {
  e.stopPropagation();
  document.getElementById('nav-verdict-menu').classList.remove('open');
  var cnt = document.getElementById('nav-export-count');
  if (cnt) cnt.textContent = navViewRows().length;
  document.getElementById('nav-export-menu').classList.toggle('open');
}
function exportNavView(format) {
  document.getElementById('nav-export-menu').classList.remove('open');
  var rows = navViewRows();
  if (!rows.length) { alert('Nothing to export in the current view.'); return; }
  var stamp = todayStamp();
  if (format === 'json') {
    var payload = { exportedAt: new Date().toISOString(), count: rows.length, techniques: rows };
    downloadFile(JSON.stringify(payload, null, 2), 'navigator_view_' + stamp + '.json', 'application/json');
  } else if (format === 'md') {
    downloadFile(navToMarkdown(rows), 'navigator_view_' + stamp + '.md', 'text/markdown;charset=utf-8');
  } else {
    downloadFile(toCSV(rows), 'navigator_view_' + stamp + '.csv', 'text/csv;charset=utf-8');
  }
}
// Tactic column collapse/expand
document.querySelectorAll('.tc-col-toggle').forEach(function (btn) {
  btn.addEventListener('click', function (e) {
    e.stopPropagation();
    e.preventDefault();
    var col = btn.closest('.tc-col');
    var collapsed = col.classList.toggle('collapsed');
    btn.innerHTML = collapsed ? '&#9656;' : '&#9662;';
    btn.title = collapsed ? 'Expand column' : 'Collapse column';
  });
});
// Open a technique panel by ID (used by deep-link on load)
function openNavByTid(tid) {
  var btn = document.querySelector('.tc-detail[data-id="' + tid + '"]');
  if (!btn) return;
  openNavDetail(btn.dataset.id, btn.dataset.name, JSON.parse(btn.dataset.rules), -1);
  var cell = document.querySelector('.tc[data-id="' + tid + '"]');
  if (cell) cell.scrollIntoView({ inline: 'center', block: 'nearest' });
}
computeNavLegendCounts();
// Expand All / Collapse All button
(function () {
  var btn = document.getElementById('expand-all-btn');
  if (!btn) return;
  var expanded = false;
  btn.addEventListener('click', function () {
    expanded = !expanded;
    btn.innerHTML = expanded ? '&#9650; Collapse All' : '&#9660; Expand All';
    document.querySelectorAll('.tc-expand').forEach(function (exBtn) {
      var parentTc = exBtn.closest('.tc');
      if (parentTc.classList.contains('tc-hidden')) return;
      var isOpen = exBtn.classList.contains('open');
      if (expanded && !isOpen) navDoExpand(exBtn, true);
      else if (!expanded && isOpen) navDoExpand(exBtn, false);
    });
  });
})();
// Cross-highlight: click on cell body highlights all cells with same data-id
var navHighlightedId = null;
document.querySelectorAll('.tc').forEach(function (tc) {
  tc.addEventListener('click', function (e) {
    if (e.target.closest('.ti') || e.target.closest('.tc-expand') || e.target.closest('.tc-detail')) return;
    var tid = tc.dataset.id;
    if (!tid) return;
    if (navHighlightedId === tid) {
      navHighlightedId = null;
      document.querySelectorAll('.tc.highlighted').forEach(function (el) { el.classList.remove('highlighted'); });
    } else {
      navHighlightedId = tid;
      document.querySelectorAll('.tc.highlighted').forEach(function (el) { el.classList.remove('highlighted'); });
      document.querySelectorAll('.tc[data-id="' + tid + '"]').forEach(function (el) { el.classList.add('highlighted'); });
    }
  });
});
// Detail navPanel — toggle on same button, switch on different
var navPanel = document.getElementById('detail-panel');
var navPanelTitle = document.getElementById('detail-title');
var navPanelTid = document.getElementById('detail-tid');
var navPanelBody = document.getElementById('detail-body');
var navOpenDetailId = null;
// Current technique panel context: { bid, name, rules, sel } — sel is the
// index of the arrow-key-highlighted rule (-1 = none). navReopenAfterDrawer
// carries the same shape so closeDrawer() can restore the panel afterwards.
var navDetail = null;
var navReopenAfterDrawer = null;

function navPaintDetailSel() {
  if (!navDetail) return;
  var rows = navPanelBody.querySelectorAll('.detail-rule[data-idx]');
  rows.forEach(function (row, i) {
    var on = i === navDetail.sel;
    row.classList.toggle('sel', on);
    if (on) row.scrollIntoView({ block: 'nearest' });
  });
}

function navMoveDetailSel(delta) {
  if (!navDetail) return;
  var rows = navPanelBody.querySelectorAll('.detail-rule[data-idx]');
  if (!rows.length) return;
  if (navDetail.sel < 0) navDetail.sel = delta > 0 ? 0 : rows.length - 1;
  else navDetail.sel = Math.min(rows.length - 1, Math.max(0, navDetail.sel + delta));
  navPaintDetailSel();
}

function navOpenSelectedRule() {
  if (!navDetail) return;
  var rows = navPanelBody.querySelectorAll('.detail-rule[data-idx]');
  var row = rows[navDetail.sel];
  if (!row) return;
  // Remember where we came from so closing the drawer reopens this panel.
  navReopenAfterDrawer = { bid: navDetail.bid, name: navDetail.name, rules: navDetail.rules, sel: navDetail.sel };
  navPanel.classList.remove('open');
  openDrawer(parseInt(row.dataset.idx, 10));
}

function openNavDetail(bid, name, rules, selIdx) {
  navOpenDetailId = bid;
  navDetail = { bid: bid, name: name, rules: rules, sel: (selIdx == null ? -1 : selIdx) };
  navPanelTitle.textContent = name;
  navPanelTid.textContent = bid;
  if (typeof updateHash === 'function') updateHash();
  var html = '';
  rules.forEach(function (r) {
    var vc = r.verdict === 'N/A' ? 'NA' : r.verdict;
    var badge = '<span class="detail-vbadge ' + vc + '">' + vLabel(r.verdict) + '</span>';
    var label = escHtml(r.id + ': ' + r.title);
    var idx = RULE_IDX_BY_ID[r.id];
    if (idx !== undefined) {
      html += '<div class="detail-rule" data-idx="' + idx + '" role="button" tabindex="0">' + badge + label + '</div>';
    } else {
      html += '<div class="detail-noverd">' + badge + label + '</div>';
    }
  });
  navPanelBody.innerHTML = html;
  // Clicking a rule opens the shared Rule Library drawer (not a new page).
  navPanelBody.querySelectorAll('.detail-rule[data-idx]').forEach(function (el, i) {
    el.addEventListener('click', function () { navDetail.sel = i; navOpenSelectedRule(); });
    el.addEventListener('mouseenter', function () { navDetail.sel = i; navPaintDetailSel(); });
  });
  navPanel.classList.add('open');
  navPaintDetailSel();
}

function closeNavDetail() {
  navPanel.classList.remove('open');
  navOpenDetailId = null;
  navDetail = null;
  navReopenAfterDrawer = null;
  if (typeof updateHash === 'function') updateHash();
}

document.getElementById('detail-close').addEventListener('click', closeNavDetail);

document.querySelectorAll('.tc-detail').forEach(function (btn) {
  btn.addEventListener('click', function (e) {
    e.stopPropagation();
    var bid = btn.dataset.id;
    if (navPanel.classList.contains('open') && navOpenDetailId === bid) {
      closeNavDetail();
      return;
    }
    openNavDetail(bid, btn.dataset.name, JSON.parse(btn.dataset.rules), -1);
  });
});

// Arrow-key navigation for the Navigator technique panel: Up/Down move
// between the listed rules, Enter opens the highlighted one, Escape closes.
// While a rule drawer is open (opened from here), Escape closes it — which
// reopens this panel via closeDrawer().
document.addEventListener('keydown', function (e) {
  if (currentTab !== 'navigator') return;
  var el = document.activeElement;
  if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA')) return;
  if (isDrawerOpen()) {
    if (e.key === 'Escape') { e.preventDefault(); closeDrawer(); }
    return;
  }
  if (!navPanel.classList.contains('open')) return;
  switch (e.key) {
    case 'ArrowDown': e.preventDefault(); navMoveDetailSel(1); break;
    case 'ArrowUp': e.preventDefault(); navMoveDetailSel(-1); break;
    case 'Enter':
      e.preventDefault();
      if (navDetail && navDetail.sel < 0) navMoveDetailSel(1);
      navOpenSelectedRule();
      break;
    case 'Escape': e.preventDefault(); closeNavDetail(); break;
  }
});


renderStripTotal();
applyState(decodeState(location.hash));
initResizableColumns();
