#!/usr/bin/env node
'use strict';

/**
 * Headless smoke test for the generated rule browser (docs/index.html).
 *
 * Register item 4.7: Playwright verification of this page was previously
 * manual, one-off and left no trace -- nothing caught a regression like an
 * unreplaced `@@MARKER@@` placeholder (the 2026-08-10 incident), a chart
 * that silently fails to render, or a row count that has drifted from the
 * real rule count. This script is the automatable version of that manual
 * check, meant to run as a CI step (see "Invocation contract" below).
 *
 * What it checks, in order:
 *   1. Raw file        -- docs/index.html has no leftover literal
 *                          `@@MARKER@@`-shaped placeholder text anywhere in
 *                          the file. Cheap, and pinpoints exactly which
 *                          marker failed to substitute (the actual failure
 *                          mode from the 2026-08-10 incident).
 *   2. Page load        -- the page navigates and finishes loading without
 *                          the browser throwing (a bad navigation, a fatal
 *                          script error before first paint, etc).
 *   3. Console/page errors -- zero console.error() calls and zero uncaught
 *                          exceptions (`pageerror`) for the whole session,
 *                          including after switching tabs.
 *   4. Rule row count   -- the number of `<tr>` rows actually rendered in
 *                          the Rule Library table matches the real rule
 *                          count from THREE independent sources that must
 *                          all agree: outputs/reports/stats.json's
 *                          `total_rules` (the generator's own source of
 *                          truth, on disk), the page's own in-browser
 *                          `RULES` array length (a page-scoped `const`, read
 *                          by identifier, not `window.RULES`), and the
 *                          `#result-count` summary text the page renders
 *                          for the user.
 *   5. The two rings     -- the Dashboards tab's Evidence and Verification
 *                          doughnuts (the two charts the page's own Info
 *                          panel copy calls "two rings" -- see the
 *                          info-note beginning "Evidence and Verification
 *                          are two rings" in page.template.html) both
 *                          construct as real Chart.js instances and are
 *                          plotting a non-empty dataset, not just present
 *                          as blank canvases.
 *
 * Invocation contract (for CI):
 *   node scripts/docs/smoke_test_rule_browser.js [options]
 *
 *   Options:
 *     --docs-dir <path>   Directory containing index.html to serve.
 *                          Default: <repo root>/docs
 *     --stats <path>      stats.json to read the real rule count from.
 *                          Default: <repo root>/outputs/reports/stats.json
 *     --port <n>           Port for the local static server. Default: 0
 *                          (OS-assigned ephemeral port).
 *     --timeout-ms <n>     Timeout for page load / chart-render waits.
 *                          Default: 15000.
 *
 *   Exit codes:
 *     0  -- every check passed.
 *     1  -- at least one check failed, OR the script itself errored out
 *           (missing files, browser launch failure, navigation timeout,
 *           etc). Both cases are a CI failure; the printed output
 *           distinguishes them.
 *
 *   Output contract: one line per check, prefixed "PASS" or "FAIL", to
 *   stdout as it runs, followed by a "SMOKE TEST: PASSED"/"SMOKE TEST:
 *   FAILED (n/total checks failed)" summary line as the last line of
 *   output. A failed run prints the concrete mismatch (which marker,
 *   which counts disagreed, which console messages) inline under its
 *   "FAIL" line -- nothing needs to be re-run with extra flags to see why
 *   it failed.
 *
 * Dependencies: the `playwright` npm package plus a downloaded Chromium
 * (`npx playwright install --with-deps chromium`). Deliberately not added
 * to the Python toolchain (.github/requirements*.txt) -- this is the one
 * piece of this repo's CI that needs a real browser, and ci_code_checks.yml
 * already provisions Node.js for the page.js syntax-check step, so a
 * Node-based smoke test reuses infrastructure that is already there rather
 * than adding a second one.
 */

const fs = require('fs');
const http = require('http');
const path = require('path');
const { chromium } = require('playwright');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
// Deliberately tolerant of whitespace before the closing `@@`: the
// 2026-08-10 incident's actual failure mode was a stray space inside the
// marker in the *asset* file (e.g. `@@INLINE_JS @@`), which made
// generate_stats.py's exact-string `.replace("@@INLINE_JS@@", ...)` no-op --
// so the text that actually ships in that failure mode is the
// space-containing form, not the clean one. A regex that only matched
// `@@[A-Z_]+@@` (no internal space) would miss exactly the bug this check
// exists to catch.
const MARKER_RE = /@@[A-Z][A-Z0-9_]*\s*@@/g;

// The two charts page.template.html's own Info panel copy names as "two
// rings" (Evidence and Verification). See the module docstring above.
const RING_CHART_IDS = ['chart-evidence', 'chart-verify'];

function parseArgs(argv) {
  const opts = {
    docsDir: path.join(REPO_ROOT, 'docs'),
    statsPath: path.join(REPO_ROOT, 'outputs', 'reports', 'stats.json'),
    port: 0,
    timeoutMs: 15000,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--docs-dir') opts.docsDir = path.resolve(argv[++i]);
    else if (a === '--stats') opts.statsPath = path.resolve(argv[++i]);
    else if (a === '--port') opts.port = parseInt(argv[++i], 10);
    else if (a === '--timeout-ms') opts.timeoutMs = parseInt(argv[++i], 10);
    else if (a === '--help' || a === '-h') {
      console.log('Usage: node smoke_test_rule_browser.js [--docs-dir <path>] [--stats <path>] [--port <n>] [--timeout-ms <n>]');
      process.exit(0);
    } else {
      console.error(`FAIL  unknown argument: ${a}`);
      process.exit(1);
    }
  }
  return opts;
}

// Minimal static file server -- no extra runtime dependency, and serving
// over http:// rather than file:// is deliberately the default (matches
// GitHub Pages, and sidesteps the file:// restrictions some Playwright
// setups impose; see Sienna's own operating notes).
function serveDir(dir, port) {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      let reqPath = decodeURIComponent(req.url.split('?')[0]);
      if (reqPath === '/') reqPath = '/index.html';
      const filePath = path.join(dir, reqPath);
      if (!filePath.startsWith(dir)) {
        res.writeHead(403);
        res.end();
        return;
      }
      fs.readFile(filePath, (err, data) => {
        if (err) {
          res.writeHead(404);
          res.end();
          return;
        }
        const ext = path.extname(filePath);
        const types = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json' };
        res.writeHead(200, { 'Content-Type': types[ext] || 'application/octet-stream' });
        res.end(data);
      });
    });
    server.on('error', reject);
    server.listen(port, '127.0.0.1', () => resolve(server));
  });
}

function record(results, name, ok, detail) {
  const line = ok ? `PASS  ${name}` : `FAIL  ${name}`;
  console.log(line);
  if (!ok && detail) {
    String(detail).split('\n').forEach((l) => console.log(`      ${l}`));
  }
  results.push({ name, ok });
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const results = [];

  const indexPath = path.join(opts.docsDir, 'index.html');

  // ── Check 1: raw file has no leftover @@MARKER@@ placeholders ──────────
  let rawHtml;
  try {
    rawHtml = fs.readFileSync(indexPath, 'utf8');
  } catch (e) {
    console.log(`FAIL  index.html readable`);
    console.log(`      could not read ${indexPath}: ${e.message}`);
    console.log('SMOKE TEST: FAILED (could not read docs/index.html)');
    process.exit(1);
  }
  const leftoverMarkers = [...new Set(rawHtml.match(MARKER_RE) || [])];
  record(
    results,
    'no leftover @@MARKER@@ placeholders in docs/index.html',
    leftoverMarkers.length === 0,
    leftoverMarkers.length ? `unreplaced marker(s): ${leftoverMarkers.join(', ')}` : null,
  );

  // ── Real rule count, from the generator's own on-disk source of truth ──
  let statsTotalRules;
  try {
    const stats = JSON.parse(fs.readFileSync(opts.statsPath, 'utf8'));
    statsTotalRules = stats.total_rules;
    if (typeof statsTotalRules !== 'number') {
      throw new Error(`stats.json has no numeric "total_rules" (got ${JSON.stringify(statsTotalRules)})`);
    }
  } catch (e) {
    console.log('FAIL  stats.json readable with numeric total_rules');
    console.log(`      ${opts.statsPath}: ${e.message}`);
    console.log('SMOKE TEST: FAILED (could not read stats.json)');
    process.exit(1);
  }

  const server = await serveDir(opts.docsDir, opts.port);
  const actualPort = server.address().port;
  const baseUrl = `http://127.0.0.1:${actualPort}`;

  const consoleErrors = [];
  const pageErrors = [];
  let browser;
  try {
    browser = await chromium.launch();
    const page = await browser.newPage();
    page.on('console', (msg) => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    });
    page.on('pageerror', (err) => {
      pageErrors.push(err.message || String(err));
    });

    // ── Check 2: page loads without the browser throwing ─────────────────
    let loadOk = true;
    let loadDetail = null;
    try {
      await page.goto(`${baseUrl}/index.html`, { waitUntil: 'load', timeout: opts.timeoutMs });
    } catch (e) {
      loadOk = false;
      loadDetail = e.message;
    }
    record(results, 'page loads without throwing', loadOk, loadDetail);

    if (!loadOk) {
      // Nothing past this point can be checked meaningfully.
      await browser.close();
      server.close();
      const failed = results.filter((r) => !r.ok).length;
      console.log(`SMOKE TEST: FAILED (${failed}/${results.length} checks failed)`);
      process.exit(1);
    }

    // Give any synchronous startup script a moment to finish before reading
    // console/page error state for the "on load" portion of check 3.
    await page.waitForTimeout(200);

    // ── Check 4: rule row count agrees across three independent sources ──
    const tableState = await page.evaluate(() => {
      // RULES is declared `const RULES = ...` at the top of the page's
      // inline <script> -- a top-level lexical binding, not a `var`, so it
      // never becomes `window.RULES`. It is still directly readable by
      // identifier from any code sharing the page's global scope, which is
      // exactly where page.evaluate() runs.
      /* eslint-disable no-undef */
      const rulesLen = typeof RULES !== 'undefined' && Array.isArray(RULES) ? RULES.length : null;
      /* eslint-enable no-undef */
      const rows = document.querySelectorAll('#table-body tr[data-idx]').length;
      const resultCountText = (document.getElementById('result-count') || {}).textContent || '';
      return { rows, rulesLen, resultCountText };
    });

    const expectedResultCount = `${statsTotalRules} / ${statsTotalRules}`;
    const rowCountOk =
      tableState.rows === statsTotalRules &&
      tableState.rulesLen === statsTotalRules &&
      tableState.resultCountText.trim() === expectedResultCount;
    record(
      results,
      `rule row count matches stats.json total_rules (${statsTotalRules})`,
      rowCountOk,
      rowCountOk
        ? null
        : [
            `stats.json total_rules : ${statsTotalRules}`,
            `<tr> rows rendered      : ${tableState.rows}`,
            `window.RULES.length     : ${tableState.rulesLen}`,
            `#result-count text      : "${tableState.resultCountText.trim()}" (expected "${expectedResultCount}")`,
          ].join('\n'),
    );

    // ── Check 5: the two rings (Evidence, Verification) actually render ──
    let ringsOk = true;
    let ringsDetail = [];
    try {
      await page.click('.tab-btn[data-tab="dashboards"]');
      await page.waitForFunction(
        (ids) => window.Chart && ids.every((id) => !!window.Chart.getChart(id)),
        RING_CHART_IDS,
        { timeout: opts.timeoutMs },
      );
      const ringState = await page.evaluate((ids) => {
        return ids.map((id) => {
          const chart = window.Chart.getChart(id);
          const canvas = document.getElementById(id);
          const rect = canvas ? canvas.getBoundingClientRect() : null;
          const data = chart ? (chart.data.datasets[0] || {}).data || [] : [];
          const sum = data.reduce((a, b) => a + (Number(b) || 0), 0);
          return {
            id,
            exists: !!chart,
            visibleSize: rect ? rect.width > 0 && rect.height > 0 : false,
            dataSum: sum,
          };
        });
      }, RING_CHART_IDS);

      for (const r of ringState) {
        if (!r.exists) {
          ringsOk = false;
          ringsDetail.push(`${r.id}: no Chart.js instance found (Chart.getChart returned nothing)`);
        } else if (!r.visibleSize) {
          ringsOk = false;
          ringsDetail.push(`${r.id}: canvas has zero rendered size`);
        } else if (!(r.dataSum > 0)) {
          ringsOk = false;
          ringsDetail.push(`${r.id}: chart exists but its dataset sums to ${r.dataSum} (nothing plotted)`);
        }
      }
    } catch (e) {
      ringsOk = false;
      ringsDetail.push(e.message);
    }
    record(
      results,
      `both rings render (${RING_CHART_IDS.join(', ')})`,
      ringsOk,
      ringsOk ? null : ringsDetail.join('\n'),
    );

    // Let any deferred work from the tab switch (chart animation callbacks,
    // etc) finish before the final console/pageerror check.
    await page.waitForTimeout(300);

    // ── Check 3: no console errors or uncaught exceptions, page-load
    //             through tab switch ──────────────────────────────────────
    const noErrors = consoleErrors.length === 0 && pageErrors.length === 0;
    record(
      results,
      'no console errors or uncaught exceptions',
      noErrors,
      noErrors
        ? null
        : [...pageErrors.map((m) => `pageerror: ${m}`), ...consoleErrors.map((m) => `console.error: ${m}`)].join('\n'),
    );

    await browser.close();
  } catch (e) {
    if (browser) await browser.close().catch(() => {});
    server.close();
    console.log(`FAIL  script execution`);
    console.log(`      unexpected error: ${e.stack || e.message}`);
    console.log('SMOKE TEST: FAILED (script error)');
    process.exit(1);
  }

  server.close();

  const failed = results.filter((r) => !r.ok).length;
  if (failed === 0) {
    console.log('SMOKE TEST: PASSED');
    process.exit(0);
  } else {
    console.log(`SMOKE TEST: FAILED (${failed}/${results.length} checks failed)`);
    process.exit(1);
  }
}

main().catch((e) => {
  console.error('FAIL  script execution');
  console.error(`      unexpected error: ${e.stack || e.message}`);
  console.error('SMOKE TEST: FAILED (script error)');
  process.exit(1);
});
