// Runs AFTER the Navigator code sliced out of scripts/docs/assets/page.js.
// Everything the matrix does (filters, search, expand, column collapse,
// hover tooltip, export, cross-highlight) is that shared code, unchanged.
// This file only swaps what the detail panel shows -- a glossary entry
// instead of a rule list -- and makes every cell, covered or not, open it.
//
// openNavDetail() below deliberately re-declares the slice's function of the
// same name: it lives in a later <script>, so it replaces the global binding
// and the slice's own .tc-detail (hamburger) handlers land here too.
(function () {
  'use strict';
  var DATA = JSON.parse(document.getElementById('glossary-data').textContent);
  var TACTIC_ID = DATA.tactics;                       // name -> TA id
  var TACTIC_NAME = {};
  Object.keys(TACTIC_ID).forEach(function (n) { TACTIC_NAME[TACTIC_ID[n]] = n; });
  var VERDICT_SW = { pass: 'sw-pass', notver: 'sw-notver', fail: 'sw-fail', nv: 'sw-nv' };
  var VERDICT_TXT = { pass: 'PASS', notver: 'NOT VERIFIED', fail: 'FAIL', nv: 'N/A' };

  function firstCell(id) { return document.querySelector('.att-matrix .tc[data-id="' + id + '"]'); }
  function colOf(tacticId) {
    return document.querySelector('.tc-col[data-tactic="' + TACTIC_NAME[tacticId] + '"]');
  }
  function kindOf(id) {
    if (/^TA\d{4}$/.test(id)) return 'tactic';
    return id.indexOf('.') > 0 ? 'subtechnique' : 'technique';
  }
  var KIND_LABEL = { tactic: 'Tactic', technique: 'Technique', subtechnique: 'Sub-technique' };

  function attackUrl(id) {
    if (kindOf(id) === 'tactic') return 'https://attack.mitre.org/tactics/' + id + '/';
    return 'https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/';
  }

  // Everything below is read from the cells _build_matrix_html() rendered,
  // so the panel can never disagree with the cell it was opened from.
  function describe(id) {
    var kind = kindOf(id);
    if (kind === 'tactic') {
      var col = colOf(id);
      var cnt = col ? col.querySelector('.tc-count') : null;
      return { id: id, kind: kind, name: TACTIC_NAME[id] || id, coverage: cnt ? cnt.textContent : '' };
    }
    var cell = firstCell(id);
    if (!cell) return null;
    var tn = cell.querySelector('.tn');
    var verdict = tcVerdict(cell);
    var state = verdict !== 'uncov' ? 'covered' : (cell.classList.contains('has-cov') ? 'partial' : 'none');
    var tactics = [];
    document.querySelectorAll('.att-matrix .tc[data-id="' + id + '"]').forEach(function (c) {
      var t = c.closest('.tc-col').dataset.tactic;
      if (tactics.indexOf(t) < 0) tactics.push(t);
    });
    var subs = [];
    if (kind === 'technique') {
      document.querySelectorAll('.att-matrix .tc.sub[data-id^="' + id + '."]').forEach(function (c) {
        if (subs.indexOf(c.dataset.id) < 0) subs.push(c.dataset.id);
      });
    }
    return {
      id: id, kind: kind, name: tn ? tn.textContent : id, verdict: verdict, state: state,
      failFlag: tcHasFail(cell), platforms: tcPlatforms(cell), tactics: tactics, subs: subs,
      parent: kind === 'subtechnique' ? id.split('.')[0] : '',
      rules: cell.dataset.rules ? JSON.parse(cell.dataset.rules) : [],
    };
  }

  function section(label, inner) {
    return '<div><div class="drawer-section-label">' + label + '</div>' + inner + '</div>';
  }
  function jumpPill(id) {
    var it = describe(id);
    return '<button type="button" class="mitre-pill gl-jump" data-go="' + escHtml(id) + '">' +
      escHtml(id) + (it ? ' ' + escHtml(it.name) : '') + '</button>';
  }

  function stateLine(it) {
    if (it.kind === 'tactic') {
      return '<div class="gl-state"><span><strong>Tactic column</strong> — ' +
        escHtml(it.coverage) + ' techniques (a technique counts if it or any sub-technique has a rule)</span></div>';
    }
    if (it.state === 'covered') {
      return '<div class="gl-state"><span class="sw ' + VERDICT_SW[it.verdict] + (it.failFlag && it.verdict !== 'fail' ? ' sw-flag' : '') +
        '"></span><span><strong>Covered</strong> — best verdict ' + VERDICT_TXT[it.verdict] +
        (it.failFlag && it.verdict !== 'fail' ? ', but a covering rule FAILed' : '') + '</span></div>';
    }
    if (it.state === 'partial') {
      return '<div class="gl-state"><span class="sw sw-uncov sw-hascov"></span><span><strong>Partial</strong>' +
        ' — no rule on the technique itself, only on sub-techniques</span></div>';
    }
    return '<div class="gl-state"><span class="sw sw-uncov"></span><span><strong>No coverage</strong>' +
      ' — no rule maps to this item</span></div>';
  }

  function renderPanel(it) {
    var blurb = DATA.blurbs[it.id];
    var note = DATA.notes[it.id];
    var html = stateLine(it);

    html += section('Mi ez', blurb
      ? '<div class="drawer-desc" lang="hu"><p>' + blurb + '</p></div>'
      : '<div class="gl-missing">No glossary blurb and no vault note for this item yet' +
        (it.kind !== 'tactic' && it.state === 'none' ? ', and no rule covers it' : '') +
        '. Nothing is filled in here on purpose — see attack.mitre.org below for the official description.</div>');

    if (note) {
      html += section('Vault note', '<div class="mitre-pills"><a class="mitre-pill" href="' +
        escHtml(encodeURI(note)) + '">' + escHtml(note.split('/').pop().replace(/\.md$/, '')) + '</a></div>');
    }

    var meta = '<span class="meta-key">ID</span><span class="meta-val">' + escHtml(it.id) + '</span>' +
      '<span class="meta-key">Type</span><span class="meta-val">' + KIND_LABEL[it.kind] + '</span>';
    if (it.tactics && it.tactics.length) {
      meta += '<span class="meta-key">' + (it.tactics.length > 1 ? 'Tactics' : 'Tactic') + '</span><span class="meta-val">' +
        it.tactics.map(escHtml).join(', ') + '</span>';
    }
    if (it.platforms && it.platforms.length) {
      meta += '<span class="meta-key">Platforms</span><span class="meta-val">' + it.platforms.map(escHtml).join(', ') + '</span>';
    }
    html += section('Metadata', '<div class="meta-grid">' + meta + '</div>');

    var rel = [];
    if (it.parent) rel.push(jumpPill(it.parent));
    (it.subs || []).forEach(function (s) { rel.push(jumpPill(s)); });
    if (rel.length) {
      html += section(it.parent ? 'Parent technique' : 'Sub-techniques (' + it.subs.length + ')',
        '<div class="mitre-pills">' + rel.join('') + '</div>');
    }

    if (it.rules && it.rules.length) {
      html += section('Covering rules', '<div class="gl-rules">' + it.rules.map(function (r) {
        var vc = r.verdict === 'N/A' ? 'NA' : r.verdict;
        var badge = '<span class="detail-vbadge ' + vc + '">' + vLabel(r.verdict) + '</span>';
        var label = escHtml(r.id + ': ' + r.title);
        return r.url
          ? '<a class="detail-rule" href="' + escHtml(r.url) + '" target="_blank" rel="noopener">' + badge + label + '</a>'
          : '<div class="detail-noverd">' + badge + label + '</div>';
      }).join('') + '</div>');
    }

    html += section('ATT&amp;CK', '<div class="mitre-pills"><a class="mitre-pill" href="' + attackUrl(it.id) +
      '" target="_blank" rel="noopener">attack.mitre.org ↗</a></div>');

    navPanelBody.innerHTML = html;
    navPanelBody.querySelectorAll('[data-go]').forEach(function (b) {
      b.addEventListener('click', function () { openGlossary(b.dataset.go, true); });
    });
  }

  function reveal(id) {
    // A sub-technique cell is display:none until its parent is expanded.
    if (kindOf(id) === 'subtechnique') {
      var parent = firstCell(id.split('.')[0]);
      var ex = parent ? parent.querySelector('.tc-expand') : null;
      if (ex && !ex.classList.contains('open')) navDoExpand(ex, true);
    }
    var target = kindOf(id) === 'tactic' ? colOf(id) : firstCell(id);
    if (target) target.scrollIntoView({ inline: 'center', block: 'nearest' });
  }

  function paintSelection(id) {
    document.querySelectorAll('.tc.highlighted').forEach(function (el) { el.classList.remove('highlighted'); });
    document.querySelectorAll('.tc-hdr.gl-selected').forEach(function (el) { el.classList.remove('gl-selected'); });
    navHighlightedId = null;
    if (!id) return;
    if (kindOf(id) === 'tactic') {
      var col = colOf(id);
      if (col) col.querySelector('.tc-hdr').classList.add('gl-selected');
    } else {
      navHighlightedId = id;
      document.querySelectorAll('.tc[data-id="' + id + '"]').forEach(function (el) { el.classList.add('highlighted'); });
    }
  }

  function openGlossary(id, scroll) {
    var it = describe(id);
    if (!it) return;
    navOpenDetailId = id;
    navDetail = { bid: id, name: it.name, rules: it.rules || [], sel: -1 };
    navPanelTitle.textContent = it.name;
    navPanelTid.textContent = id + ' · ' + KIND_LABEL[it.kind];
    renderPanel(it);
    navPanel.classList.add('open');
    paintSelection(id);
    if (scroll) reveal(id);
    updateHash();
  }

  // Replace the rule browser's rule-list panel (see header comment).
  window.openNavDetail = function (bid) { openGlossary(bid, false); };
  window.updateHash = function () {
    var url = location.pathname + location.search + (navOpenDetailId ? '#' + navOpenDetailId : '');
    // Opened straight from disk (file://) or inside a viewer that sandboxes
    // history, replaceState can throw; the deep link is a nicety, not worth
    // breaking the click for.
    try { history.replaceState(null, '', url); } catch (e) { }
  };
  var sharedClose = closeNavDetail;
  window.closeNavDetail = function () { sharedClose(); paintSelection(null); };
  document.getElementById('detail-close').addEventListener('click', function () { paintSelection(null); });

  function toggle(id) {
    if (navPanel.classList.contains('open') && navOpenDetailId === id) closeNavDetail();
    else openGlossary(id, false);
  }

  // Every technique / sub-technique cell opens its panel -- uncovered ones
  // included, which the rule browser has no reason to do (nothing to list).
  // Registered after the slice's cross-highlight listener, so this one's
  // paintSelection() has the final say on which cells are highlighted.
  document.querySelectorAll('.att-matrix .tc[data-id]').forEach(function (tc) {
    tc.setAttribute('tabindex', '0');
    tc.addEventListener('click', function (e) {
      if (e.target.closest('.ti') || e.target.closest('.tc-expand') || e.target.closest('.tc-detail')) return;
      toggle(tc.dataset.id);
    });
    tc.addEventListener('keydown', function (e) {
      if (e.target !== tc || (e.key !== 'Enter' && e.key !== ' ')) return;
      e.preventDefault();
      toggle(tc.dataset.id);
    });
  });
  // Tactic headers open the tactic's own entry (header link / caret keep
  // their rule-browser behaviour).
  document.querySelectorAll('.att-matrix .tc-col').forEach(function (col) {
    var hdr = col.querySelector('.tc-hdr');
    var tid = TACTIC_ID[col.dataset.tactic];
    if (!hdr || !tid) return;
    hdr.addEventListener('click', function (e) {
      if (e.target.closest('a') || e.target.closest('.tc-col-toggle')) return;
      toggle(tid);
    });
  });

  // Outside-click closes the toolbar dropdowns. In page.js this lives in a
  // document click handler shared with the Rule Library's own menus (outside
  // the sliced block), so only its three Navigator lines are repeated here.
  document.addEventListener('click', function () {
    ['nav-export-menu', 'nav-verdict-menu', 'nav-platform-menu'].forEach(function (id) {
      var m = document.getElementById(id);
      if (m) m.classList.remove('open');
    });
  });

  var start = decodeURIComponent(location.hash.slice(1));
  if (start && describe(start)) openGlossary(start, true);
})();
