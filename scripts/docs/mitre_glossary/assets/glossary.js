(function () {
  'use strict';
  var DATA = JSON.parse(document.getElementById('glossary-data').textContent);
  var ITEMS = DATA.items;
  var matrix = document.getElementById('matrix');
  var detail = document.getElementById('detail');
  var q = document.getElementById('q');
  var KIND = { tactic: 'Taktika', technique: 'Technika', subtechnique: 'Altechnika' };
  var cells = {};

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function mkCell(id, cls) {
    var it = ITEMS[id];
    var b = document.createElement('button');
    b.type = 'button';
    b.className = cls + (it.blurb ? '' : ' nob');
    b.dataset.id = id;
    if (cls === 'tc-hdr') {
      b.innerHTML = '<span>' + esc(it.name) + '</span><span class="tc-count">' +
        esc(id) + ' · ' + esc(it.coverage) + ' covered</span>';
    } else {
      var nSubs = Object.keys(ITEMS).filter(function (k) { return ITEMS[k].parent === id; }).length;
      var meta = it.kind === 'technique' && it.subTotal
        ? '<span class="tm">' + nSubs + '/' + it.subTotal + ' altechnika</span>' : '';
      b.innerHTML = '<span class="ti">' + esc(id) + '</span><span class="tn">' + esc(it.name) + '</span>' + meta;
    }
    b.addEventListener('click', function () { select(id); });
    (cells[id] = cells[id] || []).push(b);
    return b;
  }

  DATA.layout.forEach(function (col) {
    var c = document.createElement('div');
    c.className = 'tc-col';
    c.appendChild(mkCell(col.id, 'tc-hdr'));
    col.techniques.forEach(function (t) {
      c.appendChild(mkCell(t.id, 'tc ' + ITEMS[t.id].state));
      t.subs.forEach(function (s) { c.appendChild(mkCell(s, 'tc sub')); });
    });
    matrix.appendChild(c);
  });

  function relBtn(id) {
    var it = ITEMS[id];
    return it ? '<button type="button" data-go="' + esc(id) + '">' + esc(id) + ' ' + esc(it.name) + '</button>' : '';
  }

  function render(id) {
    var it = ITEMS[id];
    var pills = '<span class="pill">' + KIND[it.kind] + '</span>';
    if (it.kind !== 'tactic') {
      pills += it.state === 'covered'
        ? '<span class="pill cov">Lefedett</span>'
        : '<span class="pill part">Részleges</span>';
    } else {
      pills += '<span class="pill cov">' + esc(it.coverage) + ' technika lefedve</span>';
    }
    (it.platforms || []).forEach(function (p) { pills += '<span class="pill">' + esc(p) + '</span>'; });

    var body = it.blurb
      ? '<p class="d-blurb">' + it.blurb + '</p>'
      : '<p class="d-missing">Ehhez az elemhez még nincs glosszárium-szöveg (blurbs.yaml). ' +
        'Pótold, majd futtasd újra a generátort.</p>';

    var rel = [];
    if (it.parent) rel.push(relBtn(it.parent));
    Object.keys(ITEMS).forEach(function (k) {
      if (ITEMS[k].parent === id) rel.push(relBtn(k));
    });

    var meta = [];
    if (it.rules && it.rules.length) meta.push('<b>Szabályok:</b> ' + it.rules.map(esc).join(', '));
    if (it.tacticNames && it.tacticNames.length > 1) meta.push('<b>Taktikák:</b> ' + it.tacticNames.map(esc).join(', '));

    var links = '<a href="' + esc(it.url) + '" target="_blank" rel="noopener">attack.mitre.org ↗</a>';
    if (it.note) links += '<a href="' + esc(encodeURI(it.note)) + '">Vault-jegyzet: ' + esc(it.note.split('/').pop()) + '</a>';

    detail.innerHTML =
      '<div class="d-id">' + esc(id) + '</div>' +
      '<div class="d-name">' + esc(it.name) + '</div>' +
      '<div class="d-pills">' + pills + '</div>' +
      '<div class="d-section-title">Mi ez</div>' + body +
      (rel.length ? '<div class="d-section-title">Kapcsolódó</div><div class="d-rel">' + rel.join('') + '</div>' : '') +
      (meta.length ? '<div class="d-meta">' + meta.join('<br>') + '</div>' : '') +
      '<div class="d-links">' + links + '</div>';
    detail.querySelectorAll('[data-go]').forEach(function (b) {
      b.addEventListener('click', function () { select(b.dataset.go, true); });
    });
  }

  var current = null;
  function select(id, scroll) {
    if (current) (cells[current] || []).forEach(function (c) { c.classList.remove('sel'); });
    current = id;
    (cells[id] || []).forEach(function (c) { c.classList.add('sel'); });
    if (scroll && cells[id]) cells[id][0].scrollIntoView({ block: 'nearest', inline: 'nearest' });
    render(id);
    if (history.replaceState) history.replaceState(null, '', '#' + id);
  }

  q.addEventListener('input', function () {
    var term = q.value.trim().toLowerCase();
    Object.keys(cells).forEach(function (id) {
      var it = ITEMS[id];
      var hay = (id + ' ' + it.name + ' ' + it.blurb.replace(/<[^>]+>/g, '')).toLowerCase();
      var hit = !term || hay.indexOf(term) !== -1;
      cells[id].forEach(function (c) { c.classList.toggle('dim', !hit); });
    });
  });

  var start = decodeURIComponent(location.hash.slice(1));
  select(ITEMS[start] ? start : DATA.layout[0].id, true);
})();
