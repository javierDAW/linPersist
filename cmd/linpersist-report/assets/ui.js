// linpersist-report inline JavaScript.
//
// Vanilla, ~80 LOC. Three features:
//   1. Tab navigation: click a <button data-tab="..."> shows the
//      matching <section data-pane="...">.
//   2. Column sort: click <th> toggles asc/desc on the column. Uses
//      data-sort-type="num" for numeric columns, default lexicographic.
//   3. Live filter: <input class="search" data-target="#table-id">
//      filters rows by substring against the row's text content.
(function () {
  function $(sel, scope) { return (scope || document).querySelector(sel); }
  function $$(sel, scope) { return Array.from((scope || document).querySelectorAll(sel)); }

  // --- Tabs ---
  function activatePane(name) {
    $$('section.pane').forEach(function (p) {
      p.classList.toggle('active', p.dataset.pane === name);
    });
    $$('nav.tabs button').forEach(function (b) {
      b.classList.toggle('active', b.dataset.tab === name);
    });
    if (history.replaceState) {
      history.replaceState(null, '', '#' + name);
    }
  }
  $$('nav.tabs button').forEach(function (b) {
    b.addEventListener('click', function () { activatePane(b.dataset.tab); });
  });
  var initial = (location.hash || '#overview').slice(1);
  activatePane(initial);

  // --- Sortable tables ---
  function compare(a, b, type) {
    if (type === 'num') {
      var na = parseFloat(a), nb = parseFloat(b);
      if (isNaN(na)) na = -Infinity;
      if (isNaN(nb)) nb = -Infinity;
      return na - nb;
    }
    return a.localeCompare(b);
  }
  $$('table.sortable').forEach(function (table) {
    var ths = $$('th', table);
    ths.forEach(function (th, idx) {
      th.addEventListener('click', function () {
        var asc = !th.classList.contains('sort-asc');
        ths.forEach(function (x) { x.classList.remove('sort-asc', 'sort-desc'); });
        th.classList.add(asc ? 'sort-asc' : 'sort-desc');
        var type = th.dataset.sortType || '';
        var tbody = $('tbody', table);
        var rows = $$('tr', tbody);
        rows.sort(function (r1, r2) {
          var c1 = r1.children[idx] ? r1.children[idx].textContent.trim() : '';
          var c2 = r2.children[idx] ? r2.children[idx].textContent.trim() : '';
          var v = compare(c1, c2, type);
          return asc ? v : -v;
        });
        rows.forEach(function (r) { tbody.appendChild(r); });
      });
    });
  });

  // --- Live filters ---
  $$('input.search').forEach(function (inp) {
    inp.addEventListener('input', function () {
      var q = inp.value.trim().toLowerCase();
      var table = $(inp.dataset.target);
      if (!table) return;
      $$('tbody tr', table).forEach(function (r) {
        var text = r.textContent.toLowerCase();
        r.style.display = (q === '' || text.indexOf(q) !== -1) ? '' : 'none';
      });
    });
  });
})();
