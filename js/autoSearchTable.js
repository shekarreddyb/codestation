
(function ($) {
  const DEFAULTS = {
    // UI
    placeholder: null,                // override placeholder text
    inputSelector: null,              // reuse an existing input
    inputClass: 'auto-search-input form-control form-control-sm mb-2',
    placement: 'before',              // 'before' | 'after' (where to inject if auto-generated)

    // Behavior
    debounceMs: 150,
    excludeColumns: [],               // [0,2] etc., zero-based
    excludeRowSelector: '[data-search-fixed]',   // rows that are always shown
    ignoreRowSelector:  '[data-search-ignore]',  // rows whose text is ignored for matching
    rowTextGetter: null               // (tr) => 'custom searchable text'
  };

  // Small debounce helper
  function debounce(fn, ms) {
    let t; return function () {
      const ctx = this, args = arguments;
      clearTimeout(t); t = setTimeout(() => fn.apply(ctx, args), ms);
    };
  }

  // Plugin entry (supports method calls later)
  $.fn.autoSearch = function (optsOrMethod) {
    // Method calls: $('#t').autoSearch('refresh') / ('destroy')
    if (typeof optsOrMethod === 'string') {
      const method = optsOrMethod;
      return this.each(function () {
        const api = $(this).data('autoSearchApi');
        if (!api) return;
        if (method === 'refresh') api.refresh();
        if (method === 'destroy') api.destroy();
      });
    }

    const options = optsOrMethod || {};
    return this.each(function () {
      const $table = $(this);

      // Prevent double-init
      const existing = $table.data('autoSearchApi');
      if (existing) { existing.destroy(); }

      const cfg = $.extend({}, DEFAULTS, options);

      // Build placeholder: from option or table attributes
      const titleAttr =
        $table.attr('data-search-title') ||
        $table.data('title') ||
        $table.attr('aria-label') ||
        $table.attr('id') || '';
      const titleNice = titleAttr.replace(/[-_]+/g, ' ').trim();
      const autoPlaceholder = 'Search ' + (titleNice ? titleNice.toLowerCase() : 'table') + '…';
      const placeholder = cfg.placeholder || autoPlaceholder;

      // Find or create input
      let $input = cfg.inputSelector ? $(cfg.inputSelector) : $();
      if ($input.length === 0) {
        $input = $('<input type="search" />').attr('placeholder', placeholder).addClass(cfg.inputClass);
        if (cfg.placement === 'after') { $table.after($input); } else { $table.before($input); }
      } else {
        // if reusing, only set placeholder if none present
        if (!$input.attr('placeholder')) $input.attr('placeholder', placeholder);
      }

      // Cache rows (tbody only)
      const $rows = $table.find('tbody > tr');

      // Row text cache (per table)
      const rowCache = new WeakMap();

      function getRowText($tr) {
        const tr = $tr[0];
        if (rowCache.has(tr)) return rowCache.get(tr);

        if (typeof cfg.rowTextGetter === 'function') {
          const v = String(cfg.rowTextGetter(tr) || '').toUpperCase();
          rowCache.set(tr, v);
          return v;
        }

        // Build searchable text while skipping excluded columns / cells
        let buf = '';
        let colIdx = 0;
        $tr.children('td,th').each(function () {
          const $cell = $(this);
          const span = parseInt($cell.attr('colspan') || '1', 10);
          const skipIdx = cfg.excludeColumns.indexOf(colIdx) >= 0;
          const skipAttr = $cell.is('[data-search-cell="exclude"]');
          if (!skipIdx && !skipAttr) buf += ' ' + $cell.text();
          colIdx += span;
        });
        const txt = buf.replace(/\s+/g, ' ').trim().toUpperCase();
        rowCache.set(tr, txt);
        return txt;
      }

      function filterRows(queryRaw) {
        const q = (queryRaw || '').trim().toUpperCase();

        if (!q) {
          $rows.each(function () { $(this).toggle(true); });
          return;
        }

        $rows.each(function () {
          const $tr = $(this);

          // Always-visible rows (e.g., totals)
          if (cfg.excludeRowSelector && $tr.is(cfg.excludeRowSelector)) {
            $tr.toggle(true);
            return;
          }

          // Ignore content of some rows for matching (still hide if no match)
          const ignoreContent = cfg.ignoreRowSelector && $tr.is(cfg.ignoreRowSelector);
          const hay = ignoreContent ? '' : getRowText($tr);
          const match = hay.indexOf(q) >= 0;

          $tr.toggle(match);
        });
      }

      const onInput = debounce(function () {
        filterRows($input.val());
      }, cfg.debounceMs);

      $input.on('input.autoSearch', onInput);

      // API for later
      const api = {
        refresh() {
          rowCache.clear && rowCache.clear(); // WeakMap has no clear; safe no-op
          filterRows($input.val());
        },
        destroy() {
          $input.off('input.autoSearch', onInput);
          $table.removeData('autoSearchApi');
          // If the input was auto-created (no selector specified), you may remove it:
          if (!cfg.inputSelector) $input.remove();
        }
      };

      $table.data('autoSearchApi', api);

      // Initial run (handles prefilled inputs / back button)
      filterRows($input.val());
    });
  };
})(jQuery);