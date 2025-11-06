<script>
(function ($) {
  const DEFAULTS = {
    // UI
    placeholder: null,
    inputSelector: null,
    inputClass: 'auto-search-input form-control form-control-sm mb-2',
    placement: 'before', // 'before' | 'after'

    // Behavior
    debounceMs: 150,
    excludeColumns: [],
    excludeRowSelector: '[data-search-fixed]', // rows always shown (not counted for "no results")
    ignoreRowSelector:  '[data-search-ignore]', // rows whose text is ignored for matching
    rowTextGetter: null,

    // No-results row
    noResults: {
      enabled: true,
      text: 'No results found',
      className: 'auto-search-empty text-muted',
      // colspan: 'auto' uses <thead> col count; or set a number
      colspan: 'auto',
      // where to insert: 'tbody-end' (default) or 'tbody-start'
      insertAt: 'tbody-end'
    }
  };

  function debounce(fn, ms) { let t; return function(){ clearTimeout(t); t = setTimeout(()=>fn.apply(this, arguments), ms); }; }

  $.fn.autoSearch = function (optsOrMethod) {
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
      const prior = $table.data('autoSearchApi'); if (prior) prior.destroy();

      const cfg = $.extend(true, {}, DEFAULTS, options);

      // Build placeholder from attributes
      const titleAttr = $table.attr('data-search-title') || $table.data('title') || $table.attr('aria-label') || $table.attr('id') || '';
      const titleNice = titleAttr.replace(/[-_]+/g, ' ').trim();
      const autoPlaceholder = 'Search ' + (titleNice ? titleNice.toLowerCase() : 'table') + '…';
      const placeholder = cfg.placeholder || autoPlaceholder;

      // Find or create input
      let $input = cfg.inputSelector ? $(cfg.inputSelector) : $();
      if ($input.length === 0) {
        $input = $('<input type="search" />').attr('placeholder', placeholder).addClass(cfg.inputClass);
        (cfg.placement === 'after') ? $table.after($input) : $table.before($input);
      } else {
        if (!$input.attr('placeholder')) $input.attr('placeholder', placeholder);
      }

      const $thead = $table.children('thead').first();
      const $tbody = $table.children('tbody').first();
      const $rows  = $tbody.children('tr');

      // Determine colspan for the empty row
      const colCount =
        (cfg.noResults.colspan !== 'auto' && Number.isInteger(cfg.noResults.colspan))
          ? cfg.noResults.colspan
          : ($thead.find('> tr:first > th').length || $tbody.find('> tr:first > td, > tr:first > th').length || 1);

      // Ensure a single "no results" row exists (hidden by default)
      const EMPTY_ROW_SEL = 'tr.auto-search-empty-row';
      let $emptyRow = $tbody.find(EMPTY_ROW_SEL);
      if (cfg.noResults.enabled) {
        if ($emptyRow.length === 0) {
          $emptyRow = $('<tr class="auto-search-empty-row" style="display:none;"></tr>');
          const $td = $('<td>').attr('colspan', colCount).addClass(cfg.noResults.className).text(cfg.noResults.text);
          $emptyRow.append($td);
          (cfg.noResults.insertAt === 'tbody-start') ? $tbody.prepend($emptyRow) : $tbody.append($emptyRow);
        } else {
          // Update existing if options changed
          $emptyRow.find('td').attr('colspan', colCount).attr('class', cfg.noResults.className).text(cfg.noResults.text);
        }
      }

      // Row text cache
      const rowCache = new WeakMap();
      function getRowText($tr) {
        const tr = $tr[0];
        if (rowCache.has(tr)) return rowCache.get(tr);
        if (typeof cfg.rowTextGetter === 'function') {
          const v = String(cfg.rowTextGetter(tr) || '').toUpperCase(); rowCache.set(tr, v); return v;
        }
        let buf = '', colIdx = 0;
        $tr.children('td,th').each(function () {
          const $cell = $(this);
          const span = parseInt($cell.attr('colspan') || '1', 10);
          const skipIdx  = cfg.excludeColumns.indexOf(colIdx) >= 0;
          const skipAttr = $cell.is('[data-search-cell="exclude"]');
          if (!skipIdx && !skipAttr) buf += ' ' + $cell.text();
          colIdx += span;
        });
        const txt = buf.replace(/\s+/g, ' ').trim().toUpperCase();
        rowCache.set(tr, txt);
        return txt;
      }

      function applyFilter(queryRaw) {
        const q = (queryRaw || '').trim().toUpperCase();

        // Hide empty row while filtering
        if (cfg.noResults.enabled) $emptyRow.hide();

        // Toggle rows
        $rows.each(function () {
          const $tr = $(this);

          // Skip our empty row placeholder
          if ($tr.is(EMPTY_ROW_SEL)) return;

          // Rows always visible (not counted as "results")
          if (cfg.excludeRowSelector && $tr.is(cfg.excludeRowSelector)) { $tr.show(); return; }

          if (!q) { $tr.show(); return; }

          const ignoreContent = cfg.ignoreRowSelector && $tr.is(cfg.ignoreRowSelector);
          const hay = ignoreContent ? '' : getRowText($tr);
          const isMatch = hay.indexOf(q) >= 0;
          $tr.toggle(isMatch);
        });

        // Show empty row if no *filterable* rows are visible
        if (cfg.noResults.enabled) {
          const anyVisible = $rows
            .not(EMPTY_ROW_SEL)
            .filter(function () {
              const $tr = $(this);
              if (cfg.excludeRowSelector && $tr.is(cfg.excludeRowSelector)) return false; // don't count fixed rows
              return $tr.is(':visible');
            }).length > 0;
          if (!anyVisible) $emptyRow.show();
        }
      }

      const onInput = debounce(function () { applyFilter($input.val()); }, cfg.debounceMs);
      $input.on('input.autoSearch', onInput);

      const api = {
        refresh() { applyFilter($input.val()); },
        destroy() {
          $input.off('input.autoSearch', onInput);
          $table.removeData('autoSearchApi');
          if (!cfg.inputSelector) $input.remove();
          // Keep/clean empty row? We'll remove it to leave the table pristine:
          $table.find(EMPTY_ROW_SEL).remove();
        }
      };

      $table.data('autoSearchApi', api);

      // Initial
      applyFilter($input.val());
    });
  };
})(jQuery);
</script>