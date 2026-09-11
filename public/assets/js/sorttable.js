/*
 * Loghound — click a column header to sort the table by it.
 *
 * WHY IN THE BROWSER AND NOT IN SOLR. Every table in this panel is either a page of documents
 * that is already bounded (25–100 session rows) or a facet list that is already bounded (12–200
 * buckets). The whole answer is in the DOM, so sorting it is a comparison over a few hundred
 * rows and a round trip would make a click feel slower than it needs to for no gain in
 * correctness. Where a sort has to change WHICH rows come back — "the 25 sessions with the
 * highest bot score out of four million" — that is a different question and it stays where it
 * already is, in the explorer's own `sort` parameter, which is a server-side sort over the whole
 * result set. This one reorders what is on screen and says so.
 *
 * WHAT IT SORTS BY. A cell's `data-sort` when it has one, otherwise its text. That distinction
 * is load-bearing: "2.3 s", "1.2 MiB" and "09/11/2026 02:44:30" are all rendered for a human to
 * read and all sort wrongly as strings, and no amount of parsing the rendered text recovers the
 * original without guessing at its format. core.js's tbody() takes `sort` on a cell descriptor
 * for exactly this, and the views set it on every duration, byte count and timestamp.
 *
 * ABSENT SORTS LAST, in both directions. An em-dash means "nothing measured this", and a column
 * sorted descending that opens with a screen of unknowns has buried the answer.
 *
 * CSP. One delegated listener on the document, no inline handler, no onclick attribute. Headers
 * are given their affordance here rather than in each view's PHP, so a table gains sorting by
 * existing and no view has to remember to ask.
 *
 * KEYBOARD AND SCREEN READERS. A header is focusable and responds to Enter and Space, and the
 * current column carries `aria-sort` with the direction — which is how a screen reader announces
 * a sorted table, and the only part of this that a sighted reader gets from the arrow instead.
 */

'use strict';

/** Sub-rows that belong to the row above them and must travel with it. */
const ATTACHED = 'members';

/**
 * Give every header cell in a sortable table its affordance.
 *
 * Skips the expander column, which holds a button rather than a value, and any header that is
 * empty — a column with no name is a control column and sorting by it means nothing.
 */
function mark(root) {
    const scope = root || document;
    const tables = scope === document ? document.querySelectorAll('.view table') : scope.querySelectorAll('table');
    for (const table of tables) {
        const head = table.tHead;
        if (!head || head.dataset.lhSort === '1') {
            continue;
        }
        head.dataset.lhSort = '1';
        for (const th of head.querySelectorAll('th')) {
            /* A COLUMN WITH NO VISIBLE HEADING IS NOT SORTABLE. The test was `textContent`,
               which includes a visually-hidden label — so the row-opener column, whose heading
               is `<span class="sr-only">Open</span>` over a 6px-wide column, was given a sort
               control 6 pixels across. There is nothing in that column to sort by either. */
            const visible = Array.from(th.childNodes)
                .filter((n) => !(n.nodeType === 1 && n.classList && n.classList.contains('sr-only')))
                .map((n) => n.textContent || '')
                .join('')
                .trim();
            if (th.classList.contains('w-expand') || visible === '') {
                continue;
            }
            /* THE HEADER STAYS A COLUMN HEADER; A BUTTON INSIDE IT IS THE CONTROL. The `<th>`
               itself used to carry `tabindex="0"` and a keydown handler with no role at all, so
               a screen reader announced "column header, Requests" and gave the reader no reason
               to think it could be pressed — the classic control that reads as text. Putting
               `role="button"` on the `<th>` instead would have been worse: it stops being a
               columnheader, and a button takes presentational children, which would strip the
               header's own text from the accessibility tree. The ARIA authoring practice for a
               sortable table is exactly this — `aria-sort` on the header, a real button inside
               it — and it is what gets Enter, Space and a focus ring for free.

               The delegated listener matches on `th.sortable`, which still holds, because the
               press originates inside the header. */
            th.classList.add('sortable');
            th.setAttribute('aria-sort', 'none');
            th.removeAttribute('tabindex');

            const label = th.textContent.trim();
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'sort-btn';
            button.title = 'Sort by ' + label;
            while (th.firstChild) {
                button.appendChild(th.firstChild);
            }

            const mark = document.createElement('span');
            mark.className = 'sort-mark';
            mark.setAttribute('aria-hidden', 'true');
            button.appendChild(mark);
            th.appendChild(button);
        }
    }
}

/**
 * The value one cell sorts by: its `data-sort`, else its text.
 *
 * Returned as a string; compare() decides whether the pair is numeric. An em-dash and an empty
 * cell both become '', which compare() sends to the bottom whichever way the column is sorted.
 */
function keyOf(row, index) {
    const cell = row.cells[index];
    if (!cell) {
        return '';
    }
    if (cell.dataset.sort !== undefined && cell.dataset.sort !== '') {
        return cell.dataset.sort;
    }
    const text = (cell.textContent || '').trim();
    return (text === '—' || text === '-') ? '' : text;
}

/**
 * Compare two sort keys.
 *
 * Numeric when BOTH sides parse as a finite number, so a column of counts sorts by magnitude
 * and a column of names sorts alphabetically without either having to declare which it is. The
 * string comparison passes an explicit locale, because the default is whatever the machine
 * happens to be set to and that makes a screenshot unreproducible.
 */
function compare(a, b) {
    if (a === '' && b === '') {
        return 0;
    }
    if (a === '') {
        return 1;
    }
    if (b === '') {
        return -1;
    }
    const na = Number(a);
    const nb = Number(b);
    if (Number.isFinite(na) && Number.isFinite(nb)) {
        return na === nb ? 0 : (na < nb ? -1 : 1);
    }
    return String(a).localeCompare(String(b), 'en-US', { numeric: true, sensitivity: 'base' });
}

/**
 * Reorder a table's rows by one column.
 *
 * Rows are grouped with whatever follows them: the fingerprint table inserts an expanded
 * member list as a sibling `<tr class="members">`, and sorting the rows without it would leave
 * a cluster's addresses sitting under somebody else's cluster — a wrong answer produced by a
 * cosmetic action.
 *
 * The comparison is stable, because a repeated sort on a column with ties must not shuffle the
 * tied rows on every click: Array.prototype.sort is required to be stable in every engine this
 * panel supports.
 */
function sortBy(table, index, direction) {
    const body = table.tBodies[0];
    if (!body) {
        return;
    }

    const groups = [];
    for (const row of Array.prototype.slice.call(body.rows)) {
        if (row.classList.contains(ATTACHED) && groups.length) {
            groups[groups.length - 1].extra.push(row);
            continue;
        }
        groups.push({ row: row, extra: [], key: keyOf(row, index) });
    }

    groups.sort((a, b) => compare(a.key, b.key) * (direction === 'desc' ? -1 : 1));

    const fragment = document.createDocumentFragment();
    for (const group of groups) {
        fragment.appendChild(group.row);
        for (const extra of group.extra) {
            fragment.appendChild(extra);
        }
    }
    body.appendChild(fragment);

    for (const th of table.tHead.querySelectorAll('th')) {
        th.setAttribute('aria-sort', 'none');
        th.classList.remove('sorted-asc', 'sorted-desc');
    }
    const active = table.tHead.rows[table.tHead.rows.length - 1].cells[index];
    if (active) {
        active.setAttribute('aria-sort', direction === 'desc' ? 'descending' : 'ascending');
        active.classList.add(direction === 'desc' ? 'sorted-desc' : 'sorted-asc');
    }
    table.dataset.sortCol = String(index);
    table.dataset.sortDir = direction;
}

/**
 * Handle a click or an Enter/Space on a sortable header.
 *
 * The first click on a column sorts ascending for text and DESCENDING for a numeric column,
 * because "sort by requests" means "most requests first" to everybody who has ever clicked such
 * a header. Clicking the same column again reverses it.
 */
function onActivate(event) {
    const target = event.target;
    if (!target || typeof target.closest !== 'function') {
        return;
    }
    const th = target.closest('th.sortable');
    if (!th) {
        return;
    }
    const table = th.closest('table');
    if (!table || !table.tBodies[0]) {
        return;
    }
    event.preventDefault();

    const index = th.cellIndex;
    const same = String(table.dataset.sortCol || '') === String(index);
    const numeric = th.classList.contains('num');
    let direction;
    if (same) {
        direction = table.dataset.sortDir === 'asc' ? 'desc' : 'asc';
    } else {
        direction = numeric ? 'desc' : 'asc';
    }
    sortBy(table, index, direction);
}

/**
 * Wire sorting for every table on the page, now and for the ones drawn later.
 *
 * The header exists from the first byte — every view renders its table shell server-side and
 * only fills cells over the wire — so marking once at boot is enough, and a re-rendered body
 * needs no re-wiring because the listener is on the document.
 */
export function initSortableTables() {
    /* CLICK ONLY. The control inside each header is a real <button>, and a button fires a
       click for Enter and for Space by itself. Keeping a keydown listener as well meant one
       press sorted twice — once on the key, once on the click the browser synthesised from
       it — which toggles the direction straight back and reads as a header that does nothing
       when operated from the keyboard. */
    mark(document);
    document.addEventListener('click', onActivate);
}

/** Mark tables a view created after boot, e.g. inside a dialog. */
export function markSortable(root) {
    mark(root);
}
