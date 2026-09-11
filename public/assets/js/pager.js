/*
 * Loghound — the pagination control every table in the panel ends in.
 *
 * ONE CONTROL, TWO DRIVES. A table on a page pages by re-fetching its own card and keeps the
 * rest of the page where it was, so its pager is a set of buttons with a callback. The session
 * explorer's table IS the page, so its pager is a set of real links that put `start` in the URL
 * — bookmarkable, middle-clickable, and working with scripting off. Both draw the same control,
 * so a reader learns it once.
 *
 * EVERY ROW IS REACHABLE, which is the requirement this replaces "the most recent 12 of 1,890"
 * with. Previous and Next alone are not enough on ninety-five pages, so the control also carries
 * First, Last and a "go to page" box: any row in the set is at most one typed number away.
 *
 * IT SAYS WHAT THE DENOMINATOR COUNTS. "1–20 of 1,890" is a number with no noun; the server
 * sends the plural noun alongside the total (Panel\Paging::block) and it is printed. A total the
 * server could not establish is stated as unknown rather than guessed at — a pager that invents
 * a last page sends the reader to an empty one.
 *
 * Nothing here renders a value that came off the wire: the only dynamic text is a count, a page
 * number and the noun, and all of it goes in through core.js's el({text}), which is textContent.
 */

'use strict';

import { el, num } from './core.js';

/**
 * Work out the page geometry from a server `page` block.
 *
 * @param {Object} page {start, rows, total, unit, shown}
 * @returns {{start:number, rows:number, total:(number|null), pages:(number|null), page:number,
 *            from:number, to:number, unit:string}}
 */
function geometry(page) {
    const p = page || {};
    const rows = Math.max(1, Number(p.rows) || 20);
    const start = Math.max(0, Number(p.start) || 0);
    const shown = Math.max(0, Number(p.shown) || 0);
    const total = p.total === null || p.total === undefined || Number.isNaN(Number(p.total))
        ? null
        : Math.max(0, Number(p.total));

    return {
        start: start,
        rows: rows,
        total: total,
        pages: total === null ? null : Math.max(1, Math.ceil(total / rows)),
        page: Math.floor(start / rows) + 1,
        from: shown === 0 ? 0 : start + 1,
        to: start + shown,
        unit: String(p.unit || 'rows')
    };
}

/**
 * The sentence that says what is on screen and what it is a slice of.
 *
 * A set that fits on one page says so outright rather than printing "1–7 of 7", because the
 * pager beside it then has nothing to offer and the reader should not have to work that out.
 */
function summary(g) {
    if (g.from === 0) {
        return 'No ' + g.unit;
    }
    if (g.total !== null && g.total <= g.rows) {
        return 'All ' + num(g.total) + ' ' + g.unit;
    }
    const of = g.total === null ? '' : ' of ' + num(g.total);
    return num(g.from) + '–' + num(g.to) + of + ' ' + g.unit;
}

/**
 * Is there anything after this page?
 *
 * With a known total the answer is arithmetic. Without one, a full page is taken as evidence
 * that there may be more and a short page as evidence that there is not — which is the same
 * inference the CSV coverage line makes, and it is the only honest one available.
 */
function hasNext(g) {
    return g.total === null ? g.to >= g.start + g.rows : g.to < g.total;
}

/**
 * The last page's offset, or null when the total is unknown.
 */
function lastStart(g) {
    return g.pages === null ? null : (g.pages - 1) * g.rows;
}

/**
 * Build the control.
 *
 * @param {Object} page  The server's `page` block.
 * @param {Function} make (start, label, opts) => Node|null — mints one step control.
 * @param {Array<Node>} tail Extra controls appended after the steps.
 * @returns {HTMLElement}
 */
function build(page, make, tail) {
    const g = geometry(page);
    const parts = [el('span', { class: 'pager-count', text: summary(g) })];

    const steps = el('span', { class: 'pager-steps' });
    const last = lastStart(g);

    if (g.start > 0) {
        steps.appendChild(make(0, '« First', { label: 'First page' }));
        steps.appendChild(make(Math.max(0, g.start - g.rows), '← Previous', { label: 'Previous page' }));
    }

    steps.appendChild(el('span', {
        class: 'pager-pos',
        text: g.pages === null ? 'Page ' + num(g.page) : 'Page ' + num(g.page) + ' of ' + num(g.pages)
    }));

    if (hasNext(g)) {
        steps.appendChild(make(g.start + g.rows, 'Next →', { label: 'Next page' }));
        if (last !== null && last > g.start + g.rows) {
            steps.appendChild(make(last, 'Last »', { label: 'Last page' }));
        }
    }

    parts.push(steps);
    for (const node of (tail || [])) {
        if (node) {
            parts.push(node);
        }
    }

    return el('nav', { class: 'pager', 'aria-label': 'Pagination for this table' }, parts);
}

/**
 * The "go to page" box, which is what makes page 47 of 95 reachable without 46 presses.
 *
 * Absent when there is only one page, and absent when the total is unknown — a box that cannot
 * validate the number typed into it would send the reader to an offset past the end and show
 * them an empty table with no explanation.
 *
 * It is a form so Enter submits it, and the submit is intercepted: the panel's CSP allows no
 * inline handler, and the jump must not reload a page whose other cards are mid-flight.
 *
 * @param {Object} page
 * @param {Function} go   (start) => void
 * @returns {HTMLElement|null}
 */
function jumpBox(page, go) {
    const g = geometry(page);
    if (g.pages === null || g.pages < 3) {
        return null;
    }

    const input = el('input', {
        type: 'number',
        class: 'pager-jump-input',
        min: '1',
        max: String(g.pages),
        step: '1',
        value: String(g.page),
        inputmode: 'numeric',
        'aria-label': 'Go to page number, 1 to ' + g.pages
    });

    const form = el('form', { class: 'pager-jump' }, [
        el('label', { class: 'pager-jump-label' }, [
            el('span', { text: 'Go to page' }),
            input
        ]),
        el('button', { type: 'submit', class: 'ghost small', text: 'Go' })
    ]);

    form.addEventListener('submit', (event) => {
        event.preventDefault();
        const wanted = Math.min(g.pages, Math.max(1, Math.round(Number(input.value) || 1)));
        input.value = String(wanted);
        go((wanted - 1) * g.rows);
    });

    return form;
}

/**
 * Render a callback-driven pager into a container, replacing whatever was there.
 *
 * Used by every card and every dialog table: the press re-runs the card's own loader with a new
 * offset, so the rest of the page — and the rest of the dialog — stays exactly where it was.
 *
 * @param {HTMLElement} mount
 * @param {Object} page  The server's `page` block.
 * @param {Function} onPage (start) => void
 */
export function renderPager(mount, page, onPage) {
    if (!mount) {
        return;
    }
    const go = (start) => {
        if (typeof onPage === 'function') {
            onPage(start);
        }
    };

    const make = (start, label, opts) => {
        const button = el('button', {
            type: 'button',
            class: 'pager-btn',
            'aria-label': (opts && opts.label) || label,
            text: label
        });
        button.addEventListener('click', (event) => {
            event.preventDefault();
            event.stopPropagation();
            go(start);
        });
        return button;
    };

    mount.replaceChildren(build(page, make, [jumpBox(page, go)]));
}

/**
 * Render a link-driven pager, for a table whose paging belongs in the URL.
 *
 * The session explorer is the case: its table is the whole page, so a page turn is a navigation
 * and should be bookmarkable, openable in a new tab and survivable with scripting off.
 *
 * @param {HTMLElement} mount
 * @param {Object} page  The server's `page` block.
 * @param {string} [param] Query parameter carrying the offset.
 */
export function renderLinkPager(mount, page, param) {
    if (!mount) {
        return;
    }
    const key = param || 'start';
    const href = (start) => {
        const params = new URLSearchParams(window.location.search);
        params.set(key, String(start));
        return '?' + params.toString();
    };

    const make = (start, label, opts) => el('a', {
        class: 'pager-btn',
        href: href(start),
        'aria-label': (opts && opts.label) || label,
        text: label
    });

    const go = (start) => {
        window.location.assign(href(start));
    };

    mount.replaceChildren(build(page, make, [jumpBox(page, go)]));
}
