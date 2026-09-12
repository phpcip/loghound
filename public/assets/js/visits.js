/*
 * Loghound — the visit table, which is the same five columns wherever a list of visits appears.
 *
 * FIVE COLUMNS, AND THE COUNT IS THE CONTRACT: date, address, country, page, verdict. The
 * session explorer, the dimension dialog, the fingerprint dialog, the virtual-host dialog and
 * the population dialogs opened from the Overview tiles all render through this one function, so
 * none of them can drift into carrying a sixth.
 *
 * WHAT LEFT AND WHERE IT WENT. The network, the parsed client, the header fingerprint, the
 * request count, the ASN and the netblock were all columns here. Ten columns in a fixed-layout
 * table do not fit: each one is a few characters wide, so the two that carry the longest values
 * — the date and the path — were the two that lost, and the panel shipped a date column reading
 * "09/11/2026 …" with the time cut off and a page column reading "/openso…". Every one of those
 * facts is on the session document and every one of them is in the dialog the row opens, where
 * there is room to say what it means rather than to truncate it.
 *
 * WHAT THE FIVE BUY. The date is the whole instant to the second on one line, because a table of
 * visits is read by comparing times. The address is monospace, because it is an identifier read
 * one character at a time down a column. The country is its name and its flag, never the
 * two-letter code. The page gets every character the other four do not need. The verdict is the
 * word, never the stored slug.
 *
 * EVERY VALUE HERE CAME OFF THE WIRE — a path, a city, an address — and reaches the DOM through
 * core.js's el({text}), which is textContent. The only href is built by url.js from a validated
 * host and a validated path, or by identity.js with encodeURIComponent.
 */

'use strict';

import { dur, el, num, when } from './core.js';
import { countryNode, dimValue, drillRow, openButton } from './identity.js';
import { pathCell } from './url.js';

/**
 * The column widths, as percentages that sum to 100.
 *
 * Percentages only, never `ch`: the two units cannot be reconciled under `table-layout: fixed`
 * and mixing them is what starved the last column to zero in the tables this replaces. The page
 * column takes every point the other four can spare, because it is the one whose value is long
 * and whose truncation costs the reader the most.
 *
 * @type {Array<string>}
 */
const WIDTHS = ['17%', '17%', '28%', '20%', '9%', '9%'];

/* THE VERDICT IS NO LONGER A COLUMN. It was a chip at the end of every row, spending a seventh
   of the width on one word that is already the row's colour — see `.visits tbody tr[data-verdict]`
   in the stylesheet. What that width buys instead is the two facts a visit table could never
   answer: how long they stayed, and whether it counted as a bounce. The flag moves to a narrow
   column left of the address, headed CTR because the glyph needs no more than three letters
   above it and the room belongs to the columns that hold real text. */
const HEADINGS = ['Date', 'IP', 'Page', 'Email', 'Sess time', 'Bounce'];

/**
 * The `<colgroup>` and `<thead>` a visit table starts with, for a table built in the browser.
 *
 * @returns {Array<Node>}
 */
export function visitTableHead() {
    return [
        el('colgroup', {}, WIDTHS.map((w) => el('col', { style: 'width:' + w }))),
        el('thead', {}, [
            el('tr', {}, HEADINGS.map((text, i) => el('th', {
                scope: 'col',
                class: i === 5 ? 'visit-verdict' : null,
                text: text
            })))
        ])
    ];
}

/**
 * One visit row.
 *
 * The row opens the whole visit and every value inside it filters the dashboard to itself, which
 * are different questions and both worth having. A link wins the click over the row, so the
 * verdict cell ends in the explicit opener — inside the fifth column rather than as a sixth,
 * because the five-column contract is about what the reader has to read, and a chevron is a
 * control.
 *
 * @param {Object} v A visit, in the shape Panel\Sessions::shapeVisitor() returns.
 * @returns {HTMLElement}
 */
export function visitRow(v) {
    /* THE ROW CARRIES THE VERDICT AS A COLOUR. `data-verdict` is what the stylesheet colours on,
       here and in every other table that shows a scored session, so the judgement is legible
       down the whole table at a glance instead of being read one chip at a time. */
    const attrs = drillRow('session', { id: v.id });
    attrs.dataset = Object.assign({}, attrs.dataset, { verdict: v.verdict || 'unknown' });
    const tr = el('tr', attrs);

    tr.appendChild(el('td', {
        class: 'mono nowrap visit-when',
        text: when(v.ts_start),
        'data-sort': v.ts_start || ''
    }));

    /* THE FLAG RIDES WITH THE ADDRESS. They answer one question — who, and from where — so
       spending a whole column on a glyph was width taken from the page path. Both are their own
       filter control; the flag carries the country name in the panel's tooltip. */
    tr.appendChild(el('td', {
        class: 'mono clip visit-who',
        'data-sort': [v.country, v.ip].filter(Boolean).join(' ')
    }, [
        v.country
            ? countryNode(v.country, { flagOnly: true })
            : el('span', { class: 'muted visit-noflag', text: '·' }),
        v.ip ? dimValue('ip_s', v.ip, { mono: true }) : el('span', { class: 'muted', text: '—' })
    ]));

    tr.appendChild(el('td', {
        class: 'clip urlcell',
        title: v.entry || 'No entry page recorded',
        'data-sort': v.entry || ''
    }, [
        v.entry
            ? pathCell(v.entry, { host: v.host })
            : el('span', { class: 'muted', text: '—' })
    ]));

    /* THE NAME THE SITE GAVE US, and a filter like any other value: pressing it narrows the
       whole dashboard to that person. `N/A` rather than a dash where the site said nothing,
       because "we were not told" is a different fact from "there is no value". */
    tr.appendChild(el('td', {
        class: 'clip visit-email',
        title: v.ident || 'No identity was sent for this visit',
        'data-sort': v.ident || ''
    }, [
        v.ident
            ? dimValue('ident_s', v.ident)
            : el('span', { class: 'muted', text: 'N/A' })
    ]));

    /* TIME ON SITE, AND WHICH CLOCK IT CAME FROM. The engaged clock is the honest one and it
       exists only where the beacon ran; everything else falls back to the log span, which is
       blind to the final page. The cell says which one it is showing rather than presenting two
       different measurements as the same number. */
    const engaged = v.engaged_ms === null || v.engaged_ms === undefined ? null : Number(v.engaged_ms);
    const span = v.log_span_ms === null || v.log_span_ms === undefined ? null : Number(v.log_span_ms);
    const measured = engaged !== null && engaged > 0;
    const shown = measured ? engaged : span;

    tr.appendChild(el('td', {
        class: 'mono nowrap' + (measured ? ' visit-engaged' : ' muted'),
        text: shown === null || shown <= 0 ? '—' : dur(shown),
        title: shown === null || shown <= 0
            ? 'Nothing measured a duration for this visit'
            : (measured
                ? 'Engaged time, measured by the beacon'
                : 'Log span: first request to last. Blind to the final page.'),
        'data-sort': String(shown === null ? -1 : shown)
    }));

    tr.appendChild(el('td', { class: 'visit-verdict', 'data-sort': v.bounced === null ? '' : String(v.bounced) }, [
        bounceMark(v),
        openButton('session', { id: v.id }, 'Open this visit')
    ]));

    return tr;
}

/**
 * Whether this visit bounced, in the product's own definition rather than the conventional one.
 *
 * A bounce is one page AND no engagement — not merely one pageview, which counts a reader who
 * spent four minutes on the article they came for as a failure. Where no beacon ran there is no
 * engagement to judge, so the honest answer is that it is not known, and the cell says so
 * instead of guessing in either direction.
 */
function bounceMark(v) {
    if (v.bounced === true) {
        return el('span', { class: 'chip chip-accent', text: 'Bounced' });
    }
    if (v.bounced === false) {
        return el('span', { class: 'chip', text: 'Stayed' });
    }
    return el('span', { class: 'muted', text: '—' });
}

/**
 * A whole visit table, built in the browser.
 *
 * @param {Array<Object>} rows
 * @returns {HTMLElement} The `.table-wrap` the table lives in.
 */
export function visitTable(rows) {
    const body = el('tbody');
    for (const v of (rows || [])) {
        body.appendChild(visitRow(v));
    }

    const table = el('table', { class: 'tight table-fixed visits' }, visitTableHead().concat([body]));

    return el('div', { class: 'table-wrap' }, [table]);
}

/**
 * Fill an existing visit table's body.
 *
 * @param {HTMLTableElement} table
 * @param {Array<Object>} rows
 */
export function fillVisits(table, rows) {
    if (!table) {
        return;
    }
    const body = table.tBodies[0] || table.appendChild(document.createElement('tbody'));
    body.replaceChildren();
    for (const v of (rows || [])) {
        body.appendChild(visitRow(v));
    }
}

/**
 * The one sentence a visit table's caption says about its own scope.
 *
 * It never says "the most recent N of M". That phrasing was the product telling the reader that
 * the rest existed and was unreachable; the table is paged now, so the honest sentence is how
 * many there are and that all of them can be walked.
 *
 * @param {Object} page The server's `page` block.
 * @returns {string}
 */
export function visitCaption(page) {
    const total = page && page.total !== null && page.total !== undefined ? Number(page.total) : null;
    if (total === null) {
        return 'Every visit in scope.';
    }
    if (total === 0) {
        return 'No visit in scope.';
    }
    return num(total) + (total === 1 ? ' visit.' : ' visits, all of them reachable.');
}
