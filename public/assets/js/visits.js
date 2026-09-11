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

import { el, num, when } from './core.js';
import { countryNode, dimValue, drillRow, openButton, verdictChip } from './identity.js';
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
const WIDTHS = ['17%', '15%', '14%', '39%', '15%'];

/** The column headings, in order. */
const HEADINGS = ['Date', 'IP', 'Country', 'Page', 'Verdict'];

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
                class: i === 4 ? 'visit-verdict' : null,
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
    const tr = el('tr', drillRow('session', { id: v.id }));

    tr.appendChild(el('td', {
        class: 'mono nowrap visit-when',
        text: when(v.ts_start),
        'data-sort': v.ts_start || ''
    }));

    tr.appendChild(el('td', {
        class: 'mono clip',
        title: v.ip || 'Address not recorded',
        'data-sort': v.ip || ''
    }, [
        v.ip ? dimValue('ip_s', v.ip, { mono: true }) : el('span', { class: 'muted', text: '—' })
    ]));

    tr.appendChild(el('td', {
        class: 'clip',
        title: [v.city, v.region, v.country].filter(Boolean).join(', ') || 'Not geolocated',
        'data-sort': [v.country, v.city].filter(Boolean).join(' ')
    }, [
        v.country ? countryNode(v.country) : el('span', { class: 'muted', text: '—' })
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

    tr.appendChild(el('td', { class: 'visit-verdict', 'data-sort': v.verdict || '' }, [
        verdictChip(v.verdict),
        openButton('session', { id: v.id }, 'Open this visit')
    ]));

    return tr;
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
