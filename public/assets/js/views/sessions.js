/*
 * Loghound — Session explorer.
 *
 * The recent-visitors list. Every row carries identity at a glance — the flag, the address with
 * the city and the declared identity under it, the network the address belongs to BY NAME, the
 * parsed client rather than the raw User-Agent — and clicking a row opens the whole visit in the
 * shared dialog, including every request in order. All of those facts were already on the session
 * document; none of them were shown, and the table was a dead end.
 *
 * Two affordances per row, and they answer different questions. The ROW opens the record: show
 * me everything about this visit. A VALUE inside it is a link that filters the dashboard to it:
 * show me only this network, only this browser, only this country. The link wins over the row
 * because it is a real anchor, which is also what makes it work with scripting off.
 *
 * WHICH IS WHY THE ROW ENDS IN A CONTROL. Every identity cell carries two lines of values now,
 * so most of the row's surface is link and a reader aiming at the row lands on one: the row
 * filters instead of opening and reads as dead. The last cell is an explicit opener, always
 * there, never a link, and it is what the row's click was silently asking the reader to find.
 *
 * Everything rendered here came off the wire. It reaches the DOM through core.js's el({text}),
 * which is textContent, and the only value that ever becomes an href is `referer_href`, which
 * the SERVER produced with Security::safeUrl().
 */

'use strict';

import {
    api, byId, dayOnly, dec, el, fill, hideEmpty, loadCard, noDataYet, num, pct, timeOnly, when
} from '../core.js';
import { clientNode, countryNode, dimValue, drillRow, openButton } from '../identity.js';
import { activeFilters, renderFacetPanel } from '../facets.js';

/**
 * Verdict chip, the same colouring the whole panel uses.
 *
 * The chip is set in the body face, because a verdict is a word — "human", "likely_bot" — not
 * something whose characters have to line up or be copied exactly. The score sits beside it in
 * monospace with tabular figures, because that IS a number read down the column. One judgement,
 * one cell: the two were separate columns and neither was legible in the width it got.
 */
function verdictChip(verdict) {
    return el('span', {
        class: 'chip v-' + String(verdict || 'unknown'),
        text: verdict || 'unknown'
    });
}

/**
 * The facet sidebar, rendered by the SHARED control.
 *
 * It used to have its own renderer, and that renderer was the one nobody recognised as a filter:
 * five lists of `label   count` in body text with no affordance, no selected state and no
 * alignment. There is one facet renderer now (assets/js/facets.js) and the sidebar, the
 * page-wide bar and the detail dialog all use it, so none of them can drift into being the
 * unrecognisable one again.
 */
function renderFacets(data) {
    const holder = byId('se-facet-list');
    if (holder) {
        renderFacetPanel(holder, data.facets, data.multi, SIDEBAR_VALUES);
    }
}

/**
 * Values shown per dimension in the narrow sidebar before "show all".
 *
 * Nineteen dimensions at twelve values each is a two-hundred-row column nobody reads to the
 * bottom of. Six is enough to see which value dominates, which is the question a facet list
 * answers, and the rest are one press away. A value that is currently SELECTED is always shown
 * regardless of where it falls in the order — a filter you cannot see is a filter you cannot
 * remove.
 */
const SIDEBAR_VALUES = 6;

/**
 * The visitor rows.
 *
 * THE CLIENT COLUMN SHOWS THE PARSED FACTS, never the User-Agent string. Three rows of
 * truncated `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7` look identical and tell the reader
 * nothing; "Safari 17 · macOS · desktop" tells them what they wanted to know. The whole string is
 * in the dialog for anybody who needs it.
 *
 * TYPEFACE PER VALUE, not per table. Monospace is for values whose characters line up or must be
 * copied exactly — the address, the path, the timestamp being compared down the column, the
 * netname — and the body face is for prose: an organisation name, a country, a device class, a
 * verdict. The panel has both faces and had been using one for everything.
 *
 * EVERY CELL THAT IS NOT SORTABLE AS TEXT CARRIES ITS OWN SORT KEY. "2.3 s" and "09/11/2026
 * 02:44" are rendered for a human and sort wrongly as strings, so the raw number goes on the cell
 * and assets/js/sorttable.js reads it.
 *
 * SEVEN CELLS, NOT TEN. Log span, engaged time and the entry page are no longer columns here —
 * see Panel\Sessions::resultsCard() for the measurements that forced it. All three are in the
 * detail dialog the row opens, engaged time with the sentence that says why it can be unknown
 * rather than zero, which is a distinction a right-aligned column of durations cannot make.
 */
function renderRows(data) {
    const table = byId('se-table');
    const body = table.tBodies[0];
    body.replaceChildren();

    if (!data.docs.length) {
        noDataYet('se-table-empty', 'sessions');
        return;
    }
    hideEmpty('se-table-empty');

    for (const doc of data.docs) {
        const tr = el('tr', drillRow('session', { id: doc.id }));

        tr.appendChild(el('td', { class: 'clip', title: when(doc.ts_start), 'data-sort': doc.ts_start || '' }, [
            el('div', { class: 'clip-line mono', text: timeOnly(doc.ts_start) }),
            el('div', { class: 'sub mono', text: dayOnly(doc.ts_start) })
        ]));

        tr.appendChild(el('td', {
            class: 'clip',
            title: [doc.city, doc.region, doc.country].filter(Boolean).join(', ') || 'Not geolocated',
            'data-sort': [doc.country, doc.city].filter(Boolean).join(' ')
        }, [
            doc.country ? countryNode(doc.country, { short: true }) : el('span', { class: 'muted', text: '—' })
        ]));

        tr.appendChild(el('td', {
            class: 'clip',
            title: [doc.ip, doc.ident, doc.city].filter(Boolean).join(' · ') || 'Address not recorded',
            'data-sort': doc.ip || ''
        }, [visitorCell(doc)]));

        tr.appendChild(el('td', {
            class: 'clip',
            title: [doc.as_org, doc.netname, doc.as_type].filter(Boolean).join(' · ') || 'Network not resolved',
            'data-sort': doc.as_org || doc.netname || ''
        }, [networkCell(doc)]));

        tr.appendChild(el('td', {
            class: 'clip',
            title: doc.ua || 'User-Agent not recorded',
            'data-sort': doc.ua_bot_name || doc.browser || ''
        }, [clientNode(doc)]));

        tr.appendChild(el('td', {
            class: 'num',
            text: num(doc.hits),
            'data-sort': doc.hits === null ? '' : String(doc.hits)
        }));

        tr.appendChild(el('td', { class: 'clip', 'data-sort': doc.score === null ? '' : String(doc.score) }, [
            el('div', { class: 'clip-line' }, [verdictChip(doc.verdict)]),
            doc.score === null
                ? null
                : el('div', { class: 'sub mono', text: 'score ' + dec(doc.score, 0) })
        ]));

        tr.appendChild(el('td', { class: 'rowopen-cell' }, [
            openButton('session', { id: doc.id }, 'Open this visit')
        ]));

        body.appendChild(tr);
    }
}

/**
 * The visitor cell: the address, then what is known about who was behind it.
 *
 * The address leads and is monospaced, because it is an identifier whose characters are read
 * one at a time and compared down the column. The second line is prose and is set in the body
 * face a tone lighter: the city, and the identity the measured site declared for this visit if
 * it declared one. A signed-in visit says so as a chip, because "this was a logged-in human"
 * is the single most useful thing on the row when it is true and is worth the width.
 *
 * Both lines truncate on their OWN box. A `<td>` cannot truncate a two-line cell: the ellipsis
 * belongs to the line, and a cell that clips without one is what makes two columns read as one.
 */
function visitorCell(doc) {
    const lower = [];
    if (doc.city) {
        lower.push(el('span', { text: doc.city }));
    }
    if (doc.ident) {
        if (lower.length) {
            lower.push(el('span', { text: ' · ' }));
        }
        lower.push(el('span', { text: doc.ident }));
    }
    if (doc.signed_in === true) {
        if (lower.length) {
            lower.push(el('span', { text: ' ' }));
        }
        lower.push(el('span', { class: 'chip chip-good', text: 'signed in' }));
    }

    return el('div', { class: 'client' }, [
        el('div', { class: 'clip-line mono' }, [
            doc.ip ? dimValue('ip_s', doc.ip, { mono: true }) : el('span', { class: 'muted', text: '—' })
        ]),
        el('div', { class: 'sub clip-line' }, lower.length ? lower : [el('span', { text: '—' })])
    ]);
}

/**
 * The network cell: the organisation a reader recognises, then what qualifies it.
 *
 * The organisation is prose and gets the body face; the netname is an identifier out of a
 * registry — `APPLE-ENGINEERING`, `TENCENT-NET-AP-CN` — and gets monospace. All three parts are
 * filter controls.
 *
 * An absent fact is an em dash of its own, never a separator with nothing on one side of it: the
 * `·` is only ever emitted between two values that both exist, which is what stops a row reading
 * as "· hosting" when the organisation is unknown.
 */
function networkCell(doc) {
    const lower = [];
    if (doc.as_type) {
        lower.push(dimValue('as_type_s', doc.as_type));
    }
    if (doc.netname) {
        if (lower.length) {
            lower.push(el('span', { text: ' · ' }));
        }
        lower.push(dimValue('netname_s', doc.netname, { mono: true }));
    }
    return el('div', { class: 'client' }, [
        el('div', { class: 'clip-line' }, [
            doc.as_org
                ? dimValue('as_org_s', doc.as_org)
                : el('span', { class: 'muted', text: doc.asn ? 'AS' + doc.asn : '—' })
        ]),
        el('div', { class: 'sub clip-line' }, lower.length ? lower : [el('span', { text: '—' })])
    ]);
}

/** Paging controls. */
function renderPager(data) {
    const holder = byId('se-pager');
    if (!holder) {
        return;
    }
    const from = data.numFound ? data.start + 1 : 0;
    const to = Math.min(data.numFound, data.start + data.rows);
    const parts = [el('span', { text: num(from) + '–' + num(to) + ' of ' + num(data.numFound) })];

    const page = (start, label) => {
        const params = new URLSearchParams(window.location.search);
        params.set('start', String(start));
        return el('a', { href: '?' + params.toString(), text: label });
    };
    if (data.start > 0) {
        parts.push(page(Math.max(0, data.start - data.rows), '← Previous'));
    }
    if (to < data.numFound) {
        parts.push(page(data.start + data.rows, 'Next →'));
    }
    fill(holder, parts);
}

/**
 * Load the facet sidebar, and say whether the headline count is a filtered one.
 *
 * "117 matching" reads as a total unless it says otherwise, and on a filtered page it is not one.
 * The count line names how many filters produced it, which is the least it can do given the
 * chips are in a strip at the top of the page rather than next to this number.
 */
function loadFacets() {
    return loadCard('se-facets', 'Counting facet values', async () => {
        const data = await api('sessions', 'facets');
        renderFacets(data);

        const count = byId('se-count');
        if (count) {
            const filters = activeFilters().length;
            count.textContent = num(data.matched) +
                (filters ? ' matching the ' + filters + ' active filter' + (filters === 1 ? '' : 's') : ' matching') +
                ' · ' + num(data.beacon_count) + ' with beacon data (' + pct(data.beacon_count, data.matched) + ')';
        }
    });
}

/** Load a page of results. */
function loadResults() {
    return loadCard('se-results', 'Searching sessions', async () => {
        const data = await api('sessions', 'list');
        renderRows(data);
        renderPager(data);
    });
}

/**
 * Entry point.
 *
 * The table and the sidebar are separate requests: the rows appear as soon as the documents are
 * back rather than waiting on eight terms facets. The `?open=` deep link is handled by
 * detail.js, which app.js wires on every view.
 */
export default function init() {
    loadResults();
    loadFacets();
}
