/*
 * Loghound — Analytics: engagement.
 *
 * The headline bounce rate, rendered by the shared card so the Session explorer and this page
 * cannot state the metric two ways, and then the same measure per landing page — which is the
 * form of it somebody can act on, because "31% of people bounce" changes nothing and "68% of the
 * people who land on /pricing bounce" changes a page.
 *
 * EVERY ROW CARRIES BOTH DENOMINATORS. A landing page's bounce rate is only a measurement over
 * the visits where a beacon ran; a row whose measurable population is three is a row nobody should
 * draw a conclusion from, and the only way a reader can tell is if the denominator is printed
 * beside the rate rather than hidden behind it.
 */

'use strict';

import { api, byId, el, hideEmpty, loadCard, num, pct, setPop, tbody, when } from '../core.js';
import { renderBounce } from '../bounce.js';
import { pagedCard } from '../cardtable.js';
import { dimRow, dimValue } from '../identity.js';
import { pathCell } from '../url.js';

/**
 * The split bar: what share of a landing page's measurable visits bounced against what share
 * stayed on the one page they saw.
 *
 * Two segments and not one, because the interesting comparison on this table is not "how big is
 * the bounce" but "of the people who only ever saw this page, how many actually read it". A
 * single bar cannot show that and a second number column would be a sixth column.
 */
function splitBar(row) {
    const measured = row.measured || 0;
    const bounced = row.bounced || 0;
    const satisfied = row.satisfied || 0;
    const width = (n) => measured > 0 ? ((n / measured) * 100).toFixed(2) + '%' : '0%';

    return el('span', { class: 'bar bar-split' }, [
        el('span', {
            class: 'bar-evasive',
            style: 'width:' + width(bounced),
            title: num(bounced) + ' bounced'
        }),
        el('span', {
            class: 'bar-human',
            style: 'width:' + width(satisfied),
            title: num(satisfied) + ' saw one page and stayed on it'
        }),
        el('span', {
            class: 'bar-declared',
            style: 'width:' + width(Math.max(0, measured - bounced - satisfied)),
            title: num(Math.max(0, measured - bounced - satisfied)) + ' went further than the landing page'
        })
    ]);
}

/**
 * Fill the per-landing-page table.
 *
 * The rate is em-dashed rather than shown as 0% when nothing on the row could be measured. A
 * page whose visitors all arrived without a beacon has an unknown bounce rate, and printing zero
 * would make the page with the least evidence look like the best-performing one on the table.
 */
function renderPages(data) {
    setPop('an-bouncepages', data.definition);

    if (!data.rows.length) {
        tbody(byId('an-bouncepages-table'), []);
        return false;
    }
    hideEmpty('an-bouncepages-empty');

    tbody(byId('an-bouncepages-table'), data.rows.map((row) => ({
        attrs: dimRow('entry_path_s', row.path),
        cells: [
            {
                node: pathCell(row.path, { host: row.host, hosts: row.hosts }),
                class: 'clip urlcell',
                title: row.path,
                sort: row.path
            },
            { text: num(row.people), num: true, sort: row.people },
            {
                text: num(row.measured),
                num: true,
                sort: row.measured,
                title: row.people
                    ? num(row.measured) + ' of the ' + num(row.people) + ' human visits that landed here had a '
                        + 'beacon, so only those can be judged on engagement.'
                    : ''
            },
            {
                text: row.measured ? pct(row.bounced, row.measured, 1) : '—',
                num: true,
                sort: row.measured ? row.bounced / row.measured : -1,
                title: row.measured
                    ? num(row.bounced) + ' of ' + num(row.measured) + ' measurable visits bounced.'
                    : 'No visit that landed here had a beacon, so the bounce rate is unknown rather than zero.'
            },
            { node: splitBar(row), sort: row.measured ? row.bounced / row.measured : -1 }
        ]
    })));

    return true;
}

/** Entry point. */
/**
 * The signed-in visitors table.
 *
 * Every row opens the visits behind that person, because a name with a count next to it and no
 * way through is the same dead end every other table in this panel stopped being. An
 * installation whose site never calls identify() gets the empty state and a sentence saying so,
 * rather than a table with headers and nothing under them.
 */
function renderPeople(data) {
    const rows = data.people || [];

    setPop('an-people', rows.length
        ? num(data.named) + ' of ' + num(data.total) + ' visits carried an identity, across '
            + num(data.distinct) + (data.distinct === 1 ? ' person' : ' people')
            + (data.distinct > rows.length ? ' — the ' + num(rows.length) + ' most frequent are listed' : '')
        : 'No visit in range carried an identity. Your site declares one by passing it to the '
            + 'beacon; nothing is guessed, so until it does this stays empty.');

    if (!rows.length) {
        tbody(byId('an-people-table'), []);
        return false;
    }
    hideEmpty('an-people-empty');

    tbody(byId('an-people-table'), rows.map((row) => ({
        attrs: dimRow('ident_s', row.ident),
        cells: [
            { node: dimValue('ident_s', row.ident), clip: true, title: row.ident, sort: row.ident },
            { text: num(row.sessions), num: true, sort: row.sessions },
            { text: num(row.pages), num: true, sort: row.pages },
            { text: num(row.hits), num: true, sort: row.hits },
            { text: num(row.uniq_ips), num: true, sort: row.uniq_ips },
            { text: row.last ? when(row.last) : '—', mono: true, nowrap: true, sort: row.last || '' }
        ]
    })));

    return true;
}

export default function init() {
    loadCard('an-people', 'Counting visits per signed-in visitor', async () => {
        renderPeople(await api('engagement', 'people'));
    });

    loadCard('an-bounce', 'Measuring engagement on single-page visits', async () => {
        renderBounce('an-bounce', await api('engagement', 'bounce'));
    });

    pagedCard({
        id: 'an-bouncepages',
        label: 'Measuring engagement per landing page',
        empty: 'landing pages',
        fetch: (start, rows) => api('engagement', 'pages', { start: start, rows: rows }),
        render: renderPages
    });
}
