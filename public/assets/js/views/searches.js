/*
 * Loghound — Analytics: site search.
 *
 * Two paged tables, and one distinction that matters more than either of them: "nothing is
 * configured" is not "nothing was searched for". Search terms are collected only from query
 * parameters the operator has named, so on an installation where nobody has, both tables are
 * empty for ever — and an empty table under "Top searches" sends somebody hunting for a bug in
 * their own search page. Both cards check that first and say which state they are in.
 */

'use strict';

import { api, byId, el, hideEmpty, num, setPop, showEmpty, tbody } from '../core.js';
import { changeCell, magnitudeBar, pagedCard, shareBar } from '../cardtable.js';
import { dimRow } from '../identity.js';

/**
 * The empty state for an installation that has never named a search parameter.
 *
 * It names the setting where it can be marked as one and links to the page that changes it,
 * rather than printing a configuration key into a heading and leaving the reader to find it.
 */
function notConfigured(id) {
    showEmpty(id + '-empty', 'Search terms are not being collected', [
        el('p', {}, [
            'No query parameter is named on this installation, so nothing is collected. Name the one your '
            + 'search box uses under ',
            el('a', { href: '?v=settings&s=beacon', text: 'Settings, in the beacon section' }),
            '. Terms appear from the next visit onwards; nothing is recovered retrospectively.'
        ])
    ]);
}

/** Fill the top-terms table. */
function renderTerms(data) {
    if (!data.configured.length) {
        setPop('an-terms', 'Not collecting any search terms.');
        tbody(byId('an-terms-table'), []);
        notConfigured('an-terms');
        return 'own';
    }

    setPop('an-terms', num(data.searched) + ' of ' + num(data.total) + ' visits in range ran a search, read '
        + 'from ' + data.configured.join(', ') + '. Counted as visits, not searches: the same search run six '
        + 'times counts once.');

    if (!data.rows.length) {
        tbody(byId('an-terms-table'), []);
        return false;
    }
    hideEmpty('an-terms-empty');

    tbody(byId('an-terms-table'), data.rows.map((row) => ({
        attrs: dimRow('search_terms_ss', row.value),
        cells: [
            { text: row.param || '—', clip: true, sort: row.param },
            { text: row.term, clip: true, sort: row.term },
            { text: num(row.sessions), num: true, sort: row.sessions },
            { node: shareBar(row.sessions, data.searched, 'visits that searched'), sort: row.sessions }
        ]
    })));

    return true;
}

/** Fill the trending-terms table. */
function renderTrend(data) {
    if (!data.configured.length) {
        setPop('an-termtrend', 'Not collecting any search terms.');
        tbody(byId('an-termtrend-table'), []);
        notConfigured('an-termtrend');
        return 'own';
    }

    setPop('an-termtrend', 'Against ' + data.baseline + '. Ranked from the ' + num(data.considered) + ' most '
        + 'searched terms across both windows. This window is still filling and the baseline is complete.');

    if (!data.rows.length) {
        tbody(byId('an-termtrend-table'), []);
        return false;
    }
    hideEmpty('an-termtrend-empty');

    const top = data.rows.reduce((m, r) => Math.max(m, Math.abs(r.delta)), 0) || 1;
    tbody(byId('an-termtrend-table'), data.rows.map((row) => ({
        attrs: dimRow('search_terms_ss', row.value),
        cells: [
            { text: row.param || '—', clip: true, sort: row.param },
            { text: row.term, clip: true, sort: row.term },
            { text: num(row.now), num: true, sort: row.now },
            { text: num(row.prev), num: true, sort: row.prev },
            { node: changeCell(row.now, row.prev), class: 'num', sort: row.delta },
            {
                node: magnitudeBar(Math.abs(row.delta), top, 'the largest change on this page',
                    num(row.prev) + ' before, ' + num(row.now) + ' now'),
                sort: row.delta
            }
        ]
    })));

    return true;
}

/** Entry point. */
export default function init() {
    pagedCard({
        id: 'an-terms',
        label: 'Faceting search terms',
        empty: 'search terms',
        fetch: (start) => api('searches', 'terms', { start: start }),
        render: renderTerms
    });

    pagedCard({
        id: 'an-termtrend',
        label: 'Comparing this period against the one before',
        empty: 'search terms with any movement',
        fetch: (start) => api('searches', 'trending', { start: start }),
        render: renderTrend
    });
}
