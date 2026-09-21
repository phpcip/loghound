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
import { clearTableChart, rankChart } from '../tablecharts.js';
import { t as T, tn as Tn, tf as Tf, tfn as Tfn } from '../i18n.js';

/**
 * The empty state for an installation that has never named a search parameter.
 *
 * It names the setting where it can be marked as one and links to the page that changes it,
 * rather than printing a configuration key into a heading and leaving the reader to find it.
 */
function notConfigured(id) {
    showEmpty(id + '-empty', T('Search terms are not being collected'), [
        el('p', {}, Tf('No query parameter is named on this installation, so nothing is collected. Name the one your '
            + 'search box uses under {settings}. Terms appear from the next visit onwards; nothing is recovered retrospectively.', {
            settings: el('a', { href: '?v=settings&s=beacon', text: T('Settings, in the beacon section') })
        }))
    ]);
}

/** Fill the top-terms table. */
function renderTerms(data) {
    if (!data.configured.length) {
        setPop('an-terms', T('Not collecting any search terms.'));
        tbody(byId('an-terms-table'), []);
        clearTableChart('an-terms');
        notConfigured('an-terms');
        return 'own';
    }

    setPop('an-terms', T('{n} of {total} visits in range ran a search, read '
        + 'from {params}. Counted as visits, not searches: the same search run six '
        + 'times counts once.', { n: num(data.searched), total: num(data.total), params: data.configured.join(', ') }));

    if (!data.rows.length) {
        tbody(byId('an-terms-table'), []);
        clearTableChart('an-terms');
        return false;
    }
    hideEmpty('an-terms-empty');

    tbody(byId('an-terms-table'), data.rows.map((row) => ({
        attrs: dimRow('search_terms_ss', row.value),
        cells: [
            { text: row.param || '—', clip: true, sort: row.param },
            { text: row.term, clip: true, sort: row.term },
            { text: num(row.sessions), num: true, sort: row.sessions },
            { node: shareBar(row.sessions, data.searched, T('visits that searched')), sort: row.sessions }
        ]
    })));

    rankChart('an-terms', data.rows.map((row) => ({ label: row.term, value: row.sessions })),
        { label: T('Visits per search term') });

    return true;
}

/** Fill the trending-terms table. */
function renderTrend(data) {
    if (!data.configured.length) {
        setPop('an-termtrend', T('Not collecting any search terms.'));
        tbody(byId('an-termtrend-table'), []);
        clearTableChart('an-termtrend');
        notConfigured('an-termtrend');
        return 'own';
    }

    setPop('an-termtrend', T('Against {baseline}. Ranked from the {n} most '
        + 'searched terms across both windows. This window is still filling and the baseline is complete.', { baseline: data.baseline, n: num(data.considered) }));

    if (!data.rows.length) {
        tbody(byId('an-termtrend-table'), []);
        clearTableChart('an-termtrend');
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
                node: magnitudeBar(Math.abs(row.delta), top, T('the largest change on this page'),
                    T('{prev} before, {now} now', { prev: num(row.prev), now: num(row.now) })),
                sort: row.delta
            }
        ]
    })));

    rankChart('an-termtrend', data.rows.map((row) => ({
        label: row.term,
        value: row.delta,
        extra: T('{prev} before, {now} now', { prev: num(row.prev), now: num(row.now) })
    })), {
        signed: true,
        format: (v) => (v > 0 ? '+' : '') + num(v),
        label: T('Change in visits per search term against the previous period')
    });

    return true;
}

/** Entry point. */
export default function init() {
    pagedCard({
        id: 'an-terms',
        label: T('Faceting search terms'),
        empty: T('search terms'),
        fetch: (start, rows) => api('searches', 'terms', { start: start, rows: rows }),
        render: renderTerms
    });

    pagedCard({
        id: 'an-termtrend',
        label: T('Comparing this period against the one before'),
        empty: T('search terms with any movement'),
        fetch: (start, rows) => api('searches', 'trending', { start: start, rows: rows }),
        render: renderTrend
    });
}
