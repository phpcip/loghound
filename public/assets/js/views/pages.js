/*
 * Loghound — Analytics: pages.
 *
 * Three paged tables: where visits start, where the log last saw them, and what moved against the
 * period before. Every path is rendered through url.js so the row carries the full URL as a link
 * beside the path, and every row opens the path's own dimension dialog — which is where the
 * visits behind the number now live, twenty to a page.
 *
 * Every value here came off the wire and reaches the DOM through core.js's el({text}).
 */

'use strict';

import { api, byId, el, hideEmpty, num, pct, setPop, tbody } from '../core.js';
import { changeCell, magnitudeBar, pagedCard, shareBar } from '../cardtable.js';
import { dimRow } from '../identity.js';
import { pathCell } from '../url.js';
import { tokens } from '../charts.js';
import { clearTableChart, rankChart, splitChart } from '../tablecharts.js';
import { t as T, tn as Tn, tf as Tf, tfn as Tfn } from '../i18n.js';

/** The three cards' loaders, so a toggle can restart one from its first page. */
const loaders = {};

/** The scope a toggle has put each landing table into. */
const scope = { 'an-entry': 'all', 'an-exit': 'multi' };

/**
 * Fill the entry-pages table.
 *
 * The one-request column is the row's own caveat and is why it is a column rather than a
 * footnote: a landing page with two hundred visits of which a hundred and ninety made a single
 * request is a page people arrive at and leave, and a bare visit count says the opposite.
 */
function renderEntry(data) {
    if (!data.rows.length) {
        tbody(byId('an-entry-table'), []);
        clearTableChart('an-entry');
        return false;
    }
    hideEmpty('an-entry-empty');

    setPop('an-entry', data.scope_label + ' · ' + T('{n} visits in range, counted on the first '
        + 'request of each. A single-request visit has the same entry and exit page.', { n: num(data.total) }));

    tbody(byId('an-entry-table'), data.rows.map((row) => ({
        attrs: dimRow('entry_path_s', row.path),
        cells: [
            {
                node: pathCell(row.path, { host: row.host, hosts: row.hosts }),
                class: 'clip urlcell',
                title: row.path,
                sort: row.path
            },
            { text: num(row.sessions), num: true, sort: row.sessions },
            {
                text: num(row.single) + ' · ' + pct(row.single, row.sessions, 0),
                num: true,
                sort: row.sessions ? row.single / row.sessions : 0,
                title: T('{n} of {total} made no further request.', { n: num(row.single), total: num(row.sessions) })
            },
            { node: shareBar(row.sessions, data.total, T('visits in range')), sort: row.sessions }
        ]
    })));

    const t = tokens();
    splitChart('an-entry', data.rows.map((row) => ({
        label: row.path,
        parts: [
            { name: T('Went further'), value: Math.max(0, row.sessions - row.single), color: t.pop.ai },
            { name: T('Left after one request'), value: row.single, color: t.pop.unknown }
        ]
    })), { label: T('Visits per entry page, split by whether they went further') });

    return true;
}

/** Fill the exit-pages table. */
function renderExit(data) {
    if (!data.rows.length) {
        tbody(byId('an-exit-table'), []);
        clearTableChart('an-exit');
        return false;
    }
    hideEmpty('an-exit-empty');

    setPop('an-exit', data.scope_label + ' · ' + T('{n} finished visits in range. {beacon} ({pct}) had a beacon; for the rest the last '
        + 'log line is all there is.', { n: num(data.total), beacon: num(data.beacon), pct: pct(data.beacon, data.total, 0) }));

    tbody(byId('an-exit-table'), data.rows.map((row) => ({
        attrs: dimRow('exit_path_s', row.path),
        cells: [
            {
                node: pathCell(row.path, { host: row.host, hosts: row.hosts }),
                class: 'clip urlcell',
                title: row.path,
                sort: row.path
            },
            { text: num(row.sessions), num: true, sort: row.sessions },
            { node: shareBar(row.sessions, data.total, T('finished visits')), sort: row.sessions }
        ]
    })));

    rankChart('an-exit', data.rows.map((row) => ({ label: row.path, value: row.sessions })),
        { label: T('Finished visits per exit page') });

    return true;
}

/**
 * Fill the trending table.
 *
 * THE MOVEMENT COLUMN IS NOT A SHARE and does not use shareBar(). A change between two periods is
 * not a fraction of anything, so the only comparison available is against the largest change on
 * the page — which is the normalisation every other bar in the product has just stopped doing, and
 * is admissible here only because magnitudeBar() names the reference in its own title.
 */
function renderTrend(data) {
    if (!data.rows.length) {
        tbody(byId('an-trend-table'), []);
        clearTableChart('an-trend');
        return false;
    }
    hideEmpty('an-trend-empty');

    setPop('an-trend', T('Against {baseline}. Ranked from the {n} busiest '
        + 'paths across both windows, so a path with little traffic in either is absent however much it grew. '
        + 'This window is still filling and the baseline is complete.', { baseline: data.baseline, n: num(data.considered) }));

    const top = data.rows.reduce((m, r) => Math.max(m, Math.abs(r.delta)), 0) || 1;
    tbody(byId('an-trend-table'), data.rows.map((row) => ({
        attrs: dimRow('paths_ss', row.path),
        cells: [
            {
                node: pathCell(row.path, { host: row.host, hosts: row.hosts }),
                class: 'clip urlcell',
                title: row.path,
                sort: row.path
            },
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

    rankChart('an-trend', data.rows.map((row) => ({
        label: row.path,
        value: row.delta,
        extra: T('{prev} before, {now} now', { prev: num(row.prev), now: num(row.now) })
    })), {
        signed: true,
        format: (v) => (v > 0 ? '+' : '') + num(v),
        label: T('Change in requests per path against the previous period')
    });

    return true;
}

/**
 * Wire one card's scope toggle.
 *
 * A change of scope restarts the table at its first page, which is the only honest behaviour: the
 * offset the reader was at named a row in a different population.
 */
function wireToggle(id) {
    const group = document.querySelector('[data-card="' + id + '"] .toggle');
    if (!group) {
        return;
    }
    for (const button of group.querySelectorAll('button[data-scope]')) {
        button.addEventListener('click', () => {
            for (const other of group.querySelectorAll('button')) {
                other.classList.remove('on');
                other.setAttribute('aria-pressed', 'false');
            }
            button.classList.add('on');
            button.setAttribute('aria-pressed', 'true');
            scope[id] = button.dataset.scope;
            loaders[id](0);
        });
    }
}

/** Entry point. */
export default function init() {
    loaders['an-entry'] = pagedCard({
        id: 'an-entry',
        label: T('Faceting entry pages'),
        empty: T('entry pages'),
        fetch: (start, rows) => api('pages', 'entry', { start: start, rows: rows, scope: scope['an-entry'] }),
        render: renderEntry
    });

    loaders['an-exit'] = pagedCard({
        id: 'an-exit',
        label: T('Faceting exit pages'),
        empty: T('exit pages'),
        fetch: (start, rows) => api('pages', 'exit', { start: start, rows: rows, scope: scope['an-exit'] }),
        render: renderExit
    });

    loaders['an-trend'] = pagedCard({
        id: 'an-trend',
        label: T('Comparing this period against the one before'),
        empty: T('paths with any movement'),
        fetch: (start, rows) => api('pages', 'trending', { start: start, rows: rows }),
        render: renderTrend
    });

    wireToggle('an-entry');
    wireToggle('an-exit');
}
