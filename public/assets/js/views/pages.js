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
        return false;
    }
    hideEmpty('an-entry-empty');

    setPop('an-entry', data.scope_label + ' · ' + num(data.total) + ' visits in range, counted on the first '
        + 'request of each. A single-request visit has the same entry and exit page.');

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
                title: num(row.single) + ' of ' + num(row.sessions) + ' made no further request.'
            },
            { node: shareBar(row.sessions, data.total, 'visits in range'), sort: row.sessions }
        ]
    })));

    return true;
}

/** Fill the exit-pages table. */
function renderExit(data) {
    if (!data.rows.length) {
        tbody(byId('an-exit-table'), []);
        return false;
    }
    hideEmpty('an-exit-empty');

    setPop('an-exit', data.scope_label + ' · ' + num(data.total) + ' finished visits in range. '
        + num(data.beacon) + ' (' + pct(data.beacon, data.total, 0) + ') had a beacon; for the rest the last '
        + 'log line is all there is.');

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
            { node: shareBar(row.sessions, data.total, 'finished visits'), sort: row.sessions }
        ]
    })));

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
        return false;
    }
    hideEmpty('an-trend-empty');

    setPop('an-trend', 'Against ' + data.baseline + '. Ranked from the ' + num(data.considered) + ' busiest '
        + 'paths across both windows, so a path with little traffic in either is absent however much it grew. '
        + 'This window is still filling and the baseline is complete.');

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
                node: magnitudeBar(Math.abs(row.delta), top, 'the largest change on this page',
                    num(row.prev) + ' before, ' + num(row.now) + ' now'),
                sort: row.delta
            }
        ]
    })));

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
        label: 'Faceting entry pages',
        empty: 'entry pages',
        fetch: (start) => api('pages', 'entry', { start: start, scope: scope['an-entry'] }),
        render: renderEntry
    });

    loaders['an-exit'] = pagedCard({
        id: 'an-exit',
        label: 'Faceting exit pages',
        empty: 'exit pages',
        fetch: (start) => api('pages', 'exit', { start: start, scope: scope['an-exit'] }),
        render: renderExit
    });

    loaders['an-trend'] = pagedCard({
        id: 'an-trend',
        label: 'Comparing this period against the one before',
        empty: 'paths with any movement',
        fetch: (start) => api('pages', 'trending', { start: start }),
        render: renderTrend
    });

    wireToggle('an-entry');
    wireToggle('an-exit');
}
