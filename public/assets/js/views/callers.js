/*
 * Loghound — Who is querying view.
 *
 * The correlation card has three quite different things to say depending on what is
 * actually available, and the copy matters as much as the numbers:
 *
 *   ok           — both halves are present; the split is real and is shown.
 *   no_web_data  — Loghound holds Opensolr credentials but is not watching the web server
 *                  that fronts this index. Nothing is broken, and the card says, in terms of
 *                  the addresses already on the screen, what installing it there would add.
 *   unavailable  — the local sessions index could not be reached. That is a local fault and
 *                  is worded as one, never as a missing feature.
 *
 * The one thing this card must never do is claim a security finding it cannot support. "No
 * web traffic at all" is only ever shown when the web side actually answered; if the
 * sessions index is down, every address is undecided, because an absent lookup is not
 * evidence of absence.
 */

'use strict';

import { api, byId, el, hideEmpty, loadCard, num, pct, setPop, tbody } from '../core.js';
import { barsH, dispose, donut } from '../charts.js';
import {
    chartOrEmpty, fieldSetter, handleState, lfAdd, lfRemove, plotOrNote, renderFilters,
    renderVolume, resolveCore, shareBar, tokens
} from './opensolr.js';

/** How each classification is labelled and chipped in the table. */
const CLASSES = {
    bot: { label: 'Scored as a bot', chip: 'chip-bad' },
    human: { label: 'Looks human', chip: 'chip-good' },
    unknown: { label: 'Undecided', chip: '' },
    unseen: { label: 'Never seen on the site', chip: 'chip-accent' }
};

/**
 * A cell whose text is a link that filters the whole page to that value.
 *
 * The point of this page is finding the caller that should not be there; having found one,
 * the next question is always "what is it doing", and that is the volume chart and the handler
 * split on this same page narrowed to it. A real <a> so it can be opened in a new tab, and
 * because the CSP forbids an inline handler.
 */
function pickCell(field, value, active, extra) {
    const on = Array.isArray((active || {})[field]) && active[field].indexOf(value) !== -1;
    return Object.assign({
        node: el('a', {
            href: on ? lfRemove(field, value) : lfAdd(field, value),
            title: (on ? 'Remove this filter: ' : 'Filter this page to ') + value,
            text: value
        })
    }, extra || {});
}

/**
 * Fill the busiest-addresses and handlers cards: a chart each, then the exact table.
 */
function renderWho(data) {
    if (handleState('cl-who-empty', data, 'requests')) {
        tbody(byId('cl-ips-table'), []);
        tbody(byId('cl-handlers-table'), []);
        return;
    }
    hideEmpty('cl-who-empty');

    const ips = Object.keys(data.addresses);
    const handlers = Object.keys(data.handlers);
    const handlerTotal = handlers.reduce((sum, key) => sum + data.handlers[key], 0);

    if (!chartOrEmpty('cl-ips-chart', 'cl-who-empty', ips.length, 'No caller recorded', [
        'The platform returned no client address for these requests, so there is nobody to list.'
    ])) {
        barsH('cl-ips-chart', ips.slice(0, 12).map((ip) => ({
            label: ip,
            value: data.addresses[ip],
            extra: pct(data.addresses[ip], data.requests) + ' of every logged request'
        })));
    }

    if (!plotOrNote('cl-handlers-chart', handlers.length,
        'The platform recorded no handler for these requests, so there is no endpoint to plot.')) {
        barsH('cl-handlers-chart', handlers.slice(0, 12).map((path) => ({
            label: path,
            value: data.handlers[path],
            extra: pct(data.handlers[path], handlerTotal) + ' of the requests listed'
        })));
    }

    tbody(byId('cl-ips-table'), ips.map((ip) => ({
        attrs: { class: 'lf-pick' },
        cells: [
            pickCell('ip', ip, data.active, { mono: true, nowrap: true }),
            { text: num(data.addresses[ip]), num: true, sort: data.addresses[ip] },
            { node: shareBar(data.addresses[ip], data.requests) }
        ]
    })));

    tbody(byId('cl-handlers-table'), handlers.map((path) => ({
        attrs: { class: 'lf-pick' },
        cells: [
            pickCell('path', path, data.active, { mono: true, clip: true }),
            { text: num(data.handlers[path]), num: true, sort: data.handlers[path] },
            { node: shareBar(data.handlers[path], handlerTotal) }
        ]
    })));

    setPop('cl-who',
        'The ' + num(ips.length) + ' busiest addresses out of every client that queried this index in ' +
        'the selected range, accounting for ' + num(data.covered) + ' of ' + num(data.requests) +
        ' requests (' + pct(data.covered, data.requests) + '). The list is capped at ' + num(data.limit) +
        ' addresses, so a long tail of one-off callers is not shown.');
}

/**
 * Fill the correlation headline, the state explainer and the table.
 */
function renderCross(data) {
    const set = fieldSetter('cl-cross');

    if (handleState('cl-cross-empty', data, 'requests')) {
        tbody(byId('cl-cross-table'), []);
        return;
    }
    hideEmpty('cl-cross-empty');

    const classes = data.by_class || {};
    const web = data.web_state;

    for (const key of ['bot', 'human', 'unseen', 'unknown']) {
        set(key, web === 'ok' ? num(classes[key] || 0) : '—');
    }

    renderClassChart(data);
    renderCrossState(data);

    tbody(byId('cl-cross-table'), (data.rows || []).map((row) => ({
        attrs: { class: 'lf-pick' },
        cells: [
            pickCell('ip', row.ip, data.active, { mono: true, nowrap: true }),
            { text: num(row.requests), num: true, sort: row.requests },
            {
                node: el('span', {
                    class: 'chip ' + (CLASSES[row.class] ? CLASSES[row.class].chip : ''),
                    text: CLASSES[row.class] ? CLASSES[row.class].label : row.class
                })
            },
            { text: row.sessions === null ? '—' : num(row.sessions), num: true },
            { text: row.botlike === null ? '—' : num(row.botlike), num: true },
            { text: row.human === null ? '—' : num(row.human), num: true }
        ]
    })));

    setPop('cl-cross', crossPopulation(data));
}

/**
 * Draw the split of search work across the four classifications.
 *
 * A donut, because this is a composition of one whole: every request covered by the facet is
 * attributed to exactly one of the four, so the arcs sum to the figure in the centre. It is
 * drawn ONLY when the web side actually answered — the four figures above it are em-dashes
 * otherwise, and a chart of four zeroes under four em-dashes would look like a measurement
 * rather than the absence of one.
 */
function renderClassChart(data) {
    const classes = data.by_class || {};
    const t = tokens();

    if (data.web_state !== 'ok') {
        dispose('cl-cross-chart');
        return;
    }

    const rows = [
        { key: 'bot', label: 'Serving bots', color: t.pop.evasive },
        { key: 'human', label: 'Serving people', color: t.pop.human },
        { key: 'unseen', label: 'No web traffic at all', color: t.pop.ai },
        { key: 'unknown', label: 'Undecided', color: t.pop.unknown }
    ].filter((row) => (classes[row.key] || 0) > 0)
        .map((row) => ({ label: row.label, value: classes[row.key], color: row.color }));

    if (!rows.length) {
        dispose('cl-cross-chart');
        return;
    }

    donut('cl-cross-chart', rows, 'requests', num(data.covered));
}

/**
 * The sentence under the correlation headline, which changes with what is available.
 */
function crossPopulation(data) {
    const base = 'The ' + num(data.addresses) + ' busiest addresses on the search side, covering ' +
        num(data.covered) + ' of ' + num(data.requests) + ' requests (' +
        pct(data.covered, data.requests) + ') in this range. ';

    if (data.web_state === 'ok') {
        return base + 'Each address is classified by the majority of its web sessions in the same range, ' +
            'out of ' + num(data.web_sessions) + ' sessions Loghound recorded. Addresses with no web ' +
            'sessions at all are counted separately rather than assumed to be anything.';
    }
    if (data.web_state === 'no_web_data') {
        return base + 'Loghound has no web sessions in this range to compare them against, so no address ' +
            'is classified.';
    }
    return base + 'The classification could not be computed, so no address is classified.';
}

/**
 * Explain the state of the web half, in concrete terms rather than as an upsell.
 */
function renderCrossState(data) {
    const mount = byId('cl-cross-state');
    if (!mount) {
        return;
    }

    if (data.web_state === 'ok') {
        const classes = data.by_class || {};
        const botShare = pct(classes.bot || 0, data.covered);
        const unseen = classes.unseen || 0;
        mount.replaceChildren(el('p', { class: 'note' }, [
            el('strong', { text: botShare + ' of the search work above was done for bots. ' }),
            unseen > 0
                ? el('span', {
                    text: num(unseen) + ' requests came from addresses that never appear in your web logs ' +
                        'at all — they did not reach the index through your website. Look for a server-side ' +
                        'integration or a monitoring check first; if there is not one, that is an index ' +
                        'being read directly by somebody you did not authorise.'
                })
                : el('span', {
                    text: 'Every address querying the index also appears in your web logs, which is what ' +
                        'you want: nothing is reaching the index except through the site.'
                })
        ]));
        return;
    }

    if (data.web_state === 'no_web_data') {
        mount.replaceChildren(el('div', { class: 'note' }, [
            el('h4', { text: 'Loghound is not watching the web server in front of this index' }),
            el('p', {
                text: 'Everything above is real: these are the addresses that queried your search index, ' +
                    'and those are the request counts. What is missing is the other half. Loghound has no ' +
                    'web sessions in this time range, which means it is not reading the access log of the ' +
                    'site that fronts this index — either it runs on a different machine, or the tailer is ' +
                    'not running.'
            }),
            el('p', {
                text: 'Installed where that web server runs, this same table would tell you which of those ' +
                    'addresses were people, which were scrapers that Loghound had already caught by their ' +
                    'headers and their behaviour, and — the one worth having — which of them query your ' +
                    'index without ever loading a page, because those did not come through your website at all.'
            }),
            el('p', {}, [
                'Point Loghound at that server\'s access log under ',
                el('a', { href: '?v=settings', text: 'Settings' }),
                ', or install a second copy of it there. Nothing about this page changes if you do not: ',
                'the search-side numbers are complete on their own.'
            ])
        ]));
        return;
    }

    if (data.web_state === 'no_addresses') {
        mount.replaceChildren();
        return;
    }

    mount.replaceChildren(el('div', { class: 'note' }, [
        el('h4', { text: 'The web half could not be read' }),
        el('p', { text: data.web_note || 'Loghound\'s own sessions index did not answer.' }),
        el('p', {
            text: 'This is a local fault, not a missing feature: the search-side numbers above came back ' +
                'fine. Until it is fixed, no address is classified — an address Loghound could not look ' +
                'up is undecided, never "not seen".'
        })
    ]));
}

/**
 * Load both cards for the current index.
 */
function refresh() {
    loadCard('cl-filters', 'Faceting the request log', async () => {
        const chosen = await resolveCore('callers', 'cl-core', refresh);
        renderFilters('cl-filters', chosen === null
            ? { state: 'no_index', requests: 0, groups: [], active: {}, ignored: [] }
            : await api('callers', 'facets', { core: chosen }));
    });

    loadCard('cl-volume', 'Faceting request volume', async () => {
        const chosen = await resolveCore('callers', 'cl-core', refresh);
        renderVolume('cl-volume', chosen === null
            ? { state: 'no_index', requests: 0, all: [], times: [] }
            : await api('callers', 'volume', { core: chosen }));
    });

    loadCard('cl-who', 'Faceting client addresses', async () => {
        const chosen = await resolveCore('callers', 'cl-core', refresh);
        renderWho(chosen === null
            ? { state: 'no_index', requests: 0, addresses: {}, handlers: {} }
            : await api('callers', 'who', { core: chosen }));
    });

    loadCard('cl-cross', 'Matching search clients against web sessions', async () => {
        const chosen = await resolveCore('callers', 'cl-core', refresh);
        renderCross(chosen === null
            ? { state: 'no_index', requests: 0, rows: [], by_class: {}, web_state: 'no_addresses' }
            : await api('callers', 'cross', { core: chosen }));
    });
}

/**
 * Entry point. Absent when the installation has no Opensolr credentials, because the view
 * renders an explanation instead of cards.
 */
export default function init() {
    if (!byId('cl-filters-card')) {
        return;
    }
    refresh();
}
