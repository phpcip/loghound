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
import { handleState, resolveCore, shareBar } from './opensolr.js';

/** How each classification is labelled and chipped in the table. */
const CLASSES = {
    bot: { label: 'Scored as a bot', chip: 'chip-bad' },
    human: { label: 'Looks human', chip: 'chip-good' },
    unknown: { label: 'Undecided', chip: '' },
    unseen: { label: 'Never seen on the site', chip: 'chip-accent' }
};

/**
 * Fill the busiest-addresses and handlers tables.
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

    tbody(byId('cl-ips-table'), ips.map((ip) => ({
        cells: [
            { text: ip, mono: true, nowrap: true },
            { text: num(data.addresses[ip]), num: true },
            { node: shareBar(data.addresses[ip], data.requests) }
        ]
    })));

    tbody(byId('cl-handlers-table'), handlers.map((path) => ({
        cells: [
            { text: path, mono: true, clip: true },
            { text: num(data.handlers[path]), num: true },
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
    const scope = byId('cl-cross-content');
    const set = (field, value) => {
        const node = scope ? scope.querySelector('[data-field="' + field + '"]') : null;
        if (node) {
            node.textContent = value;
        }
    };

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

    renderCrossState(data);

    tbody(byId('cl-cross-table'), (data.rows || []).map((row) => ({
        cells: [
            { text: row.ip, mono: true, nowrap: true },
            { text: num(row.requests), num: true },
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
    if (!byId('cl-who-card')) {
        return;
    }
    refresh();
}
