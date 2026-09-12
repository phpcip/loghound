/*
 * Loghound — Analytics: where they came from.
 *
 * Two tables. The channel table is a closed vocabulary and is therefore NOT paged — every value
 * the parser can emit is on screen whether or not it had traffic, because an absent "Paid ad" row
 * reads as "this panel cannot tell me about paid traffic" rather than as "there was none". The
 * referring-site table is an open set and is paged like every other one.
 */

'use strict';

import { api, byId, hideEmpty, loadCard, noDataYet, num, pct, setPop, tbody } from '../core.js';
import { pagedCard, shareBar } from '../cardtable.js';
import { dimRow, dimValue } from '../identity.js';

/** The population currently selected by the toggles. */
let population = 'humans';

/** Both cards' loaders, so the toggle can restart them. */
const loaders = {};

/**
 * Fill the channel table.
 *
 * Rows with no traffic are kept and greyed rather than dropped, and they sort to the bottom
 * because the server ordered by count. The explanation column is the vocabulary's own sentence,
 * which is where "Direct is a residual, not a channel" gets said per row rather than only in the
 * card's note.
 */
function renderChannels(data) {
    setPop('an-channels', data.population_label + ' · ' + num(data.referred) + ' of ' + num(data.total)
        + ' visits (' + pct(data.referred, data.total, 0) + ') sent a referrer. The rest are Direct, which '
        + 'means none arrived — not that somebody typed your address in.');

    if (!data.rows.length) {
        tbody(byId('an-channels-table'), []);
        noDataYet('an-channels-empty', 'referrer types');
        return;
    }
    hideEmpty('an-channels-empty');

    tbody(byId('an-channels-table'), data.rows.map((row) => ({
        attrs: row.sessions ? dimRow('referer_type_s', row.value) : {},
        cells: [
            { node: dimValue('referer_type_s', row.value), sort: row.label },
            {
                text: num(row.sessions),
                num: true,
                sort: row.sessions,
                class: row.sessions ? null : 'muted'
            },
            { node: shareBar(row.sessions, data.total, 'visits'), sort: row.sessions },
            { text: row.why || '—', class: 'muted wrap', sort: row.label }
        ]
    })));
}

/** Fill the referring-sites table. */
function renderReferrers(data) {
    setPop('an-referrers', data.population_label + ' · shares are of the ' + num(data.referred) + ' visits '
        + 'that sent a referrer, not of all ' + num(data.total) + '.');

    if (!data.rows.length) {
        tbody(byId('an-referrers-table'), []);
        return false;
    }
    hideEmpty('an-referrers-empty');

    tbody(byId('an-referrers-table'), data.rows.map((row) => ({
        attrs: dimRow('referer_host_s', row.host),
        cells: [
            { node: dimValue('referer_host_s', row.host, { mono: true }), clip: true, title: row.host, sort: row.host },
            { text: num(row.sessions), num: true, sort: row.sessions },
            { node: shareBar(row.sessions, data.referred, 'referred visits'), sort: row.sessions }
        ]
    })));

    return true;
}

/** Load the channel card, which has no pages. */
function loadChannels() {
    return loadCard('an-channels', 'Faceting referrer types', async () => {
        renderChannels(await api('sources', 'channels', { pop: population }));
    });
}

/**
 * Wire both population toggles so they move together.
 *
 * TWO CONTROLS, ONE STATE. The toggle appears on both cards because either is a reasonable place
 * to reach for it, and letting them disagree would put two tables on one screen describing two
 * different populations under one heading.
 */
function initToggles() {
    for (const group of document.querySelectorAll('.toggle')) {
        for (const button of group.querySelectorAll('button[data-pop]')) {
            button.addEventListener('click', () => {
                population = button.dataset.pop;
                for (const other of document.querySelectorAll('.toggle button[data-pop]')) {
                    const on = other.dataset.pop === population;
                    other.classList.toggle('on', on);
                    other.setAttribute('aria-pressed', on ? 'true' : 'false');
                }
                loadChannels();
                loaders['an-referrers'](0);
            });
        }
    }
}

/** Entry point. */
export default function init() {
    initToggles();
    loadChannels();
    loaders['an-referrers'] = pagedCard({
        id: 'an-referrers',
        label: 'Faceting referring sites',
        empty: 'referring sites',
        fetch: (start, rows) => api('sources', 'referrers', { start: start, rows: rows, pop: population }),
        render: renderReferrers
    });
}
