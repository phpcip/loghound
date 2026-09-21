/*
 * Loghound — Analytics: where they came from.
 *
 * Two tables. The channel table is a closed vocabulary and is therefore NOT paged — every value
 * the parser can emit is on screen whether or not it had traffic, because an absent "Paid ad" row
 * reads as "this panel cannot tell me about paid traffic" rather than as "there was none". The
 * referring-site table is an open set and is paged like every other one.
 */

'use strict';

import { api, byId, el, hideEmpty, loadCard, noDataYet, num, pct, setPop, tbody } from '../core.js';
import { pagedCard, shareBar } from '../cardtable.js';
import { dimRow, dimValue } from '../identity.js';
import { renderPager } from '../pager.js';
import { hrefLink } from '../url.js';
import { clearTableChart, rankChart } from '../tablecharts.js';
import { t as T, tn as Tn, tf as Tf, tfn as Tfn } from '../i18n.js';

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
    setPop('an-channels', data.population_label + ' · ' + T('{n} of {total} visits ({pct}) sent a referrer. The rest are Direct, which '
        + 'means none arrived — not that somebody typed your address in.', { n: num(data.referred), total: num(data.total), pct: pct(data.referred, data.total, 0) }));

    if (!data.rows.length) {
        tbody(byId('an-channels-table'), []);
        clearTableChart('an-channels');
        noDataYet('an-channels-empty', T('referrer types'));
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
            { node: shareBar(row.sessions, data.total, T('visits')), sort: row.sessions },
            { text: row.why || '—', class: 'muted wrap', sort: row.label }
        ]
    })));

    rankChart('an-channels', data.rows.map((row) => ({ label: row.label, value: row.sessions })),
        { label: T('Visits per referrer type') });
}

/** Fill the referring-sites table. */
function renderReferrers(data) {
    setPop('an-referrers', data.population_label + ' · ' + T('shares are of the {n} visits '
        + 'that sent a referrer, not of all {total}.', { n: num(data.referred), total: num(data.total) }));

    if (!data.rows.length) {
        tbody(byId('an-referrers-table'), []);
        clearTableChart('an-referrers');
        return false;
    }
    hideEmpty('an-referrers-empty');

    tbody(byId('an-referrers-table'), data.rows.map((row) => ({
        attrs: dimRow('referer_host_s', row.host),
        cells: [
            { node: hostCell(row.host), clip: true, title: row.host, sort: row.host },
            { text: num(row.sessions), num: true, sort: row.sessions },
            { node: shareBar(row.sessions, data.referred, T('referred visits')), sort: row.sessions }
        ]
    })));

    rankChart('an-referrers', data.rows.map((row) => ({ label: row.host, value: row.sessions })),
        { label: T('Referred visits per referring site') });

    return true;
}

/**
 * A referring site's cell: the expander that lists the full URLs it sent, then the host filter.
 *
 * The open list is a `<tr class="members ref-urls">` under the row, the shape the fingerprint
 * table already uses. It lives only in the DOM: a reload replaces the tbody, and every expander
 * comes back closed with nothing under it, so there is no separate state to fall out of step.
 */
function hostCell(host) {
    const button = el('button', {
        type: 'button',
        class: 'expander',
        'aria-expanded': 'false',
        'aria-label': T('Show the full referrer URLs from {host}', { host: host }),
        text: '+'
    });
    button.addEventListener('click', (event) => {
        event.stopPropagation();
        toggleUrls(button, host);
    });
    return el('span', { class: 'ref-host' }, [button, dimValue('referer_host_s', host, { mono: true })]);
}

/** Open or close the URL list under a referring site's row. */
function toggleUrls(button, host) {
    const tr = button.closest('tr');
    const next = tr.nextElementSibling;

    if (next && next.classList.contains('ref-urls')) {
        next.remove();
        button.textContent = '+';
        button.setAttribute('aria-expanded', 'false');
        return;
    }

    button.textContent = '−';
    button.setAttribute('aria-expanded', 'true');

    const inner = el('div', { class: 'members-inner' });
    tr.parentNode.insertBefore(el('tr', { class: 'members ref-urls' }, [
        el('td', { colspan: '3' }, [inner])
    ]), tr.nextSibling);

    loadUrls(inner, host, 0);
}

/** Fetch one page of a site's referrer URLs into the open row, with a retry in place on failure. */
async function loadUrls(inner, host, start, rows) {
    inner.replaceChildren(el('p', { class: 'muted', text: T('Loading referrer URLs…') }));
    try {
        const data = await api('sources', 'referrer_urls', {
            host: host,
            start: start,
            rows: rows,
            pop: population
        });
        renderUrls(inner, host, data);
    } catch (err) {
        const again = el('button', { type: 'button', class: 'small', text: T('Try again') });
        again.addEventListener('click', () => loadUrls(inner, host, start, rows));
        inner.replaceChildren(
            el('p', { class: 'muted', text: T('Could not load referrer URLs: {error}', { error: String(err && err.message ? err.message : err) }) }),
            el('div', { class: 'card-error-actions' }, [again])
        );
    }
}

/**
 * The URL list itself: every full referrer this site sent, wrapped rather than cut, each with the
 * ↗ that opens it. The href is the server's safeUrl() answer and hrefLink() refuses anything else.
 */
function renderUrls(inner, host, data) {
    if (!data.rows.length) {
        inner.replaceChildren(el('p', { class: 'muted', text: T('No full referrer URL is stored for {host} in this range.', { host: host }) }));
        return;
    }

    const table = el('table', { class: 'table-fixed' }, [
        el('colgroup', {}, [el('col', { style: 'width:84%' }), el('col', { style: 'width:16%' })]),
        el('thead', {}, [el('tr', {}, [
            el('th', { scope: 'col', text: T('Referring page') }),
            el('th', { scope: 'col', class: 'num', text: T('Visits') })
        ])]),
        el('tbody', {}, data.rows.map((row) => el('tr', {}, [
            el('td', { class: 'wrap' }, [
                el('span', { class: 'mono', text: row.url }),
                hrefLink(row.href)
            ]),
            el('td', { class: 'num', text: num(row.sessions) })
        ])))
    ]);

    const mount = el('div', { class: 'pager-mount' });
    inner.replaceChildren(el('div', { class: 'table-wrap' }, [table]), mount);
    renderPager(mount, data.page, (start, rows) => loadUrls(inner, host, start, rows || data.page.rows));
}

/** Load the channel card, which has no pages. */
function loadChannels() {
    return loadCard('an-channels', T('Faceting referrer types'), async () => {
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
        label: T('Faceting referring sites'),
        empty: T('referring sites'),
        fetch: (start, rows) => api('sources', 'referrers', { start: start, rows: rows, pop: population }),
        render: renderReferrers
    });
}
