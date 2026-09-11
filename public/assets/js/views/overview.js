/*
 * Loghound — Overview view.
 *
 * Independent cards: the headline counters, the four timing numbers, the stacked traffic
 * band, the top-pages table and the search terms. Each one is its own request with its own
 * progress line and its own retry, so the timing block appears the moment it is ready
 * instead of waiting on the hourly series, and one slow facet cannot hold up the page.
 */

'use strict';

import {
    api, byId, cardChart, dur, el, hideEmpty, loadCard, noDataYet, noPivotYet, num, pct, setPop,
    showEmpty, tbody
} from '../core.js';
import { barsH, stackedTraffic, tokens } from '../charts.js';
import { dimRow } from '../identity.js';
import { renderPivot } from '../facetfilter.js';

/** Stacking order, bottom to top: most human at the bottom. */
const ORDER = ['human', 'unknown', 'declared', 'ai', 'evasive'];

/**
 * Set the text of a [data-field] element inside a container.
 */
function setField(scope, field, value) {
    const node = scope ? scope.querySelector('[data-field="' + field + '"]') : null;
    if (node) {
        node.textContent = value;
    }
}

/**
 * Fill the five headline counters and give each one its share of the total.
 */
function renderTotals(data) {
    const scope = byId('ov-stats-content');
    for (const key of ORDER) {
        setField(scope, key, num(data.totals[key]));
        const hint = scope ? scope.querySelector('[data-stat="' + key + '"] .stat-hint') : null;
        if (hint && data.total_sessions) {
            hint.textContent = hint.textContent.replace(/ · .*$/, '') +
                ' · ' + pct(data.totals[key], data.total_sessions) + ' of sessions';
        }
    }
    setPop('ov-stats', num(data.total_sessions) + ' scored sessions in the selected range, split into five ' +
        'mutually exclusive populations. Distinct human visitors: ' + num(data.human_detail.visitors) +
        ' (approximate above ~100).' + (data.pending ? ' ' + data.pending : ''));
}

/**
 * Fill the four timing numbers, their caption and the comparison bar.
 *
 * The population caption is written before the numbers so the comparison cannot be read
 * without its denominator, which is the entire point of the card.
 */
function renderTiming(data) {
    const scope = byId('ov-timing-content');
    const t = data.timing;

    for (const [key, p50, avg] of [
        ['log_span', t.log_span_p50, t.log_span_avg],
        ['wall', t.wall_p50, t.wall_avg],
        ['visible', t.visible_p50, t.visible_avg],
        ['engaged', t.engaged_p50, t.engaged_avg]
    ]) {
        setField(scope, key + '_p50', dur(p50));
        setField(scope, key + '_avg', dur(avg));
    }

    setPop('ov-timing', t.population
        ? 'All four numbers cover the same ' + num(t.population) + ' human sessions that produced beacon data — ' +
          pct(t.population, t.humans) + ' of the ' + num(t.humans) + ' human sessions in this range. The other ' +
          num(t.without_beacon) + ' had no beacon and are excluded entirely; they are not counted as zero.'
        : 'No human session in this range produced beacon data, so wall, visible and engaged time are unknown. ' +
          'They are shown as em-dashes rather than zeroes.');

    /* The mixed-planes caveat is revealed only when the range actually holds sessions with no
       transport plane. On a single-machine install it describes nothing. */
    const planes = byId('ov-timing-planes');
    if (planes) {
        planes.hidden = !t.beacon_only;
    }

    renderTimingComparison(t);
    renderTimingBars(t);
}

/**
 * Generate the one-sentence contrast between what other tools would report and what the
 * beacon measured, so the claim cannot go stale against the data on screen.
 */
function renderTimingComparison(t) {
    const note = byId('ov-timing-note');
    const existing = byId('ov-timing-compare');
    if (existing) {
        existing.remove();
    }
    if (!note || !t.population || t.engaged_p50 === null || t.all_log_span_p50 === null) {
        return;
    }
    const ratio = t.engaged_p50 > 0 ? (t.wall_p50 / t.engaged_p50) : null;
    note.insertBefore(el('p', { id: 'ov-timing-compare' }, [
        el('strong', { text: 'On this traffic: ' }),
        'a log-only tool would report a median of ',
        el('span', { class: 'mono', text: dur(t.all_log_span_p50) }),
        ' on site. A JavaScript analytics product would report ',
        el('span', { class: 'mono', text: dur(t.wall_p50) }),
        '. The median visitor was actually engaged for ',
        el('span', { class: 'mono', text: dur(t.engaged_p50) }),
        ratio && ratio >= 1.2 ? ' — ' + ratio.toFixed(1) + '× less than the wall-clock figure.' : '.'
    ]), note.firstChild);
}

/**
 * Draw the four medians as one horizontal comparison, with the accent on the honest
 * number and nothing else.
 */
function renderTimingBars(t) {
    const th = tokens();
    barsH('ov-timing-chart', [
        { label: 'Log span', value: t.log_span_p50 || 0, key: 'log_span' },
        { label: 'Wall clock', value: t.wall_p50 || 0, key: 'wall' },
        { label: 'Visible', value: t.visible_p50 || 0, key: 'visible' },
        { label: 'Engaged', value: t.engaged_p50 || 0, key: 'engaged' }
    ].map((row) => ({
        label: row.label,
        value: row.value,
        color: row.key === 'engaged' ? th.accent : th.pop.declared,
        extra: 'median'
    })), { labelWidth: 100, format: dur });
}

/**
 * Draw the stacked traffic band, or explain why there is nothing to draw.
 */
function renderSeries(data) {
    const any = ORDER.some((key) => (data.series[key] || []).some((value) => value > 0));
    if (!any) {
        noDataYet('ov-series-empty', 'sessions');
        return;
    }
    hideEmpty('ov-series-empty');
    cardChart('ov-series', 340);
    stackedTraffic('ov-series', { times: data.times, series: data.series, labels: data.labels }, ORDER);
}

/**
 * Load the top-pages table for one population.
 */
function loadPages(population) {
    return loadCard('ov-pages', 'Faceting requested paths', async () => {
        const data = await api('overview', 'toppages', { pop: population });

        setPop('ov-pages', data.population_label + ' · ' + num(data.total) + ' sessions in range. Counted as ' +
            'sessions that requested the path at least once, not as raw request count.');

        if (!data.rows.length) {
            tbody(byId('ov-pages-table'), []);
            noDataYet('ov-pages-empty', 'page requests');
            return;
        }
        hideEmpty('ov-pages-empty');

        const top = data.rows[0].sessions || 1;
        tbody(byId('ov-pages-table'), data.rows.map((row) => ({
            attrs: dimRow('paths_ss', row.path),
            cells: [
                { text: row.path, mono: true, clip: true, sort: row.path },
                { text: num(row.sessions), num: true, sort: row.sessions },
                {
                    node: el('span', { class: 'bar' }, [
                        el('span', { style: 'width:' + Math.round((row.sessions / top) * 100) + '%' })
                    ]),
                    sort: row.sessions
                }
            ]
        })));
    });
}

/**
 * Load the search-terms table.
 *
 * Two empty states, and telling them apart is the whole value of the card. "Nothing is
 * configured" sends the operator to Settings; "nothing was searched for" is a fact about the
 * range. Rendering the generic one for both would send somebody hunting for a bug in their own
 * search page when the feature had simply never been switched on.
 */
function loadSearches() {
    return loadCard('ov-searches', 'Faceting search terms', async () => {
        const data = await api('overview', 'searches');

        /* THE FEATURE IS NOT CONFIGURED, which is a different fact from "no search terms in
           this range" and needs its own sentence rather than a whole explanation crammed into
           noDataYet()'s NOUN slot. It rendered, verbatim: "No search terms — name the query
           parameters your search box uses in beacon.query_params (Settings → Beacon) and they
           start appearing here in this time range" — and leaked a config key into a heading.
           The setting is named where it can be marked as one, and the link goes to the page
           that changes it rather than telling the reader where to look for it. */
        if (!data.configured.length) {
            setPop('ov-searches', 'Not collecting any search terms.');
            tbody(byId('ov-searches-table'), []);
            showEmpty('ov-searches-empty', 'Search terms are not being collected', [
                'Loghound reads a search term out of the URL, and only from the query parameters you '
                    + 'have named. None are named on this installation, so nothing is collected and '
                    + 'nothing can appear here.',
                el('p', {}, [
                    'Name the parameter your search box uses — ',
                    el('code', { text: 'q' }),
                    ', ',
                    el('code', { text: 's' }),
                    ' or whatever your site puts in the address — under ',
                    el('a', { href: '?v=settings#set-beacon-card', text: 'Settings, in the beacon section' }),
                    '. Terms start appearing here from the next visit onwards; nothing is recovered '
                    + 'retrospectively.'
                ])
            ]);
            return;
        }

        setPop('ov-searches', num(data.searched) + ' of ' + num(data.total) + ' sessions in range ran a ' +
            'search. Counted as sessions that searched for a term at least once, not as the number of ' +
            'searches: a visitor who ran the same search six times counts once.');

        if (!data.rows.length) {
            tbody(byId('ov-searches-table'), []);
            noDataYet('ov-searches-empty', 'search terms');
            return;
        }
        hideEmpty('ov-searches-empty');

        const top = data.rows[0].sessions || 1;
        tbody(byId('ov-searches-table'), data.rows.map((row) => ({
            attrs: dimRow('search_terms_ss', row.term),
            cells: [
                { text: row.term, clip: true, sort: row.term },
                { text: num(row.sessions), num: true, sort: row.sessions },
                {
                    node: el('span', { class: 'bar' }, [
                        el('span', { style: 'width:' + Math.round((row.sessions / top) * 100) + '%' })
                    ]),
                    sort: row.sessions
                }
            ]
        })));
    });
}

/**
 * Wire the humans/all/bots toggle.
 */
function initPageToggle() {
    const group = document.querySelector('[data-card="ov-pages"] .toggle');
    if (!group) {
        return;
    }
    for (const button of group.querySelectorAll('button[data-pop]')) {
        button.addEventListener('click', () => {
            for (const other of group.querySelectorAll('button')) {
                other.classList.remove('on');
                other.setAttribute('aria-pressed', 'false');
            }
            button.classList.add('on');
            button.setAttribute('aria-pressed', 'true');
            loadPages(button.dataset.pop);
        });
    }
}

/**
 * Entry point. The four loads are started together and settle independently.
 */
export default function init() {
    initPageToggle();

    /* ONE request, TWO cards. The cross-tab rides on this payload rather than fetching again,
       so the pivot costs no extra round trip — but it is its own card, so it keeps its own
       progress line and its own failure state. Both await the same promise. */
    const totals = api('overview', 'totals');
    loadCard('ov-stats', 'Counting sessions by verdict', async () => {
        renderTotals(await totals);
    });
    if (byId('ov-pivot-table')) {
        loadCard('ov-pivot', 'Cross-tabulating the filtered population', async () => {
            const data = await totals;
            if (!renderPivot('ov-pivot', data.pivot)) {
                noPivotYet('ov-pivot-empty', 'both of its dimensions set');
            }
        });
    }
    loadCard('ov-timing', 'Measuring dwell time across four clocks', async () => {
        renderTiming(await api('overview', 'timing'));
    });
    loadCard('ov-series', 'Bucketing sessions by hour', async () => {
        renderSeries(await api('overview', 'series'));
    });
    loadPages('humans');
    loadSearches();
}
