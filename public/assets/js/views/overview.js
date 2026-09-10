/*
 * Loghound — Overview view.
 *
 * Four independent cards: the headline counters, the four timing numbers, the stacked
 * traffic band and the top-pages table. Each one is its own request with its own progress
 * line and its own retry, so the timing block appears the moment it is ready instead of
 * waiting on the hourly series, and one slow facet cannot hold up the page.
 */

'use strict';

import { api, byId, cardChart, dur, el, hideEmpty, loadCard, noDataYet, num, pct, setPop, tbody } from '../core.js';
import { barsH, stackedTraffic, tokens } from '../charts.js';

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
        ' (approximate above ~100).');
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
            cells: [
                { text: row.path, mono: true, clip: true },
                { text: num(row.sessions), num: true },
                {
                    node: el('span', { class: 'bar' }, [
                        el('span', { style: 'width:' + Math.round((row.sessions / top) * 100) + '%' })
                    ])
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

    loadCard('ov-stats', 'Counting sessions by verdict', async () => {
        renderTotals(await api('overview', 'totals'));
    });
    loadCard('ov-timing', 'Measuring dwell time across four clocks', async () => {
        renderTiming(await api('overview', 'timing'));
    });
    loadCard('ov-series', 'Bucketing sessions by hour', async () => {
        renderSeries(await api('overview', 'series'));
    });
    loadPages('humans');
}
