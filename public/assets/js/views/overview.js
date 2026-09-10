/*
 * Loghound — Overview view.
 *
 * Renders the five-population traffic band, the totals, the four timing numbers, and the
 * top-pages table with its population toggle.
 *
 * The timing block is the part to be careful with. All four numbers are computed by the
 * server over ONE population — human sessions that produced a beacon — and the caption
 * says how big that population is and how many sessions were left out. A session with no
 * beacon contributes nothing rather than contributing a zero.
 */

'use strict';

import { api, byId, dur, el, hideEmpty, load, noDataYet, num, pct, tbody } from '../core.js';
import { barsH, stackedTraffic, tokens } from '../charts.js';

/** Stacking order, bottom to top: most human at the bottom. */
const ORDER = ['human', 'unknown', 'declared', 'ai', 'evasive'];

/** Set the text of a [data-field] element inside a container. */
function setField(scope, field, value) {
    const node = scope.querySelector('[data-field="' + field + '"]');
    if (node) {
        node.textContent = value;
    }
}

/** Populate the five headline counters. */
function renderTotals(data) {
    const scope = byId('ov-stats');
    if (!scope) {
        return;
    }
    for (const key of ORDER) {
        setField(scope, key, num(data.totals[key]));
    }
    // Give each counter its share of the total, so "812" is readable as "81% of traffic".
    for (const key of ORDER) {
        const stat = scope.querySelector('[data-stat="' + key + '"] .stat-hint');
        if (stat && data.total_sessions) {
            stat.textContent = stat.textContent.replace(/ · .*$/, '') +
                ' · ' + pct(data.totals[key], data.total_sessions) + ' of sessions';
        }
    }
}

/**
 * The four timing numbers plus the comparison bar.
 *
 * The population caption is written before the numbers are, deliberately: it is the thing
 * that stops the comparison being misread, and it must be legible in a screenshot.
 */
function renderTiming(data) {
    const scope = byId('ov-timing');
    const t = data.timing;
    if (!scope) {
        return;
    }

    const fields = [
        ['log_span', t.log_span_p50, t.log_span_avg],
        ['wall', t.wall_p50, t.wall_avg],
        ['visible', t.visible_p50, t.visible_avg],
        ['engaged', t.engaged_p50, t.engaged_avg]
    ];
    for (const [key, p50, avg] of fields) {
        setField(scope, key + '_p50', dur(p50));
        setField(scope, key + '_avg', dur(avg));
    }

    const popNode = byId('ov-timing-pop');
    if (popNode) {
        if (!t.population) {
            popNode.textContent = 'No human session in this range produced beacon data, so wall, visible and ' +
                'engaged time are unknown. They are shown as em-dashes rather than zeroes.';
        } else {
            popNode.textContent =
                'All four numbers cover the same ' + num(t.population) + ' human sessions that produced beacon ' +
                'data — ' + pct(t.population, t.humans) + ' of the ' + num(t.humans) + ' human sessions in this ' +
                'range. The other ' + num(t.without_beacon) + ' had no beacon and are excluded entirely; they are ' +
                'not counted as zero.';
        }
    }

    // The contrast line: what a log-only tool would have reported for ALL human sessions,
    // against what the beacon measured. This is the product's headline claim in one
    // sentence, and it is generated rather than hard-coded so it cannot go stale.
    const note = byId('ov-timing-note');
    if (note && t.population && t.engaged_p50 !== null && t.all_log_span_p50 !== null) {
        const existing = byId('ov-timing-compare');
        if (existing) {
            existing.remove();
        }
        const ratio = t.engaged_p50 > 0 ? (t.wall_p50 / t.engaged_p50) : null;
        const line = el('p', { id: 'ov-timing-compare' }, [
            el('strong', { text: 'On this traffic: ' }),
            'a log-only tool would report a median of ',
            el('span', { class: 'mono', text: dur(t.all_log_span_p50) }),
            ' on site. A JavaScript analytics product would report ',
            el('span', { class: 'mono', text: dur(t.wall_p50) }),
            '. The median visitor was actually engaged for ',
            el('span', { class: 'mono', text: dur(t.engaged_p50) }),
            ratio && ratio >= 1.2
                ? ' — ' + ratio.toFixed(1) + '× less than the wall-clock figure.'
                : '.'
        ]);
        note.insertBefore(line, note.firstChild);
    }

    // A small horizontal comparison, medians only, so the four are seen at a glance.
    const rows = [
        { label: 'Log span', value: t.log_span_p50 || 0, key: 'log_span' },
        { label: 'Wall clock', value: t.wall_p50 || 0, key: 'wall' },
        { label: 'Visible', value: t.visible_p50 || 0, key: 'visible' },
        { label: 'Engaged', value: t.engaged_p50 || 0, key: 'engaged' }
    ];
    const th = tokens();
    barsH('ov-timing-chart', rows.map((r) => ({
        label: r.label,
        value: r.value,
        // Only the honest number gets the accent; the rest are neutral, which is the
        // visual argument the page is making.
        color: r.key === 'engaged' ? th.accent : th.pop.unknown,
        extra: 'median'
    })), { labelWidth: 96, format: dur });
}

/** The stacked traffic band. */
function renderSeries(data) {
    const any = ORDER.some((k) => (data.series[k] || []).some((v) => v > 0));
    if (!any) {
        noDataYet('ov-series-empty', 'sessions');
        return;
    }
    hideEmpty('ov-series-empty');
    stackedTraffic('ov-series', {
        times: data.times,
        series: data.series,
        labels: data.labels
    }, ORDER);
}

/** Top pages, for whichever population the toggle has selected. */
async function loadPages(population) {
    const table = byId('ov-pages');
    const popNode = byId('ov-pages-pop');
    await load('ov-pages-empty', 'top pages', async () => {
        const data = await api('overview', 'toppages', { pop: population });

        if (popNode) {
            popNode.textContent = data.population_label + ' · ' + num(data.total) +
                ' sessions in range. Counted as sessions that requested the path at least once, ' +
                'not as raw request count — a session that reloaded a page ten times counts once.';
        }

        if (!data.rows.length) {
            // replaceChildren, not innerHTML: the panel has exactly one innerHTML path
            // (core.js esc()) and it is never used for data.
            table.tBodies[0].replaceChildren();
            noDataYet('ov-pages-empty', 'page requests');
            return;
        }
        hideEmpty('ov-pages-empty');

        const top = data.rows[0].sessions || 1;
        tbody(table, data.rows.map((row) => ({
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

/** Wire the humans/all/bots toggle. */
function initPageToggle() {
    const group = document.querySelector('.toggle');
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

/** Entry point. */
export default async function init() {
    initPageToggle();

    await load('ov-series-empty', 'the overview', async () => {
        const data = await api('overview', 'summary');
        renderTotals(data);
        renderTiming(data);
        renderSeries(data);
    });

    await loadPages('humans');
}
