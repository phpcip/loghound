/*
 * Loghound — Index analytics view.
 *
 * Five independent cards, five independent requests, five independent failures. Changing
 * the index reloads all five, and each still settles on its own.
 *
 * Every number states its population. The QTime percentiles are read off a bucketed
 * histogram and are rendered with a "≤" for exactly that reason: the platform's request-log
 * endpoint cannot carry a JSON Facet, so Solr's own percentile aggregate is not available
 * here and a histogram is what there is. Printing "p95: 47 ms" from a 10 ms histogram would
 * look precise and would not be.
 */

'use strict';

import {
    api, bytes, byId, dec, dur, el, hideEmpty, loadCard, num, pct, setPop, tbody
} from '../core.js';
import { barsH, donut, draw } from '../charts.js';
import {
    chartOrEmpty, fieldSetter, handleState, histPercentile, lfAdd, lfRemove, renderFilters,
    renderVolume, resolveCore, shareBar, stateMessage, tokens
} from './opensolr.js';

/** Plain-English meaning for the status codes an index actually answers with. */
const STATUS_MEANING = {
    200: 'OK',
    400: 'Bad request — the query was malformed',
    401: 'Unauthorised — the caller did not authenticate',
    403: 'Forbidden — blocked by the index firewall',
    404: 'Not found — no such core or handler',
    413: 'Payload too large',
    429: 'Too many requests — rate limited',
    500: 'Internal error inside Solr',
    502: 'Bad gateway — the node did not answer',
    503: 'Service unavailable — the node was busy or down',
    504: 'Gateway timeout'
};

/**
 * Fill the headline stats and the caption that says what they cover.
 */
function renderHeadline(data) {
    const set = fieldSetter('ix-headline');
    const message = stateMessage(data);
    if (message) {
        for (const key of ['requests', 'zero', 'qmean', 'qmax', 'size']) {
            set(key, '—');
        }
        setPop('ix-headline', message);
        return;
    }

    const qtime = data.qtime || {};
    const size = data.size || {};

    set('requests', num(data.requests));
    set('zero', data.zero === null ? '—' : num(data.zero));
    set('qmean', qtime.mean === null || qtime.mean === undefined ? '—' : dur(qtime.mean));
    set('qmax', qtime.max === null || qtime.max === undefined ? '—' : dur(qtime.max));
    set('size', size.mean === null || size.mean === undefined ? '—' : bytes(size.mean * 1024));

    setPop('ix-headline',
        num(data.requests) + ' requests logged for ' + (data.core || 'this index') + ' in this range. ' +
        (data.zero === null
            ? 'The zero-result share could not be read.'
            : num(data.zero) + ' of them (' + dec(data.zero_pct, 1) + '%) matched no documents.') +
        ' QTime is Solr\'s own measure of time spent answering and excludes network and queueing. ' +
        'Response size is what Opensolr recorded going back to the caller.');
}

/**
 * Draw the QTime histogram and read the percentiles off it.
 */
function renderQtime(data) {
    const set = fieldSetter('ix-qtime');

    if (handleState('ix-qtime-empty', data, 'requests')) {
        return;
    }

    const edges = Object.keys(data.buckets).map(Number).sort((a, b) => a - b);
    const counts = edges.map((edge) => data.buckets[String(edge)] || 0);
    const over = data.over || 0;

    if (chartOrEmpty('ix-qtime-chart', 'ix-qtime-empty', edges.length, 'No latency to plot', [
        'The platform returned no QTime buckets for these requests, so there is no distribution to draw.'
    ])) {
        return;
    }

    const hist = counts.concat([over]);
    const upper = edges.map((edge) => edge + data.gap);
    const readAt = (p) => {
        const value = histPercentile(hist, upper, p);
        if (value === null) {
            return '—';
        }
        return value === Infinity ? '> ' + dur(data.ceiling) : '≤ ' + dur(value);
    };

    set('p50', readAt(0.5));
    set('p95', readAt(0.95));
    set('p99', readAt(0.99));
    set('over', num(over));

    const labels = edges.map((edge) => edge + '–' + (edge + data.gap));
    labels.push('> ' + data.ceiling);

    draw('ix-qtime-chart', (theme) => ({
        grid: { top: 12, bottom: 4 },
        tooltip: {
            trigger: 'axis',
            axisPointer: { type: 'shadow', shadowStyle: { color: theme.sunken } },
            formatter: (params) => {
                const p = params[0];
                return String(p.name) + ' ms<br><strong>' + num(p.value) + '</strong> requests';
            }
        },
        xAxis: {
            type: 'category',
            data: labels,
            axisLine: { lineStyle: { color: theme.border } },
            axisTick: { show: false },
            axisLabel: { color: theme.axis, fontSize: 14, interval: 9 }
        },
        yAxis: {
            type: 'value',
            axisLine: { show: false },
            axisTick: { show: false },
            splitLine: { lineStyle: { color: theme.grid, type: 'dashed' } },
            axisLabel: { color: theme.axis, fontSize: 14, formatter: (v) => num(v) }
        },
        series: [{
            type: 'bar',
            barCategoryGap: '10%',
            data: hist.slice(0, labels.length).map((value, i) => ({
                value: value,
                itemStyle: { color: i === labels.length - 1 ? theme.pop.evasive : theme.accent }
            }))
        }]
    }));

    const stats = data.stats || {};
    setPop('ix-qtime',
        num(data.requests) + ' requests, bucketed into ' + data.gap + ' ms steps up to ' +
        data.ceiling + ' ms. Percentiles are read off those buckets, so they are upper bounds ' +
        'rather than exact values. The exact extremes are' +
        (stats.max === null || stats.max === undefined
            ? ' not available from this index.'
            : ' a minimum of ' + dur(stats.min) + ' and a maximum of ' + dur(stats.max) + '.'));
}

/**
 * A cell whose text is a link that filters the whole page to that value.
 *
 * This is what makes the composition tables act on something rather than just report it: the
 * operator who spots a handler they did not expect — the owner's example was a path that is
 * neither a visitor nor a crawler — clicks it and every card on the page narrows to it.
 *
 * An <a> and not a click handler on the row: it is a real URL, so it can be opened in a new
 * tab, and the CSP forbids inline handlers anyway.
 */
function pickCell(field, value, active, text) {
    const on = Array.isArray((active || {})[field]) && active[field].indexOf(value) !== -1;
    return {
        node: el('a', {
            href: on ? lfRemove(field, value) : lfAdd(field, value),
            title: (on ? 'Remove this filter: ' : 'Filter this page to ') + value,
            text: text === undefined ? value : text
        })
    };
}

/**
 * Fill the handler and status cards: a chart each, then the exact table.
 */
function renderHandlers(data) {
    if (handleState('ix-handlers-empty', data, 'requests')) {
        tbody(byId('ix-paths-table'), []);
        tbody(byId('ix-status-table'), []);
        return;
    }
    hideEmpty('ix-handlers-empty');

    const paths = Object.keys(data.paths);
    const statuses = Object.keys(data.statuses);
    const pathTotal = paths.reduce((sum, key) => sum + data.paths[key], 0);
    const statusTotal = statuses.reduce((sum, key) => sum + data.statuses[key], 0);
    const t = tokens();

    barsH('ix-paths-chart', paths.slice(0, 10).map((path) => ({
        label: path,
        value: data.paths[path],
        extra: pct(data.paths[path], pathTotal) + ' of requests'
    })));

    tbody(byId('ix-paths-table'), paths.map((path) => ({
        attrs: { class: 'lf-pick' },
        cells: [
            Object.assign(pickCell('path', path, data.active), { mono: true, clip: true }),
            { text: num(data.paths[path]), num: true },
            { node: shareBar(data.paths[path], pathTotal) }
        ]
    })));

    /* A donut and not a second bar chart: status is a composition of one whole — every
       request has exactly one status — and the centre carries the total. Colour is the one
       accent for anything at or above 400 and the neutral population ramp below it, because
       the design system has no red to reach for. */
    donut('ix-status-chart', statuses.map((status) => ({
        label: status + (STATUS_MEANING[Number(status)] ? ' · ' + STATUS_MEANING[Number(status)] : ''),
        value: data.statuses[status],
        color: Number(status) >= 400 ? t.pop.evasive : t.pop.human
    })), 'requests', num(statusTotal));

    tbody(byId('ix-status-table'), statuses.map((status) => ({
        attrs: { class: 'lf-pick' },
        cells: [
            {
                node: el('a', {
                    class: 'chip ' + (Number(status) >= 400 ? 'chip-bad' : 'chip-good'),
                    href: Array.isArray((data.active || {}).http_status)
                        && data.active.http_status.indexOf(status) !== -1
                        ? lfRemove('http_status', status)
                        : lfAdd('http_status', status),
                    title: 'Filter this page to status ' + status,
                    text: status
                })
            },
            { text: num(data.statuses[status]), num: true },
            {
                node: el('span', { class: 'bar', title: STATUS_MEANING[Number(status)] || '' }, [
                    el('span', {
                        style: 'width:' + ((data.statuses[status] / (statusTotal || 1)) * 100).toFixed(2) + '%'
                    })
                ])
            }
        ]
    })));

    setPop('ix-handlers',
        num(data.requests) + ' requests under the current filters. Handlers and status codes are faceted ' +
        'independently, so each column totals the same population. The bar chart shows the ten busiest ' +
        'handlers; the table below it is every one the facet returned.' +
        (statuses.some((s) => Number(s) >= 400)
            ? ' Some requests were refused or failed — see the status column.'
            : ' Every logged request was answered with a 2xx.'));
}

/**
 * Fill the cluster-node card: the split as bars, then the exact table.
 */
function renderNodes(data) {
    if (handleState('ix-nodes-empty', data, 'requests')) {
        tbody(byId('ix-nodes-table'), []);
        return;
    }

    const names = Object.keys(data.nodes);
    const total = names.reduce((sum, key) => sum + data.nodes[key], 0);

    if (chartOrEmpty('ix-nodes-chart', 'ix-nodes-empty', names.length, 'No node recorded', [
        'The platform returned no cluster hostname for these requests, so there is nothing to split ' +
            'them across.'
    ])) {
        tbody(byId('ix-nodes-table'), []);
        return;
    }

    barsH('ix-nodes-chart', names.map((name) => ({
        label: name,
        value: data.nodes[name],
        extra: pct(data.nodes[name], total) + ' of the requests listed'
    })));

    tbody(byId('ix-nodes-table'), names.map((name) => ({
        attrs: { class: 'lf-pick' },
        cells: [
            Object.assign(pickCell('param_hostname', name, data.active), { mono: true, clip: true }),
            { text: num(data.nodes[name]), num: true },
            { node: shareBar(data.nodes[name], total) }
        ]
    })));

    const note = byId('ix-nodes-note');
    if (note) {
        const size = data.size || {};
        note.textContent = names.length <= 1
            ? 'One node answered every request. A single-node index has no read replicas to spread ' +
              'load across, which is expected on a small plan and worth knowing on a large one.'
            : names.length + ' nodes answered. An even split is the healthy shape for a cluster of ' +
              'read replicas; a node missing from this list is a node that stopped taking traffic. ' +
              (size.sum === null || size.sum === undefined
                  ? ''
                  : 'Together they returned ' + bytes(size.sum * 1024) + ' in this range.');
    }

    setPop('ix-nodes', num(data.requests) + ' requests in this range, grouped by the node that served them. ' +
        num(total) + ' of them (' + pct(total, data.requests) + ') fall into the nodes listed.');
}

/**
 * Load every card for the current index.
 */
function refresh() {
    loadCard('ix-headline', 'Reading the request log', async () => {
        const chosen = await resolveCore('indexes', 'ix-core', refresh);
        renderHeadline(chosen === null
            ? { state: 'no_index', note: 'This Opensolr account has no indexes yet.' }
            : await api('indexes', 'headline', { core: chosen }));
    });

    loadCard('ix-filters', 'Faceting the request log', async () => {
        const chosen = await resolveCore('indexes', 'ix-core', refresh);
        renderFilters('ix-filters', chosen === null
            ? { state: 'no_index', requests: 0, groups: [], active: {}, ignored: [] }
            : await api('indexes', 'facets', { core: chosen }));
    });

    loadCard('ix-volume', 'Faceting request volume', async () => {
        const chosen = await resolveCore('indexes', 'ix-core', refresh);
        renderVolume('ix-volume', chosen === null
            ? { state: 'no_index', requests: 0, all: [], times: [] }
            : await api('indexes', 'volume', { core: chosen }));
    });

    loadCard('ix-qtime', 'Building the QTime histogram', async () => {
        const chosen = await resolveCore('indexes', 'ix-core', refresh);
        renderQtime(chosen === null
            ? { state: 'no_index', requests: 0 }
            : await api('indexes', 'qtime', { core: chosen }));
    });

    loadCard('ix-handlers', 'Faceting handlers and status codes', async () => {
        const chosen = await resolveCore('indexes', 'ix-core', refresh);
        renderHandlers(chosen === null
            ? { state: 'no_index', requests: 0 }
            : await api('indexes', 'handlers', { core: chosen }));
    });

    loadCard('ix-nodes', 'Faceting cluster nodes', async () => {
        const chosen = await resolveCore('indexes', 'ix-core', refresh);
        renderNodes(chosen === null
            ? { state: 'no_index', requests: 0 }
            : await api('indexes', 'nodes', { core: chosen }));
    });
}

/**
 * Entry point. Absent when the installation has no Opensolr credentials, because the view
 * renders an explanation instead of cards and there is nothing to load.
 */
export default function init() {
    if (!byId('ix-filters-card')) {
        return;
    }
    refresh();
}
