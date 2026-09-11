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
import { draw, lines, tokens } from '../charts.js';
import { handleState, histPercentile, resolveCore, shareBar, stateMessage } from './opensolr.js';

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
    const scope = byId('ix-headline-content');
    const set = (field, value) => {
        const node = scope ? scope.querySelector('[data-field="' + field + '"]') : null;
        if (node) {
            node.textContent = value;
        }
    };

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
 * Draw request volume, with the zero-result subset underneath it.
 */
function renderVolume(data) {
    if (handleState('ix-volume-empty', data, 'requests')) {
        return;
    }
    hideEmpty('ix-volume-empty');

    const t = tokens();
    lines('ix-volume', data.times, [
        { name: 'All requests', color: t.accent, data: data.all },
        { name: 'Matched nothing', color: t.pop.declared, data: data.zero }
    ]);

    setPop('ix-volume',
        num(data.requests) + ' requests in this range, bucketed by time. ' +
        num(data.zero_total) + ' of them matched no documents. Both series cover every logged ' +
        'request for this index, not a sample.');
}

/**
 * Draw the QTime histogram and read the percentiles off it.
 */
function renderQtime(data) {
    if (handleState('ix-qtime-empty', data, 'requests')) {
        return;
    }
    hideEmpty('ix-qtime-empty');

    const edges = Object.keys(data.buckets).map(Number).sort((a, b) => a - b);
    const counts = edges.map((edge) => data.buckets[String(edge)] || 0);
    const over = data.over || 0;

    const scope = byId('ix-qtime-content');
    const set = (field, value) => {
        const node = scope ? scope.querySelector('[data-field="' + field + '"]') : null;
        if (node) {
            node.textContent = value;
        }
    };

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
 * Fill the handler and status tables.
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

    tbody(byId('ix-paths-table'), paths.map((path) => ({
        cells: [
            { text: path, mono: true, clip: true },
            { text: num(data.paths[path]), num: true },
            { node: shareBar(data.paths[path], pathTotal) }
        ]
    })));

    tbody(byId('ix-status-table'), statuses.map((status) => ({
        cells: [
            {
                node: el('span', {
                    class: 'chip ' + (Number(status) >= 400 ? 'chip-bad' : 'chip-good'),
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
        num(data.requests) + ' requests in this range. Handlers and status codes are faceted ' +
        'independently, so each column totals the same population.' +
        (statuses.some((s) => Number(s) >= 400)
            ? ' Some requests were refused or failed — see the status column.'
            : ' Every logged request was answered with a 2xx.'));
}

/**
 * Fill the cluster-node table.
 */
function renderNodes(data) {
    if (handleState('ix-nodes-empty', data, 'requests')) {
        tbody(byId('ix-nodes-table'), []);
        return;
    }
    hideEmpty('ix-nodes-empty');

    const names = Object.keys(data.nodes);
    const total = names.reduce((sum, key) => sum + data.nodes[key], 0);

    tbody(byId('ix-nodes-table'), names.map((name) => ({
        cells: [
            { text: name, mono: true, clip: true },
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

    loadCard('ix-volume', 'Faceting request volume', async () => {
        const chosen = await resolveCore('indexes', 'ix-core', refresh);
        renderVolume(chosen === null
            ? { state: 'no_index', requests: 0 }
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
    if (!byId('ix-headline-card')) {
        return;
    }
    refresh();
}
