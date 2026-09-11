/*
 * Loghound — Query analysis view.
 *
 * The two shape tables are driven by SERVER-SIDE STEPPED JOBS, not by a fetch. A query
 * shape cannot be faceted — it has to be computed from the recorded request, which means
 * reading documents — so the analysis is a sequence of bounded pages. The job store runs
 * exactly one page per poll and merges it into the job's context, so no request can time
 * out however large the log is, and the depth is decided on the server rather than by
 * whatever the browser felt like asking for.
 *
 * Three things follow from that, and all three are visible in the UI:
 *
 *   - The table fills in as the scan runs. Every poll carries the job's whole context, so
 *     the merged shapes are already there; rendering them on each step turns a progress
 *     bar into a result that grows.
 *   - Reloading the page rejoins. `job_latest` finds the operation, its context names the
 *     index and range it was started for, and a match means the browser reattaches instead
 *     of starting a second scan of the same thing. Starting is idempotent by target
 *     anyway, so even a race converges on one job.
 *   - Switching index starts a different job rather than reusing the running one, because
 *     the target is part of the job's identity.
 *
 * TWO CHARTS COME OUT OF THE SAME SCAN AND COST NOTHING EXTRA. Every shape carries a
 * log-scaled latency histogram — that is how per-shape percentiles survive twenty pages of
 * merging — so summing those histograms gives the distribution for the whole scanned
 * population, which was being computed on the server and then never drawn. And the shapes
 * themselves stack into matched versus matched-nothing, which is honest because a request did
 * one or the other and never both.
 *
 * Everything on screen that came out of a request — the shape, the example request, the
 * client address — is placed with textContent. The field names inside a shape are chosen
 * by whoever queried the index.
 */

'use strict';

import {
    api, byId, dur, el, hideEmpty, loadCard, num, pct, runJob, setPop, showEmpty, tbody, when
} from '../core.js';
import { barsHStacked, dispose, histogram } from '../charts.js';
import {
    cardFailure, chartOrEmpty, fieldSetter, handleState, histPercentile, indexList, rankShapes,
    renderFilters, renderVolume, resolveCore, revealCard, shapeNode, shareBar, tokens
} from './opensolr.js';

/** The two scans, and everything that differs between them. */
const SCANS = {
    shapes: {
        kind: 'shape_scan',
        card: 'qy-shapes',
        table: 'qy-shapes-table',
        mount: 'qy-shapes-job',
        title: 'Scanning the request log',
        columns: 8
    },
    zero: {
        kind: 'empty_scan',
        card: 'qy-zero',
        table: 'qy-zero-table',
        mount: 'qy-zero-job',
        title: 'Scanning requests that matched nothing',
        columns: 5
    }
};

/** The latest merged state of each scan, kept so a re-sort does not re-scan. */
const scans = {};

/**
 * Pull a scan's state out of a job envelope.
 *
 * The job's context is its accumulated result, so a running job and a finished one are
 * read exactly the same way and a partially complete scan renders as a partially complete
 * table rather than as nothing.
 */
function stateOf(job) {
    const ctx = (job && job.result) || {};
    return {
        shapes: ctx.shapes || {},
        scanned: ctx.scanned || 0,
        total: ctx.total || 0,
        edges: ctx.edges || [],
        overflow: ctx.overflow || 0,
        capped: ctx.capped === true,
        complete: ctx.complete === true,
        core: ctx.core || '',
        range: ctx.range || '',
        note: job && job.state === 'failed' ? (job.error || 'The scan could not finish.') : null
    };
}

/**
 * The p95 of one shape, read off its merged histogram.
 *
 * The histogram is merged across every page of the scan, bucket by bucket, so this is a
 * percentile over the whole scanned population and not a per-page figure. It is an upper
 * bound because the distribution is bucketed, and it is rendered with a "≤" to say so.
 */
function shapeP95(row, edges) {
    const value = shapeP95Value(row, edges);
    if (value === null) {
        return '—';
    }
    return value === Infinity ? '> ' + dur(edges[edges.length - 1]) : '≤ ' + dur(value);
}

/**
 * The same figure as a number, for the column's sort key.
 *
 * "≤ 1.2 s" and "> 5.0 s" cannot be compared as strings and cannot be parsed back without
 * guessing at the format, which is the case core.js's `sort` descriptor exists for. Infinity
 * is kept rather than clamped: the over-the-top bucket genuinely IS the largest value, and it
 * sorts as such through Number().
 */
function shapeP95Value(row, edges) {
    if (!row.timed || !edges.length) {
        return null;
    }
    return histPercentile(row.hist, edges, 0.95);
}

/**
 * Build the expandable detail row for a shape: its worst recorded example.
 *
 * A shape is an abstraction, and an abstraction nobody can tie back to a real request is
 * not actionable. The example is the concrete query the operator has to recognise as
 * something their own application sent.
 */
function detailRow(row, columns) {
    const worst = row.worst || {};
    const facts = el('dl', { class: 'kv' });
    for (const [label, value] of [
        ['When', worst.date ? when(worst.date) : '—'],
        ['From', worst.ip || '—'],
        ['QTime', worst.qtime === null || worst.qtime === undefined ? '—' : dur(worst.qtime)],
        ['Results', worst.hits === null || worst.hits === undefined ? '—' : num(worst.hits)],
        ['Status', worst.status === null || worst.status === undefined ? '—' : String(worst.status)],
        ['Node', worst.node || '—']
    ]) {
        facts.appendChild(el('dt', { text: label }));
        facts.appendChild(el('dd', { class: 'mono', text: String(value) }));
    }

    return el('tr', { class: 'members' }, [
        el('td', { colspan: String(columns) }, [
            el('div', { class: 'members-inner' }, [
                el('h4', { text: 'Slowest recorded example of this shape' }),
                facts,
                el('pre', { class: 'snippet mono request', text: worst.request || 'The full request was not recorded.' }),
                el('p', {
                    class: 'faint',
                    text: 'Shown exactly as Opensolr recorded it, and truncated. Whoever sent this request ' +
                        'chose every byte of it, so treat it as text, not as a link.'
                })
            ])
        ])
    ]);
}

/**
 * Wire one table's expander buttons.
 *
 * The row data is read through a getter rather than captured, because the table is
 * re-rendered on every poll of a running scan and on every change of sort order — a
 * captured array would go stale within a second, and the operator would expand the third
 * row and be shown the detail of whatever used to be third.
 */
function bindExpanders(table, rowsOf, columns) {
    table.addEventListener('click', (event) => {
        const button = event.target.closest ? event.target.closest('.expander') : null;
        if (!button || !table.contains(button)) {
            return;
        }
        const tr = button.closest('tr');
        const index = Number(tr.dataset.row);
        const next = tr.nextElementSibling;

        if (next && next.classList.contains('members')) {
            next.remove();
            button.textContent = '+';
            button.setAttribute('aria-expanded', 'false');
            return;
        }
        const row = rowsOf()[index];
        if (!row) {
            return;
        }
        tr.parentNode.insertBefore(detailRow(row, columns), tr.nextSibling);
        button.textContent = '−';
        button.setAttribute('aria-expanded', 'true');
    });
}

/** An expander button cell. */
function expanderCell() {
    return {
        node: el('button', {
            type: 'button',
            class: 'expander',
            text: '+',
            'aria-expanded': 'false',
            'aria-label': 'Show the slowest example of this shape'
        })
    };
}

/**
 * The population sentence both scan tables carry.
 *
 * An unlabelled number is a lie, and a capped scan is exactly the case where that matters:
 * "1,847 requests" means nothing unless the reader knows whether that was all of them, and
 * whether the scan was still running when they read it.
 */
function population(state, shapes, noun, running) {
    let covered;
    if (running) {
        covered = 'Still scanning: ' + num(state.scanned) + ' of ' + num(state.total) + ' ' + noun + ' read so far';
    } else if (state.complete) {
        covered = 'All ' + num(state.total) + ' ' + noun + ' in this range were read';
    } else {
        covered = 'The most recent ' + num(state.scanned) + ' of ' + num(state.total) + ' ' + noun +
            ' in this range were read (' + pct(state.scanned, state.total) + ')';
    }

    let sentence = covered + ', and grouped into ' + num(shapes) + ' ' +
        (shapes === 1 ? 'shape' : 'shapes') + '. ';

    if (state.capped && !running) {
        sentence += 'The scan stopped at its depth limit of eight thousand requests, so counts are a ' +
            'floor rather than a total: a shape listed here runs at least this often. ';
    }
    if (state.overflow) {
        sentence += num(state.overflow) + ' further requests belonged to shapes beyond the ' +
            'retained limit and are counted only here. ';
    }
    return sentence + 'Latency figures cover the whole scanned population — every shape carries its own ' +
        'histogram and pages are added together bucket by bucket — and percentiles are upper bounds ' +
        'because that distribution is bucketed.';
}

/**
 * A readable label for one log-scaled latency bucket.
 *
 * The edges come from the server with every page of the scan, so the labels here cannot
 * drift out of step with the buckets the server folded into.
 */
function bucketLabels(edges) {
    const labels = [];
    labels.push('< ' + edges[0] + ' ms');
    for (let i = 0; i < edges.length - 1; i += 1) {
        labels.push(edges[i] + '–' + edges[i + 1]);
    }
    labels.push('≥ ' + edges[edges.length - 1] + ' ms');
    return labels;
}

/**
 * Draw the latency distribution across everything the scan read.
 *
 * Costs no extra call: every shape already carries its own histogram over the same edges —
 * that is how the per-shape percentiles survive twenty pages of merging — so summing them
 * bucket by bucket is the distribution for the whole scanned population. It was being
 * computed on the server and then never drawn.
 */
function renderLatency(state, running) {
    const set = fieldSetter('qy-latency');
    const edges = state.edges || [];

    if (state.note) {
        handleState('qy-latency-empty', { state: 'unreachable', note: state.note }, 'requests');
        return;
    }

    const totals = edges.length ? new Array(edges.length + 1).fill(0) : [];
    let timed = 0;
    for (const hash of Object.keys(state.shapes)) {
        const hist = state.shapes[hash].hist || [];
        for (let i = 0; i < totals.length; i += 1) {
            totals[i] += hist[i] || 0;
            timed += hist[i] || 0;
        }
    }

    if (chartOrEmpty('qy-latency-chart', 'qy-latency-empty', timed, 'Nothing has been timed yet', [
        running
            ? 'The scan is still reading. This chart fills in as it goes.'
            : 'None of the scanned requests carried a QTime, so there is no distribution to draw.'
    ])) {
        for (const key of ['p50', 'p95', 'p99', 'timed']) {
            set(key, '—');
        }
        return;
    }

    const readAt = (p) => {
        const value = histPercentile(totals, edges, p);
        if (value === null) {
            return '—';
        }
        return value === Infinity ? '> ' + dur(edges[edges.length - 1]) : '≤ ' + dur(value);
    };

    set('p50', readAt(0.5));
    set('p95', readAt(0.95));
    set('p99', readAt(0.99));
    set('timed', num(timed));

    const t = tokens();
    const labels = bucketLabels(edges);
    histogram(
        'qy-latency-chart',
        labels.map((label, i) => ({ label: label, value: totals[i] || 0 })),
        (row) => (row.label.indexOf('≥') === 0 ? t.pop.evasive : t.accent),
        { noun: 'requests', prefix: '', interval: 1 }
    );

    setPop('qy-latency', num(timed) + ' of the ' + num(state.scanned) + ' scanned requests carried a ' +
        'QTime and are counted here. The buckets are log-scaled because query latency is: the structure ' +
        'worth seeing is between one and a hundred milliseconds, and a linear axis wide enough for a ' +
        'thirty-second outlier would put every real query in its first bar. Percentiles are read off ' +
        'these buckets, so they are upper bounds.' +
        (running ? ' The scan is still running, so all four figures will move.' : ''));
}

/**
 * Draw the shape composition: the busiest shapes, split into matched and matched-nothing.
 *
 * Stacked is honest here because the two parts are mutually exclusive — a request either
 * matched a document or it did not — so the length of a bar is that shape's true request
 * count and the dark part of it is the number to act on.
 */
function renderShapeChart(rows) {
    const t = tokens();
    const top = rows.slice(0, 12);

    if (!top.length) {
        dispose('qy-shapes-chart');
        return;
    }

    barsHStacked('qy-shapes-chart', top.map((row) => ({
        label: row.label,
        parts: [
            { name: 'Matched something', value: row.count - row.zero, color: t.pop.human },
            { name: 'Matched nothing', value: row.zero, color: t.pop.evasive }
        ]
    })));
}

/**
 * Render the all-requests shape table from a job state.
 */
function renderShapes(state, order, running) {
    const table = byId(SCANS.shapes.table);
    if (state.note) {
        tbody(table, []);
        dispose('qy-shapes-chart');
        handleState('qy-shapes-empty', { state: 'unreachable', note: state.note }, 'requests');
        return;
    }
    if (!state.scanned) {
        tbody(table, []);
        dispose('qy-shapes-chart');
        if (!running) {
            handleState('qy-shapes-empty', { state: 'ok', requests: 0 }, 'requests');
        }
        return;
    }
    hideEmpty('qy-shapes-empty');

    const rows = rankShapes(state.shapes, order);
    scans.shapes = { rows: rows, state: state };
    renderShapeChart(rows);

    tbody(table, rows.map((row, index) => ({
        attrs: { dataset: { row: String(index) } },
        cells: [
            expanderCell(),
            { node: shapeNode(row.label), clip: true, title: row.label, sort: row.label },
            { text: num(row.count), num: true, sort: row.count },
            { text: row.zero ? num(row.zero) : '—', num: true, sort: row.zero || 0 },
            { node: shareBar(row.zero, row.count), sort: row.count ? (row.zero || 0) / row.count : 0 },
            { text: row.mean === null ? '—' : dur(row.mean), num: true, sort: row.mean === null ? '' : row.mean },
            {
                text: shapeP95(row, state.edges),
                num: true,
                sort: shapeP95Value(row, state.edges) === null ? '' : shapeP95Value(row, state.edges)
            },
            { text: row.qmax === null ? '—' : dur(row.qmax), num: true, sort: row.qmax === null ? '' : row.qmax }
        ]
    })));

    if (!table.dataset.bound) {
        table.dataset.bound = '1';
        bindExpanders(table, () => scans.shapes.rows, SCANS.shapes.columns);
    }

    setPop('qy-shapes', population(state, rows.length, 'requests', running));
}

/**
 * Render the zero-result shape table from a job state.
 */
function renderZero(state, running) {
    const table = byId(SCANS.zero.table);
    if (state.note) {
        tbody(table, []);
        handleState('qy-zero-empty', { state: 'unreachable', note: state.note }, 'empty responses');
        return;
    }
    /* SCANNED NOTHING IS NOT A CLEAN BILL OF HEALTH. This branch fires when the scan read ZERO
       requests, and it announced "every request this index answered matched at least one
       document" — a finding derived from having looked at nothing. The card beside it reports
       the same condition honestly as "No requests in this time range", so the two sat next to
       each other saying opposite things. Zero scanned and zero empty among some scanned are
       different states and now read differently. */
    if (!state.scanned) {
        tbody(table, []);
        if (!running) {
            showEmpty('qy-zero-empty', 'Nothing was scanned', [
                'No request was read for this index in the selected range, so nothing has been checked '
                    + 'for empty responses. This card can say nothing about them either way.',
                'Widen the time range, or pick an index that is being queried.'
            ]);
        }
        return;
    }

    if (!rankShapes(state.shapes, 'count').length) {
        tbody(table, []);
        if (!running) {
            showEmpty('qy-zero-empty', 'Nothing came back empty', [
                'All ' + num(state.scanned) + ' requests read for this index in the selected range matched '
                    + 'at least one document. That is the state you want this card to be in.'
            ]);
        }
        return;
    }
    hideEmpty('qy-zero-empty');

    const rows = rankShapes(state.shapes, 'count');
    scans.zero = { rows: rows, state: state };

    tbody(table, rows.map((row, index) => ({
        attrs: { dataset: { row: String(index) } },
        cells: [
            expanderCell(),
            { node: shapeNode(row.label), clip: true, title: row.label, sort: row.label },
            { text: num(row.count), num: true, sort: row.count },
            { node: shareBar(row.count, state.scanned), sort: state.scanned ? row.count / state.scanned : 0 },
            { text: row.mean === null ? '—' : dur(row.mean), num: true, sort: row.mean === null ? '' : row.mean }
        ]
    })));

    if (!table.dataset.bound) {
        table.dataset.bound = '1';
        bindExpanders(table, () => scans.zero.rows, SCANS.zero.columns);
    }

    setPop('qy-zero', population(state, rows.length, 'requests that matched nothing', running) +
        ' A shape whose count here is close to its count in the table above matches nothing ' +
        'essentially every time it runs.');
}

/** The current sort order of the shape table. */
function order() {
    const node = byId('qy-sort');
    return node ? node.value : 'count';
}

/**
 * Render one scan's job state into its table.
 */
function paint(which, job) {
    const state = stateOf(job);
    const running = !job.done;
    if (which === 'shapes') {
        renderShapes(state, order(), running);
        renderLatency(state, running);
    } else {
        renderZero(state, running);
    }
}

/**
 * Start, or rejoin, one scan.
 *
 * A finished job for the SAME target is rendered and nothing is started: a reload after a
 * completed scan should show the result, not spend another eight thousand reads
 * reproducing it. Anything else hands over to runJob(), whose start is idempotent by
 * target — so a job already running for this index and range is rejoined rather than
 * duplicated, and one running for a different index is simply left alone.
 */
async function attach(which, target) {
    const scan = SCANS[which];

    let latest = null;
    try {
        latest = await api('queries', 'job_latest', { kind: scan.kind });
    } catch (err) {
        latest = null;
    }

    const job = latest && latest.job ? latest.job : null;
    const sameTarget = job && job.result &&
        job.result.core === target.core && job.result.range === target.range;

    if (sameTarget && job.done) {
        paint(which, job);
        return;
    }

    runJob(scan.kind, scan.mount, {
        title: scan.title,
        params: target,
        onStep: (state) => paint(which, state),
        onDone: (state) => {
            paint(which, state);
            const mount = byId(scan.mount);
            if (mount && state.state === 'done') {
                mount.replaceChildren();
            }
        }
    });
}

/**
 * Render the exact slowest requests.
 */
function renderSlowest(data) {
    if (handleState('qy-slow-empty', data, 'requests')) {
        tbody(byId('qy-slow-table'), []);
        return;
    }
    hideEmpty('qy-slow-empty');

    tbody(byId('qy-slow-table'), data.rows.map((row) => ({
        cells: [
            { text: when(row.date), nowrap: true },
            { text: row.qtime === null ? '—' : dur(row.qtime), num: true },
            { text: row.hits === null ? '—' : num(row.hits), num: true },
            { text: row.ip || '—', mono: true, nowrap: true },
            { node: shapeNode(row.shape), clip: true, title: row.shape }
        ]
    })));

    setPop('qy-slow',
        'The ' + num(data.rows.length) + ' requests with the highest QTime out of ' + num(data.requests) +
        ' logged in this range. Exact, not sampled — the platform sorted them. QTime excludes ' +
        'network time and time spent queued, so a request that felt slow to a visitor may not be here.');
}

/**
 * Tell a scan card there is nothing to scan.
 */
function nothingToScan(which, message) {
    showEmpty(SCANS[which].card + '-empty', 'Nothing to scan', [
        message,
        'Pick an index above once the list has loaded.'
    ]);
}

/**
 * Start both scans for the current index and time range.
 */
function refresh() {
    const range = new URLSearchParams(window.location.search).get('range') || '24h';

    for (const which of Object.keys(SCANS)) {
        revealCard(SCANS[which].card);
        const mount = byId(SCANS[which].mount);
        if (mount) {
            mount.replaceChildren();
        }
    }
    revealCard('qy-latency');

    /* `lf` and `outcome` are handed to the scan as job PARAMETERS rather than being read
       from the query string on the server, because a job start and every poll after it are
       POSTs to the bare view URL and carry no query string at all. `lf_packed` is the opaque
       string the server itself put in this payload; it is decoded and re-validated
       server-side, so it can express no more than a hand-written query string could. Being
       part of the parameters also makes a different filter set a different scan, which is
       correct: one job must not answer for two questions. */
    resolveCore('queries', 'qy-core', refresh).then((chosen) => {
        if (chosen === null) {
            nothingToScan('shapes', 'This Opensolr account has no indexes to scan.');
            nothingToScan('zero', 'This Opensolr account has no indexes to scan.');
            return;
        }
        return indexList('queries').then((list) => {
            const target = {
                core: chosen,
                range: range,
                lf: list.lf_packed || '',
                outcome: list.outcome || ''
            };
            attach('shapes', target);
            attach('zero', target);
        });
    }).catch((err) => {
        for (const which of Object.keys(SCANS)) {
            cardFailure(SCANS[which].card, err, refresh);
        }
    });

    loadCard('qy-filters', 'Faceting the request log', async () => {
        const chosen = await resolveCore('queries', 'qy-core', refresh);
        renderFilters('qy-filters', chosen === null
            ? { state: 'no_index', requests: 0, groups: [], active: {}, ignored: [] }
            : await api('queries', 'facets', { core: chosen }));
    });

    loadCard('qy-volume', 'Faceting request volume', async () => {
        const chosen = await resolveCore('queries', 'qy-core', refresh);
        renderVolume('qy-volume', chosen === null
            ? { state: 'no_index', requests: 0, all: [], times: [] }
            : await api('queries', 'volume', { core: chosen }));
    });

    loadCard('qy-slow', 'Asking the platform for the slowest requests', async () => {
        const chosen = await resolveCore('queries', 'qy-core', refresh);
        renderSlowest(chosen === null
            ? { state: 'no_index', requests: 0, rows: [] }
            : await api('queries', 'slowest', { core: chosen }));
    });
}

/**
 * Entry point. Absent when the installation has no Opensolr credentials, because the view
 * renders an explanation instead of cards.
 */
export default function init() {
    if (!byId('qy-filters-card')) {
        return;
    }
    const sort = byId('qy-sort');
    if (sort) {
        sort.addEventListener('change', () => {
            if (scans.shapes) {
                renderShapes(scans.shapes.state, sort.value, false);
            }
        });
    }
    refresh();
}
