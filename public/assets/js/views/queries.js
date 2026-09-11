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
 * Everything on screen that came out of a request — the shape, the example request, the
 * client address — is placed with textContent. The field names inside a shape are chosen
 * by whoever queried the index.
 */

'use strict';

import {
    api, byId, dur, el, hideEmpty, loadCard, num, pct, runJob, setPop, showEmpty, tbody, when
} from '../core.js';
import {
    cardFailure, handleState, histPercentile, rankShapes, resolveCore, revealCard, shapeNode,
    shareBar
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
    if (!row.timed || !edges.length) {
        return '—';
    }
    const value = histPercentile(row.hist, edges, 0.95);
    if (value === null) {
        return '—';
    }
    return value === Infinity ? '> ' + dur(edges[edges.length - 1]) : '≤ ' + dur(value);
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
 * Render the all-requests shape table from a job state.
 */
function renderShapes(state, order, running) {
    const table = byId(SCANS.shapes.table);
    if (state.note) {
        tbody(table, []);
        handleState('qy-shapes-empty', { state: 'unreachable', note: state.note }, 'requests');
        return;
    }
    if (!state.scanned) {
        tbody(table, []);
        if (!running) {
            handleState('qy-shapes-empty', { state: 'ok', requests: 0 }, 'requests');
        }
        return;
    }
    hideEmpty('qy-shapes-empty');

    const rows = rankShapes(state.shapes, order);
    scans.shapes = { rows: rows, state: state };

    tbody(table, rows.map((row, index) => ({
        attrs: { dataset: { row: String(index) } },
        cells: [
            expanderCell(),
            { node: shapeNode(row.label), clip: true, title: row.label },
            { text: num(row.count), num: true },
            { text: row.zero ? num(row.zero) : '—', num: true },
            { node: shareBar(row.zero, row.count) },
            { text: row.mean === null ? '—' : dur(row.mean), num: true },
            { text: shapeP95(row, state.edges), num: true },
            { text: row.qmax === null ? '—' : dur(row.qmax), num: true }
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
    if (!state.scanned) {
        tbody(table, []);
        if (!running) {
            showEmpty('qy-zero-empty', 'Nothing came back empty', [
                'Every request this index answered in the selected range matched at least one document. ' +
                    'That is the state you want this card to be in.'
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
            { node: shapeNode(row.label), clip: true, title: row.label },
            { text: num(row.count), num: true },
            { node: shareBar(row.count, state.scanned) },
            { text: row.mean === null ? '—' : dur(row.mean), num: true }
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

    resolveCore('queries', 'qy-core', refresh).then((chosen) => {
        if (chosen === null) {
            nothingToScan('shapes', 'This Opensolr account has no indexes to scan.');
            nothingToScan('zero', 'This Opensolr account has no indexes to scan.');
            return;
        }
        const target = { core: chosen, range: range };
        attach('shapes', target);
        attach('zero', target);
    }).catch((err) => {
        for (const which of Object.keys(SCANS)) {
            cardFailure(SCANS[which].card, err, refresh);
        }
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
    if (!byId('qy-shapes-card')) {
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
