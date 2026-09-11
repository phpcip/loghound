/*
 * Loghound — Performance view.
 *
 * `dur_us_l` comes from Apache's %D or nginx's $request_time and is genuinely optional:
 * stock `combined` does not log it. So the headline card checks how many matched requests
 * actually carried a duration, and if the answer is none it replaces the numbers with an
 * explanation of which directive to add rather than an axis full of zeroes.
 *
 * Percentiles rather than averages, because the average of a bimodal latency distribution
 * describes nobody's experience. p50, p95 and p99 are shown together, and the mean sits
 * beside them precisely so the gap is visible.
 *
 * Four independent cards. Changing either control reloads all four, but each still
 * settles on its own.
 */

'use strict';

import {
    api, byId, cardChart, dec, durUs, el, hideEmpty, loadCard, noDataYet, num, pct, setPop,
    showEmpty, snippet, tbody
} from '../core.js';
import { lines, stackedBars, tokens } from '../charts.js';
import { pathCell } from '../url.js';

/** Plain-English meaning for the status codes that actually turn up in web logs. */
const STATUS_MEANING = {
    200: 'OK', 201: 'Created', 204: 'No content',
    301: 'Moved permanently', 302: 'Found', 304: 'Not modified (cache hit)',
    400: 'Bad request', 401: 'Unauthorised', 403: 'Forbidden', 404: 'Not found',
    405: 'Method not allowed', 408: 'Request timeout', 413: 'Payload too large',
    429: 'Too many requests',
    500: 'Internal server error', 502: 'Bad gateway', 503: 'Service unavailable',
    504: 'Gateway timeout'
};

/** How the two controls describe themselves in a caption. */
const KIND_LABEL = {
    html: 'HTML page requests',
    api: 'API requests',
    asset: 'static asset requests',
    all: 'all requests'
};

/**
 * The colour for a status class. Affirmative is ink, 5xx is the accent, nothing else.
 */
function statusColour(t, status) {
    const first = Math.floor(status / 100);
    if (first === 5) { return t.bad; }
    if (first === 4) { return t.warn; }
    if (first === 3) { return t.mid; }
    return t.ok;
}

/**
 * Read the current control state, which every request on this view carries.
 */
function controls() {
    const kind = byId('pf-kind');
    const who = byId('pf-who');
    return {
        kind: kind ? kind.value : 'html',
        who: who ? who.value : 'all'
    };
}

/**
 * Fill the percentile headline and the coverage caption.
 */
function renderHeadline(data) {
    const scope = byId('pf-headline-content');
    const set = (field, value) => {
        const node = scope ? scope.querySelector('[data-field="' + field + '"]') : null;
        if (node) {
            node.textContent = value;
        }
    };
    set('p50', durUs(data.overall.p50));
    set('p95', durUs(data.overall.p95));
    set('p99', durUs(data.overall.p99));
    set('avg', durUs(data.overall.avg));

    setPop('pf-headline',
        num(data.requests) + ' ' + (KIND_LABEL[data.kind] || 'requests') +
        (data.who === 'human' ? ', from sessions scored human' : '') + ' in this range. ' +
        num(data.timed) + ' of them (' + dec(data.timed_pct, 1) + '%) carry a logged duration; the percentiles ' +
        'cover only those. Requests without a duration are excluded, not counted as zero.' +
        (data.who === 'human' && !data.who_supported
            ? ' NOTE: requests in this index carry no verdict, so the "Humans only" choice could not be applied ' +
              'to these figures — they cover every request in range, not only human ones. Switch back to ' +
              '"All clients" to stop the choice implying otherwise.'
            : '') +
        ignoredFilterNote(data));

    /* THREE OUTCOMES, THREE STATES. Nothing matched at all; something matched but none of it
       is timed, which is a log-format problem with a fix; or there are percentiles to read.
       The zero-request case used to have no state whatsoever — four em-dashes under a caption
       reading "0 HTML page requests in this range", which is the one card in the panel that
       said nothing about why it was blank. */
    if (data.requests === 0) {
        noDataYet('pf-headline-empty', 'requests');
        return false;
    }
    if (data.timed === 0) {
        showMissingDuration(data.requests);
        return false;
    }
    hideEmpty('pf-headline-empty');
    return true;
}

/**
 * Name the sidebar filters this view could not apply.
 *
 * The scorer's session-level conclusions do not exist on the hits core, so a verdict or
 * signal chip stays lit in the sidebar while doing nothing to these numbers. Saying so is
 * the whole point: a filter that is silently ignored turns a wrong answer into one the
 * reader has no reason to doubt.
 */
function ignoredFilterNote(data) {
    const ignored = Array.isArray(data.filters_ignored) ? data.filters_ignored : [];
    if (ignored.length === 0) {
        return '';
    }
    return ' NOTE: ' + ignored.join(', ') +
        (ignored.length === 1 ? ' is a session-level filter' : ' are session-level filters') +
        ' and could not be applied to these numbers, which cover every request in range that ' +
        'the other filters match.';
}

/**
 * Explain that no duration is being logged, and which directive fixes it.
 */
function showMissingDuration(requests) {
    showEmpty('pf-headline-empty', 'No request durations are being logged', [
        'Not one of the ' + num(requests) + ' matched requests records how long it took, so there is ' +
            'nothing to compute a percentile from. Your log format does not include the request duration — ' +
            'the stock Apache "combined" format does not.',
        'Add %D to your Apache LogFormat, or $request_time to an nginx log_format:',
        snippet('LogFormat "%h %l %u %t \\"%r\\" %>s %O %D \\"%{Referer}i\\" \\"%{User-Agent}i\\"" combined_d'),
        el('p', {}, [
            'The full recommended format, which also enables several detection rules, is in ',
            el('code', { text: 'docs/INSTALL.md' }),
            '. Everything else in this view works without it.'
        ])
    ]);
}

/**
 * Draw latency over time, leaving gaps where nothing was measured.
 */
function renderLatency(data) {
    if (!data.timed || !data.times.length) {
        noDataYet('pf-time-empty', 'timed requests');
        return;
    }
    hideEmpty('pf-time-empty');
    cardChart('pf-time', 300);
    const t = tokens();
    lines('pf-time', data.times, [
        { name: 'p50', color: t.pop.declared, data: data.p50 },
        { name: 'p95', color: t.accent, data: data.p95 }
    ], durUs);
}

/**
 * Fill the slowest-paths table.
 */
function renderPaths(data) {
    if (!data.paths.length) {
        tbody(byId('pf-paths-table'), []);
        noDataYet('pf-paths-empty', 'requests');
        return;
    }
    hideEmpty('pf-paths-empty');

    const worst = data.paths.reduce((max, row) => Math.max(max, row.p99 || 0), 1);

    tbody(byId('pf-paths-table'), data.paths.map((row) => ({
        cells: [
            {
                node: pathCell(row.path, { host: row.host, hosts: row.hosts }),
                class: 'clip urlcell',
                title: row.path,
                sort: row.path
            },
            { text: num(row.requests), num: true, sort: row.requests },
            { text: durUs(row.p50), num: true, sort: row.p50 === null ? '' : row.p50 },
            { text: durUs(row.p95), num: true, sort: row.p95 === null ? '' : row.p95 },
            { text: durUs(row.p99), num: true, sort: row.p99 === null ? '' : row.p99 },
            {
                node: el('span', {
                    class: 'bar bar-split',
                    title: 'p50 ' + durUs(row.p50) + ' · p99 ' + durUs(row.p99)
                }, [
                    el('span', {
                        class: 'bar-declared',
                        style: 'width:' + (((row.p50 || 0) / worst) * 100).toFixed(2) + '%'
                    }),
                    el('span', {
                        class: 'bar-evasive',
                        style: 'width:' + ((Math.max(0, (row.p99 || 0) - (row.p50 || 0)) / worst) * 100).toFixed(2) + '%'
                    })
                ])
            },
            { text: row.notfound ? num(row.notfound) : '—', num: true },
            { text: row.errors ? num(row.errors) : '—', num: true }
        ]
    })));
}

/**
 * Draw the status chart and fill the exact-code table.
 */
function renderStatus(data) {
    if (!data.statuses.length) {
        tbody(byId('pf-status-table'), []);
        noDataYet('pf-status-empty', 'requests');
        return;
    }
    hideEmpty('pf-status-empty');
    const t = tokens();

    stackedBars('pf-heat', data.heat_times, [
        { name: '2xx', color: t.ok, data: data.heat.s2 },
        { name: '3xx', color: t.mid, data: data.heat.s3 },
        { name: '4xx', color: t.warn, data: data.heat.s4 },
        { name: '5xx', color: t.bad, data: data.heat.s5 }
    ]);

    const total = data.statuses.reduce((sum, row) => sum + row.count, 0);
    tbody(byId('pf-status-table'), data.statuses.map((row) => ({
        cells: [
            {
                node: el('span', {
                    class: 'chip',
                    text: String(row.status),
                    style: 'border-color:' + statusColour(t, row.status) + ';color:' + statusColour(t, row.status)
                })
            },
            { text: STATUS_MEANING[row.status] || '—', class: 'muted' },
            { text: num(row.count), num: true, sort: row.count },
            {
                node: el('span', { class: 'bar', title: pct(row.count, total) }, [
                    el('span', { style: 'width:' + ((row.count / total) * 100).toFixed(2) + '%' })
                ])
            }
        ]
    })));
}

/**
 * Load all four cards for the current control state.
 */
function refresh() {
    const state = controls();

    loadCard('pf-headline', 'Computing latency percentiles', async () => {
        renderHeadline(await api('performance', 'headline', state));
    });
    loadCard('pf-time', 'Computing latency over time', async () => {
        renderLatency(await api('performance', 'latency', state));
    });
    loadCard('pf-paths', 'Computing per-path percentiles', async () => {
        renderPaths(await api('performance', 'paths', state));
    });
    loadCard('pf-status', 'Faceting response codes', async () => {
        renderStatus(await api('performance', 'status', state));
    });
}

/**
 * Entry point.
 */
export default function init() {
    for (const id of ['pf-kind', 'pf-who']) {
        const node = byId(id);
        if (node) {
            node.addEventListener('change', refresh);
        }
    }
    refresh();
}
