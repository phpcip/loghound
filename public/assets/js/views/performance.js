/*
 * Loghound — Performance view.
 *
 * `dur_us_l` comes from Apache's %D or nginx's $request_time and is genuinely optional:
 * stock `combined` does not log it. So the first thing this view does is check how many
 * of the matched requests actually carried a duration, and if the answer is none it
 * replaces the charts with an explanation of which directive to add rather than drawing
 * an axis full of zeroes.
 *
 * Percentiles rather than averages, because the average of a bimodal latency
 * distribution describes nobody's experience. p50, p95 and p99 are shown together, and
 * the mean is shown beside them precisely so the gap between them is visible.
 */

'use strict';

import { api, byId, dec, durUs, el, hideEmpty, load, noDataYet, num, pct, tbody } from '../core.js';
import { lines, stackedBars, tokens } from '../charts.js';

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

/** Colour for a status class. */
function statusColour(t, status) {
    const first = Math.floor(status / 100);
    if (first === 2) { return t.good; }
    if (first === 3) { return t.pop.unknown; }
    if (first === 4) { return t.warn; }
    if (first === 5) { return t.bad; }
    return t.pop.unknown;
}

/** Headline percentiles and the coverage caption. */
function renderHeadline(data) {
    const card = byId('pf-pop').closest('.card');
    const set = (field, value) => {
        const node = card.querySelector('[data-field="' + field + '"]');
        if (node) {
            node.textContent = value;
        }
    };
    set('p50', durUs(data.overall.p50));
    set('p95', durUs(data.overall.p95));
    set('p99', durUs(data.overall.p99));
    set('avg', durUs(data.overall.avg));

    const kindLabel = {
        html: 'HTML page requests', api: 'API requests', asset: 'static asset requests', all: 'all requests'
    }[data.kind] || 'requests';
    const whoLabel = data.who === 'human' ? ', from sessions scored human' : '';

    byId('pf-pop').textContent =
        num(data.requests) + ' ' + kindLabel + whoLabel + ' in this range. ' +
        num(data.timed) + ' of them (' + dec(data.timed_pct, 1) + '%) carry a logged duration; ' +
        'the percentiles above cover only those. Requests without a duration are excluded, not counted as zero.' +
        // The Humans-only toggle depends on the scorer copying bot_verdict_s down onto
        // hit documents, which SPEC §4.1 does not require. Say so rather than showing an
        // empty chart and letting the operator conclude they have no human traffic.
        (data.who === 'human' && !data.who_supported
            ? ' NOTE: hit documents in this index carry no verdict, so the "Humans only" ' +
              'filter cannot be applied here and matched nothing. Switch back to "All clients".'
            : '');

    // The one case where the whole view has to say "you are missing a directive".
    if (data.requests > 0 && data.timed === 0) {
        const node = byId('pf-nodur');
        node.hidden = false;
        node.classList.add('show');
        node.replaceChildren(
            el('h3', { text: 'No request durations are being logged' }),
            el('p', {
                text: 'Not one of the ' + num(data.requests) + ' matched requests carries a dur_us_l value, so ' +
                    'there is nothing to compute a percentile from. Your log format does not include the request ' +
                    'duration — the stock Apache "combined" format does not.'
            }),
            el('p', { text: 'Add %D to your Apache LogFormat (microseconds), or $request_time to an nginx log_format (seconds):' }),
            el('pre', {
                class: 'snippet mono',
                text: 'LogFormat "%h %l %u %t \\"%r\\" %>s %O %D \\"%{Referer}i\\" \\"%{User-Agent}i\\"" combined_d'
            }),
            el('p', {}, [
                'The full recommended format, which also enables several detection rules, is in ',
                el('code', { text: 'docs/INSTALL.md' }),
                '. Everything else in this view works without it.'
            ])
        );
        return false;
    }
    hideEmpty('pf-nodur');
    return true;
}

/** Latency over time. */
function renderOverTime(data, hasDurations) {
    if (!hasDurations || !data.times.length) {
        noDataYet('pf-time-empty', 'timed requests');
        return;
    }
    hideEmpty('pf-time-empty');
    const t = tokens();
    lines('pf-time', data.times, [
        { name: 'p50', color: t.pop.declared, data: data.p50 },
        { name: 'p95', color: t.accent, data: data.p95 }
    ], durUs);
}

/** Slowest-paths table. */
function renderPaths(data, hasDurations) {
    const table = byId('pf-paths');
    byId('pf-paths-pop').textContent = hasDurations
        ? 'The busiest paths in this range, with their latency percentiles. The bar compares p50 to p99 on the ' +
          'same scale — a long bar means the median visitor and the unlucky one percent had very different days.'
        : 'The busiest paths in this range. Latency columns are empty because no duration is logged.';

    if (!data.paths.length) {
        tbody(table, []);
        noDataYet('pf-paths-empty', 'requests');
        return;
    }
    hideEmpty('pf-paths-empty');

    // Shared scale across rows so the bars are comparable to each other, not each to itself.
    const worst = data.paths.reduce((m, p) => Math.max(m, p.p99 || 0), 1);

    tbody(table, data.paths.map((p) => ({
        cells: [
            { text: p.path, mono: true, clip: true },
            { text: num(p.requests), num: true },
            { text: durUs(p.p50), num: true },
            { text: durUs(p.p95), num: true },
            { text: durUs(p.p99), num: true },
            {
                node: el('span', { class: 'bar bar-split', title: 'p50 ' + durUs(p.p50) + ' · p99 ' + durUs(p.p99) }, [
                    el('span', {
                        class: 'bar-human',
                        style: 'width:' + (((p.p50 || 0) / worst) * 100).toFixed(2) + '%'
                    }),
                    el('span', {
                        class: 'bar-evasive',
                        style: 'width:' + ((Math.max(0, (p.p99 || 0) - (p.p50 || 0)) / worst) * 100).toFixed(2) + '%'
                    })
                ])
            },
            { text: p.notfound ? num(p.notfound) : '—', num: true },
            {
                text: p.errors ? num(p.errors) : '—',
                num: true,
                class: p.errors ? 'chip-bad' : null
            }
        ]
    })));
}

/** Status codes over time. */
function renderHeat(data) {
    if (!data.heat_times.length) {
        noDataYet('pf-heat-empty', 'requests');
        return;
    }
    hideEmpty('pf-heat-empty');
    const t = tokens();
    stackedBars('pf-heat', data.heat_times, [
        { name: '2xx', color: t.good, data: data.heat.s2 },
        { name: '3xx', color: t.pop.unknown, data: data.heat.s3 },
        { name: '4xx', color: t.warn, data: data.heat.s4 },
        { name: '5xx', color: t.bad, data: data.heat.s5 }
    ]);
}

/** Exact status-code table. */
function renderStatuses(data) {
    const table = byId('pf-status');
    if (!data.statuses.length) {
        tbody(table, []);
        noDataYet('pf-status-empty', 'requests');
        return;
    }
    hideEmpty('pf-status-empty');

    const total = data.statuses.reduce((sum, s) => sum + s.count, 0);
    const t = tokens();

    tbody(table, data.statuses.map((s) => ({
        cells: [
            {
                node: el('span', {
                    class: 'chip',
                    text: String(s.status),
                    style: 'border-color:' + statusColour(t, s.status) + ';color:' + statusColour(t, s.status)
                })
            },
            { text: STATUS_MEANING[s.status] || '—', class: 'muted' },
            { text: num(s.count), num: true },
            {
                node: el('span', { class: 'bar', title: pct(s.count, total) }, [
                    el('span', { style: 'width:' + ((s.count / total) * 100).toFixed(2) + '%' })
                ])
            }
        ]
    })));
}

/** Load everything for the current control state. */
async function refresh() {
    const kind = byId('pf-kind');
    const who = byId('pf-who');

    await load('pf-paths-empty', 'performance data', async () => {
        const data = await api('performance', 'summary', {
            kind: kind ? kind.value : 'html',
            who: who ? who.value : 'all'
        });
        const hasDurations = renderHeadline(data);
        renderOverTime(data, hasDurations);
        renderPaths(data, hasDurations);
        renderHeat(data);
        renderStatuses(data);
    });
}

/** Entry point. */
export default async function init() {
    for (const id of ['pf-kind', 'pf-who']) {
        const node = byId(id);
        if (node) {
            node.addEventListener('change', refresh);
        }
    }
    await refresh();
}
