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
import { barsH, dispose, stackedTraffic, tokens } from '../charts.js';
import { pagedCard } from '../cardtable.js';
import { dimRow } from '../identity.js';
import { renderPivot } from '../facetfilter.js';
import { pathCell } from '../url.js';

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

    /* EACH MEASURE NAMES ITS OWN DENOMINATOR. The caption used to claim all four covered one
       population, which was true and was the reason the card was usually empty: on a range where
       no human session happened to have a beacon, the LOG SPAN — a number that exists for every
       log-backed session — was reported as an em-dash too. The span and the three beacon clocks
       describe different populations because they are measured by different things, and saying
       which is more honest than forcing them onto one. */
    const lines = [];

    if (t.spanned) {
        lines.push('Log span covers the ' + num(t.spanned) + ' completed human session' +
            (t.spanned === 1 ? '' : 's') + ' that made more than one request.');
        if (t.single_request) {
            lines.push('A further ' + num(t.single_request) + ' made exactly one, so they have no span to ' +
                'measure and are excluded rather than averaged in as zero.');
        }
        if (t.span_floored) {
            lines.push(num(t.span_floored) + ' of them (' + pct(t.span_floored, t.spanned) +
                ') came out shorter than this log\'s clock can measure.');
        }
    } else {
        lines.push('No completed human session in this range made more than one request, so there is no ' +
            'span to measure.');
    }

    lines.push(t.population
        ? 'Wall, visible and engaged time cover the ' + num(t.population) + ' of those human sessions that ' +
          'produced beacon data (' + pct(t.population, t.humans) + ' of ' + num(t.humans) + '); the other ' +
          num(t.without_beacon) + ' had no beacon and are excluded entirely, not counted as zero.'
        : 'No human session in this range produced beacon data, so wall, visible and engaged time are ' +
          'unknown. They are shown as em-dashes rather than zeroes.');

    setPop('ov-timing', lines.join(' '));

    /* The mixed-planes caveat is revealed only when the range actually holds sessions with no
       transport plane. On a single-machine install it describes nothing. */
    const planes = byId('ov-timing-planes');
    if (planes) {
        planes.hidden = !t.beacon_only;
    }
    /* Likewise the clock-resolution paragraph: it explains a zero that is a floor rather than a
       measurement, and on a log that records a fraction there are none to explain. */
    const floor = byId('ov-timing-floor');
    if (floor) {
        floor.hidden = !t.span_floored;
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
 * Draw the medians as one horizontal comparison, with the accent on the honest number.
 *
 * A MEASURE THAT HAS NO VALUE IS NOT A BAR OF ZERO. Every row used to be coerced with
 * `|| 0`, so a card where nothing had been measured drew four empty bars against an axis
 * that read "0 ms 0 ms 0 ms 1 ms 1 ms 1 ms" — six ticks of a domain that does not exist,
 * which is a chart of nothing dressed as a chart of something. Rows with no value are
 * dropped, and when that leaves nothing at all the chart is replaced by the empty state,
 * which says so in words.
 */
function renderTimingBars(t) {
    const th = tokens();
    const rows = [
        { label: 'Log span', value: t.log_span_p50, key: 'log_span' },
        { label: 'Wall clock', value: t.wall_p50, key: 'wall' },
        { label: 'Visible', value: t.visible_p50, key: 'visible' },
        { label: 'Engaged', value: t.engaged_p50, key: 'engaged' }
    ].filter((row) => row.value !== null && row.value !== undefined);

    const node = byId('ov-timing-chart');
    if (!rows.length) {
        dispose('ov-timing-chart');
        if (node) {
            node.hidden = true;
        }
        noDataYet('ov-timing-empty', 'measured durations');
        return;
    }
    if (node) {
        node.hidden = false;
    }
    hideEmpty('ov-timing-empty');

    barsH('ov-timing-chart', rows.map((row) => ({
        label: row.label,
        value: row.value,
        color: row.key === 'engaged' ? th.accent : th.pop.declared,
        extra: 'median'
    })), { format: dur });
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
 * Load the top-pages table.
 *
 * Counted in REQUESTS now, from the hits plane — see Panel\Overview::topPages() for why the
 * session count could not rank anything and why the toggle stopped being a population. The
 * distinct sessions behind each path come along as a second column, which is the number the
 * card used to rank by and is still worth reading beside the first.
 *
 * The caption carries the server's `note`, because the count quietly omits sub-resources and
 * instrumentation and anything that omits something has to say so, and `ignored`, because a
 * Verdict filter set elsewhere in the panel cannot narrow a hits-plane card and a table that
 * silently dropped it would be a wrong answer under a chip claiming otherwise.
 */
function renderPages(data) {
    const ignored = (data.ignored || []).length
        ? ' These filters name session-level conclusions the request plane does not carry and do not ' +
          'narrow this table: ' + data.ignored.join(', ') + '.'
        : '';

    setPop('ov-pages', data.population_label + ' \u00b7 ' + num(data.total) + ' requests in range, ranked by ' +
        'how many times each path was fetched.' + (data.note ? ' ' + data.note : '') + ignored);

    if (!data.rows.length) {
        tbody(byId('ov-pages-table'), []);
        return false;
    }
    hideEmpty('ov-pages-empty');

    tbody(byId('ov-pages-table'), data.rows.map((row) => ({
        attrs: dimRow('paths_ss', row.path),
        cells: [
            {
                node: pathCell(row.path, { host: row.host, hosts: row.hosts }),
                class: 'clip urlcell',
                title: row.path,
                sort: row.path
            },
            { text: num(row.requests), num: true, sort: row.requests },
            { text: num(row.sessions), num: true, sort: row.sessions },
            shareCell(row.requests, data.total)
        ]
    })));

    return true;
}

/**
 * A share bar, as a fraction of the TOTAL rather than of the biggest row.
 *
 * THE DEFECT THIS FIXES. Every share bar in the panel divided by `rows[0]`, the largest value
 * in the list — so the top row was always exactly full width and every other row was measured
 * against it. In a top-N list of a long tail that is close to meaningless: the top three paths
 * of a busy site can be 4%, 3% and 3% of its traffic and were drawn as 100%, 75% and 75%, which
 * reads as "these three are the site". A share is a share OF something, and the something is
 * the total the card already knows.
 *
 * A zero total yields a zero-width bar rather than a division by zero, and the title carries
 * the figure in words so the bar is never the only way to read it.
 */
function shareCell(value, total) {
    const share = total > 0 ? (value / total) * 100 : 0;

    return {
        node: el('span', { class: 'bar', title: pct(value, total) + ' of all of them' }, [
            el('span', { style: 'width:' + Math.max(share > 0 ? 1 : 0, Math.round(share)) + '%' })
        ]),
        sort: value
    };
}

/**
 * Load the search-terms table.
 *
 * Two empty states, and telling them apart is the whole value of the card. "Nothing is
 * configured" sends the operator to Settings; "nothing was searched for" is a fact about the
 * range. Rendering the generic one for both would send somebody hunting for a bug in their own
 * search page when the feature had simply never been switched on.
 */
function renderSearches(data) {
    if (!data.configured.length) {
        setPop('ov-searches', 'Not collecting any search terms.');
        tbody(byId('ov-searches-table'), []);
        showEmpty('ov-searches-empty', 'Search terms are not being collected', [
            'Loghound reads a search term out of the URL, and only from the query parameters you '
                + 'have named. None are named on this installation, so nothing is collected and '
                + 'nothing can appear here.',
            el('p', {}, [
                'Name the parameter your search box uses \u2014 ',
                el('code', { text: 'q' }),
                ', ',
                el('code', { text: 's' }),
                ' or whatever your site puts in the address \u2014 under ',
                el('a', { href: '?v=settings&s=beacon', text: 'Settings, in the beacon section' }),
                '. Terms start appearing here from the next visit onwards; nothing is recovered '
                + 'retrospectively.'
            ])
        ]);
        return 'own';
    }

    setPop('ov-searches', num(data.searched) + ' of ' + num(data.total) + ' sessions in range ran a ' +
        'search. Counted as sessions that searched for a term at least once, not as the number of ' +
        'searches: a visitor who ran the same search six times counts once.');

    if (!data.rows.length) {
        tbody(byId('ov-searches-table'), []);
        return false;
    }
    hideEmpty('ov-searches-empty');

    /* Share of the sessions that actually SEARCHED, not of the largest row and not of every
       session in range. `data.searched` is the denominator the count belongs to: a term used by
       half the people who searched is 50%, whatever proportion of visitors search at all. See
       shareCell() for why dividing by the top row was wrong on every table that did it. */
    tbody(byId('ov-searches-table'), data.rows.map((row) => ({
        attrs: dimRow('search_terms_ss', row.value),
        cells: [
            { text: row.param || '—', clip: true, sort: row.param },
            { text: row.term, clip: true, sort: row.term },
            { text: num(row.sessions), num: true, sort: row.sessions },
            shareCell(row.sessions, data.searched)
        ]
    })));

    return true;
}

/** Which of the two things the top-pages table is counting. */
let scope = 'pages';

/**
 * The top-pages loader, assigned once the card is wired.
 *
 * Held here because the toggle has to restart the table AT ITS FIRST PAGE: a change of scope
 * changes the population, and the offset the reader was at named a row in a different one.
 */
let loadPages = () => {};

/**
 * Wire the pages/every-request toggle.
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
            scope = button.dataset.pop;
            loadPages(0);
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
    loadPages = pagedCard({
        id: 'ov-pages',
        label: 'Counting requests by path',
        empty: 'page requests',
        fetch: (start) => api('overview', 'toppages', { pop: scope, start: start }),
        render: renderPages
    });

    pagedCard({
        id: 'ov-searches',
        label: 'Faceting search terms',
        empty: 'search terms',
        fetch: (start) => api('overview', 'searches', { start: start }),
        render: renderSearches
    });
}
