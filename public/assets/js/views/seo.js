/*
 * Loghound — SEO Tools: this period against another.
 *
 * The period selector is a server-rendered GET form; this module submits it when a preset changes,
 * reveals the date fields for custom dates, and sets the earliest date the pickers accept. Every
 * card reads both periods from the URL through api(), so a card cannot be scoped differently from
 * the selector above it. loadCard() skips the cards that are not on this page.
 */

'use strict';

import { api, byId, dec, dur, el, hideEmpty, loadCard, num, setPop, showEmpty, tbody, when } from '../core.js';
import { changeCell, pagedCard } from '../cardtable.js';
import { dispose } from '../charts.js';
import { countryName } from '../geo.js';
import { dimValue, valueText } from '../identity.js';
import { pathCell } from '../url.js';
import { channelLines, compareBars, compareLines } from '../seo-charts.js';
import { t as T, tn as Tn, tf as Tf, tfn as Tfn } from '../i18n.js';

/** The width below which the panel is laid out for a phone; matches mobile.css. */
const PHONE_QUERY = '(max-width: 900px)';

/** What the engagement chart compares for each metric: its kind and its name. */
const QUALITY_METRICS = {
    visits: ['count', T('Visits')],
    pages_per_visit: ['ratio', T('Pages per visit')],
    one_page_share: ['pct', T('One-page visits')],
    engaged_p50: ['ms', T('Median engaged time')]
};

/** The last engagement payload, so switching the metric redraws without a fetch. */
let qualityData = null;

/** The metric the engagement chart compares. */
let qualityMetric = 'visits';

/** Is the panel laid out for a phone? */
function isPhone() {
    return window.matchMedia ? window.matchMedia(PHONE_QUERY).matches : window.innerWidth <= 900;
}

/** The words a chart axis uses for one value of a dimension. */
function chartLabel(field, value) {
    if (field === 'country_s') {
        return countryName(value) || String(value);
    }
    return valueText(field, value);
}

/**
 * Two bars per row above a card's table: the first series beside the second.
 *
 * The rows are drawn in the order the table shows them, the top 12 at desktop width and the top 8
 * on a phone, and a row with nothing in either series is left out. With nothing left, the chart is
 * removed rather than drawn empty.
 *
 * @param {string} cardId
 * @param {string} suffix Distinguishes two charts on one card.
 * @param {Array<{label:string, a:number|null, b:number|null}>} rows
 * @param {string} nameA
 * @param {string} nameB
 * @param {{format?:Function, label?:string}} [opts]
 */
function pairChart(cardId, suffix, rows, nameA, nameB, opts) {
    const options = opts || {};
    const id = cardId + '-' + suffix;
    const content = byId(cardId + '-content');
    let node = byId(id);

    const usable = (rows || [])
        .filter((row) => (Number(row.a) || 0) !== 0 || (Number(row.b) || 0) !== 0)
        .slice(0, isPhone() ? 8 : 12);

    if (!usable.length || !content) {
        if (node) {
            dispose(id);
            node.remove();
        }
        return;
    }

    if (!node) {
        node = el('div', { class: 'chart seo-pairchart', id: id, role: 'img' });
        const wrap = content.querySelector('.table-wrap');
        if (wrap && wrap.parentNode) {
            wrap.parentNode.insertBefore(node, wrap);
        } else {
            content.appendChild(node);
        }
    }
    if (options.label) {
        node.setAttribute('aria-label', options.label);
    }

    reveal(cardId);
    compareBars(id, usable, nameA, nameB, { format: options.format, rowPx: isPhone() ? 30 : 36 });
}

/** Legend name of the selected period. */
const NAME_A = T('This period');

/** Legend name of the period it is compared with. */
const NAME_B = T('Compared with');

/** The words for a figure nothing measured. */
const NOT_MEASURED = T('not measured');

/** The movers cards, with the panel the server knows each as and the field its values belong to. */
const MOVERS = {
    'seo-engines': { panel: 'engines', field: 'referer_host_s', channel: true },
    'seo-landing': { panel: 'landing', field: 'entry_path_s', channel: false },
    'seo-referrers': { panel: 'referrers', field: 'referer_host_s', channel: true },
    'seo-audience': { panel: 'audience', field: null, channel: false }
};

/** What the timeline draws for each metric. */
const METRIC_LABELS = {
    visits: T('Visits'),
    pageviews: T('Pageviews'),
    search: T('Visits from search engines'),
    ai: T('Visits from AI assistants')
};

/** The sentence an empty movers table shows, by ranking. */
const EMPTY_REASONS = {
    gain: T('Nothing grew against the comparison period.'),
    loss: T('Nothing dropped against the comparison period.'),
    now: T('No visits in this period.'),
    new: T('Nothing had visits in this period that had none in the comparison period.'),
    gone: T('Nothing that had visits in the comparison period is missing from this one.')
};

/** The last timeline payload, so switching the metric redraws without a fetch. */
let timelineData = null;

/** The metric the timeline draws. */
let metric = 'visits';

/** Loader per movers card, so a control can restart its table at page one. */
const moverLoaders = {};

/**
 * A figure in the words its kind is read in, or "not measured" when there is none.
 *
 * @param {string} kind count, ratio, pct or ms
 * @param {number|null} value
 */
function fmt(kind, value) {
    if (value === null || value === undefined) {
        return NOT_MEASURED;
    }
    if (kind === 'ratio') {
        return dec(value, 2);
    }
    if (kind === 'pct') {
        return dec(value, 1) + '%';
    }
    if (kind === 'ms') {
        return dur(value);
    }
    return num(value);
}

/** A relative change: new, gone, no change, or a signed percentage. */
function pctChange(a, b) {
    if (a === null || a === undefined || b === null || b === undefined) {
        return el('span', { class: 'muted', text: NOT_MEASURED });
    }
    if (a === b) {
        return el('span', { class: 'muted', text: T('no change') });
    }
    if (b === 0) {
        return el('span', { class: 'chip chip-accent', text: T('new') });
    }
    if (a === 0) {
        return el('span', { class: 'chip', text: T('gone') });
    }
    const p = ((a - b) / b) * 100;
    return el('span', {
        class: 'mono ' + (p > 0 ? 'trend-up' : 'trend-down'),
        text: (p > 0 ? '+' : '−') + dec(Math.abs(p), 1) + '%'
    });
}

/** A change between two percentages, in percentage points. */
function pointChange(a, b) {
    if (a === null || a === undefined || b === null || b === undefined) {
        return el('span', { class: 'muted', text: NOT_MEASURED });
    }
    const d = a - b;
    if (Math.abs(d) < 0.05) {
        return el('span', { class: 'muted', text: T('no change') });
    }
    return el('span', {
        class: 'mono ' + (d > 0 ? 'trend-up' : 'trend-down'),
        text: T('{n} pts', { n: (d > 0 ? '+' : '−') + dec(Math.abs(d), 1) })
    });
}

/** The change a metric of this kind is read as. */
function metricChange(kind, a, b) {
    return kind === 'pct' ? pointChange(a, b) : pctChange(a, b);
}

/** A sortable number for a relative change, with new above every finite change. */
function pctSort(a, b) {
    if (!b) {
        return a ? 1e12 : 0;
    }
    return (a - b) / b;
}

/** A share of a total, or the words for a total of nothing. */
function share(value, total) {
    return total > 0 ? dec((value / total) * 100, 1) + '%' : T('no visits');
}

/** Both periods and the change, on one line, for a cell. */
function dual(kind, a, b) {
    return el('span', { class: 'seo-dual' }, [
        el('span', { class: 'seo-dual-now', text: fmt(kind, a) }),
        el('span', { class: 'seo-dual-before', text: T('was {value}', { value: fmt(kind, b) }) }),
        el('span', { class: 'seo-dual-change' }, [metricChange(kind, a, b)])
    ]);
}

/** The four number cells every count comparison ends in. */
function countCells(a, b) {
    return [
        { text: num(a), num: true, sort: a },
        { text: num(b), num: true, sort: b },
        { node: changeCell(a, b), class: 'num', sort: a - b },
        { node: pctChange(a, b), class: 'num', sort: pctSort(a, b) }
    ];
}

/** Show a card's content before a chart is drawn into it, so the chart measures its real width. */
function reveal(id) {
    const content = byId(id + '-content');
    if (content) {
        content.hidden = false;
    }
}

/** The value of a select on this page, or the fallback when it is not here. */
function selected(id, fallback) {
    const node = byId(id);
    return node && node.value ? node.value : fallback;
}

/** The pressed button's value in a toggle group, or the fallback. */
function pressed(groupId, attr, fallback) {
    const button = document.querySelector('#' + groupId + ' button.on');
    return button && button.dataset[attr] ? button.dataset[attr] : fallback;
}

/** Press one button of a toggle group and report its value. */
function wireToggle(groupId, attr, onChange) {
    const group = byId(groupId);
    if (!group) {
        return;
    }
    for (const button of group.querySelectorAll('button[data-' + attr + ']')) {
        button.addEventListener('click', () => {
            for (const other of group.querySelectorAll('button')) {
                const on = other === button;
                other.classList.toggle('on', on);
                other.setAttribute('aria-pressed', on ? 'true' : 'false');
            }
            onChange(button.dataset[attr]);
        });
    }
}

/** Report a select's changes. */
function wireSelect(id, onChange) {
    const node = byId(id);
    if (node) {
        node.addEventListener('change', () => onChange(node.value));
    }
}

/** Point a card's CSV link at the choices on screen, through the export control's own overrides. */
function syncExport(cardId, params) {
    const link = document.querySelector('[data-card="' + cardId + '"] a.export[data-export]');
    if (!link) {
        return;
    }
    for (const key of Object.keys(params)) {
        const value = params[key] === null || params[key] === undefined ? '' : String(params[key]);
        link.dataset['exportParam' + key.charAt(0).toUpperCase() + key.slice(1)] = value;
    }
}

/** Say on a card which filters the request log could not apply. */
function ignoredNote(id, list) {
    const node = byId(id + '-ignored');
    if (!node) {
        return;
    }
    if (Array.isArray(list) && list.length) {
        node.textContent = T('Not applied to crawler requests, because a request does not carry it: {filters}.', { filters: list.join(', ') });
        node.hidden = false;
        return;
    }
    node.textContent = '';
    node.hidden = true;
}

/* -------------------------------------------------------------------------
 * The period selector
 * ---------------------------------------------------------------------- */

/** Submit on a preset, reveal the dates for custom, and bound the pickers by the data. */
function initPeriods() {
    const form = byId('seo-periods');
    if (!form) {
        return;
    }
    const cmp = byId('seo-cmp');
    const vs = byId('seo-vs');

    // A hidden picker is disabled too: hiding does not exempt it from validation, so a derived
    // date before the earliest one blocked Apply on a field nobody could see.
    const toggle = (span, on) => {
        if (!span) {
            return;
        }
        span.hidden = !on;
        span.querySelectorAll('input').forEach((input) => {
            input.disabled = !on;
        });
    };
    const sync = () => {
        if (cmp) {
            toggle(byId('seo-dates-a'), cmp.value === 'custom');
        }
        if (vs) {
            toggle(byId('seo-dates-b'), vs.value === 'custom');
        }
    };
    const changed = () => {
        sync();
        if (cmp && vs && cmp.value !== 'custom' && vs.value !== 'custom') {
            form.submit();
        }
    };

    if (cmp) {
        cmp.addEventListener('change', changed);
    }
    if (vs) {
        vs.addEventListener('change', changed);
    }
    sync();
    loadBounds();
}

/** Set the earliest selectable date and say when history starts. A failure leaves the pickers open. */
async function loadBounds() {
    let data;
    try {
        data = await api('seo', 'bounds');
    } catch (err) {
        return;
    }
    if (!data || !data.earliest_date) {
        return;
    }
    for (const id of ['seo-from', 'seo-to', 'seo-vs-from', 'seo-vs-to']) {
        const node = byId(id);
        if (node) {
            node.setAttribute('min', data.earliest_date);
        }
    }
    const note = byId('seo-history');
    if (note) {
        note.textContent = T('History starts {when}', { when: when(data.earliest) });
        note.hidden = false;
    }
}

/* -------------------------------------------------------------------------
 * Scorecard
 * ---------------------------------------------------------------------- */

/** Load the tiles and the timeline together. */
function loadScorecard() {
    return loadCard('seo-scorecard', T('Comparing the two periods'), async () => {
        const [card, line] = await Promise.all([api('seo', 'scorecard'), api('seo', 'timeline')]);
        reveal('seo-scorecard');
        renderTiles(card);
        timelineData = line;
        drawTimeline();
    });
}

/** One tile per headline figure. */
function renderTiles(data) {
    const mount = byId('seo-scorecard-tiles');
    if (!mount) {
        return;
    }
    setPop('seo-scorecard', T('Visits that loaded at least one page, counted in the period they arrived in, under every '
        + 'filter in force. Median engaged time covers finished visits the beacon measured: '
        + '{a} in this period, {b} in the comparison period.', { a: num(data.engaged_n.a), b: num(data.engaged_n.b) }));

    mount.replaceChildren(...data.metrics.map((m) => el('div', { class: 'seo-tile', title: m.hint }, [
        el('span', { class: 'seo-tile-label', text: m.label }),
        el('span', { class: 'seo-tile-value', text: fmt(m.kind, m.a) }),
        el('span', { class: 'seo-tile-before', text: T('Compared with {value}', { value: fmt(m.kind, m.b) }) }),
        el('span', { class: 'seo-tile-change' }, [metricChange(m.kind, m.a, m.b)])
    ])));
}

/** Draw the chosen metric for both periods. */
function drawTimeline() {
    if (!timelineData || !byId('seo-timeline')) {
        return;
    }
    compareLines('seo-timeline', {
        step: timelineData.step,
        aTimes: timelineData.a.times,
        bTimes: timelineData.b.times,
        a: timelineData.a.series[metric] || [],
        b: timelineData.b.series[metric] || [],
        nameA: NAME_A,
        nameB: NAME_B,
        what: METRIC_LABELS[metric]
    });
    const note = byId('seo-timeline-note');
    if (note) {
        note.textContent = T('{what} per {step}. Point by point, each period is drawn '
            + 'from its own start, so the lines line up by position in the period rather than by date.', { what: METRIC_LABELS[metric], step: ({ hour: T('hour'), day: T('day'), week: T('week'), month: T('month'), year: T('year') })[timelineData.step] || timelineData.step });
    }
}

/* -------------------------------------------------------------------------
 * Channels
 * ---------------------------------------------------------------------- */

/** Load the channel comparison and the channel lines together. */
function loadChannels() {
    return loadCard('seo-channels', T('Comparing channels'), async () => {
        const [data, series] = await Promise.all([api('seo', 'channels'), api('seo', 'channel_series')]);
        reveal('seo-channels');
        renderChannels(data);

        const note = byId('seo-channels-lines-note');
        if (note) {
            note.hidden = series.series.length > 0;
            note.textContent = series.series.length ? '' : T('No visits in this period to draw.');
        }
        channelLines('seo-channels-lines', series.times, series.series.map((s) => ({ name: s.label, data: s.data })), series.step);
    });
}

/** The bars and the table of channels. */
function renderChannels(data) {
    setPop('seo-channels', Tn('{n} visit in this period, {b} in the comparison '
        + 'period. Direct means no referrer arrived, not that somebody typed your address.', '{n} visits in this period, {b} in the comparison '
        + 'period. Direct means no referrer arrived, not that somebody typed your address.', data.total_a, { n: num(data.total_a), b: num(data.total_b) }));

    compareBars('seo-channels-bars', data.rows.map((r) => ({ label: r.label, a: r.a, b: r.b })), NAME_A, NAME_B);

    tbody(byId('seo-channels-table'), data.rows.map((row) => ({
        cells: [
            { node: dimValue('referer_type_s', row.value), sort: row.label },
            ...countCells(row.a, row.b),
            { text: share(row.a, data.total_a), num: true, sort: row.a },
            { text: share(row.b, data.total_b), num: true, sort: row.b }
        ]
    })));
}

/* -------------------------------------------------------------------------
 * Movers
 * ---------------------------------------------------------------------- */

/** The choices on screen for one movers card. */
function moverParams(id) {
    return {
        panel: MOVERS[id].panel,
        dim: selected(id + '-dim', ''),
        chan: selected(id + '-chan', ''),
        sort: pressed(id + '-sort', 'sort', 'gain')
    };
}

/** Start one movers card and wire its controls. */
function initMovers(id) {
    const spec = MOVERS[id];

    moverLoaders[id] = pagedCard({
        id: id,
        label: T('Ranking what moved'),
        empty: T('values'),
        fetch: (start, rows) => {
            const params = moverParams(id);
            syncExport(id, params);
            return api('seo', 'movers', {
                panel: params.panel,
                dim: params.dim || null,
                chan: params.chan || null,
                sort: params.sort,
                start: start,
                rows: rows
            });
        },
        render: (data) => renderMovers(id, spec, data)
    });

    wireSelect(id + '-dim', () => moverLoaders[id](0));
    wireSelect(id + '-chan', () => moverLoaders[id](0));
    wireToggle(id + '-sort', 'sort', () => moverLoaders[id](0));
}

/** The channels a referring site sent visits through. */
function channelNode(kinds) {
    if (!Array.isArray(kinds) || !kinds.length) {
        return el('span', { class: 'muted', text: T('not recorded') });
    }
    const parts = [];
    kinds.forEach((kind, i) => {
        if (i > 0) {
            parts.push(' ');
        }
        parts.push(dimValue('referer_type_s', kind));
    });
    return el('span', {}, parts);
}

/** The first cell of a movers row, in the shape its dimension is read in. */
function valueCell(field, row) {
    if (field === 'entry_path_s') {
        return {
            node: pathCell(row.value, { host: row.host, hosts: row.hosts }),
            class: 'clip urlcell',
            title: row.value,
            sort: row.value
        };
    }
    return {
        node: dimValue(field, row.value, { mono: field === 'referer_host_s' }),
        clip: true,
        title: row.value,
        sort: row.value
    };
}

/** Fill a movers table, or say why it is empty. */
function renderMovers(id, spec, data) {
    const field = spec.field || data.dim;
    const head = byId(id + '-head');
    if (head) {
        head.textContent = data.dim_label;
    }

    setPop(id, data.chan_label + ' · ' + Tn('{n} visit in this period, {b} in the comparison period.',
        '{n} visits in this period, {b} in the comparison period.', data.total_a, { n: num(data.total_a), b: num(data.total_b) }) + ' '
        + (data.capped
            ? T('Ranked from the {n} busiest of {total} values across both '
                + 'periods, so a value with little traffic in either can be missing.', { n: num(data.candidates), total: num(data.distinct) }) + ' '
            : '')
        + T('Showing: {what}.', { what: data.sort_label }));

    const table = byId(id + '-table');
    pairChart(id, 'chart', data.rows.map((row) => ({
        label: chartLabel(field, row.value),
        a: row.a,
        b: row.b
    })), NAME_A, NAME_B, { label: data.dim_label + ', ' + data.sort_label });

    if (!data.rows.length) {
        tbody(table, []);
        showEmpty(id + '-empty', T('Nothing to list'), [
            (EMPTY_REASONS[data.sort] || EMPTY_REASONS.now) + ' ' + T('Channel: {channel}, under every filter in force.', { channel: data.chan_label })
        ]);
        return 'own';
    }
    hideEmpty(id + '-empty');

    tbody(table, data.rows.map((row) => {
        const cells = [valueCell(field, row)];
        if (spec.channel) {
            cells.push({ node: channelNode(row.kinds), sort: (row.kinds || []).join(',') });
        }
        return { cells: cells.concat(countCells(row.a, row.b)) };
    }));
    return true;
}

/* -------------------------------------------------------------------------
 * Engagement by channel
 * ---------------------------------------------------------------------- */

/** Load the behaviour table. */
function loadQuality() {
    return loadCard('seo-quality', T('Measuring each channel'), async () => {
        renderQuality(await api('seo', 'quality'));
    });
}

/** A sortable number for a figure that may be missing. */
function sortable(value) {
    return value === null || value === undefined ? -1 : value;
}

/** Draw the chosen metric for every channel, this period beside the comparison period. */
function drawQuality() {
    if (!qualityData) {
        return;
    }
    const [kind, label] = QUALITY_METRICS[qualityMetric];
    pairChart('seo-quality', 'chart', qualityData.rows.map((row) => ({
        label: row.label,
        a: row.a[qualityMetric],
        b: row.b[qualityMetric]
    })), NAME_A, NAME_B, { format: (value) => fmt(kind, value), label: T('{what} per channel', { what: label }) });
}

/** One row per channel, headed by every channel together. */
function renderQuality(data) {
    qualityData = data;
    drawQuality();
    const rows = [data.overall].concat(data.rows);
    tbody(byId('seo-quality-table'), rows.map((row) => ({
        attrs: row.value === '' ? { class: 'seo-total' } : null,
        cells: [
            {
                node: row.value === '' ? el('strong', { text: row.label }) : dimValue('referer_type_s', row.value),
                sort: row.label
            },
            { node: dual('count', row.a.visits, row.b.visits), class: 'num', sort: row.a.visits },
            { node: dual('ratio', row.a.pages_per_visit, row.b.pages_per_visit), class: 'num', sort: sortable(row.a.pages_per_visit) },
            { node: dual('pct', row.a.one_page_share, row.b.one_page_share), class: 'num', sort: sortable(row.a.one_page_share) },
            {
                node: dual('ms', row.a.engaged_p50, row.b.engaged_p50),
                class: 'num',
                title: Tn('{n} visit measured in this period, {b} in the comparison period', '{n} visits measured in this period, {b} in the comparison period', row.a.engaged_n, { n: num(row.a.engaged_n), b: num(row.b.engaged_n) }),
                sort: sortable(row.a.engaged_p50)
            }
        ]
    })));
}

/* -------------------------------------------------------------------------
 * Crawlers
 * ---------------------------------------------------------------------- */

/** Load the crawler table for the chosen category. */
function loadCrawlers() {
    return loadCard('seo-crawlers', T('Counting crawler requests'), async () => {
        const cat = selected('seo-crawlers-cat', 'all');
        syncExport('seo-crawlers', { cat: cat });
        renderCrawlers(await api('seo', 'crawlers', { cat: cat }));
    });
}

/** How many of a crawler's requests passed forward-confirmed reverse DNS, out of those looked up. */
function verifiedNode(half) {
    if (!half.checked) {
        return el('span', { class: 'muted', text: T('not checked') });
    }
    return el('span', { class: 'mono', text: T('{n} of {total}', { n: num(half.verified), total: num(half.checked) }) });
}

/** Fill the crawler table. */
function renderCrawlers(data) {
    ignoredNote('seo-crawlers', data.ignored);
    setPop('seo-crawlers', data.category_label + ' · ' + Tn('{n} request in this period, {b} in the comparison period.',
        '{n} requests in this period, {b} in the comparison period.', data.total_a, { n: num(data.total_a), b: num(data.total_b) })
        + (data.capped ? ' ' + T('Listing the {n} busiest of {total}.', { n: num(data.rows.length), total: num(data.distinct) }) : '')
        + ' ' + T('Reverse DNS confirmed means the address’s PTR name resolves back to the same address; it does not by '
        + 'itself prove the name belongs to the company the crawler claims.'));

    pairChart('seo-crawlers', 'chart', data.rows.map((row) => ({
        label: row.name,
        a: row.a.requests,
        b: row.b.requests
    })), NAME_A, NAME_B, { label: T('Requests per crawler') });

    pairChart('seo-crawlers', 'errors', data.rows
        .filter((row) => row.a.e4 + row.a.e5 > 0)
        .sort((x, y) => (y.a.e4 + y.a.e5) - (x.a.e4 + x.a.e5))
        .map((row) => ({ label: row.name, a: row.a.e4, b: row.a.e5 })),
    T('4xx answers in this period'), T('5xx answers in this period'), { label: T('Error answers per crawler in this period') });

    if (!data.rows.length) {
        tbody(byId('seo-crawlers-table'), []);
        showEmpty('seo-crawlers-empty', T('No crawler requests'), [
            T('No declared crawler of this kind fetched anything in either period under the filters in force.')
        ]);
        return;
    }
    hideEmpty('seo-crawlers-empty');

    tbody(byId('seo-crawlers-table'), data.rows.map((row) => ({
        cells: [
            { node: dimValue('ua_bot_name_s', row.name), clip: true, title: row.name, sort: row.name },
            {
                node: row.category ? dimValue('ua_bot_cat_s', row.category) : el('span', { class: 'muted', text: T('not recorded') }),
                sort: row.category
            },
            { node: dual('count', row.a.requests, row.b.requests), class: 'num', sort: row.a.requests },
            { node: dual('count', row.a.paths, row.b.paths), class: 'num', sort: row.a.paths },
            { node: dual('count', row.a.e4, row.b.e4), class: 'num', sort: row.a.e4 },
            { node: dual('count', row.a.e5, row.b.e5), class: 'num', sort: row.a.e5 },
            {
                node: verifiedNode(row.a),
                class: 'num',
                title: T('In the comparison period: {value}', { value: row.b.checked ? T('{n} of {total}', { n: num(row.b.verified), total: num(row.b.checked) }) : T('not checked') }),
                sort: row.a.checked ? row.a.verified / row.a.checked : -1
            }
        ]
    })));
}

/* -------------------------------------------------------------------------
 * Crawled, not visited
 * ---------------------------------------------------------------------- */

/** Load the crawl gap for the chosen engine and listing. */
function loadGap() {
    return loadCard('seo-crawlgap', T('Matching crawled pages against visits'), async () => {
        const engine = selected('seo-crawlgap-engine', 'search');
        const sort = pressed('seo-crawlgap-sort', 'sort', 'crawled');
        syncExport('seo-crawlgap', { engine: engine, sort: sort });
        renderGap(await api('seo', 'crawlgap', { engine: engine, sort: sort }));
    });
}

/** Fill the crawl gap table. */
function renderGap(data) {
    ignoredNote('seo-crawlgap', data.ignored);
    setPop('seo-crawlgap', data.engine_label + ' · ' + T('the {n} pages crawled most with a 2xx answer '
        + 'in this period.', { n: num(data.examined) }) + (data.unchecked ? ' ' + T('{n} with a path too long to look up say not checked.', { n: num(data.unchecked) }) : '')
        + ' ' + T('Showing: {what}.', { what: data.sort_label }));

    pairChart('seo-crawlgap', 'chart', data.rows
        .filter((row) => row.visits !== null)
        .map((row) => ({ label: row.path, a: row.crawl, b: row.visits })),
    T('Crawler requests'), T('Visits from the channel'), { label: T('Crawler requests against visits per page') });

    if (!data.rows.length) {
        tbody(byId('seo-crawlgap-table'), []);
        showEmpty('seo-crawlgap-empty', T('Nothing to list'), [
            data.sort === 'unvisited' && data.examined
                ? T('Every page crawled most in this period also received visits from the matching channel.')
                : T('No crawler of this kind fetched a page with a 2xx answer in this period under the filters in force.')
        ]);
        return;
    }
    hideEmpty('seo-crawlgap-empty');

    tbody(byId('seo-crawlgap-table'), data.rows.map((row) => ({
        cells: [
            {
                node: pathCell(row.path, { host: row.host, hosts: row.hosts }),
                class: 'clip urlcell',
                title: row.path,
                sort: row.path
            },
            { text: num(row.crawl), num: true, sort: row.crawl },
            { text: num(row.crawlers), num: true, sort: row.crawlers },
            row.visits === null
                ? { text: T('not checked'), class: 'num muted', sort: -1 }
                : { text: num(row.visits), num: true, sort: row.visits }
        ]
    })));
}

/** Entry point. */
export default function init() {
    initPeriods();

    loadScorecard();
    wireToggle('seo-metric', 'metric', (value) => {
        metric = METRIC_LABELS[value] ? value : 'visits';
        drawTimeline();
    });

    loadChannels();

    for (const id of Object.keys(MOVERS)) {
        initMovers(id);
    }

    loadQuality();
    wireToggle('seo-quality-metric', 'metric', (value) => {
        qualityMetric = QUALITY_METRICS[value] ? value : 'visits';
        drawQuality();
    });

    wireSelect('seo-crawlers-cat', () => loadCrawlers());
    loadCrawlers();

    wireSelect('seo-crawlgap-engine', () => loadGap());
    wireToggle('seo-crawlgap-sort', 'sort', () => loadGap());
    loadGap();
}
