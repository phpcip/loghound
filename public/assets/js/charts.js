/*
 * Loghound — charting.
 *
 * A thin layer over the self-hosted ECharts build in assets/vendor/. Three jobs:
 *
 *   1. Read the design tokens out of the stylesheet rather than duplicating hex codes
 *      here. The CSS is the single source of truth for colour, so a chart cannot drift
 *      out of step with the interface around it, and dark/light needs no second palette.
 *   2. Re-render every chart when the theme changes. ECharts bakes colours into its
 *      options, so a CSS variable flip is not enough on its own.
 *   3. Apply one shared set of defaults — flat, no shadows, monospace axes, tabular
 *      numbers — so seven views look like one product.
 *
 * ECharts is loaded as a classic UMD script (window.echarts) with `defer`, so it is
 * guaranteed to have executed before this module body runs.
 */

'use strict';

import { clockOnly, dur, durUs, esc, num } from './core.js';

/**
 * Read the current theme's colours out of the stylesheet.
 *
 * getComputedStyle on the root element resolves whichever custom-property block is
 * active — base, media query, or explicit override — so this needs no knowledge of how
 * the theme was chosen.
 */
export function tokens() {
    const style = getComputedStyle(document.documentElement);
    const get = (name, fallback) => (style.getPropertyValue(name) || fallback).trim();
    return {
        text:   get('--ink', '#111111'),
        muted:  get('--muted', '#4a4540'),
        faint:  get('--faint', '#6b6560'),
        card:   get('--page', '#ffffff'),
        sunken: get('--chip', '#f4f1ec'),
        border: get('--hairline', '#d9d4cc'),
        grid:   get('--c-grid', '#e8e4dd'),
        axis:   get('--c-axis', '#6b6560'),
        accent: get('--accent', '#c05520'),
        pop: {
            human:    get('--c-human', '#d9d4cc'),
            unknown:  get('--c-unknown', '#b9b3a9'),
            declared: get('--c-declared', '#8a8279'),
            ai:       get('--c-ai', '#4a4540'),
            evasive:  get('--c-evasive', '#c05520')
        },
        ok:   get('--ok', '#111111'),
        mid:  get('--mid', '#8a8279'),
        warn: get('--warn', '#6b6560'),
        bad:  get('--bad', '#c05520'),
        mono: get('--font-mono', 'monospace')
    };
}

/**
 * The categorical ramp, in a fixed order.
 *
 * Used where a chart needs several colours that are not one of the five populations —
 * the ASN treemap, for instance. Kept short on purpose: a chart that needs a tenth
 * colour is a chart that should have been a table.
 */
export function ramp(t) {
    return [t.pop.evasive, t.pop.ai, t.pop.declared, t.pop.unknown, t.pop.human, t.accent, t.mid];
}

/** id → {instance, factory}. Kept so a theme flip can rebuild every live chart. */
const charts = new Map();

/**
 * Render (or re-render) a chart.
 *
 * `factory` is called with the current tokens and must return an ECharts option object.
 * It is stored, not just called, so the same function can be re-run on a theme change
 * with new colours and no refetch.
 *
 * @param {string} id       Element id of the .chart container.
 * @param {Function} factory (tokens) => option
 */
export function draw(id, factory) {
    const node = document.getElementById(id);
    if (!node || !window.echarts) {
        return null;
    }
    let entry = charts.get(id);
    if (!entry) {
        entry = { instance: window.echarts.init(node, null, { renderer: 'canvas' }), factory: factory };
        charts.set(id, entry);
    } else {
        entry.factory = factory;
    }
    const t = tokens();
    entry.instance.setOption(withDefaults(factory(t), t), true);
    return entry.instance;
}

/** Drop a chart (used when a view replaces a container entirely). */
export function dispose(id) {
    const entry = charts.get(id);
    if (entry) {
        entry.instance.dispose();
        charts.delete(id);
    }
}

/**
 * Place a tooltip clear of the mark that triggered it.
 *
 * THE DEFECT THIS FIXES. ECharts anchors a tooltip to the cursor, and on a horizontal bar
 * chart the cursor is ON the bar: the box covered the bar the reader was pointing at and the
 * two either side of it, so hovering to read a value hid the value. The same is true of any
 * thick mark — a stacked band, a histogram column, a donut arc.
 *
 * The rule is the opposite corner, decided per axis: the box goes into whichever vertical
 * half the cursor is NOT in, and whichever horizontal half it is not in. So on a horizontal
 * bar chart it is never on the hovered row, and on a vertical one it is never on the hovered
 * column. It flips once as the cursor crosses the middle rather than following it around,
 * which is steadier to read than a box that chases the pointer.
 *
 * A tooltip taller than half the chart cannot be kept off the hovered row vertically, so it
 * falls back to being pinned as far from the cursor as the canvas allows. Everything is
 * clamped inside the view, which is also why `confine` is set alongside it.
 */
function awayFromCursor(point, params, dom, rect, size) {
    const pad = 10;
    const [w, h] = size.contentSize;
    const [width, height] = size.viewSize;

    const clamp = (v, max) => Math.max(pad, Math.min(v, Math.max(pad, max - pad)));

    const top = point[1] > height / 2 ? pad : height - h - pad;
    const left = point[0] > width / 2 ? pad : width - w - pad;

    return [clamp(left, width - w), clamp(top, height - h)];
}

/**
 * Shared defaults applied to every option.
 *
 * Flat: no shadows anywhere, no gradients, no rounded bars. Monospace on every axis and
 * tooltip so figures line up vertically.
 *
 * The tooltip placement is here rather than on each chart because a box that covers the mark
 * it describes is wrong on every one of them, and a per-chart fix is a fix that the next
 * chart does not get.
 */
function withDefaults(option, t) {
    const base = {
        animationDuration: 260,
        textStyle: { fontFamily: t.mono, fontSize: 14, color: t.muted },
        grid: { left: 8, right: 14, top: 28, bottom: 6, containLabel: true },
        tooltip: {
            backgroundColor: t.card,
            borderColor: t.border,
            borderWidth: 1,
            padding: [8, 10],
            confine: true,
            position: awayFromCursor,
            textStyle: { color: t.text, fontFamily: t.mono, fontSize: 14 },
            extraCssText: 'box-shadow:none;border-radius:3px;'
        },
        legend: {
            top: 0,
            left: 0,
            itemWidth: 10,
            itemHeight: 10,
            itemGap: 14,
            icon: 'rect',
            textStyle: { color: t.muted, fontFamily: t.mono, fontSize: 14 }
        }
    };
    return Object.assign({}, base, option, {
        textStyle: Object.assign({}, base.textStyle, option.textStyle),
        grid: option.grid === null ? undefined : Object.assign({}, base.grid, option.grid),
        tooltip: option.tooltip === false ? undefined : Object.assign({}, base.tooltip, option.tooltip),
        legend: option.legend === false ? undefined : (option.legend ? Object.assign({}, base.legend, option.legend) : undefined)
    });
}

/**
 * How much room the category labels on a horizontal bar chart actually need.
 *
 * THE DEFECT THIS FIXES. The label column used to be a number typed at the call site —
 * 210px, 240px, 300px — and `containLabel` was asked to make it fit. When the longest label
 * was wider than the space left over, the canvas clipped it AT THE LEFT EDGE:
 * `drupal-backend.internal` rendered as `upal-backend.inte…` and `loghound.opensolr.com` as
 * `oghound.opensolr.com`. Losing the first characters is the worst possible outcome for this
 * data — hostnames, handler paths and addresses are told apart by their PREFIX, so a label
 * missing its start is not a shortened label, it is a different one.
 *
 * So the room is measured from the data instead of declared: the longest label at the width
 * the chart is actually being drawn at. It is capped at a share of the container so a single
 * enormous label cannot squeeze the bars out of existence — past the cap the label really is
 * truncated, but deliberately, from the END, with an ellipsis, and the full value is in the
 * tooltip.
 *
 * The measurement is by character count against the monospace stack the panel uses
 * everywhere, which is what makes an estimate safe here: every glyph is the same width, so
 * the only error is the advance ratio, and it is rounded up.
 *
 * @param {string} id     Element id of the chart container, for its current width.
 * @param {Array<string>} labels
 * @returns {number} Pixels to reserve for the label column.
 */
function categoryRoom(id, labels) {
    const node = document.getElementById(id);
    const available = (node && node.clientWidth) || 480;

    let longest = 0;
    for (const label of labels) {
        longest = Math.max(longest, String(label === null || label === undefined ? '' : label).length);
    }

    const wanted = Math.ceil(longest * 8.1) + 4;
    const cap = Math.max(88, Math.floor(available * 0.42));

    return Math.max(60, Math.min(wanted, cap));
}

/**
 * The category axis of a horizontal bar chart, given the room its labels were granted.
 *
 * `overflow: 'truncate'` with an explicit ellipsis is what turns "does not fit" into a
 * shortened label rather than a clipped one, and it always takes the end.
 */
function categoryAxis(t, labels, room) {
    return {
        type: 'category',
        data: labels,
        axisLine: { show: false },
        axisTick: { show: false },
        axisLabel: {
            color: t.text,
            fontSize: 14,
            width: room,
            overflow: 'truncate',
            ellipsis: '…'
        }
    };
}

/**
 * The grid of a horizontal bar chart, with the label column reserved exactly.
 *
 * `containLabel` is deliberately OFF. It asks ECharts to shrink the plot until the labels
 * fit, which it does from a measurement that does not account for a label wider than the
 * whole left margin — the case that produced the clipping above. With it off, `left` IS the
 * plot's left edge, the labels occupy the strip before it, and the arithmetic is ours. The
 * bottom is then explicit too, because nothing is reserving room for the value axis any more.
 */
function barGrid(room, right, top) {
    return {
        left: room + 14,
        right: right,
        top: top,
        bottom: 26,
        containLabel: false
    };
}

/**
 * How many ticks the value axis of a horizontal bar chart can actually show.
 *
 * `axisLabel.hideOverlap` is set on every value axis and is NOT enough on its own: measured
 * at 420px it thinned one chart's labels and left the next one's reading
 * "0 100200300400500". The label column legitimately takes a large share of a narrow chart,
 * so the plot that is left can be a hundred pixels wide with five ticks asked of it.
 *
 * Asking for fewer ticks is deterministic where hiding them is not, and a coarser scale is
 * the correct answer to a narrow one: the numbers shown are still true, there are just fewer.
 */
function valueSplit(id, room, right) {
    const node = document.getElementById(id);
    const available = (node && node.clientWidth) || 480;
    const plot = available - (room + 14) - right;

    return Math.max(2, Math.min(6, Math.round(plot / 70)));
}

/** A time category axis whose labels are formatted in the display timezone. */
export function timeAxis(t, times) {
    return {
        type: 'category',
        data: times,
        boundaryGap: false,
        axisLine: { lineStyle: { color: t.border } },
        axisTick: { show: false },
        axisLabel: {
            color: t.axis,
            fontSize: 14,
            hideOverlap: true,
            formatter: (value) => clockOnly(value)
        }
    };
}

/**
 * A value axis with a faint dashed grid and no axis line.
 *
 * `hideOverlap` for the same reason the category axis measures its column: on a narrow
 * window the plot gets short and ECharts keeps every computed tick, so the labels run into
 * each other and "0 100 200 300 400 500" renders as "0 100200300400500". Dropping ticks that
 * do not fit is the honest way to keep a readable scale — the numbers left are still true.
 */
export function valueAxis(t, formatter) {
    return {
        type: 'value',
        axisLine: { show: false },
        axisTick: { show: false },
        splitLine: { lineStyle: { color: t.grid, type: 'dashed' } },
        axisLabel: {
            color: t.axis,
            fontSize: 14,
            hideOverlap: true,
            formatter: formatter || ((v) => num(v))
        }
    };
}

/**
 * The Overview traffic chart: five mutually exclusive populations, stacked.
 *
 * Stacking is honest here precisely because the populations cannot overlap — every
 * scored session lands in exactly one band, so the top of the stack is the true total.
 *
 * @param {string} id
 * @param {Object} data {times, series:{key:[n]}, labels:{key:label}}
 * @param {Array<string>} order Population keys, bottom to top.
 */
export function stackedTraffic(id, data, order) {
    draw(id, (t) => ({
        legend: { data: order.map((k) => data.labels[k] || k) },
        grid: { top: 34 },
        tooltip: {
            trigger: 'axis',
            axisPointer: { type: 'line', lineStyle: { color: t.border } },
            formatter: (params) => {
                if (!params.length) {
                    return '';
                }
                let total = 0;
                for (const p of params) {
                    total += Number(p.value) || 0;
                }
                const lines = [
                    '<div style="color:' + t.muted + '">' + clockOnly(params[0].axisValue) + '</div>'
                ];
                for (const p of params.slice().reverse()) {
                    lines.push(
                        p.marker + ' ' + esc(p.seriesName) +
                        '<span style="float:right;padding-left:18px;font-weight:600">' + num(p.value) + '</span>'
                    );
                }
                lines.push('<div style="border-top:1px solid ' + t.border + ';margin-top:5px;padding-top:5px">' +
                    'Total<span style="float:right;padding-left:18px;font-weight:600">' + num(total) + '</span></div>');
                return lines.join('<br>');
            }
        },
        xAxis: timeAxis(t, data.times),
        yAxis: valueAxis(t),
        series: order.map((key) => ({
            name: data.labels[key] || key,
            type: 'line',
            stack: 'sessions',
            smooth: false,
            symbol: 'none',
            lineStyle: { width: 1, color: t.pop[key] },
            areaStyle: { color: t.pop[key], opacity: 0.62 },
            emphasis: { focus: 'series' },
            data: data.series[key] || []
        }))
    }));
}

/**
 * Horizontal bars, for the reason codes and anything else with long labels.
 *
 * Horizontal because rule codes are words, and words rotated 45 degrees are unreadable — and
 * because hostnames, handler paths and addresses are long, which is the case that made the
 * label column measure itself rather than take a number from the call site. See categoryRoom().
 *
 * `opts.labelWidth` is accepted and ignored: the column is measured from the data now, and a
 * hand-picked width is exactly what let a label be clipped at its left edge.
 *
 * @param {Array<{label:string,value:number,color?:string,extra?:string}>} rows
 * @param {Object} [opts] {format: value formatter}
 */
export function barsH(id, rows, opts) {
    const options = opts || {};
    const fmt = options.format || num;
    const labels = rows.map((r) => r.label).reverse();
    const room = categoryRoom(id, labels);

    draw(id, (t) => ({
        grid: barGrid(room, 74, 6),
        tooltip: {
            trigger: 'axis',
            axisPointer: { type: 'shadow', shadowStyle: { color: t.sunken } },
            formatter: (params) => {
                const p = params[0];
                const row = rows[rows.length - 1 - p.dataIndex];
                return '<strong>' + esc(p.name) + '</strong><br>' + fmt(p.value) +
                    (row && row.extra ? '<br><span style="color:' + t.muted + '">' + row.extra + '</span>' : '');
            }
        },
        xAxis: Object.assign(valueAxis(t, fmt), {
            splitNumber: valueSplit(id, room, 74),
            splitLine: { lineStyle: { color: t.grid, type: 'dashed' } }
        }),
        yAxis: categoryAxis(t, labels, room),
        series: [{
            type: 'bar',
            barMaxWidth: 16,
            data: rows.map((r) => ({
                value: r.value,
                itemStyle: { color: r.color || t.accent }
            })).reverse(),
            label: {
                show: true,
                position: 'right',
                color: t.muted,
                fontFamily: t.mono,
                fontSize: 14,
                formatter: (p) => fmt(p.value)
            }
        }]
    }));
}

/**
 * Stacked horizontal bars — used for reason codes split into evasive vs declared, which
 * is the split this product refuses to blur.
 *
 * @param {Array<{label:string, parts:Array<{name:string,value:number,color:string}>}>} rows
 */
export function barsHStacked(id, rows) {
    const names = rows.length ? rows[0].parts.map((p) => p.name) : [];
    const labels = rows.map((r) => r.label).reverse();
    const room = categoryRoom(id, labels);

    draw(id, (t) => ({
        legend: { data: names, top: 0 },
        grid: barGrid(room, 60, 30),
        tooltip: {
            trigger: 'axis',
            axisPointer: { type: 'shadow', shadowStyle: { color: t.sunken } },
            /* The axis label may have been truncated to fit its column; the tooltip carries
               the value in full, which is where the reader goes when the row is cut. */
            formatter: (params) => {
                if (!params.length) {
                    return '';
                }
                let total = 0;
                const lines = ['<strong>' + esc(params[0].name) + '</strong>'];
                for (const p of params) {
                    total += Number(p.value) || 0;
                    lines.push(p.marker + ' ' + esc(p.seriesName) +
                        '<span style="float:right;padding-left:18px;font-weight:600">' + num(p.value) + '</span>');
                }
                lines.push('<div style="border-top:1px solid ' + t.border + ';margin-top:5px;padding-top:5px">' +
                    'Total<span style="float:right;padding-left:18px;font-weight:600">' + num(total) + '</span></div>');
                return lines.join('<br>');
            }
        },
        xAxis: Object.assign(valueAxis(t), { splitNumber: valueSplit(id, room, 60) }),
        yAxis: categoryAxis(t, labels, room),
        series: names.map((name, i) => ({
            name: name,
            type: 'bar',
            stack: 'total',
            barMaxWidth: 16,
            itemStyle: { color: rows.length ? rows[0].parts[i].color : t.accent },
            data: rows.map((r) => r.parts[i].value).reverse()
        }))
    }));
}

/**
 * A donut, used for verdict distribution.
 *
 * A donut and not a pie so the total can sit in the middle, and so the eye compares arc
 * length rather than trying to judge area from the centre.
 */
export function donut(id, rows, centreLabel, centreValue) {
    draw(id, (t) => ({
        legend: {
            orient: 'vertical',
            right: 0,
            top: 'middle',
            data: rows.map((r) => r.label)
        },
        tooltip: {
            trigger: 'item',
            formatter: (p) => '<strong>' + esc(p.name) + '</strong><br>' + num(p.value) + ' (' + p.percent + '%)'
        },
        grid: null,
        series: [{
            type: 'pie',
            radius: ['58%', '82%'],
            center: ['32%', '52%'],
            avoidLabelOverlap: true,
            itemStyle: { borderColor: t.card, borderWidth: 2 },
            label: {
                show: true,
                position: 'center',
                formatter: () => '{v|' + centreValue + '}\n{l|' + centreLabel + '}',
                rich: {
                    v: { fontSize: 22, fontWeight: 600, color: t.text, fontFamily: t.mono, lineHeight: 28 },
                    l: { fontSize: 14, color: t.muted, fontFamily: t.mono }
                }
            },
            emphasis: { label: { show: true }, scale: false },
            labelLine: { show: false },
            data: rows.map((r) => ({ name: r.label, value: r.value, itemStyle: { color: r.color } }))
        }]
    }));
}

/**
 * A plain vertical histogram, for the bot-score distribution and the latency distribution.
 *
 * `opts` exists because those two count different things and a tooltip that says "sessions"
 * over a bucket of requests is simply wrong. Both of its keys are optional and the defaults
 * are the bot-score shape that was here first, so the existing caller needs no change.
 *
 * @param {Object} [opts] {noun: what a bar counts, prefix: what the x label is, interval: label stride}
 */
export function histogram(id, rows, colorFor, opts) {
    const options = opts || {};
    const noun = options.noun || 'sessions';
    const prefix = options.prefix === undefined ? 'Score ' : options.prefix;
    const interval = options.interval === undefined ? 3 : options.interval;

    draw(id, (t) => ({
        grid: { top: 12, bottom: 4 },
        tooltip: {
            trigger: 'axis',
            axisPointer: { type: 'shadow', shadowStyle: { color: t.sunken } },
            formatter: (params) => {
                const p = params[0];
                return prefix + esc(p.name) + '<br><strong>' + num(p.value) + '</strong> ' + esc(noun);
            }
        },
        xAxis: {
            type: 'category',
            data: rows.map((r) => r.label),
            axisLine: { lineStyle: { color: t.border } },
            axisTick: { show: false },
            axisLabel: { color: t.axis, fontSize: 14, interval: interval }
        },
        yAxis: valueAxis(t),
        series: [{
            type: 'bar',
            barCategoryGap: '12%',
            data: rows.map((r) => ({ value: r.value, itemStyle: { color: colorFor(r) } }))
        }]
    }));
}

/**
 * The ASN treemap: area is sessions, colour is network type.
 *
 * Colouring by `as_type_s` rather than by size is the whole point — a big box that is
 * "hosting" coloured means something very different from a big box that is "isp".
 */
export function treemap(id, nodes, colorForType, legend) {
    draw(id, (t) => ({
        legend: false,
        tooltip: {
            formatter: (p) => {
                const d = p.data;
                return '<strong>' + esc(d.name) + '</strong><br>' +
                    (d.org ? esc(d.org) + '<br>' : '') +
                    '<span style="color:' + t.muted + '">' + (d.astype || 'unknown') + '</span><br>' +
                    num(d.value) + ' sessions · ' + num(d.uniqIps) + ' IPs<br>' +
                    '<span style="color:' + t.muted + '">' + num(d.human) + ' human · ' +
                    num(d.evasive) + ' evasive</span>';
            }
        },
        grid: null,
        series: [{
            type: 'treemap',
            roam: false,
            nodeClick: false,
            breadcrumb: { show: false },
            width: '100%',
            height: '100%',
            top: legend ? 24 : 0,
            left: 0,
            right: 0,
            bottom: 0,
            itemStyle: { borderColor: t.card, borderWidth: 1, gapWidth: 1 },
            label: {
                show: true,
                color: '#ffffff',
                fontFamily: t.mono,
                fontSize: 14,
                overflow: 'truncate',
                formatter: (p) => p.data.short || p.name
            },
            upperLabel: { show: false },
            data: nodes.map((n) => ({
                name: n.name,
                short: n.short,
                value: n.value,
                org: n.org,
                astype: n.astype,
                uniqIps: n.uniqIps,
                human: n.human,
                evasive: n.evasive,
                itemStyle: { color: colorForType(n.astype) }
            }))
        }]
    }));
}

/**
 * Multi-series line, for latency over time.
 *
 * Nulls are preserved as gaps rather than joined through: a bucket with no timed
 * requests has no p95, and drawing a straight line across it would invent one.
 */
export function lines(id, times, series, formatter) {
    draw(id, (t) => ({
        legend: { data: series.map((s) => s.name) },
        grid: { top: 34 },
        tooltip: {
            trigger: 'axis',
            axisPointer: { type: 'line', lineStyle: { color: t.border } },
            formatter: (params) => {
                const lines = ['<div style="color:' + t.muted + '">' + clockOnly(params[0].axisValue) + '</div>'];
                for (const p of params) {
                    lines.push(p.marker + ' ' + esc(p.seriesName) +
                        '<span style="float:right;padding-left:18px;font-weight:600">' +
                        (p.value === null || p.value === undefined ? '—' : (formatter ? formatter(p.value) : num(p.value))) +
                        '</span>');
                }
                return lines.join('<br>');
            }
        },
        xAxis: timeAxis(t, times),
        yAxis: valueAxis(t, formatter),
        series: series.map((s) => ({
            name: s.name,
            type: 'line',
            symbol: 'none',
            connectNulls: false,
            lineStyle: { width: 1.6, color: s.color },
            itemStyle: { color: s.color },
            data: s.data
        }))
    }));
}

/** Stacked bars over time, for the status-code chart. */
export function stackedBars(id, times, series) {
    draw(id, (t) => ({
        legend: { data: series.map((s) => s.name) },
        grid: { top: 34 },
        tooltip: { trigger: 'axis', axisPointer: { type: 'shadow', shadowStyle: { color: t.sunken } } },
        xAxis: Object.assign(timeAxis(t, times), { boundaryGap: true }),
        yAxis: valueAxis(t),
        series: series.map((s) => ({
            name: s.name,
            type: 'bar',
            stack: 'status',
            barMaxWidth: 22,
            itemStyle: { color: s.color },
            data: s.data
        }))
    }));
}

/**
 * A world scatter on a plain equirectangular grid.
 *
 * There is no basemap: shipping a world GeoJSON would be a few hundred kilobytes for
 * decoration, and the panel has to work on an air-gapped box without pulling one. Points
 * are plotted at country centroids on a lon/lat grid, which is enough to answer "where is
 * this coming from" and is honest about its own resolution.
 */
export function geoScatter(id, points) {
    draw(id, (t) => ({
        legend: false,
        grid: { left: 6, right: 6, top: 10, bottom: 6, containLabel: false },
        tooltip: {
            trigger: 'item',
            formatter: (p) => '<strong>' + esc(p.data.name) + '</strong><br>' +
                num(p.data.sessions) + ' sessions · ' + num(p.data.ips) + ' IPs<br>' +
                '<span style="color:' + t.muted + '">' + num(p.data.human) + ' human · ' +
                num(p.data.evasive) + ' evasive</span>'
        },
        xAxis: {
            type: 'value', min: -180, max: 180,
            axisLine: { show: false }, axisTick: { show: false }, axisLabel: { show: false },
            splitLine: { lineStyle: { color: t.grid, type: 'dotted' } },
            interval: 30
        },
        yAxis: {
            type: 'value', min: -60, max: 85,
            axisLine: { show: false }, axisTick: { show: false }, axisLabel: { show: false },
            splitLine: { lineStyle: { color: t.grid, type: 'dotted' } },
            interval: 30
        },
        series: [{
            type: 'scatter',
            symbolSize: (v, p) => p.data.size,
            itemStyle: {
                color: (p) => (p.data.evasiveRate > 0.5 ? t.pop.evasive : t.accent),
                opacity: 0.72,
                borderColor: t.card,
                borderWidth: 1
            },
            data: points
        }]
    }));
}

/**
 * Draw a sparkline into a canvas.
 *
 * Deliberately not an ECharts instance: the fingerprint table can hold forty of them,
 * and forty chart instances with their own event handlers and resize observers would be
 * a waste. This is twenty lines of canvas and costs nothing.
 */
export function sparkline(canvas, values, color) {
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth || 132;
    const h = canvas.clientHeight || 26;
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    const ctx = canvas.getContext('2d');
    if (!ctx) {
        return;
    }
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);

    if (!values || !values.length) {
        return;
    }
    const max = Math.max(1, ...values);
    const barWidth = w / values.length;
    ctx.fillStyle = color;
    for (let i = 0; i < values.length; i += 1) {
        const raw = (values[i] / max) * (h - 2);
        const barHeight = values[i] > 0 ? Math.max(1, raw) : 0;
        ctx.fillRect(i * barWidth, h - barHeight, Math.max(1, barWidth - 1), barHeight);
    }
}

/**
 * Keep charts sized and themed.
 *
 * ResizeObserver on each container rather than a window resize listener, because the
 * session explorer's layout changes when the detail panel opens without the window
 * changing size at all.
 */
export function initCharts() {
    document.addEventListener('lh:theme', () => {
        const t = tokens();
        for (const entry of charts.values()) {
            entry.instance.setOption(withDefaults(entry.factory(t), t), true);
        }
    });

    /* A resize REBUILDS the option rather than only calling resize(). The horizontal bar
       charts reserve their label column from the container's current width, so a chart that
       is only resized keeps a column sized for the width it was born at — too wide on a
       narrowed window, and too narrow to hold the labels on a widened one, which is how a
       label gets clipped again. Coalesced into one frame because a drag fires this
       continuously. */
    const redraw = (entry) => {
        const t = tokens();
        entry.instance.setOption(withDefaults(entry.factory(t), t), true);
        entry.instance.resize();
    };

    if (window.ResizeObserver) {
        let pending = new Set();
        let queued = false;

        const flush = () => {
            queued = false;
            for (const id of pending) {
                const chart = charts.get(id);
                if (chart) {
                    redraw(chart);
                }
            }
            pending = new Set();
        };

        const observer = new ResizeObserver((entries) => {
            for (const entry of entries) {
                pending.add(entry.target.id);
            }
            if (!queued) {
                queued = true;
                window.requestAnimationFrame(flush);
            }
        });
        for (const node of document.querySelectorAll('.chart')) {
            observer.observe(node);
        }
    } else {
        window.addEventListener('resize', () => {
            for (const [, entry] of charts) {
                redraw(entry);
            }
        });
    }
}

export { dur, durUs, num };
