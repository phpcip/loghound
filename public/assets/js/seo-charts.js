/*
 * Loghound — the charts SEO Tools draws.
 *
 * Built on charts.js and nothing else: draw() for the lifecycle, the theme and the resize, and the
 * shared axes and tooltip placement. Every value interpolated into a tooltip goes through tip`…`.
 */

'use strict';

import { draw, ramp, shadowPointer, valueAxis } from './charts.js';
import { boot, markup, num, tip } from './core.js';

/**
 * The label of a bucket that starts at an instant, in the display timezone, at the bucket's grain.
 *
 * @param {string} iso
 * @param {string} step hour, day, week, month or year
 * @returns {string}
 */
export function bucketLabel(iso, step) {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) {
        return '';
    }
    const parts = {};
    const format = new Intl.DateTimeFormat('en-US', {
        timeZone: boot.tz || 'UTC',
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false
    });
    for (const p of format.formatToParts(d)) {
        parts[p.type] = p.value;
    }
    const hour = parts.hour === '24' ? '00' : parts.hour;

    if (step === 'hour') {
        return parts.month + '/' + parts.day + ' ' + hour + ':00';
    }
    if (step === 'month') {
        return parts.month + '/' + parts.year;
    }
    if (step === 'year') {
        return parts.year;
    }
    return parts.month + '/' + parts.day + '/' + parts.year;
}

/**
 * One line series, marked with a point when it has exactly one value so it is not invisible.
 */
function lineSeries(name, data, color, type, width) {
    const real = data.filter((v) => v !== null && v !== undefined).length;
    return {
        name: name,
        type: 'line',
        symbol: real === 1 ? 'circle' : 'none',
        symbolSize: 6,
        connectNulls: false,
        lineStyle: { width: width, color: color, type: type },
        itemStyle: { color: color },
        data: data
    };
}

/** A category axis of bucket labels. */
function bucketAxis(t, labels) {
    return {
        type: 'category',
        data: labels,
        boundaryGap: false,
        axisLine: { lineStyle: { color: t.border } },
        axisTick: { show: false },
        axisLabel: { color: t.axis, fontFamily: t.mono, fontSize: 14, hideOverlap: true }
    };
}

/**
 * Two periods on one axis, aligned by position: point i of each is the i-th bucket of its own period.
 *
 * The axis is labelled with period A's buckets; the tooltip names the bucket of each period.
 *
 * @param {string} id
 * @param {{a:number[], b:number[], aTimes:string[], bTimes:string[], step:string, nameA:string, nameB:string, what:string}} spec
 */
export function compareLines(id, spec) {
    const length = Math.max(spec.a.length, spec.b.length);
    const labels = [];
    for (let i = 0; i < length; i += 1) {
        labels.push(i < spec.aTimes.length ? bucketLabel(spec.aTimes[i], spec.step) : '');
    }
    const pad = (list) => {
        const out = list.slice();
        while (out.length < length) {
            out.push(null);
        }
        return out;
    };
    const a = pad(spec.a);
    const b = pad(spec.b);

    return draw(id, (t) => ({
        legend: { data: [spec.nameA, spec.nameB] },
        grid: { top: 34 },
        tooltip: {
            trigger: 'axis',
            axisPointer: { type: 'line', lineStyle: { color: t.border } },
            formatter: (params) => {
                if (!params.length) {
                    return '';
                }
                const i = params[0].dataIndex;
                const line = (name, times, values) => {
                    const when = i < times.length ? bucketLabel(times[i], spec.step) : 'no matching point';
                    const value = values[i] === null || values[i] === undefined ? 'none' : num(values[i]);
                    return tip`${name} <span style="color:${t.muted}">${when}</span>` +
                        tip`<span style="float:right;padding-left:18px;font-weight:600">${value}</span>`;
                };
                return tip`<div style="color:${t.muted}">${spec.what}</div>` +
                    line(spec.nameA, spec.aTimes, a) + '<br>' + line(spec.nameB, spec.bTimes, b);
            }
        },
        xAxis: bucketAxis(t, labels),
        yAxis: valueAxis(t),
        series: [
            lineSeries(spec.nameA, a, t.accent, 'solid', 2),
            lineSeries(spec.nameB, b, t.pop.declared, 'dashed', 1.6)
        ]
    }));
}

/**
 * Horizontal bars, two per category: the comparison period beside this period.
 *
 * The container grows with the number of categories, and the label column is measured from the
 * labels so a name is shortened at its end, never clipped at its start.
 *
 * @param {string} id
 * @param {Array<{label:string, a:number|null, b:number|null}>} rows
 * @param {string} nameA
 * @param {string} nameB
 * @param {{format?:Function, rowPx?:number}} [opts] Value formatter, and pixels per category row.
 */
export function compareBars(id, rows, nameA, nameB, opts) {
    const options = opts || {};
    const format = options.format || num;
    const say = (value) => (value === null || value === undefined ? 'not measured' : format(value));
    const node = document.getElementById(id);
    const labels = rows.map((r) => r.label).reverse();
    const width = (node && node.clientWidth) || 480;
    const longest = labels.reduce((m, l) => Math.max(m, String(l).length), 0);
    const room = Math.max(60, Math.min(Math.ceil(longest * 8.1) + 4, Math.max(88, Math.floor(width * 0.42))));

    if (node) {
        node.style.height = Math.max(160, rows.length * (options.rowPx || 44) + 70) + 'px';
    }

    const chart = draw(id, (t) => ({
        legend: { data: [nameA, nameB] },
        grid: { left: room + 14, right: 64, top: 34, bottom: 26, containLabel: false },
        tooltip: {
            trigger: 'axis',
            axisPointer: shadowPointer(t),
            formatter: (params) => {
                if (!params.length) {
                    return '';
                }
                const lines = [tip`<strong>${params[0].name}</strong>`];
                for (const p of params.slice().reverse()) {
                    lines.push(tip`${markup(p.marker)} ${p.seriesName}` +
                        tip`<span style="float:right;padding-left:18px;font-weight:600">${say(p.value)}</span>`);
                }
                return lines.join('<br>');
            }
        },
        xAxis: Object.assign(valueAxis(t, format), { splitNumber: 4 }),
        yAxis: {
            type: 'category',
            data: labels,
            axisLine: { show: false },
            axisTick: { show: false },
            axisLabel: {
                color: t.text,
                fontFamily: t.ui,
                fontSize: 14,
                width: room,
                overflow: 'truncate',
                ellipsis: '…'
            }
        },
        series: [
            {
                name: nameB,
                type: 'bar',
                barMaxWidth: 14,
                barGap: '15%',
                itemStyle: { color: t.pop.declared },
                data: rows.map((r) => r.b).reverse()
            },
            {
                name: nameA,
                type: 'bar',
                barMaxWidth: 14,
                itemStyle: { color: t.accent },
                data: rows.map((r) => r.a).reverse(),
                label: {
                    show: true,
                    position: 'right',
                    color: t.muted,
                    fontFamily: t.mono,
                    fontSize: 14,
                    formatter: (p) => (p.value === null || p.value === undefined ? '' : format(p.value))
                }
            }
        ]
    }));

    if (chart) {
        chart.resize();
    }
    return chart;
}

/**
 * One line per channel across a period, coloured from the shared ramp in the current theme.
 *
 * @param {string} id
 * @param {string[]} times Bucket starts.
 * @param {Array<{name:string, data:number[]}>} series
 * @param {string} step
 */
export function channelLines(id, times, series, step) {
    const labels = times.map((iso) => bucketLabel(iso, step));

    return draw(id, (t) => {
        const colors = ramp(t);
        return {
            legend: { data: series.map((s) => s.name) },
            grid: { top: 34 },
            tooltip: {
                trigger: 'axis',
                axisPointer: { type: 'line', lineStyle: { color: t.border } },
                formatter: (params) => {
                    if (!params.length) {
                        return '';
                    }
                    const rows = [tip`<div style="color:${t.muted}">${params[0].axisValue}</div>`];
                    for (const p of params) {
                        rows.push(tip`${markup(p.marker)} ${p.seriesName}` +
                            tip`<span style="float:right;padding-left:18px;font-weight:600">${num(p.value)}</span>`);
                    }
                    return rows.join('<br>');
                }
            },
            xAxis: bucketAxis(t, labels),
            yAxis: valueAxis(t),
            series: series.map((s, i) => lineSeries(s.name, s.data, colors[i % colors.length], 'solid', 1.8))
        };
    });
}
