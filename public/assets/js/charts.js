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

import { clockOnly, dur, durUs, markup, num, tip } from './core.js';

/**
 * Strip the characters that mean something to ECharts' rich-text grammar.
 *
 * A rich-text label is `{style|text}` and is parsed, not escaped: a brace, a pipe or a
 * newline inside the text half re-opens the grammar and the label stops being the label.
 * It is drawn on a canvas so nothing here is an injection into a document, but a value
 * that silently prints as something other than itself is the same class of defect as a
 * number that is quietly wrong, and the values are read off API responses.
 */
function richText(value) {
    return String(value === null || value === undefined ? '' : value).replace(/[{}|\n\r]/g, ' ');
}

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
        /* `--band` is the page's own "one step away from the background" tone, and `--field-border`
           is the edge of something you can interact with. Both were missing here, so the hover
           band and the tooltip had nothing to reach for but `--chip` and `--hairline` — 1.04:1
           and 1.4:1 against the page respectively. */
        band:   get('--band', '#fbfaf8'),
        field:  get('--field-border', '#b9b3a9'),
        border: get('--hairline', '#d9d4cc'),
        /* The tone-corrected accent, for anything that has to sit near text. `--accent` fails a
           contrast audit at 4.1:1 and the stylesheet says so where it declares the pair. */
        accentInk: get('--accent-ink', '#9e340f'),
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
        mono: get('--font-mono', 'monospace'),
        ui:   get('--font-ui', 'system-ui, sans-serif')
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
 * Place a tooltip beside the mark that triggered it, flipping at the edges.
 *
 * THE DEFECT THIS FIXES, and it is the second attempt at it. The first version put the box in
 * the opposite half of the whole chart — whichever vertical half the cursor was not in, and
 * whichever horizontal half it was not in. That does keep the box off the hovered mark, and it
 * does so by throwing the box as far away as the canvas allows, which produced exactly the
 * behaviour that was reported: a tooltip for a Top pages row rendering two rows away and on top
 * of other rows' text; the sessions-over-time tooltip pinned in the top-left corner, over the
 * legend it was obscuring, however far right the hovered point was; and the score-distribution
 * tooltip landing on the x-axis and a neighbouring bar. A tooltip that is nowhere near what it
 * describes is not a fixed tooltip, it is a different defect — the reader has to work out which
 * mark it belongs to, and on a dense chart there is no way to.
 *
 * A tooltip belongs NEXT TO the cursor. So the box is offered the position just to the right of
 * the pointer and vertically centred on it, and each axis flips only when that position would
 * not fit:
 *
 *   * horizontally, to the LEFT of the cursor when the box would otherwise overflow the right
 *     edge — which is what "flipping at the edge" means and what the histogram's tooltip was
 *     not doing;
 *   * vertically, clamped into the view rather than flipped, because a box centred on the
 *     cursor already covers neither the row above nor the row below on any chart whose marks
 *     are thinner than the box, and clamping is steadier to read than a jump.
 *
 * The gap is what keeps it off the mark itself. Everything ends up inside the canvas, which is
 * also why `confine` stays set alongside this: it is the backstop for a box larger than the
 * view, where no placement can satisfy both rules.
 */
function besideCursor(point, params, dom, rect, size) {
    const gap = 14;
    const pad = 4;
    const [w, h] = size.contentSize;
    const [width, height] = size.viewSize;

    let left = point[0] + gap;
    if (left + w > width - pad) {
        left = point[0] - w - gap;
    }
    left = Math.max(pad, Math.min(left, Math.max(pad, width - w - pad)));

    let top = point[1] - h / 2;
    top = Math.max(pad, Math.min(top, Math.max(pad, height - h - pad)));

    return [left, top];
}

/**
 * The band drawn behind the hovered category, for a `shadow` axis pointer.
 *
 * THE DEFECT THIS FIXES. Every chart that used a shadow pointer passed `color: t.band` and
 * nothing else, and `--band` is an OPAQUE near-white in the light theme (#fbfaf8). ECharts
 * draws the axis pointer in a layer above the series, so the band was painted OVER the bar it
 * was highlighting: hovering a bucket to read its value made the bar vanish, and the tooltip
 * then reported a figure for something no longer on screen. Observed with a thirteen-session
 * bar going completely invisible while its own tooltip said 13.
 *
 * A highlight belongs behind what it highlights. There is no way to put this layer behind the
 * series, so the band is made translucent instead: enough to read as a band, not enough to
 * change the bar under it. One helper rather than four call sites, because a highlight that
 * erases its subject is wrong on every chart and a per-chart fix is one the next chart does not
 * get.
 */
function shadowPointer(t) {
    return { type: 'shadow', shadowStyle: { color: t.band, opacity: 0.35 } };
}

/**
 * Shared defaults applied to every option.
 *
 * Flat: no shadows anywhere, no gradients, no rounded bars.
 *
 * TYPEFACE PER ROLE, not per chart. The body face is the default here and monospace is set
 * explicitly on the three things that earn it: a value axis, a time axis and a category axis
 * of identifiers, all of which are read as columns of figures or as strings whose characters
 * have to line up. A legend entry and a tooltip sentence are prose and were being set in
 * monospace only because everything was.
 *
 * ONE ROW OF LEGEND, ALWAYS. `type: 'scroll'` on every legend, because the alternative is
 * wrapping: five entries that fit on one line at 1200px take two at 380px, the second row is
 * drawn over the plot, and nothing reserves room for it — `grid.top` is a constant. A legend
 * that pages is a legend whose height is known.
 *
 * The tooltip placement is here rather than on each chart because a box that covers the mark
 * it describes is wrong on every one of them, and a per-chart fix is a fix that the next
 * chart does not get. The emphasis state is here for exactly the same reason.
 */
function withDefaults(option, t) {
    const base = {
        animationDuration: 260,
        textStyle: { fontFamily: t.ui, fontSize: 14, color: t.muted },
        grid: { left: 8, right: 14, top: 28, bottom: 6, containLabel: true },
        /* THE TOOLTIP NEEDS AN EDGE. Its fill was the PAGE colour with shadows explicitly off
           and a 1px hairline border — #2e2b28 on #111111 in the dark theme, 1.4:1 — so the one
           panel that floats over the chart had no visible boundary, and it is the fallback
           route to every label the axis truncated. The band colour separates it from the page
           in both themes and the border steps up to the field border, which is the token that
           exists for "the edge of a thing you can interact with". */
        tooltip: {
            backgroundColor: t.band,
            borderColor: t.field,
            borderWidth: 1,
            padding: [8, 10],
            confine: true,
            position: besideCursor,
            textStyle: { color: t.text, fontFamily: t.ui, fontSize: 14 },
            extraCssText: 'box-shadow:none;border-radius:2px;'
        },
        legend: {
            top: 0,
            left: 0,
            type: 'scroll',
            itemWidth: 10,
            itemHeight: 10,
            itemGap: 14,
            icon: 'rect',
            textStyle: { color: t.muted, fontFamily: t.ui, fontSize: 14 }
        }
    };

    const merged = Object.assign({}, base, option, {
        textStyle: Object.assign({}, base.textStyle, option.textStyle),
        grid: option.grid === null ? undefined : Object.assign({}, base.grid, option.grid),
        tooltip: option.tooltip === false ? undefined : Object.assign({}, base.tooltip, option.tooltip),
        legend: option.legend === false ? undefined : (option.legend ? Object.assign({}, base.legend, option.legend) : undefined)
    });

    if (Array.isArray(merged.series)) {
        merged.series = merged.series.map((s) => Object.assign({}, s, { emphasis: emphasis(t, s.emphasis) }));
    }
    return merged;
}

/**
 * What a mark looks like while it is the one being pointed at.
 *
 * THE DEFECT THIS FIXES. No series declared an emphasis state, so every chart inherited
 * ECharts' own: it LIGHTENS the mark's fill. Three of the five population colours are already
 * pale by design — `--c-human` is #d9d4cc on a #ffffff page — so lightening them lands on the
 * page colour and the hovered bar disappears. The reader's cursor erased the only bar they
 * were looking at, and the tooltip then described something that was no longer on screen.
 *
 * The replacement keeps the fill exactly as it was (`color: 'inherit'`) and states the
 * emphasis as a ring of ink around the mark. That is the editorial system's own device — a
 * rule, not a tint — it is a step in tone rather than toward the ground, and it reads on both
 * themes because --ink is the maximum contrast the palette has on either. `scale: false`
 * keeps a pie segment from growing into its neighbours, and the label is left alone so a
 * donut's centre figure does not change under the cursor.
 *
 * A series that declares its own emphasis keeps it, merged over this, so `focus: 'series'` on
 * the stacked traffic chart still works.
 */
function emphasis(t, own) {
    const base = {
        scale: false,
        itemStyle: { color: 'inherit', borderColor: t.text, borderWidth: 2, opacity: 1 }
    };
    if (!own) {
        return base;
    }
    return Object.assign({}, base, own, {
        itemStyle: Object.assign({}, base.itemStyle, own.itemStyle)
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
            fontFamily: t.mono,
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
            fontFamily: t.mono,
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

        /* AN AXIS OF WHOLE NUMBERS, ALWAYS. Every value axis in this panel measures a count, a
           duration in milliseconds or a size in bytes, and not one of them has a meaningful
           fractional tick. Without this, a domain of 0 to 1 — which is what an all-zero or
           near-zero dataset produces — is split into 0, 0.2, 0.4, 0.6, 0.8, 1 and then run
           through the duration formatter, which rounds each to the nearest millisecond and
           prints "0 ms 0 ms 0 ms 1 ms 1 ms 1 ms": six ticks, four of them duplicates, on a scale
           with nothing on it. `minInterval` makes the smallest possible step 1, so a degenerate
           domain gets two honest ticks instead of six meaningless ones. The card above is still
           responsible for not drawing a chart of nothing at all; this is what stops the AXIS
           from inventing detail the data does not have. */
        minInterval: 1,

        axisLine: { show: false },
        axisTick: { show: false },
        splitLine: { lineStyle: { color: t.grid, type: 'dashed' } },
        axisLabel: {
            color: t.axis,
            fontFamily: t.mono,
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
                    tip`<div style="color:${t.muted}">${clockOnly(params[0].axisValue)}</div>`
                ];
                for (const p of params.slice().reverse()) {
                    lines.push(
                        tip`${markup(p.marker)} ${p.seriesName}` +
                        tip`<span style="float:right;padding-left:18px;font-weight:600">${num(p.value)}</span>`
                    );
                }
                lines.push(tip`<div style="border-top:1px solid ${t.border};margin-top:5px;padding-top:5px">` +
                    tip`Total<span style="float:right;padding-left:18px;font-weight:600">${num(total)}</span></div>`);
                return lines.join('<br>');
            }
        },
        xAxis: timeAxis(t, data.times),
        yAxis: valueAxis(t),
        /* THE LEGEND AND THE BANDS HAVE TO BE THE SAME COLOUR, AND THEY WERE NOT.
           ECharts takes a legend swatch from the series' `itemStyle.color` (falling back to its
           own default palette), and takes an area from `areaStyle.color`. This series set the
           area and the line and never `itemStyle`, so the five legend entries were painted from
           ECharts' stock palette — blue, green, red — while the five bands underneath were
           painted from the population tokens. The legend declared five colours the chart did not
           use, which is why no band could be identified as humans: the key was not a key.

           `itemStyle` fixes the swatch. The second half of the same defect was the FILL: at 0.62
           opacity over the page, three tokens that are already close in tone — #d9d4cc, #b9b3a9,
           #8a8279 — land within a few percent of each other and of the page, so even a correct
           legend would have pointed at bands nobody can tell apart. The fill is now the token
           exactly, at full opacity, so the band IS the swatch; and a hairline in the page colour
           separates one band from the next, which is the editorial system's own device for
           splitting two adjacent areas without inventing a sixth colour. */
        series: order.map((key) => ({
            name: data.labels[key] || key,
            type: 'line',
            stack: 'sessions',
            smooth: false,
            symbol: 'none',
            itemStyle: { color: t.pop[key] },
            lineStyle: { width: 1, color: t.card },
            areaStyle: { color: t.pop[key], opacity: 1 },
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
            axisPointer: shadowPointer(t),
            formatter: (params) => {
                const p = params[0];
                const row = rows[rows.length - 1 - p.dataIndex];
                return tip`<strong>${p.name}</strong><br>${fmt(p.value)}` +
                    (row && row.extra ? tip`<br><span style="color:${t.muted}">${row.extra}</span>` : '');
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
            axisPointer: shadowPointer(t),
            /* The axis label may have been truncated to fit its column; the tooltip carries
               the value in full, which is where the reader goes when the row is cut. */
            formatter: (params) => {
                if (!params.length) {
                    return '';
                }
                let total = 0;
                const lines = [tip`<strong>${params[0].name}</strong>`];
                for (const p of params) {
                    total += Number(p.value) || 0;
                    lines.push(tip`${markup(p.marker)} ${p.seriesName}` +
                        tip`<span style="float:right;padding-left:18px;font-weight:600">${num(p.value)}</span>`);
                }
                lines.push(tip`<div style="border-top:1px solid ${t.border};margin-top:5px;padding-top:5px">` +
                    tip`Total<span style="float:right;padding-left:18px;font-weight:600">${num(total)}</span></div>`);
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
/**
 * Where the ring goes and how big it is, given the room the legend actually needs.
 *
 * THE DEFECT THIS FIXES. The ring was placed at a percentage of the container and the legend
 * was placed at the opposite edge, and neither knew about the other. Two things went wrong at
 * once. The legend asked for `right: 0` but the shared defaults contribute `left: 0`, and a
 * legend given both is anchored LEFT and stretched — so it rendered underneath the ring
 * rather than beside it, and `likely_human` and `likely_bot` read through the arcs. Even
 * anchored correctly, five entries of that length beside a ring whose radius is 82% of half
 * the container's SHORTER side do not fit at the widths the panel is used at.
 *
 * So the space is divided before anything is placed. The legend's width is estimated the same
 * way the horizontal bar chart's label column is — longest label, body-face advance, rounded
 * up — and capped at 44% of the container; the ring is then centred in what remains and given
 * the largest radius that fits inside it with a margin. Both are pixels, not percentages, so
 * the arithmetic is checkable and cannot drift with the container's aspect ratio.
 *
 * Under 360px of container there is no arrangement in which a ring and five labels sit side by
 * side and stay legible, so the layout stacks: the legend goes to the bottom as a scrolling
 * horizontal row and the ring takes the height that is left. That is the case every phone
 * width lands in.
 *
 * @param {string} id Element id of the chart container.
 * @param {Array<string>} labels
 * @returns {{stack:boolean, center:Array, radius:number}}
 */
function donutPlan(id, labels) {
    const node = document.getElementById(id);
    const width = (node && node.clientWidth) || 480;
    const height = (node && node.clientHeight) || 300;

    let longest = 0;
    for (const label of labels) {
        longest = Math.max(longest, String(label === null || label === undefined ? '' : label).length);
    }

    const wanted = Math.ceil(longest * 7.8) + 26;
    const legend = Math.min(wanted, Math.floor(width * 0.44));

    if (width < 360 || width - legend < 170) {
        const room = Math.max(120, height - 44);
        return { stack: true, center: ['50%', Math.round(room / 2) + 4], radius: Math.round(Math.min(room, width) / 2) - 10 };
    }

    const plot = width - legend;
    return {
        stack: false,
        center: [Math.round(plot / 2), '50%'],
        radius: Math.max(48, Math.round(Math.min(plot, height) / 2) - 12)
    };
}

export function donut(id, rows, centreLabel, centreValue) {
    const plan = donutPlan(id, rows.map((r) => r.label));

    draw(id, (t) => ({
        legend: plan.stack
            ? {
                orient: 'horizontal',
                type: 'scroll',
                left: 'center',
                right: 'auto',
                top: 'auto',
                bottom: 0,
                data: rows.map((r) => r.label)
            }
            : {
                orient: 'vertical',
                left: 'auto',
                right: 4,
                top: 'middle',
                data: rows.map((r) => r.label)
            },
        tooltip: {
            trigger: 'item',
            formatter: (p) => tip`<strong>${p.name}</strong><br>${num(p.value)} (${p.percent}%)`
        },
        grid: null,
        series: [{
            type: 'pie',
            radius: [Math.round(plan.radius * 0.62), plan.radius],
            center: plan.center,
            avoidLabelOverlap: true,
            itemStyle: { borderColor: t.card, borderWidth: 2 },
            label: {
                show: true,
                position: 'center',
                formatter: () => '{v|' + richText(centreValue) + '}\n{l|' + richText(centreLabel) + '}',
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
            axisPointer: shadowPointer(t),
            formatter: (params) => {
                const p = params[0];
                return tip`${prefix}${p.name}<br><strong>${num(p.value)}</strong> ${noun}`;
            }
        },
        xAxis: {
            type: 'category',
            data: rows.map((r) => r.label),
            axisLine: { lineStyle: { color: t.border } },
            axisTick: { show: false },
            axisLabel: { color: t.axis, fontFamily: t.mono, fontSize: 14, interval: interval }
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
 * Ink or page, whichever can actually be read on a given fill.
 *
 * THE DEFECT THIS FIXES. The treemap drew every tile label in a hardcoded white. Three of the
 * five network-type colours are pale by design — `--c-human` is #d9d4cc — so on a light theme
 * those tiles carried white text on near-white, which is not a faint label, it is no label.
 * The hex was also the one place in this file that duplicated a colour instead of reading a
 * token, which is what let it drift in the first place.
 *
 * Relative luminance by the WCAG definition, then the darker or lighter of the two text
 * colours the theme already has. It is computed per tile rather than per theme because the
 * tiles are coloured by network type and a dark theme still has pale tiles in it.
 *
 * @param {string} fill Any #rgb or #rrggbb the tokens resolve to.
 * @param {Object} t    Tokens.
 */
function readableOn(fill, t) {
    const hex = String(fill || '').trim().replace('#', '');
    const full = hex.length === 3 ? hex.split('').map((c) => c + c).join('') : hex;
    if (full.length !== 6) {
        return t.text;
    }
    const channel = (i) => {
        const v = parseInt(full.slice(i, i + 2), 16) / 255;
        return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
    };
    const luminance = 0.2126 * channel(0) + 0.7152 * channel(2) + 0.0722 * channel(4);

    /* THE THRESHOLD WAS TUNED FOR THE LIGHT PALETTE AND REPRODUCED THE DEFECT IN THE OTHER
       THEME. A fixed 0.42 answers `t.card` — the PAGE colour — for anything darker, and in the
       dark theme every network-type fill is dark, so every tile took the page colour: #111111
       on #3a3631 is 1.4:1, which is no label, which is exactly what this function was written
       to stop. Contrast is measured against BOTH candidates and the better one wins, which is
       theme-independent by construction and needs no threshold to keep in step with a retone. */
    const ratio = (a, b) => {
        const hi = Math.max(a, b) + 0.05;
        const lo = Math.min(a, b) + 0.05;
        return hi / lo;
    };
    const inkL = relativeLuminance(t.text);
    const pageL = relativeLuminance(t.card);
    if (inkL === null || pageL === null) {
        return luminance > 0.42 ? t.text : t.card;
    }
    return ratio(luminance, inkL) >= ratio(luminance, pageL) ? t.text : t.card;
}

/**
 * WCAG relative luminance for a hex colour, or null when it is not one.
 *
 * Split out of readableOn() so the two candidate text colours can be measured with the same
 * arithmetic as the fill they will be drawn on.
 */
function relativeLuminance(colour) {
    const hex = String(colour || '').trim().replace('#', '');
    const full = hex.length === 3 ? hex.split('').map((c) => c + c).join('') : hex;
    if (!/^[0-9a-fA-F]{6}$/.test(full)) {
        return null;
    }
    const channel = (i) => {
        const v = parseInt(full.slice(i, i + 2), 16) / 255;
        return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
    };
    return 0.2126 * channel(0) + 0.7152 * channel(2) + 0.0722 * channel(4);
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
                return tip`<strong>${d.name}</strong><br>` +
                    (d.org ? tip`${d.org}<br>` : '') +
                    tip`<span style="color:${t.muted}">${d.astype || 'unknown'}</span><br>` +
                    tip`${num(d.value)} sessions · ${num(d.uniqIps)} IPs<br>` +
                    tip`<span style="color:${t.muted}">${num(d.human)} human · ` +
                    tip`${num(d.evasive)} evasive</span>`;
            }
        },
        grid: null,
        series: [{
            type: 'treemap',
            roam: false,
            nodeClick: false,
            breadcrumb: { show: false },
            top: legend ? 26 : 0,
            left: 0,
            right: 0,
            bottom: 0,
            itemStyle: { borderColor: t.card, borderWidth: 1, gapWidth: 1 },
            label: {
                show: true,
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
                itemStyle: { color: colorForType(n.astype) },
                label: { color: readableOn(colorForType(n.astype), t) }
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
                const lines = [tip`<div style="color:${t.muted}">${clockOnly(params[0].axisValue)}</div>`];
                for (const p of params) {
                    lines.push(tip`${markup(p.marker)} ${p.seriesName}` +
                        tip`<span style="float:right;padding-left:18px;font-weight:600">` +
                        tip`${p.value === null || p.value === undefined ? '—' : (formatter ? formatter(p.value) : num(p.value))}` +
                        '</span>');
                }
                return lines.join('<br>');
            }
        },
        xAxis: timeAxis(t, times),
        yAxis: valueAxis(t, formatter),
        /* A SINGLE POINT HAS TO BE DRAWN AS A POINT. With `symbol: 'none'` a one-datum series
           is a zero-length line segment, which paints nothing at all — and the card above it
           was simultaneously reporting "1 data point", so the reader was told there was data
           and shown an empty axis box. A one-bucket range is an entirely ordinary outcome of a
           short time window. The marker is turned on only when there is exactly one real value
           to mark, so a full series keeps the clean unmarked line it was designed with. */
        series: series.map((s) => {
            const real = (s.data || []).filter((v) => v !== null && v !== undefined).length;
            return {
                name: s.name,
                type: 'line',
                symbol: real === 1 ? 'circle' : 'none',
                symbolSize: 6,
                connectNulls: false,
                lineStyle: { width: 1.6, color: s.color },
                itemStyle: { color: s.color },
                data: s.data
            };
        })
    }));
}

/** Stacked bars over time, for the status-code chart. */
export function stackedBars(id, times, series) {
    draw(id, (t) => ({
        legend: { data: series.map((s) => s.name) },
        grid: { top: 34 },
        tooltip: { trigger: 'axis', axisPointer: shadowPointer(t) },
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
    const mapped = hasWorld();

    draw(id, (t) => ({
        legend: false,
        grid: mapped ? null : { left: 6, right: 6, top: 10, bottom: 6, containLabel: false },
        tooltip: {
            trigger: 'item',
            formatter: (p) => tip`<strong>${p.data.name}</strong><br>` +
                tip`${num(p.data.sessions)} sessions · ${num(p.data.ips)} IPs<br>` +
                tip`<span style="color:${t.muted}">${num(p.data.human)} human · ` +
                tip`${num(p.data.evasive)} evasive</span>`
        },
        geo: mapped ? {
            map: WORLD,
            roam: false,
            silent: true,
            top: 6,
            bottom: 6,
            left: 6,
            right: 6,
            boundingCoords: [[-180, 84], [180, -58]],
            itemStyle: { areaColor: t.sunken, borderColor: t.border, borderWidth: 0.6 },
            emphasis: { disabled: true },
            select: { disabled: true }
        } : undefined,
        xAxis: mapped ? undefined : {
            type: 'value', min: -180, max: 180,
            axisLine: { show: false }, axisTick: { show: false }, axisLabel: { show: false },
            splitLine: { lineStyle: { color: t.grid, type: 'dotted' } },
            interval: 30
        },
        yAxis: mapped ? undefined : {
            type: 'value', min: -60, max: 85,
            axisLine: { show: false }, axisTick: { show: false }, axisLabel: { show: false },
            splitLine: { lineStyle: { color: t.grid, type: 'dotted' } },
            interval: 30
        },
        series: [{
            type: 'scatter',
            coordinateSystem: mapped ? 'geo' : undefined,
            symbolSize: (v, p) => p.data.size,
            itemStyle: {
                color: (p) => (p.data.evasiveRate > 0.5 ? t.pop.evasive : t.accent),
                opacity: 0.78,
                borderColor: t.card,
                borderWidth: 1
            },
            data: points
        }]
    }));
}

/** The name the world outline is registered under. */
const WORLD = 'lh-world';

/** Has the basemap been registered yet? */
function hasWorld() {
    return !!(window.echarts && window.echarts.getMap && window.echarts.getMap(WORLD));
}

/**
 * Load the world outline and register it, once.
 *
 * WHY THERE IS AN ASSET AT ALL. The map plotted country centroids as bubbles on a bare
 * longitude/latitude grid: dots and no map, and nobody reconstructs a world from a scatter.
 * A `geo` component gives the bubbles a real projection, the land a shape, and country
 * hit-testing for free.
 *
 * WHY IT IS A LOCAL FILE. The panel must work air-gapped behind a CSP that allows no outside
 * origin, and a basemap is exactly the dependency that quietly breaks that. The outline is
 * committed to the repository — Natural Earth 110m, public domain, see the note beside it —
 * simplified to the ISO code of each country and nothing else.
 *
 * WHY IT IS FETCHED RATHER THAN BUNDLED. 155 KB of coordinates on every page, for one card on
 * one view, is not a trade worth making. The caller asks for it; every other view never sees
 * it. A failed load is not an error either: the map falls back to the grid it had, which is
 * worse but honest, rather than showing an empty card.
 *
 * @param {string} base Path prefix the panel is served from.
 * @returns {Promise<boolean>} Whether a basemap is available.
 */
export async function loadWorld(base) {
    if (!window.echarts) {
        return false;
    }
    if (hasWorld()) {
        return true;
    }
    try {
        const res = await fetch((base || '') + 'assets/geo/world.json', { credentials: 'same-origin' });
        if (!res.ok) {
            return false;
        }
        window.echarts.registerMap(WORLD, await res.json());
        return true;
    } catch (err) {
        return false;
    }
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
