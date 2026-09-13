/*
 * Loghound — a chart above an aggregate table.
 *
 * The ranked tables on the analysis pages (crawlers, attackers, netblocks, countries, pages,
 * search terms, referrers, people) answer "which ones, and how much" — the question a bar chart
 * answers at a glance. This module draws that chart above the table from the same rows the
 * table was filled with, so the two can never disagree and no extra request is made.
 *
 * WHAT IT DOES NOT DO, on purpose:
 *   - It never replaces the table. The table stays the complete, exact, sortable view; the chart
 *     is the top of it.
 *   - It never draws one bar. Fewer than two rows with a value is not a comparison, so the chart
 *     is removed and the table speaks alone.
 *   - It never crowds a phone. At phone width it keeps the top 8 rows at a shorter row height;
 *     at desktop width the top 12. The full list is in the table underneath.
 *
 * The container is created beside the card's table rather than in the server markup, and
 * charts.js registers it for resizing when it is drawn, so it follows the card's width on
 * rotation, rail toggles and window resizes.
 */

'use strict';

import { barsH, barsHStacked, dispose } from './charts.js';
import { byId, el } from './core.js';

/** The width below which the panel is laid out for a phone; matches mobile.css. */
const PHONE_QUERY = '(max-width: 900px)';

/** Rows shown in the chart at phone and desktop width. */
const ROWS_PHONE = 8;
const ROWS_DESK = 12;

/** Pixels per bar row at phone and desktop width. */
const ROW_PX_PHONE = 22;
const ROW_PX_DESK = 26;

/** Pixels for the value axis, plus the legend when a chart has more than one series. */
const AXIS_PX = 40;
const LEGEND_PX = 28;

/** Is the panel currently laid out for a phone? */
function isPhone() {
    return window.matchMedia ? window.matchMedia(PHONE_QUERY).matches : window.innerWidth <= 900;
}

/** How many rows a chart shows at the current width. */
function rowLimit() {
    return isPhone() ? ROWS_PHONE : ROWS_DESK;
}

/** The chart container's id for a card. */
function chartId(cardId) {
    return cardId + '-tchart';
}

/**
 * Find or create the chart container for a card, placed directly above its table.
 *
 * Sized from the number of rows it will hold, so the value axis always fits inside the box and
 * the card never grows a nested scroll. A card without a table gets the chart at the end of its
 * content.
 *
 * @returns {string|null} The container id, or null when the card has no content area.
 */
function mount(cardId, rows, withLegend) {
    const content = byId(cardId + '-content');
    if (!content) {
        return null;
    }

    const id = chartId(cardId);
    let node = byId(id);
    if (!node) {
        node = el('div', { class: 'chart tchart', id: id, role: 'img' });
        const wrap = content.querySelector('.table-wrap');
        if (wrap && wrap.parentNode) {
            wrap.parentNode.insertBefore(node, wrap);
        } else {
            content.appendChild(node);
        }
    }

    const rowPx = isPhone() ? ROW_PX_PHONE : ROW_PX_DESK;
    node.style.height = (rows * rowPx + AXIS_PX + (withLegend ? LEGEND_PX : 0)) + 'px';
    node.hidden = false;

    return id;
}

/**
 * Remove a card's chart, when its data no longer makes a comparison.
 */
export function clearTableChart(cardId) {
    const id = chartId(cardId);
    dispose(id);
    const node = byId(id);
    if (node) {
        node.remove();
    }
}

/**
 * One value per row: the ranked bars above a top-N table.
 *
 * @param {string} cardId
 * @param {Array<{label:string,value:number,extra?:string}>} rows In rank order.
 * `signed` keeps negative values, for a change between two periods, where a fall is as much a
 * finding as a rise; only a zero is dropped.
 *
 * @param {Object} [opts] {format: value formatter, label: accessible description, signed: keep negatives}
 */
export function rankChart(cardId, rows, opts) {
    const options = opts || {};
    const usable = (rows || [])
        .filter((row) => (options.signed ? Number(row.value) !== 0 : Number(row.value) > 0))
        .slice(0, rowLimit());
    if (usable.length < 2) {
        clearTableChart(cardId);
        return;
    }

    const id = mount(cardId, usable.length, false);
    if (!id) {
        return;
    }
    if (options.label) {
        byId(id).setAttribute('aria-label', options.label);
    }

    barsH(id, usable.map((row) => ({
        label: String(row.label === null || row.label === undefined ? '' : row.label),
        value: Number(row.value) || 0,
        color: row.color,
        extra: row.extra
    })), { format: options.format });
}

/**
 * Several parts per row: the stacked bars above a table whose rows split into kinds.
 *
 * Every row must carry the same parts in the same order, because the legend and the stack are
 * built from the first row. A row whose parts sum to zero is dropped.
 *
 * @param {string} cardId
 * @param {Array<{label:string,parts:Array<{name:string,value:number,color:string}>}>} rows
 * @param {Object} [opts] {label: accessible description, keepSingle: draw even one row}
 */
export function splitChart(cardId, rows, opts) {
    const options = opts || {};
    const usable = (rows || [])
        .filter((row) => row.parts.reduce((sum, part) => sum + (Number(part.value) || 0), 0) > 0)
        .slice(0, rowLimit());
    if (usable.length < (options.keepSingle ? 1 : 2)) {
        clearTableChart(cardId);
        return;
    }

    const id = mount(cardId, usable.length, true);
    if (!id) {
        return;
    }
    if (options.label) {
        byId(id).setAttribute('aria-label', options.label);
    }

    barsHStacked(id, usable.map((row) => ({
        label: String(row.label === null || row.label === undefined ? '' : row.label),
        parts: row.parts.map((part) => ({
            name: part.name,
            value: Number(part.value) || 0,
            color: part.color
        }))
    })));
}
