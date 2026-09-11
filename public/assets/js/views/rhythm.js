/*
 * Loghound — Analytics: when they come.
 *
 * The heatmap is a CSS grid of 168 cells, not a chart. Three reasons, and none of them is
 * squeamishness about the charting library: a grid needs no layout measurement so it survives
 * being rendered inside a collapsed accordion section, it needs no second palette because it
 * shades the panel's one accent by opacity, and every cell is a real focusable element with its
 * own accessible description — which a canvas cannot offer at all.
 *
 * THE COLOUR IS THE AVERAGE, NOT THE TOTAL. A ninety-day window holds about thirteen Mondays and
 * a nine-day window holds one, so shading by the total would make whichever weekday came round
 * more often look busier. The server counts how many times each hour actually occurred and the
 * shade is the average per occurrence; the total is in the cell's description, because "eleven
 * visits across two Tuesdays" and "five and a half on a typical Tuesday" are different sentences
 * and the reader is entitled to both.
 *
 * AN HOUR THE WINDOW NEVER COVERED IS A GAP, NOT THE COLDEST SHADE. On a one-hour range that is
 * 167 of the 168 cells, and drawing them as "no traffic" would turn a range that is too short
 * into a week that looks dead.
 */

'use strict';

import { api, byId, dec, el, fill, hideEmpty, loadCard, noDataYet, num, setPop, tbody } from '../core.js';
import { magnitudeBar } from '../cardtable.js';

/** Hours of the day, as the grid's columns. */
const HOURS = 24;

/**
 * How many shades the grid has, and therefore how coarse a reading it offers.
 *
 * Five plus "nothing at all". More steps than that is a gradient nobody can read back off the
 * legend, and the grid's job is to make a pattern jump out, not to let somebody estimate a number
 * from a colour — the number is in the cell's own description and in the table beneath it.
 */
const LEVELS = 5;

/** The population currently selected by the toggle. */
let population = 'all';

/**
 * Which shade a cell gets, or null when the hour was never observed.
 *
 * @param {number|null} avg
 * @param {number} peak
 * @returns {number|null} 0..LEVELS, where 0 is observed-but-empty.
 */
function level(avg, peak) {
    if (avg === null || avg === undefined) {
        return null;
    }
    if (avg <= 0 || peak <= 0) {
        return 0;
    }
    return Math.max(1, Math.min(LEVELS, Math.ceil((avg / peak) * LEVELS)));
}

/** An hour as a two-digit clock label. */
function hourLabel(hour) {
    return String(hour).padStart(2, '0');
}

/**
 * The sentence a cell carries, which is the whole of what it means.
 */
function cellTitle(cell, tz) {
    if (cell.observed === 0) {
        return cell.day + ' at ' + hourLabel(cell.hour) + ':00 never occurred in this range. Not the same '
            + 'as no traffic.';
    }
    return cell.day + ' at ' + hourLabel(cell.hour) + ':00 ' + tz + ': '
        + dec(cell.avg, 1) + ' visits on a typical one, from ' + num(cell.total) + ' in all across '
        + num(cell.observed) + ' occurrence' + (cell.observed === 1 ? '' : 's') + '.';
}

/** The legend, which is what turns a shaded grid into something readable. */
function legend(peak, tz) {
    const swatches = [el('span', { class: 'heat-key-none', title: 'This hour never occurred in the range' })];
    for (let i = 1; i <= LEVELS; i++) {
        swatches.push(el('span', { class: 'heat-key-' + i }));
    }

    return el('div', { class: 'heat-legend' }, [
        el('span', { class: 'faint', text: 'Never observed' }),
        el('span', { class: 'heat-key' }, swatches),
        el('span', { class: 'faint', text: 'Busiest: ' + dec(peak, 1) + ' visits an hour' }),
        el('span', { class: 'faint', text: 'Times shown in ' + tz })
    ]);
}

/**
 * Draw the grid.
 */
function renderHeat(data) {
    const mount = byId('an-heat-grid');
    if (!mount) {
        return;
    }

    setPop('an-heat', data.population_label + ' · ' + num(data.total) + ' visits across '
        + num(data.hours_observed) + ' observed hours, in ' + data.timezone + '. Shaded by the average per '
        + 'occurrence, not the total.');

    if (data.hours_observed === 0) {
        fill(mount, []);
        noDataYet('an-heat-empty', 'hours of traffic');
        return;
    }
    hideEmpty('an-heat-empty');

    const byCell = new Map();
    for (const cell of data.cells) {
        byCell.set(cell.dow + ':' + cell.hour, cell);
    }

    const grid = el('div', { class: 'heat', role: 'group', 'aria-label': 'Visits by hour of the week' });

    grid.appendChild(el('span', { class: 'heat-corner', 'aria-hidden': 'true' }));
    for (let hour = 0; hour < HOURS; hour++) {
        grid.appendChild(el('span', {
            class: 'heat-hour' + (hour % 3 === 0 ? ' heat-hour-on' : ''),
            'aria-hidden': 'true',
            text: hour % 3 === 0 ? hourLabel(hour) : ''
        }));
    }

    for (let day = 0; day < data.days.length; day++) {
        grid.appendChild(el('span', { class: 'heat-day', text: data.days[day].slice(0, 3) }));
        for (let hour = 0; hour < HOURS; hour++) {
            const cell = byCell.get(day + ':' + hour) || { day: data.days[day], hour: hour, observed: 0, total: 0, avg: null };
            const shade = level(cell.avg, data.peak);
            grid.appendChild(el('span', {
                class: 'heat-cell ' + (shade === null ? 'heat-none' : 'heat-' + shade),
                tabindex: '0',
                'data-lh-tip': '1',
                'data-full': cellTitle(cell, data.timezone),
                'aria-label': cellTitle(cell, data.timezone)
            }));
        }
    }

    fill(mount, [grid, legend(data.peak, data.timezone)]);

    if (data.hours_observed < 48) {
        mount.appendChild(el('p', {
            class: 'muted',
            text: 'This range covers ' + num(data.hours_observed) + ' hours, so most of the grid is an '
                + 'absence rather than a quiet period. Try 30 or 90 days.'
        }));
    }
}

/**
 * The same grid as a ranked list, so the top of it can be quoted.
 *
 * Sorted by the average, and every row carries the occurrence count it was divided by: an hour
 * that happened once in the window has an "average" of one observation, which is not an average
 * at all, and the only way a reader can tell is if the denominator is on the row.
 */
function renderHours(data) {
    const rows = data.cells
        .filter((c) => c.observed > 0 && c.total > 0)
        .sort((a, b) => b.avg - a.avg)
        .slice(0, 20);

    setPop('an-hours', 'The twenty busiest hours for ' + data.population_label.toLowerCase() + ', by average '
        + 'per occurrence. An hour observed once has no average worth the name, which is what the observed '
        + 'column is for.');

    if (!rows.length) {
        tbody(byId('an-hours-table'), []);
        noDataYet('an-hours-empty', 'hours with any traffic');
        return;
    }
    hideEmpty('an-hours-empty');

    const peak = rows[0].avg || 1;
    tbody(byId('an-hours-table'), rows.map((cell) => ({
        cells: [
            { text: cell.day + ' ' + hourLabel(cell.hour) + ':00', nowrap: true, sort: cell.dow * 24 + cell.hour },
            { text: dec(cell.avg, 1), num: true, sort: cell.avg },
            { text: num(cell.total), num: true, sort: cell.total },
            { text: num(cell.observed), num: true, sort: cell.observed },
            {
                node: magnitudeBar(cell.avg, peak, 'the busiest hour of the week',
                    dec(cell.avg, 1) + ' visits on a typical ' + cell.day),
                sort: cell.avg
            }
        ]
    })));
}

/** Load both cards from one request. */
function load() {
    const data = api('rhythm', 'heat', { pop: population });
    loadCard('an-heat', 'Folding the range into hours of the week', async () => {
        renderHeat(await data);
    });
    loadCard('an-hours', 'Ranking the hours of the week', async () => {
        renderHours(await data);
    });
}

/** Wire the population toggle. */
function initToggle() {
    const group = document.querySelector('[data-card="an-heat"] .toggle');
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
            population = button.dataset.pop;
            load();
        });
    }
}

/** Entry point. */
export default function init() {
    initToggle();
    load();
}
