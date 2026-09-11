/*
 * Loghound — front-end core.
 *
 * Everything shared by the seven views: the boot payload, DOM construction, formatting,
 * and the fetch wrapper.
 *
 * THE RULE THAT MATTERS: every value rendered by this panel came off the wire. Paths,
 * User-Agents, referers, AS organisation names and RIR netnames are chosen by whoever
 * made the request, and a scraper that wants to attack the operator looking at the
 * dashboard will happily send a User-Agent full of markup. So:
 *
 *   - DOM is built with document.createElement and textContent. There is no innerHTML in
 *     this front end at all — not as a convention, as a fact: the one sink that existed,
 *     `el(tag, {html})`, had no callers and has been removed, so there is nothing left to
 *     reach for by accident.
 *   - Chart tooltips are the one place the panel does build markup from data, because
 *     ECharts renders a formatter's return value as HTML and there is no DOM node to set
 *     textContent on. Every dynamic value interpolated into a formatter in charts.js goes
 *     through esc() below. That is the whole reason esc() is exported: the CSP would stop
 *     an injected payload from executing, but a defence that rests entirely on one header
 *     is not a defence, and an AS organisation name is chosen by whoever holds the
 *     netblock the traffic came from.
 *   - No eval, no new Function, no inline event handlers. The CSP forbids all three and
 *     the panel is written so it never wants them.
 *   - A URL only becomes an href after the server has passed it through
 *     Security::safeUrl(); the client never decides that a scheme is safe.
 */

'use strict';

import { initCopyButtons } from './copy.js';

/* The CSV export control, imported for its side effect: one delegated listener on the document
   that keeps every export link's href in step with the controls that live only in the page. It is
   wired here rather than from app.js because the control appears on ten views and inside a dialog,
   so a per-view initialiser would be ten chances to forget one — and a forgotten one is silent,
   producing a file scoped to the defaults with nothing on screen saying so. */
import './export.js';

/**
 * Read the JSON island the server rendered.
 *
 * A <script type="application/json"> block is inert — the browser parses it as data and
 * never executes it — which is what makes it safe to hand structured values to the page
 * under a strict CSP.
 */
function readBoot() {
    const node = document.getElementById('lh-boot');
    if (!node) {
        return {};
    }
    try {
        return JSON.parse(node.textContent || '{}');
    } catch (e) {
        return {};
    }
}

export const boot = readBoot();

/**
 * Create an element.
 *
 * `attrs.text` sets textContent, which is the only way this function puts a value into the
 * document.
 *
 * THERE IS NO `attrs.html`. There was, it set innerHTML, and it had ZERO callers in the whole
 * front end — so it was not a feature anybody was using, it was the one unguarded markup sink
 * in the universal element constructor, waiting for the first author who reached for it with a
 * Solr value in hand. A sink with no callers is free to delete, and deleting it is what makes
 * the rule at the top of this file structural instead of a convention. Authored markup that
 * genuinely has to be built as a string is what `tip` is for, and `tip` escapes.
 *
 * @param {string} tag
 * @param {Object} [attrs]
 * @param {Array<Node|string>} [children]
 * @returns {HTMLElement}
 */
export function el(tag, attrs, children) {
    const node = document.createElement(tag);
    if (attrs) {
        for (const key of Object.keys(attrs)) {
            const value = attrs[key];
            if (value === null || value === undefined || value === false) {
                continue;
            }
            if (key === 'text') {
                node.textContent = String(value);
            } else if (key === 'class') {
                node.className = String(value);
            } else if (key === 'dataset') {
                for (const d of Object.keys(value)) {
                    node.dataset[d] = String(value[d]);
                }
            } else if (key === 'on') {
                for (const evt of Object.keys(value)) {
                    node.addEventListener(evt, value[evt]);
                }
            } else if (value === true) {
                node.setAttribute(key, '');
            } else {
                node.setAttribute(key, String(value));
            }
        }
    }
    if (children) {
        for (const child of children) {
            if (child === null || child === undefined || child === false) {
                continue;
            }
            node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
        }
    }
    return node;
}

/**
 * Escape a string for the rare case where authored markup has to interpolate a value.
 *
 * Prefer `el(tag, {text: value})`. This exists because the brief requires an esc()
 * helper to exist for any innerHTML path, and because refusing to provide one just means
 * somebody writes a worse one inline later.
 */
export function esc(value) {
    return String(value === null || value === undefined ? '' : value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

/**
 * A fragment that is already markup and must not be escaped again.
 *
 * The only way to get one is markup() below, so an ordinary value can never be mistaken
 * for one: `tip` escapes everything that is not an instance of this class.
 */
class Markup {
    constructor(value) {
        this.value = String(value === null || value === undefined ? '' : value);
    }
}

/**
 * Declare that a string is authored markup and may pass through `tip` unescaped.
 *
 * There are two legitimate uses and no others: the coloured swatch ECharts hands a
 * formatter as `params.marker`, and a fragment this repository wrote itself. A value that
 * came off the wire is never one of those.
 */
export function markup(value) {
    return new Markup(value);
}

/**
 * Build a markup fragment with every interpolated value escaped by default.
 *
 * ECharts renders a tooltip formatter's return value as HTML and hands it no DOM node, so
 * a formatter is the one place in this panel that has to produce markup from data. Built by
 * hand with `+`, the escaping is correct only for as long as every author remembers it —
 * and it was not: an AS organisation name, a network type and a free-form `extra` string all
 * reached a tooltip raw, sitting between two values that were escaped.
 *
 * A tagged template inverts the default. Everything interpolated is escaped unless it is
 * wrapped in markup(), so forgetting is safe and remembering is the exception that has to be
 * written down. Used as:
 *
 *     tip`<strong>${p.name}</strong><br>${num(p.value)}`
 *
 * @param {Array<string>} strings The literal parts, which are authored here.
 * @param {...*} values The interpolated parts, which are not.
 */
export function tip(strings, ...values) {
    let out = strings[0];
    for (let i = 0; i < values.length; i++) {
        const value = values[i];
        out += (value instanceof Markup ? value.value : esc(value)) + strings[i + 1];
    }
    return out;
}

/** Remove every child of a node. */
export function clear(node) {
    while (node && node.firstChild) {
        node.removeChild(node.firstChild);
    }
}

/** Replace a node's children with the supplied nodes. */
export function fill(node, children) {
    clear(node);
    for (const child of children) {
        if (child) {
            node.appendChild(child);
        }
    }
}

/** document.getElementById, shortened, because this file uses it constantly. */
export function byId(id) {
    return document.getElementById(id);
}

/**
 * Build a table body from rows.
 *
 * Each cell descriptor is `{text, mono, num, clip, nowrap, title, node, class, sort}`.
 * Everything goes through textContent unless a pre-built `node` is supplied.
 *
 * `sort` is the value the column sorts BY, when that is not the text on screen. "2.3 s",
 * "1.2 MiB" and "09/11/2026 02:44" all sort wrongly as strings and none of them can be
 * recovered from the rendered text without guessing at its format, so the raw number goes on
 * the cell as a data attribute and assets/js/sorttable.js uses it. A cell with no `sort`
 * sorts by its text, which is right for a name and for anything already in a sortable shape.
 */
export function tbody(table, rows) {
    const body = table.tBodies[0] || table.appendChild(document.createElement('tbody'));
    clear(body);
    for (const cells of rows) {
        const tr = el('tr', cells.attrs || null);
        for (const cell of (cells.cells || cells)) {
            const classes = [];
            if (cell.mono) { classes.push('mono'); }
            if (cell.num) { classes.push('num'); }
            if (cell.clip) { classes.push('clip'); }
            if (cell.nowrap) { classes.push('nowrap'); }
            if (cell.class) { classes.push(cell.class); }
            const td = el('td', {
                class: classes.join(' ') || null,
                title: cell.title || (cell.clip && cell.text ? String(cell.text) : null),
                'data-sort': cell.sort === null || cell.sort === undefined ? null : String(cell.sort)
            });
            if (cell.node) {
                td.appendChild(cell.node);
            } else {
                td.textContent = cell.text === null || cell.text === undefined ? '—' : String(cell.text);
            }
            tr.appendChild(td);
        }
        body.appendChild(tr);
    }
    return body;
}

/* -------------------------------------------------------------------------
 * Empty states
 * ---------------------------------------------------------------------- */

/**
 * Show an empty state in place of a chart or table.
 *
 * A fresh install with no data must explain what to do next. Rendering an axis with no
 * series, or a table with no rows, tells the operator nothing and looks broken.
 *
 * @param {string} id       Element id of the .empty container.
 * @param {string} heading
 * @param {Array<string|Node>} parts  Paragraph strings, or pre-built nodes.
 */
export function showEmpty(id, heading, parts) {
    const node = byId(id);
    if (!node) {
        return;
    }
    fill(node, [
        heading ? el('h3', { text: heading }) : null,
        ...(parts || []).map((p) => (typeof p === 'string' ? el('p', { text: p }) : p))
    ]);
    node.hidden = false;
    node.classList.add('show');
    const content = byId(String(id).replace(/-empty$/, '') + '-content');
    if (content) {
        content.hidden = true;
    }
}

/** Hide an empty state (data arrived after all). */
export function hideEmpty(id) {
    const node = byId(id);
    if (node) {
        node.hidden = true;
        node.classList.remove('show');
    }
    const content = byId(String(id).replace(/-empty$/, '') + '-content');
    if (content) {
        content.hidden = false;
    }
}

/**
 * How many filter values are in force on this page, and what they are called.
 *
 * Read from the boot payload, which carries the server's own reading of the query string —
 * the same object the chips are drawn from. Parsing the URL again here would be a second set
 * of reading rules that knows nothing about the per-dimension operator.
 *
 * @returns {{count: number, dimensions: string[]}}
 */
export function activeFilterSummary() {
    const state = boot.filters || {};
    const dims = Array.isArray(state.dimensions) ? state.dimensions : [];

    /* `active` is Panel\Facets::flat(), which is a MAP of field to its chosen values — not a
       flat list, whatever the name suggests. Reading it as an array answered zero for every
       filtered page, which is the one case this function exists to detect. Both shapes are
       accepted so a future change to either side cannot quietly turn the count back to zero. */
    const active = state.active;
    let count = 0;
    if (Array.isArray(active)) {
        count = active.length;
    } else if (active && typeof active === 'object') {
        for (const field of Object.keys(active)) {
            const values = active[field];
            count += Array.isArray(values) ? values.length : 1;
        }
    }

    return {
        count: count,
        dimensions: dims.map((d) => String(d.label || d.field)).filter(Boolean)
    };
}

/**
 * The URL for this page with every filter removed, in the namespace this view filters in.
 *
 * Built here rather than imported from facetfilter.js so core.js keeps no import of its own:
 * it is the root module every other one depends on, and a cycle through it is a hazard the
 * whole front end would carry for the sake of four lines.
 */
export function clearFiltersUrl() {
    const ns = String((boot.filters || {}).ns || 'f');
    const params = new URLSearchParams(window.location.search);
    for (const key of Array.from(params.keys())) {
        if (key.startsWith(ns + '[')) {
            params.delete(key);
        }
    }
    params.delete('start');
    return '?' + params.toString();
}

/**
 * The standard "there is nothing to draw" state, used by every view.
 *
 * IT NAMES THE REASON RATHER THAN LISTING THE CANDIDATES. It used to say "Either nothing has
 * been indexed yet, or nothing matched the selected range and filters", which is an admission
 * that the panel did not look — and the panel does know: the boot payload carries the filters
 * the server applied. So a page with filters in force says the filters excluded everything and
 * offers the control that undoes them, and a page with none says the range is empty and points
 * at the two things that make a fresh install empty. A reader is never left to guess which of
 * the two they are in, and neither branch is a dead end.
 *
 * @param {string} id   The `.empty` slot's element id, as emitted by Controller::cardClose().
 * @param {string} what A PLURAL NOUN naming the population — "sessions", "netblocks". Never a
 *                      sentence: it is interpolated into "No <what> in this time range".
 */
export function noDataYet(id, what) {
    const active = activeFilterSummary();

    if (active.count > 0) {
        const named = active.dimensions.slice(0, 3).join(', ');
        showEmpty(id, 'No ' + what + ' match your filters', [
            'The selected time range holds data, but nothing in it matches the ' +
                active.count + ' filter value' + (active.count === 1 ? '' : 's') +
                (named ? ' you have set on ' + named : ' you have set') + '.',
            el('p', {}, [
                'Remove a value from the filter bar above, or ',
                el('a', { href: clearFiltersUrl(), text: 'clear every filter' }),
                ' and start again.'
            ])
        ]);
        return;
    }

    showEmpty(id, 'No ' + what + ' in this time range', [
        'Nothing in the selected range produced a row. Try a wider range first — the range buttons are at the top of the page.',
        el('p', {}, [
            'If this is a fresh install: confirm a log source under ',
            el('a', { href: '?v=settings', text: 'Settings' }),
            ', then check that the reader is running. Under systemd that is ',
            el('code', { text: 'systemctl status loghound-tail.service' }),
            '; under any other supervisor, check the job you gave ',
            el('code', { text: 'bin/loghound-tail' }),
            ' to.'
        ])
    ]);
}

/**
 * The empty state for a cross-tabulation, which needs BOTH of its dimensions set on a row.
 *
 * Kept beside noDataYet() rather than expressed through it: "no session has both a bot class
 * and a network type" is a different fact from "there are no sessions", and the three pivot
 * cards used to pass that sentence as noDataYet()'s noun — producing "No No session in this
 * range has both … in this time range", into an element id that did not exist, so nothing was
 * ever rendered at all.
 *
 * @param {string} id   The `.empty` slot's element id.
 * @param {string} both What a row needs both of, e.g. "a bot class and a network type".
 */
export function noPivotYet(id, both) {
    const active = activeFilterSummary();
    showEmpty(id, 'Nothing to cross-tabulate', [
        'A row needs ' + both + ', and no session in this range carries both.',
        active.count > 0
            ? el('p', {}, [
                'Your filters may be excluding the sessions that do — ',
                el('a', { href: clearFiltersUrl(), text: 'clear every filter' }),
                ' to check.'
            ])
            : 'Both are recorded once a session has been scored, so a range with only unscored sessions in it produces no rows here.'
    ]);
}

/** Counter behind the ids snippet() mints, so two snippets on one page cannot collide. */
let snippetSeq = 0;

/**
 * A command or configuration line the operator is meant to run, WITH its copy control.
 *
 * The same `.snippet-block` + `<pre class="snippet mono">` + `[data-copy]` markup that
 * Settings::commandBlock() and Setup\View::commandBlock() emit, so a snippet built by the
 * front end is the same object as a snippet built by the server. It was not: the one snippet
 * a view module rendered — the LogFormat line on Performance — was a bare `<pre>` with no way
 * to copy it, next to a page full of snippets that all had one.
 *
 * copy.js is idempotent and removes a button whose target it cannot copy, so calling
 * initCopyButtons() again after this lands is safe and a browser with no clipboard access
 * gets no dead control.
 */
export function snippet(text) {
    snippetSeq += 1;
    const id = 'lh-snip-' + snippetSeq;
    const block = el('div', { class: 'snippet-block' }, [
        el('pre', { class: 'snippet mono', id: id, text: text }),
        el('button', { type: 'button', class: 'copy-btn', 'data-copy': id, 'aria-live': 'polite', text: 'Copy' })
    ]);
    /* Wired on the microtask after this returns, because copy.js scans the DOCUMENT for
       `[data-copy]` and the caller has not inserted the block yet. A microtask runs after the
       caller's synchronous append and before paint. */
    window.queueMicrotask(initCopyButtons);
    return block;
}

/* -------------------------------------------------------------------------
 * Formatting
 *
 * Every formatter that touches a locale passes one explicitly. Calling
 * toLocaleString() with no locale silently produces a different string on every
 * machine, which makes screenshots, bug reports and copy-paste unreliable.
 * ---------------------------------------------------------------------- */

const LOCALE = 'en-US';

/** Integer with thousands separators, or an em-dash for null/undefined. */
export function num(value) {
    if (value === null || value === undefined || Number.isNaN(value)) {
        return '—';
    }
    return Number(value).toLocaleString(LOCALE, { maximumFractionDigits: 0 });
}

/** Fixed-decimal number, or an em-dash. */
export function dec(value, places) {
    if (value === null || value === undefined || Number.isNaN(value)) {
        return '—';
    }
    return Number(value).toLocaleString(LOCALE, {
        minimumFractionDigits: places === undefined ? 1 : places,
        maximumFractionDigits: places === undefined ? 1 : places
    });
}

/** Percentage of a total, guarding against a zero denominator. */
export function pct(part, total, places) {
    if (!total) {
        return '—';
    }
    return dec((part / total) * 100, places === undefined ? 1 : places) + '%';
}

/** Bytes in binary units. */
export function bytes(value) {
    if (value === null || value === undefined || Number.isNaN(value)) {
        return '—';
    }
    let n = Number(value);
    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    let i = 0;
    while (n >= 1024 && i < units.length - 1) {
        n /= 1024;
        i += 1;
    }
    return (i === 0 ? String(Math.round(n)) : n.toFixed(1)) + ' ' + units[i];
}

/**
 * A duration in milliseconds, rendered at the resolution a human reads.
 *
 * Null stays an em-dash and never becomes "0 ms": SPEC §1 forbids inventing a metric,
 * and "no beacon arrived" must not look like "they left instantly".
 */
export function dur(ms) {
    if (ms === null || ms === undefined || Number.isNaN(ms)) {
        return '—';
    }
    const v = Number(ms);
    if (v < 1000) {
        return Math.round(v) + ' ms';
    }
    if (v < 60000) {
        return (v / 1000).toFixed(1) + ' s';
    }
    const totalSeconds = Math.round(v / 1000);
    const h = Math.floor(totalSeconds / 3600);
    const m = Math.floor((totalSeconds % 3600) / 60);
    const s = totalSeconds % 60;
    if (h > 0) {
        return h + 'h ' + String(m).padStart(2, '0') + 'm';
    }
    return m + 'm ' + String(s).padStart(2, '0') + 's';
}

/** A duration in microseconds (dur_us_l comes from %D, which is microseconds). */
export function durUs(us) {
    if (us === null || us === undefined || Number.isNaN(us)) {
        return '—';
    }
    const v = Number(us);
    if (v < 1000) {
        return Math.round(v) + ' µs';
    }
    if (v < 1000000) {
        return (v / 1000).toFixed(1) + ' ms';
    }
    return (v / 1000000).toFixed(2) + ' s';
}

/**
 * Format an ISO-8601 instant as mm/dd/yyyy hh:mm:ss in the configured display timezone.
 *
 * Built from formatToParts rather than a format string so the output is exactly this
 * shape regardless of what the browser's idea of a "short" date is. Solr stores UTC;
 * `boot.tz` decides how it is shown.
 */
export function when(iso, withSeconds) {
    if (!iso) {
        return '—';
    }
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) {
        return '—';
    }
    const opts = {
        timeZone: boot.tz || 'UTC',
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit', hour12: false
    };
    if (withSeconds !== false) {
        opts.second = '2-digit';
    }
    const parts = {};
    for (const p of new Intl.DateTimeFormat(LOCALE, opts).formatToParts(d)) {
        parts[p.type] = p.value;
    }
    const time = parts.hour + ':' + parts.minute + (withSeconds === false ? '' : ':' + parts.second);
    return parts.month + '/' + parts.day + '/' + parts.year + ' ' + time;
}

/** Just the clock part, for dense axis labels where the date is implied. */
export function clockOnly(iso) {
    if (!iso) {
        return '';
    }
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) {
        return '';
    }
    const parts = {};
    for (const p of new Intl.DateTimeFormat(LOCALE, {
        timeZone: boot.tz || 'UTC',
        month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false
    }).formatToParts(d)) {
        parts[p.type] = p.value;
    }
    return parts.month + '/' + parts.day + ' ' + parts.hour + ':' + parts.minute;
}

/**
 * The two halves of an instant, for a cell that shows the time over the date.
 *
 * A table of sessions is almost always a table of one day, so the date repeats down the
 * column and the clock is the part being read — but a full `mm/dd/yyyy hh:mm:ss` needs about
 * 160px and the column it was in has 110. Splitting it puts the part that differs on the
 * first line at full size and the part that repeats underneath in the secondary tone, and
 * neither is truncated. Same timezone rule as when(): Solr stores UTC, `boot.tz` displays it.
 */
export function timeOnly(iso) {
    return isoParts(iso, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false },
        (p) => p.hour + ':' + p.minute + ':' + p.second);
}

/** The date half of an instant, mm/dd/yyyy. */
export function dayOnly(iso) {
    return isoParts(iso, { year: 'numeric', month: '2-digit', day: '2-digit' },
        (p) => p.month + '/' + p.day + '/' + p.year);
}

/**
 * Format an instant from its parts in the display timezone.
 *
 * @param {string} iso
 * @param {Object} opts  Intl.DateTimeFormat options, without the timeZone.
 * @param {Function} join (parts) => string
 */
function isoParts(iso, opts, join) {
    if (!iso) {
        return '—';
    }
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) {
        return '—';
    }
    const parts = {};
    for (const p of new Intl.DateTimeFormat(LOCALE, Object.assign({ timeZone: boot.tz || 'UTC' }, opts))
        .formatToParts(d)) {
        parts[p.type] = p.value;
    }
    return join(parts);
}

/**
 * The words for one of the five populations, from the server's own table.
 *
 * `human`, `declared`, `ai`, `evasive` and `unknown` are keys in a facet payload and in the
 * palette's class names. They are not words: a bar tooltip reading "evasive: 12%" and a legend
 * reading "ai" are the same defect as printing a verdict slug. Query::populationLabels() is the
 * one table and it already rides in the boot payload; this is how the front end reads it.
 *
 * An unrecognised key answers as itself rather than blank — a population added on the server
 * before the labels catch up should read oddly, not disappear.
 */
export function populationLabel(key) {
    const table = boot.labels || {};
    return table[String(key)] || String(key);
}

/** Shorten a hash for display while keeping enough of it to be identifiable. */
export function shortHash(hash, keep) {
    const h = String(hash || '');
    const n = keep || 12;
    return h.length > n ? h.slice(0, n) : h;
}

/* -------------------------------------------------------------------------
 * API
 * ---------------------------------------------------------------------- */

/**
 * How long the browser will wait for one panel request before giving up.
 *
 * Longer than the server's own Solr timeout (20s by default) so a slow query reports
 * ITS diagnosis rather than being cut off here, but far short of forever: a request
 * that hangs until the tab is closed is the failure mode this whole rework exists to
 * remove. On expiry the card says what timed out and offers a retry.
 */
const REQUEST_TIMEOUT_MS = 50000;

/**
 * Fetch a data action for a view.
 *
 * The URL is built from the current query string so the active range and filters travel
 * with every request without each view having to remember them. `same-origin`
 * credentials carry HTTP Basic auth.
 *
 * @param {string} view    View slug.
 * @param {string} action  Action name (matched against the view's own allowlist).
 * @param {Object} [extra] Additional query parameters.
 * @param {AbortSignal} [signal] Caller's cancellation signal, combined with the timeout.
 */
export async function api(view, action, extra, signal) {
    const params = new URLSearchParams(window.location.search);
    params.set('v', view);
    params.set('api', action);
    if (extra) {
        for (const key of Object.keys(extra)) {
            if (extra[key] !== null && extra[key] !== undefined) {
                params.set(key, String(extra[key]));
            }
        }
    }

    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    if (signal) {
        signal.addEventListener('abort', () => controller.abort(), { once: true });
    }

    let res;
    try {
        res = await fetch('?' + params.toString(), {
            credentials: 'same-origin',
            headers: { Accept: 'application/json' },
            signal: controller.signal
        });
    } catch (err) {
        window.clearTimeout(timer);
        if (err && err.name === 'AbortError') {
            const e = new Error(
                'The request took longer than ' + Math.round(REQUEST_TIMEOUT_MS / 1000) +
                ' seconds and was given up on. Try a shorter time range, or check that Solr is responding.'
            );
            e.transport = true;
            throw e;
        }
        const e = new Error('Could not reach the panel: ' + (err && err.message ? err.message : err));
        e.transport = true;
        throw e;
    }
    window.clearTimeout(timer);

    let data = null;
    try {
        data = await res.json();
    } catch (e) {
        const err = new Error('The panel returned a response that was not JSON (HTTP ' + res.status + ').');
        err.transport = true;
        throw err;
    }
    if (goneToSetup(data)) {
        return data;
    }
    if (!res.ok || (data && data.error)) {
        const err = new Error((data && data.error) || 'Request failed with HTTP ' + res.status + '.');
        err.transport = /solr|timed out|timeout|refused|resolve|unreachable|credentials/i.test(err.message);
        throw err;
    }
    if (data && data.cache) {
        lastStamp = data.cache;
    }
    return data;
}

/**
 * Has this installation been removed underneath the page, and if so, go to the installer.
 *
 * THE CASE THIS EXISTS FOR. `install/uninstall.sh` is run on the server, or the panel's own
 * removal finishes, while a browser is sitting on a view whose cards poll. Every one of those
 * requests is now answered by public/index.php with `{"setup": "./"}` — the panel's own
 * language for "there is no panel any more" — and without this they would each be rendered as
 * a card error with a retry button, aimed at an installation that no longer exists.
 *
 * NAVIGATION IS ONE-WAY AND HAPPENS ONCE. Twelve cards can be in flight at the same moment, so
 * the flag stops eleven redundant assigns; and the target is never the server's string, only
 * the fixed relative root, so nothing in a response can steer the browser anywhere.
 *
 * The caller is handed the payload back rather than an exception, because the page is leaving
 * and a thrown error would paint a failure on a card for the moment before it does.
 *
 * @param {Object} data
 * @returns {boolean}
 */
let leaving = false;
function goneToSetup(data) {
    if (!data || typeof data.setup !== 'string' || data.setup === '') {
        return false;
    }
    if (!leaving) {
        leaving = true;
        window.location.assign('./');
    }
    return true;
}

/**
 * The provenance of the most recent answer: was it computed now, or read from the cache.
 *
 * Module-level rather than passed around, because the card that renders it is not the code that
 * asked for the data — loadCard() wraps a loader it knows nothing about, and threading the stamp
 * through every view module would be eleven places to forget it. `public/index.php` attaches it
 * to every JSON response after the view has answered, so it is always the latest read's.
 */
let lastStamp = null;

/**
 * Say when a card's numbers were computed, on the card.
 *
 * WHY THIS IS NOT OPTIONAL WITH A CACHE IN FRONT OF SOLR. The default entry lives two hours, so
 * "the dashboard says 41 evasive sessions" can mean forty-one right now or forty-one at half past
 * one, and nothing on screen distinguishes them. A dashboard that presents a two-hour-old figure
 * as a live one is the same defect as a number that does not say what it counts, which this
 * product already refuses everywhere else.
 *
 * THREE STATES, and the third one is silence. A cached answer names the instant it was computed
 * and how long ago that was — the age is what makes ten minutes readable next to an hour and
 * fifty, which a bare timestamp does not. A live answer says so in one word. And on an install
 * with the cache switched off there is nothing to disclose, so nothing is drawn: a permanent
 * "Live" on every card is furniture that means nothing.
 *
 * The instant is rendered with when(), so it is mm/dd/yyyy hh:mm:ss in the panel's display
 * timezone like every other date in this product, and never a bare toLocaleString().
 */
function renderStamp(id) {
    const card = document.querySelector('[data-card="' + id + '"]');
    const head = card ? card.querySelector('.card-head') : null;
    if (!head) {
        return;
    }

    const existing = head.querySelector('.card-stamp');
    if (!lastStamp || !lastStamp.enabled) {
        if (existing) {
            existing.remove();
        }
        return;
    }

    const node = existing || head.appendChild(el('span', { class: 'card-stamp' }));
    if (!lastStamp.cached) {
        node.textContent = 'Live';
        node.title = 'Computed for this request. Nothing was served from the query cache.';
        return;
    }

    node.textContent = 'Computed ' + when(lastStamp.computed_at, true)
        + ' \u00b7 ' + stampAge(Number(lastStamp.age) || 0) + ' old';
    node.title = 'Read from the query cache. Press Clear cache in the page header to recompute it.';
}

/**
 * An age in seconds, in the largest unit that still reads as a measurement.
 *
 * Its own formatter rather than dur(), which is built for a session duration and would render two
 * hours of cache age as "2h 00m" beside a timestamp — accurate and unreadable at a glance. The
 * question here is only "is this minutes or hours old", so that is what it answers.
 */
function stampAge(seconds) {
    if (seconds < 60) {
        return seconds + 's';
    }
    if (seconds < 3600) {
        return Math.round(seconds / 60) + ' min';
    }
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.round((seconds % 3600) / 60);

    return minutes === 0 ? hours + 'h' : hours + 'h ' + minutes + ' min';
}

/**
 * POST a state-changing action, with the CSRF token attached.
 *
 * Used by the job controls. The panel's other writes are ordinary form posts that work
 * without JavaScript; jobs cannot be, because they are a poll loop by definition.
 *
 * @param {Object} fields Form fields. `action` is required.
 */
export async function post(fields) {
    const body = new URLSearchParams();
    body.set('csrf', boot.csrf || '');
    for (const key of Object.keys(fields)) {
        body.set(key, String(fields[key]));
    }

    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    let res;
    try {
        res = await fetch('?v=' + encodeURIComponent(boot.view || 'settings'), {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                Accept: 'application/json'
            },
            body: body.toString(),
            signal: controller.signal
        });
    } catch (err) {
        window.clearTimeout(timer);
        throw new Error(err && err.name === 'AbortError'
            ? 'The operation did not respond in time.'
            : 'Could not reach the panel: ' + (err && err.message ? err.message : err));
    }
    window.clearTimeout(timer);

    const data = await res.json().catch(() => null);
    if (!data) {
        throw new Error('The panel returned a response that was not JSON (HTTP ' + res.status + ').');
    }
    if (goneToSetup(data)) {
        return data;
    }
    if (data.error) {
        const err = new Error(data.error);
        err.transport = /solr|timed out|timeout|refused|resolve|unreachable|credentials/i.test(String(data.error));
        throw err;
    }

    /* THE STATUS IS CHECKED, which api() always did and this never did. Without it a 500 whose
       body happened to be `{}` came back as a successful result — and the job loop below treats
       a result with no `done` as "still running", so it polled every 700ms forever, rendering
       "step NaN of undefined · undefineds" and never stopping. A response that is not OK is a
       failure whatever shape its body took. */
    if (!res.ok) {
        const err = new Error('The operation failed with HTTP ' + res.status + '.');
        err.transport = res.status >= 500;
        throw err;
    }
    return data;
}

/* -------------------------------------------------------------------------
 * Async cards
 *
 * Every card on every view goes through loadCard(). That is what makes the page
 * non-blocking, makes each card independent, gives every one of them a worded
 * progress line with elapsed seconds, and gives every one of them its own retry.
 * ---------------------------------------------------------------------- */

/** Cards currently in flight, so a re-entrant load cannot run twice. */
const inFlight = new Set();

/** Seconds after which a card starts showing how long it has been going. */
const SHOW_ELAPSED_AFTER = 5;

/**
 * Reveal the page-level connection banner, with the diagnosis that raised it.
 *
 * THE HEADING IS WRITTEN FROM THE MESSAGE, not fixed in the markup. It said "Solr is not
 * answering." for every transport failure — and the regex that decides a failure IS one matches
 * the substring `solr`, which "The Opensolr API could not be reached." contains. So an outage
 * of the Opensolr CONTROL PLANE, which has nothing to do with the local search index, raised a
 * page-wide banner blaming the local search index and pointed the operator at the wrong check.
 * Two different failures with two different next steps.
 *
 * It also refused to update itself once shown, so a first diagnosis that happened to be the
 * less useful of two stayed on screen while the accurate one was discarded. A later message
 * replaces an earlier one of the SAME kind and upgrades a generic heading to a specific one.
 */
function raiseConnectionBanner(message) {
    const banner = byId('lh-conn');
    const detail = byId('lh-conn-detail');
    if (!banner || !detail) {
        return;
    }

    const platform = /opensolr/i.test(String(message));
    const heading = banner.querySelector('strong');
    const was = banner.dataset.kind || '';
    const kind = platform ? 'platform' : 'index';

    if (!banner.hidden && was === kind) {
        return;
    }
    banner.dataset.kind = kind;

    if (heading) {
        heading.textContent = platform
            ? 'The Opensolr API is not answering.'
            : 'Your search index is not answering.';
    }
    detail.textContent = message;
    banner.hidden = false;
}

/* -------------------------------------------------------------------------
 * Reloading one section
 *
 * A discreet control in every async card's head that re-runs THAT card and
 * nothing else. It is deliberately not a second loading path: it re-enters
 * loadCard() with the same three arguments the view last passed, so the card's
 * own skeleton, worded progress line, failure box and retry all behave exactly
 * as they do on the first load — including the query cache.
 * ---------------------------------------------------------------------- */

/**
 * What each async card was last asked to load, keyed on the card's stable name.
 *
 * WHY THE LAST ONE AND NOT THE FIRST. A card is re-loaded whenever a filter, a range or an
 * index choice changes, and each of those passes a loader closed over the choice that is on
 * screen now. Keeping the most recent entry is what makes the refresh control reload what the
 * reader is actually looking at rather than replaying the page's opening state.
 */
const cardLoaders = new Map();

/**
 * What the control says it is, and — the part that matters — what it is not.
 *
 * TWO CONTROLS ON ONE PAGE THAT BOTH SOUND LIKE "GET ME NEW NUMBERS". Clear cache in the page
 * header discards the stored answers; this re-runs one card's fetch down the ordinary path,
 * cache included, and will happily hand back the same cached figure it had a second ago. An
 * operator who presses this expecting the other one has been misled by the product, so the
 * difference is stated on the control rather than left to be discovered.
 */
const REFRESH_TIP = 'Reloads this section only, exactly the way it loaded the first time — '
    + 'a cached answer is reused. Clear cache in the page header is what discards stored answers.';

/** Where the SVG the reload mark is drawn in lives. */
const SVG_NS = 'http://www.w3.org/2000/svg';

/**
 * The reload mark, drawn here rather than fetched or pasted in as markup.
 *
 * The panel ships with a CSP that allows no outside origin and no markup sink, so an icon is
 * built with createElementNS from two paths on the same 16x16 half-pixel grid icons.js uses:
 * an arc three-quarters of the way round and the tick that turns its end into an arrowhead.
 * `currentColor` at one stroke weight, so it follows the control's own tone in both themes and
 * needs no second palette. `aria-hidden`, because the control's name is on the button.
 */
function refreshMark() {
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', '0 0 16 16');
    svg.setAttribute('width', '16');
    svg.setAttribute('height', '16');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '1.5');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');

    for (const d of ['M13.5 8A5.5 5.5 0 1 1 11.9 4.1', 'M11.9 1.1V4.1H8.9']) {
        const path = document.createElementNS(SVG_NS, 'path');
        path.setAttribute('d', d);
        svg.appendChild(path);
    }
    return svg;
}

/**
 * This section's own name, for the control's accessible name.
 *
 * "Refresh" on eleven controls down one page is eleven identical names in a screen reader's
 * control list, which is the same as having none. The heading's words are read off the card —
 * without the section number, which is chrome — and the loader's label is the fallback for a
 * card whose heading is not in the shape cardOpen() emits.
 *
 * It works before and after the accordion has run: responsive.js moves the h2's children into
 * a `button.card-toggle` INSIDE the h2, so the words stay a descendant of the heading either
 * way and a descendant selector finds them in both shapes.
 */
function cardHeadingText(card, fallback) {
    const words = card.querySelector('.card-head h2 span:not(.card-num)');
    const text = words ? (words.textContent || '').trim() : '';
    return text === '' ? fallback : text;
}

/**
 * Give one card its refresh control, once.
 *
 * WHERE IT GOES, and why it is not where it looks like it should go. The accordion turns the
 * whole heading into `button.card-toggle` by moving every child of the h2 inside it, so a
 * control placed in the heading would end up nested in that button: invalid HTML, and a nested
 * button does not reliably get the press. It is therefore a SIBLING of the h2 in `.card-head`,
 * inserted directly after it — the same row as the chevron and the same row as `.card-stamp`
 * and the CSV export, but outside the element that folds the section. Pressing it cannot reach
 * the toggle's listener, so it cannot collapse anything.
 *
 * WHICH CARDS GET ONE is not decided here and there is no list of them anywhere: this is called
 * from loadCard(), so the set is exactly the cards whose data arrives through loadCard(), and a
 * card added by a later release is covered without anybody remembering. A card rendered entirely
 * server-side never calls it and therefore never grows a control that would have nothing to run.
 */
function ensureRefresh(id, label) {
    const card = document.querySelector('[data-card="' + id + '"]');
    const head = card ? card.querySelector('.card-head') : null;
    if (!head || head.querySelector('.card-refresh')) {
        return;
    }

    const button = el('button', {
        type: 'button',
        class: 'card-refresh',
        'data-refresh': id,
        'data-lh-tip': '1',
        'data-full': REFRESH_TIP,
        'aria-disabled': 'false',
        'aria-label': 'Refresh ' + cardHeadingText(card, label)
    }, [refreshMark()]);

    const heading = head.querySelector('h2');
    if (heading && heading.nextSibling) {
        head.insertBefore(button, heading.nextSibling);
    } else {
        head.appendChild(button);
    }
}

/**
 * Say on the control whether its card is loading.
 *
 * `aria-disabled` rather than `disabled`: a disabled button is dropped from the tab order the
 * instant it is pressed, so a keyboard operator who refreshed a section would lose their place
 * on the page. The press is not merely styled as ignored — loadCard() returns early for a card
 * that is already in flight — so the attribute states a fact the guard already enforces.
 */
function markRefreshBusy(id, busy) {
    const card = document.querySelector('[data-card="' + id + '"]');
    const button = card ? card.querySelector('.card-refresh') : null;
    if (button) {
        button.setAttribute('aria-disabled', busy ? 'true' : 'false');
    }
}

/** Whether the one delegated press handler has been installed. */
let refreshWired = false;

/**
 * Listen for a press on any refresh control, once, for the life of the page.
 *
 * Delegated because the controls are created as their cards load and because the CSP allows no
 * inline handler and no `onclick`. `stopPropagation` is not decoration: the document also
 * carries the section nav's and the accordion's own click listeners, and this press is about
 * one card and must not be read as navigation or as a fold.
 */
function wireRefresh() {
    if (refreshWired) {
        return;
    }
    refreshWired = true;

    document.addEventListener('click', (event) => {
        const button = event.target && typeof event.target.closest === 'function'
            ? event.target.closest('.card-refresh')
            : null;
        if (!button) {
            return;
        }
        event.preventDefault();
        event.stopPropagation();

        const entry = cardLoaders.get(button.getAttribute('data-refresh') || '');
        if (entry) {
            loadCard(entry.id, entry.label, entry.loader);
        }
    });
}

/**
 * Run a card's loader, showing progress and handling its failure locally.
 *
 * @param {string} id     Card base id, matching Controller::cardOpen().
 * @param {string} label  What is happening, in words. Never a bare spinner.
 * @param {Function} loader async () => void — renders into the card's content element.
 */
export async function loadCard(id, label, loader) {
    cardLoaders.set(id, { id: id, label: label, loader: loader });
    ensureRefresh(id, label);
    wireRefresh();

    if (inFlight.has(id)) {
        return;
    }
    inFlight.add(id);
    markRefreshBusy(id, true);

    const card = document.querySelector('[data-card="' + id + '"]');
    const status = byId(id + '-status');
    const skel = byId(id + '-skel');
    const content = byId(id + '-content');
    const labelNode = status ? status.querySelector('.loading-label') : null;
    const elapsedNode = status ? status.querySelector('.loading-elapsed') : null;

    const oldError = card ? card.querySelector('.card-error') : null;
    if (oldError) {
        oldError.remove();
    }
    if (status) {
        status.hidden = false;
    }
    if (skel) {
        skel.hidden = false;
    }
    if (labelNode) {
        labelNode.textContent = label + '\u2026';
    }
    if (elapsedNode) {
        elapsedNode.textContent = '';
    }

    const started = Date.now();
    const ticker = window.setInterval(() => {
        const seconds = Math.floor((Date.now() - started) / 1000);
        if (elapsedNode && seconds >= SHOW_ELAPSED_AFTER) {
            elapsedNode.textContent = seconds + 's';
            elapsedNode.classList.toggle('loading-slow', seconds >= 20);
        }
        if (labelNode && seconds === 20) {
            labelNode.textContent = label + ' \u2014 still working';
        }
    }, 1000);

    try {
        await loader();
        if (status) {
            status.hidden = true;
        }
        if (skel) {
            skel.remove();
        }
        if (content) {
            content.hidden = false;
        }
        renderStamp(id);
    } catch (err) {
        if (status) {
            status.hidden = true;
        }
        if (skel) {
            skel.remove();
        }

        /* THE BANNER IS RAISED FIRST, and the error box is drawn inside its own try. A throw
           while drawing the failure used to take the page-wide diagnosis down with it, which
           is precisely the moment an operator needs one. Ordering this way means the worst a
           broken renderer can do is cost one card its box, never the whole page its warning. */
        if (err && err.transport) {
            raiseConnectionBanner(String(err.message || ''));
        }
        try {
            renderCardError(id, label, err, () => loadCard(id, label, loader));
        } catch (e) {
            window.console.error('loghound: could not render the failure of card ' + id, e, err);
        }
    } finally {
        window.clearInterval(ticker);
        inFlight.delete(id);
        markRefreshBusy(id, false);
    }
}

/**
 * Render a failure inside one card, with a retry that re-runs only that card.
 *
 * The rest of the page is untouched: a broken facet must not take the view with it.
 */
function renderCardError(id, label, err, retry) {
    const card = document.querySelector('[data-card="' + id + '"]');
    if (!card) {
        return;
    }
    const button = el('button', { type: 'button', class: 'small', text: 'Retry' });
    button.addEventListener('click', () => {
        button.disabled = true;
        retry();
    });

    const box = el('div', { class: 'card-error', role: 'alert' }, [
        el('h4', { text: 'This section could not load' }),
        el('p', { text: String(err && err.message ? err.message : err) }),
        el('p', { class: 'faint', text: 'Everything else on this page is unaffected.' }),
        el('div', { class: 'card-error-actions' }, [button])
    ]);

    /* INSERT INTO WHATEVER NOW HOLDS THE CONTENT, not into the card.
       MEASURED DEFECT, and the worst one in the panel. responsive.js turns every card into an
       accordion by MOVING everything after the head into a new `.card-region` wrapper. After
       that the content element is a grandchild of the card, and `card.insertBefore(box,
       content)` throws NotFoundError — from inside loadCard()'s own catch block. The card was
       then left with its skeleton removed, its progress line hidden and nothing put in their
       place: a blank box, no message, no retry, and no connection banner either, because the
       throw jumped over the line that raises it. Every card on every view except whichever one
       happened to fail before the accordion ran. */
    const content = byId(id + '-content');
    const host = content && content.parentNode ? content.parentNode : (card.querySelector('.card-region') || card);
    if (content && content.parentNode === host) {
        host.insertBefore(box, content);
    } else {
        host.appendChild(box);
    }

    /* A COLLAPSED CARD MUST NOT SWALLOW ITS OWN FAILURE. The accordion decides what is open
       when the page loads, and it consults the card for trouble at that moment — but every
       card loads its data AFTER that, so a card the operator had collapsed (or any card but
       the first, on arrival) could fail into a region with `display: none` and show nothing at
       all: no error, no retry, no hint on the collapsed heading that anything had happened.
       responsive.js listens for this and opens the card. It is a notification and not a
       direct call because core.js must keep working on a page where the accordion never ran. */
    document.dispatchEvent(new CustomEvent('lh:card-trouble', { detail: { id: id } }));
}

/**
 * Create (or reuse) the chart element inside a card's content area.
 *
 * The chart div has to exist and be laid out before ECharts can measure it, so it is
 * created here after the skeleton is gone rather than sitting hidden behind one.
 */
export function cardChart(id, height) {
    const content = byId(id + '-content');
    if (!content) {
        return null;
    }
    let node = byId(id);
    if (!node) {
        node = el('div', { class: 'chart', id: id, style: 'height:' + (height || 300) + 'px' });
        content.appendChild(node);
    }
    return node;
}

/**
 * Update a card's population caption once the real denominators are known.
 *
 * The caption is rendered server-side so it is never missing; this refines it.
 */
export function setPop(id, text) {
    const node = byId(id + '-pop');
    if (node) {
        node.textContent = text;
    }
}

/* -------------------------------------------------------------------------
 * Jobs
 *
 * A long operation is a sequence of server-side steps. The browser starts it, then
 * polls; each poll executes exactly one bounded step, so no request can time out
 * however long the whole operation takes. Refreshing reattaches to the running job
 * rather than starting a second one.
 * ---------------------------------------------------------------------- */

/** Poll interval. Fast enough to feel live, slow enough not to hammer the box. */
const JOB_POLL_MS = 700;

/** Job kinds currently being polled, so two clicks cannot start two loops. */
const polling = new Set();

/**
 * Start (or reattach to) a job and drive it to completion, rendering as it goes.
 *
 * `opts.params` are the job's target parameters — the index and time range a scan runs
 * against. They travel with `job_start` only: the server stores them as the job's initial
 * context and hands them back to the planner on every poll, so a poll needs nothing but an
 * id. They also decide the job's target, which is what makes starting a scan of a second
 * index a second job rather than a handback of the first one's progress.
 *
 * `opts.onStep` is called with every polled state, including the first and the last, so a
 * caller can render partial results as the operation accumulates them rather than waiting
 * for it to finish. The job's context is on `job.result`.
 *
 * A POLL THAT COMES BACK CARRYING `setup` IS THE INSTALLATION GOING AWAY MID-OPERATION, which
 * for the teardown job is the intended ending. post() has already started the navigation to the
 * installer; the loop returns rather than throwing, which is what keeps a card from painting
 * "that was not a usable job state" over the page for the moment before it leaves.
 *
 * @param {string} kind    Job kind the hosting view registered.
 * @param {string} mountId Element id to render the job panel into.
 * @param {Object} [opts]  {title, params, onStep, onDone}
 */
export async function runJob(kind, mountId, opts) {
    const options = opts || {};
    const mount = byId(mountId);
    if (!mount || polling.has(kind)) {
        return;
    }
    polling.add(kind);

    const step = (job) => {
        renderJob(mount, job, kind, options);
        if (typeof options.onStep === 'function') {
            options.onStep(job);
        }
    };

    try {
        let job = await post(Object.assign({ action: 'job_start', kind: kind }, options.params || {}));
        if (job && typeof job.setup === 'string') {
            return;
        }
        requireJob(job);
        step(job);

        while (!job.done) {
            await new Promise((resolve) => window.setTimeout(resolve, JOB_POLL_MS));
            job = await post({ action: 'job_poll', id: job.id });
            if (job && typeof job.setup === 'string') {
                return;
            }
            requireJob(job);
            step(job);
        }
        if (job && typeof options.onDone === 'function') {
            options.onDone(job);
        }
    } catch (err) {
        /* A FAILED OPERATION OFFERS TO RUN AGAIN. It offered nothing: the mount was replaced
           with a message and the control that had started the job was gone with it, so the only
           way to retry a scan that lost its connection halfway was to reload the page. `polling`
           is released in the finally below before the button can be pressed, so the retry is a
           genuine restart and not a second loop over the first. */
        const again = el('button', { type: 'button', class: 'small', text: 'Try again' });
        again.addEventListener('click', () => {
            again.disabled = true;
            runJob(kind, mountId, options);
        });
        mount.replaceChildren(el('div', { class: 'card-error', role: 'alert' }, [
            el('h4', { text: 'The operation could not run' }),
            el('p', { text: String(err && err.message ? err.message : err) }),
            el('div', { class: 'card-error-actions' }, [again])
        ]));
    } finally {
        polling.delete(kind);
    }
}

/**
 * Reattach to a job that is already running, e.g. after a page refresh.
 *
 * Returns true when one was found and is now being polled.
 */
export async function reattachJob(kind, mountId, opts) {
    const mount = byId(mountId);
    if (!mount) {
        return false;
    }
    let job = null;
    try {
        job = await api(boot.view || 'settings', 'job_latest', { kind: kind });
    } catch (e) {
        return false;
    }
    if (!job || !job.job) {
        return false;
    }
    const options = opts || {};
    renderJob(mount, job.job, kind, options);
    if (typeof options.onStep === 'function') {
        options.onStep(job.job);
    }
    if (!job.job.done) {
        runJob(kind, mountId, options);
    }
    return true;
}

/**
 * Refuse a poll response that is not a job, rather than looping on it.
 *
 * `while (!job.done)` treats anything without a `done` as still running, so a malformed or
 * empty payload was an unbreakable 700ms loop that rendered "step NaN of undefined". A payload
 * that cannot be a job is an error the operator can see and act on.
 */
function requireJob(job) {
    if (!job || typeof job !== 'object' || typeof job.id !== 'string' || job.id === '') {
        throw new Error('The panel did not answer with a usable job state, so the operation cannot be followed. Reload the page and start it again.');
    }
}

/**
 * Draw a job's progress bar, step list and controls.
 *
 * A step's `report` is the copyable failure artefact — see src/Diagnostics.php — and is
 * rendered through snippet(), the same pre plus copy button every command on the page uses,
 * rather than as another sentence. It scrolls inside itself, so a long path or a long platform
 * message cannot widen the page it is on.
 */
function renderJob(mount, job, kind, options) {
    if (!job) {
        return;
    }
    const running = !job.done;

    const bar = el('span', { class: 'progress' }, [
        el('span', { class: 'progress-fill', style: 'width:' + (job.percent || 0) + '%' })
    ]);

    const head = el('div', { class: 'job-head' }, [
        el('span', { class: 'job-title', text: options.title || 'Operation' }),
        el('span', {
            class: 'job-meta',
            text: (running ? 'step ' + Math.min(job.step + 1, job.total) + ' of ' + job.total : job.state) +
                ' \u00b7 ' + job.elapsed + 's'
        })
    ]);

    const steps = el('ul', { class: 'job-steps' });
    for (const step of (job.steps || [])) {
        const state = step.state || 'pending';
        const mark = { done: '\u2713', failed: '\u2717', running: '\u2192', pending: '\u00b7' }[state] || '\u00b7';
        const li = el('li', { class: 'job-step-' + state }, [
            el('span', { class: 'job-mark', 'aria-hidden': 'true', text: mark }),
            el('span', { text: step.label }),
            el('span', { class: 'job-step-note', text: step.note || (state === 'pending' ? '' : state) })
        ]);
        if (step.detail) {
            li.appendChild(el('span', { class: 'job-step-detail', text: step.detail }));
        }
        if (step.report) {
            li.appendChild(snippet(String(step.report)));
        }
        steps.appendChild(li);
    }

    const actions = el('div', { class: 'job-actions' });
    if (running) {
        const cancel = el('button', { type: 'button', class: 'ghost small', text: 'Cancel' });
        cancel.addEventListener('click', async () => {
            cancel.disabled = true;
            cancel.textContent = 'Cancelling\u2026';
            try {
                await post({ action: 'job_cancel', id: job.id });
            } catch (e) {
                /* A CANCEL THAT FAILS CAN BE TRIED AGAIN. The button used to become the words
                   "Cancel failed" and stay disabled forever — a dead control reporting a dead
                   end, on the one operation the operator was trying to stop. */
                cancel.disabled = false;
                cancel.textContent = 'Cancel failed — try again';
                cancel.title = String(e && e.message ? e.message : e);
            }
        });
        actions.appendChild(cancel);
    }

    /* A JOB THAT ENDED BADLY SAYS SO, AND OFFERS THE WAY FORWARD. `job.state` carried the word
       into a meta line beside the elapsed time and nothing else did anything with it, so a scan
       that failed on the server looked exactly like one that had finished. */
    if (!running && String(job.state) === 'failed') {
        const again = el('button', { type: 'button', class: 'small', text: 'Run it again' });
        again.addEventListener('click', () => {
            again.disabled = true;
            runJob(kind, mount.id, options);
        });
        actions.appendChild(again);
    }

    mount.replaceChildren(el('div', { class: 'job' }, [
        head,
        bar,
        el('div', { class: 'loading' }, [
            el('span', { class: 'loading-label', text: job.label || '' }),
            el('span', { class: 'loading-elapsed', text: running ? job.elapsed + 's' : '' })
        ]),
        steps,
        actions
    ]));
}

/* -------------------------------------------------------------------------
 * URLs
 * ---------------------------------------------------------------------- */

/**
 * Build a panel URL from the current one, with parameters replaced.
 *
 * A value of null removes the parameter. Used for the facet links in the session
 * explorer, which have to add and remove `f[field][]` entries.
 */
export function url(changes) {
    const params = new URLSearchParams(window.location.search);
    for (const key of Object.keys(changes)) {
        if (changes[key] === null) {
            params.delete(key);
        } else {
            params.set(key, String(changes[key]));
        }
    }
    return '?' + params.toString();
}

/** Add a facet filter to the current URL. */
export function urlAddFilter(field, value) {
    const params = new URLSearchParams(window.location.search);
    params.append('f[' + field + '][]', value);
    params.delete('start');
    return '?' + params.toString();
}

/** Remove one value of one facet filter from the current URL. */
export function urlRemoveFilter(field, value) {
    const params = new URLSearchParams(window.location.search);
    const key = 'f[' + field + '][]';
    const kept = params.getAll(key).filter((v) => v !== value);
    params.delete(key);
    for (const v of kept) {
        params.append(key, v);
    }
    params.delete('start');
    return '?' + params.toString();
}

/* -------------------------------------------------------------------------
 * Theme
 * ---------------------------------------------------------------------- */

/** The three theme states, in the order the toggle cycles through them. */
const THEME_ORDER = ['auto', 'light', 'dark'];

/** Read the current mode from <html>. */
export function themeMode() {
    return document.documentElement.getAttribute('data-theme') || 'auto';
}

/** Is the panel currently painting dark? Charts need to know; CSS does not. */
export function isDark() {
    const mode = themeMode();
    if (mode === 'dark') {
        return true;
    }
    if (mode === 'light') {
        return false;
    }
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
}

/**
 * Wire the theme toggle and broadcast changes.
 *
 * The button cycles auto → light → dark. The choice is persisted in localStorage, which
 * is exactly what localStorage is for: a per-viewer convenience that does not matter if
 * it is lost.
 */
export function initTheme() {
    const button = byId('theme-toggle');
    const label = () => {
        if (button) {
            button.textContent = 'Theme: ' + themeMode();
        }
    };
    label();

    if (button) {
        button.addEventListener('click', () => {
            const next = THEME_ORDER[(THEME_ORDER.indexOf(themeMode()) + 1) % THEME_ORDER.length];
            document.documentElement.setAttribute('data-theme', next);
            try {
                if (next === 'auto') {
                    window.localStorage.removeItem('lh-theme');
                } else {
                    window.localStorage.setItem('lh-theme', next);
                }
            } catch (e) {
                /* Storage unavailable; the choice simply does not survive a reload. */
            }
            label();
            document.dispatchEvent(new CustomEvent('lh:theme'));
        });
    }

    if (window.matchMedia) {
        const mq = window.matchMedia('(prefers-color-scheme: dark)');
        const handler = () => {
            if (themeMode() === 'auto') {
                document.dispatchEvent(new CustomEvent('lh:theme'));
            }
        };
        if (mq.addEventListener) {
            mq.addEventListener('change', handler);
        }
    }
}

/* -------------------------------------------------------------------------
 * Copy to clipboard
 * ---------------------------------------------------------------------- */

/**
 * The copy-to-clipboard control.
 *
 * Re-exported rather than implemented here: the installer bundle needs the identical
 * behaviour and does not load this module, so the implementation lives in copy.js and both
 * front ends import it from there. Panel code keeps importing it from core.js.
 */
export { initCopyButtons };
