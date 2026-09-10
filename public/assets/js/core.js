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
 *   - DOM is built with document.createElement and textContent. Never innerHTML with
 *     data. The one exception is `html()` below, which exists for the handful of
 *     authored static strings, and which is never handed a value from an API response.
 *   - No eval, no new Function, no inline event handlers. The CSP forbids all three and
 *     the panel is written so it never wants them.
 *   - A URL only becomes an href after the server has passed it through
 *     Security::safeUrl(); the client never decides that a scheme is safe.
 */

'use strict';

/* -------------------------------------------------------------------------
 * Boot payload
 * ---------------------------------------------------------------------- */

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

/* -------------------------------------------------------------------------
 * DOM construction
 * ---------------------------------------------------------------------- */

/**
 * Create an element.
 *
 * `attrs.text` sets textContent (the safe default for every value from an API).
 * `attrs.html` sets innerHTML and is only ever passed a string authored in this
 * repository — see the comment at the top of the file.
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
            } else if (key === 'html') {
                node.innerHTML = String(value);
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
 * Each cell descriptor is `{text, mono, num, clip, title, node, class}`. Everything goes
 * through textContent unless a pre-built `node` is supplied.
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
                // The full value lives in the title attribute when the cell is clipped,
                // so a 900-character User-Agent is still readable without breaking layout.
                title: cell.title || (cell.clip && cell.text ? String(cell.text) : null)
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
}

/** Hide an empty state (data arrived after all). */
export function hideEmpty(id) {
    const node = byId(id);
    if (node) {
        node.hidden = true;
        node.classList.remove('show');
    }
}

/**
 * The standard "nothing has been indexed yet" state, used by every view.
 *
 * Deliberately actionable: the two reasons a fresh install is empty are that the tailer
 * is not running and that no log source has been confirmed, and both have a next step.
 */
export function noDataYet(id, what) {
    showEmpty(id, 'No ' + what + ' in this time range', [
        'Either nothing has been indexed yet, or nothing matched the selected range and filters. Try a wider range first.',
        el('p', {}, [
            'If this is a fresh install: confirm a log source under ',
            el('a', { href: '?v=settings', text: 'Settings' }),
            ', then check that the tailer is running with ',
            el('code', { text: 'systemctl status loghound-tail' }),
            '.'
        ])
    ]);
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
 * Fetch a data action for a view.
 *
 * The URL is built from the current query string so the active range and filters travel
 * with every request without each view having to remember them. `same-origin` credentials
 * carry HTTP Basic auth; the CSRF token is only needed for writes, and the panel's writes
 * are ordinary form posts.
 *
 * @param {string} view    View slug.
 * @param {string} action  Action name (matched against the view's own allowlist).
 * @param {Object} [extra] Additional query parameters.
 */
export async function api(view, action, extra) {
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
    const res = await fetch('?' + params.toString(), {
        credentials: 'same-origin',
        headers: { Accept: 'application/json' }
    });
    let data = null;
    try {
        data = await res.json();
    } catch (e) {
        throw new Error('The panel returned a response that was not JSON (HTTP ' + res.status + ').');
    }
    if (!res.ok || (data && data.error)) {
        throw new Error((data && data.error) || 'Request failed with HTTP ' + res.status + '.');
    }
    return data;
}

/**
 * Run a loader and turn any failure into a visible, honest message.
 *
 * A view that silently renders nothing when Solr is down is the worst outcome: the
 * operator concludes they have no bot traffic.
 */
export async function load(emptyId, what, fn) {
    try {
        await fn();
    } catch (err) {
        showEmpty(emptyId, 'Could not load ' + what, [
            String(err && err.message ? err.message : err),
            'The connection banner at the top of the page has more detail if this is a Solr problem.'
        ]);
    }
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

    // In 'auto', the operating system can change theme under us. Charts have colours
    // baked into their options, so they need the same notification.
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
 * Wire every [data-copy] button to copy the text of the element it names.
 *
 * Used by the beacon snippets. Falls back to a selection-based copy when the async
 * clipboard API is unavailable (it requires a secure context, and plenty of these
 * installs are plain HTTP on a private network).
 */
export function initCopyButtons() {
    for (const button of document.querySelectorAll('[data-copy]')) {
        button.addEventListener('click', async () => {
            const source = byId(button.dataset.copy);
            if (!source) {
                return;
            }
            const text = source.textContent || '';
            const done = (ok) => {
                const original = button.dataset.label || button.textContent;
                button.dataset.label = original;
                button.textContent = ok ? 'Copied' : 'Press Ctrl+C';
                window.setTimeout(() => { button.textContent = original; }, 1600);
            };
            try {
                await navigator.clipboard.writeText(text);
                done(true);
            } catch (e) {
                // Select the block so the keyboard shortcut works, and say so.
                const range = document.createRange();
                range.selectNodeContents(source);
                const sel = window.getSelection();
                sel.removeAllRanges();
                sel.addRange(range);
                done(false);
            }
        });
    }
}
