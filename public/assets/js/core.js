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
    if (!res.ok || (data && data.error)) {
        const err = new Error((data && data.error) || 'Request failed with HTTP ' + res.status + '.');
        err.transport = /solr|timed out|timeout|refused|resolve|unreachable|credentials/i.test(err.message);
        throw err;
    }
    return data;
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
    if (data.error) {
        throw new Error(data.error);
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

/** Reveal the page-level connection banner once, with the first real diagnosis. */
function raiseConnectionBanner(message) {
    const banner = byId('lh-conn');
    if (!banner || !banner.hidden) {
        return;
    }
    const detail = byId('lh-conn-detail');
    if (detail) {
        detail.textContent = message;
    }
    banner.hidden = false;
}

/**
 * Run a card's loader, showing progress and handling its failure locally.
 *
 * @param {string} id     Card base id, matching Controller::cardOpen().
 * @param {string} label  What is happening, in words. Never a bare spinner.
 * @param {Function} loader async () => void — renders into the card's content element.
 */
export async function loadCard(id, label, loader) {
    if (inFlight.has(id)) {
        return;
    }
    inFlight.add(id);

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
    } catch (err) {
        if (status) {
            status.hidden = true;
        }
        if (skel) {
            skel.remove();
        }
        renderCardError(id, label, err, () => loadCard(id, label, loader));
        if (err && err.transport) {
            raiseConnectionBanner(String(err.message || ''));
        }
    } finally {
        window.clearInterval(ticker);
        inFlight.delete(id);
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

    const content = byId(id + '-content');
    if (content) {
        card.insertBefore(box, content);
    } else {
        card.appendChild(box);
    }
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
        step(job);

        while (job && !job.done) {
            await new Promise((resolve) => window.setTimeout(resolve, JOB_POLL_MS));
            job = await post({ action: 'job_poll', id: job.id });
            step(job);
        }
        if (job && typeof options.onDone === 'function') {
            options.onDone(job);
        }
    } catch (err) {
        mount.replaceChildren(el('div', { class: 'card-error', role: 'alert' }, [
            el('h4', { text: 'The operation could not run' }),
            el('p', { text: String(err && err.message ? err.message : err) })
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

/** Draw a job's progress bar, step list and controls. */
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
                cancel.textContent = 'Cancel failed';
            }
        });
        actions.appendChild(cancel);
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
export { initCopyButtons } from './copy.js';
