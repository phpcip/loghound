/*
 * Loghound — shared front end for the Opensolr index-analytics views.
 *
 * Three views share one problem: none of them can do anything until they know which index
 * the operator is looking at, and that list comes from the platform. Fetching it once per
 * card would be three or four identical API calls per page load; fetching it before the
 * cards would make the page block on the network before it drew anything, which is the
 * exact failure the async card pattern exists to prevent.
 *
 * So the list is a shared promise. Every card awaits it, the first one to ask starts it,
 * and a rejection clears the memo so a card's own Retry button really does retry rather
 * than replaying a cached failure.
 *
 * It also owns the two things all three views now share: the FILTER CARD, which turns the
 * four dimensions the platform's request log can honestly be faceted on into links, and the
 * VOLUME CHART, which is the primary chart on each of them. Both are here rather than copied
 * three times because three copies of one field list is three places for it to drift.
 *
 * Everything rendered from these payloads came off the wire and was chosen by whoever
 * queried the customer's search index — client addresses, handler names, and the field
 * names that survive query-shape normalisation. It is always placed in the DOM as text,
 * never as markup. That includes the filter links: a value goes into a URL through
 * URLSearchParams, which encodes it, and into the page through textContent.
 */

'use strict';

import { api, byId, dec, el, hideEmpty, num, pct, setPop, showEmpty } from '../core.js';
import { dispose, lines, tokens } from '../charts.js';
import { basisNote, operatorControl, toggleUrl } from '../facetfilter.js';

/** The in-flight or resolved index list, shared by every card on a page. */
let listPromise = null;

/** The index currently selected, or null before the list has arrived. */
let selected = null;

/** Called when the operator picks a different index. */
let onPick = null;

/**
 * Fetch the account's index list, once per page.
 *
 * The memo is cleared on failure so a retry is a real retry.
 *
 * @param {string} view View slug, for the API endpoint.
 */
export function indexList(view) {
    if (!listPromise) {
        listPromise = api(view, 'indexes').catch((err) => {
            listPromise = null;
            throw err;
        });
    }
    return listPromise;
}

/**
 * Resolve the selected index, populating the picker the first time.
 *
 * Returns null when there is nothing to select — no indexes on the account, or a list the
 * platform would not give us — and the caller renders an empty state rather than querying
 * for an index that does not exist.
 *
 * @param {string} view     View slug.
 * @param {string} selectId Element id of the picker.
 * @param {Function} onChange Called with the new index name when the operator switches.
 */
export async function resolveCore(view, selectId, onChange) {
    onPick = onChange;
    const data = await indexList(view);
    const select = byId(selectId);

    if (!data.indexes || !data.indexes.length) {
        if (select) {
            select.replaceChildren(el('option', { value: '', text: 'No indexes' }));
            select.disabled = true;
        }
        selected = null;
        return null;
    }

    if (selected === null) {
        selected = data.selected && data.indexes.indexOf(data.selected) !== -1
            ? data.selected
            : data.indexes[0];
    }

    if (select && !select.dataset.ready) {
        select.replaceChildren(...data.indexes.map((name) => el('option', { value: name, text: name })));
        select.value = selected;
        select.disabled = false;
        select.dataset.ready = '1';
        select.addEventListener('change', () => {
            selected = select.value;
            for (const other of document.querySelectorAll('select[data-ready="1"]')) {
                other.value = selected;
            }
            if (typeof onPick === 'function') {
                onPick(selected);
            }
        });
    }

    return selected;
}

/**
 * Turn a response state into a sentence, or null when the state is "fine".
 *
 * Every one of these is a normal outcome the operator has to be told about in words. An
 * index the account does not own is the common one: a stale bookmark, a renamed index, or
 * an API key scoped to a different set.
 *
 * @param {Object} data An API payload carrying `state` and `note`.
 */
export function stateMessage(data) {
    if (!data || !data.state || data.state === 'ok') {
        return null;
    }
    if (data.note) {
        return String(data.note);
    }
    const known = {
        no_index: 'No index selected yet.',
        demo: 'Demo mode fabricates web traffic only; Opensolr analytics are read live.',
        not_configured: 'No Opensolr account is configured.',
        not_owner: 'This Opensolr account does not own that index.',
        unreachable: 'The Opensolr API could not be reached.',
        refused: 'Opensolr refused the request.'
    };
    return known[data.state] || 'The request log could not be read.';
}

/**
 * Render a card's empty state for a non-ok response, and say whether one was rendered.
 *
 * Returns true when the caller should stop: there is nothing to draw and the reason is
 * already on screen.
 *
 * @param {string} emptyId Element id of the card's `.empty` slot.
 * @param {Object} data
 * @param {string} what    Noun for the "nothing here" case, e.g. "requests".
 */
export function handleState(emptyId, data, what) {
    const message = stateMessage(data);
    if (message) {
        /* "EVERYTHING ELSE ON THIS PAGE IS UNAFFECTED" WAS A LIE WHEN IT MATTERED MOST. Every
           card on these four views calls this, so on an `unreachable` or `refused` state ALL of
           them rendered it — four cards each telling the reader the other three were fine.
           A platform-wide state is a page-wide fact and says so; an index-specific one keeps
           the reassurance, because there it is true. */
        const pageWide = data.state === 'unreachable' || data.state === 'refused'
            || data.state === 'not_configured';
        showEmpty(emptyId, 'No ' + what + ' to show', [
            message,
            data.state === 'no_index'
                ? 'Pick an index above once the list has loaded.'
                : pageWide
                    ? 'Every card on this page reads the same source, so they are all in this state. '
                      + 'Web-traffic views are unaffected.'
                    : 'Everything else on this page is unaffected.'
        ]);
        return true;
    }
    if (!data.requests) {
        /* FILTERED TO NOTHING IS NOT THE SAME AS NOTHING LOGGED. These views have their own
           filter namespace, and its chips may be lit directly above this message — which said
           flatly that Opensolr logged no requests, when what happened is that the reader
           excluded all of them. */
        /* `active` is the log-plane facet layer's flat(): a map of field to chosen values,
           not a list. Counting it as an array answers zero on every filtered page. */
        const active = data.active;
        let filters = 0;
        if (Array.isArray(active)) {
            filters = active.length;
        } else if (active && typeof active === 'object') {
            for (const field of Object.keys(active)) {
                filters += Array.isArray(active[field]) ? active[field].length : 1;
            }
        }
        if (filters > 0) {
            showEmpty(emptyId, 'No ' + what + ' match your filters', [
                'Opensolr logged requests for this index in the selected range, but none of them match '
                    + 'the ' + filters + ' filter value' + (filters === 1 ? '' : 's') + ' set above.',
                'Remove a value from the chips above the card, or widen the time range.'
            ]);
            return true;
        }
        showEmpty(emptyId, 'No ' + what + ' in this time range', [
            'Opensolr logged no requests for this index in the selected range. Try a wider range.',
            'The request log covers queries that reached the search index. An index nothing queries '
                + 'produces no rows here, which is not a fault.'
        ]);
        return true;
    }
    return false;
}

/* -------------------------------------------------------------------------
 * Filters
 *
 * The request-log filters live in the query string under `lf[field][]`, a namespace of
 * their own. They are NOT the `f[field][]` sidebar filters the rest of the panel uses:
 * those name fields on Loghound's own cores, none of which exists on the platform's
 * analytics shards, and an `fq` naming an absent field matches nothing — so sharing one
 * namespace would make every figure here read zero under a chip that looked like it was
 * working. The server reports those as ignored instead; see `data.ignored`.
 *
 * Everything below builds URLs and anchors. A filtered page is a link somebody can send.
 * ---------------------------------------------------------------------- */

/**
 * The query-string namespace for this plane.
 *
 * `lf`, not `f`, and the separation is load-bearing rather than tidy: these field names exist on
 * the platform's analytics shards and none of Loghound's own fields does. One namespace would mean
 * every chip set on the session explorer arrived here as a field the request log has never heard
 * of, and an `fq` naming an absent field matches nothing — so every figure would read zero under a
 * chip that looked like it was working.
 */
const LF = 'lf';

/** Field labels, matching OpensolrView::logFilterFields(). */
const FILTER_LABELS = {
    path: 'Handler',
    http_status: 'Status',
    param_hostname: 'Node',
    ip: 'Caller'
};

/** The outcome slices, matching OpensolrView::OUTCOMES. */
const OUTCOME_LABELS = {
    zero: 'Matched nothing',
    found: 'Matched something',
    slow: 'Slow answers'
};

/**
 * The current URL with one request-log filter value added.
 *
 * Delegated to the one reader-writer of the filter contract, with `lf` as the namespace. Kept as
 * an exported name because three views call it, but it no longer knows the encoding: the reserved
 * `op` key and the rule that an absent operator means "any of" are facetfilter.js's, and a second
 * implementation of them here is what made this plane's filters behave differently from the rest
 * of the panel's.
 */
export function lfAdd(field, value) {
    return toggleUrl(field, value, LF);
}

/** The current URL with one request-log filter value removed. The same gesture, same function. */
export function lfRemove(field, value) {
    return toggleUrl(field, value, LF);
}

/** The current URL with a parameter replaced, or removed when the value is null. */
function lfWith(key, value) {
    const params = new URLSearchParams(window.location.search);
    if (value === null) {
        params.delete(key);
    } else {
        params.set(key, value);
    }
    params.delete('start');
    return '?' + params.toString();
}

/** The current URL with every request-log filter and the outcome slice dropped. */
function lfClear() {
    const params = new URLSearchParams(window.location.search);
    for (const key of Array.prototype.slice.call(params.keys())) {
        if (key.indexOf('lf[') === 0 || key === 'outcome') {
            params.delete(key);
        }
    }
    return '?' + params.toString();
}

/** Is this value one of the active filters on this field? */
function isActive(active, field, value) {
    const values = (active || {})[field];
    return Array.isArray(values) && values.indexOf(value) !== -1;
}

/**
 * The chips for what is currently filtered, each a link that removes itself.
 *
 * The ignored-sidebar note is a chip too rather than a footnote, because a reader who
 * arrived here from the session explorer with a country selected needs to be told, where
 * they are looking, that it is not being applied — a number filtered by less than the page
 * implies is a wrong answer presented as a right one.
 */
function renderActive(id, data) {
    const mount = byId(id + '-active');
    if (!mount) {
        return;
    }
    const chips = [];

    for (const dim of (data.filters && data.filters.dimensions) || []) {
        const excluded = dim.op === 'none';
        for (const value of dim.values) {
            chips.push(el('a', {
                class: excluded ? 'excluded' : '',
                href: toggleUrl(dim.field, value, LF),
                title: excluded ? 'Stop excluding this value' : 'Remove this filter'
            }, [
                el('span', {
                    text: (FILTER_LABELS[dim.field] || dim.field) + ': ' + (excluded ? 'not ' : '') + value
                }),
                el('span', { text: '\u00d7' })
            ]));
        }
    }
    if (data.outcome && OUTCOME_LABELS[data.outcome]) {
        chips.push(el('a', { href: lfWith('outcome', null), title: 'Remove this slice' }, [
            el('span', { text: OUTCOME_LABELS[data.outcome] }),
            el('span', { text: '×' })
        ]));
    }
    if (chips.length > 1) {
        chips.push(el('a', { class: 'lf-clear', href: lfClear(), title: 'Remove every filter' }, [
            el('span', { text: 'Clear all' })
        ]));
    }

    mount.replaceChildren(...chips);
}

/**
 * The outcome slice buttons, with the two counts the facet actually produced.
 *
 * "Slow answers" carries no count on purpose: there is no cheap one, and a second API call
 * to put a number on a button the reader can simply press would be spending a request to
 * say what pressing it says.
 */
function renderOutcomes(id, data) {
    const mount = byId(id + '-outcomes');
    if (!mount) {
        return;
    }
    const counts = data.outcomes || {};
    const entries = [el('a', {
        class: data.outcome ? '' : 'on',
        href: lfWith('outcome', null),
        text: 'Everything'
    })];

    for (const key of Object.keys(OUTCOME_LABELS)) {
        const count = counts[key];
        const label = key === 'slow'
            ? 'Slow answers (' + num(data.slow_ms) + ' ms or worse)'
            : OUTCOME_LABELS[key];
        entries.push(el('a', {
            class: data.outcome === key ? 'on' : '',
            href: lfWith('outcome', key)
        }, [
            el('span', { text: label }),
            count === null || count === undefined
                ? null
                : el('span', { class: 'lf-count', text: num(count) })
        ]));
    }

    mount.replaceChildren(...entries);
}

/**
 * The facet columns. Each value is a link that adds or removes itself as a filter.
 */
function renderRail(id, data) {
    const mount = byId(id + '-rail');
    if (!mount) {
        return;
    }
    const groups = (data.groups || []).map((group) => el('div', { class: 'facet', dataset: { field: group.field, ns: LF } }, [
        el('h3', { text: group.label }),
        operatorControl(group),
        el('ul', {}, group.buckets.map((bucket) => {
            const state = bucket.state || (isActive(data.active, group.field, bucket.value) ? 'on' : 'off');
            const verb = state === 'on' ? 'Remove ' : (state === 'excluded' ? 'Stop excluding ' : 'Filter to ');
            return el('li', {}, [
                el('a', {
                    class: state === 'on' ? 'on' : (state === 'excluded' ? 'excluded' : ''),
                    href: toggleUrl(group.field, bucket.value, LF),
                    title: verb + group.label + ': ' + bucket.value
                }, [
                    el('span', {
                        class: 'fm',
                        'aria-hidden': 'true',
                        text: state === 'on' ? '\u2713' : (state === 'excluded' ? '\u2212' : '')
                    }),
                    el('span', { class: 'fv', text: bucket.value }),
                    el('span', {
                        class: 'fc',
                        text: bucket.count === null || bucket.count === undefined ? '\u2014' : num(bucket.count)
                    })
                ])
            ]);
        })),
        basisNote(group)
    ]));

    mount.replaceChildren(...groups);
}

/**
 * Draw the whole filter card, or say why it is empty.
 *
 * @param {string} id   Card base id, e.g. 'ix-filters'.
 * @param {Object} data The `facets` payload.
 */
export function renderFilters(id, data) {
    renderActive(id, data);

    if (handleState(id + '-empty', data, 'requests')) {
        return;
    }
    hideEmpty(id + '-empty');

    renderOutcomes(id, data);
    renderRail(id, data);

    const note = byId(id + '-note');
    if (note) {
        const parts = [
            'Each column lists the ' + num(data.limit) + ' most common values. Picking a value narrows ' +
                'every OTHER column and leaves its own complete, so a second value can always be added ' +
                'to the same column — each filtered column is counted again with its own filter lifted, ' +
                'which is what the sentence under it says.'
        ];
        if ((data.ignored || []).length) {
            parts.push('Not applied here: ' + data.ignored.join(', ') + '. Those filters describe web ' +
                'sessions Loghound scored itself; the platform\'s request log has no such fields, and ' +
                'applying them would match nothing rather than narrow anything.');
        }
        note.textContent = parts.join(' ');
    }

    setPop(id, num(data.requests) + ' requests match the current filters out of everything Opensolr ' +
        'logged for this index in this range. Every other card on this page counts the same population.');
}

/* -------------------------------------------------------------------------
 * The primary chart
 * ---------------------------------------------------------------------- */

/**
 * Draw request volume over time and the four figures above it.
 *
 * The four are the ones Opensolr's own analytics dashboard shows — total, average, peak and
 * how many buckets those came from — because a chart without them makes the reader estimate
 * numbers off an axis. "Data points" is not decoration: it is what turns "average 40" into a
 * statement about a known number of buckets.
 *
 * @param {string} id   Card base id, e.g. 'ix-volume'.
 * @param {Object} data The `volume` payload.
 */
export function renderVolume(id, data) {
    const set = fieldSetter(id);

    if (handleState(id + '-empty', data, 'requests')) {
        for (const key of ['total', 'mean', 'peak', 'points']) {
            set(key, '—');
        }
        dispose(id + '-chart');
        return;
    }

    const counts = data.all || [];
    if (!counts.length) {
        dispose(id + '-chart');
        showEmpty(id + '-empty', 'No requests to plot', [
            'Opensolr logged requests for this index in this range, but the platform returned no time ' +
                'buckets for them. Try a wider range.'
        ]);
        return;
    }
    hideEmpty(id + '-empty');

    let peak = 0;
    let total = 0;
    for (const value of counts) {
        total += value;
        peak = Math.max(peak, value);
    }

    set('total', num(data.requests));
    set('mean', dec(total / counts.length, 1));
    set('peak', num(peak));
    set('points', num(counts.length));

    const t = tokens();
    const series = [{ name: 'All requests', color: t.accent, data: counts }];
    if (data.zero_known) {
        series.push({ name: 'Matched nothing', color: t.pop.declared, data: data.zero || [] });
    }
    lines(id + '-chart', data.times, series);

    setPop(id, num(data.requests) + ' requests under the current filters, in ' + num(counts.length) +
        ' buckets across this range. ' +
        (data.zero_known
            ? num(data.zero_total) + ' of them (' + pct(data.zero_total, data.requests) +
              ') matched no documents, drawn as the second series.'
            : 'An outcome slice is selected, so the zero-result series is not drawn — it would be the ' +
              'whole of one slice and none of the other.'));
}

/* -------------------------------------------------------------------------
 * Shared rendering helpers
 * ---------------------------------------------------------------------- */

/**
 * A setter for the `[data-field]` placeholders inside one card's content.
 *
 * Scoped to the card rather than the document, because four cards on one page use the same
 * field names and a document-wide lookup would fill in whichever came first.
 */
export function fieldSetter(id) {
    const scope = byId(id + '-content');
    return (field, value) => {
        const node = scope ? scope.querySelector('[data-field="' + field + '"]') : null;
        if (node) {
            node.textContent = value;
        }
    };
}

/**
 * Refuse to draw a chart that has nothing to draw, and say so instead.
 *
 * These views query somebody else's platform and legitimately get nothing back — an index
 * nobody queried, a filter that matches no requests. An ECharts instance handed an empty
 * series renders an axis with no data, which reads as broken rather than as empty, and a
 * previously drawn chart left in place reads as stale data. So the instance is disposed and
 * the card's own empty state is shown.
 *
 * Returns true when the caller should stop.
 *
 * @param {string} chartId Element id of the .chart container.
 * @param {string} emptyId Element id of the card's .empty slot.
 * @param {number} rows    How many rows there are to draw.
 * @param {string} heading Empty-state heading.
 * @param {Array<string>} parts Empty-state paragraphs.
 */
export function chartOrEmpty(chartId, emptyId, rows, heading, parts) {
    if (rows > 0) {
        hideEmpty(emptyId);
        return false;
    }
    dispose(chartId);
    showEmpty(emptyId, heading, parts);
    return true;
}

/**
 * Draw a chart, or put a sentence where it would have been.
 *
 * FOR HALF OF A SPLIT CARD, where chartOrEmpty() cannot be used because the card's one empty
 * slot would blank the other half with it. An ECharts instance with no series renders as an
 * empty axis box, which reads as broken rather than as empty — the reason this file already
 * carries chartOrEmpty() — and four charts were reaching that state because the guard on their
 * card tested `data.requests` and not the series they were actually about to draw.
 *
 * Returns true when the caller should NOT draw.
 *
 * @param {string} chartId Element id of the .chart container.
 * @param {number} rows    How many series points there are.
 * @param {string} sentence What to say instead, naming why it is empty.
 */
export function plotOrNote(chartId, rows, sentence) {
    const node = byId(chartId);
    if (rows > 0) {
        if (node) {
            node.classList.remove('chart-note');
            node.replaceChildren();
        }
        return false;
    }
    dispose(chartId);
    if (node) {
        node.classList.add('chart-note');
        node.replaceChildren(el('p', { class: 'muted', text: sentence }));
    }
    return true;
}

/** Re-exported so a view module takes its palette from the same place as this one. */
export { tokens };

/**
 * A share bar, used in every "top N" table on these views.
 *
 * @param {number} part
 * @param {number} total
 */
export function shareBar(part, total) {
    const width = total > 0 ? (part / total) * 100 : 0;
    return el('span', { class: 'bar', title: width.toFixed(1) + '%' }, [
        el('span', { style: 'width:' + width.toFixed(2) + '%' })
    ]);
}

/**
 * Render a query shape as monospaced text.
 *
 * The field names inside a shape are chosen by whoever queried the index, so this is a
 * textContent node and never markup. It is deliberately not truncated in the DOM — the
 * cell clips it in CSS — so the full shape is available to copy and to a screen reader.
 */
export function shapeNode(label) {
    return el('code', { class: 'shape', text: String(label || '') });
}

/**
 * Sort a merged shape map into rows.
 *
 * @param {Object} shapes hash => aggregate
 * @param {string} order  One of count, zero, slow, worst.
 */
export function rankShapes(shapes, order) {
    const rows = Object.keys(shapes).map((hash) => {
        const s = shapes[hash];
        return {
            hash: hash,
            label: s.label,
            handler: s.handler,
            count: s.count,
            zero: s.zero,
            timed: s.timed,
            mean: s.timed ? s.qsum / s.timed : null,
            qmax: s.qmax,
            hist: s.hist,
            worst: s.worst
        };
    });

    const by = {
        count: (a, b) => b.count - a.count,
        zero: (a, b) => b.zero - a.zero || b.count - a.count,
        slow: (a, b) => (b.mean || 0) - (a.mean || 0),
        worst: (a, b) => (b.qmax || 0) - (a.qmax || 0)
    };
    rows.sort(by[order] || by.count);
    return rows;
}

/**
 * Read a percentile off a merged histogram.
 *
 * Returns the UPPER edge of the bucket the percentile falls into, because that is the only
 * honest reading of a bucketed distribution: everything in that bucket was at most this
 * fast. Callers render it with a "≤". Null when nothing was measured; Infinity when the
 * percentile falls past the last edge, which callers render as "over".
 *
 * @param {Array<number>} hist  Bucket counts, one longer than edges.
 * @param {Array<number>} edges Bucket lower edges.
 * @param {number} p            0..1
 */
export function histPercentile(hist, edges, p) {
    let total = 0;
    for (const n of hist) {
        total += n;
    }
    if (!total) {
        return null;
    }
    const want = total * p;
    let seen = 0;
    for (let i = 0; i < hist.length; i += 1) {
        seen += hist[i];
        if (seen >= want) {
            return i >= edges.length ? Infinity : edges[i];
        }
    }
    return Infinity;
}

/**
 * Reveal a card's content and retire its loading strip.
 *
 * The async-card pattern hides content until a fetch resolves, which is right for a card
 * backed by one request and wrong for one backed by a stepped job: the job renders its own
 * progress bar, step list, elapsed counter and Cancel button INSIDE the content area, and
 * hiding that area would replace a rich progress report with a bare strip. So a job-backed
 * card reveals itself immediately and lets the job speak for itself.
 *
 * @param {string} id Card base id.
 */
export function revealCard(id) {
    const status = byId(id + '-status');
    const skel = byId(id + '-skel');
    const content = byId(id + '-content');
    if (status) {
        status.hidden = true;
    }
    if (skel) {
        skel.remove();
    }
    if (content) {
        content.hidden = false;
    }
}

/**
 * Render a card-level failure that did not come from loadCard().
 *
 * A job-backed card has no loadCard() wrapper to catch a throw for it, so the one case
 * that still needs saying — the index list could not be read at all — is rendered here in
 * the same shape, with a retry that re-runs the caller's own initialiser.
 *
 * @param {string} id      Card base id.
 * @param {Error}  err
 * @param {Function} retry
 */
export function cardFailure(id, err, retry) {
    const card = document.querySelector('[data-card="' + id + '"]');
    if (!card) {
        return;
    }
    const existing = card.querySelector('.card-error');
    if (existing) {
        existing.remove();
    }

    const button = el('button', { type: 'button', class: 'small', text: 'Retry' });
    button.addEventListener('click', () => {
        button.disabled = true;
        retry();
    });

    card.insertBefore(el('div', { class: 'card-error', role: 'alert' }, [
        el('h4', { text: 'This section could not load' }),
        el('p', { text: String(err && err.message ? err.message : err) }),
        el('p', { class: 'faint', text: 'Everything else on this page is unaffected.' }),
        el('div', { class: 'card-error-actions' }, [button])
    ]), card.firstChild);
}
