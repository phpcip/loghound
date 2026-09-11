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
 * Everything rendered from these payloads came off the wire and was chosen by whoever
 * queried the customer's search index — client addresses, handler names, and the field
 * names that survive query-shape normalisation. It is always placed in the DOM as text,
 * never as markup.
 */

'use strict';

import { api, byId, el, showEmpty } from '../core.js';

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
        showEmpty(emptyId, 'Nothing to show', [
            message,
            data.state === 'no_index'
                ? 'Pick an index above once the list has loaded.'
                : 'Everything else on this page is unaffected.'
        ]);
        return true;
    }
    if (!data.requests) {
        showEmpty(emptyId, 'No ' + what + ' in this time range', [
            'Opensolr logged no requests for this index in the selected range. Try a wider range.',
            'The request log covers queries that reached the search index. An index nothing queries ' +
                'produces no rows here, which is not a fault.'
        ]);
        return true;
    }
    return false;
}

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
