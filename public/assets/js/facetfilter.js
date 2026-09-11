/*
 * Loghound — the client half of the facet contract: the operator, the inline filter, the
 * A–Z value browser.
 *
 * WHAT THIS FILE IS FOR. src/Panel/Facets.php owns the semantics — which values are selected,
 * what boolean operator is in force on each dimension, which tag excludes which facet, and how
 * all of that is spelled in the URL. This is the browser's side of exactly that contract and
 * nothing else. It renders three controls the panel did not have:
 *
 *   1. THE OPERATOR, per dimension, visible in the control. "Any of" / "All of" / "None of",
 *      as three real links, with the one in force marked. Nobody can tell OR from AND by
 *      looking at a list of values, and the answer belongs on the thing being operated rather
 *      than in a paragraph at the top of the page that a reader has to hold in their head
 *      while looking somewhere else. "All of" is absent — not present and greyed — on a
 *      single-valued dimension, because there `a AND b` is empty by construction and a control
 *      whose only possible answer is zero is worse than no control.
 *
 *   2. THE INLINE FILTER, directly above the value list, on every dimension long enough to
 *      need one. Focus warms the full value list; typing then narrows across EVERY value the
 *      dimension has rather than only the twelve on screen, which is the difference between a
 *      box that finds a country and one that finds the countries already visible.
 *
 *   3. THE VALUE BROWSER, a dialog: a search box, an A–Z index with the empty letters visibly
 *      inactive, the values grouped under letter headings in columns, each with its count. It
 *      reuses the panel's one dialog shell (dialog.js) rather than inventing a second kind of
 *      modal, so focus handling, Escape and the scrim are the same everywhere.
 *
 * MULTI-SELECT IN THE DIALOG STAGES, AND THAT IS DELIBERATE. In the sidebar a value is one
 * click and the page reloads, which is right: it is one decision, the result is immediately
 * on screen, and the link works with scripting off. A dialog is a BULK picking surface — the
 * reason to open it is to choose several — so closing it on the first pick would make the
 * second pick impossible. Clicking a value here toggles it in a pending set, the row updates
 * at once, and Apply navigates ONCE to the combined URL. Every row is still a real <a href>
 * carrying the result of applying the pending set plus that row, so a middle-click, a
 * copy-link and a scripting-off click all still do something coherent.
 *
 * COUNTS. Two honesty rules are enforced here rather than left to the reader. A dimension
 * whose filter is excluded from its own facet says so, because its counts are what each value
 * would match with that filter LIFTED and not what the page currently shows. A multi-valued
 * dimension says its counts overlap, because one session lands in several buckets and the
 * column does not sum to the total. Both sentences come from the server, which knows which
 * case applies.
 *
 * THE CSP has no 'unsafe-inline': no inline handler, no javascript: href, nothing but
 * delegated listeners. Every value is untrusted — an AS organisation name is whatever a
 * registry holds — and reaches the DOM through core.js's el({text}), which is textContent.
 */

'use strict';

import { api, el, fill, num } from './core.js';
import { closeDialog, dialogFail, isCurrent, openDialog } from './dialog.js';
import { dimValue } from './identity.js';

/** The query-string prefix for Loghound's own dimensions. The Opensolr log plane uses 'lf'. */
const NS = 'f';

/** The reserved key inside `f[field][…]` that carries the operator. Everything else is a value. */
const OP_KEY = 'op';

/** The default operator, and what an absent `op` means, so every old URL behaves as before. */
const OP_ANY = 'any';

/** Values in one dimension are AND-ed. Offered only where the field holds a list. */
const OP_ALL = 'all';

/** The dimension's values are excluded. */
const OP_NONE = 'none';

/** Value count above which a list gets its own inline filter box. */
const FILTER_AT = 10;

/** Rows the inline box renders for a match. Beyond this the value browser is the way in. */
const INLINE_MAX = 50;

/**
 * Shortest substring sent to the server, matching Facets::MIN_SEARCH.
 *
 * One character matches most of a term dictionary and costs a full scan to say so. Below this the
 * browser filters what it already has, which is instant and is the right answer for one letter.
 */
const MIN_SEARCH = 2;

/**
 * How long typing must pause before a search goes out.
 *
 * A burst of keystrokes must become ONE request, not one per letter. 250 ms is below the point a
 * person reads as lag and above a fast typist's inter-key gap. Enter bypasses it entirely, because
 * somebody who types faster than the debounce and presses Enter has asked for the search NOW.
 */
const SEARCH_DEBOUNCE_MS = 250;

/** The letter bar, with '#' collecting everything that does not start with a letter. */
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ#';

/**
 * field → [{value, label, count, why}] for the whole dimension.
 *
 * One fetch per dimension per page load, shared by the inline box and the dialog: whichever
 * asks first pays for the round trip. Changing a filter reloads the page, so the cache cannot
 * go stale.
 */
const fullCache = new Map();

/** field → in-flight promise, so two controls asking at once make one request. */
const pending = new Map();

/**
 * Monotonic token for value searches, so a slow answer cannot overwrite a newer one.
 *
 * The dialog has isCurrent() for the dialog as a whole; this is the finer-grained version for the
 * searches WITHIN one open dialog, where the generation never changes but the question does. A
 * response that arrives after a newer request was issued is dropped rather than rendered — out of
 * order is the normal case when one search is slow and the next is fast, and rendering it would
 * show results for a string that is no longer in the box.
 */
let searchToken = 0;

/** The dialog's pending selection: field → Set of values, discarded unless Apply is pressed. */
let staged = null;

/** The dimension the dialog is showing, so a slow fetch for a dismissed one renders nothing. */
let openField = '';

/* -------------------------------------------------------------------------
 * The URL contract — the mirror of Facets::urlFor()
 * ---------------------------------------------------------------------- */

/** The parameter name holding one dimension's values. */
function valueKey(field, ns) {
    return (ns || NS) + '[' + field + '][]';
}

/** The parameter name holding one dimension's operator. */
function opKey(field, ns) {
    return (ns || NS) + '[' + field + '][' + OP_KEY + ']';
}

/**
 * Read the whole selection out of the current URL.
 *
 * @returns {Map<string, {values: string[], op: string}>}
 */
export function readSelection(ns) {
    const prefix = ns || NS;
    const params = new URLSearchParams(window.location.search);
    const out = new Map();
    const values = new RegExp('^' + prefix + '\\[([A-Za-z0-9_]{1,64})\\]\\[\\]$');

    for (const key of Array.from(params.keys())) {
        const match = values.exec(key);
        if (!match) {
            continue;
        }
        const field = match[1];
        const chosen = params.getAll(key).filter((v) => v !== '');
        if (!chosen.length) {
            continue;
        }
        const op = params.get(opKey(field, prefix));
        out.set(field, {
            values: chosen,
            op: op === OP_ALL || op === OP_NONE ? op : OP_ANY
        });
    }
    return out;
}

/** The operator in force on one dimension, from the URL. */
export function operatorOf(field, ns) {
    const entry = readSelection(ns).get(field);
    return entry ? entry.op : OP_ANY;
}

/** The values selected on one dimension, from the URL. */
export function valuesOf(field, ns) {
    const entry = readSelection(ns).get(field);
    return entry ? entry.values : [];
}

/**
 * Build a URL for a modified selection, keeping every non-filter parameter of the page.
 *
 * `start` is dropped: changing a filter changes the result set, so page four of the old one is
 * not a place to land. Everything else the page carries — the view, the range, the search text,
 * the sort — is preserved, which is what makes a filter link shareable and the back button
 * correct.
 *
 * @param {Map<string, {values: string[], op: string}>} selection
 */
export function urlFor(selection, ns) {
    const prefix = ns || NS;
    const params = new URLSearchParams(window.location.search);
    for (const key of Array.from(params.keys())) {
        if (new RegExp('^' + prefix + '\\[[A-Za-z0-9_]{1,64}\\]\\[').test(key)) {
            params.delete(key);
        }
    }
    params.delete('start');

    for (const [field, entry] of selection) {
        for (const value of entry.values) {
            params.append(valueKey(field, prefix), value);
        }
        if (entry.op && entry.op !== OP_ANY) {
            params.set(opKey(field, prefix), entry.op);
        }
    }
    return '?' + params.toString();
}

/** The URL with one value toggled on one dimension, keeping its operator. */
export function toggleUrl(field, value, ns) {
    const selection = readSelection(ns);
    const entry = selection.get(field) || { values: [], op: OP_ANY };
    const kept = entry.values.filter((v) => v !== value);

    if (kept.length === entry.values.length) {
        kept.push(value);
    }
    if (kept.length) {
        selection.set(field, { values: kept, op: entry.op });
    } else {
        selection.delete(field);
    }
    return urlFor(selection, ns);
}

/** The URL with one dimension's operator changed. Unchanged when nothing is selected on it. */
export function operatorUrl(field, op, ns) {
    const selection = readSelection(ns);
    const entry = selection.get(field);
    if (!entry) {
        return urlFor(selection, ns);
    }
    selection.set(field, { values: entry.values, op: op });
    return urlFor(selection, ns);
}

/** The URL with one whole dimension cleared. */
export function clearFieldUrl(field, ns) {
    const selection = readSelection(ns);
    selection.delete(field);
    return urlFor(selection, ns);
}

/** The URL with nothing filtered. */
export function clearAllUrl(ns) {
    return urlFor(new Map(), ns);
}

/* -------------------------------------------------------------------------
 * The operator control
 * ---------------------------------------------------------------------- */

/**
 * The per-dimension boolean operator, as a segmented group of real links.
 *
 * Rendered from the server's `operators` list when the payload carries one, because the server
 * is what knows whether the field holds a list and therefore whether "All of" can match at all.
 * Without a payload it falls back to the two operators that are always meaningful, which is
 * what the bridge below uses on markup rendered before this component existed.
 *
 * Returns null when nothing is selected on the dimension: an operator over no values is a
 * control with no subject, and drawing one on every dimension in the panel is noise.
 */
export function operatorControl(group) {
    const field = group && group.field;
    if (!field) {
        return null;
    }
    const ns = group.ns || NS;
    const selected = Array.isArray(group.chosen) ? group.chosen : valuesOf(field, ns);
    if (!selected.length) {
        return null;
    }

    const current = group.op || operatorOf(field, ns);
    const offered = Array.isArray(group.operators) && group.operators.length
        ? group.operators
        : defaultOperators(group, current);

    const buttons = offered.map((entry) => el('a', {
        class: 'facet-op-btn' + (entry.op === current ? ' is-on' : ''),
        href: operatorUrl(field, entry.op, ns),
        title: entry.hint || '',
        'aria-current': entry.op === current ? 'true' : null,
        text: entry.label
    }));

    return el('div', {
        class: 'facet-op',
        role: 'group',
        'aria-label': 'How the selected ' + String(group.label || field).toLowerCase() + ' values combine',
        dataset: { field: field, op: current }
    }, buttons);
}

/**
 * The operators to offer when the server did not say.
 *
 * "All of" is included only when the payload states the dimension holds a list, or when it is
 * already in force — never guessed from the field name. A dimension whose arity is unknown gets
 * the two operators that cannot produce an empty view by construction.
 */
function defaultOperators(group, current) {
    const label = String(group.label || group.field).toLowerCase();
    const out = [
        { op: OP_ANY, label: 'Any of', hint: 'Match traffic carrying ANY selected ' + label + ' value.' }
    ];
    if (group.arity === 'multi' || current === OP_ALL) {
        out.push({ op: OP_ALL, label: 'All of', hint: 'Match only traffic carrying EVERY selected ' + label + ' value.' });
    }
    out.push({ op: OP_NONE, label: 'None of', hint: 'Exclude every selected ' + label + ' value; keep the rest.' });
    return out;
}

/**
 * The sentence saying what this dimension's counts count.
 *
 * Present whenever the server sent one. With exclusions in play the number beside a value is
 * NOT the number of things on the page — it is what that value would match with this
 * dimension's own filter lifted, which is the only count that lets a second value be chosen,
 * and a reader who assumes otherwise is reading a different question than the label asks.
 */
export function basisNote(group) {
    if (!group || !group.basis_note) {
        return null;
    }
    return el('p', { class: 'facet-basis', text: group.basis_note });
}

/* -------------------------------------------------------------------------
 * The inline filter box
 * ---------------------------------------------------------------------- */

/**
 * The box that narrows a dimension's values as the operator types.
 *
 * Added by ONE rule everywhere rather than per view: a dimension with more values on screen
 * than FILTER_AT gets one. It used to appear on three dimensions and not on the rest, which is
 * why country and AS organisation — the two with hundreds of values — were the hardest to use.
 */
export function filterInput(group, shown) {
    const count = shown === undefined ? (group.buckets || []).length : shown;
    if (count < FILTER_AT) {
        return null;
    }
    const id = 'facet-q-' + group.field;
    const label = String(group.label || group.field);

    return el('div', { class: 'facet-search' }, [
        el('label', { class: 'sr-only', for: id, text: 'Filter ' + label + ' values' }),
        el('input', {
            type: 'search',
            id: id,
            class: 'facet-q',
            placeholder: 'Filter ' + label.toLowerCase() + '…',
            autocomplete: 'off',
            spellcheck: 'false',
            dataset: { field: group.field, ns: group.ns || NS }
        })
    ]);
}

/**
 * The control that opens the value browser.
 *
 * Shown when the list is truncated, and it says how much is behind it when the server counted
 * the whole term space. "Show all 897 values" is a reason to press something; "Show all values"
 * on a list of thirteen is not.
 */
export function showAllButton(group) {
    if (!group.truncated && !group.distinct) {
        return null;
    }
    const total = group.distinct && group.distinct > (group.buckets || []).length ? group.distinct : null;

    return el('button', {
        type: 'button',
        class: 'facet-more',
        dataset: { field: group.field, label: String(group.label || group.field), ns: group.ns || NS },
        text: total ? 'Show all ' + num(total) + ' values' : 'Show all values'
    });
}

/**
 * Fetch every value of one dimension, once.
 *
 * Bounded on the server side, not here: a dimension can have tens of thousands of distinct
 * values — a fingerprint, an ASN, a path — and the endpoint returns the most common N of them
 * and says how many there were. The dialog states that rather than pretending the list is
 * complete.
 */
function fetchAll(field) {
    if (fullCache.has(field)) {
        return Promise.resolve(fullCache.get(field));
    }
    if (pending.has(field)) {
        return pending.get(field);
    }

    const request = api('sessions', 'values', { field: field }).then((data) => {
        const group = data && data.group ? data.group : { field: field, buckets: [] };
        fullCache.set(field, group);
        pending.delete(field);
        return group;
    }).catch((err) => {
        pending.delete(field);
        throw err;
    });

    pending.set(field, request);
    return request;
}

/**
 * Search a dimension's values on the SERVER, over every value it has.
 *
 * The listing is capped; this is not. A fingerprint or a path nowhere near the top of its
 * dimension is still findable by typing part of it, which is what makes the search box worth
 * having on exactly the dimensions that needed it most.
 *
 * @returns {Promise<{group: Object, token: number}>}
 */
function searchValues(field, term) {
    searchToken += 1;
    const token = searchToken;

    return api('sessions', 'values', { field: field, vq: term }).then((data) => ({
        group: data && data.group ? data.group : { field: field, buckets: [], searched: true },
        token: token
    }));
}

/**
 * Does the page already hold every value of this dimension?
 *
 * If it does, filtering is a local operation and must stay one: a dimension with twelve values
 * should not make a round trip to narrow twelve values, and the result would be identical. The
 * server search is for the dimensions that exceed what was fetched — which is exactly the case
 * the cached group reports with `truncated`.
 */
function isComplete(group) {
    if (!group) {
        return false;
    }
    if (group.truncated) {
        return false;
    }
    return !group.distinct || group.distinct <= (group.buckets || []).length;
}

/**
 * Run a search after the typing stops, or at once on Enter.
 *
 * One timer per input, held on the element, so two facet boxes cannot cancel each other and a
 * re-rendered card drops its timer with the node.
 */
function debounceSearch(input, run) {
    if (input.lhTimer) {
        window.clearTimeout(input.lhTimer);
    }
    input.lhTimer = window.setTimeout(() => {
        input.lhTimer = null;
        run();
    }, SEARCH_DEBOUNCE_MS);
}

/** Enter means now: cancel the pending debounce and run. */
function runNow(input, run) {
    if (input.lhTimer) {
        window.clearTimeout(input.lhTimer);
        input.lhTimer = null;
    }
    run();
}

/**
 * Warm the full list when the box is focused, so the first keystroke already has everything.
 *
 * The box stays enabled while the request is in flight and text typed meanwhile is applied when
 * it lands. A failure is silent and falls back to filtering the rows already on the page, which
 * is a worse answer but never a broken box.
 */
function onFocus(event) {
    const input = event.target;
    if (!input || !input.classList || !input.classList.contains('facet-q')) {
        return;
    }
    const field = input.dataset.field;
    if (!field || fullCache.has(field)) {
        return;
    }
    input.classList.add('is-loading');
    fetchAll(field).then(() => {
        input.classList.remove('is-loading');
        if (String(input.value || '').trim()) {
            narrow(input);
        }
    }).catch(() => {
        input.classList.remove('is-loading');
    });
}

/** Narrow a dimension's visible values as the operator types, after the typing pauses. */
function onInput(event) {
    const input = event.target;
    if (input && input.classList && input.classList.contains('facet-q')) {
        debounceSearch(input, () => narrow(input));
    }
}

/** Enter searches now, for somebody who types faster than the debounce. */
function onKey(event) {
    const input = event.target;
    if (event.key !== 'Enter' || !input || !input.classList || !input.classList.contains('facet-q')) {
        return;
    }
    event.preventDefault();
    runNow(input, () => narrow(input));
}

/**
 * Apply the typed text to a dimension's list.
 *
 * With the full list cached the <ul> is rebuilt from every matching value, most common first,
 * capped at INLINE_MAX. Without it — still loading, or the fetch failed — the rows already
 * rendered are hidden and shown, which is what the panel did before and is still correct, just
 * narrower. A list narrowed to nothing says so rather than going blank.
 */
function narrow(input) {
    const section = input.closest('.facet');
    if (!section) {
        return;
    }
    const field = input.dataset.field || '';
    const ns = input.dataset.ns || NS;
    const typed = String(input.value || '').trim();
    const needle = typed.toLowerCase();
    const list = section.querySelector('.facet-list');
    if (!list) {
        return;
    }

    stash(list);

    if (typed === '') {
        restore(list);
        for (const li of list.querySelectorAll('.facet-li')) {
            li.hidden = false;
        }
        note(section, '');
        return;
    }

    const full = fullCache.get(field);

    /* The whole dimension is already here: filter it in the page. A round trip to narrow twelve
       values would return the same twelve, slower. */
    if (full && isComplete(full)) {
        rebuild(list, full, needle, ns);
        return;
    }

    /* It is not: the list on screen is the head of a longer one, so filtering locally would
       search the wrong population and report "no match" for values that exist. Ask the server. */
    if (typed.length >= MIN_SEARCH && ns === NS) {
        input.classList.add('is-loading');
        searchValues(field, typed).then(({ group, token }) => {
            input.classList.remove('is-loading');
            if (token !== searchToken || input.value.trim() !== typed) {
                return;
            }
            rebuild(list, group, '', ns);
            note(section, sidebarNote(group.buckets || [], typed, true));
        }).catch(() => {
            input.classList.remove('is-loading');
            localNarrow(section, needle, typed, false);
        });
        return;
    }

    localNarrow(section, needle, typed, full ? isComplete(full) : false);
}

/**
 * Hide and show the rows already rendered.
 *
 * The instant path for a short string, and the fallback when a search fails. It is a worse answer
 * than the server's on a truncated list — it can only find what is on screen — so it is never the
 * FIRST answer for a dimension that has more values than were fetched.
 */
function localNarrow(section, needle, typed, complete) {
    let shown = 0;
    const kept = [];
    for (const li of section.querySelectorAll('.facet-li')) {
        const hay = String(li.dataset.value || li.textContent || '').toLowerCase();
        const hit = needle === '' || hay.indexOf(needle) >= 0;
        li.hidden = !hit;
        if (hit) {
            shown += 1;
            kept.push(li);
        }
    }
    note(section, needle === '' ? '' : sidebarNote(kept, typed === undefined ? needle : typed, complete === true));
}

/**
 * The sidebar's half of the one-message rule.
 *
 * Same reasoning as populationNote() in the dialog: a search that found nothing has to say what it
 * covered, and "no match" over a capped list is not the same statement as "no match" over the whole
 * dimension. Two wordings for one situation is how a reader comes to believe a value does not exist
 * because it was not in the twelve on screen.
 */
function sidebarNote(matches, typed, complete) {
    if (matches.length) {
        return '';
    }
    return searchSentence(0, typed, complete, false);
}

/**
 * THE sentence for "here is what your search covered and what it found".
 *
 * One builder, used by the sidebar box and by the value browser, so the two cannot drift into
 * saying different things about the same search. What it branches on is the POPULATION — was every
 * value of the dimension covered, or only the ones listed — and never on which code ran, because
 * where the filtering happened is not a fact about the reader's data.
 *
 * @param {number}  found     How many values matched.
 * @param {string}  typed     What was searched for.
 * @param {boolean} complete  Did the search cover every value of the dimension?
 * @param {boolean} truncated Were there more matches than were returned?
 */
function searchSentence(found, typed, complete, truncated) {
    const covered = complete
        ? 'Every value of this dimension was searched'
        : 'Only the values listed here were searched';
    const caveat = complete
        ? (truncated && found ? ', and there were more matches than the ' + num(found) + ' shown.' : '.')
        : ' — open the full list to search every value.';

    if (found === 0) {
        return 'No value contains “' + typed + '”. ' + covered + caveat;
    }
    return num(found) + (found === 1 ? ' value contains' : ' values contain') + ' “' + typed + '”. '
        + covered + caveat;
}

/**
 * Replace a list with the matching values out of the full set.
 *
 * Both the stored value and its human label are searched, because a reader typing "declared"
 * is looking for the signal labelled "Declared crawler" and has no reason to know it is stored
 * as `ua_declared_bot`.
 */
function rebuild(list, group, needle, ns) {
    const buckets = group.buckets || [];
    const matches = (needle === '' ? buckets : buckets.filter((bucket) => {
        const value = String(bucket.value || '').toLowerCase();
        const label = String(bucket.label || '').toLowerCase();
        return value.indexOf(needle) >= 0 || label.indexOf(needle) >= 0;
    })).slice(0, INLINE_MAX);

    fill(list, matches.map((bucket) => valueRow(group, bucket, ns)));
    note(list.closest('.facet'), matches.length ? '' : 'No ' + String(group.label || group.field).toLowerCase() + ' value matches “' + needle + '”.');
}

/**
 * Remember a list's server-rendered rows the first time it is narrowed.
 *
 * The nodes are kept, not their markup: they carry the hrefs and the selected states the server
 * built, and re-deriving those from a string is how a restored list starts disagreeing with the
 * one it replaced. Held on the element itself so a card re-render discards them with it.
 */
function stash(list) {
    if (!list.lhRows) {
        list.lhRows = Array.prototype.slice.call(list.children);
    }
}

/** Put the server-rendered rows back, visible, when the box is cleared. */
function restore(list) {
    if (!list.lhRows) {
        return;
    }
    fill(list, list.lhRows);
    for (const li of list.children) {
        li.hidden = false;
    }
}

/** One value of a dimension, as a row in a narrowed list. */
function valueRow(group, bucket, ns) {
    const value = String(bucket.value || '');
    const on = bucket.state === 'on' || bucket.state === 'excluded';

    return el('li', { class: 'facet-li', dataset: { value: value.toLowerCase() } }, [
        el('a', {
            class: 'facet-opt' + (bucket.state === 'on' ? ' is-on' : '') + (bucket.state === 'excluded' ? ' is-excluded' : ''),
            href: toggleUrl(group.field, value, ns),
            title: bucket.why || value
        }, [
            el('span', { class: 'facet-mark', 'aria-hidden': 'true', text: on ? (bucket.state === 'excluded' ? '−' : '✓') : '' }),
            el('span', { class: 'facet-val' + (group.mono ? ' mono' : ''), text: String(bucket.label || value) }),
            el('span', { class: 'facet-n', text: bucket.count === null ? '—' : num(bucket.count) })
        ])
    ]);
}

/** Put a one-line note at the end of a dimension, or clear it. */
function note(section, text) {
    if (!section) {
        return;
    }
    let node = section.querySelector('.facet-empty');
    if (!node) {
        node = el('p', { class: 'facet-note facet-empty', hidden: true });
        section.appendChild(node);
    }
    node.textContent = text;
    node.hidden = text === '';
}

/* -------------------------------------------------------------------------
 * The value browser
 * ---------------------------------------------------------------------- */

/** Open the value browser for a dimension. */
function onShowAll(event) {
    const button = event.target.closest ? event.target.closest('.facet-more') : null;
    if (!button) {
        return;
    }
    event.preventDefault();
    openValueBrowser(button.dataset.field || '', button.dataset.label || '', button.dataset.ns || NS);
}

/**
 * The dialog: search, A–Z index, values grouped under letter headings, staged selection.
 *
 * The pending set starts from whatever the URL already has, so opening the browser on a
 * dimension that is already filtered shows those values selected and lets them be removed here
 * rather than only in the sidebar.
 */
export function openValueBrowser(field, label, ns) {
    if (!field) {
        return;
    }
    openField = field;
    staged = new Set(valuesOf(field, ns));

    const { body, generation } = openDialog(label || field, 'Every value of this dimension, with the traffic behind it.');

    fetchAll(field).then((group) => {
        if (!isCurrent(generation) || openField !== field) {
            return;
        }
        renderBrowser(body, Object.assign({}, group, { label: label || group.label, ns: ns || NS }), generation);
    }).catch((err) => {
        if (isCurrent(generation)) {
            dialogFail(body, err);
        }
    });
}

/** Build the dialog's contents. */
function renderBrowser(body, group, generation) {
    const search = el('input', {
        type: 'search',
        class: 'fb-search',
        id: 'fb-search',
        placeholder: 'Search…',
        autocomplete: 'off',
        spellcheck: 'false'
    });
    const letters = el('nav', { class: 'fb-letters', 'aria-label': 'Jump to a letter' });
    const values = el('div', { class: 'fb-body' });
    const footer = el('div', { class: 'fb-foot' });
    const notes = el('div', { class: 'fb-notes' });

    fill(body, [
        el('div', { class: 'fb-head' }, [
            el('label', { class: 'sr-only', for: 'fb-search', text: 'Search ' + String(group.label) + ' values' }),
            search
        ]),
        letters,
        notes,
        values,
        footer
    ]);

    /* The listing that came back with the dialog, kept so clearing the box restores it without a
       second request. A search REPLACES what is drawn; it does not replace what is held. */
    const listing = group;
    let showing = group;

    const paint = () => {
        drawLetters(letters, showing.buckets || [], showing);
        drawValues(values, showing.buckets || [], showing);
        drawFooter(footer, listing);
        fill(notes, [populationNote(showing, listing), basisNote(listing)]);
    };

    /* Local for a short string or a dimension that is entirely here; the server otherwise. The
       two are not interchangeable: filtering locally over a capped listing reports "no match" for
       values that exist, which is the failure this whole component is about. */
    const draw = () => {
        const typed = String(search.value || '').trim();

        if (typed === '') {
            showing = listing;
            paint();
            return;
        }
        const complete = isComplete(listing);
        if (typed.length < MIN_SEARCH || complete) {
            const needle = typed.toLowerCase();

            /* `searched` says whether EVERY value was covered, not whether the server did the
               covering. Filtering a listing that holds the whole dimension covers every value of
               it, so the note must say so; filtering a capped one does not, and must not. Tying
               this to the code path instead of the population is what made the same search report
               two different things. */
            showing = Object.assign({}, listing, {
                buckets: (listing.buckets || []).filter((bucket) =>
                    String(bucket.value || '').toLowerCase().indexOf(needle) >= 0
                    || String(bucket.label || '').toLowerCase().indexOf(needle) >= 0),
                searched: complete,
                truncated: false,
                local: true,
                search: typed
            });
            paint();
            return;
        }

        search.classList.add('is-loading');
        searchValues(group.field, typed).then((result) => {
            search.classList.remove('is-loading');
            if (!isCurrent(generation) || openField !== group.field || result.token !== searchToken) {
                return;
            }
            showing = Object.assign({ ns: listing.ns, mono: listing.mono, label: listing.label }, result.group);
            paint();
        }).catch((err) => {
            search.classList.remove('is-loading');
            if (isCurrent(generation)) {
                fill(notes, [el('p', { class: 'fb-note', text: 'That search could not be run: ' + err.message })]);
            }
        });
    };

    search.addEventListener('input', () => debounceSearch(search, draw));
    search.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
            event.preventDefault();
            runNow(search, draw);
        }
    });
    values.addEventListener('click', (event) => onPick(event, listing, footer, values));
    letters.addEventListener('click', onJump);

    paint();
    search.focus();
}

/**
 * The one sentence that says what population is on screen, whatever produced it.
 *
 * THERE USED TO BE TWO MESSAGES FOR ONE SITUATION and they said opposite things. A search that
 * matched nothing on the server produced "no value contains X, every value was searched"; the same
 * search matching nothing locally produced the value list's generic "Nothing to show here", which
 * reads as an empty panel rather than as a completed search that found nothing. Which one a reader
 * got depended on where the code ran, which is not a fact about their data.
 *
 * So there is one function, and it branches on the POPULATION searched rather than on the code
 * path. Three states:
 *
 *   no search        the listing, and whether it is capped. Null when it is the whole dimension.
 *   searched: server every value of the dimension was covered.
 *   searched: local  only the values already listed were covered — which is the honest thing to
 *                    say, because on a capped dimension that is genuinely less than everything and
 *                    a reader must not read "no match" as "does not exist".
 *
 * It owns the empty state too. drawValues() renders nothing when there is nothing, because a
 * second message underneath this one is how the two got out of step in the first place.
 */
function populationNote(showing, listing) {
    const term = String(showing.search || '');

    if (!showing.search) {
        const distinct = listing.distinct;
        const listed = (listing.buckets || []).length;
        if (!distinct || distinct <= listed) {
            return null;
        }
        return el('p', {
            class: 'fb-note',
            text: 'Listing the ' + num(listed) + ' most common of ' + num(distinct)
                + ' values in this range. The search box is not limited to these — it searches every value.'
        });
    }

    return el('p', {
        class: 'fb-note',
        text: searchSentence(
            (showing.buckets || []).length,
            term,
            showing.searched === true,
            showing.truncated === true
        )
    });
}

/** Which letter a value is grouped under. Anything not starting A–Z goes to '#'. */
function letterOf(bucket) {
    const text = String(bucket.label || bucket.value || '');
    const first = (text.charAt(0) || '#').toUpperCase();
    return /[A-Z]/.test(first) ? first : '#';
}

/** The A–Z bar: every letter, the empty ones plainly inactive. */
function drawLetters(holder, buckets, group) {
    const present = new Set(buckets.map(letterOf));
    const nodes = [];

    for (const letter of ALPHABET) {
        if (present.has(letter)) {
            nodes.push(el('button', {
                type: 'button',
                class: 'fb-letter',
                dataset: { letter: letter },
                text: letter
            }));
        } else {
            nodes.push(el('span', { class: 'fb-letter is-off', 'aria-hidden': 'true', text: letter }));
        }
    }
    void group;
    fill(holder, nodes);
}

/** The values, grouped under letter headings, in columns. */
function drawValues(holder, buckets, group) {
    if (!buckets.length) {
        /* NOTHING HERE, DELIBERATELY. populationNote() above has already said what was searched and
           that it found nothing. A second message would be a second wording for one situation,
           which is exactly what this replaced. */
        fill(holder, []);
        return;
    }

    const groups = new Map();
    for (const bucket of buckets) {
        const letter = letterOf(bucket);
        if (!groups.has(letter)) {
            groups.set(letter, []);
        }
        groups.get(letter).push(bucket);
    }

    const order = Array.from(groups.keys()).sort((a, b) => {
        if (a === '#') {
            return 1;
        }
        if (b === '#') {
            return -1;
        }
        return a.localeCompare(b);
    });

    const nodes = [];
    for (const letter of order) {
        nodes.push(el('h4', { class: 'fb-letter-head', id: 'fb-letter-' + letter, text: letter }));
        nodes.push(el('div', { class: 'fb-values' }, groups.get(letter).map((bucket) => browserRow(bucket, group))));
    }
    fill(holder, nodes);
}

/**
 * One value in the browser.
 *
 * A real <a href> carrying the URL that results from applying the pending set with this value
 * toggled, recomputed whenever the pending set changes. So a plain click is intercepted and
 * staged, and a middle-click, a copied link or a click with scripting off all still land on a
 * correct page.
 */
function browserRow(bucket, group) {
    const value = String(bucket.value || '');
    const on = staged && staged.has(value);
    const label = String(bucket.label || value);

    return el('div', { class: 'fb-value' + (on ? ' is-on' : ''), dataset: { value: value } }, [
        el('a', {
            href: stagedUrl(group, value),
            title: bucket.why || value,
            'aria-pressed': on ? 'true' : 'false'
        }, [
            el('span', { class: 'fb-mark', 'aria-hidden': 'true', text: on ? '✓' : '' }),
            el('span', { class: 'fb-name' + (group.mono ? ' mono' : ''), text: label }),
            el('span', { class: 'fb-count', text: bucket.count === null ? '' : '(' + num(bucket.count) + ')' })
        ])
    ]);
}

/** The URL for the pending set with one value toggled. */
function stagedUrl(group, value) {
    const ns = group.ns || NS;
    const selection = readSelection(ns);
    const values = new Set(staged || []);

    if (values.has(value)) {
        values.delete(value);
    } else {
        values.add(value);
    }
    if (values.size) {
        selection.set(group.field, { values: Array.from(values), op: operatorOf(group.field, ns) });
    } else {
        selection.delete(group.field);
    }
    return urlFor(selection, ns);
}

/** Toggle a value in the pending set without leaving the dialog. */
function onPick(event, group, footer, values) {
    const row = event.target.closest ? event.target.closest('.fb-value') : null;
    if (!row || event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) {
        return;
    }
    event.preventDefault();

    const value = row.dataset.value || '';
    if (staged.has(value)) {
        staged.delete(value);
    } else {
        staged.add(value);
    }

    for (const node of values.querySelectorAll('.fb-value')) {
        const picked = staged.has(node.dataset.value || '');
        node.classList.toggle('is-on', picked);
        const link = node.querySelector('a');
        const mark = node.querySelector('.fb-mark');
        if (link) {
            link.href = stagedUrl(group, node.dataset.value || '');
            link.setAttribute('aria-pressed', picked ? 'true' : 'false');
        }
        if (mark) {
            mark.textContent = picked ? '✓' : '';
        }
    }
    drawFooter(footer, group);
}

/**
 * The footer: how many are pending, the operator that will apply, and Apply.
 *
 * The operator is offered HERE as well as in the sidebar, because choosing four values and then
 * discovering the operator is somewhere behind the dialog is exactly the trip this control
 * exists to save.
 */
function drawFooter(footer, group) {
    const ns = group.ns || NS;
    const count = staged ? staged.size : 0;
    const selection = readSelection(ns);

    if (count) {
        selection.set(group.field, { values: Array.from(staged), op: operatorOf(group.field, ns) });
    } else {
        selection.delete(group.field);
    }

    const opControl = operatorControl({
        field: group.field,
        label: group.label,
        ns: ns,
        arity: group.arity,
        op: operatorOf(group.field, ns),
        operators: group.operators,
        chosen: Array.from(staged || [])
    });

    fill(footer, [
        el('span', {
            class: 'fb-selected',
            text: count === 0
                ? 'Nothing selected'
                : num(count) + (count === 1 ? ' value selected' : ' values selected')
        }),
        opControl,
        el('a', {
            class: 'fb-apply' + (count ? ' primary' : ' ghost'),
            href: urlFor(selection, ns),
            text: count ? 'Apply' : 'Clear this filter'
        }),
        el('button', { type: 'button', class: 'ghost small fb-cancel', text: 'Cancel' })
    ]);
}

/** Scroll to a letter group. */
function onJump(event) {
    const button = event.target.closest ? event.target.closest('.fb-letter') : null;
    if (!button || !button.dataset.letter) {
        return;
    }
    const target = document.getElementById('fb-letter-' + button.dataset.letter);
    if (target && typeof target.scrollIntoView === 'function') {
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

/** Cancel discards the pending set; the dialog shell owns Escape and the scrim. */
function onCancel(event) {
    if (event.target.closest && event.target.closest('.fb-cancel')) {
        staged = null;
        openField = '';
        closeDialog();
    }
}

/* -------------------------------------------------------------------------
 * Pivots
 * ---------------------------------------------------------------------- */

/**
 * Draw a cross-tabulation.
 *
 * One renderer for every pivot in the panel, for the same reason there is one facet renderer:
 * three hand-written cross-tab tables is three places for the honesty rules below to be forgotten.
 *
 * EVERY CELL IS A LINK, into the view filtered by BOTH dimensions at once. A cross-tab whose cells
 * cannot be opened is a dead end — the whole reason to look at "hosting × likely_bot" is to then go
 * and see those sessions.
 *
 * THE CELLS DO NOT ADD UP TO THE ROW, and the row says so when they do not. The inner facet is
 * limited, so a row of 900 sessions showing three cells totalling 740 is the normal case, and a
 * reader who assumes the three are exhaustive has read a number that was never claimed. The
 * shortfall is printed as its own muted cell rather than left for them to work out.
 *
 * @param {string} id   Card base id, e.g. 'ov-pivot'.
 * @param {Object} data The `pivot` payload, or null when this view has none.
 */
export function renderPivot(id, data) {
    const table = document.getElementById(id + '-table');
    const body = table ? table.querySelector('tbody') : null;
    if (!body) {
        return false;
    }
    if (!data || !Array.isArray(data.rows) || !data.rows.length) {
        return false;
    }

    const rows = data.rows.map((row) => {
        const shortfall = row.count - row.covered;
        const cells = row.cells.map((cell) => el('a', {
            class: 'pivot-cell',
            href: crossUrl(data.outer, row.value, data.inner, cell.value),
            title: 'Show ' + data.outer_label + ' ' + row.label + ' and '
                + data.inner_label + ' ' + cell.label
        }, [
            el('span', { class: 'pivot-cell-label', text: cell.label }),
            el('span', { class: 'pivot-cell-n', text: num(cell.count) })
        ]));

        if (shortfall > 0) {
            cells.push(el('span', {
                class: 'pivot-cell is-rest',
                title: 'Outside the ' + num(row.cells.length) + ' values shown for this row',
                text: num(shortfall) + ' in other values'
            }));
        }

        return el('tr', {}, [
            el('td', { class: 'clip' }, [dimValue(data.outer, row.value, {
                text: data.outer === 'country_s' ? null : row.label,
                title: 'Filter every view to ' + data.outer_label + ': ' + row.label
            })]),
            el('td', { class: 'num mono', text: num(row.count) }),
            el('td', {}, [el('div', { class: 'pivot-cells' }, cells)])
        ]);
    });

    body.replaceChildren(...rows);
    return true;
}

/**
 * The URL filtered by two dimensions at once — a pivot cell's own link.
 *
 * Each dimension keeps the operator it already has, because a cell is an ADDITION to whatever the
 * operator was looking at. Clicking a cell while a dimension is set to "None of" would otherwise
 * silently flip it back to "Any of" and widen the very filter the reader was narrowing.
 */
function crossUrl(outer, outerValue, inner, innerValue) {
    const selection = readSelection();
    for (const [field, value] of [[outer, outerValue], [inner, innerValue]]) {
        const entry = selection.get(field) || { values: [], op: OP_ANY };
        if (entry.values.indexOf(value) < 0) {
            entry.values = entry.values.concat([value]);
        }
        selection.set(field, entry);
    }
    return urlFor(selection);
}

/* -------------------------------------------------------------------------
 * Mounting
 * ---------------------------------------------------------------------- */

/**
 * Give an already-rendered facet list the controls this component adds.
 *
 * A BRIDGE, and it is temporary by design. The facet lists are rendered by assets/js/facets.js,
 * which is being reworked elsewhere; until it calls operatorControl(), filterInput() and
 * showAllButton() itself, this walks the `.facet[data-field]` sections already in the DOM and
 * adds what is missing. It reads the selection from the URL rather than from a payload, so it
 * works on any markup that names its dimension, and it is idempotent: a section that already
 * has a control is left alone, so a re-render cannot produce two.
 *
 * @param {Element|Document} root
 */
export function enhance(root) {
    const scope = root || document;
    for (const section of scope.querySelectorAll('.facet[data-field]')) {
        const field = section.dataset.field;
        if (!field || section.querySelector('.facet-op')) {
            continue;
        }
        const heading = section.querySelector('.facet-head');
        const control = operatorControl({
            field: field,
            label: heading ? heading.textContent : field,
            ns: section.dataset.ns || NS
        });
        if (control && heading && heading.parentNode) {
            heading.parentNode.insertBefore(control, heading.nextSibling);
        }
    }
}

/**
 * Wire the delegated listeners and enhance whatever is already on the page.
 *
 * Four listeners on the document, not one per dimension: a facet list re-rendered by fetch()
 * needs no re-wiring, which is the same reason the rest of the panel delegates. A MutationObserver
 * re-runs the bridge when a card fills in, because the lists arrive after first paint.
 */
export function initFacetControls() {
    document.addEventListener('focusin', onFocus);
    document.addEventListener('input', onInput);
    document.addEventListener('keydown', onKey);
    document.addEventListener('click', onShowAll);
    document.addEventListener('click', onCancel);

    enhance(document);

    if (typeof window.MutationObserver === 'function') {
        let queued = false;
        const observer = new window.MutationObserver(() => {
            if (queued) {
                return;
            }
            queued = true;
            window.setTimeout(() => {
                queued = false;
                enhance(document);
            }, 0);
        });
        observer.observe(document.body, { childList: true, subtree: true });
    }
}
