/*
 * Loghound — facets that look like controls, and the bar that says what is filtered.
 *
 * THE PROBLEM THIS FILE EXISTS TO FIX, twice over.
 *
 * First, the mechanism was there and the UI was not. `?f[field][]=value` has always been parsed
 * by Controller::readFilters() and turned into `fq` clauses that scope every query on every
 * view, and it was offered on exactly one page. A name an operator could read on the Networks
 * page was not something they could act on.
 *
 * Second — and this is the harder failure — the one page that DID offer it was not recognised as
 * offering it. A column headed FILTERS with five lists of `label   count` in body text has no
 * affordance at all: nothing says a row can be pressed, nothing distinguishes a chosen value
 * from an unchosen one, and the counts do not line up so the distribution cannot be read at a
 * glance, which is most of why anybody looks at a facet list. So the rules here are:
 *
 *   - the WHOLE ROW is the target, and it reads as pressable before it is pressed;
 *   - a chosen value is unmistakable ON THE ROW, and choosing it again removes it;
 *   - the count sits in its own right-aligned column, with a proportional bar behind the row so
 *     the shape of the distribution is visible without reading a single number;
 *   - the panel SAYS how the filters combine, because nobody can tell OR from AND by looking;
 *   - a long tail gets a way in: the top twelve, a "show all", and a box that filters the values
 *     themselves — country and AS organisation both have hundreds;
 *   - the heading names the dimension in words a person uses, never a field name.
 *
 * Every value is a real <a href>, which is what makes it work with scripting off, middle-clickable
 * into a new tab, bookmarkable and visible in a screenshot. The CSP has no 'unsafe-inline', so
 * there is not an inline handler anywhere in here.
 *
 * The values are untrusted — an AS organisation name is whatever a regional registry holds — and
 * reach the DOM through core.js's el({text}), which is textContent.
 */

'use strict';

import { api, byId, clear, el, fill, num, urlAddFilter, urlRemoveFilter } from './core.js';
import { FILTER_LABELS, dimLabel, flagNode, isFilterable } from './identity.js';

/** Has the panel-wide dimension list been fetched? One request per page load, on first open. */
let loaded = false;

/** A bucket count above which the value list gets its own search box. */
const SEARCHABLE_AT = 10;

/**
 * Separator for the field/value keys of the active-filter set.
 *
 * A NUL, written as an escape rather than as a literal byte: it cannot occur in a Solr field
 * name or in a facet value, so no pair of values can be made to collide by moving the boundary,
 * and an escape keeps the source file text rather than binary.
 */
const SEP = '\u0000';

/**
 * Read the active filters straight out of the query string.
 *
 * The server's own allowlist is applied again here: a hand-edited URL naming a field the server
 * drops must not grow a chip claiming a filter that is not in force.
 *
 * @returns {Array<{field: string, value: string}>}
 */
export function activeFilters() {
    const out = [];
    const params = new URLSearchParams(window.location.search);
    for (const key of Array.from(params.keys())) {
        const match = /^f\[([A-Za-z0-9_]{1,64})\]\[\]$/.exec(key);
        if (!match || !isFilterable(match[1])) {
            continue;
        }
        for (const value of params.getAll(key)) {
            if (value !== '') {
                out.push({ field: match[1], value: value });
            }
        }
    }
    return out;
}

/** The active set as fast-lookup keys. NUL cannot occur in a field name or a Solr value. */
function activeKeys() {
    const set = new Set();
    for (const filter of activeFilters()) {
        set.add(filter.field + SEP + filter.value);
    }
    return set;
}

/** The URL with every filter removed, for the clear-all control. */
function clearAllUrl() {
    const params = new URLSearchParams(window.location.search);
    for (const key of Array.from(params.keys())) {
        if (/^f\[[A-Za-z0-9_]{1,64}\]\[\]$/.test(key)) {
            params.delete(key);
        }
    }
    params.delete('start');
    return '?' + params.toString();
}

/* -------------------------------------------------------------------------
 * The facet control
 * ---------------------------------------------------------------------- */

/**
 * One value, as a control.
 *
 * A chosen value carries a tick, a filled marker and `.is-on`, and its href REMOVES it — so the
 * same gesture selects and deselects and there is nowhere else to go to undo a choice. The bar
 * behind the row is proportional to the largest bucket in the group, not to the total, because
 * the question a facet list answers is "which of these dominates" and scaling to the total
 * flattens every list where one value holds most of the traffic.
 *
 * The aria-label carries the whole sentence, because a screen reader gets no bar and no tick.
 */
function option(group, bucket, largest, on) {
    const share = largest > 0 ? Math.max(2, Math.round((bucket.count / largest) * 100)) : 0;
    const label = dimLabel(group.field);

    if (group.filterable === false) {
        return el('li', { class: 'facet-li' }, [
            el('span', { class: 'facet-opt is-static' }, [
                el('span', { class: 'facet-fill', style: 'width:' + share + '%', 'aria-hidden': 'true' }),
                el('span', { class: 'facet-mark', 'aria-hidden': 'true' }),
                el('span', { class: 'facet-val' + (group.mono ? ' mono' : '') }, [
                    group.field === 'country_s' ? flagNode(bucket.value) : null,
                    el('span', { text: bucket.value })
                ]),
                el('span', { class: 'facet-n', text: num(bucket.count) })
            ])
        ]);
    }

    return el('li', { class: 'facet-li', dataset: { value: bucket.value.toLowerCase() } }, [
        el('a', {
            class: 'facet-opt' + (on ? ' is-on' : ''),
            href: on ? urlRemoveFilter(group.field, bucket.value) : urlAddFilter(group.field, bucket.value),
            title: on ? 'Remove this filter' : 'Filter every view to ' + label + ': ' + bucket.value,
            'aria-label': label + ' ' + bucket.value + ', ' + num(bucket.count) + ' sessions' +
                (on ? ' — selected, activate to remove' : ' — activate to filter to it')
        }, [
            el('span', { class: 'facet-fill', style: 'width:' + share + '%', 'aria-hidden': 'true' }),
            el('span', { class: 'facet-mark', 'aria-hidden': 'true', text: on ? '✓' : '' }),
            el('span', { class: 'facet-val' + (group.mono ? ' mono' : '') }, [
                group.field === 'country_s' ? flagNode(bucket.value) : null,
                el('span', { text: bucket.value })
            ]),
            el('span', { class: 'facet-n', text: num(bucket.count) })
        ])
    ]);
}

/**
 * One dimension: its name, its values, and a way into the long tail.
 *
 * The group is a <section> with a rule above it so two dimensions cannot read as one list, and
 * the heading is the dimension's own name in words — "AS organisation", not `as_org_s`.
 *
 * Exported because the session explorer's sidebar and the panel-wide bar must look and behave
 * identically. They used to be two renderers and the sidebar was the one nobody recognised.
 */
export function renderFacetGroup(group, active, max) {
    const keys = active || activeKeys();
    const largest = group.buckets.reduce((acc, bucket) => Math.max(acc, bucket.count), 0);

    const picked = group.buckets.filter((b) => keys.has(group.field + SEP + b.value));
    const cap = max && max > 0 ? max : group.buckets.length;
    const head = group.buckets.slice(0, cap);
    for (const bucket of picked) {
        if (head.indexOf(bucket) < 0) {
            head.push(bucket);
        }
    }

    const list = el('ul', { class: 'facet-list' });
    for (const bucket of head) {
        list.appendChild(option(group, bucket, largest, keys.has(group.field + SEP + bucket.value)));
    }

    const more = group.truncated || head.length < group.buckets.length;
    const chosen = picked.length;

    const section = el('section', { class: 'facet', dataset: { field: group.field } }, [
        el('h3', { class: 'facet-head' }, [
            el('span', { class: 'facet-name', text: group.label }),
            chosen ? el('span', { class: 'facet-chosen', text: num(chosen) + ' selected' }) : null
        ]),
        searchBox(group, head.length),
        list,
        more
            ? el('button', {
                type: 'button',
                class: 'facet-more',
                dataset: { field: group.field },
                text: 'Show all values'
            })
            : null,
        group.filterable === false
            ? el('p', {
                class: 'facet-note',
                text: 'Shown as a distribution only: this dimension is not in the panel\'s filter allowlist yet, ' +
                    'so its values cannot be pressed.'
            })
            : null
    ]);

    return section;
}

/**
 * The box that filters a long value list, added only when there is a list long enough to need it.
 *
 * It filters what has already been fetched rather than issuing a query per keystroke. Solr's JSON
 * facet has a `contains` option and it is deliberately not on this panel's allowlist of facet
 * keys — adding one for a search box that works perfectly well over two hundred rows already in
 * the DOM would be a new sanitiser surface bought for nothing.
 */
function searchBox(group, shown) {
    if ((shown === undefined ? group.buckets.length : shown) < SEARCHABLE_AT) {
        return null;
    }
    const id = 'facet-q-' + group.field;
    return el('div', { class: 'facet-search' }, [
        el('label', { class: 'sr-only', for: id, text: 'Filter ' + group.label + ' values' }),
        el('input', {
            type: 'search',
            id: id,
            class: 'facet-q',
            placeholder: 'Filter ' + String(group.label).toLowerCase() + '…',
            autocomplete: 'off',
            spellcheck: 'false',
            dataset: { field: group.field }
        })
    ]);
}

/**
 * Render a whole set of dimensions, with the sentence that says how they combine.
 *
 * The sentence is not decoration. filterFqs() ORs the values within one field and ANDs the fields
 * together, which is the right behaviour and completely invisible — two countries widens the
 * result, a country plus a browser narrows it — and a reader who assumes the opposite reads every
 * number wrongly.
 */
export function renderFacetPanel(holder, groups, note, max) {
    const keys = activeKeys();
    const rendered = (groups || []).map((group) => renderFacetGroup(group, keys, max));
    if (!rendered.length) {
        fill(holder, [el('p', { class: 'muted', text: 'No dimension has a value in this range and filter set.' })]);
        return;
    }
    fill(holder, [
        note ? el('p', { class: 'facet-how', text: note }) : null,
        el('div', { class: 'facet-groups' }, rendered)
    ]);
}

/* -------------------------------------------------------------------------
 * Behaviour shared by every facet list on the page
 * ---------------------------------------------------------------------- */

/**
 * Filter a group's visible values as the operator types.
 *
 * Case-insensitive substring over the value, which is what somebody typing "telefon" into a list
 * of six hundred AS organisations means. A group filtered to nothing says so rather than going
 * blank.
 */
function onSearch(event) {
    const input = event.target;
    if (!input || !input.classList || !input.classList.contains('facet-q')) {
        return;
    }
    const section = input.closest('.facet');
    if (!section) {
        return;
    }
    const needle = String(input.value || '').trim().toLowerCase();
    let shown = 0;
    for (const li of section.querySelectorAll('.facet-li')) {
        const hit = needle === '' || String(li.dataset.value || '').indexOf(needle) >= 0;
        li.hidden = !hit;
        if (hit) {
            shown += 1;
        }
    }
    let empty = section.querySelector('.facet-empty');
    if (!empty) {
        empty = el('p', { class: 'facet-note facet-empty', hidden: true });
        section.appendChild(empty);
    }
    empty.textContent = 'No value here matches “' + needle + '”.';
    empty.hidden = shown > 0;
}

/**
 * Replace a group's top-twelve list with everything there is.
 *
 * One request per dimension, on demand. The button reports what happened rather than silently
 * doing nothing when the request fails: a control that looks broken is worse than one that says
 * it is.
 */
async function onShowAll(event) {
    const button = event.target.closest('.facet-more');
    if (!button) {
        return;
    }
    event.preventDefault();
    const section = button.closest('.facet');
    const field = button.dataset.field;
    if (!section || !field) {
        return;
    }

    button.disabled = true;
    const original = button.textContent;
    button.textContent = 'Loading every value…';

    try {
        const data = await api('sessions', 'values', { field: field });
        if (!data.group) {
            button.textContent = 'No further values';
            return;
        }
        const fresh = renderFacetGroup(Object.assign({}, data.group, { truncated: false }), activeKeys());
        section.replaceWith(fresh);
        const input = fresh.querySelector('.facet-q');
        if (input) {
            input.focus();
        }
    } catch (err) {
        button.disabled = false;
        button.textContent = original;
        let note = section.querySelector('.facet-note');
        if (!note) {
            note = el('p', { class: 'facet-note' });
            section.appendChild(note);
        }
        note.textContent = 'The full list could not be loaded: ' + err.message;
    }
}

/* -------------------------------------------------------------------------
 * The page-wide bar
 * ---------------------------------------------------------------------- */

/**
 * One removable chip per active filter, with the count the filter produced.
 *
 * The whole chip is the removal link, which is what the session explorer's chips already did, so
 * there is one gesture to learn rather than two. The count is filled in once the matched total
 * is known; until then the chip is still correct, it just does not yet say how much it removed.
 */
function chip(filter) {
    return el('a', {
        class: 'fchip',
        href: urlRemoveFilter(filter.field, filter.value),
        title: 'Remove this filter'
    }, [
        el('span', { class: 'fchip-dim', text: dimLabel(filter.field) }),
        filter.field === 'country_s' ? flagNode(filter.value) : null,
        el('span', { class: 'fchip-val', text: filter.value }),
        el('span', { class: 'fchip-x', 'aria-hidden': 'true', text: '×' })
    ]);
}

/**
 * The active-filter row.
 *
 * Absent when nothing is filtered, because a strip saying "no filters" on every page is noise.
 * Present, it states in words that every number on the page is scoped — a filtered number that
 * does not say it is filtered is a wrong number, and this is drawn from the URL with no request
 * at all so it is on screen before any card has a number in it.
 */
function renderActive(holder) {
    const filters = activeFilters();
    if (!filters.length) {
        clear(holder);
        holder.hidden = true;
        return;
    }
    const fields = new Set(filters.map((f) => f.field));
    holder.hidden = false;
    fill(holder, [
        el('span', { class: 'filterbar-label', text: 'Filtered by' }),
        ...filters.map(chip),
        el('a', { class: 'filterbar-clear', href: clearAllUrl(), text: 'Clear all' }),
        el('span', {
            class: 'filterbar-note',
            text: 'Every number on this page counts only the traffic matching ' +
                (filters.length === 1
                    ? 'this filter.'
                    : (fields.size === 1
                        ? 'any of these ' + filters.length + ' values.'
                        : 'all ' + fields.size + ' of these dimensions at once — values within one dimension ' +
                          'match if any of them do.'))
        })
    ]);
}

/**
 * Mount the bar as the first child of the view.
 *
 * Created here rather than emitted by each view's body() for the same reason the host selector
 * and the bandwidth strip are: it belongs on every page, and a control that seven view files
 * each have to remember to render is one that will be missing from the eighth.
 */
function mount() {
    const existing = byId('lh-filters');
    if (existing) {
        return existing;
    }
    const view = document.querySelector('.view');
    if (!view) {
        return null;
    }

    const active = el('div', { class: 'filterbar-active', id: 'lh-filters-active', hidden: true });
    const toggle = el('button', {
        type: 'button',
        class: 'ghost small',
        id: 'lh-facets-toggle',
        'aria-expanded': 'false',
        'aria-controls': 'lh-facets-panel',
        text: 'Filter by…'
    });
    const panel = el('div', { class: 'fpanel', id: 'lh-facets-panel', hidden: true });

    const bar = el('div', { class: 'filterbar', id: 'lh-filters' }, [
        active,
        el('div', { class: 'filterbar-tools' }, [toggle]),
        panel
    ]);

    view.insertBefore(bar, view.firstChild);

    toggle.addEventListener('click', () => {
        const open = panel.hidden;
        panel.hidden = !open;
        toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        toggle.textContent = open ? 'Hide filters' : 'Filter by…';
        if (open && !loaded) {
            load(panel);
        }
    });

    return bar;
}

/**
 * Fetch the dimension lists once.
 *
 * Failure is stated in the panel and nowhere else: the bar is a control, so a Solr hiccup while
 * populating it must not put an error banner across a page whose cards are working.
 */
function load(panel) {
    loaded = true;
    fill(panel, [el('p', { class: 'muted', text: 'Counting values for every dimension…' })]);
    api('sessions', 'dimensions').then((data) => {
        renderFacetPanel(panel, data.dimensions, data.multi);
    }).catch((err) => {
        loaded = false;
        fill(panel, [el('p', { class: 'muted', text: 'The dimension list could not be loaded: ' + err.message })]);
    });
}

/**
 * Wire the filter bar and the behaviour every facet list on the page shares.
 *
 * The two delegated listeners cover the sidebar as well as the bar, so the session explorer gets
 * "show all" and value search for free and cannot drift from this file.
 *
 * Safe to call on a page with no `.view` container: it does nothing rather than throwing.
 */
export function initFilterBar() {
    document.addEventListener('input', onSearch);
    document.addEventListener('click', onShowAll);

    const bar = mount();
    if (!bar) {
        return;
    }
    renderActive(byId('lh-filters-active'));
}

export { FILTER_LABELS };
