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
 *   - a long tail gets a way in: the top twelve, a "show all", and a box that filters the values
 *     themselves — country and AS organisation both have hundreds;
 *   - the heading names the dimension in words a person uses, never a field name.
 *
 * WHAT MOVED OUT, AND WHY. The semantics are not here any more. `?f[field][]=value` plus
 * `f[field][op]=any|all|none` is read, written and applied by src/Panel/Facets.php, and its
 * browser half — the operator control, the inline filter box, the A–Z value browser — is
 * assets/js/facetfilter.js. This file renders a payload and nothing more.
 *
 * THE PARAGRAPH SAYING HOW FILTERS COMBINE IS GONE ON PURPOSE. It used to be the only place the
 * boolean behaviour was stated, which meant a reader had to hold "values within a dimension OR,
 * dimensions AND" in their head while looking at a list somewhere else on the page. The operator
 * is a control on each dimension now, showing its own state, so the prose has nothing left to
 * say. Do not put it back.
 *
 * A VALUE HAS THREE STATES, NOT TWO: chosen, chosen-and-EXCLUDED, and untouched. The middle one
 * is what the "None of" operator produces, and rendering it with a tick would put a selected mark
 * beside a value the operator has just thrown away.
 *
 * Every value is a real <a href>, which is what makes it work with scripting off, middle-clickable
 * into a new tab, bookmarkable and visible in a screenshot. The CSP has no 'unsafe-inline', so
 * there is not an inline handler anywhere in here.
 *
 * The values are untrusted — an AS organisation name is whatever a regional registry holds — and
 * reach the DOM through core.js's el({text}), which is textContent.
 */

'use strict';

import { api, boot, byId, el, fill, num } from './core.js';
import { FILTER_LABELS, dimLabel, dimValue, isFilterable } from './identity.js';
import {
    basisNote,
    blockBasisNote,
    clearFieldUrl,
    commonBasisNote,
    filterInput,
    operatorControl,
    operatorOf,
    readSelection,
    showAllButton,
    toggleUrl,
    urlFor
} from './facetfilter.js';
import { isPathField, pathTail, urlMark } from './url.js';

/** Has the panel-wide dimension list been fetched? One request per page load. */
let loaded = false;

/**
 * Where the operator's shown/hidden choice for the whole panel is kept.
 *
 * ONE KEY, NOT ONE PER VIEW. The panel is a single control that scopes every page at once, so
 * somebody who hid the filters hid the filters — re-deciding it per view would mean the same
 * gesture had to be repeated seven times and would still leave the eighth page disagreeing
 * with the seven before it. The name is in the family responsive.js already uses for the rail
 * (`lh.rail`) and for the accordion (`lh.card.<view>.<id>`).
 */
const PANEL_KEY = 'lh.facets';

/**
 * The width at or above which the panel is a column beside the results.
 *
 * The stylesheet's single mode-switch breakpoint, repeated here because the DEFAULT differs
 * either side of it: a desk screen gets the sidebar, and a phone gets the disclosure closed,
 * because an expanded dimension list on one column puts the first card several screens down.
 */
const DESK = 901;

/**
 * Has the operator asked for the dimension groups?
 *
 * Absent means shown at desk width, which is the default a reader who has never touched the
 * control gets: the panel exists to be used, and it is wanted most immediately after a filter
 * has been applied. Storage throws outright in a private window and with site data blocked,
 * so a refusal falls back to that same default rather than taking the panel away.
 *
 * @returns {boolean}
 */
function panelShown() {
    let stored = null;
    try {
        stored = window.localStorage.getItem(PANEL_KEY);
    } catch (e) {
        void e;
    }
    if (stored === 'shown') {
        return true;
    }
    if (stored === 'hidden') {
        return false;
    }
    return window.innerWidth >= DESK;
}

/**
 * Record the choice. A storage that refuses still leaves the panel working for this page.
 *
 * @param {boolean} shown
 */
function rememberPanel(shown) {
    try {
        window.localStorage.setItem(PANEL_KEY, shown ? 'shown' : 'hidden');
    } catch (e) {
        void e;
    }
}

/**
 * Put the panel's state on its own control, so the words and the ARIA cannot drift apart.
 *
 * @param {HTMLElement} toggle
 * @param {boolean}     shown
 */
function labelToggle(toggle, shown) {
    toggle.setAttribute('aria-expanded', shown ? 'true' : 'false');
    toggle.textContent = shown ? 'Hide filters' : 'Filter by…';

    /* NOT ON A PAGE THAT ALREADY HAS A FILTER RAIL. The session explorer carries its own rail
       with its own show/hide control, so this bar put a SECOND button for the same job three
       inches above the first — two controls, two labels, one thing. The rail wins there
       because it is the one with the counts in it. */
    if (document.getElementById('se-explorer')) {
        toggle.hidden = true;
    }
}

/**
 * Separator for the field/value keys of the active-filter set.
 *
 * A NUL, written as an escape rather than as a literal byte: it cannot occur in a Solr field
 * name or in a facet value, so no pair of values can be made to collide by moving the boundary,
 * and an escape keeps the source file text rather than binary.
 */
const SEP = '\u0000';

/**
 * The active filters, flattened, from the one reader that understands the URL contract.
 *
 * Kept as an export because four views import it. It is now a thin view over
 * facetfilter.readSelection(), so the parsing rules — including the reserved `op` key — live in
 * exactly one place and a hand-edited URL is read the same way by every surface.
 *
 * @returns {Array<{field: string, value: string, op: string}>}
 */
export function activeFilters() {
    const out = [];
    for (const [field, entry] of readSelection()) {
        if (!isFilterable(field)) {
            continue;
        }
        for (const value of entry.values) {
            out.push({ field: field, value: value, op: entry.op });
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

/* -------------------------------------------------------------------------
 * The facet control
 * ---------------------------------------------------------------------- */

/**
 * One value, as a control.
 *
 * THREE STATES. A chosen value carries a tick, `.is-on`, and an href that REMOVES it — so the same
 * gesture selects and deselects. A chosen value under the "None of" operator carries a minus and
 * `.is-excluded` instead, because a tick beside a value the operator has just thrown away would
 * be a lie. An untouched value carries neither.
 *
 * The bar behind the row is proportional to the largest bucket in the group, not to the total,
 * because the question a facet list answers is "which of these dominates" and scaling to the total
 * flattens every list where one value holds most of the traffic.
 *
 * The word on the row comes from the server: a stored value is `likely_human` or
 * `fp_cluster_proxy_fleet`, and the reader gets "Likely human" and "Proxy fleet fingerprint" with
 * the slug still beside it. It goes through identity.js's dimValue() so the mark, the flag and the
 * label are applied in the one place every table cell and dialog uses too.
 *
 * The aria-label carries the whole sentence, because a screen reader gets no bar and no tick.
 *
 * A PATH ROW CARRIES A SECOND CONTROL, and it is a SIBLING of the row rather than a child of it:
 * the whole row is already one <a>, and an anchor inside an anchor is not a thing a browser will
 * render. So the "open the page in a new tab" control sits after it in the <li>, which is also
 * what keeps the two affordances visually distinct — the row filters the dashboard, the little
 * link at the end leaves it.
 */
function option(group, bucket, largest) {
    const count = bucket.count === null || bucket.count === undefined ? null : bucket.count;
    const share = largest > 0 && count !== null ? Math.max(2, Math.round((count / largest) * 100)) : 0;
    const label = dimLabel(group.field);
    const state = bucket.state || 'off';
    const shown = String(bucket.label || bucket.value);
    const path = isPathField(group.field);

    /* A PATH IS SHOWN BY ITS END. Two paths sharing a long prefix are the same string once a
       narrow column has cut the tail off both, so the front goes instead and the segment that
       names the thing survives. `data-lh-full` below carries the whole path: without it
       responsive.js measures a value that now fits, decides nothing was cut, and takes away the
       tooltip that is the only way to read the rest. */
    const text = path ? pathTail(shown) : shown;

    /* A value the server marked unfilterable is a static row, not a link: it has a real count and
       no filter can be built for it, and a link that does nothing when pressed is worse than a row
       that says why. Same treatment as a whole dimension that is not filterable. */

    if (group.filterable === false || state === 'unfilterable') {
        const staticOpt = el('span', { class: 'facet-opt is-static' }, [
            el('span', { class: 'facet-fill', style: 'width:' + share + '%', 'aria-hidden': 'true' }),
            el('span', { class: 'facet-mark', 'aria-hidden': 'true' }),
            el('span', { class: 'facet-val' + (group.mono ? ' mono' : '') }, [
                dimValue(group.field, bucket.value, { text: text, mono: group.mono, link: false })
            ]),
            el('span', { class: 'facet-n', text: count === null ? '\u2014' : num(count) })
        ]);

        if (text !== shown) {
            staticOpt.setAttribute('data-lh-full', shown);
        }

        return el('li', { class: 'facet-li' + (path ? ' facet-li-url' : ''), title: bucket.why || '' }, [
            staticOpt,
            path ? urlMark(bucket.value) : null
        ]);
    }

    const verb = state === 'on'
        ? ' — selected, activate to remove'
        : (state === 'excluded' ? ' — excluded, activate to stop excluding it' : ' — activate to filter to it');

    /* THE ACCESSIBLE NAME KEEPS THE WHOLE PATH. What the column shows may be shortened; what a
       screen reader announces must not be, because there is no tooltip to fall back on. */
    const link = el('a', {
        class: 'facet-opt' + (state === 'on' ? ' is-on' : '') + (state === 'excluded' ? ' is-excluded' : ''),
        href: toggleUrl(group.field, bucket.value, group.ns),
        title: bucket.why || '',
        'aria-label': label + ' ' + shown + ', ' + (count === null ? 'not counted' : num(count) + ' sessions') + verb
    }, [
        el('span', { class: 'facet-fill', style: 'width:' + share + '%', 'aria-hidden': 'true' }),
        el('span', {
            class: 'facet-mark',
            'aria-hidden': 'true',
            text: state === 'on' ? '\u2713' : (state === 'excluded' ? '\u2212' : '')
        }),
        el('span', { class: 'facet-val' + (group.mono ? ' mono' : '') }, [
            dimValue(group.field, bucket.value, { text: text, mono: group.mono, link: false })
        ]),
        el('span', { class: 'facet-n', text: count === null ? '\u2014' : num(count) })
    ]);

    if (text !== shown) {
        link.setAttribute('data-lh-full', shown);
    }

    return el('li', {
        class: 'facet-li' + (path ? ' facet-li-url' : ''),
        dataset: { value: String(bucket.value).toLowerCase() }
    }, [
        link,
        path ? urlMark(bucket.value) : null
    ]);
}

/**
 * The "not reported" row, for a dimension whose field is only sometimes written.
 *
 * A real filter rather than a caption, and it is the clearest thing the new operators bought:
 * everything that is neither true nor false is "None of" over both values. Before there were
 * three operators the row existed as a read-only number with an apology attached, because
 * `?f[field][]=value` could not express an absence at all.
 */
function absentRow(group) {
    const absent = group.absent;
    if (!absent) {
        return null;
    }
    const selection = readSelection(group.ns);
    const on = absent.state === 'on';

    if (on) {
        selection.delete(group.field);
    } else {
        selection.set(group.field, { values: absent.values, op: absent.op });
    }

    return el('li', { class: 'facet-li facet-li-absent' }, [
        el('a', {
            class: 'facet-opt' + (on ? ' is-on' : ''),
            href: urlFor(selection, group.ns),
            title: absent.why
        }, [
            el('span', { class: 'facet-mark', 'aria-hidden': 'true', text: on ? '\u2713' : '' }),
            el('span', { class: 'facet-val muted', text: absent.label }),
            el('span', { class: 'facet-n', text: num(absent.count) })
        ])
    ]);
}

/**
 * One dimension: its name, its operator, its values, and a way into the long tail.
 *
 * The group is a <section> with a rule above it so two dimensions cannot read as one list, and
 * the heading is the dimension's own name in words — "AS organisation", not `as_org_s`.
 *
 * The order is deliberate: the name, then the OPERATOR — visible before the values it governs,
 * because a reader scanning a filtered list needs to know whether it is including or excluding
 * before they read a single count — then the filter box, the values, the way into the long tail,
 * and last the sentence saying what the counts mean.
 *
 * Exported because the session explorer's sidebar and the panel-wide bar must look and behave
 * identically. They used to be two renderers and the sidebar was the one nobody recognised.
 *
 * `common` is the basis sentence every group in this panel shares, when there is one. A group
 * whose own sentence is that one leaves it to the panel to say once; a group that is counted
 * differently keeps it.
 */
export function renderFacetGroup(group, active, max, common) {
    const keys = active || activeKeys();
    const buckets = group.buckets || [];
    const largest = buckets.reduce((acc, bucket) => Math.max(acc, bucket.count || 0), 0);

    const picked = buckets.filter((b) => keys.has(group.field + SEP + b.value));
    const cap = max && max > 0 ? max : buckets.length;
    const head = buckets.slice(0, cap);
    for (const bucket of picked) {
        if (head.indexOf(bucket) < 0) {
            head.push(bucket);
        }
    }

    const list = el('ul', { class: 'facet-list' });
    for (const bucket of head) {
        list.appendChild(option(group, bucket, largest));
    }
    const absent = absentRow(group);
    if (absent) {
        list.appendChild(absent);
    }

    const chosen = picked.length;

    return el('section', {
        class: group.filterable === false ? 'facet is-unfilterable' : 'facet',
        dataset: { field: group.field, ns: group.ns || 'f', op: group.op || operatorOf(group.field, group.ns) }
    }, [
        el('h3', { class: 'facet-head' }, [
            el('span', { class: 'facet-name', text: group.label }),
            chosen ? el('span', { class: 'facet-chosen', text: num(chosen) + ' selected' }) : null,
            chosen ? el('a', { class: 'facet-clear', href: clearFieldUrl(group.field, group.ns), text: 'Clear' }) : null
        ]),
        operatorControl(group),
        filterInput(group, head.length),
        list,
        showAllButton(Object.assign({}, group, { truncated: group.truncated || head.length < buckets.length })),
        basisNote(group, common),

        /* SAID ONCE PER PANEL, NOT ONCE PER DIMENSION. Which dimensions are not yet filterable
           varies; that some of them are not is one fact about the panel, and renderFacetPanel()
           prints it below the groups. The mark on the group itself is what says WHICH — see
           `.facet.is-unfilterable`, and the reader who wants the reason finds it in one place
           rather than reading the same paragraph under four dimensions in a row. */
        null
    ]);
}

/**
 * Render a whole set of dimensions.
 *
 * No prose about how they combine. Each dimension carries its own operator control showing its
 * own state, which is the only place that answer can be read without holding it in your head; the
 * `note` argument is accepted and ignored so a caller that still passes one is harmless.
 */
export function renderFacetPanel(holder, groups, note, max) {
    const keys = activeKeys();
    const list = groups || [];
    const common = commonBasisNote(list);
    const rendered = list.map((group) => renderFacetGroup(group, keys, max, common));
    if (!rendered.length) {
        fill(holder, [el('p', { class: 'muted', text: 'No dimension has a value in this range and filter set.' })]);
        return;
    }
    void note;

    /* THE TWO PANEL-WIDE SENTENCES, EACH SAID ONCE. Both used to be printed inside every group:
       the basis sentence under all of them, and the "not filterable yet" paragraph under each
       dimension that is not. Repeating a statement per column does not make it truer, it makes
       the column list unreadable and the panel look like it is telling you something new each
       time. Which dimensions are the unfilterable ones is on the groups themselves. */
    const unfilterable = list.filter((group) => group && group.filterable === false).length;

    fill(holder, [
        el('div', { class: 'facet-groups' }, rendered),
        blockBasisNote(common),
        unfilterable
            ? el('p', {
                class: 'facet-note facet-note-all',
                text: 'Dimensions with unpressable values are not filterable yet.'
            })
            : null
    ]);
}

/* -------------------------------------------------------------------------
 * The panel
 * ---------------------------------------------------------------------- */

/**
 * Mount the dimension lists as a column of the view.
 *
 * WHAT MOVED OUT OF HERE, AND WHY. This used to build two things: a `.filterbar` of removable
 * chips plus a "Filter by…" button, which was injected into the page toolbar, and the `.fpanel`
 * of dimension lists, which went into the view. The bar half is gone. The top bar now carries
 * exactly four controls — applied filters, duration, hostname, Opensolr resources — and the
 * chips were a fifth thing competing with them for a row that already clipped on the session
 * explorer. What the chips did is done better by the applied-filters dialog, which lists every
 * value on BOTH filter planes and lets them be removed together rather than one reload at a time.
 *
 * The disclosure that opens and closes the lists moved WITH them, into the panel's own head,
 * where it belongs: it governs this column, it is read next to what it governs, and it is not
 * page chrome.
 *
 * THE PANEL'S STATE IS THE OPERATOR'S, NOT THIS FUNCTION'S. It used to be created `hidden` on
 * every single page load with nothing written down, so applying a filter — which reloads the
 * page — made the sidebar vanish at the exact moment the next facet was wanted, and hiding it
 * was forgotten by the next navigation. The state is read from storage here and written on every
 * press, so the panel arrives in the state it was left in.
 */
function mount() {
    const existing = byId('lh-facets-panel');
    if (existing) {
        return existing;
    }
    const view = document.querySelector('.view');
    if (!view) {
        return null;
    }

    const shown = panelShown();
    const toggle = el('button', {
        type: 'button',
        class: 'ghost small',
        id: 'lh-facets-toggle',
        'aria-controls': 'lh-facets-groups'
    });
    const groups = el('div', { class: 'fpanel-groups', id: 'lh-facets-groups', hidden: !shown });
    const panel = el('div', { class: 'fpanel', id: 'lh-facets-panel' }, [
        el('div', { class: 'fpanel-head' }, [toggle]),
        groups
    ]);

    labelToggle(toggle, shown);
    view.insertBefore(panel, view.firstChild);

    toggle.addEventListener('click', () => {
        const open = groups.hidden;
        groups.hidden = !open;
        labelToggle(toggle, open);
        rememberPanel(open);
        if (open && !loaded) {
            load(groups);
        }
    });

    return panel;
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
    /* THE VIEW TRAVELS WITH THE REQUEST. The rail is one shared action, so the server cannot
       otherwise know which page it is being drawn beside — and it was counting all traffic next
       to pages that count a subset, which put 55 Romanian sessions beside an attacks table with
       none of them in it. Panel\Query::viewScope() decides what, if anything, that narrows. */
    api('sessions', 'dimensions', { for: boot.view || '' }).then((data) => {
        renderFacetPanel(panel, data.dimensions);
    }).catch((err) => {
        loaded = false;

        /* A RETRY THAT IS ON SCREEN. `loaded = false` meant a second try was possible — by
           closing the panel and opening it again, which is not a thing any reader would guess.
           The message is still a muted line rather than a banner, because the bar is a control
           and a Solr hiccup populating it must not put an error across a page whose cards work. */
        const again = el('button', { type: 'button', class: 'small', text: 'Try again' });
        again.addEventListener('click', () => {
            again.disabled = true;
            load(panel);
        });
        fill(panel, [
            el('p', { class: 'muted', text: 'The dimension list could not be loaded: ' + err.message }),
            el('div', { class: 'card-error-actions' }, [again])
        ]);
    });
}

/**
 * Wire the filter panel.
 *
 * The behaviour every facet list shares — the inline filter box, the value browser, the operator
 * control — is wired by facetfilter.js's initFacetControls() with delegated listeners on the
 * document, so the session explorer's own rail and this panel get it identically and neither can
 * drift.
 *
 * Safe to call on a page with no `.view` container: it does nothing rather than throwing.
 *
 * THE FETCH FOLLOWS THE STATE, NOT THE PRESS. The dimension lists were lazy-loaded by the
 * toggle's own handler, which was correct while the panel could only ever be opened by a
 * press; a panel that arrives open would have stayed empty for ever. It is asked for here
 * instead, whenever the panel is on screen and has not been fetched yet, so an operator who
 * has just applied a filter sees the value selected in the sidebar with no second gesture.
 * Failure is still stated inside the panel and nowhere else — see load().
 */
export function initFilterPanel() {
    if (!mount()) {
        return;
    }

    const groups = byId('lh-facets-groups');
    if (groups && !groups.hidden && !loaded) {
        load(groups);
    }
}

export { FILTER_LABELS };
