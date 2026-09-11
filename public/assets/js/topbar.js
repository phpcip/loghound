/*
 * Loghound — the sticky top bar.
 *
 * The bar itself is markup from Panel\Layout and works with scripting off: the duration and the
 * hostname are a GET form with a submit button. This module adds the four things that need
 * script and nothing else.
 *
 *   1. **Submit on change.** Choosing a duration navigates, instead of choosing a duration and
 *      then pressing Apply.
 *   2. **The hostname list.** It arrives from a facet, because populating it server-side would
 *      make every page render wait on Solr.
 *   3. **The applied-filters dialog.** What is narrowing this page, listed, with each value
 *      removable. It is the only place in the panel that shows BOTH filter planes at once —
 *      Loghound's own `f[…]` dimensions and the Opensolr request log's `lf[…]` ones — because
 *      a number narrowed on either plane is a narrowed number, and an operator should not have
 *      to know which plane a chip belongs to in order to find it.
 *   4. **The Opensolr resources dialog.** The whole account against the whole plan: indexes
 *      held against the allowance, bandwidth, disk, and how far back each index reaches.
 *
 * WHAT IT REPLACES. A front-end pass used to assemble the bar at runtime by MOVING whatever
 * furniture it found into a strip — the range links, the host selector, the chips, a bandwidth
 * readout — and condensing it on scroll. That produced four different layouts across four pages
 * and one of them clipped. There is one bar, it is rendered by the server, and it is sticky
 * always.
 *
 * Nothing here builds markup from a string. Host names, index names and filter values are all
 * chosen by somebody else, and every one of them reaches the DOM through core.js's el({text}).
 */

'use strict';

import { api, boot, byId, bytes, dec, el, num, when } from './core.js';
import { closeDialog, dialogFail, openDialog } from './dialog.js';

/** The two filter planes, in the order the dialog lists them. */
const PLANES = [
    { ns: 'f', key: 'filters', title: 'Traffic filters' },
    { ns: 'lf', key: 'log_filters', title: 'Search request filters' }
];

/* -------------------------------------------------------------------------
 * The scope form
 * ---------------------------------------------------------------------- */

/**
 * Make the duration and hostname controls navigate on change.
 *
 * A CHANGE IS A SUBMIT, NOT A LOCATION ASSIGNMENT. The form already carries the page's whole
 * state as hidden fields — the section, every filter, the chosen index, the outcome slice — so
 * submitting it is the one path that cannot drop any of them. Building a URL here instead would
 * be a second copy of the rules in Panel\Layout::stateParams(), and the two would disagree the
 * first time one of them learned about a new parameter.
 */
function wireScopeForm() {
    const form = byId('lh-scope-form');
    if (!form) {
        return;
    }

    form.addEventListener('change', (event) => {
        if (event.target && event.target.tagName === 'SELECT') {
            markEmptyFilters(form);
            form.submit();
        }
    });
}

/**
 * Say out loud, on submit, when the form is about to carry no filters at all.
 *
 * THE CASE THIS EXISTS FOR. Choosing "All hosts" submits an empty `f[host_s][]`, which the
 * server's facet reader drops — so the request arrives with no `f[…]` in it, which under
 * Panel\Scope's rule is a request that says NOTHING about filters, and the host that was just
 * cleared would be restored from the session on the very next page load. `fx=1` is how a URL
 * states an empty filter set rather than an absent one.
 *
 * Enabled only when nothing else is filtered, because a form that still carries another
 * dimension is not empty and must not claim to be.
 */
function markEmptyFilters(form) {
    const marker = byId('lh-scope-fx');
    if (!marker) {
        return;
    }

    const value = /^f\[[A-Za-z0-9_]{1,64}\]\[\d*\]$/;
    let any = false;
    for (const field of form.elements) {
        if (field.name && value.test(field.name) && String(field.value) !== '') {
            any = true;
            break;
        }
    }

    marker.disabled = any;
    marker.value = '1';
}

/**
 * Fill the hostname selector from the facet, once it answers.
 *
 * The select is rendered by the server carrying "All hosts" and whichever host is currently
 * chosen, so the form round-trips and the scope is readable before any fetch lands. The rest of
 * the list is added here. A single-host installation gets no list added at all — a selector
 * offering one choice is furniture — and the control is taken off screen instead.
 *
 * Failure is stated on the control and nowhere else. The selector scopes every number on the
 * page, so a multi-site operator who is quietly being shown all hosts at once has to be told
 * that the control they would narrow with is missing; it is still not a report, and it does not
 * take a card's failure state.
 *
 * @param {{host: string, sessions: number}[]} rows
 * @param {boolean} multi
 */
export function fillHosts(rows, multi) {
    const select = byId('lh-host');
    const field = byId('lh-hostfield');
    if (!select) {
        return;
    }
    if (!multi) {
        if (field) {
            field.hidden = true;
        }
        return;
    }

    const chosen = select.value;
    const seen = new Set(Array.prototype.map.call(select.options, (option) => option.value));

    for (const row of rows) {
        if (seen.has(row.host)) {
            const existing = Array.prototype.find.call(select.options, (o) => o.value === row.host);
            if (existing) {
                existing.textContent = row.host + ' (' + num(row.sessions) + ')';
            }
            continue;
        }
        select.appendChild(el('option', {
            value: row.host,
            text: row.host + ' (' + num(row.sessions) + ')'
        }));
    }
    select.value = chosen;
}

/** Say on the control that the host list could not be read, without raising a page banner. */
export function hostsUnavailable(err) {
    const field = byId('lh-hostfield');
    if (!field || byId('lh-hostpick-failed')) {
        return;
    }
    field.appendChild(el('span', {
        class: 'job-meta',
        id: 'lh-hostpick-failed',
        title: String(err && err.message ? err.message : err),
        text: 'list unavailable — these figures cover every host'
    }));
}

/* -------------------------------------------------------------------------
 * The applied-filters dialog
 * ---------------------------------------------------------------------- */

/**
 * The filters in force, as a staged copy the dialog may edit before anything navigates.
 *
 * Read from the boot payload rather than re-parsed out of the URL, because the payload is the
 * SERVER's reading of the query string: it has already dropped a field no schema defines and a
 * value no field could hold, and it carries the spoken label for each value. A second reader
 * here would be a second set of rules, and the dialog would list filters the page is not
 * actually applying.
 *
 * @returns {Array<{ns: string, title: string, field: string, label: string, op: string,
 *                  opLabel: string, values: Array<{value: string, label: string}>}>}
 */
function stage() {
    const out = [];
    for (const plane of PLANES) {
        const payload = boot[plane.key];
        if (!payload || !Array.isArray(payload.dimensions)) {
            continue;
        }
        for (const dim of payload.dimensions) {
            const chosen = Array.isArray(dim.chosen) ? dim.chosen : [];
            out.push({
                ns: plane.ns,
                title: plane.title,
                field: String(dim.field),
                label: String(dim.label || dim.field),
                op: String(dim.op || 'any'),
                opLabel: String(dim.op_label || ''),
                values: (dim.values || []).map((value, i) => ({
                    value: String(value),
                    label: String((chosen[i] && chosen[i].label) || value)
                }))
            });
        }
    }
    return out;
}

/**
 * The URL for a staged filter set, over BOTH namespaces at once.
 *
 * Its own builder rather than facetfilter's urlFor(), which rewrites one namespace and reads
 * the live URL to do it — calling it twice would have the second call re-read a URL the first
 * one never navigated to. Every parameter that is not a filter is kept, so the section, the
 * duration, the chosen index and the sort order all survive Apply.
 *
 * `fx`/`lfx` mark a plane the operator has emptied, so Panel\Scope can tell "no filters" from
 * "this link says nothing about filters" and does not restore what was just removed.
 */
function urlForStage(staged) {
    const params = new URLSearchParams(window.location.search);

    for (const plane of PLANES) {
        for (const key of Array.from(params.keys())) {
            if (new RegExp('^' + plane.ns + '\\[[A-Za-z0-9_]{1,64}\\]\\[').test(key)) {
                params.delete(key);
            }
        }
        params.delete(plane.ns + 'x');
    }
    params.delete('start');

    const used = new Set();
    for (const dim of staged) {
        if (!dim.values.length) {
            continue;
        }
        used.add(dim.ns);
        for (const entry of dim.values) {
            params.append(dim.ns + '[' + dim.field + '][]', entry.value);
        }
        if (dim.op && dim.op !== 'any') {
            params.set(dim.ns + '[' + dim.field + '][op]', dim.op);
        }
    }

    for (const plane of PLANES) {
        if (!used.has(plane.ns) && boot[plane.key]) {
            params.set(plane.ns + 'x', '1');
        }
    }

    return '?' + params.toString();
}

/**
 * Open the dialog that lists every applied filter.
 *
 * REMOVING IS STAGED AND APPLY IS WHAT NAVIGATES. Every other filter control in the panel is a
 * link that reloads the page on press, which is right for a control sitting next to the numbers
 * it changes and wrong inside a modal: an operator taking three filters off would reload three
 * times, and the dialog they were working in would be gone after the first.
 *
 * THREE WAYS OUT, ALL OF THEM LIVE. Close at the bottom, the cross at the top right and Escape
 * all dismiss without applying; Apply navigates. A dialog whose only working exit is the one the
 * author remembered is a trap, and this one is opened from a bar that is on every page.
 */
function openFilters() {
    const staged = stage();
    const dialog = openDialog(
        'Applied filters',
        'Every number on this page counts only the traffic these leave.'
    );
    const body = dialog.body;

    const render = () => {
        const rows = [];
        let planeShown = '';

        for (const dim of staged) {
            if (!dim.values.length) {
                continue;
            }
            if (dim.title !== planeShown) {
                planeShown = dim.title;
                rows.push(el('h3', { class: 'af-plane', text: dim.title }));
            }

            const values = el('ul', { class: 'af-values' });
            for (const entry of dim.values) {
                const drop = el('button', {
                    type: 'button',
                    class: 'af-drop',
                    'aria-label': 'Remove ' + dim.label + ': ' + entry.label
                }, [el('span', { 'aria-hidden': 'true', text: '×' })]);
                drop.addEventListener('click', () => {
                    dim.values = dim.values.filter((v) => v.value !== entry.value);
                    render();
                });
                values.appendChild(el('li', { class: 'af-value' }, [
                    el('span', { class: 'af-value-text', text: entry.label }),
                    drop
                ]));
            }

            rows.push(el('div', { class: 'af-dim' }, [
                el('div', { class: 'af-dim-head' }, [
                    el('span', { class: 'af-dim-name', text: dim.label }),
                    dim.opLabel ? el('span', { class: 'af-dim-op', text: dim.opLabel }) : null
                ]),
                values
            ]));
        }

        if (!rows.length) {
            rows.push(el('p', { class: 'muted', text: 'Nothing is filtered.' }));
        }

        const apply = el('button', { type: 'button', class: 'primary', text: 'Apply' });
        apply.addEventListener('click', () => {
            window.location.href = urlForStage(staged);
        });

        const close = el('button', { type: 'button', class: 'ghost', text: 'Close' });
        close.addEventListener('click', closeDialog);

        rows.push(el('div', { class: 'af-actions' }, [apply, close]));

        body.replaceChildren(...rows.filter(Boolean));
    };

    render();
}

/* -------------------------------------------------------------------------
 * The Opensolr resources dialog
 * ---------------------------------------------------------------------- */

/** A megabyte figure the platform reports, or an em-dash when it has not reported one. */
function mb(value) {
    return value === null || value === undefined ? '—' : bytes(Number(value) * 1024 * 1024);
}

/** A proportion bar. Loud only at a level the operator is meant to act on. */
function meter(percent, level) {
    const width = Math.max(0, Math.min(100, Number(percent) || 0));
    return el('span', { class: 'meter', role: 'img', 'aria-label': dec(width, 1) + '% used' }, [
        el('span', {
            class: 'meter-fill' + (['warn', 'critical', 'blocked'].indexOf(String(level)) >= 0
                ? ' meter-fill-loud'
                : ''),
            style: 'width:' + width + '%'
        })
    ]);
}

/** One labelled figure with its bar, for the account and for each index. */
function quotaRow(label, used, limit, percent, level, note) {
    return el('div', { class: 'res-row' }, [
        el('span', { class: 'res-label', text: label }),
        meter(percent, level),
        el('span', { class: 'res-figure mono', text: used + ' of ' + limit }),
        note ? el('span', { class: 'res-note', text: note }) : null
    ]);
}

/**
 * Draw the account's whole usage.
 *
 * EVERY ABSENT FIGURE IS AN EM-DASH AND NEVER A ZERO. The platform does not always publish the
 * index allowance, and an index that has served nothing this month reports no bandwidth rather
 * than zero bandwidth. Rendering either as 0 would be a number nobody computed — and in the
 * allowance's case it would tell an operator their plan is full when it is not.
 */
function renderResources(body, data) {
    const parts = [];

    if (data.demo_note) {
        body.replaceChildren(el('p', { class: 'muted', text: data.demo_note }));
        return;
    }

    const account = data.account || {};
    if (account.ok && account.limit !== null && account.limit !== undefined) {
        const used = Number(account.used || 0);
        const limit = Number(account.limit);
        parts.push(el('div', { class: 'res-block' }, [
            el('h3', { text: 'Indexes' }),
            quotaRow(
                'Against your plan',
                num(used),
                num(limit) + ' indexes',
                limit > 0 ? (used / limit) * 100 : 0,
                limit > 0 && used >= limit ? 'critical' : 'ok',
                account.room === null || account.room === undefined
                    ? ''
                    : num(account.room) + ' still available'
            )
        ]));
    } else {
        parts.push(el('div', { class: 'res-block' }, [
            el('h3', { text: 'Indexes' }),
            el('p', { class: 'muted', text: account.error
                ? 'The allowance could not be read: ' + account.error
                : 'No allowance was reported. This account holds ' + num(account.held || 0) + '.' })
        ]));
    }

    for (const core of (data.cores || [])) {
        const bw = core.bandwidth || {};
        const window_ = core.window || {};
        const span = core.span || {};
        const block = [el('h3', {}, [
            el('span', { class: 'mono', text: String(core.core) }),
            el('span', { class: 'res-role', text: String(core.role) })
        ])];

        block.push(quotaRow(
            'Bandwidth this month',
            mb(bw.used_mb),
            mb(bw.limit_mb),
            bw.percent,
            bw.level,
            'resets ' + (data.resets_at ? when(data.resets_at, false) : 'on the 1st')
        ));

        block.push(quotaRow(
            'Disk',
            mb(window_.size_mb),
            mb(window_.max_size_mb),
            window_.disk_ratio === null || window_.disk_ratio === undefined
                ? 0
                : Number(window_.disk_ratio) * 100,
            window_.disk_ratio !== null && window_.disk_ratio !== undefined && Number(window_.disk_ratio) >= 1
                ? 'blocked'
                : 'ok',
            window_.estimated ? 'size is projected, not reported' : ''
        ));

        block.push(el('p', { class: 'res-span' }, [
            span.days === null || span.days === undefined
                ? 'Nothing is held in this index yet.'
                : 'Holding ' + dec(span.days, 1) + ' days, from ' + when(span.oldest, false)
                    + ' to ' + when(span.newest, false) + '.'
        ]));

        if (core.blocked && core.blocked.text) {
            block.push(el('p', { class: 'res-blocked', role: 'alert', text: String(core.blocked.text) }));
        }

        parts.push(el('div', { class: 'res-block' }, block));
    }

    if (!(data.cores || []).length) {
        parts.push(el('p', { class: 'muted', text: 'No Opensolr index is configured.' }));
    }

    const close = el('button', { type: 'button', class: 'ghost', text: 'Close' });
    close.addEventListener('click', closeDialog);
    parts.push(el('div', { class: 'af-actions' }, [
        el('a', { class: 'primary', href: '?v=usage', text: 'Open Storage & bandwidth' }),
        close
    ]));

    body.replaceChildren(...parts);
}

/** Open the resources dialog and fetch what it shows. */
function openResources() {
    const dialog = openDialog('Opensolr resources', 'Usage against what the plan allows.');

    api('usage', 'account').then((data) => {
        renderResources(dialog.body, data);
    }).catch((err) => {
        dialogFail(dialog.body, err, openResources);
    });
}

/* -------------------------------------------------------------------------
 * Wiring
 * ---------------------------------------------------------------------- */

/**
 * Wire the bar on every view.
 *
 * Safe on a page that has no bar, and safe on a page whose bar has only some of the controls:
 * each piece checks for its own element and does nothing when it is absent, which is what lets
 * Panel\Layout decide per view what is drawn without this module holding a second list.
 */
export function initTopBar() {
    wireScopeForm();

    const filters = byId('lh-tb-filters');
    if (filters) {
        filters.addEventListener('click', openFilters);
    }

    const resources = byId('lh-tb-resources');
    if (resources) {
        resources.addEventListener('click', openResources);
    }
}
