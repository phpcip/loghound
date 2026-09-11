/*
 * Loghound — application entry point.
 *
 * Wires the shared behaviour (theme toggle, copy buttons, chart lifecycle) and then hands
 * off to exactly one view module, chosen from a static map keyed on <body data-view>.
 *
 * The map is static and the imports are static on purpose. A dynamic import built from a
 * URL parameter would be a way to ask the browser to fetch an arbitrary path, and the
 * whole point of the panel's CSP is that there is no such mechanism anywhere in it.
 */

'use strict';

import { boot, byId, initCopyButtons, initTheme } from './core.js';
import { initCharts } from './charts.js';
import { initDetail } from './detail.js';
import { initFilterBar } from './facets.js';
import { initFacetControls } from './facetfilter.js';
import { initSortableTables } from './sorttable.js';

import overview from './views/overview.js';
import bots from './views/bots.js';
import attacks from './views/attacks.js';
import fingerprints from './views/fingerprints.js';
import networks from './views/networks.js';
import sessions from './views/sessions.js';
import performance from './views/performance.js';
import settings from './views/settings.js';
import indexes from './views/indexes.js';
import queries from './views/queries.js';
import callers from './views/callers.js';
import usage, { initBandwidthStrip } from './views/usage.js';
import hosts, { initHostPicker } from './views/hosts.js';

/**
 * Does the view on this page honour one of the page-toolbar controls?
 *
 * The list is declared in PHP by Controller::toolbar() and travels in the boot payload. It is
 * asked here rather than guessed from the slug so that the server's answer and the browser's
 * behaviour cannot disagree, and so a view added later cannot inherit a control it ignores.
 *
 * An absent list means no controls, matching the PHP default: on a page served without the
 * payload the panel shows the data and leaves out the furniture, rather than offering
 * controls whose effect nothing has confirmed.
 */
function honours(control) {
    const declared = boot.toolbar;
    return Array.isArray(declared) && declared.indexOf(control) !== -1;
}

/** View slug → initialiser. The only routing the front end does. */
const VIEWS = {
    overview: overview,
    bots: bots,
    attacks: attacks,
    fingerprints: fingerprints,
    networks: networks,
    sessions: sessions,
    performance: performance,
    settings: settings,
    indexes: indexes,
    queries: queries,
    callers: callers,
    usage: usage,
    hosts: hosts
};

/**
 * Boot.
 *
 * Two initialisers run on EVERY view rather than on their own page, because both are page
 * furniture that a per-view module could not provide.
 *
 * The bandwidth strip has to be visible wherever the operator happens to be: it is the only
 * quota that cannot be reclaimed by deleting anything, and once it is exceeded the panel
 * itself answers 403, so a warning that only appears on the page nobody visits is no warning
 * at all.
 *
 * The host selector scopes the whole dashboard, so it belongs beside the range picker rather
 * than inside one card. Both insert themselves into the header only when they have something
 * to say — no Opensolr account, or a single virtual host, means no furniture — and both fail
 * silently, because neither is a report.
 *
 * Two more join them for the same reason. The filter bar says which filters are in force and
 * offers every dimension to filter by, and a filtered number that does not say it is filtered
 * is a wrong number on EVERY page, not on the one that happens to own the control. The detail
 * dialogs are registered here rather than per view because a row that names a network means the
 * same thing on Networks, on Bots and in the session explorer, and three views each opening
 * their own dialog is three focus bugs.
 */
function start() {
    initTheme();
    initCopyButtons();
    initCharts();
    initBandwidthStrip();
    initHostPicker();
    if (honours('facets')) {
        initFilterBar();
        initFacetControls();
    }
    initDetail();
    initSortableTables();

    const slug = document.body.dataset.view || boot.view || 'overview';
    const view = VIEWS[slug];
    if (typeof view === 'function') {
        Promise.resolve(view()).catch((err) => {
            window.console.error('[loghound] view "' + slug + '" failed to initialise:', err);
            pageFailed(slug, err);
        });
    }
}

/**
 * Say so, on the page, when a view could not start at all.
 *
 * WHAT THIS REPLACES. The rejection was written to the console and nothing else, so a throw
 * anywhere in a view's init() — before any card had asked for its data — left every card on
 * that page pulsing its loading skeleton forever, with the only evidence of what happened in a
 * devtools panel the operator has no reason to open. "It has been loading for ten minutes" is
 * not a failure mode a dashboard is allowed to have.
 *
 * Each card is taken out of its loading state so nothing is left pretending to be in flight,
 * and the page-level slot carries the one sentence that explains all of them at once. Reload
 * is the way forward: an init that threw has no partial state worth retrying around.
 */
function pageFailed(slug, err) {
    for (const status of document.querySelectorAll('.card-status')) {
        status.hidden = true;
    }
    for (const skel of document.querySelectorAll('.skel-rows')) {
        skel.remove();
    }

    const banner = byId('lh-conn');
    const detail = byId('lh-conn-detail');
    if (!banner || !detail) {
        return;
    }
    const heading = banner.querySelector('strong');
    if (heading) {
        heading.textContent = 'This page could not start.';
    }
    detail.textContent = 'Nothing on it loaded, because the ' + slug + ' view failed before it asked for any data: '
        + String(err && err.message ? err.message : err) + ' Reloading the page is the only way to retry.';
    banner.hidden = false;
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
} else {
    start();
}
