/*
 * Loghound — application entry point.
 *
 * Wires the shared behaviour (theme toggle, copy buttons, chart lifecycle, the top bar) and
 * then hands off to exactly one view module, chosen from a static map keyed on <body data-view>.
 *
 * The map is static and the imports are static on purpose. A dynamic import built from a
 * URL parameter would be a way to ask the browser to fetch an arbitrary path, and the
 * whole point of the panel's CSP is that there is no such mechanism anywhere in it.
 */

'use strict';

import { boot, byId, initCopyButtons, initTheme } from './core.js';
import { initCharts } from './charts.js';
import { initDetail } from './detail.js';
import { initFilterPanel } from './facets.js';
import { initFacetControls } from './facetfilter.js';
import { initSortableTables } from './sorttable.js';
import { initSmartSelects } from './smartselect.js';
import { initTopBar } from './topbar.js';

import overview from './views/overview.js';
import live from './views/live.js';
import sources from './views/sources.js';
import pages from './views/pages.js';
import searches from './views/searches.js';
import engagement from './views/engagement.js';
import rhythm from './views/rhythm.js';
import bots from './views/bots.js';
import attacks from './views/attacks.js';
import fingerprints from './views/fingerprints.js';
import networks from './views/networks.js';
import sessions from './views/sessions.js';
import performance from './views/performance.js';
import settings from './views/settings.js';
import indexes from './views/indexes.js';
import usage from './views/usage.js';
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
    live: live,
    sources: sources,
    pages: pages,
    searches: searches,
    engagement: engagement,
    rhythm: rhythm,
    bots: bots,
    attacks: attacks,
    fingerprints: fingerprints,
    networks: networks,
    sessions: sessions,
    performance: performance,
    settings: settings,
    indexes: indexes,
    usage: usage,
    hosts: hosts
};

/**
 * Send an old deep link to the page its card now lives on.
 *
 * EVERY SECTION USED TO BE AN ANCHOR on one long page, so links to `?v=attacks#atk-patterns-card`
 * exist — in bookmarks, in tickets, in this repository's own documentation. A section is a page
 * now, so that fragment names an element the document no longer contains: the browser would
 * land at the top of whichever page the reader happened to open and nothing would say why.
 *
 * The boot payload carries this view's whole section list, so the card id in the fragment can be
 * matched against it and the reader sent to the page that holds it. A fragment that names a card
 * on THIS page is left alone — it is already right, and replacing the URL would only take the
 * anchor away. A fragment that matches nothing is left alone too: it may belong to something
 * inside a card, and guessing would be worse than doing nothing.
 *
 * `replace` rather than `assign`, so Back goes where the reader came from rather than to a URL
 * that immediately redirects again.
 */
function followLegacyAnchor() {
    const hash = String(window.location.hash || '').replace(/^#/, '');
    if (hash === '') {
        return false;
    }

    const card = hash.replace(/-card$/, '');
    const sections = Array.isArray(boot.sections) ? boot.sections : [];
    const wanted = sections.find((entry) => entry && entry.id === card);
    if (!wanted || wanted.id === boot.section) {
        return false;
    }

    const params = new URLSearchParams(window.location.search);
    params.set('v', String(boot.view || ''));
    params.set('s', String(wanted.slug));
    window.location.replace('?' + params.toString());
    return true;
}

/**
 * Boot.
 *
 * The top bar is initialised on every view rather than by one of them, because it is page
 * furniture that a per-view module could not provide: it says what the numbers on this page are
 * scoped to, and a scope that only appears on the page that happens to own the control is a
 * scope nobody reads. It fails silently for the same reason — it is a control, not a report.
 *
 * The filter panel and the detail dialogs join it on the same reasoning. The panel offers every
 * dimension to filter by, and the dialogs exist because a row that names a network means the
 * same thing on Networks, on Bots and in the session explorer — three views each opening their
 * own dialog is three focus bugs.
 *
 * Smart selects are wired before anything else that renders a control, and they watch the
 * document afterwards, so a select injected by a later fetch is enhanced without its owner
 * knowing this module exists.
 */
function start() {
    if (followLegacyAnchor()) {
        return;
    }

    /* SAYS THAT SCRIPT IS RUNNING, for the handful of stylesheet rules that have a no-script
       fallback to take away — the top bar's own Apply button is the one that matters. Set here
       rather than in theme.js because a page whose module graph failed to load must keep the
       fallback it has. */
    document.documentElement.classList.add('lh-js');

    initTheme();
    initCopyButtons();
    initCharts();
    initSmartSelects();
    initTopBar();
    initHostPicker();
    if (honours('facets')) {
        initFilterPanel();
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
