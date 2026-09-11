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

import { boot, initCopyButtons, initTheme } from './core.js';
import { initCharts } from './charts.js';

import overview from './views/overview.js';
import bots from './views/bots.js';
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

/** View slug → initialiser. The only routing the front end does. */
const VIEWS = {
    overview: overview,
    bots: bots,
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
 */
function start() {
    initTheme();
    initCopyButtons();
    initCharts();
    initBandwidthStrip();
    initHostPicker();

    const slug = document.body.dataset.view || boot.view || 'overview';
    const view = VIEWS[slug];
    if (typeof view === 'function') {
        Promise.resolve(view()).catch((err) => {
            window.console.error('[loghound] view "' + slug + '" failed to initialise:', err);
        });
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
} else {
    start();
}
