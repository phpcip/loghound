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

/** View slug → initialiser. The only routing the front end does. */
const VIEWS = {
    overview: overview,
    bots: bots,
    fingerprints: fingerprints,
    networks: networks,
    sessions: sessions,
    performance: performance,
    settings: settings
};

/** Boot. */
function start() {
    initTheme();
    initCopyButtons();
    initCharts();

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
