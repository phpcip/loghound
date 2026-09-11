/*
 * Loghound — the CSV export control.
 *
 * WHAT THIS MODULE IS FOR, AND WHAT IT DELIBERATELY IS NOT.
 *
 * The control is a real link, with a real href, rendered by the server through
 * Layout::urlWith() — so the time range, the virtual host and every filter with its operator
 * are already in it, and the export works with scripting switched off. This module exists for
 * the one thing the server could not put in that href: the controls that live only in the page.
 *
 * The population toggle on Top pages, the two scope selects on Performance, the cluster sort and
 * the minimum-IP threshold on Fingerprints, the index picker on the three Opensolr views — none
 * of those touch the URL. A file exported without them would be scoped differently from the
 * table it was taken from, which is the single worst thing an export can be: it looks
 * authoritative, it is named after the view, and nothing on screen can correct it once it has
 * left the product. So the href is recomputed from the live controls immediately before the
 * click completes.
 *
 * Only the parameters the SERVER declared are read. `data-export-carry` on the link is the list
 * Controller::exportTool() put there from the dataset's own `carry` key, so the browser cannot
 * invent a parameter and the server re-validates every one of them against the same allowlist
 * the JSON path uses. An unknown value is dropped there, not trusted here.
 *
 * IT IS A DELEGATED LISTENER ON THE DOCUMENT, and that is required rather than tidy: the panel's
 * CSP is `script-src 'self'` with a hash for one inline import map, so there is no inline handler
 * anywhere in this front end and no element attribute can carry behaviour. One listener also
 * covers links that arrive later — the value browser's export lives inside a dialog that does not
 * exist when the page loads.
 *
 * The click is NOT cancelled and the download is NOT fetched into memory. The response carries
 * `Content-Disposition: attachment`, which every browser handles by saving the file and leaving
 * the page where it is; buffering it through fetch() and a blob URL would undo the streaming the
 * server does and would put a 2,000-row file in the tab's heap for no benefit.
 */

'use strict';

/**
 * The page controls an export link may be told to read, by parameter name.
 *
 * ONE TABLE, HERE, rather than a registration call in each view module. Seven view modules each
 * remembering to publish their own control state is seven places for one of them to forget, and a
 * forgotten one is silent: the file simply comes back scoped to the default with nothing saying
 * so. A selector that matches nothing yields nothing and the server's own default applies, which
 * is the same answer the page is showing in that case.
 *
 * `read` is given the first matching element. It returns a string, or '' for "do not send this".
 */
const LIVE_CONTROLS = {
    /* The index picker on Index analytics, Query analysis and Who is querying. All three
       selects are kept in step by views/opensolr.js and marked ready once populated. */
    core: {
        selector: 'select[data-ready="1"]',
        read: (node) => String(node.value || '')
    },

    /* The humans / all / bots toggle on Overview → Top pages. The pressed button carries the
       value; there is no form control behind it. */
    pop: {
        selector: '[data-card="ov-pages"] .toggle button.on[data-pop]',
        read: (node) => String(node.dataset.pop || '')
    },

    /* Performance: which requests are being measured, and whose. The default is HTML pages
       only, so an export that lost this would hold every static asset's latency. */
    kind: { selector: '#pf-kind', read: (node) => String(node.value || '') },
    who: { selector: '#pf-who', read: (node) => String(node.value || '') },

    /* Fingerprints: which hundred clusters this is. Sessions: the same parameter name, its own
       control, and the two views never coexist. */
    sort: { selector: '#fp-sort, #se-sort', read: (node) => String(node.value || '') },
    min_ips: { selector: '#fp-min', read: (node) => String(node.value || '') },

    /* The session explorer's search box, read live rather than from the URL so an export taken
       after typing and before pressing Search matches what the operator meant. */
    q: { selector: '#se-q', read: (node) => String(node.value || '') },

    /* The value browser writes both of these onto its own link, because the dialog knows which
       dimension it is showing and what was typed into its search box. */
    field: { selector: null, read: () => '' },
    vq: { selector: null, read: () => '' }
};

/**
 * Rebuild one export link's href from the page's live state.
 *
 * The server-rendered href is the base and stays the base: it already carries `v`, `export`, the
 * range, the host and every `f[…]`/`lf[…]` filter with its operator, all of them allowlisted on
 * the way out. This only replaces the declared page parameters, and a parameter whose control is
 * absent or empty is REMOVED rather than sent blank — an empty `pop` is not a population, and
 * letting it through would make the server fall back to its default while the URL implied a
 * choice had been made.
 */
function refresh(link) {
    const carry = String(link.dataset.exportCarry || '').split(',').map((s) => s.trim()).filter(Boolean);
    if (!carry.length) {
        return;
    }

    const base = link.dataset.exportBase || link.getAttribute('href') || '';
    if (!link.dataset.exportBase) {
        link.dataset.exportBase = base;
    }

    const query = base.indexOf('?') >= 0 ? base.slice(base.indexOf('?') + 1) : '';
    const params = new URLSearchParams(query);

    for (const name of carry) {
        const own = link.dataset['exportParam' + name.charAt(0).toUpperCase() + name.slice(1)];
        if (typeof own === 'string') {
            if (own === '') {
                params.delete(name);
            } else {
                params.set(name, own);
            }
            continue;
        }

        const spec = LIVE_CONTROLS[name];
        const node = spec && spec.selector ? document.querySelector(spec.selector) : null;
        const value = node ? spec.read(node) : '';

        if (value === '') {
            params.delete(name);
        } else {
            params.set(name, value);
        }
    }

    link.setAttribute('href', '?' + params.toString());
}

/**
 * Build an export link for a control the server could not render.
 *
 * Used by the value browser, whose card is a dialog: there is no server-side `$tools` slot to
 * put a link in, and the dimension it exports is not known until the dialog opens. The shape,
 * the class and the accessible-name rule are the same ones Controller::exportTool() applies, so
 * the two cannot drift into looking like different controls.
 *
 * The element is built with createElement and textContent rather than through core.js's el(), so
 * this module imports nothing at all: core.js imports THIS one for its side effect, and a cycle
 * between the two would work only by accident of function hoisting.
 *
 * @param {string} view    View slug the export belongs to.
 * @param {string} dataset Export slug declared by that view's exports().
 * @param {string} hint    The whole sentence that names what the file will hold.
 * @param {Object} params  Parameters this link pins itself, e.g. the dimension.
 */
export function exportLink(view, dataset, hint, params) {
    const search = new URLSearchParams(window.location.search);
    search.set('v', view);
    search.set('export', dataset);

    const carry = [];
    for (const name of Object.keys(params || {})) {
        const value = params[name] === null || params[name] === undefined ? '' : String(params[name]);
        carry.push(name);
        if (value === '') {
            search.delete(name);
        } else {
            search.set(name, value);
        }
    }

    const link = document.createElement('a');
    link.className = 'export';
    link.setAttribute('href', '?' + search.toString());
    link.setAttribute('title', hint);
    link.setAttribute('aria-label', hint);
    link.textContent = 'CSV';
    link.dataset.export = dataset;
    link.dataset.exportCarry = carry.join(',');

    for (const name of carry) {
        const value = params[name] === null || params[name] === undefined ? '' : String(params[name]);
        link.dataset['exportParam' + name.charAt(0).toUpperCase() + name.slice(1)] = value;
    }

    return link;
}

/**
 * Wire every export control on the page, present and future.
 *
 * Capture phase, so the href is final before any other listener can act on the click, and the
 * default action then navigates to the URL as rebuilt. `pointerdown` and `keydown` do the same
 * work early, which is what makes a middle-click or a "copy link address" pick up the live scope
 * too — a link people copy is a link people paste into a script.
 */
function install() {
    const handler = (event) => {
        const link = event.target instanceof Element ? event.target.closest('a.export[data-export]') : null;
        if (link) {
            refresh(link);
        }
    };

    document.addEventListener('pointerdown', handler, true);
    document.addEventListener('click', handler, true);
    document.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
            handler(event);
        }
    }, true);
    document.addEventListener('contextmenu', handler, true);
}

/* Installed on evaluation, once. There is no initialiser call from app.js because app.js is not
   this agent's to change, and a control that only works on the views whose module remembered to
   wire it is the defect the delegated listener exists to avoid. */
if (!window.__lhExportWired) {
    window.__lhExportWired = true;
    install();
}
