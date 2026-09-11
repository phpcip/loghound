/*
 * Loghound — one colour per virtual host, derived rather than assigned.
 *
 * A table of mixed traffic from six sites is a wall of near-identical hostnames, and the eye
 * cannot group it. A small coloured dot beside the name fixes that in one glance — but only if
 * the colour is the SAME colour every time. A palette handed out in arrival order, or picked at
 * random, gives a host one colour on this page and another on the next: the reader builds a
 * mental key out of the first screen and every screen after it lies to them, which is worse
 * than no colour at all.
 *
 * So the colour is a pure function of the hostname. FNV-1a over the lower-cased name, modulo
 * the palette. The same host is the same colour on every row, on every page, after every
 * reload, on every machine, in both themes, with no state anywhere and nothing to keep in sync.
 * Two hosts can collide onto one colour — eight slots, and a machine may serve more sites than
 * that — which is why the rule below is not negotiable.
 *
 * THE DOT IS NEVER THE ONLY CARRIER. The hostname is beside it, always, in words. The colour is
 * a grouping aid and not an identifier: it has to be ignorable by a reader who cannot
 * distinguish it, by a reader in high contrast, and by anyone reading a screenshot in
 * greyscale. Nothing anywhere may key off the colour alone.
 *
 * The eight values live in panel.css as --hc-0 … --hc-7, with their own dark-theme set, because
 * a colour that has to work on #ffffff and on #111111 is two colours and only a stylesheet can
 * say so. They are deliberately off the accent's hue, so a dot is never read as a selected
 * state.
 */

'use strict';

import { el } from './core.js';
import { dimValue } from './identity.js';

/** How many swatches panel.css defines. Changing this means changing the stylesheet too. */
export const PALETTE_SIZE = 8;

/**
 * Which swatch a host gets, or -1 when there is no host to colour.
 *
 * FNV-1a, both bytes of every code unit, so an internationalised hostname is spread as evenly
 * as an ASCII one instead of colliding on whatever its low bytes happen to be.
 *
 * @param {string} host
 * @returns {number} 0 … PALETTE_SIZE-1, or -1.
 */
export function hostColorIndex(host) {
    const name = String(host === null || host === undefined ? '' : host).trim().toLowerCase();
    if (name === '') {
        return -1;
    }

    let h = 0x811c9dc5;
    for (let i = 0; i < name.length; i++) {
        const c = name.charCodeAt(i);
        h = Math.imul(h ^ (c & 0xff), 0x01000193) >>> 0;
        h = Math.imul(h ^ (c >>> 8), 0x01000193) >>> 0;
    }

    return h % PALETTE_SIZE;
}

/**
 * The dot itself.
 *
 * `aria-hidden`, because it says nothing a screen reader could use: the name that follows it
 * carries the whole meaning. A host with no name gets no dot rather than a grey one, so an
 * absent value does not look like a ninth site.
 *
 * @param {string} host
 * @returns {HTMLElement|null}
 */
export function hostDot(host) {
    const index = hostColorIndex(host);
    if (index < 0) {
        return null;
    }
    return el('span', { class: 'hostdot hostdot-' + index, 'aria-hidden': 'true' });
}

/**
 * A host, as it should appear in any table or dialog: the dot, then the name as a filter.
 *
 * The name goes through identity.js's dimValue(), so pressing it narrows the whole dashboard to
 * that host exactly as it does everywhere else. This function adds the dot and nothing else —
 * it is deliberately not a second way of rendering a host.
 *
 * @param {string} host
 * @param {Object} [opts] Passed through to dimValue: {mono, title, link}.
 * @returns {HTMLElement}
 */
export function hostCell(host, opts) {
    const name = String(host === null || host === undefined ? '' : host).trim();
    if (name === '') {
        return el('span', { class: 'muted', text: '—' });
    }

    const dot = hostDot(name);
    const parts = [];
    if (dot) {
        parts.push(dot);
    }
    parts.push(dimValue('host_s', name, opts || {}));

    return el('span', { class: 'hostcell' }, parts);
}
