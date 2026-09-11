/*
 * Loghound — the mark that goes in front of a value.
 *
 * WHY THESE EXIST. A facet list of `human / likely_human / unknown / likely_bot / bot`, or of
 * `Chrome / Safari / Firefox / Edge`, is a column of words that all look alike; the reader
 * parses each one before they can compare them. A small mark in front turns scanning into
 * recognition, which is the whole job of a facet list. They are decoration on a label that is
 * already there — the word never goes away — so a mark that a reader does not recognise costs
 * nothing, and every one of them is `aria-hidden` so a screen reader reads the value once.
 *
 * DRAWN, LOCAL, AND OWNED. Inline SVG built with createElementNS from the table below: no icon
 * font, no sprite file to fetch, no CDN. The panel must work air-gapped with a CSP that allows
 * no outside origin, and an icon set is exactly the kind of dependency that quietly breaks
 * that promise. Country flags are the one exception and they are not images either — they are
 * the regional-indicator codepoints the platform composes itself.
 *
 * NEUTRAL SHAPES, NOT LOGOS. A browser is a window, an operating system is a machine, a
 * network is a rack. This is an MIT repository that ships publicly, and reproducing a vendor's
 * trademarked mark in it would be a licensing problem for everyone who forks it. The shapes
 * read as the CATEGORY, which is what a facet list needs — the word beside the mark is what
 * says which Chrome it is.
 *
 * THE EDITORIAL SYSTEM APPLIES. Flat line work at one weight, 2px-scale geometry, `currentColor`
 * for every stroke so a mark inherits the tone of the text it belongs to and follows both
 * themes with no second palette. There is no colour in this file. The one exception a value
 * may earn is the accent, and it is applied in CSS by the caller's own class — never here.
 *
 * NEVER A PLAUSIBLE GUESS. An unrecognised value gets the dimension's generic mark, and a
 * dimension with no table gets nothing at all. Drawing a Chrome window for a User-Agent the
 * parser could not place would be inventing a fact, which this product does not do anywhere
 * else either.
 *
 * @module icons
 */

'use strict';

const NS = 'http://www.w3.org/2000/svg';

/**
 * The paths, by dimension and then by value.
 *
 * Every path is drawn inside a 16x16 box on a half-pixel grid, so a 1.5px stroke lands on
 * whole device pixels at the size these are used at. `_` is the dimension's fallback.
 *
 * EVERY KEY IS A VALUE ITS PRODUCER CAN ACTUALLY EMIT, and every value a producer can emit
 * that deserves a mark of its own has one. The two are the same defect from opposite sides: a
 * mark for an impossible value is dead weight that implies a category the product does not
 * have, and a missing mark is a real value silently taking the dimension's generic shape — and
 * where that generic shape happens to BE another value's, it draws a fact that is not true.
 * Both had happened here:
 *
 *   - `as_type_s` carried `business`, which Asn::classifyOrg() cannot return, and had no entry
 *     for `unknown`, which is its commonest answer — so an unclassified network was drawn as a
 *     datacentre rack, because that is what the fallback happened to be;
 *   - `device_s` carried `tv`, which Ua::matchDevice() cannot return, and had no entry for
 *     `bot` or `unknown`, both of which it does — and the fallback was the desktop shape, so a
 *     crawler and an unplaceable client were both drawn as somebody at a computer;
 *   - `bot_class_s` carried `human`, `evasive_bot` and `unknown`, none of which Rules::classify()
 *     can return, and was missing six of the eight it can — including `none`, "not automation",
 *     which therefore got the robot;
 *   - `bot_verdict_s` carried `evasive`, which is a population key and not a verdict;
 *   - `ua_bot_cat_s` carried `archive`, and `os_s` carried `iPadOS`.
 *
 * The producers are the authority, and tests/test_icons.php reads them rather than a list kept
 * here: Score\Rules::classify() and VERDICT_ORDER, Enrich\Ua::matchDevice(), Enrich\Asn's type
 * table, Parser::refererType() and Panel\Layout::nav().
 */
const MARKS = {
    bot_verdict_s: {
        human:        ['M8 3.2a2.1 2.1 0 1 1 0 4.2 2.1 2.1 0 0 1 0-4.2Z', 'M3.4 13.6c0-2.6 2.1-4.3 4.6-4.3s4.6 1.7 4.6 4.3'],
        likely_human: ['M8 3.2a2.1 2.1 0 1 1 0 4.2 2.1 2.1 0 0 1 0-4.2Z', 'M3.4 13.6c0-2.6 2.1-4.3 4.6-4.3'],
        unknown:      ['M6 6a2 2 0 1 1 2 2v1.6', 'M8 12.4v.2'],
        likely_bot:   ['M4.5 6.5h7v6h-7z', 'M8 3.2v3.3', 'M6.6 9h.1', 'M9.3 9h.1'],
        bot:          ['M4.5 6.5h7v6h-7z', 'M8 3.2v3.3', 'M6.6 9h.1', 'M9.3 9h.1', 'M2.6 8.6v2.4', 'M13.4 8.6v2.4'],
        _:            ['M6 6a2 2 0 1 1 2 2v1.6', 'M8 12.4v.2'],
    },

    browser_s: {
        Chrome:  ['M2.2 8a5.8 5.8 0 1 1 5.8 5.8A5.8 5.8 0 0 1 2.2 8Z', 'M8 5.6a2.4 2.4 0 1 1 0 4.8 2.4 2.4 0 0 1 0-4.8Z', 'M6.3 6.6 3.2 4.3'],
        Safari:  ['M2.2 8a5.8 5.8 0 1 1 5.8 5.8A5.8 5.8 0 0 1 2.2 8Z', 'm10.4 5.6-1.5 3.3-3.3 1.5 1.5-3.3Z'],
        Firefox: ['M2.2 8a5.8 5.8 0 1 1 5.8 5.8A5.8 5.8 0 0 1 2.2 8Z', 'M5 6.1c1.3-1.8 4-2 5.5-.6', 'M11 8.6c-.3 2-2 3.2-3.7 3.1'],
        Edge:    ['M2.2 8a5.8 5.8 0 1 1 5.8 5.8A5.8 5.8 0 0 1 2.2 8Z', 'M4 9.4h7.6c.3-2.6-1.4-4-3.5-4C6.1 5.4 4.6 6.7 4 9.4Z'],
        Opera:   ['M2.2 8a5.8 5.8 0 1 1 5.8 5.8A5.8 5.8 0 0 1 2.2 8Z', 'M8 4.6c1.3 0 2 1.5 2 3.4s-.7 3.4-2 3.4-2-1.5-2-3.4.7-3.4 2-3.4Z'],
        _:       ['M2.4 3.6h11.2v8.8H2.4z', 'M2.4 6.3h11.2', 'M4.6 4.9h.1', 'M6.6 4.9h.1'],
    },

    os_s: {
        macOS:     ['M4 4.6h8a1.4 1.4 0 0 1 1.4 1.4v4.2A1.4 1.4 0 0 1 12 11.6H4a1.4 1.4 0 0 1-1.4-1.4V6A1.4 1.4 0 0 1 4 4.6Z', 'M6.2 13.4h3.6'],
        Windows:   ['M2.6 4.4 7.4 3.6v3.8H2.6z', 'M8.6 3.4 13.4 2.6v4.8H8.6z', 'M2.6 8.6h4.8v3.8L2.6 11.6z', 'M8.6 8.6h4.8v4.8l-4.8-.8z'],
        Linux:     ['M8 2.6c1.9 0 2.6 1.8 2.6 3.4 0 1.9 1.8 3.3 1.8 5 0 1.4-1.9 2.4-4.4 2.4S3.6 12.4 3.6 11c0-1.7 1.8-3.1 1.8-5 0-1.6.7-3.4 2.6-3.4Z', 'M6.8 6h.1', 'M9.1 6h.1'],
        Android:   ['M4 7.4h8v4.2H4z', 'M5.6 4.4 4.6 3', 'M10.4 4.4 11.4 3', 'M4.9 7.4a3.1 3.1 0 0 1 6.2 0'],
        iOS:       ['M5.4 2.6h5.2a1.4 1.4 0 0 1 1.4 1.4v8a1.4 1.4 0 0 1-1.4 1.4H5.4A1.4 1.4 0 0 1 4 12V4a1.4 1.4 0 0 1 1.4-1.4Z', 'M7 11.6h2'],
        'Windows Phone': ['M5.4 2.6h5.2a1.4 1.4 0 0 1 1.4 1.4v8a1.4 1.4 0 0 1-1.4 1.4H5.4A1.4 1.4 0 0 1 4 12V4a1.4 1.4 0 0 1 1.4-1.4Z', 'M6.4 4.6h3.2'],
        ChromeOS:  ['M2.6 3.6h10.8v6.2H2.6z', 'M1.6 11.6h12.8'],
        _:         ['M3 4.4h10v5.4H3z', 'M5.4 12h5.2', 'M8 9.8V12'],
    },

    device_s: {
        desktop: ['M3 4.4h10v5.4H3z', 'M5.4 12h5.2', 'M8 9.8V12'],
        mobile:  ['M5.4 2.6h5.2a1.4 1.4 0 0 1 1.4 1.4v8a1.4 1.4 0 0 1-1.4 1.4H5.4A1.4 1.4 0 0 1 4 12V4a1.4 1.4 0 0 1 1.4-1.4Z', 'M7 11.6h2'],
        tablet:  ['M4.4 2.6h7.2a1.2 1.2 0 0 1 1.2 1.2v8.4a1.2 1.2 0 0 1-1.2 1.2H4.4a1.2 1.2 0 0 1-1.2-1.2V3.8a1.2 1.2 0 0 1 1.2-1.2Z', 'M7.4 11.8h1.2'],
        bot:     ['M4.5 6.5h7v6h-7z', 'M8 3.2v3.3', 'M6.6 9h.1', 'M9.3 9h.1'],
        unknown: ['M6 6a2 2 0 1 1 2 2v1.6', 'M8 12.4v.2'],
        _:       ['M6 6a2 2 0 1 1 2 2v1.6', 'M8 12.4v.2'],
    },

    as_type_s: {
        hosting: ['M3 3.4h10v3.2H3z', 'M3 9.4h10v3.2H3z', 'M5 5h.1', 'M5 11h.1'],
        isp:     ['M8 12.6v.2', 'M5.6 10.4a3.4 3.4 0 0 1 4.8 0', 'M3.4 8a6.5 6.5 0 0 1 9.2 0'],
        mobile:  ['M5.4 2.6h5.2a1.4 1.4 0 0 1 1.4 1.4v8a1.4 1.4 0 0 1-1.4 1.4H5.4A1.4 1.4 0 0 1 4 12V4a1.4 1.4 0 0 1 1.4-1.4Z', 'M7 11.6h2'],
        vpn:     ['M4.6 7.2h6.8v5.2H4.6z', 'M6.2 7.2V5.4a1.8 1.8 0 0 1 3.6 0v1.8'],
        edu:     ['M8 3 14 6l-6 3-6-3Z', 'M4.6 7.4v3.4c0 1 1.5 1.8 3.4 1.8s3.4-.8 3.4-1.8V7.4'],
        gov:     ['M2.6 6.4 8 3.2l5.4 3.2', 'M4.4 7.4v4.4', 'M8 7.4v4.4', 'M11.6 7.4v4.4', 'M2.6 12.8h10.8'],
        unknown: ['M6 6a2 2 0 1 1 2 2v1.6', 'M8 12.4v.2'],
        _:       ['M6 6a2 2 0 1 1 2 2v1.6', 'M8 12.4v.2'],
    },

    ua_bot_cat_s: {
        search:  ['M7.2 3.4a3.6 3.6 0 1 1 0 7.2 3.6 3.6 0 0 1 0-7.2Z', 'm9.9 9.9 3 3'],
        ai:      ['M5.6 4.4h4.8v7.2H5.6z', 'M8 2.2v2.2', 'M3.4 6.6h2.2', 'M10.4 6.6h2.2', 'M3.4 9.4h2.2', 'M10.4 9.4h2.2'],
        seo:     ['M2.8 11.4 6 8.2l2.4 2.2 4.8-5', 'M10.4 5.4h2.8v2.8'],
        monitor: ['M2.4 8h2.8l1.4-3.6L9.4 12l1.4-4h2.8'],
        social:  ['M6 8a2 2 0 1 1-4 0 2 2 0 0 1 4 0Z', 'M14 4.6a2 2 0 1 1-4 0 2 2 0 0 1 4 0Z', 'M14 11.4a2 2 0 1 1-4 0 2 2 0 0 1 4 0Z', 'm5.8 7 4.4-1.8', 'm5.8 9 4.4 1.8'],
        _:       ['M4.5 6.5h7v6h-7z', 'M8 3.2v3.3', 'M6.6 9h.1', 'M9.3 9h.1'],
    },

    bot_class_s: {
        declared_crawler: ['M7.2 3.4a3.6 3.6 0 1 1 0 7.2 3.6 3.6 0 0 1 0-7.2Z', 'm9.9 9.9 3 3'],
        ai_crawler:       ['M5.6 4.4h4.8v7.2H5.6z', 'M8 2.2v2.2', 'M3.4 6.6h2.2', 'M10.4 6.6h2.2', 'M3.4 9.4h2.2', 'M10.4 9.4h2.2'],
        monitor:          ['M2.4 8h2.8l1.4-3.6L9.4 12l1.4-4h2.8'],
        spoofed_ua:       ['M4.5 6.5h7v6h-7z', 'M8 3.2v3.3', 'm3.4 3.4 9.2 9.2'],
        proxy_fleet:      ['M8 2.6a1.6 1.6 0 1 1 0 3.2 1.6 1.6 0 0 1 0-3.2Z', 'M3 13.4a1.4 1.4 0 1 1 0-2.8 1.4 1.4 0 0 1 0 2.8Z', 'M8 13.4a1.4 1.4 0 1 1 0-2.8 1.4 1.4 0 0 1 0 2.8Z', 'M13 13.4a1.4 1.4 0 1 1 0-2.8 1.4 1.4 0 0 1 0 2.8Z', 'M8 5.8v2', 'M3 10.6 7 8', 'M13 10.6 9 8'],
        headless:         ['M2.4 3.6h11.2v8.8H2.4z', 'M2.4 6.3h11.2', 'M6.2 9.2h3.6'],
        scripted:         ['m6 5.4-3 2.6 3 2.6', 'm10 5.4 3 2.6-3 2.6'],
        none:             ['M8 3.2a2.1 2.1 0 1 1 0 4.2 2.1 2.1 0 0 1 0-4.2Z', 'M3.4 13.6c0-2.6 2.1-4.3 4.6-4.3s4.6 1.7 4.6 4.3'],
        _:                ['M4.5 6.5h7v6h-7z', 'M8 3.2v3.3'],
    },

    /*
     * The panel's own views, for the navigation rail.
     *
     * Keyed by the slug in Panel\Layout::nav(). A rail that is collapsed to icons has no
     * labels left, so each of these has to carry the view on its own: a crowd for who came, a
     * magnifier over a machine for the forensics, a repeated print for the clusters, a stack
     * of racks for the networks, a trail for one visit, a gauge for latency, a set of windows
     * for the hosts, a database for the indexes, a search for the query shapes, an address for
     * who is calling, a meter for the plan, and a control for the settings.
     */
    view: {
        overview:     ['M2.6 12.4V7.2', 'M6.2 12.4V3.6', 'M9.8 12.4V6', 'M13.4 12.4V9'],
        bots:         ['M4.5 6.5h7v6h-7z', 'M8 3.2v3.3', 'M6.6 9h.1', 'M9.3 9h.1', 'M2.6 8.6v2.4', 'M13.4 8.6v2.4'],
        fingerprints: ['M8 2.6c2.6 0 4.6 2 4.6 4.5', 'M3.4 7.1C3.4 4.6 5.4 2.6 8 2.6', 'M5.6 7.4a2.4 2.4 0 0 1 4.8 0v2.2', 'M8 7.6v4.2', 'M5.4 10.6v2', 'M10.6 10.2v2.4'],
        networks:     ['M3 3.4h10v3.2H3z', 'M3 9.4h10v3.2H3z', 'M5 5h.1', 'M5 11h.1'],
        sessions:     ['M4 3.4h8v9.2H4z', 'M6.2 6h3.6', 'M6.2 8.4h3.6', 'M6.2 10.8h2'],
        performance:  ['M2.6 11.4a5.4 5.4 0 1 1 10.8 0', 'm8 11.4 2.6-3.6'],
        hosts:        ['M2.6 3.4h4.8v4.8H2.6z', 'M8.6 3.4h4.8v4.8H8.6z', 'M2.6 9.4h4.8v3.2H2.6z', 'M8.6 9.4h4.8v3.2H8.6z'],
        indexes:      ['M8 2.6c3 0 5.2.8 5.2 1.8S11 6.2 8 6.2 2.8 5.4 2.8 4.4 5 2.6 8 2.6Z', 'M2.8 4.4v7.2c0 1 2.2 1.8 5.2 1.8s5.2-.8 5.2-1.8V4.4', 'M2.8 8c0 1 2.2 1.8 5.2 1.8S13.2 9 13.2 8'],
        queries:      ['M7.2 3.4a3.6 3.6 0 1 1 0 7.2 3.6 3.6 0 0 1 0-7.2Z', 'm9.9 9.9 3 3'],
        callers:      ['M8 12.6v.2', 'M5.6 10.4a3.4 3.4 0 0 1 4.8 0', 'M3.4 8a6.5 6.5 0 0 1 9.2 0'],
        usage:        ['M2.6 11.4a5.4 5.4 0 1 1 10.8 0Z', 'M8 11.4V6.6'],
        settings:     ['M8 5.9a2.1 2.1 0 1 1 0 4.2 2.1 2.1 0 0 1 0-4.2Z', 'M8 2.4v1.6', 'M8 12v1.6', 'M13.6 8H12', 'M4 8H2.4', 'm11.9 4.1-1.1 1.1', 'm5.2 10.8-1.1 1.1', 'm11.9 11.9-1.1-1.1', 'm5.2 5.2-1.1-1.1'],
        _:            ['M2.6 4h10.8v8H2.6z'],
    },

    /* The theme control, which is the one thing in the rail that is not a view. */
    theme: {
        _: ['M8 4.4a3.6 3.6 0 1 1 0 7.2 3.6 3.6 0 0 1 0-7.2Z', 'M8 4.4v7.2a3.6 3.6 0 0 0 0-7.2Z', 'M8 1.8v1.4', 'M8 12.8v1.4', 'M14.2 8h-1.4', 'M3.2 8H1.8'],
    },

    referer_type_s: {
        search: ['M7.2 3.4a3.6 3.6 0 1 1 0 7.2 3.6 3.6 0 0 1 0-7.2Z', 'm9.9 9.9 3 3'],
        social: ['M6 8a2 2 0 1 1-4 0 2 2 0 0 1 4 0Z', 'M14 4.6a2 2 0 1 1-4 0 2 2 0 0 1 4 0Z', 'M14 11.4a2 2 0 1 1-4 0 2 2 0 0 1 4 0Z', 'm5.8 7 4.4-1.8', 'm5.8 9 4.4 1.8'],
        ai:     ['M5.6 4.4h4.8v7.2H5.6z', 'M8 2.2v2.2', 'M3.4 6.6h2.2', 'M10.4 6.6h2.2'],
        direct:   ['M8 13V3.4', 'm4.6 6.8 3.4-3.4 3.4 3.4'],
        internal: ['M5.4 6.2h5a2.4 2.4 0 0 1 0 4.8H6.6', 'm7.2 4 -2 2.2 2 2.2'],
        ad:       ['M3.4 6.6H6l4.4-2.8v8.4L6 9.4H3.4z', 'M12.4 6.2a3 3 0 0 1 0 3.6'],
        link:     ['m6.6 9.4 2.8-2.8', 'M7.4 5.2 8.8 3.8a2.4 2.4 0 0 1 3.4 3.4l-1.4 1.4', 'M8.6 10.8l-1.4 1.4a2.4 2.4 0 0 1-3.4-3.4l1.4-1.4'],
        _:        ['m3.2 8 4-4v2.6h5.6v2.8H7.2V12Z'],
    },
};

/**
 * Values that mean "this is the one to look at", per dimension.
 *
 * The single accent, used once and only where the product's own judgement says something is
 * worth acting on: automation that is hiding, and a consumer browser arriving from a hosting
 * network. Everything else inherits the tone of the text it sits beside.
 */
const LOUD = {
    bot_verdict_s: ['bot', 'likely_bot'],
    bot_class_s: ['proxy_fleet', 'headless', 'spoofed_ua', 'scripted'],
    as_type_s: ['hosting', 'vpn'],
};

/**
 * The mark for one value of one dimension, or null when the dimension has no vocabulary.
 *
 * Returns null rather than a placeholder for a dimension that is not a closed set — an AS
 * organisation, a netname, a path, an address. Those are identifiers, there is no category to
 * recognise, and a mark in front of every one would be texture rather than information.
 *
 * @param {string} field Solr field name, as the panel's filter allowlist spells it.
 * @param {string} value
 * @returns {SVGElement|null}
 */
export function icon(field, value) {
    const table = MARKS[field];
    if (!table) {
        return null;
    }
    const key = String(value === null || value === undefined ? '' : value).trim();
    const paths = table[key] || lookupLoose(field, key) || table._;
    if (!paths) {
        return null;
    }

    const svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('class', 'vicon' + (isLoud(field, key) ? ' vicon-loud' : ''));
    svg.setAttribute('viewBox', '0 0 16 16');
    svg.setAttribute('width', '16');
    svg.setAttribute('height', '16');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '1.5');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');

    for (const d of paths) {
        const path = document.createElementNS(NS, 'path');
        path.setAttribute('d', d);
        svg.appendChild(path);
    }
    return svg;
}

/** Does this dimension have a vocabulary at all? */
export function hasIcons(field) {
    return Object.prototype.hasOwnProperty.call(MARKS, field);
}

/** Lower-cased index per dimension, built on first use. */
const loose = new Map();

/**
 * Match a value that differs from the table's key only in case or separator.
 *
 * The scorer emits `likely_bot`, the User-Agent parser emits `macOS`, and a geolocation feed
 * may send `Mac OS`. One table, written the way the product spells each value, plus a
 * case-and-separator-insensitive second pass. A value that matches neither falls through to
 * the dimension's GENERIC mark — never to another value's, because a Chrome window drawn for
 * a User-Agent nobody could place is an invented fact.
 */
function lookupLoose(field, value) {
    if (!loose.has(field)) {
        const index = new Map();
        for (const key of Object.keys(MARKS[field])) {
            index.set(flatten(key), MARKS[field][key]);
        }
        loose.set(field, index);
    }
    return loose.get(field).get(flatten(value)) || null;
}

/** Case and separators removed, so `Mac OS`, `macos` and `mac_os` are one key. */
function flatten(value) {
    return String(value).toLowerCase().replace(/[\s._-]+/g, '');
}

/** Is this one of the values the product says is worth acting on? */
function isLoud(field, value) {
    const list = LOUD[field];
    return Array.isArray(list) && list.indexOf(value) !== -1;
}
