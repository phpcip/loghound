/*
 * Loghound — who a visitor is, rendered consistently wherever they appear.
 *
 * Three jobs, all of them about making the same fact look and behave the same on every view:
 *
 *   1. FLAGS. A country code renders with its flag and no network request of any kind. The
 *      regional-indicator codepoints compose into a flag in the font, so there is no image,
 *      no sprite sheet and no third-party asset — which matters because the panel must work
 *      air-gapped and its CSP allows no outside origin. A platform that does not compose them
 *      (Windows ships no country-flag glyphs) is detected once and gets the plain two-letter
 *      code instead of two letter-boxes.
 *
 *   2. THE VALUE IS THE CONTROL. Every value on screen that names a dimension Loghound can
 *      filter on is rendered as a link that filters the whole dashboard to it. No separate
 *      panel to go and find, no retyping a value that is already in front of you. It is a
 *      real <a href> and not a click handler, so it works with JavaScript off, it can be
 *      middle-clicked into a new tab, and the resulting state is in the URL where it can be
 *      bookmarked and screenshotted.
 *
 *   3. PARSED FACTS, NOT THE RAW STRING. A User-Agent in a list column is a truncated
 *      sausage that tells the reader nothing, and three identical ones tell them less. The
 *      parser already produced browser_s, browser_ver_i, os_s, device_s, ua_bot_name_s and
 *      ua_bot_cat_s at ingest; those are what a table shows. The raw string belongs in the
 *      detail dialog, where somebody who wants it can read all of it.
 *
 * TRUST. An AS organisation name is whatever a regional registry holds, a netname is whatever
 * the netblock's owner typed, and a path is whatever the client asked for. Every value here
 * reaches the DOM through core.js's el({text}), which is textContent, and into a URL through
 * encodeURIComponent. Nothing is interpolated into markup.
 */

'use strict';

import { el, num, urlAddFilter } from './core.js';
import { countryName } from './geo.js';

/**
 * Field → label, mirroring Panel\Query::filterFields() exactly.
 *
 * THIS LIST IS THE FILTERABLE SET. A dimension that is not here cannot be filtered on,
 * because Controller::readFilters() drops any field the server-side allowlist does not
 * carry — so rendering a link for one would produce a control that silently does nothing.
 * dimValue() therefore falls back to plain text for anything absent, and the gap is reported
 * rather than worked around. Absent today and needed: `ua_bot_name_s`, `city_s`, `region_s`,
 * `asn_i` and `paths_ss`. They are rendered as text until Query.php carries them.
 */
export const FILTER_LABELS = {
    host_s: 'Virtual host',
    bot_verdict_s: 'Verdict',
    bot_class_s: 'Bot class',
    as_type_s: 'Network type',
    country_s: 'Country',
    browser_s: 'Browser',
    os_s: 'OS',
    device_s: 'Device',
    ua_bot_cat_s: 'Declared bot category',
    referer_type_s: 'Referrer type',
    bot_reasons_ss: 'Signal fired',
    as_org_s: 'AS organisation',
    netname_s: 'Netname',
    fp_hash_s: 'Fingerprint',
    ip_s: 'IP',
    session_id_s: 'Session',
    sec_ch_ua_s: 'Client hints (Sec-CH-UA)',
    sec_ch_platform_s: 'Client platform',
    tls_proto_s: 'TLS version'
};

/** Is this dimension one the dashboard can actually be filtered by? */
export function isFilterable(field) {
    return Object.prototype.hasOwnProperty.call(FILTER_LABELS, String(field));
}

/** The human label for a dimension, falling back to the field name. */
export function dimLabel(field) {
    return FILTER_LABELS[String(field)] || String(field);
}

/* -------------------------------------------------------------------------
 * Flags
 * ---------------------------------------------------------------------- */

/** Cached answer from the one-time composition probe. */
let composes = null;

/**
 * Does this platform compose a regional-indicator pair into a single flag glyph?
 *
 * Measured rather than sniffed: a composed pair is ONE glyph and is therefore narrower than
 * two separate indicator letters, while a platform with no flag coverage draws two
 * letter-boxes and comes out at full width. Canvas text measurement needs no network and no
 * DOM insertion.
 *
 * Any failure — no canvas, a hardened browser, a throw — answers false, because the plain
 * two-letter code is always readable and a broken glyph is not.
 */
export function flagsSupported() {
    if (composes !== null) {
        return composes;
    }
    composes = false;
    try {
        const ctx = document.createElement('canvas').getContext('2d');
        if (!ctx) {
            return composes;
        }
        ctx.font = '32px sans-serif';
        const one = ctx.measureText('🇩').width;
        const pair = ctx.measureText('🇩🇪').width;
        composes = one > 0 && pair > 0 && pair < (one * 2) - 1;
    } catch (e) {
        composes = false;
    }
    return composes;
}

/** The flag glyph for an ISO 3166-1 alpha-2 code, or '' when the code is not one. */
export function flagEmoji(code) {
    const cc = String(code || '').trim().toUpperCase();
    if (!/^[A-Z]{2}$/.test(cc)) {
        return '';
    }
    return String.fromCodePoint(
        0x1F1E6 + cc.charCodeAt(0) - 65,
        0x1F1E6 + cc.charCodeAt(1) - 65
    );
}

/**
 * The flag as a decorative node, or null when there is nothing honest to draw.
 *
 * role="img" with the country's name as the label, because a screen reader announcing two
 * regional indicator characters is noise. The code or name always appears beside it as real
 * text, so the flag is never the only carrier of the fact.
 */
export function flagNode(code) {
    const cc = String(code || '').trim().toUpperCase();
    if (!/^[A-Z]{2}$/.test(cc) || !flagsSupported()) {
        return null;
    }
    return el('span', {
        class: 'flag',
        role: 'img',
        'aria-label': countryName(cc) || cc,
        text: flagEmoji(cc)
    });
}

/* -------------------------------------------------------------------------
 * The value as a control
 * ---------------------------------------------------------------------- */

/**
 * Render one dimension value as the control that filters the dashboard to it.
 *
 * A filterable field becomes an <a> carrying `f[field][]=value` on top of the current URL,
 * so the existing server-side mechanism does all the work and the selection lands in the
 * URL. A field the allowlist does not carry becomes plain text — a link that cannot filter
 * is a lie about what clicking it will do.
 *
 * @param {string} field  Solr field name.
 * @param {string} value  The value, exactly as it came back from Solr.
 * @param {Object} [opts] {text, mono, title, count}
 */
export function dimValue(field, value, opts) {
    const options = opts || {};
    const raw = value === null || value === undefined ? '' : String(value);
    const text = options.text === undefined || options.text === null ? raw : String(options.text);

    if (raw === '') {
        return el('span', { class: 'muted', text: '—' });
    }

    const classes = ['dim'];
    if (options.mono) {
        classes.push('mono');
    }

    if (!isFilterable(field)) {
        return el('span', { class: options.mono ? 'mono' : null, title: options.title || raw, text: text });
    }

    const node = el('a', {
        class: classes.join(' '),
        href: urlAddFilter(field, raw),
        title: options.title || ('Filter every view to ' + dimLabel(field) + ': ' + raw),
        text: text
    });
    if (options.count !== undefined && options.count !== null) {
        node.appendChild(el('span', { class: 'dim-count', text: num(options.count) }));
    }
    return node;
}

/**
 * A country: flag, then the country's name, as a filter control.
 *
 * `short` shows the two-letter code instead of the name, for the dense cells where the code
 * is what the rest of the column is already using.
 */
export function countryNode(code, opts) {
    const options = opts || {};
    const cc = String(code || '').trim().toUpperCase();
    if (cc === '') {
        return el('span', { class: 'muted', text: '—' });
    }
    const name = countryName(cc) || cc;
    const flag = flagNode(cc);
    const label = dimValue('country_s', cc, {
        text: options.short ? cc : name,
        title: 'Filter every view to ' + name + ' (' + cc + ')'
    });
    return el('span', { class: 'geo' }, [flag, label]);
}

/**
 * The client, from the PARSED fields — never the raw User-Agent string.
 *
 * A declared crawler leads with its own name, because "GPTBot" is the fact and "Mozilla/5.0
 * (compatible; GPTBot/1.2; …)" is the packaging. Everything else leads with the browser and
 * its major version, with the operating system and device class beneath it. Each of the four
 * is a filter control in its own right, which is what makes browser, OS and device sliceable
 * from every table that shows them.
 */
export function clientNode(doc) {
    const parts = [];

    if (doc.ua_bot_name) {
        parts.push(el('div', {}, [
            dimValue('ua_bot_name_s', doc.ua_bot_name, { text: doc.ua_bot_name }),
            doc.ai_crawler ? el('span', { class: 'chip chip-accent', text: 'AI' }) : null
        ]));
        parts.push(el('div', { class: 'muted' }, [
            doc.ua_bot_cat ? dimValue('ua_bot_cat_s', doc.ua_bot_cat) : el('span', { text: 'declared crawler' })
        ]));
        return el('div', { class: 'client' }, parts);
    }

    const browser = [doc.browser, doc.browser_ver].filter(Boolean).join(' ');
    parts.push(el('div', {}, [
        doc.browser
            ? dimValue('browser_s', doc.browser, { text: browser || doc.browser })
            : el('span', { class: 'muted', text: 'unknown client' })
    ]));

    const lower = [];
    if (doc.os) {
        lower.push(dimValue('os_s', doc.os));
    }
    if (doc.device) {
        if (lower.length) {
            lower.push(el('span', { class: 'muted', text: ' · ' }));
        }
        lower.push(dimValue('device_s', doc.device));
    }
    parts.push(el('div', { class: 'muted' }, lower.length ? lower : [el('span', { text: '—' })]));

    return el('div', { class: 'client' }, parts);
}

/**
 * The network: organisation on top, type and netname beneath, all three filterable.
 *
 * The organisation is the name a person recognises — "Comcast Cable", "China Telecom" — and
 * it is the column an operator scans, so it leads. The netname is what identifies the
 * specific leased range inside a large provider and is the more precise filter of the two.
 */
export function networkNode(doc) {
    const lower = [];
    if (doc.as_type) {
        lower.push(dimValue('as_type_s', doc.as_type));
    }
    if (doc.netname) {
        if (lower.length) {
            lower.push(el('span', { class: 'muted', text: ' · ' }));
        }
        lower.push(dimValue('netname_s', doc.netname, { mono: true }));
    }

    return el('div', { class: 'client' }, [
        el('div', {}, [
            doc.as_org
                ? dimValue('as_org_s', doc.as_org)
                : el('span', { class: 'muted', text: doc.asn ? 'AS' + doc.asn : 'unknown network' })
        ]),
        el('div', { class: 'muted' }, lower.length ? lower : [el('span', { text: '—' })])
    ]);
}

/**
 * The attributes that make a table row open a detail dialog.
 *
 * Spread into el('tr', …). `tabindex` and the button role are what make it reachable and
 * announced; dialog.js's delegated listener does the rest, so a table replaced by a fetch
 * needs no re-wiring.
 *
 * @param {string} kind  Subject kind a view registered an opener for.
 * @param {Object} data  Extra data- attributes the opener needs, without the lh prefix.
 */
export function drillRow(kind, data) {
    const dataset = { lhOpen: String(kind) };
    for (const key of Object.keys(data || {})) {
        if (data[key] !== null && data[key] !== undefined) {
            dataset[key] = String(data[key]);
        }
    }
    return {
        class: 'row-link',
        tabindex: '0',
        role: 'button',
        dataset: dataset,
        title: 'Open the full record'
    };
}

/**
 * A cell that opens a dimension's detail dialog rather than filtering to it.
 *
 * Used where a row's whole subject IS the dimension — an ASN row, a netname row, a country
 * row — so the row opens the record and the value inside it still filters. Both affordances
 * on one row is deliberate: "show me everything about this" and "show me only this" are
 * different questions and an operator wants both.
 */
export function dimRow(field, value, extra) {
    return drillRow('dim', Object.assign({ field: field, value: value }, extra || {}));
}
