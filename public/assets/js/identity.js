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
 *   3. A MARK PER CATEGORY. Every dimension with a closed vocabulary — verdict, browser,
 *      operating system, device class, network type, bot class, referrer type — renders a
 *      small drawn mark in front of its value, from assets/js/icons.js. It is added inside
 *      dimValue() rather than at each call site, which is what makes the facet list, the
 *      table cell, the session row and the detail dialog agree without any of them knowing
 *      about it. The mark is aria-hidden and the word beside it never goes away.
 *
 *   4. PARSED FACTS, NOT THE RAW STRING. A User-Agent in a list column is a truncated
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

import { boot, el, num } from './core.js';
import { toggleUrl } from './facetfilter.js';
import { countryName } from './geo.js';
import { icon } from './icons.js';

/**
 * Field → label, from the server's own filter allowlist.
 *
 * THIS LIST IS THE FILTERABLE SET, and it is no longer retyped here. It was a hand-kept copy of
 * Panel\Query::filterFields() and it had drifted: `ua_bot_name_s`, `city_s`, `region_s`, `asn_i`
 * and `paths_ss` were all in the server's allowlist and missing from this table, so the panel
 * rendered five dimensions as plain text and DROPPED a filter on any of them out of the URL it had
 * itself been given — the server honoured the chip and the browser refused to draw it.
 *
 * It arrives in the boot payload, which is the same answer the country names and the value
 * vocabulary got, for the same reason: one table in PHP, served once, nothing to keep in step.
 * The fallback is an empty set rather than a guessed one, so a page served without the payload
 * renders values as text instead of inventing controls.
 *
 * @type {Object<string,string>}
 */
export const FILTER_LABELS = boot.dimensions || {};

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
 * The words for a stored value, or null when the dimension holds real-world text already.
 *
 * Read from the boot payload, which carries Panel\Vocabulary once per page for the same reason it
 * carries the country names once: two copies of a table are two tables that drift. A value the
 * table does not know answers null, and the caller renders the value itself — never a
 * wrong-but-plausible label and never a blank.
 *
 * @returns {{label: string, why: string}|null}
 */
export function valueWords(field, value) {
    const table = boot.vocabulary && boot.vocabulary[field];
    if (!table) {
        return null;
    }
    return table[String(value)] || null;
}

/**
 * What a person reads for this value: the label when there is one, the value itself otherwise.
 *
 * THE SLUG IS NEVER SHOWN. Not as primary text, not as secondary text, not in a tooltip, not in a
 * detail view. `likely_human`, `fp_cluster_proxy_fleet`, `beacon_only` and `hosting` are what the
 * URL carries and what Solr stores, and they are not words; a person reading the panel sees
 * "Likely human", "Proxy fleet fingerprint", "Beacon only" and "Hosting / datacentre". The mapping
 * between the two belongs in the documentation, not on screen.
 *
 * Use this anywhere a value reaches a chart label, a legend, a table cell, a heading or a
 * sentence. dimValue() applies it for anything that is also a control.
 */
export function valueText(field, value) {
    const spoken = valueWords(field, value);
    return spoken ? spoken.label : String(value === null || value === undefined ? '' : value);
}

/**
 * Render one dimension value as the control that filters the dashboard to it.
 *
 * A filterable field becomes an <a> carrying `f[field][]=value` on top of the current URL — built
 * by facetfilter.js, so the operator already in force on that dimension is preserved and the same
 * gesture removes a value it had added. A field the allowlist does not carry becomes plain text: a
 * link that cannot filter is a lie about what clicking it will do.
 *
 * THE WORD IS NOT THE STORED VALUE. A verdict is stored as `likely_human`, a fired signal as
 * `fp_cluster_proxy_fleet`, a network type as `hosting`. Those are the right things to store, to
 * filter on and to grep for, and the wrong things to print at somebody who has not read
 * src/Score/Rules.php — so a closed vocabulary is spoken in words here, once, for every table
 * cell, facet row, chip and dialog in the panel. The table is Panel\Vocabulary in PHP and arrives
 * in the boot payload; this file keeps no second copy of it, and icons.js is the authority for the
 * MARK in front of a value and for nothing else. An unrecognised value renders as itself.
 *
 * @param {string} field  Solr field name.
 * @param {string} value  The value, exactly as it came back from Solr.
 * @param {Object} [opts] {text, mono, title, count, link, why}
 */
export function dimValue(field, value, opts) {
    const options = opts || {};
    const raw = value === null || value === undefined ? '' : String(value);
    const spoken = valueWords(field, raw);

    /* A DIMENSION WITH A VOCABULARY IS SHOWN IN WORDS, WHATEVER THE CALLER ASKED FOR. Several
       callers used to pass the slug as the visible text, or mono:true, which renders a label as
       though it were an identifier. Both are overridden here rather than fixed once per call site,
       because the next call site would get it wrong too. The slug still travels in the href. */
    const text = spoken
        ? spoken.label
        : (options.text === undefined || options.text === null ? raw : String(options.text));
    const mono = spoken ? false : options.mono;

    if (raw === '') {
        return el('span', { class: 'muted', text: '—' });
    }

    const classes = ['dim'];
    if (mono) {
        classes.push('mono');
    }

    /* A closed vocabulary gets its mark, wherever the value appears. Putting it HERE rather
       than at each call site is what makes a facet list, a table cell, a session row and a
       detail dialog agree: they all render a value through this one function. `mark: false`
       is for the few places where the mark is already on screen beside the value.

       A COUNTRY'S MARK IS ITS FLAG, AND ITS TEXT IS ITS NAME. Same single insertion point,
       for the same reason: a facet list, a pivot row and a table cell were each free to
       render `SC` on their own, and most of them did. A caller that has already put a flag
       beside the value passes `mark: false`; one that genuinely wants the code passes its
       own `text`. */
    const country = field === 'country_s';
    const mark = options.mark === false
        ? null
        : (country ? flagNode(raw) : icon(field, raw));

    /* A caller that passed the CODE as the text has not chosen the code — it has passed the
       stored value through, which every facet bucket and every pivot row does. Only a caller
       that asked for something genuinely different keeps its own text. */
    const shown = country && (text === '' || text === raw)
        ? (countryName(raw) || raw)
        : text;

    if (!isFilterable(field) || options.link === false) {
        const span = el('span', {
            class: mono ? 'mono' : null,
            title: options.title || (spoken && spoken.why ? spoken.why : (spoken ? '' : raw))
        });
        if (mark) {
            span.appendChild(mark);
        }
        span.appendChild(document.createTextNode(shown));
        return span;
    }

    const node = el('a', {
        class: classes.join(' '),
        href: toggleUrl(field, raw),
        title: (spoken && spoken.why)
            || options.title
            || ('Filter every view to ' + dimLabel(field) + ': ' + text)
    });
    if (mark) {
        node.appendChild(mark);
    }
    node.appendChild(document.createTextNode(shown));
    if (options.count !== undefined && options.count !== null) {
        node.appendChild(el('span', { class: 'dim-count', text: num(options.count) }));
    }
    return node;
}

/**
 * The verdict chip, in words, coloured the same way wherever it appears.
 *
 * THERE WERE THREE OF THESE, and all three printed the stored slug. The session table, the
 * fingerprint table and the visitor dialog each carried a byte-identical local copy whose text
 * was `verdict || 'unknown'` — so `likely_human` was rendered as chip text on two views, which
 * is the one thing valueText() exists to stop and what this file's own header calls the rule
 * that is never bent. There is one of them now and it goes through the vocabulary.
 *
 * The CLASS still carries the slug, because that is what the palette keys off
 * (`.chip.v-likely_human`), and a class name is not user-visible text. The `why` sentence from
 * the vocabulary becomes the title, so the chip explains itself on hover as every other
 * vocabulary value in the panel does.
 */
export function verdictChip(verdict) {
    const raw = verdict === null || verdict === undefined || verdict === '' ? 'unknown' : String(verdict);
    const spoken = valueWords('bot_verdict_s', raw);
    return el('span', {
        class: 'chip v-' + raw,
        title: spoken && spoken.why ? spoken.why : null,
        text: valueText('bot_verdict_s', raw)
    });
}

/**
 * A country: the flag, then the country's full name, as a filter control.
 *
 * ALWAYS THE NAME, NEVER THE BARE CODE. A sidebar reading `US BR RU IN RO KE PT SC TR VE ZA AE`
 * names nothing a reader knows: `SC` and `VE` are a guess, and a facet list you have to guess
 * at is not a filter. The flag is the regional-indicator pair the platform composes — no image,
 * no request — and the name comes from Geo\Countries through the boot payload, so there is one
 * table behind every country in the panel.
 *
 * `short` is accepted and ignored. It existed for dense cells, and the answer to a dense cell
 * is a cell that truncates its own line with the full name in a title, not a cell that shows
 * two letters. Call sites keep passing it; nothing keeps honouring it.
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
        text: name,
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
 * Spread into el('tr', …). `tabindex` is what makes it reachable; dialog.js's delegated
 * listener does the rest, so a table replaced by a fetch needs no re-wiring.
 *
 * NO `role="button"` ON A `<tr>`, and that is not a style preference. It did two things at once,
 * both bad. A row that is not a `row` leaves its `<tbody>` holding a child that is not one, so
 * the table's structure is invalid and `<th scope="col">` stops associating with the cells
 * beneath it. Worse, `button` takes PRESENTATIONAL CHILDREN: every descendant is stripped from
 * the accessibility tree — so the filter links in each cell, the explicit row opener at the end
 * and the expander inside the fingerprint rows all disappeared for a screen-reader user, which
 * is precisely the set of controls this file exists to make consistent. The row keeps its
 * tabindex and gains a real accessible name instead; Enter and Space still activate it through
 * the same delegated handler, because that handler matches on the data attribute and not on a
 * role.
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
        dataset: dataset,
        title: 'Open the full record',
        'aria-label': 'Open the full record'
    };
}

/**
 * The explicit "open this record" control that ends a drillable row.
 *
 * WHY A ROW NEEDS ONE. The row is clickable and so is every value in it, and the two mean
 * different things: the value filters the dashboard to itself, the row opens the record. A
 * link has to win that contest or a link would not be a link — but once each identity cell
 * carries two lines of values, most of the row's surface IS link, and a reader aiming at the
 * row hits one and concludes the row does nothing. This is the surface that is always the
 * row: one control, at the end, with a name.
 *
 * It is a button rather than a third affordance invented for the purpose, and it carries the
 * same data-lh-open the row does, so dialog.js's single delegated listener dispatches it with
 * no extra wiring and a table replaced by a fetch needs none either.
 *
 * @param {string} kind Subject kind a view registered an opener for.
 * @param {Object} data Extra data- attributes, without the lh prefix.
 * @param {string} [label] What the control says it will open.
 */
export function openButton(kind, data, label) {
    const attrs = {
        type: 'button',
        class: 'rowopen',
        'aria-label': label || 'Open the full record',
        title: label || 'Open the full record',
        dataset: Object.assign({ lhOpen: String(kind) }, data || {})
    };
    return el('button', attrs, [el('span', { 'aria-hidden': 'true', text: '\u203A' })]);
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
