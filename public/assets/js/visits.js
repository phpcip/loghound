/*
 * Loghound — the visit table, which is the same five columns wherever a list of visits appears.
 *
 * FIVE COLUMNS, AND THE COUNT IS THE CONTRACT: date, address, country, page, verdict. The
 * session explorer, the dimension dialog, the fingerprint dialog, the virtual-host dialog and
 * the population dialogs opened from the Overview tiles all render through this one function, so
 * none of them can drift into carrying a sixth.
 *
 * WHAT LEFT AND WHERE IT WENT. The network, the parsed client, the header fingerprint, the
 * request count, the ASN and the netblock were all columns here. Ten columns in a fixed-layout
 * table do not fit: each one is a few characters wide, so the two that carry the longest values
 * — the date and the path — were the two that lost, and the panel shipped a date column reading
 * "09/11/2026 …" with the time cut off and a page column reading "/openso…". Every one of those
 * facts is on the session document and every one of them is in the dialog the row opens, where
 * there is room to say what it means rather than to truncate it.
 *
 * WHAT THE FIVE BUY. The date is the whole instant to the second on one line, because a table of
 * visits is read by comparing times. The address is monospace, because it is an identifier read
 * one character at a time down a column. The country is its name and its flag, never the
 * two-letter code. The page gets every character the other four do not need. The verdict is the
 * word, never the stored slug.
 *
 * EVERY VALUE HERE CAME OFF THE WIRE — a path, a city, an address — and reaches the DOM through
 * core.js's el({text}), which is textContent. The only href is built by url.js from a validated
 * host and a validated path, or by identity.js with encodeURIComponent.
 */

'use strict';

import { dayOnly, dur, el, num, timeOnly, when } from './core.js';
import { copyValue } from './copy.js';
import { glyph } from './icons.js';
import { countryNode, dimValue, drillRow, openButton } from './identity.js';
import { pathCell, urlMark } from './url.js';

/**
 * The column classes, one per column, in order.
 *
 * The widths are in panel.css on these classes, shared with the server-rendered head in
 * Panel\Sessions. Date, address, email, session time and bounce are fixed px; Page carries no
 * width and takes everything that is left, because a path is the value that gets cut.
 *
 * @type {Array<string>}
 */
const COLS = ['vc-when', 'vc-who', 'vc-page', 'vc-email', 'vc-span', 'vc-bounce'];

/* THE VERDICT IS NO LONGER A COLUMN. It was a chip at the end of every row, spending a seventh
   of the width on one word that is already the row's colour — see `.visits tbody tr[data-verdict]`
   in the stylesheet. What that width buys instead is the two facts a visit table could never
   answer: how long they stayed, and whether it counted as a bounce. The flag moves to a narrow
   column left of the address, headed CTR because the glyph needs no more than three letters
   above it and the room belongs to the columns that hold real text. */
/* "BOUNCED", NOT "BOUNCE". The cell answers yes or no for one visit; a rate is something you
   average over many, and the old heading made two legitimate values look like a broken sum. */
const HEADINGS = ['Last seen', 'IP', 'Page', 'Email', 'Sess time', 'Bounced'];

/**
 * The `<colgroup>` and `<thead>` a visit table starts with, for a table built in the browser.
 *
 * @returns {Array<Node>}
 */
export function visitTableHead() {
    return [
        el('colgroup', {}, COLS.map((c) => el('col', { class: c }))),
        el('thead', {}, [
            /* `data-lh-nosort` marks a column the phone does not show, so responsive.js leaves it
               out of the sort control rather than offering an order by something invisible. */
            el('tr', {}, HEADINGS.map((text, i) => el('th', Object.assign(
                { scope: 'col', text: text },
                i === 5 ? { class: 'visit-verdict' } : {},
                (i === 1 || i === 5) ? { 'data-lh-nosort': '1' } : {}
            ))))
        ])
    ];
}

/**
 * One visit row.
 *
 * The row opens the whole visit and every value inside it filters the dashboard to itself, which
 * are different questions and both worth having. A link wins the click over the row, so the
 * verdict cell ends in the explicit opener — inside the fifth column rather than as a sixth,
 * because the five-column contract is about what the reader has to read, and a chevron is a
 * control.
 *
 * @param {Object} v A visit, in the shape Panel\Sessions::shapeVisitor() returns.
 * @returns {HTMLElement}
 */
export function visitRow(v) {
    /* THE ROW CARRIES THE VERDICT AS A COLOUR. `data-verdict` is what the stylesheet colours on,
       here and in every other table that shows a scored session, so the judgement is legible
       down the whole table at a glance instead of being read one chip at a time. */
    const attrs = drillRow('session', { id: v.id });
    attrs.dataset = Object.assign({}, attrs.dataset, { verdict: v.verdict || 'unknown' }, v.ident ? { ident: '1' } : {});
    const tr = el('tr', attrs);

    /* LAST SEEN, FALLING BACK TO ARRIVAL. `ts_end` is what the server now orders and filters
       on, so the column has to show the same instant or the top row reads as hours old. The
       fallback covers a document written before the field was shipped. */
    const seen = v.ts_end || v.ts_start;

    /* TWO SPANS, ONE LINE ON A DESKTOP AND TWO ON A PHONE. The date repeats down the column and
       the clock is the part being read, so on a narrow screen the stylesheet stacks them. */
    tr.appendChild(el('td', {
        class: 'mono nowrap visit-when',
        title: when(seen),
        'data-sort': seen || ''
    }, [
        el('span', { class: 'visit-day', text: dayOnly(seen) }),
        el('span', { class: 'visit-clock', text: timeOnly(seen) })
    ]));

    /* THE FLAG RIDES WITH THE ADDRESS. They answer one question — who, and from where — so
       spending a whole column on a glyph was width taken from the page path. Both are their own
       filter control; the flag carries the country name in the panel's tooltip. */
    tr.appendChild(el('td', {
        class: 'mono clip visit-who',
        'data-sort': [v.country, v.ip].filter(Boolean).join(' ')
    }, [
        v.country
            ? countryNode(v.country, { flagOnly: true })
            : el('span', { class: 'muted visit-noflag', text: '·' }),
        /* WRAPPED SO THE PHONE CAN DROP IT. The flag answers "where from" in one glyph; the
           address is a line of its own at 375px and the stylesheet hides it there. */
        el('span', { class: 'visit-ip' }, [
            v.ip ? dimValue('ip_s', v.ip, { mono: true }) : el('span', { class: 'muted', text: 'not recorded' })
        ])
    ]));

    tr.appendChild(el('td', {
        class: 'clip urlcell',
        'data-sort': v.entry || ''
    }, [
        v.entry
            ? pathCell(v.entry, { host: v.host })
            : noPageMark()
    ]));

    /* THE NAME THE SITE GAVE US, and a filter like any other value: pressing it narrows the
       whole dashboard to that person. `N/A` rather than a dash where the site said nothing,
       because "we were not told" is a different fact from "there is no value". */
    tr.appendChild(el('td', {
        class: 'clip visit-email',
        title: v.ident || 'No identity was sent for this visit',
        'data-sort': v.ident || ''
    }, [
        v.ident ? dimValue('ident_s', v.ident) : el('span', { class: 'muted', text: 'N/A' })
    ]));

    /* TIME ON SITE, AND WHICH CLOCK IT CAME FROM. The engaged clock is the honest one and it
       exists only where the beacon ran; everything else falls back to the log span, which is
       blind to the final page. The cell says which one it is showing rather than presenting two
       different measurements as the same number. */
    const engaged = v.engaged_ms === null || v.engaged_ms === undefined ? null : Number(v.engaged_ms);
    const span = v.log_span_ms === null || v.log_span_ms === undefined ? null : Number(v.log_span_ms);
    const measured = engaged !== null && engaged > 0;
    const shown = measured ? engaged : span;

    /* WORDS WHERE THERE IS NO NUMBER. A dash in a duration column reads as zero seconds, which
       is a measurement; "not measured" is the actual fact and is the reason the verdict for such
       a visit is capped below human. */
    const unmeasured = shown === null || shown <= 0;

    /* THE OPENER RIDES WITH THE DURATION. It used to sit in the bounce cell, which is the one a
       phone drops — so the chevron went with it and the only way into a visit was the row itself.
       Here it survives every width, and it is the last thing on the row either way. */
    tr.appendChild(el('td', {
        class: 'visit-span ' + (unmeasured ? 'nowrap muted' : 'mono nowrap' + (measured ? ' visit-engaged' : ' muted')),
        title: shown === null || shown <= 0
            ? 'Nothing measured a duration for this visit'
            : (measured
                ? 'Engaged time, measured by the beacon'
                : 'Log span: first request to last. Blind to the final page.'),
        'data-sort': String(shown === null ? -1 : shown)
    }, [
        el('span', { text: unmeasured ? 'not measured' : dur(shown) }),
        openButton('session', { id: v.id }, 'Open this visit')
    ]));

    /* SORTED THE WAY IT READS. The cell says Yes, No or an em dash now, so sorting on the raw
       boolean put "No" above "Yes" for reasons nothing on screen explained. */
    tr.appendChild(el('td', {
        class: 'visit-verdict',
        'data-sort': v.bounced === true ? '2' : (v.bounced === false ? '1' : '')
    }, [
        bounceMark(v)
    ]));

    tr.appendChild(visitBox(v, seen, shown, unmeasured));

    return tr;
}

/**
 * Whether this visit bounced, in the product's own definition rather than the conventional one.
 *
 * A bounce is one page AND no engagement — not merely one pageview, which counts a reader who
 * spent four minutes on the article they came for as a failure. Where no beacon ran there is no
 * engagement to judge, so the honest answer is that it is not known, and the cell says so
 * instead of guessing in either direction.
 */
function bounceMark(v) {
    /* A PERCENTAGE OF ONE VISIT IS NOT A PERCENTAGE. Bounced is yes or no for a single visit, and
       printing it as 0% or 100% made a column that could only ever hold two values look like a
       broken calculation. A rate is something you average over many visits, which is what the
       Engagement view is for. Null is neither: the server sends it when nothing could decide. */
    const pct = v.bounced === true ? 'Yes' : (v.bounced === false ? 'No' : '—');

    /* MEASURED, so the figure is stated plainly. The beacon recorded engagement in the browser,
       which is the only way to tell a four-minute read of one page from a visitor who left
       immediately — the distinction the conventional bounce rate gets wrong. */
    if (v.beacon === true) {
        return el('span', {
            class: v.bounced === true ? 'chip chip-accent' : 'chip',
            text: pct,
            title: v.bounced === true
                ? 'Bounced: one page, and the beacon measured no engagement on it.'
                : 'Did not bounce: more than one page, or measured engagement on the one page.'
        });
    }

    /* INFERRED, AND THE CELL SAYS SO RATHER THAN PRINTING A DASH. No beacon reported on this
       visit, so there is no engagement clock and the figure is the conventional page-count
       guess. The mark carries the explanation, because "—" made the reader decode a symbol
       that meant "we declined to answer". */
    return el('span', {
        class: 'nobeacon',
        'data-lh-tip': '1',
        'data-full': 'No beacon data for this visit, so this is inferred from the page count '
            + 'alone. Either the site is not carrying the beacon snippet, or the browser never '
            + 'ran it — an extension, a blocked script, or the visitor left before it loaded.',
        'aria-label': 'Bounce inferred: no beacon data for this visit'
    }, [
        noBeaconMark(),
        el('span', { class: 'muted', text: pct })
    ]);
}

/**
 * A visit that asked for no page at all, said in words instead of as a dash.
 *
 * WHAT IT ACTUALLY MEANS. The client fetched only non-page resources — an image, a script, a
 * stylesheet, /robots.txt — and never requested an HTML page. That is a real and common
 * shape: a hotlinked image, a crawler checking robots, a monitor pulling one asset. A dash
 * asked the reader to infer all of that from a punctuation mark, and it reads as lost data.
 *
 * IT IS ALSO UNRECOVERABLE FOR OLD VISITS, which is why this says so rather than leaving the
 * column blank pending a backfill. Asset requests are not indexed into the hits core unless
 * `ingest.index_assets` is on, so for a session recorded before the sessionizer began keeping
 * the first path of any kind, the path exists in no index to recover. New visits name what
 * they fetched; these cannot be repaired, only explained.
 */
function noPageMark() {
    return el('span', {
        class: 'nopage',
        text: 'no page',
        'data-lh-tip': '1',
        'data-full': 'This visit never requested an HTML page — it fetched only assets, such as '
            + 'an image, a script or /robots.txt. Visits recorded before this was tracked cannot '
            + 'name the asset, because asset requests are not indexed by default.'
    });
}

/** Where the mark below is drawn. */
const SVG_NS = 'http://www.w3.org/2000/svg';

/**
 * A padlock, for a visit the execution plane never reported on.
 *
 * DRAWN, NOT PASTED. The panel ships a CSP with no markup sink and no outside origin, so every
 * icon in this codebase is built with createElementNS — see icons.js and core.js's reload mark,
 * whose 16x16 half-pixel grid and single stroke weight this follows. `currentColor`, so it
 * takes the cell's own tone in both themes; `aria-hidden`, because the wrapper carries the name.
 */
function noBeaconMark() {
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', '0 0 16 16');
    svg.setAttribute('width', '13');
    svg.setAttribute('height', '13');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '1.5');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');

    for (const d of ['M3.75 7.25h8.5v6h-8.5z', 'M5.75 7.25V4.9a2.25 2.25 0 0 1 4.5 0v2.35']) {
        const path = document.createElementNS(SVG_NS, 'path');
        path.setAttribute('d', d);
        svg.appendChild(path);
    }
    return svg;
}

/**
 * A whole visit table, built in the browser.
 *
 * @param {Array<Object>} rows
 * @returns {HTMLElement} The `.table-wrap` the table lives in.
 */
export function visitTable(rows) {
    const body = el('tbody');
    for (const v of (rows || [])) {
        body.appendChild(visitRow(v));
    }

    const table = el('table', { class: 'tight table-fixed visits' }, visitTableHead().concat([body]));

    return el('div', { class: 'table-wrap' }, [table]);
}

/**
 * Fill an existing visit table's body.
 *
 * @param {HTMLTableElement} table
 * @param {Array<Object>} rows
 */
export function fillVisits(table, rows) {
    if (!table) {
        return;
    }
    const body = table.tBodies[0] || table.appendChild(document.createElement('tbody'));
    body.replaceChildren();
    for (const v of (rows || [])) {
        body.appendChild(visitRow(v));
    }
}

/**
 * The one sentence a visit table's caption says about its own scope.
 *
 * It never says "the most recent N of M". That phrasing was the product telling the reader that
 * the rest existed and was unreachable; the table is paged now, so the honest sentence is how
 * many there are and that all of them can be walked.
 *
 * @param {Object} page The server's `page` block.
 * @returns {string}
 */
export function visitCaption(page) {
    const total = page && page.total !== null && page.total !== undefined ? Number(page.total) : null;
    if (total === null) {
        return 'Every visit in scope.';
    }
    if (total === 0) {
        return 'No visit in scope.';
    }
    return num(total) + (total === 1 ? ' visit.' : ' visits, all of them reachable.');
}


/**
 * The same visit as a box of up to four lines, which mobile.css shows on a phone instead of the cells.
 *
 * Line one is a calendar mark and the instant the visit was last seen, mm/dd/yyyy hh:mm:ss, the
 * same shape every other date on the page has. Line two is the open-visit control, the flag and address, the
 * session time and the bounce, on one line that scrolls sideways when it does not fit. Line
 * three is the page, scrolled to its end, with the open-in-new-tab link. Line four is the email,
 * and is left out entirely when there is none. The address, the page and the email copy
 * themselves on a tap. It is one more cell at the end of the row, so sorting by column index and
 * the desktop layout are untouched.
 *
 * @param {Object}      v          The visit.
 * @param {string|null} seen       The instant the first line shows.
 * @param {number|null} shown      The duration in milliseconds.
 * @param {boolean}     unmeasured Whether no duration was measured.
 * @returns {HTMLElement}
 */
function visitBox(v, seen, shown, unmeasured) {
    const stamp = el('div', { class: 'vbox-line vbox-when' }, [
        glyph('calendar'),
        el('span', { class: 'mono', text: when(seen) })
    ]);

    const meta = el('div', { class: 'vbox-line vbox-meta' }, [
        el('span', { class: 'vbox-item' }, [
            openButton('session', { id: v.id }, 'Open this visit')
        ]),
        el('span', { class: 'vbox-item' }, [
            v.country ? countryNode(v.country, { flagOnly: true }) : null,
            v.ip
                ? copyValue(v.ip, { cls: 'mono', label: 'IP address' })
                : el('span', { class: 'muted', text: 'not recorded' })
        ]),
        el('span', { class: 'vbox-item' }, [
            glyph('clock'),
            el('span', { class: unmeasured ? 'muted' : 'mono', text: unmeasured ? 'not measured' : dur(shown) })
        ]),
        el('span', { class: 'vbox-item' }, [
            bounceMark(v)
        ])
    ]);

    const page = el('div', { class: 'vbox-line vbox-page' }, v.entry
        ? [urlMark(v.entry, { host: v.host }), copyValue(v.entry, { cls: 'mono', end: true, url: true, label: 'Page' })]
        : [glyph('page'), noPageMark()]);

    const mail = v.ident
        ? el('div', { class: 'vbox-line vbox-mail' }, [glyph('mail'), copyValue(v.ident, { label: 'Email' })])
        : null;

    return el('td', { class: 'visit-box', colspan: '6' }, [stamp, meta, mail, page]);
}
