/*
 * Loghound — the three detail dialogs every view opens.
 *
 * A row in this panel names one of three things, so there are three dialogs and no more:
 *
 *   VISIT — one person's or one client's visit, written for a person to read. Who they were,
 *   what they used, how long they were really here, how they arrived, what the scorer concluded
 *   and WHICH RULES FIRED to produce it, and then every request they made in order. The rule
 *   list is the thing no JavaScript analytics product can show, because it never computed a
 *   verdict in the first place.
 *
 *   DIMENSION — one value of one dimension: a country, an AS organisation, a netname, a browser,
 *   a verdict, a path, a client signature. How much traffic it accounts for and of what kind,
 *   how it breaks down along every other dimension, and then EVERY visit behind it, twenty to a
 *   page — not a sample, and not "the most recent 12 of 1,890".
 *
 *   POPULATION — one of the five headline counts on the Overview. The tiles used to be inert
 *   text: five numbers naming five populations with no way to see a single member of any of
 *   them. Pressing one now opens the visits behind it, in the same paged table.
 *
 * WHAT THIS DIALOG DOES NOT SHOW, AND THAT IS THE POINT. No session id. No header fingerprint.
 * Both were rendered as labelled fields — `SESSION 34ff9f7f1e69…`, `HEADER FINGERPRINT
 * 9e1a8b26e001…` — and a forty-character hash is not a fact about a visitor, it is a database
 * key that happened to be in the payload. What a reader can act on is what the hash MEANS: that
 * the same client configuration arrived from eleven different addresses this afternoon. So that
 * is what is written. The same rule demoted the raw User-Agent to a disclosure the curious can
 * open, and turned the ASN number and the netblock from two labelled rows into one sentence
 * about whose address space the visitor was on.
 *
 * EVERY VALUE IN HERE IS HOSTILE. Paths, User-Agents, referrers, AS organisation names, RIR
 * netnames and any identity the measured site chose to attach are all somebody else's input.
 * All of it reaches the DOM through core.js's el({text}), which is textContent. A referrer
 * becomes an href only after the SERVER has passed it through Security::safeUrl(), a site URL
 * only after url.js has rebuilt it from a validated host and a validated path — the client
 * never decides that a scheme is safe — and the filter links are built with encodeURIComponent
 * by identity.js.
 *
 * A PATH IS NEVER SHOWN BARE. The trail, the entry and exit pages and the visit table all carry
 * the full URL beside the path, as a link that opens in a new tab. A hit's own host is preferred
 * and the session's host is the fallback, because a session can cross virtual hosts.
 */

'use strict';

import {
    api, bytes, dec, dur, durUs, el, fill, num, pct, populationLabel, when
} from './core.js';
import { closeDialog, dialogFail, isCurrent, openDialog, registerOpener } from './dialog.js';
import {
    dimLabel, dimValue, flagNode, valueText, verdictChip
} from './identity.js';
import { markSortable } from './sorttable.js';
import { countryName } from './geo.js';
import { outLink, pathCell, urlMark } from './url.js';
import { renderPager } from './pager.js';
import { fillVisits, visitCaption, visitTable } from './visits.js';

/** Population keys in the order every other chart in the panel stacks them. */
const ORDER = ['human', 'unknown', 'declared', 'ai', 'evasive'];

/**
 * A definition list from [label, value, mono] triples, skipping the empty ones.
 *
 * Skipping rather than printing an em-dash for every absent field: a dialog with nine "—" rows
 * in it buries the four facts that are actually known. Where an absence is itself the finding
 * — no beacon, no conditional requests — the caller passes an explicit sentence instead.
 */
function kv(pairs) {
    const dl = el('dl', { class: 'kv' });
    for (const [label, value, mono] of pairs) {
        if (value === null || value === undefined || value === '') {
            continue;
        }
        dl.appendChild(el('dt', { text: label }));
        dl.appendChild(typeof value === 'string' || typeof value === 'number'
            ? el('dd', { class: mono ? 'mono' : null, text: String(value) })
            : el('dd', { class: mono ? 'mono' : null }, [value]));
    }
    return dl;
}

/** A plain sentence, or nothing when there is no sentence to say. */
function say(text, klass) {
    return text ? el('p', { class: klass || 'muted', text: text }) : null;
}

/** A note saying which filters produced the numbers below it, or nothing when none did. */
function filterNote(active) {
    const parts = [];
    for (const field of Object.keys(active || {})) {
        for (const value of active[field]) {
            parts.push(dimLabel(field) + ': ' + valueText(field, value));
        }
    }
    if (!parts.length) {
        return null;
    }
    return el('p', {
        class: 'faint',
        text: 'Scoped to ' + parts.join(', ') + ', and to the selected range.'
    });
}

/* -------------------------------------------------------------------------
 * The paged visit table, shared by all three dialogs
 * ---------------------------------------------------------------------- */

/**
 * A caption, a five-column visit table and its pager, wired to page server-side.
 *
 * WHY IT PAGES OVER THE WIRE AND NOT IN THE BROWSER. A fingerprint dialog can stand behind 1,890
 * visits and a country dialog behind a hundred times that. Fetching them all so the browser can
 * slice twenty would be a request whose cost is the size of the population, from a dialog the
 * reader opened out of curiosity — so each page is its own bounded read of twenty documents and
 * the one before it is thrown away.
 *
 * A failed page turn leaves the table it had and offers to try again, rather than replacing a
 * dialog full of working content with an error.
 *
 * @param {Array<Object>} rows  First page of visits.
 * @param {Object} page         The server's `page` block.
 * @param {Function} fetchPage  (start) => Promise<{visitors, page}>
 * @returns {HTMLElement}
 */
function visitBlock(rows, page, fetchPage) {
    const wrap = visitTable(rows);
    const table = wrap.querySelector('table');
    const mount = el('div', { class: 'pager-mount' });
    const caption = el('p', { class: 'faint', text: visitCaption(page) });

    const show = (state) => {
        renderPager(mount, state, async (start, rows) => {
            const busy = el('p', { class: 'muted', text: 'Loading page…' });
            mount.replaceChildren(busy);
            try {
                const next = await fetchPage(start, rows);
                fillVisits(table, next.visitors || []);
                markSortable(wrap);
                show(next.page);
            } catch (err) {
                const again = el('button', { type: 'button', class: 'small', text: 'Try again' });
                again.addEventListener('click', () => show(state));
                mount.replaceChildren(
                    el('p', { class: 'muted', text: 'That page could not be loaded: ' +
                        String(err && err.message ? err.message : err) }),
                    el('div', { class: 'card-error-actions' }, [again])
                );
            }
        });
    };
    show(page);

    return el('div', { class: 'visit-block' }, [caption, wrap, mount]);
}

/* -------------------------------------------------------------------------
 * The visit dialog
 * ---------------------------------------------------------------------- */

/**
 * How long they were here, written for whichever of the three cases this visit is.
 *
 * ONE REQUEST IS THE CASE THIS EXISTS FOR. A visit with a single hit used to render three
 * labelled fields reading `STARTED 21:51:53`, `ENDED 21:51:53` and `LOG SPAN 0 ms`, followed by
 * three paragraphs explaining what could not be known — a lot of apology for an empty block, and
 * a `0 ms` that looks like a measurement of something. One request has no duration; the honest
 * output is one sentence saying so, and then the section is over.
 *
 * With a beacon the four clocks are worth the room, because the difference between them is the
 * product's headline claim. Without one they are not shown at all: a zero is a measurement and
 * "nobody measured this" is a different statement.
 */
function howLong(s) {
    const oneRequest = s.hits !== null && s.hits <= 1;

    if (oneRequest && !s.beacon) {
        return [
            say('One request, at ' + when(s.ts_start) + ', and no beacon: nothing measured a duration.')
        ];
    }

    const parts = [];

    if (s.beacon) {
        const grid = el('div', { class: 'timing-grid' });
        const add = (key, label, value, defn) => {
            grid.appendChild(el('div', { class: 'timing', dataset: { timing: key } }, [
                el('span', { class: 'timing-label', text: label }),
                el('span', { class: 'timing-value mono', text: value }),
                el('span', { class: 'timing-defn', text: defn })
            ]));
        };
        add('log_span', 'Requesting things for', dur(s.log_span_ms), 'First request to last. Blind to the final page.');
        add('wall', 'Page open for', dur(s.wall_ms), 'Tab in any state.');
        add('visible', 'Looking at it for', dur(s.visible_ms), 'Visible and focused.');
        add('engaged', 'Actually engaged for', dur(s.engaged_ms), 'Within 30s of an interaction.');
        parts.push(grid);
        parts.push(say(num(s.interactions) + ' interactions, '
            + (s.max_scroll === null ? 'no scroll depth recorded' : s.max_scroll + '% deepest scroll')
            + ', ' + num(s.pageviews) + ' pageviews.'));
        return parts;
    }

    parts.push(say('They were requesting things for ' + dur(s.log_span_ms) + ', from '
        + when(s.ts_start) + ' to ' + when(s.ts_end) + '.'));
    parts.push(say('That is the log span, which cannot see the last page. No beacon ran, so how long they '
        + 'stayed is unknown rather than zero.'));

    return parts;
}

/**
 * One collapsible section of a dialog: shut by default, and remembered once opened.
 *
 * EVERY SECTION FOLDS, AND THEY ALL START SHUT. A visit dialog carries eight blocks — who was
 * here, what they used, the clocks, how they arrived, every request in order, the verdict and
 * its evidence, what they did — and a reader opens it for one of them. Printed in full it is
 * several screens deep, so the block somebody actually wanted was reached by scrolling past
 * seven they did not. Shut by default turns that into a list of eight headings that fits on one
 * screen, and one press.
 *
 * THE STATE IS REMEMBERED PER BLOCK, NOT PER VISIT, which is the same rule the panel's other
 * folds follow: somebody who opens "Everything they asked for" wants request trails, not that
 * one visitor's in particular, so the next dialog opens with the trail already unfolded. It
 * rides on the existing `details.fold.lh-keep[data-keep]` mechanism in responsive.js — the
 * toggle listener is delegated from the document, so it binds to dialogs that did not exist at
 * load, and refresh() re-applies the stored state after each render.
 *
 * The identity strip is deliberately NOT one of these: an email address is the one fact worth
 * a line of its own, and burying it behind a press is what made it unreachable in the first
 * place.
 *
 * @param {string} key      Stable slug; the storage key, so it must not change between renders.
 * @param {string} title    The heading, which becomes the summary.
 * @param {Array<Node>|Node} children
 * @returns {HTMLElement|null} Null when there is nothing inside, so an empty block draws nothing.
 */
function foldSection(key, title, children) {
    const kids = (Array.isArray(children) ? children : [children]).filter(Boolean);
    if (kids.length === 0) {
        return null;
    }

    return el('details', {
        class: 'fold lh-keep dlg-fold',
        dataset: { keep: 'dlg.' + key }
    }, [el('summary', { text: title })].concat(kids));
}

/** The rules that fired, each with the plain-English description of what it means. */
function firedRules(s, catalogue) {
    const list = el('ul', { class: 'plane-list' });
    for (const code of (s.reasons || [])) {
        const meta = (catalogue || {})[code];
        list.appendChild(el('li', {}, [
            dimValue('bot_reasons_ss', code),
            meta
                ? el('span', { text: ' — ' + meta.why })
                : el('span', { class: 'muted', text: ' — no description for this rule code in this panel version' })
        ]));
    }
    if (!(s.reasons || []).length) {
        list.appendChild(el('li', { class: 'muted', text: 'No signal fired.' }));
    }
    return list;
}

/**
 * The request trail: every request in the visit, in order, twenty to a page.
 *
 * THE THING AN OPERATOR READS BEHAVIOUR FROM — what somebody was trying to do and what they
 * wanted — so it is the last and largest block in the dialog rather than a footnote. It used to
 * fetch two hundred requests and then admit, in a sentence under them, that a busy session had
 * more and they were not reachable. A scraper's session is exactly the one that overflows, and
 * what it asked for at the END is exactly what was being cut off.
 *
 * @param {string} id       Session id, for the page fetches. Never rendered.
 * @param {Object} data     The detail payload.
 * @param {string|null} host The session's own virtual host, as the fallback for a hit with none.
 */
function trailBlock(id, data, host) {
    const list = el('ul', { class: 'timeline' });
    const mount = el('div', { class: 'pager-mount' });

    const paint = (hits) => {
        list.replaceChildren();
        const rows = hits || [];
        for (let i = 0; i < rows.length; i++) {
            const hit = rows[i];
            const statusClass = 't-status-' + String(hit.status === null ? '' : hit.status).charAt(0);

            /* HOW LONG THEY STAYED ON IT, which is the gap to whatever they asked for next.
               It is the only "time on page" a log can honestly give: the server sees requests,
               not attention, so the last row has no gap at all rather than a made-up one — and
               where the beacon ran, the engaged clock above is the number that means presence.
               The rows arrive newest-first, so the NEXT request in time is the previous row. */
            const prev = i > 0 ? rows[i - 1] : null;
            const gapMs = prev ? Date.parse(prev.ts) - Date.parse(hit.ts) : NaN;
            const gap = Number.isFinite(gapMs) && gapMs > 0 ? dur(gapMs) : '';
            list.appendChild(el('li', {}, [
                el('span', { class: 'muted mono', text: when(hit.ts).split(' ')[1] || '' }),
                el('span', { class: 't-method muted', text: hit.method || '' }),
                el('span', { class: 't-path urlwrap', title: hit.path + (hit.query ? '?' + hit.query : '') }, [
                    el('span', { class: 'urlpath' }, [
                        el('span', { text: hit.path }),
                        hit.query ? el('span', { class: 'muted', text: '?' + hit.query }) : null
                    ]),
                    urlMark(hit.path, { host: hit.host, fallback: host, query: hit.query })
                ]),
                el('span', { class: statusClass + ' mono', text: hit.status === null ? '—' : String(hit.status) }),
                el('span', { class: 't-bytes muted mono', text: bytes(hit.bytes) }),
                el('span', {
                    class: 't-dur muted mono',
                    text: hit.dur_us === null ? '' : durUs(hit.dur_us),
                    title: hit.dur_us === null ? '' : 'Time the server took to answer'
                }),
                el('span', {
                    class: 't-gap muted mono',
                    text: gap,
                    title: gap === '' ? '' : 'They asked for nothing else for this long'
                })
            ]));
        }
    };

    const show = (state) => {
        renderPager(mount, state, async (start, rows) => {
            mount.replaceChildren(el('p', { class: 'muted', text: 'Loading page…' }));
            try {
                const next = await api('sessions', 'trail', {
                    id: id,
                    start: start,
                    rows: rows || state.rows
                });
                paint(next.timeline);
                show(next.page);
            } catch (err) {
                const again = el('button', { type: 'button', class: 'small', text: 'Try again' });
                again.addEventListener('click', () => show(state));
                mount.replaceChildren(
                    el('p', { class: 'muted', text: 'That page could not be loaded: ' +
                        String(err && err.message ? err.message : err) }),
                    el('div', { class: 'card-error-actions' }, [again])
                );
            }
        });
    };

    if (!data.timeline.length) {
        return el('p', {
            class: 'muted',
            text: 'No individual requests came back: they have aged out of the request log, which is kept '
                + 'for less time than the summary of a visit.'
        });
    }

    paint(data.timeline);
    show(data.page);

    return el('div', {}, [list, mount]);
}

/**
 * What the measured site said about who this was, if it said anything.
 *
 * TWO INDEPENDENT FACTS, and the strip says which of them it has. A site can pass an identity
 * without the visitor being authenticated, and can record "this was a signed-in session"
 * without handing over who it was, so neither is inferred from the other. `signed_in === null`
 * means the site never told us, and it reads as "not reported" rather than as "anonymous" —
 * a visitor nobody classified is not a visitor who was classified as logged out.
 *
 * Absent entirely when there is nothing to say, because a strip announcing two unknowns on
 * every session on every installation that has not adopted the feature is noise.
 */
function identStrip(s) {
    if (!s.ident && s.signed_in === null) {
        return null;
    }

    const parts = [];
    if (s.ident) {
        parts.push(el('span', { class: 'ident-label', text: 'The site knows them as' }));
        parts.push(el('span', { class: 'ident-value mono', text: s.ident }));
    }
    parts.push(el('span', {
        class: 'chip ' + (s.signed_in === true ? 'chip-good' : ''),
        text: s.signed_in === true ? 'signed in' : (s.signed_in === false ? 'not signed in' : 'sign-in state not reported')
    }));
    parts.push(el('span', { class: 'faint', text: 'Declared by the site, not derived.' }));

    return el('div', { class: 'ident-strip' }, parts);
}

/**
 * Where they were, as a place rather than a code.
 */
function placeNode(s) {
    if (!s.country) {
        return null;
    }
    return el('span', { class: 'geo' }, [
        flagNode(s.country),
        el('span', { text: [s.city, s.region, countryName(s.country) || s.country].filter(Boolean).join(', ') })
    ]);
}

/**
 * Whose network they were on, in words, with the numbers demoted to one sentence.
 *
 * THE ASN AND THE NETBLOCK ARE NOT FIRST-CLASS FIELDS ANY MORE. `ASN AS7922` and `NETBLOCK
 * 73.0.0.0/8` were two labelled rows of a dialog that is supposed to be readable, and neither
 * says anything on its own — the fact is "they were on Comcast's consumer broadband", and the
 * numbers are how you'd look that up. So the name and the kind of network lead, as filter
 * controls, and the identifiers follow in a faint line for the operator who needs to quote them.
 */
function networkBlock(s) {
    if (!s.as_org && !s.asn && !s.netname) {
        return null;
    }

    const head = el('div', {}, [
        s.as_org
            ? dimValue('as_org_s', s.as_org)
            : el('span', { class: 'muted', text: 'An unnamed network' }),
        s.as_type ? el('span', { text: ' — ' }) : null,
        s.as_type ? dimValue('as_type_s', s.as_type) : null
    ]);

    const bits = [];
    if (s.ip_net) {
        bits.push('address block ' + s.ip_net);
    }
    if (s.asn) {
        bits.push('network AS' + s.asn);
    }
    if (s.netname) {
        bits.push('registered as ' + s.netname);
    }

    return el('div', {}, [
        head,
        bits.length ? el('div', { class: 'sub', text: 'Looked up as ' + bits.join(', ') + '.' }) : null
    ]);
}

/**
 * What the address's own network calls it, and whether that claim can be believed.
 *
 * A reverse DNS name is only evidence when it resolves back to the address it came from; the
 * panel used to print `crawl-66-249-66-1.googlebot.com (NOT forward-confirmed)` and leave the
 * reader to know what that means. Anyone can point a name at anything, and only the forward
 * lookup makes it a fact.
 */
function rdnsSentence(s) {
    if (!s.rdns) {
        return null;
    }
    return s.rdns_ok
        ? 'Reverse DNS says ' + s.rdns + ', forward-confirmed.'
        : 'Reverse DNS claims ' + s.rdns + ', which does not resolve back to this address. The claim is '
            + 'worth nothing.';
}

/**
 * What the header signature means for this visit, WITHOUT ever printing the hash.
 *
 * The hash is a database key. What the reader can act on is how many unrelated addresses wore
 * the same client configuration in the same day: one is what a browser looks like, and a dozen
 * is what one scraper behind a rotating proxy pool looks like.
 */
function signatureSentence(s) {
    if (s.fp_ips_24h === null || s.fp_ips_24h === undefined) {
        return null;
    }
    const n = Number(s.fp_ips_24h);
    if (n <= 1) {
        return 'This exact set of request headers came from this address alone in the surrounding day.';
    }
    if (n < 5) {
        return 'The same headers came from ' + num(n) + ' addresses in the surrounding day.';
    }
    return 'The same headers came from ' + num(n) + ' unrelated addresses in the surrounding day — the shape '
        + 'a proxy fleet makes.';
}

/**
 * The raw User-Agent, behind a disclosure rather than as a labelled field.
 *
 * It is real evidence and it stays available, but it is a hundred and forty characters of
 * packaging — `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 …` — whose
 * content the parser has already turned into the three facts above it. As a first-class field
 * it pushed those three off the top of the dialog.
 *
 * `<details>` rather than a scripted toggle, because the panel's CSP allows no inline handler
 * and the browser's own disclosure needs none.
 */
function rawAgent(s) {
    if (!s.ua) {
        return null;
    }
    return el('details', { class: 'raw-ua' }, [
        el('summary', { text: 'The raw User-Agent string' }),
        el('p', { class: 'mono wrap', text: s.ua })
    ]);
}

/**
 * What they did, as sentences rather than as eleven labelled numbers.
 *
 * The request count, the page/asset split and the byte total are readable as figures. The asset
 * ratio, the median gap and the gap standard deviation are not: they are inputs to the scorer,
 * and printed as `0.94` and `2300 ms` they are three rows a reader skips. What they MEAN — a
 * visit that fetched almost no page HTML, a rhythm too regular for a hand on a mouse — is worth
 * a sentence, so that is what they get.
 */
function whatTheyDid(s) {
    const facts = kv([
        ['Requests', s.hits === null ? null : num(s.hits), true],
        ['Pages / other files', s.pages === null && s.assets === null
            ? null
            : num(s.pages) + ' / ' + num(s.assets), true],
        ['Distinct pages', s.uniq_paths === null ? null : num(s.uniq_paths), true],
        ['Data sent', s.bytes === null ? null : bytes(s.bytes), true]
    ]);

    const notes = [];

    const bad = (s.status['4xx'] || 0) + (s.status['5xx'] || 0);
    if (bad > 0) {
        notes.push(num(s.status['2xx'] || 0) + ' answered, ' + num(s.status['3xx'] || 0) + ' redirected, '
            + num(s.status['4xx'] || 0) + ' refused, ' + num(s.status['5xx'] || 0) + ' broke the server.');
    }

    if (s.asset_ratio !== null && s.hits !== null && s.hits > 3) {
        if (s.asset_ratio < 0.2) {
            notes.push('Almost nothing they fetched was an image, a stylesheet or a script. A browser loads '
                + 'the trimmings; something that only wants the text does not.');
        }
    }

    if (s.gap_p50_ms !== null && s.hits !== null && s.hits > 3) {
        const steady = s.gap_stddev_ms !== null && s.gap_p50_ms > 0
            && s.gap_stddev_ms < s.gap_p50_ms * 0.15;
        notes.push('A request about every ' + dur(s.gap_p50_ms)
            + (s.gap_stddev_ms === null ? '.' : ', varying by ' + dur(s.gap_stddev_ms) + '.')
            + (steady ? ' That even a rhythm is a timer, not a hand on a mouse.' : ''));
    }

    if (s.got_304 === false && s.hits !== null && s.hits > 3) {
        notes.push('Never asked whether anything had changed since last time, which a browser cache does.');
    }

    return [facts].concat(notes.map((n) => say(n)));
}

/**
 * Render one visit into the dialog body.
 *
 * The order is the order the questions get asked: who they say they are, who they were and what
 * they used, how long they were here, how they arrived, what we concluded and why, what they
 * did, and finally every request in order.
 */
function renderSession(body, data) {
    const s = data.session;

    const who = [
        ['Address', s.ip ? dimValue('ip_s', s.ip, { mono: true }) : null],
        ['Where', placeNode(s)],
        ['Network', networkBlock(s)],
        ['Timezone of the address', s.tz, true]
    ];

    const used = [
        ['Browser', s.browser ? dimValue('browser_s', s.browser, {
            text: [s.browser, s.browser_ver].filter(Boolean).join(' ')
        }) : null],
        ['Operating system', s.os ? dimValue('os_s', s.os) : null],
        ['Kind of device', s.device ? dimValue('device_s', s.device) : null],
        ['Says it is a crawler', s.ua_bot
            ? el('span', {}, [
                el('span', { text: (s.ua_bot_name || 'yes') }),
                s.ua_bot_cat ? el('span', { text: ' — ' }) : null,
                s.ua_bot_cat ? dimValue('ua_bot_cat_s', s.ua_bot_cat) : null,
                s.ai_crawler ? el('span', { class: 'chip chip-accent', text: 'collects for AI' }) : null
            ])
            : null]
    ];

    const execution = [];
    if (s.beacon) {
        execution.push(['Scripts ran on the page', s.js ? 'yes' : 'no']);
        execution.push(['Headless signals', s.headless ? 'yes' : 'none']);
        execution.push(['The browser it claimed to be', s.ua_claim_ok === null
            ? null
            : (s.ua_claim_ok ? 'matches the engine' : 'contradicts the engine')]);
        execution.push(['Its clock against its address', s.tz_match === null
            ? null
            : (s.tz_match ? 'agree' : 'disagree')]);
        execution.push(['Graphics hardware reported', s.webgl]);
        if ((s.automation || []).length) {
            execution.push(['Automation markers', s.automation.join(', ')]);
        }
    }

    const arrival = [
        ['First page they asked for', s.entry ? pathCell(s.entry, { fallback: s.host }) : null],
        ['Last page the log saw', s.exit ? pathCell(s.exit, { fallback: s.host }) : null],
        ['Came from', s.referer
            ? (s.referer_href && s.referer_href !== '#'
                ? el('a', { href: s.referer_href, rel: 'noreferrer noopener', text: s.referer })
                : el('span', { class: 'mono wrap', text: s.referer }))
            : 'no referrer sent'],
        ['Which counts as', s.referer_type ? dimValue('referer_type_s', s.referer_type) : null],
        ['Site they were on', s.host
            ? el('span', { class: 'urlwrap' }, [
                el('span', { class: 'urlpath' }, [dimValue('host_s', s.host, { mono: true })]),
                outLink(s.host, '/')
            ])
            : null]
    ];

    const signature = signatureSentence(s);
    const rdns = rdnsSentence(s);

    fill(body, [
        identStrip(s),

        el('div', { class: 'grid-2' }, [
            foldSection('who', 'Who was here', [kv(who), say(rdns)]),
            foldSection('used', 'What they used', [kv(used), say(signature), rawAgent(s)])
        ]),

        foldSection('howlong', 'How long they were here', howLong(s)),

        foldSection('arrival', 'How they arrived', [kv(arrival)]),

        /* THE CIRCUIT COMES BEFORE THE CONCLUSION. This sat at the very bottom, under the
           verdict, the execution evidence and four blocks of counters — so the one thing a
           reader opens a visit to see, WHERE THEY WENT, was a scroll and a half below the
           fold. It belongs beside how they arrived: first page, then every page after it. */
        foldSection('trail', 'Everything they asked for, in order', [
            trailBlock(data.session.id, data, s.host)
        ]),

        foldSection('verdict', 'What we concluded, and why', [
            kv([
                ['Verdict', verdictChip(s.verdict)],
                ['Bot score', s.score === null ? null : dec(s.score, 0) + ' / 100', true],
                ['Kind of client', s.class ? dimValue('bot_class_s', s.class) : null]
            ]),
            foldSection('verdict-rules', 'What led to that', [firedRules(s, data.reasons)]),
            execution.length
                ? foldSection('verdict-execution', 'What the browser could actually do', [kv(execution)])
                : null
        ]),

        foldSection('did', 'What they did', whatTheyDid(s))
    ]);
}

/**
 * Open one visit.
 *
 * Exported so a view can open a visit it already has the id of — the `?open=` deep link on the
 * session explorer does exactly that.
 *
 * NEITHER THE HEADING NOR THE SUBTITLE IS THE SESSION ID. Both used to be: the heading was a
 * twelve-character prefix of the hash and the subtitle carried the whole forty characters "so an
 * operator reporting this has something to quote". Nobody reports a visit by its hash, and a
 * dialog whose title is a hash tells the reader nothing about whose visit they are looking at.
 * It is the visitor, by whatever name the data can give them.
 *
 * THE HANDLE IS REASSIGNED, and that is not tidying up. The second openDialog() below bumps the
 * generation, so a catch that tested the FIRST handle's token could never be true: every throw
 * out of renderSession() or markSortable() was swallowed whole, leaving the dialog frozen on
 * "Loading" with nothing on screen and nothing in the console to say why.
 */
export async function openSession(id) {
    let handle = openDialog('This visit', 'Loading the visit and every request in it…');
    try {
        const data = await api('sessions', 'detail', { id: id });
        if (!isCurrent(handle.generation)) {
            return;
        }
        const s = data.session;
        const where = [s.city, countryName(s.country) || s.country].filter(Boolean).join(', ');

        handle = openDialog(
            s.ident || s.ip || 'This visit',
            [when(s.ts_start), where, s.as_org, valueText('bot_verdict_s', s.verdict)]
                .filter(Boolean).join(' · ')
        );
        renderSession(handle.body, data);
        markSortable(handle.body);
    } catch (err) {
        if (isCurrent(handle.generation)) {
            dialogFail(handle.body, err, () => openSession(id));
        }
    }
}

/* -------------------------------------------------------------------------
 * The dimension dialog
 * ---------------------------------------------------------------------- */

/** The five-population mix as one bar, in the colours the rest of the panel uses. */
function mixBar(mix, total) {
    const denominator = total || 1;
    return el('span', { class: 'bar bar-split' }, ORDER.map((key) => el('span', {
        class: 'bar-' + key,
        style: 'width:' + (((mix[key] || 0) / denominator) * 100).toFixed(2) + '%',
        title: populationLabel(key) + ': ' + num(mix[key] || 0) + ' (' + pct(mix[key] || 0, denominator) + ')'
    })));
}

/** One breakdown: a dimension, its values with counts, each value a filter control. */
function breakdown(group, total) {
    return el('div', { class: 'fgroup' }, [
        el('h4', { text: group.label }),
        el('ul', {}, group.buckets.map((bucket) => el('li', {}, [
            dimValue(group.field, bucket.value, { count: bucket.count, mono: group.mono }),
            el('span', { class: 'faint', text: pct(bucket.count, total) })
        ])))
    ]);
}

/** What the webserver actually returned for a path, when the dimension is one. */
function requestProfile(req) {
    if (!req) {
        return null;
    }
    const statuses = req.status.map((row) => el('li', {}, [
        el('code', { class: 'mono', text: String(row.status) }),
        el('span', { class: 'faint', text: num(row.count) + ' · ' + pct(row.count, req.hits) })
    ]));

    return foldSection('request-profile', 'What the server actually returned', [
        kv([
            ['Times it was requested', num(req.hits), true],
            ['Data sent', bytes(req.bytes), true],
            ['Usually answered in', req.dur_p50 === null ? null : durUs(req.dur_p50), true],
            ['Slowest one request in twenty', req.dur_p95 === null ? null : durUs(req.dur_p95), true]
        ]),
        el('div', { class: 'fgroup' }, [el('h4', { text: 'What it answered with' }), el('ul', {}, statuses)]),
        (req.ignored || []).length
            ? el('p', { class: 'faint', text: 'Counted per request. ' + (req.ignored || []).join(', ')
                + ' do not exist on a request, so those filters are not applied and these figures cover a '
                + 'wider population than the visit counts.' })
            : null
    ]);
}

/**
 * The heading and caption for a dimension value, with NO stored value anywhere in either.
 *
 * A HASH IS NOT A TITLE. The fingerprint dialog was headed with its forty-character hash,
 * because the title was simply the value and a fingerprint's value is a hash. It is now named
 * for what it is — a client signature — and described by what it does, which is the only part a
 * reader can act on. An address is its own name and stays one; everything else gets the
 * dimension's label in front of its value, so "Romania" reads as "Country: Romania" and cannot
 * be mistaken for a city.
 *
 * @returns {{title: string, sub: string}}
 */
function dimHeading(data) {
    const field = String(data.field || '');
    const label = String(data.label || dimLabel(field));
    const sessions = num(data.sessions) + ' visit' + (data.sessions === 1 ? '' : 's');
    const range = data.range_label || 'the selected range';

    if (field === 'fp_hash_s') {
        return {
            title: 'One client signature',
            sub: sessions + ' in ' + range + ' shared this exact set of request headers, across '
                + num(data.uniq_ips) + ' address' + (data.uniq_ips === 1 ? '' : 'es')
                + ' and ' + num(data.uniq_asns) + ' network' + (data.uniq_asns === 1 ? '' : 's') + '.'
        };
    }

    if (field === 'ip_s' || field === 'session_id_s') {
        return { title: String(data.value), sub: sessions + ' in ' + range };
    }

    return {
        title: label + ': ' + valueText(field, data.value),
        sub: sessions + ' in ' + range
    };
}

/**
 * The three facts that belong beside the counts rather than at the bottom of the page.
 *
 * The virtual host is read out of the breakdown that is already on the payload rather than
 * asked for again: one host is worth naming outright, several is worth counting, and the group
 * still lists them all further down. Searches and attacks are counted server-side over the
 * same scope as every other figure here, so they cannot disagree with the visit count.
 *
 * Rendered through dimValue() like every other dimension value, so the host carries its colour
 * dot and its filter link, and reads the same here as it does anywhere else in the panel.
 */
function atAGlance(data) {
    const rows = [];
    const total = data.sessions || 0;

    const hosts = (data.breakdowns || []).find((group) => group.field === 'host_s');
    const buckets = hosts && Array.isArray(hosts.buckets) ? hosts.buckets : [];

    if (buckets.length === 1) {
        rows.push(['Virtual host', dimValue('host_s', buckets[0].value, { mono: true })]);
    } else if (buckets.length > 1) {
        rows.push(['Virtual hosts', num(buckets.length) + ' — ' + buckets[0].value
            + ' is the busiest, with ' + pct(buckets[0].count, total || 1)]);
    }

    if (data.searched !== undefined && data.searched !== null) {
        rows.push(['Searched the site', data.searched > 0
            ? num(data.searched) + ' of ' + num(total) + ' · ' + pct(data.searched, total || 1)
            : 'None of them searched']);
    }

    if (data.attacked !== undefined && data.attacked !== null) {
        rows.push(['Matched an attack pattern', data.attacked > 0
            ? num(data.attacked) + ' of ' + num(total) + ' · ' + pct(data.attacked, total || 1)
            : 'None of them']);
    }

    return rows.length ? kv(rows) : null;
}

/** Render one dimension value into the dialog body. */
function renderDimension(body, data) {
    const total = data.sessions || 0;

    fill(body, [
        el('div', { class: 'stats' }, [
            statTile('Visits', num(total), 'In range, under the active filters'),
            statTile('Addresses', num(data.uniq_ips), 'Approximate above ~100'),
            statTile('Client signatures', num(data.uniq_fps), 'Few across many addresses is one client'),
            statTile('Requests', num(data.hits), 'Log lines in these visits')
        ]),

        filterNote(data.active),

        /* THE THREE FACTS THAT WERE BURIED. The virtual host sat at the bottom of an
           eleven-group breakdown, and whether these visits searched or attacked could not be
           read at all. They belong beside the counts, in the same rendering every other value
           in the panel gets — flag, icon, filter link — rather than as bare text. */
        atAGlance(data),

        foldSection('dim-kind', 'What kind of traffic this is', [
            mixBar(data.mix, total),
            kv(ORDER.map((key) => [
                data.labels[key] || key,
                num(data.mix[key] || 0) + ' · ' + pct(data.mix[key] || 0, total || 1),
                true
            ]))
        ]),

        foldSection('dim-when', 'When, and for how long', [
            kv([
            ['First seen', when(data.first), true],
            ['Last seen', when(data.last), true],
            ['Typical time spent requesting', data.log_span_p50 === null ? null : dur(data.log_span_p50), true],
            ['Visits a beacon reported on', num(data.beacon.sessions), true],
            ['Typical time actually engaged', data.beacon.sessions
                ? (data.beacon.engaged_p50 === null ? null : dur(data.beacon.engaged_p50))
                : null, true],
            ['Typical time the page was open', data.beacon.sessions
                ? (data.beacon.wall_p50 === null ? null : dur(data.beacon.wall_p50))
                : null, true],
                ['Average bot score', data.score === null ? null : dec(data.score, 0) + ' out of 100', true],
                ['Data sent', bytes(data.bytes), true]
            ]),
            data.beacon.sessions === 0
                ? say('No beacon on any of these visits, so the measured clocks are unknown rather than zero.')
                : null
        ]),

        requestProfile(data.requests),

        /* THE VISITS COME FIRST. The breakdown is eleven dimensions deep, so the actual rows —
           the thing a reader opened this dialog to look at — sat below a screen and a half of
           percentages and were routinely missed. Summary first, then the long tail. */
        foldSection('dim-visits', 'The visits', [
            visitBlock(data.visitors, data.page, (start, rows) => api('sessions', 'visitors', {
                field: data.field,
                value: data.value,
                start: start,
                rows: rows || data.page.rows
            }))
        ]),

        foldSection('dim-breakdown', 'How it breaks down', [
            el('div', { class: 'fpanel' }, data.breakdowns.map((group) => breakdown(group, total)))
        ]),

        data.filterable
            ? el('p', {}, [
                dimValue(data.field, data.value, {
                    text: 'Filter everything to this ' + String(data.label).toLowerCase()
                })
            ])
            : null
    ]);
}

/** One headline figure with its label and the caveat that belongs to it. */
function statTile(label, value, hint) {
    return el('div', { class: 'stat' }, [
        el('span', { class: 'stat-label', text: label }),
        el('span', { class: 'stat-value mono', text: value }),
        el('span', { class: 'stat-hint', text: hint })
    ]);
}

/**
 * Open one dimension value.
 *
 * @param {string} field Solr field name; the server checks it against its own allowlist.
 * @param {string} value The value, exactly as it was rendered.
 */
export async function openDimension(field, value) {
    let handle = openDialog(dimLabel(field), 'Counting the visits behind this…');
    try {
        const data = await api('sessions', 'dimension', { field: field, value: value });
        if (!isCurrent(handle.generation)) {
            return;
        }
        const heading = dimHeading(data);
        handle = openDialog(heading.title, heading.sub);
        renderDimension(handle.body, data);
        markSortable(handle.body);
    } catch (err) {
        if (isCurrent(handle.generation)) {
            dialogFail(handle.body, err, () => openDimension(field, value));
        }
    }
}

/**
 * Open the full value list of one dimension.
 *
 * What a "distinct" count is pointing at. "Distinct IPs: 3" and "Distinct ASNs: 3" are counts
 * of VALUES, not of visits, so a list of sessions answers the wrong question — the reader wants
 * to know which three. Every row is the same value control as everywhere else, so any of them
 * filters the whole dashboard to itself.
 *
 * @param {string} field Solr field name; the server checks it against its own allowlist.
 */
export async function openDimList(field) {
    let handle = openDialog(dimLabel(field), 'Counting every value…');

    try {
        const data = await api('sessions', 'values', { field: field });
        if (!isCurrent(handle.generation)) {
            return;
        }
        if (data.error || !data.group) {
            fill(handle.body, [say(data.error || 'That dimension has no values in range.')]);
            return;
        }

        const buckets = Array.isArray(data.group.buckets) ? data.group.buckets : [];
        const shown = data.group.numBuckets === undefined || data.group.numBuckets === null
            ? num(buckets.length) + ' value' + (buckets.length === 1 ? '' : 's')
            : num(buckets.length) + ' of ' + num(data.group.numBuckets);

        handle = openDialog(dimLabel(field), shown + ', across ' + num(data.matched) + ' visits');
        fill(handle.body, [
            filterNote(data.active),
            el('div', { class: 'fpanel' }, [breakdown(data.group, data.matched || 0)])
        ]);
        markSortable(handle.body);
    } catch (err) {
        if (isCurrent(handle.generation)) {
            dialogFail(handle.body, err, () => openDimList(field));
        }
    }
}

/**
 * Open the visits inside one band of a numeric field — a histogram bucket.
 *
 * The score histogram's bars were counts with nothing behind them: "eight sessions scored 95"
 * with no way to see which eight, which is the only question the bar raises. The server owns
 * the field list and both bounds, so this passes them through and renders the same visit block
 * every other dialog uses.
 *
 * @param {string} band Numeric field the server allowlists.
 * @param {number} from Lower bound, inclusive.
 * @param {number} to   Upper bound, exclusive except at the top of the range.
 */
export async function openBand(band, from, to) {
    let handle = openDialog(dimLabel(band), 'Listing the visits in this band…');

    const fetchPage = (start, rows) => api('sessions', 'visitors', {
        band: band,
        from: from,
        to: to,
        start: start,
        rows: rows
    });

    try {
        const data = await fetchPage(0);
        if (!isCurrent(handle.generation)) {
            return;
        }
        if (data.error) {
            fill(handle.body, [say(data.error)]);
            return;
        }

        const total = data.page && data.page.total !== null ? data.page.total : 0;
        handle = openDialog(
            String(data.subject || dimLabel(band)),
            num(total) + ' visit' + (total === 1 ? '' : 's') + ' in this band'
        );
        fill(handle.body, [
            filterNote(data.active),
            visitBlock(data.visitors, data.page, fetchPage)
        ]);
        markSortable(handle.body);
    } catch (err) {
        if (isCurrent(handle.generation)) {
            dialogFail(handle.body, err, () => openBand(band, from, to));
        }
    }
}

/* -------------------------------------------------------------------------
 * The request-plane dialog
 * ---------------------------------------------------------------------- */

/**
 * One row of the request table inside a request-plane dialog.
 *
 * Deliberately NOT visitRow(): that renders a VISIT — entry page, verdict, a whole session's
 * conclusion — and these are individual log lines, which have a method, a status and a byte
 * count and no verdict of their own. Five columns again, because the count is the contract.
 */
function requestRow(r) {
    const tr = el('tr');

    tr.appendChild(el('td', {
        class: 'mono nowrap visit-when',
        text: when(r.ts, true),
        'data-sort': r.ts || ''
    }));

    tr.appendChild(el('td', { class: 'mono clip', title: r.ip || 'Address not recorded' }, [
        r.ip ? dimValue('ip_s', r.ip, { mono: true }) : el('span', { class: 'muted', text: '—' })
    ]));

    tr.appendChild(el('td', { class: 'clip' }, [
        r.country
            ? dimValue('country_s', r.country, { markOnly: true })
            : el('span', { class: 'muted', text: '—' })
    ]));

    tr.appendChild(el('td', { class: 'clip urlcell', title: (r.method || '') + ' ' + (r.path || '') }, [
        el('span', { class: 'mono muted', text: (r.method || '') + ' ' }),
        r.path ? pathCell(r.path + (r.query ? '?' + r.query : ''), { host: r.host }) : el('span', { text: '—' })
    ]));

    tr.appendChild(el('td', { class: 'num mono' }, [
        r.status === null || r.status === undefined
            ? el('span', { class: 'muted', text: '—' })
            : dimValue('status_i', r.status, { mono: true })
    ]));

    return tr;
}

/** The request table, head and body, in the shape the visit table uses. */
function requestTable(rows) {
    const table = el('table', { class: 'table-fixed visits' }, [
        el('colgroup', {}, [
            el('col', { style: 'width:23%' }),
            el('col', { style: 'width:17%' }),
            el('col', { style: 'width:6%' }),
            el('col', { style: 'width:44%' }),
            el('col', { style: 'width:10%' })
        ]),
        el('thead', {}, [
            el('tr', {}, ['Date', 'IP', 'Country', 'Request', 'Status']
                .map((t) => el('th', { scope: 'col', text: t })))
        ]),
        el('tbody', {}, rows.map(requestRow))
    ]);

    return el('div', { class: 'table-wrap' }, [table]);
}

/**
 * Open one value on the REQUEST plane.
 *
 * The sibling of openDimension(), for the dimensions that belong to a request rather than to a
 * visit — a status code, a method, an attack pattern. Those live only on the hits core, so the
 * visits dialog could only ever have answered zero for them; this asks the plane that holds
 * the answer and shows the same things every other dialog shows: the headline counts, when it
 * happened, the rows themselves, and how they break down.
 *
 * @param {string} field Solr field name; the server checks it against its own allowlist.
 * @param {string} value The value, exactly as it was rendered.
 * @param {string} [view] The view whose API answers this. Defaults to Performance, which is
 *                        where the status tables live.
 */
export async function openHitDimension(field, value, view) {
    const target = view || 'performance';
    let handle = openDialog(dimLabel(field), 'Counting the requests behind this…');

    const fetchPage = (start, rows) => api(target, 'hitdim', {
        field: field,
        value: value,
        start: start,
        rows: rows
    });

    try {
        const data = await fetchPage(0);
        if (!isCurrent(handle.generation)) {
            return;
        }
        if (data.error) {
            handle = openDialog(dimLabel(field), '');
            fill(handle.body, [say(data.error)]);
            return;
        }

        handle = openDialog(
            String(data.label) + ': ' + valueText(field, data.value),
            num(data.requests) + ' request' + (data.requests === 1 ? '' : 's')
                + ' in ' + (data.range_label || 'the selected range')
        );
        renderHitDimension(handle.body, data, fetchPage);
        markSortable(handle.body);
    } catch (err) {
        if (isCurrent(handle.generation)) {
            dialogFail(handle.body, err, () => openHitDimension(field, value, view));
        }
    }
}

/**
 * Open every request at or above a threshold — what a percentile tile is pointing at.
 *
 * "p95 is 749 ms" is a fact with one obvious follow-up, and the tile used to answer none of it.
 * The threshold travels as a number the server clamps; everything else is the request dialog
 * already built above, so the slow requests arrive with their addresses, paths and breakdowns
 * exactly as any other opened value does.
 *
 * @param {string} band  Numeric request field the server allowlists.
 * @param {number} from  Lower bound, inclusive.
 * @param {string} [view] View whose API answers this.
 * @param {string} [label] What the tile called the threshold, for the dialog's subtitle.
 */
export async function openHitBand(band, from, view, label) {
    const target = view || 'performance';
    let handle = openDialog(label || dimLabel(band), 'Counting the requests above this…');

    const fetchPage = (start, rows) => api(target, 'hitdim', {
        band: band,
        from: from,
        start: start,
        rows: rows
    });

    try {
        const data = await fetchPage(0);
        if (!isCurrent(handle.generation)) {
            return;
        }
        if (data.error) {
            fill(handle.body, [say(data.error)]);
            return;
        }

        handle = openDialog(
            (label || String(data.label)) + ' and slower',
            num(data.requests) + ' request' + (data.requests === 1 ? '' : 's')
                + ' in ' + (data.range_label || 'the selected range')
        );
        renderHitDimension(handle.body, data, fetchPage);
        markSortable(handle.body);
    } catch (err) {
        if (isCurrent(handle.generation)) {
            dialogFail(handle.body, err, () => openHitBand(band, from, view, label));
        }
    }
}

/**
 * Draw a request-plane dialog.
 *
 * Same order as the visits dialog for the same reason: the counts, then when, then the ROWS —
 * the thing the reader opened it for — and the breakdown last, because eleven dimensions of
 * percentages above the data is how the rows got missed before.
 */
function renderHitDimension(body, data, fetchPage) {
    const total = data.requests || 0;
    const mount = el('div', { class: 'pager-mount' });
    const wrap = requestTable(data.rows || []);

    const show = (state) => {
        renderPager(mount, state, async (start, rows) => {
            mount.replaceChildren(el('p', { class: 'muted', text: 'Loading page…' }));
            try {
                const next = await fetchPage(start, rows);
                const table = wrap.querySelector('tbody');
                table.replaceChildren(...(next.rows || []).map(requestRow));
                markSortable(wrap);
                show(next.page);
            } catch (err) {
                const again = el('button', { type: 'button', class: 'small', text: 'Try again' });
                again.addEventListener('click', () => show(state));
                mount.replaceChildren(
                    el('p', { class: 'muted', text: 'That page could not be loaded.' }),
                    el('div', { class: 'card-error-actions' }, [again])
                );
            }
        });
    };

    fill(body, [
        el('div', { class: 'stats' }, [
            statTile('Requests', num(total), 'In range, under the active filters'),
            statTile('Addresses', num(data.uniq_ips), 'Distinct clients behind them'),
            statTile('Pages', num(data.uniq_paths), 'Distinct paths asked for'),
            statTile('Visits', num(data.uniq_sessions), 'Sessions these requests belong to')
        ]),

        (data.ignored || []).length
            ? say('Not narrowed by ' + data.ignored.join(', ')
                + ': those are conclusions about a whole visit, and this counts requests.')
            : null,

        foldSection('req-when', 'When, and how much', [
            kv([
                ['First seen', when(data.first), true],
                ['Last seen', when(data.last), true],
                ['Data sent', bytes(data.bytes), true]
            ])
        ]),

        foldSection('req-list', 'The requests', [wrap, mount]),

        foldSection('req-breakdown', 'How it breaks down', [
            el('div', { class: 'fpanel' }, (data.breakdowns || []).map((group) => breakdown(group, total)))
        ])
    ]);

    show(data.page);
}

/* -------------------------------------------------------------------------
 * The population dialog
 * ---------------------------------------------------------------------- */

/**
 * Open the visits behind one of the five headline populations.
 *
 * WHAT THIS FIXES. The Overview's five tiles — human sessions, evasive bots, declared crawlers,
 * AI crawlers, unknown — were inert text. Five numbers naming five populations, with no way to
 * look at a single member of any of them: the most natural gesture on a dashboard, pressing the
 * big number, did nothing at all.
 *
 * @param {string} key  A population key the server allowlists (human, evasive, declared, ai, unknown).
 * @param {string} why  The one sentence that says what the population is, from the tile itself.
 */
export async function openPopulation(key, why) {
    const name = populationLabel(key);
    let handle = openDialog(name, 'Listing the visits behind this figure…');
    try {
        const data = await api('sessions', 'visitors', { pop: key, start: 0, rows: 20 });
        if (!isCurrent(handle.generation)) {
            return;
        }
        const total = data.page && data.page.total !== null ? data.page.total : null;
        handle = openDialog(
            name,
            (total === null ? '' : num(total) + ' visits in ') + (data.range_label || 'the selected range')
        );

        fill(handle.body, [
            say(why, 'muted'),
            filterNote(data.active),
            visitBlock(data.visitors, data.page, (start, rows) => api('sessions', 'visitors', {
                pop: key,
                start: start,
                rows: rows || data.page.rows
            }))
        ]);
        markSortable(handle.body);
    } catch (err) {
        if (isCurrent(handle.generation)) {
            dialogFail(handle.body, err, () => openPopulation(key, why));
        }
    }
}

/**
 * Register the three openers.
 *
 * Called once from app.js, so every view has them without each view remembering to. The
 * registration is idempotent: a second call replaces the same entries.
 */
export function initDetail() {
    registerOpener('session', (data) => openSession(data.id || ''));
    registerOpener('dim', (data) => openDimension(data.field || '', data.value || ''));
    registerOpener('pop', (data) => openPopulation(data.pop || '', data.why || ''));
    registerOpener('hitdim', (data) =>
        openHitDimension(data.field || '', data.value || '', data.view || ''));
    registerOpener('band', (data) =>
        openBand(data.band || '', Number(data.from) || 0, Number(data.to) || 0));
    registerOpener('hitband', (data) =>
        openHitBand(data.band || '', Number(data.from) || 0, data.view || '', data.label || ''));
    registerOpener('dimlist', (data) => openDimList(data.dim || ''));

    const open = new URLSearchParams(window.location.search).get('open');
    if (open) {
        openSession(open);
    }
}

export { closeDialog };
