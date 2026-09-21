/*
 * Loghound — the bounce-rate card, rendered the same way everywhere it appears.
 *
 * ONE RENDERER, because the metric appears on two pages and a metric whose definition is stated
 * twice is a metric that will eventually be stated two ways. The numbers come from Panel\Bounce,
 * which is the definition; this is the presentation of it.
 *
 * THE HEADLINE IS THE MEASURED RATE, NOT A BLEND. It is computed over the visits a beacon
 * reported on, because those are the only ones where "did they do anything on that page" is a
 * measurement. Visits without a beacon sit beside it under their own denominator. Averaging the
 * two would present a guess and a measurement as one number.
 *
 * The conventional figure is a tile of the same size, because somebody migrating needs to see
 * why the two differ rather than be told the old one was wrong.
 */

'use strict';

import { byId, el, fill, num, pct, setPop } from './core.js';
import { t as T, tn as Tn, tf as Tf, tfn as Tfn } from './i18n.js';

/** A percentage of a total, or an em-dash when the denominator is zero. */
function rate(part, total) {
    return total ? pct(part, total, 1) : '—';
}

/**
 * One headline figure with its label and the caveat that belongs to it.
 */
function tile(label, value, hint) {
    return el('div', { class: 'stat' }, [
        el('span', { class: 'stat-label', text: label }),
        el('span', { class: 'stat-value mono', text: value }),
        el('span', { class: 'stat-hint', text: hint })
    ]);
}

/**
 * The four tiles.
 *
 * @param {Object} b The `bounce` block from the server.
 * @returns {Array<Node>}
 */
function tiles(b) {
    const m = b.measured;
    const a = b.assumed;
    const seconds = Math.round(b.threshold_ms / 1000);

    return [
        tile(
            T('Bounce rate'),
            rate(m.bounced, m.sessions),
            m.sessions
                ? T('{n} of {total} human visits that loaded a page and ran a beacon.', { n: num(m.bounced), total: num(m.sessions) })
                : T('No human visit that loaded a page reported a beacon.')
        ),
        tile(
            T('Read one page and stayed'),
            rate(m.satisfied, m.sessions),
            m.sessions
                ? T('{n} visits: one page, {seconds} seconds or more engaged. Another tool '
                    + 'counts these as bounces.', { n: num(m.satisfied), seconds: seconds })
                : T('Needs a beacon, and none ran in this range.')
        ),
        tile(
            T('One page, engagement unknown'),
            rate(a.single, a.sessions),
            a.sessions
                ? T('{n} of {total} human visits that loaded a page had no beacon. '
                    + 'Not part of the rate above.', { n: num(a.single), total: num(a.sessions) })
                : T('Every human visit that loaded a page reported a beacon.')
        ),

        /* DIVIDED BY THE SESSIONS THAT LOADED A PAGE, not by every session: the tool this
           imitates counts pageviews, so a session that never loaded one does not exist in it. */
        tile(
            T('The conventional definition'),
            rate(b.conventional, b.all_landed),
            T('{n} of {total} sessions with a pageview had exactly one, bots '
                + 'included. The figure another tool would print for this traffic.', { n: num(b.conventional), total: num(b.all_landed) })
        )
    ];
}

/**
 * The coverage sentence, which is the one that keeps the headline honest.
 *
 * @param {Object} b
 * @returns {Array<Node>}
 */
function coverage(b) {
    const m = b.measured;
    const a = b.assumed;
    const out = [];

    if (b.people === 0) {
        out.push(el('p', { class: 'muted', text:
            T('No human visit in this range has finished yet, so there is nothing to measure.') }));
        return out;
    }

    if (b.landed === 0) {
        out.push(el('p', { class: 'muted', text:
            T('None of the {n} completed human visits in this range loaded a page, so there is ' +
            'no bounce rate to state.', { n: num(b.people) }) }));
        return out;
    }

    out.push(el('p', { class: 'muted', text:
        T('{n} of {total} completed human visits that loaded a page ({pct}) had a beacon and are what the rate is measured on. The other ' +
        '{rest} are judged on page count and reported separately.', {
            n: num(m.sessions),
            total: num(b.landed),
            pct: pct(m.sessions, b.landed, 0),
            rest: num(a.sessions)
        }) }));

    /* THE PAGE-LESS VISITS ARE NAMED, NOT DROPPED QUIETLY. They used to be counted as one-page
       visits, which is what made the metric wrong; saying how many there were is what stops the
       correction from looking like sessions going missing. */
    if (b.nopage > 0) {
        out.push(el('p', { class: 'muted', text:
            Tn('{n} further human visit loaded no page at all — assets, feeds, robots.txt or API endpoints only — so nobody arrived ' +
            'anywhere to bounce from, and they are outside every figure on this card.',
            '{n} further human visits loaded no page at all — assets, feeds, robots.txt or API endpoints only — so nobody arrived ' +
            'anywhere to bounce from, and they are outside every figure on this card.', b.nopage, { n: num(b.nopage) }) }));
    }

    if (b.unclassified > 0) {
        out.push(el('p', { class: 'muted', text:
            Tn('{n} visit carried no page count at all and are excluded from every figure above.',
            '{n} visits carried no page count at all and are excluded from every figure above.', b.unclassified, { n: num(b.unclassified) }) }));
    }

    return out;
}

/**
 * The comparison table: the outcomes a human visit that loaded a page can have, with their counts.
 *
 * A table rather than more tiles because these rows are a partition — they sum to the visits that
 * loaded a page — and a reader checking that they do is the point of printing them. Visits that
 * loaded no page are not a sixth row here; they are not an outcome of arriving anywhere, and the
 * coverage sentence above states how many there were.
 */
function outcomes(b) {
    const m = b.measured;
    const a = b.assumed;

    const seconds = Math.round(b.threshold_ms / 1000);
    const rows = [
        [T('Bounced'), m.bounced, T('One page, under {seconds}s engaged', { seconds: seconds })],
        [T('One page, but engaged'), m.satisfied, T('One page, {seconds}s or more engaged', { seconds: seconds })],
        [T('More than one page'), m.multi, T('Beacon present')],
        [T('One page, no beacon'), a.single, T('Engagement not measured')],
        [T('More than one page, no beacon'), a.multi, T('Engagement not measured')]
    ];

    /* THE SHARE IS OF THE VISITS THAT LOADED A PAGE, which is what the five rows partition. It
       used to divide by every completed human visit, so the column summed to well under 100%
       whenever page-less visits were in range and nothing on the card said why. */
    const body = el('tbody', {}, rows.map(([label, count, why]) => el('tr', {}, [
        el('td', { text: label }),
        el('td', { class: 'num', text: num(count) }),
        el('td', { class: 'num', text: rate(count, b.landed) }),
        el('td', { class: 'muted', text: why })
    ])));

    const table = el('table', { class: 'tight table-fixed' }, [
        el('colgroup', {}, ['30%', '12%', '12%', '46%'].map((w) => el('col', { style: 'width:' + w }))),
        el('thead', {}, [el('tr', {}, [
            el('th', { scope: 'col', text: T('Outcome') }),
            el('th', { scope: 'col', class: 'num', text: T('Visits') }),
            el('th', { scope: 'col', class: 'num', text: T('Share') }),
            el('th', { scope: 'col', text: T('Evidence') })
        ])]),
        body
    ]);

    return el('div', {}, [
        el('h3', { text: T('Outcomes') }),
        el('div', { class: 'table-wrap' }, [table])
    ]);
}

/**
 * Render the whole card.
 *
 * @param {string} id The card's base id, as handed to Panel\Sessions::bounceCard().
 * @param {Object} data The payload carrying a `bounce` block.
 */
export function renderBounce(id, data) {
    const b = data.bounce;
    const stats = byId(id + '-stats');
    const detail = byId(id + '-detail');

    if (stats) {
        fill(stats, tiles(b));
    }
    if (detail) {
        fill(detail, coverage(b).concat([outcomes(b)]));
    }

    setPop(id, b.definition);
}
