/*
 * Loghound — a card whose table is paged, wired once.
 *
 * Every analytics table in the panel is the same three things: a fetch that takes an offset, a
 * renderer that fills a `<tbody>`, and a pager underneath that re-runs the fetch. Written out per
 * card that is three chances each to forget the empty state, to forget that the refresh control
 * must reload the page the reader is ON rather than the first one, and to let a failed page turn
 * replace a card full of working content with an error.
 *
 * A page turn goes back through core.js's loadCard(), which is deliberate: the card gets its own
 * worded progress line, its own failure box and its own retry for page seven exactly as it had
 * for page one, and the refresh control in the card head re-runs the page currently on screen
 * because loadCard() remembers the LAST loader it was given.
 */

'use strict';

import { byId, el, loadCard, noDataYet, num, pct } from './core.js';
import { renderPager } from './pager.js';

/**
 * Wire a card whose table pages server-side, and load its first page.
 *
 * @param {Object} spec
 * @param {string} spec.id      Card base id, matching Controller::cardOpen().
 * @param {string} spec.label   What is happening, in words, for the progress line.
 * @param {string} spec.empty   PLURAL NOUN naming the population, for the empty state.
 * @param {Function} spec.fetch (start) => Promise<Object> — must resolve a payload with `page`.
 * @param {Function} spec.render (data) => true|false|'own' — fills the table. `false` asks for the
 *                   standard empty state; `'own'` means the renderer has already written one of
 *                   its own, which is what a card that can distinguish "not configured" from "no
 *                   data" needs — overwriting it with the generic sentence would throw away the
 *                   only difference the reader cares about.
 * @returns {Function} The loader, so a control that changes the query can re-run it from page one.
 */
export function pagedCard(spec) {
    const pagerMount = () => byId(spec.id + '-pager');

    const load = (start) => loadCard(spec.id, spec.label, async () => {
        const data = await spec.fetch(start || 0);
        const outcome = spec.render(data);

        if (outcome === false || outcome === 'own') {
            const mount = pagerMount();
            if (mount) {
                mount.replaceChildren();
            }
            if (outcome === false) {
                noDataYet(spec.id + '-empty', spec.empty);
            }
            return;
        }
        renderPager(pagerMount(), data.page, load);
    });

    load(0);

    return load;
}

/**
 * The proportional bar every top-N table ends in.
 *
 * THE DENOMINATOR IS THE TOTAL, NEVER THE BIGGEST ROW. Dividing by `rows[0]` makes the top row
 * exactly full width on every table in the product and every other row a proportion of THAT —
 * which looks like a percentage and is not one. On a long tail it is close to a lie: the three
 * busiest paths of a real site can be 4%, 3% and 3% of its traffic and were drawn as 100%, 75%
 * and 75%, which reads as "these three are the site".
 *
 * The caller passes what the share is OF, and the title says so in words, because a bar whose
 * denominator the reader has to guess is a bar they will guess wrong.
 *
 * @param {number} value
 * @param {number} total The population the share is of.
 * @param {string} [unit] Plural noun naming that population, for the title.
 * @returns {HTMLElement}
 */
export function shareBar(value, total, unit) {
    const share = total > 0 ? (value / total) * 100 : 0;
    const width = Math.max(share > 0 ? 1 : 0, Math.min(100, Math.round(share)));

    return el('span', {
        class: 'bar',
        title: total > 0
            ? pct(value, total) + ' of ' + num(total) + (unit ? ' ' + unit : '')
            : 'Nothing to take a share of'
    }, [el('span', { style: 'width:' + width + '%' })]);
}

/**
 * A bar that compares MAGNITUDES rather than showing a share.
 *
 * Kept apart from shareBar() on purpose. A movement between two periods is not a fraction of
 * anything — there is no total a change is a part of — so the only comparison available is
 * against the largest change on the page, and that is exactly the normalisation shareBar() exists
 * to refuse. It is honest here only because the title names the reference, which is the test:
 * would the reader guess the same denominator.
 *
 * @param {number} value
 * @param {number} peak  The largest magnitude on this page.
 * @param {string} against What the bar is measured against, in words.
 * @param {string} [detail] The row's own figures, appended to the title.
 * @returns {HTMLElement}
 */
export function magnitudeBar(value, peak, against, detail) {
    const width = peak > 0 ? Math.max(value > 0 ? 1 : 0, Math.min(100, Math.round((value / peak) * 100))) : 0;

    return el('span', {
        class: 'bar',
        title: (detail ? detail + '. ' : '') + 'Drawn against ' + against + ', not as a share of a total.'
    }, [el('span', { style: 'width:' + width + '%' })]);
}

/**
 * A signed change, written the way a person says it.
 *
 * A page that had no traffic at all in the baseline has no multiplier — "infinity times more" is
 * not a fact — so it is called new, which is what it is. A page that has gone to nothing is
 * called gone. Everything else gets its arithmetic difference, signed, because that is what the
 * table is sorted by and a column sorted by one number and displaying another is a table nobody
 * can check.
 *
 * @param {number} now
 * @param {number} prev
 * @returns {HTMLElement}
 */
export function changeCell(now, prev) {
    const delta = now - prev;

    if (prev === 0 && now > 0) {
        return el('span', { class: 'chip chip-accent', text: 'new' });
    }
    if (now === 0 && prev > 0) {
        return el('span', { class: 'chip', text: 'gone' });
    }
    if (delta === 0) {
        return el('span', { class: 'muted', text: 'no change' });
    }

    return el('span', {
        class: 'mono' + (delta > 0 ? ' trend-up' : ' trend-down'),
        text: (delta > 0 ? '+' : '−') + Math.abs(delta).toLocaleString('en-US')
    });
}
