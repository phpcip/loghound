/*
 * Loghound — Plan usage.
 *
 * WHERE THE ALWAYS-VISIBLE WARNING WENT. There used to be a bandwidth strip in the page header
 * of every view, polling on its own. Bandwidth is the only quota that cannot be reclaimed by
 * deleting anything — it accrues with use, resets on the 1st, and going over it blocks the index
 * completely, Opensolr answering 403 to reads as well as writes — so it genuinely does deserve
 * to be reachable from anywhere. It is: the top bar carries an Opensolr resources control on
 * every page, and behind it is the whole account rather than the one figure the strip had room
 * for, including the two quotas the strip never mentioned. See assets/js/topbar.js.
 *
 * Disk gets none of that treatment, deliberately. The rolling trim deletes the oldest data
 * before each write, so the index does not reach its disk quota and the blackout never
 * triggers on disk. Presenting it as a risk would be warning the operator about the one
 * thing the feature makes impossible. On this page it is a neutral statement of how far back
 * the data goes. The single exception is a trim that FAILED near the limit, which is a real
 * fault and is rendered as one.
 *
 * Every value rendered here came off the wire and goes into the DOM through textContent or
 * through el({text}). Nothing is interpolated into markup.
 */

'use strict';

import { api, byId, dayOnly, dec, el, fill, loadCard, num, setPop } from '../core.js';
import { t as T, tn as Tn, tf as Tf, tfn as Tfn } from '../i18n.js';

/** Levels a figure is drawn loud at. Below these it stays a quiet line of type. */
const LOUD = ['warn', 'critical', 'blocked'];

/**
 * Render megabytes at the scale a human reads them.
 *
 * Mirrors \Loghound\Quota::mb() so the same figure reads the same way whether it was
 * rendered by PHP into the page or by JavaScript into the strip.
 */
function mb(value) {
    if (value === null || value === undefined || Number.isNaN(value)) {
        return '—';
    }
    const v = Number(value);
    if (v >= 1048576) {
        return dec(v / 1048576, 1) + ' TB';
    }
    if (v >= 1024) {
        return dec(v / 1024, 1) + ' GB';
    }
    if (v >= 10) {
        return num(v) + ' MB';
    }
    return dec(v, 1) + ' MB';
}

/** A day count as a phrase, mirroring \Loghound\Quota::days(). */
function days(value) {
    if (value === null || value === undefined || Number.isNaN(value)) {
        return '—';
    }
    const v = Number(value);
    if (v < 1) {
        const hours = Math.max(1, Math.round(v * 24));
        return Tn('{n} hour', '{n} hours', hours);
    }
    if (v < 10) {
        return T('{n} days', { n: dec(v, 1) });
    }
    return Tn('{n} day', '{n} days', Math.round(v), { n: num(v) });
}

/**
 * A flat proportion bar.
 *
 * `.meter` is the panel's existing bar; the accent is applied only when the level is one
 * the operator is meant to act on, so a healthy meter is a hairline rather than a colour.
 */
function bar(percent, level) {
    const width = Math.max(0, Math.min(100, Number(percent) || 0));
    return el('span', { class: 'meter', role: 'img', 'aria-label': T('{pct}% used', { pct: dec(width, 1) }) }, [
        el('span', {
            class: 'meter-fill' + (LOUD.includes(level) ? ' meter-fill-loud' : ''),
            style: 'width:' + width + '%'
        })
    ]);
}

/* -------------------------------------------------------------------------
 * The Plan usage view
 * ---------------------------------------------------------------------- */

/**
 * One meter per index, with the consequence spelled out for any that is over.
 */
function renderBandwidth(data) {
    const mount = byId('usage-bw-meters');
    if (!mount) {
        return;
    }

    if (!data.cores.length) {
        fill(mount, [el('p', { class: 'faint', text: data.demo_note ||
            T('No Opensolr-managed index is configured, so there is no plan limit to report against.') })]);
        /* A CAPTION NAMES ITS POPULATION EVEN WHEN THE POPULATION IS EMPTY. "Nothing to
           measure yet" says nothing at all: not what would be measured, not why there is
           none, not what would put something there. */
        setPop('usage-bw', T('No Opensolr-managed index, so there is no metered bandwidth to '
            + 'report. Finish setup, or point Loghound at a managed index, and this fills in.'));
        return;
    }

    fill(mount, data.cores.map((row) => {
        const known = row.ratio !== null && row.ratio !== undefined;
        return el('div', { class: 'meterrow meterrow-' + String(row.level || 'unknown') }, [
            el('div', { class: 'meterrow-head' }, [
                el('span', { class: 'meterrow-name mono', text: row.core }),
                el('span', { class: 'meterrow-role', text: row.role === 'hits' ? T('hits') : T('sessions') }),
                el('span', {
                    class: 'meterrow-value mono',
                    text: known ? T('{used} of {limit}', { used: mb(row.used_mb), limit: mb(row.limit_mb) }) : T('not known')
                })
            ]),
            bar(row.percent, row.level),
            el('p', { class: 'meterrow-note', text: known
                ? row.headline + ' ' + T('{pct}% used, resetting in {when}.', { pct: dec(row.percent, 1), when: days((Number(row.resets_in) || 0) / 86400) })
                : (row.note || T('Opensolr has not reported usage for this index.')) })
        ]);
    }));

    const worst = data.worst;
    setPop('usage-bw', worst && worst.ratio !== null && worst.ratio !== undefined
        ? T('Highest usage across your indexes: {pct}% of the plan, warning from {warn}%. The counter resets on the 1st.',
            { pct: dec(worst.percent, 1), warn: dec(worst.warn_at, 0) })
        : T('Bandwidth usage has not been read from Opensolr yet.'));
}

/**
 * The retention window, per index. Neutral: this is how far back the data goes.
 *
 * The observed span and the projected window are rendered as two separate facts, because one
 * is read off the index and the other is arithmetic on a growth rate, and presenting them as
 * one number would give the estimate a confidence it has not got.
 */
function renderWindow(data) {
    const mount = byId('usage-window-rows');
    if (!mount) {
        return;
    }

    if (!data.cores.length) {
        fill(mount, [el('p', { class: 'faint', text: data.demo_note ||
            T('No Opensolr-managed index is configured, so the retention window has no plan limit to '
            + 'work against. Only the time-based limit below applies.') })]);
        setPop('usage-window', T('No Opensolr-managed index, so there is no disk quota to size '
            + 'a retention window against. The time-based limit still applies.'));
        return;
    }

    const rows = [];
    for (const row of data.cores) {
        const w = row.window;

        if (row.blocked) {
            rows.push(el('div', { class: 'callout callout-bad', role: 'alert' }, [
                el('h4', { text: T('{index} is blocked', { index: row.core }) }),
                el('p', { text: row.blocked.text })
            ]));
        }
        if (w.trim_alert) {
            rows.push(el('div', { class: 'callout callout-bad', role: 'alert' }, [
                el('h4', { text: T('Space could not be freed in {index}', { index: row.core }) }),
                el('p', { text: w.trim_alert.text })
            ]));
        }

        rows.push(el('div', { class: 'windowrow' }, [
            el('div', { class: 'windowrow-head' }, [
                el('span', { class: 'windowrow-name mono', text: row.core }),
                el('span', { class: 'windowrow-role', text: row.role === 'hits' ? T('hits') : T('sessions') })
            ]),
            el('div', { class: 'stats stats-tight' }, [
                stat(T('Held now'), row.span.days === null ? '—' : days(row.span.days),
                    /* mm/dd/yyyy, like every other date in the panel. This was the only one
                       rendered as an ISO prefix, by slicing the first ten characters off the
                       instant — which also threw the time away with no way to get it back. */
                    row.span.oldest ? T('oldest document {day}', { day: dayOnly(row.span.oldest) }) : T('measured from the index')),
                stat(T('Plan window'), w.plan_days === null ? '—' : days(w.plan_days),
                    w.max_size_mb === null ? T('no plan limit read') : T('estimated for {size}', { size: mb(w.max_size_mb) })),
                stat(T('Ingest'), w.ingest_mb_day === null ? '—' : T('{size}/day', { size: mb(w.ingest_mb_day) }),
                    w.ingest_mb_day === null ? T('needs two readings') : T('from observed growth')),
                stat(T('Index size'), w.size_mb === null ? '—' : mb(w.size_mb),
                    w.estimated ? T('projected since the last reading') : T('as Opensolr reported it'))
            ]),
            el('p', { class: 'windowrow-say', text: w.sentence })
        ]));
    }

    fill(mount, rows);

    /* "NEITHER — NOTHING IS BEING DELETED" WAS NOT A SAFE THING TO SAY. `limited_by` is 'none'
       whenever the window cannot be PROJECTED, which on a fresh install is the state for the
       first ten minutes even with the disk rule switched on. `window.enabled` is the disk
       rule's actual setting and is what the two honest branches below read. */
    const first = data.cores.length ? data.cores[0].window : null;
    setPop('usage-window', first
        ? T('Two limits apply and the shorter one wins. Currently: {which}', {
            which: first.limited_by === 'size' ? T('the plan window.')
                : first.limited_by === 'time' ? T('your age limit.')
                    : first.enabled
                        ? T('not yet known — the disk rule is on, but the window it leaves cannot be '
                          + 'projected until the ingest rate has been measured.')
                        : T('neither — there is no age limit and deleting for size is switched off.')
        })
        : T('No index usage is available.'));
}

/** One label/value/hint block, matching the panel's existing stat markup. */
function stat(label, value, hint) {
    return el('div', { class: 'stat' }, [
        el('span', { class: 'stat-label', text: label }),
        el('span', { class: 'stat-value mono', text: value }),
        el('span', { class: 'stat-hint', text: hint })
    ]);
}

/**
 * The two limits, side by side, with the one currently in effect marked.
 */
function renderLimits(data) {
    const table = byId('usage-limits-table');
    if (!table) {
        return;
    }
    const body = table.tBodies[0] || table.appendChild(document.createElement('tbody'));
    const first = data.cores.length ? data.cores[0].window : null;
    const inEffect = first ? first.limited_by : 'none';

    /* A ROW SAYS WHETHER ITS RULE IS ON, SEPARATELY FROM HOW LONG A WINDOW IT LEAVES. The
       size row read "not known yet" whether the rule was switched off or merely unprojected,
       which are opposite facts: one means nothing is trimming the index, the other means
       something is and the figure is pending. */
    const sizeOn = first ? first.enabled !== false : true;
    const rows = [
        {
            limit: T('Time-based'),
            by: 'privacy.retention_days',
            window: data.retention_days > 0 ? days(data.retention_days) : T('no age limit'),
            active: inEffect === 'time',
            off: !(data.retention_days > 0)
        },
        {
            limit: T('Size-based'),
            by: T('your Opensolr plan'),
            window: !sizeOn
                ? T('switched off')
                : (first && first.plan_days !== null ? days(first.plan_days) : T('not known yet')),
            active: inEffect === 'size',
            off: !sizeOn
        }
    ];

    fill(body, rows.map((row) => el('tr', { class: row.active ? 'row-on' : null }, [
        el('td', {}, [el('strong', { text: row.limit })]),
        el('td', { class: 'mono', text: row.by }),
        el('td', { class: 'num mono', text: row.window }),
        el('td', {}, [el('span', {
            class: 'chip' + (row.active ? ' chip-accent' : ''),
            text: row.active ? T('in effect') : (row.off ? T('switched off') : T('not the limit'))
        })])
    ])));

    const onCount = rows.filter((row) => !row.off).length;
    setPop('usage-limits', onCount === 0
        ? T('Both limits are switched off, so nothing is deleted for age or for size. An index that '
          + 'reaches its Opensolr disk quota is blocked by the platform, reads included.')
        : onCount === 1
            ? T('One of the two is switched on; it is the only thing deciding how much history is kept.')
            : T('Both run on their own schedule; the one that deletes sooner is the one you see.'));
}

/**
 * Entry point for the Plan usage view.
 *
 * The bandwidth meter is its own request and settles on its own, because it is the number
 * the operator came for and it must not wait behind a Solr facet.
 *
 * The window and the limits cards are two views of ONE answer, so they share one in-flight
 * promise rather than asking twice. Both still go through loadCard(), so each keeps its own
 * progress line and its own retry, and a failure is reported in both places rather than
 * leaving one card spinning for ever.
 */
export default function init() {
    loadCard('usage-bw', T('Reading plan usage from Opensolr'), async () => {
        renderBandwidth(await api('usage', 'meter'));
    });

    const plan = api('usage', 'plan');

    loadCard('usage-window', T('Measuring the retention window'), async () => {
        renderWindow(await plan);
    });
    loadCard('usage-limits', T('Comparing the retention limits'), async () => {
        renderLimits(await plan);
    });
}
