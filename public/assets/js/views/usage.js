/*
 * Loghound — Plan usage, and the bandwidth strip that appears on every page.
 *
 * Two exports, and the second one is the important one.
 *
 * `initBandwidthStrip()` runs on EVERY view. Bandwidth is the only quota that cannot be
 * reclaimed by deleting anything: it accrues with use and resets on the 1st, and going over
 * it blocks the index completely — Opensolr answers 403 to every request, reads as well as
 * writes — until the plan is upgraded or the month rolls over. The warning therefore has to
 * arrive well before the limit, because after the limit the panel that would have shown it
 * is dark. So the indicator lives in the page header rather than on one card, it refreshes
 * on its own without a reload, and it carries the upgrade link with it.
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

/**
 * How often the strip re-reads the meter, in milliseconds.
 *
 * WHY THIS NUMBER, since the dashboard's own queries are part of what it measures. Each
 * refresh is one request to this panel, which answers from a cache on disk and only reaches
 * the Opensolr control plane once every `quota.refresh_sec` seconds (five minutes by
 * default) — and that call goes to the control plane, not to the index, so it costs the
 * index nothing at all. Polling faster than the cache refreshes would produce identical
 * numbers at real cost; polling much slower would let an operator sit in front of a stale
 * meter for an hour while the month's allowance ran out. Ninety seconds is comfortably
 * inside the cache window, so on a small plan an auto-refreshing dashboard left open all day
 * adds a handful of local requests per hour and no index traffic.
 *
 * The server sends its own `refresh_sec` and the strip takes whichever is longer, so raising
 * the cache interval automatically slows the polling to match.
 */
/** Ceiling for the backoff after a failed read: slow enough not to hammer, soon enough to notice. */
const STRIP_MAX_BACKOFF_MS = 300000;

const STRIP_POLL_MS = 90000;

/** Levels that make the strip loud. Below these it stays a quiet line of type. */
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
        return hours + (hours === 1 ? ' hour' : ' hours');
    }
    if (v < 10) {
        return dec(v, 1) + ' days';
    }
    return num(v) + ' days';
}

/**
 * A flat proportion bar.
 *
 * `.meter` is the panel's existing bar; the accent is applied only when the level is one
 * the operator is meant to act on, so a healthy meter is a hairline rather than a colour.
 */
function bar(percent, level) {
    const width = Math.max(0, Math.min(100, Number(percent) || 0));
    return el('span', { class: 'meter', role: 'img', 'aria-label': dec(width, 1) + '% used' }, [
        el('span', {
            class: 'meter-fill' + (LOUD.includes(level) ? ' meter-fill-loud' : ''),
            style: 'width:' + width + '%'
        })
    ]);
}

/* -------------------------------------------------------------------------
 * The always-visible strip
 * ---------------------------------------------------------------------- */

/**
 * Insert (or update) the bandwidth strip in the page header.
 *
 * Built by JavaScript rather than rendered by PHP for the reason every other number in this
 * panel is: the figure behind it comes from an external API, and no page render in Loghound
 * is allowed to block on one. The element is created on first success, so a panel with no
 * Opensolr account, or one whose route is not wired up, simply never grows a strip rather
 * than showing an empty box for ever.
 */
function paintStrip(data) {
    const slot = byId('lh-readout');
    const worst = data && data.worst;
    if (!slot || !worst || worst.ratio === null || worst.ratio === undefined) {
        return;
    }

    let strip = byId('lh-bw');
    if (!strip) {
        strip = el('div', { class: 'bwstrip', id: 'lh-bw' });
        slot.appendChild(strip);
    }

    const level = String(worst.level || 'unknown');
    strip.className = 'bwstrip bwstrip-' + level;
    strip.setAttribute('role', LOUD.includes(level) ? 'alert' : 'status');

    const detail = mb(worst.used_mb) + ' of ' + mb(worst.limit_mb) +
        ' · ' + dec(worst.percent, 1) + '%';

    fill(strip, [
        el('span', { class: 'bwstrip-label', text: 'Bandwidth' }),
        bar(worst.percent, level),
        el('span', { class: 'bwstrip-detail mono', text: detail }),
        LOUD.includes(level)
            ? el('span', { class: 'bwstrip-say', text: worst.headline })
            : null,
        el('a', { class: 'bwstrip-link', href: '?v=usage', text: 'Plan usage' }),
        LOUD.includes(level)
            ? el('a', {
                class: 'bwstrip-link',
                href: worst.upgrade_url,
                rel: 'noopener noreferrer',
                target: '_blank',
                text: 'Upgrade'
            })
            : null
    ]);

    strip.title = worst.consequence || '';
}

/**
 * Start the strip and keep it current.
 *
 * Failure is silent by design. This is page furniture on every view, and a panel whose
 * Opensolr credentials are absent, whose route has not been wired up, or whose control
 * plane is briefly unreachable must not grow an error banner on every page for it. The
 * information the operator needs in that case is on the Plan usage view, which says so in
 * words.
 */
export function initBandwidthStrip() {
    let timer = null;

    /* A FAILED READ RETRIES; IT DOES NOT STOP FOR EVER. The catch used to null the timer and
       nothing ever set it again, so one failed poll retired the strip permanently — and this is
       the one quota that cannot be reclaimed by deleting anything: past it the panel itself is
       answered 403. A backed-off retry keeps it coming back without hammering a box that is
       already in trouble. */
    let backoff = STRIP_POLL_MS;

    const tick = async () => {
        try {
            const data = await api('usage', 'meter');
            paintStrip(data);
            backoff = STRIP_POLL_MS;
            const wanted = Math.max(STRIP_POLL_MS, (Number(data.refresh_sec) || 0) * 1000);
            timer = window.setTimeout(tick, wanted);
        } catch (err) {
            backoff = Math.min(backoff * 2, STRIP_MAX_BACKOFF_MS);
            timer = window.setTimeout(tick, backoff);
        }
    };

    tick();

    /* A tab hidden for an hour comes back to a stale meter, and the poll it was waiting on may
       have been throttled to nothing by the browser. The old guard was `timer === null`, which
       after a SUCCESSFUL tick is never true — so the one case it was written for, a tab
       returning to stale numbers, was the one case it did not cover. Cancel whatever is pending
       and read now. */
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState !== 'visible') {
            return;
        }
        if (timer !== null) {
            window.clearTimeout(timer);
            timer = null;
        }
        tick();
    });
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
            'No Opensolr-managed index is configured, so there is no plan limit to report against.' })]);
        setPop('usage-bw', 'Nothing to measure yet.');
        return;
    }

    fill(mount, data.cores.map((row) => {
        const known = row.ratio !== null && row.ratio !== undefined;
        return el('div', { class: 'meterrow meterrow-' + String(row.level || 'unknown') }, [
            el('div', { class: 'meterrow-head' }, [
                el('span', { class: 'meterrow-name mono', text: row.core }),
                el('span', { class: 'meterrow-role', text: row.role === 'hits' ? 'hits' : 'sessions' }),
                el('span', {
                    class: 'meterrow-value mono',
                    text: known ? mb(row.used_mb) + ' of ' + mb(row.limit_mb) : 'not known'
                })
            ]),
            bar(row.percent, row.level),
            el('p', { class: 'meterrow-note', text: known
                ? row.headline + ' ' + dec(row.percent, 1) + '% used, resetting in ' +
                  days((Number(row.resets_in) || 0) / 86400) + '.'
                : (row.note || 'Opensolr has not reported usage for this index.') })
        ]);
    }));

    const worst = data.worst;
    setPop('usage-bw', worst && worst.ratio !== null && worst.ratio !== undefined
        ? 'Highest usage across your indexes: ' + dec(worst.percent, 1) + '% of the plan, ' +
          'warning from ' + dec(worst.warn_at, 0) + '%. The counter resets on the 1st.'
        : 'Bandwidth usage has not been read from Opensolr yet.');
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
            'No Opensolr-managed index is configured, so the retention window has no plan limit to '
            + 'work against. Only the time-based limit below applies.' })]);
        setPop('usage-window', 'Nothing to measure yet.');
        return;
    }

    const rows = [];
    for (const row of data.cores) {
        const w = row.window;

        if (row.blocked) {
            rows.push(el('div', { class: 'callout callout-bad', role: 'alert' }, [
                el('h4', { text: row.core + ' is blocked' }),
                el('p', { text: row.blocked.text })
            ]));
        }
        if (w.trim_alert) {
            rows.push(el('div', { class: 'callout callout-bad', role: 'alert' }, [
                el('h4', { text: 'Space could not be freed in ' + row.core }),
                el('p', { text: w.trim_alert.text })
            ]));
        }

        rows.push(el('div', { class: 'windowrow' }, [
            el('div', { class: 'windowrow-head' }, [
                el('span', { class: 'windowrow-name mono', text: row.core }),
                el('span', { class: 'windowrow-role', text: row.role === 'hits' ? 'hits' : 'sessions' })
            ]),
            el('div', { class: 'stats stats-tight' }, [
                stat('Held now', row.span.days === null ? '—' : days(row.span.days),
                    /* mm/dd/yyyy, like every other date in the panel. This was the only one
                       rendered as an ISO prefix, by slicing the first ten characters off the
                       instant — which also threw the time away with no way to get it back. */
                    row.span.oldest ? 'oldest document ' + dayOnly(row.span.oldest) : 'measured from the index'),
                stat('Plan window', w.plan_days === null ? '—' : days(w.plan_days),
                    w.max_size_mb === null ? 'no plan limit read' : 'estimated for ' + mb(w.max_size_mb)),
                stat('Ingest', w.ingest_mb_day === null ? '—' : mb(w.ingest_mb_day) + '/day',
                    w.ingest_mb_day === null ? 'needs two readings' : 'from observed growth'),
                stat('Index size', w.size_mb === null ? '—' : mb(w.size_mb),
                    w.estimated ? 'projected since the last reading' : 'as Opensolr reported it')
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
        ? 'Two limits apply and the shorter one wins. Currently: ' +
          (first.limited_by === 'size' ? 'the plan window.'
              : first.limited_by === 'time' ? 'your age limit.'
                  : first.enabled
                      ? 'not yet known — the disk rule is on, but the window it leaves cannot be '
                        + 'projected until the ingest rate has been measured.'
                      : 'neither — there is no age limit and deleting for size is switched off.')
        : 'No index usage is available.');
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
            limit: 'Time-based',
            by: 'privacy.retention_days',
            window: data.retention_days > 0 ? days(data.retention_days) : 'no age limit',
            active: inEffect === 'time',
            off: !(data.retention_days > 0)
        },
        {
            limit: 'Size-based',
            by: 'your Opensolr plan',
            window: !sizeOn
                ? 'switched off'
                : (first && first.plan_days !== null ? days(first.plan_days) : 'not known yet'),
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
            text: row.active ? 'in effect' : (row.off ? 'switched off' : 'not the limit')
        })])
    ])));

    const onCount = rows.filter((row) => !row.off).length;
    setPop('usage-limits', onCount === 0
        ? 'Both limits are switched off, so nothing is deleted for age or for size. An index that '
          + 'reaches its Opensolr disk quota is blocked by the platform, reads included.'
        : onCount === 1
            ? 'One of the two is switched on; it is the only thing deciding how much history is kept.'
            : 'Both run on their own schedule; the one that deletes sooner is the one you see.');
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
    loadCard('usage-bw', 'Reading plan usage from Opensolr', async () => {
        renderBandwidth(await api('usage', 'meter'));
    });

    const plan = api('usage', 'plan');

    loadCard('usage-window', 'Measuring the retention window', async () => {
        renderWindow(await plan);
    });
    loadCard('usage-limits', 'Comparing the retention limits', async () => {
        renderLimits(await plan);
    });
}
