/*
 * Loghound — Virtual hosts, and the host selector that scopes the whole dashboard.
 *
 * Two exports.
 *
 * `initHostPicker()` runs on EVERY view. Choosing a host adds `f[host_s][]` to the URL,
 * which the server already turns into a filter on every sessions-core query, so one control
 * scopes the entire dashboard rather than one card. It is a plain navigation: the selection
 * is in the URL, so it survives a reload, it can be bookmarked, and it appears in a
 * screenshot — which matters when the screenshot is the evidence in a conversation about
 * which site is being scraped.
 *
 * The picker is NOT inserted when the answer would be trivial. One host, or no host recorded
 * at all, means no selector: a control offering a single choice is furniture nobody needs,
 * and a multi-site feature must not clutter a single-site install.
 *
 * `init()` is the comparison view itself.
 */

'use strict';

import {
    api, boot, byId, dec, el, hideEmpty, loadCard, noDataYet, num, pct, populationLabel, setPop, tbody
} from '../core.js';
import { barsH, tokens } from '../charts.js';
import { dimRow, dimValue } from '../identity.js';
import { noteHosts, outLink } from '../url.js';

/** Population keys in the order the table and the bar use them. */
const ORDER = ['human', 'unknown', 'declared', 'ai', 'evasive'];

/* -------------------------------------------------------------------------
 * The dashboard-wide selector
 * ---------------------------------------------------------------------- */

/**
 * Build the URL for a host choice.
 *
 * The empty value means "every host", and it removes the parameter rather than setting it to
 * an empty string — an empty filter value would be sent, allowlisted, and turned into a
 * filter matching nothing, which reads as "no traffic" rather than as "all traffic".
 *
 * Paging is reset with it: a start offset that was valid for six sites is meaningless for
 * one of them.
 */
function hostUrl(host) {
    const params = new URLSearchParams(window.location.search);
    params.delete('f[host_s][]');
    params.delete('start');
    if (host) {
        params.append('f[host_s][]', host);
    }
    return '?' + params.toString();
}

/**
 * Insert the host selector into the page header, if there is a choice worth offering.
 *
 * Silent on failure for the same reason the bandwidth strip is: this runs on every view, and
 * a panel whose route is not wired up, or whose sessions core is briefly unreachable, must
 * not grow an error in its header on every page.
 *
 * IT ALSO ANSWERS A QUESTION EVERY OTHER VIEW HAS. A path facet bucket carries no host, so the
 * panel cannot link a full URL for it unless it knows the installation serves exactly one site.
 * This request already has that answer, and url.js is told it — including when the request
 * fails, so nothing is left waiting on a list that is never coming.
 */
/**
 * Does the view on this page honour the host selector?
 *
 * THE FETCH IS NOT GATED, ONLY THE CONTROL. The request this function guards also answers a
 * question every view needs — url.js cannot compose a full URL for a path facet bucket unless
 * it knows whether the installation serves one site or several — so skipping the call to avoid
 * drawing a selector would take the host out of every link on pages that have no selector.
 *
 * The declaration comes from Controller::toolbar() through the boot payload, so the selector
 * appears exactly where the view's own queries are filtered by it. On Index analytics, Query
 * analysis and Who is querying it is absent because `f[host_s][]` reaches a different plane and
 * changes nothing there; on Storage & bandwidth and Settings nothing is scoped at all.
 */
function scopedByHost() {
    const declared = boot.toolbar;
    return Array.isArray(declared) && declared.indexOf('host') !== -1;
}

export function initHostPicker() {
    /* THE REQUEST IS NOT MADE WHERE NOTHING NEEDS IT. This ran unconditionally, so every page
       in the panel paid for one extra Solr facet — including the five views that neither draw
       the selector nor render a single site path. The views that need the answer are exactly
       the views that declare the host selector, because they are the ones that render paths
       whose host has to be resolved before url.js can link them.

       Where the call is skipped the list is still SETTLED, as empty rather than unknown. Any
       mark waiting on it then resolves to "no host known" instead of waiting for a reply that
       is never coming — there should be none on these views, and a stuck placeholder would be
       a worse way to find out than an honest one. */
    if (!scopedByHost()) {
        noteHosts([]);
        return;
    }

    api('hosts', 'list').then((data) => {
        noteHosts((data.hosts || []).map((row) => row.host));

        const tools = document.querySelector('.head-tools');
        if (!tools || !data.multi || byId('lh-host')) {
            return;
        }

        const selected = (data.selected || [])[0] || '';

        const select = el('select', { id: 'lh-host', 'aria-label': 'Virtual host' }, [
            el('option', { value: '', selected: selected === '' ? true : null, text: 'All hosts' }),
            ...data.hosts.map((row) => el('option', {
                value: row.host,
                selected: row.host === selected ? true : null,
                text: row.host + ' (' + num(row.sessions) + ')'
            }))
        ]);
        select.addEventListener('change', () => {
            window.location.href = hostUrl(select.value);
        });

        const wrap = el('div', { class: 'hostpick', id: 'lh-hostpick' }, [
            el('label', { for: 'lh-host', text: 'Host' }),
            select
        ]);

        tools.insertBefore(wrap, byId('lh-page-status') || null);
    }).catch((err) => {
        /* The selector scopes the WHOLE dashboard, so its absence changes what every number on
           the page means. Still not a report — it does not take a card's failure state — but a
           multi-site operator who is quietly being shown all hosts at once has to be told the
           control they use to narrow that is missing, and given something to paste. */
        noteHosts([]);
        window.console.error('loghound: the virtual-host selector could not load', err);
        const tools = document.querySelector('.head-tools');
        if (!tools || byId('lh-hostpick-failed')) {
            return;
        }
        tools.insertBefore(
            el('span', {
                class: 'job-meta',
                id: 'lh-hostpick-failed',
                title: String(err && err.message ? err.message : err),
                text: 'Host filter unavailable — these figures cover every host'
            }),
            byId('lh-page-status') || null
        );
    });
}

/* -------------------------------------------------------------------------
 * The comparison view
 * ---------------------------------------------------------------------- */

/**
 * The comparison table: one row per host, sorted by the platform's own count.
 *
 * The share column is a split bar in the population colours rather than a single percentage,
 * because "40% automation" hides whether that 40% is Googlebot or a proxy fleet, and those
 * are opposite situations. The link in the last column scopes the whole dashboard to that
 * host, which is the action an operator wants the moment they see a row that stands out.
 */
function renderTable(data) {
    const table = byId('hosts-table-table');
    if (!table) {
        return;
    }

    /* ONE EMPTY STATE, NOT TWO CONTRADICTING EACH OTHER. This used to reveal the server-rendered
       "no virtual host is being recorded — your log format does not carry it" card AND print the
       generic "nothing has been indexed yet, check the tailer is running" state underneath it.
       One said the cause is known and everything else is fine; the other said nothing is indexed
       and the reader should go and check a daemon. The explainer is the more specific of the two
       and it is the one that survives. */
    if (!data.rows.length) {
        tbody(table, []);
        const none = byId('hosts-none');
        if (none) {
            none.hidden = false;
            hideEmpty('hosts-table-empty');
        } else {
            noDataYet('hosts-table-empty', 'sessions with a virtual host');
        }
        return;
    }
    const none = byId('hosts-none');
    if (none) {
        none.hidden = true;
    }
    hideEmpty('hosts-table-empty');

    tbody(table, data.rows.map((row) => ({
        attrs: dimRow('host_s', row.host),
        cells: [
            { node: planeName(row), clip: true, title: row.host, sort: row.host },
            { text: num(row.sessions), num: true, sort: row.sessions },
            { text: num(row.counts.human), num: true, sort: row.counts.human },
            { text: num(row.counts.unknown), num: true, sort: row.counts.unknown },
            { text: num(row.counts.evasive), num: true, sort: row.counts.evasive },
            { text: num(row.counts.ai), num: true, sort: row.counts.ai },
            { text: num(row.counts.declared), num: true, sort: row.counts.declared },
            {
                text: row.bot_share === null ? '—' : row.bot_share + '%',
                num: true,
                sort: row.bot_share === null ? '' : row.bot_share
            },
            { node: splitBar(row), sort: row.evasive_share === null ? '' : row.evasive_share }
        ]
    })));

    const singlePlane = data.rows.filter((row) => row.beacon_only > 0).length;

    /* "SCORED SESSIONS" WAS THE WRONG POPULATION: `total` is every session the range and the
       filters matched, scored or not. The five population columns are what is scored, and they
       now add up on the row because the fifth one is finally printed. */
    setPop('hosts-table', num(data.rows.length) + ' virtual hosts, ' + num(data.total) +
        ' sessions in the selected range. The five population columns are mutually exclusive, ' +
        'so they add up to the session count on each row. Automation is the share of the row ' +
        'that is not human, which is the last three columns together.' +
        (singlePlane
            ? ' ' + num(singlePlane) + ' of these hosts carry sessions measured by the beacon alone, with no ' +
              'access log behind them: their verdicts rest on one plane, and one plane is the plane a ' +
              'determined client controls. They are marked in the first column.'
            : ''));
}

/**
 * The host cell, carrying a mark when the host has sessions with no transport plane.
 *
 * The hostname itself gets the same two-affordance treatment every path in the panel gets: the
 * name filters the dashboard to that host, and the small link beside it opens the site's front
 * page in a new tab. A row naming a site nobody can reach from it is a row that stops halfway.
 *
 * The mark is on the row rather than in a footnote because the table mixes the two kinds and a
 * reader comparing two rows has to be able to see which is which without leaving the row. Three
 * states, and they are genuinely different situations: every session single-plane (a site on
 * another server), some of them (a site that gained or lost a log source partway through the
 * range), or none.
 */
function planeName(row) {
    const name = el('span', { class: 'urlwrap' }, [
        el('span', { class: 'urlpath' }, [dimValue('host_s', row.host, { mono: true })]),
        outLink(row.host, '/')
    ]);
    if (!row.beacon_only) {
        return name;
    }

    const single = row.single_plane;
    return el('span', { class: 'plane-cell' }, [
        name,
        el('span', {
            class: 'chip chip-accent',
            text: single ? 'beacon only' : 'part beacon only',
            title: single
                ? 'No access log in this installation covers this host, so every session here was measured ' +
                  'by the beacon alone. The five signals that read the request log were not evaluated.'
                : num(row.beacon_only) + ' of ' + num(row.sessions) + ' sessions on this host were measured ' +
                  'by the beacon alone, with no access log behind them. The rest have all three planes.'
        })
    ]);
}

/**
 * A single bar split into the five population colours, in stacking order.
 *
 * The tooltip names the population in WORDS and states both the count and the share, matching
 * the identical bar on Networks and in the visitor dialog. It read "evasive: 12%" — a raw
 * population key — while the server had been shipping Query::populationLabels() in the boot
 * payload the whole time and this file never read it.
 */
function splitBar(row) {
    const total = row.sessions || 1;
    return el('span', { class: 'bar bar-split' }, ORDER.map((key) => el('span', {
        class: 'bar-' + key,
        style: 'width:' + ((row.counts[key] || 0) / total * 100) + '%',
        title: populationLabel(key) + ': ' + num(row.counts[key] || 0) + ' (' + pct(row.counts[key], total) + ')'
    })));
}

/**
 * Automation share per host, as a horizontal bar chart.
 *
 * Evasive automation is the series drawn in the accent, because that is the only one of the
 * five that represents something an operator might want to act on. Declared crawlers are not
 * a threat and are not coloured like one.
 */
function renderChart(data) {
    if (!data.rows.length) {
        noDataYet('hosts-share-empty', 'hosts to compare');
        return;
    }
    hideEmpty('hosts-share-empty');

    const th = tokens();
    barsH('hosts-share', data.rows.map((row) => ({
        label: row.host,
        value: row.evasive_share === null ? 0 : row.evasive_share,
        color: th.accent,
        extra: num(row.counts.evasive) + ' of ' + num(row.sessions) + ' sessions'
    })), { labelWidth: 190, format: (v) => dec(v, 1) + '%' });

    setPop('hosts-share', 'Share of each host\'s scored sessions that were evasive automation — ' +
        'clients that did not declare themselves. Declared crawlers and AI crawlers are excluded ' +
        'here; they are in the table above.');
}

/**
 * Entry point. One request feeds both cards, because they are two readings of one answer.
 */
export default function init() {
    const compare = api('hosts', 'compare');

    loadCard('hosts-table', 'Grouping sessions by virtual host', async () => {
        renderTable(await compare);
    });
    loadCard('hosts-share', 'Comparing hosts', async () => {
        renderChart(await compare);
    });
}
