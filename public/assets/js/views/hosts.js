/*
 * Loghound — Virtual hosts, and the host selector that scopes the whole dashboard.
 *
 * Two exports.
 *
 * `initHostPicker()` runs on EVERY view. It fills the hostname selector Panel\Layout renders in
 * the top bar, and it hands assets/js/url.js the list every full URL on the page is composed
 * from. Choosing a host submits `f[host_s][]`, which the server already turns into a filter on
 * every sessions-core query, so one control scopes the entire dashboard rather than one card —
 * and the selection is in the URL, so it survives a reload, it can be bookmarked, and it appears
 * in a screenshot, which matters when the screenshot is the evidence in a conversation about
 * which site is being scraped.
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
import { fillHosts, hostsUnavailable } from '../topbar.js';

/** Population keys in the order the table and the bar use them. */
const ORDER = ['human', 'unknown', 'declared', 'ai', 'evasive'];

/* -------------------------------------------------------------------------
 * The dashboard-wide selector
 * ---------------------------------------------------------------------- */

/**
 * Fetch the virtual hosts, for the selector in the top bar and for every full URL on the page.
 *
 * TWO CONSUMERS, ONE REQUEST, AND THE SECOND ONE IS WHY THE FETCH IS NOT GATED. The selector is
 * rendered by Panel\Layout and filled here — it is a plain form control, so choosing a host
 * submits `f[host_s][]` and the server turns it into a filter on every sessions-core query, which
 * is what makes one control scope the whole dashboard. But assets/js/url.js also needs the
 * answer: a path facet bucket carries no host, so the panel cannot compose a full URL for it
 * unless it knows whether the installation serves one site or several.
 *
 * THE SELECTOR IS NOT OFFERED WHERE IT WOULD DO NOTHING. A view that does not declare
 * Controller::SCOPE_HOST has no `#lh-host` in its bar at all, so there is nothing to fill; and a
 * single-host installation has no choice worth offering, so the field is taken off screen. Both
 * decisions are made where the fact is known rather than by a list of view slugs.
 *
 * Silent on failure for the same reason every other piece of page furniture is: this runs on
 * every view, and a panel whose sessions core is briefly unreachable must not grow an error in
 * its header on every page. The one thing that IS said is said on the control itself — see
 * hostsUnavailable() — because a multi-site operator being shown every host at once has to know
 * the control that would narrow it is missing.
 */
function scopedByHost() {
    const declared = boot.toolbar;
    return Array.isArray(declared) && declared.indexOf('host') !== -1;
}

export function initHostPicker() {
    /* THE REQUEST IS NOT MADE WHERE NOTHING NEEDS IT. This ran unconditionally, so every page
       in the panel paid for one extra Solr facet — including the views that neither draw the
       selector nor render a single site path. Where the call is skipped the list is still
       SETTLED, as empty rather than unknown, so any mark waiting on it resolves to "no host
       known" instead of waiting for a reply that is never coming. */
    if (!scopedByHost()) {
        noteHosts([]);
        return;
    }

    api('hosts', 'list').then((data) => {
        noteHosts((data.hosts || []).map((row) => row.host));
        fillHosts(data.hosts || [], !!data.multi);
    }).catch((err) => {
        noteHosts([]);
        window.console.error('loghound: the virtual-host list could not load', err);
        hostsUnavailable(err);
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
        noDataYet('hosts-share-empty', 'hosts');
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
