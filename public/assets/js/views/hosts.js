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

import { api, byId, el, hideEmpty, loadCard, noDataYet, num, pct, setPop, tbody } from '../core.js';
import { barsH, tokens } from '../charts.js';

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
 */
export function initHostPicker() {
    api('hosts', 'list').then((data) => {
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
    }).catch(() => {
        /* No selector. See the docblock: this is page furniture, not a report. */
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

    if (!data.rows.length) {
        tbody(table, []);
        const none = byId('hosts-none');
        if (none) {
            none.hidden = false;
        }
        noDataYet('hosts-table-empty', 'sessions with a virtual host');
        return;
    }
    hideEmpty('hosts-table-empty');

    tbody(table, data.rows.map((row) => ({
        cells: [
            { text: row.host, mono: true, clip: true },
            { text: num(row.sessions), num: true },
            { text: num(row.counts.human), num: true },
            { text: num(row.counts.evasive), num: true },
            { text: num(row.counts.ai), num: true },
            { text: num(row.counts.declared), num: true },
            { text: row.bot_share === null ? '—' : row.bot_share + '%', num: true },
            { node: splitBar(row) },
            { node: el('a', { href: hostUrl(row.host), text: 'Scope to this host' }) }
        ]
    })));

    setPop('hosts-table', num(data.rows.length) + ' virtual hosts, ' + num(data.total) +
        ' scored sessions in the selected range. The five populations are mutually exclusive, ' +
        'so they add up to the session count on each row.');
}

/** A single bar split into the five population colours, in stacking order. */
function splitBar(row) {
    const total = row.sessions || 1;
    return el('span', { class: 'bar bar-split' }, ORDER.map((key) => el('span', {
        class: 'bar-' + key,
        style: 'width:' + ((row.counts[key] || 0) / total * 100) + '%',
        title: key + ': ' + pct(row.counts[key], total)
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
    })), { labelWidth: 190, format: (v) => v + '%' });

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
