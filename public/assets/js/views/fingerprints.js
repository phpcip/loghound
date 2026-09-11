/*
 * Loghound — Fingerprint clusters view.
 *
 * The table that makes the case for the product. Each row is one `fp_hash_s` — one client
 * configuration — and the column that matters is "Distinct IPs". A browser produces a
 * fingerprint seen from one or two addresses. A scraper behind a rotating proxy pool
 * produces one seen from forty, because the proxy changes the address and nothing else.
 *
 * Rows flagged as a fleet (five or more distinct IPs, not a mobile carrier) are tinted so
 * the finding survives being screenshotted at arm's length.
 *
 * Expanding a row loads its member addresses — still an aggregate (a terms facet on
 * `ip_s`), never a document fetch — with the ASN and RIR netname for each, which is what
 * turns "suspicious" into "here is the netblock and here is who leases it".
 */

'use strict';

import {
    api, byId, dec, el, hideEmpty, loadCard, noDataYet, num, setPop, shortHash, when
} from '../core.js';
import { sparkline, tokens } from '../charts.js';
import { clientNode, countryNode, dimValue } from '../identity.js';
import { markSortable } from '../sorttable.js';

/** Rows currently expanded, so a re-sort can leave them open. */
const expanded = new Set();

/** Split a hash into a bold identifiable head and a faint tail. */
function hashNode(hash) {
    return el('span', { class: 'fp-hash', title: hash }, [
        el('span', { class: 'fp-head', text: shortHash(hash, 12) }),
        el('span', { class: 'fp-tail', text: String(hash).slice(12, 20) })
    ]);
}

/** Verdict chip with the shared verdict colouring. */
function verdictChip(verdict) {
    return el('span', {
        class: 'chip v-' + String(verdict || 'unknown'),
        text: verdict || 'unknown'
    });
}

/**
 * Where the cluster answers from, as filter controls.
 *
 * The organisation, the network type and the country are three separate dimensions and each one
 * is worth slicing by on its own — "every cluster on a hosting network" and "every cluster in
 * Brazil" are different questions and both get asked.
 */
function networkParts(row) {
    const parts = [];
    if (row.org) {
        parts.push(dimValue('as_org_s', row.org));
    }
    if (row.as_type) {
        if (parts.length) {
            parts.push(el('span', { text: ' · ' }));
        }
        parts.push(dimValue('as_type_s', row.as_type));
    }
    if (row.country) {
        if (parts.length) {
            parts.push(el('span', { text: ' · ' }));
        }
        parts.push(countryNode(row.country, { short: true }));
    }
    return parts.length ? parts : [el('span', { text: '—' })];
}

/**
 * Build one cluster row.
 *
 * @param {Object} row
 * @param {number} sparkBuckets
 */
function clusterRow(row, sparkBuckets) {
    const tr = el('tr', {
        class: 'row-link' + (row.fleet ? ' fleet' : ''),
        tabindex: '0',
        role: 'button',
        title: 'Open everything known about this fingerprint',
        dataset: { fp: row.fp, lhOpen: 'dim', field: 'fp_hash_s', value: row.fp }
    });

    const button = el('button', {
        type: 'button',
        class: 'expander',
        'aria-expanded': expanded.has(row.fp) ? 'true' : 'false',
        'aria-label': 'Show the addresses sharing this fingerprint',
        text: expanded.has(row.fp) ? '−' : '+'
    });
    tr.appendChild(el('td', {}, [button]));

    tr.appendChild(el('td', { class: 'mono', 'data-sort': row.fp }, [hashNode(row.fp)]));

    tr.appendChild(el('td', {
        class: 'num',
        'data-sort': String(row.uniq_ips),
        title: num(row.uniq_ips) + ' addresses across ' + num(row.uniq_nets) + ' netblocks and '
            + num(row.uniq_asns) + ' networks'
    }, [
        el('div', { class: 'clip-line' }, [
            row.fleet
                ? el('strong', { text: num(row.uniq_ips) })
                : document.createTextNode(num(row.uniq_ips))
        ]),
        el('div', { class: 'sub', text: num(row.uniq_nets) + ' nets · ' + num(row.uniq_asns) + ' AS' })
    ]));
    tr.appendChild(el('td', { class: 'num', text: num(row.sessions), 'data-sort': String(row.sessions) }));

    const canvas = el('canvas', {
        class: 'spark',
        'aria-label': 'Activity across the selected range, in ' + sparkBuckets + ' buckets',
        role: 'img'
    });
    canvas.__spark = row.spark;
    tr.appendChild(el('td', { 'data-sort': row.last || '' }, [canvas]));

    tr.appendChild(el('td', {
        class: 'clip',
        title: [row.ua_bot_name, row.browser, row.os, row.device].filter(Boolean).join(' · '),
        'data-sort': row.ua_bot_name || row.browser || ''
    }, [
        clientNode(row),
        el('div', { class: 'sub clip-line' }, networkParts(row))
    ]));

    tr.appendChild(el('td', { class: 'clip', 'data-sort': row.avg_score === null ? '' : String(row.avg_score) }, [
        el('div', { class: 'clip-line' }, [
            verdictChip(row.verdict),
            row.declared ? el('span', { class: 'chip chip-good', text: 'declared' }) : null
        ]),
        el('div', {
            class: 'sub mono',
            text: row.avg_score === null ? '—' : 'score ' + dec(row.avg_score, 0)
        })
    ]));

    button.addEventListener('click', () => toggle(tr, row));
    return tr;
}

/** Expand or collapse a cluster's member list. */
async function toggle(tr, row) {
    const next = tr.nextElementSibling;
    const button = tr.querySelector('.expander');

    if (next && next.classList.contains('members')) {
        next.remove();
        expanded.delete(row.fp);
        button.textContent = '+';
        button.setAttribute('aria-expanded', 'false');
        return;
    }

    expanded.add(row.fp);
    button.textContent = '−';
    button.setAttribute('aria-expanded', 'true');

    const holder = el('tr', { class: 'members' }, [
        el('td', { colspan: '10' }, [
            el('div', { class: 'members-inner' }, [el('p', { class: 'muted', text: 'Loading addresses…' })])
        ])
    ]);
    tr.parentNode.insertBefore(holder, tr.nextSibling);
    const inner = holder.querySelector('.members-inner');

    try {
        const data = await api('fingerprints', 'members', { fp: row.fp });
        renderMembers(inner, data);
    } catch (err) {
        inner.replaceChildren(el('p', { class: 'muted', text: 'Could not load addresses: ' + err.message }));
    }
}

/** Render the member-IP table for one cluster. */
function renderMembers(inner, data) {
    if (!data.rows.length) {
        inner.replaceChildren(el('p', { class: 'muted', text: 'No addresses returned for this fingerprint.' }));
        return;
    }

    const summary = el('p', { class: 'muted' }, [
        num(data.rows.length) + ' address' + (data.rows.length === 1 ? '' : 'es') +
        ' across ' + num(data.uniq_asns) + ' autonomous system' + (data.uniq_asns === 1 ? '' : 's') +
        ', ' + num(data.uniq_nets) + ' netblock' + (data.uniq_nets === 1 ? '' : 's') +
        ' and ' + num(data.uniq_countries) + ' countr' + (data.uniq_countries === 1 ? 'y' : 'ies') +
        ', sharing one header fingerprint.' +
        (data.truncated ? ' Truncated to the busiest addresses.' : '')
    ]);

    const table = el('table', { class: 'tight table-fixed' }, [
        el('colgroup', {}, [
            el('col', { style: 'width:16ch' }), el('col', { style: 'width:15ch' }),
            el('col', { style: 'width:9ch' }), el('col'), el('col', { style: 'width:18ch' }),
            el('col', { style: 'width:10ch' }), el('col', { style: 'width:16ch' }),
            el('col', { style: 'width:7ch' }), el('col', { style: 'width:6ch' }),
            el('col', { style: 'width:13ch' })
        ]),
        el('thead', {}, [
            el('tr', {}, [
                el('th', { scope: 'col', text: 'Address' }),
                el('th', { scope: 'col', text: 'Netblock' }),
                el('th', { scope: 'col', text: 'ASN' }),
                el('th', { scope: 'col', text: 'Organisation' }),
                el('th', { scope: 'col', text: 'Netname' }),
                el('th', { scope: 'col', text: 'Type' }),
                el('th', { scope: 'col', text: 'Where' }),
                el('th', { scope: 'col', class: 'num', text: 'Sess.' }),
                el('th', { scope: 'col', class: 'num', text: 'Score' }),
                el('th', { scope: 'col', text: 'Last seen' })
            ])
        ])
    ]);

    const body = el('tbody');
    for (const m of data.rows) {
        body.appendChild(el('tr', {
            class: 'row-link',
            tabindex: '0',
            role: 'button',
            title: 'Open everything known about this address',
            dataset: { lhOpen: 'dim', field: 'ip_s', value: m.ip }
        }, [
            el('td', { class: 'mono nowrap', 'data-sort': m.ip || '' }, [dimValue('ip_s', m.ip, { mono: true })]),
            el('td', { class: 'mono clip', title: m.net || '', text: m.net || '—', 'data-sort': m.net || '' }),
            el('td', { class: 'mono num', text: m.asn ? 'AS' + m.asn : '—', 'data-sort': m.asn || '' }),
            el('td', { class: 'clip', title: m.org || 'Organisation not resolved', 'data-sort': m.org || '' }, [
                m.org ? dimValue('as_org_s', m.org) : el('span', { class: 'muted', text: '—' })
            ]),
            el('td', { class: 'mono clip', title: m.netname || '', 'data-sort': m.netname || '' }, [
                m.netname ? dimValue('netname_s', m.netname, { mono: true }) : el('span', { class: 'muted', text: '—' })
            ]),
            el('td', { 'data-sort': m.as_type || '' }, [
                m.as_type
                    ? dimValue('as_type_s', m.as_type)
                    : el('span', { class: 'chip', text: 'unknown' })
            ]),
            el('td', {
                class: 'clip',
                title: [m.city, m.country].filter(Boolean).join(', ') || 'Not geolocated',
                'data-sort': [m.country, m.city].filter(Boolean).join(' ')
            }, [
                m.country ? countryNode(m.country, { short: true }) : el('span', { class: 'muted', text: '—' }),
                m.city ? el('span', { class: 'sub', text: m.city }) : null
            ]),
            el('td', { class: 'num', text: num(m.sessions), 'data-sort': String(m.sessions) }),
            el('td', {
                class: 'num',
                text: m.score === null ? '—' : dec(m.score, 0),
                'data-sort': m.score === null ? '' : String(m.score)
            }),
            el('td', { class: 'mono nowrap', text: when(m.last), 'data-sort': m.last || '' })
        ]));
    }
    table.appendChild(body);

    inner.replaceChildren(
        el('h4', { text: 'Addresses sharing this fingerprint' }),
        summary,
        el('div', { class: 'table-wrap' }, [table]),
        data.ua ? el('p', { class: 'muted mono wrap', text: data.ua }) : null
    );
    markSortable(inner);
}

/**
 * Load and render the cluster table.
 *
 * Its own card, so a re-sort or a change of the minimum-IP floor re-runs only this
 * request and shows its own progress while it does.
 */
function loadClusters() {
    return loadCard('fp-table', 'Building fingerprint clusters', async () => {
        const table = byId('fp-table-el');
        const sort = byId('fp-sort');
        const min = byId('fp-min');

        const data = await api('fingerprints', 'clusters', {
            sort: sort ? sort.value : 'ips',
            min_ips: min ? min.value : 1
        });

        table.tBodies[0].replaceChildren();

        const fleets = data.rows.filter((row) => row.fleet).length;
        setPop('fp-table', num(data.total_sessions) + ' sessions in range across ' + num(data.total_fps) +
            ' distinct header fingerprints. Showing ' + num(data.rows.length) + '. ' +
            (fleets
                ? fleets + ' cluster' + (fleets === 1 ? '' : 's') + ' below match the proxy-fleet pattern ' +
                  '(five or more distinct addresses, not a mobile carrier, not self-declared) and are marked.'
                : 'None match the proxy-fleet pattern in this range.') +
            ' Distinct-IP counts use Solr unique(), exact for small counts and approximate for large ones.');

        if (!data.rows.length) {
            noDataYet('fp-table-empty', 'fingerprint clusters');
            return;
        }
        hideEmpty('fp-table-empty');

        for (const row of data.rows) {
            table.tBodies[0].appendChild(clusterRow(row, data.spark_buckets));
        }

        const t = tokens();
        for (const canvas of table.tBodies[0].querySelectorAll('canvas.spark')) {
            sparkline(canvas, canvas.__spark || [], t.accent);
        }
    });
}

/**
 * Entry point.
 */
export default function init() {
    const sort = byId('fp-sort');
    const min = byId('fp-min');
    if (sort) {
        sort.addEventListener('change', () => { expanded.clear(); loadClusters(); });
    }
    if (min) {
        min.addEventListener('change', () => { expanded.clear(); loadClusters(); });
    }
    document.addEventListener('lh:theme', () => {
        const t = tokens();
        for (const canvas of document.querySelectorAll('canvas.spark')) {
            sparkline(canvas, canvas.__spark || [], t.accent);
        }
    });

    loadClusters();
}
