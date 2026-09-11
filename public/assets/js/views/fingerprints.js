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
import { clientNode, countryNode, dimValue, verdictChip } from '../identity.js';
import { markSortable } from '../sorttable.js';
import { renderPager } from '../pager.js';

/** Rows currently expanded, so a re-sort can leave them open. */
const expanded = new Set();

/**
 * The signature column: a short tag, and the finding the row is actually about.
 *
 * IT USED TO BE TWENTY CHARACTERS OF HASH and nothing else. A hash is a database key, not
 * something a person reads, and on the one page in the product whose subject genuinely IS the
 * hash it still should not be the widest column — what a reader needs from this cell is "is this
 * the fleet or not", with just enough of the identifier to tell two rows apart and to quote in a
 * message. Eight characters does that; the whole value is in the cell's own description and the
 * row opens a dialog that never shows it at all.
 *
 * The chip is not decoration. The orange rule on a fleet row is drawn on the cell's left edge and
 * a rule alone is a mark with no name — the legend under the table says what it means, and this
 * says it on the row.
 */
function signatureNode(row) {
    return el('span', { class: 'fp-hash' }, [
        el('span', { class: 'fp-head', text: shortHash(row.fp, 8) }),
        row.fleet
            ? el('span', {
                class: 'chip chip-accent',
                text: 'fleet',
                title: 'Five or more distinct addresses wear this one client signature, on no mobile '
                    + 'carrier and with nothing self-declared. That is the shape a rotating proxy pool makes.'
            })
            : null
    ]);
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

    tr.appendChild(el('td', {
        class: 'mono',
        'data-sort': row.fp,
        title: 'Client signature ' + row.fp
    }, [signatureNode(row)]));

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
            row.declared
                ? el('span', {
                    class: 'chip chip-good',
                    title: 'Every address in this cluster identified itself in the User-Agent, and the claim checked out.',
                    text: 'Declared'
                })
                : null
        ]),
        el('div', {
            class: 'sub mono',
            text: row.avg_score === null ? '—' : 'score ' + dec(row.avg_score, 0)
        })
    ]));

    button.addEventListener('click', () => toggle(tr, row));
    return tr;
}

/**
 * Expand or collapse a cluster's member list.
 *
 * `expanded` is cleared whenever the rows are re-fetched, because loadClusters() replaces the
 * whole tbody and never rebuilds the `<tr class="members">` beneath a row. Without that, a
 * fingerprint that was open before a failed load came back marked `aria-expanded="true"` with a
 * "−" on it, over content that no longer existed. The two sort controls cleared it; the card's
 * own Retry did not, because that path goes through core.js and knows nothing about this Set.
 */
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
        el('td', { colspan: '7' }, [
            el('div', { class: 'members-inner' }, [el('p', { class: 'muted', text: 'Loading addresses…' })])
        ])
    ]);
    tr.parentNode.insertBefore(holder, tr.nextSibling);
    const inner = holder.querySelector('.members-inner');

    try {
        const data = await api('fingerprints', 'members', { fp: row.fp, start: 0 });
        renderMembers(inner, data, row.fp);
    } catch (err) {
        /* A RETRY IN PLACE. The expander is left reading "−", so pressing it again COLLAPSES
           the row rather than retrying it — the reader has to collapse and re-expand, and the
           control gives them no reason to think that would help. */
        const again = el('button', { type: 'button', class: 'small', text: 'Try again' });
        again.addEventListener('click', () => {
            again.disabled = true;
            inner.replaceChildren(el('p', { class: 'muted', text: 'Loading addresses\u2026' }));
            api('fingerprints', 'members', { fp: row.fp, start: 0 })
                .then((data) => renderMembers(inner, data, row.fp))
                .catch((e) => inner.replaceChildren(
                    el('p', { class: 'muted', text: 'Could not load addresses: ' + e.message }),
                    el('div', { class: 'card-error-actions' }, [again])
                ));
        });
        inner.replaceChildren(
            el('p', { class: 'muted', text: 'Could not load addresses: ' + err.message }),
            el('div', { class: 'card-error-actions' }, [again])
        );
    }
}

/**
 * Render the member-address table for one cluster.
 *
 * FIVE COLUMNS, AND TWO OF THEM WENT TO THE DIALOG. It carried ten: address, netblock, ASN,
 * organisation, netname, type, where, sessions, score and last seen. The netblock, the ASN number
 * and the RIR netname are the three an operator quotes and none of them is something a reader
 * takes in while scanning — and every one of them is in the dialog each row opens, where the
 * address gets a sentence saying whose address space it sits in rather than three identifiers in
 * three columns. What is left is what a person reads down a column: who, where, whose network,
 * how much, and when.
 *
 * IT IS PAGED. A rotating-proxy cluster is the case this table exists for and is exactly the one
 * that runs to hundreds of addresses; fetching a hundred of them and calling it the list was the
 * same defect as "the most recent 12 of 1,890".
 *
 * @param {HTMLElement} inner
 * @param {Object} data
 * @param {string} fp  The fingerprint, used only to fetch further pages. Never rendered.
 */
function renderMembers(inner, data, fp) {
    if (!data.rows.length) {
        inner.replaceChildren(el('p', { class: 'muted', text: 'No addresses returned for this fingerprint.' }));
        return;
    }

    const summary = el('p', { class: 'muted' }, [
        num(data.page && data.page.total !== null ? data.page.total : data.rows.length) +
        ' addresses across ' + num(data.uniq_asns) + ' autonomous system' + (data.uniq_asns === 1 ? '' : 's') +
        ', ' + num(data.uniq_nets) + ' netblock' + (data.uniq_nets === 1 ? '' : 's') +
        ' and ' + num(data.uniq_countries) + ' countr' + (data.uniq_countries === 1 ? 'y' : 'ies') +
        ', all sharing one client signature. Each row opens everything known about that address, ' +
        'including the netblock and the network it belongs to.'
    ]);

    const table = el('table', { class: 'tight table-fixed' }, [
        el('colgroup', {}, ['22%', '20%', '28%', '10%', '20%'].map((w) => el('col', { style: 'width:' + w }))),
        el('thead', {}, [
            el('tr', {}, [
                el('th', { scope: 'col', text: 'Address' }),
                el('th', { scope: 'col', text: 'Country' }),
                el('th', { scope: 'col', text: 'Network' }),
                el('th', { scope: 'col', class: 'num', text: 'Visits' }),
                el('th', { scope: 'col', text: 'Last seen' })
            ])
        ])
    ]);

    const body = el('tbody');
    table.appendChild(body);

    const paint = (rows) => {
        body.replaceChildren();
        for (const m of rows) {
            body.appendChild(el('tr', {
                class: 'row-link',
                tabindex: '0',
                title: 'Open everything known about this address',
                dataset: { lhOpen: 'dim', field: 'ip_s', value: m.ip }
            }, [
                el('td', { class: 'mono nowrap', 'data-sort': m.ip || '' }, [dimValue('ip_s', m.ip, { mono: true })]),
                el('td', {
                    class: 'clip',
                    title: [m.city, m.country].filter(Boolean).join(', ') || 'Not geolocated',
                    'data-sort': [m.country, m.city].filter(Boolean).join(' ')
                }, [
                    m.country ? countryNode(m.country) : el('span', { class: 'muted', text: '\u2014' })
                ]),
                el('td', { class: 'clip', title: m.org || 'Network not resolved', 'data-sort': m.org || '' }, [
                    m.org ? dimValue('as_org_s', m.org) : el('span', { class: 'muted', text: '\u2014' }),
                    m.as_type ? el('div', { class: 'sub' }, [dimValue('as_type_s', m.as_type)]) : null
                ]),
                el('td', { class: 'num', text: num(m.sessions), 'data-sort': String(m.sessions) }),
                el('td', { class: 'mono nowrap', text: when(m.last), 'data-sort': m.last || '' })
            ]));
        }
    };

    const mount = el('div', { class: 'pager-mount' });
    const show = (state) => {
        renderPager(mount, state, async (start) => {
            mount.replaceChildren(el('p', { class: 'muted', text: 'Loading page\u2026' }));
            try {
                const next = await api('fingerprints', 'members', { fp: fp, start: start, rows: state.rows });
                paint(next.rows);
                show(next.page);
            } catch (e) {
                const again = el('button', { type: 'button', class: 'small', text: 'Try again' });
                again.addEventListener('click', () => show(state));
                mount.replaceChildren(
                    el('p', { class: 'muted', text: 'That page could not be loaded: ' + e.message }),
                    el('div', { class: 'card-error-actions' }, [again])
                );
            }
        });
    };

    paint(data.rows);
    show(data.page);

    inner.replaceChildren(
        el('h4', { text: 'Addresses sharing this client signature' }),
        summary,
        el('div', { class: 'table-wrap' }, [table]),
        mount,
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
    /* THE OPEN SET IS CLEARED HERE, not at each caller. This replaces the whole tbody and never
       rebuilds the member rows under it, so any fingerprint still marked open would come back
       with "−" and `aria-expanded="true"` over content that does not exist. The two sort
       handlers cleared it by hand; the card's own Retry, which goes through core.js, could not. */
    expanded.clear();
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
        sort.addEventListener('change', () => loadClusters());
    }
    if (min) {
        min.addEventListener('change', () => loadClusters());
    }
    document.addEventListener('lh:theme', () => {
        const t = tokens();
        for (const canvas of document.querySelectorAll('canvas.spark')) {
            sparkline(canvas, canvas.__spark || [], t.accent);
        }
    });

    loadClusters();
}
