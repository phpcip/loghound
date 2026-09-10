/*
 * Loghound — Networks view.
 *
 * Three resolutions of the same question. The treemap is sized by sessions and coloured
 * by `as_type_s`, because the interesting finding is never "a lot of traffic from AS14061"
 * — it is "a lot of traffic from a hosting network", and a single-colour treemap hides
 * exactly that.
 *
 * Every table carries a human/evasive mix bar for the same reason: a row that is 100
 * sessions of humans and a row that is 100 sessions of a scraper look identical until you
 * show the split.
 */

'use strict';

import { api, byId, el, hideEmpty, load, noDataYet, num, pct, tbody } from '../core.js';
import { donut, geoScatter, tokens, treemap } from '../charts.js';
import { countryName, locate } from '../geo.js';

/**
 * Colour for a network type.
 *
 * Hosting and VPN share the evasive colour because that is the honest reading: a consumer
 * browser User-Agent from either is the same weak signal, and the palette should not
 * imply a distinction the scorer does not make.
 */
function typeColour(t, type) {
    switch (type) {
        case 'isp':     return t.pop.human;
        case 'mobile':  return t.pop.declared;
        case 'edu':
        case 'gov':     return t.pop.ai;
        case 'hosting':
        case 'vpn':     return t.pop.evasive;
        default:        return t.pop.unknown;
    }
}

/** A three-segment bar showing the human / declared / evasive mix of a row. */
function mixBar(row) {
    const total = Math.max(1, row.sessions);
    const seg = (value, cls) => el('span', {
        class: cls,
        style: 'width:' + ((value / total) * 100).toFixed(2) + '%',
        title: cls.replace('bar-', '') + ': ' + num(value)
    });
    const other = Math.max(0, row.sessions - row.human - row.declared - row.evasive);
    return el('span', { class: 'bar bar-split' }, [
        seg(row.human, 'bar-human'),
        seg(row.declared, 'bar-declared'),
        seg(row.evasive, 'bar-evasive'),
        seg(other, 'bar-unknown')
    ]);
}

/** Headline counters. */
function renderStats(data) {
    const scope = byId('net-stats');
    const set = (field, value) => {
        const node = scope.querySelector('[data-field="' + field + '"]');
        if (node) {
            node.textContent = value;
        }
    };
    set('sessions', num(data.total));
    set('uniq_ips', num(data.uniq_ips));
    set('uniq_asns', num(data.uniq_asns));

    // "From datacentres" is computed here from the as_type facet rather than as another
    // Solr query: the numbers are already on the page and must agree with each other.
    let hosting = 0;
    for (const row of data.astypes) {
        if (row.as_type === 'hosting' || row.as_type === 'vpn') {
            hosting += row.sessions;
        }
    }
    set('hosting', num(hosting) + (data.total ? '  (' + pct(hosting, data.total, 0) + ')' : ''));
}

/** ASN treemap. */
function renderTreemap(data) {
    if (!data.asns.length) {
        noDataYet('net-treemap-empty', 'network activity');
        return;
    }
    hideEmpty('net-treemap-empty');
    const t = tokens();

    treemap('net-treemap', data.asns.map((a) => ({
        name: 'AS' + a.asn + (a.org ? ' · ' + a.org : ''),
        short: a.org || ('AS' + a.asn),
        value: a.sessions,
        org: a.org,
        astype: a.as_type,
        uniqIps: a.uniq_ips,
        human: a.human,
        evasive: a.evasive
    })), (type) => typeColour(t, type));

    // A legend for the colour dimension, built as DOM so it inherits the panel's type.
    const card = byId('net-treemap').closest('.card');
    const existing = card.querySelector('.type-legend');
    if (existing) {
        existing.remove();
    }
    const legend = el('div', { class: 'type-legend controls', style: 'margin-bottom:8px' });
    for (const type of ['isp', 'mobile', 'hosting', 'vpn', 'edu', 'gov', 'unknown']) {
        legend.appendChild(el('span', { class: 'controls', style: 'gap:5px' }, [
            el('span', {
                style: 'display:inline-block;width:10px;height:10px;background:' + typeColour(t, type)
            }),
            el('span', { class: 'muted', text: type })
        ]));
    }
    byId('net-treemap').parentNode.insertBefore(legend, byId('net-treemap'));
}

/** Network-type donut. */
function renderTypes(data) {
    if (!data.astypes.length) {
        noDataYet('net-types-empty', 'network types');
        return;
    }
    hideEmpty('net-types-empty');
    const t = tokens();
    donut('net-types', data.astypes.map((r) => ({
        label: r.as_type || 'unknown',
        value: r.sessions,
        color: typeColour(t, r.as_type)
    })), 'sessions', num(data.total));
}

/** The country scatter. */
function renderMap(data) {
    const points = [];
    let unplaced = 0;
    const maxSessions = data.countries.reduce((m, c) => Math.max(m, c.sessions), 1);

    for (const c of data.countries) {
        const at = locate(c.country);
        if (!at) {
            unplaced += c.sessions;
            continue;
        }
        points.push({
            name: at.name,
            value: [at.lon, at.lat],
            sessions: c.sessions,
            ips: c.uniq_ips,
            human: c.human,
            evasive: c.evasive,
            evasiveRate: c.sessions ? c.evasive / c.sessions : 0,
            // Area-proportional sizing with a floor, so a country with three sessions is
            // still visible and a country with thirty thousand does not swallow the map.
            size: Math.max(6, Math.min(42, 6 + Math.sqrt(c.sessions / maxSessions) * 34))
        });
    }

    if (!points.length) {
        noDataYet('net-map-empty', 'geolocated sessions');
        return;
    }
    hideEmpty('net-map-empty');
    geoScatter('net-map', points);

    const popNode = byId('net-map').closest('.card').querySelector('.pop');
    if (popNode) {
        popNode.textContent =
            'All sessions in range, plotted at country centroids on a plain lon/lat grid — country resolution ' +
            'only, and there is no basemap because the panel must work air-gapped. Dot area is sessions; a dot ' +
            'is drawn in the evasive colour when more than half its sessions were scored as evasive automation.' +
            (unplaced ? ' ' + num(unplaced) + ' sessions had a country value this build cannot place and are not shown.' : '');
    }
}

/** Netname table — the level that exposes a leased range. */
function renderNetnames(data) {
    const table = byId('net-netnames');
    if (!data.netnames.length) {
        tbody(table, []);
        noDataYet('net-netnames-empty', 'netblocks');
        return;
    }
    hideEmpty('net-netnames-empty');

    tbody(table, data.netnames.map((r) => ({
        cells: [
            {
                node: el('a', {
                    href: '?v=sessions&f[netname_s][]=' + encodeURIComponent(r.netname),
                    class: 'mono',
                    text: r.netname || '—'
                })
            },
            { text: r.org || '—', clip: true },
            { node: el('span', { class: 'chip', text: r.as_type || 'unknown' }) },
            { text: num(r.sessions), num: true },
            { text: num(r.uniq_ips), num: true },
            {
                // Fingerprint count per netblock: many addresses and ONE fingerprint is
                // the fleet signature, and this column is where it first shows up.
                text: num(r.uniq_fps), num: true,
                title: 'Distinct header fingerprints seen from this netblock. Many addresses sharing very few ' +
                    'fingerprints is the rotating-proxy pattern.'
            },
            { text: num(r.human), num: true },
            { text: num(r.evasive), num: true },
            { node: mixBar(r) }
        ]
    })));
}

/** ASN table. */
function renderAsns(data) {
    const table = byId('net-asns');
    if (!data.asns.length) {
        tbody(table, []);
        noDataYet('net-asns-empty', 'autonomous systems');
        return;
    }
    hideEmpty('net-asns-empty');

    tbody(table, data.asns.map((r) => ({
        cells: [
            {
                node: el('a', {
                    href: '?v=sessions&f[as_org_s][]=' + encodeURIComponent(r.org || ''),
                    class: 'mono',
                    text: 'AS' + r.asn
                })
            },
            { text: r.org || '—', clip: true },
            { node: el('span', { class: 'chip', text: r.as_type || 'unknown' }) },
            { text: num(r.sessions), num: true },
            { text: num(r.uniq_ips), num: true },
            { text: num(r.hits), num: true },
            { text: num(r.human), num: true },
            { text: num(r.evasive), num: true },
            { node: mixBar(r) }
        ]
    })));
}

/** Country table. */
function renderCountries(data) {
    const table = byId('net-countries');
    if (!data.countries.length) {
        tbody(table, []);
        noDataYet('net-countries-empty', 'geolocated sessions');
        return;
    }
    hideEmpty('net-countries-empty');

    tbody(table, data.countries.map((r) => ({
        cells: [
            {
                node: el('a', {
                    href: '?v=sessions&f[country_s][]=' + encodeURIComponent(r.country),
                    text: countryName(r.country)
                })
            },
            { text: num(r.sessions), num: true },
            { text: num(r.uniq_ips), num: true },
            { text: num(r.human), num: true },
            { text: num(r.evasive), num: true },
            {
                text: (r.cities || []).map((c) => c.city + ' (' + num(c.count) + ')').join(', ') || '—',
                clip: true
            }
        ]
    })));
}

/** Entry point. */
export default async function init() {
    await load('net-treemap-empty', 'network data', async () => {
        const data = await api('networks', 'summary');
        renderStats(data);
        renderTreemap(data);
        renderTypes(data);
        renderMap(data);
        renderNetnames(data);
        renderAsns(data);
        renderCountries(data);
    });
}
