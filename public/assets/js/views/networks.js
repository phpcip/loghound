/*
 * Loghound — Networks view.
 *
 * Five independent cards. The treemap is sized by sessions and coloured by `as_type_s`,
 * because the interesting finding is never "a lot of traffic from AS14061" — it is "a lot
 * of traffic from a hosting network", and a single-colour treemap hides exactly that.
 *
 * Every table carries a human/declared/evasive mix bar for the same reason: a row of 100
 * human sessions and a row of 100 scraper sessions look identical until the split shows.
 */

'use strict';

import {
    api, byId, cardChart, el, hideEmpty, loadCard, noDataYet, num, pct, setPop, tbody
} from '../core.js';
import { donut, geoScatter, tokens, treemap } from '../charts.js';
import { countryName, locate } from '../geo.js';
import { countryNode, dimRow, dimValue } from '../identity.js';

/**
 * The colour for a network type.
 *
 * Hosting and VPN share the accent because that is the honest reading: a consumer browser
 * User-Agent from either is the same weak signal, and the palette should not imply a
 * distinction the scorer does not make.
 */
function typeColour(t, type) {
    switch (type) {
        case 'isp':     return t.pop.human;
        case 'mobile':  return t.pop.unknown;
        case 'edu':
        case 'gov':     return t.pop.ai;
        case 'hosting':
        case 'vpn':     return t.pop.evasive;
        default:        return t.pop.declared;
    }
}

/**
 * A four-segment bar showing the human / declared / evasive / other mix of a row.
 */
function mixBar(row) {
    const total = Math.max(1, row.sessions);
    const segment = (value, cls) => el('span', {
        class: cls,
        style: 'width:' + ((value / total) * 100).toFixed(2) + '%',
        title: cls.replace('bar-', '') + ': ' + num(value)
    });
    const other = Math.max(0, row.sessions - row.human - row.declared - row.evasive);
    return el('span', { class: 'bar bar-split' }, [
        segment(row.human, 'bar-human'),
        segment(row.declared, 'bar-declared'),
        segment(row.evasive, 'bar-evasive'),
        segment(other, 'bar-unknown')
    ]);
}

/**
 * Fill the four headline counters.
 */
function renderTotals(data) {
    const scope = byId('net-stats-content');
    const set = (field, value) => {
        const node = scope ? scope.querySelector('[data-field="' + field + '"]') : null;
        if (node) {
            node.textContent = value;
        }
    };
    set('sessions', num(data.total));
    set('uniq_ips', num(data.uniq_ips));
    set('uniq_asns', num(data.uniq_asns));
    set('hosting', num(data.hosting) + (data.total ? ' · ' + pct(data.hosting, data.total, 0) : ''));
}

/**
 * Draw the ASN treemap, its colour legend and the table beneath it.
 */
function renderAsns(data) {
    if (!data.asns.length) {
        noDataYet('net-asns-empty', 'network activity');
        return;
    }
    hideEmpty('net-asns-empty');
    const t = tokens();

    treemap('net-treemap', data.asns.map((row) => ({
        name: 'AS' + row.asn + (row.org ? ' · ' + row.org : ''),
        short: row.org || ('AS' + row.asn),
        value: row.sessions,
        org: row.org,
        astype: row.as_type,
        uniqIps: row.uniq_ips,
        human: row.human,
        evasive: row.evasive
    })), (type) => typeColour(t, type));

    renderTypeLegend(t);

    tbody(byId('net-asns-table'), data.asns.map((row) => ({
        attrs: dimRow('asn_i', row.asn),
        cells: [
            { text: 'AS' + row.asn, mono: true, nowrap: true, sort: row.asn },
            {
                node: row.org ? dimValue('as_org_s', row.org) : el('span', { class: 'muted', text: '—' }),
                clip: true,
                title: row.org || 'Organisation not resolved',
                sort: row.org || ''
            },
            {
                node: row.as_type
                    ? dimValue('as_type_s', row.as_type)
                    : el('span', { class: 'chip chip-word', text: 'unknown' }),
                sort: row.as_type || ''
            },
            { text: num(row.sessions), num: true, sort: row.sessions },
            { text: num(row.uniq_ips), num: true, sort: row.uniq_ips },
            { text: num(row.hits), num: true, sort: row.hits },
            { text: num(row.human), num: true, sort: row.human },
            { text: num(row.evasive), num: true, sort: row.evasive },
            { node: mixBar(row), sort: row.sessions ? row.evasive / row.sessions : 0 }
        ]
    })));
}

/**
 * Draw the treemap's colour key as DOM, so it inherits the panel's type and palette.
 */
function renderTypeLegend(t) {
    const holder = byId('net-asns-legend');
    if (!holder) {
        return;
    }
    holder.replaceChildren(...['isp', 'mobile', 'hosting', 'vpn', 'edu', 'gov', 'unknown'].map((type) =>
        el('span', { class: 'controls', style: 'gap:6px' }, [
            el('span', { style: 'display:inline-block;width:10px;height:10px;background:' + typeColour(t, type) }),
            el('span', { class: 'muted', text: type })
        ])
    ));
}

/**
 * Draw the network-type donut.
 */
function renderTypes(data) {
    if (!data.astypes.length) {
        noDataYet('net-types-empty', 'network types');
        return;
    }
    hideEmpty('net-types-empty');
    cardChart('net-types', 300);
    const t = tokens();
    donut('net-types', data.astypes.map((row) => ({
        label: row.as_type || 'unknown',
        value: row.sessions,
        color: typeColour(t, row.as_type)
    })), 'sessions', num(data.total));
}

/**
 * Draw the country scatter, reporting how many sessions could not be placed.
 */
function renderMap(data) {
    const points = [];
    let unplaced = 0;
    const largest = data.countries.reduce((max, row) => Math.max(max, row.sessions), 1);

    for (const row of data.countries) {
        const at = locate(row.country);
        if (!at) {
            unplaced += row.sessions;
            continue;
        }
        points.push({
            name: at.name,
            value: [at.lon, at.lat],
            sessions: row.sessions,
            ips: row.uniq_ips,
            human: row.human,
            evasive: row.evasive,
            evasiveRate: row.sessions ? row.evasive / row.sessions : 0,
            size: Math.max(6, Math.min(42, 6 + Math.sqrt(row.sessions / largest) * 34))
        });
    }

    if (!points.length) {
        noDataYet('net-map-empty', 'geolocated sessions');
        return;
    }
    hideEmpty('net-map-empty');
    cardChart('net-map', 300);
    geoScatter('net-map', points);

    setPop('net-map', 'All sessions in range, plotted at country centroids on a plain lon/lat grid — country ' +
        'resolution only, and no basemap because the panel must work air-gapped. Dot area is sessions; a dot is ' +
        'drawn in the accent when more than half its sessions were scored as evasive automation.' +
        (unplaced ? ' ' + num(unplaced) + ' sessions had a country value this build cannot place.' : ''));
}

/**
 * Fill the netblock table.
 */
function renderNetnames(data) {
    if (!data.netnames.length) {
        tbody(byId('net-netnames-table'), []);
        noDataYet('net-netnames-empty', 'netblocks');
        return;
    }
    hideEmpty('net-netnames-empty');

    tbody(byId('net-netnames-table'), data.netnames.map((row) => ({
        attrs: dimRow('netname_s', row.netname),
        cells: [
            {
                node: dimValue('netname_s', row.netname, { mono: true }),
                clip: true,
                title: row.netname || '',
                sort: row.netname || ''
            },
            {
                node: row.org ? dimValue('as_org_s', row.org) : el('span', { class: 'muted', text: '—' }),
                clip: true,
                title: row.org || 'Organisation not resolved',
                sort: row.org || ''
            },
            {
                node: row.as_type
                    ? dimValue('as_type_s', row.as_type)
                    : el('span', { class: 'chip chip-word', text: 'unknown' }),
                sort: row.as_type || ''
            },
            { text: num(row.sessions), num: true, sort: row.sessions },
            { text: num(row.uniq_ips), num: true, sort: row.uniq_ips },
            {
                text: num(row.uniq_fps),
                num: true,
                sort: row.uniq_fps,
                title: 'Distinct header fingerprints from this netblock. Many addresses sharing very few ' +
                    'fingerprints is the rotating-proxy pattern.'
            },
            { text: num(row.human), num: true, sort: row.human },
            { text: num(row.evasive), num: true, sort: row.evasive },
            { node: mixBar(row), sort: row.sessions ? row.evasive / row.sessions : 0 }
        ]
    })));
}

/**
 * Fill the country table.
 */
function renderCountries(data) {
    if (!data.countries.length) {
        tbody(byId('net-countries-table'), []);
        noDataYet('net-countries-empty', 'geolocated sessions');
        return;
    }
    hideEmpty('net-countries-empty');

    tbody(byId('net-countries-table'), data.countries.map((row) => ({
        attrs: dimRow('country_s', row.country),
        cells: [
            {
                node: countryNode(row.country),
                clip: true,
                title: countryName(row.country) + ' (' + row.country + ')',
                sort: countryName(row.country) || row.country
            },
            { text: num(row.sessions), num: true, sort: row.sessions },
            { text: num(row.uniq_ips), num: true, sort: row.uniq_ips },
            { text: num(row.human), num: true, sort: row.human },
            { text: num(row.evasive), num: true, sort: row.evasive },
            {
                text: (row.cities || []).map((city) => city.city + ' (' + num(city.count) + ')').join(', ') || '—',
                clip: true,
                sort: (row.cities || []).length ? row.cities[0].city : ''
            }
        ]
    })));
}

/**
 * Entry point.
 *
 * The map and the country table share one request, which is issued once and rendered into
 * both cards — they are two views of the same facet, not two questions.
 */
export default function init() {
    loadCard('net-stats', 'Counting distinct addresses and networks', async () => {
        renderTotals(await api('networks', 'totals'));
    });
    loadCard('net-asns', 'Faceting autonomous systems', async () => {
        renderAsns(await api('networks', 'asns'));
    });
    loadCard('net-types', 'Faceting network types', async () => {
        renderTypes(await api('networks', 'types'));
    });
    loadCard('net-netnames', 'Faceting netblocks', async () => {
        renderNetnames(await api('networks', 'netnames'));
    });

    let geoPromise = null;
    const geo = () => {
        if (!geoPromise) {
            geoPromise = api('networks', 'geo');
        }
        return geoPromise;
    };
    loadCard('net-map', 'Geolocating sessions', async () => {
        renderMap(await geo());
    });
    loadCard('net-countries', 'Faceting countries', async () => {
        renderCountries(await geo());
    });
}
