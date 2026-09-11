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
    api, byId, cardChart, el, hideEmpty, loadCard, noDataYet, noPivotYet, num, pct, populationLabel,
    setPop, tbody
} from '../core.js';
import { donut, geoScatter, loadWorld, tokens, treemap } from '../charts.js';
import { countryName, locate } from '../geo.js';
import { countryNode, dimRow, dimValue, valueText } from '../identity.js';
import { renderPivot } from '../facetfilter.js';

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
 * A four-segment bar showing the mix of a row.
 *
 * The tooltip names the population in WORDS and gives both the count and the share, which is
 * what the identical bar on Virtual hosts and in the visitor dialog say. It used to derive its
 * label by stripping `bar-` off the CSS class, so it read "evasive: 214" — a palette class name
 * and a bare count, against a percentage everywhere else.
 */
function mixBar(row) {
    const total = Math.max(1, row.sessions);
    const segment = (value, key) => el('span', {
        class: 'bar-' + key,
        style: 'width:' + ((value / total) * 100).toFixed(2) + '%',
        title: populationLabel(key) + ': ' + num(value) + ' (' + pct(value, total) + ')'
    });
    const other = Math.max(0, row.sessions - row.human - row.declared - row.evasive);
    return el('span', { class: 'bar bar-split' }, [
        segment(row.human, 'human'),
        segment(row.declared, 'declared'),
        segment(row.evasive, 'evasive'),
        segment(other, 'unknown')
    ]);
}

/**
 * One network as one cell: what it is called, then what qualifies it.
 *
 * THE DEFECT THIS FIXES. The organisation, the AS number and the network type were three
 * columns, and at the widths this table is read at none of them had room: nine columns under
 * `table-layout: fixed` with a mixed `ch`/`%`/`px` colgroup starve the prose ones first, so
 * `Deutsche Telekom AG` arrived as `Deutsche Telek` with no ellipsis and no gap before the
 * word in the next column. They are one subject — this network — and belong in one cell with
 * a primary line and a quieter second one. Each part is still its own filter control.
 *
 * @param {Object} row
 * @param {Node} lead   The name this row is known by.
 * @param {Array<Node>} extra Anything that qualifies it, before the type.
 */
function networkCell(row, lead, extra) {
    const lower = (extra || []).slice();
    if (row.as_type) {
        if (lower.length) {
            lower.push(el('span', { text: ' · ' }));
        }
        lower.push(dimValue('as_type_s', row.as_type));
    }
    return el('div', { class: 'client' }, [
        el('div', { class: 'clip-line' }, [lead]),
        el('div', { class: 'sub clip-line' }, lower.length ? lower : [el('span', { text: '—' })])
    ]);
}

/**
 * The mix bar with the two counts that were columns of their own underneath it.
 *
 * Human and evasive were a numeric column each, next to a bar that already encodes both as
 * area. Two representations of one fact, costing sixteen per cent of the table between them.
 * The bar keeps the comparison and the figures sit under it as a caption, which is where a
 * reader looks once the bar has told them which row to look at.
 */
function mixCell(row) {
    /* LABEL THEN COUNT, not "N <label>". The population labels are plural nouns and one of
       them ("Unknown") is not a noun at all, so "1 declared crawlers" and "1 unknown" both
       come out wrong however the count is pluralised. Naming the population and then its
       figure is grammatical at every count and reads the same as the bar's own tooltip. */
    const other = Math.max(0, row.sessions - row.human - row.declared - row.evasive);
    const parts = [populationLabel('human') + ' ' + num(row.human)];
    if (row.declared) {
        parts.push(populationLabel('declared') + ' ' + num(row.declared));
    }
    if (row.evasive) {
        parts.push(populationLabel('evasive') + ' ' + num(row.evasive));
    }
    if (other) {
        parts.push(populationLabel('unknown') + ' ' + num(other));
    }
    return el('div', {}, [
        mixBar(row),
        el('div', { class: 'sub clip-line', text: parts.join(' · ') })
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
            {
                node: networkCell(row, row.org ? dimValue('as_org_s', row.org) : el('span', { text: 'AS' + row.asn }),
                    [el('span', { class: 'mono', text: 'AS' + row.asn })]),
                clip: true,
                title: [row.org, 'AS' + row.asn, row.as_type].filter(Boolean).join(' · '),
                sort: row.org || String(row.asn)
            },
            { text: num(row.sessions), num: true, sort: row.sessions },
            { text: num(row.uniq_ips), num: true, sort: row.uniq_ips },
            { text: num(row.hits), num: true, sort: row.hits },
            { node: mixCell(row), sort: row.sessions ? row.evasive / row.sessions : 0 }
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
    /* THE KEY READS IN WORDS. It printed the stored `as_type_s` slugs — isp, vpn, edu — three
       lines above a donut of the same values rendered as "Consumer ISP", "VPN / anonymiser"
       and "Education", so one chart's key disagreed with the next chart's labels. The swatch
       is decorative and says so; the word beside it is the whole content of the entry. */
    holder.replaceChildren(...['isp', 'mobile', 'hosting', 'vpn', 'edu', 'gov', 'unknown'].map((type) =>
        el('span', { class: 'controls', style: 'gap:6px' }, [
            el('span', {
                class: 'swatch',
                'aria-hidden': 'true',
                style: 'background:' + typeColour(t, type)
            }),
            el('span', { class: 'muted', text: valueText('as_type_s', type) })
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
        label: valueText('as_type_s', row.as_type || 'unknown'),
        value: row.sessions,
        color: typeColour(t, row.as_type)
    })), 'sessions', num(data.total));
}

/**
 * Draw the country bubbles on the world outline, reporting what could not be placed.
 *
 * THE BASEMAP IS LOADED HERE AND NOWHERE ELSE. It is 155 KB of coordinates for one card on one
 * view, so it is fetched by the card that needs it rather than bundled into every page, and it
 * is a file in this repository rather than a request to a tile server — the panel must work
 * air-gapped behind a CSP with no outside origin. If the fetch fails the chart falls back to
 * the bare longitude/latitude grid it used to be, which is worse but still true.
 */
async function renderMap(data) {
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
            name: countryName(row.country) || at.name,
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
    cardChart('net-map', 340);
    await loadWorld('');
    geoScatter('net-map', points);

    setPop('net-map', 'All sessions in range, placed at their country. Bubble area is sessions, and a bubble is ' +
        'drawn in the accent when more than half of its sessions were scored as evasive automation. Country ' +
        'resolution only: a session is placed at its country, never at a street.' +
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
                node: networkCell(row, dimValue('netname_s', row.netname, { mono: true }),
                    row.org ? [dimValue('as_org_s', row.org)] : []),
                clip: true,
                title: [row.netname, row.org, row.as_type].filter(Boolean).join(' · '),
                sort: row.netname || ''
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
            { node: mixCell(row), sort: row.sessions ? row.evasive / row.sessions : 0 }
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
    /* ONE request, TWO cards. The cross-tab rides on this payload rather than fetching again,
       so the pivot costs no extra round trip — but it is its own card, so it keeps its own
       progress line and its own failure state. Both await the same promise. */
    const totals = api('networks', 'totals');
    loadCard('net-stats', 'Counting distinct addresses and networks', async () => {
        renderTotals(await totals);
    });
    if (byId('net-pivot-table')) {
        loadCard('net-pivot', 'Cross-tabulating the filtered population', async () => {
            const data = await totals;
            if (!renderPivot('net-pivot', data.pivot)) {
                noPivotYet('net-pivot-empty', 'both a network type and a verdict');
            }
        });
    }
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
