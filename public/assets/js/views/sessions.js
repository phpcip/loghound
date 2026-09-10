/*
 * Loghound — Session explorer view.
 *
 * The only view that renders documents, so it is the one that renders the most
 * attacker-controlled text: request paths, User-Agents, referers, AS organisation names.
 * Every one of them goes into the DOM with textContent. The only value that ever becomes
 * an href is `referer_href`, which the SERVER produced by passing the raw referer through
 * Security::safeUrl() — the client never decides that a scheme is safe.
 *
 * The drill-down shows the hit timeline with the beacon overlaid, and states plainly when
 * there is no beacon rather than drawing an empty overlay.
 */

'use strict';

import {
    api, bytes, byId, clear, dec, durUs, dur, el, fill, hideEmpty, load,
    noDataYet, num, pct, shortHash, urlAddFilter, urlRemoveFilter, when
} from '../core.js';

/** Field → label, mirrored from Panel\Query::filterFields() for the chips. */
const FILTER_LABELS = {
    bot_verdict_s: 'Verdict',
    bot_class_s: 'Bot class',
    as_type_s: 'Network type',
    country_s: 'Country',
    browser_s: 'Browser',
    os_s: 'OS',
    device_s: 'Device',
    ua_bot_cat_s: 'Declared bot category',
    referer_type_s: 'Referrer type',
    bot_reasons_ss: 'Signal fired',
    as_org_s: 'AS organisation',
    netname_s: 'Netname',
    fp_hash_s: 'Fingerprint',
    ip_s: 'IP',
    session_id_s: 'Session'
};

/** Verdict chip. */
function verdictChip(verdict) {
    return el('span', { class: 'chip v-' + String(verdict || 'unknown'), text: verdict || 'unknown' });
}

/** The active-filter chips, each a link that removes itself. */
function renderActive(active) {
    const holder = byId('se-active');
    if (!holder) {
        return;
    }
    const chips = [];
    for (const field of Object.keys(active || {})) {
        for (const value of active[field]) {
            chips.push(el('a', {
                href: urlRemoveFilter(field, value),
                title: 'Remove this filter'
            }, [
                el('span', { text: (FILTER_LABELS[field] || field) + ': ' + value }),
                el('span', { text: '×' })
            ]));
        }
    }
    if (!chips.length) {
        clear(holder);
        return;
    }
    fill(holder, [el('div', { class: 'active-filters' }, chips)]);
}

/** The facet sidebar. */
function renderFacets(facets) {
    const holder = byId('se-facet-list');
    if (!holder) {
        return;
    }
    const groups = facets.map((group) => el('div', { class: 'facet-group' }, [
        el('h3', { text: group.label }),
        el('ul', {}, group.buckets.map((b) => el('li', {}, [
            el('a', { href: urlAddFilter(group.field, b.value), title: 'Filter to ' + b.value }, [
                el('span', { class: 'fv', text: b.value }),
                el('span', { class: 'fc', text: num(b.count) })
            ])
        ])))
    ]));
    fill(holder, groups.length ? groups : [el('p', { class: 'muted', text: 'No facet values in this result set.' })]);
}

/** The result table. */
function renderRows(data) {
    const table = byId('se-table');
    const body = table.tBodies[0];
    clear(body);

    if (!data.docs.length) {
        noDataYet('se-table-empty', 'sessions');
        return;
    }
    hideEmpty('se-table-empty');

    for (const doc of data.docs) {
        const tr = el('tr', { class: 'row-link', dataset: { id: doc.id }, tabindex: '0' });

        tr.appendChild(el('td', { class: 'mono nowrap', text: when(doc.ts_start) }));
        tr.appendChild(el('td', {}, [
            verdictChip(doc.verdict),
            doc.score !== null ? el('span', { class: 'muted mono', text: ' ' + dec(doc.score, 0) }) : null
        ]));
        tr.appendChild(el('td', { class: 'mono nowrap', text: doc.ip || '—' }));
        tr.appendChild(el('td', { class: 'clip', title: (doc.as_org || '') + ' ' + (doc.netname || '') }, [
            el('div', { text: doc.as_org || '—' }),
            el('div', { class: 'muted mono', text: [doc.as_type, doc.country].filter(Boolean).join(' · ') || '—' })
        ]));
        tr.appendChild(el('td', { class: 'clip', title: doc.ua || '' }, [
            el('div', {
                text: doc.ua_bot_name || [doc.browser, doc.browser_ver].filter(Boolean).join(' ') || '—'
            }),
            el('div', { class: 'muted', text: [doc.os, doc.device].filter(Boolean).join(' · ') || '—' })
        ]));
        tr.appendChild(el('td', { class: 'num', text: num(doc.hits) }));
        tr.appendChild(el('td', { class: 'num', text: dur(doc.log_span_ms) }));
        // No beacon means engaged time is genuinely unknown, and it says so instead of
        // showing a zero that would read as "bounced instantly".
        tr.appendChild(el('td', { class: 'num', text: doc.beacon ? dur(doc.engaged_ms) : '—' }));
        tr.appendChild(el('td', { class: 'clip mono', title: doc.entry || '', text: doc.entry || '—' }));

        const open = () => openDetail(doc.id);
        tr.addEventListener('click', open);
        tr.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                open();
            }
        });
        body.appendChild(tr);
    }
}

/** Paging controls. */
function renderPager(data) {
    const holder = byId('se-pager');
    if (!holder) {
        return;
    }
    const from = data.numFound ? data.start + 1 : 0;
    const to = Math.min(data.numFound, data.start + data.rows);
    const parts = [el('span', { text: num(from) + '–' + num(to) + ' of ' + num(data.numFound) })];

    const page = (start, label) => {
        const params = new URLSearchParams(window.location.search);
        params.set('start', String(start));
        return el('a', { href: '?' + params.toString(), text: label });
    };
    if (data.start > 0) {
        parts.push(page(Math.max(0, data.start - data.rows), '← Previous'));
    }
    if (to < data.numFound) {
        parts.push(page(data.start + data.rows, 'Next →'));
    }
    fill(holder, parts);
}

/* -------------------------------------------------------------------------
 * Drill-down
 * ---------------------------------------------------------------------- */

/** A definition list from [label, value] pairs, skipping empty ones. */
function kv(pairs) {
    const dl = el('dl', { class: 'kv' });
    for (const [label, value, mono] of pairs) {
        if (value === null || value === undefined || value === '') {
            continue;
        }
        dl.appendChild(el('dt', { text: label }));
        dl.appendChild(typeof value === 'string' || typeof value === 'number'
            ? el('dd', { class: mono ? 'mono' : null, text: String(value) })
            : el('dd', { class: mono ? 'mono' : null }, [value]));
    }
    return dl;
}

/** Open a session and render its detail panel. */
async function openDetail(id) {
    const card = byId('se-detail');
    const body = byId('se-detail-body');
    card.hidden = false;
    fill(body, [el('p', { class: 'muted', text: 'Loading session…' })]);
    card.scrollIntoView({ block: 'nearest' });

    try {
        const data = await api('sessions', 'detail', { id: id });
        renderDetail(body, data);
    } catch (err) {
        fill(body, [el('p', { class: 'muted', text: 'Could not load that session: ' + err.message })]);
    }
}

/** Render the session detail: identity, timings, evidence, timeline. */
function renderDetail(body, data) {
    const s = data.session;

    // --- The four timings, with the beacon caveat stated inline -----------------
    const timings = el('div', { class: 'timing-grid' });
    const add = (key, label, value, defn) => {
        timings.appendChild(el('div', { class: 'timing', dataset: { timing: key } }, [
            el('span', { class: 'timing-label', text: label }),
            el('span', { class: 'timing-value mono', text: value }),
            el('span', { class: 'timing-defn', text: defn })
        ]));
    };
    add('log_span', 'Log span', dur(s.log_span_ms), 'From the access log. Always available.');
    if (s.beacon) {
        add('wall', 'Wall clock', dur(s.wall_ms), 'Page open, tab in any state.');
        add('visible', 'Visible', dur(s.visible_ms), 'Tab visible and window focused.');
        add('engaged', 'Engaged', dur(s.engaged_ms), 'Within 30s of a real interaction.');
    }

    const beaconNote = s.beacon
        ? el('p', { class: 'muted' }, [
            'Beacon data present: ' + num(s.interactions) + ' interactions, ' +
            (s.max_scroll === null ? 'no scroll recorded' : s.max_scroll + '% maximum scroll depth') +
            ', ' + num(s.pageviews) + ' pageviews.'
        ])
        : el('p', { class: 'muted' }, [
            'No beacon arrived for this session, so wall, visible and engaged time are unknown and are not ' +
            'shown. They are not zero — nothing measured them. Log span is all there is.'
        ]);

    // --- Evidence: every reason code with its explanation -----------------------
    const reasons = el('ul', { class: 'plane-list' });
    for (const code of (s.reasons || [])) {
        const meta = data.reasons[code];
        reasons.appendChild(el('li', {}, [
            el('code', { class: 'mono', text: code }),
            meta ? el('span', { text: ' — ' + meta.why }) : el('span', { class: 'muted', text: ' — unknown rule code' })
        ]));
    }
    if (!(s.reasons || []).length) {
        reasons.appendChild(el('li', { class: 'muted', text: 'No signals fired. This session looked ordinary on every plane.' }));
    }

    // --- Execution plane -------------------------------------------------------
    const execRows = [];
    if (s.beacon) {
        execRows.push(['JavaScript ran', s.js ? 'yes' : 'no', true]);
        execRows.push(['Headless signals', s.headless ? 'yes' : 'no', true]);
        execRows.push(['UA claim verified', s.ua_claim_ok === null ? null : (s.ua_claim_ok ? 'yes' : 'no — engine features contradict the User-Agent'), false]);
        execRows.push(['Timezone matches IP', s.tz_match === null ? null : (s.tz_match ? 'yes' : 'no'), false]);
        execRows.push(['WebGL renderer', s.webgl, true]);
        if ((s.automation || []).length) {
            execRows.push(['Automation markers', s.automation.join(', '), true]);
        }
    }

    fill(body, [
        el('div', { class: 'grid-2' }, [
            el('div', {}, [
                el('h3', { text: 'Identity' }),
                kv([
                    ['Session', s.id, true],
                    ['Started', when(s.ts_start), true],
                    ['Ended', when(s.ts_end), true],
                    ['Address', el('a', {
                        href: '?v=sessions&f[ip_s][]=' + encodeURIComponent(s.ip || ''),
                        class: 'mono', text: s.ip || '—'
                    })],
                    ['Netblock', s.ip_net, true],
                    ['ASN', s.asn ? 'AS' + s.asn + (s.as_org ? ' · ' + s.as_org : '') : null],
                    ['Network type', s.as_type, true],
                    ['Netname', s.netname, true],
                    ['Reverse DNS', s.rdns ? s.rdns + (s.rdns_ok ? ' (forward-confirmed)' : ' (NOT confirmed)') : null, true],
                    ['Location', [s.city, s.region, s.country].filter(Boolean).join(', ')],
                    ['IP timezone', s.tz, true]
                ])
            ]),
            el('div', {}, [
                el('h3', { text: 'Client' }),
                kv([
                    ['Browser', [s.browser, s.browser_ver].filter(Boolean).join(' ')],
                    ['OS', s.os],
                    ['Device', s.device, true],
                    ['Declared bot', s.ua_bot ? (s.ua_bot_name || 'yes') + (s.ua_bot_cat ? ' (' + s.ua_bot_cat + ')' : '') : null],
                    ['AI crawler', s.ai_crawler ? 'yes' : null],
                    ['Fingerprint', el('a', {
                        href: '?v=fingerprints&f[fp_hash_s][]=' + encodeURIComponent(s.fp || ''),
                        class: 'mono', text: shortHash(s.fp, 20) || '—',
                        title: s.fp || ''
                    })],
                    ['IPs sharing it (±12h)', s.fp_ips_24h === null ? null : num(s.fp_ips_24h)],
                    ['Referrer', s.referer
                        ? (s.referer_href && s.referer_href !== '#'
                            // The href was validated server-side by Security::safeUrl().
                            ? el('a', { href: s.referer_href, rel: 'noreferrer noopener', text: s.referer })
                            : el('span', { class: 'mono', text: s.referer }))
                        : null],
                    ['Referrer type', s.referer_type, true],
                    ['User-Agent', el('span', { class: 'mono wrap', text: s.ua || '—' })]
                ])
            ])
        ]),

        el('h3', { text: 'How long they stayed' }),
        timings,
        beaconNote,

        el('h3', { text: 'Verdict' }),
        kv([
            ['Verdict', verdictChip(s.verdict)],
            ['Score', s.score === null ? null : dec(s.score, 0) + ' / 100', true],
            ['Class', s.class, true],
            ['Rule version', s.rule_version === null ? null : String(s.rule_version), true]
        ]),
        el('h4', { text: 'Signals that fired' }),
        reasons,

        execRows.length ? el('h4', { text: 'Execution plane' }) : null,
        execRows.length ? kv(execRows) : null,

        el('h3', { text: 'Shape' }),
        kv([
            ['Requests', num(s.hits), true],
            ['Pages / assets', num(s.pages) + ' / ' + num(s.assets), true],
            ['Distinct paths', num(s.uniq_paths), true],
            ['Bytes', bytes(s.bytes), true],
            ['Asset ratio', s.asset_ratio === null ? null : dec(s.asset_ratio * 100, 1) + '%', true],
            ['Median gap', dur(s.gap_p50_ms), true],
            ['Gap std. deviation', dur(s.gap_stddev_ms), true],
            ['Conditional requests', s.got_304 === null ? null : (s.got_304 ? 'yes' : 'none — never sent an If-None-Match')],
            ['Status mix', ['2xx', '3xx', '4xx', '5xx']
                .map((k) => k + ':' + num(s.status[k] || 0)).join('  '), true]
        ]),

        el('h3', { text: 'Request timeline' }),
        renderTimeline(data)
    ]);
}

/** The per-request timeline. */
function renderTimeline(data) {
    if (!data.timeline.length) {
        return el('p', {
            class: 'muted',
            text: 'No individual requests were returned for this session. They may have aged past the retention ' +
                'window on the hits core while the session rollup survived.'
        });
    }

    const list = el('ul', { class: 'timeline' });
    for (const hit of data.timeline) {
        const cls = 't-status-' + String(hit.status || '').charAt(0);
        list.appendChild(el('li', {}, [
            el('span', { class: 'muted', text: when(hit.ts).split(' ')[1] || '' }),
            el('span', { class: 't-method muted', text: hit.method }),
            el('span', { class: 't-path', title: hit.path + (hit.query ? '?' + hit.query : '') }, [
                el('span', { text: hit.path }),
                hit.query ? el('span', { class: 'muted', text: '?' + hit.query }) : null
            ]),
            el('span', { class: cls, text: hit.status === null ? '—' : String(hit.status) }),
            el('span', { class: 't-bytes muted', text: hit.dur_us === null ? bytes(hit.bytes) : durUs(hit.dur_us) })
        ]));
    }

    const note = data.truncated
        ? el('p', { class: 'muted', text: 'Timeline truncated — this session made more requests than the panel will fetch at once.' })
        : null;
    return el('div', {}, [list, note]);
}

/* -------------------------------------------------------------------------
 * Entry point
 * ---------------------------------------------------------------------- */

export default async function init() {
    const close = byId('se-detail-close');
    if (close) {
        close.addEventListener('click', () => { byId('se-detail').hidden = true; });
    }

    await load('se-table-empty', 'sessions', async () => {
        const data = await api('sessions', 'list');

        const count = byId('se-count');
        if (count) {
            count.textContent = num(data.numFound) + ' matching · ' +
                num(data.beacon_count) + ' with beacon data (' + pct(data.beacon_count, data.numFound) + ')';
        }

        renderActive(data.active);
        renderFacets(data.facets);
        renderRows(data);
        renderPager(data);
    });

    // A session id in the URL opens straight into the drill-down, so a link to one
    // session from the fingerprint view lands where it should.
    const params = new URLSearchParams(window.location.search);
    const open = params.get('open');
    if (open) {
        openDetail(open);
    }
}
