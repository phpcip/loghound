/*
 * Loghound — the two detail dialogs every view opens.
 *
 * A row in this panel names one of two things, so there are two dialogs and no more:
 *
 *   SESSION — one visitor's visit. Who they are, what they used, how long they were really
 *   there across all four clocks, how they arrived, what the scorer concluded and WHICH RULES
 *   FIRED to produce it, and then every request they made in order with timestamps, status
 *   codes and bytes. The rule list is the thing no JavaScript analytics product can show,
 *   because it never computed a verdict in the first place.
 *
 *   DIMENSION — one value of one dimension: a country, an AS organisation, a netname, a
 *   browser, a verdict, a path. How much traffic it accounts for and of what kind, how it
 *   breaks down along every other dimension, and a sample of the actual recent visitors behind
 *   it — each of which opens their own session dialog, so a drill-down keeps going rather than
 *   ending in a number.
 *
 * WHY THEY ARE HERE AND NOT IN A VIEW. Every view wants both. The Networks page opens a
 * netname, the Bots page opens a verdict, the Overview opens a path, and the session explorer
 * opens all of them plus a session — and each of them was previously a dead end. Registering
 * the two openers once means a table anywhere in the panel becomes drillable by adding data
 * attributes to its rows (see identity.js drillRow / dimRow) and nothing else.
 *
 * EVERY VALUE IN HERE IS HOSTILE. Paths, User-Agents, referrers, AS organisation names, RIR
 * netnames and any identity the measured site chose to attach are all somebody else's input.
 * All of it reaches the DOM through core.js's el({text}), which is textContent. The only value
 * that becomes an href is one the SERVER already passed through Security::safeUrl() — the
 * client never decides that a scheme is safe — and the filter links are built with
 * encodeURIComponent by identity.js.
 */

'use strict';

import {
    api, bytes, dec, dur, durUs, el, fill, num, pct, shortHash, when
} from './core.js';
import { closeDialog, dialogFail, isCurrent, openDialog, registerOpener } from './dialog.js';
import { clientNode, countryNode, dimLabel, dimValue, flagNode, networkNode } from './identity.js';
import { markSortable } from './sorttable.js';
import { countryName } from './geo.js';

/** Population keys in the order every other chart in the panel stacks them. */
const ORDER = ['human', 'unknown', 'declared', 'ai', 'evasive'];

/**
 * The verdict chip, coloured the same way it is everywhere else.
 *
 * A verdict is a word, not an identifier whose characters
 * have to line up, and monospace on everything was making prose read as code.
 */
function verdictChip(verdict) {
    return el('span', {
        class: 'chip v-' + String(verdict || 'unknown'),
        text: verdict || 'unknown'
    });
}

/**
 * A definition list from [label, value, mono] triples, skipping the empty ones.
 *
 * Skipping rather than printing an em-dash for every absent field: a dialog with nine "—" rows
 * in it buries the four facts that are actually known. Where an absence is itself the finding
 * — no beacon, no conditional requests — the caller passes an explicit sentence instead.
 */
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

/** A note saying which filters produced the numbers below it, or nothing when none did. */
function filterNote(active) {
    const parts = [];
    for (const field of Object.keys(active || {})) {
        for (const value of active[field]) {
            parts.push(dimLabel(field) + ': ' + value);
        }
    }
    if (!parts.length) {
        return null;
    }
    return el('p', {
        class: 'faint',
        text: 'Scoped to the filters currently in force — ' + parts.join(', ') +
            ' — and to the selected time range. Clearing them changes every number here.'
    });
}

/* -------------------------------------------------------------------------
 * The session dialog
 * ---------------------------------------------------------------------- */

/**
 * The four clocks, each with the sentence that says what it measures.
 *
 * Log span is always drawn because it always exists. The other three are drawn only when a
 * beacon arrived, and when one did not the dialog says so in words rather than showing three
 * zeroes — a zero is a measurement and "nobody measured this" is not the same claim.
 */
function clocks(s) {
    const grid = el('div', { class: 'timing-grid' });
    const add = (key, label, value, defn) => {
        grid.appendChild(el('div', { class: 'timing', dataset: { timing: key } }, [
            el('span', { class: 'timing-label', text: label }),
            el('span', { class: 'timing-value mono', text: value }),
            el('span', { class: 'timing-defn', text: defn })
        ]));
    };
    add('log_span', 'Log span', dur(s.log_span_ms), 'Last request minus first. From the access log, always present.');
    if (s.beacon) {
        add('wall', 'Wall clock', dur(s.wall_ms), 'The page existed for this long, tab in any state.');
        add('visible', 'Visible', dur(s.visible_ms), 'Tab visible and window focused.');
        add('engaged', 'Engaged', dur(s.engaged_ms), 'Visible, within 30s of a real interaction.');
    }
    return grid;
}

/** The rules that fired, each with the plain-English description of what it means. */
function firedRules(s, catalogue) {
    const list = el('ul', { class: 'plane-list' });
    for (const code of (s.reasons || [])) {
        const meta = (catalogue || {})[code];
        list.appendChild(el('li', {}, [
            dimValue('bot_reasons_ss', code),
            meta
                ? el('span', { text: ' — ' + meta.why })
                : el('span', { class: 'muted', text: ' — no description for this rule code in this panel version' })
        ]));
    }
    if (!(s.reasons || []).length) {
        list.appendChild(el('li', {
            class: 'muted',
            text: 'No signal fired. This session looked ordinary on the transport, behaviour and execution planes ' +
                'alike, which is why the verdict is what it is.'
        }));
    }
    return list;
}

/**
 * The request trail: every hit in the session, in order.
 *
 * This is the thing an operator reads behaviour from — what somebody was trying to do and what
 * they wanted — so it is the last and largest block in the dialog rather than a footnote. One
 * query against the hits core tied by `session_id_s` and sorted by time is the whole trail; the
 * server caps it and says when it did, because "the last 200 of 4,000 requests" presented as
 * the trail would be a lie by omission.
 */
function trail(data) {
    if (!data.timeline.length) {
        return el('p', {
            class: 'muted',
            text: 'No individual requests came back for this session. They may have aged past the retention ' +
                'window on the hits core while the session rollup survived — the rollup is kept longer on purpose.'
        });
    }

    const list = el('ul', { class: 'timeline' });
    for (const hit of data.timeline) {
        const statusClass = 't-status-' + String(hit.status === null ? '' : hit.status).charAt(0);
        list.appendChild(el('li', {}, [
            el('span', { class: 'muted mono', text: when(hit.ts).split(' ')[1] || '' }),
            el('span', { class: 't-method muted', text: hit.method || '' }),
            el('span', { class: 't-path', title: hit.path + (hit.query ? '?' + hit.query : '') }, [
                el('span', { text: hit.path }),
                hit.query ? el('span', { class: 'muted', text: '?' + hit.query }) : null
            ]),
            el('span', { class: statusClass + ' mono', text: hit.status === null ? '—' : String(hit.status) }),
            el('span', { class: 't-bytes muted mono', text: bytes(hit.bytes) }),
            el('span', {
                class: 't-dur muted mono',
                text: hit.dur_us === null ? '' : durUs(hit.dur_us),
                title: hit.dur_us === null ? '' : 'Time the server took to answer'
            })
        ]));
    }

    return el('div', {}, [
        list,
        data.truncated
            ? el('p', {
                class: 'muted',
                text: 'Trail truncated — this session made more requests than the panel fetches at once, so what ' +
                    'you are reading is the beginning of it, not all of it.'
            })
            : null
    ]);
}

/**
 * What the measured site said about who this was, if it said anything.
 *
 * TWO INDEPENDENT FACTS, and the strip says which of them it has. A site can pass an identity
 * without the visitor being authenticated, and can record "this was a signed-in session"
 * without handing over who it was, so neither is inferred from the other. `signed_in === null`
 * means the site never told us, and it reads as "not reported" rather than as "anonymous" —
 * a visitor nobody classified is not a visitor who was classified as logged out.
 *
 * Absent entirely when there is nothing to say, because a strip announcing two unknowns on
 * every session on every installation that has not adopted the feature is noise.
 */
function identStrip(s) {
    if (!s.ident && s.signed_in === null) {
        return null;
    }

    const parts = [];
    if (s.ident) {
        parts.push(el('span', { class: 'ident-label', text: 'Identified as' }));
        parts.push(el('span', { class: 'ident-value mono', text: s.ident }));
    }
    parts.push(el('span', {
        class: 'chip ' + (s.signed_in === true ? 'chip-good' : ''),
        text: s.signed_in === true ? 'signed in' : (s.signed_in === false ? 'anonymous' : 'sign-in state not reported')
    }));
    parts.push(el('span', {
        class: 'faint',
        text: 'Declared by the measured site through the beacon. Loghound never derives, guesses or scrapes ' +
            'either of these.'
    }));

    return el('div', { class: 'ident-strip' }, parts);
}

/**
 * Render one session into the dialog body.
 *
 * The order is the order the questions get asked: who, what they used, who they say they are,
 * how long, how they arrived, what we concluded and why, what shape the visit had, and finally
 * the trail.
 */
function renderSession(body, data) {
    const s = data.session;

    const identity = [
        ['Session', s.id, true],
        ['Started', when(s.ts_start), true],
        ['Ended', when(s.ts_end), true],
        ['Address', s.ip ? dimValue('ip_s', s.ip, { mono: true }) : null],
        ['Netblock', s.ip_net, true],
        ['Where', s.country
            ? el('span', { class: 'geo' }, [
                flagNode(s.country),
                el('span', { text: [s.city, s.region, countryName(s.country) || s.country].filter(Boolean).join(', ') })
            ])
            : null],
        ['Network', s.as_org || s.asn ? networkNode(s) : null],
        ['ASN', s.asn ? 'AS' + s.asn : null, true],
        ['Reverse DNS', s.rdns
            ? s.rdns + (s.rdns_ok ? ' (forward-confirmed)' : ' (NOT forward-confirmed)')
            : null, true],
        ['IP timezone', s.tz, true]
    ];

    const client = [
        ['Browser', s.browser ? dimValue('browser_s', s.browser, {
            text: [s.browser, s.browser_ver].filter(Boolean).join(' ')
        }) : null],
        ['OS', s.os ? dimValue('os_s', s.os) : null],
        ['Device', s.device ? dimValue('device_s', s.device, { mono: true }) : null],
        ['Declared bot', s.ua_bot
            ? (s.ua_bot_name || 'yes') + (s.ua_bot_cat ? ' (' + s.ua_bot_cat + ')' : '')
            : null],
        ['AI crawler', s.ai_crawler ? 'yes' : null],
        ['Header fingerprint', s.fp
            ? dimValue('fp_hash_s', s.fp, { mono: true, text: shortHash(s.fp, 20), title: s.fp })
            : null],
        ['Addresses sharing it (±12h)', s.fp_ips_24h === null ? null : num(s.fp_ips_24h)],
        ['User-Agent', el('span', { class: 'mono wrap', text: s.ua || 'not recorded' })]
    ];

    const arrival = [
        ['Entry page', s.entry, true],
        ['Exit page', s.exit, true],
        ['Referrer', s.referer
            ? (s.referer_href && s.referer_href !== '#'
                ? el('a', { href: s.referer_href, rel: 'noreferrer noopener', text: s.referer })
                : el('span', { class: 'mono wrap', text: s.referer }))
            : 'none sent'],
        ['Referrer type', s.referer_type ? dimValue('referer_type_s', s.referer_type) : null],
        ['Virtual host', s.host ? dimValue('host_s', s.host, { mono: true }) : null]
    ];

    const execution = [];
    if (s.beacon) {
        execution.push(['JavaScript ran', s.js ? 'yes' : 'no', true]);
        execution.push(['Headless signals', s.headless ? 'yes' : 'no', true]);
        execution.push(['UA claim verified', s.ua_claim_ok === null
            ? null
            : (s.ua_claim_ok ? 'yes' : 'no — the engine\'s features contradict the User-Agent')]);
        execution.push(['Timezone matches IP', s.tz_match === null ? null : (s.tz_match ? 'yes' : 'no')]);
        execution.push(['WebGL renderer', s.webgl, true]);
        if ((s.automation || []).length) {
            execution.push(['Automation markers', s.automation.join(', '), true]);
        }
    }

    fill(body, [
        identStrip(s),

        el('div', { class: 'grid-2' }, [
            el('div', {}, [el('h3', { text: 'Who' }), kv(identity)]),
            el('div', {}, [el('h3', { text: 'What they used' }), kv(client)])
        ]),

        el('h3', { text: 'How long they were really there' }),
        clocks(s),
        s.beacon
            ? el('p', { class: 'muted', text:
                'Beacon data present: ' + num(s.interactions) + ' interactions, ' +
                (s.max_scroll === null ? 'no scroll recorded' : s.max_scroll + '% deepest scroll') +
                ', ' + num(s.pageviews) + ' pageviews.' })
            : el('p', { class: 'muted', text:
                'No beacon arrived for this session, so wall, visible and engaged time are unknown and are not ' +
                'shown. They are not zero — nothing measured them. Log span is all there is, and it cannot see ' +
                'the last page of the visit at all.' }),

        el('h3', { text: 'How they arrived' }),
        kv(arrival),

        el('h3', { text: 'The verdict, and why' }),
        kv([
            ['Verdict', verdictChip(s.verdict)],
            ['Score', s.score === null ? null : dec(s.score, 0) + ' / 100', true],
            ['Class', s.class ? dimValue('bot_class_s', s.class) : null],
            ['Ruleset version', s.rule_version === null ? null : String(s.rule_version), true]
        ]),
        el('h4', { text: 'Rules that fired' }),
        firedRules(s, data.reasons),

        execution.length ? el('h4', { text: 'Execution plane' }) : null,
        execution.length ? kv(execution) : null,

        el('h3', { text: 'The shape of the visit' }),
        kv([
            ['Requests', num(s.hits), true],
            ['Pages / assets', num(s.pages) + ' / ' + num(s.assets), true],
            ['Distinct paths', num(s.uniq_paths), true],
            ['Bytes', bytes(s.bytes), true],
            ['Asset ratio', s.asset_ratio === null ? null : dec(s.asset_ratio * 100, 1) + '%', true],
            ['Median gap between requests', dur(s.gap_p50_ms), true],
            ['Gap standard deviation', dur(s.gap_stddev_ms), true],
            ['Conditional requests', s.got_304 === null
                ? null
                : (s.got_304 ? 'yes' : 'none — never sent an If-None-Match, which a browser cache would have')],
            ['Status mix', ['2xx', '3xx', '4xx', '5xx']
                .map((k) => k + ':' + num(s.status[k] || 0)).join('  '), true]
        ]),

        el('h3', { text: 'Everything they requested, in order' }),
        trail(data)
    ]);
}

/**
 * Open one session.
 *
 * Exported so a view can open a session it already has the id of — the `?open=` deep link on
 * the session explorer does exactly that.
 */
export async function openSession(id) {
    const handle = openDialog('Session ' + String(id).slice(0, 12), 'Loading the visit and its request trail…');
    try {
        const data = await api('sessions', 'detail', { id: id });
        if (!isCurrent(handle.generation)) {
            return;
        }
        const s = data.session;
        const where = [s.city, s.country].filter(Boolean).join(', ');
        openDialog(
            s.ident || s.ip || 'Session',
            [when(s.ts_start), where, s.as_org, s.verdict].filter(Boolean).join(' · ')
        );
        const body = document.getElementById('lh-dialog-body');
        renderSession(body, data);
        markSortable(body);
    } catch (err) {
        if (isCurrent(handle.generation)) {
            dialogFail(handle.body, err);
        }
    }
}

/* -------------------------------------------------------------------------
 * The dimension dialog
 * ---------------------------------------------------------------------- */

/** The five-population mix as one bar, in the colours the rest of the panel uses. */
function mixBar(mix, total) {
    const denominator = total || 1;
    return el('span', { class: 'bar bar-split' }, ORDER.map((key) => el('span', {
        class: 'bar-' + key,
        style: 'width:' + (((mix[key] || 0) / denominator) * 100).toFixed(2) + '%',
        title: key + ': ' + num(mix[key] || 0) + ' (' + pct(mix[key] || 0, denominator) + ')'
    })));
}

/** One breakdown: a dimension, its values with counts, each value a filter control. */
function breakdown(group, total) {
    return el('div', { class: 'fgroup' }, [
        el('h4', { text: group.label }),
        el('ul', {}, group.buckets.map((bucket) => el('li', {}, [
            dimValue(group.field, bucket.value, { count: bucket.count, mono: group.mono }),
            el('span', { class: 'faint', text: pct(bucket.count, total) })
        ])))
    ]);
}

/**
 * The recent visitors behind a dimension value.
 *
 * The point of the whole exercise: a count becomes people, each row carries enough identity to
 * read at a glance, and each row opens the visit. Kept short on purpose — this is a sample to
 * start from, and the session explorer with the filter applied is where the full list lives.
 */
function visitorTable(rows) {
    if (!rows.length) {
        return el('p', { class: 'muted', text: 'No session in range carries this value.' });
    }

    const body = el('tbody');
    for (const v of rows) {
        const tr = el('tr', {
            class: 'row-link',
            tabindex: '0',
            role: 'button',
            dataset: { lhOpen: 'session', id: v.id },
            title: 'Open this visit'
        });
        tr.appendChild(el('td', { class: 'mono nowrap', text: when(v.ts_start), 'data-sort': v.ts_start || '' }));
        tr.appendChild(el('td', { 'data-sort': [v.country, v.city].filter(Boolean).join(' ') }, [
            v.country ? countryNode(v.country, { short: true }) : el('span', { class: 'muted', text: '—' }),
            v.city ? el('div', { class: 'sub', text: v.city }) : null
        ]));
        tr.appendChild(el('td', { class: 'mono clip', title: v.ip || '' }, [
            el('span', { text: v.ident || v.ip || '—' }),
            v.signed_in === true ? el('span', { class: 'chip chip-good', text: 'signed in' }) : null
        ]));
        tr.appendChild(el('td', {
            class: 'clip',
            title: [v.as_org, v.netname].filter(Boolean).join(' · ') || 'Network not resolved',
            'data-sort': v.as_org || v.netname || ''
        }, [networkNode(v)]));
        tr.appendChild(el('td', {
            class: 'clip',
            'data-sort': v.ua_bot_name || v.browser || ''
        }, [clientNode(v)]));
        tr.appendChild(el('td', { class: 'num', text: num(v.hits), 'data-sort': v.hits === null ? '' : String(v.hits) }));
        tr.appendChild(el('td', {
            class: 'clip mono',
            title: v.entry || '',
            text: v.entry || '—',
            'data-sort': v.entry || ''
        }));
        tr.appendChild(el('td', { 'data-sort': v.verdict || '' }, [verdictChip(v.verdict)]));
        body.appendChild(tr);
    }

    const table = el('table', { class: 'tight table-fixed' }, [
        el('colgroup', {}, [
            el('col', { style: 'width:13ch' }), el('col', { style: 'width:10ch' }),
            el('col', { style: 'width:16ch' }), el('col', { style: 'width:20%' }),
            el('col', { style: 'width:16%' }), el('col', { style: 'width:6ch' }),
            el('col'), el('col', { style: 'width:11ch' })
        ]),
        el('thead', {}, [el('tr', {}, [
            el('th', { scope: 'col', text: 'Started' }),
            el('th', { scope: 'col', text: 'Where' }),
            el('th', { scope: 'col', text: 'Who' }),
            el('th', { scope: 'col', text: 'Network' }),
            el('th', { scope: 'col', text: 'Client' }),
            el('th', { scope: 'col', class: 'num', text: 'Reqs' }),
            el('th', { scope: 'col', text: 'Page' }),
            el('th', { scope: 'col', text: 'Verdict' })
        ])]),
        body
    ]);

    return el('div', { class: 'table-wrap' }, [table]);
}

/** What the webserver actually returned for a path, when the dimension is one. */
function requestProfile(req) {
    if (!req) {
        return null;
    }
    const statuses = req.status.map((row) => el('li', {}, [
        el('code', { class: 'mono', text: String(row.status) }),
        el('span', { class: 'faint', text: num(row.count) + ' · ' + pct(row.count, req.hits) })
    ]));

    return el('div', {}, [
        el('h3', { text: 'What the server actually returned' }),
        kv([
            ['Requests', num(req.hits), true],
            ['Bytes served', bytes(req.bytes), true],
            ['Median response time', req.dur_p50 === null ? null : durUs(req.dur_p50), true],
            ['95th percentile', req.dur_p95 === null ? null : durUs(req.dur_p95), true]
        ]),
        el('div', { class: 'fgroup' }, [el('h4', { text: 'Status codes' }), el('ul', {}, statuses)]),
        (req.ignored || []).length
            ? el('p', { class: 'faint', text: 'These figures come from the hits core, which cannot answer ' +
                (req.ignored || []).join(', ') + ' — those filters are not applied here and the numbers above ' +
                'are therefore wider than the session counts.' })
            : null
    ]);
}

/** Render one dimension value into the dialog body. */
function renderDimension(body, data) {
    const total = data.sessions || 0;

    fill(body, [
        el('div', { class: 'stats' }, [
            statTile('Sessions', num(total), 'In the selected range and filters'),
            statTile('Distinct addresses', num(data.uniq_ips), 'Approximate above ~100 (Solr unique())'),
            statTile('Header fingerprints', num(data.uniq_fps), 'Few fingerprints across many addresses is a fleet'),
            statTile('Requests', num(data.hits), 'Log lines attributed to these sessions')
        ]),

        filterNote(data.active),

        el('h3', { text: 'What kind of traffic this is' }),
        mixBar(data.mix, total),
        kv(ORDER.map((key) => [
            data.labels[key] || key,
            num(data.mix[key] || 0) + ' · ' + pct(data.mix[key] || 0, total || 1),
            true
        ])),

        el('h3', { text: 'When, and for how long' }),
        kv([
            ['First seen', when(data.first), true],
            ['Last seen', when(data.last), true],
            ['Median log span', data.log_span_p50 === null ? null : dur(data.log_span_p50), true],
            ['Sessions with beacon data', num(data.beacon.sessions), true],
            ['Median engaged time', data.beacon.sessions
                ? (data.beacon.engaged_p50 === null ? null : dur(data.beacon.engaged_p50))
                : null, true],
            ['Median wall clock', data.beacon.sessions
                ? (data.beacon.wall_p50 === null ? null : dur(data.beacon.wall_p50))
                : null, true],
            ['Average bot score', data.score === null ? null : dec(data.score, 0) + ' / 100', true],
            ['Bytes served', bytes(data.bytes), true]
        ]),
        data.beacon.sessions === 0
            ? el('p', { class: 'muted', text: 'No session with this value produced beacon data, so the three ' +
                'measured clocks are unknown rather than zero. Log span is all there is here.' })
            : null,

        requestProfile(data.requests),

        el('h3', { text: 'How it breaks down' }),
        el('p', { class: 'faint', text: 'Every value below is a filter: clicking one scopes the whole dashboard ' +
            'to it on top of what is already filtered.' }),
        el('div', { class: 'fpanel' }, data.breakdowns.map((group) => breakdown(group, total))),

        el('h3', { text: 'Recent visitors' }),
        el('p', { class: 'faint', text: 'The most recent ' + num(data.visitors.length) +
            ' of ' + num(total) + '. Each row opens the whole visit.' }),
        visitorTable(data.visitors),

        data.filterable
            ? el('p', {}, [
                dimValue(data.field, data.value, {
                    text: 'Filter the whole dashboard to this ' + String(data.label).toLowerCase()
                })
            ])
            : el('p', { class: 'faint', text: 'This dimension can be inspected but not filtered on: ' +
                data.field + ' is not in the panel\'s filter allowlist yet.' })
    ]);
}

/** One headline figure with its label and the caveat that belongs to it. */
function statTile(label, value, hint) {
    return el('div', { class: 'stat' }, [
        el('span', { class: 'stat-label', text: label }),
        el('span', { class: 'stat-value mono', text: value }),
        el('span', { class: 'stat-hint', text: hint })
    ]);
}

/**
 * Open one dimension value.
 *
 * @param {string} field Solr field name; the server checks it against its own allowlist.
 * @param {string} value The value, exactly as it was rendered.
 */
export async function openDimension(field, value) {
    const handle = openDialog(String(value), dimLabel(field) + ' — counting sessions…');
    try {
        const data = await api('sessions', 'dimension', { field: field, value: value });
        if (!isCurrent(handle.generation)) {
            return;
        }
        openDialog(
            String(data.value),
            data.label + ' · ' + num(data.sessions) + ' sessions in ' + (data.range_label || 'range')
        );
        const body = document.getElementById('lh-dialog-body');
        renderDimension(body, data);
        markSortable(body);
    } catch (err) {
        if (isCurrent(handle.generation)) {
            dialogFail(handle.body, err);
        }
    }
}

/**
 * Register both openers.
 *
 * Called once from app.js, so every view has them without each view remembering to. The
 * registration is idempotent: a second call replaces the same two entries.
 */
export function initDetail() {
    registerOpener('session', (data) => openSession(data.id || ''));
    registerOpener('dim', (data) => openDimension(data.field || '', data.value || ''));

    const open = new URLSearchParams(window.location.search).get('open');
    if (open) {
        openSession(open);
    }
}

export { closeDialog };
