/*
 * Loghound — Attacks view.
 *
 * Eight independent cards, and the ordering of every one of them is the same idea: WHAT THE
 * SERVER ANSWERED outranks what was tried. A traversal attempt answered 404 is what a
 * webserver is for; the same attempt answered 200 is the reason this page exists.
 *
 * Nothing on this page may be worded as though Loghound blocked anything. It reads a log after
 * the fact. The words "blocked", "stopped" and "prevented" do not appear, and "answered with a
 * 200" is never shortened to "disclosed" — a site whose error page carries a 200 status looks
 * identical in a log, and that caveat travels with the number rather than living in a footnote.
 *
 * EVERY VALUE RENDERED HERE WAS CHOSEN BY AN ATTACKER. Paths, query strings, methods, reverse
 * DNS, User-Agent-derived names. Every one of them goes into the DOM as TEXT through el() and
 * tbody(), never as markup, and the one place a URL becomes an href is refused unless the
 * server pre-validated it.
 */

'use strict';

import {
    api, byId, cardChart, el, hideEmpty, loadCard, noDataYet, noPivotYet, num, pct, setPop, tbody, when
} from '../core.js';
import { lines, stackedBars, tokens } from '../charts.js';
import { countryNode, dimRow, dimValue, drillRow, openButton, valueText, valueWords } from '../identity.js';
import { renderPivot } from '../facetfilter.js';
import { pagedCard } from '../cardtable.js';

/**
 * The colour of a status class, used by both charts so they cannot disagree.
 *
 * The accent is spent on 2xx and nowhere else. It is the only row on this page an operator
 * has to act on, and a palette that made every status equally loud would bury it in the 4xx
 * bulk that is ninety-nine per cent of the data.
 */
function statusColour(t, key) {
    switch (key) {
        case 'ok':       return t.accent;
        case 'redirect': return t.pop.ai;
        case 'refused':  return t.pop.human;
        case 'broke':    return t.pop.declared;
        default:         return t.pop.unknown;
    }
}

/** The four status classes in the order every table and chart on this page uses them. */
const STATUS_KEYS = [
    ['ok', '2xx Answered'],
    ['redirect', '3xx Redirected'],
    ['refused', '4xx Refused'],
    ['broke', '5xx Server error'],
    ['unknown', 'Status not recorded']
];

/**
 * A stacked bar showing how one row's requests were answered.
 *
 * The whole page in one control: the reader scans the column and the rows with any accent in
 * them are the ones to open. The tooltip names the class in words and gives the count and the
 * share, because a bar with no figures is a shape nobody can quote.
 */
function statusBar(row) {
    const total = Math.max(1, row.count);
    return el('span', { class: 'bar bar-split' }, STATUS_KEYS.map(([key, label]) => el('span', {
        class: 'bar-' + (key === 'ok' ? 'evasive' : (key === 'refused' ? 'human' : (key === 'redirect' ? 'ai' : 'unknown'))),
        style: 'width:' + (((row[key] || 0) / total) * 100).toFixed(2) + '%',
        title: label + ': ' + num(row[key] || 0) + ' (' + pct(row[key] || 0, total) + ')'
    })));
}

/**
 * The severity mark that precedes a pattern name.
 *
 * Words, never a coloured dot alone: this is a security page and a reader who cannot
 * distinguish the colours must still be able to sort the rows. The severity describes how much
 * a MATCH is worth before the status is known, which is why it is the quiet half of the cell
 * and the answered count is the loud one.
 */
function severityNote(severity) {
    switch (severity) {
        case 'high': return 'High if answered';
        case 'med':  return 'Medium if answered';
        case 'low':  return 'Low — usually noise';
        default:     return 'Informational';
    }
}

/**
 * A pattern as one cell: its name, then what qualifies it.
 *
 * The name is a filter control, because "show me only this pattern" is the first thing an
 * operator wants from a row. The second line carries the family and the severity, which are
 * the two facts that decide whether a row with no answered requests is worth reading at all.
 */
function patternCell(row, families) {
    return el('div', { class: 'client' }, [
        el('div', { class: 'clip-line' }, [dimValue('hit_flags_ss', row.code)]),
        el('div', {
            class: 'sub clip-line',
            text: (families[row.family] || row.family) + ' · ' + severityNote(row.severity)
        })
    ]);
}

/**
 * What this plane could not honour, as a sentence to append to a population caption.
 *
 * A verdict, a bot class and a fired scoring signal are conclusions about a whole SESSION and
 * exist only on the sessions core, so a chip for one of them stays lit in the filter bar while
 * doing nothing to five of this page's six cards. Saying so is the whole point: a filter that is
 * silently ignored turns a wrong answer into one the reader has no reason to doubt.
 */
function ignoredFilterNote(data) {
    const ignored = Array.isArray(data.filters_ignored) ? data.filters_ignored : [];
    if (ignored.length === 0) {
        return '';
    }
    return ' NOTE: ' + ignored.join(', ') +
        (ignored.length === 1 ? ' is a session-level filter' : ' are session-level filters') +
        ' and could not be applied to these numbers, which cover every request in range that ' +
        'the other filters match.';
}

/**
 * Fill card 01, and write the coverage sentence that says what the page can speak for.
 */
function renderAnswered(data) {
    const scope = byId('atk-answered-content');
    const set = (field, value) => {
        const node = scope ? scope.querySelector('[data-field="' + field + '"]') : null;
        if (node) {
            node.textContent = value;
        }
    };

    const s = data.status || {};
    set('status_ok', num(s.ok));
    set('status_redirect', num(s.redirect));
    set('status_refused', num(s.refused));
    set('status_broke', num(s.broke));
    set('matched', num(data.matched));
    set('uniq_ips', num(data.uniq_ips));
    set('evaluated', num(data.evaluated));
    set('unevaluated', num(data.unevaluated));
    set('uniq_patterns', num(data.uniq_patterns));
    set('last', data.last ? when(data.last) : '—');

    const note = byId('atk-coverage');
    if (!note) {
        return;
    }

    /* THE COVERAGE SENTENCE, and it is not decoration. `hit_flags_ss` absent means two things —
       evaluated and clean, or never looked at — and only `hit_rules_i` separates them. A page
       that reported a deployment gap as a quiet week would be exactly the kind of confident
       wrong number this product refuses everywhere else. */
    const parts = [];
    if (data.unevaluated > 0) {
        parts.push('Of ' + num(data.requests) + ' requests in range, ' + num(data.evaluated) + ' (' +
            pct(data.evaluated, data.requests, 0) + ') have been evaluated by the detector and ' +
            num(data.unevaluated) + ' were indexed before it existed. Those ' + num(data.unevaluated) +
            ' were never looked at, which is not the same as finding nothing in them — this page ' +
            'cannot speak for them either way.');
    } else if (data.requests > 0) {
        parts.push('Every one of the ' + num(data.requests) + ' requests in range has been evaluated ' +
            'by the detector, so this page covers the whole window.');
    }
    if (data.matched > 0 && s.ok === 0 && s.redirect === 0) {
        parts.push('Nothing that matched a pattern was answered with a 2xx or a 3xx: the server ' +
            'refused all ' + num(data.matched) + ' of them, which is what a webserver is supposed ' +
            'to do to a probe.');
    }
    const ignored = ignoredFilterNote(data);
    if (ignored !== '') {
        parts.push(ignored.trim());
    }

    note.textContent = parts.join(' ');
    note.hidden = parts.length === 0;
}

/**
 * Draw the pattern chart and table, ordered by what was answered.
 */
function renderPatterns(data) {
    if (!data.patterns.length) {
        tbody(byId('atk-patterns-table'), []);
        noDataYet('atk-patterns-empty', 'matched patterns');
        return;
    }
    hideEmpty('atk-patterns-empty');
    cardChart('atk-patterns', 360);

    const t = tokens();
    const families = data.families || {};

    /* The chart is the table's first two columns as a picture: one stacked bar per pattern,
       segmented by what the server answered. Top twelve only — past that the bars are shorter
       than their own labels and the table below is the better instrument. */
    const top = data.patterns.slice(0, 12);
    stackedBarsFor(top, t);

    tbody(byId('atk-patterns-table'), data.patterns.map((row) => ({
        attrs: dimRow('hit_flags_ss', row.code),
        cells: [
            { node: patternCell(row, families), clip: true, title: row.label + ' — ' + row.what, sort: row.label },
            {
                text: num(row.answered),
                num: true,
                sort: row.answered,
                title: row.answered
                    ? num(row.ok) + ' answered with a body, ' + num(row.redirect) + ' redirected. The server ' +
                        'returned something — that is not proof anything was disclosed.'
                    : 'Nothing that matched this pattern was answered with a 2xx or a 3xx.'
            },
            { text: num(row.redirect), num: true, sort: row.redirect },
            { text: num(row.refused), num: true, sort: row.refused },
            { node: el('div', {}, [statusBar(row), el('div', { class: 'sub clip-line', text: num(row.count) })]), sort: row.count },
            { text: num(row.uniq_ips), num: true, sort: row.uniq_ips },
            { text: row.last ? when(row.last) : '—', sort: row.last || '' }
        ]
    })));
}

/** The chart above the pattern table: one stacked bar per pattern, coloured by status class. */
function stackedBarsFor(rows, t) {
    const holder = byId('atk-patterns-chart');
    if (!holder) {
        return;
    }
    stackedBars('atk-patterns-chart', rows.map((r) => r.label), STATUS_KEYS.map(([key, label]) => ({
        name: label,
        color: statusColour(t, key),
        data: rows.map((r) => r[key] || 0)
    })));
}

/**
 * Fill the answered-requests table.
 *
 * FIVE COLUMNS, THE SAME FIVE AS EVERY OTHER TABLE OF EVENTS IN THE PANEL: date, address,
 * country, page, verdict. The method and the byte count are gone from the table — both belong to
 * the one request and both are in the visit the row opens — and the two columns that carry this
 * page's entire argument are MERGED rather than dropped. What the server answered and which
 * pattern matched are one judgement about one request, which is exactly what a verdict is here,
 * so they share the fifth column: the status class in words on the first line, the pattern
 * underneath it.
 *
 * EVERY CELL IN IT IS ATTACKER-CHOSEN TEXT. The path and the query string go in through el(),
 * which sets textContent, so a path containing markup is a path containing markup and never
 * becomes an element.
 */
function renderRequests(data) {
    setPop('atk-requests', num(data.page && data.page.total !== null ? data.page.total : data.total) +
        ' matched requests the server answered with a 2xx or a 3xx. A 2xx means a body came back, not ' +
        'that it was the body asked for.' + ignoredFilterNote(data));

    if (!data.requests.length) {
        tbody(byId('atk-requests-table'), []);
        return false;
    }
    hideEmpty('atk-requests-empty');

    tbody(byId('atk-requests-table'), data.requests.map((row) => ({
        attrs: row.session ? drillRow('session', { id: row.session }) : {},
        cells: [
            { text: when(row.ts, true), mono: true, nowrap: true, sort: row.ts || '' },
            {
                node: row.ip
                    ? dimValue('ip_s', row.ip, { mono: true })
                    : el('span', { class: 'muted', text: '\u2014' }),
                class: 'mono clip',
                title: row.ip || 'Address not recorded',
                sort: row.ip || ''
            },
            {
                node: row.country
                    ? countryNode(row.country)
                    : el('span', { class: 'muted', text: '\u2014' }),
                class: 'clip',
                title: [row.city, row.country].filter(Boolean).join(', ') || 'Not geolocated',
                sort: [row.country, row.city].filter(Boolean).join(' ')
            },
            { node: requestCell(row), clip: true, title: requestText(row), sort: row.path || '' },
            { node: verdictCell(row), class: 'visit-verdict', sort: row.status === null ? -1 : row.status }
        ]
    })));

    return true;
}

/**
 * What the server answered, and what it answered it to.
 *
 * The status class leads because it is the thing that decides whether the row matters at all,
 * and it is rendered in the vocabulary's own words rather than as a bare number — "2xx Answered"
 * is a sentence a reader acts on and "200" is a code they have to know. The exact code rides in
 * the description. The pattern is the second line, because "which probe was this" is the question
 * a reader asks only once they have seen that it got through.
 *
 * The row's opener sits at the end of this cell rather than in a sixth column, exactly as it does
 * in every other five-column table here: a link inside a cell wins the click over the row, so the
 * row needs one surface that unambiguously means "open the visit behind this".
 */
function verdictCell(row) {
    const klass = row.status === null ? '' : String(Math.floor(row.status / 100)) + 'xx';

    return el('div', { class: 'client' }, [
        el('div', { class: 'clip-line' }, [
            klass === ''
                ? el('span', { class: 'muted', text: 'no status logged' })
                : dimValue('status_class_s', klass, {
                    title: String(row.status) + ' \u2014 ' + statusHint(row.status)
                }),
            row.session ? openButton('session', { id: row.session }, 'Open this visit') : null
        ]),
        el('div', {
            class: 'sub clip-line',
            title: row.patterns || ''
        }, [el('span', { text: row.patterns || 'no pattern named' })])
    ]);
}

/**
 * What a status code means, in the vocabulary's own words.
 *
 * Guarded rather than assumed: Parser only ever writes 100-599, but a document could come from
 * a source that does not, and a missing vocabulary entry must not throw inside a table render
 * and take the whole card down with it.
 */
function statusHint(status) {
    if (status === null || status === undefined) {
        return 'The log line carried no parseable status.';
    }
    const spoken = valueWords('status_class_s', String(Math.floor(status / 100)) + 'xx');
    return spoken && spoken.why ? spoken.why : '';
}

/** The request target, on two lines: the path, then the query string that carried the payload. */
function requestCell(row) {
    const lower = [];
    if (row.query) {
        lower.push(el('span', { class: 'mono', text: '?' + row.query }));
    } else if (row.host) {
        lower.push(el('span', { text: row.host }));
    }
    return el('div', { class: 'client' }, [
        el('div', { class: 'clip-line' }, [
            el('span', { class: 'mono', text: (row.method ? row.method + ' ' : '') + (row.path || '/') })
        ]),
        el('div', { class: 'sub clip-line' }, lower.length ? lower : [el('span', { text: '\u2014' })])
    ]);
}

/** The full request target for a tooltip, so a clipped row can still be read. */
function requestText(row) {
    return (row.method ? row.method + ' ' : '') + (row.path || '/') +
        (row.query ? '?' + row.query : '') + (row.host ? '  [' + row.host + ']' : '');
}

/**
 * Fill the address and network tables.
 */
function renderWho(data) {
    if (!data.actors.length) {
        tbody(byId('atk-who-table'), []);
        tbody(byId('atk-networks-table'), []);
        noDataYet('atk-who-empty', 'matched addresses');
        return;
    }
    hideEmpty('atk-who-empty');

    tbody(byId('atk-who-table'), data.actors.map((row) => ({
        attrs: dimRow('ip_s', row.ip),
        cells: [
            {
                node: el('div', { class: 'client' }, [
                    el('div', { class: 'clip-line' }, [dimValue('ip_s', row.ip, { mono: true })]),
                    el('div', { class: 'sub clip-line', text: row.rdns || '—' })
                ]),
                clip: true,
                title: [row.ip, row.rdns].filter(Boolean).join(' · '),
                sort: row.ip || ''
            },
            { node: networkCell(row), clip: true, title: [row.org, row.as_type, row.country].filter(Boolean).join(' · '), sort: row.org || '' },
            { text: num(row.answered), num: true, sort: row.answered },
            { text: num(row.refused), num: true, sort: row.refused },
            { node: el('div', {}, [statusBar(row), el('div', { class: 'sub clip-line', text: num(row.count) })]), sort: row.count },
            {
                text: num(row.uniq_patterns),
                num: true,
                sort: row.uniq_patterns,
                title: 'Distinct patterns this address tried, across ' + num(row.uniq_paths) + ' distinct ' +
                    'paths. One pattern on one path is a misconfigured client; many patterns on many paths ' +
                    'is a scanner walking a list.'
            },
            { text: row.last ? when(row.last) : '—', sort: row.last || '' }
        ]
    })));

    tbody(byId('atk-networks-table'), (data.networks || []).map((row) => ({
        attrs: dimRow('as_org_s', row.org),
        cells: [
            { node: dimValue('as_org_s', row.org), clip: true, title: row.org, sort: row.org || '' },
            { text: num(row.answered), num: true, sort: row.answered },
            { text: num(row.refused), num: true, sort: row.refused },
            { text: num(row.count), num: true, sort: row.count },
            { text: num(row.uniq_ips), num: true, sort: row.uniq_ips }
        ]
    })));
}

/** The network a row came from, with its type beneath it. */
function networkCell(row) {
    const lower = [];
    if (row.as_type) {
        lower.push(dimValue('as_type_s', row.as_type));
    }
    if (row.country) {
        if (lower.length) {
            lower.push(el('span', { text: ' · ' }));
        }
        lower.push(el('span', { text: row.country }));
    }
    return el('div', { class: 'client' }, [
        el('div', { class: 'clip-line' }, [row.org ? dimValue('as_org_s', row.org) : el('span', { text: '—' })]),
        el('div', { class: 'sub clip-line' }, lower.length ? lower : [el('span', { text: '—' })])
    ]);
}

/**
 * Fill the impersonation card.
 *
 * The two failure kinds are kept apart on purpose. A crawler whose operator publishes
 * forward-confirmable reverse DNS and failed the check is one finding; a named crawler
 * answering from a rented cloud VM, where there is no published rDNS to check against and the
 * claim is nonetheless plainly false, is another — and it is the one that found this whole
 * feature. An operator should never have to guess which column produced a row.
 */
function renderImpersonation(data) {
    const scope = byId('atk-impersonation-content');
    const set = (field, value) => {
        const node = scope ? scope.querySelector('[data-field="' + field + '"]') : null;
        if (node) {
            node.textContent = value;
        }
    };
    set('declared', num(data.declared));
    set('verified', num(data.verified));
    set('rdns_failed', num(data.rdns_failed));
    set('tenant', num(data.tenant));

    if (!data.crawlers.length) {
        tbody(byId('atk-crawlers-table'), []);
        noDataYet('atk-impersonation-empty', 'declared crawler sessions');
        return;
    }
    hideEmpty('atk-impersonation-empty');

    tbody(byId('atk-crawlers-table'), data.crawlers.map((row) => ({
        attrs: dimRow('ua_bot_name_s', row.name),
        cells: [
            { node: dimValue('ua_bot_name_s', row.name), clip: true, title: row.name, sort: row.name || '' },
            { node: dimValue('ua_bot_cat_s', row.category), clip: true, sort: valueText('ua_bot_cat_s', row.category) },
            { text: num(row.sessions), num: true, sort: row.sessions },
            {
                text: num(row.verified),
                num: true,
                sort: row.verified,
                title: 'Sessions whose crawler claim passed forward-confirmed reverse DNS.'
            },
            {
                text: num(row.rdns_failed),
                num: true,
                sort: row.rdns_failed,
                title: 'This operator publishes reverse DNS and it did not back the claim up.'
            },
            {
                text: num(row.tenant),
                num: true,
                sort: row.tenant,
                title: 'Answered from general-purpose cloud tenant address space. A named search or AI ' +
                    'crawler does not run on somebody\'s rented VM.'
            },
            { text: row.last ? when(row.last) : '—', sort: row.last || '' }
        ]
    })));
}

/**
 * Draw the timeline: everything that matched, with the answered subset beneath it.
 */
function renderWhen(data) {
    if (!data.times.length) {
        noDataYet('atk-when-empty', 'matched requests');
        return;
    }
    hideEmpty('atk-when-empty');
    cardChart('atk-when', 300);

    const t = tokens();
    lines('atk-when-chart', data.times, [
        { name: 'Matched a pattern', color: t.pop.human, data: data.matched },
        { name: 'Answered 2xx or 3xx', color: t.accent, data: data.answered },
        { name: 'Distinct addresses', color: t.pop.declared, data: data.ips }
    ]);
}

/**
 * Entry point.
 *
 * The pattern facet feeds TWO cards — the pattern table and the cross-tab — from one request,
 * because they are two readings of the same facet rather than two questions. Each keeps its own
 * progress line and its own failure state, and both await the same promise.
 */
export default function init() {
    loadCard('atk-answered', 'Correlating matched requests with response codes', async () => {
        renderAnswered(await api('attacks', 'answered'));
    });

    const patterns = api('attacks', 'patterns');
    loadCard('atk-patterns', 'Faceting detection patterns against status codes', async () => {
        renderPatterns(await patterns);
    });
    if (byId('atk-pivot-table')) {
        loadCard('atk-pivot', 'Cross-tabulating patterns by status class', async () => {
            const data = await patterns;
            if (!renderPivot('atk-pivot', data.pivot)) {
                noPivotYet('atk-pivot-empty', 'both a detection pattern and a recorded status');
            }
        });
    }

    pagedCard({
        id: 'atk-requests',
        label: 'Reading the answered requests',
        empty: 'answered matched requests',
        fetch: (start, rows) => api('attacks', 'requests', { start: start, rows: rows }),
        render: renderRequests
    });
    loadCard('atk-who', 'Faceting addresses and networks', async () => {
        renderWho(await api('attacks', 'who'));
    });
    loadCard('atk-impersonation', 'Checking declared crawler claims', async () => {
        renderImpersonation(await api('attacks', 'impersonation'));
    });
    loadCard('atk-when', 'Bucketing matched requests over time', async () => {
        renderWhen(await api('attacks', 'when'));
    });
}
