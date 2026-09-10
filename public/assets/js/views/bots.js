/*
 * Loghound — Bot forensics view.
 *
 * The declared/evasive split is rendered first and everything below it repeats the
 * distinction, because a page that shows "8,412 bot sessions" without saying that 7,900
 * of them were Googlebot doing its job is worse than no page at all.
 *
 * The reason bars are stacked into those two halves for exactly that reason: a signal
 * that fires overwhelmingly on declared crawlers (ua_declared_bot) looks completely
 * different from one that fires on evasive traffic (fp_cluster_proxy_fleet), and the
 * stack shows it without needing a second chart.
 */

'use strict';

import { api, byId, dec, el, hideEmpty, load, noDataYet, num, tbody, when } from '../core.js';
import { barsHStacked, donut, histogram, tokens } from '../charts.js';

/** Verdict → the chart colour it keeps everywhere in the panel. */
function verdictColour(t, verdict) {
    switch (verdict) {
        case 'human':
        case 'likely_human':
            return t.pop.human;
        case 'unknown':
            return t.pop.unknown;
        case 'bot':
        case 'likely_bot':
            return t.pop.evasive;
        default:
            return t.pop.unknown;
    }
}

/** The two-column summary at the top. */
function renderSplit(data) {
    const set = (field, value) => {
        const node = document.querySelector('[data-field="' + field + '"]');
        if (node) {
            node.textContent = value;
        }
    };
    set('declared_sessions', num(data.split.declared.sessions));
    set('ai_sessions', num(data.split.ai.sessions));
    set('declared_hits', num((data.split.declared.hits || 0) + (data.split.ai.hits || 0)));
    set('evasive_sessions', num(data.split.evasive.sessions));
    set('evasive_ips', num(data.split.evasive.uniq_ips));
    set('evasive_hits', num(data.split.evasive.hits));
}

/** The reason bars, split declared vs evasive. */
function renderReasons(data) {
    if (!data.reasons.length) {
        noDataYet('bf-reasons-empty', 'scored bot sessions');
        return;
    }
    hideEmpty('bf-reasons-empty');
    const t = tokens();

    barsHStacked('bf-reasons', data.reasons.map((r) => ({
        label: r.label,
        parts: [
            { name: 'Evasive', value: r.evasive, color: t.pop.evasive },
            { name: 'Declared crawlers', value: r.declared, color: t.pop.declared }
        ]
    })), { labelWidth: 220 });

    // The table under the chart carries the explanation for every code. A verdict with no
    // reason is a bug (SPEC §1); a reason with no explanation is only slightly better.
    tbody(byId('bf-reason-table'), data.reasons.map((r) => ({
        cells: [
            {
                node: el('div', {}, [
                    el('code', { class: 'mono', text: r.code }),
                    el('br'),
                    el('span', { class: 'muted', text: r.label })
                ])
            },
            { text: r.why, class: 'muted wrap' },
            { text: num(r.evasive), num: true },
            { text: num(r.declared), num: true },
            { text: r.avg_score === null ? '—' : dec(r.avg_score, 0), num: true }
        ]
    })));
}

/** Verdict donut. */
function renderVerdicts(data) {
    if (!data.verdicts.length) {
        noDataYet('bf-verdicts-empty', 'scored sessions');
        return;
    }
    hideEmpty('bf-verdicts-empty');
    const t = tokens();
    donut('bf-verdicts', data.verdicts.map((v) => ({
        label: v.verdict,
        value: v.count,
        color: verdictColour(t, v.verdict)
    })), 'sessions', num(data.total));
}

/** Bot-score histogram, coloured by the band each bucket falls in. */
function renderHistogram(data) {
    const any = data.histogram.some((b) => b.count > 0);
    if (!any) {
        noDataYet('bf-histogram-empty', 'scored sessions');
        return;
    }
    hideEmpty('bf-histogram-empty');
    const t = tokens();
    histogram('bf-histogram', data.histogram.map((b) => ({
        label: String(Math.round(b.from)),
        value: b.count,
        from: b.from
    })), (row) => {
        // The colours match the verdict thresholds from SPEC §7, so the shape of the
        // distribution can be read against the bands without a legend.
        if (row.from >= 80) { return t.pop.evasive; }
        if (row.from >= 60) { return t.warn; }
        if (row.from >= 40) { return t.pop.unknown; }
        return t.pop.human;
    });
}

/** Bot class table. */
function renderClasses(data) {
    const table = byId('bf-classes');
    if (!data.classes.length) {
        tbody(table, []);
        noDataYet('bf-classes-empty', 'bot classes');
        return;
    }
    hideEmpty('bf-classes-empty');

    tbody(table, data.classes.map((c) => ({
        cells: [
            { node: el('code', { class: 'mono', text: c.class }) },
            {
                node: el('span', {
                    class: 'chip ' + (c.declared ? 'chip-good' : 'chip-bad'),
                    text: c.declared ? 'declared' : 'evasive'
                })
            },
            { text: num(c.count), num: true },
            { text: num(c.uniq_ips), num: true },
            { text: num(c.hits), num: true },
            { text: c.avg_score === null ? '—' : dec(c.avg_score, 0), num: true }
        ]
    })));
}

/** Declared crawler roll-call. */
function renderCrawlers(data) {
    const table = byId('bf-crawlers');
    if (!data.crawlers.length) {
        tbody(table, []);
        showEmptyCrawlers();
        return;
    }
    hideEmpty('bf-crawlers-empty');

    tbody(table, data.crawlers.map((c) => ({
        cells: [
            {
                node: el('span', {}, [
                    el('strong', { text: c.name }),
                    c.ai ? el('span', { class: 'chip chip-accent', text: 'AI', style: 'margin-left:6px' }) : null
                ])
            },
            { node: el('code', { class: 'mono', text: c.category || 'other' }) },
            { text: num(c.sessions), num: true },
            { text: num(c.hits), num: true },
            { text: num(c.uniq_ips), num: true },
            {
                // "Verified" is forward-confirmed reverse DNS. An unverified Googlebot is
                // not a crawler having a bad day; it is something wearing its name.
                node: el('span', {
                    class: 'chip ' + (c.verified >= c.sessions ? 'chip-good' : (c.verified > 0 ? 'chip-warn' : 'chip-bad')),
                    text: num(c.verified) + '/' + num(c.sessions),
                    title: c.verified >= c.sessions
                        ? 'Every session passed forward-confirmed reverse DNS.'
                        : 'Some or all sessions failed forward-confirmed reverse DNS — that is an impersonator, not a crawler.'
                })
            },
            { text: when(c.last), mono: true, nowrap: true }
        ]
    })));
}

/** Empty state specific to the crawler table, which has its own next step. */
function showEmptyCrawlers() {
    const node = byId('bf-crawlers-empty');
    if (!node) {
        return;
    }
    node.hidden = false;
    node.classList.add('show');
    node.replaceChildren(
        el('h3', { text: 'No self-declaring crawlers in this range' }),
        el('p', {
            text: 'Nothing arrived with a User-Agent that identifies itself as a bot. On a public site that is ' +
                'unusual over anything longer than an hour — widen the time range before concluding anything.'
        })
    );
}

/** Entry point. */
export default async function init() {
    await load('bf-reasons-empty', 'bot forensics', async () => {
        const data = await api('bots', 'summary');
        renderSplit(data);
        renderReasons(data);
        renderVerdicts(data);
        renderHistogram(data);
        renderClasses(data);
        renderCrawlers(data);
    });
}
