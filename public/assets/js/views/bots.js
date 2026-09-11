/*
 * Loghound — Bot forensics view.
 *
 * Six independent cards. The declared/evasive split is rendered first and everything
 * below it repeats the distinction, because a page that shows "8,412 bot sessions"
 * without saying that 7,900 of them were Googlebot doing its job is worse than no page.
 *
 * The reason bars are stacked into those two halves for the same reason: a signal that
 * fires overwhelmingly on declared crawlers looks completely different from one that
 * fires on evasive traffic, and the stack shows it without a second chart.
 */

'use strict';

import {
    api, byId, cardChart, dec, el, hideEmpty, loadCard, noDataYet, num, setPop, tbody, when
} from '../core.js';
import { barsHStacked, donut, histogram, tokens } from '../charts.js';
import { dimRow, dimValue } from '../identity.js';

/**
 * The chart colour a verdict keeps everywhere in the panel.
 */
function verdictColour(t, verdict) {
    switch (verdict) {
        case 'human':
        case 'likely_human':
            return t.pop.declared;
        case 'unknown':
            return t.pop.unknown;
        case 'bot':
        case 'likely_bot':
            return t.pop.evasive;
        default:
            return t.pop.unknown;
    }
}

/**
 * Set a [data-field] value inside a card's content area.
 */
function setField(cardId, field, value) {
    const node = document.querySelector('#' + cardId + '-content [data-field="' + field + '"]');
    if (node) {
        node.textContent = value;
    }
}

/**
 * Fill the two-column summary at the top.
 */
function renderSplit(data) {
    setField('bf-split', 'declared_sessions', num(data.declared.sessions));
    setField('bf-split', 'ai_sessions', num(data.ai.sessions));
    setField('bf-split', 'declared_hits', num((data.declared.hits || 0) + (data.ai.hits || 0)));
    setField('bf-split', 'evasive_sessions', num(data.evasive.sessions));
    setField('bf-split', 'evasive_ips', num(data.evasive.uniq_ips));
    setField('bf-split', 'evasive_hits', num(data.evasive.hits));
    setPop('bf-split', num(data.total) + ' scored sessions in range, of which ' + num(data.human.sessions) +
        ' were human. The two halves below are never added together.');
}

/**
 * Draw the reason bars and the table explaining every code.
 */
function renderReasons(data) {
    if (!data.reasons.length) {
        noDataYet('bf-reasons-empty', 'scored bot sessions');
        return;
    }
    hideEmpty('bf-reasons-empty');
    setPop('bf-reasons', num(data.botlike) + ' sessions with verdict bot or likely_bot. A session fires several ' +
        'rules, so the bars sum to more than the session count.');

    const t = tokens();
    barsHStacked('bf-reasons-chart', data.reasons.map((row) => ({
        label: row.label,
        parts: [
            { name: 'Evasive', value: row.evasive, color: t.pop.evasive },
            { name: 'Declared crawlers', value: row.declared, color: t.pop.declared }
        ]
    })), { labelWidth: 230 });

    tbody(byId('bf-reason-table'), data.reasons.map((row) => ({
        attrs: dimRow('bot_reasons_ss', row.code),
        cells: [
            {
                node: el('div', {}, [
                    dimValue('bot_reasons_ss', row.code, { mono: true }),
                    el('div', { class: 'muted', text: row.label })
                ]),
                clip: true,
                title: row.code,
                sort: row.label || row.code
            },
            { text: row.why, class: 'muted wrap', sort: row.severity || '' },
            { text: num(row.evasive), num: true, sort: row.evasive },
            { text: num(row.declared), num: true, sort: row.declared },
            {
                text: row.avg_score === null ? '—' : dec(row.avg_score, 0),
                num: true,
                sort: row.avg_score === null ? '' : row.avg_score
            }
        ]
    })));
}

/**
 * Draw the verdict donut.
 */
function renderVerdicts(data) {
    if (!data.verdicts.length) {
        noDataYet('bf-verdicts-empty', 'scored sessions');
        return;
    }
    hideEmpty('bf-verdicts-empty');
    cardChart('bf-verdicts', 300);
    const t = tokens();
    donut('bf-verdicts', data.verdicts.map((row) => ({
        label: row.verdict,
        value: row.count,
        color: verdictColour(t, row.verdict)
    })), 'sessions', num(data.total));
}

/**
 * Draw the score histogram, coloured by the verdict band each bucket falls in.
 */
function renderHistogram(data) {
    if (!data.histogram.some((bucket) => bucket.count > 0)) {
        noDataYet('bf-histogram-empty', 'scored sessions');
        return;
    }
    hideEmpty('bf-histogram-empty');
    cardChart('bf-histogram', 300);
    const t = tokens();
    histogram('bf-histogram', data.histogram.map((bucket) => ({
        label: String(Math.round(bucket.from)),
        value: bucket.count,
        from: bucket.from
    })), (row) => {
        if (row.from >= 80) { return t.pop.evasive; }
        if (row.from >= 60) { return t.pop.declared; }
        if (row.from >= 40) { return t.pop.unknown; }
        return t.pop.human;
    });
}

/**
 * Fill the bot class table.
 */
function renderClasses(data) {
    if (!data.classes.length) {
        tbody(byId('bf-classes-table'), []);
        noDataYet('bf-classes-empty', 'bot classes');
        return;
    }
    hideEmpty('bf-classes-empty');

    tbody(byId('bf-classes-table'), data.classes.map((row) => ({
        attrs: dimRow('bot_class_s', row.class),
        cells: [
            { node: dimValue('bot_class_s', row.class, { mono: true }), clip: true, title: row.class, sort: row.class },
            {
                node: el('span', {
                    class: 'chip chip-word ' + (row.declared ? 'chip-good' : 'chip-bad'),
                    text: row.declared ? 'declared' : 'evasive'
                }),
                sort: row.declared ? 'declared' : 'evasive'
            },
            { text: num(row.count), num: true, sort: row.count },
            { text: num(row.uniq_ips), num: true, sort: row.uniq_ips },
            { text: num(row.hits), num: true, sort: row.hits },
            {
                text: row.avg_score === null ? '—' : dec(row.avg_score, 0),
                num: true,
                sort: row.avg_score === null ? '' : row.avg_score
            }
        ]
    })));
}

/**
 * Fill the declared crawler roll-call.
 */
function renderCrawlers(data) {
    if (!data.crawlers.length) {
        tbody(byId('bf-crawlers-table'), []);
        showNoCrawlers();
        return;
    }
    hideEmpty('bf-crawlers-empty');

    tbody(byId('bf-crawlers-table'), data.crawlers.map((row) => ({
        attrs: dimRow('ua_bot_name_s', row.name),
        cells: [
            {
                node: el('span', {}, [
                    el('strong', { text: row.name }),
                    row.ai ? el('span', { class: 'chip chip-accent', text: 'AI' }) : null
                ]),
                clip: true,
                title: row.name,
                sort: row.name
            },
            { node: dimValue('ua_bot_cat_s', row.category || 'other'), sort: row.category || 'other' },
            { text: num(row.sessions), num: true, sort: row.sessions },
            { text: num(row.hits), num: true, sort: row.hits },
            { text: num(row.uniq_ips), num: true, sort: row.uniq_ips },
            {
                node: el('span', {
                    class: 'chip chip-word ' + (row.verified >= row.sessions ? 'chip-good' : 'chip-bad'),
                    text: num(row.verified) + '/' + num(row.sessions),
                    title: row.verified >= row.sessions
                        ? 'Every session passed forward-confirmed reverse DNS.'
                        : 'Some or all sessions failed forward-confirmed reverse DNS — that is an impersonator.'
                }),
                sort: row.sessions ? row.verified / row.sessions : 0
            },
            { text: when(row.last), mono: true, nowrap: true, sort: row.last || '' }
        ]
    })));
}

/**
 * The crawler table's own empty state, which has a different next step from the others.
 */
function showNoCrawlers() {
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
    const content = byId('bf-crawlers-content');
    if (content) {
        content.hidden = true;
    }
}

/**
 * Entry point. Six cards, six requests, all independent.
 */
export default function init() {
    loadCard('bf-split', 'Separating declared crawlers from evasive automation', async () => {
        renderSplit(await api('bots', 'split'));
    });
    loadCard('bf-reasons', 'Faceting signal codes', async () => {
        renderReasons(await api('bots', 'reasons'));
    });
    loadCard('bf-verdicts', 'Faceting verdicts', async () => {
        renderVerdicts(await api('bots', 'verdicts'));
    });
    loadCard('bf-histogram', 'Bucketing bot scores', async () => {
        renderHistogram(await api('bots', 'histogram'));
    });
    loadCard('bf-classes', 'Faceting bot classes', async () => {
        renderClasses(await api('bots', 'classes'));
    });
    loadCard('bf-crawlers', 'Faceting crawler names', async () => {
        renderCrawlers(await api('bots', 'crawlers'));
    });
}
