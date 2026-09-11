/*
 * Loghound — the live stream.
 *
 * One EventSource, one table, one dialog. The table is fed by the connection rather than by
 * loadCard(), which is why this card carries no skeleton and no refresh control: there is
 * nothing to re-load, only a connection to hold or to stop.
 *
 * ---------------------------------------------------------------------------------
 * WHAT A ROW IS ALLOWED TO SAY
 * ---------------------------------------------------------------------------------
 * The last column is headed "This line" and that heading is the whole contract. A verdict is
 * scored over a session once it settles; this table has one request. So the column carries what
 * the line shows and the dialog carries, under its own heading and after a separate request,
 * what the index already knows about the same address. The two are never rendered in the same
 * block and never in the same sentence.
 *
 * ---------------------------------------------------------------------------------
 * WHAT BOUNDS IT
 * ---------------------------------------------------------------------------------
 * The server ends each connection after its own limit and EventSource reconnects by itself,
 * carrying the cursor as `Last-Event-ID`, so nothing is missed and the reader sees nothing
 * happen. This end stops asking altogether once the tab has been watching for WATCH_MS, or as
 * soon as the tab is hidden — a stream nobody is looking at is the one that runs for a week.
 * Both land in the same state: stopped, with a control that says Resume and a line saying why.
 *
 * EVERY VALUE HERE CAME OFF A LOG LINE, which is attacker-chosen bytes by definition, and it is
 * rendered the moment it arrives with no batch job in between. Nothing is assigned to innerHTML
 * anywhere in this file: every node is built by core.js's el(), whose `text` is textContent, and
 * every href is built by url.js from a validated host and path.
 */

'use strict';

import { api, boot, byId, el, fill, bytes, durUs, num, timeOnly, when } from '../core.js';
import { dimValue, drillRow, flagNode, openButton, valueText, valueWords } from '../identity.js';
import { hostCell } from '../hostcolor.js';
import { pathCell } from '../url.js';
import { dialogFail, isCurrent, openDialog, registerOpener } from '../dialog.js';
import { visitCaption, visitTable } from '../visits.js';
import { renderPager } from '../pager.js';

/** Rows kept in the table. Beyond this the oldest are dropped, which the caption says. */
const MAX_ROWS = 300;

/** How long one tab keeps a stream open before it stops asking and offers to resume. */
const WATCH_MS = 15 * 60 * 1000;

/** The open connection, or null. */
let source = null;

/** Rows currently in the table, by id, so the dialog can open one without a second fetch. */
const held = new Map();

/** When this watch began, for the limit above. */
let watchStarted = 0;

/** Requests shown since the page was opened. */
let seen = 0;

/** The last thing the server said about how far behind the reader is. */
let lag = 0;

/** Lines that did not match their source's format, and the most recent reason. */
let unparsed = 0;
let unparsedWhy = '';

/* -------------------------------------------------------------------------
 * The connection
 * ---------------------------------------------------------------------- */

/**
 * Open the stream.
 *
 * The URL is the page's own query string plus the action, exactly like core.js's api(), so the
 * host chip in the top bar travels with it and the server filters the lines it sends. The
 * cursor is passed only on an explicit resume: a reconnect the browser makes on its own already
 * carries `Last-Event-ID`, which is the same value and is the one the browser is sure about.
 */
function connect(cursor) {
    const params = new URLSearchParams(window.location.search);
    params.set('v', 'live');
    params.set('api', 'stream');
    if (cursor) {
        params.set('cursor', cursor);
    }

    source = new EventSource('?' + params.toString());

    source.addEventListener('hello', onHello);
    source.addEventListener('lines', onLines);
    source.addEventListener('quiet', onQuiet);
    source.addEventListener('pause', onPause);
    source.onerror = onError;
}

/**
 * The server has accepted the connection and said what it is watching.
 *
 * The event is named `hello` rather than `open` because EventSource already fires an `open` of
 * its own, with no payload, and a listener that had to tell the two apart by whether `data`
 * parsed would be one refactor away from a silent bug.
 */
function onHello(event) {
    const data = parse(event);
    if (data === null) {
        return;
    }

    if (data.open === 0) {
        setState('off', data.sources === 0
            ? 'No log source is configured.'
            : 'No configured log file could be opened.');
        stop('nosource');
        return;
    }

    setState('live', data.hosts && data.hosts.length
        ? 'Streaming ' + data.hosts.join(', ')
        : 'Streaming ' + data.open + (data.open === 1 ? ' log file' : ' log files'));
    counts();
}

/** A batch of lines. */
function onLines(event) {
    const data = parse(event);
    if (data === null) {
        return;
    }

    lag = Number(data.lag) || 0;
    unparsed = Number(data.unparsed) || 0;
    unparsedWhy = String(data.why || '');

    addRows(Array.isArray(data.rows) ? data.rows : []);
    setState('live', 'Streaming');
    counts();
}

/** A heartbeat: the connection is alive and the log is quiet. */
function onQuiet(event) {
    const data = parse(event);
    if (data !== null) {
        lag = Number(data.lag) || 0;
        unparsed = Number(data.unparsed) || 0;
        unparsedWhy = String(data.why || '');
    }
    setState('live', 'Streaming');
    counts();
}

/**
 * The server has reached its own connection limit.
 *
 * Ordinarily nothing happens here: the browser reconnects by itself within a few seconds and
 * the reader never knows. Once this tab has been watching longer than WATCH_MS the reconnect is
 * refused instead, because a live page left open in a forgotten tab is a connection held for
 * as long as the machine is up.
 */
function onPause(event) {
    const data = parse(event);
    if (Date.now() - watchStarted >= WATCH_MS) {
        stop('limit', data && data.cursor ? String(data.cursor) : '');
        return;
    }
    setState('live', 'Reconnecting');
}

/** The connection dropped, or was refused. */
function onError() {
    if (!source) {
        return;
    }
    if (source.readyState === EventSource.CLOSED) {
        stop('lost');
        return;
    }
    setState('wait', 'Reconnecting');
}

/**
 * Read an event's payload.
 *
 * A payload that is not JSON is dropped rather than guessed at. Nothing on this page is built
 * from a string, so there is no sink for a malformed one to reach, but a silent drop is still
 * better than a half-populated row.
 */
function parse(event) {
    try {
        const data = JSON.parse(event.data);
        return data && typeof data === 'object' ? data : null;
    } catch (e) {
        return null;
    }
}

/** Where an explicit resume picks up from. */
let resumeFrom = '';

/** Close the connection and say why, with a way back. */
function stop(reason, cursor) {
    if (source) {
        source.close();
        source = null;
    }

    const words = {
        limit: 'Stopped after fifteen minutes. Nothing was lost; resuming picks up from here.',
        hidden: 'Stopped because this tab went to the background.',
        lost: 'The connection dropped and could not be re-established.',
        asked: 'Paused.',
        nosource: 'There is nothing to read. Settings is where log sources are configured.'
    };

    resumeFrom = cursor || resumeFrom;
    setState('off', words[reason] || 'Stopped.');
    toggleLabel('Resume');
    counts();
}

/** Start, or start again. */
function begin() {
    if (source) {
        return;
    }
    watchStarted = Date.now();
    setState('wait', 'Connecting');
    toggleLabel('Pause');
    connect(resumeFrom);
    resumeFrom = '';
}

/* -------------------------------------------------------------------------
 * The state line
 * ---------------------------------------------------------------------- */

/** The dot and the word beside it. */
function setState(state, text) {
    const mount = byId('lv-state');
    const label = byId('lv-state-text');
    if (mount) {
        mount.dataset.state = state;
    }
    if (label) {
        label.textContent = text;
    }
}

/** What the Pause/Resume control says it will do. */
function toggleLabel(text) {
    const button = byId('lv-toggle');
    if (button) {
        button.textContent = text;
    }
}

/**
 * The counters beside the state.
 *
 * `lag` is bytes written to the log that have not been read yet, and it is worth printing
 * because it is the difference between "the site is quiet" and "this page cannot keep up".
 * Unparsed lines are counted rather than shown: a line that does not match its source's format
 * has no fields to render, and the reason it did not match is the useful part.
 */
function counts() {
    const mount = byId('lv-counts');
    if (!mount) {
        return;
    }

    const parts = [num(seen) + (seen === 1 ? ' request' : ' requests')];
    if (lag > 0) {
        parts.push(bytes(lag) + ' not read yet');
    }
    if (unparsed > 0) {
        parts.push(num(unparsed) + ' unparsed' + (unparsedWhy ? ' (' + unparsedWhy + ')' : ''));
    }
    if (held.size >= MAX_ROWS) {
        parts.push('showing the last ' + num(MAX_ROWS));
    }

    mount.textContent = parts.join(' · ');
}

/* -------------------------------------------------------------------------
 * The table
 * ---------------------------------------------------------------------- */

/**
 * Put a batch at the top of the table.
 *
 * Sorted by the line's own timestamp within the batch, because several files are read in one
 * pass and the order they were read in is not the order the requests happened in. Across
 * batches the arrival order stands, which is what a live tail is; the Time column is on every
 * row so a reader can always see the difference.
 */
function addRows(rows) {
    if (!rows.length) {
        return;
    }

    const table = byId('lv-table');
    const body = table ? table.tBodies[0] : null;
    if (!body) {
        return;
    }

    const note = byId('lv-empty-note');
    if (note) {
        note.hidden = true;
    }

    const batch = rows.slice().sort((a, b) => String(a.ts || '').localeCompare(String(b.ts || '')));
    for (const row of batch) {
        held.set(row.id, row);
        body.insertBefore(buildRow(row), body.firstChild);
        seen++;
    }

    while (body.children.length > MAX_ROWS) {
        const last = body.lastChild;
        held.delete(last.dataset ? last.dataset.id : null);
        body.removeChild(last);
    }
}

/** One request, as seven cells. */
function buildRow(row) {
    const tr = el('tr', drillRow('liveline', { id: row.id }));

    tr.appendChild(el('td', {
        class: 'mono nowrap',
        text: timeOnly(row.ts),
        title: when(row.ts)
    }));

    tr.appendChild(el('td', { class: 'clip', title: row.host || 'The line names no host' }, [
        hostCell(row.host, { mono: true })
    ]));

    tr.appendChild(el('td', { class: 'clip mono', title: placeWords(row) }, [
        row.country ? flagNode(row.country) : null,
        row.ip ? dimValue('ip_s', row.ip, { mono: true }) : el('span', { class: 'muted', text: '—' })
    ]));

    tr.appendChild(el('td', {
        class: 'clip urlcell',
        title: (row.method ? row.method + ' ' : '') + row.path + (row.query ? '?' + row.query : '')
    }, [
        el('span', { class: 'live-method muted mono', text: row.method || '' }),
        pathCell(row.path, { host: row.host, query: row.query })
    ]));

    tr.appendChild(el('td', { class: 'num mono' }, [
        row.status === null
            ? el('span', { class: 'muted', text: '—' })
            : el('span', {
                class: 't-status-' + String(row.status).charAt(0),
                text: String(row.status),
                title: statusWords(row)
            })
    ]));

    tr.appendChild(el('td', { class: 'clip', title: row.ua || 'No User-Agent was logged' }, [
        clientWords(row)
    ]));

    tr.appendChild(el('td', { class: 'live-read' }, [
        el('span', {
            class: 'state live-tone-' + row.read.tone,
            text: row.read.label,
            title: row.read.why
        }),
        openButton('liveline', { id: row.id }, 'Open this request')
    ]));

    return tr;
}

/** The client in a few words: the browser, or what it says it is. */
function clientWords(row) {
    if (row.ua_bot && row.ua_bot_name) {
        return el('span', { text: row.ua_bot_name });
    }
    if (row.browser) {
        return dimValue('browser_s', row.browser, {
            text: [row.browser, row.browser_ver].filter(Boolean).join(' ')
        });
    }
    if (row.ua_logged && !row.ua) {
        return el('span', { class: 'muted', text: 'no User-Agent' });
    }
    return el('span', { class: 'muted', text: '—' });
}

/** Where the address is, or the honest alternative. */
function placeWords(row) {
    if (!row.geo_known) {
        return 'This address has not been located yet. Ingest looks it up; this page only reads '
            + 'what has already been looked up.';
    }
    return [row.city, row.region, row.country].filter(Boolean).join(', ') || 'Located, but unnamed';
}

/** What the status class means, in the vocabulary's own words. */
function statusWords(row) {
    const spoken = row.status_class ? valueWords('status_class_s', row.status_class) : null;
    return spoken ? spoken.label + '. ' + spoken.why : '';
}

/* -------------------------------------------------------------------------
 * The dialog
 * ---------------------------------------------------------------------- */

/** A definition list from [label, value] pairs, skipping the empty ones. */
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

/**
 * Open one request.
 *
 * The row is already in the browser — it arrived over the stream — so the request half of the
 * dialog is rendered immediately and nothing is fetched for it. The index half is a separate
 * request, made once the dialog is on screen, because it is a separate claim about a different
 * plane and because a Solr read has no business blocking a dialog the reader opened out of
 * curiosity.
 */
async function openLine(id) {
    const row = held.get(id);
    if (!row) {
        const handle = openDialog('That request is no longer held', '');
        fill(handle.body, [el('p', {
            class: 'muted',
            text: 'The table keeps the last ' + num(MAX_ROWS) + ' requests and this one has scrolled '
                + 'out of it. It is in the index once its visit has been scored.'
        })]);
        return;
    }

    const handle = openDialog(
        (row.method ? row.method + ' ' : '') + row.path,
        [when(row.ts), row.host, row.read.label].filter(Boolean).join(' · ')
    );

    fill(handle.body, [
        el('h3', { text: 'The request' }),
        kv([
            ['When', when(row.ts)],
            ['Virtual host', row.host ? hostCell(row.host) : null],
            ['Method', row.method, true],
            ['Path', pathCell(row.path, { host: row.host, query: row.query })],
            ['Query string', row.query || null, true],
            ['Protocol', row.proto, true],
            ['Answered with', statusNode(row)],
            ['Bytes sent', row.bytes === null ? null : bytes(row.bytes)],
            ['Time the server took', row.dur_us === null ? null : durUs(row.dur_us)],
            ['Kind of request', row.kind],
            ['Read from', row.file, true],
            ['Search terms in the query', (row.search_terms || []).join(', ') || null]
        ]),

        el('h3', { text: 'The client' }),
        kv([
            ['Address', row.ip ? dimValue('ip_s', row.ip, { mono: true }) : null],
            ['Address family', row.ip_ver ? 'IPv' + row.ip_ver : null],
            ['Browser', row.browser
                ? dimValue('browser_s', row.browser, {
                    text: [row.browser, row.browser_ver].filter(Boolean).join(' ')
                })
                : null],
            ['Operating system', row.os ? dimValue('os_s', row.os) : null],
            ['Kind of device', row.device ? dimValue('device_s', row.device) : null],
            ['Says it is a crawler', botNode(row)],
            ['Languages it asked for', row.accept_lang, true],
            ['TLS', [row.tls_proto, row.tls_cipher].filter(Boolean).join(' · ') || null, true],
            ['Forwarded-for header', row.xff || null, true]
        ]),
        uaBlock(row),

        el('h3', { text: 'Where it came from' }),
        geoBlock(row),
        kv([
            ['Referrer', row.referer || 'none was sent', row.referer ? true : false],
            ['Which counts as', row.referer_type ? dimValue('referer_type_s', row.referer_type) : null]
        ]),

        el('h3', { text: 'What this line shows' }),
        el('p', {
            class: 'faint',
            text: 'Read from this request alone. A verdict is scored over a whole visit once it '
                + 'settles, so there is none here.'
        }),
        readingBlock(row),

        el('h3', { text: 'What the index already knows about this address' }),
        el('div', { id: 'lv-known' }, [el('p', { class: 'muted', text: 'Asking…' })])
    ]);

    if (row.ip) {
        loadKnown(row.ip, handle.generation, 0);
    } else {
        fill(byId('lv-known'), [el('p', {
            class: 'muted',
            text: 'The line carries no client address, so there is nothing to look up.'
        })]);
    }
}

/** The status, as a number and the sentence its class carries. */
function statusNode(row) {
    if (row.status === null) {
        return null;
    }
    const spoken = row.status_class ? valueWords('status_class_s', row.status_class) : null;
    return el('span', {}, [
        el('span', { class: 'mono t-status-' + String(row.status).charAt(0), text: String(row.status) }),
        spoken ? el('span', { class: 'muted', text: ' — ' + spoken.label }) : null
    ]);
}

/** What the User-Agent claims, if it claims anything. */
function botNode(row) {
    if (!row.ua_bot) {
        return null;
    }
    return el('span', {}, [
        el('span', { text: row.ua_bot_name || 'yes' }),
        row.ua_bot_cat ? el('span', { text: ' — ' }) : null,
        row.ua_bot_cat ? dimValue('ua_bot_cat_s', row.ua_bot_cat) : null,
        row.ai_crawler ? el('span', { class: 'chip chip-accent', text: 'collects for AI' }) : null
    ]);
}

/** The raw User-Agent, folded away, because it is long and rarely the thing being read. */
function uaBlock(row) {
    if (!row.ua) {
        return row.ua_logged
            ? el('p', { class: 'muted', text: 'The client sent no User-Agent at all. Browsers always send one.' })
            : el('p', { class: 'muted', text: 'This log format does not record the User-Agent.' });
    }
    return el('details', { class: 'raw-ua' }, [
        el('summary', { text: 'The User-Agent as it was sent' }),
        el('p', { class: 'mono wrap', text: row.ua })
    ]);
}

/**
 * Geography and network ownership, or the reason they are absent.
 *
 * "Not looked up yet" is a different statement from "unknown" and the difference matters: the
 * ingest daemon does the lookup and caches it, and this page only reads that cache. A row for
 * an address nobody has resolved yet is a page that has not caught up, not a client nobody can
 * identify.
 */
function geoBlock(row) {
    const pairs = [];

    if (row.geo_known) {
        pairs.push(['Country', row.country ? dimValue('country_s', row.country) : null]);
        pairs.push(['Region', row.region]);
        pairs.push(['City', row.city ? dimValue('city_s', row.city) : null]);
        pairs.push(['Timezone of the address', row.tz, true]);
    }
    if (row.net_known) {
        pairs.push(['Network operator', row.as_org ? dimValue('as_org_s', row.as_org) : null]);
        pairs.push(['AS number', row.asn ? 'AS' + row.asn : null, true]);
        pairs.push(['Kind of network', row.as_type ? dimValue('as_type_s', row.as_type) : null]);
        pairs.push(['Netblock name', row.netname, true]);
    }

    const list = kv(pairs);
    if (row.geo_known && row.net_known) {
        return list;
    }

    const missing = [];
    if (!row.geo_known) {
        missing.push('located');
    }
    if (!row.net_known) {
        missing.push('traced to a network');
    }

    return el('div', {}, [
        list,
        el('p', {
            class: 'muted',
            text: 'This address has not been ' + missing.join(' or ') + ' yet. Ingest does that once '
                + 'and caches it; this page reads the cache and never makes the lookup itself.'
        })
    ]);
}

/** The one-line reading, and every named pattern the request matched. */
function readingBlock(row) {
    const parts = [
        el('p', {}, [
            el('span', { class: 'state live-tone-' + row.read.tone, text: row.read.label }),
            el('span', { text: ' ' + row.read.why })
        ])
    ];

    const flags = row.flags || [];
    if (!flags.length) {
        parts.push(el('p', { class: 'muted', text: 'No attack pattern matched the path or the query.' }));
        return el('div', {}, parts);
    }

    const list = el('ul', { class: 'plane-list' });
    for (const code of flags) {
        const spoken = valueWords('hit_flags_ss', code);
        list.appendChild(el('li', {}, [
            el('strong', { text: spoken ? spoken.label : code }),
            spoken && spoken.why ? el('span', { class: 'muted', text: ' ' + spoken.why }) : null
        ]));
    }
    parts.push(list);

    return el('div', {}, parts);
}

/* -------------------------------------------------------------------------
 * The other plane
 * ---------------------------------------------------------------------- */

/**
 * What has already been ingested about this address.
 *
 * THIS IS THE HALF THAT IS ALLOWED TO CARRY A VERDICT, because every session behind it has been
 * scored. The heading above it says whose claim it is, the sentence under it says how many of
 * those sessions have settled, and an address with no history at all says so in words rather
 * than rendering an empty table that reads like a failure.
 */
async function loadKnown(ip, generation, start) {
    const mount = byId('lv-known');
    if (!mount) {
        return;
    }

    try {
        const data = await api('live', 'client', { ip: ip, start: start });
        if (!isCurrent(generation)) {
            return;
        }
        renderKnown(mount, ip, data, generation);
    } catch (err) {
        if (isCurrent(generation)) {
            dialogFail(mount, err, () => loadKnown(ip, generation, start));
        }
    }
}

/** Draw it. */
function renderKnown(mount, ip, data, generation) {
    if (!data.sessions) {
        fill(mount, [el('p', {
            class: 'muted',
            text: 'No scored visit carries this address' + (data.scope ? ' on ' + data.scope : '')
                + '. That is a fact about what has been ingested, not about this client.'
        })]);
        return;
    }

    const summary = el('p', {}, [
        el('span', {
            text: num(data.sessions) + (data.sessions === 1 ? ' visit' : ' visits')
                + (data.scope ? ' on ' + data.scope : '') + ', '
                + num(data.settled) + ' of them settled'
                + (data.first ? ', first seen ' + when(data.first) : '') + '.'
        })
    ]);

    const verdicts = el('p', { class: 'live-verdicts' });
    for (const row of (data.verdicts || [])) {
        verdicts.appendChild(el('span', {
            class: 'chip v-' + row.value,
            title: (valueWords('bot_verdict_s', row.value) || {}).why || null,
            text: valueText('bot_verdict_s', row.value) + ' × ' + num(row.count)
        }));
    }
    for (const row of (data.classes || [])) {
        if (row.value === 'none') {
            continue;
        }
        verdicts.appendChild(el('span', {
            class: 'chip',
            title: (valueWords('bot_class_s', row.value) || {}).why || null,
            text: valueText('bot_class_s', row.value) + ' × ' + num(row.count)
        }));
    }

    const wrap = visitTable(data.visits || []);
    const pager = el('div', { class: 'pager-mount' });
    renderPager(pager, data.page, (next) => loadKnown(ip, generation, next));

    fill(mount, [
        summary,
        verdicts.childNodes.length ? verdicts : null,
        el('p', { class: 'faint', text: visitCaption(data.page) }),
        wrap,
        pager
    ]);
}

/* -------------------------------------------------------------------------
 * Entry point
 * ---------------------------------------------------------------------- */

/**
 * Wire the controls and open the stream.
 *
 * A browser without EventSource gets the card, the explanation and a line saying the stream
 * needs it, rather than a page whose table never fills and never says why.
 */
export default function init() {
    registerOpener('liveline', (data) => openLine(String(data.id || '')));

    const button = byId('lv-toggle');
    if (button) {
        button.addEventListener('click', () => {
            if (source) {
                stop('asked');
            } else {
                begin();
            }
        });
    }

    document.addEventListener('visibilitychange', () => {
        if (document.hidden && source) {
            stop('hidden');
        }
    });

    if (typeof window.EventSource !== 'function') {
        setState('off', 'This browser cannot hold a stream open, so there is nothing to show here.');
        toggleLabel('Resume');
        return;
    }

    if (boot.demo) {
        setState('off', 'Demo mode answers from fixtures, and there is no log file behind them.');
        toggleLabel('Resume');
        return;
    }

    begin();
}
