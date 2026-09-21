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
 * A connection is held open for as long as it is healthy. EventSource reconnects by itself when
 * one does end, carrying the cursor as `Last-Event-ID`, so nothing is missed. This end does not
 * stop on its own at all.
 *
 * IT USED TO, THREE TIMES OVER, AND ALL THREE WERE WRONG. A fifteen-minute cap ended the stream
 * in a tab somebody was watching; a `visibilitychange` handler ended it the moment the tab lost
 * focus, so glancing at another window came back to a stopped page; and the server cut every
 * connection at forty-five seconds, which put "Reconnecting" on a live page every forty-five
 * seconds forever. The operator decides: Pause stops it, and navigating away stops it because
 * the document is discarded and the connection with it. Nothing else does.
 *
 * A reconnect that the browser completes quickly is therefore not news, and saying so on the
 * state line taught the operator to distrust a page that was working. The word waits for
 * RECONNECT_QUIET_MS and is withdrawn the moment an event arrives.
 *
 * EVERY VALUE HERE CAME OFF A LOG LINE, which is attacker-chosen bytes by definition, and it is
 * rendered the moment it arrives with no batch job in between. Nothing is assigned to innerHTML
 * anywhere in this file: every node is built by core.js's el(), whose `text` is textContent, and
 * every href is built by url.js from a validated host and path.
 */

'use strict';

import { api, boot, byId, bytes, clockStamp, durUs, el, fill, num, post, stamp, timeOnly, tip, when } from '../core.js';
import { draw, shadowPointer } from '../charts.js';
import { dimValue, drillRow, flagNode, openButton, valueText, valueWords } from '../identity.js';
import { hostCell } from '../hostcolor.js';
import { hrefLink, pathCell } from '../url.js';
import { dialogFail, isCurrent, openDialog, registerOpener } from '../dialog.js';
import { visitCaption, visitTable } from '../visits.js';
import { renderPager } from '../pager.js';
import { exportLink } from '../export.js';
import { t as T, tn as Tn, tf as Tf, tfn as Tfn } from '../i18n.js';

/** Rows kept in the table. Beyond this the oldest are dropped, which the caption says. */
const MAX_ROWS = 300;

/** How long a reconnect may take before it is worth telling the operator about. */
const RECONNECT_QUIET_MS = 1500;

/** The open connection, or null. */
let source = null;

/** Pending "Reconnecting" announcement, cancelled if the stream comes back first. */
let reconnectTimer = 0;

/** Keeps the chart's window moving while the log is quiet. */
let chartTimer = 0;

/** Rows currently in the table, by id, so the dialog can open one without a second fetch. */
const held = new Map();

/** Requests shown since the page was opened. */
let seen = 0;

/** The last thing the server said about how far behind the reader is. */
let lag = 0;

/** Lines that did not match their source's format, and the most recent reason. */
let unparsed = 0;
let unparsedWhy = '';

/** Rows the server refused to send because a rule matched them. Reported, never silent. */
let excluded = 0;

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
    source.addEventListener('enrich', onEnrich);
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

    arrived();

    if (data.open === 0) {
        setState('off', data.sources === 0
            ? T('No log source is configured.')
            : T('No configured log file could be opened.'));
        stop('nosource');
        return;
    }

    setState('live', data.hosts && data.hosts.length
        ? T('Streaming {hosts}', { hosts: data.hosts.join(', ') })
        : Tn('Streaming {n} log file', 'Streaming {n} log files', data.open));
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
    excluded += Number(data.excluded) || 0;

    arrived();
    addRows(Array.isArray(data.rows) ? data.rows : []);
    setState('live', T('Streaming'));
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
    arrived();
    setState('live', T('Streaming'));
    counts();
}

/**
 * Geography that arrived after the rows it belongs to.
 *
 * The daemon resolves an address a moment after the request that carried it has already streamed
 * past, so the first row from a new address goes out with no country and no flag. This fills them
 * in where they are, rather than leaving the operator looking at a table that disagrees with the
 * dialog opened from it.
 */
function onEnrich(event) {
    const data = parse(event);
    if (data === null || !data.ips || typeof data.ips !== 'object') {
        return;
    }

    arrived();

    for (const row of held.values()) {
        const fields = row.ip ? data.ips[row.ip] : null;
        if (fields) {
            Object.assign(row, fields);
        }
    }

    paintPlaces(data.ips);
}

/**
 * Put a newly known country onto the rows already on screen.
 *
 * @param {Object} map Addresses to the fields that have just become known.
 */
function paintPlaces(map) {
    const table = byId('lv-table');
    const body = table ? table.tBodies[0] : null;
    if (!body) {
        return;
    }

    for (const tr of Array.from(body.children)) {
        const row = held.get(tr.dataset ? tr.dataset.id : null);
        if (!row || !row.ip || !map[row.ip]) {
            continue;
        }

        const cell = tr.querySelector('.live-addr');
        if (!cell) {
            continue;
        }

        cell.title = placeWords(row);
        if (row.country && !cell.querySelector('.flag')) {
            const flag = flagNode(row.country);
            if (flag) {
                cell.insertBefore(flag, cell.firstChild);
            }
        }
    }
}

/**
 * An event arrived, so whatever the connection was doing, it is doing it successfully.
 *
 * Withdraws a pending "Reconnecting" before it is ever shown. A reconnect the browser finishes
 * in a few hundred milliseconds is not something the operator needs to be told about, and being
 * told about it repeatedly is what made a working page look broken.
 */
function arrived() {
    if (reconnectTimer) {
        window.clearTimeout(reconnectTimer);
        reconnectTimer = 0;
    }
}

/**
 * The connection is being re-established. Say so only if it takes long enough to matter.
 *
 * @param {string} state The dot to show if the word is actually reached.
 */
function reconnecting(state) {
    if (reconnectTimer) {
        return;
    }
    reconnectTimer = window.setTimeout(() => {
        reconnectTimer = 0;
        setState(state, T('Reconnecting'));
    }, RECONNECT_QUIET_MS);
}

/**
 * The server let go of this connection.
 *
 * It does that when the work it has done approaches the PHP pool's execution limit, which on an
 * ordinary site is hours away, not seconds. The browser reconnects by itself carrying the cursor
 * and the reader never knows — so nothing is said unless the reconnect is slow.
 */
function onPause(event) {
    parse(event);
    reconnecting('live');
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
    reconnecting('wait');
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
    arrived();
    if (chartTimer) {
        window.clearInterval(chartTimer);
        chartTimer = 0;
    }
    if (source) {
        source.close();
        source = null;
    }

    const words = {
        lost: T('The connection dropped and could not be re-established.'),
        asked: T('Paused.'),
        nosource: T('There is nothing to read. Settings is where log sources are configured.')
    };

    resumeFrom = cursor || resumeFrom;
    setState('off', words[reason] || T('Stopped.'));
    toggleLabel(T('Resume'));
    counts();
}

/** Start, or start again. */
function begin() {
    if (source) {
        return;
    }
    setState('wait', T('Connecting'));
    toggleLabel(T('Pause'));
    connect(resumeFrom);
    resumeFrom = '';

    tickChart();
    if (!chartTimer) {
        chartTimer = window.setInterval(tickChart, 1000);
    }
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

    const parts = [Tn('{n} request', '{n} requests', seen, { n: num(seen) })];
    if (lag > 0) {
        parts.push(T('{size} not read yet', { size: bytes(lag) }));
    }
    if (unparsed > 0) {
        parts.push(T('{n} unparsed', { n: num(unparsed) }) + (unparsedWhy ? ' (' + unparsedWhy + ')' : ''));
    }
    /* SAID OUT LOUD, because a stream that is quieter than the site is busy looks broken. The
       server counts what its rules refused and this is the only place that number surfaces. */
    if (excluded > 0) {
        parts.push(T('{n} hidden by your rules', { n: num(excluded) }));
    }
    if (held.size >= MAX_ROWS) {
        parts.push(T('showing the last {n}', { n: num(MAX_ROWS) }));
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
        const tr = buildRow(row);
        hideIfFiltered(tr);
        body.insertBefore(tr, body.firstChild);
        seen++;
    }

    countIntoChart(batch.length);

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
        title: when(row.ts)
    }, [clockStamp(row.ts)]));

    /* NOTHING IN THIS TABLE IS A FILTER LINK. Every other view's cells drill into the
       dashboard, but a row here opens the request dialog — and a link inside the row won the
       click instead, navigating away with `f[ip_s][]=…` in the URL and reloading the page the
       operator was watching. A live tail cannot survive a page load, so the dimension links
       are rendered as plain values and the row keeps its own gesture. */
    tr.appendChild(el('td', { class: 'clip', title: row.host || T('The line names no host') }, [
        hostCell(row.host, { mono: true, link: false })
    ]));

    tr.appendChild(el('td', { class: 'clip mono live-addr', title: placeWords(row) }, [
        row.country ? flagNode(row.country) : null,
        row.ip
            ? dimValue('ip_s', row.ip, { mono: true, link: false })
            : el('span', { class: 'muted', text: '—' })
    ]));

    tr.appendChild(el('td', {
        class: 'clip urlcell',
        title: (row.method ? row.method + ' ' : '') + row.path + (row.query ? '?' + row.query : '')
    }, [requestCell(row)]));

    tr.appendChild(el('td', { class: 'num mono' }, [
        row.status === null
            ? el('span', { class: 'muted', text: '—' })
            : el('span', {
                class: 't-status-' + String(row.status).charAt(0),
                text: String(row.status),
                title: statusWords(row)
            })
    ]));

    /* THE CLIENT AND THE WAY IN, ON ONE LINE. The reading this row got — what "This line"
       used to print — is the title here, so nothing it said is lost; it was the same fact as
       the client name in every row anybody looked at. */
    tr.appendChild(el('td', { class: 'clip live-client', title: row.read.why || row.ua || T('No User-Agent was logged') }, [
        el('span', { class: 'live-client-name' }, [clientWords(row)]),
        openButton('liveline', { id: row.id }, T('Open this request'))
    ]));

    return tr;
}

/**
 * The method and the path, as one cell.
 *
 * The method is put INSIDE url.js's own wrapper rather than beside it. That wrapper is a flex
 * row whose path shrinks and whose link does not, and a sibling in front of it would sit on its
 * own line — and would fight the grid mobile.css turns a cell into when the table stacks.
 */
function requestCell(row) {
    const cell = pathCell(row.path, { host: row.host, query: row.query });
    if (row.method) {
        cell.insertBefore(el('span', { class: 'live-method muted mono', text: row.method }), cell.firstChild);
    }
    return cell;
}

/** The client in a few words: the browser, or what it says it is. */
function clientWords(row) {
    if (row.ua_bot && row.ua_bot_name) {
        return el('span', { text: row.ua_bot_name });
    }
    if (row.browser) {
        return dimValue('browser_s', row.browser, {
            text: [row.browser, row.browser_ver].filter(Boolean).join(' '),
            link: false
        });
    }
    if (row.ua_logged && !row.ua) {
        return el('span', { class: 'muted', text: T('no User-Agent') });
    }
    return el('span', { class: 'muted', text: '—' });
}

/** Where the address is, or the honest alternative. */
function placeWords(row) {
    if (!row.geo_known) {
        return T('This address has not been located yet. Ingest looks it up; this page only reads '
            + 'what has already been looked up.');
    }
    return [row.city, row.region, row.country].filter(Boolean).join(', ') || T('Located, but unnamed');
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
        const handle = openDialog(T('That request is no longer held'), '');
        fill(handle.body, [el('p', {
            class: 'muted',
            text: T('The table keeps the last {n} requests and this one has scrolled '
                + 'out of it. It is in the index once its visit has been scored.', { n: num(MAX_ROWS) })
        })]);
        return;
    }

    const handle = openDialog(
        (row.method ? row.method + ' ' : '') + row.path,
        [when(row.ts), row.host, row.read.label].filter(Boolean).join(' · ')
    );

    fill(handle.body, [
        el('h3', { text: T('The request') }),
        kv([
            [T('When'), stamp(row.ts)],
            [T('Virtual host'), row.host ? hostCell(row.host) : null],
            [T('Method'), row.method, true],
            /* SHOWN WITH ITS QUERY STRING. The link always carried it — siteUrl() composes path
               and query — but the cell printed the bare path, so the row looked like it would
               open something other than the request it describes. The query cannot be folded
               into the path argument: `?` is not a path character and would be encoded. */
            [T('Path'), pathCell(row.path, {
                host: row.host,
                query: row.query,
                text: row.path + (row.query ? '?' + row.query : '')
            })],
            [T('Query string'), row.query || null, true],
            [T('Protocol'), row.proto, true],
            [T('Answered with'), statusNode(row)],
            [T('Bytes sent'), row.bytes === null ? null : bytes(row.bytes)],
            [T('Time the server took'), row.dur_us === null ? null : durUs(row.dur_us)],
            [T('Kind of request'), row.kind],
            [T('Read from'), row.file, true],
            [T('Search terms in the query'), (row.search_terms || []).join(', ') || null]
        ]),

        el('h3', { text: T('The client') }),
        kv([
            [T('Address'), row.ip ? dimValue('ip_s', row.ip, { mono: true }) : null],
            [T('Address family'), row.ip_ver ? 'IPv' + row.ip_ver : null],
            [T('Browser'), row.browser
                ? dimValue('browser_s', row.browser, {
                    text: [row.browser, row.browser_ver].filter(Boolean).join(' ')
                })
                : null],
            [T('Operating system'), row.os ? dimValue('os_s', row.os) : null],
            [T('Kind of device'), row.device ? dimValue('device_s', row.device) : null],
            [T('Says it is a crawler'), botNode(row)],
            [T('Languages it asked for'), row.accept_lang, true],
            [T('TLS'), [row.tls_proto, row.tls_cipher].filter(Boolean).join(' · ') || null, true],
            [T('Forwarded-for header'), row.xff || null, true]
        ]),
        uaBlock(row),

        el('h3', { text: T('Where it came from') }),
        geoBlock(row),
        kv([
            [T('Referrer'), row.referer
                ? el('span', { class: 'refurl' }, [
                    el('span', { class: 'mono wrap', text: row.referer }),
                    hrefLink(row.referer_href)
                ])
                : T('none was sent')],
            [T('Which counts as'), row.referer_type ? dimValue('referer_type_s', row.referer_type) : null]
        ]),

        el('h3', { text: T('What this line shows') }),
        el('p', {
            class: 'faint',
            text: T('Read from this request alone. A verdict is scored over a whole visit once it '
                + 'settles, so there is none here.')
        }),
        readingBlock(row),

        el('h3', { text: T('What the index already knows about this address') }),
        el('div', { id: 'lv-known' }, [el('p', { class: 'muted', text: T('Asking…') })])
    ]);

    if (row.ip) {
        loadKnown(row.ip, handle.generation, 0);
    } else {
        fill(byId('lv-known'), [el('p', {
            class: 'muted',
            text: T('The line carries no client address, so there is nothing to look up.')
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
        el('span', { text: row.ua_bot_name || T('yes') }),
        row.ua_bot_cat ? el('span', { text: ' — ' }) : null,
        row.ua_bot_cat ? dimValue('ua_bot_cat_s', row.ua_bot_cat) : null,
        row.ai_crawler ? el('span', { class: 'chip chip-accent', text: T('collects for AI') }) : null
    ]);
}

/** The raw User-Agent, folded away, because it is long and rarely the thing being read. */
function uaBlock(row) {
    if (!row.ua) {
        return row.ua_logged
            ? el('p', { class: 'muted', text: T('The client sent no User-Agent at all. Browsers always send one.') })
            : el('p', { class: 'muted', text: T('This log format does not record the User-Agent.') });
    }
    return el('details', { class: 'raw-ua' }, [
        el('summary', { text: T('The User-Agent as it was sent') }),
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
        pairs.push([T('Country'), row.country ? dimValue('country_s', row.country) : null]);
        pairs.push([T('Region'), row.region]);
        pairs.push([T('City'), row.city ? dimValue('city_s', row.city) : null]);
        pairs.push([T('Timezone of the address'), row.tz, true]);
    }
    if (row.net_known) {
        pairs.push([T('Network operator'), row.as_org ? dimValue('as_org_s', row.as_org) : null]);
        pairs.push([T('AS number'), row.asn ? 'AS' + row.asn : null, true]);
        pairs.push([T('Kind of network'), row.as_type ? dimValue('as_type_s', row.as_type) : null]);
        pairs.push([T('Netblock name'), row.netname, true]);
    }

    const list = kv(pairs);
    if (row.geo_known && row.net_known) {
        return list;
    }

    const text = !row.geo_known && !row.net_known
        ? T('This address has not been located or traced to a network yet. Ingest does that once '
            + 'and caches it; this page reads the cache and never makes the lookup itself.')
        : (!row.geo_known
            ? T('This address has not been located yet. Ingest does that once '
                + 'and caches it; this page reads the cache and never makes the lookup itself.')
            : T('This address has not been traced to a network yet. Ingest does that once '
                + 'and caches it; this page reads the cache and never makes the lookup itself.'));

    return el('div', {}, [
        list,
        el('p', { class: 'muted', text: text })
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
        parts.push(el('p', { class: 'muted', text: T('No attack pattern matched the path or the query.') }));
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
async function loadKnown(ip, generation, start, rows) {
    const mount = byId('lv-known');
    if (!mount) {
        return;
    }

    try {
        const data = await api('live', 'client', { ip: ip, start: start, rows: rows });
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
            text: data.scope
                ? T('No scored visit carries this address on {scope}. That is a fact about what has been ingested, not about this client.', { scope: data.scope })
                : T('No scored visit carries this address. That is a fact about what has been ingested, not about this client.')
        })]);
        return;
    }

    const summary = el('p', {}, [
        el('span', {
            text: (data.scope
                ? Tn('{n} visit on {scope}', '{n} visits on {scope}', data.sessions, { n: num(data.sessions), scope: data.scope })
                : Tn('{n} visit', '{n} visits', data.sessions, { n: num(data.sessions) }))
                + ', ' + T('{n} of them settled', { n: num(data.settled) })
                + (data.first ? ', ' + T('first seen {when}', { when: when(data.first) }) : '') + '.'
        })
    ]);

    const verdicts = el('div', { class: 'live-verdicts' });
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
    renderPager(pager, data.page, (next, rows) => loadKnown(ip, generation, next, rows));

    fill(mount, [
        summary,
        verdicts.childNodes.length ? verdicts : null,
        el('p', { class: 'faint', text: visitCaption(data.page) }),
        wrap,
        pager
    ]);
}

/* -------------------------------------------------------------------------
 * Finding a row, excluding a request, and the shape of the last minute
 *
 * THREE CONTROLS, AND ONLY ONE OF THEM REACHES THE SERVER. The find box hides rows that are
 * already here; the rules travel to Live\Reader, so an excluded request is never turned into
 * a frame at all; the chart counts what arrived. None of the three changes what is stored —
 * that is per hostname, in Settings, and deliberately somewhere else.
 * ---------------------------------------------------------------------- */

/** Seconds the chart keeps. One minute reads as "now" and fits without a scroll. */
const CHART_WINDOW = 60;

/** Requests per wall-clock second, oldest first, as [epochSecond, count] pairs. */
const perSecond = [];

/** The lower-cased find text, or '' when the box is empty. */
let findText = '';

/** Rules as last read from the server, so the dialog can render without a second fetch. */
let rules = [];

/** Field slug to the words the dialog shows, filled from the same payload. */
let ruleFields = {};

/** Cap the server will enforce anyway; the dialog says so before a save is refused. */
let ruleMax = 40;

/** The built-in groups the server offers, keyed by slug. Catalogue, never edited here. */
let builtin = {};

/** Which built-in slugs are switched on. The only part of a built-in an operator changes. */
let builtinOn = [];

/**
 * Does this row survive the find box?
 *
 * The whole row's text, lower-cased, against the typed text. That is what "a simple grep over
 * what is on screen" means, and it is why no field has to be chosen: a hostname, an address, a
 * path, a status and a client name are all in there already.
 */
function matchesFind(tr) {
    return findText === '' || String(tr.textContent || '').toLowerCase().includes(findText);
}

/** Hide or show one row against the current find text. */
function hideIfFiltered(tr) {
    tr.hidden = !matchesFind(tr);
}

/**
 * Drop the rows already on screen that a rule now matches.
 *
 * WITHOUT THIS A SAVED RULE LOOKS BROKEN. The server stops sending matching requests from the
 * next connection onwards, but everything already in the table stays — so an operator excludes
 * `HEAD` and goes on looking at a screen full of HEAD requests, with the card telling them six
 * rules are hiding things. The rules are evaluated here against the row objects the table was
 * built from, which is the same data the server matched on.
 *
 * A pattern the browser will not compile is skipped rather than thrown: the server has already
 * accepted this list, and one unusable rule must not stop the other five from being applied.
 */
function pruneExcluded() {
    const table = byId('lv-table');
    const body = table ? table.tBodies[0] : null;
    if (!body) {
        return;
    }

    const live = [];
    for (const rule of rules) {
        if (rule.enabled === false) {
            continue;
        }
        try {
            live.push({ field: rule.field, re: new RegExp(rule.pattern, 'i') });
        } catch (err) {
            continue;
        }
    }
    if (!live.length) {
        return;
    }

    for (const tr of Array.prototype.slice.call(body.children)) {
        const row = held.get(tr.dataset ? tr.dataset.id : null);
        if (!row) {
            continue;
        }
        for (const rule of live) {
            const value = row[rule.field];
            if (value !== null && value !== undefined && rule.re.test(String(value))) {
                held.delete(tr.dataset.id);
                body.removeChild(tr);
                break;
            }
        }
    }
}

/** Re-apply the find text to every row now in the table. */
function applyFind() {
    const table = byId('lv-table');
    const body = table ? table.tBodies[0] : null;
    if (!body) {
        return;
    }
    for (const tr of body.children) {
        hideIfFiltered(tr);
    }
}

/**
 * Move the window so that it ends at this second, filling the silence with zeros.
 *
 * THE WINDOW IS A CLOCK, NOT A LIST OF THINGS THAT HAPPENED. It used to hold only the seconds
 * something arrived in, and the axis was a category per entry — so two requests a minute apart
 * became two categories, each drawn half the width of the card, one at each edge; and the older
 * one disappeared the moment the gap-filling pushed the window past sixty entries. A minute is
 * sixty bars whether or not anything happened in any of them, which is what makes one request
 * look like one request.
 */
function advanceChart() {
    const now = Math.floor(Date.now() / 1000);
    const last = perSecond.length ? perSecond[perSecond.length - 1][0] : now - 1;

    for (let t = last + 1; t <= now; t++) {
        perSecond.push([t, 0]);
    }

    while (perSecond.length > CHART_WINDOW) {
        perSecond.shift();
    }
    while (perSecond.length < CHART_WINDOW) {
        perSecond.unshift([perSecond[0][0] - 1, 0]);
    }
}

/** Advance the window and redraw it, whether or not anything arrived. */
function tickChart() {
    advanceChart();
    renderChart();
}

/**
 * Fold this batch into the current second and redraw.
 *
 * Counted by arrival rather than by the line's own timestamp: the chart is answering "how busy
 * is it right now", and a batch read from several files carries timestamps that are close but
 * not equal.
 */
function countIntoChart(n) {
    advanceChart();
    if (n > 0) {
        perSecond[perSecond.length - 1][1] += n;
    }
    renderChart();
}

/** The last minute as a bar per second. */
function renderChart() {
    draw('lv-chart', (theme) => ({
        grid: { top: 8, bottom: 4, left: 4, right: 4, containLabel: true },
        tooltip: {
            trigger: 'axis',
            axisPointer: shadowPointer(theme),
            formatter: (params) => {
                const p = params[0];
                return tip`${p.name}<br><strong>${num(p.value)}</strong> ${T('requests')}`;
            }
        },
        xAxis: {
            type: 'category',
            data: perSecond.map((point) => timeOnly(new Date(point[0] * 1000).toISOString())),
            axisLine: { lineStyle: { color: theme.border } },
            axisTick: { show: false },
            axisLabel: { color: theme.axis, fontSize: 14, interval: 14 }
        },
        yAxis: {
            type: 'value',
            minInterval: 1,
            axisLine: { show: false },
            axisTick: { show: false },
            splitLine: { lineStyle: { color: theme.grid, type: 'dashed' } },
            axisLabel: { color: theme.axis, fontSize: 14, formatter: (v) => num(v) }
        },
        series: [{
            type: 'bar',
            barCategoryGap: '20%',
            data: perSecond.map((point) => point[1]),
            itemStyle: { color: theme.accent }
        }]
    }));
}

/** What the line beside the Exclusions button says. */
function noteRules() {
    const note = byId('lv-excl-note');
    if (!note) {
        return;
    }
    /* BUILT-INS COUNT, because they hide rows exactly as a typed rule does. A line reading
       "nothing is being excluded" over a stream with the asset group on would be describing a
       different page from the one on screen. */
    const on = rules.filter((rule) => rule.enabled).length + builtinOn.length;
    note.textContent = on === 0
        ? T('Nothing is being excluded.')
        : Tn('{n} rule is hiding requests.', '{n} rules are hiding requests.', on);
}

/** Read the stored rules once, so the button can say what is in force before it is pressed. */
async function loadRules() {
    try {
        const data = await api('live', 'exclusions');
        rules = Array.isArray(data.rules) ? data.rules : [];
        ruleFields = data.fields && typeof data.fields === 'object' ? data.fields : {};
        ruleMax = Number(data.max) || ruleMax;
        builtin = data.builtin && typeof data.builtin === 'object' ? data.builtin : {};
        builtinOn = Array.isArray(data.builtin_on) ? data.builtin_on : [];
        noteRules();
    } catch (err) {
        rules = [];
    }
}

/**
 * The rules dialog.
 *
 * Edits are held in the browser and written in one POST, so half a change cannot reach the
 * file: the operator adds three rules, removes one, and presses Save once. The response is the
 * list AS STORED — a pattern the server refused is simply not in it, which is how the dialog
 * shows what actually happened rather than what was typed.
 */
function openExclusions() {
    const { body, generation } = openDialog(
        T('Exclusions for this page'),
        T('Hide requests from the live stream. Nothing here changes what is stored.')
    );

    const draftRules = rules.map((rule) => ({ ...rule }));

    /* THE SWITCHES ARE DRAFTED TOO, and separately from the rules, because they are a different
       kind of thing: a rule is a row an operator writes and can delete, a switch turns a group
       on. Both are held in the browser and written in one POST, so half a change cannot reach
       the file. */
    const draftBuiltin = builtinOn.slice();

    renderExclusions(body, generation, draftRules, '', draftBuiltin);
}

/**
 * Draw the dialog's contents against the working copy.
 *
 * `note` is carried in rather than written onto the old DOM: saving re-renders this whole
 * mount, so a message set before the re-render was destroyed by it — which is why saving
 * appeared to do nothing at all.
 */
function renderExclusions(mount, generation, draft, note, draftBuiltin) {
    if (!isCurrent(generation)) {
        return;
    }

    const table = el('table', { class: 'tight table-fixed' }, [
        el('colgroup', {}, [
            el('col', { style: 'width:22%' }),
            el('col', { style: 'width:50%' }),
            el('col', { style: 'width:14%' }),
            el('col', { style: 'width:14%' })
        ]),
        el('thead', {}, [el('tr', {}, [
            el('th', { scope: 'col', text: T('Field') }),
            el('th', { scope: 'col', text: T('Pattern') }),
            el('th', { scope: 'col', text: T('On') }),
            el('th', { scope: 'col', text: '' })
        ])]),
        el('tbody', {}, draft.length
            ? draft.map((rule, i) => ruleRow(rule, i, mount, generation, draft, draftBuiltin))
            : [el('tr', {}, [el('td', {
                colspan: '4',
                class: 'muted',
                text: T('No rules yet. Everything the tail reads is shown.')
            })])])
    ]);

    const fieldSelect = el('select', { id: 'lv-new-field' },
        Object.keys(ruleFields).map((slug) => el('option', { value: slug, text: ruleFields[slug] })));

    const patternInput = el('input', {
        type: 'text',
        id: 'lv-new-pattern',
        class: 'live-find',
        placeholder: T('Regular expression, e.g. ^/wp-login'),
        autocomplete: 'off',
        spellcheck: 'false'
    });

    const addButton = el('button', { type: 'button', class: 'small', text: T('Add rule') });
    addButton.addEventListener('click', () => {
        const pattern = String(patternInput.value || '').trim();
        if (pattern === '') {
            return;
        }
        if (draft.length >= ruleMax) {
            return;
        }
        draft.push({ field: fieldSelect.value, pattern: pattern, enabled: true });
        patternInput.value = '';
        renderExclusions(mount, generation, draft, '', draftBuiltin);
    });

    const saveButton = el('button', { type: 'button', class: 'small', text: T('Save rules') });
    const status = el('span', { class: 'muted', text: note || '' });

    saveButton.addEventListener('click', async () => {
        saveButton.disabled = true;
        status.textContent = T('Saving…');
        try {
            const data = await post({
                action: 'live_exclusions',
                rules: JSON.stringify(draft),
                builtin: JSON.stringify(draftBuiltin)
            });
            builtinOn = Array.isArray(data.builtin_on) ? data.builtin_on : builtinOn;
            const refused = draft.filter((r) => String(r.pattern || '').trim() !== '').length
                - (Array.isArray(data.rules) ? data.rules.length : 0);
            rules = Array.isArray(data.rules) ? data.rules : [];
            noteRules();
            pruneExcluded();

            /* RECONNECT NOW RATHER THAN WHEN THE SERVER NEXT LETS GO. The reader reads the rules
               when a connection opens, and a connection now lives for as long as it stays healthy
               — so without this a saved rule would go on being ignored indefinitely while the
               table filled with exactly what it excluded. */
            const wasRunning = source !== null;
            if (wasRunning) {
                stop('asked');
                begin();
            }

            renderExclusions(
                mount,
                generation,
                rules.map((rule) => ({ ...rule })),
                refused > 0
                    ? (wasRunning
                        ? Tn('{n} rule was refused — a pattern PCRE will not accept. The rest were saved and applied to the stream now.',
                            '{n} rules were refused — a pattern PCRE will not accept. The rest were saved and applied to the stream now.', refused)
                        : Tn('{n} rule was refused — a pattern PCRE will not accept. The rest were saved.',
                            '{n} rules were refused — a pattern PCRE will not accept. The rest were saved.', refused))
                    : (wasRunning ? T('Saved and applied to the stream now.') : T('Saved.')),
                builtinOn.slice()
            );
        } catch (err) {
            status.textContent = err && err.message ? err.message : T('The rules could not be saved.');
        }
        saveButton.disabled = false;
    });

    /* THE READY-MADE GROUPS, ABOVE THE LIST AND NOT IN IT. Each one matches the classification
       the parser already made, so a single switch covers every image, script, stylesheet, font
       and media file — and goes on covering the next format somebody invents, which a list of
       suffixes cannot. They cannot be edited or deleted: what an operator types is always
       additional to them, never in place of them. */
    const builtinRows = Object.keys(builtin).map((slug) => {
        const spec = builtin[slug] || {};
        const box = el('input', { type: 'checkbox' });
        box.checked = draftBuiltin.indexOf(slug) !== -1;
        box.addEventListener('change', () => {
            const at = draftBuiltin.indexOf(slug);
            if (box.checked && at === -1) {
                draftBuiltin.push(slug);
            } else if (!box.checked && at !== -1) {
                draftBuiltin.splice(at, 1);
            }
        });

        return el('tr', {}, [
            el('td', {}, [box]),
            el('td', {}, [
                el('span', { text: String(spec.label || slug) }),

                /* NOT `.sub`, WHICH IS TRUNCATED INSIDE A TABLE. `table .sub` clips to one line
                   with an ellipsis, which is right for a value beside a number and wrong for a
                   sentence explaining what a switch does. A plain block says the whole thing. */
                el('p', { class: 'muted builtin-why', text: String(spec.why || '') })
            ])
        ]);
    });

    const builtinTable = el('table', { class: 'tight table-fixed' }, [
        el('colgroup', {}, [el('col', { style: 'width:8%' }), el('col', { style: 'width:92%' })]),
        el('tbody', {}, builtinRows)
    ]);

    const importFile = el('input', { type: 'file', accept: '.csv,text/csv' });
    importFile.hidden = true;
    const importButton = el('button', { type: 'button', class: 'small', text: T('Import CSV') });
    importButton.addEventListener('click', () => importFile.click());
    importFile.addEventListener('change', async () => {
        const file = importFile.files && importFile.files[0];
        if (!file) {
            return;
        }
        if (file.size > 512000) {
            status.textContent = T('That file is larger than 500 KB, which is far more than a rule list. Nothing was imported.');
            importFile.value = '';
            return;
        }
        importButton.disabled = true;
        status.textContent = T('Importing…');
        try {
            const data = await post({ action: 'live_exclusions_import', csv: await file.text() });
            builtinOn = Array.isArray(data.builtin_on) ? data.builtin_on : builtinOn;
            rules = Array.isArray(data.rules) ? data.rules : [];
            noteRules();
            pruneExcluded();

            const wasRunning = source !== null;
            if (wasRunning) {
                stop('asked');
                begin();
            }

            const refused = Number(data.refused) || 0;
            renderExclusions(
                mount,
                generation,
                rules.map((rule) => ({ ...rule })),
                T('Imported and saved; duplicates were skipped') + (refused > 0
                    ? Tn(', and {n} rule was refused', ', and {n} rules were refused', refused)
                    : '')
                + '. ' + (wasRunning
                    ? T('Unsaved edits in this dialog were replaced by the stored list, and the stream was reconnected.')
                    : T('Unsaved edits in this dialog were replaced by the stored list.')),
                builtinOn.slice()
            );
        } catch (err) {
            status.textContent = err && err.message ? err.message : T('The file could not be imported.');
            importButton.disabled = false;
            importFile.value = '';
        }
    });

    fill(mount, [
        el('p', { class: 'muted', text: T('Ready-made groups first, then your own rules underneath. Nothing here changes what is '
            + 'stored — every request hidden from this page was recorded in full and is in every '
            + 'other view.') }),
        el('div', { class: 'table-wrap' }, [builtinTable]),

        el('p', { class: 'muted' }, Tf('Your own rules. A rule is a field and a regular expression. Matching is '
            + 'case-insensitive, and the pattern is the expression itself — no slashes and no flags. '
            + '{login} hides every request whose path starts that way; {four} on Status hides every 4xx.', {
            login: el('code', { class: 'mono', text: '^/wp-login' }),
            four: el('code', { class: 'mono', text: '^4' })
        })),
        el('div', { class: 'table-wrap' }, [table]),
        el('div', { class: 'live-tools' }, [fieldSelect, patternInput, addButton]),
        el('div', { class: 'live-tools' }, [
            saveButton,
            status,
            exportLink('live', 'exclusions', T('Every rule in force, built-in and your own, as a CSV file'), {}),
            importButton,
            importFile
        ])
    ]);
}

/** One rule, with its on switch and its remove control. */
function ruleRow(rule, index, mount, generation, draft, draftBuiltin) {
    const toggle = el('input', { type: 'checkbox' });
    toggle.checked = rule.enabled !== false;
    toggle.addEventListener('change', () => {
        draft[index].enabled = toggle.checked;
    });

    const remove = el('button', { type: 'button', class: 'small', text: T('Remove') });
    remove.addEventListener('click', () => {
        draft.splice(index, 1);
        renderExclusions(mount, generation, draft, '', draftBuiltin);
    });

    /* EDITED IN PLACE, because a rule that is one character wrong is the common case and
       remove-and-retype is a poor answer to it. These are real inputs that render as plain text
       until they are hovered or focused: no click-to-swap, so the value is always selectable,
       always keyboard-reachable, and there is no second state to get stuck in. */
    const field = el('select', { class: 'rule-field' },
        Object.keys(ruleFields).map((slug) => el('option', { value: slug, text: ruleFields[slug] })));
    field.value = rule.field;
    field.addEventListener('change', () => {
        draft[index].field = field.value;
    });

    const pattern = el('input', {
        type: 'text',
        class: 'rule-pattern mono',
        value: rule.pattern,
        autocomplete: 'off',
        spellcheck: 'false',
        'aria-label': T('Pattern')
    });
    pattern.addEventListener('input', () => {
        draft[index].pattern = pattern.value;
    });

    return el('tr', {}, [
        el('td', {}, [field]),
        el('td', {}, [pattern]),
        el('td', {}, [toggle]),
        el('td', {}, [remove])
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

    const find = byId('lv-find');
    if (find) {
        find.addEventListener('input', () => {
            findText = String(find.value || '').trim().toLowerCase();
            applyFind();
        });
    }

    const exclusions = byId('lv-excl');
    if (exclusions) {
        exclusions.addEventListener('click', openExclusions);
    }

    loadRules();

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

    if (typeof window.EventSource !== 'function') {
        setState('off', T('This browser cannot hold a stream open, so there is nothing to show here.'));
        toggleLabel(T('Resume'));
        return;
    }

    if (boot.demo) {
        setState('off', T('Demo mode answers from fixtures, and there is no log file behind them.'));
        toggleLabel(T('Resume'));
        return;
    }

    begin();
}
