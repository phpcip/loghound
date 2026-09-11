/*
 * Loghound — a path is never shown as a path alone.
 *
 * A row that reads `/ro-md/opensolr-search` is not actionable. It cannot be clicked, and on a
 * machine serving six virtual hosts it does not even say which site it belongs to. Everywhere a
 * path is rendered — Top pages, slowest paths, the Paths facet, a session trail, a recent
 * visitor, a virtual host — it is accompanied by the full URL, as a real link that opens in a
 * new tab.
 *
 * TWO AFFORDANCES, NOT ONE. The value text keeps being the control that filters the dashboard to
 * it; the full URL is a separate, smaller control at the end of the cell. They do different
 * things ("show me only this" against "take me to the page"), so each carries its own title
 * saying which. Replacing one with the other would silently take a feature away.
 *
 * THE SCHEME IS ASSUMED, NOT KNOWN. Nothing in a combined access log records it: there is no
 * scheme field on either core, `proto_s` is the HTTP version, and `tls_proto_s` is an nginx
 * variable that plain Apache never writes — so its absence proves nothing. The link is built as
 * https because that is the fail-safe direction: https pointed at an http-only site redirects or
 * fails visibly, while http pointed at an https site is a silent downgrade. Every link says so in
 * its own title rather than presenting the scheme as a fact.
 *
 * THE HOST AND THE PATH BOTH COME OFF THE WIRE. A request line is attacker-chosen and so is a
 * Host header, and this module's output goes into an href, which is a sink. core.js's el() sets
 * href with setAttribute and sanitises nothing, so the sanitising is here:
 *
 *   - the URL is composed from a host and a path, never from a pre-joined string somebody else
 *     built, so there is no string in which a scheme or an authority could already be hiding;
 *   - a host must be a plain hostname, an IPv4 address or a bracketed IPv6 literal, with an
 *     optional numeric port and nothing else — `@`, `/`, `\`, `?`, `#`, a colon that is not a
 *     port, whitespace, a control character or anything non-ASCII is refused outright;
 *   - a path is stripped of every leading `/` and `\` and given exactly one `/` back, which is
 *     what defeats `//evil.com` and `\/evil.com`, and is then percent-encoded without
 *     double-encoding what was already an escape;
 *   - the composed string is parsed back with URL() and refused unless it really is https, on
 *     the host asked for, with no userinfo.
 *
 * Anything that fails returns null and the caller renders plain text. A dead `href="#"` is a
 * control that lies about what pressing it will do, which is the one thing worse than no control.
 *
 * WHY THIS FILE IMPORTS NOTHING BUT core.js. facetfilter.js renders path values and therefore
 * depends on this module, so this module must not depend on facetfilter.js — hence the small
 * local read of the host filter out of the query string rather than a call into readSelection().
 * The parameter contract it mirrors is facetfilter.js's, which mirrors Panel\Facets::urlFor().
 */

'use strict';

import { el } from './core.js';

/** The scheme every link is built with, and the sentence that admits it is an assumption. */
export const SCHEME = 'https://';

/** Said in the title of every external link, so the assumption is never presented as a fact. */
export const SCHEME_NOTE = 'Nothing in an access log records whether the request was http or '
    + 'https, so this link assumes https.';

/** The filter parameter prefix, and the field the host filter lives on. */
const FILTER_NS = 'f';
const HOST_FIELD = 'host_s';

/** Solr fields that hold a site path rather than, say, a Solr request handler. */
const PATH_FIELDS = ['paths_ss', 'path_s', 'entry_path_s', 'exit_path_s'];

/** A registrable hostname: dot-separated labels of letters, digits and inner hyphens. */
const HOST_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;

/** A bracketed IPv6 literal, as a Host header spells one. */
const HOST_V6 = /^\[[0-9A-Fa-f:.]{2,45}\]$/;

/** A port is digits and nothing else — no empty port, no name, no expression. */
const PORT = /^[0-9]{1,5}$/;

/** Characters that may stand unescaped in a path segment. Note the absence of ' " < > \ and %. */
const PATH_SAFE = /^[A-Za-z0-9\-._~!$&()*+,;=:@/]$/;

/** The same, for a query string, which additionally tolerates ?. */
const QUERY_SAFE = /^[A-Za-z0-9\-._~!$&()*+,;=:@/?]$/;

/**
 * Characters encodeURIComponent() refuses to escape, spelled out.
 *
 * It leaves `!'()*~-._` alone. All but the apostrophe are in the safe sets above and never reach
 * it; the apostrophe is not, precisely because it must not survive into an href, so it would come
 * back unescaped and the finished URL would then be thrown away by HOSTILE — a legitimate path
 * with an apostrophe in it silently losing its link.
 */
const FORCED = { "'": '%27' };

/** An escape that is already well formed and must not be escaped a second time. */
const ESCAPED = /^%[0-9A-Fa-f]{2}$/;

/** Refused anywhere in a finished URL: a URL with one of these in it was not built here. */
const HOSTILE = /[\u0000-\u0020\u007F"'<>\\^`{}|]/;

/**
 * The virtual hosts this installation has, or null while that is still unknown.
 *
 * Filled by views/hosts.js from the host list it already fetches on every page. Null and empty
 * are different: null means "not answered yet" and is what the deferred upgrade below waits on.
 *
 * @type {Array<string>|null}
 */
let installHosts = null;

/**
 * Marks rendered before the host list arrived, so they can become links when it does.
 *
 * The list is only ever appended to while `installHosts` is null, and is emptied for good the
 * first time noteHosts() is called, so it cannot grow with the page.
 *
 * @type {Array<{wrap: Node, path: string, options: Object}>}
 */
const pending = [];

/* -------------------------------------------------------------------------
 * Sanitising
 * ---------------------------------------------------------------------- */

/**
 * Validate a host for use as the authority of a URL, returning it or null.
 *
 * Everything outside printable ASCII is refused before anything is parsed, which disposes of NUL,
 * tab, CR, LF and space in one test. A punycode host passes; an IDN in its unicode spelling does
 * not, and that is deliberate — an access log records the ASCII form, and a lookalike label is
 * exactly the thing that must never be turned into a live link on somebody's say-so.
 *
 * @param {string} host
 * @returns {string|null}
 */
export function safeHost(host) {
    const raw = host === null || host === undefined ? '' : String(host);
    if (raw === '' || raw.length > 255 || /[^\x21-\x7E]/.test(raw)) {
        return null;
    }

    if (raw.charAt(0) === '[') {
        const close = raw.indexOf(']');
        if (close < 0) {
            return null;
        }
        const literal = raw.slice(0, close + 1);
        const rest = raw.slice(close + 1);
        if (!HOST_V6.test(literal)) {
            return null;
        }
        if (rest === '') {
            return literal;
        }
        return rest.charAt(0) === ':' && PORT.test(rest.slice(1)) ? literal + rest : null;
    }

    const colon = raw.indexOf(':');
    const name = colon < 0 ? raw : raw.slice(0, colon);
    const port = colon < 0 ? '' : raw.slice(colon + 1);
    if (!HOST_NAME.test(name)) {
        return null;
    }
    if (colon < 0) {
        return name;
    }
    return PORT.test(port) ? name + ':' + port : null;
}

/**
 * Percent-encode one component, leaving well-formed escapes alone.
 *
 * Iterated by code point rather than by UTF-16 unit, so an astral character is encoded as the one
 * character it is. A lone surrogate cannot be encoded at all and takes the whole component down to
 * null, because a half character in a URL is not something to guess at.
 *
 * @param {string} value
 * @param {RegExp} keep Characters that may stand as themselves.
 * @returns {string|null}
 */
function encodeComponent(value, keep) {
    const chars = Array.from(value);
    let out = '';

    for (let i = 0; i < chars.length; i++) {
        const ch = chars[i];
        if (ch === '%' && ESCAPED.test(chars.slice(i, i + 3).join(''))) {
            out += chars[i] + chars[i + 1] + chars[i + 2];
            i += 2;
            continue;
        }
        if (keep.test(ch)) {
            out += ch;
            continue;
        }
        if (Object.prototype.hasOwnProperty.call(FORCED, ch)) {
            out += FORCED[ch];
            continue;
        }
        try {
            out += encodeURIComponent(ch);
        } catch (err) {
            return null;
        }
    }
    return out;
}

/**
 * Normalise a request path into something that can only ever be a path.
 *
 * EVERY leading slash and backslash is removed and exactly one slash is put back. That single
 * step is what makes `//evil.com`, `\\/evil.com` and `/\/evil.com` resolve to a path on the host
 * this link is for rather than to an authority of the attacker's choosing.
 *
 * @param {string} path
 * @returns {string|null}
 */
export function safePath(path) {
    const raw = path === null || path === undefined ? '' : String(path);
    if (/[\u0000-\u001F\u007F]/.test(raw)) {
        return null;
    }

    let rest = raw;
    while (rest.charAt(0) === '/' || rest.charAt(0) === '\\') {
        rest = rest.slice(1);
    }

    const encoded = encodeComponent(rest, PATH_SAFE);
    return encoded === null ? null : '/' + encoded;
}

/**
 * Normalise a stored query string, or null if it cannot be made safe.
 *
 * @param {string} query Without its leading `?`, which is how `query_s` stores it.
 * @returns {string|null}
 */
export function safeQuery(query) {
    const raw = query === null || query === undefined ? '' : String(query);
    if (raw === '') {
        return '';
    }
    if (/[\u0000-\u001F\u007F]/.test(raw)) {
        return null;
    }
    const encoded = encodeComponent(raw.charAt(0) === '?' ? raw.slice(1) : raw, QUERY_SAFE);
    return encoded === null ? null : '?' + encoded;
}

/**
 * The full URL for a host and a path, or null if one cannot honestly be built.
 *
 * The last two steps are the ones that matter. The composed string is parsed back with URL() and
 * refused unless the browser agrees it is https, on the host that was asked for, carrying no
 * username and no password — so any construction that smuggled an authority past the character
 * rules is caught by the parser that will actually follow the link. Then the finished string is
 * swept once more for anything that could break out of an attribute.
 *
 * @param {string} host
 * @param {string} path
 * @param {string} [query] Query string, with or without its leading `?`.
 * @returns {string|null}
 */
export function siteUrl(host, path, query) {
    const safeH = safeHost(host);
    const safeP = safePath(path);
    const safeQ = safeQuery(query);
    if (safeH === null || safeP === null || safeQ === null) {
        return null;
    }

    const composed = SCHEME + safeH + safeP + safeQ;
    if (HOSTILE.test(composed)) {
        return null;
    }

    try {
        const parsed = new URL(composed);
        if (parsed.protocol !== 'https:' || parsed.username !== '' || parsed.password !== '') {
            return null;
        }
        if (parsed.host !== safeH.toLowerCase()) {
            return null;
        }
    } catch (err) {
        return null;
    }

    return composed;
}

/* -------------------------------------------------------------------------
 * Which host a row belongs to
 * ---------------------------------------------------------------------- */

/** Is this dimension a site path, as opposed to a Solr request handler? */
export function isPathField(field) {
    return PATH_FIELDS.indexOf(String(field)) >= 0;
}

/**
 * The one host the whole dashboard is currently scoped to, or null.
 *
 * Exactly one selected value and an operator that is not "None of": two hosts scope to two, and
 * an exclusion scopes to everything except one, neither of which names a host a row belongs to.
 *
 * @returns {string|null}
 */
export function scopeHost() {
    const params = new URLSearchParams(window.location.search);
    const values = params.getAll(FILTER_NS + '[' + HOST_FIELD + '][]').filter((v) => v !== '');
    if (values.length !== 1) {
        return null;
    }
    if (params.get(FILTER_NS + '[' + HOST_FIELD + '][op]') === 'none') {
        return null;
    }
    return values[0];
}

/**
 * Record the virtual hosts this installation serves.
 *
 * Called once per page by views/hosts.js, which fetches the list anyway for the host selector.
 * Anything already rendered as ambiguous is revisited: on a single-host install every path on the
 * page becomes a link the moment the list lands, without a second request and without any view
 * knowing this happens.
 *
 * @param {Array<string>} list
 */
export function noteHosts(list) {
    installHosts = Array.isArray(list) ? list.map(String).filter((h) => h !== '') : [];
    while (pending.length) {
        upgrade(pending.shift());
    }
}

/** The single virtual host of a single-host installation, or null. */
export function soleHost() {
    return installHosts !== null && installHosts.length === 1 ? installHosts[0] : null;
}

/**
 * Which host a row's path belongs to, and how many it might belong to instead.
 *
 * In order: the host on the row itself, then the count the server resolved (more than one and
 * there is no answer to give), then the host of the session or dialog in scope, then the single
 * active host filter, then the installation's only host.
 *
 * NEVER THE MOST COMMON ONE. When none of those answer, the result is ambiguous and stays
 * ambiguous; picking a plausible host would produce a link that goes somewhere real and wrong,
 * which is worse than no link at all.
 *
 * @param {Object} row {host, hosts, fallback}
 * @returns {{host: string|null, count: number|null}}
 */
export function resolveHost(row) {
    const source = row || {};
    const own = source.host === null || source.host === undefined ? '' : String(source.host);
    const count = typeof source.hosts === 'number' ? source.hosts : null;

    if (own !== '') {
        return { host: own, count: 1 };
    }
    if (count !== null && count > 1) {
        return { host: null, count: count };
    }

    const fallback = source.fallback === null || source.fallback === undefined ? '' : String(source.fallback);
    if (fallback !== '') {
        return { host: fallback, count: 1 };
    }

    const scoped = scopeHost();
    if (scoped !== null) {
        return { host: scoped, count: 1 };
    }

    const sole = soleHost();
    if (sole !== null) {
        return { host: sole, count: 1 };
    }

    return { host: null, count: count };
}

/* -------------------------------------------------------------------------
 * Rendering
 * ---------------------------------------------------------------------- */

/**
 * The "open in a new tab" control, or null when no URL can be built.
 *
 * `target="_blank"` with `rel="noopener noreferrer"`, always and without exception: the
 * destination is a site this panel is merely reporting on, and it gets neither a handle on the
 * panel's window nor the panel's URL in its referer.
 *
 * The glyph is aria-hidden and the anchor carries its own accessible name, so a screen reader
 * hears the destination rather than an arrow.
 *
 * @param {string} host
 * @param {string} path
 * @param {string} [query]
 * @returns {HTMLElement|null}
 */
export function outLink(host, path, query) {
    const url = siteUrl(host, path, query);
    if (url === null) {
        return null;
    }
    return el('a', {
        class: 'urlout',
        href: url,
        target: '_blank',
        rel: 'noopener noreferrer',
        title: 'Open ' + url + ' in a new tab. ' + SCHEME_NOTE,
        'aria-label': 'Open ' + url + ' in a new tab'
    }, [el('span', { class: 'urlout-mark', 'aria-hidden': 'true', text: '↗' })]);
}

/**
 * The marker that stands where a link cannot: a path that belongs to more than one site.
 *
 * It says so rather than staying silent, because silence reads as "this path has no page" when
 * what it means is "this installation serves several sites and the panel will not guess between
 * them". The title says how to make the link appear, which is one click on the host filter.
 *
 * @param {number|null} count Hosts the path was seen on, when the server counted them.
 */
export function ambiguityMark(count) {
    const many = typeof count === 'number' && count > 1;
    const none = count === 0;

    const text = many ? count + ' hosts' : (none ? 'no host logged' : 'several hosts');

    let why;
    if (none) {
        why = 'No virtual host was recorded for this path, so there is no URL to link to. An access '
            + 'log that does not record %v cannot say which of this machine\'s sites a request went to.';
    } else if (many) {
        why = 'This path was requested on ' + count + ' virtual hosts, so no single URL can be linked. '
            + 'Filter to one host and the link appears.';
    } else {
        why = 'This installation serves more than one virtual host and this list does not say which of '
            + 'them the path belongs to, so no single URL can be linked. Filter to one host and the '
            + 'link appears.';
    }

    return el('span', { class: 'urlamb', text: text, title: why });
}

/**
 * The affordance that belongs beside a path: a link when there is one, a marker when there is not.
 *
 * A node is always returned, so a path is never rendered bare. When the host list has not arrived
 * yet the marker is registered for upgrade, and noteHosts() turns it into a link if the answer
 * turns out to be a single-host installation.
 *
 * @param {string} path
 * @param {Object} [opts] {host, hosts, fallback, query}
 * @returns {HTMLElement}
 */
export function urlMark(path, opts) {
    const options = opts || {};
    const seen = resolveHost(options);
    const link = seen.host === null ? null : outLink(seen.host, path, options.query);

    if (link !== null) {
        return link;
    }

    const mark = ambiguityMark(seen.count);
    if (installHosts === null) {
        pending.push({ wrap: mark, path: String(path === null || path === undefined ? '' : path), options: options });
    }
    return mark;
}

/**
 * Replace a deferred ambiguity marker with the link the host list made possible.
 *
 * A marker whose card has since been re-rendered has no parent and is simply dropped.
 *
 * @param {{wrap: Node, path: string, options: Object}} job
 */
function upgrade(job) {
    const parent = job.wrap.parentNode;
    if (parent === null) {
        return;
    }
    const seen = resolveHost(job.options);
    if (seen.host === null) {
        return;
    }
    const link = outLink(seen.host, job.path, job.options.query);
    if (link !== null) {
        parent.replaceChild(link, job.wrap);
    }
}

/**
 * A whole table cell: the path, truncated if it must be, with its affordance pinned beside it.
 *
 * The affordance is a flex item that never shrinks, so the ellipsis eats the path and never the
 * control — which is the failure a plain `text-overflow` on the cell produces, and it hides the
 * one thing this change exists to add.
 *
 * @param {string} path
 * @param {Object} [opts] {host, hosts, fallback, query, mono, text}
 * @returns {HTMLElement}
 */
export function pathCell(path, opts) {
    const options = opts || {};
    const raw = path === null || path === undefined ? '' : String(path);
    const shown = options.text === undefined || options.text === null ? raw : String(options.text);
    const classes = 'urlpath' + (options.mono === false ? '' : ' mono');

    return el('span', { class: 'urlwrap' }, [
        el('span', { class: classes, text: shown === '' ? '—' : shown }),
        urlMark(raw, options)
    ]);
}
