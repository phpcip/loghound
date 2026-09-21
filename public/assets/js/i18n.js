/*
 * Loghound — interface translation. See docs/TRANSLATING.md.
 */

'use strict';

const root = document.documentElement;
const source = root.getAttribute('data-lh-i18n');

export const locale = root.getAttribute('lang') || 'en';

async function load() {
    if (!source) {
        return {};
    }
    const ctl = typeof AbortController === 'function' ? new AbortController() : null;
    const timer = ctl ? window.setTimeout(() => ctl.abort(), 8000) : 0;
    try {
        const res = await fetch(source, { credentials: 'same-origin', signal: ctl ? ctl.signal : undefined });
        if (!res.ok) {
            return {};
        }
        const data = await res.json();
        return data && typeof data === 'object' && !Array.isArray(data) ? data : {};
    } catch (e) {
        return {};
    } finally {
        if (timer) {
            window.clearTimeout(timer);
        }
    }
}

const catalog = await load();
const own = Object.prototype.hasOwnProperty;

let rules = null;
let regions = null;

function lookup(key) {
    return own.call(catalog, key) ? catalog[key] : undefined;
}

function category(count) {
    try {
        rules = rules || new Intl.PluralRules(locale);
        return rules.select(Number(count));
    } catch (e) {
        return Number(count) === 1 ? 'one' : 'other';
    }
}

function fill(text, params) {
    if (!params) {
        return text;
    }
    return text.replace(/\{([A-Za-z0-9_]+)\}/g, (match, key) => (own.call(params, key) ? String(params[key]) : match));
}

function form(one, other, count) {
    const hit = lookup(other);
    if (typeof hit === 'string') {
        return hit;
    }
    if (hit && typeof hit === 'object') {
        const chosen = hit[category(count)];
        if (typeof chosen === 'string') {
            return chosen;
        }
        if (typeof hit.other === 'string') {
            return hit.other;
        }
    }
    return count === 1 ? one : other;
}

function parts(text, params) {
    const out = [];
    let last = 0;
    text.replace(/\{([A-Za-z0-9_]+)\}/g, (match, key, at) => {
        if (!own.call(params, key)) {
            return match;
        }
        if (at > last) {
            out.push(text.slice(last, at));
        }
        const value = params[key];
        if (value !== null && value !== undefined && value !== false && value !== '') {
            out.push(typeof value === 'object' ? value : String(value));
        }
        last = at + match.length;
        return match;
    });
    if (last < text.length) {
        out.push(text.slice(last));
    }
    return out;
}

/** Translate a string; `{name}` placeholders are filled from params. */
export function t(text, params) {
    let hit = lookup(text);
    if (hit && typeof hit === 'object') {
        hit = hit.other;
    }
    return fill(typeof hit === 'string' ? hit : text, params);
}

/** Plural: `one` and `other` are the English forms; `{n}` defaults to the count. */
export function tn(one, other, count, params) {
    return fill(form(one, other, count), Object.assign({ n: count }, params));
}

/** Translate into an array of strings and nodes, for el() children; params may be nodes. */
export function tf(text, params) {
    let hit = lookup(text);
    if (hit && typeof hit === 'object') {
        hit = hit.other;
    }
    return parts(typeof hit === 'string' ? hit : text, params || {});
}

export function tfn(one, other, count, params) {
    return parts(form(one, other, count), Object.assign({ n: count }, params));
}

/** A country's name in the interface language, from its ISO code. */
export function regionName(code, english) {
    if (!source || !/^[A-Z]{2}$/.test(String(code || ''))) {
        return english;
    }
    const custom = english ? lookup(english) : undefined;
    if (typeof custom === 'string') {
        return custom;
    }
    if (locale.split('-')[0] === 'en') {
        return english;
    }
    try {
        regions = regions || new Intl.DisplayNames([locale], { type: 'region', fallback: 'none' });
        const named = regions.of(code);
        return named || english;
    } catch (e) {
        return english;
    }
}
