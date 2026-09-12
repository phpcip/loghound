/*
 * Loghound — every dropdown in the panel, made searchable.
 *
 * THE PROBLEM. A native <select> is fine at six options and useless at sixty. The panel has
 * both: "Duration" is eight, the virtual-host selector on a busy machine is dozens, the index
 * picker is however many indexes an account owns, and the display timezone is the whole IANA
 * database. On the long ones the operator's only tools are scrolling and the browser's
 * type-to-jump, which matches from the START of an option and therefore cannot find
 * "Europe/Bucharest" from "buch".
 *
 * WHAT THIS IS. One behaviour for all of them: press it and every option is listed; type and
 * the list narrows on a substring. Nothing is hidden behind the typing — the full list is what
 * opens — so a reader who does not know what they are looking for still sees everything, which
 * is the property a plain autocomplete throws away.
 *
 * ---------------------------------------------------------------------------------
 * THE NATIVE <select> IS STILL THE STATE
 * ---------------------------------------------------------------------------------
 * It stays in the document, in its form, with its name and its value. This draws a control
 * beside it and writes the operator's choice back into it, then fires `change` exactly as the
 * browser would. That is what makes the enhancement free everywhere it is applied:
 *
 *   - a GET form submits the same parameters it always did, so the top bar works with
 *     scripting off and the server sees one shape of request either way;
 *   - every existing `change` listener in the panel keeps working, and none of them had to
 *     learn about this file;
 *   - a select whose options arrive later — the host list, the index list, the region list —
 *     is re-read rather than rebuilt, because the observer below watches the real element.
 *
 * ---------------------------------------------------------------------------------
 * APPLIED BY OBSERVATION, NOT BY A LIST
 * ---------------------------------------------------------------------------------
 * Every <select> on the page is enhanced, and the document is watched for more. A list of ids
 * would be a list to forget an entry from, and half the selects in this panel are injected by a
 * fetch that has no idea this module exists.
 *
 * `data-free="1"` marks the one field where a value the list does not contain is legitimate —
 * the Opensolr region, whose list may be unavailable — and typing one there keeps it. Every
 * other select is a closed set and typing something unknown selects nothing, which is the
 * honest behaviour for a closed set.
 *
 * No innerHTML anywhere: an option's text can be a virtual host, an index name or an AS
 * organisation, and all three are chosen by somebody else.
 */

'use strict';

import { el } from './core.js';

/** Marks a select this module has already taken over, so a re-scan is idempotent. */
const DONE = 'lhSmart';

/** The open control, if any. One at a time: two open popups is never the right answer. */
let openOne = null;

/**
 * Is this a select worth taking over?
 *
 * A multiple-choice or list-box select is a different control with different semantics, and
 * neither exists in the panel — refusing them here means one cannot be quietly broken by
 * arriving later.
 */
function eligible(select) {
    return select instanceof HTMLSelectElement
        && !select.multiple
        && (!select.size || select.size <= 1)
        && !select.dataset[DONE];
}

/** The words shown on the closed control for the current value. */
function currentText(select) {
    const option = select.options[select.selectedIndex];
    return option ? (option.textContent || '').trim() : '';
}

/** The accessible name: the author's `data-smart`, else the label that points at it. */
function nameOf(select) {
    if (select.dataset.smart) {
        return select.dataset.smart;
    }
    const label = select.id ? document.querySelector('label[for="' + CSS.escape(select.id) + '"]') : null;
    return label ? (label.textContent || '').trim() : 'Choose';
}

/**
 * Build the control for one select.
 *
 * The native element is left in the DOM and taken out of the tab order and the accessibility
 * tree: it is the value store, and a second focusable copy of the same control is a keyboard
 * trap waiting to happen. It is NOT `display: none` — a hidden form control is still submitted,
 * which is exactly what is wanted, and `.ss-native` in the stylesheet is what keeps it off
 * screen without taking it out of the form.
 */
function enhance(select) {
    if (!eligible(select)) {
        return;
    }
    select.dataset[DONE] = '1';
    select.classList.add('ss-native');
    select.setAttribute('tabindex', '-1');
    select.setAttribute('aria-hidden', 'true');

    const value = el('span', { class: 'ss-value', text: currentText(select) });
    const button = el('button', {
        type: 'button',
        class: 'ss-button',
        'aria-haspopup': 'listbox',
        'aria-expanded': 'false',
        'aria-label': nameOf(select)
    }, [value, el('span', { class: 'ss-caret', 'aria-hidden': 'true' })]);

    const search = el('input', {
        type: 'text',
        class: 'ss-search',
        autocomplete: 'off',
        spellcheck: 'false',
        'aria-label': 'Filter ' + nameOf(select)
    });
    const list = el('ul', { class: 'ss-list', role: 'listbox', 'aria-label': nameOf(select) });
    const none = el('p', { class: 'ss-none muted', text: 'Nothing matches.', hidden: true });
    const pop = el('div', { class: 'ss-pop', hidden: true }, [search, list, none]);

    const root = el('div', { class: 'ss', dataset: { for: select.id || '' } }, [button, pop]);
    select.parentNode.insertBefore(root, select);
    root.insertBefore(select, root.firstChild);

    const state = {
        select: select,
        root: root,
        button: button,
        value: value,
        search: search,
        list: list,
        none: none,
        pop: pop,
        free: select.dataset.free === '1'
    };

    button.addEventListener('click', () => (openOne === state ? close(state) : open(state)));
    button.addEventListener('keydown', (event) => {
        if (event.key === 'ArrowDown' || event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            open(state);
        }
    });
    search.addEventListener('input', () => paint(state));
    search.addEventListener('keydown', (event) => onSearchKey(state, event));
    list.addEventListener('click', (event) => {
        const row = event.target && event.target.closest ? event.target.closest('[data-value]') : null;
        if (row) {
            choose(state, row.dataset.value);
        }
    });

    /* THE OPTIONS ARE NOT COPIED, THEY ARE READ. Three selects in this panel are filled by a
       fetch that lands after this ran — the hosts, the account's indexes, the account's regions
       — and one of them is refilled on every change. Watching the real element means none of
       those owners has to announce anything, and the closed control's words follow the value
       even when something else sets it programmatically. */
    new MutationObserver(() => sync(state)).observe(select, { childList: true, subtree: true });
    select.addEventListener('change', () => sync(state));
}

/** Put the native select's current value back on the face of the control. */
function sync(state) {
    state.value.textContent = currentText(state.select);
    if (openOne === state) {
        paint(state);
    }
}

/**
 * Put the popup against its button, in viewport coordinates.
 *
 * WHY FIXED RATHER THAN ABSOLUTE. An absolutely positioned panel is clipped by any ancestor
 * that scrolls, and the panel has two of them: a dialog body and a horizontally scrolling
 * table. Inside the exclusions dialog that meant the list opened, was cut off at the dialog
 * edge, and looked like a search box with no options under it at all.
 *
 * IT FLIPS WHEN THERE IS NO ROOM BELOW. A list that opens downward off the bottom of the
 * window is the same defect in a different direction, and a control near the foot of a dialog
 * is exactly where the last rule sits.
 */
function place(state) {
    const box = state.button.getBoundingClientRect();
    const room = document.documentElement.clientHeight - box.bottom;
    const pop = state.pop;

    pop.style.left = box.left + 'px';
    pop.style.minWidth = box.width + 'px';

    if (room < 260 && box.top > room) {
        pop.style.top = '';
        pop.style.bottom = (document.documentElement.clientHeight - box.top + 4) + 'px';
        pop.style.maxHeight = (box.top - 12) + 'px';
    } else {
        pop.style.bottom = '';
        pop.style.top = (box.bottom + 4) + 'px';
        pop.style.maxHeight = (room - 12) + 'px';
    }
}

/** Keep an open popup against its button while the page moves under it. */
function follow() {
    if (openOne) {
        place(openOne);
    }
}

/** Open the popup with the whole list, whatever was typed last time. */
function open(state) {
    if (openOne && openOne !== state) {
        close(openOne);
    }
    openOne = state;
    state.search.value = '';
    state.pop.hidden = false;
    state.button.setAttribute('aria-expanded', 'true');
    paint(state);
    place(state);
    window.addEventListener('scroll', follow, true);
    window.addEventListener('resize', follow);
    state.search.focus();
}

/** Shut it, and put focus back on the control that opened it. */
function close(state, refocus) {
    state.pop.hidden = true;
    state.button.setAttribute('aria-expanded', 'false');
    if (openOne === state) {
        openOne = null;
        window.removeEventListener('scroll', follow, true);
        window.removeEventListener('resize', follow);
    }
    if (refocus !== false) {
        state.button.focus();
    }
}

/**
 * Draw the list of options that match what has been typed.
 *
 * A SUBSTRING MATCH, case-insensitively, against the words on screen AND against the stored
 * value. The two differ where it matters — the host selector shows `example.com (1,204)` and
 * stores `example.com`, the duration shows `24H` and stores `24h` — and matching only the
 * display text would make a pasted value fail to find itself.
 */
function paint(state) {
    const needle = state.search.value.trim().toLowerCase();
    const current = state.select.value;

    while (state.list.firstChild) {
        state.list.removeChild(state.list.firstChild);
    }

    let shown = 0;
    for (const option of state.select.options) {
        const text = (option.textContent || '').trim();
        if (needle !== ''
            && text.toLowerCase().indexOf(needle) < 0
            && String(option.value).toLowerCase().indexOf(needle) < 0) {
            continue;
        }
        shown += 1;
        const on = option.value === current;
        state.list.appendChild(el('li', {
            class: 'ss-opt' + (on ? ' is-on' : ''),
            role: 'option',
            'aria-selected': on ? 'true' : 'false',
            tabindex: '-1',
            dataset: { value: option.value },
            text: text === '' ? option.value : text
        }));
    }

    state.none.hidden = shown > 0;
}

/**
 * Keyboard inside the search box.
 *
 * Enter takes the first match, which is what makes the control fast: type three letters, press
 * Enter. On a `data-free` select with no match it takes the typed text instead, because that is
 * the whole reason such a select is marked free.
 */
function onSearchKey(state, event) {
    if (event.key === 'Escape') {
        event.preventDefault();
        close(state);
        return;
    }
    if (event.key === 'ArrowDown') {
        event.preventDefault();
        const first = state.list.querySelector('.ss-opt');
        if (first) {
            first.focus();
        }
        return;
    }
    if (event.key !== 'Enter') {
        return;
    }

    event.preventDefault();
    const first = state.list.querySelector('.ss-opt');
    if (first) {
        choose(state, first.dataset.value);
        return;
    }
    const typed = state.search.value.trim();
    if (state.free && typed !== '') {
        choose(state, typed);
    }
}

/**
 * Write a choice into the native select and tell everybody who was already listening.
 *
 * A `data-free` select accepts a value it has never heard of by growing an option for it, so
 * the element's value is always one of its own options — a select whose `.value` is a string it
 * has no option for reads back as the empty string, which would turn a typed region into a
 * cleared one.
 *
 * The event is dispatched with `bubbles: true` because delegated listeners are how the rest of
 * this front end is wired, and a non-bubbling change would reach none of them.
 */
function choose(state, value) {
    const select = state.select;
    const known = Array.prototype.some.call(select.options, (option) => option.value === value);

    if (!known) {
        if (!state.free) {
            return;
        }
        select.appendChild(el('option', { value: value, text: value }));
    }

    select.value = value;
    sync(state);
    close(state);
    select.dispatchEvent(new Event('change', { bubbles: true }));
}

/**
 * Keyboard on a row of the list.
 *
 * Delegated to the document because rows are rebuilt on every keystroke, so a listener per row
 * would be a listener per keystroke per option.
 */
function onListKey(event) {
    const row = event.target && event.target.closest ? event.target.closest('.ss-opt') : null;
    if (!row || !openOne) {
        return;
    }

    if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        choose(openOne, row.dataset.value);
        return;
    }
    if (event.key === 'Escape') {
        event.preventDefault();
        close(openOne);
        return;
    }
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault();
        const next = event.key === 'ArrowDown' ? row.nextElementSibling : row.previousElementSibling;
        if (next) {
            next.focus();
        } else if (event.key === 'ArrowUp') {
            openOne.search.focus();
        }
    }
}

/**
 * Enhance every select on the page, and every one that arrives later.
 *
 * Safe to call more than once: `eligible()` refuses a select that has already been taken over,
 * so a second call costs one dataset read per select and changes nothing.
 */
export function initSmartSelects() {
    for (const select of document.querySelectorAll('select')) {
        enhance(select);
    }

    new MutationObserver((records) => {
        for (const record of records) {
            for (const node of record.addedNodes) {
                if (node.nodeType !== 1) {
                    continue;
                }
                if (node.tagName === 'SELECT') {
                    enhance(node);
                }
                for (const select of node.querySelectorAll ? node.querySelectorAll('select') : []) {
                    enhance(select);
                }
            }
        }
    }).observe(document.body, { childList: true, subtree: true });

    /* CLICKING ANYWHERE ELSE SHUTS IT, which is what every menu on every platform does, and
       without it the popup would be dismissible only by pressing the control again. Focus is not
       taken back in that case: the operator has already pressed something else, and pulling
       focus away from it would be the control arguing with them. */
    document.addEventListener('click', (event) => {
        if (openOne && !openOne.root.contains(event.target)) {
            close(openOne, false);
        }
    });
    document.addEventListener('keydown', onListKey);
}
