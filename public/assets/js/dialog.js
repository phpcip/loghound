/*
 * Loghound — the shared detail dialog, and the one delegated listener that opens it.
 *
 * WHY THIS IS ITS OWN FILE. Every table in the panel wants the same thing: a row names
 * something, and clicking it should open the whole record. Writing that seven times would
 * produce seven dialogs with seven focus bugs, so there is one here and every view adopts
 * it. It is deliberately free of any knowledge of sessions, paths or networks: a view
 * registers an opener for a kind of subject and the dialog knows nothing else.
 *
 * THE CSP. The panel's script-src is 'self' with no 'unsafe-inline', so there is no inline
 * handler, no onclick attribute and no javascript: href anywhere in here. Rows advertise
 * themselves with data attributes and ONE listener on the document dispatches them, which
 * also means a table re-rendered by fetch() needs no re-wiring.
 *
 * EVERYTHING A VIEW PUTS IN THE BODY CAME OFF THE WIRE. The dialog itself sets textContent
 * and never innerHTML, and the openers are held to the same rule by core.js's el().
 *
 * A LINK INSIDE A CLICKABLE ROW WINS, AND THAT IS WHY EVERY ROW ALSO HAS A CONTROL. A value
 * in a cell is a real <a href> that filters the dashboard to it, so a click on the value must
 * navigate rather than open the dialog. Once the identity cells carry two lines of values
 * each, most of a row's surface is link, and a reader aiming at "the row" hits one and the
 * dialog appears not to open at all. The rule stays — a link that did not navigate would be a
 * worse surprise — and every drillable row carries an explicit opener at its end instead, so
 * there is always somewhere to press that is unambiguously "open this record".
 *
 * ACCESSIBILITY, because a modal that traps a keyboard user is worse than no modal:
 * aria-modal with a labelled heading, focus moved into the panel on open, Tab cycling kept
 * inside it while it is open, Escape and the scrim both close it, and focus returned to the
 * element that opened it.
 */

'use strict';

import { byId, el, fill } from './core.js';

/** Subject kind → opener. A view registers what it knows how to open. */
const openers = new Map();

/**
 * The dialogs that are conceptually open, outermost first. One SHELL, a stack of SUBJECTS.
 *
 * WHAT NESTING MEANS HERE, decided rather than left ambiguous: **a dialog opened from inside a
 * dialog replaces it on screen, and closing returns to the one underneath.** There is still
 * exactly one shell and never two modals stacked visually — that part of the original design
 * was right and is unchanged. What was missing is that the drill-down had no way back: a row
 * inside the "Recent visitors" table of a bot-class dialog opens a session, and the operator
 * who wanted a glance at that visitor had no route back to the class they were reading.
 *
 * The alternative — Close always exits to the page — was considered and rejected. It is one
 * gesture rather than two, but it silently discards a step the operator took deliberately, and
 * "the way out is also the way back" is the behaviour every drill-down in this panel already
 * has in the URL. Returning to the parent costs one refetch, of a query the server caches.
 *
 * Each frame carries the element that opened it, so focus goes back to a real node in BOTH
 * directions, and the thunk that re-opens it, so the parent can be rebuilt when its child is
 * closed. A frame whose `reopen` is null is an outermost dialog opened straight from code.
 *
 * @type {Array<{opener: (HTMLElement|null), reopen: (function(): (void|Promise<void>)|null)}>}
 */
const stack = [];

/**
 * How deep the drill-down may go before a new subject replaces the top instead of pushing.
 *
 * A person drills two levels, occasionally three. An unbounded stack is not a feature anybody
 * asked for; it is a way for a loop in the data — a value whose dialog lists a row that opens
 * the same value — to build a chain nobody can close.
 */
const MAX_DEPTH = 4;

/** Incremented on every open, so a slow fetch for a dismissed dialog renders nothing. */
let generation = 0;

/**
 * Register an opener for a kind of subject.
 *
 * The opener receives the row's own dataset (a plain object of the data- attributes) and is
 * responsible for calling openDialog() and filling the body. It is async: the dialog is
 * expected to appear immediately and fill in when the request lands.
 *
 * @param {string} kind
 * @param {function(Object): (void|Promise<void>)} fn
 */
export function registerOpener(kind, fn) {
    openers.set(String(kind), fn);
}

/**
 * Build the dialog element once and keep it.
 *
 * Created lazily rather than emitted by every view's body(), because it is a control and
 * not content: a view that never opens one should not carry its markup.
 */
function ensureDialog() {
    let root = byId('lh-dialog');
    if (root) {
        return root;
    }

    const title = el('h2', { id: 'lh-dialog-title' });
    const sub = el('p', { class: 'muted', id: 'lh-dialog-sub' });
    const close = el('button', { type: 'button', class: 'ghost small', id: 'lh-dialog-close', text: 'Close' });
    const body = el('div', { class: 'lh-dialog-body', id: 'lh-dialog-body', tabindex: '-1' });

    const panel = el('div', {
        class: 'lh-dialog-panel',
        role: 'dialog',
        'aria-modal': 'true',
        'aria-labelledby': 'lh-dialog-title'
    }, [
        el('div', { class: 'lh-dialog-head' }, [el('div', {}, [title, sub]), close]),
        body
    ]);

    const scrim = el('div', { class: 'lh-dialog-scrim' });
    root = el('div', { class: 'lh-dialog', id: 'lh-dialog', hidden: true }, [scrim, panel]);

    close.addEventListener('click', closeDialog);
    scrim.addEventListener('click', closeDialog);
    panel.addEventListener('keydown', onPanelKey);

    document.body.appendChild(root);
    return root;
}

/**
 * Make everything except the dialog unreachable while it is open, and give it back on close.
 *
 * `inert` removes a subtree from the tab order, from hit testing and from the accessibility
 * tree in one attribute — which is the whole of what "modal" means and what `aria-modal` only
 * PROMISES. Without it the page behind the scrim stayed fully tabbable and fully announced, so
 * a keyboard user who left the trap (see onPanelKey) landed on live controls they could not
 * see, and a screen-reader user could read the entire page underneath.
 *
 * Applied to the dialog's siblings rather than to <main>, so the sidebar and anything else a
 * view appends to <body> are covered too.
 */
function setBackgroundInert(on) {
    const root = byId('lh-dialog');
    for (const node of document.body.children) {
        if (node === root) {
            continue;
        }
        if (on) {
            node.setAttribute('inert', '');
        } else {
            node.removeAttribute('inert');
        }
    }
}

/**
 * Keep Tab inside the panel, and let Escape out.
 *
 * The focusable set is recomputed on every Tab rather than cached, because the body's
 * contents arrive after the dialog opens and a cached list would send Tab to a node that
 * has been replaced.
 */
function onPanelKey(event) {
    if (event.key !== 'Tab') {
        return;
    }
    const panel = event.currentTarget;

    /* TABBABLE, NOT MERELY FOCUSABLE. The selector used to end in a bare `[tabindex]`, which
       matched the dialog body — created with `tabindex="-1"` so it can take focus on open but
       never be tabbed to. That put a non-tabbable node at the END of the list, so `last` was
       something Tab would never land on: the "wrap back to the top" branch never fired, the
       browser's own Tab skipped the body, and focus left the modal for the page behind it. On
       a freshly opened dialog, whose body is the word "Loading…" and nothing else, that was
       every single time. */
    const focusable = Array.prototype.filter.call(
        panel.querySelectorAll(
            'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]),'
            + ' textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
        ),
        (node) => node.offsetParent !== null
    );

    /* NOTHING TABBABLE STILL MEANS TRAPPED. A body with no controls in it is the loading state
       and the failure state; letting Tab out of either is the same leak by another route. */
    if (!focusable.length) {
        event.preventDefault();
        byId('lh-dialog-body').focus();
        return;
    }

    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && (document.activeElement === first || !panel.contains(document.activeElement))) {
        event.preventDefault();
        last.focus();
    } else if (!event.shiftKey && (document.activeElement === last || !panel.contains(document.activeElement))) {
        event.preventDefault();
        first.focus();
    }
}

/**
 * Escape, from anywhere on the page.
 *
 * Bound to the DOCUMENT rather than to the panel. A panel-scoped Escape only works while focus
 * is inside the panel, which makes it useless in exactly the situation an operator needs it:
 * focus somewhere unexpected and a modal in the way. The nav drawer already does it this way.
 */
function onDocumentKey(event) {
    if (event.key !== 'Escape') {
        return;
    }
    const root = byId('lh-dialog');
    if (root && !root.hidden) {
        event.preventDefault();
        closeDialog();
    }
}

/**
 * Open the dialog with a heading and a caption, and return its body element.
 *
 * The caller renders into the returned node. A second open replaces the first ON SCREEN rather
 * than stacking: two modals over each other is never the right answer, and the generation
 * counter means the abandoned one's fetch cannot paint over the new one. What the second open
 * does NOT do any more is forget the first — see the stack at the top of this file, and
 * closeDialog(), which steps back to it.
 *
 * @param {string} title
 * @param {string} subtitle
 * @returns {{body: HTMLElement, generation: number}}
 */
export function openDialog(title, subtitle) {
    const root = ensureDialog();
    generation += 1;

    byId('lh-dialog-title').textContent = String(title || 'Detail');
    const sub = byId('lh-dialog-sub');
    sub.textContent = String(subtitle || '');
    sub.hidden = !subtitle;

    const body = byId('lh-dialog-body');
    fill(body, [el('p', { class: 'muted', text: 'Loading…' })]);

    /* WHOEVER OPENED IT GETS FOCUS BACK, however it was opened. A dialog opened straight from
       code — the value browser, reached by pressing "Show all" in a facet list — has no row
       handler to name its opener, and used to restore focus to nothing: the operator was
       returned to the top of the document and lost their place in the sidebar.
       A frame is minted here ONLY when the stack is empty, because onActivate has already
       pushed one for anything opened from a row, and because every opener calls this twice —
       once for "Loading…" and once with the real heading — and the second call is the same
       dialog, not a new one. */
    if (!stack.length) {
        const active = document.activeElement;
        stack.push({
            opener: active && active !== document.body ? active : null,
            reopen: null
        });
    }

    root.hidden = false;
    document.documentElement.classList.add('lh-dialog-open');
    setBackgroundInert(true);
    body.focus();

    return { body: body, generation: generation };
}

/** Has the dialog moved on since this open? A stale render must be dropped. */
export function isCurrent(token) {
    return token === generation;
}

/**
 * Put focus on a node, if it is still a node that can take it.
 *
 * Every restore path goes through here, because every one of them can be handed something
 * that has since been replaced by a re-render — and a silent `document.contains()` failure is
 * how a keyboard operator ends up at the top of the document with no idea why.
 *
 * @returns {boolean} Whether focus actually moved.
 */
function focusIfPossible(node) {
    if (!node || typeof node.focus !== 'function' || !document.contains(node)) {
        return false;
    }
    node.focus();

    return document.activeElement === node;
}

/**
 * Find the row in the REBUILT parent dialog that corresponds to the one that was pressed.
 *
 * THE NODE ITSELF IS GONE. Returning to a parent re-runs its opener, which refetches and
 * rebuilds the body from scratch, so the `<tr>` the operator pressed to drill in does not
 * survive — it is the same row logically and a different element entirely. Matching on the
 * `data-` attributes finds its replacement, which is what "put me back where I was" means to
 * the person doing it. When there is no match the dialog body takes focus, which is where a
 * freshly opened dialog puts it anyway.
 */
function restoreInsideDialog(previous) {
    const body = byId('lh-dialog-body');
    if (previous && previous.dataset && previous.dataset.lhOpen && body) {
        for (const node of body.querySelectorAll('[data-lh-open="' + previous.dataset.lhOpen + '"]')) {
            let same = true;
            for (const key of Object.keys(previous.dataset)) {
                if (node.dataset[key] !== previous.dataset[key]) {
                    same = false;
                    break;
                }
            }
            if (same && focusIfPossible(node)) {
                return;
            }
        }
    }
    focusIfPossible(body);
}

/** Shut the shell completely, whatever is on the stack, and hand the page back. */
function dismiss(frame) {
    const root = byId('lh-dialog');
    stack.length = 0;
    if (root) {
        root.hidden = true;
    }
    document.documentElement.classList.remove('lh-dialog-open');
    setBackgroundInert(false);
    focusIfPossible(frame ? frame.opener : null);
}

/**
 * Close the top dialog: back to the one underneath it, or off the screen if there is none.
 *
 * ALL THREE GESTURES DO THE SAME THING — the Close button, the scrim and Escape. A scrim press
 * that exited the whole stack while Close stepped back one would be two meanings for "dismiss"
 * on the same surface, and the operator would have to remember which. One rule: closing undoes
 * the last thing you opened.
 *
 * A parent that cannot rebuild itself does not trap anybody. Its `reopen` may be absent, and it
 * may reject; either way the whole stack is dismissed rather than left showing a dialog whose
 * controls belong to a subject that is no longer loading.
 */
export function closeDialog() {
    const root = byId('lh-dialog');
    if (!root || root.hidden) {
        stack.length = 0;
        return;
    }

    generation += 1;
    const frame = stack.pop() || null;
    const parent = stack.length ? stack[stack.length - 1] : null;

    if (!parent || typeof parent.reopen !== 'function') {
        dismiss(frame);
        return;
    }

    try {
        Promise.resolve(parent.reopen()).then(
            () => restoreInsideDialog(frame ? frame.opener : null),
            () => dismiss(frame)
        );
    } catch (e) {
        void e;
        dismiss(frame);
    }
}

/**
 * Replace a dialog body with a failure, in the same shape a card error uses.
 *
 * The message is the server's own sentence, set with textContent: a Solr error can quote a
 * User-Agent back at us and it must land as text.
 */
export function dialogFail(body, err, retry) {
    const parts = [
        el('h3', { text: 'This could not be loaded' }),
        el('p', { text: String(err && err.message ? err.message : err) })
    ];

    /* A FAILURE WITH A WAY FORWARD. Every failed CARD in the panel offers a retry; a failed
       dialog offered nothing but Close, so the only way to try again was to shut it, find the
       row again and press it again — and on a dialog opened from a facet list that row is no
       longer on screen. The caller passes what it would have run; the button re-runs it in
       place. Callers that genuinely have nothing to re-run pass nothing and get the message
       alone, which is what this always did. */
    if (typeof retry === 'function') {
        const button = el('button', { type: 'button', class: 'small', text: 'Try again' });
        button.addEventListener('click', () => {
            button.disabled = true;
            fill(body, [el('p', { class: 'muted', text: 'Loading\u2026' })]);
            retry();
        });
        parts.push(el('div', { class: 'card-error-actions' }, [button]));
    }

    fill(body, parts);
}

/**
 * Convert a DOMStringMap into a plain object, so an opener gets something ordinary.
 */
function datasetOf(node) {
    const out = {};
    for (const key of Object.keys(node.dataset)) {
        out[key] = node.dataset[key];
    }
    return out;
}

/**
 * Dispatch a click or an Enter/Space on the nearest [data-lh-open] to its opener.
 *
 * A LINK ALWAYS WINS. The filter affordance in a table cell is a real <a href>, so it must
 * navigate rather than open a dialog even though it sits inside a clickable row — which is
 * the whole reason the two are different elements. closest() then picks the INNERMOST
 * data-lh-open, so a drillable cell beats the row it is in.
 */
function onActivate(event) {
    if (event.type === 'keydown' && event.key !== 'Enter' && event.key !== ' ') {
        return;
    }
    const target = event.target;
    if (!target || typeof target.closest !== 'function') {
        return;
    }
    if (target.closest('a[href], input, select, textarea')) {
        return;
    }

    /* A button is interactive and normally wins, EXCEPT the one whose whole job is to open
       this dialog. Without the exception the explicit row opener would be swallowed by the
       same guard that protects the filter links beside it. */
    const button = target.closest('button');
    if (button && !button.hasAttribute('data-lh-open')) {
        return;
    }

    const node = target.closest('[data-lh-open]');
    if (!node) {
        return;
    }
    const fn = openers.get(node.dataset.lhOpen);
    if (typeof fn !== 'function') {
        return;
    }
    event.preventDefault();

    /* A rejected opener must never leave the row looking inert. If the opener got as far as
       putting a dialog on screen, the failure is rendered into it; if it threw before that —
       which is the case that used to be swallowed entirely, because there was no body to
       render into — a dialog is opened for the purpose. The error still reaches the console,
       because an operator reporting "clicking does nothing" needs something to paste. */
    const run = () => Promise.resolve(fn(datasetOf(node))).catch((err) => {
        let body = byId('lh-dialog-body');
        if (!body) {
            openDialog('That could not be opened', '');
            body = byId('lh-dialog-body');
        }
        if (body) {
            dialogFail(body, err instanceof Error ? err : new Error('The detail view failed to render.'), run);
        }
        console.error('loghound: opening a ' + node.dataset.lhOpen + ' failed', err);
    });

    /* THE FRAME IS PUSHED HERE, NOT IN openDialog(), and that is what makes the drill-down
       reversible. This is the one place that knows both halves of a frame at once: the element
       pressed, and the exact call that would produce this dialog again. openDialog() is called
       twice by every opener — once for the loading state and once with the real heading — so a
       push there would count one dialog as two and Close would step back through phantoms.

       A row INSIDE the open dialog lands here exactly like a row on the page, which is the
       whole nesting case: the frame beneath it keeps the page row it came from, so the chain
       of openers is intact rather than overwritten by the innermost one and then orphaned
       microseconds later when the body it lives in is replaced. */
    if (stack.length >= MAX_DEPTH) {
        stack.pop();
    }
    stack.push({ opener: node, reopen: run });
    run();
}

document.addEventListener('click', onActivate);
document.addEventListener('keydown', onActivate);
document.addEventListener('keydown', onDocumentKey);
