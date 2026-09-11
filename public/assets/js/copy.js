/*
 * Loghound — the copy-to-clipboard control, shared by the panel and the installer.
 *
 * It lives in its own module because the two front ends are separate bundles — the panel
 * loads assets/js/app.js, the installer loads assets/js/setup.js — and a copy button that
 * behaved differently depending on which screen you were looking at would be its own small
 * bug. Both import this file, so there is one implementation.
 *
 * Two constraints shape it:
 *
 *  - **The CSP is `script-src 'self'`.** No inline handler, no `onclick`, no `javascript:`.
 *    A button declares itself with `data-copy="<id of the element to copy>"` and the
 *    listener is attached here.
 *  - **`navigator.clipboard` requires a secure context.** It is undefined on a plain-HTTP
 *    install, which is a real configuration for a box being set up before TLS is arranged,
 *    and touching it there throws. So the clipboard write is attempted, and a failure falls
 *    back to selecting the snippet so it can be copied with the keyboard. If neither route
 *    is available the button is removed outright: the snippet is still selectable by hand,
 *    and a control that silently does nothing is worse than no control.
 */

'use strict';

/** How long the button shows what happened before going back to its label. */
const CONFIRM_MS = 1600;

/**
 * Can the text of an element be selected programmatically?
 *
 * The fallback path for an insecure context. Checked before a button is wired rather than
 * when it is pressed, because the answer decides whether the button is rendered at all.
 *
 * @returns {boolean}
 */
function canSelect() {
    return typeof document.createRange === 'function' &&
        typeof window.getSelection === 'function' &&
        window.getSelection() !== null;
}

/**
 * Is the async clipboard API usable here?
 *
 * @returns {boolean}
 */
function canWriteClipboard() {
    return !!(navigator.clipboard && typeof navigator.clipboard.writeText === 'function');
}

/**
 * Try the clipboard, reporting whether it took.
 *
 * A rejected promise is an ordinary outcome here, not an error worth surfacing: a browser
 * that refuses the write because the document is not a secure context, or because the
 * permission was declined, is exactly the case the selection fallback exists for.
 *
 * @param {string} text
 * @returns {Promise<boolean>}
 */
async function writeClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch (e) {
        return false;
    }
}

/**
 * Select the contents of an element so the operator can press the platform copy key.
 *
 * @param {HTMLElement} source
 * @returns {boolean} Whether a selection was actually made.
 */
function selectContents(source) {
    try {
        const range = document.createRange();
        range.selectNodeContents(source);
        const selection = window.getSelection();
        if (!selection) {
            return false;
        }
        selection.removeAllRanges();
        selection.addRange(range);
        return true;
    } catch (e) {
        return false;
    }
}

/**
 * Say what just happened, on the button itself, for a moment.
 *
 * A copy button that looks identical before and after being pressed gets pressed three
 * times and the operator still does not know whether it worked. The original label is
 * stashed in the dataset on the first press so repeated presses cannot leave "Copied"
 * behind as the permanent label.
 *
 * @param {HTMLButtonElement} button
 * @param {string} message
 */
function confirmOn(button, message) {
    if (!button.dataset.label) {
        button.dataset.label = button.textContent || 'Copy';
    }
    const original = button.dataset.label;

    if (button.dataset.resetTimer) {
        window.clearTimeout(Number(button.dataset.resetTimer));
    }

    button.textContent = message;
    button.classList.add('copy-done');
    button.dataset.resetTimer = String(window.setTimeout(function () {
        button.textContent = original;
        button.classList.remove('copy-done');
        delete button.dataset.resetTimer;
    }, CONFIRM_MS));
}

/**
 * Wire every `[data-copy]` button on the page.
 *
 * Idempotent: a button already wired is skipped, so calling this again after new markup
 * has been rendered cannot attach a second listener to the same control.
 */
export function initCopyButtons() {
    const clipboard = canWriteClipboard();
    const selection = canSelect();

    for (const button of document.querySelectorAll('[data-copy]')) {
        if (button.dataset.copyWired === '1') {
            continue;
        }

        const source = document.getElementById(button.dataset.copy);
        if (!source || (!clipboard && !selection)) {
            button.remove();
            continue;
        }

        button.dataset.copyWired = '1';
        button.addEventListener('click', async function () {
            if (clipboard && await writeClipboard(source.textContent || '')) {
                confirmOn(button, 'Copied');
                return;
            }
            confirmOn(button, selectContents(source) ? 'Selected — press copy' : 'Select it by hand');
        });
    }
}
