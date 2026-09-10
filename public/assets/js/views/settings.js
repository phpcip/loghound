/*
 * Loghound — Settings view.
 *
 * The Settings page is rendered entirely server-side (it is a set of forms, and it must
 * work with JavaScript disabled), so this module only adds the two conveniences that
 * genuinely need scripting: the snippet tabs and the copy buttons.
 *
 * The copy buttons are wired centrally in core.js — every [data-copy] on the page — so
 * this file only handles the tab strip.
 */

'use strict';

/**
 * Wire the install-snippet tabs.
 *
 * Roving selection over role="tab" buttons with arrow-key support, because a tab strip
 * that only responds to a mouse is a tab strip half the operators cannot use. No inline
 * handlers: the CSP forbids them and the listeners are attached here.
 */
function initTabs() {
    const strip = document.querySelector('.snippets .tabs');
    if (!strip) {
        return;
    }
    const tabs = Array.from(strip.querySelectorAll('[data-tab]'));

    const select = (name) => {
        for (const tab of tabs) {
            const on = tab.dataset.tab === name;
            tab.classList.toggle('on', on);
            tab.setAttribute('aria-selected', on ? 'true' : 'false');
            tab.tabIndex = on ? 0 : -1;
        }
        for (const panel of document.querySelectorAll('[data-tabpanel]')) {
            panel.hidden = panel.dataset.tabpanel !== name;
        }
    };

    for (const tab of tabs) {
        tab.addEventListener('click', () => select(tab.dataset.tab));
        tab.addEventListener('keydown', (e) => {
            const i = tabs.indexOf(tab);
            let next = null;
            if (e.key === 'ArrowRight') {
                next = tabs[(i + 1) % tabs.length];
            } else if (e.key === 'ArrowLeft') {
                next = tabs[(i - 1 + tabs.length) % tabs.length];
            }
            if (next) {
                e.preventDefault();
                select(next.dataset.tab);
                next.focus();
            }
        });
    }

    // Establish the initial roving tabindex from whichever tab the server marked active.
    const active = tabs.find((t) => t.classList.contains('on')) || tabs[0];
    if (active) {
        select(active.dataset.tab);
    }
}

/** Entry point. */
export default async function init() {
    initTabs();
}
