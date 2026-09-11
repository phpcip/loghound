/*
 * Loghound — the sticky section nav.
 *
 * The bar itself is plain markup from Panel\Layout and works with scripting off: every entry
 * is a real anchor to a real card. This module adds the three things that need script, and
 * nothing else.
 *
 *   1. **Its real height, published to CSS.** A jumped-to heading has to land clear of the
 *      bar, which means `scroll-margin-top` has to equal the bar's height — and the bar's
 *      height depends on the font the browser actually resolved, so it cannot be a number
 *      typed into the stylesheet. It is measured and written to `--set-nav-h` on the root
 *      element; the stylesheet holds a sane fallback for the instant before this runs and for
 *      the case where it never does.
 *   2. **Which section the reader is in.** The bar is more useful saying where they ARE than
 *      only where they could go. The active entry is the last card whose top has passed under
 *      the bar, which is the same rule a reader applies by eye.
 *   3. **Keeping the active entry visible.** The bar is one row that scrolls horizontally
 *      rather than wrapping to a second line, so on a narrow window the active entry can be
 *      off to the right. It is scrolled into view when it changes — never on first paint
 *      unless it needs to be, because a page that scrolls something sideways as it loads
 *      looks broken.
 *
 * No inline handlers, no inline style attribute writes beyond the one custom property, and
 * nothing here reads or renders log-derived data: the labels were escaped server-side and
 * this module only ever toggles a class and reads geometry.
 */

'use strict';

/** Extra breathing room between the bar and a jumped-to heading, in pixels. */
const CLEARANCE = 20;

/**
 * Publish the bar's measured height so the stylesheet's scroll offsets match it.
 */
function publishHeight(nav) {
    const height = Math.round(nav.getBoundingClientRect().height);
    if (height > 0) {
        document.documentElement.style.setProperty('--set-nav-h', height + 'px');
    }
    return height;
}

/**
 * Mark the entry whose card the reader is currently inside.
 *
 * `aria-current` as well as a class: the bar is a navigation landmark, and a screen reader
 * that is told which entry is current gets the same information the highlight gives everyone
 * else. Returns the link that became active, or null.
 */
function markActive(links, cards, offset) {
    let activeId = null;
    for (const card of cards) {
        if (card.getBoundingClientRect().top - offset <= 1) {
            activeId = card.id;
        }
    }
    if (activeId === null && cards.length) {
        activeId = cards[0].id;
    }

    let active = null;
    for (const link of links) {
        const on = link.getAttribute('href') === '#' + activeId;
        link.classList.toggle('on', on);
        if (on) {
            link.setAttribute('aria-current', 'true');
            active = link;
        } else {
            link.removeAttribute('aria-current');
        }
    }
    return active;
}

/**
 * Scroll the bar sideways only when the active entry is not already fully visible.
 */
function reveal(nav, link) {
    if (!link) {
        return;
    }
    const bar = nav.getBoundingClientRect();
    const item = link.getBoundingClientRect();
    if (item.left >= bar.left && item.right <= bar.right) {
        return;
    }
    nav.scrollLeft += item.left < bar.left
        ? item.left - bar.left - 12
        : item.right - bar.right + 12;
}

/**
 * Wire the bar on whichever view rendered one.
 */
function init() {
    const nav = document.getElementById('lh-section-nav');
    if (!nav) {
        return;
    }

    const links = Array.prototype.slice.call(nav.querySelectorAll('a[data-sect]'));
    const cards = [];
    for (const link of links) {
        const card = document.getElementById(link.dataset.sect + '-card');
        if (card) {
            cards.push(card);
        }
    }
    if (!cards.length) {
        return;
    }

    let height = publishHeight(nav);
    let last = null;
    let queued = false;

    const update = () => {
        queued = false;
        const active = markActive(links, cards, height + CLEARANCE);
        if (active !== last) {
            last = active;
            reveal(nav, active);
        }
    };

    const schedule = () => {
        if (!queued) {
            queued = true;
            window.requestAnimationFrame(update);
        }
    };

    window.addEventListener('scroll', schedule, { passive: true });
    window.addEventListener('resize', () => {
        height = publishHeight(nav);
        schedule();
    });

    if (window.ResizeObserver) {
        new ResizeObserver(() => {
            height = publishHeight(nav);
            schedule();
        }).observe(nav);
    }

    update();
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
} else {
    init();
}
