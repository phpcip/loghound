/**
 * Loghound — the behaviour a phone layout needs that CSS cannot express.
 *
 * Three jobs, and nothing else:
 *
 *  1. **The view navigation becomes a bar with a drawer.** Twelve links wrapped into a block
 *     317px tall at 375px — 41% of the viewport above the H1 on every page. The markup has no
 *     control to open a drawer with, so this module creates one, wires the ARIA, and marks
 *     <html> with `lh-nav-js` so the stylesheet's drawer rules are the only ones that can
 *     apply. With this file absent the navigation stays exactly as it is today.
 *
 *  2. **A table too wide for the screen becomes a list of records.** A stacked table needs
 *     every cell to carry its own column heading, and the panel's rows arrive as JSON after
 *     the page has loaded, so the heading has to be copied onto the cells at runtime. Which
 *     tables get stacked is MEASURED, never guessed from a column count: a table whose
 *     natural width exceeds its container is stacked, one that fits is left alone.
 *
 *  3. **The session facet rail becomes a disclosure.** The rail measured 5,023px tall, so on
 *     one column it puts the first session five screens down. Closed on arrival, with the
 *     number of active filters on the control, so a filtered view can never look unfiltered.
 *
 * ---------------------------------------------------------------------------------------
 * CONSTRAINTS THIS FILE IS WRITTEN AGAINST
 * ---------------------------------------------------------------------------------------
 * The panel's CSP has no 'unsafe-inline' for scripts, so there is no inline handler, no
 * javascript: URL, no eval and no Function constructor anywhere below. Every element is built
 * with createElement and filled with textContent — never innerHTML — which is also what keeps
 * a hostile hostname in a column heading from becoming markup when it is copied onto a cell.
 *
 * Listeners are delegated from a container that outlives the rows, because the views replace
 * their tbody on every fetch and on every sort, and a listener attached to a row would be
 * thrown away with it.
 *
 * It owns no other module's DOM. It adds attributes and two elements of its own; it never
 * moves, rewrites or removes anything a view rendered.
 *
 * @module responsive
 */

import { icon } from './icons.js';

const NARROW = 900;
const STACK_ATTR = 'data-lh-col';
const RAIL_KEY = 'lh.rail';
const TIP_SELECTOR = 'nav.side li a, nav.side .lh-railbtn, nav.side .theme-toggle';
const TIP_HOVERED = 'nav.side li a:hover, nav.side .lh-railbtn:hover, nav.side .theme-toggle:hover';
const HINT_ATTR = 'data-lh-hint';

/* The section bar's tooltip may be as wide as this and must keep this much clear of the window
   edge. Both numbers are the stylesheet's, repeated here because the clamp that stops the box
   running off the right has to know how wide it may get BEFORE it is drawn — see
   --lh-sectiontip-w and --lh-sectiontip-edge in panel.css, which are the same two values. */
const SECTION_TIP_MAX = 360;
const SECTION_TIP_EDGE = 12;

const FOLD_KEY = 'lh.fold.';
const CARD_KEY = 'lh.card.';

let stamping = false;
let observer = null;
let navBtn = null;
let scrim = null;
let lastFocus = null;
let applyFolds = null;
let recheckTrouble = null;
let remeasureTips = null;
let refreshPageTools = null;

/**
 * Is the viewport in the range the phone layout is written for?
 *
 * One number, matching the stylesheet's single mode-switch breakpoint, so the two can never
 * disagree about which layout is on screen.
 */
function narrow() {
    return window.innerWidth <= NARROW;
}

/**
 * Create an element with attributes and text, with no markup-parsing sink involved.
 *
 * @param {string} tag
 * @param {Object<string,string>} [attrs]
 * @param {string} [text]
 * @returns {HTMLElement}
 */
function el(tag, attrs, text) {
    const node = document.createElement(tag);
    if (attrs) {
        for (const key of Object.keys(attrs)) {
            node.setAttribute(key, attrs[key]);
        }
    }
    if (text !== undefined && text !== null) {
        node.textContent = String(text);
    }
    return node;
}

/* ===================================================================================
 * 1. The navigation bar and its drawer
 * ================================================================================ */

/**
 * Publish the height of the closed navigation bar as --lh-topbar-h.
 *
 * The bar is fixed, so three other things have to know how tall it is: the top padding of
 * <main>, the offset the sticky section nav pins at, and the scroll-margin every card uses as
 * a jump target. Measuring beats declaring because the height depends on the font the browser
 * actually resolved, and Space Grotesk may or may not be one of them.
 *
 * Measured from the bar's first row rather than from the bar, so an open drawer — which is
 * the same element, grown to fill the screen — cannot publish its own height as the offset.
 */
function publishBarHeight(side) {
    if (!side || !narrow()) {
        document.documentElement.style.removeProperty('--lh-topbar-h');
        return;
    }
    const brand = side.querySelector('.brand');
    const base = brand ? brand.getBoundingClientRect().height : 0;
    const pad = 16;
    const h = Math.round(Math.max(base + pad, navBtn ? navBtn.getBoundingClientRect().height + pad : 0, 48));
    document.documentElement.style.setProperty('--lh-topbar-h', h + 'px');
}

/**
 * Put each view's hint on screen, once.
 *
 * Every navigation link carries a sentence in its title attribute saying what the view
 * answers. On a desktop that is a tooltip; on a phone there is no hover and the sentence has
 * never been readable at all. In the drawer there is room for it, so it is rendered as a
 * second line — and the title is left in place, because the desktop tooltip is still wanted.
 */
function addNavHints(side) {
    for (const link of side.querySelectorAll('ul li a')) {
        if (link.querySelector('.lh-navhint')) {
            continue;
        }
        const hint = link.getAttribute('title');
        if (!hint) {
            continue;
        }
        link.appendChild(el('span', { class: 'lh-navhint' }, hint));
    }
}

/**
 * Open the drawer.
 *
 * The scrim is created on first use rather than on load, so a session that never opens the
 * drawer carries nothing extra in the DOM. Focus moves to the first link because the drawer
 * is a list to choose from, and where focus lands is remembered so closing can put it back.
 */
function openNav(side) {
    if (side.classList.contains('is-open')) {
        return;
    }
    lastFocus = document.activeElement;
    side.classList.add('is-open');
    navBtn.setAttribute('aria-expanded', 'true');
    document.documentElement.classList.add('lh-nav-open');

    if (!scrim) {
        scrim = el('button', { type: 'button', class: 'lh-scrim', tabindex: '-1', 'aria-hidden': 'true' });
        scrim.addEventListener('click', () => closeNav(side));
        document.body.appendChild(scrim);
    }
    scrim.hidden = false;

    /* SOMEWHERE INSIDE TO LAND. onNavKey() holds focus on the drawer when it has no focusable
       children of its own rather than letting Tab out into the page behind it, and a drawer
       that cannot take focus would make that a no-op. -1, so it is reachable from script and
       never from the tab order. */
    if (!side.hasAttribute('tabindex')) {
        side.setAttribute('tabindex', '-1');
    }

    const first = side.querySelector('ul li a');
    if (first) {
        first.focus();
    }
}

/**
 * Close the drawer and give focus back to whatever opened it.
 */
function closeNav(side) {
    if (!side.classList.contains('is-open')) {
        return;
    }
    side.classList.remove('is-open');
    navBtn.setAttribute('aria-expanded', 'false');
    document.documentElement.classList.remove('lh-nav-open');
    if (scrim) {
        scrim.hidden = true;
    }
    if (lastFocus && typeof lastFocus.focus === 'function' && document.contains(lastFocus)) {
        lastFocus.focus();
    } else {
        navBtn.focus();
    }
    lastFocus = null;
}

/**
 * Keep Tab inside the open drawer.
 *
 * Not a full focus trap library: the drawer's focusable set is its own links and two buttons,
 * all of them descendants of one element, so the first and last of that set are all a cycle
 * needs. Escape closes, which is the contract every other overlay in the panel keeps.
 */
function onNavKey(side, event) {
    if (!side.classList.contains('is-open')) {
        return;
    }
    if (event.key === 'Escape') {
        event.preventDefault();
        closeNav(side);
        return;
    }
    if (event.key !== 'Tab') {
        return;
    }
    const focusable = Array.from(side.querySelectorAll('a[href], button:not([tabindex="-1"])'))
        .filter((node) => node.offsetParent !== null);

    /* TWO LEAKS, BOTH THE SHAPE dialog.js ALREADY SOLVED.

       An empty focusable set used to `return`, which lets Tab walk into the page behind a
       drawer covering it. dialog.js does the opposite deliberately and holds focus on the
       panel; the same reasoning applies here, and the drawer itself is focusable.

       And the cycle only fired when focus was ON the first or last item. Anywhere else outside
       the drawer — document.body after a re-render, or the scrim, which is tabindex="-1" —
       matched neither test, so Tab went straight through to the page underneath. The
       `!side.contains(document.activeElement)` clause is what recovers from that, and it is
       the clause dialog.js carries and this did not. */
    if (focusable.length === 0) {
        event.preventDefault();
        side.focus();
        return;
    }

    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    const outside = !side.contains(document.activeElement);

    if (event.shiftKey && (document.activeElement === first || outside)) {
        event.preventDefault();
        last.focus();
    } else if (!event.shiftKey && (document.activeElement === last || outside)) {
        event.preventDefault();
        first.focus();
    }
}

/**
 * Turn the sidebar into a bar with a drawer.
 *
 * The control is inserted after the brand so the tab order reads brand, control, list, and it
 * carries a drawn mark rather than an icon font or an emoji: the panel has no outside asset
 * and is not getting one for a pair of lines. `lh-nav-js` goes on <html> only once the control
 * exists, so the stylesheet cannot hide a navigation that has nothing to open it.
 */
function setUpNav() {
    const side = document.querySelector('nav.side');
    if (!side || navBtn) {
        return;
    }

    const list = side.querySelector('ul');
    if (!list) {
        return;
    }
    if (!list.id) {
        list.id = 'lh-view-list';
    }

    navBtn = el('button', {
        type: 'button',
        class: 'lh-navbtn',
        'aria-expanded': 'false',
        'aria-controls': list.id
    });
    navBtn.appendChild(el('span', { class: 'lh-navbtn-mark', 'aria-hidden': 'true' }));
    navBtn.appendChild(el('span', {}, 'Views'));

    const brand = side.querySelector('.brand');
    if (brand && brand.parentNode === side) {
        brand.insertAdjacentElement('afterend', navBtn);
    } else {
        side.insertBefore(navBtn, side.firstChild);
    }

    navBtn.addEventListener('click', () => {
        if (side.classList.contains('is-open')) {
            closeNav(side);
        } else {
            openNav(side);
        }
    });

    side.addEventListener('click', (event) => {
        const link = event.target.closest ? event.target.closest('a[href]') : null;
        if (link && side.contains(link)) {
            closeNav(side);
        }
    });

    document.addEventListener('keydown', (event) => onNavKey(side, event));

    addNavHints(side);
    document.documentElement.classList.add('lh-nav-js');
    publishBarHeight(side);
}

/* ===================================================================================
 * 2. Tables as records
 * ================================================================================ */

/**
 * The column headings of a table, as plain text.
 *
 * Read from the last row of the head, because a table with a grouped header puts the real
 * column names there. A heading is taken as text and stays text all the way onto the cell: a
 * column named from a hostname or a handler path is attacker-influenced, and the only safe
 * thing to do with it is never let it near a markup sink.
 *
 * @returns {string[]}
 */
function headings(table) {
    const rows = table.tHead ? table.tHead.rows : null;
    if (!rows || rows.length === 0) {
        return [];
    }
    const row = rows[rows.length - 1];
    const out = [];
    for (const cell of row.cells) {
        const label = (cell.textContent || '').replace(/\s+/g, ' ').trim();
        const span = Math.max(1, cell.colSpan || 1);
        for (let i = 0; i < span; i++) {
            out.push(label);
        }
    }
    return out;
}

/**
 * Copy the column heading onto every cell of every body row.
 *
 * Index-based, and a cell that spans columns is left without a label on purpose — it is a
 * panel inside the record (an expanded member list, an empty-state sentence, a recorded
 * request), not one fact with a name. Only rows of THIS table are touched: a nested table
 * inside an expanded row is stamped by its own pass, with its own headings.
 */
function stampLabels(table) {
    const labels = headings(table);
    if (labels.length === 0) {
        return;
    }
    for (const body of table.tBodies) {
        for (const row of body.rows) {
            if (row.parentNode !== body) {
                continue;
            }
            let index = 0;
            for (const cell of row.cells) {
                const span = Math.max(1, cell.colSpan || 1);
                if (span === 1 && labels[index] !== undefined) {
                    if (cell.getAttribute(STACK_ATTR) !== labels[index]) {
                        cell.setAttribute(STACK_ATTR, labels[index]);
                    }
                } else if (cell.hasAttribute(STACK_ATTR)) {
                    cell.removeAttribute(STACK_ATTR);
                }
                index += span;
            }
        }
    }
}

/**
 * Decide whether a table has to be stacked, by measuring it rather than counting its columns.
 *
 * The class is removed before the measurement, because a stacked table is as wide as its
 * container by definition and would always answer "I fit". What is compared is the table's
 * own width against the width available to it: `min-width: 900px` on the nine-column tables,
 * and the natural width of the content on the others.
 *
 * A margin of 4px keeps a table that lands within rounding of its container from flipping
 * between the two layouts as a scrollbar appears and disappears.
 */
function needsStack(table) {
    const host = table.closest('.table-wrap') || table.parentElement;
    if (!host) {
        return false;
    }
    const had = table.classList.contains('lh-stack');
    if (had) {
        table.classList.remove('lh-stack');
    }
    const wide = table.getBoundingClientRect().width > host.clientWidth + 4;
    if (had && !wide) {
        table.classList.add('lh-stack');
    }
    return wide;
}

/**
 * Stack every table that does not fit, and unstack every one that now does.
 *
 * Runs on load, on resize, and whenever a view replaces its rows. The guard flag keeps the
 * attribute writes below from waking the observer that called it.
 */
function restack() {
    if (stamping) {
        return;
    }
    stamping = true;

    const on = narrow();
    for (const table of document.querySelectorAll('table')) {
        if (!on) {
            table.classList.remove('lh-stack');
            continue;
        }
        if (table.tBodies.length === 0 || table.rows.length === 0) {
            continue;
        }
        stampLabels(table);
        if (needsStack(table)) {
            table.classList.add('lh-stack');
        } else {
            table.classList.remove('lh-stack');
        }
    }

    stamping = false;
}

/* ===================================================================================
 * 3. The session facet rail as a disclosure
 * ================================================================================ */

/**
 * How many filters are currently applied, for the disclosure's label.
 *
 * Counted from the URL rather than from the rail, because the rail's own marks arrive with a
 * fetch and the count has to be right on the first paint: a filtered page whose filter
 * control says nothing is a page showing a filtered number as if it were the whole.
 */
function activeFilterCount() {
    let n = 0;
    const params = new URLSearchParams(window.location.search);
    for (const key of params.keys()) {
        if (key.startsWith('f[') || key.startsWith('lf[')) {
            n++;
        }
    }
    return n;
}

/**
 * Write the disclosure's state onto its own label.
 */
function labelFacetButton(button, open) {
    const state = button.querySelector('.lh-facetbtn-state');
    const n = activeFilterCount();
    if (!state) {
        return;
    }
    if (n > 0) {
        state.textContent = n === 1 ? '1 active' : n + ' active';
    } else {
        state.textContent = open ? 'hide' : 'show';
    }
}

/**
 * Collapse the session explorer's facet rail behind a control.
 *
 * The rail is not hidden: it is closed, with its state on the control, and one press opens
 * exactly the lists that were there before. It opens itself when the page arrives already
 * filtered, because then the filters are the thing the reader is looking at.
 */
function setUpFacets() {
    const rail = document.querySelector('.explorer .facets');
    if (!rail || rail.querySelector('.lh-facetbtn')) {
        return;
    }
    const card = rail.querySelector('section.card');
    const head = card ? card.querySelector('.card-head') : null;
    if (!card || !head) {
        return;
    }

    const button = el('button', { type: 'button', class: 'lh-facetbtn', 'aria-expanded': 'false' });
    button.appendChild(el('span', {}, 'Filters'));
    button.appendChild(el('span', { class: 'lh-facetbtn-state' }));
    head.insertAdjacentElement('afterend', button);

    /* THE CONTROLLED ELEMENT IS THE ONE THAT ACTUALLY OPENS AND CLOSES. This pointed at
       `.card-content`, a DESCENDANT of the region the handler toggles — the class goes on the
       rail two levels up and the stylesheet hangs the visibility rules off that — and it was
       set only `if (content && content.id)`, so a lookup that missed left no attribute at all
       rather than falling back. The rail is given an id if it has none, so the reference is
       always to something that exists. */
    if (!rail.id) {
        rail.id = 'lh-facet-rail';
    }
    button.setAttribute('aria-controls', rail.id);

    button.addEventListener('click', () => {
        const open = rail.classList.toggle('is-open');
        button.setAttribute('aria-expanded', open ? 'true' : 'false');
        labelFacetButton(button, open);
    });

    if (activeFilterCount() > 0) {
        rail.classList.add('is-open');
        button.setAttribute('aria-expanded', 'true');
    }

    labelFacetButton(button, rail.classList.contains('is-open'));
    document.documentElement.classList.add('lh-facets-js');
}

/* ===================================================================================
 * 4. The view navigation as an icon rail
 * ================================================================================ */

/**
 * Turn the left navigation into a rail that is collapsed to icons by default.
 *
 * WHY COLLAPSED IS THE DEFAULT. The rail listed twelve views at their full heading length and
 * took 216px of every desk screen to do it — width that the reader's own data wants, and that
 * the facet column beside the results wants more. An operator learns twelve marks in a day and
 * then never reads the words again; somebody who has not is one press from having them back,
 * and every mark carries the view's name as a title and as its accessible name in the
 * meantime, so nothing is ever unnamed.
 *
 * WHERE THE WIDTH GOES. `--side-w` is the one number the shell is built on: the rail's width
 * and <main>'s left margin both read it. Overriding it on the root element therefore moves
 * both, and the space lands in the content rather than in a gutter.
 *
 * THE CHOICE IS REMEMBERED. In localStorage, per browser, like the theme. A first visit has no
 * stored value and gets the collapsed rail, which is the state the panel is designed around.
 *
 * GATED ON SCRIPT, because the toggle is created here: without it the rail would be collapsed
 * with no way to expand it, so with scripting off the navigation stays the full list it is.
 */
function setUpRail() {
    const side = document.querySelector('nav.side');
    if (!side || side.querySelector('.lh-railbtn')) {
        return;
    }

    for (const link of side.querySelectorAll('ul li a')) {
        if (link.querySelector('.vicon')) {
            continue;
        }
        const slug = slugOf(link);
        const mark = icon('view', slug);
        if (mark) {
            link.insertBefore(mark, link.firstChild);
        }
        /* THE NAME IS THE LABEL, NOT EVERY WORD IN THE LINK. addNavHints() has already
           appended the view's one-sentence hint as a second element, so `link.textContent`
           was label and hint run together with no separator — "OverviewWho came, and how
           long they really stayed" — and that string was what a screen reader announced for
           the panel's primary navigation. The label element is the name; the hint stays
           where it is, for the drawer to render and for the tooltip never to repeat. */
        if (!link.getAttribute('aria-label')) {
            const label = link.querySelector('.navlabel');
            link.setAttribute('aria-label', ((label || link).textContent || '').trim());
        }
    }

    const toggle = side.querySelector('.theme-toggle');
    if (toggle && !toggle.querySelector('.lh-themelabel')) {
        const label = el('span', { class: 'lh-themelabel' }, toggle.textContent || 'Theme');
        toggle.textContent = '';
        const mark = icon('theme', 'theme');
        if (mark) {
            toggle.appendChild(mark);
        }
        toggle.appendChild(label);
        mirrorThemeTitle(toggle, label);
    }

    /* A PRESSED TOGGLE, NOT A DISCLOSURE. The rail never HIDES the view list — it collapses the
       labels so only the icons remain, and every link stays present and operable. Announcing
       `aria-expanded="false"` therefore told a screen-reader user the navigation was closed
       when it was fully available, which is the opposite of what they would find. `aria-pressed`
       is what a two-state control that changes an appearance says.
       `aria-controls` is gone with it: it was `(side.querySelector('ul') || {}).id ||
       'lh-view-list'` — a literal fallback that, if setUpNav() had taken either of its early
       returns, pointed at an element id that does not exist. */
    const button = el('button', {
        type: 'button',
        class: 'lh-railbtn',
        'aria-pressed': 'false'
    });
    button.appendChild(el('span', { class: 'lh-railbtn-mark', 'aria-hidden': 'true' }));
    button.appendChild(el('span', { class: 'lh-railbtn-label' }, 'Collapse'));

    const brand = side.querySelector('.brand');
    if (brand && brand.parentNode === side) {
        brand.insertAdjacentElement('afterend', button);
    } else {
        side.insertBefore(button, side.firstChild);
    }

    button.addEventListener('click', () => setRail(!isRailCollapsed()));

    watchRailTips(side);

    document.documentElement.classList.add('lh-rail');
    applyRail(isRailCollapsed());
}

/**
 * Tell the collapsed rail's tooltip where the control it belongs to is.
 *
 * THE TOOLTIP IS DRAWN IN CSS AND POSITIONED IN CSS; this supplies the one number CSS cannot
 * work out. The box has to be `position: fixed` to escape the rail's own overflow — see the
 * stylesheet for why — and a fixed box is placed against the viewport, so its vertical
 * position has to come from a measurement of the control rather than from a percentage.
 *
 * MEASURED WHEN IT IS REACHED, not once at load. The rail scrolls inside itself on a short
 * window, and a number taken at layout time would then point the tooltip at a mark the reader
 * is not on — which is worse than no tooltip, because it is confidently wrong.
 *
 * Nothing here decides whether the tooltip is visible. That is `:hover` and `:focus-visible`
 * in the stylesheet, so the affordance survives this module failing to load.
 */
function publishTipY(node) {
    if (!node || !document.documentElement.classList.contains('lh-rail-collapsed')) {
        return;
    }
    const box = node.getBoundingClientRect();
    node.style.setProperty('--lh-navtip-y', (box.top + box.height / 2) + 'px');
}

/**
 * Watch the rail for a control being pointed at, focused, or scrolled away from.
 *
 * Delegated from the rail rather than bound per control: `pointerover` and `focusin` both
 * bubble, so one pair of listeners covers every link, the collapse button and the theme
 * control, and covers any of them being added later. Both fire before the frame in which the
 * tooltip is painted, so the position is in place by the time it appears.
 *
 * The scroll pass is the case the hover pass cannot see: the pointer sits still on a mark
 * while the wheel moves the rail underneath it. Passive, because nothing here cancels it.
 */
function watchRailTips(side) {
    const publish = (event) => {
        const target = event.target;
        if (target && typeof target.closest === 'function') {
            publishTipY(target.closest(TIP_SELECTOR));
        }
    };

    side.addEventListener('pointerover', publish);
    side.addEventListener('focusin', publish);
    side.addEventListener('scroll', () => {
        publishTipY(document.querySelector(TIP_HOVERED));
        const active = document.activeElement;
        if (active && typeof active.closest === 'function' && side.contains(active)) {
            publishTipY(active.closest(TIP_SELECTOR));
        }
    }, { passive: true });
}

/**
 * The same tooltip, for the section bar at the top of a page.
 *
 * THE DEFECT. The bar is one row that never wraps, so its labels are short by contract — and
 * for a view that has not declared its own sections the label is a heading CUT to 22 characters
 * by Layout::cardsIn(). "01 Declared versus evasi…" is not a label, it is the first half of one,
 * and there was no way to read the rest: the bar sets no `title`, and even if it did, that is
 * the bubble this work exists to replace.
 *
 * WHERE THE FULL TEXT COMES FROM. `data-full` on the anchor, which Layout emits alongside the
 * trimmed label. WITHOUT IT NOTHING HAPPENS — no attribute, no tooltip — because the one thing
 * this must never do is repeat the truncated string that is already on screen, which is a
 * tooltip that tells the reader what they can see and still withholds what they cannot.
 *
 * WHEN IT SHOWS. Only when the label really is short of its full text, which is TWO different
 * conditions and both are measured rather than assumed: the rendered text differs from
 * `data-full` (the server's cut), or the label overflows its own box (a cut the browser made).
 * Re-measured on resize, because the bar scrolls horizontally and the same entry crosses that
 * line as the window changes.
 *
 * THE NAME IS THE WHOLE TEXT. `aria-label` carries the untruncated label, so a screen reader
 * reads all of it whether or not the tooltip is on screen and whether or not it is hovered.
 */
function markSectionTips(bar) {
    for (const link of bar.querySelectorAll('a[data-full]')) {
        const label = link.querySelector('.set-nav-label');
        const full = (link.getAttribute('data-full') || '').trim();
        if (!label || full === '') {
            continue;
        }

        const shown = (label.textContent || '').trim();
        const cut = shown !== full || label.scrollWidth > label.clientWidth;

        if (cut) {
            link.setAttribute('data-lh-tip', '1');
            link.setAttribute('aria-label', full);
        } else {
            link.removeAttribute('data-lh-tip');
        }
    }
}

/**
 * Put the section bar's tooltip under the entry it belongs to.
 *
 * Two numbers rather than the rail's one, because this bar scrolls sideways: neither coordinate
 * can be derived from a fixed edge the way the rail's `left` is. The horizontal one is clamped
 * so a box opened from the last entry on the row cannot run off the right of the window — the
 * clamp uses the same maximum width the stylesheet gives the box, which is why that number is a
 * token both of them read.
 */
function publishSectionTip(node) {
    if (!node) {
        return;
    }
    const box = node.getBoundingClientRect();
    const room = document.documentElement.clientWidth;
    const widest = Math.min(SECTION_TIP_MAX, room - SECTION_TIP_EDGE * 2);
    const x = Math.max(SECTION_TIP_EDGE, Math.min(box.left, room - SECTION_TIP_EDGE - widest));

    node.style.setProperty('--lh-navtip-x', x + 'px');
    node.style.setProperty('--lh-navtip-y', box.bottom + 6 + 'px');
}

/**
 * Wire the section bar's tooltips, if there is a bar and anything in it was cut.
 *
 * Delegated and passive for the same reasons the rail's are, and re-measured on the same
 * animation-frame pass everything else in this module uses, so a resize costs one layout read
 * per entry rather than one per frame of the drag.
 */
function setUpSectionTips() {
    const bar = document.getElementById('lh-section-nav');
    if (!bar || bar.dataset.lhTips === '1') {
        return null;
    }
    bar.dataset.lhTips = '1';

    const publish = (event) => {
        const target = event.target;
        if (target && typeof target.closest === 'function') {
            publishSectionTip(target.closest('#lh-section-nav a[data-lh-tip]'));
        }
    };

    bar.addEventListener('pointerover', publish);
    bar.addEventListener('focusin', publish);
    bar.addEventListener('scroll', () => {
        publishSectionTip(bar.querySelector('a[data-lh-tip]:hover'));
    }, { passive: true });

    markSectionTips(bar);
    return () => markSectionTips(bar);
}

/**
 * The two icon-only controls that live in the page rather than in a bar.
 *
 * The card head's refresh mark, and the row opener that ends every drillable table row. Both
 * are a drawn glyph with no words, both keep their `aria-label` — the accessible name is on the
 * control whatever draws the hint — and both now take the panel's own tooltip instead of
 * `title`, which is the bubble the rail and the section bar already replaced for exactly the
 * three marks beside them.
 */
const CONTROL_TIP_SELECTOR = '.card-refresh[data-lh-tip], .rowopen[data-lh-tip]';

/**
 * The same publisher serves a facet value the column had to cut — see markValueTips().
 *
 * Kept as its own list rather than appended to the one above, because those two controls are
 * ALWAYS marked (their text is a hint for a wordless glyph) while these two are marked only
 * when a measurement says the value is short of itself.
 */
const VALUE_TIP_SELECTOR = '.facet-opt[data-lh-tip], .fchip[data-lh-tip]';

/**
 * Everything one delegated listener has to recognise, composed rather than written out again.
 *
 * The two lists stay apart because they are MARKED under different rules; they are joined here
 * because they are POSITIONED under the same one, and a second `closest()` call per event would
 * be a second answer to a question with one.
 */
const CONTROL_TIP_REACH = CONTROL_TIP_SELECTOR + ', ' + VALUE_TIP_SELECTOR;

/**
 * Put that tooltip under whichever of them has just been reached.
 *
 * DELEGATED FROM THE DOCUMENT, not from a container. core.js creates the refresh controls as
 * each card loads and the views rebuild their tables on every sort and every filter, so there
 * is no set of elements to bind to at start-up — and `pointerover` and `focusin` both bubble
 * all the way up. The row opener also sits inside a table that scrolls sideways, which is the
 * same reason the section bar's box is `position: fixed` and measured when it is reached.
 *
 * The coordinates are the section bar's: a fixed box under the control, clamped so one at the
 * right-hand edge cannot open a box that runs off the window.
 */
function setUpControlTips() {
    if (document.body.dataset.lhControlTips === '1') {
        return;
    }
    document.body.dataset.lhControlTips = '1';

    const publish = (event) => {
        const target = event.target;
        if (target && typeof target.closest === 'function') {
            publishSectionTip(target.closest(CONTROL_TIP_REACH));
        }
    };

    document.addEventListener('pointerover', publish);
    document.addEventListener('focusin', publish);
}

/* ===================================================================================
 * 3b. A facet value the column had to cut
 * ================================================================================ */

/**
 * The two places a facet value is shown, and the two elements each of them needs.
 *
 * A NEW SHAPE: the tooltip is MARKED on one element and MEASURED on another. Everywhere else
 * in this module the two are the same node, but neither `.facet-val` nor `.fchip-val` can be
 * one of them — both are non-focusable `<span>`s, the component requires `:focus-visible`
 * unconditionally, and a span never takes focus. So the marker is the ancestor that is already
 * the whole target — `a.facet-opt` for a row in the panel, `a.fchip` for an applied value — and
 * the measurement is taken on the child span that actually carries the ellipsis. Declared as
 * data rather than written twice, because a third place showing a value would otherwise be a
 * third copy of the same logic.
 */
const VALUE_TIP_PARTS = [
    { marker: '.facet-opt', value: '.facet-val' },
    { marker: '.fchip', value: '.fchip-val' }
];

/**
 * Park the native bubbles that fire under the same pointer as one value tooltip.
 *
 * TWO TOOLTIPS ON ONE ELEMENT IS WHAT parkTitle() EXISTS TO PREVENT, and both of these
 * elements already own a `title`: `a.facet-opt` carries the dimension's "why" sentence, a
 * static row carries the same sentence on its `<li>`, and `a.fchip` carries "Remove this
 * filter". Every one of them explains something the reader can recover elsewhere — the why is
 * the same sentence for every value of the dimension and is in the group's own basis note, and
 * "Remove this filter" restates what pressing a chip marked with a × does — while the cut value
 * is the one thing on the row that cannot be read at all. So the value wins, and the native
 * title is parked for exactly as long as the value is cut; a value that fits keeps its title
 * untouched and gets no tooltip of ours.
 *
 * @param {HTMLElement} marker The element the tooltip is attached to.
 * @param {boolean}     cut    Whether the value inside it is truncated.
 */
function parkValueTitles(marker, cut) {
    parkTitle(marker, cut);
    const row = marker.parentElement;
    if (row && row.classList && row.classList.contains('facet-li')) {
        parkTitle(row, cut);
    }
}

/**
 * Give the panel's tooltip to every facet value the layout had to cut, and to no other.
 *
 * WHY IT IS NEEDED. `.facet-val` and `.fchip-val` both truncate with an ellipsis, and a path,
 * an AS organisation or a User-Agent is routinely longer than the column — so the reader could
 * see that something had been cut and had no way at all to read it. The native `title` on the
 * anchor did not help: it says why the DIMENSION exists, which leaves the bubble explaining the
 * category while the value stays unreadable.
 *
 * ONLY WHEN IT IS GENUINELY CUT, measured rather than assumed, because a tooltip repeating a
 * value that is fully on screen is noise the reader has to dismiss. The measurement is the
 * child span's own overflow, which is the only thing that knows whether the ellipsis is being
 * drawn — the same test the section bar makes on its labels.
 *
 * READS FIRST, THEN WRITES. The panel re-renders on every filter, every sort and every arrival
 * of data, and this runs on the same animation-frame pass everything else here uses, so the
 * measurements are taken in one sweep and applied in a second rather than interleaved, which
 * would cost one layout per row instead of one per pass.
 */
function markValueTips() {
    const seen = [];
    for (const part of VALUE_TIP_PARTS) {
        for (const marker of document.querySelectorAll(part.marker)) {
            const value = marker.querySelector(part.value);
            if (!value) {
                continue;
            }
            seen.push({
                marker: marker,
                full: (value.textContent || '').trim(),
                cut: value.scrollWidth > value.clientWidth
            });
        }
    }

    for (const entry of seen) {
        const cut = entry.cut && entry.full !== '';
        if (cut) {
            entry.marker.setAttribute('data-full', entry.full);
            entry.marker.setAttribute('data-lh-tip', '1');
        } else {
            entry.marker.removeAttribute('data-lh-tip');
            entry.marker.removeAttribute('data-full');
        }
        parkValueTitles(entry.marker, cut);
    }
}

/**
 * Park a control's `title` while the rail is collapsed, and hand it back when it expands.
 *
 * TWO TOOLTIPS ARE WORSE THAN ONE. The collapsed rail now draws the panel's own tooltip beside
 * the mark, immediately and in the panel's own type; leaving `title` in place meant the
 * browser's bubble arrived a second later, in a different place, saying something else. The
 * attribute is held in a data attribute instead of being thrown away, so the expanded rail —
 * where the label is on screen and there is no tooltip of ours — keeps the hover hint it has
 * always had, unchanged.
 */
function parkTitle(node, collapsed) {
    if (!node) {
        return;
    }
    if (collapsed) {
        const title = node.getAttribute('title');
        if (title !== null) {
            node.setAttribute(HINT_ATTR, title);
            node.removeAttribute('title');
        }
        return;
    }
    const parked = node.getAttribute(HINT_ATTR);
    if (parked !== null) {
        node.setAttribute('title', parked);
        node.removeAttribute(HINT_ATTR);
    }
}

/**
 * Keep the theme control's tooltip saying what its label says.
 *
 * The rail hides the words when it is collapsed, and a control whose only text is hidden needs
 * the same text somewhere a pointer and a screen reader can still reach. theme.js rewrites the
 * label whenever the mode changes and knows nothing about the rail, so the title follows the
 * label rather than being set once.
 */
function mirrorThemeTitle(toggle, label) {
    const sync = () => {
        const text = (label.textContent || 'Theme').trim();
        toggle.setAttribute('title', text);
        toggle.setAttribute('aria-label', text);
        parkTitle(toggle, document.documentElement.classList.contains('lh-rail-collapsed'));
    };
    sync();
    if ('MutationObserver' in window) {
        new MutationObserver(sync).observe(label, { childList: true, characterData: true, subtree: true });
    }
}

/**
 * The view a navigation link points at, taken from its own href.
 *
 * Read from the link rather than stamped on it by PHP, so the rail needs no markup change and
 * a view added to Panel\Layout::nav() gets its mark with no second list to update.
 */
function slugOf(link) {
    const href = link.getAttribute('href') || '';
    const match = href.match(/[?&]v=([a-z_]+)/);
    return match ? match[1] : '';
}

/** Has the operator asked for the labels? Absent means collapsed, which is the default. */
function isRailCollapsed() {
    try {
        return window.localStorage.getItem(RAIL_KEY) !== 'open';
    } catch (e) {
        return true;
    }
}

/** Record the choice and apply it. A storage that refuses still leaves the rail working. */
function setRail(collapsed) {
    try {
        window.localStorage.setItem(RAIL_KEY, collapsed ? 'rail' : 'open');
    } catch (e) {
        void e;
    }
    applyRail(collapsed);
}

/** Put the state on the root element, where the stylesheet and --side-w can both see it. */
function applyRail(collapsed) {
    const button = document.querySelector('.lh-railbtn');
    document.documentElement.classList.toggle('lh-rail-collapsed', collapsed);
    if (button) {
        button.setAttribute('aria-pressed', collapsed ? 'true' : 'false');
        button.setAttribute('title', collapsed ? 'Show the view names' : 'Collapse to icons');
        const label = button.querySelector('.lh-railbtn-label');
        if (label) {
            label.textContent = collapsed ? 'Expand' : 'Collapse';
        }
    }
    /* AFTER the button's own title has been written, so the state that is parked is the state
       this call just decided on rather than the one before it. */
    for (const node of document.querySelectorAll(TIP_SELECTOR)) {
        parkTitle(node, collapsed);
    }
    refresh();
}

/* ===================================================================================
 * 5. The facet panel as a left column
 * ================================================================================ */

/* ===================================================================================
 * 4b. The page toolbar, pinned under the section nav
 * ================================================================================ */

/**
 * The controls that scope the whole page, gathered into one bar that stays reachable.
 *
 * ## The defect
 *
 * The range picker, the host selector, Clear cache, the bandwidth readout and the applied
 * filters all live at the TOP of the page, and every view on this panel is several screens
 * long. An operator reading section 06 who wants the last hour instead of the last day has to
 * scroll to the top, press, and find their place again — and worse, by the time they are that
 * far down there is nothing on screen saying what the numbers they are reading are scoped TO.
 * A figure with no visible scope is a figure that will be quoted wrongly.
 *
 * ## Why the controls MOVE rather than being drawn twice
 *
 * A second copy of a control is a second thing to keep in step with the first, and the pair
 * disagree the first time one of them is re-rendered — the host selector is injected by a
 * fetch, the chips are rebuilt on every filter change. There is one of each, and it is here.
 * The page head keeps the H1 and the lead, which are not controls and must not be sticky.
 *
 * ## Why it is a sibling of `.view`
 *
 * The same reason `.set-nav` is, and it is the same trap: `.view` is a flex column, and at desk
 * width with facets it is a GRID — a sticky element inside either is sticky within its own item
 * box and has no travel at all. As a sibling of `.view` its containing block is `<main>`, so it
 * holds all the way down. It is also why it cannot overlap the facet column: the column is
 * inside `.view`, which begins below this bar, so the two occupy different bands of the page.
 *
 * ## Two sticky bars is a lot, so the second one condenses
 *
 * Stuck, it drops to a single tight row: the vertical padding halves, the bandwidth readout
 * gives up its own line and the scope line appears. On a 1440-tall desk screen the pair costs
 * about 88px; on a 375-wide phone the condensed form is what keeps that under control. The
 * `.is-stuck` class is set from a measurement rather than assumed, because the bar is only
 * stuck once the page has scrolled past it and a bar that condensed at rest would be a
 * different design.
 *
 * @returns {(function(): void)|null} A re-measure for the frame loop, or null with no toolbar.
 */
function setUpPageTools() {
    const main = document.getElementById('main') || document.querySelector('main');
    const view = document.querySelector('.view');
    if (!main || !view) {
        return null;
    }

    let bar = document.getElementById('lh-page-tools');
    if (!bar) {
        bar = el('div', { class: 'page-tools', id: 'lh-page-tools' });
        bar.appendChild(el('div', { class: 'pt-scope', id: 'lh-page-scope' }));
        main.insertBefore(bar, view);
    }

    adoptPageTools(bar);
    describeScope(bar);
    publishStuck(bar);

    /* STUCK IS A SCROLL FACT, so it is watched on scroll rather than on the frame loop this
       module's other passes use — that one wakes on resize and on rows arriving, neither of
       which happens while somebody is simply reading down the page. Passive, and it does one
       `getBoundingClientRect()` against a value the section nav already measured. */
    window.addEventListener('scroll', () => publishStuck(bar), { passive: true });

    return () => {
        adoptPageTools(bar);
        describeScope(bar);
        publishStuck(bar);
    };
}

/**
 * Take the page-level furniture into the bar, wherever it was rendered.
 *
 * IDEMPOTENT AND ORDER-INDEPENDENT, which is the whole reason it is a function and not three
 * lines inside setUpPageTools(). Two of these arrive late and neither is this module's: the
 * host selector is appended to `.head-tools` when its fetch lands, and the filter bar is
 * created by assets/js/facets.js when the boot payload says the view honours facets. Running
 * the adoption again on the frame loop costs a `parentElement` comparison per pass and removes
 * every question about which module ran first.
 *
 * A view that declares no facets never creates `#lh-filters`, so nothing is adopted and the bar
 * carries no "Filter by" — the declaration in Controller::toolbar() decides, here as everywhere
 * else, and this function never invents a control that the page would ignore.
 */
function adoptPageTools(bar) {
    const scope = bar.querySelector('.pt-scope');
    for (const selector of ['.head-tools', '#lh-filters', '#lh-readout']) {
        const node = document.querySelector(selector);
        if (node && node.parentElement !== bar) {
            bar.insertBefore(node, scope);
        }
    }

    /* The bar is furniture with nothing in it until one of those exists. An empty band under
       the section nav is two rules of chrome and no controls. */
    bar.hidden = bar.querySelector('.head-tools, #lh-filters, #lh-readout') === null;
}

/**
 * Say whether the bar has actually reached its perch, so the stylesheet can condense it.
 *
 * Measured against the section nav's published height rather than against zero, because that
 * is what it is stuck UNDER — and that height is itself measured, so a browser that resolved a
 * larger font does not leave the toolbar reporting stuck a few pixels early or late.
 */
function publishStuck(bar) {
    const root = document.documentElement;
    if (bar.hidden) {
        root.style.setProperty('--page-tools-h', '0px');
        bar.classList.remove('is-stuck');
        return;
    }
    /* ASK THE STYLESHEET WHERE THE PERCH IS, rather than working it out again here. The bar
       pins at `calc(var(--lh-topbar-h) + var(--set-nav-h))`, and a phone adds a fixed
       navigation bar to that sum — a copy of the arithmetic in this module was wrong at 375
       the moment the mobile layout put something above the section nav, and reported the bar
       unstuck for the whole page. The computed `top` of a sticky element IS that offset,
       already resolved by the engine, so there is one expression and it lives in the CSS. */
    const offset = parseFloat(window.getComputedStyle(bar).top) || 0;
    const stuck = bar.getBoundingClientRect().top <= offset + 1;
    bar.classList.toggle('is-stuck', stuck);

    /* THE JUMP OFFSET IS THE CONDENSED HEIGHT, and it is only measurable while the bar is in
       that state — so it is taken whenever it is, and kept. Every jump scrolls, and anything
       this bar has to be cleared of is below it, so by the time a target arrives the bar is
       stuck and this is the height it has. Measuring the resting height instead would push
       every heading 20-odd pixels too far down the screen on arrival. */
    if (stuck) {
        root.style.setProperty('--page-tools-h', Math.round(bar.getBoundingClientRect().height) + 'px');
    }
}

/**
 * What the numbers on this page are currently scoped to, in one line.
 *
 * THE ONE THING WORTH THE ROOM WHEN THE BAR IS CONDENSED. Scrolled into section 06, the
 * question is not "where is the range picker" — it is "am I looking at an hour or a month, one
 * host or all of them, filtered or not". The controls answer it while they are in view and
 * stop answering it the moment they are condensed, so the sentence is assembled from the same
 * controls and shown only in that state.
 *
 * Read off the DOM rather than off the boot payload, because the controls are the truth: the
 * host selector arrives from a fetch and the chips are rebuilt on every filter change, and a
 * summary derived from a payload captured at load would go stale against the very bar it sits
 * in. Nothing here is a control; it is a readout, and it is `aria-hidden` because every fact in
 * it is already announced by the control it was read from.
 */
function describeScope(bar) {
    const scope = bar.querySelector('.pt-scope');
    if (!scope) {
        return;
    }

    const parts = [];
    const range = bar.querySelector('.ranges a.on');
    if (range) {
        parts.push(range.textContent.trim());
    }

    const host = bar.querySelector('#lh-host');
    if (host) {
        parts.push(host.value === '' ? 'all hosts' : host.value);
    }

    const chips = bar.querySelectorAll('#lh-filters-active .fchip');
    if (chips.length) {
        parts.push(chips.length === 1 ? '1 filter' : chips.length + ' filters');
    }

    scope.textContent = parts.join(' · ');
    scope.setAttribute('aria-hidden', 'true');
}

/**
 * Mirror the filter panel onto the view, so the facets are a COLUMN whether or not they show.
 *
 * The "Filter by" panel is markup inside the filter bar at the top of the page, and as a block
 * it pushed every card down the screen and spread the dimensions across the full width —
 * facets on top and the content below, which is the one arrangement this panel is not allowed
 * to have on a desk screen. The panel itself is another module's, so rather than moving any
 * markup this puts classes on `.view`; the stylesheet then lays the view out as two columns
 * with the filter bar in the first one, spanning every row, and the cards in the second.
 *
 * THE COLUMN IS NOT CONDITIONAL ON THE PANEL BEING OPEN, and that is the fix. It was, and the
 * closed state therefore fell back to the full-width strip: `.filterbar` still holds the
 * applied-value chips and the show/hide control, so a shut panel meant a band of filter
 * furniture across the top with every card below it — the "horizontal block" the owner
 * reported. `has-facet-column` now says only that this view HAS a filter column, which is true
 * for exactly as long as the panel is in the document; `lh-facets-shut` says the groups are
 * hidden, and the stylesheet shrinks the track to what the chips and the button need rather
 * than moving them out of it.
 *
 * On a phone none of it applies: the two-column rules are inside `@media (min-width: 901px)`
 * and the panel stays a disclosure above the content, which is the right answer there.
 */
function watchFacetPanel() {
    const panel = document.getElementById('lh-facets-panel');
    const view = document.querySelector('.view');
    if (!panel || !view) {
        return;
    }
    const sync = () => {
        view.classList.toggle('has-facet-column', panel.isConnected);
        view.classList.toggle('lh-facets-shut', panel.hidden === true);
    };
    if ('MutationObserver' in window) {
        new MutationObserver(sync).observe(panel, { attributes: true, attributeFilter: ['hidden'] });
    }
    sync();
}

/* ===================================================================================
 * 6. Blocks that stay closed until somebody asks
 * ================================================================================ */

/**
 * Remember whether a folded block is open, per block, per browser.
 *
 * A <details> forgets on every navigation, and the panel's long technical blocks — a parsed
 * sample, a field-mapping table, the list of what a log format does not record — are things an
 * operator either always wants or never does. Re-opening them on every page load is the same
 * work every time, and closing them again is worse.
 *
 * The key is the BLOCK, not the instance: somebody who opened the field mapping for one log
 * source wanted field mappings, not that file's in particular, so all of them open together.
 * Closed is what a browser with nothing stored gets, which is the state the cards are designed
 * around.
 *
 * Delegated from the document, because a card can be re-rendered by a fetch and a listener
 * bound to the element would go with it.
 */
function setUpFolds() {
    const apply = () => {
        for (const fold of document.querySelectorAll('details.lh-keep[data-keep]')) {
            if (fold.dataset.keepWired === '1') {
                continue;
            }
            fold.dataset.keepWired = '1';
            if (foldIsOpen(fold.dataset.keep)) {
                fold.open = true;
            }
        }
    };

    document.addEventListener('toggle', (event) => {
        const fold = event.target;
        if (!fold || !fold.matches || !fold.matches('details.lh-keep[data-keep]')) {
            return;
        }
        rememberFold(fold.dataset.keep, fold.open);
        for (const other of document.querySelectorAll('details.lh-keep[data-keep="' + CSS.escape(fold.dataset.keep) + '"]')) {
            other.open = fold.open;
        }
    }, true);

    apply();
    return apply;
}

/** Has this block been opened before? Absent means closed, which is the default. */
function foldIsOpen(key) {
    try {
        return window.localStorage.getItem(FOLD_KEY + key) === 'open';
    } catch (e) {
        return false;
    }
}

/** Record the choice. A storage that refuses still leaves the block working. */
function rememberFold(key, open) {
    try {
        window.localStorage.setItem(FOLD_KEY + key, open ? 'open' : 'shut');
    } catch (e) {
        void e;
    }
}

/* ===================================================================================
 * 7. Sections: the first one open, the rest a press away
 * ================================================================================ */

/**
 * Selectors that mean "there is a problem inside this section".
 *
 * A HIDDEN PROBLEM IS THE WORST OUTCOME OF THIS WHOLE CHANGE, so a section holding any of
 * these opens regardless of the default and regardless of what the operator last chose. The
 * system check with a failing row in it must never start collapsed, and neither must a card
 * whose fetch failed, or one holding a form still waiting for a decision.
 *
 * A bare `.chip-warn` is deliberately NOT in the list, and the distinction is the point: it is
 * also the chip on the word "Note" in a sentence, and a section held open by an annotation
 * would make the whole feature useless within a week. Where a warning chip means a state
 * rather than an aside — a row of the system check, a log source awaiting review — it is
 * listed with the context that makes it one, and a form still waiting for a decision is listed
 * outright.
 *
 * A BARE `.confirm-form` IS NOT THAT DECISION, and listing it was what made this feature look
 * broken on Settings. `Panel\Settings` spells three unrelated things with that class: the
 * "looks right, start ingesting" form, which IS a pending decision; `removeForm()`, which is a
 * stop button; and the reinstall form, which is always on the page. The last two are
 * unconditional, so `set-sources` and `set-reinstall` were force-opened on every render of
 * every installation and could never show the operator what they had chosen — indistinguishable
 * from the accordion having forgotten, and exactly what `Settings::problemBanner()` warns about
 * one comment above itself: "a card that always carried the marker would be a card that never
 * folds".
 *
 * It is matched as `.confirm-form.awaiting` instead, the class Settings is adding to the one
 * form that is genuinely waiting. Nothing is uncovered in the meantime: a log source awaiting
 * review already renders `.source-head .chip-warn` ("Awaiting review") beside its form, and a
 * refusal already goes out through `problemBanner()` as `.check-row .chip-warn`, so both of the
 * states that must hold `set-sources` open are held open by a selector already on this list.
 */
const TROUBLE = '.banner-warn, .banner-bad, .card-error, .finish-bad, .beacon-stale,'
    + ' .chip-bad, .state-bad, .callout-bad, .confirm-form.awaiting, [aria-invalid="true"],'
    + ' .is-error, .check-row .chip-warn, .source-head .chip-warn';

/**
 * The page this is, for scoping a section's stored state to the view that owns it.
 *
 * `Panel\Layout::render()` stamps the view's slug on <body>, and it is the one identifier on
 * the page that is the same on every render and the same across releases. Scoping by it means
 * two views that happen to name a card the same thing can never share one stored choice, and
 * it is what makes pruning safe: a stored key can only be judged stale against the page that
 * owns it, never against whichever page the operator happens to be looking at.
 *
 * @returns {string}
 */
function viewSlug() {
    const slug = document.body ? (document.body.getAttribute('data-view') || '') : '';
    return /^[a-z0-9_-]+$/.test(slug) ? slug : 'panel';
}

/**
 * The server's own name for a section — the half of the markup that is a literal in PHP.
 *
 * `Panel\Controller::cardOpen()` emits both `data-card="<id>"` and `id="<id>-card"` from the
 * same string, and `<id>` is what a view writes by hand: it does not move when a card is
 * renumbered, retitled or reordered, and it does not change if the id convention ever does.
 * Stripping the suffix off the element id is the fallback, for the handful of cards still
 * written without going through cardOpen().
 *
 * @returns {string} '' when the card carries no stable name at all.
 */
function cardName(card) {
    const named = card.getAttribute('data-card');
    if (named) {
        return named;
    }
    const id = card.id || '';
    return id.endsWith('-card') ? id.slice(0, -'-card'.length) : id;
}

/** Where one section's stored choice lives, or '' for a card with no stable name. */
function cardStoreKey(card) {
    const name = cardName(card);
    return name === '' ? '' : CARD_KEY + viewSlug() + '.' + name;
}

/**
 * Is this card a section the accordion owns?
 *
 * THE DEFECT THIS ANSWERS, and the reason some sections remembered and some did not. The set
 * used to be `main .view > .card[id]`: a card had to be a DIRECT CHILD of the view to fold at
 * all. Bot forensics and Networks each put two cards inside a `.grid-2`, and the session
 * explorer puts two inside `.explorer`, so six cards across the panel were never registered —
 * no toggle, no stored state, and nothing for Expand all to reach. On the explorer it took the
 * whole feature down, because one registered card is fewer than the two setUpSections needs.
 * Depth is not a property of a section; being a card with a heading is.
 *
 * Two kinds of card are deliberately left out. The facet rail, because setUpFacets() already
 * gives it a disclosure of its own with its own label and its own open-when-filtered rule, and
 * two controls on one card is the bug rather than the feature. And a card that arrives `hidden`:
 * `Hosts::explainCard()` is revealed by views/hosts.js only when the range genuinely records no
 * virtual host, so it is a card that exists BECAUSE something is wrong. Folding it would hand it
 * a control nobody can press while it is hidden and then reveal it collapsed, which is the one
 * outcome this whole feature is not allowed to produce.
 */
function isSection(card) {
    return card.querySelector(':scope > .card-head > h2') !== null
        && cardName(card) !== ''
        && !card.hidden
        && card.closest('.explorer .facets') === null
        && (card.parentElement === null || card.parentElement.closest('.card') === null);
}

/**
 * Has the operator ever chosen anything on THIS page?
 *
 * The first-section-open default is for somebody who has never touched the page, so it is
 * asked once per view rather than once per card: a section added by a later release must open
 * nothing and move nothing for an operator who already arranged the page to their liking.
 *
 * Asked after the stale keys are gone, so a release that renamed every section on a page
 * leaves that page as one nobody has touched rather than one arranged into nothing.
 */
function viewHasChoices() {
    const mine = CARD_KEY + viewSlug() + '.';
    try {
        for (let i = 0; i < window.localStorage.length; i++) {
            const key = window.localStorage.key(i);
            if (key !== null && key.startsWith(mine)) {
                return true;
            }
        }
    } catch (e) {
        return false;
    }
    return false;
}

/**
 * Every view the product still has, read off the navigation.
 *
 * The sidebar lists all of them and each link carries its own slug, which is where slugOf()
 * already gets the icon rail's marks from. Reading it rather than hard-coding a list means a
 * view added to `Panel\Layout::nav()` is known here with no second list to keep in step.
 *
 * @returns {string[]} Empty when the navigation is not on the page, which is the signal to
 *                     retire nothing rather than to retire everything.
 */
function knownViews() {
    const slugs = [];
    for (const link of document.querySelectorAll('nav.side ul li a')) {
        const slug = slugOf(link);
        if (slug !== '' && slugs.indexOf(slug) === -1) {
            slugs.push(slug);
        }
    }
    return slugs;
}

/**
 * Retire stored choices that cannot belong to any view this release has.
 *
 * WHAT THIS DELIBERATELY DOES NOT DO, and the defect that taught it. It used to retire any key
 * in this page's namespace naming a section that was not on the page — and a section being
 * absent from ONE render does not mean it is gone. `Controller::pivotCard()` returns without
 * emitting anything when a view has no pivot pairing; the three Opensolr views replace their
 * whole set with one explainer when the account is not configured; a card can be conditional on
 * the data or on the query string. Pruning against what happens to be on screen therefore
 * deleted the operator's choice for a card that was merely not there this time, and the card
 * came back at its default the next time it appeared. Measured on Overview: `ov-pivot` stored
 * as open, one render without the card, and the choice was gone.
 *
 * So a key is retired only when it cannot be about a live section AT ALL:
 *
 *  - it has no view segment — `lh.card.set-solr-card`, the shape from before the choice was
 *    scoped to a view, which this release cannot read; or
 *  - its view segment names a view the product no longer has.
 *
 * A section renamed within a view that still exists therefore leaves one dead key behind. That
 * is bounded by the number of names a view has ever had, and it is the cheap side of the trade:
 * the other side deletes a choice the operator made and is still making use of.
 */
function pruneCardKeys() {
    const views = knownViews();
    try {
        const stale = [];
        for (let i = 0; i < window.localStorage.length; i++) {
            const key = window.localStorage.key(i);
            if (key === null || !key.startsWith(CARD_KEY)) {
                continue;
            }
            const rest = key.slice(CARD_KEY.length);
            const dot = rest.indexOf('.');
            if (dot === -1) {
                stale.push(key);
            } else if (views.length > 0 && views.indexOf(rest.slice(0, dot)) === -1) {
                stale.push(key);
            }
        }
        for (const key of stale) {
            window.localStorage.removeItem(key);
        }
    } catch (e) {
        void e;
    }
}

/**
 * Turn every card on the page into a section that can be collapsed, with the first one open.
 *
 * WHY THIS IS HERE AND NOT IN THE MARKUP. `Panel\Controller::cardOpen()` emits a card as a
 * heading followed by its content, and that is the right shape — it works with no script, it
 * prints, and it is what the section nav's anchors point at. An accordion needs a region to
 * toggle and a control to toggle it with, and both are built here from that same markup, so
 * the server keeps emitting one thing and nothing about a card has to know it can fold.
 *
 * THE HEADING STAYS THE HEADING. The h2 keeps its level, its number and its accent; what goes
 * inside it is a button, which is the pattern that gets an accordion keyboard support and
 * `aria-expanded` without inventing either. The card's tools — a live count, a range control —
 * stay in the head and stay visible while the section is shut, because a collapsed section
 * should still be able to tell you whether it is worth opening.
 *
 * WHAT IS OPEN ON ARRIVAL. Whatever the operator last chose on this page; failing that, the
 * first section on a page they have never touched and nothing else; and, over the top of
 * either, any section with trouble in it. The trouble rule changes what is on the screen for
 * this render and never what is in storage — see setCard() and persistChoices().
 *
 * A CARD THAT FAILS OPENS ITSELF. Cards fetch their data after this runs, so the arrival check
 * only ever saw a page that had loaded nothing yet. A card that failed while collapsed kept
 * its error, its message and its retry button inside a region with `display: none`, and the
 * operator saw a shut heading with no reason to open it. core.js announces the failure on
 * `lh:card-trouble`; this is what acts on it.
 *
 * THE SECTION NAV MUST OPEN WHAT IT JUMPS TO, for the same reason: a bar that scrolls to a
 * collapsed heading has moved the reader and shown them nothing. That listener is on the
 * document so it survives the bar being re-rendered, and it does not preventDefault — the
 * anchor still does the scrolling, this only makes sure there is something to scroll to.
 */
function setUpSections() {
    const cards = Array.from(document.querySelectorAll('main .view .card')).filter(isSection);
    if (cards.length < 2) {
        return null;
    }

    pruneCardKeys();
    const untouched = !viewHasChoices();
    cards.forEach((card, index) => foldCard(cards, card, untouched && index === 0));
    document.documentElement.classList.add('lh-sections');
    addExpandAll(cards);
    openFromHash();

    window.addEventListener('hashchange', openFromHash);

    document.addEventListener('lh:card-trouble', (event) => {
        const id = event.detail && event.detail.id;
        if (id) {
            forceCard(document.getElementById(id + '-card'));
        }
    });

    document.addEventListener('click', (event) => {
        const link = event.target.closest ? event.target.closest('.set-nav a[href^="#"]') : null;
        if (link) {
            forceCard(document.getElementById(link.getAttribute('href').slice(1)));
        }
    });

    return () => cards.forEach((card) => { if (hasTrouble(card)) { forceCard(card); } });
}

/**
 * Give one card a toggle and a region.
 *
 * Everything after the head becomes the region, so the pop line, the loading state, the
 * content and the empty state all travel together and a view that appends to the card later
 * still finds its own ids — nothing is cloned or rewritten, only moved one level down.
 *
 * The state the operator chose is written onto the element as `data-fold-chosen` and kept
 * there. It is deliberately NOT the same thing as whether the section is open: a section held
 * open by a warning is open on screen while its choice stays whatever they last pressed, which
 * is what lets the section go back to that choice the moment the warning clears.
 *
 * @param {HTMLElement[]} cards Every section on the page, for the press handler.
 * @param {HTMLElement}   card  The card to wire.
 * @param {boolean}       first Whether this card gets the never-touched-this-page default.
 */
function foldCard(cards, card, first) {
    if (card.dataset.foldWired === '1') {
        return;
    }
    card.dataset.foldWired = '1';

    const head = card.querySelector(':scope > .card-head');
    const heading = head.querySelector('h2');
    const region = el('div', { class: 'card-region', id: (card.id || cardName(card)) + '-region' });

    let node = head.nextSibling;
    while (node) {
        const next = node.nextSibling;
        region.appendChild(node);
        node = next;
    }
    card.appendChild(region);

    const button = el('button', {
        type: 'button',
        class: 'card-toggle',
        'aria-expanded': 'true',
        'aria-controls': region.id
    });
    while (heading.firstChild) {
        button.appendChild(heading.firstChild);
    }
    heading.appendChild(button);

    button.addEventListener('click', () => {
        const open = !isCardOpen(card);
        chooseCards(cards, (other) => (other === card ? open : null));
    });

    const remembered = rememberedCard(card);
    const chosen = remembered === null ? first : remembered;
    card.dataset.foldChosen = chosen ? 'open' : 'shut';
    setCard(card, hasTrouble(card) || chosen);
}

/**
 * Is anything inside this card telling the operator something is wrong?
 *
 * THE DEFECT THIS ANSWERS, and why the operator's choice never survived a reload. A section
 * held open by trouble is deliberately not recorded as a choice, so that it can go back to
 * what they last pressed once the trouble clears. That is correct — but the selectors that
 * decide what trouble IS matched data as well as diagnostics. `chip-bad` is the chip Bot
 * forensics puts on an undeclared crawler, Index analytics on a 4xx, and Who is querying on a
 * bot; `state-bad` is a value in a definition list. So on any view whose data contained one
 * bad row, every card reopened itself on every load, and Collapse all could never stick.
 *
 * A diagnostic never lives inside a table: it is a banner, a check row, a source head, or a
 * value in a card's own summary. Data is what lives in tables. Excluding table content is what
 * separates the two without having to enumerate every chip the views will ever render, which
 * is the enumeration that has now failed twice.
 */
function hasTrouble(card) {
    const region = card.querySelector(':scope > .card-region') || card;
    for (const node of region.querySelectorAll(TROUBLE)) {
        if (node.hidden || node.offsetParent === null) {
            continue;
        }
        if (node.closest('table, .lh-dialog')) {
            continue;
        }
        return true;
    }
    return false;
}

/** Is this section currently open? */
function isCardOpen(card) {
    return !card.classList.contains('is-shut');
}

/**
 * Open or close one section ON SCREEN, and nothing else.
 *
 * It writes no storage. That is the whole guard: every path that opens a section on the page's
 * behalf rather than the operator's — a fetch that failed, a jump from the section nav, a deep
 * link, a warning found on arrival — goes through here and therefore cannot leave a mark the
 * operator never made. A choice reaches storage only through persistChoices().
 *
 * A call that would not change anything returns early, because setCard() asks for a layout
 * pass and the layout pass re-checks for trouble: a section already open with a warning in it
 * would otherwise re-open itself on every animation frame, for as long as the page was up.
 *
 * Toggling re-runs the layout pass, because a table or a chart inside a section that was shut
 * measured zero and has to be measured again now that it has a width.
 */
function setCard(card, open) {
    if (!card || card.dataset.foldWired !== '1' || isCardOpen(card) === open) {
        return;
    }
    card.classList.toggle('is-shut', !open);
    const button = card.querySelector(':scope > .card-head .card-toggle');
    if (button) {
        button.setAttribute('aria-expanded', open ? 'true' : 'false');
    }
    refresh();
}

/**
 * Open a section because the page demands it, WITHOUT recording it as a choice.
 *
 * A section forced open because it holds a failure, or because a link pointed at it, is not
 * the operator expressing a preference about that section. It is open for this render; the
 * choice underneath it is untouched, and the section returns to it as soon as the reason goes.
 */
function forceCard(card) {
    setCard(card, true);
}

/** What the operator last chose for this section on this page, or null if they never have. */
function rememberedCard(card) {
    const key = cardStoreKey(card);
    if (key === '') {
        return null;
    }
    try {
        const value = window.localStorage.getItem(key);
        return value === null ? null : value === 'open';
    } catch (e) {
        return null;
    }
}

/**
 * Apply a press, then write the page's shape to storage.
 *
 * Every section is written, not only the one pressed, which is what makes Expand all and
 * Collapse all survive a reload and what pins a page the first time it is touched — after
 * that, a section added by a later release is the only one without a stored choice, and it
 * gets the shut default rather than shuffling the sections the operator arranged.
 *
 * @param {HTMLElement[]} cards Every section on the page.
 * @param {function(HTMLElement): (boolean|null)} pick The new state for a card, or null to
 *                                                     leave that one as it is.
 */
function chooseCards(cards, pick) {
    for (const card of cards) {
        const open = pick(card);
        if (open !== null) {
            card.dataset.foldChosen = open ? 'open' : 'shut';
            setCard(card, open);
        }
    }
    persistChoices(cards);
}

/**
 * Write every section's CHOICE to storage — the only place in this module that writes one.
 *
 * The value comes off `data-fold-chosen`, which a press sets and nothing else does, rather
 * than off the screen. That is what keeps a force-opened section out of storage: a card held
 * open by a warning still records the state the operator last put it in.
 */
function persistChoices(cards) {
    try {
        for (const card of cards) {
            const key = cardStoreKey(card);
            if (key !== '') {
                window.localStorage.setItem(key, card.dataset.foldChosen === 'open' ? 'open' : 'shut');
            }
        }
    } catch (e) {
        void e;
    }
}

/**
 * Open whatever the URL's fragment points at.
 *
 * Deep links into a section exist in the product and in the documentation, and a link that
 * lands on a collapsed heading has taken the reader somewhere and shown them nothing. Runs on
 * load and on every hash change.
 */
function openFromHash() {
    const id = window.location.hash.slice(1);
    if (!id) {
        return;
    }
    const target = document.getElementById(id);
    const card = target ? target.closest('.card[id]') : null;
    if (card) {
        forceCard(card);
        window.requestAnimationFrame(() => card.scrollIntoView({ block: 'start' }));
    }
}

/**
 * The control that opens everything.
 *
 * BROWSER FIND DOES NOT SEE COLLAPSED CONTENT, and Settings is a page people search for the
 * name of a setting. That makes this control part of the feature rather than a convenience:
 * without it, collapsing sections would have quietly removed Ctrl-F from the longest page in
 * the panel. It sits in the section nav, which is the one piece of chrome every page with
 * more than one section already has, and it says which way it will go.
 *
 * It is a press like any other, so it goes through chooseCards() and every section it moved is
 * in storage by the time the page is next loaded — including the ones a `.grid-2` or the
 * session explorer used to keep out of the accordion's reach entirely.
 */
function addExpandAll(cards) {
    const nav = document.getElementById('lh-section-nav');
    if (!nav || nav.querySelector('.lh-expandall')) {
        return;
    }
    const button = el('button', { type: 'button', class: 'lh-expandall' }, 'Expand all');
    button.addEventListener('click', () => {
        const open = cards.some((card) => !isCardOpen(card));
        chooseCards(cards, () => open);
        button.textContent = open ? 'Collapse all' : 'Expand all';
    });
    nav.appendChild(button);
}

/* ===================================================================================
 * Wiring
 * ================================================================================ */

/**
 * Re-evaluate everything the viewport decides, once per frame at most.
 *
 * A resize fires continuously while a phone's address bar collapses and on every rotation
 * frame, and each pass measures layout, so it is coalesced onto one animation frame.
 */
let pending = false;
function refresh() {
    if (pending) {
        return;
    }
    pending = true;
    window.requestAnimationFrame(() => {
        pending = false;
        publishBarHeight(document.querySelector('nav.side'));
        if (applyFolds) {
            applyFolds();
        }
        if (recheckTrouble) {
            recheckTrouble();
        }
        /* THE SAME ENTRY CROSSES THE LINE AS THE WINDOW CHANGES: the bar scrolls sideways and
           its labels are not cut by a width, so whether one is short of its full text is a
           measurement, and a measurement taken once at load is wrong by the first resize. */
        if (remeasureTips) {
            remeasureTips();
        }
        if (refreshPageTools) {
            refreshPageTools();
        }
        restack();
    });
}

/**
 * Watch for rows arriving.
 *
 * Every view replaces the contents of its cards when data arrives, when the reader sorts, and
 * when a filter changes, so a one-off pass over the tables at load time would label the rows
 * of an empty table and nothing else. childList only: the attributes this module writes must
 * not wake the observer that wrote them.
 */
function watch() {
    if (observer || !('MutationObserver' in window)) {
        return;
    }
    observer = new MutationObserver(() => {
        if (!stamping) {
            refresh();
        }
    });
    observer.observe(document.body, { childList: true, subtree: true });
}

/**
 * Start.
 *
 * The navigation and the facet rail are set up once; the table pass runs whenever the
 * viewport or the rows change. Nothing here waits on a network request, so the bar is a bar
 * before the first number lands.
 */
function start() {
    setUpNav();
    setUpRail();
    setUpFacets();
    refreshPageTools = setUpPageTools();
    watchFacetPanel();
    applyFolds = setUpFolds();
    recheckTrouble = setUpSections();

    /* ONE RE-MEASURE OWNER for both kinds of cut text, so the section bar's labels and the
       facet values are re-checked on the same animation frame rather than through a second
       mechanism invented beside this one. */
    const remeasureSections = setUpSectionTips();
    remeasureTips = () => {
        if (remeasureSections) {
            remeasureSections();
        }
        markValueTips();
    };
    setUpControlTips();
    markValueTips();
    restack();
    watch();

    window.addEventListener('resize', refresh);
    window.addEventListener('orientationchange', refresh);
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start, { once: true });
} else {
    start();
}
