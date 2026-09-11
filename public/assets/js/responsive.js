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
const FOLD_KEY = 'lh.fold.';
const CARD_KEY = 'lh.card.';

let stamping = false;
let observer = null;
let navBtn = null;
let scrim = null;
let lastFocus = null;
let applyFolds = null;
let recheckTrouble = null;

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
    if (focusable.length === 0) {
        return;
    }
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
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

    const content = card.querySelector('.card-content');
    if (content && content.id) {
        button.setAttribute('aria-controls', content.id);
    }

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
        if (!link.getAttribute('aria-label')) {
            link.setAttribute('aria-label', (link.textContent || '').trim());
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

    const button = el('button', {
        type: 'button',
        class: 'lh-railbtn',
        'aria-expanded': 'false',
        'aria-controls': (side.querySelector('ul') || {}).id || 'lh-view-list'
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

    document.documentElement.classList.add('lh-rail');
    applyRail(isRailCollapsed());
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
        button.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
        button.setAttribute('title', collapsed ? 'Show the view names' : 'Collapse to icons');
        const label = button.querySelector('.lh-railbtn-label');
        if (label) {
            label.textContent = collapsed ? 'Expand' : 'Collapse';
        }
    }
    refresh();
}

/* ===================================================================================
 * 5. The facet panel as a left column
 * ================================================================================ */

/**
 * Mirror the filter panel's open state onto the view, so the facets can be a COLUMN.
 *
 * The expanded "Filter by" panel is markup inside the filter bar at the top of the page, and
 * as a block it pushed every card down the screen and spread the dimensions across the full
 * width — facets on top and the content below, which is the one arrangement this panel is not
 * allowed to have on a desk screen. The panel itself is another module's, so rather than
 * moving any markup this watches its `hidden` attribute and puts a class on `.view`; the
 * stylesheet then lays the view out as two columns with the panel in the first one, spanning
 * every row, and the cards in the second. On a phone it stays a disclosure above the content,
 * which is the right answer there.
 */
function watchFacetPanel() {
    const panel = document.getElementById('lh-facets-panel');
    const view = document.querySelector('.view');
    if (!panel || !view || !('MutationObserver' in window)) {
        return;
    }
    const sync = () => view.classList.toggle('has-facet-column', panel.hidden !== true);
    new MutationObserver(sync).observe(panel, { attributes: true, attributeFilter: ['hidden'] });
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
 */
const TROUBLE = '.banner-warn, .banner-bad, .card-error, .finish-bad, .beacon-stale,'
    + ' .chip-bad, .state-bad, .callout-bad, .confirm-form, [aria-invalid="true"], .is-error,'
    + ' .check-row .chip-warn, .source-head .chip-warn';

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
 * WHAT IS OPEN ON ARRIVAL. The first section, and any section with trouble in it. After that
 * it is whatever the operator last chose on this page, because a default is for somebody who
 * has never touched it, not a reset applied to somebody who has.
 */
function setUpSections() {
    const cards = Array.from(document.querySelectorAll('main .view > .card[id]'))
        .filter((card) => card.querySelector(':scope > .card-head > h2'));
    if (cards.length < 2) {
        return null;
    }

    cards.forEach((card, index) => foldCard(card, index === 0));
    document.documentElement.classList.add('lh-sections');
    addExpandAll(cards);
    openFromHash();

    window.addEventListener('hashchange', openFromHash);

    /* The section nav must OPEN what it jumps to. A nav that scrolls to a collapsed heading
       has moved the reader somewhere and shown them nothing. The listener is on the document
       so it survives the bar being re-rendered, and it does not preventDefault: the anchor
       still does the scrolling, this only makes sure there is something to scroll to. */
    document.addEventListener('click', (event) => {
        const link = event.target.closest ? event.target.closest('.set-nav a[href^="#"]') : null;
        if (link) {
            setCard(document.getElementById(link.getAttribute('href').slice(1)), true);
        }
    });

    return () => cards.forEach((card) => { if (hasTrouble(card)) { setCard(card, true); } });
}

/**
 * Give one card a toggle and a region.
 *
 * Everything after the head becomes the region, so the pop line, the loading state, the
 * content and the empty state all travel together and a view that appends to the card later
 * still finds its own ids — nothing is cloned or rewritten, only moved one level down.
 */
function foldCard(card, first) {
    if (card.dataset.foldWired === '1') {
        return;
    }
    card.dataset.foldWired = '1';

    const head = card.querySelector(':scope > .card-head');
    const heading = head.querySelector('h2');
    const region = el('div', { class: 'card-region', id: card.id + '-region' });

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

    button.addEventListener('click', () => setCard(card, !isCardOpen(card), true));

    const remembered = rememberedCard(card.id);
    const open = hasTrouble(card) || (remembered === null ? first : remembered);
    setCard(card, open);
}

/** Is anything inside this card telling the operator something is wrong? */
function hasTrouble(card) {
    const region = card.querySelector(':scope > .card-region') || card;
    for (const node of region.querySelectorAll(TROUBLE)) {
        if (!node.hidden && node.offsetParent !== null) {
            return true;
        }
    }
    return false;
}

/** Is this section currently open? */
function isCardOpen(card) {
    return !card.classList.contains('is-shut');
}

/**
 * Open or close one section.
 *
 * `remember` is only true for a press: opening a section because the nav jumped to it, or
 * because a failure appeared inside it, is not the operator expressing a preference about it.
 * Toggling re-runs the layout pass, because a table or a chart inside a section that was shut
 * measured zero and has to be measured again now that it has a width.
 */
function setCard(card, open, remember) {
    if (!card || card.dataset.foldWired !== '1') {
        return;
    }
    card.classList.toggle('is-shut', !open);
    const button = card.querySelector(':scope > .card-head .card-toggle');
    if (button) {
        button.setAttribute('aria-expanded', open ? 'true' : 'false');
    }
    if (remember) {
        rememberCard(card.id, open);
    }
    refresh();
}

/** What the operator last chose for this section on this page, or null. */
function rememberedCard(id) {
    try {
        const value = window.localStorage.getItem(CARD_KEY + id);
        return value === null ? null : value === 'open';
    } catch (e) {
        return null;
    }
}

/** Record a press. */
function rememberCard(id, open) {
    try {
        window.localStorage.setItem(CARD_KEY + id, open ? 'open' : 'shut');
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
        setCard(card, true);
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
 */
function addExpandAll(cards) {
    const nav = document.getElementById('lh-section-nav');
    if (!nav || nav.querySelector('.lh-expandall')) {
        return;
    }
    const button = el('button', { type: 'button', class: 'lh-expandall' }, 'Expand all');
    button.addEventListener('click', () => {
        const open = cards.some((card) => !isCardOpen(card));
        cards.forEach((card) => setCard(card, open, true));
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
    watchFacetPanel();
    applyFolds = setUpFolds();
    recheckTrouble = setUpSections();
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
