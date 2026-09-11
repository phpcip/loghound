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

const NARROW = 900;
const STACK_ATTR = 'data-lh-col';

let stamping = false;
let observer = null;
let navBtn = null;
let scrim = null;
let lastFocus = null;

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
    setUpFacets();
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
