/*
 * Loghound — Session explorer.
 *
 * The visit table, in the five columns every visit table in this product shows: date, address,
 * country, page, verdict. The rows are built by assets/js/visits.js, which is the single
 * renderer the dimension dialog, the fingerprint dialog, the virtual-host dialog and the
 * population dialogs also go through — so the explorer cannot drift into having a table of its
 * own shape again.
 *
 * WHAT THIS PAGE KEEPS THAT THE DIALOGS DO NOT. The search box, the sort order and the facet
 * rail, all three of which live in the URL; and paging that also lives in the URL, because this
 * table IS the page and a page turn here should be bookmarkable, openable in a new tab and
 * survivable with scripting off. A dialog's table pages by callback instead, so turning its page
 * does not navigate away from the dialog.
 *
 * Two affordances per row, and they answer different questions. The ROW opens the record: show
 * me everything about this visit. A VALUE inside it is a link that filters the dashboard to it:
 * show me only this address, only this country. The link wins over the row because it is a real
 * anchor, which is also what makes it work with scripting off — so the verdict cell ends in an
 * explicit opener, which is the one surface that is unambiguously "the row".
 *
 * Everything rendered here came off the wire. It reaches the DOM through core.js's el({text}),
 * which is textContent, and the only href built from log data is built by url.js from a
 * validated host and a validated path.
 */

'use strict';

import { api, byId, loadCard, noDataYet, num, hideEmpty, pct } from '../core.js';
import { renderBounce } from '../bounce.js';
import { activeFilters, renderFacetPanel } from '../facets.js';
import { renderLinkPager } from '../pager.js';
import { fillVisits } from '../visits.js';

/**
 * The facet sidebar, rendered by the SHARED control.
 *
 * It used to have its own renderer, and that renderer was the one nobody recognised as a filter:
 * five lists of `label   count` in body text with no affordance, no selected state and no
 * alignment. There is one facet renderer now (assets/js/facets.js) and the sidebar, the
 * page-wide bar and the detail dialog all use it, so none of them can drift into being the
 * unrecognisable one again.
 */
function renderFacets(data) {
    const holder = byId('se-facet-list');
    if (holder) {
        renderFacetPanel(holder, data.facets, data.multi, SIDEBAR_VALUES);
    }
}

/**
 * Values shown per dimension in the narrow sidebar before "show all".
 *
 * Nineteen dimensions at twelve values each is a two-hundred-row column nobody reads to the
 * bottom of. Six is enough to see which value dominates, which is the question a facet list
 * answers, and the rest are one press away. A value that is currently SELECTED is always shown
 * regardless of where it falls in the order — a filter you cannot see is a filter you cannot
 * remove.
 */
const SIDEBAR_VALUES = 6;

/**
 * Fill the table, or say why it is empty.
 *
 * The empty slot is `se-results-empty`, which is what Controller::cardClose('se-results')
 * emits — not the table's own id with `-empty` on it, which is an element that does not exist
 * and which made the busiest view in the panel answer a filter that matched nothing with a
 * blank table and no sentence at all.
 */
function renderRows(data) {
    if (!data.docs.length) {
        fillVisits(byId('se-table'), []);
        noDataYet('se-results-empty', 'visits');
        return;
    }
    hideEmpty('se-results-empty');
    fillVisits(byId('se-table'), data.docs);
}

/**
 * Load the facet sidebar, and say whether the headline count is a filtered one.
 *
 * "117 matching" reads as a total unless it says otherwise, and on a filtered page it is not one.
 * The count line names how many filters produced it, which is the least it can do given the
 * chips are in a strip at the top of the page rather than next to this number.
 */
function loadFacets() {
    return loadCard('se-facets', 'Counting facet values', async () => {
        const data = await api('sessions', 'facets');
        renderFacets(data);

        const count = byId('se-count');
        if (count) {
            const filters = activeFilters().length;
            count.textContent = num(data.matched) +
                (filters
                    ? ' matching the ' + filters + ' active filter' + (filters === 1 ? '' : 's')
                    : ' sessions in this range') +
                ' · ' + num(data.beacon_count) + ' with beacon data (' + pct(data.beacon_count, data.matched) + ')';
        }
    });
}

/**
 * Load a page of results.
 *
 * `start` is read from the URL by the server, so the pager below the table is a set of real
 * links rather than buttons and the page the reader is on survives a reload, a bookmark and a
 * link sent to somebody else.
 */
function loadResults() {
    return loadCard('se-results', 'Searching visits', async () => {
        const data = await api('sessions', 'list');
        renderRows(data);
        renderLinkPager(byId('se-pager'), data.page);
    });
}

/**
 * Entry point.
 *
 * The table and the sidebar are separate requests: the rows appear as soon as the documents are
 * back rather than waiting on eight terms facets. The `?open=` deep link is handled by
 * detail.js, which app.js wires on every view.
 */
export default function init() {
    loadResults();
    loadFacets();
    loadCard('se-bounce', 'Measuring engagement on single-page visits', async () => {
        renderBounce('se-bounce', await api('sessions', 'bounce'));
    });
}
