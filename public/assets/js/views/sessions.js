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
import { renderLinkPager } from '../pager.js';
import { fillVisits } from '../visits.js';

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

export default function init() {
    loadResults();
}
