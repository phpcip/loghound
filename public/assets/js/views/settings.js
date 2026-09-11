/*
 * Loghound — Settings view.
 *
 * The forms are server-rendered and post normally, so the page works with JavaScript
 * disabled. What this module adds is the parts that cannot be synchronous:
 *
 *  - The long operations. Testing a Solr connection, validating Opensolr credentials and
 *    previewing retention all run as stepped jobs — start, poll, render progress, report
 *    per-step results — because doing any of them inside one request risks a gateway
 *    timeout on a slow or unreachable backend.
 *  - The beacon status, which used to be a blocking Solr query during page render.
 *  - The snippet tabs and the copy buttons.
 */

'use strict';

import { api, byId, el, post, reattachJob, runJob, when } from '../core.js';

/** Human titles for the job kinds this view can start. */
const JOB_TITLES = {
    solr_connection: 'Solr connection check',
    opensolr_check: 'Opensolr credential check',
    retention_preview: 'Retention preview',
    source_rescan: 'Log source scan'
};

/**
 * Job kinds whose result is a change to this page, keyed to the flash to land on.
 *
 * A scan rewrites the detection report the source review is rendered from, so the markup
 * on screen is stale the moment it finishes. Reloading is the honest end of that operation;
 * leaving the old cards up under a green "finished" panel is not.
 */
const RELOAD_AFTER = {
    source_rescan: '?v=settings&ok=sources_rescanned#set-sources'
};

/**
 * Wire the buttons that start long operations.
 *
 * A button is disabled while its job runs, and the server returns the already-running job
 * for a kind rather than starting a second, so a double-click cannot run the work twice.
 */
function initJobButtons() {
    for (const button of document.querySelectorAll('[data-job]')) {
        const kind = button.dataset.job;
        const mount = button.dataset.mount;

        button.addEventListener('click', async () => {
            setJobButtonsBusy(kind, true);
            await runJob(kind, mount, {
                title: JOB_TITLES[kind] || 'Operation',
                onDone: (job) => {
                    setJobButtonsBusy(kind, false);
                    reloadIfPageIsNowStale(kind, job);
                }
            });
            setJobButtonsBusy(kind, false);
        });
    }
}

/**
 * Disable or restore every button that starts a given job kind.
 */
function setJobButtonsBusy(kind, busy) {
    for (const button of document.querySelectorAll('[data-job="' + kind + '"]')) {
        button.disabled = busy;
        button.setAttribute('aria-busy', busy ? 'true' : 'false');
    }
}

/**
 * Reload the page when a finished job has invalidated what is rendered on it.
 *
 * Only on a job that actually succeeded: a failed or cancelled scan leaves the report it was
 * going to replace exactly as it was, and throwing away the panel that says why it failed
 * would leave the operator with no explanation at all. The target is a fixed string from
 * RELOAD_AFTER, never anything the server sent, so nothing here can be steered into becoming
 * a redirect to somewhere else.
 */
function reloadIfPageIsNowStale(kind, job) {
    const target = RELOAD_AFTER[kind];
    if (target && job && job.state === 'done') {
        window.location.assign(target);
    }
}

/**
 * Reattach to any operation that was still running when the page was last open.
 *
 * Refreshing mid-operation must not orphan it or start a second one; the server holds the
 * state, so the page picks the same job back up at the step it had reached.
 */
function reattachRunningJobs() {
    for (const button of document.querySelectorAll('[data-job]')) {
        const kind = button.dataset.job;
        reattachJob(kind, button.dataset.mount, {
            title: JOB_TITLES[kind] || 'Operation',
            onDone: (job) => {
                setJobButtonsBusy(kind, false);
                reloadIfPageIsNowStale(kind, job);
            }
        })
            .then((found) => {
                if (found) {
                    setJobButtonsBusy(kind, true);
                }
            })
            .catch(() => {});
    }
}

/**
 * Fetch and render whether the beacon is actually receiving data.
 *
 * An operator who has pasted a snippet into a template has no way to know whether it
 * worked, and "no engaged time in the dashboard" is indistinguishable from "no traffic".
 * This answers that question after the page has rendered, so it never holds it up.
 */
async function loadBeaconStatus() {
    const box = byId('beacon-status');
    const label = byId('beacon-status-label');
    const detail = byId('beacon-status-detail');
    if (!box || !label || !detail) {
        return;
    }

    let data;
    try {
        data = await api('settings', 'beacon');
    } catch (err) {
        box.className = 'beacon-status beacon-none';
        label.textContent = 'Beacon: status unknown';
        detail.textContent = 'Could not ask the sessions core: ' + (err && err.message ? err.message : err);
        return;
    }

    const status = data.beacon || {};
    const live = status.hour > 0;
    const everSeen = status.ever > 0;

    box.className = 'beacon-status ' + (live ? 'beacon-live' : (everSeen ? 'beacon-stale' : 'beacon-none'));
    label.textContent = 'Beacon: ' + (live ? 'Receiving data' : (everSeen ? 'Not seen in the last hour' : 'Never seen'));

    detail.replaceChildren(...(everSeen
        ? beaconDetail(status)
        : [document.createTextNode(
            'No session in the last 30 days has carried beacon data. If you have just added the snippet, load a ' +
            'page on your site and refresh this view.'
        )]));

    paintFinishBeacon(status, live, everSeen);
}

/**
 * Report the same beacon fact in the "Finish setting up" card at the top of the page.
 *
 * ONE FETCH, TWO PLACES. The card exists so that an operator who never saw the installer's
 * last screen can still find out that the beacon was never added, and asking the sessions
 * core a second time for an answer already in hand would be a second Solr query for nothing.
 *
 * Never having seen the beacon opens the commands block, because that is the case the card
 * was built for. It is only ever opened, never closed: an operator who expanded it to read
 * something must not have it collapse underneath them when this request lands.
 */
function paintFinishBeacon(status, live, everSeen) {
    const box = byId('finish-beacon');
    const label = byId('finish-beacon-label');
    const detail = byId('finish-beacon-detail');
    if (!box || !label || !detail) {
        return;
    }

    box.className = 'finish-state ' + (everSeen ? 'finish-ok' : 'finish-bad');
    label.textContent = everSeen
        ? (live ? 'Beacon: receiving data' : 'Beacon: seen, but not in the last hour')
        : 'Beacon: never seen';

    detail.replaceChildren(...(everSeen
        ? beaconDetail(status)
        : [document.createTextNode(
            'No session in the last 30 days has carried beacon data, so the snippet below has either not been ' +
            'added or is not loading. The beacon is optional, and Loghound keeps working without it.'
        )]));

    const all = byId('finish-all');
    if (all && !everSeen) {
        all.open = true;
    }
}

/**
 * Build the beacon detail line: recent counts, last arrival and coverage.
 */
function beaconDetail(status) {
    const parts = [
        document.createTextNode(
            status.hour.toLocaleString('en-US') + ' sessions in the last hour · ' +
            status.day.toLocaleString('en-US') + ' in the last 24 hours'
        )
    ];
    if (status.last) {
        parts.push(document.createTextNode(' · last at '));
        parts.push(el('span', { class: 'mono', text: when(status.last) }));
    }
    if (status.coverage !== null && status.coverage !== undefined) {
        parts.push(document.createTextNode(' · '));
        parts.push(el('span', { class: 'mono', text: status.coverage + '%' }));
        parts.push(document.createTextNode(' of sessions that were served a page'));
    }
    return parts;
}

/**
 * Wire the install-snippet tabs.
 *
 * Roving selection with arrow-key support, because a tab strip that only responds to a
 * mouse is a tab strip half the operators cannot use. No inline handlers: the CSP forbids
 * them and the listeners are attached here.
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
        tab.addEventListener('keydown', (event) => {
            const index = tabs.indexOf(tab);
            let next = null;
            if (event.key === 'ArrowRight') {
                next = tabs[(index + 1) % tabs.length];
            } else if (event.key === 'ArrowLeft') {
                next = tabs[(index - 1 + tabs.length) % tabs.length];
            }
            if (next) {
                event.preventDefault();
                select(next.dataset.tab);
                next.focus();
            }
        });
    }

    const active = tabs.find((tab) => tab.classList.contains('on')) || tabs[0];
    if (active) {
        select(active.dataset.tab);
    }
}

/**
 * Stop a settings form being submitted twice by an impatient double-click.
 */
function initSubmitGuards() {
    for (const form of document.querySelectorAll('form[method="post"]')) {
        form.addEventListener('submit', () => {
            for (const button of form.querySelectorAll('button[type="submit"]')) {
                button.disabled = true;
                button.setAttribute('aria-busy', 'true');
            }
        });
    }
}

/**
 * Entry point.
 */
export default function init() {
    initTabs();
    initSubmitGuards();
    initJobButtons();
    reattachRunningJobs();
    loadBeaconStatus();
}
