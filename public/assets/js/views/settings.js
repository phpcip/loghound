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

import { api, byId, dec, el, num, post, reattachJob, runJob, when } from '../core.js';

/** Human titles for the job kinds this view can start. */
const JOB_TITLES = {
    solr_connection: 'Solr connection check',
    opensolr_check: 'Opensolr credential check',
    retention_preview: 'Retention preview',
    source_rescan: 'Log source scan',
    destructive_uninstall: 'Removing Loghound'
};

/** The job kind that removes this installation. Named once, used three times below. */
const UNINSTALL = 'destructive_uninstall';

/**
 * Job kinds whose result is a change to this page, keyed to the flash to land on.
 *
 * A scan rewrites the detection report the source review is rendered from, so the markup
 * on screen is stale the moment it finishes. Reloading is the honest end of that operation;
 * leaving the old cards up under a green "finished" panel is not.
 */
const RELOAD_AFTER = {
    source_rescan: '?v=settings&s=sources&ok=sources_rescanned'
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
 * Run the destructive uninstall, when the server says this browser confirmed it.
 *
 * WHY IT STARTS BY ITSELF. The confirmation already happened: the operator typed the words and,
 * where two-factor is on, produced a current code, and the server answered that POST by arming
 * a one-time grant and redirecting back here. A second button at this point would be a second
 * confirmation nobody asked for, sitting in front of an operation the operator has already
 * confirmed twice. The marker is emitted only in that armed state, and `job_start` spends the
 * arm, so a reload cannot start a second run and a page load that did not follow a confirmation
 * cannot start one at all.
 *
 * REATTACH, NEVER RESTART, on the other marker. A reload in the middle of a teardown lands
 * there: the arm was spent when the run began, so there is nothing to start and everything to
 * watch. The server holds the state, so the page picks the same job back up at the step it had
 * reached — and a start from that path would be refused anyway, because the arm is gone.
 *
 * WHERE IT ENDS. A finished run has deleted config/loghound.php, so this installation no longer
 * exists and every route on it is the installer. The browser is sent there rather than left
 * looking at a panel that is gone. A run that STOPPED is left on screen with its diagnostic
 * block, because nothing local was removed at any point one of those fires and the operator
 * needs to read why.
 */
function initUninstall() {
    const mount = byId('job-uninstall');
    if (!mount) {
        return;
    }

    const options = {
        title: JOB_TITLES[UNINSTALL],
        onDone: (job) => {
            if (job && job.state === 'done') {
                window.location.assign('./');
            }
        }
    };

    if (mount.dataset.uninstallArmed === '1') {
        runJob(UNINSTALL, 'job-uninstall', options);
        return;
    }

    if (mount.dataset.uninstallRunning === '1') {
        reattachJob(UNINSTALL, 'job-uninstall', options).catch(() => {});
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

    /* TWO PAGES ASK THIS QUESTION, AND ONLY ONE OF THEM WAS ALLOWED TO. Settings is split into
       sections that render one at a time, so the Beacon section's three elements do not exist
       while Finish setup is on screen — and this guard demanded all three before doing anything.
       On Finish setup it returned immediately, paintFinishBeacon() was never reached, and the
       card sat on the "Beacon: checking" that PHP had written into it, permanently, on the one
       page whose entire job is to say whether setup is done. Either set is enough now. */
    const finish = byId('finish-beacon');
    if ((!box || !label || !detail) && !finish) {
        return;
    }

    let data;
    try {
        data = await api('settings', 'beacon');
    } catch (err) {
        /* A RETRY, because page-reload was the only way back. This box is not inside a
           loadCard(), so nothing else on the page offers one for it — and "status unknown" with
           a Solr message under it is precisely the state an operator wants to try again from. */
        /* Whichever of the two boxes is on this page gets the failure and the retry; the other
           one is not in the document and is skipped rather than thrown at. */
        const failLabel = label || byId('finish-beacon-label');
        const failDetail = detail || byId('finish-beacon-detail');
        const failBox = box || finish;

        if (failBox) {
            failBox.className = box ? 'beacon-status beacon-none' : 'finish-state finish-bad';
        }
        if (failLabel) {
            failLabel.textContent = 'Beacon: status unknown';
        }
        if (failDetail) {
            const again = el('button', { type: 'button', class: 'small', text: 'Try again' });
            again.addEventListener('click', () => {
                again.disabled = true;
                if (failLabel) {
                    failLabel.textContent = 'Beacon: asking\u2026';
                }
                loadBeaconStatus();
            });
            failDetail.replaceChildren(
                document.createTextNode('Could not ask the sessions core: '
                    + (err && err.message ? err.message : err) + ' '),
                again
            );
        }
        return;
    }

    const status = data.beacon || {};
    const live = status.hour > 0;
    const everSeen = status.ever > 0;

    /* GUARDED FOR THE SAME REASON THE GUARD ABOVE WAS RELAXED. On Finish setup these three do
       not exist — only the finish-* set does — and writing to them unconditionally would throw
       before paintFinishBeacon() ever ran, which is the failure this whole change exists to
       remove. Each page paints the box it has. */
    if (box) {
        box.className = 'beacon-status ' + (live ? 'beacon-live' : (everSeen ? 'beacon-stale' : 'beacon-none'));
    }
    if (label) {
        label.textContent = beaconLabel(live, everSeen);
    }

    if (detail) {
        detail.replaceChildren(...(everSeen
            ? beaconDetail(status)
            : [document.createTextNode(
                'No session in the last 30 days has carried beacon data. If you have just added the snippet, '
                + 'load a page on your site and refresh this view.'
            )]));
    }

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
    label.textContent = beaconLabel(live, everSeen);

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
 * The one sentence that says what the beacon is doing, used by BOTH places that say it.
 *
 * There were two of these, on one page, off one fetch, disagreeing on capitalisation and on
 * wording: "Beacon: Receiving data" against "Beacon: receiving data", and "Never seen" against
 * "never seen". The window is named too — "Never seen" reads as "not since installation", when
 * what was measured is the last thirty days, which is what the detail line underneath it had
 * been saying all along.
 */
function beaconLabel(live, everSeen) {
    if (live) {
        return 'Beacon: receiving data';
    }
    return everSeen
        ? 'Beacon: seen, but not in the last hour'
        : 'Beacon: not seen in the last 30 days';
}

/**
 * Build the beacon detail line: recent counts, last arrival and coverage.
 *
 * Every figure goes through the shared formatters. `status.hour.toLocaleString('en-US')` was
 * the only number in the panel not routed through num(), and it threw a TypeError on a null —
 * inside a loader that is not a card, so the box would have been left reading "status unknown"
 * for ever with the reason only in the console. `status.coverage` was printed raw, so a
 * coverage of five sixths rendered as 83.33333333333333%.
 */
function beaconDetail(status) {
    const parts = [
        document.createTextNode(
            num(status.hour) + ' sessions in the last hour · ' +
            num(status.day) + ' in the last 24 hours'
        )
    ];
    if (status.last) {
        parts.push(document.createTextNode(' · last at '));
        parts.push(el('span', { class: 'mono', text: when(status.last) }));
    }
    if (status.coverage !== null && status.coverage !== undefined) {
        parts.push(document.createTextNode(' · '));
        parts.push(el('span', { class: 'mono', text: dec(status.coverage, 1) + '%' }));
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
 * Fill the Opensolr region menu with what this account may actually use.
 *
 * THE MENU IS AN AFFORDANCE, NEVER THE VALIDATION. The region field used to be free text,
 * checked only when the form was submitted — so an operator had to know the platform's own
 * spelling and found out they did not by being refused. The list belongs to the account and
 * costs a control-plane call, so it is asked for AFTER the page has rendered: the markup carries
 * the stored value, this adds the rest, and the save path still refuses a region the account
 * cannot use exactly as it did before.
 *
 * A FAILURE LEAVES THE FIELD USABLE. With no credentials, no network or a refused key there is
 * no list; `data-free` on the select means assets/js/smartselect.js keeps a typed value, so the
 * operator is back to the free-text field they had. The reason is printed under it, because a
 * menu that silently has one option in it looks like a plan with one region.
 */
function loadRegions() {
    const select = byId('opensolr_region');
    if (!select) {
        return;
    }

    api('settings', 'regions').then((data) => {
        const known = new Set(Array.prototype.map.call(select.options, (option) => option.value));
        for (const region of (data.regions || [])) {
            if (!known.has(region)) {
                select.appendChild(el('option', { value: region, text: region }));
            }
        }
        const note = byId('opensolr_region_note');
        if (note && data.note) {
            note.appendChild(el('span', { class: 'faint', text: ' ' + data.note }));
        }
    }).catch((err) => {
        const note = byId('opensolr_region_note');
        if (note) {
            note.appendChild(el('span', {
                class: 'faint',
                text: ' The list of regions could not be read (' + String(err && err.message ? err.message : err)
                    + '), so type one.'
            }));
        }
    });
}

/**
 * Fill every hostname select on the exclusions card from what has actually been recorded.
 *
 * One fetch for the whole card however many rules are on it, because the answer is the same for
 * all of them. Options are appended rather than replaced, so the value a rule already carries
 * survives even when that host has since stopped appearing in the index.
 *
 * Silent on failure, and deliberately: the selects are `data-free`, so no list means the
 * operator types the hostname exactly as they would have anyway. A red line under a control
 * that still works would be reporting a problem that is not one.
 */
function loadExclusionHosts() {
    const selects = document.querySelectorAll('select[data-lh-hosts]');
    if (!selects.length) {
        return;
    }

    api('settings', 'hosts').then((data) => {
        const hosts = Array.isArray(data.hosts) ? data.hosts : [];
        if (!hosts.length) {
            return;
        }
        for (const select of selects) {
            const known = new Set(Array.prototype.map.call(select.options, (option) => option.value));
            for (const host of hosts) {
                if (!known.has(host)) {
                    select.appendChild(el('option', { value: host, text: host }));
                }
            }
        }
    }).catch(() => {});
}

/**
 * Entry point.
 */
export default function init() {
    initTabs();
    initSubmitGuards();
    initJobButtons();
    reattachRunningJobs();
    initUninstall();
    loadBeaconStatus();
    loadRegions();
    loadExclusionHosts();
}
