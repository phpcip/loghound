/**
 * Loghound — installer front end.
 *
 * Two jobs, both small:
 *
 *   1. Drive the long operations. Provisioning two Opensolr indexes takes tens of seconds
 *      and PHP-FPM will not hold a request open that long, so the server runs setup as a
 *      list of small steps and this file asks it to advance them, one budgeted request
 *      after another, while polling for progress in between. Nothing here decides what a
 *      step IS — that is entirely server-side.
 *   2. Show the custom-pattern field only when a custom pattern is being chosen.
 *
 * Constraints:
 *   - The CSP is `script-src 'self'`. No inline handlers, no eval, no new Function, no
 *     setTimeout with a string.
 *   - Everything that reaches the DOM is set with textContent. Job progress carries index
 *     names and messages from a remote API, and neither is trusted markup.
 *   - Every request carries the CSRF token, including the read-only status poll, so there
 *     is one rule rather than two.
 *
 * @license MIT
 */

/**
 * Read the server's boot payload.
 *
 * @returns {{csrf: string, jobs: Object}} Empty defaults when the block is missing.
 */
function boot() {
    const el = document.getElementById('lh-setup-boot');
    if (!el) {
        return { csrf: '', jobs: {} };
    }
    try {
        return JSON.parse(el.textContent || '{}');
    } catch (e) {
        return { csrf: '', jobs: {} };
    }
}

const BOOT = boot();

/**
 * Post to the job endpoint and return the decoded status.
 *
 * @param {string} id     Job id, as rendered into the panel's dataset.
 * @param {string} action 'run' to advance the job, 'status' to read it.
 * @returns {Promise<Object|null>} The status payload, or null when the request failed.
 */
async function jobRequest(id, action) {
    const body = new URLSearchParams();
    body.set('csrf', BOOT.csrf);
    body.set('id', id);
    body.set('action', action);

    try {
        const res = await fetch('?setup=job', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body.toString(),
            credentials: 'same-origin'
        });
        if (!res.ok) {
            return null;
        }
        return await res.json();
    } catch (e) {
        return null;
    }
}

/**
 * Format a duration for the "is it working or hung" indicator.
 *
 * A running job always shows one: on an operation that can take a minute, the difference
 * between waiting and worrying is knowing that the number is still going up.
 *
 * @param {number} seconds
 * @returns {string}
 */
function elapsedLabel(seconds) {
    if (!seconds) {
        return '';
    }
    if (seconds < 90) {
        return seconds + 's';
    }
    return Math.floor(seconds / 60) + 'm ' + (seconds % 60) + 's';
}

/**
 * Marks for each step state.
 *
 * The same glyphs the panel's own job renderer uses, so a long operation looks identical
 * in the installer and in Settings. Symbols, never emoji.
 */
const MARKS = { done: '\u2713', error: '\u2717', running: '\u2192', pending: '\u00b7' };

/**
 * Build the row for one step of a job.
 *
 * @param {Object} step
 * @returns {HTMLLIElement}
 */
function stepRow(step) {
    const li = document.createElement('li');
    li.dataset.step = step.key;

    const mark = document.createElement('span');
    mark.className = 'job-mark';
    mark.setAttribute('aria-hidden', 'true');

    const label = document.createElement('span');
    label.className = 'job-step-label';

    const note = document.createElement('span');
    note.className = 'job-step-note';

    const detail = document.createElement('span');
    detail.className = 'job-step-detail';

    li.appendChild(mark);
    li.appendChild(label);
    li.appendChild(note);
    li.appendChild(detail);
    return li;
}

/**
 * Paint one status payload into its panel.
 *
 * Steps are matched to existing rows by key and appended when they are new, because the
 * detection job grows steps as it discovers files. Every value is written with
 * textContent: progress lines carry index names and messages from a remote API, and
 * neither is trusted markup.
 *
 * @param {HTMLElement} panel
 * @param {Object} status
 */
function paint(panel, status) {
    const fill = panel.querySelector('.progress-fill');
    if (fill) {
        fill.style.width = Math.max(0, Math.min(100, status.percent || 0)) + '%';
    }

    const running = status.state === 'running';

    const meta = panel.querySelector('.job-meta');
    if (meta) {
        const where = running
            ? 'step ' + Math.min((status.complete || 0) + 1, status.total || 0) + ' of ' + (status.total || 0)
            : String(status.state || '');
        meta.textContent = where + ' \u00b7 ' + (status.elapsed || 0) + 's';
    }

    const label = panel.querySelector('.loading-label');
    if (label && Array.isArray(status.notes) && status.notes.length) {
        label.textContent = status.notes[status.notes.length - 1];
    }

    const elapsed = panel.querySelector('.loading-elapsed');
    if (elapsed) {
        elapsed.textContent = running ? elapsedLabel(status.elapsed || 0) : '';
    }

    const list = panel.querySelector('.job-steps');
    if (list && Array.isArray(status.steps)) {
        status.steps.forEach(function (step) {
            let li = list.querySelector('[data-step="' + CSS.escape(step.key) + '"]');
            if (!li) {
                li = stepRow(step);
                list.appendChild(li);
            }
            const state = step.state || 'pending';
            li.className = state === 'error' ? 'job-step-failed' : 'job-step-' + state;
            li.querySelector('.job-mark').textContent = MARKS[state] || MARKS.pending;
            li.querySelector('.job-step-label').textContent = step.label;
            li.querySelector('.job-step-note').textContent = state === 'pending' ? '' : state;
            li.querySelector('.job-step-detail').textContent = step.detail || '';
        });
    }

    panel.dataset.jobState = status.state || 'running';
}

/**
 * Reload the page once a job has finished.
 *
 * The rest of the screen is rendered server-side from the configuration that the job just
 * wrote — the detected sources, the "storage is configured" summary — so the honest way to
 * show the result is to let the server render it again.
 *
 * @param {HTMLElement} panel
 * @param {Object} status
 */
function finish(panel, status) {
    if (status.state === 'error') {
        window.location.reload();
        return;
    }
    if (status.state === 'done') {
        window.setTimeout(function () {
            window.location.reload();
        }, 700);
    }
}

/**
 * Drive one job to completion: advance it, poll it, and reload when it lands.
 *
 * The advance request is deliberately serial. A second concurrent one would be turned away
 * by the server's lock anyway, but not sending it at all keeps the reasoning simple: one
 * runner, one job, however many times the operator refreshes the page.
 *
 * @param {HTMLElement} panel
 */
async function drive(panel) {
    const id = panel.dataset.jobId;
    if (!id) {
        return;
    }

    const polling = window.setInterval(async function () {
        const status = await jobRequest(id, 'status');
        if (isJobStatus(status)) {
            paint(panel, status);
        }
    }, 1000);

    let guard = 0;
    while (guard < 60) {
        guard += 1;
        const status = await jobRequest(id, 'run');
        if (!isJobStatus(status)) {
            break;
        }
        paint(panel, status);
        if (status.state !== 'running') {
            window.clearInterval(polling);
            finish(panel, status);
            return;
        }
    }

    window.clearInterval(polling);
}

/**
 * Is this payload a job reporting on itself?
 *
 * The distinction this draws is the one the loop above used to get wrong. `jobRequest`
 * returns null when the REQUEST failed, and a status payload otherwise — and a status
 * payload always carries an `error` key, holding the job's own message and empty when there
 * is nothing wrong. Treating a populated `error` as a failed request meant that the moment a
 * job actually failed, the runner broke out without painting the failure and without
 * reloading, so the installer sat on the last frame it had drawn — reporting step 1 of 8
 * while the work behind it had already stopped. A failed job is something to SHOW, not a
 * reason to stop looking.
 *
 * A payload with no `state` is a refusal from the endpoint itself — a stale CSRF token, an
 * unknown id — and there is nothing to paint.
 *
 * @param {Object|null} status
 * @returns {boolean}
 */
function isJobStatus(status) {
    return !!status && typeof status.state === 'string' && status.state !== '';
}

/**
 * Show the pattern field only when the custom format is selected.
 *
 * Uses the `hidden` property rather than a style, so nothing here has to know what the
 * stylesheet does with the row.
 */
function wireFormatSelect() {
    const select = document.getElementById('format');
    const row = document.getElementById('regex-row');
    if (!select || !row) {
        return;
    }
    const sync = function () {
        row.hidden = select.value !== 'custom';
    };
    select.addEventListener('change', sync);
    sync();
}

/**
 * Start everything the current page needs.
 */
function init() {
    document.querySelectorAll('.job').forEach(function (panel) {
        if (panel.dataset.jobState === 'running') {
            drive(panel);
        }
    });
    wireFormatSelect();
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
