<?php
/**
 * Loghound — the UI defects found by rendering the panel, and the guards against them coming back.
 *
 * Every assertion here names a defect that was MEASURED in a real browser against the demo
 * world, not one that was reasoned about. The suite runs with no browser and no network
 * (SPEC §12), so what is pinned is the DECISION the fix made — the selector, the token, the
 * call shape — and each one says what it saw.
 *
 * The measurements, for the record:
 *
 *  - A card that failed after the accordion had wrapped it threw NotFoundError from inside
 *    loadCard()'s own catch, leaving a blank box with no error, no retry and no banner.
 *  - Two tables built in JS declared colgroups mixing `ch` with `%`; every column in them
 *    measured 0px wide.
 *  - `--rule` was used and never declared, so a border was dropped at computed-value time.
 *  - `likely_human` was rendered as chip text on two views.
 *  - The dialog's focus trap leaked on every open, because its focusable list ended in a
 *    `tabindex="-1"` node.
 *  - The range picker's targets were 24-26px wide; the navigation links 38px tall.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

/** A repository file as text, failing the test when it is not there. */
function lh_ux(string $relative): string
{
    $path = dirname(__DIR__) . '/' . $relative;
    if (!is_file($path)) {
        lh_fail($relative . ' is missing');
    }
    return (string) file_get_contents($path);
}

/** The same, with comment blocks removed, so prose cannot satisfy an assertion. */
function lh_ux_code(string $relative): string
{
    return (string) preg_replace('#/\*.*?\*/#s', '', lh_ux($relative));
}

/** Every JS module the panel loads. */
function lh_ux_modules(): array
{
    $root = dirname(__DIR__) . '/public/assets/js/';
    $out = [];
    foreach (array_merge(glob($root . '*.js') ?: [], glob($root . 'views/*.js') ?: []) as $path) {
        // Comment blocks stripped: several of them QUOTE the calls these tests scan for, as
        // part of explaining why the rule exists.
        $out[str_replace(dirname(__DIR__) . '/', '', $path)] =
            (string) preg_replace('#/\*.*?\*/#s', '', (string) file_get_contents($path));
    }
    return $out;
}

return [
    /* ------------------------------------------------------------------ *
     * The failure path
     * ------------------------------------------------------------------ */

    'a card failure is rendered into whatever now holds the content, not into the card' =>
        function (): void {
            $js = lh_ux_code('public/assets/js/core.js');

            // THE MEASURED DEFECT, and the worst one in the panel. responsive.js turns every
            // card into an accordion by MOVING everything after the head into a `.card-region`
            // wrapper, which makes the content element a GRANDCHILD of the card. The error
            // renderer did `card.insertBefore(box, content)` and threw NotFoundError — from
            // inside loadCard()'s catch, so the card lost its skeleton, its progress line and
            // any trace of what happened, and the page-wide banner never rose either.
            lh_contains($js, 'content.parentNode', 'the insertion point must be the content element\'s real parent');
            lh_false(
                str_contains($js, 'card.insertBefore(box, content)'),
                'insertBefore against a node that is not a child throws, and it throws inside a catch'
            );

            // The banner is raised BEFORE the box is drawn, and drawing it cannot take the
            // page-level diagnosis down with it.
            $catch = strstr($js, '} catch (err) {');
            lh_true(is_string($catch), 'loadCard should still have a catch');
            $raise = strpos((string) $catch, 'raiseConnectionBanner');
            $render = strpos((string) $catch, 'renderCardError');
            lh_true(is_int($raise) && is_int($render) && $raise < $render,
                'the banner must be raised before the error box is drawn, not after it');
        },

    'a card that fails while collapsed opens itself' =>
        function (): void {
            // A card the operator had folded — or any card but the first, on arrival — could
            // fail into a region with `display: none` and show nothing at all. The accordion
            // only checks for trouble at page load, and every card fetches its data after that.
            lh_contains(
                lh_ux_code('public/assets/js/core.js'),
                "new CustomEvent('lh:card-trouble'",
                'a failure must announce itself to whatever owns the folding'
            );
            lh_contains(
                lh_ux_code('public/assets/js/responsive.js'),
                "document.addEventListener('lh:card-trouble'",
                'and the accordion must act on it'
            );
        },

    'a long operation cannot spin for ever on a response that is not a job' =>
        function (): void {
            $js = lh_ux_code('public/assets/js/core.js');

            // post() never checked res.ok, so a 500 whose body happened to be `{}` came back as
            // success — and `while (!job.done)` treats anything without a `done` as still
            // running. The result was a 700ms poll loop that never ended, rendering
            // "step NaN of undefined · undefineds".
            lh_contains($js, 'if (!res.ok) {', 'post() must check the status, as api() always did');
            lh_contains($js, 'function requireJob(job)', 'a poll response must be checked for being a job');
            lh_contains($js, 'requireJob(job);', 'and checked on every turn of the loop');
        },

    'every way an operation can fail offers a way to run it again' =>
        function (): void {
            $core = lh_ux_code('public/assets/js/core.js');
            lh_contains($core, "text: 'Try again'", 'a job that could not run must offer a retry');
            lh_contains($core, "text: 'Run it again'", 'and one that ran and failed must too');
            lh_contains($core, "cancel.textContent = 'Cancel failed — try again'", 'a failed cancel is not a dead control');
            lh_contains($core, 'cancel.disabled = false;', 'and it must become pressable again');

            $dialog = lh_ux_code('public/assets/js/dialog.js');
            lh_contains($dialog, 'export function dialogFail(body, err, retry)', 'a failed dialog must accept a retry');

            $setup = lh_ux_code('public/assets/js/setup.js');
            lh_contains($setup, 'function stall(panel, message)', 'the installer must never freeze on its last frame');
            lh_contains($setup, "textContent = 'Reload and carry on'", 'and the way forward is part of the message');
        },

    /* ------------------------------------------------------------------ *
     * Empty states
     * ------------------------------------------------------------------ */

    'an empty state says WHICH of the two reasons it is empty for' =>
        function (): void {
            $js = lh_ux('public/assets/js/core.js');

            // It used to say "Either nothing has been indexed yet, or nothing matched the
            // selected range and filters", which is an admission that the panel did not look.
            // It does know: the boot payload carries the filters the server applied.
            lh_false(
                str_contains($js, 'Either nothing has been indexed yet'),
                'the panel knows whether filters are in force and must say so'
            );
            lh_contains($js, 'export function activeFilterSummary()', 'it must be able to read the filter state');
            lh_contains($js, 'export function clearFiltersUrl()', 'and offer the control that undoes it');
            lh_contains($js, 'clear every filter', 'a filtered-to-nothing state is not a dead end');
        },

    'the pivot empty state targets an element that exists, and is passed a noun' =>
        function (): void {
            // TWO defects at once, on three views. `noDataYet(id, what)` builds the heading
            // "No <what> in this time range", and all three were handed a whole sentence — so
            // even if it had rendered it would have read "No No session in this range has both
            // a bot class and a network type. in this time range". It could not render: the id
            // was `ov-pivot`, and Controller::cardClose() emits the slot as `ov-pivot-empty`.
            lh_contains(lh_ux_code('public/assets/js/core.js'), 'export function noPivotYet(id, both)',
                'a cross-tab needs its own empty state, not noDataYet with a sentence for a noun');

            foreach ([
                'public/assets/js/views/overview.js' => 'ov-pivot-empty',
                'public/assets/js/views/bots.js'     => 'bf-pivot-empty',
                'public/assets/js/views/networks.js' => 'net-pivot-empty',
            ] as $file => $id) {
                $src = lh_ux_code($file);
                lh_contains($src, "noPivotYet('" . $id . "'", $file . ' must target the card\'s real empty slot');
                lh_false(
                    (bool) preg_match("/noDataYet\('[a-z-]+-pivot'/", $src),
                    $file . ' must not pass a bare card id where an empty-slot id is wanted'
                );
            }
        },

    'a card never shows two contradicting empty states at once' =>
        function (): void {
            // Virtual hosts revealed the server-rendered "no virtual host is being recorded —
            // your log format does not carry it, everything else works" card AND printed the
            // generic "nothing is indexed, check the tailer is running" state underneath it.
            $js = lh_ux_code('public/assets/js/views/hosts.js');
            lh_contains($js, "hideEmpty('hosts-table-empty');", 'the specific explainer wins');
            lh_true(
                (bool) preg_match('/none\.hidden = false;\s*hideEmpty/', $js),
                'revealing the explainer must suppress the generic state, not sit beside it'
            );
        },

    'a scan that read nothing is never reported as a clean result' =>
        function (): void {
            $js = lh_ux('public/assets/js/views/queries.js');

            // The branch fires when the scan read ZERO requests, and it announced "every
            // request this index answered matched at least one document" — a finding derived
            // from having looked at nothing, next to a card correctly reporting "No requests in
            // this time range".
            lh_contains($js, "'Nothing was scanned'", 'zero scanned is its own state');
            lh_contains($js, 'so nothing has been checked ',
                'and it must not claim a result it did not measure');
            lh_true(
                strpos($js, "'Nothing was scanned'") < strpos($js, "'Nothing came back empty'"),
                'the zero-scanned branch must be reached before the clean-result one'
            );
        },

    /* ------------------------------------------------------------------ *
     * Words
     * ------------------------------------------------------------------ */

    'there is one verdict chip and it speaks the vocabulary' =>
        function (): void {
            // MEASURED: `span.chip.v-likely_human` rendered the text "likely_human" on the
            // Fingerprints and Sessions views. Three byte-identical local copies of the same
            // function, each printing `verdict || 'unknown'` — while identity.js's own header
            // says THE SLUG IS NEVER SHOWN and valueText() exists to stop exactly this.
            lh_contains(
                lh_ux_code('public/assets/js/identity.js'),
                'export function verdictChip(verdict)',
                'the verdict chip belongs with every other value renderer'
            );
            lh_contains(
                lh_ux_code('public/assets/js/identity.js'),
                "valueText('bot_verdict_s', raw)",
                'and it must go through the vocabulary'
            );

            foreach (['public/assets/js/views/sessions.js',
                      'public/assets/js/views/fingerprints.js',
                      'public/assets/js/detail.js'] as $file) {
                $src = lh_ux_code($file);
                lh_false(
                    str_contains($src, 'function verdictChip('),
                    $file . ' must import the shared chip rather than keeping a fourth copy'
                );
                lh_contains($src, 'verdictChip', $file . ' still uses it');
            }
        },

    'a population is never printed by its key' =>
        function (): void {
            // `human`, `declared`, `ai`, `evasive` and `unknown` are facet keys and palette
            // class names. Query::populationLabels() has been in the boot payload the whole
            // time; the hosts view never read it and printed "evasive: 12%" in every bar
            // tooltip, and the networks view derived its labels by stripping `bar-` off a CSS
            // class name.
            lh_contains(lh_ux_code('public/assets/js/core.js'), 'export function populationLabel(key)',
                'there must be one place the front end reads the population words from');

            foreach (['public/assets/js/views/hosts.js',
                      'public/assets/js/views/networks.js',
                      'public/assets/js/detail.js'] as $file) {
                lh_contains(lh_ux_code($file), 'populationLabel(', $file . ' must name populations in words');
            }
            lh_false(
                str_contains(lh_ux_code('public/assets/js/views/networks.js'), "cls.replace('bar-', '')"),
                'a palette class name is not a label'
            );
        },

    'a network type is never printed by its slug' =>
        function (): void {
            // The treemap's own key listed `isp / mobile / hosting / vpn / edu / gov / unknown`
            // three lines above a donut of the same values rendered as "Consumer ISP",
            // "Hosting / datacentre" and "Unclassified".
            $js = lh_ux_code('public/assets/js/views/networks.js');
            lh_contains($js, "valueText('as_type_s', type)", 'the colour key reads in words like everything else');
        },

    'no sentence claims nothing is deleted while the other rule is on' =>
        function (): void {
            // The exact bug the product shipped once already and fixed in ONE of the three
            // places that said it. `retention_days = 0` disables the AGE rule; the rolling disk
            // trim is separate and is on by default.
            foreach (['src/Panel/Jobs.php', 'src/Quota.php', 'src/Panel/Usage.php',
                      'public/assets/js/views/usage.js'] as $file) {
                $src = lh_ux_code($file);
                lh_false(
                    str_contains($src, 'nothing is ever deleted'),
                    $file . ': "nothing is ever deleted" is false whenever the disk rule is on'
                );
            }

            lh_false(
                str_contains(lh_ux_code('src/Panel/Settings.php'), '0 keeps everything'),
                'a retention of 0 does not keep everything; it removes one of the two rules'
            );
            lh_false(
                str_contains(lh_ux_code('src/Panel/Settings.php'), 'nothing is ever cut off'),
                'a sentence describing deletion must not end by denying it'
            );

            // Both branches exist, and both are reached from the setting rather than assumed.
            lh_contains(lh_ux_code('src/Panel/Usage.php'), '$this->quota()->enabled()',
                'the "disk looks after itself" claim must be conditional on the disk rule being on');
            lh_contains(lh_ux_code('src/Quota.php'), '$this->enabled()',
                'and so must the "nothing is being deleted" one');
        },

    'a command the panel prints is one the operator can run from anywhere' =>
        function (): void {
            // "run bin/loghound-setup" is half an instruction: the operator is on a shell
            // somewhere else on the machine, and on a box with two checkouts a relative path
            // runs the wrong one. Settings states the rule; two files had not caught up.
            //
            // src/Panel/Login.php IS NO LONGER IN THIS LIST, and the exception is the security
            // audit's, not a regression. Everything Login renders is on a PUBLIC page: the
            // sign-in form and the theft banner are served to anyone who loads ?login=1, with no
            // credentials, so an absolute path there tells an anonymous prober the deployment
            // root, the directory layout and whether the install is a symlinked deploy. The
            // usability argument holds wherever the reader is already authenticated — which is
            // every other place these commands are printed — and is outweighed where they are
            // not. The test below pins the replacement rule for that file.
            foreach (['src/Panel/Jobs.php'] as $file) {
                $src = lh_ux_code($file);
                lh_false(
                    (bool) preg_match('/(?<![\/\w])bin\/loghound-[a-z]+/', str_replace(
                        ["'/bin/loghound-", "binPath('loghound-"],
                        ['ABSOLUTE', 'ABSOLUTE'],
                        $src
                    )),
                    $file . ' prints a relative bin/ path, which fails on any shell but one'
                );
            }
            lh_contains(lh_ux_code('src/Panel/Jobs.php'), 'private static function binPath(', 'and there is one place that builds them');
        },

    'the public sign-in page never prints where the installation lives on disk' =>
        function (): void {
            // Reachable with no credentials at all, so every absolute path rendered from it is
            // reconnaissance handed to whoever asked: the deployment root, the layout, and
            // whether this is a symlinked deploy. Three sentences used to print $this->root and
            // one printed the full path of the attempt ledger.
            $src = lh_ux_code('src/Panel/Login.php');

            lh_false(
                str_contains($src, '$this->root . \'/bin/'),
                'the sign-in page must not print the install root'
            );
            lh_false(
                str_contains($src, 'Security::ledgerPath('),
                'nor the absolute path of the attempt ledger'
            );
            lh_contains(
                $src,
                'Security::LOGIN_LEDGER',
                'naming the file is enough, and it is already a public constant'
            );
        },

    'the beacon says one thing, in one voice' =>
        function (): void {
            // Two functions, one page, one fetch, disagreeing: "Beacon: Receiving data" against
            // "Beacon: receiving data", "Never seen" against "never seen". And "Never seen" is
            // not what was measured — the window is thirty days, which the detail line under it
            // had been saying all along.
            $js = lh_ux_code('public/assets/js/views/settings.js');
            lh_contains($js, 'function beaconLabel(live, everSeen)', 'one sentence, one place');
            // Its own definition plus the two call sites.
            lh_same(3, substr_count($js, 'beaconLabel('), 'both cards must read it from there');
            lh_contains($js, 'not seen in the last 30 days', 'the label must name the window it measured');
            lh_false(str_contains($js, "'Beacon: Receiving data'"), 'and there is only one capitalisation of it');
        },

    'every number goes through the shared formatters' =>
        function (): void {
            $js = lh_ux_code('public/assets/js/views/settings.js');

            // These two were the only numbers in the panel not routed through num(), and they
            // had no null guard either — a null would have thrown a TypeError inside a loader
            // that is not a card, leaving the box reading "status unknown" for ever.
            lh_false(str_contains($js, "status.hour.toLocaleString"), 'a count is num(), like every other count');
            lh_false(str_contains($js, "status.coverage + '%'"), 'a percentage is dec(), not a raw float');

            // An explicit locale everywhere, so a sorted list is the same list on every machine.
            foreach (lh_ux_modules() as $file => $src) {
                foreach (['localeCompare(', 'toLocaleString('] as $call) {
                    $offset = 0;
                    while (($at = strpos($src, $call, $offset)) !== false) {
                        $tail = substr($src, $at, 90);
                        lh_true(
                            str_contains($tail, "'en-US'") || str_contains($tail, 'LOCALE'),
                            $file . ': ' . trim($tail) . ' must pass a locale'
                        );
                        $offset = $at + 1;
                    }
                }
            }
        },

    /* ------------------------------------------------------------------ *
     * Affordances, focus and keyboard
     * ------------------------------------------------------------------ */

    'a table row is a row, and its contents stay in the accessibility tree' =>
        function (): void {
            // `role="button"` on a <tr> did two things at once. The row stopped being a `row`,
            // so its tbody held a child that was not one and `<th scope="col">` stopped
            // associating with the cells. And `button` takes PRESENTATIONAL CHILDREN: every
            // filter link, the row opener and the fingerprint expander were stripped from the
            // accessibility tree — the exact set of controls identity.js exists to make
            // consistent.
            foreach (['public/assets/js/identity.js',
                      'public/assets/js/detail.js',
                      'public/assets/js/views/fingerprints.js'] as $file) {
                lh_false(
                    str_contains(lh_ux_code($file), "role: 'button',"),
                    $file . ' must not put a button role on a table row'
                );
            }
            lh_contains(lh_ux_code('public/assets/js/identity.js'), "'aria-label': 'Open the full record'",
                'a tabbable row still needs a name of its own');

            // And it needs a focus ring the collapsed border model actually paints.
            $css = lh_ux_code('public/assets/css/panel.css');
            lh_contains($css, 'tr.row-link:focus-visible { outline:', 'a tabbable row must show where focus is');
        },

    'a sortable column header is a header with a button in it' =>
        function (): void {
            $js = lh_ux_code('public/assets/js/sorttable.js');
            lh_contains($js, "button.className = 'sort-btn'", 'the control is a real button');
            lh_contains($js, "th.removeAttribute('tabindex')", 'and the header stops being one');
            lh_false(str_contains($js, "th.setAttribute('role'"), 'a th with a role is no longer a column header');
            lh_false(
                str_contains($js, "document.addEventListener('keydown', onActivate)"),
                'a button already turns Enter and Space into a click; a second listener sorts twice'
            );

            // A column whose heading is only a visually-hidden label is not sortable: the row
            // opener's column is 6px wide and holds nothing to sort by.
            lh_contains($js, "classList.contains('sr-only')", 'a hidden heading is not a heading to sort by');
        },

    'the modal is a modal: focus stays in, Escape works from anywhere, the page behind is inert' =>
        function (): void {
            $js = lh_ux_code('public/assets/js/dialog.js');

            lh_contains($js, '[tabindex]:not([tabindex="-1"])',
                'a node that cannot be tabbed to must not be the last tab stop');
            lh_contains($js, "byId('lh-dialog-body').focus();",
                'a body with nothing tabbable in it still keeps Tab inside');
            lh_contains($js, "document.addEventListener('keydown', onDocumentKey)",
                'Escape must work with focus anywhere on the page');
            lh_contains($js, "node.setAttribute('inert', '')", 'the page behind must be unreachable');
            lh_contains($js, "node.removeAttribute('inert')", 'and reachable again afterwards');
            /* A DIALOG OPENED FROM CODE STILL RESTORES FOCUS. The value browser is reached by
               pressing "Show all" in a facet list, which is not a `data-lh-open` row, so no
               frame is minted for it by the delegated handler — openDialog() mints one from
               whatever had focus. The condition used to read `!opener`; it is now `!stack.length`
               for the same reason and with one addition: every opener calls openDialog() TWICE,
               once for the loading state and once with the real heading, and the second call
               must not be counted as a second dialog. */
            lh_contains($js, 'if (!stack.length)', 'a dialog opened from code still restores focus');
            lh_contains($js, 'active !== document.body ? active : null',
                'and it never records <body> as the thing to go back to');

            /* NESTING HAS A DEFINED MEANING AND A WAY BACK. A row inside an open dialog opens
               another one — Bot forensics' class dialog lists "Recent visitors", and each row is
               a session. The opener used to be a single variable that this overwrote with the
               in-dialog row, which openDialog() then detached microseconds later by refilling
               the body; closing returned focus to an orphan, silently. */
            lh_contains($js, 'const stack = []', 'the dialogs that are open are a stack, not a variable');
            lh_contains($js, 'stack.push({ opener: node, reopen: run })',
                'a row that opens a dialog records how to get back to the one it opened from');
            lh_contains($js, 'function restoreInsideDialog(',
                'and closing puts focus on that row again, in the rebuilt parent');
            lh_contains($js, 'MAX_DEPTH', 'the chain is bounded, so a loop in the data cannot build one nobody can close');
        },

    'nothing that cannot be pressed behaves as though it can' =>
        function (): void {
            $css = lh_ux_code('public/assets/css/panel.css');

            // The row hover was unscoped, so the scoring-weights table, the system checks and
            // every pivot row lit up under the pointer exactly as a drillable row does.
            lh_false(
                (bool) preg_match('/^\s*tbody tr:hover td\s*\{/m', $css),
                'hover feedback belongs to a row that does something'
            );
            lh_contains($css, 'tbody tr.row-link:hover td', 'a drillable row keeps it');

            // A static facet row is a <span> with no href and no handler, and it was taking the
            // full interactive hover: a border appearing from nowhere on an inert row.
            lh_contains($css, '.facet-opt.is-static:hover', 'an inert facet row must cancel the control hover');

            // The pointer belonged to a cell whose control was an inline link inside it.
            lh_false(
                str_contains($css, 'tr.lf-pick td:first-child { cursor: pointer; }'),
                'the surface that looks pressable must be the surface that is'
            );
        },

    'a two-state control that hides nothing does not claim to be expanded' =>
        function (): void {
            $js = lh_ux_code('public/assets/js/responsive.js');

            // The rail collapses the LABELS; every link stays present and operable. Announcing
            // aria-expanded="false" told a screen-reader user the navigation was closed when it
            // was fully available.
            lh_contains($js, "'aria-pressed': 'false'", 'the rail toggle is a pressed control, not a disclosure');
            lh_contains($js, "button.setAttribute('aria-pressed'", 'and its state is kept in sync');

            // aria-controls named a DESCENDANT of the region the handler toggles, and was set
            // only when a lookup happened to succeed.
            lh_contains($js, "rail.id = 'lh-facet-rail'", 'the controlled region must have an id to be named by');
            lh_contains($js, "button.setAttribute('aria-controls', rail.id)", 'and aria-controls must name it');
        },

    'every form control has a name' =>
        function (): void {
            // The scoring weight fields were the only unlabelled controls in the codebase: N
            // number boxes announced as "edit, blank", with nothing to say which rule each one
            // weighted. A column header associates with the cell, not with the input in it.
            lh_contains(
                lh_ux_code('src/Panel/Settings.php'),
                "aria-label=\"' . Security::esc('Weight for ' . \$meta['label'])",
                'a weight field must say which rule it weights'
            );
        },

    /* ------------------------------------------------------------------ *
     * Layout
     * ------------------------------------------------------------------ */

    'no stylesheet hides a sideways scroll instead of fixing it' =>
        function (): void {
            // mobile.css's own header describes measuring a 396px document at 375px and fixing
            // the causes. `body { overflow-x: hidden }` in the OTHER stylesheet would have
            // clipped that overflow rather than scrolled it, so the measurement could not have
            // found it again. The guard that was meant to catch this looked for the string on
            // `html`, in mobile.css, and never saw it.
            foreach (['public/assets/css/panel.css', 'public/assets/css/mobile.css'] as $file) {
                $css = lh_ux_code($file);
                lh_false(
                    (bool) preg_match('/^\s*(html|body)\s*\{[^}]*overflow-x:\s*hidden/mi', $css),
                    $file . ' must not clip a sideways scroll at the document level'
                );
                lh_false(
                    (bool) preg_match('/^\s*overflow-x:\s*hidden;\s*$/m', substr($css, 0, (int) (strpos($css, 'h1,') ?: 4000))),
                    $file . ' must not clip it on the body rule either'
                );
            }
        },

    'every custom property a stylesheet uses is one a stylesheet declares' =>
        function (): void {
            // `--rule` was used once and declared nowhere, so `border-bottom: 1px solid
            // var(--rule)` resolved to the guaranteed-invalid value and the WHOLE declaration
            // was dropped: thirteen rows of the Settings system check rendered with no
            // separator, in every theme, silently.
            $declared = [];
            $used = [];
            foreach (['public/assets/css/panel.css', 'public/assets/css/mobile.css'] as $file) {
                $css = lh_ux_code($file);
                preg_match_all('/(--[a-z0-9-]+)\s*:/i', $css, $d);
                $declared = array_merge($declared, $d[1]);
                preg_match_all('/var\(\s*(--[a-z0-9-]+)\s*([,)])/i', $css, $u, PREG_SET_ORDER);
                foreach ($u as $one) {
                    // A var() with a fallback survives an absent declaration by design.
                    if ($one[2] === ')') {
                        $used[] = $one[1];
                    }
                }
            }
            $declared = array_unique($declared);
            foreach (array_unique($used) as $name) {
                lh_true(
                    in_array($name, $declared, true),
                    $name . ' is used with no fallback and never declared, so every declaration using it is dropped'
                );
            }
        },

    'a colgroup built in JavaScript states every width in one unit and they sum to 100' =>
        function (): void {
            // The rule the nine server-rendered colgroups already follow, and which the two
            // built in JS did not. Mixing `ch` with `%` on a fixed-layout table with a 680px
            // min-width over-constrains it: MEASURED, every column in both tables was 0px wide,
            // and each colgroup also carried one <col> with no width at all.
            foreach (['public/assets/js/detail.js', 'public/assets/js/views/fingerprints.js'] as $file) {
                $src = lh_ux_code($file);
                preg_match_all("/el\('colgroup'.*?\]\),/s", $src, $groups);
                lh_true($groups[0] !== [], $file . ' should still declare a colgroup');

                foreach ($groups[0] as $group) {
                    lh_false(
                        (bool) preg_match("/el\('col'\)/", $group),
                        $file . ': a <col> with no width resolves to zero on a fixed-layout table'
                    );
                    lh_false(
                        (bool) preg_match('/width:\d+(ch|px)/', $group),
                        $file . ': one unit per colgroup — ch and % together over-constrain the table'
                    );
                    preg_match_all('/width:(\d+)%/', $group, $w);
                    lh_same(100, array_sum(array_map('intval', $w[1])), $file . ': the widths must sum to 100');
                }
            }
        },

    'the controls a thumb has to hit are big enough for one' =>
        function (): void {
            $panel = lh_ux_code('public/assets/css/panel.css');
            $mobile = lh_ux_code('public/assets/css/mobile.css');

            // MEASURED at 375, 390, 414, 768 and 1280 in both themes and the default.
            lh_contains($panel, 'min-width: 44px', 'the range picker measured 24-26px across');
            lh_true(
                (bool) preg_match('/\.side li a \{[^}]*min-height: 40px/s', $panel),
                'the navigation links measured 38px tall'
            );
            lh_true(
                (bool) preg_match('/\.lh-railbtn \{[^}]*min-height: 40px/s', $panel),
                'the rail toggle measured 34px, and its specificity beat the touch rule'
            );
            lh_contains($mobile, '.rowopen,', 'the row opener measured 28px across');
            lh_contains($mobile, 'input[type="checkbox"],', 'every tick box measured 20x20');
            lh_contains($mobile, '.fb-apply { min-height: var(--lh-tap); }',
                'the value browser\'s Apply is an <a>, so no button rule reached it');
            lh_contains($mobile, '.set-nav a { min-height: var(--lh-tap); }',
                'the jump bar\'s own rule was outside the pointer query, so a coarse tablet missed it');
        },

    'an auto-fit grid can always collapse to one column' =>
        function (): void {
            // A bare `minmax(190px, 1fr)` cannot shrink below its floor, so on a narrow viewport
            // it pushes the page out sideways instead of wrapping. The panel declares its grids
            // at a comfortable desk width and mobile.css relaxes each one; the arrangement works
            // only while the pairing is complete. `.recovery-codes` was the one grid that had no
            // partner — it survived at 375px because 190 < 343 collapses it anyway, and would
            // have pushed the page out at 320. The test that pins this pattern reads only
            // mobile.css, so a floor declared in panel.css alone was invisible to it.
            //
            // Either half of the pairing is acceptable: a `min()` floor in panel.css needs no
            // override at all.
            $panel = lh_ux_code('public/assets/css/panel.css');
            $mobile = lh_ux_code('public/assets/css/mobile.css');

            preg_match_all('/([a-z0-9 .#>_-]+)\s*\{[^}]*minmax\(\s*(\d+)px/i', $panel, $m, PREG_SET_ORDER);
            foreach ($m as $one) {
                $selector = trim((string) preg_replace('/^.*[;}]/s', '', $one[1]));
                $class = strrchr($selector, '.');
                lh_true(
                    is_string($class) && str_contains($mobile, $class),
                    'panel.css declares a fixed auto-fit floor for ' . $selector
                    . ' and mobile.css does not relax it, so it cannot collapse on a narrow screen'
                );
            }

            // mobile.css itself is the last word and may hold no fixed floor at all.
            preg_match_all('/minmax\(\s*(\d+)px/', $mobile, $mm);
            lh_same([], $mm[1], 'mobile.css: an auto-fit track needs a min() floor, not a fixed one');
        },

    /* ------------------------------------------------------------------ *
     * Charts
     * ------------------------------------------------------------------ */

    'a chart never draws a label in the colour of the page behind it' =>
        function (): void {
            $js = lh_ux_code('public/assets/js/charts.js');

            // readableOn() was written to fix white-on-near-white treemap labels in the LIGHT
            // theme, using a fixed luminance threshold — which reproduced the same defect in
            // the dark one, where every network-type fill is dark and therefore took the page
            // colour: #111111 on #3a3631 is 1.4:1, which is not a faint label, it is no label.
            lh_contains($js, 'function relativeLuminance(colour)', 'both candidates must be measured, not assumed');
            lh_contains($js, 'ratio(luminance, inkL) >= ratio(luminance, pageL)',
                'the better contrast wins, which needs no threshold to keep in step with a retone');

            // The hover band and the tooltip were drawn in tokens that are 1.04:1 and 1.4:1
            // against the page.
            lh_false(str_contains($js, 'shadowStyle: { color: t.sunken }'), 'the hover band must be visible');
            lh_contains($js, "band:   get('--band'", 'the band token must be available to reach for');
            lh_contains($js, 'backgroundColor: t.band,', 'and the tooltip must have an edge against the page');
        },

    'a chart with one data point draws it' =>
        function (): void {
            // `symbol: 'none'` plus a single datum is a zero-length line segment, which paints
            // nothing — while the card above it simultaneously reported "1 data point". A
            // one-bucket range is an ordinary outcome of a short time window.
            lh_contains(
                lh_ux_code('public/assets/js/charts.js'),
                "symbol: real === 1 ? 'circle' : 'none'",
                'a single point needs a marker or it is invisible'
            );
        },

    'a chart with nothing to draw says so instead of rendering an empty axis' =>
        function (): void {
            // Four charts were guarded only by their card's `data.requests`, not by the series
            // they were about to draw, and an ECharts instance with no series reads as broken
            // rather than as empty. They are halves of split cards, so the card's one empty
            // slot would blank the other half with them.
            lh_contains(
                lh_ux_code('public/assets/js/views/opensolr.js'),
                'export function plotOrNote(chartId, rows, sentence)',
                'half a split card needs an empty state that does not take the other half with it'
            );
            foreach (['public/assets/js/views/callers.js', 'public/assets/js/views/indexes.js'] as $file) {
                lh_contains(lh_ux_code($file), 'plotOrNote(', $file . ' must guard the chart it draws');
            }
        },

    /* ------------------------------------------------------------------ *
     * Tables
     * ------------------------------------------------------------------ */

    'a formatted figure carries the value it sorts by' =>
        function (): void {
            // sorttable.js falls back to the cell's TEXT when there is no `sort`, and every
            // number here is rendered through num()/dur()/durUs(), which put separators and
            // units in it. `Number('1,204')` is NaN, so "1,204" sorted BELOW "987" and "950 µs"
            // above "2.10 s". Five view files had no sort keys at all.
            foreach (['public/assets/js/views/callers.js',
                      'public/assets/js/views/indexes.js',
                      'public/assets/js/views/performance.js',
                      'public/assets/js/views/queries.js'] as $file) {
                $src = lh_ux_code($file);
                // A CELL descriptor, not any object with a formatted number in it: a caption
                // built with num() is a sentence and has nothing to sort.
                preg_match_all('/\{[^{}]*text:\s*(?:num|dur|durUs|dec|bytes)\([^{}]*num:\s*true[^{}]*\}/', $src, $cells);
                foreach ($cells[0] as $cell) {
                    lh_true(
                        str_contains($cell, 'sort:'),
                        $file . ': ' . trim(preg_replace('/\s+/', ' ', $cell)) . ' needs a sort key'
                    );
                }
            }
        },

    'every element id the front end writes into is one a view actually renders' =>
        function (): void {
            // TWO CONFIRMED DEFECTS OF THIS EXACT SHAPE, and both were silent: showEmpty() does
            // byId() and returns without complaint when the element is not there. The session
            // explorer answered a filter that matched nothing with an empty table and no
            // sentence, because it named `se-table-empty` — the TABLE's id with `-empty` on it —
            // where cardClose() emits `se-results-empty`. The three pivot cards did the same
            // with a bare card id. Nothing in the suite could see either, because the id is a
            // string in a JS file and the element is built by PHP.
            //
            // So: render every view, collect every id, and check the strings against them.
            $cfg = \Loghound\Config::load('/nonexistent-loghound-config');
            $cfg->set('ui.demo', true);
            $cfg->set('solr.hits_core', 'lh_hits');
            $cfg->set('solr.sessions_core', 'lh_sessions');

            // The Opensolr views render an explainer instead of their cards without credentials,
            // so the ids inside those cards would look absent. Shape-valid values only; demo
            // mode means nothing is ever sent anywhere.
            $cfg->set('opensolr.email', 'panel@example.test');
            $cfg->set('opensolr.api_key', str_repeat('a', 32));

            $gw = \Loghound\Panel\Gateway::fromConfig($cfg);
            $views = [
                \Loghound\Panel\Overview::class, \Loghound\Panel\Bots::class,
                \Loghound\Panel\Attacks::class,
                \Loghound\Panel\Fingerprints::class, \Loghound\Panel\Networks::class,
                \Loghound\Panel\Sessions::class, \Loghound\Panel\Performance::class,
                \Loghound\Panel\Hosts::class, \Loghound\Panel\Indexes::class,
                \Loghound\Panel\Queries::class, \Loghound\Panel\Callers::class,
                \Loghound\Panel\Usage::class, \Loghound\Panel\Settings::class,
            ];

            $ids = [];
            $saved = $_GET;
            foreach ($views as $class) {
                /** @var \Loghound\Panel\Controller $view */
                $view = new $class($cfg, $gw);
                $_GET = ['v' => $view->slug()];
                ob_start();
                try {
                    $view->body();
                } catch (\Throwable $e) {
                    ob_end_clean();
                    continue;
                }
                $html = (string) ob_get_clean();
                preg_match_all('/id="([A-Za-z0-9_-]+)"/', $html, $m);
                foreach ($m[1] as $id) {
                    $ids[$id] = true;
                }
            }
            $_GET = $saved;
            lh_true(count($ids) > 200, 'the views should have rendered a few hundred ids, got ' . count($ids));

            // What each helper is handed: an ELEMENT id, or a card BASE id it derives one from.
            $suffix = [
                'showEmpty' => '', 'hideEmpty' => '', 'noDataYet' => '', 'noPivotYet' => '',
                'plotOrNote' => '', 'setPop' => '-pop', 'revealCard' => '-content',
            ];

            $root = dirname(__DIR__) . '/public/assets/js/';
            $files = array_merge(glob($root . '*.js') ?: [], glob($root . 'views/*.js') ?: []);
            $checked = 0;

            foreach ($files as $path) {
                $src = (string) preg_replace('#/\*.*?\*/#s', '', (string) file_get_contents($path));
                $name = str_replace(dirname(__DIR__) . '/', '', $path);

                $pattern = '/\b(' . implode('|', array_keys($suffix)) . ")\(\s*'([A-Za-z0-9_-]+)'/";
                preg_match_all($pattern, $src, $calls, PREG_SET_ORDER);
                foreach ($calls as $call) {
                    $target = $call[2] . $suffix[$call[1]];
                    $checked++;
                    lh_true(
                        isset($ids[$target]),
                        $name . ': ' . $call[1] . "('" . $call[2] . "') writes into #" . $target
                        . ', which no view renders — so it does nothing, silently'
                    );
                }
            }
            lh_true($checked > 40, 'the scan should have found plenty of call sites, found ' . $checked);
        },

    'the unnamed crawlers stay below the named ones when a column is sorted' =>
        function (): void {
            /* MEASURED: Bot forensics section 06 is headed "Declared crawlers, by name" and
               ranked `unspecified bot` second — Enrich\Ua's marker for a User-Agent that
               declared itself a crawler and named nothing recognisable. Those sessions are
               counted in the declared half stated in section 01, so they cannot be dropped;
               they are grouped below the named rows behind ONE line instead.

               The grouping is a SECOND <tbody>, and the only reason it holds is that
               sorttable.js reorders the first body and leaves the others alone. That is a
               cross-file assumption with nothing in either file to enforce it: the day the
               sorter walks every body, the group and its sentence get dealt into the middle of
               the table and the line reads "below:" with Googlebot under it. */
            $view = lh_ux_code('public/assets/js/views/bots.js');
            $sorter = lh_ux_code('public/assets/js/sorttable.js');
            $php = lh_ux_code('src/Panel/Bots.php');

            lh_contains(
                $php,
                'Ua::isUnspecified',
                'Bots.php decides what counts as unnamed on its own, instead of asking Enrich\Ua'
            );
            lh_contains($view, 'row.unspecified', 'bots.js ignores the flag the server computes for it');
            lh_contains($view, 'table.appendChild(group)', 'the unnamed group is no longer a body of its own');
            lh_contains(
                $sorter,
                'table.tBodies[0]',
                'sorttable.js no longer sorts only the first body, so the unnamed crawler group and the '
                . 'line introducing it can be dealt into the middle of the table by one click'
            );
        },

    'a truncated cell can still be read in full' =>
        function (): void {
            // core.js's tbody() adds a title to every clip cell it builds. The server-rendered
            // ones had none, so a value longer than 46ch — 22ch on a phone — was simply gone.
            $php = lh_ux_code('src/Panel/Settings.php');
            lh_false(
                (bool) preg_match('/<td class="mono clip">/', $php),
                'a clipped cell with no title loses whatever it truncated'
            );
        },
];
