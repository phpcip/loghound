<?php
/**
 * Loghound — the checks that only a rendering engine can answer.
 *
 * ## Why this file exists, in one incident
 *
 * The panel's ES module graph is versioned by an import map, and the map did nothing at all.
 * Chrome discarded every one of its thirty-two entries as bare specifiers and loaded the whole
 * graph unversioned — which is exactly the staleness the map was written to prevent, so
 * operators went on hard-reloading after every release. There was a test. The test generated
 * the map, parsed it back, and agreed with itself that every module was listed and every URL
 * was stamped. It passed. It had never asked a browser.
 *
 * That is the shape of every defect in here, and none of them is exotic:
 *
 *   - A map that is PRESENT but not APPLIED.
 *   - `closeDialog()` setting `hidden` on an element whose author `display` rule outranks the
 *     browser's `[hidden]` — so Close, the scrim and Escape all appeared to do nothing, and
 *     then latched, because the second press found the attribute already set.
 *   - A country flag drawn twice because two functions each believed they owned the mark.
 *   - A four-column block whose first column sat 17px higher than the other three, because a
 *     rule written for a vertical stack was applied to a grid.
 *
 * Every one of those is invisible to a test that reads source and obvious to a browser in the
 * first second. tests/support/Browser.php is that browser: headless Chrome over the DevTools
 * protocol, driven from PHP, with no Node, no npm and no build step.
 *
 * ## These SKIP where there is no browser, and that is deliberate
 *
 * This repository is public and must clone-and-test on a bare box. With no Chrome these skip
 * by name rather than passing vacuously. The static assertions that sit beside them — in
 * tests/test_asset_versioning.php, tests/test_visitor_detail.php, tests/test_responsive.php —
 * run everywhere and always. The browser is what additionally proves the thing WORKS, as
 * opposed to being spelled correctly.
 *
 * Point it at a binary with `LOGHOUND_CHROME=/path/to/chrome`.
 *
 * ## The panel these drive
 *
 * A copy of the installation in a temporary directory, with a throwaway configuration and a
 * random Basic password generated per run, in demo mode so no Solr is needed. Never the
 * operator's own config/loghound.php.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/support/Browser.php';

/**
 * A console message a correctly working panel is allowed to produce.
 *
 * THE LIST IS EMPTY, AND KEEPING IT EMPTY IS THE POINT. "Fail on any console message" is a
 * deliberately absolute bar: the import-map defect announced itself perfectly clearly, twice
 * per module, and nothing was listening. The moment an entry is added here, the class of bug
 * this file exists to catch starts getting through again — so an entry needs a reason that
 * survives being read out loud, not a shrug.
 *
 * @return array<int,string>
 */
function lh_browser_allowed(): array
{
    return [];
}

/**
 * Everything the console said, minus what is allowed, as one printable block.
 *
 * @param array<int,string> $messages
 */
function lh_browser_noise(array $messages): string
{
    $out = [];
    foreach ($messages as $message) {
        $ok = false;
        foreach (lh_browser_allowed() as $allowed) {
            if (str_contains($message, $allowed)) {
                $ok = true;
                break;
            }
        }
        if (!$ok) {
            $out[] = '  · ' . $message;
        }
    }

    return implode("\n", $out);
}

/**
 * The twelve views, by slug, so a sweep covers the panel rather than a sample.
 *
 * @return array<int,string>
 */
function lh_browser_views(): array
{
    return [
        'overview', 'bots', 'fingerprints', 'networks', 'sessions', 'performance',
        'hosts', 'indexes', 'queries', 'callers', 'usage', 'settings',
    ];
}

return [

    /* ------------------------------------------------------------------ 1. the import map */

    'the browser accepts the import map instead of discarding it' =>
        function (): void {
            $browser = lh_browser_panel('overview');
            try {
                $noise = lh_browser_noise($browser->messages());
                lh_same(
                    '',
                    $noise,
                    "the panel put this on the console, and a page with something to say has something\n"
                        . "wrong with it. The import map's whole failure mode was a warning nobody read:\n"
                        . "\"Ignored an import map value of …: Bare specifier\", once per module, while every\n"
                        . "module loaded unversioned and operators hard-reloaded after every release.\n"
                        . $noise
                );
            } finally {
                $browser->close();
            }
        },

    'every module is fetched at its versioned URL, which is the map being APPLIED' =>
        function (): void {
            $browser = lh_browser_panel('overview');
            try {
                $modules = [];
                foreach ($browser->requests() as $url) {
                    $path = (string) parse_url($url, PHP_URL_PATH);
                    if (str_ends_with($path, '.js')) {
                        $modules[] = $url;
                    }
                }

                /* PRESENT IS NOT APPLIED, AND THIS IS THE DIFFERENCE. With the broken map the
                   page loaded and looked perfect; `app.js?v=…` was fetched because the HTML
                   names it with a query string, and `core.js` — reached through `import
                   './core.js'` — was fetched bare, from whatever the browser had cached the
                   first time this operator opened the panel. Only the second URL tells the two
                   apart, and only a browser produces it. */
                lh_true(count($modules) > 10, 'the panel loaded a module graph to check: ' . count($modules));

                $bare = [];
                foreach ($modules as $url) {
                    if (!str_contains($url, '?v=')) {
                        $bare[] = '  · ' . $url;
                    }
                }

                lh_same(
                    '',
                    implode("\n", $bare),
                    "these modules were fetched with no version, so the import map did not resolve them.\n"
                        . "A release that changes one of these lands for some operators and not others, with\n"
                        . "no error anywhere to say so — new markup against a year-old module.\n"
                        . implode("\n", $bare)
                );
            } finally {
                $browser->close();
            }
        },

    'the module graph really is versioned by file, not by one stamp for all of it' =>
        function (): void {
            $browser = lh_browser_panel('overview');
            try {
                $stamps = [];
                foreach ($browser->requests() as $url) {
                    if (!str_contains($url, '.js?v=')) {
                        continue;
                    }
                    $stamps[] = substr($url, strpos($url, '?v=') + 3);
                }

                /* A single stamp shared by everything would pass the check above and still be
                   wrong: it would mean the map was ignored and something else — a deploy-time
                   constant, a build id — was appended to every URL, which re-downloads the
                   whole graph on every release and tells you nothing about what changed. */
                lh_true(count(array_unique($stamps)) > 1, 'every module is stamped with its own modification time');
            } finally {
                $browser->close();
            }
        },

    'not one of the twelve views has anything to say on the console' =>
        function (): void {
            $server = lh_browser_serve();
            $browser = LhBrowser::open();
            try {
                $browser->headers([
                    'Authorization' => 'Basic ' . base64_encode('loghound:' . lh_browser_password()),
                ]);
                $browser->viewport(1440, 900);

                $problems = [];
                foreach (lh_browser_views() as $view) {
                    $browser->visit($server['base'] . '/?v=' . $view . '&range=24h');
                    $noise = lh_browser_noise($browser->messages());
                    if ($noise !== '') {
                        $problems[] = $view . ":\n" . $noise;
                    }
                }

                /* THE SWEEP IS THE POINT. The import map was broken on every page at once, and
                   so is anything else that lives in the shell — a module that throws on import,
                   a stylesheet blocked by the policy, a fetch to an endpoint a view forgot to
                   allowlist. One view proves the shell; twelve prove the views. */
                lh_same('', implode("\n\n", $problems), "views that put something on the console:\n"
                    . implode("\n\n", $problems));
            } finally {
                $browser->close();
            }
        },

    /* ------------------------------------------------------------------ 2. dialogs */

    'closing a dialog actually closes it, on the button and on Escape' =>
        function (): void {
            $browser = lh_browser_panel('bots');
            try {
                lh_browser_open_cards($browser);
                lh_true(lh_browser_open_dim($browser), 'a bot class row opened its dialog');

                $shown = $browser->evaluate(lh_browser_dialog_state());
                lh_same(true, json_decode((string) $shown, true)['visible'], 'the dialog is on screen to begin with');

                $browser->click('#lh-dialog-close', 1.2);
                $after = json_decode((string) $browser->evaluate(lh_browser_dialog_state()), true);

                /* THE DEFECT, AND IT AFFECTED EVERY DIALOG RATHER THAN ONLY NESTED ONES.
                   `closeDialog()` hides by setting `hidden`, which works only because the
                   BROWSER's stylesheet says `[hidden] { display: none }` — the weakest origin
                   there is. `.lh-dialog { display: flex }` outranked it, so the attribute was
                   set, the dialog stayed on screen, and every press afterwards returned early
                   on `if (root.hidden)`. Reading `hidden` back would have agreed the dialog was
                   closed. Only a computed style disagrees. */
                lh_same('none', $after['display'], 'a closed dialog computes display:none');
                lh_same(false, $after['visible'], 'and occupies no space, which is what "closed" means to a reader');
            } finally {
                $browser->close();
            }
        },

    'a dialog opened from inside a dialog closes back to the one underneath' =>
        function (): void {
            $browser = lh_browser_panel('bots');
            try {
                lh_browser_open_cards($browser);
                lh_true(lh_browser_open_dim($browser), 'the bot class dialog opened');

                $parent = json_decode((string) $browser->evaluate(lh_browser_dialog_state()), true);
                lh_true($parent['rows'] > 0, 'the class dialog lists recent visitors, which is the nesting path');

                $opened = $browser->evaluate(
                    '(function () { var r = document.querySelector("#lh-dialog-body tr[data-lh-open=session]");'
                    . ' if (!r) { return false; } r.click(); return true; })()'
                );
                $browser->settle(2.0);
                lh_same(true, $opened, 'a visitor row inside the dialog opened the session');

                $child = json_decode((string) $browser->evaluate(lh_browser_dialog_state()), true);
                lh_true($child['title'] !== $parent['title'], 'the session dialog replaced the class dialog');
                lh_same(true, $child['visible'], 'and is on screen');

                /* THE REPORTED SYMPTOM: "its Close button does nothing". It did nothing for the
                   reason above, and even once it worked there was no way back — the drill-down
                   was one-way, and the operator who glanced at a visitor lost the class they
                   were reading. Closing now steps back one level. */
                $browser->click('#lh-dialog-close', 2.0);
                $back = json_decode((string) $browser->evaluate(lh_browser_dialog_state()), true);
                lh_same(true, $back['visible'], 'closing the session returns to the class dialog rather than the page');
                lh_same($parent['title'], $back['title'], 'and it is the same class dialog it came from');

                /* FOCUS RESTORE, IN THE DIRECTION THAT USED TO FAIL SILENTLY. The row that was
                   pressed does not survive the parent being rebuilt, so it is matched by its
                   data attributes rather than by identity — and a miss used to leave a keyboard
                   operator at the top of the document with nothing to say why. */
                lh_same(
                    'session',
                    $back['activeOpen'],
                    'and focus is back on the visitor row that was pressed, not on <body>'
                );

                $browser->click('#lh-dialog-close', 1.2);
                $out = json_decode((string) $browser->evaluate(lh_browser_dialog_state()), true);
                lh_same(false, $out['visible'], 'closing the last one leaves the page');
                lh_same('dim', $out['activeOpen'], 'with focus on the page row the whole drill started from');
            } finally {
                $browser->close();
            }
        },

    'Escape steps back through a nested dialog exactly as Close does' =>
        function (): void {
            $browser = lh_browser_panel('bots');
            try {
                lh_browser_open_cards($browser);
                lh_true(lh_browser_open_dim($browser), 'the class dialog opened');
                $parent = json_decode((string) $browser->evaluate(lh_browser_dialog_state()), true);

                $browser->evaluate(
                    '(function () { var r = document.querySelector("#lh-dialog-body tr[data-lh-open=session]");'
                    . ' if (r) { r.click(); } return 1; })()'
                );
                $browser->settle(2.0);

                /* ONE MEANING FOR "DISMISS". Close, the scrim and Escape do the same thing, so
                   nobody has to remember which of the three exits the whole stack. */
                $browser->key('Escape', 2.0);
                $back = json_decode((string) $browser->evaluate(lh_browser_dialog_state()), true);
                lh_same($parent['title'], $back['title'], 'Escape returns to the dialog underneath');

                $browser->key('Escape', 1.2);
                $out = json_decode((string) $browser->evaluate(lh_browser_dialog_state()), true);
                lh_same(false, $out['visible'], 'and a second Escape leaves the page');
            } finally {
                $browser->close();
            }
        },

    /* ------------------------------------------------------------------ 5. what dialogs render */

    'a dialog never puts a vocabulary slug where a person reads a label' =>
        function (): void {
            $browser = lh_browser_panel('bots');
            try {
                lh_browser_open_cards($browser);
                lh_true(lh_browser_open_dim($browser), 'the bot class dialog opened');

                /* THE HOLE IN THE EXISTING GUARD. tests/test_facets.php renders the twelve views
                   server-side and refuses any vocabulary slug in a text node — and a dialog is
                   built in JavaScript after it opens, so not one character of it was covered.
                   `proxy_fleet` was the <h2> of this dialog for as long as the dialog existed. */
                $slugs = [];
                foreach (\Loghound\Panel\Vocabulary::all() as $values) {
                    foreach (array_keys($values) as $value) {
                        if (str_contains((string) $value, '_')) {
                            $slugs[] = (string) $value;
                        }
                    }
                }
                lh_true(count($slugs) > 20, 'the sweep knows the vocabularies it is looking for');

                $text = (string) $browser->evaluate(
                    '(document.getElementById("lh-dialog-title").textContent || "") + "\n"'
                    . ' + (document.getElementById("lh-dialog-sub").textContent || "") + "\n"'
                    . ' + (document.getElementById("lh-dialog-body").innerText || "")'
                );
                lh_true(trim($text) !== '', 'the dialog rendered something to check');

                $found = [];
                foreach (array_unique($slugs) as $slug) {
                    if (str_contains($text, $slug)) {
                        $found[] = $slug;
                    }
                }
                lh_same(
                    [],
                    $found,
                    'a person reads "Proxy fleet", not proxy_fleet. The slug is what the URL carries and '
                        . 'what Solr stores; the mapping belongs in the documentation, not in a heading.'
                );
            } finally {
                $browser->close();
            }
        },

    'a country is marked with one flag, not two' =>
        function (): void {
            $browser = lh_browser_panel('bots');
            try {
                lh_browser_open_cards($browser);
                lh_true(lh_browser_open_dim($browser), 'the dialog with the visitor table opened');

                /* TWO FUNCTIONS EACH BELIEVED THEY OWNED THE MARK. `dimValue()` inserts the flag
                   for `country_s`, and `countryNode()` went on prepending one beside it — so
                   every row of every detail dialog, the session explorer's Where cell, the
                   cluster member tables and the countries table drew it twice. Counting the
                   flags inside each `.geo` is the only check that sees it; the markup is
                   correct, the CSS is correct, and there are simply two of them. */
                $counts = (string) $browser->evaluate(
                    '(function () { var out = [];'
                    . ' for (var g of document.querySelectorAll("#lh-dialog-body .geo")) {'
                    . '   out.push(g.querySelectorAll(".flag").length); }'
                    . ' return out.join(","); })()'
                );
                lh_true($counts !== '', 'the visitor table renders countries to count');

                $bad = [];
                foreach (explode(',', $counts) as $n) {
                    if ((int) $n > 1) {
                        $bad[] = $n;
                    }
                }
                lh_same([], $bad, 'one country, one flag — found rows carrying: ' . $counts);
            } finally {
                $browser->close();
            }
        },

    /* ------------------------------------------------------------------ 4. the two sticky bars */

    'the page toolbar pins under the section nav and condenses rather than growing' =>
        function (): void {
            $server = lh_browser_serve();
            $browser = LhBrowser::open();
            try {
                $browser->headers([
                    'Authorization' => 'Basic ' . base64_encode('loghound:' . lh_browser_password()),
                ]);

                foreach ([[1440, 900], [375, 800]] as [$width, $height]) {
                    $browser->viewport($width, $height);
                    $browser->visit($server['base'] . '/?v=bots&range=24h');
                    $browser->settle(1.0);

                    $rest = json_decode((string) $browser->evaluate(lh_browser_tools_state()), true);
                    lh_same(false, $rest['stuck'], $width . 'px: the bar is not stuck at the top of the page');

                    $browser->evaluate('window.scrollTo(0, 2000); 1');
                    $browser->settle(0.8);
                    $stuck = json_decode((string) $browser->evaluate(lh_browser_tools_state()), true);

                    lh_same(true, $stuck['stuck'], $width . 'px: scrolled, the bar is stuck');
                    lh_same(
                        $stuck['navBottom'],
                        $stuck['top'],
                        $width . 'px: it pins directly under the section nav, with no gap and no overlap'
                    );

                    /* DO NOT EAT THE VIEWPORT. The first version of the condensed state simply
                       tightened the padding and revealed the scope line, and the bar got TALLER
                       — 106px became 116px at 1440, and 225px became 235px at 375 where the
                       controls wrap to four rows. Two sticky bars costing a third of a phone
                       screen is the thing this must not become, so the assertion is on the
                       measurement rather than on the intent. */
                    lh_true(
                        $stuck['height'] < $rest['height'],
                        $width . 'px: stuck (' . $stuck['height'] . 'px) must be shorter than at rest ('
                            . $rest['height'] . 'px) — a condensed state that costs more is not condensed'
                    );
                    lh_true(
                        $stuck['height'] + $stuck['navHeight'] < $height / 4,
                        $width . 'px: both bars together take ' . ($stuck['height'] + $stuck['navHeight'])
                            . 'px of a ' . $height . 'px viewport, which is more than a quarter of it'
                    );

                    /* WHAT MATTERS MOST WHEN SCROLLED is what the numbers are scoped to, and it
                       is the one thing the controls stop saying once they are condensed. */
                    lh_true(
                        trim((string) $stuck['scope']) !== '',
                        $width . 'px: the condensed bar states the range and host the page is scoped to'
                    );
                }
            } finally {
                $browser->close();
            }
        },

    'a jump from the section nav clears both sticky bars' =>
        function (): void {
            $server = lh_browser_serve();
            $browser = LhBrowser::open();
            try {
                $browser->headers([
                    'Authorization' => 'Basic ' . base64_encode('loghound:' . lh_browser_password()),
                ]);

                foreach ([[1440, 900], [375, 800]] as [$width, $height]) {
                    $browser->viewport($width, $height);
                    foreach (['bots', 'settings'] as $view) {
                        $browser->visit($server['base'] . '/?v=' . $view . '&range=24h');
                        $browser->settle(1.0);

                        $jumped = $browser->evaluate(
                            '(function () { var a = document.querySelector(".set-nav a");'
                            . ' if (!a) { return false; } a.click(); return true; })()'
                        );
                        if ($jumped !== true) {
                            continue;
                        }
                        $browser->settle(1.2);

                        /* `scroll-margin-top` used to clear ONE bar. A second sticky bar under
                           it means a jump lands the heading underneath, which is the same defect
                           the section nav's own offset was added to fix — so the offset is the
                           sum, and this measures the outcome rather than the arithmetic. */
                        $result = (string) $browser->evaluate(
                            '(function () {'
                            . ' var h = location.hash.slice(1); if (!h) { return "no hash"; }'
                            . ' var t = document.getElementById(h); if (!t) { return "no target"; }'
                            . ' var bar = document.getElementById("lh-page-tools");'
                            . ' var nav = document.querySelector(".set-nav");'
                            . ' var floor = bar && !bar.hidden'
                            . '   ? bar.getBoundingClientRect().bottom'
                            . '   : (nav ? nav.getBoundingClientRect().bottom : 0);'
                            . ' var head = t.querySelector(".card-head") || t;'
                            . ' return head.getBoundingClientRect().top >= floor - 1'
                            . '   ? "clear"'
                            . '   : "under the bar by " + Math.round(floor - head.getBoundingClientRect().top) + "px";'
                            . '})()'
                        );

                        lh_same(
                            'clear',
                            $result,
                            $width . 'px / ' . $view . ': the jump target landed underneath the pinned bars'
                        );
                    }
                }
            } finally {
                $browser->close();
            }
        },

    /* ------------------------------------------------------------------ 3. the facet column */

    'the facet groups are a left column beside the results, on every view that has them' =>
        function (): void {
            $server = lh_browser_serve();
            $browser = LhBrowser::open();
            try {
                $browser->headers([
                    'Authorization' => 'Basic ' . base64_encode('loghound:' . lh_browser_password()),
                ]);
                $browser->viewport(1440, 900);

                $seen = 0;
                foreach (lh_browser_views() as $view) {
                    $browser->visit($server['base'] . '/?v=' . $view . '&range=24h');
                    $browser->settle(0.8);
                    $state = json_decode((string) $browser->evaluate(lh_browser_facet_state()), true);

                    if (!$state['panel']) {
                        /* A view that declares no facets must not grow a "Filter by" that does
                           nothing — the same rule Controller::toolbar() already enforces for the
                           range picker and the host selector. */
                        lh_same(false, $state['bar'], $view . ' declares no facets and must show no filter control');
                        continue;
                    }
                    $seen++;

                    /* ONE PRESENTATION: a column BESIDE the results, never a band above them
                       with every card pushed below. Measured as "the panel's right edge is left
                       of the first card's left edge", which is what beside means and what a
                       full-width block cannot satisfy. */
                    lh_true(
                        $state['panelRight'] <= $state['cardLeft'],
                        $view . ': the facet panel (right edge ' . $state['panelRight'] . ') overlaps or sits above '
                            . 'the first card (left edge ' . $state['cardLeft'] . ') instead of beside it'
                    );
                    lh_true(
                        abs($state['panelTop'] - $state['cardTop']) < 8,
                        $view . ': the facet column and the first card start at the same height — '
                            . $state['panelTop'] . ' against ' . $state['cardTop']
                    );
                }

                lh_true($seen >= 4, 'several views carry facets, so the sweep means something: ' . $seen);
            } finally {
                $browser->close();
            }
        },

    'applying a filter leaves the facets exactly where they were' =>
        function (): void {
            $server = lh_browser_serve();
            $browser = LhBrowser::open();
            try {
                $browser->headers([
                    'Authorization' => 'Basic ' . base64_encode('loghound:' . lh_browser_password()),
                ]);
                $browser->viewport(1440, 900);

                $browser->visit($server['base'] . '/?v=bots&range=24h');
                $browser->settle(1.2);
                $before = json_decode((string) $browser->evaluate(lh_browser_facet_state()), true);
                lh_same(true, $before['panelVisible'], 'the groups are shown to begin with');

                /* THE WORST MOMENT TO REMOVE THE CONTROLS. Applying a filter reloads the page,
                   and the panel was created hidden on every load with nothing written down — so
                   the sidebar vanished at exactly the moment the next facet was wanted. */
                $browser->visit($server['base'] . '/?v=bots&range=24h&f%5Bbot_class_s%5D%5B%5D=proxy_fleet');
                $browser->settle(1.2);
                $after = json_decode((string) $browser->evaluate(lh_browser_facet_state()), true);

                lh_same(true, $after['panelVisible'], 'and they are still shown once a filter has been applied');
                lh_true($after['chips'] > 0, 'with the applied value on a chip: ' . $after['chips']);
            } finally {
                $browser->close();
            }
        },

    'hiding the facets is remembered, and is what a reader asked for by hiding them' =>
        function (): void {
            $server = lh_browser_serve();
            $browser = LhBrowser::open();
            try {
                $browser->headers([
                    'Authorization' => 'Basic ' . base64_encode('loghound:' . lh_browser_password()),
                ]);
                $browser->viewport(1440, 900);

                $browser->visit($server['base'] . '/?v=bots&range=24h');
                $browser->settle(1.2);
                lh_same(true, $browser->click('#lh-facets-toggle', 1.0), 'the hide control is there to press');

                $shut = json_decode((string) $browser->evaluate(lh_browser_facet_state()), true);
                lh_same(false, $shut['panelVisible'], 'pressing it hides the groups');
                lh_true($shut['cardLeft'] < 200, 'and the results take the width back: ' . $shut['cardLeft']);

                /* PER OPERATOR, THE WAY THE ACCORDION SECTIONS ARE. The choice used to be
                   forgotten by the next navigation, so a reader who hid the filters had to hide
                   them again on every page. */
                $browser->visit($server['base'] . '/?v=sessions&range=24h');
                $browser->settle(1.2);
                $next = json_decode((string) $browser->evaluate(lh_browser_facet_state()), true);
                lh_same(false, $next['panelVisible'], 'and the next view remembers that they are hidden');
            } finally {
                $browser->close();
            }
        },

    /* ------------------------------------------------------------------ 8. cut facet values */

    'a facet value the column had to cut can be read in full, and one that fits is left alone' =>
        function (): void {
            $browser = lh_browser_panel('bots');
            try {
                $browser->settle(1.5);

                /* THE DEFECT. `.facet-val` and `.fchip-val` truncate with an ellipsis — an AS
                   organisation, a path or a User-Agent is routinely longer than a 292px column —
                   and there was no way at all to read the rest. The `title` on the row did not
                   help: it carries the DIMENSION's explanation, so the bubble described the
                   category while the value stayed unreadable.

                   MEASURED, NOT ASSUMED, in both directions. A tooltip repeating a value that is
                   fully on screen is noise the reader has to dismiss, so the check is that the
                   mark tracks the overflow exactly: every cut value carries it, and no value
                   that fits does. */
                $report = json_decode((string) $browser->evaluate(
                    'JSON.stringify((function () {'
                    . ' var cut = 0, fits = 0, wrong = [];'
                    . ' for (var a of document.querySelectorAll(".facet-opt, .fchip")) {'
                    . '   var v = a.querySelector(".facet-val, .fchip-val"); if (!v) { continue; }'
                    . '   var isCut = v.scrollWidth > v.clientWidth;'
                    . '   var marked = a.hasAttribute("data-lh-tip");'
                    . '   var full = a.getAttribute("data-full") || "";'
                    . '   if (isCut) { cut++; } else { fits++; }'
                    . '   if (isCut && !marked) { wrong.push("cut but unreadable: " + v.textContent.slice(0, 40)); }'
                    . '   if (!isCut && marked) { wrong.push("fits but has a tooltip: " + v.textContent.slice(0, 40)); }'
                    . '   if (isCut && marked && full.trim() !== v.textContent.trim()) {'
                    . '     wrong.push("tooltip is not the value: " + full.slice(0, 40)); } }'
                    . ' return { cut: cut, fits: fits, wrong: wrong }; })())'
                ), true);

                lh_true(
                    $report['cut'] + $report['fits'] > 5,
                    'the sidebar rendered values to check: ' . $report['cut'] . ' cut, ' . $report['fits'] . ' whole'
                );
                lh_same([], $report['wrong'], "the tooltip does not track the truncation:\n  "
                    . implode("\n  ", $report['wrong']));

                /* AND IT IS THE PANEL'S TOOLTIP, NOT THE BROWSER'S. The native bubble arrives a
                   second late, in a different place, in the browser's own type, beside three
                   hints that do none of those things — and two tooltips on one element is what
                   parkTitle() exists to prevent. A marked row parks its `title` for exactly as
                   long as the value is cut. */
                $both = $browser->evaluate(
                    '(function () { var n = 0;'
                    . ' for (var a of document.querySelectorAll(".facet-opt[data-lh-tip], .fchip[data-lh-tip]")) {'
                    . '   if (a.hasAttribute("title")) { n++; } } return n; })()'
                );
                lh_same(0, $both, 'a row showing the panel\'s tooltip must not also fire the browser\'s');
            } finally {
                $browser->close();
            }
        },

    /* ------------------------------------------------------------------ 6. sibling alignment */

    'sibling columns in a block share a left edge, a width and a heading baseline' =>
        function (): void {
            $browser = lh_browser_panel('indexes', ['range' => '24h']);
            try {
                /* THE BLOCK IS THE INDEX VIEW'S "Slice these figures" — HANDLER / STATUS / NODE
                   / CALLER. It cannot be reached from a demo world: the Opensolr request log is
                   a platform API, not a Solr core, and this suite makes no network call. So the
                   REAL renderer is driven with a REAL payload inside the page, against the real
                   stylesheet, which is what the measurement is about. */
                $rendered = $browser->evaluate(lh_browser_rail_render(), 20.0);
                lh_same('rendered 4', $rendered, 'the four-column block was built to measure');

                $block = json_decode((string) $browser->evaluate(lh_browser_rail_measure()), true);
                $columns = $block['cols'];
                lh_same(4, count($columns), 'four columns');

                /* EACH OF THESE WAS ITS OWN DEFECT, AND EACH IS ONE NUMBER.

                   The first column sat 17px higher than the other three, because `.facet` —
                   a class written for the vertically STACKED sidebar, where `:first-child`
                   correctly drops the separator above the first group — was applied to grid
                   items, where "first" means leftmost.

                   The columns were different widths, because a grid item's `min-width` is
                   `auto`: one long handler path refused to shrink to its track and took the
                   room from its neighbours.

                   And no column read as a column, because `.fm` — the tick, the minus or the
                   empty string — had no rule at all, so a selected row's value started 14px to
                   the right of an unselected one's. */
                $tops = array_unique(array_column($columns, 'headTop'));
                lh_same(1, count($tops), 'every heading sits on the same line: ' . implode(', ', $tops));

                $rules = array_unique(array_column($columns, 'ruleBottom'));
                lh_same(1, count($rules), 'and every rule under a heading is at the same height: '
                    . implode(', ', $rules));

                $widths = array_unique(array_column($columns, 'colW'));
                lh_same(1, count($widths), 'the columns are the same width: ' . implode(', ', $widths));

                foreach ($columns as $column) {
                    lh_same(
                        1,
                        count(explode('/', (string) $column['valLefts'])),
                        $column['name'] . ': its values start at more than one left edge ('
                            . $column['valLefts'] . '), so the column does not read as a column'
                    );
                    lh_same(
                        1,
                        count(explode('/', (string) $column['cntRights'])),
                        $column['name'] . ': its counts end at more than one right edge (' . $column['cntRights'] . ')'
                    );
                }

                /* ONE FACT ABOUT THE BLOCK IS PRINTED ONCE. "Counts are what each value matches
                   on this page as filtered." was emitted per group, so the identical sentence
                   appeared four times, each under its own hairline, at four different heights,
                   below a card note that already referred to it. */
                lh_same(0, $block['perColumn'], 'the shared sentence is not repeated under every column');
                lh_same(1, $block['block'], 'it is said once, for the block it describes');
            } finally {
                $browser->close();
            }
        },

    /* ------------------------------------------------------------- 9. no sideways scrolling */

    'no page scrolls sideways at 375, with every section open' =>
        function (): void {
            /* MEASURED: Settings laid out an 809px document in a 375px viewport with the
               accordion expanded. Nothing on the page was an ELEMENT wider than the viewport —
               every candidate measured 343px — because the overflow was an inline TEXT RUN: the
               schema card prints an absolute path to `solr/hits/conf/schema.xml`, and a path is
               one word to a line breaker. It has no space, and `/` and `-` are not break
               opportunities by default, so it ran out of its block box and dragged the
               document's scroll area with it.

               THIS IS THE TEST, AND IT IS A BROWSER'S ANSWER ON PURPOSE. `body { overflow-x:
               hidden }` was in this codebase once and was removed precisely because it CLIPPED
               this class of defect rather than fixing it — with it in place the measurement that
               found this could not have found it again. A source-reading test cannot tell a
               fitted page from a hidden overflow; a rendering engine can. */
            $server = lh_browser_serve();
            $browser = LhBrowser::open();
            try {
                $browser->headers([
                    'Authorization' => 'Basic ' . base64_encode('loghound:' . lh_browser_password()),
                ]);

                foreach (lh_browser_views() as $view) {
                    $browser->viewport(375, 800);
                    $browser->visit($server['base'] . '/?v=' . $view . '&range=24h');
                    $browser->settle(1.0);
                    lh_browser_open_cards($browser);
                    $browser->evaluate(
                        '(function () { for (var d of document.querySelectorAll("details")) { d.open = true; }'
                        . ' return 1; })()'
                    );
                    $browser->settle(0.8);

                    $width = (int) $browser->evaluate('document.documentElement.scrollWidth');
                    $client = (int) $browser->evaluate('document.documentElement.clientWidth');

                    if ($width > $client) {
                        /* NAME WHAT IS WIDE, or the failure is a number nobody can act on. The
                           cause is reported as the deepest box whose own content overflows it
                           and which is not inside something that scrolls. */
                        $blame = (string) $browser->evaluate(lh_browser_overflow_blame());
                        lh_fail(
                            $view . ' scrolls sideways at 375: the document is ' . $width
                            . 'px against a ' . $client . "px viewport.\n" . $blame
                        );
                    }
                }
            } finally {
                $browser->close();
            }
        },

    'a long path or a long failure scrolls inside its own block, never widening the page' =>
        function (): void {
            $browser = lh_browser_panel('settings', [], 375);
            try {
                $browser->viewport(375, 800);
                $browser->settle(1.0);
                lh_browser_open_cards($browser);
                $browser->settle(0.6);

                /* THE CARDS ADDED WITH THIS RULE IN MIND: a critical error carries an absolute
                   path and a whole failure artefact, and the teardown card carries three
                   absolute commands. The rule for both is the same as for every command block
                   already on the page — a `<pre class="snippet">` may scroll within itself, and
                   must not widen the page it is on. */
                $report = json_decode((string) $browser->evaluate(
                    'JSON.stringify((function () {'
                    . ' var wide = 0, scrolls = 0, bad = [];'
                    . ' for (var p of document.querySelectorAll(".view pre.snippet")) {'
                    . '   var s = getComputedStyle(p);'
                    . '   if (p.scrollWidth > p.clientWidth + 1) { wide++;'
                    . '     if (s.overflowX === "auto" || s.overflowX === "scroll") { scrolls++; }'
                    . '     else { bad.push(p.id || p.textContent.slice(0, 40)); } }'
                    . '   if (Math.round(p.getBoundingClientRect().right) > document.documentElement.clientWidth + 1) {'
                    . '     bad.push("reaches past the viewport: " + (p.id || p.textContent.slice(0, 40))); } }'
                    . ' return { wide: wide, scrolls: scrolls, bad: bad }; })())'
                ), true);

                lh_true((int) $report['wide'] > 0, 'the page rendered content longer than the column');
                lh_same([], $report['bad'], "a block that cannot scroll and does not fit:\n  "
                    . implode("\n  ", (array) $report['bad']));
                lh_same(
                    (int) $report['wide'],
                    (int) $report['scrolls'],
                    'every block too long for the column scrolls within itself'
                );
            } finally {
                $browser->close();
            }
        },
];

/**
 * Name the box that is making the document wider than the viewport.
 *
 * Reported rather than guessed, because the useful answer is rarely an element wider than the
 * screen: it is usually a block of ordinary width whose own inline content overflows it — an
 * unbreakable path, a long identifier — which is invisible to anything measuring widths. So the
 * candidates are boxes whose `scrollWidth` exceeds their `clientWidth` and which are NOT inside
 * something that scrolls, which is exactly the set that pushes the page.
 */
function lh_browser_overflow_blame(): string
{
    return '(function () {'
        . ' var out = [];'
        . ' var clipped = function (n) { var p = n.parentElement;'
        . '   while (p && p !== document.documentElement) { var s = getComputedStyle(p);'
        . '     if (s.overflowX === "auto" || s.overflowX === "scroll" || s.overflowX === "hidden") { return true; }'
        . '     p = p.parentElement; } return false; };'
        . ' for (var n of document.querySelectorAll(".view *")) {'
        /* An inline box has no clientWidth at all, so every empty mark on the page reports as
           "8px in a 0px box" and buries the one line that says what is actually wrong. */
        . '   if (n.clientWidth === 0) { continue; }'
        . '   if (n.scrollWidth <= n.clientWidth + 1) { continue; }'
        . '   var s = getComputedStyle(n);'
        . '   if (s.overflowX === "auto" || s.overflowX === "scroll" || s.overflowX === "hidden") { continue; }'
        . '   if (clipped(n)) { continue; }'
        . '   var deeper = false;'
        . '   for (var c of n.children) { var cs = getComputedStyle(c);'
        . '     if (c.scrollWidth > c.clientWidth + 1 && cs.overflowX === "visible") { deeper = true; break; } }'
        . '   if (deeper) { continue; }'
        . '   out.push("  " + n.scrollWidth + "px in a " + n.clientWidth + "px box: <"'
        . '     + n.tagName.toLowerCase() + (n.className ? " class=\\"" + n.className + "\\"" : "")'
        . '     + "> " + (n.textContent || "").trim().slice(0, 70).replace(/\\s+/g, " ")); }'
        . ' return out.length ? out.join("\\n") : "  no unclipped box overflows; look at a fixed width or a grid track"; })()';
}

/**
 * Open every accordion section, so the rows under them can be pressed and measured.
 *
 * A shut section is `display: none`, and a row inside one has no box: it can still be clicked
 * from script, but it cannot take focus and it measures zero — which makes every assertion
 * about position or focus meaningless rather than false. Opening them first is the difference
 * between testing the panel and testing a collapsed one.
 */
function lh_browser_open_cards(LhBrowser $browser): void
{
    $browser->evaluate(
        '(function () { for (var c of document.querySelectorAll(".card.is-shut")) {'
        . ' var t = c.querySelector(":scope > .card-head .card-toggle"); if (t) { t.click(); } }'
        . ' return 1; })()'
    );
    $browser->settle(1.2);
}

/** Press the first bot-class row, which is the dialog the nesting defect was reported from. */
function lh_browser_open_dim(LhBrowser $browser): bool
{
    $hit = $browser->evaluate(
        '(function () { var r = document.querySelector("#bf-classes-table tr[data-lh-open=dim]");'
        . ' if (!r) { return false; } r.click(); return true; })()'
    );
    $browser->settle(2.5);

    return $hit === true;
}

/**
 * The dialog as a reader experiences it: is it on screen, what does it say, where is focus.
 *
 * `visible` is a measured height rather than the `hidden` property, because reading the
 * property back is precisely what failed to notice that the dialog never closed.
 */
function lh_browser_dialog_state(): string
{
    return 'JSON.stringify((function () {'
        . ' var d = document.getElementById("lh-dialog");'
        . ' var a = document.activeElement;'
        . ' return {'
        . '  present: !!d,'
        . '  display: d ? getComputedStyle(d).display : null,'
        . '  visible: d ? d.getBoundingClientRect().height > 0 : false,'
        . '  title: (document.getElementById("lh-dialog-title") || {}).textContent || "",'
        . '  rows: document.querySelectorAll("#lh-dialog-body tr[data-lh-open=session]").length,'
        . '  activeOpen: a && a.dataset ? (a.dataset.lhOpen || "") : ""'
        . ' }; })())';
}

/** The two pinned bars, measured against each other and against the viewport. */
function lh_browser_tools_state(): string
{
    return 'JSON.stringify((function () {'
        . ' var bar = document.getElementById("lh-page-tools");'
        . ' var nav = document.querySelector(".set-nav");'
        . ' var b = bar ? bar.getBoundingClientRect() : null;'
        . ' var n = nav ? nav.getBoundingClientRect() : null;'
        . ' return {'
        . '  present: !!bar,'
        . '  stuck: bar ? bar.classList.contains("is-stuck") : false,'
        . '  top: b ? Math.round(b.top) : null,'
        . '  height: b ? Math.round(b.height) : 0,'
        . '  navBottom: n ? Math.round(n.bottom) : null,'
        . '  navHeight: n ? Math.round(n.height) : 0,'
        . '  scope: (document.getElementById("lh-page-scope") || {}).textContent || ""'
        . ' }; })())';
}

/** Where the facet furniture ended up, and how much room the results were left. */
function lh_browser_facet_state(): string
{
    return 'JSON.stringify((function () {'
        . ' var p = document.getElementById("lh-facets-panel");'
        . ' var bar = document.getElementById("lh-filters");'
        . ' var card = document.querySelector(".view > .card");'
        . ' var pr = p ? p.getBoundingClientRect() : null;'
        . ' var cr = card ? card.getBoundingClientRect() : null;'
        . ' return {'
        . '  panel: !!p, bar: !!bar,'
        . '  panelVisible: p ? p.getBoundingClientRect().height > 0 : false,'
        . '  panelRight: pr ? Math.round(pr.right) : 0,'
        . '  panelTop: pr ? Math.round(pr.top) : 0,'
        . '  cardLeft: cr ? Math.round(cr.left) : 0,'
        . '  cardTop: cr ? Math.round(cr.top) : 0,'
        . '  chips: document.querySelectorAll("#lh-filters-active .fchip").length'
        . ' }; })())';
}

/**
 * Build the Index view's four-column block from a payload shaped like the server's.
 *
 * The payload deliberately carries a handler path far longer than a 180px track and counts of
 * wildly different digit lengths, because those are the two inputs that produced the unequal
 * widths and the ragged counts. A tidy payload would measure a tidy block and prove nothing.
 */
function lh_browser_rail_render(): string
{
    $payload = json_encode([
        'limit' => 12,
        'requests' => 99646,
        'state' => 'ok',
        'active' => [],
        'groups' => [
            ['field' => 'path', 'label' => 'Handler', 'basis' => 'filtered',
                'basis_note' => 'Counts are what each value matches on this page as filtered.',
                'buckets' => [
                    ['value' => '/select', 'count' => 91234],
                    ['value' => '/update/json/docs/with/an/extremely/long/handler/path', 'count' => 8],
                    ['value' => '/admin/mbeans', 'count' => 412],
                ]],
            ['field' => 'http_status', 'label' => 'Status', 'basis' => 'filtered',
                'basis_note' => 'Counts are what each value matches on this page as filtered.',
                'buckets' => [['value' => '200', 'count' => 90000], ['value' => '404', 'count' => 7]]],
            ['field' => 'param_hostname', 'label' => 'Node', 'basis' => 'filtered',
                'basis_note' => 'Counts are what each value matches on this page as filtered.',
                'buckets' => [['value' => 'node-one.example.invalid', 'count' => 51000]]],
            ['field' => 'ip', 'label' => 'Caller', 'basis' => 'filtered',
                'basis_note' => 'Counts are what each value matches on this page as filtered.',
                'buckets' => [['value' => '203.0.113.9', 'count' => 12], ['value' => '198.51.100.4', 'count' => 3400]]],
        ],
    ], JSON_UNESCAPED_SLASHES);

    return '(async function () {'
        . ' const m = await import("./assets/js/views/opensolr.js");'
        . ' const host = document.querySelector(".view") || document.body;'
        . ' const slots = [["lf-active", "ix-filters-active"], ["lf-outcomes", "ix-filters-outcomes"],'
        . '   ["lf-rail", "ix-filters-rail"]];'
        . ' for (const [cls, id] of slots) {'
        . '   if (!document.getElementById(id)) {'
        . '     const d = document.createElement("div"); d.className = cls; d.id = id; host.appendChild(d); } }'
        . ' for (const [tag, cls, id] of [["div", "empty", "ix-filters-empty"], ["p", "faint", "ix-filters-note"]]) {'
        . '   if (!document.getElementById(id)) {'
        . '     const n = document.createElement(tag); n.className = cls; n.id = id; host.appendChild(n); } }'
        . ' try { m.renderFilters("ix-filters", ' . $payload . '); }'
        . ' catch (e) { return "renderFilters threw: " + e.message; }'
        . ' return "rendered " + document.querySelectorAll("#ix-filters-rail > .facet").length;'
        . '})()';
}

/** Computed left edge, width, heading baseline and value edges, per sibling column. */
function lh_browser_rail_measure(): string
{
    return 'JSON.stringify((function () {'
        . ' var rail = document.getElementById("ix-filters-rail");'
        . ' var out = [];'
        . ' for (var c of rail.querySelectorAll(":scope > .facet")) {'
        . '   var h = c.querySelector("h3"); var hr = h.getBoundingClientRect();'
        . '   var lefts = [], rights = [];'
        . '   for (var v of c.querySelectorAll(".fv")) { lefts.push(Math.round(v.getBoundingClientRect().left)); }'
        . '   for (var n of c.querySelectorAll(".fc")) { rights.push(Math.round(n.getBoundingClientRect().right)); }'
        . '   var uniq = function (a) { return a.filter(function (x, i) { return a.indexOf(x) === i; }); };'
        . '   out.push({ name: h.textContent,'
        . '     colLeft: Math.round(c.getBoundingClientRect().left),'
        . '     colW: Math.round(c.getBoundingClientRect().width),'
        . '     headTop: Math.round(hr.top), ruleBottom: Math.round(hr.bottom),'
        . '     valLefts: uniq(lefts).join("/"), cntRights: uniq(rights).join("/") }); }'
        . ' return { cols: out,'
        . '   perColumn: rail.querySelectorAll(".facet > .facet-basis").length,'
        . '   block: rail.querySelectorAll(".facet-basis-all").length }; })())';
}
