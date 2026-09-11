<?php
/**
 * Loghound — tests for the phone and tablet build.
 *
 * The panel was measured at 375, 390, 414 and 768 CSS pixels in both themes before any of it
 * was written, and what those measurements found is what these tests pin:
 *
 *   - the page scrolled sideways at 375 and 390 on three views, because a grid track was
 *     declared wider than the column it lives in;
 *   - the view navigation cost 317px of a 780px viewport;
 *   - a ten-column table was a 900px canvas inside a 343px window;
 *   - controls measured between 18px and 31px against a 44px thumb;
 *   - four labels were set at 13px against a 14px floor.
 *
 * These are source-level assertions rather than rendering assertions, because the suite runs
 * with no browser and no network (SPEC §12). They therefore pin the DECISIONS — the queries,
 * the gates, the units — not the pixels, and every one of them names the defect it prevents
 * coming back.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

/** Read a file from the repository root, failing the test if it is not there. */
function lh_rp_file(string $relative): string
{
    $path = dirname(__DIR__) . '/' . $relative;
    if (!is_file($path)) {
        lh_fail($relative . ' is missing');
    }
    return (string) file_get_contents($path);
}

/** A stylesheet with its comment blocks removed, so prose cannot fail a rule assertion. */
function lh_rp_declarations(string $relative): string
{
    return (string) preg_replace('#/\*.*?\*/#s', '', lh_rp_file($relative));
}

/** PHP source with its docblocks removed, for the same reason. */
function lh_rp_code(string $relative): string
{
    return (string) preg_replace('#/\*.*?\*/#s', '', lh_rp_file($relative));
}

/** Every stylesheet and every page head, for the rules that must hold across all of them. */
function lh_rp_heads(): array
{
    return [
        'src/Panel/Layout.php',
        'src/Setup/View.php',
        'src/Panel/Login.php',
    ];
}

return [
    'the phone stylesheet exists and is loaded after panel.css on every page' =>
        function (): void {
            lh_rp_file('public/assets/css/mobile.css');

            foreach (lh_rp_heads() as $head) {
                $php = lh_rp_file($head);
                $panel = strpos($php, "assets/css/panel.css");
                $mobile = strpos($php, "assets/css/mobile.css");
                lh_true($panel !== false, $head . ' must link panel.css');
                lh_true($mobile !== false, $head . ' must link mobile.css');
                lh_true(
                    $mobile > $panel,
                    $head . ': mobile.css must be linked AFTER panel.css or none of it wins the cascade'
                );
            }
        },

    'the behaviour module is loaded as a module on every page that has chrome' =>
        function (): void {
            foreach (lh_rp_heads() as $head) {
                $php = lh_rp_file($head);
                lh_contains(
                    $php,
                    "assets/js/responsive.js",
                    $head . ' must load the module that builds the drawer and stacks the tables'
                );
                lh_contains(
                    $php,
                    'type="module" src=',
                    $head . ' must load it as a module'
                );
            }
        },

    'no page reaches for an inline script, which the CSP has no unsafe-inline for' =>
        function (): void {
            $js = lh_rp_file('public/assets/js/responsive.js');
            lh_false((bool) preg_match('/\bonclick\s*=/i', $js), 'no inline handler');
            lh_false((bool) preg_match('/[\'"`]javascript:/i', $js), 'no javascript: URL');
            lh_false((bool) preg_match('/\beval\s*\(/', $js), 'no eval');
            lh_false(str_contains($js, 'new Function'), 'no function compiled from a string');
            lh_false((bool) preg_match('/\.innerHTML\s*=/', $js), 'DOM is built with textContent');
            lh_false(
                (bool) preg_match('/\.(outerHTML|insertAdjacentHTML)\b/', $js),
                'no markup-parsing sink'
            );
        },

    'nothing in the phone stylesheet is set below the 14px floor' =>
        function (): void {
            foreach (['public/assets/css/mobile.css', 'public/assets/css/panel.css'] as $file) {
                $css = lh_rp_declarations($file);
                if (preg_match_all('/font-size:\s*(\d+(?:\.\d+)?)px/', $css, $m)) {
                    foreach ($m[1] as $px) {
                        lh_true(
                            (float) $px >= 14.0,
                            $file . ': ' . $px . 'px is below the panel floor of 14px'
                        );
                    }
                }
                if (preg_match_all('/font:\s*[^;]*?\b(\d+(?:\.\d+)?)px\//', $css, $m2)) {
                    foreach ($m2[1] as $px) {
                        lh_true(
                            (float) $px >= 14.0,
                            $file . ': a font shorthand sets ' . $px . 'px, below the floor'
                        );
                    }
                }
            }
        },

    'the phone stylesheet names no colour of its own — every one is a token' =>
        function (): void {
            $css = lh_rp_declarations('public/assets/css/mobile.css');
            lh_false(
                (bool) preg_match('/#[0-9a-fA-F]{3,8}\b/', $css),
                'a literal hex in here would not follow the theme; use a var(--token)'
            );
            foreach (['white', 'black', 'red', 'green', 'blue', 'grey', 'gray', 'orange'] as $name) {
                lh_false(
                    (bool) preg_match('/[:\s]' . $name . '\s*[;}]/i', $css),
                    'a colour name (' . $name . ') is never allowed in this project'
                );
            }
        },

    'a grid track can never be declared wider than the column it sits in' =>
        function (): void {
            $mobile = lh_rp_declarations('public/assets/css/mobile.css');

            // The measured defect: repeat(auto-fit, minmax(380px, 1fr)) in a 343px column made
            // the document 396px wide at 375, on Bot forensics and on Networks.
            preg_match_all('/minmax\(\s*(\d+)px/', $mobile, $m);
            lh_same([], $m[1], 'every minmax in the phone sheet must use min(100%, …)');
            foreach (['.grid-2', '.split-card', '.planes', '.collects', '.stats', '.timing-grid'] as $sel) {
                lh_contains(
                    $mobile,
                    $sel,
                    $sel . ' was one of the grids that could out-measure the viewport'
                );
            }
            lh_true(
                substr_count($mobile, 'minmax(min(100%,') >= 9,
                'every auto-fit grid in the panel has to be guarded, not only the two it was noticed on'
            );
        },

    'every layout switch is gated on a class only the module can add' =>
        function (): void {
            $css = lh_rp_file('public/assets/css/mobile.css');
            $js = lh_rp_file('public/assets/js/responsive.js');

            // With scripting off the panel must keep the layout it has rather than half of this
            // one: the drawer has no control to open it and a stacked table has no labels.
            lh_contains($css, '.lh-nav-js .side', 'the drawer must not apply without its control');
            lh_contains($css, 'table.lh-stack', 'a stacked table must not apply without its labels');
            lh_contains($js, "classList.add('lh-nav-js')", 'the module is what declares the drawer usable');
            lh_contains($js, "add('lh-stack')", 'the module is what declares a table stacked');
        },

    'the drawer keeps everything reachable rather than hiding it' =>
        function (): void {
            $css = lh_rp_file('public/assets/css/mobile.css');
            $js = lh_rp_file('public/assets/js/responsive.js');

            lh_contains($css, '.side.is-open > ul', 'every view link is in the open drawer');
            lh_contains($css, '.side.is-open > .theme-toggle', 'so is the theme control');
            lh_contains($css, '.side.is-open > .signout', 'so is sign out');

            lh_contains($js, "aria-expanded", 'the control must say whether it is open');
            lh_contains($js, "'Escape'", 'Escape closes, as it does on every overlay in the panel');
            lh_contains($js, 'lastFocus', 'closing returns focus to whatever opened it');
        },

    'a stacked table keeps every column, and keeps its sort control' =>
        function (): void {
            $css = lh_rp_file('public/assets/css/mobile.css');
            $js = lh_rp_file('public/assets/js/responsive.js');

            lh_contains($css, 'content: attr(data-lh-col)', 'every cell carries its own column heading');
            lh_contains($css, 'table.lh-stack thead th.sortable', 'the header becomes the sort control');
            lh_false(
                (bool) preg_match('/table\.lh-stack tbody td\s*\{[^}]*display:\s*none/s', $css),
                'no column may be dropped on a phone'
            );
            lh_contains($js, 'stampLabels', 'labels are copied onto rows the views render after load');
            lh_contains($js, 'MutationObserver', 'rows arrive from a fetch and again on every sort');
        },

    'which tables stack is measured, never guessed from a column count' =>
        function (): void {
            $js = lh_rp_file('public/assets/js/responsive.js');
            lh_contains($js, 'getBoundingClientRect().width > host.clientWidth', 'the test is width, not columns');
            lh_contains(
                $js,
                "classList.remove('lh-stack')",
                'the class has to come off before measuring or a stacked table always answers "I fit"'
            );
        },

    'touch sizing is one number, applied to every control that was too small' =>
        function (): void {
            $css = lh_rp_file('public/assets/css/mobile.css');
            lh_contains($css, '--lh-tap: 44px', 'one token decides every target');
            lh_contains($css, '(pointer: coarse), (max-width: 900px)', 'a tablet needs a thumb target too');

            // Every one of these was measured under 32px tall before the pass.
            foreach (['.ranges a', '.facet-opt', '.expander', 'th.sortable', '.setup-rail li a', '.tab'] as $sel) {
                lh_contains($css, $sel, $sel . ' was one of the controls measured below 44px');
            }
        },

    'the panel never renders a page that scrolls sideways by construction' =>
        function (): void {
            $css = lh_rp_file('public/assets/css/mobile.css');
            lh_contains($css, 'overflow-wrap: anywhere', 'an unbreakable path must wrap, not push the page out');
            lh_contains($css, 'min-width: 0', 'a grid or flex child must be allowed to shrink below its content');
            lh_false(
                str_contains($css, 'html { overflow-x: hidden'),
                'hiding the scrollbar hides the defect; the causes are fixed instead'
            );
        },

    'motion and safe areas are both handled' =>
        function (): void {
            $css = lh_rp_file('public/assets/css/mobile.css');
            lh_contains($css, '@media (prefers-reduced-motion: no-preference)', 'motion is opt-in, not opt-out');
            lh_contains($css, 'env(safe-area-inset-left)', 'a notch must not sit on the first character');
            lh_contains($css, 'env(safe-area-inset-bottom)', 'a gesture bar must not sit on the last row');
        },

    'a colgroup states every width in the same unit and they sum to 100' =>
        function (): void {
            // THE MEASURED DEFECT. Mixing `ch`, `px` and `%` in one colgroup over-constrains a
            // fixed-layout table: 737px of ch widths plus 35% in a 900px table starved the two
            // prose columns to 93px and 70px and resolved the last, width-less <col> to ZERO.
            foreach (['Sessions', 'Fingerprints', 'Networks', 'Hosts', 'Bots'] as $view) {
                $php = lh_rp_code('src/Panel/' . $view . '.php');
                if (!preg_match_all('/<colgroup>(.*?)<\/colgroup>/s', $php, $groups)) {
                    continue;
                }
                foreach ($groups[1] as $group) {
                    lh_false(
                        (bool) preg_match('/width:\d+(ch|px)/', $group),
                        $view . ': a fixed-layout colgroup must state percentages only'
                    );
                    lh_false(
                        (bool) preg_match("/<col>/", $group),
                        $view . ': a <col> with no width resolves to zero once the others over-constrain'
                    );
                    preg_match_all('/width:(\d+)%/', $group, $widths);
                    $total = array_sum(array_map('intval', $widths[1]));
                    lh_same(100, $total, $view . ': the columns must sum to exactly 100%');
                }
            }
        },

    'every interactive state states both its background and its foreground' =>
        function (): void {
            // THE DEFECT THIS GUARDS. `button:hover` fills with ink and sets the label to the
            // page colour. `.theme-toggle:hover` set only a colour — ink, chosen for the
            // RESTING background — so on hover the element took ink from one rule and ink from
            // the other and the label vanished into a solid black rectangle. One rule changed
            // the ground, another changed the figure, and neither knew about the other.
            //
            // So the pattern rather than the patch: a rule that reacts to a pointer or carries
            // a selected state declares BOTH, even when one of them is `none`. The exemptions
            // are elements that carry no text of their own.
            $exempt = '/\.bar\b|\.meter|\.facet-fill|\.lh-scrim|\.progress|\.skel|\.sort-mark'
                . '|\.beacon-dot|\.finish-dot|\.brand-mark|\.vicon|\.lh-railbtn-mark|\.lh-navbtn-mark/';

            foreach (['public/assets/css/panel.css', 'public/assets/css/mobile.css'] as $file) {
                $css = lh_rp_declarations($file);
                preg_match_all('/([^{}]+)\{([^{}]*)\}/', $css, $rules, PREG_SET_ORDER);
                foreach ($rules as $rule) {
                    $selector = trim($rule[1]);
                    $body = $rule[2];
                    if (!preg_match('/:hover|:focus|:active|\.on\b|\[aria-selected|\.is-on|:checked/', $selector)) {
                        continue;
                    }
                    if (preg_match($exempt, $selector)) {
                        continue;
                    }
                    $bg = (bool) preg_match('/(^|;|\s)background(-color)?\s*:/', $body);
                    $fg = (bool) preg_match('/(^|;|\s)color\s*:/', $body);
                    lh_true(
                        $bg === $fg,
                        $file . ': `' . preg_replace('/\s+/', ' ', $selector) . '` changes one of '
                            . 'background/color without the other, which is how text lands on its own colour'
                    );
                }
            }
        },

    'a country is its flag and its full name, from one table' =>
        function (): void {
            lh_same('Seychelles', \Loghound\Geo\Countries::name('SC'), 'SC names nothing to a reader');
            lh_same('Venezuela', \Loghound\Geo\Countries::name('ve'), 'a lower-case code is still a code');
            lh_same('United States', \Loghound\Geo\Countries::name('US'), 'the common short form, not the legal one');

            lh_same("\u{1F1F8}\u{1F1E8}", \Loghound\Geo\Countries::flag('SC'), 'composed from the two indicators');
            lh_contains(\Loghound\Geo\Countries::label('RO'), 'Romania', 'the label carries the name');

            // An unknown code is not an error: geolocation data is third-party and incomplete.
            lh_same('ZZ', \Loghound\Geo\Countries::name('ZZ'), 'an unknown code gets itself back');
            lh_same('', \Loghound\Geo\Countries::flag('ZZ'), 'and no flag, rather than two stray boxes');
            lh_same('', \Loghound\Geo\Countries::name(''), 'an absent code is absent, not "—"');
            lh_same('', \Loghound\Geo\Countries::flag('United States'), 'a name is not a code');
            lh_false(\Loghound\Geo\Countries::known('XX'), 'and it says so');

            lh_true(count(\Loghound\Geo\Countries::all()) > 240, 'the assigned set, not the ones we happened to see');
        },

    'the country table reaches the browser once, from the server' =>
        function (): void {
            $index = lh_rp_file('public/index.php');
            lh_contains($index, "'countries' => Countries::all()", 'the boot payload carries the one table');

            // The centroid module keeps coordinates and defers to the payload for names, so
            // there is no second list to drift.
            $geo = lh_rp_file('public/assets/js/geo.js');
            lh_contains($geo, '(boot.countries || {})', 'names come from the served table first');

            $identity = lh_rp_file('public/assets/js/identity.js');
            lh_false(
                str_contains($identity, 'options.short ? cc : name'),
                'a facet list of bare two-letter codes is not a filter anybody can read'
            );
        },

    'a closed vocabulary gets a mark, an open one does not, and an unknown value is never guessed' =>
        function (): void {
            $js = lh_rp_file('public/assets/js/icons.js');

            foreach (['bot_verdict_s', 'browser_s', 'os_s', 'device_s', 'as_type_s', 'bot_class_s', 'view'] as $dim) {
                lh_contains($js, $dim . ': {', $dim . ' is a closed set and has to carry marks');
            }

            // An identifier has no category to recognise, so a mark in front of every one would
            // be texture rather than information.
            foreach (['as_org_s', 'netname_s', 'ip_s', 'paths_ss'] as $open) {
                lh_false(
                    (bool) preg_match('/^\s*' . preg_quote($open, '/') . ':\s*\{/m', $js),
                    $open . ' is an identifier, not a category'
                );
            }

            lh_contains($js, '_:', 'every dimension needs a generic mark for a value it does not know');
            lh_contains($js, "table._", 'an unrecognised value falls through to the generic mark');
            lh_contains($js, "setAttribute('aria-hidden', 'true')", 'the word is read once, not twice');
            lh_contains($js, "createElementNS", 'drawn locally: no icon font, no sprite request, no CDN');
            lh_false((bool) preg_match('/#[0-9a-fA-F]{3,8}/', $js), 'a mark inherits currentColor and names no colour');
        },

    'the marks are added once, where every surface renders a value' =>
        function (): void {
            $js = lh_rp_file('public/assets/js/identity.js');
            lh_contains($js, "import { icon } from './icons.js'", 'one place decides');
            lh_contains($js, 'options.mark === false', 'one place decides whether a value carries a mark');
            lh_contains($js, 'country ? flagNode(raw) : icon(field, raw)',
                'a country\'s mark is its flag; every other closed vocabulary gets a drawn one');
            lh_contains($js, "const country = field === 'country_s';",
                'and its text is its name, in the same one place — the facet list, the pivot row, '
                    . 'the table cell and the dialog all render a value through dimValue');
        },

    'the navigation rail is collapsed by default and remembers being opened' =>
        function (): void {
            $js = lh_rp_file('public/assets/js/responsive.js');

            // Absent means collapsed: a browser with nothing stored gets the rail, which is the
            // state the panel's widths are designed around.
            lh_contains($js, "getItem(RAIL_KEY) !== 'open'", 'no stored choice is a collapsed rail');
            lh_contains($js, 'setItem(RAIL_KEY', 'the choice survives a reload');
            lh_contains($js, "classList.toggle('lh-rail-collapsed'", 'the state lives on the root element');
            lh_contains($js, "icon('view', slug)", 'every view needs its own mark once the words are gone');
            lh_contains($js, "setAttribute('aria-label'", 'a mark with no words still has a name');

            $css = lh_rp_declarations('public/assets/css/panel.css');
            lh_contains($css, ':root.lh-rail-collapsed { --side-w: 60px; }',
                'the width the rail gives back has to reach the content');
            lh_contains($css, ':root.lh-rail-collapsed .side li a .navlabel', 'collapsed means only the marks');

            // A text node cannot be addressed by a selector, which is why the label is wrapped.
            $php = lh_rp_code('src/Panel/Layout.php');
            lh_contains($php, '<span class="navlabel">', 'the label needs an element to be hidden by');
        },

    'facets are a column beside the results, never a block above them' =>
        function (): void {
            $css = lh_rp_declarations('public/assets/css/panel.css');

            // The session explorer's own rail, and the filter panel every other view uses.
            lh_contains($css, '.explorer { display: grid; grid-template-columns: 292px minmax(0, 1fr);',
                'the explorer is two columns at desk width');
            lh_contains($css, '.view.has-facet-column', 'the expanded filter panel becomes the left column too');
            lh_contains($css, '.view.has-facet-column > .filterbar', 'and the cards take the second one');

            // The collapse to one column is a phone answer and has to stay one.
            lh_contains($css, '@media (max-width: 1120px)', 'one column only when two will not fit');

            $js = lh_rp_file('public/assets/js/responsive.js');
            lh_contains($js, "classList.toggle('has-facet-column'", 'the panel keeps its owner; only a class moves');
        },

    'a status never wears a control\'s clothes, and a control never reads as text' =>
        function (): void {
            // THE DEFECT. The Solr card rendered its API key value as a chip — a bordered box
            // in a definition list where every other value is plain text — so the one boxed
            // thing on the card read as the one pressable thing on it, and it was the word
            // "Set". A control is an a[href], a button or an input; anything else wearing a
            // box is a false affordance.
            //
            // A chip keeps its box in a TABLE, where a column of them reads as a column of
            // categories. It loses it in a value list or in a sentence, where it is the only
            // bordered thing among plain text. That direction is what is pinned here.
            $css = lh_rp_declarations('public/assets/css/panel.css');
            lh_contains($css, 'dl.kv dd > .chip', 'a chip in a value list must lose its box');
            lh_contains($css, 'p > .chip', 'and so must a chip in a sentence');
            lh_contains($css, '.state {', 'a status word needs a style that is not a chip');

            // No view may put a chip where it would be the only boxed thing on the card.
            foreach (glob(dirname(__DIR__) . '/src/Panel/*.php') as $view) {
                $php = lh_rp_code(str_replace(dirname(__DIR__) . '/', '', $view));
                preg_match_all('/<dd[^>]*>[^\n]{0,400}?<span class="chip/', $php, $m);
                lh_same(
                    [],
                    $m[0],
                    basename($view) . ': a definition-list value must be a value, not a chip — '
                        . 'use <span class="state"> for a status word'
                );
            }
        },

    'a card that says a value is edited elsewhere names the command that edits it' =>
        function (): void {
            // "Run bin/loghound-setup" is half an instruction: the reader is on a shell
            // somewhere else on the machine, and a relative path either fails or runs a
            // different checkout. The beacon snippet already prints the real host for exactly
            // this reason.
            $php = lh_rp_file('src/Panel/Settings.php');
            lh_contains($php, "'php ' . self::root() . '/bin/loghound-setup'",
                'the command has to carry this installation\'s own path');

            // And the API key card has to answer the question the old copy provoked.
            lh_contains($php, 'Changing the API key', 'saying where a value lives is not saying how to change it');
            lh_contains($php, 'leaving the field blank keeps the', 'the one prompt that behaves specially is stated');
            lh_contains($php, 'set-solr-setup', 'the command is pasteable, with the same copy control as the rest');
            lh_contains($php, 'Changing your username or password', 'the sign-in card has the same gap');
        },

    'a numbered section heading is a landmark, and it wraps rather than overflows' =>
        function (): void {
            $css = lh_rp_declarations('public/assets/css/panel.css');

            // 14px uppercase with wide tracking is a label. A reader who jumps here from the
            // sticky nav has to be able to see that they arrived.
            lh_false(
                (bool) preg_match('/\.card-head > h2 \{[^}]*font:\s*700 14px/s', $css),
                'a section heading set at label size is not a heading'
            );
            lh_contains($css, 'font: 700 clamp(23px, 2.5vw, 30px)/1.15', 'the heading is sized as one');
            lh_contains($css, '.card-head > h2 > span:not(.card-num) { min-width: 0; }',
                'a long section name has to wrap, or it starts a horizontal scroll at 375px');
            lh_contains($css, '.card-num', 'the number keeps the accent and stays part of the heading');

            // The jump offset is measured from the card, not from the heading, so it is
            // unaffected by the size — but it still has to exist.
            lh_contains($css, '.card { scroll-margin-top:', 'every card clears the sticky nav');
        },

    'only the first section of a page is open, and nothing hides a problem' =>
        function (): void {
            $js = lh_rp_file('public/assets/js/responsive.js');

            // The accordion is built from the card markup Controller::cardOpen() already emits,
            // so the server keeps emitting one shape and no card has to know it can fold.
            lh_contains($js, 'function setUpSections(', 'the sections fold');
            lh_contains($js, 'index === 0', 'the first section is the one that is open by default');
            lh_contains($js, "class: 'card-toggle'", 'the heading is the control, and the control is a button');
            lh_contains($js, "'aria-expanded'", 'a collapsed section has to say that it is collapsed');
            lh_contains($js, "'aria-controls'", 'and name the region it controls');

            // A HIDDEN PROBLEM IS THE WORST OUTCOME OF THE WHOLE CHANGE.
            lh_contains($js, 'const TROUBLE', 'trouble opens a section regardless of the default');
            foreach (['.banner-warn', '.card-error', '.check-row .chip-warn', '.confirm-form'] as $sel) {
                lh_contains($js, $sel, $sel . ' must hold its section open');
            }
            lh_false(
                (bool) preg_match("/TROUBLE = [^;]*'\\.chip-warn'/s", $js),
                'a bare warning chip is also the word "Note" in a sentence; it must not hold a section open'
            );

            // Navigation and deep links must open what they land on.
            lh_contains($js, ".set-nav a[href^=\"#\"]", 'the section nav opens what it jumps to');
            lh_contains($js, 'function openFromHash(', 'and so does a deep link');
            lh_contains($js, "'hashchange'", 'including one followed after the page is already open');

            // Browser find does not see collapsed content, and Settings is a page people search.
            lh_contains($js, 'function addExpandAll(', 'collapsing without an expand-all removes Ctrl-F');

            // The choice is remembered per page; the default is for somebody who has not chosen.
            lh_contains($js, 'CARD_KEY', 'the choice survives a reload');
            lh_contains($js, 'remembered === null ? first', 'a stored choice beats the default, not the other way round');

            $css = lh_rp_declarations('public/assets/css/panel.css');
            lh_contains($css, '.lh-sections .card.is-shut > .card-region { display: none; }',
                'the region is what collapses, never the head');
            lh_contains($css, '.lh-sections .card.is-shut > .card-region { display: block; }',
                'paper has nothing to press, so nothing is folded on it');
        },

    'a file path is the heading of the block it introduces' =>
        function (): void {
            $php = lh_rp_code('src/Panel/Settings.php');
            lh_contains($php, 'private static function filePath(', 'one helper, so every card agrees');
            lh_contains($php, 'filepath-label', 'the word FILE is what says a file is being named');
            lh_false(
                str_contains($php, '<h3 class="mono">') && str_contains($php, 'Security::esc($path)'),
                'a path set as monospaced prose is a string the eye slides over'
            );

            $css = lh_rp_declarations('public/assets/css/panel.css');
            lh_contains($css, '.filepath {', 'the band exists');
            lh_contains($css, 'overflow-wrap: anywhere', 'a long path wraps inside the band, never widens the page');
        },

    'the long technical blocks are closed until somebody asks' =>
        function (): void {
            $php = lh_rp_code('src/Panel/Settings.php');
            foreach (['src-mapping', 'src-missing', 'src-samples'] as $key) {
                lh_contains($php, $key, $key . ' is one of the blocks that buries the card it sits on');
            }
            lh_contains($php, 'Five lines from this file, parsed',
                'the summary keeps the heading\'s own words — "Details" would make the reader open it to find out');

            $js = lh_rp_file('public/assets/js/responsive.js');
            lh_contains($js, 'details.lh-keep[data-keep]', 'the choice is remembered per block');
            lh_contains($js, "getItem(FOLD_KEY + key) === 'open'", 'closed is what an untouched browser gets');
        },

    'the session table carries seven columns, and its cells match its headers' =>
        function (): void {
            $php = lh_rp_code('src/Panel/Sessions.php');
            preg_match('/<table id="se-table".*?<\/tr>/s', $php, $m);
            lh_true($m !== [], 'the results table must be in the view');

            // Seven facts and the control that opens the record: ten columns did not fit.
            lh_same(8, substr_count($m[0], '<col '), 'seven columns of data, plus the opener');
            lh_same(8, substr_count($m[0], '<th scope="col"'), 'a header per column');

            // A row builder that appends a different number of cells than there are headers
            // silently shifts every label by one, which is worse than a narrow column.
            $js = lh_rp_file('public/assets/js/views/sessions.js');
            preg_match('/function renderRows.*?\n}/s', $js, $rows);
            lh_same(
                8,
                substr_count($rows[0], 'tr.appendChild('),
                'the row builder must append exactly as many cells as the table has headers'
            );
        },

    'a two-line cell truncates each line, never the cell' =>
        function (): void {
            $css = lh_rp_file('public/assets/css/panel.css');

            // text-overflow needs white-space and overflow on the box that HOLDS the text, and
            // in a two-line cell that box is the inner div — a <td> cannot do it for both.
            foreach (['.clip-line', '.sub', '.client > div'] as $sel) {
                lh_contains($css, $sel, $sel . ' is one of the boxes that has to truncate itself');
            }
            lh_contains($css, 'td.clip { max-width: 46ch; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }',
                'a single-line cell needs all three declarations, not two');
        },

    'the columns are separated by real whitespace on both sides of a cell' =>
        function (): void {
            $css = lh_rp_file('public/assets/css/panel.css');

            // The gap used to be entirely on the right of a cell — 16px between two truncated
            // strings, which is two characters and reads as one run of text.
            lh_contains($css, 'padding: 8px 14px;', 'a body cell is padded on both sides');
            lh_contains($css, 'tbody td:first-child, tbody th:first-child { padding-left: 0; }',
                'the outer edges stay flush with the text column');
            lh_contains($css, 'tbody td:last-child, tbody th:last-child { padding-right: 0; }',
                'the outer edges stay flush with the text column');
        },

    'a chart mark stays visible while it is the one being pointed at' =>
        function (): void {
            $js = lh_rp_file('public/assets/js/charts.js');

            // ECharts' default bar emphasis LIGHTENS the fill. Three of the five population
            // colours are pale by design, so hovering one landed on the page colour and the bar
            // the reader was pointing at disappeared under their cursor.
            lh_contains($js, "function emphasis(", 'the emphasis state has to be a shared default');
            lh_contains($js, "color: 'inherit'", 'the fill must not change at all');
            lh_contains($js, 'borderColor: t.text', 'the state is a rule of ink, which reads on both grounds');
            lh_contains(
                $js,
                'merged.series.map',
                'it has to be applied to every series of every chart, not to the two it was noticed on'
            );
        },

    'the donut divides its space before it places anything in it' =>
        function (): void {
            $js = lh_rp_file('public/assets/js/charts.js');
            lh_contains($js, 'function donutPlan(', 'the legend width is measured, not assumed');
            lh_contains($js, 'stack: true', 'below a width there is no side-by-side arrangement that reads');
            lh_false(
                str_contains($js, "center: ['32%', '52%']"),
                'a percentage centre knows nothing about the legend beside it'
            );
            lh_contains($js, "type: 'scroll'", 'a legend that wraps is drawn over the plot');
        },

    'a chart never names a colour of its own' =>
        function (): void {
            $js = lh_rp_file('public/assets/js/charts.js');

            // A literal colour is allowed in exactly one position: the fallback argument of a
            // token read, `get('--ink', '#111111')`. Anywhere else it cannot follow the theme.
            preg_match_all("/'#[0-9a-fA-F]{3,8}'/", $js, $all, PREG_OFFSET_CAPTURE);
            foreach ($all[0] as [$hex, $at]) {
                $before = substr($js, max(0, $at - 40), min(40, $at));
                lh_true(
                    str_contains($before, "get('--"),
                    'a literal colour outside a token fallback: ' . $hex
                );
            }
            lh_contains($js, 'function readableOn(', 'a label on a coloured tile has to be legible on it');
        },
];
