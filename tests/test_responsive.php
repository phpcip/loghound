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

/**
 * The body of one JavaScript function, by brace matching from its declaration.
 *
 * Some assertions here are about WHICH function a call sits in rather than whether a file
 * mentions it anywhere: "countryNode draws no flag of its own" is true of that body and false
 * of identity.js as a whole, which of course still calls flagNode — in the one place that owns
 * the mark. A file-wide substring check cannot tell those two apart, and the flag was drawn
 * twice on nearly every surface for exactly that reason.
 *
 * Takes the source rather than a path, so a caller that has already stripped comments is not
 * made to read the file a second time.
 */
function lh_rp_fn_body(string $source, string $name): string
{
    $at = strpos($source, 'function ' . $name . '(');
    if ($at === false) {
        return '';
    }
    $open = strpos($source, '{', $at);
    if ($open === false) {
        return '';
    }

    $depth = 0;
    $length = strlen($source);
    for ($i = $open; $i < $length; $i++) {
        if ($source[$i] === '{') {
            $depth++;
        } elseif ($source[$i] === '}') {
            $depth--;
            if ($depth === 0) {
                return substr($source, $open + 1, $i - $open - 1);
            }
        }
    }

    return '';
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
            lh_contains($js, 'country ? flagNode(raw) : icon(field, raw)',
                'a country\'s mark is its flag; every other closed vocabulary gets a drawn one');
            lh_contains($js, "const country = field === 'country_s';",
                'and its text is its name, in the same one place — the facet list, the pivot row, '
                    . 'the table cell and the dialog all render a value through dimValue');

            /* ONCE MEANS ONCE, AND THE OPT-OUT IS WHY IT WAS TWICE. dimValue() used to honour
               `mark: false` "for the few places where the mark is already on screen beside the
               value", and NO call site in the panel ever passed it — while countryNode() went
               on prepending a flag of its own next to the one dimValue inserts. Every row of
               every detail dialog, the session explorer's Where cell, the fingerprint cluster
               tables and the whole countries table drew the flag twice.

               So the assertion is inverted: the escape hatch must NOT come back, because an
               escape hatch nobody takes is just a second answer waiting to disagree with the
               first. */
            lh_false(
                str_contains($js, 'options.mark === false'),
                'the mark has no opt-out: dimValue() owns it, and a caller that drew its own is '
                    . 'how the country flag came to be rendered twice on nearly every surface'
            );
            lh_false(
                (bool) preg_match('/mark\s*:\s*false/', lh_rp_file('public/assets/js/detail.js')
                    . lh_rp_file('public/assets/js/facets.js')
                    . lh_rp_file('public/assets/js/facetfilter.js')),
                'and no caller asks for one'
            );
        },

    'a flag is drawn once per value, whoever assembled the text around it' =>
        function (): void {
            /* THE SECOND HALF OF THE SAME FIX. Removing the sibling flag from countryNode()
               closes the one call site that was found; stripping a flag out of the text closes
               it for the call site that has not been written yet. It is the same override
               dimValue() already applies when a caller passes a slug where words belong. */
            $js = lh_rp_file('public/assets/js/identity.js');

            lh_contains($js, 'export function stripFlag(', 'there is one place that removes a duplicate flag');
            lh_contains($js, 'const shown = stripFlag(', 'and dimValue() puts every caller\'s text through it');

            /* countryNode() is the function the bug was reported from: the session explorer, the
               cluster member tables, the countries table and every row of the dimension dialog's
               visitor list all render a country through it. */
            $node = lh_rp_fn_body($js, 'countryNode');
            lh_true($node !== '', 'countryNode is still there to check');
            lh_false(
                str_contains($node, 'flagNode('),
                'countryNode must not draw a flag of its own beside the one dimValue inserts'
            );
            lh_contains($node, "dimValue('country_s'", 'it renders the country through the one function');

            /* The regex has to take the pair and whatever separated it from the words, and must
               not touch a label that merely starts with a letter. */
            $strip = lh_rp_fn_body($js, 'stripFlag');
            lh_contains($strip, '\u{1F1E6}-\u{1F1FF}', 'a flag is a regional-indicator pair and nothing else');
            lh_contains($strip, '{2}', 'a pair, not one character');
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

    'a mark in the collapsed rail says what it is, in a tooltip of the panel\'s own' =>
        function (): void {
            // THE DEFECT. The rail is collapsed by default, so twelve marks in a 60px column ARE
            // the navigation, and the only way to read one was to expand the rail or to wait for
            // the browser's `title` bubble — a second late, unstyleable, and wherever the pointer
            // happens to be. That is now the primary way anybody reads this navigation.
            $css = lh_rp_declarations('public/assets/css/panel.css');
            $js = lh_rp_code('public/assets/js/responsive.js');

            // NOT A SECOND LABEL. The span the expanded rail shows is the span the tooltip is,
            // so there is one copy of every view's name in the document.
            $rule = '/:root\.lh-rail-collapsed \.side li a \.navlabel,'
                . '\s*:root\.lh-rail-collapsed \.lh-railbtn \.lh-railbtn-label,'
                . '\s*:root\.lh-rail-collapsed \.theme-toggle \.lh-themelabel \{([^}]*)\}/s';
            lh_true((bool) preg_match($rule, $css, $m), 'one rule covers all three lone marks in the rail');

            // `.side` is overflow-y: auto, and an element scrollable on one axis clips the other,
            // so an absolutely positioned box is cut off at the 60px edge of the rail — which is
            // the one place it must not be. Fixed is positioned against the viewport instead.
            lh_contains($m[1], 'position: fixed', 'no ancestor overflow may clip it');
            lh_contains($m[1], 'left: calc(var(--side-w)', 'it sits clear of the rail, to the right');
            lh_contains($m[1], 'pointer-events: none', 'moving towards a mark must not make it flicker');
            lh_contains($m[1], 'visibility: hidden', 'and it is out of the accessibility tree until shown');
            lh_false(str_contains($m[1], 'display: none'), 'a display:none box cannot be revealed by opacity');

            // Keyboard is unconditional; hover is gated on there BEING a hover, so a tap on a
            // touch screen opens the view rather than leaving a ghost label on top of it.
            lh_contains($css, ':root.lh-rail-collapsed .side li a:focus-visible .navlabel',
                'the rail is tab-navigable, so focus shows it too');
            lh_contains($css, '@media (hover: hover) and (pointer: fine)',
                'a synthesised hover on a touch screen must not strand the tooltip');

            // The position is the one thing CSS cannot work out: a fixed box is placed against
            // the viewport, and the rail scrolls inside itself on a short window.
            lh_contains($js, '--lh-navtip-y', 'the vertical position is published from a measurement');
            lh_contains($js, 'getBoundingClientRect()', 'measured, not assumed');
            lh_contains($js, "addEventListener('focusin'", 'and measured for the keyboard as well as the pointer');

            // A used-and-never-declared custom property makes every declaration reading it
            // invalid, which is a silent defect unless it is the designed fallback — so it is
            // declared, empty, with the reason beside it.
            lh_contains($css, '--lh-navtip-y: ;', 'the property is declared even while it has no value');

            // TWO TOOLTIPS ARE WORSE THAN ONE: the browser's bubble is parked while the rail is
            // collapsed and handed straight back when it expands, so the expanded rail is
            // unchanged.
            lh_contains($js, 'function parkTitle', 'the native title cannot be left to arrive on top');
            lh_contains($js, "removeAttribute('title')", 'parked while collapsed');
            lh_contains($js, "setAttribute('title', parked)", 'and given back when the words are visible');
        },

    'the section bar names a heading it had to cut, and only one it cut' =>
        function (): void {
            // "01 Declared versus evasi…" is the first half of a label with no way to reach the
            // other half: Layout::cardsIn() trims a heading to 22 characters for a bar that is
            // one row and never wraps, and the bar sets no title.
            $css = lh_rp_declarations('public/assets/css/panel.css');
            $js = lh_rp_code('public/assets/js/responsive.js');

            lh_true(
                (bool) preg_match('/\.set-nav a\[data-lh-tip\]::after \{([^}]*)\}/s', $css, $m),
                'the bar needs a tooltip of the same kind as the rail\'s'
            );
            lh_contains($m[1], 'content: attr(data-full)', 'it shows the untruncated label, never the cut one');
            lh_contains($m[1], 'position: fixed', '.set-nav is overflow-x: auto and would clip it');
            lh_contains($m[1], 'pointer-events: none', 'it must not intercept the pointer');
            lh_contains($m[1], 'visibility: hidden', 'hidden until it is asked for');

            lh_contains($css, '.set-nav a[data-lh-tip]:focus-visible::after', 'the bar is tab-navigable');

            // MEASURED, in both senses: the server may have cut the label, and the browser may be
            // cutting it as well — and the second one changes as the window changes.
            lh_contains($js, 'label.scrollWidth > label.clientWidth', 'overflow is measured, not guessed');
            lh_contains($js, 'shown !== full', 'and so is the cut the server made');
            lh_contains($js, 'remeasureTips', 'the same entry crosses that line when the window resizes');

            // The tooltip is a visual affordance; the name is on the control either way.
            lh_contains($js, "link.setAttribute('aria-label', full)", 'a screen reader gets the whole label');

            // Nothing at all when there is no full text to show, because a tooltip repeating the
            // truncated string tells the reader what they can already see.
            lh_contains($js, "bar.querySelectorAll('a[data-full]')", 'no attribute, no tooltip');
        },

    'facets are a column beside the results, never a block above them' =>
        function (): void {
            $css = lh_rp_declarations('public/assets/css/panel.css');

            // The session explorer's own rail, and the filter panel every other view uses.
            lh_contains($css, '.explorer { display: grid; grid-template-columns: 292px minmax(0, 1fr);',
                'the explorer is two columns at desk width');
            lh_contains($css, '.view.has-facet-column', 'the expanded filter panel becomes the left column too');

            /* WHAT IS IN THE COLUMN IS THE GROUPS, AND ONLY THE GROUPS. It used to be the whole
               `.filterbar` — the applied chips and the show/hide button along with the dimension
               lists — and that is what made the shut state a full-width band: hiding the groups
               left the chips and the control with nowhere to be except across the top of the
               content, with every card pushed below. The chips are page scope and belong in the
               sticky toolbar with the range picker; `.fpanel` is what stays beside the results. */
            lh_contains($css, '.view.has-facet-column:not(.lh-facets-shut) > .fpanel',
                'the dimension lists are the first column, and the cards take the second');
            lh_false(
                str_contains($css, '.view.has-facet-column > .filterbar'),
                'the applied chips and the filter control are not in the column — they are page '
                    . 'scope, and leaving them here is what turned the shut state into a band'
            );

            // The collapse to one column is a phone answer and has to stay one.
            lh_contains($css, '@media (max-width: 1120px)', 'one column only when two will not fit');

            $js = lh_rp_file('public/assets/js/responsive.js');
            lh_contains($js, "classList.toggle('has-facet-column'", 'the panel keeps its owner; only a class moves');
        },

    'a statement about a block of columns is printed once, not once per column' =>
        function (): void {
            /* THE DEFECT, ON THE INDEX VIEW'S FOUR-COLUMN BLOCK. "Counts are what each value
               matches on this page as filtered." is one fact about how the whole block was
               counted, and it was emitted per group — so the identical sentence appeared four
               times, each under its own hairline, at four different heights, directly below a
               card note that already referred to it. The facet sidebar did the same, once per
               dimension, and printed "Shown as a distribution only…" once per unfilterable one.

               This is the guard, because it creeps back every time a renderer is added: the
               per-group note may only be rendered through a call that knows what the block as a
               whole is saying, and the shared sentence has exactly one node that carries it. */
            $ff = lh_rp_file('public/assets/js/facetfilter.js');
            lh_contains($ff, 'export function commonBasisNote(', 'one place decides what every column shares');
            lh_contains($ff, 'export function blockBasisNote(', 'and one node carries it for the block');
            lh_contains($ff, 'group.basis_note === common', 'a column whose sentence is the shared one stays quiet');

            /* A COLUMN COUNTED DIFFERENTLY KEEPS ITS OWN NOTE, and that is not a loose end: a
               column carrying an exclusion is counted with its own filter lifted, which is
               exactly the difference the reader must not miss. commonBasisNote() returns '' the
               moment the columns disagree, so every one of them prints again. */
            lh_contains($ff, 'list.every((note) => note === list[0])',
                'the sentence only moves when every column really is saying it');

            foreach (['public/assets/js/facets.js', 'public/assets/js/views/opensolr.js'] as $module) {
                $js = lh_rp_file($module);
                if (!str_contains($js, 'basisNote(')) {
                    continue;
                }
                lh_false(
                    (bool) preg_match('/basisNote\(\s*group\s*\)/', $js),
                    $module . ' renders the basis note per group with no idea what the block is saying, '
                        . 'which is how one sentence came to be printed four times under four columns'
                );
                lh_contains($js, 'commonBasisNote(', $module . ' asks what the block shares before printing it');
            }

            /* The sidebar's other repeated paragraph, under every dimension that is not yet
               filterable. Which ones those are is on the groups; why is said once. */
            $facets = lh_rp_file('public/assets/js/facets.js');
            lh_contains($facets, 'facet-note-all', 'the "distributions only" note has a single place too');
            lh_contains($facets, "'facet is-unfilterable'", 'and the groups themselves say which ones they are');
        },

    'the page toolbar is one bar, pinned under the section nav, built from what a view declares' =>
        function (): void {
            $css = lh_rp_declarations('public/assets/css/panel.css');
            $js = lh_rp_file('public/assets/js/responsive.js');

            /* SIBLING OF `.view`, for the reason `.set-nav` already is: sticky inside a flex
               column or a grid is sticky within one item box and has no travel at all. */
            lh_contains($css, '.page-tools {', 'the page controls have a bar of their own');
            lh_contains($css, 'top: calc(var(--lh-topbar-h, 0px) + var(--set-nav-h));',
                'it pins under the section nav wherever that bar actually is — a phone puts a '
                    . 'fixed navigation bar above it, and assuming otherwise put this one on top of it');
            lh_contains($js, 'main.insertBefore(bar, view)', 'and it is a sibling of the view, never inside it');

            /* THE JUMP OFFSET IS THE SUM. A second pinned bar means a jump lands the heading
               underneath it, which is the defect `--set-nav-h` was added to fix one bar ago. */
            lh_contains($css, 'scroll-margin-top: calc(var(--set-nav-h) + var(--page-tools-h) + 20px);',
                'every card clears both bars');
            lh_contains(
                lh_rp_declarations('public/assets/css/mobile.css'),
                'var(--page-tools-h)',
                'including on a phone, where there are three bars to clear'
            );

            /* CONDENSED IS SHORTER, and it is one row rather than a stack — measured in
               tests/test_browser.php, declared here. */
            lh_contains($css, '.page-tools.is-stuck {', 'the bar has a condensed state');
            lh_contains($css, 'flex-wrap: nowrap;', 'which is one row that scrolls rather than several that stack');

            /* THE CONTROLS MOVE, THEY ARE NOT REDRAWN. A second copy of the host selector or the
               chips is a second thing to keep in step, and the two disagree the first time one
               is re-rendered by a fetch. */
            $adopt = lh_rp_fn_body($js, 'adoptPageTools');
            lh_true($adopt !== '', 'one function gathers the page controls');
            lh_contains($adopt, "'.head-tools', '#lh-filters', '#lh-readout'", 'the three that scope the page');
            lh_contains($adopt, 'node.parentElement !== bar', 'and it is idempotent, because two of them arrive late');

            /* A VIEW THAT DECLARES NO FACETS MUST NOT GROW A "Filter by" THAT DOES NOTHING —
               the same rule Controller::toolbar() already enforces for the range picker. */
            lh_contains($adopt, 'bar.hidden = bar.querySelector(', 'an empty bar is two rules of chrome and no controls');
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
            foreach (['.banner-warn', '.card-error', '.check-row .chip-warn'] as $sel) {
                lh_contains($js, $sel, $sel . ' must hold its section open');
            }

            /* A CONFIRMATION FORM ONLY COUNTS AS TROUBLE WHILE SOMETHING IS ACTUALLY PENDING.
               A bare `.confirm-form` was in this list, and Settings emits that class from three
               unrelated places — the pending "start ingesting" form, the remove button and the
               reinstall form, the last two unconditionally. So `set-sources` and `set-reinstall`
               were force-opened on every render of every installation and could never show the
               operator's own choice, which is most of what "the accordion does not remember"
               turned out to mean. Only the pending form carries `awaiting`. */
            lh_contains($js, '.confirm-form.awaiting', 'a PENDING confirmation must hold its section open');
            lh_false(
                (bool) preg_match("/TROUBLE = [^;]*\\.confirm-form(?!\\.awaiting)/s", $js),
                'a bare .confirm-form must not hold a section open: two of the three forms that carry '
                    . 'that class are always present, so listing it pins those cards open for ever'
            );
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
