<?php
/**
 * Loghound — the per-section refresh control.
 *
 * WHAT IT IS. A quiet mark in every async card's head that reloads THAT card. It is the answer
 * to "these numbers are stale and I do not want to lose the rest of the page", which previously
 * had only two answers: reload the whole view, or press Clear cache and throw away every stored
 * answer for every card on every page.
 *
 * WHAT IT IS NOT, AND THIS IS THE WHOLE POINT. It is not a cache bypass. It re-enters
 * `loadCard()` with the three arguments the view last passed, so the request that goes out is
 * byte-for-byte the request the first load sent: same view, same action, same query string, no
 * extra parameter, no timestamp, no POST to the clear-cache route. If the cache still holds the
 * answer, the answer comes back from the cache and the card's own provenance stamp says so.
 * Clear cache in the page header is the control that discards; this one is the control that
 * re-asks. Two tools with two jobs, and a product that blurs them has misled its operator.
 *
 * WHICH CARDS GET ONE is not a list anywhere. The control is created by `loadCard()` itself, so
 * the set is exactly the cards whose data arrives through `loadCard()` — every async card on
 * every view, and a card added by a later release with nobody remembering anything. A card
 * rendered entirely server-side never calls it and never grows a control with nothing to run.
 * The coverage test below renders every view there is, in both Opensolr states, and holds that
 * equivalence across all of them rather than sampling one page.
 *
 * The suite has no browser (SPEC §12), so the behavioural assertions are source-shape ones:
 * which function calls which, in which order, and what a given function's body is forbidden to
 * contain. They are written against function BODIES rather than the file, because "the press
 * handler does not fetch" is a statement about a body and would be meaningless about a module
 * whose whole job is fetching.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Config;
use Loghound\Panel\Controller;
use Loghound\Panel\Gateway;
use Loghound\Solr;

/** One front-end module, as text. */
function lh_cr_js(string $relative): string
{
    $path = dirname(__DIR__) . '/' . $relative;
    if (!is_file($path)) {
        lh_fail($relative . ' is missing');
    }
    return (string) file_get_contents($path);
}

/** The same, with every comment block removed, so a docblock can never satisfy a code assertion. */
function lh_cr_code(string $relative): string
{
    return (string) preg_replace('#/\*.*?\*/#s', '', lh_cr_js($relative));
}

/**
 * The body of one JavaScript function, by brace matching from its declaration.
 *
 * The useful assertions here are about WHICH function a call sits in: "the press handler starts
 * no fetch of its own" and "the in-flight guard runs before the loader" are both statements
 * about a body, and neither can be made about a file.
 */
function lh_cr_fn(string $relative, string $name): string
{
    $js = lh_cr_code($relative);
    $at = strpos($js, 'function ' . $name . '(');
    if ($at === false) {
        lh_fail($relative . ' has no function ' . $name . '()');
    }
    $open = strpos($js, '{', $at);
    if ($open === false) {
        lh_fail($name . '() has no body');
    }
    $depth = 0;
    $length = strlen($js);
    for ($i = $open; $i < $length; $i++) {
        if ($js[$i] === '{') {
            $depth++;
        } elseif ($js[$i] === '}') {
            $depth--;
            if ($depth === 0) {
                return substr($js, $open + 1, $i - $open - 1);
            }
        }
    }
    lh_fail($name . '() has an unbalanced body');
    return '';
}

/** Every front-end module, views included. */
function lh_cr_modules(): array
{
    return (array) glob(dirname(__DIR__) . '/public/assets/js/{,views/}*.js', GLOB_BRACE);
}

/**
 * Every card id the front end drives through loadCard(), read off the source.
 *
 * @return array<string,string> card id => the module that loads it
 */
function lh_cr_loaded(): array
{
    $out = [];
    foreach (lh_cr_modules() as $file) {
        if (preg_match_all("/loadCard\(\s*'([^']+)'/", (string) file_get_contents($file), $m)) {
            foreach ($m[1] as $id) {
                $out[$id] = basename($file);
            }
        }
    }
    return $out;
}

/**
 * A configuration with Opensolr connected, so the three platform views render their real cards.
 *
 * Without credentials Indexes, Query analysis and Who is querying render one explainer card
 * instead, which is a different set of cards — so both states are rendered below and the
 * equivalence has to hold in each.
 */
function lh_cr_config(bool $opensolr): Config
{
    $cfg = Config::load('/nonexistent-loghound-config');
    $cfg->set('solr.base_url', 'http://127.0.0.1:65535/solr');
    $cfg->set('solr.hits_core', 'lh_cr_hits');
    $cfg->set('solr.sessions_core', 'lh_cr_sessions');
    if ($opensolr) {
        $cfg->set('opensolr.email', 'owner@example.com');
        $cfg->set('opensolr.api_key', str_repeat('k', 32));
    }
    return $cfg;
}

/** A gateway whose transport answers with canned JSON, so nothing leaves the machine. */
function lh_cr_gateway(Config $cfg): Gateway
{
    $transport = static fn (array $request): array => [
        'status' => 200,
        'body'   => (string) json_encode([
            'responseHeader' => ['status' => 0],
            'response'       => ['numFound' => 0, 'docs' => []],
            'facets'         => ['count' => 0],
        ]),
        'error'  => '',
    ];
    return new Gateway($cfg, new Solr((array) $cfg->get('solr'), $transport), false);
}

/**
 * Every panel view there is, discovered rather than listed.
 *
 * Globbed from src/Panel so a view added later is covered by this file without anybody
 * remembering to add it — which is the same reason the control itself is not a list.
 *
 * @return array<string,Controller> slug => view
 */
function lh_cr_views(bool $opensolr): array
{
    $cfg = lh_cr_config($opensolr);
    $gw = lh_cr_gateway($cfg);

    $out = [];
    foreach (glob(dirname(__DIR__) . '/src/Panel/*.php') ?: [] as $file) {
        $class = 'Loghound\\Panel\\' . basename($file, '.php');
        if (!class_exists($class)) {
            continue;
        }
        $meta = new ReflectionClass($class);
        if ($meta->isAbstract() || !$meta->isSubclassOf(Controller::class)) {
            continue;
        }
        $view = new $class($cfg, $gw);
        $out[$view->slug()] = $view;
    }
    ksort($out);
    return $out;
}

/** Render one view's body with a clean $_GET, and hand back the HTML. */
function lh_cr_html(Controller $view): string
{
    $saved = $_GET;
    $_GET = [];
    try {
        ob_start();
        try {
            $view->body();
        } finally {
            $html = (string) ob_get_clean();
        }
    } finally {
        $_GET = $saved;
    }
    return $html;
}

/**
 * Every card a view emitted, and whether it is an async card.
 *
 * `Controller::skeleton()` is what makes a card async: it is the method that emits the progress
 * strip and the skeleton, and a card whose content is rendered server-side calls cardOpen() and
 * cardEnd() with nothing in between. So `<id>-status` in the markup is the server's own answer
 * to "does this card wait for data", and it is read here rather than guessed at.
 *
 * @return array<string,array{async:bool,job:bool}> card id => facts about it
 */
function lh_cr_cards(string $html): array
{
    $out = [];
    if (!preg_match_all('/data-card="([^"]+)"/', $html, $m)) {
        return $out;
    }
    foreach ($m[1] as $name) {
        $out[$name] = [
            'async' => str_contains($html, 'id="' . $name . '-status"'),
            'job'   => str_contains($html, 'id="' . $name . '-job"'),
        ];
    }
    return $out;
}

return [

    /* ------------------------------------------------------------------ *
     * It is the same load, not a second one
     * ------------------------------------------------------------------ */

    'pressing refresh re-enters loadCard rather than starting a loader of its own' =>
        function (): void {
            // THE DEFECT THIS FORBIDS. A refresh control written as "fetch the card's action and
            // put the rows in" is a second loading path, and a second loading path drifts: it
            // does not raise the skeleton, it does not run the elapsed-seconds ticker, it does
            // not draw the card's own failure box with its own retry, it does not re-stamp the
            // provenance line, and every one of those is a behaviour somebody has to remember to
            // copy. Re-entering loadCard() with the same three arguments means there is nothing
            // to copy and nothing to drift.
            $press = lh_cr_fn('public/assets/js/core.js', 'wireRefresh');

            lh_true(
                (bool) preg_match('/loadCard\(\s*entry\.id,\s*entry\.label,\s*entry\.loader\s*\)/', $press),
                'the press must re-run the card\'s own loader, with its own id and its own worded label'
            );

            foreach (['fetch(', 'api(', 'post(', 'XMLHttpRequest', 'card-status', '-skel'] as $sink) {
                lh_false(
                    str_contains($press, $sink),
                    'the press handler must not ' . $sink . ' — loadCard() is the one loading path'
                );
            }

            // And the loader it re-runs is the one the view passed LAST, not the one it passed
            // first: a card is re-loaded whenever a filter, a range or an index choice changes,
            // and a refresh that replayed the page's opening state would quietly undo the
            // reader's filters.
            $load = lh_cr_fn('public/assets/js/core.js', 'loadCard');
            lh_contains($load, 'cardLoaders.set(id, { id: id, label: label, loader: loader })',
                'every load records what it was, so the control has something to re-run');
            lh_contains($load, 'ensureRefresh(id, label)', 'and every load is what gives the card its control');
        },

    /* ------------------------------------------------------------------ *
     * It does not bypass the cache
     * ------------------------------------------------------------------ */

    'refreshing a section re-asks through the cache instead of discarding it' =>
        function (): void {
            // THE TWO CONTROLS THIS KEEPS APART. Clear cache is a POST carrying `clear_cache` to
            // the front controller, which empties the store for every card on every view. This
            // one re-runs one card's GET. If it quietly added `&fresh=1`, or a cache-busting
            // timestamp, or posted the clear route first, it would BE the other control wearing
            // a smaller icon — and the operator who wanted only to re-ask would have thrown away
            // the answers behind eleven other cards without being told.
            $core = lh_cr_code('public/assets/js/core.js');
            $press = lh_cr_fn('public/assets/js/core.js', 'wireRefresh');
            $ensure = lh_cr_fn('public/assets/js/core.js', 'ensureRefresh');
            $busy = lh_cr_fn('public/assets/js/core.js', 'markRefreshBusy');

            // The clear-cache route is a server form and has no business being named in the
            // front end at all, let alone from the control that must not use it.
            foreach (lh_cr_modules() as $file) {
                lh_false(
                    str_contains((string) file_get_contents($file), 'clear_cache'),
                    basename($file) . ' must not reach the clear-cache route'
                );
            }

            // No cache-buster, by any of the names one is usually spelled, and no request
            // building at all: the refresh path does not touch a URL, so it cannot add to one.
            $path = $press . $ensure . $busy;
            foreach ([
                'Date.now', 'Math.random', 'nocache', 'no-cache', 'no-store', 'cache',
                'URLSearchParams', 'params.set', 'headers',
            ] as $bust) {
                lh_false(
                    str_contains($path, $bust),
                    'the refresh path must not mention ' . $bust . ': the request has to be the '
                        . 'same request the first load sent'
                );
            }

            // And the request builder itself must not have grown a parameter for this. Its three
            // sources stay what they were: the page's own query string, the view, the action.
            $api = lh_cr_fn('public/assets/js/core.js', 'api');
            lh_contains($api, 'new URLSearchParams(window.location.search)', 'the range and the filters travel as they are');
            preg_match_all("/params\.set\('([^']+)'/", $api, $sets);
            lh_same(['v', 'api'], $sets[1], 'api() sets the view and the action and nothing else of its own');

            // The provenance line keeps telling the truth after a refresh, which it only can
            // because the refresh genuinely went back through loadCard().
            lh_contains(lh_cr_fn('public/assets/js/core.js', 'loadCard'), 'renderStamp(id)',
                'a refreshed card re-states when its numbers were computed');
            lh_contains($core, 'Clear cache in the page header',
                'the control has to say, in words, which of the two tools it is not');
        },

    /* ------------------------------------------------------------------ *
     * An impatient second press
     * ------------------------------------------------------------------ */

    'a second press while the card is loading starts no second fetch' =>
        function (): void {
            // Two fetches for one card is two renders into one content element, in whichever
            // order they happen to come back — so the card can settle on the OLDER answer. The
            // guard already existed for re-entrant loads; the control has to go through it
            // rather than around it.
            $load = lh_cr_fn('public/assets/js/core.js', 'loadCard');

            $guard = strpos($load, 'inFlight.has(id)');
            $add = strpos($load, 'inFlight.add(id)');
            $run = strpos($load, 'await loader()');
            lh_true($guard !== false && $add !== false && $run !== false, 'the in-flight guard is still there');
            lh_true($guard < $add, 'a card already loading is refused before it is registered again');
            lh_true($add < $run, 'and long before anything is fetched');

            // The press handler must not be able to defeat it.
            $press = lh_cr_fn('public/assets/js/core.js', 'wireRefresh');
            lh_false(str_contains($press, 'inFlight'), 'the press has no way to clear the guard');

            // The control says it is busy, and says it the way that keeps the keyboard working:
            // a `disabled` button is dropped from the tab order the instant it is pressed, so an
            // operator who refreshed a section with the keyboard would lose their place.
            lh_contains($load, 'markRefreshBusy(id, true)', 'the control goes quiet while the card loads');
            lh_contains($load, 'markRefreshBusy(id, false)', 'and comes back when it is done');
            lh_true(
                strpos($load, 'markRefreshBusy(id, false)') > strpos($load, 'inFlight.delete(id)'),
                'it is released in the same finally that releases the guard, so a failed load re-arms it too'
            );

            $busy = lh_cr_fn('public/assets/js/core.js', 'markRefreshBusy');
            lh_contains($busy, "setAttribute('aria-disabled'", 'busy is stated on the control');
            lh_false(
                (bool) preg_match('/\.disabled\s*=/', $busy . lh_cr_fn('public/assets/js/core.js', 'ensureRefresh')),
                'never the disabled property: it takes the control out of the tab order mid-press'
            );

            $css = (string) preg_replace('#/\*.*?\*/#s', '', lh_cr_js('public/assets/css/panel.css'));
            lh_contains($css, '.card-refresh[aria-disabled="true"]', 'and the busy state is visible, not only announced');
        },

    /* ------------------------------------------------------------------ *
     * It is not the chevron
     * ------------------------------------------------------------------ */

    'the control sits beside the fold chevron and cannot fold anything' =>
        function (): void {
            // THE TRAP. responsive.js turns a card heading into an accordion by MOVING every
            // child of the h2 into a `button.card-toggle` it builds inside it. A control placed
            // in the heading is therefore swallowed by that button on the next frame — a button
            // inside a button, which is invalid markup and does not reliably take the press. So
            // the control is a SIBLING of the h2 inside `.card-head`: the same row as the
            // chevron, the same row as the export and the provenance stamp, outside the element
            // that folds.
            $resp = lh_cr_code('public/assets/js/responsive.js');
            lh_contains($resp, 'while (heading.firstChild)', 'the heading really does surrender its children to the toggle');

            $ensure = lh_cr_fn('public/assets/js/core.js', 'ensureRefresh');
            lh_contains($ensure, "head.querySelector('h2')", 'the heading is found so the control can be put AFTER it');
            lh_contains($ensure, 'head.insertBefore(button, heading.nextSibling)', 'a sibling of the heading, in the card head');
            lh_false(str_contains($ensure, 'heading.appendChild'), 'never inside the h2, which becomes a button');
            lh_false(str_contains($ensure, 'heading.insertBefore'), 'and never among the heading\'s own children');

            // The fold listener is on the toggle itself, not on the head, so a press on a
            // sibling cannot reach it — and the press stops travelling anyway, because the
            // document also carries the section nav's listener and the accordion's.
            lh_contains($resp, "button.addEventListener('click'", 'the fold is the toggle button\'s own press');
            lh_false(str_contains($resp, "head.addEventListener('click'"), 'the card head is not a fold target');

            $press = lh_cr_fn('public/assets/js/core.js', 'wireRefresh');
            lh_contains($press, 'event.stopPropagation()', 'a refresh is about one card and must not read as navigation');
            lh_false(str_contains($press, 'is-shut'), 'and it changes nothing about what is open');
            lh_false(str_contains($press, 'aria-expanded'), 'nor about what says it is open');

            // Delegated, because the CSP allows no inline handler and because the controls are
            // created as their cards load rather than being in the served markup.
            lh_contains($press, "document.addEventListener('click'", 'one delegated listener, not one per control');
            lh_contains(lh_cr_code('public/assets/js/core.js'), 'let refreshWired = false', 'and installed once');
        },

    /* ------------------------------------------------------------------ *
     * A name, a tooltip, a target
     * ------------------------------------------------------------------ */

    'the control says which section it refreshes, and is reachable without a pointer' =>
        function (): void {
            // "Refresh" on eleven controls down one page is eleven identical entries in a screen
            // reader's control list, which is the same as having none at all.
            $ensure = lh_cr_fn('public/assets/js/core.js', 'ensureRefresh');
            lh_contains($ensure, "'aria-label': 'Refresh ' + cardHeadingText(card, label)",
                'the name carries the section, not just the verb');
            lh_contains($ensure, "type: 'button'", 'a real button, so it is in the tab order and takes Space and Enter');

            $name = lh_cr_fn('public/assets/js/core.js', 'cardHeadingText');
            lh_contains($name, ".card-head h2 span:not(.card-num)",
                'the heading\'s words, without the section number, and found whether or not the accordion has run');
            lh_contains($name, 'fallback', 'a card whose heading is not in that shape falls back to the loader\'s label');

            // The tooltip is the panel's own component, not the browser's bubble: `title` arrives
            // a second late, in a different place, in the browser's type.
            lh_false(str_contains($ensure, "title:"), 'no native title on the control');
            lh_contains($ensure, "'data-lh-tip': '1'", 'it opts into the panel\'s tooltip');
            lh_contains($ensure, "'data-full': REFRESH_TIP", 'and the text it shows is the one that separates it from Clear cache');

            $css = (string) preg_replace('#/\*.*?\*/#s', '', lh_cr_js('public/assets/css/panel.css'));
            lh_contains($css, '.card-refresh[data-lh-tip]::after', 'the control is on the tooltip component');
            lh_contains($css, '.card-refresh[data-lh-tip]:focus-visible::after',
                'keyboard is unconditional — a tooltip only a pointer can open is not reachable');
            lh_true(
                (bool) preg_match(
                    '/@media \(hover: hover\) and \(pointer: fine\) \{[^}]*\.card-refresh\[data-lh-tip\]:hover::after/s',
                    $css
                ),
                'and hover is gated, so a tap on a phone presses the control instead of stranding a label on it'
            );

            // A visible focus state, and the same 44px thumb every other icon-shaped control in
            // the panel is held to.
            lh_true(
                (bool) preg_match('/\.card-refresh:focus-visible \{[^}]*outline: 2px solid var\(--accent\)/s', $css),
                'focus has to be visible, not merely possible'
            );
            $mobile = (string) preg_replace('#/\*.*?\*/#s', '', lh_cr_js('public/assets/css/mobile.css'));
            lh_true(
                (bool) preg_match('/\.card-refresh,[^{}]*\{[^}]*min-width: var\(--lh-tap\)/s', $mobile),
                'an icon-shaped control needs the width of a thumb as well as the height'
            );
            lh_true(
                (bool) preg_match('/\.card-refresh,[^{}]*\{[^}]*min-height: var\(--lh-tap\)/s', $mobile),
                'and the height'
            );
        },

    'the mark is drawn locally, at one stroke weight, in the current colour' =>
        function (): void {
            // The panel ships with a CSP that allows no outside origin and a front end with no
            // markup sink at all, so an icon is neither a font, nor a sprite, nor a string of
            // SVG assigned somewhere. It is built the way icons.js builds every other mark.
            $mark = lh_cr_fn('public/assets/js/core.js', 'refreshMark');
            lh_contains($mark, 'createElementNS(SVG_NS', 'built as elements, never parsed from markup');
            lh_contains($mark, "'currentColor'", 'it takes the tone of the control it sits in, in both themes');
            lh_contains($mark, "svg.setAttribute('aria-hidden', 'true')", 'the name is on the button; the mark is decoration');
            lh_false(str_contains($mark, 'innerHTML'), 'no markup sink');
            lh_false(str_contains($mark, '#'), 'a drawn mark names no colour of its own');
        },

    /* ------------------------------------------------------------------ *
     * Which cards get one — the rule, held across every view
     * ------------------------------------------------------------------ */

    'every card the panel fetches gets a refresh control, on every view' =>
        function (): void {
            // THE RULE IS STRUCTURAL AND HAS NO LIST BEHIND IT: the control is created by
            // loadCard(), so the set of cards that have one is the set of cards that go through
            // loadCard(). This holds the two halves of that equivalence against every view the
            // product has, rendered in both Opensolr states, rather than against a sample:
            //
            //   - a card the server marked async (it emitted a skeleton) is driven by loadCard()
            //     and therefore has a control;
            //   - a card rendered server-side is driven by nothing and therefore has none.
            //
            // A new async card that forgot loadCard() fails here, which is the point: it is the
            // moment somebody has to decide, and the decision is one line.
            $loaded = lh_cr_loaded();
            lh_true(count($loaded) > 30, 'the panel really does load most of its cards asynchronously');

            $jobs = [];
            $seen = 0;

            foreach ([true, false] as $opensolr) {
                foreach (lh_cr_views($opensolr) as $slug => $view) {
                    foreach (lh_cr_cards(lh_cr_html($view)) as $id => $facts) {
                        $seen++;
                        $where = $slug . '/' . $id;

                        if (!$facts['async']) {
                            lh_false(
                                isset($loaded[$id]),
                                $where . ' is rendered server-side, so it must not be on loadCard(): '
                                    . 'a card with no skeleton has no progress line to raise and no '
                                    . 'content element to fill'
                            );
                            continue;
                        }

                        if (!isset($loaded[$id])) {
                            $jobs[$where] = $facts['job'];
                            continue;
                        }
                    }
                }
            }

            lh_true($seen > 80, 'every view was actually rendered, not skipped');

            // THE ONE EXCEPTION, AND WHY IT IS NOT A HOLE. Query analysis does not fetch its two
            // scan cards; it starts a background job and polls it, and the third card is drawn
            // from that job's accumulated result. Re-triggering one would start a fresh scan of
            // the request log — minutes of work and a different thing entirely from re-asking a
            // question that is already answered — so those cards keep the job's own controls.
            // Naming them here is a tripwire, not the rule: a fourth one appearing means
            // somebody added an async card outside loadCard() and has to say which it is.
            lh_same(
                ['queries/qy-shapes', 'queries/qy-latency', 'queries/qy-zero'],
                array_keys($jobs),
                'the only async cards outside loadCard() are the Query analysis scans; anything '
                    . 'else here is a card that loads by fetch and was not given a refresh control'
            );

            $queries = lh_cr_js('public/assets/js/views/queries.js');
            lh_contains($queries, 'runJob(', 'the exception is a background job, which is a different kind of load');
            lh_true($jobs['queries/qy-shapes'] && $jobs['queries/qy-zero'], 'and the scans carry the job\'s own mount');
        },

    'the set of cards with a control is not written down anywhere' =>
        function (): void {
            // A hand-kept list is the failure this whole design avoids: it is right on the day it
            // is written and wrong on the day somebody adds a card. core.js therefore knows no
            // card by name — it is handed an id by whoever is loading, and it does not care which.
            $core = lh_cr_js('public/assets/js/core.js');

            $names = [];
            foreach ([true, false] as $opensolr) {
                foreach (lh_cr_views($opensolr) as $view) {
                    foreach (array_keys(lh_cr_cards(lh_cr_html($view))) as $id) {
                        $names[$id] = true;
                    }
                }
            }
            lh_true(count($names) > 40, 'there are plenty of cards to have listed');

            foreach (array_keys($names) as $id) {
                lh_false(
                    str_contains($core, "'" . $id . "'"),
                    'core.js names the card ' . $id . '; the refresh set must be derived from '
                        . 'loadCard() being called, never from a list'
                );
            }

            // Nor is it keyed on a view: the control is identical on all of them.
            $ensure = lh_cr_fn('public/assets/js/core.js', 'ensureRefresh');
            lh_false(str_contains($ensure, 'boot.view'), 'the control does not vary by view');
            lh_false(str_contains($ensure, 'data-view'), 'and does not ask which page it is on');
        },

    /* ------------------------------------------------------------------ *
     * The tooltip's position
     * ------------------------------------------------------------------ */

    'the tooltip is positioned from a measurement, for a control that did not exist at load' =>
        function (): void {
            // The box is `position: fixed` — it has to be, to escape the overflow of everything
            // it can sit inside — and a fixed box is placed against the viewport, so CSS cannot
            // work out where the control is. responsive.js publishes both coordinates, clamped
            // so a control at the right-hand end of a card head cannot open a box that runs off
            // the window.
            $resp = lh_cr_code('public/assets/js/responsive.js');
            lh_contains($resp, 'function setUpControlTips(', 'the card head\'s control is on the tooltip too');
            lh_contains($resp, "'.card-refresh[data-lh-tip]", 'the refresh mark is one of the controls it serves');
            lh_contains($resp, 'publishSectionTip(target.closest(CONTROL_TIP_SELECTOR))',
                'it reuses the bar\'s positioner rather than a second one');

            // Delegated from the document, because core.js creates these controls as each card
            // loads — after this module has run, and repeatedly afterwards.
            $wire = lh_cr_fn('public/assets/js/responsive.js', 'setUpControlTips');
            lh_contains($wire, "document.addEventListener('pointerover'", 'nothing to bind to at start-up');
            lh_contains($wire, "document.addEventListener('focusin'", 'and the keyboard reaches it the same way');
            lh_contains($resp, 'setUpControlTips();', 'and it is actually started');

            // No markup sink in the module the suite holds to that rule.
            lh_false(str_contains($resp, '.innerHTML'), 'responsive.js still parses no markup');
        },

    'the row opener joins the same tooltip the other lone marks use' =>
        function (): void {
            // THE FOURTH ICON-ONLY CONTROL. The collapsed rail's three marks were moved onto the
            // panel's own tooltip; the row opener is a bare chevron doing the same thing and was
            // left on `title` — a bubble that arrives a second later, in a different place, in
            // the browser's type, beside three hints that do none of those things.
            $identity = lh_cr_code('public/assets/js/identity.js');
            $open = lh_cr_fn('public/assets/js/identity.js', 'openButton');

            lh_contains($open, "'data-lh-tip': '1'", 'the opener opts into the panel\'s tooltip');
            lh_contains($open, "'data-full': name", 'and the hint is the name of what it opens');
            lh_contains($open, "'aria-label': name",
                'THE ACCESSIBLE NAME STAYS: the tooltip is a visual affordance, never the name');
            lh_false(
                (bool) preg_match("/class: 'rowopen',[^}]*title:/s", $identity),
                'and the native title is gone from the control, so two hints cannot arrive at once'
            );

            $css = (string) preg_replace('#/\*.*?\*/#s', '', lh_cr_js('public/assets/css/panel.css'));
            lh_contains($css, '.rowopen[data-lh-tip]::after', 'it is on the component, not a copy of it');
            lh_contains($css, '.rowopen[data-lh-tip]:focus-visible::after', 'reachable by keyboard, unconditionally');
            lh_contains(lh_cr_code('public/assets/js/responsive.js'), ".rowopen[data-lh-tip]'",
                'and its position is published like every other one');
        },
];
