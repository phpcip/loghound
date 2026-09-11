<?php
/**
 * Loghound — the accordion's memory: every section, on every view, keyed on something stable.
 *
 * THE DEFECT THIS FILE PINS. On Settings some sections came back open after a refresh and some
 * did not, and a memory that is right for half the page is worse than no memory at all —
 * the operator cannot tell which headings they are allowed to trust.
 *
 * The cause was not in Settings. `setUpSections()` collected its sections with
 * `main .view > .card[id]`, a selector that required a card to be a DIRECT CHILD of the view.
 * Six cards across the panel are not: Bot forensics and Networks each wrap two in a `.grid-2`,
 * and the session explorer wraps two more in `.explorer`. Those six were never registered at
 * all — no toggle, no stored state, nothing for Expand all to reach — and on the explorer it
 * took the whole feature down, because one registered card is fewer than the two the accordion
 * needs before it will build anything. Depth is not a property of a section, so it is no longer
 * asked about: the set is every `.card` inside the view that has a heading and a stable name.
 *
 * The key changed with it. It was `lh.card.` + the ELEMENT id, which carries a `-card` suffix
 * that is an artefact of how `Panel\Controller::cardOpen()` spells the markup. It is now
 * `lh.card.<view slug>.<data-card>` — the view's own slug from <body data-view>, and the bare
 * id the view passes to cardOpen(), which is a literal in the PHP source and therefore the one
 * thing that survives a card being renumbered, retitled, reordered or re-marked-up.
 *
 * The suite has no browser (SPEC §12), so what can be checked here is exactly what makes the
 * scheme work: that every card every view emits carries that stable name, that no two sections
 * on a page collide, and that the module's source keeps the guards — force-open never reaching
 * storage, stale keys being dropped, and every read and write of localStorage inside a
 * try/catch so a private window still renders the page.
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

/** The module under test, as text. */
function lh_acc_js(): string
{
    $path = dirname(__DIR__) . '/public/assets/js/responsive.js';
    if (!is_file($path)) {
        lh_fail('public/assets/js/responsive.js is missing');
    }
    return (string) file_get_contents($path);
}

/** The same, with comment blocks removed, so prose can never satisfy a code assertion. */
function lh_acc_code(): string
{
    return (string) preg_replace('#/\*.*?\*/#s', '', lh_acc_js());
}

/**
 * The body of one JavaScript function, by brace matching from its declaration.
 *
 * Source-shape assertions are the only kind available without a browser, and the useful ones
 * are about WHICH function a call sits in — "no storage write inside the force-open path" is a
 * statement about a body, not about the file.
 */
function lh_acc_fn(string $name): string
{
    $js = lh_acc_code();
    $at = strpos($js, 'function ' . $name . '(');
    if ($at === false) {
        lh_fail('responsive.js has no function ' . $name . '()');
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

/**
 * A configuration with Opensolr connected, so the three platform views render their real cards.
 *
 * Without credentials Indexes, Query analysis and Who is querying render one explainer card
 * instead, which is a different shape and is pinned separately below.
 */
function lh_acc_config(bool $opensolr = true): Config
{
    $cfg = Config::load('/nonexistent-loghound-config');
    $cfg->set('solr.base_url', 'http://127.0.0.1:65535/solr');
    $cfg->set('solr.hits_core', 'lh_acc_hits');
    $cfg->set('solr.sessions_core', 'lh_acc_sessions');
    if ($opensolr) {
        $cfg->set('opensolr.email', 'owner@example.com');
        $cfg->set('opensolr.api_key', str_repeat('k', 32));
    }
    return $cfg;
}

/** A gateway whose transport answers with canned JSON, so nothing leaves the machine. */
function lh_acc_gateway(Config $cfg): Gateway
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
 * remembering to add it — which is the failure mode that let six cards go unregistered.
 *
 * @return array<string,Controller> slug => view
 */
function lh_acc_views(bool $opensolr = true): array
{
    $cfg = lh_acc_config($opensolr);
    $gw = lh_acc_gateway($cfg);

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
function lh_acc_html(Controller $view): string
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
 * Every `<section class="card">` a view emitted, in document order.
 *
 * @return array<int,array{id:string,name:string,depth:int}> depth is 0 for a direct child of
 *         the view, higher for a card a layout element wraps.
 */
function lh_acc_cards(string $html): array
{
    $doc = new DOMDocument();
    $before = libxml_use_internal_errors(true);
    $doc->loadHTML(
        '<!doctype html><html><body data-view="x"><main id="main"><div class="view">'
        . $html . '</div></main></body></html>',
        LIBXML_NONET
    );
    libxml_clear_errors();
    libxml_use_internal_errors($before);

    $xpath = new DOMXPath($doc);
    $nodes = $xpath->query('//*[contains(concat(" ", normalize-space(@class), " "), " card ")]');

    $out = [];
    foreach ($nodes ?: [] as $node) {
        $depth = 0;
        for ($parent = $node->parentNode; $parent instanceof DOMElement; $parent = $parent->parentNode) {
            if (str_contains(' ' . $parent->getAttribute('class') . ' ', ' view ')) {
                break;
            }
            $depth++;
        }
        $id = $node->getAttribute('id');
        $name = $node->getAttribute('data-card');
        if ($name === '') {
            $name = str_ends_with($id, '-card') ? substr($id, 0, -strlen('-card')) : $id;
        }
        $out[] = ['id' => $id, 'name' => $name, 'depth' => $depth];
    }
    return $out;
}

/**
 * The complete section list of the panel, pinned.
 *
 * Every section of every view, not a sample: the defect was precisely that some were covered
 * and some were not, so a test that checked a handful would have passed throughout. Adding,
 * removing or renaming a section is meant to fail this and be re-pinned deliberately, because
 * a renamed section is a stored choice that has to be pruned rather than silently orphaned.
 *
 * @return array<string,array<int,string>> slug => the `data-card` names, in render order
 */
function lh_acc_expected(): array
{
    return [
        'bots'         => ['bf-split', 'bf-reasons', 'bf-verdicts', 'bf-histogram', 'bf-classes',
                           'bf-crawlers', 'bf-pivot'],
        'callers'      => ['cl-filters', 'cl-volume', 'cl-who', 'cl-cross', 'cl-explain'],
        'fingerprints' => ['fp-explain', 'fp-table'],
        'hosts'        => ['hosts-table', 'hosts-share', 'hosts-none'],
        'indexes'      => ['ix-headline', 'ix-filters', 'ix-volume', 'ix-qtime', 'ix-handlers', 'ix-nodes'],
        'networks'     => ['net-stats', 'net-asns', 'net-types', 'net-map', 'net-netnames',
                           'net-countries', 'net-pivot'],
        'overview'     => ['ov-stats', 'ov-timing', 'ov-series', 'ov-pages', 'ov-searches', 'ov-pivot'],
        'performance'  => ['pf-headline', 'pf-time', 'pf-paths', 'pf-status'],
        'queries'      => ['qy-filters', 'qy-volume', 'qy-shapes', 'qy-latency', 'qy-zero',
                           'qy-slow', 'qy-explain'],
        'sessions'     => ['se-search', 'se-facets', 'se-results'],
        'settings'     => ['set-finish', 'set-ops', 'set-check', 'set-sources', 'set-solr',
                           'set-cache', 'set-beacon', 'set-privacy', 'set-retention', 'set-scoring',
                           'set-auth', 'set-2fa', 'set-display', 'set-reinstall'],
        'usage'        => ['usage-bw', 'usage-window', 'usage-limits'],
    ];
}

return [

    /* ------------------------------------------------------------------------------------
     * 1. THE SET — every section of every view, pinned whole
     * --------------------------------------------------------------------------------- */

    'every view the panel has is covered by this file, discovered rather than listed'
        => static function (): void {
            $slugs = array_keys(lh_acc_views());
            $pinned = array_keys(lh_acc_expected());
            sort($slugs);
            sort($pinned);
            lh_same(
                $pinned,
                $slugs,
                'a view was added or removed; its sections have to be pinned here too, because '
                . 'an unpinned view is exactly how six cards went unregistered'
            );
        },

    'every section of every view is pinned, in the order the view renders it'
        => static function (): void {
            $expected = lh_acc_expected();
            foreach (lh_acc_views() as $slug => $view) {
                $names = array_column(lh_acc_cards(lh_acc_html($view)), 'name');
                lh_same($expected[$slug], $names, $slug . ': the section list');
            }
        },

    /* ------------------------------------------------------------------------------------
     * 2. THE KEY — stable across a render, and across a release
     * --------------------------------------------------------------------------------- */

    'every card carries a name the storage key can be built from'
        => static function (): void {
            foreach (lh_acc_views() as $slug => $view) {
                foreach (lh_acc_cards(lh_acc_html($view)) as $card) {
                    lh_false(
                        $card['name'] === '',
                        $slug . ': a card with neither data-card nor an "<id>-card" id cannot be '
                        . 'keyed, so it would silently never remember anything'
                    );
                }
            }
        },

    'a section name is a literal in the view, so it cannot move when the card does'
        => static function (): void {
            foreach (lh_acc_views() as $slug => $view) {
                $source = (string) file_get_contents((new ReflectionClass($view))->getFileName());
                foreach (lh_acc_cards(lh_acc_html($view)) as $card) {
                    lh_true(
                        str_contains($source, "'" . $card['name'] . "'")
                        || str_contains($source, '"' . $card['name'] . '"'),
                        $slug . ': "' . $card['name'] . '" must be a literal in the view\'s own source. '
                        . 'A name derived from a position, a heading or a counter changes when the '
                        . 'page is re-ordered or re-worded, and the stored choice goes with it'
                    );
                }
            }
        },

    'a section name carries no character that would need escaping in a storage key'
        => static function (): void {
            foreach (lh_acc_views() as $slug => $view) {
                foreach (lh_acc_cards(lh_acc_html($view)) as $card) {
                    lh_true(
                        (bool) preg_match('/^[A-Za-z0-9_-]+$/', $card['name']),
                        $slug . ': "' . $card['name'] . '" must be plain. The key is joined with "." '
                        . 'and split on it again when stale keys are pruned, so a dot in a name '
                        . 'would make a section indistinguishable from a view'
                    );
                }
            }
        },

    'no two sections on one page resolve to the same key'
        => static function (): void {
            foreach (lh_acc_views() as $slug => $view) {
                $keys = [];
                foreach (lh_acc_cards(lh_acc_html($view)) as $card) {
                    $key = 'lh.card.' . $slug . '.' . $card['name'];
                    lh_false(
                        in_array($key, $keys, true),
                        $slug . ': two sections both key on ' . $key . ', so one would silently '
                        . 'inherit the other\'s state'
                    );
                    $keys[] = $key;
                }
            }
        },

    'the view slug is part of the key, so two pages cannot share one section\'s state'
        => static function (): void {
            $seen = [];
            foreach (lh_acc_views() as $slug => $view) {
                foreach (lh_acc_cards(lh_acc_html($view)) as $card) {
                    $seen[$card['name']][] = $slug;
                }
            }

            $js = lh_acc_code();
            lh_contains($js, "document.body.getAttribute('data-view')", 'the slug is read off the page');
            lh_contains($js, "CARD_KEY + viewSlug() + '.' + name", 'and it is part of every key');

            // Layout::render() is what puts it there; without the attribute every page would
            // share one namespace again.
            lh_contains(
                (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Layout.php'),
                '<body data-view="',
                'the slug has to be on the page for the key to be able to use it'
            );
            lh_true($seen !== [], 'there are sections to key');
        },

    /* ------------------------------------------------------------------------------------
     * 3. REGISTRATION — depth is not a property of a section
     * --------------------------------------------------------------------------------- */

    'the sections a layout element wraps are still sections'
        => static function (): void {
            // The six that the old direct-child selector dropped, named so the regression is
            // recognisable rather than just a count.
            $nested = [
                'bots'     => ['bf-verdicts', 'bf-histogram'],
                'networks' => ['net-types', 'net-map'],
                'sessions' => ['se-facets', 'se-results'],
            ];
            foreach (lh_acc_views() as $slug => $view) {
                if (!isset($nested[$slug])) {
                    continue;
                }
                $deep = [];
                foreach (lh_acc_cards(lh_acc_html($view)) as $card) {
                    if ($card['depth'] > 0) {
                        $deep[] = $card['name'];
                    }
                }
                lh_same($nested[$slug], $deep, $slug . ': the cards a wrapper holds');
            }
        },

    'the module no longer asks a section to be a direct child of the view'
        => static function (): void {
            $js = lh_acc_code();
            lh_false(
                str_contains($js, "'main .view > .card[id]'"),
                'the direct-child selector is what left six cards with no toggle and no memory'
            );
            lh_contains($js, "querySelectorAll('main .view .card')", 'depth is not asked about');
            lh_contains($js, 'function isSection(', 'what a section is has one definition');

            // A card the explorer rail owns already has a disclosure of its own; two controls on
            // one card is the bug, not the feature.
            lh_contains($js, "card.closest('.explorer .facets')", 'the facet rail keeps its own control');

            // And a card that arrives hidden is a card that exists because something is wrong.
            // Hosts::explainCard() is revealed by views/hosts.js when the range records no virtual
            // host; a fold control on it could only ever be pressed after the reveal, and the
            // reveal would show a collapsed heading.
            lh_contains($js, '!card.hidden', 'a card that is hidden on arrival is not folded');
            $hostsJs = (string) file_get_contents(dirname(__DIR__) . '/public/assets/js/views/hosts.js');
            lh_contains(
                $hostsJs,
                'hosts-none',
                'the front end is what reveals it, which is why it must not be folded behind a control'
            );
        },

    'a section is still required to have a heading to hang the control in'
        => static function (): void {
            lh_contains(
                lh_acc_fn('isSection'),
                "':scope > .card-head > h2'",
                'the h2 is what becomes the button; a card without one cannot fold'
            );
            foreach (lh_acc_views() as $slug => $view) {
                $html = lh_acc_html($view);
                foreach (lh_acc_cards($html) as $card) {
                    lh_contains(
                        $html,
                        '<div class="card-head"><h2>',
                        $slug . ': ' . $card['name'] . ' needs a heading to fold by'
                    );
                }
            }
        },

    /* ------------------------------------------------------------------------------------
     * 4. FORCE-OPEN — an override for one render, never a stored choice
     * --------------------------------------------------------------------------------- */

    'nothing that opens a section on the page\'s behalf can write to storage'
        => static function (): void {
            foreach (['setCard', 'forceCard', 'openFromHash', 'foldCard'] as $fn) {
                $body = lh_acc_fn($fn);
                lh_false(
                    str_contains($body, 'setItem'),
                    $fn . '() must not record anything. A section opened because a fetch failed, '
                    . 'because a link pointed at it, or because it holds a warning is not the '
                    . 'operator choosing, and recording it would bury the choice they did make'
                );
                lh_false(
                    str_contains($body, 'removeItem'),
                    $fn . '() must not drop a stored choice either'
                );
            }
        },

    'the choice a section records is read off the element, never off the screen'
        => static function (): void {
            $persist = lh_acc_fn('persistChoices');
            lh_contains($persist, 'dataset.foldChosen', 'the value written is the recorded choice');
            lh_false(
                str_contains($persist, 'isCardOpen') || str_contains($persist, 'is-shut'),
                'writing what is on screen would record every force-opened section as chosen'
            );

            // A press is the only thing that sets it.
            $js = lh_acc_code();
            lh_same(
                2,
                preg_match_all('/dataset\.foldChosen\s*=(?!=)/', $js),
                'foldChosen is set when a card is wired and when a card is pressed, and nowhere else'
            );
            lh_contains(lh_acc_fn('chooseCards'), 'dataset.foldChosen =', 'a press records a choice');
            lh_false(
                str_contains(lh_acc_fn('forceCard'), 'foldChosen'),
                'force-open must leave the choice underneath it exactly as it was'
            );
        },

    'every path that force-opens a section goes through the one function that cannot persist'
        => static function (): void {
            $js = lh_acc_code();
            foreach (
                [
                    "forceCard(document.getElementById(id + '-card'))" => 'a card whose fetch failed',
                    'forceCard(document.getElementById(link.getAttribute' => 'a jump from the section nav',
                    'forceCard(card);'                                   => 'a deep link and the trouble recheck',
                ] as $needle => $what
            ) {
                lh_contains($js, $needle, $what . ' must open without recording');
            }
            lh_contains($js, "document.addEventListener('lh:card-trouble'", 'core.js announces a failure here');
            lh_contains($js, 'const TROUBLE', 'and trouble on arrival still overrides the stored state');
            lh_contains($js, 'hasTrouble(card) || chosen', 'the override is over the top of the choice, not instead of it');
        },

    'a marker a card always carries is not trouble, because a card that never folds never remembers'
        => static function (): void {
            // THE SETTINGS HALF OF THE DEFECT. `.confirm-form` was in TROUBLE, and Settings spells
            // three unrelated things with it: the pending "start ingesting this file" form, the
            // stop-ingesting button, and the reinstall form. The last two are unconditional, so
            // set-sources and set-reinstall were force-opened on every render of every
            // installation and could never show the operator their own choice — which reads as
            // "it forgot". Settings::problemBanner() warns about exactly this shape.
            $js = lh_acc_code();
            $at = strpos($js, 'const TROUBLE');
            $trouble = substr($js, (int) $at, (int) strpos($js, ';', (int) $at) - (int) $at);

            lh_contains($trouble, '.confirm-form.awaiting', 'only a form genuinely awaiting a decision');
            lh_false(
                (bool) preg_match('/\.confirm-form(?!\.awaiting)/', $trouble),
                'a bare .confirm-form matches two forms that are always on the page'
            );

            $php = (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Settings.php');
            lh_contains($php, 'confirm-form awaiting', 'and Settings marks that one form as awaiting');

            // Nothing is uncovered by the narrowing: a source awaiting review already carries its
            // own marker beside the form, and a refusal goes out through problemBanner().
            lh_contains($trouble, '.source-head .chip-warn', 'a source awaiting review holds its card open');
            lh_contains($trouble, '.check-row .chip-warn', 'and so does a refusal');
            lh_contains($php, 'source-head', 'which is the block the source marker sits in');
            lh_contains($php, 'Awaiting review', 'and the words it carries when a source is unconfirmed');

            // The bare chip stays out, and it is why: it is also the chip on the word "Note".
            lh_false(
                (bool) preg_match("/TROUBLE[^;]*'\\.chip-warn'/s", $js),
                'a bare warning chip is an annotation as often as a state'
            );
        },

    'the stored choice still beats the first-section default'
        => static function (): void {
            $js = lh_acc_code();
            lh_contains($js, 'remembered === null ? first', 'a stored choice beats the default');
            lh_contains($js, 'index === 0', 'the first section is the one the default opens');
            lh_contains(
                $js,
                'untouched && index === 0',
                'and the default is only for a page the operator has never touched: once they have '
                . 'arranged it, a section added by a later release must open nothing'
            );
            lh_contains($js, 'function viewHasChoices(', 'which is asked per page, not per card');
        },

    'expand all and collapse all put every section in storage, not only the one pressed'
        => static function (): void {
            $expand = lh_acc_fn('addExpandAll');
            lh_contains($expand, 'chooseCards(cards, () => open)', 'both directions record every section');
            lh_contains(
                lh_acc_fn('chooseCards'),
                'persistChoices(cards)',
                'a press writes the whole page, so the next load matches what was on screen'
            );
        },

    /* ------------------------------------------------------------------------------------
     * 5. PRUNING and STORAGE FAILURE
     * --------------------------------------------------------------------------------- */

    'a key is retired only when it cannot belong to any view, never when it is off screen'
        => static function (): void {
            // THE SECOND DEFECT, and it was in the pruning itself. Retiring "a key in this page's
            // namespace naming a section that is not on the page" deletes the choice for a card
            // that is merely absent from THIS render — a pivot the view has no pairing for, an
            // Opensolr card with no account configured, anything conditional on the data or the
            // query string. Measured on Overview: ov-pivot stored as open, one render without
            // the card, choice gone, default on its return.
            $js = lh_acc_code();
            lh_contains(
                $js,
                'function pruneCardKeys()',
                'pruning takes no card list, so it structurally cannot judge a key by what happens '
                . 'to be on the screen'
            );
            lh_contains($js, 'pruneCardKeys();', 'and it is called without one');

            $prune = lh_acc_fn('pruneCardKeys');
            lh_contains($prune, 'removeItem', 'a key that cannot belong anywhere is removed');
            lh_contains($prune, 'window.localStorage.key(', 'which means enumerating what is there');
            lh_contains(
                $prune,
                'dot === -1',
                'a key from the release before the view slug was part of it is stale by shape'
            );
            lh_contains(
                $prune,
                'views.indexOf(rest.slice(0, dot)) === -1',
                'and a key whose view no longer exists is stale by name'
            );
            lh_contains(
                $prune,
                'views.length > 0',
                'a page with no navigation on it knows nothing, so it must retire nothing'
            );
            foreach (['cards', 'cardStoreKey', 'isSection', 'querySelectorAll'] as $forbidden) {
                lh_false(
                    str_contains($prune, $forbidden),
                    'pruning must not consult the rendered page: ' . $forbidden . ' is how the '
                    . 'choice for an absent section got deleted'
                );
            }

            lh_contains(lh_acc_fn('setUpSections'), 'pruneCardKeys()', 'it runs on every load');
            lh_contains(lh_acc_fn('knownViews'), 'slugOf(link)', 'the live views are read off the navigation');
            lh_contains(
                (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Layout.php'),
                '?v=',
                'which is where Layout::nav() puts every slug the product has'
            );
        },

    'a section absent from one render still has its choice when it comes back'
        => static function (): void {
            // The views that legitimately change their whole card set: with no Opensolr account
            // the three platform pages render one explainer instead of their sections. Pinned so
            // that "a card can be absent on a render" stays a fact this file knows, rather than
            // something a later reader has to rediscover the way the owner did.
            $full = [];
            foreach (lh_acc_views(true) as $slug => $view) {
                $full[$slug] = array_column(lh_acc_cards(lh_acc_html($view)), 'name');
            }
            $reduced = [];
            foreach (lh_acc_views(false) as $slug => $view) {
                $reduced[$slug] = array_column(lh_acc_cards(lh_acc_html($view)), 'name');
            }

            $changed = [];
            foreach ($full as $slug => $names) {
                if ($names !== ($reduced[$slug] ?? [])) {
                    $changed[] = $slug;
                }
            }
            lh_same(
                ['callers', 'indexes', 'queries'],
                $changed,
                'these views drop every one of their sections when the account is not configured, '
                . 'which is exactly the case pruning must not treat as "those sections are gone"'
            );

            // The rule, run in PHP against the reduced render with storage seeded from the full
            // one. Under the rule this replaced — retire anything in this view's namespace that
            // is not on the page — every section of all three views would be wiped here. Under
            // the rule now in the module, nothing is: a key is retired only by its shape or by
            // naming a view the product does not have.
            $views = array_keys($full);
            foreach ($full as $slug => $names) {
                $seeded = array_map(static fn (string $n): string => 'lh.card.' . $slug . '.' . $n, $names);
                $retired = array_values(array_filter($seeded, static function (string $key) use ($views): bool {
                    $rest = substr($key, strlen('lh.card.'));
                    $dot = strpos($rest, '.');
                    return $dot === false || !in_array(substr($rest, 0, $dot), $views, true);
                }));
                lh_same(
                    [],
                    $retired,
                    $slug . ': a choice made while these sections were on the page must survive a '
                    . 'render without them'
                );
            }

            // And the derivation is render-independent: the name a key is built from is spelled
            // into the markup twice, the same way, on every render.
            foreach (lh_acc_views(true) as $slug => $view) {
                foreach (lh_acc_cards(lh_acc_html($view)) as $card) {
                    if ($card['id'] !== '' && $card['name'] !== $card['id']) {
                        lh_same(
                            $card['name'] . '-card',
                            $card['id'],
                            $slug . ': the element id and the section name must agree, so which of '
                            . 'the two the key falls back on cannot matter'
                        );
                    }
                }
            }

            // And the name is read from the markup alone — never from a number that renumbers when
            // a sibling appears, nor from a heading that changes with the data.
            $name = lh_acc_fn('cardName');
            lh_contains($name, "getAttribute('data-card')", 'the server\'s own name for the section');
            lh_contains($name, 'card.id', 'or the element id, with its suffix taken off');
            foreach (['card-num', 'textContent', 'innerText', 'indexOf(card)', 'heading'] as $forbidden) {
                lh_false(
                    str_contains($name, $forbidden),
                    'a name built from ' . $forbidden . ' moves when the page is re-ordered or re-worded'
                );
            }
        },

    'every read and every write of localStorage survives a browser that refuses it'
        => static function (): void {
            $rest = lh_acc_code();
            foreach (
                ['viewHasChoices', 'pruneCardKeys', 'rememberedCard', 'persistChoices',
                 'isRailCollapsed', 'setRail', 'foldIsOpen', 'rememberFold'] as $fn
            ) {
                $body = lh_acc_fn($fn);
                lh_contains($body, 'window.localStorage', $fn . '() is a storage function');
                lh_contains(
                    $body,
                    'catch (',
                    $fn . '() must not throw in a private window or where site data is blocked; the '
                    . 'page has to render with no stored value at all'
                );
                $rest = str_replace($body, '', $rest);
            }

            // Nothing may reach storage from outside one of those.
            lh_false(
                str_contains($rest, 'window.localStorage'),
                'a storage access outside the functions that guard it would take the page down'
            );
        },

    'the accordion writes its own namespace and nobody else\'s'
        => static function (): void {
            $js = lh_acc_code();
            lh_contains($js, "const CARD_KEY = 'lh.card.'", 'the sections have their own prefix');
            lh_contains($js, "const FOLD_KEY = 'lh.fold.'", 'the folded blocks inside a card have theirs');
            lh_contains($js, "const RAIL_KEY = 'lh.rail'", 'and the navigation rail has its own');
            lh_false(
                str_starts_with('lh.fold.', 'lh.card.') || str_starts_with('lh.rail', 'lh.card.'),
                'pruning walks every key with the section prefix, so no other namespace may sit under it'
            );
        },

    /* ------------------------------------------------------------------------------------
     * 6. THE CARDS STILL WRITTEN BY HAND
     * --------------------------------------------------------------------------------- */

    'the one card not emitted through cardOpen() is still keyable, and is the only one'
        => static function (): void {
            // A card emitted by Controller::cardOpen() spells the same string twice, as
            // `data-card="<id>"` and as `id="<id>-card"`. A card whose two do not line up was
            // written by hand: Hosts::explainCard() keeps the bare id `hosts-none` on purpose,
            // because views/hosts.js unhides it by that exact id. It is keyable either way — the
            // name comes off data-card — but it is the one card whose id nothing enforces.
            $hand = [];
            foreach (lh_acc_views() as $slug => $view) {
                foreach (lh_acc_cards(lh_acc_html($view)) as $card) {
                    if ($card['id'] !== $card['name'] . '-card') {
                        $hand[] = $slug . '/' . $card['name'] . ' (id="' . $card['id'] . '")';
                    }
                }
            }
            lh_same(
                ['hosts/hosts-none (id="hosts-none")'],
                $hand,
                'there should be one card left whose id does not follow cardOpen(), and it should '
                . 'be that one'
            );
            lh_contains(
                lh_acc_fn('cardName'),
                "getAttribute('data-card')",
                'which is why the name is taken from data-card first and the id only as a fallback'
            );
            lh_contains(
                lh_acc_fn('cardName'),
                "id.endsWith('-card')",
                'and why the fallback strips the suffix rather than assuming it is there'
            );
        },

    'a view with no Opensolr account renders one explainer, and the accordion stays out of it'
        => static function (): void {
            foreach (['indexes', 'queries', 'callers'] as $slug) {
                $view = lh_acc_views(false)[$slug];
                $cards = lh_acc_cards(lh_acc_html($view));
                lh_same(
                    ['os-none'],
                    array_column($cards, 'name'),
                    $slug . ': the unconfigured page is one explainer'
                );
            }

            // One card is fewer than the two setUpSections() requires, so no toggle is built and
            // no key is written on those pages at all. That matters twice over: an explainer with
            // a fold control would be a page whose only content could be collapsed to nothing,
            // and a load that built no accordion must still not disturb what is stored.
            lh_contains(
                lh_acc_fn('setUpSections'),
                'cards.length < 2',
                'a page with one section has nothing to fold against'
            );
            $order = lh_acc_fn('setUpSections');
            lh_true(
                strpos($order, 'cards.length < 2') < strpos($order, 'pruneCardKeys'),
                'and it returns BEFORE anything touches storage'
            );
        },

    /* ------------------------------------------------------------------------------------
     * 7. HOUSE RULES
     * --------------------------------------------------------------------------------- */

    'the accordion builds its controls without a markup sink'
        => static function (): void {
            $js = lh_acc_code();
            lh_false((bool) preg_match('/\.innerHTML\s*=/', $js), 'the CSP has no unsafe-inline, and a '
                . 'heading can carry a hostname');
            lh_false((bool) preg_match('/\.(outerHTML|insertAdjacentHTML)\b/', $js), 'no markup-parsing sink');
            lh_false((bool) preg_match('/\beval\s*\(/', $js), 'no eval');
        },
];
