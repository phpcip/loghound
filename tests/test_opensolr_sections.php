<?php
/**
 * Loghound — tests for the section nav, the card numbering and the request-log filters.
 *
 * FOUR PROPERTIES, all of them things that were wrong before and would silently go wrong
 * again — each one fails as a cosmetic nothing on a screenshot and as a wrong number in use.
 *
 *  1. **One list numbers the cards.** Settings had two cards claiming 02 and two claiming 03,
 *     because every number was a literal at its own `cardOpen()` call. The numbers now come
 *     from the view's `sections()`, so they are asserted to be unique, sequential, and
 *     present on every card the view renders — a card the view forgot to declare must show up
 *     here as a missing number rather than as a silently blank badge.
 *
 *  2. **The nav is rendered outside `.view`.** `.view` is a flex column, and a `position:
 *     sticky` element inside a flex container is sticky within its own flex item box, which
 *     has no travel — so a nav emitted inside it scrolls away and never comes back. That is a
 *     DOM-ORDER fact, which is exactly the kind a test can hold: the <nav> must sit inside
 *     <main>, before the H1, and before `<div class="view">`.
 *
 *  3. **The filters are an allowlist that reaches Solr as literals.** A field the request log
 *     does not have must be dropped, not passed; a value full of Lucene syntax must arrive as
 *     a quoted term; and the sidebar filters the rest of the panel uses must be reported as
 *     ignored rather than applied to a schema that has never heard of them. A filter silently
 *     dropped is a wrong answer presented as a right one.
 *
 *  4. **Nothing here lets the API key out**, including the packed filter string that travels
 *     into a job's stored parameters.
 *
 * No test here makes a network call.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Config;
use Loghound\OpensolrLog;
use Loghound\Panel\Callers;
use Loghound\Panel\Controller;
use Loghound\Panel\Gateway;
use Loghound\Panel\Indexes;
use Loghound\Panel\Layout;
use Loghound\Panel\OpensolrView;
use Loghound\Panel\Queries;
use Loghound\Panel\Sections;
use Loghound\Panel\Settings;
use Loghound\Solr;

/** The fake credential every test looks for in places it must not appear. */
const LH_SEC_KEY = 'apikey-SECTIONS-MUST-NOT-LEAK-9a1f';

/** A config with Opensolr credentials and a Solr backend that is never reached. */
function lh_sec_config(): Config
{
    $cfg = Config::load('/nonexistent-loghound-config');
    $cfg->set('solr.base_url', 'http://127.0.0.1:65535/solr');
    $cfg->set('solr.hits_core', 'lh_sec_hits');
    $cfg->set('solr.sessions_core', 'lh_sec_sessions');
    $cfg->set('opensolr.email', 'owner@example.com');
    $cfg->set('opensolr.api_key', LH_SEC_KEY);
    return $cfg;
}

/**
 * A gateway whose transport never answers, so no test can accidentally depend on Solr.
 *
 * @param array<int,array<string,mixed>> $captured
 */
function lh_sec_gateway(array &$captured): Gateway
{
    $cfg = lh_sec_config();
    $transport = function (array $request) use (&$captured): array {
        $captured[] = $request;
        return ['status' => 0, 'body' => '', 'error' => 'not reachable in tests'];
    };
    return new Gateway($cfg, new Solr((array) $cfg->get('solr'), $transport), false);
}

/**
 * A platform client answering every call with one canned body.
 *
 * @param array<int,array<string,mixed>> $captured
 */
function lh_sec_client(string $body, array &$captured): OpensolrLog
{
    return new OpensolrLog(
        [
            'api_base' => 'https://opensolr.test/solr_manager/api',
            'email'    => 'owner@example.com',
            'api_key'  => LH_SEC_KEY,
        ],
        function (array $request) use (&$captured, $body): array {
            $captured[] = $request;
            return ['status' => 200, 'body' => $body, 'error' => ''];
        }
    );
}

/** An empty but well-formed platform answer: the state these views legitimately get. */
function lh_sec_empty_body(): string
{
    return (string) json_encode([
        'responseHeader' => ['status' => 0],
        'response' => ['numFound' => 0, 'start' => 0, 'docs' => []],
    ]);
}

/** Every view that declares a card list, freshly built. */
function lh_sec_views(): array
{
    $cfg = lh_sec_config();
    $captured = [];
    $gw = lh_sec_gateway($captured);

    return [
        new Indexes($cfg, $gw),
        new Queries($cfg, $gw),
        new Callers($cfg, $gw),
        new Settings($cfg, $gw),
    ];
}

/** Render one view's body and hand back the HTML. */
function lh_sec_body(Controller $view): string
{
    ob_start();
    $view->body();
    return (string) ob_get_clean();
}

/** Call a protected method on a view. */
function lh_sec_call(object $view, string $method, array $args = [])
{
    return (new ReflectionMethod($view, $method))->invokeArgs($view, $args);
}


return [

    /* -----------------------------------------------------------------------------
     * The card list, and the numbering that comes out of it
     * -------------------------------------------------------------------------- */

    'every view that declares sections declares them well' => function (): void {
        foreach (lh_sec_views() as $view) {
            lh_true($view instanceof Sections, $view->slug() . ' declares a card list');

            $sections = $view->sections();
            lh_true(count($sections) >= 2, $view->slug() . ' declares more than one card');

            $ids = [];
            foreach ($sections as $entry) {
                $id = (string) ($entry[0] ?? '');
                $label = (string) ($entry[1] ?? '');
                lh_true($id !== '', $view->slug() . ' card id is not empty');
                lh_true($label !== '', $view->slug() . ' nav label for ' . $id . ' is not empty');
                lh_true(
                    mb_strlen($label) <= 28,
                    $view->slug() . ' nav label "' . $label . '" is short enough for a one-row bar'
                );
                $ids[] = $id;
            }
            lh_same(count($ids), count(array_unique($ids)), $view->slug() . ' card ids are unique');
        }
    },

    'card numbers are sequential, unique, and on every card' => function (): void {
        foreach (lh_sec_views() as $view) {
            $html = lh_sec_body($view);
            preg_match_all('/class="card-num">([^<]*)</', $html, $found);
            $numbers = $found[1];

            lh_true($numbers !== [], $view->slug() . ' rendered at least one numbered card');
            lh_same(
                count($numbers),
                count(array_unique($numbers)),
                $view->slug() . ' renders no two cards with the same number'
            );
            foreach ($numbers as $i => $number) {
                lh_same(sprintf('%02d', $i + 1), $number, $view->slug() . ' card ' . ($i + 1) . ' number');
            }
        }
    },

    'no card is rendered without a number' => function (): void {
        foreach (lh_sec_views() as $view) {
            $html = lh_sec_body($view);
            if (preg_match('/class="card-num">\s*</', $html)) {
                lh_fail($view->slug() . ' rendered a card whose number is blank — its id is not in sections()');
            }
        }
    },

    'every jump target the nav names is a card that exists' => function (): void {
        foreach (lh_sec_views() as $view) {
            $html = lh_sec_body($view);
            foreach ($view->sections() as $entry) {
                $id = (string) $entry[0];
                lh_contains($html, 'id="' . $id . '-card"', $view->slug() . ' renders ' . $id);
            }
        }
    },

    'an undeclared card id gets no number rather than a wrong one' => function (): void {
        lh_same('', Layout::cardNum([['a', 'A'], ['b', 'B']], 'c'), 'an id that is not in the list');
        lh_same('01', Layout::cardNum([['a', 'A'], ['b', 'B']], 'a'), 'the first entry');
        lh_same('02', Layout::cardNum([['a', 'A'], ['b', 'B']], 'b'), 'the second entry');
        lh_same('', Layout::cardNum([], 'a'), 'an empty list');
    },

    /* -----------------------------------------------------------------------------
     * Where the nav is rendered, which is the whole reason it works
     * -------------------------------------------------------------------------- */

    'the nav is a sibling of .view and not a child of it' => function (): void {
        $cfg = lh_sec_config();
        $captured = [];
        $gw = lh_sec_gateway($captured);

        foreach ([new Indexes($cfg, $gw), new Settings($cfg, $gw)] as $view) {
            $_GET = ['v' => $view->slug()];
            ob_start();
            Layout::render($cfg, $gw, $view, ['view' => $view->slug()]);
            $html = (string) ob_get_clean();
            $_GET = [];

            $main = strpos($html, '<main id="main">');
            $nav = strpos($html, '<nav class="set-nav"');
            $h1 = strpos($html, '<h1>');
            $viewDiv = strpos($html, '<div class="view">');

            lh_true(is_int($nav), $view->slug() . ' rendered a section nav');
            lh_true($main < $nav, $view->slug() . ': the nav is inside <main>');
            lh_true($nav < $h1, $view->slug() . ': the nav is above the H1, pinned to the top of the chrome');
            lh_true(
                $nav < $viewDiv,
                $view->slug() . ': the nav is BEFORE .view — a sticky child of that flex column has no travel'
            );

            $tail = substr($html, $nav);
            lh_true(
                strpos($tail, '</nav>') < strpos($tail, '<div class="view">'),
                $view->slug() . ': the nav is closed before .view opens, so it is a sibling and not a child'
            );
        }
    },

    'the nav entry count matches the card list on every view' => function (): void {
        $cfg = lh_sec_config();
        $captured = [];
        $gw = lh_sec_gateway($captured);

        foreach (lh_sec_views() as $view) {
            $_GET = ['v' => $view->slug()];
            ob_start();
            Layout::render($cfg, $gw, $view, ['view' => $view->slug()]);
            $html = (string) ob_get_clean();
            $_GET = [];

            preg_match('#<nav class="set-nav".*?</nav>#s', $html, $m);
            preg_match_all('/data-sect="([^"]+)"/', (string) ($m[0] ?? ''), $entries);

            lh_same(
                array_map(static fn (array $e): string => (string) $e[0], $view->sections()),
                $entries[1],
                $view->slug() . ': the bar lists exactly the cards the view declares, in order'
            );
        }
    },

    'every view in the panel gets a bar, declared or derived' => function (): void {
        $cfg = lh_sec_config();
        $captured = [];
        $gw = lh_sec_gateway($captured);

        $classes = [
            'overview' => 'Overview', 'bots' => 'Bots', 'attacks' => 'Attacks',
            'fingerprints' => 'Fingerprints',
            'networks' => 'Networks', 'sessions' => 'Sessions', 'performance' => 'Performance',
            'hosts' => 'Hosts', 'indexes' => 'Indexes', 'queries' => 'Queries',
            'callers' => 'Callers', 'usage' => 'Usage', 'settings' => 'Settings',
        ];

        foreach (Layout::nav() as $item) {
            $slug = $item['slug'];
            $class = 'Loghound\\Panel\\' . ($classes[$slug] ?? '');
            if (!class_exists($class)) {
                lh_fail('no class for the nav entry ' . $slug);
            }

            $_GET = ['v' => $slug];
            ob_start();
            Layout::render($cfg, $gw, new $class($cfg, $gw), ['view' => $slug]);
            $html = (string) ob_get_clean();
            $_GET = [];

            preg_match('#<nav class="set-nav".*?</nav>#s', $html, $m);
            preg_match_all('/data-sect="([^"]+)"/', (string) ($m[0] ?? ''), $entries);

            lh_true(
                count($entries[1]) >= 2,
                $slug . ' has a section bar with something in it, declared or derived from its cards'
            );
            foreach ($entries[1] as $id) {
                lh_contains($html, 'id="' . $id . '-card"', $slug . ': the bar points at a card that exists');
            }
        }
    },

    'a derived label is escaped once, at the sink' => function (): void {
        $derive = static function (string $body): array {
            $method = new ReflectionMethod(Layout::class, 'cardsIn');

            return $method->invoke(null, $body);
        };

        /* Exactly what Controller::cardOpen() emits for a heading containing an ampersand:
           the heading in the markup is already escaped, so decoding before re-escaping is what
           stops "Storage & bandwidth" arriving in the bar as "Storage &amp;amp; bandwidth". */
        $body = '<section class="card" id="a-card" data-card="a"><div class="card-head"><h2>'
            . '<span class="card-num">01</span><span>Storage &amp; bandwidth</span></h2></div>'
            . '<section class="card"><div class="card-head"><h2>'
            . '<span class="card-num">01</span><span>No id, skip me</span></h2></div>'
            . '<section class="card" id="b-card" data-card="b"><div class="card-head"><h2>'
            . '<span class="card-num">02</span><span>Second</span></h2></div>';

        $found = $derive($body);
        lh_same(2, count($found), 'a card with no id is not a jump target');
        lh_same('a', $found[0][0], 'the id is the base id, not the element id');
        lh_same('Storage & bandwidth', $found[0][1], 'the label is decoded ready to be escaped again');
        lh_same('Second', $found[1][1], 'and the order is render order');

        lh_same([], $derive('<p>no cards here</p>'), 'a page with no cards derives nothing');
    },

    'a long derived heading is trimmed so the bar stays one row' => function (): void {
        $method = new ReflectionMethod(Layout::class, 'cardsIn');
        $body = '<section class="card" id="x-card" data-card="x"><div class="card-head"><h2>'
            . '<span class="card-num">01</span><span>' . str_repeat('word ', 12) . '</span></h2></div>';

        $found = $method->invoke(null, $body);
        lh_true(mb_strlen($found[0][1]) <= 22, 'a card heading is cut to a length a one-row bar can carry');
        lh_contains($found[0][1], '…', 'and says it was cut');
    },

    /* -----------------------------------------------------------------------------
     * The request-log filters
     * -------------------------------------------------------------------------- */

    'a field the request log does not have is dropped, not passed' => function (): void {
        $cfg = lh_sec_config();
        $captured = [];
        $_GET = ['lf' => [
            'path'          => ['select'],
            'bot_verdict_s' => ['bot'],
            'country_s'     => ['DE'],
            '../etc/passwd' => ['x'],
        ]];
        $view = new Indexes($cfg, lh_sec_gateway($captured));
        $filters = lh_sec_call($view, 'logFilters');
        $_GET = [];

        lh_same(['path' => ['select']], $filters, 'only the allowlisted field survives');
    },

    'the active filters become quoted terms in the filter list' => function (): void {
        $cfg = lh_sec_config();
        $captured = [];
        $_GET = ['lf' => ['path' => ['select', 'autocomplete'], 'ip' => ['203.0.113.9']]];
        $view = new Indexes($cfg, lh_sec_gateway($captured));
        $fqs = lh_sec_call($view, 'logFqs');
        $_GET = [];

        lh_same(3, count($fqs), 'the date filter plus one per field');
        lh_contains($fqs[1], 'path:("select" OR "autocomplete")', 'values within a field are OR-ed');
        lh_contains($fqs[2], 'ip:("203.0.113.9")', 'a second field is its own filter, so they AND');
    },

    'a value full of Lucene syntax arrives as a literal' => function (): void {
        $cfg = lh_sec_config();
        $captured = [];
        $hostile = '" OR http_status:500 OR path:"';
        $_GET = ['lf' => ['path' => [$hostile]]];
        $view = new Indexes($cfg, lh_sec_gateway($captured));
        $fqs = lh_sec_call($view, 'logFqs');
        $_GET = [];

        foreach ($fqs as $fq) {
            OpensolrLog::assertSafeFq($fq);
        }
        lh_false(
            (bool) preg_match('/path:\(\s*"\s*" OR http_status/', implode(' ', $fqs)),
            'the quote did not terminate the term'
        );
        lh_contains($fqs[1], '\\"', 'the quote was escaped rather than passed');
    },

    'a value the blunt filter check would refuse is dropped, not thrown on' => function (): void {
        $cfg = lh_sec_config();
        $captured = [];

        /* OpensolrLog::assertSafeFq() refuses these ANYWHERE in a filter, quoted or not, and it
           refuses by throwing — so a crafted query string would take the whole JSON endpoint
           down with a 500 rather than ignore a filter the UI never produced. They are dropped
           at the reading boundary instead, on exactly the grounds that check uses. */
        foreach ([
            "1.2.3.4\nwt=xml",
            "1.2.3.4\x00",
            '{!frange l=0}',
            '_query_:x',
            '_val_:x',
            '',
        ] as $hostile) {
            $_GET = ['lf' => ['ip' => [$hostile]]];
            $view = new Indexes($cfg, lh_sec_gateway($captured));
            $filters = lh_sec_call($view, 'logFilters');
            $fqs = lh_sec_call($view, 'logFqs');
            $_GET = [];

            lh_same([], $filters, 'the value was dropped: ' . lh_show($hostile));
            lh_same(1, count($fqs), 'so only the date filter is sent');
            foreach ($fqs as $fq) {
                OpensolrLog::assertSafeFq($fq);
            }
        }

        /* And a value that is merely awkward — quotes, ampersands, Lucene operators — is still
           carried, because quoting is what makes it a literal. */
        $_GET = ['lf' => ['ip' => ['1.2.3.4" OR x&wt=xml']]];
        $view = new Indexes($cfg, lh_sec_gateway($captured));
        $fqs = lh_sec_call($view, 'logFqs');
        $_GET = [];

        lh_same(2, count($fqs), 'an awkward value is not a refused one');
        OpensolrLog::assertSafeFq($fqs[1]);
    },

    'only the three named outcome slices are accepted' => function (): void {
        $cfg = lh_sec_config();
        $captured = [];

        foreach (['zero' => 'hits:[0 TO 0]', 'found' => 'hits:[1 TO *]', 'slow' => 'qtime:['] as $key => $expect) {
            $_GET = ['outcome' => $key];
            $view = new Indexes($cfg, lh_sec_gateway($captured));
            $fqs = lh_sec_call($view, 'logFqs');
            $_GET = [];

            lh_same(2, count($fqs), $key . ': the date filter plus the slice');
            lh_contains($fqs[1], $expect, $key . ' builds its own range filter');
        }

        foreach (['', 'everything', 'hits:[0 TO 0]', '../x'] as $bogus) {
            $_GET = ['outcome' => $bogus];
            $view = new Indexes($cfg, lh_sec_gateway($captured));
            $fqs = lh_sec_call($view, 'logFqs');
            $_GET = [];

            lh_same(1, count($fqs), 'an unknown slice adds nothing at all');
        }
    },

    'the sidebar filters are reported as ignored and never applied here' => function (): void {
        $cfg = lh_sec_config();
        $captured = [];
        $_GET = ['f' => ['country_s' => ['DE'], 'bot_verdict_s' => ['bot']]];
        $view = new Indexes($cfg, lh_sec_gateway($captured));
        $ignored = lh_sec_call($view, 'ignoredSidebarFilters');
        $fqs = lh_sec_call($view, 'logFqs');
        $_GET = [];

        lh_same(2, count($ignored), 'both sidebar filters are named as ignored');
        lh_same(1, count($fqs), 'and neither one reached a platform filter');
        foreach ($fqs as $fq) {
            lh_false(str_contains($fq, 'country_s'), 'a field the analytics schema lacks is not sent');
            lh_false(str_contains($fq, 'bot_verdict_s'), 'a verdict is not a request-log field');
        }
    },

    /* -----------------------------------------------------------------------------
     * Packing filters into a job, which is the one place they leave the request
     * -------------------------------------------------------------------------- */

    /* THE SCAN CRASH. A scan on the query-analysis view is started and polled by POST to the
       bare view URL, so it carries its filters in the body as the packed string the server
       itself minted. Queries::postedFilters() decoded that string and re-encoded it with its
       OWN encoder — written against the older shape of a selection, a flat list of values,
       and never updated when the operator moved inside it. It handed rawurlencode() an array,
       PHP 8.1 threw a TypeError, and the front controller turned that into a blank 500. Every
       scan on that view with any log filter active died on the first POST.

       Surviving the call would not have been much better: the second encoder had no operator
       in its output at all, so a "None of" filter would have come back as "Any of" and the
       scan would have read the complement of what the chips on screen said. */
    'a scan re-encodes its posted filters through the one encoder, operator included'
        => function (): void {
            $cfg = lh_sec_config();
            $captured = [];
            $_GET = ['lf' => ['path' => ['op' => 'none', '/select', '/admin']]];
            $view = new Indexes($cfg, lh_sec_gateway($captured));
            $packed = lh_sec_call($view, 'encodeLogFilters');
            $_GET = [];

            lh_contains($packed, 'none:', 'the minted form carries the operator');

            $_POST = ['lf' => $packed];
            $posted = (new ReflectionMethod(Queries::class, 'postedFilters'))->invoke(null);
            $_POST = [];

            lh_same(
                $packed,
                $posted,
                'the re-encode is a no-op on a string the server minted; anything else is two encoders'
            );

            $back = (new ReflectionMethod(Queries::class, 'decodeLogFilters'))->invoke(null, $posted);
            lh_same(
                ['path' => ['values' => ['/select', '/admin'], 'op' => 'none']],
                $back,
                'and "none of" must not come back as "any of" — that is the complement of the question'
            );
        },

    'the packed form a job carries can never be built by more than one encoder'
        => function (): void {
            $bodies = [
                (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Queries.php'),
                (string) file_get_contents(dirname(__DIR__) . '/src/Panel/OpensolrView.php'),
            ];

            $encoders = 0;
            foreach ($bodies as $body) {
                $encoders += preg_match_all('/array_map\(\s*.rawurlencode./', $body);
            }

            lh_same(
                1,
                $encoders,
                'two value encoders in the packing layer is how the two shapes drifted apart'
            );
        },

    'a packed filter set survives a round trip with its separators intact' => function (): void {
        $cfg = lh_sec_config();
        $captured = [];
        $_GET = ['lf' => ['path' => ['/se;lect,odd', 'plain'], 'ip' => ['203.0.113.9']]];
        $view = new Indexes($cfg, lh_sec_gateway($captured));
        $packed = lh_sec_call($view, 'encodeLogFilters');
        $_GET = [];

        $back = (new ReflectionMethod(Indexes::class, 'decodeLogFilters'))->invoke(null, $packed);

        lh_same(
            [
                'path' => ['values' => ['/se;lect,odd', 'plain'], 'op' => 'any'],
                'ip'   => ['values' => ['203.0.113.9'], 'op' => 'any'],
            ],
            $back,
            'a value containing both separators cannot split the string it travels in'
        );
        lh_true(strlen($packed) <= 256, 'the packed form fits a job parameter');
    },

    'decoding a stored filter set re-validates every part of it' => function (): void {
        $decode = static fn (string $s): array =>
            (new ReflectionMethod(Indexes::class, 'decodeLogFilters'))->invoke(null, $s);

        lh_same([], $decode(''), 'an empty string is no filters');
        lh_same([], $decode('bot_verdict_s=bot'), 'a field that is not on the allowlist is dropped');
        lh_same([], $decode('nonsense'), 'a fragment with no separator is dropped');
        lh_same(
            ['ip' => ['values' => ['1.2.3.4'], 'op' => 'any']],
            $decode('evil=x;ip=1.2.3.4'),
            'a good field survives a bad neighbour, and an unmarked set means "any of"'
        );
        lh_same(
            ['path' => ['values' => ['/select'], 'op' => 'none']],
            $decode('path=none:' . rawurlencode('/select')),
            'a resumed scan must rebuild the OPERATOR too, or it answers the opposite question'
        );
        lh_same(
            ['path' => ['values' => ['weird:thing'], 'op' => 'any']],
            $decode('path=' . rawurlencode('weird:thing')),
            'a colon inside a value is not an operator marker'
        );
        lh_same(
            [],
            $decode('ip=' . rawurlencode("1.2.3.4\nwt=xml")),
            'a stored value with a control character is dropped whole, never stitched back together'
        );
        lh_same(
            ['ip' => ['values' => ['1.2.3.4'], 'op' => 'any']],
            $decode('ip=' . rawurlencode("1.2.3.4\nwt=xml") . ',1.2.3.4'),
            'and its neighbours still survive'
        );
        lh_same(
            20,
            count($decode('path=' . implode(',', array_map('strval', range(1, 60))))['path']['values']),
            'the number of values is capped exactly as it is on the way in'
        );
    },

    'a scan carries the filters it was started with into every step' => function (): void {
        $cfg = lh_sec_config();
        $captured = [];
        $view = new Queries($cfg, lh_sec_gateway($captured));

        $platform = [];
        $view->setLogClient(lh_sec_client(lh_sec_empty_body(), $platform));

        lh_sec_call($view, 'scanStep', [
            ['core' => 'lh_index', 'range' => '24h', 'lf' => 'path=select', 'outcome' => 'slow'],
            0,
            false,
        ]);

        lh_same(1, count($platform), 'the step read the request log once');
        $url = urldecode((string) $platform[0]['url']);
        lh_contains($url, 'path:("select")', 'the stored filter was rebuilt and sent');
        lh_contains($url, 'qtime:[100 TO *]', 'so was the stored outcome slice');
    },

    'the zero-result scan reads zero-result requests whatever slice is selected' => function (): void {
        $cfg = lh_sec_config();
        $captured = [];
        $view = new Queries($cfg, lh_sec_gateway($captured));

        $platform = [];
        $view->setLogClient(lh_sec_client(lh_sec_empty_body(), $platform));

        lh_sec_call($view, 'scanStep', [
            ['core' => 'lh_index', 'range' => '24h', 'lf' => '', 'outcome' => 'found'],
            0,
            true,
        ]);

        $url = urldecode((string) $platform[0]['url']);
        lh_contains($url, 'hits:[0 TO 0]', 'the empty scan is always about the empties');
        lh_false(str_contains($url, 'hits:[1 TO *]'), 'and never contradicts itself with the other slice');
    },

    'a stored filter set cannot smuggle a field or a parser switch into a scan' => function (): void {
        $cfg = lh_sec_config();
        $captured = [];
        $view = new Queries($cfg, lh_sec_gateway($captured));

        $platform = [];
        $view->setLogClient(lh_sec_client(lh_sec_empty_body(), $platform));

        lh_sec_call($view, 'scanStep', [
            [
                'core'    => 'lh_index',
                'range'   => '24h',
                'lf'      => 'full_request=x;password=y;path=' . rawurlencode('{!frange l=0}'),
                'outcome' => 'nonsense',
            ],
            0,
            false,
        ]);

        lh_same(1, count($platform), 'the step still ran rather than failing the whole scan');
        $url = urldecode((string) $platform[0]['url']);
        lh_false(str_contains($url, 'full_request:'), 'a field not on the filter allowlist was dropped');
        lh_false(str_contains($url, 'password'), 'so was an invented one');
        lh_false(str_contains($url, 'frange'), 'and so was a value carrying a parser switch');
        lh_false(str_contains($url, 'path:'), 'that field ends up with no filter at all rather than a bad one');
        lh_false(str_contains($url, 'qtime:['), 'an unknown outcome adds no slice');
    },

    /* -----------------------------------------------------------------------------
     * The URL the range picker builds
     * -------------------------------------------------------------------------- */

    'switching the time range keeps the index, the filters and the slice' => function (): void {
        $_GET = [
            'lf'      => ['path' => ['select'], 'made_up' => ['x']],
            'f'       => ['country_s' => ['DE']],
            'outcome' => 'zero',
            'core'    => 'my_index',
            'rows'    => '9999',
        ];
        $url = Layout::urlWith(['v' => 'indexes', 'range' => '7d']);
        $_GET = [];

        $decoded = urldecode($url);
        lh_contains($decoded, 'core=my_index', 'the selected index survives');
        lh_contains($decoded, 'lf[path][0]=select', 'the request-log filter survives');
        lh_contains($decoded, 'outcome=zero', 'the outcome slice survives');
        lh_contains($decoded, 'f[country_s][0]=DE', 'the sidebar filter still travels for the other views');
        lh_contains($decoded, 'range=7d', 'the new range is applied');
        lh_false(str_contains($decoded, 'made_up'), 'a filter field that does not exist is not carried');
        lh_false(str_contains($decoded, 'rows'), 'nothing unexpected survives a navigation');
    },

    'a malformed index name or slice is not carried into the next URL' => function (): void {
        foreach ([
            ['core' => '../other/select?'],
            ['core' => ''],
            ['outcome' => 'DROP TABLE'],
            ['outcome' => 'hits:[0 TO 0]'],
        ] as $bad) {
            $_GET = $bad;
            $url = urldecode(Layout::urlWith(['v' => 'indexes']));
            $_GET = [];

            foreach ($bad as $key => $value) {
                lh_false(str_contains($url, $key . '='), $key . '=' . $value . ' was refused');
            }
        }
    },

    /* -----------------------------------------------------------------------------
     * An empty platform answer is a rendered state, not a broken chart
     * -------------------------------------------------------------------------- */

    'the filter facets survive an answer with no facets at all' => function (): void {
        $cfg = lh_sec_config();
        $captured = [];
        $view = new Indexes($cfg, lh_sec_gateway($captured));

        $platform = [];
        $view->setLogClient(lh_sec_client(lh_sec_empty_body(), $platform));

        $_GET = ['core' => 'lh_index'];
        $out = $view->api('facets');
        $_GET = [];

        lh_same('ok', $out['state'], 'an empty answer is a successful one');
        lh_same(0, $out['requests'], 'no requests are invented');
        lh_same([], $out['groups'], 'and no facet groups either');
        lh_has_key($out, 'outcomes', 'the outcome counters are present even when empty');
        lh_has_key($out, 'active', 'so is the active filter set the front end renders chips from');
    },

    'the volume chart survives an answer with no time buckets' => function (): void {
        $cfg = lh_sec_config();
        $captured = [];
        $view = new Indexes($cfg, lh_sec_gateway($captured));

        $platform = [];
        $view->setLogClient(lh_sec_client(lh_sec_empty_body(), $platform));

        $_GET = ['core' => 'lh_index'];
        $out = $view->api('volume');
        $_GET = [];

        lh_same([], $out['times'], 'no buckets rather than a broken axis');
        lh_same([], $out['all'], 'and no series to draw');
        lh_true($out['zero_known'], 'with no slice selected the zero series is meaningful');
    },

    'an outcome slice costs one call instead of two' => function (): void {
        $cfg = lh_sec_config();
        $captured = [];

        $view = new Indexes($cfg, lh_sec_gateway($captured));
        $plain = [];
        $view->setLogClient(lh_sec_client(lh_sec_empty_body(), $plain));
        $_GET = ['core' => 'lh_index'];
        $view->api('volume');
        $_GET = [];

        $sliced = new Indexes($cfg, lh_sec_gateway($captured));
        $slicedCalls = [];
        $sliced->setLogClient(lh_sec_client(lh_sec_empty_body(), $slicedCalls));
        $_GET = ['core' => 'lh_index', 'outcome' => 'found'];
        $out = $sliced->api('volume');
        $_GET = [];

        lh_false($out['zero_known'], 'the zero series is declared unavailable rather than drawn as zeroes');
        lh_true(
            count($slicedCalls) < count($plain),
            'and the second call is not made: it would be empty by construction'
        );
    },

    /* -----------------------------------------------------------------------------
     * The API key
     * -------------------------------------------------------------------------- */

    'the packed filter string carries no credential' => function (): void {
        $cfg = lh_sec_config();
        $captured = [];
        $_GET = ['lf' => ['path' => ['select']], 'outcome' => 'zero'];
        $view = new Indexes($cfg, lh_sec_gateway($captured));
        $packed = lh_sec_call($view, 'encodeLogFilters');
        $_GET = [];

        lh_false(str_contains($packed, LH_SEC_KEY), 'no key in the packed filters');
        lh_false(str_contains($packed, 'owner@example.com'), 'no account email either');
    },

    'no filter or volume payload carries the API key' => function (): void {
        $cfg = lh_sec_config();
        $captured = [];

        foreach ([Indexes::class, Queries::class, Callers::class] as $class) {
            $view = new $class($cfg, lh_sec_gateway($captured));
            $platform = [];
            $view->setLogClient(lh_sec_client(lh_sec_empty_body(), $platform));

            $_GET = ['core' => 'lh_index', 'lf' => ['path' => ['select']]];
            foreach (['facets', 'volume', 'indexes'] as $action) {
                $payload = (string) json_encode($view->api($action));
                if (str_contains($payload, LH_SEC_KEY)) {
                    lh_fail($class . '::' . $action . ' put the API key in a JSON payload');
                }
            }
            $_GET = [];
        }
    },

    'the filter markup carries nothing the CSP forbids' => function (): void {
        foreach (lh_sec_views() as $view) {
            $html = lh_sec_body($view);

            if (preg_match('/<script/i', $html)) {
                lh_fail($view->slug() . ' emitted a script element, which the CSP forbids');
            }
            if (preg_match('/\son[a-z]+\s*=/i', $html)) {
                lh_fail($view->slug() . ' emitted an inline event handler, which the CSP forbids');
            }
            if (preg_match('/javascript:/i', $html)) {
                lh_fail($view->slug() . ' emitted a javascript: URL');
            }
            if (str_contains($html, LH_SEC_KEY)) {
                lh_fail($view->slug() . ' rendered the API key');
            }
        }
    },

    /* -----------------------------------------------------------------------------
     * The front end
     * -------------------------------------------------------------------------- */

    'the filter and nav modules build DOM rather than markup' => function (): void {
        foreach ([
            '/../public/assets/js/sectionnav.js',
            '/../public/assets/js/views/opensolr.js',
            '/../public/assets/js/views/indexes.js',
            '/../public/assets/js/views/queries.js',
            '/../public/assets/js/views/callers.js',
        ] as $rel) {
            $path = __DIR__ . $rel;
            if (!is_file($path)) {
                lh_fail('missing module: ' . $rel);
            }
            $source = (string) file_get_contents($path);
            $name = basename($path);

            if (str_contains($source, 'innerHTML')) {
                lh_fail($name . ' assigns innerHTML; DOM must be built with textContent');
            }
            if (preg_match('/\bhtml:\s/', $source)) {
                lh_fail($name . ' uses the el() html attribute, which bypasses textContent');
            }
            if (str_contains($source, 'eval(') || str_contains($source, 'new Function')) {
                lh_fail($name . ' uses dynamic evaluation, which the CSP forbids');
            }
        }
    },

    'the stylesheet derives the jump offset instead of guessing it' => function (): void {
        $css = (string) file_get_contents(__DIR__ . '/../public/assets/css/panel.css');

        lh_contains($css, '--set-nav-h', 'the bar publishes its height as a custom property');
        lh_contains($css, 'scroll-margin-top: calc(var(--set-nav-h)', 'and the jump offset is derived from it');
        lh_contains($css, 'flex-wrap: nowrap', 'the bar is one row');
        lh_contains($css, 'overflow-x: auto', 'and scrolls sideways rather than taking a second line');

        if (preg_match('/\.card\[id\^="set-"\]\s*\{[^}]*scroll-margin-top:\s*\d+px/', $css)) {
            lh_fail('the jump offset is still a hardcoded pixel guess');
        }

        /* Measured on the Settings page: one unbalanced <div> in a view makes the parser close
           `.view` early, and every card after it becomes a SIBLING of `.view`. A descendant
           selector then matches nothing and every jump lands its heading under the bar, which
           is exactly the bug this whole rule exists to prevent. The offset is a property of
           being a card, not of where the parser thinks the card ended up. */
        if (preg_match('/\.view\s+\.card\s*\{[^}]*scroll-margin-top/', $css)) {
            lh_fail('the jump offset is scoped to .view, so it stops applying after any unbalanced div');
        }

        $module = (string) file_get_contents(__DIR__ . '/../public/assets/js/sectionnav.js');
        lh_contains($module, "setProperty('--set-nav-h'", 'and the real height is measured and published');
    },

    'the nav module is loaded on every page' => function (): void {
        $layout = (string) file_get_contents(__DIR__ . '/../src/Panel/Layout.php');
        lh_contains($layout, 'assets/js/sectionnav.js', 'Layout loads the section-nav module');
        lh_contains($layout, 'self::sectionNav($view, $body)', 'and renders the bar before the page head');
    },
];
