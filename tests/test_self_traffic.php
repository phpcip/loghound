<?php
/**
 * Loghound — tests for the exclusion of Loghound's own instrumentation.
 *
 * THE DEFECT THESE PIN. Overview's Top pages facets `paths_ss` on the session document, and
 * `paths_ss` was the one place in the session aggregate that was never kind-filtered — so every
 * request the beacon made to `/b.js` and `/collect.php` was counted as a path a visitor had
 * asked for, and both sat near the top of the card, ranked among the site's real pages.
 *
 * A query-side fix is impossible: `paths_ss` is multi-valued, an `fq` selects DOCUMENTS, and a
 * terms facet on a multi-valued field enumerates every value of every matching document. So the
 * fix is on the write path, and these tests hold it in place.
 *
 * WHAT IS DELIBERATELY ASSERTED, and each of these is a way the fix could go wrong:
 *
 *   - the match is host AND path, never path alone. A measured site is entitled to its own
 *     /collect.php, and deleting somebody's real page from their own analytics would be a worse
 *     defect than the double-count being fixed.
 *   - the endpoints come from `base_url`, prefix and all, rather than from the bare filenames.
 *   - the exclusion reaches `paths` and leaves `pages` alone.
 *   - the evidence of a beacon is the STAGED ROW, not the log line, so excluding the log line
 *     cannot take `beacon_b` with it.
 *   - `no_assets` does not newly fire on a visitor whose only sub-resource was our own script.
 *   - the per-source opt-out stops a file being read at all.
 *
 * NO NETWORK, NO FIXTURE FILE. The hits are produced by the REAL src/Parser.php from real
 * `combined` lines and folded by the REAL src/Sessionizer.php over the REAL src/State.php on a
 * throwaway database — two sources with two different vhosts, which is the arrangement that
 * produces the defect and the one a fixture file cannot express (a `combined` line carries no
 * %v, so one file is one host).
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';
require_once __DIR__ . '/support/LogFixtures.php';

use Loghound\Beacon;
use Loghound\Config;
use Loghound\LogDetect;
use Loghound\Parser;
use Loghound\Score\Rules;
use Loghound\Score\Signals;
use Loghound\Sessionizer;
use Loghound\Tests\TempState;

/** The panel's public URL used throughout this file. */
const LH_SELF_BASE = 'https://loghound.example.com';

/** One User-Agent for every line here, so every hit shares a client key. */
const LH_SELF_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
    . '(KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36';

/**
 * A parser configured as bin/loghound-tail configures it, pointed at one source's vhost.
 *
 * @param string $baseUrl The panel's own URL, or '' for an installation before setup.
 */
function lh_self_parser(string $sourceHost, string $baseUrl = LH_SELF_BASE): Parser
{
    $own = Config::selfEndpoints($baseUrl);

    $parser = new Parser([
        'keep_raw'  => false,
        'own_host'  => (string) $own['host'],
        'own_paths' => (array) $own['paths'],
    ]);
    $parser->setSourceHost($sourceHost);

    return $parser;
}

/**
 * Normalise one `combined` line through the real parser.
 *
 * @return array<string,mixed>|null
 */
function lh_self_hit(Parser $parser, string $method, string $target, string $time, int $status = 200, int $bytes = 500): ?array
{
    static $offset = 0;

    $line = '203.0.113.7 - - [10/Sep/2026:' . $time . ' +0000] "' . $method . ' ' . $target
        . ' HTTP/1.1" ' . $status . ' ' . $bytes . ' "-" "' . LH_SELF_UA . '"';

    return $parser->parseLine(
        LogDetect::formatByName('apache_combined'),
        $line,
        '/var/log/apache2/access.log',
        $offset++
    );
}

/**
 * One visit to a measured site, instrumented by a Loghound on its own vhost.
 *
 * Two sources, one client. The site's own log gives three requests — a page, its stylesheet and
 * a second page ten seconds later. The panel's log gives the beacon script and two collector
 * posts, which the browser made in the middle of that visit and which share the client key, so
 * they land in the same session. Returned in the order the two tailers would have produced
 * them, which is the order their timestamps put them in.
 *
 * @return array{sessions:array<int,array<string,mixed>>,hits:array<int,array<string,mixed>>}
 */
function lh_self_visit(string $baseUrl = LH_SELF_BASE): array
{
    $site  = lh_self_parser('example.com', $baseUrl);
    $panel = lh_self_parser('loghound.example.com', $baseUrl);

    $lines = [
        lh_self_hit($site, 'GET', '/', '09:00:00', 200, 9000),
        lh_self_hit($panel, 'GET', '/b.js?v=1', '09:00:01', 200, 4000),
        lh_self_hit($site, 'GET', '/app.css', '09:00:02', 200, 2000),
        lh_self_hit($panel, 'POST', '/collect.php', '09:00:04', 204, 0),
        lh_self_hit($site, 'GET', '/pricing', '09:00:10', 200, 8000),
        lh_self_hit($panel, 'POST', '/collect.php', '09:00:19', 204, 0),
    ];

    $temp        = new TempState();
    $sessionizer = new Sessionizer($temp->state(), ['base_url' => $baseUrl]);

    $hits = [];
    foreach ($lines as $line) {
        if (!is_array($line)) {
            throw new RuntimeException('a fixture line did not parse');
        }
        $hits[] = $sessionizer->assign($line);
    }

    return ['sessions' => $sessionizer->closeAll(), 'hits' => $hits];
}

/**
 * The session signal map for a shape built by hand, with the identity fields a rule needs.
 *
 * @param array<string,mixed> $session
 * @return array<string,mixed>
 */
function lh_self_signals(array $session): array
{
    return Signals::fromSession($session + [
        'session_id' => 'sess-self',
        'first'      => ['ua_s' => LH_SELF_UA, 'ua_hash_s' => sha1(LH_SELF_UA)],
    ]);
}

return [

    /* ============================================================================== *
     * Which requests are ours
     * ============================================================================== */

    'a measured site\'s own /collect.php stays its own, and only our host makes one ours' =>
        function (): void {
            $own   = Config::selfEndpoints(LH_SELF_BASE);
            $paths = (array) $own['paths'];
            $host  = (string) $own['host'];

            lh_same('loghound.example.com', $host, 'own host');

            lh_false(
                Parser::isOwnRequest('example.com', '/collect.php', $host, $paths),
                'a measured site running its own /collect.php must keep it'
            );
            lh_false(
                Parser::isOwnRequest('example.com', '/b.js', $host, $paths),
                'a measured site is allowed a /b.js of its own too'
            );

            lh_true(
                Parser::isOwnRequest('loghound.example.com', '/collect.php', $host, $paths),
                'the collector on our own host is ours'
            );
            lh_true(
                Parser::isOwnRequest('loghound.example.com', '/b.js', $host, $paths),
                'the script on our own host is ours'
            );

            lh_true(
                Parser::isOwnRequest('LOGHOUND.EXAMPLE.COM:443', '/B.js', $host, $paths),
                'case and an explicit port must not decide this'
            );

            lh_false(
                Parser::isOwnRequest('loghound.example.com', '/index.php', $host, $paths),
                'the panel\'s own pages are pages, not instrumentation'
            );
            lh_false(
                Parser::isOwnRequest(null, '/collect.php', $host, $paths),
                'a hit whose host is unknown can never be proven to be ours'
            );

            lh_false(
                Parser::isOwnRequest('loghound.example.com', '/collect.php', '', $paths),
                'before setup there is no own host, so nothing is ours'
            );
        },

    'the endpoints are derived from base_url, path prefix and all' => function (): void {
        $plain = Config::selfEndpoints('https://loghound.example.com');
        lh_same('loghound.example.com', $plain['host'], 'host');
        lh_same('/b.js', $plain['script'], 'script');
        lh_same('/collect.php', $plain['collector'], 'collector');
        lh_same(['/b.js', '/collect.php'], $plain['paths'], 'paths');

        $prefixed = Config::selfEndpoints('https://example.com/loghound/');
        lh_same('example.com', $prefixed['host'], 'host under a prefix');
        lh_same(
            ['/loghound/b.js', '/loghound/collect.php'],
            $prefixed['paths'],
            'the endpoints sit under the prefix the script tag points at'
        );

        $ported = Config::selfEndpoints('http://loghound.example.com:8443');
        lh_same('loghound.example.com', $ported['host'], 'the port is not part of the hostname');

        $none = Config::selfEndpoints('');
        lh_same('', $none['host'], 'no base_url, no own host');
        lh_same([], $none['paths'], 'no base_url, nothing to exclude');
    },

    /* ============================================================================== *
     * The parser
     * ============================================================================== */

    'the parser marks our own requests, and marks them only on our own host' => function (): void {
        $panel = lh_self_parser('loghound.example.com');
        $hit = lh_self_hit($panel, 'POST', '/collect.php', '10:00:00', 204, 0);
        lh_true(is_array($hit), 'hit');
        lh_same(true, $hit['_self_b'] ?? null, '_self_b on our own collector');
        lh_same('beacon', $hit['kind_s'], 'the collector is still classified as a beacon');

        $script = lh_self_hit($panel, 'GET', '/b.js?v=1789', '10:00:01');
        lh_same(true, $script['_self_b'] ?? null, '_self_b on our own script');
        lh_same('asset', $script['kind_s'], 'the script is still classified as an asset');
        lh_same('js', $script['asset_kind_s'], 'and still as javascript');

        $site = lh_self_parser('example.com');
        $theirs = lh_self_hit($site, 'POST', '/collect.php', '10:00:02', 204, 0);
        lh_no_key($theirs, '_self_b', 'another site\'s collector');
        lh_same('beacon', $theirs['kind_s'], 'still a beacon by kind, just not ours');
    },

    'the parser honours the configured endpoint, not the hardcoded beacon path list' =>
        function (): void {
            $prefixed = lh_self_parser('loghound.example.com', 'https://loghound.example.com/lh');

            $configured = lh_self_hit($prefixed, 'POST', '/lh/collect.php', '11:00:00', 204, 0);
            lh_same(true, $configured['_self_b'] ?? null, 'the endpoint base_url actually points at');

            $hardcoded = lh_self_hit($prefixed, 'POST', '/collect.php', '11:00:01', 204, 0);
            lh_same(
                'beacon',
                $hardcoded['kind_s'],
                'a path in the hardcoded beacon_paths list is still classified as a beacon'
            );
            lh_no_key(
                $hardcoded,
                '_self_b',
                'but this installation serves no collector there, and classification is not '
                . 'ownership — reading the hardcoded list as "ours" is the mistake that deletes '
                . 'a real page from a real site\'s analytics'
            );

            $unset = lh_self_parser('loghound.example.com', '');
            $before = lh_self_hit($unset, 'POST', '/collect.php', '11:00:02', 204, 0);
            lh_no_key($before, '_self_b', 'an installation with no base_url claims nothing');
        },

    /* ============================================================================== *
     * The session aggregate
     * ============================================================================== */

    'the session path set drops our own beacon and script, and the page count does not move' =>
        function (): void {
            $visit = lh_self_visit();
            lh_same(1, count($visit['sessions']), 'one client, one session');

            $session = $visit['sessions'][0];

            lh_same(
                ['/', '/app.css', '/pricing'],
                $session['paths'],
                'paths_ss must carry the site\'s paths and nothing of ours'
            );
            lh_same(3, $session['uniq_paths'], 'uniq_paths_i counts the same population');

            lh_same(2, $session['pages'], 'pages_i is untouched: two real pageviews');
            lh_same('/', $session['entry_path'], 'entry path');
            lh_same('/pricing', $session['exit_path'], 'exit path');
        },

    'every counter a person reads agrees about what was excluded' => function (): void {
        $session = lh_self_visit()['sessions'][0];

        lh_same(3, $session['hits'], 'hits_i counts the site\'s requests only');
        lh_same(1, $session['assets'], 'assets_i does not count our script');
        lh_same(0, $session['favicons'], 'no favicon was fetched');
        lh_same(1, $session['sub_resources'], 'sub-resources is the stylesheet alone');
        lh_same(0, $session['beacons'], 'our own collector is not the site\'s beacon traffic');
        lh_same(19000, $session['bytes'], 'the byte total excludes ours: 9000 + 2000 + 8000');

        lh_same(
            round(1 / 3, 4),
            $session['asset_ratio'],
            'asset_ratio_f divides one sub-resource by three hits, not by six'
        );

        lh_same(3, $session['st2'], 'the status classes count the same three requests');

        lh_same(3, $session['own_hits'], 'ours are counted apart: script plus two collector posts');
        lh_same(1, $session['own_assets'], 'one of ours was a sub-resource, the script');
    },

    'the inter-request gaps are measured between the site\'s own requests' => function (): void {
        $session = lh_self_visit()['sessions'][0];

        lh_same(
            [2000, 8000],
            $session['gaps'],
            '/ at 09:00:00, /app.css at 09:00:02, /pricing at 09:00:10, and our collector post '
            . 'at 09:00:04 sitting between the last two: measuring from that would report a '
            . '6-second gap and replace the site\'s request rhythm with our heartbeat interval'
        );
    },

    'our own request keeps its session, and never invents one' => function (): void {
        $visit = lh_self_visit();

        $script = $visit['hits'][1];
        lh_same('/b.js', $script['path_s'], 'the second line is our script');
        lh_true(isset($script['session_id_s']), 'it is still attributed to the visit it belongs to');
        lh_no_key($script, 'session_seq_i', 'but it holds no position among the counted hits');

        $temp        = new TempState();
        $sessionizer = new Sessionizer($temp->state(), ['base_url' => LH_SELF_BASE]);
        $panel       = lh_self_parser('loghound.example.com');

        $alone = $sessionizer->assign(lh_self_hit($panel, 'POST', '/collect.php', '12:00:00', 204, 0));
        lh_no_key(
            $alone,
            'session_id_s',
            'the same request with nothing open must open nothing: a session built out of '
            . 'instrumentation alone would carry hits_i 0 and no entry path, which is inventing '
            . 'a visit out of the act of measuring one'
        );
        lh_same([], $sessionizer->closeAll(), 'and leaves no session behind');
    },

    'a hit that never met the parser is classified and excluded just the same' => function (): void {
        $temp        = new TempState();
        $sessionizer = new Sessionizer($temp->state(), ['base_url' => LH_SELF_BASE]);

        $base = [
            'ip_s' => '203.0.113.8', 'ip_net_s' => '203.0.113.0/24',
            'ua_s' => LH_SELF_UA, 'ua_hash_s' => sha1(LH_SELF_UA),
            'status_i' => 200,
        ];

        $sessionizer->assign($base + [
            '_ts_unix' => 1_789_034_000, 'host_s' => 'example.com', 'path_s' => '/',
        ]);
        $sessionizer->assign($base + [
            '_ts_unix' => 1_789_034_002, 'host_s' => 'loghound.example.com', 'path_s' => '/collect.php',
        ]);

        $session = $sessionizer->closeAll()[0];

        lh_same(['/'], $session['paths'], 'the collector never reaches the path set');
        lh_same(1, $session['pages'], 'and is never counted as a pageview either');
        lh_same(1, $session['own_hits'], 'it is counted as ours instead');
    },

    /* ============================================================================== *
     * The beacon evidence survives the exclusion
     * ============================================================================== */

    'a session with no collector line of its own still reports a beacon' => function (): void {
        $cfg = Config::load('/nonexistent/loghound-test-config.php');
        $cfg->set('beacon.secret', str_repeat('k', 48));
        $beacon = new Beacon($cfg);

        $session = ['id' => 'sess-self', 'hits_i' => 3];

        $none = $beacon->mergeIntoSession($session, []);
        lh_same(false, $none['beacon_b'], 'no staged rows: false, and present, never absent');

        $one = $beacon->mergeIntoSession($session, [[
            'id' => 1, 'pv' => 'a', 'wall_ms' => 4000, 'visible_ms' => 3500, 'engaged_ms' => 2000,
            'interactions' => 3, 'scroll_pct' => 40, 'signals' => '[]', 'ua_claim' => 1,
            'tz' => '', 'webgl' => '',
        ]]);
        lh_same(
            true,
            $one['beacon_b'],
            'beacon_b comes from rows the collector staged in SQLite, never from the '
            . '/collect.php access-log line, so one staged row is enough with no log line at all '
            . '— which is why excluding that line from the session is safe'
        );
        lh_same(true, $one['js_b'], 'and it still proves the script executed');
    },

    /* ============================================================================== *
     * The regression the exclusion would otherwise cause
     * ============================================================================== */

    'a visitor whose only sub-resource was our own script does not become a bot' => function (): void {
        $rules = new Rules([]);

        $markupOnly = lh_self_signals([
            'hits' => 1, 'pages' => 1, 'assets' => 0, 'favicons' => 0,
            'sub_resources' => 0, 'own_assets' => 0, 'html_200' => true,
        ]);
        lh_true(
            $rules->fired('no_assets', $markupOnly) !== null,
            'a client that really fetched nothing must still fire'
        );

        $ourScriptOnly = lh_self_signals([
            'hits' => 1, 'pages' => 1, 'assets' => 0, 'favicons' => 0,
            'sub_resources' => 0, 'own_assets' => 1, 'html_200' => true,
        ]);
        lh_same(
            null,
            $rules->fired('no_assets', $ourScriptOnly),
            'before the exclusion this session\'s /b.js counted as an asset and the rule stayed '
            . 'quiet; stopping that count without this guard hands 25 bot points to a visitor '
            . 'for doing exactly what our own script tag told their browser to do'
        );
    },

    'the real pipeline never scores a beacon-only visit as asset-less' => function (): void {
        $temp        = new TempState();
        $sessionizer = new Sessionizer($temp->state(), ['base_url' => LH_SELF_BASE]);

        $site  = lh_self_parser('example.com');
        $panel = lh_self_parser('loghound.example.com');

        $sessionizer->assign(lh_self_hit($site, 'GET', '/', '13:00:00', 200, 9000));
        $sessionizer->assign(lh_self_hit($panel, 'GET', '/b.js?v=1789', '13:00:01', 200, 4000));
        $sessionizer->assign(lh_self_hit($panel, 'POST', '/collect.php', '13:00:05', 204, 0));

        $session = $sessionizer->closeAll()[0];

        lh_same(0, $session['sub_resources'], 'the site itself served no sub-resource');
        lh_same(1, $session['own_assets'], 'but our script was fetched');
        lh_same(
            null,
            (new Rules([]))->fired('no_assets', Signals::fromSession($session)),
            'end to end, this visitor must not collect 25 bot points'
        );
    },

    /* ============================================================================== *
     * The per-source opt-out
     * ============================================================================== */

    'a source is read unless it says otherwise, and every spelling of no is honoured' =>
        function (): void {
            $path = ['path' => '/var/log/apache2/access.log', 'format' => 'apache_combined'];

            lh_true(Config::sourceEnabled($path), 'absent means enabled: no existing config changes');
            lh_true(Config::sourceEnabled($path + ['enabled' => true]), 'true');
            lh_true(Config::sourceEnabled($path + ['enabled' => 'true']), 'the string true');
            lh_true(Config::sourceEnabled($path + ['enabled' => 1]), 'one');

            lh_false(Config::sourceEnabled($path + ['enabled' => false]), 'false');
            lh_false(Config::sourceEnabled($path + ['enabled' => 'false']), 'the string false');
            lh_false(Config::sourceEnabled($path + ['enabled' => 'no']), 'no');
            lh_false(Config::sourceEnabled($path + ['enabled' => '0']), 'zero as a string');
            lh_false(Config::sourceEnabled($path + ['enabled' => 0]), 'zero');

            lh_true(
                Config::sourceEnabled($path + ['enabled' => 'maybe']),
                'a value that is not a boolean at all must not quietly disable the source; it is '
                . 'refused by validate() instead, because a log file nobody is reading is the '
                . 'most expensive misconfiguration this daemon can be handed'
            );
        },

    'a source switch that is not a boolean is refused rather than obeyed' => function (): void {
        $dir = lh_tmpdir('lh-src');
        $file = $dir . '/loghound.php';

        file_put_contents($file, "<?php return " . var_export([
            'allowed_log_roots' => [$dir],
            'sources' => [['path' => $dir . '/access.log', 'format' => 'apache_combined', 'enabled' => 'maybe']],
        ], true) . ";\n");

        $errors = Config::load($file)->validate();
        lh_rmtree($dir);

        $found = false;
        foreach ($errors as $error) {
            if (str_contains((string) $error, 'sources[0].enabled')) {
                $found = true;
            }
        }
        lh_true($found, 'validate() must name the source and the key: ' . implode(' | ', $errors));
    },

    'the daemon refuses a disabled source before it opens anything' => function (): void {
        $src = (string) file_get_contents(dirname(__DIR__) . '/bin/loghound-tail');

        $guard = strpos($src, 'Config::sourceEnabled(');
        lh_true($guard !== false, 'buildSources must consult Config::sourceEnabled()');

        $tail = strpos($src, 'new Tail(');
        lh_true($tail !== false, 'buildSources constructs a Tail');
        lh_true(
            $guard < $tail,
            'the switch must be tested before a Tail is constructed: a source opened and only '
            . 'then ignored would still advance its cursor and still be reported as ingesting, '
            . 'which is not what "not ingesting" means to the operator who set it'
        );

        $glob = strpos($src, '$matches = glob($pattern)');
        lh_true($glob !== false, 'buildSources expands the pattern');
        lh_true($guard < $glob, 'a disabled source must not even cost a filesystem sweep');
    },

    'the tailer tells the parser which site the line belongs to before it parses it' =>
        function (): void {
            $src = (string) file_get_contents(dirname(__DIR__) . '/bin/loghound-tail');

            $set = strpos($src, '$this->parser->setSourceHost(');
            $parse = strpos($src, '$this->parser->parseLine(');
            lh_true($set !== false, 'process() must hand the source host to the parser');
            lh_true($parse !== false, 'process() parses the line');
            lh_true($set < $parse, 'the vhost must be known while the parser can still act on it');

            lh_contains($src, "'own_host'", 'the parser is given this installation\'s own host');
            lh_contains($src, "'own_paths'", 'and its own endpoints');
            lh_contains($src, 'Config::selfEndpoints(', 'both derived from base_url, in one place');
        },

    'the shipped example configuration documents the opt-out' => function (): void {
        $example = (string) file_get_contents(dirname(__DIR__) . '/config/loghound.example.php');

        lh_contains($example, "'enabled' => false", 'the example must show the switch being used');
        lh_contains($example, 'Absent means enabled', 'and say that leaving it out changes nothing');
        lh_contains($example, 'base_url', 'and explain where the excluded endpoints come from');
    },
];
