<?php
/**
 * Loghound — tests for the standalone beacon and the search-term dimension.
 *
 * Two features that arrived together because they answer one need: measuring a site that runs on
 * a DIFFERENT MACHINE, with nothing installed there but the script tag, and seeing what the
 * visitors of that site searched for.
 *
 * Each has a way of going quietly wrong, and there is a layer of tests per way:
 *
 *  1. TRUST. The hostname a page reports is attacker-chosen. It counts for something only when
 *     the browser-set `Origin` agrees with it AND the operator listed it. Any other combination
 *     has to keep the behaviour the collector has always had — provisional id, merge-only,
 *     nothing recorded — because this feature must be additive rather than a loosening.
 *  2. HONESTY. A session with no access log behind it has no transport plane. Its log fields must
 *     be ABSENT rather than zero, the rules that read them must not fire, and the document must
 *     say which planes it had. A zero here is not neutral: `assets == 0` is an accusation.
 *  3. BOUNDING. A search term is a literal string somebody typed, stored and faceted. Every rule
 *     about a hostile string applies: charset, length, whitespace, and dropped-not-truncated.
 *     And it must not be collected at all unless configured, on either side of the wire.
 *  4. DUPLICATION. A host that gains a log source later must produce one session, not two, and a
 *     reconfiguration must not be able to rewrite history.
 *  5. MORE THAN ONE WRITER. A pair of indexes may be shared by several installations. Nothing
 *     may assume a single writer, and no two of them may mint the same document id.
 *
 * The collector and the scorer are executable scripts that run their pipeline on include, so
 * assertions about their wiring read the source. That is narrow on purpose: everything that can
 * be exercised behaviourally is exercised, and source reading is reserved for invariants that
 * live in the wiring rather than in a class.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Beacon;
use Loghound\Config;
use Loghound\Parser;
use Loghound\Score\Rules;
use Loghound\Score\Signals;
use Loghound\Security;
use Loghound\Sessionizer;

/**
 * The throwaway directory this file writes its configuration files into.
 *
 * One directory for the whole file, created on first use and removed at shutdown, so a run
 * leaves nothing in the temp directory however many configurations the tests build. Registered
 * once: lh_tmpdir() creates, and the caller is expected to tidy up after itself.
 */
function lh_sa_dir(): string
{
    static $dir = null;
    if ($dir === null) {
        $dir = lh_tmpdir('lh_sa');
        register_shutdown_function(static function () use ($dir): void {
            lh_rmtree($dir);
        });
    }
    return $dir;
}

/**
 * A Beacon built on a written-out config file, so no test depends on the shipped defaults.
 *
 * Config::load() is the only public way in, and going through it rather than around it means
 * these tests exercise the same merge-over-defaults path an installation does — a setting that
 * the defaults would swallow shows up here rather than in production.
 */
function lh_sa_beacon(array $beacon = []): Beacon
{
    $dir = lh_sa_dir();

    $path = $dir . '/cfg_' . md5(serialize($beacon)) . '.php';
    if (!is_file($path)) {
        $data = ['beacon' => $beacon + ['secret' => str_repeat('k', 48)]];
        file_put_contents($path, '<?php return ' . var_export($data, true) . ';');
    }

    return new Beacon(Config::load($path));
}

/** The collector source, read once. */
function lh_sa_collector(): string
{
    static $src = null;
    if ($src === null) {
        $src = (string) file_get_contents(__DIR__ . '/../public/collect.php');
    }
    return $src;
}

/** The scorer source, read once. */
function lh_sa_scorer(): string
{
    static $src = null;
    if ($src === null) {
        $src = (string) file_get_contents(__DIR__ . '/../bin/loghound-score');
    }
    return $src;
}

/** The beacon script source, read once. */
function lh_sa_bjs(): string
{
    static $src = null;
    if ($src === null) {
        $src = (string) file_get_contents(__DIR__ . '/../public/b.js');
    }
    return $src;
}

/** One of the two shipped schemas, read once. */
function lh_sa_schema(string $core): string
{
    static $cache = [];
    if (!isset($cache[$core])) {
        $cache[$core] = (string) file_get_contents(__DIR__ . '/../solr/' . $core . '/conf/managed-schema.xml');
    }
    return $cache[$core];
}

/**
 * Render the Settings card and hand back its HTML.
 *
 * Self-contained rather than reusing tests/test_panel.php's helpers: the runner requires each
 * test file separately, so depending on a function another file happens to define makes this
 * file's result depend on glob order. The transport returns canned JSON and nothing leaves the
 * machine.
 *
 * @param array<string,mixed> $beacon The `beacon` section to render against.
 */
function lh_sa_settings_html(array $beacon): string
{
    $path = lh_sa_dir() . '/panel_' . md5(serialize($beacon)) . '.php';
    if (!is_file($path)) {
        $data = [
            'base_url' => 'https://loghound.example.com',
            'solr' => [
                'mode' => 'self', 'base_url' => 'http://127.0.0.1:8983/solr',
                'hits_core' => 'lh_hits', 'sessions_core' => 'lh_sessions',
                'install_id' => 'abcd1234',
            ],
            'auth' => ['mode' => 'basic', 'user' => 'x', 'password_hash' => 'y'],
            'beacon' => $beacon + ['enabled' => true, 'secret' => str_repeat('k', 48)],
        ];
        file_put_contents($path, '<?php return ' . var_export($data, true) . ';');
    }

    $cfg = Config::load($path);

    $transport = static fn (array $request): array => [
        'status' => 200,
        'body'   => (string) json_encode([
            'responseHeader' => ['status' => 0],
            'response'       => ['numFound' => 0, 'docs' => []],
            'facets'         => ['count' => 0],
        ]),
        'error'  => '',
    ];

    $gateway = new \Loghound\Panel\Gateway(
        $cfg,
        new \Loghound\Solr((array) $cfg->get('solr'), $transport),
        false
    );

    ob_start();
    try {
        (new \Loghound\Panel\Settings($cfg, $gateway))->body();
    } finally {
        $html = (string) ob_get_clean();
    }

    return $html;
}

/** A staged beacon row in the shape State::beaconsFor() returns. */
function lh_sa_row(int $id, array $payload, int $receivedAt = 1000, string $sessionId = ''): array
{
    return [
        'id'          => $id,
        'session_id'  => $sessionId,
        'received_at' => $receivedAt,
        'payload'     => $payload,
    ];
}

return [

    /* ------------------------------------------------------------------------------------
     * 1. TRUST — which hostname may speak for a site
     * --------------------------------------------------------------------------------- */

    'a reported hostname is normalised to the same shape a log line would produce'
        => static function (): void {
            lh_same('search.opensolr.com', Beacon::normaliseHost('Search.OpenSolr.com'), 'lower-cased');
            lh_same('search.opensolr.com', Beacon::normaliseHost('search.opensolr.com:8443'), 'port stripped');
            lh_same('search.opensolr.com', Beacon::normaliseHost('search.opensolr.com.'), 'root dot stripped');
            lh_same('search.opensolr.com', Beacon::normaliseHost('  search.opensolr.com '), 'trimmed');
            lh_same('localhost', Beacon::normaliseHost('localhost'), 'a single label is a hostname');
            lh_same('xn--80ak6aa92e.com', Beacon::normaliseHost('xn--80ak6aa92e.com'), 'punycode survives');
        },

    'anything that is not a hostname yields the empty string, never a coerced value'
        => static function (): void {
            foreach ([
                '',
                '-leading.hyphen.com',
                'trailing.hyphen-.com',
                'two..dots.com',
                'has space.com',
                "newline\n.com",
                'quote".com',
                'semi;colon.com',
                'brace{.com',
                'under_score.com',
                'https://search.opensolr.com',
                'search.opensolr.com/path',
                str_repeat('a', 60) . '.' . str_repeat('b', 250) . '.com',
            ] as $bad) {
                lh_same('', Beacon::normaliseHost($bad), 'refused: ' . lh_show($bad));
            }

            foreach ([null, 123, [], true, new stdClass()] as $bad) {
                lh_same('', Beacon::normaliseHost($bad), 'a non-string is not a hostname');
            }
        },

    'a hostname that reached the Virtual host dimension can carry nothing into a Solr filter'
        => static function (): void {
            /* The value ends up as a facet value beside hosts that came from the operator's own
               logs, so the charset is the guard that stops a foreign string sitting in a
               dimension everybody reads as trustworthy. */
            foreach (['a"b.com', "a'b.com", 'a b.com', 'a(b).com', 'a*b.com', 'a:b.com', 'a\\b.com'] as $bad) {
                lh_same('', Beacon::normaliseHost($bad), 'refused a Lucene metacharacter: ' . $bad);
            }
        },

    'the host is read out of an Origin header and nothing else about it is kept'
        => static function (): void {
            lh_same('search.opensolr.com', Beacon::originHost('https://search.opensolr.com'), 'https');
            lh_same('search.opensolr.com', Beacon::originHost('http://search.opensolr.com:8080'), 'port dropped');
            lh_same('search.opensolr.com', Beacon::originHost('HTTPS://Search.OpenSolr.COM'), 'case folded');
            lh_same('', Beacon::originHost('null'), 'a null origin is not a host');
            lh_same('', Beacon::originHost(''), 'no header is no host');
            lh_same('', Beacon::originHost('not a url at all'), 'garbage is not a host');
            lh_same('', Beacon::originHost(null), 'a non-string is not a host');
        },

    'the allowlist is the permission, and an empty one permits nothing'
        => static function (): void {
            $closed = lh_sa_beacon();
            lh_same([], $closed->allowedHosts(), 'nothing is listed by default');
            lh_false($closed->hostAllowed('search.opensolr.com'), 'so nothing is allowed');
            lh_false($closed->hostAllowed(''), 'and the empty hostname least of all');

            $open = lh_sa_beacon(['allowed_hosts' => ['Search.OpenSolr.com:443', 'shop.example.com']]);
            lh_true($open->hostAllowed('search.opensolr.com'), 'a listed host, normalised on both sides');
            lh_true($open->hostAllowed('SEARCH.opensolr.com'), 'and however the page spelled it');
            lh_false($open->hostAllowed('evil.example'), 'an unlisted host is refused');
            lh_false($open->hostAllowed('search.opensolr.com.evil.example'), 'a suffix is not a match');
            lh_false($open->hostAllowed('earch.opensolr.com'), 'nor is a prefix');
            lh_false($open->hostAllowed(''), 'nor is nothing');
        },

    'a garbage entry in the allowlist is dropped rather than becoming a permission'
        => static function (): void {
            $b = lh_sa_beacon(['allowed_hosts' => ['good.example.com', 'bad host', '', 42, null, ['x']]]);
            lh_same(['good.example.com'], $b->allowedHosts(), 'only the usable entry survives');
        },

    'the collector requires the page, the browser and the operator to agree'
        => static function (): void {
            $src = lh_sa_collector();

            lh_contains($src, 'function lh_site(', 'the trust decision is one named function');

            $fn = (string) strstr($src, 'function lh_site(');
            $fn = substr($fn, 0, 900);

            lh_contains($fn, 'Beacon::originHost($origin)', 'it reads the host off the Origin header');
            lh_contains(
                $fn,
                "if (\$fromOrigin === '' || \$fromOrigin !== \$claimed) {",
                'a missing Origin or one that disagrees with the page is refused, not reconciled — '
                . 'a browser cannot forge Origin, so a disagreement means the request was not built '
                . 'by a browser running on the page it claims'
            );
            lh_contains(
                $fn,
                "\$beacon->hostAllowed(\$claimed) ? \$claimed : ''",
                'and the operator still has to have listed it'
            );
            lh_contains($fn, "return '';", 'every refusal answers with no hostname at all');
        },

    'nothing from the measured site is staged unless the site was recognised'
        => static function (): void {
            $src = lh_sa_collector();

            lh_contains($src, "'host'        => \$site,", 'the hostname staged is the VERIFIED one');
            lh_contains(
                $src,
                "'terms'       => \$site === '' ? [] : \$payload['terms'],",
                'search terms are staged only for a site the operator listed — an unrecognised page '
                . 'must not be able to put values into the search dimension of somebody else\'s data'
            );
            lh_contains(
                $src,
                "'ua'          => \$site === '' ? '' : \$ua,",
                'and the User-Agent is stored only where a standalone session could need it'
            );
        },

    'a hostname gets a rate-limit bucket of its own, before the token exchange'
        => static function (): void {
            $src = lh_sa_collector();

            $window = (string) strstr($src, '$site = lh_site(');
            $window = substr($window, 0, 500);

            lh_contains($window, "'host:'", 'there is a per-hostname bucket');
            lh_contains($window, 'hash_hmac(', 'keyed-hashed like the address bucket, not stored raw');
            lh_contains($window, 'ratePerMinHost()', 'with its own limit');
            lh_contains($window, 'lh_end();', 'and exceeding it ends the request');

            lh_true(
                strpos($src, "'host:'") < strpos($src, '$isHello   = ('),
                'the hostname limit is applied BEFORE the hello branch mints anything, because the '
                . 'hello branch is protected by the limiter alone'
            );

            $b = lh_sa_beacon(['rate_per_min_host' => 50]);
            lh_same(50, $b->ratePerMinHost(), 'the limit is configurable');
            lh_same(3000, lh_sa_beacon()->ratePerMinHost(), 'and has a default');
            lh_same(1, lh_sa_beacon(['rate_per_min_host' => -9])->ratePerMinHost(), 'clamped low');
        },

    /* ------------------------------------------------------------------------------------
     * 2. BOUNDING — a search term is a hostile string
     * --------------------------------------------------------------------------------- */

    'a search term is lower-cased and whitespace-collapsed so one search is one facet value'
        => static function (): void {
            lh_same('solr hosting', Beacon::normaliseTerm('Solr Hosting'), 'lower-cased');
            lh_same('solr hosting', Beacon::normaliseTerm("solr   hosting"), 'runs of spaces collapsed');
            lh_same('solr hosting', Beacon::normaliseTerm("solr\thosting"), 'a tab is whitespace');
            lh_same('solr hosting', Beacon::normaliseTerm('  solr hosting  '), 'trimmed');
            lh_same('solr hosting', Beacon::normaliseTerm("solr\u{00A0}hosting"), 'and so is a nbsp');
        },

    'a term is stripped of control characters and repaired to valid UTF-8'
        => static function (): void {
            lh_same('ab', Beacon::normaliseTerm("a\x00b"), 'a NUL is deleted, not turned into a space: '
                . 'a NUL between two letters is not a word boundary');
            lh_same('ab', Beacon::normaliseTerm("a\x1Bb"), 'nor is an escape');
            lh_same('ab', Beacon::normaliseTerm("a\x7Fb"), 'nor DEL');

            lh_same('a b', Beacon::normaliseTerm("a\nb"), 'but a newline IS a word separator');
            lh_same('a b', Beacon::normaliseTerm("a\r\nb"), 'and so is a CRLF, collapsed to one space');
            lh_same('a b', Beacon::normaliseTerm("a\tb"), 'and a tab — deleting these would weld two '
                . 'words into a term nobody typed');

            $repaired = Beacon::normaliseTerm("caf\xC3\x28");
            lh_true(mb_check_encoding($repaired, 'UTF-8'), 'invalid UTF-8 is repaired, never passed on');

            lh_same('café', Beacon::normaliseTerm('Café'), 'and real multibyte text survives');
        },

    'an over-long term is DROPPED, never truncated into a value nobody searched for'
        => static function (): void {
            $ok = str_repeat('a', Beacon::MAX_TERM);
            lh_same($ok, Beacon::normaliseTerm($ok), 'exactly at the cap is kept');

            lh_same('', Beacon::normaliseTerm(str_repeat('a', Beacon::MAX_TERM + 1)), 'one over is dropped');
            lh_same('', Beacon::normaliseTerm(str_repeat('a', 100000)), 'and a very long one costs nothing');

            /* Counted in CHARACTERS, not bytes: a multibyte search is not half the length of an
               ASCII one, and truncating by bytes would also split a codepoint. */
            $multi = str_repeat('é', Beacon::MAX_TERM);
            lh_same(mb_strtolower($multi, 'UTF-8'), Beacon::normaliseTerm($multi), 'multibyte is measured in characters');
        },

    'an empty or non-string term is nothing, not a value'
        => static function (): void {
            foreach (['', '   ', "\n", null, 42, [], true, new stdClass()] as $bad) {
                lh_same('', Beacon::normaliseTerm($bad), 'not a term: ' . lh_show($bad));
            }
        },

    'terms come out of a raw query string only for the parameters that were named'
        => static function (): void {
            $names = Beacon::normaliseParamNames(['q']);

            lh_same(['solr hosting'], Beacon::searchTerms('q=solr+hosting', $names), 'plus is a space');
            lh_same(['solr hosting'], Beacon::searchTerms('q=solr%20hosting', $names), 'and so is %20');
            lh_same(['solr'], Beacon::searchTerms('page=2&q=solr&sort=date', $names), 'the rest of the URL is ignored');
            lh_same([], Beacon::searchTerms('s=solr', $names), 'an unnamed parameter yields nothing');
            lh_same([], Beacon::searchTerms('', $names), 'no query string, no terms');
            lh_same([], Beacon::searchTerms('q=solr', []), 'and no configured names means no collection at all');
        },

    'the session token in a URL is never collected, because only names are matched'
        => static function (): void {
            $names = Beacon::normaliseParamNames(['q']);
            $terms = Beacon::searchTerms(
                'q=solr&token=abc123secret&reset=deadbeef&email=ada%40example.com',
                $names
            );

            lh_same(['solr'], $terms, 'one value out, and it is the one that was asked for');
            foreach (['abc123secret', 'deadbeef', 'ada@example.com'] as $secret) {
                lh_false(in_array($secret, $terms, true), 'nothing else in the URL was read: ' . $secret);
            }
        },

    'a repeated parameter is several terms, and the count is capped'
        => static function (): void {
            $names = Beacon::normaliseParamNames(['q']);

            lh_same(['a', 'b'], Beacon::searchTerms('q=a&q=b', $names), 'each occurrence is its own term');
            lh_same(['a'], Beacon::searchTerms('q=a&q=a', $names), 'de-duplicated');

            $many = [];
            for ($i = 0; $i < Beacon::MAX_TERMS + 20; $i++) {
                $many[] = 'q=v' . $i;
            }
            lh_same(
                Beacon::MAX_TERMS,
                count(Beacon::searchTerms(implode('&', $many), $names)),
                'and no payload can contribute more than MAX_TERMS'
            );

            lh_same([], Beacon::searchTerms('q=' . str_repeat('x', 9000), $names), 'an absurd query string is refused whole');
        },

    'the server re-applies its own whitelist to the map the beacon sent'
        => static function (): void {
            $b = lh_sa_beacon(['query_params' => ['q']]);

            lh_same(['solr'], $b->termsOf(['q' => 'Solr']), 'a configured name is kept');
            lh_same([], $b->termsOf(['s' => 'solr']), 'a name the SERVER did not configure is dropped, '
                . 'however the page was written — the payload is attacker-chosen');
            lh_same(['solr'], $b->termsOf(['Q' => 'solr']), 'name matching is case-insensitive');
            lh_same([], $b->termsOf(['q' => 'solr', 'token' => 'secret']) === ['solr'] ? [] : ['broken'], 'and only that one');

            lh_same([], lh_sa_beacon()->termsOf(['q' => 'solr']), 'with nothing configured, nothing is collected');

            foreach (['a string', 42, null, ['list', 'not', 'map']] as $bad) {
                lh_same([], $b->termsOf($bad), 'a payload that is not a map yields nothing: ' . lh_show($bad));
            }
        },

    'search-term collection is off until it is configured, and normalise() is the gate'
        => static function (): void {
            $off = lh_sa_beacon();
            $p = $off->normalise(['qp' => ['q' => 'solr'], 'hn' => 'search.opensolr.com']);

            lh_same([], $p['terms'], 'nothing is normalised through, so nothing can be staged');
            lh_same('search.opensolr.com', $p['hostname'], 'the hostname is still validated');

            $on = lh_sa_beacon(['query_params' => ['q']]);
            lh_same(['solr'], $on->normalise(['qp' => ['q' => 'Solr']])['terms'], 'and configured, it arrives');
        },

    'the log parser fills the same field, so a host with a log source needs no beacon'
        => static function (): void {
            $parser = new Parser(['search_params' => ['q'], 'keep_raw' => false]);

            $doc = $parser->normalize([
                'remote_addr' => '198.51.100.7',
                'time'        => '10/Sep/2026:12:00:00 +0000',
                'request'     => 'GET /search?q=Solr+Hosting&token=secret HTTP/1.1',
                'status'      => '200',
                'bytes'       => '512',
            ], '/var/log/apache2/access.log', 0);

            lh_true(is_array($doc), 'the line parsed');
            lh_same(['solr hosting'], $doc['search_terms_ss'], 'the named parameter became a term');
            lh_contains((string) $doc['query_s'], 'token=secret', 'query_s still holds the whole string, unindexed');
        },

    'a parser with no configured parameters writes no search field at all'
        => static function (): void {
            $parser = new Parser(['keep_raw' => false]);

            $doc = $parser->normalize([
                'remote_addr' => '198.51.100.7',
                'time'        => '10/Sep/2026:12:00:00 +0000',
                'request'     => 'GET /search?q=solr HTTP/1.1',
                'status'      => '200',
                'bytes'       => '512',
            ], '/var/log/apache2/access.log', 0);

            lh_no_key((array) $doc, 'search_terms_ss', 'absent, not an empty list: a hit with no '
                . 'whitelisted parameter did not search for nothing, it was never asked');
        },

    /* ------------------------------------------------------------------------------------
     * 3. HONESTY — a session with one plane says so
     * --------------------------------------------------------------------------------- */

    'the merge folds search terms as a sorted, capped union across the session'
        => static function (): void {
            $b = lh_sa_beacon(['query_params' => ['q']]);

            $doc = $b->mergeIntoSession([], [
                lh_sa_row(1, ['pv' => 'a', 'terms' => ['zebra']]),
                lh_sa_row(2, ['pv' => 'a', 'terms' => ['apple', 'zebra']]),
                lh_sa_row(3, ['pv' => 'b', 'terms' => ['mango']]),
            ]);

            lh_same(['apple', 'mango', 'zebra'], $doc['search_terms_ss'], 'every distinct term, once, sorted — '
                . 'sorted because the merge is re-run on every provisional publish and a set whose '
                . 'order drifted would rewrite the document for input that had not changed');

            $rows = [];
            for ($i = 0; $i < Beacon::MAX_SESSION_TERMS + 20; $i++) {
                $rows[] = lh_sa_row($i + 1, ['pv' => 'a', 'terms' => ['term' . $i]]);
            }
            lh_same(
                Beacon::MAX_SESSION_TERMS,
                count($b->mergeIntoSession([], $rows)['search_terms_ss']),
                'and one session cannot grow past the per-session cap'
            );
        },

    'a session that searched for nothing has no search field, not an empty one'
        => static function (): void {
            $doc = lh_sa_beacon()->mergeIntoSession([], [lh_sa_row(1, ['pv' => 'a', 'wall_ms' => 100])]);
            lh_no_key($doc, 'search_terms_ss', 'absent means we were never told');
        },

    'a term staged as JSON is folded exactly like one staged as an array'
        => static function (): void {
            $doc = lh_sa_beacon()->mergeIntoSession([], [
                lh_sa_row(1, ['pv' => 'a', 'terms' => json_encode(['solr'])]),
            ]);
            lh_same(['solr'], $doc['search_terms_ss'], 'the staging blob shape does not change the result');
        },

    'the beacon never moves a session from one virtual host to another'
        => static function (): void {
            $b = lh_sa_beacon();

            $logBacked = $b->mergeIntoSession(
                ['host_s' => 'opensolr.com'],
                [lh_sa_row(1, ['pv' => 'a', 'host' => 'evil.example'])]
            );
            lh_same(
                'opensolr.com',
                $logBacked['host_s'],
                'the log is the authority on facts (SPEC 6.4): a payload claiming a different vhost '
                . 'must not be able to reattribute a session that came from log lines'
            );

            $standalone = $b->mergeIntoSession(
                ['id' => 'b' . str_repeat('a', 40)],
                [lh_sa_row(1, ['pv' => 'a', 'host' => 'Search.OpenSolr.com'])]
            );
            lh_same(
                'search.opensolr.com',
                $standalone['host_s'],
                'and only where there is no log line does the beacon supply it'
            );
        },

    'the five rules that read the request log are silent when there was no request log'
        => static function (): void {
            $rules = new Rules([]);

            foreach (Rules::TRANSPORT_CODES as $code) {
                lh_true(
                    in_array($code, Rules::codes(), true) || $code === 'periodic_timing',
                    $code . ' is a real rule code'
                );
            }

            /* A beacon-only session: no hits, no pages, no assets, no gaps — because none of it
               was observable, not because the client did nothing. */
            $signals = Signals::fromSession(['session_id' => 'b1', 'first' => [
                'ua_s' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
                    . '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            ]], ['beacon_b' => true, 'interactions_i' => 0, 'pageviews_i' => 1]);

            $ctx = ['beacon_deployed' => true, 'site_sends_304' => true, 'no_transport' => true];

            foreach (Rules::TRANSPORT_CODES as $code) {
                lh_same(null, $rules->fired($code, $signals, $ctx), $code . ' must not fire: it reads '
                    . 'evidence that was never collected, and a rule firing on an absence is a finding '
                    . 'manufactured out of nothing');
            }
        },

    'no_assets fires on the same session once there IS a log plane, so the gate is the cause'
        => static function (): void {
            $rules = new Rules([]);

            $signals = Signals::fromSession([
                'session_id' => 's1', 'hits' => 8, 'pages' => 1, 'html_200' => true,
                'assets' => 0, 'favicons' => 0, 'sub_resources' => 0,
                'first' => [
                    'ua_s' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                        . '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
                    'browser_s' => 'Chrome',
                ],
            ], ['beacon_b' => false]);

            $withLog = $rules->fired('no_assets', $signals, ['beacon_deployed' => true]);
            $withoutLog = $rules->fired('no_assets', $signals, ['beacon_deployed' => true, 'no_transport' => true]);

            lh_true($withLog !== null, 'a browser UA that fetched no sub-resources is a real finding');
            lh_same(null, $withoutLog, 'and the same session is not accused when the sub-resources '
                . 'were simply never observable');
        },

    'the interaction rule is deliberately NOT silenced: the beacon can still see that'
        => static function (): void {
            lh_false(
                in_array('no_interaction', Rules::TRANSPORT_CODES, true),
                'no_interaction reads the beacon\'s own interaction count, which a beacon-only '
                . 'session has. Silencing it would throw away one of the few signals that still '
                . 'means something on a single plane'
            );
        },

    'a beacon-only verdict always carries the sentence that says it rests on one plane'
        => static function (): void {
            $rules = new Rules([]);

            $signals = Signals::fromSession(['session_id' => 'b1', 'first' => [
                'ua_s' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
                    . '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
                'browser_s' => 'Chrome',
            ]], ['beacon_b' => true, 'interactions_i' => 12, 'pageviews_i' => 2]);

            $out = $rules->score($signals, ['beacon_deployed' => true, 'no_transport' => true]);

            lh_true(
                in_array(Rules::SINGLE_PLANE_REASON, $out['reasons'], true),
                'the reason is on the document, so it is visible in the session dialog and countable '
                . 'in the Signal fired facet'
            );
            lh_same(0, $out['detail'][Rules::SINGLE_PLANE_REASON]['weight'], 'and it is worth no points: '
                . 'it explains an absence of evidence rather than adding any');

            lh_false(
                in_array(Rules::CLEAN_REASON, $out['reasons'], true),
                '"nothing fired" must NOT be claimed, exactly as it is not for a provisional session: '
                . 'five rules were not evaluated, so it is not yet a fact about the session, and the '
                . 'no_bot_signals facet stays a count of sessions that were fully tested'
            );
        },

    'a log-backed session is not given the single-plane reason'
        => static function (): void {
            $rules = new Rules([]);

            $signals = Signals::fromSession(['session_id' => 's1', 'hits' => 12, 'pages' => 3,
                'assets' => 9, 'sub_resources' => 9, 'asset_ratio' => 0.75, 'log_span_ms' => 90000,
                'got_304' => true, 'html_200' => true, 'first' => [
                    'ua_s' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
                        . '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
                    'browser_s' => 'Chrome',
                ]], ['beacon_b' => true, 'interactions_i' => 30, 'pageviews_i' => 3]);

            $out = $rules->score($signals, ['beacon_deployed' => true, 'site_sends_304' => true]);

            lh_false(in_array(Rules::SINGLE_PLANE_REASON, $out['reasons'], true), 'three planes, no caveat');
        },

    'every reason code the scorer can emit is enumerable and has a label'
        => static function (): void {
            lh_true(
                in_array(Rules::SINGLE_PLANE_REASON, Rules::reasonCodes(), true),
                'a code on real documents is a real facet value, so anything enumerating the '
                . 'dimension has to include it or the panel shows the raw slug'
            );

            $reason = Rules::reason(Rules::SINGLE_PLANE_REASON);
            lh_same('One plane only', $reason['label'], 'it has a written label');
            lh_same('info', $reason['severity'], 'and it is not an accusation');
            lh_contains($reason['why'], 'beacon alone', 'and the explanation says what happened');
        },

    /* ------------------------------------------------------------------------------------
     * 4. THE SCORER — how a standalone session is built and de-duplicated
     * --------------------------------------------------------------------------------- */

    'a beacon-only document asserts no transport fact, and none of them is zero-filled'
        => static function (): void {
            $src = lh_sa_scorer();

            lh_contains($src, 'function buildStandaloneDoc(', 'the builder is its own function');

            $fn = (string) strstr($src, 'function buildStandaloneDoc(');
            $fn = (string) strstr($fn, '$doc = [');
            $fn = substr($fn, 0, strpos($fn, "\n}") ?: strlen($fn));

            foreach ([
                'hits_i', 'pages_i', 'assets_i', 'bytes_l', 'status_2xx_i', 'status_3xx_i',
                'status_4xx_i', 'status_5xx_i', 'got_304_b', 'asset_ratio_f', 'log_span_ms_l',
                'gap_p50_ms_l', 'gap_stddev_ms_l',
            ] as $field) {
                lh_false(
                    str_contains($fn, "'" . $field . "'"),
                    $field . ' must be ABSENT on a beacon-only session, never zero. A zero is a '
                    . 'measurement: asset_ratio_f 0.0 reads as "fetched only markup", which is a bot '
                    . 'signal, about a client whose asset fetching was never observable from here'
                );
            }

            lh_contains($fn, "'planes_s'   => 'beacon_only'", 'and the document says which planes it had');
        },

    'the standalone path is gated on a recorded hostname and on the absence of a log source'
        => static function (): void {
            $src = lh_sa_scorer();

            lh_contains($src, 'function hostHasLogSource(', 'the mode decision is a named function');
            lh_contains($src, 'function coveredHosts(', 'and coverage is resolved from the hits core');

            $gate = (string) strstr($src, 'STEP 2b');
            $gate = substr($gate, 0, 4200);

            lh_contains(
                $gate,
                "if (\$host === '' || hostHasLogSource(\$host, \$covered)) {",
                'both gates on one line: no recorded hostname means the collector did not recognise '
                . 'the site, and a covered hostname means the log line is the authority and is coming'
            );
            lh_contains($gate, 'continue;', 'and a group that fails either is left alone');
            lh_contains(
                $gate,
                'allowedHosts() !== []',
                'the whole block is skipped when the operator has listed no hosts, so an installation '
                . 'that has not configured this behaves exactly as it did before'
            );
        },

    'coverage failing to resolve means "covered", so an outage publishes nothing'
        => static function (): void {
            $src = lh_sa_scorer();

            $fn = (string) strstr($src, 'function hostHasLogSource(');
            $fn = substr($fn, 0, strpos($fn, "\n}") ?: 400);

            lh_contains(
                $fn,
                'if ($covered === null) {',
                'an unresolved answer is handled explicitly'
            );
            lh_contains(
                $fn,
                'return true;',
                'and it is TRUE — assume covered. A duplicate session published during an outage, '
                . 'with its log-backed twin arriving later, has no undo; a delay does'
            );
        },

    'a standalone group is provisional until it goes quiet, and only then are its rows consumed'
        => static function (): void {
            $src = lh_sa_scorer();

            $gate = (string) strstr($src, 'STEP 2b');
            $gate = substr($gate, 0, 5000);

            lh_contains(
                $gate,
                "\$provisional = ((int) \$group['last_ts']) > (\$now - \$idleSeconds);",
                'quiet is measured against the same idle timeout a log session closes on'
            );
            lh_contains($gate, "\$doc['provisional_b'] = true;", 'a live group is published provisional');
            lh_contains(
                $gate,
                'if ($provisional) {',
                'and the rows are consumed only in the other branch, because there is no second copy '
                . 'of the execution plane anywhere and a provisional document is about to be rewritten'
            );

            lh_true(
                strpos($gate, "\$mergedIds[] = (int) \$row['id'];") > strpos($gate, 'if ($provisional) {'),
                'the ids are collected under the settled branch'
            );
        },

    'a standalone document is deleted before the run indexes the log-backed session that replaced it'
        => static function (): void {
            $src = lh_sa_scorer();

            lh_contains($src, '$superseded[$staged] = true;', 'a beacon-minted id absorbed by a log '
                . 'session is recorded');
            lh_contains(
                $src,
                'preg_match(\Loghound\Beacon::PROVISIONAL_ID, $staged) === 1',
                'and only if it really is a collector-minted id'
            );
            lh_contains(
                $src,
                "(string) (\$payload['host'] ?? '') !== ''",
                'and only if the collector recorded a hostname on the row — a row with none could '
                . 'never have become a standalone document, so issuing a delete for it would be a '
                . 'Solr round trip per beaconed session for an answer that is always "nothing there"'
            );

            lh_true(
                strpos($src, 'if ($superseded !== []) {') < strpos($src, '$solr->addDocs($sessionCore, $chunk, true);'),
                'the delete runs BEFORE the upsert. A run that indexed the log-backed session and then '
                . 'failed would otherwise leave both documents in the index, and the duplicate is the '
                . 'thing this exists to prevent — deleting first turns a failure into a gap'
            );

            $del = (string) strstr($src, 'if ($superseded !== []) {');
            $del = substr($del, 0, 900);
            lh_contains($del, 'array_chunk(', 'the delete is chunked so one filter stays inside the length cap');
            lh_contains($del, 'array_filter(', 'and every id is re-checked against the id pattern before it '
                . 'is built into a filter literal');
        },

    'a collector-minted session id is recognisable by shape, in exactly one place'
        => static function (): void {
            lh_same(1, preg_match(Beacon::PROVISIONAL_ID, 'b' . str_repeat('a', 40)), 'a real one matches');
            lh_same(1, preg_match(Beacon::PROVISIONAL_ID, 'b' . bin2hex(random_bytes(20))), 'as minted');

            foreach ([
                'b' . str_repeat('a', 39),
                'b' . str_repeat('a', 41),
                'c' . str_repeat('a', 40),
                'b' . str_repeat('A', 40),
                'b' . str_repeat('a', 39) . '!',
                'b' . str_repeat('a', 40) . ' OR id:*',
                sha1('a log-backed session id'),
                '',
            ] as $bad) {
                lh_same(0, preg_match(Beacon::PROVISIONAL_ID, $bad), 'refused: ' . lh_show($bad));
            }

            lh_contains(
                lh_sa_collector(),
                "'b' . bin2hex(random_bytes(20))",
                'and the collector mints exactly what the pattern describes'
            );
        },

    'the scorer stamps the plane mixture on every session document it writes'
        => static function (): void {
            $src = lh_sa_scorer();

            lh_contains(
                $src,
                "\$doc['planes_s'] = !empty(\$doc['beacon_b']) ? 'log_beacon' : 'log_only';",
                'a log-backed session records whether the beacon reached it'
            );
            lh_contains($src, "\$doc['planes_s'] = 'beacon_only';", 'and a standalone one records that it did not '
                . 'have a log');
        },

    /* ------------------------------------------------------------------------------------
     * 5. THE SCHEMAS — three states, and no default that invents a claim
     * --------------------------------------------------------------------------------- */

    'both new fields exist on the cores that need them, faceted rather than merely stored'
        => static function (): void {
            foreach (['hits', 'sessions'] as $core) {
                $schema = lh_sa_schema($core);
                lh_contains(
                    $schema,
                    '<field name="search_terms_ss" type="strings" indexed="true" stored="true" docValues="true" multiValued="true"/>',
                    $core . ': search terms are a real dimension — indexed and docValues, which is what a '
                    . 'facet and a filter need. Stored-only, like query_s, would be visible on one '
                    . 'document and countable on none'
                );
            }

            lh_contains(
                lh_sa_schema('sessions'),
                '<field name="planes_s" type="string" indexed="true" stored="true" docValues="true"/>',
                'the plane mixture is filterable and readable back for the session dialog'
            );
            lh_false(
                str_contains(lh_sa_schema('hits'), 'name="planes_s"'),
                'and it is a conclusion about a whole session, so it does not belong on a hit'
            );
        },

    'query_s keeps its old flags: the new field is an addition, not a reversal'
        => static function (): void {
            lh_contains(
                lh_sa_schema('hits'),
                '<field name="query_s" type="string" indexed="false" stored="true" docValues="false"/>',
                'the whole query string stays unindexed with no docValues. It is unbounded '
                . 'attacker-controlled text with a near-unique value per request, and indexing it '
                . 'would build a term dictionary the size of the corpus'
            );
        },

    'neither new field carries a default, so no old document is made to assert anything'
        => static function (): void {
            foreach (['hits', 'sessions'] as $core) {
                $schema = lh_sa_schema($core);
                foreach (['search_terms_ss', 'planes_s', 'install_s'] as $field) {
                    if (!preg_match('~<field name="' . $field . '"[^>]*/>~', $schema, $m)) {
                        continue;
                    }
                    lh_false(
                        str_contains($m[0], 'default='),
                        $core . '.' . $field . ' must have no default. A default would write a claim onto '
                        . 'every document ever indexed, silently and irreversibly — the mistake '
                        . 'provisional_b and signed_in_b both avoid by letting absence be the third state'
                    );
                }
            }
        },

    'the documentation states the query for a transport plane as a negation, and says why'
        => static function (): void {
            $schema = lh_sa_schema('sessions');
            lh_contains(
                $schema,
                '-planes_s:beacon_only',
                'the correct filter is the negation: every session indexed before the field existed '
                . 'came from a log, so planes_s:log_only would silently exclude all of that history'
            );

            $doc = (string) file_get_contents(__DIR__ . '/../docs/BEACON.md');
            lh_contains($doc, '-planes_s:beacon_only', 'and the operator-facing docs say the same');
        },

    /* ------------------------------------------------------------------------------------
     * 6. THE SNIPPET — what the panel prints has to work first time
     * --------------------------------------------------------------------------------- */

    'the beacon reports its own hostname and the named parameters, and nothing more of the URL'
        => static function (): void {
            $js = lh_sa_bjs();

            lh_contains($js, "var HOST = T(function () { return (w.location.hostname || '').toLowerCase(); })", 'the host, not the URL');
            lh_contains($js, 'if (HOST) { out.hn = HOST; }', 'sent on every payload');
            lh_contains($js, "var raw = attr('data-params');", 'the parameter list comes off the script tag');
            lh_contains($js, 'function urlParams()', 'and is applied to the current URL at send time');

            lh_contains(
                $js,
                "u: (w.location.pathname || '').slice(0, 512),",
                'the path field is still the PATH only — the named parameters travel separately, so '
                . 'the two together are still never the whole URL'
            );

            lh_false(
                str_contains($js, 'location.search') && !str_contains($js, 'function urlParams'),
                'the query string is read in exactly one place'
            );
            lh_false(str_contains($js, 'out.qs'), 'and there is no field that carries it whole');
        },

    'the client-side parameter list refuses a name it cannot vouch for'
        => static function (): void {
            $js = lh_sa_bjs();
            $fn = (string) strstr($js, "var raw = attr('data-params');");
            $fn = substr($fn, 0, 500);

            lh_contains($fn, 'out.length < 8', 'the list is bounded');
            lh_contains($fn, 'n.length <= 40', 'and so is each name');
            lh_contains($fn, '/^[a-z0-9_\-.[\]]+$/.test(n)', 'with a charset, so a typo cannot widen the match');
        },

    'qp is omitted rather than sent empty when nothing was collected'
        => static function (): void {
            lh_contains(
                lh_sa_bjs(),
                'if (Object.prototype.hasOwnProperty.call(qp, k)) { out.qp = qp; break; }',
                'an absent key costs nothing and an empty object would have to be distinguished from '
                . 'a real one on the far side'
            );
        },

    'the snippet the panel prints carries the parameters this installation actually collects'
        => static function (): void {
            $src = (string) file_get_contents(__DIR__ . '/../src/Panel/Settings.php');

            lh_contains(
                $src,
                "\$paramsAttr = \$collected === [] ? '' : ' data-params=\"' . implode(',', \$collected) . '\"';",
                'the attribute is built from the live configuration, so a snippet never advertises an '
                . 'attribute the collector would discard'
            );
            lh_contains($src, '$htmlSnippet = \'<script src="\' . $src . \'"\' . $paramsAttr', 'and it is in the snippet');
            lh_contains($src, 'Beacon::normaliseParamNames', 'through the same normaliser the server uses');
        },

    'the panel tells an operator both CSP directives, including the one people miss'
        => static function (): void {
            $src = (string) file_get_contents(__DIR__ . '/../src/Panel/Settings.php');

            lh_contains($src, 'script-src', 'the script directive');
            lh_contains($src, 'connect-src', 'and the collector directive, which is the one that is forgotten');
            lh_contains($src, 'function cspOrigin(', 'built as an origin, since a CSP source with a path does not match');

            $doc = (string) file_get_contents(__DIR__ . '/../docs/BEACON.md');
            lh_contains($doc, 'connect-src https://loghound.example.com', 'and the docs carry it too');
            lh_contains($doc, 'the browser blocks', 'with the symptom named, because there is no error to find');
        },

    'the panel says plainly what the allowlist does not protect against'
        => static function (): void {
            $src = (string) file_get_contents(__DIR__ . '/../src/Panel/Settings.php');

            lh_contains($src, 'cannot forge the', 'it says a browser cannot forge Origin');
            lh_contains(
                $src,
                'fabricate sessions attributed to it',
                'and it says, in the interface and not only in a document, that anything which is not '
                . 'a browser can. Presenting the allowlist as authentication would be making exactly '
                . 'the claim this product exists to argue against'
            );
            lh_contains($src, 'permission, not as a password', 'in those words');
        },

    'every option b.js reads is documented in the application and in the reference'
        => static function (): void {
            /* MECHANICAL, on purpose. The option list is derivable from the source — every
               attr('data-…'), every attrInt('data-…') and every w.Loghound… — so this test
               fails the day the script grows an option the documentation does not carry,
               which is worth more than a proof-read that was accurate on the day it was done.
               b.js is the truth; the table and the document follow it. */
            $js = lh_sa_bjs();

            $found = [];
            if (preg_match_all("~attr(?:Int)?\\('(data-[a-z-]+)'~", $js, $m)) {
                foreach ($m[1] as $name) {
                    $found[$name] = true;
                }
            }
            if (preg_match_all('~w\.(Loghound[A-Za-z]*)~', $js, $m)) {
                foreach ($m[1] as $name) {
                    $found['window.' . $name] = true;
                }
            }
            if (preg_match_all('~w\.loghound\.([a-z]+)\s*=~', $js, $m)) {
                foreach ($m[1] as $name) {
                    $found['window.loghound.' . $name] = true;
                }
            }

            $options = array_keys($found);
            lh_true(count($options) >= 9, 'the derivation found the options at all, got ' . lh_show($options));

            $table = [];
            foreach (\Loghound\Panel\Settings::beaconOptions() as $opt) {
                $table[] = $opt['name'];
            }
            $doc = (string) file_get_contents(__DIR__ . '/../docs/BEACON.md');

            foreach ($options as $name) {
                $inTable = false;
                foreach ($table as $documented) {
                    if (str_starts_with($documented, $name)) {
                        $inTable = true;
                        break;
                    }
                }
                lh_true(
                    $inTable,
                    $name . ' is read by b.js and is missing from Settings::beaconOptions(). The '
                    . 'application is where somebody installing the beacon looks; an option that '
                    . 'exists only in a JavaScript docblock is undocumented for the person who '
                    . 'needs it'
                );
                lh_contains($doc, $name, $name . ' is read by b.js and is missing from docs/BEACON.md');
            }

            foreach ($table as $documented) {
                $stem = (string) strtok($documented, '(');
                lh_true(
                    isset($found[$stem]),
                    $documented . ' is documented but b.js does not read it. A reference that lists '
                    . 'an option the script ignores is worse than one that omits it: it is an '
                    . 'instruction that cannot work'
                );
            }
        },

    'the option reference answers, per installation, whether a value will actually be stored'
        => static function (): void {
            $src = (string) file_get_contents(__DIR__ . '/../src/Panel/Settings.php');

            lh_contains($src, 'function beaconOptionsTable(', 'the table is rendered');
            lh_contains($src, 'function beaconOptionState(', 'with a live column');
            lh_contains($src, "'beacon.store_identity'  => (bool) \$this->cfg->get('beacon.store_identity', false)",
                'read from the live configuration, not from a fixed string');
            lh_contains($src, 'discarded', 'and an option whose switch is off says so in as many words, because '
                . 'the failure it warns about is completely silent: the snippet works, the collector '
                . 'answers 204, and the value is dropped before anything is written');

            foreach (\Loghound\Panel\Settings::beaconOptions() as $opt) {
                foreach (['name', 'kind', 'what', 'default', 'limits'] as $key) {
                    lh_true(
                        is_string($opt[$key]) && $opt[$key] !== '',
                        $opt['name'] . ' has a ' . $key
                    );
                }
                lh_true(
                    $opt['switch'] === null || is_string($opt['switch']),
                    $opt['name'] . ' declares which configuration key governs it, or null for none'
                );
            }
        },

    'the identity block sits with the snippet and names the switch that would discard it'
        => static function (): void {
            $src = (string) file_get_contents(__DIR__ . '/../src/Panel/Settings.php');

            lh_true(
                strpos($src, '$this->beaconIdentityBlock();') > strpos($src, "echo '<h3>Install it</h3>';"),
                'the identity block reads as part of installing the snippet rather than as config '
                . 'prose several screens above it'
            );

            lh_contains($src, 'window.loghound.identify(ident, signedIn)', 'the after-load route is shown');
            lh_contains($src, 'window.LoghoundIdent', 'and the globals route');
            lh_contains($src, 'identity arrives after the page has loaded', 'each route says WHICH situation '
                . 'it is for, rather than being listed as one of three equivalents');
            lh_contains($src, 'already knows who it is at ', 'including the ordinary render-time one');
            lh_contains($src, 'Beacon::MAX_IDENT', 'and the cap is stated next to the field it caps, from the '
                . 'constant rather than from a number typed twice');
        },

    'each install tab shows that platform\'s real way of attaching an identity'
        => static function (): void {
            $src = (string) file_get_contents(__DIR__ . '/../src/Panel/Settings.php');

            lh_contains($src, 'is_user_logged_in()', 'WordPress: the real API, at a hook where it is available');
            lh_contains($src, 'wp_get_current_user()->user_email', 'reading the address off the user object, '
                . 'which is how somebody actually writes this');
            lh_contains($src, 'esc_attr(', 'escaped, so an address with a quote in it cannot break the tag');
            lh_contains($src, 'page cache', 'and the cache trap is named, because it silently serves one '
                . 'visitor\'s identity to everybody');

            lh_contains($src, '\\\\Drupal::currentUser()', 'Drupal: the real API');
            lh_contains($src, "isAuthenticated() ? '1' : '0'", 'including what a signed-out visitor gets');
            lh_contains($src, "\$attachments['#cache']['contexts'][] = 'user';", 'and the cache context, without '
                . 'which the render cache serves the first authenticated address to everyone');

            lh_contains($src, '{{Loghound Ident}}', 'GTM: a Data Layer variable, because a tag manager runs in '
                . 'the browser and cannot know who is signed in');

            lh_false(
                str_contains($src, '$gtmSnippet = $htmlSnippet;'),
                'no tab repeats the plain HTML line under a heading where it does not apply — four '
                . 'instructions of which three do not work is worse than one that does'
            );
        },

    'the rendered card warns that an identity will be thrown away when the switch is off'
        => static function (): void {
            $off = lh_sa_settings_html(['store_identity' => false]);

            lh_contains($off, 'data-ident', 'the attribute is named in the interface, not only in a '
                . 'JavaScript docblock and a markdown file');
            lh_contains(
                $off,
                'is DISCARDED',
                'and the card says so in as many words when beacon.store_identity is off. This is the '
                . 'trap the card exists to close: the snippet appears to work, the collector answers '
                . '204, the address is dropped before anything is written, the panel shows nothing, '
                . 'and there is no error anywhere to explain it'
            );
            lh_contains($off, 'beacon.store_identity', 'naming the setting to change');

            $on = lh_sa_settings_html(['store_identity' => true]);
            lh_contains($on, 'is stored', 'and with it on, the card says that instead');
            lh_false(
                str_contains($on, '<code class="mono">data-ident</code> is DISCARDED'),
                'the warning is not shown when it does not apply'
            );
        },

    'the rendered card names the parameters this installation will actually accept'
        => static function (): void {
            /* The snippets are printed through Security::esc(), so the attribute is looked for in
               the escaped form the page actually serves rather than in the form it was built in.
               Asserting on the unescaped string would pass on a page that had stopped escaping. */
            $attr = Security::esc(' data-params="q,search"');

            $none = lh_sa_settings_html([]);
            lh_contains($none, 'beacon.query_params', 'the setting is named');
            lh_contains($none, 'is empty', 'and an unconfigured installation says so rather than listing '
                . 'an attribute whose values the collector would discard');
            lh_false(
                str_contains($none, Security::esc('data-params="')),
                'so no snippet carries a data-params attribute — a snippet advertising an option that '
                . 'cannot work is an instruction that fails'
            );

            $some = lh_sa_settings_html(['query_params' => ['q', 'search']]);
            lh_contains($some, $attr, 'and a configured one emits exactly the names it accepts, so the '
                . 'pasted snippet works first time');
            lh_contains($some, 'accepting', 'with the reference table naming them too');
        },

    'the rendered card carries every option, and the standalone and CSP guidance'
        => static function (): void {
            $html = lh_sa_settings_html(['allowed_hosts' => ['search.example.com']]);

            foreach (\Loghound\Panel\Settings::beaconOptions() as $opt) {
                lh_contains($html, Security::esc($opt['name']), 'the card renders ' . $opt['name']);
            }

            lh_contains($html, 'search.example.com', 'the allowlisted host is shown back');
            lh_contains($html, 'connect-src', 'the CSP directive that is forgotten is on the page');
            lh_contains($html, 'permission, not as a password', 'and so is the honest limit of the allowlist');

            $empty = lh_sa_settings_html([]);
            lh_contains($empty, 'No hostnames are listed', 'with an empty allowlist saying what that means');
        },

    'the beacon documentation carries the standalone contract, not just a mention'
        => static function (): void {
            $doc = (string) file_get_contents(__DIR__ . '/../docs/BEACON.md');

            foreach ([
                'beacon.allowed_hosts',
                'beacon.query_params',
                'data-params',
                'permission, not an authentication',
                'fabricate sessions attributed to it',
                'planes_s',
                'TRANSPORT_CODES',
                'Access-Control-Expose-Headers',
                'CORS-simple request',
                'client key',
            ] as $needle) {
                lh_contains($doc, $needle, 'docs/BEACON.md must cover: ' . $needle);
            }
        },

    /* ------------------------------------------------------------------------------------
     * 7. MORE THAN ONE WRITER — a pair of indexes shared by several installations
     * --------------------------------------------------------------------------------- */

    'two installations tailing identically named log files do not overwrite each other'
        => static function (): void {
            $raw = [
                'remote_addr' => '198.51.100.7',
                'time'        => '10/Sep/2026:12:00:00 +0000',
                'request'     => 'GET / HTTP/1.1',
                'status'      => '200',
                'bytes'       => '512',
            ];
            $path = '/var/log/apache2/access.log';

            $a = (new Parser(['install_id' => 'aaaa1111', 'keep_raw' => false]))->normalize($raw, $path, 0);
            $b = (new Parser(['install_id' => 'bbbb2222', 'keep_raw' => false]))->normalize($raw, $path, 0);

            lh_true(
                $a['id'] !== $b['id'],
                'the SAME file at the SAME offset on two machines must not produce the same document '
                . 'id. A duplicate uniqueKey in Solr is a delete-and-add, so each installation would '
                . 'have silently overwritten the other\'s traffic, one request at a time, with no '
                . 'error anywhere'
            );

            lh_same('aaaa1111', $a['install_s'], 'and each document names its writer');
            lh_same('bbbb2222', $b['install_s']);

            $again = (new Parser(['install_id' => 'aaaa1111', 'keep_raw' => false]))->normalize($raw, $path, 0);
            lh_same($a['id'], $again['id'], 'while re-ingest by the same installation is still idempotent, '
                . 'which is what lets the tailer restart from a stale offset safely');
        },

    'an installation id that is not one is ignored rather than trusted into a delete query'
        => static function (): void {
            foreach (['../etc', 'AAAA', 'zz', 'a b', 'abc!', str_repeat('a', 40), ''] as $bad) {
                $doc = (new Parser(['install_id' => $bad, 'keep_raw' => false]))->normalize([
                    'remote_addr' => '198.51.100.7',
                    'time'        => '10/Sep/2026:12:00:00 +0000',
                    'request'     => 'GET / HTTP/1.1',
                    'status'      => '200',
                    'bytes'       => '512',
                ], '/var/log/apache2/access.log', 0);

                lh_no_key((array) $doc, 'install_s', 'refused an unusable install id: ' . lh_show($bad));
            }

            /* And with no id the ids are byte-identical to the ones this parser has always
               produced, so an upgrade does not re-key an existing index. */
            $plain = (new Parser(['keep_raw' => false]))->normalize([
                'remote_addr' => '198.51.100.7',
                'time'        => '10/Sep/2026:12:00:00 +0000',
                'request'     => 'GET / HTTP/1.1',
                'status'      => '200',
                'bytes'       => '512',
            ], '/var/log/apache2/access.log', 0);

            lh_same(sha1('/var/log/apache2/access.log:0'), $plain['id'], 'unchanged without an install id');
        },

    'a session id carries enough entropy that two installations cannot mint the same one'
        => static function (): void {
            $state = (string) file_get_contents(__DIR__ . '/../src/State.php');

            lh_contains(
                $state,
                "sha1(\$clientKey . '|' . \$firstTsMs . '|' . bin2hex(random_bytes(16)))",
                'a log-backed session id is salted with 16 cryptographically random bytes, so it is '
                . 'not a function of anything two machines could share'
            );
            lh_contains(
                lh_sa_collector(),
                'bin2hex(random_bytes(20))',
                'and a collector-minted one is 20 random bytes with no derived component at all'
            );
        },

    'retention refuses to delete on a shared pair it cannot name its own documents in'
        => static function (): void {
            $src = (string) file_get_contents(__DIR__ . '/../bin/loghound-retention');

            lh_contains($src, 'function sharedPair(', 'sharing is detected, not configured');
            lh_contains($src, 'function installScope(', 'and turned into a filter clause');
            lh_contains($src, "field' => 'install_s'", 'from a facet on the writer field');

            $probe = (string) strstr($src, 'function sharedPairProbe(');
            $probe = substr($probe, 0, 1400);
            lh_contains(
                $probe,
                'return true;',
                'a failure to establish that we are alone answers "shared". An installation with a '
                . '90-day policy must not be able to delete a neighbour\'s 365 days because a facet '
                . 'query timed out'
            );

            $scope = (string) strstr($src, 'function installScope(');
            $scope = substr($scope, 0, 700);
            lh_contains($scope, "return '';", 'not shared: delete unscoped, exactly as before');
            lh_contains($scope, 'return false;', 'shared with no usable id: there is no safe delete');
            lh_contains($scope, "'+' . Solr::termFilter('install_s', \$installId)", 'otherwise scope it');

            lh_contains($src, '$failed = true;', 'and a pass that could not run makes the exit code say so — '
                . 'a cron that exits 0 having silently not applied a retention policy is worse than '
                . 'one that fails');
        },

    'the daily rollup is never stamped with a writer, because every writer produces the same one'
        => static function (): void {
            $src = lh_sa_scorer();

            $rollup = (string) strstr($src, 'function computeRollup(');
            lh_false(
                str_contains($rollup, "'install_s'"),
                'a rollup describes the INDEX, not an installation. Several installations sharing a '
                . 'pair each recompute the same day from the same documents and write identical '
                . 'values at the same deterministic id, so a writer stamp would flap between runs '
                . 'and mean nothing'
            );
            lh_contains($rollup, "'id'         => 'rollup_daily:' . \$day", 'the id is deterministic, which is '
                . 'what makes the convergence exact rather than merely likely');
        },

    'the installation stamp is on the session document, and validated before it gets there'
        => static function (): void {
            $src = lh_sa_scorer();

            // The D modifier is part of the assertion, not decoration: without it PCRE's `$`
            // matches before a trailing newline, so "abc123\n" passed a check whose whole job is
            // to bound what reaches a field that delete queries are built from.
            lh_contains($src, "\$installId = preg_match('/^[a-f0-9]{4,32}\$/D', \$installId) === 1 ? \$installId : '';",
                'the value is validated to the shape Config::coreName demands, so a hand-edited '
                . 'configuration cannot put an arbitrary string into a field delete queries are '
                . 'built from');
            lh_contains($src, "\$doc['install_s'] = \$installId;", 'and it lands on the document');
        },

    /* ------------------------------------------------------------------------------------
     * 8. THE SESSION AGGREGATE — terms across a whole visit
     * --------------------------------------------------------------------------------- */

    'a session collects every search it ran, not just the one it arrived on'
        => static function (): void {
            $state = new class {
                private array $rows = [];
                private int $n = 0;

                public function findOpenSession(string $ck, int $idle, int $ts): ?array
                {
                    return $this->rows[$ck] ?? null;
                }

                public function openSession(string $ck, int $ts, ?string $host, array $data): string
                {
                    $this->n++;
                    $this->rows[$ck] = [
                        'session_id' => 's' . $this->n,
                        'client_key' => $ck,
                        'first_ts'   => $ts,
                        'last_ts'    => $ts,
                        'hits'       => 0,
                        'data'       => $data,
                    ];
                    return 's' . $this->n;
                }

                public function updateSession(string $id, int $ts, int $delta = 1, ?array $data = null): void
                {
                    foreach ($this->rows as $ck => $row) {
                        if ($row['session_id'] === $id) {
                            $this->rows[$ck]['last_ts'] = $ts;
                            $this->rows[$ck]['hits'] += $delta;
                            if ($data !== null) {
                                $this->rows[$ck]['data'] = $data;
                            }
                        }
                    }
                }

                public function row(string $id): array
                {
                    foreach ($this->rows as $row) {
                        if ($row['session_id'] === $id) {
                            return $row;
                        }
                    }
                    return [];
                }
            };

            $sessionizer = new Sessionizer($state, ['ingest' => ['session_idle_sec' => 1800]]);

            $base = [
                'ip_s' => '198.51.100.7', 'ip_net_s' => '198.51.100.0/24',
                'ua_s' => 'Mozilla/5.0 Chrome/131.0.0.0', 'ua_hash_s' => sha1('ua'),
                'kind_s' => 'html', 'status_i' => 200, 'host_s' => 'search.opensolr.com',
            ];

            $sessionizer->assign($base + ['path_s' => '/search', '_ts_ms' => 1000, 'search_terms_ss' => ['zebra']]);
            $sessionizer->assign($base + ['path_s' => '/search', '_ts_ms' => 2000, 'search_terms_ss' => ['apple']]);
            $sessionizer->assign($base + ['path_s' => '/search', '_ts_ms' => 3000, 'search_terms_ss' => ['zebra']]);

            $data = $state->row('s1')['data'];
            $terms = array_keys((array) $data['terms']);
            sort($terms);

            lh_same(['apple', 'zebra'], $terms, 'a union across the visit, de-duplicated — '
                . 'a visitor who searched three times searched three times, and taking only the first '
                . 'would answer "what did people search for" with the entry query and call it the visit');
        },

    'the session document carries the terms, and the scorer writes the field only when there are some'
        => static function (): void {
            $src = lh_sa_scorer();

            lh_contains($src, "if (!empty(\$session['terms'])) {", 'guarded');
            lh_contains($src, "\$doc['search_terms_ss'] = array_values(\$session['terms']);", 'and written as a list');
        },

    /* ------------------------------------------------------------------------------------
     * 9. THE PANEL — a dimension nobody can find is not delivered
     * --------------------------------------------------------------------------------- */

    'the search terms have a card, and it tells the two empty states apart'
        => static function (): void {
            $php = (string) file_get_contents(__DIR__ . '/../src/Panel/Overview.php');
            $js  = (string) file_get_contents(__DIR__ . '/../public/assets/js/views/overview.js');

            lh_contains($php, "'searches' => \$this->searches()", 'the view answers for it');
            lh_contains($php, "'field' => 'search_terms_ss'", 'faceting the real field');
            lh_contains($php, 'searchesCard()', 'and renders a card');
            lh_contains($js, "api('overview', 'searches')", 'which the front end loads');

            lh_contains(
                $js,
                'if (!data.configured.length) {',
                'nothing configured is a DIFFERENT empty state from nothing searched: a card reading '
                . '"no data" for a feature that was never switched on sends an operator hunting for a '
                . 'bug in their own search page'
            );
            lh_contains($js, 'beacon.query_params', 'so the message names the setting');
            lh_contains($js, "dimRow('search_terms_ss'", 'and every row is clickable through to the filter');
        },

    'the search-term count says it counts sessions, not searches'
        => static function (): void {
            $js = (string) file_get_contents(__DIR__ . '/../public/assets/js/views/overview.js');
            lh_contains(
                $js,
                'not as the number of ',
                'the caption states the denominator. A per-session union presented as a search count '
                . 'would be the flattering number under the honest one\'s name'
            );
        },

    'the virtual hosts table marks which rows have no access log behind them'
        => static function (): void {
            $php = (string) file_get_contents(__DIR__ . '/../src/Panel/Hosts.php');
            $js  = (string) file_get_contents(__DIR__ . '/../public/assets/js/views/hosts.js');

            lh_contains($php, "'q' => 'planes_s:beacon_only'", 'counted per host, not once for the page');
            lh_contains($php, "'single_plane'  =>", 'every session on the host');
            lh_contains($php, "'mixed_planes'  =>", 'or only some of them, which is a different situation');

            lh_contains($js, 'function planeName(', 'the mark is on the row');
            lh_contains($js, 'beacon only', 'and says what it is');
            lh_contains(
                $js,
                'one plane is the plane a ',
                'and the caption explains what that costs, because the whole argument of the product '
                . 'is that a single plane can be faked'
            );
        },

    'the timing card admits when its four numbers cover different populations'
        => static function (): void {
            $php = (string) file_get_contents(__DIR__ . '/../src/Panel/Overview.php');
            $js  = (string) file_get_contents(__DIR__ . '/../public/assets/js/views/overview.js');

            lh_contains($php, 'ov-timing-planes', 'there is a note');
            lh_contains($php, 'no log span at all', 'saying what a beacon-only session contributes to');
            lh_contains($js, 'planes.hidden = !t.beacon_only;', 'revealed only when the range actually mixes '
                . 'them, because a panel explaining absent caveats is one nobody reads');
        },

    /* ------------------------------------------------------------------------------------
     * 10. THE STATE STORE — still not one interpolated value
     * --------------------------------------------------------------------------------- */

    'the new state query binds its parameters like every other one in the file'
        => static function (): void {
            $src = (string) file_get_contents(__DIR__ . '/../src/State.php');

            lh_contains($src, 'public function unmergedBeaconGroups(', 'the method exists');

            $fn = (string) strstr($src, 'public function unmergedBeaconGroups(');
            $fn = substr($fn, 0, 1500);

            lh_contains($fn, 'LIMIT :lim', 'the limit is a bound parameter');
            lh_contains($fn, 'Security::clampInt($limit', 'and clamped before it gets there');
            lh_false(str_contains($fn, '" . $'), 'nothing is interpolated into the SQL');
            lh_false(str_contains($fn, "' . \$"), 'in either quoting style');
        },

    'beaconsFor returns the staged session id, which is what makes supersession possible'
        => static function (): void {
            $src = (string) file_get_contents(__DIR__ . '/../src/State.php');
            lh_contains($src, 'SELECT id, session_id, received_at, payload FROM beacon_staging', 'selected');
            lh_contains($src, "'session_id'  => (string) (\$row['session_id'] ?? ''),", 'and returned');
        },

];
