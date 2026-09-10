<?php
/**
 * Loghound — tests for src/Solr.php.
 *
 * NO NETWORK. Every test injects a transport closure, so the whole file runs on an
 * air-gapped box exactly as SPEC §12 requires. What is being tested is the request Solr
 * WOULD have received, which is the only thing that matters for the security guarantees:
 * a guard that "works" but still emits `shards=http://evil/` is not a guard.
 *
 * Returns an array of name => closure. Each closure throws on failure and returns nothing
 * on success, so any runner that catches exceptions can drive it. The file is also
 * directly executable (`php tests/test_solr.php`) for use before tests/run.php exists.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Security;
use Loghound\Solr;

// ============================================================================================
// Helpers
// ============================================================================================

/**
 * Assert a condition, or throw with a useful message.
 */
$ok = static function (bool $cond, string $message): void {
    if (!$cond) {
        throw new \RuntimeException('FAILED: ' . $message);
    }
};

/**
 * Assert two values are identical.
 *
 * @param mixed $expected
 * @param mixed $actual
 */
$same = static function ($expected, $actual, string $message): void {
    if ($expected !== $actual) {
        throw new \RuntimeException(
            'FAILED: ' . $message
            . "\n  expected: " . var_export($expected, true)
            . "\n  actual:   " . var_export($actual, true)
        );
    }
};

/**
 * Assert that a callable throws, optionally with a message containing a needle.
 */
$throws = static function (callable $fn, string $needle, string $message): void {
    try {
        $fn();
    } catch (\Throwable $e) {
        if ($needle !== '' && stripos($e->getMessage(), $needle) === false) {
            throw new \RuntimeException(
                'FAILED: ' . $message . ' — threw, but message was: ' . $e->getMessage()
            );
        }
        return;
    }
    throw new \RuntimeException('FAILED: ' . $message . ' — nothing was thrown.');
};

/**
 * Build a Solr client whose transport records requests instead of sending them.
 *
 * @param array<int,array<string,mixed>> $captured Filled in by reference.
 * @param array<int,array<string,mixed>> $responses Queue of canned responses; the last one
 *                                                  repeats once exhausted.
 */
$client = static function (array &$captured, array $responses = []): Solr {
    $captured = [];
    $default = ['status' => 200, 'body' => '{"responseHeader":{"status":0},"response":{"numFound":0,"docs":[]}}', 'error' => ''];

    $transport = static function (array $req) use (&$captured, &$responses, $default): array {
        $captured[] = $req;
        if ($responses === []) {
            return $default;
        }
        return count($responses) > 1 ? array_shift($responses) : $responses[0];
    };

    return new Solr([
        'base_url'  => 'https://fi.solrcluster.com/solr',
        'http_user' => 'lh',
        'http_pass' => 'secret',
        'timeout'   => 5,
    ], $transport);
};

/**
 * Decode the form-encoded body of a captured request into a parameter map, preserving
 * repeated keys as lists.
 *
 * @return array<string,array<int,string>>
 */
$decodeBody = static function (string $body): array {
    $out = [];
    foreach (explode('&', $body) as $pair) {
        if ($pair === '') {
            continue;
        }
        [$k, $v] = array_pad(explode('=', $pair, 2), 2, '');
        $out[rawurldecode($k)][] = rawurldecode($v);
    }
    return $out;
};

// ============================================================================================
// Tests
// ============================================================================================

$tests = [];

// --------------------------------------------------------------------------------------------
// Denied parameters — each one maps to a concrete attack, listed in Solr::DENIED_PARAMS.
// --------------------------------------------------------------------------------------------

$tests['solr: refuses caller-supplied shards (SSRF with the response relayed back)'] =
    static function () use ($client, $throws) {
        $cap = [];
        $solr = $client($cap);
        $throws(
            static fn() => $solr->query('hits', ['q' => '*:*', 'shards' => 'http://169.254.169.254/']),
            'refused',
            'shards must be refused'
        );
        $throws(
            static fn() => $solr->query('hits', ['q' => '*:*', 'shards.tolerant' => 'true']),
            'refused',
            'shards.* prefix must be refused'
        );
    };

$tests['solr: refuses stream.url / stream.file / stream.body (SSRF, file read, blind delete)'] =
    static function () use ($client, $throws) {
        $cap = [];
        $solr = $client($cap);
        foreach (['stream.url' => 'http://127.0.0.1:8983/', 'stream.file' => '/etc/passwd', 'stream.body' => '<delete><query>*:*</query></delete>'] as $k => $v) {
            $throws(
                static fn() => $solr->query('hits', ['q' => '*:*', $k => $v]),
                'refused',
                $k . ' must be refused'
            );
        }
    };

$tests['solr: refuses qt (handler re-dispatch) and wt (response writer / XSLT)'] =
    static function () use ($client, $throws) {
        $cap = [];
        $solr = $client($cap);
        $throws(static fn() => $solr->query('hits', ['q' => '*:*', 'qt' => '/stream']), 'refused', 'qt must be refused');
        $throws(static fn() => $solr->query('hits', ['q' => '*:*', 'wt' => 'xslt']), 'refused', 'wt must be refused');
        $throws(static fn() => $solr->query('hits', ['q' => '*:*', 'tr' => 'evil.xsl']), 'refused', 'tr must be refused');
    };

$tests['solr: refuses expr / stmt / sql (streaming expressions = RCE)'] =
    static function () use ($client, $throws) {
        $cap = [];
        $solr = $client($cap);
        foreach (['expr', 'stmt', 'sql'] as $k) {
            $throws(static fn() => $solr->query('hits', ['q' => '*:*', $k => 'x']), 'refused', $k . ' must be refused');
        }
    };

$tests['solr: refuses distrib and defType'] =
    static function () use ($client, $throws) {
        $cap = [];
        $solr = $client($cap);
        $throws(static fn() => $solr->query('hits', ['q' => '*:*', 'distrib' => 'true']), 'refused', 'distrib must be refused');
        // defType is refused because it silently breaks the {!edismax v=$uq} idiom.
        $throws(static fn() => $solr->query('hits', ['q' => '*:*', 'defType' => 'edismax']), 'refused', 'defType must be refused');
    };

$tests['solr: refuses a parameter name containing injection characters'] =
    static function () use ($client, $throws) {
        $cap = [];
        $solr = $client($cap);
        $throws(
            static fn() => $solr->query('hits', ["q\n&shards" => '*:*']),
            'illegal parameter name',
            'a parameter name with a newline must be refused'
        );
    };

// --------------------------------------------------------------------------------------------
// Clamping
// --------------------------------------------------------------------------------------------

$tests['solr: clamps rows and start (deep paging is a DoS)'] =
    static function () use ($client, $same, $decodeBody) {
        $cap = [];
        $solr = $client($cap);
        $solr->query('hits', ['q' => '*:*', 'rows' => 999999, 'start' => 99999999]);
        $body = $decodeBody((string) $cap[0]['body']);
        $same((string) Security::MAX_ROWS, $body['rows'][0], 'rows must be clamped to MAX_ROWS');
        $same((string) Security::MAX_START, $body['start'][0], 'start must be clamped to MAX_START');

        $solr->query('hits', ['q' => '*:*', 'rows' => -5, 'start' => 'drop table']);
        $body = $decodeBody((string) $cap[1]['body']);
        $same('0', $body['rows'][0], 'a negative rows must clamp to 0');
        $same('0', $body['start'][0], 'a non-numeric start must fall back to the default');
    };

// --------------------------------------------------------------------------------------------
// sort / fl / fq
// --------------------------------------------------------------------------------------------

$tests['solr: validates sort field names and directions'] =
    static function () use ($client, $throws, $same, $decodeBody) {
        $cap = [];
        $solr = $client($cap);

        $solr->query('sessions', ['q' => '*:*', 'sort' => 'ts_start desc, bot_score_f ASC']);
        $body = $decodeBody((string) $cap[0]['body']);
        $same('ts_start desc,bot_score_f asc', $body['sort'][0], 'sort must be normalised');

        $throws(
            static fn() => $solr->query('sessions', ['q' => '*:*', 'sort' => 'query(sub(1,2)) desc']),
            'unsafe sort',
            'a function query in sort must be refused'
        );
        $throws(
            static fn() => $solr->query('sessions', ['q' => '*:*', 'sort' => 'ts_start desc; drop']),
            'unsafe sort',
            'junk in sort must be refused'
        );
    };

$tests['solr: refuses fl=* and function pseudo-fields'] =
    static function () use ($client, $throws, $same, $decodeBody) {
        $cap = [];
        $solr = $client($cap);

        $solr->query('hits', ['q' => '*:*', 'fl' => 'id, path_s ,score']);
        $body = $decodeBody((string) $cap[0]['body']);
        $same('id,path_s,score', $body['fl'][0], 'fl must be normalised');

        // fl=* would start returning raw_s — the whole attacker-controlled log line.
        $throws(static fn() => $solr->query('hits', ['q' => '*:*', 'fl' => '*']), 'unsafe field in fl', 'fl=* must be refused');
        $throws(
            static fn() => $solr->query('hits', ['q' => '*:*', 'fl' => 'id,sum(bytes_l,1)']),
            'unsafe field in fl',
            'a function in fl must be refused'
        );
    };

$tests['solr: refuses local parameters in fq except facet tags'] =
    static function () use ($client, $throws) {
        $cap = [];
        $solr = $client($cap);

        // {!tag=} and {!ex=} are ours and harmless.
        $solr->query('sessions', ['q' => '*:*', 'fq' => ['{!tag=verdict}bot_verdict_s:"bot"']]);

        // Everything else changes the parser mid-filter.
        $throws(
            static fn() => $solr->query('sessions', ['q' => '*:*', 'fq' => ['{!frange l=0}sum(bytes_l,1)']]),
            'local parameters',
            '{!frange} must be refused'
        );
        $throws(
            static fn() => $solr->query('sessions', ['q' => '*:*', 'fq' => ['{!join from=a to=b}x:y']]),
            'local parameters',
            '{!join} must be refused'
        );
        $throws(
            static fn() => $solr->query('sessions', ['q' => '*:*', 'fq' => ['id:1 OR _query_:"{!xmlparser v=\'x\'}"']]),
            'magic field',
            '_query_ must be refused'
        );
        $throws(
            static fn() => $solr->query('sessions', ['q' => '*:*', 'fq' => ["id:1\nrows=999"]]),
            'control character',
            'a newline in fq must be refused'
        );
    };

$tests['solr: repeated fq parameters are encoded as repeated keys, not fq[0]'] =
    static function () use ($client, $same, $ok, $decodeBody) {
        $cap = [];
        $solr = $client($cap);
        $solr->query('sessions', ['q' => '*:*', 'fq' => ['a_s:"1"', 'b_s:"2"']]);
        $body = $decodeBody((string) $cap[0]['body']);
        $ok(isset($body['fq']), 'fq must be present under the literal key "fq"');
        $same(2, count($body['fq']), 'both fq values must survive');
        $ok(!isset($body['fq[0]']), 'http_build_query style fq[0] would be silently ignored by Solr');
    };

// --------------------------------------------------------------------------------------------
// Free text — the bound-parameter idiom
// --------------------------------------------------------------------------------------------

$tests['solr: user text is bound as uq and never spliced into q'] =
    static function () use ($client, $same, $ok, $decodeBody) {
        $cap = [];
        $solr = $client($cap);

        // A search string engineered to break out of a naively concatenated query.
        $evil = 'foo") OR path_s:* AND {!frange}sub(1,1) OR "';
        $solr->queryText('hits', $evil);

        $body = $decodeBody((string) $cap[0]['body']);
        $same('{!edismax v=$uq}', $body['q'][0], 'q must be the fixed bound-parameter form');
        $same($evil, $body['uq'][0], 'the raw text must travel intact as its own parameter');
        $ok(!isset($body['defType']), 'defType must never be set: it breaks the {!...} switch');
        $ok(isset($body['qf']), 'qf must be set');
        $ok(str_contains($body['qf'][0], 'path_txt^3'), 'qf must carry the documented boosts');
    };

$tests['solr: a leading local-param block is stripped from user text'] =
    static function () use ($client, $same, $decodeBody) {
        $cap = [];
        $solr = $client($cap);
        $solr->queryText('hits', '{!xmlparser v="x"}swiftshader');
        $body = $decodeBody((string) $cap[0]['body']);
        $same('swiftshader', $body['uq'][0], 'a leading {!...} must be stripped from bound text');
    };

$tests['solr: an empty search box means match-all, not match-nothing'] =
    static function () use ($client, $same, $ok, $decodeBody) {
        $cap = [];
        $solr = $client($cap);
        $solr->queryText('hits', "   \t ");
        $body = $decodeBody((string) $cap[0]['body']);
        $same('*:*', $body['q'][0], 'blank input must become *:*');
        $ok(!isset($body['uq']), 'uq must not be sent for a blank query');
    };

// --------------------------------------------------------------------------------------------
// Builders
// --------------------------------------------------------------------------------------------

$tests['solr: escapeTerm quotes and strips control characters'] =
    static function () use ($same) {
        $same('"a\\"b"', Solr::escapeTerm('a"b'), 'a quote must be escaped');
        $same('"a\\\\b"', Solr::escapeTerm('a\\b'), 'a backslash must be escaped');
        $same('"ab"', Solr::escapeTerm("a\nb"), 'a newline must be stripped, not escaped');
        // Solr syntax inside quotes is literal, which is the whole point.
        $same('"a:b AND c"', Solr::escapeTerm('a:b AND c'), 'query syntax must be quoted, not interpreted');
    };

$tests['solr: termsFilter with an empty list matches nothing, not everything'] =
    static function () use ($same) {
        // The classic authorisation-filter data leak: an empty IN-list that silently
        // becomes "no filter".
        $same('(-*:*)', Solr::termsFilter('ip_s', []), 'an empty terms filter must match nothing');
        $same('ip_s:("1.2.3.4" OR "5.6.7.8")', Solr::termsFilter('ip_s', ['1.2.3.4', '5.6.7.8']), 'terms filter shape');
    };

$tests['solr: builders refuse an unsafe field name'] =
    static function () use ($throws) {
        $throws(static fn() => Solr::termFilter('ip_s:x OR y', 'v'), 'unsafe field', 'termFilter field validation');
        $throws(static fn() => Solr::termsFilter('a b', ['v']), 'unsafe field', 'termsFilter field validation');
        $throws(static fn() => Solr::rangeFilter('a-b', '1', '2'), 'unsafe field', 'rangeFilter field validation');
    };

$tests['solr: rangeFilter accepts only numbers, ISO instants and date math'] =
    static function () use ($same, $throws) {
        $same('ts:[* TO 2026-09-10T00:00:00Z]', Solr::rangeFilter('ts', null, '2026-09-10T00:00:00Z'), 'ISO bound');
        $same('ts:[NOW-12HOURS TO NOW]', Solr::rangeFilter('ts', 'NOW-12HOURS', 'NOW'), 'date math bound');
        $same('bytes_l:[100 TO 2000]', Solr::rangeFilter('bytes_l', '100', '2000'), 'numeric bound');
        $same('ts:[* TO *]', Solr::rangeFilter('ts', null, null), 'open bound');
        $throws(static fn() => Solr::rangeFilter('ts', '* TO *] OR id:[*', null), 'invalid range bound', 'range bound injection');
    };

// --------------------------------------------------------------------------------------------
// JSON Facet
// --------------------------------------------------------------------------------------------

$tests['solr: jsonFacet validates fields, aggregates and limits'] =
    static function () use ($client, $same, $ok, $decodeBody) {
        $cap = [];
        $solr = $client($cap);

        $solr->jsonFacet(
            'hits',
            ['q' => '*:*', 'fq' => [Solr::termsFilter('fp_hash_s', ['aaa', 'bbb'])]],
            ['by_fp' => ['type' => 'terms', 'field' => 'fp_hash_s', 'limit' => 500, 'facet' => ['ips' => 'unique(ip_s)']]]
        );

        $body = $decodeBody((string) $cap[0]['body']);
        $same('0', $body['rows'][0], 'a facet request must not fetch documents');
        $facet = json_decode($body['json.facet'][0], true);
        $same('terms', $facet['by_fp']['type'], 'facet type must survive');
        $same('fp_hash_s', $facet['by_fp']['field'], 'facet field must survive');
        $same('unique(ip_s)', $facet['by_fp']['facet']['ips'], 'the aggregate must survive');
        $ok($facet['by_fp']['limit'] <= 10000, 'the limit must be clamped');
    };

$tests['solr: jsonFacet refuses arbitrary function queries and unknown aggregates'] =
    static function () use ($client, $throws) {
        $cap = [];
        $solr = $client($cap);

        $throws(
            static fn() => $solr->jsonFacet('hits', ['q' => '*:*'], ['x' => ['type' => 'func', 'func' => 'sum(a)']]),
            'unsupported facet type',
            'facet type func must be refused'
        );
        $throws(
            static fn() => $solr->jsonFacet('hits', ['q' => '*:*'], ['x' => 'exec(ip_s)']),
            'not on the allowlist',
            'an aggregate outside the allowlist must be refused'
        );
        $throws(
            static fn() => $solr->jsonFacet('hits', ['q' => '*:*'], ['x' => ['type' => 'terms', 'field' => 'a:b']]),
            'unsafe facet field',
            'an unsafe facet field must be refused'
        );
        $throws(
            static fn() => $solr->jsonFacet('hits', ['q' => '*:*'], ['x' => ['type' => 'query', 'q' => '{!frange}x']]),
            'local parameters',
            'a local param in a query facet must be refused'
        );
    };

$tests['solr: query() refuses a pre-serialised json.facet string'] =
    static function () use ($client, $throws) {
        $cap = [];
        $solr = $client($cap);
        $throws(
            static fn() => $solr->query('hits', ['q' => '*:*', 'json.facet' => '{"x":"unique(ip_s)"}']),
            'refused',
            'a raw json.facet blob cannot be validated and must be refused'
        );
        $throws(
            static fn() => $solr->query('hits', ['q' => '*:*', 'json' => '{"query":"*:*"}']),
            'refused',
            'the json parameter must be refused too'
        );
    };

// --------------------------------------------------------------------------------------------
// Writes
// --------------------------------------------------------------------------------------------

$tests['solr: addDocs uses softCommit and never commit=true'] =
    static function () use ($client, $ok, $same) {
        $cap = [];
        $solr = $client($cap, [['status' => 200, 'body' => '{"responseHeader":{"status":0}}', 'error' => '']]);
        $solr->addDocs('hits', [['id' => 'a', 'path_s' => '/x']], true);

        $url = (string) $cap[0]['url'];
        $ok(str_contains($url, '/hits/update'), 'must post to the update handler');
        $ok(str_contains($url, 'softCommit=true'), 'softCommit must be requested');
        $ok(!str_contains($url, 'commit=true'), 'a hard commit per batch would destroy throughput');
        $same('POST', $cap[0]['method'], 'updates are POSTed');

        $docs = json_decode((string) $cap[0]['body'], true);
        $same('a', $docs[0]['id'], 'the document must be sent as a JSON array');
    };

$tests['solr: addDocs survives invalid UTF-8 in a log line'] =
    static function () use ($client, $ok) {
        $cap = [];
        $solr = $client($cap, [['status' => 200, 'body' => '{"responseHeader":{"status":0}}', 'error' => '']]);
        // A request path is bytes, not text. json_encode would return false on this and
        // silently drop the whole batch without JSON_INVALID_UTF8_SUBSTITUTE.
        $solr->addDocs('hits', [['id' => 'a', 'path_s' => "/bad\xC3\x28path"]]);
        $ok(count($cap) === 1, 'the batch must still be sent');
        $ok(json_decode((string) $cap[0]['body'], true) !== null, 'the body must be valid JSON');
    };

$tests['solr: deleteByQuery refuses an empty query and refuses *:* without the flag'] =
    static function () use ($client, $throws, $ok) {
        $cap = [];
        $solr = $client($cap, [['status' => 200, 'body' => '{"responseHeader":{"status":0}}', 'error' => '']]);

        $throws(static fn() => $solr->deleteByQuery('hits', ''), 'empty delete', 'an empty delete query must be refused');
        $throws(static fn() => $solr->deleteByQuery('hits', '*:*'), 'allowDeleteAll', 'delete-all needs an explicit flag');
        $throws(static fn() => $solr->deleteByQuery('hits', '* : *'), 'allowDeleteAll', 'whitespace must not evade the check');

        $solr->deleteByQuery('hits', Solr::rangeFilter('ts', null, '2026-01-01T00:00:00Z'));
        $body = json_decode((string) $cap[0]['body'], true);
        $ok(isset($body['delete']['query']), 'the delete body shape must be correct');
    };

$tests['solr: atomicUpdate builds the modifier shape and refuses removeregex'] =
    static function () use ($client, $same, $throws) {
        $cap = [];
        $solr = $client($cap, [['status' => 200, 'body' => '{"responseHeader":{"status":0}}', 'error' => '']]);

        $solr->atomicUpdate('sessions', 'sess1', [
            'set' => ['bot_score_f' => 91.0],
            'add' => ['bot_reasons_ss' => ['no_js_on_html']],
        ]);
        $docs = json_decode((string) $cap[0]['body'], true);
        $same('sess1', $docs[0]['id'], 'the id must be plain');
        // json_encode writes 91.0 as "91", so compare after a float cast rather than
        // asserting on a JSON round-trip artefact.
        $same(91.0, (float) $docs[0]['bot_score_f']['set'], 'set modifier shape');
        $same(['no_js_on_html'], $docs[0]['bot_reasons_ss']['add'], 'add modifier shape');

        // removeregex evaluates a caller-supplied regex server-side against every value.
        $throws(
            static fn() => $solr->atomicUpdate('sessions', 'x', ['removeregex' => ['paths_ss' => '(a+)+$']]),
            'removeregex',
            'removeregex must be refused'
        );
        $throws(
            static fn() => $solr->atomicUpdate('sessions', 'x', ['set' => ['a b' => 1]]),
            'unsafe field',
            'an unsafe field name in an atomic update must be refused'
        );
    };

// --------------------------------------------------------------------------------------------
// Transport
// --------------------------------------------------------------------------------------------

$tests['solr: a core name cannot escape into the URL path'] =
    static function () use ($client, $throws) {
        $cap = [];
        $solr = $client($cap);
        $throws(
            static fn() => $solr->query('../admin/cores', ['q' => '*:*']),
            'unsafe core name',
            'path traversal through the core name must be refused'
        );
        $throws(static fn() => $solr->ping('hits?x=1'), 'unsafe core name', 'a query string in the core name must be refused');
    };

$tests['solr: wt=json is forced on the wire'] =
    static function () use ($client, $ok) {
        $cap = [];
        $solr = $client($cap);
        $solr->query('hits', ['q' => '*:*']);
        $ok(str_contains((string) $cap[0]['url'], 'wt=json'), 'wt=json must be forced by the client, not requested by the caller');
    };

$tests['solr: retries a 5xx and does not retry a 4xx'] =
    static function () use ($client, $same, $throws) {
        // 500 then 200: two attempts, success.
        $cap = [];
        $solr = $client($cap, [
            ['status' => 500, 'body' => '{"error":{"msg":"boom"}}', 'error' => ''],
            ['status' => 200, 'body' => '{"responseHeader":{"status":0},"response":{"numFound":7,"docs":[]}}', 'error' => ''],
        ]);
        $res = $solr->query('hits', ['q' => '*:*']);
        $same(2, count($cap), 'a 5xx must be retried');
        $same(7, $res['response']['numFound'], 'the retry result must be returned');

        // 400: one attempt, throws. Retrying a malformed request only makes noise.
        $cap2 = [];
        $solr2 = $client($cap2, [['status' => 400, 'body' => '{"error":{"msg":"unknown field zzz"}}', 'error' => '']]);
        $throws(static fn() => $solr2->query('hits', ['q' => '*:*']), 'unknown field zzz', 'a 400 must surface Solr\'s message');
        $same(1, count($cap2), 'a 4xx must not be retried');
    };

$tests['solr: a transport failure throws rather than returning an empty result'] =
    static function () use ($client, $throws, $same) {
        $cap = [];
        $solr = $client($cap, [['status' => 0, 'body' => '', 'error' => 'Could not resolve host']]);
        $throws(
            static fn() => $solr->query('hits', ['q' => '*:*']),
            'transport failure',
            'an unreachable Solr must throw, never look like "zero results"'
        );
        $same(3, count($cap), 'all three attempts must be made');
    };

$tests['solr: credentials reach the transport but never reach an exception message'] =
    static function () use ($client, $same, $ok) {
        $cap = [];
        $solr = $client($cap, [['status' => 400, 'body' => '{"error":{"msg":"undefined field zzz"}}', 'error' => '']]);

        try {
            $solr->query('hits', ['q' => '*:*']);
            throw new \RuntimeException('FAILED: a 400 should have thrown.');
        } catch (\RuntimeException $e) {
            if (str_starts_with($e->getMessage(), 'FAILED:')) {
                throw $e;
            }
            // Solr's own diagnostic is useful and is passed through...
            $ok(str_contains($e->getMessage(), 'undefined field zzz'), 'Solr\'s message must be surfaced');
            // ...but nothing about the connection may leak into it. This message ends up in
            // a journal, in a support paste, and eventually in a public issue.
            $ok(!str_contains($e->getMessage(), 'secret'), 'the HTTP password must never appear in an exception');
            $ok(!str_contains($e->getMessage(), 'fi.solrcluster.com'), 'the backend host must not leak into an exception');
        }

        $same('lh', $cap[0]['user'], 'the HTTP user must be handed to the transport');
        $same('secret', $cap[0]['pass'], 'the HTTP password must be handed to the transport');
    };

// ============================================================================================
// Standalone runner — used before tests/run.php exists.
// ============================================================================================

if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === realpath(__FILE__)) {
    $pass = 0;
    $fail = 0;
    foreach ($tests as $name => $test) {
        try {
            $test();
            $pass++;
            fwrite(STDOUT, "  ok   $name\n");
        } catch (\Throwable $e) {
            $fail++;
            fwrite(STDOUT, "  FAIL $name\n       " . str_replace("\n", "\n       ", $e->getMessage()) . "\n");
        }
    }
    fwrite(STDOUT, "\n$pass passed, $fail failed\n");
    exit($fail === 0 ? 0 : 1);
}

return $tests;
