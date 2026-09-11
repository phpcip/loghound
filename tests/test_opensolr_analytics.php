<?php
/**
 * Loghound — tests for the Opensolr index-analytics half.
 *
 * Three things are being pinned here, and all three are properties rather than happy paths.
 *
 *  1. **Query-shape normalisation is correct in both directions.** Two queries that differ
 *     only in their literals must land in the same bucket, and two queries that differ in
 *     structure must not. Getting the first wrong makes the whole feature useless; getting
 *     the second wrong makes it lie.
 *
 *  2. **Every failure is a state, not a crash.** An index the account does not own, an
 *     unreachable control plane and a garbled response are ordinary outcomes with sentences
 *     attached. A panel that throws on any of them is a panel that shows a stack trace to
 *     an operator who wanted a diagnosis.
 *
 *  3. **The API key and the hostile bytes stay where they belong.** The key reaches the
 *     request URL and nothing else — not HTML, not a JSON payload, not an error message.
 *     Query text and `full_request` are chosen by whoever queried the customer's index, and
 *     they end up on an operator's screen, so they must survive escaping as text.
 *
 * No test here makes a network call: the platform client takes an injectable transport, and
 * the Solr client already did.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Config;
use Loghound\Opensolr;
use Loghound\OpensolrLog;
use Loghound\OpensolrShape;
use Loghound\Panel\Callers;
use Loghound\Panel\Gateway;
use Loghound\Panel\Indexes;
use Loghound\Panel\JobHost;
use Loghound\Panel\Jobs;
use Loghound\Panel\Queries;
use Loghound\Security;
use Loghound\Solr;

/** The distinctive fake credential every test looks for in places it must not appear. */
const LH_OS_KEY = 'apikey-MUST-NEVER-LEAK-4f2b9c';

/**
 * The hash of one request's shape, from a query string.
 */
function lh_os_hash(string $qs): string
{
    return OpensolrShape::normalise('https://x.solrcluster.com/solr/c/select?' . $qs, 'select')['hash'];
}

/**
 * The readable label of one request's shape.
 */
function lh_os_label(string $qs): string
{
    return OpensolrShape::normalise('https://x.solrcluster.com/solr/c/select?' . $qs, 'select')['label'];
}

/**
 * A platform client whose transport is a queue of canned responses.
 *
 * @param array<int,array<string,mixed>> $responses Popped in order; the last one repeats.
 * @param array<int,array<string,mixed>> $captured  Filled with every request issued.
 */
function lh_os_client(array $responses, array &$captured): OpensolrLog
{
    $queue = $responses;
    $transport = function (array $request) use (&$captured, &$queue): array {
        $captured[] = $request;
        $next = count($queue) > 1 ? array_shift($queue) : ($queue[0] ?? null);
        return $next ?? ['status' => 200, 'body' => '{}', 'error' => ''];
    };

    return new OpensolrLog([
        'api_base' => 'https://opensolr.test/solr_manager/api',
        'email'    => 'owner@example.com',
        'api_key'  => LH_OS_KEY,
    ], $transport);
}

/**
 * A canned Solr response body carrying a result set and optional facets.
 *
 * @param array<int,array<string,mixed>> $docs
 * @param array<string,mixed>            $extra
 */
function lh_os_body(array $docs, ?int $numFound = null, array $extra = []): array
{
    return [
        'status' => 200,
        'body' => (string) json_encode(array_merge([
            'responseHeader' => ['status' => 0],
            'response' => ['numFound' => $numFound ?? count($docs), 'start' => 0, 'docs' => $docs],
        ], $extra)),
        'error' => '',
    ];
}

/** A config with Opensolr credentials and a Solr backend that is never reached. */
function lh_os_config(bool $withKey = true): Config
{
    $cfg = Config::load('/nonexistent-loghound-config');
    $cfg->set('solr.base_url', 'http://127.0.0.1:65535/solr');
    $cfg->set('solr.hits_core', 'lh_os_hits');
    $cfg->set('solr.sessions_core', 'lh_os_sessions');
    $cfg->set('opensolr.email', 'owner@example.com');
    $cfg->set('opensolr.api_key', $withKey ? LH_OS_KEY : '');
    return $cfg;
}

/**
 * A Gateway over the real Solr client with a queued transport, so the panel's own
 * sanitisers judge every filter these views build.
 *
 * @param array<int,array<string,mixed>> $bodies   Response bodies, popped in order.
 * @param array<int,array<string,mixed>> $captured Filled with every request issued.
 */
function lh_os_gateway(array $bodies, array &$captured): Gateway
{
    $queue = $bodies;
    $transport = function (array $request) use (&$captured, &$queue): array {
        $captured[] = $request;
        $next = count($queue) > 1 ? array_shift($queue) : ($queue[0] ?? null);
        return $next ?? ['status' => 200, 'body' => '{"responseHeader":{"status":0},"facets":{"count":0}}', 'error' => ''];
    };

    $cfg = lh_os_config();
    return new Gateway($cfg, new Solr((array) $cfg->get('solr'), $transport), false);
}

/** One request-log document. */
function lh_os_doc(string $request, int $hits = 5, int $qtime = 12, string $ip = '203.0.113.9'): array
{
    return [
        'date' => '2026-09-10T22:39:46Z',
        'ip' => $ip,
        'path' => 'select',
        'q' => 'x',
        'hits' => $hits,
        'qtime' => $qtime,
        'http_status' => 200,
        'size' => 4,
        'param_hostname' => 'de9.solrcluster.com',
        'full_request' => $request,
    ];
}

/**
 * A control-plane client that answers get_index_list with a fixed set of names.
 *
 * @param array<int,string> $names
 */
function lh_os_account(array $names): Opensolr
{
    $body = (string) json_encode(array_map(
        static fn (string $n): array => ['index_name' => $n, 'index_type' => 0],
        $names
    ));

    return new Opensolr(
        ['email' => 'owner@example.com', 'api_key' => LH_OS_KEY],
        static fn (array $req): array => ['status' => 200, 'body' => $body, 'error' => '']
    );
}

/**
 * A Queries view wired for tests: canned request log, canned index list, no network.
 *
 * @param array<int,array<string,mixed>> $responses
 * @param array<int,string>              $owned
 * @param array<int,array<string,mixed>> $captured
 */
function lh_os_queries(array $responses, array $owned, array &$captured): Queries
{
    $solr = [];
    $view = new Queries(lh_os_config(), lh_os_gateway([], $solr));
    $view->setLogClient(lh_os_client($responses, $captured));
    $view->setAccountClient(lh_os_account($owned));
    return $view;
}

/**
 * Call a protected method on a view.
 *
 * The job endpoints are reached through post(), which answers with JSON and exits, so a
 * test cannot drive them without taking the process down with it. The pieces post() is
 * made of — the parameter validation and the plan — are what carry the behaviour worth
 * pinning, so they are called directly.
 *
 * @param array<int,mixed> $args
 * @return mixed
 */
function lh_os_call(object $view, string $method, array $args = [])
{
    return (new ReflectionMethod($view, $method))->invokeArgs($view, $args);
}

/**
 * A job store bound to a throwaway operator identity, carrying a view's own plans.
 *
 * Salted per run for the same reason tests/test_jobs.php salts its own: the store is a real
 * file that outlives the process and start() is idempotent, so a fixed identity would hand
 * the second run of this file the first run's still-pending job.
 *
 * @param array<string,callable> $plans
 */
function lh_os_jobs(string $identity, array $plans): Jobs
{
    static $salt = null;
    if ($salt === null) {
        $salt = bin2hex(random_bytes(8));
    }
    $_SESSION['lh_job_owner'] = 'opensolr-' . $identity . '-' . $salt;
    $_SESSION['lh_user'] = 'tester';

    $captured = [];
    return new Jobs(lh_os_config(), lh_os_gateway([], $captured), $plans);
}


return [

    /* -----------------------------------------------------------------------------
     * Query-shape normalisation
     * -------------------------------------------------------------------------- */

    'differing quoted literals land in the same bucket' => function (): void {
        lh_same(
            lh_os_hash('q=' . rawurlencode('title:"foo"')),
            lh_os_hash('q=' . rawurlencode('title:"bar baz qux"')),
            'shape of a phrase query'
        );
    },

    'differing numeric literals land in the same bucket' => function (): void {
        lh_same(
            lh_os_hash('q=' . rawurlencode('price:12')),
            lh_os_hash('q=' . rawurlencode('price:98765')),
            'shape of a numeric query'
        );
    },

    'differing free text lands in the same bucket however many words' => function (): void {
        lh_same(
            lh_os_hash('q=' . rawurlencode('hello')),
            lh_os_hash('q=' . rawurlencode('a completely different set of words')),
            'shape of bare free text'
        );
    },

    'a different field is a different shape' => function (): void {
        $a = lh_os_hash('q=' . rawurlencode('title:"foo"'));
        $b = lh_os_hash('q=' . rawurlencode('body:"foo"'));
        if ($a === $b) {
            lh_fail('title: and body: must not share a shape');
        }
    },

    'a different boolean structure is a different shape' => function (): void {
        $a = lh_os_hash('q=' . rawurlencode('title:"foo" AND body:"bar"'));
        $b = lh_os_hash('q=' . rawurlencode('title:"foo" OR body:"bar"'));
        if ($a === $b) {
            lh_fail('AND and OR must not share a shape');
        }
    },

    'an extra filter is a different shape' => function (): void {
        $a = lh_os_hash('q=' . rawurlencode('title:"foo"'));
        $b = lh_os_hash('q=' . rawurlencode('title:"foo"') . '&fq=' . rawurlencode('lang:"en"'));
        if ($a === $b) {
            lh_fail('adding an fq must change the shape');
        }
    },

    'parameter order does not change the shape' => function (): void {
        lh_same(
            lh_os_hash('q=' . rawurlencode('title:"a"') . '&rows=10&fl=id,title'),
            lh_os_hash('fl=id,title&rows=10&q=' . rawurlencode('title:"z"')),
            'shape is order independent'
        );
    },

    'a different field list is a different shape' => function (): void {
        $a = lh_os_hash('q=*:*&fl=id,title');
        $b = lh_os_hash('q=*:*&fl=id,body');
        if ($a === $b) {
            lh_fail('fl names fields, so it is structure and must not be normalised away');
        }
    },

    'paging depth does not change the shape' => function (): void {
        lh_same(
            lh_os_hash('q=*:*&rows=10&start=0'),
            lh_os_hash('q=*:*&rows=250&start=9000'),
            'rows and start are numeric'
        );
    },

    'response format and cache busters do not change the shape' => function (): void {
        lh_same(
            lh_os_hash('q=*:*&wt=json&_=1699999999&indent=true'),
            lh_os_hash('q=*:*&wt=xml&_=42'),
            'noise parameters are dropped'
        );
    },

    'local parameters keep their fields but lose their numbers' => function (): void {
        lh_same(
            lh_os_hash('q=' . rawurlencode('{!knn f=vector topK=5}[0.1,0.2]')),
            lh_os_hash('q=' . rawurlencode('{!knn f=vector topK=50}[0.9,0.4]')),
            'topK is a literal, f is structure'
        );
        $a = lh_os_hash('q=' . rawurlencode('{!edismax qf=title v=$uq}'));
        $b = lh_os_hash('q=' . rawurlencode('{!edismax qf=body v=$uq}'));
        if ($a === $b) {
            lh_fail('a different qf inside a local param is a different query');
        }
    },

    'range endpoints collapse but an open end is kept' => function (): void {
        lh_same(
            lh_os_hash('fq=' . rawurlencode('date:[2020-01-01T00:00:00Z TO NOW]')),
            lh_os_hash('fq=' . rawurlencode('date:[2026-05-05T00:00:00Z TO NOW]')),
            'concrete range bounds are literals'
        );
        $bounded = lh_os_hash('fq=' . rawurlencode('date:[2020-01-01T00:00:00Z TO NOW]'));
        $open = lh_os_hash('fq=' . rawurlencode('date:[* TO NOW]'));
        if ($bounded === $open) {
            lh_fail('an open range end is structural and must not collapse to a literal');
        }
    },

    'the handler is part of the shape' => function (): void {
        $select = OpensolrShape::normalise('http://h/solr/c/select?q=*:*', 'select')['hash'];
        $auto = OpensolrShape::normalise('http://h/solr/c/autocomplete?q=*:*', 'autocomplete')['hash'];
        if ($select === $auto) {
            lh_fail('two handlers are two shapes');
        }
    },

    'a shape label never carries the literal it replaced' => function (): void {
        $label = lh_os_label('q=' . rawurlencode('title:"SUPERSECRETSEARCHTERM" AND body:HUSH'));
        if (str_contains($label, 'SUPERSECRETSEARCHTERM') || str_contains($label, 'HUSH')) {
            lh_fail('the literal survived normalisation: ' . $label);
        }
        lh_contains($label, 'title:', 'label keeps the field name');
        lh_contains($label, 'body:', 'label keeps the second field name');
    },

    'a hostile request is normalised without crashing and stays bounded' => function (): void {
        $hostile = 'http://h/solr/c/select?q=' . rawurlencode(str_repeat('a(b)[c]{!d} ', 4000))
            . '&fq=' . rawurlencode(str_repeat('x', 40000))
            . '&' . str_repeat('junk=1&', 400);
        $shape = OpensolrShape::normalise($hostile, 'select');
        lh_true(strlen($shape['hash']) === 40, 'a hash was produced');
        lh_true(mb_strlen($shape['label']) <= 400, 'the label is capped');
    },

    'control characters and null bytes cannot survive into a shape' => function (): void {
        $label = lh_os_label('q=' . rawurlencode("title:\"a\x00b\"\r\nfq=evil"));
        if (preg_match('/[\x00-\x1F\x7F]/', $label)) {
            lh_fail('a control character reached the label');
        }
    },

    /* -----------------------------------------------------------------------------
     * The platform client: failures are states
     * -------------------------------------------------------------------------- */

    'ERROR_NOT_CORE_OWNER is a state, not an exception' => function (): void {
        $captured = [];
        $client = lh_os_client([
            ['status' => 200, 'body' => '{"status":false,"msg":"ERROR_NOT_CORE_OWNER"}', 'error' => ''],
        ], $captured);

        $res = $client->log('somebody_elses_index', ['rows' => 0]);
        lh_same('not_owner', $res['state'], 'ownership refusal');
        lh_same(0, $res['numFound'], 'no rows are invented');
        lh_true($res['message'] !== '', 'the refusal carries a sentence');
        lh_same([], $res['docs'], 'docs is an empty list, not missing');
    },

    'an unreachable control plane is a state, not an exception' => function (): void {
        $captured = [];
        $client = lh_os_client([
            ['status' => 0, 'body' => '', 'error' => 'Could not resolve host: opensolr.test'],
        ], $captured);

        $res = $client->log('lh_index', ['rows' => 0]);
        lh_same('unreachable', $res['state'], 'transport failure');
        lh_has_key($res, 'facet_fields', 'the envelope shape is identical to a success');
        lh_has_key($res, 'stats', 'the envelope shape is identical to a success');
    },

    'a response that is not JSON is a state, not an exception' => function (): void {
        $captured = [];
        $client = lh_os_client([
            ['status' => 200, 'body' => '<html>502 Bad Gateway</html>', 'error' => ''],
        ], $captured);

        lh_same('unreachable', $client->log('lh_index', ['rows' => 0])['state'], 'HTML body');
    },

    'a transport that throws is contained' => function (): void {
        $client = new OpensolrLog(
            ['email' => 'a@b.c', 'api_key' => LH_OS_KEY],
            static function (array $req): array {
                throw new \RuntimeException('curl exploded on ' . $req['url']);
            }
        );
        lh_same('unreachable', $client->log('lh_index', ['rows' => 0])['state'], 'a throwing transport');
    },

    'no credentials is a state the panel can render' => function (): void {
        $client = new OpensolrLog(['email' => '', 'api_key' => '']);
        lh_false($client->isConfigured(), 'isConfigured with no credentials');
        lh_same('not_configured', $client->log('lh_index', ['rows' => 0])['state'], 'unconfigured call');
    },

    /* -----------------------------------------------------------------------------
     * The platform client: bounds and injection
     * -------------------------------------------------------------------------- */

    'rows and start are clamped whatever the caller asks for' => function (): void {
        $captured = [];
        $client = lh_os_client([lh_os_body([])], $captured);
        $client->log('lh_index', ['rows' => 999999, 'start' => 999999999]);

        $url = $captured[0]['url'];
        lh_contains($url, 'rows=' . OpensolrLog::MAX_ROWS, 'rows ceiling');
        lh_contains($url, 'start=' . OpensolrLog::MAX_START, 'start ceiling');
    },

    'negative and non-numeric rows fall back to the default' => function (): void {
        $captured = [];
        $client = lh_os_client([lh_os_body([])], $captured);
        $client->log('lh_index', ['rows' => -50, 'start' => 'DROP TABLE']);

        lh_contains($captured[0]['url'], 'rows=0', 'negative rows clamps to the floor');
        lh_contains($captured[0]['url'], 'start=0', 'garbage start becomes the default');
    },

    'a facet limit cannot exceed its ceiling' => function (): void {
        $captured = [];
        $client = lh_os_client([lh_os_body([])], $captured);
        $client->log('lh_index', ['facet_fields' => ['ip'], 'facet_limit' => 100000]);

        lh_contains($captured[0]['url'], 'facet_limit=' . OpensolrLog::MAX_FACET_LIMIT, 'facet limit ceiling');
    },

    'a local-parameter switch cannot be smuggled into a filter' => function (): void {
        $captured = [];
        $client = lh_os_client([lh_os_body([])], $captured);
        lh_throws(
            static fn () => $client->log('lh_index', ['fq' => ['{!frange l=0}query({!v=$x})']]),
            'a filter containing a parser switch'
        );
        lh_same([], $captured, 'nothing was sent');
    },

    'a filter containing a newline is refused' => function (): void {
        $captured = [];
        $client = lh_os_client([lh_os_body([])], $captured);
        lh_throws(
            static fn () => $client->log('lh_index', ['fq' => ["ip:\"1.2.3.4\"\nwt=xml"]]),
            'a filter containing a newline'
        );
    },

    'a field that is not in the analytics schema is refused' => function (): void {
        $captured = [];
        $client = lh_os_client([lh_os_body([])], $captured);
        lh_throws(
            static fn () => $client->log('lh_index', ['fl' => ['password']]),
            'an unknown field list entry'
        );
        lh_throws(
            static fn () => $client->log('lh_index', ['facet_fields' => ['../../etc/passwd']]),
            'an unknown facet field'
        );
    },

    'an index name that is not an index name is refused as a state' => function (): void {
        $captured = [];
        $client = lh_os_client([lh_os_body([])], $captured);
        lh_same('refused', $client->log('../other/select?', ['rows' => 0])['state'], 'a path as a core name');
        lh_same([], $captured, 'nothing was sent');
    },

    'a value with an ampersand cannot add a parameter' => function (): void {
        $captured = [];
        $client = lh_os_client([lh_os_body([])], $captured);
        $client->log('lh_index', ['fq' => [OpensolrLog::termFq('ip', '1.2.3.4" OR x&wt=xml')]]);

        $url = $captured[0]['url'];
        lh_false(str_contains($url, '&wt=xml'), 'the ampersand was encoded, not passed through');
        lh_contains($url, '%26wt%3Dxml', 'it travels as part of the value');
    },

    'identical calls within one request are answered once' => function (): void {
        $captured = [];
        $client = lh_os_client([lh_os_body([lh_os_doc('http://h/solr/c/select?q=*:*')])], $captured);

        $client->log('lh_index', ['rows' => 10, 'fq' => ['date:[NOW-1DAY TO NOW]']]);
        $client->log('lh_index', ['rows' => 10, 'fq' => ['date:[NOW-1DAY TO NOW]']]);

        lh_same(1, count($captured), 'the second identical call was memoised');
    },

    'facets and stats come back as maps rather than alternating lists' => function (): void {
        $captured = [];
        $client = lh_os_client([lh_os_body([], 7, [
            'facet_counts' => [
                'facet_fields' => ['ip' => ['1.1.1.1', 4, '2.2.2.2', 3]],
                'facet_ranges' => ['hits' => ['counts' => ['0', 2], 'gap' => 1, 'start' => 0, 'after' => 5]],
            ],
            'stats' => ['stats_fields' => ['qtime' => ['count' => 7, 'min' => 1, 'max' => 90, 'mean' => 11.5]]],
        ])], $captured);

        $res = $client->log('lh_index', ['facet_fields' => ['ip']]);
        lh_same(['1.1.1.1' => 4, '2.2.2.2' => 3], $res['facet_fields']['ip'], 'terms facet');
        lh_same(2, $res['facet_ranges']['hits']['counts']['0'], 'range facet bucket');
        lh_same(5, $res['facet_ranges']['hits']['after'], 'range facet after counter');
        lh_same(90.0, $res['stats']['qtime']['max'], 'stats max');
    },

    /* -----------------------------------------------------------------------------
     * The API key
     * -------------------------------------------------------------------------- */

    'the API key reaches the request and nothing else' => function (): void {
        $captured = [];
        $client = lh_os_client([lh_os_body([])], $captured);
        $res = $client->log('lh_index', ['rows' => 0]);

        lh_contains($captured[0]['url'], rawurlencode(LH_OS_KEY), 'the key is on the wire');
        lh_false(
            str_contains((string) json_encode($res), LH_OS_KEY),
            'the key is not in the result envelope'
        );
    },

    'an error that quotes the request is redacted before it escapes' => function (): void {
        $captured = [];
        $client = lh_os_client([[
            'status' => 0,
            'body' => '',
            'error' => 'Failed to connect to https://opensolr.test/request_log?api_key=' . LH_OS_KEY . '&core_name=x',
        ]], $captured);

        $message = $client->log('lh_index', ['rows' => 0])['message'];
        if (str_contains($message, LH_OS_KEY)) {
            lh_fail('the API key survived into an operator-facing message');
        }
        lh_contains($message, '[redacted]', 'the redaction is visible');
    },

    'a platform error body that echoes the key is redacted' => function (): void {
        $captured = [];
        $client = lh_os_client([[
            'status' => 200,
            'body' => '{"status":false,"msg":"ERROR_INVALID_USER_ID for api_key=' . LH_OS_KEY . '"}',
            'error' => '',
        ]], $captured);

        $res = $client->log('lh_index', ['rows' => 0]);
        lh_same('refused', $res['state'], 'a rejected credential');
        if (str_contains((string) json_encode($res), LH_OS_KEY)) {
            lh_fail('the API key survived into the response envelope');
        }
    },

    'the API key never reaches a rendered view' => function (): void {
        $captured = [];
        $cfg = lh_os_config();
        $gw = lh_os_gateway([], $captured);

        foreach ([new Indexes($cfg, $gw), new Queries($cfg, $gw), new Callers($cfg, $gw)] as $view) {
            ob_start();
            $view->body();
            $html = (string) ob_get_clean();

            if (str_contains($html, LH_OS_KEY)) {
                lh_fail($view->slug() . ' rendered the API key into the page');
            }
            if (str_contains($html, 'owner@example.com')) {
                lh_fail($view->slug() . ' rendered the account email into the page');
            }
        }
    },

    'the API key never reaches an API payload' => function (): void {
        $captured = [];
        $cfg = lh_os_config();
        $view = new Queries($cfg, lh_os_gateway([], $captured));
        $view->setLogClient(lh_os_client([lh_os_body([lh_os_doc('http://h/solr/c/select?q=title:x')])], $captured));

        $_GET['core'] = 'lh_index';
        $payload = (string) json_encode($view->api('scan'));
        unset($_GET['core']);

        if (str_contains($payload, LH_OS_KEY)) {
            lh_fail('the API key reached a JSON payload');
        }
    },

    /* -----------------------------------------------------------------------------
     * Hostile content on the operator's screen
     * -------------------------------------------------------------------------- */

    'hostile query text cannot break out of HTML' => function (): void {
        $payload = '</script><img src=x onerror=alert(1)>';
        $label = lh_os_label('q=*:*&fl=' . rawurlencode($payload));

        lh_contains($label, '<', 'the raw label really does contain the hostile bytes');

        $escaped = Security::esc($label);
        lh_false(str_contains($escaped, '<img'), 'the escaped label has no live tag');
        lh_false(str_contains($escaped, '</script>'), 'the escaped label cannot close a script');
        lh_contains($escaped, '&lt;', 'the angle bracket was escaped');
    },

    'hostile query text cannot break out of a chart tooltip or a script block' => function (): void {
        $payload = '</script><svg onload=alert(1)>';
        $label = lh_os_label('q=*:*&fl=' . rawurlencode($payload));

        $json = Security::escJs(['label' => $label]);
        lh_false(str_contains($json, '</script>'), 'JSON_HEX_TAG closed the script-break');
        lh_false(str_contains($json, '<svg'), 'the tag cannot reassemble');
    },

    'a hostile document reaching a scan payload is JSON-safe' => function (): void {
        $captured = [];
        $cfg = lh_os_config();
        $view = new Queries($cfg, lh_os_gateway([], $captured));
        $view->setLogClient(lh_os_client([
            lh_os_body([lh_os_doc('http://h/solr/c/select?q=*:*&fl=' . rawurlencode('</script><b>x</b>'))]),
        ], $captured));

        $_GET['core'] = 'lh_index';
        $payload = Security::escJs($view->api('scan'));
        unset($_GET['core']);

        lh_false(str_contains($payload, '</script>'), 'the payload cannot close the script it is embedded in');
    },

    'no rendered Opensolr view contains an inline script or handler' => function (): void {
        $captured = [];
        $cfg = lh_os_config();
        $gw = lh_os_gateway([], $captured);

        foreach ([new Indexes($cfg, $gw), new Queries($cfg, $gw), new Callers($cfg, $gw)] as $view) {
            ob_start();
            $view->body();
            $html = (string) ob_get_clean();

            if (preg_match('/<script/i', $html)) {
                lh_fail($view->slug() . ' emitted a script element, which the CSP forbids');
            }
            if (preg_match('/\son[a-z]+\s*=/i', $html)) {
                lh_fail($view->slug() . ' emitted an inline event handler, which the CSP forbids');
            }
            if (preg_match('/javascript:/i', $html)) {
                lh_fail($view->slug() . ' emitted a javascript: URL');
            }
        }
    },

    'the view front end never assigns innerHTML from data' => function (): void {
        foreach (['opensolr.js', 'indexes.js', 'queries.js', 'callers.js'] as $file) {
            $path = __DIR__ . '/../public/assets/js/views/' . $file;
            if (!is_file($path)) {
                lh_fail('missing view module: ' . $file);
            }
            $source = (string) file_get_contents($path);
            if (str_contains($source, 'innerHTML')) {
                lh_fail($file . ' assigns innerHTML; DOM must be built with textContent');
            }
            if (preg_match('/\bhtml:\s/', $source)) {
                lh_fail($file . ' uses the el() html attribute, which bypasses textContent');
            }
            if (str_contains($source, 'eval(') || str_contains($source, 'new Function')) {
                lh_fail($file . ' uses dynamic evaluation, which the CSP forbids');
            }
        }
    },

    /* -----------------------------------------------------------------------------
     * The views
     * -------------------------------------------------------------------------- */

    'a view with no credentials explains itself instead of failing' => function (): void {
        $captured = [];
        $cfg = lh_os_config(false);
        $view = new Indexes($cfg, lh_os_gateway([], $captured));

        ob_start();
        $view->body();
        $html = (string) ob_get_clean();

        lh_contains($html, 'Not connected to Opensolr', 'the explainer is rendered');
        lh_contains($html, 'config/loghound.php', 'it says where the credentials go');
        lh_same([], $captured, 'no call was made without credentials');
    },

    'demo mode never calls the platform and never fabricates search data' => function (): void {
        $captured = [];
        $cfg = lh_os_config();
        $demo = new Gateway($cfg, null, true);

        $view = new Indexes($cfg, $demo);
        $view->setLogClient(lh_os_client([lh_os_body([lh_os_doc('http://h/solr/c/select?q=*:*')], 99)], $captured));

        $_GET['core'] = 'lh_index';
        $out = $view->api('headline');
        unset($_GET['core']);

        lh_same('demo', $out['state'], 'the demo state is explicit');
        lh_same(0, $out['requests'], 'no fabricated request count');
        lh_same([], $captured, 'no call was made to the platform while showing sample data');
        lh_contains($out['note'], 'Demo mode', 'the card says why it is empty');
    },

    'an unknown action is refused rather than dispatched' => function (): void {
        $captured = [];
        $cfg = lh_os_config();
        $gw = lh_os_gateway([], $captured);

        foreach ([new Indexes($cfg, $gw), new Queries($cfg, $gw), new Callers($cfg, $gw)] as $view) {
            lh_has_key($view->api('definitely_not_an_action'), 'error', $view->slug() . ' unknown action');
        }
    },

    'a scan step folds a page of requests into shapes' => function (): void {
        $captured = [];
        $view = lh_os_queries([
            lh_os_body([
                lh_os_doc('http://h/solr/c/select?q=' . rawurlencode('title:"a"'), 3),
                lh_os_doc('http://h/solr/c/select?q=' . rawurlencode('title:"b"'), 0),
                lh_os_doc('http://h/solr/c/select?q=' . rawurlencode('body:"c"'), 0),
            ], 900),
        ], ['lh_index'], $captured);

        $out = lh_os_call($view, 'scanStep', [['core' => 'lh_index', 'range' => '24h'], 0, false]);

        lh_true($out['ok'], 'the step succeeded');
        lh_false($out['stop'] ?? false, 'more of the log is left to read');
        lh_same(3, $out['context']['scanned'], 'documents read this step');
        lh_same(900, $out['context']['total'], 'the whole population is reported');
        lh_same(2, count($out['context']['shapes']), 'two distinct shapes across three requests');

        $zeros = 0;
        foreach ($out['context']['shapes'] as $shape) {
            $zeros += $shape['zero'];
        }
        lh_same(2, $zeros, 'both empty responses were counted');
    },

    'a scan step that reaches the end of the log stops the job' => function (): void {
        $captured = [];
        $view = lh_os_queries([
            lh_os_body([lh_os_doc('http://h/solr/c/select?q=*:*')], 1),
        ], ['lh_index'], $captured);

        $out = lh_os_call($view, 'scanStep', [['core' => 'lh_index', 'range' => '24h'], 0, false]);

        lh_true($out['stop'], 'the job finishes rather than making more calls');
        lh_true($out['context']['complete'], 'the context records that the scan is complete');
        lh_false($out['context']['capped'], 'it was not stopped by the depth limit');
    },

    'scan steps merge across pages instead of replacing each other' => function (): void {
        $captured = [];
        $view = lh_os_queries([
            lh_os_body([lh_os_doc('http://h/solr/c/select?q=' . rawurlencode('title:"a"'), 5, 4)], 4000),
            lh_os_body([lh_os_doc('http://h/solr/c/select?q=' . rawurlencode('title:"z"'), 0, 900)], 4000),
        ], ['lh_index'], $captured);

        $first = lh_os_call($view, 'scanStep', [['core' => 'lh_index', 'range' => '24h'], 0, false]);
        $second = lh_os_call($view, 'scanStep', [
            array_merge(['core' => 'lh_index', 'range' => '24h'], $first['context']), 1, false,
        ]);

        lh_same(1, count($second['context']['shapes']), 'both pages folded into one shape');
        $shape = array_values($second['context']['shapes'])[0];
        lh_same(2, $shape['count'], 'the counts added');
        lh_same(1, $shape['zero'], 'the zero-result counts added');
        lh_same(904, $shape['qsum'], 'the latency sums added');
        lh_same(900, $shape['qmax'], 'the worse of the two maxima won');
        lh_same(2, array_sum($shape['hist']), 'the histograms added bucket by bucket');
        lh_same(2, $second['context']['scanned'], 'the scanned counter accumulated');
    },

    'a scan step whose stored parameters make no sense fails rather than guessing' => function (): void {
        $captured = [];
        $view = lh_os_queries([lh_os_body([])], ['lh_index'], $captured);

        foreach ([
            ['core' => '../evil', 'range' => '24h'],
            ['core' => 'lh_index', 'range' => 'whenever'],
            [],
        ] as $ctx) {
            $out = lh_os_call($view, 'scanStep', [$ctx, 0, false]);
            lh_false($out['ok'], 'a step cannot proceed on parameters it cannot validate');
        }
        lh_same([], $captured, 'and nothing was sent to the platform');
    },

    'a scan against an index the account does not own is refused before a job exists' => function (): void {
        $captured = [];
        $view = lh_os_queries([lh_os_body([])], ['mine_one', 'mine_two'], $captured);

        $_POST = ['core' => 'somebody_elses_index', 'range' => '24h'];
        $refused = lh_os_call($view, 'jobParams', ['shape_scan']);
        $_POST = [];

        lh_same(null, $refused, 'an unowned index refuses the start');
        lh_same([], $captured, 'and no request log was read for it');

        $_POST = ['core' => 'mine_two', 'range' => '7d'];
        $accepted = lh_os_call($view, 'jobParams', ['shape_scan']);
        $_POST = [];

        lh_same(['core' => 'mine_two', 'range' => '7d'], $accepted, 'an owned index is accepted');
    },

    'a malformed index name or range is refused before a job exists' => function (): void {
        $captured = [];
        $view = lh_os_queries([lh_os_body([])], ['mine_one'], $captured);

        foreach ([
            ['core' => 'mine_one/../other', 'range' => '24h'],
            ['core' => '', 'range' => '24h'],
            ['core' => 'mine_one', 'range' => 'DROP TABLE'],
            ['core' => 'mine_one'],
            ['range' => '24h'],
        ] as $post) {
            $_POST = $post;
            $out = lh_os_call($view, 'jobParams', ['shape_scan']);
            $_POST = [];
            lh_same(null, $out, 'malformed parameters refuse the start');
        }
    },

    'the ownership check fails closed when the index list cannot be read' => function (): void {
        $captured = [];
        $view = new Queries(lh_os_config(), lh_os_gateway([], $captured));
        $view->setLogClient(lh_os_client([lh_os_body([])], $captured));
        $view->setAccountClient(new Opensolr(
            ['email' => 'a@b.c', 'api_key' => LH_OS_KEY],
            static fn (array $req): array => ['status' => 0, 'body' => '', 'error' => 'unreachable']
        ));

        $_POST = ['core' => 'lh_index', 'range' => '24h'];
        $out = lh_os_call($view, 'jobParams', ['shape_scan']);
        $_POST = [];

        lh_same(null, $out, 'a check that could not be performed is a failed check');
    },

    'demo mode cannot start a scan' => function (): void {
        $captured = [];
        $view = new Queries(lh_os_config(), new Gateway(lh_os_config(), null, true));
        $view->setAccountClient(lh_os_account(['lh_index']));
        $view->setLogClient(lh_os_client([lh_os_body([])], $captured));

        $_POST = ['core' => 'lh_index', 'range' => '24h'];
        $out = lh_os_call($view, 'jobParams', ['shape_scan']);
        $_POST = [];

        lh_same(null, $out, 'a session showing fabricated data does not start a real scan');
    },

    'the view hosts jobs and registers a planner for every kind it names' => function (): void {
        $captured = [];
        $view = lh_os_queries([lh_os_body([])], ['lh_index'], $captured);

        lh_true($view instanceof JobHost, 'the view can accept a POST');

        $kinds = lh_os_call($view, 'jobKinds');
        $plans = lh_os_call($view, 'jobPlans');
        lh_same($kinds, array_keys($plans), 'every kind named has a planner behind it');

        foreach ($kinds as $kind) {
            lh_true(
                (bool) preg_match('/^[a-z][a-z0-9_]{2,31}$/', $kind),
                'kind "' . $kind . '" is acceptable to the job store'
            );
        }
    },

    'the plan is a fixed length whatever context it is handed' => function (): void {
        $captured = [];
        $view = lh_os_queries([lh_os_body([])], ['lh_index'], $captured);
        $plans = lh_os_call($view, 'jobPlans');

        foreach ($plans as $kind => $planner) {
            $empty = count($planner([]));
            $mid = count($planner(['core' => 'lh_index', 'range' => '24h', 'scanned' => 4000, 'total' => 9]));
            lh_true($empty > 1, $kind . ' plans more than one step');
            lh_same($empty, $mid, $kind . ' plan length does not move between polls');
        }
    },

    'scanning two indexes yields two jobs, and re-starting one rejoins it' => function (): void {
        $captured = [];
        $view = lh_os_queries([lh_os_body([lh_os_doc('http://h/solr/c/select?q=*:*')], 9000)], ['a_index', 'b_index'], $captured);
        $jobs = lh_os_jobs('two-targets', lh_os_call($view, 'jobPlans'));

        $first = $jobs->start('shape_scan', ['core' => 'a_index', 'range' => '24h']);
        $second = $jobs->start('shape_scan', ['core' => 'b_index', 'range' => '24h']);
        $again = $jobs->start('shape_scan', ['core' => 'a_index', 'range' => '24h']);

        lh_same(null, $first['error'] ?? null, 'the first scan started');
        lh_same(null, $second['error'] ?? null, 'the second scan started');
        if ($first['id'] === $second['id']) {
            lh_fail('two indexes must not share one job');
        }
        lh_same($first['id'], $again['id'], 're-starting the same target rejoins the running job');

        $range = $jobs->start('shape_scan', ['core' => 'a_index', 'range' => '7d']);
        if ($range['id'] === $first['id']) {
            lh_fail('a different time range is a different target');
        }
    },

    'a poll advances the job it was given and no other' => function (): void {
        $captured = [];
        $view = lh_os_queries([lh_os_body([lh_os_doc('http://h/solr/c/select?q=*:*')], 9000)], ['a_index', 'b_index'], $captured);
        $jobs = lh_os_jobs('right-target', lh_os_call($view, 'jobPlans'));

        $a = $jobs->start('shape_scan', ['core' => 'a_index', 'range' => '24h']);
        $b = $jobs->start('shape_scan', ['core' => 'b_index', 'range' => '30d']);

        $captured = [];
        $advanced = $jobs->advance($b['id']);

        lh_same($b['id'], $advanced['id'], 'the polled job is the one that moved');
        lh_same('b_index', $advanced['result']['core'], 'it resumed its own target');
        lh_same('30d', $advanced['result']['range'], 'including its own time range');
        lh_true(count($captured) >= 1, 'the step really read the request log');
        lh_contains($captured[0]['url'], 'core_name=b_index', 'and it read the right index');

        lh_same(0, $jobs->get($a['id'])['step'], 'the other job did not move');
    },

    'a view cannot advance a job belonging to another view\'s kind' => function (): void {
        $captured = [];
        $queries = lh_os_queries([lh_os_body([lh_os_doc('http://h/solr/c/select?q=*:*')], 9000)], ['lh_index'], $captured);
        $jobs = lh_os_jobs('wrong-kind', lh_os_call($queries, 'jobPlans'));

        $job = $jobs->start('shape_scan', ['core' => 'lh_index', 'range' => '24h']);

        $indexes = new Indexes(lh_os_config(), lh_os_gateway([], $captured));
        $refused = lh_os_call($indexes, 'onOwnJob', [
            $jobs,
            $job['id'],
            static fn (Jobs $j, string $id): array => $j->advance($id),
        ]);

        lh_has_key($refused, 'error', 'a view that does not host this kind refuses it');
        lh_same(0, $jobs->get($job['id'])['step'], 'and the scan was not silently finished');

        $allowed = lh_os_call($queries, 'onOwnJob', [
            $jobs,
            $job['id'],
            static fn (Jobs $j, string $id): array => $j->advance($id),
        ]);
        lh_same(1, $allowed['step'], 'the hosting view advances it normally');
    },

    'a view that hosts no jobs refuses every job endpoint' => function (): void {
        $captured = [];
        $view = new Indexes(lh_os_config(), lh_os_gateway([], $captured));

        lh_same([], lh_os_call($view, 'jobKinds'), 'the view names no kinds');
        lh_same([], lh_os_call($view, 'jobPlans'), 'and registers no planners');
        lh_same(null, lh_os_call($view, 'jobParams', ['shape_scan']), 'so no parameters are ever accepted');
        lh_has_key($view->api('job_latest'), 'error', 'and nothing can be reattached to');
    },

    'the API key never reaches a job envelope, a step note or the stored context' => function (): void {
        $captured = [];
        $view = lh_os_queries([
            lh_os_body([lh_os_doc('http://h/solr/c/select?q=' . rawurlencode('title:"x"'))], 9000),
        ], ['lh_index'], $captured);
        $jobs = lh_os_jobs('secrets', lh_os_call($view, 'jobPlans'));

        $job = $jobs->start('shape_scan', ['core' => 'lh_index', 'range' => '24h']);
        $job = $jobs->advance($job['id']);

        if (str_contains((string) json_encode($job), LH_OS_KEY)) {
            lh_fail('the API key reached a job envelope');
        }
        foreach ($job['steps'] as $step) {
            if (str_contains((string) json_encode($step), LH_OS_KEY)) {
                lh_fail('the API key reached a step note or detail');
            }
        }
        if (str_contains((string) json_encode($job['result']), LH_OS_KEY)) {
            lh_fail('the API key was persisted into the job context');
        }
        lh_contains($captured[0]['url'], rawurlencode(LH_OS_KEY), 'the key really was in play');
    },

    'a step failure carries the platform message without carrying the key' => function (): void {
        $captured = [];
        $view = lh_os_queries([[
            'status' => 0,
            'body' => '',
            'error' => 'Failed to connect to https://opensolr.test/request_log?api_key=' . LH_OS_KEY,
        ]], ['lh_index'], $captured);
        $jobs = lh_os_jobs('failure', lh_os_call($view, 'jobPlans'));

        $job = $jobs->advance($jobs->start('shape_scan', ['core' => 'lh_index', 'range' => '24h'])['id']);

        lh_same('failed', $job['state'], 'the job reached a terminal state');
        lh_true($job['done'], 'and stops being polled');
        if (str_contains((string) json_encode($job), LH_OS_KEY)) {
            lh_fail('the API key survived into a failed job');
        }
        lh_contains((string) json_encode($job), 'redacted', 'the redaction is visible in the failure');
    },

    /* -----------------------------------------------------------------------------
     * The correlation
     * -------------------------------------------------------------------------- */

    'the correlation degrades honestly when there is no web-side data' => function (): void {
        $captured = [];
        $cfg = lh_os_config();
        $view = new Callers($cfg, lh_os_gateway([
            ['status' => 200, 'body' => '{"responseHeader":{"status":0},"response":{"numFound":0,"docs":[]},"facets":{"count":0}}', 'error' => ''],
        ], $captured));
        $view->setLogClient(lh_os_client([lh_os_body([], 40, [
            'facet_counts' => ['facet_fields' => ['ip' => ['198.51.100.7', 30, '203.0.113.9', 10]]],
        ])], $captured));

        $_GET['core'] = 'lh_index';
        $out = $view->api('cross');
        unset($_GET['core']);

        lh_same('no_web_data', $out['web_state'], 'the web half is absent');
        lh_same(2, count($out['rows']), 'the search side is still reported in full');
        lh_same(0, $out['by_class']['unseen'], 'nothing is claimed to be unseen without a lookup');
        lh_same(0, $out['by_class']['bot'], 'nothing is claimed to be a bot without a lookup');
        foreach ($out['rows'] as $row) {
            lh_same('unknown', $row['class'], 'every address is undecided');
            lh_same(null, $row['sessions'], 'session counts are absent, not zero');
        }
    },

    'the correlation splits requests once the web side answers' => function (): void {
        $captured = [];
        $cfg = lh_os_config();

        $rangeProbe = ['status' => 200, 'body' => (string) json_encode([
            'responseHeader' => ['status' => 0],
            'response' => ['numFound' => 12, 'docs' => []],
            'facets' => ['count' => 12, 'addresses' => 2],
        ]), 'error' => ''];

        $byIp = ['status' => 200, 'body' => (string) json_encode([
            'responseHeader' => ['status' => 0],
            'response' => ['numFound' => 12, 'docs' => []],
            'facets' => ['count' => 12, 'by_ip' => ['buckets' => [
                ['val' => '198.51.100.7', 'count' => 9, 'botlike' => ['count' => 9], 'human' => ['count' => 0], 'declared' => ['count' => 0], 'hits' => 90],
                ['val' => '203.0.113.9', 'count' => 3, 'botlike' => ['count' => 0], 'human' => ['count' => 3], 'declared' => ['count' => 0], 'hits' => 12],
            ]]],
        ]), 'error' => ''];

        $view = new Callers($cfg, lh_os_gateway([$rangeProbe, $byIp], $captured));
        $view->setLogClient(lh_os_client([lh_os_body([], 45, [
            'facet_counts' => ['facet_fields' => ['ip' => [
                '198.51.100.7', 30, '203.0.113.9', 10, '192.0.2.44', 5,
            ]]],
        ])], $captured));

        $_GET['core'] = 'lh_index';
        $out = $view->api('cross');
        unset($_GET['core']);

        lh_same('ok', $out['web_state'], 'both halves answered');
        lh_same(30, $out['by_class']['bot'], 'the bot address\'s requests are attributed to bots');
        lh_same(10, $out['by_class']['human'], 'the human address\'s requests are attributed to people');
        lh_same(5, $out['by_class']['unseen'], 'the address with no web traffic is the security finding');
        lh_same(45, $out['requests'], 'the total is the whole log, not the facet');
        lh_same(45, $out['covered'], 'and the facet covers all of it here');
    },

    'the correlation queries the sessions core with one faceted call' => function (): void {
        $captured = [];
        $cfg = lh_os_config();
        $solr = [];

        $rangeProbe = ['status' => 200, 'body' => (string) json_encode([
            'responseHeader' => ['status' => 0],
            'response' => ['numFound' => 5, 'docs' => []],
            'facets' => ['count' => 5],
        ]), 'error' => ''];
        $byIp = ['status' => 200, 'body' => (string) json_encode([
            'responseHeader' => ['status' => 0],
            'response' => ['numFound' => 5, 'docs' => []],
            'facets' => ['count' => 5, 'by_ip' => ['buckets' => []]],
        ]), 'error' => ''];

        $view = new Callers($cfg, lh_os_gateway([$rangeProbe, $byIp], $solr));
        $view->setLogClient(lh_os_client([lh_os_body([], 40, [
            'facet_counts' => ['facet_fields' => ['ip' => ['198.51.100.7', 30, '203.0.113.9', 10]]],
        ])], $captured));

        $_GET['core'] = 'lh_index';
        $view->api('cross');
        unset($_GET['core']);

        lh_same(2, count($solr), 'exactly two Solr calls, never one per address');

        $body = urldecode((string) $solr[1]['body']);
        lh_contains($body, 'doc_type_s:session', 'the rollup documents are excluded');
        lh_contains($body, '198.51.100.7', 'the addresses were bound into one terms filter');
        lh_contains($body, 'json.facet', 'the lookup is a facet, not a document fetch');
    },

    'an address that is not an address cannot escape the terms filter' => function (): void {
        $captured = [];
        $cfg = lh_os_config();
        $solr = [];

        $rangeProbe = ['status' => 200, 'body' => (string) json_encode([
            'responseHeader' => ['status' => 0],
            'response' => ['numFound' => 5, 'docs' => []],
            'facets' => ['count' => 5],
        ]), 'error' => ''];
        $byIp = ['status' => 200, 'body' => (string) json_encode([
            'responseHeader' => ['status' => 0],
            'response' => ['numFound' => 5, 'docs' => []],
            'facets' => ['count' => 5, 'by_ip' => ['buckets' => []]],
        ]), 'error' => ''];

        $view = new Callers($cfg, lh_os_gateway([$rangeProbe, $byIp], $solr));
        $view->setLogClient(lh_os_client([lh_os_body([], 3, [
            'facet_counts' => ['facet_fields' => ['ip' => ['" OR bot_verdict_s:human OR ip_s:"', 3]]],
        ])], $captured));

        $_GET['core'] = 'lh_index';
        $out = $view->api('cross');
        unset($_GET['core']);

        lh_same(1, count($out['rows']), 'the hostile value is still reported as data');
        $body = urldecode((string) $solr[1]['body']);
        lh_false(
            (bool) preg_match('/ip_s:\(\s*"\s*" OR bot_verdict_s/', $body),
            'the quote did not terminate the term'
        );
    },
];
