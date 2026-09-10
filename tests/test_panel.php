<?php
/**
 * Loghound — tests for the web panel's security properties.
 *
 * The panel renders attacker-controlled data by definition: request paths, User-Agents
 * and referers are chosen by whoever hit the origin server, and every value on screen
 * came off the wire. These tests pin the guards rather than the happy path, because a
 * guard that is only enforced by convention is one refactor away from being gone. The
 * regression that motivated several of them was a validation accidentally wrapped in a
 * try/catch while fixing something unrelated.
 *
 * What is asserted here:
 *  - Solr injection: field names, sort keys and filter fields come from allowlists;
 *    free text is bound, never spliced; rows and start are clamped.
 *  - Output escaping: the rendered HTML escapes hostile paths, User-Agents and referers,
 *    and a javascript: referer never becomes a live href.
 *  - CSP compatibility: no inline event handler and no inline <script> is ever emitted.
 *  - Job security: ids are unguessable, scoped to the session, and a job belonging to
 *    another operator is indistinguishable from one that does not exist.
 *  - Secret redaction: an API key cannot reach a job payload, an error or a log line.
 *  - SQL: the job store is driven entirely by prepared statements.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Config;
use Loghound\Panel\Bots;
use Loghound\Panel\Controller;
use Loghound\Panel\Fingerprints;
use Loghound\Panel\Gateway;
use Loghound\Panel\Jobs;
use Loghound\Panel\Networks;
use Loghound\Panel\Overview;
use Loghound\Panel\Performance;
use Loghound\Panel\Query;
use Loghound\Panel\Sessions;
use Loghound\Security;
use Loghound\Solr;

/**
 * A configuration with the panel pointed at a fake Solr and demo mode off.
 */
function lh_panel_config(): Config
{
    $cfg = Config::load('/nonexistent-loghound-config');
    $cfg->set('solr.mode', 'custom');
    $cfg->set('solr.base_url', 'http://127.0.0.1:65535/solr');
    $cfg->set('solr.hits_core', 'lh_test_hits');
    $cfg->set('solr.sessions_core', 'lh_test_sessions');
    return $cfg;
}

/**
 * A Gateway backed by the real Solr client with a recording transport.
 *
 * Nothing leaves the machine: the transport returns canned JSON. Using the REAL client
 * means the panel's queries are judged by the same sanitisers production would apply, so
 * a test failure here is a genuine injection risk and not a mock disagreeing.
 *
 * @param array<int,array<string,mixed>> $captured Filled with every request issued.
 */
function lh_panel_gateway(array &$captured, array $docs = []): Gateway
{
    $transport = function (array $request) use (&$captured, $docs): array {
        $captured[] = $request;
        return [
            'status' => 200,
            'body' => (string) json_encode([
                'responseHeader' => ['status' => 0],
                'response' => ['numFound' => count($docs), 'docs' => $docs],
                'facets' => ['count' => 0],
            ]),
            'error' => '',
        ];
    };

    $cfg = lh_panel_config();
    return new Gateway($cfg, new Solr((array) $cfg->get('solr'), $transport), false);
}

/**
 * Decode the form-encoded body of a captured Solr request.
 *
 * @param array<string,mixed> $request
 * @return array<string,mixed>
 */
function lh_panel_params(array $request): array
{
    $params = [];
    parse_str((string) ($request['body'] ?? ''), $params);
    return $params;
}

/**
 * Run a panel view action with a given $_GET, returning the captured Solr requests.
 *
 * @param array<string,mixed> $get
 * @return array{0:array<string,mixed>,1:array<int,array<string,mixed>>}
 */
function lh_panel_run(string $class, string $action, array $get): array
{
    $saved = $_GET;
    $_GET = $get;
    $captured = [];
    try {
        $cfg = lh_panel_config();
        $view = new $class($cfg, lh_panel_gateway($captured));
        $result = $view->api($action);
    } finally {
        $_GET = $saved;
    }
    return [$result, $captured];
}

/**
 * Render a view's HTML body to a string.
 *
 * @param array<string,mixed> $get
 */
function lh_panel_html(string $class, array $get = []): string
{
    $saved = $_GET;
    $_GET = $get;
    $captured = [];
    try {
        $cfg = lh_panel_config();
        $view = new $class($cfg, lh_panel_gateway($captured));
        ob_start();
        $view->body();
        $html = (string) ob_get_clean();
    } finally {
        $_GET = $saved;
    }
    return $html;
}

/**
 * Strip attribute VALUES out of every tag, leaving only element and attribute names.
 *
 * Checking rendered HTML for `onerror=` naively fails the moment a view correctly
 * escapes a hostile search term into an attribute: the escaped text still contains the
 * characters. Only an attribute NAME can be an event handler, so the values are removed
 * before the check and the assertion then means what it says.
 */
function lh_panel_tag_skeleton(string $html): string
{
    return (string) preg_replace_callback(
        '/<[a-zA-Z][^>]*>/',
        static fn (array $m): string => (string) preg_replace('/=\s*("[^"]*"|\'[^\']*\'|[^\s>]+)/', '=', $m[0]),
        $html
    );
}

/**
 * A Jobs instance bound to a throwaway session identity.
 *
 * Each call with a different $identity simulates a different signed-in operator, which is
 * what the ownership tests need.
 */
function lh_panel_jobs(string $identity): Jobs
{
    $_SESSION['lh_job_owner'] = $identity;
    $_SESSION['lh_user'] = 'tester';
    $captured = [];
    return new Jobs(lh_panel_config(), lh_panel_gateway($captured));
}

return [

    'a filter field outside the allowlist is dropped, not queried' => function (): void {
        [$result, $captured] = lh_panel_run(Overview::class, 'totals', [
            'f' => ['bot_class_s' => ['proxy_fleet'], 'raw_s' => ['x'], 'password' => ['y']],
        ]);
        lh_true($captured !== [], 'a Solr request was issued');
        $fq = implode(' ', (array) (lh_panel_params($captured[0])['fq'] ?? []));
        lh_contains($fq, 'bot_class_s', 'the allowlisted field survives');
        lh_true(!str_contains($fq, 'raw_s'), 'raw_s never reaches a filter');
        lh_true(!str_contains($fq, 'password'), 'an invented field never reaches a filter');
    },

    'a filter value containing Solr syntax is quoted, not interpreted' => function (): void {
        [$result, $captured] = lh_panel_run(Overview::class, 'totals', [
            'f' => ['country_s' => ['DE" OR ip_s:*']],
        ]);
        $fq = implode(' ', (array) (lh_panel_params($captured[0])['fq'] ?? []));
        lh_contains($fq, '\\"', 'the embedded quote is backslash-escaped');
        lh_true(!preg_match('/country_s:\("?DE" OR ip_s:\*/', $fq), 'the injection did not become syntax');
    },

    'Query::term refuses an unsafe field name outright' => function (): void {
        lh_throws(static fn () => Query::term('ip_s;drop', 'x'), 'a field with punctuation');
        lh_throws(static fn () => Query::term('a b', 'x'), 'a field with a space');
        lh_throws(static fn () => Query::rangeUntil('ts;x', 5), 'an unsafe range field');
    },

    'free text is bound as a parameter and never spliced into q' => function (): void {
        [$result, $captured] = lh_panel_run(Sessions::class, 'list', [
            'q' => 'SwiftShader {!func}sum(1,1) "quoted" OR *:*',
        ]);
        $params = lh_panel_params($captured[0]);
        lh_same('{!edismax v=$uq}', $params['q'] ?? null, 'q is the one accepted literal');
        lh_true(!str_contains((string) ($params['q'] ?? ''), 'SwiftShader'), 'the text is not in q');
        lh_contains((string) ($params['uq'] ?? ''), 'SwiftShader', 'the text is bound as uq');
    },

    'a leading local-param block is stripped before the text is bound' => function (): void {
        [$result, $captured] = lh_panel_run(Sessions::class, 'list', [
            'q' => '{!func}sum(1,1) hello',
        ]);
        $params = lh_panel_params($captured[0]);
        lh_same('{!edismax v=$uq}', $params['q'] ?? null, 'q is still the fixed literal');
        lh_true(
            !str_starts_with((string) ($params['uq'] ?? ''), '{!'),
            'the leading switch is removed, so it cannot reach the head of the bound value'
        );
    },

    'the panel never sends a parameter Solr refuses' => function (): void {
        [$result, $captured] = lh_panel_run(Sessions::class, 'list', [
            'q' => 'x', 'sort' => 'score', 'rows' => '10',
        ]);
        foreach ($captured as $request) {
            $params = lh_panel_params($request);
            foreach (['defType', 'shards', 'qt', 'wt', 'distrib', 'stream.url', 'stream.body'] as $banned) {
                lh_no_key($params, $banned, 'request parameters');
            }
        }
    },

    'rows and start are clamped however large the request asks for' => function (): void {
        [$result] = lh_panel_run(Sessions::class, 'list', [
            'rows' => '999999', 'start' => '99999999999',
        ]);
        lh_true($result['rows'] <= 100, 'rows is clamped to the view maximum');
        lh_true($result['rows'] <= Security::MAX_ROWS, 'rows is under the hard ceiling');
        lh_true($result['start'] <= Security::MAX_START, 'start is under the hard ceiling');
    },

    'a negative or non-numeric rows value cannot become a Solr parameter' => function (): void {
        foreach (['-5', 'abc', '1e9', '0x10', ''] as $hostile) {
            [$result] = lh_panel_run(Sessions::class, 'list', ['rows' => $hostile]);
            lh_true(is_int($result['rows']) && $result['rows'] >= 1, 'rows stays a sane integer for ' . $hostile);
        }
    },

    'sort is a key into a map of literals, never assembled from input' => function (): void {
        [$result] = lh_panel_run(Sessions::class, 'list', ['sort' => 'ts_start desc; drop']);
        lh_same('recent', $result['sort'], 'an unknown sort key falls back to the default');
        foreach (Query::sorts() as $literal) {
            lh_true(
                (bool) preg_match('/^[A-Za-z0-9_]{1,64} (asc|desc)$/', $literal),
                'sort literal "' . $literal . '" is a bare field and direction'
            );
        }
    },

    'the session drill-down refuses an id that is not shaped like one' => function (): void {
        foreach (['../../etc/passwd', 'a b', '"', 'x*:*', str_repeat('a', 200)] as $hostile) {
            [$result] = lh_panel_run(Sessions::class, 'detail', ['id' => $hostile]);
            lh_has_key($result, 'error', 'hostile session id ' . substr($hostile, 0, 12));
        }
    },

    'the fingerprint drill-down refuses anything that is not a hex digest' => function (): void {
        foreach (['*', 'abc def', 'zz11', '" OR "', ''] as $hostile) {
            [$result] = lh_panel_run(Fingerprints::class, 'members', ['fp' => $hostile]);
            lh_same([], $result['rows'], 'no rows for hostile fingerprint ' . $hostile);
        }
    },

    'every facet field the panel names passes the safe-name pattern' => function (): void {
        foreach (array_keys(Query::filterFields()) as $field) {
            lh_true(Security::isSafeFieldName($field), 'filter field ' . $field);
        }
    },

    'an unknown api action is refused by every view' => function (): void {
        foreach ([Overview::class, Bots::class, Networks::class, Performance::class, Sessions::class] as $class) {
            foreach (['', 'nope', '../x', 'summary; drop'] as $action) {
                [$result] = lh_panel_run($class, $action, []);
                lh_has_key($result, 'error', $class . ' rejects "' . $action . '"');
            }
        }
    },

    'hostile log values are escaped when a session row is shaped' => function (): void {
        $hostile = '<script>alert(1)</script>';
        $saved = $_GET;
        $_GET = [];
        try {
            $captured = [];
            $cfg = lh_panel_config();
            $gateway = lh_panel_gateway($captured, [[
                'id' => 'a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0',
                'ua_s' => $hostile,
                'path_s' => $hostile,
                'referer_s' => 'javascript:alert(1)',
                'entry_path_s' => $hostile,
            ]]);
            $view = new Sessions($cfg, $gateway);
            $result = $view->api('list');
        } finally {
            $_GET = $saved;
        }

        $doc = $result['docs'][0];
        lh_same('#', $doc['referer_href'], 'a javascript: referer never becomes a live href');
        $json = (string) json_encode($result, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
        lh_true(!str_contains($json, '<script'), 'the JSON payload carries no raw script tag');
    },

    'Security::safeUrl refuses every scheme that is not http or https' => function (): void {
        foreach ([
            'javascript:alert(1)',
            'JaVaScRiPt:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'vbscript:msgbox',
            'file:///etc/passwd',
            "java\nscript:alert(1)",
            ' javascript:alert(1)',
        ] as $hostile) {
            lh_same('#', Security::safeUrl($hostile), 'safeUrl refuses ' . substr($hostile, 0, 20));
        }
        lh_same('https://example.com/a', Security::safeUrl('https://example.com/a'), 'https survives');
    },

    'no view emits an inline event handler or an inline script' => function (): void {
        foreach ([Overview::class, Bots::class, Fingerprints::class, Networks::class, Sessions::class, Performance::class] as $class) {
            $html = lh_panel_html($class, ['q' => '<img src=x onerror=alert(1)>']);
            $skeleton = lh_panel_tag_skeleton($html);
            lh_true(!preg_match('/\son[a-z]+\s*=/i', $skeleton), $class . ' emits no inline event handler');
            lh_true(!preg_match('/<script(?![^>]*type="application\/json")/i', $html), $class . ' emits no inline script');
            lh_true(!str_contains($skeleton, 'javascript:'), $class . ' emits no javascript: URL');
        }
    },

    'a hostile search term is escaped where it is echoed back into the form' => function (): void {
        $html = lh_panel_html(Sessions::class, ['q' => '"><script>alert(1)</script>']);
        lh_true(!str_contains($html, '<script>alert(1)'), 'the term is not echoed as markup');
        lh_contains($html, '&lt;script&gt;', 'the term is escaped');
    },

    'a job id is long, random and shape-checked' => function (): void {
        lh_false(Jobs::isJobId(''), 'empty');
        lh_false(Jobs::isJobId('../../x'), 'traversal');
        lh_false(Jobs::isJobId('ABCDEF012345678901234567'), 'uppercase');
        lh_false(Jobs::isJobId(str_repeat('a', 23)), 'too short');
        lh_false(Jobs::isJobId("a1b2c3d4e5f6a7b8c9d0e1f2'"), 'trailing quote');
        lh_true(Jobs::isJobId('a1b2c3d4e5f6a7b8c9d0e1f2'), 'a real id');
    },

    'one operator cannot read, advance or cancel another operator\'s job' => function (): void {
        if (!class_exists('SQLite3')) {
            lh_skip('needs ext-sqlite3');
        }
        $mine = lh_panel_jobs('owner-one-' . bin2hex(random_bytes(4)));
        $job = $mine->start('solr_connection');
        lh_has_key($job, 'id', 'the job started');
        $id = $job['id'];

        $theirs = lh_panel_jobs('owner-two-' . bin2hex(random_bytes(4)));
        lh_has_key($theirs->get($id), 'error', 'reading another owner\'s job');
        lh_has_key($theirs->advance($id), 'error', 'advancing another owner\'s job');
        lh_has_key($theirs->cancel($id), 'error', 'cancelling another owner\'s job');
        lh_same(null, $theirs->latest('solr_connection'), 'latest() is scoped to the owner');

        lh_has_key($mine->get($id), 'id', 'the owner can still read it');
    },

    'a job that does not exist and one owned by someone else are indistinguishable' => function (): void {
        if (!class_exists('SQLite3')) {
            lh_skip('needs ext-sqlite3');
        }
        $mine = lh_panel_jobs('owner-a-' . bin2hex(random_bytes(4)));
        $id = $mine->start('solr_connection')['id'];

        $theirs = lh_panel_jobs('owner-b-' . bin2hex(random_bytes(4)));
        $foreign = $theirs->get($id)['error'];
        $missing = $theirs->get('ffffffffffffffffffffffff')['error'];
        lh_same($missing, $foreign, 'the two messages are identical, so ids cannot be probed');
    },

    'starting a job twice returns the same job rather than a second one' => function (): void {
        if (!class_exists('SQLite3')) {
            lh_skip('needs ext-sqlite3');
        }
        $jobs = lh_panel_jobs('owner-idem-' . bin2hex(random_bytes(4)));
        $first = $jobs->start('retention_preview');
        $second = $jobs->start('retention_preview');
        lh_same($first['id'], $second['id'], 'a double click cannot run the work twice');
    },

    'an unknown job kind is refused before the store is touched' => function (): void {
        if (!class_exists('SQLite3')) {
            lh_skip('needs ext-sqlite3');
        }
        $jobs = lh_panel_jobs('owner-kind-' . bin2hex(random_bytes(4)));
        foreach (['', 'nope', 'solr_connection; drop', '../x'] as $kind) {
            lh_has_key($jobs->start($kind), 'error', 'kind "' . $kind . '"');
            lh_same(null, $jobs->latest($kind), 'latest() refuses kind "' . $kind . '"');
        }
    },

    'a job payload never contains the owner column' => function (): void {
        if (!class_exists('SQLite3')) {
            lh_skip('needs ext-sqlite3');
        }
        $jobs = lh_panel_jobs('owner-secret-' . bin2hex(random_bytes(4)));
        $job = $jobs->start('solr_connection');
        lh_no_key($job, 'owner', 'the job payload');
        lh_true(!str_contains((string) json_encode($job), 'owner-secret'), 'the identity is not serialised');
    },

    'a cancelled job stops at a step boundary and reports it' => function (): void {
        if (!class_exists('SQLite3')) {
            lh_skip('needs ext-sqlite3');
        }
        $jobs = lh_panel_jobs('owner-cancel-' . bin2hex(random_bytes(4)));
        $id = $jobs->start('solr_connection')['id'];
        $jobs->cancel($id);
        $after = $jobs->advance($id);
        lh_same('cancelled', $after['state'], 'the job is cancelled');
        lh_true($after['done'], 'a cancelled job is terminal so polling stops');
    },

    'an API key cannot survive redaction into a payload, error or log line' => function (): void {
        $key = 'sk-abcdef0123456789abcdef0123456789';
        foreach ([
            'https://opensolr.com/api/regions?email=a@b.c&api_key=' . $key,
            'Could not resolve host for https://user:' . $key . '@solr.example.com/solr',
            'api_key=' . $key . ' failed',
            'password=' . $key,
            'token=' . $key . '&x=1',
        ] as $leak) {
            $safe = Jobs::redact($leak);
            lh_true(!str_contains($safe, $key), 'redacted: ' . substr($leak, 0, 40));
        }
    },

    'redaction leaves ordinary diagnostics readable' => function (): void {
        $message = 'Solr query "perf.paths" failed: connection refused to 10.0.0.5:8983';
        lh_same($message, Jobs::redact($message), 'nothing useful is destroyed');
    },

    'the job store is driven only by prepared statements' => function (): void {
        $source = (string) file_get_contents(__DIR__ . '/../src/Panel/Jobs.php');
        lh_true(
            !preg_match('/(query|querySingle|exec)\s*\(\s*[\'"][^\'"]*[\'"]\s*\./', $source),
            'no SQL string is concatenated with a variable'
        );
        lh_true(!str_contains($source, 'escapeString'), 'no manual escaping is used in place of binding');
        lh_true(substr_count($source, 'bindValue') > 15, 'values are bound throughout');
    },

    'a Solr transport failure produces an error, never a silent empty result' => function (): void {
        $cfg = lh_panel_config();
        $throwing = new Solr((array) $cfg->get('solr'), static function (array $request): array {
            return ['status' => 0, 'body' => '', 'error' => 'Connection refused'];
        });
        $gateway = new Gateway($cfg, $throwing, false);
        $gateway->select('test', 'lh_test_sessions', ['q' => '*:*', 'rows' => 0]);
        lh_true($gateway->error() !== null, 'the failure is recorded rather than swallowed');
    },

    'the panel query timeout is bounded well under a request lifetime' => function (): void {
        $cfg = lh_panel_config();
        foreach (['0', '-1', '99999', 'abc', ''] as $hostile) {
            $cfg->set('ui.query_timeout', $hostile);
            $timeout = Gateway::queryTimeout($cfg);
            lh_true($timeout >= 3 && $timeout <= 45, 'timeout stays in range for "' . $hostile . '"');
        }
    },

    'every population filter is a syntactically closed Solr expression' => function (): void {
        $filters = array_merge(array_values(Query::populations()), [
            Query::POP_BOTLIKE, Query::POP_DECLARED_ANY, Query::POP_BEACON,
        ]);
        foreach ($filters as $filter) {
            lh_same(
                substr_count($filter, '('),
                substr_count($filter, ')'),
                'balanced parentheses in: ' . $filter
            );
            lh_true(!str_contains($filter, '{!'), 'no local params in: ' . $filter);
            Solr::assertSafeFilter($filter);
        }
    },

    'every population filter is accepted by the real Solr client' => function (): void {
        foreach (Query::populations() as $key => $filter) {
            Solr::assertSafeFilter($filter);
        }
        lh_true(true, 'all population filters passed assertSafeFilter');
    },
];
