<?php
/**
 * Loghound — the Solr client's shared curl handle.
 *
 * WHAT IS BEING PROTECTED. \Loghound\Solr::curlTransport() holds one curl handle for the life of
 * the process so the TCP and TLS handshake is paid once instead of once per call. Measured
 * across a 117 ms connect delay, six sequential requests went from 754 ms to 148 ms. It is also
 * the single riskiest change in the file: a reused handle carries its previous request's method,
 * body, headers, credentials and cookies, so every one of those must be reset or set again on
 * every call. Every test here is one of the ways that can go wrong.
 *
 * NO OUTBOUND REQUEST. The behavioural tests talk to a PHP built-in server on loopback that
 * this file starts and stops, and they skip themselves if a subprocess or a port is not
 * available. Nothing here reaches a network, and nothing here needs one.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

use Loghound\Solr;

/**
 * Start a loopback HTTP server that reports what it was sent, and return its base URL.
 *
 * The router echoes the request's method, Authorization header, Cookie header, Expect header,
 * Content-Length and body back as JSON, which is exactly the set of things a reused handle can
 * leak from one call into the next. It also sets a cookie on every response, so a client that
 * keeps a cookie jar across calls betrays itself on the second one.
 *
 * Returns null when a server cannot be started here, so the caller can skip rather than fail.
 *
 * @param array<string,mixed> $handles Filled with the proc handle and pipes, for shutdown.
 */
function lh_echo_server(array &$handles): ?string
{
    $dir = lh_tmpdir('transport');
    $router = $dir . '/router.php';

    file_put_contents($router, <<<'PHP'
<?php
$body = file_get_contents('php://input');
header('Content-Type: application/json');
header('Set-Cookie: lhpoison=1; Path=/');
echo json_encode([
    'responseHeader' => ['status' => 0],
    'seen' => [
        'method' => $_SERVER['REQUEST_METHOD'] ?? '',
        'auth'   => $_SERVER['HTTP_AUTHORIZATION'] ?? ($_SERVER['PHP_AUTH_USER'] ?? ''),
        'cookie' => $_SERVER['HTTP_COOKIE'] ?? '',
        'expect' => $_SERVER['HTTP_EXPECT'] ?? '',
        'len'    => strlen($body),
        'body'   => substr($body, 0, 64),
    ],
]);
PHP);

    for ($attempt = 0; $attempt < 6; $attempt++) {
        $port = random_int(21000, 61000);
        $cmd = escapeshellarg(PHP_BINARY) . ' -S 127.0.0.1:' . $port . ' ' . escapeshellarg($router);
        $proc = @proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $dir);
        if (!is_resource($proc)) {
            return null;
        }

        for ($wait = 0; $wait < 60; $wait++) {
            usleep(50000);
            $sock = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.2);
            if (is_resource($sock)) {
                fclose($sock);
                $handles = ['proc' => $proc, 'pipes' => $pipes, 'dir' => $dir];
                return 'http://127.0.0.1:' . $port;
            }
            if (proc_get_status($proc)['running'] !== true) {
                break;
            }
        }

        proc_terminate($proc);
        proc_close($proc);
    }

    return null;
}

/**
 * Stop a server started by lh_echo_server() and remove its scratch directory.
 *
 * @param array<string,mixed> $handles
 */
function lh_echo_stop(array $handles): void
{
    if (isset($handles['pipes']) && is_array($handles['pipes'])) {
        foreach ($handles['pipes'] as $pipe) {
            if (is_resource($pipe)) {
                fclose($pipe);
            }
        }
    }
    if (isset($handles['proc']) && is_resource($handles['proc'])) {
        proc_terminate($handles['proc']);
        proc_close($handles['proc']);
    }
    if (isset($handles['dir']) && is_string($handles['dir'])) {
        lh_rmtree($handles['dir']);
    }
}

/**
 * Read the shared handle out of the class, to assert identity rather than behaviour.
 *
 * Reflection on a private static is used deliberately in preference to widening the class's
 * API: "the same handle object was used twice" is the claim being made, and there is no way to
 * observe it from outside that does not either add a method that exists only for a test or
 * measure a timing, which would make the suite flaky on a loaded machine.
 */
function lh_shared_handle(): ?object
{
    $prop = new ReflectionProperty(Solr::class, 'handle');
    $value = $prop->getValue();
    return is_object($value) ? $value : null;
}

/** Clear the shared handle so a test starts from a known state. */
function lh_reset_handle(): void
{
    foreach (['handle' => null, 'handlePid' => 0] as $name => $value) {
        $prop = new ReflectionProperty(Solr::class, $name);
        $prop->setValue(null, $value);
    }
}

/**
 * One transport request against the echo server, returning what the server saw.
 *
 * @param array<string,mixed> $over
 * @return array<string,mixed>
 */
function lh_probe(string $base, array $over = []): array
{
    $req = [
        'url'             => $base . '/solr/core/select',
        'method'          => 'GET',
        'headers'         => ['Accept: application/json'],
        'body'            => null,
        'timeout'         => 10,
        'connect_timeout' => 5,
        'user'            => '',
        'pass'            => '',
    ];
    $res = Solr::curlTransport(array_merge($req, $over));
    $decoded = json_decode((string) $res['body'], true);

    return [
        'status' => (int) $res['status'],
        'error'  => (string) $res['error'],
        'seen'   => is_array($decoded) && isset($decoded['seen']) ? (array) $decoded['seen'] : [],
    ];
}

$tests = [];

$tests['transport: one curl handle is reused across requests in a process'] =
    function (): void {
        $handles = [];
        $base = lh_echo_server($handles);
        if ($base === null) {
            lh_skip('cannot start a loopback HTTP server here');
        }

        try {
            lh_reset_handle();
            lh_same(null, lh_shared_handle(), 'the shared handle must start out absent');

            $first = lh_probe($base);
            lh_same(200, $first['status'], 'the first request must reach the echo server');
            $handleAfterFirst = lh_shared_handle();
            lh_true(is_object($handleAfterFirst), 'a handle must be retained after the first request');

            $second = lh_probe($base);
            lh_same(200, $second['status'], 'the second request must reach the echo server');
            lh_true(
                lh_shared_handle() === $handleAfterFirst,
                'the SAME handle object must serve the second request — a new one would pay the handshake again'
            );
        } finally {
            lh_echo_stop($handles);
            lh_reset_handle();
        }
    };

$tests['transport: credentials from one request never reach the next'] =
    function (): void {
        $handles = [];
        $base = lh_echo_server($handles);
        if ($base === null) {
            lh_skip('cannot start a loopback HTTP server here');
        }

        try {
            lh_reset_handle();

            $withAuth = lh_probe($base, ['user' => 'lh', 'pass' => 'secret']);
            lh_same(200, $withAuth['status'], 'the authenticated request must reach the server');
            lh_true(
                ($withAuth['seen']['auth'] ?? '') !== '',
                'the credentials must actually have been sent, or this test proves nothing'
            );

            $without = lh_probe($base);
            lh_same(
                '',
                (string) ($without['seen']['auth'] ?? ''),
                'a request with no credentials must not inherit the previous request\'s Authorization header'
            );
        } finally {
            lh_echo_stop($handles);
            lh_reset_handle();
        }
    };

$tests['transport: a body from one request never reaches the next'] =
    function (): void {
        $handles = [];
        $base = lh_echo_server($handles);
        if ($base === null) {
            lh_skip('cannot start a loopback HTTP server here');
        }

        try {
            lh_reset_handle();

            $post = lh_probe($base, [
                'method'  => 'POST',
                'headers' => ['Content-Type: application/json'],
                'body'    => '{"facet":true}',
            ]);
            lh_same('POST', (string) ($post['seen']['method'] ?? ''), 'the POST must arrive as a POST');
            lh_same(14, (int) ($post['seen']['len'] ?? -1), 'the POST body must arrive intact');

            $get = lh_probe($base);
            lh_same('GET', (string) ($get['seen']['method'] ?? ''), 'the method must reset to GET');
            lh_same(0, (int) ($get['seen']['len'] ?? -1), 'a body-less request must carry no body');
            lh_same('', (string) ($get['seen']['body'] ?? ''), 'the previous body must not be re-sent');
        } finally {
            lh_echo_stop($handles);
            lh_reset_handle();
        }
    };

$tests['transport: a cookie set by the endpoint is never replayed'] =
    function (): void {
        $handles = [];
        $base = lh_echo_server($handles);
        if ($base === null) {
            lh_skip('cannot start a loopback HTTP server here');
        }

        try {
            lh_reset_handle();

            lh_probe($base);
            $second = lh_probe($base);
            lh_same(
                '',
                (string) ($second['seen']['cookie'] ?? ''),
                'Set-Cookie from a Solr endpoint must not become a header on every later request'
            );
        } finally {
            lh_echo_stop($handles);
            lh_reset_handle();
        }
    };

$tests['transport: a large body is sent without a 100-continue round trip'] =
    function (): void {
        $handles = [];
        $base = lh_echo_server($handles);
        if ($base === null) {
            lh_skip('cannot start a loopback HTTP server here');
        }

        try {
            lh_reset_handle();

            $res = lh_probe($base, [
                'method'  => 'POST',
                'headers' => ['Content-Type: application/json'],
                'body'    => '{"pad":"' . str_repeat('x', 4096) . '"}',
            ]);
            lh_same(200, $res['status'], 'the large POST must succeed');
            lh_same(
                '',
                (string) ($res['seen']['expect'] ?? ''),
                'Expect: 100-continue must be suppressed — it is one more round trip on the slow link'
            );
        } finally {
            lh_echo_stop($handles);
            lh_reset_handle();
        }
    };

$tests['transport: a failed request drops the handle rather than reusing a poisoned socket'] =
    function (): void {
        lh_reset_handle();

        try {
            $res = Solr::curlTransport([
                'url'             => 'http://127.0.0.1:1/solr/core/select',
                'method'          => 'GET',
                'headers'         => ['Accept: application/json'],
                'body'            => null,
                'timeout'         => 2,
                'connect_timeout' => 1,
                'user'            => '',
                'pass'            => '',
            ]);

            lh_same(0, (int) $res['status'], 'an unreachable port must report status 0');
            lh_true($res['error'] !== '', 'the transport error must be reported');
            lh_same(
                null,
                lh_shared_handle(),
                'a handle whose transfer failed must be discarded, not reused with unread bytes on it'
            );
        } finally {
            lh_reset_handle();
        }
    };

$tests['transport: the handle is not shared across processes'] =
    function (): void {
        lh_reset_handle();

        try {
            $pidProp = new ReflectionProperty(Solr::class, 'handlePid');
            $handleProp = new ReflectionProperty(Solr::class, 'handle');

            $stale = curl_init();
            $handleProp->setValue(null, $stale);
            $pidProp->setValue(null, (int) getmypid() + 1);

            Solr::curlTransport([
                'url'             => 'http://127.0.0.1:1/solr/core/select',
                'method'          => 'GET',
                'headers'         => [],
                'body'            => null,
                'timeout'         => 2,
                'connect_timeout' => 1,
                'user'            => '',
                'pass'            => '',
            ]);

            lh_true(
                $handleProp->getValue() !== $stale,
                'a handle inherited from another process must be replaced, never used — two processes '
                . 'writing one socket read each other\'s replies'
            );
        } finally {
            lh_reset_handle();
        }
    };

$tests['transport: the source keeps the guarantees the reuse depends on'] =
    function (): void {
        $src = (string) file_get_contents(__DIR__ . '/../src/Solr.php');

        $start = strpos($src, 'public static function curlTransport');
        lh_true($start !== false, 'curlTransport() must exist');
        $body = substr($src, (int) $start);

        $reset = strpos($body, 'curl_reset(');
        $options = strpos($body, 'curl_setopt_array(');
        lh_true($reset !== false, 'the handle must be reset before it is reused');
        lh_true($options !== false, 'the options must be set on every call');
        lh_true(
            $reset < $options,
            'curl_reset() must come BEFORE the options are set, or it erases the ones just set'
        );

        lh_contains(
            $body,
            'CURLOPT_COOKIELIST',
            'cookies survive curl_reset() and must be erased explicitly'
        );
        lh_true(
            !str_contains($body, 'curl_close('),
            'curl_close() must not appear: it is a no-op that deprecates, and it would discard the connection'
        );
        lh_contains($body, 'CURLOPT_SSL_VERIFYPEER', 'certificate verification must stay on');
        lh_contains($body, 'CURLOPT_FOLLOWLOCATION', 'redirects must still be refused');
    };

// ============================================================================================
// Standalone runner — used before tests/run.php exists.
// ============================================================================================

if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === realpath(__FILE__)) {
    require __DIR__ . '/helpers.php';
    require __DIR__ . '/../src/autoload.php';
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
