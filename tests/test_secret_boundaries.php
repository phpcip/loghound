<?php
/**
 * Loghound — tests that the Opensolr API key cannot walk out through a diagnostic.
 *
 * The key travels as a query parameter, and the platform echoes request parameters back in
 * some error paths. Every place that records "what went wrong" is therefore a place the key
 * can land: an exception message, a job note, a job's stored context, the error log.
 *
 * Three of those were covered and one was not, in each of two classes — which is the shape
 * this failure always takes. A redactor applied to three fields out of four is one somebody
 * will reasonably assume covers the fourth. These tests assert the boundary, not the field.
 *
 * The setup job matters most: its state file is served by an endpoint that answers BEFORE
 * authentication exists, because the installer runs precisely when there is no account yet.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Config;
use Loghound\Opensolr;
use Loghound\Panel\Gateway;
use Loghound\Panel\Jobs;
use Loghound\Setup\Job;
use Loghound\Solr;

/** The value that must never survive a round trip through any diagnostic. */
const LH_LEAK_KEY = 'KEY_THAT_MUST_NEVER_APPEAR_9f3a2b';

/**
 * An Opensolr client whose transport replays one canned response.
 *
 * @param array<string,mixed> $body   Decoded body the platform "returned".
 * @param int                 $status HTTP status it came back with.
 */
function lh_leak_client(array $body, int $status = 200): Opensolr
{
    $transport = static fn (array $req): array => [
        'status' => $status,
        'body'   => (string) json_encode($body),
        'error'  => '',
    ];

    return new Opensolr([
        'api_base' => 'https://opensolr.test/solr_manager/api',
        'email'    => 'test@example.com',
        'api_key'  => LH_LEAK_KEY,
        'region'   => 'FINLAND9',
    ], $transport);
}

/**
 * Recursively assert that no string anywhere in a structure carries the key.
 *
 * @param mixed $value
 */
function lh_leak_assert_clean($value, string $where): void
{
    if (is_string($value)) {
        if (str_contains($value, LH_LEAK_KEY)) {
            throw new \RuntimeException('The API key survived in ' . $where . ': ' . $value);
        }
        return;
    }
    if (is_array($value)) {
        foreach ($value as $k => $v) {
            lh_leak_assert_clean($v, $where . '[' . (string) $k . ']');
        }
    }
}

/** A throwaway directory under the system temp root, removed by the caller. */
function lh_leak_tmpdir(): string
{
    $dir = sys_get_temp_dir() . '/lh-leak-' . bin2hex(random_bytes(6));
    if (!mkdir($dir, 0700, true) && !is_dir($dir)) {
        throw new \RuntimeException('Cannot create ' . $dir);
    }
    return $dir;
}

/**
 * Remove a directory this file created, one level deep, never following a link.
 */
function lh_leak_rmdir(string $dir): void
{
    if (is_link($dir) || !is_dir($dir)) {
        return;
    }
    foreach ((array) scandir($dir) as $entry) {
        if ($entry === '.' || $entry === '..') {
            continue;
        }
        $path = $dir . '/' . $entry;
        if (!is_link($path) && is_file($path)) {
            @unlink($path);
        }
    }
    @rmdir($dir);
}

/**
 * A job store carrying one planner that records whatever string it is given.
 *
 * @param array<string,callable> $plans
 */
function lh_leak_jobs(array $plans): Jobs
{
    $_SESSION['lh_job_owner'] = 'leak-' . bin2hex(random_bytes(8));
    $_SESSION['lh_user'] = 'tester';

    $cfg = Config::load('/nonexistent-loghound-config');
    $cfg->set('solr.base_url', 'http://127.0.0.1:65535/solr');
    $cfg->set('solr.hits_core', 'lh_test_hits');
    $cfg->set('solr.sessions_core', 'lh_test_sessions');

    $transport = static fn (array $r): array => [
        'status' => 200,
        'body'   => (string) json_encode(['responseHeader' => ['status' => 0]]),
        'error'  => '',
    ];

    return new Jobs($cfg, new Gateway($cfg, new Solr((array) $cfg->get('solr'), $transport), false), $plans);
}

return [

    'a credential that happens to equal the API key survives intact'
        => static function (): void {
            $body = [
                'status' => true,
                'msg'    => [
                    'info' => [
                        'connection_url' => 'https://fi.solrcluster.test:443/solr/loghound_deadbeef_hits',
                        'auth_username'  => 'lh01abcd',
                        'auth_password'  => LH_LEAK_KEY,
                    ],
                ],
            ];

            $conn = lh_leak_client($body)->connectionDetails('loghound_deadbeef_hits');

            if (($conn['http_pass'] ?? '') !== LH_LEAK_KEY) {
                throw new \RuntimeException(
                    'The index password was altered on its way out of the client. Opensolr sets a new '
                    . 'index\'s HTTP auth password to the account API key, so a blanket redaction of '
                    . 'the response replaces the credential with its own marker and every authenticated '
                    . 'query then fails 401. Got: ' . var_export($conn['http_pass'] ?? null, true)
                );
            }
        },

    'redaction happens where a value is shown, not where it is read'
        => static function (): void {
            $echoed = 'Bad request: /api/get_core_status?email=test%40example.com&api_key=' . LH_LEAK_KEY;

            $out = lh_leak_client(['status' => false, 'msg' => $echoed])->indexStatus('lh_probe_core');

            if (($out['msg'] ?? '') !== $echoed) {
                throw new \RuntimeException(
                    'decode() is altering response values again. It must not: a response legitimately '
                    . 'carries credentials the caller needs. Containment belongs at the sinks — '
                    . 'Setup\\Job::note(), Jobs::shape() and the error log — each of which has its own test.'
                );
            }
        },

    'an HTTP error still throws a redacted message' => static function (): void {
        $client = lh_leak_client(['status' => false, 'msg' => 'api_key=' . LH_LEAK_KEY], 500);

        try {
            $client->indexStatus('lh_probe_core');
        } catch (\RuntimeException $e) {
            lh_leak_assert_clean($e->getMessage(), 'the thrown message');
            return;
        }
        throw new \RuntimeException('An HTTP 500 did not throw.');
    },

    'a setup job note is redacted before it reaches the state file' => static function (): void {
        $dir = lh_leak_tmpdir();
        try {
            $job = Job::create($dir, Job::KIND_OPENSOLR, []);
            $job->note('platform said: api_key=' . LH_LEAK_KEY . ' is invalid');

            $files = (array) glob($dir . '/*.json');
            if ($files === []) {
                throw new \RuntimeException('The job wrote no state file.');
            }

            foreach ($files as $file) {
                $raw = (string) file_get_contents((string) $file);
                if (str_contains($raw, LH_LEAK_KEY)) {
                    throw new \RuntimeException(
                        'The API key was written into ' . basename((string) $file)
                        . ', which the setup job endpoint serves before any account exists.'
                    );
                }
            }
        } finally {
            lh_leak_rmdir($dir);
        }
    },

    'a job context is redacted on its way to the browser' => static function (): void {
        $plans = [
            'leak_probe' => static fn (array $ctx): array => [
                [
                    'label' => 'Recording',
                    'run'   => static fn (array $c): array => [
                        'context' => ['detail' => 'upstream: api_key=' . LH_LEAK_KEY],
                    ],
                ],
            ],
        ];

        $jobs = lh_leak_jobs($plans);
        $started = $jobs->start('leak_probe');
        $id = (string) ($started['id'] ?? '');
        if ($id === '') {
            throw new \RuntimeException('The probe job did not start: ' . var_export($started, true));
        }

        $after = $jobs->advance($id);

        lh_leak_assert_clean($after, 'the polled job');
    },

    'the front controller redacts before it writes to the error log' => static function (): void {
        $source = (string) file_get_contents(__DIR__ . '/../public/index.php');

        preg_match_all('/error_log\((.*?)\);/s', $source, $m);
        if ($m[1] === []) {
            throw new \RuntimeException('No error_log call found; this test no longer guards anything.');
        }

        foreach ($m[1] as $call) {
            if (str_contains($call, 'getMessage()') && !str_contains($call, 'redact(')) {
                throw new \RuntimeException(
                    'An exception message reaches the error log unredacted: ' . trim($call)
                );
            }
        }
    },

    'every diagnostic field of a job passes through the same redactor' => static function (): void {
        $source = (string) file_get_contents(__DIR__ . '/../src/Panel/Jobs.php');

        $shape = strstr($source, 'private function shape(');
        if ($shape === false) {
            throw new \RuntimeException('Jobs::shape() not found.');
        }
        $shape = substr($shape, 0, (int) strpos($shape, "\n    }"));

        foreach (['error', 'result'] as $field) {
            if (!preg_match('/\'' . $field . '\'\s*=>[^,]*redact/i', $shape)) {
                throw new \RuntimeException(
                    'Jobs::shape() returns "' . $field . '" to the browser without redacting it.'
                );
            }
        }
    },
];
