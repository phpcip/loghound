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

    /* ---------------------------------------------------------------------------------
     * The block is designed to be pasted in public, so every secret is attacked by hand
     *
     * These were all found by construction rather than by reading: a sentinel per secret,
     * planted in a message shaped the way the value would really arrive, and the assertion
     * is that the sentinel is gone. Four of them survived.
     * ------------------------------------------------------------------------------ */

    'no secret this installation holds survives into a pasteable block'
        => static function (): void {
            $dir = lh_leak_tmpdir();
            @mkdir($dir . '/config', 0700, true);
            @mkdir($dir . '/var', 0700, true);

            $cfg = Config::load($dir . '/config/loghound.php');
            $cfg->set('opensolr.api_key', 'LEAKPROBE-APIKEY-0000000001');
            $cfg->set('opensolr.email', 'leakprobe-account@example.com');
            $cfg->set('beacon.secret', 'LEAKPROBE-BEACONSECRET-000000000000000001');
            $cfg->set('privacy.ip_salt', 'LEAKPROBE-ADDRESSSALT-0001');
            $cfg->set('auth.password_hash', 'LEAKPROBE-PASSWORDHASH-001');
            $cfg->set('solr.http_pass', 'LEAKPROBE-INDEXPASSWORD-01');
            $cfg->set('auth.totp', [
                'enabled'  => true,
                'secret'   => 'LEAKPROBETOTPSEEDAAAAAAAAAAAAAAA',
                'recovery' => ['LEAKPROBE-RECOVERYHASH-001'],
            ]);

            $before = $_COOKIE;
            $_COOKIE[\Loghound\Auth\Persistence::COOKIE] =
                'LEAKPROBESELECTOR:LEAKPROBE-REMEMBERVERIFIER-01';

            /* EACH SENTINEL IN THE SHAPE IT REALLY ARRIVES IN. Bare in a sentence is the one
               that matters: the shape pass has nothing to anchor on there, so anything not on
               the value list walks straight through. */
            $sentinels = [
                'LEAKPROBE-APIKEY-0000000001',
                'leakprobe-account@example.com',
                'LEAKPROBE-BEACONSECRET-000000000000000001',
                'LEAKPROBE-ADDRESSSALT-0001',
                'LEAKPROBE-PASSWORDHASH-001',
                'LEAKPROBE-INDEXPASSWORD-01',
                'LEAKPROBETOTPSEEDAAAAAAAAAAAAAAA',
                'LEAKPROBE-RECOVERYHASH-001',
                'LEAKPROBE-REMEMBERVERIFIER-01',
            ];

            foreach ($sentinels as $secret) {
                $carriers = [
                    'bare in a sentence'  => 'The platform refused: ' . $secret . ' is not valid',
                    'in a fact label'     => null,
                    'in a fact value'     => null,
                    'quoted in json'      => '{"echo":"' . $secret . '"}',
                    'in a header echo'    => 'Cookie: lh_remember=' . $secret . '; Path=/',
                ];

                foreach (['bare in a sentence', 'quoted in json', 'in a header echo'] as $how) {
                    $block = \Loghound\Diagnostics::block(\Loghound\Diagnostics::capture(
                        'Doing the thing',
                        'A step',
                        (string) $carriers[$how],
                        [],
                        $cfg,
                        $dir
                    ));
                    lh_false(
                        str_contains($block, $secret),
                        $secret . ' survived a block ' . $how
                    );
                }

                $block = \Loghound\Diagnostics::block(\Loghound\Diagnostics::capture(
                    'Doing the thing',
                    'A step',
                    'boom',
                    [$secret => 'a value', 'A label' => $secret],
                    $cfg,
                    $dir
                ));
                lh_false(
                    str_contains($block, $secret),
                    $secret . ' survived a block in a fact — labels are published too'
                );
            }

            $_COOKIE = $before;
            lh_leak_rmdir($dir);
        },

    /* A SECRET DOES NOT ONLY TRAVEL AS ITSELF. HTTP Basic sends `base64(user:pass)`, and that
       is how Loghound authenticates to Solr — where `solr.http_pass` IS the account API key on
       a managed installation. A reverse proxy or a Solr error page that reflects the request's
       Authorization header puts the account key into a message in a spelling the shape pass
       has nothing to match on and the literal pass did not know to look for, and this block is
       designed to be pasted in public. */
    'a credential is redacted in the form it is actually sent in, not only as itself'
        => static function (): void {
            $dir = lh_leak_tmpdir();
            @mkdir($dir . '/config', 0700, true);
            @mkdir($dir . '/var', 0700, true);

            $cfg = Config::load($dir . '/config/loghound.php');
            /* Deliberately full of characters that make the encodings differ from the literal;
               a sentinel of plain hex would make this test pass without testing anything. */
            $key = 'LEAKPROBE+key/with=specials?&#and-more';
            $cfg->set('opensolr.api_key', $key);
            $cfg->set('solr.http_user', 'loghound');
            $cfg->set('solr.http_pass', $key);

            $pair = base64_encode('loghound:' . $key);
            $alone = base64_encode($key);

            lh_true($pair !== $key && $alone !== $key, 'the encoded forms really are different strings');

            foreach ([
                'a reflected Basic header' => 'upstream said: Authorization: Basic ' . $pair,
                'the key alone, encoded'   => 'rejected token ' . $alone,
                'the key as itself'        => 'rejected key ' . $key,
            ] as $how => $message) {
                $block = \Loghound\Diagnostics::block(\Loghound\Diagnostics::capture(
                    'Querying the index',
                    'Reading a response',
                    $message,
                    [],
                    $cfg,
                    $dir
                ));

                foreach ([$pair, $alone, $key] as $form) {
                    lh_false(
                        str_contains($block, $form),
                        'the account key survived a pasteable block via ' . $how
                    );
                }
            }

            lh_leak_rmdir($dir);
        },

    'a fact label cannot reformat or outgrow the block it is in'
        => static function (): void {
            $block = \Loghound\Diagnostics::block(\Loghound\Diagnostics::capture(
                'Doing the thing',
                'A step',
                'boom',
                [str_repeat('w', 4000) => 'v', "two\nlines" => 'v2'],
                null,
                null
            ));

            foreach (explode("\n", $block) as $line) {
                lh_true(
                    strlen($line) <= \Loghound\Diagnostics::MAX_LABEL + \Loghound\Diagnostics::MAX_FIELD + 8,
                    'a label sets the width of every row, so an uncapped one reformats the artefact'
                );
            }
            lh_false(
                str_contains($block, str_repeat('w', 200)),
                'the label is cut, not merely padded around'
            );
        },

    'a redactor that cannot run loses the redaction, never the message'
        => static function (): void {
            foreach ([
                'src/Panel/Jobs.php',
                'src/OpensolrLog.php',
                'src/Opensolr.php',
                'src/Diagnostics.php',
            ] as $file) {
                $body = (string) file_get_contents(dirname(__DIR__) . '/' . $file);

                foreach (explode("\n", $body) as $line) {
                    if (!str_contains($line, 'preg_replace') || !str_contains($line, 'redacted')) {
                        continue;
                    }
                    lh_false(
                        (bool) preg_match('/\(string\)\s*preg_replace/', $line),
                        $file . ': casting preg_replace() to string blanks the message on a PCRE '
                        . 'failure, which hands an attacker a way to erase a diagnostic'
                    );
                }
            }
        },

    'the platform\'s own words are redacted on every branch that keeps them'
        => static function (): void {
            $body = (string) file_get_contents(dirname(__DIR__) . '/src/Opensolr.php');

            $push = strstr($body, 'public function pushConfigSet(');
            lh_true(is_string($push), 'pushConfigSet() not found');
            $push = substr((string) $push, 0, (int) strpos((string) $push, "\n    }"));

            foreach (explode("\n", $push) as $line) {
                $fromPlatform = str_contains($line, 'stringifyMsg')
                    || str_contains($line, 'getMessage')
                    || str_contains($line, "\$res['msg']");
                if (!$fromPlatform) {
                    continue;
                }
                lh_true(
                    str_contains($line, 'redact'),
                    'a msg kept from the platform must be redacted on EVERY branch, not only '
                    . 'the one where an exception was thrown: ' . trim($line)
                );
            }
        },

    'a refusal shows the operator the same redacted text it wrote down'
        => static function (): void {
            $body = (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Settings.php');

            $fn = strstr($body, 'private static function teardownRefusal(');
            lh_true(is_string($fn), 'teardownRefusal() not found');
            $fn = substr((string) $fn, 0, (int) strpos((string) $fn, "\n    }"));

            lh_false(
                (bool) preg_match("/'detail'\s*=>\s*\\\$why/", $fn),
                'the refusal returned the raw control-plane text beside a redacted copy of itself'
            );
            lh_true(
                (bool) preg_match("/'detail'\s*=>[^,]*\\\$report\['error'\]/", $fn),
                'the detail must be the redacted field, which is what the sibling path returns'
            );
        },
];
