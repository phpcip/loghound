<?php
/**
 * Loghound — the failure artefact, and the secrets that must never be in one.
 *
 * WHY THIS FILE IS MOSTLY ABOUT REDACTION. The whole point of the artefact is that an operator
 * copies it and posts it somewhere public so the bug gets found quickly. That makes it a NEW
 * SINK — one place that deliberately gathers everything about a failure, from every layer — and
 * a sink is where secrets leak. So each secret this installation holds is planted in a failure
 * path here and the block is asserted not to contain it.
 *
 * THE TRAP THAT MAKES BLANKET REDACTION WRONG. Opensolr sets a new index's HTTP auth password
 * TO THE ACCOUNT API KEY. An earlier attempt scrubbed API-key-shaped strings out of control-plane
 * RESPONSES, which replaced the credential Loghound needs with a marker and made every
 * authenticated query fail 401 — see tests/test_secret_boundaries.php, which pins that a response
 * carries its values through intact. The resolution is that redaction happens where a value is
 * SHOWN, never where it is read. Diagnostics is such a place. Both halves are asserted here: the
 * block does not carry the key, and reading the same value through the client still yields it.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Config;
use Loghound\Diagnostics;
use Loghound\Opensolr;

/** Every secret a Loghound installation holds, each a distinguishable sentinel. */
const LH_DX_KEY   = 'os-api-key-9d2f4b7a1c8e';
const LH_DX_BEACON = 'beacon-hmac-3f6a90d4c2b877e1aa55';
const LH_DX_SALT  = 'address-salt-7c1e4b92';
const LH_DX_HASH  = '$2y$10$dxhashdxhashdxhashdxhashdxhashdxhashdxhashdxhashdxh';
const LH_DX_EMAIL = 'the-operator@example.test';

/**
 * A configuration holding every one of them.
 *
 * `solr.http_pass` is set to the SAME value as the API key on purpose: that is what the platform
 * does on a managed install, and a test that used two different strings would never notice a
 * redactor that only knew about one of them.
 */
function lh_dx_config(): Config
{
    $cfg = Config::load('/nonexistent-loghound-diagnostics-config');
    $cfg->set('opensolr.api_key', LH_DX_KEY);
    $cfg->set('opensolr.email', LH_DX_EMAIL);
    $cfg->set('beacon.secret', LH_DX_BEACON);
    $cfg->set('privacy.ip_salt', LH_DX_SALT);
    $cfg->set('auth.password_hash', LH_DX_HASH);
    $cfg->set('solr.http_pass', LH_DX_KEY);
    $cfg->set('solr.mode', 'opensolr');

    return $cfg;
}

/** Every sentinel, with the name a failure message would call it by. */
function lh_dx_secrets(): array
{
    return [
        'the Opensolr API key'         => LH_DX_KEY,
        'the beacon signing key'       => LH_DX_BEACON,
        'the address salt'             => LH_DX_SALT,
        'the panel password hash'      => LH_DX_HASH,
        'the account email'            => LH_DX_EMAIL,
    ];
}

/** Fail if any sentinel survived into a string that is going to be published. */
function lh_dx_clean(string $block, string $where): void
{
    foreach (lh_dx_secrets() as $what => $value) {
        if (str_contains($block, $value)) {
            lh_fail(
                $what . ' reached ' . $where . ". The artefact is designed to be pasted in\n"
                . "public, so a secret in it is a secret published. Block was:\n" . $block
            );
        }
    }
}

return [

    // ---------------------------------------------------------------------------------
    // What a failure carries
    // ---------------------------------------------------------------------------------

    'a failure names what was attempted, where it died, and how to reproduce it'
        => static function (): void {
            $cfg = lh_dx_config();

            $report = Diagnostics::capture(
                'Pushing this release\'s configset',
                'Uploading schema.xml to loghound_abcd1234_hits',
                new \RuntimeException('Opensolr: HTTP 413 from upload_config_file: body too large'),
                ['Index' => 'loghound_abcd1234_hits', 'File' => 'solr/hits/conf/schema.xml'],
                $cfg
            );
            $block = Diagnostics::block($report);

            lh_contains($block, 'Pushing this release\'s configset', 'what it was doing, in the product\'s own words');
            lh_contains($block, 'Uploading schema.xml', 'which step died');
            lh_contains($block, 'HTTP 413', 'the complete underlying error, including what the platform returned');
            lh_contains($block, 'RuntimeException', 'the error type');
            lh_contains($block, 'loghound_abcd1234_hits', 'which index');
            lh_contains($block, 'solr/hits/conf/schema.xml', 'which file');
            lh_contains($block, 'Loghound', 'the release');
            lh_contains($block, PHP_VERSION, 'the PHP version');
            lh_contains($block, php_uname('s'), 'the operating system');
            lh_contains($block, 'Web server', 'the web server');
            lh_contains($block, 'Front end', 'which front end');
            lh_contains($block, 'UTC', 'and when, in the one date format this product uses');

            lh_same(
                1,
                preg_match('#^When +: \d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} UTC$#m', $block),
                'mm/dd/yyyy hh:mm:ss, never a bare toLocaleString: ' . $block
            );
        },

    'the block is one copyable thing: plain text, aligned, no colour, one line per fact'
        => static function (): void {
            $block = Diagnostics::block(Diagnostics::capture(
                'Doing a thing',
                'The step',
                "a message\nspread over\nthree lines",
                [],
                lh_dx_config()
            ));

            lh_false(str_contains($block, "\033"), 'no escape codes: this is pasted into a form');
            foreach (explode("\n", $block) as $line) {
                lh_true(
                    strlen($line) < 200 || str_starts_with($line, 'Error'),
                    'a row of the block is a line: ' . substr($line, 0, 80)
                );
            }
            lh_contains($block, 'a message spread over three lines', 'a multi-line error is flattened into its row');
        },

    // ---------------------------------------------------------------------------------
    // Redaction — one planted secret per failure path
    // ---------------------------------------------------------------------------------

    'every secret this installation holds is planted in a failure and none reaches the block'
        => static function (): void {
            $cfg = lh_dx_config();

            $paths = [
                'quoted bare in a platform message' =>
                    'The control plane said: index auth is ' . LH_DX_KEY . ' — retry',
                'echoed back inside a query string' =>
                    'Bad request: /api/get_core_status?email=' . LH_DX_EMAIL . '&api_key=' . LH_DX_KEY,
                'inside a URL that arrived carrying userinfo' =>
                    'curl: (7) failed to connect to https://lh01abcd:' . LH_DX_KEY . '@fi.solrcluster.test/solr',
                'the beacon key in a signing error' =>
                    'HMAC mismatch: secret=' . LH_DX_BEACON . ' payload=abc',
                'the address salt in a hashing error' =>
                    'applyIpPrivacy failed with salt ' . LH_DX_SALT,
                'the password hash read back out of the configuration' =>
                    'auth.password_hash is ' . LH_DX_HASH . ' and does not verify',
                'the index password, which on this platform IS the API key' =>
                    'Solr rejected the credentials: user lh01abcd pass ' . LH_DX_KEY,
            ];

            foreach ($paths as $what => $message) {
                $block = Diagnostics::block(Diagnostics::capture(
                    'Talking to your index',
                    'A step',
                    new \RuntimeException($message),
                    [],
                    $cfg
                ));
                lh_dx_clean($block, 'the block, via ' . $what);
            }
        },

    'a secret planted in the CONTEXT is redacted too, not only in the message'
        => static function (): void {
            $block = Diagnostics::block(Diagnostics::capture(
                'Talking to your index',
                'A step',
                'nothing secret here',
                [
                    'Index'   => 'loghound_abcd1234_hits',
                    'Base URL' => 'https://lh01abcd:' . LH_DX_KEY . '@fi.solrcluster.test/solr',
                    'Account' => LH_DX_EMAIL,
                ],
                lh_dx_config()
            ));

            lh_dx_clean($block, 'the block, via a context value the caller supplied');
        },

    'a secret in the STEP or in what it was doing is redacted as well' => static function (): void {
        $block = Diagnostics::block(Diagnostics::capture(
            'Authenticating with ' . LH_DX_KEY,
            'Signing a beacon token with ' . LH_DX_BEACON,
            'it did not work',
            [],
            lh_dx_config()
        ));

        lh_dx_clean($block, 'the block, via the step labels themselves');
    },

    'the session token and the session id are redacted, and they are not in the configuration'
        => static function (): void {
            $csrf = str_repeat('c', 64);
            $owner = str_repeat('o', 32);
            $_SESSION['lh_csrf'] = $csrf;
            $_SESSION['lh_job_owner'] = $owner;

            $text = Diagnostics::redact('the request carried csrf ' . $csrf . ' and owner ' . $owner, lh_dx_config());

            if (session_status() === PHP_SESSION_ACTIVE) {
                lh_false(str_contains($text, $csrf), 'the CSRF token is a bearer credential for the panel');
                lh_false(str_contains($text, $owner), 'and so is the job owner secret');
            } else {
                /* THE SUITE CANNOT START A SESSION — output has already been sent, so
                   session_start() is refused for the whole run — and a redactor that read
                   $_SESSION anyway would be reading a superglobal nobody had established. The
                   value-based pass is therefore inert here by design; what IS asserted is that
                   the shape-based pass still catches the labelled forms. */
                lh_contains(
                    Diagnostics::redact('csrf=' . $csrf, lh_dx_config()),
                    'csrf=' . $csrf,
                    'csrf is not one of the credential-shaped parameter names'
                );
                lh_contains(
                    Diagnostics::redact('token=' . $csrf, lh_dx_config()),
                    'token=[redacted]',
                    'but token= is, and that is the shape a session token travels in'
                );
            }

            unset($_SESSION['lh_csrf'], $_SESSION['lh_job_owner']);
        },

    'redaction is where a value is SHOWN, never where it is read' => static function (): void {
        /* THE OTHER HALF OF THE SAME RULE, and the reason it is repeated here rather than left
           to test_secret_boundaries.php: this class is the newest sink, and the temptation the
           next person will have is to move its redaction one layer down into the client, which
           is exactly the change that broke authentication before. */
        $body = [
            'status' => true,
            'msg'    => ['info' => [
                'connection_url' => 'https://fi.solrcluster.test:443/solr/loghound_abcd1234_hits',
                'auth_username'  => 'lh01abcd',
                'auth_password'  => LH_DX_KEY,
            ]],
        ];

        $client = new Opensolr(
            ['api_base' => 'https://opensolr.test/api', 'email' => LH_DX_EMAIL, 'api_key' => LH_DX_KEY],
            static fn (array $r): array => ['status' => 200, 'body' => (string) json_encode($body), 'error' => '']
        );

        lh_same(
            LH_DX_KEY,
            $client->connectionDetails('loghound_abcd1234_hits')['http_pass'],
            'Opensolr sets a new index\'s HTTP auth password to the account API key. Redacting '
            . 'the RESPONSE replaces the credential with a marker and every authenticated query '
            . 'afterwards fails 401. Containment belongs at the sinks; Diagnostics is one.'
        );
    },

    'a short configured value is not turned into a find-and-replace over ordinary prose'
        => static function (): void {
            $cfg = Config::load('/nonexistent-loghound-diagnostics-config-2');
            $cfg->set('privacy.ip_salt', 'a');

            lh_same(
                'a message about a thing',
                Diagnostics::redact('a message about a thing', $cfg),
                'a one-character "secret" would otherwise shred every sentence containing it, '
                . 'which turns a diagnostic into noise. The floor leaves it to the shape pass.'
            );
        },

    'the cap is applied after redaction, never before' => static function (): void {
        $padding = str_repeat('x', Diagnostics::MAX_FIELD - 10);

        $block = Diagnostics::block(Diagnostics::capture(
            'Doing a thing',
            'A step',
            $padding . ' api_key=' . LH_DX_KEY,
            [],
            lh_dx_config()
        ));

        lh_dx_clean($block, 'the block, via a secret sitting past the length cap');
    },

    'a report built with no configuration still redacts by shape' => static function (): void {
        $block = Diagnostics::block(Diagnostics::capture(
            'Doing a thing',
            'A step',
            'failed on /api/x?email=someone@example.test&api_key=whatever-it-was',
            []
        ));

        lh_contains($block, 'api_key=[redacted]', 'the shape pass runs with no config to name values from');
        lh_contains($block, 'email=[redacted]', 'and the account email travels beside it');
        lh_false(str_contains($block, 'whatever-it-was'), 'so the value does not survive');
    },

    'the terminal prints the same artefact the browser does, from the same builder'
        => static function (): void {
            $wizard = (string) file_get_contents(dirname(__DIR__) . '/bin/loghound-setup');

            lh_contains($wizard, 'use Loghound\\Diagnostics;', 'the wizard builds the block rather than inventing one');
            lh_contains($wizard, 'public function problem(', 'and has one place that prints it');
            lh_contains(
                $wizard,
                'Diagnostics::block(Diagnostics::capture(',
                'a bug reported from a terminal and the same bug reported from a browser have to '
                . 'arrive in the same shape, or the person reading them cannot tell they are the '
                . 'same bug'
            );
            lh_contains($wizard, "str_repeat('-', 76)", 'printed between two rules, so a copy is the block and nothing else');

            foreach ([
                "\$UI->problem('Running the ' . \$kind . ' setup job', 'Creating the job'" => 'a job that will not start',
                "\$UI->problem(\n            'Running the ' . \$kind . ' setup job'"        => 'a step that failed',
                "\$UI->problem('Writing the configuration'"                                 => 'a configuration that will not write',
            ] as $call => $what) {
                lh_contains($wizard, $call, 'the terminal prints a block for ' . $what);
            }
        },

    'the job payload carries the block as its own field, redacted on the way out'
        => static function (): void {
            $jobs = (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Jobs.php');

            lh_contains(
                $jobs,
                "'report' => isset(\$result['report']) ? self::redact((string) \$result['report']) : null,",
                'the artefact reaches the browser as its own field and goes through the same '
                . 'boundary redaction as every other field. A field that skipped it would be '
                . 'the one that leaked.'
            );

            $core = (string) file_get_contents(dirname(__DIR__) . '/public/assets/js/core.js');
            lh_contains($core, 'if (step.report) {', 'and the front end renders it');
            lh_contains($core, 'snippet(String(step.report))', 'through the shared pre plus copy button');
        },

    'a source path in the block is repository-relative, not the operator\'s directory layout'
        => static function (): void {
            $report = Diagnostics::capture(
                'Doing a thing',
                'A step',
                new \RuntimeException('boom'),
                [],
                lh_dx_config(),
                dirname(__DIR__)
            );

            lh_contains((string) $report['raised_at'], 'tests/test_diagnostics.php:', 'relative to the install root');
            lh_false(
                str_contains((string) $report['raised_at'], dirname(__DIR__)),
                'an absolute path is the operator\'s layout, which is noise in a report somebody '
                . 'else is going to read'
            );
        },
];
