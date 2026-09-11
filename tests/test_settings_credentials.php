<?php
/**
 * Loghound — changing the Opensolr account from the panel, without giving anything away.
 *
 * The Solr card used to refuse this: it said connection details are edited in
 * config/loghound.php and that a web form is the wrong place for an API key. That refusal was
 * overruled, so the cost it was avoiding has to be paid explicitly instead — and these are the
 * properties that pay it.
 *
 *   - WRITE-ONLY. The stored key never reaches the page, in any form. A masked secret is still
 *     a secret, and a length hint is still an oracle.
 *   - VALIDATED FIRST. A key that does not authenticate must never replace one that does.
 *     Pasting a typo into a panel form must not lock an operator out of their own indexes.
 *   - A CURRENT SECOND FACTOR when one is configured, because replacing this credential from a
 *     stolen session means redirecting an entire installation's data into somebody else's
 *     account, quietly.
 *   - ONE WRITE PATH. Config::save(), the same as everything else.
 *
 * Every assertion here drives the real handler against a scripted control plane. The API key in
 * the scaffold is a sentinel, so a leak into a page or a message fails a test rather than
 * escaping unnoticed.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Config;
use Loghound\Panel\Gateway;
use Loghound\Panel\Settings;
use Loghound\Security;
use Loghound\Setup\Storage;

/** The stored key. It must never appear in a rendered page or a message. */
const LH_CRED_OLD = 'SENTINEL-STORED-KEY-0001';

/** What the operator types. It must never be echoed back either. */
const LH_CRED_NEW = 'SENTINEL-TYPED-KEY-0002';

/**
 * A configured installation whose Solr card can be rendered and posted to.
 *
 * @return array{0:string,1:Config}
 */
function lh_cred_scaffold(): array
{
    $root = lh_tmpdir('lh-cred');
    @mkdir($root . '/config', 0750, true);
    @mkdir($root . '/var', 0750, true);

    $cfg = Config::load($root . '/config/loghound.php');
    $cfg->set('solr.mode', 'opensolr');
    $cfg->set('solr.install_id', 'aaaa1111');
    $cfg->set('solr.hits_core', 'loghound_aaaa1111_hits');
    $cfg->set('solr.sessions_core', 'loghound_aaaa1111_sessions');
    $cfg->set('solr.base_url', 'https://fi.solrcluster.com/solr');
    $cfg->set('opensolr.email', 'old@example.com');
    $cfg->set('opensolr.api_key', LH_CRED_OLD);
    $cfg->set('opensolr.region', 'FINLAND9');
    $cfg->set('auth.user', 'admin');
    $cfg->set('auth.password_hash', password_hash('a-long-enough-password', PASSWORD_DEFAULT));
    $cfg->set('auth.mode', 'basic');
    $cfg->save();

    return [$root, $cfg];
}

/**
 * A control plane that accepts exactly one key, and remembers what it was asked.
 *
 * @param array<int,string> $calls
 * @param string[]          $held
 */
function lh_cred_transport(array &$calls, string $goodKey, array $held = []): callable
{
    return static function (array $req) use (&$calls, $goodKey, $held): array {
        $url = (string) $req['url'];
        $calls[] = $url;

        $get = static function (string $k) use ($url): string {
            return preg_match('/[?&]' . $k . '=([^&]*)/', $url, $m) === 1 ? urldecode($m[1]) : '';
        };

        if ($get('api_key') !== $goodKey) {
            return [
                'status' => 200,
                'body'   => (string) json_encode(['status' => false, 'msg' => 'ERROR_AUTHENTICATION_FAILED']),
                'error'  => '',
            ];
        }

        $body = ['status' => true, 'msg' => 'OK'];
        if (str_contains($url, '/regions')) {
            $body = ['FINLAND9', 'GERMANY9'];
        } elseif (str_contains($url, '/get_index_list')) {
            $body = array_map(
                static fn (string $n): array => ['index_name' => $n, 'index_type' => '-1'],
                $held
            );
        }

        return ['status' => 200, 'body' => (string) json_encode($body), 'error' => ''];
    };
}

/**
 * Post to the Solr credential action and hand back the redirect target.
 *
 * @param array<string,string> $fields
 */
function lh_cred_post(Config $cfg, string $root, array $fields): string
{
    $_POST = ['action' => 'opensolr_credentials', 'csrf' => lh_csrf()] + $fields;
    $_SERVER['REQUEST_METHOD'] = 'POST';

    $settings = new Settings($cfg, new Gateway($cfg, null, false));
    $target = $settings->post();

    $_POST = [];
    return $target;
}

/** Render the Solr card and hand back its HTML. */
function lh_cred_render(Config $cfg, string $root): string
{
    $settings = new Settings($cfg, new Gateway($cfg, null, false));
    ob_start();
    $settings->body();
    return (string) ob_get_clean();
}

/** The configuration as it is ON DISK, which is the only thing that counts. */
function lh_cred_stored(string $root): array
{
    return Config::load($root . '/config/loghound.php')->all();
}

return [

    'the stored key never reaches the page, in any form' => static function (): void {
        [$root, $cfg] = lh_cred_scaffold();

        $html = lh_cred_render($cfg, $root);

        lh_false(str_contains($html, LH_CRED_OLD), 'not as a value');
        lh_false(str_contains($html, substr(LH_CRED_OLD, 0, 8)), 'not as a prefix or a mask');
        lh_false(
            (bool) preg_match('/id="opensolr_api_key"[^>]*\bvalue=/', $html),
            'the key field carries no value attribute at all, on any render'
        );
        lh_contains($html, 'type="password"', 'and it is a password field');
        lh_contains($html, 'configured', 'the card says a key is set, which reveals nothing');

        lh_rmtree($root);
    },

    'a key that does not authenticate never replaces one that does' => static function (): void {
        [$root, $cfg] = lh_cred_scaffold();

        $calls = [];
        Storage::useTestTransport(lh_cred_transport($calls, LH_CRED_OLD));
        try {
            $target = lh_cred_post($cfg, $root, [
                'opensolr_email'   => 'new@example.com',
                'opensolr_api_key' => 'SENTINEL-WRONG-KEY-9999',
                'opensolr_region'  => 'FINLAND9',
            ]);

            lh_contains($target, 'err=opensolr_refused', 'the change is refused');

            $stored = lh_cred_stored($root);
            lh_same(LH_CRED_OLD, $stored['opensolr']['api_key'], 'the working key is still the stored key');
            lh_same(
                'old@example.com',
                $stored['opensolr']['email'],
                'and the email did not move either — a refusal changes nothing, not part of it'
            );
        } finally {
            Storage::useTestTransport(null);
        }

        $html = lh_cred_render($cfg, $root);
        lh_contains($html, 'did not accept', 'the card says precisely what came back');
        lh_false(str_contains($html, LH_CRED_OLD), 'without quoting the stored key');
        lh_false(str_contains($html, 'SENTINEL-WRONG-KEY-9999'), 'or the one that was typed');

        lh_rmtree($root);
    },

    'a key that does authenticate is stored, through the one write path' => static function (): void {
        [$root, $cfg] = lh_cred_scaffold();

        $calls = [];
        Storage::useTestTransport(lh_cred_transport($calls, LH_CRED_NEW, [
            'loghound_aaaa1111_hits',
            'loghound_aaaa1111_sessions',
        ]));
        try {
            $target = lh_cred_post($cfg, $root, [
                'opensolr_email'   => 'new@example.com',
                'opensolr_api_key' => LH_CRED_NEW,
                'opensolr_region'  => 'GERMANY9',
            ]);

            lh_contains($target, 'ok=opensolr_saved', 'the change lands');
        } finally {
            Storage::useTestTransport(null);
        }

        $stored = lh_cred_stored($root);
        lh_same(LH_CRED_NEW, $stored['opensolr']['api_key'], 'the new key is stored');
        lh_same('new@example.com', $stored['opensolr']['email']);
        lh_same('GERMANY9', $stored['opensolr']['region']);

        lh_same(
            '0640',
            substr(sprintf('%o', fileperms($root . '/config/loghound.php')), -4),
            'written by Config::save(), so it carries the mode every other write does'
        );

        lh_rmtree($root);
    },

    'an empty key field keeps the stored key, exactly as the wizard prompt does'
        => static function (): void {
            [$root, $cfg] = lh_cred_scaffold();

            $calls = [];
            Storage::useTestTransport(lh_cred_transport($calls, LH_CRED_OLD, ['loghound_aaaa1111_hits']));
            try {
                $target = lh_cred_post($cfg, $root, [
                    'opensolr_email'   => 'old@example.com',
                    'opensolr_api_key' => '',
                    'opensolr_region'  => 'GERMANY9',
                ]);
                lh_contains($target, 'ok=opensolr_saved', 'changing only the region is a normal thing to do');
            } finally {
                Storage::useTestTransport(null);
            }

            $stored = lh_cred_stored($root);
            lh_same(LH_CRED_OLD, $stored['opensolr']['api_key'], 'blank means keep, never clear');
            lh_same('GERMANY9', $stored['opensolr']['region'], 'and the field that did change, changed');

            lh_rmtree($root);
        },

    'a region the account cannot use is refused, and the refusal names the ones it can'
        => static function (): void {
            [$root, $cfg] = lh_cred_scaffold();

            $calls = [];
            Storage::useTestTransport(lh_cred_transport($calls, LH_CRED_OLD));
            try {
                $target = lh_cred_post($cfg, $root, [
                    'opensolr_email'   => 'old@example.com',
                    'opensolr_api_key' => '',
                    'opensolr_region'  => 'ATLANTIS1',
                ]);
                lh_contains($target, 'err=opensolr_refused');
            } finally {
                Storage::useTestTransport(null);
            }

            lh_same('FINLAND9', lh_cred_stored($root)['opensolr']['region'], 'nothing moved');

            $html = lh_cred_render($cfg, $root);
            lh_contains($html, 'ATLANTIS1', 'the refusal names what was asked for');
            lh_contains($html, 'GERMANY9', 'and what is available instead');

            lh_rmtree($root);
        },

    'the credential change is not reachable without a current second factor' => static function (): void {
        [$root, $cfg] = lh_cred_scaffold();

        $cfg->set('auth.totp', [
            'enabled'  => true,
            'secret'   => 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
            'recovery' => [],
        ]);
        $cfg->save();

        $calls = [];
        Storage::useTestTransport(lh_cred_transport($calls, LH_CRED_NEW));
        try {
            $target = lh_cred_post($cfg, $root, [
                'opensolr_email'   => 'new@example.com',
                'opensolr_api_key' => LH_CRED_NEW,
                'opensolr_region'  => 'FINLAND9',
                'code'             => '000000',
            ]);

            lh_contains(
                $target,
                'err=totp',
                'a wrong code refuses the change: this credential can redirect an entire '
                . 'installation into somebody else\'s account, so a session alone must not buy it'
            );
            lh_same(
                [],
                $calls,
                'and it refuses BEFORE contacting the platform, so a stolen session cannot even '
                . 'use this endpoint to test keys'
            );
        } finally {
            Storage::useTestTransport(null);
        }

        lh_same(LH_CRED_OLD, lh_cred_stored($root)['opensolr']['api_key'], 'nothing changed');

        lh_rmtree($root);
    },

    'the card offers the shell route as well, because a headless install has no browser'
        => static function (): void {
            [$root, $cfg] = lh_cred_scaffold();

            $html = lh_cred_render($cfg, $root);

            lh_contains($html, 'bin/loghound-setup', 'the command is still named');
            lh_contains($html, 'set-solr-setup', 'with the same copy control as everywhere else');
            lh_contains(
                $html,
                'same validation, same outcome',
                'and the two paths are stated to agree, the way the two installers do'
            );

            lh_false(
                str_contains($html, 'a web form is the wrong place'),
                'the card no longer refuses the thing it now does'
            );

            lh_rmtree($root);
        },

    'nothing about this action can be logged, queued or handed to the browser'
        => static function (): void {
            $php = (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Settings.php');

            lh_true(
                (bool) preg_match("/unset\(\\\$_POST\['opensolr_api_key'\]\);/", $php),
                'the key is taken out of the request as soon as it has been read, so nothing '
                . 'running later in the same request can reach it'
            );
            lh_false(
                (bool) preg_match('/error_log\([^)]*api_key/i', $php),
                'and it never reaches a log call'
            );

            foreach (['opensolr_api_key', 'api_key'] as $needle) {
                lh_false(
                    (bool) preg_match('/escJs\([^)]*' . preg_quote($needle, '/') . '/i', $php),
                    $needle . ' must never be encoded into anything sent to the browser'
                );
            }
        },
];
