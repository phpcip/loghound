<?php
/**
 * Loghound — starting the installation over, without locking anybody out of it.
 *
 * THE TRAP THIS FEATURE CREATES, and the reason most of these tests exist. Resetting the
 * configuration makes Installer::isNeeded() true again, and the installer then demands the token
 * from var/install-token — which needs shell access to read. An operator who administers the box
 * through a browser would otherwise destroy their panel and be locked out of the installer in the
 * same click. The resolution is NOT to weaken the token: it is that pressing the button in an
 * authenticated session is already the stronger proof, so that proof is carried to that session
 * and to nothing else.
 *
 * The other half is that reinstall is not uninstall. It must not delete an index, a document or
 * a log file, and the things it deliberately keeps — the account, the beacon key, the address
 * salt — each cost something real to throw away.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Config;
use Loghound\Setup\Installer;
use Loghound\Setup\Reset;
use Loghound\Setup\Token;

/**
 * A finished installation: configured, signed in, with runtime state on disk.
 *
 * @return array{0:string,1:Config}
 */
function lh_re_scaffold(): array
{
    $root = lh_tmpdir('lh-reinstall');
    @mkdir($root . '/config', 0750, true);
    @mkdir($root . '/var/setup', 0750, true);

    $cfg = Config::load($root . '/config/loghound.php');
    $cfg->set('solr.mode', 'opensolr');
    $cfg->set('solr.install_id', 'aaaa1111');
    $cfg->set('solr.hits_core', 'loghound_aaaa1111_hits');
    $cfg->set('solr.sessions_core', 'loghound_aaaa1111_sessions');
    $cfg->set('solr.base_url', 'https://fi.solrcluster.com/solr');
    $cfg->set('solr.http_user', 'u');
    $cfg->set('solr.http_pass', 'p');
    $cfg->set('opensolr.email', 'me@example.com');
    $cfg->set('opensolr.api_key', 'SENTINEL-KEEP-THIS-KEY');
    $cfg->set('opensolr.region', 'FINLAND9');
    $cfg->set('beacon.secret', str_repeat('b', 64));
    $cfg->set('privacy.ip_salt', str_repeat('s', 32));
    $cfg->set('sources', [['path' => '/var/log/apache2/access.log', 'format' => 'apache_combined']]);
    $cfg->set('auth.user', 'admin');
    $cfg->set('auth.password_hash', password_hash('a-long-enough-password', PASSWORD_DEFAULT));
    $cfg->set('auth.mode', 'basic');
    $cfg->set('auth.totp', ['enabled' => true, 'secret' => 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP', 'recovery' => ['x']]);
    $cfg->save();

    foreach (['state.db', 'detect.json', 'tail-status.json'] as $f) {
        file_put_contents($root . '/var/' . $f, 'x');
    }
    file_put_contents($root . '/var/setup/deadbeefdeadbeef.json', '{}');
    file_put_contents($root . '/var/login-attempts.json', '{"a":1}');

    return [$root, $cfg];
}

return [

    'a finished installation does not need the installer, and a reset one does'
        => static function (): void {
            [$root, $cfg] = lh_re_scaffold();

            lh_false(Installer::isNeeded($cfg), 'a finished install serves the panel');

            Reset::perform($cfg);

            lh_true(
                Installer::isNeeded(Config::load($root . '/config/loghound.php')),
                'and a reset one hands the browser back to the installer — read from DISK, because '
                . 'that is what the next request will read'
            );

            lh_rmtree($root);
        },

    'reinstall is not uninstall: nothing that holds data is touched' => static function (): void {
        [$root, $cfg] = lh_re_scaffold();

        $result = Reset::perform($cfg);
        lh_true($result['ok'], 'the reset succeeded');

        $stored = Config::load($root . '/config/loghound.php');

        lh_same(
            'SENTINEL-KEEP-THIS-KEY',
            (string) $stored->get('opensolr.api_key'),
            'the account is kept, so setup can offer back the pairs it already holds'
        );
        lh_same('me@example.com', (string) $stored->get('opensolr.email'));
        lh_same('FINLAND9', (string) $stored->get('opensolr.region'));

        lh_same(
            str_repeat('b', 64),
            (string) $stored->get('beacon.secret'),
            'the beacon key is kept: rotating it would invalidate every token already in a '
            . 'visitor\'s browser, and the scorer reads an invalid token as evidence of a bot'
        );
        lh_same(
            str_repeat('s', 32),
            (string) $stored->get('privacy.ip_salt'),
            'and the address salt is kept, or hashed visitors stop matching themselves'
        );

        lh_true(
            is_file($root . '/var/login-attempts.json'),
            'the sign-in rate-limit ledger survives: a reinstall must not clear somebody\'s lockout'
        );

        lh_rmtree($root);
    },

    'what a reset clears is exactly what setup asks for again' => static function (): void {
        [$root, $cfg] = lh_re_scaffold();

        Reset::perform($cfg);
        $stored = Config::load($root . '/config/loghound.php');

        lh_same([], (array) $stored->get('sources'), 'the log files are forgotten');
        lh_same('', (string) $stored->get('solr.hits_core'), 'and the index names');
        lh_same('', (string) $stored->get('solr.sessions_core'));
        lh_same('', (string) $stored->get('solr.base_url'));
        lh_same('', (string) $stored->get('solr.install_id'));
        lh_same('', (string) $stored->get('auth.password_hash'), 'and the sign-in');
        lh_same('none', (string) $stored->get('auth.mode'));
        lh_false(
            (bool) $stored->get('auth.totp.enabled'),
            'two-factor goes with the account it protected, rather than demanding a code for an '
            . 'identity that no longer exists'
        );

        foreach (['state.db', 'detect.json', 'tail-status.json'] as $f) {
            lh_false(is_file($root . '/var/' . $f), $f . ' is removed');
        }
        lh_false(
            is_file($root . '/var/setup/deadbeefdeadbeef.json'),
            'and a stale setup job cannot be reattached to across a reinstall'
        );

        lh_rmtree($root);
    },

    'a reset that cannot write the configuration changes nothing else' => static function (): void {
        [$root, $cfg] = lh_re_scaffold();

        @chmod($root . '/config', 0500);
        @chmod($root . '/config/loghound.php', 0400);

        if (is_writable($root . '/config/loghound.php')) {
            @chmod($root . '/config', 0750);
            lh_skip('cannot make the config unwritable here (running as root?)');
        }

        $result = Reset::perform($cfg);

        @chmod($root . '/config', 0750);
        @chmod($root . '/config/loghound.php', 0640);

        lh_false($result['ok'], 'it failed');
        lh_true(
            is_file($root . '/var/state.db'),
            'and the runtime files are untouched: a reset that could not write the configuration '
            . 'must not leave a WORKING installation with its read positions thrown away'
        );

        lh_rmtree($root);
    },

    'the grant is one-time, short-lived, and belongs to the session that pressed the button'
        => static function (): void {
            $_SESSION = [];

            lh_false(Token::spendGrant(), 'a session that pressed nothing holds nothing');

            Token::grant();
            lh_true(Token::spendGrant(), 'the session that pressed the button is carried through');
            lh_false(
                Token::spendGrant(),
                'and only once — an unlock that could be re-spent is an unlock that outlives the act '
                . 'that earned it'
            );

            Token::grant();
            Token::revokeGrant();
            lh_false(Token::spendGrant(), 'a revoked grant is gone');

            $_SESSION['lh_setup_grant'] = time() - 7200;
            lh_false(
                Token::spendGrant(),
                'and an old one has expired: two hours is well past the half-hour window'
            );
            lh_no_key($_SESSION, 'lh_setup_grant');

            $_SESSION = [];
        },

    'the grant does not weaken the token for anybody who did not press the button'
        => static function (): void {
            $src = (string) file_get_contents(dirname(__DIR__) . '/src/Setup/Installer.php');

            lh_contains($src, 'Token::spendGrant()', 'the installer consults the grant');
            lh_true(
                strpos($src, "\$_SESSION['lh_setup_unlocked'] ?? 0") < strpos($src, 'Token::spendGrant()'),
                'after the ordinary unlock, as an additional way in rather than a replacement'
            );

            $token = (string) file_get_contents(dirname(__DIR__) . '/src/Setup/Token.php');
            lh_false(
                (bool) preg_match('/\$_(GET|POST|COOKIE|SERVER)\[[^\]]*grant/i', $token),
                'and nothing carries it but the session: a grant readable from a cookie, a header '
                . 'or a URL would be a grant a stranger could present'
            );

            lh_contains(
                $token,
                'GRANT_TTL',
                'it expires, so a browser left open on a shared machine does not stay a way in'
            );
        },

    'the consequences are specific, and none of them claims data is deleted'
        => static function (): void {
            $rows = Reset::consequences();
            lh_true(count($rows) >= 8, 'every moving part is named: ' . count($rows));

            $all = '';
            foreach ($rows as $row) {
                lh_true($row['what'] !== '' && $row['happens'] !== '', 'each row says what and what happens');
                $all .= ' ' . $row['what'] . ' ' . $row['happens'];
            }

            foreach ([
                'Untouched',
                'install/uninstall.sh',
                'access log',
                'signed out',
                'var/state.db',
                'read position',
                'beacon',
            ] as $needle) {
                lh_contains($all, $needle, 'the list covers ' . $needle);
            }

            lh_false(
                stripos($all, 'deletes your indexes') !== false,
                'and nothing in it claims the indexes are deleted, because they are not'
            );
        },

    'the renamed age limit keeps its value across an upgrade, under either name'
        => static function (): void {
            // privacy.retention_days became maintenance.delete_hits_after_days: "retention"
            // was being used as the name of the DELETION rule, and 0 — which reads at a glance
            // as "keep nothing" — in fact means there is no age limit at all. An installation
            // that upgrades must not silently lose the number while the name changes under it.
            $root = lh_tmpdir('lh-rename');
            @mkdir($root . '/config', 0750, true);
            $path = $root . '/config/loghound.php';

            file_put_contents($path, "<?php\nreturn ['privacy' => ['retention_days' => 45]];\n");
            $old = Config::load($path);
            lh_same(45, (int) $old->get('maintenance.delete_hits_after_days'), 'the old name is adopted');
            lh_same(45, (int) $old->get('privacy.retention_days'), 'and still answers');

            file_put_contents($path, "<?php\nreturn ['maintenance' => ['delete_hits_after_days' => 7]];\n");
            $new = Config::load($path);
            lh_same(7, (int) $new->get('privacy.retention_days'), 'the new name reaches the old readers');

            // Zero is a real setting, not an absent one, and must survive the migration as zero.
            file_put_contents($path, "<?php\nreturn ['privacy' => ['retention_days' => 0]];\n");
            $zero = Config::load($path);
            lh_same(
                0,
                (int) $zero->get('maintenance.delete_hits_after_days'),
                'zero means "no age limit" and is carried across as zero, not as the default 90'
            );

            // Whichever name is written, the file carries one answer under both.
            $cfg = Config::load($path);
            $cfg->set('privacy.retention_days', 30);
            lh_same(30, (int) $cfg->get('maintenance.delete_hits_after_days'), 'writing the old name mirrors');
            $cfg->set('maintenance.delete_hits_after_days', 14);
            lh_same(14, (int) $cfg->get('privacy.retention_days'), 'and writing the new name mirrors back');
            $cfg->save();

            $reread = Config::load($path);
            lh_same(14, (int) $reread->get('privacy.retention_days'), 'a saved file cannot disagree with itself');
            lh_same(14, (int) $reread->get('maintenance.delete_hits_after_days'));

            lh_rmtree($root);
        },

    'nothing in the product calls a deletion rule "retention is disabled"'
        => static function (): void {
            $root = dirname(__DIR__);
            $files = array_merge(
                (array) glob($root . '/src/*.php'),
                (array) glob($root . '/src/Panel/*.php'),
                (array) glob($root . '/src/Setup/*.php'),
                [$root . '/bin/loghound-retention', $root . '/config/loghound.example.php']
            );

            foreach ($files as $file) {
                $body = (string) @file_get_contents((string) $file);
                if ($body === '') {
                    continue;
                }
                // The docblock in Settings QUOTES the old sentence to explain the bug, which is
                // the one place the phrase is allowed to survive.
                $body = str_replace('printed "Retention is disabled, so nothing is ever deleted."', '', $body);

                lh_false(
                    (bool) preg_match('/retention is (disabled|off)/i', $body),
                    basename((string) $file) . ' still says "retention is disabled", which reads to '
                    . 'anyone who has not seen the code as "we do not keep your data" — the opposite '
                    . 'of what it means'
                );
            }
        },

    'both front ends describe the same reset, from the same list' => static function (): void {
        $wizard = (string) file_get_contents(dirname(__DIR__) . '/bin/loghound-setup');

        lh_contains($wizard, 'Reset::perform(', 'the shell path does the same work');
        lh_contains($wizard, 'Reset::consequences()', 'and prints the same list, rather than its own');
        lh_contains($wizard, "'LOGHOUND_CONFIRM_RESET'", 'with a confirmation that can be pre-answered');
        lh_contains(
            $wizard,
            "confirm('Reset this installation now?', false",
            'defaulting to NO, so an unattended run cannot wipe an installation by tripping over the flag'
        );
    },
];
