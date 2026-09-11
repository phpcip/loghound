<?php
/**
 * Loghound — tests for the uninstaller.
 *
 * The uninstaller is the only part of this project whose bugs are UNRECOVERABLE. A wrong
 * `rm -rf` eats a directory that is not ours; a wrong `delete_index` destroys a customer's
 * production search index and burns its name permanently, because Opensolr index names are
 * unique across the whole platform and are never released. So these tests are weighted
 * almost entirely towards refusals — the paths where the right answer is "do nothing" — and
 * barely at all towards the happy path.
 *
 * NOTHING HERE RUNS A REAL UNINSTALL. The end-to-end tests drive `install/uninstall.sh`
 * with `--dry-run` against a throwaway tree this file builds in a temp directory, and then
 * assert that every file is still there. No network: the configurations used point the
 * Opensolr control plane at a closed loopback port, which is also the case the uninstaller
 * has to get right — an unreachable control plane must delete nothing.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';
require_once __DIR__ . '/../install/opensolr-teardown.php';

use Loghound\Config;
use Loghound\Install\OpensolrTeardown;

/** The uninstaller wrapper, the installer that does the work, and the index helper. */
function lh_un_paths(): array
{
    $root = dirname(__DIR__);
    return [
        'root'      => $root,
        'uninstall' => $root . '/install/uninstall.sh',
        'install'   => $root . '/install/install.sh',
        'helper'    => $root . '/install/opensolr-teardown.php',
    ];
}

/** install.sh as text. */
function lh_un_installer_source(): string
{
    return (string) file_get_contents(lh_un_paths()['install']);
}

/**
 * Extract one shell function from install.sh, with the comment block above it.
 *
 * The comment block is included deliberately: several of the properties these tests pin
 * are promises made in a docblock — what shredding does not achieve, why a step is where
 * it is — and a promise that quietly disappears is exactly the drift worth catching.
 */
function lh_un_function(string $name): string
{
    $src = lh_un_installer_source();
    $start = strpos($src, "\n" . $name . "() {");
    if ($start === false) {
        throw new \RuntimeException('install.sh has no function ' . $name . '()');
    }
    $end = strpos($src, "\n}\n", $start);
    if ($end === false) {
        throw new \RuntimeException('could not find the end of ' . $name . '()');
    }

    $lines = explode("\n", substr($src, 0, $start));
    $comment = [];
    for ($i = count($lines) - 1; $i >= 0; $i--) {
        if (!str_starts_with(ltrim($lines[$i]), '#')) {
            break;
        }
        array_unshift($comment, $lines[$i]);
    }

    return implode("\n", $comment) . substr($src, $start, $end - $start);
}

/**
 * Write a throwaway config file and return a Config pointed at it.
 *
 * @param array<string,mixed> $overrides Merged over a complete, internally consistent
 *                                       managed-mode configuration.
 */
function lh_un_config(array $overrides = []): Config
{
    static $dir = null;
    if ($dir === null) {
        $dir = lh_tmpdir('lhun_cfg');
    }

    $cfg = Config::load($dir . '/c_' . bin2hex(random_bytes(6)) . '.php');
    $cfg->set('solr.mode', 'opensolr');
    $cfg->set('solr.install_id', '9f3c17ab');
    $cfg->set('solr.hits_core', 'loghound_9f3c17ab_hits');
    $cfg->set('solr.sessions_core', 'loghound_9f3c17ab_sessions');
    $cfg->set('opensolr.email', 'operator@example.com');
    $cfg->set('opensolr.api_key', 'not-a-real-key');
    $cfg->set('opensolr.api_base', 'http://127.0.0.1:1/api');

    foreach ($overrides as $key => $value) {
        $cfg->set($key, $value);
    }
    return $cfg;
}

/**
 * Build a throwaway install tree carrying one of every secret-bearing file.
 *
 * Built by this test, owned by this test, removed by this test. The uninstaller is only
 * ever pointed at it with --dry-run.
 *
 * @return array{0:string,1:string[]} [prefix, every file created]
 */
function lh_un_tree(): array
{
    $prefix = lh_tmpdir('lhun_tree');
    foreach (['config', 'var', 'var/setup', 'var/sessions', 'bin', 'src', 'install'] as $dir) {
        mkdir($prefix . '/' . $dir, 0750, true);
    }

    $files = [
        'config/loghound.php' => "<?php\nreturn "
            . var_export([
                'solr' => [
                    'mode'          => 'opensolr',
                    'install_id'    => '9f3c17ab',
                    'hits_core'     => 'loghound_9f3c17ab_hits',
                    'sessions_core' => 'loghound_9f3c17ab_sessions',
                    'http_pass'     => 'solr-http-password',
                ],
                'opensolr' => [
                    'api_base' => 'http://127.0.0.1:1/api',
                    'email'    => 'operator@example.com',
                    'api_key'  => 'not-a-real-key',
                ],
                'beacon'  => ['secret' => str_repeat('b', 64)],
                'privacy' => ['ip_salt' => str_repeat('s', 32)],
                'auth'    => ['password_hash' => '$2y$10$notarealhash'],
            ], true) . ";\n",
        'config/.loghound.aabbccddeeff.tmp' => '<?php return [];',
        'config/tls-panel.example.com.key'  => "-----BEGIN PRIVATE KEY-----\n",
        'var/install-token'                 => "sometoken\n",
        'var/install-attempts.json'         => '{"ips":{}}',
        'var/login-attempts.json'           => '{"ips":{}}',
        'var/state.db'                      => 'SQLite format 3',
        'var/panel-jobs.db'                 => 'SQLite format 3',
        'var/quota.json'                    => '{}',
        'var/detect.json'                   => '{}',
        'var/badlines.log'                  => "malformed line\n",
        'var/install-state.txt'             => "prefix x\n",
        'var/setup/abc123.json'             => '{"kind":"provision"}',
        'var/sessions/sess_deadbeefcafe'    => 'operator|s:2:"ok";',
        'bin/loghound-tail'                 => "#!/bin/sh\n",
        'src/autoload.php'                  => "<?php\n",
        'install/install.sh'                => "#!/bin/sh\n",
    ];

    $written = [];
    foreach ($files as $relative => $body) {
        file_put_contents($prefix . '/' . $relative, $body);
        $written[] = $relative;
    }

    return [$prefix, $written];
}

/**
 * Run the uninstaller wrapper against a prefix, always with --dry-run.
 *
 * --yes answers every reversible question so the whole teardown is walked; the index
 * deletion deliberately does not accept --yes, which one of the tests below pins.
 *
 * @param array<string,string> $env
 * @return array{out:string,code:int}
 */
function lh_un_dry_run(string $prefix, array $env = []): array
{
    $paths = lh_un_paths();

    // array_merge, not '+': the union operator keeps the LEFT operand for a duplicate
    // key, which would silently ignore a caller overriding PATH.
    $environment = array_merge([
        'PATH'            => getenv('PATH') ?: '/usr/bin:/bin',
        'HOME'            => getenv('HOME') ?: '/tmp',
        'NO_COLOR'        => '1',
        'LOGHOUND_PREFIX' => $prefix,
    ], $env);

    $cmd = escapeshellarg($paths['uninstall']) . ' --dry-run --non-interactive --yes 2>&1';

    $proc = proc_open(
        $cmd,
        [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes,
        $paths['root'],
        $environment
    );
    if (!is_resource($proc)) {
        throw new \RuntimeException('could not start the uninstaller');
    }

    $out = (string) stream_get_contents($pipes[1]) . (string) stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);

    return ['out' => $out, 'code' => proc_close($proc)];
}

/** Run the index helper as a subprocess and return its output and exit code. */
function lh_un_helper(Config $cfg, string $action): array
{
    $cfg->save();
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(lh_un_paths()['helper'])
        . ' --config=' . escapeshellarg($cfg->path()) . ' --' . escapeshellarg($action) . ' 2>&1';

    $out  = [];
    $code = 0;
    exec($cmd, $out, $code);
    return ['out' => implode("\n", $out), 'code' => $code];
}

return [

    // ---------------------------------------------------------------------------------
    // Establishing ownership of the two indexes
    // ---------------------------------------------------------------------------------

    'the plan derives both names from install_id and accepts a consistent config'
        => static function (): void {
            $plan = OpensolrTeardown::plan(lh_un_config());

            lh_same(OpensolrTeardown::OK, $plan['status'], 'status');
            lh_same(
                ['loghound_9f3c17ab_hits', 'loghound_9f3c17ab_sessions'],
                $plan['names'],
                'planned names'
            );
        },

    'a core name repointed at somebody else\'s index refuses, it does not delete'
        => static function (): void {
            // The single most dangerous input there is: a config edited to name a real
            // customer index. install_id still derives OUR pair, so a naive implementation
            // would happily delete the derived names while the operator believes the tool
            // is acting on what the file says.
            $plan = OpensolrTeardown::plan(lh_un_config(['solr.hits_core' => 'acme_prod_catalogue']));

            lh_same(OpensolrTeardown::REFUSE, $plan['status'], 'status');
            lh_same([], $plan['names'], 'names');
            lh_contains($plan['reason'], 'did not provision it', 'reason');
        },

    'a missing or malformed install_id refuses' => static function (): void {
        foreach (['', 'nope', 'ABCDEF12', '9f3c17a', '9f3c17abc', '../../etc'] as $bad) {
            $plan = OpensolrTeardown::plan(lh_un_config(['solr.install_id' => $bad]));
            lh_same(OpensolrTeardown::REFUSE, $plan['status'], 'status for install_id ' . lh_show($bad));
            lh_same([], $plan['names'], 'names for install_id ' . lh_show($bad));
        }
    },

    'a custom Solr install is reported as such and yields no names' => static function (): void {
        $plan = OpensolrTeardown::plan(lh_un_config(['solr.mode' => 'custom']));

        lh_same(OpensolrTeardown::CUSTOM, $plan['status'], 'status');
        lh_same([], $plan['names'], 'names');
    },

    'an empty account listing is a failed check, not an empty account' => static function (): void {
        // A restricted API key, a control-plane hiccup and a genuinely empty account are
        // indistinguishable from here. Two of those three must not lead to a delete.
        $e = lh_throws(static function (): void {
            OpensolrTeardown::confirmOwned(['loghound_9f3c17ab_hits'], []);
        }, 'confirmOwned with an empty listing');

        lh_contains($e->getMessage(), 'unproven', 'the reason');
    },

    'only the planned names are ever returned, never anything else in the account'
        => static function (): void {
            $account = [
                'acme_prod_catalogue',
                'loghound_9f3c17ab_hits',
                'loghound_deadbeef_hits',
                'loghound_9f3c17ab_sessions_old',
                'customer_loghound_backup',
            ];

            $owned = OpensolrTeardown::confirmOwned(
                ['loghound_9f3c17ab_hits', 'loghound_9f3c17ab_sessions'],
                $account
            );

            lh_same(['loghound_9f3c17ab_hits'], $owned['present'], 'present');
            lh_same(['loghound_9f3c17ab_sessions'], $owned['absent'], 'absent');

            // Another installation's index, and a name that merely CONTAINS ours, are in
            // the account and must not appear anywhere in the result.
            foreach ($owned['present'] as $name) {
                if ($name === 'loghound_deadbeef_hits' || $name === 'loghound_9f3c17ab_sessions_old') {
                    lh_fail('confirmOwned returned an index this installation did not create: ' . $name);
                }
            }
        },

    'a name that is not a Loghound index name is refused even if the account holds it'
        => static function (): void {
            lh_throws(static function (): void {
                OpensolrTeardown::confirmOwned(['acme_prod_catalogue'], ['acme_prod_catalogue']);
            }, 'confirmOwned on a foreign name');
        },

    'the name pattern accepts the real shape and rejects every near miss'
        => static function (): void {
            foreach (['loghound_9f3c17ab_hits', 'loghound_00000000_sessions'] as $good) {
                lh_true(preg_match(OpensolrTeardown::NAME_RE, $good), 'NAME_RE should accept ' . $good);
            }

            $bad = [
                'loghound_hits',                       // the hardcoded name a naive version would use
                'loghound_9f3c17ab_hits_backup',       // suffix
                'x_loghound_9f3c17ab_hits',            // prefix
                'loghound_9F3C17AB_hits',              // uppercase hex
                'loghound_9f3c17ab_sessions2',
                'loghound_9f3c17a_hits',               // seven hex characters
                'loghound__hits',
                'loghound_9f3c17ab_other',
                'acme_prod_catalogue',
                '',
            ];
            foreach ($bad as $name) {
                lh_false(
                    (bool) preg_match(OpensolrTeardown::NAME_RE, $name),
                    'NAME_RE should reject ' . lh_show($name)
                );
            }
        },

    // ---------------------------------------------------------------------------------
    // The helper as the uninstaller actually invokes it
    // ---------------------------------------------------------------------------------

    'an unreachable control plane deletes nothing and says so' => static function (): void {
        $res = lh_un_helper(lh_un_config(), 'delete');

        lh_same(3, $res['code'], 'exit code');
        lh_contains($res['out'], 'STATUS unverified', 'status');
        if (str_contains($res['out'], 'DELETED')) {
            lh_fail('a deletion was reported against an unreachable control plane: ' . $res['out']);
        }
    },

    'missing credentials delete nothing but still name the two indexes' => static function (): void {
        $res = lh_un_helper(lh_un_config(['opensolr.api_key' => '']), 'delete');

        lh_same(3, $res['code'], 'exit code');
        lh_contains($res['out'], 'STATUS unverified', 'status');
        lh_contains($res['out'], 'NAME loghound_9f3c17ab_hits', 'the hits name is still reported');
        if (str_contains($res['out'], 'DELETED')) {
            lh_fail('a deletion was reported with no API key: ' . $res['out']);
        }
    },

    'the helper takes no index name from its arguments' => static function (): void {
        $cfg = lh_un_config();
        $cfg->save();

        $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(lh_un_paths()['helper'])
            . ' --config=' . escapeshellarg($cfg->path())
            . ' --delete ' . escapeshellarg('acme_prod_catalogue') . ' 2>&1';

        $out  = [];
        $code = 0;
        exec($cmd, $out, $code);

        lh_same(2, $code, 'exit code for an unexpected argument');
        if (str_contains(implode("\n", $out), 'DELETED')) {
            lh_fail('an index name supplied on the command line was acted on');
        }
    },

    // ---------------------------------------------------------------------------------
    // uninstall.sh is a wrapper, not a second implementation
    // ---------------------------------------------------------------------------------

    'uninstall.sh exists, is executable and parses' => static function (): void {
        $path = lh_un_paths()['uninstall'];

        lh_true(is_file($path), 'install/uninstall.sh should exist');
        lh_true(is_executable($path), 'install/uninstall.sh should be executable');

        $out  = [];
        $code = 0;
        exec('bash -n ' . escapeshellarg($path) . ' 2>&1', $out, $code);
        if ($code !== 0) {
            lh_fail('uninstall.sh does not parse: ' . implode("\n", $out));
        }
    },

    'uninstall.sh delegates instead of reimplementing the teardown' => static function (): void {
        $src = (string) file_get_contents(lh_un_paths()['uninstall']);

        lh_contains($src, '--uninstall', 'it should invoke the installer in uninstall mode');
        if (!preg_match('/exec\s+(bash\s+)?"\$INSTALLER"\s+--uninstall\s+"\$@"/', $src)) {
            lh_fail('uninstall.sh does not exec install.sh --uninstall with the caller\'s arguments');
        }

        // A second implementation would need these. Finding one here means the two have
        // started to drift, which is exactly what the wrapper exists to prevent.
        foreach (['rm -rf', 'systemctl', 'userdel', 'a2dissite', 'delete_index', 'shred'] as $forbidden) {
            if (str_contains($src, $forbidden)) {
                lh_fail(
                    'uninstall.sh contains its own teardown logic (' . $forbidden . '); it must delegate '
                    . 'to install.sh so the two cannot drift'
                );
            }
        }
    },

    'uninstall.sh sets the shell safety flags' => static function (): void {
        lh_contains((string) file_get_contents(lh_un_paths()['uninstall']), 'set -euo pipefail', 'uninstall.sh');
    },

    // ---------------------------------------------------------------------------------
    // Every secret is accounted for
    // ---------------------------------------------------------------------------------

    'every secret-bearing file the code writes is in the shred list' => static function (): void {
        $body = lh_un_function('uninstall_secrets');

        // Enumerated from the code, not from memory: Config::save(), Setup\Token,
        // Security::LOGIN_LEDGER, Panel\Jobs, Setup\Job, Quota and the FPM pool between
        // them write every one of these.
        $required = [
            'config/loghound.php',              // API key, email, HMAC secret, ip_salt, http_pass, password hash
            'config/.loghound.',                // the same file mid-write, if save() was interrupted
            'config/tls-',                      // the self-signed private key install.sh generates
            'var/install-token',                // bearer credential for the web installer
            'var/install-attempts.json',        // its guess ledger
            'var/login-attempts.json',          // the panel's lockout ledger
            'var/state.db',                     // visitor data, beacon staging
            'var/panel-jobs.db',                // job context
            'var/setup/',                       // setup job state
            'var/sessions/sess_',               // a session file IS a signed-in panel session
            'var/quota.json',
            'var/detect.json',
            'var/badlines.log',
            'var/install-state.txt',
        ];

        foreach ($required as $path) {
            if (!str_contains($body, $path)) {
                lh_fail('uninstall_secrets() never touches ' . $path . ', so that secret survives an uninstall');
            }
        }
    },

    'the write-ahead log siblings of both SQLite databases are shredded too'
        => static function (): void {
            // Both stores run in WAL mode, so the most recent writes live in the -wal file
            // and removing only the .db leaves them readable.
            $body = lh_un_function('uninstall_secrets');
            foreach (['state.db-wal', 'state.db-shm', 'panel-jobs.db-wal', 'panel-jobs.db-shm'] as $sibling) {
                lh_contains($body, $sibling, 'the shred list');
            }
        },

    'the shred helper is honest about what overwriting does not achieve'
        => static function (): void {
            $body = lh_un_function('shred_file');

            foreach (['copy-on-write', 'SSD', 'ROTATE IT'] as $claim) {
                lh_contains($body, $claim, 'the shred_file docblock');
            }
        },

    // ---------------------------------------------------------------------------------
    // Never break the box on the way out
    // ---------------------------------------------------------------------------------

    'a web server is never reloaded before its configuration is validated'
        => static function (): void {
            $body = lh_un_function('uninstall_vhost');

            $apacheTest   = strpos($body, '"$APACHE_BIN" -t');
            $apacheReload = strpos($body, 'systemctl reload "$APACHE_SERVICE"');
            lh_true($apacheTest !== false, 'uninstall_vhost should run an apache configtest');
            lh_true($apacheReload !== false, 'uninstall_vhost should reload apache');
            lh_true($apacheTest < $apacheReload, 'the apache configtest must come before the reload');

            $nginxTest   = strpos($body, 'nginx -t');
            $nginxReload = strpos($body, 'systemctl reload nginx');
            lh_true($nginxTest !== false, 'uninstall_vhost should run nginx -t');
            lh_true($nginxReload !== false, 'uninstall_vhost should reload nginx');
            lh_true($nginxTest < $nginxReload, 'nginx -t must come before the reload');

            lh_contains($body, 'has NOT been reloaded', 'the failure branch should say it did not reload');
        },

    'a vhost path is never built from an empty directory variable' => static function (): void {
        // With no Apache on the box APACHE_SITES_ENABLED is empty, and an unguarded
        // "$APACHE_SITES_ENABLED/$VHOST_NAME" becomes "/zzz-loghound.conf" — a path at the
        // filesystem root that an rm would then be pointed at.
        $body = lh_un_function('uninstall_vhost');

        foreach (['APACHE_SITES_ENABLED', 'APACHE_SITES_AVAIL', 'NGINX_SITES_ENABLED', 'NGINX_SITES_AVAIL'] as $var) {
            if (!str_contains($body, '[[ -n "$' . $var . '"')) {
                lh_fail($var . ' is used to build a vhost path without first checking that it is set');
            }
        }
    },

    'the prefix is validated before anything destructive touches it' => static function (): void {
        $src = lh_un_installer_source();

        $validate = strpos($src, 'uninstall_validate_prefix() {');
        lh_true($validate !== false, 'there should be a prefix validator');

        $body = lh_un_function('remove_under_prefix');
        lh_contains($body, 'PREFIX_LOOKS_LIKE_LOGHOUND', 'remove_under_prefix should refuse an unvalidated prefix');
        lh_contains($body, "*..*)", 'remove_under_prefix should refuse a traversal');

        // The orchestrator must validate before it calls anything that deletes.
        $order = lh_un_function('do_uninstall');
        $v = strpos($order, 'uninstall_validate_prefix');
        $s = strpos($order, 'uninstall_secrets');
        $t = strpos($order, 'uninstall_tree');
        lh_true($v !== false && $s !== false && $t !== false, 'do_uninstall should call all three');
        lh_true($v < $s && $v < $t, 'validation must come before any deletion');
    },

    'system directories are refused as an install prefix' => static function (): void {
        $src = lh_un_installer_source();

        lh_contains($src, 'UNINSTALL_FORBIDDEN_PREFIXES', 'there should be a refusal list');
        foreach (['/usr', '/var', '/etc', '/home', '/var/www', '/usr/local'] as $dir) {
            if (!preg_match('~UNINSTALL_FORBIDDEN_PREFIXES=\(.*?' . preg_quote($dir, '~') . '[\s)].*?\)~s', $src)) {
                lh_fail($dir . ' is not in the refused-prefix list');
            }
        }
    },

    'the teardown runs in an order that does not destroy what a later step needs'
        => static function (): void {
            $body = lh_un_function('do_uninstall');

            $positions = [];
            foreach ([
                'uninstall_units',
                'uninstall_opensolr_indexes',
                'uninstall_vhost',
                'uninstall_fpm_pool',
                'uninstall_secrets',
                'uninstall_tree',
                'uninstall_user',
            ] as $step) {
                $at = strpos($body, "\n    " . $step);
                if ($at === false) {
                    lh_fail('do_uninstall never calls ' . $step . '()');
                }
                $positions[$step] = $at;
            }

            // The daemons stop first, or they re-create what is about to be removed and
            // hold the user open so userdel refuses.
            lh_true(
                $positions['uninstall_units'] < $positions['uninstall_secrets'],
                'the units must be stopped before the data is removed'
            );
            // The indexes are deleted while the credentials still exist.
            lh_true(
                $positions['uninstall_opensolr_indexes'] < $positions['uninstall_secrets'],
                'the indexes must be deleted before the API key is purged'
            );
            lh_true(
                $positions['uninstall_opensolr_indexes'] < $positions['uninstall_tree'],
                'the indexes must be deleted before the config is deleted with the tree'
            );
            // The web server stops routing before the socket goes.
            lh_true(
                $positions['uninstall_vhost'] < $positions['uninstall_fpm_pool'],
                'the vhost must go before the FPM pool it proxies to'
            );
            // The user goes last, when nothing it owns is left and nothing is running as it.
            lh_true(
                $positions['uninstall_user'] > $positions['uninstall_tree'],
                'the user must be removed after the files it owns'
            );
        },

    'the adm membership is dropped even when userdel fails' => static function (): void {
        $body = lh_un_function('uninstall_user');

        $drop = strpos($body, 'run gpasswd -d');
        $del  = strpos($body, 'run userdel');
        lh_true($drop !== false, 'uninstall_user should drop the log-read group membership');
        lh_true($del !== false, 'uninstall_user should call userdel');
        lh_true($drop < $del, 'the group membership must be dropped before userdel is attempted');
        lh_contains($body, 'no longer read /var/log', 'the failure branch should say the log access is gone');
    },

    // ---------------------------------------------------------------------------------
    // The index question is not something --yes can answer
    // ---------------------------------------------------------------------------------

    'deleting the indexes needs more than --yes' => static function (): void {
        $body = lh_un_function('confirm_delete_indexes');

        if (str_contains($body, 'ASSUME_YES')) {
            lh_fail('confirm_delete_indexes consults --yes; index deletion must be its own decision');
        }
        lh_contains($body, 'LOGHOUND_UNINSTALL_DELETE_INDEXES', 'the dedicated environment variable');
        lh_contains($body, '== "DELETE"', 'the typed confirmation word');

        // The non-interactive default is NO.
        if (!preg_match('/NONINTERACTIVE.*\n.*keeping both indexes.*\n\s*return 1/', $body)) {
            lh_fail('the non-interactive default for index deletion is not a refusal');
        }
    },

    /*
     * The one that matters most: --dry-run must not reach the delete call.
     *
     * This is a REAL bug that existed during development — the helper was invoked with
     * --delete and the DRY_RUN check came after it, so a dry run against a reachable
     * control plane would have destroyed both indexes while printing "nothing will be
     * changed". A structural assertion about where the guard sits is not enough; this
     * puts a recording stub on PATH and proves --delete is never invoked at all.
     */
    'a dry run never invokes the deleting half of the index helper' => static function (): void {
        [$prefix, ] = lh_un_tree();
        $stub   = lh_tmpdir('lhun_stub');
        $marker = $stub . '/delete-was-called';

        try {
            // Answers the installer's PHP version probe, reports a fully verified pair so
            // the dry run walks all the way to the confirmation, and records the fact if
            // it is ever asked to delete.
            file_put_contents($stub . '/php', <<<STUB
#!/usr/bin/env bash
for a in "\$@"; do
  case "\$a" in
    -r) echo "8.3.0"; exit 0 ;;
    --plan)
      echo "NAME loghound_9f3c17ab_hits"
      echo "NAME loghound_9f3c17ab_sessions"
      echo "STATUS ok"
      echo "REASON stub"
      exit 0 ;;
    --delete) touch "{$marker}"; exit 0 ;;
  esac
done
exit 0
STUB);
            chmod($stub . '/php', 0755);

            $out = lh_un_dry_run($prefix, [
                'PATH'                              => $stub . ':' . (getenv('PATH') ?: '/usr/bin:/bin'),
                'LOGHOUND_UNINSTALL_DELETE_INDEXES' => 'yes',
            ])['out'];

            // It must have walked all the way to the decision...
            lh_contains($out, 'DESTROYS DATA', 'the dry run should still show the warning');
            lh_contains($out, 'would delete loghound_9f3c17ab_hits', 'it should say what it would do');

            // ...and then not done it.
            if (file_exists($marker)) {
                lh_fail('--dry-run invoked the index helper with --delete; a dry run would have destroyed both indexes');
            }
        } finally {
            lh_rmtree($stub);
            lh_rmtree($prefix);
        }
    },

    'the dry-run guard sits before the delete call, not after it' => static function (): void {
        $body = lh_un_function('uninstall_opensolr_indexes');

        $delete = strpos($body, '--delete 2>&1');
        lh_true($delete !== false, 'uninstall_opensolr_indexes should invoke the helper with --delete');

        $guard = strpos($body, 'would delete ');
        lh_true($guard !== false, 'there should be a --dry-run branch that only describes the deletion');
        lh_true($guard < $delete, 'the --dry-run guard must come before the --delete invocation');
    },

    'the warning says the name can never be reused' => static function (): void {
        $body = lh_un_function('uninstall_opensolr_indexes');

        lh_contains($body, 'WHOLE PLATFORM', 'the warning should say the namespace is global');
        lh_contains($body, 'never released', 'the warning should say the name is not reusable');
        lh_contains($body, 'no undo', 'the warning should say the data is gone');
    },

    // ---------------------------------------------------------------------------------
    // End to end, --dry-run, against a tree this test built
    // ---------------------------------------------------------------------------------

    'a dry run walks the whole teardown and removes nothing' => static function (): void {
        [$prefix, $files] = lh_un_tree();

        try {
            $res = lh_un_dry_run($prefix);
            lh_same(0, $res['code'], 'exit code (output: ' . $res['out'] . ')');

            foreach ($files as $relative) {
                if (!file_exists($prefix . '/' . $relative)) {
                    lh_fail('--dry-run removed ' . $relative);
                }
            }
            lh_true(is_dir($prefix . '/var/sessions'), '--dry-run should not remove var/sessions');
            lh_true(is_dir($prefix . '/var/setup'), '--dry-run should not remove var/setup');
        } finally {
            lh_rmtree($prefix);
        }
    },

    'a dry run names every secret it would destroy' => static function (): void {
        [$prefix, ] = lh_un_tree();

        try {
            $out = lh_un_dry_run($prefix)['out'];

            foreach ([
                'config/loghound.php',
                'config/.loghound.aabbccddeeff.tmp',
                'config/tls-panel.example.com.key',
                'var/install-token',
                'var/state.db',
                'var/panel-jobs.db',
                'var/setup/abc123.json',
                'var/sessions/sess_deadbeefcafe',
            ] as $relative) {
                lh_contains($out, $prefix . '/' . $relative, 'the dry-run transcript');
            }
        } finally {
            lh_rmtree($prefix);
        }
    },

    'a dry run against an unreachable control plane deletes no index' => static function (): void {
        [$prefix, ] = lh_un_tree();

        try {
            $out = lh_un_dry_run($prefix, ['LOGHOUND_UNINSTALL_DELETE_INDEXES' => 'yes'])['out'];

            lh_contains($out, 'could not establish ownership', 'the transcript');
            lh_contains($out, 'loghound_9f3c17ab_hits', 'the index names should still be printed');
            if (str_contains($out, 'deleted index')) {
                lh_fail('an index deletion was reported against an unreachable control plane');
            }
        } finally {
            lh_rmtree($prefix);
        }
    },

    'the closing report names what only the operator can remove' => static function (): void {
        [$prefix, ] = lh_un_tree();

        try {
            $out = lh_un_dry_run($prefix)['out'];

            lh_contains($out, 'What was NOT removed', 'the report heading');
            lh_contains($out, 'BEACON TAG', 'the beacon snippet the operator must remove');
            lh_contains($out, 'ROTATE THE OPENSOLR API KEY', 'the rotation advice');
            lh_contains($out, 'added by hand', 'the note about the operator\'s own additions');
            lh_contains($out, 'source log files were never written to', 'the log-file guarantee');
        } finally {
            lh_rmtree($prefix);
        }
    },

    // ---------------------------------------------------------------------------------
    // Half-finished installs, and things that are not installs at all
    // ---------------------------------------------------------------------------------

    'a half-finished install uninstalls cleanly instead of aborting' => static function (): void {
        // No config, no state, no user, nothing but an empty tree — which is what a box
        // looks like when install.sh died in preflight.
        $prefix = lh_tmpdir('lhun_half');
        mkdir($prefix . '/var', 0750, true);
        file_put_contents($prefix . '/var/install-token', "token\n");

        try {
            $res = lh_un_dry_run($prefix);

            lh_same(0, $res['code'], 'exit code (output: ' . $res['out'] . ')');
            lh_contains($res['out'], 'Uninstalled', 'it should reach the end');
            lh_contains($res['out'], 'no readable configuration', 'it should say the config is missing');
            if (str_contains($res['out'], 'deleted index')) {
                lh_fail('an index was deleted with no configuration to establish ownership from');
            }
        } finally {
            lh_rmtree($prefix);
        }
    },

    'an empty prefix that was never installed to is handled' => static function (): void {
        $prefix = lh_tmpdir('lhun_empty');

        try {
            $res = lh_un_dry_run($prefix);

            lh_same(0, $res['code'], 'exit code (output: ' . $res['out'] . ')');
            lh_contains($res['out'], 'nothing that identifies it as a Loghound install', 'the refusal');
            lh_true(is_dir($prefix), 'the directory should still be there');
        } finally {
            lh_rmtree($prefix);
        }
    },

    'a prefix that is not a Loghound install is refused, not deleted' => static function (): void {
        $prefix = lh_tmpdir('lhun_notours');
        mkdir($prefix . '/wp-content', 0750, true);
        file_put_contents($prefix . '/index.php', "<?php // somebody else's site\n");

        try {
            $res = lh_un_dry_run($prefix);

            lh_same(0, $res['code'], 'exit code (output: ' . $res['out'] . ')');
            lh_contains($res['out'], 'Refusing to delete it', 'the refusal');
            lh_true(is_file($prefix . '/index.php'), 'the foreign tree must be untouched');

            if (preg_match('/DRY-RUN rm -rf ' . preg_quote($prefix, '/') . '\s*$/m', $res['out'])) {
                lh_fail('the uninstaller planned to rm -rf a tree it did not recognise');
            }
        } finally {
            lh_rmtree($prefix);
        }
    },

    'a system directory is refused as a prefix even under --yes' => static function (): void {
        $res = lh_un_dry_run('/usr');

        lh_same(0, $res['code'], 'exit code (output: ' . $res['out'] . ')');
        lh_contains($res['out'], 'refusing to treat the system directory', 'the refusal');
        if (str_contains($res['out'], 'rm -rf /usr')) {
            lh_fail('the uninstaller planned to rm -rf /usr');
        }
    },

    // ---------------------------------------------------------------------------------
    // Documentation
    // ---------------------------------------------------------------------------------

    'the documentation tells people the uninstaller exists and what it leaves'
        => static function (): void {
            $root = lh_un_paths()['root'];

            $install = (string) file_get_contents($root . '/docs/INSTALL.md');
            foreach ([
                'install/uninstall.sh',
                '--dry-run',
                'LOGHOUND_UNINSTALL_DELETE_INDEXES',
                'unique across the entire platform',
            ] as $needle) {
                lh_contains($install, $needle, 'docs/INSTALL.md');
            }

            lh_contains((string) file_get_contents($root . '/README.md'), 'install/uninstall.sh', 'README.md');
        },
];
