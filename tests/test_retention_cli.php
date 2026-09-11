<?php
/**
 * Loghound — bin/loghound-retention, run as the process it really is.
 *
 * The three passes it now makes are independent by design, and this exercises the two that
 * can be exercised without a Solr: that time-based retention being disabled does NOT stop
 * the rest of the job, and that the local SQLite state is actually purged. That second one
 * is the reason this file exists — `State::cachePurgeExpired()`, `purgeClosedSessions()`,
 * `purgeBeacons()` and `purgeRateLimits()` were correct, complete, and called from nowhere
 * in the entire project, so var/state.db grew without a bound of its own. Unbounded local
 * state is the same class of problem as an unbounded index; it just fills a different disk.
 *
 * No Solr is reachable here and none is wanted: `quota.enabled = false` switches off the
 * size-based pass, and `privacy.retention_days = 0` switches off the time-based one, so the
 * run touches nothing but SQLite. That is the configuration an operator on their own Solr
 * with retention disabled actually has, and it must still tidy up after itself.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

use Loghound\Config;
use Loghound\State;

/** The repository root, so the script under test is the one in this checkout. */
function lh_ret_root(): string
{
    return dirname(__DIR__);
}

/**
 * Write a configuration that Config::validate() accepts, in a throwaway tree.
 *
 * A base URL that is never contacted, because both deleting passes are switched off. The
 * Opensolr credentials and the panel account are filled in because Config::validate() requires
 * them even for a CLI-only run, and bin/loghound-retention aborts on any validation error.
 * None of them is ever used: nothing here opens a socket.
 *
 * @param array<string,mixed> $over Dotted keys to override.
 */
function lh_ret_config(string $dir, array $over = []): string
{
    @mkdir($dir . '/config', 0700, true);
    @mkdir($dir . '/var', 0700, true);

    $path = $dir . '/config/loghound.php';
    $cfg = Config::load($path);
    $cfg->set('opensolr.email', 'operator@example.com');
    $cfg->set('opensolr.api_key', 'not-a-real-key');
    $cfg->set('solr.base_url', 'http://127.0.0.1:9/solr');
    $cfg->set('solr.hits_core', 'lh_test_hits');
    $cfg->set('solr.sessions_core', 'lh_test_sessions');
    $cfg->set('beacon.enabled', false);
    $cfg->set('privacy.ip_mode', 'truncate');
    $cfg->set('privacy.retention_days', 0);
    $cfg->set('quota.enabled', false);
    $cfg->set('auth.mode', 'basic');
    $cfg->set('auth.user', 'operator');
    $cfg->set('auth.password_hash', password_hash('a-long-enough-password', PASSWORD_DEFAULT));
    foreach ($over as $key => $value) {
        $cfg->set($key, $value);
    }
    $cfg->save();

    return $path;
}

/**
 * Run bin/loghound-retention against a config and return [exit code, output].
 *
 * @param array<int,string> $flags
 * @return array{0:int,1:string}
 */
function lh_ret_run(string $configPath, array $flags = []): array
{
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(lh_ret_root() . '/bin/loghound-retention');
    foreach ($flags as $flag) {
        $cmd .= ' ' . escapeshellarg($flag);
    }
    $cmd .= ' 2>&1';

    $proc = proc_open(
        $cmd,
        [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes,
        dirname($configPath, 2),
        ['LOGHOUND_CONFIG' => $configPath, 'PATH' => (string) getenv('PATH')]
    );
    if (!is_resource($proc)) {
        lh_skip('cannot start a PHP subprocess here');
    }
    $out = (string) stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    fclose($pipes[2]);

    return [proc_close($proc), $out];
}

/**
 * Build a state database with rows that every purge should remove.
 *
 * Written straight through State::db() because the public API refuses to create an entry
 * that is already expired — which is correct for production and useless for a test that
 * needs one.
 */
function lh_ret_seed_state(string $dir): void
{
    $state = new State($dir . '/var/state.db');
    $db = $state->db();

    // Two days back, not one: the purges use a strict "older than" against a cutoff of
    // exactly one day, so a row seeded at the cutoff itself would survive and the test
    // would be reporting a boundary condition rather than the wiring it means to check.
    $past = time() - 172800;

    $db->exec("INSERT INTO cache_geo (k, v, negative, expires_at) VALUES ('1.2.3.4', '{}', 0, $past)");
    $db->exec("INSERT INTO cache_asn (k, v, negative, expires_at) VALUES ('1.2.3.0/24', '{}', 0, $past)");
    $db->exec(
        "INSERT INTO sessions_open (session_id, client_key, first_ts, last_ts, hits, data, closed_at)
         VALUES ('s1', 'k1', 0, 0, 1, '{}', $past)"
    );
    $db->exec(
        "INSERT INTO beacon_staging (session_id, client_key, received_at, payload, merged)
         VALUES ('s1', 'k1', $past, '{}', 1)"
    );
    $db->exec("INSERT INTO ratelimit (k, tokens, updated_at) VALUES ('ip:1.2.3.4', 1.0, $past)");

    $state->close();
}

/** Count the rows left in one table of the state database. */
function lh_ret_rows(string $dir, string $table): int
{
    $db = new SQLite3($dir . '/var/state.db', SQLITE3_OPEN_READONLY);
    $n = (int) $db->querySingle('SELECT COUNT(*) FROM ' . $table);
    $db->close();
    return $n;
}

return [

    'retention disabled still purges the local state' => function (): void {
        $dir = lh_tmpdir('lhret');
        try {
            $path = lh_ret_config($dir);
            lh_ret_seed_state($dir);

            [$code, $out] = lh_ret_run($path);

            lh_same(0, $code, 'exit code: ' . $out);
            lh_contains(
                $out,
                'Nothing is deleted for being old',
                'it says the first pass was skipped, and says it forwards: "retention is disabled" '
                . 'reads as "we do not keep your data", which is the opposite of what it meant'
            );
            lh_false(
                str_contains($out, 'retention is disabled'),
                'and the backwards phrasing must not come back'
            );
            lh_contains($out, 'Local state:', 'and that it still tidied up');

            lh_same(0, lh_ret_rows($dir, 'cache_geo'), 'expired geo cache rows');
            lh_same(0, lh_ret_rows($dir, 'cache_asn'), 'expired ASN cache rows');
            lh_same(0, lh_ret_rows($dir, 'sessions_open'), 'long-closed sessions');
            lh_same(0, lh_ret_rows($dir, 'beacon_staging'), 'merged beacon payloads');
            lh_same(0, lh_ret_rows($dir, 'ratelimit'), 'stale rate-limit buckets');
        } finally {
            lh_rmtree($dir);
        }
    },

    'a dry run reports the purge and performs none of it' => function (): void {
        $dir = lh_tmpdir('lhret');
        try {
            $path = lh_ret_config($dir);
            lh_ret_seed_state($dir);

            [$code, $out] = lh_ret_run($path, ['--dry-run']);

            lh_same(0, $code, 'exit code: ' . $out);
            lh_contains($out, 'would purge', 'it says what it would do');
            lh_same(1, lh_ret_rows($dir, 'cache_geo'), 'nothing was deleted');
            lh_same(1, lh_ret_rows($dir, 'ratelimit'), 'nothing was deleted');
        } finally {
            lh_rmtree($dir);
        }
    },

    'the size-based pass is skipped when it is switched off' => function (): void {
        $dir = lh_tmpdir('lhret');
        try {
            $path = lh_ret_config($dir);
            [$code, $out] = lh_ret_run($path);

            lh_same(0, $code, 'exit code: ' . $out);
            lh_contains(
                $out,
                'Nothing is deleted for size either',
                'it says so rather than trying, and says what the state of the DATA is rather than '
                . 'the state of a switch'
            );
            lh_contains(
                $out,
                'quota.enabled = false',
                'while still naming the setting, so the sentence is actionable'
            );
        } finally {
            lh_rmtree($dir);
        }
    },

    'a negative retention is refused rather than interpreted' => function (): void {
        $dir = lh_tmpdir('lhret');
        try {
            $path = lh_ret_config($dir, ['privacy.retention_days' => -5]);
            [$code, $out] = lh_ret_run($path);

            lh_same(1, $code, 'exit code');
            lh_contains($out, 'must be 0', 'the message names the valid range');
        } finally {
            lh_rmtree($dir);
        }
    },

    'it refuses to run under a web SAPI' => function (): void {
        $source = (string) file_get_contents(lh_ret_root() . '/bin/loghound-retention');
        lh_contains($source, "PHP_SAPI !== 'cli'", 'the guard is still there');
        lh_contains($source, 'http_response_code(404)', 'and it answers 404 rather than running');
    },
];
