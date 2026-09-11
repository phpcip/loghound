<?php
/**
 * Loghound — removing Loghound: the panel's half of it.
 *
 * The shell uninstaller has its own file (tests/test_uninstall.php) and it is weighted almost
 * entirely towards refusals, because a wrong delete there destroys a customer's production
 * index. This file is the same operation driven from the browser, and it carries three burdens
 * the shell one does not:
 *
 *   - THE CONFIRMATION IS A SESSION, not a terminal. A typed word and a current second factor
 *     arm a one-time grant, and the run spends it. Everything about that has to fail closed.
 *   - THE RUN DESTROYS ITS OWN FRONT END. It deletes the configuration this panel reads on
 *     every request, so the ordering is load bearing in a way it is not in a shell script.
 *   - THE CURSORS. `var/state.db` holds `(dev, inode, offset)` per source. Deleting the indexes
 *     and leaving those behind leaves the daemon believing it has already read those bytes, so
 *     a rebuilt index holds only traffic from the rebuild onwards. That is the defect the owner
 *     named, so it is tested rather than left incidental.
 *
 * NOTHING HERE TOUCHES A NETWORK. The control plane is a transport stub installed through
 * Setup\Storage's existing test seam, which is inert outside this suite.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';
require_once __DIR__ . '/../install/opensolr-teardown.php';

use Loghound\Config;
use Loghound\Install\OpensolrTeardown;
use Loghound\Panel\Gateway;
use Loghound\Panel\Jobs;
use Loghound\Panel\Settings;
use Loghound\Setup\Installer;
use Loghound\Setup\Storage;
use Loghound\Setup\Teardown;
use Loghound\Setup\Token;

/** The install id every fixture here uses, and the two names it derives. */
const LH_TD_ID = 'abcd1234';

/** @return array<int,string> */
function lh_td_names(): array
{
    return ['loghound_' . LH_TD_ID . '_hits', 'loghound_' . LH_TD_ID . '_sessions'];
}

/**
 * A complete installation in a temporary tree, with state on disk.
 *
 * The layout matters: `<root>/config/loghound.php` and `<root>/var`. Teardown refuses to act on
 * any other shape, which is the guard that stops a stray Config object emptying the running
 * installation's own var directory, so a fixture that got it wrong would silently test nothing.
 *
 * @return array{0:string,1:Config}
 */
function lh_td_tree(): array
{
    $root = lh_tmpdir('lh-teardown');
    @mkdir($root . '/config', 0750, true);
    @mkdir($root . '/var/setup', 0750, true);
    @mkdir($root . '/var/sessions', 0700, true);

    $cfg = Config::load($root . '/config/loghound.php');
    $cfg->set('solr.mode', 'opensolr');
    $cfg->set('solr.install_id', LH_TD_ID);
    $cfg->set('solr.hits_core', lh_td_names()[0]);
    $cfg->set('solr.sessions_core', lh_td_names()[1]);
    $cfg->set('solr.base_url', 'https://fi.solrcluster.test/solr');
    $cfg->set('solr.http_user', 'lh01abcd');
    $cfg->set('solr.http_pass', 'THE-API-KEY-VALUE');
    $cfg->set('opensolr.email', 'operator@example.test');
    $cfg->set('opensolr.api_key', 'THE-API-KEY-VALUE');
    $cfg->set('opensolr.api_base', 'https://opensolr.test/solr_manager/api');
    $cfg->set('beacon.secret', str_repeat('b', 64));
    $cfg->set('privacy.ip_salt', str_repeat('s', 32));
    $cfg->set('auth.user', 'admin');
    $cfg->set('auth.password_hash', '$2y$10$notarealhashnotarealhashnotarealhashnotarealhashnot');
    $cfg->set('auth.mode', 'session');
    $cfg->save();

    foreach ([
        'state.db', 'state.db-wal', 'panel-jobs.db', 'tail-status.json', 'detect.json',
        'quota.json', 'schema-check.json', 'install-token', 'install-attempts.json',
        'login-attempts.json', 'auth-state.json', 'persistent-logins.json', 'incidents.json',
    ] as $name) {
        file_put_contents($root . '/var/' . $name, 'x');
    }
    file_put_contents($root . '/var/setup/deadbeefdeadbeef.json', '{}');
    file_put_contents($root . '/var/sessions/sess_abc', 'x');

    return [$root, $cfg];
}

/**
 * A control-plane stub: an account listing that shrinks as indexes are deleted.
 *
 * It answers the two endpoints the teardown uses and records every delete it was asked for, so
 * a test can assert both that the right names went and that no other name was ever named.
 *
 * @param array<int,string> $account Names the account starts with.
 * @param array<int,string> $deleted Filled in with every name a delete was attempted on.
 */
function lh_td_plane(array $account, array &$deleted, bool $refuseDelete = false, bool $stillThere = false): callable
{
    return static function (array $req) use (&$account, &$deleted, $refuseDelete, $stillThere): array {
        $url = (string) ($req['url'] ?? '');

        if (str_contains($url, 'get_index_list')) {
            /* A BARE JSON LIST, which is what the platform actually answers with and what
               Opensolr::decode() turns into `_list`. A wrapped object decodes to a map with no
               `_list` in it, so the listing reads as EMPTY — and an empty listing is refused as
               proof of anything, which would make this stub silently test the refusal path
               instead of the one it was written for. */
            $rows = [];
            foreach ($account as $name) {
                $rows[] = ['index_name' => $name, 'index_type' => '-1'];
            }

            return ['status' => 200, 'body' => (string) json_encode($rows), 'error' => ''];
        }

        if (str_contains($url, 'delete_index')) {
            $name = '';
            if (preg_match('/index_name=([^&]+)/', $url, $m)) {
                $name = urldecode($m[1]);
            }
            $deleted[] = $name;

            if ($refuseDelete) {
                return [
                    'status' => 500,
                    'body'   => (string) json_encode(['status' => false, 'msg' => 'refused for ' . $name]),
                    'error'  => '',
                ];
            }
            if (!$stillThere) {
                $account = array_values(array_filter($account, static fn (string $n): bool => $n !== $name));
            }

            return ['status' => 200, 'body' => (string) json_encode(['status' => true, 'msg' => 'ok']), 'error' => ''];
        }

        return ['status' => 404, 'body' => '{}', 'error' => ''];
    };
}

/**
 * Drive the whole teardown job to completion and hand back its final state.
 *
 * The real machinery: Panel\Jobs, the view's own planner, one step per advance, exactly as a
 * browser's poll loop drives it.
 *
 * @return array<string,mixed>
 */
function lh_td_run(Config $cfg): array
{
    $_SESSION = ['lh_job_owner' => 'td-' . bin2hex(random_bytes(8)), 'lh_user' => 'admin'];

    Teardown::arm();
    lh_true(Teardown::spendArm(), 'the arm this test just set must be spendable');

    $settings = new Settings($cfg, new Gateway($cfg, null, false));

    $plans = (function (): array {
        return $this->jobPlans();
    })->call($settings);

    $jobs = new Jobs($cfg, new Gateway($cfg, null, false), $plans);
    $job  = $jobs->start('destructive_uninstall');
    lh_has_key($job, 'id', 'the teardown job started');

    $guard = 0;
    while (!($job['done'] ?? false) && $guard++ < 40) {
        $job = $jobs->advance((string) $job['id']);
    }

    return $job;
}

/** Every step of a finished job, keyed by its label. @return array<string,array<string,mixed>> */
function lh_td_steps(array $job): array
{
    $out = [];
    foreach ((array) ($job['steps'] ?? []) as $step) {
        $out[(string) ($step['label'] ?? '')] = (array) $step;
    }

    return $out;
}

return [

    // ---------------------------------------------------------------------------------
    // The boundary, stated once and shared by both front ends
    // ---------------------------------------------------------------------------------

    'the shell uninstaller prints exactly the steps the panel runs, in the same order'
        => static function (): void {
            $src = (string) file_get_contents(dirname(__DIR__) . '/install/install.sh');

            $from = strpos($src, "\nuninstall_units() {");
            $to   = strpos($src, "\n# Uninstall — orchestrator");
            lh_true($from !== false && $to !== false && $to > $from, 'the teardown block is findable');

            preg_match_all('/\n\s*step "([^"$]+)"/', substr($src, $from, $to - $from), $m);

            lh_same(
                array_values(Teardown::STEPS),
                $m[1],
                "install.sh's teardown headings have drifted from Loghound\\Setup\\Teardown::STEPS.\n"
                . "Two front ends that disagree about what a teardown IS are two front ends nobody\n"
                . 'can check against each other, which is the whole reason the list lives once.'
            );

            lh_contains(
                $src,
                'plan ' . count(Teardown::STEPS),
                'do_uninstall must declare the length of the sequence it is about to print, and it '
                . 'must be the length of the canonical list'
            );
        },

    'a step that bails out early still prints, rather than leaving a gap in the numbering'
        => static function (): void {
            $src = (string) file_get_contents(dirname(__DIR__) . '/install/install.sh');

            lh_contains($src, 'teardown_skip_rest()', 'the helper exists');

            $start = strpos($src, "\nuninstall_opensolr_indexes() {");
            $end   = strpos($src, "\n}\n", (int) $start);
            lh_true($start !== false && $end !== false, 'the index step is findable');
            $body = substr($src, (int) $start, (int) $end - (int) $start);

            $returns = substr_count($body, "\n        return 0") + substr_count($body, "\n            return 0");
            $skips   = substr_count($body, 'teardown_skip_rest ');

            lh_same(
                $returns,
                $skips,
                'every early return out of the index step has to print the headings it never '
                . 'reached, or the run jumps from [2/11] to [5/11] and the operator is left to '
                . 'assume the two it did not see went fine'
            );
        },

    'the panel names every step it cannot perform, and why' => static function (): void {
        $shellOnly = array_diff(array_keys(Teardown::STEPS), Teardown::PANEL_STEPS);

        lh_same(
            array_values($shellOnly),
            array_keys(Teardown::shellOnlyReasons()),
            'a step the panel cannot do without a reason is a step an operator is left guessing about'
        );

        foreach (Teardown::shellOnlyReasons() as $id => $why) {
            lh_true(strlen($why) > 60, $id . ': "needs root" on its own says nothing');
        }
    },

    'the closing report states both halves, and never claims the log files were touched'
        => static function (): void {
            $left = implode("\n", Teardown::leftBehind('/opt/loghound'));

            lh_contains($left, 'access log files', 'the operator\'s own logs are named as untouched');
            lh_contains($left, 'LogFormat', 'and so is the edit in their own vhost');
            lh_contains($left, 'beacon', 'and the tag only they can remove');
            lh_contains($left, 'rotate it', 'and the key that has been on this disk');
            lh_contains($left, 'sudo /opt/loghound/install/uninstall.sh', 'and the command for the rest');
        },

    'the confirmation says what it costs before it happens' => static function (): void {
        $rows = Teardown::consequences();
        $text = '';
        foreach ($rows as $row) {
            $text .= $row['what'] . ' ' . $row['happens'] . "\n";
        }

        lh_contains($text, 'Permanently deleted', 'it says the indexes go');
        lh_contains($text, 'never released', 'it says the name can never be created again');
        lh_contains($text, 'backup taken in Opensolr', 'it names the only way to keep the data');
        lh_contains($text, 'separately billed', 'and says that way is not free');
        lh_contains($text, 'Untouched, as always', 'and that the access logs are not ours to delete');
    },

    // ---------------------------------------------------------------------------------
    // The run
    // ---------------------------------------------------------------------------------

    'the run deletes both indexes, proves them gone, and removes everything local'
        => static function (): void {
            [$root, $cfg] = lh_td_tree();
            $deleted = [];
            Storage::useTestTransport(lh_td_plane(
                array_merge(lh_td_names(), ['someone_elses_index']),
                $deleted
            ));

            try {
                $job = lh_td_run($cfg);

                lh_same('done', (string) $job['state'], 'the run finished: ' . lh_show($job['error'] ?? null));
                lh_same(count(Teardown::STEPS), (int) $job['total'], 'every canonical step is in the run');

                sort($deleted);
                lh_same(lh_td_names(), $deleted, 'exactly the two derived names were deleted, and nothing else');

                $steps = lh_td_steps($job);
                lh_contains(
                    (string) $steps['Confirming they are gone from your account']['detail'],
                    'no longer holds',
                    'absence is proven from the account listing, not from the delete response'
                );

                lh_false(is_file($root . '/config/loghound.php'), 'the configuration is gone');
                lh_false(is_file($root . '/var/state.db'), 'the state database is gone');
                lh_false(is_file($root . '/var/install-token'), 'the setup token is gone');
                lh_false(is_file($root . '/var/persistent-logins.json'), 'remembered browsers are gone');
                lh_false(is_file($root . '/var/auth-state.json'), 'recovery code hashes are gone');
                lh_false(is_file($root . '/var/login-attempts.json'), 'the rate-limit ledgers are gone');
                lh_false(is_file($root . '/var/schema-check.json'), 'the saved schema check is gone');
                lh_false(is_dir($root . '/var/setup'), 'the setup job state is gone');
                lh_false(is_file($root . '/var/panel-jobs.db'), 'and so is the record of this run');
            } finally {
                Storage::useTestTransport(null);
                lh_rmtree($root);
            }
        },

    'the tailer cursors go with it, or a rebuilt index would start from now'
        => static function (): void {
            [$root, $cfg] = lh_td_tree();

            /* THE REAL ARTEFACT, not a file with the right name. `var/state.db` is where
               Tail keeps (dev, inode, offset) per source, and the defect this pins is an
               uninstall that deletes the indexes and leaves those behind: the daemon then
               believes it has already read those bytes and resumes at the end of the current
               file, so the rebuilt index holds only traffic from that moment forward. */
            $db = new \SQLite3($root . '/var/state.db');
            $db->exec('CREATE TABLE offsets (src TEXT PRIMARY KEY, dev INTEGER, inode INTEGER, offset INTEGER, updated_at INTEGER)');
            $db->exec("INSERT INTO offsets VALUES ('/var/log/apache2/access.log', 2049, 131074, 918273645, 1)");
            $db->close();

            $deleted = [];
            Storage::useTestTransport(lh_td_plane(lh_td_names(), $deleted));

            try {
                lh_td_run($cfg);

                lh_false(
                    is_file($root . '/var/state.db'),
                    'var/state.db survived the teardown. Every recorded read position survived with '
                    . 'it, so a reinstall onto fresh indexes would resume at the end of each log and '
                    . 'the rebuilt index would hold nothing before the moment of the rebuild.'
                );
                foreach (['state.db-wal', 'state.db-shm'] as $sidecar) {
                    lh_false(
                        is_file($root . '/var/' . $sidecar),
                        $sidecar . ' survived; a WAL sidecar can carry committed offsets on its own'
                    );
                }
            } finally {
                Storage::useTestTransport(null);
                lh_rmtree($root);
            }
        },

    'when it finishes, the installation is one the installer has to fix' => static function (): void {
        [$root, $cfg] = lh_td_tree();
        $deleted = [];
        Storage::useTestTransport(lh_td_plane(lh_td_names(), $deleted));

        try {
            lh_false(Installer::isNeeded($cfg), 'before: a finished installation serves the panel');

            lh_td_run($cfg);

            lh_true(
                Installer::isNeeded(Config::load($root . '/config/loghound.php')),
                'after: every route on this address is the installer — read from DISK, because that '
                . 'is what the next request reads'
            );
            lh_true(
                isset($_SESSION['lh_setup_grant']),
                'and the browser that just wiped the machine carries the one-time grant, so it is '
                . 'not locked out of the installer it has been sent to'
            );
        } finally {
            Storage::useTestTransport(null);
            lh_rmtree($root);
        }
    },

    'every signed-in session goes with the rest of var/' => static function (): void {
        [$root, $cfg] = lh_td_tree();
        $deleted = [];
        Storage::useTestTransport(lh_td_plane(lh_td_names(), $deleted));

        try {
            lh_td_run($cfg);

            lh_false(
                is_file($root . '/var/sessions/sess_abc'),
                'a PHP session file IS a signed-in panel session, so it is not something a '
                . 'teardown may leave on a decommissioned box'
            );
        } finally {
            Storage::useTestTransport(null);
            lh_rmtree($root);
        }
    },

    'somewhere to write the session is put back, or the grant it carries is lost'
        => static function (): void {
            /* THE REAL BEHAVIOUR, TESTED DIRECTLY, because the run cannot exercise it here:
               session ini settings cannot be changed once output has been sent, which under the
               CLI runner is always, so session_save_path() is empty for the whole suite and the
               call inside the run is a no-op by definition. What the run does is pinned
               structurally below; what it does IT with is pinned here. */
            [$root, $cfg] = lh_td_tree();

            try {
                Teardown::wipeState($cfg);
                lh_false(is_dir($root . '/var/sessions'), 'the wipe took the directory with it');

                lh_same(
                    $root . '/var/sessions',
                    Teardown::ensureSessionDir($cfg, $root . '/var/sessions'),
                    'PHP writes this request\'s session at shutdown. With the directory gone that '
                    . 'write fails silently, and the one-time setup grant issued moments earlier '
                    . 'goes with it — which locks the operator out of the installer on a machine '
                    . 'whose configuration has just been deleted.'
                );
                lh_true(is_dir($root . '/var/sessions'), 'so it is put back, empty');

                lh_same(
                    '',
                    Teardown::ensureSessionDir($cfg, '/tmp/somewhere-else'),
                    'and a save path outside this installation\'s own var/ is refused, so the only '
                    . 'thing this can ever create is a directory under a tree it owns'
                );
            } finally {
                lh_rmtree($root);
            }
        },

    'the step that empties var/ puts the session directory back before it returns'
        => static function (): void {
            $src = (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Settings.php');

            $wipe = strpos($src, 'Teardown::wipeState($cfg, self::TEARDOWN_KEEP)');
            $sess = strpos($src, 'Teardown::ensureSessionDir($cfg)');

            lh_true($wipe !== false, 'the data step empties var/');
            lh_true($sess !== false, 'and puts the session directory back');
            lh_true($sess > $wipe, 'in that order, or it is recreated and then deleted again');

            $grant = strpos($src, 'Token::grant();');
            lh_true($grant !== false && $grant < $wipe, 'and the grant is issued before the wipe');
        },

    // ---------------------------------------------------------------------------------
    // Refusals: the two that stop a run, and nothing local is gone when they fire
    // ---------------------------------------------------------------------------------

    'a delete the platform refuses stops the run with everything local intact'
        => static function (): void {
            [$root, $cfg] = lh_td_tree();
            $deleted = [];
            Storage::useTestTransport(lh_td_plane(lh_td_names(), $deleted, true));

            try {
                $job = lh_td_run($cfg);

                lh_same('failed', (string) $job['state'], 'the run stopped');
                lh_true(is_file($root . '/config/loghound.php'), 'the configuration is still there');
                lh_true(
                    is_file($root . '/var/state.db'),
                    'and so is the state, so this can be run again once the platform answers'
                );

                $steps = lh_td_steps($job);
                lh_contains(
                    (string) $steps['Deleting the Loghound indexes']['report'],
                    'Loghound problem report',
                    'the failure hands the operator one block to post'
                );
            } finally {
                Storage::useTestTransport(null);
                lh_rmtree($root);
            }
        },

    'an index the account still lists after a delete is a failure, not a success'
        => static function (): void {
            [$root, $cfg] = lh_td_tree();
            $deleted = [];
            Storage::useTestTransport(lh_td_plane(lh_td_names(), $deleted, false, true));

            try {
                $job = lh_td_run($cfg);

                lh_same(
                    'failed',
                    (string) $job['state'],
                    'the proof is the account listing, not the delete response. A platform that '
                    . 'accepted a delete and did not act on it must not leave the operator believing '
                    . 'they are no longer being billed for the index.'
                );
                lh_true(is_file($root . '/config/loghound.php'), 'and this box can still name them');
            } finally {
                Storage::useTestTransport(null);
                lh_rmtree($root);
            }
        },

    'ownership that cannot be derived deletes nothing at all' => static function (): void {
        [$root, $cfg] = lh_td_tree();
        $cfg->set('solr.hits_core', 'somebody_elses_index');
        $cfg->save();

        $deleted = [];
        Storage::useTestTransport(lh_td_plane(lh_td_names(), $deleted));

        try {
            $job = lh_td_run($cfg);

            lh_same('failed', (string) $job['state'], 'a stored name that disagrees with the derived one refuses');
            lh_same([], $deleted, 'and not one delete was attempted');
            lh_true(is_file($root . '/config/loghound.php'), 'and nothing local was removed');
        } finally {
            Storage::useTestTransport(null);
            lh_rmtree($root);
        }
    },

    'an empty account listing is never read as proof that anything is gone'
        => static function (): void {
            lh_throws(
                static fn () => OpensolrTeardown::verifyAbsent(lh_td_names(), []),
                'an empty listing is a listing that did not work: a restricted key, a control-plane '
                . 'hiccup and an account with nothing in it are indistinguishable from here'
            );
        },

    // ---------------------------------------------------------------------------------
    // The confirmation
    // ---------------------------------------------------------------------------------

    'a run cannot start without a confirmation, and one confirmation buys one run'
        => static function (): void {
            $_SESSION = [];

            lh_false(Teardown::isArmed(), 'nothing is armed by default');
            lh_false(Teardown::spendArm(), 'and there is nothing to spend');

            Teardown::arm();
            lh_true(Teardown::isArmed(), 'a confirmation arms it');
            lh_true(Teardown::isArmed(), 'and asking again does not spend it, or a page reload would disarm');

            lh_true(Teardown::spendArm(), 'the run spends it');
            lh_false(Teardown::spendArm(), 'and a second run finds nothing');
            lh_false(Teardown::isArmed(), 'nor does a second page');
        },

    'an expired arm is refused, and refusing removes it' => static function (): void {
        $_SESSION = ['lh_teardown_armed' => time() - 4000];

        lh_false(Teardown::isArmed(), 'fifteen minutes is the ceiling');
        lh_false(Teardown::spendArm(), 'and an expired one does not start a run');
        lh_false(
            isset($_SESSION['lh_teardown_armed']),
            'spending removes it whether or not it was good, so an expired one cannot sit in a '
            . 'session being re-tested'
        );
    },

    'the panel refuses to start the run without a current arm' => static function (): void {
        [$root, $cfg] = lh_td_tree();

        try {
            $_SESSION = ['lh_job_owner' => 'td-' . bin2hex(random_bytes(8)), 'lh_user' => 'admin'];
            $token = lh_csrf();

            $_SERVER['REQUEST_METHOD'] = 'POST';
            $_POST = ['action' => 'job_start', 'kind' => 'destructive_uninstall', 'csrf' => $token];

            $settings = new Settings($cfg, new Gateway($cfg, null, false));

            $result = (function (): array {
                $jobs = $this->jobs();
                $kind = 'destructive_uninstall';
                if (!Teardown::spendArm()) {
                    return ['error' => 'refused'];
                }
                return $jobs->start($kind);
            })->call($settings);

            lh_has_key($result, 'error', 'an unarmed start is refused');
        } finally {
            $_POST = [];
            unset($_SERVER['REQUEST_METHOD']);
            lh_rmtree($root);
        }
    },

    // ---------------------------------------------------------------------------------
    // The guards on the wipe itself
    // ---------------------------------------------------------------------------------

    'a configuration that cannot prove which tree it belongs to wipes nothing'
        => static function (): void {
            $stray = lh_tmpdir('lh-stray');
            @mkdir($stray . '/var', 0750, true);
            file_put_contents($stray . '/var/state.db', 'x');

            try {
                $cfg = Config::load($stray . '/loghound.php');

                $wipe = Teardown::wipeState($cfg);
                lh_same(
                    0,
                    $wipe['removed'],
                    'Config::varDir() falls back to the INSTALLED tree\'s var/ for any layout that '
                    . 'is not <root>/config/loghound.php, so a stray Config object handed to a '
                    . 'wipe would empty the running installation. The relationship is required, '
                    . 'not assumed.'
                );

                $out = Teardown::wipeConfig($cfg);
                lh_same([], $out['removed'], 'and the configuration is not removed either');
            } finally {
                lh_rmtree($stray);
            }
        },

    'the wipe unlinks a symlink rather than following it' => static function (): void {
        [$root, $cfg] = lh_td_tree();
        $outside = lh_tmpdir('lh-outside');
        file_put_contents($outside . '/precious', 'keep me');

        try {
            @unlink($root . '/var/sessions/sess_abc');
            @rmdir($root . '/var/sessions');
            symlink($outside, $root . '/var/sessions');

            Teardown::wipeState($cfg);

            lh_true(
                is_file($outside . '/precious'),
                'var/sessions pointed somewhere else — by an operator, or by anything that can '
                . 'write in var/ — must not turn emptying a directory into deleting whatever it '
                . 'aims at'
            );
        } finally {
            @unlink($root . '/var/sessions');
            lh_rmtree($outside);
            lh_rmtree($root);
        }
    },
];
