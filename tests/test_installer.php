<?php
/**
 * Loghound — tests for the browser installer.
 *
 * The installer runs BEFORE authentication exists, on a URL that is live from the moment
 * DNS resolves. It is the most exposed surface in the product, so these tests are weighted
 * towards the properties that would be a takeover if they broke, not towards the happy
 * path:
 *
 *   - it is unreachable the moment a valid configuration exists;
 *   - a missing or wrong setup token is refused, and guessing is rate limited;
 *   - a request without a CSRF token changes nothing;
 *   - no secret ever appears in anything rendered;
 *   - a log path outside `allowed_log_roots` is refused;
 *   - a catastrophically backtracking pattern is refused before it is stored;
 *   - the browser path and `bin/loghound-setup` produce an equivalent configuration.
 *
 * Requests are driven through a real subprocess rather than by calling the controller in
 * process, because the controller's refusals are `exit`s — which is the correct way for a
 * security gate to behave and the only way to observe it is from outside.
 *
 * No network: every Solr address used here points at a closed loopback port, and nothing
 * in these tests contacts the Opensolr control plane.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Config;
use Loghound\Setup\Detector;
use Loghound\Setup\Installer;
use Loghound\Setup\Steps;
use Loghound\Setup\Storage;
use Loghound\Setup\Job;
use Loghound\Setup\Token;

/** Repository root, for locating the runner and the CLI wizard. */
function lh_inst_root(): string
{
    return dirname(__DIR__);
}

/**
 * Build a throwaway installation tree: config/, var/, the two configsets, and a log
 * directory with a real fixture in it, plus a Config pointed at that tree.
 *
 * @return array{0:string,1:Config} [root, config]
 */
function lh_inst_scaffold(): array
{
    $root = lh_tmpdir('lhinst');
    mkdir($root . '/config', 0700, true);
    mkdir($root . '/var', 0750, true);
    mkdir($root . '/logs', 0750, true);
    copy(lh_fixture('apache_combined_human.log'), $root . '/logs/access.log');

    foreach (['hits', 'sessions'] as $core) {
        mkdir($root . '/solr/' . $core . '/conf', 0755, true);
        foreach (['managed-schema.xml', 'solrconfig.xml'] as $file) {
            $from = lh_inst_root() . '/solr/' . $core . '/conf/' . $file;
            if (is_file($from)) {
                copy($from, $root . '/solr/' . $core . '/conf/' . $file);
            }
        }
    }

    $cfg = Config::load($root . '/config/loghound.php');
    $cfg->set('allowed_log_roots', [$root . '/logs']);
    $cfg->set('discover', [
        'apache_configs'    => [],
        'apache_vhost_dirs' => [],
        'nginx_configs'     => [],
        'nginx_vhost_dirs'  => [],
        'fallback_globs'    => [$root . '/logs/*.log'],
    ]);

    return [$root, $cfg];
}

/**
 * A configuration that is complete and valid, so the installer must refuse to serve.
 *
 * Uses a closed loopback port for Solr: valid enough for Config::validate(), unreachable
 * enough that nothing in the suite can accidentally talk to a real server. The Opensolr
 * credentials are the same kind of fiction — validate() requires them to be present and never
 * contacts anything to check them.
 */
function lh_inst_valid_config(string $root): Config
{
    $cfg = Config::load($root . '/config/loghound.php');
    $cfg->set('opensolr.email', 'operator@example.com');
    $cfg->set('opensolr.api_key', 'not-a-real-key');
    $cfg->set('solr.base_url', 'http://127.0.0.1:1/solr');
    $cfg->set('solr.hits_core', 'loghound_aabbccdd_hits');
    $cfg->set('solr.sessions_core', 'loghound_aabbccdd_sessions');
    $cfg->set('solr.install_id', 'aabbccdd');
    $cfg->set('beacon.secret', str_repeat('b', 64));
    $cfg->set('privacy.ip_salt', str_repeat('s', 32));
    $cfg->set('auth.mode', 'basic');
    $cfg->set('auth.user', 'admin');
    $cfg->set('auth.password_hash', password_hash('correct horse battery', PASSWORD_DEFAULT));
    $cfg->set('sources', []);
    return $cfg;
}

/**
 * Drive one installer request in a subprocess and return what it produced.
 *
 * A fixed session id is used so a POST and the render that follows it share a session,
 * which is how the CSRF token and the unlock survive between calls.
 *
 * THE CONTROL PLANE CAN BE SCRIPTED ACROSS THE PROCESS BOUNDARY. Storage::useTestTransport()
 * takes a closure, which cannot travel through an environment variable, so `$transport` names a
 * PHP file the runner requires before the installer starts — the file installs the closure. It
 * is what lets a whole storage step be driven for real, against a control plane made of fixtures,
 * without SPEC §12's ban on network access being anywhere near it. LOGHOUND_TEST=1 is set for
 * the same reason it is set in tests/run.php: the seam is inert without it.
 *
 * @param array<string,mixed> $get
 * @param array<string,mixed> $post
 * @param string              $transport Path to a PHP file that installs a test transport.
 * @return array{out:string,code:int}
 */
function lh_inst_request(
    string $root,
    array $get = [],
    array $post = [],
    string $method = 'GET',
    bool $unlocked = false,
    bool $withCsrf = true,
    string $transport = ''
): array {
    $runner = $root . '/runner.php';
    $repo = lh_inst_root();

    $script = <<<'PHP'
<?php
declare(strict_types=1);
require getenv('LH_REPO') . '/src/autoload.php';

$lhTransport = (string) getenv('LH_TRANSPORT');
if ($lhTransport !== '' && is_file($lhTransport)) {
    require $lhTransport;
}

ini_set('session.use_cookies', '0');
ini_set('session.save_path', getenv('LH_ROOT') . '/var');
session_id('lhtestsession');
session_start();

$_GET    = json_decode((string) getenv('LH_GET'), true) ?: [];
$_POST   = json_decode((string) getenv('LH_POST'), true) ?: [];
$_SERVER['REQUEST_METHOD'] = (string) getenv('LH_METHOD');
$_SERVER['REMOTE_ADDR']    = '127.0.0.1';
$_SERVER['HTTP_HOST']      = 'loghound.test';

$_SESSION['lh_csrf'] = 'test-csrf-token';
if (getenv('LH_UNLOCKED') === '1') {
    $_SESSION['lh_setup_unlocked'] = time();
} else {
    unset($_SESSION['lh_setup_unlocked']);
}

$cfg = \Loghound\Config::load(getenv('LH_ROOT') . '/config/loghound.php');
(new \Loghound\Setup\Installer($cfg, getenv('LH_ROOT')))->handle();
PHP;

    file_put_contents($runner, $script);

    if ($withCsrf && $method === 'POST') {
        $post['csrf'] = 'test-csrf-token';
    }

    $env = [
        'LH_REPO'      => $repo,
        'LH_ROOT'      => $root,
        'LH_GET'       => (string) json_encode($get),
        'LH_POST'      => (string) json_encode($post),
        'LH_METHOD'    => $method,
        'LH_UNLOCKED'  => $unlocked ? '1' : '0',
        'LH_TRANSPORT' => $transport,
        'PATH'         => (string) getenv('PATH'),
    ];
    if ($transport !== '') {
        $env['LOGHOUND_TEST'] = '1';
    }

    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($runner) . ' 2>&1';
    $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $root, $env);
    if (!is_resource($proc)) {
        lh_fail('could not start the installer subprocess');
    }
    $out = (string) stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $code = proc_close($proc);

    return ['out' => $out, 'code' => $code];
}

/**
 * Run `bin/loghound-setup` non-interactively against a scaffolded tree.
 *
 * The base answers cover every step except storage. Every answer comes from the environment:
 * there is no terminal here, and a wizard that blocked on stdin would hang the suite rather
 * than fail it.
 *
 * NO PRIVACY ANSWERS ARE SUPPLIED EITHER. The wizard stopped asking, so a plain run leaves
 * `privacy.ip_mode` and `privacy.retention_days` at their defaults; the test that pins the two
 * environment variables passes them itself.
 *
 * NO STORAGE ANSWERS ARE SUPPLIED, AND THAT IS THE POINT. Provisioning now runs against
 * Opensolr and nothing else, so the only way to complete the storage step is over the network;
 * SPEC §12 forbids that here. With no account email in the configuration and none in the
 * environment, Storage::saveCredentials() refuses before anything is contacted and the
 * non-interactive wizard moves on — so the storage step is skipped without a single socket
 * being opened. LOGHOUND_FORCE_WRITE makes it write the rest anyway, which is what the callers
 * of this helper are actually asserting on. A caller that needs a complete configuration
 * pre-seeds the storage keys on disk first; see the CLI/browser parity test.
 *
 * @param array<string,string> $extra Environment overrides merged over the base answers.
 */
function lh_inst_cli(string $root, array $extra = []): string
{
    $env = array_merge([
        'LOGHOUND_NONINTERACTIVE'  => '1',
        'LOGHOUND_PANEL_USER'      => 'operator',
        'LOGHOUND_PANEL_PASSWORD'  => 'a-long-enough-password',
        'LOGHOUND_BASE_URL'        => 'https://loghound.example.com',
        'LOGHOUND_CONFIRM_SOURCES' => 'yes',
        'LOGHOUND_FORCE_WRITE'     => 'yes',
        'PATH'                     => (string) getenv('PATH'),
    ], $extra);

    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(lh_inst_root() . '/bin/loghound-setup')
        . ' --config=' . escapeshellarg($root . '/config/loghound.php')
        . ' --non-interactive --no-color 2>&1';

    $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $root, $env);
    if (!is_resource($proc)) {
        lh_skip('cannot start the CLI wizard here');
    }
    $out = (string) stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($proc);

    return $out;
}

/**
 * Mark the storage step already done, so a CLI run reaches the steps after it.
 *
 * The wizard stops at storage when storage fails, which is the point of that step — an
 * operator whose API key is wrong must not be asked for a password before being told. Tests
 * about the steps AFTER storage therefore have to arrive with storage settled, exactly as a
 * re-run on a working installation does, instead of relying on the wizard marching past a
 * failure. Nothing here touches the network: `storageIsProvisioned()` reads these three keys
 * and the wizard's default answer to "re-run provisioning?" is no.
 */
function lh_inst_storage_done(string $root): void
{
    $cfg = Config::load($root . '/config/loghound.php');
    $cfg->set('solr.install_id', 'a1b2c3d4');
    $cfg->set('solr.hits_core', 'loghound_a1b2c3d4_hits');
    $cfg->set('solr.sessions_core', 'loghound_a1b2c3d4_sessions');
    $cfg->set('solr.base_url', 'http://127.0.0.1:1/solr');
    $cfg->set('opensolr.email', 'someone@example.com');
    $cfg->set('opensolr.api_key', 'SENTINEL-APIKEY-1234');
    $cfg->save();
}

/**
 * Drive a job the browser installer has just started, the way the browser drives it.
 *
 * startJob() only creates the job and redirects; every step after that is a `?setup=job` POST
 * with action `run`, one step per request, which is the design that keeps any single request
 * far below the execution limit. A test that asserts on the OUTCOME of a storage choice has to
 * do the same thing rather than reaching into the job runner, or it is not testing the path an
 * operator takes.
 *
 * The id comes from the job directory rather than from the session, because the session lives
 * in the subprocess and the id is on disk either way.
 */
function lh_inst_run_job(string $root, string $kind, string $transport, int $limit = 20): void
{
    $job = Job::findRunning($root . '/var/setup', $kind);
    if ($job === null) {
        lh_fail('no ' . $kind . ' job was started');
    }

    for ($i = 0; $i < $limit; $i++) {
        $res = lh_inst_request(
            $root,
            ['setup' => 'job'],
            ['action' => 'run', 'id' => $job->id()],
            'POST',
            true,
            true,
            $transport
        );
        $status = json_decode($res['out'], true);
        if (!is_array($status) || (string) ($status['state'] ?? '') !== 'running') {
            return;
        }
    }

    lh_fail('the ' . $kind . ' job never finished');
}

/** Read the configuration back from disk as a plain array. */
function lh_inst_stored(string $root): array
{
    if (!is_file($root . '/config/loghound.php')) {
        return [];
    }
    return Config::load($root . '/config/loghound.php')->all();
}

return [
    // -------------------------------------------------------------------------
    // The gate
    // -------------------------------------------------------------------------

    'installer is needed when there is no configuration at all' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        lh_true(Installer::isNeeded($cfg), 'a fresh install needs setup');
        lh_rmtree($root);
    },

    'installer is GONE once a valid configuration exists' => static function (): void {
        [$root] = lh_inst_scaffold();
        $cfg = lh_inst_valid_config($root);
        lh_same([], $cfg->validate(), 'the fixture config should be valid');
        $cfg->save();

        $reloaded = Config::load($root . '/config/loghound.php');
        lh_false(Installer::isNeeded($reloaded), 'a complete install must not serve the installer');
        lh_rmtree($root);
    },

    'installer stays GONE when the panel cannot resolve its log directory' => static function (): void {
        [$root] = lh_inst_scaffold();
        $cfg = lh_inst_valid_config($root);

        $cfg->set('sources', [[
            'path'   => '/var/log/apache2/access.log',
            'format' => 'apache_combined',
            'host'   => 'example.com',
        ]]);
        $cfg->set('allowed_log_roots', ['/var/log']);
        $cfg->save();

        $reloaded = Config::load($root . '/config/loghound.php');

        lh_false(
            Installer::isNeeded($reloaded),
            'a complete install must not reopen the installer because a path did not resolve'
        );

        $cfg->set('allowed_log_roots', ['/nonexistent-root-' . bin2hex(random_bytes(4))]);
        $cfg->save();

        lh_false(
            Installer::isNeeded(Config::load($root . '/config/loghound.php')),
            'nor when the configured roots themselves cannot be resolved'
        );

        lh_rmtree($root);
    },

    'an unresolvable log directory is not a configuration error' => static function (): void {
        [$root] = lh_inst_scaffold();
        $cfg = lh_inst_valid_config($root);

        $missing = $root . '/no-such-dir-' . bin2hex(random_bytes(4));
        $cfg->set('sources', [[
            'path'   => $missing . '/access.log',
            'format' => 'apache_combined',
            'host'   => 'example.com',
        ]]);
        $cfg->set('allowed_log_roots', [$root]);

        $errors = implode(' | ', $cfg->validate());
        lh_true(
            strpos($errors, 'outside allowed_log_roots') === false,
            'a directory that cannot be resolved must not be reported as being outside the roots: ' . $errors
        );

        $outside = sys_get_temp_dir();
        $cfg->set('sources', [[
            'path'   => $outside . '/access.log',
            'format' => 'apache_combined',
            'host'   => 'example.com',
        ]]);

        $errors = implode(' | ', $cfg->validate());
        lh_true(
            strpos($errors, 'outside allowed_log_roots') !== false,
            'a directory that DOES resolve outside the roots must still be refused: ' . $errors
        );

        lh_rmtree($root);
    },

    'a configuration with no sign-in still needs setup' => static function (): void {
        [$root] = lh_inst_scaffold();
        $cfg = lh_inst_valid_config($root);
        $cfg->set('auth.mode', 'none');
        $cfg->set('auth.password_hash', '');
        $cfg->save();

        lh_true(
            Installer::isNeeded(Config::load($root . '/config/loghound.php')),
            'no credentials means the panel could only print an error'
        );
        lh_rmtree($root);
    },

    'a configuration that fails validation still needs setup' => static function (): void {
        [$root] = lh_inst_scaffold();
        $cfg = lh_inst_valid_config($root);
        $cfg->set('solr.hits_core', '');
        $cfg->save();

        lh_true(Installer::isNeeded(Config::load($root . '/config/loghound.php')), 'half a config is not ready');
        lh_rmtree($root);
    },

    'the security model docblock describes the gate that is actually implemented'
        => static function (): void {
        $source = (string) file_get_contents(dirname(__DIR__) . '/src/Setup/Installer.php');
        $header = substr($source, 0, (int) strpos($source, 'final class Installer'));

        lh_true(
            !preg_match('/has a usable sign-in and passes Config::validate\(\)/', $header),
            'the class docblock says the gate consults Config::validate(); isNeeded() explicitly '
            . 'does not, and when it did, an ordinary install with an unreadable log directory '
            . 'served the unauthenticated status page forever'
        );

        [$root] = lh_inst_scaffold();
        $cfg = lh_inst_valid_config($root);
        $cfg->set('sources', [[
            'path'   => sys_get_temp_dir() . '/access.log',
            'format' => 'apache_combined',
        ]]);
        $cfg->set('allowed_log_roots', [$root . '/logs']);
        $cfg->save();

        $reloaded = Config::load($root . '/config/loghound.php');
        lh_true($reloaded->validate() !== [], 'this configuration really does fail validate()');
        lh_false(Installer::isNeeded($reloaded), 'and it must still not reopen the installer');
        lh_rmtree($root);
    },

    'demo mode is the one exception and keeps the panel' => static function (): void {
        [$root] = lh_inst_scaffold();
        $cfg = lh_inst_valid_config($root);
        $cfg->set('solr.hits_core', '');
        $cfg->set('ui.demo', true);
        $cfg->save();

        lh_false(
            Installer::isNeeded(Config::load($root . '/config/loghound.php')),
            'the preview config is a deliberate developer state'
        );
        lh_rmtree($root);
    },

    // -------------------------------------------------------------------------
    // The setup token
    // -------------------------------------------------------------------------

    'a wrong token is refused and a right one is accepted' => static function (): void {
        $root = lh_tmpdir('lhtok');
        mkdir($root . '/var', 0750, true);
        $token = new Token($root . '/var');

        lh_true($token->ensure(), 'a token should be created on first contact');
        lh_true(is_file($token->path()), 'the token file should exist');
        lh_same('0600', substr(sprintf('%o', fileperms($token->path())), -4), 'token file mode');

        $real = trim((string) file_get_contents($token->path()));
        lh_true($real !== '', 'the token should not be empty');

        lh_true($token->verify('nope', '127.0.0.1') !== '', 'a wrong token must be refused');
        lh_true($token->verify('', '127.0.0.1') !== '', 'an empty token must be refused');
        lh_same('', $token->verify($real, '127.0.0.1'), 'the real token must be accepted');

        $token->destroy();
        lh_false(is_file($token->path()), 'the token must be destroyed when setup completes');
        lh_rmtree($root);
    },

    'token guessing is rate limited' => static function (): void {
        $root = lh_tmpdir('lhtok');
        mkdir($root . '/var', 0750, true);
        $token = new Token($root . '/var');
        $token->ensure();
        $real = trim((string) file_get_contents($token->path()));

        $refusals = 0;
        for ($i = 0; $i < 12; $i++) {
            if (str_contains($token->verify('wrong-' . $i, '203.0.113.9'), 'Too many attempts')) {
                $refusals++;
            }
        }
        lh_true($refusals > 0, 'a flood of guesses must eventually be turned away');

        // Even the correct token is refused once the budget is spent: failing closed is the
        // whole point. The way out is to wait the window out or delete the ledger file the
        // refusal names — the counter is on disk, so restarting PHP-FPM does nothing to it.
        $refusal = $token->verify($real, '203.0.113.9');
        lh_true(
            str_contains($refusal, 'Too many attempts'),
            'the limiter must not have an exemption for a correct guess'
        );
        lh_contains(
            $refusal,
            'install-attempts.json',
            'and it must name the file the operator has to delete, not a service to restart'
        );
        lh_true(
            !preg_match('/php-fpm|restart/i', $refusal),
            'the counter is on disk; a remedy that does not work is worse than none: ' . $refusal
        );
        lh_rmtree($root);
    },

    'a locked installer refuses to write anything' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        $cfg->save();

        $res = lh_inst_request(
            $root,
            [],
            [
                'step'      => 'admin',
                'action'    => 'finish',
                'user'      => 'intruder',
                'password'  => 'a-long-enough-password',
                'password2' => 'a-long-enough-password',
            ],
            'POST',
            false
        );

        $stored = lh_inst_stored($root);
        lh_same('', (string) $stored['auth']['password_hash'], 'a locked installer must not have written the change');
        lh_false(str_contains($res['out'], 'Fatal error'), 'no fatal: ' . $res['out']);
        lh_rmtree($root);
    },

    // -------------------------------------------------------------------------
    // CSRF
    // -------------------------------------------------------------------------

    'a POST without a CSRF token is refused and changes nothing' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        $cfg->save();

        $res = lh_inst_request(
            $root,
            [],
            [
                'step'      => 'admin',
                'action'    => 'finish',
                'user'      => 'intruder',
                'password'  => 'a-long-enough-password',
                'password2' => 'a-long-enough-password',
            ],
            'POST',
            true,
            false
        );

        lh_contains($res['out'], 'CSRF', 'the refusal should say so');

        $stored = lh_inst_stored($root);
        lh_same('', (string) $stored['auth']['password_hash'], 'nothing may be written without a CSRF token');
        lh_rmtree($root);
    },

    'an unlocked POST with a CSRF token does write' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        $cfg->save();

        Detector::runSync(Config::load($root . '/config/loghound.php'));

        lh_inst_request(
            $root,
            [],
            ['step' => 'sources', 'action' => 'confirm', 'pick' => ['0']],
            'POST',
            true
        );

        $stored = lh_inst_stored($root);
        lh_same(1, count((array) $stored['sources']), 'the confirmed log source should be stored');
        lh_rmtree($root);
    },

    'the job endpoint refuses a GET' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        $cfg->save();

        $res = lh_inst_request($root, ['setup' => 'job'], [], 'GET', true);
        lh_contains($res['out'], 'Not found', 'a job may not be driven with a GET');
        lh_rmtree($root);
    },

    'the job endpoint refuses a locked session' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        $cfg->save();

        $res = lh_inst_request(
            $root,
            ['setup' => 'job'],
            ['id' => str_repeat('a', 16), 'action' => 'run'],
            'POST',
            false
        );
        lh_contains($res['out'], 'Locked', 'the job endpoint must require the setup token');
        lh_rmtree($root);
    },

    // -------------------------------------------------------------------------
    // Rendering
    // -------------------------------------------------------------------------

    'the status page renders without a token and offers the unlock' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        $cfg->save();

        $res = lh_inst_request($root, ['setup' => 'status']);
        lh_contains($res['out'], '<h1>Set up Loghound</h1>', 'the status page should render');
        lh_contains($res['out'], 'install-token', 'it should say which file to read');
        lh_contains($res['out'], 'System check', 'it should show the requirement table');
        lh_false(str_contains($res['out'], 'Fatal error'), 'no fatal: ' . substr($res['out'], 0, 400));
        lh_rmtree($root);
    },

    'no secret is ever rendered on any screen' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();

        $apiKey  = 'SENTINEL-APIKEY-9f3c17ab';
        $beacon  = 'SENTINELBEACONSECRET' . str_repeat('9', 44);
        $salt    = 'SENTINELSALT12345678';
        $solrPw  = 'SENTINEL-SOLR-PASSWORD';

        $cfg->set('opensolr.email', 'someone@example.com');
        $cfg->set('opensolr.api_key', $apiKey);
        $cfg->set('opensolr.region', 'FINLAND9');
        $cfg->set('beacon.secret', $beacon);
        $cfg->set('privacy.ip_salt', $salt);
        $cfg->set('solr.mode', 'custom');
        $cfg->set('solr.base_url', 'http://127.0.0.1:1/solr');
        $cfg->set('solr.http_user', 'solruser');
        $cfg->set('solr.http_pass', $solrPw);
        $cfg->set('solr.hits_core', 'loghound_aabbccdd_hits');
        $cfg->set('solr.sessions_core', 'loghound_aabbccdd_sessions');
        $cfg->set('solr.install_id', 'aabbccdd');
        $cfg->set('auth.user', 'admin');
        $cfg->set('auth.password_hash', password_hash('SENTINEL-PASSWORD', PASSWORD_DEFAULT));
        $cfg->set('sources', [['path' => $root . '/logs/access.log', 'format' => 'apache_combined']]);
        $cfg->save();

        $hash = (string) $cfg->get('auth.password_hash');

        foreach (['status', 'sources', 'storage', 'privacy', 'admin'] as $step) {
            $res = lh_inst_request($root, ['setup' => $step], [], 'GET', true);
            foreach ([$apiKey, $beacon, $salt, $solrPw, $hash, 'SENTINEL-PASSWORD'] as $secret) {
                if (str_contains($res['out'], $secret)) {
                    lh_fail('a secret leaked into the ' . $step . ' screen');
                }
            }
        }
        lh_rmtree($root);
    },

    'a step cannot be reached out of order by guessing a URL' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        $cfg->save();

        $res = lh_inst_request($root, ['setup' => 'admin'], [], 'GET', true);
        lh_contains(
            $res['out'],
            'Choose your access logs',
            'jumping to the last step must land on the first unfinished one'
        );
        lh_rmtree($root);
    },

    'an unknown step falls back to the status page rather than erroring' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        $cfg->save();

        $res = lh_inst_request($root, ['setup' => '../../etc/passwd']);
        lh_contains($res['out'], 'Set up Loghound', 'an unknown route is the status page');
        lh_rmtree($root);
    },

    /**
     * The retired privacy step is gone from the wizard, not merely hidden from it.
     *
     * `?setup=privacy` is now an unrecognised route like any other, which is the behaviour a
     * stale bookmark needs: the status page, not a 500 and not a blank screen. The POST matters
     * more than the GET — a form that is no longer rendered can still be replayed by hand, and
     * the two settings it used to carry must not be writable through a step that no longer
     * exists.
     */
    'the privacy step is not a route any more, and neither reading nor posting it does anything'
        => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        $cfg->save();

        $get = lh_inst_request($root, ['setup' => 'privacy'], [], 'GET', true);
        lh_contains($get['out'], 'Set up Loghound', 'the retired step falls back to the status page');
        lh_false(
            str_contains($get['out'], 'What to keep about your visitors'),
            'and the step itself must not render'
        );
        lh_false(str_contains($get['out'], 'Fatal error'), 'no fatal: ' . substr($get['out'], 0, 400));

        $post = lh_inst_request(
            $root,
            [],
            ['step' => 'privacy', 'action' => 'save', 'ip_mode' => 'hash', 'retention_days' => '7'],
            'POST',
            true
        );
        lh_false(str_contains($post['out'], 'Fatal error'), 'no fatal: ' . substr($post['out'], 0, 400));

        $stored = lh_inst_stored($root);
        lh_same('full', $stored['privacy']['ip_mode'], 'a retired step may not still write its settings');
        lh_same(90, $stored['privacy']['retention_days'], 'nor the retention window');
        lh_rmtree($root);
    },

    'the wizard is three steps, and privacy is not one of them' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();

        lh_same(
            ['sources', 'storage', 'admin'],
            Installer::ORDER,
            'the flow, the rail and the progress map all read this one array'
        );
        lh_same(
            ['sources', 'storage', 'admin'],
            array_keys(Steps::progress($cfg)),
            'progress must describe exactly the steps the wizard has'
        );
        lh_false(defined(Installer::class . '::STEP_PRIVACY'), 'the constant itself is gone');

        lh_rmtree($root);
    },

    // -------------------------------------------------------------------------
    // Log sources
    // -------------------------------------------------------------------------

    'a log path outside allowed_log_roots is refused' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();

        $outside = $root . '/elsewhere.log';
        file_put_contents($outside, "127.0.0.1 - - [10/Sep/2026:00:00:00 +0000] \"GET / HTTP/1.1\" 200 1\n");

        $result = Detector::manualSource($cfg, $outside, 'apache_combined', '');
        lh_false($result['ok'], 'a path outside the permitted roots must be refused');
        lh_contains($result['error'], 'outside', 'and the refusal must say why');

        $inside = Detector::manualSource($cfg, $root . '/logs/access.log', 'apache_combined', '');
        lh_true($inside['ok'], 'a path inside the permitted roots is accepted: ' . $inside['error']);
        lh_rmtree($root);
    },

    'a path traversal out of an allowed root is refused' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        file_put_contents($root . '/secret.log', "x\n");

        $result = Detector::manualSource($cfg, $root . '/logs/../secret.log', 'apache_combined', '');
        lh_false($result['ok'], 'realpath must collapse the .. before the root check');
        lh_rmtree($root);
    },

    'a pattern that cannot compile or would extract nothing is refused before it is stored'
        => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();

        $noGroups = Detector::manualSource($cfg, $root . '/logs/access.log', 'custom', '/^(a+)+$/');
        lh_false(
            $noGroups['ok'],
            'a pattern with no named groups extracts nothing and is refused. This case is here under '
            . 'its own name because the test that used to cover it claimed the backtracking case and '
            . 'did not test it: /^(a+)+$/ is refused by LogDetect::formatFromRegex() for having no '
            . 'named groups, never by the backtracking probe, which accepts it'
        );
        lh_contains($noGroups['error'], 'named groups', 'and the refusal must say which problem it is');

        $broken = Detector::manualSource($cfg, $root . '/logs/access.log', 'custom', 'not-a-regex');
        lh_false($broken['ok'], 'a pattern that is not even delimited must be refused');

        $unclosed = Detector::manualSource($cfg, $root . '/logs/access.log', 'custom', '/^(?<ip>\S+/');
        lh_false($unclosed['ok'], 'a pattern that does not compile must be refused');
        lh_rmtree($root);
    },

    'the save-time regex probe is not, and does not claim to be, a backtracking proof'
        => static function (): void {
        lh_same(
            null,
            \Loghound\Security::validateUserRegex('/^(a+)+$/'),
            'an anchored pattern fails the probe\'s single fixed subject in a handful of steps '
            . 'whatever its internal shape, so the probe learns nothing and accepts it'
        );
        lh_same(
            null,
            \Loghound\Security::validateUserRegex('/^(?<remote_addr>(a+)+b) (?<status>\d{3})$/'),
            'including one shaped like a real log pattern, which is therefore storable'
        );

        $source = (string) file_get_contents(dirname(__DIR__) . '/src/Security.php');
        $at = strpos($source, 'public static function validateUserRegex');
        lh_true($at !== false, 'validateUserRegex must exist');
        $doc = substr($source, (int) strrpos(substr($source, 0, $at), '/**'), 3000);
        $doc = substr($doc, 0, (int) strpos($doc, '*/'));

        lh_true(
            !str_contains($doc, 'engineered to expose nested quantifier blowup'),
            'the docblock still claims the probe exposes catastrophic backtracking'
        );
        lh_true(
            !str_contains($doc, 'anything slow or failing is refused at save time'),
            'the docblock still claims a failing pattern cannot be saved'
        );
        lh_contains($doc, 'LogFormat::parse()', 'it must point at the guard that really contains it');
    },

    'an unknown format name is refused' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        $result = Detector::manualSource($cfg, $root . '/logs/access.log', 'nginx_or_something', '');
        lh_false($result['ok'], 'only library formats and "custom" are accepted');
        lh_rmtree($root);
    },

    'detection reads a real log and reports a mapping with samples' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();

        $report = Detector::runSync($cfg);
        $sources = (array) $report['sources'];
        lh_same(1, count($sources), 'one candidate should have been found');

        $src = $sources[0];
        lh_same('apache_combined', $src['format_name'], 'the fixture is apache combined');
        lh_true($src['confidence'] > 95, 'confidence on a clean fixture should be high');
        lh_true(count($src['samples']) > 0, 'sample lines are required by SPEC §8');
        lh_true(count($src['mapping']) > 0, 'the field mapping is required by SPEC §8');
        lh_false($src['outside_roots'], 'the fixture is inside the permitted root');

        foreach ($src['mapping'] as $row) {
            lh_has_key($row, 'token');
            lh_has_key($row, 'field');
            lh_has_key($row, 'example');
        }
        lh_rmtree($root);
    },

    'confirming a source stores it and never widens the roots on its own' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        $report = Detector::runSync($cfg);

        $errors = Steps::applySources($cfg, [(array) $report['sources'][0]]);
        lh_same([], $errors, 'a source inside the roots should apply cleanly');
        lh_same(1, count((array) $cfg->get('sources')), 'the source should be stored');
        lh_same([$root . '/logs'], (array) $cfg->get('allowed_log_roots'), 'roots must not change by themselves');

        $errors = Steps::applySources($cfg, [['path' => '/etc/shadow', 'format_name' => 'apache_combined']]);
        lh_true($errors !== [], 'a source outside the roots must be rejected on the way in');
        lh_rmtree($root);
    },

    // -------------------------------------------------------------------------
    // Storage
    // -------------------------------------------------------------------------

    'Opensolr credentials are validated before they are stored' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();

        lh_true(Storage::saveCredentials($cfg, '', '') !== [], 'an empty account is refused');
        lh_true(Storage::saveCredentials($cfg, 'not-an-email', 'abcdefghijkl') !== [], 'a bad address is refused');
        lh_true(
            Storage::saveCredentials($cfg, 'a@example.com', 'has spaces in it') !== [],
            'a key that cannot be a key is refused before any request is made'
        );
        lh_same([], Storage::saveCredentials($cfg, 'a@example.com', 'abcdefghijkl'), 'a plausible pair is accepted');
        lh_same('opensolr', $cfg->get('solr.mode'), 'accepting credentials selects managed mode');
        lh_rmtree($root);
    },

    // -------------------------------------------------------------------------
    // Storage has exactly one path
    // -------------------------------------------------------------------------

    /**
     * The four tests that follow pin a removal rather than a feature.
     *
     * Loghound provisions and manages its own two indexes on Opensolr: it creates them,
     * uploads the configsets under solr/hits/conf and solr/sessions/conf, reloads the cores
     * and verifies them. It cannot do any of that on a Solr it does not administer, so the
     * "use a Solr you already run" option was removed rather than left as a promise the
     * product could not keep. These exist so it cannot come back by accident: not as a form,
     * not as a POST action, not as an environment variable, and not as a value left in a
     * configuration file from before the removal.
     */
    'the storage screen offers one path and no second one' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        $cfg->set('sources', [['path' => $root . '/logs/access.log', 'format' => 'apache_combined']]);
        $cfg->save();

        $res = lh_inst_request($root, ['setup' => 'storage'], [], 'GET', true);

        lh_contains($res['out'], 'Let Opensolr host it', 'the managed panel must be on the screen');

        foreach ([
            'Use a Solr you already run',
            'Solr you already run',
            'name="hits_core"',
            'name="sessions_core"',
            'name="http_user"',
            'name="http_pass"',
            'value="custom"',
        ] as $gone) {
            lh_false(
                str_contains($res['out'], $gone),
                'the storage screen must not offer ' . $gone . ' — there is no second path'
            );
        }

        lh_rmtree($root);
    },

    'no entry point accepts a caller-supplied Solr URL or core name' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        $cfg->set('sources', [['path' => $root . '/logs/access.log', 'format' => 'apache_combined']]);
        $cfg->save();

        lh_false(
            method_exists(Storage::class, 'saveCustom'),
            'Storage::saveCustom() was the only door an operator-supplied base URL and core '
            . 'names could come through; it must stay gone'
        );

        lh_inst_request(
            $root,
            [],
            [
                'step'          => 'storage',
                'action'        => 'custom',
                'base_url'      => 'http://attacker.example.test:8983/solr',
                'http_user'     => 'someone',
                'http_pass'     => 'hunter2',
                'hits_core'     => 'lh_planted_hits',
                'sessions_core' => 'lh_planted_sessions',
            ],
            'POST',
            true
        );

        $stored = lh_inst_stored($root);
        lh_same('', (string) $stored['solr']['base_url'], 'no base URL may be planted by a POST');
        lh_same('', (string) $stored['solr']['http_user'], 'no username either');
        lh_same('', (string) $stored['solr']['http_pass'], 'nor a password');
        lh_same('', (string) $stored['solr']['hits_core'], 'and no core name');
        lh_same('', (string) $stored['solr']['sessions_core'], 'nor the other one');
        lh_same('opensolr', (string) $stored['solr']['mode'], 'and the mode cannot be moved off opensolr');

        lh_rmtree($root);
    },

    'the shell wizard has no storage choice, and the variables that served it are dead'
        => static function (): void {
        [$root] = lh_inst_scaffold();

        $out = lh_inst_cli($root, [
            'LOGHOUND_SOLR_CHOICE'    => '2',
            'LOGHOUND_SOLR_BASE_URL'  => 'http://attacker.example.test:8983/solr',
            'LOGHOUND_SOLR_HTTP_AUTH' => 'yes',
            'LOGHOUND_SOLR_HTTP_USER' => 'someone',
            'LOGHOUND_SOLR_HTTP_PASS' => 'hunter2',
            'LOGHOUND_HITS_CORE'      => 'lh_planted_hits',
            'LOGHOUND_SESSIONS_CORE'  => 'lh_planted_sessions',
        ]);

        if (!is_file($root . '/config/loghound.php')) {
            lh_fail('the CLI wizard wrote no configuration: ' . substr($out, -600));
        }

        foreach (['Choose 1 or 2', 'My own Solr', 'Solr base URL', 'Core name for hits'] as $gone) {
            lh_false(
                str_contains($out, $gone),
                'the wizard must not prompt ' . lh_show($gone) . '; got: ' . substr($out, -600)
            );
        }

        $stored = lh_inst_stored($root);
        lh_same('', (string) $stored['solr']['base_url'], 'LOGHOUND_SOLR_BASE_URL must do nothing');
        lh_same('', (string) $stored['solr']['http_user'], 'LOGHOUND_SOLR_HTTP_USER must do nothing');
        lh_same('', (string) $stored['solr']['http_pass'], 'LOGHOUND_SOLR_HTTP_PASS must do nothing');
        lh_same('', (string) $stored['solr']['hits_core'], 'LOGHOUND_HITS_CORE must do nothing');
        lh_same('', (string) $stored['solr']['sessions_core'], 'LOGHOUND_SESSIONS_CORE must do nothing');

        lh_rmtree($root);
    },

    'a configuration left on mode: custom is refused, and the refusal says why'
        => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();

        $cfg->set('solr.mode', 'custom');
        $cfg->set('solr.base_url', 'http://127.0.0.1:1/solr');
        $cfg->set('solr.hits_core', 'lh_hits');
        $cfg->set('solr.sessions_core', 'lh_sessions');
        $cfg->set('opensolr.email', 'operator@example.com');
        $cfg->set('opensolr.api_key', 'not-a-real-key');
        $cfg->set('beacon.enabled', false);
        $cfg->set('privacy.ip_mode', 'truncate');
        $cfg->set('auth.mode', 'basic');
        $cfg->set('auth.user', 'operator');
        $cfg->set('auth.password_hash', password_hash('a-long-enough-password', PASSWORD_DEFAULT));
        $cfg->set('sources', []);

        $errors = implode(' ', $cfg->validate());

        lh_true($errors !== '', 'a stored custom mode must not validate');
        lh_contains($errors, 'solr.mode', 'the refusal must name the setting');
        lh_contains($errors, 'no longer supported', 'and say that the option is gone');
        lh_contains(
            $errors,
            'cannot do that on a Solr it does not administer',
            'and give the reason, not just the fact'
        );
        lh_contains($errors, 'bin/loghound-setup', 'and say what to run instead');

        $cfg->set('solr.mode', 'opensolr');
        lh_same([], $cfg->validate(), 'the same configuration on the one supported mode is valid');

        lh_rmtree($root);
    },

    'the panel base URL may not carry credentials either' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();

        $errors = Steps::applyBaseUrl($cfg, 'https://someone:hunter2@loghound.example.com');
        lh_true($errors !== [], 'a panel URL with credentials must be refused');
        lh_true(
            !str_contains(implode(' ', $errors), 'hunter2'),
            'and the refusal must not echo the password: ' . implode(' ', $errors)
        );
        lh_same('', (string) $cfg->get('base_url', ''), 'and nothing is stored');

        lh_same([], Steps::applyBaseUrl($cfg, 'https://loghound.example.com'), 'a clean URL is accepted');
        lh_same('https://loghound.example.com', $cfg->get('base_url'), 'and stored');
        lh_rmtree($root);
    },

    'an unreachable Solr produces an actionable message, not a stack trace' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        $cfg->set('solr.base_url', 'http://127.0.0.1:1/solr');
        $cfg->set('solr.hits_core', 'lh_hits');

        $probe = Storage::probe($cfg);
        lh_false($probe['ok'], 'a closed port is not reachable');
        lh_contains($probe['message'], '127.0.0.1:1', 'the message must name the address it tried');
        lh_rmtree($root);
    },

    // -------------------------------------------------------------------------
    // The account
    // -------------------------------------------------------------------------

    'the panel password has a real minimum and is stored as a hash' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();

        lh_true(Steps::applyAdmin($cfg, 'admin', 'short', 'short') !== [], 'a short password is refused');
        lh_true(Steps::applyAdmin($cfg, 'admin', 'abcdefghij', 'different!!') !== [], 'a mismatch is refused');
        lh_true(Steps::applyAdmin($cfg, 'root; rm -rf /', 'abcdefghij', '') !== [], 'a wild username is refused');

        lh_same([], Steps::applyAdmin($cfg, 'admin', 'abcdefghij', 'abcdefghij'), 'a good pair is accepted');
        $hash = (string) $cfg->get('auth.password_hash');
        lh_false(str_contains($hash, 'abcdefghij'), 'the plaintext must not be in the config');
        lh_true(password_verify('abcdefghij', $hash), 'the hash must verify');
        lh_same('basic', $cfg->get('auth.mode'), 'the CLI and the browser must agree on the auth mode');
        lh_rmtree($root);
    },

    // -------------------------------------------------------------------------
    // Both installers, one result
    // -------------------------------------------------------------------------

    /**
     * The two front ends must produce the same configuration from the same answers.
     *
     * STORAGE IS PRE-SEEDED IDENTICALLY INTO BOTH TREES RATHER THAN ANSWERED. It is the one
     * step that now runs only against Opensolr, over the network, which SPEC §12 forbids here.
     * So both configurations start out looking like provisioning has already happened, and the
     * CLI wizard's storage step recognises that and keeps what it finds — which is itself the
     * behaviour that stops an unattended re-run from demanding an API key it was not given.
     * What this test still proves is what it was always for: sources, the account, the sign-in
     * mode, the panel URL and the generated secrets come out the same whichever front end the
     * operator used, and both results pass Config::validate().
     *
     * FOR THE TWO PRIVACY SETTINGS, PARITY IS NOW OVER THE DEFAULTS AND NOTHING ELSE, because
     * neither front end asks for them any more and the browser has no way to set them at all.
     * The comparison still covers `privacy.ip_mode` and `privacy.retention_days` — both sides
     * must arrive at `full` and 90 — so a front end that started writing something different
     * would still fail here; what it can no longer do is prove that the same answer produces
     * the same result, because there is no longer an answer. The environment variables the CLI
     * keeps are pinned by their own test instead.
     */
    'the browser path and the CLI path produce an equivalent configuration' => static function (): void {
        [$cliRoot, $cliCfg] = lh_inst_scaffold();
        [$webRoot, $webCfg] = lh_inst_scaffold();

        $answers = [
            'base_url'  => 'http://127.0.0.1:1/solr',
            'hits'      => 'lh_hits',
            'sessions'  => 'lh_sessions',
            'email'     => 'operator@example.com',
            'api_key'   => 'not-a-real-key',
            'region'    => 'FINLAND9',
            'user'      => 'operator',
            'password'  => 'a-long-enough-password',
            'panel_url' => 'https://loghound.example.com',
        ];

        $provisioned = static function (Config $cfg) use ($answers): void {
            $cfg->set('solr.base_url', $answers['base_url']);
            $cfg->set('solr.hits_core', $answers['hits']);
            $cfg->set('solr.sessions_core', $answers['sessions']);
            $cfg->set('opensolr.email', $answers['email']);
            $cfg->set('opensolr.api_key', $answers['api_key']);
            $cfg->set('opensolr.region', $answers['region']);
        };

        $provisioned($cliCfg);
        $cliCfg->save();
        $provisioned($webCfg);

        $env = [
            'LOGHOUND_NONINTERACTIVE'   => '1',
            'LOGHOUND_PANEL_USER'       => $answers['user'],
            'LOGHOUND_PANEL_PASSWORD'   => $answers['password'],
            'LOGHOUND_BASE_URL'         => $answers['panel_url'],
            'LOGHOUND_CONFIRM_SOURCES'  => 'yes',
            'LOGHOUND_FORCE_WRITE'      => 'yes',
            'PATH'                      => (string) getenv('PATH'),
        ];

        $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(lh_inst_root() . '/bin/loghound-setup')
            . ' --config=' . escapeshellarg($cliRoot . '/config/loghound.php')
            . ' --non-interactive --no-color 2>&1';
        $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $cliRoot, $env);
        if (!is_resource($proc)) {
            lh_skip('cannot start the CLI wizard here');
        }
        $out = (string) stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($proc);

        if (!is_file($cliRoot . '/config/loghound.php')) {
            lh_fail('the CLI wizard wrote no configuration: ' . substr($out, -600));
        }

        Steps::applyAdmin($webCfg, $answers['user'], $answers['password'], $answers['password']);
        Steps::applyBaseUrl($webCfg, $answers['panel_url']);
        Steps::ensureSecrets($webCfg);
        $webCfg->save();

        $cli = lh_inst_stored($cliRoot);
        $web = lh_inst_stored($webRoot);

        // Everything except the values that are random or machine-specific by design:
        // the two secrets, the password hash and the installation id.
        $compare = static function (array $c): array {
            unset(
                $c['beacon']['secret'],
                $c['privacy']['ip_salt'],
                $c['auth']['password_hash'],
                $c['solr']['install_id'],
                $c['discover'],
                $c['allowed_log_roots'],
                $c['sources']
            );
            return $c;
        };

        lh_same($compare($web), $compare($cli), 'the two installers must produce the same configuration');

        lh_same('full', $cli['privacy']['ip_mode'], 'an unanswered install keeps the full address');
        lh_same('full', $web['privacy']['ip_mode'], 'through either front end');
        lh_same(90, $cli['privacy']['retention_days'], 'and the 90-day default');
        lh_same(90, $web['privacy']['retention_days'], 'through either front end');

        lh_true(strlen((string) $cli['beacon']['secret']) >= 32, 'the CLI generates a beacon secret');
        lh_true(strlen((string) $web['beacon']['secret']) >= 32, 'the browser generates a beacon secret');
        lh_true(password_verify($answers['password'], (string) $cli['auth']['password_hash']), 'CLI hash verifies');
        lh_true(password_verify($answers['password'], (string) $web['auth']['password_hash']), 'web hash verifies');
        lh_same([], Config::load($cliRoot . '/config/loghound.php')->validate(), 'the CLI result is valid');
        lh_same([], Config::load($webRoot . '/config/loghound.php')->validate(), 'the browser result is valid');

        lh_rmtree($cliRoot);
        lh_rmtree($webRoot);
    },

    /**
     * The same two steps, through the panel and through the browser installer, must land the
     * same configuration.
     *
     * WHY SETTINGS IS IN THIS TEST AT ALL. The parity test above covers the two INSTALLERS, and
     * for a long time that was the whole population: a panel could not change an account or move
     * an installation onto different indexes, so there was nothing to drift. Both are now
     * ordinary panel operations, and Settings is the surface being edited most — which makes it
     * the one most likely to grow a second idea of what "choose your indexes" means.
     *
     * Both sides do exactly the same two things: save an account that does NOT hold the pair
     * currently configured, then pick the pair that account does hold. Both are driven through
     * the real handlers — the browser installer in a subprocess, because its refusals are exits
     * — against the same scripted control plane, so the comparison is of two real runs rather
     * than of two intentions.
     *
     * What is stripped from the comparison is only what is random or machine-specific by design.
     * `solr.install_id` is the important one and it is stripped for a reason worth stating: it
     * must NOT be copied from the adopted pair, because it is the salt in every document id and
     * two machines sharing it would silently overwrite each other. Each side therefore keeps its
     * own, and they are legitimately different.
     */
    'saving an account and choosing a pair lands the same configuration on either surface'
        => static function (): void {
            require_once __DIR__ . '/support/opensolr_plane.php';

            $key   = 'SENTINEL-PARITY-KEY-0001';
            $email = 'parity@example.com';
            $held  = ['loghound_bbbb2222_hits', 'loghound_bbbb2222_sessions'];

            $seed = static function (Config $cfg): void {
                $cfg->set('solr.mode', 'opensolr');
                $cfg->set('solr.install_id', 'aaaa1111');
                $cfg->set('solr.hits_core', 'loghound_aaaa1111_hits');
                $cfg->set('solr.sessions_core', 'loghound_aaaa1111_sessions');
                $cfg->set('solr.base_url', 'https://fi.solrcluster.com/solr');
                $cfg->set('base_url', 'https://shop.example.com');
                $cfg->set('opensolr.email', 'previous@example.com');
                $cfg->set('opensolr.api_key', 'SENTINEL-PARITY-OLD-0000');
                $cfg->set('opensolr.region', 'FINLAND9');
                $cfg->set('auth.user', 'admin');
                $cfg->set('auth.mode', 'basic');
                $cfg->set('auth.password_hash', password_hash('a-long-enough-password', PASSWORD_DEFAULT));
                $cfg->set('beacon.secret', str_repeat('b', 64));
                $cfg->set('privacy.ip_salt', str_repeat('s', 32));
                $cfg->save();
            };

            [$webRoot, $webCfg] = lh_inst_scaffold();
            $webCfg->set('sources', [['path' => $webRoot . '/logs/access.log', 'format' => 'apache_combined']]);
            $seed($webCfg);
            $stub = lh_opensolr_plane_stub($webRoot . '/plane.php', $held, $key);

            lh_inst_request(
                $webRoot,
                [],
                ['step' => 'storage', 'action' => 'credentials', 'email' => $email, 'api_key' => $key],
                'POST',
                true,
                true,
                $stub
            );
            lh_inst_request(
                $webRoot,
                [],
                ['step' => 'storage', 'action' => 'indexes', 'install_id' => 'bbbb2222'],
                'POST',
                true,
                true,
                $stub
            );
            lh_inst_run_job($webRoot, Job::KIND_REUSE, $stub);

            [$panelRoot, $panelCfg] = lh_inst_scaffold();
            $panelCfg->set('sources', [['path' => $panelRoot . '/logs/access.log', 'format' => 'apache_combined']]);
            $seed($panelCfg);

            $panelHeld = $held;
            Storage::useTestTransport(lh_opensolr_plane($panelHeld, $key));
            try {
                $_POST = [
                    'action'           => 'opensolr_credentials',
                    'csrf'             => lh_csrf(),
                    'opensolr_email'   => $email,
                    'opensolr_api_key' => $key,
                    'opensolr_region'  => 'FINLAND9',
                ];
                $_SERVER['REQUEST_METHOD'] = 'POST';
                (new \Loghound\Panel\Settings(
                    $panelCfg,
                    new \Loghound\Panel\Gateway($panelCfg, null, false)
                ))->post();

                $_POST = [
                    'action'     => 'opensolr_indexes',
                    'csrf'       => lh_csrf(),
                    'install_id' => 'bbbb2222',
                ];
                (new \Loghound\Panel\Settings(
                    $panelCfg,
                    new \Loghound\Panel\Gateway($panelCfg, null, false)
                ))->post();
                $_POST = [];
            } finally {
                Storage::useTestTransport(null);
            }

            $web   = lh_inst_stored($webRoot);
            $panel = lh_inst_stored($panelRoot);

            lh_same(
                'loghound_bbbb2222_hits',
                (string) $web['solr']['hits_core'],
                'the browser installer adopted the pair that was picked'
            );
            lh_same(
                'loghound_bbbb2222_hits',
                (string) $panel['solr']['hits_core'],
                'and so did Settings'
            );

            $compare = static function (array $c): array {
                unset(
                    $c['solr']['install_id'],
                    $c['auth']['password_hash'],
                    $c['discover'],
                    $c['allowed_log_roots'],
                    $c['sources']
                );
                return $c;
            };

            lh_same(
                $compare($web),
                $compare($panel),
                'the panel and the browser installer must produce the same configuration from the '
                . 'same two answers'
            );

            lh_false(
                str_contains((string) file_get_contents($webRoot . '/config/loghound.php'), 'aaaa1111_hits'),
                'and neither is left pointing at the previous account\'s indexes'
            );

            lh_rmtree($webRoot);
            lh_rmtree($panelRoot);
        },

    /**
     * The same condition has to produce the same refusal, whichever surface met it.
     *
     * A plan with no room and no pair to join is the worst state an operator can be in here, and
     * it is exactly the one where two front ends drifting would matter: one saying "your plan is
     * full" and the other quoting numbers is how a support thread starts. Both read the sentence
     * out of the same function, and this is what says so.
     */
    'a plan with nothing to join and no room says the same thing everywhere'
        => static function (): void {
            require_once __DIR__ . '/support/opensolr_plane.php';

            [$root, $cfg] = lh_inst_scaffold();
            $cfg->set('solr.mode', 'opensolr');
            $cfg->set('opensolr.email', 'full@example.com');
            $cfg->set('opensolr.api_key', 'SENTINEL-FULL-KEY-0001');
            $cfg->set('sources', [['path' => $root . '/logs/access.log', 'format' => 'apache_combined']]);
            $cfg->save();

            $held = ['someone_elses_index', 'another_one'];
            Storage::useTestTransport(lh_opensolr_plane($held, 'SENTINEL-FULL-KEY-0001', 2));
            try {
                $account = Storage::account($cfg);
            } finally {
                Storage::useTestTransport(null);
            }

            $step = \Loghound\Setup\Pairs::decide($cfg, $account);

            $stub = lh_opensolr_plane_stub($root . '/plane.php', $held, 'SENTINEL-FULL-KEY-0001', 2);
            $res  = lh_inst_request($root, ['setup' => 'storage'], [], 'GET', true, true, $stub);

            lh_contains(
                $res['out'],
                htmlspecialchars($step['dead_end'], ENT_QUOTES),
                'the browser installer renders the shared sentence, not one of its own'
            );
            lh_contains($res['out'], htmlspecialchars($step['ways_heading'], ENT_QUOTES), 'and the counted heading');
            lh_false(
                str_contains($res['out'], 'value="' . \Loghound\Setup\Pairs::CHOICE_NEW . '"'),
                'with no option that could only fail'
            );

            lh_rmtree($root);
        },

    /**
     * The shell wizard stopped asking about privacy but kept both variables.
     *
     * An unattended install from Ansible or CI is the one case where a non-default privacy
     * answer has to arrive with no human present, so dropping the prompts must not drop the
     * overrides with them. A plain run must equally not invent an answer: the defaults stand.
     */
    'the shell wizard does not ask about privacy, and still honours both variables'
        => static function (): void {
        [$plainRoot] = lh_inst_scaffold();
        lh_inst_storage_done($plainRoot);

        $out = lh_inst_cli($plainRoot);
        if (!is_file($plainRoot . '/config/loghound.php')) {
            lh_fail('the CLI wizard wrote no configuration: ' . substr($out, -600));
        }

        lh_false(
            str_contains($out, 'IP storage mode'),
            'the wizard must not prompt for an IP mode any more: ' . substr($out, -600)
        );
        lh_false(
            str_contains($out, 'Delete hits older than how many days'),
            'nor for a retention window: ' . substr($out, -600)
        );

        $plain = lh_inst_stored($plainRoot);
        lh_same('full', $plain['privacy']['ip_mode'], 'an unanswered run keeps the full address');
        lh_same(90, $plain['privacy']['retention_days'], 'and the 90-day default');
        lh_rmtree($plainRoot);

        [$envRoot] = lh_inst_scaffold();
        lh_inst_storage_done($envRoot);

        $out = lh_inst_cli($envRoot, [
            'LOGHOUND_IP_MODE'        => 'truncate',
            'LOGHOUND_RETENTION_DAYS' => '45',
        ]);
        if (!is_file($envRoot . '/config/loghound.php')) {
            lh_fail('the CLI wizard wrote no configuration: ' . substr($out, -600));
        }

        $env = lh_inst_stored($envRoot);
        lh_same('truncate', $env['privacy']['ip_mode'], 'LOGHOUND_IP_MODE must still be honoured');
        lh_same(45, $env['privacy']['retention_days'], 'LOGHOUND_RETENTION_DAYS must still be honoured');
        lh_rmtree($envRoot);

        [$oneRoot] = lh_inst_scaffold();
        lh_inst_storage_done($oneRoot);

        $out = lh_inst_cli($oneRoot, ['LOGHOUND_RETENTION_DAYS' => '7']);
        if (!is_file($oneRoot . '/config/loghound.php')) {
            lh_fail('the CLI wizard wrote no configuration: ' . substr($out, -600));
        }

        $one = lh_inst_stored($oneRoot);
        lh_same(7, $one['privacy']['retention_days'], 'one variable on its own must work');
        lh_same(
            'full',
            $one['privacy']['ip_mode'],
            'and must not drag the other away from what the configuration already held'
        );
        lh_rmtree($oneRoot);
    },

    'the shell wizard can reach the sign-in page, not only Basic' => static function (): void {
        [$root] = lh_inst_scaffold();
        lh_inst_storage_done($root);

        $out = lh_inst_cli($root, ['LOGHOUND_AUTH_MODE' => 'session']);

        if (!is_file($root . '/config/loghound.php')) {
            lh_fail('the CLI wizard wrote no configuration: ' . substr($out, -600));
        }

        $stored = lh_inst_stored($root);
        lh_same(
            'session',
            $stored['auth']['mode'],
            'a CLI operator who asks for the sign-in page must get it, not Basic. Wizard output: '
            . substr($out, -400)
        );
        lh_true(
            password_verify('a-long-enough-password', (string) $stored['auth']['password_hash']),
            'and the account itself must still be written'
        );
        lh_rmtree($root);
    },

    'the shell wizard still defaults to Basic when nobody chooses' => static function (): void {
        [$root] = lh_inst_scaffold();
        lh_inst_storage_done($root);

        $out = lh_inst_cli($root, []);

        if (!is_file($root . '/config/loghound.php')) {
            lh_fail('the CLI wizard wrote no configuration: ' . substr($out, -600));
        }

        lh_same(
            'basic',
            lh_inst_stored($root)['auth']['mode'],
            'the default must not move: it is what every install made before the sign-in page '
            . 'existed uses, and it is what keeps the CLI and the browser installer in step'
        );
        lh_rmtree($root);
    },

    'progress is read from the configuration, so setup resumes where it stopped' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();

        lh_same(Installer::STEP_SOURCES, Steps::firstIncomplete($cfg), 'a fresh install starts at the logs');

        $cfg->set('sources', [['path' => $root . '/logs/access.log', 'format' => 'apache_combined']]);
        lh_same(Installer::STEP_STORAGE, Steps::firstIncomplete($cfg), 'then storage');

        $cfg->set('solr.hits_core', 'lh_hits');
        $cfg->set('solr.sessions_core', 'lh_sessions');
        $cfg->set('solr.base_url', 'http://127.0.0.1:1/solr');
        lh_same(Installer::STEP_ADMIN, Steps::firstIncomplete($cfg), 'then the account, and nothing between');
        lh_rmtree($root);
    },

    // -------------------------------------------------------------------------
    // Jobs
    // -------------------------------------------------------------------------

    'a job id is validated before it becomes a path' => static function (): void {
        $root = lh_tmpdir('lhjob');
        mkdir($root . '/setup', 0750, true);
        file_put_contents($root . '/setup/x.json', '{}');

        lh_same(null, Job::load($root . '/setup', '../../etc/passwd'), 'traversal is refused');
        lh_same(null, Job::load($root . '/setup', 'x'), 'a non-hex id is refused');
        lh_same(null, Job::load($root . '/setup', str_repeat('z', 16)), 'non-hex characters are refused');
        lh_rmtree($root);
    },

    'an unknown job kind is refused' => static function (): void {
        $root = lh_tmpdir('lhjob');
        lh_throws(static fn () => Job::create($root . '/setup', 'rm -rf'), 'an unknown kind');
        lh_rmtree($root);
    },

    'the detection job runs to completion and writes the report' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        $cfg->save();

        $job = Job::create($root . '/var/setup', Job::KIND_DETECT);
        lh_true($job->runAll($cfg, $root), 'the detection job should finish: ' . $job->error());

        $status = $job->status($cfg, $root);
        lh_same('done', $status['state'], 'state');
        lh_same(100, $status['percent'], 'a finished job is 100%');
        foreach ($status['steps'] as $step) {
            lh_same('done', $step['state'], 'step ' . $step['key']);
        }

        lh_true(is_file($root . '/var/detect.json'), 'the report should be on disk');
        $report = Detector::lastReport($cfg);
        lh_same(1, count((array) $report['sources']), 'the fixture log should be in the report');
        lh_rmtree($root);
    },

    'a running job is reattached to rather than duplicated' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        $cfg->save();

        $first = Job::create($root . '/var/setup', Job::KIND_OPENSOLR, ['region' => 'FINLAND9']);
        $found = Job::findRunning($root . '/var/setup', Job::KIND_OPENSOLR);

        lh_true($found !== null, 'a running job should be found');
        lh_same($first->id(), $found->id(), 'and it should be the same one');
        lh_same(null, Job::findRunning($root . '/var/setup', Job::KIND_DETECT), 'of the right kind only');
        lh_rmtree($root);
    },

    'a job status payload never carries a secret' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        $cfg->set('opensolr.api_key', 'SENTINEL-APIKEY-1234');
        $cfg->set('beacon.secret', str_repeat('S', 64));
        $cfg->save();

        $job = Job::create($root . '/var/setup', Job::KIND_DETECT);
        $job->runAll($cfg, $root);

        $json = (string) json_encode($job->status($cfg, $root));
        lh_false(str_contains($json, 'SENTINEL-APIKEY-1234'), 'the API key must never reach the browser');
        lh_false(str_contains($json, str_repeat('S', 64)), 'nor the beacon secret');

        $onDisk = (string) file_get_contents(glob($root . '/var/setup/*.json')[0]);
        lh_false(str_contains($onDisk, 'SENTINEL-APIKEY-1234'), 'nor may a job file hold it');
        lh_rmtree($root);
    },

    // -------------------------------------------------------------------------
    // Provisioning, with a scripted control plane
    // -------------------------------------------------------------------------

    'provisioning creates both indexes, configures them and stores the connection' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        $cfg->set('opensolr.email', 'someone@example.com');
        $cfg->set('opensolr.api_key', 'SENTINEL-APIKEY-1234');
        $cfg->save();

        $calls = [];
        Storage::useTestTransport(static function (array $req) use (&$calls): array {
            $calls[] = $req['url'];
            $body = ['status' => true, 'msg' => 'OK'];

            if (str_contains($req['url'], '/regions')) {
                $body = ['FINLAND9', 'GERMANY9'];
            } elseif (str_contains($req['url'], '/get_core_info')) {
                preg_match('/core_name=([A-Za-z0-9_]+)/', $req['url'], $m);
                $body = ['status' => true, 'msg' => ['info' => [
                    'connection_url' => 'https://fi.solrcluster.com/solr/' . ($m[1] ?? 'x'),
                    'auth_username'  => 'solr-user',
                    'auth_password'  => 'solr-pass',
                ]]];
            } elseif (str_contains($req['url'], '/select')) {
                $body = ['responseHeader' => ['status' => 0], 'response' => ['numFound' => 0, 'docs' => []]];
            }
            return ['status' => 200, 'body' => (string) json_encode($body), 'error' => ''];
        });

        try {
            $job = Job::create($root . '/var/setup', Job::KIND_OPENSOLR, ['region' => 'FINLAND9']);
            $ok = $job->runAll($cfg, $root);
            lh_true($ok, 'provisioning should succeed: ' . $job->error());

            $stored = lh_inst_stored($root);
            lh_same('opensolr', $stored['solr']['mode'], 'managed mode');
            lh_true($stored['solr']['install_id'] !== '', 'an installation id is generated');
            lh_same(
                'loghound_' . $stored['solr']['install_id'] . '_hits',
                $stored['solr']['hits_core'],
                'the hits index carries the installation id'
            );
            lh_same(
                'loghound_' . $stored['solr']['install_id'] . '_sessions',
                $stored['solr']['sessions_core'],
                'and so does the sessions index'
            );
            lh_same('https://fi.solrcluster.com/solr', $stored['solr']['base_url'], 'base_url from connectionDetails');
            lh_same('solr-user', $stored['solr']['http_user'], 'http_user from connectionDetails');
            lh_same('solr-pass', $stored['solr']['http_pass'], 'http_pass from connectionDetails');
            lh_same('FINLAND9', $stored['opensolr']['region'], 'the chosen region is kept');

            $uploads = array_filter($calls, static fn (string $u): bool => str_contains($u, 'upload_config_file'));
            lh_same(4, count($uploads), 'two files uploaded to each of the two indexes');
        } finally {
            Storage::useTestTransport(null);
            lh_rmtree($root);
        }
    },

    'a taken index name is retried with a new id and the orphan is deleted' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        $cfg->set('opensolr.email', 'someone@example.com');
        $cfg->set('opensolr.api_key', 'SENTINEL-APIKEY-1234');
        $cfg->save();

        $created = 0;
        $calls = [];
        Storage::useTestTransport(static function (array $req) use (&$calls, &$created): array {
            $calls[] = $req['url'];
            $body = ['status' => true, 'msg' => 'OK'];

            if (str_contains($req['url'], '/regions')) {
                $body = ['FINLAND9'];
            } elseif (str_contains($req['url'], '/create_index')) {
                $created++;
                // The second create — the first attempt's sessions index — collides, so
                // the whole pair must be abandoned and the first one deleted.
                if ($created === 2) {
                    $body = ['status' => false, 'msg' => 'ERROR_CORE_NAME_TAKEN_CHOOSE_ANOTHER_CORE_NAME'];
                }
            } elseif (str_contains($req['url'], '/get_core_info')) {
                $body = ['status' => true, 'msg' => ['info' => [
                    'connection_url' => 'https://fi.solrcluster.com/solr/x',
                    'auth_username'  => 'u',
                    'auth_password'  => 'p',
                ]]];
            } elseif (str_contains($req['url'], '/select')) {
                $body = ['responseHeader' => ['status' => 0], 'response' => ['numFound' => 0, 'docs' => []]];
            }
            return ['status' => 200, 'body' => (string) json_encode($body), 'error' => ''];
        });

        try {
            $job = Job::create($root . '/var/setup', Job::KIND_OPENSOLR, ['region' => 'FINLAND9']);
            lh_true($job->runAll($cfg, $root), 'the retry should still land: ' . $job->error());

            $deletes = array_values(array_filter($calls, static fn (string $u): bool => str_contains($u, 'delete_index')));
            lh_same(1, count($deletes), 'exactly one orphan must be removed');

            $firstName = null;
            foreach ($calls as $url) {
                if (str_contains($url, '/create_index') && preg_match('/index_name=([A-Za-z0-9_]+)/', $url, $m)) {
                    $firstName = $m[1];
                    break;
                }
            }
            $stored = lh_inst_stored($root);
            lh_true($firstName !== null, 'the first attempt named an index');
            lh_true(
                $stored['solr']['hits_core'] !== $firstName,
                'the abandoned id must not be reused'
            );
            lh_true(str_contains($deletes[0], 'index_name='), 'the rollback names the index it removes');
        } finally {
            Storage::useTestTransport(null);
            lh_rmtree($root);
        }
    },

    'a refused API key fails the step it belongs to and creates nothing' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        $cfg->set('opensolr.email', 'someone@example.com');
        $cfg->set('opensolr.api_key', 'SENTINEL-APIKEY-1234');
        $cfg->save();

        $calls = [];
        Storage::useTestTransport(static function (array $req) use (&$calls): array {
            $calls[] = $req['url'];
            return [
                'status' => 200,
                'body'   => (string) json_encode(['status' => false, 'msg' => 'ERROR_INVALID_API_KEY']),
                'error'  => '',
            ];
        });

        try {
            $job = Job::create($root . '/var/setup', Job::KIND_OPENSOLR, ['region' => 'FINLAND9']);
            lh_false($job->runAll($cfg, $root), 'a refused key must fail');
            lh_same('error', $job->state(), 'the job records the failure');
            lh_contains($job->error(), 'Checking your Opensolr credentials', 'the failure names its step');
            lh_false(str_contains($job->error(), 'SENTINEL-APIKEY-1234'), 'and never quotes the key');

            $creates = array_filter($calls, static fn (string $u): bool => str_contains($u, 'create_index'));
            lh_same(0, count($creates), 'nothing may be created after a refused credential');
        } finally {
            Storage::useTestTransport(null);
            lh_rmtree($root);
        }
    },

    'the test transport seam is inert outside the test suite' => static function (): void {
        $was = getenv('LOGHOUND_TEST');
        putenv('LOGHOUND_TEST');
        try {
            lh_throws(static fn () => Storage::useTestTransport(static fn (array $r): array => []), 'outside tests');
        } finally {
            putenv('LOGHOUND_TEST=' . ($was === false ? '1' : $was));
        }
    },

    // -------------------------------------------------------------------------
    // End to end
    // -------------------------------------------------------------------------

    /**
     * The browser installer, start to finish.
     *
     * Storage is pre-seeded to look provisioned rather than answered on screen: the only way
     * to complete that step is to create two indexes on Opensolr, which is a network call, and
     * SPEC §12 forbids one here. The provisioning state machine itself is covered against a
     * fake transport by the jobs tests above; what this test is for is the walk — gate, unlock,
     * sources, account — and the fact that finishing kills the installer.
     */
    'a whole install can be completed through the browser, and then the installer is gone'
        => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        $cfg->set('solr.base_url', 'http://127.0.0.1:1/solr');
        $cfg->set('solr.hits_core', 'lh_hits');
        $cfg->set('solr.sessions_core', 'lh_sessions');
        $cfg->set('opensolr.email', 'operator@example.com');
        $cfg->set('opensolr.api_key', 'not-a-real-key');
        $cfg->save();

        $status = lh_inst_request($root, ['setup' => 'status']);
        lh_contains($status['out'], 'Prove you have access to this server', 'the gate is shown first');

        $tokenFile = $root . '/var/' . Token::FILENAME;
        lh_true(is_file($tokenFile), 'visiting the page mints a token');
        $token = trim((string) file_get_contents($tokenFile));

        lh_inst_request($root, [], ['step' => 'status', 'action' => 'unlock', 'token' => $token], 'POST');

        Detector::runSync(Config::load($root . '/config/loghound.php'));

        lh_inst_request(
            $root,
            [],
            ['step' => 'sources', 'action' => 'confirm', 'pick' => ['0']],
            'POST',
            true
        );
        lh_same(1, count((array) lh_inst_stored($root)['sources']), 'the log source is stored');

        lh_inst_request(
            $root,
            [],
            [
                'step'      => 'admin',
                'action'    => 'finish',
                'user'      => 'operator',
                'password'  => 'a-long-enough-password',
                'password2' => 'a-long-enough-password',
                'base_url'  => 'https://loghound.example.com',
            ],
            'POST',
            true
        );

        $final = Config::load($root . '/config/loghound.php');
        lh_same([], $final->validate(), 'the finished configuration must be valid');
        lh_false(Installer::isNeeded($final), 'and the installer must now be unreachable');
        lh_false(is_file($tokenFile), 'the setup token must be destroyed on completion');
        lh_true(
            password_verify('a-long-enough-password', (string) $final->get('auth.password_hash')),
            'the chosen password must work'
        );
        lh_true(
            strlen((string) $final->get('beacon.secret')) >= 32,
            'finishing generates the beacon signing key, which the retired privacy step used to'
        );
        lh_true(
            strlen((string) $final->get('privacy.ip_salt')) >= 16,
            'and the address salt, so switching to hash mode in Settings later is a setting '
            . 'change rather than one that needs a secret nobody generated'
        );
        lh_same(
            'full',
            $final->get('privacy.ip_mode'),
            'an install that was never asked keeps the full address'
        );
        lh_same(90, $final->get('privacy.retention_days'), 'and the 90-day window');
        lh_rmtree($root);
    },

    'finishing is refused while something earlier is still missing' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        $cfg->save();

        lh_inst_request(
            $root,
            [],
            [
                'step'      => 'admin',
                'action'    => 'finish',
                'user'      => 'operator',
                'password'  => 'a-long-enough-password',
                'password2' => 'a-long-enough-password',
            ],
            'POST',
            true
        );

        $after = Config::load($root . '/config/loghound.php');
        lh_same('', (string) $after->get('auth.password_hash'), 'no credentials may be written over a broken config');
        lh_true(Installer::isNeeded($after), 'and the installer must stay reachable');
        lh_rmtree($root);
    },
];
