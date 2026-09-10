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
 * enough that nothing in the suite can accidentally talk to a real server.
 */
function lh_inst_valid_config(string $root): Config
{
    $cfg = Config::load($root . '/config/loghound.php');
    $cfg->set('solr.mode', 'custom');
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
 * @param array<string,mixed> $get
 * @param array<string,mixed> $post
 * @return array{out:string,code:int}
 */
function lh_inst_request(
    string $root,
    array $get = [],
    array $post = [],
    string $method = 'GET',
    bool $unlocked = false,
    bool $withCsrf = true
): array {
    $runner = $root . '/runner.php';
    $repo = lh_inst_root();

    $script = <<<'PHP'
<?php
declare(strict_types=1);
require getenv('LH_REPO') . '/src/autoload.php';

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
    $_SESSION['lh_setup_unlocked'] = true;
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
        'LH_REPO'     => $repo,
        'LH_ROOT'     => $root,
        'LH_GET'      => (string) json_encode($get),
        'LH_POST'     => (string) json_encode($post),
        'LH_METHOD'   => $method,
        'LH_UNLOCKED' => $unlocked ? '1' : '0',
        'PATH'        => (string) getenv('PATH'),
    ];

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

        // Even the correct token is refused once the budget is spent: failing closed is
        // the whole point, and the operator waits or restarts the pool.
        lh_true(
            str_contains($token->verify($real, '203.0.113.9'), 'Too many attempts'),
            'the limiter must not have an exemption for a correct guess'
        );
        lh_rmtree($root);
    },

    'a locked installer refuses to write anything' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        $cfg->save();

        $res = lh_inst_request(
            $root,
            [],
            ['step' => 'privacy', 'action' => 'save', 'ip_mode' => 'hash', 'retention_days' => '7'],
            'POST',
            false
        );

        $stored = lh_inst_stored($root);
        lh_same('full', $stored['privacy']['ip_mode'], 'a locked installer must not have written the change');
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
            ['step' => 'privacy', 'action' => 'save', 'ip_mode' => 'hash', 'retention_days' => '7'],
            'POST',
            true,
            false
        );

        lh_contains($res['out'], 'CSRF', 'the refusal should say so');

        $stored = lh_inst_stored($root);
        lh_same('full', $stored['privacy']['ip_mode'], 'nothing may be written without a CSRF token');
        lh_rmtree($root);
    },

    'an unlocked POST with a CSRF token does write' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        $cfg->save();

        lh_inst_request(
            $root,
            [],
            ['step' => 'privacy', 'action' => 'save', 'ip_mode' => 'truncate', 'retention_days' => '45'],
            'POST',
            true
        );

        $stored = lh_inst_stored($root);
        lh_same('truncate', $stored['privacy']['ip_mode'], 'the privacy answer should be stored');
        lh_same(45, $stored['privacy']['retention_days'], 'the retention answer should be stored');
        lh_true(strlen((string) $stored['beacon']['secret']) >= 32, 'secrets are generated by this step');
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

    'a hostile pattern is refused before it is stored' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();

        $evil = Detector::manualSource($cfg, $root . '/logs/access.log', 'custom', '/^(a+)+$/');
        lh_false($evil['ok'], 'a catastrophically backtracking pattern must be refused');

        $broken = Detector::manualSource($cfg, $root . '/logs/access.log', 'custom', 'not-a-regex');
        lh_false($broken['ok'], 'a pattern that is not even delimited must be refused');

        $unclosed = Detector::manualSource($cfg, $root . '/logs/access.log', 'custom', '/^(?<ip>\S+/');
        lh_false($unclosed['ok'], 'a pattern that does not compile must be refused');
        lh_rmtree($root);
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

    'own-Solr details are validated' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();

        lh_true(Storage::saveCustom($cfg, 'javascript:alert(1)', '', '', 'a', 'b') !== [], 'only http(s)');
        lh_true(Storage::saveCustom($cfg, 'http://127.0.0.1:1/solr', '', '', 'a b', 'c') !== [], 'core name charset');
        lh_true(Storage::saveCustom($cfg, 'http://127.0.0.1:1/solr', '', '', 'same', 'same') !== [], 'cores must differ');

        lh_same(
            [],
            Storage::saveCustom($cfg, 'http://127.0.0.1:1/solr/', '', '', 'lh_hits', 'lh_sessions'),
            'a sane set of details is accepted'
        );
        lh_same('http://127.0.0.1:1/solr', $cfg->get('solr.base_url'), 'the trailing slash is normalised away');
        lh_rmtree($root);
    },

    'an empty password keeps the stored one' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
        Storage::saveCustom($cfg, 'http://127.0.0.1:1/solr', 'u', 'secret-pw', 'lh_hits', 'lh_sessions');
        Storage::saveCustom($cfg, 'http://127.0.0.1:1/solr', 'u', '', 'lh_hits', 'lh_sessions');
        lh_same('secret-pw', $cfg->get('solr.http_pass'), 're-saving the form must not blank the password');
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

    'the browser path and the CLI path produce an equivalent configuration' => static function (): void {
        [$cliRoot] = lh_inst_scaffold();
        [$webRoot, $webCfg] = lh_inst_scaffold();

        $answers = [
            'base_url'  => 'http://127.0.0.1:1/solr',
            'hits'      => 'lh_hits',
            'sessions'  => 'lh_sessions',
            'ip_mode'   => 'truncate',
            'retention' => '45',
            'user'      => 'operator',
            'password'  => 'a-long-enough-password',
            'panel_url' => 'https://loghound.example.com',
        ];

        $env = [
            'LOGHOUND_NONINTERACTIVE'   => '1',
            'LOGHOUND_SOLR_CHOICE'      => '2',
            'LOGHOUND_SOLR_BASE_URL'    => $answers['base_url'],
            'LOGHOUND_SOLR_HTTP_AUTH'   => 'no',
            'LOGHOUND_HITS_CORE'        => $answers['hits'],
            'LOGHOUND_SESSIONS_CORE'    => $answers['sessions'],
            'LOGHOUND_IP_MODE'          => $answers['ip_mode'],
            'LOGHOUND_RETENTION_DAYS'   => $answers['retention'],
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

        Storage::saveCustom($webCfg, $answers['base_url'], '', '', $answers['hits'], $answers['sessions']);
        Steps::applyPrivacy($webCfg, $answers['ip_mode'], $answers['retention']);
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

        lh_true(strlen((string) $cli['beacon']['secret']) >= 32, 'the CLI generates a beacon secret');
        lh_true(strlen((string) $web['beacon']['secret']) >= 32, 'the browser generates a beacon secret');
        lh_true(password_verify($answers['password'], (string) $cli['auth']['password_hash']), 'CLI hash verifies');
        lh_true(password_verify($answers['password'], (string) $web['auth']['password_hash']), 'web hash verifies');
        lh_same([], Config::load($cliRoot . '/config/loghound.php')->validate(), 'the CLI result is valid');
        lh_same([], Config::load($webRoot . '/config/loghound.php')->validate(), 'the browser result is valid');

        lh_rmtree($cliRoot);
        lh_rmtree($webRoot);
    },

    'progress is read from the configuration, so setup resumes where it stopped' => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();

        lh_same(Installer::STEP_SOURCES, Steps::firstIncomplete($cfg), 'a fresh install starts at the logs');

        $cfg->set('sources', [['path' => $root . '/logs/access.log', 'format' => 'apache_combined']]);
        lh_same(Installer::STEP_STORAGE, Steps::firstIncomplete($cfg), 'then storage');

        $cfg->set('solr.hits_core', 'lh_hits');
        $cfg->set('solr.sessions_core', 'lh_sessions');
        $cfg->set('solr.base_url', 'http://127.0.0.1:1/solr');
        lh_same(Installer::STEP_PRIVACY, Steps::firstIncomplete($cfg), 'then privacy');

        Steps::ensureSecrets($cfg);
        lh_same(Installer::STEP_ADMIN, Steps::firstIncomplete($cfg), 'then the account');
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
            if (preg_match('/index_name=([A-Za-z0-9_]+)/', $calls[1], $m)) {
                $firstName = $m[1];
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

    'a whole install can be completed through the browser, and then the installer is gone'
        => static function (): void {
        [$root, $cfg] = lh_inst_scaffold();
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
                'step'          => 'storage',
                'action'        => 'custom',
                'base_url'      => 'http://127.0.0.1:1/solr',
                'http_user'     => '',
                'http_pass'     => '',
                'hits_core'     => 'lh_hits',
                'sessions_core' => 'lh_sessions',
            ],
            'POST',
            true
        );
        lh_same('lh_hits', lh_inst_stored($root)['solr']['hits_core'], 'the cores are stored');

        lh_inst_request(
            $root,
            [],
            ['step' => 'privacy', 'action' => 'save', 'ip_mode' => 'hash', 'retention_days' => '30'],
            'POST',
            true
        );
        lh_same('hash', lh_inst_stored($root)['privacy']['ip_mode'], 'the privacy answer is stored');

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
        lh_true(strlen((string) $final->get('privacy.ip_salt')) >= 16, 'hash mode needs a salt');
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
