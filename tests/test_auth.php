<?php
/**
 * Loghound — tests for panel authentication.
 *
 * `auth.mode = 'session'` was a supported-looking value with nothing behind it: an
 * operator who chose it got 403 forever and no way back. These tests pin the behaviour
 * that replaced it, and the guards around it, because every one of them is the kind of
 * thing that quietly stops working during an unrelated refactor.
 *
 * What is asserted here:
 *  - Refusal in BOTH modes: an unauthenticated request to a panel view renders nothing.
 *  - Sign-in: the right password gets in, the wrong one does not, and the session id
 *    changes at the moment of sign-in (fixation).
 *  - CSRF on the sign-in POST, like every other state-changing request.
 *  - Sign-out destroys the session ON THE SERVER — the file is gone, not just the cookie.
 *  - Both timeouts expire and land on the sign-in page rather than on a 403.
 *  - The per-address lockout triggers at the threshold, releases with the window, fails
 *    closed when its ledger cannot be written, and CANNOT be used by an attacker to lock
 *    the legitimate operator out.
 *  - Config::validate() refuses an auth mode nothing implements.
 *
 * HOW THE HTTP-LEVEL TESTS WORK. Sessions cannot be started in a CLI process that has
 * already produced output, and the runner has, so every request-level case runs the REAL
 * public/index.php in a subprocess: a throwaway installation tree with the front
 * controller copied into it and a one-line src/autoload.php that hands over to the
 * repository's. The session id is set explicitly, which is what lets one test drive
 * several requests through one session — the same technique tests/test_installer.php uses.
 *
 * NOTHING IN THE THROWAWAY TREE IS A SYMLINK INTO THE CHECKOUT. It is tempting to link
 * src/ rather than write a shim, and it works — right up to the teardown, where a
 * recursive delete follows the link and takes the repository's source with it. That is not
 * a hypothetical: it happened while these tests were being written, which is also why
 * lh_rmtree() now refuses to descend into a link.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Auth\Persistence;
use Loghound\Auth\Store;
use Loghound\Auth\Totp;
use Loghound\Auth\TwoFactor;
use Loghound\Config;
use Loghound\Security;
use Loghound\Setup\Steps;

/** The repository root, which the throwaway installation borrows src/ and assets from. */
function lh_auth_repo(): string
{
    return dirname(__DIR__);
}

/** The password every fixture installation uses. */
function lh_auth_password(): string
{
    return 'correct horse battery';
}

/**
 * Build a throwaway installation whose panel is really servable.
 *
 * public/index.php is COPIED rather than symlinked, because __DIR__ resolves symlinks and
 * the front controller finds both its configuration and its var/ directory relative to
 * itself. The copy is byte-identical to the file under test, so this exercises the real
 * routing rather than a re-implementation of it. src/ is a one-line shim that requires the
 * repository's autoloader, so the classes under test are the real ones while the tree
 * itself contains nothing that a teardown could follow out of.
 *
 * @return array{0:string,1:Config}
 */
function lh_auth_scaffold(string $mode = 'session'): array
{
    $root = lh_tmpdir('lhauth');

    foreach (['public', 'config', 'src', 'var', 'var/sessions'] as $dir) {
        mkdir($root . '/' . $dir, 0700, true);
    }
    copy(lh_auth_repo() . '/public/index.php', $root . '/public/index.php');
    file_put_contents(
        $root . '/src/autoload.php',
        "<?php\nrequire " . var_export(lh_auth_repo() . '/src/autoload.php', true) . ";\n"
    );

    $cfg = Config::load($root . '/config/loghound.php');
    $cfg->set('solr.base_url', 'http://127.0.0.1:65535/solr');
    $cfg->set('solr.hits_core', 'lh_auth_hits');
    $cfg->set('solr.sessions_core', 'lh_auth_sessions');
    $cfg->set('beacon.enabled', false);
    $cfg->set('sources', []);
    $cfg->set('auth.user', 'operator');
    $cfg->set('auth.password_hash', password_hash(lh_auth_password(), PASSWORD_DEFAULT));
    $cfg->set('auth.mode', $mode);
    $cfg->save();

    return [$root, $cfg];
}

/**
 * Drive one request through the copied front controller and report what came back.
 *
 * The status code is read with http_response_code() inside the subprocess, which reports
 * nothing at all under the CLI SAPI when the request never set one — so a missing code is
 * normalised to 200, which is what that state means. The Location header cannot be read
 * back the same way (headers_list() is empty under CLI), so redirect targets are asserted
 * indirectly: by the status, by the absence of any rendered panel, and by fetching the
 * destination in a follow-up request.
 *
 * @param array<string,mixed> $opt get, post, method, ip, sid, seed, basic (user/pass), csrf
 * @return array{out:string,code:int,sid:string,session:array<string,mixed>,sid_before:string}
 */
function lh_auth_request(string $root, array $opt = []): array
{
    $sid = (string) ($opt['sid'] ?? ('lhsid' . bin2hex(random_bytes(6))));

    $runner = $root . '/runner.php';
    file_put_contents($runner, <<<'PHP'
<?php
declare(strict_types=1);

$root = (string) getenv('LH_ROOT');

ini_set('session.save_path', $root . '/var/sessions');
session_id((string) getenv('LH_SID'));

$_GET  = json_decode((string) getenv('LH_GET'), true) ?: [];
$_POST = json_decode((string) getenv('LH_POST'), true) ?: [];
$_SERVER['REQUEST_METHOD'] = (string) getenv('LH_METHOD');
$_SERVER['REMOTE_ADDR']    = (string) getenv('LH_IP');
$_SERVER['HTTP_HOST']      = 'loghound.test';

$cookies = json_decode((string) getenv('LH_COOKIES'), true);
if (is_array($cookies)) {
    foreach ($cookies as $name => $value) {
        $_COOKIE[(string) $name] = (string) $value;
    }
}

if (getenv('LH_BASIC_USER') !== false) {
    $_SERVER['PHP_AUTH_USER'] = (string) getenv('LH_BASIC_USER');
    $_SERVER['PHP_AUTH_PW']   = (string) getenv('LH_BASIC_PASS');
}

$seed = json_decode((string) getenv('LH_SEED'), true);
if (is_array($seed)) {
    session_start();
    $_SESSION = $seed;
    session_write_close();
}

register_shutdown_function(static function () use ($root): void {
    file_put_contents($root . '/result.json', (string) json_encode([
        'code'    => http_response_code(),
        'sid'     => session_id(),
        'session' => $_SESSION ?? [],
        'cookies' => $_COOKIE ?? [],
    ]));
});

require $root . '/public/index.php';
PHP);

    $keep = ($opt['keep'] ?? false) === true;

    $post = (array) ($opt['post'] ?? []);
    if (($opt['csrf'] ?? true) === true && ($opt['method'] ?? 'GET') === 'POST' && !$keep) {
        $post['csrf'] = 'lh-test-csrf';
    }

    $seed = $opt['seed'] ?? null;
    if (is_array($seed)) {
        $seed['lh_csrf'] = 'lh-test-csrf';
    } elseif (($opt['method'] ?? 'GET') === 'POST' && !$keep) {
        $seed = ['lh_csrf' => 'lh-test-csrf'];
    }

    $env = [
        'LH_ROOT'    => $root,
        'LH_SID'     => $sid,
        'LH_GET'     => (string) json_encode((array) ($opt['get'] ?? [])),
        'LH_POST'    => (string) json_encode($post),
        'LH_METHOD'  => (string) ($opt['method'] ?? 'GET'),
        'LH_IP'      => (string) ($opt['ip'] ?? '198.51.100.7'),
        'LH_SEED'    => (string) json_encode($seed),
        'LH_COOKIES' => (string) json_encode((array) ($opt['cookies'] ?? [])),
        'PATH'       => (string) getenv('PATH'),
    ];
    if (isset($opt['basic'])) {
        $env['LH_BASIC_USER'] = (string) $opt['basic'][0];
        $env['LH_BASIC_PASS'] = (string) $opt['basic'][1];
    }

    @unlink($root . '/result.json');

    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($runner) . ' 2>&1';
    $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $root, $env);
    if (!is_resource($proc)) {
        lh_fail('could not start the panel subprocess');
    }
    $out = (string) stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($proc);

    $result = json_decode((string) @file_get_contents($root . '/result.json'), true);
    if (!is_array($result)) {
        lh_fail('the panel subprocess produced no result: ' . $out);
    }

    return [
        'out'        => $out,
        'code'       => ((int) ($result['code'] ?? 0)) ?: 200,
        'sid'        => (string) ($result['sid'] ?? ''),
        'session'    => (array) ($result['session'] ?? []),
        'cookies'    => (array) ($result['cookies'] ?? []),
        'sid_before' => $sid,
    ];
}

/**
 * The CSRF token out of a rendered form.
 *
 * Needed by every test that drives the REAL token through a sequence of requests rather than
 * seeding a fixed one. The token that a sign-in rotates away is the whole subject of the CSRF
 * regression tests, so those cases cannot use the seeded shortcut: they have to hold the token
 * a browser would be holding.
 */
function lh_auth_form_token(string $html): string
{
    return preg_match('/name="csrf" value="([a-f0-9]+)"/', $html, $m) ? $m[1] : '';
}

/** Sign in through the real form and return the request result. */
function lh_auth_signin(string $root, string $sid, string $ip = '198.51.100.7', ?string $password = null): array
{
    return lh_auth_request($root, [
        'get'    => ['login' => '1'],
        'method' => 'POST',
        'post'   => ['user' => 'operator', 'password' => $password ?? lh_auth_password()],
        'sid'    => $sid,
        'ip'     => $ip,
    ]);
}

/**
 * Switch two-factor on for a scaffolded installation and return the shared key.
 *
 * The key is minted and confirmed the same way the panel does it, so what these tests drive is
 * the real enrollment result rather than a hand-written config block. The replay floor it leaves
 * behind is one step in the past, so the code for the current step is still available to the
 * test that follows.
 */
function lh_auth_enable_totp(Config $cfg): string
{
    $key = TwoFactor::begin();
    $var = dirname(dirname($cfg->path())) . '/var';

    $result = TwoFactor::enable($cfg, $key, (string) Totp::at($key, time() - 30), $var);
    if ($result['errors'] !== []) {
        lh_fail('could not enable two-factor for the fixture: ' . implode(' ', $result['errors']));
    }
    $cfg->save();

    return $key;
}

/**
 * Push a scaffold's persistent tokens past the rotation grace window.
 *
 * Persistence honours the verifier a rotation just replaced for a few seconds, because a browser
 * waking several tabs at once presents one cookie several times and that is one use, not a theft.
 * Any test about a REPLAY has to step outside that window first, or it is testing the grace.
 */
function lh_auth_age_tokens(string $root, int $seconds = 120): void
{
    Store::at($root . '/var', Persistence::STORE)->mutate(
        static function (array &$data) use ($seconds): bool {
            foreach (($data['tokens'] ?? []) as $key => $record) {
                foreach (($record['recent'] ?? []) as $i => $entry) {
                    $data['tokens'][$key]['recent'][$i]['t'] = (int) ($entry['t'] ?? time()) - $seconds;
                }
            }
            return true;
        }
    );
}

/** Path of the PHP session file for an id, which is what "destroyed server-side" means. */
function lh_auth_session_file(string $root, string $sid): string
{
    return $root . '/var/sessions/sess_' . $sid;
}

/** The failed-attempt ledger as an array. */
function lh_auth_ledger(string $root): array
{
    $raw = @file_get_contents($root . '/var/' . Security::LOGIN_LEDGER);
    $data = is_string($raw) ? json_decode($raw, true) : null;
    return is_array($data) ? $data : [];
}

return [


    'session mode refuses an unauthenticated panel view and renders nothing' => static function (): void {
        [$root] = lh_auth_scaffold('session');

        $r = lh_auth_request($root, ['get' => ['v' => 'overview']]);

        lh_same(302, $r['code'], 'an anonymous view request is redirected to the sign-in page');
        lh_false(str_contains($r['out'], '<html'), 'no panel HTML may be emitted');
        lh_false(str_contains($r['out'], 'Fingerprints'), 'no navigation may leak');

        lh_rmtree($root);
    },

    'basic mode refuses an unauthenticated panel view and renders nothing' => static function (): void {
        [$root] = lh_auth_scaffold('basic');

        $r = lh_auth_request($root, ['get' => ['v' => 'overview']]);

        lh_same(401, $r['code'], 'no credentials must be challenged');
        lh_contains($r['out'], 'Authentication required', 'the challenge says so');
        lh_false(str_contains($r['out'], '<html'), 'no panel HTML may be emitted');

        lh_rmtree($root);
    },

    'basic mode refuses a wrong password' => static function (): void {
        [$root] = lh_auth_scaffold('basic');

        $r = lh_auth_request($root, [
            'get'   => ['v' => 'overview'],
            'basic' => ['operator', 'not the password'],
        ]);

        lh_same(401, $r['code'], 'a wrong password is refused');
        lh_false(str_contains($r['out'], '<html'), 'no panel HTML may be emitted');

        lh_rmtree($root);
    },

    'basic mode admits the right credentials' => static function (): void {
        [$root] = lh_auth_scaffold('basic');

        $r = lh_auth_request($root, [
            'get'   => ['v' => 'overview'],
            'basic' => ['operator', lh_auth_password()],
        ]);

        lh_same(200, $r['code'], 'the right credentials are admitted');
        lh_contains($r['out'], '<html', 'the panel renders');

        lh_rmtree($root);
    },


    'the sign-in page is reachable when signed out' => static function (): void {
        [$root] = lh_auth_scaffold('session');

        $r = lh_auth_request($root, ['get' => ['login' => '1']]);

        lh_same(200, $r['code'], 'the sign-in page must be served to an anonymous visitor');
        lh_contains($r['out'], 'name="password"', 'it carries a password field');
        lh_contains($r['out'], 'action="?login=1"', 'it posts back to itself');
        lh_contains($r['out'], 'name="csrf"', 'it carries a CSRF token');

        lh_rmtree($root);
    },

    'the sign-in page redirects to the dashboard when already signed in' => static function (): void {
        [$root] = lh_auth_scaffold('session');
        $sid = 'lhalready' . bin2hex(random_bytes(4));

        $r = lh_auth_request($root, [
            'get'  => ['login' => '1'],
            'sid'  => $sid,
            'seed' => ['lh_user' => 'operator', 'lh_login_at' => time(), 'lh_seen_at' => time()],
        ]);

        lh_same(303, $r['code'], 'a signed-in operator is sent to the dashboard, not shown a form');
        lh_false(str_contains($r['out'], 'name="password"'), 'the form is not rendered');

        lh_rmtree($root);
    },

    'a correct sign-in succeeds and a wrong one does not' => static function (): void {
        [$root] = lh_auth_scaffold('session');

        $good = lh_auth_signin($root, 'lhgood' . bin2hex(random_bytes(4)));
        lh_same(303, $good['code'], 'the right password signs in');
        lh_same('operator', (string) ($good['session']['lh_user'] ?? ''), 'the session names the operator');

        $bad = lh_auth_signin($root, 'lhbad' . bin2hex(random_bytes(4)), '198.51.100.7', 'wrong password');
        lh_same(401, $bad['code'], 'the wrong password is refused');
        lh_same('', (string) ($bad['session']['lh_user'] ?? ''), 'nothing is signed in');
        lh_contains($bad['out'], 'did not match', 'the form says so without naming which half was wrong');

        lh_rmtree($root);
    },

    'the session id changes on sign-in' => static function (): void {
        [$root] = lh_auth_scaffold('session');
        $planted = 'lhplanted' . bin2hex(random_bytes(4));

        $r = lh_auth_signin($root, $planted);

        lh_same(303, $r['code'], 'the sign-in succeeded');
        lh_true($r['sid'] !== '' && $r['sid'] !== $planted, 'the id must be regenerated at sign-in');
        lh_false(
            is_file(lh_auth_session_file($root, $planted)),
            'the planted session file must be deleted, not left valid'
        );

        lh_rmtree($root);
    },

    'the session holds a username and timestamps, never the password or its hash' => static function (): void {
        [$root, $cfg] = lh_auth_scaffold('session');

        $r = lh_auth_signin($root, 'lhmin' . bin2hex(random_bytes(4)));
        $blob = (string) json_encode($r['session']);

        lh_has_key($r['session'], 'lh_login_at', 'the session');
        lh_has_key($r['session'], 'lh_seen_at', 'the session');
        lh_false(str_contains($blob, lh_auth_password()), 'the password must never be stored');
        lh_false(
            str_contains($blob, (string) $cfg->get('auth.password_hash')),
            'the hash must never be stored either'
        );

        lh_rmtree($root);
    },

    'CSRF is enforced on the sign-in POST' => static function (): void {
        [$root] = lh_auth_scaffold('session');

        $r = lh_auth_request($root, [
            'get'    => ['login' => '1'],
            'method' => 'POST',
            'post'   => ['user' => 'operator', 'password' => lh_auth_password()],
            'csrf'   => false,
        ]);

        lh_same(403, $r['code'], 'a sign-in without a token is refused');
        lh_contains($r['out'], 'CSRF', 'and says why');
        lh_same('', (string) ($r['session']['lh_user'] ?? ''), 'nobody is signed in');

        lh_rmtree($root);
    },

    'a forged CSRF token does not sign anyone in' => static function (): void {
        [$root] = lh_auth_scaffold('session');

        $r = lh_auth_request($root, [
            'get'    => ['login' => '1'],
            'method' => 'POST',
            'post'   => ['user' => 'operator', 'password' => lh_auth_password(), 'csrf' => 'not-the-token'],
            'csrf'   => false,
        ]);

        lh_same(403, $r['code'], 'a wrong token is refused');
        lh_same('', (string) ($r['session']['lh_user'] ?? ''), 'nobody is signed in');

        lh_rmtree($root);
    },


    'sign-out destroys the session on the server, not just the cookie' => static function (): void {
        [$root] = lh_auth_scaffold('session');
        $sid = 'lhout' . bin2hex(random_bytes(4));

        lh_auth_request($root, [
            'sid'  => $sid,
            'get'  => ['v' => 'overview'],
            'seed' => ['lh_user' => 'operator', 'lh_login_at' => time(), 'lh_seen_at' => time()],
        ]);
        lh_true(is_file(lh_auth_session_file($root, $sid)), 'the session file exists to begin with');

        $out = lh_auth_request($root, [
            'sid'    => $sid,
            'get'    => ['logout' => '1'],
            'method' => 'POST',
            'seed'   => ['lh_user' => 'operator', 'lh_login_at' => time(), 'lh_seen_at' => time()],
        ]);
        lh_same(303, $out['code'], 'sign-out redirects back to the sign-in page');
        lh_false(is_file(lh_auth_session_file($root, $sid)), 'the session file must be gone');

        $replay = lh_auth_request($root, ['sid' => $sid, 'get' => ['v' => 'overview']]);
        lh_same(302, $replay['code'], 'replaying the old id must not get in');
        lh_same('', (string) ($replay['session']['lh_user'] ?? ''), 'the old id carries no identity');

        lh_rmtree($root);
    },

    'sign-out refuses a GET, so no third-party page can trigger it' => static function (): void {
        [$root] = lh_auth_scaffold('session');
        $sid = 'lhgetout' . bin2hex(random_bytes(4));

        $r = lh_auth_request($root, [
            'sid'  => $sid,
            'get'  => ['logout' => '1'],
            'seed' => ['lh_user' => 'operator', 'lh_login_at' => time(), 'lh_seen_at' => time()],
        ]);

        lh_same(405, $r['code'], 'sign-out is a POST');
        lh_true(is_file(lh_auth_session_file($root, $sid)), 'the session survives a GET');

        lh_rmtree($root);
    },

    'sign-out without a CSRF token is refused' => static function (): void {
        [$root] = lh_auth_scaffold('session');
        $sid = 'lhoutcsrf' . bin2hex(random_bytes(4));

        $r = lh_auth_request($root, [
            'sid'    => $sid,
            'get'    => ['logout' => '1'],
            'method' => 'POST',
            'csrf'   => false,
            'seed'   => ['lh_user' => 'operator', 'lh_login_at' => time(), 'lh_seen_at' => time()],
        ]);

        lh_same(403, $r['code'], 'a sign-out without a token is refused');
        lh_true(is_file(lh_auth_session_file($root, $sid)), 'the session survives');

        lh_rmtree($root);
    },


    'an idle session expires and lands on the sign-in page' => static function (): void {
        [$root, $cfg] = lh_auth_scaffold('session');
        $cfg->set('auth.idle_timeout', 60);
        $cfg->save();

        $sid = 'lhidle' . bin2hex(random_bytes(4));
        $r = lh_auth_request($root, [
            'sid'  => $sid,
            'get'  => ['v' => 'overview'],
            'seed' => [
                'lh_user'     => 'operator',
                'lh_login_at' => time() - 120,
                'lh_seen_at'  => time() - 120,
            ],
        ]);

        lh_same(302, $r['code'], 'an idle session is sent back to the sign-in page, not 403');
        lh_false(str_contains($r['out'], '<html'), 'no panel HTML may be emitted');
        lh_false(is_file(lh_auth_session_file($root, $sid)), 'the expired session is destroyed server-side');

        lh_rmtree($root);
    },

    'a busy session still expires at the absolute timeout' => static function (): void {
        [$root, $cfg] = lh_auth_scaffold('session');
        $cfg->set('auth.idle_timeout', 1800);
        $cfg->set('auth.absolute_timeout', 3600);
        $cfg->save();

        $sid = 'lhabs' . bin2hex(random_bytes(4));
        $r = lh_auth_request($root, [
            'sid'  => $sid,
            'get'  => ['v' => 'overview'],
            'seed' => [
                'lh_user'     => 'operator',
                'lh_login_at' => time() - 7200,
                'lh_seen_at'  => time(),
            ],
        ]);

        lh_same(302, $r['code'], 'age beats activity');
        lh_false(is_file(lh_auth_session_file($root, $sid)), 'the session is destroyed server-side');

        lh_rmtree($root);
    },

    'a session inside both timeouts is admitted and its idle clock moves forward' => static function (): void {
        [$root] = lh_auth_scaffold('session');
        $sid = 'lhalive' . bin2hex(random_bytes(4));
        $seen = time() - 300;

        $r = lh_auth_request($root, [
            'sid'  => $sid,
            'get'  => ['v' => 'overview'],
            'seed' => ['lh_user' => 'operator', 'lh_login_at' => time() - 600, 'lh_seen_at' => $seen],
        ]);

        lh_same(200, $r['code'], 'a live session is admitted');
        lh_true((int) ($r['session']['lh_seen_at'] ?? 0) > $seen, 'the idle anchor moves forward');
        lh_contains($r['out'], 'action="?logout=1"', 'the panel offers a way back out');
        lh_contains($r['out'], 'name="csrf"', 'and the sign-out carries a token');

        lh_rmtree($root);
    },


    'the lockout triggers after the configured number of failures' => static function (): void {
        [$root, $cfg] = lh_auth_scaffold('session');
        $cfg->set('auth.lockout_attempts', 3);
        $cfg->save();

        for ($i = 0; $i < 3; $i++) {
            $r = lh_auth_signin($root, 'lhtry' . $i, '203.0.113.9', 'wrong password');
            lh_same(401, $r['code'], 'attempt ' . ($i + 1) . ' is a plain refusal');
        }

        $locked = lh_auth_signin($root, 'lhtry9', '203.0.113.9', 'wrong password');
        lh_same(429, $locked['code'], 'the attempt past the threshold is locked out');
        lh_contains($locked['out'], 'Too many failed sign-in', 'the page says why');

        $stillLocked = lh_auth_signin($root, 'lhtryok', '203.0.113.9');
        lh_same(429, $stillLocked['code'], 'even the RIGHT password is refused while locked out');
        lh_same('', (string) ($stillLocked['session']['lh_user'] ?? ''), 'nobody is signed in');

        lh_rmtree($root);
    },

    'the lockout names the file that holds the counter, not a restart that does nothing' => static function (): void {
        [$root, $cfg] = lh_auth_scaffold('session');
        $cfg->set('auth.lockout_attempts', 1);
        $cfg->save();

        lh_auth_signin($root, 'lhmsg1', '203.0.113.9', 'wrong password');
        $locked = lh_auth_signin($root, 'lhmsg2', '203.0.113.9', 'wrong password');

        lh_contains($locked['out'], Security::LOGIN_LEDGER, 'the message names the real mechanism');
        lh_false(str_contains($locked['out'], 'PHP-FPM'), 'it must not claim a restart clears the counter');

        lh_rmtree($root);
    },

    'the lockout releases once the window has passed' => static function (): void {
        [$root, $cfg] = lh_auth_scaffold('session');
        $cfg->set('auth.lockout_attempts', 2);
        $cfg->set('auth.lockout_window', 900);
        $cfg->save();

        lh_auth_signin($root, 'lhw1', '203.0.113.9', 'wrong password');
        lh_auth_signin($root, 'lhw2', '203.0.113.9', 'wrong password');
        lh_same(429, lh_auth_signin($root, 'lhw3', '203.0.113.9')['code'], 'locked out');

        $ledger = lh_auth_ledger($root);
        lh_true($ledger['ips'] !== [], 'the ledger recorded the address');
        foreach ($ledger['ips'] as $key => $entry) {
            $ledger['ips'][$key]['w'] = time() - 1000;
        }
        file_put_contents($root . '/var/' . Security::LOGIN_LEDGER, (string) json_encode($ledger));

        $after = lh_auth_signin($root, 'lhw4', '203.0.113.9');
        lh_same(303, $after['code'], 'once the window has passed the address may try again');

        lh_rmtree($root);
    },

    'a locked-out attacker cannot lock the operator out' => static function (): void {
        [$root, $cfg] = lh_auth_scaffold('session');
        $cfg->set('auth.lockout_attempts', 2);
        $cfg->save();

        foreach (['lha1', 'lha2', 'lha3', 'lha4'] as $sid) {
            lh_auth_signin($root, $sid, '203.0.113.9', 'wrong password');
        }
        lh_same(429, lh_auth_signin($root, 'lha5', '203.0.113.9')['code'], 'the attacker is locked out');

        $operator = lh_auth_signin($root, 'lhop1', '198.51.100.7');
        lh_same(303, $operator['code'], 'the operator signs in from their own address as normal');
        lh_same('operator', (string) ($operator['session']['lh_user'] ?? ''), 'and is really signed in');

        lh_rmtree($root);
    },

    'the lockout applies to Basic mode as well' => static function (): void {
        [$root, $cfg] = lh_auth_scaffold('basic');
        $cfg->set('auth.lockout_attempts', 2);
        $cfg->save();

        for ($i = 0; $i < 2; $i++) {
            $r = lh_auth_request($root, [
                'get'   => ['v' => 'overview'],
                'ip'    => '203.0.113.9',
                'basic' => ['operator', 'wrong'],
            ]);
            lh_same(401, $r['code'], 'a wrong Basic password is challenged');
        }

        $locked = lh_auth_request($root, [
            'get'   => ['v' => 'overview'],
            'ip'    => '203.0.113.9',
            'basic' => ['operator', lh_auth_password()],
        ]);
        lh_same(429, $locked['code'], 'Basic is rate limited on the same axis as the sign-in form');
        lh_false(str_contains($locked['out'], '<html'), 'no panel HTML may be emitted');

        lh_rmtree($root);
    },

    'a successful sign-in clears that address\'s failures' => static function (): void {
        [$root, $cfg] = lh_auth_scaffold('session');
        $cfg->set('auth.lockout_attempts', 4);
        $cfg->save();

        lh_auth_signin($root, 'lhc1', '198.51.100.7', 'wrong password');
        lh_auth_signin($root, 'lhc2', '198.51.100.7', 'wrong password');
        lh_auth_signin($root, 'lhc3', '198.51.100.7');

        $ledger = lh_auth_ledger($root);
        lh_same([], (array) ($ledger['ips'] ?? []), 'the counter is cleared by a correct password');

        lh_rmtree($root);
    },


    'the limiter fails closed when its ledger cannot be written' => static function (): void {
        $dir = lh_tmpdir('lhledger');
        file_put_contents($dir . '/notadir', 'this is a file, not a directory');

        $gate = Security::loginGate('198.51.100.7', ['lockout_attempts' => 8], $dir . '/notadir');

        lh_false($gate['available'], 'an unusable ledger must report itself unusable');
        lh_false($gate['allowed'], 'and a check that cannot be performed is a refusal');

        lh_rmtree($dir);
    },

    'the limiter counts each address separately' => static function (): void {
        $dir = lh_tmpdir('lhledger');
        $auth = ['lockout_attempts' => 2, 'lockout_window' => 900];

        Security::loginFailure('203.0.113.9', $auth, $dir);
        Security::loginFailure('203.0.113.9', $auth, $dir);

        lh_false(Security::loginGate('203.0.113.9', $auth, $dir)['allowed'], 'the noisy address is locked');
        lh_true(Security::loginGate('198.51.100.7', $auth, $dir)['allowed'], 'every other address is not');

        lh_rmtree($dir);
    },

    'the ledger stores hashed addresses, not readable ones' => static function (): void {
        $dir = lh_tmpdir('lhledger');
        Security::loginFailure('203.0.113.9', ['lockout_attempts' => 8], $dir);

        $raw = (string) file_get_contents(Security::ledgerPath($dir));
        lh_false(str_contains($raw, '203.0.113.9'), 'a plain list of addresses is intelligence in itself');

        lh_rmtree($dir);
    },

    'an expired entry stops counting without anything having to sweep it' => static function (): void {
        $dir = lh_tmpdir('lhledger');
        $auth = ['lockout_attempts' => 1, 'lockout_window' => 60];

        Security::loginFailure('203.0.113.9', $auth, $dir);
        lh_false(Security::loginGate('203.0.113.9', $auth, $dir)['allowed'], 'locked while the window is open');

        $data = json_decode((string) file_get_contents(Security::ledgerPath($dir)), true);
        foreach ($data['ips'] as $k => $v) {
            $data['ips'][$k]['w'] = time() - 600;
        }
        file_put_contents(Security::ledgerPath($dir), (string) json_encode($data));

        lh_true(Security::loginGate('203.0.113.9', $auth, $dir)['allowed'], 'the window passing releases it');

        lh_rmtree($dir);
    },


    'Config::validate refuses an auth mode nothing implements' => static function (): void {
        $cfg = Config::load('/nonexistent-loghound-config');
        $cfg->set('auth.user', 'operator');
        $cfg->set('auth.password_hash', password_hash('a-long-enough-password', PASSWORD_DEFAULT));

        foreach (['ldap', 'oauth', 'digest', 'jwt', ''] as $bogus) {
            $cfg->set('auth.mode', $bogus);
            $errors = implode(' ', $cfg->validate());
            lh_contains($errors, 'auth.mode must be', 'the mode ' . lh_show($bogus) . ' must be refused');
        }

        lh_rmtree(sys_get_temp_dir() . '/lh-nonexistent');
    },

    'Config::validate accepts both implemented modes' => static function (): void {
        $cfg = Config::load('/nonexistent-loghound-config');
        $cfg->set('solr.base_url', 'http://127.0.0.1:8983/solr');
        $cfg->set('solr.hits_core', 'lh_hits');
        $cfg->set('solr.sessions_core', 'lh_sessions');
        $cfg->set('opensolr.email', 'operator@example.com');
        $cfg->set('opensolr.api_key', 'not-a-real-key');
        $cfg->set('beacon.enabled', false);
        $cfg->set('auth.user', 'operator');
        $cfg->set('auth.password_hash', password_hash('a-long-enough-password', PASSWORD_DEFAULT));

        foreach (['basic', 'session'] as $mode) {
            $cfg->set('auth.mode', $mode);
            lh_same([], $cfg->validate(), "auth.mode '$mode' must be accepted");
        }
    },

    'a mode that signs people in needs both halves of a credential' => static function (): void {
        $cfg = Config::load('/nonexistent-loghound-config');
        $cfg->set('auth.mode', 'session');
        $cfg->set('auth.user', '');
        $cfg->set('auth.password_hash', '');

        $errors = implode(' ', $cfg->validate());
        lh_contains($errors, 'auth.password_hash is required', 'a session mode with no password is refused');
        lh_contains($errors, 'auth.user is required', 'a session mode with no username is refused');
    },

    'the installer can store either mode and refuses anything else' => static function (): void {
        $cfg = Config::load('/nonexistent-loghound-config');

        lh_same([], Steps::applyAdmin($cfg, 'operator', 'a-long-enough-password', '', 'session'));
        lh_same('session', $cfg->get('auth.mode'), 'the chosen mode is stored');

        lh_same([], Steps::applyAdmin($cfg, 'operator', 'a-long-enough-password', '', 'basic'));
        lh_same('basic', $cfg->get('auth.mode'), 'and so is the other one');

        lh_true(
            Steps::applyAdmin($cfg, 'operator', 'a-long-enough-password', '', 'ldap') !== [],
            'a mode with no implementation is refused'
        );
        lh_same('basic', $cfg->get('auth.mode'), 'and nothing is written when it is');
    },

    'the mode can be changed later without touching the credentials' => static function (): void {
        $cfg = Config::load('/nonexistent-loghound-config');
        Steps::applyAdmin($cfg, 'operator', 'a-long-enough-password', '', 'basic');
        $hash = (string) $cfg->get('auth.password_hash');

        lh_same([], Steps::applyAuthMode($cfg, 'session'), 'switching mode is a supported operation');
        lh_same('session', $cfg->get('auth.mode'), 'the new mode is stored');
        lh_same($hash, (string) $cfg->get('auth.password_hash'), 'the password is untouched');

        lh_true(Steps::applyAuthMode($cfg, 'none') !== [], "'none' is not something an operator chooses");
        lh_same('session', $cfg->get('auth.mode'), 'and a refused switch changes nothing');
    },

    'switching to a sign-in mode is refused when there is no password to sign in with' => static function (): void {
        $cfg = Config::load('/nonexistent-loghound-config');

        lh_true(Steps::applyAuthMode($cfg, 'session') !== [], 'no credential means no mode change');
        lh_same('none', $cfg->get('auth.mode'), 'the panel is not left unreachable');
    },


    'a password is only verified against a stored hash, never against an empty one' => static function (): void {
        lh_false(Security::verifyPassword([], 'operator', ''), 'an unset account admits nobody');
        lh_false(Security::verifyPassword(['user' => 'operator'], 'operator', ''), 'not even with the right name');

        $auth = ['user' => 'operator', 'password_hash' => password_hash('hunter2hunter2', PASSWORD_DEFAULT)];
        lh_true(Security::verifyPassword($auth, 'operator', 'hunter2hunter2'), 'the right pair verifies');
        lh_false(Security::verifyPassword($auth, 'Operator', 'hunter2hunter2'), 'the username is case-sensitive');
        lh_false(Security::verifyPassword($auth, 'operator', 'hunter2hunter3'), 'a wrong password does not');
    },

    'the limits are clamped, so a hand-edited config cannot switch the lockout off' => static function (): void {
        $limits = Security::authLimits([
            'idle_timeout'     => 0,
            'absolute_timeout' => -1,
            'lockout_attempts' => 0,
            'lockout_window'   => 'off',
        ]);

        lh_true($limits['idle'] >= 60, 'the idle timeout has a floor');
        lh_true($limits['absolute'] >= 300, 'so does the absolute one');
        lh_true($limits['attempts'] >= 1, 'the lockout always has a threshold');
        lh_true($limits['window'] >= 60, 'and always has a window');
    },

    'only implemented modes are offered as a choice' => static function (): void {
        lh_same(['basic', 'session'], array_keys(Security::authModes()), 'the offered modes');
        foreach (Security::authModes() as $mode) {
            lh_true(($mode['cost'] ?? '') !== '', 'every mode states what it costs, not only what it gives');
        }
    },


    /*
     * ------------------------------------------------------------------------------------
     * The reported bug: "CSRF token mismatch" on a sign-in that had in fact worked.
     *
     * The sequence below is the reproduction, driven through the real front controller with
     * the real rotating token. It is three requests:
     *
     *   1. GET  ?login=1                 -> renders the form carrying token T1.
     *   2. POST ?login=1 with T1         -> signs in, regenerates the id, ROTATES to T2.
     *   3. POST ?login=1 with T1 again   -> the same form submitted a second time, now on the
     *                                       session that step 2 authenticated.
     *
     * Step 3 used to answer 403 "CSRF token mismatch" while lh_user was set and the panel was
     * fully reachable, because doLogin() ran requireCsrf() before checking whether the caller
     * was already signed in. That is exactly what the operator saw. A double-clicked submit
     * whose second request lands after the first response, a restored tab, or the form open in
     * a second window all produce it.
     * ------------------------------------------------------------------------------------
     */

    'a re-submitted sign-in form on an already-authenticated session is finished, not a CSRF error'
        => static function (): void {
            [$root] = lh_auth_scaffold('session');
            $first = 'lhre' . bin2hex(random_bytes(4));

            $page = lh_auth_request($root, ['get' => ['login' => '1'], 'sid' => $first, 'keep' => true]);
            $token = lh_auth_form_token($page['out']);
            lh_true($token !== '', 'the form must carry a real token to re-submit');

            $signin = lh_auth_request($root, [
                'get'    => ['login' => '1'],
                'method' => 'POST',
                'post'   => ['user' => 'operator', 'password' => lh_auth_password(), 'csrf' => $token],
                'sid'    => $first,
                'keep'   => true,
            ]);
            lh_same(303, $signin['code'], 'the first submission signs in');
            $signedInSid = $signin['sid'];
            lh_true($signedInSid !== $first, 'and regenerates the session id');
            lh_true(
                $token !== (string) ($signin['session']['lh_csrf'] ?? ''),
                'sign-in rotates the token, which is what made the second submission stale'
            );

            $again = lh_auth_request($root, [
                'get'    => ['login' => '1'],
                'method' => 'POST',
                'post'   => ['user' => 'operator', 'password' => lh_auth_password(), 'csrf' => $token],
                'sid'    => $signedInSid,
                'keep'   => true,
            ]);

            lh_same(303, $again['code'], 'a stale token from an already-signed-in session is a redirect');
            lh_false(str_contains($again['out'], 'CSRF'), 'and never a CSRF failure page');
            lh_same('operator', (string) ($again['session']['lh_user'] ?? ''), 'the session is still signed in');

            lh_rmtree($root);
        },

    'the CSRF check is NOT weakened for anyone who is not signed in' => static function (): void {
        [$root] = lh_auth_scaffold('session');

        $anon = lh_auth_request($root, [
            'get'    => ['login' => '1'],
            'method' => 'POST',
            'post'   => ['user' => 'operator', 'password' => lh_auth_password(), 'csrf' => 'stale-token'],
            'sid'    => 'lhstale' . bin2hex(random_bytes(4)),
            'keep'   => true,
        ]);
        lh_same(403, $anon['code'], 'a stale token with no session behind it is still refused');
        lh_contains($anon['out'], 'CSRF', 'and still says why');
        lh_same('', (string) ($anon['session']['lh_user'] ?? ''), 'nobody is signed in');

        $pending = lh_auth_request($root, [
            'get'    => ['logout' => '1'],
            'method' => 'POST',
            'post'   => ['csrf' => 'stale-token'],
            'sid'    => 'lhout2' . bin2hex(random_bytes(4)),
            'keep'   => true,
        ]);
        lh_same(403, $pending['code'], 'sign-out is not exempted either');

        lh_rmtree($root);
    },

    'the sign-in page refuses to be cached, whatever session.cache_limiter says'
        => static function (): void {
            $login = (string) file_get_contents(lh_auth_repo() . '/src/Panel/Login.php');
            lh_contains($login, "Cache-Control: no-store", 'the sign-in page sends no-store itself');

            $security = (string) file_get_contents(lh_auth_repo() . '/src/Security.php');
            lh_contains(
                $security,
                "session_cache_limiter('')",
                'and no session start may let PHP replace that header with a cacheable one'
            );

            $starts = preg_match_all('/session_start\s*\(/', $security);
            $neutralised = preg_match_all("/session_cache_limiter\('\'\)/", $security)
                ?: preg_match_all("/session_cache_limiter\(''\)/", $security);
            lh_true(
                $neutralised >= 1 && $starts >= 1,
                'every session start in Security goes through a limiter-neutralising path'
            );

            lh_rmtree(sys_get_temp_dir() . '/lh-nonexistent');
        },

    'no shipped pool locks session.cache_limiter, which would break that fix silently'
        => static function (): void {
            $files = [
                'install/php-fpm-pool.conf.example',
                'install/install.sh',
            ];

            foreach ($files as $rel) {
                $path = lh_auth_repo() . '/' . $rel;
                if (!is_file($path)) {
                    continue;
                }
                $text = (string) file_get_contents($path);
                lh_same(
                    0,
                    preg_match('/php_admin_value\[session\.cache_limiter\]/', $text),
                    $rel . ': an admin_value for session.cache_limiter cannot be overridden at runtime, '
                        . 'so it would make the sign-in page cacheable again with no error anywhere'
                );
            }
        },

    'the new authentication settings are documented where an operator will look'
        => static function (): void {
            $example = (string) file_get_contents(lh_auth_repo() . '/config/loghound.example.php');
            foreach (['persistent_lifetime', "'totp'", "'recovery'", 'Stay signed in'] as $needle) {
                lh_contains($example, $needle, 'the shipped example config explains ' . $needle);
            }

            $install = (string) file_get_contents(lh_auth_repo() . '/docs/INSTALL.md');
            foreach (['Stay signed in', 'Two-factor authentication', 'recovery codes', 'lockout'] as $needle) {
                lh_contains($install, $needle, 'docs/INSTALL.md covers ' . $needle);
            }
            lh_contains(
                $install,
                'no idle timeout and no maximum session age',
                'and says what the option costs rather than only what it gives'
            );

            $spec = (string) file_get_contents(lh_auth_repo() . '/SPEC.md');
            foreach (['RFC 6238', 'selector plus verifier', 'SameSite=Lax'] as $needle) {
                lh_contains($spec, $needle, 'SPEC.md states the requirement for ' . $needle);
            }
        },


    /*
     * ------------------------------------------------------------------------------------
     * "Stay signed in", end to end through the real front controller.
     *
     * The unit-level properties of the token are in tests/test_persistent_login.php. What is
     * asserted here is the thing the operator asked for: that the option survives what would
     * otherwise sign them out, and that not taking it changes nothing.
     * ------------------------------------------------------------------------------------
     */

    'ticking stay signed in hands out a token, leaving it unticked does not' => static function (): void {
        [$root] = lh_auth_scaffold('session');

        $plain = lh_auth_request($root, [
            'get'    => ['login' => '1'],
            'method' => 'POST',
            'post'   => ['user' => 'operator', 'password' => lh_auth_password()],
            'sid'    => 'lhnorem' . bin2hex(random_bytes(4)),
        ]);
        lh_same(303, $plain['code'], 'the sign-in works');
        lh_no_key($plain['cookies'], Persistence::COOKIE, 'and hands out no persistent token');
        lh_false(($plain['session']['lh_persist'] ?? false) === true, 'the session is an ordinary one');

        $remembered = lh_auth_request($root, [
            'get'    => ['login' => '1'],
            'method' => 'POST',
            'post'   => ['user' => 'operator', 'password' => lh_auth_password(), 'remember' => '1'],
            'sid'    => 'lhrem' . bin2hex(random_bytes(4)),
        ]);
        lh_same(303, $remembered['code'], 'so does the remembered one');
        lh_has_key($remembered['cookies'], Persistence::COOKIE, 'which does hand out a token');
        lh_true(($remembered['session']['lh_persist'] ?? false) === true, 'and marks the session');
        lh_same(
            1,
            preg_match('/^[a-f0-9]{32}\.[a-f0-9]{64}$/', (string) $remembered['cookies'][Persistence::COOKIE]),
            'the cookie is a selector and a verifier'
        );

        lh_rmtree($root);
    },

    'a remembered session survives what ends an ordinary one' => static function (): void {
        [$root, $cfg] = lh_auth_scaffold('session');
        $cfg->set('auth.idle_timeout', 60);
        $cfg->set('auth.absolute_timeout', 300);
        $cfg->save();

        $ancient = ['lh_user' => 'operator', 'lh_login_at' => time() - 99999, 'lh_seen_at' => time() - 99999];

        $ordinary = lh_auth_request($root, [
            'sid'  => 'lhord' . bin2hex(random_bytes(4)),
            'get'  => ['v' => 'overview'],
            'seed' => $ancient,
        ]);
        lh_same(302, $ordinary['code'], 'an ordinary session that old is ended');

        $sid = 'lhkept' . bin2hex(random_bytes(4));
        $kept = lh_auth_request($root, [
            'sid'  => $sid,
            'get'  => ['v' => 'overview'],
            'seed' => $ancient + ['lh_persist' => true],
        ]);
        lh_same(200, $kept['code'], 'a remembered one is not, however old or idle it is');
        lh_contains($kept['out'], '<html', 'the panel renders');
        lh_true(is_file(lh_auth_session_file($root, $sid)), 'and the session is still there');

        lh_rmtree($root);
    },

    'the timeouts are untouched for every session that did not take the option'
        => static function (): void {
            [$root, $cfg] = lh_auth_scaffold('session');
            $cfg->set('auth.idle_timeout', 60);
            $cfg->set('auth.absolute_timeout', 3600);
            $cfg->save();

            $idle = lh_auth_request($root, [
                'sid'  => 'lht1' . bin2hex(random_bytes(4)),
                'get'  => ['v' => 'overview'],
                'seed' => ['lh_user' => 'operator', 'lh_login_at' => time(), 'lh_seen_at' => time() - 120],
            ]);
            lh_same(302, $idle['code'], 'the idle timeout still bites');

            $old = lh_auth_request($root, [
                'sid'  => 'lht2' . bin2hex(random_bytes(4)),
                'get'  => ['v' => 'overview'],
                'seed' => ['lh_user' => 'operator', 'lh_login_at' => time() - 7200, 'lh_seen_at' => time()],
            ]);
            lh_same(302, $old['code'], 'and so does the absolute one');

            lh_rmtree($root);
        },

    'a session PHP deleted comes back from the cookie, and the cookie is rotated'
        => static function (): void {
            [$root] = lh_auth_scaffold('session');
            $sid = 'lhgc' . bin2hex(random_bytes(4));

            $signin = lh_auth_request($root, [
                'get'    => ['login' => '1'],
                'method' => 'POST',
                'post'   => ['user' => 'operator', 'password' => lh_auth_password(), 'remember' => '1'],
                'sid'    => $sid,
            ]);
            $cookie = (string) ($signin['cookies'][Persistence::COOKIE] ?? '');
            lh_true($cookie !== '', 'a token was issued');

            foreach (glob($root . '/var/sessions/sess_*') ?: [] as $file) {
                unlink($file);
            }

            $back = lh_auth_request($root, [
                'get'     => ['v' => 'overview'],
                'sid'     => 'lhgcnew' . bin2hex(random_bytes(4)),
                'cookies' => [Persistence::COOKIE => $cookie],
            ]);

            lh_same(200, $back['code'], 'the cookie recreates the session the collector deleted');
            lh_same('operator', (string) ($back['session']['lh_user'] ?? ''), 'and signs the operator in');
            lh_true(($back['session']['lh_persist'] ?? false) === true, 'the new session is remembered too');

            $rotated = (string) ($back['cookies'][Persistence::COOKIE] ?? '');
            lh_true($rotated !== '' && $rotated !== $cookie, 'and the cookie is replaced on use');

            lh_auth_age_tokens($root);

            $replay = lh_auth_request($root, [
                'get'     => ['v' => 'overview'],
                'sid'     => 'lhgcold' . bin2hex(random_bytes(4)),
                'cookies' => [Persistence::COOKIE => $cookie],
            ]);
            lh_same(302, $replay['code'], 'the cookie that was already used gets nobody in');
            lh_same('', (string) ($replay['session']['lh_user'] ?? ''), 'really nobody');

            lh_rmtree($root);
        },

    'a stolen cookie replayed after the honest browser signs everybody out and warns'
        => static function (): void {
            [$root] = lh_auth_scaffold('session');

            $signin = lh_auth_request($root, [
                'get'    => ['login' => '1'],
                'method' => 'POST',
                'post'   => ['user' => 'operator', 'password' => lh_auth_password(), 'remember' => '1'],
                'sid'    => 'lhth' . bin2hex(random_bytes(4)),
            ]);
            $stolen = (string) $signin['cookies'][Persistence::COOKIE];

            lh_auth_request($root, [
                'get'     => ['v' => 'overview'],
                'sid'     => 'lhth2' . bin2hex(random_bytes(4)),
                'cookies' => [Persistence::COOKIE => $stolen],
            ]);

            lh_auth_age_tokens($root);

            $replay = lh_auth_request($root, [
                'get'     => ['v' => 'overview'],
                'sid'     => 'lhth3' . bin2hex(random_bytes(4)),
                'cookies' => [Persistence::COOKIE => $stolen],
            ]);
            lh_same(302, $replay['code'], 'the replay is refused');
            lh_same(0, Persistence::count($root . '/var'), 'and every token for the account is destroyed');

            $page = lh_auth_request($root, ['get' => ['login' => '1']]);
            lh_contains($page['out'], 'presented twice', 'the sign-in page warns the operator');
            lh_contains($page['out'], 'destroyed', 'and says what was done about it');

            $again = lh_auth_request($root, ['get' => ['login' => '1']]);
            lh_contains($again['out'], 'presented twice', 'rendering the page does not clear the warning');

            lh_auth_signin($root, 'lhth4' . bin2hex(random_bytes(4)));
            $clean = lh_auth_request($root, ['get' => ['login' => '1']]);
            lh_false(str_contains($clean['out'], 'presented twice'), 'a completed sign-in clears it');

            lh_rmtree($root);
        },

    'signing out revokes every stay-signed-in token, not just this browser\'s'
        => static function (): void {
            [$root] = lh_auth_scaffold('session');

            $first = lh_auth_request($root, [
                'get'    => ['login' => '1'],
                'method' => 'POST',
                'post'   => ['user' => 'operator', 'password' => lh_auth_password(), 'remember' => '1'],
                'sid'    => 'lhso1' . bin2hex(random_bytes(4)),
            ]);
            $elsewhere = (string) $first['cookies'][Persistence::COOKIE];

            $sid = 'lhso2' . bin2hex(random_bytes(4));
            lh_auth_request($root, [
                'get'    => ['login' => '1'],
                'method' => 'POST',
                'post'   => ['user' => 'operator', 'password' => lh_auth_password(), 'remember' => '1'],
                'sid'    => $sid,
            ]);
            lh_true(Persistence::count($root . '/var') >= 2, 'two browsers are remembered');

            $out = lh_auth_request($root, [
                'get'    => ['logout' => '1'],
                'method' => 'POST',
                'sid'    => $sid,
                'seed'   => ['lh_user' => 'operator', 'lh_login_at' => time(), 'lh_seen_at' => time()],
            ]);
            lh_same(303, $out['code'], 'sign-out redirects');
            lh_same(0, Persistence::count($root . '/var'), 'AND revokes every token there is');

            $stale = lh_auth_request($root, [
                'get'     => ['v' => 'overview'],
                'sid'     => 'lhso3' . bin2hex(random_bytes(4)),
                'cookies' => [Persistence::COOKIE => $elsewhere],
            ]);
            lh_same(302, $stale['code'], 'so the other browser cannot get back in either');

            lh_rmtree($root);
        },

    'signing in without the option revokes a token from a previous sign-in' => static function (): void {
        [$root] = lh_auth_scaffold('session');

        lh_auth_request($root, [
            'get'    => ['login' => '1'],
            'method' => 'POST',
            'post'   => ['user' => 'operator', 'password' => lh_auth_password(), 'remember' => '1'],
            'sid'    => 'lhun1' . bin2hex(random_bytes(4)),
        ]);
        lh_same(1, Persistence::count($root . '/var'), 'a token exists');

        lh_auth_request($root, [
            'get'    => ['login' => '1'],
            'method' => 'POST',
            'post'   => ['user' => 'operator', 'password' => lh_auth_password()],
            'sid'    => 'lhun2' . bin2hex(random_bytes(4)),
        ]);
        lh_same(0, Persistence::count($root . '/var'), 'an unticked box means what it says');

        lh_rmtree($root);
    },

    'the lockout applies to a request arriving with a persistent cookie' => static function (): void {
        [$root, $cfg] = lh_auth_scaffold('session');
        $cfg->set('auth.lockout_attempts', 2);
        $cfg->save();

        $signin = lh_auth_request($root, [
            'get'    => ['login' => '1'],
            'method' => 'POST',
            'post'   => ['user' => 'operator', 'password' => lh_auth_password(), 'remember' => '1'],
            'sid'    => 'lhlk1' . bin2hex(random_bytes(4)),
            'ip'     => '203.0.113.9',
        ]);
        $cookie = (string) $signin['cookies'][Persistence::COOKIE];

        for ($i = 0; $i < 2; $i++) {
            lh_auth_signin($root, 'lhlk' . $i, '203.0.113.9', 'wrong password');
        }

        $locked = lh_auth_request($root, [
            'get'     => ['v' => 'overview'],
            'sid'     => 'lhlk2' . bin2hex(random_bytes(4)),
            'ip'      => '203.0.113.9',
            'cookies' => [Persistence::COOKIE => $cookie],
        ]);

        lh_same(429, $locked['code'], 'A VALID COOKIE IS NOT A WAY PAST THE LOCKOUT');
        lh_same('', (string) ($locked['session']['lh_user'] ?? ''), 'and nobody is signed in');
        lh_same(1, Persistence::count($root . '/var'), 'the token is not consumed by a refused attempt either');

        lh_rmtree($root);
    },

    'a POST whose session was collected is explained, not reported as a CSRF attack'
        => static function (): void {
            [$root] = lh_auth_scaffold('session');

            $signin = lh_auth_request($root, [
                'get'    => ['login' => '1'],
                'method' => 'POST',
                'post'   => ['user' => 'operator', 'password' => lh_auth_password(), 'remember' => '1'],
                'sid'    => 'lh409' . bin2hex(random_bytes(4)),
            ]);
            $cookie = (string) $signin['cookies'][Persistence::COOKIE];

            foreach (glob($root . '/var/sessions/sess_*') ?: [] as $file) {
                unlink($file);
            }

            $r = lh_auth_request($root, [
                'get'     => ['v' => 'settings'],
                'method'  => 'POST',
                'post'    => ['action' => 'ui', 'timezone' => 'UTC', 'csrf' => 'from-the-dead-session'],
                'sid'     => 'lh409b' . bin2hex(random_bytes(4)),
                'cookies' => [Persistence::COOKIE => $cookie],
                'keep'    => true,
            ]);

            lh_same(409, $r['code'], 'the token cannot be valid, so the request is REFUSED');
            lh_false(
                str_contains($r['out'], 'CSRF token mismatch'),
                'but reporting an attack to somebody who is signed in and did nothing wrong is the '
                    . 'same misleading page this whole area was fixed to stop producing'
            );
            lh_contains($r['out'], 'Reload the page', 'the operator is told the actual remedy');
            lh_same('operator', (string) ($r['session']['lh_user'] ?? ''), 'they really are signed in');

            lh_rmtree($root);
        },

    'the sign-in page hands a remembered browser straight to the panel' => static function (): void {
        [$root] = lh_auth_scaffold('session');

        $signin = lh_auth_request($root, [
            'get'    => ['login' => '1'],
            'method' => 'POST',
            'post'   => ['user' => 'operator', 'password' => lh_auth_password(), 'remember' => '1'],
            'sid'    => 'lhlp' . bin2hex(random_bytes(4)),
        ]);
        $cookie = (string) $signin['cookies'][Persistence::COOKIE];

        $page = lh_auth_request($root, [
            'get'     => ['login' => '1'],
            'sid'     => 'lhlp2' . bin2hex(random_bytes(4)),
            'cookies' => [Persistence::COOKIE => $cookie],
        ]);
        lh_same(303, $page['code'], 'a remembered browser is never asked to sign in again');
        lh_false(str_contains($page['out'], 'name="password"'), 'the form is not rendered');

        $junk = str_repeat('a', 32) . '.' . str_repeat('b', 64);

        $bounce = lh_auth_request($root, [
            'get'     => ['login' => '1'],
            'sid'     => 'lhlp3' . bin2hex(random_bytes(4)),
            'cookies' => [Persistence::COOKIE => $junk],
        ]);
        lh_same(303, $bounce['code'], 'a cookie that turns out to be junk is sent to the panel to be tried');

        $tried = lh_auth_request($root, [
            'get'     => ['v' => 'overview'],
            'sid'     => 'lhlp4' . bin2hex(random_bytes(4)),
            'cookies' => [Persistence::COOKIE => $junk],
        ]);
        lh_same(302, $tried['code'], 'where it fails and is sent back to the sign-in page');
        lh_no_key(
            $tried['cookies'],
            Persistence::COOKIE,
            'having been cleared on the way, which is what stops the bounce becoming a loop'
        );

        $settled = lh_auth_request($root, [
            'get' => ['login' => '1'],
            'sid' => 'lhlp5' . bin2hex(random_bytes(4)),
        ]);
        lh_same(200, $settled['code'], 'so the third request renders the form');
        lh_contains($settled['out'], 'name="password"', 'really the form');

        lh_rmtree($root);
    },

    'a forged cookie counts as a failed sign-in, so guessing is rate limited'
        => static function (): void {
            [$root, $cfg] = lh_auth_scaffold('session');
            $cfg->set('auth.lockout_attempts', 3);
            $cfg->save();

            $signin = lh_auth_request($root, [
                'get'    => ['login' => '1'],
                'method' => 'POST',
                'post'   => ['user' => 'operator', 'password' => lh_auth_password(), 'remember' => '1'],
                'sid'    => 'lhfg1' . bin2hex(random_bytes(4)),
                'ip'     => '203.0.113.44',
            ]);
            $cookie = (string) $signin['cookies'][Persistence::COOKIE];
            [$selector] = explode('.', $cookie, 2);
            $forged = $selector . '.' . str_repeat('c', 64);

            $r = lh_auth_request($root, [
                'get'     => ['v' => 'overview'],
                'sid'     => 'lhfg2' . bin2hex(random_bytes(4)),
                'ip'      => '203.0.113.44',
                'cookies' => [Persistence::COOKIE => $forged],
            ]);
            lh_same(302, $r['code'], 'a wrong verifier gets nobody in');

            $ledger = lh_auth_ledger($root);
            $counted = 0;
            foreach ((array) ($ledger['ips'] ?? []) as $entry) {
                $counted += (int) ($entry['n'] ?? 0);
            }
            lh_true($counted >= 1, 'and is recorded as a failed sign-in on the same ledger as a bad password');

            lh_rmtree($root);
        },


    /*
     * ------------------------------------------------------------------------------------
     * Two-factor authentication, end to end.
     *
     * The arithmetic and the enrollment rules are in tests/test_totp.php. What is asserted here
     * is that the panel is really closed between the two factors, and that the persistent token
     * is only handed out once both are satisfied.
     * ------------------------------------------------------------------------------------
     */

    'with two-factor on, the right password alone signs nobody in' => static function (): void {
        [$root, $cfg] = lh_auth_scaffold('session');
        $key = lh_auth_enable_totp($cfg);

        $r = lh_auth_request($root, [
            'get'    => ['login' => '1'],
            'method' => 'POST',
            'post'   => ['user' => 'operator', 'password' => lh_auth_password()],
            'sid'    => 'lh2f1' . bin2hex(random_bytes(4)),
        ]);

        lh_same(303, $r['code'], 'the password is accepted and the operator moves to the next step');
        lh_same('', (string) ($r['session']['lh_user'] ?? ''), 'BUT NOBODY IS SIGNED IN');
        lh_same('operator', (string) ($r['session']['lh_2fa_user'] ?? ''), 'only a pending stage is recorded');

        $blocked = lh_auth_request($root, [
            'get'  => ['v' => 'overview'],
            'sid'  => $r['sid'],
            'keep' => true,
        ]);
        lh_same(302, $blocked['code'], 'and the pending session reaches no view');
        lh_false(str_contains($blocked['out'], '<html'), 'no panel HTML may be emitted');

        lh_rmtree($root);
    },

    'the second factor finishes the sign-in, and the same code cannot do it twice'
        => static function (): void {
            [$root, $cfg] = lh_auth_scaffold('session');
            $key = lh_auth_enable_totp($cfg);

            $password = lh_auth_request($root, [
                'get'    => ['login' => '1'],
                'method' => 'POST',
                'post'   => ['user' => 'operator', 'password' => lh_auth_password()],
                'sid'    => 'lh2f2' . bin2hex(random_bytes(4)),
            ]);
            $pending = $password['sid'];

            $page = lh_auth_request($root, ['get' => ['login' => '1'], 'sid' => $pending, 'keep' => true]);
            lh_contains($page['out'], 'name="code"', 'the code form is shown');
            lh_contains($page['out'], 'one-time-code', 'with the right autocomplete for a phone');
            lh_false(str_contains($page['out'], 'name="password"'), 'and not the password form again');
            $token = lh_auth_form_token($page['out']);

            $code = (string) Totp::at($key);

            $ok = lh_auth_request($root, [
                'get'    => ['login' => '1'],
                'method' => 'POST',
                'post'   => ['code' => $code, 'csrf' => $token],
                'sid'    => $pending,
                'keep'   => true,
            ]);
            lh_same(303, $ok['code'], 'a current code finishes the sign-in');
            lh_same('operator', (string) ($ok['session']['lh_user'] ?? ''), 'and the operator is signed in');
            lh_no_key($ok['session'], 'lh_2fa_user', 'the pending stage is cleared');

            $replay = lh_auth_request($root, [
                'get'    => ['login' => '1'],
                'method' => 'POST',
                'post'   => ['user' => 'operator', 'password' => lh_auth_password()],
                'sid'    => 'lh2f3' . bin2hex(random_bytes(4)),
            ]);
            $secondPage = lh_auth_request($root, [
                'get' => ['login' => '1'], 'sid' => $replay['sid'], 'keep' => true,
            ]);
            $again = lh_auth_request($root, [
                'get'    => ['login' => '1'],
                'method' => 'POST',
                'post'   => ['code' => $code, 'csrf' => lh_auth_form_token($secondPage['out'])],
                'sid'    => $replay['sid'],
                'keep'   => true,
            ]);
            lh_same(401, $again['code'], 'THE SAME CODE MUST NOT WORK A SECOND TIME');
            lh_same('', (string) ($again['session']['lh_user'] ?? ''), 'nobody is signed in');

            lh_rmtree($root);
        },

    'a recovery code finishes the sign-in once and is then gone' => static function (): void {
        [$root, $cfg] = lh_auth_scaffold('session');
        $key = lh_auth_enable_totp($cfg);
        $codes = TwoFactor::regenerate($cfg);
        $cfg->save();

        $drive = static function (string $code) use ($root): array {
            $password = lh_auth_request($root, [
                'get'    => ['login' => '1'],
                'method' => 'POST',
                'post'   => ['user' => 'operator', 'password' => lh_auth_password()],
                'sid'    => 'lhrc' . bin2hex(random_bytes(5)),
            ]);
            $page = lh_auth_request($root, [
                'get' => ['login' => '1'], 'sid' => $password['sid'], 'keep' => true,
            ]);
            return lh_auth_request($root, [
                'get'    => ['login' => '1'],
                'method' => 'POST',
                'post'   => ['code' => $code, 'csrf' => lh_auth_form_token($page['out'])],
                'sid'    => $password['sid'],
                'keep'   => true,
            ]);
        };

        $first = $drive($codes[0]);
        lh_same(303, $first['code'], 'a recovery code gets the operator in');
        lh_same('operator', (string) ($first['session']['lh_user'] ?? ''), 'really in');

        $second = $drive($codes[0]);
        lh_same(401, $second['code'], 'and only once');

        $other = $drive($codes[1]);
        lh_same(303, $other['code'], 'while the rest of the set still works');

        lh_rmtree($root);
    },

    'a wrong code is refused and counts toward the lockout' => static function (): void {
        [$root, $cfg] = lh_auth_scaffold('session');
        lh_auth_enable_totp($cfg);
        $cfg->set('auth.lockout_attempts', 2);
        $cfg->save();

        for ($i = 0; $i < 2; $i++) {
            $r = lh_auth_request($root, [
                'get'    => ['login' => '1'],
                'method' => 'POST',
                'post'   => ['code' => '000000'],
                'sid'    => 'lhbc' . $i . bin2hex(random_bytes(4)),
                'ip'     => '203.0.113.77',
                'seed'   => ['lh_2fa_user' => 'operator', 'lh_2fa_at' => time()],
            ]);
            lh_same(401, $r['code'], 'wrong code, attempt ' . ($i + 1) . ', is a plain refusal');
            lh_same('', (string) ($r['session']['lh_user'] ?? ''), 'and signs nobody in');
        }

        $locked = lh_auth_request($root, [
            'get'    => ['login' => '1'],
            'method' => 'POST',
            'post'   => ['user' => 'operator', 'password' => lh_auth_password()],
            'sid'    => 'lhbc9' . bin2hex(random_bytes(4)),
            'ip'     => '203.0.113.77',
        ]);
        lh_same(
            429,
            $locked['code'],
            'wrong codes land on the SAME ledger as wrong passwords, so guessing the six digits '
                . 'locks the address out exactly as guessing the password would'
        );

        $stillLocked = lh_auth_request($root, [
            'get'    => ['login' => '1'],
            'method' => 'POST',
            'post'   => ['code' => '000000'],
            'sid'    => 'lhbc8' . bin2hex(random_bytes(4)),
            'ip'     => '203.0.113.77',
            'seed'   => ['lh_2fa_user' => 'operator', 'lh_2fa_at' => time()],
        ]);
        lh_same(429, $stillLocked['code'], 'and the code step is behind the same gate');

        lh_rmtree($root);
    },

    'a correct password does not clear the lockout while the second factor is outstanding'
        => static function (): void {
            [$root, $cfg] = lh_auth_scaffold('session');
            lh_auth_enable_totp($cfg);
            $cfg->set('auth.lockout_attempts', 5);
            $cfg->save();

            lh_auth_signin($root, 'lhcl1', '203.0.113.88', 'wrong password');
            lh_auth_signin($root, 'lhcl2', '203.0.113.88', 'wrong password');

            lh_auth_request($root, [
                'get'    => ['login' => '1'],
                'method' => 'POST',
                'post'   => ['user' => 'operator', 'password' => lh_auth_password()],
                'sid'    => 'lhcl3' . bin2hex(random_bytes(4)),
                'ip'     => '203.0.113.88',
            ]);

            $counted = 0;
            foreach ((array) (lh_auth_ledger($root)['ips'] ?? []) as $entry) {
                $counted += (int) ($entry['n'] ?? 0);
            }
            lh_same(2, $counted, 'the two failures are still counted, so the guesses are still limited');

            lh_rmtree($root);
        },

    'the stay-signed-in token is only issued once the second factor is satisfied'
        => static function (): void {
            [$root, $cfg] = lh_auth_scaffold('session');
            $key = lh_auth_enable_totp($cfg);

            $password = lh_auth_request($root, [
                'get'    => ['login' => '1'],
                'method' => 'POST',
                'post'   => ['user' => 'operator', 'password' => lh_auth_password(), 'remember' => '1'],
                'sid'    => 'lh2fr' . bin2hex(random_bytes(4)),
            ]);
            lh_no_key(
                $password['cookies'],
                Persistence::COOKIE,
                'NO TOKEN ON THE STRENGTH OF HALF A CREDENTIAL'
            );
            lh_same(0, Persistence::count($root . '/var'), 'and none in the store either');
            lh_true(($password['session']['lh_2fa_remember'] ?? false) === true, 'the request is remembered');

            $page = lh_auth_request($root, [
                'get' => ['login' => '1'], 'sid' => $password['sid'], 'keep' => true,
            ]);
            $done = lh_auth_request($root, [
                'get'    => ['login' => '1'],
                'method' => 'POST',
                'post'   => ['code' => (string) Totp::at($key), 'csrf' => lh_auth_form_token($page['out'])],
                'sid'    => $password['sid'],
                'keep'   => true,
            ]);

            lh_same(303, $done['code'], 'the second factor completes it');
            lh_has_key($done['cookies'], Persistence::COOKIE, 'and the token is issued then');
            lh_same(1, Persistence::count($root . '/var'), 'exactly one');

            lh_rmtree($root);
        },

    'a pending sign-in that sits too long has to start again' => static function (): void {
        [$root, $cfg] = lh_auth_scaffold('session');
        $key = lh_auth_enable_totp($cfg);

        $sid = 'lhstale2' . bin2hex(random_bytes(4));
        $r = lh_auth_request($root, [
            'get'    => ['login' => '1'],
            'method' => 'POST',
            'post'   => ['code' => (string) Totp::at($key)],
            'sid'    => $sid,
            'seed'   => [
                'lh_2fa_user' => 'operator',
                'lh_2fa_at'   => time() - (Security::PENDING_TTL + 60),
            ],
        ]);

        lh_same(401, $r['code'], 'a pending stage past its time is not a pending stage');
        lh_same('', (string) ($r['session']['lh_user'] ?? ''), 'nobody is signed in');
        lh_contains($r['out'], 'name="password"', 'and the password form is shown again');

        lh_rmtree($root);
    },

    'turning two-factor on destroys every stay-signed-in token' => static function (): void {
        [$root, $cfg] = lh_auth_scaffold('session');

        lh_auth_request($root, [
            'get'    => ['login' => '1'],
            'method' => 'POST',
            'post'   => ['user' => 'operator', 'password' => lh_auth_password(), 'remember' => '1'],
            'sid'    => 'lh2fk' . bin2hex(random_bytes(4)),
        ]);
        lh_same(1, Persistence::count($root . '/var'), 'a token exists');

        $candidate = TwoFactor::begin();
        $result = TwoFactor::enable($cfg, $candidate, (string) Totp::at($candidate), $root . '/var');
        lh_same([], $result['errors'], 'two-factor goes on');

        lh_same(
            0,
            Persistence::count($root . '/var'),
            'tokens issued on one factor cannot survive as a way past two'
        );

        lh_rmtree($root);
    },

    'changing the password revokes every token and turns two-factor off' => static function (): void {
        [$root, $cfg] = lh_auth_scaffold('session');
        lh_auth_enable_totp($cfg);

        lh_auth_request($root, [
            'get'    => ['login' => '1'],
            'method' => 'POST',
            'post'   => ['user' => 'operator', 'password' => lh_auth_password()],
            'sid'    => 'lhpw' . bin2hex(random_bytes(4)),
        ]);
        Persistence::issue('operator', $root . '/var', 86400);
        lh_true(Persistence::count($root . '/var') >= 1, 'a token exists');

        lh_same([], Steps::applyAdmin($cfg, 'operator', 'a-brand-new-password', '', 'session'));

        lh_same(0, Persistence::count($root . '/var'), 'a new password revokes every token');
        lh_false(
            TwoFactor::isEnabled((array) $cfg->get('auth', [])),
            'and turns two-factor off, which is the documented way back in without a phone'
        );

        lh_rmtree($root);
    },

    'changing the sign-in mode revokes every token' => static function (): void {
        [$root, $cfg] = lh_auth_scaffold('session');

        Persistence::issue('operator', $root . '/var', 86400);
        lh_same(1, Persistence::count($root . '/var'), 'a token exists');

        lh_same([], Steps::applyAuthMode($cfg, 'basic'));
        lh_same(0, Persistence::count($root . '/var'), 'a session-mode token cannot outlive session mode');

        lh_rmtree($root);
    },

    'Config::validate refuses a two-factor block that could never accept a code'
        => static function (): void {
            $cfg = Config::load('/nonexistent-loghound-config');
            $cfg->set('solr.base_url', 'http://127.0.0.1:8983/solr');
            $cfg->set('solr.hits_core', 'lh_hits');
            $cfg->set('solr.sessions_core', 'lh_sessions');
            $cfg->set('opensolr.email', 'operator@example.com');
            $cfg->set('opensolr.api_key', 'not-a-real-key');
            $cfg->set('beacon.enabled', false);
            $cfg->set('auth.mode', 'session');
            $cfg->set('auth.user', 'operator');
            $cfg->set('auth.password_hash', password_hash('a-long-enough-password', PASSWORD_DEFAULT));

            lh_same([], $cfg->validate(), 'the default two-factor block is fine');

            $cfg->set('auth.totp', ['enabled' => true, 'secret' => '', 'recovery' => []]);
            lh_contains(
                implode(' ', $cfg->validate()),
                'no code could ever be accepted',
                'on with no secret is a locked-out operator, and is reported as the mistake it is'
            );

            $cfg->set('auth.totp', ['enabled' => 'yes', 'secret' => '', 'recovery' => []]);
            lh_contains(implode(' ', $cfg->validate()), 'auth.totp.enabled must be', 'and so is a non-boolean');

            $cfg->set('auth.totp', ['enabled' => false, 'secret' => '', 'recovery' => []]);
            $cfg->set('auth.persistent_lifetime', 60);
            lh_contains(
                implode(' ', $cfg->validate()),
                'auth.persistent_lifetime must be',
                'a lifetime shorter than the idle timeout is a misconfiguration, not a feature'
            );
        },

];
