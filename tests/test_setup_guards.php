<?php
/**
 * Loghound — tests for the setup and ingest guards that an audit found switched off.
 *
 * Every test here pins one specific regression that was live in the tree, chosen because in
 * each case the guard LOOKED present while doing nothing:
 *
 *  - Detector::examine() appended the candidate's own directory to the allowed roots before
 *    reading it, so the Security::safePath() check inside LogDetect::tailLines() could not
 *    fail. The file was read and five of its lines were rendered on the review screen; only
 *    the confirm button was blocked afterwards, which does not unread a file.
 *  - Security::validateUserRegex() runs a candidate pattern once against one fixed subject.
 *    An anchored pattern fails that subject at the first character, so `/^(a+)+$/` sails
 *    through — the probe measures usability, not safety, and the safety has to live at the
 *    point of the match instead.
 *  - Storage::solrFixes() interpolated `solr.base_url` into ready-to-paste curl commands. The
 *    form that let an operator type that URL is gone now, but the probe still reads whatever
 *    the config file holds, and a hand-edited `https://user:pass@host/solr` is exactly the
 *    case no input validation can reach — so the tests below stay, and set the key directly.
 *  - Setup\Token told a locked-out operator to restart PHP-FPM, which does nothing to a
 *    counter that lives in var/install-attempts.json, and let any passer-by spend a global
 *    budget that locked the operator out of their own installer.
 *  - Setup\Steps::applySources() and Panel\Settings::confirmSource() are documented as
 *    interchangeable and stored different things, so a custom-regex source confirmed in the
 *    panel got a format the tailer could not resolve.
 *
 * No network, no Solr, no writes outside a temp directory — except var/detect.json, which is
 * a hard-coded path in Panel\Settings and is backed up and restored around the one test that
 * needs it.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Config;
use Loghound\LogDetect;
use Loghound\LogFormat;
use Loghound\Panel\Gateway;
use Loghound\Panel\Settings;
use Loghound\Security;
use Loghound\Setup\Detector;
use Loghound\Setup\Steps;
use Loghound\Setup\Storage;
use Loghound\Setup\Token;

/**
 * A throwaway installation: an allowed log directory with a real fixture in it, and a
 * second directory outside the allowed roots holding a file nothing may read.
 *
 * @return array{0:string,1:Config}
 */
function lh_guard_scaffold(): array
{
    $root = lh_tmpdir('lhguard');
    mkdir($root . '/config', 0700, true);
    mkdir($root . '/var', 0750, true);
    mkdir($root . '/logs', 0750, true);
    mkdir($root . '/secrets', 0750, true);
    copy(lh_fixture('apache_combined_human.log'), $root . '/logs/access.log');

    $cfg = Config::load($root . '/config/loghound.php');
    $cfg->set('allowed_log_roots', [$root . '/logs']);
    $cfg->set('discover', [
        'apache_configs'    => [],
        'apache_vhost_dirs' => [],
        'nginx_configs'     => [],
        'nginx_vhost_dirs'  => [],
        'fallback_globs'    => [$root . '/logs/*.log', $root . '/secrets/*.log'],
    ]);

    return [$root, $cfg];
}

/**
 * Resolve a stored `sources[].format` the way bin/loghound-tail resolves it.
 *
 * The ladder is: library name, then delimited regex through LogDetect::formatFromRegex(),
 * then the operator's own webserver format string. Duplicated here rather than imported
 * because the tailer is a script that executes on include and cannot be required by a test;
 * the daemon's Pipeline::format() applies exactly these three rungs in this order.
 */
function lh_guard_resolve_format(string $stored): ?LogFormat
{
    $fmt = LogDetect::formatByName($stored);
    if ($fmt !== null) {
        return $fmt;
    }
    if (LogFormat::isDelimitedRegex($stored)) {
        return LogDetect::formatFromRegex($stored, 'source');
    }
    return str_contains($stored, '$')
        ? LogFormat::fromNginx($stored, 'source')
        : LogFormat::fromApache($stored, 'source');
}

/**
 * A Settings controller wired to a Solr that cannot be reached, with demo mode off.
 *
 * Demo mode would serve Panel\Fixtures::detection() instead of the report on disk, which is
 * the opposite of what the confirmation test needs.
 */
function lh_guard_settings(Config $cfg): Settings
{
    $solr = new \Loghound\Solr(
        (array) $cfg->get('solr', []),
        static fn(array $req): array => ['status' => 0, 'body' => '', 'error' => 'no network in tests']
    );
    return new Settings($cfg, new Gateway($cfg, $solr, false));
}

/** Where Panel\Settings reads and writes its detection report. */
function lh_guard_detect_file(): string
{
    return dirname(__DIR__) . '/var/detect.json';
}

return [
    'a candidate outside the allowed roots is described but never read' => static function (): void {
        [$root, $cfg] = lh_guard_scaffold();
        $marker = 'CANARY-' . bin2hex(random_bytes(8));
        file_put_contents(
            $root . '/secrets/private.log',
            '203.0.113.7 - - [10/Sep/2026:00:00:00 +0000] "GET /' . $marker
                . ' HTTP/1.1" 200 12 "-" "curl/8.0"' . "\n"
        );

        $source = Detector::examine($cfg, $root . '/secrets/private.log', [
            'origin' => 'webserver config (test.conf)',
            'server' => 'apache',
            'vhost'  => 'example.test',
        ]);

        lh_true($source['outside_roots'], 'the file is outside allowed_log_roots');
        lh_same(0, $source['lines_tested'], 'a file outside the roots must not be sampled at all');
        lh_same([], $source['samples'], 'no line of it may be rendered for review');
        lh_same([], $source['mapping'], 'no mapping can be derived from a file that was not read');
        lh_same(0.0, $source['confidence'], 'confidence in a file we never opened is zero');

        $rendered = (string) json_encode($source);
        lh_true(
            !str_contains($rendered, $marker),
            'no byte of the file may reach the report: ' . lh_show($rendered)
        );

        lh_same('example.test', $source['vhost'], 'the metadata from the config is still shown');
        lh_contains($source['source'], 'webserver config', 'and so is where the candidate came from');

        lh_rmtree($root);
    },

    'detection still samples a file inside the allowed roots' => static function (): void {
        [$root, $cfg] = lh_guard_scaffold();

        $report = Detector::runSync($cfg);
        $byPath = [];
        foreach ((array) $report['sources'] as $src) {
            $byPath[(string) $src['path']] = $src;
        }

        lh_has_key($byPath, $root . '/logs/access.log', 'the permitted candidate');
        $inside = $byPath[$root . '/logs/access.log'];
        lh_false($inside['outside_roots'], 'the fixture is inside the permitted root');
        lh_true($inside['lines_tested'] > 0, 'a permitted file is still sampled');
        lh_true(count($inside['samples']) > 0, 'SPEC §8 requires sample lines for review');
        lh_same('apache_combined', $inside['format_name'], 'and the format is still detected');

        lh_rmtree($root);
    },

    'the regex vetting at save time is not a ReDoS proof' => static function (): void {
        [$root, $cfg] = lh_guard_scaffold();

        $pattern = '/^(?<remote_addr>(a+)+b) (?<status>\d{3})$/';
        lh_same(
            null,
            Security::validateUserRegex($pattern),
            'the probe accepts a nested quantifier, which is why parse() must bound it'
        );

        $accepted = Detector::manualSource($cfg, $root . '/logs/access.log', 'custom', $pattern);
        lh_true($accepted['ok'], 'and so the pattern really can be stored: ' . $accepted['error']);

        lh_rmtree($root);
    },

    'a catastrophically backtracking pattern is contained, not left to run' => static function (): void {
        $fmt = LogFormat::fromRegex('/^(?<remote_addr>(a+)+b) (?<status>\d{3})$/');
        $line = str_repeat('a', 44) . ' 200';

        $ambient = ini_get('pcre.backtrack_limit');
        ini_set('pcre.backtrack_limit', '1000000000');
        try {
            $started = microtime(true);
            $record  = $fmt->parse($line);
            $elapsed = microtime(true) - $started;
            $after   = ini_get('pcre.backtrack_limit');
        } finally {
            if ($ambient !== false) {
                ini_set('pcre.backtrack_limit', $ambient);
            }
        }

        lh_same(null, $record, 'an abandoned line is a parse failure, never a partial record');
        lh_same(1, $fmt->backtrackFailures(), 'and it is counted rather than swallowed');
        lh_true(
            $elapsed < 0.25,
            'the match must be cut off by our own budget, not by the ambient one; took '
                . sprintf('%.3fs', $elapsed)
        );
        lh_same('1000000000', $after, 'the process-wide backtrack limit must be restored');
    },

    'a long ordinary line still parses under the backtrack budget' => static function (): void {
        $fmt = LogDetect::formatByName('apache_combined');
        lh_true($fmt !== null, 'the library format must exist');

        $path = '/' . str_repeat('a', 4000);
        $ua   = str_repeat('Mozilla/5.0 ', 300);
        $line = '198.51.100.7 - - [10/Sep/2026:00:00:00 +0000] "GET ' . $path
            . ' HTTP/1.1" 200 4096 "https://example.test/" "' . $ua . '"';

        $record = $fmt->parse($line);
        lh_true(is_array($record), 'a multi-kilobyte line is ordinary traffic and must still parse');
        lh_same('198.51.100.7', $record['remote_addr'], 'and its fields must be intact');
        lh_same($ua, $record['header_in.user-agent'], 'including the long one');
        lh_same(0, $fmt->backtrackFailures(), 'a linear pattern must never touch the budget');
    },

    'a password in the Solr base URL never reaches a returned string' => static function (): void {
        [$root, $cfg] = lh_guard_scaffold();
        $cfg->set('solr.base_url', 'https://sneaky:hunter2@solr.example.test:8983/solr');
        $cfg->set('solr.http_user', 'sneaky');
        $cfg->set('solr.http_pass', 'hunter2');
        $cfg->set('solr.hits_core', 'loghound_deadbeef_hits');

        $transport = static fn(array $req): array => [
            'status' => 400,
            'body'   => (string) json_encode([
                'error' => ['msg' => 'rejected https://sneaky:hunter2@solr.example.test:8983/solr/x'],
            ]),
            'error'  => '',
        ];

        $probe = Storage::probeCore($cfg, 'loghound_deadbeef_hits', $transport);

        lh_false($probe['ok'], 'a 400 is not a healthy core');
        $rendered = $probe['message'] . ' ' . implode(' ', (array) $probe['fix']);
        lh_true(!str_contains($rendered, 'hunter2'), 'the password leaked: ' . $rendered);
        lh_true(!str_contains($rendered, 'sneaky'), 'the username leaked: ' . $rendered);
        lh_contains($probe['message'], 'solr.example.test:8983', 'the host and port are still named');

        lh_rmtree($root);
    },

    'an unparseable Solr base URL is not echoed back' => static function (): void {
        [$root, $cfg] = lh_guard_scaffold();
        $cfg->set('solr.base_url', 'https://sneaky:changeme@');
        $cfg->set('solr.hits_core', 'loghound_deadbeef_hits');

        $transport = static fn(array $req): array => [
            'status' => 0,
            'body'   => '',
            'error'  => 'could not resolve host',
        ];

        $probe = Storage::probeCore($cfg, 'loghound_deadbeef_hits', $transport);
        lh_false($probe['ok'], 'an unresolvable host is not a healthy core');
        lh_true(
            !str_contains($probe['message'], 'changeme'),
            'a URL that cannot be parsed must not be printed verbatim: ' . $probe['message']
        );

        lh_rmtree($root);
    },

    'the health probe offers no shell hints built from the base URL' => static function (): void {
        [$root, $cfg] = lh_guard_scaffold();
        $cfg->set('solr.base_url', 'https://sneaky:hunter2@solr.example.test:8983/solr');
        $cfg->set('solr.hits_core', 'loghound_deadbeef_hits');

        $transport = static fn(array $req): array => [
            'status' => 404,
            'body'   => (string) json_encode(['error' => ['msg' => 'Not Found']]),
            'error'  => '',
        ];

        $probe = Storage::probeCore($cfg, 'loghound_deadbeef_hits', $transport);
        lh_same([], (array) $probe['fix'], 'the dead curl-command builder must stay deleted');

        lh_rmtree($root);
    },

    'the rate-limit refusal names a remedy that actually works' => static function (): void {
        $root = lh_tmpdir('lhtok');
        mkdir($root . '/var', 0750, true);
        $token = new Token($root . '/var');
        $token->ensure();
        $real = trim((string) file_get_contents($token->path()));

        $refusal = '';
        for ($i = 0; $i < 12 && $refusal === ''; $i++) {
            $answer = $token->verify('wrong-' . $i, '203.0.113.9');
            if (str_contains($answer, 'Too many attempts')) {
                $refusal = $answer;
            }
        }
        lh_true($refusal !== '', 'a flood from one address must eventually be turned away');
        lh_contains($refusal, 'install-attempts.json', 'the refusal must name the real counter');
        lh_true(
            !str_contains($refusal, 'PHP-FPM'),
            'restarting the pool does nothing to a counter on disk: ' . $refusal
        );

        $ledger = $root . '/var/install-attempts.json';
        lh_true(is_file($ledger), 'the counter is the file the message names');
        unlink($ledger);
        lh_same('', $token->verify($real, '203.0.113.9'), 'deleting it must really clear the counter');

        lh_rmtree($root);
    },

    'a stranger cannot lock the operator out of the installer' => static function (): void {
        $root = lh_tmpdir('lhtok');
        mkdir($root . '/var', 0750, true);
        $token = new Token($root . '/var');
        $token->ensure();
        $real = trim((string) file_get_contents($token->path()));

        for ($i = 0; $i < 200; $i++) {
            $token->verify('guess-' . $i, '198.51.100.' . ($i % 200));
        }

        $answer = $token->verify($real, '203.0.113.9');
        lh_same(
            '',
            $answer,
            'an unauthenticated flood from other addresses must not refuse the operator: ' . $answer
        );

        lh_rmtree($root);
    },

    'the per-address budget still bounds guessing' => static function (): void {
        $root = lh_tmpdir('lhtok');
        mkdir($root . '/var', 0750, true);
        $token = new Token($root . '/var');
        $token->ensure();
        $real = trim((string) file_get_contents($token->path()));

        for ($i = 0; $i < 8; $i++) {
            $token->verify('wrong-' . $i, '203.0.113.5');
        }
        lh_contains(
            $token->verify($real, '203.0.113.5'),
            'Too many attempts',
            'even a correct token is refused once that address has spent its budget'
        );
        lh_same('', $token->verify($real, '203.0.113.6'), 'a different address is unaffected');

        lh_rmtree($root);
    },

    'both confirmation paths store the same format for a custom pattern' => static function (): void {
        [$root, $cfg] = lh_guard_scaffold();
        $log = $root . '/logs/access.log';
        $pattern = '/^(?<remote_addr>\S+) \S+ \S+ \[(?<time>[^\]]+)\] "(?<request>[^"]*)" '
            . '(?<status>\d{3}) (?<bytes>\S+) "(?<referer>[^"]*)" "(?<ua>[^"]*)"$/';

        $manual = Detector::manualSource($cfg, $log, 'custom', $pattern);
        lh_true($manual['ok'], 'the custom pattern must be accepted: ' . $manual['error']);

        $errors = Steps::applySources($cfg, [$manual['source']]);
        lh_same([], $errors, 'the installer path must store it cleanly');
        $viaInstaller = (array) $cfg->get('sources', []);
        lh_same(1, count($viaInstaller), 'exactly one source');

        $detectFile = lh_guard_detect_file();
        $backup = is_file($detectFile) ? (string) file_get_contents($detectFile) : null;

        $panelCfg = Config::load($root . '/config/panel.php');
        $panelCfg->set('allowed_log_roots', [$root . '/logs']);

        $savedPost = $_POST;
        try {
            file_put_contents($detectFile, (string) json_encode([
                'generated_at' => time(),
                'sources'      => [$manual['source']],
            ]));

            $_POST = ['action' => 'confirm_source', 'path' => $log, 'csrf' => lh_csrf()];
            $redirect = lh_guard_settings($panelCfg)->post();
        } finally {
            $_POST = $savedPost;
            if ($backup === null) {
                @unlink($detectFile);
            } else {
                file_put_contents($detectFile, $backup);
            }
        }

        lh_contains($redirect, 'ok=source_confirmed', 'the panel must accept the source');
        $viaPanel = (array) $panelCfg->get('sources', []);
        lh_same(1, count($viaPanel), 'the panel must store exactly one source');

        lh_same(
            $viaInstaller[0]['format'],
            $viaPanel[0]['format'],
            'the two paths are documented as interchangeable and must store the same format'
        );
        lh_same($pattern, $viaPanel[0]['format'], 'and for a custom source that is the pattern itself');

        lh_rmtree($root);
    },

    'a stored custom pattern is a format the tailer can resolve' => static function (): void {
        [$root, $cfg] = lh_guard_scaffold();
        $log = $root . '/logs/access.log';
        $pattern = '/^(?<remote_addr>\S+) \S+ \S+ \[(?<time>[^\]]+)\] "(?<request>[^"]*)" '
            . '(?<status>\d{3}) (?<bytes>\S+) "(?<referer>[^"]*)" "(?<ua>[^"]*)"$/';

        $manual = Detector::manualSource($cfg, $log, 'custom', $pattern);
        lh_true($manual['ok'], 'the custom pattern must be accepted: ' . $manual['error']);
        lh_same([], Steps::applySources($cfg, [$manual['source']]), 'and must store cleanly');

        $stored = (string) ((array) $cfg->get('sources', []))[0]['format'];
        $fmt = lh_guard_resolve_format($stored);
        lh_true($fmt instanceof LogFormat, 'the tailer must be able to compile what setup stored');

        $line = trim((string) file(lh_fixture('apache_combined_human.log'))[0]);
        $record = $fmt->parse($line);
        lh_true(is_array($record), 'and the compiled format must parse the operator\'s own log');
        lh_same('198.51.100.204', $record['remote_addr'], 'into the fields they reviewed');
        lh_same('200', $record['status'], 'status included');

        lh_rmtree($root);
    },

    'a library format is stored by name by both paths' => static function (): void {
        [$root, $cfg] = lh_guard_scaffold();
        $log = $root . '/logs/access.log';

        $manual = Detector::manualSource($cfg, $log, 'apache_combined', '');
        lh_true($manual['ok'], 'a library format must be accepted: ' . $manual['error']);
        lh_same([], Steps::applySources($cfg, [$manual['source']]), 'and stored cleanly');

        $stored = (string) ((array) $cfg->get('sources', []))[0]['format'];
        lh_same('apache_combined', $stored, 'a library format is stored by its name');
        lh_true(
            LogDetect::formatByName($stored) !== null,
            'which is what the tailer looks up first'
        );

        lh_rmtree($root);
    },

    'a source with no usable format is refused by both paths' => static function (): void {
        [$root, $cfg] = lh_guard_scaffold();
        $log = $root . '/logs/access.log';

        $unusable = ['path' => $log, 'format_name' => 'unrecognised', 'format_string' => ''];
        lh_true(Steps::applySources($cfg, [$unusable]) !== [], 'the installer refuses it');
        lh_same([], (array) $cfg->get('sources', []), 'and stores nothing');

        $detectFile = lh_guard_detect_file();
        $backup = is_file($detectFile) ? (string) file_get_contents($detectFile) : null;

        $panelCfg = Config::load($root . '/config/panel.php');
        $panelCfg->set('allowed_log_roots', [$root . '/logs']);

        $savedPost = $_POST;
        try {
            file_put_contents($detectFile, (string) json_encode([
                'generated_at' => time(),
                'sources'      => [$unusable],
            ]));

            $_POST = ['action' => 'confirm_source', 'path' => $log, 'csrf' => lh_csrf()];
            $redirect = lh_guard_settings($panelCfg)->post();
        } finally {
            $_POST = $savedPost;
            if ($backup === null) {
                @unlink($detectFile);
            } else {
                file_put_contents($detectFile, $backup);
            }
        }

        lh_contains($redirect, 'err=no_usable_format', 'the panel refuses it too');
        lh_same([], (array) $panelCfg->get('sources', []), 'and stores nothing either');

        lh_rmtree($root);
    },
];
