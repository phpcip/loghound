<?php
/**
 * Loghound — tests for the "After you finish" instructions and where they are reachable.
 *
 * The defect these pin: the commands that switch ingestion on used to exist only on the
 * installer's last screen, which announces its own disappearance. An operator who clicked
 * through lost them, and nothing in the panel afterwards said ingestion had never started.
 *
 * What is asserted here:
 *  - There is ONE source for those instructions, Steps::nextSteps(), and both the installer
 *    screen and the panel's Settings card render that same source.
 *  - The unit line is a single, directly pasteable command — `systemctl enable --now` takes
 *    a list, so a copy button hands the operator something a shell accepts unedited.
 *  - No snippet is multi-line, because a copy button on a multi-line block produces
 *    something that has to be edited before it can be run.
 *  - An unset or unusable `base_url` yields a sentence naming what to fix, never a snippet
 *    pointing at a placeholder host. A copied snippet aimed at loghound.example.com fails
 *    silently and reads as the product not working.
 *  - Ingestion liveness is read from the tailer's own status document — the same file
 *    `bin/loghound-tail --status` reads — and its four states are distinguished.
 *  - Nothing in the product executes a process to answer any of this.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Config;
use Loghound\Panel\Gateway;
use Loghound\Panel\Settings;
use Loghound\Setup\Steps;
use Loghound\Solr;

/**
 * A configuration with nothing set beyond what the panel needs to render.
 */
function lh_finish_config(): Config
{
    $cfg = Config::load('/nonexistent-loghound-config');
    $cfg->set('solr.base_url', 'http://127.0.0.1:65535/solr');
    $cfg->set('solr.hits_core', 'lh_test_hits');
    $cfg->set('solr.sessions_core', 'lh_test_sessions');
    return $cfg;
}

/**
 * Render the Settings body with a given configuration, returning the HTML.
 *
 * The Solr transport is a closure returning canned JSON, so nothing leaves the machine and
 * the card is judged on what it renders rather than on what a backend replied.
 *
 * E_WARNING is masked for the duration. Every form on the page mints a CSRF token, which
 * lazily starts a session, and PHP refuses to start one once the test runner has printed a
 * line. That is an artefact of rendering a web page inside a CLI runner, not a finding, and
 * letting it through would bury the real output under a warning per form.
 */
function lh_finish_settings_html(Config $cfg): string
{
    $savedGet = $_GET;
    $savedServer = $_SERVER;
    $savedLevel = error_reporting();
    $_GET = [];
    $_SERVER['HTTP_HOST'] = 'panel.invalid';
    error_reporting($savedLevel & ~E_WARNING);
    try {
        $transport = static fn (array $request): array => [
            'status' => 200,
            'body' => (string) json_encode([
                'responseHeader' => ['status' => 0],
                'response' => ['numFound' => 0, 'docs' => []],
                'facets' => ['count' => 0],
            ]),
            'error' => '',
        ];
        $gw = new Gateway($cfg, new Solr((array) $cfg->get('solr'), $transport), false);
        $view = new Settings($cfg, $gw);
        ob_start();
        $view->body();
        return (string) ob_get_clean();
    } finally {
        $_GET = $savedGet;
        $_SERVER = $savedServer;
        error_reporting($savedLevel);
    }
}

/**
 * Find one group of Steps::nextSteps() by its key.
 *
 * @return array{key:string,title:string,lines:string[],problem:string}
 */
function lh_finish_group(Config $cfg, string $key, string $root = '/opt/loghound'): array
{
    foreach (Steps::nextSteps($cfg, $root) as $group) {
        if ((string) $group['key'] === $key) {
            return $group;
        }
    }
    lh_fail('no next-step group keyed ' . $key);
    throw new RuntimeException('unreachable');
}

/**
 * Write a tail status document into a throwaway root, as the daemon would.
 *
 * @param array<string,mixed> $overrides Merged over the minimal shape.
 */
function lh_finish_write_status(string $root, array $overrides = []): void
{
    if (!is_dir($root . '/var')) {
        mkdir($root . '/var', 0700, true);
    }
    $doc = array_merge([
        'schema'       => 1,
        'pid'          => 4242,
        'generated_at' => gmdate('Y-m-d\TH:i:s\Z'),
        'lag_bytes'    => 0,
        'totals'       => ['lines' => 12, 'docs_indexed' => 12],
        'sources'      => [['path' => '/var/log/apache2/access.log']],
    ], $overrides);
    file_put_contents($root . '/var/tail-status.json', (string) json_encode($doc));
}

/**
 * Drop comments from PHP source so a scan judges code rather than prose.
 *
 * These files document at length why there is no process execution in them, and a naive
 * substring sweep finds `exec()` in the sentence saying it is never called. Tokenising is
 * the only honest way to tell the two apart.
 */
function lh_finish_strip_comments(string $source): string
{
    $out = '';
    foreach (token_get_all($source) as $token) {
        if (is_array($token)) {
            if ($token[0] === T_COMMENT || $token[0] === T_DOC_COMMENT) {
                continue;
            }
            $out .= $token[1];
            continue;
        }
        $out .= $token;
    }
    return $out;
}

return [

    'the service and both timers are enabled by one pasteable command' => function (): void {
        $group = lh_finish_group(lh_finish_config(), 'ingest');

        lh_same(1, count($group['lines']), 'the unit step is one line');
        $line = $group['lines'][0];
        lh_contains($line, 'systemctl enable --now', 'it uses enable --now');
        foreach (['loghound-tail.service', 'loghound-score.timer', 'loghound-retention.timer'] as $unit) {
            lh_contains($line, $unit, 'the merged command names ' . $unit);
        }
        lh_same(1, preg_match_all('/systemctl/', $line), 'systemctl is invoked exactly once');
    },

    'every next-step snippet is a single line, so a copy button yields something runnable'
        => function (): void {
            $cfg = lh_finish_config();
            $cfg->set('base_url', 'https://logs.example.org');

            foreach (Steps::nextSteps($cfg, '/opt/loghound') as $group) {
                foreach ($group['lines'] as $line) {
                    lh_false(
                        str_contains($line, "\n") || str_contains($line, "\r"),
                        'group ' . $group['key'] . ' line is single-line'
                    );
                }
                lh_true(count($group['lines']) <= 1, 'group ' . $group['key'] . ' has at most one line');
            }
        },

    'the status command is built from the installation root it was handed' => function (): void {
        $group = lh_finish_group(lh_finish_config(), 'status', '/srv/loghound/');
        lh_same('/srv/loghound/bin/loghound-tail --status --human', $group['lines'][0], 'status command');
    },

    'an unset base_url yields a problem to fix, never a placeholder snippet' => function (): void {
        $cfg = lh_finish_config();
        $group = lh_finish_group($cfg, 'beacon');

        lh_same([], $group['lines'], 'no snippet is offered');
        lh_true($group['problem'] !== '', 'a problem sentence is given instead');
        lh_contains($group['problem'], 'base_url', 'it names the setting to fix');

        foreach (Steps::nextSteps($cfg, '/opt/loghound') as $one) {
            foreach ($one['lines'] as $line) {
                lh_false(str_contains($line, 'example.com'), 'no line mentions a placeholder host');
            }
        }
    },

    'a base_url carrying credentials is refused for the snippet, with a reason' => function (): void {
        $cfg = lh_finish_config();
        $cfg->set('base_url', 'https://someone:hunter2@logs.example.org');
        $group = lh_finish_group($cfg, 'beacon');

        lh_same([], $group['lines'], 'no snippet is built from a URL with userinfo');
        lh_false(str_contains($group['problem'], 'hunter2'), 'the password is not echoed back');
    },

    'a base_url that is not http(s) is refused for the snippet' => function (): void {
        foreach (['javascript:alert(1)', 'ftp://logs.example.org', 'logs.example.org'] as $bad) {
            $cfg = lh_finish_config();
            $cfg->set('base_url', $bad);
            $group = lh_finish_group($cfg, 'beacon');
            lh_same([], $group['lines'], 'no snippet from ' . $bad);
            lh_true($group['problem'] !== '', 'a reason is given for ' . $bad);
        }
    },

    'a configured base_url produces the one-line beacon tag' => function (): void {
        $cfg = lh_finish_config();
        $cfg->set('base_url', 'https://logs.example.org/');
        $group = lh_finish_group($cfg, 'beacon');

        lh_same('', $group['problem'], 'nothing to fix');
        lh_same(
            '<script src="https://logs.example.org/b.js?v=1" defer></script>',
            $group['lines'][0],
            'beacon snippet'
        );
    },

    'ingestion liveness comes from the tailer status document, and says which state it is in'
        => function (): void {
            $root = lh_tmpdir('lh_finish');
            try {
                lh_same('absent', Steps::ingestStatus($root)['state'], 'nothing written yet');

                lh_finish_write_status($root);
                $live = Steps::ingestStatus($root);
                lh_same('live', $live['state'], 'a document written now');
                lh_same(12, $live['lines'], 'the line total is carried through');
                lh_same(1, $live['sources'], 'the source count is carried through');
                lh_true($live['age_sec'] <= Steps::TAIL_STALE_AFTER, 'the age is inside the window');

                lh_finish_write_status($root, [
                    'generated_at' => gmdate('Y-m-d\TH:i:s\Z', time() - (Steps::TAIL_STALE_AFTER + 60)),
                ]);
                lh_same('stale', Steps::ingestStatus($root)['state'], 'an old document is leftovers');

                file_put_contents($root . '/var/tail-status.json', 'not json at all');
                lh_same('unreadable', Steps::ingestStatus($root)['state'], 'garbage is not silently absent');
            } finally {
                lh_rmtree($root);
            }
        },

    'ingestStatus never fabricates a number it was not given' => function (): void {
        $root = lh_tmpdir('lh_finish');
        try {
            mkdir($root . '/var', 0700, true);
            file_put_contents(
                $root . '/var/tail-status.json',
                (string) json_encode(['generated_at' => gmdate('Y-m-d\TH:i:s\Z')])
            );
            $s = Steps::ingestStatus($root);
            lh_same('live', $s['state'], 'still live: the document is current');
            foreach (['lag_bytes', 'lines', 'indexed', 'sources'] as $absent) {
                lh_same(null, $s[$absent], $absent . ' is null, not zero');
            }
        } finally {
            lh_rmtree($root);
        }
    },

    'the Settings page carries the finish card, rendering the same merged command'
        => function (): void {
            $cfg = lh_finish_config();
            $cfg->set('base_url', 'https://logs.example.org');
            $html = lh_finish_settings_html($cfg);

            lh_contains($html, 'id="set-finish-card"', 'the card is on the page');
            lh_contains($html, 'Finish setting up', 'and is headed as such');
            lh_contains(
                $html,
                'systemctl enable --now loghound-tail.service loghound-score.timer loghound-retention.timer',
                'the merged command is rendered'
            );
            lh_contains($html, 'id="finish-ingest"', 'ingestion state is reported');
            lh_contains($html, 'id="finish-beacon"', 'beacon state is reported');
        },

    'the finish card is the first card on the Settings page' => function (): void {
        $html = lh_finish_settings_html(lh_finish_config());
        $finish = strpos($html, 'id="set-finish-card"');
        $sources = strpos($html, 'id="set-sources-card"');
        lh_true(is_int($finish) && is_int($sources), 'both cards render');
        lh_true($finish < $sources, 'the finish card comes first');
    },

    'the finish card offers a copy control per snippet, with no inline handler'
        => function (): void {
            $cfg = lh_finish_config();
            $cfg->set('base_url', 'https://logs.example.org');
            $html = lh_finish_settings_html($cfg);

            foreach (['finish-cmd-ingest', 'finish-cmd-status', 'finish-cmd-beacon'] as $id) {
                lh_contains($html, 'id="' . $id . '"', $id . ' is a copyable block');
                lh_contains($html, 'data-copy="' . $id . '"', $id . ' has a copy button');
            }
            lh_false(str_contains($html, 'onclick'), 'no inline click handler');
            lh_false(str_contains($html, 'javascript:'), 'no javascript: URL');
        },

    'a snippet that cannot be built carries no copy button' => function (): void {
        $html = lh_finish_settings_html(lh_finish_config());
        lh_contains($html, 'data-copy="finish-cmd-ingest"', 'the unit command is still copyable');
        lh_false(
            str_contains($html, 'data-copy="finish-cmd-beacon"'),
            'no copy button over a beacon snippet that does not exist'
        );
    },

    'the panel claims nothing about boot persistence that it has not checked' => function (): void {
        $cfg = lh_finish_config();
        $html = lh_finish_settings_html($cfg);
        lh_contains($html, 'cannot see whether they are enabled at boot', 'the limit is stated plainly');

        $group = lh_finish_group($cfg, 'ingest');
        lh_contains($group['title'], 'reboot', 'the title says what enable buys');
    },

    'nothing that answers these questions executes a process' => function (): void {
        $files = array_merge(
            (array) glob(__DIR__ . '/../src/*.php'),
            (array) glob(__DIR__ . '/../src/*/*.php'),
            (array) glob(__DIR__ . '/../public/*.php')
        );
        lh_true(count($files) > 20, 'the sweep found the tree');

        $patterns = [
            'exec'       => '/(?<![\w>:$\-])exec\s*\(/',
            'shell_exec' => '/(?<![\w>:$\-])shell_exec\s*\(/',
            'proc_open'  => '/(?<![\w>:$\-])proc_open\s*\(/',
            'passthru'   => '/(?<![\w>:$\-])passthru\s*\(/',
            'popen'      => '/(?<![\w>:$\-])popen\s*\(/',
            'system'     => '/(?<![\w>:$\-])system\s*\(/',
        ];

        foreach ($files as $file) {
            $body = lh_finish_strip_comments((string) file_get_contents($file));
            foreach ($patterns as $name => $pattern) {
                lh_same(
                    0,
                    preg_match($pattern, $body),
                    basename($file) . ' must not call ' . $name . '()'
                );
            }
        }
    },

];
