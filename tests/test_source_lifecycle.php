<?php
/**
 * Loghound — tests for the whole life of a log source: find it, confirm it, drop it.
 *
 * Three gaps closed here, each of which LOOKED finished and left the operator stuck:
 *
 *  - The confirmation screen pre-ticked a discovered source only when it already sat inside
 *    `allowed_log_roots`, so a file the operator's own webserver configuration pointed at
 *    arrived unticked. Clicking straight through a screen that looked complete ingested
 *    nothing from it and said nothing about that. `widen[]` is the opposite case and must
 *    stay unticked forever — it is the consent that authorises reading outside those roots.
 *  - One refused source aborted the entire confirmation step, so a single un-widened file
 *    blocked the six that were fine, in the middle of an installation, with no control on
 *    the screen that changed it.
 *  - The list was frozen at install time. A host added three months later meant hand-editing
 *    a PHP file deliberately kept outside the document root at mode 0640.
 *
 * The removal tests are the security-weighted ones, because removal is the destructive half:
 * the request names a source by an id the server resolves against its own stored list, so
 * neither a path nor a list position from the form is ever acted on.
 *
 * No network: Solr points at a closed loopback port and nothing here contacts Opensolr.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Config;
use Loghound\Panel\Gateway;
use Loghound\Panel\Jobs;
use Loghound\Panel\Settings;
use Loghound\Setup\Detector;
use Loghound\Setup\Steps;
use Loghound\Solr;

/**
 * A throwaway installation with one log inside the allowed roots and one outside them.
 *
 * The outside file is a real copy of the same fixture: the point is that it is perfectly
 * parseable and still refused, because the refusal is about permission and not about
 * whether the file makes sense.
 *
 * @return array{0:string,1:Config,2:string,3:string} [root, config, inside path, outside path]
 */
function lh_life_scaffold(): array
{
    $root = lh_tmpdir('lhlife');
    mkdir($root . '/config', 0700, true);
    mkdir($root . '/var', 0750, true);
    mkdir($root . '/logs', 0750, true);
    mkdir($root . '/elsewhere', 0750, true);

    $inside  = $root . '/logs/access.log';
    $outside = $root . '/elsewhere/other.log';
    copy(lh_fixture('apache_combined_human.log'), $inside);
    copy(lh_fixture('apache_combined_human.log'), $outside);

    $cfg = Config::load($root . '/config/loghound.php');
    $cfg->set('allowed_log_roots', [$root . '/logs']);
    $cfg->set('discover', [
        'apache_configs'    => [],
        'apache_vhost_dirs' => [],
        'nginx_configs'     => [],
        'nginx_vhost_dirs'  => [],
        'fallback_globs'    => [$root . '/logs/*.log', $root . '/elsewhere/*.log'],
    ]);

    return [$root, $cfg, $inside, $outside];
}

/** A Settings controller on a given config, with demo mode as asked and no reachable Solr. */
function lh_life_settings(Config $cfg, bool $demo = false): Settings
{
    $solr = new Solr(
        (array) $cfg->get('solr', []),
        static fn (array $req): array => ['status' => 0, 'body' => '', 'error' => 'no network in tests']
    );
    return new Settings($cfg, new Gateway($cfg, $solr, $demo));
}

/**
 * Call a private method on a view.
 *
 * The job endpoints are reached through post(), which answers with JSON and exits, so a test
 * cannot drive them without taking the process down with it. The pieces post() is made of —
 * the kind list and the plan — carry the behaviour worth pinning, so they are called
 * directly, the same way tests/test_opensolr_analytics.php reaches the Opensolr views' own.
 *
 * @param array<int,mixed> $args
 * @return mixed
 */
function lh_life_call(object $view, string $method, array $args = [])
{
    return (new ReflectionMethod($view, $method))->invokeArgs($view, $args);
}

/**
 * A job store bound to a throwaway operator identity, carrying a view's own plans.
 *
 * Salted per run for the reason tests/test_jobs.php gives: the store is a real file that
 * outlives the process and start() is idempotent per owner, kind and target, so a fixed
 * identity would hand the second run of this file the first run's still-pending job.
 *
 * @param array<string,callable> $plans
 */
function lh_life_jobs(Config $cfg, array $plans): Jobs
{
    static $salt = null;
    if ($salt === null) {
        $salt = bin2hex(random_bytes(8));
    }
    $_SESSION['lh_job_owner'] = 'lifecycle-' . $salt . '-' . bin2hex(random_bytes(4));
    $_SESSION['lh_user'] = 'tester';

    $solr = new Solr(
        (array) $cfg->get('solr', []),
        static fn (array $req): array => ['status' => 0, 'body' => '', 'error' => 'no network in tests']
    );
    return new Jobs($cfg, new Gateway($cfg, $solr, false), $plans);
}

/** Run a job to completion, one step per call, and return its final shape. */
function lh_life_drain(Jobs $jobs, string $id, int $limit = 20): array
{
    $job = $jobs->get($id);
    for ($i = 0; $i < $limit && empty($job['done']); $i++) {
        $job = $jobs->advance($id);
    }
    return $job;
}

/** The identifier the remove form addresses a stored source by. */
function lh_life_source_id(string $path): string
{
    return substr(hash('sha256', $path), 0, 16);
}

return [

    /* -----------------------------------------------------------------------------
     * The confirmation screen
     * -------------------------------------------------------------------------- */

    'every discovered source arrives ticked, including one outside the allowed roots'
        => static function (): void {
            if (!function_exists('lh_inst_request')) {
                lh_skip('the installer request harness is not loaded');
            }
            [$root, $cfg, $inside, $outside] = lh_life_scaffold();
            $cfg->save();

            Detector::runSync(Config::load($root . '/config/loghound.php'));
            $report = Detector::lastReport(Config::load($root . '/config/loghound.php'));
            $paths = array_map(static fn (array $s): string => (string) $s['path'], (array) $report['sources']);

            lh_true(in_array($inside, $paths, true), 'the inside log was discovered');
            lh_true(in_array($outside, $paths, true), 'the outside log was discovered');

            $html = lh_inst_request($root, ['setup' => 'sources'], [], 'GET', true)['out'];

            foreach ($paths as $i => $path) {
                lh_contains(
                    $html,
                    'name="pick[]" value="' . $i . '" checked',
                    'a discovered source must arrive ticked, or clicking through ingests nothing '
                    . 'from it and says nothing about that: ' . $path
                );
            }

            $outsideIndex = (int) array_search($outside, $paths, true);
            lh_contains(
                $html,
                'name="widen[]" value="' . $outsideIndex . '">',
                'the widening consent must be offered for the outside source'
            );
            lh_true(
                !str_contains($html, 'name="widen[]" value="' . $outsideIndex . '" checked'),
                'widen[] is the consent that authorises reading outside allowed_log_roots and '
                . 'must never be pre-ticked'
            );

            lh_rmtree($root);
        },

    /* -----------------------------------------------------------------------------
     * Partial confirmation
     * -------------------------------------------------------------------------- */

    'a refused source does not block the sources that were fine' => static function (): void {
        if (!function_exists('lh_inst_request')) {
            lh_skip('the installer request harness is not loaded');
        }
        [$root, $cfg, $inside, $outside] = lh_life_scaffold();
        $cfg->save();

        Detector::runSync(Config::load($root . '/config/loghound.php'));
        $report = Detector::lastReport(Config::load($root . '/config/loghound.php'));
        $paths = array_map(static fn (array $s): string => (string) $s['path'], (array) $report['sources']);

        $pick = array_map('strval', array_keys($paths));
        lh_inst_request(
            $root,
            [],
            ['step' => 'sources', 'action' => 'confirm', 'pick' => $pick],
            'POST',
            true
        );

        $stored = (array) (Config::load($root . '/config/loghound.php')->get('sources', []));
        lh_same(1, count($stored), 'the storable source must be stored despite the refused one');
        lh_same($inside, (string) $stored[0]['path'], 'and it must be the one inside the roots');

        $roots = (array) Config::load($root . '/config/loghound.php')->get('allowed_log_roots', []);
        lh_true(
            !in_array(dirname($outside), $roots, true),
            'an unticked widening must never widen the roots on its own'
        );

        $next = lh_inst_request($root, ['setup' => 'storage'], [], 'GET', true)['out'];
        lh_contains($next, '1 log file confirmed', 'the step must say what it did');
        lh_contains($next, '1 was not stored', 'and that something was not stored');
        lh_contains($next, $outside, 'naming the source it refused');
        lh_contains($next, 'outside the directories', 'and the reason it refused it');

        lh_rmtree($root);
    },

    'a confirmation that could store nothing at all is still a failure' => static function (): void {
        if (!function_exists('lh_inst_request')) {
            lh_skip('the installer request harness is not loaded');
        }
        [$root, $cfg, $inside, $outside] = lh_life_scaffold();
        $cfg->set('allowed_log_roots', [$root . '/nowhere']);
        mkdir($root . '/nowhere', 0750, true);
        $cfg->save();

        Detector::runSync(Config::load($root . '/config/loghound.php'));
        $report = Detector::lastReport(Config::load($root . '/config/loghound.php'));
        $pick = array_map('strval', array_keys((array) $report['sources']));

        lh_inst_request(
            $root,
            [],
            ['step' => 'sources', 'action' => 'confirm', 'pick' => $pick],
            'POST',
            true
        );

        lh_same(
            [],
            (array) Config::load($root . '/config/loghound.php')->get('sources', []),
            'nothing storable means nothing stored'
        );

        $next = lh_inst_request($root, ['setup' => 'sources'], [], 'GET', true)['out'];
        lh_contains($next, 'banner-bad', 'and the step must report a plain failure, not a partial success');
        lh_contains($next, 'Nothing was stored', 'saying so in words');

        lh_rmtree($root);
    },

    'applySourcesReport names every stored and every refused path' => static function (): void {
        [$root, $cfg, $inside, $outside] = lh_life_scaffold();

        $result = Steps::applySourcesReport($cfg, [
            ['path' => $inside,  'format_name' => 'apache_combined'],
            ['path' => $outside, 'format_name' => 'apache_combined'],
            ['path' => $inside,  'format_name' => 'unrecognised'],
        ]);

        lh_same([$inside], $result['stored'], 'the storable path is reported as stored');
        lh_same(2, count($result['refused']), 'both refusals are reported individually');
        lh_same($outside, $result['refused'][0]['path'], 'the refused path is named');
        lh_contains($result['refused'][0]['message'], 'outside the directories', 'with its reason');
        lh_contains($result['refused'][1]['message'], 'No usable format', 'and so is the second');
        lh_same([], $result['widening'], 'nothing was asked to be widened');

        lh_same(
            ['stored', 'refused', 'widening'],
            array_keys($result),
            'the report shape callers depend on'
        );

        lh_rmtree($root);
    },

    'applySources still answers with the flat problem list its callers expect'
        => static function (): void {
            [$root, $cfg, $inside, $outside] = lh_life_scaffold();

            lh_same(
                [],
                Steps::applySources($cfg, [['path' => $inside, 'format_name' => 'apache_combined']]),
                'a clean apply reports no problems'
            );
            $problems = Steps::applySources($cfg, [['path' => $outside, 'format_name' => 'apache_combined']]);
            lh_same(1, count($problems), 'a refusal is one problem');
            lh_contains($problems[0], $outside, 'naming the path');

            lh_rmtree($root);
        },

    /* -----------------------------------------------------------------------------
     * Editing the list after installation
     * -------------------------------------------------------------------------- */

    'a configured source can be removed, by an id the server resolves itself'
        => static function (): void {
            [$root, $cfg, $inside, $outside] = lh_life_scaffold();
            $cfg->set('sources', [
                ['path' => $inside, 'format' => 'apache_combined', 'confirmed' => true],
                ['path' => $outside, 'format' => 'apache_combined', 'confirmed' => true],
            ]);
            $cfg->save();

            $view = lh_life_settings($cfg);
            $saved = $_POST;
            try {
                $_POST = ['action' => 'remove_source', 'source' => lh_life_source_id($inside)];
                lh_same('?v=settings&ok=source_removed', $view->post(), 'the removal is accepted');
            } finally {
                $_POST = $saved;
            }

            $left = (array) Config::load($root . '/config/loghound.php')->get('sources', []);
            lh_same(1, count($left), 'exactly one source is left');
            lh_same($outside, (string) $left[0]['path'], 'and it is the one that was not named');

            lh_rmtree($root);
        },

    'removal refuses a path, an index, or an id for something not configured'
        => static function (): void {
            [$root, $cfg, $inside, $outside] = lh_life_scaffold();
            $cfg->set('sources', [['path' => $inside, 'format' => 'apache_combined', 'confirmed' => true]]);
            $cfg->save();

            $view = lh_life_settings($cfg);
            $saved = $_POST;
            try {
                foreach ([
                    'a path taken on trust'   => ['path' => $inside],
                    'a list index'            => ['source' => '0'],
                    'an id of the right shape for a source nobody configured'
                                              => ['source' => lh_life_source_id('/var/log/somebody-elses.log')],
                    'an id that is not an id' => ['source' => '../../etc/passwd'],
                    'nothing at all'          => [],
                ] as $why => $extra) {
                    $_POST = array_merge(['action' => 'remove_source'], $extra);
                    lh_same(
                        '?v=settings&err=no_such_source',
                        $view->post(),
                        'removal must refuse ' . $why
                    );
                }
            } finally {
                $_POST = $saved;
            }

            lh_same(
                1,
                count((array) Config::load($root . '/config/loghound.php')->get('sources', [])),
                'and none of them removed anything'
            );

            lh_rmtree($root);
        },

    'there is no synchronous rescan action to time out' => static function (): void {
        [$root, $cfg] = lh_life_scaffold();
        $cfg->save();

        $view = lh_life_settings($cfg);
        $saved = $_POST;
        try {
            $_POST = ['action' => 'rescan'];
            lh_same(
                '?v=settings&err=unknown_action',
                $view->post(),
                'a scan walks the webserver config tree and samples up to twenty files, so it '
                . 'must not be reachable as a plain POST that FPM can kill halfway'
            );
        } finally {
            $_POST = $saved;
        }

        lh_rmtree($root);
    },

    'neither editing action is reachable through the read-only GET surface'
        => static function (): void {
            [$root, $cfg, $inside] = lh_life_scaffold();
            $cfg->set('sources', [['path' => $inside, 'format' => 'apache_combined', 'confirmed' => true]]);
            $cfg->save();

            $view = lh_life_settings($cfg);
            $saved = $_GET;
            try {
                foreach (['remove_source', 'confirm_source', 'rescan', 'job_start'] as $action) {
                    $_GET = ['source' => lh_life_source_id($inside), 'kind' => 'source_rescan'];
                    lh_same(
                        ['error' => 'Unknown action'],
                        $view->api($action),
                        'a state-changing action must not answer on the GET/JSON surface: ' . $action
                    );
                }
            } finally {
                $_GET = $saved;
            }

            lh_same(
                1,
                count((array) Config::load($root . '/config/loghound.php')->get('sources', [])),
                'and nothing was changed by asking'
            );

            lh_rmtree($root);
        },

    'the settings page hosts the rescan as one of its own job kinds' => static function (): void {
        [$root, $cfg] = lh_life_scaffold();
        $cfg->save();

        $view = lh_life_settings($cfg);
        $kinds = (array) lh_life_call($view, 'jobKinds');
        $plans = (array) lh_life_call($view, 'jobPlans');

        lh_true(in_array('source_rescan', $kinds, true), 'the rescan kind is offered');
        lh_has_key($plans, 'source_rescan', 'and a planner is registered for it');
        foreach (Jobs::KINDS as $builtin) {
            lh_true(in_array($builtin, $kinds, true), 'registering a kind kept the built-in ' . $builtin);
        }

        lh_rmtree($root);
    },

    'a rescan runs as bounded steps and republishes the detection report'
        => static function (): void {
            [$root, $cfg, $inside] = lh_life_scaffold();
            $cfg->save();

            $cfg = Config::load($root . '/config/loghound.php');
            $view = lh_life_settings($cfg);
            $jobs = lh_life_jobs($cfg, (array) lh_life_call($view, 'jobPlans'));

            $started = $jobs->start('source_rescan');
            lh_true(
                ($started['error'] ?? null) === null,
                'the rescan must start: ' . (string) ($started['error'] ?? '')
            );
            lh_true((int) $started['total'] > 1, 'and must be more than one step, or it is not stepped at all');

            $job = lh_life_drain($jobs, (string) $started['id']);
            lh_same('done', (string) $job['state'], 'the rescan finished: ' . (string) ($job['error'] ?? ''));

            $written = $root . '/var/detect.json';
            lh_true(is_file($written), 'the report was republished');
            $report = json_decode((string) file_get_contents($written), true);
            $paths = array_map(
                static fn (array $s): string => (string) $s['path'],
                (array) ($report['sources'] ?? [])
            );
            lh_true(in_array($inside, $paths, true), 'and it names the log that is there');

            lh_same([], (array) $cfg->get('sources', []), 'a scan on its own ingests nothing');

            lh_rmtree($root);
        },

    'a rescan carries forward what is already confirmed' => static function (): void {
        [$root, $cfg, $inside] = lh_life_scaffold();
        $cfg->set('sources', [['path' => $inside, 'format' => 'apache_combined', 'confirmed' => true]]);
        $cfg->save();

        $cfg = Config::load($root . '/config/loghound.php');
        $view = lh_life_settings($cfg);
        $jobs = lh_life_jobs($cfg, (array) lh_life_call($view, 'jobPlans'));

        $started = $jobs->start('source_rescan');
        lh_life_drain($jobs, (string) $started['id']);

        $report = json_decode((string) file_get_contents($root . '/var/detect.json'), true);
        $confirmed = [];
        foreach ((array) ($report['sources'] ?? []) as $src) {
            $confirmed[(string) $src['path']] = (bool) ($src['confirmed'] ?? false);
        }
        lh_true($confirmed[$inside] ?? false, 'a rescan must not un-confirm a source that is ingesting');

        lh_rmtree($root);
    },

    'demo mode offers neither the rescan button nor the rescan kind' => static function (): void {
        [$root, $cfg] = lh_life_scaffold();
        $cfg->save();

        $view = lh_life_settings($cfg, true);
        lh_same([], (array) lh_life_call($view, 'jobPlans'), 'no planner is registered in demo mode');
        lh_true(
            !in_array('source_rescan', (array) lh_life_call($view, 'jobKinds'), true),
            'so the kind is refused at start, at poll and at cancel'
        );

        $saved = $_GET;
        try {
            $_GET = [];
            ob_start();
            $view->body();
            $html = (string) ob_get_clean();
        } finally {
            $_GET = $saved;
        }
        lh_true(
            !str_contains($html, 'data-job="source_rescan"'),
            'a panel showing fabricated data must not offer to scan the real machine'
        );

        lh_rmtree($root);
    },

    'the source review offers the whole loop: scan, confirm, remove' => static function (): void {
        [$root, $cfg, $inside] = lh_life_scaffold();
        $cfg->set('sources', [['path' => $inside, 'format' => 'apache_combined', 'confirmed' => true]]);
        $cfg->save();

        $saved = $_GET;
        try {
            $_GET = [];
            ob_start();
            lh_life_settings(Config::load($root . '/config/loghound.php'))->body();
            $html = (string) ob_get_clean();
        } finally {
            $_GET = $saved;
        }

        lh_contains($html, 'data-job="source_rescan"', 'the scan control is on the page');
        lh_contains($html, 'name="action" value="remove_source"', 'and so is the removal control');
        lh_contains(
            $html,
            'name="source" value="' . lh_life_source_id($inside) . '"',
            'which names the source by its id, never by its path'
        );
        lh_true(
            !str_contains($html, 'name="action" value="remove_source"><input type="hidden" name="path"'),
            'the removal form must not carry a path for the server to trust'
        );

        lh_rmtree($root);
    },
];
