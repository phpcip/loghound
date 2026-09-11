<?php
/**
 * Loghound — tests for the job store's extension points.
 *
 * The panel's stepped-job machinery was reachable from exactly one view: the front
 * controller routed POST by naming a concrete class, and the list of job kinds was a
 * closed constant. Any view that grew an asynchronous operation was therefore dead on
 * arrival — its button posted, the router answered 405, and nothing said why.
 *
 * These tests pin the two things that fixed it, and pin them as CONTRACTS rather than as
 * implementation details: routing happens on the JobHost capability, and a view supplies
 * its own kinds and their parameters. The parameter path gets the heavier scrutiny,
 * because it is new attack surface — a browser now names a job's target.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Config;
use Loghound\Panel\Gateway;
use Loghound\Panel\JobHost;
use Loghound\Panel\Jobs;
use Loghound\Panel\Settings;
use Loghound\Solr;

/**
 * A job store bound to a throwaway operator identity, optionally carrying extra plans.
 *
 * The identity is salted with a per-run random value. The store is a real SQLite file that
 * outlives the process, and `start()` is idempotent per owner, kind and target — so a fixed
 * identity would make the second run of this file receive the FIRST run's still-pending job
 * and never reach the code under test. Two calls with the same $identity inside one run
 * still describe the same operator, which is what the ownership tests need.
 *
 * @param array<string,callable> $extraPlans
 */
function lh_jobs_store(string $identity, array $extraPlans = []): Jobs
{
    static $salt = null;
    if ($salt === null) {
        $salt = bin2hex(random_bytes(8));
    }

    $_SESSION['lh_job_owner'] = $identity . '-' . $salt;
    $_SESSION['lh_user'] = 'tester';

    $cfg = Config::load('/nonexistent-loghound-config');
    $cfg->set('solr.base_url', 'http://127.0.0.1:65535/solr');
    $cfg->set('solr.hits_core', 'lh_test_hits');
    $cfg->set('solr.sessions_core', 'lh_test_sessions');

    $transport = static fn (array $request): array => [
        'status' => 200,
        'body'   => (string) json_encode(['responseHeader' => ['status' => 0]]),
        'error'  => '',
    ];

    $gw = new Gateway($cfg, new Solr((array) $cfg->get('solr'), $transport), false);

    return new Jobs($cfg, $gw, $extraPlans);
}

/**
 * A one-step plan that records the context it was planned with and reports a note.
 *
 * @param array<int,array<string,mixed>> $seen Filled with every context the planner saw.
 * @return callable(array<string,mixed>):array<int,array{label:string,run:callable}>
 */
function lh_jobs_probe_plan(array &$seen): callable
{
    return static function (array $ctx) use (&$seen): array {
        $seen[] = $ctx;
        return [
            [
                'label' => 'Probing ' . (string) ($ctx['core'] ?? 'nothing'),
                'run'   => static fn (array $c): array => ['note' => 'saw:' . (string) ($c['core'] ?? '')],
            ],
        ];
    };
}

return [

    'the front controller routes POST on the JobHost capability, not on a class name'
        => static function (): void {
            $source = (string) file_get_contents(__DIR__ . '/../public/index.php');

            if (str_contains($source, '$view instanceof Settings')) {
                throw new \RuntimeException(
                    'index.php still routes POST by naming Settings, so no other view can host a job.'
                );
            }
            if (!str_contains($source, '$view instanceof JobHost')) {
                throw new \RuntimeException('index.php does not route POST on JobHost.');
            }
            if (!is_a(Settings::class, JobHost::class, true)) {
                throw new \RuntimeException('Settings no longer accepts POST, which breaks every settings form.');
            }
        },

    'a read-only view cannot be POSTed to' => static function (): void {
        foreach (['Overview', 'Bots', 'Fingerprints', 'Networks', 'Sessions', 'Performance'] as $view) {
            $class = 'Loghound\\Panel\\' . $view;
            if (!class_exists($class)) {
                continue;
            }
            if (is_a($class, JobHost::class, true)) {
                throw new \RuntimeException($view . ' implements JobHost but has no reason to accept POST.');
            }
        }
    },

    'a view supplies its own kind, and it is startable' => static function (): void {
        $seen = [];
        $jobs = lh_jobs_store('owner-extend-1', ['probe_scan' => lh_jobs_probe_plan($seen)]);

        if (!in_array('probe_scan', $jobs->kinds(), true)) {
            throw new \RuntimeException('A registered kind is missing from kinds().');
        }
        foreach (Jobs::KINDS as $builtin) {
            if (!in_array($builtin, $jobs->kinds(), true)) {
                throw new \RuntimeException('Registering a kind dropped the built-in ' . $builtin . '.');
            }
        }

        $job = $jobs->start('probe_scan', ['core' => 'lh_a1b2c3d4_hits']);
        if (isset($job['error'])) {
            throw new \RuntimeException('Starting a registered kind failed: ' . (string) $job['error']);
        }
        if ($seen === [] || ($seen[0]['core'] ?? null) !== 'lh_a1b2c3d4_hits') {
            throw new \RuntimeException('The planner was not handed the parameters start() was given.');
        }
    },

    'an unregistered kind is still refused' => static function (): void {
        $jobs = lh_jobs_store('owner-extend-2');
        $job  = $jobs->start('probe_scan');
        if (!isset($job['error'])) {
            throw new \RuntimeException('A kind nobody registered was accepted.');
        }
        if ($jobs->latest('probe_scan') !== null) {
            throw new \RuntimeException('latest() answered for an unregistered kind.');
        }
    },

    'a registered kind may not shadow a built-in one' => static function (): void {
        foreach (Jobs::KINDS as $builtin) {
            $threw = false;
            try {
                lh_jobs_store('owner-extend-3', [$builtin => static fn (array $c): array => []]);
            } catch (\RuntimeException $e) {
                $threw = true;
            }
            if (!$threw) {
                throw new \RuntimeException('A view was allowed to redefine the built-in kind ' . $builtin . '.');
            }
        }
    },

    'a kind name that is not a plain identifier is refused' => static function (): void {
        foreach (['', 'a', 'Probe', 'probe scan', 'probe-scan', '../x', 'probe;drop', str_repeat('p', 40)] as $bad) {
            $threw = false;
            try {
                lh_jobs_store('owner-extend-4', [$bad => static fn (array $c): array => []]);
            } catch (\RuntimeException $e) {
                $threw = true;
            }
            if (!$threw) {
                throw new \RuntimeException('Accepted a job kind named ' . var_export($bad, true) . '.');
            }
        }
    },

    'two targets of the same kind are two jobs, not one' => static function (): void {
        $seen = [];
        $jobs = lh_jobs_store('owner-target-1', ['probe_scan' => lh_jobs_probe_plan($seen)]);

        $first  = $jobs->start('probe_scan', ['core' => 'core_one']);
        $second = $jobs->start('probe_scan', ['core' => 'core_two']);

        if (($first['id'] ?? 'a') === ($second['id'] ?? 'b')) {
            throw new \RuntimeException(
                'Scanning a second index handed back the first index\'s job, so the page would '
                . 'report the wrong index\'s progress.'
            );
        }
    },

    'the same target is idempotent however the fields were ordered' => static function (): void {
        $seen = [];
        $jobs = lh_jobs_store('owner-target-2', ['probe_scan' => lh_jobs_probe_plan($seen)]);

        $first  = $jobs->start('probe_scan', ['core' => 'core_one', 'range' => '7d']);
        $second = $jobs->start('probe_scan', ['range' => '7d', 'core' => 'core_one']);

        if (($first['id'] ?? 'a') !== ($second['id'] ?? 'b')) {
            throw new \RuntimeException('A double-clicked button started a second copy of the same scan.');
        }
    },

    'job parameters must be flat, bounded scalars' => static function (): void {
        $seen = [];
        $jobs = lh_jobs_store('owner-params-1', ['probe_scan' => lh_jobs_probe_plan($seen)]);

        $rejected = [
            'nested array'      => ['core' => ['a', 'b']],
            'object'            => ['core' => new \stdClass()],
            'oversized string'  => ['core' => str_repeat('x', 257)],
            'hostile key'       => ['../core' => 'x'],
            'upper-case key'    => ['Core' => 'x'],
            'numeric key'       => [0 => 'x'],
            'too many fields'   => array_combine(
                array_map(static fn (int $i): string => 'f' . $i, range(1, 13)),
                array_fill(0, 13, 'v')
            ),
        ];

        foreach ($rejected as $why => $params) {
            $job = $jobs->start('probe_scan', $params);
            if (!isset($job['error'])) {
                throw new \RuntimeException('Accepted job parameters that should have been refused: ' . $why);
            }
        }
    },

    'a parameterised job replans from its stored parameters on every poll'
        => static function (): void {
            $seen = [];
            $jobs = lh_jobs_store('owner-replan-1', ['probe_scan' => lh_jobs_probe_plan($seen)]);

            $started = $jobs->start('probe_scan', ['core' => 'persisted_core']);
            $id = (string) ($started['id'] ?? '');
            if ($id === '') {
                throw new \RuntimeException('The job did not start.');
            }

            $seen = [];
            $jobs->advance($id);

            if ($seen === []) {
                throw new \RuntimeException('advance() did not replan the job.');
            }
            foreach ($seen as $ctx) {
                if (($ctx['core'] ?? null) !== 'persisted_core') {
                    throw new \RuntimeException(
                        'The plan was rebuilt without the parameters the job was started with, so a '
                        . 'poll would run the wrong target.'
                    );
                }
            }
        },

    'a job started by one operator is invisible to another' => static function (): void {
        $seen = [];
        $mine = lh_jobs_store('owner-isolation-a', ['probe_scan' => lh_jobs_probe_plan($seen)]);
        $job  = $mine->start('probe_scan', ['core' => 'private_core']);
        $id   = (string) ($job['id'] ?? '');

        $theirs = lh_jobs_store('owner-isolation-b', ['probe_scan' => lh_jobs_probe_plan($seen)]);

        $stolen = $theirs->get($id);
        if (!isset($stolen['error'])) {
            throw new \RuntimeException('Another operator could read a job that was not theirs.');
        }
        if ($theirs->latest('probe_scan') !== null) {
            throw new \RuntimeException('latest() leaked another operator\'s job.');
        }
    },

    'a planner that returns no steps refuses the job instead of storing an empty one'
        => static function (): void {
            $jobs = lh_jobs_store('owner-empty-1', ['probe_scan' => static fn (array $c): array => []]);
            $job  = $jobs->start('probe_scan', ['core' => 'x']);
            if (!isset($job['error'])) {
                throw new \RuntimeException('An empty plan produced a job that can never finish.');
            }
        },
];
