<?php
/**
 * Loghound — plan quota, the rolling retention window, and the vhost dimension.
 *
 * WHAT THESE TESTS ARE PROTECTING. \Loghound\Quota deletes the operator's data. A wrong
 * cutoff is not a rendering bug that someone notices and fixes; it is traffic history that
 * no longer exists. So the cutoff arithmetic is exercised on its own, as a pure function,
 * including every case in which it is required to REFUSE — and the trim loop is exercised
 * against a fake index that actually shrinks when documents are deleted, because the failure
 * mode that matters is a loop that keeps trimming past its target.
 *
 * The rest cover the promises the UI makes: that the control plane is not called once per
 * batch (it is slow, and batches arrive every couple of seconds), that a blacked-out index
 * is a clear state rather than a crash, that the retained-days estimate is arithmetic on its
 * inputs rather than a number somebody liked, that `host_s` really does scope a query, and
 * that the bandwidth copy says what the platform actually enforces.
 *
 * No network: the Opensolr client is built with an injected transport, and the Solr side is
 * a fake object with the three methods Quota calls.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

use Loghound\Config;
use Loghound\Opensolr;
use Loghound\Panel\Controller;
use Loghound\Panel\Gateway;
use Loghound\Panel\Query;
use Loghound\Quota;

/**
 * A Solr stand-in that models the one behaviour the trim depends on: deleting the oldest
 * documents makes the index smaller and moves its oldest timestamp forward.
 *
 * Documents are assumed to be spread evenly over the timespan, which is the same assumption
 * the cutoff arithmetic makes — so a test against this fake proves the loop converges, not
 * that the model is realistic. Realism is not the point; termination and bounds are.
 */
final class LhFakeSolr
{
    public int $count;
    public int $min;
    public int $max;

    /** @var array<int,string> Every filter handed to deleteByQuery, in order. */
    public array $deletes = [];

    /** @var array<int,array<string,mixed>> Every query parameter set, for assertions. */
    public array $queries = [];

    /** When set, every call throws this message — the blacked-out index. */
    public ?string $throw = null;

    public function __construct(int $count, int $min, int $max)
    {
        $this->count = $count;
        $this->min = $min;
        $this->max = $max;
    }

    /** Bounds facet: oldest, newest and the document count. */
    public function jsonFacet(string $core, array $params, array $facet): array
    {
        if ($this->throw !== null) {
            throw new RuntimeException($this->throw);
        }
        return ['facets' => [
            'count'  => $this->count,
            'oldest' => gmdate('Y-m-d\TH:i:s\Z', $this->min),
            'newest' => gmdate('Y-m-d\TH:i:s\Z', $this->max),
        ]];
    }

    /** Count the documents a `[* TO <instant>]` filter covers, assuming even spread. */
    public function query(string $core, array $params): array
    {
        if ($this->throw !== null) {
            throw new RuntimeException($this->throw);
        }
        $this->queries[] = $params;

        $fq = (string) (($params['fq'] ?? [''])[0] ?? '');
        if (!preg_match('/TO ([^\]]+)\]/', $fq, $m)) {
            return ['response' => ['numFound' => $this->count]];
        }
        $cut = (int) strtotime(trim($m[1]));
        return ['response' => ['numFound' => $this->covered($cut)]];
    }

    /** Delete, and shrink the fake index the way a real one would. */
    public function deleteByQuery(string $core, string $fq, bool $allowAll = false): array
    {
        if ($this->throw !== null) {
            throw new RuntimeException($this->throw);
        }
        $this->deletes[] = $fq;

        if (preg_match('/TO ([^\]]+)\]/', $fq, $m)) {
            $cut = (int) strtotime(trim($m[1]));
            $this->count = max(0, $this->count - $this->covered($cut));
            $this->min = max($this->min, $cut);
        }
        return ['responseHeader' => ['status' => 0]];
    }

    /** Documents older than an instant, on the even-spread assumption. */
    private function covered(int $cut): int
    {
        if ($this->max <= $this->min || $cut <= $this->min) {
            return 0;
        }
        $fraction = min(1.0, ($cut - $this->min) / ($this->max - $this->min));
        return (int) round($this->count * $fraction);
    }
}

/**
 * A Controller with nothing in it, so the filter plumbing every view inherits can be tested
 * without dragging one of the real views (and its Solr expectations) into the assertion.
 */
final class LhFilterView extends Controller
{
    public function slug(): string
    {
        return 'test';
    }

    public function title(): string
    {
        return 'Test';
    }


    public function body(): void
    {
    }

    /** @return array<string,mixed> */
    public function api(string $action): array
    {
        return [];
    }

    /**
     * The filters a sessions-core query would carry.
     *
     * @return array<int,string>
     */
    public function fqs(): array
    {
        return $this->sessionFqs();
    }

    /** Issue a facet through the gateway so the recorded request can be inspected. */
    public function run(): void
    {
        $this->gw->facet('test.fqs', 'core', ['q' => '*:*', 'fq' => $this->sessionFqs()], ['n' => 'count']);
    }
}

/**
 * Build a Config that is valid enough for Quota without touching the real config file.
 *
 * @param array<string,mixed> $over Dotted keys to set.
 */
function lh_quota_cfg(string $dir, array $over = []): Config
{
    $cfg = Config::load($dir . '/config/loghound.php');
    $cfg->set('solr.mode', 'opensolr');
    $cfg->set('solr.hits_core', 'loghound_test_hits');
    $cfg->set('solr.sessions_core', 'loghound_test_sessions');
    $cfg->set('opensolr.email', 'nobody@example.com');
    $cfg->set('opensolr.api_key', 'test-key-not-real');
    foreach ($over as $key => $value) {
        $cfg->set($key, $value);
    }
    return $cfg;
}

/**
 * An Opensolr control-plane client whose transport is canned, and a counter it increments.
 *
 * @param array<string,mixed> $coreData The msg.core_data block to answer with.
 */
function lh_quota_api(array $coreData, ?int &$calls): Opensolr
{
    $calls = 0;
    return new Opensolr(
        ['email' => 'nobody@example.com', 'api_key' => 'test-key-not-real'],
        static function (array $req) use ($coreData, &$calls): array {
            $calls++;
            return [
                'status' => 200,
                'body'   => (string) json_encode([
                    'status' => true,
                    'msg'    => [
                        'core_data' => $coreData,
                        'all_cores' => [
                            'total_number_of_cores'    => 2,
                            'total_cores_disk_mb'      => 1.0,
                            'total_cores_bandwidth_mb' => 1.0,
                        ],
                    ],
                ]),
                'error'  => '',
            ];
        }
    );
}

/** Write a quota cache file directly, so a test can pin the facts it needs. */
function lh_quota_seed(string $path, string $core, array $entry): void
{
    @mkdir(dirname($path), 0700, true);
    file_put_contents($path, (string) json_encode(['schema' => 1, 'cores' => [$core => $entry]]));
}

return [

    /* -----------------------------------------------------------------------------
     * The cutoff: the calculation, and every case where it must refuse
     * -------------------------------------------------------------------------- */

    'cutoff removes the fraction of the timespan the overage calls for' => function (): void {
        $now = 1757600000;
        $min = $now - (30 * 86400);
        $max = $now - 3600;

        $cutoff = Quota::computeCutoff(['min' => $min, 'max' => $max], 0.95, 0.80, $now, 24);
        lh_true($cutoff !== null, 'a cutoff');

        // drop = (0.95 - 0.80) / 0.95 = 0.157894…, applied to the span from the oldest doc.
        $expected = $min + (int) floor(($max - $min) * ((0.95 - 0.80) / 0.95));
        lh_same($expected, $cutoff, 'cutoff instant');
        lh_true($cutoff > $min, 'cutoff is after the oldest document');
        lh_true($cutoff < $max, 'cutoff is before the newest document');
    },

    'cutoff refuses when the index is already inside the target' => function (): void {
        $now = 1757600000;
        lh_same(null, Quota::computeCutoff(
            ['min' => $now - 86400 * 10, 'max' => $now],
            0.70,
            0.80,
            $now
        ), 'under target');
        lh_same(null, Quota::computeCutoff(
            ['min' => $now - 86400 * 10, 'max' => $now],
            0.80,
            0.80,
            $now
        ), 'exactly at target');
    },

    'cutoff refuses a missing, equal or inverted bound' => function (): void {
        $now = 1757600000;
        $ok = ['min' => $now - 86400 * 10, 'max' => $now - 3600];

        lh_same(null, Quota::computeCutoff(['min' => null, 'max' => $ok['max']], 0.99, 0.8, $now), 'no oldest');
        lh_same(null, Quota::computeCutoff(['min' => $ok['min'], 'max' => null], 0.99, 0.8, $now), 'no newest');
        lh_same(null, Quota::computeCutoff([], 0.99, 0.8, $now), 'no bounds at all');
        lh_same(null, Quota::computeCutoff(['min' => 500, 'max' => 500], 0.99, 0.8, $now), 'equal bounds');
        lh_same(null, Quota::computeCutoff(['min' => $now, 'max' => $now - 86400], 0.99, 0.8, $now), 'inverted');
    },

    'cutoff refuses timestamps from the future' => function (): void {
        $now = 1757600000;
        lh_same(null, Quota::computeCutoff(
            ['min' => $now - 86400, 'max' => $now + 7200],
            0.99,
            0.80,
            $now
        ), 'newest document is in the future');
    },

    'cutoff never enters the protected recent window' => function (): void {
        $now = 1757600000;

        // Wildly over quota over a long span: the arithmetic wants most of it, and the
        // per-step cap plus the floor both apply.
        $cutoff = Quota::computeCutoff(['min' => $now - 86400 * 100, 'max' => $now], 5.0, 0.80, $now, 24);
        lh_true($cutoff !== null, 'a cutoff');
        lh_true($cutoff <= $now - 86400, 'cutoff keeps at least the last 24 hours');

        // Every document is inside the protected window, so there is nothing it may take.
        lh_same(null, Quota::computeCutoff(
            ['min' => $now - 7200, 'max' => $now - 60],
            9.0,
            0.80,
            $now,
            24
        ), 'all data is newer than the floor');
    },

    'one cutoff step never takes more than a quarter of the timespan' => function (): void {
        $now = 1757600000;
        $min = $now - (400 * 86400);
        $max = $now - (10 * 86400);

        $cutoff = Quota::computeCutoff(['min' => $min, 'max' => $max], 4.0, 0.80, $now, 24);
        lh_true($cutoff !== null, 'a cutoff');

        $taken = ($cutoff - $min) / ($max - $min);
        lh_true($taken <= 0.2500001, 'step took ' . round($taken * 100, 2) . '% of the span');
    },

    /* -----------------------------------------------------------------------------
     * The trim loop
     * -------------------------------------------------------------------------- */

    'trim stops as soon as the target is reached' => function (): void {
        $dir = lh_tmpdir('quota');
        try {
            $cfg = lh_quota_cfg($dir);
            $api = lh_quota_api([
                'core_size_mb'      => 95.0,
                'max_core_size_mb'  => 100.0,
                'core_badnwidth_mb' => 10.0,
                'max_badnwdith_mb'  => 1000.0,
            ], $calls);

            $quota = new Quota($cfg, $api, $dir . '/var/quota.json');
            $solr = new LhFakeSolr(1000, time() - (30 * 86400), time() - 3600);

            $result = $quota->trim($solr, 'loghound_test_hits', 'ts');

            lh_same('ok', $result['state'], 'trim state');
            lh_same(1, count($solr->deletes), 'one delete was enough to reach the target');
            lh_true($result['to'] <= $result['target'] + 0.0001, 'ended at or under the target');
            lh_true($result['deleted'] > 0 && $result['deleted'] < 1000, 'deleted some but not all');
        } finally {
            lh_rmtree($dir);
        }
    },

    'trim is bounded by max steps even when hugely over quota' => function (): void {
        $dir = lh_tmpdir('quota');
        try {
            $cfg = lh_quota_cfg($dir, ['quota.max_trim_steps' => 3]);
            $api = lh_quota_api([
                'core_size_mb'      => 400.0,
                'max_core_size_mb'  => 100.0,
                'core_badnwidth_mb' => 10.0,
                'max_badnwdith_mb'  => 1000.0,
            ], $calls);

            $quota = new Quota($cfg, $api, $dir . '/var/quota.json');
            $solr = new LhFakeSolr(10000, time() - (200 * 86400), time() - 3600);

            $result = $quota->trim($solr, 'loghound_test_hits', 'ts');

            lh_same(3, count($solr->deletes), 'exactly the configured number of steps');
            lh_true($solr->count > 0, 'the index was not emptied');
        } finally {
            lh_rmtree($dir);
        }
    },

    'trim does nothing while the index is under the high-water mark' => function (): void {
        $dir = lh_tmpdir('quota');
        try {
            $cfg = lh_quota_cfg($dir);
            $api = lh_quota_api([
                'core_size_mb'      => 50.0,
                'max_core_size_mb'  => 100.0,
                'core_badnwidth_mb' => 1.0,
                'max_badnwdith_mb'  => 1000.0,
            ], $calls);

            $quota = new Quota($cfg, $api, $dir . '/var/quota.json');
            $solr = new LhFakeSolr(1000, time() - 86400 * 10, time() - 60);

            $result = $quota->trim($solr, 'loghound_test_hits', 'ts');

            lh_same('ok', $result['state'], 'state');
            lh_same([], $solr->deletes, 'nothing was deleted');
            lh_contains($result['message'], 'nothing needs deleting', 'message');
        } finally {
            lh_rmtree($dir);
        }
    },

    'trim refuses a core and timestamp field that do not belong together' => function (): void {
        $dir = lh_tmpdir('quota');
        try {
            $cfg = lh_quota_cfg($dir);
            $api = lh_quota_api([
                'core_size_mb'     => 95.0,
                'max_core_size_mb' => 100.0,
            ], $calls);
            $quota = new Quota($cfg, $api, $dir . '/var/quota.json');
            $solr = new LhFakeSolr(1000, time() - 86400 * 10, time() - 60);

            // The sessions core with the hits core's timestamp field: a hits-core decision
            // must never be able to delete session documents.
            $e = lh_throws(
                static fn () => $quota->trim($solr, 'loghound_test_sessions', 'ts'),
                'mismatched core and field'
            );
            lh_contains($e->getMessage(), 'refusing to trim', 'refusal');
            lh_same([], $solr->deletes, 'nothing was deleted');

            $e2 = lh_throws(
                static fn () => $quota->trim($solr, 'some_other_index', 'ts'),
                'an index this install does not write to'
            );
            lh_contains($e2->getMessage(), 'refusing to trim', 'refusal');
        } finally {
            lh_rmtree($dir);
        }
    },

    'a dry run reports what it would delete and deletes nothing' => function (): void {
        $dir = lh_tmpdir('quota');
        try {
            $cfg = lh_quota_cfg($dir);
            $api = lh_quota_api([
                'core_size_mb'     => 95.0,
                'max_core_size_mb' => 100.0,
            ], $calls);
            $quota = new Quota($cfg, $api, $dir . '/var/quota.json');
            $solr = new LhFakeSolr(1000, time() - (30 * 86400), time() - 3600);

            $result = $quota->trim($solr, 'loghound_test_hits', 'ts', ['dry_run' => true]);

            lh_same([], $solr->deletes, 'a dry run deletes nothing');
            lh_true($result['deleted'] > 0, 'it still reports a figure');
            lh_contains($result['message'], 'would be deleted', 'message');
        } finally {
            lh_rmtree($dir);
        }
    },

    /* -----------------------------------------------------------------------------
     * Cost: the control plane is not called per batch
     * -------------------------------------------------------------------------- */

    'the control plane is not called once per batch' => function (): void {
        $dir = lh_tmpdir('quota');
        try {
            $cfg = lh_quota_cfg($dir);
            $api = lh_quota_api([
                'core_size_mb'      => 10.0,
                'max_core_size_mb'  => 1000.0,
                'core_badnwidth_mb' => 5.0,
                'max_badnwdith_mb'  => 10000.0,
            ], $calls);

            $quota = new Quota($cfg, $api, $dir . '/var/quota.json');
            $solr = new LhFakeSolr(1000, time() - 86400, time() - 60);

            // 200 batches of 100 documents: 20 000 documents, well inside the default
            // 50 000-document threshold and inside the 300-second clock.
            for ($i = 0; $i < 200; $i++) {
                $quota->guardBeforeWrite($solr, 'loghound_test_hits', 'ts');
                $quota->noteWrite('loghound_test_hits', 100, 100 * 512);
            }

            lh_same(1, $quota->apiCalls(), 'control-plane calls for 200 batches');
            lh_same(1, $calls, 'transport requests');
            lh_same([], $solr->deletes, 'nothing was trimmed while well under quota');
        } finally {
            lh_rmtree($dir);
        }
    },

    'crossing the document threshold refreshes, and only then' => function (): void {
        $dir = lh_tmpdir('quota');
        try {
            $cfg = lh_quota_cfg($dir, ['quota.refresh_docs' => 1000]);
            $api = lh_quota_api([
                'core_size_mb'     => 10.0,
                'max_core_size_mb' => 1000.0,
            ], $calls);

            $quota = new Quota($cfg, $api, $dir . '/var/quota.json');

            $quota->usage('loghound_test_hits');
            lh_same(1, $quota->apiCalls(), 'the first read');

            for ($i = 0; $i < 9; $i++) {
                $quota->noteWrite('loghound_test_hits', 100, 51200);
                $quota->usage('loghound_test_hits');
            }
            lh_same(1, $quota->apiCalls(), 'still cached at 900 documents');

            $quota->noteWrite('loghound_test_hits', 100, 51200);
            $quota->usage('loghound_test_hits');
            lh_same(2, $quota->apiCalls(), 'refreshed at 1000 documents');
        } finally {
            lh_rmtree($dir);
        }
    },

    /* -----------------------------------------------------------------------------
     * A blacked-out index
     * -------------------------------------------------------------------------- */

    'a blacked-out index is a clear state, not a crash' => function (): void {
        $dir = lh_tmpdir('quota');
        try {
            $cfg = lh_quota_cfg($dir);
            $api = lh_quota_api([
                'core_size_mb'      => 95.0,
                'max_core_size_mb'  => 100.0,
                'core_badnwidth_mb' => 1200.0,
                'max_badnwdith_mb'  => 1000.0,
            ], $calls);

            $quota = new Quota($cfg, $api, $dir . '/var/quota.json');
            $solr = new LhFakeSolr(1000, time() - 86400 * 10, time() - 60);
            $solr->throw = 'Solr: HTTP 403 with an unparseable body.';

            $probe = $quota->probe($solr, 'loghound_test_hits');
            lh_same('blocked', $probe['state'], 'probe state');
            lh_contains($probe['message'], '403', 'says what the platform is doing');
            lh_contains($probe['message'], '17 minutes', 'says how long it lasts');

            // The trim must report it rather than throwing out of the daemon's flush path,
            // and it must name the quota rather than the 403 — a bare 403 from a Solr node
            // normally means bad credentials, and that is the wrong thing to go and check.
            $trim = $quota->trim($solr, 'loghound_test_hits', 'ts');
            lh_same('failed', $trim['state'], 'trim state when every request is refused');
            lh_contains($trim['message'], 'blocked by Opensolr', 'names the cause');
            lh_contains($trim['message'], '17 minutes', 'and how it clears');
            lh_same([], $solr->deletes, 'and it deleted nothing on the way');

            // And the guard the tailer calls must never throw, whatever happened.
            $guard = $quota->guardBeforeWrite($solr, 'loghound_test_hits', 'ts');
            lh_true(is_array($guard) && isset($guard['action']), 'the guard returned a result');

            // Bandwidth over the limit is reported as blocked, from the control plane, which
            // keeps answering while the index itself does not.
            $bw = $quota->bandwidth('loghound_test_hits');
            lh_same('blocked', $bw['level'], 'bandwidth level');
        } finally {
            lh_rmtree($dir);
        }
    },

    'an unreachable control plane keeps the last figures and says so' => function (): void {
        $dir = lh_tmpdir('quota');
        try {
            $cfg = lh_quota_cfg($dir);
            $api = new Opensolr(
                ['email' => 'nobody@example.com', 'api_key' => 'k'],
                static fn (array $req): array => ['status' => 0, 'body' => '', 'error' => 'could not connect']
            );

            $quota = new Quota($cfg, $api, $dir . '/var/quota.json');
            $usage = $quota->usage('loghound_test_hits');

            lh_same('unreachable', $usage['state'], 'state');
            lh_same(null, $usage['disk_ratio'], 'no ratio is invented');

            $solr = new LhFakeSolr(1000, time() - 86400, time() - 60);
            $trim = $quota->trim($solr, 'loghound_test_hits', 'ts');
            lh_same('skipped', $trim['state'], 'nothing is deleted without a plan limit');
            lh_same([], $solr->deletes, 'no deletes');
        } finally {
            lh_rmtree($dir);
        }
    },

    'an install with no Opensolr API key has no plan to trim against' => function (): void {
        $dir = lh_tmpdir('quota');
        try {
            $cfg = lh_quota_cfg($dir, ['opensolr.api_key' => '']);
            $quota = new Quota($cfg, null, $dir . '/var/quota.json');

            $usage = $quota->usage('loghound_test_hits');
            lh_same('not_configured', $usage['state'], 'state');
            lh_contains($usage['message'], 'API key', 'names the missing credential');

            $solr = new LhFakeSolr(1000, time() - 86400, time() - 60);
            lh_same('skipped', $quota->trim($solr, 'loghound_test_hits', 'ts')['state'], 'trim');
            lh_same([], $solr->deletes, 'no deletes');
        } finally {
            lh_rmtree($dir);
        }
    },

    /* -----------------------------------------------------------------------------
     * The retained-days estimate
     * -------------------------------------------------------------------------- */

    'the retained-days estimate is arithmetic on its inputs' => function (): void {
        $dir = lh_tmpdir('quota');
        try {
            $now = time();
            $path = $dir . '/var/quota.json';

            // 45 MB of growth over exactly one day, a 500 MB plan, an 80% target:
            // 500 * 0.8 / 45 = 8.888… days.
            lh_quota_seed($path, 'loghound_test_hits', [
                'state'       => 'ok',
                'message'     => '',
                'checked_at'  => $now,
                'size_mb'     => 145.0,
                'max_size_mb' => 500.0,
                'bw_mb'       => 20.0,
                'max_bw_mb'   => 1000.0,
                'bytes_since' => 0,
                'docs_since'  => 0,
                'samples'     => [
                    ['t' => $now - 86400, 'mb' => 100.0],
                    ['t' => $now,         'mb' => 145.0],
                ],
            ]);

            $cfg = lh_quota_cfg($dir, ['privacy.retention_days' => 0]);
            $api = lh_quota_api(['core_size_mb' => 145.0, 'max_core_size_mb' => 500.0], $calls);
            $quota = new Quota($cfg, $api, $path);

            $window = $quota->retentionWindow('loghound_test_hits', 6.0);

            lh_same(0, $calls, 'a fresh cache means no control-plane call');
            lh_near(45.0, (float) $window['ingest_mb_day'], 0.01, 'observed ingest rate');
            lh_near(8.9, (float) $window['plan_days'], 0.05, 'projected window');
            lh_same('size', $window['limited_by'], 'which limit is in effect');
            lh_contains($window['sentence'], '45 MB per day', 'the sentence quotes the rate it computed');
            lh_contains($window['sentence'], '8.9 days', 'the sentence quotes the window it computed');
            lh_contains($window['sentence'], 'estimates', 'and says the projection is an estimate');
        } finally {
            lh_rmtree($dir);
        }
    },

    'a shorter time-based retention wins over the plan window' => function (): void {
        $dir = lh_tmpdir('quota');
        try {
            $now = time();
            $path = $dir . '/var/quota.json';
            lh_quota_seed($path, 'loghound_test_hits', [
                'state'       => 'ok',
                'checked_at'  => $now,
                'size_mb'     => 145.0,
                'max_size_mb' => 500.0,
                'samples'     => [
                    ['t' => $now - 86400, 'mb' => 100.0],
                    ['t' => $now,         'mb' => 145.0],
                ],
            ]);

            $cfg = lh_quota_cfg($dir, ['privacy.retention_days' => 3]);
            $quota = new Quota($cfg, lh_quota_api([], $calls), $path);

            $window = $quota->retentionWindow('loghound_test_hits', 3.0);
            lh_same('time', $window['limited_by'], 'the shorter of the two');
            lh_contains(
                $window['sentence'],
                'age limit',
                'names the limit that bites, in the operator\'s direction: "retention" was being '
                . 'used as the name of the DELETION rule, which reads backwards to anyone who has '
                . 'not seen the code'
            );
        } finally {
            lh_rmtree($dir);
        }
    },

    'no growth history means no invented window' => function (): void {
        $dir = lh_tmpdir('quota');
        try {
            $cfg = lh_quota_cfg($dir, ['privacy.retention_days' => 0]);
            $api = lh_quota_api([
                'core_size_mb'     => 10.0,
                'max_core_size_mb' => 500.0,
            ], $calls);
            $quota = new Quota($cfg, $api, $dir . '/var/quota.json');

            $window = $quota->retentionWindow('loghound_test_hits', null);

            lh_same(null, $window['ingest_mb_day'], 'no rate');
            lh_same(null, $window['plan_days'], 'and therefore no projected window');
            lh_contains($window['sentence'], 'not known yet', 'it says so instead of guessing');
        } finally {
            lh_rmtree($dir);
        }
    },

    'a trim that failed near the limit is the one disk condition that warns' => function (): void {
        $dir = lh_tmpdir('quota');
        try {
            $now = time();
            $path = $dir . '/var/quota.json';
            lh_quota_seed($path, 'loghound_test_hits', [
                'state'       => 'ok',
                'checked_at'  => $now,
                'size_mb'     => 94.0,
                'max_size_mb' => 100.0,
                'trim'        => ['at' => $now - 60, 'state' => 'failed', 'message' => 'the delete was refused.'],
            ]);

            $cfg = lh_quota_cfg($dir);
            $quota = new Quota($cfg, lh_quota_api([], $calls), $path);
            $window = $quota->retentionWindow('loghound_test_hits', 5.0);

            lh_true(is_array($window['trim_alert']), 'an alert');
            lh_contains($window['trim_alert']['text'], 'could not free space', 'what happened');
            lh_contains($window['trim_alert']['text'], 'blocks the index completely', 'what it leads to');
        } finally {
            lh_rmtree($dir);
        }
    },

    'a healthy index raises no disk alarm at all' => function (): void {
        $dir = lh_tmpdir('quota');
        try {
            $now = time();
            $path = $dir . '/var/quota.json';
            lh_quota_seed($path, 'loghound_test_hits', [
                'state'       => 'ok',
                'checked_at'  => $now,
                'size_mb'     => 40.0,
                'max_size_mb' => 100.0,
                'samples'     => [
                    ['t' => $now - 86400, 'mb' => 30.0],
                    ['t' => $now,         'mb' => 40.0],
                ],
            ]);

            $cfg = lh_quota_cfg($dir, ['privacy.retention_days' => 0]);
            $quota = new Quota($cfg, lh_quota_api([], $calls), $path);
            $window = $quota->retentionWindow('loghound_test_hits', 4.0);

            lh_same(null, $window['trim_alert'], 'no alert');
            foreach (['running out', 'warning', 'danger', 'critical'] as $word) {
                if (stripos($window['sentence'], $word) !== false) {
                    lh_fail('the disk sentence must stay neutral; it contains "' . $word . '"');
                }
            }
        } finally {
            lh_rmtree($dir);
        }
    },

    /* -----------------------------------------------------------------------------
     * The bandwidth copy
     * -------------------------------------------------------------------------- */

    'the bandwidth copy says what the platform actually enforces' => function (): void {
        $text = Quota::CONSEQUENCE;

        lh_contains($text, '403', 'names the status code');
        lh_contains($text, 'reads as well as writes', 'says reads are blocked too');
        lh_contains($text, 'resets on the 1st', 'says when it clears');
        lh_contains($text, '17 minutes', 'says how long recovery takes');

        // The two wordings that are simply untrue of this platform.
        if (stripos($text, 'slowdown') !== false || stripos($text, 'throttl') !== false) {
            lh_fail('the consequence must not suggest throttling; the index is blocked outright');
        }
        if (preg_match('/writes will be blocked/i', $text)) {
            lh_fail('the consequence must not say only writes are blocked');
        }
    },

    'the bandwidth level warns before the limit, not after' => function (): void {
        $dir = lh_tmpdir('quota');
        try {
            $levels = [];
            foreach ([[10.0, 'ok'], [80.0, 'warn'], [95.0, 'critical'], [140.0, 'blocked']] as [$used, $want]) {
                $cfg = lh_quota_cfg($dir);
                $api = lh_quota_api([
                    'core_size_mb'      => 1.0,
                    'max_core_size_mb'  => 100.0,
                    'core_badnwidth_mb' => $used,
                    'max_badnwdith_mb'  => 100.0,
                ], $calls);
                $quota = new Quota($cfg, $api, $dir . '/var/bw-' . (int) $used . '.json');
                $bw = $quota->bandwidth('loghound_test_hits');
                $levels[] = $bw['level'];
                lh_same($want, $bw['level'], $used . ' MB of 100 MB');
                lh_contains($bw['consequence'], '403', 'the consequence travels with every level');
            }
            lh_same(['ok', 'warn', 'critical', 'blocked'], $levels, 'the ladder');
        } finally {
            lh_rmtree($dir);
        }
    },

    'the bandwidth reset is the first of next month, in UTC' => function (): void {
        $reset = Quota::nextReset();
        lh_true((bool) preg_match('/^\d{4}-\d{2}-01T00:00:00Z$/', $reset), 'shape: ' . $reset);
        lh_true(strtotime($reset) > time(), 'it is in the future');
        lh_true(Quota::secondsToReset() > 0, 'and so is the countdown');
    },

    /* -----------------------------------------------------------------------------
     * The vhost dimension
     * -------------------------------------------------------------------------- */

    'host_s is a filterable field' => function (): void {
        $fields = Query::filterFields();
        lh_has_key($fields, 'host_s', 'filterable fields');
        lh_same('host_s', Query::HOST_FIELD, 'the field constant');
        lh_same('host_s:"a.example.com"', Query::hostFq('a.example.com'), 'host filter');
        lh_same(null, Query::hostFq(''), 'no host selected means no filter, not an empty result set');
    },

    'a host filter scopes every sessions-core query' => function (): void {
        $dir = lh_tmpdir('quota');
        $saved = $_GET;
        try {
            $_GET = [
                'range' => '24h',
                'f'     => [
                    'host_s'      => ['a.example.com'],
                    'country_s'   => ['DE'],
                    'not_a_field' => ['x'],
                ],
            ];

            $cfg = lh_quota_cfg($dir);
            $view = new LhFilterView($cfg, new Gateway($cfg, null, true));
            $fqs = $view->fqs();

            $joined = implode(' | ', $fqs);
            lh_contains($joined, 'host_s:("a.example.com")', 'the host filter reached the query');
            lh_contains($joined, 'country_s:("DE")', 'other filters still apply');
            if (str_contains($joined, 'not_a_field')) {
                lh_fail('a field that is not on the allowlist must never reach a query');
            }
        } finally {
            $_GET = $saved;
            lh_rmtree($dir);
        }
    },

    'the host filter reaches Solr through the gateway' => function (): void {
        $dir = lh_tmpdir('quota');
        $saved = $_GET;
        try {
            $_GET = ['f' => ['host_s' => ['shop.example.com']]];

            $seen = [];
            $solr = new class ($seen) {
                /** @var array<int,array<string,mixed>> */
                public array $seen = [];

                public function __construct(array &$seen)
                {
                    $this->seen = &$seen;
                }

                public function jsonFacet(string $core, array $params, array $facet): array
                {
                    $this->seen[] = $params;
                    return ['facets' => ['count' => 0]];
                }
            };

            $cfg = lh_quota_cfg($dir);
            (new LhFilterView($cfg, new Gateway($cfg, $solr, false)))->run();

            lh_same(1, count($seen), 'one request');
            lh_contains(
                implode(' | ', (array) $seen[0]['fq']),
                'host_s:("shop.example.com")',
                'the filter that was sent'
            );
        } finally {
            $_GET = $saved;
            lh_rmtree($dir);
        }
    },

    'the sessions core is queried as sessions, not as sessions plus rollups' => function (): void {
        lh_same('doc_type_s:session', Query::SESSION_DOCS, 'the constant every sessions-core count needs');
    },

    /* -----------------------------------------------------------------------------
     * Small things that would be silently wrong
     * -------------------------------------------------------------------------- */

    'the target is always kept below the high-water mark' => function (): void {
        $dir = lh_tmpdir('quota');
        try {
            $cfg = lh_quota_cfg($dir, [
                'quota.disk_high_water' => 0.85,
                'quota.disk_target'     => 0.95,
            ]);
            $quota = new Quota($cfg, null, $dir . '/var/quota.json');

            lh_near(0.85, $quota->highWater(), 0.0001, 'high water');
            lh_true($quota->target() < $quota->highWater(), 'target sits below it whatever was configured');
        } finally {
            lh_rmtree($dir);
        }
    },

    'settings outside their sane range are clamped rather than obeyed' => function (): void {
        $dir = lh_tmpdir('quota');
        try {
            $cfg = lh_quota_cfg($dir, [
                'quota.disk_high_water'   => 9.0,
                'quota.min_keep_hours'    => 0,
                'quota.refresh_sec'       => 1,
                'quota.max_trim_steps'    => 5000,
                'quota.trim_cooldown_sec' => 1,
            ]);
            $quota = new Quota($cfg, null, $dir . '/var/quota.json');

            lh_true($quota->highWater() <= 0.98, 'high water');
            lh_true($quota->minKeepHours() >= 1, 'protected window');
            lh_true($quota->refreshSec() >= 30, 'refresh interval');
            lh_true($quota->maxSteps() <= 10, 'steps per trim');
            lh_true($quota->cooldownSec() >= 60, 'cooldown');
        } finally {
            lh_rmtree($dir);
        }
    },

    'the upgrade link is a validated URL' => function (): void {
        $dir = lh_tmpdir('quota');
        try {
            $bad = lh_quota_cfg($dir, ['quota.upgrade_url' => 'javascript:alert(1)']);
            lh_true(
                str_starts_with((new Quota($bad, null, $dir . '/var/q1.json'))->upgradeUrl(), 'https://'),
                'a non-http scheme is replaced, never rendered'
            );
        } finally {
            lh_rmtree($dir);
        }
    },

    'the cache file survives corruption without taking ingestion with it' => function (): void {
        $dir = lh_tmpdir('quota');
        try {
            $path = $dir . '/var/quota.json';
            @mkdir(dirname($path), 0700, true);
            file_put_contents($path, '{"schema":1,"cores":{"x":');

            $cfg = lh_quota_cfg($dir);
            $api = lh_quota_api(['core_size_mb' => 5.0, 'max_core_size_mb' => 100.0], $calls);
            $usage = (new Quota($cfg, $api, $path))->usage('loghound_test_hits');

            lh_same('ok', $usage['state'], 'a corrupt cache is simply an empty one');
        } finally {
            lh_rmtree($dir);
        }
    },

    /* -----------------------------------------------------------------------------
     * The panel views
     * -------------------------------------------------------------------------- */

    'the Plan usage page states the consequence in the page itself' => function (): void {
        $dir = lh_tmpdir('quota');
        $saved = $_GET;
        try {
            $_GET = [];
            $cfg = lh_quota_cfg($dir);
            $view = new \Loghound\Panel\Usage($cfg, new Gateway($cfg, null, true));

            ob_start();
            $view->body();
            $html = (string) ob_get_clean();

            // Authored by PHP rather than fetched, because an operator whose index is
            // already blocked cannot load anything, and this is the sentence they need.
            lh_contains($html, '403', 'the status code is on the page');
            lh_contains($html, 'reads as well as writes', 'and that reads are blocked too');
            lh_contains($html, '17 minutes', 'and how long recovery takes');

            // Disk is stated as information. If this page ever grows an alarm about it,
            // that is the regression: the trim runs before the write, so it cannot happen.
            lh_contains($html, 'Disk looks after itself', 'disk is framed as managed');

            // The dashboard's own cost is admitted rather than hidden.
            lh_contains($html, 'count towards the figure above', 'the panel admits its own usage');
        } finally {
            $_GET = $saved;
            lh_rmtree($dir);
        }
    },

    'demo mode fabricates traffic but never a plan figure' => function (): void {
        $dir = lh_tmpdir('quota');
        $saved = $_GET;
        try {
            $_GET = [];
            $cfg = lh_quota_cfg($dir);
            $view = new \Loghound\Panel\Usage($cfg, new Gateway($cfg, null, true));

            foreach (['meter', 'plan'] as $action) {
                $out = $view->api($action);
                lh_same([], $out['cores'], $action . ': no invented indexes');
                lh_contains($out['demo_note'], 'never fabricated', $action . ': it says why');
                lh_contains($out['consequence'], '403', $action . ': the real consequence still travels');
            }
        } finally {
            $_GET = $saved;
            lh_rmtree($dir);
        }
    },

    'an index over quota is reported as blocked, with the reason' => function (): void {
        $dir = lh_tmpdir('quota');
        $saved = $_GET;
        try {
            $_GET = [];
            $now = time();
            $path = $dir . '/var/quota.json';
            lh_quota_seed($path, 'loghound_test_hits', [
                'state'       => 'ok',
                'checked_at'  => $now,
                'size_mb'     => 50.0,
                'max_size_mb' => 100.0,
                'bw_mb'       => 1500.0,
                'max_bw_mb'   => 1000.0,
            ]);

            $cfg = lh_quota_cfg($dir);
            $view = new \Loghound\Panel\Usage($cfg, new Gateway($cfg, null, false));
            $view->setQuota(new Quota($cfg, lh_quota_api([], $calls), $path));

            $plan = $view->api('plan');
            $hits = null;
            foreach ($plan['cores'] as $row) {
                if ($row['core'] === 'loghound_test_hits') {
                    $hits = $row;
                }
            }

            lh_true(is_array($hits), 'the hits core is in the answer');
            lh_true(is_array($hits['blocked']), 'and it is reported as blocked');
            lh_contains($hits['blocked']['text'], 'reads as well as writes', 'reads too');
            lh_contains($hits['blocked']['text'], 'resets on the 1st', 'when bandwidth clears');
            lh_same(['bandwidth'], $hits['blocked']['over'], 'which quota was exceeded');
        } finally {
            $_GET = $saved;
            lh_rmtree($dir);
        }
    },

    'the host selector is inert with one host and offered with several' => function (): void {
        $dir = lh_tmpdir('quota');
        $saved = $_GET;
        try {
            $cfg = lh_quota_cfg($dir);

            $make = static function (array $hosts) use ($cfg) {
                $solr = new class ($hosts) {
                    /** @var array<int,array{val:string,count:int}> */
                    private array $hosts;

                    public function __construct(array $hosts)
                    {
                        $this->hosts = $hosts;
                    }

                    public function jsonFacet(string $core, array $params, array $facet): array
                    {
                        return ['facets' => [
                            'count' => 100,
                            'hosts' => ['buckets' => $this->hosts],
                        ]];
                    }
                };
                return new \Loghound\Panel\Hosts($cfg, new Gateway($cfg, $solr, false));
            };

            $_GET = [];
            $one = $make([['val' => 'only.example.com', 'count' => 100]])->api('list');
            lh_false($one['multi'], 'one host offers no choice');
            lh_true($one['present'], 'but a host was recorded');

            $none = $make([])->api('list');
            lh_false($none['present'], 'no host recorded at all is a different state');
            lh_false($none['multi'], 'and still no selector');

            $many = $make([
                ['val' => 'a.example.com', 'count' => 60],
                ['val' => 'b.example.com', 'count' => 40],
            ])->api('list');
            lh_true($many['multi'], 'two hosts is a choice worth offering');
            lh_same(2, count($many['hosts']), 'both are listed');
            lh_same('a.example.com', $many['hosts'][0]['host'], 'busiest first');
        } finally {
            $_GET = $saved;
            lh_rmtree($dir);
        }
    },

    'the host list is not scoped by the host already chosen' => function (): void {
        $dir = lh_tmpdir('quota');
        $saved = $_GET;
        try {
            $_GET = ['f' => ['host_s' => ['a.example.com'], 'country_s' => ['DE']]];

            $seen = [];
            $solr = new class ($seen) {
                /** @var array<int,array<string,mixed>> */
                public array $seen = [];

                public function __construct(array &$seen)
                {
                    $this->seen = &$seen;
                }

                public function jsonFacet(string $core, array $params, array $facet): array
                {
                    $this->seen[] = $params;
                    return ['facets' => ['count' => 0, 'hosts' => ['buckets' => []]]];
                }
            };

            $cfg = lh_quota_cfg($dir);
            $out = (new \Loghound\Panel\Hosts($cfg, new Gateway($cfg, $solr, false)))->api('list');

            $fq = implode(' | ', (array) $seen[0]['fq']);
            if (str_contains($fq, 'host_s')) {
                lh_fail('the host list must not be filtered by the host already selected: ' . $fq);
            }
            lh_contains($fq, 'country_s:("DE")', 'every other filter still applies');
            lh_same(['a.example.com'], $out['selected'], 'the selection is echoed back for the control');
        } finally {
            $_GET = $saved;
            lh_rmtree($dir);
        }
    },

    'the host comparison counts sessions, not rollups' => function (): void {
        $dir = lh_tmpdir('quota');
        $saved = $_GET;
        try {
            $_GET = [];

            $seen = [];
            $solr = new class ($seen) {
                /** @var array<int,array<string,mixed>> */
                public array $seen = [];

                public function __construct(array &$seen)
                {
                    $this->seen = &$seen;
                }

                public function jsonFacet(string $core, array $params, array $facet): array
                {
                    $this->seen[] = ['params' => $params, 'facet' => $facet];
                    return ['facets' => ['count' => 3, 'hosts' => ['buckets' => [
                        [
                            'val'      => 'a.example.com',
                            'count'    => 10,
                            'human'    => ['count' => 6],
                            'evasive'  => ['count' => 3],
                            'ai'       => ['count' => 1],
                            'declared' => ['count' => 0],
                            'unknown'  => ['count' => 0],
                        ],
                    ]]]];
                }
            };

            $cfg = lh_quota_cfg($dir);
            $out = (new \Loghound\Panel\Hosts($cfg, new Gateway($cfg, $solr, false)))->api('compare');

            lh_contains(
                implode(' | ', (array) $seen[0]['params']['fq']),
                'doc_type_s:session',
                'the sessions core is queried as sessions'
            );
            lh_same('host_s', $seen[0]['facet']['hosts']['field'], 'grouped by the vhost field');

            $row = $out['rows'][0];
            lh_same('a.example.com', $row['host'], 'host');
            lh_same(10, $row['sessions'], 'sessions');
            lh_near(40.0, (float) $row['bot_share'], 0.01, 'automation share');
            lh_near(30.0, (float) $row['evasive_share'], 0.01, 'evasive share');
        } finally {
            $_GET = $saved;
            lh_rmtree($dir);
        }
    },

    'two writers do not roll back each other\'s work' => function (): void {
        $dir = lh_tmpdir('quota');
        try {
            $path = $dir . '/var/quota.json';
            $cfg = lh_quota_cfg($dir);

            // The daemon reads the file, then the panel refreshes and writes, then the
            // daemon writes its own counter. The refresh must survive.
            $daemon = new Quota($cfg, lh_quota_api(['core_size_mb' => 1.0, 'max_core_size_mb' => 100.0], $c1), $path);
            $panel  = new Quota($cfg, lh_quota_api(['core_size_mb' => 77.0, 'max_core_size_mb' => 100.0], $c2), $path);

            $panel->usage('loghound_test_hits', true);

            $daemon->noteWrite('loghound_test_hits', 10, 1024);
            $daemon->flush();

            $stored = json_decode((string) file_get_contents($path), true);
            $entry = $stored['cores']['loghound_test_hits'];

            lh_near(77.0, (float) $entry['size_mb'], 0.001, 'the panel refresh survived');
            lh_same(10, (int) $entry['docs_since'], 'and so did the daemon counter');
        } finally {
            lh_rmtree($dir);
        }
    },
];
