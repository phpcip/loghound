<?php
/**
 * Loghound — plan quota awareness and the size-based rolling retention window.
 *
 * ---------------------------------------------------------------------------------------
 * WHY THIS EXISTS: SELF-PRESERVATION
 * ---------------------------------------------------------------------------------------
 * An Opensolr index that exceeds either its disk quota or its bandwidth quota is not
 * throttled and does not merely refuse writes. The platform installs an Apache
 * `Deny from all` over `/solr/<core>/*`, which is a TOTAL BLACKOUT: every request answers
 * 403, `/select` included, reads as well as writes. It clears by itself roughly seventeen
 * minutes after usage returns under the limit — by an upgrade, or, for bandwidth, by the
 * monthly reset on the 1st.
 *
 * So an unbounded Loghound eventually fills the operator's plan and switches its own
 * dashboard off. Preventing that is the entire point of this class.
 *
 * The two limits behave nothing alike, and the UI must not pretend otherwise:
 *
 *   DISK is reclaimable, therefore it is MANAGED, not a danger. The trim below runs BEFORE
 *   a write, so the index never reaches the quota and the blackout never triggers on disk.
 *   Disk is reported as a fact about how far back the data goes ("roughly 11 days of
 *   traffic retained, limited by your plan"), never as an alarm. The one thing here that
 *   does deserve a warning is the trim FAILING while the index is genuinely near the
 *   limit, because then the blackout really is coming.
 *
 *   BANDWIDTH cannot be reclaimed by deleting anything. It accrues with use and resets on
 *   the 1st. It is the only hard limit and the only one an operator has to watch, which is
 *   why it gets a live meter, a warning state well before the limit, and an upgrade link.
 *
 * ---------------------------------------------------------------------------------------
 * WHERE THE NUMBERS COME FROM
 * ---------------------------------------------------------------------------------------
 * One control-plane call, `GET /solr_manager/api/get_core_info?core_name=X`, whose
 * `msg.core_data` carries `core_size_mb`, `max_core_size_mb`, `core_badnwidth_mb` and
 * `max_badnwdith_mb` (the two misspellings are the platform's; they are matched exactly and
 * normalised here so nothing else in Loghound has to know about them).
 *
 * That call is EXPENSIVE — the platform derives the index size from a live Solr status
 * request — and batches arrive every couple of seconds. Calling it per batch would cost far
 * more than the ingestion it is protecting. So the answer is cached on disk with a time and
 * a document threshold, and between refreshes the size is projected locally from the bytes
 * of log actually read, using an expansion factor learned from the platform's own reported
 * growth. Every projected figure is flagged `estimated` and says so in the UI.
 *
 * ---------------------------------------------------------------------------------------
 * DELETION IS DANGEROUS
 * ---------------------------------------------------------------------------------------
 * The trim deletes by DATE, never by document count: a date cutoff is one cheap
 * delete-by-query and it leaves an answer a human understands ("you have data from this
 * date onward"), where "the oldest N documents" would need a sort, a page and an id list.
 *
 * Every guard in computeCutoff() maps to a way the operator could lose data they wanted:
 * an unknown plan limit, an empty index, a clock that moved, a bounds query that came back
 * inverted, a target that would take the whole index. Any one of them refuses the trim
 * rather than guessing. Nothing deletes without a plan limit to justify it, nothing deletes
 * inside the protected recent window, and no single step may take more than a bounded slice
 * of the data's timespan however far over quota the index is.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound;

final class Quota
{
    /** Disk ratio at which the rolling trim runs before the next write. */
    public const DEFAULT_HIGH_WATER = 0.90;

    /** Disk ratio the trim aims to come back down to. */
    public const DEFAULT_TARGET = 0.80;

    /** Bandwidth ratio at which the meter starts warning. */
    public const DEFAULT_BW_WARN = 0.75;

    /** Bandwidth ratio at which the meter becomes urgent. */
    public const DEFAULT_BW_CRITICAL = 0.90;

    /** Seconds between control-plane refreshes of one core's usage. */
    public const DEFAULT_REFRESH_SEC = 300;

    /** Documents indexed after which a refresh is due regardless of the clock. */
    public const DEFAULT_REFRESH_DOCS = 50000;

    /** Hours of the most recent data the trim will never touch, whatever the arithmetic says. */
    public const DEFAULT_MIN_KEEP_HOURS = 24;

    /** Seconds a core is left alone after a trim, so Lucene merges can catch up. */
    public const DEFAULT_COOLDOWN_SEC = 900;

    /** Delete-by-query calls one trim may issue. Each one commits, so this is a real cost. */
    public const DEFAULT_MAX_STEPS = 3;

    /** The largest slice of the data's timespan one step may remove. */
    public const MAX_STEP_FRACTION = 0.25;

    /** Cache-file format version, so a future shape change can be recognised and discarded. */
    private const SCHEMA = 1;

    /** Usage samples kept per core for the growth-rate estimate. */
    private const MAX_SAMPLES = 48;

    /** Seconds between writes of the cache file when only local estimates changed. */
    private const PERSIST_EVERY_SEC = 30;

    /**
     * Seconds before a failed control-plane call is retried.
     *
     * Without it, a refresh that failed leaves `checked_at` old, so the next batch — two
     * seconds later — decides a refresh is due and calls again. An unreachable control plane
     * would turn into one outbound request per batch, which is precisely the cost this
     * class exists to avoid, and it would arrive during whatever incident made the API
     * unreachable in the first place.
     */
    private const FAILURE_BACKOFF_SEC = 60;

    /** Bounds on the learned "index MB per MB of log read" factor. Outside these it is noise. */
    private const MIN_EXPANSION = 0.02;
    private const MAX_EXPANSION = 20.0;

    private Config $cfg;

    /** Control-plane client, or null when this install does not use managed Opensolr. */
    private ?Opensolr $api;

    private string $statePath;

    /** @var array<string,mixed> The decoded cache file. */
    private array $store;

    /**
     * @var array<string,array<string,bool>> Keys this process has changed, per core.
     *
     * The tailer and the panel both write this file. See write(): only these keys are
     * applied on top of whatever is on disk, so neither process rolls back the other's work.
     */
    private array $dirty = [];

    /**
     * The last Solr failure seen while measuring, so trim() can name it.
     *
     * bounds() and count() turn a throw into a null, because a measurement that failed is a
     * reason to refuse a delete rather than an exception to propagate out of a daemon's
     * flush path. Keeping the exception means the refusal can still say WHY — and in
     * particular can tell a quota blackout, where every request answers 403, apart from a
     * node that is merely down.
     */
    private ?\Throwable $lastSolrError = null;

    /** Wall-clock of the last cache write, so local estimates do not write a file per batch. */
    private float $lastPersist = 0.0;

    /** Real control-plane calls made by this instance. Asserted on by the tests. */
    private int $apiCalls = 0;

    /**
     * @param Opensolr|null $api        Injected by tests; built from config otherwise.
     * @param string|null   $statePath  Cache file; defaults to <prefix>/var/quota.json.
     */
    public function __construct(Config $cfg, ?Opensolr $api = null, ?string $statePath = null)
    {
        $this->cfg = $cfg;

        if ($api !== null) {
            $this->api = $api;
        } elseif (getenv('LOGHOUND_TEST') === '1') {
            // SPEC §12: the suite passes with no network access. A test that wants this
            // class to talk to a control plane injects one; anything else building a live
            // client from whatever key happens to be in a config file would make the suite
            // depend on the internet and on somebody's account.
            $this->api = null;
        } elseif ((string) $cfg->get('solr.mode') === 'opensolr'
            && (string) $cfg->get('opensolr.api_key', '') !== ''
        ) {
            $this->api = new Opensolr((array) $cfg->get('opensolr', []));
        } else {
            $this->api = null;
        }

        $this->statePath = $statePath ?? (dirname($cfg->path(), 2) . '/var/quota.json');
        $this->store = $this->read();
    }

    /* ---------------------------------------------------------------------------------
     * Settings
     *
     * Read with this class's own constants as the fallback, so the feature works on an
     * installation whose config predates it. Every one is clamped: a hand-edited
     * high-water of 5.0 must not become "never trim", and one of 0.01 must not become
     * "delete everything continuously".
     * ------------------------------------------------------------------------------ */

    /** Is size-based rolling retention switched on at all? */
    public function enabled(): bool
    {
        return $this->cfg->get('quota.enabled', true) !== false;
    }

    /** Disk ratio at which a trim runs before the next write. */
    public function highWater(): float
    {
        return self::clampFloat($this->cfg->get('quota.disk_high_water'), 0.50, 0.98, self::DEFAULT_HIGH_WATER);
    }

    /**
     * Disk ratio the trim aims for.
     *
     * Forced below the high-water mark: equal values would make every write trigger a trim
     * that frees nothing, which is a delete-and-commit loop against a live index.
     */
    public function target(): float
    {
        $target = self::clampFloat($this->cfg->get('quota.disk_target'), 0.30, 0.95, self::DEFAULT_TARGET);
        return min($target, $this->highWater() - 0.02);
    }

    /** Hours of recent data the trim will never delete. */
    public function minKeepHours(): int
    {
        return Security::clampInt($this->cfg->get('quota.min_keep_hours'), 1, 720, self::DEFAULT_MIN_KEEP_HOURS);
    }

    /** Seconds between control-plane refreshes. */
    public function refreshSec(): int
    {
        return Security::clampInt($this->cfg->get('quota.refresh_sec'), 30, 86400, self::DEFAULT_REFRESH_SEC);
    }

    /** Documents after which a refresh is due regardless of the clock. */
    public function refreshDocs(): int
    {
        return Security::clampInt($this->cfg->get('quota.refresh_docs'), 1000, 10000000, self::DEFAULT_REFRESH_DOCS);
    }

    /** Seconds a core is left alone after a trim. */
    public function cooldownSec(): int
    {
        return Security::clampInt($this->cfg->get('quota.trim_cooldown_sec'), 60, 86400, self::DEFAULT_COOLDOWN_SEC);
    }

    /** Delete-by-query calls one trim may issue. */
    public function maxSteps(): int
    {
        return Security::clampInt($this->cfg->get('quota.max_trim_steps'), 1, 10, self::DEFAULT_MAX_STEPS);
    }

    /**
     * Where the meter sends an operator who wants a bigger plan.
     *
     * Passed through Security::safeUrl(), which answers '#' for anything that is not plainly
     * http(s) — a configured `javascript:` or `data:` URL would otherwise become a live link
     * in the panel chrome, on every page, which is about the best place an attacker could
     * ask for. A refused value falls back to the platform's own pricing page rather than
     * rendering a dead '#'.
     */
    public function upgradeUrl(): string
    {
        $fallback = 'https://opensolr.com/pricing';
        $safe = Security::safeUrl((string) $this->cfg->get('quota.upgrade_url', $fallback));
        return ($safe === '' || $safe === '#') ? $fallback : $safe;
    }

    /** Real control-plane calls this instance has made. */
    public function apiCalls(): int
    {
        return $this->apiCalls;
    }

    /* ---------------------------------------------------------------------------------
     * Facts
     * ------------------------------------------------------------------------------ */

    /**
     * Current usage for one index, from the cache or from the control plane.
     *
     * Never throws and never blocks longer than the API client's own timeout. Failure is a
     * `state` with a sentence attached, exactly as OpensolrLog does it, because "the
     * platform is unreachable" and "this account does not own that index" are things the
     * operator has to be told rather than exceptions for a caller to swallow.
     *
     * The returned `size_mb` may be a local projection; `estimated` says which it is, and
     * every caller that renders it is required to pass that on.
     *
     * @param bool $force Refresh even if the cached answer is still fresh.
     * @return array<string,mixed>
     */
    public function usage(string $core, bool $force = false): array
    {
        if (!Security::isSafeCoreName($core)) {
            return self::unknown($core, 'refused', 'That is not a valid Opensolr index name.');
        }
        if ($this->api === null) {
            return self::unknown(
                $core,
                'not_configured',
                'No Opensolr API key is configured, so Loghound cannot read the account\'s plan. '
                . 'Until one is set there is no limit to work against and nothing is trimmed by size.'
            );
        }

        $entry = $this->entry($core);

        if ($force || $this->refreshDue($entry)) {
            $entry = $this->refresh($core, $entry);
        }

        return $this->shape($core, $entry);
    }

    /**
     * Is a control-plane refresh due for this core?
     *
     * Two triggers, because either alone is wrong. Time alone misses a burst that fills the
     * plan in ninety seconds; documents alone never refreshes an idle install, whose
     * bandwidth is still ticking over from the dashboard's own queries.
     *
     * @param array<string,mixed> $entry
     */
    private function refreshDue(array $entry): bool
    {
        $failed = (int) ($entry['failed_at'] ?? 0);
        if ($failed > 0 && time() - $failed < self::FAILURE_BACKOFF_SEC) {
            return false;
        }

        $checked = (int) ($entry['checked_at'] ?? 0);
        if ($checked <= 0) {
            return true;
        }
        if (time() - $checked >= $this->refreshSec()) {
            return true;
        }
        return (int) ($entry['docs_since'] ?? 0) >= $this->refreshDocs();
    }

    /**
     * Fetch one core's usage from the control plane and fold it into the cached entry.
     *
     * The learned expansion factor is updated here and only here: it is the ratio between
     * the index growth the platform reports and the log bytes Loghound read in the same
     * interval. A trim happened in between often enough that a NEGATIVE growth is ignored
     * rather than treated as a shrinking factor.
     *
     * @param array<string,mixed> $entry
     * @return array<string,mixed>
     */
    private function refresh(string $core, array $entry): array
    {
        $now = time();

        try {
            $this->apiCalls++;
            $data = $this->api->coreUsage($core);
        } catch (\Throwable $e) {
            return $this->put($core, [
                'state'     => 'unreachable',
                'message'   => 'Opensolr could not be reached for the plan usage of this index. '
                    . 'Any figures shown are the last ones it reported.',
                'failed_at' => $now,
            ], true);
        }

        if (($data['state'] ?? '') !== 'ok') {
            return $this->put($core, [
                'state'     => (string) $data['state'],
                'message'   => (string) ($data['message'] ?? ''),
                'failed_at' => $now,
            ], true);
        }

        $changes = [
            'state'       => 'ok',
            'message'     => '',
            'failed_at'   => 0,
            'checked_at'  => $now,
            'size_mb'     => (float) $data['size_mb'],
            'max_size_mb' => (float) $data['max_size_mb'],
            'bw_mb'       => (float) $data['bw_mb'],
            'max_bw_mb'   => (float) $data['max_bw_mb'],
            'account'     => $data['account'],
            'bytes_since' => 0,
            'docs_since'  => 0,
        ];

        $previousSize = isset($entry['size_mb']) ? (float) $entry['size_mb'] : null;
        $bytesSince   = (int) ($entry['bytes_since'] ?? 0);

        if ($previousSize !== null && (int) ($entry['checked_at'] ?? 0) > 0 && $bytesSince > 0) {
            $grown = (float) $data['size_mb'] - $previousSize;
            if ($grown > 0.0) {
                $factor = $grown / ($bytesSince / 1048576.0);
                if ($factor >= self::MIN_EXPANSION && $factor <= self::MAX_EXPANSION) {
                    $changes['expansion'] = round($factor, 4);
                }
            }
        }

        $samples = array_values(array_filter(
            (array) ($entry['samples'] ?? []),
            static fn ($s): bool => is_array($s) && isset($s['t'], $s['mb'])
        ));
        $samples[] = ['t' => $now, 'mb' => (float) $data['size_mb']];
        $changes['samples'] = count($samples) > self::MAX_SAMPLES
            ? array_slice($samples, -self::MAX_SAMPLES)
            : $samples;

        return $this->put($core, $changes, true);
    }

    /**
     * Record what ingestion just wrote, so the size can be projected between refreshes.
     *
     * `$bytes` is the length of the log lines that produced the documents — a figure the
     * tailer already has in hand. Weighing the encoded batch instead would mean serialising
     * every document twice to improve an estimate that the next refresh corrects anyway.
     *
     * The cache file is written at most every PERSIST_EVERY_SEC, so a batch every two
     * seconds does not become a file write every two seconds.
     */
    public function noteWrite(string $core, int $docs, int $bytes): void
    {
        if (!Security::isSafeCoreName($core) || $docs <= 0) {
            return;
        }
        $entry = $this->entry($core);
        $this->put($core, [
            'docs_since'  => (int) ($entry['docs_since'] ?? 0) + max(0, $docs),
            'bytes_since' => (int) ($entry['bytes_since'] ?? 0) + max(0, $bytes),
        ], false);
    }

    /**
     * Turn a cached entry into the structure every caller reads.
     *
     * The projection is applied here rather than at refresh time, so a figure is never
     * stored as if the platform had reported it. What is on disk is what Opensolr said;
     * what comes out of this method may be that plus an estimate, and it is labelled.
     *
     * @param array<string,mixed> $entry
     * @return array<string,mixed>
     */
    private function shape(string $core, array $entry): array
    {
        $state = (string) ($entry['state'] ?? 'unknown');
        if (!isset($entry['size_mb'], $entry['max_size_mb'])) {
            return self::unknown(
                $core,
                $state === 'ok' ? 'unknown' : $state,
                (string) ($entry['message'] ?? 'No plan usage has been read for this index yet.')
            );
        }

        $reported  = (float) $entry['size_mb'];
        $maxSize   = (float) $entry['max_size_mb'];
        $bytes     = (int) ($entry['bytes_since'] ?? 0);
        $expansion = isset($entry['expansion']) ? (float) $entry['expansion'] : 1.0;
        $added     = $bytes > 0 ? ($bytes / 1048576.0) * $expansion : 0.0;
        $size      = $reported + $added;

        $bw    = isset($entry['bw_mb']) ? (float) $entry['bw_mb'] : null;
        $maxBw = isset($entry['max_bw_mb']) ? (float) $entry['max_bw_mb'] : null;

        return [
            'core'          => $core,
            'state'         => $state,
            'message'       => (string) ($entry['message'] ?? ''),
            'checked_at'    => (int) ($entry['checked_at'] ?? 0),
            'age_sec'       => max(0, time() - (int) ($entry['checked_at'] ?? time())),
            'estimated'     => $added > 0.0,
            'reported_mb'   => $reported,
            'size_mb'       => $size,
            'max_size_mb'   => $maxSize > 0.0 ? $maxSize : null,
            'disk_ratio'    => $maxSize > 0.0 ? $size / $maxSize : null,
            'bw_mb'         => $bw,
            'max_bw_mb'     => ($maxBw !== null && $maxBw > 0.0) ? $maxBw : null,
            'bw_ratio'      => ($bw !== null && $maxBw !== null && $maxBw > 0.0) ? $bw / $maxBw : null,
            'ingest_mb_day' => $this->growthMbPerDay($entry),
            'expansion'     => $expansion,
            'account'       => (array) ($entry['account'] ?? []),
            'trim'          => (array) ($entry['trim'] ?? []),
        ];
    }

    /**
     * Observed index growth in MB per day, or null when there is not enough history.
     *
     * Only POSITIVE deltas between consecutive samples are summed. A trim makes the index
     * smaller, and a naive first-to-last slope across a trim would report a negative or
     * near-zero ingest rate exactly on the installations where the number matters most.
     *
     * Null rather than zero when the history is too short: an invented rate would produce
     * an invented retention window, and SPEC §1 forbids fabricating a metric.
     *
     * @param array<string,mixed> $entry
     */
    private function growthMbPerDay(array $entry): ?float
    {
        $samples = array_values(array_filter(
            (array) ($entry['samples'] ?? []),
            static fn ($s): bool => is_array($s) && isset($s['t'], $s['mb'])
        ));
        if (count($samples) < 2) {
            return null;
        }

        $span = (int) $samples[count($samples) - 1]['t'] - (int) $samples[0]['t'];
        if ($span < 600) {
            return null;
        }

        $grown = 0.0;
        for ($i = 1, $n = count($samples); $i < $n; $i++) {
            $delta = (float) $samples[$i]['mb'] - (float) $samples[$i - 1]['mb'];
            if ($delta > 0.0) {
                $grown += $delta;
            }
        }

        return $grown <= 0.0 ? null : round($grown / ($span / 86400.0), 3);
    }

    /* ---------------------------------------------------------------------------------
     * The bandwidth meter
     * ------------------------------------------------------------------------------ */

    /**
     * The bandwidth state, in the words the platform actually enforces.
     *
     * The copy is deliberate and is not to be softened. Exceeding the bandwidth quota does
     * NOT slow the index down and does NOT block only writes: Opensolr denies every request
     * to the index, `/select` included, until the plan is upgraded or the month rolls over
     * on the 1st, and access comes back by itself about seventeen minutes after usage is
     * under the limit again. An operator who reads "you may experience slowdowns" will make
     * the wrong decision, and by the time they find out the panel itself is dark.
     *
     * @return array<string,mixed>
     */
    public function bandwidth(string $core): array
    {
        $usage = $this->usage($core);
        $ratio = $usage['bw_ratio'] ?? null;

        $warn     = self::clampFloat($this->cfg->get('quota.bw_warn'), 0.10, 0.98, self::DEFAULT_BW_WARN);
        $critical = self::clampFloat($this->cfg->get('quota.bw_critical'), $warn + 0.01, 0.99, self::DEFAULT_BW_CRITICAL);

        if ($ratio === null) {
            $level = 'unknown';
        } elseif ($ratio >= 1.0) {
            $level = 'blocked';
        } elseif ($ratio >= $critical) {
            $level = 'critical';
        } elseif ($ratio >= $warn) {
            $level = 'warn';
        } else {
            $level = 'ok';
        }

        return [
            'core'        => $core,
            'state'       => $usage['state'],
            'note'        => $usage['message'],
            'level'       => $level,
            'used_mb'     => $usage['bw_mb'],
            'limit_mb'    => $usage['max_bw_mb'],
            'ratio'       => $ratio,
            'percent'     => $ratio === null ? null : round($ratio * 100, 1),
            'warn_at'     => round($warn * 100, 1),
            'critical_at' => round($critical * 100, 1),
            'resets_at'   => self::nextReset(),
            'resets_in'   => self::secondsToReset(),
            'age_sec'     => $usage['age_sec'],
            'upgrade_url' => $this->upgradeUrl(),
            'consequence' => self::CONSEQUENCE,
            'headline'    => self::bandwidthHeadline($level),
        ];
    }

    /**
     * What exceeding the bandwidth quota actually does. One string, used everywhere.
     *
     * Kept as a constant so the panel, the CLI and the tests all assert on the same
     * sentence: the moment two places word this differently, one of them is wrong.
     */
    public const CONSEQUENCE = 'Going over blocks the index completely: Opensolr answers 403 to every request, '
        . 'reads as well as writes, until the plan is upgraded or the quota resets on the 1st. '
        . 'Access returns on its own about 17 minutes after usage is back under the limit.';

    /**
     * What is said when the platform is refusing every request to an index.
     *
     * One string, used by the trim, the probe and the panel, so the three cannot drift.
     * It has to name the cause, because a bare 403 from a Solr node normally means bad
     * credentials, and an operator sent to check a password that is perfectly correct will
     * not find the quota that is actually blocking them.
     */
    public const BLOCKED_MESSAGE = 'This index is blocked by Opensolr: every request answers 403, reads '
        . 'included, so nothing can be read from it or deleted from it. That happens when it is over its '
        . 'disk or bandwidth quota. Bring usage back under the limit, or upgrade, and access returns by '
        . 'itself about 17 minutes later.';

    /** The short line the meter shows for each level. */
    private static function bandwidthHeadline(string $level): string
    {
        switch ($level) {
            case 'blocked':
                return 'Bandwidth quota exceeded — this index is blocked.';
            case 'critical':
                return 'Bandwidth is nearly used up for this month.';
            case 'warn':
                return 'Bandwidth is past the level worth watching.';
            case 'unknown':
                return 'Bandwidth usage is not known yet.';
            default:
                return 'Bandwidth is within the plan.';
        }
    }

    /** First instant of next month, UTC — when the platform's bandwidth counter resets. */
    public static function nextReset(): string
    {
        return gmdate('Y-m-01\T00:00:00\Z', (int) strtotime('first day of next month', time()));
    }

    /** Seconds until that reset, for a UI that would rather say "in 9 days". */
    public static function secondsToReset(): int
    {
        return max(0, (int) strtotime(self::nextReset()) - time());
    }

    /* ---------------------------------------------------------------------------------
     * The retention window — disk, stated as information and never as an alarm
     * ------------------------------------------------------------------------------ */

    /**
     * How far back the data goes, why that is the limit, and how fast it is filling.
     *
     * Two numbers, and they are different in kind. `observed_days` is a FACT read off the
     * index (newest timestamp minus oldest); `plan_days` is an ESTIMATE of what the plan
     * supports at the current growth rate. Both are reported, both are labelled, and the
     * estimate is omitted entirely rather than guessed when the growth rate is unknown.
     *
     * `limited_by` is the whole point of the card: retention is now two limits, the
     * time-based `privacy.retention_days` and this size-based window, and whichever bites
     * first wins. The operator must be able to see which one is currently in effect.
     *
     * @param float|null $observedDays Span of data in the index, from a min/max facet.
     * @return array<string,mixed>
     */
    public function retentionWindow(string $core, ?float $observedDays = null): array
    {
        $usage = $this->usage($core);
        $days  = (int) $this->cfg->get('privacy.retention_days', 0);
        $rate  = $usage['ingest_mb_day'] ?? null;
        $max   = $usage['max_size_mb'] ?? null;

        $planDays = null;
        if ($rate !== null && $rate > 0.0 && $max !== null && $max > 0.0 && $this->enabled()) {
            $planDays = round(($max * $this->target()) / $rate, 1);
        }

        $timeDays = $days > 0 ? (float) $days : null;

        $limitedBy = 'none';
        if ($timeDays !== null && $planDays !== null) {
            $limitedBy = $planDays < $timeDays ? 'size' : 'time';
        } elseif ($planDays !== null) {
            $limitedBy = 'size';
        } elseif ($timeDays !== null) {
            $limitedBy = 'time';
        }

        return [
            'core'            => $core,
            'state'           => $usage['state'],
            'enabled'         => $this->enabled(),
            'observed_days'   => $observedDays,
            'plan_days'       => $planDays,
            'retention_days'  => $timeDays,
            'limited_by'      => $limitedBy,
            'ingest_mb_day'   => $rate,
            'size_mb'         => $usage['size_mb'],
            'max_size_mb'     => $max,
            'disk_ratio'      => $usage['disk_ratio'],
            'estimated'       => $usage['estimated'],
            'high_water'      => $this->highWater(),
            'target'          => $this->target(),
            'trim'            => $usage['trim'],
            'sentence'        => $this->windowSentence($observedDays, $planDays, $timeDays, $limitedBy, $rate, $max),
            'trim_alert'      => $this->trimAlert($core, $usage),
            'upgrade_url'     => $this->upgradeUrl(),
        ];
    }

    /**
     * The plain-language line the operator reads.
     *
     * Neutral by construction. Disk is a managed dimension — the trim runs before the write,
     * so the index does not reach the quota — and a sentence about how far back the data
     * goes is information, not a problem. Every clause here is derived from a number that
     * was actually computed; where one is missing the clause is dropped rather than filled
     * in with a plausible figure.
     */
    private function windowSentence(
        ?float $observed,
        ?float $plan,
        ?float $time,
        string $limitedBy,
        ?float $rate,
        ?float $max
    ): string {
        $parts = [];

        if ($observed !== null) {
            $parts[] = 'You have ' . self::days($observed) . ' of traffic in this index right now.';
        }

        if ($limitedBy === 'size' && $plan !== null && $max !== null) {
            $parts[] = 'At the current rate your ' . self::mb($max) . ' plan holds roughly '
                . self::days($plan) . ', and Loghound keeps the window at about that by deleting '
                . 'the oldest data before it writes new data.';
        } elseif ($limitedBy === 'time' && $time !== null) {
            $parts[] = 'Your age limit keeps ' . self::days($time) . ', which is what limits the window'
                . ($plan !== null ? ' — the plan itself would hold roughly ' . self::days($plan) . '.' : '.');
        } elseif ($limitedBy === 'none') {
            /* "NOTHING IS BEING DELETED" IS ONLY TRUE IF THE SIZE RULE IS ALSO OFF. `limitedBy`
               falls to 'none' whenever the window cannot be PROJECTED — and it cannot be
               projected until the ingest rate is known, which takes two usage readings ten
               minutes apart. So a fresh install with the rolling trim on, which is the default,
               was told nothing is being deleted for either reason, one sentence before being
               told the rate is not known yet. Not knowing how far back the data goes is not the
               same fact as nothing being deleted, and the two branches say so separately. */
            $parts[] = $this->enabled()
                ? 'How far back the data goes cannot be stated yet: no age limit is set, and the plan '
                  . 'disk quota for this index has not been read. Data is still deleted when the index '
                  . 'runs out of that disk, oldest first.'
                : 'Nothing limits how far back the data goes: there is no age limit, and deleting for '
                  . 'size is switched off. An index that reaches its Opensolr disk quota is blocked by '
                  . 'the platform, reads included.';
        }

        if ($rate !== null) {
            $parts[] = 'Current ingest is about ' . self::mb($rate) . ' per day.';
        } else {
            $parts[] = 'The ingest rate is not known yet — it needs at least two usage readings '
                . 'ten minutes apart — so the window cannot be projected.';
        }

        if ($plan !== null || $rate !== null) {
            $parts[] = 'These are estimates from observed growth, not exact figures.';
        }

        return implode(' ', $parts);
    }

    /**
     * The one disk condition that IS a fault: the trim could not free space and the index
     * is genuinely close to the limit.
     *
     * Everything else about disk is informational. This is not: a failing trim means the
     * index really will reach the quota, and the blackout that follows takes the dashboard
     * with it, so it has to be loud while there is still someone able to read it.
     *
     * @param array<string,mixed> $usage
     * @return array<string,mixed>|null
     */
    private function trimAlert(string $core, array $usage): ?array
    {
        $trim  = (array) ($usage['trim'] ?? []);
        $ratio = $usage['disk_ratio'] ?? null;

        if ($ratio === null || $ratio < $this->highWater()) {
            return null;
        }
        if (($trim['state'] ?? 'ok') !== 'failed') {
            return null;
        }

        return [
            'core'    => $core,
            'percent' => round($ratio * 100, 1),
            'reason'  => (string) ($trim['message'] ?? 'unknown reason'),
            'at'      => (int) ($trim['at'] ?? 0),
            'text'    => 'Loghound could not free space in this index. It is at '
                . round($ratio * 100, 1) . '% of the plan limit and the rolling trim failed: '
                . (string) ($trim['message'] ?? 'unknown reason')
                . ' If it reaches the limit, Opensolr blocks the index completely — reads as well as writes.',
        ];
    }

    /* ---------------------------------------------------------------------------------
     * The trim
     * ------------------------------------------------------------------------------ */

    /**
     * Work out the cutoff instant for one trim step, or null when it must not run.
     *
     * PURE, and separated from everything that touches Solr precisely so it can be tested
     * to death. A wrong answer here destroys the operator's data and there is no undo.
     *
     * The arithmetic: the index is at `$ratio` of its limit and wants to be at `$target`,
     * so the fraction of it that has to go is (ratio - target) / ratio. Bytes are assumed to
     * be spread evenly over time, so that fraction of the DATA is that fraction of its
     * TIMESPAN, measured from the oldest document. The assumption is only ever approximate;
     * it does not have to be exact, because the caller measures what the cutoff would
     * actually delete and re-checks instead of trusting one calculation.
     *
     * It returns null — refusing the trim — for every one of these:
     *   - the ratio is already at or under target, so there is nothing to do;
     *   - either bound is missing, or they are equal, or they are inverted (a clock that
     *     moved, or a bounds query that came back malformed);
     *   - the newest document is in the future by more than a minute, which means the
     *     timestamps cannot be trusted to compute a window from;
     *   - the computed cutoff is not strictly after the oldest document, so the delete
     *     would remove nothing while still costing a commit;
     *   - the cutoff falls inside the protected recent window (default 24h), which is the
     *     backstop against every arithmetic mistake above: whatever the numbers say, the
     *     last day of traffic is not deleted by an automatic process.
     *
     * A single step is additionally capped at MAX_STEP_FRACTION of the timespan, so an
     * index that is somehow at 300% of its limit still comes down in bounded slices that
     * the caller re-measures between.
     *
     * @param array{min:?int,max:?int} $bounds Unix seconds of the oldest and newest document.
     * @return int|null Unix seconds; delete everything strictly older than this.
     */
    public static function computeCutoff(
        array $bounds,
        float $ratio,
        float $target,
        int $now,
        int $minKeepHours = self::DEFAULT_MIN_KEEP_HOURS
    ): ?int {
        $min = $bounds['min'] ?? null;
        $max = $bounds['max'] ?? null;

        if ($min === null || $max === null) {
            return null;
        }
        if ($ratio <= $target || $ratio <= 0.0 || $target <= 0.0) {
            return null;
        }
        if ($max <= $min) {
            return null;
        }
        if ($max > $now + 60) {
            return null;
        }

        $span = $max - $min;
        $drop = ($ratio - $target) / $ratio;
        $drop = min($drop, self::MAX_STEP_FRACTION);
        if ($drop <= 0.0) {
            return null;
        }

        $cutoff = $min + (int) floor($span * $drop);
        if ($cutoff <= $min) {
            return null;
        }

        $floor = $now - ($minKeepHours * 3600);
        if ($cutoff > $floor) {
            $cutoff = $floor;
        }
        if ($cutoff <= $min) {
            return null;
        }

        return $cutoff;
    }

    /**
     * Bring one index back under the disk target by deleting its oldest data.
     *
     * The loop is deliberately not "delete and re-read the size". Lucene marks documents
     * deleted and gives the bytes back only when a merge rewrites the segment, so the
     * platform would report the SAME size straight after a successful delete — and a naive
     * re-check would trim again, and again, until the index was empty. Instead each step
     * COUNTS what its cutoff covers, deletes it, and reduces the working ratio by the
     * fraction of documents removed. The next real refresh corrects the estimate once the
     * merges have happened; the cooldown stops another trim starting before then.
     *
     * A step refuses rather than guesses. If the count comes back as the whole index, the
     * step is abandoned: no automatic process empties an index, whatever the arithmetic
     * said.
     *
     * The core and its timestamp field are checked against the configuration as a pair, so
     * a hits-core signal can never delete from the sessions core. That is not a theoretical
     * concern — the two calls differ by one string argument.
     *
     * @param object              $solr  A \Loghound\Solr (duck-typed so tests can inject).
     * @param array<string,mixed> $opt   dry_run:bool, extra_fq:?string, logger:?callable
     * @return array<string,mixed>
     */
    public function trim(object $solr, string $core, string $tsField, array $opt = []): array
    {
        $dryRun = (bool) ($opt['dry_run'] ?? false);
        $log    = $opt['logger'] ?? static function (string $m): void {
        };
        $extra  = isset($opt['extra_fq']) ? (string) $opt['extra_fq'] : null;

        $steps  = [];
        $result = static function (string $state, string $message) use ($core, &$steps): array {
            return ['core' => $core, 'state' => $state, 'message' => $message, 'steps' => $steps, 'deleted' => 0];
        };

        if (!$this->enabled()) {
            return $result('disabled', 'Size-based retention is switched off (quota.enabled = false).');
        }
        $this->assertCorePair($core, $tsField);

        $usage = $this->usage($core);
        if ($usage['state'] !== 'ok') {
            return $result('skipped', $usage['message'] !== ''
                ? $usage['message']
                : 'No plan usage is available for this index, so nothing is trimmed.');
        }

        $ratio = $usage['disk_ratio'];
        $max   = $usage['max_size_mb'];
        if ($ratio === null || $max === null || $max <= 0.0) {
            return $result('skipped', 'This index has no readable plan limit, so nothing is trimmed.');
        }
        if ($ratio < $this->highWater()) {
            return $result('ok', 'At ' . round($ratio * 100, 1) . '% of the plan limit — under the '
                . round($this->highWater() * 100) . '% mark, so nothing needs deleting.');
        }

        $entry = $this->entry($core);
        $last  = (int) (($entry['trim']['at'] ?? 0));
        if (!$dryRun && $last > 0 && time() - $last < $this->cooldownSec()) {
            return $result('cooldown', 'A trim ran ' . (time() - $last) . 's ago. Waiting for Lucene to '
                . 'reclaim the space before deciding whether more has to go.');
        }

        $target  = $this->target();
        $working = $ratio;
        $deleted = 0;

        $this->lastSolrError = null;

        for ($step = 0; $step < $this->maxSteps(); $step++) {
            $bounds = $this->bounds($solr, $core, $tsField, $extra);
            if ($bounds === null) {
                if ($this->lastSolrError !== null && self::blackout($this->lastSolrError)) {
                    $this->recordTrim($core, 'failed', 'the index is blocked by Opensolr (403 on every request)', 0);
                    return $result('failed', self::BLOCKED_MESSAGE);
                }
                $steps[] = ['state' => 'refused', 'why' => 'The oldest and newest timestamps could not be read.'];
                break;
            }
            if ($bounds['count'] <= 0) {
                $steps[] = ['state' => 'empty', 'why' => 'The index holds no documents in this range.'];
                break;
            }

            $cutoff = self::computeCutoff($bounds, $working, $target, time(), $this->minKeepHours());
            if ($cutoff === null) {
                $steps[] = ['state' => 'refused', 'why' => 'No safe cutoff could be computed for this step.'];
                break;
            }

            $iso = gmdate('Y-m-d\TH:i:s\Z', $cutoff);
            $fq  = Solr::rangeFilter($tsField, null, $iso);
            if ($extra !== null) {
                $fq = '+' . $extra . ' +' . $fq;
            }

            $covered = $this->count($solr, $core, $fq);
            if ($covered === null) {
                if ($this->lastSolrError !== null && self::blackout($this->lastSolrError)) {
                    $this->recordTrim($core, 'failed', 'the index is blocked by Opensolr (403 on every request)', $deleted);
                    return $result('failed', self::BLOCKED_MESSAGE);
                }
                $steps[] = [
                    'state'  => 'failed',
                    'cutoff' => $iso,
                    'why'    => 'The documents to delete could not be counted, so nothing was deleted.',
                ];
                break;
            }
            if ($covered <= 0) {
                $steps[] = ['state' => 'empty', 'cutoff' => $iso, 'why' => 'Nothing is older than that cutoff.'];
                break;
            }
            if ($covered >= $bounds['count']) {
                $steps[] = [
                    'state'  => 'refused',
                    'cutoff' => $iso,
                    'why'    => 'That cutoff covers every document in the index, so it was not run.',
                ];
                break;
            }

            if ($dryRun) {
                $steps[] = ['state' => 'would_delete', 'cutoff' => $iso, 'docs' => $covered, 'query' => $fq];
                $deleted += $covered;
            } else {
                try {
                    $solr->deleteByQuery($core, $fq);
                } catch (\Throwable $e) {
                    $steps[] = ['state' => 'failed', 'cutoff' => $iso, 'docs' => $covered, 'why' => $e->getMessage()];
                    $this->recordTrim($core, 'failed', self::blackout($e)
                        ? 'the index is blocked by Opensolr (403 on every request)'
                        : $e->getMessage(), $deleted);
                    return $result(
                        'failed',
                        self::blackout($e) ? self::BLOCKED_MESSAGE : 'The delete failed: ' . $e->getMessage()
                    );
                }
                $steps[] = ['state' => 'deleted', 'cutoff' => $iso, 'docs' => $covered, 'query' => $fq];
                $deleted += $covered;
                $log(sprintf(
                    'trimmed %s: deleted %d document(s) older than %s (%.1f%% of the plan limit)',
                    $core,
                    $covered,
                    $iso,
                    $working * 100
                ));
            }

            $working *= ($bounds['count'] - $covered) / $bounds['count'];
            if ($working <= $target) {
                break;
            }

            // A dry run stops after one step, always. Nothing was deleted, so the bounds
            // query would return exactly the same answer and the loop would report the same
            // cutoff three times. One honest step is the useful thing to show.
            if ($dryRun) {
                break;
            }
        }

        $state = 'ok';
        foreach ($steps as $s) {
            if (($s['state'] ?? '') === 'failed' || ($s['state'] ?? '') === 'refused') {
                $state = $s['state'] === 'failed' ? 'failed' : 'refused';
            }
        }

        $outcome = $state !== 'ok'
            ? (string) ($steps[count($steps) - 1]['why'] ?? 'The trim did not complete.')
            : ($deleted > 0
                ? 'Deleted ' . $deleted . ' document(s); the window now starts later.'
                : 'Nothing was deleted: no step found data it was allowed to remove.');

        if (!$dryRun) {
            $this->recordTrim($core, $state, $outcome, $deleted);
        }

        return [
            'core'    => $core,
            'state'   => $state,
            'message' => $dryRun ? 'Dry run: ' . $deleted . ' document(s) would be deleted.' : $outcome,
            'steps'   => $steps,
            'deleted' => $deleted,
            'from'    => $ratio,
            'to'      => $working,
            'target'  => $target,
        ];
    }

    /**
     * The hook ingestion calls before it writes a batch.
     *
     * This is the whole feature in one method: know the disk ratio, and if it is over the
     * high-water mark, make room BEFORE writing rather than after crossing the quota. The
     * ordering is the point — trimming after the write is trimming after the blackout.
     *
     * It is cheap in the common case and must stay that way. usage() answers from the cache
     * on all but one call in `refresh_sec` seconds or `refresh_docs` documents, and the trim
     * itself only runs above the high-water mark and then not again until the cooldown has
     * passed. On a healthy install this costs one array lookup per batch.
     *
     * It never throws. A daemon that stops ingesting because its quota bookkeeping had a bad
     * day is a worse outcome than one that keeps ingesting without it, so a failure here is
     * reported to the caller's logger and ingestion continues.
     *
     * @param array<string,mixed> $opt extra_fq:?string, logger:?callable
     * @return array<string,mixed> ['action' => 'none'|'trimmed'|'failed'|'unavailable', ...]
     */
    public function guardBeforeWrite(object $solr, string $core, string $tsField, array $opt = []): array
    {
        if (!$this->enabled()) {
            return ['action' => 'none', 'reason' => 'disabled'];
        }

        try {
            $usage = $this->usage($core);
        } catch (\Throwable $e) {
            return ['action' => 'unavailable', 'reason' => $e->getMessage()];
        }

        if ($usage['state'] !== 'ok' || $usage['disk_ratio'] === null) {
            return ['action' => 'none', 'reason' => $usage['state']];
        }
        if ($usage['disk_ratio'] < $this->highWater()) {
            return ['action' => 'none', 'reason' => 'under the high-water mark', 'ratio' => $usage['disk_ratio']];
        }

        try {
            $trim = $this->trim($solr, $core, $tsField, $opt);
        } catch (\Throwable $e) {
            return ['action' => 'failed', 'reason' => $e->getMessage(), 'ratio' => $usage['disk_ratio']];
        }

        return [
            'action'  => $trim['state'] === 'ok' ? 'trimmed' : ($trim['state'] === 'cooldown' ? 'none' : $trim['state']),
            'reason'  => $trim['message'],
            'deleted' => $trim['deleted'],
            'ratio'   => $usage['disk_ratio'],
        ];
    }

    /**
     * Refuse a core/timestamp-field pair that does not belong together.
     *
     * `ts` lives on hit documents and `ts_start` on session documents. Calling trim() with
     * the hits core and `ts_start` would build a filter that matches nothing, which is
     * harmless; calling it with the sessions core and a hits-core decision is not, and this
     * is the only place that can tell the difference.
     *
     * @throws \InvalidArgumentException when the pair is not one of the two valid ones.
     */
    private function assertCorePair(string $core, string $tsField): void
    {
        $hits     = (string) $this->cfg->get('solr.hits_core');
        $sessions = (string) $this->cfg->get('solr.sessions_core');

        if ($core !== '' && $core === $hits && $tsField === 'ts') {
            return;
        }
        if ($core !== '' && $core === $sessions && $tsField === 'ts_start') {
            return;
        }
        throw new \InvalidArgumentException(
            'Quota: refusing to trim "' . $core . '" on field "' . $tsField . '" — '
            . 'that is not a configured core and timestamp pair.'
        );
    }

    /**
     * Oldest and newest timestamp, and the document count, in one facet request.
     *
     * Returned as Unix seconds because every comparison in computeCutoff() is arithmetic,
     * and because a string comparison of two ISO instants is the kind of thing that works
     * until a fractional second appears in one of them.
     *
     * @return array{min:?int,max:?int,count:int}|null
     */
    private function bounds(object $solr, string $core, string $tsField, ?string $extraFq): ?array
    {
        $params = ['q' => '*:*'];
        if ($extraFq !== null) {
            $params['fq'] = [$extraFq];
        }

        try {
            $res = $solr->jsonFacet($core, $params, [
                'oldest' => 'min(' . $tsField . ')',
                'newest' => 'max(' . $tsField . ')',
            ]);
        } catch (\Throwable $e) {
            $this->lastSolrError = $e;
            return null;
        }

        $facets = is_array($res['facets'] ?? null) ? $res['facets'] : $res;
        $min = self::toEpoch($facets['oldest'] ?? null);
        $max = self::toEpoch($facets['newest'] ?? null);
        $count = (int) ($facets['count'] ?? ($res['response']['numFound'] ?? 0));

        if ($min === null && $max === null && $count === 0) {
            return ['min' => null, 'max' => null, 'count' => 0];
        }
        return ['min' => $min, 'max' => $max, 'count' => $count];
    }

    /**
     * Count the documents one filter covers, or null when the query failed.
     *
     * `rows=0`: this is the measurement that decides whether a delete is safe, and it must
     * not drag documents back across the network to answer it.
     */
    private function count(object $solr, string $core, string $fq): ?int
    {
        try {
            $res = $solr->query($core, ['q' => '*:*', 'fq' => [$fq], 'rows' => 0]);
        } catch (\Throwable $e) {
            $this->lastSolrError = $e;
            return null;
        }
        return (int) ($res['response']['numFound'] ?? 0);
    }

    /**
     * Does this failure look like the platform's quota blackout rather than a normal error?
     *
     * The blackout is an Apache `Deny from all`, so what comes back is a 403 with an HTML
     * body — which the Solr client reports as an unparseable body rather than as a Solr
     * error. Both spellings are matched, because reporting a blackout as "check your
     * credentials" sends the operator to fix something that is not broken.
     */
    public static function blackout(\Throwable $e): bool
    {
        $m = $e->getMessage();
        return str_contains($m, '403') || stripos($m, 'forbidden') !== false;
    }

    /**
     * Probe whether an index is currently blacked out.
     *
     * Used by the panel so a dashboard full of failed cards can say WHY in one sentence
     * instead of leaving the operator to guess. Never throws: this is a diagnosis, and a
     * diagnosis that crashes is worse than none.
     *
     * @return array{state:string,message:string}
     */
    public function probe(object $solr, string $core): array
    {
        try {
            $solr->query($core, ['q' => '*:*', 'rows' => 0]);
            return ['state' => 'ok', 'message' => ''];
        } catch (\Throwable $e) {
            if (self::blackout($e)) {
                return ['state' => 'blocked', 'message' => self::BLOCKED_MESSAGE];
            }
            return ['state' => 'unreachable', 'message' => 'Solr did not answer: ' . $e->getMessage()];
        }
    }

    /* ---------------------------------------------------------------------------------
     * The cache file
     * ------------------------------------------------------------------------------ */

    /**
     * One core's cached entry, or a fresh empty one.
     *
     * @return array<string,mixed>
     */
    private function entry(string $core): array
    {
        $entry = $this->store['cores'][$core] ?? [];
        return is_array($entry) ? $entry : [];
    }

    /**
     * Apply changes to one core's entry and persist when it is worth persisting.
     *
     * CHANGES, not a whole entry, and the difference is the point. Two processes share this
     * file: the tailer, which owns the local ingest counters, and the panel, which refreshes
     * the facts when an operator is looking. If either wrote back the entire entry as it
     * looked when the process started, it would silently roll back whatever the other had
     * done in between — the tailer's byte counter, or the trim record the panel needs in
     * order to warn about a failing trim. Recording which keys this process actually touched
     * lets write() merge them onto whatever is on disk now instead.
     *
     * @param array<string,mixed> $changes
     * @return array<string,mixed> The core's entry after the change.
     */
    private function put(string $core, array $changes, bool $now): array
    {
        $entry = array_merge($this->entry($core), $changes);
        $this->store['cores'][$core] = $entry;

        foreach (array_keys($changes) as $key) {
            $this->dirty[$core][(string) $key] = true;
        }

        if ($now || (microtime(true) - $this->lastPersist) >= self::PERSIST_EVERY_SEC) {
            $this->write();
        }
        return $entry;
    }

    /**
     * Record the outcome of a trim against the core it ran on.
     *
     * Kept because the one disk condition that deserves a warning is a FAILED trim, and that
     * fact has to survive the process that discovered it: the tailer is what notices, and
     * the panel is what has to say so.
     */
    private function recordTrim(string $core, string $state, string $message, int $deleted): void
    {
        $this->put($core, [
            'trim' => [
                'at'      => time(),
                'state'   => $state,
                'message' => $message,
                'deleted' => $deleted,
            ],
        ], true);
    }

    /**
     * Read the cache file, tolerating every way it can be unusable.
     *
     * A missing, unreadable, truncated or schema-shifted file is simply an empty cache: the
     * next refresh rebuilds it. Failing here would take down ingestion over a cache.
     *
     * @return array<string,mixed>
     */
    private function read(): array
    {
        $empty = ['schema' => self::SCHEMA, 'cores' => []];

        if (!is_file($this->statePath) || !is_readable($this->statePath)) {
            return $empty;
        }
        $raw = @file_get_contents($this->statePath);
        if (!is_string($raw) || $raw === '') {
            return $empty;
        }
        $data = json_decode($raw, true);
        if (!is_array($data) || (int) ($data['schema'] ?? 0) !== self::SCHEMA || !is_array($data['cores'] ?? null)) {
            return $empty;
        }
        return $data;
    }

    /**
     * Write the cache file atomically, merging this process's changes onto what is on disk.
     *
     * Temp file plus rename, so a reader never sees a half-written document, and mode 0640
     * because the daemon writes it and the panel reads it and nobody else needs either. A
     * failure is swallowed: a read-only var/ must degrade to "no cache, refresh every time",
     * not to a daemon that will not ingest.
     *
     * The merge re-reads the file first and applies only the keys this process changed. It
     * is not a lock and does not pretend to be one — two writers landing in the same
     * millisecond still resolve as last-writer-wins on the keys they both touched — but it
     * removes the case that actually happens, which is one process holding a minutes-old
     * copy of the whole document and writing it back over somebody else's fresh work.
     */
    private function write(): void
    {
        $this->lastPersist = microtime(true);

        $dir = dirname($this->statePath);
        if (!is_dir($dir) && !@mkdir($dir, 0750, true) && !is_dir($dir)) {
            return;
        }

        $merged = $this->read();
        foreach ($this->dirty as $core => $keys) {
            $entry = is_array($merged['cores'][$core] ?? null) ? $merged['cores'][$core] : [];
            foreach (array_keys($keys) as $key) {
                $entry[$key] = $this->store['cores'][$core][$key] ?? null;
            }
            $merged['cores'][$core] = $entry;
        }
        $this->store = $merged;

        $json = json_encode($this->store, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($json === false) {
            return;
        }
        $tmp = $dir . '/.quota.' . bin2hex(random_bytes(6)) . '.tmp';
        if (@file_put_contents($tmp, $json, LOCK_EX) === false) {
            return;
        }
        @chmod($tmp, 0640);
        if (!@rename($tmp, $this->statePath)) {
            @unlink($tmp);
            return;
        }
        $this->dirty = [];
    }

    /** Flush any pending local estimate to disk. Called when a daemon shuts down. */
    public function flush(): void
    {
        $this->write();
    }

    /* ---------------------------------------------------------------------------------
     * Small helpers
     * ------------------------------------------------------------------------------ */

    /**
     * The envelope returned when there is no usage to report, identical in shape to a real
     * one so no caller has to branch on whether a key exists.
     *
     * @return array<string,mixed>
     */
    private static function unknown(string $core, string $state, string $message): array
    {
        return [
            'core'          => $core,
            'state'         => $state,
            'message'       => $message,
            'checked_at'    => 0,
            'age_sec'       => 0,
            'estimated'     => false,
            'reported_mb'   => null,
            'size_mb'       => null,
            'max_size_mb'   => null,
            'disk_ratio'    => null,
            'bw_mb'         => null,
            'max_bw_mb'     => null,
            'bw_ratio'      => null,
            'ingest_mb_day' => null,
            'expansion'     => 1.0,
            'account'       => [],
            'trim'          => [],
        ];
    }

    /**
     * Parse a Solr instant (or a numeric epoch) into Unix seconds.
     *
     * Returns null for anything it cannot read, because a bad bound has to REFUSE a delete
     * rather than be coerced into a plausible-looking one.
     *
     * @param mixed $value
     */
    private static function toEpoch($value): ?int
    {
        if (is_int($value) || is_float($value)) {
            return (int) $value;
        }
        if (!is_string($value) || $value === '') {
            return null;
        }
        $ts = strtotime($value);
        return $ts === false ? null : $ts;
    }

    /** Clamp a configured float, falling back when it is absent or not a number. */
    private static function clampFloat($value, float $min, float $max, float $default): float
    {
        if (!is_int($value) && !is_float($value) && !(is_string($value) && is_numeric($value))) {
            return $default;
        }
        return max($min, min($max, (float) $value));
    }

    /** "11 days" / "18 hours" / "2.5 days", for a sentence rather than a table. */
    public static function days(float $days): string
    {
        if ($days < 1.0) {
            $hours = max(1, (int) round($days * 24));
            return $hours . ' hour' . ($hours === 1 ? '' : 's');
        }
        if ($days < 10.0) {
            return rtrim(rtrim(number_format($days, 1), '0'), '.') . ' days';
        }
        return number_format($days, 0) . ' days';
    }

    /** Megabytes rendered at the scale a human reads them. */
    public static function mb(float $mb): string
    {
        if ($mb >= 1048576.0) {
            return number_format($mb / 1048576.0, 1) . ' TB';
        }
        if ($mb >= 1024.0) {
            return number_format($mb / 1024.0, 1) . ' GB';
        }
        if ($mb >= 10.0) {
            return number_format($mb, 0) . ' MB';
        }
        return number_format($mb, 1) . ' MB';
    }
}
