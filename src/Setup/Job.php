<?php
/**
 * Loghound — resumable setup jobs.
 *
 * WHY THIS EXISTS AT ALL
 *
 * Provisioning two Opensolr indexes takes around forty seconds against the live control
 * plane. The panel's PHP-FPM pool sets `max_execution_time = 60`. A synchronous request
 * that creates the indexes, uploads two configsets each, and then verifies connectivity
 * would be killed by the gateway somewhere in the middle — leaving indexes created, money
 * being spent on them, and no configuration written to say they exist. That is the single
 * worst place in the whole flow to fail.
 *
 * So every operation that can take more than a moment is a JOB: an ordered list of small,
 * individually named, individually attributable steps, with its state on disk.
 *
 * HOW IT RUNS WITHOUT A BACKGROUND PROCESS
 *
 * The reference PHP-FPM pool disables exec/proc_open/popen — correctly — so there is no
 * forking a worker, and `set_time_limit()` cannot lift a `php_admin_value`. Instead the
 * job is driven by the browser:
 *
 *   POST  ?setup=job&action=run     runs steps until a wall-clock budget is spent, then
 *                                   returns. The browser calls it again if work remains.
 *   GET   ?setup=job&action=status  cheap read of the state file, polled once a second,
 *                                   so progress appears while a step is still running.
 *
 * Concurrency is handled with an exclusive lock on a separate lock file: a second runner
 * (a double-click, a refresh, a second tab) cannot get it and returns the current status
 * instead. That is what makes "reload mid-provision" reattach rather than create a second
 * pair of indexes.
 *
 * The same object runs the CLI wizard: `runAll()` walks the identical steps with no budget
 * and prints each one. There is exactly one implementation of what provisioning MEANS, and
 * both front ends drive it.
 *
 * WHAT IS NEVER IN A JOB FILE
 *
 * No secrets. Not the Opensolr API key, not the beacon secret, not a password. A step that
 * needs the API key reads it from the configuration, which is the one place it is allowed
 * to live. Job files hold step names, human-readable progress notes, and index names.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Setup;

use Loghound\Config;

final class Job
{
    /** Kinds. Each maps to a step builder; anything else is refused. */
    public const KIND_DETECT   = 'detect';
    public const KIND_OPENSOLR = 'opensolr';
    public const KIND_SOLRTEST = 'solrtest';

    /**
     * Adopting a pair of indexes the account already holds.
     *
     * A kind of its own rather than a flag on KIND_OPENSOLR, because the two have different
     * steps, different failure modes and different consequences: one creates indexes and can
     * leave something behind, the other creates nothing and must not. Keeping them apart is
     * what stops a reuse run from ever reaching a create call.
     */
    public const KIND_REUSE = 'reuse';

    /** @return string[] Every kind create() will accept. */
    public static function kinds(): array
    {
        return [self::KIND_DETECT, self::KIND_OPENSOLR, self::KIND_SOLRTEST, self::KIND_REUSE];
    }

    /** Seconds a single browser-driven run() may spend before handing control back. */
    private const BUDGET_SECONDS = 20;

    /** Notes kept per job. A runaway loop must not grow the file without bound. */
    private const MAX_NOTES = 300;

    /** A job older than this is stale and may be cleaned up. */
    private const MAX_AGE = 3600;

    private string $dir;

    private string $id;

    /** @var array<string,mixed> The persisted state. */
    private array $data;

    /**
     * @param array<string,mixed> $data
     */
    private function __construct(string $dir, string $id, array $data)
    {
        $this->dir  = rtrim($dir, '/');
        $this->id   = $id;
        $this->data = $data;
    }

    /**
     * Start a new job of the given kind.
     *
     * @param array<string,mixed> $params Non-secret inputs, e.g. the chosen region.
     */
    public static function create(string $dir, string $kind, array $params = []): self
    {
        if (!in_array($kind, self::kinds(), true)) {
            throw new \InvalidArgumentException('Unknown job kind: ' . $kind);
        }
        $dir = rtrim($dir, '/');
        if (!is_dir($dir) && !@mkdir($dir, 0750, true) && !is_dir($dir)) {
            throw new \RuntimeException('Cannot create the job directory: ' . $dir);
        }

        $job = new self($dir, bin2hex(random_bytes(8)), [
            'id'         => '',
            'kind'       => $kind,
            'params'     => $params,
            'created_at' => time(),
            'updated_at' => time(),
            'state'      => 'running',
            'steps'      => [],
            'notes'      => [],
            'result'     => [],
            'error'      => '',
            'attempt'    => 0,
        ]);
        $job->data['id'] = $job->id;
        $job->write();

        return $job;
    }

    /**
     * Load an existing job by id.
     *
     * The id is validated as pure hex before it touches the filesystem: it arrives from
     * the query string, and an id is never a path.
     */
    public static function load(string $dir, string $id): ?self
    {
        if (!preg_match('/^[a-f0-9]{16}$/', $id)) {
            return null;
        }
        $path = rtrim($dir, '/') . '/' . $id . '.json';
        if (!is_file($path)) {
            return null;
        }
        $raw = @file_get_contents($path);
        $data = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($data)) {
            return null;
        }
        return new self($dir, $id, $data);
    }

    /**
     * Find the newest job of a kind that is still running.
     *
     * This is what makes the page resumable: after a reload the installer looks for an
     * unfinished job of the step it is on and reattaches to it, instead of starting a
     * second one and creating a second pair of indexes.
     */
    public static function findRunning(string $dir, string $kind): ?self
    {
        $best = null;
        foreach ((glob(rtrim($dir, '/') . '/*.json') ?: []) as $path) {
            $job = self::load($dir, basename($path, '.json'));
            if ($job === null || $job->kind() !== $kind) {
                continue;
            }
            if ($job->state() !== 'running') {
                continue;
            }
            if ($job->age() > self::MAX_AGE) {
                continue;
            }
            if ($best === null || $job->createdAt() > $best->createdAt()) {
                $best = $job;
            }
        }
        return $best;
    }

    /** Delete job files that are finished or long stale, so var/ does not accumulate. */
    public static function sweep(string $dir): void
    {
        foreach ((glob(rtrim($dir, '/') . '/*.json') ?: []) as $path) {
            if (time() - (int) @filemtime($path) > self::MAX_AGE) {
                @unlink($path);
                @unlink(substr($path, 0, -5) . '.lock');
            }
        }
    }

    public function id(): string
    {
        return $this->id;
    }

    public function kind(): string
    {
        return (string) $this->data['kind'];
    }

    public function state(): string
    {
        return (string) $this->data['state'];
    }

    public function error(): string
    {
        return (string) $this->data['error'];
    }

    public function createdAt(): int
    {
        return (int) $this->data['created_at'];
    }

    public function age(): int
    {
        return time() - (int) $this->data['created_at'];
    }

    /** @return array<string,mixed> */
    public function params(): array
    {
        return (array) $this->data['params'];
    }

    /** @return array<string,mixed> Whatever the steps have produced so far. */
    public function result(): array
    {
        return (array) $this->data['result'];
    }

    /** Store a result value. Steps use this to pass information to later steps. */
    public function setResult(string $key, $value): void
    {
        $this->data['result'][$key] = $value;
        $this->write();
    }

    /**
     * Append a human-readable progress line.
     *
     * This is what makes a long step legible: "Creating index loghound_9a411396_hits…"
     * appears while the request that creates it is still in flight, because the note is
     * flushed to the state file immediately and the poller reads that file.
     *
     * Redacted on the way in, not at the call sites. Some notes carry text the platform
     * returned, and the platform echoes request parameters back in some error paths — and
     * the API key travels as one. The state file is 0600, but the job endpoint serves its
     * contents to a browser that is not yet authenticated, because the installer runs
     * before an account exists. A boundary that is only sometimes applied is not one.
     */
    public function note(string $text): void
    {
        $this->data['notes'][] = ['t' => time(), 'text' => self::redactPatterns($text)];
        if (count($this->data['notes']) > self::MAX_NOTES) {
            $this->data['notes'] = array_slice($this->data['notes'], -self::MAX_NOTES);
        }
        $this->write();
    }

    /** Bump and read the retry counter used by the index-name collision loop. */
    public function nextAttempt(): int
    {
        $this->data['attempt'] = (int) $this->data['attempt'] + 1;
        $this->write();
        return (int) $this->data['attempt'];
    }

    /**
     * Run steps until the budget is spent, the job finishes, or a step fails.
     *
     * @param Config      $cfg  Live configuration; steps read credentials from it and
     *                          write their results back into it.
     * @param string      $root Application root, for configset paths.
     * @param int|null    $budget Wall-clock seconds; null uses the browser default.
     * @param callable|null $onStep fn(string $key, string $label, string $state, string $detail)
     *                          Called after each step. The CLI prints from it.
     * @return bool True when the job has finished (successfully or not).
     */
    public function run(Config $cfg, string $root, ?int $budget = null, ?callable $onStep = null): bool
    {
        $budget = $budget ?? self::BUDGET_SECONDS;

        $lock = @fopen($this->lockPath(), 'c');
        if ($lock === false) {
            return $this->state() !== 'running';
        }
        if (!flock($lock, LOCK_EX | LOCK_NB)) {
            fclose($lock);
            return false;
        }
        @chmod($this->lockPath(), 0600);

        $started = microtime(true);

        try {
            while (true) {
                $this->reload();

                if ($this->state() !== 'running') {
                    return true;
                }

                $steps = $this->steps($cfg, $root);
                $next = null;
                foreach ($steps as $step) {
                    $stored = $this->data['steps'][$step['key']] ?? null;
                    if (($stored['state'] ?? 'pending') !== 'done') {
                        $next = $step;
                        break;
                    }
                }

                if ($next === null) {
                    $this->data['state'] = 'done';
                    $this->data['updated_at'] = time();
                    $this->write();
                    return true;
                }

                $this->markStep($next['key'], 'running', '');
                $t0 = microtime(true);

                try {
                    /** @var callable(Job,Config,string):(string|array) $run */
                    $run = $next['run'];
                    $outcome = $run($this, $cfg, $root);
                } catch (\Throwable $e) {
                    $message = self::redact($e->getMessage(), $cfg);
                    $this->markStep($next['key'], 'error', $message, microtime(true) - $t0);
                    $this->data['state'] = 'error';
                    $this->data['error'] = $next['label'] . ': ' . $message;
                    $this->data['updated_at'] = time();
                    $this->write();
                    if ($onStep !== null) {
                        $onStep($next['key'], $next['label'], 'error', $message);
                    }
                    return true;
                }

                if (is_array($outcome) && isset($outcome['goto'])) {
                    $this->markStep($next['key'], 'pending', (string) ($outcome['detail'] ?? ''), microtime(true) - $t0);
                    $this->rewindTo((string) $outcome['goto']);
                    if ($onStep !== null) {
                        $onStep($next['key'], $next['label'], 'retry', (string) ($outcome['detail'] ?? ''));
                    }
                    continue;
                }

                $detail = is_string($outcome) ? $outcome : '';
                $this->markStep($next['key'], 'done', $detail, microtime(true) - $t0);
                if ($onStep !== null) {
                    $onStep($next['key'], $next['label'], 'done', $detail);
                }

                if ($budget > 0 && (microtime(true) - $started) >= $budget) {
                    return false;
                }
            }
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /**
     * Run the whole job to completion. Used by the CLI wizard, which has no gateway
     * timeout to respect and prints each step as it lands.
     */
    public function runAll(Config $cfg, string $root, ?callable $onStep = null): bool
    {
        $this->run($cfg, $root, 0, $onStep);
        return $this->state() === 'done';
    }

    /**
     * Mark every step from $key onwards as pending, so the runner does them again.
     *
     * Only used by the collision retry, and only after the previous attempt's indexes have
     * been rolled back.
     */
    private function rewindTo(string $key): void
    {
        $seen = false;
        foreach (array_keys($this->data['steps']) as $k) {
            if ($k === $key) {
                $seen = true;
            }
            if ($seen) {
                $this->data['steps'][$k]['state'] = 'pending';
            }
        }
        $this->data['steps'][$key]['state'] = 'pending';
        $this->write();
    }

    /**
     * A JSON-serialisable snapshot for the browser.
     *
     * Contains only what the progress UI needs. No credentials, no file paths outside the
     * application, no exception traces.
     *
     * @return array<string,mixed>
     */
    public function status(Config $cfg, string $root): array
    {
        $this->reload();

        $steps = [];
        $done  = 0;
        foreach ($this->steps($cfg, $root) as $step) {
            $stored = $this->data['steps'][$step['key']] ?? [];
            $state = (string) ($stored['state'] ?? 'pending');
            if ($state === 'done') {
                $done++;
            }
            $steps[] = [
                'key'    => $step['key'],
                'label'  => $step['label'],
                'state'  => $state,
                'detail' => (string) ($stored['detail'] ?? ''),
                'ms'     => (int) round((float) ($stored['ms'] ?? 0) * 1000),
            ];
        }

        $notes = [];
        foreach (array_slice((array) $this->data['notes'], -12) as $n) {
            $notes[] = (string) $n['text'];
        }

        return [
            'id'       => $this->id,
            'kind'     => $this->kind(),
            'state'    => $this->state(),
            'error'    => $this->error(),
            'elapsed'  => $this->age(),
            'total'    => count($steps),
            'complete' => $done,
            'percent'  => $steps === [] ? 0 : (int) round($done / count($steps) * 100),
            'steps'    => $steps,
            'notes'    => $notes,
            'result'   => $this->publicResult(),
        ];
    }

    /**
     * The parts of the result the browser is allowed to see.
     *
     * An allowlist rather than a filter: a result key added later must be opted in
     * deliberately, so nothing leaks by accident. The detection job's `sources` key is
     * deliberately NOT here — it holds raw log lines, and there is no reason to ship them
     * to the browser once a second when the page renders them server-side anyway.
     *
     * @return array<string,mixed>
     */
    private function publicResult(): array
    {
        $r = $this->result();
        $out = [];
        foreach (['install_id', 'hits', 'sessions', 'regions'] as $k) {
            if (array_key_exists($k, $r)) {
                $out[$k] = $r[$k];
            }
        }
        return $out;
    }

    /**
     * Build this job's step list.
     *
     * Rebuilt on every request rather than persisted, because a step is a closure and a
     * closure cannot be stored in JSON. Only the step STATES are persisted, keyed by name,
     * which is also what lets a job grow steps as it goes: the detection job does not know
     * how many log files it will examine until its first step has run.
     *
     * @return array<int,array{key:string,label:string,run:callable}>
     */
    private function steps(Config $cfg, string $root): array
    {
        switch ($this->kind()) {
            case self::KIND_DETECT:
                return Detector::steps($this, $cfg);
            case self::KIND_OPENSOLR:
                return Storage::opensolrSteps($this, $cfg, $root);
            case self::KIND_SOLRTEST:
                return Storage::solrTestSteps($this, $cfg);
            case self::KIND_REUSE:
                return Storage::reuseSteps($this, $cfg, $root);
        }
        return [];
    }

    /** Record a step's outcome and flush it, so the poller sees it immediately. */
    private function markStep(string $key, string $state, string $detail, ?float $seconds = null): void
    {
        $this->data['steps'][$key] = [
            'state'  => $state,
            'detail' => $detail,
            'ms'     => $seconds ?? (float) ($this->data['steps'][$key]['ms'] ?? 0),
        ];
        $this->data['updated_at'] = time();
        $this->write();
    }

    private function path(): string
    {
        return $this->dir . '/' . $this->id . '.json';
    }

    private function lockPath(): string
    {
        return $this->dir . '/' . $this->id . '.lock';
    }

    /** Re-read the state file, so a runner sees notes written by an earlier pass. */
    private function reload(): void
    {
        $raw = @file_get_contents($this->path());
        $data = is_string($raw) ? json_decode($raw, true) : null;
        if (is_array($data)) {
            $this->data = $data;
        }
    }

    /**
     * Write the state file atomically.
     *
     * tmp + rename, because the status poller reads this file without a lock: a partial
     * write would hand it half a JSON document and the progress UI would flicker into an
     * error state for no reason.
     */
    private function write(): void
    {
        $tmp = $this->dir . '/.' . $this->id . '.' . bin2hex(random_bytes(4)) . '.tmp';
        $json = json_encode($this->data, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($json === false) {
            return;
        }
        if (@file_put_contents($tmp, $json) === false) {
            return;
        }
        @chmod($tmp, 0600);
        if (!@rename($tmp, $this->path())) {
            @unlink($tmp);
        }
    }

    /**
     * Strip anything credential-shaped out of a message before it is stored or returned.
     *
     * A setup job's state file is written to var/setup/ and served back by the job endpoint,
     * which answers BEFORE authentication exists — the installer runs precisely when there is
     * no account yet. An exception thrown while provisioning can carry the whole request URL,
     * and the Opensolr API takes its key as a query parameter, so an unredacted message is a
     * credential handed to whoever is polling.
     *
     * Opensolr::redact() already covers its own errors, which is why this has not leaked in
     * practice. Relying on that is relying on one class never throwing a message it did not
     * build; this is the boundary, so the boundary redacts.
     */
    private static function redact(string $text, Config $cfg): string
    {
        $text = self::redactPatterns($text);

        $secrets = [
            (string) $cfg->get('opensolr.api_key', ''),
            (string) $cfg->get('solr.http_pass', ''),
            (string) $cfg->get('beacon.secret', ''),
            (string) $cfg->get('privacy.ip_salt', ''),
        ];
        foreach ($secrets as $secret) {
            if ($secret !== '' && strlen($secret) >= 8) {
                $text = str_replace($secret, '[redacted]', $text);
            }
        }

        return $text;
    }

    /**
     * The half of the redaction that needs no configuration.
     *
     * Split out so note() can use it. A note is written from inside an instance, which holds
     * no Config, and "there is no Config here" is not a reason to write a credential into a
     * file the job endpoint serves unauthenticated. This catches the shape a leaked key
     * actually takes — an echoed query string — without needing to know the value.
     */
    private static function redactPatterns(string $text): string
    {
        $text = preg_replace('/\b(api_key|apikey|password|passwd|token|secret)=[^&\s"\']+/i', '$1=[redacted]', $text) ?? $text;
        return preg_replace('#(://[^/\s:@]+):[^/\s:@]+@#', '$1:[redacted]@', $text) ?? $text;
    }

}
