<?php
/**
 * Loghound — long-running panel operations, as stepped jobs.
 *
 * WHY THIS EXISTS. The reference install runs PHP-FPM with `max_execution_time = 60`.
 * Real operations exceed that: provisioning two Opensolr indexes measured about forty
 * seconds, and a facet across ninety days of a busy site is not instant either. An action
 * that does its work inside one request is a gateway timeout waiting to happen, and the
 * operator is left with a dead tab and no idea whether it ran.
 *
 * HOW IT WORKS. A job is a list of named steps. Each poll from the browser executes
 * exactly one step and returns. There is no background process, no `exec()` and no worker
 * daemon, because the product has to install on a bare box with no toolchain. Every
 * individual step is bounded far below the execution limit, so no single request can time
 * out however long the whole job takes. That design also makes jobs resumable (state is
 * in SQLite, not in a process), idempotent (`start()` returns the running job for a kind
 * rather than launching a second), cancellable at step boundaries, and honest about
 * progress (the steps are known in advance, so the bar reports a real fraction).
 *
 * SECURITY.
 *  - Job ids are 96 bits of `random_bytes`, and every lookup is additionally scoped to
 *    the owner derived from the authenticated session. One operator cannot read, advance
 *    or cancel another's job by guessing an id; a job that is not yours is reported
 *    exactly as one that does not exist, so ids cannot be probed for existence.
 *  - Every statement is prepared with bound values. No SQL is built by concatenation.
 *  - Secrets never enter a job payload. Step details, persisted errors and anything sent
 *    to the error log pass through `redact()` first, because the Opensolr API key travels
 *    in a query string and a transport error can quote the URL it failed on.
 *  - Nothing here deletes. `Solr::deleteByQuery()` is documented internal-only with no
 *    HTTP path reaching it; the retention job counts and `bin/loghound-retention` acts.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Config;

final class Jobs
{
    /** Seconds a step may hold the lease before another request may take it over. */
    private const LEASE_SECONDS = 45;

    /** Finished jobs older than this are swept. */
    private const KEEP_SECONDS = 3600;

    /**
     * The job kinds this class plans itself. Anything else must be supplied by the view
     * hosting the job, through the constructor's plan registry.
     */
    public const KINDS = ['solr_connection', 'opensolr_check', 'retention_preview'];

    /**
     * The message returned for a job that does not exist AND for one owned by somebody
     * else. Identical on purpose: a distinguishable "forbidden" turns an id space into an
     * oracle.
     */
    private const NOT_AVAILABLE = 'That operation is no longer available. Start it again.';

    private \SQLite3 $db;
    private Config $cfg;
    private Gateway $gw;
    private string $owner;

    /** @var array<string,callable(array<string,mixed>):array<int,array{label:string,run:callable}>> */
    private array $extraPlans;

    /**
     * Open (and if necessary create) the job store.
     *
     * The store is its own SQLite file rather than a table inside `var/state.db`, because
     * the ingest daemons own that schema and a panel table living in it would be a
     * migration collision waiting to happen.
     *
     * A view that hosts jobs of its own passes them in as `$extraPlans`, keyed by kind.
     * The alternative — a closed const listing every kind in the application — meant a new
     * view could not offer a stepped operation at all without editing this class, which is
     * exactly the coupling the job store exists to avoid. A planner is handed the job's
     * stored context so a kind can be parameterised; the view validates those parameters
     * before `start()` ever sees them, because only the view knows what a valid target is.
     *
     * @param array<string,callable(array<string,mixed>):array<int,array{label:string,run:callable}>> $extraPlans
     * @throws \RuntimeException when `var/` cannot be created, or a supplied kind collides
     *                           with a built-in one.
     */
    public function __construct(Config $cfg, Gateway $gw, array $extraPlans = [])
    {
        foreach (array_keys($extraPlans) as $kind) {
            if (!is_string($kind) || !preg_match('/^[a-z][a-z0-9_]{2,31}$/', $kind)) {
                throw new \RuntimeException('Job kind is not a valid identifier.');
            }
            if (in_array($kind, self::KINDS, true)) {
                throw new \RuntimeException('Job kind "' . $kind . '" is already built in.');
            }
        }

        $this->cfg        = $cfg;
        $this->gw         = $gw;
        $this->extraPlans = $extraPlans;
        $this->owner      = self::owner();

        $dir = dirname(__DIR__, 2) . '/var';
        if (!is_dir($dir) && !@mkdir($dir, 0750, true) && !is_dir($dir)) {
            throw new \RuntimeException('Cannot create var/ for the job store.');
        }

        $path = $dir . '/panel-jobs.db';
        $this->db = new \SQLite3($path);
        @chmod($path, 0640);
        $this->db->busyTimeout(4000);
        $this->db->exec('PRAGMA journal_mode = WAL');
        $this->db->exec('PRAGMA synchronous = NORMAL');
        $this->db->exec(
            'CREATE TABLE IF NOT EXISTS jobs (
                id        TEXT PRIMARY KEY,
                owner     TEXT NOT NULL,
                kind      TEXT NOT NULL,
                state     TEXT NOT NULL,
                step      INTEGER NOT NULL DEFAULT 0,
                total     INTEGER NOT NULL DEFAULT 0,
                label     TEXT NOT NULL DEFAULT \'\',
                steps     TEXT NOT NULL DEFAULT \'[]\',
                context   TEXT NOT NULL DEFAULT \'{}\',
                error     TEXT,
                created   INTEGER NOT NULL,
                updated   INTEGER NOT NULL,
                lease     INTEGER NOT NULL DEFAULT 0,
                cancelled INTEGER NOT NULL DEFAULT 0
            )'
        );
        $columns = [];
        $info = $this->db->query('PRAGMA table_info(jobs)');
        while ($info !== false && ($column = $info->fetchArray(SQLITE3_ASSOC)) !== false) {
            $columns[] = (string) $column['name'];
        }
        if (!in_array('target', $columns, true)) {
            $this->db->exec('ALTER TABLE jobs ADD COLUMN target TEXT NOT NULL DEFAULT \'\'');
        }

        $this->db->exec('CREATE INDEX IF NOT EXISTS jobs_owner_kind ON jobs (owner, kind, target, state)');
        $this->sweep();
    }

    /**
     * Every kind this instance will start: the built-ins plus whatever the hosting view
     * registered. A kind absent from this list is refused before the store is touched.
     *
     * @return array<int,string>
     */
    public function kinds(): array
    {
        return array_merge(self::KINDS, array_keys($this->extraPlans));
    }

    /**
     * The opaque identity a job belongs to.
     *
     * Derived from a per-session random secret combined with the authenticated username,
     * so a job is scoped to one signed-in operator in one session. Changing user inside
     * the same session changes the owner, which makes previously started jobs invisible
     * rather than inherited — the fail-closed choice.
     *
     * A session is only started when one can be: never under CLI, and never once headers
     * have gone out. Where no session can be established the secret is minted per process
     * instead, so jobs become unreachable across requests rather than collapsing into one
     * shared identity every caller would inherit. Denying is the safe direction.
     */
    private static function owner(): string
    {
        if (session_status() !== PHP_SESSION_ACTIVE && PHP_SAPI !== 'cli' && !headers_sent()) {
            session_start();
        }
        if (empty($_SESSION['lh_job_owner']) || !is_string($_SESSION['lh_job_owner'])) {
            $_SESSION['lh_job_owner'] = bin2hex(random_bytes(16));
        }
        $user = $_SERVER['PHP_AUTH_USER'] ?? ($_SESSION['lh_user'] ?? '');
        return hash('sha256', $_SESSION['lh_job_owner'] . '|' . (is_string($user) ? $user : ''));
    }

    /**
     * Remove anything secret-shaped from a string before it is stored, returned or logged.
     *
     * The Opensolr API key travels as a query parameter, so a curl error, an exception
     * message or a quoted URL can carry it. HTTP basic credentials can appear the same
     * way inside a Solr base URL. Redaction happens at every boundary rather than at the
     * one place a leak was noticed.
     */
    public static function redact(string $text): string
    {
        $patterns = [
            '/(api_key|apikey|key|token|secret|password|passwd|pwd|salt)=([^&\s"\']*)/i' => '$1=[redacted]',
            '#(https?://)[^/@\s:]+:[^/@\s]+@#i' => '$1[redacted]@',
        ];
        foreach ($patterns as $pattern => $replacement) {
            $text = (string) preg_replace($pattern, $replacement, $text);
        }
        return $text;
    }

    /**
     * Start a job, or return the one already running for this kind, owner and target.
     *
     * Returning the existing job is the entire idempotency story: a double-clicked button,
     * a refreshed tab and a second window all converge on one job id instead of starting
     * three copies of the work. A parameterised kind narrows that further by target, so
     * scanning one index does not hand back the job that is still scanning a different
     * one — which would report the wrong index's progress under the right index's heading.
     *
     * Parameters are the caller's already-validated values; they are re-checked here as
     * scalars under a size cap, because the store must not become a place to park
     * arbitrary structures and because a planner reads them back on every poll.
     *
     * @param array<string,scalar|null> $params
     * @return array<string,mixed> The job shaped for the browser, or an `error` key.
     */
    public function start(string $kind, array $params = []): array
    {
        if (!in_array($kind, $this->kinds(), true)) {
            return ['error' => 'Unknown operation.'];
        }

        $clean = self::normaliseParams($params);
        if ($clean === null) {
            return ['error' => 'Those operation parameters are not acceptable.'];
        }

        $target = $clean === [] ? '' : hash('sha256', (string) json_encode($clean));

        $stmt = $this->db->prepare(
            'SELECT id FROM jobs
              WHERE kind = :kind AND owner = :owner AND target = :target
                AND state IN (\'pending\', \'running\')
              ORDER BY created DESC LIMIT 1'
        );
        $stmt->bindValue(':kind', $kind, SQLITE3_TEXT);
        $stmt->bindValue(':owner', $this->owner, SQLITE3_TEXT);
        $stmt->bindValue(':target', $target, SQLITE3_TEXT);
        $res = $stmt->execute();
        $row = $res ? $res->fetchArray(SQLITE3_ASSOC) : false;
        if (is_array($row)) {
            return $this->get((string) $row['id']);
        }

        $plan = $this->plan($kind, $clean);
        if ($plan === []) {
            return ['error' => 'Unknown operation.'];
        }

        $steps = array_map(
            static fn (array $s): array => [
                'label'  => $s['label'],
                'state'  => 'pending',
                'note'   => null,
                'detail' => null,
            ],
            $plan
        );

        $id  = bin2hex(random_bytes(12));
        $now = time();

        $insert = $this->db->prepare(
            'INSERT INTO jobs (id, owner, kind, target, state, step, total, label, steps, context, created, updated)
             VALUES (:id, :owner, :kind, :target, \'pending\', 0, :total, :label, :steps, :context, :now, :now)'
        );
        $insert->bindValue(':id', $id, SQLITE3_TEXT);
        $insert->bindValue(':owner', $this->owner, SQLITE3_TEXT);
        $insert->bindValue(':kind', $kind, SQLITE3_TEXT);
        $insert->bindValue(':target', $target, SQLITE3_TEXT);
        $insert->bindValue(':total', count($steps), SQLITE3_INTEGER);
        $insert->bindValue(':label', $steps[0]['label'] ?? 'Starting', SQLITE3_TEXT);
        $insert->bindValue(':steps', (string) json_encode($steps), SQLITE3_TEXT);
        $insert->bindValue(':context', (string) json_encode($clean), SQLITE3_TEXT);
        $insert->bindValue(':now', $now, SQLITE3_INTEGER);
        $insert->execute();

        return $this->get($id);
    }

    /**
     * Reduce job parameters to a flat, bounded, deterministically ordered scalar map.
     *
     * Returns null rather than a partial result when anything is out of shape, so a
     * malformed parameter refuses the job instead of starting one that silently dropped
     * the field naming its target. Sorting by key makes the target hash stable regardless
     * of the order the browser sent the fields in.
     *
     * @param array<mixed> $params
     * @return array<string,scalar|null>|null
     */
    private static function normaliseParams(array $params): ?array
    {
        if (count($params) > 12) {
            return null;
        }
        $clean = [];
        foreach ($params as $key => $value) {
            if (!is_string($key) || !preg_match('/^[a-z][a-z0-9_]{0,31}$/', $key)) {
                return null;
            }
            if ($value !== null && !is_scalar($value)) {
                return null;
            }
            if (is_string($value) && strlen($value) > 256) {
                return null;
            }
            $clean[$key] = $value;
        }
        ksort($clean);
        return $clean;
    }

    /**
     * Execute the next step of a job and return its new state.
     *
     * One step per call, always: each poll is a short request that cannot time out, and
     * the job advances one bounded unit of work. Cancellation is honoured before a step
     * starts and never during one, because a half-executed step is the one state nobody
     * can reason about. A lease stops two tabs polling the same job from running the same
     * step twice.
     *
     * @return array<string,mixed>
     */
    public function advance(string $id): array
    {
        $row = $this->row($id);
        if ($row === null) {
            return ['error' => self::NOT_AVAILABLE];
        }
        if (in_array($row['state'], ['done', 'failed', 'cancelled'], true)) {
            return $this->shape($row);
        }
        if ((int) $row['cancelled'] === 1) {
            $this->finish($id, 'cancelled', 'Cancelled.');
            return $this->get($id);
        }

        $now = time();
        if ((int) $row['lease'] > $now - self::LEASE_SECONDS && $row['state'] === 'running') {
            return $this->shape($row);
        }
        if (!$this->takeLease($id, (int) $row['lease'], $now)) {
            return $this->get($id);
        }

        $steps = self::decodeArray((string) $row['steps']);
        $ctx   = self::decodeArray((string) $row['context']);
        $plan  = $this->plan((string) $row['kind'], $ctx);
        $index = (int) $row['step'];

        if (!isset($plan[$index])) {
            $this->finish($id, 'done', 'Finished.');
            return $this->get($id);
        }

        $outcome = $this->runStep($plan[$index], $ctx, (string) $row['kind'], $index);
        $steps[$index] = array_merge($steps[$index] ?? [], $outcome['step']);
        $ctx = array_merge($ctx, $outcome['context']);

        $index++;
        $done = $outcome['stop'] || $index >= count($plan);

        $this->persistStep(
            $id,
            $index,
            $steps,
            $ctx,
            $done ? 'Finished.' : (string) ($plan[$index]['label'] ?? 'Working'),
            $done ? ($outcome['failed'] ? 'failed' : 'done') : 'running',
            $outcome['failed'] ? (string) ($outcome['step']['detail'] ?? 'The operation failed.') : null
        );

        return $this->get($id);
    }

    /**
     * Run one planned step, converting any throw into a recorded failure.
     *
     * A step that throws must not take the poll loop with it: the browser has to be told
     * which step failed and why, and the job has to reach a terminal state so it stops
     * being polled.
     *
     * @param array{label:string,run:callable} $step
     * @param array<string,mixed>              $ctx
     * @return array{step:array<string,mixed>,context:array<string,mixed>,failed:bool,stop:bool}
     */
    private function runStep(array $step, array $ctx, string $kind, int $index): array
    {
        $started = microtime(true);
        try {
            $result = ($step['run'])($ctx, $this->cfg, $this->gw);
            $ok = ($result['ok'] ?? true) !== false;
            return [
                'step' => [
                    'state'  => $ok ? 'done' : 'failed',
                    'note'   => isset($result['note']) ? self::redact((string) $result['note']) : null,
                    'detail' => isset($result['detail']) ? self::redact((string) $result['detail']) : null,
                    'ms'     => (int) round((microtime(true) - $started) * 1000),
                ],
                'context' => isset($result['context']) && is_array($result['context']) ? $result['context'] : [],
                'failed'  => !$ok,
                'stop'    => !$ok || ($result['stop'] ?? false) === true,
            ];
        } catch (\Throwable $e) {
            error_log('[loghound-panel job] ' . $kind . ' step ' . $index . ': ' . self::redact($e->getMessage()));
            return [
                'step' => [
                    'state'  => 'failed',
                    'note'   => 'failed',
                    'detail' => self::redact($e->getMessage()),
                    'ms'     => (int) round((microtime(true) - $started) * 1000),
                ],
                'context' => [],
                'failed'  => true,
                'stop'    => true,
            ];
        }
    }

    /**
     * Claim the right to execute the next step.
     *
     * A compare-and-set on the previous lease value, so two concurrent polls cannot both
     * believe they took it.
     */
    private function takeLease(string $id, int $previousLease, int $now): bool
    {
        $stmt = $this->db->prepare(
            'UPDATE jobs SET state = \'running\', lease = :now
              WHERE id = :id AND owner = :owner AND lease = :was'
        );
        $stmt->bindValue(':now', $now, SQLITE3_INTEGER);
        $stmt->bindValue(':id', $id, SQLITE3_TEXT);
        $stmt->bindValue(':owner', $this->owner, SQLITE3_TEXT);
        $stmt->bindValue(':was', $previousLease, SQLITE3_INTEGER);
        $stmt->execute();
        return $this->db->changes() > 0;
    }

    /**
     * Write the outcome of a step and release the lease.
     *
     * @param array<int,array<string,mixed>> $steps
     * @param array<string,mixed>            $ctx
     */
    private function persistStep(
        string $id,
        int $index,
        array $steps,
        array $ctx,
        string $label,
        string $state,
        ?string $error
    ): void {
        $stmt = $this->db->prepare(
            'UPDATE jobs SET step = :step, steps = :steps, context = :ctx, label = :label,
                    state = :state, error = :error, updated = :now, lease = 0
              WHERE id = :id AND owner = :owner'
        );
        $stmt->bindValue(':step', $index, SQLITE3_INTEGER);
        $stmt->bindValue(':steps', (string) json_encode($steps), SQLITE3_TEXT);
        $stmt->bindValue(':ctx', (string) json_encode($ctx), SQLITE3_TEXT);
        $stmt->bindValue(':label', $label, SQLITE3_TEXT);
        $stmt->bindValue(':state', $state, SQLITE3_TEXT);
        $stmt->bindValue(':error', $error === null ? null : self::redact($error), $error === null ? SQLITE3_NULL : SQLITE3_TEXT);
        $stmt->bindValue(':now', time(), SQLITE3_INTEGER);
        $stmt->bindValue(':id', $id, SQLITE3_TEXT);
        $stmt->bindValue(':owner', $this->owner, SQLITE3_TEXT);
        $stmt->execute();
    }

    /**
     * Ask a job to stop.
     *
     * Sets a flag rather than killing anything, so the job always stops at a boundary it
     * can describe.
     *
     * @return array<string,mixed>
     */
    public function cancel(string $id): array
    {
        if (!self::isJobId($id)) {
            return ['error' => self::NOT_AVAILABLE];
        }
        $stmt = $this->db->prepare(
            'UPDATE jobs SET cancelled = 1, updated = :now
              WHERE id = :id AND owner = :owner AND state IN (\'pending\', \'running\')'
        );
        $stmt->bindValue(':now', time(), SQLITE3_INTEGER);
        $stmt->bindValue(':id', $id, SQLITE3_TEXT);
        $stmt->bindValue(':owner', $this->owner, SQLITE3_TEXT);
        $stmt->execute();
        return $this->get($id);
    }

    /**
     * Read a job without advancing it, used to reattach after a refresh.
     *
     * @return array<string,mixed>
     */
    public function get(string $id): array
    {
        $row = $this->row($id);
        return $row === null ? ['error' => self::NOT_AVAILABLE] : $this->shape($row);
    }

    /**
     * The newest job of a kind belonging to this owner, whatever its state.
     *
     * How a reloaded page finds the operation it was watching without the browser having
     * had to remember an id.
     *
     * @return array<string,mixed>|null
     */
    public function latest(string $kind): ?array
    {
        if (!in_array($kind, $this->kinds(), true)) {
            return null;
        }
        $stmt = $this->db->prepare(
            'SELECT * FROM jobs WHERE kind = :kind AND owner = :owner ORDER BY created DESC LIMIT 1'
        );
        $stmt->bindValue(':kind', $kind, SQLITE3_TEXT);
        $stmt->bindValue(':owner', $this->owner, SQLITE3_TEXT);
        $res = $stmt->execute();
        $row = $res ? $res->fetchArray(SQLITE3_ASSOC) : false;
        return is_array($row) ? $this->shape($row) : null;
    }

    /**
     * Fetch a job row, scoped to the current owner.
     *
     * Returns null both for an unknown id and for one belonging to somebody else, so the
     * caller cannot tell the two apart.
     *
     * @return array<string,mixed>|null
     */
    private function row(string $id): ?array
    {
        if (!self::isJobId($id)) {
            return null;
        }
        $stmt = $this->db->prepare('SELECT * FROM jobs WHERE id = :id AND owner = :owner');
        $stmt->bindValue(':id', $id, SQLITE3_TEXT);
        $stmt->bindValue(':owner', $this->owner, SQLITE3_TEXT);
        $res = $stmt->execute();
        $row = $res ? $res->fetchArray(SQLITE3_ASSOC) : false;
        return is_array($row) ? $row : null;
    }

    /** Mark a job finished with a closing label. */
    private function finish(string $id, string $state, string $label): void
    {
        $stmt = $this->db->prepare(
            'UPDATE jobs SET state = :state, label = :label, updated = :now, lease = 0
              WHERE id = :id AND owner = :owner'
        );
        $stmt->bindValue(':state', $state, SQLITE3_TEXT);
        $stmt->bindValue(':label', $label, SQLITE3_TEXT);
        $stmt->bindValue(':now', time(), SQLITE3_INTEGER);
        $stmt->bindValue(':id', $id, SQLITE3_TEXT);
        $stmt->bindValue(':owner', $this->owner, SQLITE3_TEXT);
        $stmt->execute();
    }

    /** Drop finished jobs nobody is watching any more, for every owner. */
    private function sweep(): void
    {
        $stmt = $this->db->prepare('DELETE FROM jobs WHERE updated < :cut');
        $stmt->bindValue(':cut', time() - self::KEEP_SECONDS, SQLITE3_INTEGER);
        $stmt->execute();
    }

    /**
     * Decode a persisted JSON column, tolerating corruption.
     *
     * @return array<mixed>
     */
    private static function decodeArray(string $json): array
    {
        $value = json_decode($json, true);
        return is_array($value) ? $value : [];
    }

    /**
     * Shape a row for the browser.
     *
     * `percent` is a real fraction of known steps, never a guess, and `elapsed` lets the
     * UI show seconds so the operator can tell working from hung. The owner column is
     * never included.
     *
     * @param array<string,mixed> $row
     * @return array<string,mixed>
     */
    private function shape(array $row): array
    {
        $total = max(1, (int) $row['total']);
        return [
            'id'      => (string) $row['id'],
            'kind'    => (string) $row['kind'],
            'state'   => (string) $row['state'],
            'label'   => (string) $row['label'],
            'step'    => (int) $row['step'],
            'total'   => (int) $row['total'],
            'percent' => (int) round((min((int) $row['step'], $total) / $total) * 100),
            'steps'   => self::decodeArray((string) $row['steps']),
            'error'   => $row['error'] !== null ? self::redact((string) $row['error']) : null,
            'elapsed' => max(0, time() - (int) $row['created']),
            'done'    => in_array($row['state'], ['done', 'failed', 'cancelled'], true),
            'result'  => self::redactDeep(self::decodeArray((string) $row['context'])),
        ];
    }

    /**
     * Redact every string inside a structure on its way to the browser.
     *
     * `note`, `detail` and `error` were redacted and the job context was not, even though it
     * is returned to the browser as `result` on every poll and is the one part of a job that
     * holds whatever a step chose to keep — including, on the Opensolr views, text taken from
     * the platform's own responses. A redactor applied to three fields out of four is a
     * redactor somebody will assume covers the fourth.
     *
     * @param mixed $value
     * @return mixed
     */
    private static function redactDeep($value)
    {
        if (is_string($value)) {
            return self::redact($value);
        }
        if (is_array($value)) {
            $out = [];
            foreach ($value as $k => $v) {
                $out[$k] = self::redactDeep($v);
            }
            return $out;
        }
        return $value;
    }

    /**
     * The step plan for a kind.
     *
     * Rebuilt on every request rather than stored, because a step is a closure and a
     * closure cannot be serialised. Only a step's outcome is persisted. A registered
     * planner is consulted before the built-ins and is handed the job's context, which on
     * the first call is exactly the parameters `start()` was given.
     *
     * @param array<string,mixed> $ctx
     * @return array<int,array{label:string,run:callable}>
     */
    private function plan(string $kind, array $ctx = []): array
    {
        if (isset($this->extraPlans[$kind])) {
            return ($this->extraPlans[$kind])($ctx);
        }

        switch ($kind) {
            case 'solr_connection':
                return self::planSolrConnection();
            case 'opensolr_check':
                return self::planOpensolrCheck();
            case 'retention_preview':
                return self::planRetentionPreview();
            default:
                return [];
        }
    }

    /**
     * Verify the Solr backend end to end, one core at a time.
     *
     * Split fine-grained on purpose: "Solr is broken" helps nobody, "the sessions core
     * answers and the hits core does not" is a diagnosis.
     *
     * @return array<int,array{label:string,run:callable}>
     */
    private static function planSolrConnection(): array
    {
        return [
            [
                'label' => 'Checking the configuration',
                'run' => static function (array $ctx, Config $cfg, Gateway $gw): array {
                    $problems = array_values(array_filter(
                        $cfg->validate(),
                        static fn (string $e): bool => str_starts_with($e, 'solr') || str_starts_with($e, 'opensolr')
                    ));
                    if ($problems !== []) {
                        return ['ok' => false, 'note' => 'invalid', 'detail' => implode(' ', $problems)];
                    }
                    $mode = (string) $cfg->get('solr.mode');
                    return [
                        'ok'     => true,
                        'note'   => $mode,
                        'detail' => $mode === 'opensolr'
                            ? 'Managed by Opensolr.'
                            : 'Custom Solr at ' . (string) $cfg->get('solr.base_url'),
                    ];
                },
            ],
            [
                'label' => 'Pinging the sessions core',
                'run' => static function (array $ctx, Config $cfg, Gateway $gw): array {
                    $gw->resetError();
                    $ok = $gw->ping();
                    return [
                        'ok'      => $ok,
                        'note'    => $ok ? 'up' : 'down',
                        'detail'  => $ok
                            ? 'Core "' . $gw->sessionsCore() . '" answered its ping handler.'
                            : (string) ($gw->error() ?? 'No response.'),
                        'context' => ['sessions_up' => $ok],
                    ];
                },
            ],
            [
                'label' => 'Counting session documents',
                'run' => static function (array $ctx, Config $cfg, Gateway $gw): array {
                    return self::countStep($gw, $gw->sessionsCore(), 'job.count.sessions', 'sessions', 'Sessions core');
                },
            ],
            [
                'label' => 'Counting hit documents',
                'run' => static function (array $ctx, Config $cfg, Gateway $gw): array {
                    return self::countStep($gw, $gw->hitsCore(), 'job.count.hits', 'hits', 'Hits core');
                },
            ],
            [
                'label' => 'Checking how fresh the data is',
                'run' => static function (array $ctx, Config $cfg, Gateway $gw): array {
                    $gw->resetError();
                    $f = $gw->facet('job.freshness', $gw->sessionsCore(), ['q' => '*:*'], [
                        'newest' => 'max(ts_start)',
                        'oldest' => 'min(ts_start)',
                    ]);
                    $err = $gw->error();
                    if ($err !== null) {
                        return ['ok' => false, 'note' => 'failed', 'detail' => $err];
                    }
                    $newest = is_string($f['newest'] ?? null) ? $f['newest'] : null;
                    if ($newest === null) {
                        return [
                            'ok'     => true,
                            'note'   => 'empty',
                            'detail' => 'No sessions indexed yet. Confirm a log source and check that loghound-tail is running.',
                        ];
                    }
                    $age = time() - (int) strtotime($newest);
                    return [
                        'ok'      => true,
                        'note'    => $age < 300 ? 'live' : 'stale',
                        'detail'  => 'Newest session ' . gmdate('m/d/Y H:i:s', (int) strtotime($newest)) . ' UTC'
                            . ($age >= 300
                                ? ' — that is ' . (int) round($age / 60) . ' minutes ago, so ingestion may have stopped.'
                                : ' — ingestion is live.'),
                        'context' => ['newest' => $newest],
                    ];
                },
            ],
        ];
    }

    /**
     * Count the documents in a core with `rows=0`, reporting a transport failure honestly.
     *
     * Shared by the two counting steps so the failure handling exists once.
     *
     * @return array<string,mixed>
     */
    private static function countStep(Gateway $gw, string $core, string $tag, string $key, string $label): array
    {
        $gw->resetError();
        $res = $gw->select($tag, $core, ['q' => '*:*', 'rows' => 0]);
        $err = $gw->error();
        if ($err !== null) {
            return ['ok' => false, 'note' => 'failed', 'detail' => $err];
        }
        return [
            'ok'      => true,
            'note'    => number_format($res['numFound']) . ' docs',
            'detail'  => $res['numFound'] === 0
                ? $label . ' is reachable but empty.'
                : $label . ' holds ' . number_format($res['numFound']) . ' documents.',
            'context' => [$key => $res['numFound']],
        ];
    }

    /**
     * Validate Opensolr credentials, read-only.
     *
     * Deliberately does not provision, rebuild or push a configset — that is the
     * installer's job and lives in `src/Setup/`. This confirms the account works and that
     * the configured region exists. The API key is never printed, only confirmed present.
     *
     * @return array<int,array{label:string,run:callable}>
     */
    private static function planOpensolrCheck(): array
    {
        return [
            [
                'label' => 'Checking the credentials are present',
                'run' => static function (array $ctx, Config $cfg, Gateway $gw): array {
                    if ((string) $cfg->get('solr.mode') !== 'opensolr') {
                        return [
                            'ok'     => true,
                            'stop'   => true,
                            'note'   => 'n/a',
                            'detail' => 'This install uses a custom Solr, so there is nothing to check with Opensolr.',
                        ];
                    }
                    if ((string) $cfg->get('opensolr.email') === '' || (string) $cfg->get('opensolr.api_key') === '') {
                        return [
                            'ok'     => false,
                            'note'   => 'missing',
                            'detail' => 'opensolr.email and opensolr.api_key must both be set in config/loghound.php.',
                        ];
                    }
                    return ['ok' => true, 'note' => 'present', 'detail' => 'Account credentials are configured.'];
                },
            ],
            [
                'label' => 'Contacting the Opensolr API',
                'run' => static function (array $ctx, Config $cfg, Gateway $gw): array {
                    $url = rtrim((string) $cfg->get('opensolr.api_base'), '/')
                        . '/regions?email=' . rawurlencode((string) $cfg->get('opensolr.email'))
                        . '&api_key=' . rawurlencode((string) $cfg->get('opensolr.api_key'));

                    [$body, $error] = self::fetch($url, 15);
                    if ($error !== null) {
                        return ['ok' => false, 'note' => 'unreachable', 'detail' => $error];
                    }
                    $names = self::regionNames($body);
                    if ($names === []) {
                        return [
                            'ok'     => false,
                            'note'   => 'rejected',
                            'detail' => 'The API answered but listed no regions — usually a wrong email or API key.',
                        ];
                    }
                    return [
                        'ok'      => true,
                        'note'    => count($names) . ' regions',
                        'detail'  => 'Credentials accepted.',
                        'context' => ['regions' => array_slice($names, 0, 60)],
                    ];
                },
            ],
            [
                'label' => 'Matching the configured region',
                'run' => static function (array $ctx, Config $cfg, Gateway $gw): array {
                    $want = (string) $cfg->get('opensolr.region');
                    $have = array_values(array_filter((array) ($ctx['regions'] ?? []), 'is_string'));
                    if ($want === '') {
                        return [
                            'ok'     => true,
                            'note'   => 'unset',
                            'detail' => 'No region configured. Available: ' . implode(', ', array_slice($have, 0, 12)),
                        ];
                    }
                    if (!in_array($want, $have, true)) {
                        return [
                            'ok'     => false,
                            'note'   => 'unknown',
                            'detail' => 'That region is not in the list this account can use.',
                        ];
                    }
                    return ['ok' => true, 'note' => $want, 'detail' => 'Region is valid for this account.'];
                },
            ],
        ];
    }

    /**
     * Extract region names from an Opensolr API response.
     *
     * The list has been returned both bare and wrapped over time; both shapes are
     * accepted rather than failing a credential check over a response envelope.
     *
     * @return array<int,string>
     */
    private static function regionNames(string $body): array
    {
        $data = json_decode($body, true);
        if (!is_array($data)) {
            return [];
        }
        $regions = $data['regions'] ?? $data['data'] ?? $data;
        $names = [];
        foreach ((array) $regions as $region) {
            $name = is_array($region) ? ($region['region'] ?? $region['name'] ?? null) : $region;
            if (is_string($name) && $name !== '') {
                $names[] = $name;
            }
        }
        return $names;
    }

    /**
     * Show what retention would delete — a preview, never a deletion.
     *
     * `Solr::deleteByQuery()` is documented internal-only with no HTTP path reaching it,
     * and that is correct: delete-by-query is the most destructive primitive Solr exposes
     * and a web panel is the last place it belongs. The panel counts;
     * `bin/loghound-retention` deletes.
     *
     * @return array<int,array{label:string,run:callable}>
     */
    private static function planRetentionPreview(): array
    {
        return [
            [
                'label' => 'Reading the retention policy',
                'run' => static function (array $ctx, Config $cfg, Gateway $gw): array {
                    $days = (int) $cfg->get('privacy.retention_days', 0);
                    if ($days <= 0) {
                        return [
                            'ok'     => true,
                            'stop'   => true,
                            'note'   => 'disabled',
                            'detail' => 'Retention is 0, so nothing is ever deleted and there is nothing to preview.',
                        ];
                    }
                    return [
                        'ok'      => true,
                        'note'    => $days . ' days',
                        'detail'  => 'Documents older than ' . $days . ' days are eligible for deletion.',
                        'context' => ['days' => $days, 'cutoff' => 'NOW-' . $days . 'DAY'],
                    ];
                },
            ],
            [
                'label' => 'Counting sessions past retention',
                'run' => static function (array $ctx, Config $cfg, Gateway $gw): array {
                    return self::retentionCount($gw, $gw->sessionsCore(), 'ts_start', $ctx, 'sessions', 'session');
                },
            ],
            [
                'label' => 'Counting hits past retention',
                'run' => static function (array $ctx, Config $cfg, Gateway $gw): array {
                    return self::retentionCount($gw, $gw->hitsCore(), 'ts', $ctx, 'hits', 'hit');
                },
            ],
            [
                'label' => 'Summarising',
                'run' => static function (array $ctx, Config $cfg, Gateway $gw): array {
                    $total = (int) ($ctx['sessions'] ?? 0) + (int) ($ctx['hits'] ?? 0);
                    return [
                        'ok'     => true,
                        'note'   => number_format($total) . ' docs',
                        'detail' => $total === 0
                            ? 'Nothing is past retention. The index is already within policy.'
                            : number_format($total) . ' documents would be removed. The panel does not delete: run '
                              . 'bin/loghound-retention, or enable loghound-retention.timer, to apply it.',
                    ];
                },
            ],
        ];
    }

    /**
     * Count documents older than the retention cutoff on one core.
     *
     * The cutoff is Solr date math this class built from a clamped integer, never a value
     * that came from the browser.
     *
     * @param array<string,mixed> $ctx
     * @return array<string,mixed>
     */
    private static function retentionCount(
        Gateway $gw,
        string $core,
        string $field,
        array $ctx,
        string $key,
        string $noun
    ): array {
        $days = (int) ($ctx['days'] ?? 0);
        if ($days <= 0) {
            return ['ok' => true, 'note' => 'skipped', 'detail' => 'Retention is disabled.'];
        }
        $gw->resetError();
        $res = $gw->select('job.retention.' . $key, $core, [
            'q'    => '*:*',
            'fq'   => [Query::rangeUntil($field, $days)],
            'rows' => 0,
        ]);
        $err = $gw->error();
        if ($err !== null) {
            return ['ok' => false, 'note' => 'failed', 'detail' => $err];
        }
        return [
            'ok'      => true,
            'note'    => number_format($res['numFound']),
            'detail'  => number_format($res['numFound']) . ' ' . $noun . ' documents are past the retention window.',
            'context' => [$key => $res['numFound']],
        ];
    }

    /**
     * A single outbound HTTP GET with an explicit, short timeout.
     *
     * Every network call the panel makes has one. A request that hangs until the PHP
     * process is killed gives the operator a dead tab and no diagnosis; one that times out
     * in fifteen seconds gives them a sentence naming what was unreachable. The URL
     * carries an API key, so it is never quoted back in an error.
     *
     * @return array{0:string,1:?string} [body, error message or null]
     */
    private static function fetch(string $url, int $timeout): array
    {
        if (!function_exists('curl_init')) {
            return ['', 'ext-curl is not available, so the panel cannot reach the API.'];
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS      => 0,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT      => 'Loghound-Panel/1.0',
        ]);
        $body   = curl_exec($ch);
        $errno  = curl_errno($ch);
        $error  = curl_error($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        if ($errno === CURLE_OPERATION_TIMEDOUT) {
            return ['', 'Timed out after ' . $timeout . 's contacting the Opensolr API. '
                . 'Check outbound HTTPS from this host and any egress firewall.'];
        }
        if ($errno !== 0 || !is_string($body)) {
            return ['', self::redact('Could not reach the Opensolr API: ' . $error)];
        }
        if ($status < 200 || $status >= 300) {
            return ['', 'The Opensolr API answered HTTP ' . $status . '.'];
        }
        return [$body, null];
    }

    /**
     * Validate a job id from the browser before it reaches the store.
     *
     * 24 hex characters, which is the exact shape `bin2hex(random_bytes(12))` produces.
     */
    public static function isJobId(string $id): bool
    {
        return (bool) preg_match('/^[a-f0-9]{24}$/', $id);
    }
}
