<?php
/**
 * Loghound — SQLite state store.
 *
 * Everything that must survive a daemon restart but does not belong in Solr lives here:
 *
 *   offsets         where the tailer had read up to in each log file
 *   sessions_open   sessions that have not yet been idle long enough to close and score
 *   beacon_staging  beacon payloads the public collector accepted, awaiting merge
 *   cache_geo       geolocation results keyed per address, with negative caching
 *   cache_asn       Team Cymru + RIR whois results, keyed per netblock
 *   cache_rdns      forward-confirmed reverse DNS results
 *   ratelimit       token buckets for the public beacon endpoint
 *   meta            counters and small key/value state (parse_errors, schema version, ...)
 *
 * Why SQLite and not Solr or Redis: it needs no daemon, no credentials and no network, it
 * survives a power cut, and `public/collect.php` — the one public, unauthenticated write
 * path in the product — can use it without ever holding Solr credentials (SPEC §6.3).
 *
 * Concurrency: the tailer, the scorer and every collector request all touch this file at
 * once. WAL mode lets readers run while a writer commits, and a busy timeout turns the
 * remaining contention into a short wait instead of an immediate SQLITE_BUSY. Every
 * statement is prepared and bound — there is not one string-interpolated value in this file.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound;

use SQLite3;
use SQLite3Stmt;

final class State
{
    /** How long a writer waits for a competing transaction before giving up (ms). */
    private const BUSY_TIMEOUT_MS = 5000;

    /**
     * TTL applied to a NEGATIVE cache entry, in seconds.
     *
     * Much shorter than the positive TTL on purpose: a failed lookup is usually a transient
     * network problem, and caching "we don't know" for 30 days would permanently blind the
     * enrichment for that netblock. One hour is long enough to stop a dead whois server from
     * being hammered once per hit, short enough to self-heal.
     */
    private const NEGATIVE_TTL = 3600;

    private SQLite3 $db;

    /** @var array<string,SQLite3Stmt> Prepared statement cache, keyed by SQL text. */
    private array $stmts = [];

    /**
     * Open (creating if needed) the state database.
     *
     * SQLite is put into exception mode rather than being allowed to return false silently: a
     * broken state DB must be loud, because the failure mode otherwise is "ingestion restarts
     * from offset 0".
     *
     * The journal is WAL, for concurrent readers during a write and a crash-safe journal, and
     * synchronous is NORMAL. That is the right trade here: a power cut can lose the last few
     * offset updates, which re-ingests a handful of lines, and re-ingest is idempotent because
     * a hit id is sha1(file + offset). FULL would fsync on every batch for no benefit.
     *
     * @param string $path Filesystem path, e.g. var/state.db. The containing directory is
     *                     created with 0750 so the daemons can write but the world cannot
     *                     read visitor addresses out of it.
     */
    public function __construct(string $path)
    {
        $dir = dirname($path);
        if (!is_dir($dir)) {
            @mkdir($dir, 0750, true);
        }

        $this->db = new SQLite3($path, SQLITE3_OPEN_READWRITE | SQLITE3_OPEN_CREATE);
        $this->db->enableExceptions(true);
        $this->db->busyTimeout(self::BUSY_TIMEOUT_MS);

        $this->db->exec('PRAGMA journal_mode = WAL');
        $this->db->exec('PRAGMA synchronous = NORMAL');
        $this->db->exec('PRAGMA foreign_keys = ON');
        $this->db->exec('PRAGMA temp_store = MEMORY');

        @chmod($path, 0640);

        $this->migrate();
    }

    /**
     * Create the schema if it is not already there.
     *
     * Written as plain idempotent CREATE IF NOT EXISTS rather than a versioned migration
     * runner, because the schema is small and additive; `meta.schema_version` records where
     * we are so a future breaking change has something to branch on.
     *
     * `sessions_open` holds one row per open session, keyed by `client_key`, which is ip_net
     * plus ua_hash (SPEC §5.4) and is what both the tailer and the beacon collector look a
     * session up by. The public collector appends to `beacon_staging` and does nothing else
     * with it; loghound-score drains it. The three enrichment caches have an identical shape
     * and are separate tables rather than one table with a namespace column, so that each can
     * be vacuumed and sized independently.
     *
     * `sessions_open.scored_ts` arrived after version 1, so it is both in the CREATE and in an
     * addColumn() call: a fresh install gets it from the table definition, and an install that
     * already has the table gets it from the ALTER. Leaving it out of one or the other would
     * mean the feature works on exactly one of the two.
     */
    private function migrate(): void
    {
        $this->db->exec(
            'CREATE TABLE IF NOT EXISTS offsets (
                src         TEXT PRIMARY KEY,
                dev         INTEGER NOT NULL DEFAULT 0,
                inode       INTEGER NOT NULL DEFAULT 0,
                offset      INTEGER NOT NULL DEFAULT 0,
                updated_at  INTEGER NOT NULL DEFAULT 0
            )'
        );

        $this->db->exec(
            'CREATE TABLE IF NOT EXISTS sessions_open (
                session_id  TEXT PRIMARY KEY,
                client_key  TEXT NOT NULL,
                host        TEXT,
                first_ts    INTEGER NOT NULL,
                last_ts     INTEGER NOT NULL,
                hits        INTEGER NOT NULL DEFAULT 0,
                data        TEXT NOT NULL DEFAULT ' . "'{}'" . ',
                closed_at   INTEGER,
                scored_ts   INTEGER
            )'
        );
        $this->addColumn('sessions_open', 'scored_ts', 'INTEGER');
        $this->db->exec(
            'CREATE INDEX IF NOT EXISTS idx_sessions_client
                ON sessions_open (client_key, closed_at)'
        );
        $this->db->exec(
            'CREATE INDEX IF NOT EXISTS idx_sessions_last
                ON sessions_open (closed_at, last_ts)'
        );
        $this->db->exec(
            'CREATE INDEX IF NOT EXISTS idx_sessions_dirty
                ON sessions_open (closed_at, scored_ts, last_ts)'
        );

        $this->db->exec(
            'CREATE TABLE IF NOT EXISTS beacon_staging (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id  TEXT,
                client_key  TEXT,
                received_at INTEGER NOT NULL,
                payload     TEXT NOT NULL,
                merged      INTEGER NOT NULL DEFAULT 0
            )'
        );
        $this->db->exec(
            'CREATE INDEX IF NOT EXISTS idx_beacon_session
                ON beacon_staging (session_id, merged)'
        );
        $this->db->exec(
            'CREATE INDEX IF NOT EXISTS idx_beacon_clientkey
                ON beacon_staging (client_key, merged)'
        );

        foreach (['cache_geo', 'cache_asn', 'cache_rdns'] as $table) {
            $this->db->exec(
                'CREATE TABLE IF NOT EXISTS ' . $table . ' (
                    k          TEXT PRIMARY KEY,
                    v          TEXT,
                    negative   INTEGER NOT NULL DEFAULT 0,
                    expires_at INTEGER NOT NULL
                )'
            );
            $this->db->exec(
                'CREATE INDEX IF NOT EXISTS idx_' . $table . '_exp ON ' . $table . ' (expires_at)'
            );
        }

        $this->db->exec(
            'CREATE TABLE IF NOT EXISTS ratelimit (
                k          TEXT PRIMARY KEY,
                tokens     REAL NOT NULL,
                updated_at REAL NOT NULL
            )'
        );

        $this->db->exec(
            'CREATE TABLE IF NOT EXISTS meta (
                k TEXT PRIMARY KEY,
                v TEXT NOT NULL
            )'
        );

        $this->metaSet('schema_version', '2');
    }

    /**
     * Add a column to an existing table, if it is not already there.
     *
     * SQLite has no `ADD COLUMN IF NOT EXISTS`, and a plain ALTER on an existing column is an
     * error, so the current columns are read first. The table and column names are compile-time
     * literals from this file and never come from input — which they cannot, because ALTER TABLE
     * takes no bound parameters for identifiers.
     *
     * @param string $type SQL type and any default, e.g. 'INTEGER' or "TEXT NOT NULL DEFAULT ''".
     */
    private function addColumn(string $table, string $column, string $type): void
    {
        if (!preg_match('/^[a-z_][a-z0-9_]*$/D', $table) || !preg_match('/^[a-z_][a-z0-9_]*$/D', $column)) {
            throw new \InvalidArgumentException('State: unsafe identifier in addColumn().');
        }

        /* THE TYPE IS CONCATENATED TOO, and it was the one argument with no check on it at all
           while the docblock above discussed only the two names. Everything after ADD COLUMN is
           SQL, so a type carrying a comma or a semicolon is a second clause. Every caller passes
           a literal from this file, which is exactly why the guard costs nothing and exactly why
           it has to be here rather than assumed. */
        if (!preg_match('/^[A-Z]+(?: NOT NULL)?(?: DEFAULT (?:-?\d+(?:\.\d+)?|\'\'|\'[A-Za-z0-9_ -]{0,32}\'))?$/D', $type)) {
            throw new \InvalidArgumentException('State: unsafe column type in addColumn(): ' . $type);
        }

        $res = $this->db->query('PRAGMA table_info(' . $table . ')');
        if ($res === false) {
            return;
        }
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            if ((string) ($row['name'] ?? '') === $column) {
                return;
            }
        }

        $this->db->exec('ALTER TABLE ' . $table . ' ADD COLUMN ' . $column . ' ' . $type);
    }

    /** The underlying handle, for the rare caller that needs a transaction of its own. */
    public function db(): SQLite3
    {
        return $this->db;
    }

    /** Close the database. Safe to call more than once. */
    public function close(): void
    {
        foreach ($this->stmts as $stmt) {
            @$stmt->close();
        }
        $this->stmts = [];
        @$this->db->close();
    }

    /**
     * Read the recorded read position for a log file.
     *
     * The (dev, inode) pair is stored alongside the byte offset because the offset alone is
     * meaningless after a logrotate: the path now points at a brand-new file and resuming at
     * the old offset would skip everything before it. SPEC §5.1 calls this the #1 source of
     * silent data loss, and this is the state that lets the tailer detect it.
     *
     * @return array{dev:int,inode:int,offset:int,updated_at:int}|null
     */
    public function getOffset(string $src): ?array
    {
        $row = $this->one(
            'SELECT dev, inode, offset, updated_at FROM offsets WHERE src = :src',
            [':src' => $src]
        );
        if ($row === null) {
            return null;
        }
        return [
            'dev'        => (int) $row['dev'],
            'inode'      => (int) $row['inode'],
            'offset'     => (int) $row['offset'],
            'updated_at' => (int) $row['updated_at'],
        ];
    }

    /** Record the read position for a log file. */
    public function setOffset(string $src, int $dev, int $inode, int $offset): void
    {
        $this->run(
            'INSERT INTO offsets (src, dev, inode, offset, updated_at)
             VALUES (:src, :dev, :inode, :off, :now)
             ON CONFLICT(src) DO UPDATE SET
                dev = excluded.dev,
                inode = excluded.inode,
                offset = excluded.offset,
                updated_at = excluded.updated_at',
            [':src' => $src, ':dev' => $dev, ':inode' => $inode, ':off' => $offset, ':now' => time()]
        );
    }

    /** Forget a log file's position — used when a source is removed from the config. */
    public function clearOffset(string $src): void
    {
        $this->run('DELETE FROM offsets WHERE src = :src', [':src' => $src]);
    }

    /**
     * Every recorded offset, for the status command and the setup UI.
     *
     * @return array<int,array<string,mixed>>
     */
    public function allOffsets(): array
    {
        return $this->all('SELECT src, dev, inode, offset, updated_at FROM offsets ORDER BY src');
    }

    /**
     * Find the open session for a client key, if one exists and is not stale.
     *
     * @param string $clientKey ip_net + '|' + ua_hash
     * @param int    $idleSec   Sessions idle longer than this are not reused (SPEC §5.4).
     * @param int    $nowMs     Current instant, in epoch milliseconds.
     *
     * @return array{session_id:string,client_key:string,host:?string,first_ts:int,last_ts:int,hits:int,data:array}|null
     */
    public function findOpenSession(string $clientKey, int $idleSec, int $nowMs): ?array
    {
        $row = $this->one(
            'SELECT session_id, client_key, host, first_ts, last_ts, hits, data
               FROM sessions_open
              WHERE client_key = :ck AND closed_at IS NULL AND last_ts >= :cutoff
              ORDER BY last_ts DESC LIMIT 1',
            [':ck' => $clientKey, ':cutoff' => $nowMs - ($idleSec * 1000)]
        );
        return $row === null ? null : self::hydrateSession($row);
    }

    /** Fetch one session by id, open or closed. */
    public function getSession(string $sessionId): ?array
    {
        $row = $this->one(
            'SELECT session_id, client_key, host, first_ts, last_ts, hits, data
               FROM sessions_open WHERE session_id = :id',
            [':id' => $sessionId]
        );
        return $row === null ? null : self::hydrateSession($row);
    }

    /**
     * Open a new session and return its id.
     *
     * `session_id = sha1(client_key + first_ts + random)` per SPEC §5.4. The random component
     * is what stops a beacon from being able to GUESS another visitor's session id and
     * inject dwell time into it — without it the id would be a pure function of two things
     * an attacker knows.
     *
     * @param array<string,mixed> $data Arbitrary running state (counters, first-hit fields).
     */
    public function openSession(string $clientKey, int $firstTsMs, ?string $host = null, array $data = []): string
    {
        $sessionId = sha1($clientKey . '|' . $firstTsMs . '|' . bin2hex(random_bytes(16)));
        $this->run(
            'INSERT INTO sessions_open (session_id, client_key, host, first_ts, last_ts, hits, data)
             VALUES (:id, :ck, :host, :first, :last, 0, :data)',
            [
                ':id'    => $sessionId,
                ':ck'    => $clientKey,
                ':host'  => $host,
                ':first' => $firstTsMs,
                ':last'  => $firstTsMs,
                ':data'  => self::encode($data),
            ]
        );
        return $sessionId;
    }

    /**
     * Advance a session: bump the hit counter, extend the end time, replace the state blob.
     *
     * @param array<string,mixed>|null $data Null keeps the existing blob untouched.
     */
    public function updateSession(string $sessionId, int $lastTsMs, int $hitsDelta = 1, ?array $data = null): void
    {
        if ($data === null) {
            $this->run(
                'UPDATE sessions_open
                    SET last_ts = MAX(last_ts, :last), hits = hits + :delta
                  WHERE session_id = :id',
                [':last' => $lastTsMs, ':delta' => $hitsDelta, ':id' => $sessionId]
            );
            return;
        }
        $this->run(
            'UPDATE sessions_open
                SET last_ts = MAX(last_ts, :last), hits = hits + :delta, data = :data
              WHERE session_id = :id',
            [
                ':last'  => $lastTsMs,
                ':delta' => $hitsDelta,
                ':data'  => self::encode($data),
                ':id'    => $sessionId,
            ]
        );
    }

    /**
     * List sessions that have been idle longer than $idleSec and are not yet closed.
     *
     * This is what `bin/loghound-score` polls every 60s to decide what to score.
     *
     * The batch is bounded: an unbounded query after a long outage would try to load every
     * session at once.
     *
     * @return array<int,array<string,mixed>>
     */
    public function listIdleSessions(int $idleSec, int $nowMs, int $limit = 500): array
    {
        $rows = $this->all(
            'SELECT session_id, client_key, host, first_ts, last_ts, hits, data
               FROM sessions_open
              WHERE closed_at IS NULL AND last_ts < :cutoff
              ORDER BY last_ts ASC
              LIMIT :lim',
            [
                ':cutoff' => $nowMs - ($idleSec * 1000),
                ':lim'    => Security::clampInt($limit, 1, 5000, 500),
            ]
        );
        return array_map([self::class, 'hydrateSession'], $rows);
    }

    /**
     * List OPEN sessions whose aggregate has advanced since they were last published.
     *
     * This is the other half of what `bin/loghound-score` polls for: `listIdleSessions()`
     * returns what can be finalised, this returns what is still running and needs a
     * provisional document (SPEC §4.2 `provisional_b`) so the dashboard is not empty for the
     * whole idle timeout.
     *
     * "Advanced" is `scored_ts < last_ts`, both in epoch milliseconds, and that comparison is
     * what bounds the cost of the feature. A session is republished only when it has logged a
     * new hit since the last time its document went to Solr, so the work per run tracks the
     * REQUEST rate rather than the number of sessions that happen to be open — ten thousand
     * idle open sessions cost one index scan and nothing else. A NULL scored_ts means "never
     * published", which is how a session gets its first document and how the first run after an
     * upgrade picks up sessions that were already open.
     *
     * Freshest first, so that when the batch limit does bite it is the sessions an operator is
     * most likely to be watching that get published, not an arbitrary slice.
     *
     * @return array<int,array<string,mixed>>
     */
    public function listDirtyOpenSessions(int $limit = 500): array
    {
        $rows = $this->all(
            'SELECT session_id, client_key, host, first_ts, last_ts, hits, data
               FROM sessions_open
              WHERE closed_at IS NULL
                AND (scored_ts IS NULL OR scored_ts < last_ts)
              ORDER BY last_ts DESC
              LIMIT :lim',
            [':lim' => Security::clampInt($limit, 1, 5000, 500)]
        );
        return array_map([self::class, 'hydrateSession'], $rows);
    }

    /**
     * Record that a session was published to Solr as of a given instant.
     *
     * The instant is passed in rather than read from `last_ts` inside the UPDATE, and that is
     * the point: a hit that landed between the read and this write leaves `last_ts` ahead of
     * `scored_ts`, so the session stays dirty and is republished on the next run. Setting
     * `scored_ts = last_ts` in SQL would mark it clean and lose that hit from the panel until
     * the session closed.
     *
     * Wrapped in one transaction so a batch of several hundred is one fsync rather than
     * several hundred.
     *
     * @param array<string,int> $marks session_id => the ts_end, in epoch milliseconds, that
     *                                 was actually published.
     */
    public function markSessionsScored(array $marks): void
    {
        if ($marks === []) {
            return;
        }

        $this->db->exec('BEGIN IMMEDIATE');
        try {
            foreach ($marks as $sessionId => $tsMs) {
                $this->run(
                    'UPDATE sessions_open SET scored_ts = :ts WHERE session_id = :id',
                    [':ts' => (int) $tsMs, ':id' => (string) $sessionId]
                );
            }
            $this->db->exec('COMMIT');
        } catch (\Throwable $e) {
            $this->db->exec('ROLLBACK');
            throw $e;
        }
    }

    /**
     * Mark a session closed so it is never reopened or scored twice.
     *
     * The row is kept (not deleted) until purgeClosedSessions() runs, so a late beacon
     * arriving seconds after closing can still be matched and merged.
     */
    public function closeSession(string $sessionId): void
    {
        $this->run(
            'UPDATE sessions_open SET closed_at = :now WHERE session_id = :id AND closed_at IS NULL',
            [':now' => time(), ':id' => $sessionId]
        );
    }

    /**
     * Delete sessions closed longer than $olderThanSec ago, and their staged beacons.
     *
     * @return int Rows removed.
     */
    public function purgeClosedSessions(int $olderThanSec = 86400): int
    {
        $cutoff = time() - max(60, $olderThanSec);
        $this->run(
            'DELETE FROM beacon_staging
              WHERE session_id IN (SELECT session_id FROM sessions_open WHERE closed_at < :c)',
            [':c' => $cutoff]
        );
        $this->run('DELETE FROM sessions_open WHERE closed_at IS NOT NULL AND closed_at < :c', [':c' => $cutoff]);
        return $this->db->changes();
    }

    /** How many sessions are currently open. Cheap; used by the status command. */
    public function openSessionCount(): int
    {
        $row = $this->one('SELECT COUNT(*) AS n FROM sessions_open WHERE closed_at IS NULL');
        return (int) ($row['n'] ?? 0);
    }

    /**
     * Decode a session row's JSON blob into a PHP array.
     *
     * @param array<string,mixed> $row
     * @return array<string,mixed>
     */
    private static function hydrateSession(array $row): array
    {
        $data = json_decode((string) ($row['data'] ?? '{}'), true);
        return [
            'session_id' => (string) $row['session_id'],
            'client_key' => (string) $row['client_key'],
            'host'       => $row['host'] === null ? null : (string) $row['host'],
            'first_ts'   => (int) $row['first_ts'],
            'last_ts'    => (int) $row['last_ts'],
            'hits'       => (int) $row['hits'],
            'data'       => is_array($data) ? $data : [],
        ];
    }

    /**
     * Store a validated beacon payload for later merging.
     *
     * The collector calls this and nothing else — it never talks to Solr, which keeps the
     * public request path cheap and keeps Solr credentials out of it entirely (SPEC §6.3).
     *
     * @param array<string,mixed> $payload Already validated and clamped by Beacon.php.
     */
    public function stageBeacon(?string $sessionId, ?string $clientKey, array $payload): void
    {
        $this->run(
            'INSERT INTO beacon_staging (session_id, client_key, received_at, payload)
             VALUES (:sid, :ck, :now, :p)',
            [
                ':sid' => $sessionId,
                ':ck'  => $clientKey,
                ':now' => time(),
                ':p'   => self::encode($payload),
            ]
        );
    }

    /**
     * Fetch the unmerged beacons for a session (or, failing that, for a client key).
     *
     * The client-key fallback exists because the beacon's very first call happens before the
     * server has issued a session id (SPEC §6.4), so the earliest payloads can only be
     * matched by the same ip_net + ua_hash the tailer derives.
     *
     * @return array<int,array{id:int,received_at:int,payload:array}>
     */
    public function beaconsFor(?string $sessionId, ?string $clientKey = null, int $limit = 500): array
    {
        $limit = Security::clampInt($limit, 1, 5000, 500);

        if ($sessionId !== null && $clientKey !== null) {
            $rows = $this->all(
                'SELECT id, session_id, received_at, payload FROM beacon_staging
                  WHERE merged = 0 AND (session_id = :sid OR client_key = :ck)
                  ORDER BY id ASC LIMIT :lim',
                [':sid' => $sessionId, ':ck' => $clientKey, ':lim' => $limit]
            );
        } elseif ($sessionId !== null) {
            $rows = $this->all(
                'SELECT id, session_id, received_at, payload FROM beacon_staging
                  WHERE merged = 0 AND session_id = :sid ORDER BY id ASC LIMIT :lim',
                [':sid' => $sessionId, ':lim' => $limit]
            );
        } elseif ($clientKey !== null) {
            $rows = $this->all(
                'SELECT id, session_id, received_at, payload FROM beacon_staging
                  WHERE merged = 0 AND client_key = :ck ORDER BY id ASC LIMIT :lim',
                [':ck' => $clientKey, ':lim' => $limit]
            );
        } else {
            return [];
        }

        $out = [];
        foreach ($rows as $row) {
            $payload = json_decode((string) $row['payload'], true);
            $out[] = [
                'id'          => (int) $row['id'],
                'session_id'  => (string) ($row['session_id'] ?? ''),
                'received_at' => (int) $row['received_at'],
                'payload'     => is_array($payload) ? $payload : [],
            ];
        }
        return $out;
    }

    /**
     * The unmerged beacon groups that no log session has claimed, newest activity last.
     *
     * This is what the scorer walks to find STANDALONE sessions — beacons from a host whose
     * access log is not one of this installation's sources, so there is no log line coming
     * and nothing will ever claim them by client key. One row per staged session id, with the
     * client key and the timestamps of the group, so the caller can decide whether the group
     * has gone quiet without reading every payload first.
     *
     * Only rows the collector minted an id for are returned. A row with no session id at all
     * cannot be grouped into a visit and has nothing to be published as.
     *
     * The MIN(client_key) is not an arbitrary pick: every row of one beacon-minted session id
     * carries the same client key, because the collector derives it from the connection and
     * the id is bound to that connection's first call. SQLite has no ANY_VALUE, and MIN over
     * one distinct value is that value.
     *
     * @param int $limit Bound on one run's work, like every other batch in this class.
     * @return array<int,array{session_id:string,client_key:string,rows:int,first_ts:int,last_ts:int}>
     */
    public function unmergedBeaconGroups(int $limit = 500): array
    {
        $limit = Security::clampInt($limit, 1, 5000, 500);

        $rows = $this->all(
            'SELECT session_id,
                    MIN(client_key) AS client_key,
                    COUNT(*)        AS n,
                    MIN(received_at) AS first_ts,
                    MAX(received_at) AS last_ts
               FROM beacon_staging
              WHERE merged = 0 AND session_id IS NOT NULL AND session_id <> \'\'
              GROUP BY session_id
              ORDER BY last_ts ASC
              LIMIT :lim',
            [':lim' => $limit]
        );

        $out = [];
        foreach ($rows as $row) {
            $out[] = [
                'session_id' => (string) $row['session_id'],
                'client_key' => (string) ($row['client_key'] ?? ''),
                'rows'       => (int) $row['n'],
                'first_ts'   => (int) $row['first_ts'],
                'last_ts'    => (int) $row['last_ts'],
            ];
        }
        return $out;
    }

    /**
     * Mark staged beacons as merged so they are not applied to the session twice.
     *
     * The ids come from our own SELECT, but they are cast to int anyway: the day someone
     * passes a request parameter in here, that cast is what keeps it from mattering.
     *
     * @param int[] $ids
     */
    public function markBeaconsMerged(array $ids): void
    {
        if ($ids === []) {
            return;
        }
        $stmt = $this->prepare('UPDATE beacon_staging SET merged = 1 WHERE id = :id');
        $this->db->exec('BEGIN');
        try {
            foreach ($ids as $id) {
                $stmt->reset();
                $stmt->bindValue(':id', (int) $id, SQLITE3_INTEGER);
                $stmt->execute();
            }
            $this->db->exec('COMMIT');
        } catch (\Throwable $e) {
            $this->db->exec('ROLLBACK');
            throw $e;
        }
    }

    /**
     * Delete merged or orphaned beacon rows older than the cutoff.
     *
     * @return int Rows removed.
     */
    public function purgeBeacons(int $olderThanSec = 86400): int
    {
        $this->run(
            'DELETE FROM beacon_staging WHERE received_at < :c',
            [':c' => time() - max(60, $olderThanSec)]
        );
        return $this->db->changes();
    }

    /**
     * Read a cache entry.
     *
     * Three distinct outcomes, and the caller needs to tell them apart:
     *   - MISS      → return null and $hit stays false. Do the lookup.
     *   - NEGATIVE  → return null and $hit becomes true. A previous lookup failed or found
     *                 nothing; do NOT retry yet.
     *   - HIT       → return the cached array, $hit becomes true.
     *
     * Without the negative case, an IP with no geo record would be looked up on every single
     * one of its hits forever, which on a scanned server means thousands of pointless
     * outbound requests per minute.
     *
     * @param string $ns  'geo' | 'asn' | 'rdns'
     * @param bool   $hit Out-parameter: was there any entry at all?
     * @return array<string,mixed>|null
     */
    public function cacheGet(string $ns, string $key, ?bool &$hit = null): ?array
    {
        $hit   = false;
        $table = self::cacheTable($ns);

        $row = $this->one(
            'SELECT v, negative FROM ' . $table . ' WHERE k = :k AND expires_at > :now',
            [':k' => $key, ':now' => time()]
        );
        if ($row === null) {
            return null;
        }
        $hit = true;
        if ((int) $row['negative'] === 1) {
            return null;
        }
        $value = json_decode((string) $row['v'], true);
        return is_array($value) ? $value : null;
    }

    /**
     * Write a cache entry.
     *
     * Passing null (or an empty array) for $value stores a NEGATIVE entry with the short
     * negative TTL rather than the caller's TTL.
     *
     * @param string                   $ns    'geo' | 'asn' | 'rdns'
     * @param array<string,mixed>|null $value
     * @param int                      $ttl   Positive-entry lifetime in seconds.
     */
    public function cachePut(string $ns, string $key, ?array $value, int $ttl): void
    {
        $table    = self::cacheTable($ns);
        $negative = ($value === null || $value === []);
        $expires  = time() + ($negative ? self::NEGATIVE_TTL : max(60, $ttl));

        $this->run(
            'INSERT INTO ' . $table . ' (k, v, negative, expires_at)
             VALUES (:k, :v, :neg, :exp)
             ON CONFLICT(k) DO UPDATE SET
                v = excluded.v, negative = excluded.negative, expires_at = excluded.expires_at',
            [
                ':k'   => $key,
                ':v'   => $negative ? null : self::encode($value),
                ':neg' => $negative ? 1 : 0,
                ':exp' => $expires,
            ]
        );
    }

    /**
     * Drop expired rows from one or all caches.
     *
     * @return int Rows removed.
     */
    public function cachePurgeExpired(?string $ns = null): int
    {
        $tables = $ns === null ? ['cache_geo', 'cache_asn', 'cache_rdns'] : [self::cacheTable($ns)];
        $removed = 0;
        foreach ($tables as $table) {
            $this->run('DELETE FROM ' . $table . ' WHERE expires_at <= :now', [':now' => time()]);
            $removed += $this->db->changes();
        }
        return $removed;
    }

    /**
     * Map a cache namespace to its table, refusing anything unknown.
     *
     * The table name is concatenated into SQL (SQLite cannot bind an identifier), so this
     * allowlist is the ONLY thing standing between a caller's string and the query. It fails
     * closed with an exception rather than defaulting to a table.
     */
    private static function cacheTable(string $ns): string
    {
        switch ($ns) {
            case 'geo':
                return 'cache_geo';
            case 'asn':
                return 'cache_asn';
            case 'rdns':
                return 'cache_rdns';
            default:
                throw new \InvalidArgumentException('Unknown cache namespace: ' . $ns);
        }
    }

    /**
     * Token-bucket rate limit check. Returns true when the request is allowed.
     *
     * Used by `public/collect.php`, which is public and unauthenticated. A bucket refills at
     * $perMinute/60 tokens per second up to a ceiling of $burst, so a visitor whose page
     * fires a heartbeat every 15 seconds never notices it, while a script hammering the
     * endpoint is throttled within a second or two.
     *
     * The whole check is one UPSERT plus one SELECT under SQLite's row lock; there is no
     * read-modify-write race window that would let a burst of parallel requests each see a
     * full bucket, because the UPDATE computes the new level from the stored one.
     *
     * A bucket is inserted full on first sight; afterwards it is refilled by elapsed time and
     * one token is spent. A request over budget clamps the balance at -1, so that a sustained
     * flood cannot drive it to minus a million and lock the visitor out for hours after it
     * stops.
     *
     * @param string $key       Bucket identity, e.g. 'ip:203.0.113.7' or 'sess:<id>'.
     * @param int    $perMinute Sustained rate.
     * @param int    $burst     Bucket capacity; defaults to the per-minute rate.
     */
    public function rateLimit(string $key, int $perMinute, ?int $burst = null): bool
    {
        $perMinute = Security::clampInt($perMinute, 1, 100000, 120);
        $capacity  = (float) Security::clampInt($burst ?? $perMinute, 1, 100000, $perMinute);
        $refill    = $perMinute / 60.0;
        $now       = microtime(true);

        $this->run(
            'INSERT INTO ratelimit (k, tokens, updated_at)
             VALUES (:k, :cap - 1.0, :now)
             ON CONFLICT(k) DO UPDATE SET
                tokens = MIN(:cap, ratelimit.tokens + (:now - ratelimit.updated_at) * :refill) - 1.0,
                updated_at = :now',
            [':k' => $key, ':cap' => $capacity, ':now' => $now, ':refill' => $refill]
        );

        $row = $this->one('SELECT tokens FROM ratelimit WHERE k = :k', [':k' => $key]);
        $tokens = (float) ($row['tokens'] ?? 0.0);

        if ($tokens < 0.0) {
            $this->run(
                'UPDATE ratelimit SET tokens = -1.0 WHERE k = :k AND tokens < -1.0',
                [':k' => $key]
            );
            return false;
        }
        return true;
    }

    /** Drop rate-limit buckets untouched for a while, to keep the table small. */
    public function purgeRateLimits(int $olderThanSec = 3600): int
    {
        $this->run(
            'DELETE FROM ratelimit WHERE updated_at < :c',
            [':c' => microtime(true) - max(60, $olderThanSec)]
        );
        return $this->db->changes();
    }

    /** Read a small key/value setting, with a default. */
    public function metaGet(string $key, ?string $default = null): ?string
    {
        $row = $this->one('SELECT v FROM meta WHERE k = :k', [':k' => $key]);
        return $row === null ? $default : (string) $row['v'];
    }

    /** Write a small key/value setting. */
    public function metaSet(string $key, string $value): void
    {
        $this->run(
            'INSERT INTO meta (k, v) VALUES (:k, :v)
             ON CONFLICT(k) DO UPDATE SET v = excluded.v',
            [':k' => $key, ':v' => $value]
        );
    }

    /**
     * Atomically add to a numeric counter and return the new value.
     *
     * `parse_errors` lives here: SPEC §5.2 requires unparseable lines to be COUNTED, never
     * silently dropped, and a counter that survives a restart is the only version of that
     * which is actually useful.
     */
    public function counterAdd(string $key, int $delta = 1): int
    {
        $this->run(
            'INSERT INTO meta (k, v) VALUES (:k, :d)
             ON CONFLICT(k) DO UPDATE SET v = CAST(CAST(meta.v AS INTEGER) + :d AS TEXT)',
            [':k' => 'counter:' . $key, ':d' => $delta]
        );
        return (int) $this->metaGet('counter:' . $key, '0');
    }

    /** Read a counter without changing it. */
    public function counterGet(string $key): int
    {
        return (int) $this->metaGet('counter:' . $key, '0');
    }

    /**
     * Prepare a statement, reusing the compiled form across calls.
     *
     * The tailer runs the same handful of statements millions of times per day; re-preparing
     * each time would mean re-parsing the SQL each time.
     */
    private function prepare(string $sql): SQLite3Stmt
    {
        if (!isset($this->stmts[$sql])) {
            $stmt = $this->db->prepare($sql);
            if ($stmt === false) {
                throw new \RuntimeException('Failed to prepare statement: ' . $sql);
            }
            $this->stmts[$sql] = $stmt;
        }
        return $this->stmts[$sql];
    }

    /**
     * Bind parameters onto a prepared statement, choosing the SQLite type per PHP type.
     *
     * @param array<string,mixed> $params
     */
    private function bind(SQLite3Stmt $stmt, array $params): void
    {
        foreach ($params as $name => $value) {
            if ($value === null) {
                $stmt->bindValue($name, null, SQLITE3_NULL);
            } elseif (is_int($value)) {
                $stmt->bindValue($name, $value, SQLITE3_INTEGER);
            } elseif (is_float($value)) {
                $stmt->bindValue($name, $value, SQLITE3_FLOAT);
            } elseif (is_bool($value)) {
                $stmt->bindValue($name, $value ? 1 : 0, SQLITE3_INTEGER);
            } else {
                $stmt->bindValue($name, (string) $value, SQLITE3_TEXT);
            }
        }
    }

    /**
     * Execute a statement that returns no rows.
     *
     * @param array<string,mixed> $params
     */
    private function run(string $sql, array $params = []): void
    {
        $stmt = $this->prepare($sql);
        $stmt->reset();
        $stmt->clear();
        $this->bind($stmt, $params);
        $stmt->execute();
    }

    /**
     * Execute a statement and return its first row, or null.
     *
     * @param array<string,mixed> $params
     * @return array<string,mixed>|null
     */
    private function one(string $sql, array $params = []): ?array
    {
        $stmt = $this->prepare($sql);
        $stmt->reset();
        $stmt->clear();
        $this->bind($stmt, $params);
        $res = $stmt->execute();
        if ($res === false) {
            return null;
        }
        $row = $res->fetchArray(SQLITE3_ASSOC);
        return is_array($row) ? $row : null;
    }

    /**
     * Execute a statement and return all rows.
     *
     * @param array<string,mixed> $params
     * @return array<int,array<string,mixed>>
     */
    private function all(string $sql, array $params = []): array
    {
        $stmt = $this->prepare($sql);
        $stmt->reset();
        $stmt->clear();
        $this->bind($stmt, $params);
        $res = $stmt->execute();
        if ($res === false) {
            return [];
        }
        $out = [];
        while (($row = $res->fetchArray(SQLITE3_ASSOC)) !== false) {
            $out[] = $row;
        }
        return $out;
    }

    /**
     * JSON-encode a value for storage.
     *
     * Invalid UTF-8 would make json_encode return false and silently store the string
     * "false"; INVALID_UTF8_SUBSTITUTE makes it lossy-but-valid instead. Log-derived data
     * reaches this function, so that case is not hypothetical.
     *
     * @param array<string,mixed>|null $value
     */
    private static function encode(?array $value): string
    {
        $json = json_encode($value ?? [], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        return $json === false ? '{}' : $json;
    }
}
