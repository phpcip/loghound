<?php
/**
 * Loghound — Sessionizer (SPEC §5 step 4).
 *
 * Groups hits into sessions as they arrive and maintains the running aggregate that
 * bin/loghound-score later turns into a `sessions` document.
 *
 * ---------------------------------------------------------------------------------------
 * THE KEY: client_key = ip_net + ua_hash
 * ---------------------------------------------------------------------------------------
 * SPEC §5 makes this a contract, and it is worth understanding what it buys and what it
 * costs, because both matter to the verdicts downstream.
 *
 * It buys: a rotating-proxy fleet that changes its exit address WITHIN a netblock still
 * lands in one session, and a household behind one NAT is not merged into one visitor as
 * long as the devices differ (different UA → different key).
 *
 * It costs: two people behind the same /24 running the same browser version are one
 * session. On a corporate NAT or a carrier-grade NAT that is common, and the honest
 * consequence is that some sessions are two humans stitched together. This is why the
 * fingerprint-cluster signal counts distinct IPs rather than distinct sessions — the
 * session key deliberately merges, the cluster metric deliberately does not.
 *
 * ---------------------------------------------------------------------------------------
 * THE RUNNING AGGREGATE — why the scorer never re-reads the hits core
 * ---------------------------------------------------------------------------------------
 * Everything the scoring rules need about a session is accumulated here, in SQLite, while
 * the session is open: counts, status classes, gap statistics, the path set, the identity
 * fields from the first hit. When the session closes, the scorer has the whole picture
 * without issuing a single query against `hits`.
 *
 * That is not an optimisation, it is the only design that scales: the alternative is one
 * Solr query per closed session, and a site closing 20k sessions an hour would spend its
 * entire query budget re-reading data it had in memory sixty seconds earlier. The one
 * query the scorer does make is the fingerprint facet (SPEC §5 step 3), which is a
 * cross-session question and genuinely cannot be answered locally.
 *
 * ---------------------------------------------------------------------------------------
 * DEPENDENCY ON src/State.php
 * ---------------------------------------------------------------------------------------
 * This class drives the `sessions_open` table through seven State methods and nothing else:
 *
 *   findOpenSession(string $clientKey, int $idleSec, int $nowMs): ?array
 *   openSession(string $clientKey, int $firstTsMs, ?string $host, array $data): string
 *   updateSession(string $sessionId, int $lastTsMs, int $hitsDelta, ?array $data): void
 *   listIdleSessions(int $idleSec, int $nowMs, int $limit): array
 *   listDirtyOpenSessions(int $limit): array
 *   markSessionsScored(array $marks): void
 *   closeSession(string $sessionId): void
 *
 * Two things about that interface are worth knowing because they shape the code below.
 *
 * TIMESTAMPS ARE EPOCH MILLISECONDS throughout State. Hits arrive with second resolution
 * from most log formats and microsecond resolution from a few, so everything here converts
 * once, on entry, and stays in milliseconds until finalise() hands seconds back to the
 * document builder.
 *
 * IDLENESS IS MEASURED AGAINST THE HIT'S OWN TIMESTAMP, not the wall clock: findOpenSession
 * takes the "now" to compare against as an argument. That is what makes replaying a
 * historical log produce exactly the sessions it would have produced live — a property
 * worth protecting, because without it a backlog import silently merges a week of traffic
 * into one session per visitor.
 *
 * The running aggregate is stored in the row's `data` JSON blob. Nothing outside this class
 * interprets it.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound;

use Loghound\Score\Signals;

final class Sessionizer
{
    /**
     * Hard cap on the distinct-path set held per open session.
     *
     * A crawler walking a large site would otherwise accumulate an unbounded set in SQLite
     * and in memory. Above this, uniq_paths_i SATURATES at the cap — it stops being an
     * exact count and becomes "at least this many". docs/SCHEMA.md says so, and no scoring
     * rule uses uniq_paths_i as a threshold anywhere near this number, so the saturation
     * cannot change a verdict.
     */
    private const MAX_TRACKED_PATHS = 10000;

    /** Cap on the request-URI set used for repeat/conditional-request detection. */
    private const MAX_TRACKED_URIS = 5000;

    /**
     * Byte budget for the KEYS of one tracked set, on top of the entry count above.
     *
     * THE ENTRY CAPS ALONE ARE NOT A BOUND, and that is a denial of service rather than an
     * untidiness. Every key is a string an attacker chose: `path_s` is capped at MAX_TEXT
     * (2048 characters) and a URI is a path plus its query string, so ten thousand paths and
     * five thousand URIs are bounded at roughly 39 MB of live keys — and the whole aggregate
     * is json_decode'd, mutated and json_encode'd into SQLite ON EVERY HIT of that session.
     * Measured on a saturated blob: 38.8 MB, 0.074 s to decode, 131 MB peak, and on PHP's
     * stock 128 MB memory_limit the decode is fatal. One client owns one session (the key is
     * the /24 plus the User-Agent hash), so fifteen thousand requests with long distinct
     * paths is the whole attack, after which every further line from that client costs tens
     * of megabytes of work or kills the daemon.
     *
     * A quarter of a megabyte per set is far more than any real session reaches and is small
     * enough that the per-hit round trip stays in microseconds. Hitting it saturates the set
     * exactly as the entry cap does: counting stops, `paths_saturated` is raised, and
     * uniq_paths_i becomes "at least this many" — which docs/SCHEMA.md already documents and
     * which no scoring rule reads as an exact figure.
     */
    private const MAX_TRACKED_KEY_BYTES = 262144;

    /**
     * Cap on the inter-request gap list retained per session.
     *
     * The gap statistics (median, stddev) only need a representative sample; keeping every
     * gap of a 200k-request crawl would put a megabyte of integers in one SQLite row. The
     * first N gaps are kept because a scripted client's rhythm is established immediately,
     * and because a truncated sample is honest in a way a reservoir sample is not (it is
     * "the first N", not "a sample we hope is representative").
     */
    private const MAX_TRACKED_GAPS = 2000;

    /** Number of paths copied onto the session document (SPEC §4.2: capped at 50). */
    public const PATHS_ON_DOC = 50;

    /**
     * Distinct attack codes tracked per session.
     *
     * A hard bound rather than a guess: Score\Attacks defines a CLOSED vocabulary, so a real
     * session can never exceed its size, and anything past that is a corrupted aggregate or a
     * forged hit rather than a finding. Set above the table's current size so adding a rule
     * does not silently start truncating; the cost of the bound is one comparison per hit.
     */
    private const MAX_TRACKED_FLAGS = 64;

    /** @var object The State instance; see the interface assumptions in the class docblock. */
    private object $state;

    /** Idle timeout in seconds before a session is considered closed. */
    private int $idleSeconds;

    /** privacy.ip_mode — needed for the daily-salted visitor hash. */
    private string $ipMode;

    /** privacy.ip_salt. */
    private string $ipSalt;

    /** The hostname this installation's panel is published at; '' before setup. */
    private string $selfHost;

    /**
     * The paths under that hostname that belong to Loghound itself.
     *
     * @var array<int,string>
     */
    private array $selfPaths;

    /** This installation's collector path, handed to Signals::classifyRequest(); '' before setup. */
    private string $selfCollector;

    /**
     * The idle timeout is SPEC §5's 30 minutes, configurable, and clamped to something sane
     * at both ends: a 5-second timeout would turn every page load into its own session, and
     * a 24-hour one would merge a week of a NAT's traffic into a single unusable document.
     *
     * `base_url` is read for one reason: the session aggregate must be able to tell Loghound's
     * own beacon script and collector apart from the traffic it is measuring, and it has to be
     * able to do so for a hit that did not come through Parser. Config::selfEndpoints() is the
     * single derivation, shared with bin/loghound-tail, so the two cannot disagree about what
     * "ours" means.
     *
     * @param object              $state The State instance (src/State.php).
     * @param array<string,mixed> $cfg   Full config array, or at least the ingest/privacy
     *                                   sections.
     */
    public function __construct(object $state, array $cfg = [])
    {
        $this->state = $state;

        $this->idleSeconds = Security::clampInt(
            $cfg['ingest']['session_idle_sec'] ?? 1800,
            60,
            86400,
            1800
        );

        $this->ipMode = (string) ($cfg['privacy']['ip_mode'] ?? 'full');
        $this->ipSalt = (string) ($cfg['privacy']['ip_salt'] ?? '');

        $own = Config::selfEndpoints((string) ($cfg['base_url'] ?? ''));
        $this->selfHost      = (string) $own['host'];
        $this->selfPaths     = (array) $own['paths'];
        $this->selfCollector = (string) $own['collector'];
    }

    /**
     * Is this hit Loghound's own instrumentation rather than the measured site's traffic?
     *
     * Parser has usually answered this already and left `_self_b` on the hit, and its answer is
     * taken as final — it had the source's vhost override in hand at the time. The fallback
     * re-runs the SAME comparison, Parser::isOwnRequest(), for a hit that reached the sessioniser
     * by another route: a replay tool, or the test harness, neither of which goes through Parser.
     * One implementation, two entry points, so there is nothing to drift.
     *
     * @param array<string,mixed> $hit
     */
    private function isSelfRequest(array $hit): bool
    {
        if (array_key_exists('_self_b', $hit)) {
            return (bool) $hit['_self_b'];
        }

        return Parser::isOwnRequest(
            isset($hit['host_s']) ? (string) $hit['host_s'] : null,
            (string) ($hit['path_s'] ?? ''),
            $this->selfHost,
            $this->selfPaths
        );
    }

    /**
     * Assign a hit to a session, updating the running aggregate.
     *
     * Returns the hit with session_id_s, session_seq_i, fp_hash_s and visitor_s filled in.
     * The caller (bin/loghound-tail) then indexes the returned document.
     *
     * A hit with no usable timestamp cannot be sessionised or ordered, and is refused.
     * Substituting time() instead would place a replayed backlog in the present and corrupt
     * every gap statistic in the batch.
     *
     * fp_hash_s is taken from the hit, not recomputed. Parser.php already derives it from the
     * header tuple and correctly leaves it ABSENT when the format logs no headers at all;
     * recomputing here would be a second implementation of the same contract and the two
     * would drift. The fallback exists only for a hit that did not come through the parser,
     * such as one from a test harness or a replay tool. kind_s is handled the same way: it is
     * normally set by Parser.php, and when it is not it is derived through Signals, because
     * the html/asset/beacon distinction is a detection decision that drives asset_ratio_f and
     * the page count rather than a parsing detail.
     *
     * State decides what "open" means: it looks for a row on this client_key whose last_ts is
     * within the idle window of the instant we pass in. Passing the HIT's instant rather than
     * the wall clock is what makes a historical replay produce the same sessions it would
     * have produced live. The update passes hitsDelta=1 to keep State's own counter in step
     * with the aggregate's, and last_ts is advanced with MAX() inside State, so an
     * out-of-order line cannot rewind a session.
     *
     * LOGHOUND'S OWN BEACON AND COLLECTOR TAKE A SEPARATE PATH THROUGH HERE, and it differs in
     * three ways. They never OPEN a session: a session built out of nothing but instrumentation
     * would carry hits_i 0, pages_i 0 and no entry path, and publishing that would be inventing
     * a visit out of the act of measuring one. They join a session that is already open, and
     * outside one they are simply a hit document with no session_id_s. They are folded by
     * accumulateSelf(), which counts none of the traffic metrics — that method carries the full
     * reasoning, including why the hit is still indexed. And they pass hitsDelta 0 to State, so
     * its counter stays in step with the aggregate's, while still advancing last_ts: the client
     * demonstrably was still there, and the gap series is protected separately, by measuring
     * from the previous COUNTED hit. They carry no session_seq_i, because there is no position
     * among the counted hits to give them.
     *
     * The classification fallback is handed `_beacon_path` for a related reason. It has always
     * been able to honour a configured collector and has never been told one, so a hit that
     * skipped Parser was classified by extension — and the shipped collector ends in `.php`,
     * which made it an HTML PAGEVIEW. The path comes from Config::selfEndpoints(), like
     * everything else here, and is set on a copy so the key never travels on the returned hit.
     *
     * @param array<string,mixed> $hit A normalised hit from Parser.php.
     * @return array<string,mixed>
     */
    public function assign(array $hit): array
    {
        $tsMs = self::hitMillis($hit);
        if ($tsMs <= 0) {
            throw new \InvalidArgumentException('Sessionizer: hit has no usable timestamp.');
        }

        if (!isset($hit['fp_hash_s'])) {
            $hit['fp_hash_s'] = Signals::fingerprint($hit);
        }
        if (!isset($hit['visitor_s'])) {
            $hit['visitor_s'] = Signals::visitorHash($hit, $this->ipMode, $this->ipSalt);
        }

        if (!isset($hit['kind_s'])) {
            $probe = $hit;
            if (!isset($probe['_beacon_path']) && $this->selfCollector !== '') {
                $probe['_beacon_path'] = $this->selfCollector;
            }
            $classified = Signals::classifyRequest($probe);
            $hit['kind_s'] = $classified['kind_s'];
            if (isset($classified['asset_kind_s'])) {
                $hit['asset_kind_s'] = $classified['asset_kind_s'];
            }
        }

        $clientKey = self::clientKey($hit);
        $isSelf    = $this->isSelfRequest($hit);

        $row = $this->state->findOpenSession($clientKey, $this->idleSeconds, $tsMs);

        if ($row === null && $isSelf) {
            return $hit;
        }

        if ($row === null) {
            $agg = $this->newAggregate($hit);
            $sessionId = $this->state->openSession(
                $clientKey,
                $tsMs,
                isset($hit['host_s']) ? (string) $hit['host_s'] : null,
                $agg
            );
            $row = [
                'session_id' => $sessionId,
                'client_key' => $clientKey,
                'first_ts'   => $tsMs,
                'last_ts'    => $tsMs,
                'hits'       => 0,
                'data'       => $agg,
            ];
        }

        if ($isSelf) {
            $agg = self::accumulateSelf((array) $row['data'], $hit);
            $this->state->updateSession((string) $row['session_id'], $tsMs, 0, $agg);

            $hit['session_id_s'] = (string) $row['session_id'];

            return $hit;
        }

        $agg = $this->accumulate((array) $row['data'], $hit, $tsMs, (int) $row['last_ts']);

        $this->state->updateSession((string) $row['session_id'], $tsMs, 1, $agg);

        $hit['session_id_s']  = (string) $row['session_id'];
        $hit['session_seq_i'] = (int) $agg['hits'];

        return $hit;
    }

    /**
     * Close every session that has been idle longer than the timeout.
     *
     * Each row is marked closed in State before it is returned, so a subsequent run cannot
     * pick it up again and write its document twice. The row itself is kept (State purges
     * it later) so a beacon arriving seconds after the close can still be matched.
     *
     * @param int $nowMs Epoch MILLISECONDS to measure idleness against.
     * @param int $limit Batch size, so one run cannot pull an unbounded backlog into memory.
     * @return array<int,array<string,mixed>> Session aggregates ready for scoring.
     */
    public function closeIdle(int $nowMs, int $limit = 500): array
    {
        $rows = $this->state->listIdleSessions($this->idleSeconds, $nowMs, $limit);

        $out = [];
        foreach ($rows as $row) {
            $this->state->closeSession((string) $row['session_id']);
            $out[] = $this->finalise($row);
        }
        return $out;
    }

    /**
     * The OPEN sessions that need a provisional document, finalised the same way a closed one is.
     *
     * Same shape as closeIdle()'s return value on purpose: the scorer builds one document from
     * it through the same buildSessionDoc(), so there is no second definition of what a session
     * document contains and no way for the two to drift. The difference is entirely in what the
     * scorer does with it — it marks the document provisional, scores it under the provisional
     * gate, and does NOT close the row.
     *
     * Nothing here is mutated in State. The row stays open, the beacon rows stay unmerged, and
     * markProvisional() is called only after the documents are safely in Solr, for the same
     * reason the beacon rows are: a failed index must leave the session looking unpublished, so
     * the next run tries again.
     *
     * Sessions that closeIdle() has already taken in this run are excluded automatically,
     * because it stamps closed_at before returning them — which is why the scorer must call it
     * first.
     *
     * @param int $limit Batch size, bounding the cost of one run.
     * @return array<int,array<string,mixed>> Session aggregates, ready for scoring.
     */
    public function listOpen(int $limit = 500): array
    {
        $out = [];
        foreach ($this->state->listDirtyOpenSessions($limit) as $row) {
            $out[] = $this->finalise($row);
        }
        return $out;
    }

    /**
     * Record that these open sessions have been published, so they are not republished unchanged.
     *
     * `ts_end_ms` is the instant that was actually published, which is what makes the dirty
     * check exact: a hit that arrived while the run was in flight leaves the session dirty.
     *
     * @param array<int,array<string,mixed>> $sessions Aggregates from listOpen().
     */
    public function markProvisional(array $sessions): void
    {
        $marks = [];
        foreach ($sessions as $session) {
            $sid = (string) ($session['session_id'] ?? '');
            if ($sid === '') {
                continue;
            }
            $marks[$sid] = (int) ($session['ts_end_ms'] ?? 0);
        }
        $this->state->markSessionsScored($marks);
    }

    /**
     * Close every open session regardless of idleness.
     *
     * Used on a clean shutdown, so a restart does not strand half a day of open sessions in
     * SQLite, and by the test harness after replaying a fixture. Expressed as "idle for -1
     * seconds as of the far future" rather than a separate State method, which keeps the
     * State interface to the five calls documented at the top of this file.
     *
     * Draining is paged, because listIdleSessions clamps its own limit to 5000 and asking
     * for an unbounded batch would silently get the first 5000 and leave the rest open.
     *
     * @return array<int,array<string,mixed>>
     */
    public function closeAll(): array
    {
        $out = [];
        while (true) {
            $rows = $this->state->listIdleSessions(0, PHP_INT_MAX, 5000);
            if ($rows === []) {
                break;
            }
            foreach ($rows as $row) {
                $this->state->closeSession((string) $row['session_id']);
                $out[] = $this->finalise($row);
            }
        }
        return $out;
    }

    /**
     * Extract the hit's instant in epoch milliseconds.
     *
     * Parser.php writes `ts` as the Solr string and exposes Parser::epochMs() to convert it,
     * deliberately not smuggling a private numeric key onto the document (which would then
     * have to be stripped before indexing). `_ts_ms` and `_ts_unix` are accepted as
     * overrides so a replay tool or a test harness can supply the instant directly.
     *
     * @param array<string,mixed> $hit
     */
    public static function hitMillis(array $hit): int
    {
        if (isset($hit['_ts_ms'])) {
            return (int) $hit['_ts_ms'];
        }
        if (isset($hit['_ts_unix'])) {
            return ((int) $hit['_ts_unix']) * 1000;
        }
        if (isset($hit['ts']) && class_exists(Parser::class)) {
            return Parser::epochMs((string) $hit['ts']);
        }
        return 0;
    }

    /**
     * The sessionisation key: network prefix plus User-Agent hash.
     *
     * ip_net_s is expected to already be present (Parser/Enrich computes it with
     * Security::ipNetwork). When it is missing — an un-enriched hit, or a malformed
     * address — fall back to the raw address so the hit still lands in SOME session rather
     * than being dropped. A session is a grouping, not an assertion, so a degraded key is
     * better than no session at all.
     *
     * @param array<string,mixed> $hit
     */
    public static function clientKey(array $hit): string
    {
        $net = (string) ($hit['ip_net_s'] ?? ($hit['ip_s'] ?? '-'));
        $ua  = (string) ($hit['ua_hash_s'] ?? sha1((string) ($hit['ua_s'] ?? '')));
        return $net . '|' . $ua;
    }

    /**
     * Create the empty running aggregate for a new session.
     *
     * The session id itself is minted by State::openSession() as
     * sha1(client_key + first_ts + random), per SPEC §5. The random component is what stops
     * the id from being guessable: without it, anyone who knows a visitor's netblock and
     * User-Agent could compute their session id and forge beacon payloads for it, since the
     * beacon HMAC is bound to the session id.
     *
     * The aggregate's shape, and why each part of it exists:
     *
     * Favicons are counted separately from assets because SPEC §4.1 gives favicon its own
     * kind_s, but a favicon is unquestionably a sub-resource the renderer fetched, so the
     * no_assets rule and asset_ratio_f both have to include it — a session that pulled the
     * favicon did not "fetch nothing but the markup".
     *
     * Distinct paths are tracked as a path => 1 map, bounded by MAX_TRACKED_PATHS. Alongside
     * it, the full request target (path plus query) is counted as target => times seen, for
     * repeat detection, and a running count is kept of how many distinct SUB-RESOURCE URIs
     * were fetched more than once. Sub-resources only: re-navigating to the same page is
     * completely normal behaviour and says nothing about the client's HTTP cache.
     *
     * Inter-request gaps are accumulated in milliseconds, measured between COUNTED hits, which
     * is what `last_counted_ms` is for: a beacon heartbeat lands in the middle of a visit and
     * must not become the point the next real request's gap is measured from.
     *
     * `own_hits` and `own_assets` are the only trace Loghound's own instrumentation leaves in
     * the aggregate. They are not traffic and are excluded from every count above. `own_assets`
     * has one reader, Rules::ruleNoAssets(), which needs to tell "this client fetched nothing"
     * from "this client fetched only the thing we told it to fetch" — opposite verdicts.
     * `own_hits` is the total, and it is kept because `own_assets` alone cannot distinguish "no
     * instrumentation fired in this session" from "it fired and none of it was a sub-resource":
     * the collector is a POST, not an asset. Neither is a document field.
     *
     * The identity, network and client fields are lifted from the FIRST hit. The first is the
     * right choice rather than the last: it carries the external referer and the entry
     * conditions, and a session whose UA changes mid-way is already a different client_key.
     *
     * @param array<string,mixed> $hit
     * @return array<string,mixed>
     */
    private function newAggregate(array $hit): array
    {
        return [
                'hits'       => 0,
                'pages'      => 0,
                'assets'     => 0,
                'favicons'   => 0,
                'beacons'    => 0,
                'bytes'      => 0,
                'st2'        => 0,
                'st3'        => 0,
                'st4'        => 0,
                'st5'        => 0,
                'got_304'    => false,
                'html_200'   => false,
                'entry_path' => null,
                'exit_path'  => null,
                'paths'      => [],
                'paths_bytes' => 0,
                'paths_saturated' => false,
                'uris'          => [],
                'uris_bytes'    => 0,
                'repeat_assets' => 0,
                'gaps'       => [],
                'last_counted_ms' => 0,
                'own_hits'   => 0,
                'own_assets' => 0,
                'terms'      => [],
                'atk_flags'  => [],
                'atk_rules'  => null,
                'first'      => self::identityOf($hit),
        ];
    }

    /**
     * Fold one of Loghound's OWN requests into the aggregate.
     *
     * KEEP AND EXCLUDE, NOT DROP AT INGEST — the decision this whole path exists to express,
     * and the reasoning is worth stating once here rather than being rediscovered later.
     *
     * The hit document is still written to the `hits` core. It really was served, and the
     * transport plane is the record of what the webserver did; erasing a request from it to
     * tidy up a chart is the same class of dishonesty as inventing one. It is also the only
     * answer to the first question every new installation asks — "is my beacon actually
     * reaching the collector?" — which becomes unanswerable from the data the moment those
     * lines are thrown away at ingest.
     *
     * What it is excluded from is the SESSION, because the session is where the numbers a
     * person reads are computed, and Loghound's own instrumentation is not the measured site's
     * traffic. So this counts nothing: not `hits`, so `asset_ratio` keeps an honest denominator
     * and `hits_i` an honest total; not `pages`, `assets`, `favicons` or `beacons`; not `bytes`
     * or the status classes; not `paths`, which is what Overview's Top pages facets and the
     * defect that started this; not `uris`, so a repeated beacon cannot masquerade as a client
     * with no HTTP cache; and not the inter-request gaps, which is why the gap is measured from
     * `last_counted_ms` rather than from the session's last_ts.
     *
     * The two things it does record are `own_hits` and `own_assets`. They are aggregate-only —
     * finalise() carries them to the scorer and bin/loghound-score puts neither on a document —
     * and `own_assets` exists to defuse exactly one regression: `no_assets` fires on an HTML 200
     * with no sub-resources, and a visitor whose only sub-resource was `/b.js` would newly score
     * 25 bot points for having loaded the script Loghound itself asked their browser to load.
     * Rules::ruleNoAssets() reads it and stays silent. Suppressing a rule is the conservative
     * direction: it can only make a session look more human, never less.
     *
     * @param array<string,mixed> $agg
     * @param array<string,mixed> $hit
     * @return array<string,mixed>
     */
    private static function accumulateSelf(array $agg, array $hit): array
    {
        $agg['own_hits'] = (int) ($agg['own_hits'] ?? 0) + 1;

        $kind = (string) ($hit['kind_s'] ?? 'other');
        if ($kind === 'asset' || $kind === 'favicon') {
            $agg['own_assets'] = (int) ($agg['own_assets'] ?? 0) + 1;
        }

        return $agg;
    }

    /**
     * Fold one hit into the running aggregate.
     *
     * The inter-request gap is computed BEFORE the hit counter is incremented, so the first
     * hit of a session contributes no gap — there is nothing to measure it from. It is
     * floored at zero, because a log file can contain out-of-order lines, two Apache worker
     * processes flushing within the same second, and a negative gap would poison the standard
     * deviation that the periodic_timing rule reads.
     *
     * Page counting deliberately EXCLUDES beacon requests. An analytics beacon is a
     * sub-resource fired by a page, and counting it as a second pageview would make every
     * single-page visit look like a two-page one, silently disarming the single_page_10s rule
     * on exactly the traffic it exists to catch.
     *
     * A 304 is counted because it is the evidence that the client sent a conditional request,
     * an If-None-Match or an If-Modified-Since. Real browsers with a warm cache do this
     * constantly; most scripted clients never do.
     *
     * The distinct-path counter saturates rather than growing without bound, and so does the
     * distinct-search-term set. Terms are a UNION across the session rather than a first-hit
     * copy, because a visitor who searches three times searched three times and the session is
     * the thing that did it; taking only the first would answer "what did people search for"
     * with the entry query and call it the visit.
     *
     * Repeat-request detection, which feeds the no_304_on_repeat rule, involves two decisions
     * that were made against the real human fixture rather than from first principles. It
     * keys on the FULL request target, path AND query, not on path_s: a cache-busted asset
     * (/app.css?a=1832196438) is a different URL on every deploy, so the browser has nothing
     * to revalidate and legitimately never sends a conditional request — keying on path_s
     * alone would see "/app.css fetched twice, no 304" and fire on a completely normal human,
     * and it does exactly that, twice, in tests/fixtures/apache_combined_human.log. And it
     * counts SUB-RESOURCES only, because re-navigating to the same page or polling a status
     * endpoint is ordinary human behaviour, and pages are frequently served no-store, so an
     * HTML repeat carries no information about the client's cache. A repeated URI is counted
     * once however many times it repeats: three fetches of one file is one piece of evidence,
     * not two.
     *
     * The gap is measured from the previous COUNTED hit, not from the session's last_ts. Those
     * differ whenever Loghound's own beacon fired in between — accumulateSelf() records nothing
     * but still lets the session's last_ts advance, because the client demonstrably was still
     * there — and measuring from the beacon would replace the site's request rhythm, which is
     * what periodic_timing reads, with Loghound's own heartbeat interval. `last_counted_ms`
     * falls back to last_ts for an aggregate written before it existed, so a session that was
     * open across an upgrade finishes correctly instead of producing one absurd gap.
     *
     * @param array<string,mixed> $agg    The aggregate so far (State's `data` blob).
     * @param array<string,mixed> $hit
     * @param int                 $tsMs   This hit's instant, epoch milliseconds.
     * @param int                 $lastMs The session's previous last_ts, epoch milliseconds.
     * @return array<string,mixed>
     */
    private function accumulate(array $agg, array $hit, int $tsMs, int $lastMs): array
    {
        if (($agg['hits'] ?? 0) > 0) {
            $prevMs = (int) ($agg['last_counted_ms'] ?? 0);
            $gapMs  = max(0, $tsMs - ($prevMs > 0 ? $prevMs : $lastMs));
            if (count($agg['gaps']) < self::MAX_TRACKED_GAPS) {
                $agg['gaps'][] = $gapMs;
            }
        }

        $agg['last_counted_ms'] = $tsMs;
        $agg['hits']++;

        $kind   = (string) ($hit['kind_s'] ?? 'other');
        $status = (int) ($hit['status_i'] ?? 0);
        $path   = (string) ($hit['path_s'] ?? '');

        if ($kind === 'html') {
            $agg['pages']++;
            if ($status === 200) {
                $agg['html_200'] = true;
            }
            if ($agg['entry_path'] === null) {
                $agg['entry_path'] = $path;
            }
            $agg['exit_path'] = $path;
        } elseif ($kind === 'asset') {
            $agg['assets']++;
        } elseif ($kind === 'favicon') {
            $agg['favicons']++;
        } elseif ($kind === 'beacon') {
            $agg['beacons']++;
        }

        $agg['bytes'] += max(0, (int) ($hit['bytes_l'] ?? 0));

        if ($status >= 200 && $status < 300) {
            $agg['st2']++;
        } elseif ($status >= 300 && $status < 400) {
            $agg['st3']++;
            if ($status === 304) {
                $agg['got_304'] = true;
            }
        } elseif ($status >= 400 && $status < 500) {
            $agg['st4']++;
        } elseif ($status >= 500) {
            $agg['st5']++;
        }

        if ($path !== '') {
            if (isset($agg['paths'][$path])) {
                $agg['paths'][$path]++;
            } elseif (count($agg['paths']) < self::MAX_TRACKED_PATHS
                && (int) ($agg['paths_bytes'] ?? 0) + strlen($path) <= self::MAX_TRACKED_KEY_BYTES
            ) {
                $agg['paths'][$path] = 1;
                $agg['paths_bytes'] = (int) ($agg['paths_bytes'] ?? 0) + strlen($path);
            } else {
                $agg['paths_saturated'] = true;
            }
        }

        foreach ((array) ($hit['search_terms_ss'] ?? []) as $term) {
            if (!is_string($term) || $term === '' || isset($agg['terms'][$term])) {
                continue;
            }
            if (count($agg['terms'] ?? []) >= Beacon::MAX_SESSION_TERMS) {
                break;
            }
            $agg['terms'][$term] = 1;
        }

        if (isset($hit['hit_rules_i']) && is_numeric($hit['hit_rules_i'])) {
            $agg['atk_rules'] = (int) $hit['hit_rules_i'];
        }

        foreach ((array) ($hit['hit_flags_ss'] ?? []) as $flag) {
            if (!is_string($flag) || $flag === '' || isset($agg['atk_flags'][$flag])) {
                continue;
            }
            if (count((array) ($agg['atk_flags'] ?? [])) >= self::MAX_TRACKED_FLAGS) {
                break;
            }
            $agg['atk_flags'][$flag] = 1;
        }

        $uri = $path . (isset($hit['query_s']) && $hit['query_s'] !== '' ? '?' . $hit['query_s'] : '');
        if ($uri !== '' && ($kind === 'asset' || $kind === 'favicon')) {
            if (isset($agg['uris'][$uri])) {
                if ($agg['uris'][$uri] === 1) {
                    $agg['repeat_assets']++;
                }
                $agg['uris'][$uri]++;
            } elseif (count($agg['uris']) < self::MAX_TRACKED_URIS
                && (int) ($agg['uris_bytes'] ?? 0) + strlen($uri) <= self::MAX_TRACKED_KEY_BYTES
            ) {
                $agg['uris'][$uri] = 1;
                $agg['uris_bytes'] = (int) ($agg['uris_bytes'] ?? 0) + strlen($uri);
            }
        }

        return $agg;
    }

    /**
     * Copy the identity, network and client fields that the session document carries.
     *
     * Only fields that are actually PRESENT are copied. An absent field stays absent all
     * the way to Solr — SPEC §1 forbids fabricating a metric, and an enrichment that failed
     * must be visibly missing rather than quietly defaulted.
     *
     * `_logged` is carried across too, and it is not a document field. It is the list of
     * header fields the compiled log format can produce, and the ONLY way to tell "the
     * browser did not send Sec-CH-UA" from "the operator does not log Sec-CH-UA". Two rules
     * worth 70+ points depend on that distinction, so it has to travel with the session;
     * bin/loghound-score strips every underscore-prefixed key before indexing.
     *
     * @param array<string,mixed> $hit
     * @return array<string,mixed>
     */
    private static function identityOf(array $hit): array
    {
        $fields = [
            'host_s', 'src_s',
            'ip_s', 'ip_ver_i', 'ip_net_s',
            'asn_i', 'as_org_s', 'as_type_s', 'netname_s', 'rdns_s', 'rdns_ok_b',
            'country_s', 'region_s', 'city_s', 'geo_p', 'tz_s',
            'proto_s',
            'ua_s', 'ua_hash_s', 'browser_s', 'browser_ver_i', 'os_s', 'device_s',
            'ua_bot_b', 'ua_bot_name_s', 'ua_bot_cat_s', 'ai_crawler_b',
            'referer_s', 'referer_host_s', 'referer_type_s',
            'accept_s', 'accept_lang_s', 'accept_enc_s',
            'sec_ch_ua_s', 'sec_ch_platform_s', 'sec_ch_mobile_b',
            'sec_fetch_site_s', 'sec_fetch_mode_s', 'sec_fetch_dest_s', 'sec_fetch_user_s',
            'tls_proto_s', 'tls_cipher_s',
            'fp_hash_s', 'visitor_s',

            '_logged',
        ];

        $out = [];
        foreach ($fields as $f) {
            if (array_key_exists($f, $hit) && $hit[$f] !== null && $hit[$f] !== '') {
                $out[$f] = $hit[$f];
            }
        }
        return $out;
    }

    /**
     * Turn a closed open-session row into the aggregate the scorer consumes.
     *
     * This is where derived numbers are computed once, rather than in each of the rules
     * that wants them.
     *
     * State hydrates `data` into an array, and a raw JSON string is tolerated as well, so a
     * row read by some other tool still finalises.
     *
     * State stores epoch MILLISECONDS, so log_span_ms is an exact difference, while
     * ts_start and ts_end are handed back in SECONDS because that is what the document
     * builder formats into a Solr instant.
     *
     * Two path numbers come out of this: the true distinct count, saturating at
     * MAX_TRACKED_PATHS, and the capped sample that goes onto the document. SPEC §4.2 caps
     * paths_ss at 50, and uniq_paths_i carries the real number, so nothing is lost except
     * the ability to enumerate — and the UI must label the list a sample.
     *
     * `own_hits` and `own_assets` travel to the scorer and stop there. bin/loghound-score puts
     * neither on a session document, deliberately: they are not facts about the visit, they are
     * facts about Loghound's instrumentation of it, and the sessions schema has no field for
     * them. `own_assets` has exactly one reader, Rules::ruleNoAssets().
     *
     * Sub-resources are assets plus favicons. The favicon has its own kind_s in the schema
     * but it is still something the renderer went and fetched, so it belongs on this side of
     * the ratio. asset_ratio_f is then sub-resources as a fraction of ALL hits: a browser
     * rendering a page pulls CSS, JS, fonts and images, while a client that fetches only HTML
     * has a ratio of 0. Dividing by total hits rather than by pages is what makes a
     * single-page visit with ten assets and a ten-page crawl with none comparable numbers.
     *
     * The gap statistics are computed here so that every rule reads the same numbers and the
     * session document carries them for the forensics view.
     *
     * @param array<string,mixed> $row
     * @return array<string,mixed>
     */
    private function finalise(array $row): array
    {
        $agg = $row['data'] ?? [];
        if (!is_array($agg)) {
            $agg = (array) json_decode((string) $agg, true);
        }

        $firstMs = (int) $row['first_ts'];
        $lastMs  = (int) $row['last_ts'];
        $gaps    = array_map('intval', (array) ($agg['gaps'] ?? []));

        $paths = array_keys((array) ($agg['paths'] ?? []));

        $out = [
            'session_id'   => (string) $row['session_id'],
            'client_key'   => (string) $row['client_key'],
            'ts_start'     => intdiv($firstMs, 1000),
            'ts_end'       => intdiv($lastMs, 1000),
            'ts_start_ms'  => $firstMs,
            'ts_end_ms'    => $lastMs,
            'log_span_ms'  => max(0, $lastMs - $firstMs),

            'hits'         => (int) ($agg['hits'] ?? 0),
            'pages'        => (int) ($agg['pages'] ?? 0),
            'assets'       => (int) ($agg['assets'] ?? 0),
            'favicons'     => (int) ($agg['favicons'] ?? 0),
            'beacons'      => (int) ($agg['beacons'] ?? 0),
            'bytes'        => (int) ($agg['bytes'] ?? 0),

            'st2'          => (int) ($agg['st2'] ?? 0),
            'st3'          => (int) ($agg['st3'] ?? 0),
            'st4'          => (int) ($agg['st4'] ?? 0),
            'st5'          => (int) ($agg['st5'] ?? 0),
            'got_304'      => (bool) ($agg['got_304'] ?? false),
            'html_200'     => (bool) ($agg['html_200'] ?? false),

            'entry_path'   => $agg['entry_path'] ?? null,
            'exit_path'    => $agg['exit_path'] ?? null,
            'uniq_paths'   => count($paths),
            'paths_saturated' => (bool) ($agg['paths_saturated'] ?? false),
            'paths'        => array_slice($paths, 0, self::PATHS_ON_DOC),

            'repeat_assets' => (int) ($agg['repeat_assets'] ?? 0),
            'own_hits'     => (int) ($agg['own_hits'] ?? 0),
            'own_assets'   => (int) ($agg['own_assets'] ?? 0),
            'gaps'         => $gaps,
            'terms'        => self::sortedTerms($agg['terms'] ?? []),

            /* THE UNION OF WHAT ITS HITS MATCHED, and the version that judged them. Sorted for
               the same reason terms are: an open session is republished on every scorer run, and
               a set whose order drifted would rewrite the document for input that had not
               changed. `atk_rules` stays NULL when no hit in the session carried a version,
               which is the honest reading of a session assembled by a tailer that predates the
               detector — the document then carries no version either, and the Attacks view
               counts it as unevaluated rather than as clean. */
            'atk_flags'    => self::sortedFlags($agg['atk_flags'] ?? []),
            'atk_rules'    => isset($agg['atk_rules']) && is_numeric($agg['atk_rules'])
                ? (int) $agg['atk_rules']
                : null,

            'first'        => (array) ($agg['first'] ?? []),
        ];

        $out['sub_resources'] = $out['assets'] + $out['favicons'];

        $out['asset_ratio'] = $out['hits'] > 0 ? round($out['sub_resources'] / $out['hits'], 4) : 0.0;

        $out['gap_p50_ms']    = Signals::median($gaps);
        $out['gap_stddev_ms'] = Signals::stddev($gaps);

        return $out;
    }

    /**
     * The session's distinct search terms, in a stable order.
     *
     * Accumulated as a term => 1 map for the same reason paths are — membership is the
     * question, a hash lookup answers it, and the map bounds itself at
     * Beacon::MAX_SESSION_TERMS. Sorted on the way out because an open session is republished
     * on every scorer run and a set whose order drifted would rewrite the document with
     * different content for input that had not changed.
     *
     * @param mixed $terms
     * @return array<int,string>
     */
    /**
     * The session's distinct attack codes, in a stable order.
     *
     * Bounded by the same cap the accumulator applies, so a corrupted aggregate read back out
     * of SQLite cannot put an unbounded list on a document. Sorted for republish stability.
     *
     * @param mixed $flags
     * @return array<int,string>
     */
    private static function sortedFlags($flags): array
    {
        if (!is_array($flags) || $flags === []) {
            return [];
        }
        $list = array_values(array_filter(
            array_map('strval', array_keys($flags)),
            static fn (string $f): bool => $f !== ''
        ));
        sort($list);

        return array_slice($list, 0, self::MAX_TRACKED_FLAGS);
    }

    private static function sortedTerms($terms): array
    {
        if (!is_array($terms) || $terms === []) {
            return [];
        }
        $list = array_values(array_filter(
            array_map('strval', array_keys($terms)),
            static fn (string $t): bool => $t !== ''
        ));
        sort($list);

        return array_slice($list, 0, Beacon::MAX_SESSION_TERMS);
    }
}
