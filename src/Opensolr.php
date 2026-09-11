<?php
/**
 * Loghound — Opensolr managed-backend client.
 *
 * SPEC §9: setup asks one question, "[Opensolr managed] or [my own Solr]". This class is
 * the managed half. It provisions the two indexes, pushes the configset, and reports
 * health, so the operator never has to learn what a configset is.
 *
 * IMPORTANT — this is the CONTROL PLANE, not the data plane. It talks to
 * https://opensolr.com/solr_manager/api, which creates and configures indexes. Documents
 * are never written through here; that is src/Solr.php, which talks directly to the Solr
 * node this class tells it about.
 *
 * ---------------------------------------------------------------------------------------
 * THE API KEY
 * ---------------------------------------------------------------------------------------
 * The Opensolr API key is a full account credential: it can create, reconfigure and DELETE
 * every index on the account, not just Loghound's two. Accordingly:
 *
 *   * it is never echoed, never printed, never written to a log, and never included in an
 *     exception message — see redact() and the way every error path below is built;
 *   * it is sent as a POST field, not a URL query parameter, wherever the endpoint allows
 *     it, so it does not land in an intermediate proxy's access log;
 *   * it lives in config/loghound.php at mode 0640, outside the docroot (SPEC §1).
 *
 * If you add a method here, the test for whether you got this right is simple: grep your
 * new code for the variable holding the key and confirm it only ever reaches a request
 * field.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound;

final class Opensolr
{
    /** Default control-plane base. Overridable in config for staging. */
    /**
     * Most bytes a control-plane response may deliver before it is abandoned.
     *
     * Without one the transport falls back to Solr::MAX_RESPONSE_BYTES — sixty-four megabytes,
     * chosen for a facet response from OUR OWN Solr and far too generous for an API that
     * answers with a JSON object or a configset file. The platform caps an upload at roughly
     * 3.5 MB, so eight is ample for anything legitimate and small enough that a hostile or
     * compromised endpoint cannot drive json_decode(), a regex scan and an array_diff() over a
     * body of its own choosing — work that ends up in var/schema-check.json and is re-read by
     * the panel on every Settings render.
     */
    public const MAX_RESPONSE_BYTES = 8388608;

    /** Longest control-plane message kept for display or logging. */
    public const MAX_MESSAGE = 500;

    public const DEFAULT_API_BASE = 'https://opensolr.com/solr_manager/api';

    private string $apiBase;

    private string $email;

    private string $apiKey;

    private int $timeout;

    /** @var callable Transport, injectable so tests run with no network. */
    private $transport;

    /**
     * The default transport is the Solr client's curl transport, reused rather than
     * reimplemented: identical shape, identical hardening — no redirect following,
     * certificate verification on — and one implementation to audit.
     *
     * @param array<string,mixed> $cfg      The 'opensolr' section of the config.
     * @param callable|null       $transport fn(array $req): array{status:int,body:string,error:string}
     */
    public function __construct(array $cfg, ?callable $transport = null)
    {
        $this->apiBase = rtrim((string) ($cfg['api_base'] ?? self::DEFAULT_API_BASE), '/');
        $this->email   = (string) ($cfg['email'] ?? '');
        $this->apiKey  = (string) ($cfg['api_key'] ?? '');
        $this->timeout = max(5, (int) ($cfg['timeout'] ?? 60));

        $this->transport = $transport ?? [Solr::class, 'curlTransport'];
    }

    /**
     * List the regions (Opensolr calls them environments) available to this account.
     *
     * GET /regions returns a bare JSON array of country codes, e.g. ["FINLAND9","GERMANY9"].
     * The setup wizard shows these; nothing is hardcoded client-side, so a region added by
     * Opensolr appears without a Loghound release.
     *
     * The endpoint returns a list rather than an object, so decode() hands it back under a
     * synthetic key instead of pretending it is a map. Entries are plain strings today; the
     * object form used by /vector_regions is tolerated too, in case the two endpoints
     * converge later.
     *
     * A REFUSAL IS A MAP, AND SOME OF THEM ARRIVE AS HTTP 200, which decode() therefore hands
     * back rather than throwing on. Read as a list, such a map yields no regions at all — so
     * without the explicit check below, an operator with a mistyped key was told "this account
     * has no regions, check that it is active" and sent to look at their account settings,
     * which is a confidently wrong diagnosis of a one-character mistake.
     *
     * @return string[]
     */
    public function listRegions(): array
    {
        $res = $this->call('regions', [], 'GET');

        if (array_key_exists('status', $res) && empty($res['status'])) {
            throw new \RuntimeException(
                'Opensolr refused the request for regions: '
                . $this->redact(self::stringifyMsg($res['msg'] ?? 'no reason given'))
            );
        }

        $list = $res['_list'] ?? [];
        $out = [];
        foreach ((array) $list as $entry) {
            if (is_string($entry)) {
                $out[] = $entry;
            } elseif (is_array($entry) && isset($entry['environment'])) {
                $out[] = (string) $entry['environment'];
            }
        }
        return $out;
    }

    /**
     * List the indexes this account owns.
     *
     * Endpoint: GET /get_index_list, which answers with a bare JSON array of
     * {"index_name": ..., "index_type": ...} objects — so decode() hands it back under the
     * synthetic `_list` key, exactly as /regions does.
     *
     * The index analytics views use this so the account's indexes are DISCOVERED rather
     * than typed: an index name in a config file goes stale the moment one is renamed, and
     * a typed name is indistinguishable from an index the account does not own. The
     * platform also filters this list by the API key's own scope, so a restricted key sees
     * only what it is allowed to see and Loghound inherits that for free.
     *
     * Names that do not match the platform's own [A-Za-z0-9_] index-name rule are dropped
     * rather than returned: the value goes on to become a `core_name` parameter and a
     * select option, and one that could not have been created by the platform did not come
     * from the platform.
     *
     * @return string[] Index names, in the order the platform returned them.
     */
    public function listIndexes(): array
    {
        return array_column($this->listIndexEntries(), 'name');
    }

    /**
     * List the indexes this account owns, keeping the platform's own type marker.
     *
     * Same endpoint and same filtering as listIndexes(), which is a thin wrapper around
     * this. The extra field matters for one question and one only: HOW MANY INDEXES COUNT
     * AGAINST THE PLAN. `index_type` is the platform's `parent_id` — `-1` for a standalone
     * index and `0` for a core belonging to a cluster — and the limit the platform enforces
     * when it refuses a create counts standalone indexes ONLY. Counting the whole list would
     * over-report capacity use on any account that also runs a cluster, and would tell an
     * operator they are full when they are not.
     *
     * The type is carried as the string the platform sent rather than being interpreted
     * here, so a value neither side has seen before travels intact to the one place that
     * makes a decision from it.
     *
     * @return array<int,array{name:string,type:string}>
     */
    public function listIndexEntries(): array
    {
        $res = $this->call('get_index_list', [], 'GET');

        $out = [];
        foreach ((array) ($res['_list'] ?? []) as $entry) {
            $name = is_array($entry) ? ($entry['index_name'] ?? null) : $entry;
            if (!is_string($name) || !Security::isSafeCoreName($name)) {
                continue;
            }
            $type = is_array($entry) ? ($entry['index_type'] ?? '') : '';
            $out[] = [
                'name' => $name,
                'type' => is_scalar($type) ? (string) $type : '',
            ];
        }
        return $out;
    }

    /**
     * The platform's marker for an index that counts against the plan's index limit.
     *
     * `parent_id = -1` is a standalone index. Anything else belongs to a cluster and is not
     * counted by the gate in the platform's create_index.
     */
    public const TYPE_STANDALONE = '-1';

    /**
     * How many indexes on this account count against the plan's index limit.
     *
     * An entry whose type the platform did not send is counted, because the safe direction
     * for a capacity figure is to over-report use: telling an operator they have less room
     * than they do costs them a click, and telling them they have more costs them a
     * half-provisioned install.
     *
     * @param array<int,array{name:string,type:string}> $entries From listIndexEntries().
     */
    public static function countAgainstLimit(array $entries): int
    {
        $n = 0;
        foreach ($entries as $entry) {
            if (($entry['type'] ?? '') === '' || ($entry['type'] ?? '') === self::TYPE_STANDALONE) {
                $n++;
            }
        }
        return $n;
    }

    /**
     * The account's plan allowance and index usage, as the platform itself reports them.
     *
     * Endpoint: GET /get_account_summary?core_name=&signature=&email=&api_key=
     *
     * THIS IS THE AUTHORITY ON HOW MANY INDEXES MAY EXIST, and the three fields it is read for
     * — `index_limit`, `indexes_used`, `indexes_available` — are built by the platform from the
     * SAME two calls its own create gate consults, so the number a client is told and the
     * number the platform enforces cannot drift apart. The usage counts standalone indexes
     * only, exactly like the gate.
     *
     * It costs an existing index to ask. The endpoint is scoped to one core: the caller has to
     * name an index the account owns and sign it, so an account holding nothing has nothing to
     * name and its allowance cannot be read at all. That case is reported as unknown rather
     * than guessed at — see Setup\Pairs::capacity(), which never blocks on a number nobody has.
     *
     * The signature is HMAC-SHA256 over core_name . email, keyed with the API key. It proves
     * the request was built by something holding the key rather than merely replaying a URL,
     * and it is computed here because this is the one class allowed to touch the key.
     *
     * MISSING FIELDS ARE NULL, NOT ZERO. A platform older than these fields answers with the
     * rest of the summary and none of them, and a zero there would read as "your plan allows no
     * indexes" — refusing an operator whose plan is perfectly fine. Absent means unknown, and
     * unknown is the caller's problem to describe honestly.
     *
     * @return array{ok:bool,message:string,index_limit:?int,indexes_used:?int,indexes_available:?int}
     */
    public function accountSummary(string $indexName): array
    {
        if (!Security::isSafeCoreName($indexName)) {
            throw new \InvalidArgumentException('Opensolr: invalid index name: ' . $indexName);
        }

        $blank = static function (string $message): array {
            return [
                'ok'                => false,
                'message'           => $message,
                'index_limit'       => null,
                'indexes_used'      => null,
                'indexes_available' => null,
            ];
        };

        try {
            $res = $this->call('get_account_summary', [
                'core_name' => $indexName,
                'signature' => hash_hmac('sha256', $indexName . $this->email, $this->apiKey),
            ], 'GET');
        } catch (\Throwable $e) {
            return $blank($this->redact($e->getMessage()));
        }

        if (empty($res['status'])) {
            return $blank(self::stringifyMsg($res['msg'] ?? 'the platform refused the request'));
        }

        $msg = (array) ($res['msg'] ?? []);
        $int = static function (array $from, string $key): ?int {
            return array_key_exists($key, $from) && is_numeric($from[$key]) ? (int) $from[$key] : null;
        };

        return [
            'ok'                => true,
            'message'           => '',
            'index_limit'       => $int($msg, 'index_limit'),
            'indexes_used'      => $int($msg, 'indexes_used'),
            'indexes_available' => $int($msg, 'indexes_available'),
        ];
    }

    /**
     * Did this create_index response fail because the plan has no room for another index?
     *
     * THE REFUSAL IS STILL THE AUTHORITY AT THE MOMENT OF CREATION, which is why it is still
     * recognised: the allowance is read from get_account_summary before anything is created,
     * but another session can take the last slot between that check and this call. So this
     * exists to report a rare race cleanly — NOT to discover the allowance. Loghound used to
     * parse the number out of this message and remember it, because the platform published it
     * nowhere else; it publishes it now, and a remembered number goes stale the moment a plan
     * changes while one read from the account cannot.
     *
     * @param array<string,mixed> $response A decoded createIndex() response.
     */
    public static function isAtIndexLimit(array $response): bool
    {
        if (!empty($response['status'])) {
            return false;
        }
        return stripos(self::stringifyMsg($response['msg'] ?? ''), 'CANNOT_ADD_MORE_THAN') !== false;
    }

    /**
     * Read one configuration file back from a managed index.
     *
     * Endpoint: GET /get_file?index_name=&file_name=&file_extension=, which answers
     * {"status":true,"msg":"<the file's contents>"}.
     *
     * READ-ONLY, and the only reason it exists is reuse: before this installation writes
     * documents into an index that another installation created, it has to know whether that
     * index's schema is the shape this version writes. Comparing the file the platform holds
     * against the one in this checkout answers that exactly, with no version marker to keep
     * in step and no guessing from a document sample.
     *
     * The platform strips the name down to [A-Za-z0-9_-] and the extension to [A-Za-z0-9]
     * before it uses either, so a path cannot travel in them; they are shape-checked here as
     * well so a caller bug fails locally rather than being silently rewritten server-side.
     *
     * Failure is a null rather than an exception. A configset the platform cannot hand back
     * — an older index, a node that did not answer, an account that lost the file — is a
     * normal state that the reuse flow has to describe to the operator, not a crash.
     *
     * `$why` carries the reason for that null back to a caller that wants to print it, already
     * redacted. "Could not read the schema" and "could not read the schema because nothing is
     * listening on the control plane" are the same verdict and completely different problems,
     * and the operator is the one who has to tell them apart. Callers that do not care pass
     * nothing and behave exactly as before.
     *
     * @param string|null $why Set to a printable reason whenever this returns null.
     */
    public function fetchConfigFile(
        string $indexName,
        string $fileName,
        string $extension,
        ?string &$why = null
    ): ?string {
        $why = null;

        if (!Security::isSafeCoreName($indexName)) {
            throw new \InvalidArgumentException('Opensolr: invalid index name: ' . $indexName);
        }
        if (!preg_match('/^[A-Za-z0-9_-]{1,64}$/D', $fileName)
            || !preg_match('/^[A-Za-z0-9]{1,8}$/D', $extension)) {
            throw new \InvalidArgumentException('Opensolr: invalid configset file name.');
        }

        try {
            $res = $this->call('get_file', [
                'index_name'     => $indexName,
                'file_name'      => $fileName,
                'file_extension' => $extension,
            ], 'GET');
        } catch (\Throwable $e) {
            $why = $this->redact($e->getMessage());
            return null;
        }

        if (empty($res['status'])) {
            $why = 'Opensolr refused the request: '
                . $this->redact(self::stringifyMsg($res['msg'] ?? 'no reason given'));
            return null;
        }

        $body = $res['msg'] ?? '';
        if (is_string($body) && $body !== '') {
            return $body;
        }

        $why = 'Opensolr answered without any file contents.';
        return null;
    }

    /**
     * Create a managed index.
     *
     * Endpoint: GET /create_index?index_name=&region=&email=&api_key=
     *
     * Idempotency: Opensolr refuses a duplicate name with an error rather than clobbering
     * the existing index, which is the behaviour we want — a re-run of setup must not
     * silently destroy the operator's data. The caller decides whether an "already exists"
     * response is a failure or a no-op.
     *
     * Region codes are uppercase identifiers, and anything else is a caller bug or an attempt
     * to inject into the query string, so the value is validated before it is sent.
     *
     * @return array<string,mixed> Decoded response.
     */
    public function createIndex(string $indexName, string $region): array
    {
        if (!Security::isSafeCoreName($indexName)) {
            throw new \InvalidArgumentException('Opensolr: invalid index name: ' . $indexName);
        }
        if (!preg_match('/^[A-Z0-9_]{2,32}$/D', $region)) {
            throw new \InvalidArgumentException('Opensolr: invalid region: ' . $region);
        }

        return $this->call('create_index', [
            'index_name' => $indexName,
            'region'     => $region,
        ], 'GET');
    }

    /**
     * Did this create_index response fail because the name is already taken?
     *
     * Opensolr index names are unique across the ENTIRE PLATFORM, not per
     * account, so a collision is a normal outcome to be retried with a fresh
     * name — not an error to show the operator. The platform signals it with
     * ERROR_CORE_NAME_TAKEN_CHOOSE_ANOTHER_CORE_NAME.
     *
     * Matched on a substring of the code rather than the whole string so that a
     * future rewording of the message does not turn a retryable collision into
     * a hard install failure.
     *
     * @param array<string,mixed> $response A decoded createIndex() response.
     */
    public static function isNameTaken(array $response): bool
    {
        if (!empty($response['status'])) {
            return false;
        }
        $msg = self::stringifyMsg($response['msg'] ?? '');
        return stripos($msg, 'CORE_NAME_TAKEN') !== false;
    }

    /**
     * Create both indexes for an installation, retrying on name collisions.
     *
     * Both cores must share one installation id so the pair is recognisable as
     * belonging together, which means a collision on EITHER name invalidates
     * the whole id and both are retried with a new one. Retrying only the
     * colliding half would leave a mismatched pair that is confusing to
     * identify in an account holding hundreds of indexes.
     *
     * Any index created during a failed attempt is deleted before the next one,
     * so a collision cannot leave orphaned indexes accumulating in the
     * operator's account (which they may well be billed for).
     *
     * A genuine failure — a bad key, a quota, a region that is down — is NOT retried. Whatever
     * that attempt created is rolled back and the error is surfaced, because retrying with a
     * different name would not help and would only make the real error harder to find.
     *
     * @param callable(string):void|null $progress Optional status callback.
     * @return array{install_id:string,hits:string,sessions:string}
     * @throws \RuntimeException When no free name pair could be obtained.
     */
    public function provisionIndexPair(
        string $region,
        int $attempts = 5,
        ?callable $progress = null
    ): array {
        $say = $progress ?? static function (string $m): void {
        };

        for ($attempt = 1; $attempt <= $attempts; $attempt++) {
            $installId = Config::newInstallId();
            $names = [
                'hits'     => Config::coreName($installId, 'hits'),
                'sessions' => Config::coreName($installId, 'sessions'),
            ];

            $created = [];
            $collided = false;

            foreach ($names as $role => $name) {
                $say(sprintf('Creating index %s ...', $name));
                $res = $this->createIndex($name, $region);

                if (!empty($res['status'])) {
                    $created[] = $name;
                    continue;
                }
                if (self::isNameTaken($res)) {
                    $say(sprintf('Name %s is already taken, choosing another.', $name));
                    $collided = true;
                    break;
                }
                $this->rollbackIndexes($created, $say);
                throw new \RuntimeException(
                    'Opensolr refused to create ' . $name . ': ' . self::stringifyMsg($res['msg'] ?? 'unknown error')
                );
            }

            if (!$collided) {
                return ['install_id' => $installId] + $names;
            }

            $this->rollbackIndexes($created, $say);
        }

        throw new \RuntimeException(
            'Could not find a free index name pair after ' . $attempts . ' attempts.'
        );
    }

    /**
     * Delete a managed index.
     *
     * Endpoint: GET /delete_index?index_name=
     *
     * DESTRUCTIVE, and public only because rollback needs it: when provisioning creates
     * the first index of a pair and the second name collides, the first has to go, or the
     * operator accumulates orphaned indexes they may well be billed for. Nothing in the
     * panel or the daemons calls this; the only callers are the two rollback paths, in
     * provisionIndexPair() here and in the step-by-step provisioning the installers share.
     *
     * @return array<string,mixed>
     */
    public function deleteIndex(string $indexName): array
    {
        if (!Security::isSafeCoreName($indexName)) {
            throw new \InvalidArgumentException('Opensolr: invalid index name: ' . $indexName);
        }
        return $this->call('delete_index', ['index_name' => $indexName], 'GET');
    }

    /**
     * Delete indexes created during an attempt that did not complete.
     *
     * Best effort by design: if the cleanup itself fails the operator still
     * needs the original error, so a failure here is reported and swallowed
     * rather than replacing the exception that caused the rollback.
     *
     * @param string[] $names
     */
    private function rollbackIndexes(array $names, callable $say): void
    {
        foreach ($names as $name) {
            try {
                $say(sprintf('Removing partially created index %s ...', $name));
                $this->deleteIndex($name);
            } catch (\Throwable $e) {
                $say(sprintf(
                    'WARNING: could not remove %s — delete it from your Opensolr control panel.',
                    $name
                ));
            }
        }
    }

    /**
     * Health of a managed index.
     *
     * Endpoint: GET /get_core_status?core_name=
     *
     * This is the "Healthy ✓" the operator sees. It is the platform's view of the index
     * (is the node up, is the core loaded), which is a different question from
     * Solr::ping() — that one proves Loghound itself can reach and authenticate to the
     * node. Setup shows both, because "Opensolr says it is fine but we cannot connect"
     * is a firewall problem and the operator needs to be told which of the two failed.
     *
     * @return array<string,mixed>
     */
    public function indexStatus(string $indexName): array
    {
        if (!Security::isSafeCoreName($indexName)) {
            throw new \InvalidArgumentException('Opensolr: invalid index name: ' . $indexName);
        }
        return $this->call('get_core_status', ['core_name' => $indexName], 'GET');
    }

    /**
     * Connection details for a managed index.
     *
     * Endpoint: GET /get_core_info?core_name=
     * Returns msg.info.connection_url, msg.info.auth_username, msg.info.auth_password.
     *
     * This is how managed mode fills in solr.base_url / http_user / http_pass. SPEC §9 does
     * not say where those come from in managed mode; this is the answer — setup calls this
     * once after createIndex() and writes the result into the config, after which
     * src/Solr.php is mode-agnostic and simply talks to a Solr node it has credentials for.
     *
     * connection_url points at the core (…/solr/<index>), and src/Solr.php builds
     * <base>/<core>/<handler> itself, so the trailing core segment is stripped here to get the
     * base. Doing it in this one place keeps the "what shape is a base URL" knowledge from
     * spreading.
     *
     * @return array{base_url:string,http_user:string,http_pass:string}
     */
    public function connectionDetails(string $indexName): array
    {
        if (!Security::isSafeCoreName($indexName)) {
            throw new \InvalidArgumentException('Opensolr: invalid index name: ' . $indexName);
        }
        $res = $this->call('get_core_info', ['core_name' => $indexName], 'GET');

        $info = $res['msg']['info'] ?? [];
        $url  = (string) ($info['connection_url'] ?? '');
        if ($url === '') {
            throw new \RuntimeException('Opensolr: no connection_url returned for index ' . $indexName);
        }

        $base = preg_replace('#/' . preg_quote($indexName, '#') . '/?$#', '', $url) ?? $url;

        return [
            'base_url'  => rtrim((string) $base, '/'),
            'http_user' => (string) ($info['auth_username'] ?? ''),
            'http_pass' => (string) ($info['auth_password'] ?? ''),
        ];
    }

    /**
     * Plan usage for a managed index: disk used, disk allowed, bandwidth used, bandwidth allowed.
     *
     * Endpoint: GET /get_core_info?core_name=, reading `msg.core_data` rather than `msg.info`.
     *
     * THE FIELD NAMES ARE THE PLATFORM'S, MISSPELLINGS INCLUDED — `core_badnwidth_mb` and
     * `max_badnwdith_mb` are spelled exactly like that on the wire, and they are matched here
     * exactly and normalised on the way out, so nothing else in Loghound has to know. Do not
     * "fix" them: they are a contract with a live API, not a typo in this repository.
     *
     * WHY THIS IS EXPENSIVE, and why callers must cache it. The platform derives
     * `core_size_mb` by asking the Solr node for its live index status, so this is not a
     * cheap database read — it is a round trip to the control plane which is itself a round
     * trip to the index. \Loghound\Quota is the only caller and caches on both a clock and a
     * document count for that reason.
     *
     * Failure is a STATE, not an exception, for the same reason it is in OpensolrLog: "the
     * account does not own that index", "the control plane is unreachable" and "the platform
     * refused" are three different things an operator has to be told apart, and none of them
     * is a programming error. The platform answers a non-owner with HTTP 200 and
     * `{"status":false,"msg":"NOT_OWNER_ERROR"}`, which is a normal outcome for a stale
     * config or a scoped API key.
     *
     * `account` carries the platform's own account-wide totals from `msg.all_cores`, which
     * are already scoped to what this API key may see. They are informational: the limits
     * that actually block an index are the per-index ones above them.
     *
     * @return array{state:string,message:string,size_mb:float,max_size_mb:float,
     *               bw_mb:float,max_bw_mb:float,account:array<string,float>}
     */
    public function coreUsage(string $indexName): array
    {
        if (!Security::isSafeCoreName($indexName)) {
            throw new \InvalidArgumentException('Opensolr: invalid index name: ' . $indexName);
        }

        $fail = static function (string $state, string $message): array {
            return [
                'state'       => $state,
                'message'     => $message,
                'size_mb'     => 0.0,
                'max_size_mb' => 0.0,
                'bw_mb'       => 0.0,
                'max_bw_mb'   => 0.0,
                'account'     => [],
            ];
        };

        try {
            $res = $this->call('get_core_info', ['core_name' => $indexName], 'GET');
        } catch (\Throwable $e) {
            return $fail('unreachable', $this->redact($e->getMessage()));
        }

        if (empty($res['status'])) {
            $msg = self::stringifyMsg($res['msg'] ?? '');
            if (stripos($msg, 'NOT_OWNER') !== false || stripos($msg, 'INVALID_CORE_NAME') !== false) {
                return $fail(
                    'not_owner',
                    'This Opensolr account does not own that index, so the platform will not report its '
                    . 'plan usage. Check solr.hits_core / solr.sessions_core and the credentials in '
                    . 'config/loghound.php.'
                );
            }
            return $fail('refused', 'Opensolr refused the request for this index.');
        }

        $data = (array) ($res['msg']['core_data'] ?? []);
        if ($data === []) {
            return $fail('refused', 'Opensolr answered without any plan usage for this index.');
        }

        $all = (array) ($res['msg']['all_cores'] ?? []);

        return [
            'state'       => 'ok',
            'message'     => '',
            'size_mb'     => (float) ($data['core_size_mb'] ?? 0),
            'max_size_mb' => (float) ($data['max_core_size_mb'] ?? 0),
            'bw_mb'       => (float) ($data['core_badnwidth_mb'] ?? 0),
            'max_bw_mb'   => (float) ($data['max_badnwdith_mb'] ?? 0),
            'account'     => [
                'indexes'      => (float) ($all['total_number_of_cores'] ?? 0),
                'disk_mb'      => (float) ($all['total_cores_disk_mb'] ?? 0),
                'bandwidth_mb' => (float) ($all['total_cores_bandwidth_mb'] ?? 0),
            ],
        ];
    }

    /**
     * The configset files, IN DEPENDENCY ORDER. Nothing else in a conf directory is uploaded.
     *
     * ====================================================================================
     * THE ORDER IS THE SAFETY PROPERTY OF THIS METHOD, AND IT IS THE REVERSE OF WHAT IT WAS.
     * ====================================================================================
     * The platform accepts one file per call and RELOADS THE CORE after each one. So every
     * intermediate state has to be a configset that loads, and a file must never land before
     * the thing it depends on.
     *
     *   1. mapping-ISOLatin1Accent.txt   schema.xml's char filter names it. A schema that
     *                                    arrived first would reload the core against a
     *                                    missing file and THE CORE WOULD NOT LOAD AT ALL —
     *                                    which is worse than being out of date, because the
     *                                    index stops answering rather than answering with an
     *                                    old shape.
     *   2. schema.xml                    Inert while the index is still on Solr's managed
     *                                    schema factory, which is exactly what makes this
     *                                    step safe during the one-time switch to the classic
     *                                    factory: the file is simply ignored until step 3.
     *   3. solrconfig.xml                Declares ClassicIndexSchemaFactory, so ITS reload is
     *                                    the one that makes schema.xml authoritative. By then
     *                                    both files it needs are already on the index.
     *
     * This file used to upload the schema FIRST, on the reasoning that a solrconfig may refer
     * to field types the old schema lacks. That reasoning was sound and is now served better
     * by the same rule stated generally — DEPENDENCIES BEFORE DEPENDANTS — which the list
     * above encodes once. Our solrconfig refers to no field type except `text_all` through
     * `df`, and `text_all` exists in both the old schema and the new one, so step 3 is safe
     * against either.
     *
     * A REJECTED FILE STOPS THE PUSH. Every remaining state then still loads:
     *   mapping rejected     nothing changed.
     *   schema rejected      the mapping file is on the index and unused. Nothing changed.
     *   solrconfig rejected  the mapping file and schema.xml are on the index; the core is
     *                        still on the managed factory and still running the schema it had.
     *                        Setup\Schema::check() reports that state by name, because in it
     *                        every future schema upload is a silent no-op.
     * A re-run is always safe from any of the three.
     *
     * It is a list and not a glob: a stray .bak or an editor swap file in the directory would
     * otherwise be uploaded to the Solr node.
     *
     * @var array<int,string>
     */
    public const CONFIGSET_FILES = ['mapping-ISOLatin1Accent.txt', 'schema.xml', 'solrconfig.xml'];

    /**
     * Push a configset to a managed index, in CONFIGSET_FILES order.
     *
     * Endpoint: POST /upload_config_file, multipart/form-data, file field `userfile`,
     * plus core_name / email / api_key as POST fields. The platform answers
     * {"status":true|false,"msg":...}, and anything without a truthy status is a failure the
     * operator must see rather than a warning to hide.
     *
     * @param string $confDir Local directory, e.g. solr/hits/conf
     * @return array<int,array{file:string,ok:bool,msg:string}> One row per file, for the
     *                                                          setup wizard to display.
     */
    public function pushConfigSet(string $indexName, string $confDir): array
    {
        if (!Security::isSafeCoreName($indexName)) {
            throw new \InvalidArgumentException('Opensolr: invalid index name: ' . $indexName);
        }

        $real = realpath($confDir);
        if ($real === false || !is_dir($real)) {
            throw new \InvalidArgumentException('Opensolr: configset directory not found: ' . $confDir);
        }

        $order = self::CONFIGSET_FILES;
        $results = [];
        $stoppedBy = '';

        foreach ($order as $name) {
            if ($stoppedBy !== '') {
                $results[] = [
                    'file' => $name,
                    'ok'   => false,
                    'msg'  => 'not uploaded, because ' . $stoppedBy . ' was rejected first',
                ];
                continue;
            }

            $path = $real . '/' . $name;
            if (!is_file($path)) {
                $results[] = ['file' => $name, 'ok' => false, 'msg' => 'missing locally'];
                $stoppedBy = $name;
                continue;
            }

            try {
                $res = $this->uploadFile($indexName, $path);
                $ok = (bool) ($res['status'] ?? false);
                /* A REJECTION IS PLATFORM TEXT AND WAS THE ONE BRANCH THAT DID NOT REDACT IT.
                   The catch below redacts, decode() redacts, and this — the path a `status:
                   false` answer takes — handed the platform's own words straight through into
                   var/schema-check.json and onto the Settings page. An endpoint that echoes
                   part of the request it refused would therefore publish the account API key,
                   which on this platform is also the index HTTP auth password. */
                $results[] = [
                    'file' => $name,
                    'ok'   => $ok,
                    'msg'  => $ok ? 'uploaded' : $this->redact(self::stringifyMsg($res['msg'] ?? 'rejected')),
                ];
                if (!$ok) {
                    $stoppedBy = $name;
                }
            } catch (\Throwable $e) {
                $results[] = ['file' => $name, 'ok' => false, 'msg' => $this->redact($e->getMessage())];
                $stoppedBy = $name;
            }
        }

        return $results;
    }

    /**
     * Call a control-plane endpoint.
     *
     * Credentials are appended here and nowhere else, which is what makes the "never log
     * the key" rule auditable: there is exactly one place the key enters a request.
     *
     * The GET endpoints on this API read their credentials from the query string; that is the
     * platform's contract and cannot be changed from this side. POST endpoints take them as
     * fields, which is the safer of the two and is what uploadFile() uses.
     *
     * @param array<string,string> $params
     * @return array<string,mixed>
     */
    private function call(string $endpoint, array $params, string $method): array
    {
        if (!preg_match('/^[a-z0-9_]{1,64}$/D', $endpoint)) {
            throw new \InvalidArgumentException('Opensolr: invalid endpoint: ' . $endpoint);
        }
        if ($this->email === '' || $this->apiKey === '') {
            throw new \RuntimeException('Opensolr: email and api_key are required in managed mode.');
        }

        /* THE BASE URL IS CHECKED BEFORE THE CREDENTIALS ARE ATTACHED TO IT, and it was not
           checked at all. `opensolr.api_base` decides where this account's email and API key
           are sent on every single call — it is the primary credential path in the product —
           and it was taken from the configuration and concatenated, so `https://127.0.0.1/…`,
           `https://169.254.169.254/…`, an internal name or a plain `http://` host were all
           accepted. Security::safeOutboundUrl() is the same check enrich.geo_endpoint gets,
           which is the secondary path; there was no reason for the primary one to have less.

           Refused rather than defaulted: silently falling back to DEFAULT_API_BASE would send
           an operator's credentials somewhere they did not configure, which is the same class
           of surprise in the other direction. */
        if (Security::safeOutboundUrl($this->apiBase) === null) {
            throw new \RuntimeException(
                'Opensolr: opensolr.api_base must be an https URL on a public host, with no '
                . 'embedded credentials. Leave it unset to use ' . self::DEFAULT_API_BASE . '.'
            );
        }

        $params['email']   = $this->email;
        $params['api_key'] = $this->apiKey;

        $url = $this->apiBase . '/' . $endpoint;
        $qs  = http_build_query($params, '', '&', PHP_QUERY_RFC3986);

        $res = ($this->transport)([
            'method'          => $method,
            'url'             => $method === 'GET' ? $url . '?' . $qs : $url,
            'headers'         => ['Accept: application/json'],
            'body'            => $method === 'GET' ? null : $qs,
            'timeout'         => $this->timeout,
            'connect_timeout' => 10,
            'max_bytes'       => self::MAX_RESPONSE_BYTES,
            'user'            => '',
            'pass'            => '',
        ]);

        return $this->decode($res, $endpoint);
    }

    /**
     * Upload one configset file as multipart/form-data.
     *
     * Built by hand rather than with CURLFile so the transport stays a plain callable that
     * a test can replace. The boundary is random, and every field value is written
     * verbatim into the body — which is safe here because the only caller-influenced value
     * is the index name, already validated against [A-Za-z0-9_].
     *
     * The platform caps uploads at roughly 3.5 MB and accepts only xml, txt, zip, aff and dic.
     * The filename is passed through basename(), so a path can never travel in that field. The
     * file field is named `userfile`, which is what CodeIgniter's do_upload() reads by default
     * and what the platform's upload_config_file endpoint expects.
     *
     * @return array<string,mixed>
     */
    private function uploadFile(string $indexName, string $path): array
    {
        $contents = file_get_contents($path);
        if ($contents === false) {
            throw new \RuntimeException('Opensolr: cannot read ' . $path);
        }
        if (strlen($contents) > 3_000_000) {
            throw new \RuntimeException('Opensolr: configset file is too large: ' . basename($path));
        }

        /* THE SAME BASE-URL CHECK request() MAKES. This method builds its own URL rather than
           going through it, so without this the one endpoint that uploads a configset AND carries
           the credentials would be the one that never validated where it was sending them. */
        if (Security::safeOutboundUrl($this->apiBase) === null) {
            throw new \RuntimeException(
                'Opensolr: opensolr.api_base must be an https URL on a public host, with no '
                . 'embedded credentials. Leave it unset to use ' . self::DEFAULT_API_BASE . '.'
            );
        }

        /* EVERY PART OF THIS BODY IS A HEADER UNTIL THE BLANK LINE, and the body is built by
           concatenation. A filename carrying a quote or a CRLF closes the Content-Disposition
           and opens whatever the rest of it says; a credential carrying a CRLF forges a whole
           extra part. basename() strips directories and nothing else — it leaves quotes, CR and
           LF exactly where they were. These values are all ours today, which is precisely why
           the check is cheap and why "ours today" is not a property worth relying on. */
        $filename = basename($path);
        if (!preg_match('/^[A-Za-z0-9._-]{1,128}$/D', $filename)) {
            throw new \RuntimeException('Opensolr: unsafe configset filename: ' . $filename);
        }

        $boundary = '----loghound' . bin2hex(random_bytes(16));
        $eol = "\r\n";

        $fields = [
            'core_name' => $indexName,
            'email'     => $this->email,
            'api_key'   => $this->apiKey,
        ];

        foreach ($fields as $name => $value) {
            if (preg_match('/[\x00\r\n"]/', (string) $value)) {
                throw new \RuntimeException('Opensolr: unsafe value in the ' . $name . ' upload field.');
            }
        }

        $body = '';
        foreach ($fields as $name => $value) {
            $body .= '--' . $boundary . $eol;
            $body .= 'Content-Disposition: form-data; name="' . $name . '"' . $eol . $eol;
            $body .= $value . $eol;
        }
        $body .= '--' . $boundary . $eol;
        $body .= 'Content-Disposition: form-data; name="userfile"; filename="' . $filename . '"' . $eol;
        $body .= 'Content-Type: application/xml' . $eol . $eol;
        $body .= $contents . $eol;
        $body .= '--' . $boundary . '--' . $eol;

        $res = ($this->transport)([
            'method'          => 'POST',
            'url'             => $this->apiBase . '/upload_config_file',
            'headers'         => [
                'Content-Type: multipart/form-data; boundary=' . $boundary,
                'Accept: application/json',
            ],
            'body'            => $body,
            'timeout'         => $this->timeout,
            'connect_timeout' => 10,
            'max_bytes'       => self::MAX_RESPONSE_BYTES,
            'user'            => '',
            'pass'            => '',
        ]);

        return $this->decode($res, 'upload_config_file');
    }

    /**
     * Decode a control-plane response.
     *
     * Every failure message is passed through redact() before it can reach a caller, an
     * exception, or a log file. The platform echoes request parameters back in some error
     * paths, and one of those parameters is the API key.
     *
     * /regions answers with a bare JSON array, which is wrapped so that callers always get a
     * map back.
     *
     * @param array<string,mixed> $res
     * @return array<string,mixed>
     */
    private function decode(array $res, string $endpoint): array
    {
        $status = (int) ($res['status'] ?? 0);
        $body   = (string) ($res['body'] ?? '');

        if ($status === 0) {
            throw new \RuntimeException(
                'Opensolr: cannot reach the control plane (' . $endpoint . '): '
                . $this->redact((string) ($res['error'] ?? 'no response'))
            );
        }

        $decoded = json_decode($body, true);
        if ($decoded === null) {
            throw new \RuntimeException(
                'Opensolr: HTTP ' . $status . ' from ' . $endpoint . ' with an unparseable body.'
            );
        }

        if (array_is_list((array) $decoded)) {
            return ['_list' => $decoded];
        }

        if ($status >= 400) {
            throw new \RuntimeException(
                'Opensolr: HTTP ' . $status . ' from ' . $endpoint . ': '
                . $this->redact(self::stringifyMsg($decoded['msg'] ?? ''))
            );
        }

        return (array) $decoded;
    }

    /**
     * Remove the API key from any string that is about to be shown or logged.
     *
     * The last line of defence, not the first: nothing should be constructing a message
     * containing the key in the first place. It exists because the platform occasionally
     * echoes the request back in an error body, and a secret in an exception message ends
     * up in a stack trace, in a support paste, and in an issue on a public repo.
     *
     * The key is also matched inside an echoed query string, in case the platform returned a
     * normalised or partially encoded form of it.
     *
     * FOUR SHAPES, NOT ONE, and the widening is not decoration. These strings do not stay in a
     * log: Setup\Schema puts them in `var/schema-check.json` and the panel's Settings page
     * renders them, so whatever the control plane echoed back is published to a browser. The
     * literal key and `api_key=` were covered; the account email that travels beside it in every
     * request was not, nor a URL that arrived carrying userinfo, nor the other credential-shaped
     * parameter names a future endpoint may use. Panel\Jobs::redact() already redacts that set
     * for the panel's own errors and there is no reason this one should be narrower.
     *
     * preg_replace returns NULL on a PCRE failure, and casting that to a string silently
     * replaces the whole message with an empty one — so each step falls back to its input
     * rather than to nothing.
     */
    private function redact(string $text): string
    {
        /* THE NAMED PARAMETERS GO FIRST, then the bare literals. The other order replaces
           `api_key=SECRET` with `api_key=[api_key redacted]` and the pattern then matches the
           placeholder, leaving a mangled tail. Nothing leaks either way; this simply reads. */
        $patterns = [
            '/(api[_-]?key|apikey|email|token|secret|password|passwd|pwd|salt)=([^&"\s]*)/i'
                => '$1=[redacted]',
            '#(https?://)[^/@\s:]+:[^/@\s]+@#i' => '$1[redacted]@',
        ];
        foreach ($patterns as $pattern => $replacement) {
            $text = preg_replace($pattern, $replacement, $text) ?? $text;
        }

        if ($this->apiKey !== '') {
            $text = str_replace($this->apiKey, '[api_key redacted]', $text);
        }
        if ($this->email !== '') {
            $text = str_replace($this->email, '[email redacted]', $text);
        }

        /* TRUNCATED AFTER SCRUBBING, NEVER BEFORE. These strings are stored in
           var/schema-check.json and rendered into the Settings page on every load, so an `msg`
           of arbitrary length is a file and a page of arbitrary length. But cutting first
           leaves the HEAD of a credential that straddles the limit in the output, with the
           literal pass unable to match what is left of it — the same reasoning that puts
           Diagnostics::field()'s cap after its redaction. */
        if (strlen($text) > self::MAX_MESSAGE) {
            $text = substr($text, 0, self::MAX_MESSAGE) . '…';
        }

        return $text;
    }

    /**
     * Flatten the platform's `msg`, which is sometimes a string and sometimes a structure.
     *
     * @param mixed $msg
     */
    private static function stringifyMsg($msg): string
    {
        if (is_string($msg)) {
            return $msg;
        }
        return (string) json_encode($msg, JSON_UNESCAPED_SLASHES);
    }
}
