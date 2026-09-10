<?php
/**
 * Loghound — Solr HTTP client.
 *
 * THIS IS THE ONLY PATH TO SOLR IN THE ENTIRE CODEBASE. Nothing else opens a socket to a
 * Solr node, and there is deliberately no generic passthrough method: SPEC §1 forbids a
 * "proxy this query to Solr" endpoint, and the way you make that rule hold is by not
 * providing the primitive that would let someone build one.
 *
 * ---------------------------------------------------------------------------------------
 * THE THREAT MODEL, because every guard below maps to a specific attack
 * ---------------------------------------------------------------------------------------
 * The panel takes a free-text search box, sort keys, facet fields, page numbers and filter
 * selections from a browser. A Solr node reached with attacker-chosen parameters is not
 * "a search that returns odd results" — it is:
 *
 *   * arbitrary file read and SSRF, via stream.url / stream.file / shards pointing at an
 *     internal host (and the response comes back through the same channel);
 *   * remote code execution, via /stream and /sql streaming expressions, which are a small
 *     server-side language with HTTP and JDBC sources;
 *   * total data loss, via stream.body carrying <delete><query>*:*</query></delete>;
 *   * denial of service, via deep paging (start=50000000) or an unbounded rows;
 *   * cross-site scripting, via a response written by an XSLT transform the caller chose
 *     (`tr` / `wt=xslt`).
 *
 * Solr's own configuration blocks several of these (see the solrconfig.xml of each core
 * under solr/). This
 * class blocks them again, independently, because a config file can be replaced by an
 * operator restoring a stock configset and the application should still be safe.
 *
 * ---------------------------------------------------------------------------------------
 * THE ONE RULE: user text is a VALUE, never a fragment of a query
 * ---------------------------------------------------------------------------------------
 * Free text goes to Solr as its own parameter and is referenced by name from a query we
 * wrote ourselves:
 *
 *     q  = {!edismax v=$uq}
 *     uq = whatever the human typed
 *
 * The `uq` parameter is dereferenced by the parser as an opaque value. It cannot terminate
 * the local-param block, cannot introduce a second parameter, and cannot switch parsers.
 * Compare with the naive `q = 'text:' . $input`, where a single `}` or `&` changes the
 * meaning of the request. Structured values (a status code, an ASN, a session id) go
 * through the builders at the bottom of this file, which quote and escape them.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound;

final class Solr
{
    /**
     * Parameters that must never reach Solr, whoever asks and for whatever reason.
     *
     * Presence of any of these is treated as an attack, not a mistake: the request is
     * refused outright rather than having the parameter quietly dropped, because a caller
     * that tried to set `shards` has a bug or an injection and both deserve to be loud.
     *
     * Each group in the list below is refused for a specific attack.
     *
     * Remote content loading — SSRF and arbitrary file read. stream.url makes Solr fetch a
     * URL of the caller's choosing (hello, cloud metadata endpoint), stream.file makes it
     * read a local path, and stream.body lets a GET carry an update command, including a
     * delete-by-query for *:*.
     *
     * Distributed search — SSRF with the response relayed back. `shards` names the hosts a
     * distributed query fans out to, so an attacker-chosen shard is an outbound HTTP
     * request to an arbitrary host whose body is handed back to them. `distrib` and
     * `_route_` are the switches that turn it on.
     *
     * Handler selection — `qt` re-dispatches the request to a different handler by path.
     * Even though this configset defines no /stream or /sql, `qt` would reach anything Solr
     * registers implicitly, so it is refused rather than reasoned about.
     *
     * Response writers — `wt` is pinned to json by an invariant in solrconfig; refusing it
     * here as well means a stock configset cannot be talked into wt=xslt, which runs a
     * stylesheet of the caller's choosing (XXE and stored XSS), or into a serialiser this
     * client cannot parse.
     *
     * Streaming expressions and SQL — remote code execution. The handlers are not defined
     * in our configset; these are refused anyway so that pointing Loghound at somebody
     * else's Solr, which may define them, is still safe.
     *
     * Replication and core admin — `command` on /replication can fetch the whole index or
     * repoint a follower at an attacker-controlled leader.
     *
     * Parser selection — `deftype` is not dangerous on its own, but it silently breaks this
     * client's core idiom. A `{!edismax v=$uq}` switch at the start of `q` is honoured ONLY
     * by the top-level lucene parser; with defType=edismax set, edismax parses the literal
     * characters "{!edismax v=$uq}" as search terms and returns nothing. That bug is
     * invisible in a diff and expensive to find, so the parameter is refused.
     *
     * @var string[]
     */
    private const DENIED_PARAMS = [
        'stream.body', 'stream.url', 'stream.file', 'stream.contenttype',

        'shards', 'shards.tolerant', 'shards.info', 'shards.preference', 'shard.url',
        'distrib', '_route_', '_statever_',

        'qt', 'handler',

        'wt', 'tr', 'xsl',

        'expr', 'stmt', 'sql',

        'command', 'action', 'core', 'datadir', 'instancedir', 'config', 'schema',

        'deftype',
    ];

    /**
     * Prefixes that are refused wholesale, so a new parameter in a future Solr version
     * cannot slip through the exact-match list above.
     *
     * @var string[]
     */
    private const DENIED_PREFIXES = ['stream.', 'shards.', 'jdbc.', 'zk', 'core.'];

    /**
     * Aggregate functions permitted inside a JSON Facet.
     *
     * A JSON Facet's `func`/aggregate slot accepts arbitrary function queries, which can
     * reference fields, run scripts in some deployments, and are an excellent oracle for
     * reading data the caller is not supposed to see. Only these fixed forms are allowed.
     *
     * @var string[]
     */
    private const FACET_AGGS = [
        'count', 'unique', 'hll', 'sum', 'avg', 'min', 'max',
        'sumsq', 'stddev', 'variance', 'missing', 'countvals', 'percentile',
    ];

    /** JSON Facet types we support. `func` is absent on purpose — see FACET_AGGS. */
    private const FACET_TYPES = ['terms', 'range', 'query'];

    /** Base URL of the Solr instance, e.g. https://fi.solrcluster.com/solr (no core). */
    private string $baseUrl;

    private string $httpUser;

    private string $httpPass;

    /** Total request timeout in seconds. */
    private int $timeout;

    /** Connect timeout in seconds. Short: a dead node should fail fast and be retried. */
    private int $connectTimeout = 5;

    /** Total attempts per request, including the first. */
    private int $maxAttempts = 3;

    /** @var callable Transport, injectable so tests run with no network. */
    private $transport;

    /** Last transport-level error, for diagnostics. Never contains credentials. */
    private string $lastError = '';

    /**
     * The transport is a plain callable so that a test can hand over a closure returning
     * canned JSON: no mocking framework, no network, no Composer.
     *
     * @param array<string,mixed> $solrCfg The 'solr' section of the config.
     * @param callable|null       $transport fn(array $req): array{status:int,body:string,error:string}
     *                                       Injected by tests; defaults to curl.
     */
    public function __construct(array $solrCfg, ?callable $transport = null)
    {
        $this->baseUrl  = rtrim((string) ($solrCfg['base_url'] ?? ''), '/');
        $this->httpUser = (string) ($solrCfg['http_user'] ?? '');
        $this->httpPass = (string) ($solrCfg['http_pass'] ?? '');
        $this->timeout  = max(1, (int) ($solrCfg['timeout'] ?? 20));

        $this->transport = $transport ?? [self::class, 'curlTransport'];
    }

    /**
     * Liveness check: a zero-row select, deliberately NOT /admin/ping.
     *
     * Used by setup to confirm the connection details and by the daemons at startup so a
     * misconfiguration is one clear message instead of a stream of failed batches.
     *
     * Loghound's solrconfig strips every handler the application does not use, and
     * /admin/ping is one of them, so a real and perfectly healthy core answers a ping
     * request with 404 — the old check reported the backend as down while every actual
     * query worked. A `q=*:*&rows=0` select is also the better health check on its own
     * merits: it proves the core is loaded, the searcher is open and our credentials are
     * accepted, which is exactly what the caller wants to know. /admin/ping proves only
     * that a handler exists.
     *
     * The core name is validated FIRST, and a bad one is allowed to throw. A health check
     * must not become a hole in the input validation: if the catch below swallowed
     * everything, a caller could pass a core name containing a query string or a path
     * segment and learn from the returned boolean whether their injection reached a real
     * handler. Only transport-level failures — an unreachable node, an auth failure, a
     * malformed response, the thing ping is actually asking about — are turned into false.
     * The wording of the core-name error matches the one in send() so that callers and
     * tests see one consistent message for one condition regardless of entry point.
     */
    public function ping(string $core): bool
    {
        if (!Security::isSafeCoreName($core)) {
            throw new \InvalidArgumentException('Solr: unsafe core name: ' . $core);
        }

        try {
            $res = $this->send($core, '/select', ['q' => '*:*', 'rows' => 0], null, 'GET');
        } catch (\RuntimeException $e) {
            return false;
        }
        return isset($res['responseHeader']['status'])
            && (int) $res['responseHeader']['status'] === 0;
    }

    /**
     * Index a batch of documents.
     *
     * softCommit only, never commit=true. A hard commit per batch would fsync and open a
     * new searcher thousands of times a minute; SPEC §5 puts visibility on autoSoftCommit
     * (5s) and durability on autoCommit (60s, openSearcher=false) instead.
     *
     * Document ids are deterministic (sha1 of file + byte offset), so this call is
     * idempotent and safe to retry — which is what makes the retry loop in send() correct
     * for a write.
     *
     * The soft commit is asked for within a second; Solr coalesces those, so a burst of
     * batches produces one commit rather than one per batch.
     *
     * The payload is encoded with JSON_INVALID_UTF8_SUBSTITUTE because log lines are bytes,
     * not text. A request path can contain any byte an attacker likes, including invalid
     * UTF-8 sequences, and json_encode() returns false on those — which would silently drop
     * a whole batch. Substituting U+FFFD keeps the document indexable and keeps the
     * pipeline honest about the fact that the byte was not valid text.
     *
     * @param array<int,array<string,mixed>> $docs
     * @return array<string,mixed> Decoded Solr response.
     */
    public function addDocs(string $core, array $docs, bool $softCommit = true): array
    {
        if ($docs === []) {
            return ['responseHeader' => ['status' => 0], 'skipped' => true];
        }

        $params = [];
        if ($softCommit) {
            $params['softCommit'] = 'true';
            $params['commitWithin'] = '1000';
        }

        $body = json_encode(
            array_values($docs),
            JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
        );
        if ($body === false) {
            throw new \RuntimeException('Solr: unable to encode document batch: ' . json_last_error_msg());
        }

        return $this->send($core, '/update', $params, $body, 'POST', 'application/json');
    }

    /**
     * Run a search.
     *
     * $params is validated in full before anything is sent: denied parameters refuse the
     * request, rows/start are clamped, and sort/fl/fq/facet field names must pass the
     * allowlist. There is no bypass.
     *
     * For free text use queryText() instead — it is the only method that accepts human
     * input, and it binds it rather than splicing it.
     *
     * The request goes out as a form-encoded POST rather than a GET, for two practical
     * reasons: a long fq list or a big filter selection blows past the ~8 KB URL limit some
     * proxies enforce, and the failure mode there is a truncated query rather than an
     * error; and Solr's request log records the URL, so with GET every search term a user
     * typed would be written to a second log file on a third-party managed host.
     *
     * @param array<string,mixed> $params
     * @return array<string,mixed>
     */
    public function query(string $core, array $params): array
    {
        $params = $this->sanitiseQueryParams($params);

        return $this->send($core, '/select', [], self::encodeParams($params), 'POST', 'application/x-www-form-urlencoded');
    }

    /**
     * Run a free-text search over the catchall, with the user's text BOUND, not spliced.
     *
     * This is the only method in the codebase that accepts text a human typed. The text
     * travels as its own parameter (`uq`) and is referenced from a query string we wrote
     * (`{!edismax v=$uq}`). Nothing the user types can terminate the local-param block,
     * add a parameter, or change the parser.
     *
     * Note the absence of defType, which is deliberate and is why defType sits in
     * DENIED_PARAMS: the {!edismax ...} switch is honoured only by the top-level lucene
     * parser, and setting defType=edismax would make edismax read the braces as literal
     * search text and return nothing.
     *
     * An empty search box means "everything", not "match nothing".
     *
     * mm is pinned to 100%, so every term must match. On a forensic tool a search for
     * "SwiftShader 45.38" that silently ORs the terms and returns half the index is worse
     * than no results at all, because the operator will believe the extra rows.
     *
     * @param string              $userText  Raw input from the search box.
     * @param array<string,mixed> $params    Extra params (fq, rows, sort, facets...).
     * @param string[]            $qf        Field^boost list; every field name is validated.
     * @return array<string,mixed>
     */
    public function queryText(
        string $core,
        string $userText,
        array $params = [],
        array $qf = [
            'path_txt^3', 'ua_txt^2', 'as_org_txt^2', 'netname_txt^2',
            'rdns_txt', 'city_txt', 'country_txt',
        ]
    ): array {
        $text = $this->normaliseUserText($userText);

        if ($text === '') {
            $params['q'] = '*:*';
            unset($params['uq'], $params['qf']);
            return $this->query($core, $params);
        }

        $params['q']  = '{!edismax v=$uq}';
        $params['uq'] = $text;
        $params['qf'] = $this->buildQf($qf);

        $params['mm'] = '100%';

        return $this->query($core, $params);
    }

    /**
     * Run a JSON Facet request.
     *
     * The facet structure is a PHP array, validated recursively, and serialised here. A
     * caller cannot hand over a pre-built JSON string, because the whole point of the
     * validation is that we know what every field and aggregate in it is.
     *
     * This is what computes fp_ips_24h_i:
     *   jsonFacet('loghound_hits',
     *       ['q' => '*:*', 'fq' => [Solr::termsFilter('fp_hash_s', $hashes),
     *                               Solr::rangeFilter('ts', $from, $to)]],
     *       ['by_fp' => ['type' => 'terms', 'field' => 'fp_hash_s', 'limit' => 500,
     *                    'facet' => ['ips' => 'unique(ip_s)']]]);
     *
     * rows is forced to 0: a facet request never needs documents back, and asking for them
     * turns a cheap aggregate into a full stored-field fetch.
     *
     * @param array<string,mixed> $queryParams Standard params (q, fq, ...). rows is forced to 0.
     * @param array<string,mixed> $facet       JSON Facet structure.
     * @return array<string,mixed>
     */
    public function jsonFacet(string $core, array $queryParams, array $facet): array
    {
        $params = $this->sanitiseQueryParams($queryParams);

        $params['rows'] = 0;

        $params['json.facet'] = json_encode(
            $this->sanitiseFacet($facet),
            JSON_UNESCAPED_SLASHES
        );

        return $this->send(
            $core,
            '/select',
            [],
            self::encodeParams($params),
            'POST',
            'application/x-www-form-urlencoded'
        );
    }

    /**
     * Delete documents matching a query.
     *
     * INTERNAL USE ONLY. There is no HTTP path that reaches this method, and there must
     * never be one: delete-by-query is the single most destructive primitive Solr exposes.
     * The query still goes through assertSafeFilter(), and deleting everything requires an
     * explicit second argument so a bug that produces an empty filter cannot empty the
     * index by accident.
     *
     * @param string $query           A filter built by this class's builders, or a literal
     *                                written in the source of a bin/ script.
     * @param bool   $allowDeleteAll  Must be true to permit *:*.
     * @return array<string,mixed>
     */
    public function deleteByQuery(string $core, string $query, bool $allowDeleteAll = false): array
    {
        $query = trim($query);
        if ($query === '') {
            throw new \InvalidArgumentException('Solr: refusing an empty delete query.');
        }
        if (!$allowDeleteAll && preg_match('/^\*\s*:\s*\*$/', $query)) {
            throw new \InvalidArgumentException(
                'Solr: refusing to delete every document without allowDeleteAll.'
            );
        }
        self::assertSafeFilter($query);

        $body = json_encode(['delete' => ['query' => $query]], JSON_UNESCAPED_SLASHES);

        return $this->send($core, '/update', ['commit' => 'true'], (string) $body, 'POST', 'application/json');
    }

    /**
     * Apply an atomic (partial) update to one document.
     *
     * Used by the scorer to revise a verdict without rewriting the whole session document,
     * and by the beacon merge to add timing to a session that was already indexed.
     *
     * Requires an updateLog and Real Time Get on the core — Solr implements this as a
     * read-modify-write against the transaction log. Without them, EVERY FIELD NOT NAMED
     * HERE IS BLANKED, silently. Both cores' solrconfig.xml enable them; that is why.
     *
     * Only the four modifiers Solr defines are accepted. Anything else would be
     * interpreted as a literal field named "set" or "whatever" and quietly do the wrong
     * thing. `remove-regex` is refused along with the rest: it evaluates a regex
     * server-side against every value of a field, which is a ReDoS primitive burning
     * someone else's CPU, and nothing in Loghound needs it.
     *
     * @param array<string,array<string,mixed>> $ops e.g. ['set' => ['bot_score_f' => 91.0],
     *                                                     'add' => ['bot_reasons_ss' => ['no_js_on_html']],
     *                                                     'inc' => ['hits_i' => 1]]
     * @return array<string,mixed>
     */
    public function atomicUpdate(string $core, string $id, array $ops, bool $softCommit = true): array
    {
        if ($id === '' || strlen($id) > 512) {
            throw new \InvalidArgumentException('Solr: invalid document id for atomic update.');
        }

        $doc = ['id' => $id];
        foreach ($ops as $op => $fields) {
            if (!in_array($op, ['set', 'add', 'inc', 'remove', 'removeregex', 'add-distinct'], true)) {
                throw new \InvalidArgumentException('Solr: unknown atomic update operation: ' . $op);
            }
            if ($op === 'removeregex') {
                throw new \InvalidArgumentException('Solr: removeregex is not permitted.');
            }
            foreach ((array) $fields as $field => $value) {
                if (!Security::isSafeFieldName((string) $field)) {
                    throw new \InvalidArgumentException('Solr: unsafe field name in atomic update: ' . $field);
                }
                $doc[$field][$op] = $value;
            }
        }

        $params = $softCommit ? ['softCommit' => 'true'] : [];
        $body = json_encode([$doc], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);

        return $this->send($core, '/update', $params, (string) $body, 'POST', 'application/json');
    }

    /** Last transport error message. Never contains the HTTP password. */
    public function lastError(): string
    {
        return $this->lastError;
    }

    /**
     * Quote a value for use as an exact term.
     *
     * Wrapping in double quotes and escaping backslash and quote is enough for a StrField:
     * inside quotes, Solr's query parser treats everything else literally, so the colons,
     * braces, parentheses and boolean keywords that appear constantly in User-Agent strings
     * and URLs cannot change the query's structure.
     *
     * Control characters are stripped rather than escaped — a newline in a filter would
     * split the parameter, and no legitimate term contains one.
     */
    public static function escapeTerm(string $value): string
    {
        $value = preg_replace('/[\x00-\x1F\x7F]/u', '', $value) ?? '';
        return '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $value) . '"';
    }

    /**
     * Build `field:"value"`.
     */
    public static function termFilter(string $field, string $value): string
    {
        if (!Security::isSafeFieldName($field)) {
            throw new \InvalidArgumentException('Solr: unsafe field name in filter: ' . $field);
        }
        return $field . ':' . self::escapeTerm($value);
    }

    /**
     * Build `field:("a" OR "b" OR ...)`.
     *
     * Capped at maxBooleanClauses/2 so a caller with a large list gets an exception here,
     * where the stack trace is useful, rather than a "too many boolean clauses" from Solr
     * after the request has been built.
     *
     * An empty value list produces a filter that matches NOTHING. Returning an empty string
     * instead would mean "match everything", which is the classic way an authorisation
     * filter turns into a data leak.
     *
     * @param string[] $values
     */
    public static function termsFilter(string $field, array $values): string
    {
        if (!Security::isSafeFieldName($field)) {
            throw new \InvalidArgumentException('Solr: unsafe field name in filter: ' . $field);
        }
        $values = array_values(array_unique(array_map('strval', $values)));
        if ($values === []) {
            return '(-*:*)';
        }
        if (count($values) > 512) {
            throw new \InvalidArgumentException('Solr: too many values for a terms filter (max 512).');
        }
        $quoted = array_map([self::class, 'escapeTerm'], $values);
        return $field . ':(' . implode(' OR ', $quoted) . ')';
    }

    /**
     * Build `field:[from TO to]`.
     *
     * Bounds must be a plain number, an ISO-8601 instant, a Solr date-math expression
     * (NOW-12HOURS), or '*'. Everything else is refused, because a range bound is the one
     * place in a filter where a caller legitimately supplies syntax rather than a value.
     */
    public static function rangeFilter(string $field, ?string $from, ?string $to): string
    {
        if (!Security::isSafeFieldName($field)) {
            throw new \InvalidArgumentException('Solr: unsafe field name in filter: ' . $field);
        }
        $lo = self::assertRangeBound($from);
        $hi = self::assertRangeBound($to);
        return $field . ':[' . $lo . ' TO ' . $hi . ']';
    }

    /**
     * Validate one bound of a range filter.
     *
     * Three forms are accepted and nothing else: a number, including negatives and
     * decimals; an ISO-8601 UTC instant in the form Solr writes; and Solr date math, such
     * as NOW, NOW-12HOURS, NOW/DAY, NOW-90DAYS/DAY, or an instant with math applied to it.
     */
    private static function assertRangeBound(?string $bound): string
    {
        $bound = trim((string) ($bound ?? '*'));
        if ($bound === '' || $bound === '*') {
            return '*';
        }
        if (preg_match('/^-?\d+(\.\d+)?$/', $bound)) {
            return $bound;
        }
        if (preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/', $bound)) {
            return $bound;
        }
        if (preg_match('#^(NOW|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z)([-+/]\d*[A-Z]+)*$#', $bound)) {
            return $bound;
        }
        throw new \InvalidArgumentException('Solr: invalid range bound: ' . $bound);
    }

    /**
     * Validate and normalise a parameter map before it is allowed near Solr.
     *
     * A parameter NAME is part of the request line, so anything outside a strict character
     * class could inject a second parameter or a header break and is refused.
     *
     * rows and start are clamped rather than trusted, even when they come from our own
     * code: deep paging is both a denial of service, since Solr materialises start+rows
     * documents per shard, and a pointless user experience.
     *
     * fq is flattened by hand into repeat-key parameters, because http_build_query() turns
     * a PHP list into fq[0]=..&fq[1]=.., which Solr does not understand; see send().
     *
     * sort is checked field by field against the allowlist, with `score` permitted because
     * it is a pseudo-field rather than a schema field.
     *
     * fl must be an explicit list. `*` is refused so that a bug cannot start returning
     * raw_s — and therefore the full attacker-controlled log line — into a JSON response by
     * default, and function-query pseudo-fields are refused because fl accepts them and
     * they are arbitrary server-side expressions.
     *
     * json.facet is never accepted here. jsonFacet() validates a PHP array field by field
     * and aggregate by aggregate, then attaches the serialised result AFTER this method has
     * run. A pre-built JSON blob cannot be validated, so it is refused outright — that is
     * the difference between "we check facets" and "we check facets unless someone passes a
     * string".
     *
     * @param array<string,mixed> $params
     * @return array<string,mixed>
     */
    private function sanitiseQueryParams(array $params): array
    {
        $out = [];

        foreach ($params as $key => $value) {
            $key = (string) $key;

            if (!preg_match('/^[A-Za-z0-9_.\[\]-]{1,64}$/', $key)) {
                throw new \InvalidArgumentException('Solr: illegal parameter name: ' . $key);
            }

            $lower = strtolower($key);

            if (in_array($lower, self::DENIED_PARAMS, true)) {
                throw new \InvalidArgumentException(
                    'Solr: parameter "' . $key . '" is refused; see Solr::DENIED_PARAMS for why.'
                );
            }
            foreach (self::DENIED_PREFIXES as $prefix) {
                if (str_starts_with($lower, $prefix)) {
                    throw new \InvalidArgumentException(
                        'Solr: parameter "' . $key . '" is refused (denied prefix "' . $prefix . '").'
                    );
                }
            }

            $out[$key] = $value;
        }

        $out['rows']  = Security::clampInt($out['rows'] ?? 20, 0, Security::MAX_ROWS, 20);
        $out['start'] = Security::clampInt($out['start'] ?? 0, 0, Security::MAX_START, 0);

        if (isset($out['q'])) {
            self::assertSafeQuery((string) $out['q']);
        }

        if (isset($out['fq'])) {
            $fqs = is_array($out['fq']) ? $out['fq'] : [$out['fq']];
            foreach ($fqs as $fq) {
                self::assertSafeFilter((string) $fq);
            }
            $out['fq'] = array_values($fqs);
        }

        if (isset($out['sort'])) {
            $out['sort'] = self::assertSafeSort((string) $out['sort']);
        }

        if (isset($out['fl'])) {
            $out['fl'] = self::assertSafeFieldList((string) $out['fl']);
        }

        foreach (['facet.field', 'facet.pivot', 'stats.field', 'group.field', 'df'] as $fieldParam) {
            if (!isset($out[$fieldParam])) {
                continue;
            }
            $names = is_array($out[$fieldParam]) ? $out[$fieldParam] : [$out[$fieldParam]];
            foreach ($names as $name) {
                foreach (explode(',', (string) $name) as $one) {
                    $one = trim($one);
                    if ($one !== '' && !Security::isSafeFieldName($one)) {
                        throw new \InvalidArgumentException(
                            'Solr: unsafe field name in ' . $fieldParam . ': ' . $one
                        );
                    }
                }
            }
        }

        if (array_key_exists('json.facet', $out) || array_key_exists('json', $out)) {
            throw new \InvalidArgumentException(
                'Solr: pass a JSON Facet as an array to jsonFacet(); raw json/json.facet is refused.'
            );
        }

        return $out;
    }

    /**
     * Serialise a parameter map the way Solr expects.
     *
     * http_build_query() cannot be used directly: given ['fq' => ['a', 'b']] it produces
     * `fq[0]=a&fq[1]=b`, and Solr reads that as two parameters literally named "fq[0]" and
     * "fq[1]", silently applying neither filter. A dropped filter is a data leak (the
     * unfiltered result set comes back), so this is not a cosmetic detail.
     *
     * @param array<string,mixed> $params
     */
    private static function encodeParams(array $params): string
    {
        $pairs = [];
        foreach ($params as $key => $value) {
            foreach ((is_array($value) ? $value : [$value]) as $one) {
                if (is_bool($one)) {
                    $one = $one ? 'true' : 'false';
                }
                $pairs[] = rawurlencode((string) $key) . '=' . rawurlencode((string) $one);
            }
        }
        return implode('&', $pairs);
    }

    /**
     * Validate the `q` parameter.
     *
     * Only three shapes are legal, and all three are produced by this file:
     *   *:*                      match everything
     *   {!edismax v=$uq}         bound free text
     *   a filter built by the builders above
     */
    public static function assertSafeQuery(string $q): void
    {
        $q = trim($q);
        if ($q === '*:*' || $q === '{!edismax v=$uq}') {
            return;
        }
        self::assertSafeFilter($q);
    }

    /**
     * Validate a filter query string.
     *
     * These strings are built by this class or written literally in our own source. The
     * check exists to catch the day someone concatenates a value into one by hand.
     *
     * What is refused, and what each one would do:
     *   newlines / NULs   split the parameter, or terminate it early
     *   {!...}            switch the query parser mid-filter. {!frange} evaluates a
     *                     function query (an oracle for reading any field); {!xmlparser}
     *                     parses XML (XXE); {!join} reads another core. Only the harmless
     *                     facet-exclusion tags {!tag=x} and {!ex=x} are allowed through.
     *   _query_ / _val_   the legacy magic fields that embed a nested parser in a value —
     *                     the classic Solr injection, and still live in Solr 9.
     */
    public static function assertSafeFilter(string $fq): void
    {
        if ($fq === '') {
            throw new \InvalidArgumentException('Solr: empty filter.');
        }
        if (strlen($fq) > 8192) {
            throw new \InvalidArgumentException('Solr: filter is too long.');
        }
        if (preg_match('/[\x00-\x08\x0A-\x1F\x7F]/', $fq)) {
            throw new \InvalidArgumentException('Solr: control character in filter.');
        }
        if (stripos($fq, '_query_') !== false || stripos($fq, '_val_') !== false) {
            throw new \InvalidArgumentException('Solr: nested-query magic field in filter.');
        }

        $stripped = preg_replace('/^\{!(tag|ex)=[A-Za-z0-9_,]{1,128}\}/', '', $fq) ?? $fq;
        if (str_contains($stripped, '{!')) {
            throw new \InvalidArgumentException('Solr: local parameters are not permitted in a filter.');
        }
    }

    /**
     * Validate a sort specification and return it normalised.
     *
     * Exactly "<field> <asc|desc>" is accepted. A sort clause in Solr also accepts function
     * queries, which is why nothing looser is allowed through.
     */
    public static function assertSafeSort(string $sort): string
    {
        $clauses = [];
        foreach (explode(',', $sort) as $clause) {
            $clause = trim($clause);
            if ($clause === '') {
                continue;
            }
            if (!preg_match('/^([A-Za-z0-9_]{1,64})\s+(asc|desc)$/i', $clause, $m)) {
                throw new \InvalidArgumentException('Solr: unsafe sort clause: ' . $clause);
            }
            if ($m[1] !== 'score' && !Security::isSafeFieldName($m[1])) {
                throw new \InvalidArgumentException('Solr: unsafe sort field: ' . $m[1]);
            }
            $clauses[] = $m[1] . ' ' . strtolower($m[2]);
        }
        if ($clauses === []) {
            throw new \InvalidArgumentException('Solr: empty sort specification.');
        }
        return implode(',', $clauses);
    }

    /**
     * Validate an `fl` field list and return it normalised.
     *
     * This is where `fl=*` and `fl=id,sum(a,b)` both land and are refused: the first would
     * start returning raw_s to the browser, the second is server-side evaluation of an
     * expression the caller chose.
     */
    public static function assertSafeFieldList(string $fl): string
    {
        $fields = [];
        foreach (explode(',', $fl) as $field) {
            $field = trim($field);
            if ($field === '') {
                continue;
            }
            if ($field === 'score' || $field === '[child]') {
                $fields[] = $field;
                continue;
            }
            if (!Security::isSafeFieldName($field)) {
                throw new \InvalidArgumentException('Solr: unsafe field in fl: ' . $field);
            }
            $fields[] = $field;
        }
        if ($fields === []) {
            throw new \InvalidArgumentException('Solr: empty field list.');
        }
        return implode(',', $fields);
    }

    /**
     * Validate a `qf` list and return it as a Solr-formatted string.
     *
     * @param string[] $qf Entries like 'path_txt^3'.
     */
    private function buildQf(array $qf): string
    {
        $out = [];
        foreach ($qf as $entry) {
            if (!preg_match('/^([A-Za-z0-9_]{1,64})(\^\d+(\.\d+)?)?$/', trim((string) $entry), $m)) {
                throw new \InvalidArgumentException('Solr: unsafe qf entry: ' . $entry);
            }
            $out[] = trim((string) $entry);
        }
        if ($out === []) {
            throw new \InvalidArgumentException('Solr: empty qf.');
        }
        return implode(' ', $out);
    }

    /**
     * Recursively validate a JSON Facet structure.
     *
     * Both spellings are accepted: the shorthand form, 'ips' => 'unique(ip_s)', and the
     * full array form. `func` is not a permitted type, because its own `func` slot is an
     * arbitrary function query.
     *
     * `limit` is bounded, since an unbounded terms facet on ip_s would try to return every
     * distinct address in the index in a single response. A facet `sort` names a bucket
     * ("count desc", "ips desc") rather than a schema field, so it gets the same shape
     * check but resolved against bucket names. Range facet bounds go through the same
     * validator as rangeFilter(). Of the domain options only excludeTags is allowed, which
     * is how a facet ignores its own filter.
     *
     * @param array<string,mixed> $facet
     * @param int                 $depth Guard against a hand-built structure nesting deep
     *                                   enough to blow the stack (or Solr's).
     * @return array<string,mixed>
     */
    private function sanitiseFacet(array $facet, int $depth = 0): array
    {
        if ($depth > 6) {
            throw new \InvalidArgumentException('Solr: JSON Facet nested too deeply.');
        }

        $out = [];
        foreach ($facet as $name => $spec) {
            if (!preg_match('/^[A-Za-z0-9_]{1,64}$/', (string) $name)) {
                throw new \InvalidArgumentException('Solr: unsafe facet bucket name: ' . $name);
            }

            if (is_string($spec)) {
                $out[$name] = self::assertSafeAggregate($spec);
                continue;
            }
            if (!is_array($spec)) {
                throw new \InvalidArgumentException('Solr: facet "' . $name . '" must be a string or an array.');
            }

            $type = (string) ($spec['type'] ?? 'terms');
            if (!in_array($type, self::FACET_TYPES, true)) {
                throw new \InvalidArgumentException('Solr: unsupported facet type: ' . $type);
            }
            $clean = ['type' => $type];

            if ($type === 'terms' || $type === 'range') {
                $field = (string) ($spec['field'] ?? '');
                if (!Security::isSafeFieldName($field)) {
                    throw new \InvalidArgumentException('Solr: unsafe facet field: ' . $field);
                }
                $clean['field'] = $field;
            }

            if ($type === 'query') {
                $q = (string) ($spec['q'] ?? '');
                self::assertSafeFilter($q);
                $clean['q'] = $q;
            }

            if (isset($spec['limit'])) {
                $clean['limit'] = Security::clampInt($spec['limit'], -1, 10000, 10);
            }
            if (isset($spec['mincount'])) {
                $clean['mincount'] = Security::clampInt($spec['mincount'], 0, 1000000, 1);
            }
            if (isset($spec['offset'])) {
                $clean['offset'] = Security::clampInt($spec['offset'], 0, 100000, 0);
            }
            if (isset($spec['sort'])) {
                if (!preg_match('/^[A-Za-z0-9_]{1,64}\s+(asc|desc)$/i', (string) $spec['sort'])) {
                    throw new \InvalidArgumentException('Solr: unsafe facet sort: ' . $spec['sort']);
                }
                $clean['sort'] = (string) $spec['sort'];
            }

            foreach (['start', 'end'] as $bound) {
                if (isset($spec[$bound])) {
                    $clean[$bound] = self::assertRangeBound((string) $spec[$bound]);
                }
            }
            if (isset($spec['gap'])) {
                if (!preg_match('/^[-+]?\d*[A-Za-z]*$/', (string) $spec['gap'])) {
                    throw new \InvalidArgumentException('Solr: unsafe facet gap: ' . $spec['gap']);
                }
                $clean['gap'] = (string) $spec['gap'];
            }

            if (isset($spec['domain']) && is_array($spec['domain'])) {
                $tags = $spec['domain']['excludeTags'] ?? null;
                if ($tags !== null) {
                    $tags = is_array($tags) ? $tags : [$tags];
                    foreach ($tags as $tag) {
                        if (!preg_match('/^[A-Za-z0-9_]{1,64}$/', (string) $tag)) {
                            throw new \InvalidArgumentException('Solr: unsafe excludeTag: ' . $tag);
                        }
                    }
                    $clean['domain'] = ['excludeTags' => array_values(array_map('strval', $tags))];
                }
            }

            if (isset($spec['facet']) && is_array($spec['facet'])) {
                $clean['facet'] = $this->sanitiseFacet($spec['facet'], $depth + 1);
            }

            $out[$name] = $clean;
        }

        if ($out === []) {
            throw new \InvalidArgumentException('Solr: empty facet structure.');
        }
        return $out;
    }

    /**
     * Validate a facet aggregate expression such as `unique(ip_s)` or `avg(engaged_ms_l)`.
     */
    private static function assertSafeAggregate(string $agg): string
    {
        $agg = trim($agg);
        if ($agg === 'count') {
            return 'count';
        }
        if (!preg_match('/^([a-z]+)\(([A-Za-z0-9_]{1,64})(,\s*\d+(\.\d+)?)*\)$/', $agg, $m)) {
            throw new \InvalidArgumentException('Solr: unsafe facet aggregate: ' . $agg);
        }
        if (!in_array($m[1], self::FACET_AGGS, true)) {
            throw new \InvalidArgumentException('Solr: facet aggregate not on the allowlist: ' . $m[1]);
        }
        if (!Security::isSafeFieldName($m[2])) {
            throw new \InvalidArgumentException('Solr: unsafe field in facet aggregate: ' . $m[2]);
        }
        return $agg;
    }

    /**
     * Normalise free text before binding it as `uq`.
     *
     * The bound-parameter form already prevents this text from escaping into another
     * parameter. Two things are still done here:
     *
     *  1. A leading "{!..." is stripped. The value of `v` is handed to edismax as its query
     *     string and edismax does not re-dispatch on local params, so this is belt and
     *     braces — but this exact pattern has bitten the Opensolr search stack before on
     *     other code paths, and the cost of stripping it is zero.
     *  2. Control characters go, and the length is capped. A 2 MB search term is a CPU
     *     attack on the analyser, not a search.
     */
    private function normaliseUserText(string $text): string
    {
        $text = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', ' ', $text) ?? '';
        $text = trim($text);
        while (preg_match('/^\{![^}]*\}/', $text)) {
            $text = trim((string) preg_replace('/^\{![^}]*\}/', '', $text));
        }
        if (mb_strlen($text) > 512) {
            $text = mb_substr($text, 0, 512);
        }
        return $text;
    }

    /**
     * Send one request, with retries.
     *
     * Every write this class performs is idempotent — hit ids are sha1(file+offset),
     * session ids are deterministic, rollup ids encode the day — so retrying a request
     * whose response was lost cannot duplicate data. That is what makes a blind retry
     * correct here; it would not be for an API with auto-generated ids.
     *
     * The core name is validated because it becomes a path segment: without that check a
     * core name of "../../admin/cores" would reach the core admin API. wt=json is forced on
     * every request rather than taken from the caller — it is in DENIED_PARAMS — so the
     * response is always something json_decode() understands.
     *
     * A transport failure, a rate limit or a server error is retried; a 4xx is NOT. A 400
     * means the request itself is wrong, and sending it again three times only makes the
     * log noisier. Backoff is exponential with jitter, and the jitter matters when several
     * Loghound daemons share a Solr node: without it they all retry in lockstep and
     * re-create the overload they are backing off from.
     *
     * A failure surfaces Solr's own message, which is genuinely useful ("unknown field x"),
     * but never the request body: that body contains log lines, which are hostile text, and
     * this message ends up in a log file and possibly on a screen.
     *
     * @param array<string,mixed> $queryParams Parameters that go in the URL.
     * @param string|null         $body        Request body, already encoded.
     * @return array<string,mixed>             Decoded JSON response.
     */
    private function send(
        string $core,
        string $path,
        array $queryParams,
        ?string $body,
        string $method = 'POST',
        string $contentType = 'application/json'
    ): array {
        if (!Security::isSafeCoreName($core)) {
            throw new \InvalidArgumentException('Solr: unsafe core name: ' . $core);
        }
        if ($this->baseUrl === '') {
            throw new \RuntimeException('Solr: no base_url configured. Run loghound-setup.');
        }

        $queryParams['wt'] = 'json';

        $url = $this->baseUrl . '/' . $core . $path;
        if ($queryParams !== []) {
            $url .= '?' . self::encodeParams($queryParams);
        }

        $headers = ['Content-Type: ' . $contentType, 'Accept: application/json'];

        $attempt = 0;
        $lastStatus = 0;
        $lastBody = '';

        while ($attempt < $this->maxAttempts) {
            $attempt++;

            $res = ($this->transport)([
                'method'          => $method,
                'url'             => $url,
                'headers'         => $headers,
                'body'            => $body,
                'timeout'         => $this->timeout,
                'connect_timeout' => $this->connectTimeout,
                'user'            => $this->httpUser,
                'pass'            => $this->httpPass,
            ]);

            $lastStatus = (int) ($res['status'] ?? 0);
            $lastBody   = (string) ($res['body'] ?? '');
            $this->lastError = (string) ($res['error'] ?? '');

            $retryable = ($lastStatus === 0 || $lastStatus === 429 || $lastStatus >= 500);
            if (!$retryable) {
                break;
            }
            if ($attempt < $this->maxAttempts) {
                $sleepUs = (int) (150000 * (4 ** ($attempt - 1)));
                usleep($sleepUs + random_int(0, 50000));
            }
        }

        if ($lastStatus === 0) {
            throw new \RuntimeException('Solr: transport failure after ' . $attempt . ' attempts: ' . $this->lastError);
        }

        $decoded = json_decode($lastBody, true);
        if (!is_array($decoded)) {
            throw new \RuntimeException('Solr: HTTP ' . $lastStatus . ' with an unparseable body.');
        }

        if ($lastStatus >= 400) {
            $msg = $decoded['error']['msg'] ?? ('HTTP ' . $lastStatus);
            throw new \RuntimeException('Solr: ' . $msg);
        }

        return $decoded;
    }

    /**
     * Default curl transport.
     *
     * Static and parameter-driven so a test can substitute a closure with the same shape.
     * Nothing here logs, echoes, or throws with the password in the message.
     *
     * Redirects are never followed. A Solr node that answers 302 is not a Solr node, and
     * following it would send the basic-auth credentials to wherever it points. Certificate
     * verification stays on for the same reason: those credentials travel in every request,
     * and a downgraded connection hands them over. gzip is accepted because facet responses
     * compress well.
     *
     * There is deliberately no curl_close(). It has been a no-op since PHP 8.0, where the
     * handle became an object freed when it goes out of scope, and PHP 8.5 emits a
     * deprecation for it — on a daemon making thousands of requests a minute, that is
     * thousands of lines of noise in the journal.
     *
     * @param array<string,mixed> $req
     * @return array{status:int,body:string,error:string}
     */
    public static function curlTransport(array $req): array
    {
        $ch = curl_init();

        curl_setopt_array($ch, [
            CURLOPT_URL            => $req['url'],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST  => $req['method'],
            CURLOPT_HTTPHEADER     => $req['headers'],
            CURLOPT_TIMEOUT        => $req['timeout'],
            CURLOPT_CONNECTTIMEOUT => $req['connect_timeout'],
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_ENCODING       => '',
        ]);

        if ($req['body'] !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $req['body']);
        }
        if (($req['user'] ?? '') !== '') {
            curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
            curl_setopt($ch, CURLOPT_USERPWD, $req['user'] . ':' . $req['pass']);
        }

        $body   = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $error  = curl_error($ch);

        unset($ch);

        return [
            'status' => $status,
            'body'   => is_string($body) ? $body : '',
            'error'  => $error,
        ];
    }
}
