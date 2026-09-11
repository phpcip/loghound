<?php
/**
 * Loghound — Opensolr request-log client.
 *
 * WHAT THIS IS. The read side of the Opensolr platform's analytics shards, reached through
 * one endpoint: GET /solr_manager/api/request_log. It answers "what is happening to this
 * customer's search indexes" — request volume, QTime, hit counts, status codes, which node
 * served what — for the account whose email and API key are in config/loghound.php.
 *
 * WHAT THIS IS NOT, AND WILL NEVER BE. Loghound does not touch a Solr server for any of
 * this. No agent, no log file, no SSH, no log4j2 parsing, no second copy of the customer's
 * query log. The platform already indexes this data and already enforces ownership on it;
 * asking the platform is the whole design. It means there is no format to detect, no
 * volume problem to solve, no tenant isolation for Loghound to get wrong, and nothing
 * Loghound can be blamed for on a customer's node.
 *
 * ---------------------------------------------------------------------------------------
 * THE API KEY
 * ---------------------------------------------------------------------------------------
 * Identical discipline to \Loghound\Opensolr, and for the same reason: the key is a full
 * account credential. It is added to a request in exactly one place (buildUrl()), it never
 * reaches HTML, a hidden field, a browser-visible URL, a job payload, a log line or an
 * exception message, and every string that can escape this class passes through redact()
 * first. The platform echoes request parameters back in some error bodies, and one of
 * those parameters is the key.
 *
 * ---------------------------------------------------------------------------------------
 * FAILURE IS A STATE, NOT AN EXCEPTION
 * ---------------------------------------------------------------------------------------
 * Nothing here throws for an outcome the operator can be shown. An index the account does
 * not own, an unreachable control plane, a missing credential and a garbled response are
 * four different things the panel has to say out loud, so every one of them comes back as
 * a `state` with a sentence attached. Only a programming error — a field name that is not
 * a field name, a filter this class did not build — throws, because that is a bug rather
 * than a condition.
 *
 * ---------------------------------------------------------------------------------------
 * WHAT REACHES THE PLATFORM
 * ---------------------------------------------------------------------------------------
 * Callers do not hand over Solr parameters. They hand over a validated structure, and this
 * class turns it into the wire format. Two upstream behaviours make that mandatory rather
 * than tidy:
 *
 *  - The endpoint maps any parameter name containing an underscore onto a dotted Solr
 *    parameter (`facet_field` becomes `facet.field`), and it sanitises the VALUE of every
 *    such parameter down to `[a-zA-Z0-9_@+\-.:(),/ ]`. So a JSON Facet structure cannot
 *    survive the trip — its braces and quotes are stripped — and classic faceting is the
 *    only aggregation available here. Range facets survive, because their values are plain.
 *  - Parameters whose name has no underscore (`q`, `fq`, `sort`, `fl`, `rows`) are passed
 *    through untouched. Those are the ones that must be built by this class from constants
 *    and escaped literals, never assembled from a request.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound;

final class OpensolrLog
{
    /** Hard ceiling on documents per call, whatever a caller asks for. */
    public const MAX_ROWS = 500;

    /** Hard ceiling on the paging offset. Deep paging is a cost with no reader. */
    public const MAX_START = 20000;

    /** Hard ceiling on terms returned by one facet. */
    public const MAX_FACET_LIMIT = 200;

    /** Longest filter query this class will emit. */
    private const MAX_FQ_BYTES = 4096;

    /**
     * Sort specifications the panel may ask for, mapped to the literal string sent.
     *
     * A map rather than a field-plus-direction pair: the value that reaches the platform
     * is one of these constants and can never be assembled from input.
     *
     * @var array<string,string>
     */
    private const SORTS = [
        'recent'   => 'date desc',
        'oldest'   => 'date asc',
        'slowest'  => 'qtime desc',
        'biggest'  => 'size desc',
        'fewest'   => 'hits asc',
    ];

    /** The document fields this client is willing to ask for. */
    private const FIELDS = [
        'core_name', 'date', 'timestamp_unix', 'ip', 'path', 'q',
        'hits', 'qtime', 'http_status', 'size', 'param_hostname', 'full_request',
    ];

    private string $apiBase;

    private string $email;

    private string $apiKey;

    /**
     * Total request timeout in seconds.
     *
     * Deliberately well under the reference install's PHP-FPM `max_execution_time = 60`,
     * because the busiest action on these views makes two calls in one request and both
     * have to fit inside it with room to spare. An outbound call with no timeout is how a
     * panel turns a slow third party into a dead tab.
     */
    private int $timeout;

    /** @var callable Transport, injectable so tests run with no network. */
    private $transport;

    /**
     * @var array<string,array<string,mixed>> Per-request memo, keyed by the request shape.
     *
     * Deliberately in memory and deliberately per request. Nothing about a customer's
     * query log is written to disk by Loghound: it is already indexed on the platform, a
     * second copy would be waste, and query text plus client IPs is the last thing that
     * should acquire another home. A card that is drawn twice in one request costs one
     * call; a card drawn on the next request costs another, which is the correct trade.
     */
    private array $memo = [];

    /**
     * @param array<string,mixed> $cfg       The 'opensolr' section of the config.
     * @param callable|null       $transport fn(array $req): array{status:int,body:string,error:string}
     */
    public function __construct(array $cfg, ?callable $transport = null)
    {
        $this->apiBase = rtrim((string) ($cfg['api_base'] ?? Opensolr::DEFAULT_API_BASE), '/');
        $this->email   = (string) ($cfg['email'] ?? '');
        $this->apiKey  = (string) ($cfg['api_key'] ?? '');
        $this->timeout = Security::clampInt($cfg['log_timeout'] ?? null, 5, 30, 18);

        $this->transport = $transport ?? [Solr::class, 'curlTransport'];
    }

    /**
     * Are there credentials to call with at all?
     *
     * The panel asks before it renders, so an installation with no Opensolr account gets
     * an explanation of what the section would show rather than a view full of failures.
     */
    public function isConfigured(): bool
    {
        return $this->email !== '' && $this->apiKey !== '';
    }

    /**
     * The sort keys a caller may name.
     *
     * @return array<int,string>
     */
    public static function sortKeys(): array
    {
        return array_keys(self::SORTS);
    }

    /**
     * Query the request log for one index.
     *
     * @param array<string,mixed> $opt {
     *     fq:            string[]  Filters built by the builders on this class.
     *     sort:          string    A key of self::SORTS.
     *     rows, start:   int       Clamped here, again, whatever the caller did.
     *     fl:            string[]  Field names, from self::FIELDS.
     *     facet_fields:  string[]  Field names to facet.
     *     facet_limit:   int
     *     ranges:        array<string,array{start:string,end:string,gap:string,other?:string}>
     *     stats_fields:  string[]  Numeric field names for min/max/mean.
     * }
     * @return array<string,mixed> See shapeOk() and fail() for the exact envelope.
     */
    public function log(string $core, array $opt): array
    {
        if (!$this->isConfigured()) {
            return self::fail(
                'not_configured',
                'No Opensolr account is configured, so there is nothing to read the request log from.'
            );
        }
        if (!Security::isSafeCoreName($core)) {
            return self::fail('refused', 'That is not a valid Opensolr index name.');
        }

        $params = $this->buildParams($opt);
        $key = sha1($core . '|' . serialize($params));
        if (isset($this->memo[$key])) {
            return $this->memo[$key];
        }

        $params['core_name'] = $core;
        $result = $this->send($params);
        $this->memo[$key] = $result;

        return $result;
    }

    /**
     * Build the wire parameters from a validated option structure.
     *
     * Every branch below either produces a value this class chose or throws. There is no
     * path by which a caller-supplied string becomes a parameter name.
     *
     * `facet.mincount` is forced to 1 by the platform, so a facet never reports a term
     * with a zero count and the panel does not have to filter empties out.
     *
     * @param array<string,mixed> $opt
     * @return array<string,mixed>
     */
    private function buildParams(array $opt): array
    {
        $params = [
            'q'     => '*:*',
            'rows'  => Security::clampInt($opt['rows'] ?? null, 0, self::MAX_ROWS, 0),
            'start' => Security::clampInt($opt['start'] ?? null, 0, self::MAX_START, 0),
        ];

        $fqs = [];
        foreach ((array) ($opt['fq'] ?? []) as $fq) {
            $fq = (string) $fq;
            self::assertSafeFq($fq);
            $fqs[] = $fq;
        }
        if ($fqs !== []) {
            $params['fq'] = $fqs;
        }

        $sort = (string) ($opt['sort'] ?? '');
        if ($sort !== '') {
            if (!isset(self::SORTS[$sort])) {
                throw new \InvalidArgumentException('OpensolrLog: unknown sort key: ' . $sort);
            }
            $params['sort'] = self::SORTS[$sort];
        }

        $fl = self::assertFields((array) ($opt['fl'] ?? []));
        if ($fl !== []) {
            $params['fl'] = implode(',', $fl);
        }

        $facetFields = self::assertFields((array) ($opt['facet_fields'] ?? []));
        $ranges = (array) ($opt['ranges'] ?? []);

        if ($facetFields !== [] || $ranges !== []) {
            $params['facet'] = 'true';
        }
        if ($facetFields !== []) {
            $params['facet_field'] = $facetFields;
            $params['facet_limit'] = Security::clampInt(
                $opt['facet_limit'] ?? null,
                1,
                self::MAX_FACET_LIMIT,
                25
            );
            $params['facet_sort'] = 'count';
        }
        foreach ($ranges as $field => $def) {
            $field = (string) $field;
            self::assertFields([$field]);
            $params['facet_range'][] = $field;
            $params['f_' . $field . '_facet_range_start'] = self::assertBound((string) ($def['start'] ?? ''));
            $params['f_' . $field . '_facet_range_end']   = self::assertBound((string) ($def['end'] ?? ''));
            $params['f_' . $field . '_facet_range_gap']   = self::assertBound((string) ($def['gap'] ?? ''));
            $params['f_' . $field . '_facet_range_other'] = self::assertBound((string) ($def['other'] ?? 'all'));
            $params['f_' . $field . '_facet_mincount']    = '0';
        }

        $statsFields = self::assertFields((array) ($opt['stats_fields'] ?? []));
        if ($statsFields !== []) {
            $params['stats'] = 'true';
            $params['stats_field'] = $statsFields;
        }

        return $params;
    }

    /**
     * Perform one call and decode it into the envelope every caller reads.
     *
     * @param array<string,mixed> $params
     * @return array<string,mixed>
     */
    private function send(array $params): array
    {
        try {
            $res = ($this->transport)([
                'method'          => 'GET',
                'url'             => $this->buildUrl($params),
                'headers'         => ['Accept: application/json'],
                'body'            => null,
                'timeout'         => $this->timeout,
                'connect_timeout' => 5,
                'user'            => '',
                'pass'            => '',
            ]);
        } catch (\Throwable $e) {
            return self::fail('unreachable', $this->redact($e->getMessage()));
        }

        $status = (int) ($res['status'] ?? 0);
        $body   = (string) ($res['body'] ?? '');

        if ($status === 0) {
            return self::fail(
                'unreachable',
                'The Opensolr API did not answer: ' . $this->redact((string) ($res['error'] ?? 'no response'))
                . ' Check outbound HTTPS from this host.'
            );
        }
        if ($status >= 500) {
            return self::fail('unreachable', 'The Opensolr API answered HTTP ' . $status . '.');
        }

        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            return self::fail(
                'unreachable',
                'The Opensolr API answered HTTP ' . $status . ' with something that was not JSON.'
            );
        }

        $refusal = self::refusalOf($decoded);
        if ($refusal !== null) {
            return $refusal;
        }
        if (!isset($decoded['response']) || !is_array($decoded['response'])) {
            return self::fail('unreachable', 'The Opensolr API answered without a result set.');
        }

        return self::shapeOk($decoded);
    }

    /**
     * Recognise the platform's own refusals, which arrive with HTTP 200.
     *
     * ERROR_NOT_CORE_OWNER is a NORMAL outcome, not a crash: it is what the platform says
     * when the panel asks about an index the account does not own, which happens whenever
     * a stale bookmark, a renamed index or a scoped API key is in play. It is matched on a
     * substring so a future rewording does not turn a clear message into "unreachable".
     *
     * @param array<string,mixed> $decoded
     * @return array<string,mixed>|null
     */
    private static function refusalOf(array $decoded): ?array
    {
        if (!array_key_exists('msg', $decoded) || isset($decoded['response'])) {
            return null;
        }
        $msg = is_string($decoded['msg']) ? $decoded['msg'] : (string) json_encode($decoded['msg']);

        if (stripos($msg, 'NOT_CORE_OWNER') !== false || stripos($msg, 'NOT_OWNER') !== false) {
            return self::fail(
                'not_owner',
                'This Opensolr account does not own that index, so the platform will not show its '
                . 'request log. Pick another index, or check the credentials in config/loghound.php.'
            );
        }
        if (stripos($msg, 'INVALID_CORE_NAME') !== false) {
            return self::fail('not_owner', 'The platform does not recognise that index name.');
        }
        if (stripos($msg, 'INVALID_USER_ID') !== false || stripos($msg, 'API_KEY') !== false) {
            return self::fail(
                'refused',
                'Opensolr rejected the account credentials. Check opensolr.email and opensolr.api_key.'
            );
        }
        if (stripos($msg, 'ERROR') !== false) {
            return self::fail('refused', 'Opensolr refused the request.');
        }
        return null;
    }

    /**
     * Normalise a Solr response into the flat shape the panel reads.
     *
     * Classic faceting returns terms as a flat alternating list; range facets return their
     * counts the same way. Both are turned into maps here, once, so no controller has to
     * know that and no controller can get the parity wrong.
     *
     * @param array<string,mixed> $decoded
     * @return array<string,mixed>
     */
    private static function shapeOk(array $decoded): array
    {
        $response = (array) $decoded['response'];

        $facetFields = [];
        foreach ((array) ($decoded['facet_counts']['facet_fields'] ?? []) as $field => $flat) {
            $facetFields[(string) $field] = self::pairs((array) $flat);
        }

        $facetRanges = [];
        foreach ((array) ($decoded['facet_counts']['facet_ranges'] ?? []) as $field => $def) {
            $def = (array) $def;
            $facetRanges[(string) $field] = [
                'counts'  => self::pairs((array) ($def['counts'] ?? [])),
                'gap'     => (string) ($def['gap'] ?? ''),
                'start'   => (string) ($def['start'] ?? ''),
                'end'     => (string) ($def['end'] ?? ''),
                'before'  => isset($def['before']) ? (int) $def['before'] : null,
                'after'   => isset($def['after']) ? (int) $def['after'] : null,
                'between' => isset($def['between']) ? (int) $def['between'] : null,
            ];
        }

        $stats = [];
        foreach ((array) ($decoded['stats']['stats_fields'] ?? []) as $field => $def) {
            $def = (array) $def;
            $stats[(string) $field] = [
                'count' => isset($def['count']) ? (int) $def['count'] : null,
                'min'   => is_numeric($def['min'] ?? null) ? (float) $def['min'] : null,
                'max'   => is_numeric($def['max'] ?? null) ? (float) $def['max'] : null,
                'mean'  => is_numeric($def['mean'] ?? null) ? (float) $def['mean'] : null,
                'sum'   => is_numeric($def['sum'] ?? null) ? (float) $def['sum'] : null,
            ];
        }

        return [
            'state'        => 'ok',
            'message'      => '',
            'numFound'     => (int) ($response['numFound'] ?? 0),
            'start'        => (int) ($response['start'] ?? 0),
            'docs'         => array_values(array_filter((array) ($response['docs'] ?? []), 'is_array')),
            'facet_fields' => $facetFields,
            'facet_ranges' => $facetRanges,
            'stats'        => $stats,
        ];
    }

    /**
     * Turn Solr's alternating [value, count, value, count] list into a map.
     *
     * Values are cast to string because a facet on a numeric field returns numbers, and a
     * PHP array indexed by them would silently reorder and collide with string keys.
     *
     * @param array<int|string,mixed> $flat
     * @return array<string,int>
     */
    private static function pairs(array $flat): array
    {
        $out = [];
        $values = array_values($flat);
        for ($i = 0; $i + 1 < count($values); $i += 2) {
            if (is_array($values[$i]) || is_array($values[$i + 1])) {
                continue;
            }
            $out[(string) $values[$i]] = (int) $values[$i + 1];
        }
        return $out;
    }

    /**
     * The failure envelope, identical in shape to a success so callers never branch on
     * whether a key exists.
     *
     * @return array<string,mixed>
     */
    private static function fail(string $state, string $message): array
    {
        return [
            'state'        => $state,
            'message'      => $message,
            'numFound'     => 0,
            'start'        => 0,
            'docs'         => [],
            'facet_fields' => [],
            'facet_ranges' => [],
            'stats'        => [],
        ];
    }

    /**
     * Assemble the request URL, and the only place credentials enter a request.
     *
     * Built by hand rather than with http_build_query() because a repeated parameter has
     * to arrive as `fq[]=a&fq[]=b`: the endpoint reads its arrays that way, and PHP's own
     * builder would emit `fq[0]=`/`fq[1]=` indices that the dotted-name rewrite upstream
     * turns into something else entirely.
     *
     * @param array<string,mixed> $params
     */
    private function buildUrl(array $params): string
    {
        $params['email']   = $this->email;
        $params['api_key'] = $this->apiKey;

        $parts = [];
        foreach ($params as $key => $value) {
            if (is_array($value)) {
                foreach ($value as $item) {
                    $parts[] = rawurlencode((string) $key) . '%5B%5D=' . rawurlencode((string) $item);
                }
                continue;
            }
            $parts[] = rawurlencode((string) $key) . '=' . rawurlencode((string) $value);
        }

        return $this->apiBase . '/request_log?' . implode('&', $parts);
    }

    /**
     * Remove anything secret-shaped from a string before it is shown, stored or logged.
     *
     * The last line of defence, not the first. The key travels in a query string, so a
     * transport error can quote the URL it failed on, and an error body can echo the
     * request back.
     */
    private function redact(string $text): string
    {
        if ($this->apiKey !== '') {
            $text = str_replace($this->apiKey, '[redacted]', $text);
        }
        $text = (string) preg_replace('/(api_key|apikey|token|secret|password)=[^&\s"\']*/i', '$1=[redacted]', $text);
        return (string) preg_replace('#(https?://)[^/@\s:]+:[^/@\s]+@#i', '$1[redacted]@', $text);
    }

    /* ---------------------------------------------------------------------------------
     * Filter builders. Every fq the panel sends comes out of one of these.
     * ------------------------------------------------------------------------------ */

    /**
     * `date:[start TO end]` over Solr date math.
     *
     * Bounds must be date math or an ISO instant, and are validated rather than trusted,
     * because a range bound is the one place in a filter where syntax is legitimate.
     */
    public static function dateFq(string $start, string $end = 'NOW'): string
    {
        return 'date:[' . self::assertBound($start) . ' TO ' . self::assertBound($end) . ']';
    }

    /**
     * `field:[from TO to]` for a numeric field, with `*` permitted at either end.
     */
    public static function numericFq(string $field, string $from, string $to): string
    {
        self::assertFields([$field]);
        return $field . ':[' . self::assertBound($from) . ' TO ' . self::assertBound($to) . ']';
    }

    /**
     * `field:"value"` with the value escaped into a literal.
     *
     * Backslash and double quote are the only characters that can terminate a quoted
     * phrase, so escaping those two and wrapping makes any byte sequence a literal —
     * including an IP that is not an IP and a path full of Lucene operators.
     */
    public static function termFq(string $field, string $value): string
    {
        self::assertFields([$field]);
        return $field . ':' . self::quote($value);
    }

    /**
     * `field:("a" OR "b" ...)`, capped so one filter cannot become a denial of service.
     *
     * @param array<int,string> $values
     */
    public static function termsFq(string $field, array $values): string
    {
        self::assertFields([$field]);
        $values = array_values(array_unique(array_map('strval', $values)));
        if ($values === []) {
            return '-*:*';
        }
        if (count($values) > 200) {
            $values = array_slice($values, 0, 200);
        }
        return $field . ':(' . implode(' OR ', array_map([self::class, 'quote'], $values)) . ')';
    }

    /** Escape a literal into a quoted Solr term. */
    public static function quote(string $value): string
    {
        return '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $value) . '"';
    }

    /**
     * Refuse anything in a filter that this class did not put there.
     *
     * `{!` switches the query parser mid-filter, which is the classic Solr injection and
     * reaches {!frange} (a function-query oracle), {!join} (another core) and
     * {!xmlparser} (XXE). `_query_`/`_val_` are the legacy magic fields that do the same
     * thing from inside a value. Control characters split or truncate the parameter.
     *
     * @throws \InvalidArgumentException when the filter was not built here.
     */
    public static function assertSafeFq(string $fq): void
    {
        if ($fq === '') {
            throw new \InvalidArgumentException('OpensolrLog: empty filter.');
        }
        if (strlen($fq) > self::MAX_FQ_BYTES) {
            throw new \InvalidArgumentException('OpensolrLog: filter is too long.');
        }
        if (preg_match('/[\x00-\x1F\x7F]/', $fq)) {
            throw new \InvalidArgumentException('OpensolrLog: control character in filter.');
        }
        if (str_contains($fq, '{!')) {
            throw new \InvalidArgumentException('OpensolrLog: local parameters are not permitted in a filter.');
        }
        if (stripos($fq, '_query_') !== false || stripos($fq, '_val_') !== false) {
            throw new \InvalidArgumentException('OpensolrLog: nested-query magic field in filter.');
        }
    }

    /**
     * Validate field names against the fields this client knows exist.
     *
     * An allowlist rather than a character-class check: a name that passes `[A-Za-z0-9_]`
     * but is not a field in the analytics schema is a caller bug, and it would come back
     * from the platform as a silent empty facet that looks like "no traffic".
     *
     * @param array<int,string> $fields
     * @return array<int,string>
     */
    private static function assertFields(array $fields): array
    {
        $out = [];
        foreach ($fields as $field) {
            $field = (string) $field;
            if (!in_array($field, self::FIELDS, true)) {
                throw new \InvalidArgumentException('OpensolrLog: unknown log field: ' . $field);
            }
            $out[] = $field;
        }
        return array_values(array_unique($out));
    }

    /**
     * Validate a range bound, gap or facet keyword.
     *
     * The character class is the intersection of what Solr date math and numeric bounds
     * need with what the endpoint's own sanitiser leaves intact, so a bound that passes
     * here is a bound that arrives unchanged.
     */
    private static function assertBound(string $value): string
    {
        if (!preg_match('#^[A-Za-z0-9_+\-./: *]{1,40}$#D', $value)) {
            throw new \InvalidArgumentException('OpensolrLog: unsafe range bound.');
        }
        return $value;
    }
}
