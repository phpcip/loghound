<?php
/**
 * Loghound — Session explorer.
 *
 * The one view that returns documents rather than aggregates, and therefore the one that
 * needs the most care:
 *
 *  - The search box is free text from a browser. It is bound as the Solr parameter `uq`
 *    and referenced as `{!edismax ... v=$uq}` — never concatenated into `q`. Any
 *    `{!localparam}` block is stripped first so the parser cannot be switched.
 *  - Facet filters arrive as `f[field][]=value`. The field must be in
 *    Query::filterFields(); the value is quoted and escaped by Query::term/quote.
 *  - `rows` and `start` are clamped on every request (Security::clampInt, and
 *    Security::MAX_ROWS/MAX_START as the ceiling).
 *  - `sort` is a key into a map of literal sort strings, not a field plus a direction.
 *  - `fl` is an explicit allowlist (Query::sessionFl / hitFl), never `*`.
 *
 * Every value that comes back is attacker-controlled — paths, User-Agents and referers
 * are whatever the client on the wire chose to send — so the browser renders all of it
 * with textContent, and any referer shown as a link goes through Security::safeUrl on
 * the way out of PHP.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Security;

final class Sessions extends Controller
{
    /** Page size ceiling for the session list. */
    private const MAX_ROWS = 100;

    /** Hard cap on hits returned for one session's timeline. */
    private const MAX_TIMELINE = 300;

    /** Recent sessions listed inside a dimension's detail dialog. */
    private const DIMENSION_VISITORS = 12;

    /** Values shown per nested breakdown inside a dimension's detail dialog. */
    private const DIMENSION_BUCKETS = 8;

    /** Values listed per dimension in the filter bar's browse panel. */
    private const BROWSE_BUCKETS = 12;

    /**
     * Values returned for one dimension when the operator asks to see all of them.
     *
     * Bounded rather than unbounded: `limit: -1` on a terms facet asks Solr to enumerate every
     * distinct value a field has ever held, which on an AS organisation field is tens of
     * thousands of buckets built to populate a list nobody will read past the first screen of.
     * Two hundred covers every long tail worth browsing and the browser filters within it.
     */
    private const ALL_BUCKETS = 200;

    /**
     * Fields the detail dialog may open, on top of the filterable set.
     *
     * THESE ARE READ-ONLY DRILL-DOWNS, NOT FILTERS, and the difference is deliberate rather
     * than a workaround. Query::filterFields() is the server's filter allowlist and it is the
     * only thing Controller::readFilters() honours, so a value in one of the fields below can
     * be INSPECTED but cannot be turned into a `?f[…]` chip — and identity.js renders it as
     * plain text rather than as a link that would silently do nothing.
     *
     * Every one of them ought to be filterable and none of them is: `paths_ss` is what makes a
     * top-pages row openable at all, `asn_i` is the number every network table prints, `city_s`
     * and `region_s` are on the document and shown, and `ua_bot_name_s` is the crawler's own
     * name. They belong in Query::filterFields(), which is owned elsewhere; until they are
     * there this list is what lets the dialog answer for them honestly.
     *
     * @return array<string,string> field => label
     */
    private static function detailOnlyFields(): array
    {
        return [
            'paths_ss'       => 'Path',
            'asn_i'          => 'ASN',
            'city_s'         => 'City',
            'region_s'       => 'Region',
            'ua_bot_name_s'  => 'Declared crawler',
        ];
    }

    /**
     * Every dimension whose detail dialog can be opened.
     *
     * The filterable set plus the read-only additions above. `session_id_s` is excluded
     * because a session is not a dimension — it has its own dialog, reached with `detail`.
     *
     * @return array<string,string> field => label
     */
    private static function dimensionFields(): array
    {
        $out = array_merge(Query::filterFields(), self::detailOnlyFields());
        unset($out['session_id_s']);
        return $out;
    }

    /**
     * Dimensions the filter bar offers as a browsable list of values with counts.
     *
     * Restricted to the FILTERABLE set, because the panel's whole purpose is picking a filter
     * from a distribution, and to fields whose cardinality makes a top-12 list mean something.
     *
     * `ip_s` and `session_id_s` are left out on purpose. Both are identity lookups rather than
     * distributions — "the twelve busiest addresses" is not a dimension anybody browses by, and
     * a terms facet over addresses across a ninety-day window asks Solr to enumerate a field
     * with a bucket per visitor. Both are reached by clicking the row that names them.
     *
     * @return array<string,string> field => label
     */
    private static function browseFields(): array
    {
        $out = Query::filterFields();
        unset($out['ip_s'], $out['session_id_s']);
        return $out;
    }

    /** Dimensions rendered in a monospace list, because the value is an identifier. */
    private const MONO_FIELDS = ['netname_s', 'fp_hash_s', 'host_s', 'sec_ch_ua_s', 'tls_proto_s', 'paths_ss'];

    public function slug(): string
    {
        return 'sessions';
    }

    public function title(): string
    {
        return 'Session explorer';
    }

    public function subtitle(): string
    {
        return 'Search every session, then open one and watch it happen request by request.';
    }

    /**
     * @return array<string,mixed>
     */
    public function api(string $action): array
    {
        return match ($action) {
            'list'       => $this->list(),
            'facets'     => $this->facets(),
            'detail'     => $this->detail(),
            'dimension'  => $this->dimension(),
            'dimensions' => $this->dimensions(),
            'values'     => $this->values(),
            default      => ['error' => 'Unknown action'],
        };
    }

    /**
     * A page of matching sessions.
     *
     * Its own request, separate from the facet sidebar, so the table appears as soon as
     * the documents are back instead of waiting on eight terms facets. Free text goes to
     * the Gateway as text and is bound as the `uq` parameter by Solr::queryText(); it is
     * never concatenated into a query.
     *
     * @return array<string,mixed>
     */
    private function list(): array
    {
        $text = self::text('q', 200);
        $sortKey = self::param('sort', array_keys(Query::sorts()), 'recent');
        $rows = self::rows(self::MAX_ROWS, 25);
        $start = self::start();

        $res = $this->gw->search('sessions.list', $this->gw->sessionsCore(), $text, [
            'fq'    => $this->sessionFqs(),
            'sort'  => Query::sorts()[$sortKey],
            'rows'  => $rows,
            'start' => $start,
            'fl'    => Query::sessionFl(),
        ]);

        return $this->envelope([
            'q'        => $text,
            'sort'     => $sortKey,
            'rows'     => $rows,
            'start'    => $start,
            'numFound' => $res['numFound'],
            'docs'     => array_map([$this, 'shapeSession'], $res['docs']),
            'active'   => $this->filters,
        ]);
    }

    /**
     * Facet counts for the sidebar, over the same query as the result table.
     *
     * Every browsable dimension, in one request, in the same shape the panel-wide filter bar
     * and the detail dialog use — one payload shape, one renderer, one appearance. The sidebar
     * used to offer five of them and skip AS organisation, netname and fingerprint for cost
     * reasons that do not survive a limit of twelve buckets: those three are the names an
     * operator most wants to slice by, and leaving them out is why the page felt like it had
     * no filters.
     *
     * @return array<string,mixed>
     */
    private function facets(): array
    {
        [$groups, $f] = $this->dimensionGroups(
            'sessions.facets',
            self::BROWSE_BUCKETS,
            ['beacon' => ['type' => 'query', 'q' => Query::POP_BEACON]],
            self::text('q', 200)
        );

        return $this->envelope([
            'facets'       => $groups,
            'active'       => $this->filters,
            'matched'      => (int) ($f['count'] ?? 0),
            'beacon_count' => self::qcount($f, 'beacon'),
            'multi'        => self::MULTI_SELECT_NOTE,
        ]);
    }

    /**
     * How the filters combine, stated in the UI because a reader cannot tell OR from AND.
     *
     * Controller::filterFqs() ORs the values within one field and ANDs the fields together,
     * which is the right behaviour and completely invisible: two countries selected widens the
     * result, a country plus a browser narrows it, and nothing on screen said so. The sentence
     * travels with the payload so the renderer cannot drift from the query builder.
     */
    private const MULTI_SELECT_NOTE = 'Picking several values in one dimension widens the result — '
        . 'any of them match. Picking values in different dimensions narrows it — all of them must match.';

    /**
     * The full value list for ONE dimension, for the "show all" control.
     *
     * The sidebar shows the top twelve, which is the right default and useless for a long tail:
     * country and AS organisation both have one. This answers the same question without a
     * limit small enough to hide the answer, and the browser filters the returned list as the
     * operator types — Solr's JSON facet `contains` is not on the client's allowlist and adding
     * it would be a new sanitiser surface for a search box that works perfectly well locally.
     *
     * @return array<string,mixed>
     */
    private function values(): array
    {
        $fields = self::browseFields();
        $field = self::param('field', array_keys($fields), '');
        if ($field === '') {
            return $this->envelope(['error' => 'That is not a dimension this panel can list.']);
        }

        [$groups, $f] = $this->dimensionGroups(
            'sessions.values',
            self::ALL_BUCKETS,
            [],
            self::text('q', 200),
            [$field]
        );

        return $this->envelope([
            'field'   => $field,
            'group'   => $groups[0] ?? null,
            'matched' => (int) ($f['count'] ?? 0),
            'active'  => $this->filters,
        ]);
    }

    /**
     * Build the dimension groups in one faceted request.
     *
     * Shared by the sidebar, the panel-wide filter bar and the "show all" list, so the three
     * cannot disagree about which dimensions exist, what they are called or how many values
     * each shows. `$only` restricts it to one dimension for the expanded list.
     *
     * @param array<string,mixed> $extra Additional facet definitions to fold into the request.
     * @param array<int,string>|null $only
     * @return array{0:array<int,array<string,mixed>>,1:array<string,mixed>}
     */
    private function dimensionGroups(
        string $label,
        int $limit,
        array $extra = [],
        string $text = '',
        ?array $only = null
    ): array {
        $fields = self::browseFields();
        if ($only !== null) {
            $fields = array_intersect_key($fields, array_flip($only));
        }

        $definitions = $extra;
        foreach (array_keys($fields) as $field) {
            $definitions[$field] = [
                'type'     => 'terms',
                'field'    => $field,
                'limit'    => $limit,
                'mincount' => 1,
                'sort'     => 'count desc',
            ];
        }
        if ($only === null) {
            $definitions['signed_in'] = ['type' => 'query', 'q' => 'signed_in_b:true'];
            $definitions['anonymous'] = ['type' => 'query', 'q' => 'signed_in_b:false'];
        }

        $f = $this->gw->searchFacet(
            $label,
            $this->gw->sessionsCore(),
            $text,
            ['fq' => $this->sessionFqs()],
            $definitions
        );

        $groups = [];
        foreach ($fields as $field => $name) {
            $buckets = [];
            foreach (self::buckets($f, $field) as $bucket) {
                $buckets[] = [
                    'value' => (string) ($bucket['val'] ?? ''),
                    'count' => (int) ($bucket['count'] ?? 0),
                ];
            }
            if ($buckets === []) {
                continue;
            }
            $groups[] = [
                'field'      => $field,
                'label'      => $name,
                'mono'       => in_array($field, self::MONO_FIELDS, true),
                'filterable' => true,
                'buckets'    => $buckets,
                'truncated'  => count($buckets) >= $limit,
            ];
        }

        if ($only === null) {
            $group = $this->signedInGroup($f);
            if ($group !== null) {
                $groups[] = $group;
            }
        }

        return [$groups, $f];
    }

    /**
     * The value distribution of every browsable dimension, for the filter bar.
     *
     * ONE faceted request for the whole panel, issued only when the operator opens it. The
     * mechanism for filtering has existed since the beginning — `?f[field][]=value` parsed by
     * Controller::readFilters() and applied to every query on every view — and was offered in
     * the UI on this page alone, so a name an operator could see on the Networks page was not
     * something they could act on. This is the other half of that.
     *
     * Scoped by the range and by whatever is ALREADY filtered, so the counts describe the
     * traffic on screen rather than the whole index: "of what I am looking at, how does it
     * break down" is the question, and a bucket count from a wider population would not match
     * any number on the page.
     *
     * @return array<string,mixed>
     */
    private function dimensions(): array
    {
        [$groups, $f] = $this->dimensionGroups('sessions.dimensions', self::BROWSE_BUCKETS);

        return $this->envelope([
            'dimensions' => $groups,
            'matched'    => (int) ($f['count'] ?? 0),
            'active'     => $this->filters,
            'multi'      => self::MULTI_SELECT_NOTE,
        ]);
    }

    /**
     * The signed-in / anonymous / not-reported split, as a dimension group.
     *
     * THREE STATES, AND THE THIRD IS NOT A ROUNDING ERROR. `signed_in_b` is written only when
     * the measured site actually said one or the other, so "not reported" is every session on a
     * site that has not adopted the beacon attribute — which on most installations is all of
     * them. Presenting two buckets and letting the reader assume the rest were anonymous is
     * exactly the fabrication the absent field exists to prevent, so the third bucket is
     * computed here as the remainder and labelled.
     *
     * `filterable` is false because the panel's filter allowlist does not carry `signed_in_b`
     * yet, and because "not reported" is a NEGATIVE filter (`-signed_in_b:[* TO *]`) that the
     * `?f[field][]=value` mechanism cannot express at all. Both gaps are named in the handover
     * rather than worked around: the values render as a read-only distribution until then.
     *
     * Returns null when nothing in range reported it, so a group of one bucket reading
     * "not reported: everything" is never drawn.
     *
     * @param array<string,mixed> $f
     * @return array<string,mixed>|null
     */
    private function signedInGroup(array $f): ?array
    {
        $signedIn = self::qcount($f, 'signed_in');
        $anonymous = self::qcount($f, 'anonymous');
        if ($signedIn === 0 && $anonymous === 0) {
            return null;
        }

        $matched = (int) ($f['count'] ?? 0);
        $buckets = [
            ['value' => 'signed in', 'count' => $signedIn],
            ['value' => 'anonymous', 'count' => $anonymous],
        ];
        $silent = max(0, $matched - $signedIn - $anonymous);
        if ($silent > 0) {
            $buckets[] = ['value' => 'not reported', 'count' => $silent];
        }

        return [
            'field'      => 'signed_in_b',
            'label'      => 'Signed in',
            'mono'       => false,
            'filterable' => false,
            'buckets'    => $buckets,
            'truncated'  => false,
        ];
    }

    /**
     * Everything Loghound knows about one dimension value.
     *
     * The detail dialog behind every row that names a network, a country, a browser, a verdict
     * or a path. Four things, in the order an operator reads them: how much traffic this value
     * accounts for and what kind it was; how the value breaks down along the OTHER dimensions;
     * and a sample of the actual recent visitors, each of which opens their own session.
     *
     * `field` is a key into dimensionFields() — the browser sends a name, never a query
     * fragment — and `value` is bound as a quoted Solr term by termFor(). The scope carries the
     * active filters, and they are echoed back so the dialog can say which ones produced the
     * numbers in it.
     *
     * @return array<string,mixed>
     */
    private function dimension(): array
    {
        $fields = self::dimensionFields();
        $field = self::param('field', array_keys($fields), '');
        if ($field === '') {
            return $this->envelope(['error' => 'That is not a dimension this panel can open.']);
        }

        $value = self::text('value', 256);
        if ($value === '') {
            return $this->envelope(['error' => 'That row carries no value to open.']);
        }

        $solrField = Query::sessionFilterAliases()[$field] ?? $field;
        $clause = self::termFor($solrField, $value);
        if ($clause === null) {
            return $this->envelope(['error' => 'That value is not in the form this dimension holds.']);
        }
        $scope = array_merge($this->sessionFqs(), [$clause]);

        $definitions = [
            'uniq_ips'  => 'unique(ip_s)',
            'uniq_fps'  => 'unique(fp_hash_s)',
            'uniq_asns' => 'unique(asn_i)',
            'hits'      => 'sum(hits_i)',
            'pages'     => 'sum(pages_i)',
            'bytes'     => 'sum(bytes_l)',
            'score'     => 'avg(bot_score_f)',
            'first'     => 'min(ts_start)',
            'last'      => 'max(ts_end)',
            'log_span'  => 'percentile(log_span_ms_l,50)',
            'beacon'    => ['type' => 'query', 'q' => Query::POP_BEACON, 'facet' => [
                'engaged' => 'percentile(engaged_ms_l,50)',
                'wall'    => 'percentile(wall_ms_l,50)',
            ]],
        ];
        foreach (Query::populations() as $key => $filter) {
            $definitions['pop_' . $key] = ['type' => 'query', 'q' => $filter];
        }
        foreach (self::breakdownFields($field) as $sub) {
            $definitions['by_' . $sub] = [
                'type'     => 'terms',
                'field'    => $sub,
                'limit'    => self::DIMENSION_BUCKETS,
                'mincount' => 1,
                'sort'     => 'count desc',
            ];
        }

        $f = $this->gw->facet('sessions.dimension', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $scope,
        ], $definitions);

        $mix = [];
        foreach (array_keys(Query::populations()) as $key) {
            $mix[$key] = self::qcount($f, 'pop_' . $key);
        }
        $beacon = is_array($f['beacon'] ?? null) ? $f['beacon'] : [];

        $breakdowns = [];
        foreach (self::breakdownFields($field) as $sub) {
            $buckets = [];
            foreach (self::buckets($f, 'by_' . $sub) as $bucket) {
                $buckets[] = [
                    'value' => (string) ($bucket['val'] ?? ''),
                    'count' => (int) ($bucket['count'] ?? 0),
                ];
            }
            if ($buckets !== []) {
                $breakdowns[] = [
                    'field'   => $sub,
                    'label'   => $fields[$sub] ?? $sub,
                    'mono'    => in_array($sub, self::MONO_FIELDS, true),
                    'buckets' => $buckets,
                ];
            }
        }

        $recent = $this->gw->select('sessions.dimension.recent', $this->gw->sessionsCore(), [
            'q'    => '*:*',
            'fq'   => $scope,
            'sort' => 'ts_start desc',
            'rows' => self::DIMENSION_VISITORS,
            'fl'   => Query::sessionFl(),
        ]);

        return $this->envelope([
            'field'      => $field,
            'label'      => $fields[$field] ?? $field,
            'value'      => $value,
            'filterable' => isset(Query::filterFields()[$field]),
            'sessions'   => (int) ($f['count'] ?? 0),
            'uniq_ips'   => (int) (self::num($f, 'uniq_ips') ?? 0),
            'uniq_fps'   => (int) (self::num($f, 'uniq_fps') ?? 0),
            'uniq_asns'  => (int) (self::num($f, 'uniq_asns') ?? 0),
            'hits'       => self::num($f, 'hits'),
            'pages'      => self::num($f, 'pages'),
            'bytes'      => self::num($f, 'bytes'),
            'score'      => self::num($f, 'score'),
            'first'      => is_string($f['first'] ?? null) ? $f['first'] : null,
            'last'       => is_string($f['last'] ?? null) ? $f['last'] : null,
            'log_span_p50' => self::num($f, 'log_span'),
            'beacon'     => [
                'sessions'    => (int) ($beacon['count'] ?? 0),
                'engaged_p50' => self::num($beacon, 'engaged'),
                'wall_p50'    => self::num($beacon, 'wall'),
            ],
            'mix'        => $mix,
            'labels'     => Query::populationLabels(),
            'breakdowns' => $breakdowns,
            'visitors'   => array_map([$this, 'shapeVisitor'], $recent['docs']),
            'requests'   => $field === 'paths_ss' ? $this->pathRequests($value) : null,
            'active'     => $this->filters,
        ]);
    }

    /**
     * The dimensions a value is broken down BY, which is every other dimension worth showing.
     *
     * A dimension is never broken down by itself: a single bucket repeating the value you just
     * clicked is a row that answers nothing. `ip_s`, `session_id_s` and `fp_hash_s` are left
     * out for cost — a nested terms facet over addresses inside another facet is the expensive
     * shape — except that a fingerprint is exactly what a network dialog needs, so `fp_hash_s`
     * is carried as a `unique()` count instead of a bucket list.
     *
     * @return array<int,string>
     */
    private static function breakdownFields(string $field): array
    {
        $order = [
            'country_s', 'as_org_s', 'netname_s', 'as_type_s',
            'browser_s', 'os_s', 'device_s',
            'bot_verdict_s', 'bot_class_s', 'bot_reasons_ss',
            'referer_type_s', 'host_s', 'paths_ss',
        ];
        return array_values(array_filter($order, static fn (string $f): bool => $f !== $field));
    }

    /**
     * What the webserver actually did with one path, from the hits core.
     *
     * The sessions core knows which sessions touched a path; only the hits core knows what was
     * returned, how big it was and how long it took. A top-pages row is about a path, so the
     * status mix is the first thing an operator wants from it — a page quietly serving 404s to
     * a crawler is invisible in a session count.
     *
     * Returns null when the hits core cannot answer, rather than an empty shape that would read
     * as "this path was never requested".
     *
     * @return array<string,mixed>|null
     */
    private function pathRequests(string $path): ?array
    {
        $f = $this->gw->facet('sessions.dimension.path', $this->gw->hitsCore(), [
            'q'  => '*:*',
            'fq' => array_merge($this->hitFqs(), [Query::term('path_s', $path)]),
        ], [
            'bytes'  => 'sum(bytes_l)',
            'dur'    => 'percentile(dur_us_l,50)',
            'dur_p95' => 'percentile(dur_us_l,95)',
            'status' => ['type' => 'terms', 'field' => 'status_i', 'limit' => 12, 'sort' => 'count desc'],
        ]);

        $hits = (int) ($f['count'] ?? 0);
        if ($hits === 0) {
            return null;
        }

        $status = [];
        foreach (self::buckets($f, 'status') as $bucket) {
            $status[] = [
                'status' => (int) ($bucket['val'] ?? 0),
                'count'  => (int) ($bucket['count'] ?? 0),
            ];
        }

        return [
            'hits'    => $hits,
            'bytes'   => self::num($f, 'bytes'),
            'dur_p50' => self::num($f, 'dur'),
            'dur_p95' => self::num($f, 'dur_p95'),
            'status'  => $status,
            'ignored' => $this->ignoredHitFilters(),
        ];
    }

    /**
     * Build a `field:value` clause for a dimension, or null when the value cannot be one.
     *
     * String fields go through Query::term(), which validates the field name and escapes the
     * value into a quoted Solr literal, so an AS organisation name full of Lucene operators is
     * matched as text. A numeric point field is the one case where a quoted term is not the
     * right shape, so the value must be a plain integer and is refused rather than coerced —
     * "unparseable" must never become "matches everything".
     */
    private static function termFor(string $field, string $value): ?string
    {
        if (!Security::isSafeFieldName($field)) {
            return null;
        }
        if (str_ends_with($field, '_i') || str_ends_with($field, '_l')) {
            return ctype_digit($value) ? $field . ':' . $value : null;
        }
        return Query::term($field, $value);
    }

    /**
     * A visitor row: who they are at a glance, and nothing more.
     *
     * Deliberately narrower than shapeSession(). This is the Clicky-style recent-visitors list
     * — flag, network, client, time, page — and shipping sixty fields per row for a twelve-row
     * sample inside a dialog would be wasteful. The whole record is one click further on.
     *
     * @param array<string,mixed> $d
     * @return array<string,mixed>
     */
    private function shapeVisitor(array $d): array
    {
        $str = static fn (string $k) => isset($d[$k]) && is_scalar($d[$k]) ? (string) $d[$k] : null;
        $int = static fn (string $k) => isset($d[$k]) && is_numeric($d[$k]) ? (int) $d[$k] : null;

        return [
            'id'          => (string) ($d['id'] ?? ''),
            'ts_start'    => $str('ts_start'),
            'ip'          => $str('ip_s'),
            'country'     => $str('country_s'),
            'city'        => $str('city_s'),
            'as_org'      => $str('as_org_s'),
            'as_type'     => $str('as_type_s'),
            'netname'     => $str('netname_s'),
            'asn'         => $int('asn_i'),
            'browser'     => $str('browser_s'),
            'browser_ver' => $int('browser_ver_i'),
            'os'          => $str('os_s'),
            'device'      => $str('device_s'),
            'ua_bot_name' => $str('ua_bot_name_s'),
            'ua_bot_cat'  => $str('ua_bot_cat_s'),
            'ai_crawler'  => array_key_exists('ai_crawler_b', $d) ? (bool) $d['ai_crawler_b'] : null,
            'entry'       => $str('entry_path_s'),
            'hits'        => $int('hits_i'),
            'verdict'     => $str('bot_verdict_s'),
            'ident'       => $str('ident_s'),
            'signed_in'   => array_key_exists('signed_in_b', $d) ? (bool) $d['signed_in_b'] : null,
            'beacon'      => array_key_exists('beacon_b', $d) ? (bool) $d['beacon_b'] : null,
            'engaged_ms'  => $int('engaged_ms_l'),
            'log_span_ms' => $int('log_span_ms_l'),
        ];
    }

    /**
     * One session, with its hit timeline and the beacon overlay.
     *
     * @return array<string,mixed>
     */
    private function detail(): array
    {
        $id = self::text('id', 128);
        if (!preg_match('/^[A-Za-z0-9_-]{8,128}$/', $id)) {
            return $this->envelope(['error' => 'Not a session id.']);
        }

        $sess = $this->gw->select('sessions.one', $this->gw->sessionsCore(), [
            'q'    => '*:*',
            'fq'   => [Query::term('id', $id)],
            'rows' => 1,
            'fl'   => Query::sessionFl(),
        ]);

        if ($sess['docs'] === []) {
            return $this->envelope(['error' => 'That session is not in the index (it may have aged past retention).']);
        }
        $doc = $this->shapeSession($sess['docs'][0]);

        $limit = Security::clampInt($_GET['limit'] ?? null, 10, self::MAX_TIMELINE, 200);
        $hits = $this->gw->select('sessions.hits', $this->gw->hitsCore(), [
            'q'    => '*:*',
            'fq'   => [Query::term('session_id_s', $id)],
            'sort' => 'ts asc',
            'rows' => $limit,
            'fl'   => Query::hitFl(),
        ]);

        $timeline = [];
        foreach ($hits['docs'] as $h) {
            $timeline[] = [
                'id'      => (string) ($h['id'] ?? ''),
                'ts'      => (string) ($h['ts'] ?? ''),
                'seq'     => isset($h['session_seq_i']) ? (int) $h['session_seq_i'] : null,
                'method'  => (string) ($h['method_s'] ?? ''),
                'path'    => (string) ($h['path_s'] ?? ''),
                'query'   => isset($h['query_s']) ? (string) $h['query_s'] : null,
                'status'  => isset($h['status_i']) ? (int) $h['status_i'] : null,
                'bytes'   => isset($h['bytes_l']) ? (int) $h['bytes_l'] : null,
                'dur_us'  => isset($h['dur_us_l']) ? (int) $h['dur_us_l'] : null,
                'kind'    => (string) ($h['kind_s'] ?? ''),
                'asset'   => isset($h['asset_kind_s']) ? (string) $h['asset_kind_s'] : null,
                'proto'   => (string) ($h['proto_s'] ?? ''),
                'referer' => isset($h['referer_s']) ? (string) $h['referer_s'] : null,
                'referer_href' => isset($h['referer_s']) ? Security::safeUrl((string) $h['referer_s']) : null,
                'flags'   => array_values(array_map('strval', (array) ($h['hit_flags_ss'] ?? []))),
            ];
        }

        return $this->envelope([
            'session'   => $doc,
            'timeline'  => $timeline,
            'truncated' => count($timeline) >= $limit,
            'reasons'   => Bots::reasonCatalogue(),
        ]);
    }

    /**
     * Normalise a session document for the browser.
     *
     * Two jobs. First, absent stays absent: a field that Solr did not return becomes null
     * and renders as an em-dash, never as 0 — SPEC §1 forbids the zero-fill, and this is
     * where it would otherwise creep in. Second, the referer gets a pre-validated href so
     * the client never has to decide whether a URL is safe to link.
     *
     * @param array<string,mixed> $d
     * @return array<string,mixed>
     */
    private function shapeSession(array $d): array
    {
        $int = static fn (string $k) => isset($d[$k]) && is_numeric($d[$k]) ? (int) $d[$k] : null;
        $flt = static fn (string $k) => isset($d[$k]) && is_numeric($d[$k]) ? (float) $d[$k] : null;
        $str = static fn (string $k) => isset($d[$k]) && is_scalar($d[$k]) ? (string) $d[$k] : null;
        $bool = static fn (string $k) => array_key_exists($k, $d) ? (bool) $d[$k] : null;
        $list = static fn (string $k) => array_values(array_map('strval', (array) ($d[$k] ?? [])));

        $out = [
            'id'        => (string) ($d['id'] ?? ''),
            'ts_start'  => $str('ts_start'),
            'ts_end'    => $str('ts_end'),
            'host'      => $str('host_s'),
            'hits'      => $int('hits_i'),
            'pages'     => $int('pages_i'),
            'assets'    => $int('assets_i'),
            'uniq_paths' => $int('uniq_paths_i'),
            'bytes'     => $int('bytes_l'),
            'entry'     => $str('entry_path_s'),
            'exit'      => $str('exit_path_s'),
            'status'    => [
                '2xx' => $int('status_2xx_i'),
                '3xx' => $int('status_3xx_i'),
                '4xx' => $int('status_4xx_i'),
                '5xx' => $int('status_5xx_i'),
            ],
            'got_304'   => $bool('got_304_b'),

            'beacon'    => $bool('beacon_b'),
            'log_span_ms' => $int('log_span_ms_l'),
            'wall_ms'   => $int('wall_ms_l'),
            'visible_ms' => $int('visible_ms_l'),
            'engaged_ms' => $int('engaged_ms_l'),
            'interactions' => $int('interactions_i'),
            'max_scroll' => $int('max_scroll_pct_i'),
            'pageviews' => $int('pageviews_i'),
            'asset_ratio' => $flt('asset_ratio_f'),
            'gap_p50_ms' => $int('gap_p50_ms_l'),
            'gap_stddev_ms' => $int('gap_stddev_ms_l'),

            'ident'     => $str('ident_s'),
            'signed_in' => $bool('signed_in_b'),

            'ip'        => $str('ip_s'),
            'ip_net'    => $str('ip_net_s'),
            'asn'       => $int('asn_i'),
            'as_org'    => $str('as_org_s'),
            'as_type'   => $str('as_type_s'),
            'netname'   => $str('netname_s'),
            'rdns'      => $str('rdns_s'),
            'rdns_ok'   => $bool('rdns_ok_b'),
            'country'   => $str('country_s'),
            'region'    => $str('region_s'),
            'city'      => $str('city_s'),
            'tz'        => $str('tz_s'),

            'ua'        => $str('ua_s'),
            'browser'   => $str('browser_s'),
            'browser_ver' => $int('browser_ver_i'),
            'os'        => $str('os_s'),
            'device'    => $str('device_s'),
            'ua_bot'    => $bool('ua_bot_b'),
            'ua_bot_name' => $str('ua_bot_name_s'),
            'ua_bot_cat' => $str('ua_bot_cat_s'),
            'ai_crawler' => $bool('ai_crawler_b'),

            'referer'   => $str('referer_s'),
            'referer_host' => $str('referer_host_s'),
            'referer_type' => $str('referer_type_s'),

            'fp'        => $str('fp_hash_s'),
            'fp_ips_24h' => $int('fp_ips_24h_i'),

            'js'        => $bool('js_b'),
            'headless'  => $bool('headless_b'),
            'automation' => $list('automation_ss'),
            'ua_claim_ok' => $bool('ua_claim_ok_b'),
            'tz_match'  => $bool('tz_match_b'),
            'webgl'     => $str('webgl_s'),

            'score'     => $flt('bot_score_f'),
            'verdict'   => $str('bot_verdict_s'),
            'reasons'   => $list('bot_reasons_ss'),
            'class'     => $str('bot_class_s'),
            'rule_version' => $int('rule_version_i'),
        ];

        $out['referer_href'] = $out['referer'] !== null ? Security::safeUrl($out['referer']) : null;
        return $out;
    }

    /**
     * The static skeleton.
     *
     * The session detail used to be a third card at the bottom of this page, which meant
     * opening a session scrolled the operator away from the list they were working through and
     * the page grew a permanent empty section on every other visit. It is a dialog now
     * (assets/js/dialog.js), shared with every other view, so the list stays where it was.
     */
    public function body(): void
    {
        $this->searchCard();

        echo '<div class="explorer">';
        $this->facetsCard();
        $this->resultsCard();
        echo '</div>';
    }

    /**
     * The search form.
     *
     * A GET form, so every search is a bookmarkable URL and the view works with
     * JavaScript disabled.
     */
    private function searchCard(): void
    {
        self::cardOpen(
            'se-search',
            '01',
            'Search',
            'Free text is matched with edismax across path, User-Agent, AS organisation, netname, reverse DNS, '
            . 'city and country. It is sent to Solr as a bound parameter, never as query syntax.'
        );

        echo '<form class="searchbar" method="get" action="" id="se-form">';
        echo '<input type="hidden" name="v" value="sessions">';
        echo '<input type="hidden" name="range" value="' . Security::esc($this->range['key']) . '">';
        echo '<label class="sr-only" for="se-q">Search sessions</label>';
        echo '<input type="search" id="se-q" name="q" '
            . 'placeholder="Search paths, User-Agents, organisations, netnames, cities" '
            . 'value="' . Security::esc(self::text('q', 200)) . '" autocomplete="off" spellcheck="false">';
        echo '<label class="sr-only" for="se-sort">Sort by</label>';
        echo '<select id="se-sort" name="sort">';
        $active = self::param('sort', array_keys(Query::sorts()), 'recent');
        foreach ([
            'recent'  => 'Most recent',
            'oldest'  => 'Oldest first',
            'score'   => 'Highest bot score',
            'hits'    => 'Most requests',
            'engaged' => 'Most engaged time',
            'span'    => 'Longest log span',
        ] as $value => $label) {
            echo '<option value="' . Security::esc($value) . '"' . ($value === $active ? ' selected' : '') . '>'
                . Security::esc($label) . '</option>';
        }
        echo '</select>';
        echo '<button type="submit" class="primary">Search</button>';
        echo '</form>';

        self::cardEnd();
    }

    /**
     * The facet sidebar, loaded separately from the results.
     *
     * Headed "Filter by" rather than "Filters", because the previous heading described a
     * category of thing rather than an action and the list under it was not recognised as
     * something that could be pressed at all.
     */
    private function facetsCard(): void
    {
        echo '<aside class="facets" aria-label="Filter the dashboard">';
        self::cardOpen(
            'se-facets',
            '02',
            'Filter by',
            'Press a value to scope every view to it. Press it again to remove it.'
        );
        self::skeleton('se-facets', 'rows', 0, 'Counting facet values');
        echo '<div id="se-facet-list"></div>';
        self::cardClose('se-facets');
        echo '</aside>';
    }

    /**
     * The recent-visitors table.
     *
     * Every column carries identity at a glance — the flag and city, the network the address
     * belongs to by name, the parsed client rather than the raw User-Agent, the time and the
     * page they came in on. All of it was already on the document and none of it was shown.
     *
     * The widths are explicit and the table is fixed-layout (see `table-fixed` in the
     * stylesheet), because nine columns of content-driven width push the last one off the right
     * edge of the viewport — which is how a Verdict column ends up reading "VERD".
     */
    private function resultsCard(): void
    {
        echo '<div class="results">';
        self::cardOpen('se-results', '', 'Recent visitors', '', '<span class="job-meta" id="se-count"></span>');
        self::skeleton('se-results', 'rows', 0, 'Searching sessions');

        echo '<div class="table-wrap"><table id="se-table" class="table-fixed"><colgroup>'
            . '<col style="width:13ch"><col style="width:11ch"><col style="width:13ch">'
            . '<col style="width:16ch"><col style="width:20%"><col style="width:15%">'
            . '<col style="width:7ch"><col style="width:9ch"><col style="width:9ch"><col>'
            . '</colgroup><thead><tr>'
            . '<th scope="col">Started</th>'
            . '<th scope="col">Verdict</th>'
            . '<th scope="col">Where</th>'
            . '<th scope="col">Address</th>'
            . '<th scope="col">Network</th>'
            . '<th scope="col">Client</th>'
            . '<th scope="col" class="num">Reqs</th>'
            . '<th scope="col" class="num">Log span</th>'
            . '<th scope="col" class="num">Engaged</th>'
            . '<th scope="col">Page</th>'
            . '</tr></thead><tbody></tbody></table></div>';
        echo '<div class="pager" id="se-pager"></div>';

        self::cardClose('se-results');
        echo '</div>';
    }
}
