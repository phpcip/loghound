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

    /**
     * ONE SECTION, DELIBERATELY, WHICH IS WHY THIS IS EMPTY.
     *
     * Every other view in the panel has been split so that each of its sections is its own page.
     * The session explorer is not three sections that happen to be on one page: the search box,
     * the facet rail and the results table are one instrument, and separating the rail from the
     * table it filters would be the same mistake as putting a dial on a different wall from the
     * gauge. Fewer than two entries means Layout renders the whole body and the navigation gives
     * this view no sub-list, which is exactly right.
     *
     * @var array<int,array{0:string,1:string}>
     */
    public const SECTIONS = [];

    /** Hard cap on hits returned for one page of a session's request trail. */
    private const MAX_TIMELINE = 100;

    /** Values shown per nested breakdown inside a dimension's detail dialog. */
    private const DIMENSION_BUCKETS = 8;

    /** Values listed per dimension in the filter bar's browse panel. */
    private const BROWSE_BUCKETS = 12;

    /**
     * Values returned for one dimension when the operator asks to see all of them.
     *
     * Bounded rather than unbounded: `limit: -1` on a terms facet asks Solr to enumerate every
     * distinct value a field has ever held, which on a fingerprint or a path is tens of thousands
     * of buckets built to populate a list nobody will read past the first screen of.
     *
     * Two thousand rather than the two hundred this was, because the value browser groups the
     * list under an A–Z index and two hundred values sorted by COUNT covers only the head of the
     * alphabet on a long tail. The request also asks for `numBuckets`, so a dimension with more
     * distinct values than this says "the 2,000 most common of 48,391" and says that the search
     * box searches those two thousand — a truncation the reader cannot see is the one thing worse
     * than a truncation.
     */
    private const ALL_BUCKETS = 2000;

    /**
     * Values returned for one value-SEARCH.
     *
     * Smaller than the listing on purpose, and the two are not the same question. The listing is
     * "the most common values of this dimension" and wants enough to fill an A–Z index; a search
     * is "the values containing what I typed" and is read from the top down — nobody scrolls to
     * the two hundredth match, they type another character. Bounding it also bounds the response
     * of a search that matches most of a term dictionary, which is the one a single letter would
     * produce if Facets::MIN_SEARCH let it through.
     */
    private const SEARCH_BUCKETS = 200;

    /**
     * Every dimension whose detail dialog can be opened.
     *
     * The filterable set, minus `session_id_s`: a session is not a dimension, it has its own
     * dialog reached with `detail`.
     *
     * There used to be a second list here — `detailOnlyFields()` — naming `paths_ss`, `asn_i`,
     * `city_s`, `region_s` and `ua_bot_name_s` as inspectable-but-not-filterable, with a docblock
     * saying every one of them ought to be filterable and none of them was. All five are in
     * Query::filterFields() now, so the list described a state of affairs that had stopped being
     * true and made the dialog report `filterable: false` for five dimensions that filter
     * perfectly well.
     *
     * @return array<string,string> field => label
     */
    private static function dimensionFields(): array
    {
        $out = Query::filterFields();
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
        /* THE SESSIONS SUBSET, not the master list. A status is a property of a REQUEST and the
           sessions core defines neither `status_i` nor `status_class_s`, so offering them here
           would put two dimensions in the sidebar whose every value answers zero — which reads
           as "no traffic" rather than as "wrong plane". Query::hitsOnlyFields() is the list. */
        $out = Query::sessionFilterFields();
        unset($out['ip_s'], $out['session_id_s']);
        return $out;
    }

    /**
     * Numeric fields a histogram bucket may open, with their bounds and the words for them.
     *
     * A list of two rather than "any numeric field", for the reason every allowlist in this
     * file exists: the value goes into an `fq`, and a range built from a field name a request
     * chose is a filter naming whatever the caller likes.
     *
     * @var array<string,array{0:int,1:int,2:string}>
     */
    private const BAND_FIELDS = [
        'bot_score_f' => [0, 100, 'Bot score'],
        'hits_i'      => [0, 100000, 'Requests in the visit'],
    ];

    /**
     * Dimensions a caller may ask for a full value list of.
     *
     * WIDER THAN browseFields() BY EXACTLY TWO, and the difference is the whole point. The
     * filter rail leaves `ip_s` out because "the twelve busiest addresses" is not a
     * distribution anybody browses by, and a terms facet over addresses is a bucket per
     * visitor. But a tile that says "Distinct IPs: 3" is a question with one answer — WHICH
     * three — and refusing to list them there is refusing to answer the only thing the number
     * raises. Asked explicitly, for one dimension, bounded by the same cap every other list
     * uses; not offered as a permanent column in the rail.
     *
     * @return array<string,string>
     */
    private static function listableFields(): array
    {
        $out = self::browseFields();
        $all = Query::filterFields();
        foreach (['ip_s', 'asn_i'] as $field) {
            if (isset($all[$field])) {
                $out[$field] = $all[$field];
            }
        }
        return $out;
    }

    /** Dimensions rendered in a monospace list, because the value is an identifier. */
    private const MONO_FIELDS = ['netname_s', 'fp_hash_s', 'host_s', 'sec_ch_ua_s', 'tls_proto_s',
        'paths_ss', 'entry_path_s', 'exit_path_s'];

    /**
     * The words the sort selector shows, keyed by the token Query::sorts() accepts.
     *
     * Here rather than only in the <select> above, because the CSV export has to name the
     * ordering in the file: which two thousand sessions a capped export contains is decided
     * entirely by the sort, so a file that did not say which one was in force would not be
     * reproducible. Panel\Query owns the Solr sort strings; this owns how they are spoken.
     *
     * @var array<string,string>
     */
    private const SORT_LABELS = [
        'recent'  => 'Most recent first',
        'oldest'  => 'Oldest first',
        'score'   => 'Highest bot score first',
        'hits'    => 'Most requests first',
        'engaged' => 'Most engaged time first',
        'span'    => 'Longest log span first',
    ];

    /**
     * Rows per Solr call while a session export is being streamed.
     *
     * Larger than the table's own page because a table is read and a file is not: four calls of
     * five hundred is a bounded amount of work for the node, where twenty calls of a hundred is
     * the same rows at five times the round trips. Still clamped by Security::MAX_ROWS.
     */
    private const EXPORT_PAGE = 500;

    /**
     * The most sessions one export may contain.
     *
     * A DELIBERATE CLAMP, and the file states it. This view can match every session a site has
     * ever had, and a GET that streamed all of them would be a cheap way to make a Solr node
     * work very hard from a URL — so the export takes the first two thousand IN THE SORT ORDER
     * ON SCREEN and says so, which is a bounded amount of work and an answer somebody can
     * reproduce. Narrowing the range or adding a filter is how you get the rest.
     */
    private const EXPORT_SESSIONS = 2000;

    /**
     * Which page-toolbar controls this view honours.
     *
     * sessionFqs() and hitFqs() throughout. This view also SERVES the facet panel the bar
     * opens, so a page without the bar would leave every other view unable to filter.
     *
     * @return array<int,string>
     */
    public function toolbar(): array
    {
        return [self::SCOPE_RANGE, self::SCOPE_HOST, self::SCOPE_FACETS, self::SCOPE_CACHE];
    }

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
     * The two datasets on this view.
     *
     * `sessions` is the only PAGED export in the panel, and it is paged for the reason the file
     * itself states: the table on screen is twenty-five rows of a result set that can run to
     * hundreds of thousands, so "export what is on screen" would produce a file named after the
     * whole population containing its first page. It walks the result set instead, echoing each
     * page as it arrives, and stops at EXPORT_SESSIONS with the coverage line naming both the
     * number taken and the number matched.
     *
     * `values` is the facet value browser — one dimension's values with their counts, which is
     * the answer to "give me every country/path/netblock in this slice". It is capped at the
     * same two thousand buckets the dialog itself asks for, and the dimension is read through
     * the SAME allowlist the dialog uses, so `field` cannot name anything the panel would not
     * facet on.
     *
     * The drill-down dialogs are not exportable. A single session's request timeline and a
     * single dimension's breakdown are both views of ONE row the reader already opened, and
     * both are reachable as a filtered export of one of the tables above.
     *
     * @return array<string,array<string,mixed>>
     */
    public function exports(): array
    {
        return [
            'sessions' => [
                'label'   => 'Sessions',
                'shape'   => 'paged',
                'pager'   => fn (int $start, int $rows): array => $this->exportSessionPage($start, $rows),
                'page'    => self::EXPORT_PAGE,
                'cap'     => self::EXPORT_SESSIONS,
                'unit'    => 'sessions',
                'ranked'  => 'in the sort order named above',
                'carry'   => ['q', 'sort'],
                'note'    => 'Durations are milliseconds. A session still OPEN carries partial counts and a '
                    . 'provisional verdict, and is included — filter by Planes or narrow the range to exclude '
                    . 'it. The three beacon clocks are empty for sessions where no beacon ran; they are not '
                    . 'zero, and averaging them as zero would understate time on site.',
                'scope'   => [
                    'sort_label' => 'Sort order',
                    'q'          => 'Search text',
                ],
                'columns' => [
                    ['Session', 'id', 'id'],
                    ['Started', 'ts_start', 'date'],
                    ['Ended', 'ts_end', 'date'],
                    ['Virtual host', 'host', 'text'],
                    ['Verdict', 'verdict', 'vocab', 'bot_verdict_s'],
                    ['Verdict code', 'verdict', 'id'],
                    ['Bot score', 'score', 'number'],
                    ['Bot class', 'class', 'vocab', 'bot_class_s'],
                    ['Signals fired', 'reasons', 'text'],
                    ['Requests', 'hits', 'number'],
                    ['Pageviews', 'pages', 'number'],
                    ['Asset requests', 'assets', 'number'],
                    ['Distinct paths', 'uniq_paths', 'number'],
                    ['Bytes', 'bytes', 'number'],
                    ['Entry path', 'entry', 'text'],
                    ['Exit path', 'exit', 'text'],
                    ['2xx responses', 'status.2xx', 'number'],
                    ['3xx responses', 'status.3xx', 'number'],
                    ['4xx responses', 'status.4xx', 'number'],
                    ['5xx responses', 'status.5xx', 'number'],
                    ['Log span (ms)', 'log_span_ms', 'number'],
                    ['Wall clock (ms)', 'wall_ms', 'number'],
                    ['Visible time (ms)', 'visible_ms', 'number'],
                    ['Engaged time (ms)', 'engaged_ms', 'number'],
                    ['Beacon reported', 'beacon', 'bool'],
                    ['Interactions', 'interactions', 'number'],
                    ['Max scroll (percent)', 'max_scroll', 'number'],
                    ['Asset ratio', 'asset_ratio', 'number'],
                    ['Median gap between requests (ms)', 'gap_p50_ms', 'number'],
                    ['Gap standard deviation (ms)', 'gap_stddev_ms', 'number'],
                    ['IP', 'ip', 'id'],
                    ['Netblock', 'ip_net', 'id'],
                    ['ASN', 'asn', 'id'],
                    ['AS organisation', 'as_org', 'text'],
                    ['Network type', 'as_type', 'vocab', 'as_type_s'],
                    ['Netname', 'netname', 'id'],
                    ['Reverse DNS', 'rdns', 'text'],
                    ['Reverse DNS confirmed', 'rdns_ok', 'bool'],
                    ['Country', 'country', 'id'],
                    ['Region', 'region', 'text'],
                    ['City', 'city', 'text'],
                    ['User-Agent', 'ua', 'text'],
                    ['Browser', 'browser', 'text'],
                    ['Browser version', 'browser_ver', 'text'],
                    ['OS', 'os', 'text'],
                    ['Device', 'device', 'text'],
                    ['Declared crawler', 'ua_bot_name', 'text'],
                    ['Declared bot category', 'ua_bot_cat', 'vocab', 'ua_bot_cat_s'],
                    ['AI crawler', 'ai_crawler', 'bool'],
                    ['Referrer', 'referer', 'text'],
                    ['Referrer host', 'referer_host', 'text'],
                    ['Referrer type', 'referer_type', 'vocab', 'referer_type_s'],
                    ['Fingerprint', 'fp', 'id'],
                    ['Addresses sharing this fingerprint (24h)', 'fp_ips_24h', 'number'],
                    ['Signed in', 'signed_in', 'bool'],
                    ['Identity reported by the site', 'ident', 'text'],
                    ['Transport planes', 'planes', 'vocab', 'planes_s'],
                    ['Search terms', 'search_terms', 'text'],
                    ['JavaScript ran', 'js', 'bool'],
                    ['Headless', 'headless', 'bool'],
                    ['Automation markers', 'automation', 'text'],
                    ['User-Agent claim held up', 'ua_claim_ok', 'bool'],
                    ['Timezone matched the address', 'tz_match', 'bool'],
                    ['Still open (provisional)', 'provisional', 'bool'],
                    ['Rule version', 'rule_version', 'number'],
                ],
            ],

            'values' => [
                'label'   => 'Dimension values',
                'action'  => 'values',
                'key'     => 'group.buckets',
                'unit'    => 'values',
                'ranked'  => 'ranked by session count',
                'cap'     => self::ALL_BUCKETS,
                'carry'   => ['field', 'q', 'vq'],
                'note'    => 'The dimension\'s OWN filter is lifted, exactly as it is in the dialog, so this '
                    . 'lists every value that would be selectable rather than only the ones already chosen. '
                    . 'Every other filter applies. On a dimension with a closed vocabulary the listing also '
                    . 'carries values with NO traffic, at a count of zero, which is why it can hold more rows '
                    . 'than the distinct count above.',
                'scope'   => [
                    'group.label' => 'Dimension',
                    'group.field' => 'Stored field name',
                    'group.op'    => ['Operator in force on this dimension', static fn ($op): string =>
                        is_string($op) && $op !== '' ? Facets::operatorLabel($op) : ''],
                    'matched'     => 'Sessions matched by the rest of the scope',
                    'group.distinct' => 'Distinct values Solr found traffic for',
                ],
                'columns' => [
                    ['Value', 'label', 'text'],
                    ['Stored value', 'value', 'id'],
                    ['Sessions', 'count', 'number'],
                    ['What it means', 'why', 'text'],
                    ['Selected', 'state', 'text'],
                ],
            ],
        ];
    }

    /**
     * @return array<string,mixed>
     */
    public function api(string $action): array
    {
        return match ($action) {
            'list'       => $this->list(),
            'bounce'     => $this->bounce(),
            'facets'     => $this->facets(),
            'detail'     => $this->detail(),
            'trail'      => $this->trail(),
            'dimension'  => $this->dimension(),
            'visitors'   => $this->visitors(),
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
        return $this->listPage(Paging::start(), Paging::rows());
    }

    /**
     * One page of the session list, at an offset and size the CALLER decides.
     *
     * Split out of list() so the CSV export can walk the whole result set through exactly the
     * query the table runs — the same free text bound as `uq`, the same sessionFqs(), the same
     * allowlisted sort, the same explicit field list. A second query built beside it would be a
     * second place for a filter to go missing, and the export's whole claim is that the file is
     * scoped the way the page was.
     *
     * Both arguments are clamped here rather than trusted: the export passes its own page size
     * and a computed offset, and this method is the boundary that decides what Solr is asked for.
     *
     * `$full` decides how much of each document is shaped. The TABLE needs five columns and the
     * identity behind them, because that is all five columns can show; the CSV needs every field
     * the schema holds, because a file is where somebody continues working. Shaping the wide
     * version for the table would ship sixty fields a page to render five of them, and shaping
     * the narrow one for the file would silently empty sixty declared columns.
     *
     * @return array<string,mixed>
     */
    private function listPage(int $start, int $rows, bool $full = false): array
    {
        $text = self::text('q', 200);
        $sortKey = self::param('sort', array_keys(Query::sorts()), 'recent');
        $rows = Security::clampInt($rows, 1, Security::MAX_ROWS, 25);
        $start = Security::clampInt($start, 0, Security::MAX_START, 0);

        $res = $this->gw->search('sessions.list', $this->gw->sessionsCore(), $text, [
            'fq'    => $this->sessionFqs(),
            'sort'  => Query::sorts()[$sortKey],
            'rows'  => $rows,
            'start' => $start,
            'fl'    => Query::sessionFl(),
        ]);

        $docs = array_map([$this, $full ? 'shapeSession' : 'shapeVisitor'], $res['docs']);

        return $this->envelope([
            'q'        => $text,
            'sort'     => $sortKey,
            'sort_label' => self::SORT_LABELS[$sortKey] ?? $sortKey,
            'rows'     => $rows,
            'start'    => $start,
            'numFound' => $res['numFound'],
            'docs'     => $docs,
            'page'     => Paging::block($start, $rows, (int) $res['numFound'], 'visits', count($docs)),
            'active'   => $this->filters,
        ]);
    }

    /**
     * One page of sessions, in the shape Controller::exportPaged() walks.
     *
     * @return array{rows:array<int,array<string,mixed>>,total:int,payload:array<string,mixed>}
     */
    private function exportSessionPage(int $start, int $rows): array
    {
        $payload = $this->listPage($start, $rows, true);

        return [
            'rows'    => (array) ($payload['docs'] ?? []),
            'total'   => (int) ($payload['numFound'] ?? 0),
            'payload' => $payload,
        ];
    }

    /**
     * The bounce rate for whatever is on screen.
     *
     * SETTLED SESSIONS ONLY. A session that is still open has a page count that is still moving,
     * so a visitor who is on their first page right now would be counted as a one-page visit —
     * which would make the rate a measurement of how recently people arrived. Panel\Bounce owns
     * the definition and the threshold; this owns the scope, which is the same range, host and
     * filters as every other number on the page.
     *
     * @return array<string,mixed>
     */
    private function bounce(): array
    {
        $f = $this->gw->facet('sessions.bounce', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->settledSessionFqs(),
        ], Bounce::facets());

        return $this->envelope(['bounce' => Bounce::read($f)]);
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
        ]);
    }

    /**
     * The full value list for ONE dimension, for the value browser.
     *
     * The sidebar shows the top twelve, which is the right default and useless for a long tail:
     * country, AS organisation, path and fingerprint all have one. This answers the same question
     * with a much larger bound, fetched only when the browser is opened rather than shipped with
     * every page, and it asks Solr how many distinct values there really are so the dialog can say
     * what it is NOT showing.
     *
     * The whole vocabulary is offered for a closed dimension, so "show me the sessions with a
     * forged beacon" is answerable on a small site where the honest answer is none — with
     * `mincount: 1` the option is simply absent, which reads as though the question cannot be
     * asked.
     *
     * `vq` turns it into a SEARCH over every value the dimension has rather than a listing of the
     * most common ones, which is a different question and is answered by a different mechanism —
     * see valueSearch() and \Loghound\Solr::facetContains(). The two populations are not the same
     * and the dialog says so: the LISTING is capped, the SEARCH is not.
     *
     * @return array<string,mixed>
     */
    private function values(): array
    {
        $fields = self::listableFields();
        $field = self::param('field', array_keys($fields), '');
        if ($field === '') {
            return $this->envelope(['error' => 'That is not a dimension this panel can list.']);
        }

        $search = Facets::searchTerm($_GET['vq'] ?? null);
        if ($search !== '') {
            return $this->valueSearch($field, $fields[$field], $search);
        }

        [$groups, $f] = $this->dimensionGroups(
            'sessions.values',
            self::ALL_BUCKETS,
            [],
            self::text('q', 200),
            [$field],
            true
        );

        $group = $groups[0] ?? null;

        return $this->envelope([
            'field'   => $field,
            'group'   => $group === null ? null : $this->facets->withKnownValues($group),
            'matched' => (int) ($f['count'] ?? 0),
            'active'  => $this->filters,
        ]);
    }

    /**
     * Every value of one dimension whose text contains what the operator typed.
     *
     * COMPLETE, and that is the point of it. The listing above is the two thousand most common
     * values; this searches the whole term dictionary, so a fingerprint or a path that is nowhere
     * near the top of its dimension is still findable by typing part of it. Case-insensitive,
     * because the things people search here are hashes, paths and organisation names.
     *
     * It is a CLASSIC facet rather than a JSON one, and that is not a style choice: the JSON Facet
     * API has no substring filter and silently drops `contains` instead of refusing it, so the
     * obvious spelling would have returned the dimension's most common values whatever was typed.
     * The measurements are on \Loghound\Solr::facetContains().
     *
     * The dimension's own filter is excluded, exactly as it is in the listing: searching inside a
     * filtered dimension would only ever return what is already selected, which is the same defect
     * this whole component exists to fix, wearing a search box.
     *
     * @return array<string,mixed>
     */
    private function valueSearch(string $field, string $label, string $search): array
    {
        $res = $this->gw->facetSearch(
            'sessions.values.search',
            $this->gw->sessionsCore(),
            $field,
            $search,
            ['q' => '*:*', 'fq' => $this->sessionFqs()],
            $this->facets->ownTags($field),
            self::SEARCH_BUCKETS
        );

        $group = $this->facets->group(
            [$field => $res],
            $field,
            self::SEARCH_BUCKETS,
            in_array($field, self::MONO_FIELDS, true)
        );

        /* A search that matched nothing is an ANSWER, not an absent one. group() returns null for
           an empty bucket list because a dimension with no values at all should not be drawn in a
           sidebar — but "no value contains this" is exactly what the operator asked, and the
           dialog has to be able to say it rather than fall back to a listing that would look like
           the search never happened. */
        if ($group === null) {
            $group = [
                'field'      => $field,
                'label'      => $label,
                'ns'         => $this->facets->namespaceKey(),
                'mono'       => in_array($field, self::MONO_FIELDS, true),
                'filterable' => true,
                'arity'      => $this->facets->arity($field),
                'op'         => $this->facets->op($field),
                'operators'  => $this->facets->operators($field),
                'chosen'     => $this->facets->values($field),
                'buckets'    => [],
                'distinct'   => null,
                'basis'      => $this->facets->ownTags($field) === [] ? 'filtered' : 'excluded',
                'basis_note' => '',
                'overlaps'   => $this->facets->arity($field) === Facets::ARITY_MULTI,
                'vocabulary' => Vocabulary::has($field),
            ];
        }

        $group['search'] = $search;
        $group['searched'] = true;
        $group['truncated'] = count($res['buckets']) >= self::SEARCH_BUCKETS;

        return $this->envelope([
            'field'  => $field,
            'label'  => $label,
            'search' => $search,
            'group'  => $group,
            'active' => $this->filters,
        ]);
    }

    /**
     * Build the dimension groups in ONE faceted request, through the shared facet layer.
     *
     * This used to write its own terms facets, which is where the defect lived: an untagged filter
     * is inside its own facet, so choosing `host_s=opensolr.com` left the VIRTUAL HOST list with
     * exactly one entry in it and no way to add a second. Panel\Facets attaches the tag to the
     * filter and the matching `domain.excludeTags` to that dimension's facet, so a filtered
     * dimension keeps listing every value it has while every other one still narrows — in the
     * same single round trip.
     *
     * `$only` restricts it to one dimension, for the value browser.
     *
     * @param array<string,mixed>    $extra Additional facet definitions to fold into the request.
     * @param array<int,string>|null $only
     * @return array{0:array<int,array<string,mixed>>,1:array<string,mixed>}
     */
    private function dimensionGroups(
        string $label,
        int $limit,
        array $extra = [],
        string $text = '',
        ?array $only = null,
        bool $numBuckets = false,
        array $extraFqs = []
    ): array {
        $fields = array_keys(self::browseFields());
        if ($only !== null) {
            $fields = array_values(array_intersect($fields, $only));
        }

        $f = $this->gw->searchFacet(
            $label,
            $this->gw->sessionsCore(),
            $text,
            ['fq' => array_merge($this->sessionFqs(), $extraFqs)],
            array_merge($extra, $this->facetDefs($fields, $limit, $numBuckets))
        );

        $matched = (int) ($f['count'] ?? 0);
        $groups = [];
        foreach ($this->facetGroups($f, $fields, $limit, self::MONO_FIELDS) as $group) {
            $groups[] = $this->facets->withAbsentValue($group, $matched);
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
        /* THE RAIL IS SHARED, THE PAGE IS NOT. Every view fetches this one action, so the
           caller names the view it is drawn beside and the counts are narrowed to that view's
           population — Query::viewScope() says which, and says nothing for the views that count
           all traffic. The slug is checked against the router rather than trusted: an unknown
           `for` yields no scope at all, never a filter built from request text. */
        $for = (string) ($_GET['for'] ?? '');
        $scope = isset(Layout::routes()[$for]) ? Query::viewScope($for) : [];

        [$groups, $f] = $this->dimensionGroups(
            'sessions.dimensions',
            self::BROWSE_BUCKETS,
            [],
            '',
            null,
            false,
            $scope
        );

        return $this->envelope([
            'dimensions' => $groups,
            'matched'    => (int) ($f['count'] ?? 0),
            'active'     => $this->filters,
        ]);
    }

    /**
     * Everything Loghound knows about one dimension value.
     *
     * The detail dialog behind every row that names a network, a country, a browser, a verdict
     * or a path. Three things, in the order an operator reads them: how much traffic this value
     * accounts for and what kind it was; how the value breaks down along the OTHER dimensions;
     * and then the visits themselves, which arrive from `visitors` a page at a time.
     *
     * THE VISITS ARE NO LONGER A SAMPLE. This used to return twelve session documents alongside
     * the aggregates and the dialog printed "the most recent 12 of 1,890" — a number the reader
     * can see and cannot reach. The list is a paged table now, so this request carries only the
     * first page's worth and every later page is one bounded read of twenty rows rather than a
     * refetch of the whole dialog.
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

        $scope = $this->dimensionScope($field, $value);
        if ($scope === null) {
            return $this->envelope(['error' => 'That value is not in the form this dimension holds.']);
        }

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

            /* TWO FACTS WORTH THE TOP OF THE DIALOG. Whether any of these visits searched, and
               whether any of them attacked, are the two questions a reader asks about a
               population before any percentage — and both were answerable only by scrolling
               into a breakdown, or not at all. Counted as queries over the same scope, so they
               agree with every other number here by construction. */
            'searched'  => ['type' => 'query', 'q' => 'search_terms_ss:*'],
            'attacked'  => ['type' => 'query', 'q' => Query::attackFq()],
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

        $recent = $this->visitorPage('sessions.dimension.recent', $scope, 0, Paging::PAGE);

        return $this->envelope([
            'field'      => $field,
            'label'      => $fields[$field] ?? $field,
            'value'      => $value,
            'filterable' => isset(Query::filterFields()[$field]),
            'sessions'   => (int) ($f['count'] ?? 0),
            'searched'   => self::qcount($f, 'searched'),
            'attacked'   => self::qcount($f, 'attacked'),
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
            'visitors'   => $recent['rows'],
            'page'       => $recent['page'],
            'requests'   => $field === 'paths_ss' ? $this->pathRequests($value) : null,
            'active'     => $this->filters,
        ]);
    }

    /**
     * The `fq` list that scopes a query to one dimension value, or null when it cannot be one.
     *
     * Split out of dimension() because `visitors` has to build the identical scope for its own
     * paged read, and two copies of "how a dimension becomes a filter" is two places for an
     * alias or a numeric field to be handled one way here and another way there — which would
     * make page two of a dialog describe a different population from page one.
     *
     * @return array<int,string>|null
     */
    private function dimensionScope(string $field, string $value): ?array
    {
        $solrField = Query::sessionFilterAliases()[$field] ?? $field;
        $clause = self::termFor($solrField, $value);
        if ($clause === null) {
            return null;
        }

        return array_merge($this->sessionFqs(), [$clause]);
    }

    /**
     * One page of visits behind a dimension value or behind a population.
     *
     * THE ONE ENDPOINT EVERY VISIT LIST IN A DIALOG PAGES THROUGH. A dimension dialog asks for
     * `field` and `value`; the Overview's population tiles ask for `pop`. Both end in the same
     * bounded read — twenty documents, an explicit field list, an exact `numFound` — so a dialog
     * listing 1,890 visits costs exactly as much per page as one listing nine, and no caller can
     * ask for the whole set at once.
     *
     * `pop` is a KEY into Query::populations(), so the filter that reaches Solr is one of five
     * constants in this repository and never anything a request composed.
     *
     * @return array<string,mixed>
     */
    private function visitors(): array
    {
        $scope = $this->sessionFqs();
        $subject = '';

        $pop = self::param('pop', array_keys(Query::populations()), '');
        if ($pop !== '') {
            $scope[] = Query::populations()[$pop];
            $subject = Query::populationLabels()[$pop] ?? $pop;
        }

        $fields = self::dimensionFields();
        $field = self::param('field', array_keys($fields), '');
        if ($field !== '') {
            $value = self::text('value', 256);
            if ($value === '') {
                return $this->envelope(['error' => 'That row carries no value to open.']);
            }
            $scoped = $this->dimensionScope($field, $value);
            if ($scoped === null) {
                return $this->envelope(['error' => 'That value is not in the form this dimension holds.']);
            }
            $scope = $pop === '' ? $scoped : array_merge($scoped, [Query::populations()[$pop]]);
            $subject = ($fields[$field] ?? $field) . ': ' . $value;
        }

        /* A BAND OF A NUMERIC FIELD, which is what a histogram bucket is. The chart draws
           `bot_score_f` in steps of five and every bar was a count with nothing behind it.
           The field comes from a list of two, never from the request text, and both bounds are
           clamped — so the worst a crafted link can do is ask for a band that is empty. The
           upper bound is exclusive except at the very top, or the sessions sitting exactly on
           a boundary would be counted in both neighbouring bands. */
        if ($pop === '' && $field === '') {
            $band = self::param('band', array_keys(self::BAND_FIELDS), '');
            if ($band !== '') {
                [$min, $max, $label] = self::BAND_FIELDS[$band];
                $from = Security::clampInt($_GET['from'] ?? null, $min, $max, $min);
                $to = Security::clampInt($_GET['to'] ?? null, $min, $max, $max);
                if ($to < $from) {
                    $to = $max;
                }
                $scope[] = $band . ':[' . $from . ' TO ' . $to . ($to >= $max ? ']' : '}');
                $subject = $label . ' ' . $from . '–' . $to;

                $page = $this->visitorPage('sessions.band', $scope, Paging::start(), Paging::rows());

                return $this->envelope([
                    'subject'  => $subject,
                    'pop'      => '',
                    'field'    => $band,
                    'visitors' => $page['rows'],
                    'page'     => $page['page'],
                    'active'   => $this->filters,
                ]);
            }

            return $this->envelope(['error' => 'Nothing was named to list the visits of.']);
        }

        $page = $this->visitorPage('sessions.visitors', $scope, Paging::start(), Paging::rows());

        return $this->envelope([
            'subject'  => $subject,
            'pop'      => $pop,
            'field'    => $field,
            'visitors' => $page['rows'],
            'page'     => $page['page'],
            'active'   => $this->filters,
        ]);
    }

    /**
     * Read one page of session documents under a scope and shape them as visits.
     *
     * @param array<int,string> $scope
     * @return array{rows:array<int,array<string,mixed>>,page:array<string,mixed>}
     */
    private function visitorPage(string $tag, array $scope, int $start, int $rows): array
    {
        $start = Security::clampInt($start, 0, Security::MAX_START, 0);
        $rows = Security::clampInt($rows, 1, Paging::MAX_PAGE, Paging::PAGE);

        $res = $this->gw->select($tag, $this->gw->sessionsCore(), [
            'q'     => '*:*',
            'fq'    => $scope,
            'sort'  => 'ts_start desc',
            'rows'  => $rows,
            'start' => $start,
            'fl'    => Query::sessionFl(),
        ]);

        $out = array_map([$this, 'shapeVisitor'], $res['docs']);

        return [
            'rows' => $out,
            'page' => Paging::block($start, $rows, (int) $res['numFound'], 'visits', count($out)),
        ];
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
            'referer_type_s', 'host_s', 'paths_ss', 'search_terms_ss',
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
     * A visit row: exactly what the five columns render, and nothing more.
     *
     * THE SHAPE IS THE TABLE'S CONTRACT. Every visit list in the panel shows date, address,
     * country, page and verdict, so those five plus the id that opens the record are what a row
     * carries. It used to carry twenty-four fields — the network, the parsed client, the
     * declared identity, two of the four clocks — because the table used to have ten columns;
     * shipping them now would be shipping a screenful of data per page to render a fifth of it.
     *
     * `city` and `region` ride along even though neither is a column: both go into the country
     * cell's title, which is where "Chicago, Illinois" belongs when the column itself has room
     * only for the country's name.
     *
     * `host` is not about the visitor either. The page cell shows a path, and a path with no
     * site in front of it is not a URL and cannot be opened.
     *
     * @param array<string,mixed> $d
     * @return array<string,mixed>
     */
    private function shapeVisitor(array $d): array
    {
        $str = static fn (string $k) => isset($d[$k]) && is_scalar($d[$k]) ? (string) $d[$k] : null;

        return [
            'id'       => (string) ($d['id'] ?? ''),
            'ts_start' => $str('ts_start'),
            'ip'       => $str('ip_s'),
            'country'  => $str('country_s'),
            'region'   => $str('region_s'),
            'city'     => $str('city_s'),
            'host'     => $str('host_s'),

            /* WHATEVER THEY ASKED FOR FIRST, and `entry_path_s` alone was not that. The
               sessionizer records a landing PAGE, so a session that only ever fetched
               /robots.txt, /sitemap.xml or a single image had no entry path at all and the
               column printed a dash — which reads as "we lost it" when the truth is that the
               visitor never requested a page. The exit path is the same field's other end and
               costs nothing, being already in the field list; between the two, every session
               that touched anything at all now names something. */
            'entry'    => $str('entry_path_s') ?? $str('exit_path_s'),
            'verdict'  => $str('bot_verdict_s'),
            'ident'    => $str('ident_s'),

            /* TIME ON SITE AND WHETHER IT BOUNCED, which the visit table now shows in place of
               the verdict chip — the verdict is the row's colour. Both clocks travel because
               they are different measurements: `engaged_ms` exists only where the beacon ran and
               is the honest one, `log_span_ms` is the fallback and is blind to the final page.
               The browser picks and says which it used. */
            'engaged_ms'  => isset($d['engaged_ms_l']) ? (int) $d['engaged_ms_l'] : null,
            'log_span_ms' => isset($d['log_span_ms_l']) ? (int) $d['log_span_ms_l'] : null,
            'bounced'     => self::bouncedOf($d),
        ];
    }

    /**
     * Did this one visit bounce, under the product's definition rather than the conventional one?
     *
     * One page AND under the engagement threshold. NULL when it cannot be judged — no beacon
     * means no engaged clock, and a single-page visit with no measurement is exactly the case
     * the conventional bounce rate gets wrong by assuming the worst. Three states, and the
     * table prints all three.
     */
    private static function bouncedOf(array $d): ?bool
    {
        $pages = isset($d['pages_i']) ? (int) $d['pages_i'] : null;
        if ($pages === null || $pages < 1) {
            return null;
        }
        if ($pages > 1) {
            return false;
        }
        if (!isset($d['engaged_ms_l'])) {
            return null;
        }

        return (int) $d['engaged_ms_l'] < Bounce::ENGAGED_MS;
    }

    /**
     * One session, with the first page of its request trail and the beacon overlay.
     *
     * THE TRAIL IS PAGED, and that is what replaces "Trail truncated — this session made more
     * requests than the panel fetches at once". A scraper's session can run to thousands of
     * requests; fetching two hundred of them and admitting the rest exist is the same defect as
     * "the most recent 12 of 1,890", and the reader's next question — what did it ask for at the
     * end — was exactly the part that was cut off.
     *
     * Each hit carries its own `host`, because a session can legitimately cross virtual hosts, so
     * the session's own host is the fallback for a hit that has none rather than the answer for
     * all of them.
     *
     * @return array<string,mixed>
     */
    private function detail(): array
    {
        $id = self::sessionId();
        if ($id === '') {
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

        $trail = $this->trailPage($id, 0, Paging::PAGE);

        return $this->envelope([
            'session'  => $this->shapeSession($sess['docs'][0]),
            'timeline' => $trail['rows'],
            'page'     => $trail['page'],
            'reasons'  => Bots::reasonCatalogue(),
        ]);
    }

    /**
     * One page of a session's request trail.
     *
     * Its own action so turning a page of the trail costs one bounded read of the hits core
     * rather than refetching the session document, its rule catalogue and every aggregate in
     * the dialog around it.
     *
     * @return array<string,mixed>
     */
    private function trail(): array
    {
        $id = self::sessionId();
        if ($id === '') {
            return $this->envelope(['error' => 'Not a session id.']);
        }

        $page = $this->trailPage($id, Paging::start(), Paging::rows());

        return $this->envelope([
            'timeline' => $page['rows'],
            'page'     => $page['page'],
        ]);
    }

    /**
     * Read one page of hits for a session, in request order.
     *
     * @return array{rows:array<int,array<string,mixed>>,page:array<string,mixed>}
     */
    private function trailPage(string $id, int $start, int $rows): array
    {
        $start = Security::clampInt($start, 0, Security::MAX_START, 0);
        $rows = Security::clampInt($rows, 1, self::MAX_TIMELINE, Paging::PAGE);

        $hits = $this->gw->select('sessions.hits', $this->gw->hitsCore(), [
            'q'     => '*:*',
            'fq'    => [Query::term('session_id_s', $id)],
            'sort'  => 'ts asc',
            'rows'  => $rows,
            'start' => $start,
            'fl'    => Query::hitFl(),
        ]);

        $timeline = [];
        foreach ($hits['docs'] as $h) {
            $timeline[] = [
                'id'      => (string) ($h['id'] ?? ''),
                'ts'      => (string) ($h['ts'] ?? ''),
                'seq'     => isset($h['session_seq_i']) ? (int) $h['session_seq_i'] : null,
                'method'  => (string) ($h['method_s'] ?? ''),
                'host'    => isset($h['host_s']) && is_scalar($h['host_s']) ? (string) $h['host_s'] : null,
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

        return [
            'rows' => $timeline,
            'page' => Paging::block(
                $start,
                $rows,
                (int) $hits['numFound'],
                'requests',
                count($timeline),
                Paging::sizesUpTo(self::MAX_TIMELINE)
            ),
        ];
    }

    /**
     * The session id a request named, or an empty string when it is not one.
     *
     * Shape-checked rather than trusted, and checked in ONE place because two actions read it:
     * a value that is not a session id must never reach Query::term(), whose escaping is correct
     * but whose job is not to decide what an identifier looks like.
     */
    private static function sessionId(): string
    {
        $id = self::text('id', 128);

        return preg_match('/^[A-Za-z0-9_-]{8,128}$/D', $id) === 1 ? $id : '';
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
        self::bounceCard('se-bounce', '02');

        echo '<div class="explorer" id="se-explorer">';
        echo '<button type="button" class="ghost small facets-show" id="se-facets-show">'
            . 'Show filters</button>';
        $this->facetsCard();
        $this->resultsCard();
        echo '</div>';
    }

    /**
     * The bounce-rate card, in the shape every page that shows the metric renders it.
     *
     * Static and shared rather than written out twice, because the Engagement view prints the
     * identical card and two copies of a metric's markup is two places for the threshold, the
     * denominators or the definition to be stated differently. The numbers behind it come from
     * Panel\Bounce, which is the one definition; this is the one presentation of it.
     *
     * IT IS ON THE SESSION EXPLORER because that is the page an operator is on when the question
     * "did any of these people actually read anything" occurs to them, and because a rate that
     * lives on only one page is a rate most people never see. It carries the same range, the same
     * virtual host and the same filters as the table underneath it, like every other number here.
     */
    public static function bounceCard(string $id, string $num): void
    {
        self::cardOpen($id, $num, 'Bounce rate', Bounce::definition());
        self::skeleton($id, 'stats', 0, 'Measuring engagement on single-page visits');

        echo '<div class="stats" id="' . Security::esc($id) . '-stats"></div>';
        echo '<div id="' . Security::esc($id) . '-detail"></div>';

        self::cardClose($id);
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
            'Matched across path, User-Agent, AS organisation, netname, reverse DNS, city and country.'
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

        /* IN THE HEAD'S TOOL SLOT, NOT FLOATING OVER IT. Positioned absolutely at the card's
           top right, this landed on top of the refresh control that lives in the same corner —
           two controls in one place, on every screen size. cardOpen() has a slot for exactly
           this, beside the heading and before the refresh, so it goes there and the layout
           keeps them apart by itself. */
        self::cardOpen(
            'se-facets',
            '03',
            'Filter by',
            '',
            '<button type="button" class="ghost small facets-fold" id="se-facets-fold"'
                . ' aria-controls="se-explorer">Hide</button>'
        );
        self::skeleton('se-facets', 'rows', 0, 'Counting facet values');
        echo '<div id="se-facet-list"></div>';
        self::cardClose('se-facets');
        echo '</aside>';
    }

    /**
     * The visit table.
     *
     * FIVE COLUMNS, AND THE COUNT IS THE CONTRACT: date, address, country, page, verdict. The
     * same five everywhere a list of visits appears in this product — here, in the dimension
     * dialog, in the fingerprint and virtual-host dialogs, and in the population dialogs the
     * Overview tiles open. The markup below is the server-side twin of assets/js/visits.js's
     * `visitTableHead()`, and the widths are that file's `WIDTHS`; the two have to stay in step
     * or a header cell sits over the wrong column.
     *
     * THE DATE AND THE PAGE ARE WHY. With seven columns the date cell resolved to about 110px
     * and rendered "09/11/2026 …" with the time cut off, which is the column failing at the one
     * job it has, and the page cell rendered "/openso…", which names nothing. The network, the
     * client, the request count and the score are on the session document and in the dialog the
     * row opens, where each of them has room for the sentence that says what it means.
     *
     * THERE IS NO SIXTH COLUMN FOR THE OPENER. A link inside a cell wins the click over the row,
     * so a drillable row needs an unambiguous "open this" control; it goes at the right-hand end
     * of the verdict cell rather than in a column of its own, because the five-column rule is
     * about what the reader has to read and a chevron is a control.
     *
     * The historical note this replaces: it carried ten columns, and ten columns do not fit —
     * measured at a 1440px window the table resolved to 900px — its own minimum, inside an
     * 836px wrapper — and the `<colgroup>` was over-constrained, 737px of fixed `ch` widths
     * plus two percentage columns asking for another 35%. The browser resolves that by
     * starving the percentages, so the two columns carrying the longest prose got 93px and
     * 70px, and the last column, whose `<col>` had no width at all, resolved to ZERO and was
     * invisible on every desktop. `Amazon Technolo…` sat 16px from `Chrome 139` and the two
     * read as one run of text.
     *
     * A fixed layout cannot invent width that is not there, so the answer is fewer columns,
     * each holding one subject rather than one field:
     *
     *   - the address is the visitor, so what qualifies it — the city, the identity the
     *     measured site declared, whether they were signed in — is a second line inside the
     *     same cell rather than three more columns;
     *   - the verdict and its score are one judgement and share a cell;
     *   - log span, engaged time and the entry page left the table entirely. They are in the
     *     detail dialog, per session, with the definitions beside them — which is the only
     *     place the difference between a log span and an engaged second can actually be read.
     *
     * EVERY WIDTH IS A PERCENTAGE AND THEY SUM TO 100. Mixing `ch` and `%` in one colgroup is
     * what produced the starvation: percentages are of the table, `ch` is of the font, and the
     * two cannot be reconciled when the total exceeds the width. Percentages alone are exact
     * under `table-layout: fixed` and there is nothing left to over-constrain.
     */
    private function resultsCard(): void
    {
        echo '<div class="results">';
        /* THE THIRD NUMBER, which this card did not print. Layout::cardsIn() numbers the jump
           bar by position, so the bar read "03 Recent visitors" while the card head above the
           table showed nothing at all — the bar and the card disagreeing about the same card,
           which is the one thing the section numbering exists to prevent. The population is
           written by the front end once the result count is known, so it stays empty here. */
        self::cardOpen(
            'se-results',
            '04',
            'Recent visitors',
            '',
            '<span class="job-meta" id="se-count"></span>' . $this->exportTool('sessions')
        );
        self::skeleton('se-results', 'rows', 0, 'Searching sessions');

        echo '<div class="table-wrap"><table id="se-table" class="table-fixed visits"><colgroup>'
            /* THE DATE COLUMN NEVER TRUNCATES. `mm/dd/yyyy hh:mm:ss` is nineteen monospace
               characters, and at 17% of a column already narrowed by the filter sidebar it was
               being cut mid-hour — "09/12/2026 03:1…" — which is the one value on the row a
               reader scans down. The width comes out of Country, which now draws the flag only. */
            /* SIX COLUMNS, AND THE WIDTHS ARE THE CONTRACT. This head is rendered here while the
               rows are built by assets/js/visits.js, so the two have to agree column for column
               — they did not, which is why the cells were landing under the wrong headings. */
            . '<col style="width:17%"><col style="width:17%"><col style="width:28%">'
            . '<col style="width:20%"><col style="width:9%"><col style="width:9%">'
            . '</colgroup><thead><tr>'
            . '<th scope="col">Date</th>'
            . '<th scope="col">IP</th>'
            . '<th scope="col">Page</th>'
            . '<th scope="col">Email</th>'
            . '<th scope="col">Sess time</th>'
            . '<th scope="col" class="visit-verdict">Bounce</th>'
            . '</tr></thead><tbody></tbody></table></div>';
        echo '<div id="se-pager"></div>';

        self::cardClose('se-results');
        echo '</div>';
    }
}
