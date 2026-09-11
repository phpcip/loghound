<?php
/**
 * Loghound — base class for every panel view.
 *
 * Responsibilities, deliberately small:
 *  - own the validated request state (time range, paging, filters) so no controller
 *    re-parses `$_GET` and no controller invents its own clamping;
 *  - expose the Gateway (the only route to Solr);
 *  - provide the JSON response helper.
 *
 * Every subclass implements two things:
 *  - `body()`  — the static HTML skeleton of the view. It contains headings, captions and
 *                empty states, but NO data: data arrives by fetch() so a slow Solr never
 *                blocks first paint, and so there is exactly one place (the JSON endpoint)
 *                where log-derived values are serialised.
 *  - `api()`   — returns a plain array for a named data action. The array is JSON-encoded
 *                by the front controller. It contains ONLY aggregates, except in the
 *                session explorer where it contains rows-clamped session documents.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Config;
use Loghound\Security;

abstract class Controller
{
    protected Config $cfg;
    protected Gateway $gw;

    /** @var array<string,mixed> The resolved time range (see Panel\Query::range). */
    protected array $range;

    /**
     * @var array<string,array<int,string>> Active facet filters, field => list of values.
     * Only fields in Query::filterFields() ever land here.
     *
     * The flattened view of Panel\Facets, kept because it is what every API payload's `active`
     * key has carried since the beginning. The OPERATOR is not in it and must not be folded in:
     * a view reading this sees which values are selected, and `$this->facets->op($field)` says
     * what is being done with them.
     */
    protected array $filters = [];

    /**
     * The facet layer for Loghound's own cores: selection, operator, tagging, exclusion, URLs.
     *
     * One object per request, built from the query string. Every `fq` list, every facet
     * definition and every filter link on every view comes out of it, so there is nowhere left
     * for a view to keep a private copy of how filtering works.
     */
    protected Facets $facets;

    /**
     * The same layer restricted to the fields the HITS core defines.
     *
     * A second instance rather than a flag, because the two cores answer different questions
     * and the hits plane has to be able to report what it dropped without the sessions plane
     * knowing about it.
     */
    protected Facets $hitFacets;

    public function __construct(Config $cfg, Gateway $gw)
    {
        $this->cfg   = $cfg;
        $this->gw    = $gw;
        $this->range = Query::range(isset($_GET['range']) && is_string($_GET['range']) ? $_GET['range'] : null);
        $this->facets = Facets::sessions($_GET);
        $this->hitFacets = Facets::hits($_GET);
        $this->filters = $this->facets->flat();
    }

    /** The facet layer, for a view that needs the operator or a filter URL. */
    public function facetLayer(): Facets
    {
        return $this->facets;
    }

    /** URL slug for this view, e.g. 'overview'. Used for routing and nav highlighting. */
    abstract public function slug(): string;

    /** Human title shown in the header and the <title> tag. */
    abstract public function title(): string;

    /** One line under the title explaining what the view answers. */
    abstract public function subtitle(): string;

    /** Static HTML for the view. Echoes; returns nothing. */
    abstract public function body(): void;

    /**
     * Answer a data action.
     *
     * @return array<string,mixed>
     */
    abstract public function api(string $action): array;

    /**
     * Read a string parameter, restricted to an allowlist.
     *
     * An EMPTY allowlist admits nothing and yields the default. It used to mean the
     * opposite — no list, no filtering, raw request value returned — which is a trap for
     * any caller building the list dynamically: a list that comes back empty because a
     * feature is unconfigured or an account owns nothing then turned the guard off at
     * exactly the moment it was most needed. Nothing is allowed until something says it is.
     *
     * @param array<int,string> $allowed
     */
    protected static function param(string $key, array $allowed = [], string $default = ''): string
    {
        $v = $_GET[$key] ?? null;
        if (!is_string($v)) {
            return $default;
        }
        if (!in_array($v, $allowed, true)) {
            return $default;
        }
        return $v;
    }

    /**
     * Read free text (a search box), length-capped.
     *
     * The cap is not a security control on its own — the value is bound as a Solr
     * parameter, never spliced — but an unbounded query string is a cheap way to make
     * Solr work hard, so it is capped here as well.
     */
    protected static function text(string $key, int $max = 200): string
    {
        $v = $_GET[$key] ?? '';
        if (!is_string($v)) {
            return '';
        }
        $v = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $v) ?? '';
        return mb_substr(trim($v), 0, $max);
    }

    /**
     * Turn the active filters into Solr `fq` clauses.
     *
     * DELEGATED, and that is the change. This used to build the clauses itself, as
     * `field:("a" OR "b")` with no tag, which is precisely the defect the facet layer exists to
     * fix: an untagged filter is inside its own facet, so picking one host left the host list
     * with one entry in it and no way to add a second. Every clause now carries
     * `{!tag=f_<field>}` and the operator the dimension is set to, and the facet for that
     * dimension is asked for with the matching `domain.excludeTags`.
     *
     * The signature is unchanged so that no view has to move at the same time as the engine.
     * `$rename` is accepted and ignored: the aliases are a property of the plane (the sessions
     * core spells `session_id_s` as `id`) and are now declared once on the Facets instance
     * rather than passed in at each of five call sites, any one of which could forget.
     *
     * @param array<int,string>|null $only   Field names to keep, or null for all active filters.
     * @param array<string,string>   $rename Ignored; kept so callers need not change together.
     * @return array<int,string>
     */
    protected function filterFqs(?array $only = null, array $rename = []): array
    {
        return $this->facets->fqs($only);
    }

    /**
     * The labels of active filters a hits-core view cannot honour.
     *
     * A verdict, a bot class and a fired signal are conclusions the scorer reaches about a
     * whole session; they live only on the sessions core. A view that queries hits must say
     * which filters it ignored rather than print numbers under a filter chip that did
     * nothing — a silently dropped filter is a wrong answer presented as a right one.
     *
     * @return array<int,string>
     */
    protected function ignoredHitFilters(): array
    {
        $usable = array_keys(Query::hitFilterFields());
        $labels = Query::filterFields();

        $out = [];
        foreach (array_keys($this->filters) as $field) {
            if (!in_array($field, $usable, true)) {
                $out[] = $labels[$field] ?? $field;
            }
        }
        return $out;
    }

    /**
     * The filter that keeps a rollup document out of a session count.
     *
     * The sessions core holds two document types discriminated by `doc_type_s`: one per
     * closed session, and one per UTC day written by bin/loghound-score. The schema at
     * solr/sessions/conf/managed-schema.xml states the contract — every dashboard query must
     * say which type it wants — and this constant is the panel's half of it.
     */
    protected const FQ_SESSION_DOCS = 'doc_type_s:session';

    /**
     * The filter that keeps a session which has not ended out of an aggregate.
     *
     * The panel's half of the `provisional_b` contract (SPEC §4.2). A negation, for the reason
     * spelled out on Query::SETTLED_SESSIONS: the field is never written as false, so this is the
     * only spelling that also matches the sessions a site already had.
     */
    protected const FQ_SETTLED = Query::SETTLED_SESSIONS;

    /**
     * The base `fq` list for a sessions-core query: document type, time range, filters.
     *
     * The document-type clause is not optional. A rollup document carries `ts_start`, so
     * without it the rollup falls inside the selected range and is counted as a session:
     * every headline total is inflated by up to one document per day in range — ninety on a
     * ninety-day window — and the five populations stop summing to the figure printed above
     * them, because a rollup matches none of them.
     *
     * SESSIONS THAT ARE STILL OPEN ARE INCLUDED, and that is a decision rather than a default.
     * Excluding them here would mean a fresh install shows nothing for half an hour on every
     * view — the exact defect provisional documents exist to fix — so the live population is
     * what a counting or faceting card gets: how many sessions, from which networks, with which
     * verdicts, sharing which fingerprints. Their verdicts are honestly weakened by the scorer
     * (Score\Rules::DEFERRED_CODES) rather than hidden by the panel, and the five Overview
     * populations still partition the domain exactly, because a provisional verdict is still one
     * of the five and is floored into `unknown` rather than into nothing.
     *
     * A card whose number is only meaningful once a session has FINISHED must call
     * settledSessionFqs() instead and say so. Duration and engagement averages are the clear
     * case: an open session's log_span_ms_l is partial by construction, so averaging it in makes
     * "time on site" read low — which is precisely the lie the timing card exists to expose.
     *
     * Every sessions-core query reached through a Controller subclass goes through one of these
     * two. The two queries in Panel\Callers build their own `fq` list and carry the document-type
     * clause themselves; Panel\Jobs deliberately counts the whole core, because "how many
     * documents are in this index" is the question that diagnostic asks.
     *
     * @return array<int,string>
     */
    protected function sessionFqs(): array
    {
        return array_merge(
            [self::FQ_SESSION_DOCS, Query::rangeFq('ts_start', $this->range)],
            $this->facets->fqs()
        );
    }

    /**
     * sessionFqs(), restricted to sessions that have ended.
     *
     * For the cards that measure a session rather than count one. A provisional document carries
     * partial counts — hits so far, bytes so far, the span between the first hit and the most
     * recent one — so any average, percentile or ratio built on them is measuring how long ago
     * the visitor arrived, not how long they stayed. Those cards want this list; the ones that
     * answer "who is here" want sessionFqs().
     *
     * The caption on such a card has to name the population, as SPEC §10 requires of every
     * number: the figure covers completed sessions, and the live ones are deliberately not in it.
     *
     * @return array<int,string>
     */
    protected function settledSessionFqs(): array
    {
        $fqs = $this->sessionFqs();
        $fqs[] = self::FQ_SETTLED;
        return $fqs;
    }

    /**
     * The base `fq` list for a hits-core query: time range, plus every active filter the
     * hits core can actually answer.
     *
     * This used to return the range alone, so the whole sidebar — the virtual-host selector
     * included — scoped every sessions-core view and silently did nothing to Performance.
     * Picking one site and reading its latency gave the latency of every site on the
     * machine, under a chip saying otherwise.
     *
     * Filters the hits core cannot answer are dropped here and reported by
     * ignoredHitFilters(), which the view surfaces.
     *
     * It goes through the HITS facet instance and not the sessions one, and the difference is
     * load-bearing rather than tidiness: the sessions instance rewrites `session_id_s` to `id`,
     * because a session document IS its session. On the hits core `session_id_s` is a real field
     * and `id` is the hit's own identifier, so borrowing the sessions instance here would filter
     * a hit timeline by a session id against the wrong field and return nothing.
     *
     * @return array<int,string>
     */
    protected function hitFqs(): array
    {
        return array_merge(
            [Query::rangeFq('ts', $this->range)],
            $this->hitFacets->fqs()
        );
    }

    /**
     * The card a cross-tabulation is drawn into, or nothing when this view has no pivot.
     *
     * ONE CARD SHAPE for all of them, emitted here rather than written out in each view, for the
     * same reason the facet markup is: three hand-written copies of a table skeleton is three
     * places for a `<colgroup>` to drift out of step.
     *
     * The heading and the caption come from Query::pivots(), so the question the cross-tab answers
     * is on screen above it. A grid of numbers with no stated question is one the reader has to
     * guess the point of, and the guess is usually that the row total equals the sum of its cells —
     * which it does not, because the inner facet is limited. The renderer states the shortfall per
     * row; the caption states the population.
     */
    protected function pivotCard(string $id, string $num): void
    {
        $pivot = Query::pivots()[$this->slug()] ?? null;
        if ($pivot === null) {
            return;
        }
        $labels = Query::filterFields();
        $outer = $labels[$pivot[0]] ?? $pivot[0];
        $inner = $labels[$pivot[1]] ?? $pivot[1];

        self::cardOpen($id, $num, $outer . ' by ' . $inner, $pivot[2]);
        self::skeleton($id, 'rows', 0, 'Cross-tabulating ' . mb_strtolower($outer) . ' by ' . mb_strtolower($inner));
        echo '<div class="table-wrap"><table id="' . Security::esc($id) . '-table" class="table-fixed pivot">'
            . '<colgroup><col style="width:32%"><col style="width:12%"><col style="width:56%"></colgroup>'
            . '<thead><tr>'
            . '<th scope="col">' . Security::esc($outer) . '</th>'
            . '<th scope="col" class="num">Sessions</th>'
            . '<th scope="col">' . Security::esc($inner) . '</th>'
            . '</tr></thead><tbody></tbody></table></div>';
        self::cardClose($id);
    }

    /**
     * Clamp a caller-supplied `rows` value.
     *
     * Security::MAX_ROWS is the hard ceiling; each caller passes a lower, view-appropriate
     * maximum. Deep paging is separately capped by Security::MAX_START.
     */
    protected static function rows(int $max, int $default): int
    {
        return Security::clampInt($_GET['rows'] ?? null, 1, min($max, Security::MAX_ROWS), $default);
    }

    /** Clamp a caller-supplied `start` (paging offset). */
    protected static function start(): int
    {
        return Security::clampInt($_GET['start'] ?? null, 0, Security::MAX_START, 0);
    }

    /**
     * Metadata every API response carries.
     *
     * `population` and `total` are here because SPEC §10 requires every number to state
     * what it counts; putting them in the envelope means a view cannot forget to.
     *
     * @param array<string,mixed> $extra
     * @return array<string,mixed>
     */
    protected function envelope(array $extra = []): array
    {
        return array_merge([
            'range'      => $this->range['key'],
            'range_label' => $this->range['label'],
            'demo'       => $this->gw->isDemo(),
            'error'      => $this->gw->error(),
            'filters'    => $this->facets->payload(),
        ], $extra);
    }

    /**
     * Facet definitions for a set of dimensions, each one excluding its own filter.
     *
     * The method a view calls instead of hand-writing a terms facet. It is what makes the
     * multi-select work: the definition for `host_s` carries `domain.excludeTags: ['f_host_s']`
     * when a host filter is in force, so the host list keeps every host with the count it would
     * have if that filter were lifted, while every other dimension in the same request still
     * narrows. One Solr round trip, however many dimensions.
     *
     * @param array<int,string> $fields
     * @return array<string,mixed>
     */
    protected function facetDefs(array $fields, int $limit = 12, bool $numBuckets = false): array
    {
        return $this->facets->termsFacets($fields, $limit, $numBuckets);
    }

    /**
     * The rendered dimension groups for a facet response.
     *
     * @param array<string,mixed> $facets
     * @param array<int,string>   $fields
     * @param array<int,string>   $mono   Dimensions rendered monospace, because the value is an id.
     * @return array<int,array<string,mixed>>
     */
    protected function facetGroups(array $facets, array $fields, int $limit = 12, array $mono = []): array
    {
        return $this->facets->groups($facets, $fields, $limit, $mono);
    }

    /**
     * This view's cross-tabulation, as a facet definition, or an empty array when it has none.
     *
     * The pairing comes from Query::pivots(), keyed by view slug, so the choice of what is worth
     * cross-tabulating is declared in one table rather than decided inside eleven view files.
     *
     * @return array<string,mixed>
     */
    protected function pivotDef(int $outerLimit = 8, int $innerLimit = 5): array
    {
        $pivot = Query::pivots()[$this->slug()] ?? null;
        if ($pivot === null) {
            return [];
        }
        return $this->facets->pivot('pivot', $pivot[0], $pivot[1], $outerLimit, $innerLimit);
    }

    /**
     * This view's cross-tabulation, shaped for the browser, or null when it has none.
     *
     * Carries the question it answers alongside the rows, because a cross-tab with no stated
     * question is a grid of numbers a reader has to guess the point of — and `covered`, per row,
     * because the inner facet is limited and the cells of a row therefore do NOT add up to the
     * row total. Presenting them as if they did would be a wrong number.
     *
     * @param array<string,mixed> $facets
     * @return array<string,mixed>|null
     */
    protected function pivotRows(array $facets): ?array
    {
        $pivot = Query::pivots()[$this->slug()] ?? null;
        if ($pivot === null) {
            return null;
        }
        $rows = Facets::pivotRows($facets, 'pivot', $pivot[0], $pivot[1]);
        if ($rows === []) {
            return null;
        }

        $labels = Query::filterFields();
        return [
            'outer'       => $pivot[0],
            'inner'       => $pivot[1],
            'outer_label' => $labels[$pivot[0]] ?? $pivot[0],
            'inner_label' => $labels[$pivot[1]] ?? $pivot[1],
            'question'    => $pivot[2],
            'rows'        => $rows,
        ];
    }

    /**
     * Read a terms-facet bucket list out of a facets block, tolerating an absent facet.
     *
     * Solr omits a facet key entirely when the domain is empty, so every read of a bucket
     * list has to cope with "not there" — doing it in one helper keeps the controllers
     * free of isset() noise and stops a missing facet from becoming a PHP warning in the
     * middle of a JSON response.
     *
     * @param array<string,mixed> $facets
     * @return array<int,array<string,mixed>>
     */
    protected static function buckets(array $facets, string $key): array
    {
        $node = $facets[$key] ?? null;
        if (!is_array($node) || !isset($node['buckets']) || !is_array($node['buckets'])) {
            return [];
        }
        return $node['buckets'];
    }

    /**
     * Read the `count` of a query sub-facet, defaulting to 0.
     *
     * @param array<string,mixed> $facets
     */
    protected static function qcount(array $facets, string $key): int
    {
        $node = $facets[$key] ?? null;
        return is_array($node) ? (int) ($node['count'] ?? 0) : 0;
    }

    /**
     * Read a numeric aggregate, preserving null.
     *
     * Null matters: SPEC §1 forbids fabricating a metric, so "no sessions had a value for
     * this field" must reach the browser as null and render as an em-dash, not as 0.
     *
     * @param array<string,mixed> $node
     */
    protected static function num(array $node, string $key): ?float
    {
        $v = $node[$key] ?? null;
        return is_numeric($v) ? (float) $v : null;
    }

    /**
     * Emit a JSON response and stop.
     *
     * Used by the asynchronous job endpoints, which are POSTs and therefore reach a
     * controller through the front controller's state-change path rather than its JSON
     * path. Emitting here keeps the response next to the code that produced it. The same
     * JSON_HEX_* flags as Security::escJs() are set so a User-Agent containing markup
     * cannot do anything if this payload is ever rendered somewhere it should not be.
     *
     * @param array<string,mixed> $payload
     * @return never
     */
    protected static function sendJson(array $payload, int $status = 200): void
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, private');
        header('X-Content-Type-Options: nosniff');
        echo json_encode(
            $payload,
            JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
            | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
        );
        exit;
    }

    /**
     * Render the standard "population covered" caption.
     *
     * Every chart and every stat block in the panel carries one. It is a <p> and not a
     * tooltip on purpose: a caption you have to hover to find does not stop anyone
     * misreading a number in a screenshot.
     */
    protected static function pop(string $text): void
    {
        echo '<p class="pop">' . Security::esc($text) . '</p>';
    }

    /**
     * Open a card and render its header and caption.
     *
     * Emits no loading state on its own: a card whose content is rendered server-side
     * (the settings forms) calls this and then cardEnd(), while a card whose content
     * arrives over the wire calls skeleton() in between, which is what adds the progress
     * strip. Keeping the two apart means a static card can never sit there showing a
     * progress bar for data it was never going to fetch.
     *
     * @param string $id         Base id. Parts are "<id>-status", "-skel", "-content",
     *                           "-empty", "-pop"; the chart or table keeps the bare id.
     * @param string $num        Section number, e.g. "01".
     * @param string $heading    Section label, rendered uppercase.
     * @param string $population The "what this counts" caption. SPEC §10 requires one.
     * @param string $tools      Pre-escaped control markup for the right of the header.
     */
    protected static function cardOpen(
        string $id,
        string $num,
        string $heading,
        string $population = '',
        string $tools = ''
    ): void {
        $e = Security::esc($id);
        echo '<section class="card" id="' . $e . '-card" data-card="' . $e . '">';
        echo '<div class="card-head"><h2>'
            . '<span class="card-num">' . Security::esc($num) . '</span>'
            . '<span>' . Security::esc($heading) . '</span></h2>'
            . $tools
            . '</div>';
        if ($population !== '') {
            echo '<p class="pop" id="' . $e . '-pop">' . Security::esc($population) . '</p>';
        } else {
            echo '<p class="pop" id="' . $e . '-pop" hidden></p>';
        }
    }

    /**
     * Emit the loading state for an async card and open its content wrapper.
     *
     * The progress strip is a flat bar plus a sentence naming what is happening, because
     * a bare spinner tells an operator nothing about whether to keep waiting. The
     * skeleton is flat blocks with a slow opacity pulse rather than a shimmer, since a
     * shimmer is a gradient and the design system bans gradients.
     *
     * The real content is present in the DOM from the first byte and merely hidden, so
     * table headers and captions are already escaped and laid out before any data
     * arrives — the front end only ever fills in cells.
     *
     * @param string $kind   'chart', 'rows' or 'stats'.
     * @param int    $height Chart height in pixels, ignored for other kinds.
     * @param string $label  What the card says it is doing, in words.
     */
    protected static function skeleton(
        string $id,
        string $kind = 'rows',
        int $height = 300,
        string $label = 'Querying Solr'
    ): void {
        $e = Security::esc($id);

        echo '<div class="card-status" id="' . $e . '-status" data-label="' . Security::esc($label) . '">'
            . '<span class="progress progress-indeterminate"><span class="progress-fill"></span></span>'
            . '<span class="loading">'
            . '<span class="loading-label">' . Security::esc($label) . '&#8230;</span>'
            . '<span class="loading-elapsed"></span>'
            . '</span>'
            . '</div>';

        echo '<div class="skel-rows" id="' . $e . '-skel" aria-hidden="true">';
        if ($kind === 'chart') {
            echo '<div class="skel skel-chart" style="height:'
                . Security::clampInt($height, 80, 600, 300) . 'px"></div>';
        } elseif ($kind === 'stats') {
            echo '<div class="skel skel-line skel-w30" style="height:34px"></div>';
            echo '<div class="skel skel-line skel-w50"></div>';
        } else {
            foreach (['skel-w90', 'skel-w70', 'skel-w90', 'skel-w50', 'skel-w70', 'skel-w30'] as $width) {
                echo '<div class="skel skel-line ' . $width . '"></div>';
            }
        }
        echo '</div>';
        echo '<div class="card-content" id="' . $e . '-content" hidden>';
    }

    /** Close an async card: its content wrapper, its empty-state slot and the section. */
    protected static function cardClose(string $id): void
    {
        echo '</div>';
        echo '<div class="empty" id="' . Security::esc($id) . '-empty" hidden></div>';
        echo '</section>';
    }

    /** Close a card whose content was rendered server-side and needs no loading state. */
    protected static function cardEnd(): void
    {
        echo '</section>';
    }

    /**
     * The common case: a card whose entire body is one chart.
     */
    protected static function chart(
        string $id,
        string $num,
        string $heading,
        string $population,
        int $height = 300,
        string $label = 'Querying Solr'
    ): void {
        self::cardOpen($id, $num, $heading, $population);
        self::skeleton($id, 'chart', $height, $label);
        echo '<div class="chart" id="' . Security::esc($id) . '" style="height:'
            . Security::clampInt($height, 80, 600, 300) . 'px"></div>';
        self::cardClose($id);
    }
}
