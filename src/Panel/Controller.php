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
use Loghound\Csv;
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

    /**
     * The facet layer the page FURNITURE is rendered from — the union of both planes.
     *
     * Display only, and deliberately not `$this->facets`. The filter bar is one control at the
     * top of every page, so it has to be able to show a filter set on either plane: a status
     * filter chosen on a hits-plane view is real, it is narrowing that page, and rendering the
     * bar from the sessions layer would make it invisible and unremovable.
     *
     * NO QUERY IS BUILT FROM THIS. `sessionFqs()` goes through the sessions layer and `hitFqs()`
     * through the hits one; each drops what its own core cannot answer and says so through
     * `filters_ignored`, which the hits-plane views print. See Facets::all().
     */
    public function facetLayer(): Facets
    {
        return Facets::all($_GET);
    }

    /** The time-range picker scopes this view's queries. */
    public const SCOPE_RANGE = 'range';

    /** The virtual-host selector scopes this view's queries. */
    public const SCOPE_HOST = 'host';

    /** The "Filter by" facet bar scopes this view's queries. */
    public const SCOPE_FACETS = 'facets';

    /**
     * This view reads cached Solr answers, so clearing the cache changes what it shows.
     *
     * The same rule as the other three, stated once: Index analytics makes no Solr read at all —
     * its cards come from the Opensolr request-log plane, which is not cached — so clearing the
     * cache would discard nothing that page is showing.
     */
    public const SCOPE_CACHE = 'cache';

    /**
     * Which page-toolbar controls this view actually honours.
     *
     * THE TOOLBAR IS RENDERED FROM THIS AND NOTHING ELSE. It used to be rendered
     * unconditionally on every page: Layout emitted the six range links, and app.js injected
     * the host selector and the "Filter by" bar, whatever the view underneath them did with
     * the values. On Settings that produced four controls of which not one had any effect —
     * pressing 7D changed nothing, because the single Solr query on that page is deliberately
     * pinned to 30 days and no card on it reads a facet or a host. A control that responds to
     * being pressed by doing nothing is the defect this method exists to make impossible.
     *
     * It is answered per view rather than special-cased for Settings, because "hide it on
     * Settings" would have left the same lie on Storage & bandwidth, where the picker is
     * equally inert, and would have let the next view inherit whichever controls it forgot to
     * think about.
     *
     * THE DEFAULT IS NOTHING. A view that does not declare gets no controls rather than all of
     * them: an absent control is a missing affordance the operator can ask for, while a dead
     * one is a wrong answer they cannot detect. tests/test_page_toolbar.php then requires every
     * concrete view to declare its own, so the default is unreachable in a shipped release and
     * a new view cannot quietly inherit either behaviour.
     *
     * Declaring a control here is a claim that the view's own queries honour it, and that claim
     * is checked: a view that lists SCOPE_RANGE must bound its queries by `$this->range`, one
     * that lists SCOPE_HOST or SCOPE_FACETS must pass the facet filters into its `fq`.
     *
     * @return array<int,string>
     */
    public function toolbar(): array
    {
        return [];
    }

    /** Does this view honour one of the page-toolbar controls? */
    public function honours(string $control): bool
    {
        return in_array($control, $this->toolbar(), true);
    }

    /**
     * The sections this view renders, in render order.
     *
     * ONE ORDERED LIST, FOUR CONSUMERS: the left navigation's sub-items, the URL that names
     * each page, the number printed on each card, and the order body() walks where the view
     * chooses to. Each entry is `[card id, short label]` and may carry further elements the
     * view uses for its own dispatch; nothing outside the view reads past the second.
     *
     * Declared as a class constant rather than computed, because \Loghound\Panel\Layout has to
     * build the whole navigation tree — every view's sub-items, not only the current view's —
     * and rendering twelve view bodies to discover their headings would make the navigation
     * cost more than the page under it.
     *
     * @var array<int,array<int,string>>
     */
    public const SECTIONS = [];

    /**
     * This view's section list, for the navigation and for the router.
     *
     * Static so the navigation can ask a view class what pages it has without constructing it.
     * `static::` rather than `self::`, so a subclass's own list is the one that answers.
     *
     * @return array<int,array<int,string>>
     */
    public static function sectionList(): array
    {
        return static::SECTIONS;
    }

    /**
     * The same list, through an instance.
     *
     * Kept because Layout renders from the instance it already has, and because the views that
     * declared sections() before this constant existed keep working unchanged.
     *
     * @return array<int,array<int,string>>
     */
    public function sections(): array
    {
        return static::sectionList();
    }

    /**
     * The URL segment that names one section, derived from its card id.
     *
     * Card ids carry a per-view prefix — `atk-answered`, `set-solr`, `ix-volume` — which is
     * exactly right for an element id and is noise in a URL that already names the view. The
     * prefix is dropped, so the page is `?v=attacks&s=answered`. A card id with no prefix
     * answers as itself.
     *
     * The router accepts the full card id as well (see sectionFor), so every link that was ever
     * minted against an id keeps resolving.
     */
    public static function sectionSlug(string $cardId): string
    {
        $cut = strpos($cardId, '-');
        $slug = $cut === false ? $cardId : substr($cardId, $cut + 1);
        return $slug === '' ? $cardId : $slug;
    }

    /**
     * Resolve a requested section to one of this view's card ids.
     *
     * An unknown, absent or malformed value lands on the FIRST section rather than on a 404: a
     * stale bookmark to a section that has been renamed or deleted should show the view it named,
     * and a prober learns nothing from the answer either way. Returns '' when the view has fewer
     * than two sections, which is the signal to render the whole body.
     */
    public function sectionFor(?string $requested): string
    {
        $sections = $this->sections();
        if (count($sections) < 2) {
            return '';
        }

        $first = (string) ($sections[0][0] ?? '');
        if (!is_string($requested) || $requested === '') {
            return $first;
        }

        foreach ($sections as $entry) {
            $id = (string) ($entry[0] ?? '');
            if ($id !== '' && ($requested === $id || $requested === self::sectionSlug($id))) {
                return $id;
            }
        }
        return $first;
    }

    /* ---------------------------------------------------------------------------------
     * Rendering one section
     *
     * A section is a PAGE now, not a card in a stack, so body() has to be able to emit one
     * card and nothing else. Rather than making every view file dispatch by section — twelve
     * places to forget, and three of them already dispatch by a different mechanism — the
     * gate sits at the one pair of methods every card in the product is built from.
     * ------------------------------------------------------------------------------ */

    /** The card id being rendered alone, or null when the whole body is wanted. */
    private static ?string $gateOnly = null;

    /** The card cardOpen() most recently opened while the gate is on. */
    private static string $gateCard = '';

    /** Did the wanted card actually get rendered? Layout falls back when it did not. */
    private static bool $gateHit = false;

    /**
     * Render only the named card the next time body() runs.
     *
     * OUTPUT OUTSIDE A CARD IS KEPT, and that is deliberate rather than an oversight. Two things
     * live there and both have to survive: the layout wrappers a view opens around a pair of
     * cards (`<div class="grid-2">`, the session explorer's `<div class="explorer">`), which are
     * balanced and therefore harmless when the cards between them are dropped; and page-level
     * output that belongs to the view rather than to any one card — the Settings page's flash
     * message after a save is the case that matters, and swallowing it would mean an operator
     * who just changed a setting was told nothing at all.
     *
     * @param string|null $id Card id to keep, or null to render everything.
     */
    public static function renderOnlySection(?string $id): void
    {
        self::$gateOnly = $id === '' ? null : $id;
        self::$gateCard = '';
        self::$gateHit = false;
    }

    /** Did the last gated render actually emit the card it was asked for? */
    public static function sectionWasRendered(): bool
    {
        return self::$gateHit;
    }

    /** URL slug for this view, e.g. 'overview'. Used for routing and nav highlighting. */
    abstract public function slug(): string;

    /** Human title shown in the header and the <title> tag. */
    abstract public function title(): string;

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
     * The same statement in the other direction: filters a SESSIONS-core card cannot honour.
     *
     * The mirror of ignoredHitFilters(), and it was missing, so the reporting was one-sided.
     * A status is a property of a REQUEST and lives only on the hits core, but the filter bar
     * is drawn from the union of both planes (facetLayer()) precisely so that a status filter
     * chosen on a hits-plane view stays visible and removable. On a view that mixes planes —
     * Attacks is one, five hits-plane cards and one sessions-plane card — that left a card
     * whose numbers did not move under a chip that said they had, with an EMPTY
     * `filters_ignored` beside them saying nothing had been dropped.
     *
     * Read from the hits layer rather than the union for the same reason its mirror reads from
     * the sessions one: each layer already holds exactly the fields of its own plane, so the
     * difference is the set this plane cannot answer and nothing else.
     *
     * @return array<int,string>
     */
    /**
     * The installation root, as the setup steps expect to be handed it.
     *
     * Steps::nextSteps() builds the `bin/loghound-tail --status` line from it and
     * Steps::ingestStatus() finds the tailer's status document under it, so the panel and
     * the installer describe the same checkout. Resolved rather than concatenated, so the
     * command the operator copies has no `/../..` in the middle of it.
     *
     * ON THE BASE CLASS, because it was private to Settings and every view that prints a
     * command needs it. Virtual hosts and Performance both render the rescan advice, and
     * without a root to hand it they printed `bin/loghound-setup` — followable from exactly
     * one directory, by a reader who is in a browser.
     */
    protected static function root(): string
    {
        $root = dirname(__DIR__, 2);
        $real = realpath($root);
        return $real === false ? $root : $real;
    }

    protected function ignoredSessionFilters(): array
    {
        $usable = array_keys(Query::sessionFilterFields());
        $labels = Query::filterFields();

        $out = [];
        foreach (array_keys($this->hitFacets->flat()) as $field) {
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
     * solr/sessions/conf/schema.xml states the contract — every dashboard query must
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
     * two. Panel\Jobs deliberately counts the whole core, because "how many documents are in this
     * index" is the question that diagnostic asks.
     *
     * @return array<int,string>
     */
    protected function sessionFqs(): array
    {
        return array_merge(
            [self::FQ_SESSION_DOCS, Query::publicIpsOnly(), Query::rangeFq('ts_start', $this->range)],
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
            [Query::rangeFq('ts', $this->range), Query::publicIpsOnly()],
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

        self::cardOpen($id, $num, $outer . ' by ' . $inner, $pivot[2], $this->exportTool('pivot'));
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
        self::gateOpen($id);

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

        self::gateClose();
    }

    /** Close a card whose content was rendered server-side and needs no loading state. */
    protected static function cardEnd(): void
    {
        echo '</section>';

        self::gateClose();
    }

    /**
     * Start capturing a card, when only one of them is wanted.
     *
     * A buffer per card rather than a running suppression flag, because the decision to keep or
     * drop is made at the same call site either way and a buffer cannot leave half a card in the
     * output if a view returns early. A card opened and never closed unwinds with the page: PHP
     * flushes the remaining buffers at the end of the request, which is the same outcome as not
     * gating at all and is strictly better than a blank page.
     */
    private static function gateOpen(string $id): void
    {
        if (self::$gateOnly === null) {
            return;
        }
        self::$gateCard = $id;
        ob_start();
    }

    /** Finish a card: emit it when it is the one this page is, discard it when it is not. */
    private static function gateClose(): void
    {
        if (self::$gateOnly === null || self::$gateCard === '') {
            return;
        }

        $html = (string) ob_get_clean();
        if (self::$gateCard === self::$gateOnly) {
            self::$gateHit = true;
            echo $html;
        }
        self::$gateCard = '';
    }

    /* ---------------------------------------------------------------------------------
     * CSV export
     * ------------------------------------------------------------------------------ */

    /**
     * The defaults every export dataset is merged over.
     *
     * A dataset that forgets a key gets the conservative answer rather than an undefined
     * index: no columns, a hundred rows, nothing carried, and `rows` as the payload key.
     *
     * @var array<string,mixed>
     */
    private const EXPORT_DEFAULTS = [
        'label'    => '',
        'action'   => '',
        'key'      => 'rows',
        'shape'    => 'list',
        'columns'  => [],
        'cap'      => 100,
        'params'   => [],
        'unit'     => 'rows',
        'ranked'   => '',
        'total'    => '',
        'scope'    => [],
        'note'     => '',
        'carry'    => [],
        'key_head' => 'Value',
        'val_head' => 'Requests',
        'page'     => 500,
        'control'  => 'CSV',
    ];

    /**
     * The tables on this view that can be taken out as CSV, keyed by export slug.
     *
     * THE DEFAULT IS NOTHING, on the same reasoning as toolbar(): a view that has not thought
     * about which of its tables are worth exporting offers no control, because an absent
     * affordance is something an operator can ask for while a wrong file is something they
     * cannot detect once it has left the product.
     *
     * A dataset is declared rather than implemented, and it names an EXISTING `api()` action
     * instead of building a query of its own. That is the whole safety argument for this
     * feature: the export runs the query the card runs, through the same allowlists, the same
     * `fq` construction and the same clamps, so there is no second place where a filter could
     * be dropped, an operator inverted, or a field name spliced into Solr syntax. The only
     * parameters the export changes are the row limits, and the file states the limit it used.
     *
     * @return array<string,array<string,mixed>>
     */
    public function exports(): array
    {
        return [];
    }

    /**
     * The facet layer whose selection describes this view's exports.
     *
     * The sessions/hits layer for Loghound's own views; Panel\OpensolrView overrides it with
     * the request-log layer, because the two planes have disjoint field names and a preamble
     * that reported the wrong one would name filters the file was never scoped by.
     */
    protected function exportFacets(): Facets
    {
        return $this->facets;
    }

    /**
     * Stream one dataset as a CSV response.
     *
     * Called by the front controller AFTER authentication, on a GET, and it reads only. The
     * row limits are clamped twice — by the dataset's own cap and by Csv::MAX_ROWS — because
     * this is the one endpoint in the panel whose cost is proportional to a number in the
     * URL, and the file says which limit was in force.
     *
     * A HEAD gets the headers and none of the work, which is not an optimisation: without that
     * early return, asking for the headers alone would run every Solr query behind the file and
     * throw the answer away, making HEAD the cheapest way to make this endpoint expensive.
     */
    public function export(string $key): void
    {
        $declared = $this->exports();
        if (!isset($declared[$key]) || !is_array($declared[$key])) {
            if (!headers_sent()) {
                http_response_code(404);
                header('Content-Type: text/plain; charset=utf-8');
                header('Cache-Control: no-store, private');
            }
            echo "This view has no such export.\n";
            return;
        }

        $set = $declared[$key] + self::EXPORT_DEFAULTS;
        $cap = Security::clampInt($set['cap'], 1, Csv::MAX_ROWS, 100);
        $tz  = $this->exportTimezone();

        foreach ((array) $set['params'] as $name => $value) {
            if (is_string($name) && (is_string($value) || is_int($value))) {
                $_GET[$name] = (string) $value;
            }
        }

        Csv::headers(Csv::filename($this->slug(), (string) $set['label'], (string) $this->range['key'], $tz));

        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'HEAD') {
            return;
        }

        Csv::unbuffer();

        Csv::put(Csv::bom());

        if ((string) $set['shape'] === 'paged') {
            $this->exportPaged($set, $cap, $tz);
            return;
        }

        $this->exportWhole($set, $cap, $tz);
    }

    /**
     * The display timezone, which is what every instant in the file is rendered in.
     *
     * Validated against PHP's own database and defaulted to UTC, because an unknown name
     * would make DateTimeZone throw in the middle of a response whose headers have already
     * been sent — which reaches the operator as a truncated file rather than as an error.
     */
    protected function exportTimezone(): string
    {
        $tz = (string) $this->cfg->get('ui.timezone', 'UTC');
        try {
            new \DateTimeZone($tz);
        } catch (\Throwable $e) {
            return 'UTC';
        }
        return $tz;
    }

    /**
     * Write a dataset that arrives in one payload: a facet list, a classic facet map, a pivot.
     *
     * A TERMS FACET THAT RETURNED FEWER BUCKETS THAN ITS LIMIT RETURNED ALL OF THEM, and that
     * inference is what lets the file claim completeness without a second Solr call for
     * `numBuckets`: short of the limit means the dimension had nothing more to give, while at the
     * limit the honest answer is "there may be more", which is what the coverage line then says.
     *
     * @param array<string,mixed> $set
     */
    private function exportWhole(array $set, int $cap, string $tz): void
    {
        $payload = [];
        $columns = (array) $set['columns'];
        $rows = [];

        switch ((string) $set['shape']) {
            case 'custom':
                $source = $set['source'] ?? null;
                $out = is_callable($source) ? (array) $source() : [];
                $payload = (array) ($out['payload'] ?? []);
                $rows = array_values((array) ($out['rows'] ?? []));
                if (isset($out['columns']) && is_array($out['columns']) && $out['columns'] !== []) {
                    $columns = $out['columns'];
                }
                $set['total'] = '';
                $set['scope'] = (array) ($out['scope'] ?? $set['scope']);
                $knownTotal = isset($out['total']) && is_int($out['total']) ? $out['total'] : null;
                break;

            case 'map':
                $payload = $this->api((string) $set['action']);
                foreach ((array) self::exportPick($payload, (string) $set['key']) as $value => $count) {
                    $rows[] = ['value' => (string) $value, 'count' => $count];
                }
                $columns = [
                    [(string) $set['key_head'], 'value', 'id'],
                    [(string) $set['val_head'], 'count', 'number'],
                ];
                $knownTotal = self::exportTotal($payload, (string) $set['total']);
                break;

            case 'pivot':
                $payload = $this->api((string) $set['action']);
                [$rows, $columns] = self::exportPivot((array) self::exportPick($payload, (string) $set['key']));
                $knownTotal = null;
                break;

            default:
                $payload = $this->api((string) $set['action']);
                $rows = array_values((array) self::exportPick($payload, (string) $set['key']));
                $knownTotal = self::exportTotal($payload, (string) $set['total']);
        }

        $capped = count($rows) > $cap;
        $rows = array_slice($rows, 0, $cap);

        $complete = !$capped && count($rows) < $cap;

        Csv::put($this->exportPreamble($set, $payload, count($rows), $knownTotal, $complete, $cap, $tz));
        Csv::put(Csv::row(self::exportHeaders($columns)));

        foreach ($rows as $row) {
            Csv::put(Csv::row(self::exportCells($columns, (array) $row, $tz)));
        }
    }

    /**
     * Write a dataset that has to be fetched a page at a time.
     *
     * ECHOED AS IT IS READ, so the memory footprint is one page whatever the total — the
     * session explorer can match hundreds of thousands of documents and assembling them in
     * PHP to write them out afterwards would be a way to exhaust a worker from a URL. The
     * total comes from the first page's `numFound`, which is exact, so the coverage line can
     * say "the 2,000 most recent of 284,193" rather than a guess.
     *
     * @param array<string,mixed> $set
     */
    private function exportPaged(array $set, int $cap, string $tz): void
    {
        $pager = $set['pager'] ?? null;
        if (!is_callable($pager)) {
            Csv::put(Csv::row(['This export is not available on this view.']));
            return;
        }

        $page = Security::clampInt($set['page'], 1, Security::MAX_ROWS, 500);
        $columns = (array) $set['columns'];

        $first = (array) $pager(0, $page);
        $total = isset($first['total']) ? max(0, (int) $first['total']) : null;
        $wanted = $total === null ? $cap : min($cap, $total);

        Csv::put($this->exportPreamble(
            $set,
            (array) ($first['payload'] ?? []),
            $wanted,
            $total,
            $total !== null && $total <= $cap,
            $cap,
            $tz
        ));
        Csv::put(Csv::row(self::exportHeaders($columns)));

        $rows = array_values((array) ($first['rows'] ?? []));
        $written = 0;
        $start = 0;

        while ($rows !== [] && $written < $wanted) {
            foreach ($rows as $row) {
                if ($written >= $wanted) {
                    break;
                }
                Csv::put(Csv::row(self::exportCells($columns, (array) $row, $tz)));
                $written++;
            }
            if ($written >= $wanted) {
                break;
            }
            $start += $page;
            $next = (array) $pager($start, $page);
            $rows = array_values((array) ($next['rows'] ?? []));
        }
    }

    /**
     * The provenance block: what this file is, what scoped it, and what it covers.
     *
     * Written as ordinary two-column records ahead of a blank line, so a reader that wants the
     * table alone skips to the first empty record and a person who opens the file sees the
     * scope before the numbers. The coverage line is the one that matters — see the header of
     * \Loghound\Csv for why a capped export that does not say so is worse than no export.
     *
     * @param array<string,mixed> $set
     * @param array<string,mixed> $payload
     */
    private function exportPreamble(
        array $set,
        array $payload,
        int $rows,
        ?int $total,
        bool $complete,
        int $cap,
        string $tz
    ): string {
        $lines = [
            ['Loghound export', (string) $set['label']],
            ['Panel view', $this->title()],
            ['Taken', Csv::moment(gmdate('c'), $tz)],
            ['Timezone', $tz],
        ];

        if ($this->honours(self::SCOPE_RANGE)) {
            $lines[] = ['Time range', (string) $this->range['label']];
        }

        $facets = $this->exportFacets();
        $dimensions = $facets->fields();

        if (isset($dimensions[Query::HOST_FIELD])) {
            $hosts = $facets->values(Query::HOST_FIELD);
            $lines[] = ['Website', $hosts === [] ? 'All hosts' : implode('; ', $hosts)];
        }

        $filters = 0;
        foreach ($facets->selected() as $field) {
            if ($field === Query::HOST_FIELD) {
                continue;
            }
            $values = [];
            foreach ($facets->values($field) as $value) {
                $values[] = Vocabulary::has($field)
                    ? Vocabulary::label($field, $value) . ' [' . $value . ']'
                    : $value;
            }
            $lines[] = ['Filter', ($dimensions[$field] ?? $field)
                . ' — ' . Facets::operatorLabel($facets->op($field))
                . ' — ' . implode('; ', $values)];
            $filters++;
        }
        if ($filters === 0) {
            $lines[] = ['Filter', 'None'];
        }

        foreach ((array) $set['scope'] as $path => $spec) {
            $label = is_array($spec) ? (string) ($spec[0] ?? '') : (string) $spec;
            $value = self::exportPick($payload, (string) $path);
            if (is_array($spec) && isset($spec[1]) && is_callable($spec[1])) {
                $value = $spec[1]($value);
            }
            if (is_array($value)) {
                $value = implode('; ', array_map(static fn ($v): string => is_scalar($v) ? (string) $v : '', $value));
            }
            if ($label !== '' && $value !== null && $value !== '' && $value !== false) {
                $lines[] = [$label, is_bool($value) ? 'yes' : (string) $value];
            }
        }

        if ((string) $set['note'] !== '') {
            $lines[] = ['Note', (string) $set['note']];
        }

        $lines[] = ['Coverage', self::exportCoverage($set, $rows, $total, $complete, $cap)];

        $out = '';
        foreach ($lines as $line) {
            $out .= Csv::row([Csv::text($line[0]), Csv::text($line[1])]);
        }

        return $out . Csv::EOL;
    }

    /**
     * The one sentence that says whether this file is the whole set.
     *
     * Four cases, and none of them is silence. A true total of the same unit is used when the
     * payload carries one; otherwise the fact that a terms facet came back short of its limit is
     * the evidence of completeness; otherwise the file admits it is a top-N list and names the N.
     *
     * AT THE LIMIT IS THE ONLY CASE THAT HAS TO SHOUT. A terms facet that came back short of its
     * limit returned everything the dimension had, and a paged read that stopped before its clamp
     * read everything that matched; either way nothing was left out by the export, and claiming
     * otherwise would mislead in the opposite direction from the silence this replaces.
     *
     * @param array<string,mixed> $set
     */
    private static function exportCoverage(array $set, int $rows, ?int $total, bool $complete, int $cap): string
    {
        $unit = (string) $set['unit'];
        $ranked = (string) $set['ranked'];
        $tail = $ranked === '' ? '' : ', ' . $ranked;

        if ($rows === 0) {
            return 'This file has no data rows: nothing in scope produced any ' . $unit
                . '. The lines above say what the scope was.';
        }

        if ($total !== null && $rows >= $total) {
            return 'Complete. All ' . number_format($total) . ' ' . $unit . ' in scope are in this file.';
        }

        if ($rows >= $cap) {
            $of = $total === null ? '' : ' of ' . number_format($total);
            return number_format($rows) . $of . ' ' . $unit . $tail . '. That is this export\'s limit of '
                . number_format($cap) . ' rows, so this is NOT the whole set.';
        }

        if ($total !== null) {
            return 'Complete for this scope. All ' . number_format($rows) . ' ' . $unit
                . ' this card lists are in this file. The selected range holds '
                . number_format($total) . ' ' . $unit . ' in all; the difference is what this card\'s '
                . 'own controls exclude.';
        }

        if ($complete) {
            return 'Complete. Every one of the ' . number_format($rows) . ' ' . $unit
                . ' in scope is in this file.';
        }

        return 'Complete for this scope: all ' . number_format($rows) . ' ' . $unit . ' this card lists '
            . 'are in this file, short of the export\'s limit of ' . number_format($cap) . ' rows.';
    }

    /**
     * A total from the payload, but only when it is a count of the SAME unit as the rows.
     *
     * Most of these payloads carry a `total` that counts SESSIONS while the rows are countries
     * or netblocks, and printing that as the denominator would produce a coverage line that is
     * arithmetically nonsense. A dataset therefore has to name the path explicitly, and an
     * absent or non-integer value yields null rather than a number nobody computed.
     *
     * @param array<string,mixed> $payload
     */
    private static function exportTotal(array $payload, string $path): ?int
    {
        if ($path === '') {
            return null;
        }
        $value = self::exportPick($payload, $path);

        return is_int($value) || (is_string($value) && ctype_digit($value)) ? (int) $value : null;
    }

    /**
     * Flatten a cross-tabulation into one record per cell.
     *
     * A pivot on screen is a row per outer value with its inner breakdown beside it; in a
     * spreadsheet the useful shape is one row per pair, which pivots and groups without any
     * unpacking. `covered` rides along per row because the inner facet is LIMITED, so the
     * cells of one outer value do NOT sum to its total — presenting them as if they did is the
     * wrong number the on-screen renderer already refuses to print.
     *
     * @param array<string,mixed> $node
     * @return array{0:array<int,array<string,mixed>>,1:array<int,array<int,string>>}
     */
    private static function exportPivot(array $node): array
    {
        $outer = (string) ($node['outer_label'] ?? 'Value');
        $inner = (string) ($node['inner_label'] ?? 'Breakdown');

        $rows = [];
        foreach ((array) ($node['rows'] ?? []) as $row) {
            $row = (array) $row;
            foreach ((array) ($row['cells'] ?? []) as $cell) {
                $cell = (array) $cell;
                $rows[] = [
                    'outer'       => $row['value'] ?? '',
                    'outer_label' => $row['label'] ?? '',
                    'outer_total' => $row['count'] ?? null,
                    'covered'     => $row['covered'] ?? null,
                    'inner'       => $cell['value'] ?? '',
                    'inner_label' => $cell['label'] ?? '',
                    'count'       => $cell['count'] ?? null,
                ];
            }
        }

        return [$rows, [
            [$outer, 'outer_label', 'text'],
            [$outer . ' (stored value)', 'outer', 'id'],
            [$outer . ' sessions', 'outer_total', 'number'],
            [$inner, 'inner_label', 'text'],
            [$inner . ' (stored value)', 'inner', 'id'],
            ['Sessions', 'count', 'number'],
            ['Sessions covered by the listed values', 'covered', 'number'],
        ]];
    }

    /**
     * The header record: the HUMAN label of each column and never a stored field name.
     *
     * The words are the ones the table on screen uses, which is a hard rule in this product
     * (Panel\Vocabulary): a column headed `bot_verdict_s` is a column nobody who has not read
     * src/Score/Rules.php can act on, and a file is read by more people than a dashboard is.
     *
     * @param array<int,array<int,string>> $columns
     * @return array<int,string>
     */
    private static function exportHeaders(array $columns): array
    {
        $out = [];
        foreach ($columns as $column) {
            $out[] = Csv::text((string) ($column[0] ?? ''));
        }
        return $out;
    }

    /**
     * One record's cells, each formatted for its declared kind.
     *
     * The kind is what decides whether formula neutralisation applies: text and identifiers
     * are attacker-chosen and get it, numbers go through Csv::number() which cannot emit a
     * formula, dates through Csv::moment() which cannot either.
     *
     * @param array<int,array<int,string>> $columns
     * @param array<string,mixed>          $row
     * @return array<int,string>
     */
    private static function exportCells(array $columns, array $row, string $tz): array
    {
        $out = [];
        foreach ($columns as $column) {
            $value = self::exportPick($row, (string) ($column[1] ?? ''));
            $kind = (string) ($column[2] ?? 'text');
            $field = (string) ($column[3] ?? '');

            $out[] = match ($kind) {
                'number' => Csv::number($value),
                'date'   => Csv::moment($value, $tz),
                'bool'   => Csv::flag($value),
                'vocab'  => Csv::text(
                    is_string($value) && $value !== '' && $field !== ''
                        ? Vocabulary::label($field, $value)
                        : $value
                ),
                'pairs'  => Csv::text(self::exportPairs($value, $field)),
                default  => Csv::text($value),
            };
        }
        return $out;
    }

    /**
     * A nested "top five, with counts" list, flattened into one cell.
     *
     * The country table's cities column is the case: five `{city, count}` records that are on
     * screen beside the row and would otherwise be silently dropped from the file. Rendered as
     * `Chicago (26); Newark (18)` so the counts survive — a bare list of names would lose the
     * only thing that makes the order meaningful. It is a top-N inside a top-N and the dataset's
     * note says so.
     *
     * @param mixed $value
     */
    private static function exportPairs($value, string $labelKey): string
    {
        if (!is_array($value) || $value === []) {
            return '';
        }

        $out = [];
        foreach ($value as $entry) {
            if (!is_array($entry)) {
                continue;
            }
            $name = $entry[$labelKey] ?? null;
            if (!is_scalar($name) || (string) $name === '') {
                continue;
            }
            $count = $entry['count'] ?? null;
            $out[] = is_numeric($count) ? (string) $name . ' (' . $count . ')' : (string) $name;
        }

        return implode('; ', $out);
    }

    /**
     * Read a value out of a payload by dotted path, tolerating every absence.
     *
     * `status.4xx` and `pivot.rows` are both real paths in these payloads, and a missing
     * segment has to be null rather than a PHP warning emitted into the middle of a CSV.
     *
     * @param array<string,mixed> $data
     * @return mixed
     */
    private static function exportPick(array $data, string $path)
    {
        if ($path === '') {
            return null;
        }

        $node = $data;
        foreach (explode('.', $path) as $segment) {
            if (!is_array($node) || !array_key_exists($segment, $node)) {
                return null;
            }
            $node = $node[$segment];
        }

        return $node;
    }

    /**
     * The discreet control that starts an export, for a card's `$tools` slot.
     *
     * A text link in the card head rather than a button: it belongs beside the sort chips and
     * the population toggles, in their type and their tone, and it must not compete with the
     * data for attention. The accessible name is a whole sentence naming what the file will
     * contain and what scopes it, because a control that says only "CSV" leaves the reader to
     * guess whether it covers the filtered view or everything. The visible text is "CSV" unless
     * the dataset overrides it, which is what a card holding TWO tables needs: two links both
     * reading "CSV" in one card head name neither of them.
     *
     * The href is built server-side by Layout::urlWith(), so the range, the host, every filter
     * and its operator are already in it and the control works with JavaScript switched off.
     * assets/js/export.js then keeps it in step with the controls that live only in the page.
     */
    protected function exportTool(string $key): string
    {
        $declared = $this->exports();
        if (!isset($declared[$key]) || !is_array($declared[$key])) {
            return '';
        }

        $set = $declared[$key] + self::EXPORT_DEFAULTS;
        $cap = Security::clampInt($set['cap'], 1, Csv::MAX_ROWS, 100);
        $href = Layout::urlWith(self::exportQuery($this->slug(), $key, (array) $set['carry']));

        $hint = 'Download ' . $set['label'] . ' as CSV: up to ' . number_format($cap) . ' '
            . $set['unit'] . ', carrying the time range, virtual host, filters and ordering in force.';

        $carry = [];
        foreach ((array) $set['carry'] as $name) {
            if (is_string($name) && preg_match('/^[a-z_]{1,20}$/D', $name) === 1) {
                $carry[] = $name;
            }
        }

        return '<a class="export" href="' . Security::esc($href) . '"'
            . ' data-export="' . Security::esc($key) . '"'
            . ' data-export-carry="' . Security::esc(implode(',', $carry)) . '"'
            . ' title="' . Security::esc($hint) . '"'
            . ' aria-label="' . Security::esc($hint) . '">'
            . Security::esc((string) $set['control']) . '</a>';
    }

    /**
     * The query parameters an export link adds on top of the page's own state.
     *
     * `carry` names the page parameters the dataset's action reads — a population, a sort
     * order, a search box, an index — so a bookmarked or JavaScript-free export is scoped the
     * way the page was. Each one is re-validated by the action itself against its own
     * allowlist, exactly as it is on the JSON path; this only decides whether it travels.
     *
     * @param array<int,string> $carry
     * @return array<string,string>
     */
    private static function exportQuery(string $view, string $key, array $carry): array
    {
        $params = ['v' => $view, 'export' => $key];

        foreach ($carry as $name) {
            if (!is_string($name) || preg_match('/^[a-z_]{1,20}$/D', $name) !== 1) {
                continue;
            }
            $value = $_GET[$name] ?? null;
            if (is_string($value) && $value !== '') {
                $params[$name] = mb_substr($value, 0, 200);
            }
        }

        return $params;
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
