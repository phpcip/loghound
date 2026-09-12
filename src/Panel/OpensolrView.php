<?php
/**
 * Loghound — shared base for the Opensolr index-analytics views.
 *
 * WHY THIS SECTION EXISTS AT ALL. Loghound already knows, for every IP it has ever seen in
 * a web log, whether it is a bot, what network it sits on and which fingerprint cluster it
 * belongs to. Opensolr already knows, for every request that reached a customer's search
 * index, what was asked, how long it took and how many results came back. Each half is
 * useful; the two together answer a question neither can answer alone — how much of my search
 * capacity is being spent on traffic I have already classified — which is the reason this
 * belongs inside Loghound rather than in a separate tool.
 *
 * THE ARCHITECTURAL RULE, WHICH IS NOT OPEN FOR REDESIGN. Loghound never touches a Solr
 * server for any of this. No agent, no log file, no SSH, no log4j2 parsing. Everything on
 * the Solr side is read from the Opensolr platform API, which already holds the data in
 * its analytics shards and already enforces ownership on it. That means there is no format
 * to detect, no volume problem, no second copy of a customer's query log, and no way for
 * Loghound to be blamed for something happening on a customer's node.
 *
 * THREE STATES, AND ALL THREE HAVE TO READ WELL:
 *
 *  1. Credentials configured and Loghound running on the web server — everything works,
 *     including the correlation.
 *  2. Credentials configured, Loghound running somewhere else — the Solr analytics are
 *     shown in full, and the correlation card explains, concretely, what installing
 *     Loghound where the web server runs would add. Not a vague upsell: the specific
 *     question it would answer.
 *  3. No Opensolr credentials — no broken cards, no failed requests. The view explains
 *     what this section is for and where the credentials go. Loghound is completely useful
 *     without Opensolr and must never imply otherwise.
 *
 * WHAT THE READER CAN SLICE BY, AND WHY IT IS NOT MORE. Every card on every page of this
 * view answers under a filter set read from the query string — see logFilterFields() for
 * the four dimensions the platform's request log can honestly be faceted on, and for the
 * ones it cannot. The sidebar filters the rest of the panel uses (`f[…]`, verdict, country,
 * fingerprint) name fields that exist only on Loghound's own cores, so they are reported as
 * ignored rather than silently applied to a schema that has never heard of them.
 *
 * THE API KEY never reaches this layer's output. It is held by \Loghound\OpensolrLog,
 * used server-side only, and every message that can escape has been through that class's
 * redact(). Nothing here puts it in HTML, in a URL the browser sees, or in a JSON payload.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Opensolr;
use Loghound\OpensolrLog;
use Loghound\Security;

abstract class OpensolrView extends Controller implements Sections
{
    /** Terms asked for when faceting client addresses. Bounded; the tail is a long one. */
    protected const IP_FACET_LIMIT = 60;

    /** Terms per field in the filter rail. Short on purpose: it is a rail, not a report. */
    protected const FILTER_FACET_LIMIT = 15;

    /** Pages this view renders, in order. Overridden by every concrete view. */
    public const SECTIONS = [];

    /**
     * The fields of the platform's request log this section may filter on, with labels.
     *
     * THIS LIST IS WHAT THE DATA SUPPORTS, AND NOTHING MORE. The request log's fields are
     * `core_name, date, timestamp_unix, ip, path, q, hits, qtime, http_status, size,
     * param_hostname, full_request` (\Loghound\OpensolrLog::FIELDS), and only four of them
     * are worth faceting:
     *
     *  - `path` — the handler. This is the one the operator asked for: a caller hitting
     *    something like `/receive_Access` is neither a visitor nor a crawler, and the handler
     *    is the field that separates a search box from an integration.
     *  - `http_status` — refusals and failures, which is where a broken client shows up.
     *  - `param_hostname` — which cluster node answered.
     *  - `ip` — the caller. High cardinality, so the rail shows the busiest and says so.
     *
     * WHAT CANNOT BE FACETED, AND IS THEREFORE NOT OFFERED. `q` and `full_request` are
     * effectively unique per request, so a terms facet on them lists one-hit wonders. `hits` and
     * `qtime` are
     * numeric and are offered as the outcome slice below rather than as terms. And there is
     * no bot/human dimension on this plane at all: the platform records who called, never
     * what they are. That verdict exists only in Loghound's own sessions index, so it is not a
     * filter here.
     *
     * @return array<string,string>
     */
    public static function logFilterFields(): array
    {
        return [
            'path'           => 'Handler',
            'http_status'    => 'Status',
            'param_hostname' => 'Node',
            'ip'             => 'Caller',
        ];
    }

    /**
     * The outcome slices, as an allowlist of keys to labels.
     *
     * Separate from the terms filters because `hits` and `qtime` are numbers: a terms facet
     * on them would list every distinct result count the index ever returned. These are
     * range filters with names, built by outcomeFq() from constants.
     *
     * @var array<string,string>
     */
    public const OUTCOMES = [
        'zero'  => 'Matched nothing',
        'found' => 'Matched something',
        'slow'  => 'Slow answers',
    ];

    /** QTime at or above which a request counts as slow, in milliseconds. */
    private const SLOW_MS = 100;

    /** @var OpensolrLog|null Lazily built, or injected by a test. */
    private ?OpensolrLog $client = null;

    /** @var Opensolr|null Lazily built, or injected by a test. */
    private ?Opensolr $account = null;

    /** @var array<string,mixed>|null Per-request memo of the index list. */
    private ?array $indexMemo = null;

    /** @var Facets|null The request-log filter layer, built on first use. */
    private ?Facets $logFacetLayer = null;

    /**
     * Replace the request-log client, so tests run with no network.
     *
     * One of two setters on this class. A view is otherwise constructed exactly the way
     * every other panel view is, from config plus the Solr gateway.
     */
    public function setLogClient(OpensolrLog $client): void
    {
        $this->client = $client;
    }

    /**
     * Replace the control-plane client, so tests run with no network.
     *
     * Separate from the request-log client because they are separate planes: this one
     * lists and manages indexes, that one reads their traffic. A test that exercises the
     * ownership check needs to control what the account appears to own without also
     * pretending to be the analytics shards.
     */
    public function setAccountClient(Opensolr $client): void
    {
        $this->account = $client;
    }

    /** The platform client, built from the `opensolr` section of the config. */
    protected function log(): OpensolrLog
    {
        if ($this->client === null) {
            $this->client = new OpensolrLog((array) $this->cfg->get('opensolr', []));
        }
        return $this->client;
    }

    /** Are there Opensolr credentials to work with? Decides which of the three states applies. */
    protected function configured(): bool
    {
        return $this->log()->isConfigured();
    }

    /**
     * The index the view is looking at.
     *
     * Validated for shape only. Ownership is not Loghound's to decide and is not decided
     * here: the platform answers ERROR_NOT_CORE_OWNER for an index this account does not
     * hold, and that is handled as an ordinary outcome with a sentence, not as a failure.
     * Re-deriving ownership locally would mean a second API call per request to answer a
     * question the first call already answers.
     */
    protected function core(): string
    {
        $core = $_GET['core'] ?? '';
        if (!is_string($core) || $core === '' || !Security::isSafeCoreName($core)) {
            /* NAME THE FIRST INDEX RATHER THAN NAMING NOTHING. A request with no `?core=` is the
               normal first visit, and answering it with an empty string made the browser
               responsible for inventing a default — which it did only on the first of five
               concurrent cards, leaving the rest waiting on a selection that never arrived.
               The list is already in hand and memoised, so this costs nothing, and an account
               with no indexes still yields '' because there is genuinely nothing to select. */
            $list = $this->indexes();
            $names = is_array($list['indexes'] ?? null) ? $list['indexes'] : [];

            return $names === [] ? '' : (string) $names[0];
        }
        return $core;
    }

    /**
     * The account's indexes, discovered rather than typed.
     *
     * The control-plane client defaults to a sixty-second timeout, which is the whole of
     * PHP-FPM's execution budget on the reference install; the panel cannot afford that, so
     * a shorter one is imposed here. A failure is a state with a sentence, never a throw
     * that takes the page render with it.
     *
     * @return array{state:string,message:string,indexes:array<int,string>}
     */
    protected function indexes(): array
    {
        if ($this->indexMemo !== null) {
            return $this->indexMemo;
        }
        if (!$this->configured()) {
            return $this->indexMemo = [
                'state'   => 'not_configured',
                'message' => 'No Opensolr account is configured.',
                'indexes' => [],
            ];
        }

        try {
            if ($this->account === null) {
                $account = (array) $this->cfg->get('opensolr', []);
                $account['timeout'] = Security::clampInt($account['timeout'] ?? null, 5, 20, 15);
                $this->account = new Opensolr($account);
            }
            $names = $this->account->listIndexes();
            return $this->indexMemo = ['state' => 'ok', 'message' => '', 'indexes' => $names];
        } catch (\Throwable $e) {
            return $this->indexMemo = [
                'state'   => 'unreachable',
                'message' => 'The list of indexes could not be read from Opensolr. '
                    . 'Check outbound HTTPS from this host and the credentials in config/loghound.php.',
                'indexes' => [],
            ];
        }
    }

    /**
     * Read the request log for the selected index, or explain why it was not read.
     *
     * Every action on every one of these views goes through here rather than calling the
     * client directly, so the two conditions that are not "the platform said something"
     * are handled once:
     *
     *  - **Demo mode.** The panel can be run with fabricated web traffic for screenshots
     *    and offline demos. There is no fabricated Opensolr data and there should not be:
     *    the alternative is either inventing somebody's query log, or quietly making a real
     *    billed API call from a session that is showing a "these numbers are fake" banner.
     *    Both are worse than saying so.
     *  - **No index chosen yet.** The picker is filled from the platform, so the very first
     *    render of a card can legitimately have nothing selected.
     *
     * The stub returned in both cases has exactly the shape of a real result, so a caller
     * can read facets off it without a second code path.
     *
     * @param array<string,mixed> $opt Options for OpensolrLog::log().
     * @return array<string,mixed>
     */
    protected function fetch(array $opt): array
    {
        if ($this->gw->isDemo()) {
            return self::stub(
                'demo',
                'Demo mode fabricates web traffic only. Opensolr index analytics are read live from '
                . 'your account, so there is nothing to show while the panel is running on sample data.'
            );
        }

        $core = $this->core();
        if ($core === '') {
            return self::stub('no_index', '');
        }

        return $this->log()->log($core, $opt);
    }

    /**
     * A result-shaped placeholder for a call that was never made.
     *
     * @return array<string,mixed>
     */
    private static function stub(string $state, string $message): array
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

    /* ---------------------------------------------------------------------------------
     * Filters
     * ------------------------------------------------------------------------------ */

    /**
     * The active request-log filters, read out of the query string.
     *
     * Shape: `?lf[path][]=select&lf[ip][]=203.0.113.9`. A SEPARATE namespace from the `f[…]`
     * sidebar filters, and deliberately so: those name fields on Loghound's own sessions and
     * hits cores (`bot_verdict_s`, `country_s`, …), none of which exists on the platform's
     * analytics shards. Sharing one namespace would mean every chip the reader set on the
     * session explorer arrived here as a field the request log has never heard of — and an
     * `fq` naming an absent field matches nothing, so every figure would read zero under a
     * chip that looked like it was working.
     *
     * A field not in logFilterFields() is dropped without comment: the UI never produces one.
     * So is a value isFilterableValue() refuses, and for a reason worth reading there. Values
     * are length-capped and count-capped here; they are turned into a literal by
     * OpensolrLog::termsFq(), which quotes and escapes them, and the whole filter is then
     * judged again by OpensolrLog::assertSafeFq().
     *
     * @return array<string,array<int,string>>
     */
    protected function logFilters(): array
    {
        return $this->logFacets()->flat();
    }

    /**
     * The facet layer for this plane, built once per request.
     *
     * SAME COMPONENT, SAME SEMANTICS, DIFFERENT NAMESPACE. The reading rules, the value checks, the
     * three boolean operators and the URL contract are Panel\Facets — this used to be a second
     * implementation of all of it, which is how the two planes came to disagree about what a filter
     * even was: this one had no operator at all, so there was no way to ask the request log for
     * "every handler except /select".
     *
     * The namespace stays separate for the reason logFilterFields() gives: these field names exist
     * on the platform's analytics shards and nowhere in Loghound's schemas.
     *
     * The exclusion strategy is the one difference, and it is forced rather than chosen. See
     * logFilterFqs().
     */
    protected function logFacets(): Facets
    {
        if ($this->logFacetLayer === null) {
            $this->logFacetLayer = Facets::log($_GET, self::logFilterFields());
        }
        return $this->logFacetLayer;
    }

    /**
     * The request-log filter state, for the top bar's applied-filters dialog.
     *
     * The same payload shape Panel\Facets hands the sessions plane, from the layer that owns the
     * `lf[…]` namespace. It is exposed because the bar is ONE control over both planes: a filter
     * set on the request log narrows every figure on this page, and a bar that could not show it
     * would leave the operator with a narrowed number that does not say it is narrowed.
     *
     * @return array<string,mixed>
     */
    public function logFilterPayload(): array
    {
        return $this->logFacets()->payload();
    }

    /**
     * The facet layer an export's preamble describes on this plane.
     *
     * THE REQUEST-LOG LAYER, not the sessions one, and the override is load-bearing rather than
     * tidy. The two planes have disjoint field names — `bot_verdict_s` and `country_s` exist on
     * Loghound's own cores and nowhere on the platform's analytics shards, `path` and
     * `http_status` the other way round — so a preamble built from the sessions layer would list
     * filters this file was never scoped by, and would omit every filter it actually was.
     */
    protected function exportFacets(): Facets
    {
        return $this->logFacets();
    }

    /**
     * The scope lines every export on an Opensolr view carries.
     *
     * Three things the filter list alone does not say: which index was read, which outcome slice
     * was in force, and which sidebar filters this plane could not honour. The last is the one
     * that matters most — a verdict or a country chip is real on Loghound's own views and inert
     * here, because the platform records who called and never what they are — and the views
     * already tell the reader through `ignored`, so the file has to as well.
     *
     * The outcome is spoken through OUTCOMES rather than printed as its stored key, because a
     * stored slug is never shown to a person in this product.
     *
     * @return array<string,mixed>
     */
    protected function logExportScope(): array
    {
        return [
            'core'    => 'Opensolr index',
            'outcome' => ['Outcome slice', static function ($value): string {
                return is_string($value) && isset(self::OUTCOMES[$value])
                    ? self::OUTCOMES[$value]
                    : 'All requests';
            }],
            'ignored' => ['Filters this plane could not honour', static function ($value): string {
                return is_array($value) && $value !== [] ? implode('; ', $value) : 'None';
            }],
            'requests' => 'Requests matched by this scope',
            'note'     => 'Why this file may be empty',
        ];
    }

    /**
     * Is this a value the filter machinery will carry at all?
     *
     * THE FAILURE THIS PREVENTS is not an injection — OpensolrLog::termsFq() quotes and escapes
     * every value, so `{!frange}` inside one is inert text. It is a 500. `assertSafeFq()` is
     * deliberately blunt: it refuses a filter containing `{!`, `_query_`, `_val_` or a control
     * character ANYWHERE in the string, quoted or not, and it does that by throwing. A crafted
     * query string would therefore take the whole JSON endpoint down with "the panel could not
     * complete that request" instead of quietly ignoring a filter the UI never produced.
     *
     * So the value is dropped HERE, at the boundary, on exactly the grounds assertSafeFq uses.
     * That keeps the blunt check in place — it is not routed around, and it is still the last
     * word — while making a hostile URL behave like a filter nobody set.
     *
     * A control character is dropped rather than stripped out, because stripping joins the two
     * halves of the value into a third thing that was never asked for.
     */
    private static function isFilterableValue(string $value): bool
    {
        if ($value === '' || strlen($value) > 512) {
            return false;
        }
        if (preg_match('/[\x00-\x1F\x7F]/', $value)) {
            return false;
        }
        if (str_contains($value, '{!')) {
            return false;
        }
        return stripos($value, '_query_') === false && stripos($value, '_val_') === false;
    }

    /**
     * The active outcome slice, or the empty string for "everything".
     *
     * @return string A key of self::OUTCOMES, or ''.
     */
    protected function outcome(): string
    {
        return self::param('outcome', array_keys(self::OUTCOMES), '');
    }

    /**
     * The date filter every request-log query on this page carries, plus the active filters.
     *
     * The date bound is Solr date math evaluated by the platform against its own clock, so
     * there is no timezone skew between this host and the analytics shards to get wrong.
     *
     * Values within one field are OR-ed by termsFq() — a facet is a multi-select — and
     * different fields become separate `fq` entries so they AND together.
     *
     * @return array<int,string>
     */
    protected function logFqs(): array
    {
        return self::logFqsFor(Query::filterStart($this->range), $this->logFacets()->selection(), $this->outcome());
    }

    /**
     * Build the filter list from explicit parts rather than from the request.
     *
     * Exists because a stepped scan does not have the request that started it: it is resumed
     * from a stored context on every poll, so it has to be able to rebuild exactly the same
     * filters from values it re-validates itself. A scan that quietly read the whole log while
     * the page showed filter chips would be answering a different question under them.
     *
     * @param array<string,array{values:array<int,string>,op:string}> $filters Already validated by
     *        logFilters() or decodeLogFilters().
     * @return array<int,string>
     */
    protected static function logFqsFor(string $rangeStart, array $filters, string $outcome): array
    {
        $fqs = array_merge(
            [OpensolrLog::dateFq($rangeStart)],
            Facets::logFor($filters, self::logFilterFields())->fqs()
        );

        $slice = self::outcomeFq($outcome);
        if ($slice !== null) {
            $fqs[] = $slice;
        }
        return $fqs;
    }

    /**
     * The filter list with ONE dimension lifted, for computing that dimension's own facet.
     *
     * THE REQUERY STRATEGY, AND WHY THIS PLANE HAS NO CHOICE. On Loghound's own cores a filter
     * carries `{!tag=…}` and its facet is asked for with the matching `domain.excludeTags`, so one
     * request answers a whole sidebar and every dimension keeps listing every value it has.
     * Neither half of that mechanism can reach the platform:
     *
     *   - \Loghound\OpensolrLog::assertSafeFq() refuses any `{!` in a filter, by throwing. It is a
     *     blunt check and it is the right one — it is what stops a crafted value switching the
     *     query parser — so the tag cannot be added even if the endpoint would carry it.
     *   - the endpoint rewrites every underscored parameter name into a dotted Solr parameter and
     *     sanitises its VALUE down to a class with no braces, so `facet.field={!ex=…}path` would
     *     arrive as a corrupted field name.
     *
     * So the same semantics are produced by asking again with that dimension's clause removed: one
     * extra call per FILTERED dimension, at most four because this plane has four filterable
     * fields, and exactly none when nothing is filtered. The client memoises by request shape, so
     * two dimensions sharing a filter set share the call.
     *
     * @return array<int,string>
     */
    protected function logFqsExcept(string $field): array
    {
        $fqs = array_merge(
            [OpensolrLog::dateFq(Query::filterStart($this->range))],
            $this->logFacets()->fqs(null, $field)
        );

        $slice = self::outcomeFq($this->outcome());
        if ($slice !== null) {
            $fqs[] = $slice;
        }
        return $fqs;
    }

    /**
     * Turn an outcome key into a range filter, or null when no slice is selected.
     *
     * Every bound here is a constant. Nothing about the request reaches the filter except
     * the choice of which of these three to use.
     */
    private static function outcomeFq(string $outcome): ?string
    {
        return match ($outcome) {
            'zero'  => OpensolrLog::numericFq('hits', '0', '0'),
            'found' => OpensolrLog::numericFq('hits', '1', '*'),
            'slow'  => OpensolrLog::numericFq('qtime', (string) self::SLOW_MS, '*'),
            default => null,
        };
    }

    /**
     * The labels of sidebar filters this section cannot honour.
     *
     * ALL of them, always, and that is the point. `f[…]` filters name fields on Loghound's
     * own cores; the platform's request log has none of them. A reader who filtered the
     * session explorer to one country and then opened this section would otherwise see
     * unfiltered search figures under a chip claiming otherwise. Reported in the envelope so
     * the filter card can say which ones were ignored and why.
     *
     * @return array<int,string>
     */
    protected function ignoredSidebarFilters(): array
    {
        $labels = Query::filterFields();

        $out = [];
        foreach (array_keys($this->filters) as $field) {
            $out[] = $labels[$field] ?? $field;
        }
        return $out;
    }

    /**
     * Wrap a request-log result in the panel's response envelope.
     *
     * `state` and `message` always travel, so the front end renders "this account does not
     * own that index" as a sentence in the card rather than as a generic failure.
     *
     * @param array<string,mixed> $result A result from OpensolrLog::log().
     * @param array<string,mixed> $extra
     * @return array<string,mixed>
     */
    protected function logEnvelope(array $result, array $extra = []): array
    {
        return $this->envelope(array_merge([
            'state'    => (string) $result['state'],
            'note'     => (string) $result['message'],
            'core'     => $this->core(),
            'requests' => (int) $result['numFound'],
            'active'   => $this->logFilters(),
            'outcome'  => $this->outcome(),
            'ignored'  => $this->ignoredSidebarFilters(),
        ], $extra));
    }

    /**
     * Answer the actions every Opensolr view shares, or null when it is not one of them.
     *
     * `facets` and `volume` are here rather than in the view because the filter rail and the
     * primary chart belong to the plane rather than to one page of it, and a second copy of one
     * facet call is a second place for the field list to drift.
     *
     * @return array<string,mixed>|null
     */
    protected function sharedApi(string $action): ?array
    {
        if ($action === 'facets') {
            return $this->filterFacets();
        }
        if ($action === 'volume') {
            return $this->volume();
        }
        if ($action !== 'indexes') {
            return null;
        }
        $list = $this->indexes();

        return $this->envelope([
            'state'    => $list['state'],
            'note'     => $list['message'],
            'indexes'  => $list['indexes'],
            'selected' => $this->core(),
            'outcome'  => $this->outcome(),
        ]);
    }

    /**
     * The filter rail: one call, four terms facets and the outcome split.
     *
     * A FILTERED DIMENSION IS ASKED AGAIN WITHOUT ITS OWN FILTER, so the rail behaves exactly
     * as the sidebar on Loghound's own views does: the handler list keeps listing every handler
     * with the count it would have if the handler filter were lifted, and a second handler can
     * therefore be added. That used to be impossible here — the facet was computed inside its own
     * filter, so choosing `/select` left the HANDLER list with one entry in it and nothing to
     * press.
     *
     * It costs one extra call per FILTERED dimension rather than nothing, and that is forced:
     * `{!ex=…}` cannot reach this plane at all (see logFqsExcept() for both reasons). Four
     * filterable fields means four calls in the worst case and none in the ordinary one, the
     * client memoises by request shape, and each call is `rows=0` with one facet on it.
     *
     * The outcome counts come from a single-bucket range facet on `hits`: `[0 TO 1)` is the
     * requests that matched nothing, and the facet's `after` counter is everything else. One
     * facet, two numbers, no arithmetic that can drift apart. There is no cheap count for the
     * slow slice — it would need a second call for a number the reader can get by selecting
     * it — so it is offered without one rather than with a guess.
     *
     * @return array<string,mixed>
     */
    private function filterFacets(): array
    {
        $facets = $this->logFacets();
        $filtered = $facets->selected();

        $res = $this->fetch([
            'fq'           => $this->logFqs(),
            'rows'         => 0,
            'facet_fields' => array_keys(self::logFilterFields()),
            'facet_limit'  => self::FILTER_FACET_LIMIT,
            'ranges'       => ['hits' => ['start' => '0', 'end' => '1', 'gap' => '1', 'other' => 'all']],
        ]);

        $lifted = [];
        foreach ($filtered as $field) {
            $one = $this->fetch([
                'fq'           => $this->logFqsExcept($field),
                'rows'         => 0,
                'facet_fields' => [$field],
                'facet_limit'  => self::FILTER_FACET_LIMIT,
            ]);
            $lifted[$field] = (array) ($one['facet_fields'][$field] ?? []);
        }

        $groups = [];
        foreach (self::logFilterFields() as $field => $label) {
            $excluded = array_key_exists($field, $lifted);
            $terms = $excluded ? $lifted[$field] : (array) ($res['facet_fields'][$field] ?? []);
            $chosen = $facets->values($field);
            if ($terms === [] && $chosen === []) {
                continue;
            }

            $buckets = [];
            $seen = [];
            foreach ($terms as $value => $count) {
                $value = (string) $value;
                $seen[$value] = true;
                $buckets[] = [
                    'value' => $value,
                    'label' => $value,
                    'count' => (int) $count,
                    'state' => $this->logState($field, $value),
                ];
            }
            foreach ($chosen as $value) {
                if (!isset($seen[$value])) {
                    $buckets[] = [
                        'value' => $value,
                        'label' => $value,
                        'count' => null,
                        'state' => $this->logState($field, $value),
                    ];
                }
            }

            $groups[] = [
                'field'      => $field,
                'label'      => $label,
                'ns'         => 'lf',
                'filterable' => true,
                'arity'      => $facets->arity($field),
                'op'         => $facets->op($field),
                'operators'  => $facets->operators($field),
                'chosen'     => $chosen,
                'buckets'    => $buckets,
                'truncated'  => count($buckets) >= self::FILTER_FACET_LIMIT,
                'basis'      => $excluded ? 'excluded' : 'filtered',
                'basis_note' => $excluded
                    ? 'Counts are what each value would match with the ' . mb_strtolower($label)
                        . ' filter lifted, so a second value can be added.'
                    : 'Counts are what each value matches on this page as filtered.',
                'overlaps'   => false,
            ];
        }

        $hits = $res['facet_ranges']['hits'] ?? null;

        return $this->logEnvelope($res, [
            'groups'   => $groups,
            'filters'  => $facets->payload(),
            'limit'    => self::FILTER_FACET_LIMIT,
            'outcomes' => [
                'zero'  => is_array($hits) ? (int) ($hits['counts']['0'] ?? 0) : null,
                'found' => is_array($hits) && $hits['after'] !== null ? (int) $hits['after'] : null,
                'slow'  => null,
            ],
            'slow_ms'  => self::SLOW_MS,
        ]);
    }

    /**
     * What one request-log value is doing: chosen, chosen-and-excluded, or nothing.
     *
     * The same three states the sessions plane uses, because they are the states the operator
     * created and a rail that showed only two would put a tick beside a value just excluded.
     */
    private function logState(string $field, string $value): string
    {
        $facets = $this->logFacets();
        if (!in_array($value, $facets->values($field), true)) {
            return 'off';
        }
        return $facets->op($field) === Facets::OP_NONE ? 'excluded' : 'on';
    }

    /**
     * Request volume over time, with the zero-result share drawn underneath it.
     *
     * THE PRIMARY CHART ON ALL THREE VIEWS, and the one thing every analytics dashboard has.
     * It is here rather than on one view because it is the chart that makes the filter rail
     * mean something: filtered to one caller it answers "when did this client hit us", and
     * filtered to one handler it answers "when is this integration busy".
     *
     * Two calls rather than one, because the endpoint cannot express a nested facet: the
     * second is the same range facet with `hits:0` added, which is cheap and is the only way
     * to see whether a spike in traffic was a spike in USEFUL traffic. When an outcome slice
     * is already selected the second call is skipped — `hits:0` intersected with "matched
     * something" is empty by construction, and asking for it would spend a call to be told so.
     *
     * @return array<string,mixed>
     */
    private function volume(): array
    {
        $range = ['date' => [
            'start' => (string) $this->range['start'],
            'end'   => 'NOW',
            'gap'   => (string) $this->range['gap'],
            'other' => 'none',
        ]];

        $all = $this->fetch(['fq' => $this->logFqs(), 'rows' => 0, 'ranges' => $range]);
        if ($all['state'] !== 'ok') {
            return $this->logEnvelope($all, [
                'times' => [], 'all' => [], 'zero' => [], 'zero_total' => 0, 'zero_known' => false,
            ]);
        }

        $allCounts = (array) ($all['facet_ranges']['date']['counts'] ?? []);
        $times = array_keys($allCounts);

        $zeroKnown = $this->outcome() === '';
        $zeroCounts = [];
        $zeroTotal = 0;

        if ($zeroKnown) {
            $empty = $this->fetch([
                'fq'     => array_merge($this->logFqs(), [OpensolrLog::numericFq('hits', '0', '0')]),
                'rows'   => 0,
                'ranges' => $range,
            ]);
            $found = (array) ($empty['facet_ranges']['date']['counts'] ?? []);
            foreach ($times as $bucket) {
                $zeroCounts[] = (int) ($found[$bucket] ?? 0);
            }
            $zeroTotal = (int) $empty['numFound'];
        }

        return $this->logEnvelope($all, [
            'times'      => $times,
            'all'        => array_values(array_map('intval', $allCounts)),
            'zero'       => $zeroCounts,
            'zero_total' => $zeroTotal,
            'zero_known' => $zeroKnown,
        ]);
    }

    /* ---------------------------------------------------------------------------------
     * Shared markup
     * ------------------------------------------------------------------------------ */

    /**
     * The state-3 screen: no Opensolr credentials at all.
     *
     * Not an error and not a nag. Loghound is a complete product without Opensolr, and the
     * only honest thing to do is say what this section would show and where the two values
     * go. Rendered instead of the cards, so nothing on the page can fail.
     *
     * IT GOES THROUGH cardOpen() LIKE EVERY OTHER CARD. It used to emit its own `<section
     * class="card">` with a literal `01` and no id, which put it outside all three things
     * that read a card: the jump bar Layout derives from the markup, the numbering, and the
     * fold state the accordion keys on `data-card`. A card with no id cannot be remembered
     * open or shut, so this one silently ignored the operator — harmless only because it is
     * always alone on its page, which is not a property worth depending on.
     */
    protected static function noCredentials(): void
    {
        self::cardOpen('os-none', '01', 'Not connected to Opensolr');
        echo '<div class="explain">';
        echo '<p>This section reads the request log of your Opensolr search indexes and lines it up '
            . 'against the web traffic Loghound already analyses. Everything else in Loghound works '
            . 'without it — this is the search half, and it is switched off because there is no '
            . 'Opensolr account configured.</p>';
        echo '<p>With an account connected, this section answers:</p>';
        echo '<ul>';
        echo '<li>how many queries each index served, and how long they took;</li>';
        echo '<li>how often a query came back with nothing at all;</li>';
        echo '<li>which handler on the index took the traffic, and what it answered with.</li>';
        echo '</ul>';
        echo '<p>To connect one, put the email address of your Opensolr account and its API key into the '
            . '<code>opensolr</code> section of <code>config/loghound.php</code>, which lives outside the '
            . 'document root:</p>';
        echo '<pre class="snippet mono">\'opensolr\' =&gt; [' . "\n"
            . '    \'email\'   =&gt; \'you@example.com\',' . "\n"
            . '    \'api_key\' =&gt; \'&hellip;\',' . "\n"
            . '],</pre>';
        echo '<p class="faint">The key is read server-side only. It is never rendered into a page, never '
            . 'put in a URL your browser sees, and never written to a log.</p>';
        echo '</div>';
        self::cardEnd();
    }

    /**
     * The index picker, rendered empty and filled by the front end.
     *
     * Empty on purpose: the list comes from the platform, so populating it server-side
     * would make every page render wait on an API call — the exact blocking this panel is
     * built to avoid.
     */
    protected static function indexPicker(string $id): string
    {
        $e = Security::esc($id);
        return '<div class="controls">'
            . '<label for="' . $e . '">Index</label>'
            . '<select id="' . $e . '" disabled><option value="">Loading&#8230;</option></select>'
            . '</div>';
    }

    /**
     * The cards this view renders, in order, for the jump bar and the card numbering.
     *
     * @return array<int,array<int,string>>
     */
    public function sections(): array
    {
        return static::SECTIONS;
    }

    /** The number this card carries, from its position in sections() rather than a literal. */
    protected function cardNumber(string $id): string
    {
        return Layout::cardNum($this->sections(), $id);
    }

    /**
     * A row of headline figures, each stating what it counts.
     *
     * SPEC §10 requires every number to say what population it covers, so the hint is not
     * optional and there is no overload without one. The values are placeholders — an
     * em-dash — and are filled by the front end, because nothing log-derived is rendered by
     * PHP on any view in this panel.
     *
     * @param array<int,array{0:string,1:string,2:string}> $stats field, label, hint
     */
    protected static function statRow(array $stats): void
    {
        echo '<div class="stats">';
        foreach ($stats as [$field, $label, $hint]) {
            echo '<div class="stat"><span class="stat-label">' . Security::esc($label) . '</span>';
            echo '<span class="stat-value mono" data-field="' . Security::esc($field) . '">&#8212;</span>';
            echo '<span class="stat-hint">' . Security::esc($hint) . '</span></div>';
        }
        echo '</div>';
    }

    /**
     * The filter rail: what the reader can slice this section by.
     *
     * Rendered as an ordinary async card rather than as a second sidebar. The panel already
     * has a sidebar on the left and the session explorer has a facet rail of its own; a third
     * vertical column on a page whose main chart wants the width would compete with both.
     *
     * The outcome buttons and the facet lists are links, not form controls, so a filtered
     * view is a URL somebody can bookmark and send to a colleague — which is the whole reason
     * the filters live in the query string and not in a session.
     *
     * @param string $id Card base id, e.g. 'ix-filters'.
     */
    protected function filterCard(string $id, string $tools = ''): void
    {
        self::cardOpen(
            $id,
            $this->cardNumber($id),
            'Slice these figures',
            'Every page of this view answers under the filters set here.',
            $tools
        );
        self::skeleton($id, 'rows', 0, 'Faceting the request log');

        echo '<div class="lf-active" id="' . Security::esc($id) . '-active"></div>';
        echo '<div class="lf-outcomes" id="' . Security::esc($id) . '-outcomes"></div>';
        echo '<div class="lf-rail" id="' . Security::esc($id) . '-rail"></div>';
        echo '<p class="faint" id="' . Security::esc($id) . '-note"></p>';

        self::cardClose($id);
    }

    /**
     * The primary chart: request volume over time.
     *
     * @param string $id Card base id, e.g. 'ix-volume'.
     */
    protected function volumeCard(string $id): void
    {
        self::cardOpen(
            $id,
            $this->cardNumber($id),
            'Requests over time',
            'Every request the platform logged for this index under the current filters.'
        );
        self::skeleton($id, 'chart', 300, 'Faceting request volume');

        self::statRow([
            ['total', 'Requests', 'Logged by Opensolr in this range, under the current filters'],
            ['mean', 'Average per bucket', 'Requests divided by the number of buckets in the chart'],
            ['peak', 'Peak bucket', 'The busiest single bucket in the chart'],
            ['points', 'Data points', 'How many buckets the range was divided into'],
        ]);
        echo '<div class="chart" id="' . Security::esc($id) . '-chart" style="height:300px"></div>';

        self::cardClose($id);
    }
}
