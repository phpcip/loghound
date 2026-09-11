<?php
/**
 * Loghound — the panel's facet layer: filter state, boolean operators, tagging, exclusion.
 *
 * ONE COMPONENT, EVERY SECTION. Before this file the panel had a facet MECHANISM and no
 * facet SEMANTICS. `?f[field][]=value` was parsed in Controller, turned into `fq` clauses in
 * Controller, rendered in Sessions, and re-implemented from scratch for the Opensolr
 * request-log plane in OpensolrView under a second namespace. Four copies of one idea, and
 * every one of them got the same thing wrong.
 *
 * ---------------------------------------------------------------------------------------
 * WHAT WAS WRONG, PRECISELY
 * ---------------------------------------------------------------------------------------
 * A filter was applied as an ordinary `fq`, and the facet over the same field was computed
 * inside it. So the moment an operator picked `host_s=opensolr.com`, the VIRTUAL HOST facet
 * listed exactly one value — opensolr.com — because every other host had been filtered out
 * of its own facet. Same for the verdict, the country, the browser and every other
 * dimension. The interface removed the very options a multi-select needs: you could not see
 * what else existed, and you could not add a second value. Measured against a real Solr:
 *
 *     fq={!tag=f_ct}content_type:("text/html")
 *       facet, no exclusion   → buckets: text/html 483                        (one option)
 *       facet, excludeTags    → buckets: text/html 483, application/pdf 2     (both)
 *       count in both cases   → 483, the filtered total
 *
 * ---------------------------------------------------------------------------------------
 * HOW IT IS FIXED: TAG, THEN EXCLUDE
 * ---------------------------------------------------------------------------------------
 * Every dimension's `fq` carries a tag this class generates — `f_` plus the field name, or a
 * hash of it when that would be too long for Solr's local-param grammar. Never anything
 * derived from a request. The terms facet for that same dimension is then asked for with
 * `domain.excludeTags` naming its OWN tag and no other, so:
 *
 *   - the dimension keeps listing every value it has, with the count each would have if
 *     this dimension's filter were lifted;
 *   - every OTHER dimension still narrows normally, because only one tag is excluded;
 *   - the headline total (`facets.count`) remains the fully filtered figure.
 *
 * That is the whole trick, and it is why the operator can add a second and a third value.
 *
 * ---------------------------------------------------------------------------------------
 * THREE OPERATORS, AND WHY NOT ALL THREE EVERYWHERE
 * ---------------------------------------------------------------------------------------
 *   Any of   `field:("a" OR "b")`     the default; widens. Offered on every dimension.
 *   All of   `field:("a" AND "b")`    narrows. Offered ONLY on a multi-valued field.
 *   None of  `-field:("a" OR "b")`    excludes. Offered on every dimension.
 *
 * "All of" is withheld rather than disabled-with-an-explanation on a single-valued field,
 * because `a AND b` over one value per document is empty BY CONSTRUCTION — measured, not
 * assumed: on a single-valued field the AND form returned 0 where the OR form returned 485,
 * and on a genuinely multi-valued one it returned 74 where OR returned 163. A control whose
 * only possible answer is zero is worse than no control, so the field's arity decides
 * whether it appears at all (Query::multiValuedFilterFields()).
 *
 * "None of" is the operator the product was missing most. It is a pure-negative `fq`, which
 * Solr handles at the top level of a filter, verified against a real node: `-f:("a")`
 * returned the complement, and `-f:("a" OR "b")` the complement of the pair.
 *
 * ---------------------------------------------------------------------------------------
 * THE URL IS THE STATE
 * ---------------------------------------------------------------------------------------
 * Values stay where they were — `f[field][]=value`, repeated — and the operator rides in the
 * same array under a reserved key: `f[field][op]=any|all|none`. One parameter family carries
 * a dimension's whole state, and a URL with no `op` means "any of", so every link already
 * bookmarked or shared behaves exactly as it did. Numeric keys are values; `op` is the
 * operator; any other key is ignored, which is stricter than the `(array) $values` cast this
 * replaces.
 *
 * ---------------------------------------------------------------------------------------
 * TWO PLANES, TWO EXCLUSION STRATEGIES
 * ---------------------------------------------------------------------------------------
 * Loghound's own cores take `{!tag=}` and `domain.excludeTags` and answer a whole view in
 * ONE round trip. The Opensolr request-log plane cannot: \Loghound\OpensolrLog::assertSafeFq()
 * refuses any `{!` outright, and the platform endpoint sanitises the value of every
 * underscored parameter — `facet_field` among them — down to a character class with no
 * braces, so `{!ex=…}` could not arrive intact even if the filter could. There the same
 * semantics are produced by lifting one dimension's clause and asking again
 * (EXCLUDE_REQUERY): one extra request per FILTERED dimension, at most four because that
 * plane has four filterable fields, and exactly none when nothing is filtered.
 *
 * ---------------------------------------------------------------------------------------
 * SECURITY
 * ---------------------------------------------------------------------------------------
 * Field names come only from the label map handed to the constructor, and are re-checked
 * through Security::isSafeFieldName on the way into a clause. Values are quoted literals
 * (Query::quote) for a string field and must match a strict pattern for a numeric or boolean
 * one — a value that cannot be that field's type is DROPPED here rather than sent, so a
 * hand-edited URL produces a filter nobody set instead of a Solr 400 in an error banner.
 * Tag names are generated. `op` is one of three constants. Nothing in this file interpolates
 * request text into `q`, `fq`, `sort`, `fl`, `defType` or a `{!…}` local param.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Security;

final class Facets
{
    /** Values within the dimension are OR-ed. The default, and what an absent `op` means. */
    public const OP_ANY = 'any';

    /** Values within the dimension are AND-ed. Multi-valued fields only. */
    public const OP_ALL = 'all';

    /** The dimension's values are excluded. */
    public const OP_NONE = 'none';

    /** Every operator, in the order the control offers them. */
    public const OPERATORS = [self::OP_ANY, self::OP_ALL, self::OP_NONE];

    /** A facet ignores its own filter through `{!tag=}` plus `domain.excludeTags`. */
    public const EXCLUDE_TAGGED = 'tagged';

    /** A facet ignores its own filter by being asked again without that filter. */
    public const EXCLUDE_REQUERY = 'requery';

    /** A dimension holds one value per document: "All of" cannot match and is not offered. */
    public const ARITY_SINGLE = 'single';

    /** A dimension holds a list per document: all three operators are meaningful. */
    public const ARITY_MULTI = 'multi';

    /** Maximum values accepted for one dimension, matching the previous readFilters() cap. */
    private const MAX_VALUES = 20;

    /** Maximum bytes kept from one value, matching the previous readFilters() cap. */
    private const MAX_VALUE_BYTES = 256;

    /** Longest tag this class will emit, inside Solr's local-param grammar and our own check. */
    private const MAX_TAG = 60;

    /**
     * Shortest substring that may be sent as a value search.
     *
     * One character matches most of a term dictionary and costs a full scan to say so, which is a
     * cheap way to make Solr work hard on every keystroke. Two is where a search starts narrowing
     * anything, and below it the browser filters what it already has instead.
     */
    public const MIN_SEARCH = 2;

    /** Longest substring accepted, matching \Loghound\Solr::assertSafeContains(). */
    public const MAX_SEARCH = 64;

    /** Query-string keys that belong on a panel PAGE url. Everything else is an API detail. */
    private const PAGE_PARAMS = ['v', 'range', 'q', 'sort', 'rows', 'core', 'outcome'];

    /** The `f`/`lf` prefix this instance reads and writes. */
    private string $ns;

    /** @var array<string,string> field => human label. The allowlist; nothing else is a dimension. */
    private array $labels;

    /** @var array<string,string> field => 'string'|'int'|'bool'. Absent means string. */
    private array $kinds;

    /** @var array<int,string> Fields that hold a list per document, so "All of" is offered. */
    private array $multi;

    /** One of EXCLUDE_TAGGED / EXCLUDE_REQUERY. */
    private string $exclusion;

    /** @var array<string,string> Dimension field => the name the target core actually uses. */
    private array $aliases;

    /** @var array<string,array{values:array<int,string>,op:string}> The validated selection. */
    private array $sel = [];

    /** @var array<string,string> The request's page parameters, for building links. */
    private array $page = [];

    /**
     * @param array<string,string>   $labels    field => label allowlist.
     * @param array<string,string>   $kinds     field => 'string'|'int'|'bool'.
     * @param array<int,string>      $multi     Multi-valued field names.
     * @param array<string,string>   $aliases   Dimension field => target-core field name.
     */
    public function __construct(
        string $ns,
        array $labels,
        array $kinds = [],
        array $multi = [],
        string $exclusion = self::EXCLUDE_TAGGED,
        array $aliases = []
    ) {
        $this->ns = preg_match('/^[a-z]{1,4}$/D', $ns) === 1 ? $ns : 'f';
        $this->labels = array_filter(
            $labels,
            static fn (string $field): bool => Security::isSafeFieldName($field),
            ARRAY_FILTER_USE_KEY
        );
        $this->kinds = $kinds;
        $this->multi = array_values(array_intersect($multi, array_keys($this->labels)));
        $this->exclusion = $exclusion === self::EXCLUDE_REQUERY ? self::EXCLUDE_REQUERY : self::EXCLUDE_TAGGED;
        $this->aliases = $aliases;
    }

    /**
     * The facet layer for Loghound's own sessions core.
     *
     * The filter allowlist MINUS the hits-only dimensions, session aliases applied
     * (`session_id_s` is the session document's `id` on this core), and tagged exclusion because
     * this is our own Solr.
     *
     * The subtraction is not cosmetic. A status is a property of a REQUEST and the sessions core
     * does not define `status_i` or `status_class_s` at all, so a status filter carried here
     * would produce an `fq` naming a field that does not exist — which matches nothing and
     * empties every card on every sessions-plane view, under a chip saying it merely narrowed.
     * Query::hitsOnlyFields() is the list, and it is derived by subtraction for the same reason
     * hitFilterFields() is: a new dimension reaches both planes by default and has to be
     * excluded on purpose.
     */
    public static function sessions(array $get): self
    {
        $f = new self(
            'f',
            Query::sessionFilterFields(),
            Query::filterFieldKinds(),
            Query::multiValuedFilterFields(),
            self::EXCLUDE_TAGGED,
            Query::sessionFilterAliases()
        );
        return $f->read($get);
    }

    /**
     * A DISPLAY-ONLY layer over every dimension, whichever plane defines it.
     *
     * WHAT THIS IS FOR, AND WHAT IT MUST NEVER BE USED FOR. The filter bar at the top of every
     * page shows which filters are in force and offers a way to remove them, and it is rendered
     * from ONE payload whatever view is underneath. The sessions layer cannot be that payload
     * any more: it deliberately does not carry the hits-only dimensions, so a status filter set
     * from the Attacks view would narrow that page correctly and then be invisible in the bar —
     * in force, doing its job, and impossible to see or remove. An affordance that is missing
     * for a filter that IS applied is its own kind of wrong.
     *
     * So the bar is rendered from the union and the QUERIES are not. This instance builds no
     * `fq` for anybody: `Controller::sessionFqs()` goes through the sessions layer and
     * `hitFqs()` through the hits one, and each of those drops what its core cannot answer and
     * reports it (`filters_ignored`). Calling fqs() on this one would put a clause naming a
     * field the target core does not define into a query, which matches nothing while looking
     * like it narrowed — the exact defect the two narrower layers exist to prevent.
     */
    public static function all(array $get): self
    {
        $f = new self(
            'f',
            Query::filterFields(),
            Query::filterFieldKinds(),
            Query::multiValuedFilterFields(),
            self::EXCLUDE_TAGGED
        );
        return $f->read($get);
    }

    /**
     * The facet layer for the hits core.
     *
     * A narrower allowlist: a verdict, a bot class, a fired signal and a visited-path list
     * are conclusions about a whole session and exist only on the sessions core. An `fq`
     * naming a field a core does not define matches nothing, so the hits plane must be given
     * the subset it can answer and must say what it dropped (Controller::ignoredHitFilters()).
     */
    public static function hits(array $get): self
    {
        $f = new self(
            'f',
            Query::hitFilterFields(),
            Query::filterFieldKinds(),
            Query::multiValuedFilterFields(),
            self::EXCLUDE_TAGGED
        );
        return $f->read($get);
    }

    /**
     * The facet layer for the Opensolr request-log plane.
     *
     * Its own namespace, because these field names exist on the platform's analytics shards
     * and nowhere in Loghound's schemas, and vice versa. Requery exclusion, because that
     * plane refuses local params.
     *
     * @param array<string,string> $labels OpensolrView::logFilterFields().
     */
    public static function log(array $get, array $labels): self
    {
        $f = new self('lf', $labels, [], [], self::EXCLUDE_REQUERY);
        return $f->read($get);
    }

    /**
     * A log-plane layer seeded from an already-stored selection rather than from a request.
     *
     * For the stepped scans, which do not have the request that started them: a scan is resumed
     * from a persisted context on every poll, so it has to rebuild the same filters — the same
     * values AND the same operator — from values it re-validates itself. A scan that quietly read
     * the whole log while the page showed filter chips would be answering a different question
     * under them, and one that dropped a "None of" would answer the exact opposite.
     *
     * The stored selection is treated as hostile, because it is a store a future bug could write
     * anything into: it goes through the same read() as a query string.
     *
     * @param array<string,mixed>  $selection field => list of values, or field => {values, op}.
     * @param array<string,string> $labels    OpensolrView::logFilterFields().
     */
    public static function logFor(array $selection, array $labels): self
    {
        $request = [];
        foreach ($selection as $field => $spec) {
            if (!is_string($field)) {
                continue;
            }
            $values = is_array($spec) && isset($spec['values']) ? (array) $spec['values'] : (array) $spec;
            $entry = array_values(array_filter($values, 'is_string'));
            if (is_array($spec) && isset($spec['op']) && is_string($spec['op'])) {
                $entry['op'] = $spec['op'];
            }
            $request[$field] = $entry;
        }
        return self::log(['lf' => $request], $labels);
    }

    /**
     * Read the selection out of a request array.
     *
     * A field not in the allowlist is dropped in silence: the UI never produces one, so its
     * presence means someone is probing and there is nothing useful to tell them. So is a
     * value that cannot be the field's type, and an `op` that is not one of the three.
     *
     * @param array<string,mixed> $get
     */
    public function read(array $get): self
    {
        $this->page = self::pageParams($get);

        $raw = $get[$this->ns] ?? null;
        if (!is_array($raw)) {
            return $this;
        }

        foreach ($raw as $field => $spec) {
            if (!is_string($field) || !isset($this->labels[$field]) || !is_array($spec)) {
                continue;
            }

            $values = [];
            foreach ($spec as $key => $value) {
                if ($key === 'op' || !is_string($value)) {
                    continue;
                }
                if (!is_int($key) && !ctype_digit((string) $key)) {
                    continue;
                }
                $value = mb_substr($value, 0, self::MAX_VALUE_BYTES);
                if ($this->acceptsValue($field, $value)) {
                    $values[] = $value;
                }
            }
            $values = array_values(array_unique(array_slice($values, 0, self::MAX_VALUES)));
            if ($values === []) {
                continue;
            }

            $this->sel[$field] = ['values' => $values, 'op' => $this->readOp($field, $spec['op'] ?? null)];
        }

        return $this;
    }

    /**
     * Resolve a requested operator, falling back to "any of".
     *
     * "All of" asked for on a single-valued field falls back rather than being honoured:
     * honouring it would empty the view under a control the UI never offered, which reads as
     * "this combination has no traffic" instead of "that question cannot be asked here".
     */
    private function readOp(string $field, $requested): string
    {
        if (!is_string($requested) || !in_array($requested, self::OPERATORS, true)) {
            return self::OP_ANY;
        }
        if ($requested === self::OP_ALL && $this->arity($field) !== self::ARITY_MULTI) {
            return self::OP_ANY;
        }
        return $requested;
    }

    /**
     * Can this value be a value of this field at all?
     *
     * A string field takes anything printable — it is quoted into a literal. A numeric field
     * takes digits only, and a boolean takes the two words Solr writes, because a quoted
     * non-number against a point field is a Solr 400 and a 400 here becomes an error banner
     * across a page whose cards are fine. Control characters are refused rather than
     * stripped: stripping joins the two halves of a value into a third thing nobody asked
     * for.
     *
     * `{!`, `_query_` and `_val_` are refused for a reason that is NOT injection. Quoting
     * already makes them inert text — `{!frange}` inside a quoted literal is a search for that
     * string. The problem is that both \Loghound\Solr::assertSafeFilter() and
     * \Loghound\OpensolrLog::assertSafeFq() refuse those three ANYWHERE in a filter, quoted or
     * not, and they do it by THROWING. So a crafted query string would not be ignored, it would
     * take the JSON endpoint down with "the panel could not complete that request". Dropping
     * the value here, on exactly the grounds the blunt check uses, leaves the blunt check as the
     * last word and makes a hostile URL behave like a filter nobody set.
     */
    private function acceptsValue(string $field, string $value): bool
    {
        if ($value === '' || preg_match('/[\x00-\x1F\x7F]/', $value) === 1) {
            return false;
        }
        if (str_contains($value, '{!')) {
            return false;
        }
        if (stripos($value, '_query_') !== false || stripos($value, '_val_') !== false) {
            return false;
        }
        return match ($this->kind($field)) {
            'int'  => preg_match('/^-?\d{1,19}$/D', $value) === 1,
            'bool' => $value === 'true' || $value === 'false',
            default => true,
        };
    }

    /** The declared type of a dimension: 'string', 'int' or 'bool'. */
    public function kind(string $field): string
    {
        $kind = $this->kinds[$field] ?? 'string';
        return in_array($kind, ['string', 'int', 'bool'], true) ? $kind : 'string';
    }

    /** Does this dimension hold one value per document, or a list? */
    public function arity(string $field): string
    {
        return in_array($field, $this->multi, true) ? self::ARITY_MULTI : self::ARITY_SINGLE;
    }

    /** The query-string prefix this instance owns: 'f' or 'lf'. */
    public function namespaceKey(): string
    {
        return $this->ns;
    }

    /** @return array<string,string> The dimension allowlist, field => label. */
    public function fields(): array
    {
        return $this->labels;
    }

    /** @return array<string,array{values:array<int,string>,op:string}> */
    public function selection(): array
    {
        return $this->sel;
    }

    /** Is nothing filtered? */
    public function isEmpty(): bool
    {
        return $this->sel === [];
    }

    /** @return array<int,string> The fields carrying a selection, in request order. */
    public function selected(): array
    {
        return array_keys($this->sel);
    }

    /** @return array<int,string> The chosen values of one dimension, or an empty list. */
    public function values(string $field): array
    {
        return $this->sel[$field]['values'] ?? [];
    }

    /** The operator in force on one dimension. Always one of the three constants. */
    public function op(string $field): string
    {
        return $this->sel[$field]['op'] ?? self::OP_ANY;
    }

    /**
     * The legacy filter shape: field => list of values.
     *
     * Kept because it is what every `active` key in every API payload has carried since the
     * beginning and what the front end reads to draw its chips. The operator is reported
     * alongside it in payload(), never folded into this.
     *
     * @return array<string,array<int,string>>
     */
    public function flat(): array
    {
        $out = [];
        foreach ($this->sel as $field => $spec) {
            $out[$field] = $spec['values'];
        }
        return $out;
    }

    /**
     * The tag that marks one dimension's filter so its own facet can ignore it.
     *
     * Generated from the field name, which came from the allowlist, and never from request
     * text. A name long enough to overflow the local-param grammar is hashed instead of
     * truncated, because two truncated names could collide and a collision would silently
     * exclude the wrong dimension.
     */
    public function tag(string $field): string
    {
        $tag = 'f_' . $field;
        if (strlen($tag) > self::MAX_TAG) {
            $tag = 'f_' . substr(hash('sha256', $field), 0, 24);
        }
        return $tag;
    }

    /**
     * The Solr clause for one dimension, or null when it cannot be built.
     *
     * @param bool $tagged Prefix the generated tag. False on a plane that refuses local params.
     */
    public function clause(string $field, bool $tagged = true): ?string
    {
        $values = $this->values($field);
        if ($values === [] || !isset($this->labels[$field])) {
            return null;
        }

        $target = $this->aliases[$field] ?? $field;
        if (!Security::isSafeFieldName($target)) {
            return null;
        }

        $literals = [];
        foreach ($values as $value) {
            $literals[] = $this->kind($field) === 'string' ? Query::quote($value) : $value;
        }

        $op = $this->op($field);
        $joiner = $op === self::OP_ALL ? ' AND ' : ' OR ';
        $group = $target . ':(' . implode($joiner, $literals) . ')';
        $clause = ($op === self::OP_NONE ? '-' : '') . $group;

        return ($tagged && $this->exclusion === self::EXCLUDE_TAGGED ? '{!tag=' . $this->tag($field) . '}' : '')
            . $clause;
    }

    /**
     * Every active dimension as an `fq` list.
     *
     * `$only` restricts the list to fields the core about to be queried actually defines.
     * `$except` lifts one dimension, which is how the requery plane computes a facet that
     * ignores its own filter.
     *
     * @param array<int,string>|null $only
     * @return array<int,string>
     */
    public function fqs(?array $only = null, ?string $except = null): array
    {
        $out = [];
        foreach (array_keys($this->sel) as $field) {
            if ($only !== null && !in_array($field, $only, true)) {
                continue;
            }
            if ($except !== null && $field === $except) {
                continue;
            }
            $clause = $this->clause($field);
            if ($clause !== null) {
                $out[] = $clause;
            }
        }
        return $out;
    }

    /**
     * Terms-facet definitions for a set of dimensions, each excluding its own filter.
     *
     * The whole point of the component in one method: the definition for `host_s` carries
     * `domain.excludeTags: ['f_host_s']` and nothing else, so the host list stays complete
     * while every other dimension in the same request still narrows. On a requery plane no
     * exclusion is attached, and the caller asks again per filtered dimension instead.
     *
     * `numBuckets` is requested only when asked for, because it makes Solr count the whole
     * term space rather than the page of it being returned. The value browser needs it to
     * say honestly that it is showing the top N of M.
     *
     * @param array<int,string> $fields
     * @return array<string,mixed>
     */
    public function termsFacets(array $fields, int $limit, bool $numBuckets = false): array
    {
        $out = [];
        foreach ($fields as $field) {
            if (!isset($this->labels[$field])) {
                continue;
            }
            $def = [
                'type'     => 'terms',
                'field'    => $this->aliases[$field] ?? $field,
                'limit'    => Security::clampInt($limit, 1, 10000, 12),
                'mincount' => 1,
                'sort'     => 'count desc',
            ];
            if ($numBuckets) {
                $def['numBuckets'] = true;
            }
            if ($this->exclusion === self::EXCLUDE_TAGGED && isset($this->sel[$field])) {
                $def['domain'] = ['excludeTags' => [$this->tag($field)]];
            }
            $out[$field] = $def;
        }
        return $out;
    }

    /**
     * Normalise a value-search substring, or return '' when it is not worth sending.
     *
     * The gate in front of \Loghound\Solr::facetContains(). It answers '' rather than throwing for
     * anything a person could plausibly have typed — an empty box, one character, a box holding
     * only spaces — because none of those is an error, they are simply not a search yet, and the
     * browser filters locally instead. Control characters and anything over the cap are trimmed
     * away here so the blunt check downstream never has to throw on a hand-edited URL.
     */
    public static function searchTerm(?string $raw): string
    {
        if (!is_string($raw)) {
            return '';
        }
        $term = trim((string) preg_replace('/[\x00-\x1F\x7F]/', '', $raw));
        if (mb_strlen($term) < self::MIN_SEARCH) {
            return '';
        }
        return mb_substr($term, 0, self::MAX_SEARCH);
    }

    /**
     * The tags a dimension's own facet must exclude, or an empty list when nothing is filtered.
     *
     * Its own, and only its own. Used by the value browser's search, which is a classic facet and
     * spells the exclusion on the field name rather than in a domain block, but means exactly the
     * same thing: search the values this dimension HAS, not the ones left after it filtered itself.
     *
     * @return array<int,string>
     */
    public function ownTags(string $field): array
    {
        if ($this->exclusion !== self::EXCLUDE_TAGGED || !isset($this->sel[$field])) {
            return [];
        }
        return [$this->tag($field)];
    }

    /**
     * A nested facet: the inner dimension counted within each bucket of the outer one.
     *
     * A cross-tabulation, asked of Solr as one nested terms facet rather than built in PHP
     * out of one request per outer value. NO exclusion is attached to either level, and that
     * is deliberate: a pivot is a report, not a control, so its numbers must be the numbers
     * of the filtered page the reader is looking at. Attaching an exclusion would give a
     * cross-tab whose cells did not add up to anything else on screen.
     *
     * @return array<string,mixed> A single-entry facet definition, keyed by $key.
     */
    public function pivot(string $key, string $outer, string $inner, int $outerLimit = 8, int $innerLimit = 5): array
    {
        if (!Security::isSafeFieldName($outer) || !Security::isSafeFieldName($inner) || $outer === $inner) {
            return [];
        }
        if (!preg_match('/^[A-Za-z0-9_]{1,64}$/D', $key)) {
            return [];
        }

        return [
            $key => [
                'type'     => 'terms',
                'field'    => $outer,
                'limit'    => Security::clampInt($outerLimit, 1, 50, 8),
                'mincount' => 1,
                'sort'     => 'count desc',
                'facet'    => [
                    'by' => [
                        'type'     => 'terms',
                        'field'    => $inner,
                        'limit'    => Security::clampInt($innerLimit, 1, 50, 5),
                        'mincount' => 1,
                        'sort'     => 'count desc',
                    ],
                ],
            ],
        ];
    }

    /**
     * Reshape a pivot's response into rows a table can render.
     *
     * Each row carries the outer value, its own count, and the inner buckets. `covered` is
     * the sum of the inner counts and is reported rather than assumed equal to the row
     * total: the inner facet is limited, so the cells of a row normally do NOT add up to it,
     * and a reader who assumes they do is reading a different number than the label claims.
     *
     * `$outer` and `$inner` name the dimensions the two levels came from, so every cell can
     * carry the words a person reads beside the slug it filters on. Omitting them yields raw
     * values, which is only correct for a dimension whose values are already words.
     *
     * @param array<string,mixed> $facets
     * @return array<int,array<string,mixed>>
     */
    public static function pivotRows(array $facets, string $key, string $outer = '', string $inner = ''): array
    {
        $node = $facets[$key] ?? null;
        if (!is_array($node) || !is_array($node['buckets'] ?? null)) {
            return [];
        }

        $rows = [];
        foreach ($node['buckets'] as $bucket) {
            if (!is_array($bucket)) {
                continue;
            }
            $cells = [];
            $covered = 0;
            $subBuckets = $bucket['by']['buckets'] ?? null;
            foreach (is_array($subBuckets) ? $subBuckets : [] as $sub) {
                if (!is_array($sub)) {
                    continue;
                }
                $count = (int) ($sub['count'] ?? 0);
                $covered += $count;
                $value = self::scalar($sub['val'] ?? '');
                $cells[] = [
                    'value' => $value,
                    'label' => $inner === '' ? $value : Vocabulary::label($inner, $value),
                    'count' => $count,
                ];
            }
            $value = self::scalar($bucket['val'] ?? '');
            $rows[] = [
                'value'   => $value,
                'label'   => $outer === '' ? $value : Vocabulary::label($outer, $value),
                'count'   => (int) ($bucket['count'] ?? 0),
                'cells'   => $cells,
                'covered' => $covered,
            ];
        }
        return $rows;
    }

    /**
     * The operators a dimension offers, in control order, with the state of each.
     *
     * "All of" is absent — not present-and-disabled — on a single-valued field. There is no
     * sentence to write about a question that cannot be asked, and an explanation of why a
     * greyed control is greyed is exactly the paragraph this component exists to replace.
     *
     * @return array<int,array<string,mixed>>
     */
    public function operators(string $field): array
    {
        $current = $this->op($field);
        $label = $this->labels[$field] ?? $field;

        $out = [];
        foreach (self::OPERATORS as $op) {
            if ($op === self::OP_ALL && $this->arity($field) !== self::ARITY_MULTI) {
                continue;
            }
            $out[] = [
                'op'    => $op,
                'label' => self::operatorLabel($op),
                'hint'  => self::operatorHint($op, $label),
                'on'    => $op === $current,
            ];
        }
        return $out;
    }

    /** The two words the control puts on an operator button. */
    public static function operatorLabel(string $op): string
    {
        return match ($op) {
            self::OP_ALL  => 'All of',
            self::OP_NONE => 'None of',
            default       => 'Any of',
        };
    }

    /**
     * What the operator does, as a sentence about THIS dimension.
     *
     * On the control, as its title and its accessible description, because the semantics
     * belong to the thing being operated and not to a paragraph at the top of the page that
     * a reader has to hold in their head while looking somewhere else.
     */
    public static function operatorHint(string $op, string $label): string
    {
        return match ($op) {
            self::OP_ALL  => 'Match only traffic carrying EVERY selected ' . mb_strtolower($label) . ' value.',
            self::OP_NONE => 'Exclude every selected ' . mb_strtolower($label) . ' value; keep the rest.',
            default       => 'Match traffic carrying ANY selected ' . mb_strtolower($label) . ' value.',
        };
    }

    /**
     * Build the payload groups for a set of dimensions out of a facet response.
     *
     * Each bucket carries a `state`, and three states are needed rather than two: a value
     * can be chosen and included, chosen and EXCLUDED (the "none of" operator), or not
     * chosen. Rendering the middle one as "selected" would show a tick beside a value the
     * operator has just thrown away.
     *
     * `basis` states what the counts in the group MEAN, which changes with exclusion:
     * `excluded` is "what this would match if only this dimension's filter were lifted",
     * `filtered` is "what this matches on the page as filtered". Both are honest; they are
     * not the same number, and only one of them can be true of a label.
     *
     * `overlaps` says the buckets cannot be summed. On a multi-valued dimension one document
     * lands in several buckets — measured against a real node, three buckets of a
     * multi-valued field totalled 398 inside a population of 485 — so a reader adding them
     * up gets a number that means nothing.
     *
     * @param array<string,mixed>  $facets  The `facets` block from Solr.
     * @param array<int,string>    $fields  Dimensions to build, in display order.
     * @return array<int,array<string,mixed>>
     */
    public function groups(array $facets, array $fields, int $limit, array $mono = []): array
    {
        $out = [];
        foreach ($fields as $field) {
            if (!isset($this->labels[$field])) {
                continue;
            }
            $group = $this->group($facets, $field, $limit, in_array($field, $mono, true));
            if ($group !== null) {
                $out[] = $group;
            }
        }
        return $out;
    }

    /**
     * One dimension's payload, or null when nothing in range has a value for it.
     *
     * A selected value that is NOT in the returned buckets is appended with a null count.
     * It happens whenever the chosen value has fallen out of the top N, and dropping it
     * would leave the operator with a filter in force and no control to turn it off.
     *
     * @param array<string,mixed> $facets
     * @return array<string,mixed>|null
     */
    public function group(array $facets, string $field, int $limit, bool $mono = false): ?array
    {
        $chosen = $this->values($field);
        $seen = [];
        $buckets = [];

        $node = $facets[$field] ?? null;
        foreach (is_array($node) && is_array($node['buckets'] ?? null) ? $node['buckets'] : [] as $bucket) {
            if (!is_array($bucket)) {
                continue;
            }
            $value = self::scalar($bucket['val'] ?? '');
            if ($value === '') {
                continue;
            }
            $seen[$value] = true;
            $buckets[] = $this->bucket($field, $value, (int) ($bucket['count'] ?? 0));
        }

        foreach ($chosen as $value) {
            if (!isset($seen[$value])) {
                $buckets[] = $this->bucket($field, $value, null);
            }
        }

        if ($buckets === []) {
            return null;
        }

        $excluded = $this->exclusion === self::EXCLUDE_TAGGED && isset($this->sel[$field]);

        return [
            'field'      => $field,
            'label'      => $this->labels[$field],
            'ns'         => $this->ns,
            'mono'       => $mono,
            'filterable' => true,
            'arity'      => $this->arity($field),
            'op'         => $this->op($field),
            'operators'  => $this->operators($field),
            'chosen'     => $chosen,
            'buckets'    => $buckets,
            'truncated'  => count($seen) >= $limit,
            'distinct'   => is_array($node) && isset($node['numBuckets']) ? (int) $node['numBuckets'] : null,
            'basis'      => $excluded ? 'excluded' : 'filtered',
            'basis_note' => $this->basisNote($field, $excluded),
            'overlaps'   => $this->arity($field) === self::ARITY_MULTI,
            'vocabulary' => Vocabulary::has($field),
        ];
    }

    /**
     * One value of one dimension, as the interface has to render it.
     *
     * `value` is the slug and stays the slug: it is what the filter carries, what the URL
     * carries and what an operator greps for. `label` is what a person reads and is the same
     * slug again when the dimension has no vocabulary, so a caller can render `label`
     * unconditionally and never print a blank. `why` is a sentence where there is one and an
     * empty string otherwise — an invented explanation would be worse than none.
     *
     * A null `count` means the value is selected but did not come back in the facet, so the
     * control can keep offering a way to turn it off without claiming a number for it.
     *
     * @return array<string,mixed>
     */
    private function bucket(string $field, string $value, ?int $count): array
    {
        $spoken = Vocabulary::value($field, $value);

        /* A VALUE THE FILTER MACHINERY WOULD DROP IS SHOWN, AND SAYS SO. It matters from the
           moment a dimension holds text a person typed: `search_terms_ss` can genuinely contain
           `{!` or `_query_`, because somebody searched a site for it, and acceptsValue() refuses
           those — not because they are dangerous here (Query::quote() makes them an inert literal;
           measured against a live node, `field:("{!frange l=0 u=100}")` matches 0 documents and
           an escaped break-out attempt matches 0 too) but because Solr::assertSafeFilter() refuses
           them ANYWHERE in a filter and does it by throwing.

           So the value is real, the count is real, and the filter cannot be built. Rendering it as
           an ordinary link would be a row that silently does nothing when pressed; hiding it would
           be pretending a search term nobody can filter by does not exist. It is drawn as a static
           row with the reason, which is what `filterable: false` already means everywhere else. */
        $state = $this->acceptsValue($field, $value)
            ? $this->stateOf($field, $value)
            : 'unfilterable';

        return [
            'value'    => $value,
            'label'    => $spoken['label'],
            'why'      => $state === 'unfilterable'
                ? 'This value contains query syntax that the filter layer refuses to carry, so it '
                    . 'can be counted but not selected.'
                : $spoken['why'],
            'severity' => $spoken['severity'],
            'count'    => $count,
            'state'    => $state,
        ];
    }

    /**
     * Add the "not reported" row to a dimension whose field is only sometimes written.
     *
     * THE THIRD STATE IS NOT A ROUNDING ERROR. `signed_in_b` is written only when the measured
     * site actually said one or the other, so on most installations every session is in neither
     * bucket. Showing two buckets and letting the reader assume the rest were anonymous is
     * exactly the fabrication an absent field exists to prevent.
     *
     * It is a real, offerable filter rather than a caption, because the "None of" operator can
     * finally express it: everything that is neither true nor false is `-signed_in_b:(true OR
     * false)`. Before there were three operators this could not be said at all, which is why the
     * row used to be rendered as a read-only distribution with an apology attached.
     *
     * Computed as the remainder, and therefore only offered when the arithmetic is sound: a
     * single-valued dimension, a closed vocabulary, and every known value present as a bucket. A
     * remainder over a limited facet or a multi-valued field would be a number that means nothing.
     *
     * @param array<string,mixed> $group
     * @return array<string,mixed>
     */
    public function withAbsentValue(array $group, int $matched): array
    {
        $field = (string) ($group['field'] ?? '');
        $known = Vocabulary::knownValues($field);

        if ($known === [] || $this->arity($field) === self::ARITY_MULTI || !is_array($group['buckets'] ?? null)) {
            return $group;
        }

        $counted = 0;
        $seen = [];
        foreach ($group['buckets'] as $bucket) {
            $seen[(string) ($bucket['value'] ?? '')] = true;
            $counted += (int) ($bucket['count'] ?? 0);
        }
        foreach ($known as $value) {
            if (!isset($seen[$value])) {
                return $group;
            }
        }

        $absent = $matched - $counted;
        if ($absent <= 0) {
            return $group;
        }

        $group['absent'] = [
            'label'  => 'Not reported',
            'count'  => $absent,
            'why'    => 'The measured site never reported this for these sessions, so the field is absent '
                . 'rather than false. Selecting it excludes every value it could have had.',
            'op'     => self::OP_NONE,
            'values' => $known,
            'state'  => $this->op($field) === self::OP_NONE && $this->values($field) === $known ? 'on' : 'off',
        ];
        return $group;
    }

    /**
     * A group with every value of a closed vocabulary present, even the ones with no traffic.
     *
     * For the value browser only. On a small site "show me the sessions with a forged beacon"
     * is a reasonable thing to ask and the honest answer is "none" — but with `mincount: 1` the
     * option is simply missing, which reads as though the question cannot be asked. A value
     * added here carries a count of 0 rather than null, because 0 is a measurement: it was
     * counted over the selected range and there were none.
     *
     * Open vocabularies — a country, a path, an AS organisation — are returned untouched. Their
     * value set IS whatever the traffic held.
     *
     * @param array<string,mixed> $group
     * @return array<string,mixed>
     */
    public function withKnownValues(array $group): array
    {
        $field = (string) ($group['field'] ?? '');
        $known = Vocabulary::knownValues($field);
        if ($known === [] || !is_array($group['buckets'] ?? null)) {
            return $group;
        }

        $seen = [];
        foreach ($group['buckets'] as $bucket) {
            $seen[(string) ($bucket['value'] ?? '')] = true;
        }
        foreach ($known as $value) {
            if (!isset($seen[$value])) {
                $group['buckets'][] = $this->bucket($field, $value, 0);
            }
        }
        $group['complete'] = true;

        return $group;
    }

    /**
     * What one value is doing right now: chosen, chosen-and-excluded, or nothing.
     */
    private function stateOf(string $field, string $value): string
    {
        if (!in_array($value, $this->values($field), true)) {
            return 'off';
        }
        return $this->op($field) === self::OP_NONE ? 'excluded' : 'on';
    }

    /**
     * The sentence that says what this group's counts count.
     *
     * Required by the same rule that puts a population caption under every chart: a number
     * whose label describes a different question than the number answers is a wrong number,
     * and with exclusions in play that is very easy to do by accident.
     */
    private function basisNote(string $field, bool $excluded): string
    {
        $label = mb_strtolower($this->labels[$field] ?? $field);
        $note = $excluded
            ? 'Counts are what each value would match with the ' . $label . ' filter lifted, so a second value can be added.'
            : 'Counts are what each value matches on this page as filtered.';

        if ($this->arity($field) === self::ARITY_MULTI) {
            $note .= ' One session can hold several ' . $label . ' values, so these counts overlap and do not sum to the total.';
        }
        return $note;
    }

    /**
     * The whole filter state, for the bar that says what is in force.
     *
     * @return array<string,mixed>
     */
    public function payload(): array
    {
        $dims = [];
        foreach ($this->sel as $field => $spec) {
            $chosen = [];
            foreach ($spec['values'] as $value) {
                $chosen[] = $this->bucket($field, $value, null);
            }
            $dims[] = [
                'field'     => $field,
                'label'     => $this->labels[$field] ?? $field,
                'ns'        => $this->ns,
                'op'        => $spec['op'],
                'op_label'  => self::operatorLabel($spec['op']),
                'arity'     => $this->arity($field),
                'operators' => $this->operators($field),
                'values'    => $spec['values'],
                'chosen'    => $chosen,
            ];
        }

        return [
            'ns'        => $this->ns,
            'active'    => $this->flat(),
            'dimensions' => $dims,
            'exclusion' => $this->exclusion,
        ];
    }

    /* ---------------------------------------------------------------------------------
     * The URL contract
     * ------------------------------------------------------------------------------ */

    /**
     * The page parameters worth carrying from one filter link to the next.
     *
     * An ALLOWLIST, because these links are built from the query string of whatever request
     * asked for them — and a JSON request carries `api`, plus whatever the action needed
     * (`field`, `value`, `id`, `limit`). Carrying those into an href would produce a link
     * that answers with JSON instead of a page. `start` is dropped on purpose: changing a
     * filter changes the result set, so page 4 of the old one is not a place to land.
     *
     * @param array<string,mixed> $get
     * @return array<string,string>
     */
    private static function pageParams(array $get): array
    {
        $out = [];
        foreach (self::PAGE_PARAMS as $key) {
            $value = $get[$key] ?? null;
            if (is_string($value) && $value !== '' && preg_match('/^[^\x00-\x1F\x7F]{1,200}$/uD', $value) === 1) {
                $out[$key] = $value;
            }
        }
        return $out;
    }

    /**
     * A page URL for a modified selection.
     *
     * The one place a filter link is spelled, so the encoding cannot drift between the
     * sidebar, the value browser, the chips and the operator control. `$view` overrides the
     * request's own `v`, which matters because the dimension lists are fetched from one
     * view's API endpoint on EVERY page: without it, a facet clicked on Networks would
     * navigate to Sessions.
     *
     * @param array<string,array{values:array<int,string>,op:string}> $selection
     */
    public function urlFor(array $selection, ?string $view = null): string
    {
        $params = $this->page;
        if ($view !== null && preg_match('/^[a-z0-9_-]{1,32}$/D', $view) === 1) {
            $params['v'] = $view;
        }

        $pairs = [];
        foreach ($params as $key => $value) {
            $pairs[] = rawurlencode($key) . '=' . rawurlencode($value);
        }
        foreach ($selection as $field => $spec) {
            if (!isset($this->labels[$field])) {
                continue;
            }
            $base = $this->ns . '[' . $field . ']';
            foreach ($spec['values'] as $value) {
                $pairs[] = rawurlencode($base . '[]') . '=' . rawurlencode($value);
            }
            if (($spec['op'] ?? self::OP_ANY) !== self::OP_ANY) {
                $pairs[] = rawurlencode($base . '[op]') . '=' . rawurlencode($spec['op']);
            }
        }

        return '?' . implode('&', $pairs);
    }

    /** The URL with one value added to a dimension, keeping its operator. */
    public function urlAdd(string $field, string $value, ?string $view = null): string
    {
        $sel = $this->sel;
        if (!isset($this->labels[$field]) || !$this->acceptsValue($field, $value)) {
            return $this->urlFor($sel, $view);
        }
        $values = $sel[$field]['values'] ?? [];
        if (!in_array($value, $values, true) && count($values) < self::MAX_VALUES) {
            $values[] = $value;
        }
        $sel[$field] = ['values' => $values, 'op' => $this->op($field)];
        return $this->urlFor($sel, $view);
    }

    /** The URL with one value removed, dropping the dimension when it was the last one. */
    public function urlRemove(string $field, string $value, ?string $view = null): string
    {
        $sel = $this->sel;
        $values = array_values(array_filter(
            $sel[$field]['values'] ?? [],
            static fn (string $v): bool => $v !== $value
        ));
        if ($values === []) {
            unset($sel[$field]);
        } else {
            $sel[$field] = ['values' => $values, 'op' => $this->op($field)];
        }
        return $this->urlFor($sel, $view);
    }

    /** The URL with one value toggled: the gesture that both selects and deselects. */
    public function urlToggle(string $field, string $value, ?string $view = null): string
    {
        return in_array($value, $this->values($field), true)
            ? $this->urlRemove($field, $value, $view)
            : $this->urlAdd($field, $value, $view);
    }

    /**
     * The URL with one dimension's operator changed.
     *
     * Returns the unchanged URL for an operator the dimension does not offer, so a crafted
     * link cannot put a control into a state the UI has no way to leave.
     */
    public function urlOperator(string $field, string $op, ?string $view = null): string
    {
        $sel = $this->sel;
        if (!isset($sel[$field]) || $this->readOp($field, $op) !== $op) {
            return $this->urlFor($sel, $view);
        }
        $sel[$field]['op'] = $op;
        return $this->urlFor($sel, $view);
    }

    /** The URL with one whole dimension cleared. */
    public function urlClearField(string $field, ?string $view = null): string
    {
        $sel = $this->sel;
        unset($sel[$field]);
        return $this->urlFor($sel, $view);
    }

    /** The URL with nothing filtered, in this namespace. */
    public function urlClear(?string $view = null): string
    {
        return $this->urlFor([], $view);
    }

    /** Coerce a Solr bucket value to a string without turning false into ''. */
    private static function scalar($value): string
    {
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        return is_scalar($value) ? (string) $value : '';
    }
}
