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
     */
    protected array $filters = [];

    public function __construct(Config $cfg, Gateway $gw)
    {
        $this->cfg   = $cfg;
        $this->gw    = $gw;
        $this->range = Query::range(isset($_GET['range']) && is_string($_GET['range']) ? $_GET['range'] : null);
        $this->filters = self::readFilters();
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

    // -----------------------------------------------------------------------------
    // Request helpers — the only place $_GET is read
    // -----------------------------------------------------------------------------

    /**
     * Read a string parameter, restricted to an allowlist when one is given.
     *
     * @param array<int,string> $allowed
     */
    protected static function param(string $key, array $allowed = [], string $default = ''): string
    {
        $v = $_GET[$key] ?? null;
        if (!is_string($v)) {
            return $default;
        }
        if ($allowed !== [] && !in_array($v, $allowed, true)) {
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
        // Strip control characters; they have no meaning in a search box and only serve
        // to make log output and error messages confusing.
        $v = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $v) ?? '';
        return mb_substr(trim($v), 0, $max);
    }

    /**
     * Read the active facet filters from the query string.
     *
     * Shape: `?f[bot_class_s][]=proxy_fleet&f[country_s][]=DE`. A field that is not in
     * Query::filterFields() is dropped silently — the UI never generates one, so its
     * presence means someone is probing, and there is nothing useful to tell them.
     *
     * @return array<string,array<int,string>>
     */
    private static function readFilters(): array
    {
        $raw = $_GET['f'] ?? null;
        if (!is_array($raw)) {
            return [];
        }
        $allowed = Query::filterFields();
        $out = [];
        foreach ($raw as $field => $values) {
            if (!is_string($field) || !isset($allowed[$field]) || !Security::isSafeFieldName($field)) {
                continue;
            }
            foreach ((array) $values as $v) {
                if (!is_string($v) || $v === '') {
                    continue;
                }
                // Values are quoted+escaped at query time; cap the length here so a
                // multi-megabyte filter value cannot be used to bloat a Solr request.
                $out[$field][] = mb_substr($v, 0, 256);
            }
            if (isset($out[$field])) {
                $out[$field] = array_values(array_unique(array_slice($out[$field], 0, 20)));
            }
        }
        return $out;
    }

    /**
     * Turn the active filters into Solr `fq` clauses.
     *
     * Values within one field are OR-ed (a facet is a multi-select); different fields are
     * separate fq entries, so they AND together and each is independently cacheable in
     * Solr's filter cache.
     *
     * @return array<int,string>
     */
    protected function filterFqs(): array
    {
        $out = [];
        foreach ($this->filters as $field => $values) {
            $parts = [];
            foreach ($values as $v) {
                $parts[] = Query::quote($v);
            }
            $out[] = $field . ':(' . implode(' OR ', $parts) . ')';
        }
        return $out;
    }

    /**
     * The base `fq` list for a sessions-core query: time range plus active filters.
     *
     * @return array<int,string>
     */
    protected function sessionFqs(): array
    {
        return array_merge([Query::rangeFq('ts_start', $this->range)], $this->filterFqs());
    }

    /**
     * The base `fq` list for a hits-core query.
     *
     * @return array<int,string>
     */
    protected function hitFqs(): array
    {
        return [Query::rangeFq('ts', $this->range)];
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

    // -----------------------------------------------------------------------------
    // Shared response fragments
    // -----------------------------------------------------------------------------

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
        ], $extra);
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
     * Render a chart container plus its heading, caption and empty-state slot.
     *
     * Centralised so every chart in the panel is structurally identical: the JS finds the
     * canvas by id, and the empty state is already in the DOM so a view with no data
     * never shows an empty grey box.
     */
    protected static function chart(string $id, string $heading, string $population, string $height = '300px'): void
    {
        $eid = Security::esc($id);
        echo '<section class="card">';
        echo '<h2>' . Security::esc($heading) . '</h2>';
        self::pop($population);
        echo '<div class="chart" id="' . $eid . '" style="height:' . Security::esc($height) . '"></div>';
        echo '<div class="empty" id="' . $eid . '-empty" hidden></div>';
        echo '</section>';
    }
}
