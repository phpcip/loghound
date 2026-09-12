<?php
/**
 * Loghound — one page size, one offset reader, one shape for a paged payload.
 *
 * Every table in the panel shows twenty rows and offers the rest. That is a product rule
 * rather than a per-card preference, so the number lives here and each card reads it instead
 * of choosing its own; a card that quietly showed twelve and said "the most recent 12 of
 * 1,890" is the defect this class exists to make impossible.
 *
 * Two kinds of table are paged, and both go through here:
 *
 *  - a DOCUMENT list — sessions, requests — paged with Solr's `start`/`rows`, whose
 *    `numFound` is an exact total;
 *  - a TERMS FACET — paths, terms, netblocks — paged with the JSON Facet API's `offset`,
 *    whose `numBuckets` is the exact number of distinct values in the domain.
 *
 * Both produce the same `page` block in the response, so the browser has one renderer and
 * no card can invent a second way of saying how much it is showing.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Security;

final class Paging
{
    /** Rows per page, everywhere in the product. */
    public const PAGE = 20;

    /**
     * The largest page a caller may ask for.
     *
     * Higher than PAGE so an export or a wide screen can ask for more, and never above
     * Security::MAX_ROWS so a URL cannot turn one card into a full-index read.
     */
    public const MAX_PAGE = 500;

    /**
     * The page sizes the control below every table offers.
     *
     * A fixed ladder rather than a free number box: the sizes are what the pager renders as
     * options, and a reader who wants a size that is not on it can still put `rows` in the URL
     * and get it, clamped to MAX_PAGE. Every entry must be <= MAX_PAGE or the control would
     * offer a size the server then silently refuses, which is the one outcome a size selector
     * must never produce.
     *
     * @var array<int,int>
     */
    public const SIZES = [20, 50, 100, 300, 500];

    /**
     * The offset a request asked for, clamped.
     *
     * @param string $key Query parameter holding the offset, so two cards on one page can
     *                    each have their own without colliding.
     */
    public static function start(string $key = 'start'): int
    {
        return Security::clampInt($_GET[$key] ?? null, 0, Security::MAX_START, 0);
    }

    /** The page size a request asked for, clamped to something a card can render. */
    public static function rows(string $key = 'rows', int $default = self::PAGE): int
    {
        return Security::clampInt($_GET[$key] ?? null, 1, self::MAX_PAGE, $default);
    }

    /**
     * A terms facet definition that can be paged.
     *
     * `numBuckets` is what makes the page count honest: without it the browser can only say
     * "there may be more", and the pager cannot offer a last page at all.
     *
     * @param array<string,mixed> $extra Nested facets and any further terms options.
     * @return array<string,mixed>
     */
    public static function terms(
        string $field,
        int $start,
        int $rows,
        string $sort = 'count desc',
        array $extra = []
    ): array {
        return array_merge([
            'type'       => 'terms',
            'field'      => $field,
            'limit'      => $rows,
            'offset'     => $start,
            'mincount'   => 1,
            'sort'       => $sort,
            'numBuckets' => true,
        ], $extra);
    }

    /**
     * The exact number of distinct values behind a terms facet, or null when Solr did not say.
     *
     * Null rather than a guess: a pager that invents a last page sends the reader to an empty
     * one, which is worse than a pager that admits it does not know how many there are.
     *
     * @param array<string,mixed> $facets The facets block.
     */
    public static function distinct(array $facets, string $key): ?int
    {
        $node = $facets[$key] ?? null;
        if (!is_array($node) || !isset($node['numBuckets']) || !is_numeric($node['numBuckets'])) {
            return null;
        }
        return max(0, (int) $node['numBuckets']);
    }

    /**
     * The block every paged payload carries, in the one shape assets/js/pager.js renders.
     *
     * `unit` is a PLURAL NOUN naming what is being counted — "visits", "pages", "search
     * terms" — because the pager prints "1–20 of 1,890 visits" and a pager that says only
     * "1–20 of 1,890" leaves the reader to guess what the denominator counts.
     *
     * `sizes` is the ladder the page-size control offers. It is sent with every paged payload
     * rather than written into the browser, so a card with a lower ceiling of its own can send
     * a shorter ladder and the control cannot offer a size the server would refuse.
     *
     * @param array<int,int>|null $sizes Page sizes to offer, or null for the product-wide ladder.
     * @return array<string,mixed>
     */
    public static function block(
        int $start,
        int $rows,
        ?int $total,
        string $unit,
        int $shown,
        ?array $sizes = null
    ): array {
        return [
            'start' => $start,
            'rows'  => $rows,
            'total' => $total,
            'unit'  => $unit,
            'shown' => $shown,
            'sizes' => $sizes ?? self::SIZES,
        ];
    }

    /**
     * The ladder trimmed to a card that cannot serve the whole of it.
     *
     * A card with its own ceiling — the answered-requests table reads documents and caps itself
     * far below MAX_PAGE — must not offer sizes above that cap, or the reader picks 500, the
     * server clamps to 200, and the control silently disagrees with the table beneath it.
     *
     * @return array<int,int>
     */
    public static function sizesUpTo(int $cap): array
    {
        $sizes = array_values(array_filter(self::SIZES, static fn(int $s): bool => $s <= $cap));

        return $sizes === [] ? [$cap] : $sizes;
    }
}
