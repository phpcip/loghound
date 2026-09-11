<?php
/**
 * Loghound — bounce rate, defined once, measured honestly.
 *
 * ## Why this is not the number every other tool prints
 *
 * The conventional definition is "a session with exactly one pageview", and it is wrong in both
 * directions at once:
 *
 *  - Somebody who lands on an article, reads it for four minutes and leaves satisfied is counted
 *    as a bounce. It is the single most misleading figure in mainstream analytics: the visit that
 *    worked perfectly is filed under failure.
 *  - A scraper that fetches one page and vanishes is counted identically. On a site whose traffic
 *    is half automation, the conventional bounce rate is mostly a measurement of the automation.
 *
 * Loghound has the two things needed to do better, and neither is available to a log-only tool or
 * to a script that only counts pageviews. It knows **engaged time** — visible, focused, and within
 * thirty seconds of a real scroll, click or keypress — for any session the beacon reported on. And
 * it knows **whether the session was a person at all**, because every session carries a scored
 * verdict.
 *
 * ## The definition
 *
 *  1. **People only.** Bounce rate is a statement about an audience, so the population is human
 *     and likely-human sessions. Bots, declared crawlers and AI crawlers are excluded outright.
 *  2. **Completed visits only.** A session that is still open has a page count that is still
 *     moving, so measuring it measures how long ago the visitor arrived.
 *  3. **One page AND no meaningful engagement is a bounce.** One page and real engaged time is
 *     not a bounce: it is a satisfied single-page visit, which is a different outcome and is
 *     reported beside it rather than folded into it.
 *  4. **What could not be measured is reported separately.** A session with no beacon has no
 *     engaged time at all, so rule 3 cannot be applied to it and it falls back to the page count
 *     alone. Those two groups are never blended into one confident percentage: the payload
 *     carries both denominators and the card prints both.
 *
 * ## The threshold, stated rather than buried
 *
 * ENGAGED_MS is ten seconds, and the reasoning is a property of how the beacon accumulates the
 * clock rather than a round number somebody liked. Engaged time only advances while the tab is
 * visible AND focused AND within thirty seconds of a genuine interaction, so any engaged time at
 * all already implies a deliberate act. Ten seconds of it means that act was followed by sustained
 * attention rather than a bounce off the back button; below it is a glance. The card prints the
 * threshold, because a rate computed against a hidden constant is a rate nobody can check.
 *
 * ## A caveat with a date on it
 *
 * Page counts move when what counts as a page moves. Asset requests — images, stylesheets,
 * scripts — are being taken out of storage, which means a visit whose only "second page" was a
 * logo stops being a two-page visit and becomes a one-page one. That is a correction and the
 * number will get slightly worse-looking when it lands. Nothing here is calibrated against
 * today's page counts, and the threshold above is a property of the beacon clock, not of them.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

final class Bounce
{
    /**
     * Engaged milliseconds at or above which a single-page visit is NOT a bounce.
     *
     * Printed on every card that uses it. See the class docblock for why ten seconds.
     */
    public const ENGAGED_MS = 10000;

    /** Sessions that viewed one page or fewer. */
    public const SINGLE_PAGE = 'pages_i:[* TO 1]';

    /** Sessions that viewed two pages or more. */
    public const MULTI_PAGE = 'pages_i:[2 TO *]';

    /**
     * Sessions the beacon reported on.
     *
     * The positive form is correct here, unlike `provisional_b` and `planes_s`: `beacon_b` is
     * written as true by the sessionizer whenever a beacon arrived, and its absence genuinely
     * means none did.
     */
    public const BEACONED = 'beacon_b:true';

    /** Sessions with no beacon, spelled as a negation so a document predating the field is included. */
    public const NO_BEACON = '-beacon_b:true';

    /** Engaged for at least the threshold. */
    public const ENGAGED = 'engaged_ms_l:[' . self::ENGAGED_MS . ' TO *]';

    /**
     * The sentence that defines the metric, for the card.
     *
     * Here rather than in the view, because the definition and the threshold have to agree and a
     * second copy of either in a view file is how they stop agreeing.
     *
     * ONE SENTENCE, AND EVERY CLAUSE IN IT CHANGES A CONCLUSION: the population is human and
     * completed, the test is engagement rather than page count, and the bar is a stated number.
     * Nothing here explains what engaged time is — the timing card does that once, and the reader
     * of this card runs a search platform.
     */
    public static function definition(): string
    {
        return 'Completed human visits only. A bounce is one page with under '
            . (self::ENGAGED_MS / 1000) . ' seconds of engaged time; one page with more is counted '
            . 'separately as a visit that stayed.';
    }

    /**
     * The facet definitions that compute the whole metric in one request.
     *
     * Nested query facets under one population query, so the denominators cannot drift apart:
     * every count below comes from the same `fq`, the same range and the same filters as the one
     * above it.
     *
     * `conventional` sits OUTSIDE the human population on purpose. It is the figure another tool
     * would print for this traffic — one pageview, no verdict, no engagement — and the whole point
     * of showing it is that it covers a different population from the honest one. Presenting it
     * over the same denominator would hide half of what makes it wrong.
     *
     * @return array<string,mixed>
     */
    public static function facets(): array
    {
        return [
            'bounce_people' => ['type' => 'query', 'q' => Query::POP_HUMAN, 'facet' => [
                'measured' => ['type' => 'query', 'q' => self::BEACONED, 'facet' => [
                    'single'    => ['type' => 'query', 'q' => self::SINGLE_PAGE],
                    'bounced'   => ['type' => 'query', 'q' => self::SINGLE_PAGE . ' AND -' . self::ENGAGED],
                    'satisfied' => ['type' => 'query', 'q' => self::SINGLE_PAGE . ' AND ' . self::ENGAGED],
                    'multi'     => ['type' => 'query', 'q' => self::MULTI_PAGE],
                ]],
                'assumed' => ['type' => 'query', 'q' => self::NO_BEACON, 'facet' => [
                    'single' => ['type' => 'query', 'q' => self::SINGLE_PAGE],
                    'multi'  => ['type' => 'query', 'q' => self::MULTI_PAGE],
                ]],
            ]],
            'bounce_conventional' => ['type' => 'query', 'q' => self::SINGLE_PAGE],
        ];
    }

    /**
     * The nested facets that give ONE bucket — a landing page, a country — its own bounce rate.
     *
     * Deliberately smaller than facets(): inside a terms facet the cost is buckets × sub-facets,
     * so a per-row breakdown asks the three questions a row can act on and leaves the conventional
     * comparison to the headline, where it is asked once.
     *
     * @return array<string,mixed>
     */
    public static function subFacets(): array
    {
        return [
            'people'    => ['type' => 'query', 'q' => Query::POP_HUMAN],
            'bounced'   => ['type' => 'query', 'q' => Query::POP_HUMAN . ' AND ' . self::SINGLE_PAGE
                . ' AND -' . self::ENGAGED],
            'satisfied' => ['type' => 'query', 'q' => Query::POP_HUMAN . ' AND ' . self::SINGLE_PAGE
                . ' AND ' . self::ENGAGED],
            'measured'  => ['type' => 'query', 'q' => Query::POP_HUMAN . ' AND ' . self::BEACONED],
        ];
    }

    /**
     * Read facets() back into the shape the browser renders.
     *
     * Every count is returned alongside the denominator it belongs to, and no rate is computed
     * here: a percentage in a payload is a percentage whose denominator has been thrown away, and
     * this product's standing rule is that a number which does not state what it counts is a lie.
     * The browser divides, and prints both halves.
     *
     * `unclassified` is the honest remainder. A session whose `pages_i` Solr did not return falls
     * into neither the single-page nor the multi-page bucket, so it is counted rather than
     * silently dropped into whichever group would flatter the rate.
     *
     * @param array<string,mixed> $facets The facets block from a query that included facets().
     * @return array<string,mixed>
     */
    public static function read(array $facets): array
    {
        $node = static fn ($n, string $k): array => is_array($n[$k] ?? null) ? $n[$k] : [];
        $count = static fn ($n): int => is_array($n) ? (int) ($n['count'] ?? 0) : 0;

        $people   = $node($facets, 'bounce_people');
        $measured = $node($people, 'measured');
        $assumed  = $node($people, 'assumed');

        $measuredTotal = $count($measured);
        $assumedTotal  = $count($assumed);

        $measuredSingle = $count($node($measured, 'single'));
        $measuredMulti  = $count($node($measured, 'multi'));
        $assumedSingle  = $count($node($assumed, 'single'));
        $assumedMulti   = $count($node($assumed, 'multi'));

        return [
            'threshold_ms' => self::ENGAGED_MS,
            'definition'   => self::definition(),
            'people'       => $count($people),
            'all'          => (int) ($facets['count'] ?? 0),
            'conventional' => $count($node($facets, 'bounce_conventional')),
            'measured'     => [
                'sessions'     => $measuredTotal,
                'bounced'      => $count($node($measured, 'bounced')),
                'satisfied'    => $count($node($measured, 'satisfied')),
                'multi'        => $measuredMulti,
                'unclassified' => max(0, $measuredTotal - $measuredSingle - $measuredMulti),
            ],
            'assumed'      => [
                'sessions'     => $assumedTotal,
                'single'       => $assumedSingle,
                'multi'        => $assumedMulti,
                'unclassified' => max(0, $assumedTotal - $assumedSingle - $assumedMulti),
            ],
        ];
    }

    /**
     * Read subFacets() back off one bucket of a terms facet.
     *
     * @param array<string,mixed> $bucket
     * @return array<string,mixed>
     */
    public static function readBucket(array $bucket): array
    {
        $count = static fn (string $k): int => is_array($bucket[$k] ?? null)
            ? (int) ($bucket[$k]['count'] ?? 0)
            : 0;

        return [
            'people'    => $count('people'),
            'bounced'   => $count('bounced'),
            'satisfied' => $count('satisfied'),
            'measured'  => $count('measured'),
        ];
    }
}
