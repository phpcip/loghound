<?php
/**
 * Loghound — which virtual host a path belongs to.
 *
 * A path on its own is not a URL. `/opensolr-search` is a row in a table and nothing else: it
 * cannot be opened, and on a machine serving six sites it does not even say which of them it
 * came from. The panel links the full URL wherever it shows a path, and this class is the half
 * of that job the server can do honestly.
 *
 * WHY THE SERVER RESOLVES IT AND NOT THE BROWSER. Top pages facets `paths_ss` and slowest paths
 * facets `path_s`; neither bucket carries a host, and the browser cannot go and find one without
 * a request per row. A terms sub-facet on `host_s` nested inside the path facet answers it in the
 * SAME round trip: each bucket comes back knowing whether its path was seen on exactly one
 * virtual host — in which case the row carries that host and the panel can build a URL — or on
 * several, in which case it carries the count and the panel says so instead.
 *
 * THE COUNT IS HONEST, WHICH IS WHY numBuckets IS ASKED FOR. Two returned buckets would only say
 * "at least two". `numBuckets` is the real number of distinct hosts in the domain, so a row can
 * say "4 hosts" rather than a shrug. The domain is the query's, filters included, so filtering
 * the dashboard to one host collapses every ambiguous row to a resolved one — which is exactly
 * what the ambiguity marker in the panel tells the reader to do.
 *
 * NOTHING HERE EVER PICKS A HOST. When a path spans several, the answer is "several"; choosing
 * the most common one would produce a link that goes somewhere real and wrong, and a wrong link
 * that works is worse than no link.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

final class SiteUrl
{
    /**
     * The bucket name the host sub-facet is asked for under.
     *
     * Deliberately not "hosts": Hosts.php already uses that name for the top-level host facet,
     * and two different things under one name in one response is how a reader ends up debugging
     * the wrong number.
     */
    public const SUB_FACET = 'urlhosts';

    /** Hosts fetched per path. Two is enough to know "more than one"; numBuckets supplies how many. */
    private const LIMIT = 2;

    /**
     * The sub-facet to nest inside a path facet, ready to merge into its `facet` block.
     *
     * @return array<string,mixed>
     */
    public static function hostSubFacet(): array
    {
        return [
            self::SUB_FACET => [
                'type'       => 'terms',
                'field'      => Query::HOST_FIELD,
                'limit'      => self::LIMIT,
                'mincount'   => 1,
                'sort'       => 'count desc',
                'numBuckets' => true,
            ],
        ];
    }

    /**
     * Read the sub-facet back off one path bucket.
     *
     * Returns `host` — the single virtual host this path was seen on, or null — and `hosts`, how
     * many it was seen on. Both keys are always present, so a renderer never has to distinguish
     * "the server did not answer" from "the server said no": a response with no sub-facet at all
     * (an older index, a demo world, a Solr that refused the nesting) yields host null and hosts
     * zero, which the panel renders as an explicit "no host logged" marker rather than as a link
     * to somewhere invented.
     *
     * @param array<string,mixed> $bucket One bucket of the path facet.
     * @return array{host: ?string, hosts: int}
     */
    public static function resolve(array $bucket): array
    {
        $node = $bucket[self::SUB_FACET] ?? null;
        if (!is_array($node)) {
            return ['host' => null, 'hosts' => 0];
        }

        $hosts = [];
        foreach ((array) ($node['buckets'] ?? []) as $sub) {
            if (!is_array($sub)) {
                continue;
            }
            $value = isset($sub['val']) && is_scalar($sub['val']) ? (string) $sub['val'] : '';
            if ($value !== '') {
                $hosts[] = $value;
            }
        }

        $distinct = isset($node['numBuckets']) && is_numeric($node['numBuckets'])
            ? (int) $node['numBuckets']
            : count($hosts);

        if ($hosts === []) {
            return ['host' => null, 'hosts' => max(0, $distinct)];
        }
        if (count($hosts) === 1 && $distinct <= 1) {
            return ['host' => $hosts[0], 'hosts' => 1];
        }

        return ['host' => null, 'hosts' => max(count($hosts), $distinct)];
    }
}
