<?php
/**
 * Loghound — Fingerprint clusters.
 *
 * THE view. Everything else in this panel exists in some form in some other tool; this
 * one does not, and it is the README hero image.
 *
 * The idea in one sentence: `fp_hash_s` is a hash of the request headers *excluding the
 * IP address* — User-Agent, Accept, Accept-Language, Accept-Encoding, the Sec-CH-UA set,
 * the Sec-Fetch set, and the protocol version (SPEC §4.1). A real browser on a real
 * machine produces a fingerprint that a handful of IPs share at most (one home, one
 * office, one phone). A scraper running one HTTP client behind a rotating residential or
 * datacentre proxy pool produces one fingerprint shared by *dozens* of unrelated IPs
 * across unrelated ASNs — because the proxy changes the address and nothing else.
 *
 * So the table below sorts by `unique(ip_s)` descending, and the row at the top is the
 * fleet. Expanding it lists the member addresses with their ASN and RIR netname, which is
 * what turns "suspicious" into "here is the netblock, here is who leases it".
 *
 * Query shape: one terms facet on `fp_hash_s` with a nested `unique(ip_s)`, a nested
 * range facet for the sparkline, and nested single-bucket terms facets for the
 * representative UA/ASN. Cost is bucket count × sparkline buckets, which is why both are
 * bounded (Query::SPARK_BUCKETS, and a clamped row limit).
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Security;

final class Fingerprints extends Controller
{
    /** Hard ceiling on cluster rows: each one costs a nested range facet. */
    private const MAX_CLUSTERS = 100;

    /** Hard ceiling on member IPs shown when a cluster is expanded. */
    private const MAX_MEMBERS = 250;

    public function slug(): string
    {
        return 'fingerprints';
    }

    public function title(): string
    {
        return 'Fingerprint clusters';
    }

    public function subtitle(): string
    {
        return 'One header signature across many addresses is a proxy fleet wearing one client.';
    }

    /**
     * @return array<string,mixed>
     */
    public function api(string $action): array
    {
        return match ($action) {
            'clusters' => $this->clusters(),
            'members'  => $this->members(),
            default    => ['error' => 'Unknown action'],
        };
    }

    /**
     * The cluster table.
     *
     * @return array<string,mixed>
     */
    private function clusters(): array
    {
        $limit = Security::clampInt($_GET['limit'] ?? null, 5, self::MAX_CLUSTERS, 40);

        $sortKey = self::param('sort', ['ips', 'sessions', 'hits', 'score', 'recent'], 'ips');
        $sort = [
            'ips'      => 'uniq_ips desc',
            'sessions' => 'count desc',
            'hits'     => 'hits desc',
            'score'    => 'score desc',
            'recent'   => 'last desc',
        ][$sortKey];

        $minIps = Security::clampInt($_GET['min_ips'] ?? null, 1, 500, 1);

        $facet = [
            'clusters' => [
                'type'  => 'terms',
                'field' => 'fp_hash_s',
                'limit' => $limit,
                'sort'  => $sort,
                'facet' => [
                    'uniq_ips'  => 'unique(ip_s)',
                    'uniq_nets' => 'unique(ip_net_s)',
                    'uniq_asns' => 'unique(asn_i)',
                    'hits'      => 'sum(hits_i)',
                    'score'     => 'avg(bot_score_f)',
                    'first'     => 'min(ts_start)',
                    'last'      => 'max(ts_end)',
                    'spark' => [
                        'type'  => 'range',
                        'field' => 'ts_start',
                        'start' => $this->range['start'],
                        'end'   => 'NOW',
                        'gap'   => Query::sparkGap($this->range),
                    ],
                    'ua'      => ['type' => 'terms', 'field' => 'ua_s', 'limit' => 1],
                    'org'     => ['type' => 'terms', 'field' => 'as_org_s', 'limit' => 1],
                    'astype'  => ['type' => 'terms', 'field' => 'as_type_s', 'limit' => 1],
                    'verdict' => ['type' => 'terms', 'field' => 'bot_verdict_s', 'limit' => 1],
                    'class'   => ['type' => 'terms', 'field' => 'bot_class_s', 'limit' => 1],
                    'country' => ['type' => 'terms', 'field' => 'country_s', 'limit' => 1],
                    'beacon'  => ['type' => 'query', 'q' => Query::POP_BEACON],
                    'declared' => ['type' => 'query', 'q' => 'ua_bot_b:true'],
                ],
            ],
            'total_fps' => 'unique(fp_hash_s)',
        ];

        $f = $this->gw->facet('fp.clusters', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->sessionFqs(),
        ], $facet);

        $rows = [];
        foreach (self::buckets($f, 'clusters') as $b) {
            $ips = (int) (self::num($b, 'uniq_ips') ?? 0);
            if ($ips < $minIps) {
                continue;
            }
            $spark = [];
            foreach (self::buckets($b, 'spark') as $sb) {
                $spark[] = (int) ($sb['count'] ?? 0);
            }
            $first = self::firstVal($b, 'ua');
            $rows[] = [
                'fp'        => (string) ($b['val'] ?? ''),
                'sessions'  => (int) ($b['count'] ?? 0),
                'uniq_ips'  => $ips,
                'uniq_nets' => (int) (self::num($b, 'uniq_nets') ?? 0),
                'uniq_asns' => (int) (self::num($b, 'uniq_asns') ?? 0),
                'hits'      => self::num($b, 'hits'),
                'avg_score' => self::num($b, 'score'),
                'first'     => is_string($b['first'] ?? null) ? $b['first'] : null,
                'last'      => is_string($b['last'] ?? null) ? $b['last'] : null,
                'spark'     => $spark,
                'ua'        => $first,
                'org'       => self::firstVal($b, 'org'),
                'as_type'   => self::firstVal($b, 'astype'),
                'verdict'   => self::firstVal($b, 'verdict'),
                'class'     => self::firstVal($b, 'class'),
                'country'   => self::firstVal($b, 'country'),
                'beacon'    => self::qcount($b, 'beacon'),
                'declared'  => self::qcount($b, 'declared') > 0,
                'fleet'     => $ips >= 5
                    && self::firstVal($b, 'astype') !== 'mobile'
                    && self::qcount($b, 'declared') === 0,
            ];
        }

        return $this->envelope([
            'total_sessions' => (int) ($f['count'] ?? 0),
            'total_fps'      => (int) (self::num($f, 'total_fps') ?? 0),
            'sort'           => $sortKey,
            'min_ips'        => $minIps,
            'spark_buckets'  => Query::SPARK_BUCKETS,
            'rows'           => $rows,
        ]);
    }

    /**
     * The member addresses of one cluster.
     *
     * This is still an aggregate — a terms facet on `ip_s`, not a document fetch — so an
     * expanded cluster never ships session documents to the browser.
     *
     * @return array<string,mixed>
     */
    private function members(): array
    {
        $fp = self::text('fp', 64);
        if (!preg_match('/^[a-f0-9]{8,64}$/i', $fp)) {
            return $this->envelope(['rows' => [], 'error' => 'Not a fingerprint hash.']);
        }

        $limit = Security::clampInt($_GET['limit'] ?? null, 5, self::MAX_MEMBERS, 100);

        $f = $this->gw->facet('fp.members', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => array_merge($this->sessionFqs(), [Query::term('fp_hash_s', $fp)]),
        ], [
            'ips' => [
                'type'  => 'terms',
                'field' => 'ip_s',
                'limit' => $limit,
                'sort'  => 'count desc',
                'facet' => [
                    'hits'    => 'sum(hits_i)',
                    'score'   => 'avg(bot_score_f)',
                    'first'   => 'min(ts_start)',
                    'last'    => 'max(ts_end)',
                    'asn'     => ['type' => 'terms', 'field' => 'asn_i', 'limit' => 1],
                    'org'     => ['type' => 'terms', 'field' => 'as_org_s', 'limit' => 1],
                    'astype'  => ['type' => 'terms', 'field' => 'as_type_s', 'limit' => 1],
                    'netname' => ['type' => 'terms', 'field' => 'netname_s', 'limit' => 1],
                    'country' => ['type' => 'terms', 'field' => 'country_s', 'limit' => 1],
                    'city'    => ['type' => 'terms', 'field' => 'city_s', 'limit' => 1],
                    'rdns'    => ['type' => 'terms', 'field' => 'rdns_s', 'limit' => 1],
                    'net'     => ['type' => 'terms', 'field' => 'ip_net_s', 'limit' => 1],
                ],
            ],
            'uniq_asns' => 'unique(asn_i)',
            'uniq_nets' => 'unique(ip_net_s)',
            'uniq_countries' => 'unique(country_s)',
            'ua' => ['type' => 'terms', 'field' => 'ua_s', 'limit' => 1],
        ]);

        $rows = [];
        foreach (self::buckets($f, 'ips') as $b) {
            $rows[] = [
                'ip'       => (string) ($b['val'] ?? ''),
                'net'      => self::firstVal($b, 'net'),
                'sessions' => (int) ($b['count'] ?? 0),
                'hits'     => self::num($b, 'hits'),
                'asn'      => self::firstVal($b, 'asn'),
                'org'      => self::firstVal($b, 'org'),
                'as_type'  => self::firstVal($b, 'astype'),
                'netname'  => self::firstVal($b, 'netname'),
                'country'  => self::firstVal($b, 'country'),
                'city'     => self::firstVal($b, 'city'),
                'rdns'     => self::firstVal($b, 'rdns'),
                'score'    => self::num($b, 'score'),
                'first'    => is_string($b['first'] ?? null) ? $b['first'] : null,
                'last'     => is_string($b['last'] ?? null) ? $b['last'] : null,
            ];
        }

        return $this->envelope([
            'fp'             => $fp,
            'sessions'       => (int) ($f['count'] ?? 0),
            'uniq_asns'      => (int) (self::num($f, 'uniq_asns') ?? 0),
            'uniq_nets'      => (int) (self::num($f, 'uniq_nets') ?? 0),
            'uniq_countries' => (int) (self::num($f, 'uniq_countries') ?? 0),
            'ua'             => self::firstVal($f, 'ua'),
            'truncated'      => count($rows) >= $limit,
            'rows'           => $rows,
        ]);
    }

    /**
     * Read the value of the first bucket of a nested single-bucket terms facet.
     *
     * Returns null rather than an empty string when the facet is absent, so the UI can
     * distinguish "no ASN recorded" from "ASN is blank".
     *
     * @param array<string,mixed> $node
     */
    private static function firstVal(array $node, string $key): ?string
    {
        $buckets = self::buckets($node, $key);
        if ($buckets === []) {
            return null;
        }
        $v = $buckets[0]['val'] ?? null;
        return ($v === null) ? null : (string) $v;
    }

    public function body(): void
    {
        $this->explainCard();
        $this->clustersCard();
    }

    /**
     * What the reader is looking at, and the two honest caveats.
     *
     * Rendered server-side: it is prose, it never changes, and making it wait on a
     * request would be theatre.
     */
    private function explainCard(): void
    {
        self::cardOpen('fp-explain', '01', 'What this table is');
        echo '<div class="explain">';
        echo '<p><code>fp_hash_s</code> is a hash of the request headers <strong>with the IP address deliberately '
            . 'left out</strong>: User-Agent, Accept, Accept-Language, Accept-Encoding, the Sec-CH-UA set, the '
            . 'Sec-Fetch set, and the HTTP version. Two requests share a fingerprint when they were made by the '
            . 'same client software configured the same way — regardless of where they came from.</p>';
        echo '<p>A person browsing produces a fingerprint seen from one, two, maybe three addresses. A scraper '
            . 'behind a rotating proxy pool produces <strong>one fingerprint seen from dozens of unrelated '
            . 'addresses across unrelated networks</strong>, because the proxy swaps the address and nothing else. '
            . 'Sort by distinct IPs and the fleet is the first row.</p>';
        echo '<p class="caveat">Two honest caveats. A large corporate NAT or a mobile carrier gateway can put many '
            . 'real people behind one fingerprint, which is why mobile networks are excluded from the fleet flag. '
            . 'And distinct-IP counts come from Solr&rsquo;s <code>unique()</code>, which is exact for small counts '
            . 'and approximate for large ones.</p>';
        echo '</div>';
        self::cardEnd();
    }

    /**
     * The cluster table and its controls.
     */
    private function clustersCard(): void
    {
        $tools = '<div class="controls">';
        $tools .= '<label for="fp-sort">Sort</label><select id="fp-sort">';
        foreach ([
            'ips'      => 'Distinct IPs',
            'sessions' => 'Sessions',
            'hits'     => 'Requests',
            'score'    => 'Bot score',
            'recent'   => 'Most recent',
        ] as $value => $label) {
            $tools .= '<option value="' . Security::esc($value) . '">' . Security::esc($label) . '</option>';
        }
        $tools .= '</select>';
        $tools .= '<label for="fp-min">Min IPs</label>';
        $tools .= '<input type="number" id="fp-min" min="1" max="500" value="1" inputmode="numeric">';
        $tools .= '</div>';

        self::cardOpen(
            'fp-table',
            '02',
            'Clusters',
            'All sessions in the selected range, grouped by header fingerprint.',
            $tools
        );
        self::skeleton('fp-table', 'rows', 0, 'Building fingerprint clusters');

        echo '<div class="table-wrap"><table id="fp-table-el"><thead><tr>'
            . '<th scope="col" class="w-expand"><span class="sr-only">Expand</span></th>'
            . '<th scope="col">Fingerprint</th>'
            . '<th scope="col" class="num">Distinct IPs</th>'
            . '<th scope="col" class="num">Netblocks</th>'
            . '<th scope="col" class="num">ASNs</th>'
            . '<th scope="col" class="num">Sessions</th>'
            . '<th scope="col">Activity</th>'
            . '<th scope="col">Client</th>'
            . '<th scope="col" class="num">Score</th>'
            . '<th scope="col">Verdict</th>'
            . '</tr></thead><tbody></tbody></table></div>';

        self::cardClose('fp-table');
    }
}
