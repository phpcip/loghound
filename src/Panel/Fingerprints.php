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

    /**
     * The pages this view has, in render order.
     *
     * @var array<int,array{0:string,1:string}>
     */
    public const SECTIONS = [
        ['fp-explain', 'About'],
        ['fp-table', 'Clusters'],
    ];
    /** Hard ceiling on cluster rows: each one costs a nested range facet. */
    private const MAX_CLUSTERS = 100;

    /**
     * The words the cluster sort selector shows, keyed by the token clusters() accepts.
     *
     * The export has to NAME the ordering in the file, because which hundred clusters a capped
     * export contains is decided entirely by it — and a stored token is never what this product
     * shows a person (Panel\Vocabulary).
     *
     * @var array<string,string>
     */
    private const SORT_LABELS = [
        'ips'      => 'Most distinct IPs first',
        'sessions' => 'Most sessions first',
        'hits'     => 'Most requests first',
        'score'    => 'Highest bot score first',
        'recent'   => 'Most recently seen first',
    ];

    /**
     * The threshold at which a cluster is marked as a proxy fleet.
     *
     * Five distinct addresses, no mobile carrier, nothing self-declared. Here rather than as a
     * literal inside clusters(), because the number is printed in the legend on the card and a
     * legend that says five while the code tests four is worse than no legend.
     */
    public const FLEET_IPS = 5;

    /**
     * Which page-toolbar controls this view honours.
     *
     * sessionFqs() throughout, and the sparkline is built from the selected range.
     *
     * @return array<int,string>
     */
    public function toolbar(): array
    {
        return [self::SCOPE_RANGE, self::SCOPE_HOST, self::SCOPE_FACETS, self::SCOPE_CACHE];
    }

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
     * The cluster table, as CSV.
     *
     * `total_fps` is a genuine denominator here and is used as one: it is the number of DISTINCT
     * fingerprints in scope, which is the same unit as a row, so the coverage line can say "the
     * 100 widest-spread of 183" rather than falling back to "the set may be larger". Almost no
     * other table in the panel can do that, because their payload totals count sessions.
     *
     * The sort order and the minimum-IP threshold are carried, because they are what decides
     * WHICH hundred clusters this is — an export that quietly reverted to the default ordering
     * would be a different hundred rows under the same filename.
     *
     * The activity sparkline is deliberately not a column: it is twenty-four bucket counts whose
     * bucket width depends on the selected range, and flattened into one cell it would be a
     * number nobody could interpret without the geometry that produced it.
     *
     * @return array<string,array<string,mixed>>
     */
    public function exports(): array
    {
        return [
            'clusters' => [
                'label'   => 'Fingerprint clusters',
                'action'  => 'clusters',
                'unit'    => 'fingerprint clusters',
                'ranked'  => 'in the order the table is sorted',
                'cap'     => self::MAX_CLUSTERS,
                'params'  => ['limit' => self::MAX_CLUSTERS],
                'carry'   => ['sort', 'min_ips'],
                'total'   => 'total_fps',
                'note'    => 'Distinct-IP, netblock and network counts come from Solr\'s unique(), which is '
                    . 'exact for small counts and approximate for large ones. Mobile carrier networks are '
                    . 'excluded from the proxy-fleet flag, because a carrier gateway legitimately puts many '
                    . 'people behind one fingerprint.',
                'scope'   => [
                    'sort'    => ['Sort order', static fn ($v): string =>
                        is_string($v) ? (self::SORT_LABELS[$v] ?? '') : ''],
                    'min_ips' => 'Minimum distinct IPs',
                ],
                'columns' => [
                    ['Fingerprint', 'fp', 'id'],
                    ['Sessions', 'sessions', 'number'],
                    ['Distinct IPs', 'uniq_ips', 'number'],
                    ['Distinct netblocks', 'uniq_nets', 'number'],
                    ['Distinct networks (ASNs)', 'uniq_asns', 'number'],
                    ['Requests', 'hits', 'number'],
                    ['Average bot score', 'avg_score', 'number'],
                    ['First seen', 'first', 'date'],
                    ['Last seen', 'last', 'date'],
                    ['Browser', 'browser', 'text'],
                    ['Browser version', 'browser_ver', 'text'],
                    ['OS', 'os', 'text'],
                    ['Device', 'device', 'text'],
                    ['Declared crawler', 'ua_bot_name', 'text'],
                    ['Declared bot category', 'ua_bot_cat', 'vocab', 'ua_bot_cat_s'],
                    ['AS organisation', 'org', 'text'],
                    ['Network type', 'as_type', 'vocab', 'as_type_s'],
                    ['Network type code', 'as_type', 'id'],
                    ['Country', 'country', 'id'],
                    ['Verdict', 'verdict', 'vocab', 'bot_verdict_s'],
                    ['Verdict code', 'verdict', 'id'],
                    ['Bot class', 'class', 'vocab', 'bot_class_s'],
                    ['Sessions with beacon data', 'beacon', 'number'],
                    ['Declared itself', 'declared', 'bool'],
                    ['Flagged as a proxy fleet', 'fleet', 'bool'],
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
                    'browser' => ['type' => 'terms', 'field' => 'browser_s', 'limit' => 1],
                    'bver'    => ['type' => 'terms', 'field' => 'browser_ver_i', 'limit' => 1],
                    'os'      => ['type' => 'terms', 'field' => 'os_s', 'limit' => 1],
                    'device'  => ['type' => 'terms', 'field' => 'device_s', 'limit' => 1],
                    'botname' => ['type' => 'terms', 'field' => 'ua_bot_name_s', 'limit' => 1],
                    'botcat'  => ['type' => 'terms', 'field' => 'ua_bot_cat_s', 'limit' => 1],
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
                'browser'     => self::firstVal($b, 'browser'),
                'browser_ver' => self::firstVal($b, 'bver'),
                'os'          => self::firstVal($b, 'os'),
                'device'      => self::firstVal($b, 'device'),
                'ua_bot_name' => self::firstVal($b, 'botname'),
                'ua_bot_cat'  => self::firstVal($b, 'botcat'),
                'org'       => self::firstVal($b, 'org'),
                'as_type'   => self::firstVal($b, 'astype'),
                'verdict'   => self::firstVal($b, 'verdict'),
                'class'     => self::firstVal($b, 'class'),
                'country'   => self::firstVal($b, 'country'),
                'beacon'    => self::qcount($b, 'beacon'),
                'declared'  => self::qcount($b, 'declared') > 0,
                'fleet'     => $ips >= self::FLEET_IPS
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
        if (!preg_match('/^[a-f0-9]{8,64}$/iD', $fp)) {
            return $this->envelope(['rows' => [], 'error' => 'Not a fingerprint hash.']);
        }

        $start = Paging::start();
        $limit = Paging::rows();

        $f = $this->gw->facet('fp.members', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => array_merge($this->sessionFqs(), [Query::term('fp_hash_s', $fp)]),
        ], [
            'ips' => Paging::terms('ip_s', $start, $limit, 'count desc', [
                'facet' => [
                    'hits'    => 'sum(hits_i)',
                    'score'   => 'avg(bot_score_f)',
                    'first'   => 'min(ts_start)',
                    'last'    => 'max(ts_end)',
                    'org'     => ['type' => 'terms', 'field' => 'as_org_s', 'limit' => 1],
                    'astype'  => ['type' => 'terms', 'field' => 'as_type_s', 'limit' => 1],
                    'country' => ['type' => 'terms', 'field' => 'country_s', 'limit' => 1],
                    'city'    => ['type' => 'terms', 'field' => 'city_s', 'limit' => 1],
                ],
            ]),
            'uniq_asns' => 'unique(asn_i)',
            'uniq_nets' => 'unique(ip_net_s)',
            'uniq_countries' => 'unique(country_s)',
            'ua' => ['type' => 'terms', 'field' => 'ua_s', 'limit' => 1],
        ]);

        $rows = [];
        foreach (self::buckets($f, 'ips') as $b) {
            $rows[] = [
                'ip'       => (string) ($b['val'] ?? ''),
                'sessions' => (int) ($b['count'] ?? 0),
                'hits'     => self::num($b, 'hits'),
                'org'      => self::firstVal($b, 'org'),
                'as_type'  => self::firstVal($b, 'astype'),
                'country'  => self::firstVal($b, 'country'),
                'city'     => self::firstVal($b, 'city'),
                'score'    => self::num($b, 'score'),
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
            'rows'           => $rows,
            'page'           => Paging::block(
                $start,
                $limit,
                Paging::distinct($f, 'ips'),
                'addresses',
                count($rows)
            ),
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
        echo '<p>A <strong>fingerprint</strong> is a hash of the request headers <strong>with the IP address '
            . 'deliberately left out</strong>: User-Agent, Accept, Accept-Language, Accept-Encoding, the Sec-CH-UA set, the '
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
        $tools .= $this->exportTool('clusters');

        self::cardOpen(
            'fp-table',
            '02',
            'Clusters',
            'All sessions in the selected range, grouped by header fingerprint.',
            $tools
        );
        self::skeleton('fp-table', 'rows', 0, 'Building fingerprint clusters');

        echo '<div class="table-wrap"><table id="fp-table-el" class="table-fixed"><colgroup>'
            . '<col style="width:5%"><col style="width:21%"><col style="width:11%">'
            . '<col style="width:9%"><col style="width:16%"><col style="width:21%">'
            . '<col style="width:17%">'
            . '</colgroup><thead><tr>'
            . '<th scope="col" class="w-expand"><span class="sr-only">Expand</span></th>'
            . '<th scope="col">Signature</th>'
            . '<th scope="col" class="num" title="Distinct addresses, and under it the netblocks '
            . 'and networks they are spread across">IPs</th>'
            . '<th scope="col" class="num">Sess.</th>'
            . '<th scope="col">Activity</th>'
            . '<th scope="col">Client</th>'
            . '<th scope="col">Verdict</th>'
            . '</tr></thead><tbody></tbody></table></div>';

        /* THE ORANGE RULE HAS A MEANING AND NOW IT IS WRITTEN DOWN. Some rows in this table carry
           a vertical accent on their left edge and some do not, and nothing on the page said what
           the difference was — so it read as a border being painted over by a row background
           rather than as a finding. It marks the proxy-fleet pattern, which is the whole point of
           the view, and the legend states the three conditions and the threshold. */
        echo '<p class="legend"><span class="legend-fleet" aria-hidden="true"></span>'
            . '<span>An orange rule marks the <strong>proxy-fleet pattern</strong>: ' . self::FLEET_IPS
            . ' or more distinct addresses on one client signature, no mobile carrier, nothing '
            . 'self-declared. Carriers are excluded because a gateway legitimately puts many people behind '
            . 'one fingerprint.</span></p>';

        self::cardClose('fp-table');
    }
}
