<?php
/**
 * Loghound — Networks.
 *
 * Where the traffic physically came from, at three levels of resolution:
 *
 *  - **ASN** — the autonomous system. Sized by session count, coloured by `as_type_s`,
 *    because "10,000 sessions from a hosting ASN" and "10,000 sessions from a consumer
 *    ISP" are opposite findings and a single-colour treemap hides that.
 *  - **Netname** — the RIR netname of the specific netblock. This is the level that
 *    catches a leased range: the ASN says "Amazon", the netname says which customer.
 *  - **Country** — a coarse map, drawn from `country_s`.
 *
 * A note on the map: SPEC §4.1 defines `geo_p` as an indexed `location` field with no
 * docValues, which means it can be searched but not faceted or returned. The map is
 * therefore built from `country_s` counts plotted at country centroids that ship with
 * the panel — no basemap download, no CDN, works air-gapped. It is labelled as
 * country-level so nobody reads a dot as a street address. See docs/PANEL.md for the
 * schema change that would make this city-accurate.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Security;

final class Networks extends Controller
{

    /**
     * The pages this view has, in render order.
     *
     * @var array<int,array{0:string,1:string}>
     */
    public const SECTIONS = [
        ['net-stats', 'Totals'],
        ['net-asns', 'Autonomous systems'],
        ['net-types', 'Network types'],
        ['net-map', 'Where they answered from'],
        ['net-netnames', 'Netblocks'],
        ['net-countries', 'Countries'],
        ['net-pivot', 'Type by verdict'],
    ];
    /**
     * Which page-toolbar controls this view honours.
     *
     * All five queries run under sessionFqs().
     *
     * @return array<int,string>
     */
    public function toolbar(): array
    {
        return [self::SCOPE_RANGE, self::SCOPE_HOST, self::SCOPE_FACETS, self::SCOPE_CACHE];
    }

    public function slug(): string
    {
        return 'networks';
    }

    public function title(): string
    {
        return 'Networks';
    }

    public function subtitle(): string
    {
        return 'Autonomous systems, leased netblocks, and where in the world they answer from.';
    }

    /**
     * The three tables on this view, plus the cross-tab.
     *
     * Every one of them carries its own human/declared/evasive mix, which is the whole reason
     * these tables exist: a row of a hundred sessions from consumer broadband and a row of a
     * hundred from a datacentre look identical until the mix is beside them, and a CSV that
     * dropped those three columns would lose the finding and keep the number.
     *
     * The network-type donut and the world map are not here. Both are drawn from `types` and
     * `geo`, and both of those datasets ARE exportable — the type breakdown through the
     * cross-tab below, the country breakdown through the countries table — so adding a control
     * to a chart would offer the same rows a second time under a different name.
     *
     * No `total` path is declared on any of them. Each payload's `total` counts SESSIONS while a
     * row is a network, a netblock or a country, so using it as a denominator would print a
     * coverage line that is arithmetic nonsense; the export falls back to stating its own limit.
     *
     * @return array<string,array<string,mixed>>
     */
    public function exports(): array
    {
        $mix = [
            ['Sessions', 'sessions', 'number'],
            ['Distinct IPs', 'uniq_ips', 'number'],
            ['Requests', 'hits', 'number'],
            ['Bytes', 'bytes', 'number'],
            ['Average bot score', 'score', 'number'],
            ['Human sessions', 'human', 'number'],
            ['Declared crawler sessions', 'declared', 'number'],
            ['Evasive bot sessions', 'evasive', 'number'],
        ];

        $caveat = 'Distinct-IP counts come from Solr\'s unique(), which is exact for small counts and '
            . 'approximate for large ones. The three population columns are counted separately and do '
            . 'not have to sum to the session total: Unknown sessions are in neither.';

        return [
            'asns' => [
                'label'   => 'Autonomous systems',
                'action'  => 'asns',
                'key'     => 'asns',
                'unit'    => 'autonomous systems',
                'ranked'  => 'ranked by session count',
                'cap'     => 200,
                'params'  => ['limit' => 200],
                'note'    => $caveat,
                'columns' => array_merge([
                    ['Network', 'org', 'text'],
                    ['ASN', 'asn', 'id'],
                    ['Network type', 'as_type', 'vocab', 'as_type_s'],
                    ['Network type code', 'as_type', 'id'],
                    ['Country', 'country', 'id'],
                ], $mix),
            ],

            'netnames' => [
                'label'   => 'Netblocks',
                'action'  => 'netnames',
                'key'     => 'netnames',
                'unit'    => 'netblocks',
                'ranked'  => 'ranked by session count',
                'cap'     => 200,
                'params'  => ['limit' => 200],
                'note'    => $caveat,
                'columns' => array_merge([
                    ['Netblock', 'netname', 'id'],
                    ['Network', 'org', 'text'],
                    ['ASN', 'asn', 'id'],
                    ['Network type', 'as_type', 'vocab', 'as_type_s'],
                ], $mix, [
                    ['Distinct fingerprints', 'uniq_fps', 'number'],
                ]),
            ],

            'countries' => [
                'label'   => 'Countries',
                'action'  => 'geo',
                'key'     => 'countries',
                'unit'    => 'countries',
                'ranked'  => 'ranked by session count',
                'cap'     => 250,
                'note'    => $caveat . ' Geolocating a datacentre address says where the machine is, not '
                    . 'where its operator is. The cities column is the five busiest per country, not all '
                    . 'of them.',
                'columns' => array_merge([
                    ['Country', 'country', 'id'],
                ], $mix, [
                    ['Busiest cities', 'cities', 'pairs', 'city'],
                ]),
            ],

            'pivot' => [
                'label'  => 'Network type by verdict',
                'action' => 'totals',
                'shape'  => 'pivot',
                'key'    => 'pivot',
                'unit'   => 'network type and verdict pairs',
                'cap'    => 200,
                'note'   => 'One record per pair. The verdict breakdown of a network type is a LIMITED '
                    . 'facet, so its rows do not add up to that type\'s session total.',
            ],
        ];
    }

    /**
     * @return array<string,mixed>
     */
    public function api(string $action): array
    {
        return match ($action) {
            'totals'   => $this->totals(),
            'asns'     => $this->asns(),
            'types'    => $this->types(),
            'netnames' => $this->netnames(),
            'geo'      => $this->geo(),
            default    => ['error' => 'Unknown action'],
        };
    }

    /**
     * The sub-facets every network table carries.
     *
     * Each row shows its own human/declared/evasive split, because a row of 100 human
     * sessions and a row of 100 scraper sessions look identical until the mix is shown.
     *
     * @return array<string,mixed>
     */
    private static function commonFacets(): array
    {
        return [
            'uniq_ips' => 'unique(ip_s)',
            'hits'     => 'sum(hits_i)',
            'bytes'    => 'sum(bytes_l)',
            'score'    => 'avg(bot_score_f)',
            'human'    => ['type' => 'query', 'q' => Query::POP_HUMAN],
            'evasive'  => ['type' => 'query', 'q' => Query::POP_EVASIVE],
            'declared' => ['type' => 'query', 'q' => Query::POP_DECLARED_ANY],
        ];
    }

    /**
     * Headline counters, plus the datacentre share derived from the same facet so the
     * two numbers on screen cannot disagree.
     *
     * @return array<string,mixed>
     */
    private function totals(): array
    {
        $f = $this->gw->facet('net.totals', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->sessionFqs(),
        ], array_merge([
            'uniq_asns' => 'unique(asn_i)',
            'uniq_ips'  => 'unique(ip_s)',
            'hosting'   => ['type' => 'query', 'q' => 'as_type_s:(hosting OR vpn)'],
        ], $this->pivotDef(8, 5)));

        return $this->envelope([
            'total'     => (int) ($f['count'] ?? 0),
            'uniq_asns' => (int) (self::num($f, 'uniq_asns') ?? 0),
            'uniq_ips'  => (int) (self::num($f, 'uniq_ips') ?? 0),
            'hosting'   => self::qcount($f, 'hosting'),

            /* Network type crossed with verdict, on this request. It is the question behind
               "should I rate-limit this address space": a type carrying mostly people and a type
               carrying mostly automation look identical in two separate facets. */
            'pivot'     => $this->pivotRows($f),
        ]);
    }

    /**
     * Autonomous systems, feeding both the treemap and the table beneath it.
     *
     * @return array<string,mixed>
     */
    private function asns(): array
    {
        $f = $this->gw->facet('net.asns', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->sessionFqs(),
        ], [
            'asns' => [
                'type'  => 'terms',
                'field' => 'asn_i',
                'limit' => Security::clampInt($_GET['limit'] ?? null, 10, 200, 60),
                'sort'  => 'count desc',
                'facet' => self::commonFacets() + [
                    'org'     => ['type' => 'terms', 'field' => 'as_org_s', 'limit' => 1],
                    'astype'  => ['type' => 'terms', 'field' => 'as_type_s', 'limit' => 1],
                    'country' => ['type' => 'terms', 'field' => 'country_s', 'limit' => 1],
                ],
            ],
        ]);

        return $this->envelope([
            'total' => (int) ($f['count'] ?? 0),
            'asns'  => $this->tableRows($f, 'asns', 'asn'),
        ]);
    }

    /**
     * Network-type breakdown, for the donut.
     *
     * @return array<string,mixed>
     */
    private function types(): array
    {
        $f = $this->gw->facet('net.types', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->sessionFqs(),
        ], [
            'astypes' => ['type' => 'terms', 'field' => 'as_type_s', 'limit' => 12, 'facet' => self::commonFacets()],
        ]);

        return $this->envelope([
            'total'   => (int) ($f['count'] ?? 0),
            'astypes' => $this->tableRows($f, 'astypes', 'as_type'),
        ]);
    }

    /**
     * RIR netnames — the level that exposes a leased range inside a large provider.
     *
     * @return array<string,mixed>
     */
    private function netnames(): array
    {
        $f = $this->gw->facet('net.netnames', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->sessionFqs(),
        ], [
            'netnames' => [
                'type'  => 'terms',
                'field' => 'netname_s',
                'limit' => Security::clampInt($_GET['limit'] ?? null, 10, 200, 60),
                'sort'  => 'count desc',
                'facet' => self::commonFacets() + [
                    'org'      => ['type' => 'terms', 'field' => 'as_org_s', 'limit' => 1],
                    'astype'   => ['type' => 'terms', 'field' => 'as_type_s', 'limit' => 1],
                    'asn'      => ['type' => 'terms', 'field' => 'asn_i', 'limit' => 1],
                    'uniq_fps' => 'unique(fp_hash_s)',
                ],
            ],
        ]);

        return $this->envelope([
            'total'    => (int) ($f['count'] ?? 0),
            'netnames' => $this->tableRows($f, 'netnames', 'netname'),
        ]);
    }

    /**
     * Country counts, feeding the map and the table beneath it.
     *
     * @return array<string,mixed>
     */
    private function geo(): array
    {
        $f = $this->gw->facet('net.geo', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->sessionFqs(),
        ], [
            'countries' => [
                'type'  => 'terms',
                'field' => 'country_s',
                'limit' => 200,
                'sort'  => 'count desc',
                'facet' => self::commonFacets() + [
                    'cities' => ['type' => 'terms', 'field' => 'city_s', 'limit' => 5],
                ],
            ],
        ]);

        return $this->envelope([
            'total'     => (int) ($f['count'] ?? 0),
            'countries' => $this->tableRows($f, 'countries', 'country'),
        ]);
    }

    /**
     * Flatten a terms facet into table rows, pulling the shared sub-facets out.
     *
     * @param array<string,mixed> $facets
     * @return array<int,array<string,mixed>>
     */
    private function tableRows(array $facets, string $key, string $valueKey): array
    {
        $out = [];
        foreach (self::buckets($facets, $key) as $b) {
            $row = [
                $valueKey  => (string) ($b['val'] ?? ''),
                'sessions' => (int) ($b['count'] ?? 0),
                'uniq_ips' => (int) (self::num($b, 'uniq_ips') ?? 0),
                'hits'     => self::num($b, 'hits'),
                'bytes'    => self::num($b, 'bytes'),
                'score'    => self::num($b, 'score'),
                'human'    => self::qcount($b, 'human'),
                'evasive'  => self::qcount($b, 'evasive'),
                'declared' => self::qcount($b, 'declared'),
            ];
            foreach (['org', 'astype', 'country', 'asn'] as $sub) {
                $bs = self::buckets($b, $sub);
                if ($bs !== []) {
                    $row[$sub === 'astype' ? 'as_type' : $sub] = (string) ($bs[0]['val'] ?? '');
                }
            }
            if (isset($b['uniq_fps'])) {
                $row['uniq_fps'] = (int) (self::num($b, 'uniq_fps') ?? 0);
            }
            $cities = self::buckets($b, 'cities');
            if ($cities !== []) {
                $row['cities'] = array_map(
                    static fn (array $c): array => ['city' => (string) ($c['val'] ?? ''), 'count' => (int) ($c['count'] ?? 0)],
                    $cities
                );
            }
            $out[] = $row;
        }
        return $out;
    }

    public function body(): void
    {
        $this->totalsCard();
        $this->asnsCard();

        echo '<div class="grid-2">';
        self::chart(
            'net-types',
            '03',
            'Sessions by network type',
            'All sessions in range, grouped by the kind of network they came from.',
            300,
            'Faceting network types'
        );
        self::chart(
            'net-map',
            '04',
            'Where they answered from',
            'All sessions in range, plotted at country centroids — country resolution only, not city.',
            300,
            'Geolocating sessions'
        );
        echo '</div>';

        $this->netnamesCard();
        $this->countriesCard();
        $this->pivotCard('net-pivot', '07');
    }

    /** Headline network counters. */
    private function totalsCard(): void
    {
        self::cardOpen('net-stats', '01', 'Network totals', 'All sessions in the selected range.');
        self::skeleton('net-stats', 'stats', 0, 'Counting distinct addresses and networks');

        echo '<div class="stats">';
        foreach ([
            ['sessions',  'Sessions',         'In the selected range'],
            ['uniq_ips',  'Distinct IPs',     'Approximate above ~100 (Solr unique())'],
            ['uniq_asns', 'Distinct ASNs',    'Autonomous systems seen'],
            ['hosting',   'From datacentres', 'Sessions on hosting or VPN networks'],
        ] as [$key, $label, $hint]) {
            echo '<div class="stat"><span class="stat-label">' . Security::esc($label) . '</span>';
            echo '<span class="stat-value mono" data-field="' . Security::esc($key) . '">—</span>';
            echo '<span class="stat-hint">' . Security::esc($hint) . '</span></div>';
        }
        echo '</div>';

        self::cardClose('net-stats');
    }

    /** ASN treemap and table, from one request. */
    private function asnsCard(): void
    {
        self::cardOpen(
            'net-asns',
            '02',
            'Autonomous systems',
            'All sessions in range. Box area is sessions, colour is network type — a large hosting box and a large '
            . 'consumer-ISP box are opposite findings.',
            $this->exportTool('asns')
        );
        self::skeleton('net-asns', 'chart', 420, 'Faceting autonomous systems');

        echo '<div id="net-asns-legend" class="controls"></div>';
        echo '<div class="chart" id="net-treemap" style="height:420px"></div>';
        echo '<div class="table-wrap"><table id="net-asns-table" class="table-fixed"><colgroup>'
            . '<col style="width:34%"><col style="width:12%"><col style="width:11%">'
            . '<col style="width:12%"><col style="width:31%">'
            . '</colgroup><thead><tr>'
            . '<th scope="col">Network</th>'
            . '<th scope="col" class="num">Sessions</th>'
            . '<th scope="col" class="num">IPs</th>'
            . '<th scope="col" class="num">Requests</th>'
            . '<th scope="col">Mix</th>'
            . '</tr></thead><tbody></tbody></table></div>';

        self::cardClose('net-asns');
    }

    /** Netblock table. */
    private function netnamesCard(): void
    {
        self::cardOpen(
            'net-netnames',
            '05',
            'Netblocks',
            'All sessions in range, grouped by RIR netname. The netname is the level that exposes a leased range: '
            . 'the ASN says "Amazon", the netname says which customer.',
            $this->exportTool('netnames')
        );
        self::skeleton('net-netnames', 'rows', 0, 'Faceting netblocks');

        echo '<div class="table-wrap"><table id="net-netnames-table" class="table-fixed"><colgroup>'
            . '<col style="width:34%"><col style="width:12%"><col style="width:11%">'
            . '<col style="width:12%"><col style="width:31%">'
            . '</colgroup><thead><tr>'
            . '<th scope="col">Netblock</th>'
            . '<th scope="col" class="num">Sessions</th>'
            . '<th scope="col" class="num">IPs</th>'
            . '<th scope="col" class="num">Prints</th>'
            . '<th scope="col">Mix</th>'
            . '</tr></thead><tbody></tbody></table></div>';

        self::cardClose('net-netnames');
    }

    /** Country table, sharing the geo request with the map. */
    private function countriesCard(): void
    {
        self::cardOpen(
            'net-countries',
            '06',
            'Countries',
            'All sessions in range, grouped by the country the IP geolocates to. Geolocating a datacentre address '
            . 'tells you where the machine is, not where its operator is.',
            $this->exportTool('countries')
        );
        self::skeleton('net-countries', 'rows', 0, 'Faceting countries');

        echo '<div class="table-wrap"><table id="net-countries-table" class="table-fixed"><colgroup>'
            . '<col style="width:24%"><col style="width:12%"><col style="width:10%">'
            . '<col style="width:11%"><col style="width:11%"><col style="width:32%">'
            . '</colgroup><thead><tr>'
            . '<th scope="col">Country</th>'
            . '<th scope="col" class="num">Sessions</th>'
            . '<th scope="col" class="num">IPs</th>'
            . '<th scope="col" class="num">Human</th>'
            . '<th scope="col" class="num">Evasive</th>'
            . '<th scope="col">Top cities</th>'
            . '</tr></thead><tbody></tbody></table></div>';

        self::cardClose('net-countries');
    }
}
