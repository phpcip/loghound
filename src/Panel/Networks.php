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
     * @return array<string,mixed>
     */
    public function api(string $action): array
    {
        return match ($action) {
            'summary' => $this->summary(),
            default   => ['error' => 'Unknown action'],
        };
    }

    /**
     * @return array<string,mixed>
     */
    private function summary(): array
    {
        $limit = Security::clampInt($_GET['limit'] ?? null, 10, 200, 60);

        // Sub-facets shared by the ASN, netname and country tables. Each one carries its
        // own human/evasive split so no table can be read as "traffic" without also
        // showing what kind of traffic it was.
        $common = [
            'uniq_ips' => 'unique(ip_s)',
            'hits'     => 'sum(hits_i)',
            'bytes'    => 'sum(bytes_l)',
            'score'    => 'avg(bot_score_f)',
            'human'    => ['type' => 'query', 'q' => Query::POP_HUMAN],
            'evasive'  => ['type' => 'query', 'q' => Query::POP_EVASIVE],
            'declared' => ['type' => 'query', 'q' => Query::POP_DECLARED_ANY],
        ];

        $facet = [
            'asns' => [
                'type'  => 'terms',
                'field' => 'asn_i',
                'limit' => $limit,
                'sort'  => 'count desc',
                'facet' => $common + [
                    'org'    => ['type' => 'terms', 'field' => 'as_org_s', 'limit' => 1],
                    'astype' => ['type' => 'terms', 'field' => 'as_type_s', 'limit' => 1],
                    'country' => ['type' => 'terms', 'field' => 'country_s', 'limit' => 1],
                ],
            ],
            'netnames' => [
                'type'  => 'terms',
                'field' => 'netname_s',
                'limit' => $limit,
                'sort'  => 'count desc',
                'facet' => $common + [
                    'org'    => ['type' => 'terms', 'field' => 'as_org_s', 'limit' => 1],
                    'astype' => ['type' => 'terms', 'field' => 'as_type_s', 'limit' => 1],
                    'asn'    => ['type' => 'terms', 'field' => 'asn_i', 'limit' => 1],
                    'uniq_fps' => 'unique(fp_hash_s)',
                ],
            ],
            'astypes' => [
                'type'  => 'terms',
                'field' => 'as_type_s',
                'limit' => 12,
                'facet' => $common,
            ],
            'countries' => [
                'type'  => 'terms',
                'field' => 'country_s',
                'limit' => 200,
                'sort'  => 'count desc',
                'facet' => $common + [
                    'cities' => ['type' => 'terms', 'field' => 'city_s', 'limit' => 5],
                ],
            ],
            'uniq_asns' => 'unique(asn_i)',
            'uniq_ips'  => 'unique(ip_s)',
        ];

        $f = $this->gw->facet('net.summary', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->sessionFqs(),
        ], $facet);

        return $this->envelope([
            'total'     => (int) ($f['count'] ?? 0),
            'uniq_asns' => (int) (self::num($f, 'uniq_asns') ?? 0),
            'uniq_ips'  => (int) (self::num($f, 'uniq_ips') ?? 0),
            'asns'      => $this->tableRows($f, 'asns', 'asn'),
            'netnames'  => $this->tableRows($f, 'netnames', 'netname'),
            'astypes'   => $this->tableRows($f, 'astypes', 'as_type'),
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
        echo '<section class="card stats" id="net-stats">';
        echo '<h2 class="sr-only">Network totals</h2>';
        foreach ([
            ['sessions',  'Sessions',        'In the selected range'],
            ['uniq_ips',  'Distinct IPs',    'Approximate above ~100 (Solr unique())'],
            ['uniq_asns', 'Distinct ASNs',   'Autonomous systems seen'],
            ['hosting',   'From datacentres','Sessions on hosting or VPN ASNs'],
        ] as [$key, $label, $hint]) {
            echo '<div class="stat"><span class="stat-label">' . Security::esc($label) . '</span>';
            echo '<span class="stat-value mono" data-field="' . Security::esc($key) . '">—</span>';
            echo '<span class="stat-hint">' . Security::esc($hint) . '</span></div>';
        }
        echo '</section>';

        self::chart('net-treemap', 'Autonomous systems', 'All sessions in range. Box area = sessions, colour = network type (as_type_s).', '440px');

        echo '<div class="grid-2">';
        self::chart('net-types', 'Sessions by network type', 'All sessions in range, split by as_type_s and by verdict.', '300px');
        self::chart('net-map', 'Where they answered from', 'All sessions in range, plotted at country centroids — country resolution only, not city.', '300px');
        echo '</div>';

        echo '<section class="card">';
        echo '<h2>Netblocks</h2>';
        self::pop('All sessions in range, grouped by RIR netname. The netname is the level that exposes a leased range inside a large provider — the ASN says "Amazon", the netname says which customer.');
        echo '<div class="table-wrap"><table id="net-netnames"><thead><tr>'
            . '<th scope="col">Netname</th>'
            . '<th scope="col">Organisation</th>'
            . '<th scope="col">Type</th>'
            . '<th scope="col" class="num">Sessions</th>'
            . '<th scope="col" class="num">IPs</th>'
            . '<th scope="col" class="num">Fingerprints</th>'
            . '<th scope="col" class="num">Human</th>'
            . '<th scope="col" class="num">Evasive</th>'
            . '<th scope="col">Mix</th>'
            . '</tr></thead><tbody></tbody></table></div>';
        echo '<div class="empty" id="net-netnames-empty" hidden></div>';
        echo '</section>';

        echo '<section class="card">';
        echo '<h2>Autonomous systems</h2>';
        self::pop('All sessions in range, grouped by asn_i.');
        echo '<div class="table-wrap"><table id="net-asns"><thead><tr>'
            . '<th scope="col">ASN</th>'
            . '<th scope="col">Organisation</th>'
            . '<th scope="col">Type</th>'
            . '<th scope="col" class="num">Sessions</th>'
            . '<th scope="col" class="num">IPs</th>'
            . '<th scope="col" class="num">Requests</th>'
            . '<th scope="col" class="num">Human</th>'
            . '<th scope="col" class="num">Evasive</th>'
            . '<th scope="col">Mix</th>'
            . '</tr></thead><tbody></tbody></table></div>';
        echo '<div class="empty" id="net-asns-empty" hidden></div>';
        echo '</section>';

        echo '<section class="card">';
        echo '<h2>Countries</h2>';
        self::pop('All sessions in range, grouped by country_s from IP geolocation. Geolocation of a datacentre IP tells you where the machine is, not where its operator is.');
        echo '<div class="table-wrap"><table id="net-countries"><thead><tr>'
            . '<th scope="col">Country</th>'
            . '<th scope="col" class="num">Sessions</th>'
            . '<th scope="col" class="num">IPs</th>'
            . '<th scope="col" class="num">Human</th>'
            . '<th scope="col" class="num">Evasive</th>'
            . '<th scope="col">Top cities</th>'
            . '</tr></thead><tbody></tbody></table></div>';
        echo '<div class="empty" id="net-countries-empty" hidden></div>';
        echo '</section>';
    }
}
