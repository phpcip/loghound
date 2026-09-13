<?php
/**
 * Loghound — SEO Tools: this period against another.
 *
 * Nine pages, one question each, every one of them answered for two windows at once: the period
 * the operator picked (A) and the period it is compared with (B). Panel\Period owns both windows,
 * their calendar, their labels and their buckets; this class only asks Solr.
 *
 * THE POPULATION IS THE FILTER RAIL. There is no humans/bots switch on these pages. Every sessions
 * query carries the filters in force, so "humans only" is the Verdict filter, set once, and every
 * card agrees with every other card about who it is counting.
 *
 * A VISIT HERE IS A VISIT THAT LOADED A PAGE. Sessions made only of robots.txt, favicons or the
 * collector are not traffic anyone optimises for, so every sessions query is bounded to
 * `pages_i >= 1` and every caption says so.
 *
 * WINDOWS ARE ON ARRIVAL. A visit belongs to the period it started in (`ts_start`), which is how
 * "visits yesterday" is read by everyone who reads an analytics report. One request covers both
 * windows and two query sub-facets split it, so A and B can never be scoped differently.
 *
 * TWO PLANES. Traffic comes from the sessions core; crawler activity comes from the hits core,
 * where a verdict does not exist. Filters the hits core cannot answer are reported on the card
 * rather than silently dropped.
 *
 * RANKING BY CHANGE HAPPENS IN PHP. Solr sorts buckets by their count over the whole window, never
 * by the difference between two halves of it, so a bounded candidate set is fetched, ranked here,
 * and paged. Every payload says how many candidates were considered and whether the set was capped.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Security;

final class Seo extends Controller
{
    /**
     * The pages of this view, in navigation order.
     *
     * @var array<int,array{0:string,1:string}>
     */
    public const SECTIONS = [
        ['seo-scorecard', 'Scorecard'],
        ['seo-channels', 'Channels'],
        ['seo-engines', 'Search engines & AI'],
        ['seo-landing', 'Landing pages'],
        ['seo-referrers', 'Referring sites'],
        ['seo-audience', 'Countries & devices'],
        ['seo-quality', 'Engagement by channel'],
        ['seo-crawlers', 'Crawlers'],
        ['seo-crawlgap', 'Crawled, not visited'],
    ];

    /** A visit that loaded at least one page. */
    private const VISITS = 'pages_i:[1 TO *]';

    /** Finished visits the beacon measured, the only population with a real engaged time. */
    private const SETTLED_BEACON = 'beacon_b:true AND -provisional_b:true';

    /** How many values a movers ranking is taken from. */
    private const CANDIDATES = 1000;

    /** How many crawled pages the crawl gap examines. */
    private const GAP_PATHS = 100;

    /** Longest path the crawl gap looks up on the sessions core. */
    private const GAP_PATH_MAX = 400;

    /** Most crawlers listed. */
    private const CRAWLER_LIMIT = 200;

    /**
     * Channel scopes: the label and the `fq` clause, built only from constants.
     *
     * @var array<string,array{0:string,1:string}>
     */
    private const CHANNELS = [
        'all'       => ['Every visit', ''],
        'referred'  => ['Every referred visit', '-referer_type_s:(direct OR internal)'],
        'search'    => ['Search engines', 'referer_type_s:search'],
        'ai'        => ['AI assistants', 'referer_type_s:ai'],
        'search_ai' => ['Search engines and AI assistants', 'referer_type_s:(search OR ai)'],
        'social'    => ['Social networks', 'referer_type_s:social'],
        'link'      => ['Other sites', 'referer_type_s:link'],
        'ad'        => ['Paid ads', 'referer_type_s:ad'],
        'direct'    => ['Direct', 'referer_type_s:direct'],
    ];

    /**
     * The movers pages: which dimensions and which channel scopes each one offers, first is default.
     *
     * @var array<string,array{dims:array<int,string>,chans:array<int,string>}>
     */
    private const PANELS = [
        'engines'   => ['dims' => ['referer_host_s'], 'chans' => ['search_ai', 'search', 'ai']],
        'landing'   => [
            'dims'  => ['entry_path_s'],
            'chans' => ['search', 'search_ai', 'ai', 'social', 'link', 'ad', 'referred', 'direct', 'all'],
        ],
        'referrers' => ['dims' => ['referer_host_s'], 'chans' => ['referred', 'link', 'social', 'search', 'ai', 'ad']],
        'audience'  => [
            'dims'  => ['country_s', 'device_s', 'browser_s', 'os_s', 'region_s', 'city_s'],
            'chans' => ['all', 'search', 'search_ai', 'ai', 'social', 'link', 'ad', 'referred', 'direct'],
        ],
    ];

    /**
     * Dimensions a movers ranking can be taken over: label and plural noun.
     *
     * @var array<string,array{0:string,1:string}>
     */
    private const DIMENSIONS = [
        'entry_path_s'   => ['Landing page', 'landing pages'],
        'referer_host_s' => ['Referring site', 'referring sites'],
        'country_s'      => ['Country', 'countries'],
        'device_s'       => ['Device', 'devices'],
        'browser_s'      => ['Browser', 'browsers'],
        'os_s'           => ['Operating system', 'operating systems'],
        'region_s'       => ['Region', 'regions'],
        'city_s'         => ['City', 'cities'],
    ];

    /**
     * How a movers table is ranked.
     *
     * @var array<string,string>
     */
    private const SORTS = [
        'gain' => 'Biggest gains',
        'loss' => 'Biggest losses',
        'now'  => 'Most visits now',
        'new'  => 'New',
        'gone' => 'Gone',
    ];

    /**
     * Declared crawler categories the crawler page can narrow to.
     *
     * @var array<string,string>
     */
    private const CRAWLER_CATEGORIES = [
        'all'    => 'Every declared crawler',
        'search' => 'Search crawlers',
        'ai'     => 'AI crawlers',
        'seo'    => 'SEO tools',
        'social' => 'Social previews',
        'other'  => 'Other declared bots',
    ];

    /**
     * The crawl gap: which crawler category is matched against which referrer channel.
     *
     * @var array<string,string>
     */
    private const GAP_ENGINES = [
        'search' => 'Search crawlers against visits from search engines',
        'ai'     => 'AI crawlers against visits from AI assistants',
    ];

    /**
     * How the crawl gap is listed.
     *
     * @var array<string,string>
     */
    private const GAP_SORTS = [
        'crawled'   => 'Most crawled',
        'unvisited' => 'Crawled, no visits',
    ];

    /**
     * The scorecard tiles, in order: label, kind, and what the number counts.
     *
     * @var array<string,array{0:string,1:string,2:string}>
     */
    private const METRICS = [
        'visits'          => ['Visits', 'count', 'Visits that loaded at least one page.'],
        'visitors'        => ['Visitors', 'count', 'Distinct visitor identities among those visits.'],
        'pageviews'       => ['Pageviews', 'count', 'Pages loaded by those visits.'],
        'pages_per_visit' => ['Pages per visit', 'ratio', 'Pageviews divided by visits.'],
        'one_page_share'  => ['One-page visits', 'pct', 'Share of visits that loaded exactly one page.'],
        'landings'        => ['Landing pages', 'count', 'Distinct pages visits arrived on.'],
        'search'          => ['From search engines', 'count', 'Visits referred by a search engine, paid clicks excluded.'],
        'ai'              => ['From AI assistants', 'count', 'Visits referred by an AI assistant or chat product.'],
        'social'          => ['From social networks', 'count', 'Visits referred by a social platform.'],
        'link'            => ['From other sites', 'count', 'Visits referred by any other site.'],
        'engaged_p50'     => ['Median engaged time', 'ms', 'Over finished visits the beacon measured.'],
    ];

    /** @var array<string,mixed>|null The resolved comparison, once per request. */
    private ?array $resolved = null;

    /**
     * Build the view, and name the comparison where the base class names the duration.
     *
     * The duration picker does not scope this view, so the range key and label that reach an export's
     * filename and every payload's envelope are the two periods instead of a window nobody chose here.
     */
    public function __construct(\Loghound\Config $cfg, Gateway $gw)
    {
        parent::__construct($cfg, $gw);

        $p = $this->period();
        $this->range['key'] = $p['preset'] . '-vs-' . $p['vs'];
        $this->range['label'] = $p['a_label'] . ' compared with ' . $p['b_label'];
    }

    /**
     * The filter rail scopes every card; Clear cache recomputes them. There is no duration
     * control: the period selector on the page replaces it.
     *
     * @return array<int,string>
     */
    public function toolbar(): array
    {
        return [self::SCOPE_FACETS, self::SCOPE_CACHE];
    }

    /** URL slug. */
    public function slug(): string
    {
        return 'seo';
    }

    /** Title. */
    public function title(): string
    {
        return 'SEO Tools';
    }

    /**
     * The tables that can be taken out as CSV, each through the action its card runs.
     *
     * @return array<string,array<string,mixed>>
     */
    public function exports(): array
    {
        $scope = ['period.a_label' => 'Period', 'period.b_label' => 'Compared with'];
        $note = 'Visits that loaded at least one page, counted in the period they arrived in, under every '
            . 'filter in force.';

        return [
            'channels' => [
                'label'   => 'Channels, period against period',
                'action'  => 'channels',
                'unit'    => 'channels',
                'cap'     => 50,
                'scope'   => $scope,
                'note'    => $note . ' Direct means no referrer arrived.',
                'columns' => [
                    ['Channel', 'label', 'text'],
                    ['Stored value', 'value', 'id'],
                    ['Visits in the period', 'a', 'number'],
                    ['Visits in the comparison period', 'b', 'number'],
                    ['Change', 'delta', 'number'],
                ],
            ],
            'movers' => [
                'label'   => 'Movers, period against period',
                'action'  => 'movers',
                'unit'    => 'values',
                'cap'     => Paging::MAX_PAGE,
                'params'  => ['rows' => Paging::MAX_PAGE],
                'total'   => 'page.total',
                'carry'   => ['panel', 'dim', 'chan', 'sort'],
                'scope'   => $scope + ['dim_label' => 'Dimension', 'chan_label' => 'Channel', 'sort_label' => 'Showing'],
                'note'    => $note,
                'columns' => [
                    ['Value', 'value', 'text'],
                    ['Visits in the period', 'a', 'number'],
                    ['Visits in the comparison period', 'b', 'number'],
                    ['Change', 'delta', 'number'],
                ],
            ],
            'quality' => [
                'label'   => 'Engagement by channel',
                'action'  => 'quality',
                'unit'    => 'channels',
                'cap'     => 50,
                'scope'   => $scope,
                'note'    => $note . ' Engaged time is the median over finished visits the beacon measured; an '
                    . 'empty cell means none were measured.',
                'columns' => [
                    ['Channel', 'label', 'text'],
                    ['Visits in the period', 'a.visits', 'number'],
                    ['Visits in the comparison period', 'b.visits', 'number'],
                    ['Pages per visit in the period', 'a.pages_per_visit', 'number'],
                    ['Pages per visit in the comparison period', 'b.pages_per_visit', 'number'],
                    ['One-page visits in the period (%)', 'a.one_page_share', 'number'],
                    ['One-page visits in the comparison period (%)', 'b.one_page_share', 'number'],
                    ['Median engaged ms in the period', 'a.engaged_p50', 'number'],
                    ['Visits measured in the period', 'a.engaged_n', 'number'],
                    ['Median engaged ms in the comparison period', 'b.engaged_p50', 'number'],
                    ['Visits measured in the comparison period', 'b.engaged_n', 'number'],
                ],
            ],
            'crawlers' => [
                'label'   => 'Crawlers, period against period',
                'action'  => 'crawlers',
                'unit'    => 'crawlers',
                'cap'     => self::CRAWLER_LIMIT,
                'carry'   => ['cat'],
                'scope'   => $scope + ['category_label' => 'Crawlers'],
                'note'    => 'Requests from clients that declared themselves crawlers, from the access log. Forward-confirmed '
                    . 'reverse DNS means the address\'s PTR name resolves back to the same address; it does not by itself '
                    . 'prove the name belongs to the company the crawler claims.',
                'columns' => [
                    ['Crawler', 'name', 'text'],
                    ['Category', 'category', 'id'],
                    ['Requests in the period', 'a.requests', 'number'],
                    ['Requests in the comparison period', 'b.requests', 'number'],
                    ['Pages crawled in the period', 'a.paths', 'number'],
                    ['Pages crawled in the comparison period', 'b.paths', 'number'],
                    ['4xx in the period', 'a.e4', 'number'],
                    ['4xx in the comparison period', 'b.e4', 'number'],
                    ['5xx in the period', 'a.e5', 'number'],
                    ['5xx in the comparison period', 'b.e5', 'number'],
                    ['Forward-confirmed reverse DNS in the period', 'a.verified', 'number'],
                    ['Reverse DNS looked up in the period', 'a.checked', 'number'],
                ],
            ],
            'crawlgap' => [
                'label'   => 'Crawled pages against visits',
                'action'  => 'crawlgap',
                'unit'    => 'pages',
                'cap'     => self::GAP_PATHS,
                'carry'   => ['engine', 'sort'],
                'scope'   => ['period.a_label' => 'Period', 'engine_label' => 'Matching', 'sort_label' => 'Showing'],
                'note'    => 'The pages declared crawlers fetched most with a 2xx answer, against visits that arrived on '
                    . 'the same path from the matching channel. An empty visits cell means the path was not looked up.',
                'columns' => [
                    ['Page', 'path', 'text'],
                    ['Website', 'host', 'text'],
                    ['Crawler requests', 'crawl', 'number'],
                    ['Distinct crawlers', 'crawlers', 'number'],
                    ['Visits from the channel', 'visits', 'number'],
                ],
            ],
        ];
    }

    /**
     * Answer a data action.
     *
     * @return array<string,mixed>
     */
    public function api(string $action): array
    {
        return match ($action) {
            'bounds'         => $this->bounds(),
            'scorecard'      => $this->scorecard(),
            'timeline'       => $this->timeline(),
            'channels'       => $this->channels(),
            'channel_series' => $this->channelSeries(),
            'movers'         => $this->movers(),
            'quality'        => $this->quality(),
            'crawlers'       => $this->crawlers(),
            'crawlgap'       => $this->crawlGap(),
            default          => ['error' => 'Unknown action'],
        };
    }

    /**
     * The comparison this request asks for, resolved once.
     *
     * @return array<string,mixed>
     */
    private function period(): array
    {
        if ($this->resolved === null) {
            $this->resolved = Period::resolve(
                $_GET,
                Period::timezone((string) $this->cfg->get('ui.timezone', 'UTC'))
            );
        }
        return $this->resolved;
    }

    /**
     * The envelope every SEO payload carries, with the two windows named in words.
     *
     * @param array<string,mixed> $extra
     * @return array<string,mixed>
     */
    private function payload(array $extra): array
    {
        $p = $this->period();

        return $this->envelope(array_merge([
            'period' => [
                'preset'  => $p['preset'],
                'vs'      => $p['vs'],
                'a_label' => $p['a_label'],
                'b_label' => $p['b_label'],
                'step'    => $p['step'],
            ],
        ], $extra));
    }

    /**
     * The `fq` list of a sessions query: visits, both windows, any extra clause, every filter.
     *
     * @return array<int,string>
     */
    private function visitFqs(string ...$extra): array
    {
        $p = $this->period();
        $fqs = array_merge(
            [self::FQ_SESSION_DOCS, Query::publicIpsOnly(), self::VISITS, Period::union('ts_start', $p['a'], $p['b'])],
            $extra,
            $this->facets->fqs()
        );

        return array_values(array_filter($fqs, static fn (string $clause): bool => $clause !== ''));
    }

    /**
     * The `fq` list of a hits query: both windows, any extra clause, every filter the hits core can answer.
     *
     * @return array<int,string>
     */
    private function crawlFqs(string ...$extra): array
    {
        $p = $this->period();

        return array_merge(
            [Query::publicIpsOnly(), Period::union('ts', $p['a'], $p['b'])],
            $extra,
            $this->hitFacets->fqs()
        );
    }

    /**
     * Two query sub-facets, `pa` and `pb`, one per window, each carrying the same nested facets.
     *
     * @param array<string,mixed> $sub
     * @return array<string,mixed>
     */
    private function halves(string $field, array $sub = []): array
    {
        $p = $this->period();
        $out = [];
        foreach (['pa' => $p['a'], 'pb' => $p['b']] as $key => $interval) {
            $out[$key] = ['type' => 'query', 'q' => Period::clause($field, $interval)];
            if ($sub !== []) {
                $out[$key]['facet'] = $sub;
            }
        }
        return $out;
    }

    /**
     * A nested facet node, or an empty array when Solr left it out.
     *
     * @param array<string,mixed> $facets
     * @return array<string,mixed>
     */
    private static function node(array $facets, string $key): array
    {
        return is_array($facets[$key] ?? null) ? $facets[$key] : [];
    }

    /**
     * How far back the sessions core goes, for the date pickers.
     *
     * @return array<string,mixed>
     */
    private function bounds(): array
    {
        $f = $this->gw->facet('seo.bounds', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => [self::FQ_SESSION_DOCS, Query::publicIpsOnly()],
        ], [
            'first' => 'min(ts_start)',
        ]);

        $first = $f['first'] ?? null;
        $ts = is_string($first) ? strtotime($first) : false;
        if ($ts === false || $ts <= 0) {
            return $this->payload(['earliest' => null, 'earliest_date' => null]);
        }

        $tz = Period::timezone((string) $this->cfg->get('ui.timezone', 'UTC'));

        return $this->payload([
            'earliest'      => gmdate('Y-m-d\TH:i:s\Z', $ts),
            'earliest_date' => (new \DateTimeImmutable('@' . $ts))->setTimezone($tz)->format('Y-m-d'),
        ]);
    }

    /**
     * The headline numbers for both windows.
     *
     * @return array<string,mixed>
     */
    private function scorecard(): array
    {
        $sub = [
            'visitors'     => 'unique(visitor_s)',
            'with_visitor' => ['type' => 'query', 'q' => 'visitor_s:[* TO *]'],
            'pageviews'    => 'sum(pages_i)',
            'landings'     => 'unique(entry_path_s)',
            'one_page'     => ['type' => 'query', 'q' => 'pages_i:1'],
            'search'       => ['type' => 'query', 'q' => 'referer_type_s:search'],
            'ai'           => ['type' => 'query', 'q' => 'referer_type_s:ai'],
            'social'       => ['type' => 'query', 'q' => 'referer_type_s:social'],
            'link'         => ['type' => 'query', 'q' => 'referer_type_s:link'],
            'engaged'      => ['type' => 'query', 'q' => self::SETTLED_BEACON, 'facet' => [
                'p50' => 'percentile(engaged_ms_l,50)',
            ]],
        ];

        $f = $this->gw->facet('seo.scorecard', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->visitFqs(),
        ], $this->halves('ts_start', $sub));

        $a = self::summary(self::node($f, 'pa'));
        $b = self::summary(self::node($f, 'pb'));

        $metrics = [];
        foreach (self::METRICS as $key => [$label, $kind, $hint]) {
            $metrics[] = [
                'key'   => $key,
                'label' => $label,
                'kind'  => $kind,
                'hint'  => $hint,
                'a'     => $a[$key],
                'b'     => $b[$key],
            ];
        }

        return $this->payload([
            'metrics'   => $metrics,
            'engaged_n' => ['a' => $a['engaged_n'], 'b' => $b['engaged_n']],
        ]);
    }

    /**
     * One window's headline numbers from its facet node. Ratios are null when there is nothing to divide.
     *
     * @param array<string,mixed> $n
     * @return array<string,int|float|null>
     */
    private static function summary(array $n): array
    {
        $visits = (int) ($n['count'] ?? 0);
        $pageviews = (int) round(self::num($n, 'pageviews') ?? 0);
        $engaged = self::node($n, 'engaged');
        $engagedN = (int) ($engaged['count'] ?? 0);
        $identified = self::qcount($n, 'with_visitor');

        return [
            'visits'          => $visits,
            'visitors'        => $visits === 0 ? 0 : ($identified > 0 ? (int) round(self::num($n, 'visitors') ?? 0) : null),
            'pageviews'       => $pageviews,
            'pages_per_visit' => $visits > 0 ? round($pageviews / $visits, 2) : null,
            'one_page_share'  => $visits > 0 ? round(self::qcount($n, 'one_page') / $visits * 100, 1) : null,
            'landings'        => $visits > 0 ? (int) round(self::num($n, 'landings') ?? 0) : 0,
            'search'          => self::qcount($n, 'search'),
            'ai'              => self::qcount($n, 'ai'),
            'social'          => self::qcount($n, 'social'),
            'link'            => self::qcount($n, 'link'),
            'engaged_p50'     => $engagedN > 0 ? self::num($engaged, 'p50') : null,
            'engaged_n'       => $engagedN,
        ];
    }

    /**
     * Visits, pageviews, search and AI visits per bucket, for both windows.
     *
     * @return array<string,mixed>
     */
    private function timeline(): array
    {
        $p = $this->period();
        $sub = [
            'pageviews' => 'sum(pages_i)',
            'search'    => ['type' => 'query', 'q' => 'referer_type_s:search'],
            'ai'        => ['type' => 'query', 'q' => 'referer_type_s:ai'],
        ];

        $facet = [];
        foreach (['a', 'b'] as $half) {
            foreach ($p[$half . '_buckets'] as $i => $bucket) {
                $facet[$half . $i] = ['type' => 'query', 'q' => Period::clause('ts_start', $bucket), 'facet' => $sub];
            }
        }

        $f = $this->gw->facet('seo.timeline', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->visitFqs(),
        ], $facet);

        $out = [];
        foreach (['a', 'b'] as $half) {
            $times = [];
            $series = ['visits' => [], 'pageviews' => [], 'search' => [], 'ai' => []];
            foreach ($p[$half . '_buckets'] as $i => $bucket) {
                $n = self::node($f, $half . $i);
                $times[] = gmdate('Y-m-d\TH:i:s\Z', $bucket['start']);
                $series['visits'][] = (int) ($n['count'] ?? 0);
                $series['pageviews'][] = (int) round(self::num($n, 'pageviews') ?? 0);
                $series['search'][] = self::qcount($n, 'search');
                $series['ai'][] = self::qcount($n, 'ai');
            }
            $out[$half] = ['times' => $times, 'series' => $series];
        }

        return $this->payload(['step' => $p['step'], 'a' => $out['a'], 'b' => $out['b']]);
    }

    /**
     * Visits per referrer channel in both windows, every channel the parser can emit included.
     *
     * @return array<string,mixed>
     */
    private function channels(): array
    {
        $f = $this->gw->facet('seo.channels', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->visitFqs(),
        ], array_merge($this->halves('ts_start'), [
            'types' => [
                'type'     => 'terms',
                'field'    => 'referer_type_s',
                'limit'    => 20,
                'mincount' => 1,
                'sort'     => 'count desc',
                'facet'    => $this->halves('ts_start'),
            ],
        ]));

        $counts = [];
        foreach (self::buckets($f, 'types') as $bucket) {
            $counts[(string) ($bucket['val'] ?? '')] = [self::qcount($bucket, 'pa'), self::qcount($bucket, 'pb')];
        }

        $rows = [];
        foreach (self::channelValues(array_keys($counts)) as $value) {
            [$a, $b] = $counts[$value] ?? [0, 0];
            $rows[] = [
                'value' => $value,
                'label' => Vocabulary::label('referer_type_s', $value),
                'a'     => $a,
                'b'     => $b,
                'delta' => $a - $b,
            ];
        }

        usort($rows, static fn (array $x, array $y): int
            => [$y['a'], $y['b'], $x['label']] <=> [$x['a'], $x['b'], $y['label']]);

        return $this->payload([
            'total_a' => self::qcount($f, 'pa'),
            'total_b' => self::qcount($f, 'pb'),
            'rows'    => $rows,
        ]);
    }

    /**
     * Every referrer channel the vocabulary knows, followed by any value Solr returned that it does not.
     *
     * @param array<int,string|int> $seen
     * @return array<int,string>
     */
    private static function channelValues(array $seen): array
    {
        $values = Vocabulary::knownValues('referer_type_s');
        foreach ($seen as $value) {
            $value = (string) $value;
            if ($value !== '' && !in_array($value, $values, true)) {
                $values[] = $value;
            }
        }
        return $values;
    }

    /**
     * Visits per channel per bucket across period A, one series per channel that had any.
     *
     * @return array<string,mixed>
     */
    private function channelSeries(): array
    {
        $p = $this->period();

        $facet = [];
        foreach ($p['a_buckets'] as $i => $bucket) {
            $facet['a' . $i] = [
                'type'  => 'query',
                'q'     => Period::clause('ts_start', $bucket),
                'facet' => [
                    'types' => ['type' => 'terms', 'field' => 'referer_type_s', 'limit' => 20, 'mincount' => 1],
                ],
            ];
        }

        $f = $this->gw->facet('seo.channel_series', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->visitFqs(),
        ], $facet);

        $times = [];
        $grid = [];
        foreach ($p['a_buckets'] as $i => $bucket) {
            $times[] = gmdate('Y-m-d\TH:i:s\Z', $bucket['start']);
            foreach (self::buckets(self::node($f, 'a' . $i), 'types') as $type) {
                $grid[(string) ($type['val'] ?? '')][$i] = (int) ($type['count'] ?? 0);
            }
        }

        $series = [];
        foreach (self::channelValues(array_keys($grid)) as $value) {
            $data = [];
            foreach (array_keys($times) as $i) {
                $data[] = $grid[$value][$i] ?? 0;
            }
            if (array_sum($data) === 0) {
                continue;
            }
            $series[] = ['value' => $value, 'label' => Vocabulary::label('referer_type_s', $value), 'data' => $data];
        }

        return $this->payload(['step' => $p['step'], 'times' => $times, 'series' => $series]);
    }

    /**
     * What moved between the two windows on one dimension, within one channel.
     *
     * @return array<string,mixed>
     */
    private function movers(): array
    {
        $panel = self::param('panel', array_keys(self::PANELS), 'landing');
        $spec = self::PANELS[$panel];
        $dim = self::param('dim', $spec['dims'], $spec['dims'][0]);
        $chan = self::param('chan', $spec['chans'], $spec['chans'][0]);
        $sort = self::param('sort', array_keys(self::SORTS), 'gain');

        $sub = $this->halves('ts_start');
        if ($dim === 'entry_path_s') {
            $sub = array_merge($sub, SiteUrl::hostSubFacet());
        }
        if ($dim === 'referer_host_s') {
            $sub['kinds'] = ['type' => 'terms', 'field' => 'referer_type_s', 'limit' => 3, 'mincount' => 1];
        }

        $f = $this->gw->facet('seo.movers', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->visitFqs(self::CHANNELS[$chan][1]),
        ], array_merge($this->halves('ts_start'), [
            'values' => [
                'type'       => 'terms',
                'field'      => $dim,
                'limit'      => self::CANDIDATES,
                'mincount'   => 1,
                'sort'       => 'count desc',
                'numBuckets' => true,
                'facet'      => $sub,
            ],
        ]));

        $rows = [];
        foreach (self::buckets($f, 'values') as $bucket) {
            $a = self::qcount($bucket, 'pa');
            $b = self::qcount($bucket, 'pb');
            if ($a === 0 && $b === 0) {
                continue;
            }
            $row = ['value' => (string) ($bucket['val'] ?? ''), 'a' => $a, 'b' => $b, 'delta' => $a - $b];
            if ($dim === 'entry_path_s') {
                $site = SiteUrl::resolve($bucket);
                $row['host'] = $site['host'];
                $row['hosts'] = $site['hosts'];
            }
            if ($dim === 'referer_host_s') {
                $row['kinds'] = array_map(
                    static fn (array $kind): string => (string) ($kind['val'] ?? ''),
                    self::buckets($bucket, 'kinds')
                );
            }
            $rows[] = $row;
        }

        $considered = count($rows);
        $ranked = self::rank($rows, $sort);
        $start = Paging::start();
        $size = Paging::rows();
        $page = array_slice($ranked, $start, $size);
        $distinct = Paging::distinct($f, 'values');

        return $this->payload([
            'panel'      => $panel,
            'dim'        => $dim,
            'dim_label'  => self::DIMENSIONS[$dim][0],
            'chan'       => $chan,
            'chan_label' => self::CHANNELS[$chan][0],
            'sort'       => $sort,
            'sort_label' => self::SORTS[$sort],
            'total_a'    => self::qcount($f, 'pa'),
            'total_b'    => self::qcount($f, 'pb'),
            'considered' => $considered,
            'candidates' => self::CANDIDATES,
            'distinct'   => $distinct,
            'capped'     => $distinct !== null && $distinct > self::CANDIDATES,
            'rows'       => array_values($page),
            'page'       => Paging::block($start, $size, count($ranked), self::DIMENSIONS[$dim][1], count($page)),
        ]);
    }

    /**
     * Keep and order the rows a movers ranking shows. Ties fall back to the value, so a page is stable.
     *
     * @param array<int,array<string,mixed>> $rows
     * @return array<int,array<string,mixed>>
     */
    private static function rank(array $rows, string $sort): array
    {
        $kept = array_values(array_filter($rows, static fn (array $r): bool => match ($sort) {
            'gain'  => $r['delta'] > 0,
            'loss'  => $r['delta'] < 0,
            'new'   => $r['b'] === 0 && $r['a'] > 0,
            'gone'  => $r['a'] === 0 && $r['b'] > 0,
            default => $r['a'] > 0,
        }));

        usort($kept, static fn (array $x, array $y): int => match ($sort) {
            'gain'  => [$y['delta'], $y['a'], $x['value']] <=> [$x['delta'], $x['a'], $y['value']],
            'loss'  => [$x['delta'], $y['b'], $x['value']] <=> [$y['delta'], $x['b'], $y['value']],
            'gone'  => [$y['b'], $x['value']] <=> [$x['b'], $y['value']],
            default => [$y['a'], $y['delta'], $x['value']] <=> [$x['a'], $x['delta'], $y['value']],
        });

        return $kept;
    }

    /**
     * How visits from each channel behaved in both windows.
     *
     * @return array<string,mixed>
     */
    private function quality(): array
    {
        $sub = [
            'pageviews' => 'sum(pages_i)',
            'one_page'  => ['type' => 'query', 'q' => 'pages_i:1'],
            'engaged'   => ['type' => 'query', 'q' => self::SETTLED_BEACON, 'facet' => [
                'p50' => 'percentile(engaged_ms_l,50)',
            ]],
        ];

        $f = $this->gw->facet('seo.quality', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->visitFqs(),
        ], array_merge($this->halves('ts_start', $sub), [
            'types' => [
                'type'     => 'terms',
                'field'    => 'referer_type_s',
                'limit'    => 20,
                'mincount' => 1,
                'facet'    => $this->halves('ts_start', $sub),
            ],
        ]));

        $found = [];
        foreach (self::buckets($f, 'types') as $bucket) {
            $found[(string) ($bucket['val'] ?? '')] = $bucket;
        }

        $rows = [];
        foreach (self::channelValues(array_keys($found)) as $value) {
            $bucket = $found[$value] ?? [];
            $rows[] = [
                'value' => $value,
                'label' => Vocabulary::label('referer_type_s', $value),
                'a'     => self::behaviour(self::node($bucket, 'pa')),
                'b'     => self::behaviour(self::node($bucket, 'pb')),
            ];
        }

        usort($rows, static fn (array $x, array $y): int
            => [$y['a']['visits'], $y['b']['visits'], $x['label']] <=> [$x['a']['visits'], $x['b']['visits'], $y['label']]);

        return $this->payload([
            'overall' => [
                'value' => '',
                'label' => 'Every channel',
                'a'     => self::behaviour(self::node($f, 'pa')),
                'b'     => self::behaviour(self::node($f, 'pb')),
            ],
            'rows' => $rows,
        ]);
    }

    /**
     * One window's behaviour figures from its facet node.
     *
     * @param array<string,mixed> $n
     * @return array<string,int|float|null>
     */
    private static function behaviour(array $n): array
    {
        $visits = (int) ($n['count'] ?? 0);
        $pageviews = (int) round(self::num($n, 'pageviews') ?? 0);
        $engaged = self::node($n, 'engaged');
        $engagedN = (int) ($engaged['count'] ?? 0);

        return [
            'visits'          => $visits,
            'pages_per_visit' => $visits > 0 ? round($pageviews / $visits, 2) : null,
            'one_page_share'  => $visits > 0 ? round(self::qcount($n, 'one_page') / $visits * 100, 1) : null,
            'engaged_p50'     => $engagedN > 0 ? self::num($engaged, 'p50') : null,
            'engaged_n'       => $engagedN,
        ];
    }

    /**
     * Declared crawler activity in both windows, from the hits core.
     *
     * @return array<string,mixed>
     */
    private function crawlers(): array
    {
        $cat = self::param('cat', array_keys(self::CRAWLER_CATEGORIES), 'all');

        $sub = [
            'paths'    => 'unique(path_s)',
            'e4'       => ['type' => 'query', 'q' => 'status_i:[400 TO 499]'],
            'e5'       => ['type' => 'query', 'q' => 'status_i:[500 TO 599]'],
            'checked'  => ['type' => 'query', 'q' => 'rdns_ok_b:(true OR false)'],
            'verified' => ['type' => 'query', 'q' => 'rdns_ok_b:true'],
        ];

        $extra = ['ua_bot_name_s:[* TO *]'];
        if ($cat !== 'all') {
            $extra[] = Query::term('ua_bot_cat_s', $cat);
        }

        $f = $this->gw->facet('seo.hits.crawlers', $this->gw->hitsCore(), [
            'q'  => '*:*',
            'fq' => $this->crawlFqs(...$extra),
        ], array_merge($this->halves('ts'), [
            'bots' => [
                'type'       => 'terms',
                'field'      => 'ua_bot_name_s',
                'limit'      => self::CRAWLER_LIMIT,
                'mincount'   => 1,
                'sort'       => 'count desc',
                'numBuckets' => true,
                'facet'      => array_merge($this->halves('ts', $sub), [
                    'cats' => ['type' => 'terms', 'field' => 'ua_bot_cat_s', 'limit' => 1, 'mincount' => 1],
                ]),
            ],
        ]));

        $rows = [];
        foreach (self::buckets($f, 'bots') as $bucket) {
            $a = self::crawl(self::node($bucket, 'pa'));
            $b = self::crawl(self::node($bucket, 'pb'));
            if ($a['requests'] === 0 && $b['requests'] === 0) {
                continue;
            }
            $cats = self::buckets($bucket, 'cats');
            $rows[] = [
                'name'     => (string) ($bucket['val'] ?? ''),
                'category' => (string) ($cats[0]['val'] ?? ''),
                'a'        => $a,
                'b'        => $b,
            ];
        }

        usort($rows, static fn (array $x, array $y): int
            => [$y['a']['requests'], $y['b']['requests'], $x['name']] <=> [$x['a']['requests'], $x['b']['requests'], $y['name']]);

        $distinct = Paging::distinct($f, 'bots');

        return $this->payload([
            'cat'            => $cat,
            'category_label' => self::CRAWLER_CATEGORIES[$cat],
            'total_a'        => self::qcount($f, 'pa'),
            'total_b'        => self::qcount($f, 'pb'),
            'distinct'       => $distinct,
            'capped'         => $distinct !== null && $distinct > self::CRAWLER_LIMIT,
            'ignored'        => $this->ignoredHitFilters(),
            'rows'           => $rows,
        ]);
    }

    /**
     * One window's crawler figures from its facet node.
     *
     * @param array<string,mixed> $n
     * @return array<string,int>
     */
    private static function crawl(array $n): array
    {
        return [
            'requests' => (int) ($n['count'] ?? 0),
            'paths'    => (int) round(self::num($n, 'paths') ?? 0),
            'e4'       => self::qcount($n, 'e4'),
            'e5'       => self::qcount($n, 'e5'),
            'checked'  => self::qcount($n, 'checked'),
            'verified' => self::qcount($n, 'verified'),
        ];
    }

    /**
     * The pages crawlers fetched most in period A, against the visits the matching channel sent them.
     *
     * @return array<string,mixed>
     */
    private function crawlGap(): array
    {
        $engine = self::param('engine', array_keys(self::GAP_ENGINES), 'search');
        $sort = self::param('sort', array_keys(self::GAP_SORTS), 'crawled');
        $p = $this->period();

        $f = $this->gw->facet('seo.hits.crawlgap', $this->gw->hitsCore(), [
            'q'  => '*:*',
            'fq' => $this->crawlFqs(
                Period::clause('ts', $p['a']),
                Query::term('ua_bot_cat_s', $engine),
                Query::term('kind_s', 'html'),
                'status_i:[200 TO 299]'
            ),
        ], [
            'paths' => [
                'type'     => 'terms',
                'field'    => 'path_s',
                'limit'    => self::GAP_PATHS,
                'mincount' => 1,
                'sort'     => 'count desc',
                'facet'    => array_merge(SiteUrl::hostSubFacet(), ['crawlers' => 'unique(ua_bot_name_s)']),
            ],
        ]);

        $rows = [];
        $asked = [];
        foreach (self::buckets($f, 'paths') as $bucket) {
            $path = (string) ($bucket['val'] ?? '');
            $site = SiteUrl::resolve($bucket);
            $rows[] = [
                'path'     => $path,
                'host'     => $site['host'],
                'hosts'    => $site['hosts'],
                'crawl'    => (int) ($bucket['count'] ?? 0),
                'crawlers' => (int) round(self::num($bucket, 'crawlers') ?? 0),
                'visits'   => null,
            ];
            if ($path !== '' && strlen($path) <= self::GAP_PATH_MAX) {
                $asked[$path] = true;
            }
        }

        if ($asked !== []) {
            $paths = array_map('strval', array_keys($asked));
            $v = $this->gw->facet('seo.crawlgap.visits', $this->gw->sessionsCore(), [
                'q'  => '*:*',
                'fq' => $this->visitFqs(
                    Period::clause('ts_start', $p['a']),
                    Query::term('referer_type_s', $engine),
                    'entry_path_s:(' . implode(' OR ', array_map([Query::class, 'quote'], $paths)) . ')'
                ),
            ], [
                'landed' => ['type' => 'terms', 'field' => 'entry_path_s', 'limit' => count($paths), 'mincount' => 1],
            ]);

            $landed = [];
            foreach (self::buckets($v, 'landed') as $bucket) {
                $landed[(string) ($bucket['val'] ?? '')] = (int) ($bucket['count'] ?? 0);
            }
            foreach ($rows as $i => $row) {
                if (isset($asked[$row['path']])) {
                    $rows[$i]['visits'] = $landed[$row['path']] ?? 0;
                }
            }
        }

        $examined = count($rows);
        $unchecked = count(array_filter($rows, static fn (array $r): bool => $r['visits'] === null));

        if ($sort === 'unvisited') {
            $rows = array_values(array_filter($rows, static fn (array $r): bool => $r['visits'] === 0));
        }
        usort($rows, static fn (array $x, array $y): int => [$y['crawl'], $x['path']] <=> [$x['crawl'], $y['path']]);

        return $this->payload([
            'engine'       => $engine,
            'engine_label' => self::GAP_ENGINES[$engine],
            'sort'         => $sort,
            'sort_label'   => self::GAP_SORTS[$sort],
            'examined'     => $examined,
            'unchecked'    => $unchecked,
            'ignored'      => $this->ignoredHitFilters(),
            'rows'         => $rows,
        ]);
    }

    /**
     * The static skeleton: the period selector, then every card. Layout keeps the one this page is.
     */
    public function body(): void
    {
        $this->periodBar();

        $this->card(
            'seo-scorecard',
            'Period against period',
            'Visits that loaded at least one page, counted in the period they arrived in, under every filter in force.',
            '',
            '',
            '<div class="seo-tiles" id="seo-scorecard-tiles"></div>'
            . '<div class="seo-subhead"><h3>Over time</h3>'
            . self::toggle('seo-metric', 'metric', 'What the chart draws', [
                'visits'    => 'Visits',
                'pageviews' => 'Pageviews',
                'search'    => 'From search',
                'ai'        => 'From AI',
            ], 'visits')
            . '</div>'
            . '<div class="chart" id="seo-timeline" style="height:320px"></div>'
            . '<p class="seo-note" id="seo-timeline-note"></p>',
            'Comparing the two periods'
        );

        $this->card(
            'seo-channels',
            'Channels',
            'What sent each visit, in this period and in the one it is compared with.',
            $this->exportTool('channels'),
            '',
            '<div class="chart" id="seo-channels-bars" style="height:360px"></div>'
            . '<div class="table-wrap"><table id="seo-channels-table" class="seo-table"><thead><tr>'
            . '<th scope="col">Channel</th>'
            . '<th scope="col" class="num">This period</th>'
            . '<th scope="col" class="num">Compared with</th>'
            . '<th scope="col" class="num">Change</th>'
            . '<th scope="col" class="num">% change</th>'
            . '<th scope="col" class="num">Share now</th>'
            . '<th scope="col" class="num">Share before</th>'
            . '</tr></thead><tbody></tbody></table></div>'
            . '<div class="seo-subhead"><h3>Every channel across this period</h3></div>'
            . '<div class="chart" id="seo-channels-lines" style="height:320px"></div>'
            . '<p class="seo-note" id="seo-channels-lines-note" hidden></p>',
            'Comparing channels'
        );

        $this->moversCard(
            'seo-engines',
            'engines',
            'Search engines and AI assistants',
            'Visits referred by a search engine or an AI assistant, by the site that sent them.',
            'Referring site',
            true
        );
        $this->moversCard(
            'seo-landing',
            'landing',
            'Landing pages',
            'The page each visit arrived on, within the channel chosen below.',
            'Landing page',
            false
        );
        $this->moversCard(
            'seo-referrers',
            'referrers',
            'Referring sites',
            'The site that sent each visit, within the channel chosen below.',
            'Referring site',
            true
        );
        $this->moversCard(
            'seo-audience',
            'audience',
            'Countries and devices',
            'Where visits came from and what they used, within the channel chosen below.',
            'Country',
            false
        );

        $this->card(
            'seo-quality',
            'Engagement by channel',
            'How visits from each channel behaved. Median engaged time is over finished visits the beacon measured.',
            $this->exportTool('quality'),
            '',
            '<div class="table-wrap"><table id="seo-quality-table" class="seo-table"><thead><tr>'
            . '<th scope="col">Channel</th>'
            . '<th scope="col" class="num">Visits</th>'
            . '<th scope="col" class="num">Pages per visit</th>'
            . '<th scope="col" class="num">One-page visits</th>'
            . '<th scope="col" class="num">Median engaged time</th>'
            . '</tr></thead><tbody></tbody></table></div>',
            'Measuring each channel'
        );

        $this->card(
            'seo-crawlers',
            'Crawlers',
            'Requests from clients that declared themselves crawlers, from the access log.',
            $this->exportTool('crawlers'),
            self::select('seo-crawlers-cat', 'Crawlers', self::CRAWLER_CATEGORIES, 'all'),
            '<p class="seo-note" id="seo-crawlers-ignored" hidden></p>'
            . '<div class="table-wrap"><table id="seo-crawlers-table" class="seo-table"><thead><tr>'
            . '<th scope="col">Crawler</th>'
            . '<th scope="col">Category</th>'
            . '<th scope="col" class="num">Requests</th>'
            . '<th scope="col" class="num">Pages crawled</th>'
            . '<th scope="col" class="num">4xx answers</th>'
            . '<th scope="col" class="num">5xx answers</th>'
            . '<th scope="col" class="num">Reverse DNS confirmed</th>'
            . '</tr></thead><tbody></tbody></table></div>',
            'Counting crawler requests'
        );

        $this->card(
            'seo-crawlgap',
            'Crawled, not visited',
            'The pages crawlers fetched most in this period, against the visits the matching channel sent to them.',
            $this->exportTool('crawlgap'),
            self::select('seo-crawlgap-engine', 'Matching', self::GAP_ENGINES, 'search')
            . self::toggle('seo-crawlgap-sort', 'sort', 'Which pages', self::GAP_SORTS, 'crawled'),
            '<p class="seo-note" id="seo-crawlgap-ignored" hidden></p>'
            . '<div class="table-wrap"><table id="seo-crawlgap-table" class="table-fixed"><colgroup>'
            . '<col style="width:52%"><col style="width:16%"><col style="width:14%"><col style="width:18%">'
            . '</colgroup><thead><tr>'
            . '<th scope="col">Page</th>'
            . '<th scope="col" class="num">Crawler requests</th>'
            . '<th scope="col" class="num">Crawlers</th>'
            . '<th scope="col" class="num">Visits from the channel</th>'
            . '</tr></thead><tbody></tbody></table></div>',
            'Matching crawled pages against visits'
        );
    }

    /**
     * The period selector every page of this view carries above its card.
     *
     * A GET form, so it works without script; the page's other state travels as hidden fields.
     */
    private function periodBar(): void
    {
        $p = $this->period();
        $section = Controller::sectionSlug($this->sectionFor(is_string($_GET['s'] ?? null) ? $_GET['s'] : null));
        $shown = static fn (bool $on): string => $on ? '' : ' hidden';

        echo '<form class="seo-periods" id="seo-periods" method="get" action="">';
        echo Layout::hiddenFields(['v' => 'seo', 's' => $section], Period::KEYS);
        echo '<div class="seo-period-row">';
        echo self::select('seo-cmp', 'Period', Period::presets(), (string) $p['preset'], 'cmp');
        echo '<span class="seo-dates" id="seo-dates-a"' . $shown($p['preset'] === 'custom') . '>'
            . self::dateField('seo-from', 'from', 'From', (string) $p['from'], (string) $p['today'])
            . self::dateField('seo-to', 'to', 'To', (string) $p['to'], (string) $p['today'])
            . '</span>';
        echo self::select('seo-vs', 'Compared with', Period::comparisons(), (string) $p['vs'], 'vs');
        echo '<span class="seo-dates" id="seo-dates-b"' . $shown($p['vs'] === 'custom') . '>'
            . self::dateField('seo-vs-from', 'vs_from', 'From', (string) $p['vs_from'], (string) $p['today'])
            . self::dateField('seo-vs-to', 'vs_to', 'To', (string) $p['vs_to'], (string) $p['today'])
            . '</span>';
        echo '<button type="submit" class="seo-apply">Apply</button>';
        echo '</div>';
        echo '<p class="seo-period-line">'
            . '<span><strong>This period</strong>' . Security::esc((string) $p['a_label']) . '</span>'
            . '<span><strong>Compared with</strong>' . Security::esc((string) $p['b_label']) . '</span>'
            . '<span class="seo-history" id="seo-history" hidden></span>'
            . '</p>';
        echo '</form>';
    }

    /**
     * One async card: head, optional controls outside the content, skeleton, content.
     */
    private function card(
        string $id,
        string $heading,
        string $caption,
        string $tools,
        string $controls,
        string $content,
        string $loading
    ): void {
        self::cardOpen($id, Layout::cardNum(self::SECTIONS, $id), $heading, $caption, $tools);
        if ($controls !== '') {
            echo '<div class="seo-controls">' . $controls . '</div>';
        }
        self::skeleton($id, 'rows', 0, $loading);
        echo $content;
        self::cardClose($id);
    }

    /**
     * A movers card: its dimension and channel choices, its ranking toggle, and a paged table.
     */
    private function moversCard(
        string $id,
        string $panel,
        string $heading,
        string $caption,
        string $head,
        bool $channel
    ): void {
        $spec = self::PANELS[$panel];

        $controls = '';
        if (count($spec['dims']) > 1) {
            $dims = [];
            foreach ($spec['dims'] as $dim) {
                $dims[$dim] = self::DIMENSIONS[$dim][0];
            }
            $controls .= self::select($id . '-dim', 'Dimension', $dims, $spec['dims'][0]);
        }
        $chans = [];
        foreach ($spec['chans'] as $chan) {
            $chans[$chan] = self::CHANNELS[$chan][0];
        }
        $controls .= self::select($id . '-chan', 'Channel', $chans, $spec['chans'][0]);
        $controls .= self::toggle($id . '-sort', 'sort', 'Which rows', self::SORTS, 'gain');

        $e = Security::esc($id);
        $cols = $channel
            ? '<col style="width:32%"><col style="width:18%"><col style="width:12%"><col style="width:13%">'
                . '<col style="width:12%"><col style="width:13%">'
            : '<col style="width:44%"><col style="width:14%"><col style="width:14%"><col style="width:14%">'
                . '<col style="width:14%">';

        $table = '<div class="table-wrap"><table id="' . $e . '-table" class="table-fixed"><colgroup>' . $cols
            . '</colgroup><thead><tr>'
            . '<th scope="col" id="' . $e . '-head">' . Security::esc($head) . '</th>'
            . ($channel ? '<th scope="col">Channel</th>' : '')
            . '<th scope="col" class="num">This period</th>'
            . '<th scope="col" class="num">Compared with</th>'
            . '<th scope="col" class="num">Change</th>'
            . '<th scope="col" class="num">% change</th>'
            . '</tr></thead><tbody></tbody></table></div>'
            . '<div id="' . $e . '-pager"></div>';

        $this->card($id, $heading, $caption, $this->exportTool('movers'), $controls, $table, 'Ranking what moved');
    }

    /**
     * A labelled select built from constant options.
     *
     * @param array<string,string> $options
     */
    private static function select(string $id, string $label, array $options, string $current, string $name = ''): string
    {
        $out = '<span class="seo-field"><label for="' . Security::esc($id) . '">' . Security::esc($label) . '</label>'
            . '<select id="' . Security::esc($id) . '"'
            . ($name !== '' ? ' name="' . Security::esc($name) . '"' : '')
            . ' data-smart="' . Security::esc($label) . '">';
        foreach ($options as $value => $text) {
            $out .= '<option value="' . Security::esc((string) $value) . '"'
                . ((string) $value === $current ? ' selected' : '') . '>' . Security::esc($text) . '</option>';
        }
        return $out . '</select></span>';
    }

    /**
     * A row of toggle buttons built from constant options.
     *
     * @param array<string,string> $options
     */
    private static function toggle(string $id, string $attr, string $label, array $options, string $current): string
    {
        $out = '<div class="toggle" role="group" id="' . Security::esc($id) . '" aria-label="' . Security::esc($label) . '">';
        foreach ($options as $value => $text) {
            $on = (string) $value === $current;
            $out .= '<button type="button" data-' . Security::esc($attr) . '="' . Security::esc((string) $value) . '"'
                . ($on ? ' class="on" aria-pressed="true"' : ' aria-pressed="false"')
                . '>' . Security::esc($text) . '</button>';
        }
        return $out . '</div>';
    }

    /**
     * A labelled calendar date input that cannot pick a day after today.
     */
    private static function dateField(string $id, string $name, string $label, string $value, string $max): string
    {
        return '<span class="seo-field"><label for="' . Security::esc($id) . '">' . Security::esc($label) . '</label>'
            . '<input type="date" id="' . Security::esc($id) . '" name="' . Security::esc($name) . '"'
            . ' value="' . Security::esc($value) . '" max="' . Security::esc($max) . '"></span>';
    }
}
