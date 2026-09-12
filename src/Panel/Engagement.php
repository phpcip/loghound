<?php
/**
 * Loghound — Analytics: engagement.
 *
 * Bounce rate, defined the way this product can afford to define it, and then the same measure
 * per landing page — which is the form of it somebody can act on, because "31% of people bounce"
 * changes nothing and "68% of the people who land on /pricing bounce" changes a page.
 *
 * The definition, the threshold and the reasoning all live in Panel\Bounce, which is the single
 * source for them; this view owns the scope and the presentation. Every number on this page
 * carries the selected range, the selected virtual host and every active filter, like every other
 * number in the panel.
 *
 * ## Why the per-page table is scoped the way it is
 *
 * A landing page's bounce rate is only a measurement over the visits where a beacon ran, so each
 * row carries BOTH counts: how many human visits landed there, and how many of those could
 * actually be judged on engagement. A row whose measured population is three is a row nobody
 * should draw a conclusion from, and the only way a reader can tell is if the denominator is
 * printed next to the rate.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

final class Engagement extends Controller
{
    /**
     * The cards, in render order, with the short labels the jump bar and the navigation use.
     *
     * @var array<int,array{0:string,1:string}>
     */
    public const SECTIONS = [
        ['an-bounce', 'Bounce rate'],
        ['an-bouncepages', 'By landing page'],
        ['an-people', 'Signed-in visitors'],
    ];

    /** Names listed on the signed-in card. Enough to act on, short enough to read. */
    private const PEOPLE_LIMIT = 50;

    /**
     * Which page-toolbar controls this view honours.
     *
     * Both cards run under settledSessionFqs(), which carries the range, the virtual host and
     * every active filter, and restricts to visits that have finished.
     *
     * @return array<int,string>
     */
    public function toolbar(): array
    {
        return [self::SCOPE_RANGE, self::SCOPE_HOST, self::SCOPE_FACETS, self::SCOPE_CACHE];
    }

    public function slug(): string
    {
        return 'engagement';
    }

    public function title(): string
    {
        return 'Engagement';
    }


    /**
     * @return array<string,array<string,mixed>>
     */
    public function exports(): array
    {
        return [
            'bouncepages' => [
                'label'   => 'Bounce rate by landing page',
                'action'  => 'pages',
                'unit'    => 'landing pages',
                'ranked'  => 'ranked by the number of human visits that started on them',
                'cap'     => Paging::MAX_PAGE,
                'params'  => ['rows' => Paging::MAX_PAGE],
                'total'   => 'page.total',
                'note'    => Bounce::definition() . ' Each row carries the measured population as well as the '
                    . 'human one: a rate over three measurable visits is not a rate, and the denominator is the '
                    . 'only way to tell.',
                'columns' => [
                    ['Landing page', 'path', 'text'],
                    ['Human visits', 'people', 'number'],
                    ['Of those, measurable', 'measured', 'number'],
                    ['Bounced', 'bounced', 'number'],
                    ['One page, but engaged', 'satisfied', 'number'],
                    ['Website', 'host', 'text'],
                    ['Distinct hosts serving this path', 'hosts', 'number'],
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
            'bounce' => $this->bounce(),
            'pages'  => $this->pages(),
            'people' => $this->people(),
            default  => ['error' => 'Unknown action'],
        };
    }

    /**
     * The headline metric.
     *
     * @return array<string,mixed>
     */
    private function bounce(): array
    {
        $f = $this->gw->facet('engagement.bounce', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->settledSessionFqs(),
        ], Bounce::facets());

        return $this->envelope(['bounce' => Bounce::read($f)]);
    }

    /**
     * The same metric per landing page.
     *
     * The facet is over `entry_path_s` and not `paths_ss`: a bounce is a statement about where
     * somebody ARRIVED, and counting it against every path a visit touched would credit a bounce
     * to pages the visitor reached after the one they bounced from, which is nonsense.
     *
     * @return array<string,mixed>
     */
    private function pages(): array
    {
        $start = Paging::start();
        $rows = Paging::rows();

        $f = $this->gw->facet('engagement.pages', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->settledSessionFqs(),
        ], [
            'paths' => Paging::terms('entry_path_s', $start, $rows, 'count desc', [
                'facet' => array_merge(SiteUrl::hostSubFacet(), Bounce::subFacets()),
            ]),
        ]);

        $out = [];
        foreach (self::buckets($f, 'paths') as $bucket) {
            $site = SiteUrl::resolve($bucket);
            $out[] = array_merge(Bounce::readBucket($bucket), [
                'path'  => (string) ($bucket['val'] ?? ''),
                'total' => (int) ($bucket['count'] ?? 0),
                'host'  => $site['host'],
                'hosts' => $site['hosts'],
            ]);
        }

        return $this->envelope([
            'threshold_ms' => Bounce::ENGAGED_MS,
            'definition'   => Bounce::definition(),
            'total'        => (int) ($f['count'] ?? 0),
            'rows'         => $out,
            'page'         => Paging::block(
                $start,
                $rows,
                Paging::distinct($f, 'paths'),
                'landing pages',
                count($out)
            ),
        ]);
    }

    /**
     * The static skeleton.
     */
    /**
     * The signed-in card: one row per person, ordered by how often they came.
     *
     * Emitted after the two bounce cards because it answers a different question — those measure
     * behaviour, this names people — and because it is empty on any installation whose site does
     * not call identify(), which most do not.
     */
    private function peopleCard(): void
    {
        self::cardOpen(
            'an-people',
            Layout::cardNum(self::SECTIONS, 'an-people'),
            'Signed-in visitors',
            'Everyone your site named through the beacon, with what each of them did. '
            . 'Loghound never guesses an identity: these are the ones your own template declared.'
        );
        self::skeleton('an-people', 'rows', 0, 'Counting visits per signed-in visitor');

        echo '<div class="table-wrap"><table id="an-people-table" class="table-fixed"><colgroup>'
            . '<col style="width:32%"><col style="width:11%"><col style="width:11%">'
            . '<col style="width:11%"><col style="width:12%"><col style="width:23%">'
            . '</colgroup><thead><tr>'
            . '<th scope="col">Who</th>'
            . '<th scope="col" class="num">Visits</th>'
            . '<th scope="col" class="num">Pages</th>'
            . '<th scope="col" class="num">Requests</th>'
            . '<th scope="col" class="num">Addresses</th>'
            . '<th scope="col">Last seen</th>'
            . '</tr></thead><tbody></tbody></table></div>';

        self::cardClose('an-people');
    }

    /**
     * The people who signed in, by name, with what each of them did.
     *
     * WHO WAS HERE IS THE FIRST QUESTION ANYBODY ASKS, and until now the panel could not answer
     * it even when the site had said so outright: the identity landed on the session document
     * and was never faceted. This is that facet — one row per name, ordered by how often they
     * came, each row opening the visits behind it like any other dimension value.
     *
     * Sessions with no identity are not a row here. They are not anonymous either, in the sense
     * that matters: the site simply did not say, and inventing an "unknown" bucket out of every
     * visit that never declared one would bury the handful that did.
     *
     * @return array<string,mixed>
     */
    private function people(): array
    {
        $f = $this->gw->facet('engagement.people', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->sessionFqs(),
        ], [
            'named' => ['type' => 'query', 'q' => 'ident_s:*', 'facet' => [
                'people' => [
                    'type'       => 'terms',
                    'field'      => 'ident_s',
                    'limit'      => self::PEOPLE_LIMIT,
                    'sort'       => 'count desc',
                    'numBuckets' => true,
                    'facet'      => [
                        'pages'   => 'sum(pages_i)',
                        'hits'    => 'sum(hits_i)',
                        'engaged' => 'percentile(engaged_ms_l,50)',
                        'last'    => 'max(ts_end)',
                        'uniq_ips' => 'unique(ip_s)',
                    ],
                ],
            ]],
        ]);

        $named = is_array($f['named'] ?? null) ? $f['named'] : [];

        $rows = [];
        foreach (self::buckets($named, 'people') as $bucket) {
            $rows[] = [
                'ident'    => (string) ($bucket['val'] ?? ''),
                'sessions' => (int) ($bucket['count'] ?? 0),
                'pages'    => (int) (self::num($bucket, 'pages') ?? 0),
                'hits'     => (int) (self::num($bucket, 'hits') ?? 0),
                'engaged'  => self::num($bucket, 'engaged'),
                'uniq_ips' => (int) (self::num($bucket, 'uniq_ips') ?? 0),
                'last'     => is_string($bucket['last'] ?? null) ? $bucket['last'] : null,
            ];
        }

        $people = is_array($named['people'] ?? null) ? $named['people'] : [];

        return $this->envelope([
            'people'   => $rows,
            'named'    => (int) ($named['count'] ?? 0),
            'distinct' => isset($people['numBuckets']) ? (int) $people['numBuckets'] : count($rows),
            'total'    => (int) ($f['count'] ?? 0),
            'limit'    => self::PEOPLE_LIMIT,
        ]);
    }

    public function body(): void
    {
        Sessions::bounceCard('an-bounce', Layout::cardNum(self::SECTIONS, 'an-bounce'));

        self::cardOpen(
            'an-bouncepages',
            Layout::cardNum(self::SECTIONS, 'an-bouncepages'),
            'Bounce rate by landing page',
            'The same definition, per landing page. The measurable count is the denominator that matters.',
            $this->exportTool('bouncepages')
        );
        self::skeleton('an-bouncepages', 'rows', 0, 'Measuring engagement per landing page');
        $this->peopleCard();

        echo '<div class="table-wrap"><table id="an-bouncepages-table" class="table-fixed"><colgroup>'
            . '<col style="width:38%"><col style="width:12%"><col style="width:13%">'
            . '<col style="width:12%"><col style="width:25%"></colgroup><thead><tr>'
            . '<th scope="col">Landing page</th>'
            . '<th scope="col" class="num">Human visits</th>'
            . '<th scope="col" class="num">Measurable</th>'
            . '<th scope="col" class="num">Bounce rate</th>'
            . '<th scope="col" class="bar-col">Bounced against engaged</th>'
            . '</tr></thead><tbody></tbody></table></div>';
        echo '<div id="an-bouncepages-pager"></div>';

        self::cardClose('an-bouncepages');
    }
}
