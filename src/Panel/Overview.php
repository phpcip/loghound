<?php
/**
 * Loghound — Overview.
 *
 * Answers two questions and refuses to blur them together. Who was here: humans, evasive
 * automation and declared crawlers are three different populations drawn as three
 * different bands, never as one "visitors" line. And how long they actually stayed: four
 * numbers side by side with the reason they differ written next to them. That second one
 * is the product's headline claim (SPEC §0) and the most misreadable thing in the panel,
 * so all four are computed over ONE population, the population is named on the card, and
 * the figure a log-only tool would have reported sits beside them for contrast.
 *
 * Every card here fetches its own data. The four sections are four independent requests,
 * so the timing block appears as soon as it is ready rather than waiting for the hourly
 * series, and a failure in one leaves the other three working.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Security;
use Loghound\Setup\Steps;

final class Overview extends Controller
{

    /**
     * The pages this view has, in render order.
     *
     * Drives the sub-items under Overview in the left navigation, the URL that names each page,
     * and every card's number. The labels are written for a navigation column — short, and
     * distinct from each other rather than from the headings, which stay as they are on the
     * cards themselves.
     *
     * @var array<int,array{0:string,1:string}>
     */
    public const SECTIONS = [
        ['ov-stats', 'Who was here'],
        ['ov-timing', 'How long they stayed'],
        ['ov-series', 'Over time'],
        ['ov-pages', 'Top pages'],
        ['ov-searches', 'Searches'],
        ['ov-pivot', 'Country by verdict'],
    ];
    /**
     * Which page-toolbar controls this view honours.
     *
     * Every card runs under sessionFqs(), which carries the range, the host and every facet —
     * except Top pages, which counts requests and therefore runs under hitFqs(). That one
     * honours the same range, the same host and every facet the HITS core can answer, and
     * reports the ones it cannot through `ignored`, exactly as the hits-plane views do.
     *
     * @return array<int,string>
     */
    public function toolbar(): array
    {
        return [self::SCOPE_RANGE, self::SCOPE_HOST, self::SCOPE_FACETS, self::SCOPE_CACHE];
    }

    public function slug(): string
    {
        return 'overview';
    }

    public function title(): string
    {
        return 'Overview';
    }

    public function subtitle(): string
    {
        return 'Who reached the site, and how long they were actually there.';
    }

    /**
     * The three tables on this view worth taking out as CSV.
     *
     * The headline counters are not among them, and neither is the hourly series: four numbers
     * and a chart are not a dataset, and a two-cell CSV is furniture. What is here is the two
     * top-N tables and the cross-tab, all three of which are the shape somebody continues
     * working on elsewhere.
     *
     * `pop` is carried on the pages export because the population toggle is the one control on
     * this view that does not live in the URL, and an export that silently reverted to "humans
     * only" while the table on screen showed bots would be a file that contradicts the page it
     * came from.
     *
     * @return array<string,array<string,mixed>>
     */
    public function exports(): array
    {
        return [
            'pages' => [
                'label'   => 'Top pages',
                'action'  => 'toppages',
                'unit'    => 'paths',
                'ranked'  => 'ranked by the number of requests made to them',
                'cap'     => 50,
                'params'  => ['limit' => 50],
                'carry'   => ['pop'],
                'note'    => 'Counted in REQUESTS, from the hits index, with the distinct sessions that '
                    . 'made them beside each row. Sub-resources — images, stylesheets, scripts, fonts — are '
                    . 'not stored at all unless ingest.index_assets is on, and Loghound\'s own collector, '
                    . 'favicons and robots.txt are excluded here because nobody visited those. A verdict is '
                    . 'a conclusion about a whole SESSION and does not exist on the request plane, so this '
                    . 'file cannot be scoped to humans; the Sessions export can.',
                'scope'   => ['population_label' => 'Counting'],
                'columns' => [
                    ['Path', 'path', 'text'],
                    ['Requests', 'requests', 'number'],
                    ['Sessions', 'sessions', 'number'],
                    ['Virtual host', 'host', 'text'],
                    ['Distinct hosts serving this path', 'hosts', 'number'],
                ],
            ],

            'searches' => [
                'label'   => 'Search terms',
                'action'  => 'searches',
                'unit'    => 'search terms',
                'ranked'  => 'ranked by the number of sessions that searched for them',
                'cap'     => 50,
                'params'  => ['limit' => 50],
                'scope'   => ['searched' => 'Sessions that ran a search'],
                'columns' => [
                    ['Search term', 'term', 'text'],
                    ['Sessions', 'sessions', 'number'],
                ],
            ],

            'pivot' => [
                'label'  => 'Country by verdict',
                'action' => 'totals',
                'shape'  => 'pivot',
                'key'    => 'pivot',
                'unit'   => 'country and verdict pairs',
                'cap'    => 400,
                'note'   => 'One record per pair. The verdict breakdown of a country is a LIMITED facet, '
                    . 'so its rows do not add up to that country\'s session total — the covered column is '
                    . 'how much of the total the listed verdicts account for.',
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
            'timing'   => $this->timing(),
            'series'   => $this->series(),
            'toppages' => $this->topPages(),
            'searches' => $this->searches(),
            default    => ['error' => 'Unknown action'],
        };
    }

    /**
     * Session counts for each of the five mutually exclusive populations.
     *
     * @return array<string,mixed>
     */
    private function totals(): array
    {
        $facet = [];
        foreach (Query::populations() as $key => $filter) {
            $facet[$key] = ['type' => 'query', 'q' => $filter];
        }
        $facet['human']['facet'] = [
            'visitors'  => 'unique(visitor_s)',
            'pageviews' => 'sum(pages_i)',
            'hits'      => 'sum(hits_i)',
            'bytes'     => 'sum(bytes_l)',
        ];

        $f = $this->gw->facet('overview.totals', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->sessionFqs(),
        ], array_merge($facet, $this->pivotDef(10, 5)));

        $totals = [];
        foreach (array_keys(Query::populations()) as $key) {
            $totals[$key] = self::qcount($f, $key);
        }
        $human = is_array($f['human'] ?? null) ? $f['human'] : [];

        return $this->envelope([
            'pending'        => $this->pendingExplanation((int) ($f['count'] ?? 0)),
            'total_sessions' => (int) ($f['count'] ?? 0),
            'totals'         => $totals,
            'labels'         => Query::populationLabels(),
            'human_detail'   => [
                'visitors'  => self::num($human, 'visitors'),
                'pageviews' => self::num($human, 'pageviews'),
                'hits'      => self::num($human, 'hits'),
                'bytes'     => self::num($human, 'bytes'),
            ],

            /* The cross-tab rides on THIS request rather than one of its own: same `fq`, one more
               nested facet, no extra round trip. Which pairing it is comes from Query::pivots(),
               keyed by view slug, so the choice is declared in one table. */
            'pivot'          => $this->pivotRows($f),
        ]);
    }

    /**
     * The four timing numbers, each over the population it can honestly describe.
     *
     * COMPLETED SESSIONS ONLY, for all of them. An open session's log span is the gap between
     * its first hit and its most recent one, so averaging it in measures how long ago the
     * visitor arrived rather than how long they stayed — which is precisely the lie this card
     * exists to expose. Counting a live session is honest; measuring one is not.
     *
     * ------------------------------------------------------------------------------------
     * THREE DENOMINATORS, NOT ONE, AND THAT IS A CORRECTION
     * ------------------------------------------------------------------------------------
     * This method used to compute all four figures over a single population — human sessions
     * with beacon data — on the stated principle that comparing averages across two
     * denominators is a sleight of hand. The principle is right and the application was wrong,
     * because it produced a card that was empty far more often than it was informative:
     *
     *   * The three BEACON clocks genuinely only exist for sessions where the beacon ran, so
     *     they keep that population. Nothing changes.
     *   * The LOG SPAN exists for every log-backed session, and taking it over the beacon
     *     population meant that on any range where no human session happened to have a beacon
     *     — which on a one-hour window is most of them — the log-span figure was an em-dash
     *     too, under a card whose own copy says the span "exists for every session". A
     *     structurally-available number reported as unavailable is worse than a missing one.
     *   * And the span's own population is narrower than "all human sessions": a session with
     *     ONE request has a span of zero by construction. Measured on a real index, 3,205 of
     *     4,132 sessions are single-request, so the median span over all of them is 0 — which
     *     is what the card printed.
     *
     * So each figure states its own denominator and the front end prints it. That is not
     * comparing across denominators, it is refusing to hide which one each number has.
     *
     * `beaconed` keeps a log span of its own precisely SO the comparison sentence can be
     * like-for-like: "a log-only tool would have said X, we measured Y" is only honest when X
     * and Y describe the same sessions.
     *
     * @return array<string,mixed>
     */
    private function timing(): array
    {
        $human = Query::POP_HUMAN;

        $f = $this->gw->facet('overview.timing', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->settledSessionFqs(),
        ], [
            'humans' => ['type' => 'query', 'q' => $human],

            /* THE SPAN IS TAKEN OVER SESSIONS THAT CAN HAVE ONE, AND THAT IS THE WHOLE FIX.
               It used to be an average over every settled human session, three quarters of
               which are a single request — and a single request has a span of zero by
               construction, not by measurement. The median of that population is 0, the card
               printed `0 ms` under a heading that says "how long they actually stayed", and the
               distribution chart beside it drew four empty bars with an axis reading
               "0 ms 0 ms 0 ms 1 ms 1 ms 1 ms".

               `floored` rides inside this facet rather than beside it so it cannot drift out of
               step with its own denominator: it is the multi-request sessions whose span is
               STILL zero, which is the log clock's resolution rather than a duration. */
            'spanned' => ['type' => 'query', 'q' => $human . ' AND ' . Query::POP_MULTI_REQUEST, 'facet' => [
                'log_span_avg' => 'avg(log_span_ms_l)',
                'log_span_p50' => 'percentile(log_span_ms_l,50)',
                'floored'      => ['type' => 'query', 'q' => Query::POP_SPAN_FLOORED],
            ]],
            /* Does this range mix planes? The note under the card is shown only when it does,
               because on a single-machine install it would be a paragraph about a situation
               that does not apply, and a panel that explains absent caveats is one nobody
               reads. Absent `planes_s` means the session predates the field, which can only be
               a log-backed session, so the negation is the correct form of the question. */
            'beacon_only' => ['type' => 'query', 'q' => 'planes_s:beacon_only'],
            'beaconed' => ['type' => 'query', 'q' => $human . ' AND ' . Query::POP_BEACON, 'facet' => [
                'log_span_avg' => 'avg(log_span_ms_l)',
                'log_span_p50' => 'percentile(log_span_ms_l,50)',
                'wall_avg'     => 'avg(wall_ms_l)',
                'wall_p50'     => 'percentile(wall_ms_l,50)',
                'visible_avg'  => 'avg(visible_ms_l)',
                'visible_p50'  => 'percentile(visible_ms_l,50)',
                'engaged_avg'  => 'avg(engaged_ms_l)',
                'engaged_p50'  => 'percentile(engaged_ms_l,50)',
            ]],
        ]);

        $beaconed = is_array($f['beaconed'] ?? null) ? $f['beaconed'] : [];
        $humans   = is_array($f['humans'] ?? null) ? $f['humans'] : [];
        $spanned  = is_array($f['spanned'] ?? null) ? $f['spanned'] : [];

        $population = (int) ($beaconed['count'] ?? 0);
        $humanCount = (int) ($humans['count'] ?? 0);
        $spanCount  = (int) ($spanned['count'] ?? 0);

        $beaconOnly = is_array($f['beacon_only'] ?? null) ? $f['beacon_only'] : [];

        return $this->envelope([
            'timing' => [
                'beacon_only'      => (int) ($beaconOnly['count'] ?? 0),
                'population'       => $population,
                'humans'           => $humanCount,
                'without_beacon'   => max(0, $humanCount - $population),

                /* The span's own denominator, and the two populations it deliberately leaves
                   out, so the card can name both instead of quietly averaging them in. */
                'spanned'          => $spanCount,
                'single_request'   => max(0, $humanCount - $spanCount),
                'span_floored'     => self::qcount($spanned, 'floored'),

                'log_span_avg'     => self::num($spanned, 'log_span_avg'),
                'log_span_p50'     => self::num($spanned, 'log_span_p50'),
                'wall_avg'         => self::num($beaconed, 'wall_avg'),
                'wall_p50'         => self::num($beaconed, 'wall_p50'),
                'visible_avg'      => self::num($beaconed, 'visible_avg'),
                'visible_p50'      => self::num($beaconed, 'visible_p50'),
                'engaged_avg'      => self::num($beaconed, 'engaged_avg'),
                'engaged_p50'      => self::num($beaconed, 'engaged_p50'),

                /* The like-for-like figure the comparison sentence needs: the SAME sessions the
                   three beacon clocks describe, seen the way a log-only tool would have seen
                   them. Comparing the beacon's engaged time against a span taken over a
                   different population would be the sleight of hand this card exists to expose,
                   committed by the card itself. */
                'all_log_span_avg' => self::num($beaconed, 'log_span_avg'),
                'all_log_span_p50' => self::num($beaconed, 'log_span_p50'),
            ],
        ]);
    }

    /**
     * Sessions per time bucket, split into the five populations.
     *
     * The populations cannot overlap, so the areas stack to exactly the bucket total and
     * the top of the stack is not a lie.
     *
     * @return array<string,mixed>
     */
    private function series(): array
    {
        $perBucket = [];
        foreach (Query::populations() as $key => $filter) {
            $perBucket[$key] = ['type' => 'query', 'q' => $filter];
        }

        $f = $this->gw->facet('overview.series', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->sessionFqs(),
        ], [
            'series' => [
                'type'  => 'range',
                'field' => 'ts_start',
                'start' => $this->range['start'],
                'end'   => 'NOW',
                'gap'   => $this->range['gap'],
                'facet' => $perBucket,
            ],
        ]);

        $times = [];
        $series = array_fill_keys(array_keys(Query::populations()), []);
        foreach (self::buckets($f, 'series') as $bucket) {
            $times[] = (string) ($bucket['val'] ?? '');
            foreach (array_keys(Query::populations()) as $key) {
                $series[$key][] = self::qcount($bucket, $key);
            }
        }

        return $this->envelope([
            'times'  => $times,
            'series' => $series,
            'labels' => Query::populationLabels(),
            'total'  => (int) ($f['count'] ?? 0),
        ]);
    }

    /**
     * Top requested paths, counted in REQUESTS.
     *
     * ------------------------------------------------------------------------------------
     * WHY THIS MOVED TO THE HITS CORE
     * ------------------------------------------------------------------------------------
     * It used to facet `paths_ss` on the SESSIONS core, which counts "sessions that requested
     * this path at least once". That number cannot rank anything. `paths_ss` is a set per
     * session, so a visitor who read one page forty times contributes exactly what a visitor who
     * glanced at it once does — and in a one-hour window with seven human sessions EVERY row
     * read `1`. A table where every row carries the same number is not a top-N list, it is an
     * alphabet of paths in arbitrary order.
     *
     * The count an operator wants from a page list is how many times the page was FETCHED, and
     * that number exists in exactly one place: the hits core, one document per request. So this
     * is a terms facet on `path_s` there, counting requests, with `unique(session_id_s)` beside
     * it so the session figure is not lost — it is a genuinely useful second column, it is just
     * not the ranking key.
     *
     * ------------------------------------------------------------------------------------
     * WHAT THE TOGGLE BECAME, AND WHY IT IS NOT A POPULATION ANY MORE
     * ------------------------------------------------------------------------------------
     * The old toggle was humans / all / bots, and it cannot survive the move: a VERDICT is a
     * conclusion the scorer reaches about a whole session once it has ended, it lives only on
     * the sessions core, and the hits core has no field for it. There is no honest way to ask
     * the request plane "which of these were humans".
     *
     * The dishonest ways were both considered and both refused. Filtering hits on
     * `-ua_bot_b:true` and labelling it "Humans only" would put every evasive bot in the human
     * column — the exact conflation SPEC §7 says makes other tools useless, committed under the
     * word that names this product's core claim. Resolving the population into a list of session
     * ids and filtering hits by it would be correct and unbounded: a ninety-day window is
     * hundreds of thousands of ids in a query string.
     *
     * So the toggle now selects something the request plane answers EXACTLY: pageviews only, or
     * every request. `pages` is the default because this card is called Top pages. The
     * humans/bots split of a path is still one click away and still exact — open the row, and
     * the dimension dialog breaks that path down by verdict on the sessions plane, where a
     * verdict actually exists.
     *
     * ------------------------------------------------------------------------------------
     * WHAT IS EXCLUDED, AND WHY EACH ONE
     * ------------------------------------------------------------------------------------
     * Sub-resources are gone from the index entirely now (`ingest.index_assets`), so the images
     * and stylesheets that used to crowd this table are not filtered out here, they are simply
     * not there. `beacon` IS still indexed, deliberately — it is the only evidence that a
     * collector is reachable — so it is excluded here instead: Loghound's own `/collect.php`
     * appearing in a list of a site's top pages is the product contradicting its own claim not
     * to count itself, and the ownership test that was supposed to prevent it can only fire when
     * the collector is reached at the hostname the panel is published at. `favicon` and `robots`
     * are excluded on the same reasoning: nobody visited them, a browser and a crawler fetched
     * them unprompted.
     *
     * A `host_s` sub-facet rides inside the path facet so every row knows which site it belongs
     * to — one host and the panel can link the full URL, several and it says how many rather
     * than guessing. Nested rather than fetched afterwards: no second round trip, and it
     * inherits this query's filters.
     *
     * Filters the hits core cannot answer are reported rather than silently dropped, which
     * matters more on this card than on most: a Verdict chip set elsewhere in the panel does not
     * narrow this table, and a table that quietly ignored it would be a wrong answer under a
     * chip that says otherwise.
     *
     * @return array<string,mixed>
     */
    private function topPages(): array
    {
        $scope = self::param('pop', ['pages', 'all'], 'pages');

        $fqs = $this->hitFqs();
        $fqs[] = '-kind_s:(beacon OR favicon OR robots OR asset)';
        $label = 'Every request';
        if ($scope === 'pages') {
            $fqs[] = Query::term('kind_s', 'html');
            $label = 'Pageviews only';
        }

        $f = $this->gw->facet('overview.toppages', $this->gw->hitsCore(), [
            'q'  => '*:*',
            'fq' => $fqs,
        ], [
            'paths' => Paging::terms('path_s', Paging::start(), Paging::rows(), 'count desc', [
                'facet' => SiteUrl::hostSubFacet() + ['sessions' => 'unique(session_id_s)'],
            ]),
        ]);

        $rows = [];
        foreach (self::buckets($f, 'paths') as $bucket) {
            $site = SiteUrl::resolve($bucket);
            $rows[] = [
                'path'     => (string) ($bucket['val'] ?? ''),
                'requests' => (int) ($bucket['count'] ?? 0),
                'sessions' => (int) (self::num($bucket, 'sessions') ?? 0),
                'host'     => $site['host'],
                'hosts'    => $site['hosts'],
            ];
        }

        return $this->envelope([
            'population'       => $scope,
            'population_label' => $label,
            'note'             => 'Sub-resources are not stored at all, and Loghound’s own collector, '
                . 'favicons and robots.txt are excluded: nobody visited those.',
            'total'            => (int) ($f['count'] ?? 0),
            'ignored'          => $this->ignoredHitFilters(),
            'rows'             => $rows,
            'page'             => Paging::block(
                Paging::start(),
                Paging::rows(),
                Paging::distinct($f, 'paths'),
                'paths',
                count($rows)
            ),
        ]);
    }

    /**
     * What visitors typed into the site's own search box.
     *
     * A terms facet on `search_terms_ss`, which is populated from two places and reads the same
     * from both: the log parser pulls the named parameters out of the request line for a host
     * whose access log this installation reads, and the beacon reports them for a host it does
     * not. So a search page on another server appears here beside one on this machine.
     *
     * COUNTED AS SESSIONS, not as searches, and the caption says so. The field is a per-session
     * union capped at Beacon::MAX_SESSION_TERMS, so a visitor who ran the same search six times
     * contributes one — which is the number worth having ("how many people looked for this")
     * rather than the one that flatters ("how many times was this typed"). Publishing the
     * second under the first's name is the class of quiet lie this product exists to stop.
     *
     * The population toggle is deliberately absent. Filtering to humans is one click away
     * through the Verdict dimension, which scopes every card on the page at once, and a second
     * per-card toggle would let two cards on one screen disagree about who they are describing.
     *
     * @return array<string,mixed>
     */
    private function searches(): array
    {
        $f = $this->gw->facet('overview.searches', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->sessionFqs(),
        ], [
            'terms'    => Paging::terms('search_terms_ss', Paging::start(), Paging::rows()),
            'searched' => ['type' => 'query', 'q' => 'search_terms_ss:*'],
        ]);

        $rows = [];
        foreach (self::buckets($f, 'terms') as $bucket) {
            $rows[] = [
                'term'     => (string) ($bucket['val'] ?? ''),
                'sessions' => (int) ($bucket['count'] ?? 0),
            ];
        }

        $searched = is_array($f['searched'] ?? null) ? $f['searched'] : [];

        return $this->envelope([
            'configured' => \Loghound\Beacon::normaliseParamNames(
                (array) $this->cfg->get('beacon.query_params', [])
            ),
            'total'    => (int) ($f['count'] ?? 0),
            'searched' => (int) ($searched['count'] ?? 0),
            'rows'     => $rows,
            'page'     => Paging::block(
                Paging::start(),
                Paging::rows(),
                Paging::distinct($f, 'terms'),
                'search terms',
                count($rows)
            ),
        ]);
    }

    /**
     * The static skeleton of the page.
     *
     * Contains headings, captions, table headers and empty states but no data: every
     * number arrives over the wire, so the page paints immediately and each section
     * fills in on its own schedule.
     */
    public function body(): void
    {
        $this->totalsCard();
        $this->timingCard();
        self::chart(
            'ov-series',
            '03',
            'Sessions over time',
            'All scored sessions, split into five mutually exclusive populations.',
            340,
            'Bucketing sessions by hour'
        );
        $this->pagesCard();
        $this->searchesCard();
        $this->pivotCard('ov-pivot', '06');
    }

    /**
     * What they searched for, and an honest empty state when nothing is configured.
     *
     * The empty state matters more than the table here. A card that reads "no data" when the
     * feature was never switched on sends an operator looking for a bug in their search page,
     * so when `beacon.query_params` names nothing the card says that is why and where to change
     * it — the front end swaps in that message rather than the generic one.
     */
    private function searchesCard(): void
    {
        self::cardOpen(
            'ov-searches',
            '05',
            'What they searched for',
            'Sessions that ran a search, by term.',
            $this->exportTool('searches')
        );
        self::skeleton('ov-searches', 'rows', 0, 'Faceting search terms');

        echo '<div class="table-wrap"><table id="ov-searches-table"><thead><tr>'
            . '<th scope="col">Search term</th>'
            . '<th scope="col" class="num">Sessions</th>'
            . '<th scope="col" class="bar-col">Share</th>'
            . '</tr></thead><tbody></tbody></table></div>';

        echo '<div id="ov-searches-pager"></div>';

        self::cardClose('ov-searches');
    }

    /**
     * The five headline counters, each of which OPENS THE POPULATION BEHIND IT.
     *
     * WHAT THIS FIXES. These were five numbers and five captions, rendered as inert text. The
     * single most natural gesture on a dashboard — press the big number to see what is in it —
     * did nothing at all, and the only route to "show me an evasive bot" was to know that the
     * Verdict dimension existed, find it in the filter rail and pick two of its five values.
     *
     * A tile is a `<button>` carrying `data-lh-open="pop"`, which is the same delegated mechanism
     * every drillable row in the panel uses (assets/js/dialog.js): no inline handler, nothing to
     * wire per page, and the population dialog opens with its visits already paged.
     *
     * `data-why` carries the sentence into the dialog, so the words the operator reads when they
     * arrive are the same words that were on the tile they pressed — and they are written HERE,
     * in PHP, beside the population they describe, rather than copied into a JavaScript table
     * that would drift from this one.
     */
    private function totalsCard(): void
    {
        self::cardOpen('ov-stats', '01', 'Who was here', 'All scored sessions in the selected range.');
        self::skeleton('ov-stats', 'stats', 0, 'Counting sessions by verdict');

        echo '<div class="stats">';
        foreach ([
            ['human',    'Human sessions',    'Scored human or likely human',
                'Nothing in the headers, the behaviour or the browser looked like automation.'],
            ['evasive',  'Evasive bots',      'Automation that did not declare itself',
                'Scored as automation and did not say so: headless browsers, scripted clients, spoofed '
                . 'User-Agents, rotating proxy fleets.'],
            ['declared', 'Declared crawlers', 'Identified themselves and verified',
                'Said what they were in the User-Agent and the claim held up.'],
            ['ai',       'AI crawlers',       'GPTBot, ClaudeBot, PerplexityBot',
                'Declared crawlers collecting for model training or assistant answers.'],
            ['unknown',  'Unknown',           'Scored, but the evidence was inconclusive',
                'The evidence did not reach a verdict either way. A finding, not a failure to measure.'],
        ] as [$key, $label, $hint, $why]) {
            echo '<button type="button" class="stat stat-open" data-stat="' . Security::esc($key) . '"'
                . ' data-lh-open="pop" data-pop="' . Security::esc($key) . '"'
                . ' data-why="' . Security::esc($why) . '"'
                . ' aria-label="' . Security::esc('Open the visits behind ' . $label) . '">';
            echo '<span class="stat-label">' . Security::esc($label) . '</span>';
            echo '<span class="stat-value mono" data-field="' . Security::esc($key) . '">—</span>';
            echo '<span class="stat-hint">' . Security::esc($hint) . '</span>';
            echo '<span class="stat-go" aria-hidden="true">&#8250;</span>';
            echo '</button>';
        }
        echo '</div>';

        self::cardClose('ov-stats');
    }

    /** The four timing numbers, their explanations and the comparison bar. */
    private function timingCard(): void
    {
        self::cardOpen('ov-timing', '02', 'How long they actually stayed');
        self::skeleton('ov-timing', 'stats', 0, 'Measuring dwell time across four clocks');

        echo '<div class="timing-grid">';
        foreach ([
            [
                'log_span',
                'Log span',
                'Last request minus first request.',
                'What GoAccess, AWStats and every log-only tool call &ldquo;time on site&rdquo;. It cannot see the '
                . 'last page at all: once the visitor stops requesting things the log goes quiet, whether they left '
                . 'or read for ten minutes.',
            ],
            [
                'wall',
                'Wall clock',
                'Page open, tab in any state.',
                'What Clicky, GA and Plausible report. It keeps counting while the tab sits forgotten behind twelve '
                . 'others, so it is reliably the largest of the four and reliably the least meaningful.',
            ],
            [
                'visible',
                'Visible',
                'Tab visible and window focused.',
                'Measured by pausing on <code>visibilitychange</code> and <code>blur</code>. The visitor could see '
                . 'the page. Whether they were reading it is a different question.',
            ],
            [
                'engaged',
                'Engaged',
                'Visible, within 30s of a real interaction.',
                'Scroll, click, keypress, pointer movement. This is the honest number, and it is the one nobody '
                . 'else reports because it needs a beacon that measures rather than trusts.',
            ],
        ] as [$key, $label, $definition, $why]) {
            echo '<div class="timing" data-timing="' . Security::esc($key) . '">';
            echo '<span class="timing-label">' . Security::esc($label) . '</span>';
            echo '<span class="timing-value mono" data-field="' . Security::esc($key) . '_p50">—</span>';
            echo '<span class="timing-sub">median · mean <span data-field="'
                . Security::esc($key) . '_avg">—</span></span>';
            echo '<span class="timing-defn">' . Security::esc($definition) . '</span>';
            echo '<p class="timing-why">' . $why . '</p>';
            echo '</div>';
        }
        echo '</div>';

        echo '<div class="chart" id="ov-timing-chart" style="height:190px"></div>';

        echo '<div class="note" id="ov-timing-note">'
            . '<p><strong>Why they differ.</strong> Each number measures something narrower than the one before it, '
            . 'so on real traffic they descend: log span and wall clock are inflated by an open tab, visible time '
            . 'drops the background tab, and engaged time drops the visible-but-abandoned tab. A large wall clock '
            . 'with near-zero engagement means nobody was reading.</p>'
            . '<p><strong>Log span is not one of the three.</strong> It comes from the access log and is '
            . 'structurally blind to the final pageview: once the visitor stops requesting things the log goes '
            . 'quiet. The other three come from the beacon and exist only for sessions where it ran — sessions '
            . 'without one are excluded, not counted as zero.</p>'
            . '<p><strong>A span needs two requests.</strong> It is the last request minus the first, so a '
            . 'session that made a single request has a span of zero by construction and no measurement has '
            . 'happened. Those are excluded and counted separately above rather than averaged in as zeroes — on '
            . 'most sites they are the majority, and folding them in drags the median to nothing.</p>'
            . '<p id="ov-timing-floor" hidden><strong>Some spans are shorter than this log can measure.</strong> '
            . 'The stock Apache <code>%t</code> and nginx <code>$time_local</code> record whole seconds, so two '
            . 'requests inside the same second are indistinguishable and the span reads as zero. Those sessions '
            . 'are counted above as “under the clock’s resolution” rather than reported as a measured zero. '
            . 'Logging a fraction — <code>%{msec}t</code>, or HAProxy’s format — makes them measurable.</p>'
            . '<p id="ov-timing-planes" hidden><strong>Some of this traffic has no access log behind it.</strong> '
            . 'Sessions from a host measured by the beacon alone have no log span at all, so they contribute to '
            . 'the three beacon clocks and to nothing else. The log-span figure therefore covers a smaller '
            . 'population than the ones beside it, and the contrast between them is not like-for-like on a '
            . 'mixed install. Filter by <em>Planes</em> to compare one kind at a time.</p>'
            . '</div>';

        self::cardClose('ov-timing');
    }

    /**
     * Top pages, with the scope toggle.
     *
     * THE TOGGLE IS NOT A POPULATION ANY MORE and topPages() carries the full reasoning: this
     * card counts REQUESTS, requests live on the hits core, and a verdict is a conclusion about
     * a whole session that exists only on the sessions core. Offering "Humans only" over a plane
     * that has no idea which sessions were human would have meant labelling `-ua_bot_b:true` as
     * humans, which puts every evasive bot in the human column — the one conflation this product
     * is built to refuse.
     */
    private function pagesCard(): void
    {
        $tools = '<div class="toggle" role="group" aria-label="What to count">';
        foreach ([['pages', 'Pages'], ['all', 'Every request']] as [$value, $label]) {
            $tools .= '<button type="button" data-pop="' . Security::esc($value) . '"'
                . ($value === 'pages' ? ' class="on" aria-pressed="true"' : ' aria-pressed="false"')
                . '>' . $label . '</button>';
        }
        $tools .= '</div>';
        $tools .= $this->exportTool('pages');

        self::cardOpen('ov-pages', '04', 'Top pages', '', $tools);
        self::skeleton('ov-pages', 'rows', 0, 'Counting requests by path');

        echo '<div class="table-wrap"><table id="ov-pages-table"><thead><tr>'
            . '<th scope="col">Path</th>'
            . '<th scope="col" class="num">Requests</th>'
            . '<th scope="col" class="num">Sessions</th>'
            . '<th scope="col" class="bar-col">Share</th>'
            . '</tr></thead><tbody></tbody></table></div>';
        echo '<div id="ov-pages-pager"></div>';

        self::cardClose('ov-pages');
    }
    /**
     * Why there are no sessions yet, when there is traffic.
     *
     * A session is written only when it CLOSES, and it closes after the visitor has been
     * silent for ingest.session_idle_sec — half an hour by default. So on a fresh install
     * the operator starts the daemon, browses their own site to check it works, and every
     * view reports zero for the next thirty minutes while the logs are being read perfectly
     * well. "0 scored sessions" is true and reads as "nothing happened", which is a lie
     * about the only thing they want to know.
     *
     * The evidence comes from the tailer's own status file, which is a local read — no
     * second Solr query to say why the first one was empty.
     *
     * Returns an empty string whenever there is nothing to explain: sessions exist, or
     * nothing has been read either, in which case the ingestion banner already says so.
     */
    private function pendingExplanation(int $sessions): string
    {
        if ($sessions > 0) {
            return '';
        }

        $ingest = Steps::ingestStatus(dirname(__DIR__, 2));
        $lines  = (int) ($ingest['lines'] ?? 0);
        if ((string) $ingest['state'] !== 'live' || $lines < 1) {
            return '';
        }

        $idle = Security::clampInt($this->cfg->get('ingest.session_idle_sec'), 60, 86400, 1800);

        return number_format($lines) . ' requests have been read from your logs, so ingestion is working, '
            . 'and nothing has been scored yet. The scorer runs about once a minute; give it one. '
            . 'A session settles once the visitor has been quiet for ' . self::humanMinutes($idle)
            . ', and until then its numbers are still moving.';
    }

    /**
     * A duration in whole minutes, or seconds when it is shorter than one.
     */
    private static function humanMinutes(int $seconds): string
    {
        if ($seconds < 60) {
            return $seconds . ' seconds';
        }
        $minutes = (int) round($seconds / 60);

        return $minutes . ' minute' . ($minutes === 1 ? '' : 's');
    }

}
