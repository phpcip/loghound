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
     * Which page-toolbar controls this view honours.
     *
     * Every card runs under sessionFqs(), which carries the range, the host and every facet.
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
                'ranked'  => 'ranked by the number of sessions that requested them',
                'cap'     => 50,
                'params'  => ['limit' => 50],
                'carry'   => ['pop'],
                'note'    => 'Counted as sessions that requested the path at least once, not as a raw '
                    . 'request count. Loghound\'s own beacon and collector requests are excluded here, '
                    . 'because this reads the path set on the session document; a Performance export reads '
                    . 'the hits index, where they are still present.',
                'scope'   => ['population_label' => 'Population'],
                'columns' => [
                    ['Path', 'path', 'text'],
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
     * The four timing numbers, and the log-only figure they are contrasted with.
     *
     * All four cover the same population — human sessions that produced beacon data —
     * because comparing averages across two different denominators is exactly the sleight
     * of hand this card exists to expose. The denominators travel with the numbers so the
     * front end never has to guess which population a figure belongs to.
     *
     * @return array<string,mixed>
     * COMPLETED SESSIONS ONLY. An open session's log span is the gap between its first hit
     * and its most recent one, so averaging it in measures how long ago the visitor arrived
     * rather than how long they stayed — which is precisely the lie this card exists to
     * expose. Counting a live session is honest; measuring one is not.
     *
     */
    private function timing(): array
    {
        $human = Query::POP_HUMAN;

        $f = $this->gw->facet('overview.timing', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->settledSessionFqs(),
        ], [
            'humans' => ['type' => 'query', 'q' => $human, 'facet' => [
                'log_span_avg' => 'avg(log_span_ms_l)',
                'log_span_p50' => 'percentile(log_span_ms_l,50)',
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
        $population = (int) ($beaconed['count'] ?? 0);
        $humanCount = (int) ($humans['count'] ?? 0);

        $beaconOnly = is_array($f['beacon_only'] ?? null) ? $f['beacon_only'] : [];

        return $this->envelope([
            'timing' => [
                'beacon_only'      => (int) ($beaconOnly['count'] ?? 0),
                'population'       => $population,
                'humans'           => $humanCount,
                'without_beacon'   => max(0, $humanCount - $population),
                'log_span_avg'     => self::num($beaconed, 'log_span_avg'),
                'log_span_p50'     => self::num($beaconed, 'log_span_p50'),
                'wall_avg'         => self::num($beaconed, 'wall_avg'),
                'wall_p50'         => self::num($beaconed, 'wall_p50'),
                'visible_avg'      => self::num($beaconed, 'visible_avg'),
                'visible_p50'      => self::num($beaconed, 'visible_p50'),
                'engaged_avg'      => self::num($beaconed, 'engaged_avg'),
                'engaged_p50'      => self::num($beaconed, 'engaged_p50'),
                'all_log_span_avg' => self::num($humans, 'log_span_avg'),
                'all_log_span_p50' => self::num($humans, 'log_span_p50'),
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
     * Top requested paths for a caller-selected population.
     *
     * The toggle is an allowlist, not a filter string from the browser. `paths_ss` is
     * capped at 50 values per session by the scorer (SPEC §4.2), so this counts sessions
     * that touched a path rather than raw hits, and the caption says so.
     *
     * EVERY ROW CARRIES ITS HOST WHERE IT HONESTLY CAN. A path with no site in front of it is
     * not actionable and, on a machine serving several virtual hosts, does not even say which
     * site it belongs to — so a `host_s` sub-facet is nested inside the path facet and each row
     * comes back knowing whether it belongs to exactly one host (`host`) or to several
     * (`hosts`). Nested rather than fetched afterwards: it costs no second round trip, and the
     * sub-facet's domain is this query's, so filtering to one host resolves every row at once.
     *
     * The caption carries `note`, because the path set on the session document deliberately
     * excludes Loghound's own beacon script and collector (Sessionizer::accumulateSelf()), and
     * a count that quietly omits something must say so.
     *
     * @return array<string,mixed>
     */
    private function topPages(): array
    {
        $population = self::param('pop', ['humans', 'all', 'bots'], 'humans');
        $fqs = $this->sessionFqs();
        $label = 'All sessions';
        if ($population === 'humans') {
            $fqs[] = Query::POP_HUMAN;
            $label = 'Humans only';
        } elseif ($population === 'bots') {
            $fqs[] = Query::POP_BOTLIKE;
            $label = 'Bots and crawlers only';
        }

        $f = $this->gw->facet('overview.toppages', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $fqs,
        ], [
            'paths' => [
                'type'  => 'terms',
                'field' => 'paths_ss',
                'limit' => Security::clampInt($_GET['limit'] ?? null, 5, 50, 15),
                'sort'  => 'count desc',
                'facet' => SiteUrl::hostSubFacet(),
            ],
        ]);

        $rows = [];
        foreach (self::buckets($f, 'paths') as $bucket) {
            $site = SiteUrl::resolve($bucket);
            $rows[] = [
                'path'     => (string) ($bucket['val'] ?? ''),
                'sessions' => (int) ($bucket['count'] ?? 0),
                'host'     => $site['host'],
                'hosts'    => $site['hosts'],
            ];
        }

        return $this->envelope([
            'population'       => $population,
            'population_label' => $label,
            'note'             => 'Loghound’s own beacon and collector requests are not counted.',
            'total'            => (int) ($f['count'] ?? 0),
            'rows'             => $rows,
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
            'terms' => [
                'type'  => 'terms',
                'field' => 'search_terms_ss',
                'limit' => Security::clampInt($_GET['limit'] ?? null, 5, 50, 15),
                'sort'  => 'count desc',
            ],
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

        self::cardClose('ov-searches');
    }

    /** The five headline counters. */
    private function totalsCard(): void
    {
        self::cardOpen('ov-stats', '01', 'Who was here', 'All scored sessions in the selected range.');
        self::skeleton('ov-stats', 'stats', 0, 'Counting sessions by verdict');

        echo '<div class="stats">';
        foreach ([
            ['human',    'Human sessions',    'Scored human or likely human'],
            ['evasive',  'Evasive bots',      'Automation that did not declare itself'],
            ['declared', 'Declared crawlers', 'Identified themselves and verified'],
            ['ai',       'AI crawlers',       'GPTBot, ClaudeBot, PerplexityBot'],
            ['unknown',  'Unknown',           'Scored, but the evidence was inconclusive'],
        ] as [$key, $label, $hint]) {
            echo '<div class="stat" data-stat="' . Security::esc($key) . '">';
            echo '<span class="stat-label">' . Security::esc($label) . '</span>';
            echo '<span class="stat-value mono" data-field="' . Security::esc($key) . '">—</span>';
            echo '<span class="stat-hint">' . Security::esc($hint) . '</span>';
            echo '</div>';
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
            . '<p><strong>Log span is not one of the three.</strong> It comes from the access log, exists for every '
            . 'session, and is structurally blind to the final pageview. The other three come from the beacon and '
            . 'exist only for sessions where it ran — sessions without one are excluded, not counted as zero.</p>'
            . '<p id="ov-timing-planes" hidden><strong>Some of this traffic has no access log behind it.</strong> '
            . 'Sessions from a host measured by the beacon alone have no log span at all, so they contribute to '
            . 'the three beacon clocks and to nothing else. The log-span figure therefore covers a smaller '
            . 'population than the ones beside it, and the contrast between them is not like-for-like on a '
            . 'mixed install. Filter by <em>Planes</em> to compare one kind at a time.</p>'
            . '</div>';

        self::cardClose('ov-timing');
    }

    /** Top pages, with the population toggle. */
    private function pagesCard(): void
    {
        $tools = '<div class="toggle" role="group" aria-label="Population">';
        foreach ([['humans', 'Humans only'], ['all', 'All'], ['bots', 'Bots &amp; crawlers']] as [$value, $label]) {
            $tools .= '<button type="button" data-pop="' . Security::esc($value) . '"'
                . ($value === 'humans' ? ' class="on" aria-pressed="true"' : ' aria-pressed="false"')
                . '>' . $label . '</button>';
        }
        $tools .= '</div>';
        $tools .= $this->exportTool('pages');

        self::cardOpen('ov-pages', '04', 'Top pages', 'Humans only.', $tools);
        self::skeleton('ov-pages', 'rows', 0, 'Faceting requested paths');

        echo '<div class="table-wrap"><table id="ov-pages-table"><thead><tr>'
            . '<th scope="col">Path</th>'
            . '<th scope="col" class="num">Sessions</th>'
            . '<th scope="col" class="bar-col">Share</th>'
            . '</tr></thead><tbody></tbody></table></div>';

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
