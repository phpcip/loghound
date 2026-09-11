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
     * @return array<string,mixed>
     */
    public function api(string $action): array
    {
        return match ($action) {
            'totals'   => $this->totals(),
            'timing'   => $this->timing(),
            'series'   => $this->series(),
            'toppages' => $this->topPages(),
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
        ], $facet);

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

        return $this->envelope([
            'timing' => [
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
            ],
        ]);

        $rows = [];
        foreach (self::buckets($f, 'paths') as $bucket) {
            $rows[] = [
                'path'     => (string) ($bucket['val'] ?? ''),
                'sessions' => (int) ($bucket['count'] ?? 0),
            ];
        }

        return $this->envelope([
            'population'       => $population,
            'population_label' => $label,
            'total'            => (int) ($f['count'] ?? 0),
            'rows'             => $rows,
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
