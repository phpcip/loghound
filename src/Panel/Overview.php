<?php
/**
 * Loghound — Overview.
 *
 * Answers two questions and refuses to blur them together:
 *
 *   1. Who was here? Humans, evasive automation, and declared crawlers are three
 *      different populations and are drawn as three different bands, never as one
 *      "visitors" line.
 *   2. How long did they actually stay? Four numbers, side by side, with the reason they
 *      differ written next to them in plain English. This is the product's headline
 *      claim (SPEC §0) and the single most misreadable thing in the whole panel, so the
 *      comparison is built to be impossible to take out of context: same population for
 *      all four, population named on the card, and a fourth "what logs alone would have
 *      told you" figure sitting next to it for contrast.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Security;

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
            'summary'  => $this->summary(),
            'toppages' => $this->topPages(),
            default    => ['error' => 'Unknown action'],
        };
    }

    /**
     * Totals, the stacked hourly series, and the timing comparison — one Solr request.
     *
     * Everything here is a facet: `rows=0` is forced by the Gateway, so not a single
     * session document crosses the wire for this view.
     *
     * @return array<string,mixed>
     */
    private function summary(): array
    {
        $pops = Query::populations();

        // Sub-facets that break each time bucket into the five populations. They are
        // mutually exclusive by construction (see Panel\Query), so the areas stack to
        // exactly the bucket total and the chart's total line is not a lie.
        $perBucket = [];
        foreach ($pops as $key => $q) {
            $perBucket[$key] = ['type' => 'query', 'q' => $q];
        }

        $facet = [
            // --- Traffic over time -------------------------------------------------
            'series' => [
                'type'  => 'range',
                'field' => 'ts_start',
                'start' => $this->range['start'],
                'end'   => 'NOW',
                'gap'   => $this->range['gap'],
                'facet' => $perBucket,
            ],

            // --- Totals per population --------------------------------------------
            // `unique(visitor_s)` is Solr's approximate distinct count. It is exact well
            // below 100 and within a couple of percent above it; the UI labels it as
            // approximate rather than pretending otherwise.
            'human' => ['type' => 'query', 'q' => $pops['human'], 'facet' => [
                'visitors'  => 'unique(visitor_s)',
                'pageviews' => 'sum(pages_i)',
                'hits'      => 'sum(hits_i)',
                'bytes'     => 'sum(bytes_l)',
            ]],
            'unknown'  => ['type' => 'query', 'q' => $pops['unknown']],
            'declared' => ['type' => 'query', 'q' => $pops['declared'], 'facet' => ['hits' => 'sum(hits_i)']],
            'ai'       => ['type' => 'query', 'q' => $pops['ai'], 'facet' => ['hits' => 'sum(hits_i)']],
            'evasive'  => ['type' => 'query', 'q' => $pops['evasive'], 'facet' => ['hits' => 'sum(hits_i)']],

            // --- The four timing numbers ------------------------------------------
            // All four are computed over the SAME population — sessions that produced a
            // beacon — because comparing an average across two different denominators is
            // exactly the sleight of hand this view exists to expose.
            'timing' => ['type' => 'query', 'q' => Query::POP_BEACON . ' AND ' . $pops['human'], 'facet' => [
                'log_span_avg' => 'avg(log_span_ms_l)',
                'log_span_p50' => 'percentile(log_span_ms_l,50)',
                'wall_avg'     => 'avg(wall_ms_l)',
                'wall_p50'     => 'percentile(wall_ms_l,50)',
                'visible_avg'  => 'avg(visible_ms_l)',
                'visible_p50'  => 'percentile(visible_ms_l,50)',
                'engaged_avg'  => 'avg(engaged_ms_l)',
                'engaged_p50'  => 'percentile(engaged_ms_l,50)',
            ]],

            // Same metric over ALL human sessions, beacon or not. Printed beside the four
            // as "what a log-only tool would have reported", which is the comparison that
            // makes the point.
            'logonly' => ['type' => 'query', 'q' => $pops['human'], 'facet' => [
                'log_span_avg' => 'avg(log_span_ms_l)',
                'log_span_p50' => 'percentile(log_span_ms_l,50)',
            ]],

            // Beacon coverage: without this the four numbers have no denominator.
            'nobeacon' => ['type' => 'query', 'q' => $pops['human'] . ' AND -' . Query::POP_BEACON],
        ];

        $f = $this->gw->facet('overview.summary', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->sessionFqs(),
        ], $facet);

        // --- Shape the time series for ECharts ------------------------------------
        $times = [];
        $series = array_fill_keys(array_keys($pops), []);
        foreach (self::buckets($f, 'series') as $b) {
            $times[] = (string) ($b['val'] ?? '');
            foreach ($pops as $key => $_) {
                $series[$key][] = self::qcount($b, $key);
            }
        }

        $timing = is_array($f['timing'] ?? null) ? $f['timing'] : [];
        $logonly = is_array($f['logonly'] ?? null) ? $f['logonly'] : [];
        $humanNode = is_array($f['human'] ?? null) ? $f['human'] : [];

        $beaconed = (int) ($timing['count'] ?? 0);
        $humans   = (int) ($humanNode['count'] ?? 0);

        return $this->envelope([
            'total_sessions' => (int) ($f['count'] ?? 0),
            'times'          => $times,
            'series'         => $series,
            'labels'         => Query::populationLabels(),
            'totals' => [
                'human'    => $humans,
                'unknown'  => self::qcount($f, 'unknown'),
                'declared' => self::qcount($f, 'declared'),
                'ai'       => self::qcount($f, 'ai'),
                'evasive'  => self::qcount($f, 'evasive'),
            ],
            'human_detail' => [
                'visitors'  => self::num($humanNode, 'visitors'),
                'pageviews' => self::num($humanNode, 'pageviews'),
                'hits'      => self::num($humanNode, 'hits'),
                'bytes'     => self::num($humanNode, 'bytes'),
            ],
            'crawler_hits' => [
                'declared' => self::num(is_array($f['declared'] ?? null) ? $f['declared'] : [], 'hits'),
                'ai'       => self::num(is_array($f['ai'] ?? null) ? $f['ai'] : [], 'hits'),
                'evasive'  => self::num(is_array($f['evasive'] ?? null) ? $f['evasive'] : [], 'hits'),
            ],
            // The timing block carries its own denominators so the front end never has to
            // guess which population a number belongs to.
            'timing' => [
                'population'      => $beaconed,
                'humans'          => $humans,
                'without_beacon'  => self::qcount($f, 'nobeacon'),
                'log_span_avg'    => self::num($timing, 'log_span_avg'),
                'log_span_p50'    => self::num($timing, 'log_span_p50'),
                'wall_avg'        => self::num($timing, 'wall_avg'),
                'wall_p50'        => self::num($timing, 'wall_p50'),
                'visible_avg'     => self::num($timing, 'visible_avg'),
                'visible_p50'     => self::num($timing, 'visible_p50'),
                'engaged_avg'     => self::num($timing, 'engaged_avg'),
                'engaged_p50'     => self::num($timing, 'engaged_p50'),
                'all_log_span_avg' => self::num($logonly, 'log_span_avg'),
                'all_log_span_p50' => self::num($logonly, 'log_span_p50'),
            ],
        ]);
    }

    /**
     * Top requested paths, for a caller-selected population.
     *
     * A separate request from the summary so the humans/all toggle is instant and so the
     * (potentially wide) terms facet does not slow the first paint of the page.
     *
     * @return array<string,mixed>
     */
    private function topPages(): array
    {
        // The toggle is an allowlist, not a filter string from the browser.
        $pop = self::param('pop', ['humans', 'all', 'bots'], 'humans');
        $fqs = $this->sessionFqs();
        $label = 'All sessions';
        if ($pop === 'humans') {
            $fqs[] = Query::POP_HUMAN;
            $label = 'Humans only';
        } elseif ($pop === 'bots') {
            $fqs[] = Query::POP_BOTLIKE;
            $label = 'Bots and crawlers only';
        }

        $limit = Security::clampInt($_GET['limit'] ?? null, 5, 50, 15);

        // `paths_ss` is capped at 50 values per session by the scorer (SPEC §4.2), so this
        // counts "sessions that touched the path", not raw hits. The caption says so.
        $f = $this->gw->facet('overview.toppages', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $fqs,
        ], [
            'paths' => [
                'type'  => 'terms',
                'field' => 'paths_ss',
                'limit' => $limit,
                'sort'  => 'count desc',
            ],
        ]);

        $rows = [];
        foreach (self::buckets($f, 'paths') as $b) {
            $rows[] = ['path' => (string) ($b['val'] ?? ''), 'sessions' => (int) ($b['count'] ?? 0)];
        }

        return $this->envelope([
            'population'       => $pop,
            'population_label' => $label,
            'total'            => (int) ($f['count'] ?? 0),
            'rows'             => $rows,
        ]);
    }

    /**
     * The static skeleton. No data — the front end fills it from the two API actions.
     */
    public function body(): void
    {
        // ---- Headline counters ------------------------------------------------
        echo '<section class="card stats" id="ov-stats">';
        echo '<h2 class="sr-only">Totals</h2>';
        foreach ([
            ['human',    'Human sessions',     'Scored human or likely human'],
            ['evasive',  'Evasive bots',       'Automation that did not declare itself'],
            ['declared', 'Declared crawlers',  'Identified themselves and verified'],
            ['ai',       'AI crawlers',        'GPTBot, ClaudeBot, PerplexityBot, …'],
            ['unknown',  'Unknown',            'Scored, but the evidence was inconclusive'],
        ] as [$key, $label, $hint]) {
            echo '<div class="stat" data-stat="' . Security::esc($key) . '">';
            echo '<span class="stat-label">' . Security::esc($label) . '</span>';
            echo '<span class="stat-value mono" data-field="' . Security::esc($key) . '">—</span>';
            echo '<span class="stat-hint">' . Security::esc($hint) . '</span>';
            echo '</div>';
        }
        echo '</section>';

        // ---- The four timing numbers -----------------------------------------
        echo '<section class="card" id="ov-timing">';
        echo '<h2>How long they actually stayed</h2>';
        echo '<p class="pop" id="ov-timing-pop">—</p>';

        echo '<div class="timing-grid">';
        foreach ([
            ['log_span', 'Log span',    'Last request minus first request.',
                'What GoAccess, AWStats and every log-only tool call &ldquo;time on site&rdquo;. It cannot see the last page at all: once the visitor stops requesting things, the log goes quiet whether they left or read for ten minutes.'],
            ['wall', 'Wall clock',      'Page open, tab in any state.',
                'What Clicky, GA and Plausible report. It keeps counting while the tab sits forgotten behind twelve others, so it is reliably the largest of the four and reliably the least meaningful.'],
            ['visible', 'Visible',      'Tab visible and window focused.',
                'Measured by pausing on <code>visibilitychange</code> and <code>blur</code>. The visitor could see the page. Whether they were reading it is a different question.'],
            ['engaged', 'Engaged',      'Visible, within 30s of a real interaction.',
                'Scroll, click, keypress, pointer movement. This is the honest number, and it is the one nobody else reports because it needs a beacon that is measuring rather than trusting.'],
        ] as [$key, $label, $defn, $why]) {
            echo '<div class="timing" data-timing="' . Security::esc($key) . '">';
            echo '<span class="timing-label">' . Security::esc($label) . '</span>';
            echo '<span class="timing-value mono" data-field="' . Security::esc($key) . '_p50">—</span>';
            echo '<span class="timing-sub">median · mean <span class="mono" data-field="'
                . Security::esc($key) . '_avg">—</span></span>';
            echo '<span class="timing-defn">' . Security::esc($defn) . '</span>';
            echo '<p class="timing-why">' . $why . '</p>'; // static copy, authored here, not user data
            echo '</div>';
        }
        echo '</div>';

        echo '<div class="chart" id="ov-timing-chart" style="height:180px"></div>';

        echo '<div class="note" id="ov-timing-note">'
            . '<p><strong>Why they differ.</strong> Each number measures something narrower than the one before it, '
            . 'so on real traffic they descend: log span and wall clock are inflated by an open tab, visible time '
            . 'drops the background tab, and engaged time drops the visible-but-abandoned tab. If a session shows '
            . 'a large wall clock and near-zero engagement, nobody was reading. If it shows engagement close to '
            . 'visible time, someone was.</p>'
            . '<p><strong>Log span is not one of the three.</strong> It comes from the access log, is available for '
            . 'every session, and is structurally blind to the final pageview. The other three come from the beacon '
            . 'and exist only for sessions where the beacon ran — the count is stated above, and sessions without '
            . 'one are left out rather than counted as zero.</p>'
            . '</div>';
        echo '</section>';

        // ---- Traffic over time -------------------------------------------------
        self::chart('ov-series', 'Sessions over time', 'All scored sessions, split into five mutually exclusive populations.', '340px');

        // ---- Top pages ---------------------------------------------------------
        echo '<section class="card">';
        echo '<div class="card-head">';
        echo '<h2>Top pages</h2>';
        echo '<div class="toggle" role="group" aria-label="Population">';
        foreach ([['humans', 'Humans only'], ['all', 'All'], ['bots', 'Bots & crawlers']] as [$val, $label]) {
            echo '<button type="button" data-pop="' . Security::esc($val) . '"'
                . ($val === 'humans' ? ' class="on" aria-pressed="true"' : ' aria-pressed="false"')
                . '>' . Security::esc($label) . '</button>';
        }
        echo '</div></div>';
        echo '<p class="pop" id="ov-pages-pop">—</p>';
        echo '<div class="table-wrap"><table id="ov-pages"><thead><tr>'
            . '<th scope="col">Path</th>'
            . '<th scope="col" class="num">Sessions</th>'
            . '<th scope="col" class="bar-col">Share</th>'
            . '</tr></thead><tbody></tbody></table></div>';
        echo '<div class="empty" id="ov-pages-empty" hidden></div>';
        echo '</section>';
    }
}
