<?php
/**
 * Loghound — Performance.
 *
 * The only view that aggregates over the `hits` core rather than `sessions`, because
 * `dur_us_l` is a per-request measurement and lives there (SPEC §4.1). It is still
 * facets-only: `rows=0`, no documents, one request.
 *
 * Two honesty requirements shape this page:
 *
 *  - **`dur_us_l` is optional.** It comes from Apache's `%D` / nginx's
 *    `$request_time`, and a stock `combined` LogFormat does not include it. When it is
 *    missing the field is ABSENT, not zero — so every latency number here is captioned
 *    with the share of requests that actually carried a duration, and a source with none
 *    gets an empty state telling the operator which directive to add rather than a chart
 *    of zeroes.
 *  - **Averages hide the thing you are looking for.** p50 tells you what the median
 *    visitor felt; p99 tells you what your worst 1% felt, and those are the requests that
 *    time out. Both are shown, and the mean is shown next to them so the gap is visible.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Security;

final class Performance extends Controller
{
    public function slug(): string
    {
        return 'performance';
    }

    public function title(): string
    {
        return 'Performance';
    }

    public function subtitle(): string
    {
        return 'Latency percentiles per path, and what the server was answering with.';
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
        $limit = Security::clampInt($_GET['limit'] ?? null, 5, 100, 25);

        // Which requests to measure. Mixing a 3 ms cache hit on a PNG into the same
        // percentile as a rendered page produces a number that describes neither, so the
        // default is HTML only and the toggle is an allowlist.
        $kind = self::param('kind', ['html', 'asset', 'api', 'all'], 'html');
        $fqs = $this->hitFqs();
        if ($kind !== 'all') {
            $fqs[] = Query::term('kind_s', $kind);
        }

        // Optional: exclude bot traffic from latency. A scraper hammering one endpoint
        // can dominate a percentile and hide what humans experienced.
        //
        // CAVEAT, and the view says so on screen: SPEC §4.1 does NOT define
        // `bot_verdict_s` on the hits core — the verdict lives on the session document.
        // The filter therefore only works if the scorer copies the verdict down onto
        // hits. Rather than silently returning nothing, the request below also counts how
        // many matched hits carry a verdict at all, so the UI can tell the operator that
        // the toggle has no effect on their deployment instead of showing an empty chart.
        $who = self::param('who', ['all', 'human'], 'all');
        $scopeFilter = $who === 'human' ? Query::POP_HUMAN : null;

        $pct = [
            'p50' => 'percentile(dur_us_l,50)',
            'p95' => 'percentile(dur_us_l,95)',
            'p99' => 'percentile(dur_us_l,99)',
            'avg' => 'avg(dur_us_l)',
            'max' => 'max(dur_us_l)',
        ];

        $facet = [
            'paths' => [
                'type'  => 'terms',
                'field' => 'path_s',
                'limit' => $limit,
                'sort'  => 'count desc',
                'facet' => $pct + [
                    'bytes'  => 'avg(bytes_l)',
                    'errors' => ['type' => 'query', 'q' => 'status_i:[500 TO 599]'],
                    'notfound' => ['type' => 'query', 'q' => 'status_i:[400 TO 499]'],
                    'timed'  => ['type' => 'query', 'q' => 'dur_us_l:[* TO *]'],
                ],
            ],

            // Overall percentiles, for the headline numbers.
            'overall' => ['type' => 'query', 'q' => '*:*', 'facet' => $pct],

            // Coverage: how many of the matched requests actually carry a duration. This
            // is the denominator every latency number on this page depends on.
            'timed' => ['type' => 'query', 'q' => 'dur_us_l:[* TO *]'],

            // Latency over time, so a regression has a timestamp.
            'over_time' => [
                'type'  => 'range',
                'field' => 'ts',
                'start' => $this->range['start'],
                'end'   => 'NOW',
                'gap'   => $this->range['gap'],
                'facet' => ['p50' => 'percentile(dur_us_l,50)', 'p95' => 'percentile(dur_us_l,95)'],
            ],

            // Status heatmap. Classes rather than individual codes: an operator scanning
            // for trouble wants "when did the 5xx happen", not 47 rows.
            'heat' => [
                'type'  => 'range',
                'field' => 'ts',
                'start' => $this->range['start'],
                'end'   => 'NOW',
                'gap'   => $this->range['gap'],
                'facet' => [
                    's2' => ['type' => 'query', 'q' => 'status_i:[200 TO 299]'],
                    's3' => ['type' => 'query', 'q' => 'status_i:[300 TO 399]'],
                    's4' => ['type' => 'query', 'q' => 'status_i:[400 TO 499]'],
                    's5' => ['type' => 'query', 'q' => 'status_i:[500 TO 599]'],
                ],
            ],

            // Exact status codes, for the table under the heatmap.
            'statuses' => ['type' => 'terms', 'field' => 'status_i', 'limit' => 20, 'sort' => 'count desc'],
        ];

        // When a population filter is active, everything moves inside a `query` facet so
        // that `verdicted` below can still be counted over the unfiltered domain. (A
        // `domain` filter would be the natural way to express this, but Solr.php only
        // accepts `domain.excludeTags`.)
        $request = $scopeFilter === null
            ? $facet + ['verdicted' => ['type' => 'query', 'q' => 'bot_verdict_s:[* TO *]']]
            : [
                'scope'     => ['type' => 'query', 'q' => $scopeFilter, 'facet' => $facet],
                'verdicted' => ['type' => 'query', 'q' => 'bot_verdict_s:[* TO *]'],
            ];

        $raw = $this->gw->facet('perf.summary', $this->gw->hitsCore(), [
            'q'  => '*:*',
            'fq' => $fqs,
        ], $request);

        // Hits in range that carry a verdict at all — the denominator that decides
        // whether the "Humans only" toggle means anything on this deployment.
        $verdicted = self::qcount($raw, 'verdicted');
        $matchedAll = (int) ($raw['count'] ?? 0);

        $f = $scopeFilter === null
            ? $raw
            : (is_array($raw['scope'] ?? null) ? $raw['scope'] : ['count' => 0]);

        $paths = [];
        foreach (self::buckets($f, 'paths') as $b) {
            $count = (int) ($b['count'] ?? 0);
            $paths[] = [
                'path'     => (string) ($b['val'] ?? ''),
                'requests' => $count,
                'timed'    => self::qcount($b, 'timed'),
                'p50'      => self::num($b, 'p50'),
                'p95'      => self::num($b, 'p95'),
                'p99'      => self::num($b, 'p99'),
                'avg'      => self::num($b, 'avg'),
                'max'      => self::num($b, 'max'),
                'bytes'    => self::num($b, 'bytes'),
                'errors'   => self::qcount($b, 'errors'),
                'notfound' => self::qcount($b, 'notfound'),
            ];
        }

        $times = [];
        $p50 = [];
        $p95 = [];
        foreach (self::buckets($f, 'over_time') as $b) {
            $times[] = (string) ($b['val'] ?? '');
            $p50[] = self::num($b, 'p50');
            $p95[] = self::num($b, 'p95');
        }

        $heatTimes = [];
        $heat = ['s2' => [], 's3' => [], 's4' => [], 's5' => []];
        foreach (self::buckets($f, 'heat') as $b) {
            $heatTimes[] = (string) ($b['val'] ?? '');
            foreach (array_keys($heat) as $k) {
                $heat[$k][] = self::qcount($b, $k);
            }
        }

        $statuses = [];
        foreach (self::buckets($f, 'statuses') as $b) {
            $statuses[] = ['status' => (int) ($b['val'] ?? 0), 'count' => (int) ($b['count'] ?? 0)];
        }

        $overall = is_array($f['overall'] ?? null) ? $f['overall'] : [];
        $total = (int) ($f['count'] ?? 0);
        $timed = self::qcount($f, 'timed');

        return $this->envelope([
            'kind'      => $kind,
            'who'       => $who,
            // False means the hits core carries no verdicts, so filtering by population
            // is impossible here. The view says so rather than drawing an empty chart.
            'who_supported' => $verdicted > 0,
            'matched_all'   => $matchedAll,
            'requests'  => $total,
            'timed'     => $timed,
            // The share of matched requests that carry %D. The UI refuses to draw the
            // latency charts when this is zero and explains what to change instead.
            'timed_pct' => $total > 0 ? round(($timed / $total) * 100, 1) : 0.0,
            'overall'   => [
                'p50' => self::num($overall, 'p50'),
                'p95' => self::num($overall, 'p95'),
                'p99' => self::num($overall, 'p99'),
                'avg' => self::num($overall, 'avg'),
                'max' => self::num($overall, 'max'),
            ],
            'paths'     => $paths,
            'times'     => $times,
            'p50'       => $p50,
            'p95'       => $p95,
            'heat_times' => $heatTimes,
            'heat'      => $heat,
            'statuses'  => $statuses,
        ]);
    }

    public function body(): void
    {
        // ---- Controls ---------------------------------------------------------
        echo '<section class="card">';
        echo '<div class="card-head"><h2>What to measure</h2><div class="controls">';
        echo '<label for="pf-kind">Request kind</label>';
        echo '<select id="pf-kind">';
        foreach (['html' => 'HTML pages', 'api' => 'API endpoints', 'asset' => 'Static assets', 'all' => 'Everything'] as $v => $l) {
            echo '<option value="' . Security::esc($v) . '">' . Security::esc($l) . '</option>';
        }
        echo '</select>';
        echo '<label for="pf-who">Traffic</label>';
        echo '<select id="pf-who">';
        foreach (['all' => 'All clients', 'human' => 'Humans only'] as $v => $l) {
            echo '<option value="' . Security::esc($v) . '">' . Security::esc($l) . '</option>';
        }
        echo '</select>';
        echo '</div></div>';
        echo '<p class="pop" id="pf-pop">—</p>';

        echo '<div class="stats">';
        foreach ([
            ['p50', 'p50 latency', 'Half of requests were faster than this'],
            ['p95', 'p95 latency', 'One request in twenty was slower'],
            ['p99', 'p99 latency', 'The worst one percent — where timeouts live'],
            ['avg', 'Mean latency', 'Shown for contrast; a long tail drags it away from p50'],
        ] as [$key, $label, $hint]) {
            echo '<div class="stat"><span class="stat-label">' . Security::esc($label) . '</span>';
            echo '<span class="stat-value mono" data-field="' . Security::esc($key) . '">—</span>';
            echo '<span class="stat-hint">' . Security::esc($hint) . '</span></div>';
        }
        echo '</div>';
        echo '<div class="empty" id="pf-nodur" hidden></div>';
        echo '</section>';

        self::chart('pf-time', 'Latency over time', 'Matched requests that carry a duration. p50 and p95 per bucket.', '300px');

        echo '<section class="card">';
        echo '<h2>Slowest paths</h2>';
        echo '<p class="pop" id="pf-paths-pop">—</p>';
        echo '<div class="table-wrap"><table id="pf-paths"><thead><tr>'
            . '<th scope="col">Path</th>'
            . '<th scope="col" class="num">Requests</th>'
            . '<th scope="col" class="num">p50</th>'
            . '<th scope="col" class="num">p95</th>'
            . '<th scope="col" class="num">p99</th>'
            . '<th scope="col" class="bar-col">p50 vs p99</th>'
            . '<th scope="col" class="num">4xx</th>'
            . '<th scope="col" class="num">5xx</th>'
            . '</tr></thead><tbody></tbody></table></div>';
        echo '<div class="empty" id="pf-paths-empty" hidden></div>';
        echo '</section>';

        self::chart('pf-heat', 'Status codes by time', 'All matched requests, grouped into 2xx / 3xx / 4xx / 5xx.', '320px');

        echo '<section class="card">';
        echo '<h2>Status codes</h2>';
        self::pop('All matched requests in the selected range.');
        echo '<div class="table-wrap"><table id="pf-status"><thead><tr>'
            . '<th scope="col">Status</th>'
            . '<th scope="col">Meaning</th>'
            . '<th scope="col" class="num">Requests</th>'
            . '<th scope="col" class="bar-col">Share</th>'
            . '</tr></thead><tbody></tbody></table></div>';
        echo '<div class="empty" id="pf-status-empty" hidden></div>';
        echo '</section>';
    }
}
