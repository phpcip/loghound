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
            'headline' => $this->headline(),
            'latency'  => $this->latency(),
            'paths'    => $this->paths(),
            'status'   => $this->status(),
            default    => ['error' => 'Unknown action'],
        };
    }

    /**
     * The request scope every action on this view shares.
     *
     * Mixing a 3ms cache hit on a PNG into the same percentile as a rendered page
     * produces a number that describes neither, so the default is HTML only and both
     * toggles are allowlists.
     *
     * @return array{fq:array<int,string>,kind:string,who:string,scope:?string}
     */
    private function scope(): array
    {
        $kind = self::param('kind', ['html', 'asset', 'api', 'all'], 'html');
        $who  = self::param('who', ['all', 'human'], 'all');

        $fqs = $this->hitFqs();
        if ($kind !== 'all') {
            $fqs[] = Query::term('kind_s', $kind);
        }

        return [
            'fq'    => $fqs,
            'kind'  => $kind,
            'who'   => $who,
            'scope' => $who === 'human' ? Query::POP_HUMAN : null,
        ];
    }

    /**
     * Wrap a facet body in the population scope, keeping one probe outside it.
     *
     * SPEC §4.1 does not define `bot_verdict_s` on the hits core — the verdict lives on
     * the session document — so the "humans only" toggle works only where the scorer
     * copies it down. `verdicted` is counted over the UNSCOPED domain so the view can say
     * the filter has no effect on this deployment instead of drawing an empty chart. A
     * `domain` filter would be the natural way to express that, but Solr.php accepts only
     * `domain.excludeTags`, so a nested query facet does the same job.
     *
     * @param array<string,mixed> $facet
     * @return array<string,mixed>
     */
    private static function scoped(array $facet, ?string $scopeFilter): array
    {
        $probe = ['verdicted' => ['type' => 'query', 'q' => 'bot_verdict_s:[* TO *]']];
        return $scopeFilter === null
            ? $facet + $probe
            : ['scope' => ['type' => 'query', 'q' => $scopeFilter, 'facet' => $facet]] + $probe;
    }

    /**
     * Read the scoped half of a response back out.
     *
     * @param array<string,mixed> $raw
     * @return array<string,mixed>
     */
    private static function unscope(array $raw, ?string $scopeFilter): array
    {
        if ($scopeFilter === null) {
            return $raw;
        }
        return is_array($raw['scope'] ?? null) ? $raw['scope'] : ['count' => 0];
    }

    /**
     * The percentile headline and the coverage that every latency number depends on.
     *
     * @return array<string,mixed>
     */
    private function headline(): array
    {
        $scope = $this->scope();
        $percentiles = [
            'p50' => 'percentile(dur_us_l,50)',
            'p95' => 'percentile(dur_us_l,95)',
            'p99' => 'percentile(dur_us_l,99)',
            'avg' => 'avg(dur_us_l)',
            'max' => 'max(dur_us_l)',
        ];

        $raw = $this->gw->facet('perf.headline', $this->gw->hitsCore(), [
            'q'  => '*:*',
            'fq' => $scope['fq'],
        ], self::scoped([
            'overall' => ['type' => 'query', 'q' => '*:*', 'facet' => $percentiles],
            'timed'   => ['type' => 'query', 'q' => 'dur_us_l:[* TO *]'],
        ], $scope['scope']));

        $f = self::unscope($raw, $scope['scope']);
        $overall = is_array($f['overall'] ?? null) ? $f['overall'] : [];
        $total = (int) ($f['count'] ?? 0);
        $timed = self::qcount($f, 'timed');

        return $this->envelope([
            'kind'          => $scope['kind'],
            'who'           => $scope['who'],
            'who_supported' => self::qcount($raw, 'verdicted') > 0,
            'requests'      => $total,
            'timed'         => $timed,
            'timed_pct'     => $total > 0 ? round(($timed / $total) * 100, 1) : 0.0,
            'overall'       => [
                'p50' => self::num($overall, 'p50'),
                'p95' => self::num($overall, 'p95'),
                'p99' => self::num($overall, 'p99'),
                'avg' => self::num($overall, 'avg'),
                'max' => self::num($overall, 'max'),
            ],
        ]);
    }

    /**
     * Latency percentiles per time bucket, so a regression has a timestamp.
     *
     * Buckets with no timed request report null rather than zero, and the chart draws a
     * gap rather than a line through a number nobody measured.
     *
     * @return array<string,mixed>
     */
    private function latency(): array
    {
        $scope = $this->scope();

        $raw = $this->gw->facet('perf.latency', $this->gw->hitsCore(), [
            'q'  => '*:*',
            'fq' => $scope['fq'],
        ], self::scoped([
            'over_time' => [
                'type'  => 'range',
                'field' => 'ts',
                'start' => $this->range['start'],
                'end'   => 'NOW',
                'gap'   => $this->range['gap'],
                'facet' => ['p50' => 'percentile(dur_us_l,50)', 'p95' => 'percentile(dur_us_l,95)'],
            ],
            'timed' => ['type' => 'query', 'q' => 'dur_us_l:[* TO *]'],
        ], $scope['scope']));

        $f = self::unscope($raw, $scope['scope']);
        $times = [];
        $p50 = [];
        $p95 = [];
        foreach (self::buckets($f, 'over_time') as $bucket) {
            $times[] = (string) ($bucket['val'] ?? '');
            $p50[] = self::num($bucket, 'p50');
            $p95[] = self::num($bucket, 'p95');
        }

        return $this->envelope([
            'timed' => self::qcount($f, 'timed'),
            'times' => $times,
            'p50'   => $p50,
            'p95'   => $p95,
        ]);
    }

    /**
     * Per-path percentiles for the busiest paths.
     *
     * @return array<string,mixed>
     */
    private function paths(): array
    {
        $scope = $this->scope();
        $percentiles = [
            'p50' => 'percentile(dur_us_l,50)',
            'p95' => 'percentile(dur_us_l,95)',
            'p99' => 'percentile(dur_us_l,99)',
            'avg' => 'avg(dur_us_l)',
            'max' => 'max(dur_us_l)',
        ];

        $raw = $this->gw->facet('perf.paths', $this->gw->hitsCore(), [
            'q'  => '*:*',
            'fq' => $scope['fq'],
        ], self::scoped([
            'paths' => [
                'type'  => 'terms',
                'field' => 'path_s',
                'limit' => Security::clampInt($_GET['limit'] ?? null, 5, 100, 25),
                'sort'  => 'count desc',
                'facet' => $percentiles + [
                    'bytes'    => 'avg(bytes_l)',
                    'errors'   => ['type' => 'query', 'q' => 'status_i:[500 TO 599]'],
                    'notfound' => ['type' => 'query', 'q' => 'status_i:[400 TO 499]'],
                    'timed'    => ['type' => 'query', 'q' => 'dur_us_l:[* TO *]'],
                ],
            ],
            'timed' => ['type' => 'query', 'q' => 'dur_us_l:[* TO *]'],
        ], $scope['scope']));

        $f = self::unscope($raw, $scope['scope']);
        $rows = [];
        foreach (self::buckets($f, 'paths') as $bucket) {
            $rows[] = [
                'path'     => (string) ($bucket['val'] ?? ''),
                'requests' => (int) ($bucket['count'] ?? 0),
                'timed'    => self::qcount($bucket, 'timed'),
                'p50'      => self::num($bucket, 'p50'),
                'p95'      => self::num($bucket, 'p95'),
                'p99'      => self::num($bucket, 'p99'),
                'avg'      => self::num($bucket, 'avg'),
                'max'      => self::num($bucket, 'max'),
                'bytes'    => self::num($bucket, 'bytes'),
                'errors'   => self::qcount($bucket, 'errors'),
                'notfound' => self::qcount($bucket, 'notfound'),
            ];
        }

        return $this->envelope([
            'timed' => self::qcount($f, 'timed'),
            'paths' => $rows,
        ]);
    }

    /**
     * Status classes over time, plus the exact codes seen.
     *
     * Classes rather than individual codes on the chart: an operator scanning for trouble
     * wants to know when the 5xx happened, not to read forty-seven rows.
     *
     * @return array<string,mixed>
     */
    private function status(): array
    {
        $scope = $this->scope();

        $raw = $this->gw->facet('perf.status', $this->gw->hitsCore(), [
            'q'  => '*:*',
            'fq' => $scope['fq'],
        ], self::scoped([
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
            'statuses' => ['type' => 'terms', 'field' => 'status_i', 'limit' => 20, 'sort' => 'count desc'],
        ], $scope['scope']));

        $f = self::unscope($raw, $scope['scope']);

        $times = [];
        $heat = ['s2' => [], 's3' => [], 's4' => [], 's5' => []];
        foreach (self::buckets($f, 'heat') as $bucket) {
            $times[] = (string) ($bucket['val'] ?? '');
            foreach (array_keys($heat) as $key) {
                $heat[$key][] = self::qcount($bucket, $key);
            }
        }

        $statuses = [];
        foreach (self::buckets($f, 'statuses') as $bucket) {
            $statuses[] = ['status' => (int) ($bucket['val'] ?? 0), 'count' => (int) ($bucket['count'] ?? 0)];
        }

        return $this->envelope([
            'heat_times' => $times,
            'heat'       => $heat,
            'statuses'   => $statuses,
        ]);
    }

    public function body(): void
    {
        $this->headlineCard();
        self::chart(
            'pf-time',
            '02',
            'Latency over time',
            'Matched requests that carry a duration. p50 and p95 per bucket.',
            300,
            'Computing latency percentiles'
        );
        $this->pathsCard();
        $this->statusCard();
    }

    /** The percentile headline, its controls and the missing-duration explanation. */
    private function headlineCard(): void
    {
        $tools = '<div class="controls">';
        $tools .= '<label for="pf-kind">Requests</label><select id="pf-kind">';
        foreach ([
            'html'  => 'HTML pages',
            'api'   => 'API endpoints',
            'asset' => 'Static assets',
            'all'   => 'Everything',
        ] as $value => $label) {
            $tools .= '<option value="' . Security::esc($value) . '">' . Security::esc($label) . '</option>';
        }
        $tools .= '</select>';
        $tools .= '<label for="pf-who">Traffic</label><select id="pf-who">';
        foreach (['all' => 'All clients', 'human' => 'Humans only'] as $value => $label) {
            $tools .= '<option value="' . Security::esc($value) . '">' . Security::esc($label) . '</option>';
        }
        $tools .= '</select></div>';

        self::cardOpen('pf-headline', '01', 'What to measure', '', $tools);
        self::skeleton('pf-headline', 'stats', 0, 'Computing latency percentiles');

        echo '<div class="stats">';
        foreach ([
            ['p50', 'p50 latency',  'Half of requests were faster than this'],
            ['p95', 'p95 latency',  'One request in twenty was slower'],
            ['p99', 'p99 latency',  'The worst one percent — where timeouts live'],
            ['avg', 'Mean latency', 'Shown for contrast; a long tail drags it away from p50'],
        ] as [$key, $label, $hint]) {
            echo '<div class="stat"><span class="stat-label">' . Security::esc($label) . '</span>';
            echo '<span class="stat-value mono" data-field="' . Security::esc($key) . '">—</span>';
            echo '<span class="stat-hint">' . Security::esc($hint) . '</span></div>';
        }
        echo '</div>';
        echo '<div class="empty" id="pf-nodur" hidden></div>';

        self::cardClose('pf-headline');
    }

    /** Slowest paths. */
    private function pathsCard(): void
    {
        self::cardOpen(
            'pf-paths',
            '03',
            'Slowest paths',
            'The busiest paths in this range, with their latency percentiles. The bar compares p50 to p99 on a '
            . 'shared scale — a long bar means the median visitor and the unlucky one percent had different days.'
        );
        self::skeleton('pf-paths', 'rows', 0, 'Computing per-path percentiles');

        echo '<div class="table-wrap"><table id="pf-paths-table"><thead><tr>'
            . '<th scope="col">Path</th>'
            . '<th scope="col" class="num">Requests</th>'
            . '<th scope="col" class="num">p50</th>'
            . '<th scope="col" class="num">p95</th>'
            . '<th scope="col" class="num">p99</th>'
            . '<th scope="col" class="bar-col">p50 vs p99</th>'
            . '<th scope="col" class="num">4xx</th>'
            . '<th scope="col" class="num">5xx</th>'
            . '</tr></thead><tbody></tbody></table></div>';

        self::cardClose('pf-paths');
    }

    /** Status classes over time, and the exact codes. */
    private function statusCard(): void
    {
        self::cardOpen(
            'pf-status',
            '04',
            'Status codes',
            'All matched requests in the selected range, grouped into 2xx / 3xx / 4xx / 5xx.'
        );
        self::skeleton('pf-status', 'chart', 320, 'Faceting response codes');

        echo '<div class="chart" id="pf-heat" style="height:320px"></div>';
        echo '<div class="table-wrap"><table id="pf-status-table"><thead><tr>'
            . '<th scope="col">Status</th>'
            . '<th scope="col">Meaning</th>'
            . '<th scope="col" class="num">Requests</th>'
            . '<th scope="col" class="bar-col">Share</th>'
            . '</tr></thead><tbody></tbody></table></div>';

        self::cardClose('pf-status');
    }
}
