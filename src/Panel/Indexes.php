<?php
/**
 * Loghound — Index analytics.
 *
 * What is actually happening to one Opensolr search index: how much it is being asked, how
 * long it takes to answer, how often it answers with nothing, what it answers with, and
 * which node did the answering.
 *
 * Everything on this page is an aggregate. Not one card fetches a request document, because
 * a facet answers all of it and shipping a customer's query log through the panel to count
 * it would be both slower and a larger privacy surface for no gain. Nothing is stored: the
 * platform already holds this data, and a second copy inside Loghound would be waste.
 *
 * THE HISTOGRAM IS BUCKETED AND SAYS SO. The platform's request-log endpoint rewrites any
 * parameter name containing an underscore into a dotted Solr parameter and strips braces
 * and quotes out of its value, so a JSON Facet — and with it Solr's exact `percentile()`
 * aggregate — cannot survive the trip. Classic range faceting can, so the QTime
 * distribution is a fixed-width histogram and the percentiles read off it are reported as
 * "at most" a bucket edge. An approximate number labelled as approximate is honest; a
 * precise-looking number that is not precise is not.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\OpensolrLog;
use Loghound\Security;

final class Indexes extends OpensolrView
{
    /** Upper edge of the QTime histogram, in milliseconds. Anything slower lands in `after`. */
    private const QTIME_CEILING = 1000;

    /** Histogram bucket width, in milliseconds. 100 buckets across the ceiling. */
    private const QTIME_GAP = 10;

    public function slug(): string
    {
        return 'indexes';
    }

    public function title(): string
    {
        return 'Index analytics';
    }

    public function subtitle(): string
    {
        return 'What your Opensolr search indexes are being asked, and how well they answer.';
    }

    /**
     * @return array<string,mixed>
     */
    public function api(string $action): array
    {
        $shared = $this->sharedApi($action);
        if ($shared !== null) {
            return $shared;
        }

        return match ($action) {
            'headline' => $this->headline(),
            'volume'   => $this->volume(),
            'qtime'    => $this->qtime(),
            'handlers' => $this->handlers(),
            'nodes'    => $this->nodes(),
            default    => ['error' => 'Unknown action'],
        };
    }

    /**
     * Volume, latency and the zero-result share, in one call.
     *
     * The zero-result count comes from a range facet on `hits` with a single bucket rather
     * than from a second query: `[0 TO 1)` is the requests that matched nothing, and
     * everything at or above 1 falls into the facet's `after` counter. One call, two
     * numbers, no arithmetic that could drift apart.
     *
     * @return array<string,mixed>
     */
    private function headline(): array
    {
        $res = $this->fetch([
            'fq'           => $this->logFqs(),
            'rows'         => 0,
            'stats_fields' => ['qtime', 'size', 'hits'],
            'ranges'       => ['hits' => ['start' => '0', 'end' => '1', 'gap' => '1', 'other' => 'all']],
        ]);

        $hits = $res['facet_ranges']['hits'] ?? null;
        $zero = is_array($hits) ? (int) ($hits['counts']['0'] ?? 0) : null;
        $total = (int) $res['numFound'];

        return $this->logEnvelope($res, [
            'zero'     => $zero,
            'zero_pct' => ($zero !== null && $total > 0) ? round(($zero / $total) * 100, 1) : null,
            'qtime'    => $res['stats']['qtime'] ?? null,
            'size'     => $res['stats']['size'] ?? null,
            'hits'     => $res['stats']['hits'] ?? null,
        ]);
    }

    /**
     * Request volume over time, with the zero-result share drawn underneath it.
     *
     * Two calls rather than one, because the platform's endpoint cannot express a nested
     * facet: the second is the same range facet with `hits:0` added, which is cheap and is
     * the only way to see whether a spike in traffic was a spike in USEFUL traffic.
     *
     * @return array<string,mixed>
     */
    private function volume(): array
    {
        $range = ['date' => [
            'start' => (string) $this->range['start'],
            'end'   => 'NOW',
            'gap'   => (string) $this->range['gap'],
            'other' => 'none',
        ]];

        $all = $this->fetch(['fq' => $this->logFqs(), 'rows' => 0, 'ranges' => $range]);
        if ($all['state'] !== 'ok') {
            return $this->logEnvelope($all, ['times' => [], 'all' => [], 'zero' => [], 'zero_total' => 0]);
        }

        $empty = $this->fetch([
            'fq'     => array_merge($this->logFqs(), [OpensolrLog::numericFq('hits', '0', '0')]),
            'rows'   => 0,
            'ranges' => $range,
        ]);

        $allCounts  = (array) ($all['facet_ranges']['date']['counts'] ?? []);
        $zeroCounts = (array) ($empty['facet_ranges']['date']['counts'] ?? []);

        $times = array_keys($allCounts);
        $zero = [];
        foreach ($times as $bucket) {
            $zero[] = (int) ($zeroCounts[$bucket] ?? 0);
        }

        return $this->logEnvelope($all, [
            'times'     => $times,
            'all'       => array_values(array_map('intval', $allCounts)),
            'zero'      => $zero,
            'zero_total' => (int) $empty['numFound'],
        ]);
    }

    /**
     * The QTime distribution, as a fixed-width histogram.
     *
     * @return array<string,mixed>
     */
    private function qtime(): array
    {
        $res = $this->fetch([
            'fq'           => $this->logFqs(),
            'rows'         => 0,
            'stats_fields' => ['qtime'],
            'ranges'       => ['qtime' => [
                'start' => '0',
                'end'   => (string) self::QTIME_CEILING,
                'gap'   => (string) self::QTIME_GAP,
                'other' => 'all',
            ]],
        ]);

        $range = $res['facet_ranges']['qtime'] ?? ['counts' => [], 'after' => null];

        return $this->logEnvelope($res, [
            'buckets' => (array) ($range['counts'] ?? []),
            'over'    => $range['after'] ?? null,
            'gap'     => self::QTIME_GAP,
            'ceiling' => self::QTIME_CEILING,
            'stats'   => $res['stats']['qtime'] ?? null,
        ]);
    }

    /**
     * Which handler served what, and with which status code.
     *
     * @return array<string,mixed>
     */
    private function handlers(): array
    {
        $res = $this->fetch([
            'fq'           => $this->logFqs(),
            'rows'         => 0,
            'facet_fields' => ['path', 'http_status'],
            'facet_limit'  => 30,
        ]);

        return $this->logEnvelope($res, [
            'paths'    => (array) ($res['facet_fields']['path'] ?? []),
            'statuses' => (array) ($res['facet_fields']['http_status'] ?? []),
        ]);
    }

    /**
     * Which node in the cluster answered, and how large the answers were.
     *
     * A cluster is one master and N read-only replicas, so an even split across the
     * replicas is the healthy shape and a node missing from this table is a node that
     * stopped taking traffic.
     *
     * @return array<string,mixed>
     */
    private function nodes(): array
    {
        $res = $this->fetch([
            'fq'           => $this->logFqs(),
            'rows'         => 0,
            'facet_fields' => ['param_hostname'],
            'facet_limit'  => 30,
            'stats_fields' => ['size'],
        ]);

        return $this->logEnvelope($res, [
            'nodes' => (array) ($res['facet_fields']['param_hostname'] ?? []),
            'size'  => $res['stats']['size'] ?? null,
        ]);
    }

    public function body(): void
    {
        if (!$this->configured()) {
            self::noCredentials();
            return;
        }

        $this->headlineCard();

        self::chart(
            'ix-volume',
            '02',
            'Requests over time',
            'Every request the platform logged for this index in the selected range, bucketed. '
            . 'The second series is the subset that matched no documents.',
            300,
            'Faceting request volume'
        );

        $this->qtimeCard();
        $this->handlersCard();
        $this->nodesCard();
    }

    /** Volume, latency and zero-result share, with the index picker. */
    private function headlineCard(): void
    {
        self::cardOpen('ix-headline', '01', 'This index', '', self::indexPicker('ix-core'));
        self::skeleton('ix-headline', 'stats', 0, 'Reading the request log');

        echo '<div class="stats">';
        foreach ([
            ['requests', 'Requests',       'Logged by Opensolr for this index in the selected range'],
            ['zero',     'Zero results',   'Requests that matched no documents at all'],
            ['qmean',    'Mean QTime',     'Solr\'s own measure of the time spent answering'],
            ['qmax',     'Slowest',        'The single worst QTime in this range'],
            ['size',     'Mean response',  'How much data each answer carried back'],
        ] as [$key, $label, $hint]) {
            echo '<div class="stat"><span class="stat-label">' . Security::esc($label) . '</span>';
            echo '<span class="stat-value mono" data-field="' . Security::esc($key) . '">—</span>';
            echo '<span class="stat-hint">' . Security::esc($hint) . '</span></div>';
        }
        echo '</div>';

        self::cardClose('ix-headline');
    }

    /** The QTime histogram and the percentiles read off it. */
    private function qtimeCard(): void
    {
        self::cardOpen(
            'ix-qtime',
            '03',
            'How long answers take',
            'All logged requests for this index in the selected range. QTime is Solr\'s own measure of '
            . 'the time it spent answering, and it excludes network time and any time the request spent '
            . 'queued — a slow page can have a fast QTime.'
        );
        self::skeleton('ix-qtime', 'chart', 300, 'Building the QTime histogram');

        echo '<div class="stats">';
        foreach ([
            ['p50', 'p50',  'Half of requests were answered within this'],
            ['p95', 'p95',  'One request in twenty took longer'],
            ['p99', 'p99',  'The worst one percent'],
            ['over', 'Over the ceiling', 'Requests slower than the histogram\'s last bucket'],
        ] as [$key, $label, $hint]) {
            echo '<div class="stat"><span class="stat-label">' . Security::esc($label) . '</span>';
            echo '<span class="stat-value mono" data-field="' . Security::esc($key) . '">—</span>';
            echo '<span class="stat-hint">' . Security::esc($hint) . '</span></div>';
        }
        echo '</div>';
        echo '<div class="chart" id="ix-qtime-chart" style="height:280px"></div>';

        self::cardClose('ix-qtime');
    }

    /** Handlers and status codes, side by side. */
    private function handlersCard(): void
    {
        self::cardOpen(
            'ix-handlers',
            '04',
            'Handlers and status codes',
            'All logged requests for this index in the selected range, grouped by the handler that '
            . 'served them and by the status the platform recorded.'
        );
        self::skeleton('ix-handlers', 'rows', 0, 'Faceting handlers and status codes');

        echo '<div class="split-card">';
        echo '<div class="split-half"><h2>Handlers</h2>'
            . '<p class="split-note">Which endpoint on the index took the request.</p>'
            . '<div class="table-wrap"><table id="ix-paths-table"><thead><tr>'
            . '<th scope="col">Handler</th><th scope="col" class="num">Requests</th>'
            . '<th scope="col" class="bar-col">Share</th></tr></thead><tbody></tbody></table></div></div>';
        echo '<div class="split-half"><h2>Status codes</h2>'
            . '<p class="split-note">Anything other than 200 is the index refusing or failing.</p>'
            . '<div class="table-wrap"><table id="ix-status-table"><thead><tr>'
            . '<th scope="col">Status</th><th scope="col" class="num">Requests</th>'
            . '<th scope="col" class="bar-col">Share</th></tr></thead><tbody></tbody></table></div></div>';
        echo '</div>';

        self::cardClose('ix-handlers');
    }

    /** Which cluster node answered. */
    private function nodesCard(): void
    {
        self::cardOpen(
            'ix-nodes',
            '05',
            'Which node answered',
            'All logged requests for this index in the selected range, grouped by the cluster node that '
            . 'served them.'
        );
        self::skeleton('ix-nodes', 'rows', 0, 'Faceting cluster nodes');

        echo '<div class="table-wrap"><table id="ix-nodes-table"><thead><tr>'
            . '<th scope="col">Node</th>'
            . '<th scope="col" class="num">Requests</th>'
            . '<th scope="col" class="bar-col">Share</th>'
            . '</tr></thead><tbody></tbody></table></div>';
        echo '<p class="pop" id="ix-nodes-note"></p>';

        self::cardClose('ix-nodes');
    }
}
