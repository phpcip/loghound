<?php
/**
 * Loghound — Index analytics.
 *
 * What is actually happening to one Opensolr search index: how much it is being asked, how
 * long it takes to answer, how often it answers with nothing, and what it answers with.
 *
 * Everything on this page is an aggregate. Not one card fetches a request document, because
 * a facet answers all of it and shipping a customer's query log through the panel to count
 * it would be both slower and a larger privacy surface for no gain. Nothing is stored: the
 * platform already holds this data, and a second copy inside Loghound would be waste.
 *
 * WHAT IS ON SCREEN. Four figures and a volume chart above the fold — the bar Opensolr's own
 * analytics dashboard sets — then the two things that dashboard does not have: the latency
 * distribution, and the handler and status composition.
 * Everything answers under the filter rail, so the same page answers "what is this index
 * doing" and "what is this one caller doing to it" without a second view.
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

final class Indexes extends OpensolrView
{
    /** Upper edge of the QTime histogram, in milliseconds. Anything slower lands in `after`. */
    private const QTIME_CEILING = 1000;

    /** Histogram bucket width, in milliseconds. 100 buckets across the ceiling. */
    private const QTIME_GAP = 10;

    /**
     * The pages this view has, in render order. Drives the navigation and every card's number.
     *
     * @var array<int,array{0:string,1:string}>
     */
    public const SECTIONS = [
        ['ix-headline', 'This index'],
        ['ix-filters', 'Slice'],
        ['ix-volume', 'Volume'],
        ['ix-qtime', 'Latency'],
        ['ix-handlers', 'Handlers'],
    ];

    /**
     * Which page-toolbar controls this view honours.
     *
     * The range bounds the request log through logFqs(). The host selector and the
     * `f[...]` facet bar read the Loghound sessions plane and have no effect on the
     * Opensolr request log at all — this view has its own `lf[...]` filters instead.
     *
     * @return array<int,string>
     */
    public function toolbar(): array
    {
        return [self::SCOPE_RANGE];
    }

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
     * The facet tables on this view.
     *
     * They are CLASSIC facets — `value => count` maps, because the platform's request-log
     * endpoint offers classic faceting only and cannot nest — so each exports as two columns and
     * nothing is lost in the flattening.
     *
     * The headline counters and the QTime histogram are not exportable. The counters are four
     * numbers, and the histogram is a hundred fixed-width buckets whose meaning is the shape they
     * make: exported as rows it would invite somebody to average the bucket index.
     *
     * `core` is carried on all three because the index picker lives only in the page. An export
     * that lost it would silently read whichever index the account happens to list first, under a
     * filename that named the view and not the index — and the index IS the scope on this view.
     *
     * @return array<string,array<string,mixed>>
     */
    public function exports(): array
    {
        return [
            'handlers' => [
                'label'    => 'Handlers',
                'action'   => 'handlers',
                'shape'    => 'map',
                'key'      => 'paths',
                'key_head' => 'Handler',
                'val_head' => 'Requests',
                'control'  => 'Handlers CSV',
                'unit'     => 'handlers',
                'ranked'   => 'ranked by request count',
                'cap'      => 30,
                'carry'    => ['core', 'outcome'],
                'scope'    => $this->logExportScope(),
            ],

            'statuses' => [
                'label'    => 'Status codes',
                'action'   => 'handlers',
                'shape'    => 'map',
                'key'      => 'statuses',
                'key_head' => 'Status',
                'val_head' => 'Requests',
                'control'  => 'Statuses CSV',
                'unit'     => 'status codes',
                'ranked'   => 'ranked by request count',
                'cap'      => 30,
                'carry'    => ['core', 'outcome'],
                'note'     => 'Anything other than 200 is the index refusing or failing.',
                'scope'    => $this->logExportScope(),
            ],

        ];
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
            'qtime'    => $this->qtime(),
            'handlers' => $this->handlers(),
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
            'qtime'    => self::measured($res, 'qtime'),
            'size'     => self::measured($res, 'size'),
            'hits'     => self::measured($res, 'hits'),
        ]);
    }

    /**
     * A stats block, but only when the platform actually recorded the field.
     *
     * ------------------------------------------------------------------------------------
     * "MEAN RESPONSE 0 B" WAS SOLR'S ANSWER TO A QUESTION NOBODY COULD ANSWER
     * ------------------------------------------------------------------------------------
     * Solr's stats component, asked for a field that no document in the result set carries,
     * does not decline. It answers `count: 0` with `min` and `max` null and `mean` and `sum` as
     * 0.0 — the arithmetic identity, which is the correct thing for a summation and the wrong
     * thing to print. The panel read `mean` and ignored `count`, so "the platform recorded no
     * response size for any of these requests" was rendered as the measurement `0 B`, across
     * four requests that had all returned HTTP 200 and had obviously carried a body.
     *
     * That is a fabricated metric — the one thing SPEC §1 forbids outright — and the evidence
     * that it was fabricated was sitting in the same response.
     *
     * THE PLATFORM REALLY DOES NOT RECORD IT, for the traffic this card usually shows. Opensolr
     * builds its analytics documents from two sources: an Apache access log, which has the
     * client address and the response size and is where `ip`, `http_status` and `size` come
     * from; and Solr's own `solr.log`, which has the query, the hit count and the handler but
     * has never seen a socket, so it has no address and no byte count to give. The access-log
     * parser explicitly skips any path containing `select`. So a search index whose traffic is
     * `/select` — which is every search index — produces documents with no `size` at all. Where
     * an address is written anyway it is the placeholder `0.0.0.0`, which the platform's own
     * code treats as "not recorded" everywhere it reads it back.
     *
     * Nothing Loghound can do makes the number exist. What it can do is say so instead of
     * inventing one: `count: 0` yields null here, the front end renders an em-dash, and the card
     * carries the sentence explaining which requests carry a size and which do not.
     *
     * @param array<string,mixed> $res A response envelope from OpensolrLog.
     * @return array<string,mixed>|null
     */
    private static function measured(array $res, string $field): ?array
    {
        $stat = $res['stats'][$field] ?? null;
        if (!is_array($stat)) {
            return null;
        }
        if ((int) ($stat['count'] ?? 0) === 0) {
            return null;
        }

        return $stat;
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
            'stats'   => self::measured($res, 'qtime'),
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

    public function body(): void
    {
        if (!$this->configured()) {
            self::noCredentials();
            return;
        }

        $this->headlineCard();
        $this->filterCard('ix-filters');
        $this->volumeCard('ix-volume');
        $this->qtimeCard();
        $this->handlersCard();
    }

    /** Volume, latency and zero-result share, with the index picker. */
    private function headlineCard(): void
    {
        self::cardOpen('ix-headline', $this->cardNumber('ix-headline'), 'This index', '', self::indexPicker('ix-core'));
        self::skeleton('ix-headline', 'stats', 0, 'Reading the request log');

        self::statRow([
            ['requests', 'Requests',      'Logged by Opensolr for this index in the selected range'],
            ['zero',     'Zero results',  'Requests that matched no documents at all'],
            ['qmean',    'Mean QTime',    'Solr\'s own measure of the time spent answering'],
            ['qmax',     'Slowest',       'The single worst QTime in this range'],
            ['size',     'Mean response', 'How much data each answer carried back'],
        ]);

        /* THE CARD SAYS WHAT THE PLATFORM DOES AND DOES NOT RECORD. `size` is read off an Apache
           access log, and Opensolr's parser for that log skips any path containing `select` — so
           for a search index, which is almost all `/select`, the field is simply not on the
           document and the figure above is an em-dash rather than a fabricated zero. An operator
           who is not told that reads the dash as a Loghound failure and goes looking for a bug
           in the panel. */
        echo '<p class="note">Mean response is read from the platform\'s access-log records, which '
            . 'Opensolr keeps for handlers other than <code>/select</code>. A search index whose traffic '
            . 'is all <code>/select</code> has no response size recorded at all, and the figure is shown '
            . 'as an em-dash rather than as a zero.</p>';

        self::cardClose('ix-headline');
    }

    /** The QTime histogram and the percentiles read off it. */
    private function qtimeCard(): void
    {
        self::cardOpen(
            'ix-qtime',
            $this->cardNumber('ix-qtime'),
            'How long answers take',
            'All logged requests for this index under the current filters. QTime is Solr\'s own measure of '
            . 'the time it spent answering, and it excludes network time and any time the request spent '
            . 'queued — a slow page can have a fast QTime.'
        );
        self::skeleton('ix-qtime', 'chart', 300, 'Building the QTime histogram');

        self::statRow([
            ['p50',  'p50',              'Half of requests were answered within this'],
            ['p95',  'p95',              'One request in twenty took longer'],
            ['p99',  'p99',              'The worst one percent'],
            ['over', 'Over the ceiling', 'Requests slower than the histogram\'s last bucket'],
        ]);
        echo '<div class="chart" id="ix-qtime-chart" style="height:280px"></div>';

        self::cardClose('ix-qtime');
    }

    /** Handlers and status codes, side by side. */
    private function handlersCard(): void
    {
        self::cardOpen(
            'ix-handlers',
            $this->cardNumber('ix-handlers'),
            'Handlers and status codes',
            'All logged requests for this index under the current filters, grouped by the handler that '
            . 'served them and by the status the platform recorded.',
            $this->exportTool('handlers') . $this->exportTool('statuses')
        );
        self::skeleton('ix-handlers', 'rows', 0, 'Faceting handlers and status codes');

        echo '<div class="split-card">';
        echo '<div class="split-half"><h2>Handlers</h2>'
            . '<p class="split-note">Which endpoint on the index took the request. A handler that is '
            . 'neither your search box nor a crawler — an ingest or callback path, say — is a caller '
            . 'worth naming, and clicking a row filters the whole page to it.</p>'
            . '<div class="chart" id="ix-paths-chart" style="height:240px"></div>'
            . '<div class="table-wrap"><table id="ix-paths-table"><thead><tr>'
            . '<th scope="col">Handler</th><th scope="col" class="num">Requests</th>'
            . '<th scope="col" class="bar-col">Share</th></tr></thead><tbody></tbody></table></div></div>';
        echo '<div class="split-half"><h2>Status codes</h2>'
            . '<p class="split-note">Anything other than 200 is the index refusing or failing.</p>'
            . '<div class="chart" id="ix-status-chart" style="height:240px"></div>'
            . '<div class="table-wrap"><table id="ix-status-table"><thead><tr>'
            . '<th scope="col">Status</th><th scope="col" class="num">Requests</th>'
            . '<th scope="col" class="bar-col">Share</th></tr></thead><tbody></tbody></table></div></div>';
        echo '</div>';

        self::cardClose('ix-handlers');
    }
}
