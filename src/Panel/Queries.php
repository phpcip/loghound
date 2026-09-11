<?php
/**
 * Loghound — Query analysis.
 *
 * THE CENTREPIECE, AND WHY. A request log grouped by exact query string is useless: a
 * search box produces a different string for every visitor, so the "top queries" table is
 * a list of one-hit wonders and the expensive pattern underneath it never surfaces. This
 * page groups by SHAPE — the query with its literals removed and its structure kept, see
 * \Loghound\OpensolrShape — so `title:"foo"` and `title:"bar"` are one row and
 * `title:"foo"` and `body:"foo"` are two.
 *
 * Once queries are grouped that way, the single most actionable number in search becomes
 * visible and nobody else surfaces it: WHICH SHAPES RETURN NOTHING. A shape that runs ten
 * thousand times a day and matches zero documents every time is a broken filter, a field
 * that was renamed, or a UI sending a query the schema cannot answer — and on an
 * ungrouped list it is invisible, because each of those ten thousand requests looks
 * unique.
 *
 * HOW THE SCAN WORKS, AND WHY IT IS NOT ONE REQUEST. A shape cannot be faceted: it has to
 * be computed from `full_request`, which means reading documents. So the analysis is a
 * SEQUENCE of small bounded pages — each API action here reads exactly one page, folds it
 * into per-shape aggregates and hands back a cursor. The browser merges pages as they
 * arrive and shows how far it has got. No single request can time out however large the
 * log is, the card is useful before the scan finishes, and the number of pages is capped
 * so a busy index cannot turn one page view into a thousand API calls.
 *
 * The population is stated on every card, because a capped scan covers a sample and a
 * number that does not say what it counted is a lie. Nothing scanned is stored: the pages
 * are folded into counts and discarded within the request that fetched them.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\OpensolrShape;
use Loghound\Security;

final class Queries extends OpensolrView
{
    /**
     * Documents read per scan step.
     *
     * One step is one call to the platform and one rewrite of the job context, so this
     * trades API calls against payload size and against how often the operator sees the
     * table grow. 400 documents is roughly a quarter of a megabyte of recorded requests,
     * comfortably inside the client's timeout, and it keeps the step list on screen
     * readable.
     */
    private const SCAN_ROWS = 400;

    /**
     * How many steps a scan plans, and therefore how deep it goes.
     *
     * 20 steps of 400 is a ceiling of EIGHT THOUSAND requests per scan, which is the
     * honest cost of this feature: twenty bounded reads of somebody else's platform per
     * scan, about fifteen seconds of polling, and a job context that stays well under a
     * megabyte. It is a cap, not a target — a step that reaches the end of the log stops
     * the job early, so a quiet index finishes in one step and only a busy one pays the
     * full twenty.
     *
     * The plan length is FIXED. The store records `total` when the job is created and the
     * progress fraction is read against it, so a planner that grew or shrank its plan
     * between polls would report a fraction of the wrong denominator.
     */
    private const SCAN_STEPS = 20;

    /**
     * Distinct shapes retained in the job context.
     *
     * The context is rewritten on every step and shipped to the browser on every poll, so
     * it has to stay small. Past this many shapes the scan stops adding new ones and counts
     * them instead — the tail of a shape distribution is one-off queries, and the honest
     * thing is to say how many were left out rather than to grow without bound or to drop
     * the ones already counted.
     */
    private const SCAN_MAX_SHAPES = 250;

    /** Job kinds this view hosts: the whole log, and the requests that matched nothing. */
    private const KIND_ALL = 'shape_scan';
    private const KIND_ZERO = 'empty_scan';

    /**
     * The cards, in render order. Drives the jump bar and every card's number.
     *
     * @var array<int,array{0:string,1:string}>
     */
    protected const SECTIONS = [
        ['qy-filters', 'Slice'],
        ['qy-volume', 'Volume'],
        ['qy-shapes', 'Shapes'],
        ['qy-latency', 'Latency'],
        ['qy-zero', 'Finds nothing'],
        ['qy-slow', 'Slowest'],
        ['qy-explain', 'Reading these'],
    ];

    /**
     * QTime histogram edges, in milliseconds.
     *
     * Log-scaled because query latency is: the interesting structure is between 1 ms and
     * 100 ms, and a linear histogram wide enough to hold a 30-second outlier would put
     * every real query in its first bucket. Sent to the browser with every page so the
     * merge on the client cannot drift out of step with the fold on the server.
     *
     * @var array<int,int>
     */
    private const QTIME_EDGES = [0, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 30000];

    public function slug(): string
    {
        return 'queries';
    }

    public function title(): string
    {
        return 'Query analysis';
    }

    public function subtitle(): string
    {
        return 'The shapes of query your indexes actually run — and which of them find nothing.';
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
            'slowest' => $this->slowest(),
            default   => ['error' => 'Unknown action'],
        };
    }

    /** @return array<int,string> */
    protected function jobKinds(): array
    {
        return [self::KIND_ALL, self::KIND_ZERO];
    }

    /**
     * @return array<string,callable(array<string,mixed>):array<int,array{label:string,run:callable}>>
     */
    protected function jobPlans(): array
    {
        return [
            self::KIND_ALL  => fn (array $ctx): array => $this->planScan(false),
            self::KIND_ZERO => fn (array $ctx): array => $this->planScan(true),
        ];
    }

    /**
     * Validate the parameters for one scan before a job exists.
     *
     * The index name is checked twice and for two different things: that it is shaped like
     * an index name at all, and that it is one this account actually owns. The second check
     * is the one that matters and it is not the platform's to make for us here — the
     * platform would refuse the read later, but by then the name is in the store, in a step
     * note and in every poll envelope. Refusing before the job exists keeps a name the
     * account has no business naming out of all three.
     *
     * If the index list cannot be read, the start is refused. A check that cannot be
     * performed is a failed check.
     *
     * The time range travels as a parameter rather than being read from the query string,
     * because a poll is a POST to the bare view URL and carries no range at all. It is also
     * what makes two ranges two jobs rather than one job answering for whichever range
     * happened to start it.
     *
     * @return array<string,scalar|null>|null
     */
    protected function jobParams(string $kind): ?array
    {
        if ($this->gw->isDemo()) {
            return null;
        }

        $core = $_POST['core'] ?? '';
        if (!is_string($core) || $core === '' || !Security::isSafeCoreName($core)) {
            return null;
        }

        $owned = $this->indexes();
        if ($owned['state'] !== 'ok' || !in_array($core, $owned['indexes'], true)) {
            return null;
        }

        $range = $_POST['range'] ?? '';
        $ranges = Query::ranges();
        if (!is_string($range) || !isset($ranges[$range])) {
            return null;
        }

        return [
            'core'    => $core,
            'range'   => $range,
            'lf'      => self::postedFilters(),
            'outcome' => self::postedOutcome(),
        ];
    }

    /**
     * The packed filter set this scan is to run under, from the POST body.
     *
     * A poll — and a start — is a POST to the bare view URL and carries no query string, so
     * the filters cannot be read from `$_GET` the way every GET-driven card reads them. The
     * front end therefore posts back the opaque string the server itself put in the payload
     * it is looking at (`lf_packed`), and it is decoded and re-encoded HERE rather than
     * trusted: decodeLogFilters() drops any field that is not in the allowlist and caps every
     * value, so a hand-forged value can do no more than a hand-forged query string could.
     *
     * Re-encoding also canonicalises it, which matters because the params are a job's
     * identity: two spellings of the same filter set must not become two scans.
     */
    private static function postedFilters(): string
    {
        $raw = $_POST['lf'] ?? '';
        if (!is_string($raw) || $raw === '' || strlen($raw) > 256) {
            return '';
        }

        $parts = [];
        foreach (self::decodeLogFilters($raw) as $field => $values) {
            $parts[] = $field . '=' . implode(',', array_map('rawurlencode', $values));
        }
        $packed = implode(';', $parts);

        return strlen($packed) > 256 ? '' : $packed;
    }

    /** The outcome slice this scan is to run under, from the POST body. */
    private static function postedOutcome(): string
    {
        $raw = $_POST['outcome'] ?? '';
        return is_string($raw) && isset(self::OUTCOMES[$raw]) ? $raw : '';
    }

    /**
     * Build the fixed step plan for a scan.
     *
     * Every step is the same bounded unit of work at a different offset, so the plan is
     * generated rather than written out. The labels name the offset range each step reads,
     * which is what makes the progress list say something an operator can check.
     *
     * @return array<int,array{label:string,run:callable}>
     */
    private function planScan(bool $emptyOnly): array
    {
        $steps = [];
        for ($page = 0; $page < self::SCAN_STEPS; $page++) {
            $from = $page * self::SCAN_ROWS;
            $steps[] = [
                'label' => 'Requests ' . number_format($from + 1) . '–' . number_format($from + self::SCAN_ROWS),
                'run'   => function (array $ctx) use ($page, $emptyOnly): array {
                    return $this->scanStep($ctx, $page, $emptyOnly);
                },
            ];
        }
        return $steps;
    }

    /**
     * Read one page of the request log and fold it into the job's running aggregates.
     *
     * Everything the step needs comes out of the context, and every value is re-validated
     * on the way out of it. The context is persisted between polls, so treating it as
     * trusted would mean trusting a store that a future bug could write anything into; a
     * step that cannot make sense of its own parameters fails loudly instead.
     *
     * A page that reaches the end of the log sets `stop`, which finishes the job early
     * rather than making nineteen more calls for nothing.
     *
     * @param array<string,mixed> $ctx
     * @return array<string,mixed>
     */
    private function scanStep(array $ctx, int $page, bool $emptyOnly): array
    {
        $core = (string) ($ctx['core'] ?? '');
        $rangeKey = (string) ($ctx['range'] ?? '');
        $ranges = Query::ranges();

        if (!Security::isSafeCoreName($core) || !isset($ranges[$rangeKey])) {
            return [
                'ok'     => false,
                'note'   => 'invalid',
                'detail' => 'The operation lost the index or the time range it was started with.',
            ];
        }

        $packed = (string) ($ctx['lf'] ?? '');
        $outcome = (string) ($ctx['outcome'] ?? '');
        if (!isset(self::OUTCOMES[$outcome])) {
            $outcome = '';
        }

        $fqs = self::logFqsFor(
            (string) $ranges[$rangeKey]['start'],
            self::decodeLogFilters($packed),
            $emptyOnly ? 'zero' : $outcome
        );

        $from = $page * self::SCAN_ROWS;
        $res = $this->log()->log($core, [
            'fq'    => $fqs,
            'rows'  => self::SCAN_ROWS,
            'start' => $from,
            'sort'  => 'recent',
            'fl'    => ['date', 'ip', 'qtime', 'hits', 'http_status', 'path', 'q', 'param_hostname', 'full_request'],
        ]);

        if ($res['state'] !== 'ok') {
            return ['ok' => false, 'note' => $res['state'], 'detail' => $res['message']];
        }

        $read = count($res['docs']);
        $total = (int) $res['numFound'];
        $scanned = (int) ($ctx['scanned'] ?? 0) + $read;

        [$shapes, $overflow] = self::merge(
            is_array($ctx['shapes'] ?? null) ? $ctx['shapes'] : [],
            self::fold($res['docs']),
            (int) ($ctx['overflow'] ?? 0)
        );

        $exhausted = $read === 0 || $from + $read >= $total;
        $capped = !$exhausted && $page + 1 >= self::SCAN_STEPS;

        return [
            'ok'      => true,
            'stop'    => $exhausted,
            'note'    => number_format($read) . ' read',
            'detail'  => number_format($scanned) . ' of ' . number_format($total) . ' requests read, '
                . number_format(count($shapes)) . ' distinct shapes so far.',
            'context' => [
                'shapes'   => $shapes,
                'scanned'  => $scanned,
                'total'    => $total,
                'overflow' => $overflow,
                'complete' => $exhausted,
                'capped'   => $capped,
                'edges'    => self::QTIME_EDGES,
            ],
        ];
    }

    /**
     * Merge one page's shapes into the running total.
     *
     * Counts and sums merge by addition, the maximum by comparison, and the latency
     * distribution by adding histograms bucket for bucket. That is why the fold produces
     * those and not a list of samples: a sample list either grows without bound across
     * twenty pages or needs a caveat nobody reads, and a percentile computed per page
     * cannot be combined with another page's at all.
     *
     * Once the retained-shape cap is reached, an unseen shape increments the overflow
     * counter instead of being added. Shapes already being counted keep being counted, so
     * the numbers on screen never go backwards.
     *
     * @param array<string,array<string,mixed>> $into
     * @param array<string,array<string,mixed>> $page
     * @return array{0:array<string,array<string,mixed>>,1:int}
     */
    private static function merge(array $into, array $page, int $overflow): array
    {
        foreach ($page as $hash => $src) {
            if (!isset($into[$hash])) {
                if (count($into) >= self::SCAN_MAX_SHAPES) {
                    $overflow++;
                    continue;
                }
                $into[$hash] = [
                    'label'   => $src['label'],
                    'handler' => $src['handler'],
                    'count'   => 0,
                    'zero'    => 0,
                    'timed'   => 0,
                    'qsum'    => 0,
                    'qmax'    => null,
                    'hist'    => array_fill(0, count(self::QTIME_EDGES) + 1, 0),
                    'worst'   => null,
                ];
            }

            $into[$hash]['count'] += $src['count'];
            $into[$hash]['zero']  += $src['zero'];
            $into[$hash]['timed'] += $src['timed'];
            $into[$hash]['qsum']  += $src['qsum'];
            foreach ($src['hist'] as $bucket => $n) {
                $into[$hash]['hist'][$bucket] = ($into[$hash]['hist'][$bucket] ?? 0) + $n;
            }
            if ($src['qmax'] !== null && ($into[$hash]['qmax'] === null || $src['qmax'] > $into[$hash]['qmax'])) {
                $into[$hash]['qmax'] = $src['qmax'];
                $into[$hash]['worst'] = $src['worst'];
            }
        }

        return [$into, $overflow];
    }

    /**
     * Fold a page of documents into per-shape aggregates.
     *
     * Everything produced here is mergeable, because merge() adds twenty of these together
     * across the life of one job. The label is truncated harder than the display cap: it
     * is stored once per shape in a context that is rewritten on every step and shipped on
     * every poll, and two hundred characters is already more shape than a table cell shows.
     *
     * @param array<int,array<string,mixed>> $docs
     * @return array<string,array<string,mixed>>
     */
    private static function fold(array $docs): array
    {
        $shapes = [];

        foreach ($docs as $doc) {
            $shape = OpensolrShape::of($doc);
            $hash = $shape['hash'];

            $qtime = is_numeric($doc['qtime'] ?? null) ? (int) $doc['qtime'] : null;
            $hits = is_numeric($doc['hits'] ?? null) ? (int) $doc['hits'] : null;

            if (!isset($shapes[$hash])) {
                $shapes[$hash] = [
                    'label'   => mb_substr($shape['label'], 0, 200),
                    'handler' => $shape['handler'],
                    'count'   => 0,
                    'zero'    => 0,
                    'timed'   => 0,
                    'qsum'    => 0,
                    'qmax'    => null,
                    'hist'    => array_fill(0, count(self::QTIME_EDGES) + 1, 0),
                    'worst'   => null,
                ];
            }

            $shapes[$hash]['count']++;
            if ($hits === 0) {
                $shapes[$hash]['zero']++;
            }
            if ($qtime !== null) {
                $shapes[$hash]['timed']++;
                $shapes[$hash]['qsum'] += $qtime;
                $shapes[$hash]['hist'][self::bucket($qtime)]++;
                if ($shapes[$hash]['qmax'] === null || $qtime > $shapes[$hash]['qmax']) {
                    $shapes[$hash]['qmax'] = $qtime;
                    $shapes[$hash]['worst'] = self::example($doc);
                }
            }
        }

        return $shapes;
    }

    /**
     * Which histogram bucket a QTime falls into.
     *
     * Bucket i holds [edges[i], edges[i+1]); the last bucket holds everything at or above
     * the final edge, so no measurement is ever dropped for being an outlier.
     */
    private static function bucket(int $qtime): int
    {
        $edges = self::QTIME_EDGES;
        for ($i = count($edges) - 1; $i >= 0; $i--) {
            if ($qtime >= $edges[$i]) {
                return $i + 1;
            }
        }
        return 0;
    }

    /**
     * One request rendered as a reachable example.
     *
     * `full_request` is chosen byte for byte by whoever queried the index, so it is
     * truncated here and escaped at every render site. It is included because a shape
     * without a concrete example is an abstraction nobody can act on — the operator needs
     * to see the actual query to recognise which part of their application sent it.
     *
     * @param array<string,mixed> $doc
     * @return array<string,mixed>
     */
    private static function example(array $doc): array
    {
        return [
            'date'    => (string) ($doc['date'] ?? ''),
            'ip'      => (string) ($doc['ip'] ?? ''),
            'qtime'   => is_numeric($doc['qtime'] ?? null) ? (int) $doc['qtime'] : null,
            'hits'    => is_numeric($doc['hits'] ?? null) ? (int) $doc['hits'] : null,
            'status'  => is_numeric($doc['http_status'] ?? null) ? (int) $doc['http_status'] : null,
            'node'    => (string) ($doc['param_hostname'] ?? ''),
            'request' => mb_substr((string) ($doc['full_request'] ?? ''), 0, 400),
        ];
    }

    /**
     * The slowest individual requests, exactly.
     *
     * One call, sorted by QTime, no scanning: the extremes are what an operator chases
     * first, and the platform can sort them far more cheaply than the panel can find them.
     * Each row carries its shape, so a one-off outlier can be told apart from the worst
     * instance of a pattern that runs constantly.
     *
     * @return array<string,mixed>
     */
    private function slowest(): array
    {
        $rows = Security::clampInt($_GET['rows'] ?? null, 5, 50, 20);

        $res = $this->fetch([
            'fq'   => $this->logFqs(),
            'rows' => $rows,
            'sort' => 'slowest',
            'fl'   => ['date', 'ip', 'qtime', 'hits', 'http_status', 'path', 'q', 'param_hostname', 'full_request'],
        ]);

        $out = [];
        foreach ($res['docs'] as $doc) {
            $shape = OpensolrShape::of($doc);
            $out[] = self::example($doc) + ['shape' => $shape['label'], 'hash' => $shape['hash']];
        }

        return $this->logEnvelope($res, ['rows' => $out]);
    }

    public function body(): void
    {
        if (!$this->configured()) {
            self::noCredentials();
            return;
        }

        $this->filterCard('qy-filters', self::indexPicker('qy-core'));
        $this->volumeCard('qy-volume');
        $this->shapesCard();
        $this->latencyCard();
        $this->zeroCard();
        $this->slowCard();
        $this->explainCard();
    }

    /** The shape table, with the scope control and the scan progress. */
    private function shapesCard(): void
    {
        $tools = '<div class="controls"><label for="qy-sort">Order by</label><select id="qy-sort">';
        foreach ([
            'count' => 'Most requests',
            'zero'  => 'Most zero-result',
            'slow'  => 'Slowest average',
            'worst' => 'Worst single request',
        ] as $value => $label) {
            $tools .= '<option value="' . Security::esc($value) . '">' . Security::esc($label) . '</option>';
        }
        $tools .= '</select></div>';

        self::cardOpen('qy-shapes', $this->cardNumber('qy-shapes'), 'Query shapes', '', $tools);
        self::skeleton('qy-shapes', 'rows', 0, 'Scanning the request log');

        echo '<div class="job-mount" id="qy-shapes-job"></div>';
        echo '<div class="chart" id="qy-shapes-chart" style="height:300px"></div>';
        echo '<div class="table-wrap"><table id="qy-shapes-table"><thead><tr>'
            . '<th scope="col" class="w-expand"><span class="sr-only">Expand</span></th>'
            . '<th scope="col">Shape</th>'
            . '<th scope="col" class="num">Requests</th>'
            . '<th scope="col" class="num">Zero results</th>'
            . '<th scope="col" class="bar-col">Zero share</th>'
            . '<th scope="col" class="num">Mean QTime</th>'
            . '<th scope="col" class="num">p95</th>'
            . '<th scope="col" class="num">Worst</th>'
            . '</tr></thead><tbody></tbody></table></div>';

        self::cardClose('qy-shapes');
    }

    /**
     * The latency distribution across everything the scan read.
     *
     * Costs no extra call. Every shape in the scan carries its own log-scaled histogram —
     * that is how the per-shape percentiles survive being merged across twenty pages — and
     * summing those histograms bucket by bucket gives the distribution for the whole scanned
     * population. It was being computed and then never drawn.
     *
     * Log-scaled, because query latency is: the interesting structure is between 1 ms and
     * 100 ms, and a linear axis wide enough to hold a thirty-second outlier puts every real
     * query in its first bar.
     */
    private function latencyCard(): void
    {
        self::cardOpen(
            'qy-latency',
            $this->cardNumber('qy-latency'),
            'How long the scanned requests took',
            'Every timed request the scan above read, bucketed on a log scale. Costs no extra reading — '
            . 'the buckets are the same ones the per-shape percentiles are computed from.'
        );
        self::skeleton('qy-latency', 'chart', 300, 'Summing the scanned histograms');

        self::statRow([
            ['p50',   'p50',    'Half of the scanned requests were answered within this'],
            ['p95',   'p95',    'One scanned request in twenty took longer'],
            ['p99',   'p99',    'The worst one percent of the scanned requests'],
            ['timed', 'Timed',  'Scanned requests that carried a QTime at all'],
        ]);
        echo '<div class="chart" id="qy-latency-chart" style="height:280px"></div>';

        self::cardClose('qy-latency');
    }

    /** Shapes that matched nothing, scanned over zero-result requests only. */
    private function zeroCard(): void
    {
        self::cardOpen(
            'qy-zero',
            $this->cardNumber('qy-zero'),
            'Shapes that find nothing',
            ''
        );
        self::skeleton('qy-zero', 'rows', 0, 'Scanning requests that matched nothing');

        echo '<div class="job-mount" id="qy-zero-job"></div>';
        echo '<p class="note"><strong>This is the number to act on.</strong> A shape here ran against your '
            . 'index and came back with no documents. Some of that is normal — visitors search for things '
            . 'you do not sell. A shape with a high count and a hundred percent miss rate is not: it is a '
            . 'filter on a field that no longer exists, a value the schema never indexed, or a part of your '
            . 'application asking a question the index cannot answer.</p>';

        echo '<div class="table-wrap"><table id="qy-zero-table"><thead><tr>'
            . '<th scope="col" class="w-expand"><span class="sr-only">Expand</span></th>'
            . '<th scope="col">Shape</th>'
            . '<th scope="col" class="num">Empty responses</th>'
            . '<th scope="col" class="bar-col">Share of the empties</th>'
            . '<th scope="col" class="num">Mean QTime</th>'
            . '</tr></thead><tbody></tbody></table></div>';

        self::cardClose('qy-zero');
    }

    /** The worst individual requests. */
    private function slowCard(): void
    {
        self::cardOpen(
            'qy-slow',
            $this->cardNumber('qy-slow'),
            'Slowest individual requests',
            'The requests with the highest QTime under the current filters, exactly — not a sample.'
        );
        self::skeleton('qy-slow', 'rows', 0, 'Asking the platform for the slowest requests');

        echo '<div class="table-wrap"><table id="qy-slow-table"><thead><tr>'
            . '<th scope="col" class="nowrap">When</th>'
            . '<th scope="col" class="num">QTime</th>'
            . '<th scope="col" class="num">Hits</th>'
            . '<th scope="col">From</th>'
            . '<th scope="col">Shape</th>'
            . '</tr></thead><tbody></tbody></table></div>';

        self::cardClose('qy-slow');
    }

    /** What QTime is, what it is not, and how a shape is derived. */
    private function explainCard(): void
    {
        self::cardOpen('qy-explain', $this->cardNumber('qy-explain'), 'Reading these numbers');
        echo '<div class="explain">';
        echo '<p><strong>QTime is not response time.</strong> It is Solr\'s own measure of the time it spent '
            . 'answering the query, measured inside the search handler. It excludes the time the request '
            . 'spent crossing the network, waiting in a queue behind other requests, or being written back '
            . 'to your application. A page that feels slow can have a QTime of four milliseconds, and the '
            . 'cause will be somewhere else entirely. What QTime is good for is comparison: between shapes, '
            . 'between nodes, and against itself over time.</p>';
        echo '<p><strong>A shape is the query with its literals removed.</strong> Quoted phrases become '
            . '<code>"?"</code>, bare terms become <code>?</code>, numbers become <code>#</code>, and range '
            . 'endpoints become <code>[# TO #]</code>. Field names, boolean operators, parentheses, local '
            . 'parameters, boosts and the set of parameters themselves are all kept, because those are the '
            . 'parts your application chose. Two requests share a shape when your application would have '
            . 'built them the same way.</p>';
        echo '<p><strong>The shape tables cover a scan, not the whole log.</strong> Shapes cannot be '
            . 'computed by the search engine — they have to be derived from the recorded request — so the '
            . 'panel reads the log a page at a time in the background and stops at a cap of eight thousand '
            . 'requests per scan. The scan runs as a server-side operation with one bounded page per poll, '
            . 'so nothing can time out however large the log is, and reloading the page rejoins the scan '
            . 'already in progress rather than starting a second one. Each table says exactly how many '
            . 'requests it read and out of how many. The slowest-requests table above is different: that '
            . 'one is exact, because sorting is something the platform can do itself.</p>';
        echo '<p><strong>A scan runs under the filters that were set when it started.</strong> The filters '
            . 'are part of the operation\'s identity, so changing one starts a different scan rather than '
            . 'relabelling the running one, and the zero-result table below always reads zero-result '
            . 'requests whatever outcome slice is selected above — that is what it is for.</p>';
        echo '<p><strong>The latency figures survive the paging.</strong> A percentile cannot be averaged '
            . 'across pages, so none is: every shape carries a histogram of its own response times, pages '
            . 'add histograms together bucket by bucket, and the percentiles are read off the merged '
            . 'result at the end. They are reported as "at most" a bucket edge, which is the only honest '
            . 'reading of a bucketed distribution.</p>';
        echo '</div>';
        self::cardEnd();
    }
}
