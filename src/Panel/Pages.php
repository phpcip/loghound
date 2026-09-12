<?php
/**
 * Loghound — Analytics: pages.
 *
 * The three page questions every ordinary analytics tool answers and this product had nowhere to
 * answer at all: where people arrive, where they leave, and what is moving.
 *
 * ## What each card can honestly claim
 *
 * **Entry pages** are solid. The entry path is the first request of the session, which the access
 * log records directly; nothing is inferred. The one thing to know is that a visit with a single
 * request has the same page as its entry and its exit, so it appears identically in both lists —
 * the entry table therefore prints, per row, how many of its landings never went anywhere.
 *
 * **Exit pages** are a good guess and not a measurement, and the card says so rather than
 * implying otherwise. The exit path is the last request the LOG saw. That is not the same as the
 * last page the visitor looked at: once somebody stops requesting things the log goes quiet
 * whether they closed the tab or read for ten minutes, and a page served from the browser cache
 * produces no log line at all. The beacon knows when a page was abandoned; the log cannot. So the
 * card is scoped to visits with more than one request — where "they moved on and then stopped"
 * is at least a sequence — and single-request visits are offered as a separate choice rather than
 * blended in, because for those the exit page is just the entry page wearing a different label.
 *
 * **Trending pages** needs a baseline to be trending rather than just top, and names it: the
 * equivalent window immediately before the selected one (Query::previousRangeFq). Two further
 * honest limits are printed on the card. The candidate set is the busiest paths ACROSS BOTH
 * windows, so something that went from nothing to three visits is genuinely new and genuinely
 * below the cut. And the selected window runs up to this moment while the baseline is complete,
 * so everything looks slightly down near the start of a period.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Security;

final class Pages extends Controller
{
    /**
     * The cards, in render order, with the short labels the jump bar and the navigation use.
     *
     * @var array<int,array{0:string,1:string}>
     */
    public const SECTIONS = [
        ['an-entry', 'Entry pages'],
        ['an-exit', 'Exit pages'],
        ['an-trend', 'Trending'],
    ];

    /**
     * Paths considered when ranking by movement.
     *
     * Trending is a SORT the server cannot do: Solr orders buckets by their count over the whole
     * spanning window, and what is wanted is the order of the difference between two halves of it.
     * So a bounded candidate set comes back with both halves counted per bucket and the ordering
     * happens here. Two hundred is wide enough that a page can climb into the top twenty from a
     * long way down and narrow enough that the facet stays one cheap read; the card prints the
     * number, because a ranking over a candidate set that does not say what the set was is a
     * ranking nobody can check.
     */
    private const TREND_CANDIDATES = 200;

    /**
     * Which page-toolbar controls this view honours.
     *
     * Every card runs under sessionFqs(), which carries the range, the virtual host and every
     * active filter, and every one of them reads cached Solr answers.
     *
     * @return array<int,string>
     */
    public function toolbar(): array
    {
        return [self::SCOPE_RANGE, self::SCOPE_HOST, self::SCOPE_FACETS, self::SCOPE_CACHE];
    }

    public function slug(): string
    {
        return 'pages';
    }

    public function title(): string
    {
        return 'Pages';
    }


    /**
     * The three tables, as CSV.
     *
     * Each one names the caveat that belongs to it in the file's own preamble, because a
     * spreadsheet outlives the card it was taken from and the exit-page caveat is the whole
     * difference between a number and a guess.
     *
     * @return array<string,array<string,mixed>>
     */
    public function exports(): array
    {
        return [
            'entry' => [
                'label'   => 'Entry pages',
                'action'  => 'entry',
                'unit'    => 'entry pages',
                'ranked'  => 'ranked by the number of visits that started on them',
                'cap'     => Paging::MAX_PAGE,
                'params'  => ['rows' => Paging::MAX_PAGE],
                'total'   => 'page.total',
                'carry'   => ['scope'],
                'note'    => 'The entry page is the first request of the visit, taken straight from the access '
                    . 'log. A visit with a single request has the same page as its entry and its exit, and the '
                    . 'one-request column says how many of each row\'s landings those were.',
                'scope'   => ['scope_label' => 'Visits counted'],
                'columns' => [
                    ['Path', 'path', 'text'],
                    ['Visits that started here', 'sessions', 'number'],
                    ['Of those, one request only', 'single', 'number'],
                    ['Website', 'host', 'text'],
                    ['Distinct hosts serving this path', 'hosts', 'number'],
                ],
            ],

            'exit' => [
                'label'   => 'Exit pages',
                'action'  => 'exit',
                'unit'    => 'exit pages',
                'ranked'  => 'ranked by the number of visits the log last saw on them',
                'cap'     => Paging::MAX_PAGE,
                'params'  => ['rows' => Paging::MAX_PAGE],
                'total'   => 'page.total',
                'carry'   => ['scope'],
                'note'    => 'The exit page is the LAST REQUEST THE LOG SAW, which is not the same as the last '
                    . 'page the visitor looked at: a page read for ten minutes and then abandoned produces no '
                    . 'further log line, and a page served from the browser cache produces none at all. Treat '
                    . 'this as evidence, not as a measurement.',
                'scope'   => ['scope_label' => 'Visits counted'],
                'columns' => [
                    ['Path', 'path', 'text'],
                    ['Visits the log last saw here', 'sessions', 'number'],
                    ['Website', 'host', 'text'],
                    ['Distinct hosts serving this path', 'hosts', 'number'],
                ],
            ],

            'trend' => [
                'label'   => 'Trending pages',
                'action'  => 'trending',
                'unit'    => 'paths',
                'ranked'  => 'ranked by the change against the equivalent window immediately before',
                'cap'     => Paging::MAX_PAGE,
                'params'  => ['rows' => Paging::MAX_PAGE],
                'total'   => 'page.total',
                'note'    => 'The baseline is the window of the same length immediately before the selected '
                    . 'one. The selected window runs up to the moment the file was taken while the baseline is '
                    . 'complete, so a period that has only just begun makes everything look down. Candidates '
                    . 'are the busiest paths across both windows, so a path with very little traffic in either '
                    . 'is absent regardless of how much it grew.',
                'columns' => [
                    ['Path', 'path', 'text'],
                    ['Visits this period', 'now', 'number'],
                    ['Visits the period before', 'prev', 'number'],
                    ['Change', 'delta', 'number'],
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
            'entry'    => $this->entry(),
            'exit'     => $this->exitPages(),
            'trending' => $this->trending(),
            default    => ['error' => 'Unknown action'],
        };
    }

    /**
     * The scope toggle both landing tables carry, resolved to a filter and its words.
     *
     * Three choices rather than two, because "visits with more than one request" and "visits with
     * exactly one" are different questions and each is the right one somewhere: the first is what
     * an exit page means at all, the second is the page people land on and immediately leave.
     *
     * @return array{0:array<int,string>,1:string}
     */
    private function scope(string $default): array
    {
        $choice = self::param('scope', ['all', 'multi', 'single'], $default);

        return match ($choice) {
            'multi'  => [[Query::POP_MULTI_REQUEST], 'Visits that made more than one request'],
            'single' => [['hits_i:[* TO 1]'], 'Visits that made exactly one request'],
            default  => [[], 'Every visit in range'],
        };
    }

    /**
     * Where visits started.
     *
     * `entry_path_s` is the first request of the session and is written by the sessionizer from
     * the log itself, so this table infers nothing. The nested `single` count is what stops a row
     * being misread: a landing page with two hundred visits of which a hundred and ninety made one
     * request is a page people arrive at and leave, and that is invisible in a bare visit count.
     *
     * @return array<string,mixed>
     */
    private function entry(): array
    {
        [$extra, $label] = $this->scope('all');
        $start = Paging::start();
        $rows = Paging::rows();

        $f = $this->gw->facet('pages.entry', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => array_merge($this->sessionFqs(), $extra),
        ], [
            'paths' => Paging::terms('entry_path_s', $start, $rows, 'count desc', [
                'facet' => array_merge(SiteUrl::hostSubFacet(), [
                    'single' => ['type' => 'query', 'q' => 'hits_i:[* TO 1]'],
                ]),
            ]),
        ]);

        $out = [];
        foreach (self::buckets($f, 'paths') as $bucket) {
            $site = SiteUrl::resolve($bucket);
            $out[] = [
                'path'     => (string) ($bucket['val'] ?? ''),
                'sessions' => (int) ($bucket['count'] ?? 0),
                'single'   => self::qcount($bucket, 'single'),
                'host'     => $site['host'],
                'hosts'    => $site['hosts'],
            ];
        }

        return $this->envelope([
            'scope'       => self::param('scope', ['all', 'multi', 'single'], 'all'),
            'scope_label' => $label,
            'total'       => (int) ($f['count'] ?? 0),
            'rows'        => $out,
            'page'        => Paging::block($start, $rows, Paging::distinct($f, 'paths'), 'entry pages', count($out)),
        ]);
    }

    /**
     * Where the log last saw a visit.
     *
     * SCOPED TO MULTI-REQUEST VISITS BY DEFAULT, and that is the honest default rather than the
     * flattering one. For a visit with a single request the exit page is the entry page, so
     * including them fills this table with the landing-page list under a different heading and
     * makes it look like a measurement of where people leave. With two or more requests there is
     * at least a sequence, and "the last one we saw" is evidence.
     *
     * Also scoped to SETTLED sessions: a visit still in progress has a last-seen page that is
     * still moving, so counting it here records where somebody happens to be standing rather than
     * where they left.
     *
     * @return array<string,mixed>
     */
    private function exitPages(): array
    {
        [$extra, $label] = $this->scope('multi');
        $start = Paging::start();
        $rows = Paging::rows();

        $f = $this->gw->facet('pages.exit', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => array_merge($this->settledSessionFqs(), $extra),
        ], [
            'paths' => Paging::terms('exit_path_s', $start, $rows, 'count desc', [
                'facet' => SiteUrl::hostSubFacet(),
            ]),
            'beacon' => ['type' => 'query', 'q' => Query::POP_BEACON],
        ]);

        $out = [];
        foreach (self::buckets($f, 'paths') as $bucket) {
            $site = SiteUrl::resolve($bucket);
            $out[] = [
                'path'     => (string) ($bucket['val'] ?? ''),
                'sessions' => (int) ($bucket['count'] ?? 0),
                'host'     => $site['host'],
                'hosts'    => $site['hosts'],
            ];
        }

        return $this->envelope([
            'scope'       => self::param('scope', ['all', 'multi', 'single'], 'multi'),
            'scope_label' => $label,
            'total'       => (int) ($f['count'] ?? 0),
            'beacon'      => self::qcount($f, 'beacon'),
            'rows'        => $out,
            'page'        => Paging::block($start, $rows, Paging::distinct($f, 'paths'), 'exit pages', count($out)),
        ]);
    }

    /**
     * What is moving, against the window immediately before.
     *
     * ONE REQUEST COVERING BOTH WINDOWS. The `fq` spans the selected range and the baseline
     * together and two query sub-facets split it, so the two halves cannot end up scoped by
     * different filters — which they would be if this were two requests and a filter changed
     * between them.
     *
     * THE ORDERING HAPPENS HERE AND THE CARD SAYS SO. Solr can only sort buckets by their count
     * over the whole spanning window; ranking by the difference between two halves of it is not
     * something the facet API can express. So a bounded candidate set comes back and is sorted in
     * PHP, and the page the browser gets is a slice of that sorted list.
     *
     * @return array<string,mixed>
     */
    private function trending(): array
    {
        $start = Paging::start();
        $rows = Paging::rows();

        $base = array_merge(
            [self::FQ_SESSION_DOCS, Query::spanningRangeFq('ts_start', $this->range)],
            $this->facets->fqs()
        );

        $f = $this->gw->facet('pages.trending', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $base,
        ], [
            'paths' => Paging::terms('paths_ss', 0, self::TREND_CANDIDATES, 'count desc', [
                'facet' => array_merge(SiteUrl::hostSubFacet(), [
                    'now'  => ['type' => 'query', 'q' => Query::rangeFq('ts_start', $this->range)],
                    'prev' => ['type' => 'query', 'q' => Query::previousRangeFq('ts_start', $this->range)],
                ]),
            ]),
        ]);

        $candidates = [];
        foreach (self::buckets($f, 'paths') as $bucket) {
            $site = SiteUrl::resolve($bucket);
            $now = self::qcount($bucket, 'now');
            $prev = self::qcount($bucket, 'prev');
            $candidates[] = [
                'path'  => (string) ($bucket['val'] ?? ''),
                'now'   => $now,
                'prev'  => $prev,
                'delta' => $now - $prev,
                'host'  => $site['host'],
                'hosts' => $site['hosts'],
            ];
        }

        usort($candidates, static function (array $a, array $b): int {
            return $b['delta'] <=> $a['delta'] ?: $b['now'] <=> $a['now'];
        });

        $page = array_slice($candidates, $start, $rows);

        return $this->envelope([
            'candidates'   => self::TREND_CANDIDATES,
            'considered'   => count($candidates),
            'baseline'     => 'the ' . mb_strtolower((string) $this->range['label']) . ' immediately before this one',
            'range_secs'   => (int) $this->range['secs'],
            'rows'         => array_values($page),
            'page'         => Paging::block($start, $rows, count($candidates), 'paths', count($page)),
        ]);
    }

    /**
     * The static skeleton.
     */
    public function body(): void
    {
        $this->entryCard();
        $this->exitCard();
        $this->trendCard();
    }

    /**
     * The scope toggle, as the same control the Overview's population toggle uses.
     *
     * @param array<int,array{0:string,1:string}> $choices
     */
    private static function scopeToggle(array $choices, string $active): string
    {
        $out = '<div class="toggle" role="group" aria-label="Which visits to count">';
        foreach ($choices as [$value, $label]) {
            $on = $value === $active;
            $out .= '<button type="button" data-scope="' . Security::esc($value) . '"'
                . ($on ? ' class="on" aria-pressed="true"' : ' aria-pressed="false"')
                . '>' . Security::esc($label) . '</button>';
        }

        return $out . '</div>';
    }

    /** CARD 01. Where visits started. */
    private function entryCard(): void
    {
        $tools = self::scopeToggle([
            ['all', 'All visits'],
            ['multi', 'Went further'],
            ['single', 'One request only'],
        ], 'all') . $this->exportTool('entry');

        self::cardOpen(
            'an-entry',
            Layout::cardNum(self::SECTIONS, 'an-entry'),
            'Where people arrive',
            'The first request of each visit.',
            $tools
        );
        self::skeleton('an-entry', 'rows', 0, 'Faceting entry pages');

        echo '<div class="table-wrap"><table id="an-entry-table" class="table-fixed"><colgroup>'
            . '<col style="width:52%"><col style="width:14%"><col style="width:16%">'
            . '<col style="width:18%"></colgroup><thead><tr>'
            . '<th scope="col">Page</th>'
            . '<th scope="col" class="num">Visits</th>'
            . '<th scope="col" class="num">Left straight away</th>'
            . '<th scope="col" class="bar-col">Share</th>'
            . '</tr></thead><tbody></tbody></table></div>';
        echo '<div id="an-entry-pager"></div>';

        self::cardClose('an-entry');
    }

    /** CARD 02. Where the log last saw a visit. */
    private function exitCard(): void
    {
        $tools = self::scopeToggle([
            ['multi', 'Went further'],
            ['all', 'All visits'],
            ['single', 'One request only'],
        ], 'multi') . $this->exportTool('exit');

        self::cardOpen(
            'an-exit',
            Layout::cardNum(self::SECTIONS, 'an-exit'),
            'Where the log last saw them',
            'The last request of each finished visit.',
            $tools
        );
        self::skeleton('an-exit', 'rows', 0, 'Faceting exit pages');

        echo '<div class="note"><p><strong>This one is a guess.</strong> The exit page is the last request '
            . 'the LOG saw, which is not the last page the visitor looked at: a page read and then abandoned '
            . 'produces no further log line, and a page served from the browser cache produces none at all. '
            . 'Read a row as "this is where the trail goes cold".</p></div>';

        echo '<div class="table-wrap"><table id="an-exit-table" class="table-fixed"><colgroup>'
            . '<col style="width:60%"><col style="width:16%"><col style="width:24%">'
            . '</colgroup><thead><tr>'
            . '<th scope="col">Page</th>'
            . '<th scope="col" class="num">Visits</th>'
            . '<th scope="col" class="bar-col">Share</th>'
            . '</tr></thead><tbody></tbody></table></div>';
        echo '<div id="an-exit-pager"></div>';

        self::cardClose('an-exit');
    }

    /** CARD 03. What is moving. */
    private function trendCard(): void
    {
        self::cardOpen(
            'an-trend',
            Layout::cardNum(self::SECTIONS, 'an-trend'),
            'What is moving',
            'Ranked by change against the period before.',
            $this->exportTool('trend')
        );
        self::skeleton('an-trend', 'rows', 0, 'Comparing this period against the one before');

        echo '<div class="table-wrap"><table id="an-trend-table" class="table-fixed"><colgroup>'
            . '<col style="width:44%"><col style="width:13%"><col style="width:13%">'
            . '<col style="width:14%"><col style="width:16%"></colgroup><thead><tr>'
            . '<th scope="col">Page</th>'
            . '<th scope="col" class="num">This period</th>'
            . '<th scope="col" class="num">Before</th>'
            . '<th scope="col" class="num">Change</th>'
            . '<th scope="col" class="bar-col">Movement</th>'
            . '</tr></thead><tbody></tbody></table></div>';
        echo '<div id="an-trend-pager"></div>';

        self::cardClose('an-trend');
    }
}
