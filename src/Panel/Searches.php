<?php
/**
 * Loghound — Analytics: site search.
 *
 * What visitors typed into the measured site's own search box: the most common terms, and the
 * terms that moved against the period before.
 *
 * ## The distinction this page exists to make
 *
 * `search_terms_ss` is populated only when the operator has NAMED the query parameters their
 * search box uses. On an installation where nobody has, the field is empty on every session for
 * ever — and an empty table under the heading "Top searches" reads as "nobody searched for
 * anything", which sends somebody hunting for a bug in their own search page. "Not configured"
 * and "nothing searched" are different facts with different next steps, and both cards here
 * distinguish them before they draw anything.
 *
 * ## What the counts are
 *
 * SESSIONS, NOT SEARCHES. The field is a per-session union capped by the beacon, so a visitor who
 * ran the same search six times contributes one. That is the number worth having — how many
 * people looked for this — rather than the one that flatters, and publishing the second under the
 * first's name is exactly the quiet lie this product refuses everywhere else. Both cards say so.
 *
 * The terms arrive from two places and read the same from both: the log parser pulls the named
 * parameters out of the request line for a host whose access log this installation reads, and the
 * beacon reports them for a host it does not. So a search page on another server appears here
 * beside one on this machine.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Beacon;

final class Searches extends Controller
{
    /**
     * The cards, in render order, with the short labels the jump bar and the navigation use.
     *
     * @var array<int,array{0:string,1:string}>
     */
    public const SECTIONS = [
        ['an-terms', 'Top searches'],
        ['an-termtrend', 'Trending'],
    ];

    /** Terms considered when ranking by movement. See Panel\Pages::TREND_CANDIDATES. */
    private const TREND_CANDIDATES = 200;

    /**
     * Which page-toolbar controls this view honours.
     *
     * Both cards run under sessionFqs() or the spanning equivalent, which carry the range, the
     * virtual host and every active filter.
     *
     * @return array<int,string>
     */
    public function toolbar(): array
    {
        return [self::SCOPE_RANGE, self::SCOPE_HOST, self::SCOPE_FACETS, self::SCOPE_CACHE];
    }

    public function slug(): string
    {
        return 'searches';
    }

    public function title(): string
    {
        return 'Site search';
    }


    /**
     * @return array<string,array<string,mixed>>
     */
    public function exports(): array
    {
        return [
            'terms' => [
                'label'   => 'Search terms',
                'action'  => 'terms',
                'unit'    => 'search terms',
                'ranked'  => 'ranked by the number of visits that searched for them',
                'cap'     => Paging::MAX_PAGE,
                'params'  => ['rows' => Paging::MAX_PAGE],
                'total'   => 'page.total',
                'note'    => 'Counted as VISITS that searched for the term at least once, not as the number '
                    . 'of searches: somebody who ran the same search six times counts once. Terms are '
                    . 'collected only from the query parameters this installation has been told to read.',
                'scope'   => [
                    'searched'   => 'Visits that ran a search',
                    'configured' => ['Query parameters being read', static fn ($v): string =>
                        is_array($v) ? implode('; ', array_map('strval', $v)) : ''],
                ],
                'columns' => [
                    ['Parameter', 'param', 'text'],
                    ['Search term', 'term', 'text'],
                    ['Visits', 'sessions', 'number'],
                ],
            ],

            'termtrend' => [
                'label'   => 'Trending searches',
                'action'  => 'trending',
                'unit'    => 'search terms',
                'ranked'  => 'ranked by the change against the equivalent window immediately before',
                'cap'     => Paging::MAX_PAGE,
                'params'  => ['rows' => Paging::MAX_PAGE],
                'total'   => 'page.total',
                'note'    => 'The baseline is the window of the same length immediately before the selected '
                    . 'one. The selected window runs up to the moment the file was taken while the baseline '
                    . 'is complete, so a period that has only just begun makes everything look down.',
                'columns' => [
                    ['Parameter', 'param', 'text'],
                    ['Search term', 'term', 'text'],
                    ['Visits this period', 'now', 'number'],
                    ['Visits the period before', 'prev', 'number'],
                    ['Change', 'delta', 'number'],
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
            'terms'    => $this->terms(),
            'trending' => $this->trending(),
            default    => ['error' => 'Unknown action'],
        };
    }

    /**
     * The query parameters this installation reads a search term out of.
     *
     * Travels with every payload on this view, because both cards have to tell "nothing is
     * configured" apart from "nothing was searched" before they render an empty state.
     *
     * @return array<int,string>
     */
    private function configured(): array
    {
        return Beacon::normaliseParamNames((array) $this->cfg->get('beacon.query_params', []));
    }

    /**
     * The most searched-for terms.
     *
     * @return array<string,mixed>
     */
    private function terms(): array
    {
        $start = Paging::start();
        $rows = Paging::rows();

        $f = $this->gw->facet('searches.terms', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->sessionFqs(),
        ], [
            'terms'    => Paging::terms('search_terms_ss', $start, $rows),
            'searched' => ['type' => 'query', 'q' => 'search_terms_ss:*'],
        ]);

        $out = [];
        foreach (self::buckets($f, 'terms') as $bucket) {
            [$param, $term] = \Loghound\Beacon::splitTerm((string) ($bucket['val'] ?? ''));
            $out[] = [
                'param'    => $param,
                'term'     => $term,
                'value'    => (string) ($bucket['val'] ?? ''),
                'sessions' => (int) ($bucket['count'] ?? 0),
            ];
        }

        return $this->envelope([
            'configured' => $this->configured(),
            'total'      => (int) ($f['count'] ?? 0),
            'searched'   => self::qcount($f, 'searched'),
            'rows'       => $out,
            'page'       => Paging::block($start, $rows, Paging::distinct($f, 'terms'), 'search terms', count($out)),
        ]);
    }

    /**
     * Terms ranked by how much more they were searched for than in the period before.
     *
     * Same mechanism as Panel\Pages::trending(), and the same two admissions: the candidate set is
     * the busiest terms across BOTH windows, and the selected window is still filling while the
     * baseline is complete.
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

        $f = $this->gw->facet('searches.trending', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $base,
        ], [
            'terms' => Paging::terms('search_terms_ss', 0, self::TREND_CANDIDATES, 'count desc', [
                'facet' => [
                    'now'  => ['type' => 'query', 'q' => Query::rangeFq('ts_start', $this->range)],
                    'prev' => ['type' => 'query', 'q' => Query::previousRangeFq('ts_start', $this->range)],
                ],
            ]),
        ]);

        $candidates = [];
        foreach (self::buckets($f, 'terms') as $bucket) {
            $now = self::qcount($bucket, 'now');
            $prev = self::qcount($bucket, 'prev');
            [$param, $term] = \Loghound\Beacon::splitTerm((string) ($bucket['val'] ?? ''));
            $candidates[] = [
                'param' => $param,
                'term'  => $term,
                'value' => (string) ($bucket['val'] ?? ''),
                'now'   => $now,
                'prev'  => $prev,
                'delta' => $now - $prev,
            ];
        }

        usort($candidates, static function (array $a, array $b): int {
            return $b['delta'] <=> $a['delta'] ?: $b['now'] <=> $a['now'];
        });

        $page = array_slice($candidates, $start, $rows);

        return $this->envelope([
            'configured' => $this->configured(),
            'candidates' => self::TREND_CANDIDATES,
            'considered' => count($candidates),
            'baseline'   => 'the ' . mb_strtolower((string) $this->range['label']) . ' immediately before this one',
            'rows'       => array_values($page),
            'page'       => Paging::block($start, $rows, count($candidates), 'search terms', count($page)),
        ]);
    }

    /**
     * The static skeleton.
     */
    public function body(): void
    {
        self::cardOpen(
            'an-terms',
            Layout::cardNum(self::SECTIONS, 'an-terms'),
            'What they searched for',
            'Visits that ran a search, by term.',
            $this->exportTool('terms')
        );
        self::skeleton('an-terms', 'rows', 0, 'Faceting search terms');
        echo '<div class="table-wrap"><table id="an-terms-table" class="table-fixed"><colgroup>'
            . '<col style="width:18%"><col style="width:42%"><col style="width:16%"><col style="width:24%">'
            . '</colgroup><thead><tr>'
            . '<th scope="col">Parameter</th>'
            . '<th scope="col">Search term</th>'
            . '<th scope="col" class="num">Visits</th>'
            . '<th scope="col" class="bar-col">Share</th>'
            . '</tr></thead><tbody></tbody></table></div>';
        echo '<div id="an-terms-pager"></div>';
        self::cardClose('an-terms');

        self::cardOpen(
            'an-termtrend',
            Layout::cardNum(self::SECTIONS, 'an-termtrend'),
            'What they started searching for',
            'Terms ranked by how much more they were searched for than in the period before.',
            $this->exportTool('termtrend')
        );
        self::skeleton('an-termtrend', 'rows', 0, 'Comparing this period against the one before');
        echo '<div class="table-wrap"><table id="an-termtrend-table" class="table-fixed"><colgroup>'
            . '<col style="width:16%"><col style="width:28%"><col style="width:13%"><col style="width:13%">'
            . '<col style="width:14%"><col style="width:16%"></colgroup><thead><tr>'
            . '<th scope="col">Parameter</th>'
            . '<th scope="col">Search term</th>'
            . '<th scope="col" class="num">This period</th>'
            . '<th scope="col" class="num">Before</th>'
            . '<th scope="col" class="num">Change</th>'
            . '<th scope="col" class="bar-col">Movement</th>'
            . '</tr></thead><tbody></tbody></table></div>';
        echo '<div id="an-termtrend-pager"></div>';
        self::cardClose('an-termtrend');
    }
}
