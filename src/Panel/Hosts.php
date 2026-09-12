<?php
/**
 * Loghound — Virtual hosts.
 *
 * On a machine serving one site this view has nothing to say and the selector it feeds does
 * not appear. On a machine serving six, it is the difference between a dashboard and a
 * blur: `host_s` is on every hit and on every session document, and until now nothing in
 * the panel filtered on it, so six sites' traffic was added together and presented as one.
 * "Which of my sites takes the most bot traffic" is the question a multi-site install
 * actually has, and it could not be asked.
 *
 * Two things live here:
 *
 *  1. **The comparison.** One row per virtual host, with the five populations side by side
 *     and the evasive-bot share as the sort key, because that is the column an operator
 *     scans for. Computed in ONE faceted request — a terms facet on `host_s` with the
 *     population queries nested inside it — rather than one request per host, so the cost
 *     does not grow with the number of sites.
 *
 *  2. **The host list that scopes the whole dashboard.** `list` is deliberately cheap and
 *     deliberately reachable from every view (`?v=hosts&api=list`), because the selector it
 *     fills is page furniture rather than a control on one card. Selecting a host adds
 *     `f[host_s][]` to the URL, which Controller::filterFqs() already applies to every
 *     query on every view — so scoping is one mechanism, not seven.
 *
 * The list action removes the host filter from its OWN filters before it runs. Without
 * that, picking a host would reduce the selector to the host that was picked, and there
 * would be no way back.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Security;
use Loghound\Setup\Steps;

final class Hosts extends Controller
{

    /**
     * The pages this view has, in render order.
     *
     * The "no virtual host is being recorded" explainer is not one of them. It is emitted
     * outside cardOpen() — hidden markup the front end reveals when the facet comes back empty —
     * so it is page-level output and travels with whichever page the reader is on, which is the
     * only behaviour that makes sense for a message about the whole view.
     *
     * @var array<int,array{0:string,1:string}>
     */
    public const SECTIONS = [
        ['hosts-table', 'Traffic by host'],
        ['hosts-share', 'Automation share'],
    ];
    /** Hosts compared in the table. Beyond this the page stops being readable. */
    private const MAX_HOSTS = 50;

    /**
     * Which page-toolbar controls this view honours.
     *
     * The range and every other facet bound the comparison. The host selector is kept
     * deliberately: this is the page it belongs to, it shows its own current value, and
     * choosing a host here scopes the rest of the dashboard. Only the host DIMENSION is
     * lifted from this view's own queries, by fqsWithoutHost(), so the table can still
     * compare every host side by side rather than collapsing to the one just picked.
     *
     * @return array<int,string>
     */
    public function toolbar(): array
    {
        return [self::SCOPE_RANGE, self::SCOPE_HOST, self::SCOPE_FACETS, self::SCOPE_CACHE];
    }

    public function slug(): string
    {
        return 'hosts';
    }

    public function title(): string
    {
        return 'Virtual hosts';
    }

    public function subtitle(): string
    {
        return 'Which of the sites on this machine gets what kind of traffic.';
    }

    /**
     * The comparison table, as CSV.
     *
     * The five population columns are the point of the file, and they are exported as five
     * separate numbers rather than as one "bot share", because the five partition the scored
     * sessions exactly and a reader can therefore check the arithmetic on every row. The two
     * derived shares come along as well so a spreadsheet does not have to re-derive them and
     * get a different answer from the panel.
     *
     * THE HOST DIMENSION IS LIFTED FROM THIS VIEW'S OWN QUERIES, by fqsWithoutHost(), so this
     * table compares every host even when one is selected in the header. The preamble therefore
     * names the selected host and this note says the table ignores it — otherwise the file would
     * look like it disagreed with its own scope line.
     *
     * @return array<string,array<string,mixed>>
     */
    public function exports(): array
    {
        return [
            'hosts' => [
                'label'   => 'Traffic by virtual host',
                'action'  => 'compare',
                'unit'    => 'virtual hosts',
                'ranked'  => 'ranked by session count',
                'cap'     => self::MAX_HOSTS,
                'note'    => 'The host selector is deliberately NOT applied to this table: it compares '
                    . 'every host side by side, which is what the view is for. Every other filter and the '
                    . 'time range are applied. The five population columns are mutually exclusive and add '
                    . 'up to the session count on each row.',
                'columns' => [
                    ['Host', 'host', 'id'],
                    ['Sessions', 'sessions', 'number'],
                    ['Humans', 'counts.human', 'number'],
                    ['Unknown', 'counts.unknown', 'number'],
                    ['Declared crawlers', 'counts.declared', 'number'],
                    ['AI crawlers', 'counts.ai', 'number'],
                    ['Evasive bots', 'counts.evasive', 'number'],
                    ['Automation share (percent)', 'bot_share', 'number'],
                    ['Evasive share (percent)', 'evasive_share', 'number'],
                    ['Requests', 'hits', 'number'],
                    ['Pageviews', 'pages', 'number'],
                    ['Bytes', 'bytes', 'number'],
                    ['Beacon-only sessions', 'beacon_only', 'number'],
                    ['Seen on one transport plane only', 'single_plane', 'bool'],
                    ['Seen on both transport planes', 'mixed_planes', 'bool'],
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
            'list'    => $this->hostList(),
            'compare' => $this->compare(),
            default   => ['error' => 'Unknown action'],
        };
    }

    /**
     * The hosts present in the selected range, for the selector on every page.
     *
     * `multi` is what the front end acts on: with one host (or none) the selector is never
     * inserted into the page at all. A control that offers a single choice is furniture
     * nobody needs, and a multi-site feature must not clutter a single-site install.
     *
     * `present` distinguishes "this install has one vhost" from "this log format does not
     * record one", which are different situations with different answers — the second is
     * fixed by logging `%v`, and the view says so.
     *
     * @return array<string,mixed>
     */
    private function hostList(): array
    {
        /* THE DOC-TYPE CLAUSE IS NOT OPTIONAL HERE. The sessions core holds daily rollup
           documents alongside session documents, so a facet without it counts up to one extra
           document per day in range against every host. The comparison table below has always
           prepended it; this list did not, which is why the per-host counts in the header
           selector read higher than the same host's row in the table underneath. */
        $f = $this->gw->facet('hosts.list', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => array_merge([Query::SESSION_DOCS], $this->fqsWithoutHost()),
        ], Query::hostFacet(self::MAX_HOSTS));

        $hosts = [];
        foreach (self::buckets($f, 'hosts') as $bucket) {
            $host = (string) ($bucket['val'] ?? '');
            if ($host === '') {
                continue;
            }
            $hosts[] = ['host' => $host, 'sessions' => (int) ($bucket['count'] ?? 0)];
        }

        return $this->envelope([
            'hosts'    => $hosts,
            'multi'    => count($hosts) > 1,
            'present'  => $hosts !== [],
            'selected' => $this->selectedHosts(),
            'total'    => (int) ($f['count'] ?? 0),
            'field'    => Query::HOST_FIELD,
        ]);
    }

    /**
     * One row per host: the five populations, the traffic they moved, and the bot share.
     *
     * The populations are mutually exclusive and exhaustive over scored sessions, so the
     * five counts add up to the row total and the share is a real fraction rather than a
     * ratio between two overlapping sets.
     *
     * `doc_type_s:session` is on the query because the sessions core also holds the daily
     * rollup documents, and counting those as sessions would inflate every row.
     *
     * @return array<string,mixed>
     */
    private function compare(): array
    {
        $nested = ['bytes' => 'sum(bytes_l)', 'hits' => 'sum(hits_i)', 'pages' => 'sum(pages_i)'];
        foreach (Query::populations() as $key => $filter) {
            $nested[$key] = ['type' => 'query', 'q' => $filter];
        }

        /* How many of this host's sessions were measured by the beacon ALONE. This is the view
           where the mixture is most visible — a host on another server sits in the same table
           as one whose access log this machine reads — and a row whose numbers came from one
           plane has to say so rather than looking identical to a row backed by three. Counted
           per host rather than stated once for the page, because on a multi-site install it is
           true of some rows and false of others. */
        $nested['beacon_only'] = ['type' => 'query', 'q' => 'planes_s:beacon_only'];

        $f = $this->gw->facet('hosts.compare', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => array_merge([Query::SESSION_DOCS], $this->sessionFqs()),
        ], [
            'hosts' => [
                'type'     => 'terms',
                'field'    => Query::HOST_FIELD,
                'limit'    => self::MAX_HOSTS,
                'mincount' => 1,
                'sort'     => 'count desc',
                'facet'    => $nested,
            ],
        ]);

        $rows = [];
        foreach (self::buckets($f, 'hosts') as $bucket) {
            $host = (string) ($bucket['val'] ?? '');
            if ($host === '') {
                continue;
            }
            $sessions = (int) ($bucket['count'] ?? 0);
            $counts = [];
            foreach (array_keys(Query::populations()) as $key) {
                $counts[$key] = self::qcount($bucket, $key);
            }
            $botlike = $counts['evasive'] + $counts['ai'] + $counts['declared'];

            $beaconOnly = self::qcount($bucket, 'beacon_only');

            $rows[] = [
                'host'       => $host,
                'sessions'   => $sessions,
                'counts'     => $counts,
                'beacon_only'   => $beaconOnly,
                'single_plane'  => $sessions > 0 && $beaconOnly >= $sessions,
                'mixed_planes'  => $beaconOnly > 0 && $beaconOnly < $sessions,
                'bot_share'  => $sessions > 0 ? round(($botlike / $sessions) * 100, 1) : null,
                'evasive_share' => $sessions > 0 ? round(($counts['evasive'] / $sessions) * 100, 1) : null,
                'bytes'      => self::num($bucket, 'bytes'),
                'hits'       => self::num($bucket, 'hits'),
                'pages'      => self::num($bucket, 'pages'),
            ];
        }

        return $this->envelope([
            'rows'   => $rows,
            'labels' => Query::populationLabels(),
            'order'  => array_keys(Query::populations()),
            'total'  => (int) ($f['count'] ?? 0),
        ]);
    }

    /**
     * The active filters with the host filter taken out.
     *
     * Both actions here describe the SET OF HOSTS, so scoping them to the host already chosen
     * would answer a question nobody asked — the selector would collapse to the host you picked
     * and there would be no way back. Every OTHER active filter is kept: "of the traffic I am
     * currently looking at, which host does it come from" is exactly right.
     *
     * This is the facet layer's own lift-one-dimension mechanism, not a third hand-rolled copy of
     * the clause builder. It was one: it OR-ed every value, knew nothing about the boolean
     * operator, and quoted a numeric field — so on this view an excluded network type silently
     * became an included one and the host table answered a different question from every other
     * card on the page.
     *
     * @return array<int,string>
     */
    private function fqsWithoutHost(): array
    {
        return array_merge(
            [Query::rangeFq('ts_start', $this->range), Query::publicIpsOnly()],
            $this->facets->fqs(null, Query::HOST_FIELD)
        );
    }

    /**
     * The hosts currently selected, echoed back so the selector can show its own state.
     *
     * @return array<int,string>
     */
    private function selectedHosts(): array
    {
        return array_values($this->filters[Query::HOST_FIELD] ?? []);
    }

    /**
     * The static skeleton.
     *
     * Two cards, both async. The explanation of what to do when no host is recorded is
     * rendered server-side and hidden, so the answer is already in the page — including its
     * copy-paste LogFormat — before any request comes back.
     */
    public function body(): void
    {
        $this->compareCard();
        self::chart(
            'hosts-share',
            '02',
            'Automation share by host',
            'Scored sessions per virtual host, split into the five populations.',
            360,
            'Comparing hosts'
        );
        $this->explainCard();
    }

    /** The comparison table. */
    private function compareCard(): void
    {
        self::cardOpen(
            'hosts-table',
            '01',
            'Traffic by virtual host',
            'All scored sessions in the selected range, grouped by the host the request arrived on.',
            $this->exportTool('hosts')
        );
        self::skeleton('hosts-table', 'rows', 0, 'Grouping sessions by virtual host');

        echo '<div class="table-wrap"><table id="hosts-table-table" class="table-fixed"><colgroup>'
            /* THE UNKNOWN COLUMN IS HERE BECAUSE THE CAPTION CLAIMS THE ROW ADDS UP. Four of
               the five populations were on screen and the caption said "the five populations
               are mutually exclusive, so they add up to the session count on each row" — a sum
               the reader could try and would find did not hold, because the fifth was missing.
               `unknown` is a finding in this product and not an absence: a session that was
               scored and did not reach a verdict either way. Printing it is what makes the
               arithmetic on the row checkable. */
            . '<col style="width:20%"><col style="width:10%"><col style="width:10%">'
            . '<col style="width:10%"><col style="width:10%"><col style="width:10%">'
            . '<col style="width:10%"><col style="width:10%"><col style="width:10%">'
            . '</colgroup><thead><tr>'
            . '<th scope="col">Host</th>'
            . '<th scope="col" class="num">Sessions</th>'
            . '<th scope="col" class="num">Humans</th>'
            . '<th scope="col" class="num">Unknown</th>'
            . '<th scope="col" class="num">Evasive</th>'
            . '<th scope="col" class="num">AI crawlers</th>'
            . '<th scope="col" class="num">Declared</th>'
            . '<th scope="col" class="num">Automation</th>'
            . '<th scope="col" class="bar-col">Share</th>'
            . '</tr></thead><tbody></tbody></table></div>';

        self::cardClose('hosts-table');
    }

    /**
     * What to do when the log format does not record a virtual host.
     *
     * Hidden until the data says it applies. `%v` is the first field of the recommended
     * LogFormat in SPEC §8, and an operator on plain `combined` has no vhost column at all —
     * which is a fixable configuration, not a missing feature, so the fix is on the page.
     */
    private function explainCard(): void
    {
        /* WRITTEN OUT RATHER THAN THROUGH cardOpen(), for two reasons that are both load
           bearing. It starts `hidden` and the front end reveals it only when the range really
           holds no host at all, which cardOpen() has no way to express; and the front end finds
           it by the exact id `hosts-none`, which cardOpen() would have rewritten to
           `hosts-none-card`.

           `data-card` is set by hand for the same reason every other card gets one: it is the
           key the accordion stores this section's open state under, and a card without one
           silently forgets whether the operator folded it. */
        echo '<section class="card" id="hosts-none" data-card="hosts-none" hidden>';
        echo '<div class="card-head"><h2><span class="card-num">03</span>'
            . '<span>No virtual host is being recorded</span></h2></div>';
        echo '<p class="pop" id="hosts-none-pop" hidden></p>';
        echo '<div class="explain">';
        echo '<p>None of the sessions in this range records which virtual host served the request, which '
            . 'means the log format in use does not carry it. Everything else in '
            . 'Loghound works exactly as before; this page is the one thing that cannot.</p>';
        echo '<p>Apache logs it as <code>%v</code>, and it is the first field of the format Loghound '
            . 'recommends:</p>';

        /* THE CANONICAL STRING, NOT AN ABBREVIATION OF IT. This card used to print a shortened
           line — vhost, duration, referer, User-Agent — and publish it under the nickname
           `loghound`, which is the name docs/INSTALL.md, SPEC §8 and LogDetect's format library
           all give to the FULL recommended format. Two different formats under one nickname is
           the same trap as reusing `combined`, one step further in: an operator who pastes this
           card and then the documentation ends up with whichever definition Apache read last,
           and no error anywhere. It comes from Setup\Steps now, so there is one string. */
        echo '<pre class="snippet mono" id="hosts-logformat">'
            . Security::esc(Steps::recommendedLogFormat()) . "\n"
            . Security::esc(Steps::customLogLine(Steps::RECOMMENDED_NICKNAME)) . '</pre>';
        echo '<p class="faint">nginx records the same thing as <code>$host</code>. '
            . Security::esc(Steps::rescanAdvice(self::root()))
            . ' The log sources card is under <a href="?v=settings">Settings</a>. Old documents keep no '
            . 'host either way, so the comparison covers traffic from that point on.</p>';
        echo '</div>';
        echo '</section>';
    }
}
