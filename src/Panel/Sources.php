<?php
/**
 * Loghound — Analytics: where they came from.
 *
 * Two questions an ordinary analytics tool answers and this product could not: what KIND of thing
 * sent each visit, and WHICH SITE did.
 *
 * ## What a referrer is and is not
 *
 * The referrer is a header the client chooses to send, so it is evidence rather than fact.
 * Browsers strip it when moving from https to http, privacy settings remove it entirely, and any
 * client can send whatever it likes — a crawler that wants to look like a Google click will say it
 * came from Google. So the type is a classification of a claim, not a measurement of an origin,
 * and this page says that once rather than pretending otherwise per row.
 *
 * "Direct" in particular is a residual and not a channel. It means no referrer arrived, which
 * covers a bookmark, a typed address, an app that opens links without one, and every visitor
 * whose browser stripped it. Treating it as "people who typed our name in" is the single most
 * common misreading of a sources table.
 *
 * ## Why the two cards are separate
 *
 * The TYPE answers "is this organic search, paid, social, an AI assistant, or somebody linking to
 * us", which is a question about channels. The HOST answers "which of the forty sites linking to
 * us is actually sending people", which is a question about relationships. They are ranked
 * differently and read differently, and folding them into one table would answer neither.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Security;

final class Sources extends Controller
{
    /**
     * The cards, in render order, with the short labels the jump bar and the navigation use.
     *
     * @var array<int,array{0:string,1:string}>
     */
    public const SECTIONS = [
        ['an-channels', 'Channels'],
        ['an-referrers', 'Referring sites'],
    ];

    /**
     * Which page-toolbar controls this view honours.
     *
     * Both cards run under sessionFqs(), which carries the range, the virtual host and every
     * active filter.
     *
     * @return array<int,string>
     */
    public function toolbar(): array
    {
        return [self::SCOPE_RANGE, self::SCOPE_HOST, self::SCOPE_FACETS, self::SCOPE_CACHE];
    }

    public function slug(): string
    {
        return 'sources';
    }

    public function title(): string
    {
        return 'Where they came from';
    }


    /**
     * @return array<string,array<string,mixed>>
     */
    public function exports(): array
    {
        return [
            'channels' => [
                'label'   => 'Traffic channels',
                'action'  => 'channels',
                'unit'    => 'channels',
                'cap'     => 50,
                'carry'   => ['pop'],
                'note'    => 'A referrer is a header the client chose to send, so every row is a claim rather '
                    . 'than a measurement. "Direct" is the residual — no referrer arrived at all — which covers '
                    . 'bookmarks, typed addresses, apps that open links without one, and any browser that '
                    . 'stripped it. It is not a count of people who typed your name in.',
                'scope'   => ['population_label' => 'Population'],
                'columns' => [
                    ['Channel', 'label', 'text'],
                    ['Stored value', 'value', 'id'],
                    ['Visits', 'sessions', 'number'],
                    ['What it means', 'why', 'text'],
                ],
            ],

            'referrers' => [
                'label'   => 'Referring sites',
                'action'  => 'referrers',
                'unit'    => 'referring sites',
                'ranked'  => 'ranked by the number of visits they sent',
                'cap'     => Paging::MAX_PAGE,
                'params'  => ['rows' => Paging::MAX_PAGE],
                'total'   => 'page.total',
                'carry'   => ['pop'],
                'note'    => 'The host out of the referrer header, which the client chose to send. A visit with '
                    . 'no referrer at all is absent from this table entirely rather than appearing as a blank '
                    . 'row; the channel table above is where that population is counted.',
                'scope'   => ['population_label' => 'Population'],
                'columns' => [
                    ['Referring site', 'host', 'text'],
                    ['Visits', 'sessions', 'number'],
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
            'channels'  => $this->channels(),
            'referrers' => $this->referrers(),
            default     => ['error' => 'Unknown action'],
        };
    }

    /**
     * The population toggle, as a filter and its words.
     *
     * IT MATTERS MORE HERE THAN ANYWHERE. A declared crawler sends no referrer, so on a site whose
     * traffic is half automation the "Direct" row is mostly crawlers and the channel mix describes
     * the bots rather than the audience. Humans-only is therefore offered first.
     *
     * @return array{0:array<int,string>,1:string}
     */
    private function population(): array
    {
        return match (self::param('pop', ['humans', 'all', 'bots'], 'humans')) {
            'all'   => [[], 'Every visit'],
            'bots'  => [[Query::POP_BOTLIKE], 'Bots and crawlers only'],
            default => [[Query::POP_HUMAN], 'Human visits only'],
        };
    }

    /**
     * What kind of thing sent each visit.
     *
     * A closed vocabulary, so every value the parser can emit is offered whether or not it had
     * traffic — an empty "Paid ad" row is a fact about the period and an ABSENT one reads as "this
     * panel cannot tell me about paid traffic". Panel\Vocabulary is the authority for the words
     * and the explanations; nothing is retyped here.
     *
     * @return array<string,mixed>
     */
    private function channels(): array
    {
        [$extra, $label] = $this->population();

        $f = $this->gw->facet('sources.channels', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => array_merge($this->sessionFqs(), $extra),
        ], [
            'types'    => ['type' => 'terms', 'field' => 'referer_type_s', 'limit' => 20, 'sort' => 'count desc'],
            'referred' => ['type' => 'query', 'q' => 'referer_host_s:*'],
        ]);

        $counts = [];
        foreach (self::buckets($f, 'types') as $bucket) {
            $counts[(string) ($bucket['val'] ?? '')] = (int) ($bucket['count'] ?? 0);
        }

        $rows = [];
        foreach (Vocabulary::knownValues('referer_type_s') as $value) {
            $spoken = Vocabulary::value('referer_type_s', $value);
            $rows[] = [
                'value'    => $value,
                'label'    => $spoken['label'],
                'why'      => $spoken['why'],
                'sessions' => $counts[$value] ?? 0,
            ];
            unset($counts[$value]);
        }
        foreach ($counts as $value => $count) {
            $rows[] = ['value' => (string) $value, 'label' => (string) $value, 'why' => '', 'sessions' => $count];
        }

        usort($rows, static fn (array $a, array $b): int => $b['sessions'] <=> $a['sessions']);

        return $this->envelope([
            'population'       => self::param('pop', ['humans', 'all', 'bots'], 'humans'),
            'population_label' => $label,
            'total'            => (int) ($f['count'] ?? 0),
            'referred'         => self::qcount($f, 'referred'),
            'rows'             => $rows,
        ]);
    }

    /**
     * Which site sent them.
     *
     * A visit with NO referrer carries no `referer_host_s` at all, so it is absent from this facet
     * rather than appearing as a blank row. The card states how many visits that is, because a
     * table of referring sites whose counts add up to a third of the traffic is one a reader will
     * otherwise assume is broken.
     *
     * @return array<string,mixed>
     */
    private function referrers(): array
    {
        [$extra, $label] = $this->population();
        $start = Paging::start();
        $rows = Paging::rows();

        $f = $this->gw->facet('sources.referrers', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => array_merge($this->sessionFqs(), $extra),
        ], [
            'hosts'    => Paging::terms('referer_host_s', $start, $rows),
            'referred' => ['type' => 'query', 'q' => 'referer_host_s:*'],
        ]);

        $out = [];
        foreach (self::buckets($f, 'hosts') as $bucket) {
            $out[] = [
                'host'     => (string) ($bucket['val'] ?? ''),
                'sessions' => (int) ($bucket['count'] ?? 0),
            ];
        }

        return $this->envelope([
            'population'       => self::param('pop', ['humans', 'all', 'bots'], 'humans'),
            'population_label' => $label,
            'total'            => (int) ($f['count'] ?? 0),
            'referred'         => self::qcount($f, 'referred'),
            'rows'             => $out,
            'page'             => Paging::block(
                $start,
                $rows,
                Paging::distinct($f, 'hosts'),
                'referring sites',
                count($out)
            ),
        ]);
    }

    /**
     * The population toggle control, in the same shape every other card's is.
     */
    private function popToggle(): string
    {
        $active = self::param('pop', ['humans', 'all', 'bots'], 'humans');
        $out = '<div class="toggle" role="group" aria-label="Population">';
        foreach ([['humans', 'Humans only'], ['all', 'Everyone'], ['bots', 'Bots &amp; crawlers']] as [$v, $l]) {
            $out .= '<button type="button" data-pop="' . Security::esc($v) . '"'
                . ($v === $active ? ' class="on" aria-pressed="true"' : ' aria-pressed="false"')
                . '>' . $l . '</button>';
        }

        return $out . '</div>';
    }

    /**
     * The static skeleton.
     */
    public function body(): void
    {
        self::cardOpen(
            'an-channels',
            Layout::cardNum(self::SECTIONS, 'an-channels'),
            'What sent them',
            'Every channel the parser recognises, including the ones with no traffic.',
            $this->popToggle() . $this->exportTool('channels')
        );
        self::skeleton('an-channels', 'rows', 0, 'Faceting referrer types');
        echo '<div class="note"><p><strong>A referrer is a claim.</strong> Browsers strip it moving from '
            . 'https to http, privacy settings remove it, and anything that wants to look like a search click '
            . 'can say it was one. <strong>Direct is the residual</strong> — no referrer arrived — not a count '
            . 'of people who typed your address in.</p></div>';
        echo '<div class="table-wrap"><table id="an-channels-table" class="table-fixed"><colgroup>'
            . '<col style="width:22%"><col style="width:12%"><col style="width:18%">'
            . '<col style="width:48%"></colgroup><thead><tr>'
            . '<th scope="col">Channel</th>'
            . '<th scope="col" class="num">Visits</th>'
            . '<th scope="col" class="bar-col">Share</th>'
            . '<th scope="col">What it means</th>'
            . '</tr></thead><tbody></tbody></table></div>';
        self::cardClose('an-channels');

        self::cardOpen(
            'an-referrers',
            Layout::cardNum(self::SECTIONS, 'an-referrers'),
            'Which site sent them',
            'Visits that sent no referrer are counted in the card above, not here.',
            $this->popToggle() . $this->exportTool('referrers')
        );
        self::skeleton('an-referrers', 'rows', 0, 'Faceting referring sites');
        echo '<div class="table-wrap"><table id="an-referrers-table" class="table-fixed"><colgroup>'
            . '<col style="width:58%"><col style="width:16%"><col style="width:26%">'
            . '</colgroup><thead><tr>'
            . '<th scope="col">Referring site</th>'
            . '<th scope="col" class="num">Visits</th>'
            . '<th scope="col" class="bar-col">Share of referred visits</th>'
            . '</tr></thead><tbody></tbody></table></div>';
        echo '<div id="an-referrers-pager"></div>';
        self::cardClose('an-referrers');
    }
}
