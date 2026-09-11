<?php
/**
 * Loghound — Analytics: when they come.
 *
 * Hour of day against day of week, which is the conventional pair of axes for a traffic heatmap
 * and the one that actually earns its place here. A scraper on a schedule is invisible in a
 * timeline — it is a small bump among the day's real traffic — and unmistakable in this grid,
 * because it lands in the same cell every week and nothing a person does is that punctual.
 *
 * ## How it is built, and why not in Solr
 *
 * Solr has no date-part faceting: there is no way to ask a range facet for "group these by the
 * hour of the day they fell in". So the request is an ordinary hourly range facet over the
 * selected window, and the folding into a seven-by-twenty-four grid happens here, in PHP, in the
 * DISPLAY TIMEZONE. That last part is the reason it cannot be done in the browser either without
 * shipping up to 2,160 bucket counts to do it: the panel renders every instant in
 * `ui.timezone`, and a heatmap drawn in UTC would put a European site's morning peak in the
 * middle of the night.
 *
 * ## What the colour means, and why it is not the raw total
 *
 * A ninety-day window holds about thirteen Mondays and a nine-day window holds one or two, so
 * colouring by the TOTAL in a cell would make whichever weekday happened to occur more often look
 * busier. Each cell therefore also counts how many times that hour actually occurred inside the
 * window, and the colour is the AVERAGE per occurrence. The total is still in the cell's tooltip,
 * because "eleven visits in all, across two Tuesdays" is a different sentence from "five and a
 * half visits on a typical Tuesday at 09:00" and the reader is entitled to both.
 *
 * A cell that never occurred in the window is not zero traffic — it is no observation — and it is
 * drawn as an absence rather than as the coldest colour. On a one-hour range that is 167 of the
 * 168 cells, and the card says so instead of drawing an almost-empty grid and letting it read as
 * a quiet week.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Security;

final class Rhythm extends Controller
{
    /**
     * The cards, in render order, with the short labels the jump bar and the navigation use.
     *
     * @var array<int,array{0:string,1:string}>
     */
    public const SECTIONS = [
        ['an-heat', 'Heatmap'],
        ['an-hours', 'Busiest hours'],
    ];

    /** Days of the week, Monday first, as the grid's rows. */
    private const DAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];

    /**
     * Which page-toolbar controls this view honours.
     *
     * The range facet is bounded by `$this->range` and the query runs under sessionFqs(), which
     * carries the virtual host and every active filter.
     *
     * @return array<int,string>
     */
    public function toolbar(): array
    {
        return [self::SCOPE_RANGE, self::SCOPE_HOST, self::SCOPE_FACETS, self::SCOPE_CACHE];
    }

    public function slug(): string
    {
        return 'rhythm';
    }

    public function title(): string
    {
        return 'When they come';
    }

    public function subtitle(): string
    {
        return 'Hour of day against day of week — where a schedule shows up and a person does not.';
    }

    /**
     * The grid, as one record per cell.
     *
     * Flattened rather than written as a 7×24 block, because a spreadsheet pivots a long table and
     * cannot do anything useful with a grid that was already laid out for a screen. Every record
     * carries its own denominator, so the average can be recomputed and checked.
     *
     * @return array<string,array<string,mixed>>
     */
    public function exports(): array
    {
        return [
            'heat' => [
                'label'   => 'Traffic by hour and weekday',
                'action'  => 'heat',
                'key'     => 'cells',
                'unit'    => 'hour-of-week cells',
                'cap'     => 200,
                'carry'   => ['pop'],
                'note'    => 'One record per hour of the week. "Times observed" is how often that hour actually '
                    . 'occurred inside the selected window — a nine-day window holds one Monday at 09:00 and two '
                    . 'Wednesdays at 09:00 — and the average is the total divided by it. An hour that never '
                    . 'occurred carries a zero observation count and no average, which is not the same as no '
                    . 'traffic. Times are in the panel\'s display timezone, not UTC.',
                'scope'   => [
                    'population_label' => 'Population',
                    'timezone'         => 'Timezone the hours are in',
                    'hours_observed'   => 'Hours of observation in the window',
                ],
                'columns' => [
                    ['Day', 'day', 'text'],
                    ['Hour', 'hour', 'number'],
                    ['Visits in all', 'total', 'number'],
                    ['Times observed', 'observed', 'number'],
                    ['Average per occurrence', 'avg', 'number'],
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
            'heat'  => $this->heat(),
            default => ['error' => 'Unknown action'],
        };
    }

    /**
     * The population toggle, as a filter and its words.
     *
     * THE TOGGLE IS THE POINT OF THE PAGE. "Every hour of every week looks the same except 03:00
     * on Tuesdays" is a sentence about automation, and it is invisible while the automation is
     * mixed in with the human traffic that dwarfs it. Three choices, allowlisted, never a filter
     * string from the browser.
     *
     * @return array{0:array<int,string>,1:string}
     */
    private function population(): array
    {
        return match (self::param('pop', ['all', 'humans', 'bots'], 'all')) {
            'humans' => [[Query::POP_HUMAN], 'Human visits only'],
            'bots'   => [[Query::POP_BOTLIKE], 'Bots and crawlers only'],
            default  => [[], 'Every visit'],
        };
    }

    /**
     * Fold an hourly range facet into a seven-by-twenty-four grid in the display timezone.
     *
     * @return array<string,mixed>
     */
    private function heat(): array
    {
        [$extra, $label] = $this->population();

        $f = $this->gw->facet('rhythm.heat', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => array_merge($this->sessionFqs(), $extra),
        ], [
            'hours' => [
                'type'  => 'range',
                'field' => 'ts_start',
                'start' => $this->range['start'],
                'end'   => 'NOW',
                'gap'   => '+1HOUR',
            ],
        ]);

        $tz = $this->displayTimezone();
        $utc = new \DateTimeZone('UTC');

        $totals = array_fill(0, 7, array_fill(0, 24, 0));
        $observed = array_fill(0, 7, array_fill(0, 24, 0));
        $hours = 0;

        foreach (self::buckets($f, 'hours') as $bucket) {
            $stamp = isset($bucket['val']) && is_scalar($bucket['val']) ? (string) $bucket['val'] : '';
            if ($stamp === '') {
                continue;
            }
            try {
                $moment = new \DateTimeImmutable($stamp, $utc);
            } catch (\Throwable $e) {
                continue;
            }
            $local = $moment->setTimezone($tz);
            $day = ((int) $local->format('N')) - 1;
            $hour = (int) $local->format('G');
            if ($day < 0 || $day > 6 || $hour < 0 || $hour > 23) {
                continue;
            }

            $totals[$day][$hour] += (int) ($bucket['count'] ?? 0);
            $observed[$day][$hour]++;
            $hours++;
        }

        $cells = [];
        $peak = 0.0;
        foreach (self::DAYS as $day => $name) {
            for ($hour = 0; $hour < 24; $hour++) {
                $seen = $observed[$day][$hour];
                $avg = $seen > 0 ? $totals[$day][$hour] / $seen : null;
                if ($avg !== null && $avg > $peak) {
                    $peak = $avg;
                }
                $cells[] = [
                    'day'      => $name,
                    'dow'      => $day,
                    'hour'     => $hour,
                    'total'    => $totals[$day][$hour],
                    'observed' => $seen,
                    'avg'      => $avg,
                ];
            }
        }

        return $this->envelope([
            'population'       => self::param('pop', ['all', 'humans', 'bots'], 'all'),
            'population_label' => $label,
            'timezone'         => $tz->getName(),
            'days'             => self::DAYS,
            'hours_observed'   => $hours,
            'cells'            => $cells,
            'peak'             => $peak,
            'total'            => (int) ($f['count'] ?? 0),
        ]);
    }

    /**
     * The timezone every hour on this page is expressed in.
     *
     * Validated against PHP's own database and defaulted to UTC, because an unknown name would
     * make DateTimeZone throw in the middle of building a response.
     */
    private function displayTimezone(): \DateTimeZone
    {
        try {
            return new \DateTimeZone((string) $this->cfg->get('ui.timezone', 'UTC'));
        } catch (\Throwable $e) {
            return new \DateTimeZone('UTC');
        }
    }

    /**
     * The static skeleton.
     */
    public function body(): void
    {
        $tools = '<div class="toggle" role="group" aria-label="Population">';
        foreach ([['all', 'Everyone'], ['humans', 'Humans only'], ['bots', 'Bots &amp; crawlers']] as [$v, $l]) {
            $tools .= '<button type="button" data-pop="' . Security::esc($v) . '"'
                . ($v === 'all' ? ' class="on" aria-pressed="true"' : ' aria-pressed="false"')
                . '>' . $l . '</button>';
        }
        $tools .= '</div>' . $this->exportTool('heat');

        self::cardOpen(
            'an-heat',
            Layout::cardNum(self::SECTIONS, 'an-heat'),
            'Hour of day by day of week',
            'Shaded by the average visits in that hour, not the total.',
            $tools
        );
        self::skeleton('an-heat', 'chart', 300, 'Folding the range into hours of the week');
        echo '<div id="an-heat-grid"></div>';
        echo '<div class="note"><p><strong>Average, not total.</strong> A ninety-day window holds thirteen '
            . 'Mondays and a nine-day window holds one, so a total would make whichever weekday came round '
            . 'more often look busier. An hour the window never covered is drawn as a gap: no observation is '
            . 'not the same fact as no traffic.</p></div>';
        self::cardClose('an-heat');

        self::cardOpen(
            'an-hours',
            Layout::cardNum(self::SECTIONS, 'an-hours'),
            'The busiest hours of the week',
            'The same grid as a list.'
        );
        self::skeleton('an-hours', 'rows', 0, 'Ranking the hours of the week');
        echo '<div class="table-wrap"><table id="an-hours-table" class="table-fixed"><colgroup>'
            . '<col style="width:26%"><col style="width:16%"><col style="width:16%">'
            . '<col style="width:16%"><col style="width:26%"></colgroup><thead><tr>'
            . '<th scope="col">Hour of the week</th>'
            . '<th scope="col" class="num">Average visits</th>'
            . '<th scope="col" class="num">Visits in all</th>'
            . '<th scope="col" class="num">Times observed</th>'
            . '<th scope="col" class="bar-col">Share of the peak</th>'
            . '</tr></thead><tbody></tbody></table></div>';
        echo '<div id="an-hours-pager"></div>';
        self::cardClose('an-hours');
    }
}
