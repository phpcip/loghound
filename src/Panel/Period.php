<?php
/**
 * Loghound — the two windows an SEO comparison reads.
 *
 * A comparison is two half-open intervals, "this period" (A) and "compared with" (B), chosen
 * from a preset or typed as calendar dates, plus the buckets each one is drawn in over time.
 *
 * CALENDAR DAYS ARE THE OPERATOR'S DAYS. "Yesterday" starts at midnight in the display timezone
 * (`ui.timezone`), never at midnight UTC, so every boundary is computed in that zone and only then
 * turned into the UTC instants Solr stores.
 *
 * A PERIOD THAT IS STILL RUNNING IS COMPARED LIKE FOR LIKE. "Today so far" at 17:05 is compared
 * with yesterday from 00:00 to 17:05, not with the whole of yesterday, because a partial day
 * against a full one is a drop that exists only in the arithmetic.
 *
 * Every string that reaches Solr is built from integers produced here, through clause() and
 * union(), and every request value is checked by validParam() before it is read.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use DateTimeImmutable;
use DateTimeZone;
use Loghound\Security;

final class Period
{
    /** The request parameters this class owns, in the order a form carries them. */
    public const KEYS = ['cmp', 'vs', 'from', 'to', 'vs_from', 'vs_to'];

    /** The preset a request that names none lands on. */
    public const DEFAULT_PRESET = 'today';

    /** The comparison a request that names none lands on. */
    public const DEFAULT_VS = 'previous';

    /** The most buckets one period is drawn in. */
    public const MAX_BUCKETS = 120;

    /**
     * The presets for period A, keyed by the value the URL carries.
     *
     * @return array<string,string>
     */
    public static function presets(): array
    {
        return [
            'today'     => 'Today so far',
            'yesterday' => 'Yesterday',
            '7d'        => 'Last 7 days',
            '28d'       => 'Last 28 days',
            '90d'       => 'Last 90 days',
            'month'     => 'This month so far',
            'lastmonth' => 'Last month',
            'custom'    => 'Custom dates',
        ];
    }

    /**
     * What period B can be, keyed by the value the URL carries.
     *
     * @return array<string,string>
     */
    public static function comparisons(): array
    {
        return [
            'previous' => 'Previous period',
            'year'     => 'Same period a year earlier',
            'custom'   => 'Custom dates',
        ];
    }

    /**
     * Is this a calendar date the picker could have produced?
     *
     * `YYYY-MM-DD`, a real date, and a year this product can hold traffic for.
     */
    public static function validDate(string $value): bool
    {
        if (preg_match('/^(\d{4})-(\d{2})-(\d{2})$/D', $value, $m) !== 1) {
            return false;
        }
        $year = (int) $m[1];
        if ($year < 2000 || $year > 2200) {
            return false;
        }
        return checkdate((int) $m[2], (int) $m[3], $year);
    }

    /**
     * Is this a value the named period parameter accepts?
     */
    public static function validParam(string $key, string $value): bool
    {
        return match ($key) {
            'cmp'                         => isset(self::presets()[$value]),
            'vs'                          => isset(self::comparisons()[$value]),
            'from', 'to', 'vs_from', 'vs_to' => self::validDate($value),
            default                       => false,
        };
    }

    /**
     * The display timezone, falling back to UTC when the configured name is not one PHP knows.
     */
    public static function timezone(string $name): DateTimeZone
    {
        try {
            return new DateTimeZone($name);
        } catch (\Throwable $e) {
            return new DateTimeZone('UTC');
        }
    }

    /**
     * Resolve a request into both windows, their labels, the form values and the buckets.
     *
     * @param array<string,mixed> $get The request parameters.
     * @param int|null            $now Unix time to resolve against; the current time when null.
     * @return array<string,mixed>
     */
    public static function resolve(array $get, DateTimeZone $tz, ?int $now = null): array
    {
        $clock = (new DateTimeImmutable('@' . ($now ?? time())))->setTimezone($tz);
        $today = $clock->setTime(0, 0);

        $preset = self::pick($get, 'cmp', self::DEFAULT_PRESET);
        $vs = self::pick($get, 'vs', self::DEFAULT_VS);

        [$aStart, $aEnd, $shift] = self::windowA(
            $preset,
            $clock,
            $today,
            self::pick($get, 'from', ''),
            self::pick($get, 'to', ''),
            $tz
        );

        $vsFrom = self::pick($get, 'vs_from', '');
        $vsTo = self::pick($get, 'vs_to', '');
        if ($vs === 'custom' && ($vsFrom === '' || $vsTo === '')) {
            $vs = self::DEFAULT_VS;
        }

        if ($vs === 'custom') {
            [$bStart, $bEnd] = array_slice(self::dates($vsFrom, $vsTo, $clock, $today, $tz), 0, 2);
        } elseif ($vs === 'year') {
            $bStart = self::yearEarlier($aStart);
            $bEnd = self::yearEarlier($aEnd->modify('-1 second'))->modify('+1 second');
        } elseif ($preset === 'month') {
            [$bStart, $bEnd] = self::previousMonthSoFar($aStart, $clock);
        } else {
            $bStart = $aStart->modify('-' . $shift);
            $bEnd = $aEnd->modify('-' . $shift);
        }

        $a = self::interval($aStart, $aEnd);
        $b = self::interval($bStart, $bEnd);
        $step = self::step(max($a['end'] - $a['start'], $b['end'] - $b['start']));

        return [
            'preset'    => $preset,
            'vs'        => $vs,
            'a'         => $a,
            'b'         => $b,
            'a_label'   => self::label($a, $tz),
            'b_label'   => self::label($b, $tz),
            'from'      => self::day($a['start'], $tz),
            'to'        => self::day($a['end'] - 1, $tz),
            'vs_from'   => self::day($b['start'], $tz),
            'vs_to'     => self::day($b['end'] - 1, $tz),
            'today'     => $today->format('Y-m-d'),
            'step'      => $step,
            'a_buckets' => self::buckets($a, $step, $tz),
            'b_buckets' => self::buckets($b, $step, $tz),
        ];
    }

    /**
     * A Solr range clause covering one interval, inclusive to the millisecond.
     *
     * The interval is half-open, so the upper bound is the last millisecond before its end. Written
     * inclusive on both sides because that is the one range form every consumer of these clauses
     * parses, the demo fixtures included.
     *
     * @param array{start:int,end:int} $interval
     */
    public static function clause(string $field, array $interval): string
    {
        if (!Security::isSafeFieldName($field)) {
            throw new \InvalidArgumentException('Unsafe range field');
        }
        $start = (int) $interval['start'];
        $end = max($start + 1, (int) $interval['end']);

        return $field . ':[' . gmdate('Y-m-d\TH:i:s', $start) . '.000Z TO '
            . gmdate('Y-m-d\TH:i:s', $end - 1) . '.999Z]';
    }

    /**
     * One clause covering both intervals: a single range when they touch, an OR of two when not.
     *
     * @param array{start:int,end:int} $a
     * @param array{start:int,end:int} $b
     */
    public static function union(string $field, array $a, array $b): string
    {
        if ($a['start'] <= $b['end'] && $b['start'] <= $a['end']) {
            return self::clause($field, [
                'start' => min($a['start'], $b['start']),
                'end'   => max($a['end'], $b['end']),
            ]);
        }
        return '(' . self::clause($field, $a) . ' OR ' . self::clause($field, $b) . ')';
    }

    /**
     * Read one period parameter, or the default when it is absent or not a value it accepts.
     *
     * @param array<string,mixed> $get
     */
    private static function pick(array $get, string $key, string $default): string
    {
        $value = $get[$key] ?? null;
        return is_string($value) && self::validParam($key, $value) ? $value : $default;
    }

    /**
     * Period A for a preset, with the calendar shift that gives its previous period.
     *
     * @return array{0:DateTimeImmutable,1:DateTimeImmutable,2:string}
     */
    private static function windowA(
        string $preset,
        DateTimeImmutable $clock,
        DateTimeImmutable $today,
        string $from,
        string $to,
        DateTimeZone $tz
    ): array {
        switch ($preset) {
            case 'yesterday':
                return [$today->modify('-1 day'), $today, '1 day'];
            case '7d':
            case '28d':
            case '90d':
                $days = (int) $preset;
                return [$today->modify('-' . ($days - 1) . ' days'), $clock, $days . ' days'];
            case 'month':
                return [$today->modify('first day of this month'), $clock, '1 month'];
            case 'lastmonth':
                $start = $today->modify('first day of previous month');
                return [$start, $today->modify('first day of this month'), '1 month'];
            case 'custom':
                if ($from !== '' && $to !== '') {
                    [$start, $end, $first, $last] = self::dates($from, $to, $clock, $today, $tz);
                    $utc = new DateTimeZone('UTC');
                    $days = (new DateTimeImmutable($first, $utc))->diff(new DateTimeImmutable($last, $utc))->days + 1;
                    return [$start, $end, max(1, (int) $days) . ' days'];
                }
                return [$today, $clock, '1 day'];
            default:
                return [$today, $clock, '1 day'];
        }
    }

    /**
     * Two typed calendar dates as an interval, in order, never reaching past now.
     *
     * Also returns the two dates as they were applied, after ordering and clamping to today.
     *
     * @return array{0:DateTimeImmutable,1:DateTimeImmutable,2:string,3:string}
     */
    private static function dates(
        string $from,
        string $to,
        DateTimeImmutable $clock,
        DateTimeImmutable $today,
        DateTimeZone $tz
    ): array {
        if (strcmp($from, $to) > 0) {
            [$from, $to] = [$to, $from];
        }
        $last = $today->format('Y-m-d');
        if (strcmp($from, $last) > 0) {
            $from = $last;
        }
        if (strcmp($to, $last) > 0) {
            $to = $last;
        }

        $start = new DateTimeImmutable($from . ' 00:00:00', $tz);
        $end = (new DateTimeImmutable($to . ' 00:00:00', $tz))->modify('+1 day');
        if ($end > $clock) {
            $end = $clock;
        }
        return [$start, $end, $from, $to];
    }

    /**
     * The same calendar date and clock time a year earlier, with February 29 landing on February 28.
     *
     * PHP rolls an impossible date forward, so a leap day would otherwise become March 1.
     */
    private static function yearEarlier(DateTimeImmutable $at): DateTimeImmutable
    {
        $shifted = $at->modify('-1 year');
        if ($shifted->format('d') !== $at->format('d')) {
            $shifted = $shifted->modify('last day of previous month');
        }
        return $shifted;
    }

    /**
     * The previous month up to the same day and clock time as now, never past its own end.
     *
     * @return array{0:DateTimeImmutable,1:DateTimeImmutable}
     */
    private static function previousMonthSoFar(DateTimeImmutable $monthStart, DateTimeImmutable $clock): array
    {
        $start = $monthStart->modify('first day of previous month');
        $offset = (int) $clock->format('j') - 1;
        $end = $start->modify('+' . $offset . ' days')->setTime(
            (int) $clock->format('G'),
            (int) $clock->format('i'),
            (int) $clock->format('s')
        );
        if ($end > $monthStart) {
            $end = $monthStart;
        }
        return [$start, $end];
    }

    /**
     * Two instants as a half-open interval in Unix seconds, never empty.
     *
     * @return array{start:int,end:int}
     */
    private static function interval(DateTimeImmutable $start, DateTimeImmutable $end): array
    {
        $s = $start->getTimestamp();
        return ['start' => $s, 'end' => max($s + 1, $end->getTimestamp())];
    }

    /**
     * The bucket size that draws a period of this length in a readable number of points.
     */
    private static function step(int $seconds): string
    {
        $day = 86400;
        if ($seconds <= 2 * $day + 3600) {
            return 'hour';
        }
        if ($seconds <= 120 * $day) {
            return 'day';
        }
        if ($seconds <= 730 * $day) {
            return 'week';
        }
        if ($seconds <= 10 * 366 * $day) {
            return 'month';
        }
        return 'year';
    }

    /**
     * The buckets one interval is drawn in, as half-open intervals in Unix seconds.
     *
     * Hours step in real seconds; days, weeks, months and years step on the calendar of the
     * display timezone, so a day is a local day across a daylight-saving change.
     *
     * @param array{start:int,end:int} $interval
     * @return array<int,array{start:int,end:int}>
     */
    private static function buckets(array $interval, string $step, DateTimeZone $tz): array
    {
        $out = [];
        $cursor = (new DateTimeImmutable('@' . $interval['start']))->setTimezone($tz);

        while (count($out) < self::MAX_BUCKETS) {
            $from = $cursor->getTimestamp();
            if ($from >= $interval['end']) {
                break;
            }
            $cursor = match ($step) {
                'hour'  => $cursor->modify('+1 hour'),
                'day'   => $cursor->modify('+1 day'),
                'week'  => $cursor->modify('+7 days'),
                'month' => $cursor->modify('first day of next month')->setTime(0, 0),
                default => $cursor->modify('first day of january next year')->setTime(0, 0),
            };
            $to = min($cursor->getTimestamp(), $interval['end']);
            if (count($out) === self::MAX_BUCKETS - 1) {
                $to = $interval['end'];
            }
            $out[] = ['start' => $from, 'end' => max($from + 1, $to)];
        }

        return $out;
    }

    /**
     * An interval in words, mm/dd/yyyy hh:mm:ss to mm/dd/yyyy hh:mm:ss, in the display timezone.
     *
     * @param array{start:int,end:int} $interval
     */
    private static function label(array $interval, DateTimeZone $tz): string
    {
        $at = static fn (int $ts): string => (new DateTimeImmutable('@' . $ts))->setTimezone($tz)->format('m/d/Y H:i:s');
        return $at($interval['start']) . ' to ' . $at($interval['end'] - 1);
    }

    /** The calendar date an instant falls on in the display timezone, as `YYYY-MM-DD`. */
    private static function day(int $ts, DateTimeZone $tz): string
    {
        return (new DateTimeImmutable('@' . $ts))->setTimezone($tz)->format('Y-m-d');
    }
}
