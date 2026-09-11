<?php
/**
 * Loghound — Plan usage: the bandwidth meter and the retention window.
 *
 * Two dimensions, deliberately given very different weight, because only one of them is
 * something the operator has to watch.
 *
 * **Bandwidth is the hard limit.** It cannot be reclaimed by deleting anything; it accrues
 * with use and resets on the 1st. Going over it blocks the index completely — Opensolr
 * answers 403 to every request, reads as well as writes — until the plan is upgraded or the
 * month rolls over, and access returns by itself about seventeen minutes after usage is back
 * under. So it gets the prominent meter, a warning state well before the limit, and an
 * upgrade link. The warning has to arrive early, because after the limit the panel that
 * would have shown it is dark.
 *
 * **Disk is managed, not dangerous.** The rolling trim in \Loghound\Quota runs BEFORE a
 * write, so the index never reaches its disk quota and the blackout never triggers on disk.
 * Presenting disk as a risk would be warning the operator about the one thing the feature
 * makes impossible. It is reported here as what it actually is: a fact about how far back
 * the data goes. No red state, no alarm, no "running out of space". The single exception is
 * a trim that FAILED while the index is genuinely near the limit — then the blackout really
 * is coming, and that is loud.
 *
 * NOTHING HERE BLOCKS A RENDER. `body()` emits headings, captions and the copy that explains
 * the consequence — all of it static, all of it escaped — and every number arrives over
 * fetch(). The control-plane call behind these figures is slow (the platform derives the
 * index size from a live Solr status request), which is exactly why \Loghound\Quota caches it
 * on a clock and a document count and why no page render is ever allowed to wait on it.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Quota;
use Loghound\Security;
use Loghound\Setup\Storage;

final class Usage extends Controller
{

    /**
     * The pages this view has, in render order.
     *
     * @var array<int,array{0:string,1:string}>
     */
    public const SECTIONS = [
        ['usage-bw', 'Bandwidth'],
        ['usage-window', 'History held'],
        ['usage-limits', 'Retention limits'],
    ];
    /** Built lazily so a view that only renders markup never constructs a client. */
    private ?Quota $quota = null;

    /** Replace the quota reader, so tests run with no network and no cache file. */
    public function setQuota(Quota $quota): void
    {
        $this->quota = $quota;
    }

    /** The quota reader for this installation. */
    private function quota(): Quota
    {
        if ($this->quota === null) {
            $this->quota = new Quota($this->cfg);
        }
        return $this->quota;
    }

    /**
     * Which page-toolbar controls this view honours.
     *
     * Nothing here is scoped by anything. "How far back does my data go" and "what does
     * the plan allow" are not questions about a time window, a host or a filter, and the
     * single query on this page deliberately asks none of them.
     *
     * @return array<int,string>
     */
    public function toolbar(): array
    {
        return [self::SCOPE_CACHE];
    }

    public function slug(): string
    {
        return 'usage';
    }

    public function title(): string
    {
        return 'Plan usage';
    }

    public function subtitle(): string
    {
        return 'Bandwidth against your plan, and how far back the data goes.';
    }

    /**
     * One dataset: everything this page knows, per index.
     *
     * A ROW PER INDEX, not a row per card. The three cards on screen are three views of the same
     * handful of facts — bandwidth against the plan, the span actually held, the projected window —
     * and splitting them into three files would leave the reader joining them back together on the
     * index name. Somebody exporting this is tracking plan usage over weeks, so what they want is
     * one line per index per reading.
     *
     * THE MEASURED AND THE PROJECTED ARE SEPARATE COLUMNS and are labelled as such. The span held
     * is a fact — newest timestamp minus oldest — while the plan window is arithmetic on an
     * observed growth rate, and a spreadsheet that folded the two into one "retention" column
     * would give the estimate a confidence nobody computed.
     *
     * Nothing on this view is scoped by a range, a host or a filter, and toolbar() says so; the
     * preamble consequently carries no time range, which is correct rather than an omission.
     *
     * @return array<string,array<string,mixed>>
     */
    public function exports(): array
    {
        return [
            'plan' => [
                'label'   => 'Plan usage by index',
                'action'  => 'plan',
                'key'     => 'cores',
                'unit'    => 'indexes',
                'cap'     => 50,
                'note'    => 'Bandwidth is the traffic served since the 1st and is the one limit that cannot '
                    . 'be reclaimed by deleting anything. An empty figure means Opensolr has not reported '
                    . 'usage for that index yet; it is not zero. The projected window is an estimate from '
                    . 'observed growth and is a different kind of number from the span actually held.',
                'scope'   => [
                    'retention_days' => 'Age limit in days (privacy.retention_days)',
                    'rollup_forever' => 'Daily rollups kept for ever',
                    'managed'        => 'Indexes managed by Opensolr',
                ],
                'columns' => [
                    ['Index', 'core', 'id'],
                    ['Role', 'role', 'text'],
                    ['Bandwidth used (MB)', 'bandwidth.used_mb', 'number'],
                    ['Plan bandwidth (MB)', 'bandwidth.limit_mb', 'number'],
                    ['Bandwidth used (percent)', 'bandwidth.percent', 'number'],
                    ['Warning threshold (percent)', 'bandwidth.warn_at', 'number'],
                    ['Bandwidth level', 'bandwidth.level', 'text'],
                    ['Span held now (days, measured)', 'span.days', 'number'],
                    ['Oldest document held', 'span.oldest', 'date'],
                    ['Newest document held', 'span.newest', 'date'],
                    ['Projected plan window (days, estimated)', 'window.plan_days', 'number'],
                    ['Index size (MB)', 'window.size_mb', 'number'],
                    ['Plan disk quota (MB)', 'window.max_size_mb', 'number'],
                    ['Observed ingest (MB per day)', 'window.ingest_mb_day', 'number'],
                    ['Index size is projected rather than reported', 'window.estimated', 'bool'],
                    ['Deleting for size is switched on', 'window.enabled', 'bool'],
                    ['Retention limit in effect', 'window.limited_by', 'text'],
                    ['Quotas over limit (Opensolr is blocking this index)', 'blocked.over', 'text'],
                    ['Disk used against the plan quota (ratio)', 'window.disk_ratio', 'number'],
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
            'meter'   => $this->meter(),
            'plan'    => $this->plan(),
            'account' => $this->account(),
            default   => ['error' => 'Unknown action'],
        };
    }

    /**
     * Everything the account is using, against everything the plan allows.
     *
     * WHAT THIS IS FOR. The top bar used to carry a bandwidth strip: one number, on every page,
     * for the one quota that cannot be reclaimed by deleting anything. It said nothing about the
     * other two — how many indexes of the allowance are in use, and how much disk each index
     * holds against its own quota — and those are exactly as capable of stopping an installation
     * dead. The strip is replaced by a control that opens this: the whole account, in one place,
     * instead of one figure in everybody's way.
     *
     * TWO CALLS AND NEITHER IS FREE, which is why this is behind a press rather than on every
     * page. The per-index figures come from the quota cache, which is shared with the meter; the
     * index allowance is a control-plane call scoped to one index the account owns.
     *
     * AN ALLOWANCE THAT CANNOT BE READ IS NULL, NEVER ZERO. A platform that does not publish
     * these fields, an account that cannot be asked, a key that was refused: all of them mean
     * unknown, and rendering unknown as "0 of 0 indexes" would tell an operator their plan is
     * full when it is not.
     *
     * @return array<string,mixed>
     */
    private function account(): array
    {
        if ($this->gw->isDemo()) {
            return $this->demo();
        }

        $plan = $this->plan();
        $summary = Storage::account($this->cfg);
        $capacity = (array) ($summary['capacity'] ?? []);

        return array_merge($plan, [
            'account' => [
                'ok'      => (bool) ($summary['ok'] ?? false),
                'error'   => (string) ($summary['error'] ?? ''),
                'limit'   => $capacity['limit'] ?? null,
                'used'    => $capacity['counted'] ?? null,
                'room'    => $capacity['room'] ?? null,
                'held'    => (int) ($summary['total'] ?? 0),
            ],
            'resets_at' => Quota::nextReset(),
            'resets_in' => Quota::secondsToReset(),
        ]);
    }

    /**
     * The always-visible bandwidth indicator, for the strip the front end puts on every page.
     *
     * Kept as small and as cheap as it can be, because it is requested by every view rather
     * than by one. It touches no Solr at all and answers from the quota cache on all but one
     * call in `quota.refresh_sec` seconds.
     *
     * The two cores are reported separately and the WORST of them drives the strip: they have
     * independent quotas on the platform, and an operator who is told "you are fine" because
     * the average of a blocked index and an idle one looks fine has been lied to.
     *
     * The refresh interval is defensible and stated here because it has a cost: the panel's
     * own queries consume the very bandwidth this meter reports, so an auto-refreshing
     * dashboard is not free on a small plan. One control-plane call per five minutes per
     * browser is a rounding error next to the Solr queries a single dashboard page issues,
     * and it is the difference between noticing a warning state and finding out from a 403.
     *
     * @return array<string,mixed>
     */
    private function meter(): array
    {
        if ($this->gw->isDemo()) {
            return $this->demo();
        }

        $quota = $this->quota();
        $cores = $this->cores();

        $rows = [];
        foreach ($cores as $role => $core) {
            if ($core === '') {
                continue;
            }
            $bw = $quota->bandwidth($core);
            $bw['role'] = $role;
            $rows[] = $bw;
        }

        return $this->envelope([
            'cores'       => $rows,
            'worst'       => self::worst($rows),
            'consequence' => Quota::CONSEQUENCE,
            'upgrade_url' => $quota->upgradeUrl(),
            'refresh_sec' => $quota->refreshSec(),
            'resets_at'   => Quota::nextReset(),
            'resets_in'   => Quota::secondsToReset(),
        ]);
    }

    /**
     * Everything the Plan usage page shows: bandwidth, the retention window, and the limits.
     *
     * The observed span is a FACT read off the index — newest timestamp minus oldest — and it
     * is kept separate from the projected window, which is an estimate from a growth rate.
     * Conflating the two would produce a confident number nobody computed.
     *
     * @return array<string,mixed>
     */
    private function plan(): array
    {
        if ($this->gw->isDemo()) {
            return $this->demo();
        }

        $quota = $this->quota();
        $rows = [];

        foreach ($this->cores() as $role => $core) {
            if ($core === '') {
                continue;
            }
            $span = $this->span($role, $core);
            $window = $quota->retentionWindow($core, $span['days']);
            $bw = $quota->bandwidth($core);

            $rows[] = [
                'role'      => $role,
                'core'      => $core,
                'window'    => $window,
                'bandwidth' => $bw,
                'span'      => $span,
                'blocked'   => self::isBlocked($window, $bw),
            ];
        }

        return $this->envelope([
            'cores'          => $rows,
            'retention_days' => (int) $this->cfg->get('privacy.retention_days', 0),
            'rollup_forever' => (bool) $this->cfg->get('privacy.rollup_forever', true),
            'consequence'    => Quota::CONSEQUENCE,
            'upgrade_url'    => $quota->upgradeUrl(),
            'managed'        => (string) $this->cfg->get('solr.mode') === 'opensolr',
        ]);
    }

    /**
     * The demo answer: no figures at all, and a sentence saying why.
     *
     * Demo mode exists so the panel can be looked at on a box where Solr has never been
     * reachable, and \Loghound\Panel\Fixtures fabricates traffic for it. Plan usage is not
     * fabricated, for two reasons that both matter. It is real money and a real limit, and a
     * plausible invented figure is exactly the kind of number somebody screenshots and then
     * makes a decision from. And the figure comes from an external control plane, so
     * producing one in demo mode would mean a demo — which is meant to work offline, and is
     * what the test suite exercises — making an outbound request with whatever API key
     * happened to be in the config file.
     *
     * @return array<string,mixed>
     */
    private function demo(): array
    {
        return $this->envelope([
            'cores'          => [],
            'worst'          => null,
            'demo_note'      => 'Plan usage is read from your Opensolr account and is never fabricated, '
                . 'so there is nothing to show in demo mode. Connect an account in '
                . 'config/loghound.php to see bandwidth and the retention window.',
            'consequence'    => Quota::CONSEQUENCE,
            'upgrade_url'    => 'https://opensolr.com/pricing',
            'refresh_sec'    => 0,
            'resets_at'      => Quota::nextReset(),
            'resets_in'      => Quota::secondsToReset(),
            'retention_days' => (int) $this->cfg->get('privacy.retention_days', 0),
            'rollup_forever' => (bool) $this->cfg->get('privacy.rollup_forever', true),
            'managed'        => false,
        ]);
    }

    /**
     * The two cores this installation writes to, keyed by the role each one plays.
     *
     * Both are reported. The hits core is what grows and is what the rolling window is
     * really about, but the sessions core has its own quota on the platform and its own
     * blackout, so leaving it out would mean an index could be blocked without the page that
     * exists to report exactly that ever mentioning it.
     *
     * @return array<string,string>
     */
    private function cores(): array
    {
        return [
            'hits'     => (string) $this->cfg->get('solr.hits_core', ''),
            'sessions' => (string) $this->cfg->get('solr.sessions_core', ''),
        ];
    }

    /**
     * The span of data actually held in one core, in days.
     *
     * One min/max facet, which is cheap, and it is the honest answer to "how far back does
     * my data go" — no growth rate, no plan arithmetic, just the two timestamps.
     *
     * The sessions core carries the daily rollup documents alongside the session documents,
     * and rollups outlive the sessions they summarise by design, so the query says which it
     * means. Without `doc_type_s:session` the answer would be the age of the oldest rollup,
     * which is a different and much larger number.
     *
     * @return array{days:?float,oldest:?string,newest:?string,docs:int}
     */
    private function span(string $role, string $core): array
    {
        $field = $role === 'sessions' ? 'ts_start' : 'ts';
        $fq = $role === 'sessions' ? [Query::SESSION_DOCS] : [];

        $f = $this->gw->facet('usage.span.' . $role, $core, [
            'q'  => '*:*',
            'fq' => $fq,
        ], [
            'oldest' => 'min(' . $field . ')',
            'newest' => 'max(' . $field . ')',
        ]);

        $oldest = is_string($f['oldest'] ?? null) ? $f['oldest'] : null;
        $newest = is_string($f['newest'] ?? null) ? $f['newest'] : null;

        $days = null;
        if ($oldest !== null && $newest !== null) {
            $a = strtotime($oldest);
            $b = strtotime($newest);
            if ($a !== false && $b !== false && $b > $a) {
                $days = round(($b - $a) / 86400, 2);
            }
        }

        return [
            'days'   => $days,
            'oldest' => $oldest,
            'newest' => $newest,
            'docs'   => (int) ($f['count'] ?? 0),
        ];
    }

    /**
     * Is this index currently blocked by the platform?
     *
     * Derived from the quota figures rather than from a live 403, and that is deliberate:
     * the control plane keeps answering while an index is blacked out, so the ratios are
     * available exactly when Solr is not. It also names the right cause. A panel that
     * reported "Solr rejected the credentials" — which is what a bare 403 usually means —
     * would send the operator to check a password that is perfectly correct.
     *
     * @param array<string,mixed> $window
     * @param array<string,mixed> $bandwidth
     * @return array<string,mixed>|null
     */
    private static function isBlocked(array $window, array $bandwidth): ?array
    {
        $bw   = $bandwidth['ratio'] ?? null;
        $disk = $window['disk_ratio'] ?? null;

        $over = [];
        if ($bw !== null && $bw >= 1.0) {
            $over[] = 'bandwidth';
        }
        if ($disk !== null && $disk >= 1.0) {
            $over[] = 'disk';
        }
        if ($over === []) {
            return null;
        }

        return [
            'over' => $over,
            'text' => 'This index is over its ' . implode(' and ', $over) . ' quota, which means Opensolr is '
                . 'denying every request to it — reads as well as writes, a 403 on /select too. '
                . (in_array('bandwidth', $over, true)
                    ? 'Bandwidth cannot be freed by deleting anything: it resets on the 1st, or an upgrade '
                      . 'clears it now. '
                    : '')
                . 'Access returns on its own about 17 minutes after usage is back under the limit.',
        ];
    }

    /**
     * The worst bandwidth state among the cores, which is what the page strip shows.
     *
     * @param array<int,array<string,mixed>> $rows
     * @return array<string,mixed>|null
     */
    private static function worst(array $rows): ?array
    {
        $rank = ['ok' => 0, 'unknown' => 1, 'warn' => 2, 'critical' => 3, 'blocked' => 4];
        $worst = null;
        foreach ($rows as $row) {
            $level = (string) ($row['level'] ?? 'unknown');
            if ($worst === null || ($rank[$level] ?? 0) > ($rank[(string) $worst['level']] ?? 0)) {
                $worst = $row;
            }
        }
        return $worst;
    }

    /**
     * The static skeleton.
     *
     * The consequence copy is rendered by PHP rather than by the front end, because it is
     * authored text that must be on the page whether or not a fetch succeeds. An operator
     * whose index is already blocked cannot load anything, and the one sentence they need is
     * the one explaining why and how long it lasts.
     */
    public function body(): void
    {
        $this->bandwidthCard();
        $this->windowCard();
        $this->limitsCard();
    }

    /** The bandwidth meter: the one number on this page that is a warning. */
    private function bandwidthCard(): void
    {
        $tools = '<a class="ghost small" id="usage-upgrade" href="'
            . Security::esc($this->quota()->upgradeUrl())
            . '" rel="noopener noreferrer" target="_blank">Upgrade plan</a>';

        self::cardOpen(
            'usage-bw',
            '01',
            'Bandwidth this month',
            'Traffic served by your Opensolr indexes since the 1st, against the plan limit.',
            $tools . $this->exportTool('plan')
        );
        self::skeleton('usage-bw', 'stats', 0, 'Reading plan usage from Opensolr');

        echo '<div class="meters" id="usage-bw-meters"></div>';

        echo '<div class="note note-hard">';
        echo '<p><strong>Almost all of this is you, reading this dashboard.</strong> If the figure above is '
            . 'climbing and you have not changed anything, the place to look is not your traffic &mdash; it is '
            . 'how many panel pages are open and how often they are refreshed. Opensolr meters what your index '
            . 'SENDS BACK, so a query that returns a facet block spends the allowance and the log lines going '
            . 'the other way barely touch it: the tailer uploads a batch and gets a short acknowledgement, '
            . 'which is why ingesting a busy site costs almost nothing and why one dashboard left open all day '
            . 'on a small plan does not.</p>';
        echo '<p><strong>What happens if you go over.</strong> ' . Security::esc(Quota::CONSEQUENCE) . '</p>';
        echo '<p>Bandwidth is the one limit here that cannot be reclaimed by deleting anything. Disk can: '
            . 'Loghound deletes the oldest traffic before it writes new traffic, so the index stays inside '
            . 'its disk quota on its own.</p>';
        echo '<p class="faint">This dashboard\'s own queries count towards the figure above, and the reading '
            . 'on this page is the cheap part of them: each open page refreshes it at most once every few '
            . 'minutes, and the refresh is a single call to the Opensolr control plane rather than to your '
            . 'index. It is the cards on every other view that do the spending.</p>';
        echo '</div>';

        self::cardClose('usage-bw');
    }

    /** How far back the data goes. Informational, and worded as such. */
    private function windowCard(): void
    {
        self::cardOpen(
            'usage-window',
            '02',
            'How far back the data goes',
            'The retention window, and what sets it.'
        );
        self::skeleton('usage-window', 'stats', 0, 'Measuring the retention window');

        echo '<div id="usage-window-rows"></div>';

        echo '<div class="note">';
        /* THE CLAIM IS CONDITIONAL, because the behaviour is. `quota.enabled = false` is a
           supported setting, and with it off none of the sentence below is true — the index CAN
           reach its quota, and the platform then blocks it for reads as well as writes. Settings
           says exactly that on the same installation; this card asserted the opposite. */
        if ($this->quota()->enabled()) {
            echo '<p><strong>Disk looks after itself.</strong> Before each batch is written, Loghound checks how '
                . 'full the index is against your plan. Above the high-water mark it deletes the oldest data '
                . 'first, by date, in bounded steps &mdash; so the index does not reach the quota and the window '
                . 'simply rolls forward. There is nothing to act on here; it is a statement of how much history '
                . 'the plan holds.</p>';
        } else {
            echo '<p><strong>Disk does not look after itself on this installation.</strong> Deleting for size '
                . 'is switched off, so nothing trims the index as it fills and it can reach its plan quota. '
                . 'An index at its quota is blocked by Opensolr &mdash; every request is answered 403, reads '
                . 'included. Turn it back on under <a href="?v=settings&s=privacy">Settings</a>, or keep '
                . 'the index inside the plan some other way.</p>';
        }
        echo '<p class="faint">The projected window is an estimate from observed growth and is described as '
            . 'one. The span actually held is not an estimate: it is the newest timestamp in the index minus '
            . 'the oldest.</p>';
        echo '</div>';

        self::cardClose('usage-window');
    }

    /** Time-based versus size-based retention, and which one currently bites. */
    private function limitsCard(): void
    {
        self::cardOpen(
            'usage-limits',
            '03',
            'The two retention limits',
            'Whichever comes first wins.'
        );
        self::skeleton('usage-limits', 'rows', 0, 'Comparing the retention limits');

        echo '<div class="table-wrap"><table id="usage-limits-table"><thead><tr>'
            . '<th scope="col">Limit</th>'
            . '<th scope="col">Set by</th>'
            . '<th scope="col" class="num">Window</th>'
            . '<th scope="col">In effect</th>'
            . '</tr></thead><tbody></tbody></table></div>';

        echo '<div class="note">';
        echo '<p><strong>Time-based</strong> retention is <code>privacy.retention_days</code> in '
            . '<code>config/loghound.php</code>, applied by <code>bin/loghound-retention</code> on its timer. '
            . 'It is a privacy decision: how long you are willing to keep a record of a visitor.</p>';
        /* "BOTH RUN" IS ONLY TRUE WHEN BOTH ARE ON. Either can be switched off — an age limit of
           0, or `quota.enabled = false` — and the card said they both ran regardless. The row
           table above already reports which is in effect; this paragraph now agrees with it. */
        echo '<p><strong>Size-based</strong> retention is this plan window, applied by the ingest daemon '
            . 'before it writes. It is a capacity decision: how much history the index can hold. '
            . 'Whichever of the two is switched on and deletes sooner is the one you see in the table '
            . 'above; a limit that is off does nothing and says so there.</p>';
        echo '<p class="faint">Daily rollup documents are never deleted by either while '
            . '<code>privacy.rollup_forever</code> is set. They carry counts rather than visitors, they cost '
            . 'almost nothing, and they are the difference between a 90-day tool and one that can show you '
            . 'last year.</p>';
        echo '</div>';

        self::cardClose('usage-limits');
    }
}
