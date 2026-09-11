<?php
/**
 * Loghound — the Loghound index pairs an Opensolr account already holds, and whether the
 * plan has room for another.
 *
 * WHY A SEPARATE CLASS. Two questions get asked at the same moment on the storage step, by
 * both front ends, and neither has anything to do with provisioning:
 *
 *   1. "Which Loghound index pairs are already on this account?" — because one pair can
 *      serve many sites. Loghound stamps every document with the virtual host it came from,
 *      so several installations reporting into one pair stay separable in the panel by its
 *      Virtual host dimension. An operator running Loghound on six machines does not want
 *      twelve indexes; they want two, and six hostnames.
 *   2. "Is there room to create two more?" — because a plan has an index limit, and finding
 *      out halfway through provisioning means one index created, one refused, and a bill for
 *      the orphan.
 *
 * Both are answered from ONE control-plane read (get_index_list), which is what makes it
 * reasonable to ask them on every visit to the storage step.
 *
 * WHERE THE ALLOWANCE COMES FROM. `get_account_summary` reports `index_limit`,
 * `indexes_used` and `indexes_available`, built by the platform from the same two calls its
 * own create gate consults — so the number Loghound shows and the number the platform enforces
 * cannot drift apart. It is READ, every time, and never remembered: a stored allowance goes
 * stale the moment a plan changes, and it goes stale silently.
 *
 * It costs an existing index to ask, because the endpoint is scoped to one core the account
 * owns. An account holding nothing therefore has no readable allowance, and neither does an
 * older platform that does not return the fields yet. Both are reported as UNKNOWN and neither
 * blocks: refusing on a number nobody has would strand an operator whose plan was fine. The
 * guarantee is kept where it still can be — nothing is left behind when the second create is
 * the one that fails.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Setup;

use Loghound\Config;
use Loghound\Opensolr;
use Loghound\Security;

final class Pairs
{
    /** Indexes one Loghound installation needs: one for hits, one for sessions. */
    public const NEEDED = 2;

    /** The two halves of a pair, in the order they are created and displayed. */
    public const ROLES = ['hits', 'sessions'];

    /**
     * The option value meaning "provision a new pair for me", on every surface.
     *
     * It sits in the same list as the pairs and is submitted through the same field, because
     * the operator is making ONE choice. A separate control would be a second decision, and
     * the one thing every front end has to agree on is that there is only one.
     */
    public const CHOICE_NEW = 'new';

    /**
     * Config key recording that an account is set and its indexes have not been chosen yet.
     *
     * WHY IT IS RECORDED RATHER THAN DETECTED. Saving an account and choosing indexes are two
     * steps, so between them the configuration legitimately names indexes the account does not
     * hold. Noticing that costs a control-plane call, and the panel is not allowed to make one
     * per page: a momentary outage would then read as "your indexes are gone". So the fact is
     * written down at the one moment it is known for certain — when the account was saved and
     * the platform had just listed what it holds — and cleared at the one moment it stops being
     * true, when the platform confirms the newly chosen pair.
     */
    public const PENDING_KEY = 'opensolr.pair_pending';

    /**
     * Split a core name into the installation id and role it encodes.
     *
     * The shape is Config::coreName()'s, and it is matched rather than reimplemented loosely:
     * a name that does not match exactly is not a Loghound index, and treating a
     * near-miss as one would offer an operator somebody else's index to write into.
     *
     * @return array{install_id:string,role:string}|null
     */
    public static function parse(string $name): ?array
    {
        if (preg_match('/^loghound_([a-f0-9]{4,32})_(hits|sessions)$/D', $name, $m) !== 1) {
            return null;
        }
        return ['install_id' => $m[1], 'role' => $m[2]];
    }

    /**
     * Group an account's indexes into complete Loghound pairs and unmatched halves.
     *
     * AN UNMATCHED HALF IS A REAL STATE AND IS REPORTED AS ONE. It is what a provisioning
     * run that died between the two creates leaves behind, and it is billable. Hiding it
     * would leave the operator paying for something no screen ever mentions; quietly
     * adopting it would be worse, because the missing half has to be created and that is a
     * decision with a cost attached. So it is listed, named, and given a way forward.
     *
     * Pairs are ordered by installation id so the list does not reshuffle between visits —
     * the platform returns rows in whatever order its query produced, and a list of
     * near-identical names that moves under the operator's cursor is a list nobody can pick
     * from safely.
     *
     * @param array<int,array{name:string,type:string}> $entries From Opensolr::listIndexEntries().
     * @return array{pairs:array<int,array{install_id:string,hits:string,sessions:string}>,
     *               halves:array<int,array{install_id:string,role:string,name:string,missing:string}>,
     *               total:int,counted:int}
     */
    public static function group(array $entries): array
    {
        $byId = [];
        foreach ($entries as $entry) {
            $name = (string) ($entry['name'] ?? '');
            $part = self::parse($name);
            if ($part === null) {
                continue;
            }
            $byId[$part['install_id']][$part['role']] = $name;
        }
        ksort($byId);

        $pairs  = [];
        $halves = [];
        foreach ($byId as $installId => $roles) {
            if (isset($roles['hits'], $roles['sessions'])) {
                $pairs[] = [
                    'install_id' => (string) $installId,
                    'hits'       => $roles['hits'],
                    'sessions'   => $roles['sessions'],
                ];
                continue;
            }
            $role = isset($roles['hits']) ? 'hits' : 'sessions';
            $halves[] = [
                'install_id' => (string) $installId,
                'role'       => $role,
                'name'       => $roles[$role],
                'missing'    => Config::coreName((string) $installId, $role === 'hits' ? 'sessions' : 'hits'),
            ];
        }

        return [
            'pairs'   => $pairs,
            'halves'  => $halves,
            'total'   => count($entries),
            'counted' => Opensolr::countAgainstLimit($entries),
        ];
    }

    /**
     * What the plan allows, what is in use, and whether that leaves room.
     *
     * EVERY NUMBER IS THE PLATFORM'S OWN when the platform gave one. `$available` is preferred
     * over subtracting, because it is the figure the create gate is about to apply and
     * arithmetic here could only ever disagree with it. `$counted` is the locally counted
     * standalone index list, used for the usage figure only when the platform did not report
     * one — it answers the same question and is always available.
     *
     * `limit` is null when it could not be read: an account holding no index has no core to
     * name on the endpoint that reports it, and a platform older than the field does not send
     * it. `blocked` is therefore true only when the allowance is KNOWN and genuinely too small.
     * An unknown allowance never blocks, because refusing on a number nobody has is how an
     * installer strands somebody whose plan was fine all along.
     *
     * @param int      $counted   Standalone indexes counted from the account's own list.
     * @param int|null $limit     `index_limit` from get_account_summary.
     * @param int|null $used      `indexes_used` from get_account_summary.
     * @param int|null $available `indexes_available` from get_account_summary.
     * @param int      $needed    How many indexes the operator is about to ask for.
     * @return array{counted:int,limit:?int,needed:int,room:?int,blocked:bool,sentence:string}
     */
    public static function capacity(
        int $counted,
        ?int $limit = null,
        ?int $used = null,
        ?int $available = null,
        int $needed = self::NEEDED
    ): array {
        $counted = max(0, $used ?? $counted);
        $needed  = max(0, $needed);

        $room = $available !== null
            ? max(0, $available)
            : ($limit === null ? null : max(0, $limit - $counted));

        $blocked = $limit !== null && $room !== null && $room < $needed;

        return [
            'counted'  => $counted,
            'limit'    => $limit,
            'needed'   => $needed,
            'room'     => $room,
            'blocked'  => $blocked,
            'sentence' => self::sentence($counted, $limit, $needed, $room, $blocked),
        ];
    }

    /**
     * One sentence stating the numbers, in the same words in both front ends.
     *
     * Every branch names all of the figures it has — allowed, in use, needed — because
     * "your plan is full" is not something an operator can act on, and "your plan allows 5
     * indexes, 5 are in use, and Loghound needs 2" is.
     */
    private static function sentence(int $counted, ?int $limit, int $needed, ?int $room, bool $blocked): string
    {
        $indexes = static fn(int $n): string => $n . ' ' . ($n === 1 ? 'index' : 'indexes');

        if ($limit === null) {
            return 'This Opensolr account holds ' . $indexes($counted) . '. How many your plan allows '
                . 'could not be read' . ($counted === 0
                    ? ' — that figure is reported against an index, and this account has none yet'
                    : ' from this account just now')
                . ', so Loghound will not claim it has checked. If the plan turns out to be full, the '
                . 'platform says so on the first index and nothing is left behind.';
        }

        if ($blocked) {
            return 'Your Opensolr plan allows ' . $indexes($limit) . ' and ' . $counted . ' '
                . ($counted === 1 ? 'is' : 'are') . ' already in use, so there is room for '
                . ($room === 0 ? 'none' : $room) . ' more and Loghound needs ' . $needed . '.';
        }

        return 'Your Opensolr plan allows ' . $indexes($limit) . ' and ' . $counted . ' '
            . ($counted === 1 ? 'is' : 'are') . ' in use, so there is room for the ' . $needed
            . ' Loghound needs.';
    }

    /**
     * The ways out of a full plan that genuinely exist, in the order worth trying them.
     *
     * Reuse is first and is only offered when there IS a pair to reuse, because an option
     * that turns out not to apply is worse than no option. Freeing a slot and upgrading both
     * link to the account rather than describing where to click, since only the account page
     * knows what this operator's plan looks like.
     *
     * @param bool $haveReusable Whether the account already holds a complete Loghound pair.
     * @return array<int,array{key:string,text:string,url:string}>
     */
    public static function waysForward(bool $haveReusable): array
    {
        $out = [];

        if ($haveReusable) {
            $out[] = [
                'key'  => 'reuse',
                'text' => 'Reuse a pair of Loghound indexes this account already has. Nothing new is '
                    . 'created, so the plan limit does not apply, and this site is told apart from the '
                    . 'others reporting into them by its hostname.',
                'url'  => '',
            ];
        }

        $out[] = [
            'key'  => 'free',
            'text' => 'Delete an index you no longer need, which frees a slot immediately.',
            'url'  => Storage::URL_INDEXES,
        ];
        $out[] = [
            'key'  => 'upgrade',
            'text' => 'Move to a plan that allows more indexes.',
            'url'  => Storage::URL_PLANS,
        ];

        return $out;
    }

    /**
     * Is this pair one this installation is already pointed at?
     *
     * Used to mark the current pair in the list rather than offering it as a change, so an
     * operator re-running setup is not invited to "switch" to what they already have.
     *
     * @param array{hits:string,sessions:string} $pair
     */
    public static function isCurrent(Config $cfg, array $pair): bool
    {
        return $pair['hits'] === (string) $cfg->get('solr.hits_core', '')
            && $pair['sessions'] === (string) $cfg->get('solr.sessions_core', '');
    }

    /**
     * Find one pair by its installation id, among those the account holds.
     *
     * The id is matched against the DISCOVERED list rather than trusted and turned into two
     * names: the value arrives from a form field, and a name built from an unchecked id is a
     * name this installation would then write documents into. Nothing is selectable that the
     * platform did not just say the account owns.
     *
     * @param array<int,array{install_id:string,hits:string,sessions:string}> $pairs
     * @return array{install_id:string,hits:string,sessions:string}|null
     */
    public static function find(array $pairs, string $installId): ?array
    {
        if (!preg_match('/^[a-f0-9]{4,32}$/D', $installId)) {
            return null;
        }
        foreach ($pairs as $pair) {
            if ($pair['install_id'] === $installId) {
                return $pair;
            }
        }
        return null;
    }

    /**
     * What reusing this pair means, said before the operator commits to it.
     *
     * Names the consequence rather than the mechanism, because the consequence is the part
     * that is irreversible in practice: the traffic of this site lands in indexes that
     * already hold somebody else's, and the two are only ever separable by hostname.
     *
     * @param array{hits:string,sessions:string} $pair
     */
    public static function reuseConsequence(array $pair, string $host): string
    {
        $where = $host !== '' ? $host : 'this site';

        return 'Nothing in ' . $pair['hits'] . ' or ' . $pair['sessions'] . ' is cleared, reshaped '
            . 'or overwritten. What this installation records joins what is already in there, and '
            . 'the two are told apart by the hostname on every document — so ' . $where . ' shows up '
            . 'as its own value under Virtual host in the panel, alongside whatever else reports '
            . 'into this pair.';
    }

    /**
     * The hostname this installation will stamp on its documents, for the sentence above.
     *
     * Taken from the configured public address when there is one, because that is the value
     * the operator has already seen and confirmed. An unset address yields an empty string
     * and the sentence degrades to a generic phrase rather than naming a host nobody chose.
     */
    public static function siteHost(Config $cfg): string
    {
        $base = (string) $cfg->get('base_url', '');
        if ($base === '' || Security::urlHasUserinfo($base)) {
            return '';
        }
        $host = (string) parse_url($base, PHP_URL_HOST);
        return $host;
    }

    /**
     * Does the account that is configured NOW hold the pair this installation is pointed at?
     *
     * Answered from a snapshot the caller already has, so nothing here touches the network and
     * no front end pays a second read to learn something it was just told. The verdict is also
     * written into PENDING_KEY, which is what makes the interim state survive a redirect, a page
     * reload and a new sign-in.
     *
     * The four answers lead to four different sentences, and collapsing any two of them would
     * be a lie an operator acts on:
     *
     *   'unset'   — no pair is configured at all. A fresh install; there is nothing to be wrong.
     *   'owned'   — the account holds it. Normal running.
     *   'missing' — the account authenticates and does not hold it. The interim state.
     *   'unknown' — the account could not be read, so the question was not answered. A network
     *               hiccup must never be recorded as "your indexes are gone", so the flag is
     *               left exactly as it was rather than set or cleared on no evidence.
     *
     * @param array<string,mixed> $account A Storage::account() snapshot.
     * @return string One of 'unset', 'owned', 'missing', 'unknown'.
     */
    public static function settleOwnership(Config $cfg, array $account): string
    {
        $hits     = (string) $cfg->get('solr.hits_core', '');
        $sessions = (string) $cfg->get('solr.sessions_core', '');

        if ($hits === '' || $sessions === '') {
            self::clearPending($cfg);
            return 'unset';
        }

        if (empty($account['ok'])) {
            return 'unknown';
        }

        foreach ((array) ($account['pairs'] ?? []) as $pair) {
            if (self::isCurrent($cfg, (array) $pair)) {
                self::clearPending($cfg);
                return 'owned';
            }
        }

        $cfg->set(self::PENDING_KEY, true);
        return 'missing';
    }

    /** Forget that indexes were outstanding, because they are not any more. */
    public static function clearPending(Config $cfg): void
    {
        $cfg->set(self::PENDING_KEY, false);
    }

    /** Is an account set with its indexes still unchosen? */
    public static function isPending(Config $cfg): bool
    {
        return (bool) $cfg->get(self::PENDING_KEY, false);
    }

    /** The interim state in one line, for a banner that has room for one. */
    public static function pendingHeadline(): string
    {
        return 'An Opensolr account is set and its indexes have not been chosen yet.';
    }

    /**
     * The interim state, in full, ending in the choice that resolves it.
     *
     * It names the two indexes because the operator is about to go looking for them in an
     * account page, and it says what the panel will do meanwhile — stay empty — because an
     * empty dashboard with no explanation is the failure this sentence exists to prevent.
     */
    public static function pendingDetail(Config $cfg): string
    {
        $hits     = (string) $cfg->get('solr.hits_core', '');
        $sessions = (string) $cfg->get('solr.sessions_core', '');

        $named = $hits !== '' && $sessions !== ''
            ? ' — ' . $hits . ' and ' . $sessions . ' — '
            : ' ';

        return 'The two indexes this configuration names' . $named . 'belong to the account that '
            . 'was set before this one, so this account can neither read them nor write to them '
            . 'and every number in the panel stays empty until you say which indexes to use. '
            . 'Pick a pair this account already holds, or have Loghound make a new one.';
    }

    /** The heading step two carries, identically, wherever it is rendered. */
    public static function choiceHeading(): string
    {
        return 'Which indexes this installation uses';
    }

    /**
     * The line above the list, which depends only on how many pairs there are to offer.
     *
     * ONE PAIR IS STILL A CHOICE. It is listed and picked exactly like five would be, because
     * the operator has said which account to use and has not yet said anything about indexes —
     * adopting the only pair on their behalf would be Loghound deciding where their traffic
     * lands and calling it a convenience.
     */
    public static function choiceIntro(int $pairCount): string
    {
        if ($pairCount <= 0) {
            return self::noPairsReason();
        }

        if ($pairCount === 1) {
            return 'This account holds one pair of Loghound indexes. Pick it and this site records '
                . 'into it alongside whatever is already there, or have Loghound make a pair of its '
                . 'own for this site.';
        }

        return 'This account holds ' . $pairCount . ' pairs of Loghound indexes. Pick the one this '
            . 'site records into, or have Loghound make a pair of its own for it.';
    }

    /**
     * Why the list is empty, said instead of showing an empty list.
     *
     * An empty list with no explanation reads as a failure — the operator wonders whether the
     * read worked — and the honest answer is that a new account simply has nothing on it yet.
     */
    public static function noPairsReason(): string
    {
        return 'This account holds no Loghound indexes yet, so there is nothing on the list to pick '
            . 'from. Have Loghound make the first pair and it appears here from then on.';
    }

    /** The label on the option that provisions, in the same words on every surface. */
    public static function provisionLabel(): string
    {
        return 'Make a new pair for this site';
    }

    /**
     * What picking "make a new pair" commits the operator to.
     *
     * The generated names are explained rather than apologised for: an operator who was not
     * told why they cannot choose the name assumes Loghound is being unhelpful, when in fact an
     * Opensolr index name is unique across the whole platform and any fixed name would collide.
     */
    public static function provisionDetail(string $region): string
    {
        return 'Two indexes are created' . ($region !== '' ? ' in ' . $region : '')
            . ' under names generated for you, because an Opensolr index name has to be unique '
            . 'across the whole platform. They count against your plan, and nothing already on '
            . 'the account is touched.';
    }

    /**
     * Why "make a new pair" is not on the list, when the plan has no room for one.
     *
     * The numbers come from capacity() rather than being described, because "your plan is full"
     * is not something an operator can act on and "5 allowed, 5 in use, 2 needed" is.
     *
     * @param array{sentence:string} $capacity
     */
    public static function noRoomNote(array $capacity): string
    {
        return 'Making a new pair is not offered here because there is no room for one. '
            . (string) ($capacity['sentence'] ?? '');
    }

    /**
     * An unmatched half, named for what it is, in the same words on every surface.
     *
     * It is listed rather than hidden because it is billable, and it is not selectable because
     * half a pair is not somewhere Loghound can work — hits and sessions are two different
     * shapes and adopting one without the other leaves a step of setup no screen can finish.
     *
     * @param array{name:string,missing:string} $half
     */
    public static function halfNotice(array $half): string
    {
        return (string) $half['name'] . ' is on this account without its matching '
            . (string) $half['missing'] . ', which is what a setup run that stopped half way leaves '
            . 'behind. It cannot be picked here, because half a pair is not somewhere Loghound can '
            . 'work; it holds nothing useful on its own, and it still counts against your plan. '
            . 'Delete it in your Opensolr account when you want the slot back — Loghound will not '
            . 'touch it either way.';
    }

    /**
     * Neither option is available: nothing to reuse, and no room to create.
     *
     * This is the one state with no way forward inside Loghound, so it says so with the real
     * numbers and hands over to waysForward(), which lists only the routes that genuinely exist.
     *
     * @param array{sentence:string} $capacity
     */
    public static function deadEnd(array $capacity): string
    {
        return 'There is nothing to pick here yet: this account holds no pair of Loghound indexes, '
            . 'and there is no room to create one. ' . (string) ($capacity['sentence'] ?? '');
    }

    /**
     * The line introducing the ways forward, counting the ones there actually are.
     *
     * It used to say "Three ways on from here" above a list that held two whenever there was no
     * pair to reuse, which is the kind of detail that teaches an operator to stop trusting the
     * screen.
     *
     * @param array<int,array<string,mixed>> $ways
     */
    public static function waysHeading(array $ways): string
    {
        $count = count($ways);
        $word  = [1 => 'One way', 2 => 'Two ways', 3 => 'Three ways'][$count] ?? ($count . ' ways');

        return $word . ' on from here:';
    }

    /**
     * STEP TWO, DECIDED ONCE: what the operator may pick, and every sentence around it.
     *
     * This is the whole of the decision the four front ends share. They differ in how they draw
     * a list — a shell cannot render a radio and a browser cannot read a TTY — and in nothing
     * else: the options, their order, the labels, the consequences, the refusals and the numbers
     * in them all come from here. The repository has been bitten twice by the alternative, most
     * recently by a shell wizard and a browser installer that had drifted on prerequisites and
     * error wording, which is why the installer rework exists at all.
     *
     * Nothing here touches the network. It is a pure function of a Storage::account() snapshot
     * and the configuration, so a front end can render it, test it, or print it without a
     * control-plane call of its own.
     *
     * WHATEVER IS PICKED, THE OUTCOME IS TWO VALID INDEXES. `pairs` are offered only when the
     * platform has just confirmed the account holds them, `can_new` only when the plan has room,
     * and when neither holds, `dead_end` says so with the numbers instead of offering a control
     * that cannot succeed.
     *
     * @param array<string,mixed> $account A Storage::account() snapshot.
     * @return array{ok:bool,error:string,heading:string,intro:string,
     *               pairs:array<int,array{install_id:string,hits:string,sessions:string,current:bool}>,
     *               halves:array<int,string>,can_new:bool,new_label:string,new_detail:string,
     *               new_blocked:string,consequence:string,dead_end:string,
     *               ways:array<int,array{key:string,text:string,url:string}>,ways_heading:string,
     *               capacity:array<string,mixed>}
     */
    public static function decide(Config $cfg, array $account): array
    {
        $ok       = !empty($account['ok']);
        $capacity = (array) ($account['capacity'] ?? []);
        $blocked  = !empty($capacity['blocked']);

        $pairs = [];
        foreach ((array) ($account['pairs'] ?? []) as $pair) {
            $pair = (array) $pair;
            $pairs[] = [
                'install_id' => (string) $pair['install_id'],
                'hits'       => (string) $pair['hits'],
                'sessions'   => (string) $pair['sessions'],
                'current'    => self::isCurrent($cfg, $pair),
            ];
        }

        $halves = [];
        foreach ((array) ($account['halves'] ?? []) as $half) {
            $halves[] = self::halfNotice((array) $half);
        }

        $canNew   = $ok && !$blocked;
        $deadEnd  = $ok && $pairs === [] && $blocked ? self::deadEnd($capacity) : '';
        $ways     = $ok && $blocked ? self::waysForward($pairs !== []) : [];

        return [
            'ok'           => $ok,
            'error'        => (string) ($account['error'] ?? ''),
            'heading'      => self::choiceHeading(),
            'intro'        => $ok && $deadEnd === '' ? self::choiceIntro(count($pairs)) : '',
            'pairs'        => $pairs,
            'halves'       => $halves,
            'can_new'      => $canNew,
            'new_label'    => self::provisionLabel(),
            'new_detail'   => self::provisionDetail((string) $cfg->get('opensolr.region', '')),
            'new_blocked'  => $ok && $blocked && $pairs !== [] ? self::noRoomNote($capacity) : '',
            'consequence'  => $pairs !== []
                ? self::reuseConsequence($pairs[0], self::siteHost($cfg))
                : '',
            'dead_end'     => $deadEnd,
            'ways'         => $ways,
            'ways_heading' => self::waysHeading($ways),
            'capacity'     => $capacity,
        ];
    }
}
