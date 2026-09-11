<?php
/**
 * Loghound — choosing which indexes an installation uses, as one choice, on every surface.
 *
 * WHAT THESE PIN.
 *
 * 1. SAYING WHICH ACCOUNT IS NOT SAYING WHICH INDEXES. Step one saves the account on its own,
 *    with no guard about what that account holds and no checkbox qualifying a different
 *    decision. The checkbox that used to be there is gone, and it must not come back: it led
 *    with the guard instead of the situation and it existed to prevent a state that is
 *    legitimate.
 *
 * 2. THE STATE BETWEEN THE TWO STEPS IS REAL AND IS REPORTED. An account is set, its indexes
 *    have not been chosen, and the panel says exactly that — not "a service is not answering",
 *    which is what an unowned index used to surface as. It survives a redirect, a reload and a
 *    new sign-in, because an operator who saves an account and closes the tab has to be able to
 *    come back and finish.
 *
 * 3. STEP TWO IS A LIST PLUS ONE MORE OPTION. Every pair the account holds, selectable, however
 *    few there are; plus "make a new pair". No account with a usable route out is ever left
 *    without one, and nobody is forced into two new indexes.
 *
 * 4. THE EDGES READ AS THEMSELVES. No pairs says why the list is empty. An unmatched half is
 *    named as the leftover it is and is not selectable. No pairs AND no room is a dead end with
 *    the real numbers and the ways out that genuinely exist.
 *
 * 5. ONE IMPLEMENTATION. Every surface renders Setup\Pairs::decide(), so the same condition
 *    produces the same words in the panel, the browser installer and both shell paths.
 *
 * No test here touches the network: every control plane is a scripted closure, and the API keys
 * are sentinels so a leak into a page or a message fails a test rather than escaping unnoticed.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';
require_once __DIR__ . '/support/opensolr_plane.php';

use Loghound\Config;
use Loghound\Panel\Gateway;
use Loghound\Panel\Settings;
use Loghound\Setup\Pairs;
use Loghound\Setup\Storage;

/** The account this installation starts on. */
const LH_CH_EMAIL_A = 'first@example.com';
const LH_CH_KEY_A   = 'SENTINEL-CHOICE-KEY-AAAA';

/** The account it is moved to, which holds a different pair. */
const LH_CH_EMAIL_B = 'second@example.com';
const LH_CH_KEY_B   = 'SENTINEL-CHOICE-KEY-BBBB';

/**
 * An installation pointed at one pair, with a panel password so Settings can be posted to.
 *
 * @return array{0:string,1:Config}
 */
function lh_ch_scaffold(string $installId = 'aaaa1111'): array
{
    $root = lh_tmpdir('lh-choice');
    @mkdir($root . '/config', 0750, true);
    @mkdir($root . '/var/setup', 0750, true);

    $cfg = Config::load($root . '/config/loghound.php');
    $cfg->set('solr.mode', 'opensolr');
    $cfg->set('solr.install_id', $installId);
    $cfg->set('solr.hits_core', 'loghound_' . $installId . '_hits');
    $cfg->set('solr.sessions_core', 'loghound_' . $installId . '_sessions');
    $cfg->set('solr.base_url', 'https://fi.solrcluster.com/solr');
    $cfg->set('base_url', 'https://shop.example.com');
    $cfg->set('opensolr.email', LH_CH_EMAIL_A);
    $cfg->set('opensolr.api_key', LH_CH_KEY_A);
    $cfg->set('opensolr.region', 'FINLAND9');
    $cfg->set('auth.user', 'admin');
    $cfg->set('auth.mode', 'basic');
    $cfg->set('auth.password_hash', password_hash('a-long-enough-password', PASSWORD_DEFAULT));
    $cfg->set('beacon.secret', str_repeat('b', 64));
    $cfg->set('privacy.ip_salt', str_repeat('s', 32));
    $cfg->save();

    return [$root, $cfg];
}

/**
 * The scripted control plane, with this suite's keys.
 *
 * It is tests/support/opensolr_plane.php, unaltered — the same fixtures the browser installer
 * is driven against in a subprocess, which is what makes the equivalence assertion mean
 * anything.
 *
 * @param array<int,string> $calls Kept for callers that assert on what was asked.
 * @param array<int,string> $held
 */
function lh_ch_transport(
    array &$calls,
    array &$held,
    string $goodKey = LH_CH_KEY_B,
    ?int $limit = null
): callable {
    $plane = lh_opensolr_plane($held, $goodKey, $limit);

    return static function (array $req) use (&$calls, $plane): array {
        $calls[] = (string) $req['url'];
        return $plane($req);
    };
}

/** Both halves of a pair, as the platform would list them. */
function lh_ch_pair(string $installId): array
{
    return ['loghound_' . $installId . '_hits', 'loghound_' . $installId . '_sessions'];
}

/**
 * Post to the Settings page and hand back the redirect target.
 *
 * @param array<string,string> $fields
 */
function lh_ch_post(Config $cfg, string $action, array $fields): string
{
    $_POST = ['action' => $action, 'csrf' => lh_csrf()] + $fields;
    $_SERVER['REQUEST_METHOD'] = 'POST';

    $target = (new Settings($cfg, new Gateway($cfg, null, false)))->post();

    $_POST = [];
    return $target;
}

/** Render the whole Settings page, as a fresh sign-in would see it, from the config on disk. */
function lh_ch_render(string $root): string
{
    $cfg = Config::load($root . '/config/loghound.php');
    ob_start();
    (new Settings($cfg, new Gateway($cfg, null, false)))->body();
    return (string) ob_get_clean();
}

/** The configuration as it is ON DISK, which is the only thing that counts. */
function lh_ch_stored(string $root): array
{
    return Config::load($root . '/config/loghound.php')->all();
}

/** A Storage::account() snapshot taken against a scripted control plane. */
function lh_ch_account(Config $cfg, array $held, ?int $limit = null): array
{
    $calls = [];
    Storage::useTestTransport(lh_ch_transport($calls, $held, (string) $cfg->get('opensolr.api_key'), $limit));
    try {
        return Storage::account($cfg);
    } finally {
        Storage::useTestTransport(null);
    }
}

return [

    // -------------------------------------------------------------------------
    // Step one saves the account, and says nothing about indexes
    // -------------------------------------------------------------------------

    'saving the account asks nothing about indexes, and there is no box to tick'
        => static function (): void {
            [$root] = lh_ch_scaffold();

            $html = lh_ch_render($root);

            lh_false(
                str_contains($html, 'accept_reindex'),
                'the checkbox that qualified a different decision is gone from the markup'
            );
            lh_false(
                str_contains($html, 'I will choose new indexes'),
                'and so is its label'
            );
            lh_false(
                str_contains($html, 'Without this, changing to an account'),
                'and the copy that led with the guard instead of the situation'
            );

            lh_contains($html, 'Which Opensolr account this installation uses', 'step one is named');
            lh_contains($html, Pairs::choiceHeading(), 'step two is named, separately');

            lh_true(
                strpos($html, 'Which Opensolr account this installation uses')
                    < strpos($html, Pairs::choiceHeading()),
                'and step two comes after step one, because it is the second question'
            );

            lh_rmtree($root);
        },

    'an account that does not hold the configured pair is saved anyway, and said so'
        => static function (): void {
            [$root, $cfg] = lh_ch_scaffold();

            $held  = lh_ch_pair('bbbb2222');
            $calls = [];

            Storage::useTestTransport(lh_ch_transport($calls, $held));
            try {
                $target = lh_ch_post($cfg, 'opensolr_credentials', [
                    'opensolr_email'   => LH_CH_EMAIL_B,
                    'opensolr_api_key' => LH_CH_KEY_B,
                    'opensolr_region'  => 'FINLAND9',
                ]);
            } finally {
                Storage::useTestTransport(null);
            }

            lh_contains(
                $target,
                'ok=opensolr_saved',
                'naming an account is not refused because of what it does or does not hold'
            );

            $stored = lh_ch_stored($root);
            lh_same(LH_CH_KEY_B, $stored['opensolr']['api_key'], 'the new key is stored');
            lh_same(LH_CH_EMAIL_B, $stored['opensolr']['email']);
            lh_true(
                (bool) $stored['opensolr']['pair_pending'],
                'and the configuration records that indexes are still outstanding'
            );

            lh_rmtree($root);
        },

    'the interim state survives a reload and a fresh sign-in, and says what it is'
        => static function (): void {
            [$root, $cfg] = lh_ch_scaffold();

            $held  = lh_ch_pair('bbbb2222');
            $calls = [];

            Storage::useTestTransport(lh_ch_transport($calls, $held));
            try {
                lh_ch_post($cfg, 'opensolr_credentials', [
                    'opensolr_email'   => LH_CH_EMAIL_B,
                    'opensolr_api_key' => LH_CH_KEY_B,
                    'opensolr_region'  => 'FINLAND9',
                ]);

                $html = lh_ch_render($root);
            } finally {
                Storage::useTestTransport(null);
            }

            lh_contains(
                $html,
                'indexes have not been chosen yet',
                'the panel says what actually happened'
            );
            lh_false(
                str_contains($html, 'A service this panel depends on is not answering'),
                'and never the sentence that sends the operator to check a network that is fine'
            );
            lh_contains(
                $html,
                Pairs::choiceHeading(),
                'and the route out of it is on the same card'
            );
            lh_contains(
                $html,
                'chip chip-warn',
                'carrying the marker that stops the accordion folding it away'
            );

            lh_false(str_contains($html, LH_CH_KEY_B), 'no key reaches the page');

            lh_rmtree($root);
        },

    // -------------------------------------------------------------------------
    // Step two: the list, and the one more option
    // -------------------------------------------------------------------------

    'one pair is still a choice, offered beside the option that makes a new one'
        => static function (): void {
            [$root, $cfg] = lh_ch_scaffold();
            $held = lh_ch_pair('bbbb2222');

            $step = Pairs::decide($cfg, lh_ch_account($cfg, $held));

            lh_same(1, count($step['pairs']), 'the one pair the account holds is on the list');
            lh_true($step['can_new'], 'and so is the option that makes a new pair');
            lh_contains(
                $step['intro'],
                'one pair',
                'a single pair is presented as something to pick, never adopted on the operator\'s behalf'
            );
            lh_contains($step['new_label'], 'new pair', 'the extra option says what it does');

            lh_rmtree($root);
        },

    'an account with no Loghound indexes says why the list is empty' => static function (): void {
        [$root, $cfg] = lh_ch_scaffold();
        $held = [];

        $step = Pairs::decide($cfg, lh_ch_account($cfg, $held));

        lh_same([], $step['pairs'], 'there is nothing to list');
        lh_true($step['can_new'], 'so the only route out is offered');
        lh_contains(
            $step['intro'],
            'nothing on the list to pick from',
            'and the reason is stated rather than left as an empty box'
        );
        lh_contains($step['intro'], 'holds no Loghound indexes yet', 'naming the actual reason');

        lh_rmtree($root);
    },

    'an unmatched half is named as the leftover it is, and is not selectable'
        => static function (): void {
            [$root, $cfg] = lh_ch_scaffold();
            $held = array_merge(lh_ch_pair('bbbb2222'), ['loghound_cccc3333_hits']);

            $step = Pairs::decide($cfg, lh_ch_account($cfg, $held));

            lh_same(1, count($step['pairs']), 'the half does not become a pair');
            lh_same(
                ['bbbb2222'],
                array_column($step['pairs'], 'install_id'),
                'and it is not on the list of things that can be picked'
            );
            lh_same(1, count($step['halves']), 'it is reported');
            lh_contains($step['halves'][0], 'loghound_cccc3333_hits', 'by name');
            lh_contains($step['halves'][0], 'loghound_cccc3333_sessions', 'with the half it lacks');
            lh_contains($step['halves'][0], 'counts against your plan', 'and what it is costing');

            lh_rmtree($root);
        },

    'no pair and no room is a dead end that names the numbers and the ways out'
        => static function (): void {
            [$root, $cfg] = lh_ch_scaffold();
            $held = ['someone_elses_index', 'another_one'];

            $step = Pairs::decide($cfg, lh_ch_account($cfg, $held, 2));

            lh_same([], $step['pairs'], 'nothing to join');
            lh_false($step['can_new'], 'and no room to create');
            lh_contains($step['dead_end'], 'no pair of Loghound indexes', 'it says there is nothing to pick');
            lh_contains($step['dead_end'], 'allows 2 indexes', 'with the plan\'s own number');
            lh_contains($step['dead_end'], 'needs 2', 'and what Loghound is asking for');

            lh_same(
                ['free', 'upgrade'],
                array_column($step['ways'], 'key'),
                'the routes out are the ones that genuinely exist — reuse is not offered when '
                . 'there is nothing to reuse'
            );
            lh_contains(
                $step['ways_heading'],
                'Two ways',
                'and the list is introduced by how many it actually holds'
            );

            lh_rmtree($root);
        },

    'a full plan with a pair on it keeps the list and withholds only the new pair'
        => static function (): void {
            [$root, $cfg] = lh_ch_scaffold();
            $held = lh_ch_pair('bbbb2222');

            $step = Pairs::decide($cfg, lh_ch_account($cfg, $held, 2));

            lh_same(1, count($step['pairs']), 'the pair is still pickable — joining creates nothing');
            lh_false($step['can_new'], 'the option that cannot succeed is not offered');
            lh_same('', $step['dead_end'], 'and this is not a dead end, because there is a way through');
            lh_contains($step['new_blocked'], 'no room for one', 'the absence is explained');
            lh_contains($step['new_blocked'], 'allows 2 indexes', 'with the numbers');

            lh_rmtree($root);
        },

    // -------------------------------------------------------------------------
    // Step two, acted on
    // -------------------------------------------------------------------------

    'picking a pair points this installation at it and clears the outstanding state'
        => static function (): void {
            [$root, $cfg] = lh_ch_scaffold();

            $held  = lh_ch_pair('bbbb2222');
            $calls = [];

            Storage::useTestTransport(lh_ch_transport($calls, $held));
            try {
                lh_ch_post($cfg, 'opensolr_credentials', [
                    'opensolr_email'   => LH_CH_EMAIL_B,
                    'opensolr_api_key' => LH_CH_KEY_B,
                    'opensolr_region'  => 'FINLAND9',
                ]);
                lh_true((bool) lh_ch_stored($root)['opensolr']['pair_pending'], 'outstanding first');

                $target = lh_ch_post($cfg, 'opensolr_indexes', ['install_id' => 'bbbb2222']);
            } finally {
                Storage::useTestTransport(null);
            }

            lh_contains($target, 'ok=pair_switched', 'the choice lands');

            $stored = lh_ch_stored($root);
            lh_same('loghound_bbbb2222_hits', $stored['solr']['hits_core'], 'the pair is adopted');
            lh_same('loghound_bbbb2222_sessions', $stored['solr']['sessions_core']);
            lh_false((bool) $stored['opensolr']['pair_pending'], 'and nothing is outstanding any more');

            lh_false(
                in_array('bbbb2222', [$stored['solr']['install_id']], true),
                'adopting takes the pair\'s core names and never the pair\'s installation id — the '
                . 'id is the salt in every document id, so sharing it would let two machines '
                . 'overwrite each other'
            );

            lh_same([], Config::load($root . '/config/loghound.php')->validate(), 'and the result is valid');

            lh_rmtree($root);
        },

    'choosing a new pair creates one, from the panel, without anybody running a shell'
        => static function (): void {
            [$root, $cfg] = lh_ch_scaffold();

            $held  = [];
            $calls = [];

            Storage::useTestTransport(lh_ch_transport($calls, $held, LH_CH_KEY_A));
            try {
                $target = lh_ch_post($cfg, 'opensolr_indexes', ['install_id' => Pairs::CHOICE_NEW]);
            } finally {
                Storage::useTestTransport(null);
            }

            lh_contains($target, 'ok=pair_created', 'the panel can provision, so nobody is sent to a shell');

            $stored = lh_ch_stored($root);
            lh_true(
                (bool) preg_match('/^loghound_[a-f0-9]+_hits$/', (string) $stored['solr']['hits_core']),
                'a fresh pair was made'
            );
            lh_same(2, count($held), 'two indexes, and only two');
            lh_false((bool) $stored['opensolr']['pair_pending'], 'nothing outstanding');

            lh_rmtree($root);
        },

    'provisioning from the panel is refused before a job exists when the plan is full'
        => static function (): void {
            [$root, $cfg] = lh_ch_scaffold();

            $held  = ['someone_elses_index', 'another_one'];
            $calls = [];

            Storage::useTestTransport(lh_ch_transport($calls, $held, LH_CH_KEY_A, 2));
            try {
                $target = lh_ch_post($cfg, 'opensolr_indexes', ['install_id' => Pairs::CHOICE_NEW]);
            } finally {
                Storage::useTestTransport(null);
            }

            lh_contains($target, 'err=pair_failed', 'the refusal is a refusal');
            lh_same(
                [],
                array_values(array_filter($calls, static fn (string $u): bool => str_contains($u, '/create_index'))),
                'and nothing was created — the capacity check comes first'
            );
            lh_same(2, count($held), 'the account is untouched');

            $html = lh_ch_render($root);
            lh_contains($html, 'allows 2 indexes', 'the numbers are on the card');
            lh_contains($html, 'Delete an index you no longer need', 'with a way forward that exists');

            lh_rmtree($root);
        },

    'a choice that names nothing changes nothing' => static function (): void {
        [$root, $cfg] = lh_ch_scaffold();

        $target = lh_ch_post($cfg, 'opensolr_indexes', ['install_id' => '../../etc']);
        lh_contains($target, 'err=pair_unknown', 'an id that is not an id is refused before anything reads it');

        $stored = lh_ch_stored($root);
        lh_same('loghound_aaaa1111_hits', $stored['solr']['hits_core'], 'and the pair in use did not move');

        lh_rmtree($root);
    },

    // -------------------------------------------------------------------------
    // One implementation, four surfaces
    // -------------------------------------------------------------------------

    /**
     * The words are not re-spelled per surface.
     *
     * The repository has been bitten twice by two places building one thing: the beacon snippet
     * drifted to `?v=1` in one copy and a real version in the other, and the installer rework
     * exists because the shell wizard and the browser installer had drifted on prerequisites and
     * error wording. So every surface has to be reading the decision, not describing it.
     */
    'every surface renders the same decision rather than describing it again' => static function (): void {
        $surfaces = [
            'src/Panel/Settings.php'  => 'the Settings card',
            'src/Setup/View.php'      => 'the browser installer',
            'bin/loghound-setup'      => 'the shell wizard',
        ];

        foreach ($surfaces as $file => $what) {
            $code = (string) file_get_contents(dirname(__DIR__) . '/' . $file);

            lh_contains($code, 'Pairs::decide(', $what . ' renders the shared decision');
            lh_contains($code, 'Pairs::CHOICE_NEW', $what . ' uses the shared option value');

            lh_false(
                str_contains($code, 'This account holds no Loghound indexes yet'),
                $what . ' must not carry its own copy of the empty-list sentence'
            );
            lh_false(
                str_contains($code, 'what a setup run that stopped half way leaves behind'),
                $what . ' must not carry its own copy of the unmatched-half sentence'
            );
            lh_false(
                str_contains($code, 'ways on from here'),
                $what . ' must not count the ways forward itself'
            );
        }

        $installer = (string) file_get_contents(dirname(__DIR__) . '/src/Setup/Installer.php');
        lh_contains($installer, 'Pairs::settleOwnership(', 'and the interim state is recorded in one place');
        lh_contains(
            (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Settings.php'),
            'Pairs::settleOwnership(',
            'from the same call, on the surface most likely to drift'
        );
    },

    'the ways forward are counted, not asserted' => static function (): void {
        lh_contains(Pairs::waysHeading(Pairs::waysForward(true)), 'Three ways', 'three when there are three');
        lh_contains(Pairs::waysHeading(Pairs::waysForward(false)), 'Two ways', 'and two when there are two');
    },

    /**
     * A verdict on evidence, never on silence.
     *
     * "The control plane did not answer" and "that account does not hold your indexes" lead an
     * operator to do opposite things, so a failed read must not be allowed to write down the
     * second one — nor to clear it, which would hide a state that is still true.
     */
    'an account that could not be read changes no verdict' => static function (): void {
        [$root, $cfg] = lh_ch_scaffold();

        $cfg->set(Pairs::PENDING_KEY, true);
        lh_same(
            'unknown',
            Pairs::settleOwnership($cfg, ['ok' => false, 'error' => 'timed out', 'pairs' => []]),
            'a failed read answers nothing'
        );
        lh_true(Pairs::isPending($cfg), 'and leaves what was already recorded exactly as it was');

        $cfg->set('solr.hits_core', '');
        lh_same('unset', Pairs::settleOwnership($cfg, ['ok' => true, 'pairs' => []]), 'a fresh install is not a fault');
        lh_false(Pairs::isPending($cfg), 'and has nothing outstanding');

        lh_rmtree($root);
    },
];
