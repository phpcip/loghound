<?php
/**
 * Loghound — reusing indexes that already exist, and never creating ones there is no room for.
 *
 * WHAT THESE PIN, and why each one is worth a test.
 *
 * 1. A PLAN LIMIT IS CHECKED BEFORE THE FIRST CREATE, NOT AFTER THE SECOND. Provisioning makes
 *    two indexes. Learning halfway that the plan allows one leaves an index in the operator's
 *    account with nothing pointing at it and a bill attached. So capacity is read first and,
 *    when the allowance is known, refuses with no side effect at all.
 *
 * 2. THE HALF-WAY FAILURE IS HANDLED ANYWAY. A check is not a guarantee: another machine can
 *    take the last slot between the check and the create. When the SECOND create is refused,
 *    the first index must be deleted — and that used to happen on exactly one refusal, the
 *    name collision, while every other refusal threw straight past the rollback.
 *
 * 3. THE LIMIT IS LEARNED AND REMEMBERED. No Opensolr endpoint publishes an account's index
 *    allowance; the number appears only in the refusal a create gets when the plan is full. It
 *    is parsed out of that one message and written to the configuration, so the next attempt
 *    refuses up front instead of paying for the discovery twice.
 *
 * 4. REUSE JOINS, IT DOES NOT OVERWRITE. Adopting a pair must not create an index, must not
 *    clear one, and must not push a configset over a schema that is already correct — because
 *    the pair may hold another site's data. A schema that is genuinely older stops the run
 *    unless the operator agreed to the upgrade.
 *
 * 5. PAIRS ARE PAIRS. An unmatched half is a real state a failed install leaves behind. It is
 *    reported as one and is never offered as something adoptable.
 *
 * No test here touches the network: every control plane is a scripted closure, and the API key
 * in each configuration is a sentinel so a leak into a message fails a test rather than
 * escaping unnoticed.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Config;
use Loghound\Opensolr;
use Loghound\Setup\Job;
use Loghound\Setup\Pairs;
use Loghound\Setup\Storage;

/** The sentinel that must never appear in anything shown to an operator. */
const LH_REUSE_KEY = 'SENTINEL-APIKEY-REUSE-1';

/**
 * A throwaway installation with credentials, configsets, and no indexes yet.
 *
 * @return array{0:string,1:Config}
 */
function lh_reuse_scaffold(): array
{
    $root = lh_tmpdir('lh-reuse');
    @mkdir($root . '/config', 0750, true);
    @mkdir($root . '/var/setup', 0750, true);

    foreach (['hits', 'sessions'] as $role) {
        @mkdir($root . '/solr/' . $role . '/conf', 0750, true);
        file_put_contents(
            $root . '/solr/' . $role . '/conf/schema.xml',
            '<schema name="loghound-' . $role . '" version="1.6">'
            . '<field name="id" type="string"/>'
            . '<field name="ts_dt" type="pdate"/>'
            . '<field name="host_s" type="string"/>'
            . '<dynamicField name="*_s" type="string"/>'
            . '</schema>'
        );
        file_put_contents($root . '/solr/' . $role . '/conf/mapping-ISOLatin1Accent.txt', '"a" => "a"' . "\n");
        file_put_contents(
            $root . '/solr/' . $role . '/conf/solrconfig.xml',
            '<config><schemaFactory class="ClassicIndexSchemaFactory"/></config>'
        );
    }

    $cfg = Config::load($root . '/config/loghound.php');
    $cfg->set('solr.mode', 'opensolr');
    $cfg->set('opensolr.email', 'someone@example.com');
    $cfg->set('opensolr.api_key', LH_REUSE_KEY);
    $cfg->set('base_url', 'https://shop.example.com');
    $cfg->save();

    return [$root, $cfg];
}

/**
 * A scripted control plane with a plan limit and a memory of what it holds.
 *
 * The create gate is the real platform's: the limit is checked BEFORE the name. So is
 * get_account_summary, which is where the allowance is published — scoped to one core, signed,
 * and refusing a core the account does not hold, exactly as the live endpoint does.
 *
 * @param array<int,string>       $calls   Filled with every request URL, in order.
 * @param array<int,string>       $held    Index names the account holds.
 * @param int|null                $limit   Plan allowance; null means unlimited.
 * @param array<string,string>    $schemas Index name => the schema.xml it runs.
 */
function lh_reuse_transport(
    array &$calls,
    array &$held,
    ?int $limit = null,
    array $schemas = [],
    ?callable $override = null
): callable {
    return static function (array $req) use (&$calls, &$held, $limit, $schemas, $override): array {
        $url = (string) $req['url'];
        $calls[] = $url;

        $forced = $override === null ? null : $override($url, count($calls));
        if (is_array($forced)) {
            return ['status' => 200, 'body' => (string) json_encode($forced), 'error' => ''];
        }

        $name = static function (string $u, string $param): string {
            return preg_match('/[?&]' . $param . '=([A-Za-z0-9_.\-%@]+)/', $u, $m) === 1
                ? urldecode($m[1])
                : '';
        };

        $body = ['status' => true, 'msg' => 'OK'];

        if (str_contains($url, '/regions')) {
            $body = ['FINLAND9', 'GERMANY9'];
        } elseif (str_contains($url, '/get_index_list')) {
            $body = array_map(
                static fn (string $n): array => ['index_name' => $n, 'index_type' => '-1'],
                array_values($held)
            );
        } elseif (str_contains($url, '/create_index')) {
            $wanted = $name($url, 'index_name');
            if ($limit !== null && count($held) >= $limit) {
                $body = ['status' => false, 'msg' => 'ERROR_CANNOT_ADD_MORE_THAN_' . $limit . '_CORES'];
            } elseif (in_array($wanted, $held, true)) {
                $body = ['status' => false, 'msg' => 'ERROR_CORE_NAME_TAKEN_CHOOSE_ANOTHER_CORE_NAME'];
            } else {
                $held[] = $wanted;
            }
        } elseif (str_contains($url, '/delete_index')) {
            $gone = $name($url, 'index_name');
            $held = array_values(array_filter($held, static fn (string $n): bool => $n !== $gone));
        } elseif (str_contains($url, '/get_account_summary')) {
            $core = $name($url, 'core_name');
            $sig  = $name($url, 'signature');
            $want = hash_hmac('sha256', $core . 'someone@example.com', LH_REUSE_KEY);
            if (!in_array($core, $held, true)) {
                $body = ['status' => false, 'msg' => 'ERROR_NOT_CORE_OWNER'];
            } elseif (!hash_equals($want, $sig)) {
                $body = ['status' => false, 'msg' => 'ERROR_INVALID_SIGNATURE'];
            } elseif ($limit === null) {
                $body = ['status' => true, 'msg' => ['plan' => 'Free']];
            } else {
                $body = ['status' => true, 'msg' => [
                    'plan'              => 'Free',
                    'index_limit'       => $limit,
                    'indexes_used'      => count($held),
                    'indexes_available' => max(0, $limit - count($held)),
                ]];
            }
        } elseif (str_contains($url, '/get_file')) {
            $core = $name($url, 'index_name');
            $body = isset($schemas[$core])
                ? ['status' => true, 'msg' => $schemas[$core]]
                : ['status' => false, 'msg' => 'ERROR_INVALID_CORE_NAME'];
        } elseif (str_contains($url, '/get_core_info')) {
            $core = $name($url, 'core_name');
            $body = ['status' => true, 'msg' => ['info' => [
                'connection_url' => 'https://fi.solrcluster.com/solr/' . $core,
                'auth_username'  => 'solr-user',
                'auth_password'  => 'solr-pass',
            ]]];
        } elseif (str_contains($url, '/select')) {
            $body = ['responseHeader' => ['status' => 0], 'response' => ['numFound' => 3, 'docs' => []]];
        }

        return ['status' => 200, 'body' => (string) json_encode($body), 'error' => ''];
    };
}

/** Every URL of a run that hit one endpoint. */
function lh_reuse_hits(array $calls, string $endpoint): array
{
    return array_values(array_filter($calls, static fn (string $u): bool => str_contains($u, $endpoint)));
}

/** The schema a pair created by an older Loghound would be running. */
function lh_reuse_old_schema(string $role): string
{
    return '<schema name="loghound-' . $role . '" version="1.6">'
        . '<field name="id" type="string"/>'
        . '<dynamicField name="*_s" type="string"/>'
        . '</schema>';
}

/** The schema this checkout writes, for an index that is already up to date. */
function lh_reuse_current_schema(string $root, string $role): string
{
    return (string) file_get_contents($root . '/solr/' . $role . '/conf/schema.xml');
}

return [


    'a Loghound index name is recognised, and a near-miss is not' => static function (): void {
        lh_same(
            ['install_id' => '9f3c17ab', 'role' => 'hits'],
            Pairs::parse('loghound_9f3c17ab_hits'),
            'the shape Config::coreName builds'
        );
        lh_same(
            ['install_id' => 'deadbeef', 'role' => 'sessions'],
            Pairs::parse('loghound_deadbeef_sessions')
        );

        foreach ([
            'loghound_9f3c17ab_visits',
            'loghound__hits',
            'loghound_9F3C17AB_hits',
            'xloghound_9f3c17ab_hits',
            'loghound_9f3c17ab_hits_2',
            'my_loghound_9f3c17ab_hits',
            'loghound_9f3c17ab',
        ] as $name) {
            lh_same(
                null,
                Pairs::parse($name),
                $name . ' is not a Loghound index and must not be offered as one'
            );
        }
    },

    'pairs are grouped as pairs, and an unmatched half is named as a leftover' => static function (): void {
        $grouped = Pairs::group([
            ['name' => 'loghound_bbbb2222_sessions', 'type' => '-1'],
            ['name' => 'my_other_index',             'type' => '-1'],
            ['name' => 'loghound_aaaa1111_hits',     'type' => '-1'],
            ['name' => 'loghound_bbbb2222_hits',     'type' => '-1'],
            ['name' => 'loghound_cccc3333_hits',     'type' => '-1'],
        ]);

        lh_same(1, count($grouped['pairs']), 'exactly one complete pair');
        lh_same('bbbb2222', $grouped['pairs'][0]['install_id']);
        lh_same('loghound_bbbb2222_hits', $grouped['pairs'][0]['hits']);
        lh_same('loghound_bbbb2222_sessions', $grouped['pairs'][0]['sessions']);

        lh_same(2, count($grouped['halves']), 'both lone halves are reported');
        $byName = [];
        foreach ($grouped['halves'] as $half) {
            $byName[$half['name']] = $half['missing'];
        }
        lh_same(
            'loghound_aaaa1111_sessions',
            $byName['loghound_aaaa1111_hits'] ?? '',
            'a lone hits index names the sessions index it is missing'
        );
        lh_same('loghound_cccc3333_sessions', $byName['loghound_cccc3333_hits'] ?? '');

        lh_same(5, $grouped['total'], 'the account total counts everything, Loghound or not');
        lh_same(5, $grouped['counted'], 'and so does the figure the plan limit applies to');
    },

    'a cluster core does not count against the index limit' => static function (): void {
        lh_same(
            2,
            Opensolr::countAgainstLimit([
                ['name' => 'standalone_one', 'type' => '-1'],
                ['name' => 'cluster_core',   'type' => '0'],
                ['name' => 'no_type_given',  'type' => ''],
            ]),
            'the platform counts standalone indexes only; an untyped row is counted to be safe'
        );
    },


    'the allowance is read from the account, signed, and never invented' => static function (): void {
        [$root, $cfg] = lh_reuse_scaffold();

        $held  = ['other_a', 'other_b'];
        $calls = [];

        Storage::useTestTransport(lh_reuse_transport($calls, $held, 5));
        try {
            $account = Storage::account($cfg);

            lh_same(5, $account['capacity']['limit'], 'index_limit comes from the platform');
            lh_same(2, $account['capacity']['counted'], 'and so does indexes_used');
            lh_same(3, $account['capacity']['room'], 'and indexes_available is used as given, not recomputed');
            lh_false($account['capacity']['blocked'], 'three free slots are room for two');

            $asked = lh_reuse_hits($calls, '/get_account_summary');
            lh_same(1, count($asked), 'one summary call answers the allowance');
            lh_true(
                str_contains($asked[0], 'signature='),
                'the endpoint is signed, and a request without a signature is refused outright'
            );
        } finally {
            Storage::useTestTransport(null);
            lh_rmtree($root);
        }
    },

    'an allowance that cannot be read is unknown, and unknown never blocks' => static function (): void {
        [$root, $cfg] = lh_reuse_scaffold();

        $empty = [];
        $calls = [];
        Storage::useTestTransport(lh_reuse_transport($calls, $empty, 5));
        try {
            $account = Storage::account($cfg);
            lh_same(
                null,
                $account['capacity']['limit'],
                'an account holding nothing has no core to name on the endpoint that reports the '
                . 'allowance, so there is no allowance to report'
            );
            lh_false($account['capacity']['blocked'], 'and an unknown allowance must never block');
            lh_same([], lh_reuse_hits($calls, '/get_account_summary'), 'nothing is even asked');
            lh_contains($account['capacity']['sentence'], 'could not be read');
        } finally {
            Storage::useTestTransport(null);
        }

        // An older platform answers the summary without the three fields at all.
        $held  = ['other_a'];
        $calls = [];
        Storage::useTestTransport(lh_reuse_transport($calls, $held, null));
        try {
            $account = Storage::account($cfg);
            lh_same(
                null,
                $account['capacity']['limit'],
                'a platform that predates the fields reports no allowance, and a zero there would '
                . 'read as "your plan allows none" and refuse an operator whose plan is fine'
            );
            lh_false($account['capacity']['blocked']);
            lh_same(1, count(lh_reuse_hits($calls, '/get_account_summary')), 'it was asked, and answered without them');
        } finally {
            Storage::useTestTransport(null);
            lh_rmtree($root);
        }
    },

    'a refusal is recognised without being mined for the number' => static function (): void {
        lh_true(
            Opensolr::isAtIndexLimit(['status' => false, 'msg' => 'ERROR_CANNOT_ADD_MORE_THAN_5_CORES']),
            'the refusal is still recognised, because it is the authority at the moment of creation'
        );
        lh_false(
            Opensolr::isAtIndexLimit(['status' => false, 'msg' => 'ERROR_CORE_NAME_TAKEN_CHOOSE_ANOTHER_CORE_NAME']),
            'a name collision is not a full plan'
        );
        lh_false(
            Opensolr::isAtIndexLimit(['status' => true, 'msg' => 'ERROR_CANNOT_ADD_MORE_THAN_5_CORES']),
            'a truthy status is never a refusal, whatever the message says'
        );

        lh_false(
            method_exists(Opensolr::class, 'indexLimitFromResponse'),
            'the allowance must not be parsed out of an error message any more: the platform '
            . 'publishes it, and a number scraped from a refusal was only ever a workaround'
        );
        lh_false(
            method_exists(\Loghound\Setup\Pairs::class, 'knownLimit'),
            'nor remembered — a stored allowance goes stale the moment a plan changes, silently'
        );
        lh_no_key(Config::defaults()['opensolr'], 'index_limit');
    },

    'the capacity sentence states every number it has, and only blocks on one it knows'
        => static function (): void {
            $full = Pairs::capacity(5, 5, 5, 0);
            lh_true($full['blocked'], 'no slots left is no room for two');
            lh_same(0, $full['room']);
            lh_contains($full['sentence'], '5', 'the allowance is named');
            lh_contains($full['sentence'], 'Loghound needs 2', 'and so is what Loghound wants');

            $tight = Pairs::capacity(4, 5, 4, 1);
            lh_true($tight['blocked'], 'one free slot is not two');

            $fine = Pairs::capacity(1, 5, 1, 4);
            lh_false($fine['blocked'], 'four free slots are enough');
            lh_contains($fine['sentence'], 'room for the 2');

            $derived = Pairs::capacity(1, 5);
            lh_same(4, $derived['room'], 'with no availability given, it is derived from the allowance');

            $unknown = Pairs::capacity(4);
            lh_false(
                $unknown['blocked'],
                'an allowance that could not be read must never block: refusing on a number nobody '
                . 'has is how an installer strands somebody whose plan was fine'
            );
            lh_same(null, $unknown['room']);
            lh_contains(
                $unknown['sentence'],
                'could not be read',
                'and the screen says so rather than implying it checked'
            );
        },

    'a full plan stops provisioning before a single index is created' => static function (): void {
        [$root, $cfg] = lh_reuse_scaffold();

        $held  = ['someone_elses_index', 'another_index'];
        $calls = [];

        Storage::useTestTransport(lh_reuse_transport($calls, $held, 2));
        try {
            $job = Job::create($root . '/var/setup', Job::KIND_OPENSOLR, ['region' => 'FINLAND9']);
            lh_false($job->runAll($cfg, $root), 'a full plan must stop the job');

            lh_same([], lh_reuse_hits($calls, '/create_index'), 'and stop it BEFORE any create call');
            lh_same(2, count($held), 'the account is left exactly as it was');

            lh_contains($job->error(), '2', 'the operator is told the allowance');
            lh_contains($job->error(), 'Loghound needs 2', 'and what was being asked for');
            lh_false(str_contains($job->error(), LH_REUSE_KEY), 'the API key never appears');
        } finally {
            Storage::useTestTransport(null);
            lh_rmtree($root);
        }
    },

    'a full plan is read as full on every run, never remembered from the last one'
        => static function (): void {
            [$root, $cfg] = lh_reuse_scaffold();
            $held  = ['a', 'b'];
            $calls = [];

            Storage::useTestTransport(lh_reuse_transport($calls, $held, 2));
            try {
                $first = Job::create($root . '/var/setup', Job::KIND_OPENSOLR, ['region' => 'FINLAND9']);
                lh_false($first->runAll($cfg, $root), 'full, so it refuses');

                $calls = [];
                $second = Job::create($root . '/var/setup', Job::KIND_OPENSOLR, ['region' => 'FINLAND9']);
                lh_false($second->runAll($cfg, $root), 'still full, so it refuses again');
                lh_true(
                    count(lh_reuse_hits($calls, '/get_account_summary')) > 0,
                    'and it ASKED again rather than trusting a number it kept: a plan can change '
                    . 'between two runs, and a remembered allowance would not notice'
                );
            } finally {
                Storage::useTestTransport(null);
                lh_rmtree($root);
            }

            $stored = (string) @file_get_contents($root . '/config/loghound.php');
            lh_false(
                str_contains($stored, 'index_limit'),
                'and nothing about the allowance is written to the configuration'
            );
        },

    'a plan that fills up between the check and the second create leaves nothing behind'
        => static function (): void {
            [$root, $cfg] = lh_reuse_scaffold();

            $held  = ['other_a'];
            $calls = [];

            // The allowance says room for three more, so the check passes. Then another
            // session takes the last slot, and the SECOND create is refused — the race a
            // check structurally cannot win, and the reason the rollback has to exist.
            $creates = 0;
            $raced = static function (string $url, int $n) use (&$creates): ?array {
                if (!str_contains($url, '/create_index')) {
                    return null;
                }
                $creates++;
                return $creates === 2
                    ? ['status' => false, 'msg' => 'ERROR_CANNOT_ADD_MORE_THAN_4_CORES']
                    : null;
            };

            Storage::useTestTransport(lh_reuse_transport($calls, $held, 4, [], $raced));
            try {
                $job = Job::create($root . '/var/setup', Job::KIND_OPENSOLR, ['region' => 'FINLAND9']);
                lh_false($job->runAll($cfg, $root), 'the job must fail');

                lh_same(
                    2,
                    count(lh_reuse_hits($calls, '/create_index')),
                    'the check found room, so it got as far as trying both halves'
                );
                lh_same(
                    1,
                    count(lh_reuse_hits($calls, '/delete_index')),
                    'and it gave the one it did create back'
                );
                lh_same(
                    ['other_a'],
                    $held,
                    'so the account holds exactly what it held before — no orphan, no charge'
                );

                lh_contains(
                    $job->error(),
                    'took the last slot',
                    'and the message says this was a race rather than implying the check lied'
                );
                lh_contains($job->error(), 'Nothing has been left behind');
                lh_false(
                    str_contains($job->error(), 'CANNOT_ADD_MORE_THAN'),
                    'without pasting the platform constant at the operator'
                );
            } finally {
                Storage::useTestTransport(null);
                lh_rmtree($root);
            }
        },

    'reusing a pair writes no index, clears nothing and pushes no configset' => static function (): void {
        [$root, $cfg] = lh_reuse_scaffold();

        $held = ['loghound_aaaa1111_hits', 'loghound_aaaa1111_sessions'];
        $calls = [];
        $schemas = [
            'loghound_aaaa1111_hits'     => lh_reuse_current_schema($root, 'hits'),
            'loghound_aaaa1111_sessions' => lh_reuse_current_schema($root, 'sessions'),
        ];

        Storage::useTestTransport(lh_reuse_transport($calls, $held, 2, $schemas));
        try {
            $job = Job::create($root . '/var/setup', Job::KIND_REUSE, ['install_id' => 'aaaa1111']);
            lh_true($job->runAll($cfg, $root), 'reuse should succeed: ' . $job->error());

            lh_same([], lh_reuse_hits($calls, '/create_index'), 'nothing is created');
            lh_same([], lh_reuse_hits($calls, '/delete_index'), 'nothing is deleted');
            lh_same([], lh_reuse_hits($calls, '/upload_config_file'), 'and no schema is pushed over a match');
            lh_same([], lh_reuse_hits($calls, '/reset_core'), 'nothing is reset');

            lh_same('loghound_aaaa1111_hits', (string) $cfg->get('solr.hits_core'));
            lh_same('loghound_aaaa1111_sessions', (string) $cfg->get('solr.sessions_core'));
            lh_same('https://fi.solrcluster.com/solr', (string) $cfg->get('solr.base_url'));
            lh_same('solr-user', (string) $cfg->get('solr.http_user'));

            lh_same(2, count($held), 'the account still holds exactly the pair it held');
        } finally {
            Storage::useTestTransport(null);
            lh_rmtree($root);
        }
    },

    'reuse takes the pair\'s core names and never the pair\'s installation id'
        => static function (): void {
            // A hit's document id is sha1(install_id \0 src:offset). Two machines both tailing
            // /var/log/apache2/access.log produce the same src:offset, so two installations
            // sharing one pair of indexes AND one installation id would overwrite each other's
            // traffic silently, byte offset for byte offset. Reuse is what makes that reachable.
            $ids = [];

            foreach (['first', 'second'] as $which) {
                [$root, $cfg] = lh_reuse_scaffold();

                $held = ['loghound_aaaa1111_hits', 'loghound_aaaa1111_sessions'];
                $calls = [];
                $schemas = [
                    'loghound_aaaa1111_hits'     => lh_reuse_current_schema($root, 'hits'),
                    'loghound_aaaa1111_sessions' => lh_reuse_current_schema($root, 'sessions'),
                ];

                Storage::useTestTransport(lh_reuse_transport($calls, $held, 4, $schemas));
                try {
                    $job = Job::create($root . '/var/setup', Job::KIND_REUSE, ['install_id' => 'aaaa1111']);
                    lh_true($job->runAll($cfg, $root), $which . ' reuse should succeed: ' . $job->error());

                    $id = (string) $cfg->get('solr.install_id');
                    lh_true($id !== '', $which . ' installation has an id');
                    lh_same(
                        'loghound_aaaa1111_hits',
                        (string) $cfg->get('solr.hits_core'),
                        $which . ' uses the pair it adopted'
                    );
                    lh_true(
                        $id !== 'aaaa1111',
                        'the installation id must NOT be the pair\'s id: it is the salt that keeps '
                        . 'two machines tailing the same filename from writing the same document ids'
                    );
                    $ids[$which] = $id;
                } finally {
                    Storage::useTestTransport(null);
                    lh_rmtree($root);
                }
            }

            lh_true(
                $ids['first'] !== $ids['second'],
                'and two installations adopting the SAME pair must still differ, or one silently '
                . 'overwrites the other'
            );
        },

    'reuse never blanks a region a previous provisioning run chose' => static function (): void {
        [$root, $cfg] = lh_reuse_scaffold();
        $cfg->set('opensolr.region', 'GERMANY9');
        $cfg->save();

        $held = ['loghound_aaaa1111_hits', 'loghound_aaaa1111_sessions'];
        $calls = [];
        $schemas = [
            'loghound_aaaa1111_hits'     => lh_reuse_current_schema($root, 'hits'),
            'loghound_aaaa1111_sessions' => lh_reuse_current_schema($root, 'sessions'),
        ];

        Storage::useTestTransport(lh_reuse_transport($calls, $held, 2, $schemas));
        try {
            $job = Job::create($root . '/var/setup', Job::KIND_REUSE, ['install_id' => 'aaaa1111']);
            lh_true($job->runAll($cfg, $root), 'reuse should succeed: ' . $job->error());
            lh_same(
                'GERMANY9',
                (string) $cfg->get('opensolr.region'),
                'adopting indexes asks no region question, so it must not erase the answer to one'
            );
        } finally {
            Storage::useTestTransport(null);
            lh_rmtree($root);
        }
    },

    'an older schema stops reuse rather than being written into' => static function (): void {
        [$root, $cfg] = lh_reuse_scaffold();

        $held = ['loghound_aaaa1111_hits', 'loghound_aaaa1111_sessions'];
        $calls = [];
        $schemas = [
            'loghound_aaaa1111_hits'     => lh_reuse_old_schema('hits'),
            'loghound_aaaa1111_sessions' => lh_reuse_current_schema($root, 'sessions'),
        ];

        Storage::useTestTransport(lh_reuse_transport($calls, $held, 2, $schemas));
        try {
            $job = Job::create($root . '/var/setup', Job::KIND_REUSE, ['install_id' => 'aaaa1111']);
            lh_false($job->runAll($cfg, $root), 'a shape that does not match must stop the run');

            lh_same(
                [],
                lh_reuse_hits($calls, '/upload_config_file'),
                'and it must change nothing while it stops'
            );
            lh_contains($job->error(), 'ts_dt', 'the missing fields are named, not counted');
            lh_contains($job->error(), 'host_s');
            lh_contains($job->error(), 'older version', 'and the reason is said plainly');
        } finally {
            Storage::useTestTransport(null);
            lh_rmtree($root);
        }
    },

    'an older schema is upgraded only when the operator agreed to it' => static function (): void {
        [$root, $cfg] = lh_reuse_scaffold();

        $held = ['loghound_aaaa1111_hits', 'loghound_aaaa1111_sessions'];
        $calls = [];
        $schemas = [
            'loghound_aaaa1111_hits'     => lh_reuse_old_schema('hits'),
            'loghound_aaaa1111_sessions' => lh_reuse_current_schema($root, 'sessions'),
        ];

        Storage::useTestTransport(lh_reuse_transport($calls, $held, 2, $schemas));
        try {
            $job = Job::create($root . '/var/setup', Job::KIND_REUSE, [
                'install_id'     => 'aaaa1111',
                'upgrade_schema' => true,
            ]);
            lh_true($job->runAll($cfg, $root), 'with consent it should land: ' . $job->error());

            $uploads = lh_reuse_hits($calls, '/upload_config_file');
            lh_same(
                count(\Loghound\Opensolr::CONFIGSET_FILES),
                count($uploads),
                'the whole configset goes to the ONE index that needed it, and only that one'
            );
            lh_same([], lh_reuse_hits($calls, '/create_index'), 'still nothing created');
            lh_same([], lh_reuse_hits($calls, '/delete_index'), 'still nothing deleted');
        } finally {
            Storage::useTestTransport(null);
            lh_rmtree($root);
        }
    },

    'a schema that cannot be read is never treated as one that matches' => static function (): void {
        [$root, $cfg] = lh_reuse_scaffold();

        $held  = ['loghound_aaaa1111_hits', 'loghound_aaaa1111_sessions'];
        $calls = [];

        Storage::useTestTransport(lh_reuse_transport($calls, $held, 2, []));
        try {
            $job = Job::create($root . '/var/setup', Job::KIND_REUSE, ['install_id' => 'aaaa1111']);
            lh_false($job->runAll($cfg, $root), 'an unreadable schema must stop the run');
            lh_contains($job->error(), 'readable schema', 'and say that is what happened');
            lh_same([], lh_reuse_hits($calls, '/upload_config_file'), 'changing nothing');
        } finally {
            Storage::useTestTransport(null);
            lh_rmtree($root);
        }

        lh_same(
            [],
            Storage::schemaFieldNames('<html><body>502 Bad Gateway</body></html>'),
            'a document that is not a schema yields no fields, which callers read as "unreadable"'
        );
        lh_same(
            ['id', 'ts_dt', '*_s'],
            Storage::schemaFieldNames(
                '<schema><field name="id" type="string"/><field name="ts_dt" type="pdate"/>'
                . '<dynamicField name="*_s" type="string"/></schema>'
            ),
            'static and dynamic fields are both read, because a dynamic field is what makes a '
            . 'missing static one silent'
        );
        lh_same(
            [],
            Storage::schemaShortfall(
                '<schema><field name="id" type="string"/></schema>',
                '<schema><field name="id" type="string"/><field name="extra_s" type="string"/></schema>'
            ),
            'an index with MORE than this version writes is not a mismatch'
        );
    },

    'a pair that is not on the account cannot be adopted' => static function (): void {
        [$root, $cfg] = lh_reuse_scaffold();

        $held  = ['loghound_aaaa1111_hits', 'loghound_aaaa1111_sessions'];
        $calls = [];

        Storage::useTestTransport(lh_reuse_transport($calls, $held, 2));
        try {
            $job = Job::create($root . '/var/setup', Job::KIND_REUSE, ['install_id' => 'ffff9999']);
            lh_false($job->runAll($cfg, $root), 'an id the account does not hold must be refused');
            lh_same(
                '',
                (string) $cfg->get('solr.hits_core', ''),
                'and no index name may be written from an unchecked id'
            );
            lh_contains($job->error(), 'no longer on this Opensolr account');
        } finally {
            Storage::useTestTransport(null);
            lh_rmtree($root);
        }

        lh_same(
            null,
            Pairs::find([['install_id' => 'aaaa1111', 'hits' => 'h', 'sessions' => 's']], '../../etc'),
            'an id that is not hex is refused before it is matched against anything'
        );
    },

    'the account read answers both questions at once, from one call' => static function (): void {
        [$root, $cfg] = lh_reuse_scaffold();

        $held = [
            'loghound_aaaa1111_hits',
            'loghound_aaaa1111_sessions',
            'loghound_bbbb2222_hits',
            'unrelated_index',
        ];
        $calls = [];

        Storage::useTestTransport(lh_reuse_transport($calls, $held, 6));
        try {
            $account = Storage::account($cfg);

            lh_true($account['ok'], 'the read succeeded');
            lh_same(
                1,
                count(lh_reuse_hits($calls, '/get_index_list')),
                'one control-plane call answers pairs, halves and capacity together'
            );
            lh_same(1, count($account['pairs']), 'one complete pair');
            lh_same(1, count($account['halves']), 'one leftover half');
            lh_same(4, $account['capacity']['counted'], 'and the usage counts everything on the account');
        } finally {
            Storage::useTestTransport(null);
            lh_rmtree($root);
        }
    },

    'a control plane that will not answer is a state on the screen, not an exception'
        => static function (): void {
            [$root, $cfg] = lh_reuse_scaffold();
            $calls = [];
            $held  = [];

            Storage::useTestTransport(static function (array $req) use (&$calls): array {
                $calls[] = (string) $req['url'];
                return ['status' => 0, 'body' => '', 'error' => 'Connection timed out'];
            });
            try {
                $account = Storage::account($cfg);
                lh_false($account['ok'], 'it failed');
                lh_same([], $account['pairs'], 'with no pairs invented');
                lh_contains($account['error'], 'could not be reached', 'and a sentence with an action in it');
                lh_false(str_contains($account['error'], LH_REUSE_KEY), 'never quoting the API key');
            } finally {
                Storage::useTestTransport(null);
                lh_rmtree($root);
            }
        },


    'every platform code an operator can hit becomes a sentence with an action in it'
        => static function (): void {
            $cases = [
                'Opensolr: HTTP 403 from regions: ERROR_AUTHENTICATION_FAILED' => 'under Account',
                'ERROR_INVALID_SIGNATURE'                                      => 'issue a new one',
                'ERROR_CANNOT_ADD_MORE_THAN_1_CORES'                           => 'Reuse a pair',
                'ERROR_CORE_NAME_TAKEN_CHOOSE_ANOTHER_CORE_NAME'               => 'picks another',
                'NOT_OWNER_ERROR'                                              => 'does not own that index',
                'WRONG_API_HOST'                                               => 'api_base',
                'SERVER_COUNTRY_DOES_NOT_EXIST'                                => 'regions in the list',
                'Opensolr: cannot reach the control plane (regions): timeout'  => 'outbound HTTPS',
                'Opensolr: HTTP 500 from create_index with an unparseable body.' => 'Nothing has been created',
            ];

            foreach ($cases as $raw => $expected) {
                $said = Storage::explainApi($raw);
                lh_contains($said, $expected, 'explaining ' . $raw);
                lh_false(
                    (bool) preg_match('/\bERROR_[A-Z_]+\b/', $said),
                    'a translated message must not paste the platform constant back: ' . $said
                );
            }

            lh_contains(
                Storage::explainApi('Opensolr says no, api_key=' . LH_REUSE_KEY),
                '[redacted]',
                'an untranslated message still has its credentials scrubbed'
            );
            lh_false(
                str_contains(Storage::explainApi('failed for api_key=' . LH_REUSE_KEY), LH_REUSE_KEY),
                'and the key itself never survives'
            );
        },

    'the ways forward only include reuse when there is something to reuse' => static function (): void {
        $keys = array_column(Pairs::waysForward(false), 'key');
        lh_same(['free', 'upgrade'], $keys, 'an option that cannot apply is worse than no option');

        $withPair = array_column(Pairs::waysForward(true), 'key');
        lh_same(['reuse', 'free', 'upgrade'], $withPair, 'and it comes first when it does apply');

        foreach (Pairs::waysForward(true) as $way) {
            if ($way['url'] !== '') {
                lh_true(
                    str_starts_with($way['url'], 'https://opensolr.com/'),
                    'every route out links to the account rather than describing where to click'
                );
            }
        }
    },

    'what reuse means is said before it happens, and names the hostname that separates sites'
        => static function (): void {
            $pair = ['install_id' => 'aaaa1111', 'hits' => 'loghound_aaaa1111_hits', 'sessions' => 'loghound_aaaa1111_sessions'];

            $said = Pairs::reuseConsequence($pair, 'shop.example.com');
            lh_contains($said, 'shop.example.com', 'the site is named');
            lh_contains($said, 'Virtual host', 'and so is the dimension that tells them apart');
            lh_contains($said, 'joins', 'joining, not overwriting');
            lh_contains($said, 'loghound_aaaa1111_hits', 'and the indexes are named');

            lh_false(
                str_contains(Pairs::reuseConsequence($pair, ''), 'example'),
                'with no configured address it degrades to a generic phrase rather than inventing a host'
            );
        },

    'the hostname comes from the configured address, and never from a credentialled URL'
        => static function (): void {
            [$root, $cfg] = lh_reuse_scaffold();

            lh_same('shop.example.com', Pairs::siteHost($cfg));

            $cfg->set('base_url', 'https://user:pass@shop.example.com');
            lh_same(
                '',
                Pairs::siteHost($cfg),
                'an address carrying a credential yields nothing rather than being parsed for parts'
            );

            $cfg->set('base_url', '');
            lh_same('', Pairs::siteHost($cfg));

            lh_rmtree($root);
        },
];
