<?php
/**
 * Loghound — pressing "Try again" must not abandon an index the account is billed for.
 *
 * THE BUG THESE PIN. Provisioning is a job, and a job's `result` is per job. The reuse
 * branch in Storage::createOne() consulted that result to decide whether a taken index name
 * was one the installation had created itself. Within one job that is correct. Across a
 * retry it is not: "Try again" cannot reattach to a job that has already failed, so
 * Installer::startJob() creates a NEW job whose result is empty, and the branch could never
 * fire. The retry therefore read "name taken", concluded a stranger held it, rewound with a
 * fresh installation id, and left the index the previous attempt had created sitting in the
 * operator's account — unreferenced by any configuration, and billed for. Once per retry.
 *
 * The fix is to establish ownership against the platform rather than against the job's own
 * memory, so the tests below drive a scripted control plane through a real two-job sequence
 * and assert on the calls that reached it.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Config;
use Loghound\Setup\Job;
use Loghound\Setup\Storage;

/**
 * A throwaway installation prefix with a saved configuration holding Opensolr credentials.
 *
 * Mirrors what the storage step has written by the time provisioning starts: managed mode
 * and an account, but no index names yet.
 *
 * @return array{0:string,1:Config}
 */
function lh_retry_scaffold(): array
{
    $root = lh_tmpdir('lh-retry');
    @mkdir($root . '/config', 0750, true);
    @mkdir($root . '/var/setup', 0750, true);

    foreach (['hits', 'sessions'] as $role) {
        @mkdir($root . '/solr/' . $role . '/conf', 0750, true);
        file_put_contents($root . '/solr/' . $role . '/conf/schema.xml', '<schema/>');
        file_put_contents($root . '/solr/' . $role . '/conf/mapping-ISOLatin1Accent.txt', '"a" => "a"' . "\n");
        file_put_contents($root . '/solr/' . $role . '/conf/solrconfig.xml', '<config/>');
    }

    $cfg = Config::load($root . '/config/loghound.php');
    $cfg->set('solr.mode', 'opensolr');
    $cfg->set('opensolr.email', 'someone@example.com');
    $cfg->set('opensolr.api_key', 'SENTINEL-APIKEY-1234');
    $cfg->save();

    return [$root, $cfg];
}

/**
 * A scripted Opensolr control plane that remembers which indexes it has created.
 *
 * This is the whole point of the file: the platform, not the job, is the thing that knows
 * an index exists. `create_index` refuses a name it has already handed out, exactly as the
 * real API does, and `get_index_list` reports what the account holds.
 *
 * @param array<int,string> $calls   Filled with every request URL, in order.
 * @param array<int,string> $held    Index names the account holds; seeded and updated here.
 * @param callable|null     $failure fn(string $url, int $n): ?array — return a body to
 *                                   override the scripted one, e.g. to fail a later step.
 *                                   A body carrying `__raw` is used as the transport result
 *                                   itself, which is how a network failure is simulated.
 */
function lh_retry_transport(array &$calls, array &$held, ?callable $failure = null): callable
{
    return static function (array $req) use (&$calls, &$held, $failure): array {
        $url = (string) $req['url'];
        $calls[] = $url;

        $override = $failure === null ? null : $failure($url, count($calls));
        if (is_array($override) && isset($override['__raw'])) {
            return (array) $override['__raw'];
        }
        if (is_array($override)) {
            return ['status' => 200, 'body' => (string) json_encode($override), 'error' => ''];
        }

        $body = ['status' => true, 'msg' => 'OK'];

        if (str_contains($url, '/regions')) {
            $body = ['FINLAND9'];
        } elseif (str_contains($url, '/get_index_list')) {
            $body = array_map(
                static fn (string $n): array => ['index_name' => $n, 'index_type' => 'standard'],
                array_values($held)
            );
        } elseif (str_contains($url, '/create_index')) {
            preg_match('/index_name=([A-Za-z0-9_]+)/', $url, $m);
            $name = $m[1] ?? '';
            if (in_array($name, $held, true)) {
                $body = ['status' => false, 'msg' => 'ERROR_CORE_NAME_TAKEN_CHOOSE_ANOTHER_CORE_NAME'];
            } else {
                $held[] = $name;
            }
        } elseif (str_contains($url, '/delete_index')) {
            preg_match('/index_name=([A-Za-z0-9_]+)/', $url, $m);
            $held = array_values(array_filter($held, static fn (string $n): bool => $n !== ($m[1] ?? '')));
        } elseif (str_contains($url, '/get_core_info')) {
            preg_match('/core_name=([A-Za-z0-9_]+)/', $url, $m);
            $body = ['status' => true, 'msg' => ['info' => [
                'connection_url' => 'https://fi.solrcluster.com/solr/' . ($m[1] ?? 'x'),
                'auth_username'  => 'solr-user',
                'auth_password'  => 'solr-pass',
            ]]];
        } elseif (str_contains($url, '/select')) {
            $body = ['responseHeader' => ['status' => 0], 'response' => ['numFound' => 0, 'docs' => []]];
        }

        return ['status' => 200, 'body' => (string) json_encode($body), 'error' => ''];
    };
}

/** Every index name a scripted run asked the platform to create, in order. */
function lh_retry_created(array $calls): array
{
    $names = [];
    foreach ($calls as $url) {
        if (str_contains($url, '/create_index') && preg_match('/index_name=([A-Za-z0-9_]+)/', $url, $m)) {
            $names[] = $m[1];
        }
    }
    return $names;
}

return [

    'a retry after a mid-provision failure reuses the index the first attempt created'
        => static function (): void {
            [$root, $cfg] = lh_retry_scaffold();
            $held = [];
            $calls = [];

            $fail = static function (string $url, int $n): ?array {
                return str_contains($url, '/upload_config_file')
                    ? ['status' => false, 'msg' => 'ERROR_UPLOAD_REJECTED']
                    : null;
            };

            Storage::useTestTransport(lh_retry_transport($calls, $held, $fail));
            try {
                $first = Job::create($root . '/var/setup', Job::KIND_OPENSOLR, ['region' => 'FINLAND9']);
                lh_false($first->runAll($cfg, $root), 'the first attempt must fail on the upload');
                lh_same('error', $first->state(), 'and record that failure');

                $madeFirst = lh_retry_created($calls);
                lh_same(2, count($madeFirst), 'the first attempt creates exactly the pair');
                lh_same(2, count($held), 'and the account now holds both');
                $installId = (string) $cfg->get('solr.install_id', '');
                lh_true($installId !== '', 'the first attempt settled on an installation id');
            } finally {
                Storage::useTestTransport(null);
            }

            $calls = [];
            Storage::useTestTransport(lh_retry_transport($calls, $held));
            try {
                $second = Job::create($root . '/var/setup', Job::KIND_OPENSOLR, ['region' => 'FINLAND9']);
                lh_same([], $second->result(), 'a fresh job starts with no memory of the first');

                lh_true($second->runAll($cfg, $root), 'the retry should succeed: ' . $second->error());

                lh_same(
                    2,
                    count($held),
                    'the retry must not leave the account holding more than the pair it needs'
                );
                $deletes = array_filter($calls, static fn (string $u): bool => str_contains($u, 'delete_index'));
                lh_same(0, count($deletes), 'nothing had to be deleted, because nothing was abandoned');
            } finally {
                Storage::useTestTransport(null);
                lh_rmtree($root);
            }
        },

    'a retry does not rewind onto a fresh installation id' => static function (): void {
        [$root, $cfg] = lh_retry_scaffold();
        $held = [];
        $calls = [];

        $fail = static fn (string $url, int $n): ?array => str_contains($url, '/get_core_info')
            ? ['status' => false, 'msg' => 'ERROR_TEMPORARY']
            : null;

        Storage::useTestTransport(lh_retry_transport($calls, $held, $fail));
        try {
            $first = Job::create($root . '/var/setup', Job::KIND_OPENSOLR, ['region' => 'FINLAND9']);
            lh_false($first->runAll($cfg, $root), 'the first attempt must fail fetching the connection');
            $installId = (string) $cfg->get('solr.install_id', '');
            $hits = (string) $cfg->get('solr.hits_core', '');
            lh_true($installId !== '' && $hits !== '', 'the first attempt named the pair');
        } finally {
            Storage::useTestTransport(null);
        }

        $calls = [];
        Storage::useTestTransport(lh_retry_transport($calls, $held));
        try {
            $second = Job::create($root . '/var/setup', Job::KIND_OPENSOLR, ['region' => 'FINLAND9']);
            lh_true($second->runAll($cfg, $root), 'the retry should succeed: ' . $second->error());

            lh_same(
                $installId,
                (string) $cfg->get('solr.install_id', ''),
                'the installation id must survive the retry, or the first pair is orphaned'
            );
            lh_same($hits, (string) $cfg->get('solr.hits_core', ''), 'and so must the hits index name');

            foreach (lh_retry_created($calls) as $name) {
                lh_true(
                    str_contains($name, $installId),
                    'the retry tried to create ' . $name . ', which is not part of the original pair'
                );
            }
        } finally {
            Storage::useTestTransport(null);
            lh_rmtree($root);
        }
    },

    'a name held by somebody else is still abandoned for a fresh id' => static function (): void {
        [$root, $cfg] = lh_retry_scaffold();

        $held = [];
        $calls = [];
        $taken = null;

        $stranger = static function (string $url, int $n) use (&$taken): ?array {
            if (!str_contains($url, '/create_index')) {
                return null;
            }
            preg_match('/index_name=([A-Za-z0-9_]+)/', $url, $m);
            $name = $m[1] ?? '';
            if ($taken === null && str_ends_with($name, '_hits')) {
                $taken = $name;
                return ['status' => false, 'msg' => 'ERROR_CORE_NAME_TAKEN_CHOOSE_ANOTHER_CORE_NAME'];
            }
            return null;
        };

        Storage::useTestTransport(lh_retry_transport($calls, $held, $stranger));
        try {
            $job = Job::create($root . '/var/setup', Job::KIND_OPENSOLR, ['region' => 'FINLAND9']);
            lh_true($job->runAll($cfg, $root), 'the collision should be retried, not fatal: ' . $job->error());

            lh_true($taken !== null, 'the scripted stranger refused a name');
            lh_true(
                (string) $cfg->get('solr.hits_core', '') !== $taken,
                'a name this account does not hold must not be reused'
            );
            lh_same(2, count($held), 'exactly one pair is left behind');
        } finally {
            Storage::useTestTransport(null);
            lh_rmtree($root);
        }
    },

    'an unreachable control plane fails the step rather than abandoning the index'
        => static function (): void {
            [$root, $cfg] = lh_retry_scaffold();
            $held = [];
            $calls = [];

            $fail = static fn (string $url, int $n): ?array => str_contains($url, '/upload_config_file')
                ? ['status' => false, 'msg' => 'ERROR_UPLOAD_REJECTED']
                : null;

            Storage::useTestTransport(lh_retry_transport($calls, $held, $fail));
            try {
                $first = Job::create($root . '/var/setup', Job::KIND_OPENSOLR, ['region' => 'FINLAND9']);
                $first->runAll($cfg, $root);
                lh_same(2, count($held), 'the first attempt created the pair');
            } finally {
                Storage::useTestTransport(null);
            }

            $before = $held;
            $calls = [];

            $seen = 0;
            /**
             * Fail every index-list read but the first.
             *
             * The capacity check reads the list before anything is created, so the OWNERSHIP
             * read this test is about is the second one. Letting the first through is what
             * keeps the job walking as far as createOne(), where the fail-closed branch lives.
             */
            $blind = static function (string $url, int $n) use (&$seen): ?array {
                if (!str_contains($url, '/get_index_list')) {
                    return null;
                }
                $seen++;
                return $seen === 1
                    ? null
                    : ['__raw' => ['status' => 0, 'body' => '', 'error' => 'Connection timed out']];
            };

            Storage::useTestTransport(lh_retry_transport($calls, $held, $blind));
            try {
                $second = Job::create($root . '/var/setup', Job::KIND_OPENSOLR, ['region' => 'FINLAND9']);
                lh_false($second->runAll($cfg, $root), 'a control plane that cannot answer must fail the step');
                lh_contains(
                    $second->error(),
                    'already taken',
                    'and the message must say why it stopped'
                );
                lh_false(
                    str_contains($second->error(), 'SENTINEL-APIKEY-1234'),
                    'without ever quoting the API key'
                );
                lh_same($before, $held, 'and nothing may be created or deleted while it cannot tell');
            } finally {
                Storage::useTestTransport(null);
                lh_rmtree($root);
            }
        },

    'a control plane that cannot be counted stops before the first index is created'
        => static function (): void {
            [$root, $cfg] = lh_retry_scaffold();
            $held = [];
            $calls = [];

            $blind = static fn (string $url, int $n): ?array => str_contains($url, '/get_index_list')
                ? ['__raw' => ['status' => 0, 'body' => '', 'error' => 'Connection timed out']]
                : null;

            Storage::useTestTransport(lh_retry_transport($calls, $held, $blind));
            try {
                $job = Job::create($root . '/var/setup', Job::KIND_OPENSOLR, ['region' => 'FINLAND9']);
                lh_false($job->runAll($cfg, $root), 'a capacity check that cannot be made must stop the job');
                lh_same([], lh_retry_created($calls), 'and it must stop BEFORE anything is created');
                lh_same([], $held, 'so the account is left exactly as it was');
                lh_contains(
                    $job->error(),
                    'could not be reached',
                    'the operator is told what could not be done, not given a transport error'
                );
                lh_false(
                    str_contains($job->error(), 'SENTINEL-APIKEY-1234'),
                    'without ever quoting the API key'
                );
            } finally {
                Storage::useTestTransport(null);
                lh_rmtree($root);
            }
        },
];
