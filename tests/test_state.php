<?php
/**
 * Loghound — tests for src/State.php.
 *
 * Every test gets its own SQLite file in a temp directory and deletes it afterwards, so the
 * suite never touches var/state.db and two runs cannot collide.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

use Loghound\State;

/**
 * Run a closure with a fresh State instance, cleaning up afterwards whatever happens.
 */
function lh_with_state(callable $fn): void
{
    $dir = lh_tmpdir('lh_state');
    $state = new State($dir . '/state.db');
    try {
        $fn($state);
    } finally {
        $state->close();
        lh_rmtree($dir);
    }
}

return [

    'the database is created in WAL mode with the expected tables' => function (): void {
        lh_with_state(function (State $state): void {
            $mode = $state->db()->querySingle('PRAGMA journal_mode');
            lh_same('wal', strtolower((string) $mode), 'journal_mode');

            $tables = [];
            $res = $state->db()->query("SELECT name FROM sqlite_master WHERE type='table'");
            while (($row = $res->fetchArray(SQLITE3_ASSOC)) !== false) {
                $tables[] = $row['name'];
            }
            foreach ([
                'offsets', 'sessions_open', 'beacon_staging',
                'cache_geo', 'cache_asn', 'cache_rdns', 'ratelimit', 'meta',
            ] as $table) {
                lh_true(in_array($table, $tables, true), "table $table exists");
            }
        });
    },

    'tail offsets round-trip with their dev and inode' => function (): void {
        lh_with_state(function (State $state): void {
            lh_same(null, $state->getOffset('/var/log/apache2/access.log'), 'unknown source');

            $state->setOffset('/var/log/apache2/access.log', 66310, 12345, 4096);
            $off = $state->getOffset('/var/log/apache2/access.log');

            lh_same(66310, $off['dev'], 'dev');
            lh_same(12345, $off['inode'], 'inode');
            lh_same(4096, $off['offset'], 'offset');
            lh_true($off['updated_at'] > 0, 'updated_at');

            // A logrotate replaces the file: new inode, offset back to 0.
            $state->setOffset('/var/log/apache2/access.log', 66310, 99999, 0);
            $off = $state->getOffset('/var/log/apache2/access.log');
            lh_same(99999, $off['inode'], 'inode after rotate');
            lh_same(0, $off['offset'], 'offset after rotate');

            lh_same(1, count($state->allOffsets()), 'allOffsets');

            $state->clearOffset('/var/log/apache2/access.log');
            lh_same(null, $state->getOffset('/var/log/apache2/access.log'), 'after clear');
        });
    },

    'sessions open, advance, are found by client key and close' => function (): void {
        lh_with_state(function (State $state): void {
            $now = 1789034228000;
            $ck  = '203.0.113.0/24|' . sha1('Mozilla/5.0');

            lh_same(null, $state->findOpenSession($ck, 1800, $now), 'no session yet');

            $id = $state->openSession($ck, $now, 'example.com', ['pages' => 1]);
            lh_same(40, strlen($id), 'session id is a sha1');

            $found = $state->findOpenSession($ck, 1800, $now);
            lh_same($id, $found['session_id'], 'found by client key');
            lh_same('example.com', $found['host'], 'host');
            lh_same(1, $found['data']['pages'], 'data blob');
            lh_same(0, $found['hits'], 'hits');

            $state->updateSession($id, $now + 5000, 1, ['pages' => 2]);
            $found = $state->findOpenSession($ck, 1800, $now);
            lh_same(1, $found['hits'], 'hits after update');
            lh_same($now + 5000, $found['last_ts'], 'last_ts');
            lh_same(2, $found['data']['pages'], 'data after update');

            // Beyond the idle timeout (measured from last_ts, which is now+5s) the session
            // must not be reused: 30 minutes and 10 seconds later is past the cutoff.
            lh_same(null, $state->findOpenSession($ck, 1800, $now + 1810000), 'stale session');

            lh_same(1, $state->openSessionCount(), 'open count');
            $state->closeSession($id);
            lh_same(0, $state->openSessionCount(), 'open count after close');
            lh_same(null, $state->findOpenSession($ck, 1800, $now), 'closed session is not reused');
        });
    },

    'two session ids for the same client key are different' => function (): void {
        lh_with_state(function (State $state): void {
            // The random component is what stops a beacon from guessing another visitor's
            // session id from the two things it already knows.
            $ck = '203.0.113.0/24|abc';
            $a = $state->openSession($ck, 1789034228000);
            $b = $state->openSession($ck, 1789034228000);
            lh_true($a !== $b, 'session ids differ');
        });
    },

    'listIdleSessions returns only sessions past the timeout' => function (): void {
        lh_with_state(function (State $state): void {
            $now = 1789034228000;
            $old = $state->openSession('ck-old', $now - 3600000);
            $state->updateSession($old, $now - 3600000, 1);
            $new = $state->openSession('ck-new', $now);
            $state->updateSession($new, $now, 1);

            $idle = $state->listIdleSessions(1800, $now);
            lh_same(1, count($idle), 'idle count');
            lh_same($old, $idle[0]['session_id'], 'the old one');

            // Closing it takes it out of the list without deleting the row.
            $state->closeSession($old);
            lh_same(0, count($state->listIdleSessions(1800, $now)), 'after close');
            lh_true(is_array($state->getSession($old)), 'row still readable for a late beacon');
        });
    },

    'beacons stage, are fetched by session or client key, and merge once' => function (): void {
        lh_with_state(function (State $state): void {
            $state->stageBeacon('sess-1', 'ck-1', ['visible_ms' => 4000]);
            $state->stageBeacon(null, 'ck-1', ['visible_ms' => 9000]);
            $state->stageBeacon('sess-2', 'ck-2', ['visible_ms' => 1]);

            // The client-key fallback is what catches the beacon's very first call, which
            // happens before the server has issued a session id at all.
            $rows = $state->beaconsFor('sess-1', 'ck-1');
            lh_same(2, count($rows), 'beacons for session 1');
            lh_same(4000, $rows[0]['payload']['visible_ms'], 'payload');

            $state->markBeaconsMerged(array_column($rows, 'id'));
            lh_same(0, count($state->beaconsFor('sess-1', 'ck-1')), 'after merge');
            // The other session's beacon is untouched.
            lh_same(1, count($state->beaconsFor('sess-2')), 'session 2 unaffected');

            lh_same([], $state->beaconsFor(null, null), 'no selector returns nothing');
        });
    },

    'caches distinguish miss, hit and negative hit' => function (): void {
        lh_with_state(function (State $state): void {
            // MISS: nothing stored.
            $hit = null;
            lh_same(null, $state->cacheGet('geo', '203.0.113.9', $hit), 'miss value');
            lh_same(false, $hit, 'miss flag');

            // HIT.
            $state->cachePut('geo', '203.0.113.9', ['country_s' => 'DE'], 86400);
            $value = $state->cacheGet('geo', '203.0.113.9', $hit);
            lh_same(true, $hit, 'hit flag');
            lh_same('DE', $value['country_s'], 'hit value');

            // NEGATIVE: a stored "we looked and found nothing". Without this the same
            // fruitless lookup would be repeated on every hit from that address forever.
            $state->cachePut('asn', '198.51.100.0/24', null, 86400);
            lh_same(null, $state->cacheGet('asn', '198.51.100.0/24', $hit), 'negative value');
            lh_same(true, $hit, 'negative flag');

            // Namespaces are separate stores.
            lh_same(null, $state->cacheGet('rdns', '203.0.113.9', $hit), 'other namespace');
            lh_same(false, $hit, 'other namespace flag');

            // An unknown namespace must fail loudly rather than defaulting to a table.
            lh_throws(static fn() => $state->cacheGet('../etc/passwd', 'x'), 'bad namespace');
        });
    },

    'expired cache entries are treated as a miss and can be purged' => function (): void {
        lh_with_state(function (State $state): void {
            // A TTL below the 60s floor is clamped up, so expiry is forced directly.
            $state->cachePut('geo', 'k', ['country_s' => 'FR'], 60);
            $state->db()->exec("UPDATE cache_geo SET expires_at = 1 WHERE k = 'k'");

            $hit = null;
            lh_same(null, $state->cacheGet('geo', 'k', $hit), 'expired value');
            lh_same(false, $hit, 'expired reads as a miss');

            lh_same(1, $state->cachePurgeExpired('geo'), 'purged rows');
        });
    },

    'the rate limiter allows a burst then refuses' => function (): void {
        lh_with_state(function (State $state): void {
            // 60/min = 1 token per second, capacity 5.
            for ($i = 0; $i < 5; $i++) {
                lh_true($state->rateLimit('ip:203.0.113.9', 60, 5), "request $i allowed");
            }
            // The sixth in the same instant has no tokens left.
            lh_false($state->rateLimit('ip:203.0.113.9', 60, 5), 'request 6 refused');

            // A different key has its own bucket.
            lh_true($state->rateLimit('ip:198.51.100.1', 60, 5), 'other key allowed');

            // A sustained flood cannot drive the balance arbitrarily negative, which would
            // lock the visitor out long after they stopped.
            for ($i = 0; $i < 50; $i++) {
                $state->rateLimit('ip:203.0.113.9', 60, 5);
            }
            $tokens = (float) $state->db()->querySingle(
                "SELECT tokens FROM ratelimit WHERE k = 'ip:203.0.113.9'"
            );
            lh_true($tokens >= -2.0, 'token floor holds, got ' . $tokens);
        });
    },

    'meta values and counters persist' => function (): void {
        lh_with_state(function (State $state): void {
            lh_same('2', $state->metaGet('schema_version'), 'schema_version');
            lh_same('fallback', $state->metaGet('nope', 'fallback'), 'default');

            $state->metaSet('last_run', '2026-09-10T09:57:08Z');
            lh_same('2026-09-10T09:57:08Z', $state->metaGet('last_run'), 'round trip');

            // parse_errors lives here: SPEC §5.2 requires unparseable lines to be counted.
            lh_same(0, $state->counterGet('parse_errors'), 'initial');
            lh_same(1, $state->counterAdd('parse_errors'), 'first add');
            lh_same(4, $state->counterAdd('parse_errors', 3), 'second add');
            lh_same(4, $state->counterGet('parse_errors'), 'read back');
        });
    },

    'purge helpers remove old rows' => function (): void {
        lh_with_state(function (State $state): void {
            $id = $state->openSession('ck', 1789034228000);
            $state->stageBeacon($id, 'ck', ['x' => 1]);
            $state->closeSession($id);

            // Nothing is old enough yet.
            lh_same(0, $state->purgeClosedSessions(86400), 'nothing purged yet');

            // Age the rows past the cutoff.
            $state->db()->exec('UPDATE sessions_open SET closed_at = 1');
            $state->db()->exec('UPDATE beacon_staging SET received_at = 1');

            lh_true($state->purgeClosedSessions(86400) >= 1, 'session purged');
            lh_same(null, $state->getSession($id), 'session gone');
            lh_same(0, count($state->beaconsFor($id)), 'its beacons gone too');

            $state->rateLimit('k', 60, 5);
            $state->db()->exec('UPDATE ratelimit SET updated_at = 1');
            lh_same(1, $state->purgeRateLimits(3600), 'rate limit purged');
        });
    },

    'the state file is not world-readable' => function (): void {
        $dir = lh_tmpdir('lh_perm');
        try {
            $path = $dir . '/state.db';
            $state = new State($path);
            $state->close();
            // Visitor IP addresses live in this file; other local users must not read it.
            $mode = fileperms($path) & 0777;
            lh_same(0, $mode & 0007, 'no world permissions, got ' . decoct($mode));
        } finally {
            lh_rmtree($dir);
        }
    },
];
