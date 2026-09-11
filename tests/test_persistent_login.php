<?php
/**
 * Loghound — tests for "stay signed in": the token, its rotation, and theft.
 *
 * These are the properties the feature is worth nothing without, so each one is asserted
 * directly rather than inferred from the sign-in flow working:
 *
 *   - The store holds a HASH. A stolen copy of var/persistent-logins.json yields no cookie.
 *   - A cookie is good ONCE. Using it replaces it, and the one that was used stops working.
 *   - Replay is DETECTED, not merely refused: a verifier that misses a selector that exists
 *     destroys every token descended from that sign-in and leaves a warning for the operator.
 *   - A selector nobody has heard of is NOT treated as an attack, because that is what an old
 *     browser profile looks like and an alarm on every one of those is an alarm nobody reads.
 *   - Revocation is total, and a store that cannot be written refuses rather than admits.
 *
 * The cookie is driven through $_COOKIE directly here. Persistence mirrors what it sets into
 * $_COOKIE so that the rest of the same request sees the current value, which is what makes the
 * rotation observable without a browser.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Auth\Persistence;
use Loghound\Auth\Store;

/** Forget any cookie a previous case left behind. */
function lh_persist_reset(): void
{
    unset($_COOKIE[Persistence::COOKIE]);
}

/** The raw records in a store. @return array<string,mixed> */
function lh_persist_tokens(string $var): array
{
    $data = Store::at($var, Persistence::STORE)->read();
    return is_array($data['tokens'] ?? null) ? $data['tokens'] : [];
}

/**
 * Push every record's rotation timestamp back, so the grace window has passed.
 *
 * Faster and more reliable than sleeping, and it is the clock the code actually reads.
 */
function lh_persist_age(string $var, int $seconds): void
{
    Store::at($var, Persistence::STORE)->mutate(static function (array &$data) use ($seconds): bool {
        foreach (($data['tokens'] ?? []) as $key => $record) {
            foreach (($record['recent'] ?? []) as $i => $entry) {
                $data['tokens'][$key]['recent'][$i]['t'] = (int) ($entry['t'] ?? time()) - $seconds;
            }
        }
        return true;
    });
}

return [

    'a token is issued as a selector and a verifier, and only the hash is kept'
        => static function (): void {
            $var = lh_tmpdir('lhpersist');
            lh_persist_reset();

            lh_true(Persistence::issue('operator', $var, 86400), 'issuing must succeed');

            $cookie = (string) ($_COOKIE[Persistence::COOKIE] ?? '');
            lh_same(1, preg_match('/^[a-f0-9]{32}\.[a-f0-9]{64}$/', $cookie), 'selector.verifier');

            [$selector, $verifier] = explode('.', $cookie, 2);

            $raw = (string) file_get_contents(Store::at($var, Persistence::STORE)->path());
            lh_true(str_contains($raw, $selector), 'the selector is a public lookup id');
            lh_false(str_contains($raw, $verifier), 'THE VERIFIER MUST NEVER BE STORED');
            lh_true(str_contains($raw, hash('sha256', $verifier)), 'only its hash is');

            lh_rmtree($var);
        },

    'the store is 0600, because it holds bearer credentials' => static function (): void {
        $var = lh_tmpdir('lhpersist');
        lh_persist_reset();

        Persistence::issue('operator', $var, 86400);

        $path = Store::at($var, Persistence::STORE)->path();
        lh_same('0600', substr(sprintf('%o', fileperms($path)), -4), 'the token store');
        lh_same('0600', substr(sprintf('%o', fileperms($path . '.lock')), -4), 'and its lock');

        lh_rmtree($var);
    },

    'a valid cookie signs the operator in and is replaced by a different one'
        => static function (): void {
            $var = lh_tmpdir('lhpersist');
            lh_persist_reset();

            Persistence::issue('operator', $var, 86400);
            $first = (string) $_COOKIE[Persistence::COOKIE];

            $result = Persistence::consume($var, 86400);
            lh_same('ok', $result['state'], 'a fresh cookie verifies');
            lh_same('operator', $result['user'], 'and names the operator');

            $second = (string) $_COOKIE[Persistence::COOKIE];
            lh_true($second !== $first, 'A COOKIE IS GOOD ONCE: using it must replace it');
            lh_same(1, count(lh_persist_tokens($var)), 'and there is still exactly one record');

            lh_rmtree($var);
        },

    'the cookie that was already used stops working once the rotation has settled'
        => static function (): void {
            $var = lh_tmpdir('lhpersist');
            lh_persist_reset();

            Persistence::issue('operator', $var, 86400);
            $used = (string) $_COOKIE[Persistence::COOKIE];

            lh_same('ok', Persistence::consume($var, 86400)['state'], 'the first use works');

            lh_persist_age($var, 120);

            $_COOKIE[Persistence::COOKIE] = $used;
            lh_same('theft', Persistence::consume($var, 86400)['state'], 'the second use of it does not');

            lh_rmtree($var);
        },

    'a burst of tabs waking with the same cookie is one use, not a theft' => static function (): void {
        $var = lh_tmpdir('lhpersist');
        lh_persist_reset();

        Persistence::issue('operator', $var, 86400);
        $shared = (string) $_COOKIE[Persistence::COOKIE];

        $states = [];
        for ($tab = 0; $tab < 3; $tab++) {
            $_COOKIE[Persistence::COOKIE] = $shared;
            $states[] = Persistence::consume($var, 86400)['state'];
        }

        lh_same(
            ['ok', 'ok', 'ok'],
            $states,
            'PHP deletes a session file after 24 idle minutes, so a remembered browser is on this '
                . 'path every morning; three tabs revalidating together must not destroy the account'
        );
        lh_false(Persistence::hasAlert($var), 'and must not raise a theft warning');
        lh_same(1, count(lh_persist_tokens($var)), 'the token survives');

        lh_rmtree($var);
    },

    'the grace is narrow: the same cookie after it has passed is a theft' => static function (): void {
        $var = lh_tmpdir('lhpersist');
        lh_persist_reset();

        Persistence::issue('operator', $var, 86400);
        $stolen = (string) $_COOKIE[Persistence::COOKIE];

        Persistence::consume($var, 86400);
        lh_persist_age($var, 31);

        $_COOKIE[Persistence::COOKIE] = $stolen;
        lh_same(
            'theft',
            Persistence::consume($var, 86400)['state'],
            'a cookie out of a backup or a proxy log is replayed minutes or days later, never seconds'
        );
        lh_true(Persistence::hasAlert($var), 'and that is what raises the warning');

        lh_rmtree($var);
    },

    'a replayed verifier destroys the whole family and leaves a warning' => static function (): void {
        $var = lh_tmpdir('lhpersist');
        lh_persist_reset();

        Persistence::issue('operator', $var, 86400);
        $stolen = (string) $_COOKIE[Persistence::COOKIE];

        Persistence::consume($var, 86400);
        $honest = (string) $_COOKIE[Persistence::COOKIE];
        lh_same(1, count(lh_persist_tokens($var)), 'the honest browser holds the only live token');

        lh_persist_age($var, 120);

        $_COOKIE[Persistence::COOKIE] = $stolen;
        $replay = Persistence::consume($var, 86400);

        lh_same('theft', $replay['state'], 'a verifier that misses an existing selector is a replay');
        lh_same('', $replay['user'], 'and signs nobody in');
        lh_same([], lh_persist_tokens($var), 'EVERY token in that family is destroyed');
        lh_true(Persistence::hasAlert($var), 'and the operator has a warning waiting');

        $_COOKIE[Persistence::COOKIE] = $honest;
        lh_same(
            'stale',
            Persistence::consume($var, 86400)['state'],
            'the honest browser is signed out too, which is the price of not knowing which was which'
        );

        lh_rmtree($var);
    },

    'the warning survives a page render and is only cleared by a completed sign-in'
        => static function (): void {
            $var = lh_tmpdir('lhpersist');
            lh_persist_reset();

            Persistence::issue('operator', $var, 86400);
            $stolen = (string) $_COOKIE[Persistence::COOKIE];
            Persistence::consume($var, 86400);
            lh_persist_age($var, 120);
            $_COOKIE[Persistence::COOKIE] = $stolen;
            Persistence::consume($var, 86400);

            lh_true(Persistence::hasAlert($var), 'the warning is set');
            lh_true(Persistence::hasAlert($var), 'asking again does not clear it');
            lh_true(Persistence::hasAlert($var), 'nor does a third render of the sign-in page');

            lh_true(Persistence::takeAlert($var), 'a completed sign-in takes it');
            lh_false(Persistence::hasAlert($var), 'and it is gone');
            lh_false(Persistence::takeAlert($var), 'taking it twice reports nothing');

            lh_rmtree($var);
        },

    'a selector nobody knows is a stale cookie, not an attack' => static function (): void {
        $var = lh_tmpdir('lhpersist');
        lh_persist_reset();

        Persistence::issue('operator', $var, 86400);

        $_COOKIE[Persistence::COOKIE] = str_repeat('a', 32) . '.' . str_repeat('b', 64);
        $result = Persistence::consume($var, 86400);

        $before = filemtime(Store::at($var, Persistence::STORE)->path());
        clearstatcache();

        lh_same('stale', $result['state'], 'an unknown selector is simply unknown');
        lh_false(Persistence::hasAlert($var), 'NO alarm: this is what an old browser profile looks like');
        lh_same(1, count(lh_persist_tokens($var)), 'and no other token is harmed');
        lh_false(Persistence::present(), 'the useless cookie is cleared from the browser');

        for ($i = 0; $i < 25; $i++) {
            $_COOKIE[Persistence::COOKIE] = bin2hex(random_bytes(16)) . '.' . bin2hex(random_bytes(32));
            Persistence::consume($var, 86400);
        }
        clearstatcache();
        lh_same(
            $before,
            filemtime(Store::at($var, Persistence::STORE)->path()),
            'an unknown selector must not rewrite the store: this path is reachable by anyone on '
                . 'the internet, and a locked write per made-up cookie is an amplifier'
        );

        lh_rmtree($var);
    },

    'a malformed cookie is discarded without touching the store' => static function (): void {
        $var = lh_tmpdir('lhpersist');
        lh_persist_reset();

        Persistence::issue('operator', $var, 86400);
        $before = lh_persist_tokens($var);

        foreach (['', 'nonsense', 'no-dot-here', 'zz.zz', str_repeat('a', 32), '../../etc/passwd.x'] as $bad) {
            $_COOKIE[Persistence::COOKIE] = $bad;
            $state = Persistence::consume($var, 86400)['state'];
            lh_true(in_array($state, ['none', 'stale'], true), 'refused: ' . lh_show($bad));
            lh_false(Persistence::hasAlert($var), 'and not reported as theft: ' . lh_show($bad));
        }

        lh_same($before, lh_persist_tokens($var), 'the store is untouched throughout');

        lh_rmtree($var);
    },

    'an expired token is refused and pruned' => static function (): void {
        $var = lh_tmpdir('lhpersist');
        lh_persist_reset();

        Persistence::issue('operator', $var, 86400);
        $cookie = (string) $_COOKIE[Persistence::COOKIE];

        $store = Store::at($var, Persistence::STORE);
        $store->mutate(static function (array &$data): bool {
            foreach ($data['tokens'] as $key => $record) {
                $data['tokens'][$key]['expires'] = time() - 10;
            }
            return true;
        });

        $_COOKIE[Persistence::COOKIE] = $cookie;
        lh_same('stale', Persistence::consume($var, 86400)['state'], 'an aged-out token does not sign anyone in');
        lh_same([], lh_persist_tokens($var), 'and is pruned rather than left lying about');

        lh_rmtree($var);
    },

    'using a token slides its expiry forward, so a browser in daily use never ages out'
        => static function (): void {
            $var = lh_tmpdir('lhpersist');
            lh_persist_reset();

            Persistence::issue('operator', $var, 86400);

            $store = Store::at($var, Persistence::STORE);
            $store->mutate(static function (array &$data): bool {
                foreach ($data['tokens'] as $key => $record) {
                    $data['tokens'][$key]['expires'] = time() + 60;
                }
                return true;
            });

            lh_same('ok', Persistence::consume($var, 86400)['state'], 'it still works while it is alive');

            $tokens = lh_persist_tokens($var);
            $record = reset($tokens);
            lh_true((int) $record['expires'] > time() + 80000, 'and the replacement gets the full lifetime');

            lh_rmtree($var);
        },

    'revoking destroys every token and clears the cookie' => static function (): void {
        $var = lh_tmpdir('lhpersist');
        lh_persist_reset();

        Persistence::issue('operator', $var, 86400);
        Persistence::consume($var, 86400);
        Persistence::issue('operator', $var, 86400);
        lh_true(Persistence::count($var) >= 1, 'there are tokens to revoke');

        Persistence::revokeAll($var);

        lh_same([], lh_persist_tokens($var), 'every record is gone');
        lh_same(0, Persistence::count($var), 'nothing is counted');
        lh_false(Persistence::present(), 'and this browser no longer holds one');

        lh_rmtree($var);
    },

    'revoking on an installation that never used the feature writes nothing' => static function (): void {
        $var = lh_tmpdir('lhpersist');
        lh_persist_reset();

        Persistence::revokeAll($var);

        lh_false(
            Store::at($var, Persistence::STORE)->exists(),
            'a revocation must not create the file it is emptying'
        );
        lh_false(Persistence::hasAlert($var), 'and there is no warning to find');

        lh_rmtree($var);
    },

    'a store that cannot be written refuses to issue, rather than pretending it did'
        => static function (): void {
            $dir = lh_tmpdir('lhpersist');
            file_put_contents($dir . '/blocked', 'a file where a directory would have to be');
            lh_persist_reset();

            lh_false(Persistence::issue('operator', $dir . '/blocked', 86400), 'issuing reports failure');
            lh_false(Persistence::present(), 'and no cookie is handed out for a token that does not exist');

            lh_rmtree($dir);
        },

    'the lifetime is clamped, so a hand-edited config cannot make the option a no-op'
        => static function (): void {
            lh_same(Persistence::DEFAULT_LIFETIME, Persistence::lifetime([]), 'the default is the maximum');
            lh_true(Persistence::lifetime(['persistent_lifetime' => 0]) >= 86400, 'zero cannot switch it off');
            lh_true(Persistence::lifetime(['persistent_lifetime' => -1]) >= 86400, 'nor can a negative');
            lh_true(Persistence::lifetime(['persistent_lifetime' => 'forever']) >= 86400, 'nor a string');
            lh_same(
                Persistence::DEFAULT_LIFETIME,
                Persistence::lifetime(['persistent_lifetime' => PHP_INT_MAX]),
                'and it cannot exceed what can still be pruned'
            );
            lh_same(604800, Persistence::lifetime(['persistent_lifetime' => 604800]), 'a real value is honoured');
        },

    'the form field is only taken as yes for a value that means yes' => static function (): void {
        $before = $_POST;

        foreach (['1', 'on', 'yes'] as $yes) {
            $_POST = [Persistence::FIELD => $yes];
            lh_true(Persistence::requested(), lh_show($yes) . ' means yes');
        }
        foreach (['0', '', 'off', 'no', 'true'] as $no) {
            $_POST = [Persistence::FIELD => $no];
            lh_false(Persistence::requested(), lh_show($no) . ' does not');
        }
        $_POST = [];
        lh_false(Persistence::requested(), 'an absent checkbox does not');

        $_POST = $before;
    },

    'the Store refuses rather than half-writes when it cannot be locked' => static function (): void {
        $dir = lh_tmpdir('lhstore');
        file_put_contents($dir . '/blocked', 'not a directory');

        $store = Store::at($dir . '/blocked', 'thing.json');
        lh_same(null, $store->mutate(static function (array &$d): bool {
            $d['written'] = true;
            return true;
        }), 'a mutate that cannot be performed reports null');
        lh_same([], $store->read(), 'and nothing was written');
    },

    'the Store round-trips and replaces atomically' => static function (): void {
        $dir = lh_tmpdir('lhstore');
        $store = Store::at($dir, 'thing.json');

        lh_same([], $store->read(), 'an unwritten store reads as empty');
        lh_false($store->exists(), 'and does not exist');

        $result = $store->mutate(static function (array &$d) {
            $d['n'] = 1;
            return 'done';
        });
        lh_same('done', $result, 'the callback result is returned');
        lh_same(['n' => 1], $store->read(), 'and the data is there');

        $store->mutate(static function (array &$d): bool {
            $d['n'] = (int) $d['n'] + 1;
            return true;
        });
        lh_same(['n' => 2], $store->read(), 'a second pass reads what the first wrote');

        file_put_contents($store->path(), '{ this is not json');
        lh_same([], $store->read(), 'a corrupt store reads as empty rather than throwing');

        lh_rmtree($dir);
    },

];
