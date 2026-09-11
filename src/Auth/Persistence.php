<?php
/**
 * Loghound — "stay signed in", built as a rotating selector/verifier token.
 *
 * WHAT THE OPERATOR ASKED FOR. To stay signed in permanently, and never to be signed out
 * again unless they sign out themselves. Not a longer timeout: no timeout.
 *
 * WHY A LONG-LIVED SESSION COOKIE IS NOT THE ANSWER. It looks like the answer and it fails
 * within a day. PHP's session garbage collector deletes session FILES on a schedule of its
 * own (session.gc_maxlifetime, 1440 seconds by default, swept probabilistically on other
 * people's requests). A cookie that outlives the file it names is a dangling reference: the
 * operator is signed out by a cron-shaped accident, which is precisely the thing they asked
 * never to happen again. Raising gc_maxlifetime to a decade instead leaves every expired
 * session in the world on disk, valid, forever. The session must stay short-lived and
 * something else must be able to recreate it.
 *
 * THE DESIGN, and every property of it is load-bearing:
 *
 *   SELECTOR PLUS VERIFIER. The cookie is `<selector>.<verifier>`. The selector is a public
 *   lookup id, stored in the clear. The verifier is a 256-bit secret, and only its SHA-256 is
 *   stored. An attacker who reads var/persistent-logins.json — a backup, a misconfigured
 *   webserver, a second tenant on the box — gets a list of hashes and no usable cookie. The
 *   two halves are separate because looking a token up BY its secret forces either a linear
 *   scan comparing secrets (a timing oracle) or an index on the secret (which means storing
 *   something equivalent to it). With a selector, the lookup is on public data and the secret
 *   is only ever compared, in constant time, through Security::equals().
 *
 *   SHA-256 AND NOT password_hash(). The verifier is 256 bits from random_bytes(), not a
 *   human's password: there is no dictionary to attack and no work factor worth paying on a
 *   path that runs on every request. A slow hash here buys nothing and costs a login.
 *
 *   THE VERIFIER ROTATES ON EVERY USE; THE SELECTOR DOES NOT. Each time a cookie signs
 *   somebody in, a fresh verifier replaces the stored hash and the cookie is reissued under the
 *   same selector. A cookie is therefore good exactly once — a copy taken from a backup, a
 *   proxy log or a synced browser profile stops working the moment the real browser makes one
 *   more request. The selector stays put deliberately: it is the SERIES identifier, it carries
 *   no secret, and it is the only thing that makes the next property possible.
 *
 *   THEFT DETECTION, which is why the selector is stable. A verifier that does not match a
 *   selector that DOES exist can only mean that this series has already been used and rotated —
 *   two parties are holding copies of one cookie. That is not a wrong guess (guessing a
 *   selector is 128 bits of work); it is a replay. Rotating the selector as well would have
 *   destroyed exactly this signal: the replayed cookie would name a selector nobody had heard
 *   of, indistinguishable from an old browser profile, and the attack would look like ordinary
 *   staleness. A selector that is genuinely not found IS treated as ordinary staleness and
 *   silently discarded, because an alarm on every returning old profile is an alarm nobody
 *   reads. The one deliberate exception to "good once" is ROTATION_GRACE — thirty seconds in
 *   which the verifier a rotation just replaced is still honoured, because a browser waking
 *   several tabs at once is one use and not two. What that buys and what it costs is set out on
 *   the constant, and it is the difference between a theft warning that means something and one
 *   that fires every morning.
 *
 *   A REPLAY REVOKES EVERYTHING FOR THAT ACCOUNT, not just the series it was found in. A
 *   verifier being replayed means a copy of a cookie, or of the store, got out; nothing in the
 *   evidence says which OTHER tokens went with it. The honest browser is signed out too. That
 *   is the correct price: the alternative is leaving credentials alive on the strength of a
 *   guess about the scope of a breach.
 *
 *   REVOCABLE, AND REVOKED BY EVERYTHING THAT SHOULD REVOKE IT. Explicit sign-out destroys
 *   the presented token and every other token for the account, because there is one operator
 *   and "sign me out" means out. Changing the password, changing the sign-in mode and turning
 *   two-factor on all do the same: each is a statement that the old proofs of identity no
 *   longer stand.
 *
 *   SameSite=Lax, NOT Strict. This is the one cookie in the project that must arrive on a
 *   top-level navigation from somewhere else, because arriving there is its entire purpose:
 *   Strict would withhold it exactly when the operator clicks a link to the panel from their
 *   mail client and would leave them at the sign-in form, which is the bug the feature exists
 *   to remove. Lax still withholds it from cross-site POSTs and subresource loads, so it is
 *   not a CSRF hole; and the session cookie it leads to stays Strict.
 *
 * WHAT IT COSTS, WHICH THE FORM AND SETTINGS BOTH SAY OUT LOUD. Whoever holds that browser
 * profile is signed in to this panel indefinitely. There is no timeout to save the operator
 * from a lost laptop, and the only way back out is an explicit sign-out (or bin/loghound-setup
 * changing the password). That is not a defect of this implementation; it is what "never sign
 * me out" means, and an operator choosing it deserves to be told rather than reassured.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Auth;

use Loghound\Security;

final class Persistence
{
    /** The cookie. Named for what it is, so an operator clearing cookies by hand can find it. */
    public const COOKIE = 'lh_remember';

    /** The store inside var/. */
    public const STORE = 'persistent-logins.json';

    /** The form field on the sign-in page. */
    public const FIELD = 'remember';

    /**
     * Default lifetime: ten years, slid forward on every use.
     *
     * "Permanently" has to be a number somewhere, and an unbounded one would mean a record
     * that can never be pruned. Ten years, renewed on each visit, is indistinguishable from
     * permanent for a browser in daily use while still letting a genuinely abandoned token
     * age out of the file instead of accumulating.
     */
    public const DEFAULT_LIFETIME = 315360000;

    /** Hard cap on records kept, so a pathological loop cannot grow the file without bound. */
    private const MAX_TOKENS = 50;

    /**
     * Seconds after a rotation during which the verifier it replaced is still accepted.
     *
     * WHY THIS EXISTS, and it is not a convenience. PHP deletes session files it has not seen
     * for session.gc_maxlifetime — twenty-four minutes by default. A remembered browser is
     * therefore on the token path every single morning, and an operator with three panel tabs
     * open wakes the laptop and all three revalidate at the same instant with the same cookie.
     * Under a strict reading of "a cookie is good once", one of them rotates and the other two
     * are replays: every token destroyed, everybody signed out, and a theft warning on the
     * sign-in page. Daily. A warning that fires every morning is a warning that gets ignored,
     * and then it is not a warning at all.
     *
     * So one use by one browser is defined as one use, and the width of "one use" is this
     * window. Accepting the superseded verifier ALSO rotates, and the verifier it displaces
     * stays acceptable for its own window, so a burst of tabs all converge on a live cookie.
     *
     * WHAT IT COSTS, exactly: a stolen verifier replayed within thirty seconds of the honest
     * browser's use of that same verifier is accepted instead of detected. Nothing outside that
     * window is, so a cookie copied out of a backup, a proxy log or a synced profile and used
     * minutes or days later still trips detection — which is the case that actually happens.
     * Thirty seconds is orders of magnitude longer than a browser's wake-up burst and orders of
     * magnitude shorter than any realistic theft-to-replay interval.
     */
    private const ROTATION_GRACE = 30;

    /** Superseded hashes remembered per token. A browser has tabs, not thousands of them. */
    private const MAX_RECENT = 8;

    /**
     * The configured lifetime, clamped.
     *
     * A day at the bottom, because anything shorter is the idle timeout with extra steps and
     * an operator who wanted that would not have ticked the box. Read through clampInt so a
     * hand-edited config cannot set it to zero and turn every persistent token into an
     * instantly-expired one, which would look like the feature silently not working.
     *
     * @param array<string,mixed> $auth The 'auth' section of the config.
     */
    public static function lifetime(array $auth): int
    {
        return Security::clampInt(
            $auth['persistent_lifetime'] ?? null,
            86400,
            self::DEFAULT_LIFETIME,
            self::DEFAULT_LIFETIME
        );
    }

    /** Did the sign-in form ask to be remembered? */
    public static function requested(): bool
    {
        $value = $_POST[self::FIELD] ?? null;
        return $value === '1' || $value === 'on' || $value === 'yes';
    }

    /** Is a persistent-login cookie present on this request? */
    public static function present(): bool
    {
        return is_string($_COOKIE[self::COOKIE] ?? null) && ($_COOKIE[self::COOKIE] ?? '') !== '';
    }

    /**
     * Mint a token for an operator and set the cookie.
     *
     * Called only after the password AND, when it is enabled, the second factor have both
     * been satisfied. A token issued any earlier would be a bearer credential handed out on
     * the strength of half a credential.
     *
     * @return bool False when the store could not be written, which the caller must surface
     *              rather than ignore: the operator ticked a box and is entitled to know it
     *              did not take effect.
     */
    public static function issue(string $user, ?string $varDir, int $lifetime): bool
    {
        $selector = bin2hex(random_bytes(16));
        $verifier = bin2hex(random_bytes(32));
        $expires  = time() + $lifetime;

        $ok = self::store($varDir)->mutate(
            static function (array &$data) use ($selector, $verifier, $user, $expires): bool {
                $data['tokens'] = self::prune(is_array($data['tokens'] ?? null) ? $data['tokens'] : []);
                $data['tokens'][$selector] = [
                    'user'    => $user,
                    'hash'    => hash('sha256', $verifier),
                    'recent'  => [],
                    'created' => time(),
                    'used'    => time(),
                    'expires' => $expires,
                ];
                return true;
            }
        );

        if ($ok !== true) {
            return false;
        }

        self::sendCookie($selector . '.' . $verifier, $expires);
        return true;
    }

    /**
     * Examine a presented cookie, rotate it, and say what happened.
     *
     * One locked pass over the store, so two requests arriving with the same cookie cannot both
     * rotate it and reach inconsistent conclusions about what the current verifier is.
     *
     * A SELECTOR THAT IS NOT IN THE STORE IS ANSWERED FROM A READ, before the write lock is ever
     * taken. This path is reachable by anyone on the internet — it runs on any request carrying a
     * cookie named lh_remember — and taking an exclusive lock and rewriting the file for every
     * made-up selector would be a disk-and-lock amplifier handed to whoever cared to send them.
     * An unknown selector is not counted as a failed sign-in either (it is what a pruned or
     * revoked cookie looks like), so nothing else would have bounded it. The re-check inside the
     * lock is what the decision is actually made on; this only declines to do work for a selector
     * that demonstrably was not there.
     *
     * States:
     *   none    — no cookie was presented.
     *   ok      — verified; 'user' names the operator and the cookie has been replaced.
     *   stale   — the selector is unknown (pruned, revoked, or from another installation).
     *   expired — the record was found but has aged out.
     *   theft   — the selector exists and the verifier does not match. Family destroyed.
     *   store   — the store could not be read or written; the request is refused.
     *
     * @return array{state:string,user:string}
     */
    public static function consume(?string $varDir, int $lifetime): array
    {
        $raw = is_string($_COOKIE[self::COOKIE] ?? null) ? (string) $_COOKIE[self::COOKIE] : '';
        if ($raw === '') {
            return ['state' => 'none', 'user' => ''];
        }

        $parts = explode('.', $raw, 2);
        if (count($parts) !== 2
            || !preg_match('/^[a-f0-9]{32}$/D', $parts[0])
            || !preg_match('/^[a-f0-9]{64}$/D', $parts[1])
        ) {
            self::clearCookie();
            return ['state' => 'stale', 'user' => ''];
        }

        [$selector, $verifier] = $parts;

        $store = self::store($varDir);

        if (!isset($store->read()['tokens'][$selector])) {
            self::clearCookie();
            return ['state' => 'stale', 'user' => ''];
        }

        $result = $store->mutate(
            static function (array &$data) use ($selector, $verifier, $lifetime): array {
                $tokens = self::prune(is_array($data['tokens'] ?? null) ? $data['tokens'] : []);

                $found = null;
                foreach ($tokens as $key => $record) {
                    if (Security::equals((string) $key, $selector) && is_array($record)) {
                        $found = $key;
                    }
                }

                if ($found === null) {
                    $data['tokens'] = $tokens;
                    return ['state' => 'stale', 'user' => '', 'cookie' => '', 'expires' => 0];
                }

                $record = $tokens[$found];
                $owner = (string) ($record['user'] ?? '');
                $expected = (string) ($record['hash'] ?? '');

                $given = hash('sha256', $verifier);
                $recent = self::freshlySuperseded($record);

                $accepted = Security::equals($expected, $given);
                foreach ($recent as $entry) {
                    if (Security::equals((string) $entry['h'], $given)) {
                        $accepted = true;
                    }
                }

                if (!$accepted) {
                    foreach ($tokens as $key => $other) {
                        if (!is_array($other) || (string) ($other['user'] ?? '') === $owner) {
                            unset($tokens[$key]);
                        }
                    }
                    $data['tokens'] = $tokens;
                    $data['alert'] = ['at' => time()];
                    return ['state' => 'theft', 'user' => '', 'cookie' => '', 'expires' => 0];
                }

                if ((int) ($record['expires'] ?? 0) <= time()) {
                    unset($tokens[$found]);
                    $data['tokens'] = $tokens;
                    return ['state' => 'expired', 'user' => '', 'cookie' => '', 'expires' => 0];
                }

                $next = bin2hex(random_bytes(32));
                $expires = time() + $lifetime;

                $recent[] = ['h' => $expected, 't' => time()];

                $tokens[$found] = [
                    'user'    => $owner,
                    'hash'    => hash('sha256', $next),
                    'recent'  => array_slice($recent, -self::MAX_RECENT),
                    'created' => (int) ($record['created'] ?? time()),
                    'used'    => time(),
                    'expires' => $expires,
                ];

                $data['tokens'] = self::prune($tokens);

                return [
                    'state'   => 'ok',
                    'user'    => $owner,
                    'cookie'  => $found . '.' . $next,
                    'expires' => $expires,
                ];
            }
        );

        /* THE COOKIE IS CLEARED HERE TOO, AND IT WAS NOT. Every other refusal path clears it;
           this one returned first, which turned an unwritable var/ into an unbreakable loop
           the operator could not get out of without deleting the cookie by hand:
           Security::resumeRemembered maps 'store' onto the 'login' state, requireAuth
           redirects to ?login=1, and Panel\Login sees Persistence::present() — which tests
           only that the cookie string is non-empty — and redirects straight back. Round and
           round, with the sign-in form never rendered, on the one failure whose remedy is
           written on that form. */
        if (!is_array($result)) {
            self::clearCookie();
            return ['state' => 'store', 'user' => ''];
        }

        if ($result['state'] === 'ok' && $result['user'] !== '') {
            self::sendCookie((string) $result['cookie'], (int) $result['expires']);
            return ['state' => 'ok', 'user' => (string) $result['user']];
        }

        self::clearCookie();

        return ['state' => (string) $result['state'], 'user' => ''];
    }

    /**
     * Destroy every token for this installation and clear the cookie on this browser.
     *
     * There is one operator, so "every token" and "every token for that account" are the same
     * set; keeping it whole-store means a sign-out cannot leave a forgotten record behind
     * because of a username that was spelled differently.
     *
     * A store that has never been written is left alone rather than created, so revoking on
     * an installation that has never used the feature touches no disk at all.
     */
    public static function revokeAll(?string $varDir): void
    {
        self::clearCookie();

        $store = self::store($varDir);
        if (!$store->exists()) {
            return;
        }

        $store->mutate(static function (array &$data): bool {
            $data['tokens'] = [];
            return true;
        });
    }

    /**
     * Whether a theft is waiting to be reported, without clearing it.
     *
     * Separate from takeAlert() on purpose. The sign-in page is public, so if rendering it
     * cleared the flag, any crawler or probe that fetched ?login=1 would erase the warning
     * before the operator ever saw it. Rendering asks; only a completed sign-in clears.
     */
    public static function hasAlert(?string $varDir): bool
    {
        $store = self::store($varDir);
        if (!$store->exists()) {
            return false;
        }
        return isset($store->read()['alert']);
    }

    /**
     * Whether a theft was detected since the last time anyone was told, and forget it.
     *
     * Read-and-clear in one locked pass, so the warning is shown once rather than on every
     * render of the sign-in page forever.
     */
    public static function takeAlert(?string $varDir): bool
    {
        $store = self::store($varDir);
        if (!$store->exists()) {
            return false;
        }

        $seen = $store->mutate(static function (array &$data): bool {
            $had = isset($data['alert']);
            unset($data['alert']);
            return $had;
        });

        return $seen === true;
    }

    /** How many live tokens exist, for Settings to report. */
    public static function count(?string $varDir): int
    {
        $data = self::store($varDir)->read();
        $tokens = is_array($data['tokens'] ?? null) ? $data['tokens'] : [];
        return count(self::prune($tokens));
    }

    /**
     * Expire the cookie in this browser.
     *
     * $_COOKIE is cleared unconditionally, for the same reason sendCookie() sets it
     * unconditionally: within this request the token is gone either way.
     */
    public static function clearCookie(): void
    {
        unset($_COOKIE[self::COOKIE]);

        if (!headers_sent()) {
            setcookie(self::COOKIE, '', self::cookieOptions(time() - 42000));
        }
    }

    /** The token store for an installation. */
    public static function store(?string $varDir): Store
    {
        return Store::at($varDir, self::STORE);
    }

    /**
     * The hashes this record superseded inside the grace window, newest last.
     *
     * A LIST AND NOT JUST THE LAST ONE, because a burst is a burst: three tabs waking together
     * all hold the verifier from before any of them ran, and each one that is accepted rotates
     * again. Keeping only the immediately previous hash would accept the second tab and call the
     * third a thief — which is the same false alarm this window exists to remove, moved one
     * request to the right.
     *
     * Pruned by time on every pass, and capped as a backstop: a browser has tabs, not thousands
     * of them, and an unbounded list would be a way to grow the file.
     *
     * @param array<string,mixed> $record
     * @return array<int,array{h:string,t:int}>
     */
    private static function freshlySuperseded(array $record): array
    {
        $now = time();
        $out = [];

        foreach (is_array($record['recent'] ?? null) ? $record['recent'] : [] as $entry) {
            if (!is_array($entry) || !is_string($entry['h'] ?? null)) {
                continue;
            }
            $at = (int) ($entry['t'] ?? 0);
            if ($at <= 0 || ($now - $at) > self::ROTATION_GRACE) {
                continue;
            }
            $out[] = ['h' => $entry['h'], 't' => $at];
        }

        return array_slice($out, -self::MAX_RECENT);
    }

    /**
     * Drop expired records, and the oldest ones past the cap.
     *
     * Pruning can only ever forgive a token, never invent one, so doing it opportunistically
     * on every write is safe and means nothing has to sweep this file on a schedule.
     *
     * @param array<string,mixed> $tokens
     * @return array<string,mixed>
     */
    private static function prune(array $tokens): array
    {
        $now = time();
        $out = [];
        foreach ($tokens as $key => $record) {
            if (!is_string($key) || !preg_match('/^[a-f0-9]{32}$/D', $key) || !is_array($record)) {
                continue;
            }
            if ((int) ($record['expires'] ?? 0) <= $now) {
                continue;
            }
            $out[$key] = $record;
        }

        if (count($out) > self::MAX_TOKENS) {
            /* `used` is read with a default, like every other field in this class. A store
               written by an older build, hand-edited, or truncated by a full disk would
               otherwise raise an undefined-key warning INSIDE the authentication path, which
               under a warning-to-exception handler is a 500 on every request carrying the
               cookie. A record with no `used` sorts oldest, which is the safe direction. */
            uasort(
                $out,
                static fn(array $a, array $b): int => ((int) ($b['used'] ?? 0)) <=> ((int) ($a['used'] ?? 0))
            );
            $out = array_slice($out, 0, self::MAX_TOKENS, true);
        }

        return $out;
    }

    /**
     * Set the cookie with the flags this token requires.
     *
     * $_COOKIE is updated whether or not the header could go out, because it is this request's
     * view of what the current token is: after a rotation, anything later in the same request
     * that asks must be told about the replacement and not the value it superseded.
     *
     * The header itself is only sent when headers have not already gone. Both real callers run
     * before any output — Security::requireAuth() from the front controller, and Panel\Login
     * before it renders — so in the application this guard never fires; it is there because a
     * setcookie() after output is a warning in the operator's error log and nothing else.
     */
    private static function sendCookie(string $value, int $expires): void
    {
        $_COOKIE[self::COOKIE] = $value;

        if (!headers_sent()) {
            setcookie(self::COOKIE, $value, self::cookieOptions($expires));
        }
    }

    /**
     * The cookie flags, in one place so the clear and the set cannot disagree.
     *
     * HttpOnly so script cannot read it even if a cross-site scripting hole ever appeared in
     * the panel. Secure only when the request really arrived over TLS, for the same reason the
     * session cookie is conditional: marking it unconditionally on a plain-HTTP install makes
     * the browser drop it and the feature silently stop working. SameSite=Lax, for the reason
     * set out in the class docblock.
     *
     * The TLS question goes through Security::isHttps() rather than reading $_SERVER['HTTPS']
     * here. This is a ten-year bearer credential, and the expression that used to be inline
     * answered NO behind every TLS-terminating proxy — which is how this token came to be
     * issued in the clear on exactly the deployments the project documents support for.
     *
     * @param string[] $trustedProxies
     * @return array<string,mixed>
     */
    private static function cookieOptions(int $expires, array $trustedProxies = []): array
    {
        return [
            'expires'  => $expires,
            'path'     => '/',
            'domain'   => '',
            'secure'   => Security::isHttps($trustedProxies !== [] ? $trustedProxies : self::$proxies),
            'httponly' => true,
            'samesite' => 'Lax',
        ];
    }

    /**
     * The trusted-proxy list, handed down once per request so the cookie helpers can ask
     * Security::isHttps() without every call site having to carry it.
     *
     * Request-scoped and set by the front controller before anything reads a cookie. Empty
     * means "believe no forwarded header", which is the safe default: an installation that
     * has not declared its proxies gets the direct-connection answer and nothing else.
     *
     * @var string[]
     */
    private static array $proxies = [];

    /**
     * Declare which proxies this installation sits behind, for the cookie flags.
     *
     * @param string[] $cidrs
     */
    public static function trustProxies(array $cidrs): void
    {
        self::$proxies = array_values(array_filter($cidrs, 'is_string'));
    }
}
