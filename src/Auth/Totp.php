<?php
/**
 * Loghound — HOTP (RFC 4226) and TOTP (RFC 6238).
 *
 * The second factor, written out rather than pulled in: SPEC §2 says no Composer, and a
 * six-digit one-time password is forty lines of arithmetic that every authenticator app on
 * earth already agrees on. Correctness is not a matter of opinion here, so it is pinned
 * against the published vectors — RFC 4226 Appendix D for HOTP and RFC 6238 Appendix B for
 * TOTP — in tests/test_totp.php. Those vectors ARE the proof; a change that breaks them has
 * broken interoperability with every app the operator might be using.
 *
 * WHAT IS FIXED AND WHY
 *
 *   HMAC-SHA1, 6 digits, 30-second step. Not because they are the strongest choices but
 *   because they are the ones every app implements. SHA256 and SHA512 are in RFC 6238 and
 *   are advertised by the URI's `algorithm` parameter, and a meaningful fraction of apps
 *   ignore that parameter and try SHA1 anyway — producing codes that never match, with no
 *   diagnosis available to the operator. The security of a 30-second six-digit code rests on
 *   rate limiting, not on the hash.
 *
 *   A WINDOW OF ±1 STEP, and no more. That is 90 seconds of tolerance, which covers an
 *   unsynchronised phone clock and a slow typist. A wider window multiplies the number of
 *   codes valid at any instant, which is exactly the quantity a brute-force attempt is
 *   working against.
 *
 * REPLAY IS PREVENTED BY THE CALLER'S STORED COUNTER, NOT BY TIME. verify() takes the last
 * step that was ever accepted and refuses anything at or below it, then returns the step it
 * accepted so the caller can persist it. A code is therefore good exactly once: an attacker
 * who reads one over the operator's shoulder, or off a phishing page, has 30 seconds of
 * nothing. Without this, the ±1 window alone leaves a code replayable for a minute and a
 * half.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Auth;

use Loghound\Security;

final class Totp
{
    /** Seconds per step. RFC 6238's default and the only value any app assumes. */
    public const PERIOD = 30;

    /** Digits in a code. */
    public const DIGITS = 6;

    /** The HMAC used. SHA1 for interoperability; see the class docblock. */
    public const ALGORITHM = 'sha1';

    /** Steps either side of the current one that are accepted, for clock drift. */
    public const WINDOW = 1;

    /** Bytes of entropy in a generated secret. 20 = one SHA-1 block, and RFC 4226's minimum. */
    public const SECRET_BYTES = 20;

    /**
     * Mint a fresh shared secret, Base32 encoded.
     *
     * 160 bits from random_bytes(). RFC 4226 §4 requires at least 128 and recommends 160.
     */
    public static function newSecret(): string
    {
        return Base32::encode(random_bytes(self::SECRET_BYTES));
    }

    /**
     * Is this a secret we would accept — correct alphabet, and enough of it?
     *
     * Called before a secret is ever stored and before it is used, so a hand-edited config
     * cannot put a one-character secret behind the second factor and have it silently work.
     */
    public static function isValidSecret(string $secret): bool
    {
        $raw = Base32::decode($secret);
        return $raw !== null && strlen($raw) >= 16;
    }

    /**
     * The `otpauth://totp/` URI an authenticator app scans.
     *
     * The shape is Google's de-facto standard, which every app follows: the label is
     * `Issuer:Account`, both halves percent-encoded, and `issuer` is repeated as a query
     * parameter because older apps read one and newer apps read the other. Every parameter
     * is spelled out rather than left to a default, so an app that does read them cannot
     * disagree with what verify() computes.
     *
     * Percent-encoding is rawurlencode(), not urlencode(): a space in a site name must
     * become %20 and not '+', which is only meaningful in a form body and is taken
     * literally here.
     */
    public static function uri(string $issuer, string $account, string $secret): string
    {
        $label = rawurlencode($issuer) . ':' . rawurlencode($account);

        $params = [
            'secret'    => $secret,
            'issuer'    => $issuer,
            'algorithm' => strtoupper(self::ALGORITHM),
            'digits'    => (string) self::DIGITS,
            'period'    => (string) self::PERIOD,
        ];

        $query = [];
        foreach ($params as $key => $value) {
            $query[] = $key . '=' . rawurlencode($value);
        }

        return 'otpauth://totp/' . $label . '?' . implode('&', $query);
    }

    /**
     * Which 30-second step a moment in time falls in.
     */
    public static function step(?int $timestamp = null, int $period = self::PERIOD): int
    {
        return intdiv($timestamp ?? time(), max(1, $period));
    }

    /**
     * HOTP: the code for a counter value, RFC 4226 §5.
     *
     * The counter is packed as a 64-bit big-endian integer, HMAC'd with the raw secret, and
     * the low four bits of the last byte select where in the digest to read a 31-bit integer
     * from. That truncation is the whole of "dynamic truncation" and its only purpose is to
     * avoid a fixed window that an attacker could attack in isolation.
     *
     * @param string $rawSecret The DECODED secret bytes, not the Base32 text.
     */
    public static function hotp(string $rawSecret, int $counter, int $digits = self::DIGITS): string
    {
        $digest = hash_hmac(self::ALGORITHM, self::packCounter($counter), $rawSecret, true);

        $offset = ord($digest[strlen($digest) - 1]) & 0x0F;
        $binary = ((ord($digest[$offset]) & 0x7F) << 24)
            | ((ord($digest[$offset + 1]) & 0xFF) << 16)
            | ((ord($digest[$offset + 2]) & 0xFF) << 8)
            | (ord($digest[$offset + 3]) & 0xFF);

        $digits = max(1, min(10, $digits));
        $code = $binary % (10 ** $digits);

        return str_pad((string) $code, $digits, '0', STR_PAD_LEFT);
    }

    /**
     * TOTP: the code for a moment in time.
     *
     * @param string $secret Base32 secret as stored.
     */
    public static function at(
        string $secret,
        ?int $timestamp = null,
        int $period = self::PERIOD,
        int $digits = self::DIGITS
    ): ?string {
        $raw = Base32::decode($secret);
        if ($raw === null || $raw === '') {
            return null;
        }
        return self::hotp($raw, self::step($timestamp, $period), $digits);
    }

    /**
     * Verify a submitted code, with replay refused, and report which step was accepted.
     *
     * Returns the accepted step so the caller can store it as the new floor. Null means
     * refused, and it means refused for every reason alike — a wrong code, a code from a
     * step already used, a malformed secret — because the operator gains nothing from being
     * told which, and an attacker would.
     *
     * The candidate steps are walked from oldest to newest and compared in constant time
     * through Security::equals(). Every candidate is compared even after one matches, so the
     * time taken does not reveal how far off the submitted code was; the matched step is
     * remembered rather than returned early.
     *
     * @param int $lastStep The highest step ever accepted for this secret; 0 when none.
     */
    public static function verify(
        string $secret,
        string $code,
        int $lastStep = 0,
        ?int $timestamp = null,
        int $window = self::WINDOW
    ): ?int {
        $code = preg_replace('/[^0-9]/', '', $code) ?? '';
        if (strlen($code) !== self::DIGITS) {
            return null;
        }

        $raw = Base32::decode($secret);
        if ($raw === null || strlen($raw) < 16) {
            return null;
        }

        $now = self::step($timestamp);
        $window = max(0, min(10, $window));
        $accepted = null;

        for ($offset = -$window; $offset <= $window; $offset++) {
            $candidate = $now + $offset;
            if ($candidate <= $lastStep || $candidate < 0) {
                continue;
            }
            if (Security::equals(self::hotp($raw, $candidate), $code) && $accepted === null) {
                $accepted = $candidate;
            }
        }

        return $accepted;
    }

    /**
     * Pack a counter as eight big-endian bytes.
     *
     * Written by hand rather than with pack('J') so it behaves identically on a 32-bit
     * build, where 'J' is unavailable and a 64-bit int does not exist.
     */
    private static function packCounter(int $counter): string
    {
        $out = '';
        for ($shift = 56; $shift >= 0; $shift -= 8) {
            $out .= chr(($counter >> $shift) & 0xFF);
        }
        return $out;
    }
}
