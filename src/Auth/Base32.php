<?php
/**
 * Loghound — Base32 (RFC 4648) for TOTP secrets.
 *
 * Authenticator apps exchange the shared secret as Base32, so a secret has to travel
 * through this on the way into the `otpauth://` URI and back out of whatever the operator
 * typed by hand. There is no Base32 in PHP's standard library, so it is written here and
 * pinned against the RFC 4648 §10 test vectors in tests/test_totp.php.
 *
 * Two details matter for interoperability and both are deliberate:
 *
 *   - PADDING IS OPTIONAL ON THE WAY IN AND OMITTED ON THE WAY OUT. The `secret=` parameter
 *     of an otpauth URI is conventionally unpadded, and Google Authenticator, Aegis, 1Password
 *     and FreeOTP all accept it that way. decode() accepts '=' padding anyway, because a
 *     secret pasted from somewhere else may carry it.
 *   - DECODING IS CASE-INSENSITIVE AND IGNORES SPACES. The panel prints the secret grouped
 *     in fours for anyone typing it in, so the thing they type back has spaces in it. Any
 *     character that is not in the alphabet after that is a real error and is refused rather
 *     than skipped: silently dropping an unrecognised character would turn a typo into a
 *     different, valid-looking secret.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Auth;

final class Base32
{
    /** The RFC 4648 §6 alphabet. */
    public const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Encode raw bytes as unpadded Base32.
     */
    public static function encode(string $bytes): string
    {
        if ($bytes === '') {
            return '';
        }

        $bits = '';
        $len = strlen($bytes);
        for ($i = 0; $i < $len; $i++) {
            $bits .= str_pad(decbin(ord($bytes[$i])), 8, '0', STR_PAD_LEFT);
        }

        $out = '';
        foreach (str_split($bits, 5) as $chunk) {
            $out .= self::ALPHABET[bindec(str_pad($chunk, 5, '0', STR_PAD_RIGHT))];
        }
        return $out;
    }

    /**
     * Encode raw bytes as Base32 with RFC 4648 '=' padding to a multiple of eight.
     *
     * Only the test vectors and anything that has to round-trip through a padded
     * implementation need this; the URI uses encode().
     */
    public static function encodePadded(string $bytes): string
    {
        $out = self::encode($bytes);
        $pad = (8 - (strlen($out) % 8)) % 8;
        return $out . str_repeat('=', $pad);
    }

    /**
     * Decode Base32 to raw bytes, or null when the input is not Base32.
     *
     * Null rather than an exception or a best effort: every caller is validating something
     * a human typed, and "that is not a valid secret" is an answer they need, not a crash.
     * Trailing bits that do not complete a byte are dropped, which is what the encoding's
     * own padding rules mean — but a group of leftover bits that is not all zero is a
     * malformed encoding and is refused.
     */
    public static function decode(string $text): ?string
    {
        $text = strtoupper(str_replace([' ', "\t", "\r", "\n", '-'], '', $text));
        $text = rtrim($text, '=');
        if ($text === '') {
            return '';
        }

        $bits = '';
        $len = strlen($text);
        for ($i = 0; $i < $len; $i++) {
            $index = strpos(self::ALPHABET, $text[$i]);
            if ($index === false) {
                return null;
            }
            $bits .= str_pad(decbin($index), 5, '0', STR_PAD_LEFT);
        }

        $whole = intdiv(strlen($bits), 8);
        $remainder = substr($bits, $whole * 8);
        if ($remainder !== '' && strpos($remainder, '1') !== false) {
            return null;
        }

        $out = '';
        for ($i = 0; $i < $whole; $i++) {
            $out .= chr((int) bindec(substr($bits, $i * 8, 8)));
        }
        return $out;
    }

    /**
     * Group a Base32 secret in fours for a human to read off a screen.
     *
     * Presentation only. Base32::decode() strips the spaces again, so what is displayed and
     * what an app is given are the same secret.
     */
    public static function group(string $secret, int $size = 4): string
    {
        $chunks = str_split($secret, max(1, $size));
        return implode(' ', $chunks === false ? [$secret] : $chunks);
    }
}
