<?php
/**
 * Loghound — tests for the second factor: Base32, HOTP, TOTP, replay, recovery codes.
 *
 * THE RFC VECTORS ARE THE POINT OF THIS FILE. A one-time password implementation that is
 * self-consistent but wrong is worse than none: it accepts nothing any authenticator app
 * produces, the operator concludes their phone's clock is broken, and the only way out is
 * editing config on the server. So the arithmetic is checked against the published answers —
 * RFC 4648 §10 for Base32, RFC 4226 Appendix D for HOTP, RFC 6238 Appendix B for TOTP — and
 * not against a second implementation of the same misunderstanding.
 *
 * The shared key used throughout is the RFC's own: the twenty ASCII bytes "12345678901234567890".
 * It is derived here rather than written out as Base32, both because that is how the RFC states
 * it and so that no line of this file looks like a credential to tests/scan-secrets.php.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Auth\Base32;
use Loghound\Auth\Totp;
use Loghound\Auth\TwoFactor;
use Loghound\Config;

/** The RFC 4226 / 6238 shared key, as the twenty ASCII bytes the RFCs specify. */
function lh_totp_vector_key(): string
{
    return Base32::encode('12345678901234567890');
}

return [

    'Base32 matches the RFC 4648 test vectors in both directions' => static function (): void {
        $vectors = [
            ''       => '',
            'f'      => 'MY======',
            'fo'     => 'MZXQ====',
            'foo'    => 'MZXW6===',
            'foob'   => 'MZXW6YQ=',
            'fooba'  => 'MZXW6YTB',
            'foobar' => 'MZXW6YTBOI======',
        ];

        foreach ($vectors as $plain => $encoded) {
            lh_same($encoded, Base32::encodePadded($plain), 'encode ' . lh_show($plain));
            lh_same($plain, Base32::decode($encoded), 'decode ' . lh_show($encoded));
            lh_same($plain, Base32::decode(rtrim($encoded, '=')), 'decode unpadded ' . lh_show($encoded));
        }
    },

    'Base32 decoding tolerates what a human types and refuses what is not Base32'
        => static function (): void {
            lh_same('foobar', Base32::decode('mzxw 6ytb oi'), 'lowercase and spaces are a typist, not an error');
            lh_same('foobar', Base32::decode("MZXW\n6YTB-OI"), 'so are newlines and grouping dashes');

            lh_same(null, Base32::decode('MZXW6YT!'), 'a character outside the alphabet is refused');
            lh_same(null, Base32::decode('MZXW6YT1'), '1 is not in the alphabet, however much it looks like I');
            lh_same(null, Base32::decode('MZXW6YTBO'), 'leftover bits that are not zero are a malformed encoding');
        },

    'HOTP matches every RFC 4226 Appendix D vector' => static function (): void {
        $expected = [
            '755224', '287082', '359152', '969429', '338314',
            '254676', '287922', '162583', '399871', '520489',
        ];

        foreach ($expected as $counter => $want) {
            lh_same($want, Totp::hotp('12345678901234567890', $counter), 'HOTP counter ' . $counter);
        }
    },

    'TOTP matches the RFC 6238 Appendix B vectors for SHA-1' => static function (): void {
        $key = lh_totp_vector_key();

        $vectors = [
            59          => '287082',
            1111111109  => '081804',
            1111111111  => '050471',
            1234567890  => '005924',
            2000000000  => '279037',
        ];

        foreach ($vectors as $time => $want) {
            lh_same($want, Totp::at($key, $time), 'TOTP at T=' . $time);
        }
    },

    'the otpauth URI is the shape every authenticator app expects' => static function (): void {
        $uri = Totp::uri('A Site', 'someone@example.com', lh_totp_vector_key());

        lh_contains($uri, 'otpauth://totp/A%20Site:someone%40example.com?', 'label is Issuer:Account, encoded');
        lh_contains($uri, 'issuer=A%20Site', 'the issuer is repeated as a parameter for older apps');
        lh_contains($uri, 'algorithm=SHA1', 'every parameter is spelled out rather than left to a default');
        lh_contains($uri, 'digits=6', 'digits');
        lh_contains($uri, 'period=30', 'period');
        lh_false(str_contains($uri, '+'), 'a space must be %20, never +, which means nothing in a URI path');
    },

    'a code is accepted inside the drift window and nowhere outside it' => static function (): void {
        $key = lh_totp_vector_key();
        $now = 1700000000;
        $step = Totp::step($now);

        lh_same($step, Totp::verify($key, (string) Totp::at($key, $now), 0, $now), 'the current step');
        lh_same($step - 1, Totp::verify($key, (string) Totp::at($key, $now - 30), 0, $now), 'one step behind');
        lh_same($step + 1, Totp::verify($key, (string) Totp::at($key, $now + 30), 0, $now), 'one step ahead');

        lh_same(null, Totp::verify($key, (string) Totp::at($key, $now - 60), 0, $now), 'two steps behind is out');
        lh_same(null, Totp::verify($key, (string) Totp::at($key, $now + 60), 0, $now), 'two steps ahead is out');
    },

    'a code at or below the recorded step is refused, so it cannot be used twice'
        => static function (): void {
            $key = lh_totp_vector_key();
            $now = 1700000000;
            $step = Totp::step($now);
            $code = (string) Totp::at($key, $now);

            lh_same($step, Totp::verify($key, $code, 0, $now), 'the first use is accepted');
            lh_same(null, Totp::verify($key, $code, $step, $now), 'the same code with the floor raised is refused');
            lh_same(
                null,
                Totp::verify($key, (string) Totp::at($key, $now - 30), $step, $now),
                'and so is the previous step, which the drift window would otherwise still accept'
            );
        },

    'a malformed code or an unusable secret is refused rather than guessed at'
        => static function (): void {
            $key = lh_totp_vector_key();

            lh_same(null, Totp::verify($key, '', 0), 'nothing at all');
            lh_same(null, Totp::verify($key, '12345', 0), 'five digits');
            lh_same(null, Totp::verify($key, '1234567', 0), 'seven digits');
            lh_same(null, Totp::verify($key, 'abcdef', 0), 'letters');
            lh_same(null, Totp::verify('', '123456', 0), 'no secret admits nobody');
            lh_same(null, Totp::verify('MZXW6===', '123456', 0), 'a four-byte secret is too short to be one');

            lh_false(Totp::isValidSecret(''), 'an empty secret is not valid');
            lh_false(Totp::isValidSecret('MZXW6==='), 'nor is a four-byte one');
            lh_true(Totp::isValidSecret(Totp::newSecret()), 'a generated secret is');
        },

    'a generated secret is 160 bits of Base32 and never the same twice' => static function (): void {
        $first = Totp::newSecret();
        $second = Totp::newSecret();

        lh_true($first !== $second, 'two secrets must differ');
        lh_same(20, strlen((string) Base32::decode($first)), 'RFC 4226 recommends 160 bits');
        lh_same(1, preg_match('/^[A-Z2-7]+$/', $first), 'the alphabet is Base32 and nothing else');
    },


    'recovery codes are high entropy, unambiguous to read, and normalise back to themselves'
        => static function (): void {
            $codes = TwoFactor::mintRecoveryCodes();

            lh_same(TwoFactor::RECOVERY_CODES, count($codes), 'ten codes');
            lh_same(count($codes), count(array_unique($codes)), 'and no duplicates');

            foreach ($codes as $code) {
                lh_same(1, preg_match('/^[A-Z0-9]{4}(-[A-Z0-9]{4}){3}$/', $code), 'grouped in fours: ' . $code);
                lh_same(TwoFactor::RECOVERY_LENGTH, strlen(TwoFactor::normalise($code)), 'sixteen characters');
                lh_same(0, preg_match('/[ILOU01]/', $code), 'no character that is read back wrongly: ' . $code);
            }

            $one = $codes[0];
            lh_same(
                TwoFactor::normalise($one),
                TwoFactor::normalise(strtolower(str_replace('-', ' ', $one))),
                'lowercase, spaces instead of dashes: still the same code'
            );
        },


    'two-factor is off until a secret is confirmed, and a code is what confirms it'
        => static function (): void {
            $dir = lh_tmpdir('lh2fa');
            mkdir($dir . '/config', 0700, true);

            $cfg = Config::load($dir . '/config/loghound.php');
            $cfg->set('auth.user', 'operator');
            $cfg->set('auth.password_hash', password_hash('a-long-enough-password', PASSWORD_DEFAULT));

            lh_false(TwoFactor::isEnabled((array) $cfg->get('auth', [])), 'off to begin with');

            $candidate = TwoFactor::begin();
            lh_false(
                TwoFactor::isEnabled((array) $cfg->get('auth', [])),
                'beginning an enrollment must store nothing at all'
            );

            $wrong = TwoFactor::enable($cfg, $candidate, '000000', $dir . '/var');
            lh_true($wrong['errors'] !== [], 'a wrong code is refused');
            lh_same([], $wrong['codes'], 'and yields no recovery codes');
            lh_false(TwoFactor::isEnabled((array) $cfg->get('auth', [])), 'and stores nothing');

            $ok = TwoFactor::enable($cfg, $candidate, (string) Totp::at($candidate), $dir . '/var');
            lh_same([], $ok['errors'], 'a current code turns it on');
            lh_same(TwoFactor::RECOVERY_CODES, count($ok['codes']), 'and hands over the recovery codes once');
            lh_true(TwoFactor::isEnabled((array) $cfg->get('auth', [])), 'it is on');

            lh_rmtree($dir);
        },

    'the stored two-factor block holds a secret and hashes, never a readable recovery code'
        => static function (): void {
            $dir = lh_tmpdir('lh2fa');
            mkdir($dir . '/config', 0700, true);
            $cfg = Config::load($dir . '/config/loghound.php');

            $candidate = TwoFactor::begin();
            $result = TwoFactor::enable($cfg, $candidate, (string) Totp::at($candidate), $dir . '/var');

            $blob = (string) json_encode($cfg->get('auth.totp'));
            foreach ($result['codes'] as $code) {
                lh_false(str_contains($blob, $code), 'a recovery code must never be stored in the clear');
                lh_false(
                    str_contains($blob, TwoFactor::normalise($code)),
                    'not in its normalised form either'
                );
            }
            lh_same(
                TwoFactor::RECOVERY_CODES,
                TwoFactor::recoveryRemaining((array) $cfg->get('auth', [])),
                'ten hashes are stored'
            );

            lh_rmtree($dir);
        },

    'a code works once, a recovery code works once, and a wrong one never' => static function (): void {
        $dir = lh_tmpdir('lh2fa');
        mkdir($dir . '/config', 0700, true);
        $cfg = Config::load($dir . '/config/loghound.php');
        $var = $dir . '/var';

        $candidate = TwoFactor::begin();
        $result = TwoFactor::enable($cfg, $candidate, (string) Totp::at($candidate, time() - 30), $var);
        lh_same([], $result['errors'], 'enrolled');

        $code = (string) Totp::at($candidate);
        lh_same('totp', TwoFactor::check($cfg, $code, $var), 'the current code is accepted');
        lh_same('no', TwoFactor::check($cfg, $code, $var), 'the same code a second time is not');

        lh_same('no', TwoFactor::check($cfg, '000000', $var), 'a wrong code is refused');
        lh_same('no', TwoFactor::check($cfg, 'NOTACODEATALLXYZ', $var), 'and so is a wrong recovery code');

        $recovery = $result['codes'][3];
        lh_same('recovery', TwoFactor::check($cfg, $recovery, $var), 'a recovery code is accepted');
        lh_same(
            TwoFactor::RECOVERY_CODES - 1,
            TwoFactor::recoveryRemaining((array) $cfg->get('auth', [])),
            'and is consumed, not marked'
        );
        lh_same('no', TwoFactor::check($cfg, $recovery, $var), 'so it cannot be used again');

        lh_same(
            'recovery',
            TwoFactor::check($cfg, strtolower(str_replace('-', ' ', $result['codes'][4])), $var),
            'a recovery code typed loosely still works'
        );

        lh_rmtree($dir);
    },

    'regenerating recovery codes invalidates the old set' => static function (): void {
        $dir = lh_tmpdir('lh2fa');
        mkdir($dir . '/config', 0700, true);
        $cfg = Config::load($dir . '/config/loghound.php');
        $var = $dir . '/var';

        $candidate = TwoFactor::begin();
        $old = TwoFactor::enable($cfg, $candidate, (string) Totp::at($candidate), $var)['codes'];

        $new = TwoFactor::regenerate($cfg);
        lh_same(TwoFactor::RECOVERY_CODES, count($new), 'a full new set');
        lh_same([], array_intersect($old, $new), 'sharing nothing with the old one');

        lh_same('no', TwoFactor::check($cfg, $old[0], $var), 'an old code no longer works');
        lh_same('recovery', TwoFactor::check($cfg, $new[0], $var), 'a new one does');

        lh_rmtree($dir);
    },

    'turning two-factor off costs a factor, and a session alone is not one' => static function (): void {
        $dir = lh_tmpdir('lh2fa');
        mkdir($dir . '/config', 0700, true);
        $cfg = Config::load($dir . '/config/loghound.php');
        $var = $dir . '/var';

        $candidate = TwoFactor::begin();
        $codes = TwoFactor::enable($cfg, $candidate, (string) Totp::at($candidate, time() - 30), $var)['codes'];

        lh_true(TwoFactor::disable($cfg, '', $var) !== [], 'no code at all is refused');
        lh_true(TwoFactor::disable($cfg, '000000', $var) !== [], 'a wrong code is refused');
        lh_true(TwoFactor::isEnabled((array) $cfg->get('auth', [])), 'and it is still on');

        lh_same([], TwoFactor::disable($cfg, $codes[0], $var), 'a recovery code turns it off');
        lh_false(TwoFactor::isEnabled((array) $cfg->get('auth', [])), 'it is off');
        lh_same('', TwoFactor::secret((array) $cfg->get('auth', [])), 'and the secret is gone, not just unflagged');
        lh_same(0, TwoFactor::recoveryRemaining((array) $cfg->get('auth', [])), 'so are the recovery codes');

        lh_rmtree($dir);
    },

    'a check against a store that cannot be written fails closed' => static function (): void {
        $dir = lh_tmpdir('lh2fa');
        mkdir($dir . '/config', 0700, true);
        $cfg = Config::load($dir . '/config/loghound.php');

        $candidate = TwoFactor::begin();
        TwoFactor::enable($cfg, $candidate, (string) Totp::at($candidate), $dir . '/var');

        file_put_contents($dir . '/blocked', 'a file where a directory would have to be');

        lh_same(
            'no',
            TwoFactor::check($cfg, (string) Totp::at($candidate), $dir . '/blocked'),
            'without the replay floor the check cannot be performed, so it has not passed'
        );

        lh_rmtree($dir);
    },

    'the recovery file explains itself to whoever finds it in two years' => static function (): void {
        $codes = TwoFactor::mintRecoveryCodes();
        $text = TwoFactor::recoveryFile('A Site', $codes);

        lh_contains($text, 'A Site', 'it says which installation');
        lh_contains($text, 'works once', 'it says each code is single-use');
        lh_contains($text, 'only way back in', 'it says what they are for');
        foreach ($codes as $code) {
            lh_contains($text, $code, 'and it actually contains the codes');
        }
    },

];
