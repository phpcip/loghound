<?php
/**
 * Loghound — tests for the Settings actions behind two-factor and "stay signed in".
 *
 * The enrollment RULES are pinned in tests/test_totp.php and the sign-in flow in
 * tests/test_auth.php. What is asserted here is the panel's half: that each action writes what
 * it should and nothing else, that a failure leaves the configuration exactly as it was, and
 * that the two paths which can strip a factor cannot be reached with a session alone.
 *
 * Settings::post() is driven directly. It is reached only on POST and the front controller has
 * already enforced CSRF by then, which is asserted where it belongs — in the front controller's
 * own tests — rather than re-implemented here.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Auth\Persistence;
use Loghound\Auth\Totp;
use Loghound\Auth\TwoFactor;
use Loghound\Config;
use Loghound\Panel\Gateway;
use Loghound\Panel\Settings;
use Loghound\Security;

/**
 * A Settings view over a throwaway installation.
 *
 * @return array{0:Settings,1:Config,2:string} view, config, installation root
 */
function lh_set_view(): array
{
    $root = lh_tmpdir('lhset');
    mkdir($root . '/config', 0700, true);

    $cfg = Config::load($root . '/config/loghound.php');
    $cfg->set('solr.base_url', 'http://127.0.0.1:65535/solr');
    $cfg->set('solr.hits_core', 'h');
    $cfg->set('solr.sessions_core', 's');
    $cfg->set('auth.user', 'operator');
    $cfg->set('auth.mode', 'session');
    $cfg->set('auth.password_hash', password_hash('a-long-enough-password', PASSWORD_DEFAULT));
    $cfg->save();

    $_SESSION = [];
    $_POST = [];

    return [new Settings($cfg, Gateway::fromConfig($cfg)), $cfg, $root];
}

/** Run one settings action and return where it redirects to. */
function lh_set_post(Settings $view, array $post): string
{
    $_POST = $post + ['csrf' => lh_csrf()];
    return $view->post();
}

return [

    'starting an enrollment writes nothing to the configuration' => static function (): void {
        [$view, $cfg] = lh_set_view();
        $before = (array) $cfg->get('auth.totp');

        $to = lh_set_post($view, ['action' => 'totp_begin']);

        lh_contains($to, '#set-2fa', 'it lands on the two-factor card');
        lh_same($before, (array) $cfg->get('auth.totp'), 'NOTHING is stored by starting');
        lh_true(Totp::isValidSecret(TwoFactor::pendingSecret()), 'the candidate secret is in the session');
        lh_false(TwoFactor::isEnabled((array) $cfg->get('auth', [])), 'and two-factor is still off');
    },

    'cancelling an enrollment discards the candidate secret' => static function (): void {
        [$view, $cfg] = lh_set_view();

        lh_set_post($view, ['action' => 'totp_begin']);
        lh_true(TwoFactor::pendingSecret() !== '', 'there is something to cancel');

        $to = lh_set_post($view, ['action' => 'totp_cancel']);

        lh_contains($to, 'ok=totp_cancelled', 'it says so');
        lh_same('', TwoFactor::pendingSecret(), 'the candidate secret is gone');
        lh_false(TwoFactor::isEnabled((array) $cfg->get('auth', [])), 'and nothing was turned on');
    },

    'an enrollment that has expired is refused rather than half-applied' => static function (): void {
        [$view, $cfg] = lh_set_view();

        lh_set_post($view, ['action' => 'totp_begin']);
        $secret = TwoFactor::pendingSecret();
        $_SESSION['lh_totp_setup']['at'] = time() - (TwoFactor::ENROLL_TTL + 60);

        $to = lh_set_post($view, ['action' => 'totp_enable', 'code' => (string) Totp::at($secret)]);

        lh_contains($to, 'err=totp_expired', 'a stale setup is refused');
        lh_false(TwoFactor::isEnabled((array) $cfg->get('auth', [])), 'and nothing was turned on');
    },

    'a wrong confirmation code changes nothing at all' => static function (): void {
        [$view, $cfg] = lh_set_view();

        lh_set_post($view, ['action' => 'totp_begin']);
        $secret = TwoFactor::pendingSecret();

        $to = lh_set_post($view, ['action' => 'totp_enable', 'code' => '000000']);

        lh_contains($to, 'err=totp_bad_code', 'it says the code was wrong');
        lh_false(TwoFactor::isEnabled((array) $cfg->get('auth', [])), 'two-factor is still off');
        lh_same($secret, TwoFactor::pendingSecret(), 'and the enrollment survives, so the operator can retry');
        lh_same([], TwoFactor::takeCodes(), 'no recovery codes were minted');
    },

    'confirming with a current code turns it on and hands over the codes once'
        => static function (): void {
            [$view, $cfg, $root] = lh_set_view();

            lh_set_post($view, ['action' => 'totp_begin']);
            $secret = TwoFactor::pendingSecret();

            $to = lh_set_post($view, ['action' => 'totp_enable', 'code' => (string) Totp::at($secret)]);

            lh_contains($to, 'ok=totp_on', 'it says it is on');
            lh_true(TwoFactor::isEnabled((array) $cfg->get('auth', [])), 'and it is');
            lh_same('', TwoFactor::pendingSecret(), 'the enrollment is finished, not left open');

            $reloaded = Config::load($root . '/config/loghound.php');
            lh_true(
                TwoFactor::isEnabled((array) $reloaded->get('auth', [])),
                'and it reached disk, not just this process'
            );

            $codes = TwoFactor::takeCodes();
            lh_same(TwoFactor::RECOVERY_CODES, count($codes), 'ten codes are waiting to be shown');
            lh_same([], TwoFactor::takeCodes(), 'exactly once');
        },

    'turning it on destroys every remembered browser' => static function (): void {
        [$view, $cfg] = lh_set_view();

        Persistence::issue('operator', $cfg->varDir(), 86400);
        lh_same(1, Persistence::count($cfg->varDir()), 'a browser is remembered');

        lh_set_post($view, ['action' => 'totp_begin']);
        lh_set_post($view, [
            'action' => 'totp_enable',
            'code'   => (string) Totp::at(TwoFactor::pendingSecret()),
        ]);

        lh_same(
            0,
            Persistence::count($cfg->varDir()),
            'a token issued on one factor cannot survive as a way past two'
        );
    },

    'turning it off needs a code, and a session is not one' => static function (): void {
        [$view, $cfg] = lh_set_view();

        lh_set_post($view, ['action' => 'totp_begin']);
        $secret = TwoFactor::pendingSecret();
        lh_set_post($view, ['action' => 'totp_enable', 'code' => (string) Totp::at($secret, time() - 30)]);
        $codes = TwoFactor::takeCodes();

        $no = lh_set_post($view, ['action' => 'totp_disable', 'code' => '']);
        lh_contains($no, 'err=totp_bad_code', 'no code is refused');
        lh_true(TwoFactor::isEnabled((array) $cfg->get('auth', [])), 'and it stays on');

        $wrong = lh_set_post($view, ['action' => 'totp_disable', 'code' => '000000']);
        lh_contains($wrong, 'err=totp_bad_code', 'a wrong code is refused');
        lh_true(TwoFactor::isEnabled((array) $cfg->get('auth', [])), 'and it stays on');

        $right = lh_set_post($view, ['action' => 'totp_disable', 'code' => $codes[0]]);
        lh_contains($right, 'ok=totp_off', 'a recovery code turns it off');
        lh_false(TwoFactor::isEnabled((array) $cfg->get('auth', [])), 'and it is off');
        lh_same('', TwoFactor::secret((array) $cfg->get('auth', [])), 'with the secret gone, not just unflagged');
    },

    'regenerating is refused when there is nothing to regenerate' => static function (): void {
        [$view, $cfg] = lh_set_view();

        $to = lh_set_post($view, ['action' => 'totp_regenerate']);

        lh_contains($to, 'err=totp_off_already', 'there are no codes to reissue');
        lh_same([], TwoFactor::takeCodes(), 'and none were minted');
    },

    'regenerating replaces the set and shows the new one once' => static function (): void {
        [$view, $cfg, $root] = lh_set_view();

        lh_set_post($view, ['action' => 'totp_begin']);
        lh_set_post($view, [
            'action' => 'totp_enable',
            'code'   => (string) Totp::at(TwoFactor::pendingSecret(), time() - 30),
        ]);
        $old = TwoFactor::takeCodes();

        lh_contains(
            lh_set_post($view, ['action' => 'totp_regenerate']),
            'err=totp_bad_code',
            'ten fresh recovery codes are a standing way past the phone, so a session alone is not enough'
        );
        lh_contains(
            lh_set_post($view, ['action' => 'totp_regenerate', 'code' => '000000']),
            'err=totp_bad_code',
            'and a wrong code is no better'
        );

        $to = lh_set_post($view, [
            'action' => 'totp_regenerate',
            'code'   => (string) Totp::at(TwoFactor::secret((array) $cfg->get('auth', []))),
        ]);
        lh_contains($to, 'ok=totp_codes', 'a current code reissues them');

        $new = TwoFactor::takeCodes();
        lh_same(TwoFactor::RECOVERY_CODES, count($new), 'a full new set');
        lh_same([], array_intersect($old, $new), 'sharing nothing with the old one');

        $reloaded = Config::load($root . '/config/loghound.php');
        lh_same(
            'no',
            TwoFactor::check($reloaded, $old[0], $reloaded->varDir()),
            'and the old codes really stopped working, on disk'
        );
    },

    'starting an enrollment while it is already on is refused' => static function (): void {
        [$view, $cfg] = lh_set_view();

        lh_set_post($view, ['action' => 'totp_begin']);
        lh_set_post($view, [
            'action' => 'totp_enable',
            'code'   => (string) Totp::at(TwoFactor::pendingSecret()),
        ]);
        TwoFactor::takeCodes();

        $to = lh_set_post($view, ['action' => 'totp_begin']);

        lh_contains($to, 'err=totp_already_on', 'you cannot enrol a second phone over the first');
        lh_same('', TwoFactor::pendingSecret(), 'and no candidate secret is left lying about');
    },

    'revoking remembered browsers destroys every token' => static function (): void {
        [$view, $cfg] = lh_set_view();

        Persistence::issue('operator', $cfg->varDir(), 86400);
        Persistence::issue('operator', $cfg->varDir(), 86400);
        lh_same(2, Persistence::count($cfg->varDir()), 'two browsers are remembered');

        $to = lh_set_post($view, ['action' => 'revoke_remembered']);

        lh_contains($to, 'ok=remembered_revoked', 'it says so');
        lh_same(0, Persistence::count($cfg->varDir()), 'and none are');
    },

    'the recovery-code download only echoes things that are recovery codes'
        => static function (): void {
            lh_true(
                TwoFactor::looksLikeRecoveryCode('ABCD-EFGH-JKMN-PQRS'),
                'the shape mintRecoveryCodes produces is accepted'
            );

            foreach (TwoFactor::mintRecoveryCodes() as $code) {
                lh_true(TwoFactor::looksLikeRecoveryCode($code), 'every real code is accepted: ' . $code);
            }

            $rejected = [
                '',
                'ABCD-EFGH-JKMN',
                'ABCD-EFGH-JKMN-PQRST',
                'abcd-efgh-jkmn-pqrs',
                '<script>alert(1)</script>',
                "ABCD-EFGH-JKMN-PQRS\nContent-Type: text/html",
                '../../etc/passwd',
                'ABCD EFGH JKMN PQRS',
            ];
            foreach ($rejected as $bad) {
                lh_false(
                    TwoFactor::looksLikeRecoveryCode($bad),
                    'nothing else may be routed into a download: ' . lh_show($bad)
                );
            }
        },

    /*
     * ------------------------------------------------------------------------------------
     * Rate limiting on the panel's own factor checks.
     *
     * Six digits is a million possibilities. A code is only as strong as the number of guesses
     * allowed against it, so an endpoint inside the panel that verifies one without counting is
     * not a weaker control than the sign-in form — it is no control, and it is reachable by
     * exactly the attacker the second factor exists to stop: one holding a stolen session.
     * ------------------------------------------------------------------------------------
     */

    'turning two-factor off is rate limited, so a stolen session cannot grind the code'
        => static function (): void {
            [$view, $cfg] = lh_set_view();
            $cfg->set('auth.lockout_attempts', 3);
            $cfg->save();

            lh_set_post($view, ['action' => 'totp_begin']);
            lh_set_post($view, [
                'action' => 'totp_enable',
                'code'   => (string) Totp::at(TwoFactor::pendingSecret(), time() - 30),
            ]);
            TwoFactor::takeCodes();

            for ($i = 0; $i < 3; $i++) {
                lh_contains(
                    lh_set_post($view, ['action' => 'totp_disable', 'code' => '000000']),
                    'err=totp_bad_code',
                    'guess ' . ($i + 1) . ' is a plain refusal'
                );
            }

            lh_contains(
                lh_set_post($view, ['action' => 'totp_disable', 'code' => '000000']),
                'err=totp_locked',
                'AND THEN THE ADDRESS IS LOCKED OUT, exactly as it would be on the sign-in form'
            );

            lh_contains(
                lh_set_post($view, [
                    'action' => 'totp_disable',
                    'code'   => (string) Totp::at(TwoFactor::secret((array) $cfg->get('auth', []))),
                ]),
                'err=totp_locked',
                'even the right code is refused while locked out'
            );
            lh_true(TwoFactor::isEnabled((array) $cfg->get('auth', [])), 'and it is still on');
        },

    'the enrollment confirmation is rate limited too, so the form is not a free oracle'
        => static function (): void {
            [$view, $cfg] = lh_set_view();
            $cfg->set('auth.lockout_attempts', 2);
            $cfg->save();

            lh_set_post($view, ['action' => 'totp_begin']);

            for ($i = 0; $i < 2; $i++) {
                lh_contains(
                    lh_set_post($view, ['action' => 'totp_enable', 'code' => '000000']),
                    'err=totp_bad_code',
                    'guess ' . ($i + 1)
                );
            }

            lh_contains(
                lh_set_post($view, ['action' => 'totp_enable', 'code' => '000000']),
                'err=totp_locked',
                'the confirmation step counts on the same ledger as everything else'
            );
        },

    'the panel and the sign-in form share ONE ledger, so guesses cannot be laundered'
        => static function (): void {
            [$view, $cfg] = lh_set_view();
            $cfg->set('auth.lockout_attempts', 4);
            $cfg->save();

            lh_set_post($view, ['action' => 'totp_begin']);
            lh_set_post($view, [
                'action' => 'totp_enable',
                'code'   => (string) Totp::at(TwoFactor::pendingSecret(), time() - 30),
            ]);
            TwoFactor::takeCodes();

            $_SERVER['REMOTE_ADDR'] = '203.0.113.55';

            lh_set_post($view, ['action' => 'totp_disable', 'code' => '000000']);
            lh_set_post($view, ['action' => 'totp_regenerate', 'code' => '000000']);

            $counted = 0;
            $raw = @file_get_contents(Security::ledgerPath($cfg->varDir()));
            foreach ((array) ((json_decode((string) $raw, true) ?: [])['ips'] ?? []) as $entry) {
                $counted += (int) ($entry['n'] ?? 0);
            }

            lh_same(
                2,
                $counted,
                'a wrong code on ANY panel endpoint lands on the same per-address counter the '
                    . 'sign-in form uses, so alternating between them buys no extra guesses'
            );

            unset($_SERVER['REMOTE_ADDR']);
        },

    'a factor check whose ledger cannot be written is refused, not waved through'
        => static function (): void {
            [$view, $cfg, $root] = lh_set_view();

            lh_set_post($view, ['action' => 'totp_begin']);
            lh_set_post($view, [
                'action' => 'totp_enable',
                'code'   => (string) Totp::at(TwoFactor::pendingSecret(), time() - 30),
            ]);
            $codes = TwoFactor::takeCodes();

            lh_rmtree($root . '/var');
            file_put_contents($root . '/var', 'a file where the directory has to be');

            lh_contains(
                lh_set_post($view, ['action' => 'totp_disable', 'code' => $codes[0]]),
                'err=',
                'a check that cannot be counted is a check that has not passed'
            );
            lh_true(TwoFactor::isEnabled((array) $cfg->get('auth', [])), 'and two-factor stays on');
        },

    'an abandoned enrollment expires on the clock, not when the session ends'
        => static function (): void {
            [$view, $cfg] = lh_set_view();

            lh_set_post($view, ['action' => 'totp_begin']);
            lh_true(TwoFactor::pendingSecret() !== '', 'there is a candidate secret');

            $_SESSION['lh_totp_setup']['at'] = time() - (TwoFactor::ENROLL_TTL - 30);
            lh_true(TwoFactor::pendingSecret() !== '', 'still alive just inside the window');

            $_SESSION['lh_totp_setup']['at'] = time() - (TwoFactor::ENROLL_TTL + 1);
            lh_same('', TwoFactor::pendingSecret(), 'and gone one second past it');
            lh_no_key($_SESSION, 'lh_totp_setup', 'really gone, not merely reported as expired');
        },

    'expired enrollment state is swept even when nobody asks for it' => static function (): void {
        [$view] = lh_set_view();

        lh_set_post($view, ['action' => 'totp_begin']);
        TwoFactor::stashCodes(TwoFactor::mintRecoveryCodes());

        $_SESSION['lh_totp_setup']['at'] = time() - (TwoFactor::ENROLL_TTL + 60);
        $_SESSION['lh_totp_codes']['at'] = time() - (TwoFactor::ENROLL_TTL + 60);

        TwoFactor::sweepEphemeral();

        lh_no_key(
            $_SESSION,
            'lh_totp_setup',
            'a session that never expires — which "stay signed in" makes possible — must not mean '
                . 'a pending secret that never expires'
        );
        lh_no_key($_SESSION, 'lh_totp_codes', 'and plaintext recovery codes must not ride along either');
    },

    'a live enrollment is not swept' => static function (): void {
        [$view] = lh_set_view();

        lh_set_post($view, ['action' => 'totp_begin']);
        $secret = TwoFactor::pendingSecret();

        TwoFactor::sweepEphemeral();

        lh_same($secret, TwoFactor::pendingSecret(), 'the sweep only removes what has actually expired');
    },

    'the settings page refuses an action it does not know' => static function (): void {
        [$view] = lh_set_view();

        lh_contains(lh_set_post($view, ['action' => 'totp_whatever']), 'err=unknown_action', 'unknown action');
        lh_contains(lh_set_post($view, []), 'err=unknown_action', 'no action at all');
    },

];
