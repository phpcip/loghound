<?php
/**
 * Loghound — two-factor authentication: enrollment, verification, recovery.
 *
 * The state and the decisions. The arithmetic is in Totp, the QR drawing in Qr, the replay
 * counter in Store; this is the part that knows what may be turned on, when, and by whom.
 *
 * ENROLLMENT IS TWO-PHASE ON PURPOSE. begin() mints a secret and hands it back; nothing is
 * stored. enable() only writes it once the operator has proved they can produce a current code
 * from it. A one-phase flow — store the secret, then ask for a code — locks an operator out of
 * their own panel the moment they close the tab with the QR code still on screen, and the way
 * back in is hand-editing config/loghound.php on the server. The pending secret therefore lives
 * in the enrolling operator's session and nowhere else, and evaporates on its own.
 *
 * RECOVERY CODES ARE THE ONLY WAY BACK IN, AND ARE TREATED AS SUCH. Ten of them, shown once,
 * stored only as SHA-256 hashes. Sixteen characters from a 30-character alphabet is about 78
 * bits each, which is why a fast hash is the right hash: there is no dictionary to grind and no
 * work factor worth paying. The alphabet has no I, L, O or U in it — not for aesthetics, but
 * because these get copied onto paper and read back months later, and 1/I/l and 0/O are where
 * that goes wrong. U is out so that no code can spell a word.
 *
 * A USED RECOVERY CODE IS DELETED, NOT MARKED. A flag would have to be trusted; an absent row
 * cannot be replayed.
 *
 * TURNING IT OFF COSTS A FACTOR. Disabling requires a current code or a recovery code, never
 * just the session — otherwise stealing a session cookie is enough to strip the second factor
 * off and the factor protects nothing. The same reasoning makes enabling it destroy every
 * persistent-login token: those were issued on the strength of one factor, so they cannot
 * survive as a way past two.
 *
 * THE SECRET NEVER LEAVES THIS BOX. It is drawn locally by Qr, so no third party ever sees it;
 * it lives in config/loghound.php beside the password hash, outside the document root; it is
 * never put in a job payload, a log line or an error message, and Panel\Jobs::redact() already
 * strips anything shaped like `secret=` from what does get logged.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Auth;

use Loghound\Config;
use Loghound\Security;

final class TwoFactor
{
    /** Where the replay floor lives. Not config: it changes on every sign-in. */
    public const STORE = 'auth-state.json';

    /** Session key holding a candidate secret that has not been confirmed yet. */
    private const S_PENDING = 'lh_totp_setup';

    /** Session key holding recovery codes that are waiting to be shown once. */
    private const S_CODES = 'lh_totp_codes';

    /** How long an unconfirmed enrollment, or an uncollected set of codes, survives. */
    public const ENROLL_TTL = 900;

    /** Recovery codes issued at a time. */
    public const RECOVERY_CODES = 10;

    /** Characters in a recovery code. 16 from a 30-letter alphabet is about 78 bits. */
    public const RECOVERY_LENGTH = 16;

    /**
     * The recovery-code alphabet: no I, L, O or U.
     *
     * See the class docblock — this is a transcription-error decision, not a style one.
     */
    public const RECOVERY_ALPHABET = 'ABCDEFGHJKMNPQRSTVWXYZ23456789';

    /** Is the second factor switched on for this installation? */
    public static function isEnabled(array $auth): bool
    {
        return ($auth['totp']['enabled'] ?? false) === true
            && Totp::isValidSecret((string) ($auth['totp']['secret'] ?? ''));
    }

    /** The active secret, or '' when there is none. */
    public static function secret(array $auth): string
    {
        return (string) ($auth['totp']['secret'] ?? '');
    }

    /** How many recovery codes are left unused. */
    public static function recoveryRemaining(array $auth): int
    {
        $codes = $auth['totp']['recovery'] ?? [];
        return is_array($codes) ? count($codes) : 0;
    }

    /**
     * Start an enrollment: a fresh secret, stored nowhere.
     *
     * The caller keeps it in the enrolling session and passes it back to enable().
     */
    public static function begin(): string
    {
        return Totp::newSecret();
    }

    /**
     * Mint a candidate secret and hold it in the enrolling operator's session.
     *
     * THE SESSION IS THE ONLY PLACE IT GOES until a code confirms it. That is what makes
     * walking away mid-enrollment harmless: nothing was written, so there is nothing demanding
     * a code that no phone can produce. A quarter of an hour is long enough to find the
     * authenticator app and short enough that an abandoned attempt does not sit in a session
     * file — and that matters more than usual here, because a session that took the "stay
     * signed in" option has no timeout of its own to clean up after it.
     */
    public static function beginEnrollment(): string
    {
        $secret = self::begin();

        $_SESSION[self::S_PENDING] = ['secret' => $secret, 'at' => time()];

        return $secret;
    }

    /** The candidate secret this session is enrolling, or '' when there is none. */
    public static function pendingSecret(): string
    {
        $pending = $_SESSION[self::S_PENDING] ?? null;
        if (!is_array($pending)) {
            return '';
        }

        $secret = is_string($pending['secret'] ?? null) ? $pending['secret'] : '';
        $at = (int) ($pending['at'] ?? 0);

        if ($secret === '' || $at <= 0 || (time() - $at) > self::ENROLL_TTL) {
            self::cancelEnrollment();
            return '';
        }

        return $secret;
    }

    /** Throw away an enrollment in progress. */
    public static function cancelEnrollment(): void
    {
        unset($_SESSION[self::S_PENDING]);
    }

    /**
     * Drop a candidate secret or a set of recovery codes that has outlived ENROLL_TTL.
     *
     * WHY THIS IS NOT LEFT TO pendingSecret() AND takeCodes(). Both discard what they find to be
     * expired, but only when something asks — and an operator who starts an enrollment and never
     * comes back never asks. The entry then sits in their session for as long as the session
     * lasts, and since "stay signed in" exists, that can be forever: a session with no timeout
     * means a pending secret with no timeout, which is exactly the interaction worth closing.
     *
     * So the expiry is swept on every authenticated request instead. The session is being opened
     * and written on that request anyway, so it costs an array check and nothing else, and it
     * makes the TTL a property of the clock rather than of whether anybody happened to look.
     */
    public static function sweepEphemeral(): void
    {
        foreach ([self::S_PENDING, self::S_CODES] as $key) {
            $held = $_SESSION[$key] ?? null;
            if (!is_array($held)) {
                continue;
            }
            if ((time() - (int) ($held['at'] ?? 0)) > self::ENROLL_TTL) {
                unset($_SESSION[$key]);
            }
        }
    }

    /**
     * Hold a freshly minted set of recovery codes for exactly one render.
     *
     * There is no way round this without giving up POST/Redirect/GET: the codes exist only in
     * the request that generated them, and that request answers with a redirect so a refresh
     * cannot re-run it. They are therefore parked in the operator's own session and taken out
     * by the next render, which is also what "shown exactly once" means.
     *
     * THE PLAINTEXT IS NOT PERSISTED ANYWHERE ELSE AND DOES NOT LINGER: takeCodes() removes it,
     * and a set that is never collected expires with ENROLL_TTL. A session that took the "stay
     * signed in" option never expires on its own, so without that clock the codes would live in
     * a session file indefinitely.
     *
     * @param string[] $codes
     */
    public static function stashCodes(array $codes): void
    {
        $_SESSION[self::S_CODES] = ['codes' => array_values($codes), 'at' => time()];
    }

    /**
     * Take the codes that are waiting to be shown, and forget them.
     *
     * @return string[]
     */
    public static function takeCodes(): array
    {
        $held = $_SESSION[self::S_CODES] ?? null;
        unset($_SESSION[self::S_CODES]);

        if (!is_array($held) || !is_array($held['codes'] ?? null)) {
            return [];
        }
        if ((time() - (int) ($held['at'] ?? 0)) > self::ENROLL_TTL) {
            return [];
        }

        $out = [];
        foreach ($held['codes'] as $code) {
            if (is_string($code) && self::looksLikeRecoveryCode($code)) {
                $out[] = $code;
            }
        }
        return $out;
    }

    /**
     * Is this the exact shape mintRecoveryCodes() produces?
     *
     * Used on the way out of the session and on the way in from the download form. The download
     * form hands the codes back so they can be written into a text file without their plaintext
     * ever being stored — which means the request body decides what that file says, so it is
     * checked against the shape rather than echoed. Nothing arbitrary can be routed through it.
     */
    public static function looksLikeRecoveryCode(string $code): bool
    {
        return (bool) preg_match('/^[A-Z0-9]{4}(-[A-Z0-9]{4}){3}$/', $code)
            && strlen(self::normalise($code)) === self::RECOVERY_LENGTH;
    }

    /**
     * The otpauth URI for a candidate secret.
     *
     * The issuer is the operator's own site name, so an authenticator holding accounts for
     * several installations shows which is which. The account name is the panel username.
     */
    public static function uri(Config $cfg, string $secret): string
    {
        $issuer = trim((string) $cfg->get('site_name', 'Loghound'));
        $user = trim((string) $cfg->get('auth.user', 'admin'));
        return Totp::uri($issuer === '' ? 'Loghound' : $issuer, $user === '' ? 'admin' : $user, $secret);
    }

    /**
     * The QR code for a candidate secret, as inline SVG.
     *
     * The accessible label deliberately does NOT contain the secret: a screen reader reading
     * the shared key out loud in an open-plan office is a real disclosure, and the secret is
     * already on the page as selectable text for anyone who needs it.
     */
    public static function qr(Config $cfg, string $secret, int $moduleSize = 5): ?string
    {
        return Qr::svg(self::uri($cfg, $secret), $moduleSize, 4, 'Two-factor setup QR code');
    }

    /**
     * Switch the second factor on, given a candidate secret and a code proving it works.
     *
     * The order is: validate the secret, verify the code against it, and only then write.
     * Nothing is stored on a failed attempt, so an operator who mistypes has lost nothing but
     * the attempt — and the attempt still counts toward the lockout, because this endpoint
     * verifies a one-time code and every endpoint that does is a guessing target.
     *
     * The recovery codes are returned in plaintext ONCE, for the caller to show. They are not
     * stored in plaintext and cannot be recovered afterwards; regenerate() is the only way to
     * get a readable set again, and it invalidates the old one.
     *
     * @return array{errors:string[],codes:string[]}
     */
    public static function enable(Config $cfg, string $secret, string $code, ?string $varDir): array
    {
        if (!Totp::isValidSecret($secret)) {
            return ['errors' => ['That setup has expired. Start again to get a fresh QR code.'], 'codes' => []];
        }

        $step = self::acceptStep($secret, $code, $varDir);
        if ($step === null) {
            return [
                'errors' => ['That code was not right. Check your authenticator and enter the current code.'],
                'codes'  => [],
            ];
        }

        $codes = self::mintRecoveryCodes();

        $cfg->set('auth.totp', [
            'enabled'  => true,
            'secret'   => $secret,
            'recovery' => self::hashAll($codes),
        ]);

        Persistence::revokeAll($varDir);

        return ['errors' => [], 'codes' => $codes];
    }

    /**
     * Switch the second factor off, given a current code or a recovery code.
     *
     * @return string[] Problems; empty means it is off.
     */
    public static function disable(Config $cfg, string $code, ?string $varDir): array
    {
        $auth = (array) $cfg->get('auth', []);
        if (!self::isEnabled($auth)) {
            return [];
        }

        if (self::check($cfg, $code, $varDir) === 'no') {
            return ['That code was not right. Enter a current code, or one of your recovery codes.'];
        }

        $cfg->set('auth.totp', ['enabled' => false, 'secret' => '', 'recovery' => []]);
        Persistence::revokeAll($varDir);

        return [];
    }

    /**
     * Issue a fresh set of recovery codes, invalidating the old set.
     *
     * @return string[] The plaintext codes, to be shown once.
     */
    public static function regenerate(Config $cfg): array
    {
        $codes = self::mintRecoveryCodes();

        $totp = (array) $cfg->get('auth.totp', []);
        $totp['recovery'] = self::hashAll($codes);
        $cfg->set('auth.totp', $totp);

        return $codes;
    }

    /**
     * Check a submitted second factor: a TOTP code, or a recovery code.
     *
     * Returns 'totp', 'recovery' or 'no'. A TOTP code is tried first because it is what an
     * operator normally submits, and because a recovery code that is accepted is CONSUMED —
     * a six-digit string could never be mistaken for a sixteen-character one, but the order
     * makes the intent unambiguous.
     *
     * FAILS CLOSED. When the replay store cannot be read or written the answer is 'no': the
     * floor that stops a code being used twice is part of the check, and a check that cannot
     * be performed is a failed check.
     */
    public static function check(Config $cfg, string $code, ?string $varDir): string
    {
        $auth = (array) $cfg->get('auth', []);
        if (!self::isEnabled($auth)) {
            return 'no';
        }

        $trimmed = trim($code);

        if (preg_match('/^[0-9\s]{6,8}$/', $trimmed)) {
            if (self::acceptStep(self::secret($auth), $trimmed, $varDir) !== null) {
                return 'totp';
            }
            return 'no';
        }

        return self::consumeRecoveryCode($cfg, $trimmed) ? 'recovery' : 'no';
    }

    /**
     * Verify a TOTP code and move the replay floor, atomically.
     *
     * The read of the floor, the verification and the write of the new floor happen inside one
     * exclusive lock. Splitting them would leave a window in which two requests presenting the
     * same code both read the old floor and both succeed, which is exactly the replay the floor
     * exists to prevent.
     *
     * @return int|null The accepted step, or null when refused.
     */
    private static function acceptStep(string $secret, string $code, ?string $varDir): ?int
    {
        if (!preg_match('/^[0-9\s]{6,8}$/', trim($code))) {
            return null;
        }

        $accepted = Store::at($varDir, self::STORE)->mutate(
            static function (array &$data) use ($secret, $code): ?int {
                $last = (int) ($data['totp_last_step'] ?? 0);
                $step = Totp::verify($secret, $code, $last);
                if ($step === null) {
                    return null;
                }
                $data['totp_last_step'] = $step;
                return $step;
            }
        );

        return is_int($accepted) ? $accepted : null;
    }

    /**
     * Match a recovery code against the stored hashes and delete the one that matched.
     *
     * Every stored hash is compared even after one matches, so the time taken does not reveal
     * which code was presented or how many are left.
     */
    private static function consumeRecoveryCode(Config $cfg, string $code): bool
    {
        $normalised = self::normalise($code);
        if (strlen($normalised) !== self::RECOVERY_LENGTH) {
            return false;
        }

        $totp = (array) $cfg->get('auth.totp', []);
        $stored = is_array($totp['recovery'] ?? null) ? $totp['recovery'] : [];
        $given = hash('sha256', $normalised);

        $matched = null;
        foreach ($stored as $index => $hash) {
            if (is_string($hash) && Security::equals($hash, $given) && $matched === null) {
                $matched = $index;
            }
        }

        if ($matched === null) {
            return false;
        }

        unset($stored[$matched]);
        $totp['recovery'] = array_values($stored);
        $cfg->set('auth.totp', $totp);

        return true;
    }

    /**
     * Ten fresh recovery codes, grouped in fours for reading off a screen or a printout.
     *
     * @return string[]
     */
    public static function mintRecoveryCodes(): array
    {
        $codes = [];
        for ($n = 0; $n < self::RECOVERY_CODES; $n++) {
            $raw = '';
            for ($i = 0; $i < self::RECOVERY_LENGTH; $i++) {
                $raw .= self::RECOVERY_ALPHABET[random_int(0, strlen(self::RECOVERY_ALPHABET) - 1)];
            }
            $chunks = str_split($raw, 4);
            $codes[] = implode('-', $chunks === false ? [$raw] : $chunks);
        }
        return $codes;
    }

    /**
     * Reduce a recovery code to the form it is hashed in.
     *
     * Uppercased, with everything that is not in the alphabet removed, so the grouping dashes
     * the panel prints and any spaces or line breaks a paste brings along do not matter.
     */
    public static function normalise(string $code): string
    {
        $upper = strtoupper($code);
        $out = '';
        for ($i = 0, $n = strlen($upper); $i < $n; $i++) {
            if (strpos(self::RECOVERY_ALPHABET, $upper[$i]) !== false) {
                $out .= $upper[$i];
            }
        }
        return $out;
    }

    /**
     * The plaintext codes as stored hashes.
     *
     * @param string[] $codes
     * @return string[]
     */
    private static function hashAll(array $codes): array
    {
        $out = [];
        foreach ($codes as $code) {
            $out[] = hash('sha256', self::normalise($code));
        }
        return $out;
    }

    /**
     * The recovery codes as the plain-text file an operator downloads.
     *
     * No branding, no date beyond the one line that says when they were made, and an explicit
     * statement of what they are for: this file is the thing that gets found in a drawer in
     * two years and has to explain itself.
     *
     * @param string[] $codes
     */
    public static function recoveryFile(string $siteName, array $codes): string
    {
        $lines = [];
        $lines[] = 'Loghound two-factor recovery codes for ' . $siteName;
        $lines[] = 'Generated ' . gmdate('m/d/Y H:i:s') . ' UTC';
        $lines[] = '';
        $lines[] = 'Each code works once, in place of a code from your authenticator app.';
        $lines[] = 'They are the only way back in if you lose the phone. Keep them somewhere';
        $lines[] = 'a stranger cannot reach, and not in the same place as your password.';
        $lines[] = '';
        foreach ($codes as $code) {
            $lines[] = '  ' . $code;
        }
        $lines[] = '';
        return implode("\n", $lines);
    }
}
