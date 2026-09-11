<?php
/**
 * Loghound — the setup token.
 *
 * THE PROBLEM THIS SOLVES
 *
 * A browser installer on a fresh, empty install is a full takeover primitive. Whoever
 * reaches the URL first can point the application at a Solr they control, set the admin
 * password, and own everything that follows. Loghound is deployed by pointing a vhost at
 * public/ — which means the URL is live and world-reachable from the moment DNS resolves,
 * possibly minutes before the operator gets round to opening it.
 *
 * So the installer proves, before it accepts a single byte that will be written to the
 * configuration, that whoever is driving it has SHELL ACCESS TO THIS MACHINE. A random
 * token is written to var/install-token with mode 0600 on first contact, and the installer
 * asks the operator to paste it. Reading that file requires being the service user or root.
 * This is the same mechanism Grafana, Matomo and phpMyAdmin's setup script use, and it is
 * the only thing standing between a fresh install and the internet.
 *
 * WHAT IT DOES NOT GATE
 *
 * The status page — the requirement checks and the "here is what is missing" list — is
 * readable without the token, deliberately: an operator staring at a permission problem
 * needs to see it, and it contains no secret. Everything that WRITES is gated.
 *
 * The token file is deleted the moment setup completes.
 *
 * RATE LIMITING
 *
 * Guessing is bounded by a fixed-window counter in var/install-attempts.json. It is
 * implemented here with plain files rather than through State (SQLite) on purpose: a
 * missing ext-sqlite3 is one of the things the status page has to be able to REPORT, so
 * the screen that reports it cannot itself depend on SQLite being present.
 *
 * THE LIMIT IS PER ADDRESS, AND ONLY PER ADDRESS. There used to be a second, global budget
 * of 40 attempts per window on top of it. It bought nothing and cost availability: the
 * token is 128 bits of random, so an attacker who somehow controls forty thousand addresses
 * is no closer to guessing it than one who controls eight — but any unauthenticated
 * passer-by could spend the global budget in a couple of seconds and lock the real operator
 * out of their own installer for a quarter of an hour, over and over, while the machine sat
 * there with an unfinished config. A rate limiter that a stranger can aim at the operator
 * is a denial-of-service tool wearing a security hat, so it is gone; the per-address budget
 * is what actually bounds guessing, and the window is long enough to make sustained
 * guessing from one address pointless.
 *
 * That leaves address rotation resetting an attacker's own counter, which is the correct
 * trade: the alternative punishes the operator for the attacker's traffic, and the thing
 * standing between the installer and the internet is the entropy of the token, not this
 * ledger. Anything that cannot be measured — an unwritable var/ — still DENIES.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Setup;

use Loghound\Security;

final class Token
{
    /** File name inside var/. Named so it is obvious in a directory listing. */
    public const FILENAME = 'install-token';

    /**
     * How long a setup grant stands, in seconds.
     *
     * Half an hour: long enough to walk through three screens without being hurried, short
     * enough that a browser left open on a shared machine does not stay a way in. It is also
     * consumed on first use, so this is the ceiling and not the usual lifetime.
     */
    private const GRANT_TTL = 1800;

    /** Session key holding a setup grant. */
    private const GRANT_KEY = 'lh_setup_grant';

    /**
     * Record that THIS browser has already proved what the token exists to prove.
     *
     * THE TRAP THIS EXISTS TO CLOSE. Starting the installation over from the panel removes the
     * configuration, which makes Installer::isNeeded() true again — and the installer then asks
     * for the token in var/install-token, which needs shell access to read. An operator who
     * administers this box entirely through the browser would have destroyed their panel and
     * been locked out of the installer in the same click, with no way back that does not
     * involve SSH.
     *
     * The resolution is not to weaken the token. It is that confirming that action in an
     * AUTHENTICATED session is itself a stronger proof than reading a file: it required the
     * panel password, and a second factor where one is configured. So that proof is carried
     * forward, to that browser's session and nowhere else.
     *
     * A FRESH VISITOR IS UNAFFECTED. There is no cookie, header or URL parameter that carries
     * this; it lives in the session and only the session that pressed the button has it.
     * Anyone else reaching the installer still has to read the file.
     */
    public static function grant(): void
    {
        Security::startSession();
        $_SESSION[self::GRANT_KEY] = time();
    }

    /**
     * Spend a setup grant, if this session holds one that is still good.
     *
     * ONE-TIME AND SHORT-LIVED. It is removed whether or not it was still valid, so an expired
     * one cannot sit in a session being re-tested, and a valid one converts into the installer's
     * ordinary unlock exactly once. After that the session is unlocked on its own terms and this
     * has nothing more to say.
     */
    public static function spendGrant(): bool
    {
        Security::startSession();

        $at = $_SESSION[self::GRANT_KEY] ?? null;
        unset($_SESSION[self::GRANT_KEY]);

        return is_int($at) && $at > 0 && (time() - $at) <= self::GRANT_TTL;
    }

    /** Drop any grant this session holds, without spending it. */
    public static function revokeGrant(): void
    {
        Security::startSession();
        unset($_SESSION[self::GRANT_KEY]);
    }

    /** Attempt ledger, next to the token. */
    private const ATTEMPTS = 'install-attempts.json';

    /** Attempts allowed per window, per client address. */
    private const MAX_PER_IP = 8;

    /** Window length in seconds. An hour: long enough that guessing is hopeless. */
    private const WINDOW = 3600;

    private string $varDir;

    public function __construct(string $varDir)
    {
        $this->varDir = rtrim($varDir, '/');
    }

    /** Absolute path of the token file, for the "run this to read it" instruction. */
    public function path(): string
    {
        return $this->varDir . '/' . self::FILENAME;
    }

    /**
     * Make sure a token exists, creating one on first contact.
     *
     * Returns false when var/ cannot be written, which the caller turns into a status-page
     * failure with the chown/chmod that fixes it. It deliberately does NOT throw: a
     * permissions problem must render as a page, never as a stack trace.
     */
    public function ensure(): bool
    {
        if (is_file($this->path()) && filesize($this->path()) > 0) {
            return true;
        }
        if (!is_dir($this->varDir) && !@mkdir($this->varDir, 0750, true) && !is_dir($this->varDir)) {
            return false;
        }

        $token = bin2hex(random_bytes(16));

        /* A FRESH NAME, CHMOD'D BEFORE THE FIRST BYTE, THEN RENAMED OVER THE TARGET. The old
           shape opened the real path with 'wb' and chmod'd it afterwards — and chmod does not
           narrow a descriptor somebody already holds, so a local account spinning on open()
           during the window between fopen and chmod keeps a readable fd and reads the token the
           moment it is written. Security::writePrivateFile() does it the way Config::save()
           does: O_CREAT|O_EXCL on a name nobody can have guessed, mode set while the file is
           still empty, atomic rename. */
        if (!Security::writePrivateFile($this->path(), $token . "\n", 0600)) {
            return false;
        }

        return true;
    }

    /** Has a token been minted? */
    public function exists(): bool
    {
        return is_file($this->path());
    }

    /**
     * Verify a pasted token.
     *
     * Constant-time comparison through Security::equals, and the rate limiter is consumed
     * BEFORE the comparison so a flood of wrong guesses cannot be distinguished from a
     * flood of right ones by timing the response.
     *
     * The refusal names the file the counter actually lives in. It used to say "restart
     * PHP-FPM to clear the counter", which does nothing whatsoever — the ledger is on disk,
     * not in a worker's memory — so an operator who locked themselves out followed the
     * instruction, watched it not work, and had no idea what to do next. A remedy that does
     * not work is worse than no remedy at all.
     *
     * @return string '' on success, otherwise a human-readable refusal.
     */
    public function verify(string $given, string $clientIp): string
    {
        if (!$this->allow($clientIp)) {
            return 'Too many attempts from this address. Wait an hour, or clear the counter with: '
                . 'sudo rm ' . $this->varDir . '/' . self::ATTEMPTS;
        }
        if (!$this->exists()) {
            return 'No setup token has been created yet. Reload this page.';
        }

        $stored = (string) @file_get_contents($this->path());
        $stored = trim($stored);
        $given  = trim($given);

        if ($stored === '' || $given === '') {
            return 'That is not the setup token.';
        }
        if (!Security::equals($stored, $given)) {
            return 'That is not the setup token. Read it again with: sudo cat ' . $this->path();
        }

        /* A CORRECT TOKEN GIVES THE BUDGET BACK. allow() counts unconditionally so that the
           refusal costs the same whether the token was right or wrong — which is the timing
           property it was written for and which is preserved, because the clearing happens
           only once the comparison has already succeeded. Without it, eight CORRECT unlocks in
           an hour locked the operator out of their own installer, which is a lockout earned by
           doing nothing wrong. */
        $this->forgive($clientIp);

        return '';
    }

    /**
     * Forget this address's attempts after it proves it holds the token.
     *
     * The same rule Security::loginSuccess() follows for the panel: a counter that only ever
     * goes up turns a successful credential into a lockout.
     */
    private function forgive(string $clientIp): void
    {
        $file = $this->varDir . '/' . self::ATTEMPTS;
        $fh = @fopen($file, 'c+');
        if ($fh === false) {
            return;
        }
        if (!flock($fh, LOCK_EX)) {
            fclose($fh);
            return;
        }

        $data = json_decode((string) stream_get_contents($fh), true);
        if (is_array($data) && is_array($data['ips'] ?? null)) {
            unset($data['ips'][$clientIp === '' ? 'unknown' : hash('sha256', $clientIp)]);
            ftruncate($fh, 0);
            rewind($fh);
            fwrite($fh, (string) json_encode($data));
            fflush($fh);
        }

        flock($fh, LOCK_UN);
        fclose($fh);
    }

    /**
     * Remove the token once setup is finished.
     *
     * Best effort: if the unlink fails the installer is already unreachable (the config is
     * complete and valid), so a leftover file is untidy rather than dangerous. It is still
     * worth trying, because the file is a credential and credentials should not outlive
     * their purpose.
     */
    public function destroy(): void
    {
        @unlink($this->path());
        @unlink($this->varDir . '/' . self::ATTEMPTS);
    }

    /**
     * Consume one attempt for this address, returning false when its budget is exhausted.
     *
     * Fixed window rather than a token bucket: the numbers here are small and human-scaled
     * ("eight tries in an hour"), and a fixed window is trivially auditable.
     *
     * Only the calling address is ever consulted, so no amount of traffic from anywhere else
     * can refuse the operator — see the class docblock for why the global budget that used
     * to sit here was removed. The map of addresses is pruned when it grows, which can drop
     * an attacker's own row and hand them a fresh eight; that is deliberate, and preferable
     * to an unbounded file that a stranger can grow at will.
     *
     * A ledger that cannot be parsed — truncated by a crash mid-write, or simply not the
     * shape this method wrote — is treated exactly like an expired window and started over,
     * rather than being indexed into and turning a corrupt file into a fatal error on the
     * one screen that has to keep rendering when things are broken.
     */
    private function allow(string $clientIp): bool
    {
        $file = $this->varDir . '/' . self::ATTEMPTS;
        $now  = time();

        $fh = @fopen($file, 'c+');
        if ($fh === false) {
            return false;
        }
        @chmod($file, 0600);

        if (!flock($fh, LOCK_EX)) {
            fclose($fh);
            return false;
        }

        $raw = (string) stream_get_contents($fh);
        $data = json_decode($raw, true);
        if (!is_array($data)
            || !is_array($data['ips'] ?? null)
            || (int) ($data['window'] ?? 0) + self::WINDOW < $now
        ) {
            $data = ['window' => $now, 'ips' => []];
        }

        $key = $clientIp === '' ? 'unknown' : hash('sha256', $clientIp);
        $perIp = (int) ($data['ips'][$key] ?? 0);

        $allowed = $perIp < self::MAX_PER_IP;

        $data['ips'][$key] = $perIp + 1;
        if (count($data['ips']) > 500) {
            $data['ips'] = array_slice($data['ips'], -200, null, true);
        }

        ftruncate($fh, 0);
        rewind($fh);
        fwrite($fh, (string) json_encode($data));
        fflush($fh);
        flock($fh, LOCK_UN);
        fclose($fh);

        return $allowed;
    }
}
