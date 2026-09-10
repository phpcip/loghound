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

    /** Attempt ledger, next to the token. */
    private const ATTEMPTS = 'install-attempts.json';

    /** Attempts allowed per window, per client address. */
    private const MAX_PER_IP = 8;

    /** Attempts allowed per window in total, so rotating addresses does not help. */
    private const MAX_TOTAL = 40;

    /** Window length in seconds. */
    private const WINDOW = 900;

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

        $fh = @fopen($this->path(), 'wb');
        if ($fh === false) {
            return false;
        }
        @chmod($this->path(), 0600);
        fwrite($fh, $token . "\n");
        fclose($fh);

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
     * @return string '' on success, otherwise a human-readable refusal.
     */
    public function verify(string $given, string $clientIp): string
    {
        if (!$this->allow($clientIp)) {
            return 'Too many attempts. Wait 15 minutes, or restart PHP-FPM to clear the counter.';
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
        return '';
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
     * Consume one attempt, returning false when the budget is exhausted.
     *
     * Fixed window rather than a token bucket: the numbers here are small and human-scaled
     * ("eight tries in a quarter of an hour"), and a fixed window is trivially auditable.
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
        if (!is_array($data) || (int) ($data['window'] ?? 0) + self::WINDOW < $now) {
            $data = ['window' => $now, 'total' => 0, 'ips' => []];
        }

        $key = $clientIp === '' ? 'unknown' : hash('sha256', $clientIp);
        $perIp = (int) ($data['ips'][$key] ?? 0);
        $total = (int) ($data['total'] ?? 0);

        $allowed = $perIp < self::MAX_PER_IP && $total < self::MAX_TOTAL;

        $data['ips'][$key] = $perIp + 1;
        $data['total'] = $total + 1;
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
