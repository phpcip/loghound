<?php
/**
 * Loghound — the small locked JSON stores that authentication state lives in.
 *
 * Two things in this namespace have to remember something across requests that is NOT
 * configuration: the persistent-login tokens, and the last TOTP step that was accepted.
 * Neither belongs in config/loghound.php — one changes on every sign-in and the other on
 * every second factor, and rewriting the file that holds the Opensolr API key and the
 * beacon secret on a schedule set by whoever is hitting the login form is a bad trade.
 *
 * WHY A FILE AND NOT SQLITE. The same reason Security::LOGIN_LEDGER is a file: the login
 * path has to keep working on an installation whose ext-sqlite3 is missing or whose state
 * database is being rebuilt. An authentication control that depends on a component the
 * panel is meant to REPORT on is a control that disappears exactly when it matters.
 *
 * WHY 0600 AND NOT 0640. config/loghound.php is 0640 because the ingest daemon reads it.
 * Nothing but the panel reads these, and one of them is a set of bearer tokens, so the
 * group bit is not earned.
 *
 * WHY BOTH A LOCK AND A RENAME. The lock is held on a sibling `.lock` file so that a
 * read-modify-write cannot interleave with another request's — token rotation is exactly
 * that shape, and two requests rotating the same token concurrently must not both succeed.
 * The rename is what makes the replacement atomic, so a reader (or a crash) never sees half
 * a JSON document. Setup\Job and Config both write this way; the lock is the part this adds.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Auth;

final class Store
{
    private string $path;

    /**
     * @param string $path Absolute path to the JSON file; its directory is created on write.
     */
    public function __construct(string $path)
    {
        $this->path = $path;
    }

    /**
     * A store by name inside an installation's var/ directory.
     */
    public static function at(?string $varDir, string $name): self
    {
        $dir = ($varDir !== null && $varDir !== '') ? rtrim($varDir, '/') : dirname(__DIR__, 2) . '/var';
        return new self($dir . '/' . $name);
    }

    /** The file this store is kept in. */
    public function path(): string
    {
        return $this->path;
    }

    /** Whether anything has ever been written. Lets a revoke-everything call stay a no-op. */
    public function exists(): bool
    {
        return is_file($this->path);
    }

    /**
     * Read the store.
     *
     * A missing, unreadable or corrupt file reads as an empty array rather than throwing:
     * for both callers "nothing recorded" is a valid and safe state — no persistent token
     * exists, and no TOTP step has been accepted yet, which is the most conservative
     * starting point in each case. Taken under a shared lock so a concurrent mutate()
     * cannot be observed halfway.
     *
     * @return array<string,mixed>
     */
    public function read(): array
    {
        if (!is_file($this->path)) {
            return [];
        }
        $lock = @fopen($this->lockPath(), 'c');
        if ($lock !== false) {
            @chmod($this->lockPath(), 0600);
            @flock($lock, LOCK_SH);
        }
        $raw = @file_get_contents($this->path);
        if ($lock !== false) {
            @flock($lock, LOCK_UN);
            fclose($lock);
        }
        $data = is_string($raw) ? json_decode($raw, true) : null;
        return is_array($data) ? $data : [];
    }

    /**
     * Read, hand the array to $fn, and write back whatever $fn leaves in it.
     *
     * The callback receives the store by reference and may return any value, which is
     * returned to the caller — that is how a token rotation both mutates the store and
     * reports the new cookie in one locked pass.
     *
     * Returns null WITHOUT calling $fn when the store cannot be locked or written. Callers
     * must treat that as a refusal: this is an authentication store, and a write that
     * cannot be performed is a failed write, never a skipped one.
     *
     * @param callable(array<string,mixed>&):mixed $fn
     * @return mixed|null
     */
    public function mutate(callable $fn)
    {
        $dir = dirname($this->path);
        if (!is_dir($dir) && !@mkdir($dir, 0750, true) && !is_dir($dir)) {
            return null;
        }

        $lock = @fopen($this->lockPath(), 'c');
        if ($lock === false) {
            return null;
        }
        @chmod($this->lockPath(), 0600);
        if (!flock($lock, LOCK_EX)) {
            fclose($lock);
            return null;
        }

        $raw = @file_get_contents($this->path);
        $data = is_string($raw) ? json_decode($raw, true) : null;
        $data = is_array($data) ? $data : [];

        $result = $fn($data);

        $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($json === false) {
            flock($lock, LOCK_UN);
            fclose($lock);
            return null;
        }

        $tmp = $dir . '/.' . basename($this->path) . '.' . bin2hex(random_bytes(6)) . '.tmp';
        $fh = @fopen($tmp, 'xb');
        if ($fh === false) {
            flock($lock, LOCK_UN);
            fclose($lock);
            return null;
        }
        @chmod($tmp, 0600);
        $written = fwrite($fh, $json);
        fflush($fh);
        fclose($fh);

        if ($written === false || $written !== strlen($json) || !@rename($tmp, $this->path)) {
            @unlink($tmp);
            flock($lock, LOCK_UN);
            fclose($lock);
            return null;
        }
        @chmod($this->path, 0600);

        flock($lock, LOCK_UN);
        fclose($lock);

        return $result;
    }

    /** The sibling file the exclusive lock is taken on. */
    private function lockPath(): string
    {
        return $this->path . '.lock';
    }
}
