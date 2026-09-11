<?php
/**
 * Loghound — putting an installation back to the state the installer expects.
 *
 * WHAT REINSTALL IS, AND WHAT IT IS NOT. It returns this MACHINE to the beginning of setup:
 * the panel account, the log sources and the index names go, and the operator walks the three
 * screens again. It is not an uninstall. It does not delete an Opensolr index, it does not
 * touch a document, and it does not remove a single line from a log file. `install/uninstall.sh`
 * is the thing that removes data, it proves ownership before it deletes an index, and pointing
 * at it is the honest answer for an operator who wants the data gone as well.
 *
 * WHAT SURVIVES ON PURPOSE, because each one costs something to throw away:
 *
 *   - THE TWO INDEXES AND EVERYTHING IN THEM. They are the history. A reinstall that emptied
 *     them would be an uninstall wearing a friendlier word.
 *   - THE OPENSOLR CREDENTIALS. They describe an account, not an installation, and keeping
 *     them means the storage step can immediately offer the pairs that account already holds —
 *     which is how a reinstall lands back on the same data. Changing account is a different
 *     action, and it has its own card.
 *   - THE BEACON SIGNING KEY AND THE ADDRESS SALT. Rotating the beacon key would invalidate
 *     every token already issued to a live visitor's browser, and the scorer reads an invalid
 *     token as evidence of a bot — so a reinstall would manufacture a wave of false verdicts
 *     out of honest traffic. Rotating the address salt would break the continuity of every
 *     hashed address already indexed, so the same visitor would stop matching themselves.
 *     Neither is installation state, and neither is worth that.
 *   - THE SIGN-IN RATE-LIMIT LEDGER. A reinstall must not clear somebody else's lockout.
 *
 * WHAT THE RUNNING DAEMONS DO IN THE MEANTIME, which is defined rather than lucky. `bin/loghound-tail`
 * reads its configuration once at startup and again only on SIGHUP, and a reload whose
 * configuration fails `Config::validate()` is REFUSED and logged, keeping the previous one. A
 * reset configuration fails validation by construction — it names no indexes. So a tailer that
 * is already running cannot pick up the half-reset state at all: it keeps writing to the pair it
 * started with, which still exists and still belongs to the account, and nothing is corrupted or
 * lost. If the operator then reuses that same pair, not even a request is missed.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Setup;

use Loghound\Auth\Persistence;
use Loghound\Config;

final class Reset
{
    /**
     * Runtime files that describe THIS installation's progress through its own data.
     *
     * Every one of them is a position, a cache or a staging area — nothing here is a record
     * anybody would miss, and all of it is wrong the moment the indexes behind it might change.
     * `login-attempts.json` is deliberately absent: it is a rate-limit ledger, and a reinstall
     * that cleared it would hand an attacker a way to reset their own lockout.
     */
    private const RUNTIME_FILES = [
        'state.db',
        'state.db-wal',
        'state.db-shm',
        'detect.json',
        'tail-status.json',
    ];

    /**
     * Configuration keys a reinstall clears, each with the value it goes back to.
     *
     * Read this list as the answer to "what will I have to do again": choose the log files,
     * settle the indexes, and set a username and password. Nothing else is touched, and the
     * keys that are NOT here are the ones the class docblock explains keeping.
     *
     * `solr.install_id` is cleared because it identifies this installation rather than the
     * account — it is the salt in every hit's document id, so a genuinely fresh installation
     * should get a fresh one, and reusing an existing pair mints one anyway.
     *
     * @return array<string,mixed>
     */
    public static function clearedKeys(): array
    {
        return [
            'sources'            => [],
            'solr.hits_core'     => '',
            'solr.sessions_core' => '',
            'solr.base_url'      => '',
            'solr.http_user'     => '',
            'solr.http_pass'     => '',
            'solr.install_id'    => '',
            'auth.user'          => '',
            'auth.password_hash' => '',
            'auth.mode'          => 'none',
            'auth.totp'          => ['enabled' => false, 'secret' => '', 'recovery' => []],
        ];
    }

    /**
     * Reset the installation, and report exactly what was done.
     *
     * The configuration is written through Config::save() like every other change — one write
     * path, one set of permissions, one atomic replace — so there is no moment at which the
     * file is truncated, partially written or readable by anyone new.
     *
     * ORDER MATTERS ON FAILURE. The configuration is written FIRST, and the runtime files are
     * only removed once it has landed. A reset that cleared the state database and then could
     * not write the configuration would leave a working installation that had lost its read
     * positions for no reason; this way a failed write leaves everything exactly as it was.
     *
     * Every persistent-login token is revoked, because the account they authenticate no longer
     * exists. Two-factor is switched off for the same reason: its secret belonged to an account
     * that has been removed, and leaving it enabled would demand a code for an identity nobody
     * holds.
     *
     * @return array{ok:bool,error:string,removed:string[]}
     */
    public static function perform(Config $cfg): array
    {
        foreach (self::clearedKeys() as $key => $value) {
            $cfg->set($key, $value);
        }

        try {
            $cfg->save();
        } catch (\Throwable $e) {
            return ['ok' => false, 'error' => $e->getMessage(), 'removed' => []];
        }

        if (function_exists('opcache_invalidate')) {
            @opcache_invalidate($cfg->path(), true);
        }

        $varDir = rtrim($cfg->varDir(), '/');

        Persistence::revokeAll($varDir);

        $removed = [];
        foreach (self::RUNTIME_FILES as $name) {
            $path = $varDir . '/' . $name;
            if (is_file($path) && @unlink($path)) {
                $removed[] = $name;
            }
        }

        foreach ((glob($varDir . '/setup/*') ?: []) as $stale) {
            if (is_file($stale)) {
                @unlink($stale);
            }
        }

        return ['ok' => true, 'error' => '', 'removed' => $removed];
    }

    /**
     * Exactly what pressing the button does, in specifics rather than a warning.
     *
     * Nobody should press this and then discover what it meant, so each line names a real thing
     * and says what becomes of it. The list is shared by the panel and by anything else that has
     * to describe the same action, which is what stops one of them from being reassuring and the
     * other accurate.
     *
     * @return array<int,array{what:string,happens:string}>
     */
    public static function consequences(): array
    {
        return [
            [
                'what'    => 'Your Opensolr indexes, and everything in them',
                'happens' => 'Untouched. Not a document is deleted, and the two indexes stay on your '
                    . 'account exactly as they are. Setup will offer them back to you as a pair you '
                    . 'can rejoin, so a reinstall can land on the same history it started with. To '
                    . 'delete the data as well, run install/uninstall.sh, which proves the account '
                    . 'owns an index before it removes it.',
            ],
            [
                'what'    => 'Your access log files',
                'happens' => 'Untouched. Loghound never writes to them, and a reinstall does not '
                    . 'change that.',
            ],
            [
                'what'    => 'The sign-in',
                'happens' => 'Removed. The username, the password and two-factor all go, and every '
                    . 'browser that was staying signed in is signed out — including this one. You '
                    . 'will set a new username and password at the end of setup.',
            ],
            [
                'what'    => 'The chosen log files',
                'happens' => 'Forgotten. Setup scans for them again and asks you to confirm the '
                    . 'format, the same as on a first install.',
            ],
            [
                'what'    => 'The index names and their connection details',
                'happens' => 'Forgotten by this machine. Nothing is deleted at Opensolr; the panel '
                    . 'simply stops pointing at them until setup names a pair again.',
            ],
            [
                'what'    => 'The sessions database (var/state.db)',
                'happens' => 'Deleted. That is the tailer\'s read position in every log file, the '
                    . 'sessions still open, the beacon rows not yet merged, and the enrichment '
                    . 'caches. After the reinstall each log is read from its END again, so the gap '
                    . 'is not backfilled, and sessions in flight are lost. Everything already '
                    . 'indexed is unaffected.',
            ],
            [
                'what'    => 'The Opensolr account details',
                'happens' => 'Kept. The email, the API key and the region stay, so setup can show '
                    . 'you the indexes that account already holds instead of asking for the key '
                    . 'again. Change the account in the Solr card above if that is what you want.',
            ],
            [
                'what'    => 'The beacon signing key and the address salt',
                'happens' => 'Kept, deliberately. A new signing key would make every token already '
                    . 'in a visitor\'s browser invalid, and the scorer reads an invalid token as '
                    . 'evidence of a bot — so rotating it would turn honest traffic into false '
                    . 'verdicts. A new address salt would stop hashed visitors matching themselves '
                    . 'across the reinstall.',
            ],
            [
                'what'    => 'The service and the timers',
                'happens' => 'Left running and still enabled at boot. The reader keeps the '
                    . 'configuration it started with — a reload onto a half-finished one is refused '
                    . 'and logged — so it carries on writing to the indexes it already had, and '
                    . 'nothing is corrupted. Stop them first if you want a clean break.',
            ],
        ];
    }

    /**
     * The one line that stops ingestion for the duration, for an operator who wants to.
     *
     * Offered rather than done. Loghound runs no processes and executes no shell — a published
     * property worth more than the convenience — so this is a command the operator pastes, and
     * it is the same unit list the rest of the product names.
     */
    public static function stopCommand(): string
    {
        return 'sudo systemctl stop loghound-tail.service loghound-score.timer loghound-retention.timer';
    }
}
