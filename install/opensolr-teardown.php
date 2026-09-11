<?php
/**
 * Loghound — deletion of the two Opensolr indexes this installation provisioned.
 *
 * Called by `install/install.sh --uninstall`. It exists as its own file rather than as a
 * `php -r` string inside the shell script because the decision it makes is the single most
 * dangerous thing either script does, and a decision that dangerous has to be readable and
 * testable on its own.
 *
 * THE PROBLEM THIS FILE SOLVES
 * ---------------------------------------------------------------------------------------
 * The credentials in config/loghound.php can delete ANY index in the operator's Opensolr
 * account, and that account is where their real search indexes live. Opensolr index names
 * are permanent and unique across the whole platform: a deleted name is gone, its data is
 * gone, and nobody — including the operator — can ever create that name again. So the only
 * acceptable behaviour is to delete exactly the two indexes this installation created, and
 * to delete nothing at all the moment that cannot be PROVEN.
 *
 * OWNERSHIP IS ESTABLISHED, NEVER ASSUMED
 * ---------------------------------------------------------------------------------------
 * Five independent gates, all of which must pass:
 *
 *   1. solr.mode is 'opensolr'. A 'custom' install points at a Solr the operator runs
 *      themselves, and this file has no business touching it.
 *   2. solr.install_id is lowercase hex. It is generated once by Config::newInstallId()
 *      and never changes; it is the identity of the pair.
 *   3. The names are DERIVED from that id by Config::coreName() — the same function that
 *      created them — not read from anywhere a person could have typed into.
 *   4. Each derived name matches /^loghound_[a-f0-9]{8}_(hits|sessions)$/, and equals the
 *      name stored in solr.hits_core / solr.sessions_core. A stored name that disagrees
 *      with the derived one means this install was repointed at an index it did not
 *      provision, and that index is somebody's data.
 *   5. Opensolr's own GET /get_index_list says the account currently holds the name.
 *
 * A CHECK THAT COULD NOT BE PERFORMED IS A FAILED CHECK. An unreachable control plane, a
 * missing API key, an unreadable config, an empty index list — every one of those is
 * reported as `unverified` and deletes nothing. There is no "probably fine" branch.
 *
 * WHAT IS NEVER ACCEPTED
 * ---------------------------------------------------------------------------------------
 * No index name is ever read from argv, from the environment, or from operator input. No
 * prefix sweep, no wildcard, no "starts with loghound_". The only names that can reach
 * Opensolr::deleteIndex() are the two this file derived and then found in the account.
 *
 * OUTPUT is line-oriented and machine-readable, because the shell script parses it:
 *
 *   STATUS  ok | custom | refuse | unverified
 *   REASON  <one line, no secrets>
 *   NAME    <index name>                (one per index in the plan)
 *   DELETED <index name>
 *   ABSENT  <index name>                (planned, but the account does not hold it)
 *   FAILED  <index name> <message>
 *
 * EXIT CODES: 0 the requested work completed, 2 usage error, 3 nothing was done because
 * ownership could not be established, 4 a deletion was attempted and failed.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Install;

use Loghound\Config;
use Loghound\Opensolr;

require_once __DIR__ . '/../src/autoload.php';

final class OpensolrTeardown
{
    /**
     * The only shape an index name this installation created can have.
     *
     * Config::coreName() builds 'loghound_' . <8 hex> . '_' . <role>, so this is that
     * function's output expressed as an acceptance test. It is applied to the DERIVED name
     * as a second lock on the same door: if coreName() ever changes shape, this refuses
     * rather than deletes.
     */
    public const NAME_RE = '/^loghound_[a-f0-9]{8}_(hits|sessions)$/';

    /** Ownership is proven and the two names are safe to act on. */
    public const OK = 'ok';

    /** The install uses its own Solr; the platform holds nothing for us to delete. */
    public const CUSTOM = 'custom';

    /** The configuration is readable but does not describe a pair we provisioned. */
    public const REFUSE = 'refuse';

    /** The check could not be performed. Treated exactly like a failed check. */
    public const UNVERIFIED = 'unverified';

    /**
     * Work out which two indexes, if any, this installation is entitled to delete.
     *
     * Derives both names from solr.install_id and then requires the stored core names to
     * agree with the derivation. The agreement test is the one that matters: install_id
     * alone would happily name a pair that this install has never written to, and the
     * stored names alone are just strings in a file anyone with write access could edit.
     * Requiring both to say the same thing means a single edited value refuses instead of
     * deleting.
     *
     * @return array{status:string,reason:string,names:string[]}
     */
    public static function plan(Config $cfg): array
    {
        $mode = (string) $cfg->get('solr.mode', '');
        if ($mode !== 'opensolr') {
            return self::verdict(
                self::CUSTOM,
                'solr.mode is ' . ($mode === '' ? 'unset' : $mode) . ', not opensolr'
            );
        }

        $installId = (string) $cfg->get('solr.install_id', '');
        if (!preg_match('/^[a-f0-9]{8}$/', $installId)) {
            return self::verdict(
                self::REFUSE,
                'solr.install_id is missing or is not an 8-character lowercase hex id'
            );
        }

        $names = [];
        foreach (['hits', 'sessions'] as $role) {
            try {
                $derived = Config::coreName($installId, $role);
            } catch (\Throwable $e) {
                return self::verdict(self::REFUSE, 'the ' . $role . ' name cannot be derived from install_id');
            }

            if (!preg_match(self::NAME_RE, $derived)) {
                return self::verdict(self::REFUSE, 'the derived ' . $role . ' name is not a Loghound index name');
            }

            $stored = (string) $cfg->get('solr.' . $role . '_core', '');
            if ($stored !== $derived) {
                return self::verdict(
                    self::REFUSE,
                    'solr.' . $role . '_core does not match the name this install_id would have created, '
                    . 'so this installation did not provision it'
                );
            }

            $names[] = $derived;
        }

        if (count(array_unique($names)) !== 2) {
            return self::verdict(self::REFUSE, 'the two index names are not distinct');
        }

        return self::verdict(self::OK, 'both names derive from solr.install_id and match the stored config', $names);
    }

    /**
     * Narrow a plan to the names the account demonstrably holds right now.
     *
     * The account listing is the last gate and the only one that is evidence rather than
     * derivation. An empty listing is NOT read as "the indexes are already gone" — it is
     * read as "the listing did not work", because a restricted API key, a control-plane
     * hiccup and an account with nothing in it are indistinguishable from here, and two of
     * those three must not lead to a delete attempt.
     *
     * @param string[] $planned The output of plan()['names'].
     * @param string[] $account Index names Opensolr::listIndexes() returned.
     * @return array{present:string[],absent:string[]}
     */
    public static function confirmOwned(array $planned, array $account): array
    {
        if ($account === []) {
            throw new \RuntimeException('The Opensolr account listing came back empty; ownership is unproven.');
        }

        $present = [];
        $absent  = [];
        foreach ($planned as $name) {
            if (!preg_match(self::NAME_RE, $name)) {
                throw new \RuntimeException('Refusing to act on a name that is not a Loghound index name.');
            }
            if (in_array($name, $account, true)) {
                $present[] = $name;
            } else {
                $absent[] = $name;
            }
        }

        return ['present' => $present, 'absent' => $absent];
    }

    /**
     * Build a verdict row.
     *
     * @param string[] $names
     * @return array{status:string,reason:string,names:string[]}
     */
    private static function verdict(string $status, string $reason, array $names = []): array
    {
        return ['status' => $status, 'reason' => $reason, 'names' => $names];
    }

    /**
     * Entry point. `--config=PATH` plus exactly one of `--plan` or `--delete`.
     *
     * `--plan` performs every local gate and, when they pass, also asks the control plane
     * for the account listing, so the operator is shown the same verdict the delete would
     * act on rather than an optimistic preview of it.
     *
     * @param string[] $args
     */
    public static function main(array $args): int
    {
        $configPath = '';
        $action     = '';

        foreach ($args as $arg) {
            if (str_starts_with($arg, '--config=')) {
                $configPath = substr($arg, 9);
            } elseif ($arg === '--plan' || $arg === '--delete') {
                if ($action !== '') {
                    return self::usage('--plan and --delete are mutually exclusive');
                }
                $action = substr($arg, 2);
            } else {
                return self::usage('unknown argument: ' . $arg);
            }
        }

        if ($configPath === '' || $action === '') {
            return self::usage('need --config=PATH and one of --plan or --delete');
        }
        if (!is_file($configPath) || !is_readable($configPath)) {
            self::emit(self::UNVERIFIED, 'the configuration file is missing or unreadable: ' . $configPath);
            return 3;
        }

        try {
            $cfg = Config::load($configPath);
        } catch (\Throwable $e) {
            self::emit(self::UNVERIFIED, 'the configuration file could not be parsed');
            return 3;
        }

        $plan = self::plan($cfg);
        if ($plan['status'] !== self::OK) {
            self::emit($plan['status'], $plan['reason'], $plan['names']);
            return $plan['status'] === self::CUSTOM ? 0 : 3;
        }

        foreach ($plan['names'] as $name) {
            self::line('NAME', $name);
        }

        $opensolr = (array) $cfg->get('opensolr', []);
        if ((string) ($opensolr['api_key'] ?? '') === '' || (string) ($opensolr['email'] ?? '') === '') {
            self::emit(self::UNVERIFIED, 'the Opensolr credentials are no longer in the configuration');
            return 3;
        }

        try {
            $api     = new Opensolr($opensolr);
            $account = $api->listIndexes();
            $owned   = self::confirmOwned($plan['names'], $account);
        } catch (\Throwable $e) {
            self::emit(self::UNVERIFIED, self::safeMessage($e));
            return 3;
        }

        self::emit(self::OK, 'the account holds ' . count($owned['present']) . ' of the two indexes');
        foreach ($owned['absent'] as $name) {
            self::line('ABSENT', $name);
        }

        if ($action === 'plan') {
            return 0;
        }

        $failed = 0;
        foreach ($owned['present'] as $name) {
            try {
                $api->deleteIndex($name);
                self::line('DELETED', $name);
            } catch (\Throwable $e) {
                self::line('FAILED', $name . ' ' . self::safeMessage($e));
                $failed++;
            }
        }

        return $failed > 0 ? 4 : 0;
    }

    /**
     * Print a status verdict.
     *
     * @param string[] $names
     */
    private static function emit(string $status, string $reason, array $names = []): void
    {
        self::line('STATUS', $status);
        self::line('REASON', $reason);
        foreach ($names as $name) {
            self::line('NAME', $name);
        }
    }

    /** Print one machine-readable record, with newlines flattened so one record is one line. */
    private static function line(string $key, string $value): void
    {
        fwrite(STDOUT, $key . ' ' . str_replace(["\r", "\n"], ' ', $value) . "\n");
    }

    /**
     * Render an exception for the operator.
     *
     * Opensolr already redacts the API key out of every message it raises, but this is the
     * last point before text reaches a terminal and an install log, so the length is capped
     * too: an unredacted body echoed back by a proxy has no business being pasted into a
     * support ticket in full.
     */
    private static function safeMessage(\Throwable $e): string
    {
        $msg = str_replace(["\r", "\n"], ' ', $e->getMessage());
        return strlen($msg) > 300 ? substr($msg, 0, 300) . '…' : $msg;
    }

    /** Report a usage error on stderr and return the usage exit code. */
    private static function usage(string $problem): int
    {
        fwrite(STDERR, 'opensolr-teardown: ' . $problem . "\n");
        fwrite(STDERR, "usage: opensolr-teardown.php --config=PATH (--plan | --delete)\n");
        return 2;
    }
}

/**
 * Run only when executed directly, so the test suite can require this file and exercise
 * plan() and confirmOwned() without the CLI running and without any network access.
 */
if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === realpath(__FILE__)) {
    exit(OpensolrTeardown::main(array_slice($argv, 1)));
}
