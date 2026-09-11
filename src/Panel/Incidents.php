<?php
/**
 * Loghound — the critical errors an operator has to be told about.
 *
 * THE QUESTION THIS ANSWERS. An operator whose panel is empty currently has no way to find
 * out why. The tailer's parse errors, a rejected configset, a failed schema push, a source it
 * cannot read and an unreachable control plane are each a separate counter in a separate file,
 * and each of them requires knowing to go and look. This is the one place that gathers them.
 *
 * ---------------------------------------------------------------------------------------
 * THE ADMISSION TEST IS "IS SOMETHING NOT WORKING", NOT "WAS THIS AN ERROR"
 * ---------------------------------------------------------------------------------------
 * There are no levels here, no severities and no filters, because every one of those turns
 * the question into "which level should I look at" and the answer to that is always "all of
 * them", which is how a list of errors becomes a list nobody reads.
 *
 *   IN  — the tailer stopped or cannot read a source; a configset was rejected; a schema push
 *         failed; the control plane is unreachable; Solr is refusing writes; a job died; the
 *         collector cannot write; authentication cannot function because its store is
 *         unwritable.
 *   OUT — a single parse error; one slow query; a retried request that then succeeded; a
 *         warning; anything informational; anything that resolved itself.
 *
 * THE ONE REAL EDGE is parsing. A single unparsed line is nothing — logs contain rubbish and
 * the parser is supposed to drop it. An ENTIRE SOURCE failing to parse is the product silently
 * ingesting nothing, which looks exactly like an empty panel and has no other symptom. The
 * distinction is whether the function is broken, and that is what is measured: lines read with
 * zero documents indexed and a parse error for each of them.
 *
 * ---------------------------------------------------------------------------------------
 * TWO SOURCES, ONE LIST
 * ---------------------------------------------------------------------------------------
 * `current()` DERIVES what is wrong right now from the evidence the product already writes —
 * the tailer's status document, the saved schema verdict, the configuration, the writability
 * of var/. A derived entry disappears by itself when the condition clears, which is exactly
 * what should happen to "Solr is unreachable" the moment Solr answers.
 *
 * `all()` reads a bounded LEDGER of things that happened and are over — a job that died, a
 * push that failed — which no later probe can rediscover. Written by whoever detected it,
 * through `record()`.
 *
 * Both hand back Diagnostics reports, so an entry renders identically whichever it came from
 * and carries the same copyable block.
 *
 * ---------------------------------------------------------------------------------------
 * THE FILE
 * ---------------------------------------------------------------------------------------
 * `var/incidents.json`, mode 0600, never under the document root, bounded to KEEP entries and
 * pruned on every write. Entries are redacted by Diagnostics before they are written AND again
 * when they are read, because a ledger written by an older release is still untrusted input.
 * A ledger that cannot be parsed is started over rather than indexed into: a corrupt file must
 * not make the one card that reports breakage the card that breaks.
 *
 * AN EMPTY CARD IS THE NORMAL STATE. It is not an unfinished panel, and the view says so.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Config;
use Loghound\Diagnostics;
use Loghound\Security;
use Loghound\Setup\Schema;
use Loghound\Setup\Steps;

final class Incidents
{
    /** File name inside var/. Named so it is obvious in a directory listing. */
    public const FILE = 'incidents.json';

    /** Entries kept. Older ones are dropped, newest first. */
    public const KEEP = 50;

    /**
     * Seconds within which an identical failure updates the entry it repeats instead of
     * appending a second one.
     *
     * A loop that fails once a second would otherwise fill the ledger with one incident in
     * KEEP copies and push out everything else — which is the failure mode that makes a
     * bounded log useless exactly when it matters.
     */
    private const COALESCE = 3600;

    /**
     * Record something that broke and is over.
     *
     * The caller has already decided this passes the admission test; that judgement belongs
     * where the failure is, because only there is it known whether the function is broken.
     *
     * Best effort by design. A ledger write that fails must never take down the operation that
     * was reporting a failure in the first place, so this returns false and says nothing.
     *
     * @param array<string,mixed> $report A Diagnostics::capture() report.
     */
    public static function record(string $varDir, array $report): bool
    {
        $dir = rtrim($varDir, '/');
        if ($dir === '' || (!is_dir($dir) && !@mkdir($dir, 0750, true) && !is_dir($dir))) {
            return false;
        }

        $entries = self::read($dir);
        $now     = (int) ($report['at'] ?? time());

        foreach ($entries as $i => $existing) {
            if (self::sameFailure($existing, $report)
                && $now - (int) ($existing['at'] ?? 0) <= self::COALESCE
            ) {
                $entries[$i] = $report + ['seen' => (int) ($existing['seen'] ?? 1) + 1];
                return self::write($dir, $entries);
            }
        }

        array_unshift($entries, $report + ['seen' => 1]);

        return self::write($dir, array_slice($entries, 0, self::KEEP));
    }

    /**
     * Everything in the ledger, newest first, redacted on the way out.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function all(string $varDir, ?Config $cfg = null): array
    {
        $out = [];
        foreach (self::read(rtrim($varDir, '/')) as $entry) {
            $out[] = self::clean($entry, $cfg);
        }

        return $out;
    }

    /** Empty the ledger. Used by the card's own control and by a teardown. */
    public static function clear(string $varDir): bool
    {
        $path = rtrim($varDir, '/') . '/' . self::FILE;
        if (!is_file($path)) {
            return true;
        }

        return @unlink($path);
    }

    /** Absolute path of the ledger, for the card to name and for a teardown to remove. */
    public static function path(string $varDir): string
    {
        return rtrim($varDir, '/') . '/' . self::FILE;
    }

    /**
     * What is broken right now, derived from evidence the product already writes.
     *
     * Nothing here asks the network. Every check reads a local file or the configuration, so
     * this renders on a Settings page whose Solr is down — which is the case it exists for.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function current(Config $cfg, string $root): array
    {
        $out = [];
        foreach ([
            self::ingestIncidents($cfg, $root),
            self::schemaIncidents($cfg, $root),
            self::storageIncidents($cfg),
        ] as $group) {
            foreach ($group as $incident) {
                $out[] = $incident;
            }
        }

        return $out;
    }

    /**
     * The ingest half: is the reader running, can it read what it was given, is anything
     * landing in Solr at all.
     *
     * Read from the raw status document rather than through Steps::ingestStatus(), which
     * flattens away the two things that matter here — the per-source rows and the totals.
     *
     * @return array<int,array<string,mixed>>
     */
    private static function ingestIncidents(Config $cfg, string $root): array
    {
        $out    = [];
        $status = Steps::ingestStatus($root);
        $state  = (string) ($status['state'] ?? 'absent');
        $file   = (string) ($status['file'] ?? '');

        $sources = self::configuredSources($cfg);

        if ($state === 'refused') {
            return [self::incident(
                'Reading your access logs',
                'The reader refused the configuration it was asked to reload',
                implode(' ', array_filter((array) ($status['errors'] ?? []), 'is_string'))
                    ?: 'The reader rejected the configuration and kept the previous one.',
                ['Status file' => $file],
                $cfg,
                $root
            )];
        }

        if ($sources !== [] && ($state === 'absent' || $state === 'unreadable' || $state === 'stale')) {
            $why = match ($state) {
                'absent'     => 'The reader has never written a status document, so it has not run on '
                    . 'this machine since the sources were configured.',
                'unreadable' => 'The reader\'s status document cannot be read or is not the shape this '
                    . 'release writes.',
                default      => 'The reader last wrote its status document '
                    . (int) ($status['age_sec'] ?? 0) . ' seconds ago, so it has stopped.',
            };

            $out[] = self::incident(
                'Reading your access logs',
                'Ingestion is not running',
                $why . ' Nothing new is reaching either index while this is true.',
                ['Status file' => $file, 'Sources configured' => (string) count($sources)],
                $cfg,
                $root
            );
        }

        $doc = self::statusDocument($root);

        if ($doc !== null) {
            foreach (self::unreadableSources($cfg, $doc) as $path) {
                $out[] = self::incident(
                    'Reading your access logs',
                    'A log source cannot be read',
                    'The reader is running but is not reading this file. It is either gone, or it is '
                        . 'not readable by the user the reader runs as. Nothing from it is being '
                        . 'ingested.',
                    ['File' => $path],
                    $cfg,
                    $root
                );
            }

            $totals = is_array($doc['totals'] ?? null) ? $doc['totals'] : [];
            $lines  = (int) ($totals['lines'] ?? 0);
            $docs   = (int) ($totals['docs_indexed'] ?? 0);
            $errors = (int) ($totals['parse_errors'] ?? 0);
            $solr   = (int) ($totals['solr_errors'] ?? 0);

            if ($lines > 0 && $docs === 0 && $errors >= $lines) {
                $out[] = self::incident(
                    'Reading your access logs',
                    'Every line read is failing to parse',
                    'The reader has read ' . $lines . ' line' . ($lines === 1 ? '' : 's') . ' and '
                        . 'indexed none of them: the configured log format does not match what is '
                        . 'actually in the file. A single unparsed line is normal and is not reported '
                        . 'here; a whole source failing is the panel silently staying empty. Confirm '
                        . 'the format again on the log sources card.',
                    ['Lines read' => (string) $lines, 'Parse errors' => (string) $errors],
                    $cfg,
                    $root
                );
            }

            if ($solr > 0) {
                $out[] = self::incident(
                    'Writing documents to Solr',
                    'Solr is refusing writes',
                    'The reader has had ' . $solr . ' batch' . ($solr === 1 ? '' : 'es')
                        . ' rejected by Solr. Documents that were in them are not in the index.',
                    ['Solr errors' => (string) $solr],
                    $cfg,
                    $root
                );
            }
        }

        return $out;
    }

    /**
     * The schema half: a configset that was rejected, a push that failed, a control plane that
     * could not be reached.
     *
     * Only `bad` is admitted. `warn` covers "the saved check was taken against another release"
     * and "nothing has been checked yet", neither of which is something being broken.
     *
     * @return array<int,array<string,mixed>>
     */
    private static function schemaIncidents(Config $cfg, string $root): array
    {
        try {
            $notice = Schema::notice($cfg, $root);
        } catch (\Throwable $e) {
            return [self::incident(
                'Checking your index schemas',
                'The schema check could not run',
                $e->getMessage(),
                [],
                $cfg,
                $root
            )];
        }

        if ((string) ($notice['severity'] ?? '') !== 'bad') {
            return [];
        }

        return [self::incident(
            'Checking your index schemas',
            (string) ($notice['headline'] ?? 'A schema could not be read'),
            (string) ($notice['detail'] ?? ''),
            ['State' => (string) ($notice['state'] ?? '')],
            $cfg,
            $root
        )];
    }

    /**
     * The storage half: can this installation write the files that make it function.
     *
     * An unwritable var/ is not an inconvenience. Security::loginGate() refuses to check a
     * password it cannot count the attempt for, the job store cannot be opened, and the setup
     * token cannot be minted — so authentication itself stops working, which is exactly the
     * kind of thing this card exists to name instead of leaving as a blank screen.
     *
     * @return array<int,array<string,mixed>>
     */
    private static function storageIncidents(Config $cfg): array
    {
        $varDir = rtrim($cfg->varDir(), '/');
        if ($varDir !== '' && is_dir($varDir) && is_writable($varDir)) {
            return [];
        }

        return [self::incident(
            'Keeping this installation\'s own state',
            'Loghound cannot write to its var directory',
            'Signing in cannot work while this is true: the panel refuses to check a password it '
                . 'cannot record the attempt for, rather than check one without counting it. The '
                . 'long operations on this page cannot start either. Give the directory to the user '
                . 'this panel runs as.',
            ['Directory' => $varDir === '' ? 'not configured' : $varDir],
            $cfg,
            null
        )];
    }

    /**
     * Log sources that are configured and switched on but that the reader is not reading.
     *
     * A source the reader could not open is simply absent from its status document — it never
     * becomes a Tail — so the comparison is between what is configured and what is reported,
     * plus any reported row whose file has since disappeared.
     *
     * @param array<string,mixed> $doc
     * @return array<int,string>
     */
    private static function unreadableSources(Config $cfg, array $doc): array
    {
        $reported = [];
        $gone     = [];
        foreach ((array) ($doc['sources'] ?? []) as $row) {
            if (!is_array($row) || !is_string($row['path'] ?? null)) {
                continue;
            }
            $reported[$row['path']] = true;
            if (($row['exists'] ?? true) === false) {
                $gone[] = $row['path'];
            }
        }

        $missing = [];
        foreach (self::configuredSources($cfg) as $path) {
            if (!isset($reported[$path]) && !str_contains($path, '*')) {
                $missing[] = $path;
            }
        }

        return array_values(array_unique(array_merge($missing, $gone)));
    }

    /**
     * Configured log paths that are switched on.
     *
     * A source the operator has paused is not broken, so it is not a candidate for "cannot be
     * read". Config::sourceEnabled() is the one place that decision is made.
     *
     * @return array<int,string>
     */
    private static function configuredSources(Config $cfg): array
    {
        $out = [];
        foreach ((array) $cfg->get('sources', []) as $source) {
            if (!is_array($source) || !Config::sourceEnabled($source)) {
                continue;
            }
            $path = $source['path'] ?? null;
            if (is_string($path) && $path !== '') {
                $out[] = $path;
            }
        }

        return $out;
    }

    /**
     * The tailer's status document, raw.
     *
     * @return array<string,mixed>|null
     */
    private static function statusDocument(string $root): ?array
    {
        $file = (string) (Steps::ingestStatus($root)['file'] ?? '');
        if ($file === '' || !is_file($file) || !is_readable($file)) {
            return null;
        }

        $raw = @file_get_contents($file);
        $doc = is_string($raw) ? json_decode($raw, true) : null;

        return is_array($doc) ? $doc : null;
    }

    /**
     * Build one entry, in the same shape the ledger stores.
     *
     * @param array<string,string> $facts
     * @return array<string,mixed>
     */
    private static function incident(
        string $doing,
        string $step,
        string $error,
        array $facts,
        Config $cfg,
        ?string $root
    ): array {
        return Diagnostics::capture($doing, $step, $error, $facts, $cfg, $root) + ['seen' => 1];
    }

    /**
     * Are two reports the same failure, for coalescing purposes?
     *
     * Keyed on what was being done and where it died, not on the error text: a transport
     * failure that quotes a different port number each time is still the same failure, and
     * treating it as a new one is how a ledger fills up with one incident.
     *
     * @param array<string,mixed> $a
     * @param array<string,mixed> $b
     */
    private static function sameFailure(array $a, array $b): bool
    {
        return (string) ($a['doing'] ?? '') === (string) ($b['doing'] ?? '')
            && (string) ($a['step'] ?? '') === (string) ($b['step'] ?? '');
    }

    /**
     * Read the ledger, tolerating every way it can be wrong.
     *
     * @return array<int,array<string,mixed>>
     */
    private static function read(string $dir): array
    {
        $path = $dir . '/' . self::FILE;
        if (!is_file($path) || !is_readable($path)) {
            return [];
        }

        $raw  = @file_get_contents($path);
        $data = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($data)) {
            return [];
        }

        $out = [];
        foreach ($data as $entry) {
            if (is_array($entry) && isset($entry['doing'])) {
                $out[] = $entry;
            }
        }

        return array_slice($out, 0, self::KEEP);
    }

    /**
     * Replace the ledger atomically, at 0600.
     *
     * Security::writePrivateFile() is the one write path in this product that creates a file
     * with its mode already set rather than chmod-ing a descriptor somebody may already hold.
     *
     * @param array<int,array<string,mixed>> $entries
     */
    private static function write(string $dir, array $entries): bool
    {
        $json = json_encode(array_values($entries), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        if (!is_string($json)) {
            return false;
        }

        return Security::writePrivateFile($dir . '/' . self::FILE, $json . "\n", 0600);
    }

    /**
     * Re-redact and shape one stored entry on the way out.
     *
     * A ledger written by an older release, or by a path whose redaction was narrower, is
     * untrusted input like anything else that has been on disk. Running it through the same
     * sink again costs nothing and is the difference between a rule and a hope.
     *
     * @param array<string,mixed> $entry
     * @return array<string,mixed>
     */
    private static function clean(array $entry, ?Config $cfg): array
    {
        $facts = [];
        foreach ((array) ($entry['facts'] ?? []) as $label => $value) {
            $facts[(string) $label] = Diagnostics::redact((string) $value, $cfg);
        }

        $env = [];
        foreach ((array) ($entry['environment'] ?? []) as $label => $value) {
            $env[(string) $label] = Diagnostics::redact((string) $value, $cfg);
        }

        return [
            'at'          => (int) ($entry['at'] ?? 0),
            'doing'       => Diagnostics::redact((string) ($entry['doing'] ?? ''), $cfg),
            'step'        => Diagnostics::redact((string) ($entry['step'] ?? ''), $cfg),
            'error'       => Diagnostics::redact((string) ($entry['error'] ?? ''), $cfg),
            'error_class' => (string) ($entry['error_class'] ?? ''),
            'raised_at'   => (string) ($entry['raised_at'] ?? ''),
            'facts'       => $facts,
            'environment' => $env,
            'seen'        => max(1, (int) ($entry['seen'] ?? 1)),
        ];
    }
}
