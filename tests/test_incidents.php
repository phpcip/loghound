<?php
/**
 * Loghound — the critical errors card: what gets in, and what must not.
 *
 * THE QUESTION IT ANSWERS. An operator whose panel is empty has no way to find out why: the
 * tailer's parse errors, a rejected configset, a failed schema push, a source it cannot read and
 * an unreachable control plane are each a separate counter in a separate file, and each requires
 * knowing to go and look. The card gathers them.
 *
 * THE ADMISSION TEST IS "IS SOMETHING NOT WORKING", NOT "WAS THIS AN ERROR". Most of this file
 * is the OUT list, because a card that admits warnings is a card nobody reads, and the moment
 * that happens the four counters it replaced are back.
 *
 * THE ONE REAL EDGE IS PARSING. A single unparsed line is nothing — logs contain rubbish and the
 * parser drops it on purpose. An entire source failing to parse is the product silently ingesting
 * nothing, which is indistinguishable from an empty panel and has no other symptom. Both are
 * pinned below.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Config;
use Loghound\Diagnostics;
use Loghound\Panel\Incidents;

/** A sentinel that must never survive into the ledger or out of it. */
const LH_IN_KEY = 'incident-api-key-4a7d2f9c';

/**
 * An installation with a configured source, in the layout the product actually has.
 *
 * @return array{0:string,1:Config}
 */
function lh_in_tree(): array
{
    $root = lh_tmpdir('lh-incidents');
    @mkdir($root . '/config', 0750, true);
    @mkdir($root . '/var', 0750, true);

    /* THE SHIPPED SCHEMAS HAVE TO BE PRESENT, because a tree without them is a real critical
       error — Schema::notice() reports `unreadable`, severity `bad`, and the card is right to
       say so. A fixture that omitted them would raise that incident in every test here and
       hide whichever one the test was actually about. */
    @symlink(dirname(__DIR__) . '/solr', $root . '/solr');

    $cfg = Config::load($root . '/config/loghound.php');
    $cfg->set('solr.mode', 'opensolr');
    $cfg->set('solr.install_id', 'abcd1234');
    $cfg->set('solr.hits_core', 'loghound_abcd1234_hits');
    $cfg->set('solr.sessions_core', 'loghound_abcd1234_sessions');
    $cfg->set('opensolr.api_key', LH_IN_KEY);
    $cfg->set('opensolr.email', 'op@example.test');
    $cfg->set('sources', [['path' => '/var/log/apache2/access.log', 'format' => 'apache_combined']]);

    return [$root, $cfg];
}

/**
 * Write a tailer status document into the tree.
 *
 * @param array<string,mixed> $totals
 * @param array<int,array<string,mixed>> $sources
 */
function lh_in_status(string $root, array $totals, array $sources, int $age = 0): void
{
    file_put_contents($root . '/var/tail-status.json', (string) json_encode([
        'schema'       => 1,
        'pid'          => 123,
        'generated_at' => gmdate('Y-m-d\TH:i:s\Z', time() - $age),
        'started_at'   => gmdate('Y-m-d\TH:i:s\Z', time() - 600),
        'totals'       => $totals + [
            'lines' => 0, 'docs_indexed' => 0, 'parse_errors' => 0,
            'badlines_kept' => 0, 'batches' => 0, 'solr_errors' => 0, 'enrich_skipped' => 0,
        ],
        'sources'      => $sources,
    ]));
}

/** One healthy source row. @return array<string,mixed> */
function lh_in_source(string $path = '/var/log/apache2/access.log'): array
{
    return ['path' => $path, 'exists' => true, 'dev' => 1, 'inode' => 2, 'offset' => 3, 'size' => 3];
}

/** Every "step" line in a set of incidents, so a test can say what was admitted. */
function lh_in_steps(array $incidents): array
{
    return array_map(static fn (array $i): string => (string) $i['step'], $incidents);
}

return [

    // ---------------------------------------------------------------------------------
    // IN — something is not working
    // ---------------------------------------------------------------------------------

    'a reader that has stopped is in the card' => static function (): void {
        [$root, $cfg] = lh_in_tree();

        try {
            lh_in_status($root, ['lines' => 100, 'docs_indexed' => 100], [lh_in_source()], 600);

            lh_contains(
                implode(' | ', lh_in_steps(Incidents::current($cfg, $root))),
                'Ingestion is not running',
                'a stale status document means the reader is not running, and nothing new is '
                . 'reaching either index while that is true'
            );
        } finally {
            lh_rmtree($root);
        }
    },

    'a reader that has never run, on an installation with sources, is in the card'
        => static function (): void {
            [$root, $cfg] = lh_in_tree();

            try {
                lh_contains(
                    implode(' | ', lh_in_steps(Incidents::current($cfg, $root))),
                    'Ingestion is not running',
                    'no status document at all, with sources configured, is the commonest cause of '
                    . 'an empty panel and had no symptom anywhere in the product'
                );
            } finally {
                lh_rmtree($root);
            }
        },

    'a source the reader cannot read is in the card, by name' => static function (): void {
        [$root, $cfg] = lh_in_tree();

        try {
            /* A SOURCE THE READER COULD NOT OPEN IS SIMPLY ABSENT from its status document —
               it never becomes a Tail at all — so the only way to see it is to compare what is
               configured against what is reported. */
            lh_in_status($root, ['lines' => 5, 'docs_indexed' => 5], []);

            $found = Incidents::current($cfg, $root);
            lh_contains(implode(' | ', lh_in_steps($found)), 'A log source cannot be read', 'it is admitted');

            $all = '';
            foreach ($found as $incident) {
                $all .= Diagnostics::block($incident);
            }
            lh_contains($all, '/var/log/apache2/access.log', 'and the block names which file');
        } finally {
            lh_rmtree($root);
        }
    },

    'a source whose file has gone is in the card' => static function (): void {
        [$root, $cfg] = lh_in_tree();

        try {
            $gone = lh_in_source();
            $gone['exists'] = false;
            lh_in_status($root, ['lines' => 5, 'docs_indexed' => 5], [$gone]);

            lh_contains(
                implode(' | ', lh_in_steps(Incidents::current($cfg, $root))),
                'A log source cannot be read',
                'a row the reader is holding open on a file that has disappeared'
            );
        } finally {
            lh_rmtree($root);
        }
    },

    'an entire source failing to parse is in the card' => static function (): void {
        [$root, $cfg] = lh_in_tree();

        try {
            lh_in_status($root, ['lines' => 2000, 'docs_indexed' => 0, 'parse_errors' => 2000], [lh_in_source()]);

            lh_contains(
                implode(' | ', lh_in_steps(Incidents::current($cfg, $root))),
                'Every line read is failing to parse',
                'the configured format does not match the file. The product is ingesting nothing '
                . 'and the only symptom anywhere is a panel that stays empty.'
            );
        } finally {
            lh_rmtree($root);
        }
    },

    'Solr refusing writes is in the card' => static function (): void {
        [$root, $cfg] = lh_in_tree();

        try {
            lh_in_status($root, ['lines' => 900, 'docs_indexed' => 800, 'solr_errors' => 3], [lh_in_source()]);

            lh_contains(
                implode(' | ', lh_in_steps(Incidents::current($cfg, $root))),
                'Solr is refusing writes',
                'a rejected batch is documents that are not in the index'
            );
        } finally {
            lh_rmtree($root);
        }
    },

    'nowhere to write is in the card, because authentication stops working'
        => static function (): void {
            [$root, $cfg] = lh_in_tree();

            try {
                lh_in_status($root, ['lines' => 9, 'docs_indexed' => 9], [lh_in_source()]);
                chmod($root . '/var', 0500);

                $steps = implode(' | ', lh_in_steps(Incidents::current($cfg, $root)));
                if (is_writable($root . '/var')) {
                    lh_skip('this filesystem or user ignores the mode, so unwritability cannot be staged');
                }

                lh_contains(
                    $steps,
                    'cannot write to its var directory',
                    'the panel refuses to check a password it cannot record the attempt for, so '
                    . 'signing in stops working entirely'
                );
            } finally {
                @chmod($root . '/var', 0750);
                lh_rmtree($root);
            }
        },

    // ---------------------------------------------------------------------------------
    // OUT — nothing is broken
    // ---------------------------------------------------------------------------------

    'a working installation has an empty card, and that is the normal state'
        => static function (): void {
            [$root, $cfg] = lh_in_tree();

            try {
                lh_in_status($root, ['lines' => 10000, 'docs_indexed' => 10000], [lh_in_source()]);

                lh_same(
                    [],
                    lh_in_steps(Incidents::current($cfg, $root)),
                    'an empty card is what a working installation looks like'
                );
                lh_same([], Incidents::all($cfg->varDir(), $cfg), 'and the ledger is empty too');
            } finally {
                lh_rmtree($root);
            }
        },

    'a single parse error is not an incident' => static function (): void {
        [$root, $cfg] = lh_in_tree();

        try {
            lh_in_status($root, ['lines' => 10000, 'docs_indexed' => 9999, 'parse_errors' => 1], [lh_in_source()]);

            lh_same(
                [],
                lh_in_steps(Incidents::current($cfg, $root)),
                'logs contain rubbish and the parser drops it on purpose. The distinction is '
                . 'whether the FUNCTION is broken, not whether an error occurred.'
            );
        } finally {
            lh_rmtree($root);
        }
    },

    'a source the operator has paused is not a source that cannot be read'
        => static function (): void {
            [$root, $cfg] = lh_in_tree();

            try {
                $cfg->set('sources', [[
                    'path'    => '/var/log/apache2/access.log',
                    'format'  => 'apache_combined',
                    'enabled' => false,
                ]]);
                lh_in_status($root, ['lines' => 10, 'docs_indexed' => 10], []);

                lh_same(
                    [],
                    lh_in_steps(Incidents::current($cfg, $root)),
                    'a log the operator switched off is not broken, and reporting it as such would '
                    . 'train them to ignore the card'
                );
            } finally {
                lh_rmtree($root);
            }
        },

    'an installation with no sources yet is not an installation that is broken'
        => static function (): void {
            [$root, $cfg] = lh_in_tree();

            try {
                $cfg->set('sources', []);

                lh_same(
                    [],
                    lh_in_steps(Incidents::current($cfg, $root)),
                    'a fresh install has not been given a log yet. That is the Finish setup card\'s '
                    . 'business, not a critical error.'
                );
            } finally {
                lh_rmtree($root);
            }
        },

    'a glob source is never reported as unreadable on the strength of its pattern'
        => static function (): void {
            [$root, $cfg] = lh_in_tree();

            try {
                $cfg->set('sources', [['path' => '/var/log/apache2/*access.log', 'format' => 'apache_combined']]);
                lh_in_status($root, ['lines' => 10, 'docs_indexed' => 10], [lh_in_source('/var/log/apache2/a-access.log')]);

                lh_same(
                    [],
                    lh_in_steps(Incidents::current($cfg, $root)),
                    'the reader expands a pattern into real paths, so the pattern itself never '
                    . 'appears in the status document and comparing the two directly would report '
                    . 'every glob on every installation as broken'
                );
            } finally {
                lh_rmtree($root);
            }
        },

    // ---------------------------------------------------------------------------------
    // The ledger
    // ---------------------------------------------------------------------------------

    'the ledger is 0600, under var/, and never in the document root' => static function (): void {
        [$root, $cfg] = lh_in_tree();

        try {
            Incidents::record($cfg->varDir(), Diagnostics::capture('Doing', 'A step', 'it broke', [], $cfg));

            $path = Incidents::path($cfg->varDir());
            lh_true(is_file($path), 'the ledger was written');
            lh_same($root . '/var/incidents.json', $path, 'under var/, beside the other private state');

            $mode = fileperms($path) & 0777;
            if ($mode !== 0600) {
                lh_fail('the ledger is mode ' . decoct($mode) . '; it carries failure detail and must be 0600');
            }
        } finally {
            lh_rmtree($root);
        }
    },

    'a secret planted in a recorded failure is not in the file, nor on the way back out'
        => static function (): void {
            [$root, $cfg] = lh_in_tree();

            try {
                Incidents::record($cfg->varDir(), Diagnostics::capture(
                    'Talking to the control plane',
                    'Listing your indexes',
                    new \RuntimeException('rejected: api_key=' . LH_IN_KEY . ' and bare ' . LH_IN_KEY),
                    ['Key' => LH_IN_KEY],
                    $cfg
                ));

                $raw = (string) file_get_contents(Incidents::path($cfg->varDir()));
                lh_false(str_contains($raw, LH_IN_KEY), 'the key is not in the file on disk');

                $out = Incidents::all($cfg->varDir(), $cfg);
                lh_false(
                    str_contains((string) json_encode($out), LH_IN_KEY),
                    'nor on the way back out — a ledger written by an older release, or by a path '
                    . 'whose redaction was narrower, is untrusted input like anything else that '
                    . 'has been on disk'
                );
            } finally {
                lh_rmtree($root);
            }
        },

    'the ledger is bounded and identical failures coalesce' => static function (): void {
        [$root, $cfg] = lh_in_tree();

        try {
            for ($i = 0; $i < 5; $i++) {
                Incidents::record($cfg->varDir(), Diagnostics::capture(
                    'Talking to the control plane',
                    'Listing your indexes',
                    'timed out after ' . $i . 's',
                    [],
                    $cfg
                ));
            }

            $out = Incidents::all($cfg->varDir(), $cfg);
            lh_same(
                1,
                count($out),
                'a loop failing once a second would otherwise fill the ledger with one incident in '
                . 'fifty copies and push out everything else, which is a bounded log made useless '
                . 'at exactly the moment it matters'
            );
            lh_same(5, (int) $out[0]['seen'], 'and the card says how many times');

            for ($i = 0; $i < Incidents::KEEP + 10; $i++) {
                Incidents::record($cfg->varDir(), Diagnostics::capture(
                    'Doing thing ' . $i,
                    'Step ' . $i,
                    'it broke',
                    [],
                    $cfg
                ));
            }

            lh_true(
                count(Incidents::all($cfg->varDir(), $cfg)) <= Incidents::KEEP,
                'the ledger is pruned on every write'
            );
        } finally {
            lh_rmtree($root);
        }
    },

    'a corrupt ledger is started over rather than indexed into' => static function (): void {
        [$root, $cfg] = lh_in_tree();

        try {
            file_put_contents($root . '/var/incidents.json', '{"not": "a list"');

            lh_same(
                [],
                Incidents::all($cfg->varDir(), $cfg),
                'the one card that reports breakage must not be the card that breaks'
            );
            lh_true(
                Incidents::record($cfg->varDir(), Diagnostics::capture('Doing', 'Step', 'broke', [], $cfg)),
                'and a write still lands'
            );
        } finally {
            lh_rmtree($root);
        }
    },

    'clearing empties the ledger and nothing else' => static function (): void {
        [$root, $cfg] = lh_in_tree();

        try {
            lh_in_status($root, ['lines' => 100, 'docs_indexed' => 0, 'parse_errors' => 100], [lh_in_source()]);
            Incidents::record($cfg->varDir(), Diagnostics::capture('Doing', 'Step', 'broke', [], $cfg));

            Incidents::clear($cfg->varDir());

            lh_same([], Incidents::all($cfg->varDir(), $cfg), 'the recorded failures are gone');
            lh_true(
                count(Incidents::current($cfg, $root)) > 0,
                'and everything still broken is reported again immediately, because it is measured '
                . 'rather than remembered — which is what stops this card being a place a real '
                . 'problem can be dismissed'
            );
        } finally {
            lh_rmtree($root);
        }
    },

    // ---------------------------------------------------------------------------------
    // The card
    // ---------------------------------------------------------------------------------

    'the card has no levels, no severities and no filters' => static function (): void {
        $src = (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Settings.php');

        $start = strpos($src, 'private function errorsSection(): void');
        lh_true($start !== false, 'the card exists');
        $card = substr($src, (int) $start, 4000);

        foreach (['severity', 'level', 'WARNING', 'Filter by'] as $banned) {
            lh_false(
                str_contains($card, $banned),
                'the card must not offer "' . $banned . '": every level control turns the question '
                . 'into "which one should I look at", and the answer to that is always "all of '
                . 'them", which is how a list of errors becomes a list nobody reads'
            );
        }
    },

    'an empty card reads as reassurance, not as an unfinished panel' => static function (): void {
        $src = (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Settings.php');

        lh_contains($src, 'Nothing is broken.', 'it says so in words');
        lh_contains(
            $src,
            'is what a working installation looks like',
            'and says that an empty one is the normal state, rather than leaving the reader to '
            . 'wonder whether the card works'
        );
    },
];
