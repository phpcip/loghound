<?php
/**
 * Loghound — tests for src/Tail.php.
 *
 * These run against real files on a real filesystem in a temp directory. Log rotation
 * is a filesystem behaviour (rename, unlink, truncate, inode reuse); a mock would test
 * the mock. No network is used.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

/**
 * A tiny in-memory cursor store standing in for \Loghound\State.
 *
 * Tail takes load/save callables precisely so it can be tested without SQLite and
 * without depending on State's API, which another agent owns.
 */
final class LhTailCursorStore
{
    /** @var array<string,array{dev:int,inode:int,offset:int}> */
    public array $rows = [];

    /** Load the stored cursor for a path, or null when we have never seen it. */
    public function load(string $path): ?array
    {
        return $this->rows[$path] ?? null;
    }

    /** Persist a cursor for a path. */
    public function save(string $path, int $dev, int $inode, int $offset): void
    {
        $this->rows[$path] = ['dev' => $dev, 'inode' => $inode, 'offset' => $offset];
    }
}

/**
 * Collects every chunk Tail rejects, so a test can assert that nothing was dropped
 * silently. An object rather than an array because the array would be copied on return.
 */
final class LhBadLineSink
{
    /** @var array<int,array{0:string,1:int,2:string}> */
    public array $rows = [];

    /** Record a rejected chunk with its offset and the reason it was rejected. */
    public function add(string $chunk, int $offset, string $why): void
    {
        $this->rows[] = [$chunk, $offset, $why];
    }

    /** How many chunks have been rejected. */
    public function count(): int
    {
        return count($this->rows);
    }
}

/**
 * Build a Tail plus its cursor store and bad-line sink for a given path.
 *
 * @return array{0:\Loghound\Tail,1:LhTailCursorStore,2:LhBadLineSink}
 */
function lh_tail_make(string $path, array $opts = []): array
{
    $store = new LhTailCursorStore();
    $bad = new LhBadLineSink();
    $opts['on_bad_line'] = static function (string $chunk, int $off, string $why) use ($bad): void {
        $bad->add($chunk, $off, $why);
    };
    $tail = new \Loghound\Tail(
        $path,
        static fn(string $p): ?array => $store->load($p),
        static function (string $p, int $d, int $i, int $o) use ($store): void {
            $store->save($p, $d, $i, $o);
        },
        $opts
    );
    return [$tail, $store, $bad];
}

/**
 * Poll a tailer and return the lines it emitted.
 *
 * @return string[]
 */
function lh_tail_poll(\Loghound\Tail $tail): array
{
    $out = [];
    $tail->poll(static function (string $line, int $offset, string $src) use (&$out): void {
        $out[] = $line;
    });
    return $out;
}

return [

    // ---------------------------------------------------------------------
    // Baseline behaviour
    // ---------------------------------------------------------------------

    'reads appended lines from a file it has never seen when start_at=start' => function () {
        $dir  = lh_tmpdir();
        $path = $dir . '/access.log';
        file_put_contents($path, "one\ntwo\n");

        [$tail] = lh_tail_make($path, ['start_at' => 'start']);
        lh_same(['one', 'two'], lh_tail_poll($tail));

        file_put_contents($path, "three\n", FILE_APPEND);
        lh_same(['three'], lh_tail_poll($tail), 'second poll should only see new bytes');
    },

    'defaults to starting at EOF so a first run does not replay the whole file' => function () {
        $dir  = lh_tmpdir();
        $path = $dir . '/access.log';
        file_put_contents($path, "old-1\nold-2\n");

        [$tail] = lh_tail_make($path); // no start_at => 'end'
        lh_same([], lh_tail_poll($tail), 'existing content must not be replayed');

        file_put_contents($path, "new-1\n", FILE_APPEND);
        lh_same(['new-1'], lh_tail_poll($tail));
    },

    'never commits a partial line' => function () {
        $dir  = lh_tmpdir();
        $path = $dir . '/access.log';
        file_put_contents($path, "complete\npart");

        [$tail, $store] = lh_tail_make($path, ['start_at' => 'start']);
        lh_same(['complete'], lh_tail_poll($tail));

        // Offset must sit at the start of the incomplete line, not past it.
        lh_same(strlen("complete\n"), $store->rows[$path]['offset']);

        // Finish the line; it must now come through whole and exactly once.
        file_put_contents($path, "ial\n", FILE_APPEND);
        lh_same(['partial'], lh_tail_poll($tail));
    },

    'gives each line the byte offset it starts at' => function () {
        $dir  = lh_tmpdir();
        $path = $dir . '/access.log';
        file_put_contents($path, "aaa\nbbbb\n");

        [$tail] = lh_tail_make($path, ['start_at' => 'start']);
        $seen = [];
        $tail->poll(static function (string $line, int $offset) use (&$seen): void {
            $seen[$line] = $offset;
        });
        // sha1(file+offset) is the document id, so these must be exact.
        lh_same(['aaa' => 0, 'bbbb' => 4], $seen);
    },

    // ---------------------------------------------------------------------
    // Rotation — the reason this class exists
    // ---------------------------------------------------------------------

    'ROTATION: drains the old inode to EOF before switching to the new file' => function () {
        $dir  = lh_tmpdir();
        $path = $dir . '/access.log';
        file_put_contents($path, "before-1\n");

        [$tail] = lh_tail_make($path, ['start_at' => 'start']);
        lh_same(['before-1'], lh_tail_poll($tail));

        // logrotate renames the live file. The webserver has NOT reopened yet, so it
        // keeps writing to the same (now renamed) inode — this is the window in which
        // a naive tailer loses data.
        rename($path, $path . '.1');
        file_put_contents($path . '.1', "after-rename-1\nafter-rename-2\n", FILE_APPEND);

        // The webserver is told to reopen and starts a brand new file.
        file_put_contents($path, "new-file-1\n");

        $got = lh_tail_poll($tail);

        // Both the trailing lines of the OLD inode and the first line of the NEW file
        // must be present, and in that order.
        lh_same(['after-rename-1', 'after-rename-2', 'new-file-1'], $got);
    },

    'ROTATION: survives the gap where the new file does not exist yet' => function () {
        $dir  = lh_tmpdir();
        $path = $dir . '/access.log';
        file_put_contents($path, "line-a\n");

        [$tail] = lh_tail_make($path, ['start_at' => 'start']);
        lh_tail_poll($tail);

        // Rename away, nothing at $path for a moment.
        rename($path, $path . '.1');
        file_put_contents($path . '.1', "line-b\n", FILE_APPEND);

        lh_same(['line-b'], lh_tail_poll($tail), 'must still drain the old inode');
        lh_same([], lh_tail_poll($tail), 'no file, no lines, no crash');

        // Replacement appears.
        file_put_contents($path, "line-c\n");
        lh_same(['line-c'], lh_tail_poll($tail));
    },

    'ROTATION while stopped: finds the previous inode by .1 and drains its tail' => function () {
        $dir  = lh_tmpdir();
        $path = $dir . '/access.log';
        file_put_contents($path, "seen-1\n");

        [$tail, $store] = lh_tail_make($path, ['start_at' => 'start']);
        lh_same(['seen-1'], lh_tail_poll($tail));
        $tail->close();

        // Daemon is down. More lines land in the live file, then it is rotated.
        file_put_contents($path, "missed-1\nmissed-2\n", FILE_APPEND);
        rename($path, $path . '.1');
        file_put_contents($path, "fresh-1\n");

        // Daemon restarts with the same persisted cursor.
        $tail2 = new \Loghound\Tail(
            $path,
            static fn(string $p): ?array => $store->load($p),
            static function (string $p, int $d, int $i, int $o) use ($store): void {
                $store->save($p, $d, $i, $o);
            },
            ['start_at' => 'start']
        );

        $got = [];
        $tail2->poll(static function (string $l) use (&$got): void {
            $got[] = $l;
        });

        lh_same(['missed-1', 'missed-2', 'fresh-1'], $got);
    },

    'ROTATION while stopped: reports honestly when the old inode is unrecoverable' => function () {
        $dir  = lh_tmpdir();
        $path = $dir . '/access.log';
        file_put_contents($path, "seen-1\n");

        [$tail, $store] = lh_tail_make($path, ['start_at' => 'start']);
        lh_tail_poll($tail);
        $tail->close();

        // Rotated AND compressed while we were down: the original inode is gone.
        file_put_contents($path, "lost-1\n", FILE_APPEND);
        rename($path, $path . '.1');
        // Simulate gzip: new inode, original unlinked.
        copy($path . '.1', $path . '.1.gz');
        unlink($path . '.1');
        file_put_contents($path, "fresh-1\n");

        $tail2 = new \Loghound\Tail(
            $path,
            static fn(string $p): ?array => $store->load($p),
            static function (string $p, int $d, int $i, int $o) use ($store): void {
                $store->save($p, $d, $i, $o);
            },
            ['start_at' => 'start']
        );
        $got = [];
        $tail2->poll(static function (string $l) use (&$got): void {
            $got[] = $l;
        });

        lh_same(['fresh-1'], $got, 'the new file must still be picked up');

        $status = $tail2->status();
        lh_same(1, $status['missed_rotations'], 'the loss must be counted, not hidden');
        lh_contains((string) $status['note'], 'could not be found', 'status note');
    },

    // ---------------------------------------------------------------------
    // DELETION — the `find /var/log/apache2 -mtime +10 -delete` case.
    //
    // On Linux an unlinked file that we hold open keeps reading forever with no
    // error at all. A tailer that trusts its own descriptor therefore looks
    // perfectly healthy while ingesting nothing, which is the worst failure mode
    // this class can have. These tests are the guard against exactly that.
    // ---------------------------------------------------------------------

    'DELETION: notices the file was unlinked while we held it open' => function () {
        $dir  = lh_tmpdir();
        $path = $dir . '/access.log';
        file_put_contents($path, "alive-1\n");

        [$tail] = lh_tail_make($path, ['start_at' => 'start']);
        lh_same(['alive-1'], lh_tail_poll($tail));

        // The cron fires. The directory entry is gone; our descriptor is not.
        file_put_contents($path, "last-gasp\n", FILE_APPEND);
        unlink($path);

        // Everything written before the unlink must still be read...
        lh_same(['last-gasp'], lh_tail_poll($tail));

        $st = $tail->status();
        lh_same(1, $st['deletions'], 'the deletion must be detected and counted');
        lh_same(false, $st['exists']);
        lh_true($st['missing_since'] !== null, 'the time it went missing must be recorded');
    },

    'DELETION: does not keep reading a deleted inode once a new file appears' => function () {
        $dir  = lh_tmpdir();
        $path = $dir . '/access.log';
        file_put_contents($path, "old-1\n");

        [$tail] = lh_tail_make($path, ['start_at' => 'start']);
        lh_tail_poll($tail);

        // Save a handle to the deleted inode by writing through a hardlink, so the test
        // can prove we do NOT read from it after it loses its name.
        link($path, $dir . '/ghost');
        unlink($path);
        lh_tail_poll($tail);                       // notices the deletion, releases the fd

        // Someone appends to the orphaned inode (via the surviving hardlink). A tailer
        // still holding that descriptor would happily read this and report it as live
        // traffic. We must not.
        file_put_contents($dir . '/ghost', "ghost-line\n", FILE_APPEND);

        // Meanwhile the web server creates a fresh log at the original path.
        file_put_contents($path, "new-1\n");

        $got = lh_tail_poll($tail);
        lh_true(!in_array('ghost-line', $got, true), 'must not read from the unlinked inode');
        lh_same(['new-1'], $got);
    },

    'DELETION: a replacement file is read from byte 0, with no false loss alarm' => function () {
        $dir  = lh_tmpdir();
        $path = $dir . '/access.log';
        file_put_contents($path, "gen1-a\ngen1-b\n");

        [$tail] = lh_tail_make($path, ['start_at' => 'start']);
        lh_same(['gen1-a', 'gen1-b'], lh_tail_poll($tail));

        unlink($path);
        lh_tail_poll($tail);                       // detect the deletion

        // A new file at the same path is a NEW file: read it from the beginning, even
        // though its size is smaller than our last offset.
        file_put_contents($path, "gen2-a\n");
        lh_same(['gen2-a'], lh_tail_poll($tail));

        // And critically: this is not a lost rotation. We read the old file to EOF
        // ourselves before it went away, so raising the alarm here would cry wolf on
        // every single cron-driven deletion.
        lh_same(0, $tail->status()['missed_rotations'], 'no false missed-rotation alarm');
    },

    'DELETION: a long absence is reported quietly, not as an error' => function () {
        $dir  = lh_tmpdir();
        $path = $dir . '/access.log';
        file_put_contents($path, "x\n");

        [$tail] = lh_tail_make($path, ['start_at' => 'start']);
        lh_tail_poll($tail);
        unlink($path);

        // Several polls with nothing there: no exception, no output, no state churn.
        for ($i = 0; $i < 5; $i++) {
            lh_same([], lh_tail_poll($tail));
        }
        lh_true(is_int($tail->status()['missing_for_sec']), 'absence duration must be reported');
    },

    'never opens a source file for writing' => function () {
        // The read-only guarantee, enforced rather than merely documented: other tools
        // (fail2ban, log shippers) read the same files and the operator is entitled to
        // know Loghound cannot disturb them. A read-only directory would stop any
        // create/truncate attempt; a read-only FILE still allows us to read it.
        $dir  = lh_tmpdir();
        $path = $dir . '/access.log';
        file_put_contents($path, "a\nb\n");
        chmod($path, 0444);

        [$tail] = lh_tail_make($path, ['start_at' => 'start']);
        lh_same(['a', 'b'], lh_tail_poll($tail));

        // Size and mtime must be exactly what they were: we never wrote, never truncated.
        clearstatcache(true, $path);
        lh_same(4, (int) filesize($path), 'the source file must be untouched');
    },

    // ---------------------------------------------------------------------
    // Truncation
    // ---------------------------------------------------------------------

    'TRUNCATION: restarts at zero when the file shrinks below the cursor' => function () {
        $dir  = lh_tmpdir();
        $path = $dir . '/access.log';
        file_put_contents($path, "long-line-one\nlong-line-two\n");

        [$tail] = lh_tail_make($path, ['start_at' => 'start']);
        lh_same(['long-line-one', 'long-line-two'], lh_tail_poll($tail));

        // copytruncate / `> access.log`: same inode, size back to zero.
        file_put_contents($path, "post-truncate\n");

        lh_same(['post-truncate'], lh_tail_poll($tail));
        lh_same(1, $tail->status()['truncations']);
    },

    // ---------------------------------------------------------------------
    // Hostile / malformed input
    // ---------------------------------------------------------------------

    'drops a line longer than max_line_bytes instead of buffering forever' => function () {
        $dir  = lh_tmpdir();
        $path = $dir . '/access.log';

        // 5 KB with no newline at all, then a normal line.
        file_put_contents($path, str_repeat('X', 5000) . "\ngood-line\n");

        [$tail, , $bad] = lh_tail_make($path, ['start_at' => 'start', 'max_line_bytes' => 1024]);
        $got = lh_tail_poll($tail);

        lh_true(in_array('good-line', $got, true), 'a normal line after the blob must still be read');
        lh_true(!in_array(str_repeat('X', 5000), $got, true), 'the oversized blob must not be emitted');
        lh_same(1, $tail->status()['overlong_lines']);
        lh_same(1, $bad->count(), 'the dropped line must be reported, never silently lost');
    },

    'does not buffer without bound when the file contains no newline at all' => function () {
        $dir  = lh_tmpdir();
        $path = $dir . '/access.log';
        file_put_contents($path, str_repeat('Y', 9000)); // no terminator, ever

        [$tail, , $bad] = lh_tail_make($path, ['start_at' => 'start', 'max_line_bytes' => 1024]);
        lh_same([], lh_tail_poll($tail));
        lh_same(1, $tail->status()['overlong_lines']);
        lh_same(0, $tail->status()['pending_bytes'], 'the buffer must have been released');
        lh_same(1, $bad->count());
    },

    'a rotation never replays lines that were already drained' => function () {
        // Regression guard: the old inode must be checkpointed at its post-drain offset
        // before the descriptor is released, otherwise a restart re-reads it via the
        // rotated-file recovery path and every line is indexed twice.
        $dir  = lh_tmpdir();
        $path = $dir . '/access.log';
        file_put_contents($path, "a-1\n");

        [$tail, $store] = lh_tail_make($path, ['start_at' => 'start']);
        lh_tail_poll($tail);

        rename($path, $path . '.1');
        file_put_contents($path . '.1', "a-2\n", FILE_APPEND);
        lh_same(['a-2'], lh_tail_poll($tail), 'drained from the renamed inode');

        // The replacement appears only now, and the daemon has meanwhile restarted.
        file_put_contents($path, "b-1\n");
        $tail2 = new \Loghound\Tail(
            $path,
            static fn(string $p): ?array => $store->load($p),
            static function (string $p, int $d, int $i, int $o) use ($store): void {
                $store->save($p, $d, $i, $o);
            },
            ['start_at' => 'start']
        );
        $got = [];
        $tail2->poll(static function (string $l) use (&$got): void {
            $got[] = $l;
        });
        lh_same(['b-1'], $got, 'a-2 must not be emitted a second time');
    },

    'tolerates CRLF and skips blank lines' => function () {
        $dir  = lh_tmpdir();
        $path = $dir . '/access.log';
        file_put_contents($path, "alpha\r\n\n\nbeta\r\n");

        [$tail] = lh_tail_make($path, ['start_at' => 'start']);
        lh_same(['alpha', 'beta'], lh_tail_poll($tail));
    },

    'a missing file is not an error' => function () {
        $dir  = lh_tmpdir();
        $path = $dir . '/never-created.log';

        [$tail] = lh_tail_make($path, ['start_at' => 'start']);
        lh_same([], lh_tail_poll($tail));
        lh_same(false, $tail->status()['exists']);
    },

    'status reports lag in bytes' => function () {
        $dir  = lh_tmpdir();
        $path = $dir . '/access.log';
        file_put_contents($path, "a\n");

        [$tail] = lh_tail_make($path, ['start_at' => 'start']);
        lh_tail_poll($tail);
        lh_same(0, $tail->status()['lag_bytes']);

        // Bytes written but not yet polled are lag.
        file_put_contents($path, "bbbb\n", FILE_APPEND);
        lh_same(5, $tail->status()['lag_bytes']);
    },
];
