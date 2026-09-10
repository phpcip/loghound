<?php
/**
 * Loghound — rotation-safe log tailing.
 *
 * This class is the single most important piece of correctness in the ingest path, and
 * the one that every naive `tail -F` reimplementation gets wrong. Read the rotation
 * notes below before changing anything here.
 *
 * ---------------------------------------------------------------------------------
 * WHY THIS IS HARD
 * ---------------------------------------------------------------------------------
 *
 * A log file is not a stable object. Under logrotate it is one of these, nightly:
 *
 *   1. RENAME + CREATE (the common Debian/Ubuntu Apache and nginx case)
 *        access.log  ->  access.log.1     (same inode, new name)
 *        access.log                        (new file, new inode)
 *      The webserver keeps writing to the OLD inode until it is told to reopen
 *      (`postrotate ... reload`). So between the rename and the reload there are STILL
 *      NEW LINES arriving in access.log.1. A tailer that reacts to "the inode under
 *      this path changed" by simply jumping to the new file loses every one of them.
 *      That is silent data loss, it happens once per day, and nobody notices because
 *      the tool never reports it.
 *
 *      *** THE RULE: on an inode change, DRAIN THE OLD INODE TO EOF FIRST. ***
 *
 *      We can always do that safely while the daemon is running, because we still hold
 *      an open descriptor to the old inode. A descriptor keeps the inode alive even
 *      after the file has been renamed away or unlinked entirely, so the drain works
 *      regardless of what logrotate did to the directory entry.
 *
 *   2. COPYTRUNCATE
 *        the file is copied to access.log.1, then truncated to zero in place.
 *      Same inode, size suddenly smaller than our offset. We restart at offset 0.
 *      Anything written between our last read and the truncate is genuinely gone — it
 *      only exists inside the copy, which we cannot identify by inode. This is a
 *      property of copytruncate, not of this code, and it is why docs/INSTALL.md tells
 *      operators not to use it.
 *
 *   3. ROTATION WHILE THE DAEMON IS STOPPED
 *      We come back with a stored (dev, inode, offset) that no longer matches the file
 *      at that path. We then look for the rotated file among the usual suffixes
 *      (.1, .0, -YYYYMMDD) and check its INODE against the stored one. Only an inode
 *      match is trusted — matching by name would happily read a file that has nothing
 *      to do with our cursor. If the rotated copy was compressed (`.gz`), compression
 *      created a NEW inode and the original is gone: those trailing bytes cannot be
 *      recovered, and we say so in the status output instead of pretending otherwise.
 *      `delaycompress` in the logrotate config avoids this entirely.
 *
 *   4. THE FILE SIMPLY DISAPPEARS for a moment (rotate scripts that move then create).
 *      We hold the cursor and keep polling; nothing is lost and nothing is reset.
 *
 *   5. OUTRIGHT DELETION WHILE WE HOLD IT OPEN. This is NOT hypothetical — the first
 *      production target for this tool has exactly this in its crontab:
 *
 *          @daily /usr/bin/find /var/log/apache2/ -type f -mtime +10 -exec /usr/bin/rm -f {} +
 *
 *      Logs there are DELETED after ten days, not rotated. On Linux, unlinking a file
 *      that a process holds open does not disturb that process at all: the descriptor
 *      stays valid and keeps referring to an inode with no directory entry. A tailer
 *      that only ever reads from its open descriptor will therefore go on reading a
 *      deleted file forever — quietly getting nothing, while every health check it
 *      reports says it is fine. **This is the failure mode that makes log tailers look
 *      like they work while losing everything**, and it is why every poll re-stats the
 *      PATH and compares (dev, inode) against the open descriptor rather than trusting
 *      the descriptor it already has. We also check `st_nlink == 0` on the open
 *      descriptor, which is a direct "this inode has no name any more" signal and
 *      catches the case where stat() on the path fails for an unrelated reason.
 *
 *   6. THE PATH DISAPPEARS AND NOTHING REPLACES IT. Do not crash, do not busy-loop, do
 *      not fill the journal with one line per second. The cursor is held, the file is
 *      reported as missing with the time it went away, and when a file appears at that
 *      path again it is treated as what it is: a NEW file, read from byte 0.
 *
 * ---------------------------------------------------------------------------------
 * READ-ONLY, ALWAYS
 * ---------------------------------------------------------------------------------
 * A source log file is opened with fopen($path, 'rb') and nothing else, anywhere in
 * this class or in bin/loghound-tail. No mode string with 'w', 'a', 'x' or '+' is ever
 * applied to a source. Loghound never writes to, truncates, rotates, renames or deletes
 * a log file it reads — other tooling (fail2ban, log shippers, the operator's own
 * scripts) is reading the same files and must not have the ground moved under it.
 * Loghound's own writes all go to var/ inside the application directory.
 *
 * ---------------------------------------------------------------------------------
 * PARTIAL LINES
 * ---------------------------------------------------------------------------------
 * A webserver's write of a log line is not atomic from our point of view: we can and do
 * read a half-written line at EOF. The committed offset therefore only ever advances
 * past a byte we have seen a terminating "\n" for. The tail of an incomplete line is
 * held in an internal buffer and re-joined with the next read. Committing an offset
 * mid-line would corrupt both that line and the id (sha1(file+offset)) of the next one.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound;

final class Tail
{
    /** Absolute path of the live log file. */
    private string $path;

    /** @var callable(string):?array  Loads {dev, inode, offset} for a path, or null. */
    private $loadCursor;

    /** @var callable(string,int,int,int):void  Persists {path, dev, inode, offset}. */
    private $saveCursor;

    /** @var callable(string,int,string):void|null  Called with an unusable raw chunk. */
    private $onBadLine;

    /** Open descriptor for the inode we are currently reading. */
    private $fh = null;

    /** Byte offset within the current inode of the first byte we have NOT committed. */
    private int $offset = 0;

    /** Device and inode of the file behind $fh, for change detection. */
    private int $dev = 0;
    private int $inode = 0;

    /** Bytes read past $offset that do not yet end in a newline. */
    private string $pending = '';

    /** Where to begin when a path is seen for the very first time: 'end' or 'start'. */
    private string $startAt;

    /** A "line" longer than this is malformed or hostile and is discarded, not buffered. */
    private int $maxLineBytes;

    /** Bytes per fread(). 256 KB keeps syscall count low without a large resident buffer. */
    private int $readChunk;

    /** Suffix patterns logrotate may have used, tried in order when resuming after a gap. */
    private array $rotateSuffixes;

    /**
     * The last inode this process drained to EOF and then released.
     *
     * When a file is deleted (or rotated) while we are running we always read it to the
     * end before letting go of the descriptor, so there is provably nothing left in it.
     * Remembering which inode that was lets the "rotated while we were stopped" recovery
     * path tell the difference between "we never saw the end of that file" (a real gap
     * worth reporting) and "we finished with it two seconds ago" (nothing to report).
     * Without this, a box that deletes its logs on a cron would raise a false
     * missed-rotation alarm every single time.
     *
     * @var array{dev:int,inode:int}|null
     */
    private ?array $consumed = null;

    // ---- Counters, all surfaced through status() -----------------------------
    private int $lines = 0;
    private int $rotations = 0;
    private int $truncations = 0;
    private int $deletions = 0;
    private int $missedRotations = 0;
    private int $overlong = 0;
    private ?string $lastNote = null;
    private float $lastReadAt = 0.0;

    /** Unix time the path was first observed to be missing, or null when it is present. */
    private ?int $missingSince = null;

    /**
     * @param string   $path       Absolute path to the live log file.
     * @param callable $loadCursor fn(string $path): ?array{dev:int,inode:int,offset:int}
     * @param callable $saveCursor fn(string $path, int $dev, int $inode, int $offset): void
     * @param array    $opts       start_at, max_line_bytes, read_chunk, rotate_suffixes,
     *                             on_bad_line
     */
    public function __construct(string $path, callable $loadCursor, callable $saveCursor, array $opts = [])
    {
        $this->path = $path;
        $this->loadCursor = $loadCursor;
        $this->saveCursor = $saveCursor;

        // Default 'end': a first start on a busy box must not replay a 4 GB backlog and
        // spend a day catching up. `--from-start` on the daemon flips this.
        $this->startAt      = ($opts['start_at'] ?? 'end') === 'start' ? 'start' : 'end';
        $this->maxLineBytes = max(1024, (int) ($opts['max_line_bytes'] ?? 16384));
        $this->readChunk    = max(4096, (int) ($opts['read_chunk'] ?? 262144));
        $this->onBadLine    = $opts['on_bad_line'] ?? null;

        // Ordered most-likely-first. Only used to RE-FIND an inode we already know, so a
        // wrong guess here costs nothing: the inode check rejects it.
        $this->rotateSuffixes = $opts['rotate_suffixes'] ?? ['.1', '.0'];
    }

    /**
     * Poll the file once and hand every newly completed line to $onLine.
     *
     * $onLine receives (string $line, int $offset, string $sourcePath) where $offset is
     * the byte position of the first character of the line within the inode it came
     * from. That pair is what makes `id = sha1(file + offset)` idempotent across a
     * re-ingest, per SPEC §4.1.
     *
     * @return int Number of lines emitted during this poll.
     */
    public function poll(callable $onLine): int
    {
        $emitted = 0;

        // stat() results are cached per request; in a long-running daemon that cache is
        // the difference between noticing a rotation in one second and never noticing it.
        clearstatcache(true, $this->path);
        $st = @stat($this->path);

        // ---------------------------------------------------------------
        // Case A: we already hold a descriptor.
        // ---------------------------------------------------------------
        if (is_resource($this->fh)) {
            $fst = @fstat($this->fh);

            // Does the PATH still lead to the inode we are holding? This comparison, made
            // on every single poll, is the whole defence against case 5 above. An open
            // descriptor to a deleted file reads happily and forever; only re-stat'ing the
            // path reveals that it is no longer the file anyone is writing to.
            $sameFile = $st !== false
                && $fst !== false
                && (int) $st['dev'] === (int) $fst['dev']
                && (int) $st['ino'] === (int) $fst['ino'];

            // Direct unlink signal: an inode with no remaining directory entry. Belt and
            // braces alongside the path comparison, and the one that still works when
            // stat() on the path fails for an unrelated reason (a directory whose
            // permissions changed under us, for instance).
            $unlinked = $fst !== false && isset($fst['nlink']) && (int) $fst['nlink'] === 0;

            if ($sameFile && !$unlinked) {
                // Truncation: the file we are holding got shorter than our cursor.
                // copytruncate, `> access.log`, or a disk-full recovery. Anything we had
                // not read is gone; restart cleanly at 0 rather than reading garbage
                // from the middle of a new line.
                if ((int) $st['size'] < $this->offset) {
                    $this->truncations++;
                    $this->lastNote = 'file truncated at offset ' . $this->offset . '; restarted at 0';
                    $this->resetToOffset(0);
                }
                $this->missingSince = null;
                $emitted += $this->drain($onLine);
                $this->persist();
                return $emitted;
            }

            // *** THE ROTATION / DELETION PATH ***
            // The path now points at a different inode (rename+create), or the path has
            // vanished (moved away, unlinked, deleted by a find -mtime cron). Either way
            // our descriptor still refers to the OLD inode, which the webserver may still
            // be appending to until it is told to reopen. Drain it to EOF before letting
            // go of it. Skipping this is the single most common cause of silent nightly
            // data loss in log tailers.
            $emitted += $this->drain($onLine);

            // Checkpoint the OLD inode at its post-drain offset before letting go. If the
            // daemon dies right here, the stored cursor says "this inode is consumed up
            // to byte N", and the rotated-file recovery below will correctly find nothing
            // left to read. Without this checkpoint the cursor still holds the pre-drain
            // offset and every line we just emitted would be emitted a second time.
            $this->persist();

            // Remember that we finished this inode, so that if a NEW file appears at the
            // same path we do not go hunting for "lost" bytes that we have in fact
            // already read. See the $consumed docblock.
            $this->consumed = ['dev' => $this->dev, 'inode' => $this->inode];

            $this->closeHandle();

            if ($st === false) {
                // Path is gone. This is either a rotate script mid-flight (the file has
                // been moved and its replacement not yet created) or an outright deletion.
                // We cannot tell the two apart yet, and we do not need to: in both cases
                // the correct behaviour is to hold the cursor, note the time, and wait.
                // No busy-loop (the daemon's poll interval governs), no repeated log line.
                $this->deletions++;
                $this->missingSince = time();
                $this->lastNote = 'file disappeared (deleted, or rotated and not yet '
                    . 'replaced); drained it to EOF before releasing the descriptor';
                return $emitted;
            }

            // A different inode is present at the path: the normal rename+create rotation.
            $this->rotations++;
            $this->missingSince = null;
            $this->lastNote = $unlinked
                ? 'previous file was unlinked while open; drained to EOF and switched to the new one'
                : 'rotation detected; drained previous inode to EOF';

            // Fall through and open the new inode from its beginning.
            $emitted += $this->openAt($st, 0, $onLine);
            return $emitted;
        }

        // ---------------------------------------------------------------
        // Case B: no descriptor — first poll, or we just closed a rotated one.
        // ---------------------------------------------------------------
        if ($st === false) {
            // Configured source does not exist (yet). Not an error, and not a reason to
            // make noise on every poll: a vhost with no traffic since install has no log
            // file, and a deleted one may be recreated by the next request. The cursor is
            // kept exactly as it was, so nothing is re-read if the same inode returns.
            if ($this->missingSince === null) {
                $this->missingSince = time();
            }
            $this->lastNote = 'file does not exist (missing for '
                . (time() - $this->missingSince) . 's)';
            return $emitted;
        }

        $this->missingSince = null;
        $cursor = ($this->loadCursor)($this->path);

        if ($cursor === null) {
            // Never seen this path before.
            $start = $this->startAt === 'start' ? 0 : (int) $st['size'];
            return $emitted + $this->openAt($st, $start, $onLine);
        }

        $sameInode = (int) $cursor['dev'] === (int) $st['dev']
            && (int) $cursor['inode'] === (int) $st['ino'];

        if ($sameInode) {
            $off = (int) $cursor['offset'];
            if ((int) $st['size'] < $off) {
                // Truncated while we were not running.
                $this->truncations++;
                $this->lastNote = 'file was truncated while the daemon was stopped; restarted at 0';
                $off = 0;
            }
            return $emitted + $this->openAt($st, $off, $onLine);
        }

        // Rotation happened while we were NOT running, so there is no descriptor to
        // drain. Try to find the old inode on disk and read its tail before moving on.
        $emitted += $this->drainRotatedByInode($cursor, $onLine);

        return $emitted + $this->openAt($st, 0, $onLine);
    }

    /**
     * Open the file at $path, seek to $offset, adopt it as the current inode and drain.
     *
     * @param array $st stat() of the file we are adopting.
     */
    private function openAt(array $st, int $offset, callable $onLine): int
    {
        // 'rb' — read-only, binary. The daemon must never be able to write to a log file
        // it is only supposed to observe; it runs as group `adm` which has read access
        // and nothing more.
        $fh = @fopen($this->path, 'rb');
        if ($fh === false) {
            $this->lastNote = 'cannot open for reading (permission denied?)';
            return 0;
        }

        $this->fh    = $fh;
        $this->dev   = (int) $st['dev'];
        $this->inode = (int) $st['ino'];
        $this->resetToOffset($offset);

        $n = $this->drain($onLine);
        $this->persist();
        return $n;
    }

    /**
     * After a rotation that happened while we were stopped: locate the file that holds
     * the inode our cursor refers to, and read whatever we had not read from it.
     *
     * Matching is by INODE, never by name. `access.log.1` may be last night's file or
     * the one from three days ago depending on the rotate schedule and whether the
     * daemon has been down for a while; reading the wrong one would inject stale traffic
     * as if it were live. An inode match is proof.
     */
    private function drainRotatedByInode(array $cursor, callable $onLine): int
    {
        // Did WE finish that inode ourselves, moments ago? Then there is nothing to
        // recover and nothing to warn about. This is the common path on a box that
        // deletes its logs on a cron rather than rotating them: the file vanishes, we
        // drain and release it, a new one appears at the same path, and raising a
        // "missed rotation" alarm here would be simply wrong.
        if ($this->consumed !== null
            && (int) $this->consumed['dev'] === (int) $cursor['dev']
            && (int) $this->consumed['inode'] === (int) $cursor['inode']
        ) {
            $this->lastNote = 'previous file was fully read before it disappeared; '
                . 'starting the replacement from the beginning';
            return 0;
        }

        $candidates = [];
        foreach ($this->rotateSuffixes as $suffix) {
            $candidates[] = $this->path . $suffix;
        }
        // Date-stamped rotations (`dateext`): access.log-20260910 and similar.
        foreach (glob($this->path . '-*') ?: [] as $g) {
            $candidates[] = $g;
        }

        foreach ($candidates as $candidate) {
            if (str_ends_with($candidate, '.gz') || str_ends_with($candidate, '.bz2')
                || str_ends_with($candidate, '.xz') || str_ends_with($candidate, '.zst')) {
                // A compressed rotation is a NEW inode; the original is unlinked. There
                // is nothing here that can match our cursor, so do not waste a stat.
                continue;
            }
            clearstatcache(true, $candidate);
            $cst = @stat($candidate);
            if ($cst === false) {
                continue;
            }
            if ((int) $cst['dev'] !== (int) $cursor['dev'] || (int) $cst['ino'] !== (int) $cursor['inode']) {
                continue;
            }

            // Found it. Read from where we left off to the end of that file.
            $fh = @fopen($candidate, 'rb');
            if ($fh === false) {
                continue;
            }
            $saveFh = $this->fh;
            $this->fh = $fh;
            $this->resetToOffset(min((int) $cursor['offset'], (int) $cst['size']));
            $n = $this->drain($onLine);
            // Checkpoint against the OLD inode so a crash between here and adopting the
            // new file cannot cause these lines to be replayed on the next start.
            ($this->saveCursor)($this->path, (int) $cursor['dev'], (int) $cursor['inode'], $this->offset);
            fclose($fh);
            $this->fh = $saveFh;

            $this->rotations++;
            $this->lastNote = 'resumed and drained rotated file ' . basename($candidate);
            return $n;
        }

        // Nothing matched. Either the rotated copy was compressed (its inode is gone) or
        // it has already been pruned by `rotate N`. Those bytes are unrecoverable; count
        // and report it rather than silently starting from zero as if all were well.
        $this->missedRotations++;
        $this->lastNote = 'rotation happened while stopped and the previous inode could not be '
            . 'found (compressed or pruned); some lines were not ingested';
        return 0;
    }

    /**
     * Read from the current descriptor to EOF, emitting every complete line.
     *
     * Only bytes that end in "\n" are committed; a trailing partial line stays in
     * $pending and is completed on a later poll. The file position of $fh is always
     * $this->offset + strlen($this->pending), which is why this never seeks during a
     * normal read.
     */
    private function drain(callable $onLine): int
    {
        if (!is_resource($this->fh)) {
            return 0;
        }

        $emitted = 0;

        while (true) {
            $buf = @fread($this->fh, $this->readChunk);
            if ($buf === false || $buf === '') {
                break; // EOF, or a read error we will retry on the next poll.
            }
            $this->lastReadAt = microtime(true);
            $this->pending .= $buf;

            // Split out every complete line in the buffer.
            $pos = 0;
            while (($nl = strpos($this->pending, "\n", $pos)) !== false) {
                $line = substr($this->pending, $pos, $nl - $pos);
                $lineOffset = $this->offset + $pos;
                // Tolerate CRLF, which appears when logs are written on or copied from
                // a Windows host, and skip blank lines rather than counting them as
                // parse errors.
                $line = rtrim($line, "\r");

                if (strlen($line) > $this->maxLineBytes) {
                    // A complete but absurdly long line. No real access-log line reaches
                    // 16 KB; this is a corrupted region, an embedded binary blob, or a
                    // deliberately enormous request URI. Report it and move on rather
                    // than pushing a multi-megabyte document into Solr.
                    $this->overlong++;
                    if ($this->onBadLine !== null) {
                        ($this->onBadLine)(
                            substr($line, 0, 512),
                            $lineOffset,
                            'line of ' . strlen($line) . ' bytes exceeds max_line_bytes ('
                                . $this->maxLineBytes . ')'
                        );
                    }
                } elseif ($line !== '') {
                    $onLine($line, $lineOffset, $this->path);
                    $this->lines++;
                    $emitted++;
                }
                $pos = $nl + 1;
            }

            if ($pos > 0) {
                $this->offset += $pos;
                $this->pending = substr($this->pending, $pos);
            }

            // Second guard, for the case the loop above cannot catch: bytes that contain
            // NO newline at all. Left alone this buffer would grow until the process ran
            // out of memory, so once it passes the limit it is dropped, reported, and the
            // cursor jumps past it. Never grow the buffer without bound.
            if (strlen($this->pending) > $this->maxLineBytes) {
                $this->overlong++;
                if ($this->onBadLine !== null) {
                    ($this->onBadLine)(
                        substr($this->pending, 0, 512),
                        $this->offset,
                        'line exceeded max_line_bytes (' . $this->maxLineBytes . ') with no newline'
                    );
                }
                $this->offset += strlen($this->pending);
                $this->pending = '';
                // The descriptor is already positioned here, but be explicit: an
                // inconsistency between $offset and the file position corrupts every
                // subsequent document id.
                @fseek($this->fh, $this->offset, SEEK_SET);
            }

            if (strlen($buf) < $this->readChunk) {
                break; // Short read means we reached EOF.
            }
        }

        return $emitted;
    }

    /**
     * Point the current descriptor and all buffered state at a specific byte offset.
     */
    private function resetToOffset(int $offset): void
    {
        $this->offset = max(0, $offset);
        $this->pending = '';
        if (is_resource($this->fh)) {
            @fseek($this->fh, $this->offset, SEEK_SET);
        }
    }

    /**
     * Persist the cursor so a restart resumes exactly where we stopped.
     *
     * Called after every drain rather than on a timer: the cost is one small SQLite
     * write per poll, and the alternative is re-ingesting (or losing) whatever happened
     * between the last checkpoint and a crash.
     */
    private function persist(): void
    {
        ($this->saveCursor)($this->path, $this->dev, $this->inode, $this->offset);
    }

    /**
     * Release the descriptor without disturbing the committed offset.
     */
    private function closeHandle(): void
    {
        if (is_resource($this->fh)) {
            @fclose($this->fh);
        }
        $this->fh = null;
        $this->pending = '';
    }

    /**
     * Close cleanly, checkpointing first. Called on SIGTERM so a restart does not
     * re-read or skip anything.
     */
    public function close(): void
    {
        if (is_resource($this->fh)) {
            $this->persist();
        }
        $this->closeHandle();
    }

    /**
     * Machine-readable state for `loghound-tail --status`.
     *
     * lag_bytes is the honest measure of whether ingestion is keeping up: it is how many
     * bytes exist in the file past our committed offset right now.
     *
     * @return array<string,mixed>
     */
    public function status(): array
    {
        clearstatcache(true, $this->path);
        $st = @stat($this->path);
        $size = $st === false ? null : (int) $st['size'];

        return [
            'path'             => $this->path,
            'exists'           => $st !== false,
            'dev'              => $this->dev,
            'inode'            => $this->inode,
            'offset'           => $this->offset,
            'size'             => $size,
            // Negative lag would mean the file shrank under us — surfaced as 0 with the
            // truncation counter telling the real story.
            'lag_bytes'        => $size === null ? null : max(0, $size - $this->offset),
            'pending_bytes'    => strlen($this->pending),
            'lines'            => $this->lines,
            'rotations'        => $this->rotations,
            'truncations'      => $this->truncations,
            // How many times the file we were reading was deleted or moved away out from
            // under us. On a box with a `find -mtime +N -delete` cron this ticks up on a
            // schedule and is entirely normal; a sudden jump is worth a look.
            'deletions'        => $this->deletions,
            'missing_since'    => $this->missingSince === null
                ? null
                : gmdate('Y-m-d\TH:i:s\Z', $this->missingSince),
            'missing_for_sec'  => $this->missingSince === null ? null : time() - $this->missingSince,
            'missed_rotations' => $this->missedRotations,
            'overlong_lines'   => $this->overlong,
            'last_read_at'     => $this->lastReadAt > 0 ? gmdate('Y-m-d\TH:i:s\Z', (int) $this->lastReadAt) : null,
            'note'             => $this->lastNote,
        ];
    }

    /** Path this tailer is following. */
    public function path(): string
    {
        return $this->path;
    }

    /** Total lines emitted since the process started. */
    public function lineCount(): int
    {
        return $this->lines;
    }
}
