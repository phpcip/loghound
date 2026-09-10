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

    /** Counters, all surfaced through status(). */
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
     * `start_at` defaults to 'end' because a first start on a busy box must not replay a
     * 4 GB backlog and spend a day catching up; the daemon's `--from-start` flips it.
     *
     * `rotate_suffixes` is ordered most-likely-first and defaults to ['.1', '.0']. It is
     * only ever used to RE-FIND an inode we already know, so a wrong guess here costs
     * nothing: the inode check in drainRotatedByInode() rejects a candidate that does not
     * match.
     *
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

        $this->startAt      = ($opts['start_at'] ?? 'end') === 'start' ? 'start' : 'end';
        $this->maxLineBytes = max(1024, (int) ($opts['max_line_bytes'] ?? 16384));
        $this->readChunk    = max(4096, (int) ($opts['read_chunk'] ?? 262144));
        $this->onBadLine    = $opts['on_bad_line'] ?? null;

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
     * The poll has two halves, and the numbered cases they handle are the ones set out in
     * the WHY THIS IS HARD notes at the top of this file.
     *
     * Case A — a descriptor is already open. Every poll re-stats the PATH and compares
     * (dev, inode) against fstat() of the descriptor rather than trusting the descriptor
     * it already holds: an open descriptor to a deleted file reads happily and forever, so
     * this comparison is the entire defence against a tailer that reports healthy while
     * ingesting nothing (case 5). st_nlink == 0 on the open descriptor is checked
     * alongside it as a direct "this inode has no name any more" signal, which still works
     * when stat() on the path fails for an unrelated reason such as a parent directory
     * whose permissions changed under us. When the path and the descriptor still agree, a
     * size below the committed offset means truncation (copytruncate, `> access.log`, a
     * disk-full recovery): whatever we had not read is gone, so we restart cleanly at 0
     * rather than reading garbage from the middle of a line. When they disagree, the old
     * inode is drained to EOF before the descriptor is released — the webserver may still
     * be appending to it until it is told to reopen, and skipping that drain is the single
     * most common cause of silent nightly data loss in log tailers — then the cursor is
     * checkpointed against the OLD inode, because a crash between the drain and the
     * checkpoint would emit every one of those lines a second time on the next start. If
     * the path has vanished entirely rather than been replaced, we cannot yet tell a
     * rotate script mid-flight from an outright deletion, and we do not need to: in both
     * cases the right behaviour is to hold the cursor, record the time it went away, and
     * wait — no busy-loop, since the daemon's poll interval governs, and no repeated log
     * line filling the journal.
     *
     * Case B — no descriptor, meaning the first poll or the one right after a rotation was
     * handled. A missing path is not an error and not a reason to make noise on every
     * poll: a vhost with no traffic since install has no log file yet, and a deleted one
     * may be recreated by the next request, so the cursor is held untouched and nothing is
     * re-read if the same inode comes back. A cursor whose inode still matches resumes at
     * the stored offset, subject to the recycled-inode check in
     * offsetIsAtLineBoundary(). A cursor whose inode does not match means a rotation
     * happened while we were not running, with no descriptor left to drain, so the old
     * inode is hunted down on disk first.
     *
     * clearstatcache() is not optional here. stat() results are cached per request, and in
     * a long-running daemon that cache is the difference between noticing a rotation
     * within one second and never noticing it at all.
     *
     * @return int Number of lines emitted during this poll.
     */
    public function poll(callable $onLine): int
    {
        $emitted = 0;

        clearstatcache(true, $this->path);
        $st = @stat($this->path);

        if (is_resource($this->fh)) {
            $fst = @fstat($this->fh);

            $sameFile = $st !== false
                && $fst !== false
                && (int) $st['dev'] === (int) $fst['dev']
                && (int) $st['ino'] === (int) $fst['ino'];

            $unlinked = $fst !== false && isset($fst['nlink']) && (int) $fst['nlink'] === 0;

            if ($sameFile && !$unlinked) {
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

            $emitted += $this->drain($onLine);

            $this->persist();

            $this->consumed = ['dev' => $this->dev, 'inode' => $this->inode];

            $this->closeHandle();

            if ($st === false) {
                $this->deletions++;
                $this->missingSince = time();
                $this->lastNote = 'file disappeared (deleted, or rotated and not yet '
                    . 'replaced); drained it to EOF before releasing the descriptor';
                return $emitted;
            }

            $this->rotations++;
            $this->missingSince = null;
            $this->lastNote = $unlinked
                ? 'previous file was unlinked while open; drained to EOF and switched to the new one'
                : 'rotation detected; drained previous inode to EOF';

            $emitted += $this->openAt($st, 0, $onLine);
            return $emitted;
        }

        if ($st === false) {
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
            $start = $this->startAt === 'start' ? 0 : (int) $st['size'];
            return $emitted + $this->openAt($st, $start, $onLine);
        }

        $sameInode = (int) $cursor['dev'] === (int) $st['dev']
            && (int) $cursor['inode'] === (int) $st['ino'];

        if ($sameInode) {
            $off = (int) $cursor['offset'];
            if ((int) $st['size'] < $off) {
                $this->truncations++;
                $this->lastNote = 'file was truncated while the daemon was stopped; restarted at 0';
                $off = 0;
            } elseif ($off > 0 && !$this->offsetIsAtLineBoundary($off)) {
                $this->missedRotations++;
                $this->lastNote = 'inode matched but the cursor was not at a line boundary; '
                    . 'the inode was recycled by a rotation, restarted at 0';
                $off = 0;
            }
            return $emitted + $this->openAt($st, $off, $onLine);
        }

        $emitted += $this->drainRotatedByInode($cursor, $onLine);

        return $emitted + $this->openAt($st, 0, $onLine);
    }

    /**
     * Open the file at $path, seek to $offset, adopt it as the current inode and drain.
     *
     * The mode is 'rb' — read-only, binary — and never anything else. The daemon must not
     * be able to write to a log file it is only supposed to observe; it runs as group
     * `adm`, which has read access and nothing more.
     *
     * @param array $st stat() of the file we are adopting.
     */
    private function openAt(array $st, int $offset, callable $onLine): int
    {
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
     *
     * The first test is whether WE finished that inode ourselves moments ago, in which
     * case there is nothing to recover and nothing to warn about. That is the common path
     * on a box that deletes its logs on a cron rather than rotating them: the file
     * vanishes, we drain and release it, a new one appears at the same path, and raising a
     * "missed rotation" alarm there would be simply wrong.
     *
     * Candidates are the configured rotate suffixes plus date-stamped rotations, which
     * `dateext` writes as access.log-20260910 and similar.
     *
     * Once the tail of the matched file has been read, the cursor is saved against the OLD
     * inode, so that a crash between that point and adopting the new file cannot replay
     * those lines on the next start.
     *
     * Compressed candidates are skipped without even a stat(): compression creates a NEW
     * inode and unlinks the original, so nothing behind a .gz/.bz2/.xz/.zst name can ever
     * match our cursor. When no candidate matches, the rotated copy was either compressed
     * or already pruned by `rotate N`; those bytes are unrecoverable, and the loss is
     * counted and reported rather than passed over by silently starting from zero as if
     * all were well.
     */
    private function drainRotatedByInode(array $cursor, callable $onLine): int
    {
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
        foreach (glob($this->path . '-*') ?: [] as $g) {
            $candidates[] = $g;
        }

        foreach ($candidates as $candidate) {
            if (str_ends_with($candidate, '.gz') || str_ends_with($candidate, '.bz2')
                || str_ends_with($candidate, '.xz') || str_ends_with($candidate, '.zst')) {
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

            $fh = @fopen($candidate, 'rb');
            if ($fh === false) {
                continue;
            }
            $saveFh = $this->fh;
            $this->fh = $fh;
            $this->resetToOffset(min((int) $cursor['offset'], (int) $cst['size']));
            $n = $this->drain($onLine);
            ($this->saveCursor)($this->path, (int) $cursor['dev'], (int) $cursor['inode'], $this->offset);
            fclose($fh);
            $this->fh = $saveFh;

            $this->rotations++;
            $this->lastNote = 'resumed and drained rotated file ' . basename($candidate);
            return $n;
        }

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
     *
     * CRLF is tolerated, because logs written on or copied from a Windows host carry it,
     * and blank lines are skipped rather than counted as parse errors.
     *
     * Two separate guards keep a hostile or corrupted file from exhausting memory. The
     * first catches a complete but absurdly long line: no real access-log line reaches
     * 16 KB, so what arrives is a corrupted region, an embedded binary blob or a
     * deliberately enormous request URI, and it is reported and skipped instead of being
     * pushed into Solr as a multi-megabyte document. The second catches what the first
     * cannot see — a run of bytes containing NO newline at all, which left alone would
     * grow the buffer until the process ran out of memory. Once past the limit that buffer
     * is dropped, reported, and the cursor jumps past it, with an explicit fseek() to keep
     * $offset and the descriptor's position in step: an inconsistency between the two
     * corrupts the id of every document that follows.
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
                break;
            }
            $this->lastReadAt = microtime(true);
            $this->pending .= $buf;

            $pos = 0;
            while (($nl = strpos($this->pending, "\n", $pos)) !== false) {
                $line = substr($this->pending, $pos, $nl - $pos);
                $lineOffset = $this->offset + $pos;
                $line = rtrim($line, "\r");

                if (strlen($line) > $this->maxLineBytes) {
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
                @fseek($this->fh, $this->offset, SEEK_SET);
            }

            if (strlen($buf) < $this->readChunk) {
                break;
            }
        }

        return $emitted;
    }

    /**
     * Is the stored cursor sitting immediately after a newline?
     *
     * Used on startup to detect a recycled inode. Inode numbers are RECYCLED: on ext4 a
     * logrotate cycle that renames access.log to access.log.1, compresses it, unlinks the
     * original and creates a fresh access.log routinely hands the new file the inode just
     * freed by the old one. The dev+inode pair then matches a cursor belonging to a file
     * that no longer exists, and resuming at the stored offset silently skips the
     * beginning of the new file — the tailer looks healthy and quietly drops lines, which
     * is the worst failure this class has.
     *
     * Only complete lines are ever committed, so a cursor that belongs to this file always
     * has "\n" at offset-1. If it does not, the inode number matches by coincidence rather
     * than by identity and the cursor must be discarded. Checking that one byte is enough
     * to tell a genuine resume from a recycled inode, and it costs a single read of a
     * single byte per startup.
     *
     * Deliberately conservative: any read failure returns true, so an unreadable
     * or unusual file resumes as before rather than being re-ingested from the
     * beginning. Duplicate ingestion is bounded and idempotent (document ids are
     * derived from file+offset); a spurious restart at 0 on every poll would not be.
     */
    private function offsetIsAtLineBoundary(int $offset): bool
    {
        if ($offset <= 0) {
            return true;
        }
        $fh = @fopen($this->path, 'rb');
        if ($fh === false) {
            return true;
        }
        $ok = true;
        if (@fseek($fh, $offset - 1) === 0) {
            $byte = @fread($fh, 1);
            if ($byte !== false && $byte !== '') {
                $ok = ($byte === "\n");
            }
        }
        fclose($fh);
        return $ok;
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
     * bytes exist in the file past our committed offset right now. A negative value would
     * mean the file shrank under us, so it is surfaced as 0 and the truncation counter
     * tells the real story instead.
     *
     * deletions counts how many times the file we were reading was deleted or moved away
     * out from under us. On a box with a `find -mtime +N -delete` cron it ticks up on a
     * schedule and is entirely normal; a sudden jump is worth a look.
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
            'lag_bytes'        => $size === null ? null : max(0, $size - $this->offset),
            'pending_bytes'    => strlen($this->pending),
            'lines'            => $this->lines,
            'rotations'        => $this->rotations,
            'truncations'      => $this->truncations,
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
