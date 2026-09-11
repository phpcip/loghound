<?php
/**
 * Loghound — reading the access logs as they are written, without touching ingest.
 *
 * ---------------------------------------------------------------------------------
 * A SECOND READER, AND NOTHING ELSE
 * ---------------------------------------------------------------------------------
 * \Loghound\Tail is the ingest tailer. It owns a cursor, it persists that cursor to
 * var/state.db, and losing a byte of it loses a log line for ever. This class must never be
 * confused with it. It opens the same files with fopen($path, 'rb'), it seeks, it reads, and
 * that is the complete list of things it does to the filesystem. No cursor is stored, no
 * offset is written, no lock is taken, nothing is created. Two readers on one file is fine on
 * every platform this runs on; a second WRITER of the ingest cursor would not be, which is why
 * there is not one.
 *
 * The cursor for this class lives in the BROWSER, as the SSE event id, and comes back on
 * reconnect. It is therefore untrusted, and is treated as untrusted: it can only name an
 * offset inside a file this class already resolved from the configuration, it is checked
 * against the inode it claims, and anything that does not add up starts at end-of-file. The
 * worst a forged cursor achieves is re-reading a file the operator is already authorised to
 * see the contents of.
 *
 * ---------------------------------------------------------------------------------
 * WHICH FILES, AND WHICH LINES
 * ---------------------------------------------------------------------------------
 * The files come from `sources` in the configuration and from nowhere else — never from a
 * request parameter. Each configured pattern is expanded with glob() and every expansion is
 * re-checked against `allowed_log_roots` with Security::safePath(), exactly as
 * bin/loghound-tail does it, because a glob expanded at read time is a different thing from a
 * pattern validated at save time.
 *
 * A HOST IS NOT A FILE. One file can carry several virtual hosts — `other_vhosts_access.log`
 * is precisely that, with %v at the front of every line — and one host can be written to more
 * than one file. So the host selection is applied to the PARSED LINE and not to the filename:
 * a file is skipped up front only when the operator pinned it to a single host in the
 * configuration and that host is not selected. Everything else is read and filtered line by
 * line.
 *
 * ---------------------------------------------------------------------------------
 * PARTIAL LINES AND ROTATION
 * ---------------------------------------------------------------------------------
 * A webserver's write is not atomic from here, so the last line of a read is routinely half
 * written. Bytes are only ever committed past a terminating newline; the tail sits in an
 * in-memory buffer for the life of the connection and the published cursor points at the
 * first byte that has NOT been handed to the browser. A reconnect therefore re-reads the
 * partial line rather than starting after it.
 *
 * On rotation the open descriptor is drained to end-of-file FIRST and only then swapped for
 * the new inode — the same rule \Loghound\Tail is built around, for the same reason: between
 * the rename and the webserver's reopen there are still new lines arriving in the old file.
 * Here it costs a few lines that would otherwise be missed from the screen rather than from
 * the index, but getting it wrong in one reader and right in the other would make the live
 * page disagree with the data every night at midnight, which is worse than either.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Live;

use Loghound\Config;
use Loghound\LogDetect;
use Loghound\LogFormat;
use Loghound\Parser;
use Loghound\Score\Attacks;
use Loghound\Security;
use SQLite3;

final class Reader
{
    /** Files read at once. A machine with more log sources than this has a different problem. */
    public const MAX_SOURCES = 32;

    /** Bytes taken from one file in one poll. */
    private const READ_CHUNK = 262144;

    /** Rows handed to the browser in one poll, across every file. */
    private const LINE_BUDGET = 400;

    /** Unterminated bytes held for a line that never ends. Beyond this the buffer is dropped. */
    private const MAX_PENDING = 1048576;

    /** The shape a cursor must have before any part of it is believed. */
    private const CURSOR_RE = '/^\d{1,3}:\d{1,20}:\d{1,20}(?:,\d{1,3}:\d{1,20}:\d{1,20})*$/D';

    private Config $cfg;

    private Parser $parser;

    /**
     * The resolved log files, in a stable order, each with the format and host override the
     * configuration gave it.
     *
     * @var array<int,array{path:string,format:string,host:?string,label:string}>
     */
    private array $sources = [];

    /** @var array<int,resource> Open read-only descriptors, keyed by source index. */
    private array $handles = [];

    /** @var array<int,int> First byte of each file not yet handed to the browser. */
    private array $committed = [];

    /** @var array<int,string> Bytes read past that offset which do not yet end in a newline. */
    private array $pending = [];

    /** @var array<int,int> The inode each open descriptor refers to. */
    private array $inodes = [];

    /** @var array<string,LogFormat|null> Compiled formats, memoised by their configured name. */
    private array $formats = [];

    /** @var array<int,string> Hosts the operator has selected, or empty for all of them. */
    private array $hosts;

    /** The operator's display filter, applied to every row before it goes on the wire. */
    private Rules $rules;

    /** The read-only handle on the enrichment cache the ingest daemon fills, or null. */
    private ?SQLite3 $cache = null;

    /** Have we already tried and failed to open that cache? */
    private bool $cacheTried = false;

    /** @var array<string,array<string,mixed>|null> Per-connection memo of geo lookups. */
    private array $geoMemo = [];

    /** @var array<string,array<string,mixed>|null> Per-connection memo of network lookups. */
    private array $asnMemo = [];

    /** Lines that did not match their source's format since the connection opened. */
    private int $unparsed = 0;

    /** Why the most recent one did not. */
    private string $unparsedWhy = '';

    /**
     * @param array<int,string> $hosts Virtual hosts to keep, or an empty list for every host.
     */
    public function __construct(Config $cfg, array $hosts = [], ?Rules $rules = null)
    {
        $this->cfg = $cfg;
        $this->rules = $rules ?? Rules::fromConfig($cfg);
        $this->hosts = array_values(array_filter(array_map(
            static fn ($h): string => is_string($h) ? strtolower(trim($h)) : '',
            $hosts
        ), static fn (string $h): bool => $h !== ''));

        $own = Config::selfEndpoints((string) $cfg->get('base_url', ''));
        $this->parser = new Parser([
            'ip_mode'       => (string) $cfg->get('privacy.ip_mode', 'full'),
            'ip_salt'       => (string) $cfg->get('privacy.ip_salt', ''),
            'keep_raw'      => true,
            'search_params' => (array) $cfg->get('beacon.query_params', []),
            'install_id'    => (string) $cfg->get('solr.install_id', ''),
            'own_host'      => (string) $own['host'],
            'own_paths'     => (array) $own['paths'],
        ]);

        $this->resolveSources();
    }

    /**
     * The files this reader will watch, for the page to name before a line has arrived.
     *
     * @return array<int,array{label:string,host:?string,format:string,readable:bool}>
     */
    public function watching(): array
    {
        $out = [];
        foreach ($this->sources as $src) {
            $out[] = [
                'label'    => $src['label'],
                'host'     => $src['host'],
                'format'   => $src['format'],
                'readable' => is_readable($src['path']),
            ];
        }
        return $out;
    }

    /**
     * Open every file, at the position a cursor names or at end-of-file.
     *
     * END-OF-FILE IS THE DEFAULT AND THE HONEST ONE. A live page that opened at the start of a
     * rotated log would spend its first minute replaying yesterday under a heading that says
     * "now". A cursor is only honoured when the inode it names is still the inode at that path,
     * so a stream resumed across a rotation starts at the end of the new file rather than at a
     * byte offset that means something else entirely.
     */
    public function open(string $cursor = ''): void
    {
        $positions = $this->parseCursor($cursor);

        foreach ($this->sources as $i => $src) {
            $fh = @fopen($src['path'], 'rb');
            if ($fh === false) {
                continue;
            }

            $st = @fstat($fh);
            $size = is_array($st) ? (int) ($st['size'] ?? 0) : 0;
            $inode = is_array($st) ? (int) ($st['ino'] ?? 0) : 0;

            $want = $positions[$i] ?? null;
            $at = $size;
            if ($want !== null && $want['inode'] === $inode && $want['offset'] <= $size) {
                $at = $want['offset'];
            }

            @fseek($fh, $at);
            $this->handles[$i]   = $fh;
            $this->committed[$i] = $at;
            $this->pending[$i]   = '';
            $this->inodes[$i]    = $inode;
        }
    }

    /** Close every descriptor. Called on the way out of a stream. */
    public function close(): void
    {
        foreach ($this->handles as $fh) {
            if (is_resource($fh)) {
                @fclose($fh);
            }
        }
        $this->handles = [];

        if ($this->cache instanceof SQLite3) {
            @$this->cache->close();
            $this->cache = null;
        }
    }

    /**
     * Read whatever has been appended since the last call.
     *
     * The line budget is a ceiling on what one poll hands over, not a filter: lines past it
     * stay in the buffer with the cursor still behind them, and come out on the next poll. So
     * a burst arrives late rather than partially, and `lag` says how many bytes are still
     * unread when it does. Nothing is silently dropped except a single "line" longer than a
     * megabyte, which is not a log line.
     *
     * @return array{rows:array<int,array<string,mixed>>,cursor:string,lag:int,unparsed:int,unparsed_why:string,dropped:int}
     */
    public function poll(): array
    {
        $rows = [];
        $lag = 0;
        $dropped = 0;
        $excluded = 0;
        $budget = self::LINE_BUDGET;

        foreach ($this->sources as $i => $src) {
            if (!isset($this->handles[$i]) || !is_resource($this->handles[$i])) {
                continue;
            }
            $fh = $this->handles[$i];

            $st = @fstat($fh);
            if (!is_array($st)) {
                continue;
            }
            $size = (int) ($st['size'] ?? 0);
            $at = $this->committed[$i] + strlen($this->pending[$i]);

            if ($size < $at) {
                $this->committed[$i] = 0;
                $this->pending[$i] = '';
                $at = 0;
            }

            if ($size > $at) {
                @fseek($fh, $at);
                $chunk = @fread($fh, (int) min(self::READ_CHUNK, $size - $at));
                if (is_string($chunk) && $chunk !== '') {
                    $this->pending[$i] .= $chunk;
                }
            }

            while ($budget > 0) {
                $nl = strpos($this->pending[$i], "\n");
                if ($nl === false) {
                    break;
                }
                $line = rtrim(substr($this->pending[$i], 0, $nl), "\r");
                $offset = $this->committed[$i];

                $this->pending[$i] = substr($this->pending[$i], $nl + 1);
                $this->committed[$i] += $nl + 1;

                if ($line === '') {
                    continue;
                }

                $row = $this->translate($line, $i, $offset);
                if ($row !== null) {
                    if ($this->rules->excludes($row)) {
                        $excluded++;
                        continue;
                    }
                    $rows[] = $row;
                    $budget--;
                }
            }

            if (strlen($this->pending[$i]) > self::MAX_PENDING) {
                $this->committed[$i] += strlen($this->pending[$i]);
                $this->pending[$i] = '';
                $dropped++;
            }

            $lag += max(0, $size - ($this->committed[$i] + strlen($this->pending[$i])));

            $this->followRotation($i, $size);
        }

        return [
            'rows'         => $rows,
            'cursor'       => $this->cursor(),
            'lag'          => $lag,
            'unparsed'     => $this->unparsed,
            'unparsed_why' => $this->unparsedWhy,
            'dropped'      => $dropped,
            'excluded'     => $excluded,
        ];
    }

    /**
     * The position of every file, as one line of digits the browser gives back on reconnect.
     */
    public function cursor(): string
    {
        $parts = [];
        foreach ($this->sources as $i => $src) {
            if (!isset($this->committed[$i])) {
                continue;
            }
            $parts[] = $i . ':' . ($this->inodes[$i] ?? 0) . ':' . $this->committed[$i];
        }
        return implode(',', $parts);
    }

    /** How many files were actually opened. Zero is a state the page has to explain. */
    public function openCount(): int
    {
        return count($this->handles);
    }

    /** How many files the configuration pointed at, whether or not they opened. */
    public function sourceCount(): int
    {
        return count($this->sources);
    }

    /**
     * Swap to the new inode once the old one has been read to its end.
     *
     * DRAIN FIRST. Under the rename-and-create rotation every Debian webserver ships with, the
     * server keeps writing to the renamed file until it is told to reopen, so a reader that
     * jumps to the new inode the instant the path changes skips everything written in between.
     * The swap therefore waits until this poll has consumed the old descriptor to its end.
     */
    private function followRotation(int $i, int $size): void
    {
        if ($this->committed[$i] + strlen($this->pending[$i]) < $size) {
            return;
        }

        $path = $this->sources[$i]['path'];
        clearstatcache(true, $path);
        $st = @stat($path);
        if (!is_array($st)) {
            return;
        }

        $inode = (int) ($st['ino'] ?? 0);
        if ($inode === ($this->inodes[$i] ?? 0)) {
            return;
        }

        $fh = @fopen($path, 'rb');
        if ($fh === false) {
            return;
        }

        if (is_resource($this->handles[$i])) {
            @fclose($this->handles[$i]);
        }
        $this->handles[$i]   = $fh;
        $this->committed[$i] = 0;
        $this->pending[$i]   = '';
        $this->inodes[$i]    = $inode;
    }

    /**
     * Expand the configured sources into the list of files this reader may open.
     *
     * The same three gates bin/loghound-tail applies, in the same order: the entry may be
     * switched off, the pattern is bounded before glob() does any filesystem work, and every
     * expansion is resolved against `allowed_log_roots`. A path that fails any of them is not
     * read, and no request parameter participates in the decision at any point.
     */
    private function resolveSources(): void
    {
        $roots = (array) $this->cfg->get('allowed_log_roots', ['/var/log']);
        $seen = [];

        foreach ((array) $this->cfg->get('sources', []) as $src) {
            if (count($this->sources) >= self::MAX_SOURCES) {
                break;
            }
            if (!is_array($src)) {
                continue;
            }
            $pattern = (string) ($src['path'] ?? '');
            if ($pattern === '' || !Config::sourceEnabled($src)) {
                continue;
            }
            if (strlen($pattern) > 512 || substr_count($pattern, '*') > 4 || str_contains($pattern, '{')) {
                continue;
            }

            $host = isset($src['host']) && is_string($src['host']) && trim($src['host']) !== ''
                ? strtolower(trim($src['host']))
                : null;

            if ($host !== null && $this->hosts !== [] && !in_array($host, $this->hosts, true)) {
                continue;
            }

            $matches = glob($pattern) ?: [];
            if ($matches === [] && is_file($pattern)) {
                $matches = [$pattern];
            }

            foreach ($matches as $file) {
                if (count($this->sources) >= self::MAX_SOURCES) {
                    break;
                }
                $real = Security::safePath($file, $roots);
                if ($real === null || isset($seen[$real]) || !is_readable($real)) {
                    continue;
                }
                $seen[$real] = true;
                $this->sources[] = [
                    'path'   => $real,
                    'format' => (string) ($src['format'] ?? 'combined'),
                    'host'   => $host,
                    'label'  => basename($real),
                ];
            }
        }
    }

    /**
     * Turn one raw line into the row the browser renders, or null when it is not shown.
     *
     * Null covers three different things and that is deliberate: a line that did not match its
     * format (counted, and the reason reported once rather than per line), a line belonging to
     * a virtual host the operator has filtered out, and Loghound's own instrumentation, which
     * is excluded from the index for the same reason and would be noise here.
     *
     * @return array<string,mixed>|null
     */
    private function translate(string $line, int $index, int $offset): ?array
    {
        $src = $this->sources[$index];
        $fmt = $this->format($src['format']);
        if ($fmt === null) {
            return null;
        }

        $this->parser->setSourceHost($src['host']);

        try {
            $doc = $this->parser->parseLine($fmt, $line, $src['path'], $offset);
        } catch (\Throwable $e) {
            $doc = null;
        }

        if ($doc === null) {
            $this->unparsed++;
            $this->unparsedWhy = (string) $this->parser->lastError();
            return null;
        }

        $host = isset($doc['host_s']) ? (string) $doc['host_s'] : null;
        if ($this->hosts !== [] && ($host === null || !in_array(strtolower($host), $this->hosts, true))) {
            return null;
        }

        if (!empty($doc['_self_b'])) {
            return null;
        }

        $doc = Attacks::apply($doc);

        return $this->shape($doc, $src, $index, $offset);
    }

    /**
     * The row, as the browser receives it.
     *
     * STORED VALUES TRAVEL WHERE A VOCABULARY EXISTS FOR THEM. `hit_flags_ss`, `referer_type_s`
     * and `as_type_s` are handed over as the slugs they are, because Panel\Vocabulary already
     * reaches the browser in the boot payload and translating them here would be a second copy
     * of wording that has one home. Everything without a vocabulary — the request kind, the
     * one-line reading — is turned into words on this side, once.
     *
     * @param array<string,mixed> $doc
     * @param array{path:string,format:string,host:?string,label:string} $src
     * @return array<string,mixed>
     */
    private function shape(array $doc, array $src, int $index, int $offset): array
    {
        $ip = isset($doc['ip_s']) ? (string) $doc['ip_s'] : null;
        $flags = isset($doc['hit_flags_ss']) ? array_values((array) $doc['hit_flags_ss']) : [];

        $geo = $ip === null ? [] : $this->geo($ip);
        $net = $ip === null ? [] : $this->network($ip);

        return [
            'id'      => $index . '-' . $offset,
            'ts'      => (string) ($doc['ts'] ?? ''),
            'host'    => isset($doc['host_s']) ? (string) $doc['host_s'] : null,
            'file'    => $src['label'],

            'method'  => isset($doc['method_s']) ? (string) $doc['method_s'] : null,
            'path'    => (string) ($doc['path_s'] ?? ''),
            'query'   => isset($doc['query_s']) ? (string) $doc['query_s'] : null,
            'proto'   => isset($doc['proto_s']) ? (string) $doc['proto_s'] : null,
            'status'  => isset($doc['status_i']) ? (int) $doc['status_i'] : null,
            'status_class' => isset($doc['status_class_s']) ? (string) $doc['status_class_s'] : null,
            'bytes'   => isset($doc['bytes_l']) ? (int) $doc['bytes_l'] : null,
            'dur_us'  => isset($doc['dur_us_l']) ? (int) $doc['dur_us_l'] : null,

            'kind'       => self::kindWord((string) ($doc['kind_s'] ?? ''), $doc['asset_kind_s'] ?? null),
            'kind_slug'  => (string) ($doc['kind_s'] ?? ''),

            'ip'      => $ip,
            'ip_ver'  => isset($doc['ip_ver_i']) ? (int) $doc['ip_ver_i'] : null,

            'country' => $geo['country_s'] ?? null,
            'region'  => $geo['region_s'] ?? null,
            'city'    => $geo['city_s'] ?? null,
            'tz'      => $geo['tz_s'] ?? null,
            'geo_known' => $geo !== [],

            'asn'     => isset($net['asn_i']) ? (int) $net['asn_i'] : null,
            'as_org'  => $net['as_org_s'] ?? null,
            'as_type' => $net['as_type_s'] ?? null,
            'netname' => $net['netname_s'] ?? null,
            'net_known' => $net !== [],

            'ua'          => isset($doc['ua_s']) ? (string) $doc['ua_s'] : null,
            'ua_logged'   => array_key_exists('ua_hash_s', $doc),
            'browser'     => isset($doc['browser_s']) ? (string) $doc['browser_s'] : null,
            'browser_ver' => isset($doc['browser_ver_i']) ? (int) $doc['browser_ver_i'] : null,
            'os'          => isset($doc['os_s']) ? (string) $doc['os_s'] : null,
            'device'      => isset($doc['device_s']) ? (string) $doc['device_s'] : null,
            'ua_bot'      => array_key_exists('ua_bot_b', $doc) ? (bool) $doc['ua_bot_b'] : null,
            'ua_bot_name' => isset($doc['ua_bot_name_s']) ? (string) $doc['ua_bot_name_s'] : null,
            'ua_bot_cat'  => isset($doc['ua_bot_cat_s']) ? (string) $doc['ua_bot_cat_s'] : null,
            'ai_crawler'  => array_key_exists('ai_crawler_b', $doc) ? (bool) $doc['ai_crawler_b'] : null,

            'referer'      => isset($doc['referer_s']) ? (string) $doc['referer_s'] : null,
            'referer_host' => isset($doc['referer_host_s']) ? (string) $doc['referer_host_s'] : null,
            'referer_type' => isset($doc['referer_type_s']) ? (string) $doc['referer_type_s'] : null,

            'accept_lang' => isset($doc['accept_lang_s']) ? (string) $doc['accept_lang_s'] : null,
            'tls_proto'   => isset($doc['tls_proto_s']) ? (string) $doc['tls_proto_s'] : null,
            'tls_cipher'  => isset($doc['tls_cipher_s']) ? (string) $doc['tls_cipher_s'] : null,
            'xff'         => isset($doc['xff_s']) ? (string) $doc['xff_s'] : null,

            'search_terms' => isset($doc['search_terms_ss']) ? array_values((array) $doc['search_terms_ss']) : [],

            'flags'  => $flags,
            'read'   => self::reading($doc, $flags),
            'raw'    => isset($doc['raw_s']) ? (string) $doc['raw_s'] : null,
        ];
    }

    /**
     * What this ONE LINE shows, which is not a verdict and must never be printed as one.
     *
     * A verdict belongs to a session: it is a correlation over many requests, scored once the
     * session settles, and this page has seen exactly one request. So the words here describe
     * the line and stop there — a declared crawler in the User-Agent, a pattern that matched,
     * a status the server returned, a sub-resource rather than a page. Every one of them is
     * checkable against the bytes on screen, which is the test a provisional read has to pass.
     *
     * `tone` is for emphasis and carries no claim of its own. Ordered so the strongest
     * line-alone fact wins: something matched, then the server refused, then the client said
     * what it was, then what kind of request it is.
     *
     * @param array<string,mixed> $doc
     * @param array<int,string>   $flags
     * @return array{code:string,label:string,why:string,tone:string}
     */
    private static function reading(array $doc, array $flags): array
    {
        $status = isset($doc['status_i']) ? (int) $doc['status_i'] : null;

        if ($flags !== []) {
            $decisive = null;
            foreach ($flags as $code) {
                if (Attacks::isDecisive($code)) {
                    $decisive = $code;
                    break;
                }
            }

            $named = Attacks::describe($decisive ?? $flags[0]);
            return [
                'code'  => 'matched',
                'label' => count($flags) === 1 ? $named['label'] : $named['label'] . ' +' . (count($flags) - 1),
                'why'   => 'The request matched a named pattern. Whether it achieved anything depends on '
                    . 'what the server answered.',
                'tone'  => $decisive === null ? 'watch' : 'alarm',
            ];
        }

        if ($status !== null && $status >= 500) {
            return [
                'code'  => 'server_error',
                'label' => 'Server error',
                'why'   => 'The server broke trying to answer this request.',
                'tone'  => 'alarm',
            ];
        }

        if ($status !== null && $status >= 400) {
            return [
                'code'  => 'refused',
                'label' => 'Refused',
                'why'   => 'The server declined. Nothing was served.',
                'tone'  => 'watch',
            ];
        }

        if (!empty($doc['ua_bot_b'])) {
            $name = isset($doc['ua_bot_name_s']) ? (string) $doc['ua_bot_name_s'] : '';
            return [
                'code'  => 'declared_bot',
                'label' => $name === '' ? 'Declared crawler' : 'Says it is ' . $name,
                'why'   => 'The User-Agent names a crawler. Nothing in one line confirms the claim; the '
                    . 'reverse-DNS check that would is part of scoring a session.',
                'tone'  => 'watch',
            ];
        }

        if (array_key_exists('ua_hash_s', $doc) && ($doc['ua_s'] ?? '') === '') {
            return [
                'code'  => 'no_ua',
                'label' => 'No User-Agent',
                'why'   => 'The client sent no User-Agent at all. Browsers always send one.',
                'tone'  => 'watch',
            ];
        }

        $kind = (string) ($doc['kind_s'] ?? '');
        if ($kind === 'asset' || $kind === 'favicon') {
            return [
                'code'  => 'sub_resource',
                'label' => 'Sub-resource',
                'why'   => 'A file a page pulled in, not a page anybody asked for.',
                'tone'  => 'plain',
            ];
        }
        if ($kind === 'robots') {
            return [
                'code'  => 'crawl_file',
                'label' => 'Crawl file',
                'why'   => 'robots.txt, a sitemap or a .well-known path.',
                'tone'  => 'plain',
            ];
        }
        if ($kind === 'api') {
            return [
                'code'  => 'api',
                'label' => 'API call',
                'why'   => 'A machine-readable endpoint rather than a page.',
                'tone'  => 'plain',
            ];
        }
        if ($kind === 'beacon') {
            return [
                'code'  => 'beacon',
                'label' => 'Beacon',
                'why'   => 'An analytics collector on the measured site.',
                'tone'  => 'plain',
            ];
        }

        return [
            'code'  => 'page',
            'label' => 'Page',
            'why'   => 'An ordinary page request with nothing notable in the line itself.',
            'tone'  => 'plain',
        ];
    }

    /**
     * The request kind in a word, for the two dimensions that have no stored vocabulary.
     *
     * Translated here rather than in the browser because `kind_s` and `asset_kind_s` are not in
     * Panel\Vocabulary — they are ingest-side classifications rather than conclusions, and
     * adding them to the vocabulary would make them filterable, which is a decision nobody has
     * asked for. An unrecognised value renders as itself, never as a plausible guess.
     */
    private static function kindWord(string $kind, $assetKind): string
    {
        $asset = is_string($assetKind) && $assetKind !== '' ? $assetKind : '';

        $named = match ($asset) {
            'js'    => 'Script',
            'css'   => 'Stylesheet',
            'map'   => 'Source map',
            'img'   => 'Image',
            'font'  => 'Font',
            'media' => 'Media',
            default => $asset,
        };

        return match ($kind) {
            'html'    => 'Page',
            'api'     => 'API',
            'asset'   => $named === '' ? 'Sub-resource' : $named,
            'favicon' => 'Icon',
            'robots'  => 'Crawl file',
            'beacon'  => 'Beacon',
            'other'   => 'File',
            default   => $kind === '' ? 'Unclassified' : $kind,
        };
    }

    /**
     * Compile a source's format, memoised for the life of the connection.
     *
     * The same three-way resolution bin/loghound-tail uses, so a file that parses for the
     * daemon parses identically here: a library name first, then a delimited PCRE through the
     * vetting LogDetect applies to a custom pattern, then the operator's own LogFormat string.
     */
    private function format(string $name): ?LogFormat
    {
        if (array_key_exists($name, $this->formats)) {
            return $this->formats[$name];
        }

        $fmt = null;
        try {
            $fmt = LogDetect::formatByName($name);
            if ($fmt === null && LogFormat::isDelimitedRegex($name)) {
                $fmt = LogDetect::formatFromRegex($name, 'source');
            } elseif ($fmt === null) {
                $fmt = str_contains($name, '$')
                    ? LogFormat::fromNginx($name, 'source')
                    : LogFormat::fromApache($name, 'source');
            }
        } catch (\Throwable $e) {
            $fmt = null;
        }

        return $this->formats[$name] = $fmt;
    }

    /**
     * Where this address is, IF the ingest daemon has already looked it up.
     *
     * NOTHING IS LOOKED UP HERE. Geo and network enrichment are network calls — an HTTP round
     * trip to the platform, a whois session, a DNS query — and a page that made them per line
     * would stall behind whichever of them was slow, on a loop that is supposed to be reading
     * a file. So this reads the cache the daemon fills and answers "not looked up yet" when
     * there is nothing in it, which the row renders as exactly that rather than as "unknown".
     *
     * @return array<string,mixed>
     */
    private function geo(string $ip): array
    {
        if (array_key_exists($ip, $this->geoMemo)) {
            return $this->geoMemo[$ip] ?? [];
        }
        return ($this->geoMemo[$ip] = $this->cacheRead('cache_geo', $ip)) ?? [];
    }

    /**
     * Who owns this address, on the same cache-only terms as geo().
     *
     * Keyed by network rather than by address, because that is how \Loghound\Enrich\Asn stores
     * it: one whois answer covers a /24 or a /48, and asking per address would miss every
     * entry the daemon has already written.
     *
     * @return array<string,mixed>
     */
    private function network(string $ip): array
    {
        $key = Security::ipNetwork($ip, 24, 48);
        if (array_key_exists($key, $this->asnMemo)) {
            return $this->asnMemo[$key] ?? [];
        }
        return ($this->asnMemo[$key] = $this->cacheRead('cache_asn', $key)) ?? [];
    }

    /**
     * Read one entry from the ingest daemon's enrichment cache, READ-ONLY.
     *
     * Opened with SQLITE3_OPEN_READONLY and not through \Loghound\State, deliberately. State's
     * constructor opens the database read-write, creates it when it is absent and runs its
     * migrations; all three are correct for a daemon that owns the file and wrong for a web
     * request that is only borrowing two rows out of it. A panel that could create or migrate
     * the ingest state is a panel that can corrupt it from a page load.
     *
     * The table shape mirrors \Loghound\State::cacheTable() — `cache_geo` and `cache_asn`,
     * keyed by `k`, with a JSON `v`, a `negative` flag and an `expires_at`. A negative entry
     * means the lookup was made and found nothing, which is not the same as never having
     * looked, so it answers null exactly as State does.
     *
     * @return array<string,mixed>|null
     */
    private function cacheRead(string $table, string $key): ?array
    {
        $db = $this->cacheDb();
        if ($db === null) {
            return null;
        }

        try {
            $stmt = $db->prepare(
                'SELECT v, negative FROM ' . $table . ' WHERE k = :k AND expires_at > :now LIMIT 1'
            );
            if ($stmt === false) {
                return null;
            }
            $stmt->bindValue(':k', $key, SQLITE3_TEXT);
            $stmt->bindValue(':now', time(), SQLITE3_INTEGER);
            $res = $stmt->execute();
            $row = $res === false ? false : $res->fetchArray(SQLITE3_ASSOC);
            if (!is_array($row) || (int) ($row['negative'] ?? 0) === 1) {
                return null;
            }
            $value = json_decode((string) ($row['v'] ?? ''), true);
            return is_array($value) ? $value : null;
        } catch (\Throwable $e) {
            return null;
        }
    }

    /** The read-only handle on var/state.db, opened at most once and never created. */
    private function cacheDb(): ?SQLite3
    {
        if ($this->cacheTried) {
            return $this->cache;
        }
        $this->cacheTried = true;

        $path = $this->cfg->varDir() . '/state.db';
        if (!is_file($path) || !is_readable($path)) {
            return null;
        }

        try {
            $db = new SQLite3($path, SQLITE3_OPEN_READONLY);
            $db->enableExceptions(true);
            $db->busyTimeout(1000);
            return $this->cache = $db;
        } catch (\Throwable $e) {
            return null;
        }
    }

    /**
     * Read a cursor the browser gave back.
     *
     * Shape first, then meaning: anything that is not digits and colons is refused whole rather
     * than parsed leniently, and a source index outside the list this request resolved is
     * dropped. The inode travels with the offset so that open() can tell "resume here" from
     * "that offset belonged to a file that has since been rotated away".
     *
     * @return array<int,array{inode:int,offset:int}>
     */
    private function parseCursor(string $cursor): array
    {
        $cursor = trim($cursor);
        if ($cursor === '' || strlen($cursor) > 2048 || preg_match(self::CURSOR_RE, $cursor) !== 1) {
            return [];
        }

        $out = [];
        foreach (explode(',', $cursor) as $part) {
            [$i, $inode, $offset] = explode(':', $part);
            $i = (int) $i;
            if (!isset($this->sources[$i])) {
                continue;
            }
            $out[$i] = ['inode' => (int) $inode, 'offset' => (int) $offset];
        }
        return $out;
    }
}
