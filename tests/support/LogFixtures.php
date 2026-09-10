<?php
/**
 * Loghound — test scaffolding.
 *
 * NOT PRODUCTION CODE. Everything here stands in for a component another part of the
 * project owns, so the scoring engine can be exercised end-to-end against the real captured
 * log files without a network, a database, or the rest of the pipeline being finished:
 *
 *   CombinedLogReader  stands in for src/Parser.php + src/LogFormat.php
 *   MiniUa             stands in for src/Enrich/Ua.php
 *   FpCluster          stands in for the Solr JSON Facet that computes fp_ips_24h_i
 *   TempState          NOT a stand-in — it wraps the REAL src/State.php on a temp database
 *
 * Each stand-in is the smallest thing that produces the fields the scorer reads, and each is
 * deliberately dumb: if a test passes here it is because the SCORING logic is right, not
 * because a clever stand-in flattered it.
 *
 * The one thing that is NOT a stand-in is the log data. tests/fixtures/*.log are real
 * captured lines and nothing in this file alters them.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Tests;

use Loghound\Security;

/**
 * A throwaway State backed by a temporary SQLite file.
 *
 * NOT a stand-in any more — src/State.php has landed, so the scoring tests drive the REAL
 * sessions_open table rather than a hand-written imitation of it. That matters: the
 * millisecond timestamps, the closed_at marker and the JSON `data` blob are all things a
 * fake would have got subtly right and the real thing gets exactly right.
 *
 * SQLite is used on disk rather than :memory: because State opens its own connection and
 * sets a busy timeout; a temp file is the least surprising way to get an isolated database
 * per test run. It is deleted when the object goes out of scope.
 */
final class TempState
{
    private string $path;

    private \Loghound\State $state;

    public function __construct()
    {
        $this->path = sys_get_temp_dir() . '/loghound-test-' . bin2hex(random_bytes(8)) . '.db';
        $this->state = new \Loghound\State($this->path);
    }

    public function state(): \Loghound\State
    {
        return $this->state;
    }

    public function __destruct()
    {
        $this->state->close();
        foreach ([$this->path, $this->path . '-wal', $this->path . '-shm'] as $f) {
            if (is_file($f)) {
                @unlink($f);
            }
        }
    }
}

/**
 * Enough User-Agent parsing to feed the rules.
 *
 * src/Enrich/Ua.php will do this properly. All the scorer needs is browser, major version,
 * OS, device class and the self-declared-bot flags, so that is all this produces.
 */
final class MiniUa
{
    /**
     * AI crawler names from SPEC §4.1. Kept here only so the honest-crawler tests have
     * something real to classify.
     *
     * @var string[]
     */
    private const AI_CRAWLERS = [
        'gptbot', 'claudebot', 'perplexitybot', 'bytespider', 'amazonbot',
        'meta-externalagent', 'applebot-extended', 'ccbot', 'diffbot', 'omgili',
        'cohere-ai', 'imagesiftbot', 'youbot', 'timpibot', 'webzio',
    ];

    /**
     * @return array<string,mixed> Fields to merge onto a hit.
     */
    public static function parse(string $ua): array
    {
        $out = ['ua_s' => $ua, 'ua_hash_s' => sha1($ua)];
        $lower = strtolower($ua);

        // --- self-declared bots ----------------------------------------------------------
        foreach (self::AI_CRAWLERS as $name) {
            if (str_contains($lower, $name)) {
                return $out + [
                    'ua_bot_b'      => true,
                    'ua_bot_name_s' => $name,
                    'ua_bot_cat_s'  => 'ai',
                    'ai_crawler_b'  => true,
                    'device_s'      => 'bot',
                ];
            }
        }
        $known = [
            'googlebot' => 'search', 'bingbot' => 'search', 'yandexbot' => 'search',
            'duckduckbot' => 'search', 'baiduspider' => 'search', 'applebot' => 'search',
            'ahrefsbot' => 'seo', 'semrushbot' => 'seo', 'mj12bot' => 'seo',
            'uptimerobot' => 'monitor', 'pingdom' => 'monitor', 'statuscake' => 'monitor',
            'facebookexternalhit' => 'social', 'twitterbot' => 'social', 'slackbot' => 'social',
        ];
        foreach ($known as $name => $cat) {
            if (str_contains($lower, $name)) {
                return $out + [
                    'ua_bot_b'      => true,
                    'ua_bot_name_s' => $name,
                    'ua_bot_cat_s'  => $cat,
                    'ai_crawler_b'  => false,
                    'device_s'      => 'bot',
                ];
            }
        }
        if (preg_match('/(bot|crawler|spider|slurp|scrapy|python-requests|curl|wget|httpclient)/i', $ua)) {
            return $out + [
                'ua_bot_b'      => true,
                'ua_bot_name_s' => 'unknown',
                'ua_bot_cat_s'  => 'other',
                'ai_crawler_b'  => false,
                'device_s'      => 'bot',
            ];
        }

        // --- consumer browsers ------------------------------------------------------------
        // Order matters: Edge and Opera both carry "Chrome" in their UA.
        $browser = null;
        $version = 0;
        if (preg_match('#Edg/(\d+)#', $ua, $m)) {
            $browser = 'Edge';
            $version = (int) $m[1];
        } elseif (preg_match('#OPR/(\d+)#', $ua, $m)) {
            $browser = 'Opera';
            $version = (int) $m[1];
        } elseif (preg_match('#Chrome/(\d+)#', $ua, $m)) {
            $browser = 'Chrome';
            $version = (int) $m[1];
        } elseif (preg_match('#Firefox/(\d+)#', $ua, $m)) {
            $browser = 'Firefox';
            $version = (int) $m[1];
        } elseif (preg_match('#Version/(\d+).*Safari#', $ua, $m)) {
            $browser = 'Safari';
            $version = (int) $m[1];
        }

        $os = 'unknown';
        if (str_contains($ua, 'Windows NT')) {
            $os = 'Windows';
        } elseif (str_contains($ua, 'Mac OS X')) {
            $os = 'Mac OS X';
        } elseif (str_contains($ua, 'Android')) {
            $os = 'Android';
        } elseif (str_contains($ua, 'iPhone') || str_contains($ua, 'iPad')) {
            $os = 'iOS';
        } elseif (str_contains($ua, 'Linux') || str_contains($ua, 'X11')) {
            $os = 'Linux';
        }

        $device = 'desktop';
        if (str_contains($ua, 'Mobile') || $os === 'Android' || $os === 'iOS') {
            $device = 'mobile';
        }

        $out['os_s']       = $os;
        $out['device_s']   = $device;
        $out['ua_bot_b']   = false;
        $out['ai_crawler_b'] = false;
        if ($browser !== null) {
            $out['browser_s']     = $browser;
            $out['browser_ver_i'] = $version;
        }
        return $out;
    }
}

/**
 * Reads an apache `combined` log into normalised hit arrays.
 *
 * Enough of src/Parser.php to run the scorer. It sets only the fields `combined` actually
 * carries — which is the point of using these fixtures: they prove what the detector can
 * and cannot do with the log format most sites are running, rather than with the enriched
 * format SPEC §8 recommends.
 *
 * Fields it deliberately does NOT set: as_type_s, asn_i, netname_s, rdns_ok_b, country_s,
 * tz_s, and every Sec-* / Accept-* header. They are not in the file. Inventing them would
 * be exactly the fabrication SPEC §1 forbids, and several tests below exist precisely to
 * show which rules go quiet as a result.
 */
final class CombinedLogReader
{
    /** Apache combined, with a tolerant escaped-quote-aware pattern for the quoted fields. */
    private const PATTERN =
        '/^(?<ip>\S+) (?<ident>\S+) (?<user>\S+) \[(?<ts>[^\]]+)\] "(?<req>(?:[^"\\\\]|\\\\.)*)" '
        . '(?<status>\d{3}) (?<bytes>\S+) "(?<ref>(?:[^"\\\\]|\\\\.)*)" "(?<ua>(?:[^"\\\\]|\\\\.)*)"/';

    /**
     * @return array<int,array<string,mixed>> Hits, sorted by timestamp.
     */
    public static function read(string $path, string $host = 'opensolr.com'): array
    {
        $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) {
            throw new \RuntimeException('Cannot read fixture: ' . $path);
        }

        $hits = [];
        foreach ($lines as $offset => $line) {
            $hit = self::parseLine($line, $path, $offset, $host);
            if ($hit !== null) {
                $hits[] = $hit;
            }
        }

        // A real tailer sees lines in the order the webserver wrote them, which is
        // chronological. The fixtures were assembled by grepping, so they are not. Sorting
        // here reproduces what the daemon would actually see; without it, inter-request
        // gaps come out negative and every timing statistic is meaningless.
        usort($hits, static fn(array $a, array $b): int => $a['_ts_unix'] <=> $b['_ts_unix']);

        return $hits;
    }

    /**
     * @return array<string,mixed>|null
     */
    public static function parseLine(string $line, string $src, int $offset, string $host): ?array
    {
        if (!preg_match(self::PATTERN, $line, $m)) {
            return null;
        }

        $ts = \DateTimeImmutable::createFromFormat('d/M/Y:H:i:s O', $m['ts']);
        if ($ts === false) {
            return null;
        }

        // "METHOD target PROTO"
        $reqParts = explode(' ', $m['req']);
        $method   = $reqParts[0] ?? 'GET';
        $target   = $reqParts[1] ?? '/';
        $proto    = $reqParts[2] ?? 'HTTP/1.0';

        $qpos  = strpos($target, '?');
        $path  = $qpos === false ? $target : substr($target, 0, $qpos);
        $query = $qpos === false ? '' : substr($target, $qpos + 1);

        $hit = [
            // sha1(file + offset) — the same deterministic id the real pipeline uses.
            'id'        => sha1($src . '|' . $offset),
            // Matches what Parser.php emits: `ts` is the Solr instant string, and the
            // numeric instant is handed over separately (Sessionizer::hitMillis).
            'ts'        => gmdate('Y-m-d\TH:i:s.000\Z', $ts->getTimestamp()),
            '_ts_ms'    => $ts->getTimestamp() * 1000,
            '_ts_unix'  => $ts->getTimestamp(),
            'host_s'    => $host,
            'src_s'     => basename($src),

            'ip_s'      => $m['ip'],
            'ip_net_s'  => Security::ipNetwork($m['ip']),
            'ip_ver_i'  => str_contains($m['ip'], ':') ? 6 : 4,

            'method_s'  => $method,
            'path_s'    => $path,
            'proto_s'   => $proto,
            'status_i'  => (int) $m['status'],

            'raw_s'     => $line,
        ];

        if ($query !== '') {
            $hit['query_s'] = $query;
        }
        if ($m['bytes'] !== '-') {
            $hit['bytes_l'] = (int) $m['bytes'];
        }
        // ABSENT, never empty string: "-" in a combined log means the header was not sent.
        if ($m['ref'] !== '-' && $m['ref'] !== '') {
            $hit['referer_s'] = $m['ref'];
            $refHost = parse_url($m['ref'], PHP_URL_HOST);
            if (is_string($refHost)) {
                $hit['referer_host_s'] = $refHost;
                $hit['referer_type_s'] = $refHost === $host ? 'internal'
                    : (preg_match('/google|bing|duckduckgo|yandex|baidu/i', $refHost) ? 'search' : 'link');
            }
        }

        if ($m['ua'] !== '-' && $m['ua'] !== '') {
            $hit += MiniUa::parse($m['ua']);
        }

        return $hit;
    }
}

/**
 * Local reimplementation of the fp_ips_24h_i facet.
 *
 * bin/loghound-score asks Solr:
 *     fq = fp_hash_s:(...) AND ts:[T-12h TO T+12h]
 *     json.facet = { by_fp: { terms fp_hash_s, facet: { ips: unique(ip_s) } } }
 *
 * This computes exactly that from the parsed hits, so the scoring tests exercise the real
 * rule with real numbers and still run with no network — which SPEC §12 requires.
 */
final class FpCluster
{
    /**
     * @param array<int,array<string,mixed>> $hits    Every hit in the corpus.
     * @param int                            $centreTs Session midpoint, the facet's centre.
     * @return int Distinct IPs sharing $fpHash within ±12h of $centreTs.
     */
    public static function distinctIps(array $hits, string $fpHash, int $centreTs): int
    {
        $window = 12 * 3600;
        $ips = [];
        foreach ($hits as $hit) {
            if (($hit['fp_hash_s'] ?? null) !== $fpHash) {
                continue;
            }
            $delta = abs(((int) $hit['_ts_unix']) - $centreTs);
            if ($delta > $window) {
                continue;
            }
            $ips[(string) $hit['ip_s']] = true;
        }
        return count($ips);
    }
}
