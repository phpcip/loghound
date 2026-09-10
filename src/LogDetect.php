<?php
/**
 * Loghound — Log discovery and format detection.
 *
 * This class implements the detection ladder from SPEC §8, in order:
 *
 *   1. READ THE WEBSERVER CONFIG. `discoverFromApacheConfig()` / `discoverFromNginxConfig()`
 *      parse the real httpd.conf / nginx.conf tree — following Include / IncludeOptional /
 *      include, expanding ${APACHE_LOG_DIR} and friends — and return, for every access log,
 *      the exact format string and the vhost it belongs to. This is DETERMINISTIC: there is
 *      no guessing, no sampling and no confidence value, because the answer is written down
 *      in the operator's own config. It is the headline setup feature.
 *   2. KNOWN-FORMAT LIBRARY. When the config cannot be read (containers, restricted perms,
 *      a config we do not understand), `detectFromSample()` scores sample lines against the
 *      built-in library STRUCTURALLY — field 1 must actually parse as an IP, the bracketed
 *      field must actually parse as a date, the status must actually be 3 digits in range —
 *      rather than rewarding whichever regex happened to match.
 *   3. GENERATE A CANDIDATE. `proposeRegex()` tokenizes a sample and proposes a pattern.
 *   4. Custom regex, supplied by the operator and vetted by Security::validateUserRegex().
 *
 * JSON log formats (Caddy, Traefik, nginx `escape=json`) are first-class members of the
 * library and are parsed natively by LogFormat's JSON mode, never through a regex.
 *
 * Security: every path this class opens is resolved with Security::safePath() against an
 * allowlist of configuration roots, so a hostile `Include /../../home/x/.ssh/id_rsa` in a
 * config we were pointed at cannot turn discovery into an arbitrary-file-read primitive.
 * Include recursion is depth-capped and cycle-guarded; every file read is size-capped.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound;

final class LogDetect
{
    /** Never read a config file larger than this — a 200 MB "config" is an attack, not a config. */
    private const MAX_CONFIG_BYTES = 4194304; // 4 MB

    /** Include/include recursion cap. Real trees are 2-3 deep; 12 is generous. */
    private const MAX_INCLUDE_DEPTH = 12;

    /** Total files visited during one discovery run, to bound a glob bomb. */
    private const MAX_CONFIG_FILES = 500;

    /**
     * nginx's own built-in `combined` format, used when `access_log <path>;` names no format.
     * Copied verbatim from nginx's ngx_http_log_module default.
     */
    private const NGINX_BUILTIN_COMBINED =
        '$remote_addr - $remote_user [$time_local] "$request" '
        . '$status $body_bytes_sent "$http_referer" "$http_user_agent"';

    /**
     * Group names proposeRegex() emits, mapped to canonical Loghound raw fields.
     *
     * PCRE group names may only contain word characters, so `header_in.user-agent` cannot be
     * a group name; these aliases bridge the two vocabularies.
     */
    private const REGEX_FIELD_ALIASES = [
        'referer'    => 'header_in.referer',
        'user_agent' => 'header_in.user-agent',
        'useragent'  => 'header_in.user-agent',
        'ua'         => 'header_in.user-agent',
        'ip'         => 'remote_addr',
        'xff'        => 'header_in.x-forwarded-for',
        'host'       => 'vhost',
    ];

    // =============================================================================
    // Ladder step 1 — read the webserver configuration
    // =============================================================================

    /**
     * Parse an Apache configuration tree and return every access log it defines.
     *
     * Handles, because real configs contain all of them:
     *  - `LogFormat "<fmt>" <nickname>` and the nickname-less form used by TransferLog;
     *  - `CustomLog <target> <nickname|"<fmt>">` including `env=`/`expr=` suffixes;
     *  - `TransferLog <target>`;
     *  - `Include` / `IncludeOptional` with globs, resolved against ServerRoot;
     *  - `Define NAME VALUE` plus `${VAR}` expansion, seeded from /etc/apache2/envvars and
     *    from the distribution defaults, which is what makes `${APACHE_LOG_DIR}` resolve;
     *  - `<VirtualHost>` blocks with `ServerName`, so each log knows which vhost it serves;
     *  - piped (`|/usr/bin/rotatelogs ...`) and `syslog:` targets, which are RECOGNISED and
     *    skipped rather than being emitted as nonsense file paths.
     *
     * @param string[] $configFiles Top-level configs, e.g. /etc/apache2/apache2.conf
     * @param string[] $vhostDirs   Directories scanned for *.conf, e.g. sites-enabled
     * @param array<string,mixed> $opts 'allowed_config_roots' => string[] override.
     *
     * @return array<string,array{format:string,format_name:?string,vhost:?string,vhosts:string[],server:string,config:string}>
     *         Keyed by absolute log file path.
     */
    public static function discoverFromApacheConfig(
        array $configFiles,
        array $vhostDirs = [],
        array $opts = []
    ): array {
        $state = [
            'roots'      => self::configRoots($configFiles, $vhostDirs, $opts),
            'defines'    => self::apacheSeedDefines($configFiles),
            'formats'    => self::apacheBuiltinFormats(),
            'results'    => [],
            'seen'       => [],
            'files'      => 0,
            'serverRoot' => '',
            'vhost'      => [],   // stack of vhost ServerNames
        ];

        // ServerRoot defaults to the directory holding the first config we were given, which
        // is what Apache itself effectively does on Debian and RHEL layouts.
        foreach ($configFiles as $f) {
            $real = Security::safePath($f, $state['roots']);
            if ($real !== null) {
                $state['serverRoot'] = dirname($real);
                break;
            }
        }

        foreach ($configFiles as $file) {
            self::apacheWalk($file, $state, 0);
        }

        // Vhost directories are walked too: on Debian they are Included from apache2.conf, but
        // on a container image the operator may point us straight at sites-enabled.
        foreach ($vhostDirs as $dir) {
            foreach (self::globConfigs($dir . '/*.conf', $state['roots']) as $file) {
                self::apacheWalk($file, $state, 1);
            }
        }

        return $state['results'];
    }

    /**
     * Parse an nginx configuration tree and return every access log it defines.
     *
     * Handles `log_format` (including the multi-quoted-string continuation form and the
     * `escape=json` JSON-template idiom), `access_log` with and without a named format,
     * `access_log off`, `include` globs, and `server { server_name ...; }` context.
     *
     * @param string[] $configFiles e.g. ['/etc/nginx/nginx.conf']
     * @param string[] $vhostDirs   e.g. ['/etc/nginx/sites-enabled', '/etc/nginx/conf.d']
     * @param array<string,mixed> $opts
     *
     * @return array<string,array{format:string,format_name:?string,vhost:?string,vhosts:string[],server:string,config:string}>
     */
    public static function discoverFromNginxConfig(
        array $configFiles,
        array $vhostDirs = [],
        array $opts = []
    ): array {
        $state = [
            'roots'   => self::configRoots($configFiles, $vhostDirs, $opts),
            'formats' => ['combined' => self::NGINX_BUILTIN_COMBINED],
            'results' => [],
            'seen'    => [],
            'files'   => 0,
            'vhost'   => [],
            'prefix'  => '/etc/nginx',
        ];

        foreach ($configFiles as $f) {
            $real = Security::safePath($f, $state['roots']);
            if ($real !== null) {
                $state['prefix'] = dirname($real);
                break;
            }
        }

        foreach ($configFiles as $file) {
            self::nginxWalk($file, $state, 0);
        }
        foreach ($vhostDirs as $dir) {
            foreach (self::globConfigs($dir . '/*', $state['roots']) as $file) {
                self::nginxWalk($file, $state, 1);
            }
        }

        return $state['results'];
    }

    /**
     * Run both discoverers over the `discover` section of the config.
     *
     * Convenience for `bin/loghound-setup`: it does not need to know which webserver is
     * installed, it just asks for everything and takes whatever comes back.
     *
     * @param array<string,mixed> $discoverCfg Config::get('discover')
     * @return array<string,array> Keyed by absolute log path.
     */
    public static function discoverAll(array $discoverCfg): array
    {
        $apache = self::discoverFromApacheConfig(
            (array) ($discoverCfg['apache_configs'] ?? []),
            (array) ($discoverCfg['apache_vhost_dirs'] ?? [])
        );
        $nginx = self::discoverFromNginxConfig(
            (array) ($discoverCfg['nginx_configs'] ?? []),
            (array) ($discoverCfg['nginx_vhost_dirs'] ?? [])
        );
        // Apache first so a path claimed by both (impossible in practice) keeps one answer.
        return $apache + $nginx;
    }

    // =============================================================================
    // Ladder step 2 — the known-format library
    // =============================================================================

    /**
     * The built-in format library.
     *
     * Every entry is compiled lazily and memoised, because compiling twelve regexes on every
     * call would be wasteful when the tail daemon asks for one by name.
     *
     * @return array<string,LogFormat>
     */
    public static function library(): array
    {
        static $lib = null;
        if ($lib !== null) {
            return $lib;
        }

        $lib = [];

        // ---- Apache -------------------------------------------------------------
        // Order matters for ties: apache_combined is listed before nginx_combined because
        // the two grammars accept the same bytes and PHP's sort is stable, so an Apache
        // installation (the common case) gets the Apache answer.
        $lib['apache_combined'] = LogFormat::fromApache(
            '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"',
            'apache_combined'
        );
        $lib['apache_vhost_combined'] = LogFormat::fromApache(
            '%v %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"',
            'apache_vhost_combined'
        );
        $lib['apache_common'] = LogFormat::fromApache(
            '%h %l %u %t "%r" %>s %b',
            'apache_common'
        );
        // The format Loghound recommends in docs/INSTALL.md (SPEC §8).
        $lib['apache_loghound'] = LogFormat::fromApache(
            '%v:%p %h %l %u %t "%r" %>s %O %D "%{Referer}i" "%{User-Agent}i" '
            . '"%{Accept}i" "%{Accept-Language}i" "%{Accept-Encoding}i" '
            . '"%{Sec-CH-UA}i" "%{Sec-CH-UA-Platform}i" "%{Sec-CH-UA-Mobile}i" '
            . '"%{Sec-Fetch-Site}i" "%{Sec-Fetch-Mode}i" "%{Sec-Fetch-Dest}i" "%{Sec-Fetch-User}i" '
            . '"%{X-Forwarded-For}i" "%H" "%{SSL_PROTOCOL}x" "%{SSL_CIPHER}x"',
            'apache_loghound'
        );

        // ---- nginx --------------------------------------------------------------
        $lib['nginx_combined'] = LogFormat::fromNginx(
            self::NGINX_BUILTIN_COMBINED,
            'nginx_combined'
        );
        $lib['nginx_combined_xff'] = LogFormat::fromNginx(
            self::NGINX_BUILTIN_COMBINED . ' "$http_x_forwarded_for"',
            'nginx_combined_xff'
        );
        // Kubernetes ingress-nginx default. Its trailing fields are what identify it.
        $lib['ingress_nginx'] = LogFormat::fromNginx(
            '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent '
            . '"$http_referer" "$http_user_agent" $request_length $request_time '
            . '[$proxy_upstream_name] [$proxy_alternative_upstream_name] $upstream_addr '
            . '$upstream_response_length $upstream_response_time $upstream_status $req_id',
            'ingress_nginx'
        );

        // ---- JSON formats (parsed natively, never through a regex) ---------------
        $lib['caddy_json'] = LogFormat::fromJson('caddy_json', [
            'ts'                                 => 'time',
            // remote_ip first, client_ip last: when Caddy emits both, client_ip is the one
            // that has had trusted-proxy resolution applied, so it must win.
            'request.remote_addr'                => 'remote_addr',
            'request.remote_ip'                  => 'remote_addr',
            'request.client_ip'                  => 'remote_addr',
            'request.proto'                      => 'proto',
            'request.method'                     => 'method',
            'request.host'                       => 'vhost',
            'request.uri'                        => 'uri_full',
            'request.headers.User-Agent'         => 'header_in.user-agent',
            'request.headers.Referer'            => 'header_in.referer',
            'request.headers.Accept'             => 'header_in.accept',
            'request.headers.Accept-Language'    => 'header_in.accept-language',
            'request.headers.Accept-Encoding'    => 'header_in.accept-encoding',
            'request.headers.Sec-Ch-Ua'          => 'header_in.sec-ch-ua',
            'request.headers.Sec-Ch-Ua-Platform' => 'header_in.sec-ch-ua-platform',
            'request.headers.Sec-Ch-Ua-Mobile'   => 'header_in.sec-ch-ua-mobile',
            'request.headers.Sec-Fetch-Site'     => 'header_in.sec-fetch-site',
            'request.headers.Sec-Fetch-Mode'     => 'header_in.sec-fetch-mode',
            'request.headers.Sec-Fetch-Dest'     => 'header_in.sec-fetch-dest',
            'request.headers.Sec-Fetch-User'     => 'header_in.sec-fetch-user',
            'request.headers.X-Forwarded-For'    => 'header_in.x-forwarded-for',
            'request.tls.proto'                  => 'var.ssl_protocol',
            'request.tls.cipher_suite'           => 'var.ssl_cipher',
            'status'                             => 'status',
            'size'                               => 'bytes',
            'duration'                           => 'dur_s',
        ], ['source' => 'Caddy structured JSON access log (http.log.access)']);

        $lib['traefik_json'] = LogFormat::fromJson('traefik_json', [
            'StartUTC'                    => 'time',
            'ClientHost'                  => 'remote_addr',
            'RequestMethod'               => 'method',
            'RequestPath'                 => 'uri_full',
            'RequestProtocol'             => 'proto',
            'RequestHost'                 => 'vhost',
            'request_User-Agent'          => 'header_in.user-agent',
            'request_Referer'             => 'header_in.referer',
            'request_Accept'              => 'header_in.accept',
            'request_Accept-Language'     => 'header_in.accept-language',
            'request_X-Forwarded-For'     => 'header_in.x-forwarded-for',
            'DownstreamContentSize'       => 'bytes',
            'Duration'                    => 'dur_ns',
            // OriginStatus is the backend's answer; DownstreamStatus is what the client saw,
            // which is the one that belongs on the hit document, so it is applied last.
            'OriginStatus'                => 'status',
            'DownstreamStatus'            => 'status',
        ], ['source' => 'Traefik JSON access log']);

        // ---- Fixed-grammar formats (regex, not expressible as a LogFormat string) --
        $lib['haproxy_http'] = LogFormat::fromRegex(
            '~^(?:\S{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+?\[\d+\]:\s+)?'
            . '([0-9a-fA-F:.]+):(\d+)\s+'                       // client:port
            . '\[([^\]]+)\]\s+'                                 // accept date
            . '(\S+)\s+(\S+)\s+'                                // frontend, backend/server
            . '([\d\-+/]+)\s+'                                  // Tq/Tw/Tc/Tr/Tt timers
            . '(\d{3}|-1)\s+(\d+|-)\s+'                          // status, bytes_read
            . '(\S+)\s+(\S+)\s+(\S+)\s+'                         // req cookie, res cookie, term state
            . '([\d/]+)\s+([\d/]+)\s+'                           // conn counts, queues
            . '(?:\{[^}]*\}\s+)*'                                // optional captured headers
            . '"((?:[^"\\\\]|\\\\.)*)"\s*$~',                    // "METHOD uri HTTP/x"
            [
                'remote_addr', 'remote_port', 'time', 'frontend', 'backend', 'timers',
                'status', 'bytes', 'cookie.req', 'cookie.res', 'conn_status',
                'conn_counts', 'queues', 'request',
            ],
            'haproxy_http',
            ['time_format' => 'd/M/Y:H:i:s.v']
        );

        $lib['aws_alb'] = LogFormat::fromRegex(
            '~^(\S+) (\S+) (\S+) ([0-9a-fA-F:.]+):(\d+) (\S+) '
            . '(-?[\d.]+) (-?[\d.]+) (-?[\d.]+) (\d{3}|-) (\d{3}|-) (\d+) (\d+) '
            . '"((?:[^"\\\\]|\\\\.)*)" "((?:[^"\\\\]|\\\\.)*)" (\S+) (\S+)(?:\s.*)?$~',
            [
                'alb_type', 'time', 'elb', 'remote_addr', 'remote_port', 'upstream_addr',
                'request_processing_time', 'dur_s', 'response_processing_time',
                'status', 'upstream_status', 'bytes_in', 'bytes',
                'request', 'header_in.user-agent', 'var.ssl_cipher', 'var.ssl_protocol',
            ],
            'aws_alb'
        );

        $lib['cloudfront'] = LogFormat::fromRegex(
            "~^(\\d{4}-\\d{2}-\\d{2})\t(\\d{2}:\\d{2}:\\d{2})\t(\\S+)\t(\\d+|-)\t(\\S+)\t(\\S+)\t"
            . "(\\S+)\t(\\S+)\t(\\d{3}|-)\t(\\S*)\t(\\S*)\t(\\S*)\t(\\S*)\t(\\S+)\t(\\S+)\t"
            . "(\\S+)\t(\\S+)\t(\\d+|-)\t([\\d.]+|-)(?:\t.*)?$~",
            [
                'date', 'time_hms', 'edge_location', 'bytes', 'remote_addr', 'method',
                // cs(Host) is the CloudFront distribution domain (d111….cloudfront.net);
                // x-host-header is the Host the VIEWER actually asked for, which is the site
                // the operator recognises, so that one becomes `vhost`.
                'cdn_host', 'uri', 'status', 'header_in.referer', 'header_in.user-agent',
                'query_raw', 'cookie.all', 'edge_result_type', 'edge_request_id',
                'vhost', 'scheme', 'bytes_in', 'dur_s',
            ],
            'cloudfront',
            // CloudFront percent-encodes the UA, referer and query in its W3C log.
            ['urldecode' => ['header_in.user-agent', 'header_in.referer', 'query_raw', 'uri']]
        );

        return $lib;
    }

    /**
     * Fetch one library format by name, or null when there is no such format.
     */
    public static function formatByName(string $name): ?LogFormat
    {
        return self::library()[$name] ?? null;
    }

    /**
     * Score sample lines against the whole library and return ranked candidates.
     *
     * Scoring is STRUCTURAL, which is the whole point. A format "matching" only proves its
     * regex accepted the bytes; what we actually need to know is whether the fields it
     * produced are semantically the things they claim to be. So each parsed record is graded
     * on questions with objectively right answers — does field `remote_addr` parse as an IP,
     * does `time` parse as a date, is `status` a real HTTP status, is `bytes` numeric-or-dash,
     * does `request` decompose into a real method plus an HTTP version — and the confidence
     * is (fraction of lines parsed) x (mean structural grade).
     *
     * That is why `apache_common` cannot win on a `combined` line: both patterns are anchored
     * at end-of-line, so common simply does not parse it, and even if it did the missing
     * referer/UA columns would not earn it any structural credit.
     *
     * @param string[] $lines Sample lines (200 is a good number; order does not matter).
     * @param int      $max   How many candidates to return.
     *
     * @return array<int,array{name:string,confidence:float,parsed:int,total:int,format:LogFormat,fields:string[],samples:array<int,array<string,string>>}>
     */
    public static function detectFromSample(array $lines, int $max = 5): array
    {
        // W3C-style logs (CloudFront) carry '#Version'/'#Fields' headers; blank lines and
        // comments are not records and must not count against any candidate.
        $lines = array_values(array_filter($lines, static function ($l): bool {
            $l = trim((string) $l);
            return $l !== '' && $l[0] !== '#';
        }));

        if ($lines === []) {
            return [];
        }
        // Bound the work: 200 lines is plenty to separate a dozen formats.
        if (count($lines) > 200) {
            $lines = array_slice($lines, -200);
        }

        $candidates = [];

        foreach (self::library() as $name => $fmt) {
            $parsed  = 0;
            $grade   = 0.0;
            $samples = [];

            foreach ($lines as $line) {
                $rec = $fmt->parse($line);
                if ($rec === null) {
                    continue;
                }
                $parsed++;
                $grade += self::structuralGrade($rec);
                if (count($samples) < 5) {
                    $samples[] = $rec;
                }
            }

            if ($parsed === 0) {
                continue;
            }

            $parseRate  = $parsed / count($lines);
            $meanGrade  = $grade / $parsed;
            $confidence = round($parseRate * $meanGrade * 100, 1);

            $candidates[] = [
                'name'       => $name,
                'confidence' => $confidence,
                'parsed'     => $parsed,
                'total'      => count($lines),
                'format'     => $fmt,
                'fields'     => $fmt->fieldMap(),
                'samples'    => $samples,
            ];
        }

        // Highest confidence first; on a tie the richer format wins, because a format that
        // captures Sec-CH-UA in addition to everything else is strictly more useful and
        // cannot have got there by luck (the columns had to be present to parse at all).
        usort($candidates, static function (array $a, array $b): int {
            if ($a['confidence'] !== $b['confidence']) {
                return $b['confidence'] <=> $a['confidence'];
            }
            return count($b['fields']) <=> count($a['fields']);
        });

        return array_slice($candidates, 0, max(1, $max));
    }

    /**
     * Grade one parsed record on how well its fields match what they claim to be.
     *
     * Returns 0.0-1.0. Only checks that APPLY are counted, so a format with fewer fields is
     * neither rewarded nor punished for the fields it does not have — it is punished, in
     * detectFromSample, by simply failing to parse richer lines.
     *
     * @param array<string,string> $rec
     */
    private static function structuralGrade(array $rec): float
    {
        $score = 0.0;
        $count = 0;

        // --- Field 1 must be a client address -----------------------------------
        if (isset($rec['remote_addr'])) {
            $count++;
            $v = $rec['remote_addr'];
            if (filter_var($v, FILTER_VALIDATE_IP) !== false) {
                $score += 1.0;
            } elseif ($v === '-' || $v === '') {
                $score += 0.2;                                    // legal but uninformative
            } elseif (preg_match('/^[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$/', $v)) {
                $score += 0.6;                                    // HostnameLookups On
            }
        }

        // --- The timestamp must actually be a timestamp --------------------------
        if (isset($rec['time'])) {
            $count++;
            if (self::looksLikeTime($rec['time'])) {
                $score += 1.0;
            }
        } elseif (isset($rec['date'], $rec['time_hms'])) {
            $count++;
            if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $rec['date'])
                && preg_match('/^\d{2}:\d{2}:\d{2}$/', $rec['time_hms'])) {
                $score += 1.0;
            }
        }

        // --- Status must be a real HTTP status ------------------------------------
        if (isset($rec['status'])) {
            $count++;
            $s = (int) $rec['status'];
            if ($s >= 100 && $s <= 599) {
                $score += 1.0;
            }
        }

        // --- Bytes must be numeric, or Apache's '-' for zero ----------------------
        if (isset($rec['bytes'])) {
            $count++;
            if ($rec['bytes'] === '-' || ctype_digit($rec['bytes'])) {
                $score += 1.0;
            }
        }

        // --- The request line must decompose into method + target + HTTP version --
        if (isset($rec['request'])) {
            $count++;
            $score += self::gradeRequestLine($rec['request']);
        } else {
            if (isset($rec['method'])) {
                $count++;
                $score += self::isHttpMethod($rec['method']) ? 1.0 : 0.0;
            }
            if (isset($rec['proto'])) {
                $count++;
                $score += preg_match('~^HTTP/[0-9.]+$~i', $rec['proto']) ? 1.0 : 0.0;
            }
            if (isset($rec['uri']) || isset($rec['uri_full'])) {
                $count++;
                $u = $rec['uri'] ?? $rec['uri_full'];
                $score += ($u !== '' && ($u[0] === '/' || str_contains($u, '://'))) ? 1.0 : 0.0;
            }
        }

        // --- Referer is a URL, a '-', or (rarely) a bare path ---------------------
        if (isset($rec['header_in.referer'])) {
            $count++;
            $r = $rec['header_in.referer'];
            if ($r === '-' || $r === '') {
                $score += 1.0;
            } elseif (preg_match('~^[a-z][a-z0-9+.\-]*://~i', $r) || $r[0] === '/') {
                $score += 1.0;
            } else {
                $score += 0.3;                                    // junk referers are common
            }
        }

        // --- A User-Agent field that never contains a slash is probably not one ---
        if (isset($rec['header_in.user-agent'])) {
            $count++;
            $ua = $rec['header_in.user-agent'];
            if ($ua === '-' || $ua === '' || str_contains($ua, '/') || str_contains($ua, ' ')) {
                $score += 1.0;
            } else {
                $score += 0.3;
            }
        }

        // A format that produced nothing gradeable gets no credit at all.
        return $count === 0 ? 0.0 : $score / $count;
    }

    /**
     * Grade a `"METHOD target HTTP/x.y"` request line.
     *
     * Full credit needs all three parts. A malformed request line is genuinely logged by
     * every webserver (attackers send them constantly), so a partial match still earns
     * something rather than disqualifying an otherwise correct format.
     */
    private static function gradeRequestLine(string $request): float
    {
        if ($request === '-' || $request === '') {
            return 0.5;                                           // aborted request: legal
        }
        if (preg_match('~^([A-Za-z\-_]{3,20})\s+(\S+)\s+(HTTP/[0-9.]+)$~', $request, $m)) {
            return self::isHttpMethod($m[1]) ? 1.0 : 0.7;
        }
        if (preg_match('~^([A-Za-z\-_]{3,20})\s+(\S+)$~', $request, $m)) {
            return self::isHttpMethod($m[1]) ? 0.7 : 0.3;         // HTTP/0.9 or truncated
        }
        return 0.1;
    }

    /** Is this token one of the HTTP methods a webserver actually logs? */
    private static function isHttpMethod(string $m): bool
    {
        static $methods = [
            'GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT',
            'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK', 'REPORT',
            'SEARCH', 'PURGE', 'BASELINE-CONTROL',
        ];
        return in_array(strtoupper($m), $methods, true);
    }

    /**
     * Does this token look like a timestamp in any of the shapes webservers emit?
     *
     * Deliberately structural: an Apache bracketed date, an ISO-8601 stamp, a
     * `YYYY-MM-DD HH:MM:SS` stamp, or an epoch value of plausible magnitude.
     */
    private static function looksLikeTime(string $v): bool
    {
        $v = trim($v, '[]');
        if ($v === '') {
            return false;
        }
        // Apache / nginx $time_local: 10/Sep/2026:09:57:08 +0000
        if (preg_match('~^\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(\.\d+)?(\s[+-]\d{4})?$~', $v)) {
            return true;
        }
        // ISO-8601 with T or a space separator.
        if (preg_match('~^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}~', $v)) {
            return true;
        }
        // Epoch seconds / milliseconds / microseconds, incl. Caddy's float seconds.
        if (preg_match('~^\d{9,19}(\.\d+)?$~', $v)) {
            return true;
        }
        return false;
    }

    // =============================================================================
    // Ladder step 3 — propose a pattern from a sample
    // =============================================================================

    /**
     * Last-resort: generate a candidate regex from sample lines.
     *
     * The approach is to tokenize each line into a SHAPE — the sequence of structural token
     * kinds (bracketed group, quoted string, bare token) — take the shape the majority of the
     * sample agrees on, and then name the slots by what they contain rather than by position
     * alone. This produces a pattern that is at least self-consistent across the sample; the
     * setup UI still shows it to a human for confirmation, as SPEC §8 requires.
     *
     * The returned pattern is guaranteed to compile and to pass Security::validateUserRegex().
     * Returns null when the sample has no agreed shape, which is the honest answer.
     *
     * @param string[] $lines
     */
    public static function proposeRegex(array $lines): ?string
    {
        $lines = array_values(array_filter($lines, static function ($l): bool {
            $l = trim((string) $l);
            return $l !== '' && $l[0] !== '#';
        }));
        if ($lines === []) {
            return null;
        }

        // Group the sample by structural shape and take the most common one.
        $byShape = [];
        foreach ($lines as $line) {
            $tokens = self::shapeTokens((string) $line);
            if ($tokens === []) {
                continue;
            }
            $key = implode(',', array_column($tokens, 0));
            $byShape[$key]['count'] = ($byShape[$key]['count'] ?? 0) + 1;
            $byShape[$key]['sample'] = $byShape[$key]['sample'] ?? $tokens;
        }
        if ($byShape === []) {
            return null;
        }
        uasort($byShape, static fn(array $a, array $b): int => $b['count'] <=> $a['count']);
        $winner = reset($byShape);

        // Fewer than a third of the lines agreeing means there is no shape to propose.
        if ($winner['count'] * 3 < count($lines)) {
            return null;
        }

        $tokens = $winner['sample'];

        // A log record has columns. One or two tokens is not a shape worth proposing — it is
        // what a stack trace, a JSON blob or a blank-ish line tokenizes to, and proposing a
        // one-group pattern for it would be a confident answer to a question we cannot answer.
        if (count($tokens) < 4) {
            return null;
        }

        $names = self::nameShapeSlots($tokens);

        // Refuse a proposal that recognised nothing. The whole value of a generated pattern
        // is that its groups have MEANING; a row of f1..f9 placeholders tells the operator
        // nothing they could confirm, and SPEC §8 requires them to confirm it.
        $recognised = count(array_intersect($names, ['ip', 'time', 'request', 'status', 'bytes']));
        if ($recognised < 2) {
            return null;
        }

        $regex = '';
        foreach ($tokens as $i => $tok) {
            if ($i > 0) {
                $regex .= '\s+';
            }
            $name = $names[$i];
            switch ($tok[0]) {
                case 'bracket':
                    $regex .= '\[(?<' . $name . '>[^\]]*)\]';
                    break;
                case 'quoted':
                    $regex .= '"(?<' . $name . '>(?:[^"\\\\]|\\\\.)*)"';
                    break;
                default:
                    $regex .= '(?<' . $name . '>\S+)';
                    break;
            }
        }

        $pattern = '~^' . $regex . '\s*$~';

        // Never hand back something that would not survive the ReDoS gate or would not even
        // match the sample it was derived from.
        if (Security::validateUserRegex($pattern) !== null) {
            return null;
        }
        if (@preg_match($pattern, (string) $lines[0]) === false) {
            return null;
        }

        return $pattern;
    }

    /**
     * Build a LogFormat from a proposed or operator-supplied regex.
     *
     * Translates the word-only PCRE group names into Loghound's canonical raw field names
     * (`ua` -> `header_in.user-agent`), which is the bridge proposeRegex() needs because PCRE
     * forbids the dots and dashes in the canonical vocabulary.
     */
    public static function formatFromRegex(string $pattern, string $name = 'custom'): ?LogFormat
    {
        if (Security::validateUserRegex($pattern) !== null) {
            return null;
        }
        $fields = [];
        if (preg_match_all('/\(\?P?<([A-Za-z_][A-Za-z0-9_]*)>/', $pattern, $m)) {
            foreach ($m[1] as $group) {
                $fields[] = self::REGEX_FIELD_ALIASES[$group] ?? $group;
            }
        }
        if ($fields === []) {
            return null;
        }
        return LogFormat::fromRegex($pattern, $fields, $name, ['unescape' => true]);
    }

    /**
     * Tokenize a line into structural slots: bracketed, quoted, or bare.
     *
     * @return array<int,array{0:string,1:string}> [kind, value]
     */
    private static function shapeTokens(string $line): array
    {
        $line   = rtrim($line, "\r\n");
        $tokens = [];
        $len    = strlen($line);
        $i      = 0;

        while ($i < $len) {
            $c = $line[$i];
            if ($c === ' ' || $c === "\t") {
                $i++;
                continue;
            }
            if ($c === '[') {
                $close = strpos($line, ']', $i);
                if ($close !== false) {
                    $tokens[] = ['bracket', substr($line, $i + 1, $close - $i - 1)];
                    $i = $close + 1;
                    continue;
                }
            }
            if ($c === '"') {
                // Walk to the next quote that is not backslash-escaped.
                $j = $i + 1;
                while ($j < $len) {
                    if ($line[$j] === '\\') {
                        $j += 2;
                        continue;
                    }
                    if ($line[$j] === '"') {
                        break;
                    }
                    $j++;
                }
                if ($j < $len) {
                    $tokens[] = ['quoted', substr($line, $i + 1, $j - $i - 1)];
                    $i = $j + 1;
                    continue;
                }
            }
            $j = $i;
            while ($j < $len && $line[$j] !== ' ' && $line[$j] !== "\t") {
                $j++;
            }
            $tokens[] = ['bare', substr($line, $i, $j - $i)];
            $i = $j;
        }

        // A hostile line could produce thousands of slots; a real log line has under 40.
        return count($tokens) > 64 ? [] : $tokens;
    }

    /**
     * Assign a group name to every slot of a proposed shape.
     *
     * Naming is driven by content where content is decisive (an IP, a date, a request line,
     * a 3-digit status) and by position only as a fallback, which keeps the proposal useful
     * on formats whose columns are in an unusual order.
     *
     * @param array<int,array{0:string,1:string}> $tokens
     * @return string[]
     */
    private static function nameShapeSlots(array $tokens): array
    {
        $names       = [];
        $haveIp      = false;
        $haveTime    = false;
        $haveRequest = false;
        $haveStatus  = false;
        $haveBytes   = false;
        $quotedAfter = 0;   // quoted slots seen after the request line
        $spare       = 1;

        foreach ($tokens as $i => $tok) {
            [$kind, $value] = $tok;

            if (!$haveIp && $kind === 'bare' && filter_var($value, FILTER_VALIDATE_IP) !== false) {
                $names[$i] = 'ip';
                $haveIp = true;
                continue;
            }
            if (!$haveTime && self::looksLikeTime($value)) {
                $names[$i] = 'time';
                $haveTime = true;
                continue;
            }
            if (!$haveRequest && $kind === 'quoted' && self::gradeRequestLine($value) >= 0.7) {
                $names[$i] = 'request';
                $haveRequest = true;
                continue;
            }
            if ($haveRequest && !$haveStatus && $kind === 'bare' && preg_match('/^\d{3}$/', $value)) {
                $names[$i] = 'status';
                $haveStatus = true;
                continue;
            }
            if ($haveStatus && !$haveBytes && $kind === 'bare'
                && ($value === '-' || ctype_digit($value))) {
                $names[$i] = 'bytes';
                $haveBytes = true;
                continue;
            }
            if ($haveRequest && $kind === 'quoted') {
                // Convention across every mainstream format: referer then user-agent.
                $quotedAfter++;
                if ($quotedAfter === 1) {
                    $names[$i] = 'referer';
                    continue;
                }
                if ($quotedAfter === 2) {
                    $names[$i] = 'ua';
                    continue;
                }
            }
            $names[$i] = 'f' . $spare++;
        }

        return $names;
    }

    // =============================================================================
    // Sampling helper
    // =============================================================================

    /**
     * Read the last N lines of a log file without loading the whole thing.
     *
     * Used by the setup wizard to feed detectFromSample(). Reads backwards in 64 KB chunks,
     * so it is O(N lines) rather than O(file size) on a multi-gigabyte access log.
     *
     * The path is resolved through Security::safePath() against the operator's allowed log
     * roots, so this cannot be pointed at /etc/shadow by editing a form field.
     *
     * @param string[] $allowedRoots
     * @return string[] Oldest-first.
     */
    public static function tailLines(string $path, int $n, array $allowedRoots): array
    {
        $real = Security::safePath($path, $allowedRoots);
        if ($real === null || !is_file($real) || !is_readable($real)) {
            return [];
        }

        $fh = @fopen($real, 'rb');
        if ($fh === false) {
            return [];
        }

        $chunk = 65536;
        $size  = (int) filesize($real);
        $pos   = $size;
        $buf   = '';
        $lines = [];

        while ($pos > 0 && count($lines) <= $n) {
            $read = (int) min($chunk, $pos);
            $pos -= $read;
            fseek($fh, $pos);
            $buf = (string) fread($fh, $read) . $buf;
            $lines = explode("\n", $buf);
            // The first element may be a partial line unless we reached the start of file.
            if ($pos > 0) {
                array_shift($lines);
            }
        }
        fclose($fh);

        $lines = array_values(array_filter($lines, static fn($l) => trim((string) $l) !== ''));
        return array_slice($lines, -$n);
    }

    // =============================================================================
    // Apache config walking
    // =============================================================================

    /**
     * Read and process one Apache config file, recursing through Include directives.
     *
     * @param array<string,mixed> $st Mutable walk state (see discoverFromApacheConfig).
     */
    private static function apacheWalk(string $file, array &$st, int $depth): void
    {
        if ($depth > self::MAX_INCLUDE_DEPTH || $st['files'] >= self::MAX_CONFIG_FILES) {
            return;
        }
        $real = Security::safePath($file, $st['roots']);
        if ($real === null || !is_file($real) || !is_readable($real)) {
            return;
        }
        // Cycle guard: a config that Includes its own directory would otherwise loop forever.
        if (isset($st['seen'][$real])) {
            return;
        }
        $st['seen'][$real] = true;
        $st['files']++;

        $text = self::readCapped($real);
        if ($text === null) {
            return;
        }

        foreach (self::logicalLines($text) as $line) {
            $args = self::apacheArgs($line);
            if ($args === []) {
                continue;
            }
            $directive = strtolower($args[0]['v']);

            switch ($directive) {
                case 'define':
                    // `Define APACHE_LOG_DIR /var/log/apache2`
                    if (isset($args[1])) {
                        $st['defines'][$args[1]['v']] = $args[2]['v'] ?? '';
                    }
                    break;

                case 'serverroot':
                    if (isset($args[1])) {
                        $st['serverRoot'] = self::expandVars($args[1]['v'], $st['defines']);
                    }
                    break;

                case '<virtualhost':
                    // Push a fresh (unnamed) vhost context; ServerName fills it in.
                    $st['vhost'][] = null;
                    break;

                case '</virtualhost>':
                    array_pop($st['vhost']);
                    break;

                case 'servername':
                    if (isset($args[1]) && $st['vhost'] !== []) {
                        // Strip a :port suffix; the vhost identity is the name.
                        $name = preg_replace('/:\d+$/', '', $args[1]['v']);
                        $st['vhost'][count($st['vhost']) - 1] = $name;
                    }
                    break;

                case 'logformat':
                    // `LogFormat "<fmt>" <nickname>` — or no nickname, which sets the default.
                    if (isset($args[1])) {
                        $nick = $args[2]['v'] ?? '';
                        $st['formats'][$nick] = $args[1]['raw'];
                    }
                    break;

                case 'customlog':
                case 'transferlog':
                    self::apacheCustomLog($directive, $args, $st, $real);
                    break;

                case 'include':
                case 'includeoptional':
                    if (isset($args[1])) {
                        $spec = self::expandVars($args[1]['v'], $st['defines']);
                        // Include paths are relative to ServerRoot, as Apache defines them.
                        if ($spec !== '' && $spec[0] !== '/') {
                            $spec = rtrim($st['serverRoot'], '/') . '/' . $spec;
                        }
                        // Apache treats a directory argument as "every file inside it".
                        if (is_dir($spec)) {
                            $spec = rtrim($spec, '/') . '/*';
                        }
                        foreach (self::globConfigs($spec, $st['roots']) as $inc) {
                            self::apacheWalk($inc, $st, $depth + 1);
                        }
                    }
                    break;
            }
        }
    }

    /**
     * Handle a CustomLog / TransferLog directive: resolve the target and the format.
     *
     * @param array<int,array{v:string,q:bool,raw:string}> $args
     * @param array<string,mixed> $st
     */
    private static function apacheCustomLog(string $directive, array $args, array &$st, string $configFile): void
    {
        if (!isset($args[1])) {
            return;
        }
        $target = self::expandVars($args[1]['v'], $st['defines']);

        // Piped and syslog targets are real and common, and there is no file to tail. Being
        // explicit about skipping them beats emitting a bogus path the operator has to debug.
        if ($target === '' || $target[0] === '|' || str_starts_with($target, 'syslog:')) {
            return;
        }
        if ($target[0] !== '/') {
            $target = rtrim($st['serverRoot'], '/') . '/' . $target;
        }

        // Second argument: either a nickname defined by LogFormat, or a literal format.
        $formatName = null;
        if ($directive === 'transferlog') {
            // TransferLog uses the most recent nickname-less LogFormat, else Common Log Format.
            $format = $st['formats'][''] ?? $st['formats']['common'];
        } elseif (isset($args[2])) {
            $arg = $args[2];
            if (str_contains($arg['v'], '%')) {
                // A literal format string given inline rather than a nickname.
                $format = $arg['raw'];
            } else {
                $formatName = $arg['v'];
                $format = $st['formats'][$formatName] ?? null;
                if ($format === null) {
                    // Nickname defined later in the file, or in a file we could not read.
                    // Record the name so the setup UI can say exactly what is missing.
                    $format = '';
                }
            }
        } else {
            $format = $st['formats'][''] ?? $st['formats']['common'];
        }

        $vhost = null;
        for ($i = count($st['vhost']) - 1; $i >= 0; $i--) {
            if ($st['vhost'][$i] !== null) {
                $vhost = $st['vhost'][$i];
                break;
            }
        }

        if (isset($st['results'][$target])) {
            // The same file can be written by several vhosts; record them all rather than
            // pretending the log belongs to one of them.
            if ($vhost !== null && !in_array($vhost, $st['results'][$target]['vhosts'], true)) {
                $st['results'][$target]['vhosts'][] = $vhost;
            }
            return;
        }

        $st['results'][$target] = [
            'format'      => $format,
            'format_name' => $formatName,
            'vhost'       => $vhost,
            'vhosts'      => $vhost === null ? [] : [$vhost],
            'server'      => 'apache',
            'config'      => $configFile,
        ];
    }

    /**
     * Seed the ${VAR} table Apache configs rely on.
     *
     * On Debian/Ubuntu ${APACHE_LOG_DIR} is not defined in any .conf at all — it comes from
     * /etc/apache2/envvars, which is a shell script sourced by the init wrapper. Reading the
     * `export NAME=value` lines out of it is what makes Debian discovery work at all; without
     * it every CustomLog resolves to a literal '${APACHE_LOG_DIR}/access.log'.
     *
     * @param string[] $configFiles
     * @return array<string,string>
     */
    private static function apacheSeedDefines(array $configFiles): array
    {
        // Sensible distribution defaults, overridden by anything we actually read.
        $defines = [
            'APACHE_LOG_DIR'  => is_dir('/var/log/httpd') ? '/var/log/httpd' : '/var/log/apache2',
            'APACHE_RUN_DIR'  => '/var/run/apache2',
            'APACHE_RUN_USER' => 'www-data',
            'SUFFIX'          => '',
        ];

        $candidates = ['/etc/apache2/envvars', '/etc/httpd/conf/envvars'];
        foreach ($configFiles as $f) {
            $candidates[] = dirname($f) . '/envvars';
        }

        foreach (array_unique($candidates) as $envvars) {
            if (!is_file($envvars) || !is_readable($envvars)) {
                continue;
            }
            $text = self::readCapped($envvars);
            if ($text === null) {
                continue;
            }
            // Only `export NAME=value` lines; we are reading, not executing, the shell script.
            if (preg_match_all('/^\s*export\s+([A-Z_][A-Z0-9_]*)=(.*)$/mi', $text, $m, PREG_SET_ORDER)) {
                foreach ($m as $set) {
                    $val = trim($set[2]);
                    $val = trim($val, "\"'");
                    // Skip values that themselves need shell evaluation.
                    if (str_contains($val, '$(') || str_contains($val, '`')) {
                        continue;
                    }
                    $defines[$set[1]] = $val;
                }
            }
        }

        // Resolve one level of ${VAR} inside the seeded values (envvars does this to itself).
        foreach ($defines as $k => $v) {
            $defines[$k] = self::expandVars($v, $defines);
        }

        return $defines;
    }

    /**
     * The formats Apache defines without any config: Common Log Format and combined.
     *
     * Present so that a `CustomLog ... common` in a config that never declares `common`
     * (because Apache ships it) still resolves to a real format string.
     *
     * @return array<string,string>
     */
    private static function apacheBuiltinFormats(): array
    {
        return [
            'common'         => '"%h %l %u %t \"%r\" %>s %b"',
            'combined'       => '"%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""',
            'combinedio'     => '"%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %I %O"',
            'vhost_common'   => '"%v %h %l %u %t \"%r\" %>s %b"',
            'vhost_combined' => '"%v %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""',
            'referer'        => '"%{Referer}i -> %U"',
            'agent'          => '"%{User-agent}i"',
        ];
    }

    /**
     * Split an Apache directive line into arguments, honouring double quotes.
     *
     * Returns for each argument both the unquoted VALUE (used for paths and nicknames) and
     * the RAW token including its quotes and `\"` escapes (used for LogFormat strings, whose
     * quoting is part of the format and must be stripped exactly once, by LogFormat itself).
     *
     * @return array<int,array{v:string,q:bool,raw:string}>
     */
    private static function apacheArgs(string $line): array
    {
        $args = [];
        $len  = strlen($line);
        $i    = 0;

        while ($i < $len) {
            if ($line[$i] === ' ' || $line[$i] === "\t") {
                $i++;
                continue;
            }
            if ($line[$i] === '"') {
                $j = $i + 1;
                $v = '';
                while ($j < $len) {
                    if ($line[$j] === '\\' && $j + 1 < $len) {
                        $v .= $line[$j + 1];
                        $j += 2;
                        continue;
                    }
                    if ($line[$j] === '"') {
                        break;
                    }
                    $v .= $line[$j];
                    $j++;
                }
                $args[] = ['v' => $v, 'q' => true, 'raw' => substr($line, $i, $j - $i + 1)];
                $i = $j + 1;
                continue;
            }
            $j = $i;
            while ($j < $len && $line[$j] !== ' ' && $line[$j] !== "\t") {
                $j++;
            }
            $tok = substr($line, $i, $j - $i);
            $args[] = ['v' => $tok, 'q' => false, 'raw' => $tok];
            $i = $j;
        }

        // Normalise block-open tags so `<VirtualHost *:443>` matches the switch above.
        if ($args !== [] && $args[0]['v'] !== '' && $args[0]['v'][0] === '<') {
            $args[0]['v'] = strtolower(rtrim($args[0]['v'], '>'));
            if (str_starts_with($args[0]['v'], '</')) {
                $args[0]['v'] .= '>';
            }
        }

        return $args;
    }

    // =============================================================================
    // nginx config walking
    // =============================================================================

    /**
     * Read and process one nginx config file, recursing through include directives.
     *
     * @param array<string,mixed> $st
     */
    private static function nginxWalk(string $file, array &$st, int $depth): void
    {
        if ($depth > self::MAX_INCLUDE_DEPTH || $st['files'] >= self::MAX_CONFIG_FILES) {
            return;
        }
        $real = Security::safePath($file, $st['roots']);
        if ($real === null || !is_file($real) || !is_readable($real)) {
            return;
        }
        if (isset($st['seen'][$real])) {
            return;
        }
        $st['seen'][$real] = true;
        $st['files']++;

        $text = self::readCapped($real);
        if ($text === null) {
            return;
        }

        foreach (self::nginxStatements($text) as $stmt) {
            [$type, $tokens] = $stmt;

            if ($type === 'close') {
                array_pop($st['vhost']);
                continue;
            }
            if ($tokens === []) {
                continue;
            }
            $directive = strtolower($tokens[0]);

            if ($type === 'open') {
                // Only `server` blocks change the vhost context; everything else is pushed
                // as a placeholder so the matching '}' pops the right thing.
                $st['vhost'][] = $directive === 'server' ? null : false;
                continue;
            }

            switch ($directive) {
                case 'server_name':
                    if (isset($tokens[1]) && $st['vhost'] !== []) {
                        $top = count($st['vhost']) - 1;
                        if ($st['vhost'][$top] === null) {
                            $st['vhost'][$top] = $tokens[1];
                        }
                    }
                    break;

                case 'log_format':
                    if (isset($tokens[1])) {
                        $name  = $tokens[1];
                        $parts = array_slice($tokens, 2);
                        // Drop the `escape=json|default|none` option token if present.
                        $parts = array_values(array_filter(
                            $parts,
                            static fn(string $p): bool => !str_starts_with($p, 'escape=')
                        ));
                        // nginx concatenates the remaining quoted strings with no separator.
                        $st['formats'][$name] = implode('', $parts);
                    }
                    break;

                case 'access_log':
                    self::nginxAccessLog($tokens, $st, $real);
                    break;

                case 'include':
                    if (isset($tokens[1])) {
                        $spec = $tokens[1];
                        if ($spec !== '' && $spec[0] !== '/') {
                            $spec = rtrim($st['prefix'], '/') . '/' . $spec;
                        }
                        foreach (self::globConfigs($spec, $st['roots']) as $inc) {
                            self::nginxWalk($inc, $st, $depth + 1);
                        }
                    }
                    break;
            }
        }
    }

    /**
     * Handle an nginx `access_log` directive.
     *
     * @param string[] $tokens
     * @param array<string,mixed> $st
     */
    private static function nginxAccessLog(array $tokens, array &$st, string $configFile): void
    {
        if (!isset($tokens[1])) {
            return;
        }
        $target = $tokens[1];

        // `access_log off;` disables logging for that context — nothing to tail.
        if ($target === 'off' || $target === '') {
            return;
        }
        // syslog:, memory: and stderr targets have no file behind them.
        if (str_starts_with($target, 'syslog:') || str_starts_with($target, 'memory:')
            || $target === 'stderr' || $target === '/dev/stdout' || $target === '/dev/stderr') {
            return;
        }
        if ($target[0] !== '/') {
            $target = rtrim($st['prefix'], '/') . '/' . $target;
        }

        // Third token is the format name unless it is an option like `buffer=32k`.
        $formatName = 'combined';
        if (isset($tokens[2]) && !str_contains($tokens[2], '=') && $tokens[2] !== 'gzip') {
            $formatName = $tokens[2];
        }
        $format = $st['formats'][$formatName] ?? '';

        $vhost = null;
        for ($i = count($st['vhost']) - 1; $i >= 0; $i--) {
            if (is_string($st['vhost'][$i])) {
                $vhost = $st['vhost'][$i];
                break;
            }
        }

        if (isset($st['results'][$target])) {
            if ($vhost !== null && !in_array($vhost, $st['results'][$target]['vhosts'], true)) {
                $st['results'][$target]['vhosts'][] = $vhost;
            }
            return;
        }

        $st['results'][$target] = [
            'format'      => $format,
            'format_name' => $formatName,
            'vhost'       => $vhost,
            'vhosts'      => $vhost === null ? [] : [$vhost],
            'server'      => 'nginx',
            'config'      => $configFile,
        ];
    }

    /**
     * Split an nginx config into statements and block markers.
     *
     * nginx's grammar is small enough to tokenize directly: `#` starts a comment outside
     * quotes, `;` ends a simple directive, `{` opens a block (the tokens before it are the
     * block header), `}` closes one. Quoted strings keep their contents verbatim, which is
     * essential because a log_format body is full of `;`-free but space-rich text.
     *
     * @return array<int,array{0:string,1:string[]}> ['stmt'|'open'|'close', tokens]
     */
    private static function nginxStatements(string $text): array
    {
        $out    = [];
        $tokens = [];
        $buf    = '';
        $quote  = '';
        $len    = strlen($text);

        for ($i = 0; $i < $len; $i++) {
            $c = $text[$i];

            if ($quote !== '') {
                if ($c === '\\' && $i + 1 < $len) {
                    // Keep the escape sequence intact: `\"` inside a log_format is data.
                    $buf .= $c . $text[$i + 1];
                    $i++;
                    continue;
                }
                if ($c === $quote) {
                    $quote = '';
                    $tokens[] = $buf;
                    $buf = '';
                    continue;
                }
                $buf .= $c;
                continue;
            }

            if ($c === '"' || $c === "'") {
                // Flush any bare token that ran straight into the quote.
                if ($buf !== '') {
                    $tokens[] = $buf;
                    $buf = '';
                }
                $quote = $c;
                continue;
            }
            if ($c === '#') {
                if ($buf !== '') {
                    $tokens[] = $buf;
                    $buf = '';
                }
                $nl = strpos($text, "\n", $i);
                $i  = $nl === false ? $len : $nl;
                continue;
            }
            if ($c === ';' || $c === '{' || $c === '}') {
                if ($buf !== '') {
                    $tokens[] = $buf;
                    $buf = '';
                }
                if ($c === ';') {
                    if ($tokens !== []) {
                        $out[] = ['stmt', $tokens];
                    }
                } elseif ($c === '{') {
                    $out[] = ['open', $tokens];
                } else {
                    $out[] = ['close', []];
                }
                $tokens = [];
                continue;
            }
            if ($c === ' ' || $c === "\t" || $c === "\n" || $c === "\r") {
                if ($buf !== '') {
                    $tokens[] = $buf;
                    $buf = '';
                }
                continue;
            }
            $buf .= $c;
        }

        return $out;
    }

    // =============================================================================
    // Shared file helpers
    // =============================================================================

    /**
     * The set of directories discovery is allowed to read configuration from.
     *
     * Defaults to the parent directory of every config file and vhost dir we were pointed at,
     * plus /etc. An `Include` that resolves outside this set is refused by Security::safePath,
     * which is what stops a compromised vhost snippet from exfiltrating arbitrary files
     * through the setup UI's "here is what we found" screen.
     *
     * @param string[] $configFiles
     * @param string[] $vhostDirs
     * @param array<string,mixed> $opts
     * @return string[]
     */
    private static function configRoots(array $configFiles, array $vhostDirs, array $opts): array
    {
        if (!empty($opts['allowed_config_roots']) && is_array($opts['allowed_config_roots'])) {
            return $opts['allowed_config_roots'];
        }
        $roots = ['/etc'];
        foreach ($configFiles as $f) {
            $roots[] = dirname((string) $f);
        }
        foreach ($vhostDirs as $d) {
            $roots[] = (string) $d;
        }
        return array_values(array_unique(array_filter($roots)));
    }

    /**
     * Expand `glob()` and keep only files that resolve inside the allowed config roots.
     *
     * @param string[] $roots
     * @return string[]
     */
    private static function globConfigs(string $spec, array $roots): array
    {
        // GLOB_NOSORT would be faster but a stable order makes discovery reproducible, and
        // reproducible output is what lets an operator diff two setup runs.
        $hits = @glob($spec, GLOB_BRACE);
        if ($hits === false) {
            return [];
        }
        $out = [];
        foreach ($hits as $hit) {
            if (!is_file($hit)) {
                continue;
            }
            $real = Security::safePath($hit, $roots);
            if ($real !== null) {
                $out[] = $real;
            }
        }
        return $out;
    }

    /**
     * Read a config file with a hard size cap.
     *
     * Returns null rather than a truncated document, because half a config is worse than no
     * config: it would silently drop the CustomLog lines that happen to live past the cap.
     */
    private static function readCapped(string $path): ?string
    {
        $size = @filesize($path);
        if ($size === false || $size > self::MAX_CONFIG_BYTES) {
            return null;
        }
        $text = @file_get_contents($path);
        return $text === false ? null : $text;
    }

    /**
     * Split config text into logical lines: comments dropped, `\`-continuations joined.
     *
     * Apache allows a directive to span lines with a trailing backslash, and the recommended
     * Loghound LogFormat in SPEC §8 uses exactly that, so failing to join would mean failing
     * to detect our own recommended format.
     *
     * @return string[]
     */
    private static function logicalLines(string $text): array
    {
        $out     = [];
        $pending = '';

        foreach (preg_split('/\r\n|\n|\r/', $text) ?: [] as $raw) {
            $line = rtrim($raw);
            if ($pending === '') {
                $trimmed = ltrim($line);
                // Apache comments must start the line; a '#' mid-directive is data.
                if ($trimmed === '' || $trimmed[0] === '#') {
                    continue;
                }
                $line = $trimmed;
            }
            if (str_ends_with($line, '\\')) {
                $pending .= substr($line, 0, -1);
                continue;
            }
            $out[] = $pending . $line;
            $pending = '';
        }
        if ($pending !== '') {
            $out[] = $pending;
        }
        return $out;
    }

    /**
     * Expand `${NAME}` references using the Define/envvars table.
     *
     * Unknown variables are left as-is on purpose: an unresolved `${FOO}` in the reported
     * path is an honest "we could not work this out" that the setup UI can show, whereas
     * silently deleting it would produce a plausible-looking but wrong path.
     *
     * @param array<string,string> $defines
     */
    private static function expandVars(string $value, array $defines): string
    {
        if (!str_contains($value, '${')) {
            return $value;
        }
        return (string) preg_replace_callback(
            '/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/',
            static fn(array $m): string => $defines[$m[1]] ?? $m[0],
            $value
        );
    }
}
