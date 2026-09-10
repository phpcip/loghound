<?php
/**
 * Loghound — Log format compiler.
 *
 * Turns an Apache `LogFormat` string, an nginx `log_format` string, a JSON field map or a
 * hand-written regex into a *compiled parser*: one anchored PCRE plus an ordered list of
 * field names, or (for JSON logs) a key-path map applied to the decoded object.
 *
 * Why compile rather than hand-write parsers per format: the operator's real format is
 * whatever is in their httpd.conf, and it is almost never one of the three well-known ones.
 * `LogDetect` reads the actual server config and hands the exact format string to this class,
 * which is what makes zero-configuration setup deterministic instead of a guess.
 *
 * Output vocabulary (deliberately shared between the Apache and nginx front-ends so that
 * `Parser` only ever has to know ONE set of raw key names):
 *
 *   remote_addr  ident  remote_user  time  request  method  uri  uri_full  query  query_raw
 *   proto  status  bytes  bytes_out  bytes_in  dur_us  dur_ms  dur_s  upstream_time
 *   vhost  port  scheme  conn_status  request_id
 *   header_in.<lowercased-header>     e.g. header_in.user-agent, header_in.x-forwarded-for
 *   header_out.<lowercased-header>
 *   env.<name>   note.<name>   var.<name>   cookie.<name>
 *
 * Security notes:
 *  - Everything here consumes attacker-controlled bytes. `parse()` never throws, never
 *    executes anything, and returns null rather than a partial record.
 *  - Generated patterns use only bounded, non-nested quantifiers so they cannot backtrack
 *    catastrophically. A *user-supplied* pattern (`fromRegex`) is the one exception and must
 *    be vetted through Security::validateUserRegex() by the caller before it gets here.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound;

final class LogFormat
{
    /** Compiled to a PCRE that is matched against the whole line. */
    public const KIND_REGEX = 'regex';

    /** Compiled to a key-path map applied to a decoded JSON object. */
    public const KIND_JSON = 'json';

    /**
     * Apache directive letter => [canonical field name, pattern type].
     *
     * `%v` is typed `host` (not `token`) on purpose: the recommended Loghound format starts
     * with `%v:%p`, and a greedy `\S+` for the vhost would backtrack across the colon into
     * whatever colon appears last on the line. Excluding ':' from the vhost class removes
     * the ambiguity entirely instead of relying on the engine to backtrack "correctly".
     */
    private const APACHE_DIRECTIVES = [
        'h' => ['remote_addr',  'token'],
        'a' => ['remote_addr',  'token'],   // client IP ignoring X-Forwarded-For
        'A' => ['local_addr',   'token'],
        'l' => ['ident',        'token'],
        'u' => ['remote_user',  'token'],
        't' => ['time',         'time_bracket'],
        'r' => ['request',      'text'],
        's' => ['status',       'status'],
        'b' => ['bytes',        'num'],     // '-' when zero, hence the num type allows '-'
        'O' => ['bytes_out',    'num'],
        'I' => ['bytes_in',     'num'],
        'S' => ['bytes_total',  'num'],
        'D' => ['dur_us',       'num'],     // microseconds
        'T' => ['dur_s',        'float'],   // seconds (integer unless %{ms}T / %{us}T used)
        'v' => ['vhost',        'host'],
        'V' => ['vhost',        'host'],
        'p' => ['port',         'port'],
        'H' => ['proto',        'text'],
        'm' => ['method',       'token'],
        'U' => ['uri',          'path'],    // path only, never contains '?'
        'q' => ['query',        'query'],   // '' or '?...' — leading '?' included by Apache
        'f' => ['filename',     'text'],
        'k' => ['keepalive',    'num'],
        'X' => ['conn_status',  'token'],
        'P' => ['pid',          'token'],
        'L' => ['request_id',   'token'],
        'R' => ['handler',      'token'],
    ];

    /**
     * nginx variable name => [canonical field name, pattern type].
     *
     * Only the fixed variables need an entry; `$http_*`, `$sent_http_*`, `$upstream_http_*`
     * and `$cookie_*` are handled generically below because their suffix is the header name.
     */
    private const NGINX_VARS = [
        'remote_addr'                     => ['remote_addr',    'token'],
        'binary_remote_addr'              => ['remote_addr',    'token'],
        'proxy_protocol_addr'             => ['proxy_addr',     'optional'],
        'realip_remote_addr'              => ['proxy_addr',     'optional'],
        'remote_user'                     => ['remote_user',    'token'],
        'time_local'                      => ['time',           'time_local'],
        'time_iso8601'                    => ['time',           'time_iso'],
        'msec'                            => ['time',           'float'],
        'request'                         => ['request',        'text'],
        'status'                          => ['status',         'status'],
        'body_bytes_sent'                 => ['bytes',          'num'],
        'bytes_sent'                      => ['bytes_out',      'num'],
        'request_length'                  => ['bytes_in',       'num'],
        'request_time'                    => ['dur_s',          'float'],
        'upstream_response_time'          => ['upstream_time',  'floatlist'],
        'upstream_connect_time'           => ['upstream_connect_time', 'floatlist'],
        'upstream_header_time'            => ['upstream_header_time',  'floatlist'],
        'upstream_response_length'        => ['upstream_len',   'floatlist'],
        'upstream_addr'                   => ['upstream_addr',  'optional'],
        'upstream_status'                 => ['upstream_status', 'optional'],
        'upstream_cache_status'           => ['upstream_cache', 'optional'],
        'server_name'                     => ['vhost',          'host'],
        'host'                            => ['vhost',          'host'],
        'http_host'                       => ['vhost',          'host'],
        'server_addr'                     => ['local_addr',     'token'],
        'server_port'                     => ['port',           'port'],
        'remote_port'                     => ['remote_port',    'port'],
        'server_protocol'                 => ['proto',          'text'],
        'request_method'                  => ['method',         'token'],
        'uri'                             => ['uri',            'path'],
        'document_uri'                    => ['uri',            'path'],
        'request_uri'                     => ['uri_full',       'token'],
        'args'                            => ['query_raw',      'query_raw'],
        'query_string'                    => ['query_raw',      'query_raw'],
        'scheme'                          => ['scheme',         'token'],
        'ssl_protocol'                    => ['var.ssl_protocol', 'optional'],
        'ssl_cipher'                      => ['var.ssl_cipher',   'optional'],
        'ssl_session_reused'              => ['var.ssl_reused',   'optional'],
        'connection'                      => ['connection',     'token'],
        'connection_requests'             => ['connection_requests', 'num'],
        'pipe'                            => ['pipe',           'token'],
        'gzip_ratio'                      => ['gzip_ratio',     'optional'],
        'request_id'                      => ['request_id',     'token'],
        'req_id'                          => ['request_id',     'token'],
        'proxy_upstream_name'             => ['upstream_name',  'optional'],
        'proxy_alternative_upstream_name' => ['upstream_alt_name', 'optional'],
        'service_name'                    => ['upstream_name',  'optional'],
        'service_port'                    => ['upstream_port',  'optional'],
    ];

    private string $kind;
    private string $name;
    private string $source;

    /** Compiled PCRE (regex kind only). */
    private string $pattern = '';

    /** @var string[] Field name per capture group, in capture order. */
    private array $fields = [];

    /** @var array<string,string> JSON key path (dotted) => canonical field name. */
    private array $jsonMap = [];

    /**
     * Explicit DateTime::createFromFormat() format for the `time` field, when the log format
     * pinned one down (e.g. Apache's `%{%Y-%m-%d %H:%M:%S}t`). Null means "let Parser sniff".
     */
    private ?string $timeFormat = null;

    /** Whether captured values carry Apache/nginx backslash escaping that must be undone. */
    private bool $unescape = true;

    /**
     * Fields whose captured value is percent-encoded and must be urldecode()d.
     *
     * CloudFront's W3C log percent-encodes the User-Agent, Referer and query string, so a
     * raw capture there reads `Mozilla%2F5.0%20(...)`. Applying the decode at parse time
     * means nothing downstream has to know which format the line came from.
     *
     * @var string[]
     */
    private array $urldecode = [];

    /**
     * Private: instances are only ever produced by the named constructors below, so that
     * every LogFormat in the system has a known provenance.
     *
     * @param string[]              $fields
     * @param array<string,string>  $jsonMap
     */
    private function __construct(
        string $kind,
        string $name,
        string $source,
        string $pattern,
        array $fields,
        array $jsonMap = [],
        ?string $timeFormat = null,
        bool $unescape = true,
        array $urldecode = []
    ) {
        $this->kind       = $kind;
        $this->name       = $name;
        $this->source     = $source;
        $this->pattern    = $pattern;
        $this->fields     = $fields;
        $this->jsonMap    = $jsonMap;
        $this->timeFormat = $timeFormat;
        $this->unescape   = $unescape;
        $this->urldecode  = $urldecode;
    }

    // -----------------------------------------------------------------------------
    // Named constructors
    // -----------------------------------------------------------------------------

    /**
     * Compile an Apache `LogFormat` string.
     *
     * Accepts the string either as it appears in the config (wrapped in double quotes with
     * `\"` around each quoted field) or already unwrapped, because callers get it from both
     * places: LogDetect reads it out of httpd.conf, the setup UI may get it pasted by hand.
     *
     * @param string $fmt  e.g. `"%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""`
     * @param string $name Cosmetic label used in the setup UI ("combined", "loghound", ...).
     */
    public static function fromApache(string $fmt, string $name = 'apache'): self
    {
        $raw    = $fmt;
        $fmt    = self::stripOuterQuotes($fmt);
        $tokens = self::tokenizeApache($fmt);

        $regex      = '';
        $fields     = [];
        $timeFormat = null;

        foreach ($tokens as $k => $tok) {
            if ($tok[0] === 'lit') {
                // Literal text between directives is matched verbatim; '~' is our delimiter.
                $regex .= preg_quote($tok[1], '~');
                continue;
            }

            $spec = self::resolveApacheDirective($tok[1], $tok[2]);
            if ($spec === null) {
                // Unknown directive: consume a bare token so the rest of the line still
                // lines up, but do not capture it — an unnamed field is worse than none.
                $regex .= '(?:\S*)';
                continue;
            }
            [$field, $type, $custom, $tf] = $spec;

            if ($tf !== null && $timeFormat === null) {
                $timeFormat = $tf;
            }

            $quoted  = self::isQuotedContext($tokens, $k);
            $subject = $custom ?? self::patternFor($type, $quoted);

            $regex   .= '(' . $subject . ')';
            $fields[] = self::uniqueField($fields, $field);
        }

        // Anchored at both ends. This is what makes format *discrimination* work: without
        // the trailing anchor, `common` would happily match a `combined` line and the
        // detector would pick the wrong (lossier) format.
        $pattern = '~^' . $regex . '\s*$~';

        return new self(self::KIND_REGEX, $name, $raw, $pattern, $fields, [], $timeFormat, true);
    }

    /**
     * Compile an nginx `log_format` body.
     *
     * The caller passes the concatenation of the quoted parts, exactly as nginx itself
     * concatenates them — LogDetect does that joining while reading nginx.conf.
     *
     * An nginx format whose body is a JSON template (the `escape=json` idiom) is detected
     * here and routed to fromJson(), because parsing JSON with a regex is how you end up
     * with a parser that breaks the first time a key order changes.
     *
     * @param string $fmt e.g. `$remote_addr - $remote_user [$time_local] "$request" $status ...`
     */
    public static function fromNginx(string $fmt, string $name = 'nginx'): self
    {
        $raw = $fmt;
        $fmt = self::stripOuterQuotes($fmt);

        // JSON template? Then it is a JSON log, not a delimited one.
        if (preg_match('/^\s*\{/', $fmt) && preg_match('/\}\s*$/', $fmt)) {
            $map = self::nginxJsonTemplateMap($fmt);
            if ($map !== []) {
                return self::fromJson($name, $map, ['source' => $raw]);
            }
        }

        $tokens = self::tokenizeNginx($fmt);

        $regex  = '';
        $fields = [];

        foreach ($tokens as $k => $tok) {
            if ($tok[0] === 'lit') {
                $regex .= preg_quote($tok[1], '~');
                continue;
            }
            [$field, $type] = self::resolveNginxVar($tok[1]);
            $quoted  = self::isQuotedContext($tokens, $k);
            $regex  .= '(' . self::patternFor($type, $quoted) . ')';
            $fields[] = self::uniqueField($fields, $field);
        }

        $pattern = '~^' . $regex . '\s*$~';

        return new self(self::KIND_REGEX, $name, $raw, $pattern, $fields, [], null, true);
    }

    /**
     * Build a parser for a JSON-per-line log (Caddy, Traefik, nginx escape=json, ...).
     *
     * JSON logs are first-class here, not shoehorned through a regex: a key map is far more
     * robust than a pattern because key ORDER and key PRESENCE both vary between versions,
     * and neither matters to a map.
     *
     * @param array<string,string> $map  dotted JSON key path => canonical field name.
     *                                   Array values (Caddy's header lists) take element 0.
     * @param array<string,mixed>  $opts 'time_format' => DateTime format for the time field,
     *                                   'source' => original format text for display.
     */
    public static function fromJson(string $name, array $map, array $opts = []): self
    {
        return new self(
            self::KIND_JSON,
            $name,
            (string) ($opts['source'] ?? json_encode($map)),
            '',
            [],
            $map,
            isset($opts['time_format']) ? (string) $opts['time_format'] : null,
            false // JSON values are already decoded by json_decode(); no extra unescaping.
        );
    }

    /**
     * Build a parser from an explicit PCRE with named groups.
     *
     * This is the escape hatch of SPEC §8 step 4 and the mechanism behind the built-in
     * non-Apache/non-nginx formats (HAProxy, ALB, CloudFront), whose grammars are fixed and
     * not expressible as a LogFormat string.
     *
     * @param string   $pattern Delimited PCRE. If it contains named groups the names ARE the
     *                          field names; otherwise $fields supplies them positionally.
     * @param string[] $fields  Field name per capture group when the pattern is unnamed.
     * @param array<string,mixed> $opts 'time_format', 'unescape' (default false),
     *                                  'urldecode' => string[] of fields to percent-decode.
     */
    public static function fromRegex(
        string $pattern,
        array $fields = [],
        string $name = 'custom',
        array $opts = []
    ): self {
        if ($fields === []) {
            // Derive the ordered field list from the named groups in declaration order.
            if (preg_match_all('/\(\?P?<([A-Za-z_][A-Za-z0-9_.]*)>/', $pattern, $m)) {
                $fields = $m[1];
            }
        }
        return new self(
            self::KIND_REGEX,
            $name,
            $pattern,
            $pattern,
            $fields,
            [],
            isset($opts['time_format']) ? (string) $opts['time_format'] : null,
            (bool) ($opts['unescape'] ?? false),
            (array) ($opts['urldecode'] ?? [])
        );
    }

    // -----------------------------------------------------------------------------
    // Parsing
    // -----------------------------------------------------------------------------

    /**
     * Parse one raw log line into the canonical raw-field array.
     *
     * Contract: returns null for anything that does not match COMPLETELY. Never a partial
     * record, never an exception, never a warning — the caller (the tail daemon) counts the
     * null and samples the line to var/badlines.log so nothing is silently lost.
     *
     * @return array<string,string>|null
     */
    public function parse(string $line): ?array
    {
        // Trailing newline is an artifact of reading, not part of the record.
        $line = rtrim($line, "\r\n");
        if ($line === '') {
            return null;
        }

        if ($this->kind === self::KIND_JSON) {
            return $this->parseJson($line);
        }

        $m = [];
        // @-suppressed: a pathological line can trip the backtrack limit, which emits a
        // warning and returns false. That is a normal, expected outcome here, not an error.
        $ok = @preg_match($this->pattern, $line, $m);
        if ($ok !== 1) {
            return null;
        }

        $out = [];
        foreach ($this->fields as $i => $field) {
            // Named groups (fromRegex) are addressable by name; generated patterns by index.
            $value = $m[$field] ?? ($m[$i + 1] ?? '');
            if (!is_string($value)) {
                continue;
            }
            if ($this->unescape && $value !== '') {
                $value = self::unescape($value);
            }
            // Percent-decoded only for the formats that declare it (CloudFront), so a real
            // path containing a literal '%20' in an ordinary Apache log stays untouched.
            if ($value !== '' && in_array($field, $this->urldecode, true)) {
                $value = rawurldecode($value);
            }
            $out[$field] = $value;
        }
        return $out;
    }

    /**
     * Parse a JSON log line by walking the key map.
     *
     * A line that is not a JSON object at all yields null (counted as a parse error), which
     * is also how a JSON format loses the detection contest against a regex format.
     *
     * @return array<string,string>|null
     */
    private function parseJson(string $line): ?array
    {
        $doc = json_decode($line, true);
        if (!is_array($doc) || array_is_list($doc)) {
            return null;
        }

        $out = [];
        foreach ($this->jsonMap as $path => $field) {
            $value = self::digJson($doc, $path);
            if ($value === null) {
                continue; // Absent stays absent — never zero-filled. SPEC §1 Correctness.
            }
            $out[$field] = $value;
        }
        // A JSON object with none of the expected keys is not this format.
        return $out === [] ? null : $out;
    }

    /**
     * Follow a dotted path into a decoded JSON document and flatten the leaf to a string.
     *
     * Header values in Caddy are arrays (`{"User-Agent":["Mozilla/5.0 ..."]}`) because HTTP
     * allows repeats; we take the first element, which is what every consumer means.
     *
     * @param array<mixed> $doc
     */
    private static function digJson(array $doc, string $path): ?string
    {
        $node = $doc;
        foreach (explode('.', $path) as $segment) {
            if (!is_array($node) || !array_key_exists($segment, $node)) {
                return null;
            }
            $node = $node[$segment];
        }
        if (is_array($node)) {
            $node = $node[0] ?? ($node[array_key_first($node)] ?? null);
        }
        if (is_bool($node)) {
            return $node ? '1' : '0';
        }
        if ($node === null || is_array($node) || is_object($node)) {
            return null;
        }
        return (string) $node;
    }

    // -----------------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------------

    /** Ordered list of canonical field names, one per capture group. */
    public function fieldMap(): array
    {
        return $this->kind === self::KIND_JSON ? array_values($this->jsonMap) : $this->fields;
    }

    /** The compiled PCRE; empty string for JSON formats. */
    public function pattern(): string
    {
        return $this->pattern;
    }

    /** Cosmetic name shown in the setup UI. */
    public function name(): string
    {
        return $this->name;
    }

    /** KIND_REGEX or KIND_JSON. */
    public function kind(): string
    {
        return $this->kind;
    }

    /** The original format string, for display and for round-tripping into the config. */
    public function source(): string
    {
        return $this->source;
    }

    /** Explicit DateTime format for the `time` field, or null to let Parser sniff it. */
    public function timeFormat(): ?string
    {
        return $this->timeFormat;
    }

    /** True when the format captures the named canonical field. */
    public function hasField(string $field): bool
    {
        return in_array($field, $this->fieldMap(), true);
    }

    // -----------------------------------------------------------------------------
    // Apache internals
    // -----------------------------------------------------------------------------

    /**
     * Split an Apache format string into literal runs and directive tokens.
     *
     * Apache's directive grammar is: `%` [`!`][status,list] [`<`|`>`] [`{arg}`] letter.
     * The status-code condition (`%400,501{Referer}i`) only changes whether Apache writes
     * the value or a `-`; either way it occupies one field, so we parse past it and ignore it.
     *
     * @return array<int,array{0:string,1:string,2?:?string}> ['lit', text] | ['dir', letter, arg]
     */
    private static function tokenizeApache(string $fmt): array
    {
        $tokens = [];
        $lit    = '';
        $len    = strlen($fmt);

        for ($i = 0; $i < $len; $i++) {
            $c = $fmt[$i];
            if ($c !== '%') {
                $lit .= $c;
                continue;
            }
            // `%%` is a literal percent sign.
            if ($i + 1 < $len && $fmt[$i + 1] === '%') {
                $lit .= '%';
                $i++;
                continue;
            }

            $j = $i + 1;
            if ($j < $len && $fmt[$j] === '!') {
                $j++;                                   // negated status condition
            }
            while ($j < $len && (ctype_digit($fmt[$j]) || $fmt[$j] === ',')) {
                $j++;                                   // status-code condition list
            }
            if ($j < $len && ($fmt[$j] === '<' || $fmt[$j] === '>')) {
                $j++;                                   // original/final request modifier
            }

            $arg = null;
            if ($j < $len && $fmt[$j] === '{') {
                $close = strpos($fmt, '}', $j);
                if ($close === false) {
                    $lit .= $c;                         // malformed: treat '%' as literal
                    continue;
                }
                $arg = substr($fmt, $j + 1, $close - $j - 1);
                $j   = $close + 1;
            }

            if ($j >= $len) {
                $lit .= substr($fmt, $i);               // trailing garbage: keep it literal
                break;
            }

            if ($lit !== '') {
                $tokens[] = ['lit', $lit];
                $lit = '';
            }
            $tokens[] = ['dir', $fmt[$j], $arg];
            $i = $j;
        }

        if ($lit !== '') {
            $tokens[] = ['lit', $lit];
        }
        return $tokens;
    }

    /**
     * Map one Apache directive to [field, type, customPattern|null, timeFormat|null].
     *
     * Returns null for directives we do not model, which the caller turns into a
     * non-capturing token so the rest of the line still aligns.
     *
     * @return array{0:string,1:string,2:?string,3:?string}|null
     */
    private static function resolveApacheDirective(string $letter, ?string $arg): ?array
    {
        // `%{...}` variants first — the brace argument changes the meaning of the letter.
        if ($arg !== null) {
            $lower = strtolower($arg);
            switch ($letter) {
                case 'i':
                    return ['header_in.' . $lower, 'text', null, null];
                case 'o':
                    return ['header_out.' . $lower, 'text', null, null];
                case 'e':
                    return ['env.' . $lower, 'text', null, null];
                case 'n':
                    return ['note.' . $lower, 'text', null, null];
                case 'x':
                    // mod_ssl / mod_log_config extensions: %{SSL_PROTOCOL}x, %{SSL_CIPHER}x
                    return ['var.' . $lower, 'text', null, null];
                case 'C':
                    return ['cookie.' . $lower, 'text', null, null];
                case 'p':
                    return ['port', 'port', null, null];
                case 'T':
                    // %{ms}T / %{us}T / %{s}T select the unit of the request duration.
                    if ($lower === 'ms') {
                        return ['dur_ms', 'float', null, null];
                    }
                    if ($lower === 'us') {
                        return ['dur_us', 'num', null, null];
                    }
                    return ['dur_s', 'float', null, null];
                case 't':
                    return self::apacheTimeDirective($arg);
            }
            // Unknown brace directive: skip it without capturing.
            return null;
        }

        if (!isset(self::APACHE_DIRECTIVES[$letter])) {
            return null;
        }
        [$field, $type] = self::APACHE_DIRECTIVES[$letter];
        return [$field, $type, null, null];
    }

    /**
     * Resolve `%{...}t`, Apache's custom-timestamp directive.
     *
     * Three families exist and they need different patterns:
     *  - numeric families (`sec`, `msec`, `usec`, `msec_frac`, `usec_frac`) → plain digits;
     *  - `begin:`/`end:` prefixes, which only select WHICH instant is printed → strip them;
     *  - anything else is a strftime template, which we translate into both a matching regex
     *    and a DateTime::createFromFormat() format so Parser does not have to guess.
     *
     * @return array{0:string,1:string,2:?string,3:?string}
     */
    private static function apacheTimeDirective(string $arg): array
    {
        // begin:/end: only pick the instant, not the rendering.
        if (preg_match('/^(begin|end):(.*)$/s', $arg, $m)) {
            $arg = $m[2];
        }
        $lower = strtolower($arg);

        if ($lower === '' ) {
            return ['time', 'time_bracket', null, null];
        }
        if (in_array($lower, ['sec', 'msec', 'usec', 'msec_frac', 'usec_frac'], true)) {
            // Epoch variants. Parser sniffs the magnitude, so no format hint is needed.
            return ['time', 'num', '\d+', null];
        }

        [$regex, $dateFormat] = self::strftimeToRegex($arg);
        return ['time', 'custom', $regex, $dateFormat];
    }

    /**
     * Translate a strftime template into [regex, DateTime format].
     *
     * Only the specifiers that actually appear in webserver log configs are supported; an
     * unrecognised one becomes a permissive `\S+` in the regex and is dropped from the date
     * format, which degrades to "Parser sniffs it" rather than to a crash.
     *
     * @return array{0:string,1:?string}
     */
    private static function strftimeToRegex(string $fmt): array
    {
        // specifier => [regex fragment, DateTime::createFromFormat fragment]
        static $map = [
            'Y' => ['\d{4}',            'Y'],
            'y' => ['\d{2}',            'y'],
            'm' => ['\d{2}',            'm'],
            'd' => ['\d{2}',            'd'],
            'e' => ['[ \d]\d',          'j'],
            'H' => ['\d{2}',            'H'],
            'I' => ['\d{2}',            'h'],
            'M' => ['\d{2}',            'i'],
            'S' => ['\d{2}',            's'],
            'p' => ['[APap][Mm]',       'A'],
            'z' => ['[+-]\d{4}',        'O'],
            'Z' => ['[A-Za-z_\/+-]+',   'T'],
            'b' => ['[A-Za-z]{3}',      'M'],
            'h' => ['[A-Za-z]{3}',      'M'],
            'B' => ['[A-Za-z]+',        'F'],
            'a' => ['[A-Za-z]{3}',      'D'],
            'A' => ['[A-Za-z]+',        'l'],
            'j' => ['\d{3}',            null],
            's' => ['\d+',              'U'],
            'F' => ['\d{4}-\d{2}-\d{2}', 'Y-m-d'],
            'T' => ['\d{2}:\d{2}:\d{2}', 'H:i:s'],
            'D' => ['\d{2}\/\d{2}\/\d{2}', 'm/d/y'],
            'n' => ['\n',               null],
            't' => ['\t',               null],
        ];

        $regex  = '';
        $date   = '';
        $usable = true;
        $len    = strlen($fmt);

        for ($i = 0; $i < $len; $i++) {
            if ($fmt[$i] !== '%' || $i + 1 >= $len) {
                $regex .= preg_quote($fmt[$i], '~');
                // Only letters mean something to DateTime::createFromFormat, so only letters
                // need the backslash. Escaping '-' and ':' too would work but would make the
                // stored format unreadable in the setup UI.
                $date  .= ctype_alpha($fmt[$i]) ? '\\' . $fmt[$i] : $fmt[$i];
                continue;
            }
            $spec = $fmt[++$i];
            if ($spec === '%') {
                $regex .= '%';
                $date  .= '\\%';
                continue;
            }
            if (!isset($map[$spec])) {
                $regex .= '\S+';
                $usable = false;      // cannot reconstruct a parse format any more
                continue;
            }
            $regex .= $map[$spec][0];
            if ($map[$spec][1] === null) {
                $usable = false;
            } else {
                $date .= $map[$spec][1];
            }
        }

        return [$regex, $usable ? $date : null];
    }

    // -----------------------------------------------------------------------------
    // nginx internals
    // -----------------------------------------------------------------------------

    /**
     * Split an nginx log_format body into literal runs and `$variable` tokens.
     *
     * Supports both `$name` and `${name}`. nginx variable names are `[A-Za-z0-9_]`, so the
     * greedy scan is unambiguous.
     *
     * @return array<int,array{0:string,1:string}> ['lit', text] | ['var', name]
     */
    private static function tokenizeNginx(string $fmt): array
    {
        $tokens = [];
        $lit    = '';
        $len    = strlen($fmt);

        for ($i = 0; $i < $len; $i++) {
            $c = $fmt[$i];
            if ($c !== '$') {
                $lit .= $c;
                continue;
            }
            $j    = $i + 1;
            $name = '';

            if ($j < $len && $fmt[$j] === '{') {
                $close = strpos($fmt, '}', $j);
                if ($close === false) {
                    $lit .= $c;
                    continue;
                }
                $name = substr($fmt, $j + 1, $close - $j - 1);
                $i    = $close;
            } else {
                while ($j < $len && (ctype_alnum($fmt[$j]) || $fmt[$j] === '_')) {
                    $name .= $fmt[$j];
                    $j++;
                }
                if ($name === '') {
                    $lit .= $c;    // a bare '$' is a literal dollar sign
                    continue;
                }
                $i = $j - 1;
            }

            if ($lit !== '') {
                $tokens[] = ['lit', $lit];
                $lit = '';
            }
            $tokens[] = ['var', $name];
        }

        if ($lit !== '') {
            $tokens[] = ['lit', $lit];
        }
        return $tokens;
    }

    /**
     * Map one nginx variable name to [field, type].
     *
     * The `$http_*` family is handled generically because the suffix IS the header name with
     * dashes turned into underscores — that is nginx's own rule, so we simply invert it.
     *
     * @return array{0:string,1:string}
     */
    private static function resolveNginxVar(string $var): array
    {
        $var = strtolower($var);

        if (isset(self::NGINX_VARS[$var])) {
            return self::NGINX_VARS[$var];
        }
        if (str_starts_with($var, 'http_')) {
            return ['header_in.' . str_replace('_', '-', substr($var, 5)), 'text'];
        }
        if (str_starts_with($var, 'sent_http_')) {
            return ['header_out.' . str_replace('_', '-', substr($var, 10)), 'text'];
        }
        if (str_starts_with($var, 'upstream_http_')) {
            return ['upstream_header.' . str_replace('_', '-', substr($var, 14)), 'text'];
        }
        if (str_starts_with($var, 'cookie_')) {
            return ['cookie.' . substr($var, 7), 'text'];
        }
        if (str_starts_with($var, 'arg_')) {
            return ['arg.' . substr($var, 4), 'text'];
        }
        // Unknown variable: keep it, namespaced, rather than dropping the column.
        return ['var.' . $var, 'optional'];
    }

    /**
     * Extract a key map from an nginx JSON log template.
     *
     * The `escape=json` idiom looks like:
     *   log_format json escape=json '{"time":"$time_iso8601","ip":"$remote_addr", ...}';
     * so every `"key":"$var"` (or unquoted `"key":$var`) pair gives us one mapping. Keys we
     * cannot resolve to a canonical field are dropped rather than guessed at.
     *
     * @return array<string,string> JSON key => canonical field
     */
    private static function nginxJsonTemplateMap(string $fmt): array
    {
        $map = [];
        if (!preg_match_all('/"([^"]+)"\s*:\s*"?\$\{?([A-Za-z0-9_]+)\}?"?/', $fmt, $m, PREG_SET_ORDER)) {
            return $map;
        }
        foreach ($m as $pair) {
            [$field] = self::resolveNginxVar($pair[2]);
            $map[$pair[1]] = $field;
        }
        return $map;
    }

    // -----------------------------------------------------------------------------
    // Shared helpers
    // -----------------------------------------------------------------------------

    /**
     * Pattern for a field of the given type.
     *
     * Inside a quoted field every type collapses to the same thing, because the quoting IS
     * the delimiter: the value runs to the next unescaped quote. Both Apache and nginx
     * escape an embedded quote (`\"` and `\x22` respectively), so a backslash pair is the
     * only way one can occur and `(?:[^"\\]|\\.)*` consumes it correctly.
     *
     * Every alternative below is linear and non-nested: none of these can backtrack
     * catastrophically no matter what a hostile line contains.
     */
    private static function patternFor(string $type, bool $quoted): string
    {
        if ($quoted) {
            return '(?:[^"\\\\]|\\\\.)*';
        }

        switch ($type) {
            case 'time_bracket':
                // Apache's %t emits its own square brackets, e.g. [10/Sep/2026:09:57:08 +0000]
                return '\[[^\]]*\]';
            case 'time_local':
                // nginx $time_local contains a space, so it needs a structural pattern, not \S+.
                return '\d{1,2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4}';
            case 'time_iso':
                return '\S+';
            case 'status':
                return '(?:\d{3}|-)';
            case 'num':
                return '(?:-|\d+)';
            case 'float':
                return '(?:-|\d+(?:\.\d+)?)';
            case 'floatlist':
                // nginx joins per-upstream values with ", " (and ":" across upstream groups).
                return '(?:-|\d+(?:\.\d+)?(?:\s*[,:]\s*(?:-|\d+(?:\.\d+)?))*)';
            case 'port':
                return '(?:\d+|-)';
            case 'host':
                // Excludes ':' so `%v:%p` splits deterministically instead of by backtracking.
                return '[^\s:]+';
            case 'path':
                return '[^\s?]*';
            case 'query':
                // Apache's %q is '' or '?...'.
                return '(?:\?\S*)?';
            case 'query_raw':
                // nginx's $args has no leading '?' and is empty when there is no query.
                return '\S*';
            case 'optional':
                return '\S*';
            case 'text':
            case 'token':
            default:
                return '\S+';
        }
    }

    /**
     * Is this directive wrapped in literal double quotes in the format string?
     *
     * Determined structurally — the preceding literal must end with a quote and the
     * following literal must start with one — rather than by tracking a "we are inside
     * quotes" flag, which gets it wrong the moment a format contains an odd number of them.
     *
     * @param array<int,array> $tokens
     */
    private static function isQuotedContext(array $tokens, int $index): bool
    {
        $prev = $tokens[$index - 1] ?? null;
        $next = $tokens[$index + 1] ?? null;

        $openedBefore = $prev !== null && $prev[0] === 'lit' && str_ends_with($prev[1], '"');
        $closedAfter  = $next !== null && $next[0] === 'lit' && str_starts_with($next[1], '"');

        return $openedBefore && $closedAfter;
    }

    /**
     * Guarantee a unique field name when a format logs the same thing twice.
     *
     * Rare but real (`%h ... %{X-Forwarded-For}i ... %h`). The first occurrence keeps the
     * plain name — which is the one Parser consumes — and later ones get a numeric suffix so
     * no data is silently overwritten.
     *
     * @param string[] $existing
     */
    private static function uniqueField(array $existing, string $field): string
    {
        if (!in_array($field, $existing, true)) {
            return $field;
        }
        $n = 2;
        while (in_array($field . '__' . $n, $existing, true)) {
            $n++;
        }
        return $field . '__' . $n;
    }

    /**
     * Strip the config-level double quotes and undo the config-level backslash escaping.
     *
     * `LogFormat "%h ... \"%r\" ..."` arrives with the outer quotes and `\"` inside; both
     * are httpd.conf syntax rather than part of the format, so they come off exactly once.
     */
    private static function stripOuterQuotes(string $fmt): string
    {
        $fmt = trim($fmt);
        if (strlen($fmt) >= 2 && $fmt[0] === '"' && str_ends_with($fmt, '"')) {
            $fmt = substr($fmt, 1, -1);
            $fmt = str_replace(
                ['\\"', '\\t', '\\n', '\\r', '\\\\'],
                ['"',   "\t",  "\n",  "\r",  '\\'],
                $fmt
            );
        } elseif (strlen($fmt) >= 2 && $fmt[0] === "'" && str_ends_with($fmt, "'")) {
            $fmt = substr($fmt, 1, -1);
        }
        return $fmt;
    }

    /**
     * Undo the escaping a webserver applies to logged values.
     *
     * Apache writes `\"` for a quote, `\\` for a backslash and `\xNN` for any control
     * character; nginx writes `\xNN` for control characters, `"` and `\`. Both are covered
     * by the same table, so one implementation serves both.
     *
     * This must happen AFTER the regex match (the pattern relies on the escapes being
     * intact to find the field boundary) and BEFORE anything looks at the value.
     */
    public static function unescape(string $s): string
    {
        // Fast path: the overwhelming majority of values contain no backslash at all.
        if (!str_contains($s, '\\')) {
            return $s;
        }
        $out = preg_replace_callback(
            '/\\\\(x[0-9A-Fa-f]{2}|[\\\\"nrtvbf\'])/',
            static function (array $m): string {
                $e = $m[1];
                if ($e[0] === 'x') {
                    return chr((int) hexdec(substr($e, 1)));
                }
                switch ($e) {
                    case 'n':  return "\n";
                    case 'r':  return "\r";
                    case 't':  return "\t";
                    case 'v':  return "\v";
                    case 'b':  return "\x08";
                    case 'f':  return "\f";
                    case '"':  return '"';
                    case '\'': return '\'';
                    default:   return '\\';
                }
            },
            $s
        );
        // preg_replace_callback returns null only on a PCRE failure; keep the original then.
        return $out ?? $s;
    }
}
