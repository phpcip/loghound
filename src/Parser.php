<?php
/**
 * Loghound — Hit normalizer.
 *
 * Takes the raw field array produced by a compiled `LogFormat` and turns it into the
 * normalized hit document defined in SPEC §4.1, using EXACTLY those field names.
 *
 * Two rules govern everything in here, and both come straight from SPEC §1:
 *
 *  1. **Absent means absent.** If the operator's LogFormat does not log `Accept-Language`,
 *     the document has no `accept_lang_s` key at all — not an empty string, not a zero, not
 *     a "-" placeholder. Zero-filling an unknown is fabricating a metric, and every later
 *     aggregate (facet counts, "how many hits had no Accept header") would be a lie.
 *  2. **A hostile line must never crash the daemon and never produce a partial document.**
 *     Every value is length-capped, control-character-stripped and forced to valid UTF-8
 *     before it reaches the document, because a log line contains whatever bytes a stranger
 *     chose to send. If the two irreducible facts (a timestamp and a request target) cannot
 *     be recovered, `normalize()` returns null and the caller counts it as a parse error.
 *
 * What this class does NOT do: any network I/O. Geo, ASN and rDNS enrichment happen in
 * `Enrich\*` and are merged by the tail daemon, so a slow whois server can never stall
 * parsing. UA parsing IS done here because it is pure string work with no I/O.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound;

use DateTimeImmutable;
use DateTimeZone;
use Loghound\Enrich\Ua;

final class Parser
{
    /** Longest path/referer/UA we will store. Beyond this it is an attack, not a request. */
    private const MAX_TEXT = 2048;

    /**
     * File extension => `asset_kind_s`. Anything here also forces `kind_s` = asset.
     *
     * This table is now load-bearing twice over. It has always decided what counts as a
     * sub-resource for `asset_ratio_f` and the `no_assets` rule; since `ingest.index_assets`
     * it also decides what is never written to the index at all (bin/loghound-tail,
     * Pipeline::indexes). Adding an extension here therefore removes those requests from
     * every hits-plane facet as well as adding them to the ratio — both are correct for a
     * sub-resource, but it is the reason an entry has to genuinely be one.
     *
     * `map` is a source map: emitted beside a bundle, fetched by devtools, and never a page.
     * It used to fall through to `other`, which meant it counted against the asset ratio it
     * should have counted toward and appeared in Top pages.
     */
    private const ASSET_KINDS = [
        'js' => 'js', 'mjs' => 'js', 'cjs' => 'js',
        'map' => 'map',
        'css' => 'css',
        'png' => 'img', 'jpg' => 'img', 'jpeg' => 'img', 'gif' => 'img', 'webp' => 'img',
        'svg' => 'img', 'avif' => 'img', 'bmp' => 'img', 'tiff' => 'img', 'tif' => 'img',
        'woff' => 'font', 'woff2' => 'font', 'ttf' => 'font', 'otf' => 'font', 'eot' => 'font',
        'mp4' => 'media', 'webm' => 'media', 'ogv' => 'media', 'ogg' => 'media', 'mp3' => 'media',
        'wav' => 'media', 'm4a' => 'media', 'm4v' => 'media', 'mov' => 'media', 'avi' => 'media',
        'mkv' => 'media', 'flac' => 'media', 'aac' => 'media', 'ts' => 'media', 'm3u8' => 'media',
    ];

    /** Extensions that mean "a page a human looked at" rather than a sub-resource. */
    private const HTML_EXTS = [
        'html', 'htm', 'xhtml', 'php', 'phtml', 'php5', 'php7', 'asp', 'aspx', 'jsp',
        'cgi', 'pl', 'do', 'action', 'shtml',
    ];

    /**
     * Search-engine referer hosts (suffix match).
     *
     * Kept short and mainstream on purpose: a giant list of dead engines adds maintenance
     * cost and changes nothing about the numbers.
     */
    private const SEARCH_HOSTS = [
        'google.', 'bing.com', 'duckduckgo.com', 'search.yahoo.', 'yahoo.co', 'yandex.',
        'baidu.com', 'ecosia.org', 'search.brave.com', 'startpage.com', 'qwant.com',
        'naver.com', 'seznam.cz', 'ask.com', 'aol.com', 'mojeek.com', 'lycos.com',
        'search.marcia.com', 'searx.', 'presearch.com', 'onesearch.com', 'petalsearch.com',
    ];

    /** Referers that mean an LLM assistant sent the visitor (a category of its own now). */
    private const AI_REFERER_HOSTS = [
        'chatgpt.com', 'chat.openai.com', 'openai.com', 'perplexity.ai', 'claude.ai',
        'anthropic.com', 'gemini.google.com', 'bard.google.com', 'copilot.microsoft.com',
        'you.com', 'poe.com', 'phind.com', 'kagi.com', 'deepseek.com', 'mistral.ai',
    ];

    /** Social network referer hosts (suffix match). */
    private const SOCIAL_HOSTS = [
        'facebook.com', 'fb.com', 'l.facebook.com', 'instagram.com', 'twitter.com', 'x.com',
        't.co', 'linkedin.com', 'lnkd.in', 'reddit.com', 'out.reddit.com', 'pinterest.',
        'tiktok.com', 'youtube.com', 'youtu.be', 'whatsapp.com', 'telegram.org', 't.me',
        'mastodon.social', 'bsky.app', 'threads.net', 'vk.com', 'weibo.com', 'discord.com',
    ];

    /** Ad-network referer hosts, and the click-id query parameters that mean "paid click". */
    private const AD_HOSTS = [
        'doubleclick.net', 'googleadservices.com', 'googlesyndication.com', 'adservice.google.',
        'ads.microsoft.com', 'bing.ads', 'taboola.com', 'outbrain.com',
    ];
    private const AD_CLICK_PARAMS = [
        'gclid', 'gbraid', 'wbraid', 'dclid', 'msclkid', 'fbclid', 'ttclid', 'twclid',
        'li_fat_id', 'rdt_cid', 'epik',
    ];

    /** @var array<string,mixed> Normalizer options — see the constructor. */
    private array $opts;

    /** Count of lines that could not be normalized into a complete document. */
    private int $errors = 0;

    /** Human-readable reason the last failure happened, for var/badlines.log. */
    private ?string $lastError = null;

    /**
     * @param array<string,mixed> $opts
     *   'ip_mode'        string  full|truncate|hash            (privacy.ip_mode)
     *   'ip_salt'        string  keyed salt for hash mode      (privacy.ip_salt)
     *   'keep_raw'       bool    store the original line       (ingest.keep_raw)
     *   'host'           string  vhost override for this source, when the format has no %v
     *   'src'            string  default source label
     *   'internal_hosts' string[] extra hostnames counted as `internal` referers
     *   'beacon_paths'   string[] request paths that ARE the beacon collector
     *   'own_host'       string  the hostname THIS installation is served from (Config::selfEndpoints)
     *   'own_paths'      string[] the paths under that host that are Loghound's own (ditto)
     */
    public function __construct(array $opts = [])
    {
        $this->opts = $opts + [
            'ip_mode'        => 'full',
            'ip_salt'        => '',
            'keep_raw'       => true,
            'host'           => '',
            'src'            => '',
            'internal_hosts' => [],
            'beacon_paths'   => ['/collect.php', '/lh/collect', '/loghound/collect.php'],
            'own_host'       => '',
            'own_paths'      => [],
            'search_params'  => [],
            'install_id'     => '',
        ];

        $this->opts['search_params'] = Beacon::normaliseParamNames((array) $this->opts['search_params']);

        $installId = (string) $this->opts['install_id'];
        $this->opts['install_id'] = preg_match('/^[a-f0-9]{4,32}$/D', $installId) === 1 ? $installId : '';

        $this->opts['own_host'] = strtolower(trim((string) $this->opts['own_host']));
    }

    /**
     * Point the parser at the source it is about to read a line from.
     *
     * `host` is the vhost override for a log format that carries no %v, and it is a property
     * of the SOURCE, not of the installation — one daemon tails many files. bin/loghound-tail
     * used to apply it AFTER parsing, which was too late for anything that has to compare the
     * request's host against something: by then the classification was already done. Setting it
     * here, before the line is handed over, means host_s is resolved while the parser can still
     * act on it, which is what lets isOwnRequest() match on host AND path rather than on path
     * alone.
     *
     * One parser instance serves every source because the daemon reads one line at a time; the
     * call sits immediately before parseLine() so the two can never drift apart.
     */
    public function setSourceHost(?string $host): void
    {
        $this->opts['host'] = $host === null ? '' : trim($host);
    }

    /**
     * Is this request Loghound's own instrumentation, served by THIS installation?
     *
     * The single implementation of the comparison, called from normalize() for a hit the parser
     * produced and from Sessionizer for one that arrived some other way.
     *
     * BOTH HALVES MUST MATCH, and that is the whole point of the method existing. `/collect.php`
     * and `/b.js` are ordinary filenames; a measured site may serve either of them for its own
     * reasons, and quietly deleting a real page from its owner's analytics would be a worse
     * defect than the double-count this exclusion exists to fix. So the request is ours only
     * when it was made to the hostname this panel is published at, at one of the paths this
     * panel publishes. An empty own-host, the pre-setup state, matches nothing at all.
     *
     * Hostnames are compared case-insensitively with any port stripped, exactly as normalize()
     * stores host_s. Paths are compared case-insensitively too, matching classifyPath(), which
     * is the conservative direction on a case-insensitive filesystem.
     *
     * @param string[] $ownPaths
     */
    public static function isOwnRequest(?string $host, string $path, string $ownHost, array $ownPaths): bool
    {
        $ownHost = strtolower(trim($ownHost));
        if ($ownHost === '' || $ownPaths === []) {
            return false;
        }

        $host = strtolower((string) preg_replace('/:\d+$/', '', trim((string) $host)));
        if ($host === '' || $host !== $ownHost) {
            return false;
        }

        $path = strtolower($path);
        foreach ($ownPaths as $own) {
            if ($path === strtolower((string) $own)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Parse and normalize one raw log line in a single call.
     *
     * This is what the tail daemon uses: it knows the file, the byte offset and the format,
     * and wants a document or a counted failure.
     *
     * The document it returns carries `_logged`, the set of fields this log format is even
     * capable of producing. Without it, "the browser did not send Sec-CH-UA" is
     * indistinguishable from "the operator does not log Sec-CH-UA", and the two heaviest
     * header-consistency rules would either fire on every visitor of a plain `combined`
     * site or never fire at all. Score\Signals reads it and stays silent for any signal the
     * log cannot speak to, which is the only safe default: a false "this human is a bot"
     * costs more than a missed detection.
     *
     * `_logged` is underscore-prefixed so the indexer strips it. It is a property of the
     * SOURCE, not of the hit, and has no place in a Solr document.
     *
     * @return array<string,mixed>|null
     */
    public function parseLine(LogFormat $fmt, string $line, string $src, int $offset): ?array
    {
        $raw = $fmt->parse($line);
        if ($raw === null) {
            $this->errors++;
            $this->lastError = 'line did not match the format for this source';
            return null;
        }
        $doc = $this->normalize($raw, $src, $offset, $line, $fmt->timeFormat());

        if ($doc !== null) {
            $doc['_logged'] = self::loggedFields($fmt);
        }

        return $doc;
    }

    /**
     * The set of normalized field names a given log format can populate.
     *
     * Derived from the format's own field map rather than from configuration,
     * so it stays correct when an operator changes their LogFormat and the
     * parser is recompiled — there is no second place to keep in sync.
     *
     * The map inside is from raw capture name to the document field it ends up as. Only
     * fields a scoring rule actually asks about need to appear in it; anything else is
     * irrelevant to the "could this have been logged?" question. Request headers arrive
     * from LogFormat as `header_in.<lowercased header name>` — Apache's %{Name}i and
     * nginx's $http_name both normalise to that — so they are keyed by the header name
     * itself. TLS details are not request headers and come through Apache's %{VARNAME}x or
     * nginx's $ssl_*, so both spellings and both separator styles are accepted.
     *
     * Results are memoised per format pattern: this runs on every line, and the
     * answer cannot change for a given compiled format. The memo is bounded, because a
     * single install has a handful of formats but a test harness can compile many, and a
     * static that never shrinks would grow with them.
     *
     * @return string[] Sorted, unique normalized field names.
     */
    public static function loggedFields(LogFormat $fmt): array
    {
        static $cache = [];

        $key = $fmt->pattern() . '|' . implode(',', $fmt->fieldMap());
        if (isset($cache[$key])) {
            return $cache[$key];
        }

        static $direct = [
            'vhost'      => 'host_s',
            'status'     => 'status_i',
            'bytes_out'  => 'bytes_l',
            'bytes'      => 'bytes_l',
            'dur_us'     => 'dur_us_l',
            'dur_ms'     => 'dur_us_l',
            'dur_s'      => 'dur_us_l',
            'protocol'   => 'proto_s',
        ];
        static $headers = [
            'referer'            => 'referer_s',
            'user-agent'         => 'ua_s',
            'accept'             => 'accept_s',
            'accept-language'    => 'accept_lang_s',
            'accept-encoding'    => 'accept_enc_s',
            'sec-ch-ua'          => 'sec_ch_ua_s',
            'sec-ch-ua-platform' => 'sec_ch_platform_s',
            'sec-ch-ua-mobile'   => 'sec_ch_mobile_b',
            'sec-fetch-site'     => 'sec_fetch_site_s',
            'sec-fetch-mode'     => 'sec_fetch_mode_s',
            'sec-fetch-dest'     => 'sec_fetch_dest_s',
            'sec-fetch-user'     => 'sec_fetch_user_s',
            'x-forwarded-for'    => 'xff_s',
        ];
        static $env = [
            'ssl_protocol' => 'tls_proto_s',
            'ssl_cipher'   => 'tls_cipher_s',
        ];

        $out = [];
        foreach ($fmt->fieldMap() as $rawName) {
            $name = strtolower((string) $rawName);

            if (isset($direct[$name])) {
                $out[$direct[$name]] = true;
                continue;
            }
            if (str_starts_with($name, 'header_in.')) {
                $header = substr($name, strlen('header_in.'));
                if (isset($headers[$header])) {
                    $out[$headers[$header]] = true;
                }
                continue;
            }
            $flat = str_replace(['ssl.', '-'], ['ssl_', '_'], $name);
            if (isset($env[$flat])) {
                $out[$env[$flat]] = true;
            }
        }

        $fields = array_keys($out);
        sort($fields);

        if (count($cache) > 64) {
            $cache = [];
        }
        $cache[$key] = $fields;

        return $fields;
    }

    /**
     * Turn a raw field array into a normalized hit document.
     *
     * The document is assembled in sections, and each one has decisions behind it.
     *
     * Identity and time. The id is idempotent — derived from the installation, the file and the
     * byte offset — so re-ingesting the same file after a crash overwrites rather than
     * duplicates, which is what lets the tail daemon restart from a stale offset safely. `ts` is
     * written as an ISO-8601 instant in UTC with a trailing Z, which is what Solr's pdate wants.
     *
     * THE INSTALLATION ID IS IN THE HIT ID, AND THAT IS NOT DECORATION. One pair of indexes may
     * be shared by SEVERAL installations on different machines — that is the point of pointing a
     * new install at an existing `loghound_<hex>_hits`/`_sessions` pair. Two machines both
     * tailing `/var/log/apache2/access.log` produce the same `$src` and the same byte offsets,
     * so `sha1($src . ':' . $offset)` gave them IDENTICAL document ids, and a Solr update with a
     * duplicate uniqueKey is a delete-and-add: each machine would have silently overwritten the
     * other's traffic, one request at a time, with no error anywhere. Mixing the installation id
     * in removes the collision while keeping the idempotency that matters, because re-ingest is
     * always the SAME installation reading the same file again.
     *
     * A NUL separator is used for the reason it is used in the beacon token: it cannot occur in
     * an install id or a path, so no pair of values can be made to collide by moving the
     * boundary. An empty install id reproduces the old ids exactly, so an installation that has
     * not got one — only a test harness, in practice — is unaffected.
     *
     * `install_s` carries the same value onto the document, so a destructive operation can be
     * scoped to the documents this installation actually wrote. See bin/loghound-retention.
     *
     * Request line. Path depth counts real segments, so '/a/b/c' is 3 and '/' is 0.
     *
     * Search terms. `query_s` keeps the whole query string, stored and unfaceted, for the
     * reasons written next to it in the schema. `search_terms_ss` is the opposite: the values
     * of the parameters the operator NAMED in `beacon.query_params`, and nothing else out of
     * the URL, as a faceted dimension. A site whose access log this installation reads
     * therefore gets its visitors' searches with no beacon involved at all — which is the
     * whole reason the extraction lives here rather than only on the beacon path. The field
     * is absent when no parameter was named or none was present; see Beacon::searchTerms().
     *
     * Host. When the format has no %v, the vhost is the one the operator told us this file
     * serves. Either way a :port suffix is stripped and the host lowercased, because hosts
     * are case-insensitive and a facet on "Example.com" versus "example.com" would split one
     * site into two.
     *
     * Network. `ip_net_s` is derived from the TRUE address, before the privacy transform,
     * because it is the clustering key that groups a rotating-proxy fleet's exits. Note for
     * privacy reviewers: in 'hash' mode this deliberately still exposes the /24 (v4) or /48
     * (v6). That is the same granularity 'truncate' mode publishes, and losing it would
     * disable the fingerprint/network correlation this product exists to do; it is
     * documented in docs/PRIVACY.md. A client field that is a hostname rather than an
     * address — HostnameLookups On, or a proxy that logs a name — is kept as it is: it is
     * still the client identity, it just is not an address.
     *
     * Ours. `_self_b` marks a request to THIS installation's own beacon script or collector,
     * decided by isOwnRequest() against the pair Config::selfEndpoints() derived from
     * `base_url`. It is underscore-prefixed, so bin/loghound-tail strips it before the document
     * reaches Solr: it is a handoff to Sessionizer, which excludes those requests from every
     * session metric, not a field. The hit itself is still indexed — Sessionizer::accumulateSelf()
     * carries the reasoning for keeping rather than dropping it — and `kind_s` is left exactly as
     * classifyPath() decided it, because a request to a collector is a beacon request whoever
     * the collector belongs to. Classification and ownership are different questions.
     *
     * Response. Apache logs '-' for the status when the connection died before one was
     * chosen; that is genuinely unknown, so the field stays absent rather than becoming 0.
     * Apache's '-' for %b means something different — zero bytes of body — and is recorded
     * as the known zero it is.
     *
     * Headers. Every header-derived field is ABSENT unless the operator logs the header.
     * That includes referer_type_s, which is always derivable in principle ('direct' when
     * there is no referer) but is only emitted when the format actually logs the header,
     * since otherwise "direct" would be a guess. Sec-CH-UA-Platform arrives quoted
     * ("Windows") and the quotes are transport syntax, not data. Structured-header booleans
     * are ?1 for true and ?0 for false, and anything else is garbage. TLS details come from
     * mod_ssl (%{SSL_PROTOCOL}x) or nginx's $ssl_protocol. JA4 is v2, sourced from HAProxy;
     * the field is populated if it ever shows up in a log.
     *
     * User-Agent. Even an empty UA is hashed: "this client sends no User-Agent" is itself a
     * stable identity worth clustering on, and one of the loudest bot signals there is.
     *
     * Fingerprint. `fp_hash_s` is THE cluster key of SPEC §4.1 — a stable-ish visitor
     * identity built from network, UA and language, daily-salted under 'hash'.
     *
     * Raw line. `raw_s` is stored but not indexed, so it needs no analysis-safety treatment,
     * but it still has to be valid UTF-8 or the Solr update request itself fails.
     *
     * @param array<string,string> $raw        Output of LogFormat::parse().
     * @param string               $src        Log file this line came from (`src_s`).
     * @param int                  $offset     Byte offset of the line, for the idempotent id.
     * @param string               $line       The original line, stored as `raw_s` if enabled.
     * @param string|null          $timeFormat Explicit DateTime format from the LogFormat.
     *
     * @return array<string,mixed>|null Null when the line cannot yield a complete document.
     */
    public function normalize(
        array $raw,
        string $src,
        int $offset,
        string $line = '',
        ?string $timeFormat = null
    ): ?array {
        $doc = [];

        $installId = (string) $this->opts['install_id'];

        $doc['id']    = $installId === ''
            ? sha1($src . ':' . $offset)
            : sha1($installId . "\0" . $src . ':' . $offset);
        $doc['src_s'] = self::sanitizeText($src, 512) ?? $src;

        if ($installId !== '') {
            $doc['install_s'] = $installId;
        }

        $ts = $this->extractTimestamp($raw, $timeFormat);
        if ($ts === null) {
            $this->errors++;
            $this->lastError = 'no parseable timestamp';
            return null;
        }
        $doc['ts'] = $ts->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s.v\Z');

        $req = $this->extractRequest($raw);
        if ($req === null) {
            $this->errors++;
            $this->lastError = 'no parseable request target';
            return null;
        }

        self::put($doc, 'method_s', $req['method'] === null ? null : strtoupper($req['method']));
        $doc['path_s'] = $req['path'];
        self::put($doc, 'query_s', $req['query']);
        self::put($doc, 'proto_s', self::normalizeProto($req['proto'] ?? ($raw['proto'] ?? null)));

        $terms = Beacon::searchTerms((string) ($req['query'] ?? ''), (array) $this->opts['search_params']);
        if ($terms !== []) {
            $doc['search_terms_ss'] = $terms;
        }

        $doc['path_depth_i'] = count(array_filter(explode('/', $req['path']), 'strlen'));

        $host = $raw['vhost'] ?? ($req['host'] ?? null);
        if (($host === null || $host === '' || $host === '-') && $this->opts['host'] !== '') {
            $host = (string) $this->opts['host'];
        }
        if (is_string($host) && $host !== '' && $host !== '-') {
            $host = strtolower((string) preg_replace('/:\d+$/', '', $host));
            self::put($doc, 'host_s', self::sanitizeText($host, 255));
        }

        /* THE HOST THE REQUEST LINE ITSELF NAMED, kept only for the length of the pipeline.
           A request line in absolute form — `GET http://elsewhere.example/ HTTP/1.1` — is how a
           client asks a proxy to fetch somebody else's site, and it is indistinguishable from an
           ordinary request once the target has been reduced to a path. Underscore-prefixed, so
           bin/loghound-tail strips it before indexing: it is evidence for Score\Attacks, not a
           field the schema defines. Absent whenever the target was in origin form, which is
           every ordinary request. */
        if (isset($req['host']) && is_string($req['host']) && $req['host'] !== '') {
            $doc['_abs_host'] = strtolower((string) preg_replace('/:\d+$/', '', $req['host']));
        }

        $ip = trim((string) ($raw['remote_addr'] ?? ''));
        if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP) !== false) {
            $isV6 = str_contains($ip, ':');
            $doc['ip_ver_i'] = $isV6 ? 6 : 4;

            $doc['ip_net_s'] = Security::ipNetwork($ip, 24, 48);

            $doc['ip_s'] = Security::applyIpPrivacy(
                $ip,
                (string) $this->opts['ip_mode'],
                (string) $this->opts['ip_salt']
            );
        } elseif ($ip !== '' && $ip !== '-') {
            self::put($doc, 'ip_s', self::sanitizeText($ip, 255));
        }

        /* RANGE-CHECKED, NOT MERELY CAST. `status_i` is a `pint` — 32 bits — and PHP's (int)
           is 64, so a format that does not itself bound the field (a quoted "%>s", any JSON
           format, a generated pattern whose slot is `(?<status>\S+)`) could carry a value above
           2147483647 straight into an update that Solr rejects WHOLE. bin/loghound-tail drops
           the entire batch on a failed flush, so one crafted line loses up to batch_max good
           documents. 100..599 is what a status code is; anything else is not a status. */
        $status = $raw['status'] ?? null;
        if (is_string($status) && ctype_digit($status) && strlen($status) <= 3) {
            $code = (int) $status;
            if ($code >= 100 && $code <= 599) {
                $doc['status_i'] = $code;

                /* THE CLASS, AS A TERM, because the class is the question an operator asks and a
                   range query is not a facet. "Was it answered" is 2xx-or-3xx against everything
                   else, and asking that of `status_i` means either a range filter (which a facet
                   cannot bucket) or a sixty-bucket terms facet the reader has to add up. One
                   string per document, six possible values, and the exact code stays available
                   beside it for the investigator who wants 403 apart from 401.

                   WRITTEN ONLY WHERE `status_i` IS. A log line whose status did not parse gets
                   neither field, so absence means "not recorded" on both and never "1xx". */
                $doc['status_class_s'] = ((int) ($code / 100)) . 'xx';
            }
        }

        $bytes = $raw['bytes'] ?? ($raw['bytes_out'] ?? null);
        if (is_string($bytes)) {
            if (ctype_digit($bytes)) {
                $doc['bytes_l'] = (int) $bytes;
            } elseif ($bytes === '-') {
                $doc['bytes_l'] = 0;
            }
        }

        $durUs = $this->extractDurationUs($raw);
        if ($durUs !== null) {
            $doc['dur_us_l'] = $durUs;
        }

        [$kind, $assetKind] = $this->classifyPath($req['path']);
        $doc['kind_s'] = $kind;
        self::put($doc, 'asset_kind_s', $assetKind);

        if (self::isOwnRequest(
            $doc['host_s'] ?? null,
            $req['path'],
            (string) $this->opts['own_host'],
            (array) $this->opts['own_paths']
        )) {
            $doc['_self_b'] = true;
        }

        $referer = self::header($raw, 'referer');
        if ($referer !== null) {
            self::put($doc, 'referer_s', self::sanitizeText($referer, self::MAX_TEXT));
            $refHost = self::hostOf($referer);
            self::put($doc, 'referer_host_s', $refHost);
        }
        if (array_key_exists('header_in.referer', $raw)) {
            $doc['referer_type_s'] = $this->refererType(
                $referer,
                $doc['referer_host_s'] ?? null,
                $doc['host_s'] ?? null,
                $req['query']
            );
        }

        $accept     = self::header($raw, 'accept');
        $acceptLang = self::header($raw, 'accept-language');
        $acceptEnc  = self::header($raw, 'accept-encoding');
        self::put($doc, 'accept_s', self::sanitizeText($accept, 512));
        self::put($doc, 'accept_lang_s', self::sanitizeText($acceptLang, 255));
        self::put($doc, 'accept_enc_s', self::sanitizeText($acceptEnc, 255));

        $secChUa       = self::header($raw, 'sec-ch-ua');
        $secChPlatform = self::header($raw, 'sec-ch-ua-platform');
        $secChMobile   = self::header($raw, 'sec-ch-ua-mobile');
        self::put($doc, 'sec_ch_ua_s', self::sanitizeText($secChUa, 512));
        self::put($doc, 'sec_ch_platform_s', self::sanitizeText(trim((string) $secChPlatform, '"'), 64));
        if ($secChMobile !== null) {
            if ($secChMobile === '?1') {
                $doc['sec_ch_mobile_b'] = true;
            } elseif ($secChMobile === '?0') {
                $doc['sec_ch_mobile_b'] = false;
            }
        }

        self::put($doc, 'sec_fetch_site_s', self::sanitizeText(self::header($raw, 'sec-fetch-site'), 64));
        self::put($doc, 'sec_fetch_mode_s', self::sanitizeText(self::header($raw, 'sec-fetch-mode'), 64));
        self::put($doc, 'sec_fetch_dest_s', self::sanitizeText(self::header($raw, 'sec-fetch-dest'), 64));
        self::put($doc, 'sec_fetch_user_s', self::sanitizeText(self::header($raw, 'sec-fetch-user'), 64));

        self::put($doc, 'xff_s', self::sanitizeText(self::header($raw, 'x-forwarded-for'), 512));

        self::put($doc, 'tls_proto_s', self::sanitizeText($raw['var.ssl_protocol'] ?? null, 32));
        self::put($doc, 'tls_cipher_s', self::sanitizeText($raw['var.ssl_cipher'] ?? null, 128));
        self::put($doc, 'ja4_s', self::sanitizeText(
            $raw['var.ja4'] ?? (self::header($raw, 'x-ja4') ?? null),
            64
        ));

        $uaLogged = array_key_exists('header_in.user-agent', $raw);
        $uaRaw    = self::header($raw, 'user-agent');
        $uaClean  = $uaRaw === null ? '' : (self::sanitizeText($uaRaw, self::MAX_TEXT) ?? '');

        if ($uaClean !== '') {
            $doc['ua_s'] = $uaClean;
        }
        if ($uaLogged) {
            $doc['ua_hash_s'] = sha1($uaClean);
            foreach (Ua::parse($uaClean)->fields() as $k => $v) {
                $doc[$k] = $v;
            }
        }

        $fp = $this->fingerprint($raw, $doc);
        if ($fp !== null) {
            $doc['fp_hash_s'] = $fp;
        }

        if (isset($doc['ip_net_s'], $doc['ua_hash_s'])) {
            $base = $doc['ip_net_s'] . '|' . $doc['ua_hash_s'] . '|' . ($acceptLang ?? '');
            $doc['visitor_s'] = $this->opts['ip_mode'] === 'hash'
                ? substr(hash_hmac('sha256', $base, ((string) $this->opts['ip_salt']) . gmdate('Y-m-d')), 0, 24)
                : substr(sha1($base), 0, 24);
        }

        if ($this->opts['keep_raw'] && $line !== '') {
            $doc['raw_s'] = self::sanitizeText($line, 8192) ?? '';
        }

        return $doc;
    }

    /** How many lines have failed to normalize since the last reset. */
    public function errors(): int
    {
        return $this->errors;
    }

    /** Why the most recent failure happened (for var/badlines.log annotations). */
    public function lastError(): ?string
    {
        return $this->lastError;
    }

    /** Reset the error counter, e.g. after flushing stats to the meta table. */
    public function resetErrors(): void
    {
        $this->errors = 0;
        $this->lastError = null;
    }

    /**
     * Recover the request time from whatever shape this format logs it in.
     *
     * CloudFront is the awkward one: it splits the instant across two W3C columns, a date
     * and a time, both of them UTC.
     *
     * @param array<string,string> $raw
     */
    private function extractTimestamp(array $raw, ?string $format): ?DateTimeImmutable
    {
        if (isset($raw['time']) && trim($raw['time']) !== '') {
            return self::parseTimestamp($raw['time'], $format);
        }
        if (isset($raw['date'], $raw['time_hms'])) {
            return self::parseTimestamp($raw['date'] . 'T' . $raw['time_hms'] . 'Z', null);
        }
        return null;
    }

    /**
     * Parse a timestamp in any of the shapes webservers emit, always returning UTC.
     *
     * Handled explicitly rather than by handing everything to strtotime(), because
     * strtotime() interprets a naive string in PHP's default timezone — which is whatever
     * the operator's php.ini says — and that would silently shift every timestamp in the
     * index by the server's UTC offset.
     *
     * The shapes are tried in this order:
     *
     *  1. An explicit format from the LogFormat, which wins because it cannot be ambiguous.
     *  2. Apache %t and nginx $time_local: 10/Sep/2026:09:57:08 +0000, where the fraction is
     *     optional — HAProxy writes 10/Sep/2026:09:57:08.123 with no offset at all. A
     *     timestamp with no offset logged is treated as UTC.
     *  3. ISO-8601 / RFC3339, with a 'T' or a space, with or without an offset. A naive
     *     string is again interpreted as UTC, because UTC is the fallback zone — never the
     *     server's local time.
     *  4. Epoch values, where the magnitude tells us the unit: Caddy logs float seconds,
     *     Apache's %{msec}t logs milliseconds and %{usec}t microseconds.
     *
     * @param string|null $format Explicit DateTime::createFromFormat() format, when known.
     */
    public static function parseTimestamp(string $value, ?string $format = null): ?DateTimeImmutable
    {
        $utc   = new DateTimeZone('UTC');
        $value = trim(trim($value), '[]');
        if ($value === '' || $value === '-') {
            return null;
        }

        if ($format !== null && $format !== '') {
            $dt = DateTimeImmutable::createFromFormat($format, $value, $utc);
            if ($dt instanceof DateTimeImmutable) {
                return $dt->setTimezone($utc);
            }
        }

        if (preg_match(
            '~^(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(?:\s*([+-]\d{4}))?$~D',
            $value,
            $m
        )) {
            $offset = $m[8] ?? '+0000';
            $frac   = isset($m[7]) && $m[7] !== '' ? str_pad(substr($m[7], 0, 3), 3, '0') : '000';
            $rebuilt = sprintf(
                '%02d/%s/%s:%s:%s:%s.%s %s',
                (int) $m[1], ucfirst(strtolower($m[2])), $m[3], $m[4], $m[5], $m[6], $frac, $offset
            );
            $dt = DateTimeImmutable::createFromFormat('d/M/Y:H:i:s.v O', $rebuilt, $utc);
            if ($dt instanceof DateTimeImmutable) {
                return $dt->setTimezone($utc);
            }
        }

        if (preg_match('~^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}~', $value)) {
            try {
                return (new DateTimeImmutable($value, $utc))->setTimezone($utc);
            } catch (\Exception $e) {
                return null;
            }
        }

        if (preg_match('~^(\d{9,19})(?:\.(\d+))?$~D', $value, $m)) {
            $digits = strlen($m[1]);
            $intPart = $m[1];
            $micro   = 0;

            if ($digits >= 16) {
                $micro   = (int) substr($intPart, -6);
                $intPart = substr($intPart, 0, -6);
            } elseif ($digits >= 13) {
                $micro   = ((int) substr($intPart, -3)) * 1000;
                $intPart = substr($intPart, 0, -3);
            } elseif (isset($m[2])) {
                $micro = (int) str_pad(substr($m[2], 0, 6), 6, '0');
            }

            $dt = DateTimeImmutable::createFromFormat(
                'U.u',
                $intPart . '.' . str_pad((string) $micro, 6, '0', STR_PAD_LEFT),
                $utc
            );
            if ($dt instanceof DateTimeImmutable) {
                return $dt->setTimezone($utc);
            }
        }

        return null;
    }

    /**
     * Convert a hit document's `ts` back into epoch milliseconds.
     *
     * The Sessionizer needs arithmetic on the instant; the document needs the Solr string.
     * Rather than smuggling a private key into the document (which would then have to be
     * stripped before indexing, and would break the moment someone forgot), the conversion
     * is exposed here.
     */
    public static function epochMs(string $ts): int
    {
        $dt = DateTimeImmutable::createFromFormat('Y-m-d\TH:i:s.v\Z', $ts, new DateTimeZone('UTC'));
        if (!$dt instanceof DateTimeImmutable) {
            return 0;
        }
        return (int) ($dt->format('U') * 1000 + (int) $dt->format('v'));
    }

    /**
     * Recover method / path / query / protocol from whichever fields the format provides.
     *
     * Three sources, in order of preference:
     *   - a `"%r"`-style request line, which is what almost every format logs;
     *   - separate `$request_method` / `$uri` / `$args` fields (nginx, Caddy, Traefik);
     *   - a `$request_uri` that bundles path and query.
     *
     * Absolute-URI targets (`GET http://host/path HTTP/1.1`) are decomposed, because that is
     * what AWS ALB always logs and what a proxy request looks like — leaving the scheme and
     * host glued to the path would fragment every path facet.
     *
     * A request line with no protocol is HTTP/0.9, or one the client truncated. A request
     * line that is outright garbage — very common, since scanners send raw TLS bytes to
     * port 80 — is kept as the path, because that preserves the evidence instead of
     * dropping the hit. A target that was entirely control characters is recorded under a
     * stable marker for the same reason: the hit exists and has no usable path, and the
     * probe should still leave a trace.
     *
     * Apache's %q carries its own '?' while nginx's $args does not, so the two are joined
     * differently. `query_s` is stored without the leading '?', because the '?' is a
     * delimiter rather than data. A '#fragment' is never sent on the wire, but proxies and
     * bad clients log one anyway, so it is removed.
     *
     * @param array<string,string> $raw
     * @return array{method:?string,path:string,query:?string,proto:?string,host:?string}|null
     */
    private function extractRequest(array $raw): ?array
    {
        $method = null;
        $proto  = null;
        $target = null;

        $request = $raw['request'] ?? null;
        if (is_string($request) && $request !== '' && $request !== '-') {
            $split = self::splitRequestLine($request);
            $method = $split['method'];
            $target = $split['target'];
            $proto  = $split['proto'];
        }

        if ($target === null) {
            $method = $raw['method'] ?? null;
            $proto  = $raw['proto'] ?? null;
            if (isset($raw['uri_full']) && $raw['uri_full'] !== '') {
                $target = $raw['uri_full'];
            } elseif (isset($raw['uri'])) {
                $target = $raw['uri'];
                if (isset($raw['query']) && $raw['query'] !== '') {
                    $target .= $raw['query'];
                } elseif (isset($raw['query_raw']) && $raw['query_raw'] !== '') {
                    $target .= '?' . $raw['query_raw'];
                }
            }
        }

        if ($target === null || $target === '') {
            return null;
        }

        $host = null;
        if (preg_match('~^[a-z][a-z0-9+.\-]*://~i', $target)) {
            $parts = parse_url($target);
            if (is_array($parts)) {
                $host   = $parts['host'] ?? null;
                $target = ($parts['path'] ?? '/')
                    . (isset($parts['query']) ? '?' . $parts['query'] : '');
            }
        }

        $query = null;
        $qpos  = strpos($target, '?');
        if ($qpos !== false) {
            $query  = substr($target, $qpos + 1);
            $target = substr($target, 0, $qpos);
        }
        $hpos = strpos($target, '#');
        if ($hpos !== false) {
            $target = substr($target, 0, $hpos);
        }

        $path = self::sanitizeText($target, self::MAX_TEXT);
        if ($path === null) {
            $path = '/';
        }

        return [
            'method' => is_string($method) && $method !== '' && $method !== '-'
                ? self::sanitizeText($method, 32)
                : null,
            'path'   => $path,
            'query'  => self::sanitizeText($query, self::MAX_TEXT),
            'proto'  => is_string($proto) ? $proto : null,
            'host'   => $host,
        ];
    }

    /**
     * Longest request line this parser will decompose into method / target / protocol.
     *
     * A real one is bounded by the origin server: Apache's LimitRequestLine is 8190 by
     * default and nginx's large_client_header_buffers is 8k. Anything past that was not a
     * request any server answered, so there is nothing to decompose — it is kept whole as
     * the target, which is what the surrounding docblock means by "preserves the evidence".
     */
    private const MAX_REQUEST_LINE = 8192;

    /**
     * Split a `"%r"` request line into method, target and protocol, in linear time.
     *
     * THIS WAS A REGULAR EXPRESSION AND IT WAS A DENIAL OF SERVICE. The pattern was
     * `~^(\S+)\s+(.*?)\s+(HTTP/[0-9.]+)$~i`, in which `.*?` and the `\s+` on either side of
     * it all match whitespace: for every way of splitting a run of spaces, the lazy group
     * re-walks the remainder, and the trailing literal denies PCRE the required-substring
     * short-circuit that would otherwise cut the search off. A request line of `GET`, six
     * thousand spaces and `HTTP/1.1x` is 6 KB — inside every server's own line limit and
     * inside `ingest.max_line_bytes` — and measured at 13 ms against 0.04 ms for an ordinary
     * line: a 300-fold collapse in ingest throughput, from one request, repeatable at line
     * rate. `%r` is logged verbatim even for a request the server answered 400, so an
     * attacker does not need a valid request to get their bytes in here.
     *
     * It was also silently WRONG under the same input. `preg_match` returns `false` when the
     * backtrack limit is exhausted, which is falsy and therefore indistinguishable from "did
     * not match", so the line fell through to the second pattern and the protocol token was
     * stored as the request path.
     *
     * A request line is `METHOD SP TARGET SP PROTOCOL` and needs no search at all: the method
     * ends at the first whitespace and the protocol begins after the last. `strcspn` and
     * `strrpos` answer both in one pass each, with no backtracking to exhaust, and the result
     * is identical to the pattern's on every well-formed line. Garbage stays garbage and is
     * kept as the target exactly as before.
     *
     * @return array{method:?string,target:?string,proto:?string}
     */
    private static function splitRequestLine(string $request): array
    {
        $none = ['method' => null, 'target' => $request, 'proto' => null];

        if (strlen($request) > self::MAX_REQUEST_LINE) {
            return $none;
        }

        $head = strcspn($request, " \t");
        if ($head === 0 || $head >= strlen($request)) {
            return $none;
        }

        $method = substr($request, 0, $head);
        $rest   = ltrim(substr($request, $head), " \t");
        if ($rest === '') {
            return $none;
        }

        $sp  = strrpos($rest, ' ');
        $tab = strrpos($rest, "\t");
        $cut = max($sp === false ? -1 : $sp, $tab === false ? -1 : $tab);

        if ($cut >= 0) {
            $tail = substr($rest, $cut + 1);
            if (preg_match('~^HTTP/[0-9.]{1,8}$~iD', $tail) === 1) {
                $target = rtrim(substr($rest, 0, $cut), " \t");
                if ($target !== '') {
                    return ['method' => $method, 'target' => $target, 'proto' => $tail];
                }
            }
        }

        return ['method' => $method, 'target' => $rest, 'proto' => null];
    }

    /**
     * Normalize the protocol token for faceting.
     *
     * `HTTP/2.0` (what Caddy and nginx log) and `HTTP/2` (what Apache logs) are the same
     * protocol, and a facet that splits them into two rows is just wrong.
     */
    private static function normalizeProto(?string $proto): ?string
    {
        if ($proto === null) {
            return null;
        }
        $proto = strtoupper(trim($proto));
        if ($proto === '' || $proto === '-') {
            return null;
        }
        if ($proto === 'HTTP/2.0') {
            return 'HTTP/2';
        }
        if ($proto === 'HTTP/3.0') {
            return 'HTTP/3';
        }
        return self::sanitizeText($proto, 16);
    }

    /**
     * Request duration in microseconds, from whichever timing field the format carries.
     *
     * Returns null (⇒ the field is absent) when the format logs no timing at all, which is
     * the case for plain `combined`. Never 0 — "not measured" and "took no time" are
     * different facts and the Performance view must not conflate them.
     *
     * The sources, in order of preference: %D, already microseconds and the most precise
     * thing Apache offers; %{ms}T; %T and nginx's $request_time, in seconds and possibly
     * fractional; and Traefik's field, which is nanoseconds.
     *
     * @param array<string,string> $raw
     */
    private function extractDurationUs(array $raw): ?int
    {
        if (isset($raw['dur_us']) && ctype_digit($raw['dur_us'])) {
            return (int) $raw['dur_us'];
        }
        if (isset($raw['dur_ms']) && is_numeric($raw['dur_ms'])) {
            return (int) round(((float) $raw['dur_ms']) * 1000);
        }
        if (isset($raw['dur_s']) && is_numeric($raw['dur_s'])) {
            return (int) round(((float) $raw['dur_s']) * 1000000);
        }
        if (isset($raw['dur_ns']) && is_numeric($raw['dur_ns'])) {
            return (int) round(((float) $raw['dur_ns']) / 1000);
        }
        return null;
    }

    /**
     * Classify a request path into `kind_s` and, for assets, `asset_kind_s`.
     *
     * The order of the tests is the contract: the beacon collector must never be counted as
     * a page, a favicon must never be counted as an image asset (it is requested by the
     * browser unprompted and would inflate the asset ratio that feeds the `no_assets` rule),
     * and robots.txt must never be counted as HTML (crawlers fetching it are not pageviews).
     *
     * The tests run in this order: our own beacon endpoint; browser-initiated site chrome
     * that is neither a page nor a real asset request; crawler-facing metadata files;
     * sub-resources; machine-facing endpoints; pages, meaning an explicit page extension or
     * no extension at all for pretty URLs; and finally downloads, feeds and anything else
     * carrying an extension we do not model.
     *
     * @return array{0:string,1:?string}
     */
    private function classifyPath(string $path): array
    {
        $lower = strtolower($path);
        $base  = basename($lower);

        foreach ((array) $this->opts['beacon_paths'] as $bp) {
            if ($lower === strtolower((string) $bp)) {
                return ['beacon', null];
            }
        }

        if (str_starts_with($base, 'favicon.') || str_starts_with($base, 'apple-touch-icon')) {
            return ['favicon', null];
        }

        if ($lower === '/robots.txt' || $lower === '/ads.txt' || $lower === '/app-ads.txt'
            || $lower === '/security.txt' || str_starts_with($lower, '/.well-known/')
            || preg_match('~^sitemap.*\.xml(\.gz)?$~D', $base) === 1
            || $lower === '/sitemap_index.xml') {
            return ['robots', null];
        }

        /*
         * A DOT IN A PRETTY URL IS NOT A FILE EXTENSION.
         *
         * This took everything after the last dot and treated it as one, which is right for
         * `/style.css` and catastrophic for a slug that happens to contain a dot. On this
         * installation the victims were the entire `/learn/` library, because those titles are
         * full of dots — `…query-parser.-how-it-works-and-how-it-helps` yielded an "extension"
         * of `-how-it-works-and-how-it-helps`, `…solr.fastlrucache-cache-class-removed-in-solr-9`
         * yielded one 42 characters long, and `my-schema.xml-doesnt-take-effect` yielded
         * `xml-doesnt-take-effect`.
         *
         * None matched an asset kind, an api extension or HTML_EXTS, so each fell through to
         * `other` — and `other` is not a page. The consequences ran through every layer above:
         * `pages` never incremented, so real readers arrived as sessions with `pages_i: 0`;
         * `entry_path_s` and `exit_path_s` were never set, so the page column had nothing to
         * show; the Pages view undercounted its own articles; and the cap that keeps a
         * page-less visit at `likely_human` was demoting people who had read an article.
         *
         * A REAL EXTENSION IS SHORT AND ALPHANUMERIC, which is the whole test. Anything else is
         * part of the slug and the path has no extension at all — which the block below already
         * treats as a page, exactly as this method's own docblock says it should. Eight
         * characters covers `woff2`, `xhtml` and `m3u8` with room to spare, and the character
         * class excludes every hyphenated tail above. `.pdf`, `.apk` and `.webp` still read as
         * extensions and still classify as downloads and assets, so nothing that is not a page
         * is swept into the pageview count to buy this.
         */
        $ext = '';
        $dot = strrpos($base, '.');
        if ($dot !== false && $dot < strlen($base) - 1) {
            $candidate = substr($base, $dot + 1);
            if (preg_match('~^[a-z0-9]{1,8}$~D', $candidate) === 1) {
                $ext = $candidate;
            }
        }

        if ($ext !== '' && isset(self::ASSET_KINDS[$ext])) {
            return ['asset', self::ASSET_KINDS[$ext]];
        }

        if (str_starts_with($lower, '/api/') || str_contains($lower, '/api/')
            || str_contains($lower, '/rest/') || str_contains($lower, '/graphql')
            || str_starts_with($lower, '/wp-json/') || str_contains($lower, '/jsonapi')
            || $ext === 'json' || $ext === 'xml' || $ext === 'rss' || $ext === 'atom') {
            return ['api', null];
        }

        if ($ext === '' || in_array($ext, self::HTML_EXTS, true)) {
            return ['html', null];
        }

        return ['other', null];
    }

    /**
     * Classify where a visitor came from.
     *
     * `ad` is tested before `search` on purpose: a paid Google click has a google.com
     * referer AND a gclid, and calling it organic search would overstate SEO performance,
     * which is exactly the kind of quietly-wrong number this project refuses to produce.
     *
     * Internal is tested before either of them, because a same-site referer cannot belong to
     * any of the other categories. A paid click is identified by the click-id the ad network
     * appends to OUR url, not by the referring host.
     */
    private function refererType(?string $referer, ?string $refHost, ?string $host, ?string $query): string
    {
        if ($referer === null || $referer === '') {
            return 'direct';
        }

        if ($refHost !== null && $host !== null && $refHost === $host) {
            return 'internal';
        }
        if ($refHost !== null) {
            foreach ((array) $this->opts['internal_hosts'] as $internal) {
                if ($refHost === strtolower((string) $internal)) {
                    return 'internal';
                }
            }
        }

        if ($query !== null && $query !== '') {
            parse_str($query, $params);
            foreach (self::AD_CLICK_PARAMS as $p) {
                if (isset($params[$p]) && $params[$p] !== '') {
                    return 'ad';
                }
            }
            $medium = strtolower((string) ($params['utm_medium'] ?? ''));
            if (in_array($medium, ['cpc', 'ppc', 'paid', 'paidsearch', 'display', 'banner'], true)) {
                return 'ad';
            }
        }
        if ($refHost !== null && self::hostMatches($refHost, self::AD_HOSTS)) {
            return 'ad';
        }

        if ($refHost !== null && self::hostMatches($refHost, self::AI_REFERER_HOSTS)) {
            return 'ai';
        }
        if ($refHost !== null && self::hostMatches($refHost, self::SEARCH_HOSTS)) {
            return 'search';
        }
        if ($refHost !== null && self::hostMatches($refHost, self::SOCIAL_HOSTS)) {
            return 'social';
        }

        return 'link';
    }

    /**
     * Suffix/substring match of a hostname against a needle list.
     *
     * Entries ending in '.' (e.g. 'google.') match any TLD, which is how one entry covers
     * google.com, google.co.uk, google.de and the other 190 of them. The match is anchored
     * at a label boundary, so 'google.' matches 'www.google.co.uk' but not 'notgoogle.com'.
     *
     * @param string[] $needles
     */
    private static function hostMatches(string $host, array $needles): bool
    {
        foreach ($needles as $needle) {
            if (str_ends_with($needle, '.')) {
                if ($host === rtrim($needle, '.')
                    || str_contains('.' . $host, '.' . $needle)) {
                    return true;
                }
                continue;
            }
            if ($host === $needle || str_ends_with($host, '.' . $needle)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extract the lowercased hostname from a referer URL.
     *
     * Returns null for a referer that is not an absolute URL (a bare path, or junk), because
     * an invented host would poison the referrer facet. A hostname is a restricted grammar,
     * and anything that does not fit it came from a forged referer.
     */
    private static function hostOf(string $url): ?string
    {
        $host = parse_url($url, PHP_URL_HOST);
        if (!is_string($host) || $host === '') {
            return null;
        }
        $host = strtolower($host);
        if (!preg_match('/^[a-z0-9._\-\[\]:]{1,253}$/D', $host)) {
            return null;
        }
        return $host;
    }

    /**
     * Compute `fp_hash_s`, the header-tuple fingerprint.
     *
     * SPEC §4.1: "sha1 of the normalized header tuple: ua + accept + accept_lang +
     * accept_enc + sec_ch_ua + sec_ch_platform + sec_fetch_* + proto. **Excludes IP by
     * design — that is the point.**"
     *
     * Excluding the address is what makes this the strongest anti-fleet signal available
     * from a log line alone: a scraper rotating through 400 residential proxies changes its
     * IP on every request but keeps sending byte-identical headers, so all 400 requests
     * collapse onto one fingerprint. `fp_ips_24h_i` on the session document then counts how
     * many distinct addresses shared it, and a browser fingerprint seen from five unrelated
     * networks in twelve hours is not a browser.
     *
     * Components are joined with "\n" (which cannot occur inside a header value) so that
     * "abc" + "" and "ab" + "c" cannot collide.
     *
     * Returns null when the format logs none of these headers — a constant hash across every
     * hit would be worse than useless, it would fire the cluster rule on the whole site. At
     * least one real header has to have been logged: the protocol on its own is not a
     * fingerprint, it is a two-value enum.
     *
     * @param array<string,string> $raw
     * @param array<string,mixed>  $doc
     */
    private function fingerprint(array $raw, array $doc): ?string
    {
        $parts = [
            $doc['ua_s']              ?? '',
            $doc['accept_s']          ?? '',
            $doc['accept_lang_s']     ?? '',
            $doc['accept_enc_s']      ?? '',
            $doc['sec_ch_ua_s']       ?? '',
            $doc['sec_ch_platform_s'] ?? '',
            $doc['sec_fetch_site_s']  ?? '',
            $doc['sec_fetch_mode_s']  ?? '',
            $doc['sec_fetch_dest_s']  ?? '',
            $doc['sec_fetch_user_s']  ?? '',
            $doc['proto_s']           ?? '',
        ];

        $headersSeen = false;
        foreach (
            [
                'header_in.user-agent', 'header_in.accept', 'header_in.accept-language',
                'header_in.accept-encoding', 'header_in.sec-ch-ua', 'header_in.sec-ch-ua-platform',
                'header_in.sec-fetch-site', 'header_in.sec-fetch-mode',
                'header_in.sec-fetch-dest', 'header_in.sec-fetch-user',
            ] as $key
        ) {
            if (array_key_exists($key, $raw)) {
                $headersSeen = true;
                break;
            }
        }
        if (!$headersSeen) {
            return null;
        }

        return sha1(implode("\n", $parts));
    }

    /**
     * Read a request header from the raw field array, mapping "-" and "" to null.
     *
     * Apache writes `-` for a header the client did not send. That is genuinely "absent",
     * so it must not survive as the literal string "-" in a facet.
     *
     * @param array<string,string> $raw
     */
    private static function header(array $raw, string $name): ?string
    {
        $v = $raw['header_in.' . $name] ?? null;
        if (!is_string($v)) {
            return null;
        }
        $v = trim($v);
        return ($v === '' || $v === '-') ? null : $v;
    }

    /**
     * Set a document field only when there is an actual value.
     *
     * The single enforcement point for SPEC §1's "absent, not zero-filled" rule: nothing in
     * normalize() assigns an optional field except through here.
     *
     * @param array<string,mixed> $doc
     * @param mixed               $value
     */
    private static function put(array &$doc, string $key, $value): void
    {
        if ($value === null || $value === '' || $value === '-') {
            return;
        }
        $doc[$key] = $value;
    }

    /**
     * Make an arbitrary log-derived byte string safe to put in a Solr document.
     *
     * Three separate problems, all of which are real on a public webserver:
     *  - **Invalid UTF-8.** A request path is bytes, not text; latin-1 and outright binary
     *    arrive daily. An invalid sequence makes the whole JSON update request fail, which
     *    would take down ingestion for the entire batch, not just the offending hit.
     *  - **Control characters.** C0 controls are illegal in XML and meaningless in a facet.
     *  - **Length.** A 2 MB "path" from a buffer-overflow probe must not become a 2 MB field.
     *
     * Returns null for values that are empty, "-", or reduce to nothing after cleaning, so
     * the caller's put() drops the field entirely.
     *
     * The byte cap is applied BEFORE any multibyte work, so that a hostile 50 MB field
     * cannot make the mb_* functions do 50 MB of work per line. Invalid sequences are
     * dropped by round-tripping through mb_convert_encoding(). The characters removed after
     * that are the C0 controls — none of them kept, not even tab, which has no business in a
     * log field — plus DEL; all are single ASCII bytes, so a byte-wise class is UTF-8 safe.
     */
    public static function sanitizeText(?string $s, int $max = self::MAX_TEXT): ?string
    {
        if ($s === null) {
            return null;
        }
        if (strlen($s) > $max * 4) {
            $s = substr($s, 0, $max * 4);
        }
        $s = trim($s);
        if ($s === '' || $s === '-') {
            return null;
        }
        if (!mb_check_encoding($s, 'UTF-8')) {
            $s = mb_convert_encoding($s, 'UTF-8', 'UTF-8');
        }
        $s = (string) preg_replace('/[\x00-\x1F\x7F]/', '', $s);
        if (mb_strlen($s, 'UTF-8') > $max) {
            $s = mb_substr($s, 0, $max, 'UTF-8');
        }
        $s = trim($s);
        return $s === '' ? null : $s;
    }
}
