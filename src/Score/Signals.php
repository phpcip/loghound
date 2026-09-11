<?php
/**
 * Loghound — signal extraction (SPEC §7 input side).
 *
 * Rules.php decides; this file only observes. Everything here answers a factual question
 * about a hit or a session — "is this fingerprint shared", "did a conditional request ever
 * happen", "does the platform the browser claims match the platform the header claims" —
 * and returns the answer plus, crucially, NULL when the answer is unknown.
 *
 * ---------------------------------------------------------------------------------------
 * NULL IS NOT FALSE. This is the single most important idea in this file.
 * ---------------------------------------------------------------------------------------
 * SPEC §1: "Never fabricate a metric." In a detector, the dangerous direction is treating
 * an absent measurement as a negative one:
 *
 *   * rdns_ok_b absent (rDNS lookups disabled) is NOT "reverse DNS failed". Reading it as
 *     false would flag every declared crawler on the site the moment an operator turned
 *     enrichment off.
 *   * sec_ch_ua_s absent when the log format does not capture it is NOT "the browser sent
 *     no Sec-CH-UA". Reading it as false would flag 100% of Chrome traffic on any site
 *     running plain apache `combined`, which is most of them.
 *   * no beacon on a site that never installed the beacon is NOT "JavaScript did not run".
 *
 * Every accessor below returns null for unknown, and every rule in Rules.php is written to
 * do nothing when it gets one. A detector that guesses is worse than no detector, because
 * people believe it.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Score;

use Loghound\Security;

final class Signals
{
    /**
     * Definitive automation markers reported by the beacon (SPEC §6.2).
     *
     * Each of these is a property that exists ONLY because a browser is being driven by an
     * automation framework. None of them has a legitimate reason to be present on a real
     * user's browser, which is why the rule they feed is worth 100 points on its own.
     *
     * What each code means, in the order they are listed:
     *   webdriver        navigator.webdriver === true
     *   cdc_props        $cdc_asdjflasutopfhvcZLmcfl_, chromedriver's injected object
     *   nightmare        window.__nightmare
     *   phantom          _phantom / callPhantom / __phantomas
     *   playwright       window.__playwright*
     *   puppeteer        window.__puppeteer*
     *   selenium         window.__selenium* / document.$cdc_
     *   dom_automation   window.domAutomation / domAutomationController
     *
     * @var string[]
     */
    public const DEFINITIVE_MARKERS = [
        'webdriver',
        'cdc_props',
        'nightmare',
        'phantom',
        'playwright',
        'puppeteer',
        'selenium',
        'dom_automation',
    ];

    /**
     * WebGL renderer strings that mean "there is no GPU behind this browser".
     *
     * A real desktop or phone reports its actual GPU here. These four are the software
     * rasterisers a headless browser falls back to, and seeing one on a UA claiming a
     * consumer desktop browser is very close to proof.
     *
     * Known false-positive population, and it is why this is 90 and not 100: virtual
     * desktops, some CI runners used by humans, and Linux machines with broken GPU drivers
     * genuinely report llvmpipe. Those users exist. They are rare, and 90 alone is enough
     * for `bot`, so this rule is documented in docs/DETECTION.md as one to lower if you
     * serve a VDI-heavy audience.
     *
     * @var string[]
     */
    public const HEADLESS_RENDERERS = [
        'swiftshader',
        'llvmpipe',
        'mesa offscreen',
        'microsoft basic render',
    ];

    /**
     * Declared crawlers whose operator publishes verifiable reverse DNS.
     *
     * Only these can have their claim CHECKED, so only these can FAIL the check. A crawler
     * not on this list that declares itself in the UA is taken at its word — being unable
     * to verify a claim is not evidence against it.
     *
     * @var array<string,string[]> bot name (lowercase) => rDNS suffixes that count as valid
     */
    public const VERIFIABLE_CRAWLERS = [
        'googlebot'       => ['.googlebot.com', '.google.com'],
        'google-inspectiontool' => ['.googlebot.com', '.google.com'],
        'storebot-google' => ['.googlebot.com', '.google.com'],
        'bingbot'         => ['.search.msn.com'],
        'adidxbot'        => ['.search.msn.com'],
        'yandexbot'       => ['.yandex.ru', '.yandex.net', '.yandex.com'],
        'baiduspider'     => ['.baidu.com', '.baidu.jp'],
        'duckduckbot'     => ['.duckduckgo.com'],
        'applebot'        => ['.applebot.apple.com'],
        'petalbot'        => ['.petalsearch.com', '.aspiegel.com'],
    ];

    /**
     * File extensions that make a request a sub-resource rather than a page.
     *
     * @var array<string,string> extension => asset_kind_s
     */
    private const ASSET_EXTENSIONS = [
        'js' => 'js', 'mjs' => 'js', 'cjs' => 'js',
        'css' => 'css',
        'png' => 'img', 'jpg' => 'img', 'jpeg' => 'img', 'gif' => 'img', 'webp' => 'img',
        'svg' => 'img', 'avif' => 'img', 'bmp' => 'img', 'ico' => 'img',
        'woff' => 'font', 'woff2' => 'font', 'ttf' => 'font', 'otf' => 'font', 'eot' => 'font',
        'mp4' => 'media', 'webm' => 'media', 'mp3' => 'media', 'ogg' => 'media',
        'wav' => 'media', 'm4a' => 'media', 'mov' => 'media',
    ];

    /**
     * Query parameters that, in combination, identify an analytics beacon.
     *
     * See classifyRequest() for how they are used and why the heuristic is shaped this way.
     *
     * @var string[]
     */
    private const BEACON_PARAMS = [
        'site_id', 'href', 'title', 'res', 'lang', 'tz', 'tc', 'ck', 'px', 'jsuid',
        'hm', 'heatmap', 'ref', 'dl', 'dt', 'tid', 'cid', 'uid', 'sid', 'ec', 'ea', 'el',
        'v', 'aip', 'ul', 'sd', 'vp', 'je', 'cs', 'cm', 'utmac', '_ga', 'idsite', 'rec',
        'apiv', 'action_name', 'urlref', 'pv_id', 'send_image', 'e_c', 'e_a', 'n', 'p', 'u',
    ];

    /**
     * Compute fp_hash_s — the cross-IP cluster key (SPEC §4.1).
     *
     * sha1 over the normalised header tuple. IP is EXCLUDED by design: a fleet on rotating
     * residential proxies changes its address on every single request, so any fingerprint
     * that includes the address identifies nothing. What it cannot change without breaking
     * the browser it is impersonating is the exact set and order of headers that browser
     * sends.
     *
     * "Normalised" means: lowercase, whitespace collapsed, and a MISSING component encoded
     * as the empty slot rather than skipped. The empty slot matters — "Accept-Language was
     * not sent" and "Accept-Language was en-US" must produce different tuples, and simply
     * omitting the absent one would let those two collide with a shifted tuple.
     *
     * HONEST LIMITATION, and it is a big one: the tuple below has eleven components, and
     * with plain apache `combined` nine of them are not logged — the whole Accept, Sec-CH
     * and Sec-Fetch set — so this degenerates to a hash of the User-Agent plus the protocol
     * version, the only two `combined` records. That still catches a fleet that uses one UA
     * across many addresses, but a fleet that also rotates its Chrome major version splits into one
     * cluster per version and can fall below the detection threshold. The recommended
     * LogFormat in SPEC §8 exists precisely to make this field discriminating, and
     * docs/SCHEMA.md says so in the section an operator will actually read.
     *
     * FALLBACK ONLY. Parser.php computes fp_hash_s from the same tuple during normalisation
     * and, importantly, leaves it ABSENT when the format logs no headers at all — a constant
     * hash across every hit would fire the cluster rule on the entire site. Sessionizer uses
     * the parser's value whenever it is present and calls this only for a hit that did not
     * come through the parser (a replay tool, a test harness). The component list below is
     * kept identical to the parser's for that reason.
     *
     * Normalisation collapses runs of whitespace, because some clients send ", " where
     * others send ",".
     *
     * @param array<string,mixed> $hit
     */
    public static function fingerprint(array $hit): string
    {
        $parts = [];
        foreach ([
            'ua_s', 'accept_s', 'accept_lang_s', 'accept_enc_s',
            'sec_ch_ua_s', 'sec_ch_platform_s',
            'sec_fetch_site_s', 'sec_fetch_mode_s', 'sec_fetch_dest_s', 'sec_fetch_user_s',
            'proto_s',
        ] as $field) {
            $value = isset($hit[$field]) ? (string) $hit[$field] : '';
            $value = strtolower(trim((string) preg_replace('/\s+/', ' ', $value)));
            $parts[] = $value;
        }
        return sha1(implode("\x1f", $parts));
    }

    /**
     * Compute visitor_s — a stable-ish identifier across sessions.
     *
     * "Stable-ish" is the honest description and the UI must repeat it: this survives a
     * session boundary but not a network change, a browser update that bumps the UA, or a
     * privacy mode switch. It is not a person and must never be labelled as one.
     *
     * In `hash` privacy mode the daily salt is folded in, so the same visitor gets a
     * different identifier tomorrow and cross-day tracking of an individual becomes
     * impossible while same-day sessionisation still works.
     *
     * @param array<string,mixed> $hit
     */
    public static function visitorHash(array $hit, string $ipMode = 'full', string $salt = ''): string
    {
        $material = ($hit['ip_net_s'] ?? ($hit['ip_s'] ?? '-'))
            . '|' . ($hit['ua_hash_s'] ?? sha1((string) ($hit['ua_s'] ?? '')))
            . '|' . ($hit['accept_lang_s'] ?? '');

        if ($ipMode === 'hash') {
            return substr(hash_hmac('sha256', (string) $material, $salt . gmdate('Y-m-d')), 0, 24);
        }
        return substr(sha1((string) $material), 0, 24);
    }

    /**
     * Classify a request into kind_s (and asset_kind_s where applicable).
     *
     * Lives here rather than in Parser.php because it is a DETECTION decision, not a
     * parsing one: kind_s drives the page count and asset_ratio_f, and both feed scoring
     * rules. Parser.php may set kind_s itself; Sessionizer only calls this when it is
     * absent, so there is exactly one implementation either way.
     *
     * The interesting case is `beacon`. Getting it wrong is not cosmetic: an analytics
     * beacon is a sub-resource fired BY a page, and counting it as a second pageview turns
     * every one-page visit into a two-page one — which would silently disarm the
     * single_page_10s rule on precisely the traffic it exists to catch. The bot fleet in
     * tests/fixtures/apache_combined_bot_fleet.log fires exactly one such beacon per
     * session, so this is not a hypothetical.
     *
     * Detection is deliberately generic rather than a list of vendor URLs, because
     * self-hosted analytics endpoints have random paths (Clicky's is a hex string). A GET
     * whose query carries three or more of the classic beacon parameters AND whose response
     * is under 4 KB is a beacon: real pages are bigger, and no page needs `res=1920x1080`
     * and `tz=America/New_York` in its query string. It is a heuristic and it is labelled
     * as one; the failure mode is a beacon counted as a page, which is the conservative
     * direction (it makes a session look MORE human, never less).
     *
     * The tests run in a deliberate order. Loghound's own collector comes first, when the
     * operator has told us where it lives — `_beacon_path` is set by Sessionizer from
     * Config::selfEndpoints(), and it matters: the shipped collector is `collect.php`, so
     * without it the extension test below would classify the collector as an HTML pageview,
     * which is precisely the miscount the paragraph above describes. Then the generic
     * analytics-beacon heuristic.
     * API-ish paths are checked AFTER the beacon test, because a beacon endpoint often lives
     * under /api/ too and "beacon" is the more specific answer. A path with no extension at
     * all is a page — the common case for modern URLs, and the reason extension-based
     * classification alone is not enough. A known extension we do not classify, a PDF, an
     * installer, an archive, is neither a page (it is not a navigation that a beacon would
     * follow) nor a sub-resource (it was not pulled in by the renderer).
     *
     * @param array<string,mixed> $hit
     * @return array{kind_s:string,asset_kind_s?:string}
     */
    public static function classifyRequest(array $hit): array
    {
        $path  = (string) ($hit['path_s'] ?? '');
        $query = (string) ($hit['query_s'] ?? '');
        $lower = strtolower($path);

        $ownBeacon = (string) ($hit['_beacon_path'] ?? '');
        if ($ownBeacon !== '' && $lower === strtolower($ownBeacon)) {
            return ['kind_s' => 'beacon'];
        }

        if ($lower === '/robots.txt') {
            return ['kind_s' => 'robots'];
        }

        $base = substr($lower, strrpos($lower, '/') !== false ? strrpos($lower, '/') + 1 : 0);
        if ($base === 'favicon.ico' || str_starts_with($base, 'apple-touch-icon')) {
            return ['kind_s' => 'favicon'];
        }

        $dot = strrpos($base, '.');
        $ext = $dot !== false ? substr($base, $dot + 1) : '';

        if ($ext !== '' && isset(self::ASSET_EXTENSIONS[$ext])) {
            return ['kind_s' => 'asset', 'asset_kind_s' => self::ASSET_EXTENSIONS[$ext]];
        }

        if ($query !== '') {
            parse_str($query, $parsed);
            $matches = 0;
            foreach (self::BEACON_PARAMS as $p) {
                if (array_key_exists($p, $parsed)) {
                    $matches++;
                }
            }
            $bytes = isset($hit['bytes_l']) ? (int) $hit['bytes_l'] : null;
            if ($matches >= 3 && ($bytes === null || $bytes < 4096)) {
                return ['kind_s' => 'beacon'];
            }
        }

        if (str_contains($lower, '/api/')
            || str_starts_with($lower, '/api')
            || $ext === 'json'
            || $ext === 'rss'
            || $ext === 'atom'
        ) {
            return ['kind_s' => 'api'];
        }

        if ($ext === '') {
            return ['kind_s' => 'html'];
        }

        if ($ext === 'html' || $ext === 'htm' || $ext === 'php' || $ext === 'asp' || $ext === 'aspx') {
            return ['kind_s' => 'html'];
        }

        return ['kind_s' => 'other'];
    }

    /**
     * Build the complete signal map that Rules.php scores.
     *
     * Every value is either a fact or null. Nothing here decides anything; the point of
     * separating this from Rules is that each signal can be asserted on its own in a test
     * without running the scorer, and that a rule change never silently changes what a
     * signal MEANS.
     *
     * The map is built in groups, and several of them carry a decision.
     *
     * Declared bot. A client "claims a real browser" when the UA parses as a consumer
     * browser and does not also declare itself a bot. Several rules hinge on this: the point
     * of no_js_on_html and hosting_asn_browser_ua is the CONTRADICTION between claiming to be
     * Chrome and not behaving like it, and neither is a contradiction for a crawler that
     * never claimed to be a browser in the first place.
     *
     * rDNS. NULL when the lookup was not performed or did not resolve, never coerced to
     * anything else. A crawler's claim can only FAIL verification when we were able to verify
     * it at all.
     *
     * Header self-consistency. Both signals return null unless the log format actually
     * captures the header, so an operator on plain `combined` never trips them; see
     * headerLogged().
     *
     * Session shape. Sub-resources are assets plus favicon — everything the renderer went and
     * fetched — and that, not `assets`, is what the no_assets rule asks about. The repeat
     * counter is distinct sub-resource URIs fetched more than once in this session. `own_assets`
     * is the sub-resources the session fetched from LOGHOUND itself, which Sessionizer counts
     * apart and excludes from every other number here; it exists so no_assets can tell "fetched
     * nothing" from "fetched only our own beacon script", and nothing else reads it.
     *
     * Fingerprint cluster. NULL when the scorer could not reach Solr. A rule reading null
     * must not treat it as 1: "we could not check" is not "this fingerprint is unique".
     *
     * Execution plane. The beacon keys are all optional, and absence means the beacon did not
     * report it. Two values are derived rather than read: which definitive markers actually
     * fired, and whether the WebGL renderer names a software rasteriser. Forgery is accepted
     * in two shapes — Beacon.php reports it as a code inside automation_ss, which is where
     * its timing-sanity check in SPEC §6.3 puts it, and a dedicated field is honoured too, so
     * neither spelling is silently ignored.
     *
     * @param array<string,mixed> $session Aggregate from Sessionizer::closeIdle().
     * @param array<string,mixed> $beacon  Merged beacon data (Beacon::mergeIntoSession()).
     *                                     Empty array when no beacon arrived.
     * @param int|null            $fpIps   fp_ips_24h_i, or null when it could not be computed.
     * @return array<string,mixed>
     */
    public static function fromSession(array $session, array $beacon = [], ?int $fpIps = null): array
    {
        $first = (array) ($session['first'] ?? []);

        $s = [];

        $s['session_id']  = (string) ($session['session_id'] ?? '');
        $s['fp_hash']     = (string) ($first['fp_hash_s'] ?? '');
        $s['as_type']     = isset($first['as_type_s']) ? (string) $first['as_type_s'] : null;
        $s['asn']         = isset($first['asn_i']) ? (int) $first['asn_i'] : null;
        $s['ua']          = (string) ($first['ua_s'] ?? '');
        $s['browser']     = isset($first['browser_s']) ? (string) $first['browser_s'] : null;
        $s['browser_ver'] = isset($first['browser_ver_i']) ? (int) $first['browser_ver_i'] : null;
        $s['os']          = isset($first['os_s']) ? (string) $first['os_s'] : null;
        $s['device']      = isset($first['device_s']) ? (string) $first['device_s'] : null;

        $s['ua_bot']      = isset($first['ua_bot_b']) ? (bool) $first['ua_bot_b'] : false;
        $s['ua_bot_name'] = isset($first['ua_bot_name_s']) ? (string) $first['ua_bot_name_s'] : null;
        $s['ua_bot_cat']  = isset($first['ua_bot_cat_s']) ? (string) $first['ua_bot_cat_s'] : null;
        $s['ai_crawler']  = isset($first['ai_crawler_b']) ? (bool) $first['ai_crawler_b'] : false;

        $s['claims_browser'] = !$s['ua_bot']
            && $s['browser'] !== null
            && in_array(strtolower((string) $s['browser']), [
                'chrome', 'firefox', 'safari', 'edge', 'opera', 'samsung internet', 'brave',
            ], true);

        $s['rdns']    = isset($first['rdns_s']) ? (string) $first['rdns_s'] : null;
        $s['rdns_ok'] = array_key_exists('rdns_ok_b', $first) ? (bool) $first['rdns_ok_b'] : null;

        $s['crawler_verifiable'] = $s['ua_bot'] && self::isVerifiableCrawler($s['ua_bot_name']);

        $s['secch_mismatch']    = self::secChMismatch($first, $s);
        $s['platform_mismatch'] = self::platformMismatch($first);

        $s['hits']         = (int) ($session['hits'] ?? 0);
        $s['pages']        = (int) ($session['pages'] ?? 0);
        $s['assets']       = (int) ($session['assets'] ?? 0);
        $s['favicons']     = (int) ($session['favicons'] ?? 0);
        $s['sub_resources'] = (int) ($session['sub_resources'] ?? ($s['assets'] + $s['favicons']));
        $s['own_assets']   = (int) ($session['own_assets'] ?? 0);
        $s['uniq_paths']   = (int) ($session['uniq_paths'] ?? 0);
        $s['log_span_ms']  = (int) ($session['log_span_ms'] ?? 0);
        $s['asset_ratio']  = (float) ($session['asset_ratio'] ?? 0.0);
        $s['html_200']     = (bool) ($session['html_200'] ?? false);
        $s['got_304']      = (bool) ($session['got_304'] ?? false);
        $s['repeat_assets'] = (int) ($session['repeat_assets'] ?? 0);

        $gaps = array_map('intval', (array) ($session['gaps'] ?? []));
        $s['gap_count']     = count($gaps);
        $s['gap_p50_ms']    = (int) ($session['gap_p50_ms'] ?? self::median($gaps));
        $s['gap_stddev_ms'] = (int) ($session['gap_stddev_ms'] ?? self::stddev($gaps));
        $s['periodic']      = self::isPeriodic($gaps);

        $s['fp_ips_24h'] = $fpIps;

        $s['beacon']         = (bool) ($beacon['beacon_b'] ?? false);
        $s['js']             = array_key_exists('js_b', $beacon) ? (bool) $beacon['js_b'] : null;
        $s['headless']       = array_key_exists('headless_b', $beacon) ? (bool) $beacon['headless_b'] : null;
        $s['ua_claim_ok']    = array_key_exists('ua_claim_ok_b', $beacon) ? (bool) $beacon['ua_claim_ok_b'] : null;
        $s['tz_match']       = array_key_exists('tz_match_b', $beacon) ? (bool) $beacon['tz_match_b'] : null;
        $s['webgl']          = isset($beacon['webgl_s']) ? (string) $beacon['webgl_s'] : null;
        $s['automation']     = array_values(array_filter(
            array_map('strval', (array) ($beacon['automation_ss'] ?? []))
        ));
        $s['interactions']   = array_key_exists('interactions_i', $beacon)
            ? (int) $beacon['interactions_i'] : null;
        $s['max_scroll_pct'] = array_key_exists('max_scroll_pct_i', $beacon)
            ? (int) $beacon['max_scroll_pct_i'] : null;
        $s['pageviews']      = array_key_exists('pageviews_i', $beacon)
            ? (int) $beacon['pageviews_i'] : null;
        $s['wall_ms']        = array_key_exists('wall_ms_l', $beacon) ? (int) $beacon['wall_ms_l'] : null;
        $s['visible_ms']     = array_key_exists('visible_ms_l', $beacon) ? (int) $beacon['visible_ms_l'] : null;
        $s['engaged_ms']     = array_key_exists('engaged_ms_l', $beacon) ? (int) $beacon['engaged_ms_l'] : null;

        $s['definitive_markers'] = array_values(array_intersect($s['automation'], self::DEFINITIVE_MARKERS));

        $s['beacon_forged'] = (bool) ($beacon['beacon_forged_b'] ?? false)
            || in_array('beacon_forged', $s['automation'], true);

        $s['headless_renderer'] = self::isHeadlessRenderer($s['webgl']);

        return $s;
    }

    /**
     * Is this declared crawler one whose identity we can verify by forward-confirmed rDNS?
     */
    public static function isVerifiableCrawler(?string $botName): bool
    {
        if ($botName === null || $botName === '') {
            return false;
        }
        return array_key_exists(strtolower($botName), self::VERIFIABLE_CRAWLERS);
    }

    /**
     * Does a WebGL renderer string name a software rasteriser?
     *
     * Returns null when the beacon did not report one — a browser with WebGL blocked, or
     * no beacon at all. Not false: "we did not see a GPU" is not "there is no GPU".
     */
    public static function isHeadlessRenderer(?string $webgl): ?bool
    {
        if ($webgl === null || $webgl === '') {
            return null;
        }
        $lower = strtolower($webgl);
        foreach (self::HEADLESS_RENDERERS as $needle) {
            if (str_contains($lower, $needle)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Sec-CH-UA versus the User-Agent's own browser claim.
     *
     * Returns:
     *   true   the header is absent or contradicts the UA, on a client that must send it
     *   false  the header is present and consistent
     *   null   we cannot tell — and this is the common case, so read it carefully
     *
     * The null cases are what keep this rule from being a disaster:
     *
     *   * The log format does not capture Sec-CH-UA. Then its absence from the document
     *     says nothing about what the browser sent, and firing here would flag every
     *     Chrome user on any site running plain `combined`.
     *   * The UA does not claim a Chromium browser. Firefox and Safari do not send
     *     Sec-CH-UA at all; expecting it would flag every one of them.
     *   * The UA claims Chrome older than 89, which predates the header.
     *   * Sec-CH-UA is sent only on secure contexts, so a plain-HTTP request legitimately
     *     has none. When the format captures the TLS protocol and it says the request was
     *     NOT over TLS, the browser was right not to send the header and its absence must
     *     not be read as evasion.
     *
     * Only Chromium-family browsers send the header, and only from version 89 onwards. When
     * it is logged, expected and not sent, that is the mismatch. When it IS present, the
     * versions it advertises are compared with the UA's claim: the header looks like
     * "Chromium";v="152", "Not(A:Brand";v="24", "Google Chrome";v="152", and the
     * "Not(A:Brand" entry carries a deliberately meaningless version, so a match on ANY
     * advertised version is enough to call it consistent.
     *
     * @param array<string,mixed> $first The first hit's identity fields.
     * @param array<string,mixed> $s     Partially built signal map (browser, version).
     */
    public static function secChMismatch(array $first, array $s): ?bool
    {
        if (!self::headerLogged($first, 'sec_ch_ua_s')) {
            return null;
        }

        $browser = strtolower((string) ($s['browser'] ?? ''));
        $ver     = (int) ($s['browser_ver'] ?? 0);

        if (!in_array($browser, ['chrome', 'edge', 'opera', 'brave', 'samsung internet'], true)) {
            return null;
        }
        if ($ver > 0 && $ver < 89) {
            return null;
        }
        if (array_key_exists('tls_proto_s', $first)
            && stripos((string) $first['tls_proto_s'], 'tls') === false
            && stripos((string) $first['tls_proto_s'], 'ssl') === false
        ) {
            return null;
        }

        $secCh = trim((string) ($first['sec_ch_ua_s'] ?? ''));
        if ($secCh === '' || $secCh === '-') {
            return true;
        }

        if ($ver > 0 && preg_match_all('/v="(\d+)/', $secCh, $m)) {
            $versions = array_map('intval', $m[1]);
            if (!in_array($ver, $versions, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Sec-CH-UA-Platform versus the operating system the User-Agent claims.
     *
     * Same null discipline as secChMismatch(): unknown unless the header is actually
     * captured by the log format and the UA gave us an OS to compare against.
     *
     * Chromium sends the low-entropy platform hint by default, so its absence on a format
     * that captures it is itself suspicious — but that is a weaker statement than a
     * contradiction, and Sec-CH-UA's own absence already covers the case. Returning null here
     * keeps the two rules from double-counting the same evidence.
     *
     * The header has a fixed vocabulary, which is mapped onto the OS names Enrich/Ua.php
     * produces. "Unknown", or a platform we do not model, is not a contradiction.
     *
     * @param array<string,mixed> $first
     */
    public static function platformMismatch(array $first): ?bool
    {
        if (!self::headerLogged($first, 'sec_ch_platform_s')) {
            return null;
        }
        $platform = trim((string) ($first['sec_ch_platform_s'] ?? ''), " \t\"'");
        if ($platform === '' || $platform === '-') {
            return null;
        }

        $os = strtolower((string) ($first['os_s'] ?? ''));
        if ($os === '') {
            return null;
        }

        $expected = [
            'windows'  => ['windows'],
            'macos'    => ['mac os', 'macos', 'mac os x', 'os x'],
            'linux'    => ['linux', 'ubuntu', 'fedora', 'debian'],
            'android'  => ['android'],
            'ios'      => ['ios', 'iphone os'],
            'chrome os' => ['chrome os', 'chromium os'],
            'chromeos' => ['chrome os', 'chromium os'],
        ];

        $key = strtolower($platform);
        if (!isset($expected[$key])) {
            return null;
        }

        foreach ($expected[$key] as $needle) {
            if (str_contains($os, $needle)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Does this log format actually capture the given header?
     *
     * Parser.php is expected to record which Loghound fields the compiled format can
     * produce, under `_logged`. Without that list we cannot distinguish "the browser did
     * not send it" from "the operator does not log it", and the difference decides whether
     * two 70-plus-point rules fire on every visitor or on none. When `_logged` is missing
     * entirely, this returns false — the conservative answer, which disarms the rules
     * rather than arming them against everyone.
     *
     * There is one fallback: a field that is present with a value proves the format captures
     * it, which makes the rules work for a hit that carries the header even when the parser
     * did not publish a `_logged` list.
     *
     * @param array<string,mixed> $first
     */
    public static function headerLogged(array $first, string $field): bool
    {
        $logged = $first['_logged'] ?? null;
        if (!is_array($logged)) {
            return array_key_exists($field, $first) && (string) $first[$field] !== '';
        }
        return in_array($field, $logged, true);
    }

    /**
     * Median of a list of integers. 0 for an empty list.
     *
     * The median rather than the mean because inter-request gaps are wildly skewed: one
     * five-minute pause in an otherwise dense session would drag a mean far away from
     * anything that describes the session's rhythm.
     *
     * @param int[] $values
     */
    public static function median(array $values): int
    {
        $n = count($values);
        if ($n === 0) {
            return 0;
        }
        sort($values);
        $mid = intdiv($n, 2);
        if ($n % 2 === 1) {
            return (int) $values[$mid];
        }
        return (int) round(($values[$mid - 1] + $values[$mid]) / 2);
    }

    /**
     * Population standard deviation of a list of integers. 0 for fewer than two values.
     *
     * @param int[] $values
     */
    public static function stddev(array $values): int
    {
        $n = count($values);
        if ($n < 2) {
            return 0;
        }
        $mean = array_sum($values) / $n;
        $sum = 0.0;
        foreach ($values as $v) {
            $sum += ($v - $mean) ** 2;
        }
        return (int) round(sqrt($sum / $n));
    }

    /**
     * Is this session's request rhythm machine-regular?
     *
     * This is the input to the periodic_timing rule, and it is written defensively because
     * a naive "standard deviation is low" test fires on completely normal humans.
     *
     * Three conditions, all required:
     *
     *  1. At least four gaps (five requests). Below that, "regular" is noise — two requests
     *     one second apart have a standard deviation of zero and mean nothing.
     *
     *  2. Median gap of at least one second. THIS IS THE IMPORTANT ONE. When a browser
     *     renders a page it fetches every sub-resource at once: six requests inside the
     *     same second, gaps of 0,0,0,0,1. That has a tiny standard deviation and is not a
     *     schedule, it is a burst — every human page load in
     *     tests/fixtures/apache_combined_human.log looks like this. Requiring a real
     *     interval means we are asking "is something waking up on a timer", which is the
     *     actual question.
     *
     *  3. Coefficient of variation (stddev / median) below 0.10. Relative rather than
     *     absolute: a client polling every 5 seconds and one polling every 5 minutes are
     *     equally scripted, and a fixed millisecond threshold would only catch the fast one.
     *
     * @param int[] $gaps
     */
    public static function isPeriodic(array $gaps): bool
    {
        if (count($gaps) < 4) {
            return false;
        }
        $median = self::median($gaps);
        if ($median < 1000) {
            return false;
        }
        $stddev = self::stddev($gaps);
        return ($stddev / $median) < 0.10;
    }

    /**
     * Clamp a score into 0–100.
     *
     * Weights are additive and can total well over 100 — an automation marker plus a
     * headless renderer plus a failed UA claim is 275. That is fine and even desirable
     * internally (it means the verdict is robust to one weight being wrong), but the
     * published number is a 0–100 confidence and must stay in range.
     */
    public static function clampScore(float $score): float
    {
        return round(max(0.0, min(100.0, $score)), 1);
    }

    /**
     * Clamp helper kept next to the others so Rules never reaches into Security directly
     * for a bare number.
     */
    public static function clampInt($value, int $min, int $max, int $default): int
    {
        return Security::clampInt($value, $min, $max, $default);
    }
}
