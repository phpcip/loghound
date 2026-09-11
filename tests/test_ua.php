<?php
/**
 * Loghound — tests for src/Enrich/Ua.php.
 *
 * Two things matter here beyond "does it recognise Chrome": that the Chrome-derived browsers
 * (Edge, Opera, Samsung, Vivaldi) are NOT reported as Chrome, and that the declared-bot
 * table is right — because `ua_declared_bot` is a weight-100 rule and `ai_crawler_b` is a
 * membership list SPEC §4.1 fixes by name.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

use Loghound\Enrich\Ua;

return [

    'mainstream browsers are identified with their major version' => function (): void {
        $cases = [
            // UA => [browser, major, os, device]
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36'
                => ['Chrome', 152, 'macOS', 'desktop'],
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36'
                => ['Chrome', 147, 'Windows 10/11', 'desktop'],
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36'
                => ['Chrome', 150, 'Linux', 'desktop'],
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0'
                => ['Firefox', 131, 'Windows 10/11', 'desktop'],
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15'
                => ['Safari', 17, 'macOS', 'desktop'],
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1'
                => ['Safari', 17, 'iOS 17', 'mobile'],
            'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36'
                => ['Chrome', 151, 'Android 14', 'mobile'],
            'Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/604.1'
                => ['Safari', 17, 'iOS 17', 'tablet'],
        ];

        foreach ($cases as $ua => [$browser, $major, $os, $device]) {
            $f = Ua::parse($ua)->fields();
            lh_same($browser, $f['browser_s'] ?? null, 'browser for ' . substr($ua, 0, 40));
            lh_same($major, $f['browser_ver_i'] ?? null, 'version for ' . substr($ua, 0, 40));
            lh_same($os, $f['os_s'] ?? null, 'os for ' . substr($ua, 0, 40));
            lh_same($device, $f['device_s'] ?? null, 'device for ' . substr($ua, 0, 40));
        }
    },

    'Chrome-derived browsers are not reported as Chrome' => function (): void {
        // Every one of these carries "Chrome/" in its UA. Testing Chrome first would make
        // the browser facet a single misleading bar.
        $cases = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36 Edg/152.0.2903.86'
                => 'Edge',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36 OPR/136.0.0.0'
                => 'Opera',
            'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/145.0.0.0 Mobile Safari/537.36'
                => 'Samsung Internet',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Vivaldi/7.2'
                => 'Vivaldi',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 YaBrowser/25.2 Safari/537.36'
                => 'Yandex Browser',
        ];

        foreach ($cases as $ua => $expected) {
            lh_same($expected, Ua::parse($ua)->fields()['browser_s'] ?? null, 'browser');
        }
    },

    'declared crawlers get a name and a category' => function (): void {
        $cases = [
            // UA fragment => [name, category, ai?]
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
                => ['Googlebot', 'search', false],
            'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)'
                => ['bingbot', 'search', false],
            'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot'
                => ['GPTBot', 'ai', true],
            'Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)'
                => ['ClaudeBot', 'ai', true],
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36; compatible; PerplexityBot/1.0'
                => ['PerplexityBot', 'ai', true],
            'Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)'
                => ['Bytespider', 'ai', true],
            'meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)'
                => ['meta-externalagent', 'ai', true],
            'Mozilla/5.0 (compatible; CCBot/2.0; +https://commoncrawl.org/faq/)'
                => ['CCBot', 'ai', true],
            'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)'
                => ['AhrefsBot', 'seo', false],
            'Mozilla/5.0 (compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)'
                => ['UptimeRobot', 'monitor', false],
            'Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)'
                => ['CensysInspect', 'security', false],
            'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)'
                => ['facebookexternalhit', 'social', false],
            'curl/8.4.0'
                => ['curl', 'other', false],
            'python-requests/2.32.3'
                => ['python-requests', 'other', false],
            'Go-http-client/2.0'
                => ['Go-http-client', 'other', false],
        ];

        foreach ($cases as $ua => [$name, $cat, $ai]) {
            $u = Ua::parse($ua);
            $f = $u->fields();
            lh_true($u->isBot(), 'isBot for ' . $name);
            lh_same(true, $f['ua_bot_b'] ?? null, 'ua_bot_b for ' . $name);
            lh_same($name, $f['ua_bot_name_s'] ?? null, 'ua_bot_name_s');
            lh_same($cat, $f['ua_bot_cat_s'] ?? null, 'ua_bot_cat_s for ' . $name);
            lh_same($ai, $f['ai_crawler_b'] ?? null, 'ai_crawler_b for ' . $name);
            lh_same('bot', $f['device_s'] ?? null, 'device_s for ' . $name);
        }
    },

    'Applebot-Extended is an AI crawler while plain Applebot is a search crawler' => function (): void {
        // The specific ordering trap in the table: the -Extended variant must be tested first
        // or it would be swallowed by the plain 'applebot' needle and mislabelled.
        $ext = Ua::parse('Mozilla/5.0 (compatible; Applebot-Extended/0.1; +http://www.apple.com/go/applebot)')->fields();
        lh_same('Applebot-Extended', $ext['ua_bot_name_s'], 'name');
        lh_same('ai', $ext['ua_bot_cat_s'], 'category');
        lh_same(true, $ext['ai_crawler_b'], 'ai_crawler_b');

        $plain = Ua::parse('Mozilla/5.0 (compatible; Applebot/0.1; +http://www.apple.com/go/applebot)')->fields();
        lh_same('Applebot', $plain['ua_bot_name_s'], 'name');
        lh_same('search', $plain['ua_bot_cat_s'], 'category');
        lh_same(false, $plain['ai_crawler_b'], 'ai_crawler_b');
    },

    'every AI crawler SPEC section 4.1 names is detected' => function (): void {
        // The list is a contract, so it is asserted as one.
        $names = [
            'GPTBot/1.2', 'ClaudeBot/1.0', 'PerplexityBot/1.0', 'Bytespider', 'Amazonbot/0.1',
            'meta-externalagent/1.1', 'Applebot-Extended/0.1', 'CCBot/2.0', 'Diffbot/0.1',
            'Omgilibot/0.1', 'cohere-ai', 'ImagesiftBot', 'YouBot/1.0', 'Timpibot/0.1',
            'Webzio-Extended/1.0',
        ];
        foreach ($names as $token) {
            $f = Ua::parse('Mozilla/5.0 (compatible; ' . $token . '; +http://example.com/bot)')->fields();
            lh_same(true, $f['ai_crawler_b'] ?? null, 'ai_crawler_b for ' . $token);
            lh_same('ai', $f['ua_bot_cat_s'] ?? null, 'ua_bot_cat_s for ' . $token);
        }
    },

    'a User-Agent that declares a crawler without naming one is marked as unnamed' => function (): void {
        /* THE DEFECT THIS PINS. `unspecified bot` outranks most real crawlers on a live site,
           and Bot forensics section 06 is headed "Declared crawlers, by name" — so it was
           ranking the absence of a name second, against Googlebot and GPTBot. The view can
           only group them below the named ones if it can ASK which is which, and this is the
           question it asks. */
        $cases = [
            'Mozilla/5.0 (compatible; SiteCrawler/1.0)'                       => 'unspecified crawler',
            'Mozilla/5.0 (compatible; NewsSpider/2.0)'                        => 'unspecified spider',
            'Mozilla/5.0 (compatible; Zqbot/1.0)'                             => 'unspecified bot',
            'Mozilla/5.0 (compatible; Zqbot; +mail@example.com)'              => 'unspecified bot',
            'Mozilla/5.0 (compatible; Acme/1.0; +https://example.com/about)'  => 'unspecified agent',
        ];

        foreach ($cases as $ua => $name) {
            $f = Ua::parse($ua)->fields();
            lh_same($name, $f['ua_bot_name_s'] ?? null, 'name for ' . $ua);
            lh_same(true, $f['ua_bot_b'] ?? null, 'still a declared bot: ' . $ua);
            lh_true(
                Ua::isUnspecified((string) ($f['ua_bot_name_s'] ?? '')),
                $ua . ' produced a name a by-name table would rank against real crawlers'
            );
        }
    },

    'the +http marker stays a bucket of its own, apart from unspecified bot' => function (): void {
        /* The two are DIFFERENT EVIDENCE — a client that called itself a bot against one that
           merely left a contact URL and matched nothing else — and `ua_bot_name_s` is a filter
           dimension, so each of these strings is in somebody's bookmarked panel URL and in
           exported files. Merging them would answer a saved filter with zero rows and would
           split the index's own history. If a change ever makes this test fail, that is what
           it broke. */
        $bot = Ua::parse('Mozilla/5.0 (compatible; Zqbot/1.0; +https://example.com/bot)')->fields();
        $agent = Ua::parse('Mozilla/5.0 (compatible; Acme/1.0; +https://example.com/about)')->fields();

        lh_same('unspecified bot', $bot['ua_bot_name_s'] ?? null, 'a self-declared bot keeps its own name');
        lh_same('unspecified agent', $agent['ua_bot_name_s'] ?? null, 'a bare contact URL keeps its own name');
        lh_true(
            ($bot['ua_bot_name_s'] ?? '') !== ($agent['ua_bot_name_s'] ?? ''),
            'two genuinely different populations were merged into one stored value'
        );
    },

    'isUnspecified answers for the markers and for nothing else' => function (): void {
        foreach (Ua::UNSPECIFIED_NAMES as $name) {
            lh_true(Ua::isUnspecified($name), 'isUnspecified for ' . $name);
        }
        foreach (['Googlebot', 'GPTBot', 'AhrefsBot', 'UptimeRobot', 'curl', 'facebookexternalhit'] as $name) {
            lh_false(Ua::isUnspecified($name), 'a real crawler must never be filed as unnamed: ' . $name);
        }
        lh_false(Ua::isUnspecified(''), 'the empty string is not a marker');
        lh_false(Ua::isUnspecified('Unspecified Bot'), 'the list is exact, not a prefix guess');
    },

    'every last-resort name in the table is declared in UNSPECIFIED_NAMES' => function (): void {
        /* The list and the table are two places, so they are checked against each other. A
           sixth last-resort entry added to BOTS without a line here would quietly reappear
           among the named crawlers in Bot forensics, ranked by a count it earned honestly —
           which is exactly how the original defect looked. */
        $table = (new ReflectionClass(Ua::class))->getReflectionConstant('BOTS')->getValue();

        $declared = [];
        foreach ($table as [, $name]) {
            if (stripos($name, 'unspecified') === 0) {
                $declared[$name] = true;
            }
        }

        foreach (array_keys($declared) as $name) {
            lh_true(
                Ua::isUnspecified($name),
                $name . ' is minted by the table and is not in Ua::UNSPECIFIED_NAMES'
            );
        }
        foreach (Ua::UNSPECIFIED_NAMES as $name) {
            lh_true(
                isset($declared[$name]),
                $name . ' is declared unnamed but nothing in the table produces it'
            );
        }
        lh_true(count($declared) >= 4, 'the sweep should have seen the markers, saw ' . count($declared));
    },

    'a normal browser is not flagged as a bot' => function (): void {
        $f = Ua::parse(
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
            . 'Chrome/152.0.0.0 Safari/537.36'
        )->fields();

        lh_same(false, $f['ua_bot_b'], 'ua_bot_b');
        lh_same(false, $f['ai_crawler_b'], 'ai_crawler_b');
        lh_no_key($f, 'ua_bot_name_s', 'fields');
        lh_no_key($f, 'ua_bot_cat_s', 'fields');
    },

    'claimsBrowser is true only for a real browser UA' => function (): void {
        // This gates the `no_js_on_html` rule: firing it on curl would flood the results.
        $browsers = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
        ];
        foreach ($browsers as $ua) {
            lh_true(Ua::parse($ua)->claimsBrowser(), 'claimsBrowser for ' . substr($ua, 0, 30));
        }

        $notBrowsers = [
            'curl/8.4.0',
            'python-requests/2.32.3',
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)',
            '',
            '-',
        ];
        foreach ($notBrowsers as $ua) {
            lh_false(Ua::parse($ua)->claimsBrowser(), 'claimsBrowser for ' . lh_show($ua));
        }
    },

    'an empty User-Agent is a known fact, not an unknown' => function (): void {
        $f = Ua::parse('')->fields();
        lh_same('unknown', $f['device_s'], 'device_s');
        lh_same(false, $f['ua_bot_b'], 'ua_bot_b');
        lh_no_key($f, 'browser_s', 'fields');
        lh_no_key($f, 'os_s', 'fields');
    },

    'an unrecognised UA yields absent fields, not empty strings' => function (): void {
        $f = Ua::parse('SomeTotallyUnknownThing')->fields();
        lh_no_key($f, 'browser_s', 'fields');
        lh_no_key($f, 'browser_ver_i', 'fields');
        lh_no_key($f, 'os_s', 'fields');
    },

    'parsing is memoised and the cache can be cleared' => function (): void {
        Ua::clearCache();
        $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36';
        // Same string ⇒ same object identity, which is what makes the hot path free.
        lh_true(Ua::parse($ua) === Ua::parse($ua), 'memoised');
        Ua::clearCache();
        lh_true(Ua::parse($ua) !== null, 'still works after a clear');
    },

    'a hostile User-Agent cannot crash the parser' => function (): void {
        foreach ([
            str_repeat('Chrome/', 5000),
            "\x00\x01\x02",
            str_repeat('(', 2000) . str_repeat(')', 2000),
            'Mozilla/5.0 ' . str_repeat('a', 100000),
        ] as $ua) {
            $f = Ua::parse($ua)->fields();
            lh_true(is_array($f), 'fields is an array');
        }
    },
];
