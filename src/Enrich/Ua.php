<?php
/**
 * Loghound — User-Agent parsing and declared-bot classification.
 *
 * Deliberately a curated table in code rather than a downloaded regex database
 * (ua-parser, browscap, DeviceAtlas). Three reasons, all of which matter more than the
 * extra coverage a 5 MB regex file would buy:
 *
 *  1. `git clone` + `install.sh` must work on an air-gapped box (SPEC §2). A parser that
 *     needs a periodic download of somebody else's regexes is not that.
 *  2. Those databases exist to answer "which phone is this", a question this project does
 *     not ask. Loghound needs browser family, major version, OS family and device class —
 *     four coarse buckets — plus an accurate answer to "does this UA declare itself a bot".
 *  3. A UA string is attacker-controlled. Running hundreds of unaudited third-party regexes
 *     over hostile input on the ingest hot path is a ReDoS surface we can simply not have.
 *
 * **This table is meant to be edited.** Adding a crawler is one line in BOTS; adding a
 * browser is one entry in matchBrowser(). Both are ordered lists where the first match wins,
 * so specific entries must come before general ones — `applebot-extended` before `applebot`,
 * `Edg/` before `Chrome/`.
 *
 * What this class explicitly does NOT do is decide whether a client is *actually* a bot. It
 * only reports what the UA CLAIMS. `Score/Rules.php` decides the verdict by correlating this
 * with the other two planes, because a declared crawler and a headless Chrome pretending to
 * be Safari are completely different findings (SPEC §7: "Honest crawlers are not the enemy").
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Enrich;

final class Ua
{
    /**
     * Declared-crawler table: [needle (lowercase), display name, category, is-AI-crawler].
     *
     * Category is one of SPEC §4.1's `ua_bot_cat_s` values:
     *   search | ai | seo | monitor | security | social | other
     *
     * The `ai` flag drives `ai_crawler_b`, whose membership list is fixed by SPEC §4.1:
     * GPTBot, ClaudeBot, PerplexityBot, Bytespider, Amazonbot, meta-externalagent,
     * Applebot-Extended, CCBot, Diffbot, Omgili, cohere-ai, ImagesiftBot, YouBot, Timpibot,
     * Webzio. The close relatives of those (OAI-SearchBot, ChatGPT-User, Google-Extended,
     * anthropic-ai) are included as well and annotated, because an operator asking "who is
     * training on my content" means all of them.
     *
     * ORDER IS SIGNIFICANT — first match wins.
     *
     * The table is grouped: AI/LLM crawlers first, which is the SPEC §4.1 ai_crawler_b list,
     * then search engines, SEO and marketing crawlers, uptime and performance monitors,
     * scanners and security research, social and link unfurlers, generic HTTP clients and
     * libraries, and finally the last-resort generic markers.
     *
     * Individual entries that need explaining: OAI-SearchBot is OpenAI's search index and
     * ChatGPT-User its user-triggered fetch; FacebookBot collects Meta's LLM corpus;
     * Applebot-Extended must be listed BEFORE applebot or the plain needle would swallow it;
     * Google-Extended is Gemini training. Palo Alto's scanner identifies itself as "Expanse, a
     * Palo Alto Networks company", and the trailing comma in the needle is what keeps it from
     * matching the ordinary English word. HeadlessChrome is honest headless.
     *
     * The generic HTTP clients are not "bots" in the crawler sense, but they self-declare as
     * non-browsers, and that is exactly what `ua_declared_bot` needs to know.
     *
     * The last-resort markers sit at the very bottom deliberately: 'bot' as a substring
     * matches far too much — Cubot phones, "Abbot" — so anything specific must have had its
     * chance first.
     *
     * @var array<int,array{0:string,1:string,2:string,3:bool}>
     */
    private const BOTS = [
        ['gptbot',                'GPTBot',              'ai',       true],
        ['oai-searchbot',         'OAI-SearchBot',       'ai',       true],
        ['chatgpt-user',          'ChatGPT-User',        'ai',       true],
        ['claudebot',             'ClaudeBot',           'ai',       true],
        ['claude-web',            'Claude-Web',          'ai',       true],
        ['claude-searchbot',      'Claude-SearchBot',    'ai',       true],
        ['anthropic-ai',          'anthropic-ai',        'ai',       true],
        ['perplexitybot',         'PerplexityBot',       'ai',       true],
        ['perplexity-user',       'Perplexity-User',     'ai',       true],
        ['bytespider',            'Bytespider',          'ai',       true],
        ['amazonbot',             'Amazonbot',           'ai',       true],
        ['meta-externalagent',    'meta-externalagent',  'ai',       true],
        ['meta-externalfetcher',  'meta-externalfetcher', 'ai',      true],
        ['facebookbot',           'FacebookBot',         'ai',       true],
        ['applebot-extended',     'Applebot-Extended',   'ai',       true],
        ['google-extended',       'Google-Extended',     'ai',       true],
        ['ccbot',                 'CCBot',               'ai',       true],
        ['diffbot',               'Diffbot',             'ai',       true],
        ['omgilibot',             'Omgilibot',           'ai',       true],
        ['omgili',                'Omgili',              'ai',       true],
        ['cohere-ai',             'cohere-ai',           'ai',       true],
        ['cohere-training-data-crawler', 'cohere-training-data-crawler', 'ai', true],
        ['imagesiftbot',          'ImagesiftBot',        'ai',       true],
        ['youbot',                'YouBot',              'ai',       true],
        ['timpibot',              'Timpibot',            'ai',       true],
        ['webzio-extended',       'Webzio-Extended',     'ai',       true],
        ['webzio',                'Webzio',              'ai',       true],
        ['ai2bot',                'AI2Bot',              'ai',       true],
        ['duckassistbot',         'DuckAssistBot',       'ai',       true],
        ['petalbot',              'PetalBot',            'ai',       true],
        ['mistralai-user',        'MistralAI-User',      'ai',       true],

        ['googlebot-image',       'Googlebot-Image',     'search',   false],
        ['googlebot-video',       'Googlebot-Video',     'search',   false],
        ['googlebot-news',        'Googlebot-News',      'search',   false],
        ['storebot-google',       'StoreBot-Google',     'search',   false],
        ['google-inspectiontool', 'Google-InspectionTool', 'search', false],
        ['adsbot-google',         'AdsBot-Google',       'search',   false],
        ['mediapartners-google',  'Mediapartners-Google', 'search',  false],
        ['googlebot',             'Googlebot',           'search',   false],
        ['bingpreview',           'BingPreview',         'search',   false],
        ['adidxbot',              'adidxbot',            'search',   false],
        ['bingbot',               'bingbot',             'search',   false],
        ['slurp',                 'Yahoo! Slurp',        'search',   false],
        ['duckduckbot',           'DuckDuckBot',         'search',   false],
        ['duckduckgo-favicons',   'DuckDuckGo-Favicons', 'search',   false],
        ['baiduspider',           'Baiduspider',         'search',   false],
        ['yandexbot',             'YandexBot',           'search',   false],
        ['yandeximages',          'YandexImages',        'search',   false],
        ['sogou',                 'Sogou',               'search',   false],
        ['exabot',                'Exabot',              'search',   false],
        ['seznambot',             'SeznamBot',           'search',   false],
        ['naver',                 'Naverbot',            'search',   false],
        ['qwantify',              'Qwantify',            'search',   false],
        ['applebot',              'Applebot',            'search',   false],
        ['ia_archiver',           'ia_archiver',         'search',   false],
        ['archive.org_bot',       'archive.org_bot',     'search',   false],

        ['ahrefsbot',             'AhrefsBot',           'seo',      false],
        ['ahrefssiteaudit',       'AhrefsSiteAudit',     'seo',      false],
        ['semrushbot',            'SemrushBot',          'seo',      false],
        ['mj12bot',               'MJ12bot',             'seo',      false],
        ['majestic',              'MajesticSEO',         'seo',      false],
        ['dotbot',                'DotBot',              'seo',      false],
        ['rogerbot',              'rogerbot',            'seo',      false],
        ['screaming frog',        'Screaming Frog',      'seo',      false],
        ['blexbot',               'BLEXBot',             'seo',      false],
        ['seokicks',              'SEOkicks',            'seo',      false],
        ['barkrowler',            'Barkrowler',          'seo',      false],
        ['dataforseobot',         'DataForSeoBot',       'seo',      false],
        ['serpstatbot',           'serpstatbot',         'seo',      false],
        ['sitecheckerbotcrawler', 'SiteCheckerBot',      'seo',      false],
        ['linkdexbot',            'linkdexbot',          'seo',      false],
        ['zoominfobot',           'ZoominfoBot',         'seo',      false],

        ['uptimerobot',           'UptimeRobot',         'monitor',  false],
        ['pingdom',               'Pingdom',             'monitor',  false],
        ['statuscake',            'StatusCake',          'monitor',  false],
        ['site24x7',              'Site24x7',            'monitor',  false],
        ['newrelicpinger',        'NewRelicPinger',      'monitor',  false],
        ['datadog',               'Datadog Agent',       'monitor',  false],
        ['betteruptime',          'Better Uptime',       'monitor',  false],
        ['hetrixtools',           'HetrixTools',         'monitor',  false],
        ['check_http',            'Nagios check_http',   'monitor',  false],
        ['zabbix',                'Zabbix',              'monitor',  false],
        ['prometheus',            'Prometheus',          'monitor',  false],
        ['blackbox_exporter',     'blackbox_exporter',   'monitor',  false],
        ['gtmetrix',              'GTmetrix',            'monitor',  false],
        ['lighthouse',            'Lighthouse',          'monitor',  false],
        ['chrome-lighthouse',     'Chrome-Lighthouse',   'monitor',  false],

        ['censysinspect',         'CensysInspect',       'security', false],
        ['expanse,',              'Expanse',             'security', false],
        ['internetmeasurement',   'InternetMeasurement', 'security', false],
        ['shodan',                'Shodan',              'security', false],
        ['zgrab',                 'ZGrab',               'security', false],
        ['masscan',               'masscan',             'security', false],
        ['nmap',                  'Nmap',                'security', false],
        ['nuclei',                'Nuclei',              'security', false],
        ['sqlmap',                'sqlmap',              'security', false],
        ['wpscan',                'WPScan',              'security', false],
        ['nikto',                 'Nikto',               'security', false],
        ['dirbuster',             'DirBuster',           'security', false],
        ['gobuster',              'gobuster',            'security', false],
        ['paloaltonetworks',      'Palo Alto Networks',  'security', false],
        ['l9explore',             'l9explore',           'security', false],

        ['facebookexternalhit',   'facebookexternalhit', 'social',   false],
        ['twitterbot',            'Twitterbot',          'social',   false],
        ['linkedinbot',           'LinkedInBot',         'social',   false],
        ['slackbot',              'Slackbot',            'social',   false],
        ['discordbot',            'Discordbot',          'social',   false],
        ['telegrambot',           'TelegramBot',         'social',   false],
        ['whatsapp',              'WhatsApp',            'social',   false],
        ['pinterest',             'Pinterestbot',        'social',   false],
        ['redditbot',             'redditbot',           'social',   false],
        ['mastodon',              'Mastodon',            'social',   false],
        ['embedly',               'Embedly',             'social',   false],
        ['skypeuripreview',       'SkypeUriPreview',     'social',   false],
        ['vkshare',               'VKShare',             'social',   false],
        ['bsky',                  'Bluesky',             'social',   false],

        ['curl/',                 'curl',                'other',    false],
        ['wget/',                 'Wget',                'other',    false],
        ['python-requests',       'python-requests',     'other',    false],
        ['python-urllib',         'python-urllib',       'other',    false],
        ['aiohttp',               'aiohttp',             'other',    false],
        ['httpx/',                'httpx',               'other',    false],
        ['scrapy',                'Scrapy',              'other',    false],
        ['go-http-client',        'Go-http-client',      'other',    false],
        ['okhttp',                'OkHttp',              'other',    false],
        ['apache-httpclient',     'Apache-HttpClient',   'other',    false],
        ['java/',                 'Java',                'other',    false],
        ['libwww-perl',           'libwww-perl',         'other',    false],
        ['postmanruntime',        'PostmanRuntime',      'other',    false],
        ['insomnia',              'Insomnia',            'other',    false],
        ['httpie',                'HTTPie',              'other',    false],
        ['axios/',                'axios',               'other',    false],
        ['node-fetch',            'node-fetch',          'other',    false],
        ['guzzlehttp',            'GuzzleHttp',          'other',    false],
        ['php/',                  'PHP',                 'other',    false],
        ['ruby',                  'Ruby',                'other',    false],
        ['dart/',                 'Dart',                'other',    false],
        ['powershell',            'PowerShell',          'other',    false],
        ['winhttp',               'WinHTTP',             'other',    false],
        ['headlesschrome',        'HeadlessChrome',      'other',    false],
        ['phantomjs',             'PhantomJS',           'other',    false],
        ['electron/',             'Electron',            'other',    false],

        ['crawler',               'unspecified crawler', 'other',    false],
        ['spider',                'unspecified spider',  'other',    false],
        ['bot/',                  'unspecified bot',     'other',    false],
        ['bot;',                  'unspecified bot',     'other',    false],
        ['+http',                 'unspecified agent',   'other',    false],
    ];

    /** Windows NT version => human name. NT 10.0 covers both 10 and 11; the UA cannot tell. */
    private const WINDOWS_NT = [
        '10.0' => 'Windows 10/11',
        '6.3'  => 'Windows 8.1',
        '6.2'  => 'Windows 8',
        '6.1'  => 'Windows 7',
        '6.0'  => 'Windows Vista',
        '5.2'  => 'Windows XP',
        '5.1'  => 'Windows XP',
    ];

    /** Memoisation cap. Access logs repeat a handful of UAs millions of times. */
    private const CACHE_MAX = 4096;

    /** @var array<string,self> */
    private static array $cache = [];

    private string $raw;

    /** @var array<string,mixed> Solr fields, only those we actually know. */
    private array $fields = [];

    private bool $isBot = false;

    private bool $claimsBrowser = false;

    /**
     * Private: always go through parse(), which memoises.
     */
    private function __construct(string $ua)
    {
        $this->raw = $ua;
        $this->analyse();
    }

    /**
     * Parse (and memoise) a User-Agent string.
     *
     * The cache is what makes UA parsing free on the ingest hot path: a busy site has maybe
     * a few thousand distinct UAs per day against millions of hits.
     *
     * It is a simple bounded cache: on overflow everything is dropped and it starts again,
     * rather than implementing an LRU. Refilling costs microseconds and the code stays
     * auditable.
     */
    public static function parse(string $ua): self
    {
        if (isset(self::$cache[$ua])) {
            return self::$cache[$ua];
        }
        $obj = new self($ua);
        if (count(self::$cache) >= self::CACHE_MAX) {
            self::$cache = [];
        }
        self::$cache[$ua] = $obj;
        return $obj;
    }

    /**
     * The Solr fields derived from this UA, using SPEC §4.1 names.
     *
     * Fields we cannot determine are ABSENT, not empty: an unrecognised UA must not become
     * `browser_s: ""`, which would silently create a huge fake facet bucket.
     *
     * `ua_bot_b` and `ai_crawler_b` ARE always present when a UA was logged, because with the
     * string in hand both are known facts rather than unknowns.
     *
     * @return array<string,mixed>
     */
    public function fields(): array
    {
        return $this->fields;
    }

    /**
     * Does this UA claim to be a real, interactive browser?
     *
     * Used by the `no_js_on_html` rule (SPEC §7, weight 70): "HTML 200 served, no beacon
     * ever, and UA claims a real browser". The rule must not fire for curl or for a
     * self-declared crawler, because those never claimed to run JavaScript in the first
     * place and holding it against them would flood the results with false positives.
     *
     * A UA claims to be a browser when it carries a real engine token (AppleWebKit, Gecko,
     * Trident, Presto) AND does not self-declare as a bot.
     */
    public function claimsBrowser(): bool
    {
        return $this->claimsBrowser;
    }

    /** Does this UA self-declare as a crawler, monitor, scanner or HTTP library? */
    public function isBot(): bool
    {
        return $this->isBot;
    }

    /** The original string, as logged. */
    public function raw(): string
    {
        return $this->raw;
    }

    /**
     * Run the whole classification once, at construction time.
     *
     * An empty User-Agent is a fact, not an unknown: it is a client that chose to send none.
     *
     * The browser family and version are worked out even for a declared bot, because many of
     * them advertise the Chrome build they embed, and knowing which one is useful when a
     * "Googlebot" turns out to be a spoof.
     */
    private function analyse(): void
    {
        $ua = $this->raw;

        if (trim($ua) === '') {
            $this->fields['device_s']     = 'unknown';
            $this->fields['ua_bot_b']     = false;
            $this->fields['ai_crawler_b'] = false;
            return;
        }

        $lower = strtolower($ua);

        foreach (self::BOTS as [$needle, $name, $cat, $ai]) {
            if (str_contains($lower, $needle)) {
                $this->isBot = true;
                $this->fields['ua_bot_b']      = true;
                $this->fields['ua_bot_name_s'] = $name;
                $this->fields['ua_bot_cat_s']  = $cat;
                $this->fields['ai_crawler_b']  = $ai;
                $this->fields['device_s']      = 'bot';
                break;
            }
        }
        if (!$this->isBot) {
            $this->fields['ua_bot_b']     = false;
            $this->fields['ai_crawler_b'] = false;
        }

        $browser = self::matchBrowser($ua);
        if ($browser !== null) {
            $this->fields['browser_s'] = $browser[0];
            if ($browser[1] !== null) {
                $this->fields['browser_ver_i'] = $browser[1];
            }
        }

        $os = self::matchOs($ua);
        if ($os !== null) {
            $this->fields['os_s'] = $os;
        }

        if (!$this->isBot) {
            $this->fields['device_s'] = self::matchDevice($ua);
        }

        $this->claimsBrowser = !$this->isBot && (bool) preg_match(
            '~AppleWebKit/|Gecko/|Trident/|Presto/|Gecko\)~i',
            $ua
        );
    }

    /**
     * Identify the browser family and major version.
     *
     * Order is the whole algorithm: Edge, Opera, Samsung Internet, Vivaldi and Yandex all
     * carry `Chrome/` in their UA, so each must be tested before Chrome or every one of them
     * would be reported as Chrome. Safari must come last because every WebKit browser on iOS
     * carries `Safari/`.
     *
     * The table maps a case-insensitive needle to a family and a version-capturing regex.
     * Safari is the exception to the pattern: it reports its marketing version in `Version/`
     * rather than in `Safari/`, and a bare `Safari/` with no `Version/` at all is usually an
     * embedded WebKit view rather than the browser.
     *
     * @return array{0:string,1:?int}|null [family, major version]
     */
    private static function matchBrowser(string $ua): ?array
    {
        static $table = [
            ['~Edg(?:e|A|iOS)?/([0-9]+)~i',        'Edge'],
            ['~OPR/([0-9]+)~i',                    'Opera'],
            ['~Opera[/ ]([0-9]+)~i',               'Opera'],
            ['~SamsungBrowser/([0-9]+)~i',         'Samsung Internet'],
            ['~Vivaldi/([0-9]+)~i',                'Vivaldi'],
            ['~YaBrowser/([0-9]+)~i',              'Yandex Browser'],
            ['~UCBrowser/([0-9]+)~i',              'UC Browser'],
            ['~DuckDuckGo/([0-9]+)~i',             'DuckDuckGo'],
            ['~Brave/([0-9]+)~i',                  'Brave'],
            ['~HeadlessChrome/([0-9]+)~i',         'HeadlessChrome'],
            ['~CriOS/([0-9]+)~i',                  'Chrome'],
            ['~Chromium/([0-9]+)~i',               'Chromium'],
            ['~Chrome/([0-9]+)~i',                 'Chrome'],
            ['~FxiOS/([0-9]+)~i',                  'Firefox'],
            ['~Firefox/([0-9]+)~i',                'Firefox'],
            ['~SeaMonkey/([0-9]+)~i',              'SeaMonkey'],
            ['~Version/([0-9]+)[.0-9]*\s+(?:Mobile/\S+\s+)?Safari/~i', 'Safari'],
            ['~MSIE ([0-9]+)~i',                   'Internet Explorer'],
            ['~Trident/.*rv:([0-9]+)~i',           'Internet Explorer'],
        ];

        foreach ($table as [$re, $family]) {
            if (preg_match($re, $ua, $m)) {
                return [$family, isset($m[1]) ? (int) $m[1] : null];
            }
        }
        if (preg_match('~Safari/~i', $ua) && preg_match('~AppleWebKit/~i', $ua)) {
            return ['Safari', null];
        }
        return null;
    }

    /**
     * Identify the operating system family.
     *
     * Coarse on purpose. "Windows 10/11" rather than a build number, "Linux" rather than a
     * distribution: those are the buckets a traffic report is actually read in, and the
     * finer detail in a UA is mostly fiction anyway (Chrome freezes its OS version). macOS is
     * the clearest case: Safari and Chrome both freeze it at 10_15_7, so no version number is
     * reported for it.
     */
    private static function matchOs(string $ua): ?string
    {
        if (preg_match('~Windows Phone~i', $ua)) {
            return 'Windows Phone';
        }
        if (preg_match('~Windows NT ([0-9.]+)~i', $ua, $m)) {
            return self::WINDOWS_NT[$m[1]] ?? 'Windows';
        }
        if (preg_match('~Windows~i', $ua)) {
            return 'Windows';
        }
        if (preg_match('~(?:iPhone|iPad|iPod).*?(?:CPU )?(?:iPhone )?OS ([0-9_]+)~i', $ua, $m)) {
            return 'iOS ' . str_replace('_', '.', explode('_', $m[1])[0]);
        }
        if (preg_match('~(iPhone|iPad|iPod)~i', $ua)) {
            return 'iOS';
        }
        if (preg_match('~Android[ /]?([0-9]+)~i', $ua, $m)) {
            return 'Android ' . $m[1];
        }
        if (preg_match('~Android~i', $ua)) {
            return 'Android';
        }
        if (preg_match('~CrOS~i', $ua)) {
            return 'ChromeOS';
        }
        if (preg_match('~Mac OS X ([0-9_]+)~i', $ua, $m)) {
            return 'macOS';
        }
        if (preg_match('~Macintosh|Mac OS~i', $ua)) {
            return 'macOS';
        }
        if (preg_match('~(FreeBSD|OpenBSD|NetBSD|DragonFly)~i', $ua, $m)) {
            return ucfirst(strtolower($m[1]));
        }
        if (preg_match('~Ubuntu~i', $ua)) {
            return 'Linux';
        }
        if (preg_match('~Linux|X11~i', $ua)) {
            return 'Linux';
        }
        return null;
    }

    /**
     * Classify the device: desktop | mobile | tablet | bot | unknown.
     *
     * Tablet is tested before mobile because an Android tablet is an Android UA WITHOUT the
     * `Mobile` token — that absence is the only thing distinguishing the two, and testing
     * mobile first would swallow every tablet.
     */
    private static function matchDevice(string $ua): string
    {
        if (preg_match('~iPad|Tablet|PlayBook|Kindle|Silk/|Nexus (?:7|9|10)~i', $ua)) {
            return 'tablet';
        }
        if (preg_match('~Android~i', $ua) && !preg_match('~Mobile~i', $ua)) {
            return 'tablet';
        }
        if (preg_match('~Mobi|iPhone|iPod|Windows Phone|BlackBerry|Opera Mini~i', $ua)) {
            return 'mobile';
        }
        if (preg_match('~Windows NT|Macintosh|X11|CrOS|Linux x86_64~i', $ua)) {
            return 'desktop';
        }
        return 'unknown';
    }

    /**
     * Drop the memo cache.
     *
     * Only needed by the test suite and by a long-running daemon that wants to reclaim the
     * memory after a traffic spike introduced thousands of one-off UAs.
     */
    public static function clearCache(): void
    {
        self::$cache = [];
    }
}
