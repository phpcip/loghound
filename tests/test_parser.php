<?php
/**
 * Loghound — tests for src/Parser.php.
 *
 * The behaviours asserted here are the ones SPEC §1 and §4.1 make non-negotiable:
 * exact field names, absent-means-absent, UTC timestamps, and a fingerprint that is
 * independent of the client address.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

use Loghound\LogDetect;
use Loghound\LogFormat;
use Loghound\Parser;

/**
 * Build a combined-format hit document from one line, with a fixed source and offset.
 *
 * @param array<string,mixed> $opts Parser options.
 * @return array<string,mixed>|null
 */
function lh_hit(string $line, array $opts = [], int $offset = 0): ?array
{
    $fmt = LogDetect::formatByName('apache_combined');
    $parser = new Parser($opts + ['keep_raw' => false, 'host' => 'example.com']);
    return $parser->parseLine($fmt, $line, '/var/log/apache2/access.log', $offset);
}

return [

    'a combined line becomes a complete hit document' => function (): void {
        $line = '203.0.113.9 - - [10/Sep/2026:09:57:08 +0000] "GET /docs/install?x=1 HTTP/1.1" '
            . '200 15234 "https://www.google.com/" '
            . '"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
            . '(KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"';

        $hit = lh_hit($line);
        lh_true(is_array($hit), 'hit');

        lh_same(sha1('/var/log/apache2/access.log:0'), $hit['id'], 'id');
        lh_same('/var/log/apache2/access.log', $hit['src_s'], 'src_s');
        lh_same('2026-09-10T09:57:08.000Z', $hit['ts'], 'ts');
        lh_same('203.0.113.9', $hit['ip_s'], 'ip_s');
        lh_same(4, $hit['ip_ver_i'], 'ip_ver_i');
        lh_same('203.0.113.0/24', $hit['ip_net_s'], 'ip_net_s');
        lh_same('GET', $hit['method_s'], 'method_s');
        lh_same('/docs/install', $hit['path_s'], 'path_s');
        lh_same('x=1', $hit['query_s'], 'query_s');
        lh_same('HTTP/1.1', $hit['proto_s'], 'proto_s');
        lh_same(200, $hit['status_i'], 'status_i');
        lh_same(15234, $hit['bytes_l'], 'bytes_l');
        lh_same(2, $hit['path_depth_i'], 'path_depth_i');
        lh_same('html', $hit['kind_s'], 'kind_s');
        lh_same('example.com', $hit['host_s'], 'host_s');
        lh_same('www.google.com', $hit['referer_host_s'], 'referer_host_s');
        lh_same('search', $hit['referer_type_s'], 'referer_type_s');
        lh_same('Chrome', $hit['browser_s'], 'browser_s');
        lh_same(152, $hit['browser_ver_i'], 'browser_ver_i');
        lh_same('macOS', $hit['os_s'], 'os_s');
        lh_same('desktop', $hit['device_s'], 'device_s');
        lh_same(false, $hit['ua_bot_b'], 'ua_bot_b');
        lh_same(40, strlen($hit['ua_hash_s']), 'ua_hash_s is a sha1');
        lh_same(40, strlen($hit['fp_hash_s']), 'fp_hash_s is a sha1');
    },

    'headers the format does not log are ABSENT, never empty or zero' => function (): void {
        $line = '203.0.113.9 - - [10/Sep/2026:09:57:08 +0000] "GET / HTTP/1.1" 200 12 "-" "curl/8.4.0"';
        $hit  = lh_hit($line);

        // `combined` carries no Accept, no client hints, no timing, no TLS details.
        foreach ([
            'accept_s', 'accept_lang_s', 'accept_enc_s',
            'sec_ch_ua_s', 'sec_ch_platform_s', 'sec_ch_mobile_b',
            'sec_fetch_site_s', 'sec_fetch_mode_s', 'sec_fetch_dest_s', 'sec_fetch_user_s',
            'xff_s', 'tls_proto_s', 'tls_cipher_s', 'ja4_s',
            'dur_us_l', 'asset_kind_s',
        ] as $field) {
            lh_no_key($hit, $field, 'hit');
        }

        // Apache's "-" for an unsent Referer must not survive as the literal string "-".
        lh_no_key($hit, 'referer_s', 'hit');
        lh_no_key($hit, 'referer_host_s', 'hit');
        // ...but referer_type_s IS derivable, because the header WAS logged and was empty.
        lh_same('direct', $hit['referer_type_s'], 'referer_type_s');
    },

    'timestamps normalise to UTC from every shape' => function (): void {
        // Apache/nginx bracketed local time with an offset: must be shifted to UTC.
        lh_same(
            '2026-09-10T07:57:08.000Z',
            Parser::parseTimestamp('[10/Sep/2026:09:57:08 +0200]')->format('Y-m-d\TH:i:s.v\Z'),
            'apache +0200'
        );
        lh_same(
            '2026-09-10T14:57:08.000Z',
            Parser::parseTimestamp('10/Sep/2026:09:57:08 -0500')->format('Y-m-d\TH:i:s.v\Z'),
            'nginx -0500'
        );
        // HAProxy: milliseconds, no offset at all.
        lh_same(
            '2026-09-10T09:57:08.123Z',
            Parser::parseTimestamp('10/Sep/2026:09:57:08.123')->format('Y-m-d\TH:i:s.v\Z'),
            'haproxy ms'
        );
        // ISO-8601 with an offset, and the same instant naive (which must mean UTC).
        lh_same(
            '2026-09-10T09:57:08.000Z',
            Parser::parseTimestamp('2026-09-10T11:57:08+02:00')->format('Y-m-d\TH:i:s.v\Z'),
            'iso offset'
        );
        lh_same(
            '2026-09-10T09:57:08.000Z',
            Parser::parseTimestamp('2026-09-10 09:57:08')->format('Y-m-d\TH:i:s.v\Z'),
            'naive iso is UTC'
        );
        // Epoch seconds (Caddy logs a float), milliseconds and microseconds.
        lh_same(
            '2026-09-10T09:57:08.000Z',
            Parser::parseTimestamp('1789034228')->format('Y-m-d\TH:i:s.v\Z'),
            'epoch seconds'
        );
        lh_same(
            '2026-09-10T09:57:08.250Z',
            Parser::parseTimestamp('1789034228.25')->format('Y-m-d\TH:i:s.v\Z'),
            'epoch float seconds'
        );
        lh_same(
            '2026-09-10T09:57:08.250Z',
            Parser::parseTimestamp('1789034228250')->format('Y-m-d\TH:i:s.v\Z'),
            'epoch milliseconds'
        );

        lh_same(null, Parser::parseTimestamp('not a time'), 'garbage');
        lh_same(null, Parser::parseTimestamp('-'), 'dash');
    },

    'epochMs round-trips the ts field' => function (): void {
        $hit = lh_hit('203.0.113.9 - - [10/Sep/2026:09:57:08 +0000] "GET / HTTP/1.1" 200 1 "-" "x"');
        lh_same(1789034228000, Parser::epochMs($hit['ts']), 'epochMs');
    },

    'kind_s and asset_kind_s classify the whole table' => function (): void {
        $cases = [
            '/'                                  => ['html', null],
            '/docs/install'                      => ['html', null],
            '/index.php'                         => ['html', null],
            '/app.js'                            => ['asset', 'js'],
            '/a/b/theme.min.css'                 => ['asset', 'css'],
            '/img/logo.webp'                     => ['asset', 'img'],
            '/fonts/inter.woff2'                 => ['asset', 'font'],
            '/media/clip.mp4'                    => ['asset', 'media'],
            '/api/v1/things'                     => ['api', null],
            '/wp-json/wp/v2/posts'               => ['api', null],
            '/data.json'                         => ['api', null],
            '/robots.txt'                        => ['robots', null],
            '/sitemap.xml'                       => ['robots', null],
            '/.well-known/acme-challenge/abc'    => ['robots', null],
            '/favicon.ico'                       => ['favicon', null],
            '/apple-touch-icon-180x180.png'      => ['favicon', null],
            '/downloads/report.pdf'              => ['other', null],
            '/collect.php'                       => ['beacon', null],
        ];

        foreach ($cases as $path => [$kind, $assetKind]) {
            $line = '203.0.113.9 - - [10/Sep/2026:09:57:08 +0000] "GET ' . $path
                . ' HTTP/1.1" 200 12 "-" "Mozilla/5.0"';
            $hit = lh_hit($line);
            lh_same($kind, $hit['kind_s'], "kind_s for $path");
            if ($assetKind === null) {
                lh_no_key($hit, 'asset_kind_s', "asset_kind_s for $path");
            } else {
                lh_same($assetKind, $hit['asset_kind_s'], "asset_kind_s for $path");
            }
        }
    },

    'referer_type_s distinguishes ad, ai, search, social, internal and link' => function (): void {
        $cases = [
            // [referer, request target, expected type]
            ['https://www.google.com/',              '/a',              'search'],
            ['https://duckduckgo.com/?q=x',          '/a',              'search'],
            ['https://chatgpt.com/c/1',              '/a',              'ai'],
            ['https://www.perplexity.ai/search',     '/a',              'ai'],
            ['https://t.co/abc',                     '/a',              'social'],
            ['https://www.reddit.com/r/php',         '/a',              'social'],
            ['https://example.com/other',            '/a',              'internal'],
            ['https://news.ycombinator.com/item',    '/a',              'link'],
            // A paid Google click has a search referer AND a click id — it is an ad, not SEO.
            ['https://www.google.com/',              '/a?gclid=abc123', 'ad'],
            ['https://www.bing.com/',                '/a?utm_medium=cpc', 'ad'],
            ['-',                                    '/a',              'direct'],
        ];

        foreach ($cases as [$referer, $target, $expected]) {
            $line = '203.0.113.9 - - [10/Sep/2026:09:57:08 +0000] "GET ' . $target
                . ' HTTP/1.1" 200 12 "' . $referer . '" "Mozilla/5.0"';
            $hit = lh_hit($line);
            lh_same($expected, $hit['referer_type_s'], "referer_type_s for $referer $target");
        }
    },

    'fp_hash_s is independent of the IP address' => function (): void {
        // The single most important property in the product: two different addresses sending
        // byte-identical headers must land on the SAME fingerprint (SPEC §4.1).
        $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
            . 'Chrome/147.0.0.0 Safari/537.36';

        $a = lh_hit('198.51.100.1 - - [10/Sep/2026:09:57:08 +0000] "GET /a HTTP/1.1" 200 1 "-" "' . $ua . '"');
        $b = lh_hit('203.0.113.77 - - [10/Sep/2026:10:11:12 +0000] "GET /b HTTP/1.1" 404 9 "-" "' . $ua . '"');

        lh_same($a['fp_hash_s'], $b['fp_hash_s'], 'fp_hash_s across different IPs');
        // And a different UA must NOT collide.
        $c = lh_hit('198.51.100.1 - - [10/Sep/2026:09:57:08 +0000] "GET /a HTTP/1.1" 200 1 "-" "curl/8.4.0"');
        lh_true($a['fp_hash_s'] !== $c['fp_hash_s'], 'different UA gives a different fingerprint');
    },

    'fp_hash_s uses the full header tuple when the format logs it' => function (): void {
        $fmt = LogFormat::fromApache(
            '%h %t "%r" %>s %b "%{User-Agent}i" "%{Accept}i" "%{Accept-Language}i" '
            . '"%{Sec-CH-UA-Platform}i" "%{Sec-Fetch-Dest}i"'
        );
        $parser = new Parser(['keep_raw' => false]);

        $base = '203.0.113.9 [10/Sep/2026:09:57:08 +0000] "GET / HTTP/1.1" 200 1 "Mozilla/5.0" '
            . '"text/html" "%s" "\\"macOS\\"" "document"';

        $en = $parser->normalize($fmt->parse(sprintf($base, 'en-US')), 'x', 0);
        $de = $parser->normalize($fmt->parse(sprintf($base, 'de-DE')), 'x', 1);

        lh_same('en-US', $en['accept_lang_s'], 'accept_lang_s');
        lh_same('macOS', $en['sec_ch_platform_s'], 'sec_ch_platform_s (quotes stripped)');
        lh_same('document', $en['sec_fetch_dest_s'], 'sec_fetch_dest_s');
        // Changing one component of the tuple must change the fingerprint.
        lh_true($en['fp_hash_s'] !== $de['fp_hash_s'], 'Accept-Language is part of the tuple');
    },

    'fp_hash_s is absent when the format logs no headers at all' => function (): void {
        // Common Log Format. A constant fingerprint across every hit would be worse than
        // none: it would make the whole site look like one giant proxy fleet.
        $fmt = LogDetect::formatByName('apache_common');
        $parser = new Parser(['keep_raw' => false]);
        $hit = $parser->parseLine(
            $fmt,
            '203.0.113.9 - - [10/Sep/2026:09:57:08 +0000] "GET / HTTP/1.1" 200 12',
            'x',
            0
        );
        lh_true(is_array($hit), 'hit');
        lh_no_key($hit, 'fp_hash_s', 'hit');
    },

    'status "-" is absent while bytes "-" is a real zero' => function (): void {
        $line = '203.0.113.9 - - [10/Sep/2026:09:57:08 +0000] "GET / HTTP/1.1" 200 - "-" "x"';
        $hit  = lh_hit($line);
        lh_same(0, $hit['bytes_l'], 'bytes_l');

        $fmt = LogFormat::fromApache('%h %t "%r" %>s %b');
        $parser = new Parser(['keep_raw' => false]);
        $hit2 = $parser->parseLine(
            $fmt,
            '203.0.113.9 [10/Sep/2026:09:57:08 +0000] "GET / HTTP/1.1" - -',
            'x',
            0
        );
        // Apache logs '-' for the status when the connection died before one was chosen.
        // That is genuinely unknown, so the field must not become 0.
        lh_no_key($hit2, 'status_i', 'hit');
        lh_same(0, $hit2['bytes_l'], 'bytes_l');
    },

    'duration is converted to microseconds from %D, %T and %{ms}T' => function (): void {
        $parser = new Parser(['keep_raw' => false]);

        $us = LogFormat::fromApache('%h %t "%r" %>s %b %D');
        $hit = $parser->parseLine($us, '203.0.113.9 [10/Sep/2026:09:57:08 +0000] "GET / HTTP/1.1" 200 1 15321', 'x', 0);
        lh_same(15321, $hit['dur_us_l'], 'from %D');

        $sec = LogFormat::fromApache('%h %t "%r" %>s %b %T');
        $hit = $parser->parseLine($sec, '203.0.113.9 [10/Sep/2026:09:57:08 +0000] "GET / HTTP/1.1" 200 1 2', 'x', 0);
        lh_same(2000000, $hit['dur_us_l'], 'from %T');

        $ms = LogFormat::fromApache('%h %t "%r" %>s %b %{ms}T');
        $hit = $parser->parseLine($ms, '203.0.113.9 [10/Sep/2026:09:57:08 +0000] "GET / HTTP/1.1" 200 1 31', 'x', 0);
        lh_same(31000, $hit['dur_us_l'], 'from %{ms}T');
    },

    'an absolute-URI request target is decomposed' => function (): void {
        // What AWS ALB always logs, and what a proxy request looks like.
        $line = '203.0.113.9 - - [10/Sep/2026:09:57:08 +0000] '
            . '"GET http://shop.example.net:80/cart?id=7 HTTP/1.1" 200 12 "-" "Mozilla/5.0"';
        $fmt = LogDetect::formatByName('apache_combined');
        $parser = new Parser(['keep_raw' => false]);   // no host override: take it from the URI
        $hit = $parser->parseLine($fmt, $line, 'x', 0);

        lh_same('/cart', $hit['path_s'], 'path_s');
        lh_same('id=7', $hit['query_s'], 'query_s');
        lh_same('shop.example.net', $hit['host_s'], 'host_s');
    },

    'the LogFormat SPEC section 8 recommends fills every field it promises' => function (): void {
        // This is the block docs/INSTALL.md tells operators to paste. If it ever stops
        // producing the client hints and Sec-Fetch fields, the detection quality ceiling
        // drops silently and nothing else would notice.
        $fmt    = LogDetect::formatByName('apache_loghound');
        $parser = new Parser(['keep_raw' => false]);

        $line = 'opensolr.com:443 203.0.113.9 - - [10/Sep/2026:09:57:08 +0000] '
            . '"GET /docs?a=1 HTTP/2" 200 15234 31337 "https://www.google.com/" '
            . '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
            . 'Chrome/152.0.0.0 Safari/537.36" "text/html,*/*" "en-US,en;q=0.9" "gzip, br" '
            . '"\\"Chromium\\";v=\\"152\\"" "\\"Windows\\"" "?0" '
            . '"none" "navigate" "document" "?1" "-" "HTTP/2" "TLSv1.3" "TLS_AES_128_GCM_SHA256"';

        $hit = $parser->parseLine($fmt, $line, '/var/log/apache2/access.log', 0);
        lh_true(is_array($hit), 'hit');

        lh_same('opensolr.com', $hit['host_s'], 'host_s');
        lh_same('/docs', $hit['path_s'], 'path_s');
        lh_same('HTTP/2', $hit['proto_s'], 'proto_s');
        lh_same(31337, $hit['dur_us_l'], 'dur_us_l');
        lh_same('text/html,*/*', $hit['accept_s'], 'accept_s');
        lh_same('en-US,en;q=0.9', $hit['accept_lang_s'], 'accept_lang_s');
        lh_same('gzip, br', $hit['accept_enc_s'], 'accept_enc_s');
        lh_same('"Chromium";v="152"', $hit['sec_ch_ua_s'], 'sec_ch_ua_s');
        lh_same('Windows', $hit['sec_ch_platform_s'], 'sec_ch_platform_s');
        lh_same(false, $hit['sec_ch_mobile_b'], 'sec_ch_mobile_b');
        lh_same('none', $hit['sec_fetch_site_s'], 'sec_fetch_site_s');
        lh_same('navigate', $hit['sec_fetch_mode_s'], 'sec_fetch_mode_s');
        lh_same('document', $hit['sec_fetch_dest_s'], 'sec_fetch_dest_s');
        lh_same('?1', $hit['sec_fetch_user_s'], 'sec_fetch_user_s');
        lh_same('TLSv1.3', $hit['tls_proto_s'], 'tls_proto_s');
        lh_same('TLS_AES_128_GCM_SHA256', $hit['tls_cipher_s'], 'tls_cipher_s');
        lh_same('search', $hit['referer_type_s'], 'referer_type_s');
        // X-Forwarded-For was logged as "-" — that is absent, not an empty string.
        lh_no_key($hit, 'xff_s', 'hit');
    },

    'privacy modes transform ip_s while ip_net_s stays the cluster key' => function (): void {
        $line = '203.0.113.77 - - [10/Sep/2026:09:57:08 +0000] "GET / HTTP/1.1" 200 1 "-" "x"';

        $full = lh_hit($line, ['ip_mode' => 'full']);
        lh_same('203.0.113.77', $full['ip_s'], 'full mode');

        $trunc = lh_hit($line, ['ip_mode' => 'truncate']);
        lh_same('203.0.113.0/24', $trunc['ip_s'], 'truncate mode');

        $hash = lh_hit($line, ['ip_mode' => 'hash', 'ip_salt' => str_repeat('s', 32)]);
        lh_same(24, strlen($hash['ip_s']), 'hash mode length');
        lh_true($hash['ip_s'] !== '203.0.113.77', 'hash mode does not store the address');

        // ip_net_s is derived from the true address in every mode — it is the clustering key.
        foreach ([$full, $trunc, $hash] as $hit) {
            lh_same('203.0.113.0/24', $hit['ip_net_s'], 'ip_net_s');
        }
    },

    'IPv6 is reduced to a /48 network' => function (): void {
        $line = '2a01:4f8:c17:2b::1 - - [10/Sep/2026:09:57:08 +0000] "GET / HTTP/1.1" 200 1 "-" "x"';
        $hit  = lh_hit($line);
        lh_same(6, $hit['ip_ver_i'], 'ip_ver_i');
        lh_same('2a01:4f8:c17::/48', $hit['ip_net_s'], 'ip_net_s');
    },

    'a hostile line never crashes and never yields a partial document' => function (): void {
        $fmt = LogDetect::formatByName('apache_combined');
        $parser = new Parser(['keep_raw' => true]);

        $hostile = [
            // Path made entirely of control characters.
            "203.0.113.9 - - [10/Sep/2026:09:57:08 +0000] \"GET \x01\x02\x03 HTTP/1.1\" 200 1 \"-\" \"x\"",
            // Invalid UTF-8 in the User-Agent.
            "203.0.113.9 - - [10/Sep/2026:09:57:08 +0000] \"GET /a HTTP/1.1\" 200 1 \"-\" \"\xff\xfe\xfd\"",
            // A 100 KB path.
            '203.0.113.9 - - [10/Sep/2026:09:57:08 +0000] "GET /' . str_repeat('A', 100000)
                . ' HTTP/1.1" 200 1 "-" "x"',
            // A request line that is not a request line at all (a TLS ClientHello on :80).
            "203.0.113.9 - - [10/Sep/2026:09:57:08 +0000] \"\\x16\\x03\\x01\" 400 0 \"-\" \"-\"",
        ];

        foreach ($hostile as $i => $line) {
            $hit = $parser->parseLine($fmt, $line, 'x', $i);
            if ($hit === null) {
                continue;   // counted as a parse error, which is a legitimate outcome
            }
            // Whatever survived must be a COMPLETE document: id, ts and path are the three
            // fields nothing downstream can work without.
            lh_has_key($hit, 'id', "hit $i");
            lh_has_key($hit, 'ts', "hit $i");
            lh_has_key($hit, 'path_s', "hit $i");
            // And every string field must be valid UTF-8, or the Solr update would fail.
            foreach ($hit as $k => $v) {
                if (is_string($v)) {
                    lh_true(mb_check_encoding($v, 'UTF-8'), "field $k of hit $i is valid UTF-8");
                    lh_true(strlen($v) <= 8192, "field $k of hit $i is length-capped");
                }
            }
        }
    },

    'unparseable lines are counted, not silently dropped' => function (): void {
        $fmt = LogDetect::formatByName('apache_combined');
        $parser = new Parser();

        lh_same(0, $parser->errors(), 'initial error count');
        $parser->parseLine($fmt, 'not a log line at all', 'x', 0);
        $parser->parseLine($fmt, '', 'x', 1);
        lh_same(2, $parser->errors(), 'error count');
        lh_true(is_string($parser->lastError()), 'lastError');

        $parser->resetErrors();
        lh_same(0, $parser->errors(), 'after reset');
    },

    'keep_raw stores the original line and can be switched off' => function (): void {
        $line = '203.0.113.9 - - [10/Sep/2026:09:57:08 +0000] "GET / HTTP/1.1" 200 1 "-" "x"';

        $with = lh_hit($line, ['keep_raw' => true]);
        lh_same($line, $with['raw_s'], 'raw_s');

        $without = lh_hit($line, ['keep_raw' => false]);
        lh_no_key($without, 'raw_s', 'hit');
    },

    'sanitizeText drops empties, dashes and control characters' => function (): void {
        lh_same(null, Parser::sanitizeText(null), 'null');
        lh_same(null, Parser::sanitizeText(''), 'empty');
        lh_same(null, Parser::sanitizeText('-'), 'dash');
        lh_same(null, Parser::sanitizeText("\x00\x01\x02"), 'controls only');
        lh_same('ab', Parser::sanitizeText("a\x00b"), 'embedded control');
        lh_same('abc', Parser::sanitizeText('abcdef', 3), 'length cap');
        lh_true(mb_check_encoding((string) Parser::sanitizeText("v\xff\xfealid"), 'UTF-8'), 'utf8 repair');
    },
];
