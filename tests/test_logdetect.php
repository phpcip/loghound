<?php
/**
 * Loghound — tests for src/LogDetect.php.
 *
 * The important ones here are the DISCOVERY tests: they build a miniature but realistic
 * Apache and nginx configuration tree on disk — with Include directives, ${APACHE_LOG_DIR},
 * an envvars file, vhost blocks and a piped CustomLog — and assert that discovery returns
 * the exact log paths, the exact format strings and the right vhost for each. That is the
 * headline setup feature (SPEC §8 step 1) and it is deterministic, so it can be asserted
 * exactly rather than with a confidence value.
 *
 * No test here touches the network.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

use Loghound\LogDetect;
use Loghound\LogFormat;

return [

    'apache discovery reads LogFormat, CustomLog, Include and ${APACHE_LOG_DIR}' => function (): void {
        $root = lh_tmpdir('lh_apache');
        try {
            mkdir($root . '/sites-enabled', 0700, true);

            // Debian puts APACHE_LOG_DIR in envvars, not in any .conf — discovery has to
            // read the shell file or every path stays literally '${APACHE_LOG_DIR}/...'.
            file_put_contents($root . '/envvars', "export APACHE_LOG_DIR=/var/log/apache2\n");

            file_put_contents($root . '/apache2.conf', implode("\n", [
                '# a comment that must be ignored',
                'ServerRoot "' . $root . '"',
                'LogFormat "%h %l %u %t \\"%r\\" %>s %O \\"%{Referer}i\\" \\"%{User-Agent}i\\"" combined',
                'LogFormat "%h %l %u %t \\"%r\\" %>s %O" common',
                'CustomLog ${APACHE_LOG_DIR}/other_vhosts_access.log combined',
                'IncludeOptional sites-enabled/*.conf',
                '',
            ]));

            // A continuation line, because the LogFormat this project recommends uses them.
            file_put_contents($root . '/sites-enabled/000-site.conf', implode("\n", [
                '<VirtualHost *:443>',
                '    ServerName shop.example.com:443',
                // Trailing single backslash: an Apache line continuation, which is what the
                // LogFormat recommended in SPEC §8 uses and which discovery must join.
                '    LogFormat "%v:%p %h %l %u %t \\"%r\\" %>s %O %D \\',
                '\\"%{Referer}i\\" \\"%{User-Agent}i\\"" loghound',
                '    CustomLog ${APACHE_LOG_DIR}/shop_access.log loghound',
                '    ErrorLog ${APACHE_LOG_DIR}/shop_error.log',
                '</VirtualHost>',
                '<VirtualHost *:80>',
                '    ServerName plain.example.com',
                '    CustomLog "|/usr/bin/rotatelogs /var/log/apache2/piped.log 86400" combined',
                '    CustomLog ' . $root . '/relative_access.log common',
                '</VirtualHost>',
                '',
            ]));

            $found = LogDetect::discoverFromApacheConfig(
                [$root . '/apache2.conf'],
                [$root . '/sites-enabled'],
                ['allowed_config_roots' => [$root]]
            );

            lh_has_key($found, '/var/log/apache2/other_vhosts_access.log', 'discovery');
            lh_has_key($found, '/var/log/apache2/shop_access.log', 'discovery');
            lh_has_key($found, $root . '/relative_access.log', 'discovery');

            // A piped CustomLog has no file behind it and must be recognised and skipped.
            foreach (array_keys($found) as $path) {
                lh_false(str_contains($path, 'rotatelogs'), 'piped target must be skipped');
                lh_false(str_contains($path, 'piped.log'), 'piped target must be skipped');
            }
            // ErrorLog is not an access log.
            lh_no_key($found, '/var/log/apache2/shop_error.log', 'discovery');

            $shop = $found['/var/log/apache2/shop_access.log'];
            lh_same('loghound', $shop['format_name'], 'shop format name');
            lh_same('shop.example.com', $shop['vhost'], 'shop vhost');
            lh_contains($shop['format'], '%v:%p', 'shop format string');
            // The continuation line must have been joined, so the tail of the format is there.
            lh_contains($shop['format'], 'User-Agent', 'shop format string continuation');

            // And the discovered format string must actually compile into a working parser.
            $fmt = LogFormat::fromApache($shop['format'], 'loghound');
            $rec = $fmt->parse(
                'shop.example.com:443 203.0.113.9 - - [10/Sep/2026:09:57:08 +0000] '
                . '"GET / HTTP/1.1" 200 900 15321 "-" "Mozilla/5.0"'
            );
            lh_true(is_array($rec), 'parsed with the discovered format');
            lh_same('shop.example.com', $rec['vhost'], 'vhost');
            lh_same('15321', $rec['dur_us'], 'dur_us');
        } finally {
            lh_rmtree($root);
        }
    },

    'apache discovery resolves a built-in nickname the config never declares' => function (): void {
        $root = lh_tmpdir('lh_apache2');
        try {
            file_put_contents($root . '/httpd.conf', implode("\n", [
                'ServerRoot "' . $root . '"',
                'CustomLog /var/log/httpd/access_log combined',
                '',
            ]));

            $found = LogDetect::discoverFromApacheConfig(
                [$root . '/httpd.conf'],
                [],
                ['allowed_config_roots' => [$root]]
            );

            lh_has_key($found, '/var/log/httpd/access_log', 'discovery');
            // Apache ships `combined`; a config that just uses it must still resolve.
            lh_contains($found['/var/log/httpd/access_log']['format'], '%{User-Agent}i', 'format');
        } finally {
            lh_rmtree($root);
        }
    },

    'apache Include cannot escape the allowed config roots' => function (): void {
        $root    = lh_tmpdir('lh_inside');
        $outside = lh_tmpdir('lh_outside');
        try {
            // A hostile snippet outside the allowlist that would define an extra log.
            file_put_contents($outside . '/evil.conf', "CustomLog /var/log/evil.log combined\n");

            file_put_contents($root . '/apache2.conf', implode("\n", [
                'ServerRoot "' . $root . '"',
                'CustomLog /var/log/ok.log combined',
                'Include ' . $outside . '/*.conf',
                '',
            ]));

            $found = LogDetect::discoverFromApacheConfig(
                [$root . '/apache2.conf'],
                [],
                ['allowed_config_roots' => [$root]]
            );

            lh_has_key($found, '/var/log/ok.log', 'discovery');
            // safePath must have refused the include, so the evil log is not present.
            lh_no_key($found, '/var/log/evil.log', 'discovery');
        } finally {
            lh_rmtree($root);
            lh_rmtree($outside);
        }
    },

    'nginx discovery reads log_format, access_log, include and server_name' => function (): void {
        $root = lh_tmpdir('lh_nginx');
        try {
            mkdir($root . '/conf.d', 0700, true);

            file_put_contents($root . '/nginx.conf', <<<'CONF'
http {
    # a comment; must not break the tokenizer
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    log_format  jsonlog escape=json '{"t":"$time_iso8601","ip":"$remote_addr",'
                                    '"req":"$request","st":"$status"}';

    access_log  /var/log/nginx/access.log  main;

    include conf.d/*.conf;
}
CONF);

            file_put_contents($root . '/conf.d/site.conf', <<<'CONF'
server {
    listen 443 ssl;
    server_name  api.example.com www.api.example.com;
    access_log /var/log/nginx/api_access.log jsonlog buffer=32k flush=5s;
}
server {
    listen 80;
    server_name off.example.com;
    access_log off;
}
CONF);

            $found = LogDetect::discoverFromNginxConfig(
                [$root . '/nginx.conf'],
                [$root . '/conf.d'],
                ['allowed_config_roots' => [$root]]
            );

            lh_has_key($found, '/var/log/nginx/access.log', 'discovery');
            lh_has_key($found, '/var/log/nginx/api_access.log', 'discovery');

            $main = $found['/var/log/nginx/access.log'];
            lh_same('main', $main['format_name'], 'main format name');
            // The three quoted continuation strings must have been concatenated.
            lh_contains($main['format'], '$http_x_forwarded_for', 'main format joined');

            $api = $found['/var/log/nginx/api_access.log'];
            lh_same('jsonlog', $api['format_name'], 'api format name');
            lh_same('api.example.com', $api['vhost'], 'api vhost');

            // The main format must compile and parse a real nginx line.
            $fmt = LogFormat::fromNginx($main['format'], 'main');
            $rec = $fmt->parse(
                '203.0.113.9 - - [10/Sep/2026:09:57:08 +0000] "GET / HTTP/1.1" 200 512 '
                . '"-" "Mozilla/5.0" "198.51.100.7"'
            );
            lh_true(is_array($rec), 'parsed with the discovered nginx format');
            lh_same('198.51.100.7', $rec['header_in.x-forwarded-for'], 'XFF');

            // And the JSON one must compile into a JSON parser, not a regex.
            $jsonFmt = LogFormat::fromNginx($api['format'], 'jsonlog');
            lh_same(LogFormat::KIND_JSON, $jsonFmt->kind(), 'json kind');
            $jrec = $jsonFmt->parse('{"t":"2026-09-10T09:57:08+00:00","ip":"203.0.113.9","req":"GET / HTTP/1.1","st":"200"}');
            lh_same('203.0.113.9', $jrec['remote_addr'], 'json remote_addr');
        } finally {
            lh_rmtree($root);
        }
    },

    'the built-in library covers every format SPEC section 8 names' => function (): void {
        $lib = LogDetect::library();
        foreach ([
            'apache_combined', 'apache_vhost_combined', 'apache_common', 'apache_loghound',
            'nginx_combined', 'nginx_combined_xff', 'ingress_nginx',
            'caddy_json', 'traefik_json', 'haproxy_http', 'aws_alb', 'cloudfront',
        ] as $name) {
            lh_has_key($lib, $name, 'library');
            lh_true($lib[$name] instanceof LogFormat, $name . ' is a LogFormat');
        }
    },

    'detection picks vhost_combined over combined on a vhost line' => function (): void {
        $lines = [
            'shop.example.com 203.0.113.9 - - [10/Sep/2026:09:57:08 +0000] "GET /a HTTP/1.1" 200 12 "-" "Mozilla/5.0"',
            'shop.example.com 203.0.113.10 - - [10/Sep/2026:09:57:09 +0000] "GET /b HTTP/1.1" 200 34 "-" "Mozilla/5.0"',
        ];
        $ranked = LogDetect::detectFromSample($lines);

        lh_true($ranked !== [], 'candidates');
        lh_same('apache_vhost_combined', $ranked[0]['name'], 'winner');
        lh_true($ranked[0]['confidence'] > 90.0, 'confidence');
    },

    'detection recognises Caddy JSON natively' => function (): void {
        $line = json_encode([
            'level'   => 'info',
            'ts'      => 1789041428.123,
            'logger'  => 'http.log.access',
            'msg'     => 'handled request',
            'request' => [
                'remote_ip' => '203.0.113.9',
                'proto'     => 'HTTP/2.0',
                'method'    => 'GET',
                'host'      => 'example.com',
                'uri'       => '/a?b=1',
                'headers'   => [
                    'User-Agent' => ['Mozilla/5.0'],
                    'Referer'    => ['https://example.com/'],
                ],
                'tls'       => ['proto' => 'tls1.3', 'cipher_suite' => 'TLS_AES_128_GCM_SHA256'],
            ],
            'duration' => 0.0123,
            'size'     => 4096,
            'status'   => 200,
        ]);

        $ranked = LogDetect::detectFromSample([$line, $line, $line]);
        lh_same('caddy_json', $ranked[0]['name'], 'winner');
        lh_true($ranked[0]['confidence'] > 80.0, 'confidence');
    },

    'detection recognises an AWS ALB line' => function (): void {
        $line = 'https 2026-09-10T09:57:08.123456Z app/my-lb/50dc6c495c0c9188 203.0.113.9:41234 '
            . '10.0.1.7:80 0.001 0.002 0.000 200 200 336 1234 '
            . '"GET https://example.com:443/a HTTP/1.1" "Mozilla/5.0" '
            . 'ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 '
            . 'arn:aws:elasticloadbalancing:eu-west-1:1:targetgroup/x/y "Root=1-abc" "example.com" "arn" 0';

        $ranked = LogDetect::detectFromSample([$line, $line]);
        lh_same('aws_alb', $ranked[0]['name'], 'winner');
    },

    'detection recognises an HAProxy http-log line' => function (): void {
        $line = '203.0.113.9:56789 [10/Sep/2026:09:57:08.123] fe-https be-app/srv1 '
            . '0/0/1/2/3 200 1234 - - ---- 1/1/0/0/0 0/0 "GET /a HTTP/1.1"';

        $ranked = LogDetect::detectFromSample([$line, $line]);
        lh_same('haproxy_http', $ranked[0]['name'], 'winner');
    },

    'detection recognises Traefik JSON and ingress-nginx' => function (): void {
        $traefik = json_encode([
            'StartUTC'              => '2026-09-10T09:57:08.123Z',
            'ClientHost'            => '203.0.113.9',
            'RequestMethod'         => 'GET',
            'RequestPath'           => '/a?b=1',
            'RequestProtocol'       => 'HTTP/2.0',
            'RequestHost'           => 't.example',
            'OriginStatus'          => 500,
            'DownstreamStatus'      => 200,
            'DownstreamContentSize' => 4096,
            'Duration'              => 12345678,   // nanoseconds
            'request_User-Agent'    => 'Mozilla/5.0',
        ]);
        lh_same('traefik_json', LogDetect::detectFromSample([$traefik, $traefik])[0]['name'], 'traefik');

        $ingress = '203.0.113.9 - - [10/Sep/2026:09:57:08 +0000] "GET /a HTTP/1.1" 200 512 '
            . '"-" "Mozilla/5.0" 331 0.031 [default-svc-80] [] 10.1.2.3:8080 512 0.030 200 abc123def';
        lh_same('ingress_nginx', LogDetect::detectFromSample([$ingress, $ingress])[0]['name'], 'ingress');
    },

    'detection recognises a CloudFront W3C line and decodes its percent-encoding' => function (): void {
        $line = implode("\t", [
            '2026-09-10', '09:57:08', 'IAD79-C1', '1234', '203.0.113.9', 'GET',
            'd111.cloudfront.net', '/index.html', '200', 'https://ref.example/',
            'Mozilla%2F5.0%20(Windows)', 'a=1', '-', 'Hit', 'abc123',
            'example.com', 'https', '345', '0.031',
        ]);

        $ranked = LogDetect::detectFromSample([$line, $line]);
        lh_same('cloudfront', $ranked[0]['name'], 'winner');

        $rec = LogDetect::formatByName('cloudfront')->parse($line);
        // CloudFront percent-encodes the UA in its log; it must be decoded at parse time.
        lh_same('Mozilla/5.0 (Windows)', $rec['header_in.user-agent'], 'user-agent');
        // cs(Host) is the distribution domain; x-host-header is the site the viewer asked for.
        lh_same('d111.cloudfront.net', $rec['cdn_host'], 'cdn_host');
        lh_same('example.com', $rec['vhost'], 'vhost');
    },

    'detection returns nothing for input that is not a log at all' => function (): void {
        $ranked = LogDetect::detectFromSample([
            'the quick brown fox',
            'jumps over the lazy dog',
            '{{not json either',
        ]);
        // Either no candidate, or one so weak nobody would confirm it.
        if ($ranked !== []) {
            lh_true($ranked[0]['confidence'] < 60.0, 'confidence on garbage');
        }
    },

    'detection ignores blank lines and W3C # headers' => function (): void {
        $lines = [
            '#Version: 1.0',
            '#Fields: date time x-edge-location',
            '',
            '203.0.113.9 - - [10/Sep/2026:09:57:08 +0000] "GET /a HTTP/1.1" 200 12 "-" "Mozilla/5.0"',
        ];
        $ranked = LogDetect::detectFromSample($lines);
        lh_same('apache_combined', $ranked[0]['name'], 'winner');
        lh_same(1, $ranked[0]['total'], 'only the real line was counted');
        lh_same(100.0, $ranked[0]['confidence'], 'confidence');
    },

    'proposeRegex generates a pattern that parses its own sample' => function (): void {
        // A deliberately unknown shape: combined with two extra bare columns on the end.
        $lines = [
            '203.0.113.9 - - [10/Sep/2026:09:57:08 +0000] "GET /a HTTP/1.1" 200 12 "-" "Mozilla/5.0" 331 0.031',
            '203.0.113.10 - - [10/Sep/2026:09:57:09 +0000] "GET /b HTTP/1.1" 404 0 "-" "curl/8.4" 210 0.004',
        ];

        $pattern = LogDetect::proposeRegex($lines);
        lh_true(is_string($pattern), 'a pattern was proposed');

        $fmt = LogDetect::formatFromRegex((string) $pattern, 'proposed');
        lh_true($fmt instanceof LogFormat, 'the proposal compiles');

        foreach ($lines as $line) {
            $rec = $fmt->parse($line);
            lh_true(is_array($rec), 'proposed pattern parses its own sample');
            lh_has_key($rec, 'remote_addr', 'proposed record');
            lh_has_key($rec, 'status', 'proposed record');
            lh_has_key($rec, 'header_in.user-agent', 'proposed record');
        }
        lh_same('203.0.113.9', $fmt->parse($lines[0])['remote_addr'], 'remote_addr');
        lh_same('404', $fmt->parse($lines[1])['status'], 'status');
    },

    'proposeRegex declines when the sample has no agreed shape' => function (): void {
        $lines = [
            'a b c',
            '"one" [two] three four five six seven',
            '{"json":true}',
            'x',
        ];
        lh_same(null, LogDetect::proposeRegex($lines), 'no consensus shape');
        lh_same(null, LogDetect::proposeRegex([]), 'empty sample');
    },

    'tailLines reads the last N lines and honours the allowed roots' => function (): void {
        $dir = lh_tmpdir('lh_tail');
        try {
            $path = $dir . '/access.log';
            $lines = [];
            for ($i = 1; $i <= 500; $i++) {
                $lines[] = 'line ' . $i;
            }
            file_put_contents($path, implode("\n", $lines) . "\n");

            $tail = LogDetect::tailLines($path, 5, [$dir]);
            lh_same(5, count($tail), 'tail count');
            lh_same('line 496', $tail[0], 'first of tail');
            lh_same('line 500', $tail[4], 'last of tail');

            // Outside the allowlist: refused, not read.
            lh_same([], LogDetect::tailLines($path, 5, ['/nonexistent-root']), 'outside root');
        } finally {
            lh_rmtree($dir);
        }
    },
];
