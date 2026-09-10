<?php
/**
 * Loghound — tests for src/LogFormat.php.
 *
 * These prove the compiler handles the things that actually break log parsers in the field:
 * escaped quotes inside a quoted field, Apache's \xNN control-character escaping, adjacent
 * directives with no separator (%U%q), the vhost:port prefix, custom strftime timestamps,
 * and JSON logs that must not be forced through a regex.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

use Loghound\LogFormat;

return [

    'apache combined compiles and parses a plain line' => function (): void {
        $fmt = LogFormat::fromApache('%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"');

        $line = '203.0.113.9 - - [10/Sep/2026:09:57:08 +0000] "GET /a/b HTTP/1.1" 200 1234 '
            . '"https://example.com/" "Mozilla/5.0"';
        $rec = $fmt->parse($line);

        lh_true(is_array($rec), 'record');
        lh_same('203.0.113.9', $rec['remote_addr'], 'remote_addr');
        lh_same('[10/Sep/2026:09:57:08 +0000]', $rec['time'], 'time');
        lh_same('GET /a/b HTTP/1.1', $rec['request'], 'request');
        lh_same('200', $rec['status'], 'status');
        lh_same('1234', $rec['bytes'], 'bytes');
        lh_same('https://example.com/', $rec['header_in.referer'], 'referer');
        lh_same('Mozilla/5.0', $rec['header_in.user-agent'], 'user-agent');
    },

    'the config-quoted form is unwrapped exactly once' => function (): void {
        // As it appears in httpd.conf: outer quotes plus \" around each quoted field.
        $fmt = LogFormat::fromApache('"%h %l %u %t \"%r\" %>s %b"');
        $rec = $fmt->parse('203.0.113.9 - - [10/Sep/2026:09:57:08 +0000] "GET / HTTP/1.1" 200 12');

        lh_true(is_array($rec), 'record');
        lh_same('GET / HTTP/1.1', $rec['request'], 'request');
    },

    'a quoted field containing an escaped quote is captured whole' => function (): void {
        $fmt = LogFormat::fromApache('%h %t "%r" %>s %b "%{User-Agent}i"');

        // A real referer-spam UA: the client sent a literal double quote, Apache wrote \".
        $line = '203.0.113.9 [10/Sep/2026:09:57:08 +0000] "GET /x HTTP/1.1" 200 5 '
            . '"Mozilla/5.0 \"evil\" Safari"';
        $rec = $fmt->parse($line);

        lh_true(is_array($rec), 'record');
        // The field must not have been cut short at the inner quote, and the escaping must
        // have been undone so the stored value is what the client actually sent.
        lh_same('Mozilla/5.0 "evil" Safari', $rec['header_in.user-agent'], 'user-agent');
    },

    'apache \\xNN control escaping is decoded' => function (): void {
        $fmt = LogFormat::fromApache('%h %t "%r" %>s %b');

        // Apache writes a raw newline in a request line as \x0a.
        $rec = $fmt->parse('203.0.113.9 [10/Sep/2026:09:57:08 +0000] "GET /a\\x0ab HTTP/1.1" 400 0');

        lh_true(is_array($rec), 'record');
        lh_same("GET /a\nb HTTP/1.1", $rec['request'], 'request');
    },

    'a backslash that is not an escape survives untouched' => function (): void {
        $fmt = LogFormat::fromApache('%h %t "%r" %>s %b');
        // \\ is a literal backslash; it must decode to one backslash, not vanish.
        $rec = $fmt->parse('203.0.113.9 [10/Sep/2026:09:57:08 +0000] "GET /a\\\\b HTTP/1.1" 200 1');

        lh_true(is_array($rec), 'record');
        lh_same('GET /a\\b HTTP/1.1', $rec['request'], 'request');
    },

    'vhost:port prefix splits deterministically' => function (): void {
        $fmt = LogFormat::fromApache('%v:%p %h %l %u %t "%r" %>s %O %D');

        $line = 'shop.example.com:443 203.0.113.9 - - [10/Sep/2026:09:57:08 +0000] '
            . '"GET /cart?id=7:8 HTTP/1.1" 200 900 15321';
        $rec = $fmt->parse($line);

        lh_true(is_array($rec), 'record');
        // The colon inside the query must not confuse the vhost/port split.
        lh_same('shop.example.com', $rec['vhost'], 'vhost');
        lh_same('443', $rec['port'], 'port');
        lh_same('15321', $rec['dur_us'], 'dur_us');
    },

    'adjacent %U%q splits path from query' => function (): void {
        $fmt = LogFormat::fromApache('%h %t %m %U%q %H %>s');

        $rec = $fmt->parse('203.0.113.9 [10/Sep/2026:09:57:08 +0000] GET /search?q=a+b HTTP/1.1 200');

        lh_true(is_array($rec), 'record');
        lh_same('/search', $rec['uri'], 'uri');
        lh_same('?q=a+b', $rec['query'], 'query');
        lh_same('HTTP/1.1', $rec['proto'], 'proto');
    },

    'an empty %q is allowed' => function (): void {
        $fmt = LogFormat::fromApache('%h %t %m %U%q %H %>s');
        $rec = $fmt->parse('203.0.113.9 [10/Sep/2026:09:57:08 +0000] GET /plain HTTP/1.1 200');

        lh_true(is_array($rec), 'record');
        lh_same('/plain', $rec['uri'], 'uri');
        lh_same('', $rec['query'], 'query');
    },

    'the %{format}t strftime variant compiles and reports its parse format' => function (): void {
        $fmt = LogFormat::fromApache('%h %{%Y-%m-%d %H:%M:%S}t "%r" %>s %b');

        lh_same('Y-m-d H:i:s', $fmt->timeFormat(), 'timeFormat');

        $rec = $fmt->parse('203.0.113.9 2026-09-10 09:57:08 "GET / HTTP/1.1" 200 12');
        lh_true(is_array($rec), 'record');
        lh_same('2026-09-10 09:57:08', $rec['time'], 'time');
    },

    'the header directives i / o / e / x are namespaced apart' => function (): void {
        $fmt = LogFormat::fromApache(
            '%h "%{Accept}i" "%{Content-Type}o" "%{SSL_PROTOCOL}x" "%{HTTPS}e"'
        );
        $rec = $fmt->parse('203.0.113.9 "text/html" "text/html; charset=utf-8" "TLSv1.3" "on"');

        lh_true(is_array($rec), 'record');
        lh_same('text/html', $rec['header_in.accept'], 'Accept');
        lh_same('text/html; charset=utf-8', $rec['header_out.content-type'], 'Content-Type');
        lh_same('TLSv1.3', $rec['var.ssl_protocol'], 'SSL_PROTOCOL');
        lh_same('on', $rec['env.https'], 'HTTPS env');
    },

    'a line that does not match returns null rather than a partial record' => function (): void {
        $fmt = LogFormat::fromApache('%h %l %u %t "%r" %>s %b');

        lh_same(null, $fmt->parse('this is not a log line'), 'garbage line');
        lh_same(null, $fmt->parse(''), 'empty line');
        // Trailing extra columns must not be accepted: the pattern is anchored at both ends,
        // which is what lets the detector tell `common` and `combined` apart.
        lh_same(
            null,
            $fmt->parse('203.0.113.9 - - [10/Sep/2026:09:57:08 +0000] "GET / HTTP/1.1" 200 12 "x" "y"'),
            'combined line against common'
        );
    },

    'binary and control bytes cannot crash the parser' => function (): void {
        $fmt = LogFormat::fromApache('%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"');

        foreach (["\x00\x01\x02", str_repeat('"', 5000), "\xff\xfe invalid utf8", "\n\r\t"] as $junk) {
            // The only acceptable outcomes are null or an array — never an exception.
            $out = $fmt->parse($junk);
            lh_true($out === null || is_array($out), 'hostile input result');
        }
    },

    'fieldMap and pattern are exposed for the setup UI' => function (): void {
        $fmt = LogFormat::fromApache('%h %t "%r" %>s %b', 'tiny');

        lh_same('tiny', $fmt->name(), 'name');
        lh_same(LogFormat::KIND_REGEX, $fmt->kind(), 'kind');
        lh_same(['remote_addr', 'time', 'request', 'status', 'bytes'], $fmt->fieldMap(), 'fieldMap');
        lh_contains($fmt->pattern(), '^', 'pattern is anchored');
        lh_true($fmt->hasField('status'), 'hasField(status)');
        lh_false($fmt->hasField('header_in.referer'), 'hasField(referer)');
    },

    'a repeated directive gets a distinct field name instead of overwriting' => function (): void {
        $fmt = LogFormat::fromApache('%h %h %t');
        lh_same(['remote_addr', 'remote_addr__2', 'time'], $fmt->fieldMap(), 'fieldMap');
    },

    'nginx combined parses' => function (): void {
        $fmt = LogFormat::fromNginx(
            '$remote_addr - $remote_user [$time_local] "$request" '
            . '$status $body_bytes_sent "$http_referer" "$http_user_agent"'
        );

        $line = '203.0.113.9 - - [10/Sep/2026:09:57:08 +0000] "GET /a HTTP/1.1" 200 512 '
            . '"-" "curl/8.4.0"';
        $rec = $fmt->parse($line);

        lh_true(is_array($rec), 'record');
        lh_same('203.0.113.9', $rec['remote_addr'], 'remote_addr');
        // $time_local contains a space, so this proves the structural pattern is used and
        // not a naive \S+ that would stop at the offset.
        lh_same('10/Sep/2026:09:57:08 +0000', $rec['time'], 'time');
        lh_same('512', $rec['bytes'], 'bytes');
        lh_same('curl/8.4.0', $rec['header_in.user-agent'], 'user-agent');
    },

    'nginx generic $http_ variables become canonical header fields' => function (): void {
        $fmt = LogFormat::fromNginx(
            '$remote_addr [$time_local] "$request" $status $body_bytes_sent '
            . '"$http_x_forwarded_for" "$http_sec_ch_ua" $request_time'
        );

        $line = '203.0.113.9 [10/Sep/2026:09:57:08 +0000] "GET / HTTP/2.0" 200 10 '
            . '"198.51.100.1, 203.0.113.5" "\\"Chromium\\";v=\\"152\\"" 0.031';
        $rec = $fmt->parse($line);

        lh_true(is_array($rec), 'record');
        lh_same('198.51.100.1, 203.0.113.5', $rec['header_in.x-forwarded-for'], 'XFF');
        lh_same('"Chromium";v="152"', $rec['header_in.sec-ch-ua'], 'Sec-CH-UA');
        lh_same('0.031', $rec['dur_s'], 'request_time');
    },

    'an nginx JSON template becomes a JSON parser, not a regex' => function (): void {
        $fmt = LogFormat::fromNginx(
            '{"time":"$time_iso8601","ip":"$remote_addr","req":"$request",'
            . '"status":"$status","bytes":"$body_bytes_sent","ua":"$http_user_agent"}',
            'nginx_json'
        );

        lh_same(LogFormat::KIND_JSON, $fmt->kind(), 'kind');

        $rec = $fmt->parse(
            '{"time":"2026-09-10T09:57:08+00:00","ip":"203.0.113.9","req":"GET / HTTP/1.1",'
            . '"status":"200","bytes":"512","ua":"Mozilla/5.0"}'
        );
        lh_true(is_array($rec), 'record');
        lh_same('203.0.113.9', $rec['remote_addr'], 'remote_addr');
        lh_same('GET / HTTP/1.1', $rec['request'], 'request');
        lh_same('Mozilla/5.0', $rec['header_in.user-agent'], 'user-agent');
    },

    'a JSON parser skips keys the line does not carry' => function (): void {
        $fmt = LogFormat::fromJson('t', [
            'ip'  => 'remote_addr',
            'ua'  => 'header_in.user-agent',
            'ref' => 'header_in.referer',
        ]);

        $rec = $fmt->parse('{"ip":"203.0.113.9","ua":"Mozilla/5.0"}');
        lh_true(is_array($rec), 'record');
        // The absent key must be absent, not an empty string — SPEC §1.
        lh_no_key($rec, 'header_in.referer', 'record');

        lh_same(null, $fmt->parse('not json'), 'non-JSON line');
        lh_same(null, $fmt->parse('[1,2,3]'), 'JSON array line');
        lh_same(null, $fmt->parse('{"unrelated":1}'), 'JSON with none of our keys');
    },

    'a JSON header array takes its first element' => function (): void {
        $fmt = LogFormat::fromJson('caddyish', [
            'request.headers.User-Agent' => 'header_in.user-agent',
            'request.remote_ip'          => 'remote_addr',
        ]);

        $rec = $fmt->parse(
            '{"request":{"remote_ip":"203.0.113.9","headers":{"User-Agent":["Mozilla/5.0","dup"]}}}'
        );
        lh_true(is_array($rec), 'record');
        lh_same('Mozilla/5.0', $rec['header_in.user-agent'], 'user-agent');
    },

    'fromRegex derives its field list from named groups' => function (): void {
        $fmt = LogFormat::fromRegex('~^(?<remote_addr>\S+) (?<status>\d{3})$~');
        lh_same(['remote_addr', 'status'], $fmt->fieldMap(), 'fieldMap');

        $rec = $fmt->parse('203.0.113.9 404');
        lh_same('404', $rec['status'], 'status');
    },

    'unescape is a no-op on a value with no backslash' => function (): void {
        lh_same('/plain/path', LogFormat::unescape('/plain/path'), 'unescape');
        lh_same('a"b', LogFormat::unescape('a\\"b'), 'escaped quote');
        lh_same("a\tb", LogFormat::unescape('a\\x09b'), 'hex escape');
    },
];
