<?php
/**
 * Loghound — a path is never shown as a path alone.
 *
 * THE DEFECT. Overview → Top pages rendered a column of `/opensolr-search`, `/ro-md/opensolr-search`,
 * `/changelog`. None of them could be clicked, and on an installation serving several virtual hosts
 * none of them said which site they belonged to. The same was true of the slowest-paths table, the
 * Paths facet in all three places it is drawn, the session trail, the entry and exit pages, the
 * recent-visitors table and the Virtual hosts view.
 *
 * What is pinned here is the whole contract, because every part of it is a way the fix could rot:
 *
 *   1. The URL is built from a host and a path by url.js, never by splicing a string, and the
 *      builder refuses `javascript:`, `data:`, `//evil.com`, `\/evil.com`, `https://a@evil.com`, a
 *      host carrying `@` or `/`, CR, LF, NUL and TAB, and a path that tries to start an authority.
 *   2. The server resolves the host where it honestly can — a `host_s` sub-facet nested inside the
 *      path facet — and says how many hosts a path spans when it cannot.
 *   3. AMBIGUITY IS NEVER RESOLVED BY GUESSING. A path on several hosts renders a marker saying so,
 *      not a link to the most common one. A link that works and goes somewhere wrong is worse than
 *      no link.
 *   4. Every external link carries target="_blank" AND rel="noopener noreferrer".
 *   5. The filter affordance survives. The value still filters the dashboard; the URL is a second,
 *      separate control. Replacing one with the other would take a feature away silently.
 *
 * The JavaScript is exercised for real where node is available, and asserted structurally where it
 * is not — the suite must still pass on a box with php-cli and nothing else (SPEC §12).
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

use Loghound\Config;
use Loghound\Panel\Gateway;
use Loghound\Panel\Overview;
use Loghound\Panel\Performance;
use Loghound\Panel\Query;
use Loghound\Panel\Sessions;
use Loghound\Panel\SiteUrl;
use Loghound\Solr;

/** Read one of the panel's asset files. */
function lh_url_file(string $relative): string
{
    $path = dirname(__DIR__) . '/' . $relative;
    if (!is_file($path)) {
        lh_fail('missing file: ' . $relative);
    }
    return (string) file_get_contents($path);
}

/** The front-end files that render a path, a host, or the control beside one. */
function lh_url_render_sites(): array
{
    return [
        'public/assets/js/views/overview.js',
        'public/assets/js/views/performance.js',
        'public/assets/js/views/hosts.js',
        'public/assets/js/facets.js',
        'public/assets/js/facetfilter.js',
        'public/assets/js/detail.js',
    ];
}

/** A panel wired to the synthetic world, so a payload can be asked for without a Solr. */
function lh_url_demo(): array
{
    $cfg = Config::load('/nonexistent-loghound-config');
    $cfg->set('ui.demo', true);
    return [$cfg, Gateway::fromConfig($cfg)];
}

/**
 * Run one panel action against a fake Solr that records what was asked, and answers nothing.
 *
 * The REAL Solr client is used, so the request is built and sanitised exactly as production would
 * build it: a facet this client would refuse fails here rather than in a year's time.
 *
 * @param array<string,mixed> $get
 * @return array<int,array<string,mixed>> Every request issued.
 */
function lh_url_capture(string $class, string $action, array $get): array
{
    $captured = [];
    $transport = function (array $request) use (&$captured): array {
        $captured[] = $request;
        return [
            'status' => 200,
            'body'   => (string) json_encode([
                'responseHeader' => ['status' => 0],
                'response'       => ['numFound' => 0, 'docs' => []],
                'facets'         => ['count' => 0],
            ]),
            'error'  => '',
        ];
    };

    $cfg = Config::load('/nonexistent-loghound-config');
    $cfg->set('solr.base_url', 'http://127.0.0.1:65535/solr');
    $cfg->set('solr.hits_core', 'lh_url_hits');
    $cfg->set('solr.sessions_core', 'lh_url_sessions');

    $saved = $_GET;
    $_GET = $get;
    try {
        (new $class($cfg, new Gateway($cfg, new Solr((array) $cfg->get('solr'), $transport), false)))->api($action);
    } finally {
        $_GET = $saved;
    }
    return $captured;
}

/**
 * Every value of a repeated parameter in a captured request body.
 *
 * parse_str() keeps only the last `fq`, which is exactly the one a test about filters needs to
 * see all of, so the body is split by hand.
 *
 * @param array<string,mixed> $request
 * @return array<int,string>
 */
function lh_url_params(array $request, string $key): array
{
    $out = [];
    foreach (explode('&', (string) ($request['body'] ?? '')) as $pair) {
        if ($pair === '') {
            continue;
        }
        [$k, $v] = array_pad(explode('=', $pair, 2), 2, '');
        if (rawurldecode($k) === $key) {
            $out[] = rawurldecode($v);
        }
    }
    return $out;
}

/**
 * Run one panel action against the synthetic world.
 *
 * @param array<string,mixed> $get
 * @return array<string,mixed>
 */
function lh_url_api(string $class, string $action, array $get): array
{
    [$cfg, $gw] = lh_url_demo();
    $saved = $_GET;
    $_GET = $get;
    try {
        return (new $class($cfg, $gw))->api($action);
    } finally {
        $_GET = $saved;
    }
}

/**
 * Run the URL builder under node against a list of hostile inputs, or skip.
 *
 * The real public/assets/js/url.js is copied beside a three-line stand-in for core.js, so what is
 * measured is the shipped file and not a paraphrase of it. Anything that stops node from being
 * usable — not installed, not executable, a sandbox that forbids exec — is a skip and not a
 * failure: this suite has to pass on a bare box with php-cli and nothing else.
 *
 * @return array<string,mixed>
 */
function lh_url_probe(): array
{
    $which = @shell_exec('command -v node 2>/dev/null');
    if (!is_string($which) || trim($which) === '') {
        lh_skip('node is not on PATH, so the URL builder is asserted structurally only');
    }

    $dir = lh_tmpdir('lhurl');
    copy(dirname(__DIR__) . '/public/assets/js/url.js', $dir . '/url.js');
    file_put_contents(
        $dir . '/core.js',
        "export function el(tag, attrs, children) {\n"
        . "    return { tag: tag, attrs: attrs || {}, children: (children || []).filter(Boolean) };\n"
        . "}\n"
    );
    file_put_contents($dir . '/probe.mjs', lh_url_probe_source());

    $out = @shell_exec('cd ' . escapeshellarg($dir) . ' && node probe.mjs 2>&1');
    $decoded = json_decode(is_string($out) ? $out : '', true);
    lh_rmtree($dir);

    if (!is_array($decoded)) {
        lh_fail('the URL builder probe did not return JSON: ' . lh_show((string) $out));
    }
    return $decoded;
}

/**
 * The probe script.
 *
 * Every control character is built with String.fromCharCode rather than written literally, so this
 * file stays readable and greppable and no editor silently normalises the input the test depends
 * on.
 */
function lh_url_probe_source(): string
{
    return <<<'JS'
import { ambiguityMark, outLink, resolveHost, safeHost, safePath, siteUrl } from './url.js';

globalThis.window = { location: { search: '' } };

const CR = String.fromCharCode(13);
const LF = String.fromCharCode(10);
const TAB = String.fromCharCode(9);
const NUL = String.fromCharCode(0);

const urls = {};
const add = (name, host, path, query) => { urls[name] = siteUrl(host, path, query); };

add('plain', 'example.com', '/changelog');
add('nested', 'example.com', '/ro-md/opensolr-search');
add('root', 'example.com', '');
add('port', 'example.com:8443', '/a');
add('ipv4', '192.0.2.10', '/a');
add('ipv6', '[2001:db8::1]', '/a');
add('ipv6_port', '[2001:db8::1]:8443', '/a');
add('already_escaped', 'example.com', '/a%2Fb');
add('needs_escape', 'example.com', '/a b');
add('apostrophe', 'example.com', "/it's");
add('query', 'example.com', '/search', 'q=hello&page=2');

add('protocol_relative', 'example.com', '//evil.com/x');
add('backslash_relative', 'example.com', '\\/evil.com/x');
add('double_backslash', 'example.com', '\\\\/evil.com/x');
add('javascript_path', 'example.com', 'javascript:alert(1)');
add('host_javascript', 'javascript:alert(1)', '/a');
add('host_data', 'data:text/html,x', '/a');
add('host_scheme', 'https://evil.com', '/a');
add('host_userinfo', 'a@evil.com', '/a');
add('host_password', 'user:pass@evil.com', '/a');
add('host_slash', 'example.com/evil.com', '/a');
add('host_backslash', 'example.com\\evil.com', '/a');
add('host_query', 'example.com?x=1', '/a');
add('host_fragment', 'example.com#x', '/a');
add('host_crlf', 'example.com' + CR + LF, '/a');
add('host_tab', 'example.com' + TAB, '/a');
add('host_nul', 'example.com' + NUL, '/a');
add('host_space', 'example.com ', '/a');
add('host_empty', '', '/a');
add('host_leading_dash', '-example.com', '/a');
add('host_empty_label', 'example..com', '/a');
add('host_bad_port', 'example.com:notaport', '/a');
add('host_empty_port', 'example.com:', '/a');
add('path_crlf', 'example.com', '/a' + CR + LF + 'b');
add('path_nul', 'example.com', '/a' + NUL + 'b');
add('path_quote', 'example.com', '/a"b');
add('path_angle', 'example.com', '/a<script>');
add('query_crlf', 'example.com', '/a', 'x=1' + CR + LF + 'y=2');

const link = outLink('example.com', '/changelog');
const refused = outLink('a@evil.com', '/changelog');

const resolutions = {
    own_host: resolveHost({ host: 'a.example', hosts: 1 }),
    many_hosts: resolveHost({ host: null, hosts: 4 }),
    many_beats_fallback: resolveHost({ host: null, hosts: 4, fallback: 'a.example' }),
    fallback: resolveHost({ host: null, hosts: 1, fallback: 'a.example' }),
    nothing: resolveHost({ host: null, hosts: 0 }),
    unknown: resolveHost({})
};

const marks = {
    many: ambiguityMark(4).attrs,
    none: ambiguityMark(0).attrs,
    unknown: ambiguityMark(null).attrs
};

console.log(JSON.stringify({
    urls: urls,
    host_ok: safeHost('example.com'),
    host_refused: safeHost('a@evil.com'),
    path_root: safePath('////'),
    link: link === null ? null : link.attrs,
    refused: refused,
    resolutions: resolutions,
    marks: marks
}));
JS;
}

return [

    /* ---------------------------------------------------------------------
     * The URL builder, run for real
     * ------------------------------------------------------------------ */

    'the URL builder composes a real URL from a host and a path' => function (): void {
        $probe = lh_url_probe();
        $urls = $probe['urls'];

        lh_same('https://example.com/changelog', $urls['plain']);
        lh_same('https://example.com/ro-md/opensolr-search', $urls['nested']);
        lh_same('https://example.com/', $urls['root'], 'an empty path is the site root, not a refusal');
        lh_same('https://example.com:8443/a', $urls['port']);
        lh_same('https://192.0.2.10/a', $urls['ipv4']);
        lh_same('https://[2001:db8::1]/a', $urls['ipv6']);
        lh_same('https://[2001:db8::1]:8443/a', $urls['ipv6_port']);
        lh_same('https://example.com/search?q=hello&page=2', $urls['query']);
    },

    'an escape already in the path is left alone, and everything else is escaped' => function (): void {
        $urls = lh_url_probe()['urls'];

        lh_same('https://example.com/a%2Fb', $urls['already_escaped'], 'a valid escape must not be escaped twice');
        lh_same('https://example.com/a%20b', $urls['needs_escape'], 'a space in a path has to be encoded');
        lh_same('https://example.com/it%27s', $urls['apostrophe'], 'an apostrophe must not survive into an href');
    },

    'the URL builder refuses every shape that would change the origin' => function (): void {
        $urls = lh_url_probe()['urls'];

        foreach ([
            'protocol_relative' => '//evil.com must resolve to a path on this host',
            'backslash_relative' => 'a leading backslash is not an authority either',
            'double_backslash' => 'nor are two of them',
        ] as $case => $why) {
            lh_same('https://example.com/evil.com/x', $urls[$case], $why);
        }

        foreach ([
            'host_javascript', 'host_data', 'host_scheme', 'host_userinfo', 'host_password',
            'host_slash', 'host_backslash', 'host_query', 'host_fragment', 'host_crlf',
            'host_tab', 'host_nul', 'host_space', 'host_empty', 'host_leading_dash',
            'host_empty_label', 'host_bad_port', 'host_empty_port',
            'path_crlf', 'path_nul', 'query_crlf',
        ] as $case) {
            lh_same(null, $urls[$case], $case . ' must produce no URL at all, so no link is rendered');
        }
    },

    'a scheme in a path is a path, and a quote in one is escaped' => function (): void {
        $urls = lh_url_probe()['urls'];

        lh_same(
            'https://example.com/javascript:alert(1)',
            $urls['javascript_path'],
            'a request line CAN contain that text; it is a relative path on this host and nothing else'
        );
        lh_same('https://example.com/a%22b', $urls['path_quote'], 'a quote could close the href attribute');
        lh_same('https://example.com/a%3Cscript%3E', $urls['path_angle']);
    },

    'a refused value produces no link at all, never a dead one' => function (): void {
        $probe = lh_url_probe();

        lh_same(null, $probe['refused'], 'a link that cannot be built must be null, not href="#"');
        lh_same('example.com', $probe['host_ok']);
        lh_same(null, $probe['host_refused']);
        lh_same('/', $probe['path_root'], 'a path of nothing but slashes is the root, with exactly one');
    },

    'every external link opens in a new tab and hands the destination nothing' => function (): void {
        $link = lh_url_probe()['link'];

        lh_same('_blank', $link['target'], 'a site link must not navigate the panel away');
        lh_same(
            'noopener noreferrer',
            $link['rel'],
            'noopener or the destination gets a handle on this window; noreferrer or it gets the panel URL'
        );
        lh_contains($link['href'], 'https://example.com/changelog');
        lh_contains($link['title'], 'new tab', 'the control says what it does');
        lh_contains($link['title'], 'assumes https', 'and admits the one thing it had to assume');
    },

    /* ---------------------------------------------------------------------
     * Host resolution and the refusal to guess
     * ------------------------------------------------------------------ */

    'a host on the row wins, and several hosts beat every fallback there is' => function (): void {
        $seen = lh_url_probe()['resolutions'];

        lh_same('a.example', $seen['own_host']['host'], 'the row knows its own host');
        lh_same(null, $seen['many_hosts']['host'], 'four hosts is not an answer, and must not become one');
        lh_same(4, $seen['many_hosts']['count']);
        lh_same(
            null,
            $seen['many_beats_fallback']['host'],
            'a session host must not be applied to a path the server said spans four sites'
        );
        lh_same('a.example', $seen['fallback']['host'], 'one host and a fallback: the fallback applies');
        lh_same(null, $seen['nothing']['host']);
        lh_same(null, $seen['unknown']['host']);
    },

    'an ambiguous path says so in words, and says how to make the link appear' => function (): void {
        $marks = lh_url_probe()['marks'];

        lh_same('4 hosts', $marks['many']['text'], 'the marker states the number rather than shrugging');
        lh_contains($marks['many']['title'], '4 virtual hosts');
        lh_contains($marks['many']['title'], 'Filter to one host', 'and says what to do about it');

        lh_same('no host logged', $marks['none']['text']);
        lh_contains($marks['none']['title'], '%v', 'a log with no host in it is a different problem, named');

        lh_same('several hosts', $marks['unknown']['text']);
        lh_contains(
            $marks['unknown']['title'],
            'does not say which',
            'an uncounted ambiguity says the list did not name a host — not that the path is on several, '
                . 'which is a stronger claim than the panel has evidence for'
        );
        lh_contains($marks['unknown']['title'], 'Filter to one host');
    },

    /* ---------------------------------------------------------------------
     * The server half
     * ------------------------------------------------------------------ */

    'the host sub-facet is nested, bounded and asks for the real number of hosts' => function (): void {
        $facet = SiteUrl::hostSubFacet();

        lh_has_key($facet, SiteUrl::SUB_FACET);
        $spec = $facet[SiteUrl::SUB_FACET];

        lh_same('terms', $spec['type']);
        lh_same(Query::HOST_FIELD, $spec['field'], 'the host field, not a second spelling of it');
        lh_same(2, $spec['limit'], 'two buckets is all it takes to know "more than one"');
        lh_same(true, $spec['numBuckets'], 'without this a row can only say "several", never "four"');
    },

    'one host resolves, several do not, and an absent sub-facet is not an invitation to guess'
        => function (): void {
            $one = SiteUrl::resolve([
                'val' => '/a',
                SiteUrl::SUB_FACET => ['numBuckets' => 1, 'buckets' => [['val' => 'a.example', 'count' => 9]]],
            ]);
            lh_same('a.example', $one['host']);
            lh_same(1, $one['hosts']);

            $many = SiteUrl::resolve([
                'val' => '/a',
                SiteUrl::SUB_FACET => [
                    'numBuckets' => 4,
                    'buckets' => [['val' => 'a.example', 'count' => 9], ['val' => 'b.example', 'count' => 3]],
                ],
            ]);
            lh_same(null, $many['host'], 'the most common host is still the wrong host');
            lh_same(4, $many['hosts'], 'and the count is the real one, not the page size');

            $truncated = SiteUrl::resolve([
                SiteUrl::SUB_FACET => [
                    'buckets' => [['val' => 'a.example'], ['val' => 'b.example']],
                ],
            ]);
            lh_same(null, $truncated['host'], 'no numBuckets is not permission to pick one');
            lh_same(2, $truncated['hosts']);

            $absent = SiteUrl::resolve(['val' => '/a']);
            lh_same(null, $absent['host']);
            lh_same(0, $absent['hosts'], 'both keys are always present, so no renderer has to guess either');

            $empty = SiteUrl::resolve([SiteUrl::SUB_FACET => ['numBuckets' => 0, 'buckets' => []]]);
            lh_same(null, $empty['host']);
            lh_same(0, $empty['hosts']);
        },

    'Top pages ships a host or a host count on every single row' => function (): void {
        $payload = lh_url_api(Overview::class, 'toppages', ['range' => '24h']);

        lh_true($payload['rows'] !== [], 'the synthetic world has to produce rows or this proves nothing');
        foreach ($payload['rows'] as $row) {
            lh_has_key($row, 'path');
            lh_has_key($row, 'host', 'a path with no site in front of it is not a URL');
            lh_has_key($row, 'hosts', 'and a row that cannot name one has to say how many there are');
            lh_true(
                $row['host'] !== null || $row['hosts'] !== 1,
                'a row that spans exactly one host must carry it: ' . lh_show($row)
            );
        }
    },

    'the slowest-paths table ships the same two keys, and keeps the ones it had'
        => function (): void {
            $payload = lh_url_api(Performance::class, 'paths', ['range' => '24h']);

            lh_true($payload['paths'] !== [], 'no rows means nothing was tested');
            foreach ($payload['paths'] as $row) {
                lh_has_key($row, 'host');
                lh_has_key($row, 'hosts');
                lh_has_key($row, 'p95', 'the host sub-facet must not have displaced the percentiles');
                lh_has_key($row, 'requests');
            }
        },

    'the host sub-facet rides inside the path facet, in one request, under the same filters'
        => function (): void {
            foreach ([
                [Overview::class, 'toppages', 'paths'],
                [Performance::class, 'paths', 'paths'],
            ] as [$class, $action, $parent]) {
                $captured = lh_url_capture($class, $action, [
                    'range' => '24h',
                    'f'     => ['host_s' => ['example.com']],
                ]);

                lh_same(1, count($captured), $class . '::' . $action . ' must not spend a second round trip on this');

                $json = lh_url_params($captured[0], 'json.facet');
                lh_same(1, count($json), 'one facet structure per request');
                $facet = json_decode($json[0], true);

                lh_has_key($facet, $parent, $class . ': the path facet is where the sub-facet has to live');
                lh_has_key($facet[$parent], 'facet', $class . ': nested, so it inherits the parent\'s domain');
                lh_has_key(
                    $facet[$parent]['facet'],
                    SiteUrl::SUB_FACET,
                    $class . ': the host sub-facet is gone, so every row is ambiguous again'
                );
                lh_same(Query::HOST_FIELD, $facet[$parent]['facet'][SiteUrl::SUB_FACET]['field']);

                $fqs = implode(' | ', lh_url_params($captured[0], 'fq'));
                lh_contains(
                    $fqs,
                    'host_s',
                    $class . ': the host filter must be on the query the sub-facet is computed under, '
                        . 'or scoping the dashboard would not resolve a single row'
                );
            }
        },

    'a session trail carries a host per request, with the session as the fallback' => function (): void {
        $list = lh_url_api(Sessions::class, 'list', ['range' => '24h']);
        $id = (string) ($list['docs'][0]['id'] ?? '');
        lh_true($id !== '', 'the synthetic world has to return a session');

        $detail = lh_url_api(Sessions::class, 'detail', ['range' => '24h', 'id' => $id]);

        lh_has_key($detail['session'], 'host', 'the session host is the fallback for a hit without one');
        lh_true($detail['timeline'] !== [], 'a session with no trail proves nothing');
        foreach ($detail['timeline'] as $hit) {
            lh_has_key($hit, 'host', 'host_s was in hitFl() all along and was never mapped through');
            lh_has_key($hit, 'path');
        }
    },

    'a recent visitor carries the host its entry path belongs to' => function (): void {
        $dim = lh_url_api(Sessions::class, 'dimension', [
            'range' => '24h',
            'field' => 'paths_ss',
            'value' => '/login',
        ]);

        lh_true(($dim['visitors'] ?? []) !== [], 'no sample visitors means nothing was tested');
        foreach ($dim['visitors'] as $visitor) {
            lh_has_key($visitor, 'host', 'the entry path in this row cannot be opened without it');
            lh_has_key($visitor, 'entry');
        }
    },

    /* ---------------------------------------------------------------------
     * The guards are in the file, whether or not node ran
     * ------------------------------------------------------------------ */

    'the URL builder is one file and it states every guard it applies' => function (): void {
        $js = lh_url_file('public/assets/js/url.js');

        foreach ([
            'export function safeHost(' => 'a host is validated, not trusted',
            'export function safePath(' => 'and so is a path',
            'export function siteUrl(' => 'and the two are joined in one place',
            "while (rest.charAt(0) === '/' || rest.charAt(0) === '\\\\')"
                => 'every leading slash and backslash goes, which is what kills //evil.com',
            'new URL(composed)' => 'the finished string is parsed back by the thing that will follow it',
            "parsed.protocol !== 'https:'" => 'and refused unless it really is https',
            "parsed.username !== ''" => 'userinfo is a spoofed hostname wearing a disguise',
            'parsed.host !== safeH.toLowerCase()' => 'and the authority must be the one we asked for',
            'SCHEME + safeH + safeP + safeQ' => 'built from parts, never from a string somebody handed us',
        ] as $needle => $why) {
            lh_contains($js, $needle, $why);
        }

        lh_false(
            str_contains($js, "href: '#'") || str_contains($js, 'href: "#"'),
            'a refusal renders no link; it never renders a dead one'
        );
    },

    'the only new-tab link in the panel\'s own render sites is the one this builder makes'
        => function (): void {
            $js = lh_url_file('public/assets/js/url.js');
            lh_contains($js, "target: '_blank'");
            lh_contains($js, "rel: 'noopener noreferrer'");

            $at = strpos($js, "target: '_blank'");
            $window = substr($js, $at, 200);
            lh_contains(
                $window,
                "rel: 'noopener noreferrer'",
                'the two attributes are written together, so one cannot be dropped without the other'
            );

            foreach (lh_url_render_sites() as $file) {
                lh_false(
                    str_contains(lh_url_file($file), 'target:'),
                    $file . ' opens a new tab of its own, bypassing the sanitiser'
                );
            }
        },

    'no render site builds an href by sticking strings together' => function (): void {
        foreach (array_merge(lh_url_render_sites(), ['public/assets/js/url.js']) as $file) {
            $js = lh_url_file($file);

            preg_match_all('/href:\s*([^,\n}]+)/', $js, $matches);
            foreach ($matches[1] as $expression) {
                lh_false(
                    (bool) preg_match('~https?:~i', $expression),
                    $file . ' splices a scheme into an href: ' . $expression
                );
                lh_false(
                    str_contains($expression, '+'),
                    $file . ' concatenates an href rather than building one: ' . $expression
                );
            }
        }
    },

    /* ---------------------------------------------------------------------
     * Every render site actually uses it
     * ------------------------------------------------------------------ */

    'every place that shows a path shows the full URL beside it' => function (): void {
        foreach ([
            'public/assets/js/views/overview.js' => ['pathCell(row.path', 'host: row.host', 'hosts: row.hosts'],
            'public/assets/js/views/performance.js' => ['pathCell(row.path', 'host: row.host', 'hosts: row.hosts'],
            'public/assets/js/facets.js' => ['isPathField(group.field)', 'urlMark(bucket.value)'],
            'public/assets/js/facetfilter.js' => ['isPathField(group.field)', 'urlMark(value)'],
            'public/assets/js/detail.js' => ['urlMark(hit.path', 'pathCell(s.entry', 'pathCell(s.exit', 'pathCell(v.entry'],
            'public/assets/js/views/hosts.js' => ["outLink(row.host, '/')", 'noteHosts('],
        ] as $file => $needles) {
            $js = lh_url_file($file);
            lh_true(
                str_contains($js, "from './url.js'") || str_contains($js, "from '../url.js'"),
                $file . ' must import the builder rather than growing a URL of its own'
            );
            foreach ($needles as $needle) {
                lh_contains($js, $needle, $file . ' no longer renders that value with its URL');
            }
        }
    },

    'no table cell renders a bare path any more' => function (): void {
        foreach ([
            'public/assets/js/views/overview.js' => '{ text: row.path, mono: true, clip: true',
            'public/assets/js/views/performance.js' => '{ text: row.path, mono: true, clip: true',
        ] as $file => $gone) {
            lh_false(
                str_contains(lh_url_file($file), $gone),
                $file . ' is back to printing a path with nothing beside it'
            );
        }

        lh_false(
            str_contains(lh_url_file('public/assets/js/detail.js'), "text: v.entry || '—',"),
            'the recent-visitors entry page is a bare path again'
        );
    },

    'the value still filters the dashboard — the URL is a second control, not a replacement'
        => function (): void {
            $facets = lh_url_file('public/assets/js/facets.js');
            lh_contains(
                $facets,
                'href: toggleUrl(group.field, bucket.value, group.ns)',
                'the facet row is still the filter control it always was'
            );

            $overview = lh_url_file('public/assets/js/views/overview.js');
            lh_contains(
                $overview,
                "dimRow('paths_ss', row.path)",
                'a Top pages row still opens the path\'s record and still filters to it'
            );

            $hosts = lh_url_file('public/assets/js/views/hosts.js');
            lh_contains(
                $hosts,
                "dimValue('host_s', row.host, { mono: true })",
                'the hostname is still the control that scopes the dashboard'
            );
        },

    'an anchor is never nested inside another anchor' => function (): void {
        foreach (['public/assets/js/facets.js', 'public/assets/js/facetfilter.js'] as $file) {
            $js = lh_url_file($file);
            lh_false(
                (bool) preg_match('/urlMark\([^)]*\)\s*\n?\s*\]\)\s*,?\s*\n?\s*\]\)\s*,\s*\n?\s*urlMark/', $js),
                $file . ': two marks on one row'
            );
            lh_contains(
                $js,
                "path ? urlMark(",
                $file . ': the mark is a sibling of the row, conditional on the field being a path'
            );
        }
    },

    /* ---------------------------------------------------------------------
     * Layout
     * ------------------------------------------------------------------ */

    'the link beside a path never gets eaten by the ellipsis that truncates it' => function (): void {
        $css = lh_url_file('public/assets/css/panel.css');

        lh_contains($css, '.urlwrap {', 'the pair needs a container or it cannot be laid out');
        lh_contains($css, '.urlwrap > .urlpath {', 'and the path needs to be the half that shrinks');
        lh_contains($css, 'flex: 0 0 auto', 'while the control is the half that does not');
        lh_contains($css, '.urlamb {', 'the ambiguity marker has a look of its own');
        lh_contains($css, 'td.urlcell {', 'and the cell stops truncating on the path\'s behalf');
    },

    'a phone gets the whole URL and a thumb-sized control, and the card still collapses'
        => function (): void {
            $css = lh_url_file('public/assets/css/mobile.css');

            lh_contains($css, 'table.lh-stack .urlwrap { flex-wrap: wrap; }', 'a long URL wraps in a card');
            lh_contains($css, 'table.lh-stack td.urlcell { overflow: visible; }', 'and is not clipped by the cell');
            lh_contains($css, 'overflow-wrap: anywhere', 'a 96-character path must not scroll the page sideways');
            lh_contains($css, '.urlout {', 'the control gets the tap-target floor every other control has');
            lh_contains($css, 'min-height: var(--lh-tap)');
        },

    'nothing operator-facing that this added is set below 14px' => function (): void {
        foreach (['public/assets/css/panel.css', 'public/assets/css/mobile.css'] as $file) {
            $css = lh_url_file($file);
            foreach (['.urlout', '.urlamb', '.urlout-mark'] as $selector) {
                $at = strpos($css, $selector . ' {');
                if ($at === false) {
                    continue;
                }
                $block = substr($css, $at, (int) strpos($css, '}', $at) - $at);
                if (preg_match('/font-size:\s*(\d+)px/', $block, $m)) {
                    lh_true(
                        (int) $m[1] >= 14,
                        $file . ' sets ' . $selector . ' at ' . $m[1] . 'px, below the 14px floor'
                    );
                }
            }
        }
    },

    'the panel never states the scheme as a fact it knows' => function (): void {
        $js = lh_url_file('public/assets/js/url.js');

        lh_contains($js, 'SCHEME IS ASSUMED, NOT KNOWN', 'the file says so where the next reader will find it');
        lh_contains($js, 'assumes https', 'and every link says so in its own title');
        lh_false(
            (bool) preg_match('/\bproto_s\b[^\n]*scheme/i', $js),
            'proto_s is the HTTP version and must never be read as a URL scheme'
        );
    },
];
