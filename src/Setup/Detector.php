<?php
/**
 * Loghound — log discovery, shared by both installers (SPEC §8).
 *
 * `bin/loghound-setup` and the browser installer both call this, so there is exactly one
 * answer to "which files will be ingested, with which format, and how sure are we". The
 * output is the report shape the Settings view already reads from `var/detect.json`, which
 * means a source confirmed in either installer shows up as confirmed in the panel.
 *
 * THE LADDER (SPEC §8), in order, best answer first:
 *
 *   1. Read the operator's own webserver configuration. That yields the exact format
 *      string, the exact file list AND the vhost each file belongs to. Deterministic —
 *      there is nothing to guess, because the answer is written down in their config.
 *   2. Score the last 200 lines of each candidate file against the built-in format
 *      library, structurally: field 1 must really parse as an IP, the bracketed field must
 *      really parse as a date, the status must really be a status.
 *   3. Propose a pattern generated from the sample when nothing in the library matches.
 *
 * WHATEVER RUNG IT LANDS ON, THE OPERATOR CONFIRMS. A format is never used silently. The
 * report carries five real lines rendered as parsed records precisely so a human can see
 * that the User-Agent is in the User-Agent column, and a confidence percentage that is
 * shown even — especially — when it is bad.
 *
 * It runs as a Job because it is not necessarily fast: the reference install has a 15 MB
 * access log, and a box with twenty vhosts has twenty of them.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Setup;

use Loghound\Config;
use Loghound\LogDetect;
use Loghound\LogFormat;
use Loghound\Parser;
use Loghound\Security;

final class Detector
{
    /** Lines sampled per file. 200 separates a dozen formats comfortably. */
    private const SAMPLE_LINES = 200;

    /** Sample lines shown to the operator. SPEC §8 says five. */
    private const SHOW_LINES = 5;

    /** A single rendered value is truncated at this many characters for display. */
    private const MAX_VALUE = 400;

    /**
     * Canonical capture name → the Loghound field it becomes, for the mapping table.
     *
     * This is a DISPLAY table: Parser owns the real conversion, and Parser::loggedFields()
     * is what the "not logged, and what that costs you" list below is computed from. This
     * one exists so the review screen can say `%{User-Agent}i → ua_s` next to a real
     * example, which is the whole point of the confirmation step.
     */
    private const DOC_FIELD = [
        'remote_addr' => 'ip_s',
        'time'        => 'ts',
        'request'     => 'method_s + path_s + query_s + proto_s',
        'method'      => 'method_s',
        'uri'         => 'path_s',
        'query'       => 'query_s',
        'query_raw'   => 'query_s',
        'protocol'    => 'proto_s',
        'status'      => 'status_i',
        'bytes'       => 'bytes_l',
        'bytes_out'   => 'bytes_l',
        'dur_us'      => 'dur_us_l',
        'dur_ms'      => 'dur_us_l',
        'dur_s'       => 'dur_us_l',
        'vhost'       => 'host_s',
        'port'        => '(not indexed)',
        'ident'       => '(ignored)',
        'remote_user' => '(ignored)',
        'user'        => '(ignored)',
    ];

    /**
     * Fields whose absence measurably weakens detection, and the honest cost of each.
     *
     * Shown on the review screen so "plain combined works but detects less" is a concrete
     * statement rather than a vague warning.
     */
    private const COSTS = [
        'dur_us_l'          => ['%D', 'Request duration is not logged, so the Performance view has no latency data.'],
        'accept_s'          => ['%{Accept}i', 'Weakens the header fingerprint that exposes proxy fleets sharing one browser build.'],
        'accept_lang_s'     => ['%{Accept-Language}i', 'Weakens the same fingerprint, and disables the timezone cross-check.'],
        'accept_enc_s'      => ['%{Accept-Encoding}i', 'Weakens the header fingerprint.'],
        'sec_ch_ua_s'       => ['%{Sec-CH-UA}i', 'Disables the ua_secch_mismatch rule entirely — a spoofed Chrome cannot be caught on headers.'],
        'sec_ch_platform_s' => ['%{Sec-CH-UA-Platform}i', 'Disables the platform_mismatch rule.'],
        'sec_fetch_site_s'  => ['%{Sec-Fetch-Site}i', 'Loses the navigation context that separates a real click from a scripted fetch.'],
        'xff_s'             => ['%{X-Forwarded-For}i', 'Behind a proxy, every visitor looks like the proxy.'],
        'host_s'            => ['%v', 'All virtual hosts are merged into one, so per-site numbers are not available.'],
    ];

    /**
     * Build the detection job's steps.
     *
     * The list GROWS: the first step works out which files are candidates, and the steps
     * that sample them only exist once it has. Job::steps() rebuilds from the stored
     * results on every request, which is what makes that possible.
     *
     * @return array<int,array{key:string,label:string,run:callable}>
     */
    public static function steps(Job $job, Config $cfg): array
    {
        $steps = [[
            'key'   => 'discover',
            'label' => 'Looking for access logs',
            'run'   => static function (Job $j, Config $c): string {
                $found = self::candidates($c, $j);
                $j->setResult('candidates', $found);
                if ($found === []) {
                    return 'No access log found automatically — you can type a path instead.';
                }
                return count($found) . ' candidate file' . (count($found) === 1 ? '' : 's') . ' to examine.';
            },
        ]];

        foreach ((array) ($job->result()['candidates'] ?? []) as $path => $meta) {
            $steps[] = [
                'key'   => 'file:' . md5((string) $path),
                'label' => 'Reading ' . basename((string) $path),
                'run'   => static function (Job $j, Config $c) use ($path, $meta): string {
                    $source = self::examine($c, (string) $path, (array) $meta);
                    $sources = (array) ($j->result()['sources'] ?? []);
                    $sources[(string) $path] = $source;
                    $j->setResult('sources', $sources);

                    if (!empty($source['outside_roots'])) {
                        return 'Outside the directories Loghound may read — listed, not opened.';
                    }
                    if ($source['lines_tested'] === 0) {
                        return 'Empty or unreadable — skipped.';
                    }
                    return sprintf(
                        '%s, %s%% of %d sampled lines parse cleanly.',
                        $source['format_name'],
                        rtrim(rtrim(number_format($source['confidence'], 1), '0'), '.'),
                        $source['lines_tested']
                    );
                },
            ];
        }

        $steps[] = [
            'key'   => 'report',
            'label' => 'Saving the detection report',
            'run'   => static function (Job $j, Config $c): string {
                $report = self::report(array_values((array) ($j->result()['sources'] ?? [])), $c);
                $path = self::writeReport($c, $report);
                $j->setResult('report_path', $path === null ? '' : $path);
                return $path === null
                    ? 'Report kept in memory (var/ is not writable).'
                    : 'Saved to ' . $path . '.';
            },
        ];

        return $steps;
    }

    /**
     * Run the whole detection synchronously and return the report.
     *
     * The CLI wizard uses this: it has no gateway timeout to respect and prints as it goes.
     *
     * @param callable|null $say fn(string $line): void — progress output.
     * @return array<string,mixed> The report.
     */
    public static function runSync(Config $cfg, ?callable $say = null): array
    {
        $say = $say ?? static function (string $s): void {
        };

        $sources = [];
        foreach (self::candidates($cfg, null) as $path => $meta) {
            $say('Reading ' . $path . ' ...');
            $sources[] = self::examine($cfg, (string) $path, (array) $meta);
        }

        $report = self::report($sources, $cfg);
        $path = self::writeReport($cfg, $report);
        if ($path !== null) {
            $say('Detection report written to ' . $path);
        }
        return $report;
    }

    /**
     * Every file worth examining, keyed by path, with whatever the config told us.
     *
     * Ladder step 1 (read the webserver config) is tried first and its answers are marked
     * as such, because a format read out of httpd.conf is a fact, not a guess. Ladder step
     * 2's candidates are then added for anything the config did not account for.
     *
     * @return array<string,array<string,mixed>>
     */
    public static function candidates(Config $cfg, ?Job $job): array
    {
        $out = [];

        try {
            $fromConfig = LogDetect::discoverAll((array) $cfg->get('discover', []));
        } catch (\Throwable $e) {
            $fromConfig = [];
            if ($job !== null) {
                $job->note('Could not read the webserver configuration: ' . $e->getMessage());
            }
        }

        foreach ($fromConfig as $path => $meta) {
            if (!@is_file((string) $path)) {
                continue;
            }
            $out[(string) $path] = [
                'origin'        => 'webserver config (' . basename((string) ($meta['config'] ?? '?')) . ')',
                'server'        => (string) ($meta['server'] ?? 'apache'),
                'vhost'         => $meta['vhost'] ?? null,
                'format_string' => (string) ($meta['format'] ?? ''),
                'format_name'   => $meta['format_name'] ?? null,
            ];
        }

        foreach ((array) $cfg->get('discover.fallback_globs', []) as $glob) {
            foreach ((glob((string) $glob) ?: []) as $file) {
                if (isset($out[$file])) {
                    continue;
                }
                $out[$file] = [
                    'origin'        => 'found in the usual location',
                    'server'        => str_contains($file, 'nginx') ? 'nginx' : 'apache',
                    'vhost'         => null,
                    'format_string' => '',
                    'format_name'   => null,
                ];
            }
        }

        return array_slice($out, 0, 20, true);
    }

    /**
     * Examine one file: sample it, grade the format, render the mapping and the examples.
     *
     * THE ALLOWED ROOTS ARE PASSED THROUGH UNWIDENED. An earlier version appended the
     * candidate's own directory to them before calling LogDetect::tailLines(), which meant
     * the Security::safePath() check inside tailLines() could never fail: the file was read,
     * and up to five of its lines were rendered on the review screen, before anything looked
     * at `outside_roots`. Blocking confirmation afterwards does not undo a read.
     *
     * So a candidate outside `allowed_log_roots` is now DESCRIBED but never opened: the
     * path, the vhost and where the candidate came from are all metadata out of the
     * operator's own webserver configuration, and everything that would require reading the
     * file — confidence, mapping, missing fields, sample lines — is left empty. Widening the
     * roots is a separate, explicit decision (Steps::applySources()'s $widen), after which a
     * re-run of detection samples the file normally.
     *
     * @param array<string,mixed> $meta From candidates()
     * @return array<string,mixed> One entry of the report's `sources` list.
     */
    public static function examine(Config $cfg, string $path, array $meta): array
    {
        $roots = (array) $cfg->get('allowed_log_roots', ['/var/log']);

        $source = [
            'path'          => $path,
            'server'        => (string) ($meta['server'] ?? 'apache'),
            'vhost'         => $meta['vhost'] ?? null,
            'source'        => (string) ($meta['origin'] ?? ''),
            'format_name'   => (string) ($meta['format_name'] ?? ''),
            'format_string' => (string) ($meta['format_string'] ?? ''),
            'confidence'    => 0.0,
            'lines_tested'  => 0,
            'lines_parsed'  => 0,
            'confirmed'     => false,
            'outside_roots' => Security::safePath(dirname($path), $roots) === null,
            'mapping'       => [],
            'missing'       => [],
            'samples'       => [],
            'alternatives'  => [],
        ];

        if ($source['outside_roots']) {
            $source['format_name'] = $source['format_name'] !== '' ? $source['format_name'] : 'unknown';
            return $source;
        }

        $lines = LogDetect::tailLines($path, self::SAMPLE_LINES, $roots);
        if ($lines === []) {
            $source['format_name'] = $source['format_name'] !== '' ? $source['format_name'] : 'unknown';
            return $source;
        }
        $source['lines_tested'] = count($lines);

        $fmt = null;
        if ($source['format_string'] !== '') {
            try {
                $fmt = $source['server'] === 'nginx'
                    ? LogFormat::fromNginx($source['format_string'], 'from-config')
                    : LogFormat::fromApache($source['format_string'], 'from-config');
            } catch (\Throwable $e) {
                $fmt = null;
            }
        }

        if ($fmt !== null) {
            [$confidence, $parsed, $records] = self::grade($fmt, $lines);
            $source['confidence']  = $confidence;
            $source['lines_parsed'] = $parsed;
            if ($source['format_name'] === '') {
                $source['format_name'] = 'from your webserver configuration';
            }
        }

        if ($fmt === null || $source['confidence'] < 50.0) {
            $ranked = LogDetect::detectFromSample($lines, 3);
            if ($ranked !== []) {
                $best = $ranked[0];
                if ($fmt === null || $best['confidence'] > $source['confidence']) {
                    $fmt = $best['format'];
                    $source['format_name']   = (string) $best['name'];
                    $source['format_string'] = $fmt->source();
                    $source['confidence']    = (float) $best['confidence'];
                    $source['lines_parsed']  = (int) $best['parsed'];
                    $source['source'] = $source['source'] === ''
                        ? 'matched the built-in format library'
                        : $source['source'] . ' — overridden by the format library, which matches this file better';
                }
                foreach (array_slice($ranked, 1) as $alt) {
                    $source['alternatives'][] = [
                        'name'       => (string) $alt['name'],
                        'confidence' => (float) $alt['confidence'],
                    ];
                }
            } elseif ($fmt === null) {
                $proposal = LogDetect::proposeRegex($lines);
                if ($proposal !== null) {
                    $fmt = LogDetect::formatFromRegex($proposal, 'proposed');
                    $source['format_name']   = 'a pattern generated from your log';
                    $source['format_string'] = $proposal;
                    $source['source'] = 'nothing in the format library matched, so this was generated from the file';
                    if ($fmt !== null) {
                        [$c, $p] = self::grade($fmt, $lines);
                        $source['confidence'] = $c;
                        $source['lines_parsed'] = $p;
                    }
                }
            }
        }

        if ($fmt === null) {
            $source['format_name'] = 'unrecognised';
            return $source;
        }

        [, , $records] = self::grade($fmt, $lines);
        $source['mapping'] = self::mapping($fmt, $records);
        $source['missing'] = self::missing($fmt);
        $source['samples'] = self::samples($fmt, $lines);

        return $source;
    }

    /**
     * Parse rate and structural sample records for one compiled format.
     *
     * @param string[] $lines
     * @return array{0:float,1:int,2:array<int,array<string,string>>}
     */
    private static function grade(LogFormat $fmt, array $lines): array
    {
        if ($lines === []) {
            return [0.0, 0, []];
        }
        $parsed = 0;
        $records = [];
        foreach ($lines as $line) {
            $rec = $fmt->parse((string) $line);
            if ($rec === null) {
                continue;
            }
            $parsed++;
            if (count($records) < self::SHOW_LINES) {
                $records[] = $rec;
            }
        }
        return [round($parsed / count($lines) * 100, 1), $parsed, $records];
    }

    /**
     * The token → field → example table.
     *
     * @param array<int,array<string,string>> $records
     * @return array<int,array{token:string,field:string,example:string}>
     */
    private static function mapping(LogFormat $fmt, array $records): array
    {
        $first = $records[0] ?? [];
        $out = [];

        foreach ($fmt->fieldMap() as $canonical) {
            $canonical = (string) $canonical;
            $field = self::DOC_FIELD[$canonical] ?? null;

            if ($field === null && str_starts_with($canonical, 'header_in.')) {
                $header = substr($canonical, strlen('header_in.'));
                $field = self::headerField($header);
                $canonicalLabel = $header;
            } elseif ($field === null && str_starts_with($canonical, 'var.')) {
                $flat = str_replace('-', '_', substr($canonical, strlen('var.')));
                $field = $flat === 'ssl_protocol' ? 'tls_proto_s'
                    : ($flat === 'ssl_cipher' ? 'tls_cipher_s' : '(not indexed)');
                $canonicalLabel = $canonical;
            } else {
                $canonicalLabel = $canonical;
            }

            $out[] = [
                'token'   => $canonicalLabel,
                'field'   => (string) ($field ?? '(not indexed)'),
                'example' => self::clip((string) ($first[$canonical] ?? '')),
            ];
        }

        return $out;
    }

    /** Header name → Loghound field, for the display table. */
    private static function headerField(string $header): string
    {
        static $map = [
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
        return $map[strtolower($header)] ?? '(not indexed)';
    }

    /**
     * What this format cannot tell us, and what that costs.
     *
     * Computed from Parser::loggedFields(), which is the same function the scorer consults
     * before deciding whether a signal may fire — so this list is exactly the set of rules
     * that will stay silent, not an approximation of it.
     *
     * @return array<int,array{field:string,token:string,why:string}>
     */
    private static function missing(LogFormat $fmt): array
    {
        $have = [];
        try {
            $have = array_flip(Parser::loggedFields($fmt));
        } catch (\Throwable $e) {
            return [];
        }

        $out = [];
        foreach (self::COSTS as $field => [$token, $why]) {
            if (!isset($have[$field])) {
                $out[] = ['field' => $field, 'token' => $token, 'why' => $why];
            }
        }
        return $out;
    }

    /**
     * Five real lines, raw and parsed.
     *
     * These are attacker-controlled bytes: a request path is chosen by whoever sent it.
     * Control characters are replaced here so they cannot reach a terminal, and every
     * value is escaped again at the point of output. Nothing is reformatted otherwise —
     * the operator has to be able to recognise their own traffic.
     *
     * @param string[] $lines
     * @return array<int,array{raw:string,parsed:array<string,string>}>
     */
    private static function samples(LogFormat $fmt, array $lines): array
    {
        $out = [];
        foreach (array_reverse($lines) as $line) {
            if (count($out) >= self::SHOW_LINES) {
                break;
            }
            $rec = $fmt->parse((string) $line);
            if ($rec === null) {
                continue;
            }
            $parsed = [];
            foreach ($rec as $k => $v) {
                $v = (string) $v;
                if ($v === '' || $v === '-') {
                    continue;
                }
                $parsed[(string) $k] = self::clip($v);
            }
            $out[] = ['raw' => self::clip((string) $line, 1000), 'parsed' => $parsed];
        }
        return $out;
    }

    /** Strip control characters and truncate, for any value that will be displayed. */
    private static function clip(string $value, int $max = self::MAX_VALUE): string
    {
        $value = (string) preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '?', $value);
        if (mb_strlen($value) > $max) {
            $value = mb_substr($value, 0, $max) . '…';
        }
        return $value;
    }

    /**
     * Assemble the report, carrying forward anything already confirmed.
     *
     * @param array<int,array<string,mixed>> $sources
     * @return array<string,mixed>
     */
    public static function report(array $sources, Config $cfg): array
    {
        $confirmed = [];
        foreach ((array) $cfg->get('sources', []) as $s) {
            if (isset($s['path'])) {
                $confirmed[(string) $s['path']] = true;
            }
        }
        foreach ($sources as $i => $src) {
            $sources[$i]['confirmed'] = isset($confirmed[(string) ($src['path'] ?? '')]);
        }

        return [
            'generated_at' => time(),
            'sources'      => array_values($sources),
        ];
    }

    /**
     * Persist the report where the Settings view reads it.
     *
     * Best effort: a read-only var/ must not turn a successful detection into a failure,
     * because the config is what actually drives ingestion.
     *
     * @param array<string,mixed> $report
     * @return string|null The path written, or null.
     */
    public static function writeReport(Config $cfg, array $report): ?string
    {
        $path = dirname($cfg->path(), 2) . '/var/detect.json';
        $dir = dirname($path);
        if (!is_dir($dir) && !@mkdir($dir, 0750, true) && !is_dir($dir)) {
            return null;
        }
        $json = json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($json === false || @file_put_contents($path, $json) === false) {
            return null;
        }
        @chmod($path, 0640);
        return $path;
    }

    /**
     * Read back the last report, or an empty one.
     *
     * @return array<string,mixed>
     */
    public static function lastReport(Config $cfg): array
    {
        $path = dirname($cfg->path(), 2) . '/var/detect.json';
        if (!is_file($path)) {
            return ['sources' => []];
        }
        $raw = @file_get_contents($path);
        $data = is_string($raw) ? json_decode($raw, true) : null;
        return is_array($data) ? $data : ['sources' => []];
    }

    /**
     * Build a source entry for a path the operator typed in, refusing anything unsafe.
     *
     * TWO checks, both mandatory:
     *
     *  - the path must resolve INSIDE `allowed_log_roots`. That list is what stops the log
     *    setting from becoming an arbitrary-file-read primitive, and the browser installer
     *    never widens it — a widening is a decision, and it is offered separately and
     *    explicitly for paths that the operator's own webserver config pointed at.
     *  - a custom pattern must survive Security::validateUserRegex(), which refuses one
     *    that does not compile and one that backtracks badly enough to wedge the ingest
     *    daemon. Rejecting it here is the only moment a human is present to fix it.
     *
     * @return array{ok:bool,error:string,source:array<string,mixed>}
     */
    public static function manualSource(Config $cfg, string $path, string $format, string $regex): array
    {
        $fail = static fn(string $msg): array => ['ok' => false, 'error' => $msg, 'source' => []];

        $path = trim($path);
        if ($path === '') {
            return $fail('Enter the full path of an access log file.');
        }
        if (!@is_file($path)) {
            return $fail('There is no file at ' . $path . ' that this server can see.');
        }

        $roots = (array) $cfg->get('allowed_log_roots', []);
        if (Security::safePath($path, $roots) === null) {
            return $fail(
                $path . ' is outside the directories Loghound is allowed to read ('
                . implode(', ', $roots) . '). That list is a safety control, so it is not '
                . 'widened from a web form: add the directory to allowed_log_roots with the '
                . 'shell wizard, then come back.'
            );
        }

        if ($format === 'custom') {
            $why = Security::validateUserRegex($regex);
            if ($why !== null) {
                return $fail($why);
            }
            $fmt = LogDetect::formatFromRegex($regex, 'custom');
            if ($fmt === null) {
                return $fail('That pattern compiled but captured no named groups, so nothing would be extracted.');
            }
            $meta = [
                'origin'        => 'entered by hand, with a custom pattern',
                'server'        => 'custom',
                'vhost'         => null,
                'format_string' => $regex,
                'format_name'   => 'custom',
            ];
        } else {
            if (LogDetect::formatByName($format) === null) {
                return $fail('Unknown log format: ' . $format);
            }
            $meta = [
                'origin'        => 'entered by hand',
                'server'        => str_starts_with($format, 'nginx') ? 'nginx' : 'apache',
                'vhost'         => null,
                'format_string' => '',
                'format_name'   => $format,
            ];
        }

        $source = self::examine($cfg, $path, $meta);
        $source['format_name']   = (string) $meta['format_name'];
        $source['format_string'] = (string) $meta['format_string'];

        return ['ok' => true, 'error' => '', 'source' => $source];
    }

    /**
     * The library formats an operator may pick from by hand.
     *
     * @return array<string,string> name => human label
     */
    public static function formatChoices(): array
    {
        $out = [];
        foreach (array_keys(LogDetect::library()) as $name) {
            $out[(string) $name] = str_replace('_', ' ', (string) $name);
        }
        $out['custom'] = 'custom pattern (regular expression)';
        return $out;
    }
}
