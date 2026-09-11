<?php
/**
 * Loghound — claims the documentation makes about the code, checked against the code.
 *
 * WHY THIS FILE EXISTS. Seven contradictions between this repository and its own
 * documentation were found by reading both: a rule weighted 25 that two documents called 55,
 * a rule weighted 80 that one called 45, a verdict-matrix row asserting `likely_bot` for an
 * arithmetic that lands in `unknown`, a network type in the panel's vocabulary that the
 * classifier cannot produce, a whole config section missing from the file that claims to show
 * every supported setting, and a count of reason codes that was one short.
 *
 * Every one of those is the same defect: **prose a reader would act on, saying the opposite of
 * what the code does.** Fixing the seven lines is worth nothing on its own, because the next
 * weight change puts them back. So the properties are asserted here, generically, against the
 * constants themselves — a number in a table, a value in a vocabulary and a count in a
 * sentence are all things a test can read.
 *
 * The code is the authority in each case, with one exception that is called out where it
 * happens: a value the panel offered and the classifier could never emit was removed from the
 * panel rather than added to the classifier, because inventing a network class changes what
 * the scoring rules see and nobody asked for a scoring change.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

use Loghound\Config;
use Loghound\Enrich\Asn;
use Loghound\LogDetect;
use Loghound\Panel\Vocabulary;
use Loghound\Score\Rules;
use Loghound\Setup\Steps;

/** The repository root. */
function lh_claims_root(): string
{
    return dirname(__DIR__);
}

/** One documentation file, read whole. */
function lh_claims_doc(string $relative): string
{
    $body = (string) @file_get_contents(lh_claims_root() . '/' . $relative);
    if ($body === '') {
        lh_fail($relative . ' is missing from the repository');
    }
    return $body;
}

/**
 * Every dotted key in a nested configuration array.
 *
 * A list-valued key is a leaf: `sources` and `trusted_proxies` are values, not sections.
 *
 * @param array<string,mixed> $array
 * @return string[]
 */
function lh_claims_keys(array $array, string $prefix = ''): array
{
    $out = [];
    foreach ($array as $key => $value) {
        $dotted = $prefix === '' ? (string) $key : $prefix . '.' . $key;
        if (is_array($value) && $value !== [] && !array_is_list($value)) {
            $out = array_merge($out, lh_claims_keys($value, $dotted));
            continue;
        }
        $out[] = $dotted;
    }
    return $out;
}

/**
 * One documentation file with its whitespace collapsed onto a single line.
 *
 * Markdown wraps, and PHP docblocks wrap harder. The sentence naming a rule and the phrase
 * quoting its weight are routinely the same sentence and different LINES, so a pattern that
 * stops at a newline reads none of them — which is exactly how a documented 45 for a rule
 * weighted 80, and a documented 55 for a rule weighted 25, both survived being read by people.
 */
function lh_claims_flat(string $relative): string
{
    return (string) preg_replace('/\s+/', ' ', lh_claims_doc($relative));
}

/**
 * The one dotted key that is allowed to be missing from the shipped example configuration.
 *
 * `maintenance.delete_hits_after_days` is the other name for `privacy.retention_days`, mirrored
 * by Config so that an upgrade across the rename cannot lose the value. It is ONE number under
 * two names; listing both in the example file would put it in there twice and invite somebody
 * to set them to different values.
 */
const LH_CLAIMS_ALIAS_KEY = 'maintenance.delete_hits_after_days';

/**
 * Every file that could publish a `LogFormat` line to an operator.
 *
 * Source, panel JavaScript and prose all together, because the incident this group of tests
 * was written from was one surface disagreeing with another: the card that told the operator
 * what to paste and the stored format that had to be rebuilt afterwards were maintained in
 * different files by different hands, and neither knew about the other.
 *
 * `tests/` is deliberately absent. A fixture is allowed to contain a stock `combined` line —
 * that is the point of a fixture — and scanning them would make every one of these tests fail
 * for the one reason that does not matter.
 *
 * @return string[] Repository-relative paths.
 */
function lh_claims_format_surfaces(): array
{
    $root = lh_claims_root();
    $files = array_merge(
        (array) glob($root . '/src/*.php'),
        (array) glob($root . '/src/*/*.php'),
        (array) glob($root . '/public/assets/js/*.js'),
        (array) glob($root . '/public/assets/js/views/*.js'),
        (array) glob($root . '/docs/*.md'),
        [$root . '/SPEC.md', $root . '/README.md']
    );

    $out = [];
    foreach ($files as $file) {
        $out[] = ltrim(str_replace($root, '', (string) $file), '/');
    }
    sort($out);
    return $out;
}

/**
 * Every `LogFormat "…" nickname` a body of text publishes.
 *
 * The `s` flag is load-bearing: the recommended format is ONE Apache directive spread over
 * five physical lines with continuation backslashes, and a pattern that stopped at a newline
 * would read the first fifth of it and call the rest prose.
 *
 * THE BODY IS MATCHED LAZILY RATHER THAN BY COUNTING ESCAPES, and that is a correction. A
 * pattern that walked the quoted string properly — `(?:\\.|[^"\\])*` — read Apache's `\"` and
 * markdown's `\"` and stopped dead on JavaScript's `\\"`, so a `LogFormat` literal pasted into
 * a panel view was invisible to every test here. Which is the file the defect was in. The
 * terminator is instead "a quote followed by whitespace and a nickname", which is the shape of
 * the directive in every escaping convention this repository writes it in. The 1200-character
 * cap keeps a stray `LogFormat` in prose from swallowing the rest of a file looking for one.
 *
 * @return array<int,array{format:string,nickname:string,offset:int}>
 */
function lh_claims_logformats(string $body): array
{
    if (!preg_match_all(
        '/LogFormat\s+"(.{0,1200}?)"\s+([A-Za-z0-9_]+)/s',
        $body,
        $hits,
        PREG_SET_ORDER | PREG_OFFSET_CAPTURE
    )) {
        return [];
    }

    $out = [];
    foreach ($hits as $hit) {
        $out[] = [
            'format'   => (string) preg_replace('/\s+/', ' ', $hit[1][0]),
            'nickname' => (string) $hit[2][0],
            'offset'   => (int) $hit[0][1],
        ];
    }
    return $out;
}

/**
 * The nicknames Apache answers to whether or not anybody defined them.
 *
 * Read out of the code's own list rather than retyped, so a name added there is a name these
 * tests start refusing on the same commit.
 *
 * @return string[]
 */
function lh_claims_reserved_nicknames(): array
{
    $method = new ReflectionMethod(LogDetect::class, 'apacheBuiltinFormats');

    return array_map('strval', array_keys((array) $method->invoke(null)));
}

/** A private class constant, for a test that has to know what a classifier can produce. */
function lh_claims_const(string $class, string $name)
{
    $all = (new ReflectionClass($class))->getConstants();
    if (!array_key_exists($name, $all)) {
        lh_fail($class . '::' . $name . ' no longer exists; re-read this test');
    }
    return $all[$name];
}

return [

    'every rule weight printed in a documentation table is the weight the code carries'
        => static function (): void {
            $weights = Rules::WEIGHTS;
            $checked = 0;

            foreach (['SPEC.md', 'docs/DETECTION.md'] as $doc) {
                $body = lh_claims_doc($doc);

                if (!preg_match_all(
                    '/^\|\s*`([a-z0-9_]+)`\s*\|\s*\*{0,2}(\d{1,3})\*{0,2}\s*\|/m',
                    $body,
                    $rows,
                    PREG_SET_ORDER
                )) {
                    continue;
                }

                foreach ($rows as [, $code, $stated]) {
                    if (!isset($weights[$code])) {
                        continue;
                    }
                    $checked++;
                    lh_same(
                        $weights[$code],
                        (int) $stated,
                        $doc . ' states ' . $stated . ' for ' . $code . ', which the ruleset weights '
                        . $weights[$code] . '. A weight in prose that disagrees with the constant is '
                        . 'how an operator decides a rule is decisive when it is corroborating, or the '
                        . 'other way round'
                    );
                }
            }

            lh_true($checked >= 30, 'both weight tables must still be readable by this test');
        },

    'a rule weight quoted in running prose is the weight the code carries'
        => static function (): void {
            $weights = Rules::WEIGHTS;

            $files = array_merge(
                ['docs/BEACON.md', 'docs/DETECTION.md', 'docs/PRIVACY.md', 'README.md', 'SPEC.md'],
                array_map(
                    static fn (string $p): string => 'src/' . basename(dirname($p)) . '/' . basename($p),
                    (array) glob(lh_claims_root() . '/src/Score/*.php')
                )
            );

            foreach ($files as $doc) {
                $body = lh_claims_flat($doc);

                foreach ($weights as $code => $weight) {
                    if (!preg_match_all(
                        '/`' . preg_quote($code, '/') . '`[^.]{0,160}?\b(\d{1,3})\s*points/',
                        $body,
                        $hits,
                        PREG_SET_ORDER
                    )) {
                        continue;
                    }
                    foreach ($hits as [$whole, $stated]) {
                        lh_same(
                            $weight,
                            (int) $stated,
                            $doc . ' says "' . trim($whole) . '" and the ruleset weights ' . $code
                            . ' at ' . $weight
                        );
                    }
                }
            }
        },

    'the verdict matrix agrees with the arithmetic it is describing'
        => static function (): void {
            $rules = new Rules();
            $score = Rules::WEIGHTS['no_interaction'] + Rules::WEIGHTS['single_page_10s'];
            $verdict = $rules->verdictFor((float) $score);

            lh_same('unknown', $verdict, 'a beacon with no interaction on a single short page is ' . $score
                . ' points, which is deliberately short of a verdict');

            foreach (['README.md', 'SPEC.md', 'docs/DETECTION.md'] as $doc) {
                foreach (explode("\n", lh_claims_doc($doc)) as $line) {
                    if (!str_contains($line, 'zero interaction') || !str_starts_with(trim($line), '|')) {
                        continue;
                    }
                    if (preg_match('/^\|\s*`[a-z0-9_]+`\s*\|\s*\*{0,2}\d/', trim($line)) === 1) {
                        continue;
                    }
                    lh_contains(
                        $line,
                        $verdict,
                        $doc . ' has a verdict-matrix row for a session with no interaction that does not '
                        . 'say ' . $verdict . '. The matrix is the first thing anybody reads about this '
                        . 'product, and a row that overstates a verdict is the one claim it cannot make'
                    );
                }
            }
        },

    'the panel offers exactly the network types the classifier can produce'
        => static function (): void {
            $keywords = (array) lh_claims_const(Asn::class, 'TYPE_KEYWORDS');
            $overrides = (array) lh_claims_const(Asn::class, 'TYPE_OVERRIDES');

            $emittable = array_values(array_unique(array_merge(
                array_keys($keywords),
                array_map('strval', array_values($overrides)),
                ['unknown']
            )));
            sort($emittable);

            $offered = Vocabulary::knownValues('as_type_s');
            sort($offered);

            lh_same(
                $emittable,
                $offered,
                'the value browser offers every entry in the vocabulary as a filter, so one the '
                . 'classifier cannot emit is a filter that returns nothing on every index for ever — '
                . 'indistinguishable, to the operator, from "no such traffic this week"'
            );
        },

    'the shipped example configuration really does show every supported setting'
        => static function (): void {
            $defaults = lh_claims_keys(Config::defaults());
            $example = lh_claims_keys((array) require lh_claims_root() . '/config/loghound.example.php');

            $missing = array_values(array_diff($defaults, $example));
            $invented = array_values(array_diff($example, $defaults));

            $missing = array_values(array_diff($missing, [LH_CLAIMS_ALIAS_KEY]));

            lh_same(
                [],
                $missing,
                'config/loghound.example.php says it shows every supported setting; these are in '
                . 'Config::defaults() and not in it: ' . implode(', ', $missing)
            );
            lh_same(
                [],
                $invented,
                'and these are in the example and are not settings at all, which is worse — somebody '
                . 'will set one and wait for it to do something: ' . implode(', ', $invented)
            );

            $body = lh_claims_doc('config/loghound.example.php');
            lh_contains($body, 'maintenance.delete_hits_after_days', 'the alias is named rather than hidden');
        },

    'the example configuration states the same default the code would have used'
        => static function (): void {
            $defaults = Config::defaults();
            $example = (array) require lh_claims_root() . '/config/loghound.example.php';

            foreach (['quota', 'privacy', 'scoring', 'ui'] as $section) {
                foreach ((array) $defaults[$section] as $key => $value) {
                    if (is_array($value) || !array_key_exists($key, (array) $example[$section])) {
                        continue;
                    }
                    lh_same(
                        $value,
                        $example[$section][$key],
                        $section . '.' . $key . ' is documented with a value the code does not use, '
                        . 'which is a lie an operator cannot catch without reading the source'
                    );
                }
            }
        },

    'a count of reason codes stated anywhere is the number the ruleset actually emits'
        => static function (): void {
            $real = count(Rules::reasonCodes());
            $words = [
                10 => 'ten', 11 => 'eleven', 12 => 'twelve', 13 => 'thirteen', 14 => 'fourteen',
                15 => 'fifteen', 16 => 'sixteen', 17 => 'seventeen', 18 => 'eighteen',
                19 => 'nineteen', 20 => 'twenty', 21 => 'twenty-one', 22 => 'twenty-two',
            ];

            lh_true(isset($words[$real]), 'this test needs a word for ' . $real);
            $allowed = [$words[$real], (string) $real];

            $files = array_merge(
                (array) glob(lh_claims_root() . '/src/*.php'),
                (array) glob(lh_claims_root() . '/src/*/*.php'),
                (array) glob(lh_claims_root() . '/docs/*.md'),
                [lh_claims_root() . '/SPEC.md', lh_claims_root() . '/README.md']
            );

            foreach ($files as $file) {
                $body = (string) @file_get_contents((string) $file);
                if ($body === '' || !preg_match_all('/([\w-]+)\s+reason codes/i', $body, $hits, PREG_SET_ORDER)) {
                    continue;
                }
                foreach ($hits as [$whole, $quantifier]) {
                    if (!isset($words[$real]) || !in_array(strtolower($quantifier), array_merge(
                        array_values($words),
                        array_map('strval', array_keys($words))
                    ), true)) {
                        continue;
                    }
                    lh_true(
                        in_array(strtolower($quantifier), $allowed, true),
                        basename((string) $file) . ' says "' . trim($whole) . '" and Rules::reasonCodes() '
                        . 'returns ' . $real . ' — the seventeen weighted rules plus provisional_session, '
                        . 'beacon_only_session and no_bot_signals'
                    );
                }
            }
        },

    'the three synthetic reason codes are emitted, so they are part of the count'
        => static function (): void {
            $codes = Rules::reasonCodes();

            foreach (['provisional_session', 'beacon_only_session', 'no_bot_signals'] as $code) {
                lh_true(
                    in_array($code, $codes, true),
                    $code . ' is worth no points but is written to bot_reasons_ss, so anything counting '
                    . 'what the panel must be able to name has to count it'
                );
                lh_no_key(Rules::WEIGHTS, $code, 'and it carries no weight');
            }

            lh_same(
                count(Rules::WEIGHTS) + 3,
                count($codes),
                'the emittable set is the weighted rules plus exactly those three'
            );
        },

    'no LogFormat this product publishes reuses a nickname Apache already defines'
        => static function (): void {
            $reserved = lh_claims_reserved_nicknames();
            $checked = 0;

            $surfaces = ['Setup\Steps::recommendedLogFormat()' => Steps::recommendedLogFormat()]
                + ['Setup\Steps::durationLogFormat()' => Steps::durationLogFormat()];

            foreach (lh_claims_format_surfaces() as $file) {
                $surfaces[$file] = (string) @file_get_contents(lh_claims_root() . '/' . $file);
            }

            foreach ($surfaces as $where => $body) {
                foreach (lh_claims_logformats($body) as $found) {
                    $checked++;
                    lh_false(
                        in_array($found['nickname'], $reserved, true),
                        $where . ' publishes a LogFormat under the nickname `' . $found['nickname']
                        . '`, which Apache already defines. Debian and Ubuntu declare it in '
                        . 'apache2.conf, and redefining it inside a <VirtualHost> does not reliably '
                        . 'win: configtest passes, the reload succeeds, the lines keep coming out in '
                        . 'the old shape, and nothing is written to any error log. An operator who '
                        . 'follows this advice has no way at all to find out it did nothing'
                    );
                }
            }

            lh_true(
                $checked >= 4,
                'this test must still be finding the published LogFormat lines; it found ' . $checked
            );
        },

    'a LogFormat nickname this product publishes names exactly one format string'
        => static function (): void {
            $byNickname = [];

            $surfaces = ['Setup\Steps::recommendedLogFormat()' => Steps::recommendedLogFormat()]
                + ['Setup\Steps::durationLogFormat()' => Steps::durationLogFormat()];

            foreach (lh_claims_format_surfaces() as $file) {
                $surfaces[$file] = (string) @file_get_contents(lh_claims_root() . '/' . $file);
            }

            foreach ($surfaces as $where => $body) {
                foreach (lh_claims_logformats($body) as $found) {
                    $byNickname[$found['nickname']][$found['format']][] = $where;
                }
            }

            foreach ($byNickname as $nickname => $formats) {
                $where = [];
                foreach ($formats as $places) {
                    $where = array_merge($where, $places);
                }
                lh_same(
                    1,
                    count($formats),
                    'the nickname `' . $nickname . '` is published for ' . count($formats)
                    . ' different format strings, across ' . implode(', ', array_unique($where))
                    . '. Apache keeps the last definition it reads, so an operator who pastes both '
                    . 'gets whichever one came second and no warning that the other was discarded — '
                    . 'the same silent failure as reusing `combined`, one step further in'
                );
            }
        },

    'every surface that suggests changing the log format also says to rescan the source'
        => static function (): void {
            /* PROXIMITY, NOT CONTAINMENT. A file-wide search for the word would pass SPEC.md on
               a `bin/loghound-setup` in its directory listing four hundred lines away, which is
               not an instruction anybody reading the format block would ever see. The window is
               the block the reader is actually in. */
            $window = 2000;
            $checked = 0;

            foreach (lh_claims_format_surfaces() as $file) {
                $body = (string) @file_get_contents(lh_claims_root() . '/' . $file);

                foreach (lh_claims_logformats($body) as $found) {
                    if (!str_contains($found['format'], '%D')) {
                        continue;
                    }
                    $checked++;
                    $near = substr($body, $found['offset'], $window);
                    lh_true(
                        preg_match('/rescan|loghound-setup|re-confirm/i', $near) === 1,
                        $file . ' publishes a LogFormat carrying %D under `' . $found['nickname']
                        . '` and does not, within ' . $window . ' characters, tell the operator to '
                        . 'rescan the source. Loghound stores the compiled format PER SOURCE, so '
                        . 'taking this advice is what breaks the ingest: from the first line of the '
                        . 'new shape every line is a parse error, the counter climbs, and nothing '
                        . 'new reaches the panel. Suggesting the change without the rescan is the '
                        . 'product breaking on its own instructions'
                    );
                }
            }

            lh_true($checked >= 3, 'this test must still be finding the %D formats; it found ' . $checked);
        },

    'the rescan advice says why, not just what, and is never a pasteable line'
        => static function (): void {
            $advice = Steps::RESCAN_ADVICE;

            foreach (['rescan', 'per source', 'parse error'] as $needle) {
                lh_contains(
                    strtolower($advice),
                    $needle,
                    'the rescan advice has to name "' . $needle . '". An operator who is told to '
                    . 'rescan without being told that the stored format is what went wrong will '
                    . 'skip it the next time, because it reads like housekeeping'
                );
            }

            lh_false(
                str_contains($advice, "\n"),
                'the advice is prose rendered inside a <p>; a newline in it suggests it was meant '
                . 'for a <pre>, and the panel puts a Copy button on those'
            );
        },

    'docs/INSTALL.md documents all three ways a %D change silently does nothing'
        => static function (): void {
            $flat = strtolower(lh_claims_flat('docs/INSTALL.md'));

            $causes = [
                'the reused nickname' => [
                    'do not reuse the name',
                    'apache2.conf',
                    'virtual host',
                ],
                'the reload that never happened' => [
                    'graceful reload',
                    'same master process',
                    'sigusr1',
                ],
                'the stored format that is now wrong' => [
                    'stores the log format',
                    'parse error',
                    'rescan the source',
                ],
            ];

            foreach ($causes as $cause => $needles) {
                foreach ($needles as $needle) {
                    lh_contains(
                        $flat,
                        $needle,
                        'docs/INSTALL.md must document ' . $cause . ', and the phrase "' . $needle
                        . '" is missing. All three produce the same symptom — a correct config, a '
                        . 'clean reload, and no durations — so a document that covers two of them '
                        . 'sends the reader round the two they already checked'
                    );
                }
            }

            lh_contains(
                $flat,
                Steps::DURATION_NICKNAME,
                'and it must name the nickname the panel hands out, or the operator who read the '
                . 'card and the operator who read the manual are configuring two different things'
            );
        },

    'the panel builds its duration advice from the code, not from its own copy of it'
        => static function (): void {
            $php = lh_claims_doc('src/Panel/Performance.php');
            $js = lh_claims_doc('public/assets/js/views/performance.js');

            foreach (['Steps::durationLogFormat()', 'Steps::RESCAN_ADVICE'] as $call) {
                lh_contains(
                    $php,
                    $call,
                    'the Performance card must build its empty state from ' . $call . '. The nickname '
                    . 'and the rescan instruction are decided in Setup\Steps and checked against '
                    . 'docs/INSTALL.md here; a second copy in the panel is a copy nothing compares'
                );
            }

            lh_same(
                [],
                lh_claims_logformats($js),
                'and views/performance.js must not carry a LogFormat literal of its own. It did, '
                . 'with a nickname no PHP test could read — which is how a card can go on '
                . 'recommending a format the documentation stopped publishing'
            );
        },

    'the plan allowance is documented as read from the platform, not remembered'
        => static function (): void {
            lh_no_key(
                (array) Config::defaults()['opensolr'],
                'index_limit',
                'a stored allowance goes stale the moment a plan changes, silently'
            );

            foreach (['SPEC.md', 'docs/INSTALL.md', 'docs/INSTALL-WEB.md'] as $doc) {
                $body = lh_claims_doc($doc);
                lh_false(
                    str_contains($body, 'opensolr.index_limit'),
                    $doc . ' still tells the reader about a configuration key that does not exist'
                );
                $lower = strtolower($body);
                lh_true(
                    str_contains($lower, 'get_account_summary') || str_contains($lower, 'account summary'),
                    $doc . ' has to say where the allowance comes from, because the answer changed: the '
                    . 'platform publishes it now and Loghound reads it live'
                );
            }
        },
];
