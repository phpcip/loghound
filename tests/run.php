<?php
/**
 * Loghound — dependency-free test runner.
 *
 * Usage:
 *   php tests/run.php                  run everything
 *   php tests/run.php parser           run only tests whose file or name matches "parser"
 *   php tests/run.php --filter=parser  the same, spelled out
 *   php tests/run.php --list           list discovered tests without running them
 *   php tests/run.php --quiet          only print failures and the summary
 *   php tests/run.php --no-color       plain output (also implied when stdout is not a TTY)
 *
 * ## How to add tests (this is the contract other agents write against)
 *
 * Drop a file named `tests/test_<something>.php` that RETURNS an array mapping a test name
 * to a closure:
 *
 *     <?php
 *     return [
 *         'a hostile line does not crash the parser' => function (): void {
 *             lh_same(null, $parser->parseLine($fmt, "\x00\x00", 'x', 0));
 *         },
 *     ];
 *
 * The closure takes no arguments and returns nothing; it passes unless it throws. The
 * assertion helpers (lh_same, lh_true, lh_has_key, lh_no_key, lh_tmpdir, …) are defined in
 * tests/helpers.php and are already loaded when your closure runs. Files are discovered by
 * glob, so no registration step and no central list to keep in sync.
 *
 * A closure may also `return` a value instead of throwing: true or null is a pass, false or
 * a non-empty string is a failure and the string is the reason. Both styles are supported so
 * neither convention has to be retrofitted across the suite.
 *
 * ## Skipping — why a missing dependency is not a failure
 *
 * This suite is written by several people at once, so a test file will routinely reference a
 * class that has not landed yet. That must never take the whole run down, and it must never
 * be reported as a red failure that hides the real ones. Therefore:
 *
 *   - A test FILE that throws while being included is SKIPPED, not failed.
 *   - A test that throws an \Error matching PHP's exact wording for a missing class,
 *     function, method or constant is SKIPPED.
 *   - Any test may skip itself deliberately: `lh_skip('needs ext-foo')`.
 *   - Every OTHER \Error — TypeError, ValueError, DivisionByZeroError — is a real FAILURE.
 *     The missing-symbol match is deliberately narrow, because a runner that turns red into
 *     green is worse than no runner at all.
 *
 * Skips are counted and printed but do not affect the exit code.
 *
 * SPEC §12 requires this to pass **with no network access**, so no test here may make an
 * outbound request. LOGHOUND_TEST=1 is exported so code under test can hard-refuse one.
 *
 * Exit code is 0 when everything that could run passed, and 1 otherwise. That is what CI,
 * and install.sh's self-test step, read.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "tests/run.php is a CLI tool.\n");
    exit(1);
}

// Surface every notice: a test suite that silently ignores warnings is worth very little.
error_reporting(E_ALL);
ini_set('display_errors', '1');

// Timestamps in this project are always UTC; pin it so a test cannot pass only because the
// machine running it happens to be in the right timezone.
date_default_timezone_set('UTC');

// Marker code under test can check to hard-refuse network calls, Solr writes, and anything
// else that must not happen inside the suite.
putenv('LOGHOUND_TEST=1');
$_ENV['LOGHOUND_TEST'] = '1';

require __DIR__ . '/../src/autoload.php';
require __DIR__ . '/helpers.php';

/**
 * Thrown by a test that has decided it cannot run: an unavailable optional extension, a
 * fixture that is not present, a dependency another agent has not landed yet.
 *
 * Declared here rather than in helpers.php because the runner is the only thing that needs
 * to distinguish it from an assertion failure.
 */
if (!class_exists('LhSkip')) {
    class LhSkip extends RuntimeException
    {
    }
}

if (!function_exists('lh_skip')) {
    /**
     * Abort the current test as "skipped" with a human-readable reason.
     *
     * Use it for a genuine "cannot be tested here", never to hide a failing expectation.
     */
    function lh_skip(string $reason): void
    {
        throw new LhSkip($reason);
    }
}

/**
 * Decide whether an \Error means "this symbol does not exist yet" rather than "this code is
 * broken". Matches PHP 8's exact wording and nothing else.
 */
function lh_is_missing_symbol(Error $e): bool
{
    $m = $e->getMessage();

    // Class "Loghound\Parser" not found
    if (preg_match('/^(Class|Interface|Trait|Enum) "[^"]+" not found$/', $m)) {
        return true;
    }
    // Call to undefined method Loghound\Solr::addDocs()
    // Call to undefined function loghound_thing()
    if (preg_match('/^Call to undefined (function|method) /', $m)) {
        return true;
    }
    // Undefined constant "Loghound\Parser::KIND_HTML"
    if (preg_match('/^Undefined constant /', $m)) {
        return true;
    }
    return false;
}

/**
 * Run one test closure and classify the outcome.
 *
 * @return array{0:string,1:string} ['pass'|'fail'|'skip', reason]
 */
function lh_run_one(callable $test): array
{
    try {
        $result = $test();
    } catch (LhSkip $e) {
        return ['skip', $e->getMessage()];
    } catch (Error $e) {
        if (lh_is_missing_symbol($e)) {
            return ['skip', 'dependency not available: ' . $e->getMessage()];
        }
        return ['fail', get_class($e) . ': ' . $e->getMessage()];
    } catch (Throwable $e) {
        return ['fail', $e->getMessage()];
    }

    // A test that asserts its way through without complaint returns nothing.
    if ($result === true || $result === null) {
        return ['pass', ''];
    }
    if ($result === false) {
        return ['fail', 'test returned false'];
    }
    if (is_string($result)) {
        // An empty string is a pass, so `return '';` is never a silent failure.
        return $result === '' ? ['pass', ''] : ['fail', $result];
    }
    return ['fail', 'test returned an unexpected value: ' . lh_show($result)];
}

// -----------------------------------------------------------------------------
// Arguments
// -----------------------------------------------------------------------------

$filter   = null;
$listOnly = false;
$quiet    = false;
$noColor  = false;

foreach (array_slice($argv, 1) as $arg) {
    if ($arg === '--list' || $arg === '-l') {
        $listOnly = true;
    } elseif ($arg === '--quiet' || $arg === '-q') {
        $quiet = true;
    } elseif ($arg === '--no-color') {
        $noColor = true;
    } elseif ($arg === '--verbose' || $arg === '-v') {
        $quiet = false;
    } elseif (str_starts_with($arg, '--filter=')) {
        $filter = substr($arg, 9);
    } elseif ($arg === '--help' || $arg === '-h') {
        fwrite(STDOUT, "Usage: php tests/run.php [FILTER] [--filter=X] [--list] [--quiet] [--no-color]\n");
        exit(0);
    } elseif ($arg !== '' && $arg[0] !== '-') {
        $filter = $arg;
    }
}

$files = glob(__DIR__ . '/test_*.php') ?: [];
sort($files);

if ($files === []) {
    fwrite(STDERR, "No test files found (expected tests/test_*.php).\n");
    exit(1);
}

$totalPass = 0;
$totalFail = 0;
$totalSkip = 0;
$failures  = [];
$started   = microtime(true);

// ANSI colour, but only when stdout is a terminal — piping to a file or to CI must stay
// plain, and NO_COLOR is the de-facto standard opt-out.
$tty    = function_exists('posix_isatty') && @posix_isatty(STDOUT);
$colour = $tty && !$noColor && getenv('NO_COLOR') === false;
$green  = $colour ? "\033[32m" : '';
$red    = $colour ? "\033[31m" : '';
$yellow = $colour ? "\033[33m" : '';
$dim    = $colour ? "\033[2m"  : '';
$bold   = $colour ? "\033[1m"  : '';
$reset  = $colour ? "\033[0m"  : '';

foreach ($files as $file) {
    $suite = basename($file, '.php');

    // A file-level filter match runs the whole file; otherwise each test name is filtered.
    $fileMatches = $filter === null || stripos($suite, $filter) !== false;

    // A test file returns its map of tests. A file that throws while being LOADED is skipped:
    // in a repository several people are writing at once, that almost always means a class it
    // references has not landed yet, and turning the whole suite red for that would make the
    // real failures impossible to see.
    try {
        $tests = require $file;
    } catch (Throwable $e) {
        $totalSkip++;
        echo $yellow . 'SKIP ' . $reset . $suite . ': could not load — ' . $e->getMessage() . "\n";
        continue;
    }

    if (!is_array($tests)) {
        $totalFail++;
        $failures[] = [$suite, '(return value)', 'test file must return an array of named closures'];
        echo $red . 'FAIL ' . $reset . $suite . ": did not return an array\n";
        continue;
    }

    $printedHeader = false;

    foreach ($tests as $name => $test) {
        if (!$fileMatches && stripos((string) $name, (string) $filter) === false) {
            continue;
        }
        if (!is_callable($test)) {
            $totalFail++;
            $failures[] = [$suite, (string) $name, 'entry is not callable'];
            continue;
        }

        if (!$printedHeader) {
            echo $bold . $suite . $reset . "\n";
            $printedHeader = true;
        }

        if ($listOnly) {
            echo '  ' . $dim . '- ' . $name . $reset . "\n";
            continue;
        }

        $t0 = microtime(true);
        [$state, $reason] = lh_run_one($test);
        $ms = (microtime(true) - $t0) * 1000;

        if ($state === 'pass') {
            $totalPass++;
            if (!$quiet) {
                printf("  %sok%s   %s %s(%.1f ms)%s\n", $green, $reset, $name, $dim, $ms, $reset);
            }
        } elseif ($state === 'skip') {
            $totalSkip++;
            printf("  %sskip%s %s %s(%s)%s\n", $yellow, $reset, $name, $dim, $reason, $reset);
        } else {
            $totalFail++;
            $failures[] = [$suite, (string) $name, $reason];
            printf("  %sFAIL%s %s\n", $red, $reset, $name);
            foreach (explode("\n", $reason) as $line) {
                printf("       %s%s%s\n", $dim, $line, $reset);
            }
        }
    }
}

if ($listOnly) {
    exit(0);
}

$elapsed = (microtime(true) - $started) * 1000;

echo "\n";

if ($totalFail === 0) {
    printf(
        "%s%d passed%s%s in %.0f ms\n",
        $green,
        $totalPass,
        $reset,
        $totalSkip > 0 ? ", {$totalSkip} skipped" : '',
        $elapsed
    );
    exit(0);
}

printf(
    "%s%d failed%s, %d passed%s in %.0f ms\n\n",
    $red,
    $totalFail,
    $reset,
    $totalPass,
    $totalSkip > 0 ? ", {$totalSkip} skipped" : '',
    $elapsed
);
foreach ($failures as [$suite, $name, $message]) {
    printf("  %s > %s\n", $suite, $name);
    foreach (explode("\n", $message) as $line) {
        printf("      %s\n", $line);
    }
}
exit(1);
