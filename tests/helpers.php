<?php
/**
 * Loghound — Test assertion helpers.
 *
 * Dependency-free by design (SPEC §2: no Composer, so no PHPUnit). These functions are
 * loaded by tests/run.php before any test file, so every test file can call them without
 * requiring anything. The guard around the definitions means a test file may also require
 * this file directly — handy when running one file by hand during development.
 *
 * An assertion failure throws; the runner catches it, marks that one test failed and carries
 * on with the rest, so a single broken test never hides the state of the other fifty.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

if (!function_exists('lh_fail')) {
    /**
     * Fail the current test with a message.
     *
     * @throws RuntimeException always
     */
    function lh_fail(string $message): void
    {
        throw new RuntimeException($message);
    }

    /**
     * Render any value as a short, readable string for a failure message.
     *
     * Long values are truncated: a diff of two 4 KB log lines is unreadable and the first
     * 300 characters are always enough to see what went wrong.
     */
    function lh_show($value): string
    {
        if (is_string($value)) {
            $out = "'" . $value . "'";
        } elseif ($value === null) {
            $out = 'null';
        } elseif (is_bool($value)) {
            $out = $value ? 'true' : 'false';
        } elseif (is_array($value)) {
            $out = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
            $out = $out === false ? 'array(?)' : $out;
        } else {
            $out = var_export($value, true);
        }
        return strlen($out) > 300 ? substr($out, 0, 300) . '…' : $out;
    }

    /** Assert a value is truthy. */
    function lh_true($value, string $what = 'value'): void
    {
        if (!$value) {
            lh_fail($what . ' should be true, got ' . lh_show($value));
        }
    }

    /** Assert a value is falsy. */
    function lh_false($value, string $what = 'value'): void
    {
        if ($value) {
            lh_fail($what . ' should be false, got ' . lh_show($value));
        }
    }

    /** Assert strict equality (===). */
    function lh_same($expected, $actual, string $what = 'value'): void
    {
        if ($expected !== $actual) {
            lh_fail($what . ': expected ' . lh_show($expected) . ', got ' . lh_show($actual));
        }
    }

    /** Assert loose equality — for floats and numeric strings. */
    function lh_eq($expected, $actual, string $what = 'value'): void
    {
        if ($expected != $actual) {
            lh_fail($what . ': expected ' . lh_show($expected) . ', got ' . lh_show($actual));
        }
    }

    /** Assert two floats are within $eps of each other. */
    function lh_near(float $expected, float $actual, float $eps, string $what = 'value'): void
    {
        if (abs($expected - $actual) > $eps) {
            lh_fail($what . ': expected ' . $expected . ' ±' . $eps . ', got ' . $actual);
        }
    }

    /** Assert an array has a key. */
    function lh_has_key(array $array, string $key, string $what = 'array'): void
    {
        if (!array_key_exists($key, $array)) {
            lh_fail($what . " should contain key '$key'; keys are " . lh_show(array_keys($array)));
        }
    }

    /**
     * Assert an array does NOT have a key.
     *
     * Used constantly in these tests: SPEC §1 forbids zero-filling an unknown, so "the field
     * is absent" is a behaviour that has to be asserted, not just hoped for.
     */
    function lh_no_key(array $array, string $key, string $what = 'array'): void
    {
        if (array_key_exists($key, $array)) {
            lh_fail($what . " should NOT contain key '$key' (got " . lh_show($array[$key]) . ')');
        }
    }

    /** Assert a string contains a substring. */
    function lh_contains(string $haystack, string $needle, string $what = 'string'): void
    {
        if (!str_contains($haystack, $needle)) {
            lh_fail($what . ' should contain ' . lh_show($needle) . '; got ' . lh_show($haystack));
        }
    }

    /** Assert a callable throws. Returns the exception so the test can inspect it. */
    function lh_throws(callable $fn, string $what = 'call'): Throwable
    {
        try {
            $fn();
        } catch (Throwable $e) {
            return $e;
        }
        lh_fail($what . ' should have thrown');
        // Unreachable; keeps static analysis happy about the return type.
        throw new RuntimeException('unreachable');
    }

    /**
     * Create a throwaway directory tree for a test, returning its path.
     *
     * Tests that need real files on disk (config discovery, the SQLite state store) use this
     * rather than a fixture directory, so they leave nothing behind and cannot collide when
     * two runs overlap.
     */
    function lh_tmpdir(string $prefix = 'lh'): string
    {
        $dir = sys_get_temp_dir() . '/' . $prefix . '_' . bin2hex(random_bytes(6));
        mkdir($dir, 0700, true);
        return $dir;
    }

    /**
     * Recursively delete a directory created by lh_tmpdir().
     *
     * NEVER FOLLOWS A SYMLINK. is_dir() answers true for a link that POINTS AT a
     * directory, so recursing on it deletes the contents of the target — and a test
     * fixture that links to somewhere in the checkout would therefore delete part of the
     * repository when it tidied up. That is not hypothetical: it happened, and it took the
     * whole of src/ with it. A link is removed with unlink(), which detaches the link and
     * leaves whatever it pointed at alone.
     */
    function lh_rmtree(string $dir): void
    {
        if (is_link($dir) || !is_dir($dir)) {
            @unlink($dir);
            return;
        }
        foreach (scandir($dir) ?: [] as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $path = $dir . '/' . $entry;
            (is_dir($path) && !is_link($path)) ? lh_rmtree($path) : @unlink($path);
        }
        @rmdir($dir);
    }

    /** Absolute path to the tests/fixtures directory. */
    function lh_fixture(string $name): string
    {
        return __DIR__ . '/fixtures/' . $name;
    }

    /**
     * Read a fixture log file as an array of lines, with the trailing newline stripped.
     *
     * @return string[]
     */
    function lh_fixture_lines(string $name): array
    {
        $path = lh_fixture($name);
        if (!is_file($path)) {
            lh_fail('missing fixture: ' . $path);
        }
        $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        return $lines === false ? [] : $lines;
    }
}
