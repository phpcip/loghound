<?php
/**
 * Loghound — the secret scanner runs as part of the test suite.
 *
 * This repository is public, and a secret that reaches a commit stays in the
 * history forever even after the file is deleted. Relying on someone
 * remembering to run a scanner by hand is not a control; running it on every
 * `php tests/run.php` is.
 *
 * The scan itself lives in tests/scan-secrets.php so it can also be used as a
 * pre-commit hook and as a one-off history audit.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

return [
    'no secrets in any tracked file' => static function (): bool {
        $script = __DIR__ . '/scan-secrets.php';
        if (!is_file($script)) {
            throw new \RuntimeException('tests/scan-secrets.php is missing — the safety net is gone');
        }

        $out = [];
        $code = 0;
        exec('php ' . escapeshellarg($script) . ' 2>&1', $out, $code);

        if ($code !== 0) {
            throw new \RuntimeException(
                "The secret scanner found something in a tracked file:\n\n"
                . implode("\n", $out)
            );
        }
        return true;
    },

    'the scanner actually detects a planted secret' => static function (): bool {
        // A scanner nobody has verified is worse than no scanner, because it
        // creates confidence without providing cover. Plant a credential in a
        // temporary file, confirm it is caught, and clean up.
        //
        // The value below is a throwaway generated for this test — it is not,
        // and must never be, a real key from anywhere.
        $tmp = sys_get_temp_dir() . '/lh_canary_' . bin2hex(random_bytes(4)) . '.php';
        file_put_contents(
            $tmp,
            "<?php\n\$config = ['api_key' => '" . str_repeat('a1b2c3d4', 4) . "'];\n"
        );

        // Run THE REAL SCANNER against the planted file. An earlier version of
        // this test re-declared the patterns inline and silently drifted from
        // the scanner, reporting a failure that did not exist in the real code.
        // Testing a copy of the logic tests nothing.
        $out  = [];
        $code = 0;
        exec(
            'php ' . escapeshellarg(__DIR__ . '/scan-secrets.php')
            . ' --file=' . escapeshellarg($tmp) . ' 2>&1',
            $out,
            $code
        );

        @unlink($tmp);

        if ($code === 0) {
            throw new \RuntimeException(
                'The scanner reported clean on a file containing a planted credential; '
                . 'it would not catch a real one either. Output: ' . implode(' | ', $out)
            );
        }
        return true;
    },

    'config/loghound.php is ignored and has never been committed' => static function (): bool {
        $root = dirname(__DIR__);

        // Ignored by git.
        exec('cd ' . escapeshellarg($root) . ' && git check-ignore -q config/loghound.php 2>/dev/null', $o, $code);
        if ($code !== 0) {
            throw new \RuntimeException(
                'config/loghound.php is NOT gitignored — it holds the Opensolr API key, '
                . 'the beacon HMAC secret and the IP salt'
            );
        }

        // And never present in any commit.
        $n = (int) trim((string) shell_exec(
            'cd ' . escapeshellarg($root) . ' && git log --all --oneline -- config/loghound.php 2>/dev/null | wc -l'
        ));
        if ($n !== 0) {
            throw new \RuntimeException(
                "config/loghound.php appears in {$n} commit(s); the history needs rewriting "
                . 'and every secret it held must be rotated'
            );
        }
        return true;
    },

    'runtime state and credential material cannot be committed' => static function (): bool {
        $root = dirname(__DIR__);

        // Each of these would leak either visitor data or a credential. They are
        // checked as paths rather than by scanning content, because the danger is
        // the file existing in a commit at all.
        $mustBeIgnored = [
            'var/state.db',
            'var/install-token',
            'var/badlines.log',
            'config/loghound.php',
            'server.key',
            'server.pem',
            '.env',
            'backup.sql',
            'dump.tar.gz',
        ];

        $leaks = [];
        foreach ($mustBeIgnored as $path) {
            $o = [];
            $code = 0;
            exec(
                'cd ' . escapeshellarg($root) . ' && git check-ignore -q ' . escapeshellarg($path) . ' 2>/dev/null',
                $o,
                $code
            );
            if ($code !== 0) {
                $leaks[] = $path;
            }
        }

        if ($leaks !== []) {
            throw new \RuntimeException(
                'These are NOT gitignored and would be committed: ' . implode(', ', $leaks)
            );
        }
        return true;
    },
];
