#!/usr/bin/env php
<?php
/**
 * Loghound — secret scanner.
 *
 * This repository is public. Anything that reaches a commit is public forever,
 * even if the file is deleted afterwards, because the blob stays in history.
 * .gitignore only helps when a pattern happens to match, so this is the second
 * line of defence: it looks at CONTENT, not filenames.
 *
 * Run it before committing, and it also runs as part of the test suite:
 *
 *     php tests/scan-secrets.php            # working tree, tracked files
 *     php tests/scan-secrets.php --staged   # what is about to be committed
 *     php tests/scan-secrets.php --history  # every blob in every commit (slow)
 *
 * Exit code 0 = clean, 1 = something found. Findings are printed with the file,
 * line number and a redacted excerpt — the point is to tell you where to look,
 * not to reprint the secret into your terminal scrollback.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

$root = dirname(__DIR__);
chdir($root);

$mode = 'tree';
$explicit = [];
foreach (array_slice($argv, 1) as $arg) {
    if ($arg === '--staged') {
        $mode = 'staged';
    } elseif ($arg === '--history') {
        $mode = 'history';
    } elseif (str_starts_with($arg, '--file=')) {
        // Scan specific paths instead of the repository. Used by the test suite
        // to prove the scanner really catches a planted credential — verifying
        // the actual code path rather than a copy of the patterns, which would
        // drift from this file the moment either changed.
        $mode = 'explicit';
        $explicit[] = substr($arg, strlen('--file='));
    } elseif ($arg === '--help' || $arg === '-h') {
        echo "usage: scan-secrets.php [--staged|--history|--file=PATH ...]\n";
        exit(0);
    }
}

/**
 * Patterns that indicate a real secret rather than a mention of one.
 *
 * Each entry is [label, regex]. They are deliberately shaped to match assigned
 * VALUES ("api_key => 'abc123…'") rather than the words themselves, so that
 * documentation explaining what an API key is does not trip the scanner. A
 * scanner that cries wolf gets disabled, and a disabled scanner protects
 * nothing.
 */
$patterns = [
    ['private key block',   '/-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/'],
    ['AWS access key id',   '/\bAKIA[0-9A-Z]{16}\b/'],
    ['AWS secret key',      '/aws_secret_access_key\s*[=:]\s*[\'"][A-Za-z0-9\/+=]{40}[\'"]/i'],
    ['GitHub token',        '/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/'],
    ['Slack token',         '/\bxox[abposr]-[A-Za-z0-9-]{10,}\b/'],
    ['Stripe key',          '/\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/'],
    ['JWT',                 '/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/'],
    ['assigned secret',     '/\b(?:api[_-]?key|apikey|secret|password|passwd|auth[_-]?token|access[_-]?token|agent[_-]?secret)\b\s*(?:=>|=|:)\s*[\'"][A-Za-z0-9\/+_=-]{16,}[\'"]/i'],
    ['basic auth in URL',   '/\b[a-z][a-z0-9+.-]*:\/\/[^\/\s:@]+:[^\/\s:@]{6,}@/i'],
    ['hex secret 32+',      '/\b[a-f0-9]{32,}\b/i'],
];

/**
 * Things that legitimately look like secrets and are not.
 *
 * Kept narrow on purpose. Every entry here is a hole in the scanner, so each one
 * names why it is safe.
 */
$allow = [
    // Placeholder values in the shipped example config and in documentation.
    '/YOUR_[A-Z_]+/',
    '/(?:example|placeholder|changeme|replace[_-]?me|dummy|sample|redacted|xxx+)/i',
    // password_hash() output is a verifier, not a credential; it is meant to be stored.
    '/\$2[aby]\$\d{2}\$/',
    // Git object ids, checksums and the vendored ECharts integrity hash.
    '/\b(?:sha1|sha256|sha512|md5|integrity|checksum|commit)\b/i',
    // Field and function names that contain the word but assign nothing secret.
    '/password_hash|auth\.password_hash|hash_hmac|random_bytes|bin2hex/',
    // Header fingerprints and other content hashes. These are IDENTIFIERS derived
    // from public request headers — the whole product is built on publishing them
    // in the UI — and they are the same shape as a hex API key, so they have to be
    // distinguished by context rather than by form. Narrow on purpose: only lines
    // that name a fingerprint field qualify, so a real hex secret sitting on an
    // unrelated line is still caught.
    '/fp_hash|fingerprint|ua_hash|_hash_s|\bfp\b|Fp\s*=/i',
];

/** @return string[] */
function trackedFiles(string $mode, array $explicit = []): array
{
    if ($mode === 'explicit') {
        return array_values(array_filter($explicit, static fn(string $f): bool => is_file($f)));
    }
    if ($mode === 'staged') {
        exec('git diff --cached --name-only --diff-filter=ACM 2>/dev/null', $out);
    } else {
        exec('git ls-files 2>/dev/null', $out);
    }
    return array_values(array_filter($out, static fn(string $f): bool => is_file($f)));
}

$findings = [];

/**
 * Scan one blob of text and record anything that matches without being allowed.
 */
function scanText(string $label, string $text, array $patterns, array $allow, array &$findings): void
{
    $lines = explode("\n", $text);
    foreach ($lines as $n => $line) {
        if (strlen($line) > 4000) {
            // A minified vendor bundle on one line produces noise, not signal.
            continue;
        }
        foreach ($allow as $ok) {
            if (preg_match($ok, $line)) {
                continue 2;
            }
        }
        foreach ($patterns as [$what, $re]) {
            if (preg_match($re, $line, $m)) {
                $hit = (string) ($m[0] ?? '');
                $findings[] = [
                    'file' => $label,
                    'line' => $n + 1,
                    'what' => $what,
                    // Redacted: enough to locate it, not enough to leak it further.
                    'hint' => substr($hit, 0, 6) . str_repeat('.', 6) . substr($hit, -4),
                ];
                break;
            }
        }
    }
}

if ($mode === 'history') {
    // Every blob ever committed. Slow, but this is the only check that catches a
    // secret that was committed and then deleted.
    exec('git rev-list --objects --all 2>/dev/null', $objects);
    $seen = 0;
    foreach ($objects as $entry) {
        $parts = explode(' ', $entry, 2);
        if (count($parts) !== 2) {
            continue;
        }
        [$sha, $path] = $parts;
        if (!preg_match('/\.(php|js|json|md|txt|xml|yml|yaml|conf|sh|html|css|log)$/i', $path)) {
            continue;
        }
        $blob = shell_exec('git cat-file -p ' . escapeshellarg($sha) . ' 2>/dev/null');
        if ($blob === null || strlen($blob) > 2_000_000) {
            continue;
        }
        $seen++;
        scanText($path . ' @ ' . substr($sha, 0, 8), $blob, $patterns, $allow, $findings);
    }
    echo "scanned {$seen} blob(s) across all commits\n";
} else {
    $files = trackedFiles($mode, $explicit);
    foreach ($files as $file) {
        $text = @file_get_contents($file);
        if ($text === false || strlen($text) > 2_000_000) {
            continue;
        }
        scanText($file, $text, $patterns, $allow, $findings);
    }
    echo 'scanned ' . count($files) . " file(s) (" . $mode . ")\n";
}

if ($findings === []) {
    echo "clean — no secrets found\n";
    exit(0);
}

echo "\nPOSSIBLE SECRETS FOUND — do not commit until resolved:\n\n";
foreach ($findings as $f) {
    printf("  %-52s line %-5d %s  [%s]\n", $f['file'], $f['line'], $f['what'], $f['hint']);
}
echo "\n" . count($findings) . " finding(s).\n";
echo "If one is a false positive, add a narrow rule to \$allow in this file and say why.\n";
exit(1);
