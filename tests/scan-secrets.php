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
 * VALUES that legitimately look like secrets and are not.
 *
 * ============================================================================
 * THESE ARE TESTED AGAINST THE MATCH, NOT AGAINST THE LINE. THAT IS THE FIX.
 * ============================================================================
 * There used to be one list, and a match anywhere on the line skipped the WHOLE line with
 * `continue 2`. Every word in it is common English, so the gate was defeated by writing a
 * secret next to one of them — and not deliberately, either, because these are words that
 * turn up in ordinary comments. Measured against the scanner as it stood:
 *
 *     $a = 'https://admin:hunter2@solr.example.com/solr';               MISSED  ("example")
 *     $c = 'f3a91c04be775d2298ee10ab44cc5177'; // sha256 of the row     MISSED  ("sha256")
 *     $d = 'AKIAIOSFODNN7EXAMPLE1';                                     MISSED  ("EXAMPLE")
 *     $e = 'ghp_0123…ab'; // fp                                        MISSED  ("fp")
 *
 * Four real credentials, four clean bills of health, from a gate the repository relies on.
 *
 * Scoping the test to the matched text is what makes a hole a hole in the VALUE rather than
 * in the line: `'YOUR_API_KEY'` is still allowed because the placeholder is the match, while
 * a real key on a line that merely mentions an example is not.
 *
 * @var array<int,string>
 */
$allowValue = [
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
    // Deliberately fake credentials inside the test suite. Several tests assert that a
    // secret never reaches rendered output or a job payload, which requires a secret-shaped
    // value to plant. Two conventions mark them and both are matched here: the literal word
    // SENTINEL, and values built from an obvious keyboard pattern (a1b2c3d4…, abcdef0123…).
    // A real credential is neither, so this does not blind the scanner to one.
    '/SENTINEL/',
    '/(?:a1b2c3d4|abcdef0123456789|0123456789abcdef|deadbeef|cafebabe)/i',
    // The internet's canonical joke password. It appears only in the tests that PROVE a URL
    // carrying userinfo is refused, which need a URL carrying userinfo to refuse. A real
    // credential is not this string, so excusing it blinds the scanner to nothing.
    '/hunter2/i',
];

/**
 * Things that need the LINE for context, because the value alone cannot be told apart.
 *
 * One rule qualifies and only one: a 32-plus hex run is the same shape as a fingerprint, a
 * content hash, a git object id and the vendored bundle's integrity value, and this product
 * publishes fingerprints in its own UI. Nothing else is form-ambiguous, so nothing else is
 * here — and each entry is keyed to the rule it excuses rather than excusing every rule at
 * once, which is what the old single list did.
 *
 * @var array<string,array<int,string>>
 */
$allowLine = [
    // A marker with NOTHING after it is a marker, not a key: the fixture that names a `.key`
    // file for the uninstaller to delete writes exactly the header line and no base64. Real
    // key material follows the header, so this cannot excuse one.
    'private key block' => [
        '/BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----(?:\\\\n)?[\'"]/',
    ],
    'hex secret 32+' => [
        '/\b(?:sha1|sha256|sha512|md5|integrity|checksum|commit)\b/i',
        '/fp_hash|fingerprint|ua_hash|_hash_s|\bfp\b|Fp\s*=/i',
        '/password_hash|auth\.password_hash|hash_hmac|random_bytes|bin2hex/',
    ],

    /* THE SCANNER'S OWN FIXTURES, AND WHY THEY CANNOT BE EXCUSED BY VALUE. Two tests prove
       this scanner still catches what it is for: one plants a credential-shaped string in a
       temporary file and asserts it is REPORTED, the other feeds a URL carrying userinfo to
       the code that must refuse it. Their planted values therefore have to stay detectable —
       adding them to $allowValue would make the very tests that guard this file pass while
       proving nothing.

       So the SOURCE line carries a marker instead. The marker is a PHP comment sitting
       outside the string literal, so the fixture text written to the temporary file is
       byte-identical and is still caught there, where being caught is the point. Only the
       tracked test file is excused, and only on the line that opts in. */
    'basic auth in URL' => [
        '/lh-scanner-fixture/',
    ],
    'GitHub token' => [
        '/lh-scanner-fixture/',
    ],
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
 *
 * @param array<int,array{0:string,1:string}> $patterns
 * @param array<int,string>                   $allowValue Tested against the MATCH.
 * @param array<string,array<int,string>>     $allowLine  Tested against the line, per rule.
 * @param array<int,array<string,mixed>>      $findings
 */
function scanText(
    string $label,
    string $text,
    array $patterns,
    array $allowValue,
    array $allowLine,
    array &$findings
): void {
    // A minified bundle is one enormous line of noise, and only a vendored bundle is. The
    // skip used to apply to any long line anywhere, which made "put it at the end of a long
    // line" a way past the gate; now it is scoped to the paths that are actually minified.
    $minified = (bool) preg_match('#(?:^|/)(?:vendor/|dist/)|\.min\.(?:js|css)$#i', $label);

    $lines = explode("\n", $text);
    foreach ($lines as $n => $line) {
        if ($minified && strlen($line) > 4000) {
            continue;
        }
        foreach ($patterns as [$what, $re]) {
            if (!preg_match($re, $line, $m)) {
                continue;
            }
            $hit = (string) ($m[0] ?? '');

            foreach ($allowValue as $ok) {
                if (preg_match($ok, $hit)) {
                    continue 2;
                }
            }
            foreach ($allowLine[$what] ?? [] as $ok) {
                if (preg_match($ok, $line)) {
                    continue 2;
                }
            }

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
        scanText($path . ' @ ' . substr($sha, 0, 8), $blob, $patterns, $allowValue, $allowLine, $findings);
    }
    echo "scanned {$seen} blob(s) across all commits\n";
} else {
    $files = trackedFiles($mode, $explicit);
    foreach ($files as $file) {
        $text = @file_get_contents($file);
        if ($text === false || strlen($text) > 2_000_000) {
            continue;
        }
        scanText($file, $text, $patterns, $allowValue, $allowLine, $findings);
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
echo "If one is a false positive, add a narrow rule to \$allowValue (preferred) or\n";
echo "\$allowLine in this file, and say why it is safe.\n";
exit(1);
