<?php
/**
 * Loghound — translation catalog tool. See docs/TRANSLATING.md.
 *
 *   php tools/i18n.php template        write lang/template.json from the source
 *   php tools/i18n.php check <code>    report what lang/<code>.json (and config/lang/<code>.json) lacks
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

$root = dirname(__DIR__);
require $root . '/src/autoload.php';

use Loghound\I18n;

/** Registered string tables: [class, constant or static method, path of the wanted values]. */
const REGISTRY = [
    ['Loghound\Panel\Layout', 'NAV_GROUPS', '*.label', '*.hint'],
    ['Loghound\Panel\Vocabulary', 'VERDICTS', '*.label', '*.why'],
    ['Loghound\Panel\Vocabulary', 'BOT_CLASSES', '*.label', '*.why'],
    ['Loghound\Panel\Vocabulary', 'AS_TYPES', '*.label', '*.why'],
    ['Loghound\Panel\Vocabulary', 'REFERER_TYPES', '*.label', '*.why'],
    ['Loghound\Panel\Vocabulary', 'BOT_CATEGORIES', '*.label', '*.why'],
    ['Loghound\Panel\Vocabulary', 'PLANES', '*.label', '*.why'],
    ['Loghound\Panel\Vocabulary', 'SIGNED_IN', '*.label', '*.why'],
    ['Loghound\Panel\Vocabulary', 'STATUS_CLASSES', '*.label', '*.why'],
    ['Loghound\Panel\Vocabulary', 'CALLERS', '*.label', '*.why'],
    ['Loghound\Score\Rules', 'REASONS', '*.label', '*.why'],
    ['Loghound\Score\Attacks', 'RULES', '*.label', '*.what', '*.misses', '*.over'],
    ['Loghound\Panel\Bots', 'reasonCatalogue()', '*.label', '*.why'],
    ['Loghound\Live\Rules', 'FIELDS', '*'],
    ['Loghound\Live\Rules', 'BUILTIN', '*.label', '*.why'],
    ['Loghound\Setup\Installer', 'LABELS', '*'],
    ['Loghound\Setup\Teardown', 'STEPS', '*'],
    ['Loghound\Setup\Detector', 'COSTS', '*.1'],
    ['Loghound\Setup\Detector', 'DOC_FIELD', '*'],
    ['Loghound\Setup\Schema', 'ROLES', '*'],
    ['Loghound\Exclusions', 'FIELDS', '*'],
    ['Loghound\AttackPatterns', 'KINDS', '*'],
    ['Loghound\AttackPatterns', 'DEFAULTS', '*.what'],
    ['Loghound\Panel\Seo', 'CHANNELS', '*.0'],
    ['Loghound\Panel\Seo', 'DIMENSIONS', '*.0', '*.1'],
    ['Loghound\Panel\Seo', 'SORTS', '*'],
    ['Loghound\Panel\Seo', 'CRAWLER_CATEGORIES', '*'],
    ['Loghound\Panel\Seo', 'GAP_ENGINES', '*'],
    ['Loghound\Panel\Seo', 'GAP_SORTS', '*'],
    ['Loghound\Panel\Seo', 'METRICS', '*.0', '*.2'],
    ['Loghound\Panel\Sessions', 'SORT_LABELS', '*'],
    ['Loghound\Panel\Sessions', 'ORDER_LABELS', '*'],
    ['Loghound\Panel\Sessions', 'BAND_FIELDS', '*.2'],
    ['Loghound\Panel\Performance', 'HIT_BAND_FIELDS', '*.2'],
    ['Loghound\Panel\Controller', 'EXPORT_DEFAULTS', 'unit', 'control'],
];

/** String constants whose value is shown through I18n::t() at run time. */
const CONSTANT_KEYS = [
    ['Loghound\Setup\Schema', ['CURRENT', 'BEHIND', 'MANAGED', 'UNCONFIGURED', 'UNREADABLE']],
];

/** Every panel view declares SECTIONS; their labels are translated by Controller::sectionList(). */
const SECTION_VIEWS_DIR = '/src/Panel';

final class Catalog
{
    /** @var array<string,array{forms:?array{0:string,1:string},where:array<int,string>}> */
    public array $keys = [];

    /** @var array<int,string> */
    public array $warnings = [];

    public function add(string $key, string $where, ?string $singular = null): void
    {
        if ($key === '' || !preg_match('/[A-Za-z]/', $key)) {
            return;
        }
        if (!isset($this->keys[$key])) {
            $this->keys[$key] = ['forms' => null, 'where' => []];
        }
        if ($singular !== null) {
            $this->keys[$key]['forms'] = [$singular, $key];
        }
        if (count($this->keys[$key]['where']) < 3) {
            $this->keys[$key]['where'][] = $where;
        }
    }
}

function relative(string $root, string $path): string
{
    return ltrim(substr($path, strlen($root)), '/');
}

/** @return array<int,string> */
function files(string $dir, string $ext): array
{
    $out = [];
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $file) {
        if ($file->isFile() && strtolower($file->getExtension()) === $ext && !str_contains($file->getPathname(), '/vendor/')) {
            $out[] = $file->getPathname();
        }
    }
    sort($out);
    return $out;
}

function phpLiteral(string $lit): ?string
{
    if ($lit[0] === "'") {
        return str_replace(['\\\\', "\\'"], ['\\', "'"], substr($lit, 1, -1));
    }
    if ($lit[0] === '"') {
        $body = substr($lit, 1, -1);
        if (preg_match('/(?<!\\\\)\$/', $body)) {
            return null;
        }
        return stripcslashes(str_replace('\\$', '$', $body));
    }
    return null;
}

/** Resolve a class name as written in a file, against its namespace and imports. */
function resolveClass(string $name, string $namespace, array $uses, string $self): string
{
    if ($name === 'self' || $name === 'static') {
        return $self;
    }
    if ($name[0] === '\\') {
        return ltrim($name, '\\');
    }
    $first = explode('\\', $name)[0];
    if (isset($uses[$first])) {
        return $uses[$first] . substr($name, strlen($first));
    }
    return ($namespace === '' ? '' : $namespace . '\\') . $name;
}

function scanPhp(string $root, string $file, Catalog $cat): void
{
    $tokens = token_get_all((string) file_get_contents($file));
    $n = count($tokens);
    $namespace = '';
    $uses = [];
    $class = '';
    $rel = relative($root, $file);
    $skip = static fn ($t): bool => is_array($t) && in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true);

    for ($i = 0; $i < $n; $i++) {
        $t = $tokens[$i];
        if (!is_array($t)) {
            continue;
        }
        if ($t[0] === T_NAMESPACE) {
            $namespace = '';
            for ($j = $i + 1; $j < $n && $tokens[$j] !== ';' && $tokens[$j] !== '{'; $j++) {
                if (is_array($tokens[$j]) && in_array($tokens[$j][0], [T_NAME_QUALIFIED, T_STRING], true)) {
                    $namespace .= $tokens[$j][1];
                }
            }
            continue;
        }
        if ($t[0] === T_USE && $class === '') {
            $name = '';
            $alias = '';
            for ($j = $i + 1; $j < $n && $tokens[$j] !== ';'; $j++) {
                if (is_array($tokens[$j]) && in_array($tokens[$j][0], [T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED, T_STRING], true)) {
                    if ($name !== '' && is_array($tokens[$j - 2] ?? null) && ($tokens[$j - 2][0] ?? null) === T_AS) {
                        $alias = $tokens[$j][1];
                    } elseif ($name === '') {
                        $name = ltrim($tokens[$j][1], '\\');
                    }
                }
            }
            if ($name !== '') {
                $parts = explode('\\', $name);
                $uses[$alias !== '' ? $alias : end($parts)] = $name;
            }
            continue;
        }
        if (in_array($t[0], [T_CLASS, T_INTERFACE, T_TRAIT, T_ENUM], true)) {
            $j = $i + 1;
            while ($skip($tokens[$j])) {
                $j++;
            }
            if (is_array($tokens[$j]) && $tokens[$j][0] === T_STRING) {
                $class = ($namespace === '' ? '' : $namespace . '\\') . $tokens[$j][1];
            }
            continue;
        }
        if ($t[0] !== T_STRING || $t[1] !== 'I18n') {
            continue;
        }
        $j = $i + 1;
        if (($tokens[$j][1] ?? $tokens[$j]) !== '::') {
            continue;
        }
        $method = is_array($tokens[$j + 1]) ? $tokens[$j + 1][1] : '';
        if (!in_array($method, ['t', 'tn', 'html', 'htmln', 'mark'], true)) {
            continue;
        }
        $k = $j + 2;
        while ($skip($tokens[$k])) {
            $k++;
        }
        if ($tokens[$k] !== '(') {
            continue;
        }

        $args = [];
        $current = [];
        $depth = 0;
        for ($m = $k; $m < $n; $m++) {
            $s = is_array($tokens[$m]) ? $tokens[$m][1] : $tokens[$m];
            if ($s === '(' || $s === '[') {
                $depth++;
                if ($depth === 1) {
                    continue;
                }
            }
            if ($s === ')' || $s === ']') {
                $depth--;
                if ($depth === 0) {
                    $args[] = $current;
                    break;
                }
            }
            if ($s === ',' && $depth === 1) {
                $args[] = $current;
                $current = [];
                continue;
            }
            if (!$skip($tokens[$m])) {
                $current[] = $tokens[$m];
            }
        }

        $wanted = in_array($method, ['tn', 'htmln'], true) ? 2 : 1;
        $values = [];
        for ($a = 0; $a < $wanted; $a++) {
            $values[] = argValue($args[$a] ?? [], $namespace, $uses, $class);
        }
        $where = $rel . ':' . $t[2];
        if ($values[0] === null || ($wanted === 2 && $values[1] === null)) {
            $cat->warnings[] = $where . '  I18n::' . $method . '() with a key that is not a literal';
            continue;
        }
        if ($wanted === 2) {
            $cat->add($values[1], $where, $values[0]);
        } else {
            $cat->add($values[0], $where);
        }
    }
}

/** A literal chain, or a class constant, as a string; null for anything computed. */
function argValue(array $toks, string $namespace, array $uses, string $class): ?string
{
    if ($toks === []) {
        return null;
    }
    $out = '';
    $expectString = true;
    foreach ($toks as $tok) {
        if ($expectString) {
            if (!is_array($tok) || $tok[0] !== T_CONSTANT_ENCAPSED_STRING) {
                break;
            }
            $value = phpLiteral($tok[1]);
            if ($value === null) {
                return null;
            }
            $out .= $value;
        } elseif ($tok !== '.') {
            $out = null;
            break;
        }
        $expectString = !$expectString;
    }
    if ($out !== null && !$expectString) {
        return $out;
    }

    $text = '';
    foreach ($toks as $tok) {
        $text .= is_array($tok) ? $tok[1] : $tok;
    }
    if (preg_match('/^(\\\\?[A-Za-z_][A-Za-z0-9_\\\\]*)::([A-Z][A-Z0-9_]*)$/', $text, $m) === 1) {
        $fqcn = resolveClass($m[1], $namespace, $uses, $class);
        try {
            $value = (new ReflectionClassConstant($fqcn, $m[2]))->getValue();
            return is_string($value) ? $value : null;
        } catch (Throwable $e) {
            return null;
        }
    }
    return null;
}

function scanJs(string $root, string $file, Catalog $cat): void
{
    $src = (string) file_get_contents($file);
    $rel = relative($root, $file);
    if (!preg_match('/import\s*\{([^}]*)\}\s*from\s*[\'"][^\'"]*i18n\.js[\'"]/', $src, $imp)) {
        return;
    }
    $names = [];
    foreach (explode(',', $imp[1]) as $part) {
        $bits = preg_split('/\s+as\s+/', trim($part));
        if (in_array($bits[0], ['t', 'tn', 'tf', 'tfn'], true)) {
            $names[$bits[1] ?? $bits[0]] = $bits[0];
        }
    }
    if ($names === []) {
        return;
    }
    $alt = implode('|', array_map('preg_quote', array_keys($names)));
    $lit = '(?:\'(?:[^\'\\\\\n]|\\\\.)*\'|"(?:[^"\\\\\n]|\\\\.)*"|`(?:[^`\\\\$]|\\\\.|\$(?!\{))*`)';
    $chain = $lit . '(?:\s*\+\s*' . $lit . ')*';
    $re = '/(?<![A-Za-z0-9_$])(?<![^.]\.)(' . $alt . ')\(\s*(' . $chain . ')(?:\s*,\s*(' . $chain . '))?/';
    preg_match_all($re, $src, $all, PREG_SET_ORDER | PREG_OFFSET_CAPTURE);
    foreach ($all as $m) {
        $fn = $names[$m[1][0]];
        $line = substr_count(substr($src, 0, $m[0][1]), "\n") + 1;
        $where = $rel . ':' . $line;
        $first = jsChain($m[2][0]);
        if (in_array($fn, ['tn', 'tfn'], true)) {
            $second = isset($m[3]) ? jsChain($m[3][0]) : null;
            if ($second === null) {
                $cat->warnings[] = $where . '  ' . $fn . '() without a literal plural form';
                continue;
            }
            $cat->add($second, $where, $first);
        } else {
            $cat->add($first, $where);
        }
    }
    if (preg_match_all('/(?<![A-Za-z0-9_$])(?<![^.]\.)(' . $alt . ')\(\s*(?![\'"`)])/', $src, $dyn, PREG_OFFSET_CAPTURE)) {
        foreach ($dyn[0] as $d) {
            $line = substr_count(substr($src, 0, $d[1]), "\n") + 1;
            $cat->warnings[] = $rel . ':' . $line . '  ' . trim($d[0]) . '… with a key that is not a literal';
        }
    }
}

function jsChain(string $chain): string
{
    preg_match_all('/\'((?:[^\'\\\\\n]|\\\\.)*)\'|"((?:[^"\\\\\n]|\\\\.)*)"|`((?:[^`\\\\$]|\\\\.|\$(?!\{))*)`/', $chain, $parts, PREG_SET_ORDER);
    $out = '';
    foreach ($parts as $p) {
        $body = $p[1] !== '' ? $p[1] : (($p[2] ?? '') !== '' ? $p[2] : ($p[3] ?? ''));
        $out .= json_decode('"' . str_replace(['"', "\\'", '\\`'], ['\\"', "'", '`'], $body) . '"') ?? $body;
    }
    return $out;
}

/** @return array<int,string> */
function pick(mixed $data, string $path): array
{
    $parts = $path === '' ? [] : explode('.', $path);
    $nodes = [$data];
    foreach ($parts as $part) {
        $next = [];
        foreach ($nodes as $node) {
            if (!is_array($node)) {
                continue;
            }
            if ($part === '*') {
                foreach ($node as $child) {
                    $next[] = $child;
                }
            } elseif (array_key_exists($part, $node)) {
                $next[] = $node[$part];
            }
        }
        $nodes = $next;
    }
    return array_values(array_filter($nodes, 'is_string'));
}

function scanRegistry(string $root, Catalog $cat): void
{
    foreach (REGISTRY as $entry) {
        [$class, $source] = $entry;
        try {
            if (str_ends_with($source, '()')) {
                $data = $class::{substr($source, 0, -2)}();
            } else {
                $data = (new ReflectionClassConstant($class, $source))->getValue();
            }
        } catch (Throwable $e) {
            $cat->warnings[] = 'registry  ' . $class . '::' . $source . ' could not be read: ' . $e->getMessage();
            continue;
        }
        foreach (array_slice($entry, 2) as $path) {
            foreach (pick($data, $path) as $value) {
                $cat->add($value, $class . '::' . $source);
            }
        }
    }

    foreach (CONSTANT_KEYS as [$class, $names]) {
        foreach ($names as $name) {
            $value = (new ReflectionClassConstant($class, $name))->getValue();
            if (is_string($value)) {
                $cat->add($value, $class . '::' . $name);
            }
        }
    }

    foreach (files($root . SECTION_VIEWS_DIR, 'php') as $file) {
        $class = 'Loghound\\Panel\\' . basename($file, '.php');
        if (!class_exists($class) || !defined($class . '::SECTIONS')) {
            continue;
        }
        foreach ((array) constant($class . '::SECTIONS') as $section) {
            if (isset($section[1]) && is_string($section[1])) {
                $cat->add($section[1], $class . '::SECTIONS');
            }
        }
    }

    foreach (files($root . '/src/Panel', 'php') as $file) {
        $src = (string) file_get_contents($file);
        if (!preg_match('/function exports\(\): array\s*\{(.*?)\n    \}/s', $src, $m)) {
            continue;
        }
        if (preg_match_all("/'(label|unit)'\s*=>\s*'((?:[^'\\\\]|\\\\.)*)'/", $m[1], $pairs, PREG_SET_ORDER)) {
            foreach ($pairs as $p) {
                $cat->add(str_replace("\\'", "'", $p[2]), relative($root, $file) . ' exports()');
            }
        }
    }
}

function extract_all(string $root): Catalog
{
    $cat = new Catalog();
    foreach (array_merge(files($root . '/src', 'php'), [$root . '/public/index.php']) as $file) {
        scanPhp($root, $file, $cat);
    }
    scanRegistry($root, $cat);
    foreach (files($root . '/public/assets/js', 'js') as $file) {
        if (basename($file) !== 'i18n.js') {
            scanJs($root, $file, $cat);
        }
    }
    ksort($cat->keys, SORT_STRING);
    return $cat;
}

/** @return array<int,string> */
function placeholders(string $text): array
{
    preg_match_all('/\{([A-Za-z0-9_]+)\}/', $text, $m);
    $out = array_values(array_unique($m[1]));
    sort($out);
    return $out;
}

$command = $argv[1] ?? '';

if ($command === 'template') {
    $cat = extract_all($root);
    $out = ['@name' => 'Template', '@locale' => 'en'];
    foreach ($cat->keys as $key => $meta) {
        $out[$key] = $meta['forms'] === null ? $key : ['one' => $meta['forms'][0], 'other' => $meta['forms'][1]];
    }
    $json = json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    file_put_contents($root . '/lang/template.json', $json . "\n");
    fwrite(STDOUT, count($cat->keys) . " strings written to lang/template.json\n");
    foreach ($cat->warnings as $warning) {
        fwrite(STDERR, 'warning: ' . $warning . "\n");
    }
    exit(0);
}

if ($command === 'check' && isset($argv[2])) {
    $code = $argv[2];
    if (!I18n::isAvailable($root, $code) || $code === I18n::SOURCE) {
        fwrite(STDERR, "No catalog for '$code' in lang/ or config/lang/.\n");
        exit(2);
    }
    $cat = extract_all($root);
    [$map] = I18n::catalog($root, $code);
    $missing = array_diff_key($cat->keys, $map);
    $obsolete = array_diff_key($map, $cat->keys);
    $problems = [];
    foreach ($map as $key => $value) {
        if (!isset($cat->keys[$key])) {
            continue;
        }
        $want = placeholders($key);
        if ($cat->keys[$key]['forms'] !== null) {
            $want = array_values(array_unique(array_merge($want, placeholders($cat->keys[$key]['forms'][0]))));
            sort($want);
        }
        foreach ((array) $value as $form => $text) {
            $have = placeholders((string) $text);
            if (array_diff($have, $want) !== []) {
                $problems[] = $key . ' [' . $form . ']: unknown placeholder {' . implode('}, {', array_diff($have, $want)) . '}';
            }
        }
    }
    foreach ($missing as $key => $meta) {
        fwrite(STDOUT, 'missing   ' . json_encode($key, JSON_UNESCAPED_UNICODE) . '   (' . implode(', ', $meta['where']) . ")\n");
    }
    foreach (array_keys($obsolete) as $key) {
        fwrite(STDOUT, 'obsolete  ' . json_encode($key, JSON_UNESCAPED_UNICODE) . "\n");
    }
    foreach ($problems as $problem) {
        fwrite(STDOUT, 'mismatch  ' . $problem . "\n");
    }
    fwrite(STDOUT, sprintf("%d strings, %d missing, %d obsolete, %d placeholder problems\n", count($cat->keys), count($missing), count($obsolete), count($problems)));
    exit($missing === [] && $problems === [] ? 0 : 1);
}

fwrite(STDERR, "Usage: php tools/i18n.php template | check <code>\n");
exit(2);
