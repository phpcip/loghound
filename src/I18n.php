<?php
/**
 * Loghound — interface translation. See docs/TRANSLATING.md.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound;

final class I18n
{
    public const SOURCE = 'en';

    private const CODE = '/^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,2}$/D';

    private const CATEGORIES = ['zero', 'one', 'two', 'few', 'many', 'other'];

    private const MAX_BYTES = 8388608;

    private static string $root = '';

    private static string $lang = self::SOURCE;

    /** @var array<string,string|array<string,string>>|null */
    private static ?array $map = null;

    /** @var array<string,string> */
    private static array $meta = [];

    /** @var array<string,\MessageFormatter|false> */
    private static array $icu = [];

    public static function boot(string $root, string $lang): void
    {
        self::$root = rtrim($root, '/');
        self::$lang = self::isAvailable(self::$root, $lang) ? $lang : self::SOURCE;
        self::$map = null;
        self::$meta = [];
    }

    public static function language(): string
    {
        return self::$lang;
    }

    public static function locale(): string
    {
        self::load();
        $locale = self::$meta['@locale'] ?? self::$lang;
        return preg_match(self::CODE, $locale) === 1 ? $locale : self::$lang;
    }

    public static function t(string $text, array $params = []): string
    {
        self::load();
        $hit = self::$map[$text] ?? null;
        if (is_array($hit)) {
            $hit = $hit['other'] ?? null;
        }
        return self::fill(is_string($hit) ? $hit : $text, $params);
    }

    public static function tn(string $one, string $other, int|float $count, array $params = []): string
    {
        return self::fill(self::form($one, $other, $count), $params + ['n' => $count]);
    }

    /** Marks an English string for the catalog without translating it: it is stored as is and translated where it is shown. */
    public static function mark(string $text): string
    {
        return $text;
    }

    /** Escaped translation for an HTML context; $html values are inserted as markup, unescaped. */
    public static function html(string $text, array $html = []): string
    {
        return self::fill(Security::esc(self::t($text)), $html);
    }

    public static function htmln(string $one, string $other, int|float $count, array $html = []): string
    {
        return self::fill(Security::esc(self::form($one, $other, $count)), $html + ['n' => (string) $count]);
    }

    /** `lang` and, when there is a catalog, where the browser fetches it from. */
    public static function htmlAttrs(): string
    {
        $out = 'lang="' . Security::esc(self::locale()) . '"';
        $version = self::version(self::$root, self::$lang);
        if ($version !== '') {
            $out .= ' data-lh-i18n="' . Security::esc('?i18n=' . rawurlencode(self::$lang) . '&h=' . $version) . '"';
        }
        return $out;
    }

    /**
     * Every language that can be selected, code => name in its own language.
     *
     * @return array<string,string>
     */
    public static function available(string $root): array
    {
        $root = rtrim($root, '/');
        $out = [self::SOURCE => 'English'];
        foreach ([$root . '/lang', $root . '/config/lang'] as $dir) {
            foreach (glob($dir . '/*.json') ?: [] as $file) {
                $code = basename($file, '.json');
                if (preg_match(self::CODE, $code) !== 1 || isset($out[$code])) {
                    continue;
                }
                $name = self::read($file)['@name'] ?? null;
                $out[$code] = is_string($name) && trim($name) !== '' ? trim($name) : $code;
            }
        }
        return $out;
    }

    public static function isAvailable(string $root, string $lang): bool
    {
        if ($lang === self::SOURCE) {
            return true;
        }
        return preg_match(self::CODE, $lang) === 1 && self::files(rtrim($root, '/'), $lang) !== [];
    }

    /** Pick a language from an Accept-Language header, among the installed ones. */
    public static function negotiate(string $root, string $header): string
    {
        $offered = self::available($root);
        $best = self::SOURCE;
        $bestQ = 0.0;
        foreach (explode(',', $header) as $i => $part) {
            if ($i >= 20) {
                break;
            }
            $bits = explode(';', trim($part));
            $tag = strtolower(trim($bits[0]));
            $q = 1.0;
            foreach (array_slice($bits, 1) as $param) {
                if (preg_match('/^\s*q=([01](?:\.\d{1,3})?)\s*$/D', $param, $m) === 1) {
                    $q = (float) $m[1];
                }
            }
            foreach ([$tag, explode('-', $tag)[0]] as $candidate) {
                foreach (array_keys($offered) as $code) {
                    if (strtolower($code) === $candidate && $q > $bestQ) {
                        $best = $code;
                        $bestQ = $q;
                    }
                }
            }
        }
        return $best;
    }

    /** The catalog request: `?i18n=<code>&h=<version>`. Answers and exits. */
    public static function serve(string $root, mixed $lang, mixed $version): never
    {
        $root = rtrim($root, '/');
        $lang = is_string($lang) ? $lang : '';
        header('Content-Type: application/json; charset=utf-8');
        header('X-Content-Type-Options: nosniff');

        if (self::files($root, $lang) === []) {
            http_response_code(404);
            header('Cache-Control: no-store');
            exit('{}');
        }

        $current = self::version($root, $lang);
        header($current !== '' && $version === $current
            ? 'Cache-Control: private, max-age=31536000, immutable'
            : 'Cache-Control: no-store');

        [$map, $meta] = self::merge($root, $lang);
        $json = json_encode(
            $meta + $map,
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
        );
        exit(is_string($json) ? $json : '{}');
    }

    /**
     * The merged catalog of one language, for tools/i18n.php.
     *
     * @return array{0:array<string,string|array<string,string>>,1:array<string,string>}
     */
    public static function catalog(string $root, string $lang): array
    {
        return self::merge(rtrim($root, '/'), $lang);
    }

    private static function load(): void
    {
        if (self::$map !== null) {
            return;
        }
        [self::$map, self::$meta] = self::$root === ''
            ? [[], []]
            : self::merge(self::$root, self::$lang);
    }

    /** @return array<int,string> */
    private static function files(string $root, string $lang): array
    {
        if (preg_match(self::CODE, $lang) !== 1) {
            return [];
        }
        $out = [];
        foreach ([$root . '/lang/' . $lang . '.json', $root . '/config/lang/' . $lang . '.json'] as $file) {
            if (is_file($file) && is_readable($file)) {
                $out[] = $file;
            }
        }
        return $out;
    }

    private static function version(string $root, string $lang): string
    {
        if ($root === '') {
            return '';
        }
        $stamp = '';
        foreach (self::files($root, $lang) as $file) {
            $stamp .= $file . ':' . (string) filemtime($file) . ':' . (string) filesize($file) . ';';
        }
        return $stamp === '' ? '' : substr(hash('sha256', $stamp), 0, 16);
    }

    /** @return array{0:array<string,string|array<string,string>>,1:array<string,string>} */
    private static function merge(string $root, string $lang): array
    {
        $map = [];
        $meta = [];
        foreach (self::files($root, $lang) as $file) {
            foreach (self::read($file) as $key => $value) {
                if (str_starts_with($key, '@')) {
                    if (is_string($value)) {
                        $meta[$key] = $value;
                    }
                } else {
                    $map[$key] = $value;
                }
            }
        }
        return [$map, $meta];
    }

    /** @return array<string,string|array<string,string>> */
    private static function read(string $file): array
    {
        $size = @filesize($file);
        if ($size === false || $size > self::MAX_BYTES) {
            return [];
        }
        $raw = @file_get_contents($file);
        $data = is_string($raw) ? json_decode($raw, true, 4) : null;
        if (!is_array($data)) {
            if (is_string($raw) && PHP_SAPI !== 'cli') {
                error_log('Loghound: translation file is not valid JSON and was ignored: ' . $file);
            }
            return [];
        }

        $out = [];
        foreach ($data as $key => $value) {
            if (!is_string($key) || $key === '') {
                continue;
            }
            if (is_string($value)) {
                if ($value !== '') {
                    $out[$key] = $value;
                }
                continue;
            }
            if (is_array($value)) {
                $forms = [];
                foreach (self::CATEGORIES as $category) {
                    if (isset($value[$category]) && is_string($value[$category]) && $value[$category] !== '') {
                        $forms[$category] = $value[$category];
                    }
                }
                if (isset($forms['other'])) {
                    $out[$key] = $forms;
                }
            }
        }
        return $out;
    }

    private static function form(string $one, string $other, int|float $count): string
    {
        self::load();
        $hit = self::$map[$other] ?? null;
        $english = (float) $count === 1.0 ? $one : $other;
        if (is_array($hit)) {
            return $hit[self::category($count)] ?? $hit['other'] ?? $english;
        }
        return is_string($hit) ? $hit : $english;
    }

    private static function fill(string $text, array $params): string
    {
        if ($params === []) {
            return $text;
        }
        $pairs = [];
        foreach ($params as $key => $value) {
            $pairs['{' . $key . '}'] = is_scalar($value) || $value instanceof \Stringable ? (string) $value : '';
        }
        return strtr($text, $pairs);
    }

    /** CLDR plural category of an integer count in the current language. */
    private static function category(int|float $count): string
    {
        $locale = self::locale();
        $base = strtolower(explode('-', $locale)[0]);
        $n = abs($count);

        if ((float) $n !== floor((float) $n)) {
            return self::icuCategory($locale, $count) ?? 'other';
        }
        $n = (int) $n;
        $m10 = $n % 10;
        $m100 = $n % 100;

        switch ($base) {
            case 'zh': case 'ja': case 'ko': case 'vi': case 'th': case 'id': case 'ms': case 'lo': case 'my':
                return 'other';
            case 'fr':
                return $n <= 1 ? 'one' : ($n !== 0 && $n % 1000000 === 0 ? 'many' : 'other');
            case 'ro': case 'mo':
                return $n === 1 ? 'one' : (($n === 0 || ($m100 >= 2 && $m100 <= 19)) ? 'few' : 'other');
            case 'ru': case 'uk': case 'be':
                if ($m10 === 1 && $m100 !== 11) {
                    return 'one';
                }
                return ($m10 >= 2 && $m10 <= 4 && ($m100 < 12 || $m100 > 14)) ? 'few' : 'many';
            case 'pl':
                if ($n === 1) {
                    return 'one';
                }
                return ($m10 >= 2 && $m10 <= 4 && ($m100 < 12 || $m100 > 14)) ? 'few' : 'many';
            case 'cs': case 'sk':
                return $n === 1 ? 'one' : ($n >= 2 && $n <= 4 ? 'few' : 'other');
            case 'en': case 'de': case 'nl': case 'sv': case 'da': case 'nb': case 'no': case 'fi':
            case 'et': case 'el': case 'hu': case 'bg': case 'tr':
                return $n === 1 ? 'one' : 'other';
            case 'es': case 'it': case 'pt': case 'ca':
                if ($n === 1) {
                    return 'one';
                }
                return $n !== 0 && $n % 1000000 === 0 ? 'many' : 'other';
        }

        return self::icuCategory($locale, $count) ?? ($n === 1 ? 'one' : 'other');
    }

    private static function icuCategory(string $locale, int|float $count): ?string
    {
        if (!class_exists(\MessageFormatter::class)) {
            return null;
        }
        if (!isset(self::$icu[$locale])) {
            try {
                self::$icu[$locale] = \MessageFormatter::create(
                    $locale,
                    '{0,plural,zero{zero}one{one}two{two}few{few}many{many}other{other}}'
                ) ?? false;
            } catch (\Throwable $e) {
                self::$icu[$locale] = false;
            }
        }
        $fmt = self::$icu[$locale];
        if ($fmt === false) {
            return null;
        }
        $out = $fmt->format([$count]);
        return is_string($out) && in_array($out, self::CATEGORIES, true) ? $out : null;
    }
}
