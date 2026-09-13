<?php
/**
 * Loghound — the exclusion rules the live tail applies to its own stream.
 *
 * WHAT THESE ARE NOT. They are not the ingestion blacklist. Nothing here decides what is
 * stored: a rule in this file hides a line from ONE page, and the same request is still read,
 * still scored and still indexed exactly as before. The two were kept apart on purpose — the
 * live page is a window onto every host at once and its rules are a reader's convenience,
 * while the ingestion blacklist is a policy about the data itself and belongs per hostname in
 * Settings. Mixing them would mean tidying a noisy view quietly threw traffic away.
 *
 * WHERE THEY ARE APPLIED. In Live\Reader::poll(), on the row the parser produced and before it
 * is put on the wire. Filtering there rather than in the browser is the whole point: an
 * excluded line costs one preg_match and then nothing — no JSON, no SSE frame, no DOM node.
 *
 * THE PATTERN IS A BODY, NEVER A COMPLETE REGEX. The operator types `^/wp-login` and this
 * class wraps it. A caller-supplied delimiter would let a pattern carry its own modifiers,
 * which is a way to ask PCRE for behaviour the person writing the rule never sees; wrapping
 * here means the flags are ours and only the body is theirs.
 *
 * A PATTERN THAT COSTS TOO MUCH IS TREATED AS NO MATCH. preg_match() returns false rather
 * than 0 when it hits the backtrack limit, and false is not a match — so a catastrophic
 * pattern degrades to showing the line instead of hanging the poll loop. Length caps on both
 * the pattern and the subject keep that from being reached in the first place.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Live;

use Loghound\Config;

final class Rules
{
    /**
     * The row fields a rule may test, mapped to the words the interface shows.
     *
     * Keyed by the key Reader::shape() actually emits, so a rule cannot name a field that
     * will never be there. `status` is compared as text because a rule wants `^4` to mean
     * "any 4xx" far more often than it wants an integer comparison.
     */
    /* THE PATH IS FIRST BECAUSE IT IS THE ANSWER ALMOST EVERY TIME. The order here is the order
       the dialog offers, and the first entry is what an operator gets if they do not look — so
       the first entry has to be the one they meant. With the hostname there, a rule typed as
       `/callback` was silently a hostname rule that could never match anything. */
    public const FIELDS = [
        'path'    => 'Request path',
        'host'    => 'Hostname',
        'ip'      => 'Client address',
        'query'   => 'Query string',
        'method'  => 'Method',
        'status'  => 'Status',
        'ua'      => 'User-Agent',
        'browser' => 'Client',

        /* THE CLASSIFICATION THE PARSER ALREADY MADE. Every row arrives having been sorted into
           page, asset, favicon, robots, api, beacon or other, and matching on that is what lets
           one rule cover every image, script, stylesheet, font and media file at once — and go
           on covering the next format somebody invents, which a list of suffixes cannot.
           `kind_slug` and not `kind`: the latter is the word the row displays ("Image",
           "Stylesheet"), the former is the stable value, and a rule must not break because a
           label was reworded. */
        'kind_slug' => 'Request kind',
    ];

    /**
     * The junk every access log carries, as rules nobody should have to type.
     *
     * WHY FOUR AND NOT FORTY. Each one matches the parser's own classification rather than a
     * file extension, so `assets` is every image, script, stylesheet, source map, font and media
     * file in a single comparison — correct today and still correct when a new format appears.
     * A suffix list would be longer, slower on every line, and wrong the moment it aged.
     *
     * OFF BY DEFAULT, EVERY ONE. The live page's promise is that it shows the log as it is
     * written; a panel that quietly hid most of the traffic on first run would be lying about
     * exactly the thing it exists to show. An operator turns these on because the noise is in
     * their way, which is a decision they have made rather than one made for them.
     *
     * These are not editable and are never written into the operator's own list: they sit above
     * it, and a rule added by hand is evaluated after them. Nothing here can be deleted, so
     * nothing here can be lost.
     *
     * @var array<string,array{field:string,pattern:string,label:string,why:string}>
     */
    public const BUILTIN = [
        'assets' => [
            'field'   => 'kind_slug',
            'pattern' => '^(asset|favicon)$',
            'label'   => 'Images, scripts, stylesheets, fonts, media and icons',
            'why'     => 'Everything a browser fetches because a page told it to. On a busy '
                . 'site this is most of the log and none of it is somebody arriving.',
        ],
        'crawl' => [
            'field'   => 'kind_slug',
            'pattern' => '^robots$',
            'label'   => 'Crawl files',
            'why'     => 'robots.txt, ads.txt, security.txt, sitemaps and /.well-known/. '
                . 'Fetched by crawlers and by nobody reading anything.',
        ],
        'api' => [
            'field'   => 'kind_slug',
            'pattern' => '^api$',
            'label'   => 'Machine endpoints',
            'why'     => 'Paths under /api/, /rest/, /graphql and /wp-json/, plus anything '
                . 'ending .json, .xml, .rss or .atom. Traffic between programs.',
        ],
        'beacon' => [
            'field'   => 'kind_slug',
            'pattern' => '^beacon$',
            'label'   => "Loghound's own beacon",
            'why'     => 'Every measured page posts one. It is how the execution plane is '
                . 'read, and it is never a visit of its own.',
        ],
    ];

    /** Where the built-in switches live: a list of the keys that are ON. */
    public const BUILTIN_CONFIG_KEY = 'live.exclusions_builtin';

    /** Where the rules live in the configuration file. */
    public const CONFIG_KEY = 'live.exclusions';

    /** More rules than a person can reason about, and a bound on the per-line cost. */
    public const MAX_RULES = 40;

    /** Long enough for any sane pattern, short enough that the engine cannot be asked for much. */
    public const MAX_PATTERN = 200;

    /** A subject longer than this is truncated before matching; only a User-Agent ever gets close. */
    private const MAX_SUBJECT = 2048;

    /** @var array<int,array{field:string,pattern:string,enabled:bool}> */
    private array $rules;

    /** @var array<int,string> Compiled patterns, by the same index as $rules. */
    private array $compiled = [];

    /** @var array<int,string> Keys of the built-in groups that are switched on. */
    private array $builtin = [];

    /** @var array<int,array{0:string,1:string}> Compiled built-ins as [field, regex] pairs. */
    private array $builtinCompiled = [];

    /**
     * @param array<int,array{field:string,pattern:string,enabled:bool}> $rules Already sanitised.
     * @param array<int,string> $builtin Keys of BUILTIN that are on, already sanitised.
     */
    private function __construct(array $rules, array $builtin = [])
    {
        $this->rules = $rules;
        $this->builtin = $builtin;

        foreach ($this->rules as $i => $rule) {
            if ($rule['enabled']) {
                $this->compiled[$i] = self::wrap($rule['pattern']);
            }
        }

        foreach ($builtin as $key) {
            $spec = self::BUILTIN[$key] ?? null;
            if ($spec !== null) {
                $this->builtinCompiled[] = [$spec['field'], self::wrap($spec['pattern'])];
            }
        }
    }

    /**
     * The built-in keys that are switched on, from whatever the file holds.
     *
     * An unknown key is dropped rather than kept: a group removed in a later release must not
     * linger in the configuration as a switch for something that no longer exists.
     *
     * @param mixed $raw
     * @return array<int,string>
     */
    public static function sanitiseBuiltin($raw): array
    {
        $out = [];
        foreach ((array) $raw as $key) {
            if (is_string($key) && isset(self::BUILTIN[$key]) && !in_array($key, $out, true)) {
                $out[] = $key;
            }
        }
        return $out;
    }

    /** Which built-in groups are on, for the dialog to render. @return array<int,string> */
    public function builtinOn(): array
    {
        return $this->builtin;
    }

    /**
     * Read the stored rules.
     *
     * Anything malformed in the file is dropped rather than refused: this is a display filter,
     * and a typo in it must not be able to stop the live page from loading.
     */
    public static function fromConfig(Config $cfg): self
    {
        return new self(
            self::sanitise((array) $cfg->get(self::CONFIG_KEY, [])),
            self::sanitiseBuiltin($cfg->get(self::BUILTIN_CONFIG_KEY, []))
        );
    }

    /** Build from an already-sanitised list, for the save path and for tests. */
    public static function fromList(array $rules, array $builtin = []): self
    {
        return new self(self::sanitise($rules), self::sanitiseBuiltin($builtin));
    }

    /**
     * Coerce whatever arrived into the stored shape, dropping what cannot be used.
     *
     * Applied on the way IN from the browser and on the way OUT of the file, so a rule that
     * was hand-edited into the configuration is held to the same limits as one added in the
     * dialog. A pattern PCRE refuses to compile is dropped here, which is what keeps the
     * matching loop free of error suppression it would otherwise need on every line.
     *
     * @param array<int|string,mixed> $raw
     * @return array<int,array{field:string,pattern:string,enabled:bool}>
     */
    public static function sanitise(array $raw): array
    {
        $out = [];

        foreach ($raw as $item) {
            if (!is_array($item) || count($out) >= self::MAX_RULES) {
                continue;
            }

            $field = is_string($item['field'] ?? null) ? $item['field'] : '';
            if (!isset(self::FIELDS[$field])) {
                continue;
            }

            $pattern = is_string($item['pattern'] ?? null) ? trim($item['pattern']) : '';
            if ($pattern === '' || strlen($pattern) > self::MAX_PATTERN) {
                continue;
            }
            if (!self::compiles($pattern)) {
                continue;
            }

            $out[] = [
                'field'   => $field,
                'pattern' => $pattern,
                'enabled' => !isset($item['enabled']) || (bool) $item['enabled'],
            ];
        }

        return $out;
    }

    /**
     * Does this pattern compile, as we would run it?
     *
     * Public because the save path reports a bad pattern back to the operator by name rather
     * than silently dropping it, and it must ask the same question this class answers.
     */
    public static function compiles(string $pattern): bool
    {
        if ($pattern === '' || strlen($pattern) > self::MAX_PATTERN) {
            return false;
        }

        set_error_handler(static fn (): bool => true);
        $ok = preg_match(self::wrap($pattern), '') !== false;
        restore_error_handler();

        return $ok;
    }

    /**
     * Should this row be kept out of the stream?
     *
     * First match wins and the rest are not evaluated, so the common case — a handful of rules
     * and a line that matches the first one — costs one comparison.
     *
     * @param array<string,mixed> $row A row as Reader::shape() built it.
     */
    public function excludes(array $row): bool
    {
        /* THE BUILT-INS ARE TESTED FIRST, and that is the cheap order rather than a statement
           about priority: they are the ones that match most of a noisy log, and first match
           wins, so the common line costs one comparison. They cannot be edited or removed, so
           the operator's own rules are always additional to them and never in conflict. */
        foreach ($this->builtinCompiled as [$field, $regex]) {
            $value = $row[$field] ?? null;
            if ($value !== null && preg_match($regex, substr((string) $value, 0, self::MAX_SUBJECT)) === 1) {
                return true;
            }
        }

        foreach ($this->compiled as $i => $regex) {
            $value = $row[$this->rules[$i]['field']] ?? null;
            if ($value === null) {
                continue;
            }

            $subject = substr((string) $value, 0, self::MAX_SUBJECT);
            if (preg_match($regex, $subject) === 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * The rules as stored, for the dialog to render and for the file to carry.
     *
     * @return array<int,array{field:string,pattern:string,enabled:bool}>
     */
    public function all(): array
    {
        return $this->rules;
    }

    /** How many rules are actually being applied, which is what the page reports. */
    public function activeCount(): int
    {
        return count($this->compiled) + count($this->builtinCompiled);
    }

    /** Header names an imported CSV may use, mapped to keys. */
    public const CSV_COLUMNS = [
        'Source'  => 'source',
        'Field'   => 'field',
        'Pattern' => 'pattern',
        'On'      => 'enabled',
        'Enabled' => 'enabled',
    ];

    /**
     * Rules read from a CSV file: the operator's rows, and the built-in groups switched on or off.
     *
     * Reads the file the live dialog exports. A "Built-in" row whose field and pattern are one of
     * BUILTIN switches that group; every other row is an operator rule in the raw shape
     * sanitise() accepts. Field accepts the label or the slug. Nothing is trusted: the caller
     * sanitises both halves.
     *
     * @return array{rules:array<int,array{field:string,pattern:string,enabled:bool}>,on:array<int,string>,off:array<int,string>}
     */
    public static function fromCsv(string $text): array
    {
        $fields = [];
        foreach (self::FIELDS as $slug => $label) {
            $fields[strtolower($slug)] = $slug;
            $fields[strtolower($label)] = $slug;
        }

        $out = ['rules' => [], 'on' => [], 'off' => []];
        foreach (\Loghound\Csv::readTable($text, self::CSV_COLUMNS, ['field', 'pattern']) as $row) {
            $field = $fields[strtolower($row['field'] ?? '')] ?? '';
            $pattern = $row['pattern'] ?? '';
            $enabled = \Loghound\Csv::yes($row['enabled'] ?? '');

            if (strtolower($row['source'] ?? '') === 'built-in') {
                foreach (self::BUILTIN as $key => $spec) {
                    if ($spec['field'] === $field && $spec['pattern'] === $pattern) {
                        $out[$enabled ? 'on' : 'off'][] = $key;
                        continue 2;
                    }
                }
            }

            $out['rules'][] = ['field' => $field, 'pattern' => $pattern, 'enabled' => $enabled];
        }

        return $out;
    }

    /**
     * Every rule in force, built-ins included, in the order excludes() tests them.
     *
     * For the CSV export, which has to describe what is actually hiding rows rather than only
     * the half an operator typed — a file listing four of nine rules would be read as the whole
     * list and would be wrong about why something is missing from the stream.
     *
     * @return array<int,array{source:string,field:string,pattern:string,enabled:bool,label:string}>
     */
    public function allInForce(): array
    {
        $out = [];

        foreach (self::BUILTIN as $key => $spec) {
            $out[] = [
                'source'  => 'Built-in',
                'field'   => self::FIELDS[$spec['field']] ?? $spec['field'],
                'pattern' => $spec['pattern'],
                'enabled' => in_array($key, $this->builtin, true),
                'label'   => $spec['label'],
            ];
        }

        foreach ($this->rules as $rule) {
            $out[] = [
                'source'  => 'Yours',
                'field'   => self::FIELDS[$rule['field']] ?? $rule['field'],
                'pattern' => $rule['pattern'],
                'enabled' => $rule['enabled'],
                'label'   => '',
            ];
        }

        return $out;
    }

    /**
     * The operator's pattern as a complete regex.
     *
     * `~` is the delimiter and any `~` inside the body is escaped, so a pattern cannot end the
     * expression early and append flags of its own. Case-insensitive because every field here
     * is a hostname, a path, a method or a User-Agent, and nobody writing `wp-login` means to
     * miss `WP-Login`. `u` is deliberately absent: a log line is bytes, and a rule must not
     * stop matching because a User-Agent carried invalid UTF-8.
     */
    private static function wrap(string $pattern): string
    {
        return '~' . str_replace('~', '\\~', $pattern) . '~i';
    }
}
