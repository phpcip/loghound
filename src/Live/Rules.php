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
    public const FIELDS = [
        'host'    => 'Hostname',
        'ip'      => 'Client address',
        'path'    => 'Request path',
        'query'   => 'Query string',
        'method'  => 'Method',
        'status'  => 'Status',
        'ua'      => 'User-Agent',
        'browser' => 'Client',
    ];

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

    /**
     * @param array<int,array{field:string,pattern:string,enabled:bool}> $rules Already sanitised.
     */
    private function __construct(array $rules)
    {
        $this->rules = $rules;

        foreach ($this->rules as $i => $rule) {
            if ($rule['enabled']) {
                $this->compiled[$i] = self::wrap($rule['pattern']);
            }
        }
    }

    /**
     * Read the stored rules.
     *
     * Anything malformed in the file is dropped rather than refused: this is a display filter,
     * and a typo in it must not be able to stop the live page from loading.
     */
    public static function fromConfig(Config $cfg): self
    {
        return new self(self::sanitise((array) $cfg->get(self::CONFIG_KEY, [])));
    }

    /** Build from an already-sanitised list, for the save path and for tests. */
    public static function fromList(array $rules): self
    {
        return new self(self::sanitise($rules));
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
        return count($this->compiled);
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
