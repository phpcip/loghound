<?php
/**
 * Loghound — traffic this installation refuses to record, per hostname.
 *
 * WHAT THIS IS, AND WHAT Live\Rules IS NOT. A rule here means the request is never stored:
 * not as a hit, not folded into a session, not counted in any total, not present in any facet.
 * Live\Rules hides a line from one page and changes nothing about the data. The two were kept
 * apart deliberately — tidying a noisy view must never silently throw traffic away, and
 * deciding what the index is made of must not depend on which page somebody had open.
 *
 * BOTH PLANES, OR IT IS NOT AN EXCLUSION. A hostname is measured by the access log, by the
 * beacon, or by both, and a rule that only covered one of them would be a promise the product
 * does not keep: the operator excludes `/health`, sees it vanish from Pages, and finds the
 * same path still arriving as beacon sessions. So this class is consulted in two places —
 * Pipeline::process() in bin/loghound-tail, before enrichment and before the sessionizer, and
 * public/collect.php, before a payload is staged.
 *
 * THE COST IS PAID ONCE AND EARLY. In the tail the check runs after the line is parsed (the
 * fields have to exist to be tested) but before geolocation, ASN and rDNS, so an excluded
 * request costs one preg_match and never reaches a lookup, a session or the batch.
 *
 * `*` ON A PATH IS THE WHOLE HOSTNAME. An operator who wants a host gone entirely should not
 * have to think of a regular expression that matches everything, and `.*` in a field labelled
 * "path" reads like a mistake. It is spelled out rather than inferred: only the exact string
 * `*`, only on the path field.
 *
 * PATTERNS ARE BODIES, NEVER COMPLETE EXPRESSIONS, for the reason Live\Rules gives: a
 * caller-supplied delimiter carries caller-supplied flags, and the flags are ours.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound;

final class Exclusions
{
    /**
     * What a rule may test, mapped to the words the interface shows.
     *
     * Three, and not the live page's eight. These are the facts both planes have: a log line
     * and a beacon payload each know the path, the address and the User-Agent. Status and
     * method exist only on the log side, and a rule that silently did nothing to beacon
     * traffic is the asymmetry this class exists to avoid.
     */
    public const FIELDS = [
        'path'   => 'Request path',
        'ip'     => 'Client address',
        'ua'     => 'User-Agent',
        'client' => 'Client',
        'method' => 'Method',
        'status' => 'Status',
        'query'  => 'Query string',
    ];

    /**
     * Fields a beacon payload cannot carry, so a rule on one of them is log-only.
     *
     * A beacon is always a POST to the collector and never has a status of its own, so a rule
     * on either would quietly do nothing to a host measured by the beacon alone. That is worth
     * having — most traffic has a log behind it — but it is not worth having SILENTLY, so the
     * settings card names them and this list is what it names them from.
     */
    public const LOG_ONLY_FIELDS = ['method', 'status'];

    /** Where the rules live in the configuration file. */
    public const CONFIG_KEY = 'exclusions';

    /** A bound on the per-request cost, and on what a person can reason about. */
    public const MAX_RULES = 100;

    /** Long enough for any sane pattern, short enough to bound the engine. */
    public const MAX_PATTERN = 200;

    /** The path pattern that means "everything from this hostname". */
    public const ALL = '*';

    /** A subject longer than this is truncated before matching; only a User-Agent gets close. */
    private const MAX_SUBJECT = 2048;

    /** @var array<int,array{host:string,field:string,pattern:string,enabled:bool}> */
    private array $rules;

    /** @var array<string,array<int,array{field:string,regex:?string}>> Compiled, grouped by lower-case host. */
    private array $byHost = [];

    /** @var array<string,bool> Hostnames excluded outright. */
    private array $whole = [];

    /**
     * @param array<int,array{host:string,field:string,pattern:string,enabled:bool}> $rules Sanitised.
     */
    private function __construct(array $rules)
    {
        $this->rules = $rules;

        foreach ($this->rules as $rule) {
            if (!$rule['enabled']) {
                continue;
            }

            $host = $rule['host'];
            if ($rule['field'] === 'path' && $rule['pattern'] === self::ALL) {
                $this->whole[$host] = true;
                continue;
            }

            $this->byHost[$host][] = [
                'field' => $rule['field'],
                'regex' => self::wrap($rule['pattern']),
            ];
        }
    }

    /** Read the stored rules. */
    public static function fromConfig(Config $cfg): self
    {
        return new self(self::sanitise((array) $cfg->get(self::CONFIG_KEY, [])));
    }

    /** Build from an already-supplied list, for the save path and for tests. */
    public static function fromList(array $rules): self
    {
        return new self(self::sanitise($rules));
    }

    /**
     * Coerce whatever arrived into the stored shape, dropping what cannot be used.
     *
     * A rule that does not compile is dropped rather than stored, so the matching path never
     * has to suppress an error per request — and the save path reports which one was refused
     * instead of writing a rule that would silently never fire.
     *
     * An empty hostname is allowed and means EVERY hostname. That is the honest reading of
     * "leave it blank", and it is how an operator excludes a scanner probing every vhost.
     *
     * @param array<int|string,mixed> $raw
     * @return array<int,array{host:string,field:string,pattern:string,enabled:bool}>
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

            $whole = $field === 'path' && $pattern === self::ALL;
            if (!$whole && !self::compiles($pattern)) {
                continue;
            }

            $host = is_string($item['host'] ?? null) ? strtolower(trim($item['host'])) : '';
            if ($host !== '' && preg_match('/^[a-z0-9.:_-]{1,253}$/D', $host) !== 1) {
                continue;
            }
            if ($whole && $host === '') {
                continue;
            }

            $out[] = [
                'host'    => $host,
                'field'   => $field,
                'pattern' => $pattern,
                'enabled' => !isset($item['enabled']) || (bool) $item['enabled'],
            ];
        }

        return $out;
    }

    /** Does this pattern compile, as we would run it? */
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

    /** Is anything configured at all? The callers skip the work entirely when not. */
    public function isEmpty(): bool
    {
        return $this->byHost === [] && $this->whole === [];
    }

    /**
     * Should this request be refused?
     *
     * The single entry point both planes use, so the log side and the beacon side cannot
     * disagree about what a rule means. The observed values arrive as a map rather than as
     * positional arguments, because the two planes carry different subsets of them: a log line
     * has a method and a status, a beacon payload has neither, and a caller should be able to
     * state what it knows without counting out empty strings in the right order.
     *
     * A FIELD THE CALLER DID NOT SUPPLY CANNOT MATCH. An absent value is skipped rather than
     * tested as an empty string, so a rule on `method` is inert on the beacon path instead of
     * being accidentally true there — which is the difference between a rule that does nothing
     * on one plane and a rule that refuses everything on it.
     *
     * @param string               $host   The virtual host the request was for.
     * @param array<string,string> $values Field slug (see FIELDS) to the value observed.
     */
    public function excludes(string $host, array $values = []): bool
    {
        $host = strtolower(trim($host));

        if ($host !== '' && isset($this->whole[$host])) {
            return true;
        }

        foreach ([$host, ''] as $scope) {
            if ($scope === '' && $host === '') {
                break;
            }
            foreach ($this->byHost[$scope] ?? [] as $rule) {
                $value = $values[$rule['field']] ?? '';
                if ($value === '') {
                    continue;
                }
                if (preg_match($rule['regex'], substr($value, 0, self::MAX_SUBJECT)) === 1) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * The log-side reading of one parsed hit.
     *
     * A convenience over excludes(), so the tail does not have to know which document field
     * carries which fact — and so that mapping lives in one place if a field is ever renamed.
     *
     * @param array<string,mixed> $hit A parsed line, before enrichment.
     */
    public function excludesHit(array $hit): bool
    {
        return $this->excludes((string) ($hit['host_s'] ?? ''), [
            'path'   => (string) ($hit['path_s'] ?? ''),
            'ip'     => (string) ($hit['ip_s'] ?? ''),
            'ua'     => (string) ($hit['ua_s'] ?? ''),

            /* THE PARSED CLIENT, NOT THE RAW STRING. `ua` matches the whole header, which is
               where a rule has to spell out an entire Chrome User-Agent to name a browser;
               this is the name the parser already worked out — `curl`, `python-requests`,
               `GPTBot`, `Chrome` — so `^curl` or `^python` is the whole rule. The refusal runs
               after Parser::parseLine(), so these fields exist by the time it is consulted;
               a client the parser could not name yields an empty string and matches nothing,
               which is the honest outcome rather than a rule that fires on everything. */
            'client' => (string) ($hit['ua_bot_name_s'] ?? $hit['browser_s'] ?? ''),
            'method' => (string) ($hit['method_s'] ?? ''),
            'status' => isset($hit['status_i']) ? (string) $hit['status_i'] : '',
            'query'  => (string) ($hit['query_s'] ?? ''),
        ]);
    }

    /**
     * The rules as stored, for the settings card to render and the file to carry.
     *
     * @return array<int,array{host:string,field:string,pattern:string,enabled:bool}>
     */
    public function all(): array
    {
        return $this->rules;
    }

    /** How many rules are actually in force. */
    public function activeCount(): int
    {
        $n = count($this->whole);
        foreach ($this->byHost as $rules) {
            $n += count($rules);
        }
        return $n;
    }

    /**
     * The operator's pattern as a complete regex.
     *
     * Identical to Live\Rules::wrap() and deliberately so: two places in the product accept a
     * regular expression from a person, and they must not differ in what that expression
     * means. `~` delimits, an inner `~` is escaped so a pattern cannot end the expression and
     * append flags, matching is case-insensitive, and `u` is absent because a log line is
     * bytes and a rule must not stop matching on invalid UTF-8.
     */
    private static function wrap(string $pattern): string
    {
        return '~' . str_replace('~', '\\~', $pattern) . '~i';
    }
}
