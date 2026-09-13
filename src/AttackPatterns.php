<?php
/**
 * Loghound — the operator's own attack patterns, per hostname, on top of the built-in detector.
 *
 * WHAT THIS IS. Score\Attacks is the built-in vocabulary: the same table on every installation,
 * written so that nothing in it can accuse a real visitor on anybody's site. That constraint is
 * exactly why it cannot know that THIS site has no WordPress, and so it cannot call
 * `/wp-json/batch/v1` an attack. This class is where an operator says what is an attack on their
 * own hosts. A request matching one of these patterns is written with `atk_custom_pattern` on
 * `hit_flags_ss` and the patterns themselves on `hit_patterns_ss`, and `atk_custom_pattern` is
 * decisive on its own (Score\Attacks::DECISIVE), because the operator has said so.
 *
 * SHIPPED DEFAULTS ARE SWITCHED OFF, NEVER DELETED. The installation ships DEFAULTS: probes that are
 * an attack on any website — webshell file names, dev and deploy secrets, botnet droppers. An
 * operator who disagrees switches one off; that choice is stored as the default's id in `off`, so
 * the next release cannot quietly add it back, and a default added by a later release starts on.
 *
 * WHAT DID NOT SHIP, AND WHY. The list was curated from a production ban list of 190 patterns, and
 * everything that is a REAL path for somebody was left out: `/wp-admin`, `/wp-login.php`,
 * `/wp-json/`, `/xmlrpc.php`, `/admin.php`, `/login.php`, `/vendor/`, `/node_modules/`, `/swagger`,
 * `/graphql`, `/actuator/`, `/bitrix`, `/typo3/`, `/cgi-bin`, device login pages, and the generic
 * SQL, XSS and traversal shapes that Score\Attacks already names and deliberately keeps
 * non-decisive. On a site that runs none of those, the operator adds them here for that hostname.
 *
 * TWO KINDS OF PATTERN. `text` is a case-insensitive substring of the decoded request (path plus
 * query string, percent-decoded twice, exactly the surface Score\Attacks reads). `regex` is a
 * PCRE body — never a complete expression — wrapped the way Exclusions wraps one: `~` delimits, an
 * inner `~` is escaped, matching is case-insensitive, and the flags are ours. A regex that does not
 * compile is refused on save, patterns are capped in length, and the subject is capped by
 * Attacks::MAX_SURFACE, so a pattern cannot be made to run for long; a match that hits the PCRE
 * backtrack limit returns false and counts as no match.
 *
 * READ ONCE PER PROCESS. The reader loads these when it starts, like exclusions, so a change applies
 * from the next reload of the ingest daemon. Flags are written at ingest and never recomputed.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound;

use Loghound\Score\Attacks;

final class AttackPatterns
{
    /** Where the operator's choices live in the configuration file. */
    public const CONFIG_KEY = 'attack_patterns';

    /** The two pattern kinds, mapped to the words the interface shows. */
    public const KINDS = [
        'text'  => 'Text',
        'regex' => 'Regular expression',
    ];

    /** A bound on per-request cost and on what a person can reason about. */
    public const MAX_RULES = 200;

    /** Long enough for any sane pattern, short enough to bound the engine. */
    public const MAX_PATTERN = 200;

    /** How many matched patterns are written onto one hit. */
    public const MAX_ON_HIT = 5;

    /**
     * The patterns every installation ships with, all switched on.
     *
     * Every entry is a request no visitor's browser makes on any website: a webshell file name, a
     * developer or deployment secret, a botnet dropper, a scanner's own marker. Each is a lower-case
     * substring of the decoded request. The id is the stable key the `off` list stores, so it must
     * never be renamed or reused.
     *
     * @var array<string,array{pattern:string,what:string}>
     */
    public const DEFAULTS = [
        'webshell-wso'          => ['pattern' => '/wso.php', 'what' => 'WSO webshell'],
        'webshell-c99'          => ['pattern' => '/c99.php', 'what' => 'c99 webshell'],
        'webshell-r57'          => ['pattern' => '/r57.php', 'what' => 'r57 webshell'],
        'webshell-shl'          => ['pattern' => '/shl.php', 'what' => 'Webshell name'],
        'webshell-newfile'      => ['pattern' => '/newfile.php', 'what' => 'Dropped webshell name'],
        'webshell-1234'         => ['pattern' => '/1234.php', 'what' => 'Dropped webshell name'],
        'webshell-wp2019'       => ['pattern' => '/wp-2019.php', 'what' => 'Dropped webshell name'],
        'webshell-wpadd'        => ['pattern' => '/wp-add.php', 'what' => 'Dropped webshell name'],
        'webshell-ioxi01'       => ['pattern' => '/ioxi01.php', 'what' => 'Dropped webshell name'],
        'webshell-ioxi02'       => ['pattern' => '/ioxi02.php', 'what' => 'Dropped webshell name'],
        'webshell-luuf'         => ['pattern' => '/luuf.php', 'what' => 'Dropped webshell name'],
        'webshell-admin404'     => ['pattern' => '/admin404.php', 'what' => 'Dropped webshell name'],
        'webshell-xxxss'        => ['pattern' => '/xxxss', 'what' => 'Scanner XSS marker path'],
        'probe-checkwaf'        => ['pattern' => '/?checkwaf', 'what' => 'WAF fingerprinting probe'],
        'probe-nmap'            => ['pattern' => '/nmaplowercheck', 'what' => 'Nmap HTTP scan marker'],
        'probe-shell-query'     => ['pattern' => '/shell?', 'what' => 'IoT botnet shell command probe'],
        'probe-php-cgi'         => ['pattern' => '/php-cgi', 'what' => 'PHP-CGI argument injection probe'],
        'probe-checkacesso'     => ['pattern' => 'checkacesso.php', 'what' => 'Phishing kit probe'],
        'dropper-wget-sh'       => ['pattern' => '/wget.sh', 'what' => 'Botnet dropper script'],
        'dropper-yakuza'        => ['pattern' => '/yakuza.arm4', 'what' => 'Botnet ARM binary'],
        'dropper-ppc'           => ['pattern' => '/c.ppc', 'what' => 'Botnet PowerPC binary'],
        'secret-vite-config'    => ['pattern' => '/vite.config.js', 'what' => 'Front-end build config'],
        'secret-deploy-config'  => ['pattern' => '/.deployment-config', 'what' => 'Deployment config'],
        'secret-app-properties' => ['pattern' => '/application.properties', 'what' => 'Spring application config'],
        'secret-app-ini'        => ['pattern' => '/application.ini', 'what' => 'Application config'],
        'secret-ftpsync'        => ['pattern' => '/ftpsync.settings', 'what' => 'Editor FTP credentials'],
        'secret-ftpconfig'      => ['pattern' => '/.ftpconfig', 'what' => 'Editor FTP credentials'],
        'secret-user-secrets'   => ['pattern' => '/user_secrets.yml', 'what' => 'Secrets file'],
        'secret-bitbucket'      => ['pattern' => '/bitbucket-pipelines.yml', 'what' => 'CI pipeline config'],
        'secret-phpcs'          => ['pattern' => '/phpcs.xml', 'what' => 'Developer tooling config'],
        'secret-nuget'          => ['pattern' => '/.nuget', 'what' => 'Package manager credentials'],
        'secret-concord'        => ['pattern' => '/.concord/', 'what' => 'Deployment tooling directory'],
        'secret-kube'           => ['pattern' => '/.kube/', 'what' => 'Kubernetes credentials'],
        'secret-terraform'      => ['pattern' => '/.terraform/', 'what' => 'Terraform state directory'],
        'secret-ds-store'       => ['pattern' => '/.ds_store', 'what' => 'macOS directory listing file'],
        'secret-bzr'            => ['pattern' => '/.bzr/', 'what' => 'Bazaar repository'],
        'secret-git-dir'        => ['pattern' => '/.git/', 'what' => 'Git repository'],
        'secret-dockerfile'     => ['pattern' => '/dockerfile', 'what' => 'Container build file'],
        'secret-debug-log'      => ['pattern' => '/debug.log', 'what' => 'Exposed debug log'],
        'secret-debug-dbg'      => ['pattern' => '/debug.dbg', 'what' => 'Exposed debug dump'],
        'backup-rar'            => ['pattern' => '/backup.rar', 'what' => 'Site backup archive'],
        'backup-zip'            => ['pattern' => '/backup.zip', 'what' => 'Site backup archive'],
        'backup-7z'             => ['pattern' => '/backup.7z', 'what' => 'Site backup archive'],
        'backup-tar'            => ['pattern' => '/backup.tar', 'what' => 'Site backup archive'],
        'backup-website-bz2'    => ['pattern' => '/website.bz2', 'what' => 'Site backup archive'],
        'backup-sql-xz'         => ['pattern' => '.sql.xz', 'what' => 'Database dump'],
        'backup-sql-tgz'        => ['pattern' => '.sql.tar.gz', 'what' => 'Database dump'],
        'backup-conf-war'       => ['pattern' => 'conf.war', 'what' => 'Java config archive'],
    ];

    /** @var array<int,array{host:string,kind:string,pattern:string,enabled:bool}> Operator rules, sanitised. */
    private array $rules;

    /** @var array<string,bool> Default ids switched off. */
    private array $off;

    /** @var array<string,array<int,array{kind:string,pattern:string,test:string}>> Active tests by lower-case host ('' = every host). */
    private array $byHost = [];

    /**
     * @param array<int,array{host:string,kind:string,pattern:string,enabled:bool}> $rules Sanitised.
     * @param array<int,string>                                                     $off   Sanitised default ids.
     */
    private function __construct(array $rules, array $off)
    {
        $this->rules = $rules;
        $this->off = array_fill_keys($off, true);

        foreach (self::DEFAULTS as $id => $default) {
            if (!isset($this->off[$id])) {
                $this->byHost[''][] = ['kind' => 'text', 'pattern' => $default['pattern'], 'test' => $default['pattern']];
            }
        }

        foreach ($this->rules as $rule) {
            if (!$rule['enabled']) {
                continue;
            }
            $this->byHost[$rule['host']][] = [
                'kind'    => $rule['kind'],
                'pattern' => $rule['pattern'],
                'test'    => $rule['kind'] === 'regex' ? self::wrap($rule['pattern']) : strtolower($rule['pattern']),
            ];
        }
    }

    /** Read the stored choices. */
    public static function fromConfig(Config $cfg): self
    {
        $raw = (array) $cfg->get(self::CONFIG_KEY, []);
        return new self(self::sanitise((array) ($raw['rules'] ?? [])), self::sanitiseOff((array) ($raw['off'] ?? [])));
    }

    /** Build from already-supplied lists, for the save path and for tests. */
    public static function fromLists(array $rules, array $off = []): self
    {
        return new self(self::sanitise($rules), self::sanitiseOff($off));
    }

    /**
     * Coerce posted or stored operator rules into the stored shape, dropping what cannot be used.
     *
     * A regex that does not compile, a pattern that is empty or too long, an unknown kind and a
     * hostname that is not a hostname are all dropped, so matching never has to suppress an error
     * per request; the save path compares counts and reports a refusal. An empty hostname means
     * every hostname, as it does for exclusions.
     *
     * @param array<int|string,mixed> $raw
     * @return array<int,array{host:string,kind:string,pattern:string,enabled:bool}>
     */
    public static function sanitise(array $raw): array
    {
        $out = [];

        foreach ($raw as $item) {
            if (!is_array($item) || count($out) >= self::MAX_RULES) {
                continue;
            }

            $kind = is_string($item['kind'] ?? null) ? $item['kind'] : 'text';
            if (!isset(self::KINDS[$kind])) {
                continue;
            }

            $pattern = is_string($item['pattern'] ?? null) ? trim($item['pattern']) : '';
            if ($pattern === '' || strlen($pattern) > self::MAX_PATTERN || preg_match('/[\x00-\x1f\x7f]/', $pattern) === 1) {
                continue;
            }
            if ($kind === 'regex' && !self::compiles($pattern)) {
                continue;
            }

            $host = is_string($item['host'] ?? null) ? strtolower(trim($item['host'])) : '';
            if ($host !== '' && preg_match('/^[a-z0-9.:_-]{1,253}$/D', $host) !== 1) {
                continue;
            }

            $out[] = [
                'host'    => $host,
                'kind'    => $kind,
                'pattern' => $pattern,
                'enabled' => !isset($item['enabled']) || (bool) $item['enabled'],
            ];
        }

        return $out;
    }

    /**
     * Keep only ids that name a shipped default.
     *
     * @param array<int|string,mixed> $raw
     * @return array<int,string>
     */
    public static function sanitiseOff(array $raw): array
    {
        $out = [];
        foreach ($raw as $id) {
            if (is_string($id) && isset(self::DEFAULTS[$id]) && !in_array($id, $out, true)) {
                $out[] = $id;
            }
        }
        return $out;
    }

    /** Header names an imported CSV may use, mapped to keys. */
    public const CSV_COLUMNS = [
        'Source'   => 'source',
        'Hostname' => 'host',
        'Host'     => 'host',
        'Kind'     => 'kind',
        'Pattern'  => 'pattern',
        'On'       => 'enabled',
        'Enabled'  => 'enabled',
    ];

    /**
     * Patterns read from a CSV file: the operator's rows, and the shipped defaults switched on or off.
     *
     * A row whose Source is "Shipped" and whose pattern is a shipped default sets that default on
     * or off; every other row is an operator pattern in the raw shape sanitise() accepts. Kind
     * accepts the label or the slug and defaults to text. Nothing is trusted: the caller
     * sanitises the rules and sanitiseOff() only keeps ids that exist.
     *
     * @return array{rules:array<int,array{host:string,kind:string,pattern:string,enabled:bool}>,on:array<int,string>,off:array<int,string>}
     */
    public static function fromCsv(string $text): array
    {
        $byPattern = [];
        foreach (self::DEFAULTS as $id => $default) {
            $byPattern[strtolower($default['pattern'])] = $id;
        }

        $kinds = [];
        foreach (self::KINDS as $slug => $label) {
            $kinds[strtolower($slug)] = $slug;
            $kinds[strtolower($label)] = $slug;
        }

        $out = ['rules' => [], 'on' => [], 'off' => []];
        foreach (Csv::readTable($text, self::CSV_COLUMNS, ['pattern']) as $row) {
            $pattern = $row['pattern'] ?? '';
            $enabled = Csv::yes($row['enabled'] ?? '');
            $shippedId = $byPattern[strtolower($pattern)] ?? null;

            if (strtolower($row['source'] ?? '') === 'shipped' && $shippedId !== null) {
                $out[$enabled ? 'on' : 'off'][] = $shippedId;
                continue;
            }

            $host = strtolower($row['host'] ?? '');
            $out['rules'][] = [
                'host'    => $host === 'every host' ? '' : $host,
                'kind'    => $kinds[strtolower($row['kind'] ?? '')] ?? 'text',
                'pattern' => $pattern,
                'enabled' => $enabled,
            ];
        }

        return $out;
    }

    /**
     * The shipped default ids switched off.
     *
     * @return array<int,string>
     */
    public function off(): array
    {
        return array_keys($this->off);
    }

    /** Does this regex body compile, as it would run? */
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
     * The patterns this request matches, in the order they are configured, capped at MAX_ON_HIT.
     *
     * Tested against Score\Attacks::surfaceOf() — the same decoded, lower-cased, length-capped
     * surface the built-in detector reads — so a pattern and a built-in rule can never disagree
     * about what the request said. Rules for the hit's own hostname and rules for every hostname
     * both apply.
     *
     * @param array<string,mixed> $hit A parsed hit document.
     * @return array<int,string>
     */
    public function matches(array $hit): array
    {
        if ($this->byHost === []) {
            return [];
        }

        $surface = Attacks::surfaceOf((string) ($hit['path_s'] ?? ''), (string) ($hit['query_s'] ?? ''));
        if ($surface === '') {
            return [];
        }

        $host = strtolower(trim((string) ($hit['host_s'] ?? '')));
        $scopes = $host === '' ? [''] : ['', $host];

        $found = [];
        foreach ($scopes as $scope) {
            foreach ($this->byHost[$scope] ?? [] as $rule) {
                $hitIt = $rule['kind'] === 'regex'
                    ? @preg_match($rule['test'], $surface) === 1
                    : str_contains($surface, $rule['test']);
                if ($hitIt && !in_array($rule['pattern'], $found, true)) {
                    $found[] = $rule['pattern'];
                    if (count($found) >= self::MAX_ON_HIT) {
                        return $found;
                    }
                }
            }
        }

        return $found;
    }

    /**
     * The operator rules as stored.
     *
     * @return array<int,array{host:string,kind:string,pattern:string,enabled:bool}>
     */
    public function rules(): array
    {
        return $this->rules;
    }

    /** Is this shipped default switched off? */
    public function isOff(string $id): bool
    {
        return isset($this->off[$id]);
    }

    /** How many patterns are actually in force, defaults included. */
    public function activeCount(): int
    {
        $n = 0;
        foreach ($this->byHost as $tests) {
            $n += count($tests);
        }
        return $n;
    }

    /**
     * The operator's regex body as a complete expression.
     *
     * Identical to Exclusions::wrap() on purpose: two places accept a regular expression from a
     * person and they must not differ in what it means.
     */
    private static function wrap(string $pattern): string
    {
        return '~' . str_replace('~', '\\~', $pattern) . '~i';
    }
}
