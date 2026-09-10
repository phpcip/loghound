<?php
/**
 * Loghound — Configuration.
 *
 * The config is a plain PHP array returned from config/loghound.php, which lives OUTSIDE
 * the document root and holds the Opensolr API key and the beacon HMAC secret. It is a PHP
 * file rather than JSON/YAML for one reason: if it is ever served by a misconfigured
 * webserver it executes and returns nothing instead of printing the secrets as text.
 *
 * defaults() below is the single source of truth for what a setting is called and what it
 * defaults to. Anything not listed there is not a supported setting.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound;

final class Config
{
    /** @var array<string,mixed> */
    private array $data;

    private string $path;

    /**
     * @param array<string,mixed> $data
     */
    private function __construct(array $data, string $path)
    {
        $this->data = $data;
        $this->path = $path;
    }

    /**
     * The complete default configuration.
     *
     * Defaults are chosen to be safe rather than convenient: authentication starts as
     * 'none' (which makes the panel refuse to serve at all until it is set), and the
     * beacon secret starts empty so a fresh install cannot accidentally run with a
     * predictable key.
     *
     * @return array<string,mixed>
     */
    public static function defaults(): array
    {
        return [
            // ---- Identity -------------------------------------------------------
            'site_name' => 'Loghound',
            'base_url'  => '',      // e.g. https://loghound.example.com — used for the beacon snippet

            // ---- Solr backend ---------------------------------------------------
            'solr' => [
                // 'opensolr' provisions and manages indexes through the Opensolr API;
                // 'custom' points at any Solr 9 the operator already runs.
                'mode'          => 'opensolr',
                'base_url'      => '',          // custom mode: http://host:8983/solr
                'http_user'     => '',
                'http_pass'     => '',
                // Core names are EMPTY by default and filled in by the setup
                // wizard. They must not be hardcoded: on Opensolr an index name
                // is unique across the WHOLE PLATFORM, not just within one
                // account, so a fixed default would collide for the second
                // person who ever installs this. See Config::newInstallId() and
                // Config::coreName().
                'hits_core'     => '',
                'sessions_core' => '',
                // Random per-installation token that makes the core names
                // unique. Generated once at setup and never changed afterwards:
                // it is part of the identity of the two indexes, so rotating it
                // would orphan the data rather than rename it.
                'install_id'    => '',
                'timeout'       => 20,
                // Batching. softCommit only — a hard commit per batch would destroy
                // throughput and is never needed for near-real-time visibility.
                'batch_size'    => 500,
                'batch_ms'      => 2000,
            ],

            // ---- Opensolr managed backend --------------------------------------
            'opensolr' => [
                'api_base' => 'https://opensolr.com/solr_manager/api',
                'email'    => '',
                'api_key'  => '',   // secret
                'region'   => '',   // one of GET /regions
            ],

            // ---- Log sources ----------------------------------------------------
            // Each entry: ['path' => glob, 'format' => name|regex-id, 'host' => optional override]
            'sources' => [],

            // Roots a configured log path is allowed to resolve inside. Anything outside
            // these is refused, which stops the log-path setting from becoming an
            // arbitrary-file-read primitive.
            'allowed_log_roots' => ['/var/log'],

            // Where to look when auto-detecting on first run.
            'discover' => [
                'apache_configs' => [
                    '/etc/apache2/apache2.conf',
                    '/etc/httpd/conf/httpd.conf',
                ],
                'apache_vhost_dirs' => [
                    '/etc/apache2/sites-enabled',
                    '/etc/httpd/conf.d',
                ],
                'nginx_configs' => ['/etc/nginx/nginx.conf'],
                'nginx_vhost_dirs' => [
                    '/etc/nginx/sites-enabled',
                    '/etc/nginx/conf.d',
                ],
                'fallback_globs' => [
                    '/var/log/apache2/*access*.log',
                    '/var/log/httpd/*access*log',
                    '/var/log/nginx/*access*.log',
                ],
            ],

            // ---- Ingestion ------------------------------------------------------
            'ingest' => [
                'poll_ms'          => 1000,   // tail poll interval
                'session_idle_sec' => 1800,   // 30 minutes
                'keep_raw'         => true,   // store the original line (≈2x index size)
                'catchall'         => true,   // build the full-text catchall field
                'max_line_bytes'   => 16384,  // a longer "line" is malformed or hostile
                'badline_sample'   => 200,    // cap on sampled unparseable lines
            ],

            // ---- Enrichment -----------------------------------------------------
            'enrich' => [
                'geo_enabled'   => true,
                // Opensolr's ezcmd geolocation service. Country/city/lat-lon/timezone only:
                // it carries no ASN or hosting classification, so it feeds the map, not the
                // bot score. ASN comes from Team Cymru and netname from RIR whois.
                'geo_endpoint'  => 'https://ezcmd.com/apps/api_ezip_locator/lookup/%s/1/%s',
                'geo_key'       => '',
                'geo_ttl_days'  => 30,
                'asn_enabled'   => true,
                'asn_ttl_days'  => 30,
                'whois_enabled' => true,
                'whois_ttl_days' => 30,
                'rdns_enabled'  => true,
                'rdns_ttl_days' => 7,
                // Enrichment must never block ingestion; a lookup that exceeds this is
                // abandoned and the field is simply left absent on the document.
                'lookup_timeout' => 3,
            ],

            // ---- Beacon ---------------------------------------------------------
            'beacon' => [
                'enabled'          => true,
                'secret'           => '',    // secret — generated by install.sh
                'heartbeat_ms'     => 15000,
                'idle_timeout_ms'  => 30000, // interaction older than this stops "engaged"
                'token_max_age'    => 43200, // 12h
                'rate_per_min'     => 120,
                'max_payload'      => 8192,
            ],

            // ---- Privacy --------------------------------------------------------
            'privacy' => [
                'ip_mode'         => 'full',   // full | truncate | hash
                'ip_salt'         => '',       // secret, used by 'hash' mode
                'retention_days'  => 90,       // 0 disables deletion
                'rollup_forever'  => true,     // keep the tiny daily rollup indefinitely
            ],

            // ---- Scoring --------------------------------------------------------
            'scoring' => [
                'rule_version' => 1,
                // Per-rule weight overrides, keyed by rule code. Empty = use built-ins.
                'weights'      => [],
                'thresholds'   => [
                    'bot'          => 80,
                    'likely_bot'   => 60,
                    'unknown'      => 40,
                    'likely_human' => 20,
                ],
            ],

            // ---- Panel ----------------------------------------------------------
            'auth' => [
                'mode'          => 'none',     // none | basic | session
                'user'          => '',
                'password_hash' => '',
            ],

            // Proxies whose X-Forwarded-For header we are willing to believe.
            'trusted_proxies' => [],

            'ui' => [
                'timezone'    => 'UTC',
                'date_format' => 'm/d/Y H:i:s',
            ],
        ];
    }

    /**
     * Generate a fresh installation id.
     *
     * Eight lowercase hex characters from a cryptographically secure source.
     * Not a hash of anything about the host: deriving it from a hostname or a
     * MAC address would make it guessable, and two people installing on
     * identically-named boxes would collide exactly when they least expect it.
     *
     * Eight hex characters is 4.3 billion values. Collisions are handled by
     * retrying on the API's ERROR_CORE_NAME_TAKEN response rather than by
     * hoping, so the width only has to make retries rare, not impossible.
     */
    public static function newInstallId(): string
    {
        return bin2hex(random_bytes(4));
    }

    /**
     * Build a core name for this installation.
     *
     * Opensolr index names live in a GLOBAL namespace shared by every account
     * on the platform, are permanent once created, and must match
     * [a-zA-Z0-9_] with a 50 character limit. So the name has to be unique per
     * installation, not per account, and it cannot be changed later.
     *
     * Layout: loghound_<install id>_<role>  e.g. loghound_9f3c17ab_hits
     * That is 26 characters, comfortably inside the limit, and it keeps the
     * "loghound_" prefix so the indexes are recognisable in an account that
     * holds hundreds of them.
     *
     * @param string $role 'hits' or 'sessions'
     */
    public static function coreName(string $installId, string $role): string
    {
        if (!preg_match('/^[a-f0-9]{4,32}$/', $installId)) {
            throw new \InvalidArgumentException('Install id must be lowercase hex.');
        }
        if (!in_array($role, ['hits', 'sessions'], true)) {
            throw new \InvalidArgumentException('Unknown core role: ' . $role);
        }
        return 'loghound_' . $installId . '_' . $role;
    }

    /**
     * Load the config file, merging it over the defaults.
     *
     * A missing file is not an error: it yields defaults and lets the setup wizard run.
     */
    public static function load(string $path): self
    {
        $data = self::defaults();
        if (is_file($path) && is_readable($path)) {
            /** @psalm-suppress UnresolvableInclude */
            $loaded = require $path;
            if (is_array($loaded)) {
                $data = self::mergeDeep($data, $loaded);
            }
        }
        return new self($data, $path);
    }

    /**
     * Recursive array merge where the override wins for scalars and lists.
     *
     * A plain array_merge_recursive would concatenate lists (turning a replaced
     * `sources` list into an append), which is not what a config override means.
     *
     * @param array<string,mixed> $base
     * @param array<string,mixed> $over
     * @return array<string,mixed>
     */
    private static function mergeDeep(array $base, array $over): array
    {
        foreach ($over as $k => $v) {
            if (is_array($v) && isset($base[$k]) && is_array($base[$k]) && !array_is_list($v)) {
                $base[$k] = self::mergeDeep($base[$k], $v);
            } else {
                $base[$k] = $v;
            }
        }
        return $base;
    }

    /**
     * Read a setting with dotted-path notation, e.g. get('solr.hits_core').
     *
     * @param mixed $default
     * @return mixed
     */
    public function get(string $key, $default = null)
    {
        $node = $this->data;
        foreach (explode('.', $key) as $part) {
            if (!is_array($node) || !array_key_exists($part, $node)) {
                return $default;
            }
            $node = $node[$part];
        }
        return $node;
    }

    /**
     * Write a setting with dotted-path notation. Does not persist until save().
     *
     * @param mixed $value
     */
    public function set(string $key, $value): void
    {
        $parts = explode('.', $key);
        $node = &$this->data;
        foreach ($parts as $part) {
            if (!isset($node[$part]) || !is_array($node[$part])) {
                $node[$part] = [];
            }
            $node = &$node[$part];
        }
        $node = $value;
    }

    /** @return array<string,mixed> */
    public function all(): array
    {
        return $this->data;
    }

    /**
     * Persist the config atomically with restrictive permissions.
     *
     * Written to a temp file in the same directory then renamed, so a crash mid-write
     * cannot leave a half-parsed config that locks the operator out. Mode 0640 keeps the
     * API key and HMAC secret away from other local users; the leading exit() guard means
     * a webserver that somehow serves the file as PHP still emits nothing.
     */
    public function save(): void
    {
        $export = var_export($this->data, true);
        $php = "<?php\n"
            . "/**\n"
            . " * Loghound configuration — generated file.\n"
            . " *\n"
            . " * Contains secrets (Opensolr API key, beacon HMAC secret). Keep mode 0640 and\n"
            . " * keep it out of the document root and out of version control.\n"
            . " */\n"
            . "if (PHP_SAPI !== 'cli' && !defined('LOGHOUND')) { exit; }\n\n"
            . "return " . $export . ";\n";

        $dir = dirname($this->path);
        $tmp = $dir . '/.loghound.' . bin2hex(random_bytes(6)) . '.tmp';

        if (file_put_contents($tmp, $php, LOCK_EX) === false) {
            throw new \RuntimeException('Unable to write config to ' . $dir);
        }
        chmod($tmp, 0640);
        if (!rename($tmp, $this->path)) {
            @unlink($tmp);
            throw new \RuntimeException('Unable to move config into place: ' . $this->path);
        }
    }

    /**
     * Validate the config and return a list of human-readable problems.
     *
     * Called by the setup wizard and by every daemon at startup so a misconfiguration
     * surfaces as a clear message instead of a stream of failed Solr requests.
     *
     * @return string[]
     */
    public function validate(): array
    {
        $errors = [];

        $solrMode = $this->get('solr.mode');
        if (!in_array($solrMode, ['opensolr', 'custom'], true)) {
            $errors[] = "solr.mode must be 'opensolr' or 'custom'.";
        }
        if ($solrMode === 'opensolr') {
            if ($this->get('opensolr.email') === '') {
                $errors[] = 'opensolr.email is required in managed mode.';
            }
            if ($this->get('opensolr.api_key') === '') {
                $errors[] = 'opensolr.api_key is required in managed mode.';
            }
        } elseif ($solrMode === 'custom' && $this->get('solr.base_url') === '') {
            $errors[] = 'solr.base_url is required when solr.mode is custom.';
        }

        foreach (['hits_core', 'sessions_core'] as $k) {
            $name = (string) $this->get('solr.' . $k);
            if ($name === '') {
                // The common case for an empty name is "setup has not run yet",
                // so say that rather than complaining about a regex.
                $errors[] = "solr.$k is not set — run bin/loghound-setup to create the indexes.";
            } elseif (!Security::isSafeCoreName($name)) {
                $errors[] = "solr.$k must match [A-Za-z0-9_]{1,64}.";
            } elseif (strlen($name) > 50) {
                // Opensolr caps index names at 50 characters. Enforce it here
                // too so the failure surfaces at setup rather than as an opaque
                // API rejection halfway through provisioning.
                $errors[] = "solr.$k must be 50 characters or fewer (Opensolr limit).";
            }
        }

        // The two cores must be distinct, or the scorer would write session
        // documents into the hits index and every aggregate would be wrong.
        if ($this->get('solr.hits_core') !== '' &&
            $this->get('solr.hits_core') === $this->get('solr.sessions_core')) {
            $errors[] = 'solr.hits_core and solr.sessions_core must be different indexes.';
        }

        if ($this->get('beacon.enabled') && strlen((string) $this->get('beacon.secret')) < 32) {
            $errors[] = 'beacon.secret must be at least 32 characters; run install.sh to generate one.';
        }

        $ipMode = $this->get('privacy.ip_mode');
        if (!in_array($ipMode, ['full', 'truncate', 'hash'], true)) {
            $errors[] = "privacy.ip_mode must be 'full', 'truncate' or 'hash'.";
        }
        if ($ipMode === 'hash' && strlen((string) $this->get('privacy.ip_salt')) < 16) {
            $errors[] = 'privacy.ip_salt must be at least 16 characters when ip_mode is hash.';
        }

        $authMode = $this->get('auth.mode');
        if (!in_array($authMode, ['none', 'basic', 'session'], true)) {
            $errors[] = "auth.mode must be 'none', 'basic' or 'session'.";
        }
        if ($authMode === 'basic' && $this->get('auth.password_hash') === '') {
            $errors[] = 'auth.password_hash is required when auth.mode is basic.';
        }

        // Every configured source must resolve inside an allowed root.
        $roots = (array) $this->get('allowed_log_roots', []);
        foreach ((array) $this->get('sources', []) as $i => $src) {
            if (empty($src['path'])) {
                $errors[] = "sources[$i].path is missing.";
                continue;
            }
            // A glob is expanded at read time; validate the literal directory part now.
            $dir = dirname((string) $src['path']);
            if (Security::safePath($dir, $roots) === null) {
                $errors[] = "sources[$i].path is outside allowed_log_roots: " . $src['path'];
            }
        }

        return $errors;
    }
}
