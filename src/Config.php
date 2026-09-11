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
    /**
     * The only storage backend there is.
     *
     * Loghound provisions and manages its own two indexes on Opensolr; it cannot do that on a
     * Solr it does not administer. The key `solr.mode` survives as a constant so that a
     * configuration written before the bring-your-own-Solr option was removed — which still
     * carries `mode: custom` on disk — is refused by validate() with an explanation instead of
     * being read as "some other backend" and silently ignored.
     */
    public const SOLR_MODE = 'opensolr';

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
     * The settings, section by section.
     *
     * Identity. `base_url` is the panel's own public URL, e.g. https://loghound.example.com,
     * and is used to build the beacon snippet.
     *
     * Solr backend. `mode` is 'opensolr' and nothing else. Loghound provisions and manages its
     * own two indexes through the Opensolr API — it creates them, uploads their configsets and
     * reloads them — and it cannot do any of that on a Solr it does not administer, so pointing
     * it at one was a promise the product could not keep. The key is retained rather than
     * deleted because a configuration written before the removal still carries `mode: custom`
     * on disk, and only a key that is still read can refuse it; validate() does exactly that.
     *
     * `base_url`, `http_user` and `http_pass` are the connection details of the node the
     * provisioned indexes landed on, filled in from Opensolr::connectionDetails() during setup.
     * src/Solr.php is mode-agnostic: it talks to a node it has credentials for and does not
     * care how they got there. The core names are EMPTY by default and filled in by the setup
     * wizard. They must not be hardcoded: on Opensolr an index name is unique across the WHOLE
     * PLATFORM, not just within one account, so a fixed default would collide for the second
     * person who ever installs this — see newInstallId() and coreName(). `install_id` is the
     * random per-installation token that makes those names unique; it is generated once at
     * setup and never changed afterwards, because it is part of the identity of the two indexes
     * and rotating it would orphan the data rather than rename it. Batching is softCommit only:
     * a hard commit per batch would destroy throughput and is never needed for near-real-time
     * visibility.
     *
     * Opensolr managed backend. `api_key` is a secret, and `region` must be one of the values
     * returned by GET /regions.
     *
     * Log sources. Each entry is ['path' => glob, 'format' => name|regex-id, 'host' =>
     * optional override]. `allowed_log_roots` are the roots a configured log path must
     * resolve inside; anything outside them is refused, which is what stops the log-path
     * setting from becoming an arbitrary-file-read primitive. `discover` is where to look
     * when auto-detecting on first run.
     *
     * Ingestion. `poll_ms` is the tail poll interval, `session_idle_sec` 30 minutes,
     * `keep_raw` stores the original line and roughly doubles the index size, `catchall`
     * builds the full-text field, `max_line_bytes` is the length past which a "line" is
     * malformed or hostile, and `badline_sample` caps how many unparseable lines are sampled.
     *
     * Enrichment. `geo_endpoint` is Opensolr's ezcmd geolocation service, which returns
     * country, city, lat-lon and timezone only: it carries no ASN or hosting classification,
     * so it feeds the map, not the bot score. ASN comes from Team Cymru and netname from RIR
     * whois. `lookup_timeout` exists because enrichment must never block ingestion — a lookup
     * that exceeds it is abandoned and the field is simply left absent from the document.
     *
     * Beacon. `secret` is generated by install.sh. `idle_timeout_ms` is the age past which an
     * interaction no longer counts as "engaged", and `token_max_age` is 12 hours.
     *
     * Privacy. `ip_mode` is full, truncate or hash; `ip_salt` is a secret used by hash mode;
     * `retention_days` of 0 disables deletion; `rollup_forever` keeps the tiny daily rollup
     * indefinitely.
     *
     * Scoring. `weights` holds per-rule overrides keyed by rule code, and an empty map means
     * the built-in weights are used.
     *
     * Panel. `auth.mode` is 'basic' (the browser's own password prompt, which scripts and curl
     * can also use) or 'session' (Loghound's own sign-in page, with a real sign-out); 'none' is
     * the pre-setup state and makes the panel refuse to serve at all. `idle_timeout` ends a
     * session that has done nothing for 30 minutes and `absolute_timeout` ends one 12 hours
     * after sign-in however busy it has been — both session mode only. `lockout_attempts`
     * failed sign-ins from one address within `lockout_window` seconds lock that address out
     * until the window passes, and that applies to BOTH modes. `trusted_proxies` lists the
     * proxies whose X-Forwarded-For header we are willing to believe, which is also what the
     * lockout keys on: get it wrong behind a reverse proxy and every visitor shares one
     * counter.
     *
     * @return array<string,mixed>
     */
    public static function defaults(): array
    {
        return [
            'site_name' => 'Loghound',
            'base_url'  => '',

            'solr' => [
                'mode'          => self::SOLR_MODE,
                'base_url'      => '',
                'http_user'     => '',
                'http_pass'     => '',
                'hits_core'     => '',
                'sessions_core' => '',
                'install_id'    => '',
                'timeout'       => 20,
                'batch_size'    => 500,
                'batch_ms'      => 2000,
            ],

            'opensolr' => [
                'api_base' => 'https://opensolr.com/solr_manager/api',
                'email'    => '',
                'api_key'  => '',
                'region'   => '',
            ],

            'sources' => [],

            'allowed_log_roots' => ['/var/log'],

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

            'ingest' => [
                'poll_ms'          => 1000,
                'session_idle_sec' => 1800,
                'keep_raw'         => true,
                'catchall'         => true,
                'max_line_bytes'   => 16384,
                'badline_sample'   => 200,
            ],

            'enrich' => [
                'geo_enabled'   => true,
                'geo_endpoint'  => 'https://ezcmd.com/apps/api_ezip_locator/lookup/%s/1/%s',
                'geo_key'       => '',
                'geo_ttl_days'  => 30,
                'asn_enabled'   => true,
                'asn_ttl_days'  => 30,
                'whois_enabled' => true,
                'whois_ttl_days' => 30,
                'rdns_enabled'  => true,
                'rdns_ttl_days' => 7,
                'lookup_timeout' => 3,
            ],

            'beacon' => [
                'enabled'          => true,
                'secret'           => '',
                'heartbeat_ms'     => 15000,
                'idle_timeout_ms'  => 30000,
                'token_max_age'    => 43200,
                'rate_per_min'     => 120,
                'max_payload'      => 8192,
            ],

            'privacy' => [
                'ip_mode'         => 'full',
                'ip_salt'         => '',
                'retention_days'  => 90,
                'rollup_forever'  => true,
            ],

            'scoring' => [
                'rule_version' => 1,
                'weights'      => [],
                'thresholds'   => [
                    'bot'          => 80,
                    'likely_bot'   => 60,
                    'unknown'      => 40,
                    'likely_human' => 20,
                ],
            ],

            'auth' => [
                'mode'             => 'none',
                'user'             => '',
                'password_hash'    => '',
                'idle_timeout'     => 1800,
                'absolute_timeout' => 43200,
                'lockout_attempts' => 8,
                'lockout_window'   => 900,
            ],

            'quota' => [
                'enabled'           => true,
                'disk_high_water'   => Quota::DEFAULT_HIGH_WATER,
                'disk_target'       => Quota::DEFAULT_TARGET,
                'min_keep_hours'    => Quota::DEFAULT_MIN_KEEP_HOURS,
                'refresh_sec'       => Quota::DEFAULT_REFRESH_SEC,
                'refresh_docs'      => Quota::DEFAULT_REFRESH_DOCS,
                'trim_cooldown_sec' => Quota::DEFAULT_COOLDOWN_SEC,
                'max_trim_steps'    => Quota::DEFAULT_MAX_STEPS,
                'bw_warn'           => Quota::DEFAULT_BW_WARN,
                'bw_critical'       => Quota::DEFAULT_BW_CRITICAL,
                'upgrade_url'       => 'https://opensolr.com/pricing',
            ],

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
     * The file this configuration loads from and saves to.
     *
     * Needed by anything that has to act on the FILE rather than on the values: the setup
     * wizard invalidates the opcode cache entry after writing (config/loghound.php is a
     * PHP file, so a stale entry silently hands the next request the previous array), and
     * the installer decides whether it should be reachable at all by asking whether this
     * path exists.
     */
    public function path(): string
    {
        return $this->path;
    }

    /**
     * Persist the config atomically with restrictive permissions.
     *
     * Written to a temp file in the same directory then renamed, so a crash mid-write
     * cannot leave a half-parsed config that locks the operator out. Mode 0640 keeps the
     * API key and HMAC secret away from other local users; the leading exit() guard means
     * a webserver that somehow serves the file as PHP still emits nothing.
     *
     * The temp is created with fopen('xb') and chmod'ed BEFORE any content is written:
     * file_put_contents() would have created it under the umask, leaving a window in which
     * a file containing every secret was world-readable. Exclusive creation also means an
     * existing file or a planted symlink at that path is refused rather than followed.
     *
     * A shutdown handler and a sweep of older orphans between them make sure a copy of the
     * secrets does not outlive the write. See sweepStaleTemps().
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
        self::sweepStaleTemps($dir);

        $tmp = $dir . '/.loghound.' . bin2hex(random_bytes(6)) . '.tmp';

        $fh = @fopen($tmp, 'xb');
        if ($fh === false) {
            throw new \RuntimeException('Unable to write config to ' . $dir);
        }
        @chmod($tmp, 0640);

        register_shutdown_function(static function () use ($tmp): void {
            if (is_file($tmp)) {
                @unlink($tmp);
            }
        });

        $written = fwrite($fh, $php);
        fflush($fh);
        fclose($fh);

        if ($written === false || $written !== strlen($php)) {
            @unlink($tmp);
            throw new \RuntimeException('Unable to write config to ' . $dir);
        }

        if (!rename($tmp, $this->path)) {
            @unlink($tmp);
            throw new \RuntimeException('Unable to move config into place: ' . $this->path);
        }
    }

    /**
     * Remove temp files an earlier write died before renaming.
     *
     * The temp carries the COMPLETE secret set — Opensolr API key, beacon HMAC secret, IP
     * salt, Solr password, panel password hash. A fatal error, an OOM kill or a SIGKILL
     * between the write and the rename used to leave that second copy on disk indefinitely,
     * unknown to every other part of the system, including the uninstaller. The shutdown
     * handler registered in save() covers an orderly death; this covers the kind that runs
     * no handlers.
     *
     * Only files older than the grace period are touched, so a concurrent write in another
     * process is never pulled out from under it.
     */
    private static function sweepStaleTemps(string $dir): void
    {
        $cutoff = time() - 300;

        foreach ((array) glob($dir . '/.loghound.*.tmp') as $stale) {
            if (!is_string($stale) || is_link($stale) || !is_file($stale)) {
                continue;
            }
            if ((int) @filemtime($stale) < $cutoff) {
                @unlink($stale);
            }
        }
    }

    /**
     * Validate the config and return a list of human-readable problems.
     *
     * Called by the setup wizard and by every daemon at startup so a misconfiguration
     * surfaces as a clear message instead of a stream of failed Solr requests.
     *
     * Several of the messages are worded deliberately. The common case for an empty core name
     * is "setup has not run yet", so that is what it says rather than complaining about a
     * regex. Opensolr caps index names at 50 characters, and the limit is enforced here too so
     * that the failure surfaces at setup rather than as an opaque API rejection halfway
     * through provisioning. The two cores must be distinct, or the scorer would write session
     * documents into the hits index and every aggregate would be wrong.
     *
     * `solr.mode: custom` gets a paragraph of its own rather than a one-line refusal, and this
     * is the loud failure the removal of the bring-your-own-Solr option promised. An install
     * that predates the removal has a working, populated config on disk; the three daemons all
     * call this method at startup and abort on any error, so the operator meets this sentence
     * the moment they upgrade rather than discovering weeks later that the panel has been
     * pointed at a Solr Loghound can no longer manage. The message therefore has to say what
     * changed, why, and what to do — a bare "invalid value" would leave them guessing.
     *
     * Every configured source must resolve inside an allowed root. A glob is expanded at read
     * time, so what is validated now is the literal directory part of it.
     *
     * A directory that cannot be resolved at all is NOT an error here, and the distinction
     * matters more than it looks. Security::safePath() returns null for two different facts —
     * "resolved outside the allowed roots" and "could not be resolved" — and the panel process
     * runs under an open_basedir that deliberately excludes the log directories, so realpath()
     * on a perfectly good log path returns false there. Treating that as a fatal configuration
     * error made a correctly installed instance look unconfigured, which handed every request
     * to the unauthenticated web installer: a disclosure of the whole environment, a re-minted
     * setup token, and a hard denial of service of the panel. The enforcement that matters is
     * unaffected and lives where it belongs — bin/loghound-tail re-validates every expanded
     * glob with safePath() at read time, in a CLI process that has no open_basedir.
     *
     * @return string[]
     */
    public function validate(): array
    {
        $errors = [];

        $solrMode = (string) $this->get('solr.mode');
        if ($solrMode !== self::SOLR_MODE) {
            $errors[] = "solr.mode must be '" . self::SOLR_MODE . "'"
                . ($solrMode === 'custom'
                    ? ", and this configuration says 'custom'. Pointing Loghound at a Solr you "
                        . 'run yourself is no longer supported: Loghound provisions and manages its own '
                        . 'two indexes on Opensolr — creating them, uploading their configsets and '
                        . 'reloading them — and it cannot do that on a Solr it does not administer. '
                        . "Set solr.mode to 'opensolr' and re-run bin/loghound-setup to provision the "
                        . 'two indexes on your Opensolr account. Your existing data is not moved by '
                        . 'doing so.'
                    : ', which is the only storage backend there is.');
        } else {
            if ($this->get('opensolr.email') === '') {
                $errors[] = 'opensolr.email is required — the indexes are provisioned on your Opensolr account.';
            }
            if ($this->get('opensolr.api_key') === '') {
                $errors[] = 'opensolr.api_key is required — the indexes are provisioned on your Opensolr account.';
            }
        }

        foreach (['hits_core', 'sessions_core'] as $k) {
            $name = (string) $this->get('solr.' . $k);
            if ($name === '') {
                $errors[] = "solr.$k is not set — run bin/loghound-setup to create the indexes.";
            } elseif (!Security::isSafeCoreName($name)) {
                $errors[] = "solr.$k must match [A-Za-z0-9_]{1,64}.";
            } elseif (strlen($name) > 50) {
                $errors[] = "solr.$k must be 50 characters or fewer (Opensolr limit).";
            }
        }

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

        $errors = array_merge($errors, $this->validateAuth());

        $roots = (array) $this->get('allowed_log_roots', []);
        foreach ((array) $this->get('sources', []) as $i => $src) {
            if (empty($src['path'])) {
                $errors[] = "sources[$i].path is missing.";
                continue;
            }
            $dir = dirname((string) $src['path']);
            if (@realpath($dir) === false) {
                continue;
            }
            if (Security::safePath($dir, $roots) === null) {
                $errors[] = "sources[$i].path is outside allowed_log_roots: " . $src['path'];
            }
        }

        return $errors;
    }

    /**
     * Validate the panel authentication section.
     *
     * The mode list is EXACTLY the modes that have an implementation behind them:
     * Security::authModes() for the two an operator can choose, plus 'none', which is the
     * pre-setup state and is implemented as "refuse to serve and point at the installer".
     * Anything else is refused here rather than accepted and discovered later, because a
     * configuration value that looks supported and does nothing is how an operator ends up
     * with a panel that answers 403 forever — which is exactly what 'session' did before it
     * was built.
     *
     * A mode that signs people in needs both halves of a credential, so the username is
     * required alongside the hash. Without it, Security::verifyPassword compares the
     * submitted name against '' and the account can only be reached by sending an empty
     * username, which is a confusing way to be locked out.
     *
     * The timeouts and lockout numbers are clamped rather than rejected at runtime
     * (Security::authLimits), so a value outside the range is reported here as the
     * configuration mistake it is while the panel keeps working on the clamped one.
     *
     * @return string[]
     */
    private function validateAuth(): array
    {
        $errors = [];

        $mode = $this->get('auth.mode');
        $usable = array_keys(Security::authModes());

        if (!in_array($mode, array_merge(['none'], $usable), true)) {
            $errors[] = "auth.mode must be 'none', '" . implode("' or '", $usable) . "'.";
            return $errors;
        }

        if (in_array($mode, $usable, true)) {
            if ((string) $this->get('auth.password_hash', '') === '') {
                $errors[] = 'auth.password_hash is required when auth.mode is ' . $mode . '.';
            }
            if ((string) $this->get('auth.user', '') === '') {
                $errors[] = 'auth.user is required when auth.mode is ' . $mode . '.';
            }
        }

        $bounds = [
            'idle_timeout'     => [60, 86400],
            'absolute_timeout' => [300, 2592000],
            'lockout_attempts' => [1, 1000],
            'lockout_window'   => [60, 86400],
        ];
        foreach ($bounds as $key => [$min, $max]) {
            $value = $this->get('auth.' . $key);
            if (!is_int($value) || $value < $min || $value > $max) {
                $errors[] = "auth.$key must be a whole number between $min and $max.";
            }
        }

        if ((int) $this->get('auth.absolute_timeout', 0) < (int) $this->get('auth.idle_timeout', 0)) {
            $errors[] = 'auth.absolute_timeout must not be shorter than auth.idle_timeout.';
        }

        return $errors;
    }
}
