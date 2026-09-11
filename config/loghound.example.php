<?php
/**
 * Loghound — EXAMPLE configuration.
 *
 * ---------------------------------------------------------------------------------
 * YOU DO NOT NORMALLY EDIT THIS FILE, AND YOU NEVER COPY IT INTO PLACE BY HAND.
 * ---------------------------------------------------------------------------------
 * The real configuration lives at config/loghound.php and is written by the setup
 * wizard:
 *
 *     sudo -u loghound php bin/loghound-setup
 *
 * The wizard detects your log format from your own webserver config, provisions Solr,
 * and generates the beacon HMAC secret and the IP salt with random_bytes(). Copying
 * this file and filling in blanks would leave those secrets empty, and Config::validate()
 * would refuse to start the daemons.
 *
 * This file exists so you can SEE every supported setting with its default and an
 * explanation, in one place. `Config::defaults()` in src/Config.php is the single source
 * of truth; anything not listed there is not a supported setting.
 *
 * ---------------------------------------------------------------------------------
 * THE REAL FILE CONTAINS SECRETS
 * ---------------------------------------------------------------------------------
 * config/loghound.php holds the Opensolr API key, the beacon HMAC secret and the IP
 * hashing salt. It is written at mode 0640 inside a 0700 directory owned by the service
 * user, outside the document root, and is excluded by .gitignore.
 *
 * It is a PHP file rather than JSON or YAML for exactly one reason: if it is ever served
 * by a misconfigured webserver it EXECUTES and returns nothing, instead of printing your
 * secrets as text. The guard on the line below is the second half of that protection.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

// Refuses to hand anything back unless it is being loaded by the application itself.
if (PHP_SAPI !== 'cli' && !defined('LOGHOUND')) {
    exit;
}

return [

    // =====================================================================
    // Identity
    // =====================================================================

    /** Shown in the panel header. Cosmetic. */
    'site_name' => 'Loghound',

    /**
     * Public URL of this panel, no trailing slash. Used to build the beacon snippet
     * the Settings page shows you. Leave empty and the snippet will be a placeholder.
     */
    'base_url' => 'https://loghound.example.com',

    // =====================================================================
    // Solr backend
    // =====================================================================

    'solr' => [
        /**
         * 'opensolr', and nothing else. Loghound provisions and manages its own two indexes
         * through the Opensolr API — it creates them, uploads their configsets and reloads
         * them — and it cannot do that on a Solr it does not administer, so there is no
         * option to point it at one. An older configuration saying 'custom' is refused by
         * Config::validate() with an explanation rather than silently ignored.
         */
        'mode' => 'opensolr',

        /**
         * Connection details of the node the provisioned indexes landed on. Filled in during
         * setup from Opensolr::connectionDetails(); you do not type these.
         */
        'base_url'  => '',
        'http_user' => '',
        'http_pass' => '',

        /**
         * Core / index names. EMPTY until the setup wizard fills them in — they must
         * not be hardcoded.
         *
         * An Opensolr index name is unique across the WHOLE PLATFORM, not just within
         * your account, and it is permanent once created. A fixed default like
         * 'loghound_hits' would therefore collide for the second person who ever
         * installs this. Config::coreName() builds `loghound_<install id>_<role>`
         * instead, e.g. loghound_9f3c17ab_hits. Max 50 characters (Opensolr's limit).
         */
        'hits_core'     => '',
        'sessions_core' => '',

        /**
         * Random per-installation token that makes those names unique. Generated once
         * at setup and NEVER rotated: it is part of the identity of the two indexes,
         * so changing it would orphan the data rather than rename it.
         */
        'install_id'    => '',

        /** Seconds before a Solr request is abandoned. */
        'timeout' => 20,

        /**
         * Batching: whichever comes first. softCommit only — a hard commit per batch
         * would open a new searcher every couple of seconds and destroy throughput for
         * no benefit. Hard commits are left to the core's autoCommit
         * (maxTime=60000, openSearcher=false).
         */
        'batch_size' => 500,
        'batch_ms'   => 2000,
    ],

    // =====================================================================
    // Opensolr managed backend  ('solr.mode' => 'opensolr')
    // =====================================================================

    'opensolr' => [
        'api_base' => 'https://opensolr.com/solr_manager/api',
        'email'    => '',
        /** SECRET. Written by the setup wizard, never printed back. */
        'api_key'  => '',
        /** One of GET /regions — the wizard lists them for you. */
        'region'   => '',
    ],

    // =====================================================================
    // Log sources
    // =====================================================================

    /**
     * What to ingest. Written by the wizard after you confirm the detected mapping;
     * you can add entries by hand and re-run the daemon.
     *
     *   path   an absolute path or a glob. Globs are RE-EVALUATED ON EVERY POLL, so a
     *          new vhost's log file is picked up without a daemon restart.
     *   format a library format name ('apache_combined', 'apache_loghound',
     *          'nginx_combined', ...) OR the literal LogFormat / log_format string
     *          from your own webserver config.
     *   host   optional vhost override, for a format that does not log %v.
     *
     * DO NOT point Loghound at its own vhost's access log: it would ingest its own
     * beacon traffic and inflate every number it reports.
     */
    'sources' => [
        [
            'path'   => '/var/log/apache2/example_com_access.log',
            'format' => 'apache_combined',
            'host'   => 'example.com',
        ],
        [
            'path'   => '/var/log/nginx/*access*.log',
            'format' => 'nginx_combined',
        ],
    ],

    /**
     * SECURITY CONTROL. A configured log path is resolved with realpath() and must sit
     * inside one of these roots, or it is refused. Without this the log-path setting
     * would be an arbitrary-file-read primitive. Globs are re-checked at read time, not
     * only when they are saved.
     */
    'allowed_log_roots' => ['/var/log'],

    /** Where the wizard looks on first run. */
    'discover' => [
        'apache_configs' => [
            '/etc/apache2/apache2.conf',
            '/etc/httpd/conf/httpd.conf',
        ],
        'apache_vhost_dirs' => [
            '/etc/apache2/sites-enabled',
            '/etc/httpd/conf.d',
        ],
        'nginx_configs'    => ['/etc/nginx/nginx.conf'],
        'nginx_vhost_dirs' => [
            '/etc/nginx/sites-enabled',
            '/etc/nginx/conf.d',
        ],
        /** Used only when the webserver configs cannot be read. */
        'fallback_globs' => [
            '/var/log/apache2/*access*.log',
            '/var/log/httpd/*access*log',
            '/var/log/nginx/*access*.log',
        ],
    ],

    // =====================================================================
    // Ingestion
    // =====================================================================

    'ingest' => [
        /** Tail poll interval. 1s is live enough for a dashboard and costs nothing. */
        'poll_ms' => 1000,

        /** Session idle timeout. 30 minutes is the analytics convention. */
        'session_idle_sec' => 1800,

        /**
         * Store the complete original log line in raw_s (STORED, NOT INDEXED).
         * Enables retroactive rescoring when you change the ruleset — and roughly
         * DOUBLES the index size. It also keeps a full copy of every request line,
         * including anything sensitive your own URLs put in a query string.
         */
        'keep_raw' => true,

        /**
         * Build the full-text catchall field. The first thing to turn off at high
         * volume; the session explorer's free-text search stops working without it.
         */
        'catchall' => true,

        /** A "line" longer than this is malformed or hostile. Dropped and reported. */
        'max_line_bytes' => 16384,

        /**
         * Cap on how many unparseable lines are sampled to var/badlines.log. They are
         * always COUNTED; this only limits how many are written. The cap matters: a
         * format that suddenly stops matching would otherwise fill the disk with a
         * copy of your access log within minutes.
         */
        'badline_sample' => 200,
    ],

    // =====================================================================
    // Enrichment
    //
    // Each of these sends visitor IP ADDRESSES to a third party. Turn off anything you
    // are not comfortable with — see docs/PRIVACY.md. Enrichment failure NEVER blocks
    // indexing: the field is simply absent from the document.
    // =====================================================================

    'enrich' => [
        /**
         * Geolocation: country_s, region_s, city_s, geo_p and tz_s.
         *
         * Off means NONE of those five fields appears on any document, and the panel's map
         * and country facets are empty. It also costs you `tz_mismatch`, one of the
         * seventeen scoring rules — see docs/DETECTION.md.
         *
         * There are two sources behind these fields and they need nothing from you:
         *
         *   - The Opensolr platform's geolocation endpoint, authenticated with the
         *     opensolr.email / opensolr.api_key pair already set above. City level.
         *   - Team Cymru's country column, which comes back with the ASN lookup that is
         *     already being made. Country level, free, and it keeps working when the
         *     endpoint above is unreachable. It needs asn_enabled below, because it is
         *     that query which carries it.
         *
         * tz_s is taken from whichever of those reported the country, and is derived from
         * the country itself for the 216 territories that have exactly one IANA timezone.
         * Multi-zone countries — the US, Russia, Canada, Australia, Brazil, Germany and 25
         * others — get no tz_s unless the endpoint supplied one, because guessing a zone
         * would make tz_mismatch fire on people who did nothing wrong.
         */
        'geo_enabled'  => true,

        /**
         * Leave EMPTY unless you are pointed at a staging platform with a geolocation
         * endpoint at a different address. Empty derives the URL from opensolr.api_base,
         * so a staging control plane is followed automatically. https only.
         */
        'geo_endpoint' => '',

        'geo_ttl_days' => 30,

        'asn_enabled'  => true,   // Team Cymru: ASN, AS org, network type, country
        'asn_ttl_days' => 30,

        'whois_enabled'  => true, // RIR whois: netname — catches leased ranges
        'whois_ttl_days' => 30,

        'rdns_enabled'  => true,  // reverse DNS + forward confirmation
        'rdns_ttl_days' => 7,

        /** A lookup that exceeds this is abandoned and the field is left absent. */
        'lookup_timeout' => 3,
    ],

    // =====================================================================
    // Beacon  (public/b.js and public/collect.php)
    // =====================================================================

    'beacon' => [
        'enabled' => true,

        /**
         * SECRET, at least 32 characters. Generated by the setup wizard with
         * random_bytes(). Without it a visitor could claim any session id and any
         * dwell time; with it, forged timings become evidence instead of data.
         */
        'secret' => '',

        /** Heartbeat while engaged time is advancing, so a killed tab keeps data. */
        'heartbeat_ms' => 15000,

        /** An interaction older than this stops counting as "engaged". */
        'idle_timeout_ms' => 30000,

        /** Beacon tokens older than this are refused. 12 hours. */
        'token_max_age' => 43200,

        /** Per-IP token bucket on the public collector. */
        'rate_per_min' => 120,

        /** Hard payload cap. Anything larger is rejected before it is parsed. */
        'max_payload' => 8192,

        /**
         * Store the identity string the measured site attaches to a session.
         *
         * WHAT IT STORES: whatever your site puts in `data-ident` on the beacon tag — in
         * practice a signed-in visitor's email address, customer number or account id — on
         * the session document, where it appears in the panel, in the Solr index and in
         * every backup of that index. It is kept for `privacy.retention_days` like the rest
         * of the session and is deleted with it.
         *
         * OFF by default, and deliberately: everything else Loghound collects is a
         * measurement of a browser, and this is a name. Turning it on is a decision about
         * personal data that only you can make. With it off the string is discarded by
         * Beacon::normalise() before anything is written, so it never reaches the staging
         * database either.
         *
         * Loghound never guesses an identity. No cookie is read, no form is scraped, no
         * meta tag is looked for. If your site does not declare one, there is none.
         */
        'store_identity' => false,

        /**
         * Store whether the visitor was signed in — a boolean, and nothing else.
         *
         * WHAT IT STORES: `signed_in_b` on the session document, true or false, from your
         * site's `data-signed-in` attribute. Nothing that identifies anybody. A session
         * where your site said nothing gets NO field at all, which is why "not reported"
         * is a third state in the panel rather than being counted as anonymous.
         *
         * ON by default and independent of `store_identity`: the split between signed-in
         * and anonymous traffic — engaged time, paths, bounce, bot verdict — is one of the
         * most useful things this panel can show, and it is worth having without storing a
         * single email address.
         */
        'store_signed_in' => true,
    ],

    // =====================================================================
    // Privacy   — read docs/PRIVACY.md before changing these
    // =====================================================================

    'privacy' => [
        /**
         * 'full'     keep the address. Best detection. Personal data under GDPR.
         *            The default, because you already have the raw address in your own
         *            access logs — Loghound storing it changes your exposure less than
         *            people assume.
         * 'truncate' /24 for IPv4, /48 for IPv6. Geo and ASN still work. The
         *            fingerprint-cluster rule counts DISTINCT IPs, so truncation makes
         *            it noisier in both directions.
         * 'hash'     keyed hash, salt rotated daily. Cross-day correlation of an
         *            individual becomes impossible. Loses geo, ASN, netname and rDNS
         *            entirely — there is no address left to look up.
         */
        'ip_mode' => 'full',

        /** SECRET, used only by 'hash' mode. With it, IPv4 is trivially brute-forced. */
        'ip_salt' => '',

        /** loghound-retention deletes past this. 0 disables deletion entirely. */
        'retention_days' => 90,

        /**
         * Keep the daily rollup documents forever. They are aggregate counts with no
         * per-visitor field, so long-term trends survive the deletion of the detail.
         */
        'rollup_forever' => true,
    ],

    // =====================================================================
    // Scoring   — see docs/DETECTION.md for every rule and its rationale
    // =====================================================================

    'scoring' => [
        /**
         * BUMP THIS whenever you change a weight. It is written onto every session
         * document, so a verdict stays traceable to the ruleset that produced it.
         * Changing a weight without bumping it makes historical scores silently
         * incomparable.
         */
        'rule_version' => 1,

        /**
         * Per-rule weight overrides, keyed by rule code. Empty = use the built-ins.
         * Setting a weight to 0 disables the rule, and its reason code stops being
         * emitted — which is intended: a rule contributing nothing should not appear
         * in the explanation.
         *
         * Two worth considering:
         *   'no_js_on_html' => 40    // a technical audience blocks the beacon a lot
         *   'tz_mismatch'   => 0     // everyone here is behind a corporate VPN
         */
        'weights' => [],

        'thresholds' => [
            'bot'          => 80,
            'likely_bot'   => 60,
            'unknown'      => 40,
            'likely_human' => 20,
        ],
    ],

    // =====================================================================
    // Panel
    // =====================================================================

    'auth' => [
        /**
         * 'none'    FAILS CLOSED — the panel returns 503 and refuses to serve. An
         *           analytics dashboard left open on the internet is a data breach,
         *           and defaults decide outcomes.
         * 'basic'   HTTP Basic. Simple, works behind any proxy, easy to script against.
         * 'session' Form login with a session cookie.
         */
        'mode' => 'basic',

        'user' => 'admin',

        /** password_hash(PASSWORD_DEFAULT). NEVER a plaintext password. */
        'password_hash' => '',
    ],

    /**
     * Proxies whose X-Forwarded-For header we are willing to believe, as CIDRs.
     *
     * XFF is attacker-controlled unless the immediate peer is a proxy YOU put there.
     * If anything sits in front of your webserver and this list is empty, every visitor
     * appears to come from the proxy and every IP-based signal in the ruleset becomes
     * worthless. If it is too broad, any visitor can forge their own source address.
     */
    'trusted_proxies' => [
        // '10.0.0.0/8',
        // '172.16.0.0/12',
    ],

    // =====================================================================
    // UI
    // =====================================================================

    'ui' => [
        'timezone'    => 'UTC',
        'date_format' => 'm/d/Y H:i:s',
    ],
];
