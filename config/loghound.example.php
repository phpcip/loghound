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

        /**
         * WRITTEN BY LOGHOUND, NOT BY YOU. Records that an account has been saved and its
         * indexes have not been chosen yet.
         *
         * Choosing an account and choosing indexes are two separate steps, and the gap
         * between them is a legal state rather than one to be prevented: the account is
         * saved on its own, and the two indexes named above may still belong to whichever
         * account was set before it. While that is true every panel query fails, and
         * without this key the panel could only report the symptom — "a service is not
         * answering" — which is accurate and useless. With it, every view says plainly
         * that indexes have not been chosen and links to the list.
         *
         * It is a recorded verdict rather than a live check on purpose: it is written at
         * the one moment the answer is known, when the account was just saved and the
         * platform had just listed what it holds, and cleared at the one moment it stops
         * being true, when a connection to the chosen pair is proved. No page spends a
         * control-plane call on it, and a failed read changes it in neither direction.
         *
         * Remove it by hand and the banner goes; the next time either step runs, it comes
         * back with the truth.
         */
        'pair_pending' => '',
    ],

    // =====================================================================
    // Log sources
    // =====================================================================

    /**
     * What to ingest. Written by the wizard after you confirm the detected mapping;
     * you can add entries by hand and re-run the daemon.
     *
     *   path    an absolute path or a glob. Globs are RE-EVALUATED ON EVERY POLL, so a
     *           new vhost's log file is picked up without a daemon restart.
     *   format  a library format name ('apache_combined', 'apache_loghound',
     *           'nginx_combined', ...) OR the literal LogFormat / log_format string
     *           from your own webserver config.
     *   host    optional vhost override, for a format that does not log %v.
     *   enabled optional. FALSE STOPS THE FILE BEING READ. Absent means enabled, so
     *           every existing configuration is unchanged; set it to false and the
     *           entry stays configured, stays detected and stays visible in Settings,
     *           and the daemon leaves it alone. The skip is written to the log when
     *           the daemon starts, so a file nobody is reading says so.
     *
     * LOGHOUND'S OWN VHOST. Requests to Loghound's own beacon script and collector are
     * recognised by host and path — derived from `base_url` — and are excluded from every
     * session number, so a `/collect.php` of your own on a measured site is untouched and
     * ours is never counted as a page somebody visited.
     *
     * That is not the same thing as excluding the PANEL. If Loghound's own access log is
     * one of the sources below, every visit you make to the panel becomes a session in the
     * data the panel shows you — real page views of a real site, which happens to be this
     * one. Whether you want that is your call, not ours; `enabled => false` is how you say
     * no, and leaving it out is how you say yes.
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
        [
            'path'    => '/var/log/apache2/loghound_access.log',
            'format'  => 'apache_combined',
            'host'    => 'loghound.example.com',
            'enabled' => false,
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

        /**
         * Write a document for every SUB-RESOURCE request: images, stylesheets, scripts,
         * fonts, media and source maps.
         *
         * Off, and that is the right default for almost everybody. Sub-resources are the
         * large majority of lines in an ordinary access log, so leaving this on means the
         * index is mostly pictures — paid for in disk, in your Opensolr quota and in the
         * size of every facet — to answer questions nobody asks about a font file. They
         * also crowded out the "Top pages" table with `/img/logo.png`.
         *
         * NOTHING IS LOST FROM THE SCORING. These requests are still read, still enriched,
         * still attack-matched and still counted into their session: the asset ratio, the
         * sub-resource count, the repeated-URI check behind `no_304_on_repeat` and the
         * inter-request timing all see the complete traffic. Only the per-request document
         * is refused.
         *
         * Turn it on if you want per-image latency on the Performance view, or if you are
         * debugging a CDN. Requests that are not sub-resources — pages, APIs, robots.txt,
         * the beacon collector — are always stored whatever this says.
         */
        'index_assets' => false,

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
    // The live page
    //
    // THESE HIDE LINES FROM ONE PAGE. They are not an ingestion filter: a request matched
    // here is still read, still scored and still indexed exactly as it was. What they buy is
    // a readable tail — an endpoint your own monitoring hits twice a second drowns a live
    // view and tells you nothing you did not already know.
    //
    // To stop something being STORED AT ALL, that is a different setting per hostname, in
    // Settings under Exclusions. These two are deliberately separate.
    //
    // Each rule is a field, a pattern and whether it is on. The pattern is a regular
    // expression BODY — no delimiters, no flags; matching is case-insensitive. Fields:
    // host, ip, path, query, method, status, ua, browser.
    // =====================================================================

    // =====================================================================
    // Traffic this installation refuses to record, per hostname
    //
    // A rule here means NEVER STORED: not a hit, not folded into a session, not counted in
    // any total, not present in any facet. Both planes are covered — the access log and the
    // beacon — because a rule that only stopped one of them would be a promise this product
    // does not keep.
    //
    // To merely tidy the live page, that is a different setting and it stores everything:
    // `live.exclusions` below.
    //
    // Each rule is a hostname, a field, a pattern and whether it is on. Fields: path, ip, ua.
    // The pattern is a regular expression BODY — no delimiters, no flags, case-insensitive.
    // An empty hostname means EVERY hostname. The exact pattern `*` on `path` excludes that
    // hostname entirely, and it is the only place a literal star means anything.
    //
    // Empty in a new installation: nothing is refused until you say so.
    // =====================================================================

    'exclusions' => [
        // ['host' => '', 'field' => 'path', 'pattern' => '^/wp-login\.php', 'enabled' => true],
        // ['host' => '', 'field' => 'path', 'pattern' => '^/xmlrpc\.php',   'enabled' => true],
        // ['host' => '', 'field' => 'ua',   'pattern' => 'uptimerobot|pingdom', 'enabled' => true],
        // ['host' => 'staging.example.com', 'field' => 'path', 'pattern' => '*', 'enabled' => true],
    ],

    'live' => [
        'exclusions' => [
            // ['field' => 'path', 'pattern' => '^/solr_manager/', 'enabled' => true],
            // ['field' => 'ua',   'pattern' => 'uptime|pingdom',  'enabled' => true],
        ],
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

        /**
         * Hostnames whose beacons may open a session. Empty means every host.
         *
         * THIS IS A PERMISSION, NOT A PASSWORD. It is matched against the Origin the caller
         * sent, and the caller chooses that header: a browser reports it honestly, and
         * anything that is not a browser sends whatever it likes. Listing a host therefore
         * means beacons can be FABRICATED against that host by anyone who bothers to try.
         * What the list is good for is keeping one honest site's measurements out of
         * another's when several of them report into the same pair of indexes.
         *
         * Empty by default. An unlisted host's beacons still contribute every TIMING — wall,
         * visible and engaged time, interactions, scroll, pageviews — and contribute NO signal
         * code at all, so the execution plane reports no `headless_b` for them.
         *
         * THAT IS THE ANTI-FRAMING RULE AND IT IS WORTH UNDERSTANDING. A staged beacon is
         * re-attached to a session by the visitor's address block and User-Agent hash, so any
         * page loaded in that visitor's browser — an advert, an iframe, any site they open —
         * can post a beacon that merges into their real session. If an unlisted beacon could
         * assert `automation_webdriver`, any web page on the internet could have any of your
         * visitors recorded as a headless bot. Listing your own hosts is what says "beacons
         * claiming to be this site may speak about my visitors".
         *
         *     'allowed_hosts' => ['shop.example.com', 'www.example.com'],
         */
        'allowed_hosts' => [],

        /**
         * Query-string parameter NAMES whose values are kept as search terms.
         *
         * THE ONE PLACE LOGHOUND STORES SOMETHING A PERSON TYPED. Everything else in the
         * index is what a request looked like — an address, a path, a header, a hash, a
         * duration. This is what somebody was looking FOR, in their own words, and it is
         * attached to a session that may also carry their address.
         *
         * So it is empty by default and nothing is collected until you name a parameter.
         * Adding 'q' here is a decision about your visitors' privacy, not a display option;
         * docs/PRIVACY.md covers what it means and what to tell them.
         *
         *     'query_params' => ['q', 's', 'search'],
         */
        'query_params' => [],

        /**
         * Beacon requests per minute per HOSTNAME, above the per-address `rate_per_min`.
         *
         * The per-address bucket stops one visitor flooding the endpoint; this one stops one
         * site doing it, which is the case that matters when a single pair of indexes is
         * collecting for several. Generous by default: a busy site legitimately sends
         * thousands a minute, and a limit that fires on real traffic is a limit that gets
         * turned off.
         */
        'rate_per_min_host' => 3000,
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

        /**
         * Delete hits older than this many days. 0 means NEVER delete for age.
         *
         * Read the zero carefully: it does not mean "keep nothing", it means there is no AGE
         * limit and hits are kept indefinitely as far as age is concerned. Whether they
         * actually survive is then decided by the other rule — the rolling size window under
         * `quota`, which deletes the oldest data when an index approaches the disk its
         * Opensolr plan gives it. The two are independent and whichever bites first wins.
         *
         * Also readable and writable as `maintenance.delete_hits_after_days`. It is the same
         * one number under two names — Config mirrors a write to either onto the other, so an
         * upgrade could not silently lose it — and there is no second setting to keep in step.
         */
        'retention_days' => 90,

        /**
         * Keep the daily rollup documents forever. They are aggregate counts with no
         * per-visitor field, so long-term trends survive the deletion of the detail.
         */
        'rollup_forever' => true,
    ],

    // =====================================================================
    // Plan quota — the SECOND retention rule, and the one that deletes by size
    // =====================================================================

    /**
     * Retention is two limits, not one, and whichever bites first wins.
     *
     * `privacy.retention_days` above is a decision about VISITORS: how long you are willing
     * to keep a record of one. This section is a decision about CAPACITY: an Opensolr plan
     * gives each index a disk allowance, and an index that reaches it is BLOCKED by the
     * platform — reads included, so the panel goes dark too. So the oldest data is deleted
     * before that happens, which is why this is on by default.
     *
     * Both the ingest daemon (before it writes) and `bin/loghound-retention` (daily) apply
     * it. `bin/loghound-retention --dry-run` prints the cutoff and the document count of
     * every step and deletes nothing, which is the honest way to decide these numbers.
     */
    'quota' => [
        /**
         * Switch the rolling size window off entirely.
         *
         * Supported, and it does NOT mean "unlimited": with it off an index grows until it
         * reaches the plan allowance, at which point the platform blocks it. Turn it off
         * when you would rather be blocked than lose the oldest data — and then watch the
         * meter on the panel's Maintenance card.
         */
        'enabled' => true,

        /**
         * Fraction of the plan's disk at which a trim runs before the next write, and the
         * fraction it comes back down to. The target is forced below the high-water mark:
         * equal values would make every write trigger a trim that frees nothing, which is a
         * delete-and-commit loop against a live index.
         */
        'disk_high_water' => 0.90,
        'disk_target'     => 0.80,

        /**
         * Hours of the most recent data the trim will never delete, whatever the arithmetic
         * says. It is the floor that stops a badly sized plan from deleting the traffic the
         * dashboard is currently showing.
         */
        'min_keep_hours' => 24,

        /**
         * How often the plan usage is re-read from Opensolr: after this many seconds, or
         * after this many documents indexed, whichever comes first.
         *
         * Not free. The platform derives the index size by asking the Solr node, so this is
         * a control-plane round trip that is itself a round trip to the index — hence a
         * five-minute clock rather than a per-write check.
         */
        'refresh_sec'  => 300,
        'refresh_docs' => 50000,

        /**
         * Seconds a core is left alone after a trim, and the number of delete-by-query calls
         * one trim may issue.
         *
         * Deleting in Lucene marks documents deleted; the bytes come back when a merge
         * rewrites the segments, on the index's own schedule. So a trim that immediately
         * re-measured would read the size from BEFORE the merge and delete again. The
         * cooldown is what lets the merges catch up, and the step cap bounds what one pass
         * can do — each step commits, so it is a real cost.
         */
        'trim_cooldown_sec' => 900,
        'max_trim_steps'    => 3,

        /**
         * Fractions of the plan's monthly bandwidth at which the meter starts warning and
         * becomes urgent. Bandwidth is NOT trimmable — nothing Loghound deletes reduces it —
         * so these only ever warn, early enough to act on.
         */
        'bw_warn'     => 0.75,
        'bw_critical' => 0.90,

        /** Where the panel sends you when an allowance is the thing that needs changing. */
        'upgrade_url' => 'https://opensolr.com/pricing',
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
         * 'session' Form login with a session cookie. Required for two-factor and for
         *           "stay signed in": HTTP Basic has no second step to put a code in,
         *           and no way to sign out.
         */
        'mode' => 'basic',

        'user' => 'admin',

        /** password_hash(PASSWORD_DEFAULT). NEVER a plaintext password. */
        'password_hash' => '',

        /**
         * Session-mode timeouts, in seconds. Both are enforced by the application on every
         * request, not left to PHP's session garbage collector.
         *
         * `idle_timeout` ends a session that has done nothing for this long.
         * `absolute_timeout` ends one this long after sign-in, however busy it has been.
         *
         * NEITHER APPLIES TO A BROWSER THAT TOOK "Stay signed in" on the sign-in form. That
         * is what the option is; every other session is governed by these exactly as before.
         */
        'idle_timeout'     => 1800,
        'absolute_timeout' => 43200,

        /**
         * Failed sign-ins from ONE address within `lockout_window` seconds that lock that
         * address out until the window passes.
         *
         * ONE LEDGER COVERS EVERYTHING THAT CHECKS A CREDENTIAL: both sign-in modes, the
         * second-factor step, the two-factor enrollment confirmation, turning two-factor
         * off, reissuing recovery codes, and a request arriving with a "stay signed in"
         * cookie. A recovery code counts the same as a six-digit one, and a wrong code
         * costs the same delay as a wrong password, so no endpoint is a cheaper place to
         * guess and alternating between them buys no extra attempts. Six digits is a
         * million possibilities; this is the only thing standing between a stolen password
         * and a guessed code, so raising it materially weakens the second factor.
         */
        'lockout_attempts' => 8,
        'lockout_window'   => 900,

        /**
         * How long a "stay signed in" token lives, in seconds, renewed every time the
         * browser is used. The default is ten years, which for a browser in daily use is
         * indistinguishable from permanent; a number is needed at all only so that a
         * genuinely abandoned token can be pruned instead of accumulating.
         *
         * Clamped to 86400 at the bottom, because anything shorter is the idle timeout with
         * extra steps and nobody who ticked that box wanted it.
         *
         * WHAT THE OPTION COSTS, since this is where an operator will come looking: a
         * browser that takes it has no timeout at all. Whoever holds that browser profile
         * has this panel until somebody presses Sign out. Signing out revokes every token,
         * and so does changing the password, changing `mode`, or turning two-factor on.
         * Settings > Sign-in says how many browsers are currently remembered and can
         * destroy all of them. The tokens live in `var/persistent-logins.json`, mode 0600;
         * deleting that file signs every remembered browser out.
         */
        'persistent_lifetime' => 315360000,

        /**
         * Two-factor authentication (TOTP — RFC 6238, the six-digit codes every
         * authenticator app produces). Off by default; existing installs are untouched.
         *
         * SET THIS UP IN Settings > Two-factor, not by hand. That screen mints the secret,
         * draws the QR code locally (nothing is sent to any third party), and refuses to
         * switch anything on until you have entered a code that proves your app has it —
         * which is what stops a half-finished setup from locking you out.
         *
         * 'enabled'  true only once a code has confirmed the secret. `enabled` true with no
         *            usable `secret` is refused by Config::validate(), because it would
         *            demand a code that nothing on earth could produce.
         * 'secret'   The shared key, Base32. Treat it exactly like the password hash below:
         *            anyone who reads it can generate your codes.
         * 'recovery' SHA-256 hashes of the ten one-time recovery codes. The codes themselves
         *            are shown once, at the moment they are generated, and are not stored —
         *            so they cannot be recovered from here, only replaced.
         *
         * LOST THE PHONE AND THE RECOVERY CODES? Run bin/loghound-setup on the server and
         * set a new password. That turns two-factor off and revokes every remembered
         * browser. Being able to run it is already proof of who you are.
         *
         * The replay floor — the last code step that was accepted, which is what stops a
         * code being used twice — is NOT here. It changes on every sign-in, so it lives in
         * `var/auth-state.json` rather than in this file.
         */
        'totp' => [
            'enabled'  => false,
            'secret'   => '',
            'recovery' => [],
        ],
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
    // ANSWER CACHE (optional — memcached)
    // =====================================================================

    /**
     * Cache the panel's Solr answers in memcached.
     *
     * IT SAVES TWO THINGS, AND THE SECOND ONE IS MONEY.
     *
     * The wait. Solr answers a panel facet in single-digit milliseconds. Getting the question
     * there and the answer back is what costs: a panel in one country and an index in another
     * measures around 240 ms per call, of which more than 110 ms is the TCP and TLS handshake,
     * and a page drawing six cards pays it six times.
     *
     * The metered bandwidth. Opensolr meters OUTGOING traffic — the responses Solr sends back —
     * so it is reads that consume a plan's bandwidth allowance, not writes. The tailer pushing
     * log lines in uploads them and gets back a short acknowledgement, which is why ingestion
     * costs almost nothing against that quota however busy the site is. The consequence is that
     * the metered bandwidth on a Loghound installation is almost entirely the panel's own
     * reads: leaving a view open, or reloading it a few times, spends plan allowance on
     * identical queries, and a facet response over a large index is not small. The cache is
     * therefore the only real lever on that bill, and the bandwidth figure the panel shows you
     * on its own Storage & bandwidth page is, in practice, mostly the panel itself.
     *
     * BOTH OF THESE ARE ALSO CONTROLS IN SETTINGS, and Settings writes back to this file. Edit
     * them here or there; they are the same two values.
     *
     * 'enabled'     Off by default. Turning it on changes what the numbers on the dashboard
     *               mean — they become as old as `ttl_seconds` allows — so it is an explicit
     *               decision rather than an inherited default. Off means every read goes
     *               straight to Solr, which is how an install with no cache behaves.
     *
     * 'server'      `host:port`, a bare host (port 11211 assumed), `[::1]:11211`, or an
     *               absolute path to a unix socket.
     *
     *               MEMCACHED HAS NO AUTHENTICATION AND NO ENCRYPTION. What lands in it is your
     *               traffic data: paths, addresses, user agents, verdicts. Bind it to 127.0.0.1
     *               or use a socket. Loghound derives its key prefix from an HMAC over this
     *               installation's own secret material, so two Loghounds sharing one memcached
     *               cannot address each other's entries and a co-tenant application cannot
     *               guess one of ours — but no key scheme makes a memcached listening on a
     *               public interface safe, and nothing in Loghound can fix that for you.
     *
     * 'ttl_seconds' How long one answer may be reused. Default 7200 (two hours), which suits
     *               checking the panel once or twice a day. Clamped to 60 seconds at the low
     *               end — below that a cache is storing answers nothing lives to read, and the
     *               honest way to want fresh numbers is 'enabled' => false — and to 86400
     *               (twenty-four hours) at the high end.
     *
     *               A long duration is comfortable because of two things that always work:
     *               every card says when its numbers were computed, and the Clear cache button
     *               at the top of every page throws the whole lot away at once without waiting
     *               for anything to expire.
     *
     * NOT REQUIRED. No memcached extension, no server, or a server that stops answering, all
     * degrade to exactly the behaviour of an install with no cache — never to an error on a
     * page. Settings > System check reports which of those you have.
     *
     * NEVER CACHED, whatever these are set to: background job steps (a count you are watching
     * after a delete must be the count now), the liveness check, and anything that failed. A
     * failed read is not stored, so one bad minute cannot become two hours of a dashboard
     * confidently reporting that nothing is happening.
     */
    'cache' => [
        'enabled'     => false,
        'server'      => '127.0.0.1:11211',
        'ttl_seconds' => 7200,
    ],

    // =====================================================================
    // UI
    // =====================================================================

    'ui' => [
        'timezone'    => 'UTC',
        'date_format' => 'm/d/Y H:i:s',
    ],
];
