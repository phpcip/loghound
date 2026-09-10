<?php
/**
 * Loghound — where the index lives (SPEC §9).
 *
 * This is the centre of setup, and the one screen an operator must not have to read
 * documentation to get through. There are exactly two answers to "where should the index
 * live?":
 *
 *   1. **Opensolr managed.** You do not run Solr. You give Loghound your Opensolr account
 *      email and API key and it creates, configures and verifies the two indexes for you.
 *   2. **Your own Solr 9.** You already run one. You give Loghound a base URL, optional
 *      HTTP auth, and the two core names.
 *
 * Both paths end at exactly the same configuration keys, which is what makes the browser
 * installer and `bin/loghound-setup` interchangeable:
 *
 *     solr.mode  solr.hits_core  solr.sessions_core  solr.install_id
 *     solr.base_url  solr.http_user  solr.http_pass
 *     opensolr.email  opensolr.api_key  opensolr.region
 *
 * THE INDEX NAMES ARE GENERATED, NEVER TYPED
 *
 * An Opensolr index name is unique across the WHOLE PLATFORM — not per account — and is
 * permanent once created. A fixed `loghound_hits` would therefore work for exactly one
 * person on earth and collide for everybody after them. Every installation gets a random
 * id from Config::newInstallId() and its names from Config::coreName(); a collision is
 * retried with a completely fresh id, and any index created during the failed attempt is
 * deleted first so nobody is billed for an orphan.
 *
 * THE API KEY
 *
 * It comes from what the operator types, and from nowhere else: no default, no pre-filled
 * value, no environment variable, no fallback account. It is written straight into
 * config/loghound.php (mode 0640, outside the document root) and is never rendered back
 * into a page, a hidden field, a job file, a session, a log line or an error message.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Setup;

use Loghound\Config;
use Loghound\Opensolr;
use Loghound\Security;
use Loghound\Solr;

final class Storage
{
    /**
     * Per-request network timeout for setup traffic, in seconds.
     *
     * Deliberately short and explicit. A control-plane call that hangs must fail with a
     * message the operator can act on, not sit there until the gateway kills PHP.
     */
    public const NET_TIMEOUT = 25;

    /** How many times a colliding index-name pair is retried with a fresh id. */
    private const MAX_NAME_ATTEMPTS = 5;

    /**
     * Test-only HTTP transport.
     *
     * The provisioning state machine — create, collide, roll back, retry with a fresh id,
     * upload, verify — is the most consequential code in setup: getting it wrong leaves
     * indexes in someone's account that they are billed for. It therefore has to be
     * testable without touching the network, and the steps build their own clients, so
     * there is nowhere to pass a transport in from the outside.
     *
     * Inert unless LOGHOUND_TEST=1 is in the environment, which only tests/run.php sets.
     * It is a seam, not a switch: production code cannot reach it.
     *
     * @var callable|null
     */
    private static $testTransport = null;

    /**
     * Install the test transport. Refuses to do anything outside the test suite.
     *
     * @param callable|null $transport fn(array $req): array{status:int,body:string,error:string}
     * @throws \RuntimeException When called anywhere but under tests/run.php.
     */
    public static function useTestTransport(?callable $transport): void
    {
        if (getenv('LOGHOUND_TEST') !== '1') {
            throw new \RuntimeException('Storage::useTestTransport() is available under tests only.');
        }
        self::$testTransport = $transport;
    }

    /**
     * The transport a client should use when the caller did not supply one.
     *
     * @param callable|null $given
     */
    private static function transport(?callable $given): ?callable
    {
        if ($given !== null) {
            return $given;
        }
        return getenv('LOGHOUND_TEST') === '1' ? self::$testTransport : null;
    }

    /**
     * Validate and store the Opensolr account credentials.
     *
     * Nothing is contacted here; this only records what was typed, so the (slow) network
     * validation can run as a job with visible progress. The key is written to the config
     * because that is the only place it is allowed to live — holding it in a session or a
     * hidden form field to "verify it first" would put it somewhere less safe.
     *
     * @return string[] Human-readable problems; empty means accepted.
     */
    public static function saveCredentials(Config $cfg, string $email, string $apiKey): array
    {
        $errors = [];

        $email = trim($email);
        if ($email === '') {
            $errors[] = 'Enter the email address of your Opensolr account.';
        } elseif (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            $errors[] = 'That does not look like an email address.';
        }

        $apiKey = trim($apiKey);
        $stored = (string) $cfg->get('opensolr.api_key', '');
        if ($apiKey === '' && $stored === '') {
            $errors[] = 'Enter your Opensolr API key. You will find it under Account in your '
                . 'Opensolr control panel.';
        } elseif ($apiKey !== '' && !preg_match('/^[A-Za-z0-9_\-]{8,128}$/', $apiKey)) {
            $errors[] = 'That API key does not look right — it should be a single line of '
                . 'letters, digits, hyphens or underscores with no spaces.';
        }

        if ($errors !== []) {
            return $errors;
        }

        $cfg->set('solr.mode', 'opensolr');
        $cfg->set('opensolr.email', $email);
        if ($apiKey !== '') {
            $cfg->set('opensolr.api_key', $apiKey);
        }

        return [];
    }

    /**
     * Build the control-plane client from the stored credentials.
     *
     * @param callable|null $transport Injected by tests so the suite never touches the network.
     */
    public static function client(Config $cfg, ?callable $transport = null): Opensolr
    {
        $section = (array) $cfg->get('opensolr', []);
        $section['timeout'] = self::NET_TIMEOUT;
        return new Opensolr($section, self::transport($transport));
    }

    /**
     * Ask the platform which regions this account may use.
     *
     * Doubles as the credential check: the endpoint needs a valid email and API key, and
     * it is the cheapest, most harmless call on the whole API — it creates nothing and
     * changes nothing.
     *
     * @return string[]
     * @throws \RuntimeException With a message safe to show; the key is redacted upstream.
     */
    public static function listRegions(Config $cfg, ?callable $transport = null): array
    {
        $regions = self::client($cfg, $transport)->listRegions();
        if ($regions === []) {
            throw new \RuntimeException(
                'Opensolr accepted the request but returned no regions for this account. '
                . 'Check in your Opensolr control panel that the account is active.'
            );
        }
        return $regions;
    }

    /**
     * The provisioning step list.
     *
     * Every step is small, individually named, and idempotent enough to be re-run after a
     * failure — which is what makes the "Try again" button safe: completed steps are
     * skipped, and the job picks up at the one that failed.
     *
     * @return array<int,array{key:string,label:string,run:callable}>
     */
    public static function opensolrSteps(Job $job, Config $cfg, string $root): array
    {
        $region = (string) ($job->params()['region'] ?? '');

        return [
            [
                'key'   => 'verify',
                'label' => 'Checking your Opensolr credentials',
                'run'   => static fn(Job $j, Config $c): string => self::checkCredentials($j, $c, $region),
            ],

            [
                'key'   => 'create_hits',
                'label' => 'Creating the hits index',
                'run'   => static function (Job $j, Config $c) use ($region): array|string {
                    return self::createOne($j, $c, $region, 'hits');
                },
            ],

            [
                'key'   => 'create_sessions',
                'label' => 'Creating the sessions index',
                'run'   => static function (Job $j, Config $c) use ($region): array|string {
                    return self::createOne($j, $c, $region, 'sessions');
                },
            ],

            [
                'key'   => 'connect',
                'label' => 'Fetching the connection details',
                'run'   => static fn(Job $j, Config $c): string => self::fetchConnection($j, $c),
            ],

            [
                'key'   => 'schema_hits',
                'label' => 'Uploading the hits schema',
                'run'   => static function (Job $j, Config $c) use ($root): string {
                    return self::pushConfigset($j, $c, (string) $c->get('solr.hits_core'), $root . '/solr/hits/conf');
                },
            ],

            [
                'key'   => 'schema_sessions',
                'label' => 'Uploading the sessions schema',
                'run'   => static function (Job $j, Config $c) use ($root): string {
                    return self::pushConfigset($j, $c, (string) $c->get('solr.sessions_core'), $root . '/solr/sessions/conf');
                },
            ],

            [
                'key'   => 'verify_hits',
                'label' => 'Verifying the hits index answers',
                'run'   => static function (Job $j, Config $c): string {
                    return self::verifyCore($j, $c, (string) $c->get('solr.hits_core'));
                },
            ],

            [
                'key'   => 'verify_sessions',
                'label' => 'Verifying the sessions index answers',
                'run'   => static function (Job $j, Config $c): string {
                    return self::verifyCore($j, $c, (string) $c->get('solr.sessions_core'));
                },
            ],
        ];
    }

    /**
     * Prove the stored credentials work, and that the chosen region exists on this account.
     *
     * Listing regions is the cheapest and most harmless authenticated call the control
     * plane offers: it creates nothing, changes nothing, and fails loudly on a bad email
     * or API key. Doing it as the first provisioning step is what stops a mistyped key
     * from surfacing three screens later, halfway through creating billable indexes.
     *
     * @throws \RuntimeException When the credentials are refused or the region is not offered.
     */
    private static function checkCredentials(Job $job, Config $cfg, string $region): string
    {
        $job->note('Contacting opensolr.com …');
        $regions = self::listRegions($cfg);
        $job->setResult('regions', $regions);

        if ($region !== '' && !in_array($region, $regions, true)) {
            throw new \RuntimeException(
                'The region "' . $region . '" is not available on this account. '
                . 'Available: ' . implode(', ', $regions) . '.'
            );
        }

        $cfg->set('opensolr.region', $region);
        self::persist($cfg);

        return 'Credentials accepted; region ' . $region . ' is available.';
    }

    /**
     * Ask the platform where the new indexes live, and store the answer.
     *
     * This is how managed mode fills in solr.base_url, solr.http_user and solr.http_pass,
     * after which src/Solr.php is mode-agnostic and simply talks to a node it has
     * credentials for.
     *
     * Opensolr::connectionDetails() returns the keys `base_url`, `http_user` and
     * `http_pass`. Reading `user`/`pass` instead — the obvious guess — silently yields
     * empty credentials and a later HTTP 401 that is miserable to trace back to here.
     *
     * The returned progress line names the HOST only. The credentials that came back in
     * the same response are written to the configuration and never rendered.
     *
     * @throws \RuntimeException When the platform has no connection URL for the index.
     */
    private static function fetchConnection(Job $job, Config $cfg): string
    {
        $hits = (string) $cfg->get('solr.hits_core', '');
        $job->note('Asking where ' . $hits . ' lives …');

        $conn = self::client($cfg)->connectionDetails($hits);

        $cfg->set('solr.base_url', $conn['base_url']);
        $cfg->set('solr.http_user', $conn['http_user']);
        $cfg->set('solr.http_pass', $conn['http_pass']);
        self::persist($cfg);

        $host = (string) parse_url($conn['base_url'], PHP_URL_HOST);

        return 'Your indexes are on ' . ($host !== '' ? $host : 'the Opensolr platform') . '.';
    }

    /**
     * Create one of the two indexes, handling the platform-wide name collision.
     *
     * Returns a `goto` instruction rather than throwing when the name is taken: the job
     * rewinds to `create_hits` with a brand-new installation id, because the pair must
     * share one id to be recognisable as a pair in an account holding hundreds of indexes.
     *
     * @param string $role 'hits' or 'sessions'
     * @return array{goto:string,detail:string}|string
     */
    private static function createOne(Job $job, Config $cfg, string $region, string $role): array|string
    {
        $installId = (string) $cfg->get('solr.install_id', '');
        if ($installId === '') {
            $installId = Config::newInstallId();
            $cfg->set('solr.install_id', $installId);
        }

        $key  = $role === 'hits' ? 'solr.hits_core' : 'solr.sessions_core';
        $name = Config::coreName($installId, $role);
        $cfg->set($key, $name);
        self::persist($cfg);

        $job->note('Creating index ' . $name . ' …');
        $res = self::client($cfg)->createIndex($name, $region);

        if (!empty($res['status'])) {
            $job->setResult($role, $name);
            $job->setResult('install_id', $installId);
            return 'Created ' . $name . '.';
        }

        if (!Opensolr::isNameTaken($res)) {
            throw new \RuntimeException(self::readableApiError($res));
        }

        if (($job->result()[$role] ?? null) === $name) {
            return 'Index ' . $name . ' already exists from an earlier attempt — reusing it.';
        }

        $attempt = $job->nextAttempt();
        if ($attempt >= self::MAX_NAME_ATTEMPTS) {
            throw new \RuntimeException(
                'Could not find a free index name after ' . $attempt . ' attempts. '
                . 'That is unusual — try again, and if it persists say so in your Opensolr control panel.'
            );
        }

        $job->note('The name ' . $name . ' is already taken on the platform; choosing another.');

        if ($role === 'sessions') {
            $hits = (string) $cfg->get('solr.hits_core', '');
            if ($hits !== '') {
                $job->note('Removing the partially created index ' . $hits . ' …');
                try {
                    self::client($cfg)->deleteIndex($hits);
                } catch (\Throwable $e) {
                    $job->note('Could not remove ' . $hits . ' — delete it from your Opensolr control panel.');
                }
            }
        }

        $cfg->set('solr.install_id', Config::newInstallId());
        $cfg->set('solr.hits_core', '');
        $cfg->set('solr.sessions_core', '');
        self::persist($cfg);

        return ['goto' => 'create_hits', 'detail' => 'Name taken; retrying with a new id.'];
    }

    /**
     * Push the configset for one index and report file by file.
     *
     * Order matters and is enforced inside Opensolr::pushConfigSet(): schema first, then
     * solrconfig. Reversed, the core reloads against a solrconfig referring to field types
     * the old schema does not define, and the reload fails.
     */
    private static function pushConfigset(Job $job, Config $cfg, string $core, string $confDir): string
    {
        if ($core === '') {
            throw new \RuntimeException('The index name is missing — the previous step did not finish.');
        }
        if (!is_dir($confDir)) {
            throw new \RuntimeException('The configset directory is missing from this checkout: ' . $confDir);
        }

        $job->note('Uploading the schema to ' . $core . ' …');
        $results = self::client($cfg)->pushConfigSet($core, $confDir);

        $failed = [];
        foreach ($results as $row) {
            $job->note($row['file'] . ': ' . $row['msg']);
            if (!$row['ok']) {
                $failed[] = $row['file'] . ' (' . $row['msg'] . ')';
            }
        }
        if ($failed !== []) {
            throw new \RuntimeException(
                'The index was created but its configuration was rejected: ' . implode(', ', $failed)
                . '. The index is in your Opensolr control panel; you can upload the files from '
                . 'solr/ by hand there, or press Try again.'
            );
        }

        return 'Schema and solrconfig uploaded, index reloaded.';
    }

    /** Prove Loghound itself can reach and authenticate to a core. */
    private static function verifyCore(Job $job, Config $cfg, string $core): string
    {
        $job->note('Querying ' . $core . ' …');
        $probe = self::probeCore($cfg, $core);
        if (!$probe['ok']) {
            throw new \RuntimeException($probe['message']);
        }
        return $probe['message'];
    }

    /**
     * Validate and store the details of a Solr the operator already runs.
     *
     * The core names are offered pre-filled with this installation's generated names, but
     * on your own Solr the namespace is yours, so a plain `loghound_hits` is perfectly
     * fine and easier to recognise in the Solr admin UI.
     *
     * @return string[] Problems; empty means accepted.
     */
    public static function saveCustom(
        Config $cfg,
        string $baseUrl,
        string $httpUser,
        string $httpPass,
        string $hitsCore,
        string $sessionsCore
    ): array {
        $errors = [];

        $baseUrl = rtrim(trim($baseUrl), '/');
        if ($baseUrl === '') {
            $errors[] = 'Enter the base URL of your Solr, for example http://127.0.0.1:8983/solr';
        } elseif (Security::safeUrl($baseUrl) === '#') {
            $errors[] = 'The Solr address must be a plain http:// or https:// URL with no spaces.';
        }

        foreach ([['hits', $hitsCore], ['sessions', $sessionsCore]] as [$role, $name]) {
            $name = trim($name);
            if ($name === '') {
                $errors[] = 'Enter a name for the ' . $role . ' core.';
            } elseif (!Security::isSafeCoreName($name)) {
                $errors[] = 'The ' . $role . ' core name may only contain letters, digits and underscores.';
            } elseif (strlen($name) > 50) {
                $errors[] = 'The ' . $role . ' core name must be 50 characters or fewer.';
            }
        }
        if (trim($hitsCore) !== '' && trim($hitsCore) === trim($sessionsCore)) {
            $errors[] = 'The two cores must be different, or session documents would be written '
                . 'into the hits index and every number in the dashboard would be wrong.';
        }

        if ($errors !== []) {
            return $errors;
        }

        $cfg->set('solr.mode', 'custom');
        $cfg->set('solr.base_url', $baseUrl);
        $cfg->set('solr.http_user', trim($httpUser));
        if ($httpPass !== '') {
            $cfg->set('solr.http_pass', $httpPass);
        }
        $cfg->set('solr.hits_core', trim($hitsCore));
        $cfg->set('solr.sessions_core', trim($sessionsCore));

        if ((string) $cfg->get('solr.install_id', '') === '') {
            $cfg->set('solr.install_id', Config::newInstallId());
        }

        return [];
    }

    /**
     * Connectivity test for an operator-run Solr, as a two-step job.
     *
     * @return array<int,array{key:string,label:string,run:callable}>
     */
    public static function solrTestSteps(Job $job, Config $cfg): array
    {
        return [
            [
                'key'   => 'hits',
                'label' => 'Querying the hits core',
                'run'   => static function (Job $j, Config $c): string {
                    return self::verifyCore($j, $c, (string) $c->get('solr.hits_core'));
                },
            ],
            [
                'key'   => 'sessions',
                'label' => 'Querying the sessions core',
                'run'   => static function (Job $j, Config $c): string {
                    return self::verifyCore($j, $c, (string) $c->get('solr.sessions_core'));
                },
            ],
        ];
    }

    /**
     * Ask one core for zero rows and turn the outcome into a sentence a human can act on.
     *
     * "Could not connect to Solr" is useless. This produces, for example:
     *   "Connection refused to fi.solrcluster.com:443 — check the address and that this
     *    server is allowed to reach it."
     *
     * @return array{ok:bool,message:string,fix:string[]}
     */
    public static function probeCore(Config $cfg, string $core, ?callable $transport = null): array
    {
        $base = (string) $cfg->get('solr.base_url', '');
        $where = self::hostPort($base);

        if ($base === '') {
            return [
                'ok' => false,
                'message' => 'No Solr address has been configured yet.',
                'fix' => [],
            ];
        }
        if ($core === '' || !Security::isSafeCoreName($core)) {
            return [
                'ok' => false,
                'message' => 'The index name is missing or invalid.',
                'fix' => [],
            ];
        }

        try {
            $solrCfg = (array) $cfg->get('solr', []);
            $solrCfg['timeout'] = 10;
            $solr = new Solr($solrCfg, self::transport($transport));
            $res = $solr->query($core, ['q' => '*:*', 'rows' => 0]);
        } catch (\Throwable $e) {
            return [
                'ok'      => false,
                'message' => self::readableSolrError($e->getMessage(), $where, $core),
                'fix'     => self::solrFixes($cfg, $where, $core, $e->getMessage()),
            ];
        }

        $found = (int) ($res['response']['numFound'] ?? 0);
        return [
            'ok' => true,
            'message' => $core . ' answered on ' . $where . ' and holds '
                . number_format($found) . ' document' . ($found === 1 ? '' : 's') . '.',
            'fix' => [],
        ];
    }

    /**
     * The whole-installation health probe used by the status page and the CLI.
     *
     * @return array{ok:bool,message:string,fix:string[]}
     */
    public static function probe(Config $cfg, ?callable $transport = null): array
    {
        return self::probeCore($cfg, (string) $cfg->get('solr.hits_core', ''), $transport);
    }

    /** host:port of a base URL, with the scheme's default port filled in. */
    private static function hostPort(string $base): string
    {
        $host = (string) parse_url($base, PHP_URL_HOST);
        if ($host === '') {
            return $base === '' ? 'the configured address' : $base;
        }
        $port = parse_url($base, PHP_URL_PORT);
        if ($port === null || $port === false) {
            $port = parse_url($base, PHP_URL_SCHEME) === 'https' ? 443 : 80;
        }
        return $host . ':' . $port;
    }

    /**
     * Translate a transport or Solr error into something with a next action in it.
     *
     * The input is already credential-free: Solr::curlTransport never puts the password in
     * an error, and Opensolr redacts the API key before any message escapes.
     */
    private static function readableSolrError(string $raw, string $where, string $core): string
    {
        $lower = strtolower($raw);

        if (str_contains($lower, 'connection refused')) {
            return 'Connection refused to ' . $where . ' — nothing is listening there. Check the '
                . 'address, and that Solr is running.';
        }
        if (str_contains($lower, 'could not resolve') || str_contains($lower, 'name or service not known')) {
            return 'The name in the address could not be resolved from this server (' . $where . ').';
        }
        if (str_contains($lower, 'timed out') || str_contains($lower, 'timeout')) {
            return 'No answer from ' . $where . ' before the timeout. Usually a firewall between '
                . 'this server and Solr.';
        }
        if (str_contains($lower, 'certificate') || str_contains($lower, 'ssl')) {
            return 'The TLS certificate of ' . $where . ' was rejected. Loghound will not send '
                . 'credentials over an unverified connection.';
        }
        if (str_contains($lower, '401') || str_contains($lower, 'unauthorized')) {
            return $where . ' answered, but refused the username and password.';
        }
        if (str_contains($lower, '403') || str_contains($lower, 'forbidden')) {
            return $where . ' answered, but this account is not allowed to read ' . $core . '.';
        }
        if (str_contains($lower, '404') || str_contains($lower, 'not found')) {
            return $where . ' answered, but there is no core called ' . $core . ' on it.';
        }
        return $where . ' did not answer as expected: ' . $raw;
    }

    /**
     * Concrete things to try, matched to the failure.
     *
     * @return string[]
     */
    private static function solrFixes(Config $cfg, string $where, string $core, string $raw): array
    {
        $lower = strtolower($raw);
        $base  = (string) $cfg->get('solr.base_url', '');

        if (str_contains($lower, '401') || str_contains($lower, 'unauthorized')) {
            return (string) $cfg->get('solr.mode') === 'opensolr'
                ? ['The credentials come from your Opensolr control panel. Press Try again to fetch them once more.']
                : ['Check the Solr username and password on the previous screen.'];
        }
        if (str_contains($lower, '404') || str_contains($lower, 'not found')) {
            return [
                'curl -sS ' . $base . '/admin/cores?action=STATUS   # lists the cores that do exist',
            ];
        }
        return [
            'curl -sS -m 5 "' . $base . '/' . $core . '/select?q=*:*&rows=0&wt=json"',
        ];
    }

    /**
     * Turn a control-plane refusal into a sentence, without ever echoing the key.
     *
     * @param array<string,mixed> $res
     */
    private static function readableApiError(array $res): string
    {
        $msg = $res['msg'] ?? '';
        $msg = is_string($msg) ? $msg : (string) json_encode($msg, JSON_UNESCAPED_SLASHES);

        if (stripos($msg, 'API_KEY') !== false || stripos($msg, 'AUTH') !== false) {
            return 'Opensolr did not accept the email address and API key. Check them in your '
                . 'Opensolr control panel under Account.';
        }
        if (stripos($msg, 'LIMIT') !== false || stripos($msg, 'QUOTA') !== false) {
            return 'Your Opensolr plan has no room for another index. Remove one, or upgrade, '
                . 'then press Try again.';
        }
        return 'Opensolr refused to create the index: ' . $msg;
    }

    /**
     * Write the configuration, keeping the running process's view of it authoritative.
     *
     * Every step persists as soon as it has something worth keeping, which is what makes
     * the whole installer resumable: the partly-written config file IS the wizard's state,
     * so nothing is held in a session that a lost cookie could throw away.
     */
    public static function persist(Config $cfg): void
    {
        $cfg->save();
        if (function_exists('opcache_invalidate')) {
            @opcache_invalidate($cfg->path(), true);
        }
    }
}
