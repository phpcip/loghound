<?php
/**
 * Loghound — where the index lives (SPEC §9).
 *
 * This is the centre of setup, and the one screen an operator must not have to read
 * documentation to get through. There is exactly one answer to "where should the index
 * live?": you give Loghound your Opensolr account email and API key, and it creates,
 * configures and verifies the two indexes for you.
 *
 * WHY THERE IS NO "POINT IT AT MY OWN SOLR" OPTION
 *
 * There used to be one, and it was removed. Loghound does not merely read and write two
 * indexes — it OWNS them: it creates them, uploads the configsets under solr/hits/conf and
 * solr/sessions/conf, reloads the cores, verifies they answer, and later reports and trims
 * them against the account's plan. None of that is possible on a Solr somebody else
 * administers, where Loghound has no route to create a core or install a configset and no way
 * to keep the schema right. Offering the option therefore promised something the product
 * could not deliver, and the failure surfaced late — after ingestion had begun against a
 * schema nobody had checked. An Opensolr account is now a hard requirement.
 *
 * This class ends at the configuration keys the rest of the product reads, which is what makes
 * the browser installer and `bin/loghound-setup` interchangeable:
 *
 *     solr.mode  solr.hits_core  solr.sessions_core  solr.install_id
 *     solr.base_url  solr.http_user  solr.http_pass
 *     opensolr.email  opensolr.api_key  opensolr.region
 *
 * `solr.base_url`, `solr.http_user` and `solr.http_pass` are still real keys and still
 * required: fetchConnection() fills them in from Opensolr::connectionDetails(), and
 * src/Solr.php remains mode-agnostic — it talks to a node it has credentials for and does not
 * care how they got there. What went away is the door that let a caller supply them.
 *
 * THE INDEX NAMES ARE GENERATED, NEVER TYPED
 *
 * An Opensolr index name is unique across the WHOLE PLATFORM — not per account — and is
 * permanent once created. A fixed `loghound_hits` would therefore work for exactly one
 * person on earth and collide for everybody after them. Every installation gets a random
 * id from Config::newInstallId() and its names from Config::coreName(); a collision with
 * an index somebody else holds is retried with a completely fresh id, and any index created
 * during the failed attempt is deleted first so nobody is billed for an orphan.
 *
 * A name taken by an index THIS account already holds is a different case and is reused
 * rather than abandoned, because a failed attempt leaves exactly that: the id is persisted,
 * the names are derived from it, and a retry re-derives them. See createOne().
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

        $cfg->set('solr.mode', Config::SOLR_MODE);
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
     * failure — which is what makes the "Try again" button safe.
     *
     * "Try again" does NOT resume the failed job. A failed job is no longer running, so
     * Installer::startJob() cannot reattach to it and creates a fresh one, whose step states
     * are all pending. Every step therefore runs again from the top. That is safe only
     * because each one is idempotent against work an earlier attempt already did:
     * checkCredentials() only reads, createOne() reuses an index this account already holds
     * under this installation's id, fetchConnection() re-reads the connection details,
     * pushConfigset() re-uploads and reloads, and verifyCore() only queries.
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
     * A NAME THAT IS TAKEN IS NOT NECESSARILY SOMEBODY ELSE'S. `solr.install_id` is
     * persisted, and the two names are derived from it, so an attempt that created an index
     * and then failed at a later step leaves a name that THIS account already holds. Pressing
     * "Try again" starts a fresh job, and a fresh job's result is empty — so the in-job reuse
     * check below cannot see the earlier attempt at all. Treating that as a stranger's name
     * and rewinding with a new id abandons an index the account is billed for, silently, once
     * per retry. Ownership is therefore established against the platform rather than against
     * this job's memory: accountOwns() answers the question the job result cannot.
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

        if (($job->result()[$role] ?? null) === $name || self::accountOwns($cfg, $name)) {
            $job->setResult($role, $name);
            $job->setResult('install_id', $installId);
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
     * Does this Opensolr account already hold an index of this name?
     *
     * Asked only on the collision branch, which is rare, so the extra control-plane call
     * costs nothing in the normal path. `get_index_list` is filtered by the platform to the
     * indexes this API key may see, which is exactly the question being asked: an index that
     * comes back in this list belongs to the account, and because the name is derived from
     * this installation's own `solr.install_id`, it belongs to this installation.
     *
     * A failure to answer is NOT treated as "not ours". Assuming a stranger owns the name is
     * what abandons a billable index, so an unreachable control plane fails the step with a
     * sentence instead — the operator can press "Try again" once the network is back, and
     * nothing has been thrown away in the meantime.
     *
     * ONE RESIDUAL AMBIGUITY, stated rather than hidden. Opensolr::listIndexes() returns an
     * empty array both for an account that holds nothing and for a refusal the platform sent
     * as HTTP 200 with `status:false`, because the endpoint's success shape is a bare JSON
     * list and a refusal is a map. An empty list is therefore read here as "holds nothing",
     * which is the right reading in the case that actually occurs: the `verify` step at the
     * top of this same job has already proved the credentials by listing regions, so a
     * refusal at this point is not a documented outcome, while a brand-new account holding
     * no indexes at all and colliding with a stranger's name is a real one — and refusing
     * that would strand the first install on an unrecoverable screen.
     *
     * @throws \RuntimeException When the account's index list could not be read.
     */
    private static function accountOwns(Config $cfg, string $name): bool
    {
        try {
            $held = self::client($cfg)->listIndexes();
        } catch (\Throwable $e) {
            throw new \RuntimeException(
                'The name ' . $name . ' is already taken, and Opensolr could not be asked whether '
                . 'this account is the one holding it. Nothing has been changed or removed. '
                . 'Check outbound HTTPS from this server and press Try again.'
            );
        }

        return in_array($name, $held, true);
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
     * Connectivity test for the two provisioned indexes, as a two-step job.
     *
     * Reads the stored connection details and asks each core for zero rows. It is
     * mode-agnostic by construction — it only needs a base URL and credentials, which
     * fetchConnection() has already written — so it serves both the end of provisioning and
     * the "Test the connection" button on the setup status page.
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
     * NOTHING HERE IS BUILT FROM `solr.base_url`. Every sentence names the target through
     * hostPort(), which keeps the host and the port and drops everything else, and that stays
     * true now that no form can supply the base URL at all: this method reads whatever is in
     * the config file, and a config file hand-edited to `https://user:pass@host/solr` is
     * exactly the case that no refusal at an input can reach. The `fix` list used to be
     * assembled by interpolating the base URL into ready-to-paste `curl` commands; it was
     * rendered nowhere, so it was deleted rather than repaired. If a caller ever wants those
     * hints back, build them from hostPort() and the core name and add a test that a
     * password in the base URL cannot reach the returned strings.
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
                'fix'     => [],
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

    /**
     * host:port of a base URL, with the scheme's default port filled in.
     *
     * This is the ONLY thing any message in this class is allowed to say about the Solr
     * address, so a URL it cannot parse degrades to a generic phrase rather than being
     * echoed back verbatim: an unparseable base URL is exactly the shape a mistyped
     * `https://user:pass@host/solr` takes, and printing it would print the password.
     */
    private static function hostPort(string $base): string
    {
        $host = (string) parse_url($base, PHP_URL_HOST);
        if ($host === '') {
            return 'the configured address';
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
     * The input is expected to be credential-free — Solr::curlTransport never puts the
     * password in an error, and Opensolr redacts the API key before any message escapes —
     * but the last branch passes the raw text through to the operator, so "expected" is not
     * good enough. Any `scheme://user:pass@` in it is stripped before anything is built from
     * it, which costs one regex and removes the whole class of "some transport helpfully
     * included the URL it was given".
     */
    private static function readableSolrError(string $raw, string $where, string $core): string
    {
        $raw = (string) preg_replace('~([a-zA-Z][a-zA-Z0-9+.\-]*://)[^/\s@]*@~', '$1', $raw);
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
